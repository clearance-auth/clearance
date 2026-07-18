import type { AuthContext, HookEndpointContext } from "@clearance/core";
import type { AuthMiddleware } from "@clearance/core/api";
import { generateId } from "@clearance/core/utils/id";
import { getIp } from "@clearance/core/utils/ip";
import {
	getActiveTransactionAdapter,
	isTransactionActive,
	runWithEndpointContext,
	runWithTransaction,
} from "@clearance/core/context";
import { shouldPublishLog } from "@clearance/core/env";
import { APIError } from "@clearance/core/error";
import {
	ATTR_CONTEXT,
	ATTR_HOOK_TYPE,
	ATTR_HTTP_ROUTE,
	ATTR_OPERATION_ID,
	withSpan,
} from "@clearance/core/instrumentation";
import type { Endpoint, EndpointContext, InputContext } from "@clearance/call";
import {
	kAPIErrorHeaderSymbol,
	serializeSignedCookie,
	toResponse,
} from "@clearance/call";
import { createDefu } from "defu";
import { isAPIError } from "../utils/is-api-error";
import { copyEndpointMetadata } from "../utils/shim";
import { isRequestLike } from "../utils/url";
import { assertSessionCredentialMigrationComplete } from "../db/session-credential-migration";
import { readInternalCredentialAuthority } from "../internal/credential-authority";
import {
	issueInitialStagedAuthenticationCapability,
	takeStagedAuthenticationContinuation,
} from "../internal/staged-authentication-context";
import {
	appendInternalRuntimeAudit,
	attachCapturedInternalRuntimeAudit,
	classifyRuntimeInteractiveAuthenticationRoute,
	getRuntimeAuditRequestContext,
	readInternalRuntimeAudit,
	runWithRuntimeAuditRequestContext,
	type InternalRuntimeAuditRequestContext,
} from "../internal/runtime-audit";
const credentialMigrationChecks = new WeakMap<object, Promise<void>>();

const rejectActiveTransactionSymbol = Symbol.for(
	"clearance.endpoint.reject-active-transaction",
);

type ActiveTransactionRejection = () => APIError;

/**
 * Mark an endpoint that must reject before dispatch performs any authority or
 * hook work inside an already-active transaction. Cookie-bearing lifecycle
 * routes use this because their response headers cannot be published safely by
 * an outer transaction that outlives the endpoint response.
 */
export function rejectActiveTransactionEndpoint<T extends Endpoint>(
	endpoint: T,
	createError: ActiveTransactionRejection,
): T {
	const guarded = copyEndpointMetadata((async (...args: any[]) => {
		const adapter = (args[0] as { context?: { adapter?: object } } | undefined)
			?.context?.adapter;
		if (adapter && (await isTransactionActive(adapter))) throw createError();
		return (endpoint as (...args: any[]) => unknown)(...args);
	}) as T, endpoint);
	Object.defineProperty(guarded, rejectActiveTransactionSymbol, {
		configurable: false,
		enumerable: false,
		value: createError,
		writable: false,
	});
	return guarded;
}

function normalizePreflightAPIError(
	error: APIError,
	shouldReturnResponse: boolean,
): Response | never {
	const headers = mergeAPIErrorHeaders(error);
	if (!shouldReturnResponse) {
		if (headers) {
			Object.defineProperty(error, kAPIErrorHeaderSymbol, {
				enumerable: false,
				configurable: true,
				writable: false,
				value: headers,
			});
		}
		throw error;
	}
	return toResponse(error, {
		headers: headers ?? undefined,
		status: error.statusCode,
	});
}

async function activeDispatchTransaction(
	context: AuthContext,
): Promise<AuthContext["adapter"] | null> {
	return (await getActiveTransactionAdapter(
		context.adapter,
	)) as AuthContext["adapter"] | null;
}

async function assertDispatchCredentialAuthority(context: AuthContext) {
	const authority = readInternalCredentialAuthority(context.options);
	if (authority?.generation === "legacy-v1") return;
	let pending = credentialMigrationChecks.get(context);
	if (!pending) {
		pending = assertSessionCredentialMigrationComplete(
			context.adapter,
			context.options,
		).catch((error) => {
			credentialMigrationChecks.delete(context);
			throw error;
		});
		credentialMigrationChecks.set(context, pending);
	}
	await pending;
}

/**
 * Input accepted by {@link dispatchAuthEndpoint}. `context` must already be a
 * resolved `AuthContext`; the caller owns `baseURL` resolution. A fresh
 * dispatch carries no `session` (the shared context has none), while a resumed
 * dispatch carries the in-flight request's `session` through.
 */
export type DispatchContext = Partial<
	InputContext<string, any> & EndpointContext<string, any>
> & {
	context: AuthContext & {
		returned?: unknown | undefined;
		responseHeaders?: Headers | undefined;
	};
	operationId?: string | undefined;
};

/**
 * The working context a dispatch runs against: the input plus the resolved
 * `path` and the `asResponse` decision.
 */
type InternalContext = DispatchContext & {
	path?: string | undefined;
	asResponse?: boolean | undefined;
};

const defuReplaceArrays = createDefu((obj, key, value) => {
	if (Array.isArray(obj[key]) && Array.isArray(value)) {
		obj[key] = value;
		return true;
	}
});

type Hook = {
	matcher: (context: HookEndpointContext) => boolean;
	handler: AuthMiddleware;
};

const hooksSourceWeakMap = new WeakMap<
	AuthMiddleware,
	`user` | `plugin:${string}`
>();

/**
 * Resolves the operation id used for spans, preferring an explicit
 * `operationId`, then the OpenAPI one, then the caller's `fallback` (the
 * `auth.api.*` map key), and finally the route path.
 */
export function getOperationId(endpoint: Endpoint, fallback?: string): string {
	const opts = endpoint.options as
		| {
				operationId?: string;
				metadata?: { openapi?: { operationId?: string } };
		  }
		| undefined;
	return (
		opts?.operationId ??
		opts?.metadata?.openapi?.operationId ??
		fallback ??
		endpoint.path ??
		"/:virtual"
	);
}

function dispatchRequestHeaders(input: DispatchContext): Headers | undefined {
	if (input.headers) return new Headers(input.headers);
	const headers = input.request?.headers;
	return headers ? new Headers(headers) : undefined;
}

function validRequestId(value: string | null): string | null {
	if (
		!value ||
		value.length > 128 ||
		value.trim() !== value ||
		!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
	) {
		return null;
	}
	return value;
}

function boundedHeader(value: string | null, maximum: number): string | null {
	if (
		value === null ||
		value.length > maximum ||
		value.trim() !== value ||
		/[\0\r\n]/.test(value)
	) {
		return null;
	}
	return value;
}

function normalizedMethod(value: string): string {
	const method = value.toUpperCase();
	return /^[A-Z]+$/.test(method) && method.length <= 16 ? method : "DIRECT";
}

function safeClientIp(value: string | null): string | null {
	return value && value.length <= 64 && /^[0-9A-Fa-f:.]+$/.test(value)
		? value
		: null;
}

function createRuntimeAuditRequestContext(
	input: DispatchContext,
	operationId: string,
	route: string,
	method: string,
): InternalRuntimeAuditRequestContext {
	const headers = dispatchRequestHeaders(input);
	return Object.freeze({
		correlationId:
			validRequestId(headers?.get("x-request-id") ?? null) ??
			`rt_${generateId(24)}`,
		operationId: operationId.slice(0, 256) || "/:virtual",
		route: route.slice(0, 512),
		method,
		clientIp: safeClientIp(
			headers ? getIp(headers, input.context.options) : null,
		),
		userAgent: boundedHeader(headers?.get("user-agent") ?? null, 512),
	});
}

function stableAuditErrorCode(error: APIError): string | undefined {
	const code = error.body?.code;
	return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,127}$/.test(code)
		? code
		: undefined;
}

async function appendFailedLoginAudit(
	context: AuthContext,
	route: string,
	error: APIError,
	status: number | undefined,
): Promise<void> {
	const authenticationMethod =
		classifyRuntimeInteractiveAuthenticationRoute(route);
	if (
		!authenticationMethod ||
		error.body?.code === "MANAGED_AUTHENTICATION_REQUIRED"
	) {
		return;
	}
	const binding =
		readInternalRuntimeAudit(context.options) ??
		readInternalRuntimeAudit(context.adapter);
	if (!binding) return;
	const request = await getRuntimeAuditRequestContext();
	if (!request) {
		throw new Error("Runtime audit request context is unavailable");
	}
	const httpStatus =
		typeof status === "number" &&
		Number.isSafeInteger(status) &&
		status >= 100 &&
		status <= 599
			? status
			: 500;
	const code = stableAuditErrorCode(error);
	await runWithTransaction(context.adapter, async () => {
		const transaction = await activeDispatchTransaction(context);
		if (!transaction) {
			throw new Error("Runtime audit transaction is unavailable");
		}
		attachCapturedInternalRuntimeAudit(transaction, binding);
		await appendInternalRuntimeAudit(transaction, {
			actor: "anonymous",
			action: "auth.login.failed",
			subjectType: null,
			subjectId: null,
			outcome: "failure",
			source: "system",
			organizationId: null,
			message: "Interactive authentication failed",
			metadata: {
				status: httpStatus,
				...(code ? { code } : {}),
				method: authenticationMethod,
			},
			request,
		});
	});
}

/**
 * Merge a set of response headers onto the dispatch's accumulator, appending
 * `set-cookie` (multiple cookies are legal) and replacing everything else.
 */
function mergeResponseHeaders(
	context: InternalContext["context"],
	headers: Headers | null | undefined,
) {
	if (!headers) return;
	headers.forEach((value, key) => {
		if (!context.responseHeaders) {
			context.responseHeaders = new Headers({ [key]: value });
		} else if (key.toLowerCase() === "set-cookie") {
			context.responseHeaders.append(key, value);
		} else {
			context.responseHeaders.set(key, value);
		}
	});
}

/**
 * Combine the two header sources an `APIError` can carry into one set:
 * - `kAPIErrorHeaderSymbol`: `ctx.responseHeaders` accumulated via
 *   `c.setCookie` / `c.setHeader` before the throw.
 * - `e.headers`: explicit headers on the error (e.g. `location` from
 *   `c.redirect`).
 *
 * `c.redirect()` reuses `ctx.responseHeaders` as `e.headers`, so when both
 * point at the same object iterating each would duplicate every `set-cookie`;
 * the identity check skips that copy. Explicit error headers override
 * accumulated ones, while cookies from both accumulate.
 */
function mergeAPIErrorHeaders(error: APIError): Headers | null {
	const ctxHeaders = (
		error as APIError & { [kAPIErrorHeaderSymbol]?: Headers }
	)[kAPIErrorHeaderSymbol];
	const errHeaders =
		error.headers && error.headers !== ctxHeaders
			? new Headers(error.headers)
			: null;
	if (!ctxHeaders && !errHeaders) return null;
	const headers = new Headers();
	ctxHeaders?.forEach((value, key) => {
		headers.append(key, value);
	});
	errHeaders?.forEach((value, key) => {
		if (key.toLowerCase() === "set-cookie") {
			headers.append(key, value);
		} else {
			headers.set(key, value);
		}
	});
	return headers;
}

async function runBeforeHooks(
	context: InternalContext,
	hooks: Hook[],
	endpoint: Endpoint,
	operationId: string,
) {
	let modifiedContext: Partial<InternalContext> = {};

	for (const hook of hooks) {
		let matched = false;
		try {
			matched = hook.matcher(context as HookEndpointContext);
		} catch (error) {
			// Surface which plugin's matcher failed in the logs without leaking
			// internal details to the caller.
			const hookSource = hooksSourceWeakMap.get(hook.handler) ?? "unknown";
			context.context.logger.error(
				`An error occurred during ${hookSource} hook matcher execution:`,
				error,
			);
			throw new APIError("INTERNAL_SERVER_ERROR", {
				message:
					"An error occurred during hook matcher execution. Check the logs for more details.",
			});
		}
		if (!matched) continue;

		const hookSource = hooksSourceWeakMap.get(hook.handler) ?? "unknown";
		const route = endpoint.path ?? "/:virtual";
		// `returnHeaders: true` so headers the hook sets via `c.setHeader` /
		// `c.setCookie` come back to us instead of being discarded; the hook's
		// own return value arrives as `result.response`.
		const result = (await withSpan(
			`hook before ${route} ${hookSource}`,
			{
				[ATTR_HOOK_TYPE]: "before",
				[ATTR_HTTP_ROUTE]: route,
				[ATTR_CONTEXT]: hookSource,
				[ATTR_OPERATION_ID]: operationId,
			},
			() =>
				hook.handler({
					...context,
					returnHeaders: true,
				}),
		).catch((e: unknown) => {
			if (
				isAPIError(e) &&
				shouldPublishLog(context.context.logger.level, "debug")
			) {
				e.stack = e.errorStack;
			}
			throw e;
		})) as { response?: unknown; headers?: Headers | null } | undefined;

		mergeResponseHeaders(context.context, result?.headers);

		const hookReturn = result?.response;
		if (hookReturn && typeof hookReturn === "object") {
			if (
				"context" in hookReturn &&
				typeof (hookReturn as { context?: unknown }).context === "object"
			) {
				const { headers, ...rest } = (
					hookReturn as { context: Partial<InternalContext> }
				).context;
				if (headers instanceof Headers) {
					if (modifiedContext.headers) {
						headers.forEach((value, key) => {
							modifiedContext.headers?.set(key, value);
						});
					} else {
						modifiedContext.headers = headers;
					}
				}
				modifiedContext = defuReplaceArrays(rest, modifiedContext);
				continue;
			}
			return hookReturn;
		}
	}
	return { context: modifiedContext };
}

async function runAfterHooks(
	context: InternalContext,
	hooks: Hook[],
	endpoint: Endpoint,
	operationId: string,
) {
	for (const hook of hooks) {
		if (!hook.matcher(context as HookEndpointContext)) continue;

		const hookSource = hooksSourceWeakMap.get(hook.handler) ?? "unknown";
		const route = endpoint.path ?? "/:virtual";
		const result = (await withSpan(
			`hook after ${route} ${hookSource}`,
			{
				[ATTR_HOOK_TYPE]: "after",
				[ATTR_HTTP_ROUTE]: route,
				[ATTR_CONTEXT]: hookSource,
				[ATTR_OPERATION_ID]: operationId,
			},
			() => hook.handler(context),
		).catch((e) => {
			if (isAPIError(e)) {
				if (shouldPublishLog(context.context.logger.level, "debug")) {
					e.stack = e.errorStack;
				}
				return {
					response: e,
					headers: mergeAPIErrorHeaders(e),
				};
			}
			throw e;
		})) as {
			response: unknown;
			headers?: Headers | null;
		};
		mergeResponseHeaders(context.context, result.headers);
		if (result.response !== undefined) {
			context.context.returned = result.response;
		}
	}
	return {
		response: context.context.returned,
		headers: context.context.responseHeaders,
	};
}

function getHooks(authContext: AuthContext) {
	const plugins = authContext.options.plugins || [];
	const beforeHooks: Hook[] = [];
	const afterHooks: Hook[] = [];
	const beforeHookHandler = authContext.options.hooks?.before;
	if (beforeHookHandler) {
		hooksSourceWeakMap.set(beforeHookHandler, "user");
		beforeHooks.push({
			matcher: () => true,
			handler: beforeHookHandler,
		});
	}
	const afterHookHandler = authContext.options.hooks?.after;
	if (afterHookHandler) {
		hooksSourceWeakMap.set(afterHookHandler, "user");
		afterHooks.push({
			matcher: () => true,
			handler: afterHookHandler,
		});
	}
	const pluginBeforeHooks = plugins.flatMap((plugin) =>
		(plugin.hooks?.before ?? []).map((h) => {
			hooksSourceWeakMap.set(h.handler, `plugin:${plugin.id}`);
			return h;
		}),
	);
	const pluginAfterHooks = plugins.flatMap((plugin) =>
		(plugin.hooks?.after ?? []).map((h) => {
			hooksSourceWeakMap.set(h.handler, `plugin:${plugin.id}`);
			return h;
		}),
	);

	// Plugin hooks run after the user-configured hooks.
	if (pluginBeforeHooks.length) beforeHooks.push(...pluginBeforeHooks);
	if (pluginAfterHooks.length) afterHooks.push(...pluginAfterHooks);

	return { beforeHooks, afterHooks };
}

/**
 * Run a single endpoint through the configured `hooks.before` / `hooks.after`
 * pipeline, normalizing the response, headers, and `APIError`s the same way a
 * router or `auth.api.*` dispatch does.
 *
 * This is the canonical hook runner. The HTTP router and `auth.api.*` reach it
 * through {@link toAuthEndpoints}. Plugins call it directly when they need to
 * re-enter the pipeline on purpose, such as resuming `/oauth2/authorize` after
 * a fresh sign-in. Calling an endpoint as a plain function deliberately skips
 * hooks; `dispatchAuthEndpoint` is the supported way to opt back in.
 *
 * @param endpoint The endpoint to dispatch.
 * @param input Input context whose `context` is an already-resolved `AuthContext`.
 */
export async function dispatchAuthEndpoint(
	endpoint: Endpoint,
	input: DispatchContext,
): Promise<unknown> {
	const inheritedRuntimeAuditContext = await getRuntimeAuditRequestContext();
	if (!inheritedRuntimeAuditContext) {
		const operationId = input.operationId ?? getOperationId(endpoint);
		const route = endpoint.path ?? "/:virtual";
		const endpointMethod = endpoint.options?.method;
		const defaultMethod = Array.isArray(endpointMethod)
			? endpointMethod[0]
			: endpointMethod;
		const method = normalizedMethod(
			input.method ?? input.request?.method ?? defaultMethod ?? "DIRECT",
		);
		return runWithRuntimeAuditRequestContext(
			createRuntimeAuditRequestContext(input, operationId, route, method),
			() => dispatchAuthEndpoint(endpoint, input),
		);
	}

	const activeTransaction = await activeDispatchTransaction(input.context);
	const createActiveTransactionError = (
		endpoint as Endpoint & {
			[rejectActiveTransactionSymbol]?: ActiveTransactionRejection;
		}
	)[rejectActiveTransactionSymbol];
	const operationId = input.operationId ?? getOperationId(endpoint);
	const route = endpoint.path ?? "/:virtual";
	const endpointMethod = endpoint.options?.method;
	const defaultMethod = Array.isArray(endpointMethod)
		? endpointMethod[0]
		: endpointMethod;
	const methodName =
		input.method ?? input.request?.method ?? defaultMethod ?? "?";
	const shouldReturnResponse = input.asResponse ?? isRequestLike(input.request);
	if (activeTransaction && createActiveTransactionError) {
		return normalizePreflightAPIError(
			createActiveTransactionError(),
			shouldReturnResponse,
		);
	}

	let internalContext: InternalContext = {
		...input,
		context: {
			...input.context,
			// Direct auth.api calls may enter with a wrapper around the root
			// adapter. Reuse the owning transaction adapter so every nested
			// authority read, mutation, and after-commit hook joins that owner.
			adapter: activeTransaction ?? input.context.adapter,
			returned: undefined,
			responseHeaders: undefined,
			// A fresh dispatch (shared context) has no session; a resumed dispatch
			// carries the in-flight request's session through.
			session: input.context.session ?? null,
		},
		path: endpoint.path,
		headers: input.headers ? new Headers(input.headers) : undefined,
	};

	return withSpan(
		`${methodName} ${route}`,
		{
			[ATTR_HTTP_ROUTE]: route,
			[ATTR_OPERATION_ID]: operationId,
		},
		async () =>
			runWithEndpointContext(internalContext, async () => {
				await assertDispatchCredentialAuthority(internalContext.context);
				const { beforeHooks, afterHooks } = getHooks(internalContext.context);
				const before = await runBeforeHooks(
					internalContext,
					beforeHooks,
					endpoint,
					operationId,
				);
				if (
					"context" in before &&
					before.context &&
					typeof before.context === "object"
				) {
					const { headers, ...rest } = before.context as { headers: Headers };
					// Request-header overrides from the hook merge into the request
					// headers; response headers are already accumulated separately.
					if (headers) {
						if (!internalContext.headers) {
							internalContext.headers = new Headers();
						}
						const requestHeaders = internalContext.headers;
						headers.forEach((value, key) => {
							requestHeaders.set(key, value);
						});
					}
					internalContext = defuReplaceArrays(rest, internalContext);
					if (activeTransaction) {
						// Hook context overrides may not escape the transaction that owns this
						// direct API dispatch.
						internalContext.context.adapter = activeTransaction;
					}
				} else if (before) {
					// A before hook short-circuited. Serialize the response headers it
					// accumulated (`c.setHeader` / `c.setCookie`), not the request headers.
					const responseHeaders = internalContext.context.responseHeaders;
					return shouldReturnResponse
						? toResponse(before, { headers: responseHeaders })
						: input.returnHeaders
							? { headers: responseHeaders, response: before }
							: before;
				}

				internalContext.asResponse = false;
				internalContext.returnHeaders = true;
				internalContext.returnStatus = true;
				const result = (await runWithEndpointContext(internalContext, () =>
						withSpan(
							`handler ${route}`,
							{
								[ATTR_HTTP_ROUTE]: route,
								[ATTR_OPERATION_ID]: operationId,
							},
							() => (endpoint as any)(internalContext as any),
						),
					).catch(async (e: unknown) => {
						if (isAPIError(e)) {
							return {
								response: e,
								status: e.statusCode,
								headers: mergeAPIErrorHeaders(e),
							};
						}
						const continuation = takeStagedAuthenticationContinuation(e);
						if (continuation) {
							const issued = await runWithTransaction(
								internalContext.context.adapter,
								() =>
									issueInitialStagedAuthenticationCapability(
										internalContext.context,
										continuation,
									),
							);
							const headers = new Headers();
							headers.append(
								"set-cookie",
								await serializeSignedCookie(
									issued.cookie.name,
									issued.bearer,
									internalContext.context.secret,
									issued.cookie.attributes,
								),
							);
							headers.set("cache-control", "no-store");
							headers.set("pragma", "no-cache");
							const error = new APIError("FORBIDDEN", {
								code: "MANAGED_AUTHENTICATION_REQUIRED",
								message: "Additional authentication is required",
								allowedFactors: issued.allowedFactors,
								expiresAt: issued.expiresAt.toISOString(),
							});
							return {
								response: error,
								status: error.statusCode,
								headers,
							};
						}
						throw e;
					})) as
					| Response
					| { headers: Headers | null; response: any; status?: number };

				// A raw Response skips after hooks and post-processing.
				if (result instanceof Response) {
					return result;
				}

				internalContext.context.returned = result.response;
				internalContext.context.responseHeaders = result.headers ?? undefined;
				if (isAPIError(result.response)) {
					await appendFailedLoginAudit(
						internalContext.context,
						route,
						result.response,
						result.status ?? result.response.statusCode,
					);
				}

				const managedRemediation =
						isAPIError(result.response) &&
						result.response.body?.code === "MANAGED_AUTHENTICATION_REQUIRED";
				const after = managedRemediation
						? {
								response: result.response,
								headers: result.headers,
							}
						: await runAfterHooks(
								internalContext,
								afterHooks,
								endpoint,
								operationId,
							);
				if (after.response !== undefined) {
					result.response = after.response;
				}
				result.headers = after.headers ?? result.headers;
				if (
					isAPIError(result.response) &&
					shouldPublishLog(internalContext.context.logger.level, "debug")
				) {
					result.response.stack = result.response.errorStack;
				}

				if (isAPIError(result.response) && !shouldReturnResponse) {
					// Non-response path: re-throw the raw APIError to `auth.api.*`
					// callers, attaching the merged headers so an outer pipeline sees
					// the same set we would have written on a response.
					if (result.headers) {
						Object.defineProperty(result.response, kAPIErrorHeaderSymbol, {
							enumerable: false,
							configurable: true,
							writable: false,
							value: result.headers,
						});
					}
					throw result.response;
				}

				return shouldReturnResponse
					? toResponse(result.response, {
							headers: result.headers ?? undefined,
							status: result.status,
						})
					: input.returnHeaders
						? input.returnStatus
							? {
									headers: result.headers,
									response: result.response,
									status: result.status,
								}
							: {
									headers: result.headers,
									response: result.response,
								}
						: input.returnStatus
							? { response: result.response, status: result.status }
							: result.response;
			}),
	);
}
