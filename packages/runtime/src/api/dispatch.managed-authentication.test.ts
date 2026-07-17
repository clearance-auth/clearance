import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyReaderInput,
	RuntimeAuthenticationPolicyReaderResult,
} from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import {
	runWithRequestState,
	runWithTransaction,
} from "@clearance/core/context";
import type { Endpoint } from "@clearance/call";
import { afterEach, describe, expect, it, vi } from "vitest";
import { init } from "../context/init";
import { getMigrations } from "../db/get-migration";
import { passkey } from "../plugins/passkey";
import { twoFactor } from "../plugins/two-factor";
import {
	attachInternalAuthenticationPolicy,
	type InternalRuntimeAuthenticationPolicyBinding,
} from "../internal/authentication-policy";
import {
	createInternalSessionIssuanceContext,
	ManagedSessionIssuanceError,
} from "../internal/session-issuance-context";
import {
	consumePreloadedStagedAuthenticationCapability,
	createStagedSessionIssuanceContext,
	inspectStagedAuthenticationAuthority,
	preloadStagedAuthenticationCapability,
	rotateStagedAuthenticationCapability,
} from "../internal/staged-authentication-context";
import type { Session } from "../types";
import { dispatchAuthEndpoint } from "./dispatch";

const databases: DatabaseSync[] = [];
const identity = Object.freeze({
	projectId: "managed-stage-project",
	environmentId: "managed-stage-environment",
});

function policy(
	override: Partial<RuntimeAuthenticationPolicy> = {},
): RuntimeAuthenticationPolicy {
	return {
		passwordLockout: {
			enabled: true,
			maxFailedAttempts: 10,
			durationSeconds: 900,
		},
		factorLockout: {
			enabled: true,
			maxFailedAttempts: 10,
			durationSeconds: 900,
		},
		minimumAssurance: "multi_factor",
		allowedFactors: { passkey: true, totp: true },
		trustedDevice: { enabled: false, maxAgeSeconds: 0 },
		assuranceMaxAgeSeconds: 300,
		...override,
	};
}

async function setup() {
	const database = new DatabaseSync(":memory:");
	databases.push(database);
	let revision = "7";
	let effective = policy();
	let afterHookCalls = 0;
	const options = {
		baseURL: "http://localhost:3000",
		secret: "managed-staged-dispatch-secret-with-sufficient-length",
		database,
		plugins: [passkey(), twoFactor()],
		hooks: {
			after: createAuthMiddleware(async (ctx) => {
				if (ctx.path !== "/managed-stage/start") return;
				afterHookCalls += 1;
				return { replaced: true };
			}),
		},
	} satisfies ClearanceOptions;
	const reader = {
		async readForSubject(
			input: RuntimeAuthenticationPolicyReaderInput,
		): Promise<RuntimeAuthenticationPolicyReaderResult> {
			return {
				scope: identity,
				subjectId: input.subjectId,
				revision,
				environment: effective,
				organizationMembership: null,
				organizationOverride: null,
				effective,
			};
		},
	} satisfies InternalRuntimeAuthenticationPolicyBinding["reader"];
	attachInternalAuthenticationPolicy(options, { identity, reader });
	await (await getMigrations(options)).runMigrations();
	const context = await init(options);
	const user = await context.internalAdapter.createUser({
		email: `managed-stage-${databases.length}@example.test`,
		name: "Managed stage user",
	});
	return {
		context,
		user,
		get afterHookCalls() {
			return afterHookCalls;
		},
		setRevision(value: string) {
			revision = value;
		},
		setEffective(value: RuntimeAuthenticationPolicy) {
			effective = value;
		},
	};
}

function issuanceEndpoint(userId: string) {
	return createAuthEndpoint(
		"/managed-stage/start",
		{ method: "POST" },
		async (ctx) => {
			await ctx.context.internalAdapter.createSession(
				userId,
				false,
				undefined,
				false,
				createInternalSessionIssuanceContext({
					purpose: "interactive",
					subjectId: userId,
					evidence: [{ kind: "primary", primaryMethod: "password" }],
				}),
			);
			return ctx.json({ unexpected: true });
		},
	);
}

async function dispatch(
	context: Awaited<ReturnType<typeof init>>,
	endpoint: Endpoint,
	cookie?: string,
): Promise<Response> {
	const headers = new Headers(cookie ? { cookie } : undefined);
	return runWithRequestState(
		new WeakMap(),
		async () =>
			(await dispatchAuthEndpoint(endpoint, {
				context,
				headers,
				request: new Request(`http://localhost:3000${endpoint.path}`, {
					method: "POST",
					headers,
				}),
				asResponse: true,
			})) as Response,
	);
}

function remediationCookie(response: Response): {
	header: string;
	bearer: string;
} {
	const setCookie = response.headers.get("set-cookie");
	expect(setCookie).toBeTruthy();
	const header = setCookie!.split(";", 1)[0]!;
	const signed = decodeURIComponent(header.slice(header.indexOf("=") + 1));
	const separator = signed.lastIndexOf(".");
	expect(separator).toBeGreaterThan(0);
	return { header, bearer: signed.slice(0, separator) };
}

async function sessionRows(context: Awaited<ReturnType<typeof init>>) {
	return context.adapter.findMany<Session>({ model: "session" });
}

afterEach(() => {
	vi.useRealTimers();
	for (const database of databases.splice(0)) database.close();
});

describe("managed staged authentication dispatch", () => {
	it("creates no authority before dispatch conversion and rejects forged contexts", async () => {
		const runtime = await setup();
		await expect(
			runtime.context.internalAdapter.createSession(
				runtime.user.id,
				false,
				undefined,
				false,
				createInternalSessionIssuanceContext({
					purpose: "interactive",
					subjectId: runtime.user.id,
					evidence: [{ kind: "primary", primaryMethod: "password" }],
				}),
			),
		).rejects.toMatchObject({ reason: "policy_unsatisfied" });
		expect(await sessionRows(runtime.context)).toHaveLength(0);
		expect(
			await runtime.context.adapter.count({ model: "sessionCredential" }),
		).toBe(0);
		expect(await runtime.context.adapter.count({ model: "verification" })).toBe(0);

		await expect(
			runtime.context.internalAdapter.createSession(
				runtime.user.id,
				false,
				undefined,
				false,
				{ purpose: "staged" } as never,
			),
		).rejects.toBeInstanceOf(ManagedSessionIssuanceError);
	});

	it("converts only the authentic rejection into a digest-only no-store remediation", async () => {
		const runtime = await setup();
		const response = await dispatch(
			runtime.context,
			issuanceEndpoint(runtime.user.id),
		);
		expect(response.status).toBe(403);
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(response.headers.get("pragma")).toBe("no-cache");
		expect(runtime.afterHookCalls).toBe(0);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body).toMatchObject({
			code: "MANAGED_AUTHENTICATION_REQUIRED",
			allowedFactors: ["passkey", "totp"],
		});
		const { bearer } = remediationCookie(response);
		expect(JSON.stringify(body)).not.toContain(bearer);
		const verificationRows = await runtime.context.adapter.findMany<
			Record<string, unknown>
		>({ model: "verification" });
		expect(verificationRows).toHaveLength(1);
		expect(JSON.stringify(verificationRows)).not.toContain(bearer);
		expect(String(verificationRows[0]?.identifier)).toMatch(
			/^managed-authentication-remediation:v1:/,
		);
		expect(await sessionRows(runtime.context)).toHaveLength(0);
		expect(
			await runtime.context.adapter.count({ model: "sessionCredential" }),
		).toBe(0);
	});

	it("enforces stage and binding and allows one concurrent consume winner", async () => {
		const runtime = await setup();
		const start = await dispatch(
			runtime.context,
			issuanceEndpoint(runtime.user.id),
		);
		const cookie = remediationCookie(start).header;
		const wrong = createAuthEndpoint(
			"/managed-stage/wrong",
			{ method: "POST" },
			async (ctx) =>
				ctx.json({
					accepted: Boolean(
						await preloadStagedAuthenticationCapability(ctx, {
							stage: "passkey_authentication",
							binding: "wrong",
						}),
					),
				}),
		);
		expect(await (await dispatch(runtime.context, wrong, cookie)).json()).toEqual({
			accepted: false,
		});

		const consume = createAuthEndpoint(
			"/managed-stage/consume",
			{ method: "POST" },
			async (ctx) => {
				const preloaded = await preloadStagedAuthenticationCapability(ctx, {
					stage: "select_factor",
					binding: "initial",
				});
				if (!preloaded) return ctx.json({ accepted: false });
				const accepted = await runWithTransaction(
					ctx.context.adapter,
					() =>
						consumePreloadedStagedAuthenticationCapability(ctx, preloaded),
				);
				return ctx.json({ accepted: Boolean(accepted) });
			},
		);
		const results = await Promise.all([
			dispatch(runtime.context, consume, cookie),
			dispatch(runtime.context, consume, cookie),
		]);
		const bodies = await Promise.all(results.map((result) => result.json()));
		expect(bodies.filter((body) => body.accepted === true)).toHaveLength(1);
		expect(
			await (await dispatch(runtime.context, consume, cookie)).json(),
		).toEqual({ accepted: false });
	});

	it("preloads TOTP without a caller-known binding but authorizes only after consume", async () => {
		const runtime = await setup();
		const start = await dispatch(
			runtime.context,
			issuanceEndpoint(runtime.user.id),
		);
		const initialCookie = remediationCookie(start).header;
		const totpBinding = "server-only-totp-enrollment";
		const rotate = createAuthEndpoint(
			"/managed-stage/totp-select",
			{ method: "POST" },
			async (ctx) => {
				const preloaded = await preloadStagedAuthenticationCapability(ctx, {
					stage: "select_factor",
					binding: "initial",
				});
				if (!preloaded) return ctx.json({ rotated: false });
				const rotated = await runWithTransaction(
					ctx.context.adapter,
					async () => {
						const authority =
							await consumePreloadedStagedAuthenticationCapability(
								ctx,
								preloaded,
							);
						if (!authority) return false;
						await rotateStagedAuthenticationCapability(ctx, authority, {
							stage: "totp_enrollment_verification",
							binding: totpBinding,
						});
						return true;
					},
				);
				return ctx.json({ rotated });
			},
		);
		const rotated = await dispatch(runtime.context, rotate, initialCookie);
		expect(await rotated.clone().json()).toEqual({ rotated: true });
		const totpCookie = remediationCookie(rotated).header;

		const wrongStage = createAuthEndpoint(
			"/managed-stage/totp-wrong-stage",
			{ method: "POST" },
			async (ctx) =>
				ctx.json({
					preloaded: Boolean(
						await preloadStagedAuthenticationCapability(ctx, {
							stage: "passkey_authentication",
						}),
					),
				}),
		);
		expect(
			await (await dispatch(runtime.context, wrongStage, totpCookie)).json(),
		).toEqual({ preloaded: false });

		const preloadOnly = createAuthEndpoint(
			"/managed-stage/totp-preload-only",
			{ method: "POST" },
			async (ctx) => {
				const preloaded = await preloadStagedAuthenticationCapability(ctx, {
					stage: "totp_enrollment_verification",
				});
				let issued = false;
				if (preloaded) {
					await runWithTransaction(ctx.context.adapter, async () => {
						try {
							await createStagedSessionIssuanceContext(ctx, preloaded, {
								factorMethod: "totp",
								factorAt: new Date(),
								binding: totpBinding,
							});
							issued = true;
						} catch {}
					});
				}
				return ctx.json({
					preloaded: Boolean(preloaded),
					inspected: Boolean(
						preloaded && inspectStagedAuthenticationAuthority(preloaded),
					),
					issued,
				});
			},
		);
		expect(
			await (await dispatch(runtime.context, preloadOnly, totpCookie)).json(),
		).toEqual({ preloaded: true, inspected: false, issued: false });

		const consume = createAuthEndpoint(
			"/managed-stage/totp-consume",
			{ method: "POST" },
			async (ctx) => {
				const preloaded = await preloadStagedAuthenticationCapability(ctx, {
					stage: "totp_enrollment_verification",
				});
				if (!preloaded) return ctx.json({ accepted: false });
				const view = await runWithTransaction(
					ctx.context.adapter,
					async () => {
						const authority =
							await consumePreloadedStagedAuthenticationCapability(
								ctx,
								preloaded,
							);
						return authority
							? inspectStagedAuthenticationAuthority(authority)
							: null;
					},
				);
				return ctx.json({ accepted: Boolean(view), binding: view?.binding });
			},
		);
		expect(
			await (await dispatch(runtime.context, consume, totpCookie)).json(),
		).toEqual({ accepted: true, binding: totpBinding });
	});
});
