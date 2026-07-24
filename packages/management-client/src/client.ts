import {
	ManagementApiError,
	managementApiErrorFromResponse,
} from "./error.js";
import {
	resolveOperationPath,
	type AnyOperationSpec,
	type ApiPath,
	type OperationInput,
	type OperationOutput,
	type OperationRegistry,
} from "./spec.js";

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface ManagementResponse<Output> {
	readonly data: Output;
	readonly requestId?: string;
	/** Reuse only for an identical mutation retry. */
	readonly idempotencyKey?: string;
	readonly idempotencyReplayed: boolean;
}

export interface ManagementCallOptions<Operation extends AnyOperationSpec> {
	readonly confirm?: true;
	readonly idempotencyKey?: string;
	readonly signal?: AbortSignal;
}

export interface ManagementClient<Registry extends OperationRegistry> {
	call<Id extends keyof Registry & string>(
		id: Id,
		input: OperationInput<Registry[Id]>,
		options?: ManagementCallOptions<Registry[Id]>,
	): Promise<ManagementResponse<OperationOutput<Registry[Id]>>>;
}

interface ManagementClientConfig<Registry extends OperationRegistry> {
	readonly baseUrl: string;
	readonly registry: Registry;
	readonly fetch: FetchLike;
	readonly credentials?: RequestCredentials;
	readonly headers?: Readonly<Record<string, string>>;
	readonly authorization?: string;
	readonly csrf?: { readonly header: string; readonly token: string };
	readonly createIdempotencyKey?: () => string;
}

const VISIBLE_ASCII_KEY = /^[\x21-\x7e]{1,200}$/;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const TRANSPORT_KEY = /^[A-Za-z][A-Za-z0-9_]*$/;
const API_PATH = /^\/v1(?:\/(?:[A-Za-z0-9._~!$&'()*+,;=@%-]+|:[A-Za-z][A-Za-z0-9_]*))+$/;
const HTTP_METHODS = new Set(["GET", "POST", "PATCH", "DELETE"]);
const CONFIRMATIONS = new Set(["none", "client-required", "client-required-when-live", "server-required"]);
const BASE_PROTECTED_HEADERS = new Set(["authorization", "idempotency-key", "accept", "content-type"]);
const OPERATION_KEYS = new Set(["id", "http", "mutation", "supportsDryRun", "confirmation", "confirmationWhen", "schemas", "transport"]);
const HTTP_KEYS = new Set(["method", "path", "currentPath"]);
const SCHEMA_KEYS = new Set(["input", "output"]);
const TRANSPORT_KEYS = new Set(["path", "query", "body"]);
const CONDITION_KEYS = new Set(["inputKey", "equals"]);

function protocolError(message: string, response?: Response, idempotencyKey?: string): ManagementApiError {
	return new ManagementApiError({
		code: "MANAGEMENT_PROTOCOL_ERROR",
		message,
		status: response?.status ?? 0,
		stage: "management-client.protocol",
		remediation: "Check that the API route and generated operation registry use the same contract version.",
		retryable: false,
		requestId: response?.headers.get("x-request-id") ?? undefined,
		idempotencyKey,
	});
}

function normalizedBaseUrl(baseUrl: string, mode: "browser" | "server"): string {
	const trimmed = baseUrl.trim();
	const normalized = trimmed.replace(/\/+$/, "");
	const invalid = (message: string) => new ManagementApiError({
		code: "MANAGEMENT_CLIENT_BASE_URL_INVALID",
		message,
		status: 0,
		stage: "management-client.config",
		remediation: mode === "server"
			? "Use HTTPS, or explicit HTTP only on localhost or a loopback IP during development."
			: "Pass a same-origin path such as /api or a credential-free HTTP(S) URL without query or fragment.",
	});
	if (trimmed.startsWith("//")) throw invalid("Protocol-relative Management API URLs are forbidden.");
	if (trimmed.includes("\\")) throw invalid("Management API URLs cannot contain backslashes.");
	if (mode === "browser" && (normalized === "" || normalized.startsWith("/"))) {
		if (/[?#\\]/.test(normalized)) throw invalid("Browser Management API paths cannot contain query, fragment, or backslash components.");
		let parsed: URL;
		try {
			parsed = new URL(normalized || "/", "https://clearance.invalid");
			decodeURI(parsed.pathname);
		} catch {
			throw invalid("Browser management client baseUrl is malformed.");
		}
		if (parsed.origin !== "https://clearance.invalid" || parsed.search || parsed.hash || parsed.pathname !== (normalized || "/")) {
			throw invalid("Browser management client baseUrl must be a normalized same-origin path.");
		}
		return normalized;
	}
	let parsed: URL;
	const absoluteMatch = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*)([^?#]*)/.exec(trimmed);
	if (!absoluteMatch) throw invalid("Management client baseUrl must be an absolute HTTP(S) URL.");
	const suppliedPath = absoluteMatch[2] ?? "";
	if (suppliedPath.includes("%") || /\/(?:\.|\.\.)(?:\/|$)/.test(suppliedPath)) {
		throw invalid("Management client baseUrl path cannot contain encoded separators or traversal segments.");
	}
	if (suppliedPath.includes("//") || (suppliedPath.length > 1 && suppliedPath.endsWith("/"))) {
		throw invalid("Management client baseUrl path must not contain empty segments or a non-root trailing slash.");
	}
	try {
		decodeURI(suppliedPath);
		parsed = new URL(trimmed);
	} catch {
		throw invalid("Management client baseUrl must be an absolute HTTP(S) URL.");
	}
	if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.username || parsed.password || parsed.search || parsed.hash) {
		throw invalid("Management client baseUrl must be credential-free HTTP(S) without query or fragment.");
	}
	if (parsed.protocol === "http:" && !isLoopbackHost(parsed.hostname)) {
		throw invalid(mode === "server"
			? "Server bearer transport requires HTTPS outside explicit loopback development."
			: "Browser credential transport requires HTTPS outside explicit loopback development.");
	}
	if (parsed.pathname !== (suppliedPath || "/")) {
		throw invalid("Management client baseUrl path must already be canonical and cannot change during URL normalization.");
	}
	return `${parsed.origin}${parsed.pathname === "/" ? "" : parsed.pathname}`;
}

function isLoopbackHost(hostname: string): boolean {
	const lower = hostname.toLowerCase();
	if (lower === "localhost" || lower.endsWith(".localhost") || lower === "[::1]" || lower === "::1") return true;
	const octets = lower.split(".");
	return octets.length === 4 && octets[0] === "127" && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function isCanonicalApiPath(value: unknown): value is ApiPath {
	if (typeof value !== "string" || !API_PATH.test(value) || value.includes("%")) return false;
	try {
		decodeURI(value);
		const normalized = new URL(value, "https://clearance.invalid");
		return normalized.origin === "https://clearance.invalid" && !normalized.search && !normalized.hash && normalized.pathname === value;
	} catch {
		return false;
	}
}

function generatedIdempotencyKey(): string {
	const randomUuid = globalThis.crypto?.randomUUID;
	if (!randomUuid) throw new ManagementApiError({
		code: "MANAGEMENT_CLIENT_IDEMPOTENCY_UNAVAILABLE",
		message: "The runtime cannot generate an idempotency key.",
		status: 0,
		stage: "management-client.idempotency",
		remediation: "Provide idempotencyKey explicitly or configure a crypto-capable runtime.",
	});
	return randomUuid.call(globalThis.crypto);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(record: Record<string, unknown>, allowed: ReadonlySet<string>, label: string): void {
	const unexpected = Object.keys(record).find((key) => !allowed.has(key));
	if (unexpected) throw protocolError(`${label} contains unexpected key ${unexpected}.`);
}

function schemaAccepts(schema: unknown, value: unknown): boolean {
	if (!isRecord(schema) || typeof schema.safeParse !== "function") return false;
	try {
		return (schema.safeParse(value) as { success?: unknown }).success === true;
	} catch {
		return false;
	}
}

function schemaParsesTo(schema: unknown, value: unknown, expected: unknown): boolean {
	if (!isRecord(schema) || typeof schema.safeParse !== "function") return false;
	try {
		const result = schema.safeParse(value) as { success?: unknown; data?: unknown };
		return result.success === true && Object.is(result.data, expected);
	} catch {
		return false;
	}
}

function schemaParseResult(schema: unknown, value: unknown): { success: boolean; data?: unknown } {
	if (!isRecord(schema) || typeof schema.safeParse !== "function") return { success: false };
	try {
		const result = schema.safeParse(value) as { success?: unknown; data?: unknown };
		return result.success === true ? { success: true, data: result.data } : { success: false };
	} catch {
		return { success: false };
	}
}

function schemaShape(value: unknown, operationId: string): Record<string, unknown> {
	if (!isRecord(value) || typeof value.safeParse !== "function") {
		throw protocolError(`${operationId} input schema must expose safeParse.`);
	}
	const definition = isRecord(value.def) ? value.def : undefined;
	if (definition?.type === "union" && Array.isArray(definition.options) && definition.options.length > 0) {
		const shapes = definition.options.map((option) => schemaShape(option, operationId));
		const fields = new Map<string, unknown[]>();
		for (const shape of shapes) {
			for (const [key, schema] of Object.entries(shape)) {
				const variants = fields.get(key) ?? [];
				variants.push(schema);
				fields.set(key, variants);
			}
		}
		return Object.fromEntries([...fields].map(([key, variants]) => [
			key,
			{
				safeParse(input: unknown) {
					for (const schema of variants) {
						const parsed = schemaParseResult(schema, input);
						if (parsed.success) return { success: true, data: parsed.data };
					}
					return { success: false };
				},
			},
		]));
	}
	const catchall = definition && isRecord(definition.catchall) ? definition.catchall : undefined;
	const catchallDefinition = catchall && isRecord(catchall.def) ? catchall.def : undefined;
	if (definition?.type !== "object" || catchallDefinition?.type !== "never" || !isRecord(definition.shape)) {
		throw protocolError(`${operationId} input schema must be a strict Zod object or a union of strict Zod objects.`);
	}
	return definition.shape;
}

function assertOutputSchema(value: unknown, operationId: string): void {
	if (!isRecord(value) || typeof value.safeParse !== "function") {
		throw protocolError(`${operationId} output schema must expose safeParse.`);
	}
}

function transportKeys(value: unknown, label: string): string[] {
	if (!Array.isArray(value) || value.some((key) => typeof key !== "string" || !TRANSPORT_KEY.test(key))) {
		throw protocolError(`${label} must be an array of logical input keys.`);
	}
	return value;
}

function pathProjection(value: unknown, label: string): Array<readonly [string, string]> {
	if (Array.isArray(value)) {
		if (value.some((key) => typeof key !== "string" || !TRANSPORT_KEY.test(key))) {
			throw protocolError(`${label} must map semantic input keys to route placeholders.`);
		}
		return value.map((key) => [key, key] as const);
	}
	if (!isRecord(value)) throw protocolError(`${label} must map semantic input keys to route placeholders.`);
	const entries = Object.entries(value);
	if (entries.some(([semantic, placeholder]) => !TRANSPORT_KEY.test(semantic) ||
		typeof placeholder !== "string" || !TRANSPORT_KEY.test(placeholder))) {
		throw protocolError(`${label} must map semantic input keys to route placeholders.`);
	}
	if (new Set(entries.map(([, placeholder]) => placeholder)).size !== entries.length) {
		throw protocolError(`${label} cannot map multiple semantic input keys to one route placeholder.`);
	}
	return entries as Array<readonly [string, string]>;
}

function queryProjection(value: unknown, label: string): Array<readonly [string, string]> {
	if (Array.isArray(value)) {
		if (value.some((key) => typeof key !== "string" || !TRANSPORT_KEY.test(key))) {
			throw protocolError(`${label} must map semantic input keys to HTTP query keys.`);
		}
		return value.map((key) => [key, key] as const);
	}
	if (!isRecord(value)) throw protocolError(`${label} must map semantic input keys to HTTP query keys.`);
	const entries = Object.entries(value);
	if (entries.some(([semantic, wire]) => !TRANSPORT_KEY.test(semantic) ||
		typeof wire !== "string" || !TRANSPORT_KEY.test(wire))) {
		throw protocolError(`${label} must map semantic input keys to HTTP query keys.`);
	}
	if (new Set(entries.map(([, wire]) => wire)).size !== entries.length) {
		throw protocolError(`${label} cannot map multiple semantic input keys to one HTTP query key.`);
	}
	return entries as Array<readonly [string, string]>;
}

function assertRegistry(registry: OperationRegistry): void {
	if (!isRecord(registry)) throw protocolError("Operation registry must be an object.");
	for (const [registryKey, untrusted] of Object.entries(registry)) {
		if (!OPERATION_ID.test(registryKey)) throw protocolError(`Registry key ${registryKey} is invalid.`);
		if (!isRecord(untrusted)) throw protocolError(`Registry operation ${registryKey} must be an object.`);
		const operation = untrusted as Record<string, unknown>;
		assertExactKeys(operation, OPERATION_KEYS, `Registry operation ${registryKey}`);
		if (typeof operation.id !== "string" || !OPERATION_ID.test(operation.id) || registryKey !== operation.id) {
			throw protocolError(`Registry key ${registryKey} must match a valid descriptor id.`);
		}
		const operationId = operation.id;
		if (!isRecord(operation.http)) throw protocolError(`${operationId} http must be an object.`);
		assertExactKeys(operation.http, HTTP_KEYS, `${operationId} http`);
		if (!HTTP_METHODS.has(operation.http.method as string) || !isCanonicalApiPath(operation.http.path) ||
			(operation.http.currentPath !== undefined && !isCanonicalApiPath(operation.http.currentPath))) {
			throw protocolError(`${operationId} must declare a valid method and /v1 path.`);
		}
		if (typeof operation.mutation !== "boolean" || typeof operation.supportsDryRun !== "boolean") {
			throw protocolError(`${operationId} mutation and supportsDryRun must be booleans.`);
		}
		if (typeof operation.confirmation !== "string" || !CONFIRMATIONS.has(operation.confirmation)) {
			throw protocolError(`${operationId} has an invalid confirmation policy.`);
		}
		if (!isRecord(operation.schemas)) throw protocolError(`${operationId} schemas must be an object.`);
		assertExactKeys(operation.schemas, SCHEMA_KEYS, `${operationId} schemas`);
		const inputShape = schemaShape(operation.schemas.input, operationId);
		const fields = new Set(Object.keys(inputShape));
		assertOutputSchema(operation.schemas.output, operationId);
		if (!isRecord(operation.transport)) throw protocolError(`${operationId} transport must be an object.`);
		assertExactKeys(operation.transport, TRANSPORT_KEYS, `${operationId} transport`);
		const pathProjectionEntries = pathProjection(operation.transport.path, `${operationId} transport.path`);
		const pathKeys = pathProjectionEntries.map(([semantic]) => semantic);
		const routePlaceholders = pathProjectionEntries.map(([, placeholder]) => placeholder);
		const queryProjectionEntries = queryProjection(operation.transport.query, `${operationId} transport.query`);
		const queryKeys = queryProjectionEntries.map(([semantic]) => semantic);
		const bodyKeys = transportKeys(operation.transport.body, `${operationId} transport.body`);
		const projections = [...pathKeys, ...queryKeys, ...bodyKeys];
		if (new Set(projections).size !== projections.length || projections.length !== fields.size || projections.some((key) => !fields.has(key))) {
			throw protocolError(`${operationId} must project every logical input key exactly once.`);
		}
		const routeParams = [...operation.http.path.matchAll(/:([A-Za-z][A-Za-z0-9_]*)/g)].map((match) => match[1]!);
		if (new Set(routeParams).size !== routeParams.length || routeParams.length !== pathKeys.length || routeParams.some((key) => !routePlaceholders.includes(key))) {
			throw protocolError(`${operationId} must project every route parameter exactly once into path.`);
		}
		if (operation.http.method === "GET" && (bodyKeys.length > 0 || operation.confirmation === "server-required")) {
			throw protocolError(`${operationId} GET operation cannot project or synthesize a request body.`);
		}
		const dryRunSchema = inputShape.dryRun;
		const booleanCompatibleDryRun = schemaParsesTo(dryRunSchema, true, true) && schemaParsesTo(dryRunSchema, false, false) &&
			!schemaAccepts(dryRunSchema, "true") && !schemaAccepts(dryRunSchema, 1) && !schemaAccepts(dryRunSchema, null);
		if ((operation.supportsDryRun === true && !booleanCompatibleDryRun) ||
			(operation.supportsDryRun === false && fields.has("dryRun"))) {
			throw protocolError(`${operationId} supportsDryRun must exactly match a boolean-compatible dryRun input field.`);
		}
		if (operation.http.currentPath !== undefined) {
			if (pathKeys.length !== 1 || routeParams.length !== 1 || operation.http.currentPath === operation.http.path ||
				operation.http.currentPath.includes(":") || !schemaParsesTo(inputShape[pathKeys[0]!], undefined, undefined)) {
				throw protocolError(`${operationId} currentPath requires one optional semantic path key and a parameter-free alternate path.`);
			}
		}
		if (operation.confirmation === "client-required-when-live") {
			if (!isRecord(operation.confirmationWhen) || typeof operation.confirmationWhen.inputKey !== "string" ||
				!TRANSPORT_KEY.test(operation.confirmationWhen.inputKey) || !fields.has(operation.confirmationWhen.inputKey) ||
				!("equals" in operation.confirmationWhen) ||
				!(["string", "number", "boolean"].includes(typeof operation.confirmationWhen.equals) || operation.confirmationWhen.equals === null) ||
				(typeof operation.confirmationWhen.equals === "number" && !Number.isFinite(operation.confirmationWhen.equals))) {
				throw protocolError(`${operationId} must declare a valid semantic live-input condition.`);
			}
			assertExactKeys(operation.confirmationWhen, CONDITION_KEYS, `${operationId} confirmationWhen`);
			const conditionSchema = inputShape[operation.confirmationWhen.inputKey];
			const conditionAccepted = schemaParsesTo(
				conditionSchema,
				operation.confirmationWhen.equals,
				operation.confirmationWhen.equals,
			);
			if (!conditionAccepted) {
				throw protocolError(`${operationId} live-input condition must be accepted by its semantic field schema.`);
			}
			if (!projections.includes(operation.confirmationWhen.inputKey)) {
				throw protocolError(`${operationId} live-input condition must be projected onto the wire.`);
			}
			const omitted = schemaParseResult(conditionSchema, undefined);
			if (omitted.success) {
				const nonLive = omitted.data !== undefined &&
					(["string", "boolean"].includes(typeof omitted.data) ||
						(typeof omitted.data === "number" && Number.isFinite(omitted.data)) || omitted.data === null) &&
					!Object.is(omitted.data, operation.confirmationWhen.equals);
				if (!nonLive) {
					throw protocolError(`${operationId} omitted live-input must parse to an explicit non-live semantic value.`);
				}
			}
		} else if (operation.confirmationWhen !== undefined) {
			throw protocolError(`${operationId} cannot declare a live-input condition for ${operation.confirmation}.`);
		}
	}
}

function snapshotRegistry<Registry extends OperationRegistry>(registry: Registry): Registry {
	assertRegistry(registry);
	const snapshot = Object.create(null) as Record<string, AnyOperationSpec>;
	for (const [id, operation] of Object.entries(registry)) {
		snapshot[id] = Object.freeze({
			...operation,
			http: Object.freeze({ ...operation.http }),
			schemas: Object.freeze({ ...operation.schemas }),
			transport: Object.freeze({
				path: Object.freeze(Array.isArray(operation.transport.path)
					? [...operation.transport.path]
					: { ...operation.transport.path }),
				query: Object.freeze(Array.isArray(operation.transport.query)
					? [...operation.transport.query]
					: { ...operation.transport.query }),
				body: Object.freeze([...operation.transport.body]),
			}),
			confirmationWhen: operation.confirmationWhen
				? Object.freeze({ ...operation.confirmationWhen })
				: undefined,
		});
	}
	return Object.freeze(snapshot) as Registry;
}

function assertTransportHeaders(config: ManagementClientConfig<OperationRegistry>): void {
	const protectedHeaders = new Set(BASE_PROTECTED_HEADERS);
	if (config.csrf) {
		if (!config.csrf.header.trim() || !config.csrf.token) throw protocolError("CSRF header and token must be non-empty.");
		const csrfHeader = config.csrf.header.toLowerCase();
		if (BASE_PROTECTED_HEADERS.has(csrfHeader)) throw protocolError(`CSRF header ${config.csrf.header} conflicts with protected transport authority.`);
		try {
			new Headers([[config.csrf.header, config.csrf.token]]);
		} catch {
			throw protocolError("CSRF header or token is invalid.");
		}
		protectedHeaders.add(csrfHeader);
	}
	const customHeaders = new Set<string>();
	for (const [name, value] of Object.entries(config.headers ?? {})) {
		const normalizedName = name.toLowerCase();
		if (protectedHeaders.has(normalizedName)) throw protocolError(`Custom header ${name} is transport-protected.`);
		if (customHeaders.has(normalizedName)) throw protocolError(`Custom header ${name} is duplicated case-insensitively.`);
		customHeaders.add(normalizedName);
		if (typeof value !== "string") throw protocolError(`Custom header ${name} must be a string.`);
		try {
			new Headers([[name, value]]);
		} catch {
			throw protocolError(`Custom header ${name} is invalid.`);
		}
	}
}

function requireConfirmation(
	operation: AnyOperationSpec,
	logicalInput: Record<string, unknown>,
	options: ManagementCallOptions<AnyOperationSpec>,
): void {
	if (operation.supportsDryRun && logicalInput.dryRun === true) return;
	const live = operation.confirmation === "client-required-when-live" && operation.confirmationWhen !== undefined
		? Object.is(logicalInput[operation.confirmationWhen.inputKey], operation.confirmationWhen.equals)
		: false;
	const required = operation.confirmation === "client-required" ||
		operation.confirmation === "server-required" ||
		live;
	if (!required || options.confirm === true) return;
	throw new ManagementApiError({
		code: "MANAGEMENT_CLIENT_CONFIRMATION_REQUIRED",
		message: `${operation.id} requires explicit confirmation before it can run.`,
		status: 0,
		stage: "management-client.confirmation",
		remediation: "Review the operation and call it again with confirm: true.",
	});
}

function queryPath(path: ApiPath, query: unknown): ApiPath {
	if (!query || typeof query !== "object" || Array.isArray(query)) throw protocolError("Query schema must produce an object.");
	const params = new URLSearchParams();
	for (const [key, value] of Object.entries(query as Record<string, unknown>)) {
		if (value === undefined || value === null) continue;
		if (Array.isArray(value)) {
			for (const entry of value) {
				if (!isQueryScalar(entry)) throw protocolError(`Query schema produced unsupported ${key} array entry.`);
				params.append(key, String(entry));
			}
		} else if (isQueryScalar(value)) {
			params.set(key, String(value));
		} else {
			throw protocolError(`Query schema produced unsupported ${key} value.`);
		}
	}
	const serialized = params.toString();
	return (serialized ? `${path}?${serialized}` : path) as ApiPath;
}

function isQueryScalar(value: unknown): value is string | number | boolean {
	return typeof value === "string" || typeof value === "boolean" ||
		(typeof value === "number" && Number.isFinite(value));
}

async function responsePayload(response: Response): Promise<unknown> {
	if (response.status === 204) return undefined;
	const text = await response.text();
	if (!text) return undefined;
	try {
		return JSON.parse(text) as unknown;
	} catch {
		return undefined;
	}
}

function parseInput(operation: AnyOperationSpec, input: OperationInput<AnyOperationSpec>) {
	const parsed = operation.schemas.input.safeParse(input);
	if (!parsed.success) throw protocolError(`${operation.id} input failed validation.`);
	if (!parsed.data || typeof parsed.data !== "object" || Array.isArray(parsed.data)) {
		throw protocolError(`${operation.id} input schema must produce an object.`);
	}
	const logical = parsed.data as Record<string, unknown>;
	const project = (keys: readonly string[]) => Object.fromEntries(keys.map((key) => [key, logical[key]]));
	const projectQuery = (projection: AnyOperationSpec["transport"]["query"]) => Object.fromEntries(
		(Array.isArray(projection) ? projection.map((key) => [key, key] as const) : Object.entries(projection))
			.map(([semantic, wire]) => [wire, logical[semantic]]),
	);
	return {
		logical,
		path: project(Array.isArray(operation.transport.path)
			? operation.transport.path
			: Object.keys(operation.transport.path)),
		query: (Array.isArray(operation.transport.query)
			? operation.transport.query.length
			: Object.keys(operation.transport.query).length) > 0
			? projectQuery(operation.transport.query)
			: undefined,
		body: operation.transport.body.length > 0 ? project(operation.transport.body) : undefined,
	};
}

function validatedOutput(
	operation: AnyOperationSpec,
	payload: unknown,
	response: Response,
	idempotencyKey: string | undefined,
): unknown {
	const parsed = operation.schemas.output.safeParse(payload);
	if (!parsed.success) throw protocolError(`${operation.id} returned a response outside its declared output schema.`, response, idempotencyKey);
	return parsed.data;
}

function callSpec(
	config: ManagementClientConfig<OperationRegistry>,
	operation: AnyOperationSpec,
	input: OperationInput<AnyOperationSpec>,
	options: ManagementCallOptions<AnyOperationSpec>,
): Promise<ManagementResponse<unknown>> {
	return (async () => {
		const parsed = parseInput(operation, input);
		requireConfirmation(operation, parsed.logical, options);
		const mutation = operation.mutation;
		const suppliedIdempotencyKey = Object.prototype.hasOwnProperty.call(options, "idempotencyKey");
		const idempotencyKey: unknown = mutation
			? suppliedIdempotencyKey
				? options.idempotencyKey
				: (config.createIdempotencyKey ?? generatedIdempotencyKey)()
			: undefined;
		if (mutation && (typeof idempotencyKey !== "string" || !VISIBLE_ASCII_KEY.test(idempotencyKey))) {
			throw new ManagementApiError({
				code: "MANAGEMENT_CLIENT_IDEMPOTENCY_INVALID",
				message: "idempotencyKey must be 1-200 visible ASCII characters.",
				status: 0,
				stage: "management-client.idempotency",
				remediation: "Use a UUID or another opaque visible-ASCII token.",
			});
		}
		const dryRun = operation.supportsDryRun && parsed.logical.dryRun === true;
		const body = operation.confirmation === "server-required"
			? { ...(parsed.body as Record<string, unknown>), confirm: !dryRun }
			: parsed.body;
		const headers = new Headers(config.headers);
		headers.set("accept", "application/json");
		if (config.authorization) headers.set("authorization", config.authorization);
		if (body !== undefined) headers.set("content-type", "application/json");
		if (mutation) headers.set("idempotency-key", idempotencyKey as string);
		if (mutation && config.csrf) headers.set(config.csrf.header, config.csrf.token);
		let response: Response;
		try {
			let path: ApiPath;
			try {
				path = resolveOperationPath(operation, parsed.path);
			} catch {
				throw protocolError(`${operation.id} path projection did not produce required non-empty strings.`);
			}
			response = await config.fetch(`${config.baseUrl}${parsed.query === undefined ? path : queryPath(path, parsed.query)}`, {
				method: operation.http.method,
				headers,
				credentials: config.credentials,
				...(body !== undefined ? { body: JSON.stringify(body) } : {}),
				signal: options.signal,
			});
		} catch (cause) {
			if (cause instanceof ManagementApiError) throw cause;
			throw new ManagementApiError({
				code: "MANAGEMENT_API_UNREACHABLE",
				message: "Clearance Management API could not be reached.",
				status: 0,
				stage: "management-client.transport",
				remediation: "Check the API origin, browser session, and network connection.",
				retryable: true,
				idempotencyKey: idempotencyKey as string | undefined,
			});
		}
		const payload = await responsePayload(response);
		if (!response.ok) throw managementApiErrorFromResponse(response, payload, { idempotencyKey: idempotencyKey as string | undefined });
		return {
			data: validatedOutput(operation, payload, response, idempotencyKey as string | undefined),
			requestId: response.headers.get("x-request-id") ?? undefined,
			idempotencyKey: idempotencyKey as string | undefined,
			idempotencyReplayed: response.headers.get("idempotency-replayed") === "true",
		};
	})();
}

function createManagementClient<Registry extends OperationRegistry>(
	config: ManagementClientConfig<Registry>,
): ManagementClient<Registry> {
	const safeConfig: ManagementClientConfig<Registry> = Object.freeze({
		...config,
		registry: snapshotRegistry(config.registry),
		headers: Object.freeze({ ...config.headers }),
		csrf: config.csrf ? Object.freeze({ ...config.csrf }) : undefined,
	});
	assertTransportHeaders(safeConfig);
	return {
		call<Id extends keyof Registry & string>(
			id: Id,
			input: OperationInput<Registry[Id]>,
			options: ManagementCallOptions<Registry[Id]> = {},
		) {
			if (!Object.hasOwn(safeConfig.registry, id)) throw protocolError(`Unknown operation id ${id}.`);
			const operation = safeConfig.registry[id]!;
			return callSpec(safeConfig, operation, input as OperationInput<AnyOperationSpec>, options as ManagementCallOptions<AnyOperationSpec>) as Promise<
				ManagementResponse<OperationOutput<Registry[Id]>>
			>;
		},
	};
}

export interface BrowserManagementClientOptions<Registry extends OperationRegistry> {
	readonly baseUrl: string;
	readonly registry: Registry;
	readonly fetch?: FetchLike;
	readonly csrfToken?: string;
	readonly csrfHeader?: string;
	readonly createIdempotencyKey?: () => string;
}

/** Cookie/BFF transport. Its API deliberately exposes no bearer-token option. */
export function createBrowserManagementClient<Registry extends OperationRegistry>(
	options: BrowserManagementClientOptions<Registry>,
): ManagementClient<Registry> {
	const untyped = options as BrowserManagementClientOptions<Registry> & Record<string, unknown>;
	if ("bearerToken" in untyped || "token" in untyped || "authorization" in untyped) {
		throw new ManagementApiError({
			code: "MANAGEMENT_BROWSER_BEARER_FORBIDDEN",
			message: "Browser management clients cannot accept bearer tokens.",
			status: 0,
			stage: "management-client.browser",
			remediation: "Use the server client for operator bearer credentials.",
		});
	}
	const fetch = options.fetch ?? globalThis.fetch;
	if (!fetch) throw protocolError("Browser management client requires a Fetch implementation.");
	return createManagementClient({
		baseUrl: normalizedBaseUrl(options.baseUrl, "browser"),
		registry: options.registry,
		fetch,
		credentials: "include",
		csrf: options.csrfToken ? { header: options.csrfHeader ?? "x-csrf-token", token: options.csrfToken } : undefined,
		createIdempotencyKey: options.createIdempotencyKey,
	});
}

export interface ServerManagementClientOptions<Registry extends OperationRegistry> {
	readonly baseUrl: string;
	readonly registry: Registry;
	readonly bearerToken: string;
	readonly fetch?: FetchLike;
	readonly headers?: Readonly<Record<string, string>>;
	readonly createIdempotencyKey?: () => string;
}

/** Server transport: bearer auth is explicit and never read from environment. */
export function createServerManagementClient<Registry extends OperationRegistry>(
	options: ServerManagementClientOptions<Registry>,
): ManagementClient<Registry> {
	if (!options.bearerToken.trim()) throw new ManagementApiError({
		code: "MANAGEMENT_SERVER_BEARER_REQUIRED",
		message: "Server management client requires a non-empty bearer token.",
		status: 0,
		stage: "management-client.server",
		remediation: "Pass the operator credential from your server-side secret store.",
	});
	const fetch = options.fetch ?? globalThis.fetch;
	if (!fetch) throw protocolError("Server management client requires a Fetch implementation.");
	return createManagementClient({
		baseUrl: normalizedBaseUrl(options.baseUrl, "server"),
		registry: options.registry,
		fetch,
		headers: options.headers,
		authorization: `Bearer ${options.bearerToken}`,
		createIdempotencyKey: options.createIdempotencyKey,
	});
}
