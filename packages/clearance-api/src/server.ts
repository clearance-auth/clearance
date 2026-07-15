import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Context, Next } from "hono";
import {
	assertClientScopeHeaders,
	assertProductionCredentialKey,
	assertProductionSecret,
	ClearanceError,
	createManagementStore,
	createManagementApplication,
	createAuthBridgeRuntimeGateway,
	createScimConnectionReal,
	createSsoConnectionReal,
	isClearanceError,
	isForbiddenDefaultSecret,
	assertIdempotencyKeyValid,
	createIdempotencyBackend,
	fingerprintIdempotentRequest,
	idempotencyConflictError,
	type IdempotencyBackend,
	parseCorsOrigins,
	requireOperatorToken,
	resolveOperatorScope,
	reserveSetupLink,
	commitSetupLink,
	releaseSetupLink,
	deleteSsoProviderById,
	deleteScimProviderById,
	type ManagementStore,
	type ManagementApplication,
	type ResourceScope,
} from "@clearance/management";
import { registerAccessRoutes } from "./routes/access.js";
import { registerConfigRoutes } from "./routes/config.js";
import { registerEnterpriseRoutes } from "./routes/enterprise.js";
import { registerEventRoutes } from "./routes/events.js";
import { registerOperationRoutes } from "./routes/operations.js";
import { registerOrganizationRoutes } from "./routes/organizations.js";
import { registerPlatformRoutes } from "./routes/platform.js";
import { registerUserRoutes } from "./routes/users.js";
import { timingSafeEqual, createHash, randomUUID } from "node:crypto";
import type { IncomingMessage, Server, ServerResponse } from "node:http";

const port = Number(process.env.CLEARANCE_API_PORT ?? 3200);
export const DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024;

export function resolveMaxRequestBodyBytes(
	env: Record<string, string | undefined> = process.env,
): number {
	const raw = env.CLEARANCE_API_MAX_BODY_BYTES;
	if (raw === undefined || raw.trim() === "") return DEFAULT_MAX_REQUEST_BODY_BYTES;
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value < 1 || value > 64 * 1024 * 1024) {
		throw new Error(
			"CLEARANCE_API_MAX_BODY_BYTES must be an integer between 1 and 67108864",
		);
	}
	return value;
}

const MAX_REQUEST_BODY_BYTES = resolveMaxRequestBodyBytes();

class RequestBodyTooLargeError extends Error {
	constructor() {
		super(`Request body exceeds the ${MAX_REQUEST_BODY_BYTES}-byte limit`);
		this.name = "RequestBodyTooLargeError";
	}
}

// Production refuses default secrets at boot
assertProductionSecret(process.env.CLEARANCE_SECRET);
const strictStartup =
	process.env.NODE_ENV === "production" ||
	process.env.CLEARANCE_STRICT_SECRETS === "1";
if (strictStartup) {
	if (isForbiddenDefaultSecret(process.env.CLEARANCE_SECRET)) {
		throw new Error("Clearance API refuses missing/default/weak CLEARANCE_SECRET");
	}
	requireOperatorToken();
	assertProductionCredentialKey(process.env);
	if (!process.env.DATABASE_URL?.trim()) {
		throw new Error("Clearance API requires DATABASE_URL in strict/production mode");
	}
}

let storePromise: Promise<ManagementStore> | null = null;
let managementApplication: ManagementApplication | null = null;
function getStore(): Promise<ManagementStore> {
	if (!storePromise) {
		const url = process.env.DATABASE_URL?.trim();
		storePromise = createManagementStore({
			dataPath: process.env.CLEARANCE_DATA_PATH,
			databaseUrl: url || undefined,
		});
	}
	return storePromise;
}

function applicationFor(store: ManagementStore): ManagementApplication {
	if (!managementApplication) {
		managementApplication = createManagementApplication({
			store,
			...(store.backend === "postgres"
				? { authRuntime: createAuthBridgeRuntimeGateway({ store }) }
				: {}),
		});
	}
	return managementApplication;
}

function runtimeDatabaseConfigured(): boolean {
	return Boolean(process.env.DATABASE_URL);
}

function backupConfiguration(): {
	configuredDirectory: string | undefined;
	production: boolean;
} {
	return {
		configuredDirectory: process.env.CLEARANCE_BACKUP_DIR?.trim(),
		production: process.env.NODE_ENV === "production",
	};
}

/**
 * Long-lived API process: refresh so external CLI writes are visible before
 * serving. Flushes pending local mutations first.
 */
async function storeForRequest(): Promise<ManagementStore> {
	const store = await getStore();
	await store.refresh();
	return store;
}

/** Simple in-memory rate limit (per client key) — always enabled */
const rateBuckets = new Map<string, { count: number; resetAt: number }>();
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = Number(process.env.CLEARANCE_API_RATE_MAX ?? 120);
const RATE_MAX_BUCKETS = 10_000;

/**
 * Rate-limit keying (FOLLOW.md P2.3.3).
 *
 * Default: key on the SOCKET remote address, never on client-supplied
 * headers — x-forwarded-for from an untrusted client would let one attacker
 * partition the limiter into unlimited buckets. The node bridge in start()
 * stamps x-clearance-socket-remote from req.socket unconditionally
 * (overwriting anything a client sent), so that header is server-derived.
 *
 * CLEARANCE_TRUSTED_PROXY=1: honor x-forwarded-for, taking the LAST hop —
 * the entry appended by the trusted proxy (the console BFF), i.e. the address
 * the proxy actually saw. Set this ONLY when the API is reachable exclusively
 * via trusted proxies; a directly reachable API with this flag re-opens the
 * spoofing hole.
 */
const TRUSTED_PROXY = process.env.CLEARANCE_TRUSTED_PROXY === "1";

function rateLimitClientKey(c: Context): string {
	const socketAddr =
		c.req.header("x-clearance-socket-remote")?.trim() || "local";
	if (TRUSTED_PROXY) {
		const xff = c.req.header("x-forwarded-for");
		if (xff) {
			const hops = xff
				.split(",")
				.map((hop) => hop.trim())
				.filter(Boolean);
			const lastUntrustedHop = hops[hops.length - 1];
			if (lastUntrustedHop) return `xff:${lastUntrustedHop}`;
		}
	}
	return `sock:${socketAddr}`;
}

function rateLimit(ip: string): { ok: boolean; remaining: number } {
	const now = Date.now();
	let bucket = rateBuckets.get(ip);
	if (!bucket || now >= bucket.resetAt) {
		if (!bucket && rateBuckets.size >= RATE_MAX_BUCKETS) {
			for (const [key, candidate] of rateBuckets) {
				if (now >= candidate.resetAt) rateBuckets.delete(key);
			}
			if (rateBuckets.size >= RATE_MAX_BUCKETS) {
				return { ok: false, remaining: 0 };
			}
		}
		bucket = { count: 0, resetAt: now + RATE_WINDOW_MS };
		rateBuckets.set(ip, bucket);
	}
	bucket.count += 1;
	return { ok: bucket.count <= RATE_MAX, remaining: Math.max(0, RATE_MAX - bucket.count) };
}

function safeEqualToken(a: string, b: string): boolean {
	const ha = createHash("sha256").update(a).digest();
	const hb = createHash("sha256").update(b).digest();
	return timingSafeEqual(ha, hb);
}

/**
 * Operator principal scope (server-side only)
 * -------------------------------------------
 * CLEARANCE_OPERATOR_TOKEN authenticates the operator. Project/environment
 * authority is derived exclusively from server configuration:
 *   CLEARANCE_PROJECT_ID + CLEARANCE_ENV_ID, or the store's initialized
 *   meta.config after `init` (local single-project profile).
 *
 * Client headers `X-Clearance-Project-Id` / `X-Clearance-Environment-Id` are
 * never used as authority. If present they must match principal scope
 * (consistency check only) — they cannot broaden or select another scope.
 *
 * Resource routes reject with SCOPE_REQUIRED when principal scope is absent.
 * Init and health remain usable without scope (bootstrapping).
 */
function principalScope(store: ManagementStore): ResourceScope {
	return resolveOperatorScope(store);
}

function scopeForRequest(store: ManagementStore, c: Context): ResourceScope {
	const scope = principalScope(store);
	assertClientScopeHeaders(
		scope,
		c.req.header("x-clearance-project-id"),
		c.req.header("x-clearance-environment-id"),
	);
	return scope;
}

/** @deprecated Use principalScope — kept for tests that import scopeFromStore */
function scopeFromStore(store: ManagementStore): {
	projectId?: string;
	environmentId?: string;
} {
	try {
		return principalScope(store);
	} catch {
		return {
			projectId:
				process.env.CLEARANCE_PROJECT_ID ??
				store.snapshot.meta.config.projectId ??
				store.snapshot.projects[0]?.id,
			environmentId:
				process.env.CLEARANCE_ENV_ID ??
				store.snapshot.meta.config.environmentId ??
				store.snapshot.environments[0]?.id,
		};
	}
}

/** @deprecated Prefer scopeForRequest — header check only, never authority */
function assertScope(
	store: ManagementStore,
	headerProject?: string | null,
	headerEnv?: string | null,
): ResourceScope {
	const scope = principalScope(store);
	assertClientScopeHeaders(scope, headerProject, headerEnv);
	return scope;
}

const app = new Hono();
const processStartedAt = Date.now();
let draining = false;
let inFlightRequests = 0;
let requestDurationSeconds = 0;
const requestCounts = new Map<string, number>();
const requestLoggingEnabled =
	strictStartup || process.env.CLEARANCE_REQUEST_LOG === "1";

app.use("*", async (c, next) => {
	const suppliedRequestId = c.req.header("x-request-id") ?? "";
	const requestId = /^[A-Za-z0-9._:-]{1,128}$/.test(suppliedRequestId)
		? suppliedRequestId
		: randomUUID();
	const started = performance.now();
	inFlightRequests += 1;
	c.header("x-request-id", requestId);
	try {
		await next();
	} finally {
		inFlightRequests -= 1;
		const durationSeconds = (performance.now() - started) / 1000;
		requestDurationSeconds += durationSeconds;
		const key = `${c.req.method}|${c.res.status}`;
		requestCounts.set(key, (requestCounts.get(key) ?? 0) + 1);
		if (requestLoggingEnabled) {
			console.log(
				JSON.stringify({
					event: "http_request",
					service: "clearance-api",
					requestId,
					method: c.req.method,
					path: c.req.path,
					status: c.res.status,
					durationMs: Math.round(durationSeconds * 1000),
				}),
			);
		}
	}
});

const corsOrigins = parseCorsOrigins();
app.use(
	"*",
	cors({
		origin: (origin) => {
			if (!origin) return corsOrigins[0] ?? "http://localhost:3100";
			return corsOrigins.includes(origin) ? origin : null;
		},
		allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
		allowHeaders: [
			"Content-Type",
			"Authorization",
			"X-Clearance-Project-Id",
			"X-Clearance-Environment-Id",
		],
		credentials: true,
		maxAge: 600,
	}),
);

app.use("*", async (c, next) => {
	const { ok, remaining } = rateLimit(rateLimitClientKey(c));
	c.header("X-RateLimit-Limit", String(RATE_MAX));
	c.header("X-RateLimit-Remaining", String(remaining));
	if (!ok) {
		return c.json(
			{
				error: {
					code: "RATE_LIMITED",
					message: "Too many requests",
					stage: "api.rate_limit",
					retryable: true,
					remediation: "Retry after 60s",
				},
			},
			429,
		);
	}
	return next();
});

async function requireOperator(c: Context, next: Next) {
	// Health is public
	if (c.req.path === "/health") return next();
	let expected: string;
	try {
		expected = requireOperatorToken();
	} catch (e) {
		return c.json(
			{
				error: {
					code: "OPERATOR_TOKEN_UNCONFIGURED",
					message: e instanceof Error ? e.message : "Operator token required",
					stage: "api.auth",
					retryable: false,
					remediation: "Set CLEARANCE_OPERATOR_TOKEN (≥16 chars)",
				},
			},
			503,
		);
	}
	const auth = c.req.header("authorization") ?? "";
	const match = /^Bearer\s+(.+)$/i.exec(auth);
	if (!match || !safeEqualToken(match[1]!, expected)) {
		return c.json(
			{
				error: {
					code: "UNAUTHORIZED",
					message: "Bearer operator token required",
					stage: "api.auth",
					retryable: false,
					remediation: "Authorization: Bearer <CLEARANCE_OPERATOR_TOKEN>",
				},
			},
			401,
		);
	}
	return next();
}

app.use("/v1/*", requireOperator);

app.use("/v1/*", async (c, next) => {
	if (!["POST", "PUT", "PATCH", "DELETE"].includes(c.req.method)) return next();
	if (!(c.req.header("content-type") ?? "").toLowerCase().includes("application/json")) return next();
	const request = await c.req.raw.clone().json().catch(() => undefined);
	if (!request || typeof request !== "object" || Array.isArray(request)) return next();
	for (const field of ["dryRun", "confirm"] as const) {
		if (Object.hasOwn(request, field) && typeof (request as Record<string, unknown>)[field] !== "boolean") {
			return c.json({
				error: {
					code: "API_BOOLEAN_INVALID",
					message: `${field} must be a JSON boolean.`,
					stage: "api.request",
					retryable: false,
					remediation: `Send ${field} as true or false without quotes.`,
				},
			}, 400);
		}
	}
	return next();
});

/**
 * Idempotency-Key replay for /v1/* mutations (FOLLOW.md P2.3.2).
 *
 * Keys are scoped per method+route; the request body is fingerprinted.
 * - Same key + same payload  → the ORIGINAL response body and status are
 *   replayed byte-identically, except that one-time credentials are omitted
 *   from the durable replay envelope. Replays are marked with the
 *   Idempotency-Replayed: true response header.
 * - Same key + different payload → structured 409 IDEMPOTENCY_KEY_CONFLICT.
 * Responses with status >= 500 are never stored (retries must re-execute).
 * Storage: Postgres companion table with TTL for PgStore; process-local
 * in-memory map for the JSON dev store (see management idempotency.ts).
 * Registered AFTER requireOperator so unauthenticated requests can neither
 * consume nor replay keys.
 */
const IDEMPOTENT_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
let idempotencyBackend: IdempotencyBackend | null = null;

/**
 * Build the response body that is safe to persist for a later replay.
 * Password-setup tokens and other one-time credentials must never enter the
 * Postgres companion table or development memory backend. A replay still
 * returns the original resource and status while reporting the omitted secret.
 */
function idempotencyReplayBody(path: string, body: string): string | null {
	const sensitive =
		path === "/v1/users" ||
		path === "/v1/keys" ||
		/^\/v1\/keys\/[^/]+\/rotate$/.test(path) ||
		path === "/v1/sso/setup-links" ||
		path === "/v1/scim/setup-links" ||
		path === "/v1/scim";
	if (!sensitive) return body;
	try {
		const parsed = JSON.parse(body) as Record<string, unknown>;
		const omitted: string[] = [];
		for (const key of path === "/v1/users"
			? ["passwordSetupToken"]
			: path.endsWith("/setup-links")
				? ["token", "url"]
				: path === "/v1/keys" || path.endsWith("/rotate")
					? ["secret"]
					: []) {
			if (Object.hasOwn(parsed, key)) {
				// biome-ignore lint/performance/noDelete: one-time credentials must not enter persistence.
				delete parsed[key];
				omitted.push(key);
			}
		}
		if (path === "/v1/scim") {
			const connection = parsed.connection;
			if (connection && typeof connection === "object" && Object.hasOwn(connection, "bearerTokenOnce")) {
				// biome-ignore lint/performance/noDelete: one-time credentials must not enter persistence.
				delete (connection as Record<string, unknown>).bearerTokenOnce;
				omitted.push("connection.bearerTokenOnce");
			}
		}
		if (omitted.length === 0) return body;
		parsed.oneTimeSecretsOmitted = omitted;
		return JSON.stringify(parsed);
	} catch {
		// A sensitive response that cannot be inspected may contain a generated
		// credential, so it is never persisted for replay.
		return null;
	}
}

function idempotencyBackendFor(
	store: ManagementStore,
): IdempotencyBackend {
	if (!idempotencyBackend) {
		idempotencyBackend = createIdempotencyBackend(store);
	}
	return idempotencyBackend;
}

app.use("/v1/*", async (c, next) => {
	if (!IDEMPOTENT_METHODS.has(c.req.method)) return next();
	const key = c.req.header("idempotency-key");
	if (key === undefined) return next();
	try {
		assertIdempotencyKeyValid(key);
		const store = await getStore();
		const backend = idempotencyBackendFor(store);
		// Scope includes the caller's credential fingerprint. The API is
		// single-operator today (one bearer token), which would make this a
		// no-op — but if per-operator tokens ever land, a shared key+body must
		// NOT replay operator A's stored response to operator B (cross-tenant
		// disclosure) or silently drop B's write (adversarial finding m3).
		const authHeader = c.req.header("authorization") ?? "";
		const operatorFp = createHash("sha256")
			.update(authHeader)
			.digest("hex")
			.slice(0, 16);
		const scopeKey = `${c.req.method} ${c.req.path} op:${operatorFp}`;
		// Clone the raw request so the route handler's body read is untouched.
		const rawBody = await c.req.raw.clone().text();
		const fingerprint = fingerprintIdempotentRequest(scopeKey, rawBody);
		const existing = await backend.get(scopeKey, key);
		if (existing) {
			if (existing.fingerprint !== fingerprint) {
				throw idempotencyConflictError(scopeKey);
			}
			return c.newResponse(existing.body, existing.status as 200, {
				"content-type": existing.contentType,
				"Idempotency-Replayed": "true",
			});
		}
		await next();
		const res = c.res;
		if (res && res.status < 500) {
			const responseBody = await res.clone().text();
			const replayBody = idempotencyReplayBody(c.req.path, responseBody);
			if (replayBody !== null) {
				await backend.put({
					scopeKey,
					key,
					fingerprint,
					status: res.status,
					contentType: res.headers.get("content-type") ?? "application/json",
					body: replayBody,
				});
			}
		}
		return;
	} catch (e) {
		return handleError(c, e);
	}
});

/**
 * Public capability-authorized customer setup.
 * The random single-use token is the authority; operator bearer credentials are
 * never exposed to the browser.
 *
 * Flow: reserve (durable lease + stable attempt id) → provision (runtime +
 * management with deterministic ids from attempt lineage) → commit (consume once)
 * | release + exact-id compensate. After process death past runtime insert,
 * lease expiry allows the same capability to re-reserve the same attempt id,
 * reconcile the existing provider/connection row, and complete commit.
 * Replay after successful commit remains hard-failed.
 */
app.post("/setup/:kind", async (c) => {
	const kindParam = c.req.param("kind");
	if (kindParam !== "sso" && kindParam !== "scim") {
		return c.json({ error: { code: "SETUP_KIND", message: "Unknown setup kind" } }, 404);
	}
	const kind = kindParam;
	let body: {
		token?: string;
		provider?: string;
		organizationId?: string;
		protocol?: string;
		issuer?: string;
		domain?: string;
		clientId?: string;
		clientSecret?: string;
		samlEntryPoint?: string;
		samlCertificate?: string;
	};
	try {
		body = await c.req.json();
	} catch {
		return c.json({ error: { code: "SETUP_INPUT", message: "JSON body required" } }, 400);
	}
	if (!body.token || !body.provider) {
		return c.json(
			{ error: { code: "SETUP_INPUT", message: "token and provider are required" } },
			400,
		);
	}
	if (
		kind === "sso" &&
		body.protocol !== "saml" &&
		(!body.issuer || !body.clientId || !body.clientSecret)
	) {
		return c.json(
			{
				error: {
					code: "SETUP_INPUT",
					message: "OIDC issuer, clientId, and clientSecret are required",
				},
			},
			400,
		);
	}
	if (
		kind === "sso" &&
		body.protocol === "saml" &&
		(!body.issuer || !body.samlEntryPoint || !body.samlCertificate)
	) {
		return c.json(
			{
				error: {
					code: "SETUP_INPUT",
					message: "SAML issuer, entry point, and X.509 signing certificate are required",
				},
			},
			400,
		);
	}

	const store = await storeForRequest();
	const token = body.token;
	const organizationId = body.organizationId;

	let reservationId: string | undefined;
	let provisionedConnectionId: string | undefined;
	/** True when this request inserted a new connection (not a crash-recovery reuse). */
	let provisionedIsNew = false;

	try {
		const reserved = await reserveSetupLink(store, {
			token,
			kind,
			organizationId,
			actor: "customer-setup",
		});
		reservationId = reserved.reservationId;
		// Attempt id is stable across re-reserves of the same capability digest.
		const setupAttemptId = reserved.reservationId;

		const beforeIds = new Set(
			(kind === "sso"
				? store.snapshot.identityConnections
				: store.snapshot.directoryConnections
			).map((c) => c.id),
		);

		const connection =
			kind === "sso"
				? await createSsoConnectionReal(store, {
						organizationId: reserved.capability.organizationId,
						provider: body.provider,
						protocol: body.protocol === "saml" ? "saml" : "oidc",
						issuer: body.issuer,
						domain: body.domain,
						clientId: body.clientId,
						clientSecret: body.clientSecret,
						samlEntryPoint: body.samlEntryPoint,
						samlCertificate: body.samlCertificate,
						actor: "customer-setup",
						setupAttemptId,
					})
				: await createScimConnectionReal(store, {
						organizationId: reserved.capability.organizationId,
						provider: body.provider,
						actor: "customer-setup",
						setupAttemptId,
					});
		provisionedConnectionId = connection.id;
		provisionedIsNew = !beforeIds.has(connection.id);

		await commitSetupLink(store, {
			token,
			kind,
			organizationId: reserved.capability.organizationId,
			reservationId,
			actor: "customer-setup",
		});
		await store.ready();

		if (kind === "scim") {
			const scimConn = connection as {
				id: string;
				endpoint?: string;
				bearerTokenOnce?: string;
			};
			const bearerTokenOnce =
				typeof scimConn.bearerTokenOnce === "string" ? scimConn.bearerTokenOnce : undefined;
			const publicConn = { ...(connection as object) } as Record<string, unknown>;
			delete publicConn.bearerTokenOnce;
			const absoluteEndpoint = absolutePublicUrl(
				typeof scimConn.endpoint === "string" ? scimConn.endpoint : "/api/auth/scim/v2",
			);
			const responseBody: Record<string, unknown> = {
				ok: true,
				kind,
				connection: { ...publicConn, endpoint: absoluteEndpoint },
			};
			// One-time handoff only — never re-fetched or written to store/audit.
			if (bearerTokenOnce && bearerTokenOnce.length > 0) {
				responseBody.scimHandoff = {
					bearerToken: bearerTokenOnce,
					endpoint: absoluteEndpoint,
					retrieveAgain: false,
					warning:
						"Save and copy this SCIM bearer token and endpoint now. Clearance cannot show the token again.",
				};
			}
			return c.json(responseBody, 201);
		}

		return c.json({ ok: true, kind, connection }, 201);
	} catch (error) {
		// Compensate only a connection this request newly created. Snapshot-diff
		// cleanup can delete an unrelated connection created concurrently for the
		// same organization. Never delete a row recovered from an earlier attempt
		// of the same setup capability (deterministic reuse) — leave it for the
		// next retry after release. Keep the reservation held until cleanup
		// completes so this capability cannot be re-reserved into the window.
		if (provisionedConnectionId && provisionedIsNew) {
			await compensateSetupConnection(store, {
				kind,
				connectionId: provisionedConnectionId,
			}).catch(() => undefined);
		}
		if (reservationId) {
			await releaseSetupLink(store, {
				token,
				kind,
				reservationId,
				actor: "customer-setup",
			}).catch(() => undefined);
		}
		return handleError(c, error);
	}
});

function absolutePublicUrl(pathOrUrl: string): string {
	if (/^https?:\/\//i.test(pathOrUrl)) return pathOrUrl;
	const base = (
		process.env.CLEARANCE_BASE_URL ??
		process.env.CLEARANCE_AUTH_URL ??
		"http://localhost:3300"
	).replace(/\/$/, "");
	const path = pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`;
	return `${base}${path}`;
}

/**
 * Remove the exact management + runtime connection returned to this setup
 * attempt when a later commit step fails. Best-effort runtime cleanup is
 * skipped when DATABASE_URL / bridge is unavailable.
 */
async function compensateSetupConnection(
	store: ManagementStore,
	opts: {
		kind: "sso" | "scim";
		connectionId: string;
	},
): Promise<void> {
	if (opts.kind === "sso") {
		await store.mutateDurable((data) => {
			data.identityConnections = data.identityConnections.filter(
				(connection) => connection.id !== opts.connectionId,
			);
		});
		await store.ready();
		await deleteSsoProviderById(opts.connectionId).catch(() => undefined);
		return;
	}
	await store.mutateDurable((data) => {
		data.directoryConnections = data.directoryConnections.filter(
			(connection) => connection.id !== opts.connectionId,
		);
	});
	await store.ready();
	await deleteScimProviderById(opts.connectionId).catch(() => undefined);
}

// --- Bootstrapping (no project scope required) ---

// Liveness is process-only: dependency failures must never create a restart
// loop. Readiness checks the durable store and goes false while SIGTERM drains.
app.get("/livez", (c) =>
	c.json({ ok: true, service: "clearance-api", state: "live" }),
);

app.get("/readyz", async (c) => {
	if (draining) {
		return c.json({ ok: false, service: "clearance-api", state: "draining" }, 503);
	}
	try {
		const store = await storeForRequest();
		await store.ready();
		return c.json({
			ok: true,
			service: "clearance-api",
			state: "ready",
			storeBackend: store.backend,
		});
	} catch {
		return c.json(
			{ ok: false, service: "clearance-api", state: "dependency_unavailable" },
			503,
		);
	}
});

app.get("/metrics", (c) => {
	const lines = [
		"# HELP clearance_http_requests_total Total HTTP requests handled.",
		"# TYPE clearance_http_requests_total counter",
	];
	for (const [key, count] of [...requestCounts.entries()].sort()) {
		const [method, status] = key.split("|");
		lines.push(
			`clearance_http_requests_total{method="${method}",status="${status}"} ${count}`,
		);
	}
	lines.push(
		"# HELP clearance_http_request_duration_seconds_sum Cumulative HTTP request duration.",
		"# TYPE clearance_http_request_duration_seconds_sum counter",
		`clearance_http_request_duration_seconds_sum ${requestDurationSeconds}`,
		"# HELP clearance_http_requests_in_flight Current HTTP requests in flight.",
		"# TYPE clearance_http_requests_in_flight gauge",
		`clearance_http_requests_in_flight ${inFlightRequests}`,
		"# HELP clearance_process_uptime_seconds Process uptime.",
		"# TYPE clearance_process_uptime_seconds gauge",
		`clearance_process_uptime_seconds ${(Date.now() - processStartedAt) / 1000}`,
		"",
	);
	return c.body(lines.join("\n"), 200, {
		"content-type": "text/plain; version=0.0.4; charset=utf-8",
	});
});

app.get("/health", async (c) => {
	return c.json({
		ok: true,
		service: "clearance-api",
		version: "0.2.1",
	});
});

/**
 * Safe operator-session descriptor for the CLI. The bearer credential is
 * verified by requireOperator and is intentionally never reflected here.
 */
app.route(
	"/",
	registerPlatformRoutes({
		storeForRequest,
		principalScope,
		scopeForRequest,
		handleError,
	}),
);

app.route(
	"/",
	registerUserRoutes({
		storeForRequest,
		scopeForRequest,
		handleError,
		applicationFor,
	}),
);

app.route(
	"/",
	registerOrganizationRoutes({
		storeForRequest,
		scopeForRequest,
		handleError,
		applicationFor,
	}),
);

app.route(
	"/",
	registerEventRoutes({ storeForRequest, scopeForRequest, handleError }),
);

app.route(
	"/",
	registerAccessRoutes({
		storeForRequest,
		scopeForRequest,
		handleError,
		applicationFor,
	}),
);

app.route("/", registerConfigRoutes({ storeForRequest, scopeForRequest, handleError }));

app.route(
	"/",
	registerEnterpriseRoutes({
		storeForRequest,
		scopeForRequest,
		handleError,
		runtimeDatabaseConfigured,
	}),
);

app.route(
	"/",
	registerOperationRoutes({
		storeForRequest,
		handleError,
		runtimeDatabaseConfigured,
		backupConfiguration,
	}),
);

function handleError(
	c: { json: (body: unknown, status?: number) => Response },
	e: unknown,
) {
	if (isClearanceError(e)) {
		return c.json(e.toJSON(), e.status);
	}
	console.error("Unexpected Clearance API error", e);
	return c.json({
		error: {
			code: "INTERNAL",
			message: "An unexpected internal error occurred.",
			stage: "api",
		},
	}, 500);
}

async function readBoundedRequestBody(
	req: IncomingMessage,
): Promise<Buffer | undefined> {
	if (req.method === "GET" || req.method === "HEAD") return undefined;
	const rawContentLength = req.headers["content-length"];
	if (typeof rawContentLength === "string") {
		const contentLength = Number(rawContentLength);
		if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
			throw new RequestBodyTooLargeError();
		}
	}

	const chunks: Buffer[] = [];
	let total = 0;
	for await (const chunk of req) {
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		total += buffer.length;
		if (total > MAX_REQUEST_BODY_BYTES) {
			throw new RequestBodyTooLargeError();
		}
		chunks.push(buffer);
	}
	return total > 0 ? Buffer.concat(chunks, total) : undefined;
}

function payloadTooLargeResponse(): string {
	return JSON.stringify({
		error: {
			code: "REQUEST_BODY_TOO_LARGE",
			message: `Request body exceeds the ${MAX_REQUEST_BODY_BYTES}-byte limit`,
			stage: "api.request_body",
			retryable: false,
			remediation: `Send a request body no larger than ${MAX_REQUEST_BODY_BYTES} bytes`,
		},
	});
}

/** Node HTTP bridge with a hard limit before Hono authentication/body parsing. */
async function nodeRequestHandler(req: IncomingMessage, res: ServerResponse) {
	try {
		const url = `http://localhost:${port}${req.url}`;
		const headers = new Headers();
		for (const [k, v] of Object.entries(req.headers)) {
			if (v) headers.set(k, Array.isArray(v) ? v.join(",") : v);
		}
		// Server-derived socket address for rate-limit keying. Unconditionally
		// overwritten so a client can never smuggle its own value (P2.3.3).
		headers.set(
			"x-clearance-socket-remote",
			req.socket?.remoteAddress ?? "unknown",
		);
		const body = await readBoundedRequestBody(req);
		const response = await app.fetch(
			new Request(url, {
				method: req.method,
				headers,
				body: body && body.length > 0 ? new Uint8Array(body) : undefined,
			}),
		);
		res.statusCode = response.status;
		response.headers.forEach((value, key) => {
			res.setHeader(key, value);
		});
		const ab = await response.arrayBuffer();
		res.end(Buffer.from(ab));
	} catch (error) {
		if (error instanceof RequestBodyTooLargeError) {
			const body = payloadTooLargeResponse();
			res.statusCode = 413;
			res.setHeader("content-type", "application/json; charset=utf-8");
			res.setHeader("content-length", String(Buffer.byteLength(body)));
			res.setHeader("connection", "close");
			res.end(body, () => {
				if (!req.complete) req.destroy();
			});
			return;
		}
		if (!res.headersSent) {
			res.statusCode = 500;
			res.setHeader("content-type", "application/json; charset=utf-8");
			res.end(
				JSON.stringify({
					error: {
						code: "INTERNAL",
						message: "Internal server error",
						stage: "api.bridge",
					},
				}),
			);
		} else {
			res.destroy();
		}
	}
}

function installGracefulShutdown(
	server: Server,
	store: ManagementStore,
	options: { registerSignals?: boolean; timeoutMs?: number } = {},
) {
	let shutdownPromise: Promise<void> | null = null;
	const shutdown = (signal: string): Promise<void> => {
		if (shutdownPromise) return shutdownPromise;
		draining = true;
		console.log(JSON.stringify({ event: "shutdown_started", service: "clearance-api", signal }));
		shutdownPromise = new Promise((resolve) => {
			const timeout = setTimeout(() => {
				console.error(JSON.stringify({ event: "shutdown_timeout", service: "clearance-api" }));
				server.closeAllConnections?.();
				process.exitCode = 1;
				resolve();
			}, options.timeoutMs ?? Number(process.env.CLEARANCE_SHUTDOWN_TIMEOUT_MS ?? 25_000));
			timeout.unref();
			server.close(async (error) => {
				try {
					if (error) throw error;
					await store.ready();
					const destroy = (store as ManagementStore & { destroy?: () => Promise<void> }).destroy;
					if (destroy) await destroy.call(store);
					console.log(JSON.stringify({ event: "shutdown_completed", service: "clearance-api" }));
				} catch (shutdownError) {
					console.error(JSON.stringify({
						event: "shutdown_failed",
						service: "clearance-api",
						message: shutdownError instanceof Error ? shutdownError.message : String(shutdownError),
					}));
					process.exitCode = 1;
				} finally {
					clearTimeout(timeout);
					resolve();
				}
			});
			server.closeIdleConnections?.();
		});
		return shutdownPromise;
	};
	if (options.registerSignals !== false) {
		process.once("SIGTERM", () => void shutdown("SIGTERM"));
		process.once("SIGINT", () => void shutdown("SIGINT"));
	}
	return shutdown;
}

async function start() {
	// Eager store init so postgres schema exists before traffic
	const store = await getStore();
	await store.ready();

	const { createServer } = await import("node:http");
	const server = createServer(nodeRequestHandler);
	server.listen(port, () => {
		console.log(
			`clearance-api listening on http://localhost:${port} (store=${store.backend}, cors=${corsOrigins.join(",")})`,
		);
	});
	installGracefulShutdown(server, store);
	return server;
}

const isDirectRun =
	typeof process.argv[1] === "string" &&
	(process.argv[1].endsWith(`${"server.ts"}`) ||
		process.argv[1].endsWith(`${"server.js"}`));
if (isDirectRun) {
	start().catch((err) => {
		console.error(err);
		process.exit(1);
	});
}

export {
	app,
	getStore,
	storeForRequest,
	start,
	assertScope,
	scopeFromStore,
	principalScope,
	scopeForRequest,
	nodeRequestHandler,
	readBoundedRequestBody,
	idempotencyReplayBody,
	installGracefulShutdown,
};
