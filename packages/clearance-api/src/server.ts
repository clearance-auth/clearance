import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Context, Next } from "hono";
import {
	addMember,
	addMemberInAuth,
	applyUpgrade,
	executeMemberImportPlan,
	planMemberImport,
	type MemberImportFormat,
	archiveOrganization,
	archiveOrganizationInAuth,
	assertClientScopeHeaders,
	assertProductionCredentialKey,
	assertProductionSecret,
	ClearanceError,
	createManagementStore,
	createBackup,
	createPostgresBackup,
	createProject,
	createEnvironment,
	planProjectCreate,
	planEnvironmentCreate,
	createOrganization,
	createOrgInAuth,
	createScimConnection,
	createScimConnectionReal,
	createSsoConnection,
	createSsoConnectionReal,
	createUser,
	createUserInAuth,
	createUserWithPasswordSetupInAuth,
	deleteUser,
	deleteUserInAuth,
	disableScimConnection,
	disableScimConnectionReal,
	disableSsoConnection,
	disableSsoConnectionReal,
	disableUser,
	disableUserInAuth,
	ensureAuthMigrated,
	exportUsers,
	getLatestReadiness,
	getRuntimeSchemaStatus,
	initProject,
	inspectEnvironment,
	inspectMembership,
	inspectOrganization,
	inspectScimConnection,
	inspectSession,
	inspectSessionInAuth,
	inspectSsoConnection,
	inspectUser,
	isClearanceError,
	isForbiddenDefaultSecret,
	listEnvironments,
	listEventsPage,
	exportEvents,
	inspectEvent,
	replayDiagnosticTrace,
	listMembers,
	listOrganizations,
	listOrganizationsPage,
	listRoles,
	listSessionsPage,
	listSessionsPageInAuth,
	listUsers,
	listUsersPage,
	migrateRuntimeSchema,
	planRuntimeSchema,
	migrationStatus,
	parseLegacyFixture,
	planUpgrade,
	planMigration,
	previewMigration,
	rollbackMigrationDurable,
	rollbackUpgrade,
	runMigrationDurable,
	verifyMigrationDurable,
	verifyUpgrade,
	assertIdempotencyKeyValid,
	createIdempotencyBackend,
	fingerprintIdempotentRequest,
	idempotencyConflictError,
	type IdempotencyBackend,
	overviewStats,
	promoteEnvironment,
	revokeSession,
	revokeSessionInAuth,
	restoreBackup,
	restorePostgresBackup,
	removeMember,
	removeMemberInAuth,
	parseCorsOrigins,
	requireOperatorToken,
	resolveOperatorScope,
	createRole,
	createApiKey,
	listApiKeys,
	inspectApiKey,
	validateApiKeyName,
	normalizeAndValidateApiKeyScopes,
	rotateApiKey,
	revokeApiKey,
	listProjects,
	configureSsoConnection,
	listSsoConnections,
	listScimConnections,
	createSetupLink,
	publicConfig,
	setConfig,
	validateConfig,
	diffConfig,
	rotateScimCredential,
	rotateSsoCredential,
	updateMember,
	updateMemberInAuth,
	updateOrganization,
	updateOrganizationInAuth,
	updateRole,
	validateRole,
	updateUser,
	updateUserInAuth,
	parseUserStatusInput,
	reserveSetupLink,
	commitSetupLink,
	releaseSetupLink,
	deleteSsoProviderById,
	deleteScimProviderById,
	runDoctor,
	runReadinessCheck,
	testScimConnection,
	testScimConnectionReal,
	testScimConnectionLive,
	testSsoConnection,
	testSsoConnectionReal,
	testSsoConnectionLive,
	upgradeCheck,
	upgradeCheckWithDb,
	verifyBackup,
	verifyPostgresBackup,
	syncRuntimeOrganizationToManagementDurable,
	type ManagementStore,
	type ResourceScope,
} from "@clearance/management";
import { timingSafeEqual, createHash, randomBytes, randomUUID } from "node:crypto";
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
		version: "0.2.0",
	});
});

/**
 * Safe operator-session descriptor for the CLI. The bearer credential is
 * verified by requireOperator and is intentionally never reflected here.
 */
app.get("/v1/whoami", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = principalScope(store);
		return c.json({
			operator: { id: "operator", type: "operator", authenticated: true },
			projectId: scope.projectId,
			environmentId: scope.environmentId,
			storeBackend: store.backend,
		});
	} catch (error) {
		return handleError(c, error);
	}
});

app.get("/v1/doctor", async (c) => {
	const store = await storeForRequest();
	return c.json(await runDoctor(store));
});

app.get("/v1/dev", (c) => c.json({
	commands: [
		"clearance init --name my-app",
		"pnpm stack:smoke",
		"pnpm stack:up",
		"pnpm --filter @clearance/sample-b2b dev",
		"pnpm --filter @clearance/api dev",
		"pnpm --filter @clearance/console dev",
	],
}));

app.post("/v1/init", async (c) => {
	const store = await storeForRequest();
	const body = await c.req.json().catch(() => ({}));
	const result = initProject(store, {
		name: (body as { name?: string }).name ?? "clearance-app",
		environment: (body as { environment?: string }).environment,
		source: "api",
	});
	await store.ready();
	return c.json(result);
});

// --- Resource routes (principal-derived scope enforced) ---

app.get("/v1/overview", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		return c.json(overviewStats(store, scope));
	} catch (e) {
		return handleError(c, e);
	}
});

// --- Projects ---

app.get("/v1/projects", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		return c.json({ projects: listProjects(store).filter((project) => project.id === scope.projectId), scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/projects/current", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const project = listProjects(store).find((candidate) => candidate.id === scope.projectId);
		if (!project) throw new ClearanceError({ code: "PROJECT_NOT_FOUND", message: "Project not found.", stage: "project.inspect", status: 404 });
		return c.json({ project, overview: overviewStats(store, scope), scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/projects/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const project = listProjects(store).find((candidate) => candidate.id === c.req.param("id") && candidate.id === scope.projectId);
		if (!project) throw new ClearanceError({ code: "PROJECT_NOT_FOUND", message: "Project not found.", stage: "project.inspect", status: 404 });
		return c.json({ project, overview: overviewStats(store, scope), scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/projects", async (c) => {
	try {
		const store = await storeForRequest();
		const body = await c.req.json();
		if (body.dryRun === true) {
			return c.json({ dryRun: true, project: planProjectCreate({ name: body.name }, store.snapshot.projects) });
		}
		const project = createProject(store, { name: body.name, actor: "api", source: "api" });
		await store.ready();
		return c.json({ project }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

// --- Environments ---

app.get("/v1/environments", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		return c.json({
			environments: listEnvironments(store, { scope }),
			scope,
		});
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/environments/current", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		return c.json(inspectEnvironment(store, undefined, { scope }));
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/environments", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json();
		const projectId = body.projectId ?? scope.projectId;
		if (projectId !== scope.projectId) throw new ClearanceError({ code: "SCOPE_MISMATCH", message: "Environment project is outside the operator scope.", stage: "env.create", status: 404 });
		if (body.dryRun === true) {
			return c.json({ dryRun: true, environment: planEnvironmentCreate(store, { projectId, name: body.name, kind: body.kind }), scope });
		}
		const environment = createEnvironment(store, { projectId, name: body.name, kind: body.kind, actor: "api" });
		await store.ready();
		return c.json({ environment, scope }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/environments/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const result = inspectEnvironment(store, c.req.param("id"), { scope });
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

/**
 * Plan/apply environment promotion. Defaults to dry-run unless confirm=true.
 * Mutating apply is blocked when no Deployment resource exists (structured blockers).
 * Body: { to: string, from?: string, dryRun?: boolean, confirm?: boolean }
 */
app.post("/v1/environments/promote", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		const to =
			body && typeof body === "object" && typeof (body as { to?: unknown }).to === "string"
				? (body as { to: string }).to
				: "";
		const from =
			body &&
			typeof body === "object" &&
			typeof (body as { from?: unknown }).from === "string"
				? (body as { from: string }).from
				: undefined;
		const dryRun =
			body && typeof body === "object" && "dryRun" in body
				? (body as { dryRun?: unknown }).dryRun
				: undefined;
		const confirm =
			body && typeof body === "object" && "confirm" in body
				? (body as { confirm?: unknown }).confirm
				: undefined;
		if (dryRun !== undefined && typeof dryRun !== "boolean") {
			throw new ClearanceError({
				code: "ENV_PROMOTE_INPUT_INVALID",
				message: "dryRun must be a JSON boolean",
				stage: "env.promote",
				status: 400,
			});
		}
		if (confirm !== undefined && typeof confirm !== "boolean") {
			throw new ClearanceError({
				code: "ENV_PROMOTE_INPUT_INVALID",
				message: "confirm must be a JSON boolean",
				stage: "env.promote",
				status: 400,
			});
		}
		const result = promoteEnvironment(store, {
			to,
			...(from ? { from } : {}),
			...(dryRun !== undefined ? { dryRun } : {}),
			...(confirm !== undefined ? { confirm } : {}),
			scope,
			actor: "api",
			source: "api",
		});
		if (!result.dryRun) {
			await store.ready();
		}
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

/**
 * List users. Without limit/cursor this is the legacy unpaginated contract.
 * With ?limit= and/or ?cursor= it is keyset-paginated (createdAt+id asc,
 * opaque fail-closed cursor) and the response carries nextCursor.
 */
app.get("/v1/users", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const limitRaw = c.req.query("limit");
		const cursor = c.req.query("cursor");
		if (limitRaw !== undefined || cursor !== undefined) {
			const page = listUsersPage(store, {
				scope,
				...(limitRaw !== undefined ? { limit: Number(limitRaw) } : {}),
				...(cursor !== undefined ? { cursor } : {}),
			});
			return c.json({ users: page.users, nextCursor: page.nextCursor, scope });
		}
		const users = listUsers(store, { scope });
		return c.json({ users, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/users/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		// Cross-scope ids fail closed as USER_NOT_FOUND
		const user = inspectUser(store, c.req.param("id"), scope);
		return c.json({ user, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/users", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json();
		if (body.dryRun === true) {
			if (typeof body.email !== "string" || !body.email.trim()) {
				throw new ClearanceError({ code: "USER_EMAIL_REQUIRED", message: "Email is required.", stage: "users.create", status: 400 });
			}
			if (typeof body.name !== "string" || !body.name.trim()) {
				throw new ClearanceError({ code: "USER_NAME_REQUIRED", message: "Name is required.", stage: "users.create", status: 400 });
			}
			const email = body.email.trim().toLowerCase();
			if (listUsers(store, { scope }).some((user) => user.email.toLowerCase() === email && user.status !== "deleted")) {
				throw new ClearanceError({ code: "USER_EXISTS", message: `User ${body.email} already exists`, stage: "users.create", status: 409 });
			}
			return c.json({ dryRun: true, email, name: body.name.trim(), scope });
		}
		const provisioned = process.env.DATABASE_URL
			? await (async () => {
					await ensureAuthMigrated();
					if (typeof body.password === "string" && body.password.length > 0) {
						return {
							user: await createUserInAuth({
								email: body.email,
								name: body.name,
								password: body.password,
								managementStore: store,
							}),
							passwordSetup: undefined,
						};
					}
					return createUserWithPasswordSetupInAuth({
						email: body.email,
						name: body.name,
						managementStore: store,
					});
				})()
			: {
					user: createUser(store, {
						email: body.email,
						name: body.name,
						projectId: scope.projectId,
						environmentId: scope.environmentId,
						source: "api",
					}),
					passwordSetup: undefined,
				};
		await store.ready();
		return c.json(
			{
				user: provisioned.user,
				...(provisioned.passwordSetup
					? {
							passwordSetupToken: provisioned.passwordSetup.token,
							passwordSetupExpiresAt: provisioned.passwordSetup.expiresAt,
						}
					: {}),
			},
			201,
		);
	} catch (e) {
		return handleError(c, e);
	}
});

app.patch("/v1/users/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		// Fail closed: invalid status is never silently ignored when present.
		const status = parseUserStatusInput(
			"status" in body ? body.status : undefined,
			"users.update",
		);
		if (body.dryRun === true) {
			inspectUser(store, c.req.param("id"), scope);
			return c.json({ dryRun: true, id: c.req.param("id"), name: body.name, email: body.email, status, scope });
		}
		const user = process.env.DATABASE_URL
			? await (async () => {
					await ensureAuthMigrated();
					return updateUserInAuth(store, c.req.param("id"), {
						name: body.name,
						email: body.email,
						status,
						actor: "api",
						source: "api",
						scope,
					});
				})()
			: updateUser(store, c.req.param("id"), {
					name: body.name,
					email: body.email,
					status,
					actor: "api",
					source: "api",
					scope,
				});
		await store.ready();
		return c.json({ user, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/users/:id/disable", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (body.dryRun === true) {
			return c.json({ dryRun: true, user: inspectUser(store, c.req.param("id"), scope), scope });
		}
		const user = process.env.DATABASE_URL
			? await (async () => {
					await ensureAuthMigrated();
					return disableUserInAuth(store, c.req.param("id"), {
						actor: "api",
						source: "api",
						scope,
					});
				})()
			: disableUser(store, c.req.param("id"), {
					actor: "api",
					source: "api",
					scope,
				});
		await store.ready();
		return c.json({ user, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.delete("/v1/users/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const user = process.env.DATABASE_URL
			? await (async () => {
					await ensureAuthMigrated();
					return deleteUserInAuth(store, c.req.param("id"), {
						actor: "api",
						source: "api",
						scope,
					});
				})()
			: deleteUser(store, c.req.param("id"), {
					actor: "api",
					source: "api",
					scope,
				});
		await store.ready();
		return c.json({ user, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

/**
 * Export scoped users (bounded, redacted, deterministic).
 * File paths are CLI-only; API returns the envelope in the response body.
 * Arbitrary filesystem output paths are never accepted.
 */
app.post("/v1/users/export", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (
			body &&
			typeof body === "object" &&
			("outputPath" in body || "path" in body || "output" in body)
		) {
			throw new ClearanceError({
				code: "USERS_EXPORT_PATH_FORBIDDEN",
				message:
					"API user export does not accept filesystem output paths; the envelope is returned in the response body",
				stage: "users.export",
				status: 400,
				remediation:
					"Omit outputPath/path/output from the request, or use the CLI: clearance users export --output <path>",
			});
		}
		const limit =
			body && typeof body === "object" && "limit" in body
				? Number((body as { limit?: unknown }).limit)
				: undefined;
		const format =
			body &&
			typeof body === "object" &&
			typeof (body as { format?: unknown }).format === "string"
				? (body as { format: string }).format
				: "json";
		const status =
			body &&
			typeof body === "object" &&
			typeof (body as { status?: unknown }).status === "string"
				? (body as { status: string }).status
				: undefined;
		const envelope = exportUsers(store, {
			scope,
			format,
			limit,
			...(status ? { status } : {}),
			actor: "api",
			source: "api",
		});
		await store.ready();
		return c.json(envelope);
	} catch (e) {
		return handleError(c, e);
	}
});

/**
 * List organizations. Legacy unpaginated without params; keyset-paginated
 * (createdAt+id asc) with ?limit=/?cursor=, returning nextCursor.
 */
app.get("/v1/organizations", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const limitRaw = c.req.query("limit");
		const cursor = c.req.query("cursor");
		if (limitRaw !== undefined || cursor !== undefined) {
			const page = listOrganizationsPage(store, {
				scope,
				...(limitRaw !== undefined ? { limit: Number(limitRaw) } : {}),
				...(cursor !== undefined ? { cursor } : {}),
			});
			return c.json({
				organizations: page.organizations,
				nextCursor: page.nextCursor,
				scope,
			});
		}
		return c.json({
			organizations: listOrganizations(store, { scope }),
			scope,
		});
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/organizations/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const organization = inspectOrganization(store, c.req.param("id"), scope);
		return c.json({ organization, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/organizations", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json();
		let organization;
		if (process.env.DATABASE_URL) {
			const ownerUserId =
				body.ownerUserId ??
				store.snapshot.principals.find((p) => p.status === "active")?.id;
			if (!ownerUserId) {
				throw new Error("Create a user first or provide ownerUserId");
			}
			await ensureAuthMigrated();
			const runtimeOrg = await createOrgInAuth({
				name: body.name,
				slug: body.slug,
				userId: ownerUserId,
			});
			organization = await syncRuntimeOrganizationToManagementDurable(
				store,
				runtimeOrg,
				ownerUserId,
				{ actor: "api", role: "owner" },
			);
		} else {
			organization = createOrganization(store, {
				name: body.name,
				slug: body.slug,
				projectId: scope.projectId,
				environmentId: scope.environmentId,
				source: "api",
			});
		}
		await store.ready();
		return c.json({ organization }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.patch("/v1/organizations/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (body == null || typeof body !== "object") {
			throw new ClearanceError({
				code: "ORG_UPDATE_EMPTY",
				message: "At least one of name or slug is required",
				stage: "orgs.update",
				status: 400,
			});
		}
		const unknownFields = Object.keys(body).filter(
			(key) => key !== "name" && key !== "slug" && key !== "status" && key !== "dryRun",
		);
		if (unknownFields.length > 0) {
			throw new ClearanceError({
				code: "ORG_UPDATE_FIELD_INVALID",
				message: `Unsupported organization update field: ${unknownFields[0]}`,
				stage: "orgs.update",
				status: 400,
				remediation: "Only name and slug are mutable; use the archive endpoint for status",
			});
		}
		// Reject non-mutable fields explicitly (status goes through archive)
		if ("status" in body) {
			throw new ClearanceError({
				code: "ORG_STATUS_IMMUTABLE",
				message: "Organization status cannot be set via update; use archive",
				stage: "orgs.update",
				status: 400,
				remediation: "POST /v1/organizations/:id/archive with confirm=true",
			});
		}
		const name =
			body && typeof body === "object" && "name" in body
				? (body as { name: unknown }).name
				: undefined;
		const slug =
			body && typeof body === "object" && "slug" in body
				? (body as { slug: unknown }).slug
				: undefined;
		if (name !== undefined && typeof name !== "string") {
			throw new ClearanceError({
				code: "ORG_NAME_REQUIRED",
				message: "Name must be a string",
				stage: "orgs.update",
				status: 400,
			});
		}
		if (slug !== undefined && typeof slug !== "string") {
			throw new ClearanceError({
				code: "ORG_SLUG_INVALID",
				message: "Slug must be a string",
				stage: "orgs.update",
				status: 400,
			});
		}
		if (body.dryRun === true) {
			inspectOrganization(store, c.req.param("id"), scope);
			return c.json({ dryRun: true, id: c.req.param("id"), name, slug, scope });
		}
		const organization = process.env.DATABASE_URL
			? await (async () => {
					await ensureAuthMigrated();
					return updateOrganizationInAuth(store, c.req.param("id"), {
						...(name !== undefined ? { name } : {}),
						...(slug !== undefined ? { slug } : {}),
						actor: "api",
						source: "api",
						scope,
					});
				})()
			: updateOrganization(store, c.req.param("id"), {
					...(name !== undefined ? { name } : {}),
					...(slug !== undefined ? { slug } : {}),
					actor: "api",
					source: "api",
					scope,
				});
		await store.ready();
		return c.json({ organization, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

/**
 * Archive organization. Defaults to dry-run unless confirm=true.
 * Body: { dryRun?: boolean, confirm?: boolean }
 * When DATABASE_URL is set, uses coordinated runtime+management archive.
 */
app.post("/v1/organizations/:id/archive", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		const dryRun =
			body && typeof body === "object" && "dryRun" in body
				? (body as { dryRun?: unknown }).dryRun
				: undefined;
		const confirm =
			body && typeof body === "object" && "confirm" in body
				? (body as { confirm?: unknown }).confirm
				: undefined;
		if (dryRun !== undefined && typeof dryRun !== "boolean") {
			throw new ClearanceError({
				code: "ORG_ARCHIVE_INPUT_INVALID",
				message: "dryRun must be a JSON boolean",
				stage: "orgs.archive",
				status: 400,
			});
		}
		if (confirm !== undefined && typeof confirm !== "boolean") {
			throw new ClearanceError({
				code: "ORG_ARCHIVE_INPUT_INVALID",
				message: "confirm must be a JSON boolean",
				stage: "orgs.archive",
				status: 400,
			});
		}
		const result = process.env.DATABASE_URL
			? await archiveOrganizationInAuth(store, c.req.param("id"), {
					...(dryRun !== undefined ? { dryRun } : {}),
					...(confirm !== undefined ? { confirm } : {}),
					actor: "api",
					source: "api",
					scope,
				})
			: archiveOrganization(store, c.req.param("id"), {
					...(dryRun !== undefined ? { dryRun } : {}),
					...(confirm !== undefined ? { confirm } : {}),
					actor: "api",
					source: "api",
					scope,
				});
		if (!result.dryRun) {
			await store.ready();
		}
		return c.json({ ...result, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/organizations/:id/members", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const members = listMembers(store, c.req.param("id"), { scope });
		return c.json({ members, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/organizations/:id/members", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (
			body == null ||
			typeof body !== "object" ||
			typeof body.principalId !== "string" ||
			!body.principalId.trim()
		) {
			throw new ClearanceError({
				code: "MEMBER_PRINCIPAL_REQUIRED",
				message: "principalId is required",
				stage: "orgs.members.add",
				status: 400,
				remediation: "Pass principalId in the request body",
			});
		}
		const principalId = String(body.principalId).trim();
		const role = body.role !== undefined ? body.role : "member";
		if (body.dryRun === true) {
			inspectOrganization(store, c.req.param("id"), scope);
			inspectUser(store, principalId, scope);
			return c.json({ dryRun: true, organizationId: c.req.param("id"), principalId, role, scope });
		}
		const membership = process.env.DATABASE_URL
			? await (async () => {
					await ensureAuthMigrated();
					return addMemberInAuth(store, {
						organizationId: c.req.param("id"),
						principalId,
						role,
						actor: "api",
						auditSource: "api",
						scope,
					});
				})()
			: addMember(store, {
					organizationId: c.req.param("id"),
					principalId,
					role,
					actor: "api",
					auditSource: "api",
					scope,
				});
		await store.ready();
		return c.json({ membership, scope }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/organizations/:id/members/import", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		const format = body.format as MemberImportFormat | undefined;
		if (format !== "json" && format !== "csv") {
			throw new ClearanceError({
				code: "MEMBER_IMPORT_FORMAT_REQUIRED",
				message: "Member import format must be json or csv",
				stage: "orgs.members.import",
				status: 400,
				remediation: "Send format as json or csv.",
			});
		}
		if (typeof body.content !== "string") {
			throw new ClearanceError({
				code: "MEMBER_IMPORT_CONTENT_REQUIRED",
				message: "Member import content is required",
				stage: "orgs.members.import",
				status: 400,
				remediation: "Send the local file contents in the authenticated request.",
			});
		}
		const plan = planMemberImport(store, {
			organizationId: c.req.param("id"),
			content: body.content,
			format,
		});
		if (body.dryRun === true || body.confirm !== true) {
			return c.json({ dryRun: true, ...plan, scope });
		}
		const result = await executeMemberImportPlan(plan, async (row) => {
			const membership = process.env.DATABASE_URL
				? await addMemberInAuth(store, {
						organizationId: plan.organizationId,
						principalId: row.principalId,
						role: row.role,
						source: "import",
						actor: "api",
						auditSource: "import",
						scope,
					})
				: addMember(store, {
						organizationId: plan.organizationId,
						principalId: row.principalId,
						role: row.role,
						source: "import",
						actor: "api",
						auditSource: "import",
						scope,
					});
			await store.ready();
			return membership;
		});
		return c.json({ ...result, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.patch("/v1/organizations/:id/members/:memberId", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const orgId = c.req.param("id");
		const memberId = c.req.param("memberId");
		// Ensure org is in scope (cross-scope ids indistinguishable from missing)
		inspectOrganization(store, orgId, scope);
		const existing = inspectMembership(store, memberId, scope);
		if (existing.organizationId !== orgId) {
			// Treat as missing — do not leak cross-org membership existence
			throw new ClearanceError({
				code: "MEMBER_NOT_FOUND",
				message: "Membership not found",
				stage: "orgs.members.update",
				status: 404,
			});
		}
		const body = await c.req.json().catch(() => ({}));
		if (body == null || typeof body !== "object" || body.role === undefined) {
			throw new ClearanceError({
				code: "ROLE_REQUIRED",
				message: "Role is required",
				stage: "orgs.members.update",
				status: 400,
			});
		}
		if (body.dryRun === true) {
			return c.json({ dryRun: true, organizationId: orgId, membershipId: memberId, role: body.role, scope });
		}
		const membership = process.env.DATABASE_URL
			? await (async () => {
					await ensureAuthMigrated();
					return updateMemberInAuth(store, memberId, {
						role: body.role,
						actor: "api",
						auditSource: "api",
						scope,
					});
				})()
			: updateMember(store, memberId, {
					role: body.role,
					actor: "api",
					auditSource: "api",
					scope,
				});
		await store.ready();
		return c.json({ membership, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.delete("/v1/organizations/:id/members/:memberId", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const orgId = c.req.param("id");
		const memberId = c.req.param("memberId");
		inspectOrganization(store, orgId, scope);
		const existing = inspectMembership(store, memberId, scope);
		if (existing.organizationId !== orgId) {
			throw new ClearanceError({
				code: "MEMBER_NOT_FOUND",
				message: "Membership not found",
				stage: "orgs.members.remove",
				status: 404,
			});
		}
		const body = await c.req.json().catch(() => ({}));
		if (body.dryRun === true) {
			return c.json({ dryRun: true, organizationId: orgId, membershipId: memberId, membership: existing, scope });
		}
		const membership = process.env.DATABASE_URL
			? await (async () => {
					await ensureAuthMigrated();
					return removeMemberInAuth(store, memberId, {
						actor: "api",
						auditSource: "api",
						scope,
					});
				})()
			: removeMember(store, memberId, {
					actor: "api",
					auditSource: "api",
					scope,
				});
		await store.ready();
		return c.json({ membership, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

/**
 * List audit events, keyset-paginated (createdAt+id desc, newest first).
 * limit stays the page size (default 50, fail-closed validation matching the
 * CLI's EVENTS_LIST_OPTION_INVALID); nextCursor walks older history.
 */
app.get("/v1/events", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const limitRaw = c.req.query("limit");
		const cursor = c.req.query("cursor");
		const action = c.req.query("action");
		const organizationId = c.req.query("organizationId");
		const page = listEventsPage(store, {
			scope,
			...(limitRaw !== undefined ? { limit: Number(limitRaw) } : {}),
			...(cursor !== undefined ? { cursor } : {}),
			...(action !== undefined ? { action } : {}),
			...(organizationId !== undefined ? { organizationId } : {}),
		});
		return c.json({ events: page.events, nextCursor: page.nextCursor, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/events/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const result = inspectEvent(store, c.req.param("id"), { scope });
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

/**
 * Export scoped audit events (bounded, redacted, deterministic).
 * File paths are CLI-only; API returns the envelope in the response body.
 */
app.post("/v1/events/export", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		const limit =
			body && typeof body === "object" && "limit" in body
				? Number((body as { limit?: unknown }).limit)
				: undefined;
		const format =
			body && typeof body === "object" && typeof (body as { format?: unknown }).format === "string"
				? (body as { format: string }).format
				: "json";
		const action =
			body && typeof body === "object" && typeof (body as { action?: unknown }).action === "string"
				? (body as { action: string }).action
				: undefined;
		const organizationId =
			body &&
			typeof body === "object" &&
			typeof (body as { organizationId?: unknown }).organizationId === "string"
				? (body as { organizationId: string }).organizationId
				: undefined;
		const before =
			body &&
			typeof body === "object" &&
			typeof (body as { before?: unknown }).before === "string"
				? (body as { before: string }).before
				: undefined;
		const envelope = exportEvents(store, {
			scope,
			format,
			limit,
			...(action ? { action } : {}),
			...(organizationId ? { organizationId } : {}),
			...(before ? { before } : {}),
			actor: "api",
			source: "api",
		});
		await store.ready();
		return c.json(envelope);
	} catch (e) {
		return handleError(c, e);
	}
});

/**
 * Replay a SCIM diagnostic trace. Defaults to dry-run unless confirm=true.
 * Body: { id: string, dryRun?: boolean, confirm?: boolean }
 */
app.post("/v1/events/replay", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		const id =
			body && typeof body === "object" && typeof (body as { id?: unknown }).id === "string"
				? (body as { id: string }).id
				: "";
		const bodyDryRun =
			body && typeof body === "object" && (body as { dryRun?: unknown }).dryRun === true;
		const confirm =
			body && typeof body === "object" && (body as { confirm?: unknown }).confirm === true;
		// Safe default: dry-run unless confirm is explicit and dryRun is not forced
		const dryRun = bodyDryRun || !confirm;
		const result = replayDiagnosticTrace(store, id, {
			scope,
			dryRun,
			confirm: confirm && !bodyDryRun,
			actor: "api",
			source: "api",
		});
		if (!result.dryRun) {
			await store.ready();
		}
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

// --- Sessions (principal-derived scope; never expose tokens) ---

/**
 * List sessions, keyset-paginated (createdAt+id desc, newest first). limit
 * keeps the shipped SESSION_LIMIT_INVALID validation as the page size;
 * nextCursor walks older sessions. Runtime (DATABASE_URL) and JSON paths
 * share the same documented ordering and opaque cursor format.
 */
// --- API keys ---

app.get("/v1/keys", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		return c.json({ apiKeys: listApiKeys(store, { scope, includeRevoked: c.req.query("includeRevoked") === "true" }), scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/keys", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json();
		if (body.dryRun === true) {
			const name = validateApiKeyName(body.name, "keys.create");
			const scopes = normalizeAndValidateApiKeyScopes(body.scopes, "keys.create");
			return c.json({ dryRun: true, apiKey: { name, scopes }, secretGenerated: false, scope });
		}
		const result = await createApiKey(store, { name: body.name, scopes: body.scopes, scope, actor: "api", source: "api" });
		await store.ready();
		return c.json({ ...result, scope }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/keys/:id/rotate", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (body.dryRun === true) {
			const apiKey = inspectApiKey(store, c.req.param("id"), { scope });
			if (apiKey.status === "revoked") throw new ClearanceError({ code: "API_KEY_REVOKED", message: "Revoked API keys cannot be rotated", stage: "keys.rotate", status: 409 });
			return c.json({ dryRun: true, apiKey, secretGenerated: false, scope });
		}
		const result = await rotateApiKey(store, c.req.param("id"), { scope, actor: "api", source: "api" });
		await store.ready();
		return c.json({ ...result, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/keys/:id/revoke", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (body.dryRun === true) {
			const apiKey = inspectApiKey(store, c.req.param("id"), { scope });
			return c.json({ dryRun: true, apiKey, wouldChange: apiKey.status === "active", scope });
		}
		const result = await revokeApiKey(store, c.req.param("id"), { scope, actor: "api", source: "api" });
		await store.ready();
		return c.json({ ...result, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/sessions", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const limitRaw = c.req.query("limit");
		const cursor = c.req.query("cursor");
		const limit = Number(limitRaw ?? 100);
		const page = process.env.DATABASE_URL
			? await listSessionsPageInAuth(store, {
					scope,
					limit,
					...(cursor !== undefined ? { cursor } : {}),
				})
			: listSessionsPage(store, {
					scope,
					limit,
					...(cursor !== undefined ? { cursor } : {}),
				});
		return c.json({
			sessions: page.sessions,
			nextCursor: page.nextCursor,
			scope,
		});
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/sessions/:id/revoke", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (body.dryRun === true) {
			const session = process.env.DATABASE_URL
				? await inspectSessionInAuth(store, c.req.param("id"), { scope })
				: inspectSession(store, c.req.param("id"), { scope });
			return c.json({ dryRun: true, session, wouldChange: session.status === "active", scope });
		}
		const result = process.env.DATABASE_URL
			? await (async () => {
					await ensureAuthMigrated();
					return revokeSessionInAuth(store, c.req.param("id"), {
						actor: "api",
						source: "api",
						scope,
					});
				})()
			: revokeSession(store, c.req.param("id"), {
					actor: "api",
					source: "api",
					scope,
				});
		await store.ready();
		return c.json({ ...result, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

// --- Roles (principal-derived scope; client headers never authority) ---

app.get("/v1/roles", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const roles = listRoles(store, { scope });
		return c.json({ roles, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/roles/validate", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		const result = validateRole(store, {
			name: (body as { name?: unknown }).name,
			slug: (body as { slug?: unknown }).slug,
			permissions: (body as { permissions?: unknown }).permissions,
			scope,
		});
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/roles", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json();
		if (body.dryRun === true) {
			return c.json({ dryRun: true, validation: validateRole(store, { name: body.name, slug: body.slug, permissions: body.permissions, scope }), scope });
		}
		const role = await createRole(store, {
			name: body.name,
			slug: body.slug,
			description: body.description,
			permissions: body.permissions,
			scope,
			actor: "api",
			source: "api",
		});
		await store.ready();
		return c.json({ role, scope }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.patch("/v1/roles/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (body.dryRun === true) {
			return c.json({ dryRun: true, id: c.req.param("id"), validation: validateRole(store, { name: body.name, permissions: body.permissions, scope }), scope });
		}
		const role = await updateRole(store, c.req.param("id"), {
			name: body.name,
			description: body.description,
			permissions: body.permissions,
			scope,
			actor: "api",
			source: "api",
		});
		await store.ready();
		return c.json({ role, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/settings", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		return c.json({
			config: store.snapshot.meta.config,
			schemaVersion: store.snapshot.meta.schemaVersion,
			releaseVersion: store.snapshot.releaseVersion,
			resourceCounts: store.resourceCounts(),
			storeBackend: store.backend,
			scope,
			/** Principal scope is server-configured; headers are not authority. */
			tokenBoundary: "principal-derived-scope",
			telemetry: { remoteSinks: [], default: "disabled" },
			auth: { mode: "bearer-operator" },
		});
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/config", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		return c.json({ ...publicConfig(store.snapshot.meta.config, c.req.query("key")), scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.patch("/v1/config/:key", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const request = await c.req.json();
		if (!request || typeof request !== "object" || Array.isArray(request) || typeof request.value !== "string") {
			throw new ClearanceError({
				code: "CONFIG_VALUE_INVALID",
				message: "Config values must be JSON strings.",
				stage: "config.set",
				status: 400,
				remediation: "Send an object with a string value field.",
			});
		}
		const key = c.req.param("key");
		const value = request.value;
		const candidate = { ...store.snapshot.meta.config, [key]: value };
		validateConfig(store, candidate);
		if (request.dryRun === true) {
			return c.json({ dryRun: true, changed: store.snapshot.meta.config[key] !== value, key, ...publicConfig(candidate), scope });
		}
		const result = setConfig(store, key, value);
		if (result.changed) await store.ready();
		return c.json({ ok: true, changed: result.changed, key, ...publicConfig(result.config), scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/config/validate", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const request = await c.req.json().catch(() => ({}));
		const candidate = request.config ?? store.snapshot.meta.config;
		validateConfig(store, candidate);
		return c.json({ ok: true, source: request.config === undefined ? "current" : "candidate", ...publicConfig(candidate), scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/config/diff", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const request = await c.req.json();
		validateConfig(store, request.config);
		return c.json({ ...diffConfig(store.snapshot.meta.config, request.config), scope });
	} catch (e) {
		return handleError(c, e);
	}
});

// --- Enterprise routes (scope enforced on org ownership inside services) ---

app.get("/v1/sso", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const scopedOrgIds = new Set(listOrganizations(store, { scope }).map((org) => org.id));
		const connections = listSsoConnections(store, c.req.query("organizationId")).filter((connection) => scopedOrgIds.has(connection.organizationId));
		return c.json({ connections, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/sso", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json();
		// Fail closed if organizationId is outside principal scope
		inspectOrganization(store, body.organizationId, scope);
		const connection = process.env.DATABASE_URL
			? await createSsoConnectionReal(store, body)
			: createSsoConnection(store, body);
		await store.ready();
		return c.json({ connection }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.patch("/v1/sso/:id", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const request = await c.req.json().catch(() => ({}));
		if (request.dryRun === true) {
			const current = inspectSsoConnection(store, c.req.param("id"), { scope });
			return c.json({
				dryRun: true,
				connection: current,
				proposed: {
					issuer: request.issuer ?? current.issuer,
					audience: request.audience ?? current.audience,
					domains: request.domain ? [request.domain] : request.domains ?? current.domains,
				},
				scope,
			});
		}
		const connection = configureSsoConnection(store, c.req.param("id"), {
			issuer: request.issuer,
			audience: request.audience,
			domains: request.domain ? [request.domain] : request.domains,
		}, { scope, actor: "api", source: "api" });
		await store.ready();
		return c.json({ connection, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/sso/setup-links", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const request = await c.req.json();
		inspectOrganization(store, request.organizationId, scope);
		const link = createSetupLink(store, { organizationId: request.organizationId, kind: "sso", actor: "api" });
		await store.ready();
		return c.json({ ...link, scope }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/sso/:id/test", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const conn = store.snapshot.identityConnections.find(
			(x) => x.id === c.req.param("id"),
		);
		if (!conn) {
			return c.json(
				{ error: { code: "SSO_NOT_FOUND", message: "SSO connection not found", stage: "sso.test" } },
				404,
			);
		}
		inspectOrganization(store, conn.organizationId, scope);
		const body = await c.req.json().catch(() => ({}));
		const result = body.live === true
			? await testSsoConnectionLive(store, c.req.param("id"))
			: process.env.DATABASE_URL
				? await testSsoConnectionReal(store, c.req.param("id"), body)
				: testSsoConnection(store, c.req.param("id"), body);
		await store.ready();
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/sso/:id/rotate", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		// Validate scope before mutation (fail closed for missing/cross-scope).
		const current = inspectSsoConnection(store, c.req.param("id"), { scope });
		if (body.dryRun === true) {
			if (!(current as { hasClientSecret?: boolean }).hasClientSecret && !current.clientSecretFingerprint) {
				throw new ClearanceError({ code: "SSO_NO_SECRET", message: "No encrypted client secret to rotate", stage: "sso.rotate", status: 400 });
			}
			return c.json({ dryRun: true, connection: current, wouldChange: true, scope });
		}
		const connection = rotateSsoCredential(store, c.req.param("id"), {
			actor: "api",
			source: "api",
			scope,
		});
		await store.ready();
		return c.json({ connection, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/sso/:id/disable", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (body.dryRun === true) {
			const connection = inspectSsoConnection(store, c.req.param("id"), { scope });
			return c.json({ dryRun: true, connection, wouldChange: connection.status !== "disabled", scope });
		}
		const result = process.env.DATABASE_URL
			? await disableSsoConnectionReal(store, c.req.param("id"), {
					actor: "api",
					source: "api",
					scope,
				})
			: disableSsoConnection(store, c.req.param("id"), {
					actor: "api",
					source: "api",
					scope,
				});
		await store.ready();
		return c.json({ ...result, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/scim", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json();
		inspectOrganization(store, body.organizationId, scope);
		const developmentBearerToken = process.env.DATABASE_URL
			? undefined
			: `scimtok_${randomBytes(24).toString("base64url")}`;
		const connection = process.env.DATABASE_URL
			? await createScimConnectionReal(store, body)
			: {
					...createScimConnection(store, { ...body, bearerToken: developmentBearerToken }),
					bearerTokenOnce: developmentBearerToken,
				};
		await store.ready();
		return c.json({ connection }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/scim", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const scopedOrgIds = new Set(listOrganizations(store, { scope }).map((org) => org.id));
		const connections = listScimConnections(store, c.req.query("organizationId")).filter((connection) => scopedOrgIds.has(connection.organizationId));
		return c.json({ connections, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/scim/setup-links", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const request = await c.req.json();
		inspectOrganization(store, request.organizationId, scope);
		const link = createSetupLink(store, { organizationId: request.organizationId, kind: "scim", actor: "api" });
		await store.ready();
		return c.json({ ...link, scope }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/scim/:id/test", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const conn = store.snapshot.directoryConnections.find(
			(x) => x.id === c.req.param("id"),
		);
		if (!conn) {
			return c.json(
				{
					error: {
						code: "SCIM_NOT_FOUND",
						message: "SCIM connection not found",
						stage: "scim.test",
					},
				},
				404,
			);
		}
		inspectOrganization(store, conn.organizationId, scope);
		const body = await c.req.json().catch(() => ({}));
		const result = body.live === true
			? await testScimConnectionLive(store, c.req.param("id"))
			: process.env.DATABASE_URL
				? await testScimConnectionReal(store, c.req.param("id"), body)
				: testScimConnection(store, c.req.param("id"), body);
		await store.ready();
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/scim/:id/rotate", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		const current = inspectScimConnection(store, c.req.param("id"), { scope });
		if (body.dryRun === true) {
			if (!(current as { hasBearerToken?: boolean }).hasBearerToken && !current.bearerTokenFingerprint) {
				throw new ClearanceError({ code: "SCIM_NO_TOKEN", message: "No encrypted bearer token to rotate", stage: "scim.rotate", status: 400 });
			}
			return c.json({ dryRun: true, connection: current, wouldChange: true, scope });
		}
		const connection = rotateScimCredential(store, c.req.param("id"), {
			actor: "api",
			source: "api",
			scope,
		});
		await store.ready();
		return c.json({ connection, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/scim/:id/disable", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		if (body.dryRun === true) {
			const connection = inspectScimConnection(store, c.req.param("id"), { scope });
			return c.json({ dryRun: true, connection, wouldChange: connection.status !== "disabled", scope });
		}
		const result = process.env.DATABASE_URL
			? await disableScimConnectionReal(store, c.req.param("id"), {
					actor: "api",
					source: "api",
					scope,
				})
			: disableScimConnection(store, c.req.param("id"), {
					actor: "api",
					source: "api",
					scope,
				});
		await store.ready();
		return c.json({ ...result, scope });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/scim/traces/:traceId/replay", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json().catch(() => ({}));
		const dryRun = body.dryRun === true || body.confirm !== true;
		const result = replayDiagnosticTrace(store, c.req.param("traceId"), {
			dryRun,
			confirm: body.confirm === true && !dryRun,
			actor: "api",
			source: "api",
			scope,
		});
		if (!result.dryRun) await store.ready();
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

// --- Readiness routes (scope enforced) ---

app.post("/v1/readiness/check", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		const body = await c.req.json();
		inspectOrganization(store, body.organizationId, scope);
		const report = runReadinessCheck(store, body.organizationId);
		await store.ready();
		return c.json({ report });
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/readiness/:orgId", async (c) => {
	try {
		const store = await storeForRequest();
		const scope = scopeForRequest(store, c);
		inspectOrganization(store, c.req.param("orgId"), scope);
		const report = getLatestReadiness(store, c.req.param("orgId"));
		return c.json({ report });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/backups", async (c) => {
	try {
		const store = await storeForRequest();
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		if (body.dir !== undefined) {
			throw new ClearanceError({
				code: "BACKUP_DIRECTORY_SERVER_MANAGED",
				message: "Backup storage is configured by the API deployment",
				stage: "backup.create",
				status: 400,
				remediation: "Set CLEARANCE_BACKUP_DIR on the API and mount durable storage there.",
			});
		}
		const configuredDirectory = process.env.CLEARANCE_BACKUP_DIR?.trim();
		if (process.env.NODE_ENV === "production" && !configuredDirectory) {
			throw new ClearanceError({
				code: "BACKUP_DIRECTORY_NOT_CONFIGURED",
				message: "The API backup directory is not configured",
				stage: "backup.create",
				status: 503,
				remediation: "Set CLEARANCE_BACKUP_DIR and mount durable backup storage before retrying.",
			});
		}
		const backup = process.env.DATABASE_URL
			? createPostgresBackup(store, configuredDirectory || undefined)
			: createBackup(store, configuredDirectory || undefined);
		await store.ready();
		return c.json({ backup }, 201);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/backups/:id/verify", async (c) => {
	try {
		const store = await storeForRequest();
		const backup = process.env.DATABASE_URL
			? await verifyPostgresBackup(store, c.req.param("id"))
			: verifyBackup(store, c.req.param("id"));
		await store.ready();
		return c.json({ backup });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/backups/:id/restore", async (c) => {
	try {
		const store = await storeForRequest();
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		if (body.confirm !== true) {
			throw new ClearanceError({
				code: "BACKUP_RESTORE_CONFIRM_REQUIRED",
				message: "Backup restore requires explicit confirmation",
				stage: "backup.restore",
				status: 400,
				remediation: "Verify the backup first, then send confirm as true.",
			});
		}
		const target = typeof body.target === "string" ? body.target : undefined;
		const result = process.env.DATABASE_URL
			? await restorePostgresBackup(store, c.req.param("id"), target)
			: (() => {
					if (!target) {
						throw new ClearanceError({
							code: "BACKUP_RESTORE_TARGET_REQUIRED",
							message: "A restore target is required for the development store",
							stage: "backup.restore",
							status: 400,
							remediation: "Send an isolated target path.",
						});
					}
					return restoreBackup(store, c.req.param("id"), target);
				})();
		await store.ready();
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/upgrades/check", async (c) => {
	try {
		const store = await storeForRequest();
		const result = process.env.DATABASE_URL
			? await upgradeCheckWithDb(store)
			: upgradeCheck(store);
		await store.ready();
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/upgrades/plan", async (c) => {
	try {
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		return c.json(await planUpgrade({
			target: typeof body.target === "string" ? body.target : undefined,
			dir: typeof body.dir === "string" ? body.dir : undefined,
			current: typeof body.current === "string" ? body.current : undefined,
			dryRun: body.dryRun === true,
		}));
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/upgrades/apply", async (c) => {
	try {
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		return c.json(await applyUpgrade({
			plan: typeof body.plan === "string" ? body.plan : undefined,
			dir: typeof body.dir === "string" ? body.dir : undefined,
			dryRun: body.dryRun === true,
			yes: body.confirm === true,
		}));
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/upgrades/verify", async (c) => {
	try {
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		return c.json(await verifyUpgrade({
			plan: typeof body.plan === "string" ? body.plan : undefined,
			dir: typeof body.dir === "string" ? body.dir : undefined,
			healthUrl: typeof body.healthUrl === "string" ? body.healthUrl : undefined,
			dryRun: body.dryRun === true,
		}));
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/upgrades/rollback", async (c) => {
	try {
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		return c.json(await rollbackUpgrade({
			plan: typeof body.plan === "string" ? body.plan : undefined,
			dir: typeof body.dir === "string" ? body.dir : undefined,
			dryRun: body.dryRun === true,
			yes: body.confirm === true,
			restoreActive: body.restoreActive === true,
			confirm: typeof body.activeDatabaseConfirmation === "string"
				? body.activeDatabaseConfirmation
				: undefined,
			backupDir: typeof body.backupDir === "string" ? body.backupDir : undefined,
		}));
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/schema/status", async (c) => {
	try {
		const store = await storeForRequest();
		return c.json({
			management: {
				schemaVersion: store.snapshot.meta.schemaVersion,
				releaseVersion: store.snapshot.releaseVersion,
				initializedAt: store.snapshot.meta.initializedAt,
			},
			runtime: await getRuntimeSchemaStatus(),
		});
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/schema/generate", async (c) => {
	try {
		const plan = await planRuntimeSchema("schema.generate");
		return c.json({ kind: "schema.generate", ...plan });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/schema/migrate", async (c) => {
	try {
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		const dryRun = body.dryRun === true;
		if (!dryRun && body.confirm !== true) {
			throw new ClearanceError({
				code: "SCHEMA_MIGRATE_CONFIRMATION_REQUIRED",
				message: "Schema migration requires explicit confirmation",
				stage: "schema.migrate",
				status: 400,
				remediation: "Review a dry run, then send confirm as true.",
			});
		}
		return c.json(await migrateRuntimeSchema({ dryRun }));
	} catch (e) {
		return handleError(c, e);
	}
});

function migrationFixture(body: Record<string, unknown>) {
	if (!("fixture" in body)) {
		throw new ClearanceError({
			code: "CLEARANCE_IMPORT_FIXTURE_REQUIRED",
			message: "A legacy migration fixture is required",
			stage: "import.legacy.fixture",
			status: 400,
			remediation: "Send the validated fixture in the authenticated request body.",
		});
	}
	return parseLegacyFixture(body.fixture);
}

app.post("/v1/import/legacy", async (c) => {
	try {
		const store = await storeForRequest();
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		const fixture = migrationFixture(body);
		const preview = previewMigration(store, fixture);
		if (body.dryRun === true || body.confirm !== true) {
			return c.json({
				schemaVersion: "v1",
				dryRun: true,
				source: "legacy",
				preview,
				storeBackend: store.backend,
			});
		}
		const planned = planMigration(store, fixture);
		await store.ready();
		await store.refresh();
		await runMigrationDurable(store, planned.id, fixture);
		const verification = await verifyMigrationDurable(store, planned.id, fixture);
		await store.ready();
		return c.json({
			schemaVersion: "v1",
			dryRun: false,
			source: "legacy",
			migration: verification.plan,
			preview,
			verification: {
				reconciled: verification.reconciled,
				expected: verification.expected,
				actual: verification.actual,
			},
			storeBackend: store.backend,
		});
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/migrations/plan", async (c) => {
	try {
		const store = await storeForRequest();
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		if (body.source !== "legacy") {
			throw new ClearanceError({
				code: "CLEARANCE_IMPORT_SOURCE_INVALID",
				message: "Only legacy imports are supported",
				stage: "migration.plan",
				status: 400,
				remediation: "Send source as legacy.",
			});
		}
		const plan = planMigration(store, migrationFixture(body));
		await store.ready();
		return c.json({ plan });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/migrations/:id/run", async (c) => {
	try {
		const store = await storeForRequest();
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		const plan = await runMigrationDurable(store, c.req.param("id"), migrationFixture(body), {
			dryRun: body.dryRun === true,
		});
		await store.ready();
		return c.json({ plan });
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/migrations/:id/verify", async (c) => {
	try {
		const store = await storeForRequest();
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		const result = await verifyMigrationDurable(store, c.req.param("id"), migrationFixture(body));
		await store.ready();
		return c.json(result);
	} catch (e) {
		return handleError(c, e);
	}
});

app.post("/v1/migrations/:id/rollback", async (c) => {
	try {
		const store = await storeForRequest();
		const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
		if (body.confirm !== true) {
			throw new ClearanceError({
				code: "MIGRATION_ROLLBACK_CONFIRM_REQUIRED",
				message: "Migration rollback requires explicit confirmation",
				stage: "migration.rollback",
				status: 400,
				remediation: "Review the plan, then send confirm as true.",
			});
		}
		const plan = await rollbackMigrationDurable(store, c.req.param("id"), migrationFixture(body));
		await store.ready();
		return c.json({ plan });
	} catch (e) {
		return handleError(c, e);
	}
});

app.get("/v1/migrations/:id", async (c) => {
	try {
		const store = await storeForRequest();
		return c.json({ plan: migrationStatus(store, c.req.param("id")) });
	} catch (e) {
		return handleError(c, e);
	}
});

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
