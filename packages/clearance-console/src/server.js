import { createServer } from "node:http";
import {
	createHash,
	randomBytes,
	randomUUID,
	scryptSync,
	timingSafeEqual,
} from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, extname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const publicDir = join(__dirname, "..", "public");

const DEFAULT_PORT = Number(process.env.CLEARANCE_CONSOLE_PORT ?? 3100);
const DEFAULT_API_BASE = process.env.CLEARANCE_API_URL ?? "http://localhost:3200";

const SESSION_COOKIE = "clearance_console_session";
const CSRF_COOKIE = "clearance_console_csrf";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
export const MAX_BODY_BYTES = 64 * 1024 * 1024;

class RequestBodyTooLargeError extends Error {
	constructor(limit) {
		super(`Request body exceeds the ${limit}-byte limit`);
		this.name = "RequestBodyTooLargeError";
		this.limit = limit;
	}
}

/** Hop-by-hop / browser-only headers that must never be forwarded upstream. */
const STRIP_REQUEST_HEADERS = new Set([
	"authorization",
	"cookie",
	"cookie2",
	"host",
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailers",
	"transfer-encoding",
	"upgrade",
	// Client must not set or override operator scope — server owns these.
	"x-clearance-project-id",
	"x-clearance-environment-id",
	// Prevent client from injecting operator token via alternate headers.
	"x-api-key",
	"x-operator-token",
	"x-clearance-operator-token",
	"x-csrf-token",
]);

const mime = {
	".html": "text/html; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
	".json": "application/json",
	".svg": "image/svg+xml",
};

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const SAFE_REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;
let consoleDraining = false;

export function requestIdForHeader(value) {
	const supplied = Array.isArray(value) ? value[0] : value;
	return typeof supplied === "string" && SAFE_REQUEST_ID.test(supplied)
		? supplied
		: randomUUID();
}

/**
 * Parse CLEARANCE_CONSOLE_OPERATORS JSON:
 * [{"username":"admin","password":"...","role":"admin"},{"username":"viewer","password":"...","role":"viewer"}]
 * Or CLEARANCE_CONSOLE_ADMIN_USER / CLEARANCE_CONSOLE_ADMIN_PASSWORD (+ optional viewer pair).
 */
export function parseOperatorAccounts(env = process.env) {
	const accounts = [];
	const raw = env.CLEARANCE_CONSOLE_OPERATORS?.trim();
	if (raw) {
		const parsed = JSON.parse(raw);
		if (!Array.isArray(parsed)) {
			throw new Error("CLEARANCE_CONSOLE_OPERATORS must be a JSON array");
		}
		for (const row of parsed) {
			if (!row?.username || !row?.password) {
				throw new Error("Each operator requires username and password");
			}
			const role = row.role === "viewer" ? "viewer" : "admin";
			accounts.push({
				username: String(row.username),
				password: String(row.password),
				role,
			});
		}
	}
	if (env.CLEARANCE_CONSOLE_ADMIN_USER && env.CLEARANCE_CONSOLE_ADMIN_PASSWORD) {
		accounts.push({
			username: String(env.CLEARANCE_CONSOLE_ADMIN_USER),
			password: String(env.CLEARANCE_CONSOLE_ADMIN_PASSWORD),
			role: "admin",
		});
	}
	if (env.CLEARANCE_CONSOLE_VIEWER_USER && env.CLEARANCE_CONSOLE_VIEWER_PASSWORD) {
		accounts.push({
			username: String(env.CLEARANCE_CONSOLE_VIEWER_USER),
			password: String(env.CLEARANCE_CONSOLE_VIEWER_PASSWORD),
			role: "viewer",
		});
	}
	// Deduplicate by username (last wins)
	const byName = new Map();
	for (const a of accounts) byName.set(a.username, a);
	return [...byName.values()];
}

function isWeakSecret(value) {
	if (!value || value.length < 16) return true;
	const lower = value.toLowerCase();
	return (
		lower.includes("change-me") ||
		lower.includes("dev-secret") ||
		lower === "secret" ||
		lower === "password" ||
		lower === "clearance"
	);
}

/**
 * Resolve console runtime config from env or explicit options.
 * Operator token (upstream management API) and session material are server-only.
 */
export function resolveConfig(overrides = {}) {
	const projectId =
		overrides.projectId ??
		process.env.CLEARANCE_PROJECT_ID ??
		process.env.CLEARANCE_PROJECT ??
		"";
	const environmentId =
		overrides.environmentId ??
		process.env.CLEARANCE_ENV_ID ??
		process.env.CLEARANCE_ENVIRONMENT_ID ??
		process.env.CLEARANCE_ENVIRONMENT ??
		"";

	const operators =
		overrides.operators ??
		(() => {
			try {
				return parseOperatorAccounts(process.env);
			} catch (e) {
				if (overrides.allowOperatorParseError) return [];
				throw e;
			}
		})();

	const sessionSecret = String(
		overrides.sessionSecret ??
			process.env.CLEARANCE_CONSOLE_SESSION_SECRET ??
			"",
	);

	const nodeEnv =
		overrides.nodeEnv ?? process.env.NODE_ENV ?? "development";
	const strict =
		nodeEnv === "production" || process.env.CLEARANCE_STRICT_SECRETS === "1";

	if (strict) {
		if (!operators.length) {
			throw new Error(
				"Production console requires CLEARANCE_CONSOLE_OPERATORS (or ADMIN_USER/PASSWORD)",
			);
		}
		if (!sessionSecret || isWeakSecret(sessionSecret)) {
			throw new Error(
				"Production console requires strong CLEARANCE_CONSOLE_SESSION_SECRET (≥16 chars)",
			);
		}
		const operatorToken = String(
			overrides.operatorToken ?? process.env.CLEARANCE_OPERATOR_TOKEN ?? "",
		);
		if (!operatorToken || isWeakSecret(operatorToken)) {
			throw new Error(
				"Production console requires strong CLEARANCE_OPERATOR_TOKEN (upstream, server-only)",
			);
		}
	}

	const maxBodyBytes = Number(
		overrides.maxBodyBytes ??
			process.env.CLEARANCE_CONSOLE_MAX_BODY_BYTES ??
			DEFAULT_MAX_BODY_BYTES,
	);
	if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > MAX_BODY_BYTES) {
		throw new Error(`CLEARANCE_CONSOLE_MAX_BODY_BYTES must be an integer between 1 and ${MAX_BODY_BYTES}`);
	}

	return {
		port: Number(overrides.port ?? process.env.CLEARANCE_CONSOLE_PORT ?? DEFAULT_PORT),
		apiBase: String(
			overrides.apiBase ?? process.env.CLEARANCE_API_URL ?? DEFAULT_API_BASE,
		).replace(/\/$/, ""),
		/** Upstream management API credential — never sent to browser */
		operatorToken: String(
			overrides.operatorToken ?? process.env.CLEARANCE_OPERATOR_TOKEN ?? "",
		),
		projectId: String(projectId || ""),
		environmentId: String(environmentId || ""),
		publicDir: overrides.publicDir ?? publicDir,
		environmentLabel:
			overrides.environmentLabel ??
			process.env.CLEARANCE_ENVIRONMENT_LABEL ??
			(environmentId ? String(environmentId) : "development"),
		operators,
		sessionSecret:
			sessionSecret ||
			// Dev-only fallback (production already failed above)
			"dev-console-session-secret-not-for-prod!!",
		nodeEnv,
		secureCookies:
			overrides.secureCookies ??
			(nodeEnv === "production" || process.env.CLEARANCE_CONSOLE_SECURE_COOKIES === "1"),
		/** In-memory session map (process-local opaque sessions) */
		sessions: overrides.sessions ?? new Map(),
		maxBodyBytes,
	};
}

/**
 * Assert production operator/session config is present and safe.
 * Throws — use at process start.
 */
export function assertConsoleProductionConfig(config = resolveConfig()) {
	const nodeEnv = config.nodeEnv ?? process.env.NODE_ENV ?? "development";
	if (nodeEnv !== "production" && process.env.CLEARANCE_STRICT_SECRETS !== "1") {
		return config;
	}
	if (!config.operators?.length) {
		throw new Error("Console production: no operator accounts configured");
	}
	if (!config.sessionSecret || isWeakSecret(config.sessionSecret)) {
		throw new Error("Console production: unsafe session secret");
	}
	if (!config.operatorToken || isWeakSecret(config.operatorToken)) {
		throw new Error("Console production: missing/unsafe upstream operator token");
	}
	return config;
}

function hashPassword(password, salt) {
	return scryptSync(password, salt, 32).toString("hex");
}

function sessionFingerprint(token) {
	return createHash("sha256").update(token).digest("hex").slice(0, 16);
}

export function createOperatorSession(config, account) {
	const token = randomBytes(32).toString("base64url");
	const csrf = randomBytes(24).toString("base64url");
	const record = {
		token,
		csrf,
		username: account.username,
		role: account.role,
		createdAt: Date.now(),
		expiresAt: Date.now() + SESSION_TTL_MS,
	};
	config.sessions.set(token, record);
	return record;
}

export function destroyOperatorSession(config, token) {
	if (token) config.sessions.delete(token);
}

export function getSessionFromRequest(req, config) {
	const cookies = parseCookies(req.headers.cookie);
	const token = cookies[SESSION_COOKIE];
	if (!token) return null;
	const session = config.sessions.get(token);
	if (!session) return null;
	if (session.expiresAt <= Date.now()) {
		config.sessions.delete(token);
		return null;
	}
	return session;
}

function parseCookies(header) {
	const out = {};
	if (!header) return out;
	for (const part of String(header).split(";")) {
		const idx = part.indexOf("=");
		if (idx === -1) continue;
		const k = part.slice(0, idx).trim();
		const v = part.slice(idx + 1).trim();
		out[k] = decodeURIComponent(v);
	}
	return out;
}

function cookieFlags(config, { httpOnly = true } = {}) {
	const parts = ["Path=/", "SameSite=Strict"];
	if (httpOnly) parts.push("HttpOnly");
	if (config.secureCookies) parts.push("Secure");
	return parts.join("; ");
}

function setSessionCookies(res, config, session) {
	const base = cookieFlags(config, { httpOnly: true });
	const csrfBase = cookieFlags(config, { httpOnly: false }); // double-submit readable by JS optional; we also accept header
	res.appendHeader?.(
		"Set-Cookie",
		`${SESSION_COOKIE}=${encodeURIComponent(session.token)}; ${base}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
	);
	// node http may not have appendHeader on older — use array
	const cookies = [
		`${SESSION_COOKIE}=${encodeURIComponent(session.token)}; ${base}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
		`${CSRF_COOKIE}=${encodeURIComponent(session.csrf)}; ${csrfBase}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
	];
	res.setHeader("Set-Cookie", cookies);
}

function clearSessionCookies(res, config) {
	const base = cookieFlags(config, { httpOnly: true });
	const csrfBase = cookieFlags(config, { httpOnly: false });
	res.setHeader("Set-Cookie", [
		`${SESSION_COOKIE}=; ${base}; Max-Age=0`,
		`${CSRF_COOKIE}=; ${csrfBase}; Max-Age=0`,
	]);
}

/**
 * Same-origin check for browser mutations: Origin or Referer must match Host.
 */
export function isSameOriginRequest(req) {
	const host = req.headers.host;
	if (!host) return false;
	const origin = req.headers.origin;
	if (origin) {
		try {
			const o = new URL(origin);
			return o.host === host;
		} catch {
			return false;
		}
	}
	const referer = req.headers.referer || req.headers.referrer;
	if (referer) {
		try {
			const r = new URL(referer);
			return r.host === host;
		} catch {
			return false;
		}
	}
	// Non-browser clients without Origin/Referer are rejected for mutations
	return false;
}

/**
 * Double-submit CSRF: require X-CSRF-Token (or X-XSRF-Token) header matching
 * the session csrf. Cookie alone is not sufficient.
 */
export function validateCsrf(req, session) {
	if (!session?.csrf) return false;
	const header = String(
		req.headers["x-csrf-token"] || req.headers["x-xsrf-token"] || "",
	);
	if (!header || header.length !== session.csrf.length) return false;
	try {
		const headerOk = timingSafeEqual(
			Buffer.from(header),
			Buffer.from(session.csrf),
		);
		// Optional: also match CSRF cookie when present
		const cookies = parseCookies(req.headers.cookie);
		const cookieToken = cookies[CSRF_COOKIE] || "";
		if (cookieToken) {
			if (cookieToken.length !== session.csrf.length) return false;
			const cookieOk = timingSafeEqual(
				Buffer.from(cookieToken),
				Buffer.from(session.csrf),
			);
			return headerOk && cookieOk;
		}
		return headerOk;
	} catch {
		return false;
	}
}

/**
 * Build upstream headers for a proxied management API call.
 * - Strips client Authorization and scope headers
 * - Injects Bearer CLEARANCE_OPERATOR_TOKEN (server-only)
 * - Injects configured project/environment scope when set
 * - Sets x-forwarded-for from the BFF's OWN client socket address (server-
 *   derived, never from client headers) so the API's rate limiter can key
 *   per browser client when CLEARANCE_TRUSTED_PROXY=1 is set on the API.
 */
export function buildUpstreamHeaders(reqHeaders, config, clientAddress) {
	const headers = {};
	const incoming = reqHeaders ?? {};

	for (const [rawKey, value] of Object.entries(incoming)) {
		if (value == null) continue;
		const key = rawKey.toLowerCase();
		if (STRIP_REQUEST_HEADERS.has(key)) continue;
		if (
			key === "content-type" ||
			key === "accept" ||
			key === "accept-language" ||
			key === "user-agent" ||
			key === "x-request-id" ||
			key === "x-correlation-id"
		) {
			headers[key] = Array.isArray(value) ? value.join(",") : String(value);
		}
	}

	if (!headers["content-type"] && !headers["Content-Type"]) {
		headers["content-type"] = "application/json";
	}

	// Server-owned operator auth — never take from client.
	if (config.operatorToken) {
		headers.authorization = `Bearer ${config.operatorToken}`;
	}

	// Server-owned scope — never take from client.
	if (config.projectId) {
		headers["x-clearance-project-id"] = config.projectId;
	}
	if (config.environmentId) {
		headers["x-clearance-environment-id"] = config.environmentId;
	}

	// Server-derived client identity for upstream rate limiting. Client-sent
	// x-forwarded-for is never forwarded (it is not in the allowlist above);
	// only the socket address the console itself observed is sent.
	if (clientAddress) {
		headers["x-forwarded-for"] = String(clientAddress);
	}

	return headers;
}

function setSecurityHeaders(res) {
	res.setHeader("X-Content-Type-Options", "nosniff");
	res.setHeader("X-Frame-Options", "DENY");
	res.setHeader("Referrer-Policy", "no-referrer");
	res.setHeader(
		"Content-Security-Policy",
		[
			"default-src 'self'",
			"script-src 'self'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"connect-src 'self'",
			"font-src 'self'",
			"object-src 'none'",
			"base-uri 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
		].join("; "),
	);
}

function json(res, status, body) {
	res.statusCode = status;
	res.setHeader("content-type", "application/json; charset=utf-8");
	setSecurityHeaders(res);
	res.end(JSON.stringify(body));
}

function readBody(req, maxBytes) {
	const contentLength = req.headers["content-length"];
	if (
		typeof contentLength === "string" &&
		/^\d+$/.test(contentLength) &&
		Number(contentLength) > maxBytes
	) {
		// Consume the request after returning the 413 so keep-alive connections
		// remain usable. The declared length is only an early gate; streamed byte
		// counting below remains authoritative.
		req.resume();
		return Promise.reject(new RequestBodyTooLargeError(maxBytes));
	}

	return new Promise((resolve, reject) => {
		const chunks = [];
		let total = 0;
		let settled = false;

		const cleanup = () => {
			req.off("data", onData);
			req.off("end", onEnd);
			req.off("error", onError);
			req.off("aborted", onAborted);
		};
		const onData = (chunk) => {
			if (settled) return;
			const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			total += buffer.length;
			if (total > maxBytes) {
				settled = true;
				cleanup();
				// Drain remaining bytes without buffering them.
				req.resume();
				reject(new RequestBodyTooLargeError(maxBytes));
				return;
			}
			chunks.push(buffer);
		};
		const onEnd = () => {
			if (settled) return;
			settled = true;
			cleanup();
			resolve(Buffer.concat(chunks, total));
		};
		const onError = (error) => {
			if (settled) return;
			settled = true;
			cleanup();
			reject(error);
		};
		const onAborted = () => onError(new Error("Request body aborted"));

		req.on("data", onData);
		req.on("end", onEnd);
		req.on("error", onError);
		req.on("aborted", onAborted);
	});
}

function payloadTooLarge(res, stage, limit) {
	return json(res, 413, {
		error: {
			code: "PAYLOAD_TOO_LARGE",
			message: `Request body exceeds the ${limit}-byte limit`,
			stage,
			retryable: false,
			limitBytes: limit,
		},
	});
}

function authenticateOperator(config, username, password) {
	const account = config.operators.find((a) => a.username === username);
	if (!account) return null;
	const salt = createHash("sha256")
		.update(`${config.sessionSecret}:${account.username}`)
		.digest("hex")
		.slice(0, 32);
	const a = Buffer.from(hashPassword(password, salt), "hex");
	const b = Buffer.from(hashPassword(account.password, salt), "hex");
	if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
	return account;
}

/**
 * Local console auth + config endpoints (never proxies operator token).
 */
export async function handleConsoleAuth(req, res, config, url) {
	if (url.pathname === "/api/console/config") {
		const session = getSessionFromRequest(req, config);
		return json(res, 200, {
			ok: true,
			apiBase: config.apiBase,
			hasOperatorToken: Boolean(config.operatorToken),
			projectId: config.projectId || null,
			environmentId: config.environmentId || null,
			environmentLabel: config.environmentLabel,
			authMode: "operator-session",
			scopeSource: "server-env",
			authenticated: Boolean(session),
			role: session?.role ?? null,
			username: session?.username ?? null,
			csrfRequired: true,
			// never: operatorToken, session token, passwords
		});
	}

	if (url.pathname === "/api/console/session" && (req.method === "GET" || req.method === "HEAD")) {
		const session = getSessionFromRequest(req, config);
		if (!session) {
			return json(res, 401, {
				error: {
					code: "NOT_AUTHENTICATED",
					message: "No operator session",
					stage: "console.session",
				},
			});
		}
		return json(res, 200, {
			ok: true,
			username: session.username,
			role: session.role,
			csrf: session.csrf,
			expiresAt: new Date(session.expiresAt).toISOString(),
			// never raw session token
		});
	}

	if (url.pathname === "/api/console/login" && req.method === "POST") {
		if (!isSameOriginRequest(req) && config.requireOrigin !== false) {
			return json(res, 403, {
				error: {
					code: "CSRF_ORIGIN",
					message: "Login requires same-origin Origin or Referer",
					stage: "console.login",
				},
			});
		}
		let raw;
		try {
			raw = await readBody(req, config.maxBodyBytes);
		} catch (error) {
			if (error instanceof RequestBodyTooLargeError) {
				return payloadTooLarge(res, "console.login", error.limit);
			}
			throw error;
		}
		let body = {};
		try {
			body = raw.length ? JSON.parse(raw.toString("utf8")) : {};
		} catch {
			return json(res, 400, {
				error: { code: "BAD_JSON", message: "Invalid JSON", stage: "console.login" },
			});
		}
		const username = String(body.username ?? "");
		const password = String(body.password ?? "");
		if (!config.operators.length) {
			return json(res, 503, {
				error: {
					code: "OPERATORS_UNCONFIGURED",
					message: "No console operator accounts configured",
					stage: "console.login",
					remediation: "Set CLEARANCE_CONSOLE_OPERATORS",
				},
			});
		}
		const account = authenticateOperator(config, username, password);
		if (!account) {
			return json(res, 401, {
				error: {
					code: "INVALID_CREDENTIALS",
					message: "Invalid username or password",
					stage: "console.login",
				},
			});
		}
		const session = createOperatorSession(config, account);
		setSessionCookies(res, config, session);
		return json(res, 200, {
			ok: true,
			username: account.username,
			role: account.role,
			csrf: session.csrf,
		});
	}

	if (url.pathname === "/api/console/logout" && req.method === "POST") {
		const session = getSessionFromRequest(req, config);
		if (!session) {
			return json(res, 401, {
				error: {
					code: "NOT_AUTHENTICATED",
					message: "Operator session required",
					stage: "console.logout",
				},
			});
		}
		if (!isSameOriginRequest(req) || !validateCsrf(req, session)) {
			return json(res, 403, {
				error: {
					code: "CSRF_TOKEN",
					message: "Logout requires same-origin request and valid CSRF token",
					stage: "console.logout",
				},
			});
		}
		if (session) destroyOperatorSession(config, session.token);
		clearSessionCookies(res, config);
		return json(res, 200, { ok: true });
	}

	return null; // not handled
}

/**
 * Authorize browser request for /api/* management proxy.
 * Mutations require session + admin + CSRF + same-origin.
 * Reads require session (any role).
 */
export function authorizeConsoleRequest(req, config, url) {
	// Health is public
	const upstreamPath = url.pathname.replace(/^\/api/, "") || "/";
	if (upstreamPath === "/health" || upstreamPath === "/") {
		return { ok: true, session: null, public: true };
	}
	if (upstreamPath.startsWith("/setup/") && req.method === "POST") {
		if (!isSameOriginRequest(req)) {
			return {
				ok: false,
				status: 403,
				error: {
					code: "CSRF_ORIGIN",
					message: "Setup submission requires a same-origin request",
					stage: "console.setup",
				},
			};
		}
		return { ok: true, session: null, public: true };
	}

	// console/* handled separately
	if (url.pathname.startsWith("/api/console/")) {
		return { ok: true, session: null, public: true };
	}

	const session = getSessionFromRequest(req, config);
	if (!session) {
		return {
			ok: false,
			status: 401,
			error: {
				code: "NOT_AUTHENTICATED",
				message: "Operator session required",
				stage: "console.auth",
				remediation: "POST /api/console/login",
			},
		};
	}

	const method = (req.method ?? "GET").toUpperCase();
	if (SAFE_METHODS.has(method)) {
		return { ok: true, session };
	}

	// Mutations
	if (session.role !== "admin") {
		return {
			ok: false,
			status: 403,
			error: {
				code: "FORBIDDEN_ROLE",
				message: "Viewer role cannot perform mutations",
				stage: "console.auth.role",
				remediation: "Sign in as an admin operator",
			},
		};
	}

	if (!isSameOriginRequest(req)) {
		return {
			ok: false,
			status: 403,
			error: {
				code: "CSRF_ORIGIN",
				message: "Mutation requires same-origin Origin or Referer",
				stage: "console.auth.csrf",
			},
		};
	}

	if (!validateCsrf(req, session)) {
		return {
			ok: false,
			status: 403,
			error: {
				code: "CSRF_TOKEN",
				message: "Valid CSRF token required for mutations",
				stage: "console.auth.csrf",
				remediation: "Send X-CSRF-Token matching session csrf",
			},
		};
	}

	return { ok: true, session };
}

/**
 * Proxy /api/* → management API with server-owned auth + scope.
 */
export async function handleProxy(req, res, config, url) {
	const local = await handleConsoleAuth(req, res, config, url);
	if (local !== null) return;

	const authz = authorizeConsoleRequest(req, config, url);
	if (!authz.ok) {
		return json(res, authz.status, { error: authz.error });
	}

	const upstreamPath = url.pathname.replace(/^\/api/, "") || "/";
	const needsOperator =
		upstreamPath === "/v1" ||
		upstreamPath.startsWith("/v1/") ||
		(upstreamPath !== "/health" &&
			upstreamPath !== "/" &&
			!upstreamPath.startsWith("/setup/"));

	if (needsOperator && !config.operatorToken) {
		return json(res, 503, {
			error: {
				code: "OPERATOR_TOKEN_UNCONFIGURED",
				message: "Console missing CLEARANCE_OPERATOR_TOKEN",
				stage: "console.proxy.auth",
				retryable: false,
				remediation: "Set CLEARANCE_OPERATOR_TOKEN on the console process (≥16 chars)",
			},
		});
	}

	// Reject credential smuggling via query
	for (const key of url.searchParams.keys()) {
		const lower = key.toLowerCase();
		if (
			lower === "authorization" ||
			lower === "token" ||
			lower === "operator_token" ||
			lower === "access_token" ||
			lower === "bearer"
		) {
			return json(res, 400, {
				error: {
					code: "CLIENT_AUTH_OVERRIDE_REJECTED",
					message: "Authorization must not be supplied by the client",
					stage: "console.proxy.auth",
					retryable: false,
					remediation: "Remove auth query params; console injects the operator token",
				},
			});
		}
	}

	const target = `${config.apiBase}${upstreamPath}${url.search}`;
	const headers = buildUpstreamHeaders(
		req.headers,
		config,
		req.socket?.remoteAddress,
	);
	if (!needsOperator) {
		delete headers.authorization;
		delete headers["x-clearance-project-id"];
		delete headers["x-clearance-environment-id"];
	}

	try {
		const init = { method: req.method ?? "GET", headers };
		if (req.method !== "GET" && req.method !== "HEAD") {
			let body;
			try {
				body = await readBody(req, config.maxBodyBytes);
			} catch (error) {
				if (error instanceof RequestBodyTooLargeError) {
					return payloadTooLarge(res, "console.proxy", error.limit);
				}
				throw error;
			}
			if (body.length > 0) init.body = body;
		}
		const upstream = await fetch(target, init);
		const buf = Buffer.from(await upstream.arrayBuffer());
		res.statusCode = upstream.status;
		const ct = upstream.headers.get("content-type");
		if (ct) res.setHeader("content-type", ct);
		setSecurityHeaders(res);
		res.end(buf);
	} catch (e) {
		json(res, 502, {
			error: {
				code: "PROXY_UPSTREAM",
				message: e instanceof Error ? e.message : String(e),
				stage: "console.proxy",
				retryable: true,
				remediation: `Check CLEARANCE_API_URL (${config.apiBase}) and that the API is running`,
			},
		});
	}
}

function serveStatic(req, res, config, url) {
	let path = url.pathname === "/" ? "/index.html" : url.pathname;
	if (
		[
			"/overview",
			"/users",
			"/organizations",
			"/members",
			"/sessions",
			"/roles",
			"/events",
			"/settings",
			"/readiness",
			"/login",
			"/setup/sso",
			"/setup/scim",
		].includes(path)
	) {
		path = path.startsWith("/setup/") ? "/setup.html" : "/index.html";
	}

	const file = join(config.publicDir, path);
	if (!file.startsWith(config.publicDir) || !existsSync(file)) {
		res.statusCode = 404;
		setSecurityHeaders(res);
		res.end("Not found");
		return;
	}

	const ext = extname(file);
	res.setHeader("content-type", mime[ext] ?? "application/octet-stream");
	setSecurityHeaders(res);
	res.end(readFileSync(file));
}

/**
 * Create an HTTP request listener for the operator console.
 */
export function createHandler(overrides = {}) {
	const config = resolveConfig(overrides);
	return async function handler(req, res) {
		const requestId = requestIdForHeader(req.headers["x-request-id"]);
		// The normalized value is also what the management proxy forwards upstream.
		req.headers["x-request-id"] = requestId;
		res.setHeader("x-request-id", requestId);
		const url = new URL(req.url ?? "/", `http://localhost:${config.port}`);
		const started = performance.now();
		try {
			if (url.pathname === "/livez") {
				json(res, 200, { ok: true, service: "clearance-console", state: "live" });
				return;
			}
			if (url.pathname === "/readyz") {
				if (consoleDraining) {
					json(res, 503, { ok: false, service: "clearance-console", state: "draining" });
					return;
				}
				try {
					const upstream = await fetch(`${config.apiBase}/readyz`, {
						signal: AbortSignal.timeout(3_000),
					});
					json(res, upstream.ok ? 200 : 503, {
						ok: upstream.ok,
						service: "clearance-console",
						state: upstream.ok ? "ready" : "dependency_unavailable",
					});
				} catch {
					json(res, 503, { ok: false, service: "clearance-console", state: "dependency_unavailable" });
				}
				return;
			}
			if (url.pathname.startsWith("/api/")) {
				await handleProxy(req, res, config, url);
				return;
			}
			serveStatic(req, res, config, url);
		} finally {
			if (config.nodeEnv === "production" || process.env.CLEARANCE_REQUEST_LOG === "1") {
				console.log(JSON.stringify({
					event: "http_request",
					service: "clearance-console",
					requestId,
					method: req.method,
					path: url.pathname,
					status: res.statusCode,
					durationMs: Math.round(performance.now() - started),
				}));
			}
		}
	};
}

/**
 * Create an HTTP server instance (does not listen).
 */
export function createConsoleServer(overrides = {}) {
	const config = resolveConfig(overrides);
	if (
		(config.nodeEnv === "production" || process.env.CLEARANCE_STRICT_SECRETS === "1") &&
		!overrides.skipProductionAssert
	) {
		assertConsoleProductionConfig(config);
	}
	const server = createServer(createHandler(config));
	server.clearanceConfig = config;
	return server;
}

// Default singleton for `node src/server.js` and existing imports.
let defaultConfig;
let server;
try {
	defaultConfig = resolveConfig();
	if (
		defaultConfig.nodeEnv === "production" ||
		process.env.CLEARANCE_STRICT_SECRETS === "1"
	) {
		assertConsoleProductionConfig(defaultConfig);
	}
	server = createConsoleServer({ ...defaultConfig, skipProductionAssert: true });
} catch (e) {
	if (
		process.env.NODE_ENV === "production" ||
		process.env.CLEARANCE_STRICT_SECRETS === "1"
	) {
		console.error(e instanceof Error ? e.message : e);
		process.exit(1);
	}
	defaultConfig = resolveConfig({
		operators: [],
		sessionSecret: "dev-console-session-secret-not-for-prod!!",
		allowOperatorParseError: true,
	});
	server = createConsoleServer({ ...defaultConfig, skipProductionAssert: true });
}

const apiBase = defaultConfig.apiBase;
const port = defaultConfig.port;

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
	server.listen(port, () => {
		const tokenState = defaultConfig.operatorToken ? "configured" : "MISSING";
		const ops = defaultConfig.operators.length;
		console.log(
			`clearance-console http://localhost:${port} (api ${apiBase}, operator token ${tokenState}, local operators ${ops})`,
		);
	});
	const shutdown = (signal) => {
		if (consoleDraining) return;
		consoleDraining = true;
		console.log(JSON.stringify({ event: "shutdown_started", service: "clearance-console", signal }));
		const timeout = setTimeout(() => {
			console.error(JSON.stringify({ event: "shutdown_timeout", service: "clearance-console" }));
			server.closeAllConnections?.();
			process.exitCode = 1;
		}, Number(process.env.CLEARANCE_SHUTDOWN_TIMEOUT_MS ?? 25_000));
		timeout.unref();
		server.close((error) => {
			clearTimeout(timeout);
			if (error) {
				console.error(JSON.stringify({ event: "shutdown_failed", service: "clearance-console", message: error.message }));
				process.exitCode = 1;
			} else {
				console.log(JSON.stringify({ event: "shutdown_completed", service: "clearance-console" }));
			}
		});
		server.closeIdleConnections?.();
	};
	process.once("SIGTERM", () => shutdown("SIGTERM"));
	process.once("SIGINT", () => shutdown("SIGINT"));
}

export {
	server,
	publicDir,
	apiBase,
	port,
	defaultConfig,
	STRIP_REQUEST_HEADERS,
	SESSION_COOKIE,
	CSRF_COOKIE,
	sessionFingerprint,
};
