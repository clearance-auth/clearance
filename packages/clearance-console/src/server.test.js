import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
	publicDir,
	buildUpstreamHeaders,
	resolveConfig,
	createConsoleServer,
	STRIP_REQUEST_HEADERS,
	assertConsoleProductionConfig,
	SESSION_COOKIE,
} from "./server.js";

const root = dirname(fileURLToPath(import.meta.url));
const appJs = readFileSync(join(publicDir, "app.js"), "utf8");
const indexHtml = readFileSync(join(publicDir, "index.html"), "utf8");
const stylesCss = readFileSync(join(publicDir, "styles.css"), "utf8");
const setupHtml = readFileSync(join(publicDir, "setup.html"), "utf8");
const setupJs = readFileSync(join(publicDir, "setup.js"), "utf8");

function listen(server) {
	return new Promise((resolve, reject) => {
		server.listen(0, "127.0.0.1", () => {
			const addr = server.address();
			resolve(typeof addr === "object" && addr ? addr.port : 0);
		});
		server.on("error", reject);
	});
}

function close(server) {
	return new Promise((resolve) => server.close(() => resolve()));
}

/** Minimal mock management API that records the last request. */
function createMockApi(handler) {
	/** @type {{ method?: string, url?: string, headers: Record<string, string|string[]|undefined>, body: string }[]} */
	const requests = [];
	const server = createServer(async (req, res) => {
		const chunks = [];
		for await (const c of req) chunks.push(c);
		const body = Buffer.concat(chunks).toString("utf8");
		const headers = {};
		for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = v;
		const record = { method: req.method, url: req.url, headers, body };
		requests.push(record);
		if (handler) {
			await handler(req, res, record);
			return;
		}
		res.statusCode = 200;
		res.setHeader("content-type", "application/json");
		res.end(JSON.stringify({ ok: true, path: req.url, echoAuth: headers.authorization || null }));
	});
	return { server, requests };
}

function cookieHeader(res) {
	const raw = res.headers.getSetCookie?.() ?? [];
	if (raw.length) return raw.map((c) => c.split(";")[0]).join("; ");
	const single = res.headers.get("set-cookie");
	if (!single) return "";
	// Node may join multiple with comma incorrectly; handle best-effort
	return single
		.split(/,(?=\s*[^;]+=)/)
		.map((c) => c.split(";")[0].trim())
		.join("; ");
}

async function login(port, username, password) {
	const origin = `http://127.0.0.1:${port}`;
	const res = await fetch(`${origin}/api/console/login`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			origin,
		},
		body: JSON.stringify({ username, password }),
	});
	const body = await res.json();
	const cookie = cookieHeader(res);
	return { res, body, cookie, csrf: body.csrf, origin };
}

function rawRequest(port, { path, method = "POST", headers = {}, chunks = [] }) {
	return new Promise((resolve, reject) => {
		const req = httpRequest(
			{ host: "127.0.0.1", port, path, method, headers },
			(res) => {
				const responseChunks = [];
				res.on("data", (chunk) => responseChunks.push(chunk));
				res.on("end", () => {
					const text = Buffer.concat(responseChunks).toString("utf8");
					resolve({ status: res.statusCode, headers: res.headers, text });
				});
			},
		);
		req.on("error", reject);
		for (const chunk of chunks) req.write(chunk);
		req.end();
	});
}

// Tripwires: source-grep checks over the shipped static assets. Rendered-DOM
// behavior (login form, routing, escaping) is proven by src/ui.test.js; these
// greps remain only to catch accidental deletion/renaming of shipped surfaces.
describe("console shell assets", () => {
	it("ships primary nav surfaces in index.html", () => {
		for (const nav of [
			"Overview",
			"Users",
			"Organizations",
			"Members",
			"Sessions",
			"Roles",
			"Events",
			"Readiness",
			"Settings",
		]) {
			assert.match(indexHtml, new RegExp(nav));
		}
		assert.match(indexHtml, /data-theme="dark"|theme-dark|--bg/);
		assert.match(indexHtml, /data-route="roles"/);
		assert.match(indexHtml, /data-route="sessions"/);
		assert.match(indexHtml, /data-route="members"/);
	});

	it("app.js declares readiness route fetching readiness API", () => {
		assert.match(appJs, /readiness\s*:/);
		assert.match(appJs, /\/v1\/readiness\//);
		assert.match(appJs, /renderReadiness/);
	});

	it("app.js declares roles route with validate-before-save workflow", () => {
		assert.match(appJs, /roles\s*:/);
		assert.match(appJs, /renderRoles/);
		assert.match(appJs, /\/v1\/roles\/validate/);
		assert.match(appJs, /\/v1\/roles/);
		assert.match(appJs, /clearance roles list --json/);
		assert.match(appJs, /parsePermissionsText/);
		assert.match(appJs, /canMutate/);
		// Built-ins must be treated as immutable in the UI
		assert.match(appJs, /built_in|role_builtin_/);
		assert.match(appJs, /Immutable|immutable/);
		// Viewer mutation UI disabled / absent
		assert.match(appJs, /viewer.*inspect|cannot create or update|View only/i);
	});

	it("app.js declares sessions list/revoke workflow with confirmation and no token UI", () => {
		assert.match(appJs, /sessions\s*:/);
		assert.match(appJs, /renderSessions/);
		assert.match(appJs, /\/v1\/sessions/);
		assert.match(appJs, /\/v1\/sessions\/\$\{|\/v1\/sessions\/.*revoke|sessions\/.*\/revoke/);
		assert.match(appJs, /clearance sessions list --json/);
		assert.match(appJs, /clearance sessions revoke/);
		assert.match(appJs, /confirmDestructive|window\.confirm/);
		assert.match(appJs, /sanitizeSessionForUi|SESSION_SENSITIVE_KEY/);
		assert.match(appJs, /sessionsLoadVersion|revokingId/);
		assert.match(appJs, /No active sessions|Loading sessions/);
		// Must never interpolate token-like fields into HTML
		assert.doesNotMatch(appJs, /session\.token|session\.bearer|Bearer \$\{/);
		assert.doesNotMatch(appJs, /\$\{\s*session\.token\s*\}/);
	});

	it("app.js declares members list/add/update/remove workflow", () => {
		assert.match(appJs, /members\s*:/);
		assert.match(appJs, /renderMembers/);
		assert.match(appJs, /\/v1\/organizations\/\$\{.*\}\/members|\/v1\/organizations\/.*\/members/);
		assert.match(appJs, /clearance orgs members list/);
		assert.match(appJs, /clearance orgs members add/);
		assert.match(appJs, /clearance orgs members update/);
		assert.match(appJs, /clearance orgs members remove/);
		assert.match(appJs, /membersLoadVersion|mutatingId|membersState/);
		assert.match(appJs, /canMutate/);
		assert.match(appJs, /viewer.*inspect members|cannot add members|View only/i);
	});

	it("public dir exists", () => {
		assert.equal(existsSync(publicDir), true);
	});

	it("preserves dark dense product tokens", () => {
		assert.match(stylesCss, /--bg:\s*#0b0d10/);
		assert.match(stylesCss, /--panel:\s*#12151a/);
		assert.match(indexHtml, /data-theme="dark"/);
		assert.match(stylesCss, /\.role-form|\.badge-locked|\.role-validate-preview/);
		assert.match(stylesCss, /\.member-form|\.sessions-table|\.sr-only|\.danger-action/);
	});

	it("declares all MANAGEMENT_SURFACES console routes", () => {
		for (const key of [
			"overview",
			"users",
			"organizations",
			"members",
			"sessions",
			"roles",
			"events",
			"readiness",
			"settings",
		]) {
			assert.match(appJs, new RegExp(`${key}\\s*:`));
		}
	});

	it("ships capability-token setup pages for SSO and SCIM", () => {
		assert.match(setupHtml, /Customer setup/i);
		assert.match(setupJs, /\/api\/setup\//);
		assert.match(setupJs, /URLSearchParams/);
		assert.doesNotMatch(setupJs, /authorization|operator.token/i);
	});

	it("SCIM setup renders one-time handoff with copy controls and never persists token", () => {
		assert.match(setupJs, /scimHandoff/);
		assert.match(setupJs, /renderScimHandoff/);
		assert.match(setupJs, /bearerToken/);
		assert.match(setupJs, /cannot show the token again|cannot be retrieved/i);
		assert.match(setupJs, /navigator\.clipboard\.writeText|setup-copy/);
		assert.match(setupJs, /history\.replaceState/);
		// No durable browser persistence APIs for the one-time secret
		assert.doesNotMatch(setupJs, /\blocalStorage\b/);
		assert.doesNotMatch(setupJs, /\bsessionStorage\b/);
		assert.doesNotMatch(setupJs, /document\.cookie/);
		// Must not re-fetch the SCIM secret after the setup POST
		const fetchMatches = setupJs.match(/\bfetch\s*\(/g) || [];
		assert.equal(fetchMatches.length, 1, "setup.js should perform only the setup POST fetch");
	});
});

describe("resolveConfig / buildUpstreamHeaders", () => {
	it("injects bearer operator token from config, not client headers", () => {
		const headers = buildUpstreamHeaders(
			{
				authorization: "Bearer evil-client-token",
				"x-clearance-project-id": "proj_evil",
				"x-clearance-environment-id": "env_evil",
				"content-type": "application/json",
				"x-api-key": "smuggled",
			},
			{
				operatorToken: "server-operator-token-32chars!!",
				projectId: "proj_server",
				environmentId: "env_server",
			},
		);
		assert.equal(headers.authorization, "Bearer server-operator-token-32chars!!");
		assert.equal(headers["x-clearance-project-id"], "proj_server");
		assert.equal(headers["x-clearance-environment-id"], "env_server");
		assert.equal(headers["x-api-key"], undefined);
		assert.equal(headers["content-type"], "application/json");
	});

	it("omits scope headers when not configured", () => {
		const headers = buildUpstreamHeaders(
			{ authorization: "Bearer client" },
			{ operatorToken: "tok", projectId: "", environmentId: "" },
		);
		assert.equal(headers.authorization, "Bearer tok");
		assert.equal(headers["x-clearance-project-id"], undefined);
		assert.equal(headers["x-clearance-environment-id"], undefined);
	});

	it("sets x-forwarded-for from the server-observed client socket, never from client headers", () => {
		// Client-supplied XFF is dropped (not in the allowlist); the console's
		// own socket observation is the only source (P2.3.3 companion work).
		const headers = buildUpstreamHeaders(
			{ "x-forwarded-for": "6.6.6.6, 7.7.7.7", "content-type": "application/json" },
			{ operatorToken: "tok", projectId: "", environmentId: "" },
			"192.0.2.55",
		);
		assert.equal(headers["x-forwarded-for"], "192.0.2.55");

		// No client address observed → no XFF header invented
		const noAddr = buildUpstreamHeaders(
			{ "x-forwarded-for": "6.6.6.6" },
			{ operatorToken: "tok", projectId: "", environmentId: "" },
		);
		assert.equal(noAddr["x-forwarded-for"], undefined);
	});

	it("strips listed override headers by name", () => {
		for (const h of [
			"authorization",
			"x-clearance-project-id",
			"x-clearance-environment-id",
			"x-operator-token",
			"cookie",
		]) {
			assert.equal(STRIP_REQUEST_HEADERS.has(h), true, h);
		}
	});

	it("resolveConfig reads CLEARANCE_* env names without exposing token in label", () => {
		const cfg = resolveConfig({
			operatorToken: "secret-token-value",
			projectId: "proj_x",
			environmentId: "env_y",
			environmentLabel: "staging",
			apiBase: "http://api.example:3200/",
			operators: [{ username: "a", password: "p", role: "admin" }],
			sessionSecret: "session-secret-value-32chars!!",
		});
		assert.equal(cfg.apiBase, "http://api.example:3200");
		assert.equal(cfg.projectId, "proj_x");
		assert.equal(cfg.environmentId, "env_y");
		assert.equal(cfg.environmentLabel, "staging");
		assert.equal(cfg.operatorToken, "secret-token-value");
	});

	it("fails production when operator/session config is unsafe", () => {
		assert.throws(
			() =>
				assertConsoleProductionConfig(
					resolveConfig({
						nodeEnv: "production",
						operators: [],
						sessionSecret: "weak",
						operatorToken: "",
						skipProductionAssert: true,
					}),
				),
			/operator|session|token/i,
		);
		const operators = [{ username: "admin", password: "strong-password", role: "admin" }];
		assert.throws(
			() => resolveConfig({
				nodeEnv: "production",
				operators,
				sessionSecret: "clearance-secret",
				operatorToken: "strong-operator-token-value-32chars",
			}),
			/session/i,
		);
		assert.throws(
			() => resolveConfig({
				nodeEnv: "production",
				operators,
				sessionSecret: "strong-session-secret-value-32chars",
				operatorToken: "test-secret-value-that-is-long-enough",
			}),
			/operator.*token/i,
		);
	});

	it("rejects console body limits above the bounded production maximum", () => {
		assert.throws(
			() => resolveConfig({ maxBodyBytes: 64 * 1024 * 1024 + 1 }),
			/between 1 and 67108864/,
		);
	});
});

describe("operator sessions, roles, CSRF", () => {
	/** @type {import('node:http').Server} */
	let mock;
	/** @type {ReturnType<typeof createMockApi>} */
	let mockApi;
	/** @type {import('node:http').Server} */
	let consoleServer;
	/** @type {number} */
	let consolePort;
	const OPERATOR = "test-operator-token-32chars!!";
	const PROJECT = "proj_console_test";
	const ENV = "env_console_test";
	const ADMIN = { username: "admin", password: "admin-pass-32chars-long!!", role: "admin" };
	const VIEWER = { username: "viewer", password: "viewer-pass-32chars-long!", role: "viewer" };

	before(async () => {
		mockApi = createMockApi((req, res) => {
			if (req.url?.startsWith("/health")) {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ ok: true, version: "0.2.1", service: "clearance-api" }));
				return;
			}
			if (req.url?.startsWith("/v1/users")) {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(
					JSON.stringify({
						users: [
							{
								id: "usr_1",
								email: "safe@example.com",
								name: '<img src=x onerror=alert(1)>',
								status: "active",
							},
						],
					}),
				);
				return;
			}
			res.statusCode = 200;
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ ok: true, path: req.url }));
		});
		mock = mockApi.server;
		const mockPort = await listen(mock);
		consoleServer = createConsoleServer({
			apiBase: `http://127.0.0.1:${mockPort}`,
			operatorToken: OPERATOR,
			projectId: PROJECT,
			environmentId: ENV,
			environmentLabel: "test",
			port: 0,
			nodeEnv: "development",
			sessionSecret: "console-session-secret-32chars!!",
			operators: [ADMIN, VIEWER],
			secureCookies: false,
		});
		consolePort = await listen(consoleServer);
	});

	after(async () => {
		await close(consoleServer);
		await close(mock);
	});

	it("login sets HttpOnly session cookie and returns csrf; never leaks upstream token", async () => {
		const { res, body, cookie } = await login(consolePort, ADMIN.username, ADMIN.password);
		assert.equal(res.status, 200);
		assert.equal(body.role, "admin");
		assert.ok(body.csrf);
		assert.match(cookie, new RegExp(SESSION_COOKIE));
		const setCookie = res.headers.getSetCookie?.() ?? [res.headers.get("set-cookie")];
		const joined = setCookie.filter(Boolean).join("\n");
		assert.match(joined, /HttpOnly/i);
		assert.match(joined, /SameSite=Strict/i);
		const raw = JSON.stringify(body);
		assert.equal(raw.includes(OPERATOR), false);
		assert.equal(body.operatorToken, undefined);
		assert.equal(body.token === undefined || !String(body.token).includes(OPERATOR), true);
	});

	it("rejects an oversized unauthenticated login from Content-Length before buffering", async () => {
		const limited = createConsoleServer({
			apiBase: consoleServer.clearanceConfig.apiBase,
			operatorToken: OPERATOR,
			projectId: PROJECT,
			environmentId: ENV,
			port: 0,
			nodeEnv: "development",
			sessionSecret: "console-session-secret-32chars!!",
			operators: [ADMIN, VIEWER],
			secureCookies: false,
			maxBodyBytes: 128,
		});
		const port = await listen(limited);
		try {
			const origin = `http://127.0.0.1:${port}`;
			const response = await rawRequest(port, {
				path: "/api/console/login",
				headers: {
					origin,
					"content-type": "application/json",
					"content-length": "129",
				},
				chunks: [Buffer.alloc(129, "x")],
			});
			assert.equal(response.status, 413);
			const body = JSON.parse(response.text);
			assert.equal(body.error?.code, "PAYLOAD_TOO_LARGE");
			assert.equal(body.error?.stage, "console.login");
			assert.equal(body.error?.limitBytes, 128);
		} finally {
			await close(limited);
		}
	});

	it("rejects an oversized chunked mutation while streaming and never proxies it", async () => {
		const limited = createConsoleServer({
			apiBase: consoleServer.clearanceConfig.apiBase,
			operatorToken: OPERATOR,
			projectId: PROJECT,
			environmentId: ENV,
			port: 0,
			nodeEnv: "development",
			sessionSecret: "console-session-secret-32chars!!",
			operators: [ADMIN, VIEWER],
			secureCookies: false,
			maxBodyBytes: 128,
		});
		const port = await listen(limited);
		try {
			const { cookie, csrf, origin } = await login(
				port,
				ADMIN.username,
				ADMIN.password,
			);
			mockApi.requests.length = 0;
			const response = await rawRequest(port, {
				path: "/api/v1/users",
				headers: {
					cookie,
					origin,
					"x-csrf-token": csrf,
					"content-type": "application/json",
					"transfer-encoding": "chunked",
				},
				chunks: [Buffer.alloc(80, "a"), Buffer.alloc(80, "b")],
			});
			assert.equal(response.status, 413);
			const body = JSON.parse(response.text);
			assert.equal(body.error?.code, "PAYLOAD_TOO_LARGE");
			assert.equal(body.error?.stage, "console.proxy");
			assert.equal(body.error?.limitBytes, 128);
			assert.equal(mockApi.requests.length, 0);
		} finally {
			await close(limited);
		}
	});

	it("unauthenticated /v1 reads return 401", async () => {
		const res = await fetch(`http://127.0.0.1:${consolePort}/api/v1/users`);
		assert.equal(res.status, 401);
		const body = await res.json();
		assert.equal(body.error?.code, "NOT_AUTHENTICATED");
	});

	it("serves setup routes and proxies same-origin capability submissions without operator auth", async () => {
		const origin = `http://127.0.0.1:${consolePort}`;
		const page = await fetch(`${origin}/setup/scim?token=capability`);
		assert.equal(page.status, 200);
		assert.match(await page.text(), /Customer setup/i);

		mockApi.requests.length = 0;
		const denied = await fetch(`${origin}/api/setup/scim`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ token: "capability", provider: "okta" }),
		});
		assert.equal(denied.status, 403);

		const allowed = await fetch(`${origin}/api/setup/scim`, {
			method: "POST",
			headers: { "content-type": "application/json", origin },
			body: JSON.stringify({ token: "capability", provider: "okta" }),
		});
		assert.equal(allowed.status, 200);
		assert.equal(mockApi.requests.length, 1);
		assert.equal(mockApi.requests[0].url, "/setup/scim");
		assert.equal(mockApi.requests[0].headers.authorization, undefined);
		assert.match(mockApi.requests[0].body, /capability/);
	});

	it("setup.js SCIM handoff keeps plaintext only in page memory/DOM", async () => {
		const onceToken = "scimtok_one_time_secret_value";
		const endpoint = "https://auth.example/api/auth/scim/v2";
		const storage = { local: {}, session: {} };
		const clipboard = { last: "" };
		/** @type {any[]} */
		const fetchCalls = [];

		const elements = new Map();
		function el(tag, id) {
			const node = {
				tagName: tag.toUpperCase(),
				id: id || "",
				hidden: false,
				textContent: "",
				className: "",
				children: [],
				dataset: {},
				attributes: {},
				listeners: {},
				setAttribute(k, v) {
					this.attributes[k] = v;
				},
				addEventListener(type, fn) {
					this.listeners[type] = fn;
				},
				appendChild(child) {
					this.children.push(child);
					return child;
				},
				append(...kids) {
					for (const k of kids) this.children.push(k);
				},
				replaceChildren(...kids) {
					this.children = [...kids];
				},
			};
			if (id) elements.set(id, node);
			return node;
		}
		const form = el("form", "setup-form");
		const result = el("p", "result");
		const title = el("h1", "title");
		const ssoFields = el("div", "sso-fields");
		elements.set("setup-form", form);
		elements.set("result", result);
		elements.set("title", title);
		elements.set("sso-fields", ssoFields);

		const document = {
			getElementById(id) {
				return elements.get(id) || null;
			},
			createElement(tag) {
				return el(tag);
			},
		};
		const location = {
			pathname: "/setup/scim",
			search: "?token=capability-token&org=org_1",
			href: "http://127.0.0.1/setup/scim?token=capability-token&org=org_1",
		};
		const history = {
			replaceState(_a, _b, path) {
				location.pathname = path;
				location.search = "";
				location.href = `http://127.0.0.1${path}`;
			},
		};
		const localStorage = {
			setItem(k, v) {
				storage.local[k] = v;
			},
			getItem(k) {
				return storage.local[k] ?? null;
			},
		};
		const sessionStorage = {
			setItem(k, v) {
				storage.session[k] = v;
			},
			getItem(k) {
				return storage.session[k] ?? null;
			},
		};
		const navigator = {
			clipboard: {
				async writeText(v) {
					clipboard.last = v;
				},
			},
		};
		async function fetch(url, opts) {
			fetchCalls.push({ url, opts });
			return {
				ok: true,
				async json() {
					return {
						ok: true,
						kind: "scim",
						connection: { id: "scim_1", endpoint },
						scimHandoff: {
							bearerToken: onceToken,
							endpoint,
							retrieveAgain: false,
							warning:
								"Save and copy this SCIM bearer token and endpoint now. Clearance cannot show the token again.",
						},
					};
				},
			};
		}

		// Execute setup.js with the simulated page environment
		const runner = new Function(
			"document",
			"location",
			"history",
			"fetch",
			"navigator",
			"localStorage",
			"sessionStorage",
			"URLSearchParams",
			"FormData",
			"globalThis",
			`${setupJs}\nreturn { form, result, __clearanceSetup: globalThis.__clearanceSetup };`,
		);
		const fakeFormData = class {
			entries() {
				return Object.entries({ provider: "okta" })[Symbol.iterator]();
			}
		};
		const g = {};
		const ctx = runner(
			document,
			location,
			history,
			fetch,
			navigator,
			localStorage,
			sessionStorage,
			URLSearchParams,
			fakeFormData,
			g,
		);
		assert.equal(title.textContent, "SCIM setup");
		assert.equal(ssoFields.hidden, true);

		await form.listeners.submit({ preventDefault() {} });
		assert.equal(fetchCalls.length, 1);
		assert.match(fetchCalls[0].url, /\/api\/setup\/scim/);
		assert.equal(location.search, "", "capability token removed from URL after submit");
		assert.equal(Object.keys(storage.local).length, 0);
		assert.equal(Object.keys(storage.session).length, 0);

		const serialized = JSON.stringify(result);
		assert.match(serialized, new RegExp(onceToken));
		assert.match(serialized, /cannot show the token again/i);
		assert.match(serialized, new RegExp(endpoint.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));

		// Copy control writes only to clipboard API (in-memory for this test)
		const copyBtn = (function findCopy(node) {
			if (node?.className === "setup-copy") return node;
			for (const c of node?.children || []) {
				const found = findCopy(c);
				if (found) return found;
			}
			return null;
		})(result);
		assert.ok(copyBtn, "copy control present");
		await copyBtn.listeners.click();
		assert.ok(
			clipboard.last === onceToken || clipboard.last === endpoint,
			"copy writes handoff secret to clipboard only",
		);

		// No second fetch / re-hydration of token
		assert.equal(fetchCalls.length, 1);
		assert.equal(localStorage.getItem("scimToken"), null);
		assert.equal(sessionStorage.getItem("scimToken"), null);
	});

	it("admin session can read and mutates with CSRF + same-origin; injects upstream token", async () => {
		const { cookie, csrf, origin } = await login(
			consolePort,
			ADMIN.username,
			ADMIN.password,
		);
		mockApi.requests.length = 0;
		const read = await fetch(`http://127.0.0.1:${consolePort}/api/v1/users`, {
			headers: {
				cookie,
				authorization: "Bearer client-forged-token",
				"x-clearance-project-id": "proj_forged",
			},
		});
		assert.equal(read.status, 200);
		assert.equal(mockApi.requests.length, 1);
		assert.equal(mockApi.requests[0].headers.authorization, `Bearer ${OPERATOR}`);
		assert.notEqual(mockApi.requests[0].headers.authorization, "Bearer client-forged-token");
		assert.equal(mockApi.requests[0].headers["x-clearance-project-id"], PROJECT);

		// Mutation without CSRF fails
		const noCsrf = await fetch(`http://127.0.0.1:${consolePort}/api/v1/users`, {
			method: "POST",
			headers: {
				cookie,
				origin,
				"content-type": "application/json",
			},
			body: JSON.stringify({ email: "a@b.com" }),
		});
		assert.equal(noCsrf.status, 403);
		assert.equal((await noCsrf.json()).error?.code, "CSRF_TOKEN");

		// Mutation without origin fails
		const noOrigin = await fetch(`http://127.0.0.1:${consolePort}/api/v1/users`, {
			method: "POST",
			headers: {
				cookie,
				"x-csrf-token": csrf,
				"content-type": "application/json",
			},
			body: JSON.stringify({ email: "a@b.com" }),
		});
		assert.equal(noOrigin.status, 403);
		assert.equal((await noOrigin.json()).error?.code, "CSRF_ORIGIN");

		// Valid mutation
		mockApi.requests.length = 0;
		const ok = await fetch(`http://127.0.0.1:${consolePort}/api/v1/users`, {
			method: "POST",
			headers: {
				cookie,
				origin,
				"x-csrf-token": csrf,
				"content-type": "application/json",
			},
			body: JSON.stringify({ email: "a@b.com", name: "A" }),
		});
		assert.equal(ok.status, 200);
		assert.equal(mockApi.requests.length, 1);
		assert.equal(mockApi.requests[0].method, "POST");
		assert.match(mockApi.requests[0].body, /a@b\.com/);
		assert.equal(mockApi.requests[0].headers.authorization, `Bearer ${OPERATOR}`);
	});

	it("proxied requests carry x-forwarded-for from the browser's socket address", async () => {
		const { cookie } = await login(consolePort, ADMIN.username, ADMIN.password);
		mockApi.requests.length = 0;
		const read = await fetch(`http://127.0.0.1:${consolePort}/api/v1/users`, {
			headers: {
				cookie,
				// A spoofed client XFF must not survive the proxy
				"x-forwarded-for": "6.6.6.6",
			},
		});
		assert.equal(read.status, 200);
		assert.equal(mockApi.requests.length, 1);
		// The console observed the test client's loopback socket, not the spoof.
		assert.equal(mockApi.requests[0].headers["x-forwarded-for"], "127.0.0.1");
	});

	it("viewer can read but mutations are forbidden", async () => {
		const { cookie, csrf, origin } = await login(
			consolePort,
			VIEWER.username,
			VIEWER.password,
		);
		const read = await fetch(`http://127.0.0.1:${consolePort}/api/v1/users`, {
			headers: { cookie },
		});
		assert.equal(read.status, 200);

		const mut = await fetch(`http://127.0.0.1:${consolePort}/api/v1/users`, {
			method: "POST",
			headers: {
				cookie,
				origin,
				"x-csrf-token": csrf,
				"content-type": "application/json",
			},
			body: JSON.stringify({ email: "x@y.com" }),
		});
		assert.equal(mut.status, 403);
		assert.equal((await mut.json()).error?.code, "FORBIDDEN_ROLE");
	});

	it("rejects login without same-origin evidence in development", async () => {
		const res = await fetch(`http://127.0.0.1:${consolePort}/api/console/login`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ username: ADMIN.username, password: ADMIN.password }),
		});
		assert.equal(res.status, 403);
		assert.equal((await res.json()).error?.code, "CSRF_ORIGIN");
	});

	it("logout requires CSRF and clears session", async () => {
		const { cookie, origin, csrf } = await login(
			consolePort,
			ADMIN.username,
			ADMIN.password,
		);
		const denied = await fetch(
			`http://127.0.0.1:${consolePort}/api/console/logout`,
			{
				method: "POST",
				headers: { cookie, origin, "content-type": "application/json" },
				body: "{}",
			},
		);
		assert.equal(denied.status, 403);
		const out = await fetch(`http://127.0.0.1:${consolePort}/api/console/logout`, {
			method: "POST",
			headers: {
				cookie,
				origin,
				"x-csrf-token": csrf,
				"content-type": "application/json",
			},
			body: "{}",
		});
		assert.equal(out.status, 200);
		const again = await fetch(`http://127.0.0.1:${consolePort}/api/v1/users`, {
			headers: { cookie },
		});
		assert.equal(again.status, 401);
	});

	it("rejects auth query-string smuggling when authenticated", async () => {
		const { cookie } = await login(consolePort, ADMIN.username, ADMIN.password);
		const res = await fetch(
			`http://127.0.0.1:${consolePort}/api/v1/overview?token=steal-me&authorization=Bearer+x`,
			{ headers: { cookie } },
		);
		assert.equal(res.status, 400);
		const body = await res.json();
		assert.equal(body.error?.code, "CLIENT_AUTH_OVERRIDE_REJECTED");
	});

	it("exposes non-secret console config without operator token", async () => {
		const res = await fetch(`http://127.0.0.1:${consolePort}/api/console/config`);
		assert.equal(res.status, 200);
		const body = await res.json();
		assert.equal(body.hasOperatorToken, true);
		assert.equal(body.projectId, PROJECT);
		assert.equal(body.environmentId, ENV);
		assert.equal(body.authMode, "operator-session");
		const raw = JSON.stringify(body);
		assert.equal(raw.includes(OPERATOR), false);
		assert.equal(body.operatorToken, undefined);
	});

	it("proxies health without requiring client credentials", async () => {
		const res = await fetch(`http://127.0.0.1:${consolePort}/api/health`);
		assert.equal(res.status, 200);
		const body = await res.json();
		assert.equal(body.ok, true);
	});

	it("separates process liveness from upstream-backed readiness", async () => {
		const live = await fetch(`http://127.0.0.1:${consolePort}/livez`);
		assert.equal(live.status, 200);
		assert.deepEqual(await live.json(), {
			ok: true,
			service: "clearance-console",
			state: "live",
		});
		const ready = await fetch(`http://127.0.0.1:${consolePort}/readyz`);
		assert.equal(ready.status, 200);
		assert.deepEqual(await ready.json(), {
			ok: true,
			service: "clearance-console",
			state: "ready",
		});
	});

	it("reuses safe request IDs and replaces unsafe IDs in responses and structured logs", async () => {
		const previousLog = console.log;
		const previousRequestLog = process.env.CLEARANCE_REQUEST_LOG;
		const lines = [];
		console.log = (line) => lines.push(String(line));
		process.env.CLEARANCE_REQUEST_LOG = "1";
		try {
			const supplied = "console.trace-123";
			const valid = await fetch(`http://127.0.0.1:${consolePort}/livez`, {
				headers: { "x-request-id": supplied },
			});
			assert.equal(valid.status, 200);
			assert.equal(valid.headers.get("x-request-id"), supplied);

			const invalid = await fetch(`http://127.0.0.1:${consolePort}/livez`, {
				headers: { "x-request-id": "unsafe request id with spaces" },
			});
			assert.equal(invalid.status, 200);
			const generated = invalid.headers.get("x-request-id");
			assert.match(generated, /^[0-9a-f-]{36}$/);
			assert.notEqual(generated, "unsafe request id with spaces");

			const entries = lines.map((line) => JSON.parse(line));
			assert.ok(entries.some((entry) => entry.event === "http_request" && entry.requestId === supplied));
			assert.ok(entries.some((entry) => entry.event === "http_request" && entry.requestId === generated));
		} finally {
			console.log = previousLog;
			if (previousRequestLog === undefined) {
				delete process.env.CLEARANCE_REQUEST_LOG;
			} else {
				process.env.CLEARANCE_REQUEST_LOG = previousRequestLog;
			}
		}
	});

	it("serves SPA shell and static assets with security headers", async () => {
		const res = await fetch(`http://127.0.0.1:${consolePort}/readiness?org=org_1`);
		assert.equal(res.status, 200);
		const html = await res.text();
		assert.match(html, /Clearance Console/);
		assert.equal(res.headers.get("x-content-type-options"), "nosniff");
		assert.equal(res.headers.get("x-frame-options"), "DENY");
		assert.match(res.headers.get("content-security-policy") || "", /default-src 'self'/);

		const js = await fetch(`http://127.0.0.1:${consolePort}/app.js`);
		assert.equal(js.status, 200);
		assert.match(await js.text(), /escapeHtml/);
	});

	it("returns 401 (not 503) when session missing even if token configured", async () => {
		const bare = createConsoleServer({
			apiBase: "http://127.0.0.1:1",
			operatorToken: OPERATOR,
			projectId: "",
			environmentId: "",
			operators: [ADMIN],
			sessionSecret: "console-session-secret-32chars!!",
			nodeEnv: "development",
		});
		const port = await listen(bare);
		try {
			const res = await fetch(`http://127.0.0.1:${port}/api/v1/overview`);
			assert.equal(res.status, 401);
		} finally {
			await close(bare);
		}
	});

	it("returns 503 when authenticated but upstream operator token missing", async () => {
		const bare = createConsoleServer({
			apiBase: "http://127.0.0.1:1",
			operatorToken: "",
			operators: [ADMIN],
			sessionSecret: "console-session-secret-32chars!!",
			nodeEnv: "development",
		});
		const port = await listen(bare);
		try {
			const { cookie } = await login(port, ADMIN.username, ADMIN.password);
			const res = await fetch(`http://127.0.0.1:${port}/api/v1/overview`, {
				headers: { cookie },
			});
			assert.equal(res.status, 503);
			const body = await res.json();
			assert.equal(body.error?.code, "OPERATOR_TOKEN_UNCONFIGURED");
		} finally {
			await close(bare);
		}
	});
});

describe("roles surface helpers and integration", () => {
	function loadParsePermissionsText() {
		const match = appJs.match(/function parsePermissionsText\(text\) \{[\s\S]*?\n\}/);
		assert.ok(match, "parsePermissionsText must exist");
		// eslint-disable-next-line no-new-func
		return new Function(`${match[0]}; return parsePermissionsText;`)();
	}

	it("parsePermissionsText trims blanks and drops case-insensitive duplicates", () => {
		const parse = loadParsePermissionsText();
		assert.deepEqual(parse("  billing:read \n\nbilling:write\nBilling:Read\n  \n"), [
			"billing:read",
			"billing:write",
		]);
		assert.deepEqual(parse(""), []);
		assert.deepEqual(parse("   \n  "), []);
	});

	it("roles SPA route is served and app.js wires /roles", async () => {
		// Static structure: path /roles loads shell; app.js maps route key
		assert.match(appJs, /history\.replaceState[\s\S]*name/);
		assert.match(appJs, /routes\[path\]/);
		assert.match(indexHtml, /data-route="roles"/);

		const server = createConsoleServer({
			apiBase: "http://127.0.0.1:1",
			operatorToken: "roles-spa-shell-token-32chars!!!!",
			sessionSecret: "roles-spa-shell-session-secret!!",
			operators: [{ username: "a", password: "p", role: "admin" }],
			nodeEnv: "development",
			secureCookies: false,
		});
		const port = await listen(server);
		try {
			const res = await fetch(`http://127.0.0.1:${port}/roles`);
			assert.equal(res.status, 200);
			assert.match(res.headers.get("content-type") || "", /text\/html/);
			const html = await res.text();
			assert.match(html, /Clearance Console/);
			assert.match(html, /data-route="roles"/);
		} finally {
			await close(server);
		}
	});

	it("admin can list/validate/create/update roles via console proxy with CSRF", async () => {
		/** @type {import('node:http').Server} */
		let mock;
		/** @type {ReturnType<typeof createMockApi>} */
		let mockApi;
		/** @type {import('node:http').Server} */
		let consoleServer;
		const OPERATOR = "roles-op-token-32chars-long!!!!";
		const ADMIN = {
			username: "roles-admin",
			password: "roles-admin-pass-32chars-long!",
			role: "admin",
		};
		const roles = [
			{
				id: "role_builtin_owner",
				name: "Owner",
				slug: "owner",
				kind: "built_in",
				permissions: ["ac:read", "ac:update"],
				description: "Full control",
			},
			{
				id: "role_builtin_admin",
				name: "Admin",
				slug: "admin",
				kind: "built_in",
				permissions: ["ac:read"],
			},
			{
				id: "role_builtin_member",
				name: "Member",
				slug: "member",
				kind: "built_in",
				permissions: ["ac:read"],
			},
		];

		mockApi = createMockApi((req, res, record) => {
			const url = req.url || "";
			if (url.startsWith("/v1/roles/validate") && req.method === "POST") {
				const body = JSON.parse(record.body || "{}");
				if (!Array.isArray(body.permissions) || body.permissions.length === 0) {
					res.statusCode = 400;
					res.setHeader("content-type", "application/json");
					res.end(
						JSON.stringify({
							error: {
								code: "ROLE_PERMISSIONS_EMPTY",
								message: "permissions must not be empty",
								remediation: "Provide at least one resource:action permission",
							},
						}),
					);
					return;
				}
				const permissions = [...body.permissions]
					.map((p) => String(p).trim().toLowerCase())
					.sort();
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(
					JSON.stringify({
						ok: true,
						name: body.name,
						slug: body.slug || String(body.name || "").toLowerCase().replace(/\s+/g, "-"),
						permissions,
					}),
				);
				return;
			}
			if (url === "/v1/roles" && req.method === "POST") {
				const body = JSON.parse(record.body || "{}");
				const role = {
					id: `role_${roles.length + 1}`,
					name: body.name,
					slug: body.slug || "custom",
					kind: "custom",
					permissions: body.permissions,
					description: body.description,
				};
				roles.push(role);
				res.statusCode = 201;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ role }));
				return;
			}
			if (url.startsWith("/v1/roles/") && req.method === "PATCH") {
				const id = decodeURIComponent(url.slice("/v1/roles/".length).split("?")[0]);
				const body = JSON.parse(record.body || "{}");
				const role = roles.find((r) => r.id === id);
				if (!role || role.kind === "built_in") {
					res.statusCode = 403;
					res.setHeader("content-type", "application/json");
					res.end(
						JSON.stringify({
							error: { code: "ROLE_BUILT_IN", message: "Built-in roles cannot be updated" },
						}),
					);
					return;
				}
				if (body.name) role.name = body.name;
				if (body.permissions) role.permissions = body.permissions;
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ role }));
				return;
			}
			if (url.startsWith("/v1/roles") && req.method === "GET") {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ roles }));
				return;
			}
			res.statusCode = 404;
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ error: { message: "not found", path: url } }));
		});
		mock = mockApi.server;
		const mockPort = await listen(mock);
		consoleServer = createConsoleServer({
			apiBase: `http://127.0.0.1:${mockPort}`,
			operatorToken: OPERATOR,
			projectId: "proj_roles",
			environmentId: "env_roles",
			environmentLabel: "test",
			port: 0,
			nodeEnv: "development",
			sessionSecret: "roles-console-session-secret-32!!",
			operators: [ADMIN],
			secureCookies: false,
		});
		const consolePort = await listen(consoleServer);
		try {
			const { cookie, csrf, origin } = await login(
				consolePort,
				ADMIN.username,
				ADMIN.password,
			);
			const headers = {
				cookie,
				origin,
				"x-csrf-token": csrf,
				"content-type": "application/json",
			};

			const list = await fetch(`http://127.0.0.1:${consolePort}/api/v1/roles`, {
				headers: { cookie },
			});
			assert.equal(list.status, 200);
			const listed = await list.json();
			assert.equal(listed.roles.filter((r) => r.kind === "built_in").length, 3);

			const validate = await fetch(
				`http://127.0.0.1:${consolePort}/api/v1/roles/validate`,
				{
					method: "POST",
					headers,
					body: JSON.stringify({
						name: "Billing",
						permissions: ["billing:write", "Billing:read"],
					}),
				},
			);
			assert.equal(validate.status, 200);
			const validated = await validate.json();
			assert.deepEqual(validated.permissions, ["billing:read", "billing:write"]);

			const create = await fetch(`http://127.0.0.1:${consolePort}/api/v1/roles`, {
				method: "POST",
				headers,
				body: JSON.stringify({
					name: "Billing",
					slug: "billing",
					permissions: validated.permissions,
				}),
			});
			assert.equal(create.status, 201);
			const created = await create.json();
			assert.equal(created.role.kind, "custom");
			assert.equal(created.role.slug, "billing");

			const patch = await fetch(
				`http://127.0.0.1:${consolePort}/api/v1/roles/${created.role.id}`,
				{
					method: "PATCH",
					headers,
					body: JSON.stringify({
						name: "Billing Ops",
						permissions: ["billing:read", "billing:write", "billing:refund"],
					}),
				},
			);
			assert.equal(patch.status, 200);
			assert.equal((await patch.json()).role.name, "Billing Ops");

			// Built-in update rejected by upstream (proxied)
			const builtinPatch = await fetch(
				`http://127.0.0.1:${consolePort}/api/v1/roles/role_builtin_owner`,
				{
					method: "PATCH",
					headers,
					body: JSON.stringify({ name: "Nope" }),
				},
			);
			assert.equal(builtinPatch.status, 403);

			// Upstream auth is server-injected
			const rolesReqs = mockApi.requests.filter((r) =>
				String(r.url || "").startsWith("/v1/roles"),
			);
			assert.ok(rolesReqs.length >= 4);
			assert.ok(
				rolesReqs.every((r) => r.headers.authorization === `Bearer ${OPERATOR}`),
			);
		} finally {
			await close(consoleServer);
			await close(mock);
		}
	});

	it("viewer can list roles but cannot validate or mutate via console proxy", async () => {
		/** @type {import('node:http').Server} */
		let mock;
		/** @type {import('node:http').Server} */
		let consoleServer;
		const OPERATOR = "roles-viewer-op-token-32chars!!!!";
		const VIEWER = {
			username: "roles-viewer",
			password: "roles-viewer-pass-32chars-long",
			role: "viewer",
		};
		const mockApi = createMockApi((req, res) => {
			if (req.url?.startsWith("/v1/roles") && req.method === "GET") {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(
					JSON.stringify({
						roles: [
							{
								id: "role_builtin_owner",
								name: "Owner",
								slug: "owner",
								kind: "built_in",
								permissions: ["ac:read"],
							},
						],
					}),
				);
				return;
			}
			res.statusCode = 200;
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ ok: true }));
		});
		mock = mockApi.server;
		const mockPort = await listen(mock);
		consoleServer = createConsoleServer({
			apiBase: `http://127.0.0.1:${mockPort}`,
			operatorToken: OPERATOR,
			sessionSecret: "roles-viewer-session-secret-32!!",
			operators: [VIEWER],
			nodeEnv: "development",
			secureCookies: false,
		});
		const consolePort = await listen(consoleServer);
		try {
			const { cookie, csrf, origin } = await login(
				consolePort,
				VIEWER.username,
				VIEWER.password,
			);
			const read = await fetch(`http://127.0.0.1:${consolePort}/api/v1/roles`, {
				headers: { cookie },
			});
			assert.equal(read.status, 200);

			const validate = await fetch(
				`http://127.0.0.1:${consolePort}/api/v1/roles/validate`,
				{
					method: "POST",
					headers: {
						cookie,
						origin,
						"x-csrf-token": csrf,
						"content-type": "application/json",
					},
					body: JSON.stringify({ name: "X", permissions: ["a:b"] }),
				},
			);
			assert.equal(validate.status, 403);
			assert.equal((await validate.json()).error?.code, "FORBIDDEN_ROLE");

			const create = await fetch(`http://127.0.0.1:${consolePort}/api/v1/roles`, {
				method: "POST",
				headers: {
					cookie,
					origin,
					"x-csrf-token": csrf,
					"content-type": "application/json",
				},
				body: JSON.stringify({ name: "X", permissions: ["a:b"] }),
			});
			assert.equal(create.status, 403);
			assert.equal((await create.json()).error?.code, "FORBIDDEN_ROLE");
		} finally {
			await close(consoleServer);
			await close(mock);
		}
	});

	it("roles templates escape role fields and use formatApiError with remediation", () => {
		assert.match(appJs, /escapeHtml\(role\.name\)/);
		assert.match(appJs, /escapeHtml\(role\.slug\)/);
		assert.match(appJs, /formatApiError/);
		assert.match(appJs, /err\?\.remediation/);
		// No raw unescaped role field interpolations in HTML templates
		assert.doesNotMatch(appJs, /\$\{\s*role\.name\s*\}/);
		assert.doesNotMatch(appJs, /\$\{\s*role\.slug\s*\}/);
	});
});

describe("sessions + members console surfaces", () => {
	it("sessions and members SPA routes serve the shell", async () => {
		assert.match(appJs, /history\.replaceState[\s\S]*name/);
		assert.match(indexHtml, /data-route="sessions"/);
		assert.match(indexHtml, /data-route="members"/);
		assert.match(appJs, /setRoute\("members"/);

		const server = createConsoleServer({
			apiBase: "http://127.0.0.1:1",
			operatorToken: "sess-members-spa-token-32chars!!!",
			sessionSecret: "sess-members-spa-session-secret!!",
			operators: [{ username: "a", password: "p", role: "admin" }],
			nodeEnv: "development",
			secureCookies: false,
		});
		const port = await listen(server);
		try {
			for (const path of ["/sessions", "/members"]) {
				const res = await fetch(`http://127.0.0.1:${port}${path}`);
				assert.equal(res.status, 200, path);
				assert.match(res.headers.get("content-type") || "", /text\/html/);
				const html = await res.text();
				assert.match(html, /Clearance Console/);
				assert.match(html, new RegExp(`data-route="${path.slice(1)}"`));
			}
		} finally {
			await close(server);
		}
	});

	it("admin can list/revoke sessions via console proxy with CSRF; strips client auth", async () => {
		const OPERATOR = "sess-op-token-32chars-long!!!!!!";
		const ADMIN = {
			username: "sess-admin",
			password: "sess-admin-pass-32chars-long!!!",
			role: "admin",
		};
		/** @type {{ id: string, principalId: string, status: string, createdAt: string }[]} */
		const sessions = [
			{
				id: "sess_active_1",
				principalId: "usr_1",
				status: "active",
				createdAt: "2026-01-01T00:00:00.000Z",
			},
		];
		const mockApi = createMockApi((req, res, record) => {
			const url = req.url || "";
			if (url.startsWith("/v1/sessions/") && url.endsWith("/revoke") && req.method === "POST") {
				const id = decodeURIComponent(
					url.slice("/v1/sessions/".length).replace(/\/revoke$/, ""),
				);
				const session = sessions.find((s) => s.id === id);
				if (!session) {
					res.statusCode = 404;
					res.setHeader("content-type", "application/json");
					res.end(
						JSON.stringify({
							error: { code: "SESSION_NOT_FOUND", message: "Session not found" },
						}),
					);
					return;
				}
				const already = session.status === "revoked";
				session.status = "revoked";
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				// Upstream must never return token material; assert console proxies body as-is
				res.end(
					JSON.stringify({
						session: { ...session, revokedAt: "2026-01-02T00:00:00.000Z" },
						idempotent: already,
					}),
				);
				return;
			}
			if (url.startsWith("/v1/sessions") && req.method === "GET") {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ sessions, scope: { projectId: "proj_s" } }));
				return;
			}
			res.statusCode = 404;
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ error: { message: "not found", path: url } }));
		});
		const mock = mockApi.server;
		const mockPort = await listen(mock);
		const consoleServer = createConsoleServer({
			apiBase: `http://127.0.0.1:${mockPort}`,
			operatorToken: OPERATOR,
			projectId: "proj_s",
			environmentId: "env_s",
			sessionSecret: "sess-console-session-secret-32!!",
			operators: [ADMIN],
			nodeEnv: "development",
			secureCookies: false,
		});
		const consolePort = await listen(consoleServer);
		try {
			const { cookie, csrf, origin } = await login(
				consolePort,
				ADMIN.username,
				ADMIN.password,
			);
			const headers = {
				cookie,
				origin,
				"x-csrf-token": csrf,
				"content-type": "application/json",
			};

			const list = await fetch(`http://127.0.0.1:${consolePort}/api/v1/sessions`, {
				headers: { cookie },
			});
			assert.equal(list.status, 200);
			const listed = await list.json();
			assert.equal(listed.sessions.length, 1);
			assert.equal(listed.sessions[0].id, "sess_active_1");
			assert.equal("token" in listed.sessions[0], false);

			// Mutation without CSRF rejected by console (never hits upstream)
			const noCsrf = await fetch(
				`http://127.0.0.1:${consolePort}/api/v1/sessions/sess_active_1/revoke`,
				{
					method: "POST",
					headers: { cookie, origin, "content-type": "application/json" },
					body: "{}",
				},
			);
			assert.equal(noCsrf.status, 403);
			assert.equal((await noCsrf.json()).error?.code, "CSRF_TOKEN");

			const revoke = await fetch(
				`http://127.0.0.1:${consolePort}/api/v1/sessions/sess_active_1/revoke`,
				{ method: "POST", headers, body: "{}" },
			);
			assert.equal(revoke.status, 200);
			const revoked = await revoke.json();
			assert.equal(revoked.session.status, "revoked");
			assert.equal(revoked.idempotent, false);
			assert.equal("token" in revoked.session, false);

			const again = await fetch(
				`http://127.0.0.1:${consolePort}/api/v1/sessions/sess_active_1/revoke`,
				{ method: "POST", headers, body: "{}" },
			);
			assert.equal(again.status, 200);
			assert.equal((await again.json()).idempotent, true);

			const sessReqs = mockApi.requests.filter((r) =>
				String(r.url || "").startsWith("/v1/sessions"),
			);
			assert.ok(sessReqs.length >= 3);
			assert.ok(
				sessReqs.every((r) => r.headers.authorization === `Bearer ${OPERATOR}`),
			);
			// Client Authorization must never override server injection
			assert.ok(
				!sessReqs.some((r) =>
					String(r.headers.authorization || "").includes("evil"),
				),
			);
			const wire = JSON.stringify(sessReqs);
			assert.doesNotMatch(wire, /"token"\s*:/);
		} finally {
			await close(consoleServer);
			await close(mock);
		}
	});

	it("viewer can list sessions but cannot revoke via console proxy", async () => {
		const OPERATOR = "sess-viewer-op-token-32chars!!!!";
		const VIEWER = {
			username: "sess-viewer",
			password: "sess-viewer-pass-32chars-long!",
			role: "viewer",
		};
		const mockApi = createMockApi((req, res) => {
			if (req.url?.startsWith("/v1/sessions") && req.method === "GET") {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(
					JSON.stringify({
						sessions: [
							{
								id: "sess_v",
								principalId: "usr_v",
								status: "active",
								createdAt: "2026-01-01T00:00:00.000Z",
							},
						],
					}),
				);
				return;
			}
			res.statusCode = 200;
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ ok: true }));
		});
		const mock = mockApi.server;
		const mockPort = await listen(mock);
		const consoleServer = createConsoleServer({
			apiBase: `http://127.0.0.1:${mockPort}`,
			operatorToken: OPERATOR,
			sessionSecret: "sess-viewer-session-secret-32!!",
			operators: [VIEWER],
			nodeEnv: "development",
			secureCookies: false,
		});
		const consolePort = await listen(consoleServer);
		try {
			const { cookie, csrf, origin } = await login(
				consolePort,
				VIEWER.username,
				VIEWER.password,
			);
			const read = await fetch(`http://127.0.0.1:${consolePort}/api/v1/sessions`, {
				headers: { cookie },
			});
			assert.equal(read.status, 200);

			const revoke = await fetch(
				`http://127.0.0.1:${consolePort}/api/v1/sessions/sess_v/revoke`,
				{
					method: "POST",
					headers: {
						cookie,
						origin,
						"x-csrf-token": csrf,
						"content-type": "application/json",
					},
					body: "{}",
				},
			);
			assert.equal(revoke.status, 403);
			assert.equal((await revoke.json()).error?.code, "FORBIDDEN_ROLE");
			// Viewer mutation must not reach upstream
			assert.equal(
				mockApi.requests.filter((r) => r.method === "POST").length,
				0,
			);
		} finally {
			await close(consoleServer);
			await close(mock);
		}
	});

	it("admin can list/add/update/remove members via console proxy with CSRF", async () => {
		const OPERATOR = "mem-op-token-32chars-long!!!!!!!";
		const ADMIN = {
			username: "mem-admin",
			password: "mem-admin-pass-32chars-long!!!!",
			role: "admin",
		};
		const orgId = "org_console_1";
		/** @type {{ id: string, organizationId: string, principalId: string, role: string, status: string }[]} */
		const members = [
			{
				id: "mem_owner",
				organizationId: orgId,
				principalId: "usr_owner",
				role: "owner",
				status: "active",
			},
		];
		const mockApi = createMockApi((req, res, record) => {
			const url = req.url || "";
			const base = `/v1/organizations/${orgId}/members`;
			if (url === base && req.method === "GET") {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ members, scope: { projectId: "proj_m" } }));
				return;
			}
			if (url === base && req.method === "POST") {
				const body = JSON.parse(record.body || "{}");
				if (!body.principalId) {
					res.statusCode = 400;
					res.setHeader("content-type", "application/json");
					res.end(
						JSON.stringify({
							error: {
								code: "MEMBER_PRINCIPAL_REQUIRED",
								message: "principalId is required",
							},
						}),
					);
					return;
				}
				const membership = {
					id: `mem_${members.length + 1}`,
					organizationId: orgId,
					principalId: body.principalId,
					role: body.role || "member",
					status: "active",
				};
				members.push(membership);
				res.statusCode = 201;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ membership }));
				return;
			}
			const memberMatch = url.match(
				new RegExp(`^/v1/organizations/${orgId}/members/([^/?]+)$`),
			);
			if (memberMatch && req.method === "PATCH") {
				const id = decodeURIComponent(memberMatch[1]);
				const body = JSON.parse(record.body || "{}");
				const membership = members.find((m) => m.id === id);
				if (!membership) {
					res.statusCode = 404;
					res.setHeader("content-type", "application/json");
					res.end(
						JSON.stringify({
							error: { code: "MEMBER_NOT_FOUND", message: "not found" },
						}),
					);
					return;
				}
				membership.role = body.role;
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ membership }));
				return;
			}
			if (memberMatch && req.method === "DELETE") {
				const id = decodeURIComponent(memberMatch[1]);
				const membership = members.find((m) => m.id === id);
				if (!membership) {
					res.statusCode = 404;
					res.setHeader("content-type", "application/json");
					res.end(
						JSON.stringify({
							error: { code: "MEMBER_NOT_FOUND", message: "not found" },
						}),
					);
					return;
				}
				membership.status = "removed";
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ membership }));
				return;
			}
			res.statusCode = 404;
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ error: { message: "not found", path: url } }));
		});
		const mock = mockApi.server;
		const mockPort = await listen(mock);
		const consoleServer = createConsoleServer({
			apiBase: `http://127.0.0.1:${mockPort}`,
			operatorToken: OPERATOR,
			projectId: "proj_m",
			environmentId: "env_m",
			sessionSecret: "mem-console-session-secret-32!!!",
			operators: [ADMIN],
			nodeEnv: "development",
			secureCookies: false,
		});
		const consolePort = await listen(consoleServer);
		try {
			const { cookie, csrf, origin } = await login(
				consolePort,
				ADMIN.username,
				ADMIN.password,
			);
			const headers = {
				cookie,
				origin,
				"x-csrf-token": csrf,
				"content-type": "application/json",
			};
			const base = `http://127.0.0.1:${consolePort}/api/v1/organizations/${orgId}/members`;

			const list = await fetch(base, { headers: { cookie } });
			assert.equal(list.status, 200);
			assert.equal((await list.json()).members.length, 1);

			const noCsrf = await fetch(base, {
				method: "POST",
				headers: { cookie, origin, "content-type": "application/json" },
				body: JSON.stringify({ principalId: "usr_x", role: "member" }),
			});
			assert.equal(noCsrf.status, 403);
			assert.equal((await noCsrf.json()).error?.code, "CSRF_TOKEN");

			const add = await fetch(base, {
				method: "POST",
				headers,
				body: JSON.stringify({ principalId: "usr_member", role: "admin" }),
			});
			assert.equal(add.status, 201);
			const added = await add.json();
			assert.equal(added.membership.role, "admin");
			assert.equal(added.membership.principalId, "usr_member");

			const patch = await fetch(`${base}/${added.membership.id}`, {
				method: "PATCH",
				headers,
				body: JSON.stringify({ role: "member" }),
			});
			assert.equal(patch.status, 200);
			assert.equal((await patch.json()).membership.role, "member");

			const del = await fetch(`${base}/${added.membership.id}`, {
				method: "DELETE",
				headers,
			});
			assert.equal(del.status, 200);
			assert.equal((await del.json()).membership.status, "removed");

			const memReqs = mockApi.requests.filter((r) =>
				String(r.url || "").includes("/members"),
			);
			assert.ok(memReqs.length >= 4);
			assert.ok(
				memReqs.every((r) => r.headers.authorization === `Bearer ${OPERATOR}`),
			);
		} finally {
			await close(consoleServer);
			await close(mock);
		}
	});

	it("viewer can list members but cannot mutate via console proxy", async () => {
		const OPERATOR = "mem-viewer-op-token-32chars!!!!!";
		const VIEWER = {
			username: "mem-viewer",
			password: "mem-viewer-pass-32chars-long!!",
			role: "viewer",
		};
		const orgId = "org_v";
		const mockApi = createMockApi((req, res) => {
			if (
				req.url?.startsWith(`/v1/organizations/${orgId}/members`) &&
				req.method === "GET"
			) {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ members: [] }));
				return;
			}
			res.statusCode = 200;
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ ok: true }));
		});
		const mock = mockApi.server;
		const mockPort = await listen(mock);
		const consoleServer = createConsoleServer({
			apiBase: `http://127.0.0.1:${mockPort}`,
			operatorToken: OPERATOR,
			sessionSecret: "mem-viewer-session-secret-32!!!!",
			operators: [VIEWER],
			nodeEnv: "development",
			secureCookies: false,
		});
		const consolePort = await listen(consoleServer);
		try {
			const { cookie, csrf, origin } = await login(
				consolePort,
				VIEWER.username,
				VIEWER.password,
			);
			const base = `http://127.0.0.1:${consolePort}/api/v1/organizations/${orgId}/members`;
			const read = await fetch(base, { headers: { cookie } });
			assert.equal(read.status, 200);

			const headers = {
				cookie,
				origin,
				"x-csrf-token": csrf,
				"content-type": "application/json",
			};
			for (const [method, path, body] of [
				["POST", base, JSON.stringify({ principalId: "u1", role: "member" })],
				["PATCH", `${base}/mem_1`, JSON.stringify({ role: "admin" })],
				["DELETE", `${base}/mem_1`, undefined],
			]) {
				const res = await fetch(path, {
					method,
					headers,
					...(body ? { body } : {}),
				});
				assert.equal(res.status, 403, method);
				assert.equal((await res.json()).error?.code, "FORBIDDEN_ROLE");
			}
			assert.equal(
				mockApi.requests.filter((r) => r.method !== "GET").length,
				0,
			);
		} finally {
			await close(consoleServer);
			await close(mock);
		}
	});

	it("sessions UI helpers strip credential-like keys and escape session fields", () => {
		assert.match(appJs, /function sanitizeSessionForUi/);
		assert.match(appJs, /SESSION_SENSITIVE_KEY/);
		assert.match(appJs, /escapeHtml\(session\.id\)/);
		assert.match(appJs, /escapeHtml\(session\.principalId\)/);
		assert.doesNotMatch(appJs, /\$\{\s*session\.id\s*\}/);
		assert.doesNotMatch(appJs, /\$\{\s*member\.principalId\s*\}/);
		assert.match(appJs, /escapeHtml\(member\.principalId\)|escapeHtml\(member\.id\)/);
		// Source must not reference browser storage of session tokens
		assert.doesNotMatch(appJs, /localStorage\.setItem\([^)]*token/i);
		assert.doesNotMatch(appJs, /sessionStorage\.setItem/);
	});

	it("sessions and members guard route races, confirm every mutation, and remain usable on narrow screens", () => {
		assert.match(appJs, /navigationVersion/);
		assert.match(appJs, /params\?\.routeVersion !== navigationVersion/);
		assert.match(
			appJs,
			/confirmDestructive\(\s*`Add principal \$\{principalId\}/,
		);
		assert.match(appJs, /data-original-role=/);
		assert.match(appJs, /data-update-member=.*disabled/);
		assert.match(appJs, /class="table-scroll" tabindex="0" role="region"/);
		assert.match(stylesCss, /\.table-scroll\s*\{[^}]*overflow-x:\s*auto/s);
		assert.match(indexHtml, /data-route="overview"[^>]*aria-current="page"/);
		assert.match(appJs, /setAttribute\("aria-current", "page"\)/);
	});

	it("sanitizeSessionForUi drops token-like fields", () => {
		const start = appJs.indexOf("const SESSION_SENSITIVE_KEY");
		const fnStart = appJs.indexOf("function sanitizeSessionForUi(raw)");
		assert.ok(start >= 0 && fnStart > start, "sanitizeSessionForUi must exist");
		// Grab through the next top-level function after sanitizeSessionForUi
		const afterFn = appJs.slice(fnStart);
		const endRel = afterFn.search(/\nfunction [a-zA-Z]/);
		assert.ok(endRel > 0, "sanitizeSessionForUi must be followed by another function");
		const snippet = appJs.slice(start, fnStart + endRel);
		// eslint-disable-next-line no-new-func
		const sanitize = new Function(`${snippet}; return sanitizeSessionForUi;`)();
		const dirty = {
			id: "sess_1",
			principalId: "usr_1",
			status: "active",
			createdAt: "2026-01-01T00:00:00.000Z",
			token: "super-secret-session-token",
			bearerToken: "Bearer leak",
			password: "nope",
			authorization: "Bearer x",
		};
		const clean = sanitize(dirty);
		assert.equal(clean.id, "sess_1");
		assert.equal(clean.principalId, "usr_1");
		assert.equal("token" in clean, false);
		assert.equal("bearerToken" in clean, false);
		assert.equal("password" in clean, false);
		assert.equal("authorization" in clean, false);
		assert.equal(JSON.stringify(clean).includes("super-secret"), false);
	});
});

describe("rendering safety (XSS)", () => {
	function loadEscapeHtml() {
		const match = appJs.match(/function escapeHtml\(s\) \{[\s\S]*?\n\}/);
		assert.ok(match, "escapeHtml function must exist in app.js");
		// eslint-disable-next-line no-new-func
		return new Function(`${match[0]}; return escapeHtml;`)();
	}

	it("escapeHtml neutralizes markup and quotes", () => {
		const escapeHtml = loadEscapeHtml();
		const dirty = `<img src=x onerror="alert('xss')"> & "q" 's'`;
		const out = escapeHtml(dirty);
		assert.equal(out.includes("<"), false);
		assert.equal(out.includes(">"), false);
		assert.match(out, /&lt;img/);
		assert.match(out, /&amp;/);
		assert.match(out, /&quot;/);
		assert.match(out, /&#39;/);
		assert.equal(out.startsWith("&lt;img"), true);
		assert.equal(out.includes("<script"), false);
		assert.equal(escapeHtml("<svg/onload=alert(1)>"), "&lt;svg/onload=alert(1)&gt;");
	});

	it("escapeHtml handles nullish and non-strings", () => {
		const escapeHtml = loadEscapeHtml();
		assert.equal(escapeHtml(null), "");
		assert.equal(escapeHtml(undefined), "");
		assert.equal(escapeHtml(42), "42");
	});

	it("templates escape user-controlled API fields (no raw ${u.email} etc.)", () => {
		const rawFieldPatterns = [
			/\$\{\s*u\.email\s*\}/,
			/\$\{\s*u\.name\s*\}/,
			/\$\{\s*u\.status\s*\}/,
			/\$\{\s*u\.id\s*\}/,
			/\$\{\s*o\.name\s*\}/,
			/\$\{\s*o\.slug\s*\}/,
			/\$\{\s*o\.status\s*\}/,
			/\$\{\s*o\.id\s*\}/,
			/\$\{\s*e\.action\s*\}/,
			/\$\{\s*e\.message\s*\}/,
			/\$\{\s*e\.actor\s*\}/,
			/\$\{\s*e\.outcome\s*\}/,
			/\$\{\s*e\.correlationId\s*\}/,
			/\$\{\s*c\.name\s*\}/,
			/\$\{\s*c\.detail\s*\}/,
			/\$\{\s*c\.status\s*\}/,
			/\$\{\s*c\.id\s*\}/,
			/\$\{\s*c\.fingerprint\s*\}/,
			/\$\{\s*report\.overall\s*\}/,
			/\$\{\s*report\.signature\s*\}/,
			/\$\{\s*report\.organizationId\s*\}/,
			/\$\{\s*settings\.releaseVersion\s*\}/,
			/\$\{\s*settings\.schemaVersion\s*\}/,
			/\$\{\s*configJson\s*\}/,
			/\$\{\s*session\.id\s*\}/,
			/\$\{\s*session\.principalId\s*\}/,
			/\$\{\s*session\.status\s*\}/,
			/\$\{\s*session\.userAgent\s*\}/,
			/\$\{\s*member\.id\s*\}/,
			/\$\{\s*member\.principalId\s*\}/,
			/\$\{\s*member\.role\s*\}/,
			/\$\{\s*member\.status\s*\}/,
		];
		for (const re of rawFieldPatterns) {
			let searchFrom = 0;
			let match;
			while ((match = appJs.slice(searchFrom).match(re))) {
				const idx = searchFrom + (match.index ?? 0);
				const window = appJs.slice(Math.max(0, idx - 80), idx + 80);
				assert.match(
					window,
					/escapeHtml\s*\(|escapeAttr\s*\(|stateError\s*\(|stateEmpty\s*\(|stateLoading\s*\(|cliBlock\s*\(/,
					`Unescaped API field interpolation near: ${window.replace(/\s+/g, " ")}`,
				);
				searchFrom = idx + match[0].length;
			}
		}
	});

	it("innerHTML error paths use stateError or escapeHtml", () => {
		assert.match(appJs, /function stateError/);
		assert.match(appJs, /function escapeHtml/);
		assert.match(appJs, /stateError\(/);
		assert.match(appJs, /stateError[\s\S]*?escapeHtml\(msg\)/);
	});

	it("client api() strips Authorization and scope headers; uses CSRF for mutations", () => {
		assert.match(appJs, /delete headers\.authorization/);
		assert.match(appJs, /x-clearance-project-id/);
		assert.match(appJs, /x-clearance-environment-id/);
		assert.match(appJs, /x-csrf-token|operatorCsrf/);
		assert.doesNotMatch(appJs, /process\.env/);
		assert.doesNotMatch(appJs, /localStorage/);
		assert.doesNotMatch(appJs, /sessionStorage/);
		assert.doesNotMatch(appJs, /Bearer \$\{/);
	});

	it("routes implement loading, error, and empty states", () => {
		assert.match(appJs, /stateLoading/);
		assert.match(appJs, /stateError/);
		assert.match(appJs, /stateEmpty/);
		for (const name of [
			"renderOverview",
			"renderUsers",
			"renderOrgs",
			"renderMembers",
			"renderSessions",
			"renderRoles",
			"renderEvents",
			"renderReadiness",
			"renderSettings",
		]) {
			assert.match(appJs, new RegExp(`async function ${name}|function ${name}`));
		}
		assert.match(appJs, /No users yet/);
		assert.match(appJs, /No organizations yet/);
		assert.match(appJs, /No custom roles yet|No roles returned/);
		assert.match(appJs, /No events yet/);
		assert.match(appJs, /No active sessions|No members in this organization/);
	});

	it("forms exist for supported mutations with CLI equivalents", () => {
		assert.match(appJs, /u-form|Create user/);
		assert.match(appJs, /o-form|Create organization/);
		assert.match(appJs, /r-form|Create custom role|Create role/);
		assert.match(appJs, /m-form|Add member/);
		assert.match(appJs, /ready-run|Run readiness check/);
		assert.match(appJs, /POST.*\/v1\/users|method:\s*"POST"[\s\S]*\/v1\/users/);
		assert.match(appJs, /\/v1\/organizations/);
		assert.match(appJs, /\/v1\/roles\/validate/);
		assert.match(appJs, /\/v1\/sessions/);
		assert.match(appJs, /\/v1\/readiness\/check/);
		assert.match(appJs, /cliBlock|clearance users create/);
		assert.match(appJs, /clearance orgs create/);
		assert.match(appJs, /clearance orgs members (list|add|update|remove)/);
		assert.match(appJs, /clearance sessions (list|revoke)/);
		assert.match(appJs, /clearance roles (list|create|validate)/);
		assert.match(appJs, /clearance readiness check/);
		assert.match(appJs, /copy-cli|data-copy/);
	});
});

describe("package metadata", () => {
	it("test script runs the server and DOM suites", () => {
		const pkg = JSON.parse(
			readFileSync(join(root, "..", "package.json"), "utf8"),
		);
		assert.equal(pkg.name, "@clearance/console");
		assert.match(pkg.scripts.test, /server\.test\.js/);
		assert.match(pkg.scripts.test, /ui\.test\.js/);
	});
});
