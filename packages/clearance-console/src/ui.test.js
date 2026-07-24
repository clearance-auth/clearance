/**
 * DOM-level behavioral tests for the console SPA login flow.
 *
 * These exist because the 2026-07-13 audit found the login backend fully
 * implemented and tested while the shipped UI had no way to reach it (dead
 * consoleLogin, no form). They run the real public/app.js against the real
 * public/index.html markup in happy-dom with a stateful mock of the console
 * server, and MUST fail if the login form or its wiring is removed.
 */
import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import vm from "node:vm";
import { randomUUID } from "node:crypto";
import { Window } from "happy-dom";

const here = path.dirname(fileURLToPath(import.meta.url));
const indexHtml = readFileSync(
	path.join(here, "..", "public", "index.html"),
	"utf8",
);
const appJs = readFileSync(path.join(here, "..", "public", "app.js"), "utf8");

const GOOD = { username: "admin", password: "correct-horse" };
const CSRF = "csrf-token-for-tests";

/** Stateful mock of the console server's /api surface. */
function createMockServer() {
	const state = { loggedIn: false, requests: [], deferAssignments: false, assignmentResolvers: [], credentialFailures: 0 };
	async function fetchImpl(input, init = {}) {
		const url = String(input);
		const method = (init.method || "GET").toUpperCase();
		const headers = {};
		for (const [k, v] of Object.entries(init.headers || {})) {
			headers[k.toLowerCase()] = v;
		}
		const record = { url, method, headers, body: init.body ?? null };
		state.requests.push(record);
		const respond = (status, body) => ({
			ok: status >= 200 && status < 300,
			status,
			statusText: String(status),
			json: async () => body,
		});
		const authed = () => state.loggedIn;

		if (url === "/api/console/session") {
			return authed()
				? respond(200, {
						ok: true,
						username: GOOD.username,
						role: "admin",
						csrf: CSRF,
						expiresAt: new Date(8640000000000).toISOString(),
					})
				: respond(401, {
						error: { code: "NOT_AUTHENTICATED", message: "No operator session" },
					});
		}
		if (url === "/api/console/login" && method === "POST") {
			const body = JSON.parse(String(init.body || "{}"));
			if (body.username === GOOD.username && body.password === GOOD.password) {
				state.loggedIn = true;
				return respond(200, {
					ok: true,
					username: GOOD.username,
					role: "admin",
					csrf: CSRF,
				});
			}
			return respond(401, {
				error: {
					code: "INVALID_CREDENTIALS",
					message: "Invalid username or password",
				},
			});
		}
		if (url === "/api/console/logout" && method === "POST") {
			if (!authed()) {
				return respond(401, {
					error: { code: "NOT_AUTHENTICATED", message: "Operator session required" },
				});
			}
			if (headers["x-csrf-token"] !== CSRF) {
				return respond(403, {
					error: { code: "CSRF_TOKEN", message: "CSRF token required" },
				});
			}
			state.loggedIn = false;
			return respond(200, { ok: true });
		}
		if (url === "/api/health") {
			return respond(200, { ok: true, version: "0.3.0" });
		}
		if (url === "/api/console/config") {
			return respond(200, {
				ok: true,
				environmentLabel: "test",
				authenticated: authed(),
				role: authed() ? "admin" : null,
				username: authed() ? GOOD.username : null,
				hasOperatorToken: true,
			});
		}
		// Everything else is the proxied management surface: session-gated.
		if (!authed()) {
			return respond(401, {
				error: { code: "NOT_AUTHENTICATED", message: "Operator session required" },
			});
		}
		if (url === "/api/v1/overview") {
			return respond(200, {
				totalUsers: 3,
				activeUsers: 2,
				organizations: 1,
				activeSessions: 1,
				recentEvents: [],
			});
		}
		if (url === "/api/v1/organizations") {
			return respond(200, {
				organizations: [{ id: "org_1", name: "Acme", slug: "acme", status: "active" }],
			});
		}
		if (url === "/api/v1/roles") {
			return respond(200, {
				roles: [{ id: "role_builtin_member", name: "Member", slug: "member", kind: "built_in", permissions: ["projects:read"] }],
			});
		}
		if (url === "/api/v1/organizations/org_1/authorization/assignments") {
			if (state.deferAssignments) {
				return new Promise((resolve) => {
					state.assignmentResolvers.push(() => resolve(respond(200, { assignments: [] })));
				});
			}
			return respond(200, { assignments: [] });
		}
		if (url === "/api/v1/organizations/org_1/authorization/assignments/principal/user_1" && method === "PATCH") {
			return respond(200, {
				dryRun: true,
				wouldChange: true,
				currentRevision: "1",
				assignment: { roleIds: ["role_builtin_member"] },
			});
		}
		if (url === "/api/v1/organizations/org_1/service-accounts") {
			return respond(200, { serviceAccounts: [{ serviceAccountId: "svc_1", name: "Deploy automation", status: "active" }] });
		}
		if (url === "/api/v1/organizations/org_1/service-accounts/svc_1") {
			return respond(200, {
				serviceAccount: { serviceAccountId: "svc_1", name: "Deploy automation", status: "active" },
				assignments: [],
			});
		}
		if (/^\/api\/v1\/organizations\/org_1\/service-accounts\/svc_1\/credentials(?:\/cred_1\/(?:rotate|revoke))?$/.test(url) && method === "POST") {
			if (state.credentialFailures > 0) {
				state.credentialFailures -= 1;
				return respond(503, { error: { code: "UPSTREAM_UNAVAILABLE", message: "Response lost" } });
			}
			return respond(200, { secret: "one-time-secret" });
		}
		if (url.startsWith("/api/v1/users")) {
			return respond(200, { users: [] });
		}
		return respond(200, { ok: true });
	}
	return { state, fetchImpl };
}

/** Boot the real SPA source in happy-dom against the mock server. */
function bootConsole() {
	const window = new Window({ url: "http://localhost:3100/overview" });
	window.confirm = () => true;
	const bodyMarkup = indexHtml
		.replace(/^[\s\S]*<body>/, "")
		.replace(/<\/body>[\s\S]*$/, "")
		.replace(/<script[^>]*><\/script>/g, "");
	window.document.body.innerHTML = bodyMarkup;

	const server = createMockServer();
	const sandbox = {
		window,
		document: window.document,
		location: window.location,
		history: window.history,
		navigator: window.navigator,
		fetch: server.fetchImpl,
		setInterval: () => 0,
		clearInterval: () => {},
		setTimeout,
		console,
		confirm: () => true,
		URLSearchParams,
		crypto: { randomUUID },
	};
	sandbox.globalThis = sandbox;
	vm.createContext(sandbox);
	vm.runInContext(appJs, sandbox, { filename: "app.js" });
	return { window, document: window.document, server };
}

async function until(predicate, what) {
	const deadline = Date.now() + 2000;
	for (;;) {
		if (predicate()) return;
		if (Date.now() > deadline) {
			assert.fail(`timed out waiting for: ${what}`);
		}
		await new Promise((r) => setTimeout(r, 5));
	}
}

function submitLogin(document, window, username, password) {
	document.getElementById("login-username").value = username;
	document.getElementById("login-password").value = password;
	document
		.getElementById("console-login-form")
		.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
}

async function openServiceAccountCredentials(ctx) {
	const { document, window } = ctx;
	await until(() => document.getElementById("login-host").hidden === false, "login view visible");
	submitLogin(document, window, GOOD.username, GOOD.password);
	await until(() => document.querySelector(".app").hidden === false, "app visible after login");
	document.querySelector('[data-route="service-accounts"]').dispatchEvent(new window.Event("click", { bubbles: true }));
	await until(() => document.querySelector('[data-inspect-account="svc_1"]'), "service account listed");
	document.querySelector('[data-inspect-account="svc_1"]').dispatchEvent(new window.Event("click", { bubbles: true }));
	await until(() => document.querySelector('[data-credential-action="create"]'), "credential actions rendered");
}

function credentialRequests(server, suffix = "") {
	return server.state.requests.filter((request) => request.method === "POST" && request.url === `/api/v1/organizations/org_1/service-accounts/svc_1/credentials${suffix}`);
}

describe("console SPA login flow (DOM)", () => {
	let ctx;
	beforeEach(() => {
		ctx = bootConsole();
	});

	it("unauthenticated boot renders the login form, not the surfaces", async () => {
		const { document } = ctx;
		await until(
			() => document.getElementById("login-host").hidden === false,
			"login view visible",
		);
		const form = document.querySelector('form[data-testid="console-login"]');
		assert.ok(form, "login form must exist in served markup");
		assert.equal(document.querySelector(".app").hidden, true, "app shell hidden");
		assert.ok(document.getElementById("login-username"));
		assert.ok(document.getElementById("login-password"));
	});

	it("bad credentials show a structured error and stay on the login view", async () => {
		const { document, window } = ctx;
		await until(
			() => document.getElementById("login-host").hidden === false,
			"login view visible",
		);
		submitLogin(document, window, GOOD.username, "wrong-password");
		await until(
			() => document.getElementById("login-error").hidden === false,
			"login error visible",
		);
		assert.match(
			document.getElementById("login-error").textContent,
			/Invalid username or password/,
		);
		assert.equal(document.getElementById("login-host").hidden, false);
		assert.equal(document.querySelector(".app").hidden, true);
	});

	it("login POST is same-origin JSON with no CSRF header; success renders Overview and the sign-out control", async () => {
		const { document, window, server } = ctx;
		await until(
			() => document.getElementById("login-host").hidden === false,
			"login view visible",
		);
		submitLogin(document, window, GOOD.username, GOOD.password);
		await until(
			() => document.querySelector(".app").hidden === false,
			"app shell visible after login",
		);
		const login = server.state.requests.find(
			(r) => r.url === "/api/console/login",
		);
		assert.ok(login, "login request issued");
		assert.equal(login.method, "POST");
		assert.equal(login.headers["content-type"], "application/json");
		assert.equal(
			login.headers["x-csrf-token"],
			undefined,
			"login must not carry a CSRF header (token is issued BY login)",
		);
		assert.deepEqual(JSON.parse(login.body), GOOD);

		assert.equal(document.getElementById("login-host").hidden, true);
		const signout = document.querySelector('[data-testid="console-signout"]');
		assert.equal(signout.hidden, false, "sign-out control visible");
		assert.match(signout.textContent, /admin/, "role/username surfaced");
		await until(
			() => /Total users/.test(document.getElementById("view").innerHTML),
			"overview rendered with live data",
		);
		assert.ok(
			server.state.requests.some((r) => r.url === "/api/v1/overview"),
			"overview fetched from management surface",
		);
	});

	it("logout carries the issued CSRF token and returns to the login view", async () => {
		const { document, window, server } = ctx;
		await until(
			() => document.getElementById("login-host").hidden === false,
			"login view visible",
		);
		submitLogin(document, window, GOOD.username, GOOD.password);
		await until(
			() => document.querySelector(".app").hidden === false,
			"app visible after login",
		);
		document
			.getElementById("signout-btn")
			.dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(
			() => document.getElementById("login-host").hidden === false,
			"login view after logout",
		);
		const logout = server.state.requests.find(
			(r) => r.url === "/api/console/logout",
		);
		assert.ok(logout, "logout request issued");
		assert.equal(
			logout.headers["x-csrf-token"],
			CSRF,
			"mutations carry the issued CSRF token",
		);
		assert.equal(server.state.loggedIn, false, "server session destroyed");
		assert.match(
			document.getElementById("login-notice").textContent,
			/Signed out/,
		);
	});

	it("mid-session 401 on a data call routes back to login with an expiry notice", async () => {
		const { document, window, server } = ctx;
		await until(
			() => document.getElementById("login-host").hidden === false,
			"login view visible",
		);
		submitLogin(document, window, GOOD.username, GOOD.password);
		await until(
			() => document.querySelector(".app").hidden === false,
			"app visible after login",
		);
		// Server-side revocation (expiry) without client knowledge.
		server.state.loggedIn = false;
		document
			.querySelector('.rail button[data-route="users"]')
			.dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(
			() => document.getElementById("login-host").hidden === false,
			"login view after session expiry",
		);
		assert.match(
			document.getElementById("login-notice").textContent,
			/Session expired/,
		);
		assert.equal(document.querySelector(".app").hidden, true);
	});

	it("authorization route previews a revisioned replacement through the CSRF BFF", async () => {
		const { document, window, server } = ctx;
		await until(() => document.getElementById("login-host").hidden === false, "login view visible");
		submitLogin(document, window, GOOD.username, GOOD.password);
		await until(() => document.querySelector(".app").hidden === false, "app visible after login");
		document.querySelector('[data-route="authorization"]').dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => document.getElementById("az-replace-id"), "authorization screen rendered");
		document.getElementById("az-replace-id").value = "user_1";
		document.getElementById("az-role-ids").value = "role_builtin_member";
		document.getElementById("az-preview").dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(
			() => server.state.requests.some((request) => request.url === "/api/v1/organizations/org_1/authorization/assignments/principal/user_1"),
			"authorization preview request",
		);
		const preview = server.state.requests.find((request) => request.url === "/api/v1/organizations/org_1/authorization/assignments/principal/user_1");
		assert.equal(preview.method, "PATCH");
		assert.equal(preview.headers["x-csrf-token"], CSRF);
		assert.deepEqual(JSON.parse(preview.body), { roleIds: ["role_builtin_member"], dryRun: true });
		await until(() => document.getElementById("az-apply").disabled === false, "apply enabled after preview");
	});

	it("ignores delayed authorization work after navigation to service accounts", async () => {
		const { document, window, server } = ctx;
		await until(() => document.getElementById("login-host").hidden === false, "login view visible");
		submitLogin(document, window, GOOD.username, GOOD.password);
		await until(() => document.querySelector(".app").hidden === false, "app visible after login");
		server.state.deferAssignments = true;
		document.querySelector('[data-route="authorization"]').dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => document.getElementById("az-assignments"), "authorization shell rendered");
		document.querySelector('[data-route="service-accounts"]').dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => document.getElementById("sa-create-form"), "service-account screen rendered");
		for (const resolve of server.state.assignmentResolvers.splice(0)) resolve();
		await new Promise((resolve) => setTimeout(resolve, 20));
		assert.ok(document.getElementById("sa-create-form"), "new route remains visible");
		assert.equal(document.getElementById("az-assignments"), null, "old authorization result cannot overwrite the new route");
	});

	it("reuses one canonical operation ID for a failed credential retry, then replaces it when the payload changes or succeeds", async () => {
		const { document, window, server } = ctx;
		await openServiceAccountCredentials(ctx);
		server.state.credentialFailures = 1;
		const create = document.querySelector('[data-credential-action="create"]');
		create.dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => credentialRequests(server).length === 1 && create.disabled === false, "failed credential create");
		create.dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => credentialRequests(server).length === 2 && create.disabled === false, "credential create retry");
		const [first, retry] = credentialRequests(server).map((request) => JSON.parse(request.body));
		assert.match(first.operationId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
		assert.equal(retry.operationId, first.operationId, "an exact retry reuses its operation ID");

		document.getElementById("sa-expires-at").value = "2030-01-01T00:00:00.000Z";
		create.dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => credentialRequests(server).length === 3 && create.disabled === false, "changed credential create");
		const changed = JSON.parse(credentialRequests(server)[2].body);
		assert.notEqual(changed.operationId, first.operationId, "a changed payload gets a new operation ID");
		assert.equal(changed.expiresAt, "2030-01-01T00:00:00.000Z");

		create.dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => credentialRequests(server).length === 4 && create.disabled === false, "credential create after success");
		assert.notEqual(JSON.parse(credentialRequests(server)[3].body).operationId, changed.operationId, "success clears retry state");
	});

	it("sends operation IDs for rotate retries and omits them for revoke", async () => {
		const { document, window, server } = ctx;
		await openServiceAccountCredentials(ctx);
		document.getElementById("sa-credential-id").value = "cred_1";
		server.state.credentialFailures = 1;
		const rotate = document.querySelector('[data-credential-action="rotate"]');
		rotate.dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => credentialRequests(server, "/cred_1/rotate").length === 1 && rotate.disabled === false, "failed credential rotate");
		rotate.dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => credentialRequests(server, "/cred_1/rotate").length === 2 && rotate.disabled === false, "credential rotate retry");
		const [first, retry] = credentialRequests(server, "/cred_1/rotate").map((request) => JSON.parse(request.body));
		assert.match(first.operationId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
		assert.equal(retry.operationId, first.operationId, "an exact rotate retry reuses its operation ID");

		const revoke = document.querySelector('[data-credential-action="revoke"]');
		revoke.dispatchEvent(new window.Event("click", { bubbles: true }));
		await until(() => credentialRequests(server, "/cred_1/revoke").length === 1 && revoke.disabled === false, "credential revoke");
		assert.deepEqual(JSON.parse(credentialRequests(server, "/cred_1/revoke")[0].body), {}, "revoke must omit operationId");
	});
});
