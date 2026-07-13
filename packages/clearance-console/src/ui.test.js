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
	const state = { loggedIn: false, requests: [] };
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
			return respond(200, { ok: true, version: "0.2.1" });
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
});
