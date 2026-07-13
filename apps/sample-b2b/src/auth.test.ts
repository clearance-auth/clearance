import { describe, expect, it } from "vitest";
import { createClearanceAuth, socialProvidersFromEnvironment } from "@clearance/auth";
import {
	escapeHtml,
	getSetCookieValues,
	isAllowedSocialRedirect,
	sameOriginMutationOrigin,
	socialSignInMarkup,
	toSafeSessionView,
} from "./server.js";

describe("sample-b2b uses real @clearance/auth", () => {
	it("createClearanceAuth exposes handler and api", () => {
		const bundle = createClearanceAuth({
			baseURL: "http://localhost:3300",
			secret: "test-secret-value-that-is-long-enough-32",
			databaseUrl:
				process.env.DATABASE_URL ??
				"postgres://clearance:clearance@127.0.0.1:5434/clearance",
		});
		expect(typeof bundle.auth.handler).toBe("function");
		expect(typeof bundle.auth.api.signUpEmail).toBe("function");
		expect(bundle.plugins.organization).toBe(true);
		void bundle.destroy();
	});
});

describe("configured social login", () => {
	it("enables providers with complete credential pairs", () => {
		const providers = socialProvidersFromEnvironment({
			CLEARANCE_GITHUB_CLIENT_ID: "github-id",
			CLEARANCE_GITHUB_CLIENT_SECRET: "github-secret",
		});
		expect(Object.keys(providers)).toEqual(["github"]);
		expect(providers.github).toMatchObject({ clientId: "github-id" });
		expect(providers.google).toBeUndefined();
	});

	it("fails startup when a provider credential pair is incomplete", () => {
		expect(() =>
			socialProvidersFromEnvironment({
				CLEARANCE_GOOGLE_CLIENT_ID: "incomplete-google",
			}),
		).toThrow(/requires both/i);
	});

	it("renders a sign-in action for every configured provider", () => {
		const markup = socialSignInMarkup(["github", "google"]);
		expect(markup).toContain('data-social-provider="github"');
		expect(markup).toContain("Continue with Github");
		expect(markup).toContain('data-social-provider="google"');
	});

	it("allows HTTPS IdPs and local HTTP development while rejecting active schemes", () => {
		expect(
			isAllowedSocialRedirect("https://accounts.example.test/oauth", "https://app.test"),
		).toBe(true);
		expect(
			isAllowedSocialRedirect("http://localhost:4444/oauth", "http://localhost:3300"),
		).toBe(true);
		expect(
			isAllowedSocialRedirect("http://idp.example.test/oauth", "https://app.test"),
		).toBe(false);
		expect(isAllowedSocialRedirect("javascript:alert(1)", "https://app.test")).toBe(
			false,
		);
		expect(isAllowedSocialRedirect("data:text/html,pwned", "https://app.test")).toBe(
			false,
		);
	});
});

describe("sign-out cookie forwarding", () => {
	it("requires real same-origin Origin or Referer evidence", () => {
		expect(
			sameOriginMutationOrigin("https://app.test", undefined, "https://app.test"),
		).toBe("https://app.test");
		expect(
			sameOriginMutationOrigin(
				undefined,
				"https://app.test/dashboard",
				"https://app.test",
			),
		).toBe("https://app.test");
		expect(sameOriginMutationOrigin(undefined, undefined, "https://app.test")).toBeNull();
		expect(
			sameOriginMutationOrigin("https://evil.test", undefined, "https://app.test"),
		).toBeNull();
	});

	it("preserves HTTPS cookie names and every runtime expiration attribute", () => {
		const headers = new Headers();
		headers.append(
			"set-cookie",
			"__Secure-clearance.session_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
		);
		headers.append(
			"set-cookie",
			"__Secure-clearance.session_data=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure",
		);
		const cookies = getSetCookieValues(headers);
		expect(cookies).toHaveLength(2);
		expect(cookies[0]).toContain("__Secure-clearance.session_token=");
		expect(cookies[0]).toContain("Secure");
		expect(cookies[1]).toContain("Expires=Thu, 01 Jan 1970 00:00:00 GMT");
	});
});

describe("HTML escaping of user-provided output", () => {
	it("neutralizes markup payloads before HTML interpolation", () => {
		const payload = `<img src=x onerror="alert('xss')"> & "q" 's'`;
		const out = escapeHtml(payload);
		expect(out.includes("<")).toBe(false);
		expect(out.includes(">")).toBe(false);
		expect(out).toMatch(/&lt;img/);
		expect(out).toMatch(/&amp;/);
		expect(out).toMatch(/&quot;/);
		expect(out).toMatch(/&#39;/);
		expect(escapeHtml("<svg/onload=alert(1)>")).toBe(
			"&lt;svg/onload=alert(1)&gt;",
		);
	});

	it("escapes nullish values safely", () => {
		expect(escapeHtml(null)).toBe("");
		expect(escapeHtml(undefined)).toBe("");
		expect(escapeHtml(42)).toBe("42");
	});
});

describe("safe session endpoint metadata", () => {
	it("returns user/session metadata without raw bearer or session credentials", () => {
		const rawToken = "raw-session-bearer-token-SECRET-value-xyz";
		const view = toSafeSessionView({
			user: {
				id: "usr_1",
				email: "a@b.com",
				name: `<script>alert(1)</script>`,
			},
			session: {
				token: rawToken,
				userId: "usr_1",
				expiresAt: "2099-01-01T00:00:00.000Z",
			},
		});
		expect(view).toBeTruthy();
		const json = JSON.stringify(view);
		expect(json).not.toContain(rawToken);
		expect(json).not.toContain("bearer");
		expect(view!.session.active).toBe(true);
		expect(view!.session.userId).toBe("usr_1");
		expect(view!.user.email).toBe("a@b.com");
		// name may contain markup in JSON (escaping is for HTML path); token must be absent
		expect(view!.session).not.toHaveProperty("token");
		expect((view as { session: { token?: string } }).session.token).toBeUndefined();
		expect(view!.session.id).not.toContain(rawToken.slice(0, 8));
	});

	it("returns null when session or user missing", () => {
		expect(toSafeSessionView({})).toBeNull();
		expect(
			toSafeSessionView({ user: { id: "1", email: "a", name: "n" } }),
		).toBeNull();
	});
});
