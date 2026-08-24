import type { GenericEndpointContext } from "@clearance/core";
import { describe, expect, it } from "vitest";
import { assertTrustedOrigin, resolveAllowedOrigins, resolveRpID } from "./origin";
import type { PasskeyOptions } from "./types";

function fakeCtx(
	init: {
		baseURL?: string | undefined;
		trustedOrigins?: string[] | undefined;
		originHeader?: string | undefined;
	} = {},
): GenericEndpointContext {
	return {
		context: {
			options: {
				baseURL: init.baseURL,
				trustedOrigins: init.trustedOrigins ?? [],
			},
		},
		headers:
			init.originHeader === undefined
				? undefined
				: new Headers({ origin: init.originHeader }),
	} as unknown as GenericEndpointContext;
}

describe("passkey origin/RP policy", () => {
	it("derives the RP ID from an explicit plugin option", () => {
		const ctx = fakeCtx({ baseURL: "https://ignored.example.com" });
		expect(resolveRpID(ctx, { rpID: "explicit.example.com" })).toBe(
			"explicit.example.com",
		);
	});

	it("derives the RP ID from a static string baseURL when no explicit rpID is set", () => {
		const ctx = fakeCtx({ baseURL: "https://app.example.com" });
		expect(resolveRpID(ctx, undefined)).toBe("app.example.com");
	});

	it("fails closed when neither an explicit rpID nor a static string baseURL is configured", () => {
		const ctx = fakeCtx({ baseURL: undefined });
		expect(() => resolveRpID(ctx, undefined)).toThrow();
	});

	it("fails closed when baseURL is a dynamic (non-string) configuration", () => {
		const ctx = fakeCtx({});
		ctx.context.options.baseURL = {
			allowedHosts: ["app.example.com"],
		} as never;
		expect(() => resolveRpID(ctx, undefined)).toThrow();
	});

	it("rejects a request whose Origin header is missing", () => {
		const ctx = fakeCtx({ baseURL: "https://app.example.com" });
		expect(() => assertTrustedOrigin(ctx, undefined, "app.example.com")).toThrow();
	});

	it("rejects a request whose Origin header is not in the allow-list", () => {
		const ctx = fakeCtx({
			baseURL: "https://app.example.com",
			originHeader: "https://evil.example.com",
		});
		expect(() => assertTrustedOrigin(ctx, undefined, "app.example.com")).toThrow();
	});

	it("accepts a request whose Origin matches the static baseURL origin", () => {
		const ctx = fakeCtx({
			baseURL: "https://app.example.com",
			trustedOrigins: ["https://app.example.com"],
			originHeader: "https://app.example.com",
		});
		expect(assertTrustedOrigin(ctx, undefined, "app.example.com")).toBe(
			"https://app.example.com",
		);
	});

	it("accepts an explicit plugin origin compatible with the RP ID", () => {
		const ctx = fakeCtx({
			baseURL: "https://app.example.com",
			originHeader: "https://accounts.app.example.com",
		});
		const options: PasskeyOptions = {
			origin: ["https://accounts.app.example.com"],
		};
		expect(assertTrustedOrigin(ctx, options, "app.example.com")).toBe(
			"https://accounts.app.example.com",
		);
	});

	it("fails closed while resolving an explicit origin incompatible with the RP ID", () => {
		const ctx = fakeCtx({ baseURL: "https://app.example.com" });
		const options: PasskeyOptions = { origin: ["https://evil.example.com"] };
		expect(() => resolveAllowedOrigins(ctx, options, "app.example.com")).toThrow();
	});

	it("never trusts a wildcard entry from ClearanceOptions.trustedOrigins", () => {
		const ctx = fakeCtx({
			baseURL: "https://app.example.com",
			trustedOrigins: ["https://*.app.example.com"],
		});
		const allowed = resolveAllowedOrigins(ctx, undefined, "app.example.com");
		expect(allowed).not.toContain("https://sub.app.example.com");
	});

	it("accepts a literal trustedOrigins entry compatible with the RP ID", () => {
		const ctx = fakeCtx({
			baseURL: "https://app.example.com",
			trustedOrigins: ["https://accounts.app.example.com"],
		});
		const allowed = resolveAllowedOrigins(ctx, undefined, "app.example.com");
		expect(allowed).toContain("https://accounts.app.example.com");
	});

	it("silently excludes a trustedOrigins entry incompatible with the RP ID", () => {
		const ctx = fakeCtx({
			baseURL: "https://app.example.com",
			trustedOrigins: ["https://unrelated.example.org"],
		});
		const allowed = resolveAllowedOrigins(ctx, undefined, "app.example.com");
		expect(allowed).not.toContain("https://unrelated.example.org");
	});

	it("allows http for an explicit localhost origin", () => {
		const ctx = fakeCtx({
			baseURL: "http://localhost:3000",
			trustedOrigins: ["http://localhost:3000"],
			originHeader: "http://localhost:3000",
		});
		expect(assertTrustedOrigin(ctx, undefined, "localhost")).toBe(
			"http://localhost:3000",
		);
	});

	it("rejects http for a non-loopback host even if it matches the RP ID", () => {
		const ctx = fakeCtx({
			baseURL: "https://app.example.com",
			trustedOrigins: ["http://app.example.com"],
		});
		const allowed = resolveAllowedOrigins(ctx, undefined, "app.example.com");
		expect(allowed).not.toContain("http://app.example.com");
	});

	it("includes the static canonical baseURL origin even with no explicit trustedOrigins entry", () => {
		const ctx = fakeCtx({ baseURL: "https://app.example.com" });
		const allowed = resolveAllowedOrigins(ctx, undefined, "app.example.com");
		expect(allowed).toContain("https://app.example.com");
	});

	it("never trusts a dynamic (function) trustedOrigins configuration", () => {
		const ctx = fakeCtx({ baseURL: "https://app.example.com" });
		ctx.context.options.trustedOrigins = (() => [
			"https://from-dynamic-callback.example.com",
		]) as unknown as string[];
		const allowed = resolveAllowedOrigins(ctx, undefined, "app.example.com");
		expect(allowed).not.toContain("https://from-dynamic-callback.example.com");
	});

	it("never reads a per-request ctx.context.trustedOrigins value", () => {
		const ctx = fakeCtx({ baseURL: "https://app.example.com" });
		(ctx.context as unknown as { trustedOrigins: string[] }).trustedOrigins = [
			"https://per-request.example.com",
		];
		const allowed = resolveAllowedOrigins(ctx, undefined, "app.example.com");
		expect(allowed).not.toContain("https://per-request.example.com");
	});

	describe("rpID syntax validation", () => {
		it("accepts a canonical bare hostname rpID", () => {
			const ctx = fakeCtx({});
			expect(resolveRpID(ctx, { rpID: "app.example.com" })).toBe(
				"app.example.com",
			);
		});

		it("canonicalizes an rpID to lowercase", () => {
			const ctx = fakeCtx({});
			expect(resolveRpID(ctx, { rpID: "App.Example.COM" })).toBe(
				"app.example.com",
			);
		});

		it("rejects an rpID containing a scheme", () => {
			const ctx = fakeCtx({});
			expect(() =>
				resolveRpID(ctx, { rpID: "https://app.example.com" }),
			).toThrow();
		});

		it("rejects an rpID containing a port", () => {
			const ctx = fakeCtx({});
			expect(() => resolveRpID(ctx, { rpID: "app.example.com:3000" })).toThrow();
		});

		it("rejects an rpID containing a path", () => {
			const ctx = fakeCtx({});
			expect(() => resolveRpID(ctx, { rpID: "app.example.com/path" })).toThrow();
		});

		it("rejects an rpID containing whitespace", () => {
			const ctx = fakeCtx({});
			expect(() => resolveRpID(ctx, { rpID: "app example.com" })).toThrow();
		});

		it("rejects an rpID that is an IPv4 literal", () => {
			const ctx = fakeCtx({});
			expect(() => resolveRpID(ctx, { rpID: "192.168.0.1" })).toThrow();
		});

		it("rejects public suffixes and non-localhost single-label rpIDs", () => {
			const ctx = fakeCtx({});
			expect(() => resolveRpID(ctx, { rpID: "com" })).toThrow();
			expect(() => resolveRpID(ctx, { rpID: "co.uk" })).toThrow();
			expect(() => resolveRpID(ctx, { rpID: "github.io" })).toThrow();
			expect(() => resolveRpID(ctx, { rpID: "intranet" })).toThrow();
			expect(resolveRpID(ctx, { rpID: "localhost" })).toBe("localhost");
		});

		it("rejects a malformed hostname (leading dot, double dot, trailing dot)", () => {
			const ctx = fakeCtx({});
			expect(() => resolveRpID(ctx, { rpID: ".example.com" })).toThrow();
			expect(() => resolveRpID(ctx, { rpID: "example..com" })).toThrow();
			expect(() => resolveRpID(ctx, { rpID: "example.com." })).toThrow();
		});

		it("never degrades a malformed rpID to an empty allow-list: resolveRpID fails closed first", () => {
			const ctx = fakeCtx({ baseURL: "https://app.example.com" });
			expect(() => resolveRpID(ctx, { rpID: "https://bad" })).toThrow();
		});
	});
});
