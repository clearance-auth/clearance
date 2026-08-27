import { describe, expect, it, vi } from "vitest";
import { DEFAULT_MANAGEMENT_API_ORIGIN } from "./cli-defaults.js";
import { renderLocalDoctor, runLocalDoctor, type LocalDoctorDependencies } from "./local-doctor.js";

function dependencies(overrides: Partial<LocalDoctorDependencies> = {}): LocalDoctorDependencies {
	return {
		cliVersion: () => "0.3.1",
		inspectConfig: async () => ({ state: "ready" }),
		inspectProfile: async () => ({ state: "configured", apiOrigin: "http://profile.test:13200" }),
		inspectSkill: async () => ({ state: "installed" }),
		inspectCompletion: async () => ({ state: "installed" }),
		fetch: async () => new Response("ok", { status: 200 }),
		...overrides,
	};
}

describe("local doctor", () => {
	it("uses the documented Compose default for a missing profile and remains unauthenticated", async () => {
		const fetch = vi.fn(async () => new Response("ok", { status: 200 }));
		const result = await runLocalDoctor({}, dependencies({ inspectProfile: async () => ({ state: "absent" }), fetch }));
		expect(result.apiOrigin).toBe(DEFAULT_MANAGEMENT_API_ORIGIN);
		expect(result.checks.find((check) => check.id === "profile")).toMatchObject({ status: "warn" });
		expect(fetch).toHaveBeenCalledWith("http://localhost:13200/health", expect.objectContaining({ method: "GET" }));
		expect((fetch.mock.calls[0]?.[1] as RequestInit).headers).toBeUndefined();
	});

	it("fails safely when local profile configuration cannot be read", async () => {
		const result = await runLocalDoctor({ profile: "prod" }, dependencies({ inspectProfile: async () => { throw new Error("token=secret"); } }));
		expect(result.ok).toBe(false);
		expect(result.checks.find((check) => check.id === "profile")).toMatchObject({ status: "fail", summary: "Profile prod could not be inspected safely" });
		expect(renderLocalDoctor(result)).not.toContain("secret");
	});

	it("reports healthy and unreachable APIs without requiring authentication", async () => {
		const healthy = await runLocalDoctor({}, dependencies());
		expect(healthy.checks.find((check) => check.id === "api")).toMatchObject({ status: "pass" });
		const unreachable = await runLocalDoctor({}, dependencies({ fetch: async () => { throw new Error("ECONNREFUSED token=secret"); } }));
		expect(unreachable.checks.find((check) => check.id === "api")).toMatchObject({ status: "fail", summary: "Management API is unreachable" });
		expect(unreachable.ok).toBe(false);
	});

	it("bounds a stalled health check", async () => {
		const fetch: typeof globalThis.fetch = async (_url, init) => new Promise((_, reject) => {
			init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
		});
		const result = await runLocalDoctor({}, dependencies({ fetch, timeoutMs: 1 }));
		expect(result.checks.find((check) => check.id === "api")).toMatchObject({ status: "fail", summary: "Management API health check timed out" });
	});

	it("reports missing feature setup as warnings and unsafe inspection as failures", async () => {
		const result = await runLocalDoctor({}, dependencies({
			inspectSkill: async () => ({ state: "missing" }),
			inspectCompletion: async () => ({ state: "conflict", detail: "bad\nstate" }),
		}));
		expect(result.checks.find((check) => check.id === "skill")).toMatchObject({ status: "warn" });
		expect(result.checks.find((check) => check.id === "completion")).toMatchObject({ status: "fail", detail: "bad state" });
	});

	it("checks local configuration separately and sanitizes its detail", async () => {
		const result = await runLocalDoctor({}, dependencies({
			inspectConfig: async () => ({ state: "unsafe", detail: "bad\u001b[31m\nowner\u202e" }),
		}));
		expect(result.checks.find((check) => check.id === "config")).toMatchObject({
			status: "fail",
			detail: "bad owner",
		});
		expect(renderLocalDoctor(result)).not.toContain("\u001b");
	});
});
