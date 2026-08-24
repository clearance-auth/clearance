import { describe, expect, it, vi } from "vitest";
import {
	accentStylesheet,
	canonicalScopeForHostedStartup,
	canonicalAuthHeaders,
	closeVaultHostInDependencyOrder,
	configModule,
	contentSecurityPolicy,
	customHostnameFromAuthority,
	hostedContextForAuthority,
	rawHostAuthority,
	serveOperationalProbe,
	vaultRequestURL,
	type HostedRequestContext,
} from "./server.js";

function probeResponse() {
	return {
		statusCode: 0,
		setHeader: vi.fn(),
		end: vi.fn(),
	};
}

const canonicalScope = Object.freeze({ projectId: "project-canonical", environmentId: "env-canonical" });
const canonicalPresentation = Object.freeze({
	productLabel: "Clearance",
	homeLabel: "Clearance Vault",
	accentColor: "#2563eb",
	logoUrl: null,
	version: 3,
	updatedAt: null,
});

const activeCustomDomain = Object.freeze({
	origin: "https://login.acme.example",
	hostname: "login.acme.example",
	scope: Object.freeze({ projectId: "project-acme", environmentId: "env-live" }),
	presentation: Object.freeze({
		productLabel: "Acme",
		homeLabel: "Acme Account",
		accentColor: "#cc5500",
		logoUrl: "https://cdn.acme.example/logo.svg",
		version: 9,
		updatedAt: "2026-07-24T00:00:00.000Z",
	}),
	domainVersion: 14,
});

async function customContext(): Promise<HostedRequestContext> {
	return hostedContextForAuthority({
		authority: "login.acme.example",
		canonicalScope,
		canonicalPresentation,
		resolver: { resolveActiveHostedDomain: async () => activeCustomDomain },
	});
}

describe("vault hosted authorities", () => {
	it("rejects an invalid configured canonical scope through topology authority", async () => {
		const previousProjectId = process.env.CLEARANCE_PROJECT_ID;
		const previousEnvironmentId = process.env.CLEARANCE_ENV_ID;
		process.env.CLEARANCE_PROJECT_ID = "project-live";
		process.env.CLEARANCE_ENV_ID = "env_live_typo";
		const getProjectById = vi.fn().mockResolvedValue({ id: "project-live" });
		const getEnvironment = vi.fn().mockResolvedValue(null);
		const store = {
			snapshot: {
				meta: { config: {} },
				projects: [],
				environments: [],
			},
			storeV2Topology: {
				authoritative: true,
				getProjectById,
				getEnvironment,
			},
		} as unknown as Parameters<typeof canonicalScopeForHostedStartup>[0];

		try {
			await expect(canonicalScopeForHostedStartup(store)).rejects.toMatchObject({
				code: "SCOPE_INVALID",
				status: 403,
			});
			expect(getProjectById).toHaveBeenCalledWith("project-live");
			expect(getEnvironment).toHaveBeenCalledWith({
				projectId: "project-live",
				id: "env_live_typo",
			});
		} finally {
			if (previousProjectId === undefined) delete process.env.CLEARANCE_PROJECT_ID;
			else process.env.CLEARANCE_PROJECT_ID = previousProjectId;
			if (previousEnvironmentId === undefined) delete process.env.CLEARANCE_ENV_ID;
			else process.env.CLEARANCE_ENV_ID = previousEnvironmentId;
		}
	});

	it("requires exactly one raw Host authority", () => {
		expect(() => rawHostAuthority({
			headers: { host: "login.acme.example" },
			rawHeaders: ["Host", "login.acme.example", "Host", "attacker.example"],
		})).toThrow("Vault request must contain exactly one valid Host authority");
	});

	it("maps only the exact configured authority to the explicit canonical scope", async () => {
		const context = await hostedContextForAuthority({
			authority: new URL(process.env.CLEARANCE_VAULT_URL ?? "http://localhost:3400").host,
			canonicalScope,
			canonicalPresentation,
		});

		expect(context.scope).toEqual(canonicalScope);
		expect(context.presentation.productLabel).toBe("Clearance");
	});

	it("derives custom scope and branding only from an active normalized claim", async () => {
		const context = await customContext();

		expect(context).toMatchObject({
			origin: "https://login.acme.example",
			hostname: "login.acme.example",
			scope: { projectId: "project-acme", environmentId: "env-live" },
			presentation: { productLabel: "Acme", homeLabel: "Acme Account" },
		});
		expect(configModule(context)).toContain('"passkeyRpId":"login.acme.example"');
	});

	it.each(["unknown.example", "pending.example", "disabled.example"]) (
		"rejects unresolved non-active custom host %s before content selection",
		async (authority) => {
			await expect(hostedContextForAuthority({
				authority,
				canonicalScope,
				canonicalPresentation,
				resolver: { resolveActiveHostedDomain: async () => null },
			})).rejects.toThrow("Vault host is not an active hosted domain");
		},
	);

	it.each(["Login.Acme.example", "login.acme.example:443", "https://login.acme.example", "//login.acme.example"]) (
		"rejects malformed custom authority %s",
		(authority) => expect(customHostnameFromAuthority(authority)).toBeNull(),
	);
});

describe("vault auth request URLs", () => {
	it.each([
		"https://attacker.example/api/auth/sign-in/email",
		"attacker.example:443",
		"//attacker.example/api/auth/sign-in/email",
		"/api//auth/sign-in/email",
	])("rejects an absolute or hostile request target: %s", (target) => {
		expect(() => vaultRequestURL(target)).toThrow(
			"Vault request target must use an origin-form path and query",
		);
	});

	it("constructs auth requests from the selected origin and strips forwarded authority selection", async () => {
		const context = await customContext();
		const url = vaultRequestURL("/api/auth/sign-in/email?redirect=%2Faccount", context.origin);
		const headers = canonicalAuthHeaders({
			host: "attacker.example",
			forwarded: "host=attacker.example;proto=http",
			"x-forwarded-host": "attacker.example",
			"x-forwarded-proto": "http",
			"x-forwarded-for": "203.0.113.99",
			"x-real-ip": "203.0.113.100",
			"x-request-id": "request-1",
		}, context.authority, "127.0.0.1");

		expect(url.href).toBe("https://login.acme.example/api/auth/sign-in/email?redirect=%2Faccount");
		expect(headers.get("host")).toBe("login.acme.example");
		expect(headers.get("forwarded")).toBeNull();
		expect(headers.get("x-forwarded-host")).toBeNull();
		expect(headers.get("x-forwarded-proto")).toBeNull();
		expect(headers.get("x-real-ip")).toBeNull();
		expect(headers.get("x-forwarded-for")).toBe("127.0.0.1");
		expect(headers.get("x-request-id")).toBe("request-1");
	});
});

describe("vault operational probes", () => {
	it("routes healthz before authority resolution and without readiness dependencies", async () => {
		const response = probeResponse();
		const readiness = vi.fn().mockRejectedValue(new Error("database unavailable"));
		const noncanonicalRequest = {
			method: "GET",
			url: "/healthz",
			// These deliberately hostile host fields would fail normal routing. The
			// probe handler must not inspect either one.
			get headers() {
				throw new Error("host resolution must not run for healthz");
			},
			get rawHeaders() {
				throw new Error("host resolution must not run for healthz");
			},
		};

		await expect(serveOperationalProbe(
			noncanonicalRequest,
			response as never,
			readiness,
		)).resolves.toBe(true);
		expect(readiness).not.toHaveBeenCalled();
		expect(response.statusCode).toBe(200);
	});

	it("uses the readiness dependency without resolving a hosted authority", async () => {
		const response = probeResponse();
		const readiness = vi.fn().mockResolvedValue(undefined);
		await serveOperationalProbe({ method: "GET", url: "/readyz" }, response as never, readiness);

		expect(readiness).toHaveBeenCalledOnce();
		expect(response.statusCode).toBe(200);
	});
});

describe("vault host shutdown", () => {
	it("drains HTTP before retiring bundles and destroying the store, even after a close error", async () => {
		const events: string[] = [];
		let finishHttpDrain!: () => void;
		const httpDrained = new Promise<void>((resolve) => {
			finishHttpDrain = resolve;
		});
		const closeFailure = new Error("server was already closed");

		const shutdown = closeVaultHostInDependencyOrder({
			closeHttp: async () => {
				events.push("http:stopping");
				await httpDrained;
				events.push("http:drained");
				throw closeFailure;
			},
			closeBundles: async () => {
				events.push("bundles:retired");
			},
			destroyStore: async () => {
				events.push("store:destroyed");
			},
		});

		await Promise.resolve();
		expect(events).toEqual(["http:stopping"]);
		finishHttpDrain();
		await expect(shutdown).rejects.toBe(closeFailure);
		expect(events).toEqual([
			"http:stopping",
			"http:drained",
			"bundles:retired",
			"store:destroyed",
		]);
	});
});

describe("host-scoped presentation output", () => {
	it("does not share presentation values across host contexts", async () => {
		const context = await customContext();
		const canonical = await hostedContextForAuthority({
			authority: new URL(process.env.CLEARANCE_VAULT_URL ?? "http://localhost:3400").host,
			canonicalScope,
			canonicalPresentation,
		});

		expect(configModule(context)).toContain('"productName":"Acme"');
		expect(configModule(canonical)).not.toContain('"productName":"Acme"');
		expect(accentStylesheet(context)).toContain("#cc5500");
		expect(accentStylesheet(canonical)).toContain("#2563eb");
	});

	it("permits only the prevalidated logo origin in CSP", async () => {
		const context = await customContext();
		const policy = contentSecurityPolicy(context);

		expect(policy).toContain("img-src 'self' data: https://cdn.acme.example");
		expect(policy).not.toContain("https:;");
	});
});
