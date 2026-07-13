/**
 * Live-mode conformance producer tests (FOLLOW.md P2.1).
 *
 * The audit found mode:"live" was structurally unreachable — readiness's
 * liveCertified gate had consumers but no producer. These tests prove:
 * (a) every arming refusal (loopback, plain HTTP, SAML, missing endpoint)
 * (b) live probes stamp mode:"live" traces via injected fetch
 * (c) the readiness gate flips liveCertified only when BOTH live traces exist
 * No real network is touched: fetchImpl is injected everywhere.
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	JsonStore,
	createOrganization,
	createScimConnection,
	createSsoConnection,
	initProject,
	runReadinessCheck,
	testScimConnectionLive,
	testSsoConnectionLive,
} from "../index.js";
import { ClearanceError } from "../services/errors.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-live-conf-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

beforeEach(() => {
	process.env.CLEARANCE_CREDENTIAL_KEY =
		"live-conformance-test-key-material-32-bytes!!";
	process.env.CLEARANCE_CREDENTIAL_KEY_ID = "k-live";
});

afterEach(() => {
	for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const SAML_CERT = readFileSync(
	new URL("../../../../fixtures/sso/test-certificate.pem", import.meta.url),
	"utf8",
);

function setup(store: JsonStore, issuer: string | undefined, protocol = "oidc") {
	initProject(store, { name: "Live" });
	const org = createOrganization(store, { name: "Acme" });
	const sso = createSsoConnection(store, {
		organizationId: org.id,
		provider: "okta",
		protocol: protocol as never,
		...(issuer ? { issuer } : {}),
		audience: "clearance-sp",
		...(protocol === "saml"
			? {
					samlEntryPoint: "https://customer.okta.test/app/clearance/sso/saml",
					samlCertificate: SAML_CERT,
				}
			: {}),
	} as never);
	return { org, sso };
}

const ISSUER = "https://idp.example.com";
const DISCOVERY = {
	issuer: ISSUER,
	authorization_endpoint: `${ISSUER}/oauth2/authorize`,
	token_endpoint: `${ISSUER}/oauth2/token`,
	jwks_uri: `${ISSUER}/oauth2/keys`,
};

function jsonResponse(status: number, body: unknown): Response {
	return {
		ok: status >= 200 && status < 300,
		status,
		statusText: String(status),
		json: async () => body,
		text: async () => JSON.stringify(body),
		headers: new Map() as never,
	} as unknown as Response;
}

function fetchStub(
	routes: Record<string, () => Response | Promise<Response>>,
): typeof fetch {
	return (async (input: unknown) => {
		const url = String(input);
		for (const [prefix, handler] of Object.entries(routes)) {
			if (url.startsWith(prefix)) return handler();
		}
		throw new TypeError(`fetch failed: no stub route for ${url}`);
	}) as typeof fetch;
}

describe("live conformance arming refusals (fail closed, no network)", () => {
	it("refuses a loopback issuer", async () => {
		const store = tempStore();
		const { sso } = setup(store, "https://127.0.0.1:8443");
		await expect(testSsoConnectionLive(store, sso.id)).rejects.toMatchObject({
			code: "SSO_LIVE_ENDPOINT_LOOPBACK",
		});
	});
	it("refuses localhost and *.localhost issuers", async () => {
		const store = tempStore();
		const { sso } = setup(store, "https://tenant.localhost");
		await expect(testSsoConnectionLive(store, sso.id)).rejects.toMatchObject({
			code: "SSO_LIVE_ENDPOINT_LOOPBACK",
		});
	});
	it("refuses plain HTTP", async () => {
		const store = tempStore();
		const { sso } = setup(store, "http://idp.example.com");
		await expect(testSsoConnectionLive(store, sso.id)).rejects.toMatchObject({
			code: "SSO_LIVE_ENDPOINT_INSECURE",
		});
	});
	it("refuses a missing issuer", async () => {
		const store = tempStore();
		const { sso } = setup(store, undefined);
		await expect(testSsoConnectionLive(store, sso.id)).rejects.toMatchObject({
			code: "SSO_LIVE_ENDPOINT_MISSING",
		});
	});
	it("refuses SAML live (browser exchange required) with remediation", async () => {
		const store = tempStore();
		const { sso } = setup(store, ISSUER, "saml");
		await expect(testSsoConnectionLive(store, sso.id)).rejects.toMatchObject({
			code: "SSO_LIVE_SAML_UNSUPPORTED",
		});
	});
	it("refuses a loopback SCIM endpoint", async () => {
		const store = tempStore();
		const { org } = setup(store, ISSUER);
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
			endpoint: "https://localhost:9443/scim/v2",
			bearerToken: "secret-bearer-token-value",
		});
		await expect(testScimConnectionLive(store, scim.id)).rejects.toMatchObject({
			code: "SCIM_LIVE_ENDPOINT_LOOPBACK",
		});
	});
	it("refuses IPv6-mapped loopback issuers (URL parser normalizes ::ffff:127.0.0.1 to hex form)", async () => {
		for (const host of ["[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[::]"]) {
			const store = tempStore();
			const { sso } = setup(store, `https://${host}:8443`);
			await expect(testSsoConnectionLive(store, sso.id)).rejects.toMatchObject({
				code: "SSO_LIVE_ENDPOINT_LOOPBACK",
			});
		}
	});
	it("unknown connection ids fail closed", async () => {
		const store = tempStore();
		setup(store, ISSUER);
		await expect(testSsoConnectionLive(store, "sso_missing")).rejects.toBeInstanceOf(
			ClearanceError,
		);
	});
});

describe("live probes stamp mode:live and classify failures", () => {
	it("SSO pass: real discovery + JWKS shape via injected fetch", async () => {
		const store = tempStore();
		const { sso } = setup(store, ISSUER);
		const result = await testSsoConnectionLive(store, sso.id, {
			fetchImpl: fetchStub({
				[`${ISSUER}/.well-known/openid-configuration`]: () =>
					jsonResponse(200, DISCOVERY),
				[DISCOVERY.jwks_uri]: () =>
					jsonResponse(200, { keys: [{ kty: "RSA", kid: "k1" }] }),
			}),
		});
		expect(result.pass).toBe(true);
		expect(result.mode).toBe("live");
		expect(result.trace.mode).toBe("live");
		expect(result.trace.outcome).toBe("pass");
		// The connection payload must stay redacted (no secret material).
		expect(JSON.stringify(result.connection)).not.toContain("Encrypted");
	});

	it("SSO auth rejection classifies as auth_rejected with a live fail trace", async () => {
		const store = tempStore();
		const { sso } = setup(store, ISSUER);
		const result = await testSsoConnectionLive(store, sso.id, {
			fetchImpl: fetchStub({
				[ISSUER]: () => jsonResponse(403, { error: "forbidden" }),
			}),
		});
		expect(result.pass).toBe(false);
		expect(result.trace.mode).toBe("live");
		expect(result.trace.stage).toBe("discovery.fetch");
		expect(result.trace.cause).toBe("auth_rejected");
	});

	it("SSO network failure classifies as network, TLS-looking failures as tls", async () => {
		const store = tempStore();
		const { sso } = setup(store, ISSUER);
		const network = await testSsoConnectionLive(store, sso.id, {
			fetchImpl: (async () => {
				throw new TypeError("fetch failed: ECONNREFUSED");
			}) as typeof fetch,
		});
		expect(network.pass).toBe(false);
		expect(network.trace.cause).toBe("network");

		const tls = await testSsoConnectionLive(store, sso.id, {
			fetchImpl: (async () => {
				throw new TypeError("fetch failed: self-signed certificate in chain");
			}) as typeof fetch,
		});
		expect(tls.pass).toBe(false);
		expect(tls.trace.cause).toBe("tls");
	});

	it("SSO issuer-mismatch discovery fails validation with a live fail trace", async () => {
		const store = tempStore();
		const { sso } = setup(store, ISSUER);
		const result = await testSsoConnectionLive(store, sso.id, {
			fetchImpl: fetchStub({
				[ISSUER]: () =>
					jsonResponse(200, { ...DISCOVERY, issuer: "https://evil.example.com" }),
			}),
		});
		expect(result.pass).toBe(false);
		expect(result.trace.stage).toBe("discovery.validate");
	});

	it("SSRF guard: discovery URLs are remote-controlled and must pass the live-endpoint policy before any fetch", async () => {
		const store = tempStore();
		const { sso } = setup(store, ISSUER);
		const hostileTargets = [
			"http://169.254.169.254/latest/meta-data/", // plaintext + metadata service
			"https://127.0.0.1:6379/", // loopback
			"https://[::ffff:127.0.0.1]/keys", // IPv6-mapped loopback
		];
		for (const jwks of hostileTargets) {
			let fetchedHostile = false;
			const result = await testSsoConnectionLive(store, sso.id, {
				fetchImpl: (async (input: unknown) => {
					const url = String(input);
					if (url.startsWith(`${ISSUER}/.well-known/`)) {
						return jsonResponse(200, { ...DISCOVERY, jwks_uri: jwks });
					}
					fetchedHostile = true; // the probe must never reach here
					return jsonResponse(200, { keys: [{ kid: "k" }] });
				}) as typeof fetch,
			});
			expect(result.pass).toBe(false);
			expect(result.trace.cause).toBe("untrusted_discovery_url");
			expect(fetchedHostile).toBe(false); // no request left the guard
		}
	});

	it("SCIM probe refuses redirects instead of following them (SSRF second hop)", async () => {
		const store = tempStore();
		const { org } = setup(store, ISSUER);
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
			endpoint: "https://scim.example.com/scim/v2",
			bearerToken: "secret-bearer-token-value",
		});
		const seenUrls: string[] = [];
		const result = await testScimConnectionLive(store, scim.id, {
			fetchImpl: (async (input: unknown, init?: RequestInit) => {
				seenUrls.push(String(input));
				expect(init?.redirect).toBe("manual");
				return {
					ok: false,
					status: 302,
					statusText: "302",
					headers: new Map() as never,
					json: async () => ({}),
					text: async () => "",
				} as unknown as Response;
			}) as typeof fetch,
		});
		expect(result.pass).toBe(false);
		expect(seenUrls.every((u) => u.startsWith("https://scim.example.com"))).toBe(
			true,
		);
	});

	it("SCIM pass: ServiceProviderConfig + one-item Users read, read-only", async () => {
		const store = tempStore();
		const { org } = setup(store, ISSUER);
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
			endpoint: "https://scim.example.com/scim/v2",
			bearerToken: "secret-bearer-token-value",
		});
		const seenMethods: string[] = [];
		const result = await testScimConnectionLive(store, scim.id, {
			fetchImpl: (async (input: unknown, init?: RequestInit) => {
				seenMethods.push((init?.method ?? "GET").toUpperCase());
				const url = String(input);
				if (url.includes("ServiceProviderConfig")) {
					return jsonResponse(200, { patch: { supported: true } });
				}
				return jsonResponse(200, { totalResults: 1, Resources: [{}] });
			}) as typeof fetch,
		});
		expect(result.pass).toBe(true);
		expect(result.mode).toBe("live");
		expect(result.trace.mode).toBe("live");
		expect(seenMethods.every((m) => m === "GET")).toBe(true); // never mutates
	});
});

describe("readiness liveCertified flips only on BOTH live passes", () => {
	it("simulation-only stays uncertified; sso+scim live passes certify", async () => {
		const store = tempStore();
		const { org, sso } = setup(store, ISSUER);
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
			endpoint: "https://scim.example.com/scim/v2",
			bearerToken: "secret-bearer-token-value",
		});

		const before = runReadinessCheck(store, org.id);
		expect(before.conformance.liveCertified).toBe(false);

		await testSsoConnectionLive(store, sso.id, {
			fetchImpl: fetchStub({
				[`${ISSUER}/.well-known/openid-configuration`]: () =>
					jsonResponse(200, DISCOVERY),
				[DISCOVERY.jwks_uri]: () =>
					jsonResponse(200, { keys: [{ kty: "RSA", kid: "k1" }] }),
			}),
		});
		const ssoOnly = runReadinessCheck(store, org.id);
		expect(ssoOnly.conformance.liveCertified).toBe(false); // scim still missing

		await testScimConnectionLive(store, scim.id, {
			fetchImpl: fetchStub({
				"https://scim.example.com": () =>
					jsonResponse(200, { totalResults: 0, Resources: [] }),
			}),
		});
		const both = runReadinessCheck(store, org.id);
		expect(both.conformance.liveCertified).toBe(true);
		expect(both.conformance.mode).toBe("live");
	});

	it("a live FAIL does not certify", async () => {
		const store = tempStore();
		const { org, sso } = setup(store, ISSUER);
		await testSsoConnectionLive(store, sso.id, {
			fetchImpl: (async () => {
				throw new TypeError("fetch failed: ECONNREFUSED");
			}) as typeof fetch,
		});
		const report = runReadinessCheck(store, org.id);
		expect(report.conformance.liveCertified).toBe(false);
	});
});
