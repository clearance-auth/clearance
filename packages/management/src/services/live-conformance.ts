/**
 * Live SSO/SCIM conformance probes — the only producers of mode: "live".
 *
 * Everything else in the conformance lab is honestly labeled "simulation";
 * readiness.liveCertified requires live sso.test AND scim.test traces, which
 * only these functions can produce. Scope (per FOLLOW.md P2.1): read-only
 * discovery / metadata / endpoint conformance against a real external tenant.
 * A full interactive SSO login against a live IdP requires a browser actor
 * and is out of scope here; live SAML metadata exchange likewise refuses
 * rather than pretending.
 *
 * Arming rules (fail closed):
 *  - endpoint must be HTTPS (SSO_LIVE_ENDPOINT_INSECURE / SCIM_...)
 *  - endpoint must not be loopback/localhost (…_ENDPOINT_LOOPBACK)
 *  - operator confirmation (--yes) is enforced by the CLI/API callers
 *  - only READ requests are issued; a live tenant is never mutated
 */
import { computeDiscoveryUrl, validateDiscoveryDocument } from "@clearance/sso";
import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type {
	DiagnosticTrace,
	DirectoryConnection,
	IdentityConnection,
} from "../types/resources.js";
import { recordEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { decryptCredential } from "./credentials.js";
import { probeScimEndpoint } from "./scim-probe.js";
import { publicIdentityConnection, publicDirectoryConnection } from "./redact.js";

export const LIVE_CONFORMANCE_MODE = "live" as const;
export const LIVE_EVIDENCE_LABEL =
	"live read-only conformance probe against the configured external endpoint (not full sign-in certification)";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"]);

function isLoopbackHost(hostname: string): boolean {
	let h = hostname.toLowerCase();
	if (LOOPBACK_HOSTS.has(h)) return true;
	if (h.endsWith(".localhost")) return true;
	// Unbracket IPv6 literals, then unwrap IPv4-mapped forms — the URL parser
	// normalizes https://[::ffff:127.0.0.1]/ to [::ffff:7f00:1], which naive
	// string checks miss (found by adversarial review).
	if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
	if (h === "::1" || h === "::") return true;
	const mapped = /^::ffff:(.+)$/.exec(h);
	if (mapped) {
		const tail = mapped[1];
		if (/^\d{1,3}(\.\d{1,3}){3}$/.test(tail)) return isLoopbackHost(tail);
		// Hex-group form (::ffff:7f00:1): high 16 bits of the IPv4 address.
		const hex = /^([0-9a-f]{1,4}):[0-9a-f]{1,4}$/.exec(tail);
		if (hex) {
			const firstOctet = Number.parseInt(hex[1], 16) >> 8;
			if (firstOctet === 127 || firstOctet === 0) return true;
		}
	}
	if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
	if (/^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
	return false;
}

export function assertLiveEndpoint(
	rawUrl: string | undefined,
	subsystem: "sso" | "scim",
	stage: string,
): URL {
	const codePrefix = subsystem === "sso" ? "SSO" : "SCIM";
	if (!rawUrl) {
		throw new ClearanceError({
			code: `${codePrefix}_LIVE_ENDPOINT_MISSING`,
			message: "Live conformance requires a configured external endpoint",
			stage,
			status: 400,
			remediation:
				subsystem === "sso"
					? "Configure the connection issuer URL first"
					: "Configure the SCIM endpoint URL first",
		});
	}
	let url: URL;
	try {
		url = new URL(rawUrl);
	} catch {
		throw new ClearanceError({
			code: `${codePrefix}_LIVE_ENDPOINT_INVALID`,
			message: `Endpoint is not a valid URL: ${rawUrl}`,
			stage,
			status: 400,
		});
	}
	if (url.protocol !== "https:") {
		throw new ClearanceError({
			code: `${codePrefix}_LIVE_ENDPOINT_INSECURE`,
			message: `Live conformance requires HTTPS; got ${url.protocol}//`,
			stage,
			status: 400,
			remediation: "Live probes never run over plaintext HTTP. Use the simulation lab for local endpoints.",
		});
	}
	if (isLoopbackHost(url.hostname)) {
		throw new ClearanceError({
			code: `${codePrefix}_LIVE_ENDPOINT_LOOPBACK`,
			message: `Live conformance refuses loopback host ${url.hostname}`,
			stage,
			status: 400,
			remediation: "Point the connection at the real external tenant, or use the simulation lab (sso test --fixture / scim test) for local verification.",
		});
	}
	return url;
}

/** Classify a fetch failure into the diagnostic cause model. */
function classifyFetchError(err: unknown): {
	cause: "network" | "tls" | "timeout";
	detail: string;
} {
	const message =
		err instanceof Error
			? `${err.message}${err.cause instanceof Error ? `: ${err.cause.message}` : ""}`
			: String(err);
	if (/abort/i.test(message)) return { cause: "timeout", detail: message };
	if (/certificate|tls|ssl|handshake|self[- ]signed/i.test(message)) {
		return { cause: "tls", detail: message };
	}
	return { cause: "network", detail: message };
}

function pushTrace(store: ManagementStore, trace: DiagnosticTrace): DiagnosticTrace {
	store.mutate((data) => {
		data.traces.unshift(trace);
		if (data.traces.length > 2000) data.traces.length = 2000;
	});
	return trace;
}

export interface LiveProbeResult<C> {
	pass: boolean;
	trace: DiagnosticTrace;
	connection: C;
	mode: typeof LIVE_CONFORMANCE_MODE;
	evidence: string;
	endpoint: string;
}

export interface LiveProbeOptions {
	fetchImpl?: typeof fetch;
	timeoutMs?: number;
}

async function fetchWithTimeout(
	url: string,
	opts: LiveProbeOptions,
	accept: string,
): Promise<Response> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
	try {
		return await (opts.fetchImpl ?? fetch)(url, {
			method: "GET",
			headers: { accept, "user-agent": "clearance-live-conformance/0.1" },
			redirect: "manual",
			signal: controller.signal,
		});
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Live OIDC conformance: fetch and validate the real discovery document and
 * JWKS from the configured issuer. SAML connections refuse — live SAML
 * metadata exchange needs a browser actor (rendered E2E), and pretending
 * otherwise is exactly what this codebase does not do.
 */
export async function testSsoConnectionLive(
	store: ManagementStore,
	id: string,
	opts: LiveProbeOptions = {},
): Promise<LiveProbeResult<IdentityConnection>> {
	const conn = store.snapshot.identityConnections.find((c) => c.id === id);
	if (!conn) {
		throw new ClearanceError({
			code: "SSO_NOT_FOUND",
			message: `SSO connection ${id} not found`,
			stage: "sso.test.live",
			status: 404,
		});
	}
	if (conn.protocol === "saml") {
		throw new ClearanceError({
			code: "SSO_LIVE_SAML_UNSUPPORTED",
			message:
				"Live SAML conformance requires an interactive browser exchange and is not yet supported",
			stage: "sso.test.live",
			status: 400,
			remediation:
				"Use OIDC live conformance, or the SAML simulation lab. Live SAML lands with the rendered-browser E2E stage.",
		});
	}
	const issuerUrl = assertLiveEndpoint(conn.issuer, "sso", "sso.test.live");
	const corr = `corr_sso_live_${newId("t").slice(4)}`;
	const base = {
		id: newId("tr"),
		correlationId: corr,
		organizationId: conn.organizationId,
		connectionId: conn.id,
		subsystem: "sso" as const,
		mode: LIVE_CONFORMANCE_MODE,
		createdAt: nowIso(),
	};

	const failTrace = (
		stage: string,
		cause: string,
		owner: "customer" | "application",
		remediation: string,
		checks: Array<{ name: string; pass: boolean; detail?: string }>,
	): LiveProbeResult<IdentityConnection> => {
		const trace = pushTrace(store, {
			...base,
			stage,
			outcome: "fail",
			cause,
			causeConfidence: 0.9,
			owner,
			remediation,
			checks,
			redactedResponse: { evidence: LIVE_EVIDENCE_LABEL },
		});
		recordEvent(store, {
			actor: "operator",
			action: "sso.test",
			subjectType: "identity_connection",
			subjectId: id,
			outcome: "failure",
			source: "sso",
			organizationId: conn.organizationId,
			correlationId: corr,
			message: `Live SSO conformance failed at ${stage}: ${cause}`,
			metadata: { mode: LIVE_CONFORMANCE_MODE, endpoint: issuerUrl.origin },
		});
		return {
			pass: false,
			trace,
			connection: publicIdentityConnection(conn) as IdentityConnection,
			mode: LIVE_CONFORMANCE_MODE,
			evidence: LIVE_EVIDENCE_LABEL,
			endpoint: issuerUrl.origin,
		};
	};

	const discoveryUrl = computeDiscoveryUrl(conn.issuer!);
	let res: Response;
	try {
		res = await fetchWithTimeout(discoveryUrl, opts, "application/json");
	} catch (err) {
		const { cause, detail } = classifyFetchError(err);
		return failTrace(
			"discovery.fetch",
			cause,
			cause === "tls" ? "customer" : "customer",
			cause === "tls"
				? "The issuer presented an invalid TLS certificate; the customer IdP team must fix the certificate chain"
				: "The issuer discovery endpoint is unreachable; verify the issuer URL and network path",
			[{ name: "discovery_fetch", pass: false, detail }],
		);
	}
	if (res.status === 401 || res.status === 403) {
		return failTrace(
			"discovery.fetch",
			"auth_rejected",
			"customer",
			"The IdP rejected the discovery request; check tenant visibility settings",
			[{ name: "discovery_status", pass: false, detail: `HTTP ${res.status}` }],
		);
	}
	if (!res.ok) {
		return failTrace(
			"discovery.fetch",
			"non_success",
			"customer",
			`Discovery endpoint returned HTTP ${res.status}; verify the issuer URL`,
			[{ name: "discovery_status", pass: false, detail: `HTTP ${res.status}` }],
		);
	}
	let discovery: Record<string, unknown>;
	try {
		discovery = (await res.json()) as Record<string, unknown>;
	} catch {
		return failTrace(
			"discovery.parse",
			"malformed_body",
			"customer",
			"Discovery endpoint did not return JSON; verify the issuer URL points at an OIDC issuer",
			[{ name: "discovery_json", pass: false }],
		);
	}
	try {
		validateDiscoveryDocument(discovery as never, conn.issuer!);
	} catch (err) {
		return failTrace(
			"discovery.validate",
			"bad_discovery",
			"customer",
			err instanceof Error ? err.message : "Discovery document failed validation",
			[{ name: "discovery_document", pass: false, detail: err instanceof Error ? err.message : undefined }],
		);
	}

	// SSRF guard: every URL taken FROM the discovery document is remote-
	// controlled data (a malicious or MITM'd issuer chooses it). Each one must
	// pass the same HTTPS + non-loopback policy as the issuer itself before
	// the server will fetch it — otherwise a hostile discovery doc can point
	// the probe at 127.0.0.1/link-local/metadata services (adversarial-review
	// finding M1).
	for (const field of ["jwks_uri", "authorization_endpoint", "token_endpoint"]) {
		try {
			assertLiveEndpoint(String(discovery[field] ?? ""), "sso", "sso.test.live");
		} catch (err) {
			return failTrace(
				"discovery.validate",
				"untrusted_discovery_url",
				"customer",
				`Discovery ${field} is not a trusted HTTPS non-loopback URL; refusing to contact it`,
				[
					{
						name: field,
						pass: false,
						detail: err instanceof Error ? err.message : String(err),
					},
				],
			);
		}
	}

	// JWKS reachability + shape (read-only).
	const jwksUri = String(discovery.jwks_uri ?? "");
	let jwksOk = false;
	let jwksDetail = "";
	try {
		const jwksRes = await fetchWithTimeout(jwksUri, opts, "application/json");
		if (jwksRes.ok) {
			const jwks = (await jwksRes.json()) as { keys?: unknown[] };
			jwksOk = Array.isArray(jwks.keys) && jwks.keys.length > 0;
			jwksDetail = jwksOk ? `${jwks.keys!.length} keys` : "no keys in JWKS";
		} else {
			jwksDetail = `HTTP ${jwksRes.status}`;
		}
	} catch (err) {
		jwksDetail = classifyFetchError(err).detail;
	}
	if (!jwksOk) {
		return failTrace(
			"jwks.fetch",
			"bad_jwks",
			"customer",
			`JWKS endpoint unusable (${jwksDetail}); signing keys cannot be verified`,
			[{ name: "jwks", pass: false, detail: jwksDetail }],
		);
	}

	const trace = pushTrace(store, {
		...base,
		stage: "discovery.validate",
		outcome: "pass",
		cause: `live discovery + JWKS conformance for ${issuerUrl.origin}`,
		causeConfidence: 1,
		owner: "application",
		checks: [
			{ name: "discovery_fetch", pass: true, detail: discoveryUrl },
			{ name: "discovery_document", pass: true, detail: conn.issuer },
			{ name: "jwks", pass: true, detail: jwksDetail },
			{ name: "mode", pass: true, detail: "live" },
		],
		redactedResponse: { evidence: LIVE_EVIDENCE_LABEL, endpoint: issuerUrl.origin },
	});
	store.mutate((data) => {
		const idx = data.identityConnections.findIndex((c) => c.id === id);
		if (idx >= 0) {
			data.identityConnections[idx] = { ...conn, status: "testing", updatedAt: nowIso() };
		}
	});
	recordEvent(store, {
		actor: "operator",
		action: "sso.test",
		subjectType: "identity_connection",
		subjectId: id,
		outcome: "success",
		source: "sso",
		organizationId: conn.organizationId,
		correlationId: corr,
		message: `Live SSO discovery conformance passed for ${issuerUrl.origin} — ${LIVE_EVIDENCE_LABEL}`,
		metadata: { mode: LIVE_CONFORMANCE_MODE, endpoint: issuerUrl.origin },
	});
	return {
		pass: true,
		trace,
		connection: publicIdentityConnection(
			store.snapshot.identityConnections.find((c) => c.id === id)!,
		) as IdentityConnection,
		mode: LIVE_CONFORMANCE_MODE,
		evidence: LIVE_EVIDENCE_LABEL,
		endpoint: issuerUrl.origin,
	};
}

/**
 * Live SCIM conformance: real read-only GETs (ServiceProviderConfig, then a
 * one-item Users page) against the configured endpoint with the stored
 * bearer credential. Never mutates the tenant.
 */
export async function testScimConnectionLive(
	store: ManagementStore,
	id: string,
	opts: LiveProbeOptions = {},
): Promise<LiveProbeResult<DirectoryConnection>> {
	const conn = store.snapshot.directoryConnections.find((c) => c.id === id);
	if (!conn) {
		throw new ClearanceError({
			code: "SCIM_NOT_FOUND",
			message: `SCIM connection ${id} not found`,
			stage: "scim.test.live",
			status: 404,
		});
	}
	const endpointUrl = assertLiveEndpoint(conn.endpoint, "scim", "scim.test.live");
	const bearerToken = conn.bearerTokenEncrypted
		? decryptCredential(conn.bearerTokenEncrypted)
		: undefined;
	const corr = `corr_scim_live_${newId("t").slice(4)}`;
	const base = {
		id: newId("tr"),
		correlationId: corr,
		organizationId: conn.organizationId,
		connectionId: conn.id,
		subsystem: "scim" as const,
		mode: LIVE_CONFORMANCE_MODE,
		createdAt: nowIso(),
	};

	const finish = (
		pass: boolean,
		stage: string,
		cause: string,
		checks: Array<{ name: string; pass: boolean; detail?: string }>,
		remediation?: string,
	): LiveProbeResult<DirectoryConnection> => {
		const trace = pushTrace(store, {
			...base,
			stage,
			outcome: pass ? "pass" : "fail",
			cause,
			causeConfidence: pass ? 1 : 0.9,
			owner: pass ? "application" : "customer",
			...(remediation ? { remediation } : {}),
			checks,
			redactedResponse: { evidence: LIVE_EVIDENCE_LABEL, endpoint: endpointUrl.origin },
		});
		recordEvent(store, {
			actor: "operator",
			action: "scim.test",
			subjectType: "directory_connection",
			subjectId: id,
			outcome: pass ? "success" : "failure",
			source: "scim",
			organizationId: conn.organizationId,
			correlationId: corr,
			message: pass
				? `Live SCIM conformance passed for ${endpointUrl.origin} — ${LIVE_EVIDENCE_LABEL}`
				: `Live SCIM conformance failed at ${stage}: ${cause}`,
			metadata: { mode: LIVE_CONFORMANCE_MODE, endpoint: endpointUrl.origin },
		});
		return {
			pass,
			trace,
			connection: publicDirectoryConnection(conn) as DirectoryConnection,
			mode: LIVE_CONFORMANCE_MODE,
			evidence: LIVE_EVIDENCE_LABEL,
			endpoint: endpointUrl.origin,
		};
	};

	const spc = await probeScimEndpoint({
		endpoint: conn.endpoint,
		bearerToken,
		path: "/ServiceProviderConfig",
		timeoutMs: opts.timeoutMs ?? 10_000,
		...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
	});
	if (!spc.ok) {
		return finish(false, "serviceproviderconfig.fetch", spc.reason, [
			{ name: "service_provider_config", pass: false, detail: spc.message },
		], spc.reason === "authentication"
			? "The SCIM endpoint rejected the bearer credential; rotate the token with the customer IT admin"
			: "Verify the SCIM base URL and network path");
	}

	const users = await probeScimEndpoint({
		endpoint: conn.endpoint,
		bearerToken,
		path: "/Users?count=1",
		timeoutMs: opts.timeoutMs ?? 10_000,
		...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
	});
	if (!users.ok) {
		return finish(false, "users.read", users.reason, [
			{ name: "service_provider_config", pass: true, detail: `HTTP ${spc.status}` },
			{ name: "users_read", pass: false, detail: users.message },
		], "ServiceProviderConfig succeeded but the Users resource is not readable; check credential scopes");
	}

	return finish(true, "users.read", `live read-only conformance for ${endpointUrl.origin}`, [
		{ name: "service_provider_config", pass: true, detail: `HTTP ${spc.status}` },
		{ name: "users_read", pass: true, detail: `HTTP ${users.status}` },
		{ name: "mode", pass: true, detail: "live" },
		{ name: "tenant_mutation", pass: true, detail: "read-only probe; no writes issued" },
	]);
}
