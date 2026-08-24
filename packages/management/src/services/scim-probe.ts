/**
 * SCIM connection probe — performs real SCIM HTTP requests against a configured
 * endpoint. Outcomes for network, auth, malformed body, and non-success status
 * are failures. Evidence is always "local protocol verification" unless the
 * operator explicitly points at a real tenant (still not certification).
 */
import { lookup as dnsLookup } from "node:dns/promises";
import {
	createServer,
	request as httpRequest,
	type IncomingMessage,
	type ServerResponse,
} from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import { ClearanceError } from "./errors.js";

export type ScimProbeOutcome =
	| { ok: true; status: number; path: string; bodySnippet: string }
	| {
			ok: false;
			reason: "network" | "authentication" | "malformed_body" | "non_success";
			status?: number;
			message: string;
			path?: string;
	};

export type ScimProbeOptions = {
	endpoint: string;
	bearerToken?: string;
	/** Relative path under endpoint (default ServiceProviderConfig) */
	path?: string;
	timeoutMs?: number;
	fetchImpl?: typeof fetch;
};

const blockedAddresses = new BlockList();
const publicIpv6Addresses = new BlockList();
publicIpv6Addresses.addSubnet("2000::", 3, "ipv6");
for (const [network, prefix] of [
	["0.0.0.0", 8],
	["10.0.0.0", 8],
	["100.64.0.0", 10],
	["127.0.0.0", 8],
	["169.254.0.0", 16],
	["172.16.0.0", 12],
	["192.0.0.0", 24],
	["192.0.2.0", 24],
	["192.168.0.0", 16],
	["198.18.0.0", 15],
	["198.51.100.0", 24],
	["203.0.113.0", 24],
	["224.0.0.0", 4],
] as const) {
	blockedAddresses.addSubnet(network, prefix, "ipv4");
}
for (const [network, prefix] of [
	["::", 128],
	["::1", 128],
	["fc00::", 7],
	["fe80::", 10],
	["ff00::", 8],
	["2001:db8::", 32],
] as const) {
	blockedAddresses.addSubnet(network, prefix, "ipv6");
}

function normalizedAddress(address: string): { address: string; family: 4 | 6 } {
	const unbracketed = address.startsWith("[") && address.endsWith("]")
		? address.slice(1, -1)
		: address;
	const mappedDotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(unbracketed);
	if (mappedDotted) return { address: mappedDotted[1]!, family: 4 };
	const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(unbracketed);
	if (mappedHex) {
		const high = Number.parseInt(mappedHex[1]!, 16);
		const low = Number.parseInt(mappedHex[2]!, 16);
		return {
			address: `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`,
			family: 4,
		};
	}
	return { address: unbracketed, family: isIP(unbracketed) === 6 ? 6 : 4 };
}

function assertPublicAddress(address: string): { address: string; family: 4 | 6 } {
	const normalized = normalizedAddress(address);
	if (
		isIP(normalized.address) === 0 ||
		(normalized.family === 6 &&
			!publicIpv6Addresses.check(normalized.address, "ipv6")) ||
		blockedAddresses.check(
			normalized.address,
			normalized.family === 4 ? "ipv4" : "ipv6",
		)
	) {
		throw new ClearanceError({
			code: "SCIM_ENDPOINT_FORBIDDEN",
			message: "SCIM probes refuse local, private, reserved, and link-local destinations",
			stage: "scim.probe.address",
			status: 400,
			remediation: "Use a publicly routable SCIM endpoint; use injected fixture transport for local protocol tests.",
		});
	}
	return normalized;
}

async function resolvePublicAddress(hostname: string): Promise<{ address: string; family: 4 | 6 }> {
	const literal = isIP(normalizedAddress(hostname).address);
	if (literal) return assertPublicAddress(hostname);
	let results: Array<{ address: string; family: number }>;
	try {
		results = await dnsLookup(hostname, { all: true, verbatim: true }) as Array<{
			address: string;
			family: number;
		}>;
	} catch (error) {
		throw new ClearanceError({
			code: "SCIM_ENDPOINT_DNS_FAILED",
			message: error instanceof Error ? error.message : "SCIM endpoint DNS lookup failed",
			stage: "scim.probe.dns",
			status: 400,
		});
	}
	if (results.length === 0) {
		throw new ClearanceError({
			code: "SCIM_ENDPOINT_DNS_FAILED",
			message: "SCIM endpoint DNS lookup returned no addresses",
			stage: "scim.probe.dns",
			status: 400,
		});
	}
	const safe = results.map((result) => assertPublicAddress(result.address));
	return safe[0]!;
}

async function pinnedRequest(
	url: URL,
	headers: Record<string, string>,
	timeoutMs: number,
): Promise<{ status: number; text: string }> {
	const target = await resolvePublicAddress(url.hostname);
	return new Promise((resolve, reject) => {
		const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(url, {
			method: "GET",
			headers,
			lookup: (_hostname, _options, callback) => {
				callback(null, target.address, target.family);
			},
		}, (response) => {
			const chunks: Buffer[] = [];
			let size = 0;
			response.on("data", (chunk: Buffer | string) => {
				if (size >= 65_536) return;
				const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
				chunks.push(buffer.subarray(0, Math.max(0, 65_536 - size)));
				size += buffer.length;
			});
			response.on("end", () => resolve({
				status: response.statusCode ?? 0,
				text: Buffer.concat(chunks).toString("utf8"),
			}));
		});
		request.setTimeout(timeoutMs, () => request.destroy(new Error("SCIM probe timed out")));
		request.on("error", reject);
		request.end();
	});
}

function joinScimUrl(endpoint: string, path: string): string {
	const base = endpoint.replace(/\/$/, "");
	const rel = path.startsWith("/") ? path : `/${path}`;
	// If endpoint already ends with /v2, append path; otherwise assume base is root
	return `${base}${rel}`;
}

/**
 * Issue a real SCIM GET against the connection endpoint.
 * Uses application/scim+json Accept and optional Bearer token.
 */
export async function probeScimEndpoint(
	opts: ScimProbeOptions,
): Promise<ScimProbeOutcome> {
	const path = opts.path ?? "/ServiceProviderConfig";
	const url = joinScimUrl(opts.endpoint, path);
	const headers: Record<string, string> = {
		accept: "application/scim+json, application/json",
		"user-agent": "clearance-scim-probe/0.1",
	};
	if (opts.bearerToken) {
		headers.authorization = `Bearer ${opts.bearerToken}`;
	}

	const timeoutMs = opts.timeoutMs ?? 5_000;
	let timer: ReturnType<typeof setTimeout> | undefined;

	try {
		let status: number;
		let text: string;
		if (opts.fetchImpl) {
			const controller = new AbortController();
			timer = setTimeout(() => controller.abort(), timeoutMs);
			const response = await opts.fetchImpl(url, {
				method: "GET",
				headers,
				signal: controller.signal,
				redirect: "manual",
			});
			status = response.status;
			text = await response.text();
		} else {
			const response = await pinnedRequest(new URL(url), headers, timeoutMs);
			status = response.status;
			text = response.text;
		}
		const snippet = text.slice(0, 400);

		if (status >= 300 && status < 400) {
			return {
				ok: false,
				reason: "non_success",
				status,
				message: `SCIM endpoint answered with a redirect (${status}); redirects are refused (probe never follows them)`,
				path,
			};
		}

		if (status === 401 || status === 403) {
			return {
				ok: false,
				reason: "authentication",
				status,
				message: `SCIM endpoint rejected credentials (${status})`,
				path,
			};
		}

		if (status >= 400) {
			return {
				ok: false,
				reason: "non_success",
				status,
				message: `SCIM endpoint returned non-success status ${status}`,
				path,
			};
		}

		// Malformed body: success status but invalid JSON when body present
		const trimmed = text.trim();
		if (trimmed.length > 0) {
			try {
				JSON.parse(trimmed);
			} catch {
				return {
					ok: false,
					reason: "malformed_body",
					status,
					message: "SCIM response body is not valid JSON",
					path,
				};
			}
		}

		return { ok: true, status, path, bodySnippet: snippet };
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		return {
			ok: false,
			reason: "network",
			message: `SCIM network error: ${msg}`,
			path,
		};
	} finally {
		if (timer) clearTimeout(timer);
	}
}

export function probeOutcomeToError(outcome: Extract<ScimProbeOutcome, { ok: false }>): ClearanceError {
	const code =
		outcome.reason === "authentication"
			? "SCIM_UNAUTHORIZED"
			: outcome.reason === "malformed_body"
				? "SCIM_MALFORMED"
				: outcome.reason === "network"
					? "SCIM_NETWORK"
					: "SCIM_PROBE_FAILED";
	return new ClearanceError({
		code,
		message: outcome.message,
		stage:
			outcome.reason === "authentication"
				? "auth.bearer"
				: outcome.reason === "malformed_body"
					? "response.parse"
					: outcome.reason === "network"
						? "connection.network"
						: "connection.http",
		remediation:
			outcome.reason === "authentication"
				? "Rotate SCIM token and update the IdP connector"
				: outcome.reason === "network"
					? "Verify endpoint URL reachability and TLS"
					: "Inspect SCIM provider response and endpoint path",
		status: outcome.status && outcome.status >= 400 ? outcome.status : 502,
	});
}

/**
 * Deterministic local SCIM HTTP fixture for tests.
 * Modes: ok | unauthorized | malformed | non_success
 */
export function createLocalScimFixtureServer(
	mode: "ok" | "unauthorized" | "malformed" | "non_success" = "ok",
	expectedToken = "test-scim-token",
): {
	server: ReturnType<typeof createServer>;
	listen: () => Promise<{ baseUrl: string; port: number }>;
	close: () => Promise<void>;
	requests: Array<{ method?: string; url?: string; authorization?: string }>;
} {
	const requests: Array<{
		method?: string;
		url?: string;
		authorization?: string;
	}> = [];

	const server = createServer((req: IncomingMessage, res: ServerResponse) => {
		const auth = req.headers.authorization;
		requests.push({
			method: req.method,
			url: req.url,
			authorization: typeof auth === "string" ? auth : undefined,
		});

		if (mode === "unauthorized") {
			res.statusCode = 401;
			res.setHeader("content-type", "application/scim+json");
			res.end(
				JSON.stringify({
					schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
					status: "401",
					detail: "Unauthorized",
				}),
			);
			return;
		}

		if (mode === "non_success") {
			res.statusCode = 503;
			res.setHeader("content-type", "application/scim+json");
			res.end(
				JSON.stringify({
					schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
					status: "503",
					detail: "Service Unavailable",
				}),
			);
			return;
		}

		if (expectedToken && auth !== `Bearer ${expectedToken}`) {
			res.statusCode = 401;
			res.setHeader("content-type", "application/scim+json");
			res.end(
				JSON.stringify({
					schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
					status: "401",
					detail: "Invalid token",
				}),
			);
			return;
		}

		if (mode === "malformed") {
			res.statusCode = 200;
			res.setHeader("content-type", "application/scim+json");
			res.end("not-json{{{");
			return;
		}

		// ok
		res.statusCode = 200;
		res.setHeader("content-type", "application/scim+json");
		if (req.url?.includes("ServiceProviderConfig") || req.url === "/" || !req.url) {
			res.end(
				JSON.stringify({
					schemas: [
						"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
					],
					patch: { supported: true },
					bulk: { supported: false, maxOperations: 0 },
					filter: { supported: true, maxResults: 100 },
					changePassword: { supported: false },
					sort: { supported: false },
					etag: { supported: false },
					authenticationSchemes: [
						{
							type: "oauthbearertoken",
							name: "OAuth Bearer Token",
							description: "local fixture",
						},
					],
				}),
			);
			return;
		}
		res.end(
			JSON.stringify({
				schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
				totalResults: 0,
				Resources: [],
			}),
		);
	});

	return {
		server,
		requests,
		listen: () =>
			new Promise((resolve, reject) => {
				server.listen(0, "127.0.0.1", () => {
					const addr = server.address();
					if (!addr || typeof addr === "string") {
						reject(new Error("no address"));
						return;
					}
					resolve({
						port: addr.port,
						baseUrl: `http://127.0.0.1:${addr.port}`,
					});
				});
				server.on("error", reject);
			}),
		close: () =>
			new Promise((resolve) => {
				server.close(() => resolve());
			}),
	};
}
