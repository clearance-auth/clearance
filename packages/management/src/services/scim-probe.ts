/**
 * SCIM connection probe — performs real SCIM HTTP requests against a configured
 * endpoint. Outcomes for network, auth, malformed body, and non-success status
 * are failures. Evidence is always "local protocol verification" unless the
 * operator explicitly points at a real tenant (still not certification).
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
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

	const fetchFn = opts.fetchImpl ?? fetch;
	const controller = new AbortController();
	const timer = setTimeout(
		() => controller.abort(),
		opts.timeoutMs ?? 5_000,
	);

	try {
		const res = await fetchFn(url, {
			method: "GET",
			headers,
			signal: controller.signal,
			// SSRF guard: a validated external endpoint could still answer
			// 302 → http://127.0.0.1/... and a following fetch would obey it.
			// Redirects are refused, never followed (adversarial finding M2).
			redirect: "manual",
		});
		const text = await res.text();
		const snippet = text.slice(0, 400);

		if (res.status >= 300 && res.status < 400) {
			return {
				ok: false,
				reason: "non_success",
				status: res.status,
				message: `SCIM endpoint answered with a redirect (${res.status}); redirects are refused (probe never follows them)`,
				path,
			};
		}

		if (res.status === 401 || res.status === 403) {
			return {
				ok: false,
				reason: "authentication",
				status: res.status,
				message: `SCIM endpoint rejected credentials (${res.status})`,
				path,
			};
		}

		if (res.status >= 400) {
			return {
				ok: false,
				reason: "non_success",
				status: res.status,
				message: `SCIM endpoint returned non-success status ${res.status}`,
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
					status: res.status,
					message: "SCIM response body is not valid JSON",
					path,
				};
			}
		}

		return { ok: true, status: res.status, path, bodySnippet: snippet };
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		return {
			ok: false,
			reason: "network",
			message: `SCIM network error: ${msg}`,
			path,
		};
	} finally {
		clearTimeout(timer);
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
