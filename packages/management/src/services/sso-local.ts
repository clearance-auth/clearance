/**
 * Local OIDC protocol verification: authorization URL + state, nonce, PKCE,
 * and callback validation against a deterministic local issuer fixture.
 *
 * Evidence is always local protocol verification — never Okta/Entra tenant certification.
 */
import { createHash, randomBytes } from "node:crypto";
import {
	createServer,
	type IncomingMessage,
	type ServerResponse,
} from "node:http";
import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DiagnosticTrace, IdentityConnection } from "../types/resources.js";
import { recordEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";

export const SSO_LOCAL_PROTOCOL_MODE = "simulation" as const;
export const SSO_LOCAL_EVIDENCE_LABEL =
	"local protocol verification (not Okta/Entra tenant certification)" as const;

function b64url(buf: Buffer): string {
	return buf
		.toString("base64")
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
}

export function generatePkcePair(): {
	codeVerifier: string;
	codeChallenge: string;
	codeChallengeMethod: "S256";
} {
	const codeVerifier = b64url(randomBytes(32));
	const codeChallenge = b64url(
		createHash("sha256").update(codeVerifier).digest(),
	);
	return { codeVerifier, codeChallenge, codeChallengeMethod: "S256" };
}

export function buildAuthorizationUrl(input: {
	authorizationEndpoint: string;
	clientId: string;
	redirectUri: string;
	state: string;
	nonce: string;
	codeChallenge: string;
	codeChallengeMethod?: string;
	scope?: string;
}): string {
	const u = new URL(input.authorizationEndpoint);
	u.searchParams.set("response_type", "code");
	u.searchParams.set("client_id", input.clientId);
	u.searchParams.set("redirect_uri", input.redirectUri);
	u.searchParams.set("scope", input.scope ?? "openid profile email");
	u.searchParams.set("state", input.state);
	u.searchParams.set("nonce", input.nonce);
	u.searchParams.set("code_challenge", input.codeChallenge);
	u.searchParams.set(
		"code_challenge_method",
		input.codeChallengeMethod ?? "S256",
	);
	return u.toString();
}

export type LocalOidcSession = {
	state: string;
	nonce: string;
	codeVerifier: string;
	codeChallenge: string;
	clientId: string;
	redirectUri: string;
	issuedCode?: string;
};

/**
 * Deterministic local OIDC issuer fixture (discovery + authorize + token).
 * Validates state echo, PKCE S256, and returns id_token carrying nonce.
 */
export function createLocalOidcIssuerFixture(opts?: {
	clientId?: string;
	clientSecret?: string;
}): {
	listen: () => Promise<{
		issuer: string;
		authorizationEndpoint: string;
		tokenEndpoint: string;
		jwksUri: string;
		discovery: Record<string, unknown>;
	}>;
	close: () => Promise<void>;
	sessions: Map<string, LocalOidcSession>;
	registerSession: (session: LocalOidcSession) => void;
} {
	const clientId = opts?.clientId ?? "clearance-local-client";
	const sessions = new Map<string, LocalOidcSession>();
	let issuerBase = "";

	const server = createServer(
		async (req: IncomingMessage, res: ServerResponse) => {
			const host = req.headers.host ?? "127.0.0.1";
			const url = new URL(req.url ?? "/", `http://${host}`);

			if (url.pathname === "/.well-known/openid-configuration") {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(
					JSON.stringify({
						issuer: issuerBase,
						authorization_endpoint: `${issuerBase}/authorize`,
						token_endpoint: `${issuerBase}/token`,
						jwks_uri: `${issuerBase}/jwks`,
						response_types_supported: ["code"],
						subject_types_supported: ["public"],
						id_token_signing_alg_values_supported: ["none"],
						code_challenge_methods_supported: ["S256"],
					}),
				);
				return;
			}

			if (url.pathname === "/authorize") {
				const state = url.searchParams.get("state") ?? "";
				const nonce = url.searchParams.get("nonce") ?? "";
				const challenge = url.searchParams.get("code_challenge") ?? "";
				const method = url.searchParams.get("code_challenge_method") ?? "";
				const redirectUri = url.searchParams.get("redirect_uri") ?? "";
				const reqClientId = url.searchParams.get("client_id") ?? "";
				const session = sessions.get(state);

				if (
					!session ||
					session.nonce !== nonce ||
					session.codeChallenge !== challenge ||
					method !== "S256" ||
					session.clientId !== reqClientId ||
					session.redirectUri !== redirectUri
				) {
					res.statusCode = 400;
					res.end("invalid_authorize_request");
					return;
				}
				const code = b64url(randomBytes(16));
				session.issuedCode = code;
				const redirect = new URL(redirectUri);
				redirect.searchParams.set("code", code);
				redirect.searchParams.set("state", state);
				res.statusCode = 302;
				res.setHeader("Location", redirect.toString());
				res.end();
				return;
			}

			if (url.pathname === "/token" && req.method === "POST") {
				const chunks: Buffer[] = [];
				for await (const c of req) chunks.push(c as Buffer);
				const body = Buffer.concat(chunks).toString("utf8");
				const params = new URLSearchParams(body);
				const code = params.get("code") ?? "";
				const verifier = params.get("code_verifier") ?? "";
				const grant = params.get("grant_type");
				const redirectUri = params.get("redirect_uri") ?? "";
				const reqClientId = params.get("client_id") ?? clientId;

				const session = [...sessions.values()].find((s) => s.issuedCode === code);
				if (
					grant !== "authorization_code" ||
					!session ||
					session.clientId !== reqClientId ||
					session.redirectUri !== redirectUri
				) {
					res.statusCode = 400;
					res.setHeader("content-type", "application/json");
					res.end(JSON.stringify({ error: "invalid_grant" }));
					return;
				}
				const expectedChallenge = b64url(
					createHash("sha256").update(verifier).digest(),
				);
				if (expectedChallenge !== session.codeChallenge) {
					res.statusCode = 400;
					res.setHeader("content-type", "application/json");
					res.end(JSON.stringify({ error: "invalid_pkce" }));
					return;
				}

				const header = b64url(
					Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })),
				);
				const payload = b64url(
					Buffer.from(
						JSON.stringify({
							iss: issuerBase,
							sub: "local-user-1",
							aud: session.clientId,
							nonce: session.nonce,
							exp: Math.floor(Date.now() / 1000) + 300,
							iat: Math.floor(Date.now() / 1000),
						}),
					),
				);
				const idToken = `${header}.${payload}.`;

				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(
					JSON.stringify({
						access_token: b64url(randomBytes(16)),
						token_type: "Bearer",
						expires_in: 3600,
						id_token: idToken,
					}),
				);
				return;
			}

			if (url.pathname === "/jwks") {
				res.statusCode = 200;
				res.setHeader("content-type", "application/json");
				res.end(JSON.stringify({ keys: [] }));
				return;
			}

			res.statusCode = 404;
			res.end("not found");
		},
	);

	return {
		sessions,
		registerSession: (session) => {
			sessions.set(session.state, session);
		},
		listen: () =>
			new Promise((resolve, reject) => {
				server.listen(0, "127.0.0.1", () => {
					const addr = server.address();
					if (!addr || typeof addr === "string") {
						reject(new Error("no address"));
						return;
					}
					issuerBase = `http://127.0.0.1:${addr.port}`;
					resolve({
						issuer: issuerBase,
						authorizationEndpoint: `${issuerBase}/authorize`,
						tokenEndpoint: `${issuerBase}/token`,
						jwksUri: `${issuerBase}/jwks`,
						discovery: {
							issuer: issuerBase,
							authorization_endpoint: `${issuerBase}/authorize`,
							token_endpoint: `${issuerBase}/token`,
							jwks_uri: `${issuerBase}/jwks`,
							response_types_supported: ["code"],
							subject_types_supported: ["public"],
							id_token_signing_alg_values_supported: ["none"],
							code_challenge_methods_supported: ["S256"],
						},
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

export function decodeJwtPayload(idToken: string): Record<string, unknown> {
	const parts = idToken.split(".");
	if (parts.length < 2) throw new Error("invalid id_token");
	const pad =
		parts[1].length % 4 === 0 ? "" : "=".repeat(4 - (parts[1].length % 4));
	const json = Buffer.from(
		parts[1].replace(/-/g, "+").replace(/_/g, "/") + pad,
		"base64",
	).toString("utf8");
	return JSON.parse(json) as Record<string, unknown>;
}

/**
 * Exercise full local OIDC authorize→callback→token path with state/nonce/PKCE.
 * Labels evidence as local protocol verification; never Okta/Entra certification.
 */
export async function verifySsoOidcLocalProtocol(
	store: ManagementStore,
	connectionId: string,
	opts: {
		issuer?: {
			authorizationEndpoint: string;
			tokenEndpoint: string;
			issuer: string;
		};
		clientId?: string;
		redirectUri?: string;
		fetchImpl?: typeof fetch;
	} = {},
): Promise<{
	pass: boolean;
	trace: DiagnosticTrace;
	connection: IdentityConnection;
	mode: "simulation";
	evidence: typeof SSO_LOCAL_EVIDENCE_LABEL;
	authorizationUrl: string;
	certifiedExternalTenant: false;
}> {
	const conn = store.snapshot.identityConnections.find(
		(c) => c.id === connectionId,
	);
	if (!conn) {
		throw new ClearanceError({
			code: "SSO_NOT_FOUND",
			message: `SSO connection ${connectionId} not found`,
			stage: "sso.local-protocol",
			status: 404,
		});
	}

	const corr = `corr_sso_local_${newId("t").slice(4)}`;
	const base = {
		id: newId("tr"),
		correlationId: corr,
		organizationId: conn.organizationId,
		connectionId: conn.id,
		subsystem: "sso" as const,
		mode: SSO_LOCAL_PROTOCOL_MODE,
		createdAt: nowIso(),
	};

	let fixture: ReturnType<typeof createLocalOidcIssuerFixture> | null = null;
	let issuerMeta = opts.issuer;

	try {
		if (!issuerMeta) {
			fixture = createLocalOidcIssuerFixture({
				clientId: opts.clientId ?? conn.clientId ?? "clearance-local-client",
			});
			const listened = await fixture.listen();
			issuerMeta = {
				issuer: listened.issuer,
				authorizationEndpoint: listened.authorizationEndpoint,
				tokenEndpoint: listened.tokenEndpoint,
			};
		}

		const clientId = opts.clientId ?? conn.clientId ?? "clearance-local-client";
		const redirectUri = opts.redirectUri ?? "http://127.0.0.1/callback";
		const state = b64url(randomBytes(16));
		const nonce = b64url(randomBytes(16));
		const pkce = generatePkcePair();

		const session: LocalOidcSession = {
			state,
			nonce,
			codeVerifier: pkce.codeVerifier,
			codeChallenge: pkce.codeChallenge,
			clientId,
			redirectUri,
		};

		if (fixture) {
			fixture.registerSession(session);
		}

		const authorizationUrl = buildAuthorizationUrl({
			authorizationEndpoint: issuerMeta.authorizationEndpoint,
			clientId,
			redirectUri,
			state,
			nonce,
			codeChallenge: pkce.codeChallenge,
		});

		const authUrl = new URL(authorizationUrl);
		if (
			authUrl.searchParams.get("state") !== state ||
			authUrl.searchParams.get("nonce") !== nonce ||
			authUrl.searchParams.get("code_challenge") !== pkce.codeChallenge ||
			authUrl.searchParams.get("code_challenge_method") !== "S256"
		) {
			throw new ClearanceError({
				code: "SSO_AUTH_URL_INVALID",
				message: "Authorization URL missing state/nonce/PKCE",
				stage: "authorization.url",
			});
		}

		const fetchFn = opts.fetchImpl ?? fetch;

		const authRes = await fetchFn(authorizationUrl, { redirect: "manual" });
		if (authRes.status !== 302 && authRes.status !== 303) {
			throw new ClearanceError({
				code: "SSO_AUTHORIZE_FAILED",
				message: `Authorize endpoint returned ${authRes.status}`,
				stage: "authorization.redirect",
			});
		}
		const location = authRes.headers.get("location");
		if (!location) {
			throw new ClearanceError({
				code: "SSO_CALLBACK_MISSING",
				message: "Authorize did not return redirect Location",
				stage: "authorization.callback",
			});
		}
		const callback = new URL(location);
		const returnedState = callback.searchParams.get("state");
		const code = callback.searchParams.get("code");
		if (returnedState !== state) {
			throw new ClearanceError({
				code: "SSO_STATE_MISMATCH",
				message: "Callback state does not match",
				stage: "authorization.state",
			});
		}
		if (!code) {
			throw new ClearanceError({
				code: "SSO_CODE_MISSING",
				message: "Callback missing authorization code",
				stage: "authorization.code",
			});
		}

		const tokenRes = await fetchFn(issuerMeta.tokenEndpoint, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: redirectUri,
				client_id: clientId,
				code_verifier: pkce.codeVerifier,
			}).toString(),
		});
		if (!tokenRes.ok) {
			const t = await tokenRes.text();
			throw new ClearanceError({
				code: "SSO_TOKEN_FAILED",
				message: `Token endpoint failed: ${tokenRes.status} ${t.slice(0, 120)}`,
				stage: "token.exchange",
			});
		}
		const tokenBody = (await tokenRes.json()) as {
			id_token?: string;
			access_token?: string;
		};
		if (!tokenBody.id_token) {
			throw new ClearanceError({
				code: "SSO_ID_TOKEN_MISSING",
				message: "Token response missing id_token",
				stage: "token.id_token",
			});
		}
		const claims = decodeJwtPayload(tokenBody.id_token);
		if (claims.nonce !== nonce) {
			throw new ClearanceError({
				code: "SSO_NONCE_MISMATCH",
				message: "id_token nonce does not match",
				stage: "token.nonce",
			});
		}
		if (claims.iss !== issuerMeta.issuer) {
			throw new ClearanceError({
				code: "SSO_ISSUER_MISMATCH",
				message: "id_token issuer does not match local fixture issuer",
				stage: "token.issuer",
			});
		}

		const trace: DiagnosticTrace = {
			...base,
			stage: "oidc.local_protocol",
			outcome: "pass",
			cause: SSO_LOCAL_EVIDENCE_LABEL,
			causeConfidence: 1,
			owner: "application",
			checks: [
				{
					name: "authorization_url",
					pass: true,
					detail: "state+nonce+PKCE S256",
				},
				{ name: "state", pass: true },
				{ name: "nonce", pass: true },
				{ name: "pkce", pass: true, detail: "S256" },
				{ name: "callback", pass: true },
				{ name: "token_exchange", pass: true },
				{
					name: "evidence",
					pass: true,
					detail: SSO_LOCAL_EVIDENCE_LABEL,
				},
				{
					name: "external_tenant_certification",
					pass: false,
					detail: "false — local fixture only",
				},
			],
			redactedResponse: {
				evidence: SSO_LOCAL_EVIDENCE_LABEL,
				certifiedExternalTenant: false,
			},
		};

		store.mutate((data) => {
			data.traces.unshift(trace);
			const idx = data.identityConnections.findIndex(
				(c) => c.id === connectionId,
			);
			if (idx >= 0) {
				data.identityConnections[idx] = {
					...conn,
					status: "testing",
					updatedAt: nowIso(),
				};
			}
		});

		recordEvent(store, {
			actor: "system",
			action: "sso.local-protocol",
			subjectType: "identity_connection",
			subjectId: connectionId,
			outcome: "success",
			source: "sso",
			organizationId: conn.organizationId,
			correlationId: corr,
			message: SSO_LOCAL_EVIDENCE_LABEL,
			metadata: {
				mode: SSO_LOCAL_PROTOCOL_MODE,
				evidence: SSO_LOCAL_EVIDENCE_LABEL,
				certifiedExternalTenant: false,
			},
		});

		return {
			pass: true,
			trace,
			connection: store.snapshot.identityConnections.find(
				(c) => c.id === connectionId,
			)!,
			mode: SSO_LOCAL_PROTOCOL_MODE,
			evidence: SSO_LOCAL_EVIDENCE_LABEL,
			authorizationUrl,
			certifiedExternalTenant: false,
		};
	} finally {
		if (fixture) await fixture.close();
	}
}
