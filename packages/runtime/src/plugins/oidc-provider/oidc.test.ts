import {
	createLocalJWKSet,
	decodeProtectedHeader,
	jwtVerify,
	SignJWT,
} from "jose";
import type { Listener } from "listhen";
import { listen } from "listhen";
import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	test,
} from "vitest";
import type { AuthClient } from "../../client";
import { createAuthClient } from "../../client";
import { toNodeHandler } from "../../integrations/node";
import { getTestInstance } from "../../test-utils/test-instance";
import { generateCredentialOperationKey } from "../../utils/operation-key";
import { genericOAuth } from "../generic-oauth";
import { genericOAuthClient } from "../generic-oauth/client";
import { admin } from "../admin";
import { jwt } from "../jwt";
import {
	createOAuthTokenPair,
	oidcProvider,
	rotateOAuthRefreshToken,
} from ".";
import type { OidcClientPlugin } from "./client";
import { oidcClient } from "./client";
import type { Client } from "./types";

// Pre-verifies any user the RP creates via OAuth signup so the existing-user
// path on the RP side does not trip the local-emailVerified gate.
const autoVerifyUserHook = {
	user: {
		create: {
			before: async (user: Record<string, unknown>) => ({
				data: { ...user, emailVerified: true },
			}),
		},
	},
} as const;

const RESERVED_ADDITIONAL_CLAIM_NAMES = [
	"iss",
	"sub",
	"aud",
	"exp",
	"nbf",
	"iat",
	"jti",
	"auth_time",
	"nonce",
	"acr",
	"amr",
	"azp",
	"at_hash",
	"c_hash",
	"s_hash",
	"sid",
	"cnf",
	"act",
	"may_act",
	"middle_name",
	"nickname",
	"preferred_username",
	"website",
	"gender",
	"birthdate",
	"zoneinfo",
	"locale",
	"phone_number",
	"phone_number_verified",
	"address",
	"updated_at",
	"_claim_names",
	"_claim_sources",
	"client_id",
	"scope",
	"authorization_details",
	"token_type",
	"token_use",
	"username",
	"groups",
	"roles",
	"entitlements",
	"events",
	"toe",
	"txn",
	"htm",
	"htu",
	"ath",
	"jkt",
] as const;

// Type for the server client with OIDC plugin
type ServerClient = AuthClient<{
	plugins: [OidcClientPlugin];
}>;

/**
 * Helper to handle OIDC consent flow when required per OIDC spec
 */
async function handleConsentFlow(
	redirectURI: string,
	serverClient: ServerClient,
	sessionHeaders: Headers,
	consentHeaders: Headers,
): Promise<string> {
	if (!redirectURI.includes("consent_code=")) {
		return redirectURI;
	}

	// Extract consent code from redirect URL
	const url = new URL(redirectURI, "http://localhost:3000");
	const consentCode = url.searchParams.get("consent_code");

	if (!consentCode) {
		throw new Error("Consent code not found in redirect URL");
	}

	// Merge session headers with consent cookies
	const authHeaders = new Headers(sessionHeaders);
	consentHeaders.forEach((value, key) => {
		if (key.toLowerCase() === "cookie") {
			const existing = authHeaders.get("Cookie") || "";
			authHeaders.set("Cookie", existing ? `${existing}; ${value}` : value);
		} else {
			authHeaders.set(key, value);
		}
	});

	// Accept consent
	const response = await serverClient.oauth2.consent(
		{ accept: true, consent_code: consentCode },
		{ headers: authHeaders, throw: true },
	);

	return response.redirectURI;
}

describe("oidc init", () => {
	it("default options", () => {
		const provider = oidcProvider({
			loginPage: "/login",
		});
		const options = provider.options;
		expect(options).toMatchInlineSnapshot(`
			{
			  "accessTokenExpiresIn": 300,
			  "allowPlainCodeChallengeMethod": false,
			  "codeExpiresIn": 600,
			  "defaultScope": "openid",
			  "loginPage": "/login",
			  "refreshTokenExpiresIn": 604800,
			  "scopes": [
			    "openid",
			    "profile",
			    "email",
			    "offline_access",
			  ],
			  "storeClientSecret": "plain",
			}
		`);
	});

	it("rejects access-token lifetimes above five minutes", () => {
		expect(() =>
			oidcProvider({ loginPage: "/login", accessTokenExpiresIn: 301 }),
		).toThrow("between 1 and 300 seconds");
	});

	it("fails closed without rollback-capable transactions", () => {
		const provider = oidcProvider({ loginPage: "/login" });
		expect(() =>
			provider.init?.({
				adapter: { options: { adapterConfig: { transaction: false } } },
				options: {},
			} as any),
		).toThrow("rollback-capable transactions");
	});

	it("refuses direct refresh rotation without rollback-capable transactions", async () => {
		await expect(
			rotateOAuthRefreshToken(
				{ options: { adapterConfig: { transaction: false } } } as any,
				"oauthAccessToken",
				{
					presentedRefreshToken: "unsupported-adapter-refresh-token",
					clientId: "unsupported-adapter-client",
					accessTokenExpiresAt: new Date(Date.now() + 300_000),
					secretConfig: "unsupported-adapter-secret",
				},
			),
		).rejects.toThrow("rollback-capable transactions");
	});
});

describe("oidc", async () => {
	const {
		auth: authorizationServer,
		signInWithTestUser,
		customFetchImpl,
		testUser,
	} = await getTestInstance({
		baseURL: "http://localhost:3000",
		plugins: [
			oidcProvider({
				loginPage: "/login",
				consentPage: "/oauth2/authorize",
				requirePKCE: true,
				getAdditionalUserInfoClaim(user) {
					return {
						custom: "custom value",
						userId: user.id,
					};
				},
			}),
			jwt(),
		],
	});
	const { headers } = await signInWithTestUser();
	const serverClient = createAuthClient({
		plugins: [oidcClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: {
			customFetchImpl,
			headers,
		},
	});

	let server: Listener;

	beforeAll(async () => {
		server = await listen(toNodeHandler(authorizationServer.handler), {
			port: 3000,
		});
	});

	afterAll(async () => {
		await server.close();
	});

	let application: Client = {
		clientId: "test-client-id",
		clientSecret: "test-client-secret-oidc",
		redirectUrls: ["http://localhost:3000/api/auth/oauth2/callback/test"],
		metadata: {},
		type: "web",
		disabled: false,
		name: "test",
	};

	it("should create oidc client", async ({ expect }) => {
		const createdClient = await serverClient.oauth2.register({
			client_name: application.name,
			redirect_uris: application.redirectUrls,
			logo_uri: application.icon,
		});
		expect(createdClient.data).toMatchObject({
			client_id: expect.any(String),
			client_secret: expect.any(String),
			client_name: "test",
			redirect_uris: ["http://localhost:3000/api/auth/oauth2/callback/test"],
			grant_types: ["authorization_code"],
			response_types: ["code"],
			token_endpoint_auth_method: "client_secret_basic",
			client_id_issued_at: expect.any(Number),
			client_secret_expires_at: 0,
		});
		if (createdClient.data) {
			application = {
				clientId: createdClient.data.client_id,
				clientSecret: createdClient.data.client_secret,
				redirectUrls: createdClient.data.redirect_uris,
				metadata: {},
				icon: createdClient.data.logo_uri,
				type: "web",
				disabled: false,
				name: createdClient.data.client_name!,
			};
		}
		const client = await authorizationServer.api.getOAuthClient({
			params: {
				id: application.clientId,
			},
			headers,
		});
		expect(client).toEqual({
			clientId: application.clientId,
			name: application.name,
			icon: null,
		});
	});

	it("should sign in the user with the provider", async ({ expect }) => {
		// The RP (Relying Party) - the client application
		const { customFetchImpl: customFetchImplRP, cookieSetter } =
			await getTestInstance({
				account: {
					accountLinking: {
						trustedProviders: ["test"],
					},
				},
				databaseHooks: autoVerifyUserHook,
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "test",
								clientId: application.clientId,
								clientSecret: application.clientSecret || "",
								authorizationUrl:
									"http://localhost:3000/api/auth/oauth2/authorize",
								tokenUrl: "http://localhost:3000/api/auth/oauth2/token",
								scopes: ["openid", "profile", "email"],
								pkce: true,
							},
						],
					}),
				],
			});

		const client = createAuthClient({
			plugins: [genericOAuthClient()],
			baseURL: "http://localhost:5000",
			fetchOptions: {
				customFetchImpl: customFetchImplRP,
			},
		});
		const oAuthHeaders = new Headers();
		const data = await client.signIn.oauth2(
			{
				providerId: "test",
				callbackURL: "/dashboard",
			},
			{
				throw: true,
				onSuccess: cookieSetter(oAuthHeaders),
			},
		);
		expect(data.url).toContain(
			"http://localhost:3000/api/auth/oauth2/authorize",
		);
		expect(data.url).toContain(`client_id=${application.clientId}`);

		// Make the authorization request
		let redirectURI = "";
		const consentHeaders = new Headers();
		await serverClient.$fetch(data.url, {
			method: "GET",
			onError(context) {
				redirectURI = context.response.headers.get("Location") || "";
				// Capture any consent cookies
				cookieSetter(consentHeaders)(context);
			},
		});

		// Handle consent flow if required (per OIDC spec for non-trusted clients)
		redirectURI = await handleConsentFlow(
			redirectURI,
			serverClient,
			headers,
			consentHeaders,
		);

		// Verify we got an authorization code
		expect(redirectURI).toContain(
			"http://localhost:3000/api/auth/oauth2/callback/test?code=",
		);

		// Complete the OAuth flow
		let callbackURL = "";
		await client.$fetch(redirectURI, {
			headers: oAuthHeaders,
			onError(context) {
				callbackURL = context.response.headers.get("Location") || "";
			},
		});
		expect(callbackURL).toContain("/dashboard");
	});

	it("should sign in after a consent flow", async ({ expect }) => {
		// The RP (Relying Party) - the client application
		const { customFetchImpl: customFetchImplRP, cookieSetter } =
			await getTestInstance({
				account: {
					accountLinking: {
						trustedProviders: ["test"],
					},
				},
				databaseHooks: autoVerifyUserHook,
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "test",
								clientId: application.clientId,
								clientSecret: application.clientSecret || "",
								authorizationUrl:
									"http://localhost:3000/api/auth/oauth2/authorize",
								tokenUrl: "http://localhost:3000/api/auth/oauth2/token",
								scopes: ["openid", "profile", "email"],
								prompt: "consent",
								pkce: true,
							},
						],
					}),
				],
			});

		const client = createAuthClient({
			plugins: [genericOAuthClient()],
			baseURL: "http://localhost:5000",
			fetchOptions: {
				customFetchImpl: customFetchImplRP,
			},
		});
		const oAuthHeaders = new Headers();
		const data = await client.signIn.oauth2(
			{
				providerId: "test",
				callbackURL: "/dashboard",
			},
			{
				throw: true,
				onSuccess: cookieSetter(oAuthHeaders),
			},
		);
		expect(data.url).toContain(
			"http://localhost:3000/api/auth/oauth2/authorize",
		);
		expect(data.url).toContain(`client_id=${application.clientId}`);

		let redirectURI = "";
		const newHeaders = new Headers();
		await serverClient.$fetch(data.url, {
			method: "GET",
			onError(context) {
				redirectURI = context.response.headers.get("Location") || "";
				cookieSetter(newHeaders)(context);
				newHeaders.append("Cookie", headers.get("Cookie") || "");
			},
		});
		expect(redirectURI).toContain("/oauth2/authorize?");
		expect(redirectURI).toContain("consent_code=");
		expect(redirectURI).toContain("client_id=");

		// No need to extract consent_code - it's in the signed cookie
		const res = await serverClient.oauth2.consent(
			{
				accept: true,
			},
			{
				headers: newHeaders,
				throw: true,
			},
		);
		expect(res.redirectURI).toContain(
			"http://localhost:3000/api/auth/oauth2/callback/test?code=",
		);

		let callbackURL = "";
		await client.$fetch(res.redirectURI, {
			headers: oAuthHeaders,
			onError(context) {
				callbackURL = context.response.headers.get("Location") || "";
			},
		});
		expect(callbackURL).toContain("/dashboard");
	});

	it("should sign in after a login flow", async ({ expect }) => {
		// The RP (Relying Party) - the client application
		const { customFetchImpl: customFetchImplRP, cookieSetter } =
			await getTestInstance({
				account: {
					accountLinking: {
						trustedProviders: ["test"],
					},
				},
				databaseHooks: autoVerifyUserHook,
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "test",
								clientId: application.clientId,
								clientSecret: application.clientSecret || "",
								authorizationUrl:
									"http://localhost:3000/api/auth/oauth2/authorize",
								tokenUrl: "http://localhost:3000/api/auth/oauth2/token",
								scopes: ["openid", "profile", "email"],
								prompt: "login",
								pkce: true,
							},
						],
					}),
				],
			});

		const client = createAuthClient({
			plugins: [genericOAuthClient()],
			baseURL: "http://localhost:5000",
			fetchOptions: {
				customFetchImpl: customFetchImplRP,
			},
		});
		const oAuthHeaders = new Headers();
		const data = await client.signIn.oauth2(
			{
				providerId: "test",
				callbackURL: "/dashboard",
			},
			{
				throw: true,
				onSuccess: cookieSetter(oAuthHeaders),
			},
		);
		expect(data.url).toContain(
			"http://localhost:3000/api/auth/oauth2/authorize",
		);
		expect(data.url).toContain(`client_id=${application.clientId}`);

		let redirectURI = "";
		const newHeaders = new Headers();
		await serverClient.$fetch(data.url, {
			method: "GET",
			onError(context) {
				redirectURI = context.response.headers.get("Location") || "";
				cookieSetter(newHeaders)(context);
			},
			headers: newHeaders,
		});
		expect(redirectURI).toContain("/login");

		await serverClient.signIn.email(
			{
				email: testUser.email,
				password: testUser.password,
			},
			{
				headers: newHeaders,
				onError(context) {
					redirectURI = context.response.headers.get("Location") || "";
					cookieSetter(newHeaders)(context);
				},
			},
		);

		expect(redirectURI).toContain(
			"http://localhost:3000/api/auth/oauth2/callback/test?code=",
		);
		let callbackURL = "";
		await client.$fetch(redirectURI, {
			headers: oAuthHeaders,
			onError(context) {
				callbackURL = context.response.headers.get("Location") || "";
			},
		});
		expect(callbackURL).toContain("/dashboard");
	});

	describe("prompt parameter handling", () => {
		it("should return login_required error when prompt=none and user not authenticated", async ({
			expect,
		}) => {
			// Create an OAuth client
			const testClient = await serverClient.oauth2.register({
				client_name: "test-login-required-prompt-none",
				redirect_uris: [
					"http://localhost:3000/api/auth/oauth2/callback/login-required",
				],
			});
			const clientId = testClient.data?.client_id ?? "";
			const redirectUri = testClient.data?.redirect_uris?.[0] ?? "";

			// Try to authorize with prompt=none
			const authUrl = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl.searchParams.set("client_id", clientId);
			authUrl.searchParams.set("redirect_uri", redirectUri);
			authUrl.searchParams.set("response_type", "code");
			authUrl.searchParams.set("scope", "openid profile email");
			authUrl.searchParams.set("state", "test-state");
			authUrl.searchParams.set("prompt", "none");
			authUrl.searchParams.set("code_challenge", "test-challenge");
			authUrl.searchParams.set("code_challenge_method", "S256");

			const response = await customFetchImpl(authUrl.toString(), {
				method: "GET",
				redirect: "manual",
			});
			const redirectURI = response.headers.get("Location") || "";

			expect(redirectURI).toContain("error=login_required");
			expect(redirectURI).toContain("error_description=Authentication");
			expect(redirectURI).toContain("prompt");
			expect(redirectURI).toContain("none");
		});

		it("should not redirect to invalid redirect_uri when prompt=none", async ({
			expect,
		}) => {
			const attackerRedirect = "https://malicious.com/callback";
			const authUrl = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl.searchParams.set("client_id", application.clientId);
			authUrl.searchParams.set("redirect_uri", attackerRedirect);
			authUrl.searchParams.set("response_type", "code");
			authUrl.searchParams.set("scope", "openid");
			authUrl.searchParams.set("state", "x");
			authUrl.searchParams.set("prompt", "none");

			const response = await customFetchImpl(authUrl.toString(), {
				method: "GET",
				redirect: "manual",
			});

			const location = response.headers.get("Location") || "";
			expect(location === null || location === "").not.toContain(
				"malicious.com",
			);
			expect([400, 302]).toContain(response.status);
		});

		it("should return 400 invalid_request when prompt=none without redirect_uri", async ({
			expect,
		}) => {
			const authUrl = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl.searchParams.set("client_id", application.clientId);
			authUrl.searchParams.set("response_type", "code");
			authUrl.searchParams.set("scope", "openid");
			authUrl.searchParams.set("state", "x");
			authUrl.searchParams.set("prompt", "none");
			// No redirect_uri - must not fall through to login page

			const response = await customFetchImpl(authUrl.toString(), {
				method: "GET",
				redirect: "manual",
			});

			expect(response.status).toBe(400);
			const location = response.headers.get("Location") || "";
			expect(location).not.toContain("/login");
			const body = await response.json().catch(() => ({}));
			expect(body.error ?? body.code).toBe("invalid_request");
		});

		it("should return consent_required error when prompt=none and consent needed", async ({
			expect,
		}) => {
			// Create a new OAuth application that requires consent
			const newClient = await serverClient.oauth2.register({
				client_name: "test-consent-required",
				redirect_uris: ["http://localhost:3000/api/auth/oauth2/callback/test2"],
			});

			// Create a fresh user session that hasn't consented to this new client yet
			const { headers: freshHeaders } = await signInWithTestUser();

			// Try to authorize with prompt=none on the new client
			const authUrl = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl.searchParams.set("client_id", newClient.data?.client_id || "");
			authUrl.searchParams.set(
				"redirect_uri",
				newClient.data?.redirect_uris[0] || "",
			);
			authUrl.searchParams.set("response_type", "code");
			authUrl.searchParams.set("scope", "openid profile email");
			authUrl.searchParams.set("state", "test-state");
			authUrl.searchParams.set("prompt", "none");
			authUrl.searchParams.set("code_challenge", "test-challenge");
			authUrl.searchParams.set("code_challenge_method", "S256");

			let redirectURI = "";
			await customFetchImpl(authUrl.toString(), {
				method: "GET",
				headers: freshHeaders,
				redirect: "manual",
			}).then((res) => {
				redirectURI = res.headers.get("Location") || "";
			});

			expect(redirectURI).toContain("error=consent_required");
			expect(redirectURI).toContain("error_description=Consent");
			expect(redirectURI).toContain("prompt");
			expect(redirectURI).toContain("none");
		});

		it("should succeed with prompt=none when user authenticated and consented", async ({
			expect,
		}) => {
			// Create a new client for this test
			const testClient = await serverClient.oauth2.register({
				client_name: "test-prompt-none-success",
				redirect_uris: [
					"http://localhost:3000/api/auth/oauth2/callback/test-none",
				],
			});

			// First, establish consent by doing a normal authorization flow
			const authUrl1 = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl1.searchParams.set("client_id", testClient.data?.client_id || "");
			authUrl1.searchParams.set(
				"redirect_uri",
				testClient.data?.redirect_uris[0] || "",
			);
			authUrl1.searchParams.set("response_type", "code");
			authUrl1.searchParams.set("scope", "openid profile email");
			authUrl1.searchParams.set("state", "initial-state");
			authUrl1.searchParams.set("code_challenge", "test-challenge");
			authUrl1.searchParams.set("code_challenge_method", "S256");

			let consentRedirect = "";
			await serverClient.$fetch(authUrl1.toString(), {
				method: "GET",
				onError(context) {
					consentRedirect = context.response.headers.get("Location") || "";
				},
			});

			// If consent is required, accept it
			if (consentRedirect.includes("consent_code=")) {
				const consentUrl = new URL(consentRedirect, "http://localhost:3000");
				const consentCode = consentUrl.searchParams.get("consent_code");

				await serverClient.oauth2.consent(
					{ accept: true, consent_code: consentCode },
					{ throw: true },
				);
			}

			// Now test prompt=none - should succeed since consent is established
			const authUrl = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl.searchParams.set("client_id", testClient.data?.client_id || "");
			authUrl.searchParams.set(
				"redirect_uri",
				testClient.data?.redirect_uris[0] || "",
			);
			authUrl.searchParams.set("response_type", "code");
			authUrl.searchParams.set("scope", "openid profile email");
			authUrl.searchParams.set("state", "test-state");
			authUrl.searchParams.set("prompt", "none");
			authUrl.searchParams.set("code_challenge", "test-challenge");
			authUrl.searchParams.set("code_challenge_method", "S256");

			let redirectURI = "";
			await serverClient.$fetch(authUrl.toString(), {
				method: "GET",
				onError(context) {
					redirectURI = context.response.headers.get("Location") || "";
				},
			});

			// Should succeed with authorization code
			expect(redirectURI).toContain("code=");
			expect(redirectURI).toContain("state=test-state");
			expect(redirectURI).not.toContain("error=");
		});

		it("should handle prompt=login with consent requirement", async ({
			expect,
		}) => {
			// Create a new client that will require consent
			const loginConsentClient = await serverClient.oauth2.register({
				client_name: "test-login-consent",
				redirect_uris: [
					"http://localhost:3000/api/auth/oauth2/callback/login-consent",
				],
			});

			// User is already authenticated, but we force login with prompt=login
			const authUrl = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl.searchParams.set(
				"client_id",
				loginConsentClient.data?.client_id || "",
			);
			authUrl.searchParams.set(
				"redirect_uri",
				loginConsentClient.data?.redirect_uris[0] || "",
			);
			authUrl.searchParams.set("response_type", "code");
			authUrl.searchParams.set("scope", "openid profile email");
			authUrl.searchParams.set("state", "test-state");
			authUrl.searchParams.set("prompt", "login"); // Force login even though already authenticated
			authUrl.searchParams.set("code_challenge", "test-challenge");
			authUrl.searchParams.set("code_challenge_method", "S256");

			let redirectURI = "";
			const loginHeaders = new Headers();
			await serverClient.$fetch(authUrl.toString(), {
				method: "GET",
				onError(context) {
					redirectURI = context.response.headers.get("Location") || "";
					// Capture any cookies from the redirect
					const setCookie = context.response.headers.get("set-cookie");
					if (setCookie) {
						loginHeaders.set("Cookie", setCookie);
					}
				},
			});

			// Should redirect to login page
			expect(redirectURI).toContain("/login");
			expect(redirectURI).toContain("client_id");

			await serverClient.signIn.email(
				{
					email: testUser.email,
					password: testUser.password,
				},
				{
					headers: loginHeaders,
					onError(context) {
						redirectURI = context.response.headers.get("Location") || "";
						// Capture session cookies
						const setCookie = context.response.headers.get("set-cookie");
						if (setCookie) {
							const existing = loginHeaders.get("Cookie") || "";
							loginHeaders.set(
								"Cookie",
								existing ? `${existing}; ${setCookie}` : setCookie,
							);
						}
					},
				},
			);

			// After login with prompt=login removed, should proceed to consent
			// Should NOT still be redirecting to login
			expect(redirectURI).not.toContain("/login");
			// Should have consent_code (since this is a new client requiring consent)
			expect(redirectURI).toContain("consent_code=");

			// Extract consent code and accept consent
			const consentUrl = new URL(redirectURI, "http://localhost:3000");
			const consentCode = consentUrl.searchParams.get("consent_code");
			expect(consentCode).toBeTruthy();

			const consentResponse = await serverClient.oauth2.consent(
				{ accept: true, consent_code: consentCode },
				{ headers: loginHeaders, throw: true },
			);

			// After consent, should redirect to the client's redirect_uri with code
			expect(consentResponse.redirectURI).toContain(
				loginConsentClient.data?.redirect_uris[0] || "",
			);
			expect(consentResponse.redirectURI).toContain("code=");
			expect(consentResponse.redirectURI).toContain("state=test-state");
		});
	});

	describe("max_age parameter handling", () => {
		it("should force re-authentication when session age exceeds max_age", async ({
			expect,
		}) => {
			// This test verifies that max_age triggers re-authentication
			// In a real scenario, we'd need to manipulate session creation time
			// For now, we test with max_age=0 which should always trigger re-authentication

			const authUrl = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl.searchParams.set("client_id", application.clientId);
			authUrl.searchParams.set(
				"redirect_uri",
				application.redirectUrls[0] || "",
			);
			authUrl.searchParams.set("response_type", "code");
			authUrl.searchParams.set("scope", "openid profile email");
			authUrl.searchParams.set("state", "test-state");
			authUrl.searchParams.set("max_age", "0"); // Force immediate re-authentication
			authUrl.searchParams.set("code_challenge", "test-challenge");
			authUrl.searchParams.set("code_challenge_method", "S256");

			let redirectURI = "";
			await serverClient.$fetch(authUrl.toString(), {
				method: "GET",
				onError(context) {
					redirectURI = context.response.headers.get("Location") || "";
				},
			});

			// Should redirect to login page (same behavior as prompt=login)
			expect(redirectURI).toContain("/login");
			expect(redirectURI).toContain("client_id=" + application.clientId);
		});

		it("should not force re-authentication when session age is within max_age", async ({
			expect,
		}) => {
			const authUrl = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl.searchParams.set("client_id", application.clientId);
			authUrl.searchParams.set(
				"redirect_uri",
				application.redirectUrls[0] || "",
			);
			authUrl.searchParams.set("response_type", "code");
			authUrl.searchParams.set("scope", "openid profile email");
			authUrl.searchParams.set("state", "test-state");
			authUrl.searchParams.set("max_age", "3600"); // 1 hour - should be valid
			authUrl.searchParams.set("code_challenge", "test-challenge");
			authUrl.searchParams.set("code_challenge_method", "S256");

			let redirectURI = "";
			await serverClient.$fetch(authUrl.toString(), {
				method: "GET",
				onError(context) {
					redirectURI = context.response.headers.get("Location") || "";
				},
			});

			// Should either succeed with code or redirect to consent (but NOT to login)
			expect(redirectURI).not.toContain("/login");
			// It should either have a code or consent_code
			expect(
				redirectURI.includes("code=") || redirectURI.includes("consent_code="),
			).toBe(true);
		});
	});

	/**
	 * @see https://github.com/clearance-auth/clearance
	 */
	describe("cookie persistence bug (issue #4594)", () => {
		// Reproduce issue #4594: oidc_login_prompt cookie persists after OIDC flow
		// and causes subsequent normal logins to redirect to OIDC client
		it("should not redirect to OIDC client on subsequent normal logins", async ({
			expect,
		}) => {
			// Step 1: Create a new OAuth client for this test
			const testClient = await serverClient.oauth2.register({
				client_name: "test-cookie-persistence",
				redirect_uris: [
					"http://localhost:3000/api/auth/oauth2/callback/test-persist",
				],
			});

			// Step 2: Logout to start fresh
			await serverClient.signOut({
				fetchOptions: {
					throw: false,
				},
			});

			// Step 3: Initiate OIDC authorization flow (which will set oidc_login_prompt cookie)
			const authUrl = new URL(
				"http://localhost:3000/api/auth/oauth2/authorize",
			);
			authUrl.searchParams.set("client_id", testClient.data?.client_id || "");
			authUrl.searchParams.set(
				"redirect_uri",
				testClient.data?.redirect_uris[0] || "",
			);
			authUrl.searchParams.set("response_type", "code");
			authUrl.searchParams.set("scope", "openid profile email");
			authUrl.searchParams.set("state", "test-state");
			authUrl.searchParams.set("code_challenge", "test-challenge");
			authUrl.searchParams.set("code_challenge_method", "S256");

			const oidcHeaders = new Headers();
			let redirectURI = "";

			await customFetchImpl(authUrl.toString(), {
				method: "GET",
				redirect: "manual",
			}).then((res) => {
				redirectURI = res.headers.get("Location") || "";
				// Capture the oidc_login_prompt cookie
				const setCookie = res.headers.get("set-cookie");
				if (setCookie) {
					oidcHeaders.set("Cookie", setCookie);
				}
			});

			// Should redirect to login and set oidc_login_prompt cookie
			expect(redirectURI).toContain("/login");
			expect(oidcHeaders.get("Cookie")).toContain("oidc_login_prompt");

			// Step 4: Complete the OIDC login flow
			await customFetchImpl("http://localhost:3000/api/auth/sign-in/email", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Cookie: oidcHeaders.get("Cookie") || "",
				},
				body: JSON.stringify({
					email: testUser.email,
					password: testUser.password,
				}),
				redirect: "manual",
			}).then((res) => {
				redirectURI = res.headers.get("Location") || "";
				// Update cookies with session
				const setCookie = res.headers.get("set-cookie");
				if (setCookie) {
					const existing = oidcHeaders.get("Cookie") || "";
					oidcHeaders.set(
						"Cookie",
						existing ? `${existing}; ${setCookie}` : setCookie,
					);
				}
			});

			// Should redirect to consent or client callback (OIDC flow continues)
			expect(redirectURI).not.toContain("/login");

			// Step 5: Now do a NORMAL login to the main app (NOT OIDC flow)
			// This simulates a user later logging into the main app directly
			// The bug was that oidc_login_prompt cookie would still be present
			// and cause a redirect to the OIDC client
			const normalLoginHeaders = new Headers();
			let normalLoginRedirect = "";

			await customFetchImpl("http://localhost:3000/api/auth/sign-in/email", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					email: testUser.email,
					password: testUser.password,
				}),
				redirect: "manual",
			}).then((res) => {
				normalLoginRedirect = res.headers.get("Location") || "";
				const setCookie = res.headers.get("set-cookie");
				if (setCookie) {
					normalLoginHeaders.set("Cookie", setCookie);
				}
			});

			expect(normalLoginRedirect).not.toContain("oauth2/callback");
			expect(normalLoginRedirect).not.toContain(
				testClient.data?.redirect_uris[0] || "",
			);
		});
	});

	describe("end session endpoint", () => {
		it("should return end_session_endpoint in metadata", async ({ expect }) => {
			const response: any = await serverClient.$fetch(
				"/.well-known/openid-configuration",
				{
					method: "GET",
				},
			);
			const metadata = response.data || response;
			expect(metadata.end_session_endpoint).toBe(
				"http://localhost:3000/api/auth/oauth2/endsession",
			);
		});

		it("should logout successfully without parameters", async ({ expect }) => {
			const response = await serverClient.$fetch("/oauth2/endsession", {
				method: "GET",
				headers: { "Sec-Fetch-Site": "same-origin" },
			});
			expect(response.data).toMatchObject({
				success: true,
				message: "Logout successful",
			});
		});

		it("should logout with post_logout_redirect_uri and state", async ({
			expect,
		}) => {
			let redirectLocation = "";
			await serverClient.$fetch(
				`/oauth2/endsession?client_id=${application.clientId}&post_logout_redirect_uri=${encodeURIComponent(application.redirectUrls[0]!)}&state=test-state`,
				{
					method: "GET",
					headers: { "Sec-Fetch-Site": "same-origin" },
					onError(context) {
						redirectLocation = context.response.headers.get("Location") || "";
					},
				},
			);
			expect(redirectLocation).toContain(application.redirectUrls[0]);
			expect(redirectLocation).toContain("state=test-state");
		});

		it("should fail with invalid client_id", async ({ expect }) => {
			const response = await serverClient.$fetch(
				"/oauth2/endsession?client_id=invalid-client",
				{
					method: "GET",
				},
			);
			expect(response.error).toMatchObject({
				error: "invalid_client",
				error_description: "Invalid client_id",
			});
		});

		it("should fail with post_logout_redirect_uri without client_id", async ({
			expect,
		}) => {
			const response = await serverClient.$fetch(
				`/oauth2/endsession?post_logout_redirect_uri=${encodeURIComponent("http://localhost:3000/callback")}`,
				{
					method: "GET",
				},
			);
			expect(response.error).toMatchObject({
				error: "invalid_request",
				error_description: expect.stringContaining("client_id is required"),
			});
		});

		it("should fail with unregistered post_logout_redirect_uri", async ({
			expect,
		}) => {
			const response = await serverClient.$fetch(
				`/oauth2/endsession?client_id=${application.clientId}&post_logout_redirect_uri=${encodeURIComponent("http://evil.com/callback")}`,
				{
					method: "GET",
				},
			);
			expect(response.error).toMatchObject({
				error: "invalid_request",
				error_description: expect.stringContaining("not registered"),
			});
		});

		it("should support POST method", async ({ expect }) => {
			const response = await serverClient.$fetch("/oauth2/endsession", {
				method: "POST",
				headers: { "Sec-Fetch-Site": "same-origin" },
			});
			expect(response.data).toMatchObject({
				success: true,
				message: "Logout successful",
			});
		});
	});
});

describe("oidc storage", async () => {
	let server: Listener;

	afterEach(async () => {
		if (server) {
			await server.close();
		}
	});

	test.for([
		{
			storeClientSecret: undefined,
		},
		{
			storeClientSecret: "hashed",
		},
		{
			storeClientSecret: "encrypted",
		},
	] as const)("OIDC base test", async ({ storeClientSecret }) => {
		const {
			auth: authorizationServer,
			signInWithTestUser,
			customFetchImpl,
			db,
		} = await getTestInstance({
			baseURL: "http://localhost:3000",
			plugins: [
				oidcProvider({
					loginPage: "/login",
					consentPage: "/oauth2/authorize",
					requirePKCE: true,
					getAdditionalUserInfoClaim(user) {
						return {
							custom: "custom value",
							userId: user.id,
						};
					},
					storeClientSecret,
				}),
				jwt(),
			],
		});
		const { headers } = await signInWithTestUser();
		const serverClient = createAuthClient({
			plugins: [oidcClient()],
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
				headers,
			},
		});

		server = await listen(toNodeHandler(authorizationServer.handler), {
			port: 3000,
		});

		let application: Client = {
			clientId: "test-client-id",
			clientSecret: "test-client-secret-oidc",
			redirectUrls: ["http://localhost:3000/api/auth/oauth2/callback/test"],
			metadata: {},
			icon: "",
			type: "web",
			disabled: false,
			name: "test",
		};
		const createdClient = await serverClient.oauth2.register({
			client_name: application.name,
			redirect_uris: application.redirectUrls,
			logo_uri: application.icon,
		});
		expect(createdClient.data).toMatchObject({
			client_id: expect.any(String),
			client_secret: expect.any(String),
			client_name: "test",
			logo_uri: "",
			redirect_uris: ["http://localhost:3000/api/auth/oauth2/callback/test"],
			grant_types: ["authorization_code"],
			response_types: ["code"],
			token_endpoint_auth_method: "client_secret_basic",
			client_id_issued_at: expect.any(Number),
			client_secret_expires_at: 0,
		});
		if (createdClient.data) {
			application = {
				clientId: createdClient.data.client_id,
				clientSecret: createdClient.data.client_secret,
				redirectUrls: createdClient.data.redirect_uris,
				metadata: {},
				icon: createdClient.data.logo_uri || "",
				type: "web",
				disabled: false,
				name: createdClient.data.client_name || "",
			};
		}
		// The RP (Relying Party) - the client application
		const { customFetchImpl: customFetchImplRP, cookieSetter } =
			await getTestInstance({
				account: {
					accountLinking: {
						trustedProviders: ["test"],
					},
				},
				databaseHooks: autoVerifyUserHook,
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "test",
								clientId: application.clientId,
								clientSecret: application.clientSecret || "",
								authorizationUrl:
									"http://localhost:3000/api/auth/oauth2/authorize",
								tokenUrl: "http://localhost:3000/api/auth/oauth2/token",
								scopes: ["openid", "profile", "email"],
								pkce: true,
							},
						],
					}),
				],
			});

		const client = createAuthClient({
			plugins: [genericOAuthClient()],
			baseURL: "http://localhost:5000",
			fetchOptions: {
				customFetchImpl: customFetchImplRP,
			},
		});
		const oAuthHeaders = new Headers();
		const data = await client.signIn.oauth2(
			{
				providerId: "test",
				callbackURL: "/dashboard",
			},
			{
				throw: true,
				onSuccess: cookieSetter(oAuthHeaders),
			},
		);
		expect(data.url).toContain(
			"http://localhost:3000/api/auth/oauth2/authorize",
		);
		expect(data.url).toContain(`client_id=${application.clientId}`);

		let redirectURI = "";
		const newHeaders = new Headers();
		await serverClient.$fetch(data.url, {
			method: "GET",
			onError(context) {
				redirectURI = context.response.headers.get("Location") || "";
				cookieSetter(newHeaders)(context);
				// Note: headers might be available from parent scope (serverClient auth)
				// newHeaders already has the consent cookies
			},
		});

		// Handle consent flow if required (per OIDC spec for non-trusted clients)
		redirectURI = await handleConsentFlow(
			redirectURI,
			serverClient,
			headers,
			newHeaders,
		);

		// Verify we got an authorization code
		expect(redirectURI).toContain(
			"http://localhost:3000/api/auth/oauth2/callback/test?code=",
		);

		let callbackURL = "";
		await client.$fetch(redirectURI, {
			headers: oAuthHeaders,
			onError(context) {
				callbackURL = context.response.headers.get("Location") || "";
			},
		});
		expect(callbackURL).toContain("/dashboard");
	});
});

describe("oidc token response format", async () => {
	async function setupOAuthFlowAndGetCode(
		scopes: string[],
		databaseHooks?: any,
	) {
		const {
			auth: authorizationServer,
			signInWithTestUser,
			customFetchImpl,
			db,
		} = await getTestInstance({
			baseURL: "http://localhost:3000",
			databaseHooks,
			plugins: [
				admin(),
				oidcProvider({
					loginPage: "/login",
					consentPage: "/oauth2/authorize",
					requirePKCE: false,
				}),
				jwt(),
			],
		});
		const { headers } = await signInWithTestUser();
		const serverClient = createAuthClient({
			plugins: [oidcClient()],
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
				headers,
			},
		});

		const server = await listen(toNodeHandler(authorizationServer.handler), {
			port: 3000,
		});

		const createdClient = await serverClient.oauth2.register({
			client_name: "test-app",
			redirect_uris: ["http://localhost:3000/api/auth/oauth2/callback/test"],
			logo_uri: "",
		});

		const application = {
			clientId: createdClient.data!.client_id,
			clientSecret: createdClient.data!.client_secret,
		};

		const { customFetchImpl: customFetchImplRP, cookieSetter } =
			await getTestInstance({
				databaseHooks: autoVerifyUserHook,
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "test",
								clientId: application.clientId,
								clientSecret: application.clientSecret,
								authorizationUrl:
									"http://localhost:3000/api/auth/oauth2/authorize",
								tokenUrl: "http://localhost:3000/api/auth/oauth2/token",
								scopes,
								pkce: false,
							},
						],
					}),
				],
			});

		const client = createAuthClient({
			plugins: [genericOAuthClient()],
			baseURL: "http://localhost:5000",
			fetchOptions: {
				customFetchImpl: customFetchImplRP,
			},
		});
		const oAuthHeaders = new Headers();
		const data = await client.signIn.oauth2(
			{
				providerId: "test",
				callbackURL: "/dashboard",
			},
			{
				throw: true,
				onSuccess: cookieSetter(oAuthHeaders),
			},
		);

		let redirectURI = "";
		const consentHeaders = new Headers();
		await serverClient.$fetch(data.url, {
			method: "GET",
			onError(context) {
				redirectURI = context.response.headers.get("Location") || "";
				cookieSetter(consentHeaders)(context);
			},
		});

		redirectURI = await handleConsentFlow(
			redirectURI,
			serverClient,
			headers,
			consentHeaders,
		);

		const url = new URL(redirectURI);
		const code = url.searchParams.get("code")!;

		return {
			server,
			customFetchImpl,
			application,
			code,
			db,
		};
	}

	it("should return Bearer token_type in authorization_code token response", async ({
		expect,
	}) => {
		const { server, customFetchImpl, application, code, db } =
			await setupOAuthFlowAndGetCode(["openid", "profile", "email"]);

		const tokenResponse = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					grant_type: "authorization_code",
					code,
					redirect_uri: "http://localhost:3000/api/auth/oauth2/callback/test",
					client_id: application.clientId,
					client_secret: application.clientSecret,
				}),
			},
		);

		const tokenData = await tokenResponse.json();

		expect(tokenResponse.headers.get("cache-control")).toBe("no-store");
		expect(tokenResponse.headers.get("pragma")).toBe("no-cache");
		expect(tokenData.token_type).toBe("Bearer");
		expect(tokenData.access_token).toBeDefined();
		expect(tokenData.expires_in).toBe(300);
		expect(tokenData.id_token).toBeDefined();
		expect(tokenData.scope).toBeDefined();
		expect(tokenData.refresh_token).toBeUndefined();

		const rows = await db.findMany<Record<string, any>>({
			model: "oauthAccessToken",
		});
		expect(rows).toHaveLength(1);
		expect(rows[0]?.accessToken).toMatch(/^clr_oauth_ref_access_/);
		expect(rows[0]?.refreshToken).toMatch(/^clr_oauth_ref_refresh_/);
		expect(rows[0]?.accessTokenDigest).toMatch(/^v1:/);
		expect(rows[0]?.refreshTokenDigest).toBeNull();
		expect(rows[0]?.refreshStatus).toBe("none");
		expect(
			rows[0]?.accessTokenExpiresAt.getTime() - Date.now(),
		).toBeLessThanOrEqual(300_000);

		await server.close();
	});

	it("rejects a banned user on OIDC userinfo and refresh while revoking the family", async () => {
		const { server, customFetchImpl, application, code, db } =
			await setupOAuthFlowAndGetCode([
				"openid",
				"profile",
				"email",
				"offline_access",
			]);
		try {
			const issuedResponse = await customFetchImpl(
				"http://localhost:3000/api/auth/oauth2/token",
				{
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({
						grant_type: "authorization_code",
						code,
						redirect_uri:
							"http://localhost:3000/api/auth/oauth2/callback/test",
						client_id: application.clientId,
						client_secret: application.clientSecret,
					}),
				},
			);
			expect(issuedResponse.status).toBe(200);
			const issued = await issuedResponse.json();
			const [row] = await db.findMany<Record<string, any>>({
				model: "oauthAccessToken",
			});
			await db.update({
				model: "user",
				where: [{ field: "id", value: row!.userId }],
				update: {
					banned: true,
					banReason: "disabled",
					updatedAt: new Date(),
				},
			});

			const userInfo = await customFetchImpl(
				"http://localhost:3000/api/auth/oauth2/userinfo",
				{
					headers: { authorization: `Bearer ${issued.access_token}` },
				},
			);
			expect(userInfo.status).toBe(401);
			const refresh = await customFetchImpl(
				"http://localhost:3000/api/auth/oauth2/token",
				{
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({
						grant_type: "refresh_token",
						refresh_token: issued.refresh_token,
						client_id: application.clientId,
						client_secret: application.clientSecret,
					}),
				},
			);
			expect(refresh.status).toBe(401);
			expect(await refresh.json()).toMatchObject({ error: "invalid_grant" });
			const revoked = await db.findOne<Record<string, any>>({
				model: "oauthAccessToken",
				where: [{ field: "id", value: row!.id }],
			});
			expect(revoked).toMatchObject({
				refreshStatus: "revoked",
				revokedAt: expect.any(Date),
			});
		} finally {
			await server.close();
		}
	});

	it("rejects an existing access token after its OIDC client is disabled", async () => {
		const { server, customFetchImpl, application, code, db } =
			await setupOAuthFlowAndGetCode(["openid", "profile", "email"]);
		try {
			const issuedResponse = await customFetchImpl(
				"http://localhost:3000/api/auth/oauth2/token",
				{
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({
						grant_type: "authorization_code",
						code,
						redirect_uri:
							"http://localhost:3000/api/auth/oauth2/callback/test",
						client_id: application.clientId,
						client_secret: application.clientSecret,
					}),
				},
			);
			expect(issuedResponse.status).toBe(200);
			const issued = await issuedResponse.json();
			await db.update<{ disabled: boolean }>({
				model: "oauthApplication",
				where: [{ field: "clientId", value: application.clientId }],
				update: { disabled: true },
			});

			const userInfo = await customFetchImpl(
				"http://localhost:3000/api/auth/oauth2/userinfo",
				{
					headers: { authorization: `Bearer ${issued.access_token}` },
				},
			);
			expect(userInfo.status).toBe(401);
			expect(await userInfo.json()).toMatchObject({ error: "invalid_token" });
		} finally {
			await server.close();
		}
	});

	it("returns a committed token response when a public delete.after hook fails", async () => {
		const { server, customFetchImpl, application, code, db } =
			await setupOAuthFlowAndGetCode(["openid", "profile"], {
				verification: {
					delete: {
						after: async () => {
							throw new Error("observer delivery failed");
						},
					},
				},
			});
		const exchange = () =>
			customFetchImpl("http://localhost:3000/api/auth/oauth2/token", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "authorization_code",
					code,
					redirect_uri: "http://localhost:3000/api/auth/oauth2/callback/test",
					client_id: application.clientId,
					client_secret: application.clientSecret,
				}),
			});

		try {
			const first = await exchange();
			expect(first.status).toBe(200);
			expect(await first.json()).toMatchObject({
				token_type: "Bearer",
				access_token: expect.any(String),
			});
			expect(await db.findMany({ model: "oauthAccessToken" })).toHaveLength(1);

			const replay = await exchange();
			expect(replay.status).toBe(401);
			expect(await replay.json()).toMatchObject({ error: "invalid_grant" });
		} finally {
			await server.close();
		}
	});

	it("should return Bearer token_type in refresh_token grant response", async ({
		expect,
	}) => {
		const { server, customFetchImpl, application, code, db } =
			await setupOAuthFlowAndGetCode([
				"openid",
				"profile",
				"email",
				"offline_access",
			]);

		const initialTokenResponse = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					grant_type: "authorization_code",
					code,
					redirect_uri: "http://localhost:3000/api/auth/oauth2/callback/test",
					client_id: application.clientId,
					client_secret: application.clientSecret,
				}),
			},
		);

		const initialTokenData = await initialTokenResponse.json();
		expect(initialTokenResponse.headers.get("cache-control")).toBe("no-store");
		expect(initialTokenResponse.headers.get("pragma")).toBe("no-cache");
		expect(initialTokenData.refresh_token).toBeDefined();
		expect(initialTokenData.token_type).toBe("Bearer");
		const [parentBeforeRotation] = await db.findMany<Record<string, any>>({
			model: "oauthAccessToken",
		});
		expect(parentBeforeRotation?.accessToken).toMatch(/^clr_oauth_ref_access_/);
		expect(parentBeforeRotation?.refreshToken).toMatch(
			/^clr_oauth_ref_refresh_/,
		);
		expect(parentBeforeRotation?.accessTokenDigest).toMatch(/^v1:/);
		expect(parentBeforeRotation?.refreshTokenDigest).toMatch(/^v1:/);

		const refreshTokenResponse = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					grant_type: "refresh_token",
					refresh_token: initialTokenData.refresh_token,
					client_id: application.clientId,
					client_secret: application.clientSecret,
				}),
			},
		);

		const refreshTokenData = await refreshTokenResponse.json();

		expect(refreshTokenResponse.headers.get("cache-control")).toBe("no-store");
		expect(refreshTokenResponse.headers.get("pragma")).toBe("no-cache");
		expect(refreshTokenData.token_type).toBe("Bearer");
		expect(refreshTokenData.access_token).toBeDefined();
		expect(refreshTokenData.expires_in).toBeDefined();
		expect(refreshTokenData.refresh_token).toBeDefined();
		expect(refreshTokenData.scope).toBeDefined();
		expect(refreshTokenData.refresh_token).not.toBe(
			initialTokenData.refresh_token,
		);

		const rowsAfterRotation = await db.findMany<Record<string, any>>({
			model: "oauthAccessToken",
			sortBy: { field: "rotationCounter", direction: "asc" },
		});
		expect(rowsAfterRotation).toHaveLength(2);
		const [parent, successor] = rowsAfterRotation;
		expect(parent?.refreshStatus).toBe("consumed");
		expect(successor?.refreshStatus).toBe("active");
		expect(successor?.familyId).toBe(parent?.familyId);
		expect(successor?.parentTokenId).toBe(parent?.id);
		expect(successor?.rotationCounter).toBe(1);
		expect(successor?.refreshTokenExpiresAt).toEqual(
			parent?.refreshTokenExpiresAt,
		);
		expect(successor?.accessToken).toMatch(/^clr_oauth_ref_access_/);
		expect(successor?.refreshToken).toMatch(/^clr_oauth_ref_refresh_/);

		const replayResponse = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "refresh_token",
					refresh_token: initialTokenData.refresh_token,
					client_id: application.clientId,
					client_secret: application.clientSecret,
				}),
			},
		);
		expect(replayResponse.status).toBe(401);
		expect((await replayResponse.json()).error).toBe("invalid_grant");

		const successorAfterReplay = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "refresh_token",
					refresh_token: refreshTokenData.refresh_token,
					client_id: application.clientId,
					client_secret: application.clientSecret,
				}),
			},
		);
		expect(successorAfterReplay.status).toBe(401);

		const userInfoAfterReplay = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/userinfo",
			{
				headers: {
					authorization: `Bearer ${refreshTokenData.access_token}`,
				},
			},
		);
		expect(userInfoAfterReplay.status).toBe(401);
		const revokedRows = await db.findMany<Record<string, any>>({
			model: "oauthAccessToken",
		});
		expect(revokedRows.every((row) => row.refreshStatus === "revoked")).toBe(
			true,
		);

		await server.close();
	});

	it("recovers the exact OAuth refresh successor without persisting a reversible retry secret", async () => {
		const { server, customFetchImpl, application, code, db } =
			await setupOAuthFlowAndGetCode([
				"openid",
				"profile",
				"email",
				"offline_access",
			]);
		const tokenUrl = "http://localhost:3000/api/auth/oauth2/token";
		const initialResponse = await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				grant_type: "authorization_code",
				code,
				redirect_uri: "http://localhost:3000/api/auth/oauth2/callback/test",
				client_id: application.clientId,
				client_secret: application.clientSecret,
			}),
		});
		const initial = await initialResponse.json();
		const idempotencyKey = generateCredentialOperationKey();
		const rotate = (operationKey: string) =>
			customFetchImpl(tokenUrl, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"Idempotency-Key": operationKey,
				},
				body: JSON.stringify({
					grant_type: "refresh_token",
					refresh_token: initial.refresh_token,
					client_id: application.clientId,
					client_secret: application.clientSecret,
				}),
			});

		try {
			const predictable = await rotate("a".repeat(22));
			expect(predictable.status).toBe(400);
			expect(await predictable.json()).toMatchObject({
				error: "invalid_request",
			});

			const responses = await Promise.all(
				Array.from({ length: 16 }, () => rotate(idempotencyKey)),
			);
			for (const response of responses) {
				expect(response.status).toBe(200);
				expect(response.headers.get("cache-control")).toBe("no-store");
				expect(response.headers.get("pragma")).toBe("no-cache");
			}
			const successors = await Promise.all(
				responses.map((response) => response.json()),
			);
			const first = successors[0]!;
			expect(new Set(successors.map((value) => value.access_token))).toEqual(
				new Set([first.access_token]),
			);
			expect(new Set(successors.map((value) => value.refresh_token))).toEqual(
				new Set([first.refresh_token]),
			);

			const rowsBeforeReuse = await db.findMany<Record<string, any>>({
				model: "oauthAccessToken",
				sortBy: { field: "rotationCounter", direction: "asc" },
			});
			expect(rowsBeforeReuse).toHaveLength(2);
			const [parent, successor] = rowsBeforeReuse;
			expect(parent?.refreshStatus).toBe("consumed");
			expect(parent?.rotationNonceDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
			expect(parent?.recoveryExpiresAt).toBeInstanceOf(Date);
			expect(successor?.refreshStatus).toBe("active");
			const persisted = JSON.stringify(rowsBeforeReuse);
			expect(persisted).not.toContain(idempotencyKey);
			expect(persisted).not.toContain(first.access_token);
			expect(persisted).not.toContain(first.refresh_token);
			expect(parent).not.toHaveProperty("recoverySecretCiphertext");

			const reuseResponse = await rotate(generateCredentialOperationKey());
			expect(reuseResponse.status).toBe(401);
			expect(await reuseResponse.json()).toMatchObject({
				error: "invalid_grant",
			});
			const revokedRows = await db.findMany<Record<string, any>>({
				model: "oauthAccessToken",
			});
			expect(revokedRows).toHaveLength(2);
			expect(
				revokedRows.every((row) => row.refreshStatus === "revoked"),
			).toBe(true);
			expect(
				revokedRows.every(
					(row) =>
						row.rotationNonceDigest === null &&
						row.recoveryExpiresAt === null,
				),
			).toBe(true);
		} finally {
			await server.close();
		}
	});

	it("rejects legacy OAuth bearer writes after storage is sealed", async () => {
		const { server, application, db } =
			await setupOAuthFlowAndGetCode(["openid"]);
		const [user] = await db.findMany<{ id: string }>({
			model: "user",
			limit: 1,
		});
		const now = new Date();
		const legacyRefresh = "legacy-refresh-without-offline-access";
		await expect(
			db.create({
				model: "oauthAccessToken",
				forceAllowId: true,
				data: {
				id: "legacy-online-only-token",
				accessToken: null,
				refreshToken: legacyRefresh,
				accessTokenDigest: null,
				refreshTokenDigest: null,
				digestVersion: null,
				familyId: null,
				refreshStatus: null,
				rotationCounter: null,
				parentTokenId: null,
				consumedAt: null,
				revokedAt: null,
				reuseDetectedAt: null,
				accessTokenExpiresAt: new Date(now.getTime() + 300_000),
				refreshTokenExpiresAt: new Date(now.getTime() + 3_600_000),
				clientId: application.clientId,
				userId: user!.id,
				scopes: "openid",
				createdAt: now,
				updatedAt: now,
				},
			}),
		).rejects.toThrow(
			"Clearance credential authority rejects replayable bearer storage",
		);
		await server.close();
	});

	it("revokes the family when the same refresh token races", async () => {
		const { server, customFetchImpl, application, code, db } =
			await setupOAuthFlowAndGetCode([
				"openid",
				"profile",
				"email",
				"offline_access",
			]);
		const tokenUrl = "http://localhost:3000/api/auth/oauth2/token";
		const initialResponse = await customFetchImpl(tokenUrl, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				grant_type: "authorization_code",
				code,
				redirect_uri: "http://localhost:3000/api/auth/oauth2/callback/test",
				client_id: application.clientId,
				client_secret: application.clientSecret,
			}),
		});
		const initial = await initialResponse.json();
		const rotate = () =>
			customFetchImpl(tokenUrl, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "refresh_token",
					refresh_token: initial.refresh_token,
					client_id: application.clientId,
					client_secret: application.clientSecret,
				}),
			});
		const responses = await Promise.all([rotate(), rotate()]);
		expect(responses.map((response) => response.status).sort()).toEqual([
			200, 401,
		]);
		const rows = await db.findMany<Record<string, any>>({
			model: "oauthAccessToken",
		});
		expect(rows).toHaveLength(2);
		expect(rows.every((row) => row.refreshStatus === "revoked")).toBe(true);

		await server.close();
	});

	/**
	 * Concurrent redemption of the same authorization code must mint tokens
	 * for exactly one caller. Reverting `consumeVerificationValue` back to a
	 * `findVerificationValue` + `deleteVerificationByIdentifier` pair makes
	 * this test fail with two successes.
	 *
	 * @see https://github.com/clearance-auth/clearance
	 */
	it("rejects concurrent redemption of the same authorization code", async () => {
		const { server, customFetchImpl, application, code } =
			await setupOAuthFlowAndGetCode(["openid", "profile", "email"]);

		const exchange = () =>
			customFetchImpl("http://localhost:3000/api/auth/oauth2/token", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "authorization_code",
					code,
					redirect_uri: "http://localhost:3000/api/auth/oauth2/callback/test",
					client_id: application.clientId,
					client_secret: application.clientSecret,
				}),
			});

		const [first, second] = await Promise.all([exchange(), exchange()]);
		const firstBody = (await first.json()) as {
			access_token?: string;
			error?: string;
		};
		const secondBody = (await second.json()) as {
			access_token?: string;
			error?: string;
		};

		const successes = [firstBody, secondBody].filter(
			(b) => b.access_token != null,
		);
		const failures = [firstBody, secondBody].filter((b) => b.error != null);
		expect(successes).toHaveLength(1);
		expect(failures).toHaveLength(1);
		expect(failures[0]?.error).toBe("invalid_grant");

		await server.close();
	});
});

describe("oidc-jwt", async () => {
	let server: Listener | null = null;

	afterEach(async () => {
		if (server) {
			await server.close();
			server = null;
		}
	});

	test.for([
		{ useJwt: true, description: "with jwt plugin", expected: "EdDSA" },
		{ useJwt: false, description: "without jwt plugin", expected: "HS256" },
	])(
		"testing oidc-provider $description to return token signed with $expected",
		async ({ useJwt, expected }) => {
		const {
			auth: authorizationServer,
			signInWithTestUser,
			customFetchImpl,
			testUser,
			db,
		} = await getTestInstance({
			baseURL: "http://localhost:3000",
			plugins: [
					oidcProvider({
						loginPage: "/login",
						consentPage: "/oauth2/authorize",
						requirePKCE: true,
						metadata: { issuer: "https://issuer.clearance.test" },
						getAdditionalUserInfoClaim(user) {
							return {
								custom: "custom value",
								userId: user.id,
								iss: "https://attacker.example.test",
								sub: "attacker-controlled-sub",
								aud: "attacker-controlled-audience",
								sid: "attacker-controlled-family",
								exp: 1,
								nbf: 4_102_444_800,
								iat: 1,
								jti: "attacker-controlled-token-id",
								auth_time: 4_102_444_800,
								nonce: "attacker-controlled-nonce",
								acr: "attacker-controlled-acr",
								amr: ["attacker-controlled-amr"],
								azp: "attacker-controlled-authorized-party",
								at_hash: "attacker-controlled-access-token-hash",
								c_hash: "attacker-controlled-code-hash",
								s_hash: "attacker-controlled-state-hash",
								cnf: { jkt: "attacker-controlled-confirmation" },
								act: { sub: "attacker-controlled-actor" },
								may_act: { sub: "attacker-controlled-future-actor" },
								name: "Attacker Controlled Name",
								given_name: "Attacker",
								family_name: "Controlled",
								profile: "https://attacker.example.test/profile",
								picture: "https://attacker.example.test/picture",
								email: "attacker@example.test",
								email_verified: "attacker-controlled-email-verification",
								updated_at: "attacker-controlled-update",
								middle_name: "attacker-controlled-middle-name",
								nickname: "attacker-controlled-nickname",
								preferred_username: "attacker-controlled-username",
								website: "https://attacker.example.test",
								gender: "attacker-controlled-gender",
								birthdate: "1970-01-01",
								zoneinfo: "attacker-controlled-zone",
								locale: "attacker-controlled-locale",
								phone_number: "+15555550100",
								phone_number_verified: true,
								address: { formatted: "attacker-controlled-address" },
								_claim_names: { email: "attacker-source" },
								_claim_sources: { "attacker-source": {} },
								client_id: "attacker-controlled-client",
								scope: "attacker-controlled-scope",
								authorization_details: [{ type: "attacker-controlled" }],
								token_type: "attacker-controlled-token-type",
								token_use: "attacker-controlled-token-use",
								username: "attacker-controlled-username",
								groups: ["attacker-controlled-group"],
								roles: ["attacker-controlled-role"],
								entitlements: ["attacker-controlled-entitlement"],
								events: { "attacker-controlled-event": {} },
								toe: 1,
								txn: "attacker-controlled-transaction",
								htm: "DELETE",
								htu: "https://attacker.example.test/resource",
								ath: "attacker-controlled-access-token-hash",
								jkt: "attacker-controlled-key-thumbprint",
							};
						},
						useJWTPlugin: useJwt,
					}),
				...(useJwt ? [jwt()] : []),
			],
		});
		const { headers } = await signInWithTestUser();
		const serverClient = createAuthClient({
			plugins: [oidcClient()],
			baseURL: "http://localhost:3000",
			fetchOptions: {
				customFetchImpl,
				headers,
			},
		});
		server = await listen(toNodeHandler(authorizationServer.handler), {
			port: 3000,
		});
		let application: Client = {
			clientId: "test-client-id",
			clientSecret: "test-client-secret-oidc",
			redirectUrls: ["http://localhost:3000/api/auth/oauth2/callback/test"],
			metadata: {},
			icon: "",
			type: "web",
			disabled: false,
			name: "test",
		};
		const createdClient = await serverClient.oauth2.register({
			client_name: application.name,
			redirect_uris: application.redirectUrls,
			logo_uri: application.icon,
		});
		expect(createdClient.data).toMatchObject({
			client_id: expect.any(String),
			client_secret: expect.any(String),
			client_name: "test",
			logo_uri: "",
			redirect_uris: ["http://localhost:3000/api/auth/oauth2/callback/test"],
			grant_types: ["authorization_code"],
			response_types: ["code"],
			token_endpoint_auth_method: "client_secret_basic",
			client_id_issued_at: expect.any(Number),
			client_secret_expires_at: 0,
		});
		if (createdClient.data) {
			application = {
				clientId: createdClient.data.client_id,
				clientSecret: createdClient.data.client_secret,
				redirectUrls: createdClient.data.redirect_uris,
				metadata: {},
				icon: createdClient.data.logo_uri || "",
				type: "web",
				disabled: false,
				name: createdClient.data.client_name || "",
			};
		}

		// The RP (Relying Party) - the client application
		const { customFetchImpl: customFetchImplRP, cookieSetter } =
			await getTestInstance({
				account: {
					accountLinking: {
						trustedProviders: ["test"],
					},
				},
				databaseHooks: autoVerifyUserHook,
				plugins: [
					genericOAuth({
						config: [
							{
								providerId: "test",
								clientId: application.clientId,
								clientSecret: application.clientSecret || "",
								authorizationUrl:
									"http://localhost:3000/api/auth/oauth2/authorize",
								tokenUrl: "http://localhost:3000/api/auth/oauth2/token",
								scopes: ["openid", "profile", "email"],
								pkce: true,
							},
						],
					}),
				],
			});

		const client = createAuthClient({
			plugins: [genericOAuthClient()],
			baseURL: "http://localhost:5000",
			fetchOptions: {
				customFetchImpl: customFetchImplRP,
			},
		});
		const oAuthHeaders = new Headers();
		const data = await client.signIn.oauth2(
			{
				providerId: "test",
				callbackURL: "/dashboard",
			},
			{
				throw: true,
				onSuccess: cookieSetter(oAuthHeaders),
			},
		);
		expect(data.url).toContain(
			"http://localhost:3000/api/auth/oauth2/authorize",
		);
		expect(data.url).toContain(`client_id=${application.clientId}`);

		let redirectURI = "";
		const newHeaders = new Headers();
		await serverClient.$fetch(data.url, {
			method: "GET",
			onError(context) {
				redirectURI = context.response.headers.get("Location") || "";
				cookieSetter(newHeaders)(context);
				if (headers.get("Cookie")) {
					newHeaders.append("Cookie", headers.get("Cookie") || "");
				}
			},
		});

		// Check if consent is needed (per OIDC spec)
		if (redirectURI.includes("consent_code=")) {
			// Handle consent flow - this is expected per OIDC spec for non-trusted clients
			expect(redirectURI).toContain("/oauth2/authorize?");
			expect(redirectURI).toContain("consent_code=");
			expect(redirectURI).toContain("client_id=");

			// Extract consent_code from URL
			const url = new URL(redirectURI, "http://localhost:3000");
			const consentCode = url.searchParams.get("consent_code");

			const res = await serverClient.oauth2.consent(
				{
					accept: true,
					consent_code: consentCode,
				},
				{
					headers: newHeaders,
					throw: true,
				},
			);
			expect(res.redirectURI).toContain(
				"http://localhost:3000/api/auth/oauth2/callback/test?code=",
			);
			redirectURI = res.redirectURI;
		} else {
			// Direct code response (trusted client)
			expect(redirectURI).toContain(
				"http://localhost:3000/api/auth/oauth2/callback/test?code=",
			);
		}
		let authToken = undefined;
		let callbackURL = "";
		await client.$fetch(redirectURI, {
			headers: oAuthHeaders,
			onError(context) {
				callbackURL = context.response.headers.get("Location") || "";
				authToken = context.response.headers.get("set-auth-token")!;
			},
		});
		expect(callbackURL).toContain("/dashboard");
		const accessToken = await client.getAccessToken(
			{ providerId: "test", userId: testUser.id },
			{
				auth: {
					type: "Bearer",
					token: authToken,
				},
			},
		);
		const decoded = decodeProtectedHeader(accessToken.data?.idToken!);
		const discoveryResponse = await customFetchImpl(
			"http://localhost:3000/api/auth/.well-known/openid-configuration",
		);
		expect(discoveryResponse.status).toBe(200);
		const discovery = (await discoveryResponse.json()) as { issuer: string };
		expect(discovery.issuer).toBe("https://issuer.clearance.test");
		const standardVerification = {
			issuer: discovery.issuer,
			audience: application.clientId,
		};
		let verifiedPayload: Awaited<ReturnType<typeof jwtVerify>>["payload"];
		if (useJwt) {
			const jwks = await authorizationServer.api.getJwks();
			const jwkSet = createLocalJWKSet(jwks);
			const checkSignature = await jwtVerify(
				accessToken.data?.idToken!,
				jwkSet,
				standardVerification,
			);
			expect(checkSignature).toBeDefined();
			expect(Number.isInteger(checkSignature.payload.iat)).toBeTruthy();
			expect(Number.isInteger(checkSignature.payload.exp)).toBeTruthy();
			verifiedPayload = checkSignature.payload;
		} else {
			const clientSecret = application.clientSecret;
			const checkSignature = await jwtVerify(
				accessToken.data?.idToken!,
				new TextEncoder().encode(clientSecret),
				standardVerification,
			);
			expect(checkSignature).toBeDefined();
			verifiedPayload = checkSignature.payload;
		}
		expect(verifiedPayload.sub).toBe(verifiedPayload.userId);
		expect(verifiedPayload.iss).toBe(discovery.issuer);
		expect(verifiedPayload.sub).not.toBe("attacker-controlled-sub");
		expect(verifiedPayload.aud).toBe(application.clientId);
		expect(verifiedPayload.sid).toEqual(expect.any(String));
		expect(verifiedPayload.sid).not.toBe("attacker-controlled-family");
		expect(verifiedPayload.iat).not.toBe(1);
		expect(verifiedPayload.auth_time).toEqual(expect.any(Number));
		expect(Number.isInteger(verifiedPayload.auth_time)).toBe(true);
		expect(verifiedPayload.auth_time).toBeLessThanOrEqual(
			Math.floor(Date.now() / 1000),
		);
		expect(verifiedPayload.auth_time).toBeGreaterThan(
			Math.floor(Date.now() / 1000) - 3600,
		);
		expect(verifiedPayload.acr).toBe("urn:mace:incommon:iap:silver");
		expect(verifiedPayload.email).not.toBe("attacker@example.test");
		expect(verifiedPayload.email_verified).toEqual(expect.any(Boolean));
		expect(verifiedPayload.name).not.toBe("Attacker Controlled Name");
		expect(verifiedPayload.given_name).not.toBe("Attacker");
		expect(verifiedPayload.family_name).not.toBe("Controlled");
		expect(verifiedPayload.profile).not.toBe(
			"https://attacker.example.test/profile",
		);
		expect(verifiedPayload.picture).toBeUndefined();
		expect(Number.isInteger(verifiedPayload.updated_at)).toBe(true);
		for (const claim of [
			"jti",
			"amr",
			"azp",
			"at_hash",
			"c_hash",
			"s_hash",
			"cnf",
			"act",
			"may_act",
		]) {
			expect(verifiedPayload[claim]).toBeUndefined();
		}
		expect(verifiedPayload.custom).toBe("custom value");

		const userInfoResponse = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/userinfo",
			{
				headers: {
					authorization: `Bearer ${accessToken.data?.accessToken}`,
				},
			},
		);
		expect(userInfoResponse.status).toBe(200);
		const userInfo = await userInfoResponse.json();
		expect(userInfo).toMatchObject({
			custom: "custom value",
		});
		expect(userInfo.sub).toBe(userInfo.userId);
		expect(userInfo.sub).not.toBe("attacker-controlled-sub");
		expect(userInfo.email).not.toBe("attacker@example.test");
		expect(userInfo.email_verified).toEqual(expect.any(Boolean));
		expect(userInfo.name).not.toBe("Attacker Controlled Name");
		expect(userInfo.given_name).not.toBe("Attacker");
		expect(userInfo.family_name).not.toBe("Controlled");
		expect(userInfo.picture).not.toBe(
			"https://attacker.example.test/picture",
		);
		for (const claim of RESERVED_ADDITIONAL_CLAIM_NAMES) {
			if (claim === "sub") continue;
			expect(userInfo[claim]).toBeUndefined();
		}

		if (useJwt) {
			const targetUserId = verifiedPayload.sub as string;
			const targetFamilyId = verifiedPayload.sid as string;
			const targetBefore = await db.findOne<Record<string, any>>({
				model: "oauthAccessToken",
				where: [
					{ field: "userId", value: targetUserId },
					{ field: "clientId", value: application.clientId },
					{ field: "familyId", value: targetFamilyId },
				],
			});
			expect(targetBefore).not.toBeNull();
			const siblingFamily = await createOAuthTokenPair(
				db,
				"oauthAccessToken",
				{
					accessTokenExpiresAt: new Date(Date.now() + 300_000),
					refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
					clientId: application.clientId,
					userId: targetUserId,
					scopes: "openid offline_access",
					familyId: "endsession-jwks-sibling-family",
					issueRefreshToken: true,
				},
			);

			const endSessionURL = new URL(
				"http://localhost:3000/api/auth/oauth2/endsession",
			);
			endSessionURL.searchParams.set(
				"id_token_hint",
				accessToken.data?.idToken!,
			);
			const endSessionResponse = await authorizationServer.handler(
				new Request(endSessionURL, {
					method: "GET",
					headers: { "Sec-Fetch-Site": "same-origin" },
				}),
			);
			expect(endSessionResponse.status).toBe(200);

			const targetAfter = await db.findOne<Record<string, any>>({
				model: "oauthAccessToken",
				where: [{ field: "id", value: targetBefore!.id }],
			});
			const siblingAfter = await db.findOne<Record<string, any>>({
				model: "oauthAccessToken",
				where: [{ field: "id", value: siblingFamily.row.id }],
			});
			expect(targetAfter?.refreshStatus).toBe("revoked");
			expect(siblingAfter?.refreshStatus).toBe("active");
		}

		// expect(checkSignature.payload).toBeDefined();
		expect(decoded.alg).toBe(expected);
		},
	);
});

/**
 * @see https://github.com/clearance-auth/clearance
 */
describe("oidc-provider refresh_token grant client authentication", () => {
	const REFRESH_TOKEN = "pw9m-test-refresh-token";
	const CLIENT_ID = "pw9m-confidential-test-client";
	const CLIENT_SECRET = "pw9m-secret-only-the-client-knows";

	async function seedConfidentialClientAndToken(
		db: Awaited<ReturnType<typeof getTestInstance>>["db"],
		userId: string,
	) {
		await db.create({
			model: "oauthApplication",
			data: {
				clientId: CLIENT_ID,
				clientSecret: CLIENT_SECRET,
				type: "web",
				name: "Confidential Test Client",
				redirectUrls: "http://localhost/callback",
				disabled: false,
				metadata: null,
				icon: null,
				userId: null,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});
		await createOAuthTokenPair(db, "oauthAccessToken", {
			clientId: CLIENT_ID,
			userId,
			scopes: "openid profile email offline_access",
			accessTokenExpiresAt: new Date(Date.now() - 60 * 1000),
			refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000),
			issueRefreshToken: true,
			accessToken: "stale-access-token-not-used",
			refreshToken: REFRESH_TOKEN,
		});
	}

	it("should reject refresh_token grant on confidential client without client_secret", async () => {
		const { customFetchImpl, signInWithTestUser, db } = await getTestInstance({
			plugins: [
				oidcProvider({
					loginPage: "/login",
					consentPage: "/oauth2/authorize",
					requirePKCE: false,
				}),
			],
		});
		const { user } = await signInWithTestUser();
		await seedConfidentialClientAndToken(db, user.id);

		const response = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: REFRESH_TOKEN,
					client_id: CLIENT_ID,
				}).toString(),
			},
		);
		const body = await response.json().catch(() => null);

		expect(response.status).toBe(401);
		expect(body?.error).toBe("invalid_client");
		expect(body?.access_token).toBeUndefined();
	});

	it("should reject refresh_token grant on confidential client with wrong client_secret", async () => {
		const { customFetchImpl, signInWithTestUser, db } = await getTestInstance({
			plugins: [
				oidcProvider({
					loginPage: "/login",
					consentPage: "/oauth2/authorize",
					requirePKCE: false,
				}),
			],
		});
		const { user } = await signInWithTestUser();
		await seedConfidentialClientAndToken(db, user.id);

		const response = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: REFRESH_TOKEN,
					client_id: CLIENT_ID,
					client_secret: "wrong-secret",
				}).toString(),
			},
		);
		const body = await response.json().catch(() => null);

		expect(response.status).toBe(401);
		expect(body?.error).toBe("invalid_client");
		expect(body?.access_token).toBeUndefined();
	});

	it("should accept refresh_token grant when client_secret comes via Authorization: Basic", async () => {
		const { customFetchImpl, signInWithTestUser, db } = await getTestInstance({
			plugins: [
				oidcProvider({
					loginPage: "/login",
					consentPage: "/oauth2/authorize",
					requirePKCE: false,
				}),
			],
		});
		const { user } = await signInWithTestUser();
		await seedConfidentialClientAndToken(db, user.id);

		const basic = `Basic ${Buffer.from(
			`${CLIENT_ID}:${CLIENT_SECRET}`,
		).toString("base64")}`;

		const response = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					authorization: basic,
				},
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: REFRESH_TOKEN,
				}).toString(),
			},
		);
		const body = await response.json().catch(() => null);

		expect(response.status).toBe(200);
		expect(body?.access_token).toBeDefined();
		expect(body?.refresh_token).toBeDefined();
	});

	it("should accept refresh_token grant when Authorization: Basic and matching client_id is in body", async () => {
		const { customFetchImpl, signInWithTestUser, db } = await getTestInstance({
			plugins: [
				oidcProvider({
					loginPage: "/login",
					consentPage: "/oauth2/authorize",
					requirePKCE: false,
				}),
			],
		});
		const { user } = await signInWithTestUser();
		await seedConfidentialClientAndToken(db, user.id);

		const basic = `Basic ${Buffer.from(
			`${CLIENT_ID}:${CLIENT_SECRET}`,
		).toString("base64")}`;

		const response = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					authorization: basic,
				},
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: REFRESH_TOKEN,
					client_id: CLIENT_ID,
				}).toString(),
			},
		);
		const body = await response.json().catch(() => null);

		expect(response.status).toBe(200);
		expect(body?.access_token).toBeDefined();
	});

	it("should reject refresh_token grant when body client_id does not match Authorization: Basic", async () => {
		const { customFetchImpl, signInWithTestUser, db } = await getTestInstance({
			plugins: [
				oidcProvider({
					loginPage: "/login",
					consentPage: "/oauth2/authorize",
					requirePKCE: false,
				}),
			],
		});
		const { user } = await signInWithTestUser();
		await seedConfidentialClientAndToken(db, user.id);

		const basic = `Basic ${Buffer.from(
			`${CLIENT_ID}:${CLIENT_SECRET}`,
		).toString("base64")}`;

		const response = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					authorization: basic,
				},
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: REFRESH_TOKEN,
					client_id: "different-client-id",
				}).toString(),
			},
		);
		const body = await response.json().catch(() => null);

		expect(response.status).toBe(401);
		expect(body?.error).toBe("invalid_client");
	});

	it("should reject refresh_token grant when the confidential client is disabled", async () => {
		const { customFetchImpl, signInWithTestUser, db } = await getTestInstance({
			plugins: [
				oidcProvider({
					loginPage: "/login",
					consentPage: "/oauth2/authorize",
					requirePKCE: false,
				}),
			],
		});
		const { user } = await signInWithTestUser();
		await seedConfidentialClientAndToken(db, user.id);
		await db.update<{ disabled: boolean }>({
			model: "oauthApplication",
			where: [{ field: "clientId", value: CLIENT_ID }],
			update: { disabled: true },
		});

		const response = await customFetchImpl(
			"http://localhost:3000/api/auth/oauth2/token",
			{
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: REFRESH_TOKEN,
					client_id: CLIENT_ID,
					client_secret: CLIENT_SECRET,
				}).toString(),
			},
		);
		const body = await response.json().catch(() => null);
		expect(response.status).toBe(401);
		expect(body?.error).toBe("invalid_client");
		expect(body?.access_token).toBeUndefined();
	});
});

/**
 * @see https://github.com/clearance-auth/clearance
 */
describe("oidc-provider discovery metadata and PKCE gate (security)", () => {
	const buildInstance = async (
		options?: Partial<Parameters<typeof oidcProvider>[0]>,
	) => {
		const { auth, customFetchImpl, signInWithTestUser } = await getTestInstance(
			{
				baseURL: "http://localhost:3000",
				plugins: [
					oidcProvider({
						loginPage: "/login",
						consentPage: "/oauth2/authorize",
						...options,
					}),
				],
			},
		);
		return { auth, customFetchImpl, signInWithTestUser };
	};

	it("/.well-known/openid-configuration must not advertise alg=none", async () => {
		const { auth } = await buildInstance();
		const res = await auth.handler(
			new Request(
				"http://localhost:3000/api/auth/.well-known/openid-configuration",
				{ method: "GET" },
			),
		);
		const body = (await res.json()) as {
			id_token_signing_alg_values_supported: string[];
			code_challenge_methods_supported: string[];
		};
		expect(body.id_token_signing_alg_values_supported).not.toContain("none");
		expect(body.code_challenge_methods_supported).toEqual(["S256"]);
	});

	it("authorize must reject code_challenge_method=plain when allowPlainCodeChallengeMethod is false (default)", async () => {
		const trustedClient: Client = {
			clientId: "pkce-plain-rejection-client",
			clientSecret: "test-client-secret",
			redirectUrls: ["http://localhost:3000/cb"],
			metadata: {},
			type: "web",
			disabled: false,
			name: "test",
			icon: undefined,
			skipConsent: true,
		};
		const { auth, signInWithTestUser } = await buildInstance({
			trustedClients: [trustedClient],
		});
		const { headers: sessionHeaders } = await signInWithTestUser();

		const url = new URL("http://localhost:3000/api/auth/oauth2/authorize");
		url.searchParams.set("client_id", trustedClient.clientId);
		url.searchParams.set("redirect_uri", trustedClient.redirectUrls[0]!);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("scope", "openid profile email");
		url.searchParams.set("state", "xyz");
		url.searchParams.set(
			"code_challenge",
			"plainPkceVerifier_at_least_43_chars_long_for_validity",
		);
		url.searchParams.set("code_challenge_method", "plain");

		const res = await auth.handler(
			new Request(url, { method: "GET", headers: sessionHeaders }),
		);
		const location = res.headers.get("location") ?? "";
		expect(location).toContain("error=invalid_request");
		expect(location).toMatch(/invalid.*code.*challenge.*method/i);
	});

	it("authorize must reject missing code_challenge_method when code_challenge is provided", async () => {
		const trustedClient: Client = {
			clientId: "pkce-missing-method-client",
			clientSecret: "test-client-secret",
			redirectUrls: ["http://localhost:3000/cb"],
			metadata: {},
			type: "web",
			disabled: false,
			name: "test",
			icon: undefined,
			skipConsent: true,
		};
		const { auth, signInWithTestUser } = await buildInstance({
			trustedClients: [trustedClient],
		});
		const { headers: sessionHeaders } = await signInWithTestUser();

		const url = new URL("http://localhost:3000/api/auth/oauth2/authorize");
		url.searchParams.set("client_id", trustedClient.clientId);
		url.searchParams.set("redirect_uri", trustedClient.redirectUrls[0]!);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("scope", "openid profile email");
		url.searchParams.set("state", "xyz");
		url.searchParams.set(
			"code_challenge",
			"someChallengeValue_at_least_43_chars_long_for_validity",
		);
		// code_challenge_method intentionally omitted

		const res = await auth.handler(
			new Request(url, { method: "GET", headers: sessionHeaders }),
		);
		const location = res.headers.get("location") ?? "";
		const callback = trustedClient.redirectUrls[0]!;
		const issuedCode =
			location.startsWith(callback) && /[?&]code=/.test(location);
		expect(issuedCode).toBe(false);
		expect(location).toContain("error=invalid_request");
	});

	it("authorize must reject code_challenge_method without code_challenge", async () => {
		const trustedClient: Client = {
			clientId: "pkce-method-without-challenge-client",
			clientSecret: "test-client-secret",
			redirectUrls: ["http://localhost:3000/cb"],
			metadata: {},
			type: "web",
			disabled: false,
			name: "test",
			icon: undefined,
			skipConsent: true,
		};
		const { auth, signInWithTestUser } = await buildInstance({
			trustedClients: [trustedClient],
		});
		const { headers: sessionHeaders } = await signInWithTestUser();

		const url = new URL("http://localhost:3000/api/auth/oauth2/authorize");
		url.searchParams.set("client_id", trustedClient.clientId);
		url.searchParams.set("redirect_uri", trustedClient.redirectUrls[0]!);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("scope", "openid profile email");
		url.searchParams.set("state", "xyz");
		url.searchParams.set("code_challenge_method", "S256");
		// code_challenge intentionally omitted

		const res = await auth.handler(
			new Request(url, { method: "GET", headers: sessionHeaders }),
		);
		const location = res.headers.get("location") ?? "";
		const callback = trustedClient.redirectUrls[0]!;
		const issuedCode =
			location.startsWith(callback) && /[?&]code=/.test(location);
		expect(issuedCode).toBe(false);
		expect(location).toContain("error=invalid_request");
	});

	it("authorize accepts missing code_challenge_method when allowPlainCodeChallengeMethod is opted in", async () => {
		const trustedClient: Client = {
			clientId: "pkce-plain-opt-in-client",
			clientSecret: "test-client-secret",
			redirectUrls: ["http://localhost:3000/cb"],
			metadata: {},
			type: "web",
			disabled: false,
			name: "test",
			icon: undefined,
			skipConsent: true,
		};
		const { auth, signInWithTestUser } = await buildInstance({
			trustedClients: [trustedClient],
			allowPlainCodeChallengeMethod: true,
		});
		const { headers: sessionHeaders } = await signInWithTestUser();

		const codeChallenge =
			"someChallengeValue_at_least_43_chars_long_for_validity";
		const url = new URL("http://localhost:3000/api/auth/oauth2/authorize");
		url.searchParams.set("client_id", trustedClient.clientId);
		url.searchParams.set("redirect_uri", trustedClient.redirectUrls[0]!);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("scope", "openid profile email");
		url.searchParams.set("state", "xyz");
		url.searchParams.set("code_challenge", codeChallenge);
		// code_challenge_method intentionally omitted; the opt-in retains the
		// legacy "default to plain" behavior so this should issue a code.

		const res = await auth.handler(
			new Request(url, { method: "GET", headers: sessionHeaders }),
		);
		const location = res.headers.get("location") ?? "";
		const callback = trustedClient.redirectUrls[0]!;
		const issuedCode =
			location.startsWith(callback) && /[?&]code=/.test(location);
		expect(issuedCode).toBe(true);
		expect(location).not.toContain("error=");

		// Inspect the persisted verification value to prove the fallback-resolved
		// `plain` method was written to storage. Regression: a previous shape only
		// touched a local and never wrote it back to `query.code_challenge_method`,
		// so the token endpoint compared against `undefined` at exchange time and
		// broke PKCE verification.
		const code = new URL(location).searchParams.get("code")!;
		const { internalAdapter } = await auth.$context;
		const stored = await internalAdapter.findVerificationValue(code);
		expect(stored).toBeDefined();
		const storedValue = JSON.parse(stored!.value) as {
			codeChallengeMethod?: string;
		};
		expect(storedValue.codeChallengeMethod).toBe("plain");
	});
});

describe("oidc end session cross-site protection (security)", async () => {
	const { auth, signInWithTestUser, db } = await getTestInstance({
		baseURL: "http://localhost:3000",
		plugins: [oidcProvider({ loginPage: "/login" })],
	});
	const { user, headers } = await signInWithTestUser();
	const cookie = headers.get("cookie") ?? "";

	async function seedAccessToken() {
		await db.create({
			model: "oauthApplication",
			data: {
				clientId: "endsession-csrf-client",
				clientSecret: "endsession-csrf-secret",
				type: "web",
				name: "Endsession CSRF Client",
				redirectUrls: "http://localhost/callback",
				disabled: false,
				metadata: null,
				icon: null,
				userId: null,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});
		return createOAuthTokenPair(db, "oauthAccessToken", {
			accessTokenExpiresAt: new Date(Date.now() + 3600 * 1000),
			refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000),
			clientId: "endsession-csrf-client",
			userId: user.id,
			scopes: "openid",
			issueRefreshToken: true,
		});
	}

	it("rejects a cross-site GET logout carrying only a session cookie", async () => {
		const { row } = await seedAccessToken();

		const response = await auth.handler(
			new Request("http://localhost:3000/api/auth/oauth2/endsession", {
				method: "GET",
				headers: { cookie, "Sec-Fetch-Site": "cross-site" },
			}),
		);
		expect(response.status).toBe(403);

		// A blocked logout must leave the session and OAuth tokens intact.
		const session = await auth.api.getSession({
			headers: new Headers({ cookie }),
		});
		expect(session?.user.id).toBe(user.id);
		const tokenRow = await db.findOne({
			model: "oauthAccessToken",
			where: [{ field: "id", value: row.id }],
		});
		expect(tokenRow).not.toBeNull();
	});

	it("allows a same-site cookie-only logout", async () => {
		const response = await auth.handler(
			new Request("http://localhost:3000/api/auth/oauth2/endsession", {
				method: "GET",
				headers: { cookie, "Sec-Fetch-Site": "same-origin" },
			}),
		);
		expect(response.status).toBe(200);
	});

	it("revokes only the family identified by the validated RP logout hint", async () => {
		const clientA = {
			clientId: "endsession-family-client-a",
			clientSecret: "endsession-family-secret-a",
		};
		const clientB = {
			clientId: "endsession-family-client-b",
			clientSecret: "endsession-family-secret-b",
		};
		for (const client of [clientA, clientB]) {
			await db.create({
				model: "oauthApplication",
				data: {
					...client,
					type: "web",
					name: client.clientId,
					redirectUrls: "http://localhost/callback",
					disabled: false,
					metadata: null,
					icon: null,
					userId: null,
					createdAt: new Date(),
					updatedAt: new Date(),
				},
			});
		}

		const target = await createOAuthTokenPair(db, "oauthAccessToken", {
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
			clientId: clientA.clientId,
			userId: user.id,
			scopes: "openid offline_access",
			familyId: "endsession-family-a-target",
			issueRefreshToken: true,
		});
		const sameClientOtherFamily = await createOAuthTokenPair(
			db,
			"oauthAccessToken",
			{
				accessTokenExpiresAt: new Date(Date.now() + 300_000),
				refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
				clientId: clientA.clientId,
				userId: user.id,
				scopes: "openid offline_access",
				familyId: "endsession-family-a-other",
				issueRefreshToken: true,
			},
		);
		const otherClient = await createOAuthTokenPair(db, "oauthAccessToken", {
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
			clientId: clientB.clientId,
			userId: user.id,
			scopes: "openid offline_access",
			familyId: "endsession-family-b",
			issueRefreshToken: true,
		});
		const idTokenHint = await new SignJWT({
			sid: target.row.familyId,
		})
			.setProtectedHeader({ alg: "HS256" })
			.setSubject(user.id)
			.setIssuer("http://localhost:3000")
			.setAudience(clientA.clientId)
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(new TextEncoder().encode(clientA.clientSecret));

		const url = new URL(
			"http://localhost:3000/api/auth/oauth2/endsession",
		);
		url.searchParams.set("id_token_hint", idTokenHint);
		url.searchParams.set("client_id", clientA.clientId);
		const response = await auth.handler(
			new Request(url, {
				method: "GET",
				headers: { "Sec-Fetch-Site": "same-origin" },
			}),
		);
		expect(response.status).toBe(200);

		const rows = await db.findMany<Record<string, any>>({
			model: "oauthAccessToken",
			where: [
				{
					field: "id",
					operator: "in",
					value: [
						target.row.id,
						sameClientOtherFamily.row.id,
						otherClient.row.id,
					],
				},
			],
		});
		const byId = new Map(rows.map((row) => [row.id, row]));
		expect(byId.get(target.row.id)?.refreshStatus).toBe("revoked");
		expect(byId.get(sameClientOtherFamily.row.id)?.refreshStatus).toBe(
			"active",
		);
		expect(byId.get(otherClient.row.id)?.refreshStatus).toBe("active");
	});

	it("revokes every family for a validated pre-sid id_token_hint on the (userId, clientId) pair", async () => {
		const clientA = {
			clientId: "endsession-presid-client-a",
			clientSecret: "endsession-presid-secret-a",
		};
		const clientB = {
			clientId: "endsession-presid-client-b",
			clientSecret: "endsession-presid-secret-b",
		};
		for (const client of [clientA, clientB]) {
			await db.create({
				model: "oauthApplication",
				data: {
					...client,
					type: "web",
					name: client.clientId,
					redirectUrls: "http://localhost/callback",
					disabled: false,
					metadata: null,
					icon: null,
					userId: null,
					createdAt: new Date(),
					updatedAt: new Date(),
				},
			});
		}

		const familyOne = await createOAuthTokenPair(db, "oauthAccessToken", {
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
			clientId: clientA.clientId,
			userId: user.id,
			scopes: "openid offline_access",
			familyId: "endsession-presid-a-one",
			issueRefreshToken: true,
		});
		const familyTwo = await createOAuthTokenPair(db, "oauthAccessToken", {
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
			clientId: clientA.clientId,
			userId: user.id,
			scopes: "openid offline_access",
			familyId: "endsession-presid-a-two",
			issueRefreshToken: true,
		});
		const otherClient = await createOAuthTokenPair(db, "oauthAccessToken", {
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
			clientId: clientB.clientId,
			userId: user.id,
			scopes: "openid offline_access",
			familyId: "endsession-presid-b",
			issueRefreshToken: true,
		});

		// Valid HS256 pre-sid hint: fully verifiable sub + aud, intentionally no sid.
		const idTokenHint = await new SignJWT({})
			.setProtectedHeader({ alg: "HS256" })
			.setSubject(user.id)
			.setIssuer("http://localhost:3000")
			.setAudience(clientA.clientId)
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(new TextEncoder().encode(clientA.clientSecret));

		const url = new URL(
			"http://localhost:3000/api/auth/oauth2/endsession",
		);
		url.searchParams.set("id_token_hint", idTokenHint);
		url.searchParams.set("client_id", clientA.clientId);
		const response = await auth.handler(
			new Request(url, {
				method: "GET",
				headers: { "Sec-Fetch-Site": "same-origin" },
			}),
		);
		expect(response.status).toBe(200);

		const rows = await db.findMany<Record<string, any>>({
			model: "oauthAccessToken",
			where: [
				{
					field: "id",
					operator: "in",
					value: [familyOne.row.id, familyTwo.row.id, otherClient.row.id],
				},
			],
		});
		const byId = new Map(rows.map((row) => [row.id, row]));
		expect(byId.get(familyOne.row.id)).toMatchObject({
			refreshStatus: "revoked",
			revokedAt: expect.any(Date),
			rotationNonceDigest: null,
			recoveryExpiresAt: null,
		});
		expect(byId.get(familyTwo.row.id)).toMatchObject({
			refreshStatus: "revoked",
			revokedAt: expect.any(Date),
			rotationNonceDigest: null,
			recoveryExpiresAt: null,
		});
		expect(byId.get(otherClient.row.id)?.refreshStatus).toBe("active");
		// Digest rows remain present after revocation.
		expect(byId.get(familyOne.row.id)?.refreshTokenDigest).toBeTruthy();
		expect(byId.get(familyTwo.row.id)?.refreshTokenDigest).toBeTruthy();

		for (const refreshToken of [
			familyOne.refreshToken!,
			familyTwo.refreshToken!,
		]) {
			const refreshResponse = await auth.handler(
				new Request("http://localhost:3000/api/auth/oauth2/token", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({
						grant_type: "refresh_token",
						refresh_token: refreshToken,
						client_id: clientA.clientId,
						client_secret: clientA.clientSecret,
					}),
				}),
			);
			expect(refreshResponse.status).toBe(401);
			expect(await refreshResponse.json()).toMatchObject({
				error: "invalid_grant",
			});
		}
	});

	it("does not revoke OAuth families for an invalid id_token_hint", async () => {
		const client = {
			clientId: "endsession-invalid-hint-client",
			clientSecret: "endsession-invalid-hint-secret",
		};
		await db.create({
			model: "oauthApplication",
			data: {
				...client,
				type: "web",
				name: client.clientId,
				redirectUrls: "http://localhost/callback",
				disabled: false,
				metadata: null,
				icon: null,
				userId: null,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});
		const family = await createOAuthTokenPair(db, "oauthAccessToken", {
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
			clientId: client.clientId,
			userId: user.id,
			scopes: "openid offline_access",
			familyId: "endsession-invalid-hint-family",
			issueRefreshToken: true,
		});

		// Signature fails verification against the registered client secret.
		const invalidHint = await new SignJWT({})
			.setProtectedHeader({ alg: "HS256" })
			.setSubject(user.id)
			.setIssuer("http://localhost:3000")
			.setAudience(client.clientId)
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(new TextEncoder().encode("wrong-client-secret"));

		const url = new URL(
			"http://localhost:3000/api/auth/oauth2/endsession",
		);
		url.searchParams.set("id_token_hint", invalidHint);
		url.searchParams.set("client_id", client.clientId);
		const response = await auth.handler(
			new Request(url, {
				method: "GET",
				headers: { "Sec-Fetch-Site": "same-origin" },
			}),
		);
		expect(response.status).toBe(200);

		const row = await db.findOne<Record<string, any>>({
			model: "oauthAccessToken",
			where: [{ field: "id", value: family.row.id }],
		});
		expect(row?.refreshStatus).toBe("active");
		expect(row?.revokedAt).toBeNull();

		const refreshResponse = await auth.handler(
			new Request("http://localhost:3000/api/auth/oauth2/token", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "refresh_token",
					refresh_token: family.refreshToken!,
					client_id: client.clientId,
					client_secret: client.clientSecret,
				}),
			}),
		);
		expect(refreshResponse.status).toBe(200);
		expect((await refreshResponse.json()).access_token).toBeDefined();
	});
});
