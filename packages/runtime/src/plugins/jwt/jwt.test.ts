import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import type { JSONWebKeySet } from "jose";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { createAuthClient } from "../../client";
import { attachInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { getTestInstance } from "../../test-utils/test-instance";
import { generateCredentialOperationKey } from "../../utils/operation-key";
import { jwt } from ".";
import { jwtClient } from "./client";
import {
	JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM,
	JWT_SESSION_SOURCE_ORGANIZATION_CLAIM,
	JWT_SESSION_SOURCE_SUBJECT_CLAIM,
} from "./sign";
import type { JWKOptions, Jwk, JwtOptions } from "./types";
import { generateExportedKeyPair, toExpJWT } from "./utils";

const managedJwtIdentity = {
	projectId: "jwt-project",
	environmentId: "jwt-environment",
} satisfies RuntimeAuthenticationPolicyIdentity;

const managedJwtPolicy = {
	passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	factorLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	minimumAssurance: "single_factor",
	allowedFactors: { totp: true, passkey: true },
	trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
	assuranceMaxAgeSeconds: 300,
} satisfies RuntimeAuthenticationPolicy;

function managedJwtOptions(override: JwtOptions = {}) {
	const options = {
		plugins: [
			jwt({
				...override,
				disableSettingJwtHeader: true,
				jwt: {
					getSubject: async () => "application-subject",
					definePayload: async () => ({
						[JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM]: "forged",
						[JWT_SESSION_SOURCE_SUBJECT_CLAIM]: "forged",
						[JWT_SESSION_SOURCE_ORGANIZATION_CLAIM]: "forged",
					}),
					...override.jwt,
				},
			}),
		],
		logger: { level: "error" },
	} satisfies ClearanceOptions;
	attachInternalAuthenticationPolicy(options, {
		identity: managedJwtIdentity,
		reader: {
			async readForSubject(input) {
				return {
					scope: managedJwtIdentity,
					subjectId: input.subjectId,
					revision: "1",
					environment: managedJwtPolicy,
					organizationMembership: null,
					organizationOverride: null,
					effective: managedJwtPolicy,
				};
			},
		},
	});
	return options;
}

describe("jwt compatibility", async () => {
	const { auth, signInWithTestUser } = await getTestInstance({
		plugins: [jwt()],
		logger: { level: "error" },
	});
	const { headers } = await signInWithTestUser();

	it("emits the legacy session JWT header by default", async () => {
		const response = await auth.handler(
			new Request("http://localhost:3000/api/auth/get-session", { headers }),
		);

		expect(response.status).toBe(200);
		expect(response.headers.get("set-auth-jwt")).toEqual(expect.any(String));
		expect(response.headers.get("set-auth-jwt")?.length).toBeGreaterThan(10);
		expect(response.headers.get("access-control-expose-headers")).toContain(
			"set-auth-jwt",
		);
	});

	it("keeps deprecated GET /token functional with migration and cache headers", async () => {
		const response = await auth.handler(
			new Request("http://localhost:3000/api/auth/token", {
				method: "GET",
				headers,
			}),
		);

		expect(response.status).toBe(200);
		expect(response.headers.get("deprecation")).toBe("true");
		expect(response.headers.get("link")).toBe(
			'</token>; rel="successor-version"',
		);
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(response.headers.get("pragma")).toBe("no-cache");
		expect(await response.json()).toMatchObject({
			token: expect.any(String),
		});
	});

	it("keeps legacy JWT reads available with secondary-storage-only sessions", async () => {
		const store = new Map<string, string>();
		const secondary = await getTestInstance({
			secondaryStorage: {
				namespace: "jwt-secondary-compatibility-test",
				set(key, value) {
					store.set(key, value);
				},
				get(key) {
					return store.get(key) ?? null;
				},
				delete(key) {
					store.delete(key);
				},
			},
			plugins: [jwt()],
			logger: { level: "error" },
		});
		const signedIn = await secondary.signInWithTestUser();
		const requests: Array<{
			method: string;
			status: number;
			cacheControl: string | null;
			pragma: string | null;
			tokenMode: string | null;
		}> = [];
		const secondaryClient = createAuthClient({
			plugins: [jwtClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) => {
					const request = new Request(url, init);
					const response = await secondary.auth.handler(request);
					requests.push({
						method: request.method,
						status: response.status,
						cacheControl: response.headers.get("cache-control"),
						pragma: response.headers.get("pragma"),
						tokenMode: response.headers.get("clearance-jwt-token-mode"),
					});
					return response;
				},
			},
		});
		const response = await secondaryClient.token({
			fetchOptions: { headers: signedIn.headers },
		});

		expect(response.data?.token).toEqual(expect.any(String));
		expect(requests).toEqual([
			{
				method: "POST",
				status: 503,
				cacheControl: "no-store",
				pragma: "no-cache",
				tokenMode: "legacy-get",
			},
			{
				method: "GET",
				status: 200,
				cacheControl: "no-store",
				pragma: "no-cache",
				tokenMode: null,
			},
		]);
	});
});

describe("jwt session derivative authority", async () => {
	it("binds live managed sessions, rejects stale sources, and preserves generic tokens", async () => {
		const local = await getTestInstance(managedJwtOptions());
		const signedIn = await local.signInWithTestUser();
		const currentSession = await local.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		const response = await local.auth.handler(
			new Request("http://localhost:3000/api/auth/token", {
				method: "GET",
				headers: signedIn.headers,
			}),
		);
		const { token } = (await response.json()) as { token: string };
		const payload = decodeJwt(token);

		expect(payload).toMatchObject({
			sub: "application-subject",
			[JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM]: expect.any(String),
			[JWT_SESSION_SOURCE_SUBJECT_CLAIM]: signedIn.user.id,
			[JWT_SESSION_SOURCE_ORGANIZATION_CLAIM]: null,
		});
		expect(
			(await local.auth.api.verifyJWT({ body: { token } })).payload,
		).toMatchObject({ sub: "application-subject" });

		await local.client.revokeSession({
			id: currentSession.data!.session.id,
			fetchOptions: { headers: signedIn.headers },
		});
		expect(
			(await local.auth.api.verifyJWT({ body: { token } })).payload,
		).toBeNull();

		const generic = await local.auth.api.signJWT({
			body: {
				payload: {
					sub: "generic-subject",
					exp: Math.floor(Date.now() / 1000) + 60,
				},
			},
		});
		expect(
			(
				await local.auth.api.verifyJWT({
					body: { token: generic.token },
				})
			).payload,
		).toMatchObject({ sub: "generic-subject" });
	});

	it("rejects a remote signer that strips managed session authority", async () => {
		let signingCalls = 0;
		const local = await getTestInstance(
			managedJwtOptions({
				jwks: {
					remoteUrl: "https://example.com/.well-known/jwks.json",
					keyPairConfig: { alg: "EdDSA", crv: "Ed25519" },
				},
				jwt: {
					async sign(payload) {
						signingCalls += 1;
						const stripped = { ...payload };
						delete stripped[JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM];
						delete stripped[JWT_SESSION_SOURCE_SUBJECT_CLAIM];
						delete stripped[JWT_SESSION_SOURCE_ORGANIZATION_CLAIM];
						const encode = (value: unknown) =>
							Buffer.from(JSON.stringify(value)).toString("base64url");
						return `${encode({ alg: "EdDSA", typ: "JWT" })}.${encode(stripped)}.signature`;
					},
				},
			}),
		);
		const signedIn = await local.signInWithTestUser();
		const refresh = async () => {
			const headers = new Headers(signedIn.headers);
			headers.set("idempotency-key", generateCredentialOperationKey());
			return local.auth.handler(
				new Request("http://localhost:3000/api/auth/token", {
					method: "POST",
					headers,
				}),
			);
		};

		expect((await refresh()).status).toBe(500);
		expect((await refresh()).status).toBe(500);
		expect(signingCalls).toBe(2);
	});
});

describe("jwt", async () => {
	// Testing the default behavior
	const { auth, signInWithTestUser, cookieSetter } = await getTestInstance({
		plugins: [jwt({ disableSettingJwtHeader: true })],
		logger: {
			level: "error",
		},
	});

	const { headers } = await signInWithTestUser();
	const client = createAuthClient({
		plugins: [jwtClient()],
		baseURL: "http://localhost:3000/api/auth",
		fetchOptions: {
			customFetchImpl: async (url, init) => {
				return auth.handler(new Request(url, init));
			},
		},
	});

	it("does not mint a token as a side effect of reading the session", async () => {
		let token = "";
		await client.getSession({
			fetchOptions: {
				headers,
				onSuccess(context) {
					token = context.response.headers.get("set-auth-jwt") || "";
				},
			},
		});

		expect(token).toBe("");
	});

	it("keeps canonical POST /token functional", async () => {
		const setCookies = cookieSetter(headers);
		const token = await client.token({
			fetchOptions: {
				headers,
				onSuccess(context) {
					expect(context.response.headers.get("cache-control")).toBe(
						"no-store",
					);
					expect(context.response.headers.get("pragma")).toBe("no-cache");
					return setCookies(context);
				},
			},
		});

		expect(token.data?.token).toBeDefined();
	});

	it("survives a lost refresh response through an exact retry", async () => {
		const local = await getTestInstance({
			plugins: [jwt({ disableSettingJwtHeader: true })],
			logger: { level: "error" },
		});
		const signedIn = await local.signInWithTestUser();
		const operation = generateCredentialOperationKey();
		const refreshRequest = () => {
			const requestHeaders = new Headers(signedIn.headers);
			requestHeaders.set("idempotency-key", operation);
			return local.auth.handler(
				new Request("http://localhost:3000/api/auth/token", {
					method: "POST",
					headers: requestHeaders,
				}),
			);
		};
		const sessionCookieValue = (response: Response) =>
			response.headers
				.get("set-cookie")
				?.match(/clearance\.session_token=([^;]+)/)?.[1];

		const lost = await refreshRequest();
		expect(lost.status).toBe(200);
		const successorCookie = sessionCookieValue(lost);
		expect(successorCookie).toBeTruthy();

		const recoveryHeaders = new Headers(signedIn.headers);
		recoveryHeaders.set("idempotency-key", operation);
		const recovered = await local.auth.handler(
			new Request("http://localhost:3000/api/auth/get-session", {
				headers: recoveryHeaders,
			}),
		);
		expect(recovered.status).toBe(200);
		expect(sessionCookieValue(recovered)).toBe(successorCookie);
		const recoveredBody = await recovered.json();
		expect(recoveredBody.session.token).toBe(recoveredBody.session.id);

		const retry = await refreshRequest();
		expect(retry.status).toBe(200);
		expect(sessionCookieValue(retry)).toBe(successorCookie);
	});

	it.each([
		["missing", undefined],
		["different", generateCredentialOperationKey()],
	])(
		"denies consumed-session recovery with a %s idempotency key",
		async (_label, recoveryOperation) => {
			const local = await getTestInstance({
				plugins: [jwt({ disableSettingJwtHeader: true })],
				logger: { level: "error" },
			});
			const signedIn = await local.signInWithTestUser();
			const operation = generateCredentialOperationKey();
			const refreshHeaders = new Headers(signedIn.headers);
			refreshHeaders.set("idempotency-key", operation);
			const lost = await local.auth.handler(
				new Request("http://localhost:3000/api/auth/token", {
					method: "POST",
					headers: refreshHeaders,
				}),
			);
			expect(lost.status).toBe(200);

			const recoveryHeaders = new Headers(signedIn.headers);
			if (recoveryOperation) {
				recoveryHeaders.set("idempotency-key", recoveryOperation);
			}
			const denied = await local.auth.handler(
				new Request("http://localhost:3000/api/auth/get-session", {
					headers: recoveryHeaders,
				}),
			);
			expect(denied.status).toBe(200);
			expect(await denied.json()).toBeNull();
		},
	);

	it("uses POST and generates an idempotency key for each client refresh operation", async () => {
		const localClient = createAuthClient({
			plugins: [jwtClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) => {
					const request = new Request(url, init);
					expect(request.method).toBe("POST");
					expect(request.headers.get("idempotency-key")).toMatch(
						/^clr_op_v1_[A-Za-z0-9_-]{43}$/,
					);
					return auth.handler(request);
				},
			},
		});

		const token = await localClient.token({
			fetchOptions: {
				headers,
				onSuccess: cookieSetter(headers),
			},
		});
		expect(token.data?.token).toBeDefined();
	});

	it("rejects headerless refresh rotation", async () => {
		const headerless = new Headers(headers);
		headerless.delete("idempotency-key");
		await expect(
			auth.api.getToken({ headers: headerless }),
		).rejects.toMatchObject({
			status: "BAD_REQUEST",
			statusCode: 400,
		});
	});

	it("rejects a predictable repeated refresh operation key", async () => {
		const predictable = new Headers(headers);
		predictable.set("idempotency-key", "a".repeat(22));
		await expect(
			auth.api.getToken({ headers: predictable }),
		).rejects.toMatchObject({
			status: "BAD_REQUEST",
			statusCode: 400,
		});
	});

	it("Get JWKS", async () => {
		// If no JWK exists, this makes sure it gets added.
		// TODO: Replace this with a generate JWKS endpoint once it exists.
		const token = await client.token({
			fetchOptions: {
				headers,
				onSuccess: cookieSetter(headers),
			},
		});

		expect(token.data?.token).toBeDefined();

		const jwks = await client.jwks();

		expect(jwks.data?.keys).length.above(0);
		expect(jwks.data?.keys[0]!.alg).toBe("EdDSA");
	});

	it("Signed tokens can be validated with the JWKS", async () => {
		const token = await client.token({
			fetchOptions: {
				headers,
				onSuccess: cookieSetter(headers),
			},
		});

		const jwks = await client.jwks();

		const localJwks = createLocalJWKSet(jwks.data!);
		const decoded = await jwtVerify(token.data?.token!, localJwks);

		expect(decoded).toBeDefined();
		expect(decoded.payload.sid).toEqual(expect.any(String));
		expect(decoded.payload.session_family).toEqual(expect.any(String));
		expect(decoded.payload.session_generation).toBeGreaterThan(0);
	});

	it("caps access-token expiry at the authoritative session expiry", async () => {
		const local = await getTestInstance({
			plugins: [jwt({ jwt: { expirationTime: "5m" } })],
			logger: { level: "error" },
		});
		const signedIn = await local.signInWithTestUser();
		const cookie = signedIn.headers.get("cookie") || "";
		const signedValue = cookie.split("clearance.session_token=")[1] || "";
		const refreshSecret = signedValue.split(".")[0] || "";
		const expiresAt = new Date(Date.now() + 30_000);
		const context = await local.auth.$context;
		await context.internalAdapter.updateSession(refreshSecret, { expiresAt });
		const localClient = createAuthClient({
			plugins: [jwtClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) =>
					local.auth.handler(new Request(url, init)),
			},
		});
		const result = await localClient.token({
			fetchOptions: { headers: signedIn.headers },
		});
		const keys = await localClient.jwks();
		const decoded = await jwtVerify(
			result.data!.token,
			createLocalJWKSet(keys.data!),
		);
		expect(decoded.payload.exp).toBeLessThanOrEqual(
			Math.floor(expiresAt.getTime() / 1000),
		);
		expect(decoded.payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
	});

	it("should set subject to user id by default", async () => {
		const token = await client.token({
			fetchOptions: {
				headers,
				onSuccess: cookieSetter(headers),
			},
		});

		const jwks = await client.jwks();

		const localJwks = createLocalJWKSet(jwks.data!);
		const decoded = await jwtVerify(token.data?.token!, localJwks);
		expect(decoded.payload.sub).toBeDefined();
		expect(decoded.payload.sub).toBe(decoded.payload.id);
	});

	const algorithmsToTest: {
		keyPairConfig: JWKOptions;
		expectedOutcome: {
			ec: string;
			length: number;
			crv?: string | undefined;
			alg: string;
		};
	}[] = [
		{
			keyPairConfig: {
				alg: "EdDSA",
				crv: "Ed25519",
			},
			expectedOutcome: {
				ec: "OKP",
				length: 43,
				crv: "Ed25519",
				alg: "EdDSA",
			},
		},
		{
			keyPairConfig: {
				alg: "ES256",
			},
			expectedOutcome: {
				ec: "EC",
				length: 43,
				crv: "P-256",
				alg: "ES256",
			},
		},
		{
			keyPairConfig: {
				alg: "ES512",
			},
			expectedOutcome: {
				ec: "EC",
				length: 88,
				crv: "P-521",
				alg: "ES512",
			},
		},
		{
			keyPairConfig: {
				alg: "PS256",
			},
			expectedOutcome: {
				ec: "RSA",
				length: 342,
				alg: "PS256",
			},
		},
		{
			keyPairConfig: {
				alg: "RS256",
			},
			expectedOutcome: {
				ec: "RSA",
				length: 342,
				alg: "RS256",
			},
		},
	];

	for (const algorithm of algorithmsToTest) {
		const expectedOutcome = algorithm.expectedOutcome;
		for (const disablePrivateKeyEncryption of [false, true]) {
			const jwtOptions: JwtOptions = {
				disableSettingJwtHeader: true,
				jwks: {
					keyPairConfig: {
						...algorithm.keyPairConfig,
					},
					disablePrivateKeyEncryption: disablePrivateKeyEncryption,
				},
			};
			try {
				const { auth, signInWithTestUser, cookieSetter } =
					await getTestInstance({
					plugins: [jwt(jwtOptions)],
					logger: {
						level: "error",
					},
				});

				const alg: string =
					algorithm.keyPairConfig.alg +
					("crv" in algorithm.keyPairConfig
						? `(${algorithm.keyPairConfig.crv})`
						: "");
				const enc: string = disablePrivateKeyEncryption
					? " without private key encryption"
					: "";

				it(`${alg} algorithm${enc} can be used to generate JWKS`, async () => {
					// Unit test (JWS Supported key)
					const { publicWebKey, privateWebKey } =
						await generateExportedKeyPair(jwtOptions);
					for (const key of [publicWebKey, privateWebKey]) {
						expect(key.kty).toBe(expectedOutcome.ec);
						if (key.x) expect(key.x).toHaveLength(expectedOutcome.length);
						if (key.y) expect(key.y).toHaveLength(expectedOutcome.length);
						if (key.n) expect(key.n).toHaveLength(expectedOutcome.length);
					}

					// Functional test (JWKS)
					const jwks = await auth.api.getJwks();
					expect(jwks.keys.at(0)?.kty).toBe(expectedOutcome.ec);
					if (jwks.keys.at(0)?.crv)
						expect(jwks.keys.at(0)?.crv).toBe(expectedOutcome.crv);
					expect(jwks.keys.at(0)?.alg).toBe(expectedOutcome.alg);
					if (jwks.keys.at(0)?.x)
						expect(jwks.keys.at(0)?.x).toHaveLength(expectedOutcome.length);
					if (jwks.keys.at(0)?.y)
						expect(jwks.keys.at(0)?.y).toHaveLength(expectedOutcome.length);
					if (jwks.keys.at(0)?.n)
						expect(jwks?.keys.at(0)?.n).toHaveLength(expectedOutcome.length);
				});

				const client = createAuthClient({
					plugins: [jwtClient()],
					baseURL: "http://localhost:3000/api/auth",
					fetchOptions: {
						customFetchImpl: async (url, init) => {
							return auth.handler(new Request(url, init));
						},
					},
				});
				let headers: Headers | undefined = undefined;

				it(`${alg} algorithm${enc}: Client can sign in`, async () => {
					try {
						const { headers: heads } = await signInWithTestUser();
						headers = heads;
						expect(headers).toBeDefined();
					} catch (err) {
						console.error(err);
						expect.unreachable();
					}
				});

				it(`${alg} algorithm${enc}: Client gets a token`, async () => {
					const token = await client.token({
						fetchOptions: {
							headers,
							onSuccess: cookieSetter(headers!),
						},
					});

					expect(token.data?.token).toBeDefined();
				});

				it(`${alg} algorithm${enc}: session reads do not mint tokens`, async () => {
					let token = "";
					await client.getSession({
						fetchOptions: {
							headers,
							onSuccess(context) {
								token = context.response.headers.get("set-auth-jwt") || "";
							},
						},
					});

					expect(token).toBe("");
				});

				it(`${alg} algorithm${enc}: Signed tokens can be validated with the JWKS`, async () => {
					const token = await client.token({
						fetchOptions: {
							headers,
							onSuccess: cookieSetter(headers!),
						},
					});

					const jwks = await client.jwks();

					const localJwks = createLocalJWKSet(jwks.data!);
					const decoded = await jwtVerify(token.data?.token!, localJwks);

					expect(decoded).toBeDefined();
				});

				it(`${alg} algorithm${enc}: Should set subject to user id by default`, async () => {
					const token = await client.token({
						fetchOptions: {
							headers,
							onSuccess: cookieSetter(headers!),
						},
					});

					const jwks = await client.jwks();

					const localJwks = createLocalJWKSet(jwks.data!);
					const decoded = await jwtVerify(token.data?.token!, localJwks);
					expect(decoded.payload.sub).toBeDefined();
					expect(decoded.payload.sub).toBe(decoded.payload.id);
				});
			} catch (err) {
				console.error(err);
				expect.unreachable();
			}
		}
	}
});

describe.for([
	{
		alg: "EdDSA",
		crv: "Ed25519",
	},
	{
		alg: "ES256",
	},
	{
		alg: "ES512",
	},
	{
		alg: "PS256",
	},
	{
		alg: "RS256",
	},
] as JWKOptions[])("signJWT - alg: $alg", async (keyPairConfig) => {
	const { auth } = await getTestInstance({
		plugins: [
			jwt({
				jwks: {
					keyPairConfig,
				},
			}),
		],
		logger: {
			level: "error",
		},
	});

	it("should sign a JWT", async () => {
		const jwt = await auth.api.signJWT({
			body: {
				payload: {
					sub: "123",
					exp: 1000,
					iat: 1000,
					iss: "https://example.com",
					aud: "https://example.com",
					custom: "custom",
				},
			},
		});
		expect(jwt?.token).toBeDefined();
	});

	it("should be a valid JWT", async () => {
		const jwt = await auth.api.signJWT({
			body: {
				payload: {
					sub: "123",
					exp: Math.floor(Date.now() / 1000) + 600,
					iat: Math.floor(Date.now() / 1000),
					iss: "https://example.com",
					aud: "https://example.com",
					custom: "custom",
				},
			},
		});
		const jwks = await auth.api.getJwks();
		const localJwks = createLocalJWKSet(jwks);
		const decoded = await jwtVerify(jwt?.token!, localJwks);

		// Verify the kid from the JWT exists in the JWKS
		const kidFromJwt = decoded.protectedHeader.kid;
		const keyExists = jwks.keys.some((key) => key.kid === kidFromJwt);
		expect(keyExists).toBe(true);

		expect(decoded).toMatchObject({
			payload: {
				iss: "https://example.com",
				aud: "https://example.com",
				sub: "123",
				exp: expect.any(Number),
				iat: expect.any(Number),
				custom: "custom",
			},
			protectedHeader: {
				alg: keyPairConfig.alg,
				kid: expect.any(String),
			},
		});
	});

	it("shouldn't let you sign from a client", async () => {
		const client = createAuthClient({
			plugins: [jwtClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) => {
					return auth.handler(new Request(url, init));
				},
			},
		});
		const jwt = await client.$fetch("/sign-jwt", {
			method: "POST",
			body: {
				payload: { sub: "123" },
			},
		});
		expect(jwt.error?.status).toBe(404);
	});
});

describe("jwt - remote signing", async () => {
	it("should fail if sign is defined and remoteUrl is not", async () => {
		expect(() =>
			getTestInstance({
				plugins: [
					jwt({
						jwt: {
							sign: () => {
								return "123";
							},
						},
					}),
				],
			}),
		).toThrowError(
			"options.jwks.remoteUrl must be set when using options.jwt.sign",
		);
	});
});

describe("jwt - remote url", async () => {
	it("should require specifying the alg when using remoteUrl", async () => {
		expect(() =>
			getTestInstance({
				plugins: [
					jwt({
						jwks: {
							remoteUrl: "https://example.com/.well-known/jwks.json",
						},
					}),
				],
			}),
		).toThrowError(
			"options.jwks.keyPairConfig.alg must be specified when using the oidc plugin with options.jwks.remoteUrl",
		);
	});

	it("should accept remoteUrl with alg specified", async () => {
		const { auth } = await getTestInstance({
			plugins: [
				jwt({
					disableSettingJwtHeader: true,
					jwks: {
						remoteUrl: "https://example.com/.well-known/jwks.json",
						keyPairConfig: {
							alg: "ES256",
						},
					},
				}),
			],
		});
		expect(auth).toBeDefined();
	});

	it("should disable /jwks endpoint when remoteUrl is configured", async () => {
		const { auth } = await getTestInstance({
			plugins: [
				jwt({
					disableSettingJwtHeader: true,
					jwks: {
						remoteUrl: "https://example.com/.well-known/jwks.json",
						keyPairConfig: {
							alg: "ES256",
						},
					},
				}),
			],
		});

		const client = createAuthClient({
			plugins: [jwtClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) => {
					return auth.handler(new Request(url, init));
				},
			},
		});

		const response = await client.$fetch<JSONWebKeySet>("/jwks");
		expect(response.error?.status).toBe(404);
	});

	it("should work with different algorithms when remoteUrl is set", async () => {
		const algorithms = ["ES256", "ES512", "RS256", "PS256", "EdDSA"];

		for (const alg of algorithms) {
			const { auth } = await getTestInstance({
				plugins: [
					jwt({
						jwks: {
							remoteUrl: "https://example.com/.well-known/jwks.json",
							keyPairConfig: {
								alg: alg as any,
							},
						},
					}),
				],
			});
			expect(auth).toBeDefined();
		}
	}, 15000);

	it("should still allow token generation when remoteUrl is set", async () => {
		const { auth, signInWithTestUser, cookieSetter } = await getTestInstance({
			plugins: [
				jwt({
					jwks: {
						remoteUrl: "https://example.com/.well-known/jwks.json",
						keyPairConfig: {
							alg: "ES256",
						},
					},
				}),
			],
		});

		const { headers } = await signInWithTestUser();

		const client = createAuthClient({
			plugins: [jwtClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) => {
					return auth.handler(new Request(url, init));
				},
			},
		});

		const token = await client.token({
			fetchOptions: {
				headers,
			},
		});

		expect(token.data?.token).toBeDefined();
		expect(token.data?.token).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/); // JWT format
	});

	it("should work with custom sign function and remoteUrl", async () => {
		const mockSignFunction = (payload: any) => {
			// Mock JWT with test signature
			const header = Buffer.from(
				JSON.stringify({ alg: "ES256", typ: "JWT" }),
			).toString("base64url");
			const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
			const signature = "mock-signature";
			return `${header}.${body}.${signature}`;
		};

		const { auth, signInWithTestUser, cookieSetter } = await getTestInstance({
			plugins: [
				jwt({
					jwks: {
						remoteUrl: "https://example.com/.well-known/jwks.json",
						keyPairConfig: {
							alg: "ES256",
						},
					},
					jwt: {
						sign: mockSignFunction,
					},
				}),
			],
		});

		const { headers } = await signInWithTestUser();

		const client = createAuthClient({
			plugins: [jwtClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) => {
					return auth.handler(new Request(url, init));
				},
			},
		});

		const token = await client.token({
			fetchOptions: {
				headers,
			},
		});

		expect(token.data?.token).toBeDefined();
		// Verify it's using our mock sign function
		expect(token.data?.token).toContain("mock-signature");
	});

	it("should validate that remoteUrl is a valid URL format", async () => {
		const invalidUrls = [
			"not-a-url",
			"http://",
			"//example.com",
			"example.com/jwks",
		];

		for (const url of invalidUrls) {
			// While the current implementation doesn't validate URL format,
			// this test documents expected behavior
			const { auth } = await getTestInstance({
				plugins: [
					jwt({
						jwks: {
							remoteUrl: url,
							keyPairConfig: {
								alg: "ES256",
							},
						},
					}),
				],
			});
			// Currently passes, but documents that URL validation might be needed
			expect(auth).toBeDefined();
		}
	});

	it("should work with remoteUrl pointing to different paths", async () => {
		const validPaths = [
			"https://example.com/.well-known/jwks.json",
			"https://auth.example.com/jwks",
			"https://api.example.com/v1/keys",
			"https://example.com:8080/jwks.json",
		];

		for (const url of validPaths) {
			const { auth } = await getTestInstance({
				plugins: [
					jwt({
						jwks: {
							remoteUrl: url,
							keyPairConfig: {
								alg: "ES256",
							},
						},
					}),
				],
			});
			expect(auth).toBeDefined();
		}
	});

	it("should handle remoteUrl with query parameters", async () => {
		const { auth } = await getTestInstance({
			plugins: [
				jwt({
					jwks: {
						remoteUrl: "https://example.com/jwks?version=1&format=json",
						keyPairConfig: {
							alg: "RS256",
						},
					},
				}),
			],
		});
		expect(auth).toBeDefined();
	});

	it("should not interfere with other JWT endpoints when remoteUrl is set", async () => {
		const { auth, signInWithTestUser, cookieSetter } = await getTestInstance({
			plugins: [
				jwt({
					disableSettingJwtHeader: true,
					jwks: {
						remoteUrl: "https://example.com/.well-known/jwks.json",
						keyPairConfig: {
							alg: "ES256",
						},
					},
				}),
			],
		});

		const { headers } = await signInWithTestUser();

		const client = createAuthClient({
			plugins: [jwtClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) => {
					return auth.handler(new Request(url, init));
				},
			},
		});

		// Test that /token endpoint still works
		const tokenResponse = await client.token({
			fetchOptions: {
				headers,
				onSuccess: cookieSetter(headers),
			},
		});
		expect(tokenResponse.data?.token).toBeDefined();

		// Test that /jwks endpoint returns 404
		const jwksResponse = await client.$fetch("/jwks");
		expect(jwksResponse.error?.status).toBe(404);

		// Test that session endpoint still returns JWT header
		let jwtHeader = "";
		await client.getSession({
			fetchOptions: {
				headers,
				onSuccess(context) {
					jwtHeader = context.response.headers.get("set-auth-jwt") || "";
				},
			},
		});
		expect(jwtHeader).toBe("");
	});
});

describe("jwt - custom adapter", async () => {
	it("should use custom adapter", async () => {
		const storage: Jwk[] = [];
		const { auth } = await getTestInstance({
			plugins: [
				jwt({
					adapter: {
						getJwks: async () => {
							return storage;
						},
						createJwk: async (data) => {
							const key = {
								...data,
								id: crypto.randomUUID(),
								createdAt: new Date(),
							};
							storage.push(key);
							return key;
						},
					},
				}),
			],
		});
		const token = await auth.api.signJWT({
			body: {
				payload: {
					sub: "123",
				},
			},
		});
		expect(token?.token).toBeDefined();
		expect(storage.length).toBe(1);
	});
});

describe("jwt private key storage", () => {
	it("binds protection to the persisted public key and fails closed", async () => {
		const storage: Jwk[] = [];
		const contexts: Array<{
			operation: "encrypt" | "decrypt";
			publicKey: string;
		}> = [];
		let rejectDecryption = false;
		const { auth } = await getTestInstance({
			plugins: [
				jwt({
					jwks: {
						privateKeyStorage: {
							async encrypt(privateKey, publicKey) {
								contexts.push({ operation: "encrypt", publicKey });
								return JSON.stringify({ privateKey, publicKey });
							},
							async decrypt(encryptedPrivateKey, publicKey) {
								contexts.push({ operation: "decrypt", publicKey });
								if (rejectDecryption) throw new Error("protector unavailable");
								const stored = JSON.parse(encryptedPrivateKey) as {
									privateKey: string;
									publicKey: string;
								};
								if (stored.publicKey !== publicKey) {
									throw new Error("wrong public key context");
								}
								return stored.privateKey;
							},
						},
					},
					adapter: {
						getJwks: async () => storage,
						createJwk: async (data) => {
							const key = {
								...data,
								id: crypto.randomUUID(),
								createdAt: new Date(),
							};
							storage.push(key);
							return key;
						},
					},
				}),
			],
		});

		await auth.api.signJWT({ body: { payload: { sub: "subject" } } });
		expect(contexts).toEqual([
			expect.objectContaining({ operation: "encrypt" }),
			expect.objectContaining({ operation: "decrypt" }),
		]);
		expect(contexts[0]?.publicKey).toBe(storage[0]?.publicKey);
		expect(contexts[1]?.publicKey).toBe(storage[0]?.publicKey);

		const originalPublicKey = storage[0]!.publicKey;
		storage[0] = {
			...storage[0]!,
			publicKey: JSON.stringify({
				...JSON.parse(originalPublicKey),
				kid: "wrong-context",
			}),
		};
		await expect(
			auth.api.signJWT({ body: { payload: { sub: "subject" } } }),
		).rejects.toThrow(
			"Failed to decrypt private key with configured private key storage",
		);

		storage[0] = { ...storage[0]!, publicKey: originalPublicKey };
		rejectDecryption = true;
		await expect(
			auth.api.signJWT({ body: { payload: { sub: "subject" } } }),
		).rejects.toThrow(
			"Failed to decrypt private key with configured private key storage",
		);
	});
});

describe("jwt - custom jwksPath", async () => {
	it("should use custom jwksPath when specified", async () => {
		const { auth } = await getTestInstance({
			plugins: [
				jwt({
					jwks: {
						jwksPath: "/.well-known/jwks.json",
					},
				}),
			],
		});

		const client = createAuthClient({
			plugins: [jwtClient({ jwks: { jwksPath: "/.well-known/jwks.json" } })],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) => {
					return auth.handler(new Request(url, init));
				},
			},
		});

		const jwks = await client.jwks();
		expect(jwks.error).toBeNull();
		expect(jwks.data?.keys).toBeDefined();
		expect(jwks.data?.keys.length).toBeGreaterThan(0);

		// Verify old /jwks endpoint is not found
		const oldJwks = await client.$fetch<JSONWebKeySet>("/jwks");
		expect(oldJwks.error?.status).toBe(404);
	});
});

describe("toExpJWT", () => {
	const iat = 1000; // base iat for testing

	describe("with number input", () => {
		it("should return the number as-is", () => {
			expect(toExpJWT(3600, iat)).toBe(3600);
			expect(toExpJWT(0, iat)).toBe(0);
			expect(toExpJWT(9999999, iat)).toBe(9999999);
		});
	});

	describe("with Date input", () => {
		it("should convert Date to seconds timestamp", () => {
			const date = new Date("2024-01-01T00:00:00.000Z");
			const expectedSeconds = Math.floor(date.getTime() / 1000);
			expect(toExpJWT(date, iat)).toBe(expectedSeconds);
		});

		it("should floor milliseconds", () => {
			const date = new Date(1704067200500);
			expect(toExpJWT(date, iat)).toBe(1704067200);
		});
	});

	describe("with valid TimeString input", () => {
		it("should parse short format and add to iat", () => {
			expect(toExpJWT("1h", iat)).toBe(iat + 3600);
			expect(toExpJWT("7d", iat)).toBe(iat + 604800);
			expect(toExpJWT("30m", iat)).toBe(iat + 1800);
			expect(toExpJWT("1s", iat)).toBe(iat + 1);
		});

		it("should parse long format and add to iat", () => {
			expect(toExpJWT("1 hour", iat)).toBe(iat + 3600);
			expect(toExpJWT("7 days", iat)).toBe(iat + 604800);
			expect(toExpJWT("30 minutes", iat)).toBe(iat + 1800);
		});

		it("should handle negative values", () => {
			expect(toExpJWT("-1h", iat)).toBe(iat - 3600);
			expect(toExpJWT("1h ago", iat)).toBe(iat - 3600);
		});
	});

	describe("with invalid string input", () => {
		it("should throw TypeError for invalid format", () => {
			expect(() => toExpJWT("invalid" as any, iat)).toThrow(TypeError);
			expect(() => toExpJWT("" as any, iat)).toThrow(TypeError);
			expect(() => toExpJWT("abc123" as any, iat)).toThrow(TypeError);
		});
	});
});
