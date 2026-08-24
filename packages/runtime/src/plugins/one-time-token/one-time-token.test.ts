import type {
	ClearancePlugin,
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import { createAuthMiddleware } from "@clearance/core/api";
import { APIError } from "@clearance/core/error";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseCookies } from "../../cookies";
import { makeSignature } from "../../crypto";
import { attachInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { createInternalSessionIssuanceContext } from "../../internal/session-issuance-context";
import { getTestInstance } from "../../test-utils/test-instance";
import { isAPIError } from "../../utils/is-api-error";
import { oneTimeToken } from ".";
import { oneTimeTokenClient } from "./client";
import { defaultKeyHasher } from "./utils";

const managedOneTimeTokenIdentity = {
	projectId: "one-time-token-policy-project",
	environmentId: "one-time-token-policy-environment",
} satisfies RuntimeAuthenticationPolicyIdentity;

const managedOneTimeTokenPolicy = {
	passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	factorLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	minimumAssurance: "single_factor",
	allowedFactors: { totp: true, passkey: true },
	trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
	assuranceMaxAgeSeconds: 300,
} satisfies RuntimeAuthenticationPolicy;

async function createManagedOneTimeTokenRuntime() {
	let revision = "1";
	let organizationMembership: string | null = null;
	let readerError: Error | null = null;
	const secondaryStore = new Map<string, string>();
	const options = {
		session: {
			storeSessionInDatabase: true,
			additionalFields: {
				activeOrganizationId: {
					type: "string",
					required: false,
				},
			},
		},
		secondaryStorage: {
			namespace: "managed-one-time-token-policy",
			get: async (key: string) => secondaryStore.get(key) ?? null,
			set: async (key: string, value: string) => {
				secondaryStore.set(key, value);
			},
			delete: async (key: string) => {
				secondaryStore.delete(key);
			},
		},
		plugins: [oneTimeToken()],
	} satisfies ClearanceOptions;
	attachInternalAuthenticationPolicy(options, {
		identity: managedOneTimeTokenIdentity,
		reader: {
			async readForSubject(input) {
				if (readerError) throw readerError;
				return {
					scope: managedOneTimeTokenIdentity,
					subjectId: input.subjectId,
					revision,
					environment: managedOneTimeTokenPolicy,
					organizationMembership:
						input.organizationId &&
						organizationMembership === input.organizationId
							? {
								subjectId: input.subjectId,
								organizationId: input.organizationId,
							}
							: null,
					organizationOverride: null,
					effective: managedOneTimeTokenPolicy,
				};
			},
		},
	});
	const runtime = await getTestInstance(options, {
		disableTestUser: true,
		clientOptions: { plugins: [oneTimeTokenClient()] },
	});
	return {
		...runtime,
		secondaryStore,
		setRevision(value: string) {
			revision = value;
		},
		setOrganizationMembership(value: string | null) {
			organizationMembership = value;
		},
		setReaderError(value: Error | null) {
			readerError = value;
		},
	};
}

function rawSetCookieEntries(headers: Headers) {
	if (typeof headers.getSetCookie === "function") {
		return headers.getSetCookie();
	}
	const header = headers.get("set-cookie");
	return header ? header.split(/,(?=\s*[^;,]+=)/) : [];
}

const unrelatedVerifyCookiePlugin = {
	id: "one-time-token-unrelated-cookie",
	hooks: {
		after: [
			{
				matcher: (ctx) => ctx.path === "/one-time-token/verify",
				handler: createAuthMiddleware(async (ctx) => {
					ctx.setCookie("unrelated", "preserved");
				}),
			},
		],
	},
} satisfies ClearancePlugin;

describe("One-time token", async () => {
	const { auth, signInWithTestUser, client } = await getTestInstance(
		{
			plugins: [oneTimeToken()],
		},
		{
			clientOptions: {
				plugins: [oneTimeTokenClient()],
			},
		},
	);

	afterEach(() => {
		vi.useRealTimers();
	});

	it("should work", async () => {
		const { headers } = await signInWithTestUser();
		const response = await auth.api.generateOneTimeToken({
			headers,
		});
		expect(response.token).toBeDefined();
		const session = await auth.api.verifyOneTimeToken({
			body: {
				token: response.token,
			},
		});
		expect(session).toBeDefined();
		const shouldFail = await auth.api
			.verifyOneTimeToken({
				body: {
					token: response.token,
				},
			})
			.catch((e) => e);
		expect(isAPIError(shouldFail)).toBeTruthy();
	});

	it("should expire", async () => {
		const { headers } = await signInWithTestUser();
		const response = await auth.api.generateOneTimeToken({
			headers,
		});
		vi.useFakeTimers();
		await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
		const shouldFail = await auth.api
			.verifyOneTimeToken({
				body: {
					token: response.token,
				},
			})
			.catch((e) => e);
		expect(isAPIError(shouldFail)).toBeTruthy();
		vi.useRealTimers();
	});

	// A one-time token is single-use: racing two redemptions of the same
	// valid token must burn the record exactly once, so only one caller
	// gets a session and the other is rejected.
	it("should only redeem a token once under concurrent verification", async () => {
		const { headers } = await signInWithTestUser();
		const response = await auth.api.generateOneTimeToken({
			headers,
		});
		expect(response.token).toBeDefined();

		const results = await Promise.allSettled([
			auth.api.verifyOneTimeToken({ body: { token: response.token } }),
			auth.api.verifyOneTimeToken({ body: { token: response.token } }),
		]);

		const fulfilled = results.filter((r) => r.status === "fulfilled");
		const rejected = results.filter((r) => r.status === "rejected");
		expect(fulfilled).toHaveLength(1);
		expect(rejected).toHaveLength(1);
		expect(isAPIError((rejected[0] as PromiseRejectedResult).reason)).toBe(
			true,
		);
	});

	it("should work with client", async () => {
		const { headers } = await signInWithTestUser();
		const response = await client.oneTimeToken.generate({
			fetchOptions: {
				headers,
				throw: true,
			},
		});
		expect(response.token).toBeDefined();
		const session = await client.oneTimeToken.verify({
			token: response.token,
		});
		expect(session.data?.session).toBeDefined();
	});

	it("should reject token when underlying session has expired", async () => {
		const testInstance = await getTestInstance(
			{
				session: {
					expiresIn: 60,
					updateAge: 0,
				},
				plugins: [oneTimeToken({ expiresIn: 10 })],
			},
			{
				clientOptions: {
					plugins: [oneTimeTokenClient()],
				},
			},
		);

		const { headers } = await testInstance.signInWithTestUser();

		const response = await testInstance.auth.api.generateOneTimeToken({
			headers,
		});
		expect(response.token).toBeDefined();

		vi.useFakeTimers();
		await vi.advanceTimersByTimeAsync(2 * 60 * 1000);

		const shouldFail = await testInstance.auth.api
			.verifyOneTimeToken({
				body: {
					token: response.token,
				},
			})
			.catch((e) => e);

		expect(isAPIError(shouldFail)).toBeTruthy();
		expect(shouldFail.body.message).toBe("Session not found");

		vi.useRealTimers();
	});

	describe("should work with different storeToken options", () => {
		describe("hashed", async () => {
			const { auth, signInWithTestUser } = await getTestInstance(
				{
					plugins: [
						oneTimeToken({
							storeToken: "hashed",
							async generateToken(session, ctx) {
								return "123456";
							},
						}),
					],
				},
				{
					clientOptions: {
						plugins: [oneTimeTokenClient()],
					},
				},
			);
			const { internalAdapter } = await auth.$context;

			it("should work with hashed", async () => {
				const { headers } = await signInWithTestUser();
				const response = await auth.api.generateOneTimeToken({
					headers,
				});
				expect(response.token).toBeDefined();
				expect(response.token).toBe("123456");

				const hashedToken = await defaultKeyHasher(response.token);
				const storedToken = await internalAdapter.findVerificationValueAndPruneExpired(
					`one-time-token:${hashedToken}`,
				);
				expect(storedToken).toBeDefined();

				const session = await auth.api.verifyOneTimeToken({
					body: {
						token: response.token,
					},
				});
				expect(session).toBeDefined();
				expect(session.user.email).toBeDefined();
			});
		});

		describe("custom hasher", async () => {
			const { auth, signInWithTestUser } = await getTestInstance({
				plugins: [
					oneTimeToken({
						storeToken: {
							type: "custom-hasher",
							hash: async (token) => {
								return token + "hashed";
							},
						},
						async generateToken(session, ctx) {
							return "123456";
						},
					}),
				],
			});
			const { internalAdapter } = await auth.$context;
			it("should work with custom hasher", async () => {
				const { headers } = await signInWithTestUser();
				const response = await auth.api.generateOneTimeToken({
					headers,
				});
				expect(response.token).toBeDefined();
				expect(response.token).toBe("123456");

				const hashedToken = response.token + "hashed";
				const storedToken = await internalAdapter.findVerificationValueAndPruneExpired(
					`one-time-token:${hashedToken}`,
				);
				expect(storedToken).toBeDefined();

				const session = await auth.api.verifyOneTimeToken({
					body: {
						token: response.token,
					},
				});
				expect(session).toBeDefined();
			});
		});
	});

	describe("disableClientRequest option", async () => {
		const { auth, signInWithTestUser, client } = await getTestInstance(
			{
				plugins: [
					oneTimeToken({
						disableClientRequest: true,
					}),
				],
			},
			{
				clientOptions: {
					plugins: [oneTimeTokenClient()],
				},
			},
		);

		it("should allow server-side requests", async () => {
			const { headers } = await signInWithTestUser();
			const response = await auth.api.generateOneTimeToken({
				headers,
			});
			expect(response.token).toBeDefined();
		});

		it("should reject client requests when disableClientRequest is true", async () => {
			const { headers } = await signInWithTestUser();
			const shouldFail = await client.oneTimeToken.generate({
				fetchOptions: {
					headers,
				},
			});
			expect(shouldFail.error?.message).toBe("Client requests are disabled");
		});
	});

	describe("disableSetSessionCookie option", async () => {
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				oneTimeToken({
					disableSetSessionCookie: true,
				}),
			],
		});

		it("should not set session cookie when disableSetSessionCookie is true", async () => {
			const { headers } = await signInWithTestUser();
			const response = await auth.api.generateOneTimeToken({
				headers,
			});
			expect(response.token).toBeDefined();

			const verifyResponse = await auth.api.verifyOneTimeToken({
				body: {
					token: response.token,
				},
				asResponse: true,
			});

			const setCookieHeader = verifyResponse.headers.get("set-cookie");
			expect(setCookieHeader).toBeNull();
		});

		it("should set session cookie by default", async () => {
			const defaultInstance = await getTestInstance({
				plugins: [oneTimeToken()],
			});

			const { headers } = await defaultInstance.signInWithTestUser();
			const response = await defaultInstance.auth.api.generateOneTimeToken({
				headers,
			});

			const verifyResponse = await defaultInstance.auth.api.verifyOneTimeToken({
				body: {
					token: response.token,
				},
				asResponse: true,
			});

			const setCookieHeader = verifyResponse.headers.get("set-cookie");
			expect(setCookieHeader).toBeDefined();
			expect(setCookieHeader).toContain("clearance.session_token");
		});
	});

	it("does not publish cookies when cache versioning fails after redemption", async () => {
		const cacheVersionFailure = new APIError("INTERNAL_SERVER_ERROR", {
			message: "cache version unavailable",
		});
		let failCacheVersion = false;
		const instance = await getTestInstance({
			session: {
				cookieCache: {
					enabled: true,
					version: () => {
						if (failCacheVersion) throw cacheVersionFailure;
						return "1";
					},
				},
			},
			plugins: [oneTimeToken(), unrelatedVerifyCookiePlugin],
		});
		const { headers } = await instance.signInWithTestUser();
		const generated = await instance.auth.api.generateOneTimeToken({ headers });
		failCacheVersion = true;

		const failed = await instance.auth.api.verifyOneTimeToken({
			body: { token: generated.token },
			asResponse: true,
		});

		expect(failed.status).toBe(500);
		const cookies = rawSetCookieEntries(failed.headers);
		expect(cookies).toContainEqual(
			expect.stringMatching(/^unrelated=preserved(?:;|$)/),
		);
		expect(
			cookies.some((cookie) =>
				/^clearance\.(?:session_token|session_data|account_data|dont_remember)(?:\.\d+)?=/.test(
					cookie,
				),
			),
		).toBe(false);

		const burned = await instance.auth.api
			.verifyOneTimeToken({ body: { token: generated.token } })
			.catch((error) => error);
		expect(isAPIError(burned)).toBe(true);
		expect(burned.body.message).toBe("Invalid token");
	});

	describe("setOttHeaderOnNewSession option", async () => {
		it("should set OTT header on new session when enabled", async () => {
			const testInstance = await getTestInstance({
				plugins: [
					oneTimeToken({
						setOttHeaderOnNewSession: true,
					}),
				],
			});

			const response = await testInstance.auth.api.signUpEmail({
				body: {
					email: "ott-header-test@test.com",
					password: "password123",
					name: "OTT Header Test",
				},
				asResponse: true,
			});

			const ottHeader = response.headers.get("set-ott");
			expect(ottHeader).toBeDefined();
			expect(ottHeader).toHaveLength(32);

			const exposeHeaders = response.headers.get(
				"access-control-expose-headers",
			);
			expect(exposeHeaders).toContain("set-ott");
		});

		it("should not set OTT header on new session by default", async () => {
			const testInstance = await getTestInstance({
				plugins: [oneTimeToken()],
			});

			const response = await testInstance.auth.api.signUpEmail({
				body: {
					email: "ott-header-test-default@test.com",
					password: "password123",
					name: "OTT Header Test Default",
				},
				asResponse: true,
			});

			const ottHeader = response.headers.get("set-ott");
			expect(ottHeader).toBeNull();
		});

		it("should set OTT header on sign in when enabled", async () => {
			const testInstance = await getTestInstance({
				plugins: [
					oneTimeToken({
						setOttHeaderOnNewSession: true,
					}),
				],
			});

			// First create a user
			await testInstance.auth.api.signUpEmail({
				body: {
					email: "ott-signin-test@test.com",
					password: "password123",
					name: "OTT SignIn Test",
				},
			});

			// Then sign in
			const response = await testInstance.auth.api.signInEmail({
				body: {
					email: "ott-signin-test@test.com",
					password: "password123",
				},
				asResponse: true,
			});

			const ottHeader = response.headers.get("set-ott");
			expect(ottHeader).toBeDefined();
			expect(ottHeader).toHaveLength(32);
		});
	});
});

describe("one-time token managed session authority", () => {
	it("burns a policy-revised token without publishing an authenticated cookie", async () => {
		const runtime = await createManagedOneTimeTokenRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-ott-revision@example.test",
				password: "password",
				name: "Managed OTT Revision",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const generated = await runtime.auth.api.generateOneTimeToken({ headers });
		runtime.setRevision("2");
		let setCookie = "not-observed";
		const redeemed = await runtime.client.oneTimeToken.verify({
			token: generated.token,
			fetchOptions: {
				onResponse(context) {
					setCookie = context.response.headers.get("set-cookie") || "";
				},
			},
		});

		expect(redeemed.error).not.toBeNull();
		expect(setCookie).not.toContain("clearance.session_token=");
		runtime.setRevision("1");
		const burned = await runtime.auth.api
			.verifyOneTimeToken({ body: { token: generated.token } })
			.catch((error) => error);
		expect(isAPIError(burned)).toBe(true);
		expect(burned.body.message).toBe("Invalid token");
	});

	it("rejects a token bound to a rotated source credential without publishing a cookie", async () => {
		const runtime = await createManagedOneTimeTokenRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-ott-rotation@example.test",
				password: "password",
				name: "Managed OTT Rotation",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const generated = await runtime.auth.api.generateOneTimeToken({ headers });
		const sourceCredential =
			Object.fromEntries(parseCookies(headers.get("cookie") || ""))[
				"clearance.session_token"
			]?.split(".")[0] || "";
		expect(sourceCredential).not.toBe("");
		const context = await runtime.auth.$context;
		const rotated = await context.internalAdapter.rotateSessionCredential(
			sourceCredential,
		);
		expect(rotated?.refreshToken).toEqual(expect.any(String));
		let setCookie = "not-observed";
		const redeemed = await runtime.client.oneTimeToken.verify({
			token: generated.token,
			fetchOptions: {
				onResponse(context) {
					setCookie = context.response.headers.get("set-cookie") || "";
				},
			},
		});

		expect(redeemed.error).not.toBeNull();
		expect(setCookie).not.toContain("clearance.session_token=");
	});

	it("rejects membership removal for an exact organization-bound source session", async () => {
		const runtime = await createManagedOneTimeTokenRuntime();
		const context = await runtime.auth.$context;
		const organizationId = "managed-ott-organization";
		const user = await context.internalAdapter.createUser({
			email: "managed-ott-membership@example.test",
			name: "Managed OTT Membership",
		});
		runtime.setOrganizationMembership(organizationId);
		const session = await context.internalAdapter.createSession(
			user.id,
			false,
			{ activeOrganizationId: organizationId },
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
				targetOrganizationId: organizationId,
			}),
		);
		const headers = new Headers({
			cookie: `clearance.session_token=${session.token}.${await makeSignature(session.token, context.secret)}`,
		});
		const generated = await runtime.auth.api.generateOneTimeToken({ headers });
		runtime.setOrganizationMembership(null);
		let setCookie = "not-observed";
		const redeemed = await runtime.client.oneTimeToken.verify({
			token: generated.token,
			fetchOptions: {
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});

		expect(redeemed.error).not.toBeNull();
		expect(setCookie).not.toContain("clearance.session_token=");
		runtime.setOrganizationMembership(organizationId);
		const burned = await runtime.auth.api
			.verifyOneTimeToken({ body: { token: generated.token } })
			.catch((error) => error);
		expect(isAPIError(burned)).toBe(true);
		expect(burned.body.message).toBe("Invalid token");
	});

	it("burns a token when the managed policy reader fails", async () => {
		const runtime = await createManagedOneTimeTokenRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-ott-reader-failure@example.test",
				password: "password",
				name: "Managed OTT Reader Failure",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const generated = await runtime.auth.api.generateOneTimeToken({ headers });
		runtime.setReaderError(new Error("policy reader unavailable"));
		await expect(
			runtime.auth.api.verifyOneTimeToken({ body: { token: generated.token } }),
		).rejects.toThrow("Authentication policy authority is unavailable");
		runtime.setReaderError(null);
		const burned = await runtime.auth.api
			.verifyOneTimeToken({ body: { token: generated.token } })
			.catch((error) => error);
		expect(isAPIError(burned)).toBe(true);
		expect(burned.body.message).toBe("Invalid token");
	});

	it("allows exactly one managed redemption to publish the source session", async () => {
		const runtime = await createManagedOneTimeTokenRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-ott-concurrent@example.test",
				password: "password",
				name: "Managed OTT Concurrent",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const generated = await runtime.auth.api.generateOneTimeToken({ headers });
		const source = await runtime.client.getSession({ fetchOptions: { headers } });
		const sourceCredential =
			Object.fromEntries(parseCookies(headers.get("cookie") || ""))["clearance.session_token"]
				?.split(".")[0] || "";
		const results = await Promise.allSettled([
			runtime.auth.api.verifyOneTimeToken({
				body: { token: generated.token },
				asResponse: true,
			}),
			runtime.auth.api.verifyOneTimeToken({
				body: { token: generated.token },
				asResponse: true,
			}),
		]);
		const fulfilled = results.filter(
			(result): result is PromiseFulfilledResult<Response> =>
				result.status === "fulfilled",
		);
		expect(fulfilled).toHaveLength(2);
		const winner = fulfilled.find((result) => result.value.status === 200)?.value;
		const loser = fulfilled.find((result) => result.value.status === 400)?.value;
		expect(winner).toBeDefined();
		expect(loser).toBeDefined();
		const winnerResponse = winner!;
		const winnerBody = await winnerResponse.clone().json();
		expect(winnerBody.session.id).toBe(source.data?.session.id);
		const rawSessionCookies = rawSetCookieEntries(winnerResponse.headers).filter(
			(entry) => entry.trim().startsWith("clearance.session_token="),
		);
		expect(rawSessionCookies).toHaveLength(1);
		expect(
			rawSessionCookies[0]!.split(";", 1)[0]!.split("=", 2)[1]!.split(".")[0],
		).toBe(sourceCredential);
		const loserBody = await loser!.clone().json();
		expect(loserBody.message).toBe("Invalid token");
		const third = await runtime.auth.api
			.verifyOneTimeToken({ body: { token: generated.token } })
			.catch((error) => error);
		expect(isAPIError(third)).toBe(true);
		expect(third.body.message).toBe("Invalid token");
	});
});
