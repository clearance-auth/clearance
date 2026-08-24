import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { clearance } from "../../auth/full";
import { createAuthClient } from "../../client";
import { getMigrations } from "../../db/get-migration";
import { attachInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { readInternalSessionIssuanceContext } from "../../internal/session-issuance-context";
import { getTestInstance } from "../../test-utils/test-instance";
import { magicLink } from ".";
import { magicLinkClient } from "./client";
import { defaultKeyHasher } from "./utils";

type VerificationEmail = {
	email: string;
	token: string;
	url: string;
	metadata?: Record<string, any>;
};

async function managedMagicLinkTestRuntime(
	minimumAssurance: RuntimeAuthenticationPolicy["minimumAssurance"],
) {
	const database = new DatabaseSync(":memory:");
	let sent: VerificationEmail = { email: "", token: "", url: "" };
	const identity = {
		projectId: "magic-link-policy-project",
		environmentId: "magic-link-policy-environment",
	} satisfies RuntimeAuthenticationPolicyIdentity;
	const policy = {
		passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
		factorLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
		minimumAssurance,
		allowedFactors: { totp: true, passkey: true },
		trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
		assuranceMaxAgeSeconds: 300,
	} satisfies RuntimeAuthenticationPolicy;
	const options = {
		baseURL: "http://localhost:3000",
		secret: "managed-magic-link-test-secret",
		database,
		plugins: [
			magicLink({
				async sendMagicLink(data) {
					sent = data;
				},
			}),
		],
	} satisfies ClearanceOptions;
	attachInternalAuthenticationPolicy(options, {
		identity,
		reader: {
			async readForSubject(input) {
				return {
					scope: identity,
					subjectId: input.subjectId,
					revision: "1",
					environment: policy,
					organizationMembership: null,
					organizationOverride: null,
					effective: policy,
				};
			},
		},
	});
	await (await getMigrations(options)).runMigrations();
	return { auth: clearance(options), database, readSent: () => sent };
}

describe("magic-link managed authentication transactions", () => {
	it("rolls back token adoption and identity creation when policy rejects", async () => {
		const runtime = await managedMagicLinkTestRuntime("multi_factor");
		const email = "managed-magic-link-reject@example.test";
		try {
			await runtime.auth.api.signInMagicLink({
				body: { email },
				headers: new Headers(),
			});
			await expect(
				runtime.auth.api.magicLinkVerify({
					query: { token: runtime.readSent().token },
					headers: new Headers(),
				}),
			).rejects.toMatchObject({ reason: "policy_unsatisfied" });
			const context = await runtime.auth.$context;
			await expect(context.adapter.count({ model: "user" })).resolves.toBe(0);
			await expect(context.adapter.count({ model: "account" })).resolves.toBe(0);
			await expect(context.adapter.count({ model: "session" })).resolves.toBe(0);
			await expect(
				context.internalAdapter.findVerificationValueAndPruneExpired(runtime.readSent().token),
			).resolves.not.toBeNull();
		} finally {
			runtime.database.close();
		}
	});

	it("issues a managed session when single-factor policy allows email links", async () => {
		const runtime = await managedMagicLinkTestRuntime("single_factor");
		try {
			await runtime.auth.api.signInMagicLink({
				body: { email: "managed-magic-link-allow@example.test" },
				headers: new Headers(),
			});
			const response = await runtime.auth.api.magicLinkVerify({
				query: { token: runtime.readSent().token },
				headers: new Headers(),
			});
			expect(response.token).toEqual(expect.any(String));
			const context = await runtime.auth.$context;
			await expect(context.adapter.count({ model: "user" })).resolves.toBe(1);
			await expect(context.adapter.count({ model: "session" })).resolves.toBe(1);
		} finally {
			runtime.database.close();
		}
	});
});

describe("magic link", async () => {
	let verificationEmail: VerificationEmail = {
		email: "",
		token: "",
		url: "",
	};
	const { customFetchImpl, testUser, sessionSetter } = await getTestInstance({
		plugins: [
			magicLink({
				async sendMagicLink(data) {
					verificationEmail = data;
				},
			}),
		],
	});

	const client = createAuthClient({
		plugins: [magicLinkClient()],
		fetchOptions: {
			customFetchImpl,
		},
		baseURL: "http://localhost:3000",
		basePath: "/api/auth",
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("should send magic link", async () => {
		await client.signIn.magicLink({
			email: testUser.email,
		});
		expect(verificationEmail).toMatchObject({
			email: testUser.email,
			url: expect.stringContaining(
				"http://localhost:3000/api/auth/magic-link/verify",
			),
		});
		expect(verificationEmail.metadata).toBeUndefined();
	});

	it("should forward metadata to sendMagicLink", async () => {
		await client.signIn.magicLink({
			email: testUser.email,
			metadata: {
				inviteId: "123",
			},
		});

		expect(verificationEmail).toMatchObject({
			email: testUser.email,
			metadata: {
				inviteId: "123",
			},
		});
	});
	it("should verify magic link", async () => {
		const headers = new Headers();
		const response = await client.magicLink.verify({
			query: {
				token: new URL(verificationEmail.url).searchParams.get("token") || "",
			},
			fetchOptions: {
				onSuccess: sessionSetter(headers),
			},
		});
		expect(response.data?.token).toBeDefined();
		const clearanceCookie = headers.get("set-cookie");
		expect(clearanceCookie).toBeDefined();
	});

	it("passes consumed email-link evidence to the real session boundary", async () => {
		let sent: VerificationEmail = { email: "", token: "", url: "" };
		const { auth, customFetchImpl, testUser } = await getTestInstance({
			plugins: [
				magicLink({
					async sendMagicLink(data) {
						sent = data;
					},
				}),
			],
		});
		const adapter = (await auth.$context).internalAdapter;
		const authoritativeUser = await adapter.findUserByEmail(testUser.email);
		expect(authoritativeUser).not.toBeNull();
		const consumeVerificationValue = vi.spyOn(
			adapter,
			"consumeVerificationValue",
		);
		const createSession = vi.spyOn(adapter, "createSession");
		const isolatedClient = createAuthClient({
			plugins: [magicLinkClient()],
			fetchOptions: { customFetchImpl },
			baseURL: "http://localhost:3000",
			basePath: "/api/auth",
		});

		await isolatedClient.magicLink.verify({ query: { token: "invalid-token" } });
		expect(createSession).not.toHaveBeenCalled();

		await isolatedClient.signIn.magicLink({ email: testUser.email });
		const response = await isolatedClient.magicLink.verify({
			query: { token: sent.token },
		});
		expect(response.data?.token).toBeDefined();
		expect(consumeVerificationValue).toHaveBeenCalledWith(sent.token, {
			purpose: "magic-link:sign-in",
			subject: sent.token,
			identifier: sent.token,
		});
		expect(await adapter.findVerificationValueAndPruneExpired(sent.token)).toBeNull();
		expect(createSession).toHaveBeenCalledTimes(1);
		const [subjectId, dontRememberMe, override, overrideAll, issuanceContext] =
			createSession.mock.calls[0]!;
		expect([subjectId, dontRememberMe, override, overrideAll]).toEqual([
			authoritativeUser!.user.id,
			false,
			undefined,
			false,
		]);
		expect(readInternalSessionIssuanceContext(issuanceContext)).toEqual({
			purpose: "interactive",
			subjectId: authoritativeUser!.user.id,
			evidence: [{ kind: "primary", primaryMethod: "email_link" }],
			targetOrganizationId: null,
		});
	});

	it("shouldn't verify magic link with the same token", async () => {
		await client.magicLink.verify(
			{
				query: {
					token: new URL(verificationEmail.url).searchParams.get("token") || "",
				},
			},
			{
				onError(context) {
					expect(context.response.status).toBe(302);
					const location = context.response.headers.get("location");
					expect(location).toContain("?error=INVALID_TOKEN");
				},
			},
		);
	});

	it("shouldn't verify magic link with an expired token", async () => {
		await client.signIn.magicLink({
			email: testUser.email,
		});
		const token = verificationEmail.token;
		vi.useFakeTimers();
		await vi.advanceTimersByTimeAsync(1000 * 60 * 5 + 1);
		await client.magicLink.verify(
			{
				query: {
					token,
					callbackURL: "/callback",
				},
			},
			{
				onError(context) {
					expect(context.response.status).toBe(302);
					const location = context.response.headers.get("location");
					expect(location).toContain("?error=INVALID_TOKEN");
				},
			},
		);
	});

	it("should redirect to errorCallbackURL in case of error", async () => {
		const errorCallbackURL = new URL("http://localhost:3000/error-page");
		errorCallbackURL.searchParams.set("foo", "bar");
		errorCallbackURL.searchParams.set("baz", "qux");

		await client.magicLink.verify(
			{
				query: {
					token: "invalid-token",
					errorCallbackURL: errorCallbackURL.toString(),
				},
			},
			{
				onError(context) {
					expect(context.response.status).toBe(302);

					const location = context.response.headers.get("location");
					expect(location).toBeDefined();

					const url = new URL(location!);
					expect(url.origin).toBe(errorCallbackURL.origin);
					expect(url.pathname).toBe(errorCallbackURL.pathname);
					expect(url.searchParams.get("foo")).toBe("bar");
					expect(url.searchParams.get("baz")).toBe("qux");
					expect(url.searchParams.get("error")).toBe("INVALID_TOKEN");
				},
			},
		);
	});

	it("should sign up with magic link", async () => {
		const email = "new-email@email.com";
		await client.signIn.magicLink({
			email,
			name: "test",
		});
		expect(verificationEmail).toMatchObject({
			email,
			url: expect.stringContaining(
				"http://localhost:3000/api/auth/magic-link/verify",
			),
		});
		const headers = new Headers();
		await client.magicLink.verify({
			query: {
				token: new URL(verificationEmail.url).searchParams.get("token") || "",
			},
			fetchOptions: {
				onSuccess: sessionSetter(headers),
			},
		});
		const session = await client.getSession({
			fetchOptions: {
				headers,
			},
		});
		expect(session.data?.user).toMatchObject({
			name: "test",
			email: "new-email@email.com",
			emailVerified: true,
		});
	});

	it("should verify email and return emailVerified true in session for existing unverified user", async () => {
		// Create an unverified user with a separate test instance
		const email = "unverified-user@email.com";
		let magicLinkEmail: VerificationEmail = {
			email: "",
			token: "",
			url: "",
		};

		const {
			auth,
			customFetchImpl: testFetchImpl,
			sessionSetter: testSessionSetter,
		} = await getTestInstance({
			plugins: [
				magicLink({
					async sendMagicLink(data) {
						magicLinkEmail = data;
					},
				}),
			],
		});

		const testClient = createAuthClient({
			plugins: [magicLinkClient()],
			fetchOptions: {
				customFetchImpl: testFetchImpl,
			},
			baseURL: "http://localhost:3000",
			basePath: "/api/auth",
		});

		const internalAdapter = (await auth.$context).internalAdapter;

		// Create user with emailVerified: false
		const newUser = await auth.api.signUpEmail({
			body: {
				email,
				name: "Unverified User",
				password: "password123",
			},
		});

		expect(newUser.user?.emailVerified).toBe(false);

		// Send magic link
		await testClient.signIn.magicLink({
			email,
		});

		// Verify magic link
		const headers = new Headers();
		const response = await testClient.magicLink.verify({
			query: {
				token: new URL(magicLinkEmail.url).searchParams.get("token") || "",
			},
			fetchOptions: {
				onSuccess: testSessionSetter(headers),
			},
		});

		// Check that the response contains emailVerified: true
		expect(response.data?.user.emailVerified).toBe(true);

		// Also verify session has emailVerified: true
		const session = await testClient.getSession({
			fetchOptions: {
				headers,
			},
		});
		expect(session.data?.user.emailVerified).toBe(true);

		// Verify DB was actually updated
		const updatedUser = await internalAdapter.findUserByEmail(email);
		expect(updatedUser?.user.emailVerified).toBe(true);
	});

	it("should clear an unverified account's password when verify adopts it", async () => {
		// An account created with a password but never email-verified must not keep
		// that password once magic-link verification proves control of the mailbox.
		const email = "unverified-pw-user@email.com";
		const existingPassword = "existing-password-123";
		let magicLinkEmail: VerificationEmail = { email: "", token: "", url: "" };

		const {
			auth,
			customFetchImpl: testFetchImpl,
			sessionSetter: testSessionSetter,
		} = await getTestInstance({
			emailAndPassword: {
				enabled: true,
				requireEmailVerification: true,
			},
			plugins: [
				magicLink({
					async sendMagicLink(data) {
						magicLinkEmail = data;
					},
				}),
			],
		});

		const testClient = createAuthClient({
			plugins: [magicLinkClient()],
			fetchOptions: { customFetchImpl: testFetchImpl },
			baseURL: "http://localhost:3000",
			basePath: "/api/auth",
		});

		const internalAdapter = (await auth.$context).internalAdapter;

		const created = await auth.api.signUpEmail({
			body: { email, name: "Test User", password: existingPassword },
		});
		const userId = created.user!.id;
		expect(created.user?.emailVerified).toBe(false);

		// Precondition: the password is blocked behind the verification gate.
		await expect(
			auth.api.signInEmail({ body: { email, password: existingPassword } }),
		).rejects.toThrow();

		await testClient.signIn.magicLink({ email });
		const headers = new Headers();
		const response = await testClient.magicLink.verify({
			query: {
				token: new URL(magicLinkEmail.url).searchParams.get("token") || "",
			},
			fetchOptions: { onSuccess: testSessionSetter(headers) },
		});

		// The owner is signed in and the account is verified.
		expect(response.data?.user.emailVerified).toBe(true);
		const session = await testClient.getSession({ fetchOptions: { headers } });
		expect(session.data?.user.emailVerified).toBe(true);

		// The credential is gone, so the password no longer works.
		const accounts = await internalAdapter.findAccounts(userId);
		expect(
			accounts.find((account) => account.providerId === "credential"),
		).toBeUndefined();
		await expect(
			auth.api.signInEmail({ body: { email, password: existingPassword } }),
		).rejects.toThrow();
	});

	it("should use custom generateToken function", async () => {
		const customGenerateToken = vi.fn(() => "custom_token");

		const { customFetchImpl } = await getTestInstance({
			plugins: [
				magicLink({
					async sendMagicLink(data) {
						verificationEmail = data;
					},
					generateToken: customGenerateToken,
				}),
			],
		});

		const customClient = createAuthClient({
			plugins: [magicLinkClient()],
			fetchOptions: {
				customFetchImpl,
			},
			baseURL: "http://localhost:3000/api/auth",
		});

		await customClient.signIn.magicLink({
			email: testUser.email,
		});

		expect(customGenerateToken).toHaveBeenCalled();
		expect(verificationEmail.token).toBe("custom_token");
	});

	it("should return additional fields", async () => {
		const { customFetchImpl, sessionSetter, auth } = await getTestInstance({
			user: {
				additionalFields: {
					foo: {
						type: "string",
						required: false,
					},
				},
			},
			plugins: [
				magicLink({
					async sendMagicLink(data) {
						verificationEmail = data;
					},
				}),
			],
		});

		const client = createAuthClient({
			plugins: [magicLinkClient()],
			fetchOptions: {
				customFetchImpl,
			},
			baseURL: "http://localhost:3000/api/auth",
		});

		const email = "test-email@test.com";
		await client.signIn.magicLink({
			email,
		});

		const headers = new Headers();
		const response = await client.magicLink.verify({
			query: {
				token: new URL(verificationEmail.url).searchParams.get("token") || "",
			},
			fetchOptions: {
				onSuccess: sessionSetter(headers),
			},
		});

		expect(response.data?.user).toBeDefined();
		// @ts-expect-error
		expect(response.data?.user.foo).toBeNull();

		await auth.api.updateUser({
			body: {
				foo: "bar",
			},
			headers,
		});

		await client.signIn.magicLink({
			email,
		});
		{
			const response = await client.magicLink.verify({
				query: {
					token: new URL(verificationEmail.url).searchParams.get("token")!,
				},
				fetchOptions: {
					onSuccess: sessionSetter(headers),
				},
			});

			// @ts-expect-error
			expect(response.data?.user.foo).toBe("bar");
		}
	});
});

describe("magic link verify", async () => {
	const verificationEmail: VerificationEmail[] = [
		{
			email: "",
			token: "",
			url: "",
		},
	];
	const { customFetchImpl, testUser, sessionSetter } = await getTestInstance({
		plugins: [
			magicLink({
				async sendMagicLink(data) {
					verificationEmail.push(data);
				},
			}),
		],
	});

	const client = createAuthClient({
		plugins: [magicLinkClient()],
		fetchOptions: {
			customFetchImpl,
		},
		baseURL: "http://localhost:3000/api/auth",
	});

	it("should verify last magic link", async () => {
		await client.signIn.magicLink({
			email: testUser.email,
		});
		await client.signIn.magicLink({
			email: testUser.email,
		});
		await client.signIn.magicLink({
			email: testUser.email,
		});
		const headers = new Headers();
		const lastEmail = verificationEmail.pop() as VerificationEmail;
		const response = await client.magicLink.verify({
			query: {
				token: new URL(lastEmail.url).searchParams.get("token") || "",
			},
			fetchOptions: {
				onSuccess: sessionSetter(headers),
			},
		});
		expect(response.data?.token).toBeDefined();
		const clearanceCookie = headers.get("set-cookie");
		expect(clearanceCookie).toBeDefined();
	});
});

describe("magic link verify origin validation", async () => {
	it("should reject untrusted callbackURL on verify", async () => {
		let verificationEmail: VerificationEmail = {
			email: "",
			token: "",
			url: "",
		};

		const { customFetchImpl, testUser } = await getTestInstance({
			trustedOrigins: ["http://localhost:3000"],
			plugins: [
				magicLink({
					async sendMagicLink(data) {
						verificationEmail = data;
					},
				}),
			],
			advanced: {
				disableOriginCheck: false,
			},
		});

		const client = createAuthClient({
			plugins: [magicLinkClient()],
			fetchOptions: {
				customFetchImpl,
			},
			baseURL: "http://localhost:3000",
			basePath: "/api/auth",
		});

		await client.signIn.magicLink({
			email: testUser.email,
		});

		const token =
			new URL(verificationEmail.url).searchParams.get("token") || "";
		const res = await client.magicLink.verify({
			query: {
				token,
				callbackURL: "http://malicious.com",
			},
		});

		expect(res.error?.status).toBe(403);
		expect(res.error?.message).toBe("Invalid callbackURL");
	});
});

describe("magic link storeToken", async () => {
	it("should store token in hashed", async () => {
		let verificationEmail: VerificationEmail = {
			email: "",
			token: "",
			url: "",
		};
		const { auth, signInWithTestUser, testUser } = await getTestInstance({
			plugins: [
				magicLink({
					storeToken: "hashed",
					sendMagicLink(data, request) {
						verificationEmail = data;
					},
				}),
			],
		});

		const internalAdapter = (await auth.$context).internalAdapter;
		const { headers } = await signInWithTestUser();
		await auth.api.signInMagicLink({
			body: {
				email: testUser.email,
			},
			headers,
		});
		const hashedToken = await defaultKeyHasher(verificationEmail.token);
		const storedToken =
			await internalAdapter.findVerificationValueAndPruneExpired(hashedToken);
		expect(storedToken).toBeDefined();
		const response2 = await auth.api.signInMagicLink({
			body: {
				email: testUser.email,
			},
			headers,
		});
		expect(response2.status).toBe(true);
	});

	it("should store token with custom hasher", async () => {
		let verificationEmail: VerificationEmail = {
			email: "",
			token: "",
			url: "",
		};
		const { auth, signInWithTestUser, testUser } = await getTestInstance({
			plugins: [
				magicLink({
					storeToken: {
						type: "custom-hasher",
						async hash(token) {
							return token + "hashed";
						},
					},
					sendMagicLink(data, request) {
						verificationEmail = data;
					},
				}),
			],
		});

		const internalAdapter = (await auth.$context).internalAdapter;
		const { headers } = await signInWithTestUser();
		await auth.api.signInMagicLink({
			body: {
				email: testUser.email,
			},
			headers,
		});
		const hashedToken = `${verificationEmail.token}hashed`;
		const storedToken =
			await internalAdapter.findVerificationValueAndPruneExpired(hashedToken);
		expect(storedToken).toBeDefined();
		const response2 = await auth.api.signInMagicLink({
			body: {
				email: testUser.email,
			},
			headers,
		});
		expect(response2.status).toBe(true);
	});
});

/**
 * Magic-link tokens are consumed atomically on the first verification call that
 * finds the token: the row is deleted before any subsequent success checks
 * (signup gates, session creation, etc.), so even a verify that ends in
 * `INVALID_TOKEN`, `new_user_signup_disabled`, or `failed_to_create_session`
 * still burns the token. `allowedAttempts` is retained on the options type for
 * backward compatibility but does not multiply redemptions; a token mints at
 * most one session regardless of the value.
 *
 * @see https://github.com/clearance-auth/clearance
 */
describe("magic link single-use semantics", async () => {
	async function setup(allowedAttempts?: number) {
		let verificationEmail: VerificationEmail = {
			email: "",
			token: "",
			url: "",
		};
		const { customFetchImpl, testUser, sessionSetter } = await getTestInstance({
			plugins: [
				magicLink({
					...(allowedAttempts !== undefined ? { allowedAttempts } : {}),
					async sendMagicLink(data) {
						verificationEmail = data;
					},
				}),
			],
		});
		const client = createAuthClient({
			plugins: [magicLinkClient()],
			fetchOptions: { customFetchImpl },
			baseURL: "http://localhost:3000",
			basePath: "/api/auth",
		});
		return {
			client,
			testUser,
			sessionSetter,
			getToken: () =>
				new URL(verificationEmail.url).searchParams.get("token") || "",
			triggerSignIn: () => client.signIn.magicLink({ email: testUser.email }),
		};
	}

	it("rejects the second verification with the default allowedAttempts (1)", async () => {
		const { client, sessionSetter, getToken, triggerSignIn } = await setup();
		await triggerSignIn();
		const token = getToken();

		const headers = new Headers();
		const response = await client.magicLink.verify({
			query: { token },
			fetchOptions: { onSuccess: sessionSetter(headers) },
		});
		expect(response.data?.token).toBeDefined();
		expect(headers.get("set-cookie")).toBeDefined();

		await client.magicLink.verify(
			{ query: { token } },
			{
				onError(context) {
					expect(context.response.status).toBe(302);
					expect(context.response.headers.get("location")).toContain(
						"?error=INVALID_TOKEN",
					);
				},
				onSuccess() {
					throw new Error("Should not succeed");
				},
			},
		);
	});

	it("rejects the second verification even when allowedAttempts is set to 3", async () => {
		const { client, sessionSetter, getToken, triggerSignIn } = await setup(3);
		await triggerSignIn();
		const token = getToken();

		const headers = new Headers();
		const response = await client.magicLink.verify({
			query: { token },
			fetchOptions: { onSuccess: sessionSetter(headers) },
		});
		expect(response.data?.token).toBeDefined();

		await client.magicLink.verify(
			{ query: { token } },
			{
				onError(context) {
					expect(context.response.status).toBe(302);
					expect(context.response.headers.get("location")).toContain(
						"?error=INVALID_TOKEN",
					);
				},
				onSuccess() {
					throw new Error("Should not succeed");
				},
			},
		);
	});

	it("rejects the second verification even when allowedAttempts is Infinity", async () => {
		const { client, sessionSetter, getToken, triggerSignIn } =
			await setup(Infinity);
		await triggerSignIn();
		const token = getToken();

		const headers = new Headers();
		await client.magicLink.verify({
			query: { token },
			fetchOptions: { onSuccess: sessionSetter(headers) },
		});

		await client.magicLink.verify(
			{ query: { token } },
			{
				onError(context) {
					expect(context.response.status).toBe(302);
					expect(context.response.headers.get("location")).toContain(
						"?error=INVALID_TOKEN",
					);
				},
				onSuccess() {
					throw new Error("Should not succeed");
				},
			},
		);
	});

	/**
	 * Two HTTP requests that race the same verification token must produce
	 * exactly one session. Reproduces the original race described in the
	 * advisory, where both requests passed the find-check-update sequence
	 * before either consumed the row.
	 *
	 * The interleaving relies on the in-memory adapter yielding control at
	 * each `await` boundary; reverting `signInMagicLink` to its pre-patch
	 * find/update/delete sequence makes this test fail with two session
	 * tokens (verified empirically), so a synthetic scheduling barrier is
	 * unnecessary.
	 */
	it("mints at most one session under concurrent verification of the same token", async () => {
		const { client, getToken, triggerSignIn } = await setup();
		await triggerSignIn();
		const token = getToken();

		const responses = await Promise.all([
			client.magicLink.verify({ query: { token } }),
			client.magicLink.verify({ query: { token } }),
		]);

		const sessionTokens = responses
			.map((r) => r.data?.token)
			.filter((t): t is string => typeof t === "string" && t.length > 0);
		expect(sessionTokens).toHaveLength(1);
	});
});
