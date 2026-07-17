import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import type { GoogleProfile } from "@clearance/core/social-providers";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import * as apiModule from "../../api";
import { clearance } from "../../auth/full";
import { signJWT } from "../../crypto";
import { getMigrations } from "../../db/get-migration";
import { attachInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { readInternalSessionIssuanceContext } from "../../internal/session-issuance-context";
import { getTestInstance } from "../../test-utils/test-instance";
import { DEFAULT_SECRET } from "../../utils/constants";
import { anonymous } from ".";
import { anonymousClient } from "./client";

let testIdToken: string;
let handlers: ReturnType<typeof http.post>[];

const server = setupServer();

beforeAll(async () => {
	const data: GoogleProfile = {
		email: "user@email.com",
		email_verified: true,
		name: "First Last",
		picture: "https://lh3.googleusercontent.com/a-/AOh14GjQ4Z7Vw",
		exp: 1234567890,
		sub: "1234567890",
		iat: 1234567890,
		aud: "test",
		azp: "test",
		nbf: 1234567890,
		iss: "test",
		locale: "en",
		jti: "test",
		given_name: "First",
		family_name: "Last",
	};
	testIdToken = await signJWT(data, DEFAULT_SECRET);

	handlers = [
		http.post("https://oauth2.googleapis.com/token", () => {
			return HttpResponse.json({
				access_token: "test",
				refresh_token: "test",
				id_token: testIdToken,
			});
		}),
	];

	server.listen({ onUnhandledRequest: "bypass" });
	server.use(...handlers);
});

afterEach(() => {
	vi.restoreAllMocks();
	server.resetHandlers();
	server.use(...handlers);
});

afterAll(() => server.close());

describe("anonymous", async () => {
	const linkAccountFn = vi.fn();
	const { client, sessionSetter, testUser, cookieSetter } =
		await getTestInstance(
			{
				plugins: [
					anonymous({
						async onLinkAccount(data) {
							linkAccountFn(data);
						},
						schema: {
							user: {
								fields: {
									isAnonymous: "is_anon",
								},
							},
						},
					}),
				],
				socialProviders: {
					google: {
						clientId: "test",
						clientSecret: "test",
					},
				},
			},
			{
				clientOptions: {
					plugins: [anonymousClient()],
				},
			},
		);
	const headers = new Headers();

	it("passes anonymous evidence bound to the server-created user", async () => {
		const { auth, client } = await getTestInstance(
			{ plugins: [anonymous()] },
			{
				disableTestUser: true,
				clientOptions: { plugins: [anonymousClient()] },
			},
		);
		const context = await auth.$context;
		const originalCreateSession = context.internalAdapter.createSession.bind(
			context.internalAdapter,
		);
		const createSession = vi
			.spyOn(context.internalAdapter, "createSession")
			.mockImplementation((...args) => originalCreateSession(...args));

		try {
			const response = await client.signIn.anonymous();
			expect(response.error).toBeNull();
			expect(response.data?.user).toBeDefined();
			const authoritativeUserId = response.data!.user.id;
			expect(createSession).toHaveBeenCalledOnce();
			const [subjectId, , , , issuanceContext] = createSession.mock.calls[0]!;
			expect(subjectId).toBe(authoritativeUserId);
			expect(readInternalSessionIssuanceContext(issuanceContext)).toEqual({
				purpose: "interactive",
				subjectId: authoritativeUserId,
				evidence: [{ kind: "primary", primaryMethod: "anonymous" }],
				targetOrganizationId: null,
			});
		} finally {
			createSession.mockRestore();
		}
	});

	it("reaches anonymous_not_allowed under managed policy", async () => {
		const database = new DatabaseSync(":memory:");
		const identity = {
			projectId: "anonymous-policy-project",
			environmentId: "anonymous-policy-environment",
		} satisfies RuntimeAuthenticationPolicyIdentity;
		const policy = {
			passwordLockout: {
				enabled: true,
				maxFailedAttempts: 10,
				durationSeconds: 900,
			},
			factorLockout: {
				enabled: true,
				maxFailedAttempts: 10,
				durationSeconds: 900,
			},
			minimumAssurance: "single_factor",
			allowedFactors: { totp: true, passkey: true },
			trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
			assuranceMaxAgeSeconds: 300,
		} satisfies RuntimeAuthenticationPolicy;
		const options = {
			baseURL: "http://localhost:3000",
			secret: "managed-anonymous-issuance-test-secret",
			database,
			plugins: [anonymous()],
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

		try {
			await (await getMigrations(options)).runMigrations();
			const auth = clearance(options);
			const context = await auth.$context;
			await expect(auth.api.signInAnonymous()).rejects.toMatchObject({
				reason: "policy_unsatisfied",
				requirement: { reason: "anonymous_not_allowed" },
			});
			await expect(context.adapter.count({ model: "user" })).resolves.toBe(0);
			await expect(context.adapter.count({ model: "session" })).resolves.toBe(0);
		} finally {
			database.close();
		}
	});

	it("preflights managed transaction support before creating an anonymous user", async () => {
		const database = new DatabaseSync(":memory:");
		const identity = {
			projectId: "anonymous-no-transaction-project",
			environmentId: "anonymous-no-transaction-environment",
		} satisfies RuntimeAuthenticationPolicyIdentity;
		const policy = {
			passwordLockout: {
				enabled: true,
				maxFailedAttempts: 10,
				durationSeconds: 900,
			},
			factorLockout: {
				enabled: true,
				maxFailedAttempts: 10,
				durationSeconds: 900,
			},
			minimumAssurance: "single_factor",
			allowedFactors: { totp: true, passkey: true },
			trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
			assuranceMaxAgeSeconds: 300,
		} satisfies RuntimeAuthenticationPolicy;
		const options = {
			baseURL: "http://localhost:3000",
			secret: "managed-anonymous-no-transaction-test-secret",
			database,
			plugins: [anonymous()],
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

		try {
			await (await getMigrations(options)).runMigrations();
			const auth = clearance(options);
			const context = await auth.$context;
			context.adapter.options!.adapterConfig.transaction = false;

			await expect(auth.api.signInAnonymous()).rejects.toThrow(
				"Managed anonymous sign-in requires rollback-capable database transactions",
			);
			await expect(context.adapter.count({ model: "user" })).resolves.toBe(0);
			await expect(context.adapter.count({ model: "session" })).resolves.toBe(0);
		} finally {
			database.close();
		}
	});

	it("should sign in anonymously", async () => {
		await client.signIn.anonymous({
			fetchOptions: {
				onSuccess: sessionSetter(headers),
			},
		});
		const session = await client.getSession({
			fetchOptions: {
				headers,
			},
		});
		expect(session.data?.session).toBeDefined();
		expect(session.data?.user.isAnonymous).toBe(true);
	});

	it("link anonymous user account", async () => {
		expect(linkAccountFn).toHaveBeenCalledTimes(0);
		await client.signIn.email(testUser, {
			headers,
		});
		expect(linkAccountFn).toHaveBeenCalledWith(expect.any(Object));
		linkAccountFn.mockClear();
	});

	it("should link in social sign on", async () => {
		const headers = new Headers();
		await client.signIn.anonymous({
			fetchOptions: {
				onSuccess: sessionSetter(headers),
			},
		});

		await client.getSession({
			fetchOptions: {
				headers,
			},
		});

		const singInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/dashboard",
			fetchOptions: {
				onSuccess: cookieSetter(headers),
			},
		});
		const state = new URL(singInRes.data?.url || "").searchParams.get("state");
		await client.$fetch("/callback/google", {
			query: {
				state,
				code: "test",
			},
			headers,
		});
		expect(linkAccountFn).toHaveBeenCalledWith(expect.any(Object));
	});

	it("should call onLinkAccount when anonymous user verifies email", async () => {
		/**
		 * @see https://github.com/clearance-auth/clearance
		 */
		const linkAccountFn = vi.fn();
		let verificationToken = "";

		const { client, sessionSetter, auth } = await getTestInstance(
			{
				plugins: [
					anonymous({
						async onLinkAccount(data) {
							linkAccountFn(data);
						},
					}),
				],
				emailAndPassword: {
					enabled: true,
					requireEmailVerification: true,
				},
				emailVerification: {
					autoSignInAfterVerification: true,
					async sendVerificationEmail({ url }) {
						verificationToken = new URL(url).searchParams.get("token") || "";
					},
				},
			},
			{
				clientOptions: {
					plugins: [anonymousClient()],
				},
				disableTestUser: true,
			},
		);

		const anonHeaders = new Headers();

		await client.signIn.anonymous({
			fetchOptions: {
				onSuccess: sessionSetter(anonHeaders),
			},
		});

		await auth.api.signUpEmail({
			body: {
				email: "newuser@example.com",
				password: "password123",
				name: "New User",
			},
			headers: anonHeaders,
		});

		await auth.api.verifyEmail({
			query: { token: verificationToken },
			headers: anonHeaders,
		});

		expect(linkAccountFn).toHaveBeenCalledTimes(1);
		expect(linkAccountFn).toHaveBeenCalledWith(expect.any(Object));
	});

	it("should work with generateName", async () => {
		const { client, sessionSetter } = await getTestInstance(
			{
				plugins: [
					anonymous({
						generateName() {
							return "i-am-anonymous";
						},
					}),
				],
			},
			{
				clientOptions: {
					plugins: [anonymousClient()],
				},
			},
		);
		const res = await client.signIn.anonymous({
			fetchOptions: {
				onSuccess: sessionSetter(headers),
			},
		});
		expect(res.data?.user.name).toBe("i-am-anonymous");
	});

	it("should work with generateRandomEmail", async () => {
		const testHeaders = new Headers();
		const { client, sessionSetter } = await getTestInstance(
			{
				plugins: [
					anonymous({
						generateRandomEmail() {
							const id = crypto.randomUUID();
							return `custom-${id}@example.com`;
						},
					}),
				],
			},
			{
				clientOptions: {
					plugins: [anonymousClient()],
				},
			},
		);
		const res = await client.signIn.anonymous({
			fetchOptions: {
				onSuccess: sessionSetter(testHeaders),
			},
		});
		expect(res.data?.user.email).toMatch(/^custom-[a-f0-9-]+@example\.com$/);
	});

	it("should work with async generateRandomEmail", async () => {
		const testHeaders = new Headers();
		const { client, sessionSetter } = await getTestInstance(
			{
				plugins: [
					anonymous({
						async generateRandomEmail() {
							const id = crypto.randomUUID();
							return `async-${id}@example.com`;
						},
					}),
				],
			},
			{
				clientOptions: {
					plugins: [anonymousClient()],
				},
			},
		);
		const res = await client.signIn.anonymous({
			fetchOptions: {
				onSuccess: sessionSetter(testHeaders),
			},
		});
		expect(res.data?.user.email).toMatch(/^async-[a-f0-9-]+@example\.com$/);
	});

	it("should throw error if generateRandomEmail returns invalid email", async () => {
		const testHeaders = new Headers();
		const { client, sessionSetter } = await getTestInstance(
			{
				plugins: [
					anonymous({
						generateRandomEmail() {
							return "not-an-email";
						},
					}),
				],
			},
			{
				clientOptions: {
					plugins: [anonymousClient()],
				},
			},
		);

		const res = await client.signIn.anonymous({
			fetchOptions: {
				onSuccess: sessionSetter(testHeaders),
			},
		});

		expect(res.error).toBeDefined();
		expect(res.data).toBeNull();
		expect(res.error?.message).toBe(
			"Email was not generated in a valid format",
		);
	});

	it("should throw error if async generateRandomEmail returns invalid email", async () => {
		const testHeaders = new Headers();
		const { client, sessionSetter } = await getTestInstance(
			{
				plugins: [
					anonymous({
						async generateRandomEmail() {
							return "still-not-an-email";
						},
					}),
				],
			},
			{
				clientOptions: {
					plugins: [anonymousClient()],
				},
			},
		);

		const res = await client.signIn.anonymous({
			fetchOptions: {
				onSuccess: sessionSetter(testHeaders),
			},
		});

		expect(res.error).toBeDefined();
		expect(res.data).toBeNull();
		expect(res.error?.message).toBe(
			"Email was not generated in a valid format",
		);
	});

	it("should not reject first-time anonymous sign-in", async () => {
		const { client, sessionSetter } = await getTestInstance(
			{
				plugins: [anonymous()],
			},
			{
				clientOptions: {
					plugins: [anonymousClient()],
				},
			},
		);
		const freshHeaders = new Headers();

		// First-time anonymous sign-in should succeed without 400 error
		const res = await client.signIn.anonymous({
			fetchOptions: {
				onSuccess: sessionSetter(freshHeaders),
			},
		});

		expect(res.data?.user).toBeDefined();
		expect(res.error).toBeNull();

		// Verify session is actually created and contains isAnonymous
		const session = await client.getSession({
			fetchOptions: {
				headers: freshHeaders,
			},
		});
		expect(session.data?.session).toBeDefined();
		expect(session.data?.user.isAnonymous).toBe(true);
	});

	it("should reject subsequent anonymous sign-in attempts once signed in", async () => {
		const { client, sessionSetter } = await getTestInstance(
			{
				plugins: [anonymous()],
			},
			{
				clientOptions: {
					plugins: [anonymousClient()],
				},
			},
		);
		const persistentHeaders = new Headers();

		// First sign-in should succeed
		await client.signIn.anonymous({
			fetchOptions: {
				headers: persistentHeaders,
				onSuccess: sessionSetter(persistentHeaders),
			},
		});

		// Verify session is established before testing rejection
		const session = await client.getSession({
			fetchOptions: {
				headers: persistentHeaders,
			},
		});
		expect(session.data?.session).toBeDefined();
		expect(session.data?.user.isAnonymous).toBe(true);

		// Second attempt should be rejected at the endpoint level
		const secondAttempt = await client.signIn.anonymous({
			fetchOptions: {
				headers: persistentHeaders,
			},
		});

		expect(secondAttempt.data).toBeNull();
		expect(secondAttempt.error).toBeDefined();
		expect(secondAttempt.error?.message).toBe(
			"Anonymous users cannot sign in again anonymously",
		);
	});

	describe("anonymous cleanup safeguards", () => {
		function createMiddlewareContext({
			newSessionUser,
			deleteUser,
			deleteUserSessions,
		}: {
			newSessionUser: Record<string, any>;
			deleteUser: ReturnType<typeof vi.fn>;
			deleteUserSessions?: ReturnType<typeof vi.fn>;
		}) {
			return {
				path: "/sign-in/anonymous",
				context: {
					responseHeaders: new Headers({
						"set-cookie":
							"clearance.session_token=new-token.value; Path=/; HttpOnly",
					}),
					authCookies: {
						sessionToken: {
							name: "clearance.session_token",
							options: {},
						},
						sessionData: {
							name: "clearance.session_data",
							options: {},
						},
						dontRememberToken: {
							name: "clearance.dont_remember",
							options: {},
						},
					},
					newSession: {
						user: newSessionUser,
						session: {
							token: "new-token",
						},
					},
					internalAdapter: {
						deleteUser,
						deleteUserSessions: deleteUserSessions ?? vi.fn(),
					},
					options: {},
					secret: "secret",
					setNewSession: vi.fn(),
				},
				headers: new Headers(),
				query: {},
				error: vi.fn(),
				json: vi.fn(),
				getSignedCookie: vi.fn(),
				setCookie: vi.fn(),
				setSignedCookie: vi.fn(),
			} as any;
		}

		it("does not delete when the new session is still anonymous", async () => {
			const plugin = anonymous();
			const handler = plugin.hooks?.after?.[0]?.handler;
			const deleteUser = vi.fn();
			const ctx = createMiddlewareContext({
				newSessionUser: {
					id: "anon-user",
					isAnonymous: true,
				},
				deleteUser,
			});

			vi.spyOn(apiModule, "getSessionFromCtx").mockResolvedValue({
				user: {
					id: "anon-user",
					isAnonymous: true,
				},
				session: {
					token: "old-token",
				},
			} as any);

			await handler?.(ctx);

			expect(deleteUser).not.toHaveBeenCalled();
		});

		it("deletes the previous anonymous user when linking a new account", async () => {
			const plugin = anonymous();
			const handler = plugin.hooks?.after?.[0]?.handler;
			const deleteUser = vi.fn();
			const deleteUserSessions = vi.fn();
			const ctx = createMiddlewareContext({
				newSessionUser: {
					id: "linked-user",
					isAnonymous: false,
				},
				deleteUser,
				deleteUserSessions,
			});

			vi.spyOn(apiModule, "getSessionFromCtx").mockResolvedValue({
				user: {
					id: "anon-user",
					isAnonymous: true,
				},
				session: {
					token: "old-token",
				},
			} as any);

			await handler?.(ctx);

			expect(deleteUserSessions).toHaveBeenCalledWith("anon-user");
			expect(deleteUser).toHaveBeenCalledWith("anon-user");
		});
	});
});
