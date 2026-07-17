import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import { AfterTransactionHookError } from "@clearance/core/context";
import { describe, expect, it, vi } from "vitest";
import { makeSignature } from "../../crypto";
import { attachInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { createInternalSessionIssuanceContext } from "../../internal/session-issuance-context";
import { parseCookies, parseSetCookieHeader } from "../../cookies";
import { digestSessionRefreshSecret } from "../../db/session-credential";
import { getSecondarySessionKeys } from "../../db/session-credential-migration";
import { getTestInstance } from "../../test-utils/test-instance";
import { jwt } from "../jwt";
import { jwtClient } from "../jwt/client";
import { multiSession } from ".";
import { multiSessionClient } from "./client";

const managedMultiSessionIdentity = {
	projectId: "multi-session-policy-project",
	environmentId: "multi-session-policy-environment",
} satisfies RuntimeAuthenticationPolicyIdentity;

const managedMultiSessionPolicy = {
	passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	factorLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	minimumAssurance: "single_factor",
	allowedFactors: { totp: true, passkey: true },
	trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
	assuranceMaxAgeSeconds: 300,
} satisfies RuntimeAuthenticationPolicy;

async function createManagedMultiSessionRuntime(
	maximumSessions = 5,
	secondaryFailure?: { failKey: string | null; error: Error },
	secondaryOnly = false,
	preserveSessionInDatabase = false,
) {
	let revision = "1";
	let organizationMembership: string | null = null;
	let readerError: Error | null = null;
	const subjectRevisions = new Map<string, string>();
	const secondaryStore = new Map<string, string>();
	const options = {
		session: {
			storeSessionInDatabase: !secondaryOnly,
			preserveSessionInDatabase,
			additionalFields: {
				activeOrganizationId: {
					type: "string",
					required: false,
				},
			},
		},
		plugins: [multiSession({ maximumSessions })],
		...(secondaryFailure || secondaryOnly
			? {
					secondaryStorage: {
						async get(key: string) {
							return secondaryStore.get(key) ?? null;
						},
						async set(key: string, value: string) {
							secondaryStore.set(key, value);
						},
						async delete(key: string) {
							if (secondaryFailure && key === secondaryFailure.failKey) {
								throw secondaryFailure.error;
							}
							secondaryStore.delete(key);
						},
					},
			  }
			: {}),
	} satisfies ClearanceOptions;
	if (!secondaryOnly) {
		attachInternalAuthenticationPolicy(options, {
			identity: managedMultiSessionIdentity,
			reader: {
				async readForSubject(input) {
					if (readerError) throw readerError;
					return {
						scope: managedMultiSessionIdentity,
						subjectId: input.subjectId,
						revision: subjectRevisions.get(input.subjectId) ?? revision,
						environment: managedMultiSessionPolicy,
						organizationMembership:
							input.organizationId &&
							organizationMembership === input.organizationId
								? {
										subjectId: input.subjectId,
										organizationId: input.organizationId,
									}
								: null,
						organizationOverride: null,
						effective: managedMultiSessionPolicy,
					};
				},
			},
		});
	}
	const runtime = await getTestInstance(options, {
		disableTestUser: true,
		clientOptions: { plugins: [multiSessionClient()] },
	});
	return {
		...runtime,
		setRevision(value: string) {
			revision = value;
		},
		setOrganizationMembership(value: string | null) {
			organizationMembership = value;
		},
		setReaderError(value: Error | null) {
			readerError = value;
		},
		setSubjectRevision(subjectId: string, value: string | null) {
			if (value === null) subjectRevisions.delete(subjectId);
			else subjectRevisions.set(subjectId, value);
		},
	};
}

async function signedMultiSessionCookie(
	secret: string,
	session: { id: string; token: string },
) {
	return `clearance.session_token_multi-${encodeURIComponent(session.id)}=${session.token}.${await makeSignature(session.token, secret)}`;
}

async function signedNamedMultiSessionCookie(
	secret: string,
	name: string,
	token: string,
) {
	return `${name}=${token}.${await makeSignature(token, secret)}`;
}

describe("multi-session", async () => {
	const { client, testUser, cookieSetter } = await getTestInstance(
		{
			plugins: [
				multiSession({
					maximumSessions: 2,
				}),
			],
		},
		{
			clientOptions: {
				plugins: [multiSessionClient()],
			},
		},
	);

	const headers = new Headers();
	const testUser2 = {
		email: "second-email@test.com",
		password: "password",
		name: "Name",
	};

	it.each([0, -1, 1.5, 101, Number.NaN])(
		"rejects an unsafe maximumSessions value of %s",
		(maximumSessions) => {
			expect(() => multiSession({ maximumSessions })).toThrow(
				"multiSession maximumSessions must be a safe integer between 1 and 100",
			);
		},
	);

	it("should set multi session when there is set-cookie header", async () => {
		await client.signIn.email(
			{
				email: testUser.email,
				password: testUser.password,
			},
			{
				onResponse(context) {
					expect(context.response.headers.get("cache-control")).toBe(
						"no-store",
					);
					expect(context.response.headers.get("pragma")).toBe("no-cache");
					const setCookieString = context.response.headers.get("set-cookie");
					const setCookies = parseSetCookieHeader(setCookieString || "");
					const sessionToken = setCookies
						.get("clearance.session_token")
						?.value.split(".")[0];
					const multiSession = Array.from(setCookies.entries()).find(([name]) =>
						name.startsWith("clearance.session_token_multi-"),
					)?.[1].value;
					expect(sessionToken).not.toBe(null);
					expect(multiSession).not.toBe(null);
					expect(multiSession).toContain(sessionToken);
					expect(setCookieString).toContain("clearance.session_token_multi-");
				},
				onSuccess: cookieSetter(headers),
			},
		);
		await client.signUp.email(testUser2, {
			onSuccess: cookieSetter(headers),
		});
	});

	it("should get active session", async () => {
		const session = await client.getSession({
			fetchOptions: {
				headers,
			},
		});
		expect(session.data?.user.email).toBe(testUser2.email);
	});

	let sessionId = "";
	it("should list all device sessions", async () => {
		const res = await client.multiSession.listDeviceSessions({
			fetchOptions: {
				headers,
			},
		});
		if (res.data) {
			sessionId =
				res.data.find((s) => s.user.email === testUser.email)?.session.id ||
				"";
		}
		expect(res.data).toHaveLength(2);
	});

	it("should set active session when only multi-session cookies are present", async () => {
		const existingCookieHeader = headers.get("cookie") || "";
		const multiOnlyCookieHeader = existingCookieHeader
			.split(";")
			.map((cookie) => cookie.trim())
			.filter(Boolean)
			.filter((cookie) => !cookie.startsWith("clearance.session_token="))
			.join("; ");

		const multiOnlyHeaders = new Headers();
		multiOnlyHeaders.set("cookie", multiOnlyCookieHeader);

		const res = await client.multiSession.setActive({
			sessionId,
			fetchOptions: {
				headers: multiOnlyHeaders,
			},
		});
		expect(res.error).toBeNull();
		expect(res.data?.user.email).toBe(testUser.email);
	});

	it("should set active session", async () => {
		const res = await client.multiSession.setActive({
			sessionId,
			fetchOptions: {
				headers,
			},
		});
		expect(res.data?.user.email).toBe(testUser.email);
	});

	it("should revoke a session and set the next active", async () => {
		await client.multiSession.revoke(
			{
				sessionId,
			},
			{
				onSuccess(context) {
					cookieSetter(headers)(context);
				},
				headers,
			},
		);
		const active = await client.getSession({
			fetchOptions: { headers },
		});
		expect(active.data?.user.email).toBe(testUser2.email);
		const res = await client.multiSession.listDeviceSessions({
			fetchOptions: {
				headers,
			},
		});
		expect(res.data).toHaveLength(1);
	});

	it("accepts legacy session-token aliases for switching and revocation", async () => {
		const legacy = await getTestInstance(
			{
				plugins: [multiSession({ maximumSessions: 2 })],
			},
			{
				clientOptions: { plugins: [multiSessionClient()] },
			},
		);
		const legacyHeaders = new Headers();
		const firstUser = {
			email: "legacy-multi-first@test.com",
			password: "password",
			name: "Legacy First",
		};
		const secondUser = {
			email: "legacy-multi-second@test.com",
			password: "password",
			name: "Legacy Second",
		};
		let firstToken = "";
		let secondToken = "";
		let firstLegacyHandle = "";
		let secondLegacyHandle = "";

		await legacy.client.signUp.email(firstUser, {
			onSuccess: legacy.cookieSetter(legacyHeaders),
			onResponse(context) {
				firstToken =
					parseSetCookieHeader(
						context.response.headers.get("set-cookie") || "",
					)
						.get("clearance.session_token")
						?.value.split(".")[0] || "";
			},
		});
		const firstPublicSession = await legacy.client.getSession({
			fetchOptions: { headers: legacyHeaders },
		});
		firstLegacyHandle = firstPublicSession.data?.session.token || "";
		expect(firstLegacyHandle).toBe(firstPublicSession.data?.session.id);
		expect(firstLegacyHandle).not.toBe(firstToken);
		await legacy.client.signUp.email(secondUser, {
			onSuccess: legacy.cookieSetter(legacyHeaders),
			onResponse(context) {
				secondToken =
					parseSetCookieHeader(
						context.response.headers.get("set-cookie") || "",
					)
						.get("clearance.session_token")
						?.value.split(".")[0] || "";
			},
		});
		const secondPublicSession = await legacy.client.getSession({
			fetchOptions: { headers: legacyHeaders },
		});
		secondLegacyHandle = secondPublicSession.data?.session.token || "";
		expect(secondLegacyHandle).toBe(secondPublicSession.data?.session.id);
		expect(secondLegacyHandle).not.toBe(secondToken);
		expect(firstToken).not.toBe("");
		expect(secondToken).not.toBe("");

		const switched = await legacy.client.multiSession.setActive({
			sessionToken: firstLegacyHandle,
			fetchOptions: {
				headers: legacyHeaders,
				onSuccess: legacy.cookieSetter(legacyHeaders),
			},
		});
		expect(switched.error).toBeNull();
		expect(switched.data?.user.email).toBe(firstUser.email);
		expect(
			(
				await legacy.client.getSession({
					fetchOptions: { headers: legacyHeaders },
				})
			).data?.user.email,
		).toBe(firstUser.email);

		const rawTokenSwitch = await legacy.client.multiSession.setActive({
			sessionToken: secondToken,
			fetchOptions: {
				headers: legacyHeaders,
				onSuccess: legacy.cookieSetter(legacyHeaders),
			},
		});
		expect(rawTokenSwitch.error).toBeNull();
		expect(rawTokenSwitch.data?.user.email).toBe(secondUser.email);

		const revoked = await legacy.client.multiSession.revoke(
			{ sessionToken: firstToken },
			{ headers: legacyHeaders },
		);
		expect(revoked.error).toBeNull();
		expect(
			(
				await legacy.client.getSession({
					fetchOptions: { headers: legacyHeaders },
				})
			).data?.user.email,
		).toBe(secondUser.email);
		expect(
			(
				await legacy.client.multiSession.listDeviceSessions({
					fetchOptions: { headers: legacyHeaders },
				})
			).data,
		).toHaveLength(1);
	});

	it("migrates a legacy token-named cookie during JWT rotation without revoking the successor", async () => {
		const local = await getTestInstance(
			{
				plugins: [
					multiSession({ maximumSessions: 2 }),
					jwt({ disableSettingJwtHeader: true }),
				],
				logger: { level: "error" },
			},
			{
				clientOptions: {
					plugins: [multiSessionClient(), jwtClient()],
				},
			},
		);
		const rotationHeaders = new Headers();
		await local.client.signUp.email(
			{
				email: "legacy-cookie-rotation@test.com",
				password: "password",
				name: "Legacy Cookie Rotation",
			},
			{ onSuccess: local.cookieSetter(rotationHeaders) },
		);
		const publicSession = await local.client.getSession({
			fetchOptions: { headers: rotationHeaders },
		});
		const sessionId = publicSession.data!.session.id;
		const cookieEntries = Object.fromEntries(
			(rotationHeaders.get("cookie") || "")
				.split(";")
				.map((entry) => entry.trim())
				.filter(Boolean)
				.map((entry) => {
					const separator = entry.indexOf("=");
					return [entry.slice(0, separator), entry.slice(separator + 1)];
				}),
		);
		const primaryCookie = cookieEntries["clearance.session_token"]!;
		const predecessor = primaryCookie.split(".")[0]!;
		const canonicalName = `clearance.session_token_multi-${encodeURIComponent(sessionId)}`;
		const legacyName = `clearance.session_token_multi-${predecessor.toLowerCase()}`;
		cookieEntries[legacyName] = cookieEntries[canonicalName]!;
		delete cookieEntries[canonicalName];
		rotationHeaders.set(
			"cookie",
			Object.entries(cookieEntries)
				.map(([name, value]) => `${name}=${value}`)
				.join("; "),
		);

		let rotationSetCookie = "";
		const rotated = await local.client.token({
			fetchOptions: {
				headers: rotationHeaders,
				onResponse(context) {
					rotationSetCookie =
						context.response.headers.get("set-cookie") || "";
				},
				onSuccess: local.cookieSetter(rotationHeaders),
			},
		});
		expect(rotated.data?.token).toEqual(expect.any(String));
		const rotatedCookies = parseSetCookieHeader(rotationSetCookie);
		expect(rotatedCookies.get(legacyName)?.["max-age"]).toBe(0);
		expect(rotatedCookies.get(canonicalName)?.value).toBeDefined();

		const successor = await local.client.getSession({
			fetchOptions: { headers: rotationHeaders },
		});
		expect(successor.data?.session.id).toBe(sessionId);
		expect(successor.data?.session.token).toBe(sessionId);
		const listed = await local.client.multiSession.listDeviceSessions({
			fetchOptions: { headers: rotationHeaders },
		});
		expect(listed.data).toHaveLength(1);
	});

	it("evicts malformed signed capacity overflow during JWT credential rotation", async () => {
		const local = await getTestInstance(
			{
				plugins: [
					multiSession({ maximumSessions: 1 }),
					jwt({ disableSettingJwtHeader: true }),
				],
			},
			{
				disableTestUser: true,
				clientOptions: {
					plugins: [multiSessionClient(), jwtClient()],
				},
			},
		);
		const headers = new Headers();
		const signup = await local.client.signUp.email(
			{
				email: "multi-rotation-capacity@example.test",
				password: "password",
				name: "Rotation Capacity",
			},
			{ onSuccess: local.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const active = await local.client.getSession({ fetchOptions: { headers } });
		const context = await local.auth.$context;
		const overflow = await context.internalAdapter.createSession(
			active.data!.user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: active.data!.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		headers.set(
			"cookie",
			`${headers.get("cookie")}; ${await signedNamedMultiSessionCookie(context.secret, "clearance.session_token_multi-", overflow.token)}`,
		);
		const rotated = await local.client.token({
			fetchOptions: {
				headers,
				onSuccess: local.cookieSetter(headers),
			},
		});
		expect(rotated.data?.token).toEqual(expect.any(String));
		expect(await context.internalAdapter.findSession(overflow.token)).toBeNull();
	});

	it("should sign-out all sessions", async () => {
		const newHeaders = new Headers();
		await client.signOut({
			fetchOptions: {
				headers,
				onSuccess: cookieSetter(newHeaders),
			},
		});
		const res = await client.multiSession.listDeviceSessions({
			fetchOptions: {
				headers,
			},
		});
		expect(res.data).toHaveLength(0);
		const res2 = await client.multiSession.listDeviceSessions({
			fetchOptions: {
				headers: newHeaders,
			},
		});
		expect(res2.data).toHaveLength(0);
	});

	it("should replace old multi-session cookie when same user signs in again", async () => {
		const sameUserHeaders = new Headers();
		const sameUser = {
			email: "same-user@test.com",
			password: "password",
			name: "Same User",
		};

		let firstSessionToken = "";
		const firstSignUp = await client.signUp.email(sameUser, {
			onSuccess: cookieSetter(sameUserHeaders),
			onResponse(context) {
				const header = context.response.headers.get("set-cookie");
				const cookies = parseSetCookieHeader(header || "");
				firstSessionToken =
					cookies.get("clearance.session_token")?.value.split(".")[0] || "";
			},
		});
		expect(firstSignUp.error).toBeNull();
		const firstSessionId =
			(
				await client.getSession({
					fetchOptions: { headers: sameUserHeaders },
				})
			).data?.session.id || "";

		const sessionsAfterFirst = await client.multiSession.listDeviceSessions({
			fetchOptions: { headers: sameUserHeaders },
		});
		const firstUserSessions = sessionsAfterFirst.data?.filter(
			(s) => s.user.email === sameUser.email,
		);
		expect(firstUserSessions).toHaveLength(1);

		let secondSessionToken = "";
		const secondSignIn = await client.signIn.email(
			{
				email: sameUser.email,
				password: sameUser.password,
			},
			{
				onSuccess: cookieSetter(sameUserHeaders),
				onResponse(context) {
					const header = context.response.headers.get("set-cookie");
					const cookies = parseSetCookieHeader(header || "");
					secondSessionToken =
						cookies.get("clearance.session_token")?.value.split(".")[0] || "";
					// Verify old cookie is being deleted
					const oldCookieName = `clearance.session_token_multi-${encodeURIComponent(firstSessionId)}`;
					const oldCookie = cookies.get(oldCookieName);
					expect(oldCookie?.["max-age"]).toBe(0);
				},
				headers: sameUserHeaders,
			},
		);
		expect(secondSignIn.error).toBeNull();
		const secondSessionId =
			(
				await client.getSession({
					fetchOptions: { headers: sameUserHeaders },
				})
			).data?.session.id || "";

		expect(secondSessionToken).not.toBe(firstSessionToken);
		const sessionsAfterSecond = await client.multiSession.listDeviceSessions({
			fetchOptions: { headers: sameUserHeaders },
		});
		const secondUserSessions = sessionsAfterSecond.data?.filter(
			(s) => s.user.email === sameUser.email,
		);
		expect(secondUserSessions).toHaveLength(1);
		expect(secondUserSessions?.[0]?.session.id).toBe(secondSessionId);
	});

	it("keeps exactly N tracked active sessions when N+1 is admitted", async () => {
		const local = await getTestInstance(
			{
				plugins: [multiSession({ maximumSessions: 2 })],
			},
			{
				disableTestUser: true,
				clientOptions: { plugins: [multiSessionClient()] },
			},
		);
		const localHeaders = new Headers();
		const users = [
			{
				email: "multi-cap-first@test.com",
				password: "password",
				name: "Cap First",
			},
			{
				email: "multi-cap-second@test.com",
				password: "password",
				name: "Cap Second",
			},
			{
				email: "multi-cap-third@test.com",
				password: "password",
				name: "Cap Third",
			},
		];

		for (const user of users.slice(0, 2)) {
			const signup = await local.client.signUp.email(user, {
				headers: localHeaders,
				onSuccess: local.cookieSetter(localHeaders),
			});
			expect(signup.error).toBeNull();
		}
		const atLimit = await local.client.multiSession.listDeviceSessions({
			fetchOptions: { headers: localHeaders },
		});
		expect(atLimit.data).toHaveLength(2);
		expect(await local.db.findMany({ model: "session" })).toHaveLength(2);

		const overflowSignup = await local.client.signUp.email(users[2]!, {
			headers: localHeaders,
			onSuccess: local.cookieSetter(localHeaders),
		});
		expect(overflowSignup.error).toBeNull();
		const active = await local.client.getSession({
			fetchOptions: { headers: localHeaders },
		});
		expect(active.data?.user.email).toBe(users[2]!.email);

		const afterEviction = await local.client.multiSession.listDeviceSessions({
			fetchOptions: { headers: localHeaders },
		});
		expect(afterEviction.data).toHaveLength(2);
		expect(afterEviction.data?.map((entry) => entry.user.email)).toContain(
			users[2]!.email,
		);
		const persistedSessions = await local.db.findMany<{ id: string }>({
			model: "session",
		});
		expect(persistedSessions).toHaveLength(2);
		expect(
			persistedSessions.some(
				(session) => session.id === active.data?.session.id,
			),
		).toBe(true);
	});

	it("should reject forged multi-session cookies on sign-out", async () => {
		const attackerUser = {
			email: "attacker@test.com",
			password: "password",
			name: "Attacker",
		};
		const victimUser = {
			email: "victim@test.com",
			password: "password",
			name: "Victim",
		};

		const attackerHeaders = new Headers();
		await client.signUp.email(attackerUser, {
			onSuccess: cookieSetter(attackerHeaders),
		});

		const victimHeaders = new Headers();
		let victimSessionToken = "";
		const victimSignUp = await client.signUp.email(victimUser, {
			onSuccess: cookieSetter(victimHeaders),
			onResponse(context) {
				const header = context.response.headers.get("set-cookie");
				const cookies = parseSetCookieHeader(header || "");
				victimSessionToken =
					cookies.get("clearance.session_token")?.value.split(".")[0] || "";
			},
		});
		expect(victimSignUp.error).toBeNull();
		const victimSessionId =
			(
				await client.getSession({
					fetchOptions: { headers: victimHeaders },
				})
			).data?.session.id || "";

		const attackerSession = await client.getSession({
			fetchOptions: { headers: attackerHeaders },
		});
		const victimSession = await client.getSession({
			fetchOptions: { headers: victimHeaders },
		});
		expect(attackerSession.data?.user.email).toBe(attackerUser.email);
		expect(victimSession.data?.user.email).toBe(victimUser.email);

		const forgedCookieName = `clearance.session_token_multi-${encodeURIComponent(victimSessionId)}`;
		const forgedCookieValue = `${victimSessionToken}.fake-signature`;

		const signOutHeaders = new Headers(attackerHeaders);
		signOutHeaders.set(
			"cookie",
			`${attackerHeaders.get("cookie")}; ${forgedCookieName}=${forgedCookieValue}`,
		);

		await client.signOut({
			fetchOptions: {
				headers: signOutHeaders,
			},
		});

		const victimSessionAfter = await client.getSession({
			fetchOptions: { headers: victimHeaders },
		});
		expect(victimSessionAfter.data?.user.email).toBe(victimUser.email);
		expect(victimSessionAfter.data?.session.id).toBe(victimSessionId);

		const attackerSessionAfter = await client.getSession({
			fetchOptions: { headers: attackerHeaders },
		});
		expect(attackerSessionAfter.data).toBeNull();
	});

	it("binds set-active and revoke to the signed cookie value, not the body token", async () => {
		// A validly-signed multi-session cookie must only act on the session it was
		// signed for. The signature covers the cookie value, not its name, so a
		// request that presents its own valid cookie under another session's cookie
		// name (naming that other token in the body) must not revoke the other
		// session.
		const callerUser = {
			email: "ms-bind-caller@test.com",
			password: "password",
			name: "Caller",
		};
		const otherUser = {
			email: "ms-bind-other@test.com",
			password: "password",
			name: "Other",
		};

		const callerHeaders = new Headers();
		let callerSignedMultiCookie = "";
		const callerSignUp = await client.signUp.email(callerUser, {
			onSuccess: cookieSetter(callerHeaders),
			onResponse(context) {
				const cookies = parseSetCookieHeader(
					context.response.headers.get("set-cookie") || "",
				);
				callerSignedMultiCookie =
					Array.from(cookies.entries()).find(([name]) =>
						name.startsWith("clearance.session_token_multi-"),
					)?.[1].value || "";
			},
		});
		expect(callerSignUp.error).toBeNull();
		const callerSessionId =
			(
				await client.getSession({
					fetchOptions: { headers: callerHeaders },
				})
			).data?.session.id || "";

		const otherHeaders = new Headers();
		const otherSignUp = await client.signUp.email(otherUser, {
			onSuccess: cookieSetter(otherHeaders),
		});
		expect(otherSignUp.error).toBeNull();
		const otherSessionId =
			(
				await client.getSession({
					fetchOptions: { headers: otherHeaders },
				})
			).data?.session.id || "";
		expect(callerSignedMultiCookie).not.toBe("");
		expect(callerSessionId).not.toBe("");
		expect(otherSessionId).not.toBe("");

		// Place the caller's own validly-signed multi-session cookie under the other
		// session's cookie name and name the other token in the request body.
		const craftedHeaders = new Headers(callerHeaders);
		craftedHeaders.set(
			"cookie",
			`${callerHeaders.get("cookie")}; clearance.session_token_multi-${encodeURIComponent(otherSessionId)}=${callerSignedMultiCookie}`,
		);

		const forgedActivation = await client.multiSession.setActive({
			sessionId: otherSessionId,
			fetchOptions: { headers: craftedHeaders },
		});
		expect(forgedActivation.error?.status).toBe(401);

		const forgedRevoke = await client.multiSession.revoke(
			{ sessionId: otherSessionId },
			{ headers: craftedHeaders },
		);
		expect(forgedRevoke.error?.status).toBe(401);

		const otherAfter = await client.getSession({
			fetchOptions: { headers: otherHeaders },
		});
		expect(otherAfter.data?.session.id).toBe(otherSessionId);
	});

	it("ignores foreign cookie names and expires invalid exact-prefix signatures", async () => {
		const local = await getTestInstance(
			{ plugins: [multiSession({ maximumSessions: 2 })] },
			{
				disableTestUser: true,
				clientOptions: { plugins: [multiSessionClient()] },
			},
		);
		const localHeaders = new Headers();
		const signup = await local.client.signUp.email(
			{
				email: "multi-cookie-name-scope@example.test",
				password: "password",
				name: "Cookie Name Scope",
			},
			{ onSuccess: local.cookieSetter(localHeaders) },
		);
		expect(signup.error).toBeNull();
		const active = await local.client.getSession({
			fetchOptions: { headers: localHeaders },
		});
		const invalidName = "clearance.session_token_multi-invalid-signature";
		const foreignName = `foreign_clearance.session_token_multi-${encodeURIComponent(active.data!.session.id)}`;
		const substringName = `clearance.session_token_shadow_multi-${encodeURIComponent(active.data!.session.id)}`;
		localHeaders.set(
			"cookie",
			[
				localHeaders.get("cookie"),
				`${invalidName}=invalid.fake-signature`,
				`${foreignName}=invalid.fake-signature`,
				`${substringName}=invalid.fake-signature`,
			]
				.filter(Boolean)
				.join("; "),
		);
		let setCookie = "";
		const listed = await local.client.multiSession.listDeviceSessions({
			fetchOptions: {
				headers: localHeaders,
				onResponse(context) {
					setCookie = context.response.headers.get("set-cookie") || "";
				},
			},
		});
		expect(listed.data).toHaveLength(1);
		const expired = parseSetCookieHeader(setCookie);
		expect(expired.get(invalidName)?.["max-age"]).toBe(0);
		expect(expired.has(foreignName)).toBe(false);
		expect(expired.has(substringName)).toBe(false);
	});
});

describe("multi-session managed session authority", () => {
	it("does not activate a cookie-proven session after its policy revision changes", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-activation@example.test",
				password: "password",
				name: "Managed Multi Activation",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const sessionId = active.data!.session.id;
		runtime.setRevision("2");
		let setCookie = "not-observed";
		const result = await runtime.client.multiSession.setActive({
			sessionId,
			fetchOptions: {
				headers,
				onResponse(context) {
					setCookie = context.response.headers.get("set-cookie") || "";
				},
			},
		});

		expect(result.error?.status).toBe(401);
		expect(setCookie).not.toContain("clearance.session_token=");
		expect(
			parseSetCookieHeader(setCookie).get(
				`clearance.session_token_multi-${encodeURIComponent(sessionId)}`,
			)?.["max-age"],
		).toBe(0);
	});

	it("expires a policy-revised session during device-session listing", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-list-revision@example.test",
				password: "password",
				name: "Managed Multi List Revision",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		runtime.setRevision("2");
		let setCookie = "";
		const listed = await runtime.client.multiSession.listDeviceSessions({
			fetchOptions: {
				headers,
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});
		expect(listed.data).toEqual([]);
		expect(
			parseSetCookieHeader(setCookie).get(
				`clearance.session_token_multi-${encodeURIComponent(active.data!.session.id)}`,
			)?.["max-age"],
		).toBe(0);
	});

	it("skips a newer current-user credential that fails managed authority", async () => {
		vi.useFakeTimers({ now: new Date("2030-01-01T00:00:00.000Z") });
		try {
			const runtime = await createManagedMultiSessionRuntime();
			const headers = new Headers();
			const signup = await runtime.client.signUp.email(
				{
					email: "managed-multi-fallback@example.test",
					password: "password",
					name: "Managed Multi Fallback",
				},
				{ onSuccess: runtime.cookieSetter(headers) },
			);
			expect(signup.error).toBeNull();
			const active = await runtime.client.getSession({ fetchOptions: { headers } });
			const context = await runtime.auth.$context;
			const issue = async (userId: string) =>
				context.internalAdapter.createSession(
					userId,
					false,
					undefined,
					false,
					createInternalSessionIssuanceContext({
						purpose: "interactive",
						subjectId: userId,
						evidence: [{ kind: "primary", primaryMethod: "password" }],
					}),
				);
			const olderCurrentUser = await issue(active.data!.user.id);
			vi.setSystemTime(new Date("2030-01-01T00:00:01.000Z"));
			const newestCurrentUser = await issue(active.data!.user.id);
			vi.setSystemTime(new Date("2030-01-01T00:00:02.000Z"));
			const otherSignup = await runtime.client.signUp.email({
				email: "managed-multi-other@example.test",
				password: "password",
				name: "Managed Multi Other",
			});
			expect(otherSignup.error).toBeNull();
			const newerOtherUser = await issue(otherSignup.data!.user.id);
			const rotated = await context.internalAdapter.rotateSessionCredential(
				newestCurrentUser.token,
			);
			expect(rotated?.refreshToken).toEqual(expect.any(String));
			const secret = context.secret;
			headers.set(
				"cookie",
				[
					headers.get("cookie"),
					await signedMultiSessionCookie(secret, olderCurrentUser),
					await signedMultiSessionCookie(secret, newestCurrentUser),
					await signedMultiSessionCookie(secret, newerOtherUser),
				]
					.filter(Boolean)
					.join("; "),
			);

			const revoked = await runtime.client.multiSession.revoke(
				{ sessionId: active.data!.session.id },
				{
					headers,
					onSuccess: runtime.cookieSetter(headers),
				},
			);
			expect(revoked.error).toBeNull();
			const fallback = await runtime.client.getSession({
				fetchOptions: { headers },
			});
			expect(fallback.data?.session.id).toBe(olderCurrentUser.id);
		} finally {
			vi.useRealTimers();
		}
	});

	it("cleans malformed, duplicate, and authority-invalid tracked cookies", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-cleanup@example.test",
				password: "password",
				name: "Managed Multi Cleanup",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const context = await runtime.auth.$context;
		const invalid = await context.internalAdapter.createSession(
			active.data!.user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: active.data!.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		await context.internalAdapter.rotateSessionCredential(invalid.token);
		const invalidName = `clearance.session_token_multi-${encodeURIComponent(invalid.id)}`;
		const duplicateName = "clearance.session_token_multi-duplicate";
		const malformedName = "clearance.session_token_multi-";
		const invalidCookie = await signedMultiSessionCookie(context.secret, invalid);
		const activeCookie = Object.fromEntries(
			parseCookies(headers.get("cookie") || ""),
		)["clearance.session_token_multi-" + encodeURIComponent(active.data!.session.id)]!;
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				`${duplicateName}=${activeCookie}`,
				invalidCookie,
				`${malformedName}=garbage`,
			]
				.filter(Boolean)
				.join("; "),
		);
		let setCookie = "";
		const revoked = await runtime.client.multiSession.revoke(
			{ sessionId: active.data!.session.id },
			{
				headers,
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		);
		expect(revoked.error).toBeNull();
		const expired = parseSetCookieHeader(setCookie);
		expect(expired.get(duplicateName)?.["max-age"]).toBe(0);
		expect(expired.get(invalidName)?.["max-age"]).toBe(0);
		expect(expired.get(malformedName)?.["max-age"]).toBe(0);
		expect(expired.get("clearance.session_token")?.["max-age"]).toBe(0);
	});

	it("revokes verified overflow credentials when a lowered session cap signs out", async () => {
		const runtime = await createManagedMultiSessionRuntime(1);
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-lowered-signout@example.test",
				password: "password",
				name: "Managed Multi Lowered Signout",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const context = await runtime.auth.$context;
		const sourceToken =
			Object.fromEntries(parseCookies(headers.get("cookie") || ""))["clearance.session_token"]
				?.split(".")[0] || "";
		const overflow = await context.internalAdapter.createSession(
			signup.data!.user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: signup.data!.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		headers.set(
			"cookie",
			`${headers.get("cookie")}; ${await signedMultiSessionCookie(context.secret, overflow)}`,
		);
		const signedOut = await runtime.client.signOut({ fetchOptions: { headers } });
		expect(signedOut.error).toBeNull();
		expect(await context.internalAdapter.findSession(sourceToken)).toBeNull();
		expect(await context.internalAdapter.findSession(overflow.token)).toBeNull();
	});

	it("revokes verified overflow credentials when admitting a new session under a lowered cap", async () => {
		const runtime = await createManagedMultiSessionRuntime(1);
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-lowered-admission-source@example.test",
				password: "password",
				name: "Managed Multi Lowered Admission Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const context = await runtime.auth.$context;
		const sourceToken =
			Object.fromEntries(parseCookies(headers.get("cookie") || ""))["clearance.session_token"]
				?.split(".")[0] || "";
		const overflow = await context.internalAdapter.createSession(
			signup.data!.user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: signup.data!.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		headers.set(
			"cookie",
			`${headers.get("cookie")}; ${await signedMultiSessionCookie(context.secret, overflow)}`,
		);
		const admitted = await runtime.client.signUp.email(
			{
				email: "managed-multi-lowered-admission-next@example.test",
				password: "password",
				name: "Managed Multi Lowered Admission Next",
			},
			{ headers, onSuccess: runtime.cookieSetter(headers) },
		);
		expect(admitted.error).toBeNull();
		expect(await context.internalAdapter.findSession(sourceToken)).toBeNull();
		expect(await context.internalAdapter.findSession(overflow.token)).toBeNull();
	});

	it("cleans invalid cookies after finding the set-active target", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-set-active-cleanup@example.test",
				password: "password",
				name: "Managed Multi Set Active Cleanup",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const createSession = () =>
			context.internalAdapter.createSession(
				signup.data!.user.id,
				false,
				undefined,
				false,
				createInternalSessionIssuanceContext({
					purpose: "interactive",
					subjectId: signup.data!.user.id,
					evidence: [{ kind: "primary", primaryMethod: "password" }],
				}),
			);
		const target = await createSession();
		const invalid = await createSession();
		await context.internalAdapter.rotateSessionCredential(invalid.token);
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				await signedMultiSessionCookie(context.secret, target),
				await signedMultiSessionCookie(context.secret, invalid),
			].join("; "),
		);
		let setCookie = "";
		const activated = await runtime.client.multiSession.setActive({
			sessionId: target.id,
			fetchOptions: {
				headers,
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});
		expect(activated.error).toBeNull();
		expect(
			parseSetCookieHeader(setCookie).get(
				`clearance.session_token_multi-${encodeURIComponent(invalid.id)}`,
			)?.["max-age"],
		).toBe(0);
	});

	it("cleans invalid cookies after finding a non-active revoke target", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-revoke-cleanup@example.test",
				password: "password",
				name: "Managed Multi Revoke Cleanup",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const createSession = () =>
			context.internalAdapter.createSession(
				signup.data!.user.id,
				false,
				undefined,
				false,
				createInternalSessionIssuanceContext({
					purpose: "interactive",
					subjectId: signup.data!.user.id,
					evidence: [{ kind: "primary", primaryMethod: "password" }],
				}),
			);
		const target = await createSession();
		const invalid = await createSession();
		await context.internalAdapter.rotateSessionCredential(invalid.token);
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				await signedMultiSessionCookie(context.secret, target),
				await signedMultiSessionCookie(context.secret, invalid),
			].join("; "),
		);
		let setCookie = "";
		const revoked = await runtime.client.multiSession.revoke(
			{ sessionId: target.id },
			{
				headers,
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		);
		expect(revoked.error).toBeNull();
		expect(
			parseSetCookieHeader(setCookie).get(
				`clearance.session_token_multi-${encodeURIComponent(invalid.id)}`,
			)?.["max-age"],
		).toBe(0);
	});

	it("retains a canonical live cookie behind a lexically earlier mismatched duplicate", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-canonical-duplicate@example.test",
				password: "password",
				name: "Managed Multi Canonical Duplicate",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const context = await runtime.auth.$context;
		const token =
			parseCookies(headers.get("cookie") || "")
				.get(
					`clearance.session_token_multi-${encodeURIComponent(active.data!.session.id)}`,
				)
				?.split(".")[0] || "";
		const duplicateName = "clearance.session_token_multi-000-mismatch";
		headers.set(
			"cookie",
			`${headers.get("cookie")}; ${await signedNamedMultiSessionCookie(context.secret, duplicateName, token)}`,
		);
		let setCookie = "";
		const listed = await runtime.client.multiSession.listDeviceSessions({
			fetchOptions: {
				headers,
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});
		expect(listed.data?.map((entry) => entry.session.id)).toContain(
			active.data!.session.id,
		);
		expect(parseSetCookieHeader(setCookie).get(duplicateName)?.["max-age"]).toBe(
			0,
		);
		expect(await context.internalAdapter.findSession(token)).not.toBeNull();
	});

	it("cleans invalid names beyond the authority-read budget without rejecting the request", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-input-envelope@example.test",
				password: "password",
				name: "Managed Multi Input Envelope",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const originalCookie = headers.get("cookie") || "";
		const attackHeaders = new Headers(headers);
		attackHeaders.set(
			"cookie",
			[
				originalCookie,
				...Array.from(
					{ length: 101 },
					(_, index) =>
						`clearance.session_token_multi-overflow-${index}=invalid.invalid`,
				),
			].join("; "),
		);
		let setCookie = "";
		const listed = await runtime.client.multiSession.listDeviceSessions({
			fetchOptions: {
				headers: attackHeaders,
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});
		expect(listed.error).toBeNull();
		expect(
			parseSetCookieHeader(setCookie).get(
				"clearance.session_token_multi-overflow-99",
			)?.["max-age"],
		).toBe(0);
		const originalToken =
			parseCookies(originalCookie)
				.get(
					`clearance.session_token_multi-${encodeURIComponent(active.data!.session.id)}`,
				)
				?.split(".")[0] || "";
		expect(await (await runtime.auth.$context).internalAdapter.findSession(originalToken)).not.toBeNull();
		const recovered = await runtime.client.multiSession.listDeviceSessions({
			fetchOptions: { headers: new Headers({ cookie: originalCookie }) },
		});
		expect(recovered.data?.map((entry) => entry.session.id)).toContain(
			active.data!.session.id,
		);
	});

	it("signs out over-envelope inputs without managed authority reads", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-signout-envelope@example.test",
				password: "password",
				name: "Managed Multi Signout Envelope",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const activeToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		const attackHeaders = new Headers(headers);
		attackHeaders.set(
			"cookie",
			[
				headers.get("cookie"),
				...Array.from(
					{ length: 100 },
					(_, index) =>
						`clearance.session_token_multi-signout-overflow-${index}=invalid.invalid`,
				),
			].join("; "),
		);
		const originalFindSession = context.internalAdapter.findSession.bind(
			context.internalAdapter,
		);
		let authorityReads = 0;
		const lookup = vi
			.spyOn(context.internalAdapter, "findSession")
			.mockImplementation(async (token) => {
				authorityReads += 1;
				return originalFindSession(token);
			});
		let setCookie = "";
		try {
			const signedOut = await runtime.client.signOut({
				fetchOptions: {
					headers: attackHeaders,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			});
			expect(signedOut.error).toBeNull();
			expect(authorityReads).toBe(0);
		} finally {
			lookup.mockRestore();
		}
		expect(setCookie).toContain("clearance.session_token_multi-");
		expect(await context.internalAdapter.findSession(activeToken)).toBeNull();
	});

	it("revokes over-envelope inputs within its authority-read budget", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-revoke-envelope@example.test",
				password: "password",
				name: "Managed Multi Revoke Envelope",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const context = await runtime.auth.$context;
		const activeToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		const attackHeaders = new Headers(headers);
		attackHeaders.set(
			"cookie",
			[
				headers.get("cookie"),
				...Array.from(
					{ length: 100 },
					(_, index) =>
						`clearance.session_token_multi-revoke-overflow-${index}=invalid.invalid`,
				),
			].join("; "),
		);
		const originalFindSession = context.internalAdapter.findSession.bind(
			context.internalAdapter,
		);
		let authorityReads = 0;
		const lookup = vi
			.spyOn(context.internalAdapter, "findSession")
			.mockImplementation(async (token) => {
				authorityReads += 1;
				return originalFindSession(token);
			});
		let setCookie = "";
		try {
			const revoked = await runtime.client.multiSession.revoke(
				{ sessionId: active.data!.session.id },
				{
					headers: attackHeaders,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			);
			expect(revoked.error).toBeNull();
			expect(authorityReads).toBeLessThanOrEqual(100);
		} finally {
			lookup.mockRestore();
		}
		expect(setCookie).toContain("clearance.session_token_multi-");
		expect(await context.internalAdapter.findSession(activeToken)).toBeNull();
	});

	it("signs out every signature-verified token without authority gating", async () => {
		const runtime = await createManagedMultiSessionRuntime(1);
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-invalid-signout@example.test",
				password: "password",
				name: "Managed Multi Invalid Signout",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const context = await runtime.auth.$context;
		const otherUser = await context.internalAdapter.createUser({
			email: "managed-multi-invalid-signout-other@example.test",
			name: "Managed Multi Invalid Signout Other",
		});
		const policyRevisedSession = await context.internalAdapter.createSession(
			otherUser.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: otherUser.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		const liveUser = await context.internalAdapter.createUser({
			email: "managed-multi-live-signout@example.test",
			name: "Managed Multi Live Signout",
		});
		const liveSession = await context.internalAdapter.createSession(
			liveUser.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: liveUser.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				await signedMultiSessionCookie(context.secret, policyRevisedSession),
				await signedNamedMultiSessionCookie(
					context.secret,
					"clearance.session_token_multi-000-live-duplicate",
					liveSession.token,
				),
				await signedMultiSessionCookie(context.secret, liveSession),
			].join("; "),
		);
		runtime.setSubjectRevision(otherUser.id, "2");
		expect(
			await context.internalAdapter.findSession(policyRevisedSession.token),
		).toBeNull();
		const signedOut = await runtime.client.signOut({ fetchOptions: { headers } });
		expect(signedOut.error).toBeNull();
		runtime.setSubjectRevision(otherUser.id, null);
		expect(
			await context.internalAdapter.findSession(policyRevisedSession.token),
		).toBeNull();
		expect(await context.internalAdapter.findSession(liveSession.token)).toBeNull();
	});

	it("validates stale-first cookies before evicting the oldest live admission", async () => {
		vi.useFakeTimers({ now: new Date("2030-01-01T00:00:00.000Z") });
		try {
			const runtime = await createManagedMultiSessionRuntime(2);
			const context = await runtime.auth.$context;
			const issue = async (label: string) => {
				const user = await context.internalAdapter.createUser({
					email: `managed-multi-${label}@example.test`,
					name: label,
				});
				return context.internalAdapter.createSession(
					user.id,
					false,
					undefined,
					false,
					createInternalSessionIssuanceContext({
						purpose: "interactive",
						subjectId: user.id,
						evidence: [{ kind: "primary", primaryMethod: "password" }],
					}),
				);
			};
			const stale = await issue("stale-admission");
			await context.internalAdapter.rotateSessionCredential(stale.token);
			vi.setSystemTime(new Date("2030-01-01T00:00:01.000Z"));
			const older = await issue("older-admission");
			vi.setSystemTime(new Date("2030-01-01T00:00:02.000Z"));
			const newer = await issue("newer-admission");
			const headers = new Headers({
				cookie: [
					await signedMultiSessionCookie(context.secret, stale),
					await signedMultiSessionCookie(context.secret, older),
					await signedNamedMultiSessionCookie(
						context.secret,
						"clearance.session_token_multi-000-newer-duplicate",
						newer.token,
					),
					await signedMultiSessionCookie(context.secret, newer),
				].join("; "),
			});
			vi.setSystemTime(new Date("2030-01-01T00:00:03.000Z"));
			const admitted = await runtime.client.signUp.email(
				{
					email: "managed-multi-new-admission@example.test",
					password: "password",
					name: "New Admission",
				},
				{ headers },
			);
			expect(admitted.error).toBeNull();
			expect(await context.internalAdapter.findSession(older.token)).toBeNull();
			expect(await context.internalAdapter.findSession(newer.token)).not.toBeNull();
		} finally {
			vi.useRealTimers();
		}
	});

	it("selects a live fallback behind a stale-first cookie", async () => {
		const runtime = await createManagedMultiSessionRuntime(1);
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-fallback-active@example.test",
				password: "password",
				name: "Fallback Active",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const context = await runtime.auth.$context;
		const issue = async (email: string) => {
			const user = await context.internalAdapter.createUser({ email, name: email });
			return context.internalAdapter.createSession(
				user.id,
				false,
				undefined,
				false,
				createInternalSessionIssuanceContext({
					purpose: "interactive",
					subjectId: user.id,
					evidence: [{ kind: "primary", primaryMethod: "password" }],
				}),
			);
		};
		const stale = await issue("managed-multi-fallback-stale@example.test");
		await context.internalAdapter.rotateSessionCredential(stale.token);
		const fallback = await issue("managed-multi-fallback-live@example.test");
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				await signedMultiSessionCookie(context.secret, stale),
				await signedNamedMultiSessionCookie(
					context.secret,
					"clearance.session_token_multi-000-fallback-duplicate",
					fallback.token,
				),
				await signedMultiSessionCookie(context.secret, fallback),
			].join("; "),
		);
		let fallbackSetCookie = "";
		const revoked = await runtime.client.multiSession.revoke(
			{ sessionId: active.data!.session.id },
			{
				headers,
				onResponse(response) {
					fallbackSetCookie = response.response.headers.get("set-cookie") || "";
					runtime.cookieSetter(headers)(response);
				},
			},
		);
		expect(revoked.error).toBeNull();
		expect(
			parseSetCookieHeader(fallbackSetCookie)
				.get("clearance.session_token")
				?.value.split(".")[0],
		).toBe(fallback.token);
		expect(await context.internalAdapter.findSession(fallback.token)).not.toBeNull();
		expect(signup.error).toBeNull();
	});

	it("rejects false postcommit active-revoke recovery when raw authority remains", async () => {
		const runtime = await createManagedMultiSessionRuntime(2);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-false-revoke-first@example.test",
				password: "password",
				name: "False Revoke First",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		await runtime.client.signUp.email(
			{
				email: "managed-multi-false-revoke-second@example.test",
				password: "password",
				name: "False Revoke Second",
			},
			{ headers, onSuccess: runtime.cookieSetter(headers) },
		);
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const activeToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		const context = await runtime.auth.$context;
		const stagedCleanupName =
			"clearance.session_token_multi-invalid-staged-cleanup";
		headers.set(
			"cookie",
			`${headers.get("cookie")}; ${stagedCleanupName}=invalid.invalid`,
		);
		const deletion = vi
			.spyOn(context.internalAdapter, "deleteSessionById")
			.mockImplementationOnce(async () => {
				runtime.setSubjectRevision(active.data!.user.id, "2");
				throw new AfterTransactionHookError([
					new Error("false active-revoke postcommit signal"),
				]);
			});
		let setCookie = "";
		try {
			const revoked = await runtime.client.multiSession.revoke(
				{ sessionId: active.data!.session.id },
				{
					headers,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			);
			expect(revoked.error).not.toBeNull();
		} finally {
			deletion.mockRestore();
		}
		expect(
			parseSetCookieHeader(setCookie).get(
				`clearance.session_token_multi-${encodeURIComponent(active.data!.session.id)}`,
			)?.["max-age"],
		).not.toBe(0);
		expect(
			parseSetCookieHeader(setCookie).get(stagedCleanupName)?.["max-age"],
		).not.toBe(0);
		expect(setCookie).not.toMatch(/clearance\.session_token=[^;]+/);
		runtime.setSubjectRevision(active.data!.user.id, null);
		expect(await context.internalAdapter.findSession(activeToken)).not.toBeNull();
	});

	it("rejects false postcommit admission recovery without publishing tracking state", async () => {
		const runtime = await createManagedMultiSessionRuntime(1);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-false-admission-source@example.test",
				password: "password",
				name: "False Admission Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const source = await runtime.client.getSession({ fetchOptions: { headers } });
		const sourceToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		const context = await runtime.auth.$context;
		const deletion = vi
			.spyOn(context.internalAdapter, "deleteSessions")
			.mockImplementationOnce(async () => {
				runtime.setSubjectRevision(source.data!.user.id, "2");
				throw new AfterTransactionHookError([
					new Error("false admission postcommit signal"),
				]);
			});
		let setCookie = "";
		try {
			const admitted = await runtime.client.signUp.email(
				{
					email: "managed-multi-false-admission-new@example.test",
					password: "password",
					name: "False Admission New",
				},
				{
					headers,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			);
			expect(admitted.error).not.toBeNull();
		} finally {
			deletion.mockRestore();
		}
		const responseCookies = parseSetCookieHeader(setCookie);
		expect(
			Array.from(responseCookies.keys()).some((name) =>
				name.startsWith("clearance.session_token_multi-"),
			),
		).toBe(false);
		expect(
			responseCookies.get(
				`clearance.session_token_multi-${encodeURIComponent(source.data!.session.id)}`,
			)?.["max-age"],
		).not.toBe(0);
		runtime.setSubjectRevision(source.data!.user.id, null);
		expect(await context.internalAdapter.findSession(sourceToken)).not.toBeNull();
	});

	it("publishes active-revoke fallback after secondary cleanup fails postcommit", async () => {
		const failure = {
			failKey: null as string | null,
			error: new Error("active revoke secondary cleanup failed"),
		};
		const runtime = await createManagedMultiSessionRuntime(2, failure);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-revoke-fallback-first@example.test",
				password: "password",
				name: "First Fallback",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		await runtime.client.signUp.email(
			{
				email: "managed-multi-revoke-fallback-second@example.test",
				password: "password",
				name: "Second Fallback",
			},
			{ headers, onSuccess: runtime.cookieSetter(headers) },
		);
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const activeToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		failure.failKey = `session-handle:${active.data!.session.id}`;
		const revoked = await runtime.client.multiSession.revoke(
			{ sessionId: active.data!.session.id },
			{ headers, onSuccess: runtime.cookieSetter(headers) },
		);
		expect(revoked.error).toBeNull();
		const context = await runtime.auth.$context;
		expect(await context.internalAdapter.findSession(activeToken)).toBeNull();
		const fallback = await runtime.client.getSession({ fetchOptions: { headers } });
		expect(fallback.data?.session.id).not.toBe(active.data!.session.id);
	});

	it("publishes overflow admission after secondary cleanup fails postcommit", async () => {
		const failure = {
			failKey: null as string | null,
			error: new Error("overflow admission secondary cleanup failed"),
		};
		const runtime = await createManagedMultiSessionRuntime(1, failure);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-overflow-source@example.test",
				password: "password",
				name: "Overflow Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const source = await runtime.client.getSession({ fetchOptions: { headers } });
		const sourceToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		failure.failKey = `session-handle:${source.data!.session.id}`;
		const admitted = await runtime.client.signUp.email(
			{
				email: "managed-multi-overflow-successor@example.test",
				password: "password",
				name: "Overflow Successor",
			},
			{ headers, onSuccess: runtime.cookieSetter(headers) },
		);
		expect(admitted.error).toBeNull();
		const context = await runtime.auth.$context;
		expect(await context.internalAdapter.findSession(sourceToken)).toBeNull();
		const listed = await runtime.client.multiSession.listDeviceSessions({
			fetchOptions: { headers },
		});
		expect(listed.data).toHaveLength(1);
		expect(listed.data?.[0]?.user.email).toBe(
			"managed-multi-overflow-successor@example.test",
		);
	});

	it("finishes signout after tracked-session cleanup fails postcommit", async () => {
		const failure = {
			failKey: null as string | null,
			error: new Error("signout secondary cleanup failed"),
		};
		const runtime = await createManagedMultiSessionRuntime(2, failure);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-signout-first@example.test",
				password: "password",
				name: "Signout First",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const first = await runtime.client.getSession({ fetchOptions: { headers } });
		const firstToken =
			Array.from(parseCookies(headers.get("cookie") || "").entries())
				.find(([name]) =>
					name.startsWith("clearance.session_token_multi-"),
				)?.[1]
				.split(".")[0] || "";
		await runtime.client.signUp.email(
			{
				email: "managed-multi-signout-second@example.test",
				password: "password",
				name: "Signout Second",
			},
			{ headers, onSuccess: runtime.cookieSetter(headers) },
		);
		const secondToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		failure.failKey = `session-handle:${first.data!.session.id}`;
		const signedOut = await runtime.client.signOut({ fetchOptions: { headers } });
		expect(signedOut.error).toBeNull();
		const context = await runtime.auth.$context;
		expect(await context.internalAdapter.findSession(firstToken)).toBeNull();
		expect(await context.internalAdapter.findSession(secondToken)).toBeNull();
	});

	it("does not complete secondary-only signout when the credential authority remains", async () => {
		const failure = {
			failKey: null as string | null,
			error: new Error("secondary credential deletion failed"),
		};
		const runtime = await createManagedMultiSessionRuntime(1, failure, true);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-secondary-signout@example.test",
				password: "password",
				name: "Secondary Signout",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const token =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		failure.failKey = getSecondarySessionKeys(context.options).credential(
			await digestSessionRefreshSecret(token),
		);
		let setCookie = "";
		await expect(
			runtime.client.signOut({
				fetchOptions: {
					headers,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			}),
		).rejects.toThrow();
		expect(await context.internalAdapter.findSession(token)).not.toBeNull();
		expect(
			parseSetCookieHeader(setCookie).get(
				Array.from(parseCookies(headers.get("cookie") || "").keys()).find((name) =>
					name.startsWith("clearance.session_token_multi-"),
				) || "",
			)?.["max-age"],
		).not.toBe(0);
	});

	it("does not publish a successor after secondary-only admission cleanup fails", async () => {
		const failure = {
			failKey: null as string | null,
			error: new Error("secondary admission deletion failed"),
		};
		const runtime = await createManagedMultiSessionRuntime(1, failure, true);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-secondary-admission-source@example.test",
				password: "password",
				name: "Secondary Admission Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const sourceToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		failure.failKey = getSecondarySessionKeys(context.options).credential(
			await digestSessionRefreshSecret(sourceToken),
		);
		let setCookie = "";
		const admitted = await runtime.client.signUp.email(
			{
				email: "managed-multi-secondary-admission-successor@example.test",
				password: "password",
				name: "Secondary Admission Successor",
			},
			{
				headers,
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		);
		expect(admitted.error).not.toBeNull();
		expect(await context.internalAdapter.findSession(sourceToken)).not.toBeNull();
		expect(
			Array.from(parseSetCookieHeader(setCookie).keys()).some((name) =>
				name.startsWith("clearance.session_token_multi-"),
			),
		).toBe(false);
	});

	it("propagates managed authority outages without expiring tracked cookies", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const signup = await runtime.client.signUp.email(
			{
				email: "managed-multi-reader-outage@example.test",
				password: "password",
				name: "Managed Multi Reader Outage",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		expect(signup.error).toBeNull();
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const cookieName = `clearance.session_token_multi-${encodeURIComponent(active.data!.session.id)}`;
		runtime.setReaderError(new Error("policy reader unavailable"));
		let listSetCookie = "";
		const listed = await runtime.client.multiSession.listDeviceSessions({
			fetchOptions: {
				headers,
				onResponse(response) {
					listSetCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});
		expect(listed.error).not.toBeNull();
		let activationSetCookie = "";
		const activated = await runtime.client.multiSession.setActive({
			sessionId: active.data!.session.id,
			fetchOptions: {
				headers,
				onResponse(response) {
					activationSetCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});
		expect(activated.error).not.toBeNull();
		for (const setCookie of [listSetCookie, activationSetCookie]) {
			expect(parseSetCookieHeader(setCookie).get(cookieName)?.["max-age"]).not.toBe(
				0,
			);
		}
		runtime.setReaderError(null);
		const listedAfterRecovery = await runtime.client.multiSession.listDeviceSessions({
			fetchOptions: { headers },
		});
		expect(listedAfterRecovery.data?.map((entry) => entry.session.id)).toContain(
			active.data!.session.id,
		);
	});

	it("signout cleans malformed signed names and revokes every verified token", async () => {
		const runtime = await createManagedMultiSessionRuntime(1);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-signed-malformed-source@example.test",
				password: "password",
				name: "Signed Malformed Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const issue = async (email: string) => {
			const user = await context.internalAdapter.createUser({ email, name: email });
			return context.internalAdapter.createSession(
				user.id,
				false,
				undefined,
				false,
				createInternalSessionIssuanceContext({
					purpose: "interactive",
					subjectId: user.id,
					evidence: [{ kind: "primary", primaryMethod: "password" }],
				}),
			);
		};
		const malformed = await issue("managed-multi-signed-malformed@example.test");
		const overflow = await issue("managed-multi-signed-overflow@example.test");
		const sourceToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				...await Promise.all(
					Array.from({ length: 97 }, (_, index) =>
						signedNamedMultiSessionCookie(
							context.secret,
							`clearance.session_token_multi-alias-${index.toString().padStart(3, "0")}`,
							sourceToken,
						),
					),
				),
				await signedNamedMultiSessionCookie(
					context.secret,
					"clearance.session_token_multi-",
					malformed.token,
				),
				await signedMultiSessionCookie(context.secret, overflow),
			].join("; "),
		);
		let setCookie = "";
		const signedOut = await runtime.client.signOut({
			fetchOptions: {
				headers,
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});
		expect(signedOut.error).toBeNull();
		expect(await context.internalAdapter.findSession(malformed.token)).toBeNull();
		expect(await context.internalAdapter.findSession(overflow.token)).toBeNull();
		expect(
			parseSetCookieHeader(setCookie).get("clearance.session_token_multi-")?.[
				"max-age"
			],
		).toBe(0);
	});

	it("admission reaches distinct valid sessions behind copied aliases", async () => {
		const runtime = await createManagedMultiSessionRuntime(1);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-alias-admission-source@example.test",
				password: "password",
				name: "Alias Admission Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const overflowUser = await context.internalAdapter.createUser({
			email: "managed-multi-alias-admission-overflow@example.test",
			name: "Alias Admission Overflow",
		});
		const overflow = await context.internalAdapter.createSession(
			overflowUser.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: overflowUser.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		const sourceToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				...await Promise.all(
					Array.from({ length: 98 }, (_, index) =>
						signedNamedMultiSessionCookie(
							context.secret,
							`clearance.session_token_multi-alias-${index.toString().padStart(3, "0")}`,
							sourceToken,
						),
					),
				),
				await signedMultiSessionCookie(context.secret, overflow),
			].join("; "),
		);
		const admitted = await runtime.client.signUp.email(
			{
				email: "managed-multi-alias-admission-successor@example.test",
				password: "password",
				name: "Alias Admission Successor",
			},
			{ headers },
		);
		expect(admitted.error).toBeNull();
		expect(await context.internalAdapter.findSession(overflow.token)).toBeNull();
	});

	it("does not commit staged cleanup when a later authority lookup fails", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-late-outage-source@example.test",
				password: "password",
				name: "Late Outage Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const source = await runtime.client.getSession({ fetchOptions: { headers } });
		const token =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		const laterUser = await context.internalAdapter.createUser({
			email: "managed-multi-late-outage-later@example.test",
			name: "Late Outage Later",
		});
		const later = await context.internalAdapter.createSession(
			laterUser.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: laterUser.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		const duplicateName = "clearance.session_token_multi-000-staged-cleanup";
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				await signedNamedMultiSessionCookie(context.secret, duplicateName, token),
				await signedMultiSessionCookie(context.secret, later),
			].join("; "),
		);
		const originalFindSession = context.internalAdapter.findSession.bind(
			context.internalAdapter,
		);
		let calls = 0;
		const lookup = vi
			.spyOn(context.internalAdapter, "findSession")
			.mockImplementation(async (candidateToken) => {
				calls += 1;
				if (calls === 2) throw new Error("later authority outage");
				return originalFindSession(candidateToken);
			});
		let setCookie = "";
		try {
			const listed = await runtime.client.multiSession.listDeviceSessions({
				fetchOptions: {
					headers,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			});
			expect(listed.error).not.toBeNull();
		} finally {
			lookup.mockRestore();
		}
		expect(source.data).not.toBeNull();
		expect(parseSetCookieHeader(setCookie).get(duplicateName)?.["max-age"]).not.toBe(
			0,
		);
	});

	it("keeps the 100th active-revoke fallback within its request-wide authority-read budget", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-active-read-budget@example.test",
				password: "password",
				name: "Active Read Budget",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const context = await runtime.auth.$context;
		const fallbackUser = await context.internalAdapter.createUser({
			email: "managed-multi-active-read-fallback@example.test",
			name: "Active Read Fallback",
		});
		const fallback = await context.internalAdapter.createSession(
			fallbackUser.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: fallbackUser.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				...await Promise.all(
					Array.from({ length: 98 }, (_, index) =>
						signedNamedMultiSessionCookie(
							context.secret,
							`clearance.session_token_multi-unissued-${index.toString().padStart(3, "0")}`,
							`unissued-token-${index}`,
						),
					),
				),
				await signedMultiSessionCookie(context.secret, fallback),
			].join("; "),
		);
		const originalFindSession = context.internalAdapter.findSession.bind(
			context.internalAdapter,
		);
		let calls = 0;
		const lookup = vi
			.spyOn(context.internalAdapter, "findSession")
			.mockImplementation(async (candidateToken) => {
				calls += 1;
				return originalFindSession(candidateToken);
			});
		let setCookie = "";
		try {
			const revoked = await runtime.client.multiSession.revoke(
				{ sessionId: active.data!.session.id },
				{
					headers,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			);
			expect(revoked.error).toBeNull();
		} finally {
			lookup.mockRestore();
		}
		expect(calls).toBeLessThanOrEqual(100);
		expect(
			parseSetCookieHeader(setCookie)
				.get("clearance.session_token")
				?.value.split(".")[0],
		).toBe(fallback.token);
	});

	it("evicts malformed signed capacity overflow during admission", async () => {
		const runtime = await createManagedMultiSessionRuntime(1);
		const headers = new Headers();
		const source = await runtime.client.signUp.email(
			{
				email: "managed-multi-malformed-admission-source@example.test",
				password: "password",
				name: "Malformed Admission Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const overflow = await context.internalAdapter.createSession(
			source.data!.user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: source.data!.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		headers.set(
			"cookie",
			`${headers.get("cookie")}; ${await signedNamedMultiSessionCookie(context.secret, "clearance.session_token_multi-mismatched", overflow.token)}`,
		);
		const admitted = await runtime.client.signUp.email(
			{
				email: "managed-multi-malformed-admission-successor@example.test",
				password: "password",
				name: "Malformed Admission Successor",
			},
			{ headers },
		);
		expect(admitted.error).toBeNull();
		expect(await context.internalAdapter.findSession(overflow.token)).toBeNull();
	});

	it("prioritizes active and non-active targets above 101 lexically earlier groups", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const source = await runtime.client.signUp.email(
			{
				email: "managed-multi-nonactive-budget-source@example.test",
				password: "password",
				name: "Nonactive Budget Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const target = await context.internalAdapter.createSession(
			source.data!.user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: source.data!.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				await signedMultiSessionCookie(context.secret, target),
				...await Promise.all(
					Array.from({ length: 99 }, (_, index) =>
						signedNamedMultiSessionCookie(
							context.secret,
							`clearance.session_token_multi-000-unissued-${index.toString().padStart(3, "0")}`,
							`unissued-token-${index}`,
						),
					),
				),
			].join("; "),
		);
		const originalFindSession = context.internalAdapter.findSession.bind(
			context.internalAdapter,
		);
		let calls = 0;
		const lookup = vi
			.spyOn(context.internalAdapter, "findSession")
			.mockImplementation(async (token) => {
				calls += 1;
				return originalFindSession(token);
			});
		try {
			const revoked = await runtime.client.multiSession.revoke(
				{ sessionId: target.id },
				{ headers },
			);
			expect(revoked.error).toBeNull();
		} finally {
			lookup.mockRestore();
		}
		expect(calls).toBeLessThanOrEqual(100);
		expect(await context.internalAdapter.findSession(target.token)).toBeNull();
	});

	it("prioritizes a deprecated active session-token alias above 101 lexically earlier groups", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-deprecated-active-budget@example.test",
				password: "password",
				name: "Deprecated Active Budget",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const token =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				...await Promise.all(
					Array.from({ length: 100 }, (_, index) =>
						signedNamedMultiSessionCookie(
							context.secret,
							`clearance.session_token_multi-000-unissued-${index.toString().padStart(3, "0")}`,
							`unissued-token-${index}`,
						),
					),
				),
			].join("; "),
		);
		const originalFindSession = context.internalAdapter.findSession.bind(
			context.internalAdapter,
		);
		let calls = 0;
		const lookup = vi
			.spyOn(context.internalAdapter, "findSession")
			.mockImplementation(async (candidateToken) => {
				calls += 1;
				return originalFindSession(candidateToken);
			});
		try {
			const revoked = await runtime.client.multiSession.revoke(
				{ sessionToken: token },
				{ headers },
			);
			expect(revoked.error).toBeNull();
		} finally {
			lookup.mockRestore();
		}
		expect(calls).toBeLessThanOrEqual(100);
	});

	it("accepts proven postcommit deletion with a preserved modern raw session row", async () => {
		const runtime = await createManagedMultiSessionRuntime(
			1,
			undefined,
			false,
			true,
		);
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-preserved-row-source@example.test",
				password: "password",
				name: "Preserved Row Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const sourceToken =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		const context = await runtime.auth.$context;
		const originalDeleteSessions = context.internalAdapter.deleteSessions.bind(
			context.internalAdapter,
		);
		const deletion = vi
			.spyOn(context.internalAdapter, "deleteSessions")
			.mockImplementationOnce(async (tokens) => {
				await originalDeleteSessions(tokens);
				throw new AfterTransactionHookError([
					new Error("preserved-row postcommit signal"),
				]);
			});
		try {
			const admitted = await runtime.client.signUp.email(
				{
					email: "managed-multi-preserved-row-successor@example.test",
					password: "password",
					name: "Preserved Row Successor",
				},
				{ headers },
			);
			expect(admitted.error).toBeNull();
		} finally {
			deletion.mockRestore();
		}
		expect(await context.internalAdapter.findSession(sourceToken)).toBeNull();
	});

	it("rejects exact predecessor recovery while middleware authenticates its live successor", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		await runtime.client.signUp.email(
			{
				email: "managed-multi-predecessor-source@example.test",
				password: "password",
				name: "Predecessor Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const active = await runtime.client.getSession({ fetchOptions: { headers } });
		const context = await runtime.auth.$context;
		const token =
			parseCookies(headers.get("cookie") || "")
				.get("clearance.session_token")
				?.split(".")[0] || "";
		const rotated = await context.internalAdapter.rotateSessionCredential(token);
		const successorToken = rotated?.refreshToken;
		expect(successorToken).toEqual(expect.any(String));
		headers.set(
			"cookie",
			[
				await signedNamedMultiSessionCookie(
					context.secret,
					"clearance.session_token",
					successorToken!,
				),
				await signedNamedMultiSessionCookie(
					context.secret,
					`clearance.session_token_multi-${encodeURIComponent(active.data!.session.id)}`,
					successorToken!,
				),
				await signedNamedMultiSessionCookie(
					context.secret,
					`clearance.session_token_multi-${encodeURIComponent(token)}`,
					token,
				),
			].join("; "),
		);
		const postcommit = new AfterTransactionHookError([
			new Error("exact predecessor postcommit signal"),
		]);
		const successor = await context.internalAdapter.findSession(successorToken!);
		expect(successor).not.toBeNull();
		const originalFindSession = context.internalAdapter.findSession.bind(
			context.internalAdapter,
		);
		const resolution = vi
			.spyOn(context.internalAdapter, "findSession")
			.mockImplementation(async (candidateToken) =>
				candidateToken === token ? successor : originalFindSession(candidateToken),
			);
		const deletion = vi
			.spyOn(context.internalAdapter, "deleteSessionById")
			.mockImplementationOnce(async () => {
				throw postcommit;
			});
		let setCookie = "";
		try {
			const revoked = await runtime.client.multiSession.revoke(
				{ sessionToken: token },
				{
					headers,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			);
			expect(revoked.error).not.toBeNull();
			expect(revoked.error?.status).toBe(500);
			expect(deletion).toHaveBeenCalledWith(active.data!.session.id);
		} finally {
			deletion.mockRestore();
			resolution.mockRestore();
		}
		expect(setCookie).not.toContain("clearance.session_token=");
		expect(setCookie).not.toContain("max-age=0");
	});

	it("rejects token-only overflow recovery while its predecessor family remains live", async () => {
		const runtime = await createManagedMultiSessionRuntime(100);
		const headers = new Headers();
		const source = await runtime.client.signUp.email(
			{
				email: "managed-multi-token-only-source@example.test",
				password: "password",
				name: "Token Only Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const overflow = await context.internalAdapter.createSession(
			source.data!.user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: source.data!.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		await context.internalAdapter.rotateSessionCredential(overflow.token);
		headers.set(
			"cookie",
			[
				headers.get("cookie"),
				...await Promise.all(
					Array.from({ length: 99 }, (_, index) =>
						signedNamedMultiSessionCookie(
							context.secret,
							`clearance.session_token_multi-unissued-${index.toString().padStart(3, "0")}`,
							`unissued-token-${index}`,
						),
					),
				),
				await signedNamedMultiSessionCookie(
					context.secret,
					"clearance.session_token_multi-zzzz-overflow",
					overflow.token,
				),
			].join("; "),
		);
		const deletion = vi
			.spyOn(context.internalAdapter, "deleteSessions")
			.mockImplementationOnce(async () => {
				throw new AfterTransactionHookError([
					new Error("token-only predecessor postcommit signal"),
				]);
			});
		try {
			const admitted = await runtime.client.signUp.email(
				{
					email: "managed-multi-token-only-successor@example.test",
					password: "password",
					name: "Token Only Successor",
				},
				{ headers },
			);
			expect(admitted.error).not.toBeNull();
		} finally {
			deletion.mockRestore();
		}
	});

	it("reserves middleware authority when active tracking is absent from 100 plugin groups", async () => {
		const runtime = await createManagedMultiSessionRuntime();
		const headers = new Headers();
		const source = await runtime.client.signUp.email(
			{
				email: "managed-multi-untracked-active-source@example.test",
				password: "password",
				name: "Untracked Active Source",
			},
			{ onSuccess: runtime.cookieSetter(headers) },
		);
		const context = await runtime.auth.$context;
		const target = await context.internalAdapter.createSession(
			source.data!.user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: source.data!.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		const primaryCookie = (headers.get("cookie") || "")
			.split(";")
			.map((entry) => entry.trim())
			.find((entry) => entry.startsWith("clearance.session_token="));
		headers.set(
			"cookie",
			[
				primaryCookie,
				await signedMultiSessionCookie(context.secret, target),
				...await Promise.all(
					Array.from({ length: 99 }, (_, index) =>
						signedNamedMultiSessionCookie(
							context.secret,
							`clearance.session_token_multi-000-unissued-${index.toString().padStart(3, "0")}`,
							`unissued-token-${index}`,
						),
					),
				),
			]
				.filter(Boolean)
				.join("; "),
		);
		const originalFindSession = context.internalAdapter.findSession.bind(
			context.internalAdapter,
		);
		let calls = 0;
		const lookup = vi
			.spyOn(context.internalAdapter, "findSession")
			.mockImplementation(async (token) => {
				calls += 1;
				return originalFindSession(token);
			});
		try {
			const revoked = await runtime.client.multiSession.revoke(
				{ sessionId: target.id },
				{ headers },
			);
			expect(revoked.error).toBeNull();
		} finally {
			lookup.mockRestore();
		}
		expect(calls).toBeLessThanOrEqual(100);
		expect(await context.internalAdapter.findSession(target.token)).toBeNull();
	});
});
