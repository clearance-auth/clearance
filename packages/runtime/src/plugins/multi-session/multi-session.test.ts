import { describe, expect, it } from "vitest";
import { parseSetCookieHeader } from "../../cookies";
import { getTestInstance } from "../../test-utils/test-instance";
import { jwt } from "../jwt";
import { jwtClient } from "../jwt/client";
import { multiSession } from ".";
import { multiSessionClient } from "./client";

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

		const revoked = await legacy.client.multiSession.revoke(
			{ sessionToken: secondLegacyHandle },
			{ headers: legacyHeaders },
		);
		expect(revoked.error).toBeNull();
		expect(
			(
				await legacy.client.getSession({
					fetchOptions: { headers: legacyHeaders },
				})
			).data?.user.email,
		).toBe(firstUser.email);
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
});
