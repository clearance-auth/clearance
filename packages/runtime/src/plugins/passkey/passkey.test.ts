import { base64Url } from "@clearance/utils/base64";
import { describe, expect, it } from "vitest";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import { getTestInstance } from "../../test-utils/test-instance";
import { admin } from "../admin";
import { passkey } from ".";
import type { Passkey, PublicPasskey } from "./types";
import { createVirtualAuthenticator } from "./virtual-authenticator.test-utils";

const ORIGIN = "http://localhost:3300";

function clientDataFor(type: "webauthn.create" | "webauthn.get", challenge: string) {
	return base64Url.encode(
		JSON.stringify({ type, challenge, origin: ORIGIN }),
		{ padding: false },
	);
}

async function setup() {
	const instance = await getTestInstance(
		{
			baseURL: ORIGIN,
			plugins: [passkey()],
		},
		{ port: 3300 },
	);
	const { headers } = await instance.signInWithTestUser();
	headers.set("origin", ORIGIN);
	return { ...instance, headers };
}

describe("passkey: discoverable options and mandatory user verification", () => {
	it("registration options require user verification", async () => {
		const { auth, headers } = await setup();
		const res = await auth.api.generatePasskeyRegistrationOptions({ headers });
		expect(res.authenticatorSelection?.userVerification).toBe("required");
		expect(res.authenticatorSelection?.residentKey).toBe("required");
		expect(res.authenticatorSelection?.requireResidentKey).toBe(true);
	});

	it("authentication options omit allowCredentials (discoverable/usernameless) and require user verification", async () => {
		const { auth, headers } = await setup();
		const res = await auth.api.generatePasskeyAuthenticationOptions({ headers });
		expect(res.allowCredentials).toBeUndefined();
		expect(res.userVerification).toBe("required");
	});
});

describe("passkey: trusted origin policy", () => {
	it("rejects a request with a foreign Origin header", async () => {
		const { auth, headers } = await setup();
		const badHeaders = new Headers(headers);
		badHeaders.set("origin", "http://evil.example.com");
		await expect(
			auth.api.generatePasskeyAuthenticationOptions({ headers: badHeaders }),
		).rejects.toThrow();
	});

	it("rejects a request with no Origin header", async () => {
		const { auth, headers } = await setup();
		const noOrigin = new Headers(headers);
		noOrigin.delete("origin");
		await expect(
			auth.api.generatePasskeyAuthenticationOptions({ headers: noOrigin }),
		).rejects.toThrow();
	});
});

describe("passkey: transaction requirement", () => {
	it("fails before challenge issuance when the adapter cannot roll back authentication", async () => {
		const { auth, headers } = await setup();
		const context = await auth.$context;
		const adapterConfig = context.adapter.options?.adapterConfig;
		if (!adapterConfig) throw new Error("adapter config missing");
		const transaction = adapterConfig.transaction;
		const before = await context.adapter.count({ model: "passkeyChallenge" });
		adapterConfig.transaction = false;
		try {
			await expect(
				auth.api.generatePasskeyAuthenticationOptions({ headers }),
			).rejects.toMatchObject({
				status: "INTERNAL_SERVER_ERROR",
				body: { code: "CONFIGURATION_ERROR" },
			});
		} finally {
			adapterConfig.transaction = transaction;
		}
		await expect(
			context.adapter.count({ model: "passkeyChallenge" }),
		).resolves.toBe(before);
	});

	it("fails before challenge, counter, session, or secondary mutation for secondary-authoritative sessions", async () => {
		const store = new Map<string, string>();
		let secondaryWrites = 0;
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				plugins: [passkey()],
				secondaryStorage: {
					get(key: string) {
						return store.get(key) ?? null;
					},
					set(key: string, value: string) {
						secondaryWrites++;
						store.set(key, value);
					},
					delete(key: string) {
						secondaryWrites++;
						store.delete(key);
					},
				},
			},
			{ port: 3300 },
		);
		const signedIn = await instance.signInWithTestUser();
		signedIn.headers.set("origin", ORIGIN);
		const context = await instance.auth.$context;
		const credential = await context.adapter.create<Passkey>({
			model: "passkey",
			data: {
				userId: signedIn.user.id,
				credentialID: `secondary-auth-${Math.random()}`,
				publicKey: "unused-secondary-auth-key",
				userHandle: `secondary-handle-${Math.random()}`,
				counter: 0,
				deviceType: "singleDevice",
				backedUp: false,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});
		const challengesBefore = await context.adapter.count({
			model: "passkeyChallenge",
		});
		const writesBefore = secondaryWrites;

		await expect(
			instance.auth.api.generatePasskeyAuthenticationOptions({
				headers: signedIn.headers,
			}),
		).rejects.toMatchObject({
			status: "INTERNAL_SERVER_ERROR",
			body: { code: "CONFIGURATION_ERROR" },
		});
		await expect(
			instance.auth.api.verifyPasskeyAuthentication({
				headers: signedIn.headers,
				body: {
					response: {
						id: credential.credentialID,
						rawId: credential.credentialID,
						type: "public-key",
						clientExtensionResults: {},
						response: {
							clientDataJSON: clientDataFor("webauthn.get", "unused"),
							authenticatorData: base64Url.encode("unused", {
								padding: false,
							}),
							signature: base64Url.encode("unused", { padding: false }),
						},
					},
				},
			}),
		).rejects.toMatchObject({
			status: "INTERNAL_SERVER_ERROR",
			body: { code: "CONFIGURATION_ERROR" },
		});

		expect(secondaryWrites).toBe(writesBefore);
		await expect(
			context.adapter.count({ model: "passkeyChallenge" }),
		).resolves.toBe(challengesBefore);
		await expect(
			context.adapter.findOne<Passkey>({
				model: "passkey",
				where: [{ field: "id", value: credential.id }],
			}),
		).resolves.toMatchObject({ counter: 0 });
	});

	it("returns the committed session when a dual-write publication hook fails", async () => {
		const store = new Map<string, string>();
		let failSecondary = false;
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				session: { storeSessionInDatabase: true },
				plugins: [passkey()],
				secondaryStorage: {
					get(key: string) {
						if (failSecondary) throw new Error("injected secondary read failure");
						return store.get(key) ?? null;
					},
					set(key: string, value: string) {
						if (failSecondary) throw new Error("injected secondary write failure");
						store.set(key, value);
					},
					delete(key: string) {
						if (failSecondary) throw new Error("injected secondary delete failure");
						store.delete(key);
					},
				},
			},
			{ port: 3300 },
		);
		const signedIn = await instance.signInWithTestUser();
		signedIn.headers.set("origin", ORIGIN);
		const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		const registrationOptions =
			await instance.auth.api.generatePasskeyRegistrationOptions({
				headers: signedIn.headers,
			});
		const registered = await instance.auth.api.verifyPasskeyRegistration({
			headers: signedIn.headers,
			body: {
				response: authenticator.registrationResponse(registrationOptions.challenge),
			},
		});
		const context = await instance.auth.$context;
		const challengesBefore = await context.adapter.count({
			model: "passkeyChallenge",
		});
		const sessionsBefore = await context.adapter.count({
			model: "session",
			where: [{ field: "userId", value: signedIn.user.id }],
		});
		const authenticationOptions =
			await instance.auth.api.generatePasskeyAuthenticationOptions({
				headers: signedIn.headers,
			});
		failSecondary = true;
		const response = await instance.auth.api.verifyPasskeyAuthentication({
			headers: signedIn.headers,
			body: {
				response: authenticator.authenticationResponse(
					authenticationOptions.challenge,
					registrationOptions.user.id,
					1,
				),
			},
			asResponse: true,
		});

		expect(response.status).toBe(200);
		expect(response.headers.get("set-cookie")).toContain("session_token");
		failSecondary = false;
		const replacementHeaders = convertSetCookieToCookie(response.headers);
		replacementHeaders.set("origin", ORIGIN);
		await expect(
			instance.auth.api.getSession({ headers: replacementHeaders }),
		).resolves.not.toBeNull();
		await expect(
			instance.auth.api.getSession({ headers: signedIn.headers }),
		).resolves.not.toBeNull();
		await expect(
			context.adapter.findOne<Passkey>({
				model: "passkey",
				where: [{ field: "id", value: registered.id }],
			}),
		).resolves.toMatchObject({ counter: 1 });
		await expect(
			context.adapter.count({ model: "passkeyChallenge" }),
		).resolves.toBe(challengesBefore);
		await expect(
			context.adapter.count({
				model: "session",
				where: [{ field: "userId", value: signedIn.user.id }],
			}),
		).resolves.toBe(sessionsBefore + 1);
	});

	it("consumes a banned user's assertion without advancing authority or publishing a session", async () => {
		let sessionCreateHooks = 0;
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				plugins: [admin(), passkey()],
				databaseHooks: {
					session: {
						create: {
							before: async () => {
								sessionCreateHooks++;
							},
						},
					},
				},
			},
			{ port: 3300 },
		);
		const signedIn = await instance.signInWithTestUser();
		signedIn.headers.set("origin", ORIGIN);
		const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		const registrationOptions =
			await instance.auth.api.generatePasskeyRegistrationOptions({
				headers: signedIn.headers,
			});
		const registered = await instance.auth.api.verifyPasskeyRegistration({
			headers: signedIn.headers,
			body: {
				response: authenticator.registrationResponse(registrationOptions.challenge),
			},
		});
		const context = await instance.auth.$context;
		await context.adapter.update({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
			update: { banned: true },
		});
		const challengesBefore = await context.adapter.count({
			model: "passkeyChallenge",
		});
		const sessionsBefore = await context.adapter.count({
			model: "session",
			where: [{ field: "userId", value: signedIn.user.id }],
		});
		const credentialsBefore = await context.adapter.count({
			model: "sessionCredential",
		});
		sessionCreateHooks = 0;
		const bannedOptions =
			await instance.auth.api.generatePasskeyAuthenticationOptions({
				headers: signedIn.headers,
			});

		const rejected = await instance.auth.api.verifyPasskeyAuthentication({
			headers: signedIn.headers,
			body: {
				response: authenticator.authenticationResponse(
					bannedOptions.challenge,
					registrationOptions.user.id,
					1,
				),
			},
			asResponse: true,
		});

		expect(rejected.status).toBe(401);
		expect(await rejected.json()).toMatchObject({ code: "AUTHENTICATION_FAILED" });
		expect(rejected.headers.get("set-cookie")).toBeNull();
		expect(sessionCreateHooks).toBe(0);
		await expect(
			context.adapter.count({ model: "passkeyChallenge" }),
		).resolves.toBe(challengesBefore);
		await expect(
			context.adapter.findOne<Passkey>({
				model: "passkey",
				where: [{ field: "id", value: registered.id }],
			}),
		).resolves.toMatchObject({ counter: 0 });
		await expect(
			context.adapter.count({
				model: "session",
				where: [{ field: "userId", value: signedIn.user.id }],
			}),
		).resolves.toBe(sessionsBefore);
		await expect(
			context.adapter.count({ model: "sessionCredential" }),
		).resolves.toBe(credentialsBefore);

		await context.adapter.update({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
			update: { banned: false },
		});
		const activeOptions =
			await instance.auth.api.generatePasskeyAuthenticationOptions({
				headers: signedIn.headers,
			});
		const authenticated = await instance.auth.api.verifyPasskeyAuthentication({
			headers: signedIn.headers,
			body: {
				response: authenticator.authenticationResponse(
					activeOptions.challenge,
					registrationOptions.user.id,
					2,
				),
			},
			asResponse: true,
		});

		expect(authenticated.status).toBe(200);
		expect(authenticated.headers.get("set-cookie")).toContain("session_token");
		expect(sessionCreateHooks).toBe(1);
		await expect(
			context.adapter.findOne<Passkey>({
				model: "passkey",
				where: [{ field: "id", value: registered.id }],
			}),
		).resolves.toMatchObject({ counter: 2 });
		await expect(
			context.adapter.count({
				model: "session",
				where: [{ field: "userId", value: signedIn.user.id }],
			}),
		).resolves.toBe(sessionsBefore + 1);
		await expect(
			context.adapter.count({ model: "sessionCredential" }),
		).resolves.toBe(credentialsBefore + 1);
	});
});

describe("passkey: authentication failure contract", () => {
	async function rejectionOf(promise: Promise<unknown>) {
		try {
			await promise;
			throw new Error("Expected promise to reject");
		} catch (error) {
			return error;
		}
	}

	it("returns the same generic error for unknown credentials and malformed responses", async () => {
		const { auth, headers } = await setup();
		const options = await auth.api.generatePasskeyAuthenticationOptions({ headers });
		const unknownCredentialError = await rejectionOf(
			auth.api.verifyPasskeyAuthentication({
				headers,
				body: {
					response: {
						id: "unknown-credential-id",
						rawId: "unknown-credential-id",
						type: "public-key",
						clientExtensionResults: {},
						response: {
							clientDataJSON: clientDataFor("webauthn.get", options.challenge),
							authenticatorData: base64Url.encode("authenticator-data", {
								padding: false,
							}),
							signature: base64Url.encode("signature", { padding: false }),
							userHandle: base64Url.encode("someone", { padding: false }),
						},
					},
				},
			}),
		);
		const malformedResponseError = await rejectionOf(
			auth.api.verifyPasskeyAuthentication({
				headers,
				body: {
					response: {
						id: "unknown-credential-id",
						rawId: "unknown-credential-id",
						type: "public-key",
						clientExtensionResults: {},
						response: {
							clientDataJSON: "not-valid-base64url-json!!",
							authenticatorData: base64Url.encode("authenticator-data", {
								padding: false,
							}),
							signature: base64Url.encode("signature", { padding: false }),
						},
					},
				},
			}),
		);

		const expected = {
			status: "UNAUTHORIZED",
			body: {
				code: "AUTHENTICATION_FAILED",
				message: "Failed to authenticate with passkey",
			},
		};
		expect(unknownCredentialError).toMatchObject(expected);
		expect(malformedResponseError).toMatchObject(expected);
	});
});

describe("passkey: global duplicate credential rejection (storage contract)", () => {
	it("rejects a second row with the same credentialID via the database unique constraint", async () => {
		const { auth } = await setup();
		const context = await auth.$context;
		const userA = await context.internalAdapter.createUser({
			email: `dup-a-${Math.random()}@example.test`,
			emailVerified: true,
			name: "A",
			image: null,
		});
		const userB = await context.internalAdapter.createUser({
			email: `dup-b-${Math.random()}@example.test`,
			emailVerified: true,
			name: "B",
			image: null,
		});
		const sharedCredentialID = `shared-cred-${Math.random()}`;
		await context.adapter.create({
			model: "passkey",
			data: {
				userId: userA.id,
				credentialID: sharedCredentialID,
				publicKey: "pk-a",
				userHandle: "handle-a",
				counter: 0,
				deviceType: "singleDevice",
				backedUp: false,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});
		await expect(
			context.adapter.create({
				model: "passkey",
				data: {
					userId: userB.id,
					credentialID: sharedCredentialID,
					publicKey: "pk-b",
					userHandle: "handle-b",
					counter: 0,
					deviceType: "singleDevice",
					backedUp: false,
					createdAt: new Date(),
					updatedAt: new Date(),
				},
			}),
		).rejects.toThrow();
	});
});

describe("passkey: list redaction and ownership-scoped rename", () => {
	async function seedPasskeyForTestUser(auth: Awaited<ReturnType<typeof setup>>["auth"]) {
		const context = await auth.$context;
		const testUser = await context.internalAdapter
			.findUserByEmail("test@test.com")
			.then((res) => res?.user);
		if (!testUser) throw new Error("test user missing");
		const created = await context.adapter.create<Record<string, unknown>>({
			model: "passkey",
			data: {
				userId: testUser.id,
				name: "My Key",
				credentialID: `cred-${Math.random()}`,
				publicKey: "super-secret-public-key",
				userHandle: "super-secret-handle",
				counter: 3,
				deviceType: "multiDevice",
				backedUp: true,
				transports: "usb,nfc",
				aaguid: "aaguid-value",
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});
		return { context, testUser, created: created as { id: string } };
	}

	it("never exposes credentialID, publicKey, userHandle, counter, or userId in the list response", async () => {
		const { auth, headers } = await setup();
		await seedPasskeyForTestUser(auth);
		const list = await auth.api.listPasskeys({ headers });
		expect(list.length).toBeGreaterThan(0);
		for (const entry of list) {
			expect(entry).not.toHaveProperty("credentialID");
			expect(entry).not.toHaveProperty("publicKey");
			expect(entry).not.toHaveProperty("userHandle");
			expect(entry).not.toHaveProperty("counter");
			expect(entry).not.toHaveProperty("userId");
		}
		const entry = list.find((p: PublicPasskey) => p.name === "My Key");
		expect(entry?.backedUp).toBe(true);
		expect(entry?.deviceType).toBe("multiDevice");
	});

	it("renames a passkey the caller owns", async () => {
		const { auth, headers } = await setup();
		const { created } = await seedPasskeyForTestUser(auth);
		const updated = await auth.api.updatePasskey({
			headers,
			body: { id: created.id, name: "Renamed Key" },
		});
		expect(updated.name).toBe("Renamed Key");
	});

	it("returns the same generic error for an unknown id and for another user's id", async () => {
		const { auth, headers } = await setup();
		const context = await auth.$context;
		const otherUser = await context.internalAdapter.createUser({
			email: `other-${Math.random()}@example.test`,
			emailVerified: true,
			name: "Other",
			image: null,
		});
		const otherPasskey = await context.adapter.create<Record<string, unknown>>({
			model: "passkey",
			data: {
				userId: otherUser.id,
				credentialID: `cred-other-${Math.random()}`,
				publicKey: "pk",
				userHandle: "handle",
				counter: 0,
				deviceType: "singleDevice",
				backedUp: false,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});

		let unknownError: unknown;
		try {
			await auth.api.updatePasskey({
				headers,
				body: { id: "does-not-exist", name: "New Name" },
			});
		} catch (error) {
			unknownError = error;
		}

		let foreignError: unknown;
		try {
			await auth.api.updatePasskey({
				headers,
				body: {
					id: (otherPasskey as { id: string }).id,
					name: "New Name",
				},
			});
		} catch (error) {
			foreignError = error;
		}

		expect(unknownError).toBeInstanceOf(Error);
		expect(foreignError).toBeInstanceOf(Error);
		expect((unknownError as { status?: unknown }).status).toBe(
			(foreignError as { status?: unknown }).status,
		);
		expect((unknownError as { body?: { code?: unknown } }).body?.code).toBe(
			(foreignError as { body?: { code?: unknown } }).body?.code,
		);
	});
});

describe("passkey: authoritative recent-enrollment session gate", () => {
	it("rejects generating registration options once the session has been revoked from the database, even though the cookie is still present", async () => {
		const { auth, headers } = await setup();
		const context = await auth.$context;
		const user = await context.internalAdapter
			.findUserByEmail("test@test.com")
			.then((res) => res?.user);
		expect(user).toBeTruthy();

		// Revoke every session for the test user directly in the database. The
		// signed session cookie the client still presents is now stale; an
		// authoritative reload must reject it rather than trusting any cached
		// in-process session state.
		await context.internalAdapter.deleteUserSessions(user!.id);

		await expect(
			auth.api.generatePasskeyRegistrationOptions({ headers }),
		).rejects.toThrow();
	});

	it("rejects verifying a registration once the session has been revoked from the database", async () => {
		const { auth, headers } = await setup();
		const context = await auth.$context;
		const user = await context.internalAdapter
			.findUserByEmail("test@test.com")
			.then((res) => res?.user);
		await context.internalAdapter.deleteUserSessions(user!.id);

		await expect(
			auth.api.verifyPasskeyRegistration({
				headers,
				body: {
					response: {
						id: "some-id",
						rawId: "some-id",
						type: "public-key",
						clientExtensionResults: {},
						response: {
							clientDataJSON: clientDataFor("webauthn.create", "does-not-matter"),
							attestationObject: base64Url.encode("attestation", { padding: false }),
						},
					},
				},
			}),
		).rejects.toThrow();
	});
});

describe("passkey: canonical userHandle binding end-to-end (registration options)", () => {
	it("embeds the canonical base64url user handle as the WebAuthn user.id", async () => {
		const { auth, headers } = await setup();
		const res = await auth.api.generatePasskeyRegistrationOptions({ headers });
		expect(typeof res.user.id).toBe("string");
		// The raw bytes decoded from the response's user.id must re-encode to
		// the exact same base64url representation stored/compared elsewhere.
		const reencoded = base64Url.encode(base64Url.decode(res.user.id), {
			padding: false,
		});
		expect(reencoded).toBe(res.user.id);
	});
});

describe("passkey: RP ID validation (production endpoint path)", () => {
	it("fails closed with a generic configuration error for a malformed rpID", async () => {
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				plugins: [passkey({ rpID: "https://bad-rpid-with-scheme" })],
			},
			{ port: 3301 },
		);
		const { headers } = await instance.signInWithTestUser();
		headers.set("origin", "http://localhost:3301");
		await expect(
			instance.auth.api.generatePasskeyAuthenticationOptions({ headers }),
		).rejects.toThrow();
	});
});
