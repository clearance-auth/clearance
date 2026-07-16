import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { passkey } from ".";
import { createVirtualAuthenticator } from "./virtual-authenticator.test-utils";

const ORIGIN = "http://localhost:3310";
const RP_ID = "localhost";

describe("passkey ceremony core", () => {
	it("completes a real registration and signed discoverable authentication ceremony", async () => {
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				plugins: [passkey()],
			},
			{ port: 3310 },
		);
		const { headers } = await instance.signInWithTestUser();
		headers.set("origin", ORIGIN);
		const authenticator = createVirtualAuthenticator(ORIGIN, RP_ID);

		const registrationOptions =
			await instance.auth.api.generatePasskeyRegistrationOptions({ headers });
		const registered = await instance.auth.api.verifyPasskeyRegistration({
			headers,
			body: {
				name: "Platform passkey",
				response: authenticator.registrationResponse(registrationOptions.challenge),
			},
		});

		expect(registered.name).toBe("Platform passkey");
		expect(registered).not.toHaveProperty("credentialID");
		expect(registered).not.toHaveProperty("publicKey");
		expect(registered).not.toHaveProperty("userHandle");
		expect(registered).not.toHaveProperty("counter");

		const authenticationOptions =
			await instance.auth.api.generatePasskeyAuthenticationOptions({ headers });
		const authenticated = await instance.auth.api.verifyPasskeyAuthentication({
			headers,
			body: {
				response: authenticator.authenticationResponse(
					authenticationOptions.challenge,
					registrationOptions.user.id,
					1,
				),
			},
		});

		expect(authenticated.user.email).toBe("test@test.com");
		expect(authenticated.session).toBeTruthy();
		const stored = await (await instance.auth.$context).adapter.findOne<{
			counter: number;
		}>({
			model: "passkey",
			where: [{ field: "id", value: registered.id }],
		});
		expect(stored?.counter).toBe(1);

		const replayOptions =
			await instance.auth.api.generatePasskeyAuthenticationOptions({ headers });
		await expect(
			instance.auth.api.verifyPasskeyAuthentication({
				headers,
				body: {
					response: authenticator.authenticationResponse(
						replayOptions.challenge,
						registrationOptions.user.id,
						1,
					),
				},
			}),
		).rejects.toMatchObject({
			status: "UNAUTHORIZED",
			body: { code: "AUTHENTICATION_FAILED" },
		});
		const afterReplay = await (await instance.auth.$context).adapter.findOne<{
			counter: number;
		}>({
			model: "passkey",
			where: [{ field: "id", value: registered.id }],
		});
		expect(afterReplay?.counter).toBe(1);
	});

	it("rejects registration and authentication responses without user verification", async () => {
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				plugins: [passkey()],
			},
			{ port: 3310 },
		);
		const { headers } = await instance.signInWithTestUser();
		headers.set("origin", ORIGIN);

		const registrationAuthenticator = createVirtualAuthenticator(ORIGIN, RP_ID);
		const registrationOptions =
			await instance.auth.api.generatePasskeyRegistrationOptions({ headers });
		await expect(
			instance.auth.api.verifyPasskeyRegistration({
				headers,
				body: {
					response: registrationAuthenticator.registrationResponse(
						registrationOptions.challenge,
						{ userVerified: false },
					),
				},
			}),
		).rejects.toMatchObject({
			status: "BAD_REQUEST",
			body: { code: "REGISTRATION_FAILED" },
		});

		const authenticator = createVirtualAuthenticator(ORIGIN, RP_ID);
		const validOptions =
			await instance.auth.api.generatePasskeyRegistrationOptions({ headers });
		await instance.auth.api.verifyPasskeyRegistration({
			headers,
			body: {
				response: authenticator.registrationResponse(validOptions.challenge),
			},
		});
		const authenticationOptions =
			await instance.auth.api.generatePasskeyAuthenticationOptions({ headers });
		await expect(
			instance.auth.api.verifyPasskeyAuthentication({
				headers,
				body: {
					response: authenticator.authenticationResponse(
						authenticationOptions.challenge,
						validOptions.user.id,
						1,
						{ userVerified: false },
					),
				},
			}),
		).rejects.toMatchObject({
			status: "UNAUTHORIZED",
			body: { code: "AUTHENTICATION_FAILED" },
		});
	});
});
