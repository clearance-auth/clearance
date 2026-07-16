import { describe, expect, expectTypeOf, it } from "vitest";
import { createAuthClient, passkeyClient } from "./client.js";
import { createClearanceAuth } from "./create-auth.js";
import type {
	ClearancePasskeyAuthenticationResponse,
	ClearancePasskeyDeletionProof,
} from "./public-types/index.js";

const databaseUrl =
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const secret = "unit-test-secret-value-not-default!!";

function productPlugins(bundle: { auth: unknown }) {
	return (bundle.auth as unknown as {
		options: {
			plugins: Array<{ id: string; options?: unknown }>;
		};
	}).options.plugins;
}

describe("@clearance/auth passkey product integration", () => {
	it("enables passkeys by default, supports explicit disable, and forwards options", async () => {
		const defaults = createClearanceAuth({
			baseURL: "https://auth.example.test",
			secret,
			databaseUrl,
		});
		const disabled = createClearanceAuth({
			baseURL: "https://auth.example.test",
			secret,
			databaseUrl,
			passkeys: false,
		});
		const configuredPasskeys = {
			rpID: "example.test",
			rpName: "Example",
			origin: ["https://auth.example.test", "https://app.example.test"],
			authenticatorSelection: {
				authenticatorAttachment: "platform" as const,
			},
			rateLimit: { window: 120, max: 6 },
		};
		const configured = createClearanceAuth({
			baseURL: "https://auth.example.test",
			secret,
			databaseUrl,
			passkeys: configuredPasskeys,
		});

		try {
			expect(productPlugins(defaults).some(({ id }) => id === "passkey")).toBe(
				true,
			);
			expect(defaults.plugins.passkeys).toBe(true);
			expect(productPlugins(disabled).some(({ id }) => id === "passkey")).toBe(
				false,
			);
			expect(disabled.plugins.passkeys).toBe(false);
			expect(
				productPlugins(configured).find(({ id }) => id === "passkey")?.options,
			).toEqual(configuredPasskeys);
			expect(configured.plugins.passkeys).toBe(true);
		} finally {
			await Promise.all([
				defaults.destroy(),
				disabled.destroy(),
				configured.destroy(),
			]);
		}
	});

	it("exports the conditional passkey client surface", () => {
		const plugin = passkeyClient();
		const client = createAuthClient({ plugins: [plugin] });

		expect(plugin.id).toBe("passkey");
		expect(typeof client.signIn.passkey).toBe("function");
		expect(typeof client.passkey.addPasskey).toBe("function");
		expect(typeof client.passkey.deletePasskey).toBe("function");
		expect(typeof client.passkey.renamePasskey).toBe("function");
		expect(typeof client.useListPasskeys.get).toBe("function");
		expect(typeof client.useListPasskeys.subscribe).toBe("function");
		expectTypeOf(client.signIn.passkey).toBeFunction();
		expectTypeOf(client.passkey.addPasskey).toBeFunction();
		expectTypeOf(client.passkey.deletePasskey).toBeFunction();
		expectTypeOf(client.passkey.renamePasskey).toBeFunction();
		expectTypeOf(client.useListPasskeys.get).toBeFunction();
	});

	it("uses POST generation requests, a registration body, and exact path metadata", async () => {
		const requests: Array<{
			path: string;
			options: { method?: string; body?: unknown };
		}> = [];
		const fetch = async (
			path: string,
			options: { method?: string; body?: unknown },
		) => {
			requests.push({ path, options });
			return {
				data: null,
				error: {
					code: "EXPECTED_TEST_STOP",
					message: "Stop before invoking the browser authenticator",
					status: 400,
					statusText: "BAD_REQUEST",
				},
			};
		};
		const plugin = passkeyClient();
		const actions = plugin.getActions(
			fetch as never,
			{ notify: () => undefined } as never,
			undefined,
		);

		await actions.passkey.addPasskey({ authenticatorAttachment: "platform" });
		await actions.signIn.passkey();

		expect(requests).toEqual([
			{
				path: "/passkey/generate-registration-options",
				options: {
					method: "POST",
					body: { authenticatorAttachment: "platform" },
					throw: false,
				},
			},
			{
				path: "/passkey/generate-authentication-options",
				options: { method: "POST", throw: false },
			},
		]);
		expect(plugin.pathMethods).toMatchObject({
			"/passkey/generate-registration-options": "POST",
			"/passkey/generate-authentication-options": "POST",
			"/passkey/generate-deletion-options": "POST",
			"/passkey/delete": "POST",
			"/passkey/list": "GET",
			"/passkey/update": "POST",
		});
	});
});

/** Checked by the focused TypeScript verification command; never executed. */
async function assertConditionalPasskeyProductTypes() {
	const defaults = createClearanceAuth({
		baseURL: "https://auth.example.test",
		secret,
		databaseUrl,
	});
	void defaults.auth.api.generatePasskeyRegistrationOptions;
	void defaults.auth.api.verifyPasskeyRegistration;
	void defaults.auth.api.generatePasskeyAuthenticationOptions;
	void defaults.auth.api.verifyPasskeyAuthentication;
	void defaults.auth.api.generatePasskeyDeletionOptions;
	void defaults.auth.api.deletePasskey;
	void defaults.auth.api.listPasskeys;
	void defaults.auth.api.updatePasskey;
	const registrationOptions =
		await defaults.auth.api.generatePasskeyRegistrationOptions({
			headers: new Headers(),
			body: { authenticatorAttachment: "platform" },
		});
	const registrationRpID: string = registrationOptions.rp.id;
	const registrationResidentKey: "required" =
		registrationOptions.authenticatorSelection.residentKey;
	const registrationRequiresResidentKey: true =
		registrationOptions.authenticatorSelection.requireResidentKey;
	const registrationUserVerification: "required" =
		registrationOptions.authenticatorSelection.userVerification;
	const registrationAttestation: "none" = registrationOptions.attestation;
	const registrationTimeout: number = registrationOptions.timeout;
	void registrationRpID;
	void registrationResidentKey;
	void registrationRequiresResidentKey;
	void registrationUserVerification;
	void registrationAttestation;
	void registrationTimeout;

	const authenticationOptions =
		await defaults.auth.api.generatePasskeyAuthenticationOptions({
			headers: new Headers(),
		});
	const authenticationRpID: string = authenticationOptions.rpId;
	const authenticationUserVerification: "required" =
		authenticationOptions.userVerification;
	const authenticationTimeout: number = authenticationOptions.timeout;
	const noAllowCredentials: undefined = authenticationOptions.allowCredentials;
	void authenticationRpID;
	void authenticationUserVerification;
	void authenticationTimeout;
	void noAllowCredentials;

	const deletionOptions = await defaults.auth.api.generatePasskeyDeletionOptions({
		headers: new Headers(),
		body: { id: "target-passkey" },
	});
	const deletionRpID: string = deletionOptions.rpId;
	const deletionUserVerification: "required" =
		deletionOptions.userVerification;
	const deletionCredentialId: string = deletionOptions.allowCredentials[0].id;
	const deletionCredentialType: "public-key" =
		deletionOptions.allowCredentials[0].type;
	void deletionRpID;
	void deletionUserVerification;
	void deletionCredentialId;
	void deletionCredentialType;

	const passkeyResponse: ClearancePasskeyAuthenticationResponse = {
		id: "other-passkey",
		rawId: "other-passkey",
		type: "public-key",
		clientExtensionResults: {},
		response: {
			clientDataJSON: "client-data",
			authenticatorData: "authenticator-data",
			signature: "signature",
			userHandle: "user-handle",
		},
	};
	const serverDeletionProofs: ClearancePasskeyDeletionProof[] = [
		{ type: "password", password: "password" },
		{ type: "totp", code: "123456" },
		{ type: "recovery-code", code: "recovery-code" },
		{ type: "passkey", response: passkeyResponse },
	];
	for (const proof of serverDeletionProofs) {
		const deleted = await defaults.auth.api.deletePasskey({
			headers: new Headers(),
			body: { id: "target-passkey", proof },
		});
		const deletedStatus: true = deleted.status;
		void deletedStatus;
	}

	const disabled = createClearanceAuth({
		baseURL: "https://auth.example.test",
		secret,
		databaseUrl,
		passkeys: false,
	});
	// @ts-expect-error explicit disable removes passkey endpoints
	void disabled.auth.api.generatePasskeyRegistrationOptions;
	// @ts-expect-error explicit disable removes passkey deletion endpoints
	void disabled.auth.api.deletePasskey;

	const client = createAuthClient({ plugins: [passkeyClient()] });
	void client.signIn.passkey;
	void client.passkey.addPasskey;
	void client.passkey.deletePasskey;
	void client.passkey.renamePasskey;
	await client.passkey.deletePasskey({
		id: "target-passkey",
		proof: { type: "password", password: "password" },
	});
	await client.passkey.deletePasskey({
		id: "target-passkey",
		proof: { type: "totp", code: "123456" },
	});
	await client.passkey.deletePasskey({
		id: "target-passkey",
		proof: { type: "recovery-code", code: "recovery-code" },
	});
	await client.passkey.deletePasskey({
		id: "target-passkey",
		proof: { type: "passkey" },
	});
	await client.passkey.deletePasskey({
		id: "target-passkey",
		// @ts-expect-error browser-facing passkey proof does not accept an assertion
		proof: { type: "passkey", response: passkeyResponse },
	});
	const signIn = await client.signIn.passkey();
	if (signIn.data) {
		const email: string = signIn.data.user.email;
		const sessionId: string = signIn.data.session.id;
		const expiresAt: Date = signIn.data.session.expiresAt;
		void email;
		void sessionId;
		void expiresAt;
	}
	const listState = client.useListPasskeys.get();
	const firstPasskeyId: string | undefined = listState.data?.[0]?.id;
	const unsubscribe = client.useListPasskeys.subscribe((state) => {
		const pending: boolean = state.isPending;
		void pending;
	});
	unsubscribe();
	await listState.refetch();
	void firstPasskeyId;

	const baseClient = createAuthClient({ plugins: [] });
	// @ts-expect-error a client without passkeyClient has no typed passkey actions
	void baseClient.passkey.addPasskey;
	// @ts-expect-error a client without passkeyClient has no typed deletion action
	void baseClient.passkey.deletePasskey;
	// @ts-expect-error a client without passkeyClient has no typed passkey query
	void baseClient.useListPasskeys.get();
}

void assertConditionalPasskeyProductTypes;
