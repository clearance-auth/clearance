import { beforeEach, describe, expect, it, vi } from "vitest";

const { startAuthenticationMock } = vi.hoisted(() => ({
	startAuthenticationMock: vi.fn(),
}));

vi.mock("@simplewebauthn/browser", () => ({
	startAuthentication: startAuthenticationMock,
	startRegistration: vi.fn(),
}));

import { passkeyClient } from "./client";

const assertion = {
	id: "other-credential",
	rawId: "other-credential",
	type: "public-key" as const,
	authenticatorAttachment: "platform" as const,
	clientExtensionResults: {},
	response: {
		clientDataJSON: "client-data",
		authenticatorData: "authenticator-data",
		signature: "signature",
		userHandle: "user-handle",
	},
};

function createActions(fetch: ReturnType<typeof vi.fn>) {
	const notifications: string[] = [];
	const plugin = passkeyClient();
	const actions = plugin.getActions(
		fetch as never,
		{ notify: (signal: string) => notifications.push(signal) } as never,
		undefined,
	);
	const atoms = plugin.getAtoms(fetch as never);
	return { actions, atoms, notifications, plugin };
}

describe("passkey client deletion", () => {
	beforeEach(() => {
		startAuthenticationMock.mockReset();
	});

	it.each([
		{ type: "password", password: "correct horse" } as const,
		{ type: "totp", code: "123456" } as const,
		{ type: "recovery-code", code: "recovery-code" } as const,
	])("posts a $type proof directly and refreshes both signals", async (proof) => {
		const fetch = vi.fn().mockResolvedValue({
			data: { status: true },
			error: null,
		});
		const { actions, atoms, notifications } = createActions(fetch);

		const result = await actions.passkey.deletePasskey({
			id: "target-passkey",
			proof,
			fetchOptions: { headers: { "x-test": "direct-proof" } },
		});

		expect(result).toEqual({ data: { status: true }, error: null });
		expect(fetch).toHaveBeenCalledOnce();
		expect(fetch).toHaveBeenCalledWith("/passkey/delete", {
			headers: { "x-test": "direct-proof" },
			method: "POST",
			body: { id: "target-passkey", proof },
			throw: false,
		});
		expect(atoms.$listPasskeys.get()).toBeGreaterThan(0);
		expect(notifications).toEqual(["$sessionSignal"]);
	});

	it("gets target-bound options, performs WebAuthn, and posts the assertion", async () => {
		const deletionOptions = {
			challenge: "deletion-challenge",
			rpId: "example.test",
			timeout: 120_000,
			allowCredentials: [{ id: "other-credential", type: "public-key" }],
			userVerification: "required",
		};
		const fetch = vi
			.fn()
			.mockResolvedValueOnce({ data: deletionOptions, error: null })
			.mockResolvedValueOnce({ data: { status: true }, error: null });
		startAuthenticationMock.mockResolvedValue(assertion);
		const { actions, atoms, notifications } = createActions(fetch);

		const result = await actions.passkey.deletePasskey({
			id: "target-passkey",
			proof: { type: "passkey" },
			fetchOptions: { headers: { "x-test": "passkey-proof" } },
		});

		expect(result).toEqual({ data: { status: true }, error: null });
		expect(fetch.mock.calls).toEqual([
			[
				"/passkey/generate-deletion-options",
				{
					headers: { "x-test": "passkey-proof" },
					method: "POST",
					body: { id: "target-passkey" },
					throw: false,
				},
			],
			[
				"/passkey/delete",
				{
					headers: { "x-test": "passkey-proof" },
					method: "POST",
					body: {
						id: "target-passkey",
						proof: { type: "passkey", response: assertion },
					},
					throw: false,
				},
			],
		]);
		expect(startAuthenticationMock).toHaveBeenCalledWith({
			optionsJSON: deletionOptions,
		});
		expect(atoms.$listPasskeys.get()).toBeGreaterThan(0);
		expect(notifications).toEqual(["$sessionSignal"]);
	});

	it("maps browser failures to the generic deletion-proof error", async () => {
		const fetch = vi.fn().mockResolvedValue({
			data: {
				challenge: "deletion-challenge",
				rpId: "example.test",
				timeout: 120_000,
				allowCredentials: [{ id: "other-credential", type: "public-key" }],
				userVerification: "required",
			},
			error: null,
		});
		startAuthenticationMock.mockRejectedValue(
			new Error("platform-specific cancellation detail"),
		);
		const { actions, atoms, notifications } = createActions(fetch);

		const result = await actions.passkey.deletePasskey({
			id: "target-passkey",
			proof: { type: "passkey" },
		});

		expect(result).toEqual({
			data: null,
			error: {
				code: "DELETION_PROOF_FAILED",
				message: "Passkey deletion proof failed",
				status: 401,
				statusText: "UNAUTHORIZED",
			},
		});
		expect(JSON.stringify(result)).not.toContain("platform-specific");
		expect(fetch).toHaveBeenCalledOnce();
		expect(atoms.$listPasskeys.get()).toBe(0);
		expect(notifications).toEqual([]);
	});

	it("declares both deletion paths and invalidates both atoms after deletion", () => {
		const plugin = passkeyClient();

		expect(plugin.pathMethods).toMatchObject({
			"/passkey/generate-deletion-options": "POST",
			"/passkey/delete": "POST",
		});
		expect(
			plugin.atomListeners.some(
				({ matcher, signal }) =>
					signal === "$listPasskeys" && matcher("/passkey/delete"),
			),
		).toBe(true);
		expect(
			plugin.atomListeners.some(
				({ matcher, signal }) =>
					signal === "$sessionSignal" && matcher("/passkey/delete"),
			),
		).toBe(true);
	});
});
