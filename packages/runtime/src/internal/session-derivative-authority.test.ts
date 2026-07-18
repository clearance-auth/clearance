import type { InternalAdapter } from "@clearance/core";
import { createHMAC } from "@clearance/utils/hmac";
import { describe, expect, it } from "vitest";
import {
	attachInternalSessionDerivativeAuthority,
	captureInternalSessionDerivativeAuthority,
	ManagedSessionDerivativeAuthorityError,
	validateInternalSessionDerivativeAuthority,
	type InternalSessionDerivativeAuthority,
} from "./session-derivative-authority";

const authority = (overrides: Partial<InternalSessionDerivativeAuthority> = {}) =>
	Object.freeze({
		sourceSessionId: "session_1",
		sourceSubjectId: "user_1",
		sourceOrganizationId: "organization_1",
		sourceExpiresAt: 1_893_456_000_000,
		policyProjectId: "project_1",
		policyEnvironmentId: "environment_1",
		policyRevision: "7",
		...overrides,
	});

function attached(input: {
	live?: InternalSessionDerivativeAuthority;
	capture?: InternalSessionDerivativeAuthority;
	secrets?: {
		currentVersion: number;
		keys: ReadonlyMap<number, string>;
		legacySecret?: string;
	};
	onValidate?: () => void;
} = {}) {
	const adapter = {} as InternalAdapter;
	const secrets = input.secrets ?? {
		currentVersion: 1,
		keys: new Map([[1, "derivative-authority-test-secret"]]),
	};
	const hmac = createHMAC("SHA-256", "base64urlnopad");
	const signatureInput = (payload: string) =>
		`clearance:session-derivative-authority:v1:${payload}`;
	const secretForVersion = (version: number) =>
		version === -1 ? secrets.legacySecret ?? secrets.keys.get(-1) : secrets.keys.get(version);
	attachInternalSessionDerivativeAuthority(adapter, {
		capture: async () => input.capture ?? authority(),
		validate: async () => {
			input.onValidate?.();
			return input.live ?? authority();
		},
		signatureVersion: () => secrets.currentVersion,
		sign: async (payload) =>
			hmac.sign(secretForVersion(secrets.currentVersion)!, signatureInput(payload)),
		verify: async (payload, version, signature) => {
			const secret = secretForVersion(version);
			return secret
				? hmac.verify(secret, signatureInput(payload), signature)
				: false;
		},
	});
	return adapter;
}

describe("session derivative authority", () => {
	it("keeps unmanaged adapters on the legacy undefined path", async () => {
		const adapter = {} as InternalAdapter;
		await expect(
			captureInternalSessionDerivativeAuthority(adapter, {
				purpose: "jwt",
				sourceSessionId: "session_1",
			}),
		).resolves.toBeUndefined();
		await expect(
			validateInternalSessionDerivativeAuthority(adapter, "malformed", {
				purpose: "jwt",
			}),
		).resolves.toBeUndefined();
	});

	it("canonicalizes equivalent token and stable-ID captures without secrets", async () => {
		const adapter = attached();
		const [fromToken, fromId] = await Promise.all([
			captureInternalSessionDerivativeAuthority(adapter, {
				purpose: "device",
				sourceSessionToken: "clr_rt_secret_material",
			}),
			captureInternalSessionDerivativeAuthority(adapter, {
				purpose: "device",
				sourceSessionId: "session_1",
			}),
		]);
		expect(fromToken).toBe(fromId);
		expect(fromToken).not.toContain("clr_rt_secret_material");
		expect(fromToken).not.toContain("credential");
	});

	it("rejects malformed and noncanonical inputs", async () => {
		const adapter = attached();
		const binding = await captureInternalSessionDerivativeAuthority(adapter, {
			purpose: "jwt",
			sourceSessionId: "session_1",
		});
		for (const value of [
			undefined,
			"",
			"not-json",
			`${binding} `,
			JSON.stringify({ ...JSON.parse(binding!), extra: true }),
			JSON.stringify({ ...JSON.parse(binding!), sourceExpiresAt: 1.1 }),
		]) {
			await expect(
				validateInternalSessionDerivativeAuthority(adapter, value, {
					purpose: "jwt",
				}),
			).rejects.toBeInstanceOf(ManagedSessionDerivativeAuthorityError);
		}
	});

	it("rejects every signed-field, purpose, and signature mutation before live lookup", async () => {
		let reads = 0;
		const adapter = attached({
			live: authority(),
			onValidate: () => {
				reads += 1;
			},
		});
		const binding = await captureInternalSessionDerivativeAuthority(adapter, {
			purpose: "jwt",
			sourceSessionId: "session_1",
		});
		for (const mutation of [
			{ sourceSessionId: "session_2" },
			{ purpose: "oidc" },
			{ signature: "B".repeat(43) },
		]) {
			await expect(
				validateInternalSessionDerivativeAuthority(
					adapter,
					JSON.stringify({ ...JSON.parse(binding!), ...mutation }),
					{ purpose: "jwt" },
				),
			).rejects.toMatchObject({ reason: "authority_invalid" });
		}
		expect(reads).toBe(0);
	});

	it("uses the current stable secret and accepts configured historical keys", async () => {
		const oldSecrets = {
			currentVersion: 1,
			keys: new Map([[1, "derivative-authority-old-secret"]]),
		};
		const oldAdapter = attached({ secrets: oldSecrets });
		const oldBinding = await captureInternalSessionDerivativeAuthority(oldAdapter, {
			purpose: "oidc",
			sourceSessionId: "session_1",
		});
		const rotatedSecrets = {
			currentVersion: 2,
			keys: new Map([
				[2, "derivative-authority-new-secret"],
				[1, "derivative-authority-old-secret"],
			]),
		};
		const rotatedAdapter = attached({ secrets: rotatedSecrets });
		await expect(
			validateInternalSessionDerivativeAuthority(rotatedAdapter, oldBinding, {
				purpose: "oidc",
			}),
		).resolves.toEqual(authority());
		const currentBinding = await captureInternalSessionDerivativeAuthority(
			rotatedAdapter,
			{ purpose: "oidc", sourceSessionId: "session_1" },
		);
		expect(JSON.parse(currentBinding!).signatureVersion).toBe(2);
		await expect(
			validateInternalSessionDerivativeAuthority(oldAdapter, currentBinding, {
				purpose: "oidc",
			}),
		).rejects.toMatchObject({ reason: "authority_invalid" });
	});

	it("accepts a bare-secret binding through the migrated legacy secret", async () => {
		const bareAdapter = attached({
			secrets: {
				currentVersion: -1,
				keys: new Map(),
				legacySecret: "derivative-authority-bare-secret",
			},
		});
		const binding = await captureInternalSessionDerivativeAuthority(bareAdapter, {
			purpose: "mcp",
			sourceSessionId: "session_1",
		});
		expect(JSON.parse(binding!).signatureVersion).toBe(-1);
		const migratedAdapter = attached({
			secrets: {
				currentVersion: 2,
				keys: new Map([[2, "derivative-authority-new-secret"]]),
				legacySecret: "derivative-authority-bare-secret",
			},
		});
		await expect(
			validateInternalSessionDerivativeAuthority(migratedAdapter, binding, {
				purpose: "mcp",
			}),
		).resolves.toEqual(authority());
	});

	it("fails closed for expected mismatches and live authority drift", async () => {
		const bindingAdapter = attached();
		const binding = await captureInternalSessionDerivativeAuthority(
			bindingAdapter,
			{ purpose: "oidc", sourceSessionId: "session_1" },
		);
		for (const expected of [
			{ purpose: "jwt" },
			{ purpose: "oidc", subjectId: "user_2" },
			{ purpose: "oidc", organizationId: null },
		]) {
			await expect(
				validateInternalSessionDerivativeAuthority(bindingAdapter, binding, expected),
			).rejects.toMatchObject({ reason: "authority_mismatched" });
		}
		for (const live of [
			authority({ sourceExpiresAt: 1_893_456_000_001 }),
			authority({ policyRevision: "8" }),
			authority({ sourceOrganizationId: null }),
			authority({ sourceSubjectId: "user_2" }),
		]) {
			await expect(
				validateInternalSessionDerivativeAuthority(attached({ live }), binding, {
					purpose: "oidc",
				}),
			).rejects.toMatchObject({ reason: "authority_stale" });
		}
	});

	it("returns a fresh frozen scalar-expiry result", async () => {
		const adapter = attached();
		const binding = await captureInternalSessionDerivativeAuthority(adapter, {
			purpose: "mcp",
			sourceSessionId: "session_1",
		});
		const result = await validateInternalSessionDerivativeAuthority(
			adapter,
			binding,
			{ purpose: "mcp" },
		);
		expect(result).toEqual(authority());
		expect(Object.isFrozen(result)).toBe(true);
		expect(typeof result?.sourceExpiresAt).toBe("number");
	});
});
