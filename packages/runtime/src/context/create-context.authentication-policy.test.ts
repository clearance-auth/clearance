import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicyReader,
} from "@clearance/core";
import { ClearanceError } from "@clearance/core/error";
import { describe, expect, it } from "vitest";
import { getAdapter } from "../db/adapter-kysely";
import {
	attachInternalAuthenticationPolicy,
	readInternalAuthenticationPolicy,
} from "../internal/authentication-policy";
import { createAuthContext } from "./create-context";

const identity = { projectId: "project_1", environmentId: "environment_1" };
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
	minimumAssurance: "single_factor" as const,
	allowedFactors: { totp: true, passkey: true },
	trustedDevice: { enabled: false, maxAgeSeconds: 0 },
	assuranceMaxAgeSeconds: 300,
};

function reader(): RuntimeAuthenticationPolicyReader {
	return {
		async readForSubject(input) {
			return {
				scope: identity,
				subjectId: input.subjectId,
				revision: "1",
				environment: policy,
				organizationMembership: input.organizationId
					? {
							subjectId: input.subjectId,
							organizationId: input.organizationId,
						}
					: null,
				organizationOverride: null,
				effective: policy,
			};
		},
	};
}

function options(
	override: Partial<ClearanceOptions> = {},
): ClearanceOptions {
	return {
		baseURL: "http://localhost:3000",
		secret: "managed-policy-context-test-secret-value",
		database: new DatabaseSync(":memory:"),
		...override,
	};
}

describe("managed authentication policy context propagation", () => {
	it("shares one captured binding across normalized options and adapter reuse", async () => {
		const runtimeOptions = options();
		attachInternalAuthenticationPolicy(runtimeOptions, {
			identity,
			reader: reader(),
		});
		const binding = readInternalAuthenticationPolicy(runtimeOptions)!;
		const adapter = await getAdapter(runtimeOptions);

		const first = await createAuthContext(adapter, runtimeOptions, () => "sqlite");
		expect(readInternalAuthenticationPolicy(first.options)).toBe(binding);
		expect(readInternalAuthenticationPolicy(adapter)).toBe(binding);
		expect(readInternalAuthenticationPolicy(adapter.options!)).toBe(binding);

		const second = await createAuthContext(adapter, runtimeOptions, () => "sqlite");
		expect(readInternalAuthenticationPolicy(second.options)).toBe(binding);
	});

	it("rejects a mismatched binding on a reused adapter", async () => {
		const firstOptions = options();
		attachInternalAuthenticationPolicy(firstOptions, {
			identity,
			reader: reader(),
		});
		const adapter = await getAdapter(firstOptions);
		await createAuthContext(adapter, firstOptions, () => "sqlite");

		const mismatched = options();
		attachInternalAuthenticationPolicy(mismatched, {
			identity: { ...identity, environmentId: "environment_2" },
			reader: reader(),
		});
		await expect(
			createAuthContext(adapter, mismatched, () => "sqlite"),
		).rejects.toBeInstanceOf(ClearanceError);
	});

	it("fails configuration without primary DB session transactions", async () => {
		const noDatabase = options({ database: undefined });
		attachInternalAuthenticationPolicy(noDatabase, {
			identity,
			reader: reader(),
		});
		await expect(
			createAuthContext(await getAdapter(noDatabase), noDatabase, () => "memory"),
		).rejects.toThrow("requires a primary database");

		const secondaryOnlySessions = options({
			secondaryStorage: {
				get: async () => null,
				set: async () => {},
				delete: async () => {},
			},
		});
		attachInternalAuthenticationPolicy(secondaryOnlySessions, {
			identity,
			reader: reader(),
		});
		await expect(
			createAuthContext(
				await getAdapter(secondaryOnlySessions),
				secondaryOnlySessions,
				() => "sqlite",
			),
		).rejects.toThrow("stored in the primary database");

		const noTransactions = options();
		attachInternalAuthenticationPolicy(noTransactions, {
			identity,
			reader: reader(),
		});
		const adapter = await getAdapter(noTransactions);
		adapter.options!.adapterConfig.transaction = false;
		await expect(
			createAuthContext(adapter, noTransactions, () => "sqlite"),
		).rejects.toThrow("rollback-capable database transactions");
	});
});
