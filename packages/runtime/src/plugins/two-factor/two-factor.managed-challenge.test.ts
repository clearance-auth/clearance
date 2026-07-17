import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { describe, expect, it } from "vitest";
import { clearance } from "../../auth/full";
import { getMigrations } from "../../db/get-migration";
import { attachInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "../../internal/verification-challenge-context";
import { TWO_FACTOR_CHALLENGE_PURPOSE } from "./utils";

async function managedRuntime() {
	const database = new DatabaseSync(":memory:");
	const identity = {
		projectId: "two-factor-policy-project",
		environmentId: "two-factor-policy-environment",
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
		minimumAssurance: "multi_factor",
		allowedFactors: { totp: true, passkey: true },
		trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
		assuranceMaxAgeSeconds: 300,
	} satisfies RuntimeAuthenticationPolicy;
	const options = {
		baseURL: "http://localhost:3000",
		secret: "managed-two-factor-test-secret",
		database,
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
	return { context: await clearance(options).$context, database };
}

describe("managed two-factor challenge bindings", () => {
	it("rejects a purpose mismatch without spending the challenge", async () => {
		const runtime = await managedRuntime();
		const identifier = "2fa-purpose-bound-challenge";
		try {
			await createInternalVerificationChallenge(
				runtime.context.internalAdapter,
				{
					purpose: TWO_FACTOR_CHALLENGE_PURPOSE.signIn,
					subject: "user-1",
				},
				{
					identifier,
					value: "user-1",
					expiresAt: new Date(Date.now() + 60_000),
				},
			);

			const mismatched = await runWithTransaction(
				runtime.context.adapter,
				() =>
					consumeInternalVerificationChallenge(
						runtime.context.internalAdapter,
						{
							purpose: TWO_FACTOR_CHALLENGE_PURPOSE.otp,
							subject: "user-1",
							identifier,
						},
					),
			);
			expect(mismatched).toBeNull();

			const consumed = await runWithTransaction(
				runtime.context.adapter,
				() =>
					consumeInternalVerificationChallenge(
						runtime.context.internalAdapter,
						{
							purpose: TWO_FACTOR_CHALLENGE_PURPOSE.signIn,
							subject: "user-1",
							identifier,
						},
					),
			);
			expect(consumed?.value).toBe("user-1");
		} finally {
			runtime.database.close();
		}
	});

	it("rolls challenge consumption and its authorized mutation back for retry", async () => {
		const runtime = await managedRuntime();
		const identifier = "2fa-rollback-challenge";
		try {
			await runtime.context.adapter.create({
				model: "user",
				forceAllowId: true,
				data: {
					id: "user-rollback",
					name: "before",
					email: "rollback@example.test",
					emailVerified: true,
				},
			});
			await createInternalVerificationChallenge(
				runtime.context.internalAdapter,
				{
					purpose: TWO_FACTOR_CHALLENGE_PURPOSE.signIn,
					subject: "user-rollback",
				},
				{
					identifier,
					value: "user-rollback",
					expiresAt: new Date(Date.now() + 60_000),
				},
			);

			await expect(
				runWithTransaction(runtime.context.adapter, async () => {
					const consumed = await consumeInternalVerificationChallenge(
						runtime.context.internalAdapter,
						{
							purpose: TWO_FACTOR_CHALLENGE_PURPOSE.signIn,
							subject: "user-rollback",
							identifier,
						},
					);
					expect(consumed).not.toBeNull();
					const adapter = await getCurrentAdapter(runtime.context.adapter);
					await adapter.update({
						model: "user",
						where: [{ field: "id", value: "user-rollback" }],
						update: { name: "rolled-back" },
					});
					throw new Error("force rollback");
				}),
			).rejects.toThrow("force rollback");
			await expect(
				runtime.context.adapter.findOne<{ name: string }>({
					model: "user",
					where: [{ field: "id", value: "user-rollback" }],
				}),
			).resolves.toMatchObject({ name: "before" });

			const retried = await runWithTransaction(
				runtime.context.adapter,
				async () => {
					const consumed = await consumeInternalVerificationChallenge(
						runtime.context.internalAdapter,
						{
							purpose: TWO_FACTOR_CHALLENGE_PURPOSE.signIn,
							subject: "user-rollback",
							identifier,
						},
					);
					const adapter = await getCurrentAdapter(runtime.context.adapter);
					await adapter.update({
						model: "user",
						where: [{ field: "id", value: "user-rollback" }],
						update: { name: "committed" },
					});
					return consumed;
				},
			);
			expect(retried?.value).toBe("user-rollback");
			await expect(
				runtime.context.adapter.findOne<{ name: string }>({
					model: "user",
					where: [{ field: "id", value: "user-rollback" }],
				}),
			).resolves.toMatchObject({ name: "committed" });
			await expect(
				runWithTransaction(runtime.context.adapter, () =>
					consumeInternalVerificationChallenge(
						runtime.context.internalAdapter,
						{
							purpose: TWO_FACTOR_CHALLENGE_PURPOSE.signIn,
							subject: "user-rollback",
							identifier,
						},
					),
				),
			).resolves.toBeNull();
		} finally {
			runtime.database.close();
		}
	});
});
