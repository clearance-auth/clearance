import { serializeSignedCookie } from "@clearance/call";
import { runWithTransaction } from "@clearance/core/context";
import { describe, expect, it } from "vitest";
import {
	attachInternalAuthenticationPolicy,
	type InternalRuntimeAuthenticationPolicyBinding,
} from "../../internal/authentication-policy";
import {
	attachStagedAuthenticationContinuation,
	digestStagedAuthenticationPolicy,
	issueInitialStagedAuthenticationCapability,
	takeStagedAuthenticationContinuation,
} from "../../internal/staged-authentication-context";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import { getTestInstance } from "../../test-utils/test-instance";
import { encodeBackupCodes } from "../two-factor/backup-codes";
import { twoFactor } from "../two-factor";
import type { TwoFactorTable } from "../two-factor/types";
import { passkey } from ".";
import { digestPasskeyChallenge } from "./challenge";
import { createVirtualAuthenticator } from "./virtual-authenticator.test-utils";

const ORIGIN = "http://localhost:3300";
const identity = Object.freeze({
	projectId: "recovery-repair-project",
	environmentId: "recovery-repair-environment",
});

function policy(passkeyAllowed = true) {
	return {
		passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
		factorLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
		minimumAssurance: "multi_factor" as const,
		allowedFactors: { passkey: passkeyAllowed, totp: false },
		trustedDevice: { enabled: false, maxAgeSeconds: 0 },
		assuranceMaxAgeSeconds: 300,
	};
}

async function setup(lockoutEnabled = true) {
	let revision = "1";
	let effective = policy();
	const options = {
		baseURL: ORIGIN,
		plugins: [
			passkey(),
			twoFactor({
				backupCodeOptions: { storeBackupCodes: "hashed" },
				accountLockout: { enabled: lockoutEnabled },
			}),
		],
	};
	attachInternalAuthenticationPolicy(options, {
		identity,
		reader: {
			async readForSubject(input) {
				return {
					scope: identity,
					subjectId: input.subjectId,
					revision,
					environment: effective,
					organizationMembership: null,
					organizationOverride: null,
					effective,
				};
			},
		} satisfies InternalRuntimeAuthenticationPolicyBinding["reader"],
	});
	const instance = await getTestInstance(options, {
		port: 3300,
		disableTestUser: true,
	});
	const context = await instance.auth.$context;
	const user = await context.internalAdapter.createUser({
		email: `recovery-repair-${Math.random()}@example.test`,
		name: "Recovery repair user",
	});
	const recoveryCode = "recovery-repair-code";
	const factor = await context.adapter.create<TwoFactorTable>({
		model: "twoFactor",
		data: {
			userId: user.id,
			secret: "encrypted-source-secret",
			backupCodes: await encodeBackupCodes(
				[recoveryCode, "other-recovery-code"],
				context.secretConfig,
				{ storeBackupCodes: "hashed" },
			),
			verified: true,
			trustDeviceGeneration: "recovery-repair-trust-generation",
		},
	});
	await context.internalAdapter.updateUser(user.id, { twoFactorEnabled: true });
	return {
		instance,
		context,
		user,
		factor,
		recoveryCode,
		setPolicy(value: ReturnType<typeof policy>) {
			effective = value;
		},
		setRevision(value: string) {
			revision = value;
		},
		policyInput: () => ({ revision, digest: digestStagedAuthenticationPolicy(effective) }),
	};
}

async function stagedHeaders(
	fixture: Awaited<ReturnType<typeof setup>>,
): Promise<Headers> {
	const now = new Date();
	const failure = new Error("issue recovery repair staged authority");
	const policyInput = fixture.policyInput();
	attachStagedAuthenticationContinuation(failure, {
		subjectId: fixture.user.id,
		projectId: identity.projectId,
		environmentId: identity.environmentId,
		organizationId: null,
		policyRevision: policyInput.revision,
		policyDigest: await policyInput.digest,
		primaryMethod: "password",
		primaryAt: now,
		dontRememberMe: false,
		allowedFactors: ["passkey"],
		expiresAt: new Date(now.getTime() + 120_000),
	});
	const seed = takeStagedAuthenticationContinuation(failure);
	if (!seed) throw new Error("staged authority was not created");
	const issued = await runWithTransaction(fixture.context.adapter, () =>
		issueInitialStagedAuthenticationCapability(fixture.context as never, seed),
	);
	const serialized = await serializeSignedCookie(
		issued.cookie.name,
		issued.bearer,
		fixture.context.secret,
		issued.cookie.attributes,
	);
	return new Headers({
		origin: ORIGIN,
		cookie: serialized.slice(0, serialized.indexOf(";")),
	});
}

async function beginRepair(fixture: Awaited<ReturnType<typeof setup>>) {
	const response = await (fixture.instance.auth.api as any).recoveryFactorRepair({
		headers: await stagedHeaders(fixture),
		body: { repairFactor: "passkey", recoveryCode: fixture.recoveryCode },
		asResponse: true,
	});
	expect(response.status).toBe(200);
	expect(response.headers.get("cache-control")).toBe("no-store");
	expect(response.headers.get("set-cookie")).toContain("recovery_factor_repair");
	const headers = convertSetCookieToCookie(response.headers);
	headers.set("origin", ORIGIN);
	return headers;
}

async function options(
	fixture: Awaited<ReturnType<typeof setup>>,
	headers: Headers,
) {
	const response = await (fixture.instance.auth.api as any)
		.generatePasskeyRecoveryRepairRegistrationOptions({ headers, asResponse: true });
	expect(response.status).toBe(200);
	expect(response.headers.get("cache-control")).toBe("no-store");
	expect(response.headers.get("pragma")).toBe("no-cache");
	const body = await response.json();
	const next = convertSetCookieToCookie(response.headers);
	next.set("origin", ORIGIN);
	return { body, next, response };
}

async function challengeExpiry(
	fixture: Awaited<ReturnType<typeof setup>>,
	challenge: string,
): Promise<Date> {
	const record = await fixture.context.adapter.findOne<{ expiresAt: Date }>({
		model: "passkeyChallenge",
		where: [
			{
				field: "digestId",
				value: await digestPasskeyChallenge("recovery-registration", challenge),
			},
		],
	});
	expect(record).toBeTruthy();
	return new Date(record!.expiresAt);
}

describe("passkey recovery repair", () => {
	it("refuses passkey recovery when durable attempt lockout is disabled", async () => {
		const fixture = await setup(false);
		const response = await (fixture.instance.auth.api as any).recoveryFactorRepair({
			headers: await stagedHeaders(fixture),
			body: { repairFactor: "passkey", recoveryCode: fixture.recoveryCode },
			asResponse: true,
		});
		expect(response.status).toBe(401);
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(0);
		expect(await fixture.context.adapter.count({ model: "passkey" })).toBe(0);
	});

	it("repairs with exactly one passkey, never creates a session, and returns only completion", async () => {
		const fixture = await setup();
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(0);
		const first = await beginRepair(fixture);
		const issued = await options(fixture, first);
		expect(issued.body.authenticatorSelection).toMatchObject({
			residentKey: "required",
			requireResidentKey: true,
			userVerification: "required",
		});
		expect(issued.response.headers.get("set-cookie")).toContain(
			"recovery_factor_repair",
		);
		expect(issued.response.headers.get("set-cookie")).not.toContain("session_token");
		const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		const verified = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: issued.next,
				body: { response: authenticator.registrationResponse(issued.body.challenge) },
				asResponse: true,
			});
		expect(verified.status).toBe(200);
		expect(await verified.json()).toEqual({ status: true, recoveryComplete: true });
		expect(verified.headers.get("cache-control")).toBe("no-store");
		expect(verified.headers.get("set-cookie")).toContain("recovery_factor_repair=");
		expect(verified.headers.get("set-cookie")).toMatch(/max-age=0/i);
		expect(verified.headers.get("set-cookie")).not.toContain("session_token");
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(0);
		expect(
			await fixture.context.adapter.count({
				model: "passkey",
				where: [{ field: "userId", value: fixture.user.id }],
			}),
		).toBe(1);
	});

	it("burns every rejected proof and issues a deadline-preserving recovery-only retry", async () => {
		const fixture = await setup();
		const issued = await options(fixture, await beginRepair(fixture));
		const deadline = await challengeExpiry(fixture, issued.body.challenge);
		const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		const wrongOrigin = new Headers(issued.next);
		wrongOrigin.set("origin", "http://wrong.example.test");
		const rejectedOrigin = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: wrongOrigin,
				body: { response: authenticator.registrationResponse(issued.body.challenge) },
				asResponse: true,
			});
		expect(rejectedOrigin.status).toBe(401);
		expect(rejectedOrigin.headers.get("set-cookie")).toContain(
			"recovery_factor_repair",
		);
		const predecessorReplay = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: issued.next,
				body: { response: authenticator.registrationResponse(issued.body.challenge) },
				asResponse: true,
			});
		expect(predecessorReplay.status).toBe(401);

		const retryHeaders = convertSetCookieToCookie(rejectedOrigin.headers);
		retryHeaders.set("origin", ORIGIN);
		const retried = await options(fixture, retryHeaders);
		expect(await challengeExpiry(fixture, retried.body.challenge)).toEqual(deadline);
		const retryAuthenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		const rejectedUv = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: retried.next,
				body: {
					response: retryAuthenticator.registrationResponse(retried.body.challenge, {
						userVerified: false,
					}),
				},
				asResponse: true,
			});
		expect(rejectedUv.status).toBe(401);
		expect((await rejectedUv.clone().json()).code).toBe("REMEDIATION_FAILED");
		expect(rejectedUv.headers.get("set-cookie")).toContain("recovery_factor_repair");
		const rejectedUvReplay = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: retried.next,
				body: { response: retryAuthenticator.registrationResponse(retried.body.challenge) },
				asResponse: true,
			});
		expect(rejectedUvReplay.status).toBe(401);

		const secondRetryHeaders = convertSetCookieToCookie(rejectedUv.headers);
		secondRetryHeaders.set("origin", ORIGIN);
		const secondRetry = await options(fixture, secondRetryHeaders);
		expect(await challengeExpiry(fixture, secondRetry.body.challenge)).toEqual(deadline);
		const successfulAuthenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		const completed = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: secondRetry.next,
				body: {
					response: successfulAuthenticator.registrationResponse(secondRetry.body.challenge),
				},
				asResponse: true,
			});
		expect(completed.status).toBe(200);
		expect(await fixture.context.adapter.count({ model: "passkey" })).toBe(1);
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("burns malformed client data before it can replay and permits a fresh registration", async () => {
		const fixture = await setup();
		const issued = await options(fixture, await beginRepair(fixture));
		const deadline = await challengeExpiry(fixture, issued.body.challenge);
		const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		const malformed = authenticator.registrationResponse(issued.body.challenge);
		malformed.response.clientDataJSON = "definitely-not-base64url";
		const rejected = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: issued.next,
				body: { response: malformed },
				asResponse: true,
			});
		expect(rejected.status).toBe(401);
		expect(rejected.headers.get("set-cookie")).toContain("recovery_factor_repair");

		const predecessorReplay = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: issued.next,
				body: { response: authenticator.registrationResponse(issued.body.challenge) },
				asResponse: true,
			});
		expect(predecessorReplay.status).toBe(401);
		const retryHeaders = convertSetCookieToCookie(rejected.headers);
		retryHeaders.set("origin", ORIGIN);
		const retry = await options(fixture, retryHeaders);
		expect(await challengeExpiry(fixture, retry.body.challenge)).toEqual(deadline);
		// The malformed proof could not identify and delete its original
		// challenge. A successor capability must still reject that challenge
		// because its durable binding is to the newly issued ceremony only.
		const bindingMismatch = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: retry.next,
				body: { response: authenticator.registrationResponse(issued.body.challenge) },
				asResponse: true,
			});
		expect(bindingMismatch.status).toBe(401);
		expect(bindingMismatch.headers.get("set-cookie")).toContain(
			"recovery_factor_repair",
		);
		const bindingPredecessorReplay = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: retry.next,
				body: { response: authenticator.registrationResponse(retry.body.challenge) },
				asResponse: true,
			});
		expect(bindingPredecessorReplay.status).toBe(401);
		const finalRetryHeaders = convertSetCookieToCookie(bindingMismatch.headers);
		finalRetryHeaders.set("origin", ORIGIN);
		const finalRetry = await options(fixture, finalRetryHeaders);
		expect(await challengeExpiry(fixture, finalRetry.body.challenge)).toEqual(deadline);
		const successfulAuthenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		const completed = await (fixture.instance.auth.api as any)
			.verifyPasskeyRecoveryRepairRegistration({
				headers: finalRetry.next,
				body: {
					response: successfulAuthenticator.registrationResponse(
						finalRetry.body.challenge,
					),
				},
				asResponse: true,
			});
		expect(completed.status).toBe(200);
		expect(await fixture.context.adapter.count({ model: "passkey" })).toBe(1);
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("serializes concurrent registration attempts to one credential and no session", async () => {
		const fixture = await setup();
		const issued = await options(fixture, await beginRepair(fixture));
		const first = createVirtualAuthenticator(ORIGIN, "localhost");
		const second = createVirtualAuthenticator(ORIGIN, "localhost");
		const attempts = await Promise.all([
			(fixture.instance.auth.api as any).verifyPasskeyRecoveryRepairRegistration({
				headers: new Headers(issued.next),
				body: { response: first.registrationResponse(issued.body.challenge) },
				asResponse: true,
			}),
			(fixture.instance.auth.api as any).verifyPasskeyRecoveryRepairRegistration({
				headers: new Headers(issued.next),
				body: { response: second.registrationResponse(issued.body.challenge) },
				asResponse: true,
			}),
		]);
		expect(attempts.map((response) => response.status).sort()).toEqual([200, 401]);
		expect(
			await fixture.context.adapter.count({
				model: "passkey",
				where: [{ field: "userId", value: fixture.user.id }],
			}),
		).toBe(1);
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("rejects existing factors and policy drift without leaving a credential or session", async () => {
		const existing = await setup();
		const existingHeaders = await beginRepair(existing);
		await existing.context.adapter.create({
			model: "passkey",
			data: {
				userId: existing.user.id,
				name: "Existing passkey",
				credentialID: "existing-credential",
				publicKey: "existing-public-key",
				userHandle: "existing-user-handle",
				counter: 0,
				deviceType: "multiDevice",
				backedUp: true,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});
		const blocked = await (existing.instance.auth.api as any)
			.generatePasskeyRecoveryRepairRegistrationOptions({
				headers: existingHeaders,
				asResponse: true,
			});
		expect(blocked.status).toBe(401);
		expect((await blocked.json()).code).toBe("REMEDIATION_FAILED");

		const drifted = await setup();
		const issued = await options(drifted, await beginRepair(drifted));
		drifted.setPolicy(policy(false));
		drifted.setRevision("2");
		const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		await expect(
			(drifted.instance.auth.api as any).verifyPasskeyRecoveryRepairRegistration({
				headers: issued.next,
				body: { response: authenticator.registrationResponse(issued.body.challenge) },
			}),
		).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
		expect(await drifted.context.adapter.count({ model: "passkey" })).toBe(0);
		expect(await drifted.context.adapter.count({ model: "session" })).toBe(0);
	});
});
