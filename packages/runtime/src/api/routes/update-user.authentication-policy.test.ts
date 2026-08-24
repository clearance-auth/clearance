import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import { describe, expect, it, vi } from "vitest";
import { attachInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { getTestInstance } from "../../test-utils/test-instance";

const identity = {
	projectId: "update-user-policy-project",
	environmentId: "update-user-policy-environment",
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
	minimumAssurance: "single_factor",
	allowedFactors: { totp: true, passkey: true },
	trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
	assuranceMaxAgeSeconds: 300,
} satisfies RuntimeAuthenticationPolicy;

function managedOptions(
	overrides: Partial<ClearanceOptions> = {},
): ClearanceOptions {
	const options = {
		baseURL: "http://localhost:3000",
		secret: "managed-update-user-test-secret-that-is-long-enough",
		emailAndPassword: { enabled: true },
		...overrides,
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
	return options;
}

describe("managed update-user transactions", () => {
	it("rolls back password mutation and session revocation when replacement issuance fails", async () => {
		const { auth, client, sessionSetter } = await getTestInstance(
			managedOptions(),
			{ disableTestUser: true },
		);
		const headers = new Headers();
		const email = `managed-password-change-${Date.now()}@example.test`;
		const originalPassword = "original-password-123";
		const replacementPassword = "replacement-password-123";
		await client.signUp.email({
			email,
			password: originalPassword,
			name: "Managed password change",
			fetchOptions: { onSuccess: sessionSetter(headers) },
		});
		const context = await auth.$context;
		const originalCreateSession = context.internalAdapter.createSession.bind(
			context.internalAdapter,
		);
		const createSession = vi
			.spyOn(context.internalAdapter, "createSession")
			.mockRejectedValueOnce(new Error("forced replacement issuance failure"))
			.mockImplementation(originalCreateSession);

		const failed = await client.changePassword({
			newPassword: replacementPassword,
			currentPassword: originalPassword,
			revokeOtherSessions: true,
			fetchOptions: { headers },
		});
		expect(failed.error).not.toBeNull();
		createSession.mockRestore();

		const session = await client.getSession({ fetchOptions: { headers } });
		expect(session.data?.user.email).toBe(email);
		const [account] = await context.internalAdapter.findAccounts(
			session.data!.user.id,
		);
		expect(
			await context.password.verify({
				hash: account!.password!,
				password: originalPassword,
			}),
		).toBe(true);
		expect(
			await context.password.verify({
				hash: account!.password!,
				password: replacementPassword,
			}),
		).toBe(false);

		const retried = await client.changePassword({
			newPassword: replacementPassword,
			currentPassword: originalPassword,
			revokeOtherSessions: true,
			fetchOptions: { headers },
		});
		expect(retried.data?.token).toMatch(/^clr_rt_/);
	});

	it("rolls back delete-token consumption and account deletion together", async () => {
		let token = "";
		const { auth, client, sessionSetter } = await getTestInstance(
			managedOptions({
				user: {
					deleteUser: {
						enabled: true,
						async sendDeleteAccountVerification(input) {
							token = input.token;
						},
					},
				},
			}),
			{ disableTestUser: true },
		);
		const headers = new Headers();
		const email = `managed-delete-${Date.now()}@example.test`;
		const password = "delete-password-123";
		await client.signUp.email({
			email,
			password,
			name: "Managed delete",
			fetchOptions: { onSuccess: sessionSetter(headers) },
		});
		await client.deleteUser({ password, fetchOptions: { headers } });
		expect(token).toHaveLength(32);

		const context = await auth.$context;
		const identifier = `delete-account-${token}`;
		const originalDeleteAccounts = context.internalAdapter.deleteAccounts.bind(
			context.internalAdapter,
		);
		const deleteAccounts = vi
			.spyOn(context.internalAdapter, "deleteAccounts")
			.mockRejectedValueOnce(new Error("forced account deletion failure"))
			.mockImplementation(originalDeleteAccounts);
		const request = () =>
			new Request(
				`http://localhost:3000/api/auth/delete-user/callback?token=${token}`,
				{
					method: "GET",
					headers: { cookie: headers.get("cookie") ?? "" },
				},
			);

		const failed = await auth.handler(request());
		expect(failed.status).toBeGreaterThanOrEqual(500);
		deleteAccounts.mockRestore();
		await expect(
			context.internalAdapter.findVerificationValueAndPruneExpired(identifier),
		).resolves.not.toBeNull();
		await expect(
			client.getSession({ fetchOptions: { headers } }),
		).resolves.toMatchObject({ data: { user: { email } } });

		const retried = await auth.handler(request());
		expect(retried.status).toBe(200);
		await expect(
			context.internalAdapter.findVerificationValueAndPruneExpired(identifier),
		).resolves.toBeNull();
	});
});
