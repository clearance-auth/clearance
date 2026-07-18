import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import {
	queueAfterTransactionHook,
	runWithTransaction,
} from "@clearance/core/context";
import { describe, expect, it, vi } from "vitest";
import { parseCookies } from "../../cookies";
import { attachInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { getTestInstance } from "../../test-utils/test-instance";
import { getOrgAdapter } from "./adapter";
import { organizationClient } from "./client";
import { organization } from "./organization";
import type { OrganizationOptions } from "./types";

const identity = {
	projectId: "organization-transition-project",
	environmentId: "organization-transition-environment",
} satisfies RuntimeAuthenticationPolicyIdentity;

const policy = {
	passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	factorLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	minimumAssurance: "single_factor",
	allowedFactors: { totp: true, passkey: true },
	trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
	assuranceMaxAgeSeconds: 300,
} satisfies RuntimeAuthenticationPolicy;

function managedOrganizationOptions(
	allowOrganizationMembership = true,
	requireStoredMembership = true,
	membershipLimit?: number,
	organizationHooks?: OrganizationOptions["organizationHooks"],
) {
	const options = {
		plugins: [
			organization({
				async sendInvitationEmail() {},
				...(membershipLimit === undefined ? {} : { membershipLimit }),
				...(organizationHooks === undefined ? {} : { organizationHooks }),
			}),
		],
	} satisfies ClearanceOptions;
	attachInternalAuthenticationPolicy(options, {
		identity,
		reader: {
			async readForSubject(input) {
				const membership =
					input.organizationId && input.transaction
						? await input.transaction.findOne<{
							userId: string;
							organizationId: string;
						}>({
								model: "member",
								where: [
									{ field: "userId", value: input.subjectId },
									{
										field: "organizationId",
										value: input.organizationId,
									},
								],
							})
						: null;
				return {
					scope: identity,
					subjectId: input.subjectId,
					revision: "1",
					environment: policy,
					organizationMembership:
						allowOrganizationMembership &&
						input.organizationId &&
						(membership || !requireStoredMembership)
						? {
								subjectId: input.subjectId,
								organizationId: input.organizationId,
							}
						: null,
					organizationOverride: null,
					effective: policy,
				};
			},
		},
	});
	return options;
}

describe("managed organization session transitions", () => {
	it("fails closed for secondary-only sessions before direct or destructive lifecycle work", async () => {
		const secondary = new Map<string, string>();
		const options = managedOrganizationOptions() as ClearanceOptions;
		// Initialization correctly requires managed sessions to be database-backed.
		// Simulate a later unsafe configuration change to prove this transition
		// boundary itself never splits the two authorities.
		options.session = { storeSessionInDatabase: true };
		options.secondaryStorage = {
			namespace: "managed-org-secondary-transition",
			get: async (key) => secondary.get(key) ?? null,
			set: async (key, value) => {
				secondary.set(key, value);
			},
			delete: async (key) => {
				secondary.delete(key);
			},
		};
		const fixture = await getTestInstance(options, {
			clientOptions: { plugins: [organizationClient()] },
		});
		const signedIn = await fixture.signInWithTestUser();
		const source = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		const context = await fixture.auth.$context;
		context.options.session!.storeSessionInDatabase = false;
		const organizationId = "managed-secondary-transition-organization";
		await context.adapter.create({
			model: "organization",
			data: {
				id: organizationId,
				name: "Managed secondary transition organization",
				slug: "managed-secondary-transition-organization",
				logo: null,
				metadata: null,
				createdAt: new Date(),
			},
			forceAllowId: true,
		});
		await context.adapter.create({
			model: "member",
			data: {
				id: "managed-secondary-transition-member",
				organizationId,
				userId: signedIn.user.id,
				role: "member",
				createdAt: new Date(),
			},
			forceAllowId: true,
		});
		const secondaryKeysBefore = [...secondary.keys()].sort();
		const beforeCapture = vi.fn();
		const afterCapture = vi.fn(async () => {
			await context.adapter.delete({
				model: "member",
				where: [{ field: "id", value: "managed-secondary-transition-member" }],
			});
		});
		const deleteSession = vi.spyOn(context.internalAdapter, "deleteSession");
		const createSession = vi.spyOn(context.internalAdapter, "createSession");
		const findSession = vi.spyOn(context.internalAdapter, "findSession");
		const transaction = vi.spyOn(context.adapter, "transaction");
		const getSignedCookie = vi.fn(async () => {
			throw new Error("must not read transition cookies");
		});
		const adapter = getOrgAdapter(context);
		const unsupportedContext = (session: typeof source.data) =>
			({
				context: { ...context, session },
				getSignedCookie,
			}) as never;
		await expect(
			adapter.setActiveOrganization(
				source.data!.session.token,
				organizationId,
				unsupportedContext(source.data),
				{ beforeCapture, afterCapture },
			),
		).rejects.toMatchObject({
			body: {
				code: "MANAGED_ORGANIZATION_SECONDARY_SESSION_TRANSITION_UNSUPPORTED",
			},
		});
		await expect(
			adapter.setActiveOrganization(
				"missing-or-mismatched-source",
				organizationId,
				unsupportedContext(null),
				{ beforeCapture, afterCapture },
			),
		).rejects.toMatchObject({
			body: {
				code: "MANAGED_ORGANIZATION_SECONDARY_SESSION_TRANSITION_UNSUPPORTED",
			},
		});
		expect(beforeCapture).not.toHaveBeenCalled();
		expect(afterCapture).not.toHaveBeenCalled();
		expect(getSignedCookie).not.toHaveBeenCalled();
		expect(findSession).not.toHaveBeenCalled();
		expect(transaction).not.toHaveBeenCalled();
		expect(deleteSession).not.toHaveBeenCalled();
		expect(createSession).not.toHaveBeenCalled();
		expect([...secondary.keys()].sort()).toEqual(secondaryKeysBefore);

		// The supplied after-capture callback models an active destructive route
		// (member removal). It remains absent, so no rollback cleanup can leave a
		// secondary ghost after an authority split.
		expect(afterCapture).not.toHaveBeenCalled();
		await expect(
			context.adapter.findOne({
				model: "organization",
				where: [{ field: "id", value: organizationId }],
			}),
		).resolves.not.toBeNull();
		await expect(
			context.adapter.findOne({
				model: "member",
				where: [
					{ field: "organizationId", value: organizationId },
					{ field: "userId", value: signedIn.user.id },
				],
			}),
		).resolves.not.toBeNull();
		await expect(
			context.adapter.findOne({
				model: "session",
				where: [{ field: "id", value: source.data!.session.id }],
			}),
		).resolves.toMatchObject({ id: source.data!.session.id });
	});

	it("replaces the presented bearer when explicitly setting and unsetting an organization", async () => {
		const options = managedOrganizationOptions();
		const { auth, client, cookieSetter, signInWithTestUser } =
			await getTestInstance(options, {
				clientOptions: { plugins: [organizationClient()] },
			});
		const { headers } = await signInWithTestUser();
		const initialSession = await client.getSession({ fetchOptions: { headers } });
		expect(initialSession.data?.session).toBeDefined();
		const sourceId = initialSession.data!.session.id;
		const organizationRecord = await client.organization.create({
			name: "Managed organization",
			slug: "managed-organization",
			fetchOptions: { headers, onSuccess: cookieSetter(headers) },
		});
		expect(organizationRecord.error).toBeNull();

		const firstSuccessor = await client.getSession({ fetchOptions: { headers } });
		expect(firstSuccessor.data?.session.id).not.toBe(sourceId);
		expect(firstSuccessor.data?.session.activeOrganizationId).toBe(
			organizationRecord.data?.id,
		);

		const context = await auth.$context;
		expect(
			await context.adapter.findOne({
				model: "session",
				where: [{ field: "id", value: sourceId }],
			}),
		).toBeNull();

		const unset = await client.organization.setActive({
			organizationId: null,
			fetchOptions: { headers, onSuccess: cookieSetter(headers) },
		});
		expect(unset.error).toBeNull();
		const finalSession = await client.getSession({ fetchOptions: { headers } });
		expect(finalSession.data?.session.id).not.toBe(firstSuccessor.data?.session.id);
		expect(finalSession.data?.session.activeOrganizationId).toBeNull();
	});

	it("supports the server auth.api transition path with authoritative headers", async () => {
		const options = {
			plugins: [organization()],
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
			},
		});
		const fixture = await getTestInstance(options, {
			clientOptions: { plugins: [organizationClient()] },
		});
		const signedIn = await fixture.signInWithTestUser();
		const context = await fixture.auth.$context;
		const organizationId = "server_transition_organization";
		await context.adapter.create({
			model: "organization",
			data: {
				id: organizationId,
				name: "Server transition organization",
				slug: "server-transition-organization",
				logo: null,
				metadata: null,
				createdAt: new Date(),
			},
			forceAllowId: true,
		});
		await context.adapter.create({
			model: "member",
			data: {
				id: "server_transition_member",
				organizationId,
				userId: signedIn.user.id,
				role: "owner",
				createdAt: new Date(),
			},
			forceAllowId: true,
		});
		const response = await fixture.auth.api.setActiveOrganization({
			body: { organizationId },
			headers: signedIn.headers,
			asResponse: true,
		});
		expect(response.headers.get("set-cookie")).toContain("clearance.session_token");
		expect((await response.json()).id).toBe(organizationId);
	});

	it("preserves the signed dont-remember marker through HTTP transition issuance", async () => {
		const options = {
			plugins: [organization()],
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
			},
		});
		const fixture = await getTestInstance(options, {
			clientOptions: { plugins: [organizationClient()] },
		});
		const headers = new Headers();
		const signedIn = await fixture.client.signIn.email(
			{ ...fixture.testUser, rememberMe: false },
			{ onSuccess: fixture.cookieSetter(headers) },
		);
		expect(headers.get("cookie")).toContain("dont_remember");
		const context = await fixture.auth.$context;
		const organizationId = "dont_remember_transition_organization";
		await context.adapter.create({
			model: "organization",
			data: {
				id: organizationId,
				name: "Dont remember organization",
				slug: "dont-remember-transition-organization",
				logo: null,
				metadata: null,
				createdAt: new Date(),
			},
			forceAllowId: true,
		});
		await context.adapter.create({
			model: "member",
			data: {
				id: "dont_remember_transition_member",
				organizationId,
				userId: signedIn.data!.user.id,
				role: "owner",
				createdAt: new Date(),
			},
			forceAllowId: true,
		});
		const createSession = vi.spyOn(context.internalAdapter, "createSession");
		const transition = await fixture.client.organization.setActive({
			organizationId,
			fetchOptions: { headers },
		});
		expect(transition.error).toBeNull();
		expect(createSession.mock.calls.at(-1)?.[1]).toBe(true);
	});

	it("commits invitation acceptance with a new bearer and publishes its cookie", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const owner = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Invitation transition organization",
			slug: "invitation-transition-organization",
			fetchOptions: {
				headers: owner.headers,
				onSuccess: fixture.cookieSetter(owner.headers),
			},
		});
		expect(created.error).toBeNull();

		const invitee = {
			email: "managed-invitee@example.com",
			password: "managed-invitee-password",
			name: "Managed Invitee",
		};
		const invitation = await fixture.client.organization.inviteMember({
			organizationId: created.data!.id,
			email: invitee.email,
			role: "member",
			fetchOptions: { headers: owner.headers },
		});
		expect(invitation.error).toBeNull();
		const inviteeHeaders = new Headers();
		await fixture.client.signUp.email(invitee, {
			onSuccess: fixture.cookieSetter(inviteeHeaders),
		});
		const source = await fixture.client.getSession({
			fetchOptions: { headers: inviteeHeaders },
		});
		const accepted = await fixture.client.organization.acceptInvitation({
			invitationId: invitation.data!.id,
			fetchOptions: {
				headers: inviteeHeaders,
				onSuccess: fixture.cookieSetter(inviteeHeaders),
			},
		});

		expect(accepted.error).toBeNull();
		expect(accepted.data?.invitation.status).toBe("accepted");
		const successor = await fixture.client.getSession({
			fetchOptions: { headers: inviteeHeaders },
		});
		expect(successor.data?.session.id).not.toBe(source.data?.session.id);
		expect(successor.data?.session.activeOrganizationId).toBe(created.data!.id);
		const context = await fixture.auth.$context;
		await expect(
			context.internalAdapter.findSession(source.data!.session.token),
		).resolves.toBeNull();
	});

	it("rolls invitation acceptance back when target policy rejects issuance", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(false), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const owner = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Rejected invitation organization",
			slug: "rejected-invitation-organization",
			keepCurrentActiveOrganization: true,
			fetchOptions: { headers: owner.headers },
		});
		const invitee = {
			email: "managed-rejected-invitee@example.com",
			password: "managed-rejected-password",
			name: "Managed Rejected Invitee",
		};
		const invitation = await fixture.client.organization.inviteMember({
			organizationId: created.data!.id,
			email: invitee.email,
			role: "member",
			fetchOptions: { headers: owner.headers },
		});
		const inviteeHeaders = new Headers();
		const signedUp = await fixture.client.signUp.email(invitee, {
			onSuccess: fixture.cookieSetter(inviteeHeaders),
		});
		const accepted = await fixture.client.organization.acceptInvitation({
			invitationId: invitation.data!.id,
			fetchOptions: { headers: inviteeHeaders },
		});
		expect(accepted.error).not.toBeNull();

		const context = await fixture.auth.$context;
		await expect(
			context.adapter.findOne({
				model: "invitation",
				where: [{ field: "id", value: invitation.data!.id }],
			}),
		).resolves.toMatchObject({ status: "pending" });
		await expect(
			context.adapter.findOne({
				model: "member",
				where: [
					{ field: "organizationId", value: created.data!.id },
					{ field: "userId", value: signedUp.data!.user.id },
				],
			}),
		).resolves.toBeNull();
	});

	it("serializes distinct invitation acceptances at the organization membership limit", async () => {
		const fixture = await getTestInstance(
			managedOrganizationOptions(true, true, 2),
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const owner = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Membership limit organization",
			slug: "membership-limit-organization",
			keepCurrentActiveOrganization: true,
			fetchOptions: { headers: owner.headers },
		});
		expect(created.error).toBeNull();
		const invitees = [
			{
				email: "membership-limit-first@example.com",
				password: "membership-limit-password",
				name: "Membership Limit First",
			},
			{
				email: "membership-limit-second@example.com",
				password: "membership-limit-password",
				name: "Membership Limit Second",
			},
		];
		const invitations = await Promise.all(
			invitees.map((invitee) =>
				fixture.client.organization.inviteMember({
					organizationId: created.data!.id,
					email: invitee.email,
					role: "member",
					fetchOptions: { headers: owner.headers },
				}),
			),
		);
		expect(invitations.every((invitation) => invitation.error === null)).toBe(true);
		const inviteeHeaders = [new Headers(), new Headers()];
		await Promise.all(
			invitees.map((invitee, index) =>
				fixture.client.signUp.email(invitee, {
					onSuccess: fixture.cookieSetter(inviteeHeaders[index]!),
				}),
			),
		);

		const acceptances = await Promise.all(
			invitations.map((invitation, index) =>
				fixture.client.organization.acceptInvitation({
					invitationId: invitation.data!.id,
					fetchOptions: {
						headers: inviteeHeaders[index]!,
						onSuccess: fixture.cookieSetter(inviteeHeaders[index]!),
					},
				}),
			),
		);
		expect(acceptances.filter((result) => result.error === null)).toHaveLength(1);
		const rejectedIndex = acceptances.findIndex((result) => result.error !== null);
		expect(rejectedIndex).toBeGreaterThanOrEqual(0);
		const context = await fixture.auth.$context;
		await expect(
			context.adapter.findOne({
				model: "invitation",
				where: [{ field: "id", value: invitations[rejectedIndex]!.data!.id }],
			}),
		).resolves.toMatchObject({ status: "pending" });
		await expect(
			context.adapter.count({
				model: "member",
				where: [{ field: "organizationId", value: created.data!.id }],
			}),
		).resolves.toBe(2);
	});

	it("publishes the environment successor on unauthorized fallback", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const signedIn = await fixture.signInWithTestUser();
		await fixture.client.organization.create({
			name: "Fallback source organization",
			slug: "fallback-source-organization",
			fetchOptions: {
				headers: signedIn.headers,
				onResponse: fixture.cookieSetter(signedIn.headers),
			},
		});
		const source = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		const fallback = await fixture.client.organization.setActive({
			organizationId: "organization_without_membership",
			fetchOptions: {
				headers: signedIn.headers,
				onResponse: fixture.cookieSetter(signedIn.headers),
			},
		});
		expect(fallback.error?.status).toBe(403);
		const successor = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		expect(successor.data?.session.activeOrganizationId).toBeFalsy();
		expect(successor.data?.session.id).not.toBe(source.data?.session.id);
		const context = await fixture.auth.$context;
		await expect(
			context.internalAdapter.findSession(source.data!.session.token),
		).resolves.toBeNull();
	});

	it("publishes the committed active-delete successor before surfacing an after-hook failure", async () => {
		const fixture = await getTestInstance(
			managedOrganizationOptions(true, true, undefined, {
				afterDeleteOrganization: async () => {
					throw new Error("after delete failed");
				},
			}),
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const signedIn = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "After hook failure organization",
			slug: "after-hook-failure-organization",
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		expect(created.error).toBeNull();
		const source = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		let setCookie = "";
		const deleted = await fixture.client.organization.delete({
			organizationId: created.data!.id,
			fetchOptions: {
				headers: signedIn.headers,
				onResponse(response) {
					setCookie = response.response.headers.get("set-cookie") || "";
					fixture.cookieSetter(signedIn.headers)(response);
				},
			},
		});
		expect(deleted.error?.status).toBe(500);
		expect(setCookie).toContain("clearance.session_token");
		expect(setCookie).not.toMatch(/Max-Age=0/i);
		const context = await fixture.auth.$context;
		await expect(
			context.adapter.findOne({
				model: "organization",
				where: [{ field: "id", value: created.data!.id }],
			}),
		).resolves.toBeNull();
		await expect(
			context.internalAdapter.findSession(source.data!.session.token),
		).resolves.toBeNull();
		const successor = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		expect(successor.data?.session.activeOrganizationId).toBeFalsy();
		expect(successor.data?.session.id).not.toBe(source.data?.session.id);
	});

	it("revokes every database session scoped to a deleted organization, including stale nonmembers", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const owner = await fixture.signInWithTestUser();
		const organizationRecord = await fixture.client.organization.create({
			name: "Stale session deletion organization",
			slug: "stale-session-deletion-organization",
			fetchOptions: {
				headers: owner.headers,
				onSuccess: fixture.cookieSetter(owner.headers),
			},
		});
		const secondHeaders = new Headers();
		const second = await fixture.client.signUp.email(
			{
				email: "stale-session-member@test.com",
				password: "password",
				name: "stale session member",
			},
			{ onSuccess: fixture.cookieSetter(secondHeaders) },
		);
		await fixture.auth.api.addMember({
			body: {
				organizationId: organizationRecord.data!.id,
				userId: second.data!.user.id,
				role: "member",
			},
			headers: owner.headers,
		});
		await fixture.client.organization.setActive({
			organizationId: organizationRecord.data!.id,
			fetchOptions: {
				headers: secondHeaders,
				onSuccess: fixture.cookieSetter(secondHeaders),
			},
		});
		const staleSession = await fixture.client.getSession({
			fetchOptions: { headers: secondHeaders },
		});
		const context = await fixture.auth.$context;
		await context.adapter.delete({
			model: "member",
			where: [
				{ field: "organizationId", value: organizationRecord.data!.id },
				{ field: "userId", value: second.data!.user.id },
			],
		});
		const deleted = await fixture.client.organization.delete({
			organizationId: organizationRecord.data!.id,
			fetchOptions: {
				headers: owner.headers,
				onSuccess: fixture.cookieSetter(owner.headers),
			},
		});
		expect(deleted.error).toBeNull();
		await expect(
			context.internalAdapter.findSession(staleSession.data!.session.token),
		).resolves.toBeNull();
	});

	it("treats a target deleted before its locked transition as unavailable", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const signedIn = await fixture.signInWithTestUser();
		const source = await fixture.client.organization.create({
			name: "Deleted target source organization",
			slug: "deleted-target-source-organization",
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		const target = await fixture.client.organization.create({
			name: "Deleted target organization",
			slug: "deleted-target-organization",
			keepCurrentActiveOrganization: true,
			fetchOptions: { headers: signedIn.headers },
		});
		expect(source.error).toBeNull();
		expect(target.error).toBeNull();
		const sourceSession = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		const context = await fixture.auth.$context;
		await context.adapter.delete({
			model: "organization",
			where: [{ field: "id", value: target.data!.id }],
		});

		const rejected = await fixture.client.organization.setActive({
			organizationId: target.data!.id,
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		expect(rejected.error?.status).toBe(403);
		const successor = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		expect(successor.data?.session.activeOrganizationId).toBeFalsy();
		expect(successor.data?.session.id).not.toBe(sourceSession.data?.session.id);
	});

	it("does not disclose an existing target without membership", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const signedIn = await fixture.signInWithTestUser();
		const source = await fixture.client.organization.create({
			name: "Unavailable membership source organization",
			slug: "unavailable-membership-source-organization",
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		expect(source.error).toBeNull();
		const context = await fixture.auth.$context;
		const targetId = "existing-unavailable-target";
		await context.adapter.create({
			model: "organization",
			data: {
				id: targetId,
				name: "Existing unavailable target",
				slug: "existing-unavailable-target",
				logo: null,
				metadata: null,
				createdAt: new Date(),
			},
			forceAllowId: true,
		});
		const rejected = await fixture.client.organization.setActive({
			organizationId: targetId,
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		expect(rejected.error?.status).toBe(403);
		expect((await fixture.client.getSession({ fetchOptions: { headers: signedIn.headers } })).data?.session.activeOrganizationId).toBeFalsy();
	});

	it("gives unknown and nonmember slug targets the same fallback response and cookie", async () => {
		const attempt = async (slug: string, createTarget: boolean) => {
			const fixture = await getTestInstance(managedOrganizationOptions(), {
				clientOptions: { plugins: [organizationClient()] },
			});
			const signedIn = await fixture.signInWithTestUser();
			const source = await fixture.client.organization.create({
				name: `Slug fallback source ${slug}`,
				slug: `slug-fallback-source-${slug}`,
				fetchOptions: {
					headers: signedIn.headers,
					onSuccess: fixture.cookieSetter(signedIn.headers),
				},
			});
			expect(source.error).toBeNull();
			if (createTarget) {
				const context = await fixture.auth.$context;
				await context.adapter.create({
					model: "organization",
					data: {
						id: `nonmember-${slug}`,
						name: "Nonmember slug target",
						slug,
						logo: null,
						metadata: null,
						createdAt: new Date(),
					},
					forceAllowId: true,
				});
			}
			let setCookie = "";
			const rejected = await fixture.client.organization.setActive({
				organizationSlug: slug,
				fetchOptions: {
					headers: signedIn.headers,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			});
			return { status: rejected.error?.status, setCookie };
		};

		const unknown = await attempt("unknown-slug-target", false);
		const nonmember = await attempt("nonmember-slug-target", true);
		expect(unknown.status).toBe(403);
		expect(nonmember.status).toBe(403);
		expect(unknown.setCookie).toContain("clearance.session_token");
		expect(nonmember.setCookie).toContain("clearance.session_token");
		expect(unknown.setCookie).not.toMatch(/Max-Age=0/i);
		expect(nonmember.setCookie).not.toMatch(/Max-Age=0/i);
	});

	it("activates an authorized slug through the locked transition", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const signedIn = await fixture.signInWithTestUser();
		await fixture.client.organization.create({
			name: "Slug transition source organization",
			slug: "slug-transition-source-organization",
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		const destination = await fixture.client.organization.create({
			name: "Slug transition destination organization",
			slug: "slug-transition-destination-organization",
			keepCurrentActiveOrganization: true,
			fetchOptions: { headers: signedIn.headers },
		});
		const transitioned = await fixture.client.organization.setActive({
			organizationSlug: destination.data!.slug,
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		expect(transitioned.error).toBeNull();
		expect(transitioned.data?.id).toBe(destination.data?.id);
		expect((await fixture.client.getSession({ fetchOptions: { headers: signedIn.headers } })).data?.session.activeOrganizationId).toBe(destination.data?.id);
	});

	it("revokes a stale source with lost active membership without replacement", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(true, false), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const signedIn = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Lost membership organization",
			slug: "lost-membership-organization",
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		const source = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		const context = await fixture.auth.$context;
		await context.adapter.delete({
			model: "member",
			where: [
				{ field: "organizationId", value: created.data!.id },
				{ field: "userId", value: source.data!.user.id },
			],
		});
		const rejected = await fixture.client.organization.setActive({
			organizationId: "another_unavailable_organization",
			fetchOptions: {
				headers: signedIn.headers,
				onResponse: fixture.cookieSetter(signedIn.headers),
			},
		});
		expect(rejected.error?.status).toBe(403);
		await expect(
			context.internalAdapter.findSession(source.data!.session.token),
		).resolves.toBeNull();
		await expect(
			fixture.client.getSession({ fetchOptions: { headers: signedIn.headers } }),
		).resolves.toMatchObject({ data: null });
	});

	it("durably revokes a stale active source when explicitly clearing it without publishing a successor", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(true, false), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const signedIn = await fixture.signInWithTestUser();
		const activeOrganization = await fixture.client.organization.create({
			name: "Stale source explicit clear organization",
			slug: "stale-source-explicit-clear-organization",
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		expect(activeOrganization.error).toBeNull();
		const source = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		const context = await fixture.auth.$context;
		await context.adapter.delete({
			model: "member",
			where: [
				{ field: "organizationId", value: activeOrganization.data!.id },
				{ field: "userId", value: signedIn.user.id },
			],
		});

		let publishedCookie: string | null = null;
		const cleared = await fixture.client.organization.setActive({
			organizationId: null,
			fetchOptions: {
				headers: signedIn.headers,
				onResponse(response) {
					publishedCookie = response.response.headers.get("set-cookie");
				},
			},
		});

		expect(cleared.error?.status).toBe(403);
		expect(publishedCookie).toBeNull();
		await expect(
			context.internalAdapter.findSession(source.data!.session.token),
		).resolves.toBeNull();
		await expect(
			fixture.client.getSession({ fetchOptions: { headers: signedIn.headers } }),
		).resolves.toMatchObject({ data: null });
	});

	it("rechecks stale source membership under its owning lock before a valid destination can issue a successor", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(true, false), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const signedIn = await fixture.signInWithTestUser();
		const sourceOrganization = await fixture.client.organization.create({
			name: "Stale source locked transition organization",
			slug: "stale-source-locked-transition-organization",
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: fixture.cookieSetter(signedIn.headers),
			},
		});
		const destinationOrganization = await fixture.client.organization.create({
			name: "Valid destination after stale source organization",
			slug: "valid-destination-after-stale-source-organization",
			keepCurrentActiveOrganization: true,
			fetchOptions: { headers: signedIn.headers },
		});
		expect(sourceOrganization.error).toBeNull();
		expect(destinationOrganization.error).toBeNull();
		const source = await fixture.client.getSession({
			fetchOptions: { headers: signedIn.headers },
		});
		const context = await fixture.auth.$context;

		let releaseSourceRemoval: () => void = () => {};
		const sourceRemovalGate = new Promise<void>((resolve) => {
			releaseSourceRemoval = resolve;
		});
		let signalSourceRemovalStarted: () => void = () => {};
		const sourceRemovalStarted = new Promise<void>((resolve) => {
			signalSourceRemovalStarted = resolve;
		});
		const sourceRemoval = context.adapter.transaction(async (transaction) => {
			await transaction.delete({
				model: "member",
				where: [
					{ field: "organizationId", value: sourceOrganization.data!.id },
					{ field: "userId", value: signedIn.user.id },
				],
			});
			signalSourceRemovalStarted();
			await sourceRemovalGate;
		});
		await sourceRemovalStarted;
		let publishedCookie: string | null = null;
		let transitionSettled = false;
		const switchAttempt = fixture.client.organization.setActive({
			organizationId: destinationOrganization.data!.id,
			fetchOptions: {
				headers: signedIn.headers,
				onResponse(response) {
					publishedCookie = response.response.headers.get("set-cookie");
				},
			},
		}).then((result) => {
			transitionSettled = true;
			return result;
		});
		await Promise.resolve();
		expect(transitionSettled).toBe(false);
		releaseSourceRemoval();
		await sourceRemoval;
		const switched = await switchAttempt;

		expect(switched.error?.status).toBe(403);
		expect(publishedCookie).toBeNull();
		await expect(
			context.internalAdapter.findSession(source.data!.session.token),
		).resolves.toBeNull();
	});

	it("rotates self-removal, leave, and active-organization deletion atomically", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const owner = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Lifecycle transition organization",
			slug: "lifecycle-transition-organization",
			fetchOptions: {
				headers: owner.headers,
				onSuccess: fixture.cookieSetter(owner.headers),
			},
		});
		const organizationId = created.data!.id;

		const addOwner = async (email: string, name: string) => {
			const headers = new Headers();
			const signedUp = await fixture.client.signUp.email(
				{ email, password: "managed-owner-password", name },
				{ onSuccess: fixture.cookieSetter(headers) },
			);
			const member = await fixture.auth.api.addMember({
				body: {
					organizationId,
					userId: signedUp.data!.user.id,
					role: "owner",
				},
			});
			await fixture.client.organization.setActive({
				organizationId,
				fetchOptions: { headers, onSuccess: fixture.cookieSetter(headers) },
			});
			return { headers, member: member! };
		};

		const removable = await addOwner(
			"managed-removable@example.com",
			"Managed Removable",
		);
		const removeSource = await fixture.client.getSession({
			fetchOptions: { headers: removable.headers },
		});
		const removed = await fixture.client.organization.removeMember({
			organizationId,
			memberIdOrEmail: removable.member.id,
			fetchOptions: {
				headers: removable.headers,
				onSuccess: fixture.cookieSetter(removable.headers),
			},
		});
		expect(removed.error).toBeNull();
		const removeSuccessor = await fixture.client.getSession({
			fetchOptions: { headers: removable.headers },
		});
		expect(removeSuccessor.data?.session.activeOrganizationId).toBeNull();

		const leaving = await addOwner(
			"managed-leaving@example.com",
			"Managed Leaving",
		);
		const leaveSource = await fixture.client.getSession({
			fetchOptions: { headers: leaving.headers },
		});
		const left = await fixture.client.organization.leave(
			{ organizationId },
			{
				headers: leaving.headers,
				onSuccess: fixture.cookieSetter(leaving.headers),
			},
		);
		expect(left.error).toBeNull();
		const leaveSuccessor = await fixture.client.getSession({
			fetchOptions: { headers: leaving.headers },
		});
		expect(leaveSuccessor.data?.session.activeOrganizationId).toBeNull();

		const deleteSource = await fixture.client.getSession({
			fetchOptions: { headers: owner.headers },
		});
		const deleted = await fixture.client.organization.delete({
			organizationId,
			fetchOptions: {
				headers: owner.headers,
				onSuccess: fixture.cookieSetter(owner.headers),
			},
		});
		expect(deleted.error).toBeNull();
		const deleteSuccessor = await fixture.client.getSession({
			fetchOptions: { headers: owner.headers },
		});
		expect(deleteSuccessor.data?.session.activeOrganizationId).toBeNull();

		const context = await fixture.auth.$context;
		for (const source of [removeSource, leaveSource, deleteSource]) {
			await expect(
				context.internalAdapter.findSession(source.data!.session.token),
			).resolves.toBeNull();
		}
		await expect(
			context.adapter.findOne({
				model: "organization",
				where: [{ field: "id", value: organizationId }],
			}),
		).resolves.toBeNull();
	});

	it("serializes concurrent final-owner departures", async () => {
		const fixture = await getTestInstance(managedOrganizationOptions(), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const first = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Concurrent owner organization",
			slug: "concurrent-owner-organization",
			fetchOptions: {
				headers: first.headers,
				onSuccess: fixture.cookieSetter(first.headers),
			},
		});
		const organizationId = created.data!.id;
		const secondHeaders = new Headers();
		const second = await fixture.client.signUp.email(
			{
				email: "concurrent-owner@example.com",
				password: "concurrent-owner-password",
				name: "Concurrent Owner",
			},
			{ onSuccess: fixture.cookieSetter(secondHeaders) },
		);
		await fixture.auth.api.addMember({
			body: { organizationId, userId: second.data!.user.id, role: "owner" },
		});
		await fixture.client.organization.setActive({
			organizationId,
			fetchOptions: {
				headers: secondHeaders,
				onSuccess: fixture.cookieSetter(secondHeaders),
			},
		});

		const departures = await Promise.all([
			fixture.client.organization.leave(
				{ organizationId },
				{
					headers: first.headers,
					onSuccess: fixture.cookieSetter(first.headers),
				},
			),
			fixture.client.organization.leave(
				{ organizationId },
				{
					headers: secondHeaders,
					onSuccess: fixture.cookieSetter(secondHeaders),
				},
			),
		]);
		expect(departures.filter((result) => result.error === null)).toHaveLength(1);
		const context = await fixture.auth.$context;
		const owners = (await context.adapter.findMany<{
			role: string;
		}>({
			model: "member",
			where: [{ field: "organizationId", value: organizationId }],
		})).filter((member) => member.role.split(",").includes("owner"));
		expect(owners).toHaveLength(1);
	});

	it("serializes creator demotion with a concurrent owner departure", async () => {
		let releaseDemotion: () => void = () => {};
		const demotionGate = new Promise<void>((resolve) => {
			releaseDemotion = resolve;
		});
		let signalDemotionEntered: () => void = () => {};
		const demotionEntered = new Promise<void>((resolve) => {
			signalDemotionEntered = resolve;
		});
		const fixture = await getTestInstance(managedOrganizationOptions(
			true,
			true,
			undefined,
			{
				beforeUpdateMemberRole: async () => {
					signalDemotionEntered();
					await demotionGate;
				},
			},
		), {
			clientOptions: { plugins: [organizationClient()] },
		});
		const first = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Concurrent role mutation organization",
			slug: "concurrent-role-mutation-organization",
			fetchOptions: {
				headers: first.headers,
				onSuccess: fixture.cookieSetter(first.headers),
			},
		});
		const organizationId = created.data!.id;
		const context = await fixture.auth.$context;
		const firstMember = await context.adapter.findOne<{
			id: string;
		}>({
			model: "member",
			where: [
				{ field: "organizationId", value: organizationId },
				{ field: "userId", value: first.user.id },
			],
		});
		if (!firstMember) throw new Error("First owner was not created");
		const secondHeaders = new Headers();
		const second = await fixture.client.signUp.email(
			{
				email: "concurrent-role-owner@example.com",
				password: "concurrent-role-owner-password",
				name: "Concurrent Role Owner",
			},
			{ onSuccess: fixture.cookieSetter(secondHeaders) },
		);
		await fixture.auth.api.addMember({
			body: { organizationId, userId: second.data!.user.id, role: "owner" },
		});
		await fixture.client.organization.setActive({
			organizationId,
			fetchOptions: {
				headers: secondHeaders,
				onSuccess: fixture.cookieSetter(secondHeaders),
			},
		});

		let demotionSettled = false;
		const demotionAttempt = fixture.client.organization.updateMemberRole({
			organizationId,
			memberId: firstMember.id,
			role: "member",
			fetchOptions: { headers: first.headers },
		}).then((result) => {
			demotionSettled = true;
			return result;
		});
		await demotionEntered;
		const departure = await fixture.client.organization.leave(
			{ organizationId },
			{ headers: secondHeaders },
		);
		expect(demotionSettled).toBe(false);
		releaseDemotion();
		const demotion = await demotionAttempt;
		expect([demotion, departure].filter((result) => result.error === null)).toHaveLength(
			1,
		);
		const owners = (await context.adapter.findMany<{ role: string }>({
			model: "member",
			where: [{ field: "organizationId", value: organizationId }],
		})).filter((member) => member.role.split(",").includes("owner"));
		expect(owners).toHaveLength(1);
	});
});

describe("unmanaged organization session transitions", () => {
	it("rejects every cookie-capable direct endpoint inside an external transaction before hooks, mutation, or cookies", async () => {
		const hooks = { beforeCreateOrganization: vi.fn(), afterCreateOrganization: vi.fn(), beforeDeleteOrganization: vi.fn(), afterDeleteOrganization: vi.fn(), beforeAcceptInvitation: vi.fn(), afterAcceptInvitation: vi.fn(), beforeRemoveMember: vi.fn(), afterRemoveMember: vi.fn() };
		const fixture = await getTestInstance({ plugins: [organization({ async sendInvitationEmail() {}, organizationHooks: hooks })] }, { clientOptions: { plugins: [organizationClient()] } });
		const owner = await fixture.signInWithTestUser();
		const org = await fixture.client.organization.create({ name: "Dispatch guard organization", slug: "dispatch-guard-organization", fetchOptions: { headers: owner.headers, onSuccess: fixture.cookieSetter(owner.headers) } });
		const context = await fixture.auth.$context;
		const ownerMember = await context.adapter.findOne<{ id: string }>({ model: "member", where: [{ field: "organizationId", value: org.data!.id }, { field: "userId", value: owner.user.id }] });
		if (!ownerMember) throw new Error("Expected owner membership");
		const inviteeHeaders = new Headers();
		const invitee = await fixture.client.signUp.email({ email: "dispatch-guard-invitee@example.com", password: "dispatch-guard-password", name: "Dispatch Guard Invitee" }, { onSuccess: fixture.cookieSetter(inviteeHeaders) });
		const invitation = await fixture.client.organization.inviteMember({ organizationId: org.data!.id, email: invitee.data!.user.email, role: "member", fetchOptions: { headers: owner.headers } });
		Object.values(hooks).forEach((hook) => hook.mockClear());
		const responses = await runWithTransaction(context.adapter, async () => [
			await fixture.auth.api.createOrganization({ body: { name: "Rejected nested create", slug: "rejected-nested-create" }, headers: owner.headers, asResponse: true }),
			await fixture.auth.api.deleteOrganization({ body: { organizationId: org.data!.id }, headers: owner.headers, asResponse: true }),
			await fixture.auth.api.getFullOrganization({ query: { organizationId: org.data!.id }, headers: owner.headers, asResponse: true }),
			await fixture.auth.api.setActiveOrganization({ body: { organizationId: null }, headers: owner.headers, asResponse: true }),
			await fixture.auth.api.acceptInvitation({ body: { invitationId: invitation.data!.id }, headers: inviteeHeaders, asResponse: true }),
			await fixture.auth.api.removeMember({ body: { organizationId: org.data!.id, memberIdOrEmail: ownerMember.id }, headers: owner.headers, asResponse: true }),
			await fixture.auth.api.leaveOrganization({ body: { organizationId: org.data!.id }, headers: owner.headers, asResponse: true }),
		]);
		for (const response of responses) {
			expect(response.status).toBe(500);
			expect(response.headers.get("set-cookie")).toBeNull();
			expect(await response.clone().json()).toMatchObject({ code: "ORGANIZATION_LIFECYCLE_NESTED_TRANSACTION" });
		}
		for (const hook of Object.values(hooks)) expect(hook).not.toHaveBeenCalled();
		await expect(context.adapter.findOne({ model: "organization", where: [{ field: "id", value: org.data!.id }] })).resolves.not.toBeNull();
		await expect(context.adapter.findOne({ model: "invitation", where: [{ field: "id", value: invitation.data!.id }] })).resolves.toMatchObject({ status: "pending" });
		await expect(context.adapter.findOne({ model: "member", where: [{ field: "organizationId", value: org.data!.id }, { field: "userId", value: invitee.data!.user.id }] })).resolves.toBeNull();
	});

	it("rejects organization additional fields that conflict with reserved serialization timestamps", () => {
		expect(() =>
			organization({
			schema: {
				organization: {
					additionalFields: {
						updatedAt: {
							type: "date",
							required: false,
							returned: true,
							input: true,
						},
					},
				},
			},
			} as never),
		).toThrow(
			'Organization plugin schema.organization physical column "updatedAt" is assigned to both core field "updatedAt" and additional field "updatedAt"',
		);
	});

	it("defers update-organization hooks until an external transaction commits", async () => {
		const afterUpdateOrganization = vi.fn();
		const fixture = await getTestInstance({ plugins: [organization({ organizationHooks: { afterUpdateOrganization } })] }, { clientOptions: { plugins: [organizationClient()] } });
		const owner = await fixture.signInWithTestUser();
		const org = await fixture.client.organization.create({ name: "Committed update hook organization", slug: "committed-update-hook-organization", fetchOptions: { headers: owner.headers } });
		const context = await fixture.auth.$context;
		await expect(runWithTransaction(context.adapter, async () => {
			await fixture.auth.api.updateOrganization({ body: { organizationId: org.data!.id, data: { name: "Rolled back update" } }, headers: owner.headers });
			expect(afterUpdateOrganization).not.toHaveBeenCalled();
			throw new Error("rollback update");
		})).rejects.toThrow("rollback update");
		expect(afterUpdateOrganization).not.toHaveBeenCalled();
		await expect(context.adapter.findOne<{ name: string }>({ model: "organization", where: [{ field: "id", value: org.data!.id }] })).resolves.toMatchObject({ name: "Committed update hook organization" });
		await runWithTransaction(context.adapter, async () => {
			await fixture.auth.api.updateOrganization({ body: { organizationId: org.data!.id, data: { name: "Committed update" } }, headers: owner.headers });
			expect(afterUpdateOrganization).not.toHaveBeenCalled();
		});
		expect(afterUpdateOrganization).toHaveBeenCalledTimes(1);
		expect(afterUpdateOrganization).toHaveBeenLastCalledWith(expect.objectContaining({ organization: expect.objectContaining({ name: "Committed update" }) }));
	});

	it("defers invitation-create hooks until an external transaction commits", async () => {
		const afterCreateInvitation = vi.fn();
		const fixture = await getTestInstance({ plugins: [organization({ async sendInvitationEmail() {}, organizationHooks: { afterCreateInvitation } })] }, { clientOptions: { plugins: [organizationClient()] } });
		const owner = await fixture.signInWithTestUser();
		const org = await fixture.client.organization.create({ name: "Committed invitation hook organization", slug: "committed-invitation-hook-organization", fetchOptions: { headers: owner.headers } });
		const context = await fixture.auth.$context;
		const email = "outer-invitation-hook@example.com";
		await expect(runWithTransaction(context.adapter, async () => {
			await fixture.auth.api.createInvitation({ body: { organizationId: org.data!.id, email, role: "member" }, headers: owner.headers });
			expect(afterCreateInvitation).not.toHaveBeenCalled();
			throw new Error("rollback invitation");
		})).rejects.toThrow("rollback invitation");
		expect(afterCreateInvitation).not.toHaveBeenCalled();
		await expect(context.adapter.findOne({ model: "invitation", where: [{ field: "email", value: email }] })).resolves.toBeNull();
		await runWithTransaction(context.adapter, async () => {
			await fixture.auth.api.createInvitation({ body: { organizationId: org.data!.id, email, role: "member" }, headers: owner.headers });
			expect(afterCreateInvitation).not.toHaveBeenCalled();
		});
		expect(afterCreateInvitation).toHaveBeenCalledTimes(1);
		expect(afterCreateInvitation).toHaveBeenLastCalledWith(expect.objectContaining({ invitation: expect.objectContaining({ email }) }));
	});

	it("does not let beforeAddMember redirect direct additions or an initial owner", async () => {
		const redirectedUserId = "before-add-member-redirected-user";
		const redirectedOrganizationId = "before-add-member-redirected-organization";
		const fixture = await getTestInstance(
			{
				plugins: [
					organization({
						organizationHooks: {
							beforeAddMember: async () => ({
								data: {
									userId: redirectedUserId,
									organizationId: redirectedOrganizationId,
								},
							}),
						},
					}),
				],
			},
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const owner = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Before add member ownership organization",
			slug: "before-add-member-ownership-organization",
			fetchOptions: {
				headers: owner.headers,
				onSuccess: fixture.cookieSetter(owner.headers),
			},
		});
		expect(created.error).toBeNull();
		const context = await fixture.auth.$context;
		const initialOwner = await context.adapter.findOne<{
			userId: string;
			organizationId: string;
			role: string;
		}>({
			model: "member",
			where: [{ field: "organizationId", value: created.data!.id }],
		});
		expect(initialOwner).toMatchObject({
			userId: owner.user.id,
			organizationId: created.data!.id,
		});
		expect(initialOwner?.role.split(",")).toContain("owner");

		const target = await fixture.client.signUp.email({
			email: "before-add-member-target@example.com",
			password: "before-add-member-password",
			name: "Before Add Member Target",
		});
		const added = await fixture.auth.api.addMember({
			body: {
				organizationId: created.data!.id,
				userId: target.data!.user.id,
				role: "member",
			},
		});
		expect(added).toMatchObject({
			userId: target.data!.user.id,
			organizationId: created.data!.id,
		});
		await expect(
			context.adapter.findOne({
				model: "member",
				where: [
					{ field: "organizationId", value: redirectedOrganizationId },
					{ field: "userId", value: redirectedUserId },
				],
			}),
		).resolves.toBeNull();
	});

	it("fails invitation acceptance before hooks or mutation without lifecycle transactions", async () => {
		const beforeAcceptInvitation = vi.fn();
		const fixture = await getTestInstance(
			{
				plugins: [
					organization({
						async sendInvitationEmail() {},
						organizationHooks: { beforeAcceptInvitation },
					}),
				],
			},
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const owner = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Transaction required invitation organization",
			slug: "transaction-required-invitation-organization",
			fetchOptions: { headers: owner.headers },
		});
		const invitee = {
			email: "transaction-required-invitee@example.com",
			password: "transaction-required-password",
			name: "Transaction Required Invitee",
		};
		const invitation = await fixture.client.organization.inviteMember({
			organizationId: created.data!.id,
			email: invitee.email,
			role: "member",
			fetchOptions: { headers: owner.headers },
		});
		const inviteeHeaders = new Headers();
		const signup = await fixture.client.signUp.email(invitee, {
			onSuccess: fixture.cookieSetter(inviteeHeaders),
		});
		const source = await fixture.client.getSession({
			fetchOptions: { headers: inviteeHeaders },
		});
		const context = await fixture.auth.$context;
		context.adapter.options!.adapterConfig.transaction = false;

		const accepted = await fixture.client.organization.acceptInvitation({
			invitationId: invitation.data!.id,
			fetchOptions: { headers: inviteeHeaders },
		});
		expect(accepted.error?.status).toBe(500);
		expect(accepted.error?.code).toBe(
			"ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED",
		);
		expect(beforeAcceptInvitation).not.toHaveBeenCalled();
		await expect(
			context.adapter.findOne({
				model: "invitation",
				where: [{ field: "id", value: invitation.data!.id }],
			}),
		).resolves.toMatchObject({ status: "pending" });
		await expect(
			context.adapter.findOne({
				model: "member",
				where: [
					{ field: "organizationId", value: created.data!.id },
					{ field: "userId", value: signup.data!.user.id },
				],
			}),
		).resolves.toBeNull();
		await expect(
			context.adapter.findOne({
				model: "session",
				where: [{ field: "id", value: source.data!.session.id }],
			}),
		).resolves.toMatchObject({ id: source.data!.session.id });
	});

	it("fails active lifecycle and owner departures without transactions with zero mutation", async () => {
		const beforeRemoveMember = vi.fn();
		const beforeDeleteOrganization = vi.fn();
		const fixture = await getTestInstance(
			{
				plugins: [
					organization({
						organizationHooks: {
							beforeRemoveMember,
							beforeDeleteOrganization,
						},
					}),
				],
			},
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const first = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Transaction required lifecycle organization",
			slug: "transaction-required-lifecycle-organization",
			fetchOptions: {
				headers: first.headers,
				onSuccess: fixture.cookieSetter(first.headers),
			},
		});
		const secondHeaders = new Headers();
		const second = await fixture.client.signUp.email(
			{
				email: "transaction-required-owner@example.com",
				password: "transaction-required-password",
				name: "Transaction Required Owner",
			},
			{ onSuccess: fixture.cookieSetter(secondHeaders) },
		);
		const secondMember = await fixture.auth.api.addMember({
			body: {
				organizationId: created.data!.id,
				userId: second.data!.user.id,
				role: "owner",
			},
		});
		await fixture.client.organization.setActive({
			organizationId: created.data!.id,
			fetchOptions: {
				headers: secondHeaders,
				onSuccess: fixture.cookieSetter(secondHeaders),
			},
		});
		const firstSource = await fixture.client.getSession({
			fetchOptions: { headers: first.headers },
		});
		const secondSource = await fixture.client.getSession({
			fetchOptions: { headers: secondHeaders },
		});
		const context = await fixture.auth.$context;
		context.adapter.options!.adapterConfig.transaction = false;

		const removed = await fixture.client.organization.removeMember({
			organizationId: created.data!.id,
			memberIdOrEmail: secondMember!.id,
			fetchOptions: { headers: secondHeaders },
		});
		const left = await fixture.client.organization.leave(
			{ organizationId: created.data!.id },
			{ headers: secondHeaders },
		);
		const deleted = await fixture.client.organization.delete({
			organizationId: created.data!.id,
			fetchOptions: { headers: secondHeaders },
		});
		const concurrentDepartures = await Promise.all([
			fixture.client.organization.leave(
				{ organizationId: created.data!.id },
				{ headers: first.headers },
			),
			fixture.client.organization.leave(
				{ organizationId: created.data!.id },
				{ headers: secondHeaders },
			),
		]);
		for (const result of [removed, left, deleted, ...concurrentDepartures]) {
			expect(result.error?.status).toBe(500);
			expect(result.error?.code).toBe(
				"ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED",
			);
		}
		expect(beforeRemoveMember).not.toHaveBeenCalled();
		expect(beforeDeleteOrganization).not.toHaveBeenCalled();
		await expect(
			context.adapter.findOne({
				model: "organization",
				where: [{ field: "id", value: created.data!.id }],
			}),
		).resolves.not.toBeNull();
		await expect(
			context.adapter.count({
				model: "member",
				where: [{ field: "organizationId", value: created.data!.id }],
			}),
		).resolves.toBe(2);
		for (const source of [firstSource, secondSource]) {
			await expect(
				context.adapter.findOne({
					model: "session",
					where: [{ field: "id", value: source.data!.session.id }],
				}),
			).resolves.toMatchObject({ id: source.data!.session.id });
		}
	});

	it("clears active team scope when switching organization scope", async () => {
		const fixture = await getTestInstance(
			{ plugins: [organization({ teams: { enabled: true } })] },
			{
				clientOptions: {
					plugins: [organizationClient({ teams: { enabled: true } })],
				},
			},
		);
		const { headers } = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Legacy team clearing organization",
			slug: "legacy-team-clearing-organization",
			fetchOptions: { headers, onSuccess: fixture.cookieSetter(headers) },
		});
		expect(created.error).toBeNull();
		const source = await fixture.client.getSession({ fetchOptions: { headers } });
		const context = await fixture.auth.$context;
		await context.internalAdapter.updateSession(source.data!.session.token, {
			activeTeamId: "stale-team-scope",
		});

		const cleared = await fixture.client.organization.setActive({
			organizationId: null,
			fetchOptions: { headers, onSuccess: fixture.cookieSetter(headers) },
		});
		expect(cleared.error).toBeNull();
		const successor = await fixture.client.getSession({ fetchOptions: { headers } });
		expect(successor.data?.session.activeOrganizationId).toBeFalsy();
		expect(successor.data?.session.activeTeamId).toBeFalsy();
		await context.internalAdapter.updateSession(successor.data!.session.token, {
			activeTeamId: "orphaned-team-scope",
		});
		const staleTeamCleared = await fixture.client.organization.setActive({
			organizationId: null,
			fetchOptions: { headers, onSuccess: fixture.cookieSetter(headers) },
		});
		expect(staleTeamCleared.error).toBeNull();
		const afterStaleTeamClear = await fixture.client.getSession({
			fetchOptions: { headers },
		});
		expect(afterStaleTeamClear.data?.session.activeOrganizationId).toBeFalsy();
		expect(afterStaleTeamClear.data?.session.activeTeamId).toBeFalsy();
		await context.internalAdapter.updateSession(
			afterStaleTeamClear.data!.session.token,
			{ activeTeamId: "omitted-body-stale-team-scope" },
		);
		const omittedBodyResponse = await fixture.auth.api.setActiveOrganization({
			body: {},
			headers,
			asResponse: true,
		});
		expect(omittedBodyResponse.status).toBe(200);
		const replacement = await context.adapter.findOne<{
			activeOrganizationId: string | null;
			activeTeamId: string | null;
			userId: string;
		}>({
			model: "session",
			where: [{ field: "userId", value: afterStaleTeamClear.data!.user.id }],
		});
		expect(replacement?.activeOrganizationId).toBeFalsy();
		expect(replacement?.activeTeamId).toBeFalsy();
	});

	it("does not report lost-membership revocation when durable deletion fails", async () => {
		const fixture = await getTestInstance(
			{ plugins: [organization()] },
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const { headers } = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Revocation failure organization",
			slug: "revocation-failure-organization",
			fetchOptions: { headers, onSuccess: fixture.cookieSetter(headers) },
		});
		expect(created.error).toBeNull();
		const source = await fixture.client.getSession({ fetchOptions: { headers } });
		const sourceCredential = Object.fromEntries(
			parseCookies(headers.get("cookie") || ""),
		)["clearance.session_token"]?.split(".")[0];
		expect(sourceCredential).toEqual(expect.any(String));
		const context = await fixture.auth.$context;
		await context.adapter.delete({
			model: "member",
			where: [
				{ field: "organizationId", value: created.data!.id },
				{ field: "userId", value: source.data!.user.id },
			],
		});
		const deletionFailure = new Error("durable session revocation failed");
		const deleteSession = vi
			.spyOn(context.internalAdapter, "deleteSession")
			.mockRejectedValue(deletionFailure);
		let setCookie = "";
		try {
			const rejected = await fixture.client.organization.setActive({
				organizationId: "unavailable-organization",
				fetchOptions: {
					headers,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			});
			expect(rejected.error?.status).toBe(500);
			expect(setCookie).not.toMatch(/clearance\.session_token=.*Max-Age=0/i);
			expect(deleteSession).toHaveBeenCalledWith(sourceCredential);
		} finally {
			deleteSession.mockRestore();
		}
	});

	it("clears the browser session before surfacing a committed stale-source revocation hook failure", async () => {
		const fixture = await getTestInstance(
			{ plugins: [organization()] },
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const { headers } = await fixture.signInWithTestUser();
		const created = await fixture.client.organization.create({
			name: "Committed revocation hook failure organization",
			slug: "committed-revocation-hook-failure-organization",
			fetchOptions: { headers, onSuccess: fixture.cookieSetter(headers) },
		});
		expect(created.error).toBeNull();
		const source = await fixture.client.getSession({ fetchOptions: { headers } });
		const context = await fixture.auth.$context;
		await context.adapter.delete({
			model: "member",
			where: [
				{ field: "organizationId", value: created.data!.id },
				{ field: "userId", value: source.data!.user.id },
			],
		});
		const originalDeleteSession = context.internalAdapter.deleteSession.bind(
			context.internalAdapter,
		);
		const deleteSession = vi
			.spyOn(context.internalAdapter, "deleteSession")
			.mockImplementation(async (token) => {
			await originalDeleteSession(token);
			await queueAfterTransactionHook(async () => {
				throw new Error("committed revocation hook failure");
			}, context.adapter);
			});
		let setCookie = "";
		try {
			const rejected = await fixture.client.organization.setActive({
				organizationId: "unavailable-organization",
				fetchOptions: {
					headers,
					onResponse(response) {
						setCookie = response.response.headers.get("set-cookie") || "";
					},
				},
			});
			expect(rejected.error?.status).toBe(500);
			expect(setCookie).toMatch(/clearance\.session_token=.*Max-Age=0/i);
			await expect(
				context.internalAdapter.findSession(source.data!.session.token),
			).resolves.toBeNull();
		} finally {
			deleteSession.mockRestore();
		}
	});

	it("retains the legacy in-place session identity", async () => {
		const fixture = await getTestInstance(
			{ plugins: [organization()] },
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const { headers } = await fixture.signInWithTestUser();
		const source = await fixture.client.getSession({ fetchOptions: { headers } });
		const created = await fixture.client.organization.create({
			name: "Legacy organization",
			slug: "legacy-transition-organization",
			fetchOptions: { headers, onSuccess: fixture.cookieSetter(headers) },
		});
		expect(created.error).toBeNull();
		const successor = await fixture.client.getSession({ fetchOptions: { headers } });
		expect(successor.data?.session.id).toBe(source.data?.session.id);
		expect(successor.data?.session.activeOrganizationId).toBe(created.data?.id);
	});
});
