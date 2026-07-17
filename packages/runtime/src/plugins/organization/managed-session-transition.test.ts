import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import { describe, expect, it, vi } from "vitest";
import { parseCookies } from "../../cookies";
import { attachInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { getTestInstance } from "../../test-utils/test-instance";
import { organizationClient } from "./client";
import { organization } from "./organization";

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
) {
	const options = {
		plugins: [
			organization({
				async sendInvitationEmail() {},
				...(membershipLimit === undefined ? {} : { membershipLimit }),
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
		const fixture = await getTestInstance(managedOrganizationOptions(), {
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

		const [demotion, departure] = await Promise.all([
			fixture.client.organization.updateMemberRole({
				organizationId,
				memberId: firstMember.id,
				role: "member",
				fetchOptions: { headers: first.headers },
			}),
			fixture.client.organization.leave(
				{ organizationId },
				{ headers: secondHeaders },
			),
		]);
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
