import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import { describe, expect, it, vi } from "vitest";
import type { AuthQueryAtom } from "../../../client";
import { createAuthClient } from "../../../client";
import { parseSetCookieHeader } from "../../../cookies";
import { attachInternalAuthenticationPolicy } from "../../../internal/authentication-policy";
import { getTestInstance } from "../../../test-utils/test-instance";
import * as cookies from "../../../cookies";
import { organizationClient } from "../client";
import { ORGANIZATION_ERROR_CODES } from "../error-codes";
import { organization } from "../organization";
import type { OrganizationOptions } from "../types";

const managedIdentity = {
	projectId: "crud-members-project",
	environmentId: "crud-members-environment",
} satisfies RuntimeAuthenticationPolicyIdentity;

const managedPolicy = {
	passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	factorLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	minimumAssurance: "single_factor",
	allowedFactors: { totp: true, passkey: true },
	trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
	assuranceMaxAgeSeconds: 300,
} satisfies RuntimeAuthenticationPolicy;

function managedOrganizationOptions(
	organizationHooks?: OrganizationOptions["organizationHooks"],
) {
	const options = {
		plugins: [organization({ organizationHooks })],
	} satisfies ClearanceOptions;
	attachInternalAuthenticationPolicy(options, {
		identity: managedIdentity,
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
									{ field: "organizationId", value: input.organizationId },
								],
							})
						: null;
				return {
					scope: managedIdentity,
					subjectId: input.subjectId,
					revision: "1",
					environment: managedPolicy,
					organizationMembership:
						input.organizationId && membership
							? {
									subjectId: input.subjectId,
									organizationId: input.organizationId,
								}
							: null,
					organizationOverride: null,
					effective: managedPolicy,
				};
			},
		},
	});
	return options;
}

describe("listMembers", async () => {
	const { auth, signInWithTestUser, cookieSetter } = await getTestInstance({
		plugins: [organization()],
	});
	const ctx = await auth.$context;
	const { headers } = await signInWithTestUser();
	const client = createAuthClient({
		plugins: [organizationClient()],
		baseURL: "http://localhost:3000/api/auth",
		fetchOptions: {
			customFetchImpl: async (url, init) => {
				return auth.handler(new Request(url, init));
			},
		},
	});
	const org = await client.organization.create({
		name: "test",
		slug: "test",
		metadata: {
			test: "test",
		},
		fetchOptions: {
			headers,
		},
	});
	const secondOrg = await client.organization.create({
		name: "test-second",
		slug: "test-second",
		metadata: {
			test: "second-org",
		},
		fetchOptions: {
			headers,
		},
	});

	for (let i = 0; i < 10; i++) {
		const user = await ctx.adapter.create({
			model: "user",
			data: {
				email: `test${i}@test.com`,
				name: `test${i}`,
			},
		});
		await auth.api.addMember({
			body: {
				organizationId: org.data?.id as string,
				userId: user.id,
				role: "member",
			},
		});
	}
	it("should return all members", async () => {
		await client.organization.setActive({
			organizationId: org.data?.id as string,
			fetchOptions: {
				headers,
			},
		});
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
		});
		expect(members.data?.members.length).toBe(11);
		expect(members.data?.total).toBe(11);
	});

	it("should return all members by organization slug", async () => {
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				organizationSlug: "test-second",
			},
		});
		expect(members.data?.members.length).toBe(1);
		expect(members.data?.total).toBe(1);
	});

	it("should limit the number of members", async () => {
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				limit: 5,
			},
		});
		expect(members.data?.members.length).toBe(5);
		expect(members.data?.total).toBe(11);
	});

	it("should offset the members", async () => {
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				offset: 5,
			},
		});
		expect(members.data?.members.length).toBe(6);
		expect(members.data?.total).toBe(11);
	});

	it("should filter the members", async () => {
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				filterField: "createdAt",
				filterOperator: "gt",
				filterValue: new Date(
					Date.now() - 1000 * 60 * 60 * 24 * 30,
				).toISOString(),
			},
		});
		expect(members.data?.members.length).toBe(11);
		expect(members.data?.total).toBe(11);
	});

	it("should filter the members verifying the operator functionality", async () => {
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				filterField: "role",
				filterOperator: "ne",
				filterValue: "owner",
			},
		});
		expect(members.data?.members.length).toBe(10);
		expect(members.data?.total).toBe(10);
	});

	it("should filter the members with 'in' operator", async () => {
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				filterField: "role",
				filterOperator: "in",
				filterValue: ["member", "owner"],
			},
		});
		expect(members.data?.members.length).toBe(11);
		expect(members.data?.total).toBe(11);
	});

	it("should filter the members with 'not_in' operator", async () => {
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				filterField: "role",
				filterOperator: "not_in",
				filterValue: ["owner"],
			},
		});
		expect(members.data?.members.length).toBe(10);
		expect(members.data?.total).toBe(10);
	});

	it("should filter the members with 'starts_with' operator", async () => {
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				filterField: "role",
				filterOperator: "starts_with",
				filterValue: "mem",
			},
		});
		expect(members.data?.members.length).toBe(10);
		expect(members.data?.total).toBe(10);
	});

	it("should sort the members", async () => {
		const defaultMembers = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
		});
		const firstMember = defaultMembers.data?.members[0];
		if (!firstMember) {
			throw new Error("No first member found");
		}
		const secondMember = defaultMembers.data?.members[1];
		if (!secondMember) {
			throw new Error("No second member found");
		}
		await ctx.adapter.update({
			model: "member",
			where: [{ field: "id", value: secondMember.id }],
			update: {
				// update the second member to be the oldest
				createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30),
			},
		});
		const lastMember =
			defaultMembers.data?.members[defaultMembers.data?.members.length - 1];
		if (!lastMember) {
			throw new Error("No last member found");
		}
		const oneBeforeLastMember =
			defaultMembers.data?.members[defaultMembers.data?.members.length - 2];
		if (!oneBeforeLastMember) {
			throw new Error("No one before last member found");
		}
		await ctx.adapter.update({
			model: "member",
			where: [{ field: "id", value: oneBeforeLastMember.id }],
			update: {
				// update the one before last member to be the newest
				createdAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
			},
		});
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				sortBy: "createdAt",
				sortDirection: "asc",
			},
		});
		expect(members.data?.members[0]!.id).not.toBe(firstMember.id);
		expect(
			members.data?.members[members.data?.members.length - 1]!.id,
		).not.toBe(lastMember.id);
		expect(members.data?.members[0]!.id).toBe(secondMember.id);
		expect(members.data?.members[members.data?.members.length - 1]!.id).toBe(
			oneBeforeLastMember.id,
		);
	});

	it("should list members by organization id", async () => {
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers,
			},
			query: {
				organizationId: secondOrg.data?.id as string,
			},
		});
		expect(members.data?.members.length).toBe(1);
		expect(members.data?.total).toBe(1);
	});

	it("should not list members if not a member", async () => {
		const newHeaders = new Headers();
		await client.signUp.email({
			email: "test21@test.com",
			name: "test22",
			password: "password",
			fetchOptions: {
				onSuccess: cookieSetter(newHeaders),
			},
		});
		const members = await client.organization.listMembers({
			fetchOptions: {
				headers: newHeaders,
			},
			query: {
				organizationId: org.data?.id as string,
			},
		});
		expect(members.error).toBeTruthy();
		expect(members.error?.message).toBe(
			ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION
				.message,
		);
	});
});

describe("updateMemberRole", async () => {
	const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
		plugins: [organization()],
	});

	it("should update the member role", async () => {
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({
			plugins: [organizationClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl,
			},
		});

		const org = await client.organization.create({
			name: "test",
			slug: "test",
			metadata: {
				test: "test",
			},
			fetchOptions: {
				headers,
			},
		});

		const newUser = await auth.api.signUpEmail({
			body: {
				email: "test2@test.com",
				name: "test",
				password: "password",
			},
		});

		const member = await auth.api.addMember({
			body: {
				organizationId: org.data?.id as string,
				userId: newUser.user.id,
				role: "member",
			},
		});
		const updatedMember = await client.organization.updateMemberRole(
			{
				organizationId: org.data?.id as string,
				memberId: member?.id as string,
				role: "admin",
			},
			{
				headers,
			},
		);
		expect(updatedMember.data?.role).toBe("admin");
	});

	it("should not update the member role if the member updating is not a member	", async () => {
		const { headers, user } = await signInWithTestUser();
		const client = createAuthClient({
			plugins: [organizationClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl,
			},
		});

		await client.organization.create({
			name: "test",
			slug: "test",
			metadata: {
				test: "test",
			},
			fetchOptions: {
				headers,
			},
		});

		const newUser = await auth.api.signUpEmail({
			body: {
				email: "test3@test.com",
				name: "test",
				password: "password",
			},
		});
		const newOrg = await client.organization.create(
			{
				name: "test2",
				slug: "test2",
				metadata: {
					test: "test",
				},
			},
			{
				headers: new Headers({
					authorization: `Bearer ${newUser.token}`,
				}),
			},
		);
		await auth.api.addMember({
			body: {
				organizationId: newOrg.data?.id as string,
				userId: user.id,
				role: "admin",
			},
		});
		const updatedMember = await client.organization.updateMemberRole(
			{
				organizationId: newOrg.data?.id as string,
				memberId: newOrg.data?.members[0]?.id as string,
				role: "admin",
			},
			{
				headers,
			},
		);
		expect(updatedMember.error).toBeTruthy();
		expect(updatedMember.error?.message).toBe(
			ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER
				.message,
		);
	});

	it("should not allow a comma-delimited role string", async () => {
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({
			plugins: [organizationClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl,
			},
		});

		const org = await client.organization.create({
			name: "escalation",
			slug: "escalation",
			fetchOptions: {
				headers,
			},
		});

		const adminUser = await auth.api.signUpEmail({
			body: {
				email: "admin-escalation@test.com",
				name: "admin",
				password: "password",
			},
		});

		const adminMember = await auth.api.addMember({
			body: {
				organizationId: org.data?.id as string,
				userId: adminUser.user.id,
				role: "admin",
			},
		});

		const adminHeaders = new Headers({
			authorization: `Bearer ${adminUser.token}`,
		});

		const escalated = await client.organization.updateMemberRole(
			{
				organizationId: org.data?.id as string,
				memberId: adminMember?.id as string,
				role: "admin,owner" as "admin",
			},
			{
				headers: adminHeaders,
			},
		);

		expect(escalated.error?.status).toBe(403);
		expect(escalated.data).toBeNull();

		const ctx = await auth.$context;
		const persisted = await ctx.adapter.findOne<{ role: string }>({
			model: "member",
			where: [{ field: "id", value: adminMember?.id as string }],
		});
		expect(persisted?.role).toBe("admin");
	});

	it("should reject updating a member to an unknown role", async () => {
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({
			plugins: [organizationClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl,
			},
		});

		const org = await client.organization.create({
			name: "unknown-role",
			slug: "unknown-role",
			fetchOptions: {
				headers,
			},
		});

		const newUser = await auth.api.signUpEmail({
			body: {
				email: "unknown-role@test.com",
				name: "test",
				password: "password",
			},
		});

		const member = await auth.api.addMember({
			body: {
				organizationId: org.data?.id as string,
				userId: newUser.user.id,
				role: "member",
			},
		});

		const updated = await client.organization.updateMemberRole(
			{
				organizationId: org.data?.id as string,
				memberId: member?.id as string,
				role: "superadmin" as "admin",
			},
			{
				headers,
			},
		);

		expect(updated.error?.status).toBe(400);
		expect(updated.error?.message).toContain(
			ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND,
		);
	});

	it("should reject updating a member to an empty role list", async () => {
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({
			plugins: [organizationClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl,
			},
		});

		const org = await client.organization.create({
			name: "empty-role",
			slug: "empty-role",
			fetchOptions: {
				headers,
			},
		});

		const newUser = await auth.api.signUpEmail({
			body: {
				email: "empty-role@test.com",
				name: "test",
				password: "password",
			},
		});

		const member = await auth.api.addMember({
			body: {
				organizationId: org.data?.id as string,
				userId: newUser.user.id,
				role: "member",
			},
		});

		for (const role of [[], ","] as ("admin" | "admin"[])[]) {
			const updated = await client.organization.updateMemberRole(
				{
					organizationId: org.data?.id as string,
					memberId: member?.id as string,
					role,
				},
				{
					headers,
				},
			);
			expect(updated.error?.status).toBe(400);
		}
	});

	it("revalidates hook-produced owner roles before preserving the last owner", async () => {
		const { auth: hookedAuth, signInWithTestUser: signIn } =
			await getTestInstance({
				plugins: [
					organization({
						organizationHooks: {
							beforeUpdateMemberRole: async () => ({
								data: { role: " member " },
							}),
						},
					}),
				],
			});
		const { headers } = await signIn();
		const hookedClient = createAuthClient({
			plugins: [organizationClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl: async (url, init) =>
					hookedAuth.handler(new Request(url, init)),
			},
		});
		const org = await hookedClient.organization.create({
			name: "hook-owner",
			slug: `hook-owner-${crypto.randomUUID()}`,
			fetchOptions: { headers },
		});
		const owner = await hookedAuth.api.getActiveMember({ headers });
		const result = await hookedClient.organization.updateMemberRole(
			{
				organizationId: org.data?.id,
				memberId: owner?.id as string,
				role: "admin",
			},
			{ headers },
		);
		expect(result.error?.status).toBe(400);
		const persisted = await (await hookedAuth.$context).adapter.findOne<{ role: string }>({
			model: "member",
			where: [{ field: "id", value: owner?.id as string }],
		});
			expect(persisted?.role).toBe("owner");
		});

	it("rejects an update when the target changes during beforeUpdateMemberRole", async () => {
		let release!: () => void;
		let entered!: () => void;
		const barrier = new Promise<void>((resolve) => { release = resolve; });
		const enteredBarrier = new Promise<void>((resolve) => { entered = resolve; });
		const afterUpdateMemberRole = vi.fn();
		const { auth: hookedAuth, signInWithTestUser: signIn, customFetchImpl: fetch } = await getTestInstance({
			plugins: [organization({ organizationHooks: { beforeUpdateMemberRole: async () => { entered(); await barrier; }, afterUpdateMemberRole } })],
		});
		const { headers } = await signIn();
		const hookedClient = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl: fetch } });
		const org = await hookedClient.organization.create({ name: "update-barrier", slug: `update-barrier-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const target = await hookedAuth.api.signUpEmail({ body: { email: `update-barrier-${crypto.randomUUID()}@test.com`, name: "target", password: "password" } });
		const membership = await hookedAuth.api.addMember({ body: { organizationId: org.data?.id as string, userId: target.user.id, role: "member" } });
		const update = hookedClient.organization.updateMemberRole({ organizationId: org.data?.id, memberId: membership?.id as string, role: "member" }, { headers });
		await enteredBarrier;
		const context = await hookedAuth.$context;
		await context.adapter.update({ model: "member", where: [{ field: "id", value: membership?.id as string }], update: { role: "admin" } });
		release();
		const result = await update;
		expect(result.error?.status).toBe(400);
		expect((await context.adapter.findOne<{ role: string }>({ model: "member", where: [{ field: "id", value: membership?.id as string }] }))?.role).toBe("admin");
		expect(afterUpdateMemberRole).not.toHaveBeenCalled();
	});

	it("uses the locked live target role as previousRole when it changes before transaction entry", async () => {
		const afterUpdateMemberRole = vi.fn();
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			plugins: [organization({ organizationHooks: { afterUpdateMemberRole } })],
		});
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl } });
		const org = await client.organization.create({ name: "locked-update-role", slug: `locked-update-role-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const target = await auth.api.signUpEmail({ body: { email: `locked-update-role-${crypto.randomUUID()}@test.com`, name: "target", password: "password" } });
		const membership = await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: target.user.id, role: "member" } });
		const context = await auth.$context;
		let release!: () => void;
		let entered!: () => void;
		const barrier = new Promise<void>((resolve) => { release = resolve; });
		const enteredBarrier = new Promise<void>((resolve) => { entered = resolve; });
		const transaction = context.adapter.transaction.bind(context.adapter);
		const transactionSpy = vi.spyOn(context.adapter, "transaction").mockImplementation(async (callback) => {
			entered();
			await barrier;
			return transaction(callback);
		});
		const update = client.organization.updateMemberRole({ organizationId: org.data?.id, memberId: membership?.id as string, role: "member" }, { headers });
		await enteredBarrier;
		await context.adapter.update({ model: "member", where: [{ field: "id", value: membership?.id as string }], update: { role: "admin" } });
		release();
		const result = await update;
		transactionSpy.mockRestore();
		expect(result.error).toBeNull();
		expect(afterUpdateMemberRole).toHaveBeenCalledTimes(1);
		expect(afterUpdateMemberRole.mock.calls[0]?.[0]).toMatchObject({ previousRole: "admin", member: { role: "member" } });
		expect((await context.adapter.findOne<{ role: string }>({ model: "member", where: [{ field: "id", value: membership?.id as string }] }))?.role).toBe("member");
	});
});

describe("member removal session authority", () => {
	it("rejects removal when the target changes during beforeRemoveMember", async () => {
		let release!: () => void;
		let entered!: () => void;
		const barrier = new Promise<void>((resolve) => { release = resolve; });
		const enteredBarrier = new Promise<void>((resolve) => { entered = resolve; });
		const afterRemoveMember = vi.fn();
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			plugins: [organization({ organizationHooks: { beforeRemoveMember: async () => { entered(); await barrier; }, afterRemoveMember } })],
		});
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl } });
		const org = await client.organization.create({ name: "remove-barrier", slug: `remove-barrier-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const target = await auth.api.signUpEmail({ body: { email: `remove-barrier-${crypto.randomUUID()}@test.com`, name: "target", password: "password" } });
		const membership = await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: target.user.id, role: "member" } });
		const remove = auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: membership?.id as string }, headers, asResponse: true });
		await enteredBarrier;
		const context = await auth.$context;
		await context.adapter.update({ model: "member", where: [{ field: "id", value: membership?.id as string }], update: { role: "admin" } });
		release();
		const response = await remove;
		expect(response.status).toBe(400);
		expect((await context.adapter.findOne<{ role: string }>({ model: "member", where: [{ field: "id", value: membership?.id as string }] }))?.role).toBe("admin");
		expect(afterRemoveMember).not.toHaveBeenCalled();
	});

	it("uses the locked live target role when it changes before transaction entry", async () => {
		const afterRemoveMember = vi.fn();
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			plugins: [organization({ organizationHooks: { afterRemoveMember } })],
		});
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl } });
		const org = await client.organization.create({ name: "locked-remove-role", slug: `locked-remove-role-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const target = await auth.api.signUpEmail({ body: { email: `locked-remove-role-${crypto.randomUUID()}@test.com`, name: "target", password: "password" } });
		const membership = await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: target.user.id, role: "member" } });
		const context = await auth.$context;
		let release!: () => void;
		let entered!: () => void;
		const barrier = new Promise<void>((resolve) => { release = resolve; });
		const enteredBarrier = new Promise<void>((resolve) => { entered = resolve; });
		const transaction = context.adapter.transaction.bind(context.adapter);
		const transactionSpy = vi.spyOn(context.adapter, "transaction").mockImplementation(async (callback) => {
			entered();
			await barrier;
			return transaction(callback);
		});
		const removal = auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: membership?.id as string }, headers });
		await enteredBarrier;
		await context.adapter.update({ model: "member", where: [{ field: "id", value: membership?.id as string }], update: { role: "admin" } });
		release();
		await removal;
		transactionSpy.mockRestore();
		expect(afterRemoveMember).toHaveBeenCalledTimes(1);
		expect(afterRemoveMember.mock.calls[0]?.[0]).toMatchObject({ member: { id: membership?.id, role: "admin" } });
		expect(await context.adapter.findOne({ model: "member", where: [{ field: "id", value: membership?.id as string }] })).toBeNull();
	});

	it("revokes every database session scoped to the removed organization by id", async () => {
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			plugins: [organization()],
		});
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({
			plugins: [organizationClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: { customFetchImpl },
		});
		const orgResponse = await client.organization.create({
			name: "session-authority",
			slug: `session-authority-${crypto.randomUUID()}`,
			fetchOptions: { headers },
		});
		const target = await auth.api.signUpEmail({
			body: {
				email: `session-authority-${crypto.randomUUID()}@test.com`,
				name: "target",
				password: "password",
			},
		});
		const membership = await auth.api.addMember({
			body: {
				organizationId: orgResponse.data?.id as string,
				userId: target.user.id,
				role: "member",
			},
		});
		const context = await auth.$context;
		const scopedOne = await context.internalAdapter.createSession(target.user.id, false, {
			activeOrganizationId: orgResponse.data?.id,
		});
		const scopedTwo = await context.internalAdapter.createSession(target.user.id, false, {
			activeOrganizationId: orgResponse.data?.id,
		});
		const unrelated = await context.internalAdapter.createSession(target.user.id, false, {
			activeOrganizationId: "another-organization",
		});

		await auth.api.removeMember({
			body: {
				organizationId: orgResponse.data?.id,
				memberIdOrEmail: membership?.id as string,
			},
			headers,
		});

		expect(await context.internalAdapter.findSession(scopedOne.token)).toBeNull();
		expect(await context.internalAdapter.findSession(scopedTwo.token)).toBeNull();
		expect(await context.internalAdapter.findSession(unrelated.token)).not.toBeNull();
	});

	it("revokes secondary-only scoped sessions before deletion and preserves unrelated sessions", async () => {
		const secondary = new Map<string, string>();
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			session: { storeSessionInDatabase: false },
			secondaryStorage: {
				get: (key) => secondary.get(key) ?? null,
				set: (key, value) => void secondary.set(key, value),
				delete: (key) => void secondary.delete(key),
			},
			plugins: [organization()],
		});
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({
			plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth",
			fetchOptions: { customFetchImpl },
		});
		const org = await client.organization.create({ name: "secondary-session", slug: `secondary-session-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const target = await auth.api.signUpEmail({ body: { email: `secondary-${crypto.randomUUID()}@test.com`, name: "target", password: "password" } });
		const membership = await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: target.user.id, role: "member" } });
		const context = await auth.$context;
		const scoped = await context.internalAdapter.createSession(target.user.id, false, { activeOrganizationId: org.data?.id });
		const unrelated = await context.internalAdapter.createSession(target.user.id, false, { activeOrganizationId: "other-org" });
		const deleted = vi.spyOn(context.internalAdapter, "deleteSessionById");
		await auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: membership?.id as string }, headers });
		expect(deleted).toHaveBeenCalledWith(scoped.id);
		expect(deleted).not.toHaveBeenCalledWith(unrelated.id);
		expect(await context.internalAdapter.findSession(unrelated.token)).not.toBeNull();
	});

	it("aborts secondary-only removal when durable session deletion fails", async () => {
		const secondary = new Map<string, string>();
		const afterRemoveMember = vi.fn();
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			session: { storeSessionInDatabase: false },
			secondaryStorage: { get: (key) => secondary.get(key) ?? null, set: (key, value) => void secondary.set(key, value), delete: (key) => void secondary.delete(key) },
			plugins: [organization({ organizationHooks: { afterRemoveMember } })],
		});
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl } });
		const org = await client.organization.create({ name: "secondary-failure", slug: `secondary-failure-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const target = await auth.api.signUpEmail({ body: { email: `secondary-failure-${crypto.randomUUID()}@test.com`, name: "target", password: "password" } });
		const membership = await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: target.user.id, role: "member" } });
		const context = await auth.$context;
		await context.internalAdapter.createSession(target.user.id, false, { activeOrganizationId: org.data?.id });
		vi.spyOn(context.internalAdapter, "deleteSessionById").mockRejectedValueOnce(new Error("secondary unavailable"));
		await expect(auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: membership?.id as string }, headers })).rejects.toThrow("secondary unavailable");
		expect(await context.adapter.findOne({ model: "member", where: [{ field: "id", value: membership?.id as string }] })).not.toBeNull();
		expect(afterRemoveMember).not.toHaveBeenCalled();
	});

	it("does not revoke secondary sessions when locked sole-owner validation rejects removal", async () => {
		const secondary = new Map<string, string>();
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			session: { storeSessionInDatabase: false },
			secondaryStorage: { get: (key) => secondary.get(key) ?? null, set: (key, value) => void secondary.set(key, value), delete: (key) => void secondary.delete(key) },
			plugins: [organization()],
		});
		const { headers, user } = await signInWithTestUser();
		const client = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl } });
		const org = await client.organization.create({ name: "secondary-rejected", slug: `secondary-rejected-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const context = await auth.$context;
		const ownerMember = await context.adapter.findOne<{ id: string }>({ model: "member", where: [{ field: "organizationId", value: org.data?.id as string }, { field: "userId", value: user.id }] });
		if (!ownerMember) throw new Error("Owner membership missing");
		const scoped = await context.internalAdapter.createSession(user.id, false, { activeOrganizationId: org.data?.id });
		const deleted = vi.spyOn(context.internalAdapter, "deleteSessionById");
		await expect(auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: ownerMember.id }, headers })).rejects.toThrow(ORGANIZATION_ERROR_CODES.YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER.message);
		expect(deleted).not.toHaveBeenCalledWith(scoped.id);
		expect(await context.internalAdapter.findSession(scoped.token)).not.toBeNull();
		expect(await context.adapter.findOne({ model: "member", where: [{ field: "id", value: ownerMember.id }] })).not.toBeNull();
	});

	it("runs afterRemoveMember once after the member deletion commits", async () => {
		const afterRemoveMember = vi.fn();
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			plugins: [organization({ organizationHooks: { afterRemoveMember } })],
		});
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl } });
		const org = await client.organization.create({ name: "after-remove", slug: `after-remove-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const target = await auth.api.signUpEmail({ body: { email: `after-remove-${crypto.randomUUID()}@test.com`, name: "target", password: "password" } });
		const membership = await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: target.user.id, role: "member" } });
		await auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: membership?.id as string }, headers });
		expect(afterRemoveMember).toHaveBeenCalledTimes(1);
		expect(await (await auth.$context).adapter.findOne({ model: "member", where: [{ field: "id", value: membership?.id as string }] })).toBeNull();
	});

	it("keeps committed self-removal and its after hook when cookie publication fails", async () => {
		const afterRemoveMember = vi.fn();
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			plugins: [organization({ organizationHooks: { afterRemoveMember } })],
		});
		const { headers, user } = await signInWithTestUser();
		const client = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl } });
		const org = await client.organization.create({ name: "cookie-failure", slug: `cookie-failure-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const secondOwner = await auth.api.signUpEmail({ body: { email: `second-owner-${crypto.randomUUID()}@test.com`, name: "owner", password: "password" } });
		await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: secondOwner.user.id, role: "owner" } });
		const context = await auth.$context;
		const ownerMember = await context.adapter.findOne<{ id: string }>({ model: "member", where: [{ field: "organizationId", value: org.data?.id as string }, { field: "userId", value: user.id }] });
		if (!ownerMember) throw new Error("Owner membership missing");
		vi.spyOn(cookies, "setSessionCookie").mockRejectedValueOnce(new Error("cookie publication failed"));
		await expect(auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: ownerMember.id }, headers })).rejects.toThrow("cookie publication failed");
		expect(await context.adapter.findOne({ model: "member", where: [{ field: "id", value: ownerMember.id }] })).toBeNull();
		expect(afterRemoveMember).toHaveBeenCalledTimes(1);
	});

	it("publishes the committed successor then returns AFTER_TRANSACTION_HOOK_FAILED for active self-removal", async () => {
		const afterRemoveMember = vi.fn(async () => {
			throw new Error("after remove failed");
		});
		const { auth, client, cookieSetter, signInWithTestUser } =
			await getTestInstance(
				managedOrganizationOptions({ afterRemoveMember }),
				{ clientOptions: { plugins: [organizationClient()] } },
			);
		const { headers, user } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "after-hook-failure",
			slug: `after-hook-failure-${crypto.randomUUID()}`,
			fetchOptions: { headers, onSuccess: cookieSetter(headers) },
		});
		expect(org.error).toBeNull();
		const source = await auth.api.getSession({ headers });
		if (!source) throw new Error("Managed source session missing");
		const secondOwner = await auth.api.signUpEmail({ body: { email: `after-hook-owner-${crypto.randomUUID()}@test.com`, name: "owner", password: "password" } });
		await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: secondOwner.user.id, role: "owner" } });
		const context = await auth.$context;
		const ownerMember = await context.adapter.findOne<{ id: string }>({ model: "member", where: [{ field: "organizationId", value: org.data?.id as string }, { field: "userId", value: user.id }] });
		if (!ownerMember) throw new Error("Owner membership missing");
		const response = await auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: ownerMember.id }, headers, asResponse: true });
		expect(response.status).toBe(500);
		const publishedCookie = response.headers.get("set-cookie") || "";
		expect(publishedCookie).toContain("clearance.session_token=");
		const successorToken = parseSetCookieHeader(publishedCookie)
			.get("clearance.session_token")
			?.value;
		expect(successorToken).toBeTruthy();
		expect(await response.clone().json()).toMatchObject({ code: "AFTER_TRANSACTION_HOOK_FAILED" });
		expect(await context.internalAdapter.findSession(source.session.token)).toBeNull();
		const successor = await auth.api.getSession({
			headers: new Headers({
				cookie: `clearance.session_token=${successorToken}`,
			}),
		});
		expect(successor?.session.id).not.toBe(source.session.id);
		expect(successor?.user.id).toBe(user.id);
		expect(successor?.session.activeOrganizationId).toBeNull();
		expect(await context.adapter.findOne({ model: "member", where: [{ field: "id", value: ownerMember.id }] })).toBeNull();
		expect(afterRemoveMember).toHaveBeenCalledTimes(1);
	});

	it("recovers only the exact presenting legacy session after an active self-removal hook failure", async () => {
		const afterRemoveMember = vi.fn(async () => {
			throw new Error("after remove failed");
		});
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			plugins: [organization({ organizationHooks: { afterRemoveMember } })],
		});
		const { headers, user } = await signInWithTestUser();
		const client = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl } });
		const org = await client.organization.create({ name: "legacy-after-hook-failure", slug: `legacy-after-hook-failure-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const source = await auth.api.getSession({ headers });
		if (!source) throw new Error("Legacy source session missing");
		const secondOwner = await auth.api.signUpEmail({ body: { email: `legacy-after-hook-owner-${crypto.randomUUID()}@test.com`, name: "owner", password: "password" } });
		await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: secondOwner.user.id, role: "owner" } });
		const context = await auth.$context;
		const ownerMember = await context.adapter.findOne<{ id: string }>({ model: "member", where: [{ field: "organizationId", value: org.data?.id as string }, { field: "userId", value: user.id }] });
		if (!ownerMember) throw new Error("Owner membership missing");
		const response = await auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: ownerMember.id }, headers, asResponse: true });
		expect(response.status).toBe(500);
		const successorToken = parseSetCookieHeader(response.headers.get("set-cookie") || "")
			.get("clearance.session_token")
			?.value;
		expect(successorToken).toBeTruthy();
		expect(await response.clone().json()).toMatchObject({ code: "AFTER_TRANSACTION_HOOK_FAILED" });
		const presentingSession = await auth.api.getSession({
			headers: new Headers({
				cookie: `clearance.session_token=${successorToken}`,
			}),
		});
		expect(presentingSession?.session.id).toBe(source.session.id);
		expect(presentingSession?.user.id).toBe(user.id);
		expect(presentingSession?.session.activeOrganizationId).toBeNull();
		expect(await context.adapter.findOne({ model: "member", where: [{ field: "id", value: ownerMember.id }] })).toBeNull();
		expect(afterRemoveMember).toHaveBeenCalledTimes(1);
	});

	it("suppresses afterRemoveMember when a post-delete transaction failure rolls back", async () => {
		const afterRemoveMember = vi.fn();
		const { auth, signInWithTestUser, customFetchImpl } = await getTestInstance({
			plugins: [organization({ organizationHooks: { afterRemoveMember } })],
		});
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({ plugins: [organizationClient()], baseURL: "http://localhost:3000/api/auth", fetchOptions: { customFetchImpl } });
		const org = await client.organization.create({ name: "rollback-after-delete", slug: `rollback-after-delete-${crypto.randomUUID()}`, fetchOptions: { headers } });
		const target = await auth.api.signUpEmail({ body: { email: `rollback-after-delete-${crypto.randomUUID()}@test.com`, name: "target", password: "password" } });
		const membership = await auth.api.addMember({ body: { organizationId: org.data?.id as string, userId: target.user.id, role: "member" } });
		const context = await auth.$context;
		const transaction = context.adapter.transaction.bind(context.adapter);
		vi.spyOn(context.adapter, "transaction").mockImplementation(async (callback) =>
			transaction(async (trx) => {
				await callback(trx);
				throw new Error("forced rollback after member deletion");
			}),
		);
		await expect(auth.api.removeMember({ body: { organizationId: org.data?.id, memberIdOrEmail: membership?.id as string }, headers })).rejects.toThrow("forced rollback after member deletion");
		expect(await context.adapter.findOne({ model: "member", where: [{ field: "id", value: membership?.id as string }] })).not.toBeNull();
		expect(afterRemoveMember).not.toHaveBeenCalled();
	});
});

describe("activeMemberRole", async () => {
	const { auth, signInWithTestUser } = await getTestInstance({
		plugins: [organization()],
	});
	const ctx = await auth.$context;
	const { headers } = await signInWithTestUser();
	const client = createAuthClient({
		plugins: [organizationClient()],
		baseURL: "http://localhost:3000/api/auth",
		fetchOptions: {
			customFetchImpl: async (url, init) => {
				return auth.handler(new Request(url, init));
			},
		},
	});
	const org = await client.organization.create({
		name: "test",
		slug: "test",
		metadata: {
			test: "test",
		},
		fetchOptions: {
			headers,
		},
	});
	await client.organization.create({
		name: "test-second",
		slug: "test-second",
		metadata: {
			test: "second-org",
		},
		fetchOptions: {
			headers,
		},
	});

	let selectedUserId = "";
	for (let i = 0; i < 10; i++) {
		const user = await ctx.adapter.create({
			model: "user",
			data: {
				email: `test${i}@test.com`,
				name: `test${i}`,
			},
		});

		if (i == 0) {
			selectedUserId = user.id;
		}

		await auth.api.addMember({
			body: {
				organizationId: org.data?.id as string,
				userId: user.id,
				role: "member",
			},
		});
	}

	it("should return the active member role on active organization", async () => {
		await client.organization.setActive({
			organizationId: org.data?.id as string,
			fetchOptions: {
				headers,
			},
		});

		const activeMember = await client.organization.getActiveMemberRole({
			fetchOptions: {
				headers,
			},
		});

		expect(activeMember.data?.role).toBe("owner");
	});

	it("should return active member role on organization", async () => {
		await client.organization.setActive({
			organizationId: org.data?.id as string,
			fetchOptions: {
				headers,
			},
		});

		const activeMember = await client.organization.getActiveMemberRole({
			query: {
				userId: selectedUserId,
			},
			fetchOptions: {
				headers,
			},
		});

		expect(activeMember.data?.role).toBe("member");
	});

	/**
	 * @see https://github.com/clearance-auth/clearance
	 */
	it("should clear active member role hook data after sign out", async () => {
		const originalWindow = global.window;
		global.window = {} as unknown as Window & typeof globalThis;
		try {
			const { headers: signOutHeaders } = await signInWithTestUser();
			const signOutClient = createAuthClient({
				plugins: [organizationClient()],
				baseURL: "http://localhost:3000/api/auth",
				fetchOptions: {
					customFetchImpl: async (url, init) => {
						return auth.handler(new Request(url, init));
					},
					headers: signOutHeaders,
				},
			});
			const signOutOrg = await signOutClient.organization.create({
				name: "sign-out-role-test",
				slug: "sign-out-role-test",
			});
			await signOutClient.organization.setActive({
				organizationId: signOutOrg.data?.id as string,
			});

			const activeRole = await waitForAuthQueryAtom(
				signOutClient.useActiveMemberRole,
				(value) => value.data?.role === "owner",
			);
			expect(activeRole.data?.role).toBe("owner");
			await nextTick();

			await signOutClient.signOut();

			const roleAfterSignOut = await waitForAuthQueryAtom(
				signOutClient.useActiveMemberRole,
				(value) => value.data === null,
			);
			expect(roleAfterSignOut.data).toBeNull();
		} finally {
			global.window = originalWindow;
		}
	});
});

type AuthQueryValue<Result> = ReturnType<AuthQueryAtom<Result>["get"]>;

async function waitForAuthQueryAtom<Result>(
	atom: AuthQueryAtom<Result>,
	predicate: (value: AuthQueryValue<Result>) => boolean,
) {
	return await new Promise<AuthQueryValue<Result>>((resolve, reject) => {
		let settled = false;
		const timeout = setTimeout(() => {
			if (settled) return;
			settled = true;
			reject(new Error("Timed out waiting for auth query atom state"));
		}, 1000);

		atom.subscribe((value) => {
			if (settled || value.isPending || value.isRefetching) return;
			if (!predicate(value)) return;
			settled = true;
			clearTimeout(timeout);
			resolve(value);
		});
		atom.get();
	});
}

async function nextTick() {
	await new Promise((resolve) => setTimeout(resolve, 25));
}

describe("inviteMember role validation", async () => {
	const { signInWithTestUser, customFetchImpl } = await getTestInstance({
		plugins: [organization()],
	});

	it("should fail when inviting with a non-existent role", async () => {
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({
			plugins: [organizationClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl,
			},
		});

		const org = await client.organization.create({
			name: "Test Org Validation",
			slug: "test-org-validation",
			fetchOptions: {
				headers,
			},
		});

		// Attempt to invite with a fake role
		const { error } = await client.organization.inviteMember({
			email: "fake-role@test.com",
			// @ts-expect-error - testing invalid role validation
			role: "super-invalid-role-123",
			organizationId: org.data?.id as string,
			fetchOptions: {
				headers,
			},
		});

		expect(error).toBeTruthy();
		expect(error?.status).toBe(400);
		expect(error?.message).toContain(
			ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND.code,
		);
	});

	it("should succeed when inviting with a valid default role", async () => {
		const { headers } = await signInWithTestUser();
		const client = createAuthClient({
			plugins: [organizationClient()],
			baseURL: "http://localhost:3000/api/auth",
			fetchOptions: {
				customFetchImpl,
			},
		});

		const org = await client.organization.create({
			name: "Test Org Validation 2",
			slug: "test-org-validation-2",
			fetchOptions: {
				headers,
			},
		});

		const { data, error } = await client.organization.inviteMember({
			email: "valid@test.com",
			role: "admin", // Valid default role
			organizationId: org.data?.id as string,
			fetchOptions: {
				headers,
			},
		});

		expect(error).toBeNull();
		expect(data).toBeDefined();
	});
});
