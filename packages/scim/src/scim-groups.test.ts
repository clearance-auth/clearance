import { sso } from "@clearance/sso";
import { clearance } from "@clearance/runtime";
import { memoryAdapter } from "@clearance/runtime/adapters/memory";
import { createAuthClient } from "@clearance/runtime/client";
import { setCookieToHeader } from "@clearance/runtime/cookies";
import { bearer, organization } from "@clearance/runtime/plugins";
import { describe, expect, it } from "vitest";
import { scim } from ".";
import { scimClient } from "./client";
import type { SCIMGroupBinding } from "./group-resources";

describe("SCIM Groups", () => {
	it("maps a scoped Group lifecycle to teams without changing organization membership", async () => {
		const data = {
			user: [], session: [], verification: [], account: [], ssoProvider: [],
			scimProvider: [], scimGroup: [], organization: [], member: [], invitation: [], team: [], teamMember: [],
		};
		const auth = clearance({
			database: memoryAdapter(data), baseURL: "http://localhost:3000",
			emailAndPassword: { enabled: true },
			plugins: [sso(), scim(), organization({ teams: { enabled: true } })],
		});
		const client = createAuthClient({
			baseURL: "http://localhost:3000", plugins: [bearer(), scimClient()],
			fetchOptions: { customFetchImpl: async (url, init) => auth.handler(new Request(url, init)) },
		});
		const admin = { email: "groups-admin@example.com", password: "password", name: "Groups Admin" };
		await client.signUp.email(admin);
		const headers = new Headers();
		await client.signIn.email(admin, { throw: true, onSuccess: setCookieToHeader(headers) });
		const org = await auth.api.createOrganization({ body: { slug: "groups-org", name: "Groups Org" }, headers });
		const otherOrg = await auth.api.createOrganization({ body: { slug: "groups-other-org", name: "Groups Other Org" }, headers });
		const tokenFor = async (providerId: string, organizationId: string) => (await auth.api.generateSCIMToken({ body: { providerId, organizationId }, headers })).scimToken;
		const token = await tokenFor("groups-provider", org!.id);
		const otherToken = await tokenFor("groups-other-provider", otherOrg!.id);
		const authz = (scimToken: string) => ({ authorization: `Bearer ${scimToken}` });
		const createUser = (userName: string, scimToken = token) => auth.api.createSCIMUser({ body: { userName, emails: [{ value: `${userName}@example.com` }] }, headers: authz(scimToken) });
		const [alice, bob] = await Promise.all([createUser("alice"), createUser("bob")]);
		const outsider = await createUser("outsider", otherToken);
		const ctx = await auth.$context;
		const teamsBeforeRejectedCreate = await ctx.adapter.count({ model: "team" });
		const transaction = ctx.adapter.options!.adapterConfig.transaction;
		ctx.adapter.options!.adapterConfig.transaction = false;
		try {
			await expect(auth.api.createSCIMGroup({ body: { displayName: "No Transaction" }, headers: authz(token) })).rejects.toThrow("SCIM Group mutations require rollback-capable database transactions");
		} finally {
			ctx.adapter.options!.adapterConfig.transaction = transaction;
		}
		expect(await ctx.adapter.count({ model: "team" })).toBe(teamsBeforeRejectedCreate);
		await expect(auth.api.createSCIMGroup({
			body: { displayName: "Rejected", externalId: "rejected", members: [{ value: outsider.id }] }, headers: authz(token),
		})).rejects.toThrow("Group members must be SCIM-provisioned users in this organization");
		expect(await ctx.adapter.count({ model: "team" })).toBe(teamsBeforeRejectedCreate);
		expect(await ctx.adapter.findOne({ model: "scimGroup", where: [{ field: "externalId", value: "rejected" }] })).toBeNull();

		const created = await auth.api.createSCIMGroup({
			body: { displayName: "Engineering", externalId: "eng", members: [{ value: alice.id }] }, headers: authz(token),
		});
		expect(created).toMatchObject({ displayName: "Engineering", externalId: "eng", members: [{ value: alice.id }] });
		expect(created.meta.location).toContain(`/Groups/${created.id}`);
		await expect(auth.api.createSCIMGroup({ body: { displayName: "Duplicate", externalId: "eng" }, headers: authz(token) })).rejects.toThrow("Group already exists");

		await auth.api.patchSCIMGroup({
			params: { groupId: created.id }, headers: authz(token),
			body: { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [
				{ op: "add", path: "Members", value: [{ value: bob.id }] },
				{ op: "replace", path: "URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:GROUP:DisplayName", value: "Platform Engineering" },
			] },
		});
		const patched = await auth.api.getSCIMGroup({ params: { groupId: created.id }, headers: authz(token) });
		expect(patched).toMatchObject({ displayName: "Platform Engineering" });
		expect(patched.members.map((member) => member.value).sort()).toEqual([alice.id, bob.id].sort());
		expect(new Date(patched.meta.lastModified).getTime()).toBeGreaterThan(new Date(created.meta.lastModified).getTime());
		const replacedMember = await auth.api.patchSCIMGroup({
			params: { groupId: created.id }, headers: authz(token),
			body: { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [
				{ op: "replace", path: `urn:ietf:params:scim:schemas:core:2.0:Group:members[value eq "${alice.id}"]`, value: { value: bob.id } },
			] },
		});
		expect(replacedMember.members.map((member) => member.value)).toEqual([bob.id]);
		await expect(auth.api.patchSCIMGroup({
			params: { groupId: created.id }, headers: authz(token),
			body: { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [
				{ op: "remove", path: 'Members[value eq "missing-user"]' },
			] },
		})).rejects.toMatchObject({ body: { scimType: "noTarget" } });
		await expect(auth.api.patchSCIMGroup({
			params: { groupId: created.id }, headers: authz(token),
			body: { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [] },
		})).rejects.toThrow();
		const groupBinding = await ctx.adapter.findOne<SCIMGroupBinding>({ model: "scimGroup", where: [{ field: "id", value: created.id }] });
		const teamBeforeNoop = await ctx.adapter.findOne<{ updatedAt?: Date }>({ model: "team", where: [{ field: "id", value: groupBinding!.teamId }] });
		const unchanged = await auth.api.patchSCIMGroup({
			params: { groupId: created.id }, headers: authz(token),
			body: { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [
				{ op: "replace", path: "DisplayName", value: "Platform Engineering" },
			] },
		});
		expect(unchanged.meta.lastModified).toEqual(replacedMember.meta.lastModified);
		const teamAfterNoop = await ctx.adapter.findOne<{ updatedAt?: Date }>({ model: "team", where: [{ field: "id", value: groupBinding!.teamId }] });
		expect(teamAfterNoop?.updatedAt).toEqual(teamBeforeNoop?.updatedAt);

		const replaced = await auth.api.updateSCIMGroup({
			params: { groupId: created.id }, headers: authz(token),
			body: { displayName: "Platform", externalId: "platform", members: [{ value: bob.id }] },
		});
		expect(replaced).toMatchObject({ displayName: "Platform", externalId: "platform", members: [{ value: bob.id }] });
		const membershipsBefore = await Promise.all([alice.id, bob.id].map((userId) => ctx.adapter.findOne<{ role: string }>({ model: "member", where: [{ field: "organizationId", value: org!.id }, { field: "userId", value: userId }] })));
		for (const userId of [alice.id, bob.id]) {
			expect(await ctx.adapter.findOne({ model: "member", where: [{ field: "organizationId", value: org!.id }, { field: "userId", value: userId }] })).not.toBeNull();
		}
		expect((await Promise.all([alice.id, bob.id].map((userId) => ctx.adapter.findOne<{ role: string }>({ model: "member", where: [{ field: "organizationId", value: org!.id }, { field: "userId", value: userId }] })))).map((member) => member?.role)).toEqual(membershipsBefore.map((member) => member?.role));

		const second = await auth.api.createSCIMGroup({ body: { displayName: "Design" }, headers: authz(token) });
		await auth.api.createSCIMGroup({ body: { displayName: "Private", members: [{ value: outsider.id }] }, headers: authz(otherToken) });
		const scopedGroupIds = [created.id, second.id].sort((left, right) => left.localeCompare(right));
		const page = await auth.api.listSCIMGroups({ query: { startIndex: 2, count: 1 }, headers: authz(token) });
		expect(page).toMatchObject({ totalResults: 2, startIndex: 2, itemsPerPage: 1, Resources: scopedGroupIds.slice(1, 2).map((id) => ({ id })) });
		const filtered = await auth.api.listSCIMGroups({ query: { filter: 'externalId eq "platform"' }, headers: authz(token) });
		expect(filtered.Resources).toHaveLength(1);
		expect(filtered.Resources[0]?.id).toBe(created.id);
		await expect(auth.api.getSCIMGroup({ params: { groupId: created.id }, headers: authz(otherToken) })).rejects.toThrow("Group not found");

		const binding = await ctx.adapter.findOne<SCIMGroupBinding>({ model: "scimGroup", where: [{ field: "id", value: created.id }] });
		await auth.api.deleteSCIMGroup({ params: { groupId: created.id }, headers: authz(token) });
		expect(await ctx.adapter.findOne({ model: "scimGroup", where: [{ field: "id", value: created.id }] })).toBeNull();
		expect(await ctx.adapter.findOne({ model: "team", where: [{ field: "id", value: binding!.teamId }] })).toBeNull();
		expect(await ctx.adapter.findMany({ model: "teamMember", where: [{ field: "teamId", value: binding!.teamId }] })).toEqual([]);
		expect(await ctx.adapter.findOne({ model: "member", where: [{ field: "organizationId", value: org!.id }, { field: "userId", value: bob.id }] })).not.toBeNull();

		const types = await auth.api.getSCIMResourceTypes();
		expect(types.Resources.map((resource) => resource.id)).toContain("Group");
		const schema = await auth.api.getSCIMSchema({ params: { schemaId: "urn:ietf:params:scim:schemas:core:2.0:Group" } });
		const memberSchema = schema.attributes.find((attribute) => attribute.name === "members");
		const memberAttributes = memberSchema && "subAttributes" in memberSchema
			? memberSchema.subAttributes as readonly { name: string; referenceTypes?: readonly string[]; canonicalValues?: readonly string[] }[]
			: [];
		expect(memberAttributes.find((attribute) => attribute.name === "$ref")?.referenceTypes).toEqual(["User"]);
		expect(memberAttributes.find((attribute) => attribute.name === "type")?.canonicalValues).toEqual(["User"]);
	});

	it("refuses to deprovision the final organization team", async () => {
		const data = { user: [], session: [], verification: [], account: [], ssoProvider: [], scimProvider: [], scimGroup: [], organization: [], member: [], invitation: [], team: [], teamMember: [] };
		const auth = clearance({ database: memoryAdapter(data), baseURL: "http://localhost:3000", emailAndPassword: { enabled: true }, plugins: [sso(), scim(), organization({ teams: { enabled: true, defaultTeam: { enabled: false } } })] });
		const client = createAuthClient({ baseURL: "http://localhost:3000", plugins: [bearer(), scimClient()], fetchOptions: { customFetchImpl: async (url, init) => auth.handler(new Request(url, init)) } });
		const admin = { email: "solo-groups-admin@example.com", password: "password", name: "Solo Groups Admin" };
		await client.signUp.email(admin);
		const headers = new Headers();
		await client.signIn.email(admin, { throw: true, onSuccess: setCookieToHeader(headers) });
		const org = await auth.api.createOrganization({ body: { slug: "solo-groups-org", name: "Solo Groups Org" }, headers });
		const { scimToken } = await auth.api.generateSCIMToken({ body: { providerId: "solo-groups-provider", organizationId: org!.id }, headers });
		const group = await auth.api.createSCIMGroup({ body: { displayName: "Only Team" }, headers: { authorization: `Bearer ${scimToken}` } });
		await expect(auth.api.deleteSCIMGroup({ params: { groupId: group.id }, headers: { authorization: `Bearer ${scimToken}` } })).rejects.toThrow("The last team cannot be removed");
		const ctx = await auth.$context;
		expect(await ctx.adapter.findOne({ model: "scimGroup", where: [{ field: "id", value: group.id }] })).not.toBeNull();
	});
});
