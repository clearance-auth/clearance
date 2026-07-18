import { describe, expect, it, vi } from "vitest";
import { createAuthClient } from "../../../client";
import { createAccessControl } from "../../access";
import { getTestInstance } from "../../../test-utils/test-instance";
import { attachInternalAuthorizationAuthority } from "../../../internal/authorization-authority";
import { defaultStatements } from "../access";
import { organizationClient } from "../client";
import { ORGANIZATION_ERROR_CODES } from "../error-codes";
import { organization } from "../organization";

describe("get-full-organization", async () => {
	const { auth, signInWithTestUser, cookieSetter } = await getTestInstance({
		plugins: [organization()],
	});
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

	it("should get organization by organizationId", async () => {
		const { headers } = await signInWithTestUser();

		//set the second org as active
		await client.organization.setActive({
			organizationId: secondOrg.data?.id as string,
			fetchOptions: {
				headers,
			},
		});
		const orgById = await client.organization.getFullOrganization({
			query: {
				// get the first org
				organizationId: org.data?.id as string,
			},
			fetchOptions: {
				headers,
			},
		});
		expect(orgById.data?.name).toBe("test");
	});

	it("should get organization by organizationSlug", async () => {
		const { headers } = await signInWithTestUser();
		const orgBySlug = await client.organization.getFullOrganization({
			query: {
				organizationSlug: "test",
			},
			fetchOptions: {
				headers,
			},
		});
		expect(orgBySlug.data?.name).toBe("test");
	});

	it("should return null when no active organization and no query params", async () => {
		await client.organization.setActive({
			organizationId: null,
			fetchOptions: {
				headers,
			},
		});
		const result = await client.organization.getFullOrganization({
			fetchOptions: {
				headers: headers,
			},
		});
		expect(result.data).toBeNull();
		expect(result.error).toBeNull();
	});

	it("should throw FORBIDDEN when user is not a member of the organization", async () => {
		const newHeaders = new Headers();
		await client.signUp.email(
			{
				email: "test3@test.com",
				password: "password",
				name: "test3",
			},
			{
				onSuccess: cookieSetter(newHeaders),
			},
		);
		const result = await client.organization.getFullOrganization({
			query: {
				organizationId: org.data?.id as string,
			},
			fetchOptions: {
				headers: newHeaders,
			},
		});
		expect(result.error?.status).toBe(403);
		expect(result.error?.code).toContain(
			ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION.code,
		);
	});

	it("clears the session after revoking a stale active organization", async () => {
		const { headers } = await signInWithTestUser();
		const scopedOrganization = await client.organization.create({
			name: "get-full hook failure",
			slug: "get-full-hook-failure",
			fetchOptions: { headers },
		});
		const source = await client.getSession({ fetchOptions: { headers } });
		const context = await auth.$context;
		await context.adapter.delete({
			model: "member",
			where: [
				{ field: "organizationId", value: scopedOrganization.data?.id as string },
				{ field: "userId", value: source.data?.user.id as string },
			],
		});
		const response = await auth.handler(
			new Request("http://localhost:3000/api/auth/organization/get-full-organization", {
				headers,
			}),
		);
		expect(response.status).toBe(403);
		await expect(
			context.internalAdapter.findSession(source.data!.session.token),
		).resolves.toBeNull();
	});

	it("preserves a same-token successor that moved after stale active-membership detection", async () => {
		const fixture = await getTestInstance({ plugins: [organization()] });
		const { headers, user } = await fixture.signInWithTestUser();
		const stale = await fixture.auth.api.createOrganization({
			body: { name: "stale source", slug: "stale-source" },
			headers,
		});
		const successor = await fixture.auth.api.createOrganization({
			body: {
				name: "concurrent successor",
				slug: "concurrent-successor",
				keepCurrentActiveOrganization: true,
			},
			headers,
		});
		const source = await fixture.auth.api.getSession({ headers });
		if (!source) throw new Error("Expected source session");
		const context = await fixture.auth.$context;
		await context.adapter.delete({
			model: "member",
			where: [
				{ field: "organizationId", value: stale.id },
				{ field: "userId", value: user.id },
			],
		});
		let signalMembershipRead!: () => void;
		let releaseMembershipRead!: () => void;
		const membershipRead = new Promise<void>((resolve) => {
			signalMembershipRead = resolve;
		});
		const membershipRelease = new Promise<void>((resolve) => {
			releaseMembershipRead = resolve;
		});
		let held = false;
		const originalFindOne = context.adapter.findOne.bind(context.adapter);
		const findOne = vi.spyOn(context.adapter, "findOne").mockImplementation(async (input) => {
			const result = await originalFindOne(input);
			if (
				!held &&
				input.model === "member" &&
				input.where.some((condition) =>
					condition.field === "organizationId" && condition.value === stale.id,
				)
			) {
				held = true;
				signalMembershipRead();
				await membershipRelease;
			}
			return result;
		});
		try {
			const request = fixture.auth.handler(
				new Request("http://localhost:3000/api/auth/organization/get-full-organization", { headers }),
			);
			await membershipRead;
			await context.adapter.update({
				model: "session",
				where: [{ field: "id", value: source.session.id }],
				update: { activeOrganizationId: successor.id, activeTeamId: null },
			});
			releaseMembershipRead();
			const response = await request;
			expect(response.status).toBe(403);
			expect(response.headers.get("set-cookie")).toBeNull();
			await expect(context.adapter.findOne<{
				activeOrganizationId?: string | null;
			}>({
				model: "session",
				where: [{ field: "id", value: source.session.id }],
			})).resolves.toMatchObject({ activeOrganizationId: successor.id });
		} finally {
			findOne.mockRestore();
		}
	});

	it("does not disclose whether a requested organization exists", async () => {
		const result = await client.organization.getFullOrganization({
			query: {
				organizationId: "non-existent-org-id",
			},
			fetchOptions: {
				headers,
			},
		});
		expect(result.error?.status).toBe(403);
		expect(result.error?.code).toContain(
			ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION.code,
		);
	});

	it("keeps a valid active scope unchanged for unknown and inaccessible full-organization slugs", async () => {
		const newHeaders = new Headers();
		await client.signUp.email(
			{
				email: "non-oracle-full-org@test.com",
				password: "password",
				name: "non-oracle-full-org",
			},
			{ onSuccess: cookieSetter(newHeaders) },
		);
		const active = await client.organization.create({
			name: "private-active-organization",
			slug: "private-active-organization",
			fetchOptions: { headers: newHeaders },
		});
		let unknownCookie = "";
		const unknown = await client.organization.getFullOrganization({
			query: { organizationSlug: "unknown-private-organization" },
			fetchOptions: {
				headers: newHeaders,
				onResponse(response) {
					unknownCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});
		let inaccessibleCookie = "";
		const inaccessible = await client.organization.getFullOrganization({
			query: { organizationSlug: org.data?.slug as string },
			fetchOptions: {
				headers: newHeaders,
				onResponse(response) {
					inaccessibleCookie = response.response.headers.get("set-cookie") || "";
				},
			},
		});
		expect(unknown.error?.status).toBe(403);
		expect(inaccessible.error?.status).toBe(403);
		expect(unknownCookie).toBe(inaccessibleCookie);
		expect(unknownCookie).toBe("");
		expect((await client.getSession({ fetchOptions: { headers: newHeaders } })).data?.session.activeOrganizationId).toBe(active.data?.id);
	});

	it("does not activate a stale slug candidate after reassignment", async () => {
		const fixture = await getTestInstance(
			{ plugins: [organization()] },
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const { headers, user } = await fixture.signInWithTestUser();
		const source = await fixture.client.organization.create({
			name: "slug source",
			slug: "slug-source",
			fetchOptions: { headers },
		});
		const candidate = await fixture.client.organization.create({
			name: "stale candidate",
			slug: "reassigned-slug",
			keepCurrentActiveOrganization: true,
			fetchOptions: { headers },
		});
		const replacement = await fixture.client.organization.create({
			name: "replacement target",
			slug: "replacement-slug",
			keepCurrentActiveOrganization: true,
			fetchOptions: { headers },
		});
		const context = await fixture.auth.$context;
		let signalLookup!: () => void;
		let releaseLookup!: () => void;
		const lookupRead = new Promise<void>((resolve) => { signalLookup = resolve; });
		const lookupRelease = new Promise<void>((resolve) => { releaseLookup = resolve; });
		let held = false;
		const originalFindOne = context.adapter.findOne.bind(context.adapter);
		const findOne = vi.spyOn(context.adapter, "findOne").mockImplementation(async (input) => {
			const result = await originalFindOne(input);
			if (
				!held && input.model === "organization" &&
				input.where.some((condition) =>
					condition.field === "slug" && condition.value === "reassigned-slug",
				)
			) {
				held = true;
				signalLookup();
				await lookupRelease;
			}
			return result;
		});
		try {
			const activation = fixture.client.organization.setActive({
				organizationSlug: "reassigned-slug",
				fetchOptions: { headers },
			});
			await lookupRead;
			await context.adapter.update({
				model: "organization",
				where: [{ field: "id", value: candidate.data!.id }],
				update: { slug: "former-candidate" },
			});
			await context.adapter.update({
				model: "organization",
				where: [{ field: "id", value: replacement.data!.id }],
				update: { slug: "reassigned-slug" },
			});
			releaseLookup();
			const result = await activation;
			expect(result.data).toBeNull();
			expect(result.error?.status).toBe(403);
			const sessions = await context.adapter.findMany<{
				activeOrganizationId?: string | null;
			}>({ model: "session", where: [{ field: "userId", value: user.id }] });
			expect(sessions.some((session) => session.activeOrganizationId === candidate.data!.id)).toBe(false);
			expect(sessions.some((session) => session.activeOrganizationId === replacement.data!.id)).toBe(false);
			expect(source.data).not.toBeNull();
		} finally {
			findOne.mockRestore();
		}
	});

	it("should include invitations in the response", async () => {
		await client.organization.setActive({
			organizationId: org.data?.id as string,
			fetchOptions: {
				headers,
			},
		});

		// Create an invitation
		await client.organization.inviteMember({
			email: "invited@test.com",
			role: "member",
			fetchOptions: {
				headers,
			},
		});

		const fullOrg = await client.organization.getFullOrganization({
			fetchOptions: {
				headers,
			},
		});

		expect(fullOrg.data?.invitations).toBeDefined();
		expect(Array.isArray(fullOrg.data?.invitations)).toBe(true);
		const invitation = fullOrg.data?.invitations.find(
			(inv: any) => inv.email === "invited@test.com",
		);
		expect(invitation).toBeDefined();
		expect(invitation?.role).toBe("member");
	});

	it("should prioritize organizationSlug over organizationId when both are provided", async () => {
		const result = await client.organization.getFullOrganization({
			query: {
				organizationId: org.data?.id as string,
				organizationSlug: secondOrg.data?.slug as string,
			},
			fetchOptions: {
				headers,
			},
		});
		expect(result.data).toBeTruthy();
		expect(result.data?.name).toBe(secondOrg.data?.name);
	});

	it("should allow listing members with membersLimit", async () => {
		const { headers } = await signInWithTestUser();
		await client.organization.setActive({
			organizationId: org.data?.id as string,
			fetchOptions: {
				headers,
			},
		});
		const newUser = await auth.api.signUpEmail({
			body: {
				email: "test2@test.com",
				password: "password",
				name: "test2",
			},
		});
		await auth.api.addMember({
			body: {
				userId: newUser.user.id,
				role: "member",
				organizationId: org.data?.id as string,
			},
		});
		const FullOrganization = await client.organization.getFullOrganization({
			fetchOptions: {
				headers,
			},
		});
		expect(FullOrganization.data?.members.length).toBe(2);

		const limitedMembers = await client.organization.getFullOrganization({
			query: {
				membersLimit: 1,
			},
			fetchOptions: {
				headers,
			},
		});
		expect(limitedMembers.data?.members.length).toBe(1);
	});

	it("should use default membershipLimit when no membersLimit is specified", async () => {
		await client.organization.setActive({
			organizationId: org.data?.id as string,
			fetchOptions: {
				headers,
			},
		});
		for (let i = 3; i <= 5; i++) {
			const newUser = await auth.api.signUpEmail({
				body: {
					email: `test-${i}@test.com`,
					password: "password",
					name: `test${i}`,
				},
			});
			await auth.api.addMember({
				body: {
					userId: newUser.user.id,
					role: "member",
					organizationId: org.data?.id as string,
				},
			});
		}

		const fullOrg = await client.organization.getFullOrganization({
			fetchOptions: {
				headers,
			},
		});

		expect(fullOrg.data?.members.length).toBeGreaterThan(3);
		expect(fullOrg.data?.members.length).toBeLessThanOrEqual(6);
	});
});

describe("organization hooks", async () => {
	it("finalizes authorization ownership in the organization-create transaction", async () => {
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [organization()],
		});
		const context = await auth.$context;
		const transaction = context.adapter.transaction.bind(context.adapter);
		Object.assign(context.adapter, {
			transaction: async (callback: any) =>
				transaction(async (activeTransaction) =>
					callback(
						Object.assign(activeTransaction, {
							rawTransactionQuery: vi.fn(),
						}),
					),
				),
		});
		const finalize = vi.fn(async () => {});
		attachInternalAuthorizationAuthority(context.internalAdapter, {
			async readEffectiveAuthorization(input) {
				return {
					organizationId: input.organizationId,
					subject: input.subject,
					revision: "1",
					actions: [],
				};
			},
			initializeOrganizationOwner: finalize,
		});
		const { headers, user } = await signInWithTestUser();
		const createdOrganization = await auth.api.createOrganization({
			body: { name: "authorized", slug: "authorized" },
			headers,
		});
		expect(finalize).toHaveBeenCalledOnce();
		expect(finalize).toHaveBeenCalledWith(
			expect.objectContaining({
				organizationId: createdOrganization.id,
				ownerPrincipalId: user.id,
				transaction: expect.objectContaining({
					rawTransactionQuery: expect.any(Function),
				}),
			}),
		);
	});

	it("rolls back organization creation when authorization finalization fails", async () => {
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [organization()],
		});
		const context = await auth.$context;
		const transaction = context.adapter.transaction.bind(context.adapter);
		Object.assign(context.adapter, {
			transaction: async (callback: any) =>
				transaction(async (activeTransaction) =>
					callback(
						Object.assign(activeTransaction, {
							rawTransactionQuery: vi.fn(),
						}),
					),
				),
		});
		attachInternalAuthorizationAuthority(context.internalAdapter, {
			async readEffectiveAuthorization(input) {
				return {
					organizationId: input.organizationId,
					subject: input.subject,
					revision: "1",
					actions: [],
				};
			},
			async initializeOrganizationOwner() {
				throw new Error("authorization finalization failed");
			},
		});
		const { headers } = await signInWithTestUser();
		await expect(
			auth.api.createOrganization({
				body: { name: "rollback authorization", slug: "rollback-authorization" },
				headers,
			}),
		).rejects.toThrow("Authorization authority is unavailable");
		expect(await context.adapter.count({ model: "organization" })).toBe(0);
		expect(await context.adapter.count({ model: "member" })).toBe(0);
	});

	it("serializes concurrent numeric organization-limit admission", async () => {
		const { client, signInWithTestUser } = await getTestInstance(
			{ plugins: [organization({ organizationLimit: 1 })] },
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const { headers } = await signInWithTestUser();
		const [first, second] = await Promise.all([
			client.organization.create({
				name: "first limited organization",
				slug: "first-limited-organization",
				keepCurrentActiveOrganization: true,
				fetchOptions: { headers },
			}),
			client.organization.create({
				name: "second limited organization",
				slug: "second-limited-organization",
				keepCurrentActiveOrganization: true,
				fetchOptions: { headers },
			}),
		]);
		expect([first, second].filter((result) => result.error === null)).toHaveLength(1);
		expect([first, second].find((result) => result.error)?.error?.code).toBe(
			ORGANIZATION_ERROR_CODES.YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS.code,
		);
	});

	it("reevaluates function organization-limit admission after the creator lock", async () => {
		let functionLimitCalls = 0;
		let signalPreflight!: () => void;
		let releasePreflight!: () => void;
		const preflightReady = new Promise<void>((resolve) => { signalPreflight = resolve; });
		const preflightRelease = new Promise<void>((resolve) => { releasePreflight = resolve; });
		const { client, signInWithTestUser, auth } = await getTestInstance(
			{
				plugins: [organization({
					organizationLimit: async () => {
						functionLimitCalls += 1;
						if (functionLimitCalls <= 2) {
							if (functionLimitCalls === 2) signalPreflight();
							await preflightRelease;
							return false;
						}
						return functionLimitCalls >= 4;
					},
				})],
			},
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const { headers } = await signInWithTestUser();
		const first = client.organization.create({
			name: "first function-limited organization",
			slug: "first-function-limited-organization",
			keepCurrentActiveOrganization: true,
			fetchOptions: { headers },
		});
		const second = client.organization.create({
			name: "second function-limited organization",
			slug: "second-function-limited-organization",
			keepCurrentActiveOrganization: true,
			fetchOptions: { headers },
		});
		await preflightReady;
		releasePreflight();
		const [firstResult, secondResult] = await Promise.all([first, second]);
		expect([firstResult, secondResult].filter((result) => result.error === null)).toHaveLength(1);
		expect([firstResult, secondResult].find((result) => result.error)?.error?.code).toBe(
			ORGANIZATION_ERROR_CODES.YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS.code,
		);
	});

	it("should apply beforeCreateOrganization hook", async () => {
		const beforeCreateOrganization = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance(
			{
				plugins: [
					organization({
						organizationHooks: {
							beforeCreateOrganization: async (data) => {
								beforeCreateOrganization();
								return {
									data: {
										...data.organization,
										metadata: {
											hookCalled: true,
										},
										name: "changed-name",
									},
								};
							},
						},
					}),
				],
			},
			{
				clientOptions: {
					plugins: [organizationClient()],
				},
			},
		);
		const { headers } = await signInWithTestUser();
		const result = await auth.api.createOrganization({
			body: {
				name: "test",
				slug: "test",
			},
			headers,
		});
		expect(beforeCreateOrganization).toHaveBeenCalled();
		expect(result?.name).toBe("changed-name");
		expect(result?.metadata).toEqual({
			hookCalled: true,
		});
	});

	it("should apply afterCreateOrganization hook", async () => {
		const afterCreateOrganization = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					organizationHooks: {
						afterCreateOrganization: async (data) => {
							afterCreateOrganization();
						},
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		await auth.api.createOrganization({
			body: {
				name: "test",
				slug: "test",
			},
			headers,
		});
		expect(afterCreateOrganization).toHaveBeenCalled();
	});

	it("pins the initial member to the default owner role after beforeAddMember", async () => {
		const beforeAddMember = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					organizationHooks: {
						beforeAddMember: async (data) => {
							beforeAddMember();
							return {
								data: {
									role: "changed-role",
								},
							};
						},
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		await auth.api.createOrganization({
			body: {
				name: "test",
				slug: "test",
			},
			headers,
		});
		expect(beforeAddMember).toHaveBeenCalled();
		const member = await auth.api.getActiveMember({
			headers,
		});
		expect(member?.role).toBe("owner");
	});

	it("pins the initial member to an explicitly configured creator role", async () => {
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					creatorRole: "admin",
					organizationHooks: {
						beforeAddMember: async () => ({ data: { role: "member" } }),
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		await auth.api.createOrganization({
			body: { name: "creator-role", slug: "creator-role" },
			headers,
		});
		expect((await auth.api.getActiveMember({ headers }))?.role).toBe("admin");
	});

	it("rolls back callback writes and does not run after hooks when default-team creation fails", async () => {
		const afterCreateOrganization = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					teams: {
						enabled: true,
						defaultTeam: {
							enabled: true,
							customCreateDefaultTeam: async (organization, ctx) => {
								if (!ctx) throw new Error("Expected transaction context");
								await ctx.context.adapter.create({
									model: "team",
									data: {
										organizationId: organization.id,
										name: "callback write",
										createdAt: new Date(),
									},
								});
								throw new Error("default team failed");
							},
						},
					},
					organizationHooks: { afterCreateOrganization },
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		await expect(auth.api.createOrganization({
			body: { name: "rollback", slug: "rollback" },
			headers,
		})).rejects.toThrow("default team failed");
		const context = await auth.$context;
		expect(await context.adapter.count({ model: "organization" })).toBe(0);
		expect(await context.adapter.count({ model: "team" })).toBe(0);
		expect(afterCreateOrganization).not.toHaveBeenCalled();
	});

	it("rechecks dynamic update authority after the preflight hook", async () => {
		const ac = createAccessControl({ ...defaultStatements });
		const support = ac.newRole({
			organization: [], member: [], invitation: [], team: [], ac: [],
		});
		let updateOrganizationId = "";
		let deleteDynamicRole!: () => Promise<unknown>;
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [organization({
				ac,
				roles: { support },
				dynamicAccessControl: { enabled: true },
				organizationHooks: {
					beforeUpdateOrganization: async () => {
						await deleteDynamicRole();
					},
				},
			})],
		});
		const { headers, user } = await signInWithTestUser();
		const org = await auth.api.createOrganization({
			body: { name: "dynamic update", slug: "dynamic-update" },
			headers,
		});
		updateOrganizationId = org.id;
		const context = await auth.$context;
		deleteDynamicRole = () => context.adapter.delete({
			model: "organizationRole",
			where: [
				{ field: "organizationId", value: updateOrganizationId },
				{ field: "role", value: "support" },
			],
		});
		await context.adapter.update({
			model: "member",
			where: [
				{ field: "organizationId", value: org.id },
				{ field: "userId", value: user.id },
			],
			update: { role: "support" },
		});
		await context.adapter.create({
			model: "organizationRole",
			data: {
				organizationId: org.id,
				role: "support",
				permission: JSON.stringify({ organization: ["update"] }),
				createdAt: new Date(),
			},
		});
		const response = await auth.api.updateOrganization({
			body: { organizationId: org.id, data: { name: "must not persist" } },
			headers,
			asResponse: true,
		});
		expect(response.status).toBe(403);
		expect(await context.adapter.findOne<{ name: string }>({
			model: "organization",
			where: [{ field: "id", value: org.id }],
		})).toMatchObject({ name: "dynamic update" });
	});

	it("fails update before hooks or writes without a rollback-capable adapter", async () => {
		const beforeUpdateOrganization = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [organization({ organizationHooks: { beforeUpdateOrganization } })],
		});
		const { headers } = await signInWithTestUser();
		const org = await auth.api.createOrganization({
			body: { name: "transaction-required update", slug: "transaction-required-update" },
			headers,
		});
		const context = await auth.$context;
		const originalTransaction = context.adapter.options!.adapterConfig.transaction;
		context.adapter.options!.adapterConfig.transaction = false;
		try {
			const response = await auth.api.updateOrganization({
				body: { organizationId: org.id, data: { name: "must not persist" } },
				headers,
				asResponse: true,
			});
			expect(response.status).toBe(500);
			expect(await response.json()).toMatchObject({
				code: "ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED",
			});
			expect(beforeUpdateOrganization).not.toHaveBeenCalled();
			expect(await context.adapter.findOne<{ name: string }>({
				model: "organization",
				where: [{ field: "id", value: org.id }],
			})).toMatchObject({ name: "transaction-required update" });
		} finally {
			context.adapter.options!.adapterConfig.transaction = originalTransaction;
		}
	});

	it("runs delete hooks after committed active and inactive organization deletion", async () => {
		const observedDeletedOrganizations: string[] = [];
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					teams: { enabled: true },
					organizationHooks: {
						afterDeleteOrganization: async ({ organization }, ctx) => {
							if (!ctx) throw new Error("expected endpoint context");
							const current = await ctx.context.adapter.findOne({
								model: "organization",
								where: [{ field: "id", value: organization.id }],
							});
							if (!current) observedDeletedOrganizations.push(organization.id);
						},
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		const active = await auth.api.createOrganization({
			body: { name: "active", slug: "active" },
			headers,
		});
		const inactive = await auth.api.createOrganization({
			body: { name: "inactive", slug: "inactive", keepCurrentActiveOrganization: true },
			headers,
		});
		await auth.api.deleteOrganization({ body: { organizationId: inactive.id }, headers });
		await auth.api.deleteOrganization({ body: { organizationId: active.id }, headers });
		expect(observedDeletedOrganizations).toEqual([inactive.id, active.id]);
	});

	it("publishes the committed legacy null-scope session when active deletion hooks fail after commit", async () => {
		const afterDeleteOrganization = vi.fn(async () => {
			throw new Error("legacy delete after hook failed");
		});
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [organization({ organizationHooks: { afterDeleteOrganization } })],
		});
		const { headers } = await signInWithTestUser();
		const org = await auth.api.createOrganization({
			body: { name: "legacy deletion", slug: "legacy-deletion" },
			headers,
		});
		const source = await auth.api.getSession({ headers });
		const response = await auth.api.deleteOrganization({
			body: { organizationId: org.id },
			headers,
			asResponse: true,
		});
		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ code: "AFTER_TRANSACTION_HOOK_FAILED" });
		expect(response.headers.get("set-cookie") || "").toMatch(/clearance\.session_token=/i);
		const context = await auth.$context;
		expect(await context.adapter.findOne({
			model: "organization",
			where: [{ field: "id", value: org.id }],
		})).toBeNull();
		expect(await context.adapter.findOne<{
			activeOrganizationId?: string | null;
		}>({
			model: "session",
			where: [{ field: "id", value: source!.session.id }],
		})).toMatchObject({ activeOrganizationId: null });
	});

	it("fails closed before hooks or mutation when sessions use secondary storage only", async () => {
		const secondary = new Map<string, string>();
		const beforeDeleteOrganization = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance({
			session: { storeSessionInDatabase: false },
			secondaryStorage: {
				get: (key) => secondary.get(key) ?? null,
				set: (key, value) => void secondary.set(key, value),
				delete: (key) => void secondary.delete(key),
			},
			plugins: [organization({ organizationHooks: { beforeDeleteOrganization } })],
		});
		const { headers } = await signInWithTestUser();
		const createdOrganization = await auth.api.createOrganization({
			body: { name: "secondary-only", slug: "secondary-only" },
			headers,
		});
		const response = await auth.api.deleteOrganization({
			body: { organizationId: createdOrganization.id },
			headers,
			asResponse: true,
		});

		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({
			code: "ORGANIZATION_SECONDARY_SESSION_REVOCATION_UNSUPPORTED",
		});
		expect(beforeDeleteOrganization).not.toHaveBeenCalled();
		const context = await auth.$context;
		expect(await context.adapter.findOne({
			model: "organization",
			where: [{ field: "id", value: createdOrganization.id }],
		})).not.toBeNull();
		expect((await auth.api.getSession({ headers }))?.session.activeOrganizationId).toBe(
			createdOrganization.id,
		);
	});

	it("should apply afterAddMember hook", async () => {
		const afterAddMember = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					organizationHooks: {
						afterAddMember: async (data) => {
							afterAddMember();
						},
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		await auth.api.createOrganization({
			body: {
				name: "test",
				slug: "test",
			},
			headers,
		});
		expect(afterAddMember).toHaveBeenCalled();
	});

	it("should apply beforeCreateTeam hook", async () => {
		const beforeCreateTeam = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					teams: {
						enabled: true,
					},
					organizationHooks: {
						beforeCreateTeam: async (data) => {
							beforeCreateTeam();
							return {
								data: {
									name: "changed-name",
									organizationId: "wrong-organization",
								},
							};
						},
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		const result = await auth.api.createOrganization({
			body: {
				name: "test",
				slug: "test",
			},
			headers,
		});
		expect(beforeCreateTeam).toHaveBeenCalled();
		const team = await auth.api.listOrganizationTeams({
			headers,
			query: {
				organizationId: result?.id,
			},
		});
		expect(team[0]?.name).toBe("changed-name");
		expect(team[0]?.organizationId).toBe(result?.id);
	});

	it("should apply afterCreateTeam hook", async () => {
		const afterCreateTeam = vi.fn();
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					teams: {
						enabled: true,
					},
					organizationHooks: {
						afterCreateTeam: async (data) => {
							afterCreateTeam();
						},
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		await auth.api.createOrganization({
			body: {
				name: "test",
				slug: "test",
			},
			headers,
		});
		expect(afterCreateTeam).toHaveBeenCalled();
	});

	/**
	 * @see https://github.com/clearance-auth/clearance
	 */
	it("should allow passing id through `beforeCreateTeam`", async () => {
		const customTeamId = "custom-team-id";
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					teams: {
						enabled: true,
					},
					organizationHooks: {
						beforeCreateTeam: async () => {
							return {
								data: {
									id: customTeamId,
								},
							};
						},
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		const result = await auth.api.createOrganization({
			body: {
				name: "test",
				slug: "test",
			},
			headers,
		});
		const teams = await auth.api.listOrganizationTeams({
			headers,
			query: {
				organizationId: result?.id,
			},
		});
		expect(teams[0]?.id).toBe(customTeamId);
	});

	it("ignores invitation IDs supplied through `beforeCreateInvitation`", async () => {
		const customInvitationId = "custom-invitation-id";
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					organizationHooks: {
						beforeCreateInvitation: async () => {
							return {
								data: {
									id: customInvitationId,
								},
							};
						},
					},
					async sendInvitationEmail() {},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		const org = await auth.api.createOrganization({
			body: {
				name: "test",
				slug: "test",
			},
			headers,
		});
		const invitation = await auth.api.createInvitation({
			body: {
				email: "invited@test.com",
				role: "member",
				organizationId: org?.id,
			},
			headers,
		});
		expect(invitation?.id).toBeDefined();
		expect(invitation?.id).not.toBe(customInvitationId);
	});

	it("should allow internal organization creation when disabled for users", async () => {
		const { auth } = await getTestInstance({
			plugins: [
				organization({
					allowUserToCreateOrganization: false,
				}),
			],
		});

		const newUser = await auth.api.signUpEmail({
			body: {
				email: "internal@test.com",
				password: "password",
				name: "Internal User",
			},
		});

		const internalOrg = await auth.api.createOrganization({
			body: {
				name: "Internal Org",
				slug: "internal-org",
				userId: newUser.user.id,
			},
		});
		expect(internalOrg).toBeDefined();
		expect(internalOrg?.name).toBe("Internal Org");
	});
});

describe("updateOrganization", async () => {
	const { auth, signInWithTestUser } = await getTestInstance({
		plugins: [organization()],
	});

	/**
	 * @see https://github.com/clearance-auth/clearance
	 */
	it("should clear the logo when passing null", async () => {
		const { headers } = await signInWithTestUser();
		const org = await auth.api.createOrganization({
			body: {
				name: "Logo Org",
				slug: "logo-org",
				logo: "https://example.com/logo.png",
			},
			headers,
		});
		expect(org?.logo).toBe("https://example.com/logo.png");

		const updated = await auth.api.updateOrganization({
			body: {
				organizationId: org!.id,
				data: {
					logo: null,
				},
			},
			headers,
		});
		expect(updated?.logo).toBeNull();
	});

	/**
	 * @see https://github.com/clearance-auth/clearance
	 */
	it("should accept a null logo on create", async () => {
		const { headers } = await signInWithTestUser();
		const org = await auth.api.createOrganization({
			body: {
				name: "Null Logo Org",
				slug: "null-logo-org",
				logo: null,
			},
			headers,
		});
		expect(org?.logo).toBeNull();
	});
});
