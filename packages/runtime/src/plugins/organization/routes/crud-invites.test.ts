import type {
	ClearanceOptions,
	GenerateIdFn,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
} from "@clearance/core";
import { createAuthMiddleware } from "@clearance/core/api";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import { describe, expect, it, vi } from "vitest";
import { parseSetCookieHeader } from "../../../cookies";
import { attachInternalAuthenticationPolicy } from "../../../internal/authentication-policy";
import { getTestInstance } from "../../../test-utils/test-instance";
import { organizationClient } from "../client";
import { createAccessControl } from "../../access";
import { defaultStatements } from "../access/statement";
import { organization } from "../organization";
import type { OrganizationOptions } from "../types";

describe("invitation delivery", () => {
	it("sends legacy email only after the owning transaction commits", async () => {
		let sent = 0;
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					async sendInvitationEmail() {
						sent += 1;
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		const organizationRecord = await auth.api.createOrganization({
			body: { name: "Legacy commit", slug: `legacy-commit-${Date.now()}` },
			headers,
		});
		const context = await auth.$context;

		await expect(
			runWithTransaction(context.adapter, async () => {
				await auth.api.createInvitation({
					body: {
						email: "legacy-rollback@example.test",
						role: "member",
						organizationId: organizationRecord.id,
					},
					headers,
				});
				throw new Error("rollback legacy invitation");
			}),
		).rejects.toThrow("rollback legacy invitation");
		expect(sent).toBe(0);

		await runWithTransaction(context.adapter, async () => {
			await auth.api.createInvitation({
				body: {
					email: "legacy-commit@example.test",
					role: "member",
					organizationId: organizationRecord.id,
				},
				headers,
			});
		});
		expect(sent).toBe(1);
	});

	it("requires a transaction for authority-protected invitation persistence", async () => {
		let sent = false;
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					async sendInvitationEmail() {
						sent = true;
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		const organizationRecord = await auth.api.createOrganization({
			body: { name: "Legacy", slug: `legacy-${Date.now()}` },
			headers,
		});
		const context = await auth.$context;
		(context.adapter as unknown as { transaction: () => Promise<never> }).transaction = async () => {
			throw new Error("legacy invitation must not open a transaction");
		};
		await expect(
			auth.api.createInvitation({
				body: {
					email: "legacy-invite@example.test",
					role: "member",
					organizationId: organizationRecord.id,
				},
				headers,
			}),
		).rejects.toThrow("legacy invitation must not open a transaction");
		expect(sent).toBe(false);
	});
});

/**
 * @see https://github.com/clearance-auth/clearance
 */
describe("organization invitation recipient ownership gates", async () => {
	const VICTIM_EMAIL = "victim@target.example";
	const ATTACKER_PASSWORD = "attacker-password-123";

	type SetupInviteOptions = {
		authOptions?: Partial<ClearanceOptions>;
		organizationOptions?: OrganizationOptions;
	};

	type AuthOptionsWithAdvancedGenerateId = Partial<ClearanceOptions> & {
		advanced: NonNullable<Partial<ClearanceOptions>["advanced"]> & {
			generateId: GenerateIdFn;
		};
	};

	const databaseOwnedIdAuthOptions = {
		advanced: {
			database: {
				generateId: "serial",
			},
		},
	} satisfies Partial<ClearanceOptions>;

	let customIdSequence = 0;
	const customAdvancedIdAuthOptions = {
		advanced: {
			cookies: {},
			generateId: ({ model }) => `${model}-custom-id-${customIdSequence++}`,
		},
	} satisfies AuthOptionsWithAdvancedGenerateId;

	async function setupInvite({
		authOptions,
		organizationOptions,
	}: SetupInviteOptions = {}) {
		const helpers = await getTestInstance(
			{
				...authOptions,
				plugins: [
					organization(organizationOptions),
					...(authOptions?.plugins ?? []),
				],
			},
			{ clientOptions: { plugins: [organizationClient()] } },
		);
		const { client, signInWithTestUser, cookieSetter } = helpers;
		const { headers: adminHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Acme",
			slug: "acme",
			fetchOptions: {
				headers: adminHeaders,
				onSuccess: cookieSetter(adminHeaders),
			},
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: VICTIM_EMAIL,
			role: "member",
			fetchOptions: { headers: adminHeaders },
		});
		return {
			...helpers,
			adminHeaders,
			orgId: org.data!.id,
			invitationId: String(invite.data!.id!),
		};
	}

	async function signUpUnverifiedRecipient(
		client: Awaited<ReturnType<typeof setupInvite>>["client"],
		signInWithUser: Awaited<ReturnType<typeof setupInvite>>["signInWithUser"],
	) {
		await client.signUp.email({
			email: VICTIM_EMAIL,
			password: ATTACKER_PASSWORD,
			name: "recipient",
		});
		const { headers, res } = await signInWithUser(
			VICTIM_EMAIL,
			ATTACKER_PASSWORD,
		);
		expect(res.user.email).toBe(VICTIM_EMAIL);
		expect(res.user.emailVerified).toBe(false);
		return headers;
	}

	it("accepts an invitation by ID from an unverified matching session by default", async () => {
		const { client, signInWithUser, invitationId, auth, adminHeaders } =
			await setupInvite();
		const recipientHeaders = await signUpUnverifiedRecipient(
			client,
			signInWithUser,
		);

		const accept = await client.organization.acceptInvitation({
			invitationId,
			fetchOptions: { headers: recipientHeaders },
		});

		expect(accept.error).toBeNull();
		expect(accept.data?.invitation?.status).toBe("accepted");

		const orgAfter = await auth.api.getFullOrganization({
			headers: adminHeaders,
		});
		const memberEmails = (orgAfter?.members ?? []).map((m) => m.user.email);
		expect(memberEmails).toContain(VICTIM_EMAIL);
	});

	it("marks an invitation rejected by ID from an unverified matching session by default", async () => {
		const { client, signInWithUser, invitationId } = await setupInvite();
		const recipientHeaders = await signUpUnverifiedRecipient(
			client,
			signInWithUser,
		);

		const reject = await client.organization.rejectInvitation({
			invitationId,
			fetchOptions: { headers: recipientHeaders },
		});

		expect(reject.error).toBeNull();
	});

	it("gets an invitation by ID from an unverified matching session by default", async () => {
		const { client, signInWithUser, invitationId } = await setupInvite();
		const recipientHeaders = await signUpUnverifiedRecipient(
			client,
			signInWithUser,
		);

		const got = await client.organization.getInvitation({
			query: { id: invitationId },
			fetchOptions: { headers: recipientHeaders },
		});

		expect(got.error).toBeNull();
		expect(got.data?.email).toBe(VICTIM_EMAIL);
	});

	it("rejects listUserInvitations from an unverified session", async () => {
		const { client, signInWithUser } = await setupInvite();
		const attackerHeaders = await signUpUnverifiedRecipient(
			client,
			signInWithUser,
		);

		const list = await client.organization.listUserInvitations({
			fetchOptions: { headers: attackerHeaders },
		});

		expect(list.data).toBeNull();
		expect(list.error?.status).toBe(403);
	});

	/**
	 * @see https://github.com/clearance-auth/clearance
	 */
	it("keeps listUserInvitations gated when invitation ID verification is disabled", async () => {
		const { client, signInWithUser } = await setupInvite({
			organizationOptions: {
				requireEmailVerificationOnInvitation: false,
			},
		});
		const attackerHeaders = await signUpUnverifiedRecipient(
			client,
			signInWithUser,
		);

		const list = await client.organization.listUserInvitations({
			fetchOptions: { headers: attackerHeaders },
		});

		expect(list.data).toBeNull();
		expect(list.error?.status).toBe(403);
	});

	it("requires verified email for invitation ID calls when explicitly enabled", async () => {
		const acceptSetup = await setupInvite({
			organizationOptions: {
				requireEmailVerificationOnInvitation: true,
			},
		});
		const acceptHeaders = await signUpUnverifiedRecipient(
			acceptSetup.client,
			acceptSetup.signInWithUser,
		);
		const accept = await acceptSetup.client.organization.acceptInvitation({
			invitationId: acceptSetup.invitationId,
			fetchOptions: { headers: acceptHeaders },
		});
		expect(accept.data).toBeNull();
		expect(accept.error?.status).toBe(403);

		const getSetup = await setupInvite({
			organizationOptions: {
				requireEmailVerificationOnInvitation: true,
			},
		});
		const getHeaders = await signUpUnverifiedRecipient(
			getSetup.client,
			getSetup.signInWithUser,
		);
		const got = await getSetup.client.organization.getInvitation({
			query: { id: getSetup.invitationId },
			fetchOptions: { headers: getHeaders },
		});
		expect(got.data).toBeNull();
		expect(got.error?.status).toBe(403);

		const rejectSetup = await setupInvite({
			organizationOptions: {
				requireEmailVerificationOnInvitation: true,
			},
		});
		const rejectHeaders = await signUpUnverifiedRecipient(
			rejectSetup.client,
			rejectSetup.signInWithUser,
		);
		const reject = await rejectSetup.client.organization.rejectInvitation({
			invitationId: rejectSetup.invitationId,
			fetchOptions: { headers: rejectHeaders },
		});
		expect(reject.data).toBeNull();
		expect(reject.error?.status).toBe(403);
	});

	it("requires verified email for invitation ID calls when the database owns IDs", async () => {
		const acceptSetup = await setupInvite({
			authOptions: databaseOwnedIdAuthOptions,
		});
		const acceptHeaders = await signUpUnverifiedRecipient(
			acceptSetup.client,
			acceptSetup.signInWithUser,
		);
		const accept = await acceptSetup.client.organization.acceptInvitation({
			invitationId: acceptSetup.invitationId,
			fetchOptions: { headers: acceptHeaders },
		});
		expect(accept.data).toBeNull();
		expect(accept.error?.status).toBe(403);

		const getSetup = await setupInvite({
			authOptions: databaseOwnedIdAuthOptions,
		});
		const getHeaders = await signUpUnverifiedRecipient(
			getSetup.client,
			getSetup.signInWithUser,
		);
		const got = await getSetup.client.organization.getInvitation({
			query: { id: getSetup.invitationId },
			fetchOptions: { headers: getHeaders },
		});
		expect(got.data).toBeNull();
		expect(got.error?.status).toBe(403);

		const rejectSetup = await setupInvite({
			authOptions: databaseOwnedIdAuthOptions,
		});
		const rejectHeaders = await signUpUnverifiedRecipient(
			rejectSetup.client,
			rejectSetup.signInWithUser,
		);
		const reject = await rejectSetup.client.organization.rejectInvitation({
			invitationId: rejectSetup.invitationId,
			fetchOptions: { headers: rejectHeaders },
		});
		expect(reject.data).toBeNull();
		expect(reject.error?.status).toBe(403);
	});

	it("requires verified email for invitation ID calls when advanced generateId is custom", async () => {
		const { client, signInWithUser, invitationId } = await setupInvite({
			authOptions: customAdvancedIdAuthOptions,
		});
		const recipientHeaders = await signUpUnverifiedRecipient(
			client,
			signInWithUser,
		);

		const accept = await client.organization.acceptInvitation({
			invitationId,
			fetchOptions: { headers: recipientHeaders },
		});

		expect(accept.data).toBeNull();
		expect(accept.error?.status).toBe(403);
	});

	it("accepts an invitation by ID with database-owned IDs when verification is explicitly disabled", async () => {
		const { client, signInWithUser, invitationId, auth, adminHeaders } =
			await setupInvite({
				authOptions: databaseOwnedIdAuthOptions,
				organizationOptions: {
					requireEmailVerificationOnInvitation: false,
				},
			});
		const recipientHeaders = await signUpUnverifiedRecipient(
			client,
			signInWithUser,
		);

		const accept = await client.organization.acceptInvitation({
			invitationId,
			fetchOptions: { headers: recipientHeaders },
		});

		expect(accept.error).toBeNull();
		expect(accept.data?.invitation?.status).toBe("accepted");

		const orgAfter = await auth.api.getFullOrganization({
			headers: adminHeaders,
		});
		const memberEmails = (orgAfter?.members ?? []).map((m) => m.user.email);
		expect(memberEmails).toContain(VICTIM_EMAIL);
	});

	it("accepts the invitation once the recipient verifies their email when verification is required", async () => {
		const { client, signInWithUser, invitationId, auth, adminHeaders } =
			await setupInvite({
				organizationOptions: {
					requireEmailVerificationOnInvitation: true,
				},
			});
		await client.signUp.email({
			email: VICTIM_EMAIL,
			password: ATTACKER_PASSWORD,
			name: "victim",
		});
		const ctx = await auth.$context;
		const victim = await ctx.internalAdapter.findUserByEmail(VICTIM_EMAIL);
		await ctx.internalAdapter.updateUser(victim!.user.id, {
			emailVerified: true,
		});
		const { headers: victimHeaders } = await signInWithUser(
			VICTIM_EMAIL,
			ATTACKER_PASSWORD,
		);

		const list = await client.organization.listUserInvitations({
			fetchOptions: { headers: victimHeaders },
		});
		expect(list.error).toBeNull();
		expect(
			list.data?.some((invitation) => invitation.id === invitationId),
		).toBe(true);

		const accept = await client.organization.acceptInvitation({
			invitationId,
			fetchOptions: { headers: victimHeaders },
		});

		expect(accept.error).toBeNull();
		expect(accept.data?.invitation?.status).toBe("accepted");

		const orgAfter = await auth.api.getFullOrganization({
			headers: adminHeaders,
		});
		const memberEmails = (orgAfter?.members ?? []).map((m) => m.user.email);
		expect(memberEmails).toContain(VICTIM_EMAIL);
	});
});

describe("invitation lifecycle authority", () => {
	const INVITEE_EMAIL = "lifecycle-invitee@example.test";
	const PASSWORD = "lifecycle-password-123";
	const managedIdentity = {
		projectId: "crud-invites-project",
		environmentId: "crud-invites-environment",
	} satisfies RuntimeAuthenticationPolicyIdentity;
	const managedPolicy = {
		passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
		factorLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
		minimumAssurance: "single_factor",
		allowedFactors: { totp: true, passkey: true },
		trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
		assuranceMaxAgeSeconds: 300,
	} satisfies RuntimeAuthenticationPolicy;

	async function setup(organizationOptions?: OrganizationOptions) {
		return getTestInstance(
			{
				plugins: [
					organization({
						...organizationOptions,
						async sendInvitationEmail() {},
					}),
				],
			},
			{ clientOptions: { plugins: [organizationClient()] } },
		);
	}

	async function setupManaged(
		organizationOptions?: OrganizationOptions,
		authOptions: Partial<ClearanceOptions> = {},
	) {
		const options = {
			...authOptions,
			plugins: [
				organization({
					...organizationOptions,
					async sendInvitationEmail() {},
				}),
			],
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
										{
											field: "organizationId",
											value: input.organizationId,
										},
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
		return getTestInstance(options, {
			clientOptions: { plugins: [organizationClient()] },
		});
	}

	it("fails closed before session middleware or acceptance hooks for managed secondary-authoritative sessions", async () => {
		const secondary = new Map<string, string>();
		const beforeAcceptInvitation = vi.fn();
		const afterAcceptInvitation = vi.fn();
		const { auth, client, signInWithUser, db } =
			await setupManaged(
				{
					teams: { enabled: true },
					organizationHooks: { beforeAcceptInvitation, afterAcceptInvitation },
				},
				{
					session: { storeSessionInDatabase: true },
					secondaryStorage: {
						namespace: "crud-invites-managed-secondary",
						get: async (key) => secondary.get(key) ?? null,
						set: async (key, value) => void secondary.set(key, value),
						delete: async (key) => void secondary.delete(key),
					},
				},
			);
		const context = await auth.$context;
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders, res: invitee } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);
		const org = await context.adapter.create({
			model: "organization",
			data: {
				name: "Managed secondary invitation",
				slug: "managed-secondary-invitation",
				createdAt: new Date(),
			},
		});
		const invite = await context.adapter.create({
			model: "invitation",
			data: {
				email: INVITEE_EMAIL,
				role: "member",
				organizationId: org.id,
				inviterId: invitee.user.id,
				status: "pending",
				expiresAt: new Date(Date.now() + 60_000),
				createdAt: new Date(),
			},
		});
		const sourceSession = await auth.api.getSession({ headers: inviteeHeaders });
		const secondaryBefore = new Map(secondary);
		const laterMiddleware = vi.fn();
		const acceptanceMiddleware =
			auth.api.acceptInvitation.options.use as unknown as Array<
				ReturnType<typeof createAuthMiddleware>
			>;
		acceptanceMiddleware.splice(
			0,
			0,
			createAuthMiddleware(async () => {
				context.options.session!.storeSessionInDatabase = false;
				return {};
			}),
		);
		acceptanceMiddleware.splice(
			2,
			0,
			createAuthMiddleware(async () => {
				laterMiddleware();
				return {};
			}),
		);
		const accepted = await auth.api.acceptInvitation({
			body: { invitationId: invite.id },
			headers: inviteeHeaders,
			asResponse: true,
		});
		expect(accepted.status).toBe(500);
		expect(await accepted.json()).toMatchObject({
			code:
			"MANAGED_ORGANIZATION_SECONDARY_SESSION_TRANSITION_UNSUPPORTED",
		});
		expect(beforeAcceptInvitation).not.toHaveBeenCalled();
		expect(afterAcceptInvitation).not.toHaveBeenCalled();
		expect(laterMiddleware).not.toHaveBeenCalled();
		expect(accepted.headers.get("set-cookie")).toBeNull();
		expect(secondary).toEqual(secondaryBefore);
		context.options.session!.storeSessionInDatabase = true;
		const [invitationAfter, membership, teamMembership, sourceAfter] =
			await Promise.all([
				db.findOne<{ status: string }>({
					model: "invitation",
					where: [{ field: "id", value: invite.id }],
				}),
				db.findOne({
					model: "member",
					where: [
						{ field: "organizationId", value: org.id },
						{ field: "userId", value: invitee.user.id },
					],
				}),
				db.findOne({
					model: "teamMember",
					where: [{ field: "userId", value: invitee.user.id }],
				}),
				auth.api.getSession({ headers: inviteeHeaders }),
			]);
		expect(invitationAfter?.status).toBe("pending");
		expect(membership).toBeNull();
		expect(teamMembership).toBeNull();
		expect(sourceAfter?.session.token).toBe(sourceSession?.session.token);
	});

	it("re-pins invitation authority after a hostile before-create hook", async () => {
		const { client, signInWithTestUser, db } = await setup({
			schema: {
				invitation: {
					additionalFields: {
						note: { type: "string", required: false },
					},
				},
			},
			organizationHooks: {
				beforeCreateInvitation: async () => ({
					data: {
						id: "hook-controlled-id",
						organizationId: "hook-controlled-org",
						email: "hook-controlled@example.test",
						role: "owner",
						teamId: "hook-controlled-team",
						teamIds: ["hook-controlled-team"],
						inviterId: "hook-controlled-inviter",
						status: "accepted",
						expiresAt: new Date(0),
						createdAt: new Date(0),
						note: "validated hook field",
					},
				}),
			},
		});
		const { headers } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Lifecycle",
			slug: "lifecycle",
			fetchOptions: { headers },
		});

		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			note: "request value",
			fetchOptions: { headers },
		} as never);
		expect(invite.error).toBeNull();
		expect(invite.data).toMatchObject({
			email: INVITEE_EMAIL,
			organizationId: org.data!.id,
			role: "member",
			status: "pending",
			note: "validated hook field",
		});
		expect(invite.data?.id).not.toBe("hook-controlled-id");

		const persisted = await db.findOne<{ inviterId: string; createdAt: Date }>({
			model: "invitation",
			where: [{ field: "id", value: invite.data!.id }],
		});
		expect(persisted?.inviterId).not.toBe("hook-controlled-inviter");
		expect(persisted?.createdAt.getTime()).toBeGreaterThan(0);
	});

	it("rejects a bearer made stale by a before hook before persisting an invitation", async () => {
		let revokeBearer: (() => Promise<void>) | undefined;
		const { auth, client, signInWithTestUser, db } = await setup({
			organizationHooks: {
				beforeCreateInvitation: async () => revokeBearer?.(),
			},
		});
		const { headers } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Revoked actor",
			slug: "revoked-actor",
			fetchOptions: { headers },
		});
		const source = await auth.api.getSession({ headers });
		if (!source) throw new Error("Expected source session");
		const context = await auth.$context;
		revokeBearer = async () => {
			await context.adapter.update({
				model: "session",
				where: [{ field: "id", value: source.session.id }],
				update: { expiresAt: new Date(0) },
			});
		};
		const result = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers },
		});
		expect(result.error?.status).toBe(401);
		expect(await db.count({ model: "invitation", where: [{ field: "organizationId", value: org.data!.id }] })).toBe(0);
	});

	it("persists the immutable actor when a before-create hook mutates inviter", async () => {
		const { client, signInWithTestUser, db } = await setup({
			organizationHooks: {
				beforeCreateInvitation: async ({ inviter }) => {
					(inviter as { id: string }).id = "hook-substituted-inviter";
				},
			},
		});
		const { headers, user } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Immutable inviter",
			slug: "immutable-inviter",
			fetchOptions: { headers },
		});
		const result = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers },
		});
		expect(result.error).toBeNull();
		expect(await db.findOne<{ inviterId: string }>({
			model: "invitation",
			where: [{ field: "id", value: result.data!.id }],
		})).toMatchObject({ inviterId: user.id });
	});

	it("passes the locked current organization snapshot to invitationLimit", async () => {
		let db!: Awaited<ReturnType<typeof setup>>["db"];
		let observedOrganizationName: string | undefined;
		const instance = await setup({
			invitationLimit: ({ organization }) => {
				observedOrganizationName = organization.name;
				return 1;
			},
			organizationHooks: {
				beforeCreateInvitation: async ({ organization }) => {
					await db.update({
						model: "organization",
						where: [{ field: "id", value: organization.id }],
						update: { name: "Locked organization snapshot" },
					});
				},
			},
		});
		db = instance.db;
		const { client, signInWithTestUser } = instance;
		const { headers } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Old organization snapshot",
			slug: "organization-limit-snapshot",
			fetchOptions: { headers },
		});
		const result = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers },
		});
		expect(result.error).toBeNull();
		expect(observedOrganizationName).toBe("Locked organization snapshot");
	});

	it("reject and cancel race through a single pending-state transition", async () => {
		const { client, signInWithTestUser, signInWithUser, db } = await setup();
		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Race",
			slug: "invitation-race",
			fetchOptions: { headers: ownerHeaders },
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers: ownerHeaders },
		});
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);

		const [rejected, canceled] = await Promise.all([
			client.organization.rejectInvitation({
				invitationId: String(invite.data!.id),
				fetchOptions: { headers: inviteeHeaders },
			}),
			client.organization.cancelInvitation({
				invitationId: String(invite.data!.id),
				fetchOptions: { headers: ownerHeaders },
			}),
		]);
		expect([rejected.error, canceled.error].filter(Boolean)).toHaveLength(1);
		const persisted = await db.findOne<{ status: string }>({
			model: "invitation",
			where: [{ field: "id", value: invite.data!.id }],
		});
		expect(["rejected", "canceled"]).toContain(persisted?.status);
	});

	it("rejects acceptance at the exact expiration instant", async () => {
		let expireDuringBeforeAccept = false;
		let db: Awaited<ReturnType<typeof setup>>["db"];
		const instance = await setup({
			organizationHooks: {
				beforeAcceptInvitation: async ({ invitation }) => {
					if (expireDuringBeforeAccept) {
						await db.update({
							model: "invitation",
							where: [{ field: "id", value: invitation.id }],
							update: { expiresAt: frozenAt },
						});
					}
				},
			},
		});
		const { client, signInWithTestUser, signInWithUser } = instance;
		db = instance.db;
		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Exact expiration",
			slug: "exact-expiration",
			fetchOptions: { headers: ownerHeaders },
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers: ownerHeaders },
		});
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);
		const frozenAt = new Date();
		await db.update({
			model: "invitation",
			where: [{ field: "id", value: invite.data!.id }],
			update: { expiresAt: frozenAt },
		});
		vi.useFakeTimers();
		vi.setSystemTime(frozenAt);
		try {
			const rejectedAtPreflight = await client.organization.acceptInvitation({
				invitationId: String(invite.data!.id),
				fetchOptions: { headers: inviteeHeaders },
			});
			expect(rejectedAtPreflight.data).toBeNull();
			expect(rejectedAtPreflight.error?.code).toBe("INVITATION_NOT_FOUND");
		} finally {
			vi.useRealTimers();
		}

		await db.update({
			model: "invitation",
			where: [{ field: "id", value: invite.data!.id }],
			update: { expiresAt: new Date(frozenAt.getTime() + 1) },
		});
		expireDuringBeforeAccept = true;
		vi.useFakeTimers();
		vi.setSystemTime(frozenAt);
		try {
			const rejectedAfterLock = await client.organization.acceptInvitation({
				invitationId: String(invite.data!.id),
				fetchOptions: { headers: inviteeHeaders },
			});
			expect(rejectedAfterLock.data).toBeNull();
			expect(rejectedAfterLock.error?.code).toBe("INVITATION_NOT_FOUND");
		} finally {
			vi.useRealTimers();
		}
		expect(
			await db.findOne<{ status: string }>({
				model: "invitation",
				where: [{ field: "id", value: invite.data!.id }],
			}),
		).toEqual(expect.objectContaining({ status: "pending" }));
	});

	it("revalidates the rejection recipient after its before hook", async () => {
		let markReady!: () => void;
		let release!: () => void;
		const ready = new Promise<void>((resolve) => (markReady = resolve));
		const wait = new Promise<void>((resolve) => (release = resolve));
		const { client, signInWithTestUser, signInWithUser, db } = await setup({
			organizationHooks: {
				beforeRejectInvitation: async () => {
					markReady();
					await wait;
				},
			},
		});
		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Reject revalidation",
			slug: "reject-revalidation",
			fetchOptions: { headers: ownerHeaders },
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers: ownerHeaders },
		});
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);
		const rejected = client.organization.rejectInvitation({
			invitationId: String(invite.data!.id),
			fetchOptions: { headers: inviteeHeaders },
		});
		await ready;
		await db.update({
			model: "invitation",
			where: [{ field: "id", value: invite.data!.id }],
			update: { email: "other@example.test" },
		});
		release();
		expect((await rejected).error?.code).toBe(
			"YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
		);
		expect(
			await db.findOne<{ status: string }>({
				model: "invitation",
				where: [{ field: "id", value: invite.data!.id }],
			}),
		).toEqual(expect.objectContaining({ status: "pending" }));
	});

	it("revalidates cancellation authority after its before hook", async () => {
		let markReady!: () => void;
		let release!: () => void;
		const ready = new Promise<void>((resolve) => (markReady = resolve));
		const wait = new Promise<void>((resolve) => (release = resolve));
		const { client, signInWithTestUser, db } = await setup({
			organizationHooks: {
				beforeCancelInvitation: async () => {
					markReady();
					await wait;
				},
			},
		});
		const { headers: ownerHeaders, user } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Cancel revalidation",
			slug: "cancel-revalidation",
			fetchOptions: { headers: ownerHeaders },
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers: ownerHeaders },
		});
		const canceled = client.organization.cancelInvitation({
			invitationId: String(invite.data!.id),
			fetchOptions: { headers: ownerHeaders },
		});
		await ready;
		await db.delete({
			model: "member",
			where: [
				{ field: "organizationId", value: org.data!.id },
				{ field: "userId", value: user.id },
			],
		});
		release();
		expect((await canceled).error?.code).toBe("MEMBER_NOT_FOUND");
		expect(
			await db.findOne<{ status: string }>({
				model: "invitation",
				where: [{ field: "id", value: invite.data!.id }],
			}),
		).toEqual(expect.objectContaining({ status: "pending" }));
	});

	it("does not create a replacement invitation when acceptance wins a re-invite cancellation race", async () => {
		let holdReinvite = false;
		let markReinviteReady!: () => void;
		let releaseReinvite!: () => void;
		const reinviteReady = new Promise<void>((resolve) => {
			markReinviteReady = resolve;
		});
		const reinviteRelease = new Promise<void>((resolve) => {
			releaseReinvite = resolve;
		});
		const { client, signInWithTestUser, signInWithUser, db } = await setup({
			cancelPendingInvitationsOnReInvite: true,
			organizationHooks: {
				beforeCreateInvitation: async () => {
					if (holdReinvite) {
						markReinviteReady();
						await reinviteRelease;
					}
				},
			},
		});
		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Reinvite race",
			slug: "reinvite-race",
			fetchOptions: { headers: ownerHeaders },
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers: ownerHeaders },
		});
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);

		holdReinvite = true;
		const reinvite = client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers: ownerHeaders },
		});
		await reinviteReady;
		const accepted = await client.organization.acceptInvitation({
			invitationId: String(invite.data!.id),
			fetchOptions: { headers: inviteeHeaders },
		});
		expect(accepted.error).toBeNull();
		releaseReinvite();
		const rejectedReinvite = await reinvite;
		expect(rejectedReinvite.data).toBeNull();
		expect(rejectedReinvite.error?.code).toBe(
			"USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
		);

		const invitations = await db.findMany<{ id: string; status: string }>({
			model: "invitation",
			where: [
				{ field: "email", value: INVITEE_EMAIL },
				{ field: "organizationId", value: org.data!.id },
			],
		});
		expect(invitations).toEqual([
			expect.objectContaining({ id: invite.data!.id, status: "accepted" }),
		]);
	});

	it("replaces a pending invitation at the limit without consuming another slot", async () => {
		const { client, signInWithTestUser, db } = await setup({
			invitationLimit: 1,
			cancelPendingInvitationsOnReInvite: true,
		});
		const { headers } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Net zero replacement",
			slug: "net-zero-replacement",
			fetchOptions: { headers },
		});
		const original = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers },
		});
		const replacement = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers },
		});
		expect(replacement.error).toBeNull();
		expect(replacement.data?.id).not.toBe(original.data?.id);
		const invitations = await db.findMany<{ id: string; status: string }>({
			model: "invitation",
			where: [{ field: "organizationId", value: org.data!.id }],
		});
		expect(invitations.filter((invitation) => invitation.status === "pending")).toHaveLength(1);
		expect(
			invitations.find((invitation) => invitation.id === original.data!.id)?.status,
		).toBe("canceled");
	});

	it("repairs duplicate pending invitations while resending deterministically", async () => {
		const { client, signInWithTestUser, db } = await setup();
		const { headers, user } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Duplicate pending repair",
			slug: "duplicate-pending-repair",
			fetchOptions: { headers },
		});
		const original = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers },
		});
		const duplicate = await db.create<{ id: string }>({
			model: "invitation",
			data: {
				email: INVITEE_EMAIL,
				role: "member",
				organizationId: org.data!.id,
				inviterId: user.id,
				status: "pending",
				expiresAt: new Date(Date.now() + 60_000),
				createdAt: new Date(),
			},
		});
		const resent = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			resend: true,
			fetchOptions: { headers },
		});
		expect(resent.error).toBeNull();
		const invitations = await db.findMany<{ id: string; status: string }>({
			model: "invitation",
			where: [
				{ field: "organizationId", value: org.data!.id },
				{ field: "email", value: INVITEE_EMAIL },
			],
		});
		expect(invitations.filter((invitation) => invitation.status === "pending")).toHaveLength(1);
		expect(invitations.filter((invitation) => invitation.status === "canceled")).toHaveLength(1);
		expect([original.data!.id, duplicate.id]).toContain(resent.data?.id);
	});

	it("rolls back acceptance when a dynamic role is deleted after preflight", async () => {
		let holdAcceptance = false;
		let markAcceptanceReady!: () => void;
		let releaseAcceptance!: () => void;
		const acceptanceReady = new Promise<void>((resolve) => {
			markAcceptanceReady = resolve;
		});
		const acceptanceRelease = new Promise<void>((resolve) => {
			releaseAcceptance = resolve;
		});
		const { client, signInWithTestUser, signInWithUser, db } = await setup({
			dynamicAccessControl: { enabled: true },
			organizationHooks: {
				beforeAcceptInvitation: async () => {
					if (holdAcceptance) {
						markAcceptanceReady();
						await acceptanceRelease;
					}
				},
			},
		});
		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Dynamic role acceptance",
			slug: "dynamic-role-acceptance",
			fetchOptions: { headers: ownerHeaders },
		});
		await db.create({
			model: "organizationRole",
			data: {
				organizationId: org.data!.id,
				role: "support",
				permission: JSON.stringify({ organization: ["read"] }),
				createdAt: new Date(),
			},
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "support",
			fetchOptions: { headers: ownerHeaders },
		} as never);
		expect(invite.error).toBeNull();
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders, res: invitee } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);

		holdAcceptance = true;
		const acceptance = client.organization.acceptInvitation({
			invitationId: String(invite.data!.id),
			fetchOptions: { headers: inviteeHeaders },
		});
		await acceptanceReady;
		await db.delete({
			model: "organizationRole",
			where: [
				{ field: "organizationId", value: org.data!.id },
				{ field: "role", value: "support" },
			],
		});
		releaseAcceptance();
		const rejectedAcceptance = await acceptance;
		expect(rejectedAcceptance.data).toBeNull();
		expect(rejectedAcceptance.error?.code).toBe("ROLE_NOT_FOUND");

		const [persistedInvitation, membership] = await Promise.all([
			db.findOne<{ status: string }>({
				model: "invitation",
				where: [{ field: "id", value: invite.data!.id }],
			}),
			db.findOne<{ userId: string }>({
				model: "member",
				where: [
					{ field: "organizationId", value: org.data!.id },
					{ field: "userId", value: invitee.user.id },
				],
			}),
		]);
		expect(persistedInvitation?.status).toBe("pending");
		expect(membership).toBeNull();
	});

	it("does not create an invitation when a dynamic role is deleted after preflight", async () => {
		let holdCreation = false;
		let markCreationReady!: () => void;
		let releaseCreation!: () => void;
		const creationReady = new Promise<void>((resolve) => {
			markCreationReady = resolve;
		});
		const creationRelease = new Promise<void>((resolve) => {
			releaseCreation = resolve;
		});
		const { client, signInWithTestUser, db } = await setup({
			dynamicAccessControl: { enabled: true },
			organizationHooks: {
				beforeCreateInvitation: async () => {
					if (holdCreation) {
						markCreationReady();
						await creationRelease;
					}
				},
			},
		});
		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Dynamic role creation",
			slug: "dynamic-role-creation",
			fetchOptions: { headers: ownerHeaders },
		});
		await db.create({
			model: "organizationRole",
			data: {
				organizationId: org.data!.id,
				role: "support",
				permission: JSON.stringify({ organization: ["read"] }),
				createdAt: new Date(),
			},
		});

		holdCreation = true;
		const creation = client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "support",
			fetchOptions: { headers: ownerHeaders },
		} as never);
		await creationReady;
		await db.delete({
			model: "organizationRole",
			where: [
				{ field: "organizationId", value: org.data!.id },
				{ field: "role", value: "support" },
			],
		});
		releaseCreation();
		const rejectedCreation = await creation;
		expect(rejectedCreation.data).toBeNull();
		expect(rejectedCreation.error?.code).toBe("ROLE_NOT_FOUND");
		expect(
			await db.findOne({
				model: "invitation",
				where: [
					{ field: "organizationId", value: org.data!.id },
					{ field: "email", value: INVITEE_EMAIL },
				],
			}),
		).toBeNull();
	});

	it("rejects invitation creation when the inviter is revoked while a hook waits", async () => {
		let markReady!: () => void;
		let release!: () => void;
		const ready = new Promise<void>((resolve) => {
			markReady = resolve;
		});
		const wait = new Promise<void>((resolve) => {
			release = resolve;
		});
		const { client, signInWithTestUser, db } = await setup({
			organizationHooks: {
				beforeCreateInvitation: async () => {
					markReady();
					await wait;
				},
			},
		});
		const { headers, user } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Revoked inviter",
			slug: "revoked-inviter",
			fetchOptions: { headers },
		});
		const creation = client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers },
		});
		await ready;
		await db.delete({
			model: "member",
			where: [
				{ field: "organizationId", value: org.data!.id },
				{ field: "userId", value: user.id },
			],
		});
		release();
		const rejectedCreation = await creation;
		expect(rejectedCreation.data).toBeNull();
		expect(rejectedCreation.error?.code).toBe("MEMBER_NOT_FOUND");
		expect(
			await db.findOne({
				model: "invitation",
				where: [
					{ field: "organizationId", value: org.data!.id },
					{ field: "email", value: INVITEE_EMAIL },
				],
			}),
		).toBeNull();
	});

	it("uses dynamic invitation permission from the owning transaction", async () => {
		const ac = createAccessControl({ ...defaultStatements });
		const { auth, signInWithTestUser, db } = await getTestInstance({
			plugins: [
				organization({
					ac,
					dynamicAccessControl: { enabled: true },
					async sendInvitationEmail() {},
				}),
			],
		});
		const { headers, user } = await signInWithTestUser();
		const org = await auth.api.createOrganization({
			headers,
			body: { name: "Transaction role", slug: "transaction-role" },
		});
		await db.create({
			model: "organizationRole",
			data: {
				organizationId: org.id,
				role: "delegator",
				permission: JSON.stringify({}),
				createdAt: new Date(),
			},
		});
		await db.update({
			model: "member",
			where: [
				{ field: "organizationId", value: org.id },
				{ field: "userId", value: user.id },
			],
			update: { role: "delegator" },
		});
		const context = await auth.$context;

		const invitation = await runWithTransaction(context.adapter, async () => {
			const transaction = await getCurrentAdapter(context.adapter);
			await transaction.update({
				model: "organizationRole",
				where: [
					{ field: "organizationId", value: org.id },
					{ field: "role", value: "delegator" },
				],
				update: { permission: JSON.stringify({ invitation: ["create"] }) },
			});
			return auth.api.createInvitation({
				headers,
				body: {
					organizationId: org.id,
					email: "transaction-local-permission@example.test",
					role: "member",
				},
			});
		});
		expect(invitation.email).toBe("transaction-local-permission@example.test");
	});

	it("serializes concurrent invitations for the same email after both preflights pass", async () => {
		let hookCalls = 0;
		let markFirstReady!: () => void;
		let markSecondReady!: () => void;
		let releaseFirst!: () => void;
		let releaseSecond!: () => void;
		const firstReady = new Promise<void>((resolve) => {
			markFirstReady = resolve;
		});
		const secondReady = new Promise<void>((resolve) => {
			markSecondReady = resolve;
		});
		const firstRelease = new Promise<void>((resolve) => {
			releaseFirst = resolve;
		});
		const secondRelease = new Promise<void>((resolve) => {
			releaseSecond = resolve;
		});
		const { client, signInWithTestUser, db } = await setup({
			organizationHooks: {
				beforeCreateInvitation: async () => {
					hookCalls += 1;
					if (hookCalls === 1) {
						markFirstReady();
						await firstRelease;
					} else {
						markSecondReady();
						await secondRelease;
					}
				},
			},
		});
		const { headers } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Same email",
			slug: "same-email",
			fetchOptions: { headers },
		});
		const first = client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers },
		});
		await firstReady;
		const second = client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers },
		});
		await secondReady;
		releaseFirst();
		const created = await first;
		expect(created.error).toBeNull();
		releaseSecond();
		const rejected = await second;
		expect(rejected.data).toBeNull();
		expect(rejected.error?.code).toBe(
			"USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION",
		);
		expect(
			await db.count({
				model: "invitation",
				where: [
					{ field: "organizationId", value: org.data!.id },
					{ field: "email", value: INVITEE_EMAIL },
				],
			}),
		).toBe(1);
	});

	it("enforces the invitation limit after concurrent preflights", async () => {
		let hookCalls = 0;
		let markFirstReady!: () => void;
		let markSecondReady!: () => void;
		let releaseFirst!: () => void;
		let releaseSecond!: () => void;
		const firstReady = new Promise<void>((resolve) => (markFirstReady = resolve));
		const secondReady = new Promise<void>((resolve) => (markSecondReady = resolve));
		const firstRelease = new Promise<void>((resolve) => (releaseFirst = resolve));
		const secondRelease = new Promise<void>((resolve) => (releaseSecond = resolve));
		const { client, signInWithTestUser } = await setup({
			invitationLimit: 1,
			organizationHooks: {
				beforeCreateInvitation: async () => {
					hookCalls += 1;
					if (hookCalls === 1) {
						markFirstReady();
						await firstRelease;
					} else {
						markSecondReady();
						await secondRelease;
					}
				},
			},
		});
		const { headers } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Last slot",
			slug: "last-slot",
			fetchOptions: { headers },
		});
		const first = client.organization.inviteMember({
			organizationId: org.data!.id,
			email: "first-slot@example.test",
			role: "member",
			fetchOptions: { headers },
		});
		await firstReady;
		const second = client.organization.inviteMember({
			organizationId: org.data!.id,
			email: "second-slot@example.test",
			role: "member",
			fetchOptions: { headers },
		});
		await secondReady;
		releaseFirst();
		expect((await first).error).toBeNull();
		releaseSecond();
		const rejected = await second;
		expect(rejected.data).toBeNull();
		expect(rejected.error?.code).toBe("INVITATION_LIMIT_REACHED");
	});

	it("runs after-accept once after the accepting transaction commits", async () => {
		let afterAcceptCalls = 0;
		const { client, signInWithTestUser, signInWithUser, db } = await setup({
			organizationHooks: {
				afterAcceptInvitation: async () => {
					afterAcceptCalls += 1;
				},
			},
		});
		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "After accept",
			slug: "after-accept",
			fetchOptions: { headers: ownerHeaders },
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers: ownerHeaders },
		});
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);

		const accepted = await client.organization.acceptInvitation({
			invitationId: String(invite.data!.id),
			fetchOptions: { headers: inviteeHeaders },
		});
		expect(accepted.error).toBeNull();
		expect(afterAcceptCalls).toBe(1);
		const persisted = await db.findOne<{ status: string }>({
			model: "invitation",
			where: [{ field: "id", value: invite.data!.id }],
		});
		expect(persisted?.status).toBe("accepted");
	});

	it("publishes the committed successor then surfaces an after-accept hook failure", async () => {
		const hookFailure = new Error("after accept failure");
		const { auth, client, cookieSetter, signInWithTestUser, signInWithUser, db } =
			await setupManaged({
				organizationHooks: {
					afterAcceptInvitation: async () => {
						throw hookFailure;
					},
				},
			});
		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Throwing after accept",
			slug: "throwing-after-accept",
			fetchOptions: {
				headers: ownerHeaders,
				onSuccess: cookieSetter(ownerHeaders),
			},
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			fetchOptions: { headers: ownerHeaders },
		});
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);
		const sourceSession = await auth.api.getSession({ headers: inviteeHeaders });
		let publishedCookie: string | null = null;
		const accepted = await client.organization.acceptInvitation({
			invitationId: String(invite.data!.id),
			fetchOptions: {
				headers: inviteeHeaders,
				onResponse: (response) => {
					publishedCookie = response.response.headers.get("set-cookie");
				},
			},
		});

		expect(accepted.data).toBeNull();
		expect(accepted.error?.status).toBe(500);
		expect(publishedCookie).toContain("clearance.session_token=");
		expect(publishedCookie).not.toContain("Max-Age=0");
		const successorToken = parseSetCookieHeader(publishedCookie || "")
			.get("clearance.session_token")
			?.value;
		expect(successorToken).toBeTruthy();
		const successorSession = await auth.api.getSession({
			headers: new Headers({
				cookie: `clearance.session_token=${successorToken}`,
			}),
		});
		expect(successorSession?.session.activeOrganizationId).toBe(org.data!.id);
		expect(successorSession?.session.token).not.toBe(
			sourceSession?.session.token,
		);
		const sourceUserId = sourceSession?.user.id;
		expect(sourceUserId).toBeTruthy();

		const [persistedInvitation, persistedMembership] = await Promise.all([
			db.findOne<{ status: string }>({
				model: "invitation",
				where: [{ field: "id", value: invite.data!.id }],
			}),
			db.findOne<{ organizationId: string; userId: string }>({
				model: "member",
				where: [
					{ field: "organizationId", value: org.data!.id },
					{ field: "userId", value: sourceUserId! },
				],
			}),
		]);
		expect(persistedInvitation?.status).toBe("accepted");
		expect(persistedMembership).toBeTruthy();
	});
});

/**
 * An invitation's teamId must be scoped to the invitation's organization at
 * creation AND acceptance, and team read endpoints must verify organization
 * membership rather than relying on a teamMember row alone.
 */
describe("invitation teamId must belong to the invitation's organization", async () => {
	const OTHER_USER_EMAIL = "user-b@example.com";
	const INVITEE_EMAIL = "invitee@example.com";
	const PASSWORD = "test-password-123";

	function setup() {
		return getTestInstance(
			{
				databaseHooks: {
					user: {
						create: {
							before: async (user) => ({
								data: { ...user, emailVerified: true },
							}),
						},
					},
				},
				plugins: [
					organization({
						teams: { enabled: true },
						async sendInvitationEmail() {},
					}),
				],
			},
			{
				clientOptions: {
					plugins: [organizationClient({ teams: { enabled: true } })],
				},
			},
		);
	}

	it("rejects creating an invitation with a teamId from another organization", async () => {
		const { client, signInWithTestUser, signInWithUser, cookieSetter } =
			await setup();

		// First org owner (default test user) creates an org and a team.
		const { headers: ownerHeaders } = await signInWithTestUser();
		const firstOrg = await client.organization.create({
			name: "Org A",
			slug: "org-a",
			fetchOptions: {
				headers: ownerHeaders,
				onSuccess: cookieSetter(ownerHeaders),
			},
		});
		const firstTeam = await client.organization.createTeam({
			name: "Team A",
			organizationId: firstOrg.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		const firstTeamId = firstTeam.data!.id;

		// A second user creates their own organization.
		await client.signUp.email({
			email: OTHER_USER_EMAIL,
			password: PASSWORD,
			name: "User B",
		});
		const { headers: secondUserHeaders } = await signInWithUser(
			OTHER_USER_EMAIL,
			PASSWORD,
		);
		const otherOrg = await client.organization.create({
			name: "Org B",
			slug: "org-b",
			fetchOptions: {
				headers: secondUserHeaders,
				onSuccess: cookieSetter(secondUserHeaders),
			},
		});

		// The second user invites into their own org with a teamId from the first org.
		const invite = await client.organization.inviteMember({
			organizationId: otherOrg.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			teamId: firstTeamId,
			fetchOptions: { headers: secondUserHeaders },
		});

		expect(invite.data).toBeNull();
		expect(invite.error?.code).toBe("TEAM_NOT_FOUND");
	});

	it("rejects accepting an invitation whose teamId points at another org", async () => {
		const { client, signInWithTestUser, signInWithUser, cookieSetter, db } =
			await setup();

		// First org + team.
		const { headers: ownerHeaders } = await signInWithTestUser();
		const firstOrg = await client.organization.create({
			name: "Org A",
			slug: "org-a",
			fetchOptions: {
				headers: ownerHeaders,
				onSuccess: cookieSetter(ownerHeaders),
			},
		});
		const firstTeam = await client.organization.createTeam({
			name: "Team A",
			organizationId: firstOrg.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		const firstTeamId = firstTeam.data!.id;

		// Second org with its OWN team so the invitation passes the create-side check.
		await client.signUp.email({
			email: OTHER_USER_EMAIL,
			password: PASSWORD,
			name: "User B",
		});
		const { headers: secondUserHeaders } = await signInWithUser(
			OTHER_USER_EMAIL,
			PASSWORD,
		);
		const otherOrg = await client.organization.create({
			name: "Org B",
			slug: "org-b",
			fetchOptions: {
				headers: secondUserHeaders,
				onSuccess: cookieSetter(secondUserHeaders),
			},
		});
		const otherTeam = await client.organization.createTeam({
			name: "Team B",
			organizationId: otherOrg.data!.id,
			fetchOptions: { headers: secondUserHeaders },
		});

		const invite = await client.organization.inviteMember({
			organizationId: otherOrg.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			teamId: otherTeam.data!.id,
			fetchOptions: { headers: secondUserHeaders },
		});
		const invitationId = String(invite.data!.id);

		// Update the persisted invitation directly in the database to point at
		// the first org's team, standing in for a stale or moved team that the
		// create-side check did not cover.
		await db.update({
			model: "invitation",
			where: [{ field: "id", value: invitationId }],
			update: { teamId: firstTeamId },
		});

		// The invited recipient accepts.
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);
		const accept = await client.organization.acceptInvitation({
			invitationId,
			fetchOptions: { headers: inviteeHeaders },
		});

		expect(accept.error?.code).toBe("TEAM_NOT_FOUND");

		// No teamMember row may exist against the first org's team.
		const firstTeamMembers = await db.findMany({
			model: "teamMember",
			where: [{ field: "teamId", value: firstTeamId }],
		});
		expect(firstTeamMembers.length).toBe(0);
	});

	it("uses the accepted invitation team ids if they change after the initial read", async () => {
		const PASSWORD = "test-password-123";
		const INVITEE_EMAIL = "accepted-row-invitee@example.com";
		let db: Awaited<ReturnType<typeof getTestInstance>>["db"];
		let replacementTeamId = "";

		const instance = await getTestInstance(
			{
				databaseHooks: {
					user: {
						create: {
							before: async (user) => ({
								data: { ...user, emailVerified: true },
							}),
						},
					},
				},
				plugins: [
					organization({
						teams: { enabled: true },
						async sendInvitationEmail() {},
						organizationHooks: {
							beforeAcceptInvitation: async ({ invitation }) => {
								await db.update({
									model: "invitation",
									where: [{ field: "id", value: invitation.id }],
									update: { teamId: replacementTeamId },
								});
							},
						},
					}),
				],
			},
			{
				clientOptions: {
					plugins: [organizationClient({ teams: { enabled: true } })],
				},
			},
		);
		db = instance.db;
		const { client, signInWithTestUser, signInWithUser, cookieSetter } =
			instance;

		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Org A",
			slug: "org-a",
			fetchOptions: {
				headers: ownerHeaders,
				onSuccess: cookieSetter(ownerHeaders),
			},
		});
		const staleTeam = await client.organization.createTeam({
			name: "Stale Team",
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		const currentTeam = await client.organization.createTeam({
			name: "Current Team",
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		replacementTeamId = currentTeam.data!.id;

		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			teamId: staleTeam.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		const invitationId = String(invite.data!.id);

		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders, res: inviteeRes } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);

		const accept = await client.organization.acceptInvitation({
			invitationId,
			fetchOptions: { headers: inviteeHeaders },
		});

		expect(accept.error).toBeNull();
		expect(accept.data?.invitation.teamId).toBe(currentTeam.data!.id);

		const teamMembers = await db.findMany<{ teamId: string }>({
			model: "teamMember",
			where: [{ field: "userId", value: inviteeRes.user.id }],
		});
		expect(teamMembers.map((m) => m.teamId)).toEqual([currentTeam.data!.id]);
	});

	it("keeps the invitation pending when a referenced team no longer exists", async () => {
		const { client, signInWithTestUser, signInWithUser, cookieSetter, db } =
			await setup();

		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Org A",
			slug: "org-a",
			fetchOptions: {
				headers: ownerHeaders,
				onSuccess: cookieSetter(ownerHeaders),
			},
		});
		const invitedTeam = await client.organization.createTeam({
			name: "Team A",
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		await client.organization.createTeam({
			name: "Team B",
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});

		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			teamId: invitedTeam.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		const invitationId = String(invite.data!.id);

		await db.delete({
			model: "team",
			where: [{ field: "id", value: invitedTeam.data!.id }],
		});

		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);
		const accept = await client.organization.acceptInvitation({
			invitationId,
			fetchOptions: { headers: inviteeHeaders },
		});

		expect(accept.error?.code).toBe("TEAM_NOT_FOUND");

		const invitationAfter = await db.findOne<{ status: string }>({
			model: "invitation",
			where: [{ field: "id", value: invitationId }],
		});
		expect(invitationAfter?.status).toBe("pending");
	});

	it("rolls back acceptance when the team disappears after its initial read", async () => {
		const { auth, client, signInWithTestUser, signInWithUser, db } =
			await setup();
		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Admission race",
			slug: "admission-race",
			fetchOptions: { headers: ownerHeaders },
		});
		const team = await client.organization.createTeam({
			name: "Admission race team",
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			teamId: team.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders, res: invitee } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);
		const sourceSession = await auth.api.getSession({ headers: inviteeHeaders });
		const context = await auth.$context;
		const originalTransaction = context.adapter.transaction;
		let removedAfterInitialTeamRead = false;
		context.adapter.transaction = async (callback) =>
			originalTransaction(async (transaction) => {
				const transactionWithDeletion = new Proxy(transaction, {
					get(target, property, receiver) {
						if (property !== "findOne") {
							return Reflect.get(target, property, receiver);
						}
						return async (...args: Parameters<typeof transaction.findOne>) => {
							const [input] = args;
							const result = await Reflect.apply(
								target.findOne,
								target,
								args,
							);
							if (
								!removedAfterInitialTeamRead &&
								input.model === "team" &&
								input.where.some(
									(condition) =>
										condition.field === "id" &&
										condition.value === team.data!.id,
								) &&
								result
							) {
								removedAfterInitialTeamRead = true;
								await target.delete({
									model: "team",
									where: [{ field: "id", value: team.data!.id }],
								});
							}
							return result;
						};
					},
				});
				return callback(transactionWithDeletion);
			});
		try {
			const accepted = await client.organization.acceptInvitation({
				invitationId: String(invite.data!.id),
				fetchOptions: { headers: inviteeHeaders },
			});
			expect(accepted.error?.code).toBe("TEAM_NOT_FOUND");
		} finally {
			context.adapter.transaction = originalTransaction;
		}
		expect(removedAfterInitialTeamRead).toBe(true);
		const [invitationAfter, membership, teamMembership, sessionAfter] =
			await Promise.all([
				db.findOne<{ status: string }>({
					model: "invitation",
					where: [{ field: "id", value: invite.data!.id }],
				}),
				db.findOne({
					model: "member",
					where: [
						{ field: "organizationId", value: org.data!.id },
						{ field: "userId", value: invitee.user.id },
					],
				}),
				db.findOne({
					model: "teamMember",
					where: [
						{ field: "teamId", value: team.data!.id },
						{ field: "userId", value: invitee.user.id },
					],
				}),
				auth.api.getSession({ headers: inviteeHeaders }),
			]);
		expect(invitationAfter?.status).toBe("pending");
		expect(membership).toBeNull();
		expect(teamMembership).toBeNull();
		expect(sessionAfter?.session.token).toBe(sourceSession?.session.token);
		expect(sessionAfter?.session.activeOrganizationId).toBe(
			sourceSession?.session.activeOrganizationId,
		);
	});

	it("clears the removed team from a pending invitation so it degrades to an organization-level invitation", async () => {
		const { client, signInWithTestUser, signInWithUser, cookieSetter, db } =
			await setup();

		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Org A",
			slug: "org-a",
			fetchOptions: {
				headers: ownerHeaders,
				onSuccess: cookieSetter(ownerHeaders),
			},
		});
		const invitedTeam = await client.organization.createTeam({
			name: "Team A",
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		await client.organization.createTeam({
			name: "Team B",
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});

		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			teamId: invitedTeam.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		const invitationId = String(invite.data!.id);

		const removed = await client.organization.removeTeam({
			teamId: invitedTeam.data!.id,
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		expect(removed.error).toBeNull();

		const invitationAfter = await db.findOne<{
			status: string;
			teamId: string | null;
		}>({
			model: "invitation",
			where: [{ field: "id", value: invitationId }],
		});
		expect(invitationAfter?.status).toBe("pending");
		expect(invitationAfter?.teamId ?? null).toBeNull();

		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders, res: inviteeRes } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);
		const accept = await client.organization.acceptInvitation({
			invitationId,
			fetchOptions: { headers: inviteeHeaders },
		});

		expect(accept.error).toBeNull();
		expect(accept.data?.member).toBeDefined();

		const teamMembers = await db.findMany({
			model: "teamMember",
			where: [{ field: "userId", value: inviteeRes.user.id }],
		});
		expect(teamMembers.length).toBe(0);
	});

	it("keeps the remaining teams on a multi-team invitation when one team is removed", async () => {
		const { client, signInWithTestUser, signInWithUser, cookieSetter, db } =
			await setup();

		const { headers: ownerHeaders } = await signInWithTestUser();
		const org = await client.organization.create({
			name: "Org A",
			slug: "org-a",
			fetchOptions: {
				headers: ownerHeaders,
				onSuccess: cookieSetter(ownerHeaders),
			},
		});
		const teamA = await client.organization.createTeam({
			name: "Team A",
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		const teamB = await client.organization.createTeam({
			name: "Team B",
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});

		const invite = await client.organization.inviteMember({
			organizationId: org.data!.id,
			email: INVITEE_EMAIL,
			role: "member",
			teamId: [teamA.data!.id, teamB.data!.id],
			fetchOptions: { headers: ownerHeaders },
		});
		const invitationId = String(invite.data!.id);

		const removed = await client.organization.removeTeam({
			teamId: teamA.data!.id,
			organizationId: org.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		expect(removed.error).toBeNull();

		const invitationAfter = await db.findOne<{
			status: string;
			teamId: string | null;
		}>({
			model: "invitation",
			where: [{ field: "id", value: invitationId }],
		});
		expect(invitationAfter?.status).toBe("pending");
		expect(invitationAfter?.teamId).toBe(teamB.data!.id);

		await client.signUp.email({
			email: INVITEE_EMAIL,
			password: PASSWORD,
			name: "Invitee",
		});
		const { headers: inviteeHeaders, res: inviteeRes } = await signInWithUser(
			INVITEE_EMAIL,
			PASSWORD,
		);
		const accept = await client.organization.acceptInvitation({
			invitationId,
			fetchOptions: { headers: inviteeHeaders },
		});

		expect(accept.error).toBeNull();

		const teamMembers = await db.findMany<{ teamId: string }>({
			model: "teamMember",
			where: [{ field: "userId", value: inviteeRes.user.id }],
		});
		expect(teamMembers.map((m) => m.teamId)).toEqual([teamB.data!.id]);
	});

	it("does not list another organization's team members from a mismatched teamMember row", async () => {
		const { client, signInWithTestUser, signInWithUser, cookieSetter, db } =
			await setup();

		// First org + team.
		const { headers: ownerHeaders } = await signInWithTestUser();
		const firstOrg = await client.organization.create({
			name: "Org A",
			slug: "org-a",
			fetchOptions: {
				headers: ownerHeaders,
				onSuccess: cookieSetter(ownerHeaders),
			},
		});
		const firstTeam = await client.organization.createTeam({
			name: "Team A",
			organizationId: firstOrg.data!.id,
			fetchOptions: { headers: ownerHeaders },
		});
		const firstTeamId = firstTeam.data!.id;

		// The second user is NOT a member of the first organization.
		await client.signUp.email({
			email: OTHER_USER_EMAIL,
			password: PASSWORD,
			name: "User B",
		});
		const { headers: secondUserHeaders, res: secondUserRes } =
			await signInWithUser(OTHER_USER_EMAIL, PASSWORD);

		// Insert a teamMember row directly in the database tying the second user
		// to the first org's team, standing in for a stale or mismatched row.
		await db.create({
			model: "teamMember",
			data: {
				teamId: firstTeamId,
				userId: secondUserRes.user.id,
				createdAt: new Date(),
			},
		});

		const list = await client.organization.listTeamMembers({
			query: { teamId: firstTeamId },
			fetchOptions: { headers: secondUserHeaders },
		});

		expect(list.data).toBeNull();
		expect(list.error?.code).toBe("USER_IS_NOT_A_MEMBER_OF_THE_TEAM");
	});
});
