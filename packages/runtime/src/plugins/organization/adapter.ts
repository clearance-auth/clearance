import type { AuthContext, GenericEndpointContext } from "@clearance/core";
import {
	AfterTransactionHookError,
	getCurrentDBAdapterAsyncLocalStorage,
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import type {
	DBTransactionAdapter,
	WhereOperator,
} from "@clearance/core/db/adapter";
import { APIError, ClearanceError } from "@clearance/core/error";
import { filterOutputFields } from "@clearance/core/utils/db";
import { parseJSON } from "../../client/parser";
import type { InferAdditionalFieldsFromPluginOptions } from "../../db";
import {
	digestSessionRefreshSecret,
	SESSION_CREDENTIAL_MODEL,
	type SessionCredential,
} from "../../db/session-credential";
import { readInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { readInternalCredentialAuthority } from "../../internal/credential-authority";
import { captureInternalSessionIssuanceContext } from "../../internal/session-issuance-context";
import { SESSION_ASSURANCE_RESERVED_FIELDS } from "../../security/session-assurance";
import type { Session, User } from "../../types";
import { getDate } from "../../utils/date";
import type {
	InferInvitation,
	InferMember,
	InferOrganization,
	InferTeam,
	InvitationInput,
	Member,
	MemberInput,
	OrganizationInput,
	Team,
	TeamInput,
	TeamMember,
} from "./schema";
import type { OrganizationOptions } from "./types";

export type ActiveOrganizationTransitionOrchestration = Readonly<{
	/**
	 * Runs as the first operation inside the owning transition transaction,
	 * before source-session or policy reads can establish a repeatable-read
	 * snapshot. Lifecycle routes use this seam to acquire their organization
	 * mutation lock before any authorization or invariant check.
	 */
	beforeCapture?: (() => void | Promise<void>) | undefined;
	/**
	 * Runs after managed source authority has been captured and while its owning
	 * transaction is still active. Lifecycle routes use this seam for membership
	 * or organization mutations that must commit with the successor session.
	 * In unmanaged mode it runs immediately before the legacy in-place update.
	 */
	afterCapture?: (() => void | Promise<void>) | undefined;
	/**
	 * Trusted server callers can provide the source cookie intent when no request
	 * cookie is available. When omitted, the signed request marker is authoritative
	 * and absence means a remembered session.
	 */
	dontRememberMe?: boolean | undefined;
	/**
	 * Exposes the prepared successor secret to an outer transaction owner. The
	 * owner must discard it on rollback and may recover it only when its own
	 * boundary reports AfterTransactionHookError after commit.
	 */
	onSuccessorPrepared?: ((successor: Session) => void) | undefined;
	/**
	 * Re-throw a post-commit transaction hook failure after the successor has
	 * been prepared. Omit this to preserve the legacy recovery behavior, which
	 * returns the committed successor when one is available.
	 */
	propagateAfterTransactionHookError?: boolean | undefined;
}>;

export const MANAGED_ORGANIZATION_SECONDARY_SESSION_TRANSITION_UNSUPPORTED = {
	code: "MANAGED_ORGANIZATION_SECONDARY_SESSION_TRANSITION_UNSUPPORTED",
	message:
		"Managed organization transitions require database-backed sessions when secondary storage is configured",
} as const;

/**
 * Managed session replacement needs one rollback boundary for source revocation
 * and successor publication. Secondary-authoritative session storage cannot
 * provide that boundary, so every lifecycle route must reject it before hooks
 * or request-derived transition work begins.
 */
export function assertManagedOrganizationTransitionSupported(
	context: AuthContext,
): void {
	if (
		readInternalAuthenticationPolicy(context.options) &&
		context.options.secondaryStorage &&
		context.options.session?.storeSessionInDatabase !== true
	) {
		throw APIError.from(
			"INTERNAL_SERVER_ERROR",
			MANAGED_ORGANIZATION_SECONDARY_SESSION_TRANSITION_UNSUPPORTED,
		);
	}
}

type ActiveManagedTransition = { reentrantAttempted: boolean };
const activeManagedTransitions = new WeakMap<
	object,
	Map<string, ActiveManagedTransition>
>();

/**
 * Resolves the configured per-team member cap to a concrete number for a given
 * team-add. Returns `undefined` only when no cap is configured. Throws when the
 * cap is a function but no session is available to evaluate it, so a sessionless
 * server-side add fails closed instead of silently bypassing the limit.
 */
export async function resolveMaximumMembersPerTeam(
	teams: OrganizationOptions["teams"],
	context: {
		teamId: string;
		organizationId: string;
		session: { user: User; session: Session } | null;
	},
): Promise<number | undefined> {
	const maximumMembersPerTeam = teams?.maximumMembersPerTeam;
	if (maximumMembersPerTeam === undefined) return undefined;
	if (typeof maximumMembersPerTeam === "number") return maximumMembersPerTeam;
	if (!context.session) {
		throw new ClearanceError(
			"`teams.maximumMembersPerTeam` is configured as a function but no session is available to evaluate it. Provide a session-bearing request or configure a numeric limit.",
		);
	}
	return await maximumMembersPerTeam({
		teamId: context.teamId,
		session: context.session,
		organizationId: context.organizationId,
	});
}

export const getOrgAdapter = <O extends OrganizationOptions>(
	context: AuthContext,
	options?: O | undefined,
) => {
	const baseAdapter = context.adapter;
	const orgAdditionalFields = options?.schema?.organization?.additionalFields;
	const memberAdditionalFields = options?.schema?.member?.additionalFields;
	const invitationAdditionalFields =
		options?.schema?.invitation?.additionalFields;
	const teamAdditionalFields = options?.schema?.team?.additionalFields;
	const hasAtomicTeamTransaction = async () => {
		if (typeof baseAdapter.options?.adapterConfig.transaction === "function") {
			return true;
		}
		// A transaction adapter can omit the root's options. Locate *its* active
		// owner rather than trusting the current ALS root: an unrelated nested
		// transaction may be current while this adapter is owned by a parent.
		type TransactionOwner = {
			rootAdapter: DBTransactionAdapter;
			adapter: DBTransactionAdapter;
			activeTransactions?: ReadonlyMap<object, TransactionOwner>;
			isTransactionActive: boolean;
			parent?: TransactionOwner;
		};
		const store = (await getCurrentDBAdapterAsyncLocalStorage()).getStore() as
			| TransactionOwner
			| undefined;
		const findOwner = (current: TransactionOwner | undefined): TransactionOwner | undefined => {
			for (let owner = current; owner; owner = owner.parent) {
				const registered = owner.activeTransactions?.get(baseAdapter);
				if (registered?.isTransactionActive) return registered;
				if (
					owner.isTransactionActive &&
					(owner.rootAdapter === baseAdapter || owner.adapter === baseAdapter)
				) {
					return owner;
				}
			}
			return undefined;
		};
		const owner = findOwner(store);
		return (
			typeof owner?.rootAdapter.options?.adapterConfig.transaction ===
			"function"
		);
	};
	const filterOrganizationOutput = <
		T extends Record<string, unknown> | null,
	>(organization: T): T => {
		const filtered = filterOutputFields(organization, orgAdditionalFields);
		if (!filtered) return filtered;
		const { updatedAt: _updatedAt, ...visible } = filtered;
		return visible as T;
	};
	const lockTeamMembership = async (
		adapter: DBTransactionAdapter,
		data: { organizationId: string; teamId: string },
	): Promise<
		| {
				status: "ready";
				organization: InferOrganization<O, false>;
				team: Team;
		  }
		| { status: "organizationNotFound" }
		| { status: "teamNotFound" }
	> => {
		// This must remain the first transaction operation. Locking the parent
		// serializes team deletion with every admission that depends on it.
		const organization = await adapter.update<InferOrganization<O, false>>({
			model: "organization",
			where: [{ field: "id", value: data.organizationId }],
			update: { updatedAt: new Date() },
		});
		if (!organization) return { status: "organizationNotFound" };
		const team = await adapter.update<Team>({
			model: "team",
			where: [{ field: "id", value: data.teamId }],
			update: { updatedAt: new Date() },
		});
		if (!team || team.organizationId !== data.organizationId) {
			return { status: "teamNotFound" };
		}
		return { status: "ready", organization, team };
	};
	const deduplicateTeamMemberPair = async (
		adapter: DBTransactionAdapter,
		data: { teamId: string; userId: string },
	): Promise<TeamMember | null> => {
		const members = await adapter.findMany<TeamMember>({
			model: "teamMember",
			where: [
				{ field: "teamId", value: data.teamId },
				{ field: "userId", value: data.userId },
			],
			sortBy: { field: "id", direction: "asc" },
		});
		const [member, ...duplicates] = members;
		for (const duplicate of duplicates) {
			await adapter.delete({
				model: "teamMember",
				where: [{ field: "id", value: duplicate.id }],
			});
		}
		return member ?? null;
	};
	const deduplicateTeamMembers = async (
		adapter: DBTransactionAdapter,
		teamId: string,
	): Promise<Map<string, TeamMember>> => {
		const members = await adapter.findMany<TeamMember>({
			model: "teamMember",
			where: [{ field: "teamId", value: teamId }],
			sortBy: { field: "id", direction: "asc" },
		});
		const membersByUserId = new Map<string, TeamMember>();
		for (const member of members) {
			if (!membersByUserId.has(member.userId)) {
				membersByUserId.set(member.userId, member);
				continue;
			}
			await adapter.delete({
				model: "teamMember",
				where: [{ field: "id", value: member.id }],
			});
		}
		return membersByUserId;
	};
	return {
		findOrganizationBySlug: async (
			slug: string,
		): Promise<InferOrganization<O> | null> => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const organization = await adapter.findOne<InferOrganization<O, false>>({
				model: "organization",
				where: [
					{
						field: "slug",
						value: slug,
					},
				],
			});
			return filterOrganizationOutput(organization) as InferOrganization<O> | null;
		},
		createOrganization: async (data: {
			organization: OrganizationInput &
				// This represents the additional fields from the plugin options
				Record<string, any>;
		}): Promise<InferOrganization<O>> => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const organization = await adapter.create<
				OrganizationInput,
				InferOrganization<O, false>
			>({
				model: "organization",
				data: {
					...data.organization,
					metadata: data.organization.metadata
						? JSON.stringify(data.organization.metadata)
						: undefined,
				},
				forceAllowId: true,
			});

			const result = {
				...organization,
				metadata:
					organization.metadata && typeof organization.metadata === "string"
						? JSON.parse(organization.metadata)
						: undefined,
			};
			return filterOrganizationOutput(result) as InferOrganization<O>;
		},
		findMemberByEmail: async (data: {
			email: string;
			organizationId: string;
		}) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const user = await adapter.findOne<User>({
				model: "user",
				where: [
					{
						field: "email",
						value: data.email.toLowerCase(),
					},
				],
			});
			if (!user) {
				return null;
			}
			const member = await adapter.findOne<InferMember<O, false>>({
				model: "member",
				where: [
					{
						field: "organizationId",
						value: data.organizationId,
					},
					{
						field: "userId",
						value: user.id,
					},
				],
			});
			if (!member) {
				return null;
			}
			return {
				...member,
				user: {
					id: user.id,
					name: user.name,
					email: user.email,
					image: user.image,
				},
			};
		},
		listMembers: async (data: {
			organizationId?: string | undefined;
			limit?: number | undefined;
			offset?: number | undefined;
			sortBy?: string | undefined;
			sortOrder?: ("asc" | "desc") | undefined;
			filter?:
				| {
						field: string;
						operator?: WhereOperator;
						value: any;
				  }
				| undefined;
		}) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const members = await Promise.all([
				adapter.findMany<InferMember<O, false>>({
					model: "member",
					where: [
						{ field: "organizationId", value: data.organizationId },
						...(data.filter?.field
							? [
									{
										field: data.filter?.field,
										value: data.filter?.value,
										...(data.filter.operator
											? { operator: data.filter.operator }
											: {}),
									},
								]
							: []),
					],
					limit:
						data.limit ||
						(typeof options?.membershipLimit === "number"
							? options.membershipLimit
							: 100) ||
						100,
					offset: data.offset || 0,
					sortBy: data.sortBy
						? { field: data.sortBy, direction: data.sortOrder || "asc" }
						: undefined,
				}),
				adapter.count({
					model: "member",
					where: [
						{ field: "organizationId", value: data.organizationId },
						...(data.filter?.field
							? [
									{
										field: data.filter?.field,
										value: data.filter?.value,
										...(data.filter.operator
											? { operator: data.filter.operator }
											: {}),
									},
								]
							: []),
					],
				}),
			]);
			const users = await adapter.findMany<User>({
				model: "user",
				where: [
					{
						field: "id",
						value: members[0].map((member) => member.userId),
						operator: "in",
					},
				],
			});
			return {
				members: members[0].map((member) => {
					const user = users.find((user) => user.id === member.userId);
					if (!user) {
						throw new ClearanceError(
							"Unexpected error: User not found for member",
						);
					}
					return {
						...member,
						user: {
							id: user.id,
							name: user.name,
							email: user.email,
							image: user.image,
						},
					};
				}),
				total: members[1],
			};
		},
		findMemberByOrgId: async (data: {
			userId: string;
			organizationId: string;
		}) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const result = await adapter.findOne<
				InferMember<O, false> & { user: User }
			>({
				model: "member",
				where: [
					{
						field: "userId",
						value: data.userId,
					},
					{
						field: "organizationId",
						value: data.organizationId,
					},
				],
				join: {
					user: true,
				},
			});
			if (!result || !result.user) return null;
			const { user, ...member } = result;

			return {
				...member,
				user: {
					id: user.id,
					name: user.name,
					email: user.email,
					image: user.image,
				},
			};
		},
		findMemberById: async (memberId: string) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const result = await adapter.findOne<
				InferMember<O, false> & { user: User }
			>({
				model: "member",
				where: [
					{
						field: "id",
						value: memberId,
					},
				],
				join: {
					user: true,
				},
			});
			if (!result) {
				return null;
			}
			const { user, ...member } = result;

			return {
				...(member as unknown as InferMember<O, false>),
				user: {
					id: user.id,
					name: user.name,
					email: user.email,
					image: user.image,
				},
			};
		},
		createMember: async (
			data: Omit<MemberInput, "id"> &
				// Additional fields from the plugin options
				Record<string, any>,
		) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const member = await adapter.create<
				typeof data,
				Member & InferAdditionalFieldsFromPluginOptions<"member", O, false>
			>({
				model: "member",
				data: {
					...data,
					createdAt: new Date(),
				},
			});
			return member;
		},
		updateMember: async (memberId: string, role: string) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const member = await adapter.update<InferMember<O, false>>({
				model: "member",
				where: [
					{
						field: "id",
						value: memberId,
					},
				],
				update: {
					role,
				},
			});
			return member;
		},
		deleteMember: async ({
			memberId,
			organizationId,
			userId: _userId,
		}: {
			memberId: string;
			organizationId: string;
			userId?: string;
		}) => {
			return runWithTransaction(baseAdapter, async () => {
				const adapter = await getCurrentAdapter(baseAdapter);
				let userId: string;
				if (!_userId) {
					const member = await adapter.findOne<Member>({
						model: "member",
						where: [{ field: "id", value: memberId }],
					});
					if (!member) {
						throw new ClearanceError("Member not found");
					}
					userId = member.userId;
				} else {
					userId = _userId;
				}
				const member = await adapter.delete<InferMember<O, false>>({
					model: "member",
					where: [
						{
							field: "id",
							value: memberId,
						},
					],
				});
				if (options?.teams?.enabled) {
					const teams = await adapter.findMany<Team>({
						model: "team",
						where: [{ field: "organizationId", value: organizationId }],
					});
					if (teams.length > 0) {
						await adapter.deleteMany({
							model: "teamMember",
							where: [
								{ field: "userId", value: userId },
								{
									field: "teamId",
									value: teams.map((team) => team.id),
									operator: "in",
								},
							],
						});
					}
				}
				return member;
			});
		},
		updateOrganization: async (
			organizationId: string,
			data: Partial<OrganizationInput>,
		): Promise<InferOrganization<O> | null> => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const organization = await adapter.update<InferOrganization<O, false>>({
				model: "organization",
				where: [
					{
						field: "id",
						value: organizationId,
					},
				],
				update: {
					...data,
					metadata:
						typeof data.metadata === "object"
							? JSON.stringify(data.metadata)
							: data.metadata,
				},
			});
			if (!organization) {
				return null;
			}
			const result = {
				...organization,
				metadata: organization.metadata
					? parseJSON<Record<string, any>>(organization.metadata)
					: undefined,
			};
			return filterOrganizationOutput(result) as InferOrganization<O>;
		},
		deleteOrganization: async (organizationId: string) => {
			return runWithTransaction(baseAdapter, async () => {
				const adapter = await getCurrentAdapter(baseAdapter);
				if (options?.teams?.enabled === true) {
					const teams = await adapter.findMany<Team>({
						model: "team",
						where: [{ field: "organizationId", value: organizationId }],
					});
					for (const team of teams) {
						await adapter.deleteMany({
							model: "teamMember",
							where: [{ field: "teamId", value: team.id }],
						});
					}
					await adapter.deleteMany({
						model: "team",
						where: [{ field: "organizationId", value: organizationId }],
					});
				}
				if (options?.dynamicAccessControl?.enabled) {
					await adapter.deleteMany({
						model: "organizationRole",
						where: [{ field: "organizationId", value: organizationId }],
					});
				}
				await adapter.deleteMany({
					model: "member",
					where: [
						{
							field: "organizationId",
							value: organizationId,
						},
					],
				});
				await adapter.deleteMany({
					model: "invitation",
					where: [
						{
							field: "organizationId",
							value: organizationId,
						},
					],
				});
				await adapter.delete<InferOrganization<O, false>>({
					model: "organization",
					where: [
						{
							field: "id",
							value: organizationId,
						},
					],
				});
				return organizationId;
			});
		},
		setActiveOrganization: async (
			sessionToken: string,
			organizationId: string | null,
			ctx: GenericEndpointContext,
			orchestration?: ActiveOrganizationTransitionOrchestration | undefined,
		): Promise<Session> => {
			if (
				ctx.context.options !== context.options ||
				ctx.context.adapter !== context.adapter
			) {
				throw new ClearanceError(
					"Organization transitions require the adapter's authoritative endpoint context",
				);
			}
			assertManagedOrganizationTransitionSupported(context);
			if (
				orchestration?.dontRememberMe !== undefined &&
				typeof orchestration.dontRememberMe !== "boolean"
			) {
				throw new ClearanceError(
					"Organization transition dontRememberMe must be a boolean",
				);
			}
			const dontRememberMarker =
				typeof ctx.getSignedCookie === "function"
					? await ctx.getSignedCookie(
							ctx.context.authCookies.dontRememberToken.name,
							ctx.context.secret,
						)
					: null;
			const dontRememberMe =
				orchestration?.dontRememberMe ?? Boolean(dontRememberMarker);
			const managed = Boolean(readInternalAuthenticationPolicy(context.options));
			const requestSession = ctx.context.session;
			if (
				!requestSession ||
				requestSession.session.token !== sessionToken ||
				requestSession.user.id !== requestSession.session.userId
			) {
				throw new ClearanceError(
					"Organization transitions require the exact presenting session context",
				);
			}
			if (
				(orchestration?.beforeCapture || orchestration?.afterCapture) &&
				typeof context.adapter.options?.adapterConfig.transaction !== "function"
			) {
				throw new ClearanceError(
					"Organization transition lifecycle work requires a rollback-capable database transaction",
				);
			}
			if (!managed) {
				const updateLegacySession = async (): Promise<Session> => {
					await orchestration?.beforeCapture?.();
					await orchestration?.afterCapture?.();
					const session = await context.internalAdapter.updateSession(
						sessionToken,
						{
							activeOrganizationId: organizationId,
							activeTeamId: null,
						},
					);
					if (!session) {
						throw new ClearanceError(
							"The presented session is no longer active for this organization transition",
						);
					}
					return session as Session;
				};
				return orchestration?.beforeCapture || orchestration?.afterCapture
					? runWithTransaction(context.adapter, updateLegacySession)
					: updateLegacySession();
			}
			if (
				typeof context.adapter.options?.adapterConfig.transaction !== "function"
			) {
				throw new Error(
					"Managed authentication requires rollback-capable database transactions",
				);
			}

			let committedSuccessor: Session | undefined;
			try {
				return await runWithTransaction(context.adapter, async () => {
					const transactionAdapter = await getCurrentAdapter(context.adapter);
					const transactionTransitions =
						activeManagedTransitions.get(transactionAdapter) ?? new Map();
					const existingTransition = transactionTransitions.get(sessionToken);
					if (existingTransition) {
						existingTransition.reentrantAttempted = true;
						throw new ClearanceError(
							"Recursive organization transitions from the same source are not allowed",
						);
					}
					const transition: ActiveManagedTransition = {
						reentrantAttempted: false,
					};
					transactionTransitions.set(sessionToken, transition);
					activeManagedTransitions.set(
						transactionAdapter,
						transactionTransitions,
					);
					try {
						await orchestration?.beforeCapture?.();
						const issuanceContext = await captureInternalSessionIssuanceContext(
							context.internalAdapter,
							{
								purpose: "organization",
								sourceSessionToken: sessionToken,
								targetOrganizationId: organizationId,
							},
						);
						if (!issuanceContext) {
							throw new ClearanceError(
								"Managed organization transitions require captured session issuance authority",
							);
						}

						const source = await context.internalAdapter.findSession(sessionToken);
						if (
							!source ||
							source.session.token !== sessionToken ||
							source.user.id !== requestSession.user.id ||
							source.session.id !== requestSession.session.id
						) {
							throw new ClearanceError(
								"The presented session changed during this organization transition",
							);
						}
						const sourceExpiresAt = new Date(source.session.expiresAt);
						if (!Number.isFinite(sourceExpiresAt.getTime())) {
							throw new ClearanceError(
								"The presented session changed during this organization transition",
							);
						}
						const legacyCredentialAuthority =
							readInternalCredentialAuthority(context.options)?.generation ===
							"legacy-v1";
						const rawSource = await transactionAdapter.findOne<Session>({
							model: "session",
							where: [{ field: "id", value: source.session.id }],
						});
						const sourceCredential = legacyCredentialAuthority
							? null
							: await transactionAdapter.findOne<SessionCredential>({
									model: SESSION_CREDENTIAL_MODEL,
									where: [
										{
											field: "secretDigest",
											value: await digestSessionRefreshSecret(sessionToken),
										},
									],
								});
						if (
							!rawSource ||
							(legacyCredentialAuthority
								? rawSource.token !== sessionToken
								: !sourceCredential ||
									sourceCredential.status !== "active" ||
									sourceCredential.sessionId !== source.session.id)
						) {
							throw new ClearanceError(
								"The presented session changed during this organization transition",
							);
						}
						const sourceAuthority = Object.fromEntries(
							SESSION_ASSURANCE_RESERVED_FIELDS.map((field) => [
								field,
								(rawSource as unknown as Record<string, unknown>)[field],
							]),
						);

						await orchestration?.afterCapture?.();
						const currentRawSource = await transactionAdapter.findOne<Session>({
							model: "session",
							where: [{ field: "id", value: source.session.id }],
						});
						const currentCredential = sourceCredential
							? await transactionAdapter.findOne<SessionCredential>({
									model: SESSION_CREDENTIAL_MODEL,
									where: [{ field: "id", value: sourceCredential.id }],
								})
							: null;
						const authorityUnchanged = SESSION_ASSURANCE_RESERVED_FIELDS.every(
							(field) => {
								const before = sourceAuthority[field];
								const after = (
									currentRawSource as unknown as
										| Record<string, unknown>
										| undefined
								)?.[field];
								return before instanceof Date || after instanceof Date
									? new Date(before as string | number | Date).getTime() ===
											new Date(after as string | number | Date).getTime()
									: Object.is(before, after);
							},
						);
						if (
							transition.reentrantAttempted ||
							!currentRawSource ||
							currentRawSource.id !== rawSource.id ||
							currentRawSource.userId !== rawSource.userId ||
							new Date(currentRawSource.expiresAt).getTime() !==
								sourceExpiresAt.getTime() ||
							(legacyCredentialAuthority
								? currentRawSource.token !== sessionToken
								: !currentCredential ||
									currentCredential.status !== "active" ||
									currentCredential.sessionId !== source.session.id ||
									currentCredential.secretDigest !==
										sourceCredential?.secretDigest) ||
							!authorityUnchanged
						) {
							throw new ClearanceError(
								"The source session changed during organization transition lifecycle work",
							);
						}

						await context.internalAdapter.deleteSession(sessionToken);
						const successor = await context.internalAdapter.createSession(
							source.user.id,
							dontRememberMe,
							{
								...source.session,
								expiresAt: sourceExpiresAt,
								__preserveSessionExpiresAt: true,
							},
							true,
							issuanceContext,
						);
						committedSuccessor = successor;
						orchestration?.onSuccessorPrepared?.(successor);
						return successor;
					} finally {
						transactionTransitions.delete(sessionToken);
						if (transactionTransitions.size === 0) {
							activeManagedTransitions.delete(transactionAdapter);
						}
					}
				});
			} catch (error) {
				if (
					error instanceof AfterTransactionHookError &&
					committedSuccessor &&
					!orchestration?.propagateAfterTransactionHookError
				) {
					return committedSuccessor;
				}
				throw error;
			}
		},
		findOrganizationById: async (
			organizationId: string,
		): Promise<InferOrganization<O> | null> => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const organization = await adapter.findOne<InferOrganization<O, false>>({
				model: "organization",
				where: [
					{
						field: "id",
						value: organizationId,
					},
				],
			});
			return filterOrganizationOutput(organization) as InferOrganization<O> | null;
		},
		checkMembership: async ({
			userId,
			organizationId,
		}: {
			userId: string;
			organizationId: string;
		}) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const member = await adapter.findOne<InferMember<O, false>>({
				model: "member",
				where: [
					{
						field: "userId",
						value: userId,
					},
					{
						field: "organizationId",
						value: organizationId,
					},
				],
			});
			return member;
		},
		/**
		 * @requires db
		 */
		findFullOrganization: async ({
			organizationId,
			isSlug,
			includeTeams,
			membersLimit,
		}: {
			organizationId: string;
			isSlug?: boolean | undefined;
			includeTeams?: boolean | undefined;
			membersLimit?: number | undefined;
		}) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const result = await adapter.findOne<
				InferOrganization<O, false> & {
					invitation: InferInvitation<O>[];
					member: InferMember<O>[];
					team: InferTeam<O>[] | undefined;
				}
			>({
				model: "organization",
				where: [{ field: isSlug ? "slug" : "id", value: organizationId }],
				join: {
					invitation: true,
					member: membersLimit ? { limit: membersLimit } : true,
					...(includeTeams ? { team: true } : {}),
				},
			});
			if (!result) {
				return null;
			}

			const {
				invitation: invitations,
				member: members,
				team: teams,
				...org
			} = result;
			const userIds = members.map((member) => member.userId);
			const users =
				userIds.length > 0
					? await adapter.findMany<User>({
							model: "user",
							where: [{ field: "id", value: userIds, operator: "in" }],
							limit:
								(typeof options?.membershipLimit === "number"
									? options.membershipLimit
									: 100) || 100,
						})
					: [];

			const userMap = new Map(users.map((user) => [user.id, user]));
			const membersWithUsers = members.map((member) => {
				const user = userMap.get(member.userId);
				if (!user) {
					throw new ClearanceError(
						"Unexpected error: User not found for member",
					);
				}
				const filteredMember = filterOutputFields(
					member,
					memberAdditionalFields,
				);
				return {
					...filteredMember,
					user: {
						id: user.id,
						name: user.name,
						email: user.email,
						image: user.image,
					},
				};
			});

			const filteredOrg = filterOrganizationOutput(org);
			const filteredInvitations = invitations.map((inv) =>
				filterOutputFields(inv, invitationAdditionalFields),
			);
			const filteredTeams = teams?.map((team) =>
				filterOutputFields(team, teamAdditionalFields),
			);

			return {
				...filteredOrg,
				invitations: filteredInvitations,
				members: membersWithUsers,
				teams: filteredTeams,
			};
		},
		listOrganizations: async (
			userId: string,
		): Promise<InferOrganization<O>[]> => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const result = await adapter.findMany<
				InferMember<O, false> & { organization: InferOrganization<O, false> }
			>({
				model: "member",
				where: [
					{
						field: "userId",
						value: userId,
					},
				],
				join: {
					organization: true,
				},
			});

			if (!result || result.length === 0) {
				return [];
			}

			const organizations = result.map(
				(member) =>
					filterOrganizationOutput(member.organization) as InferOrganization<O>,
			);

			return organizations;
		},
		createTeam: async (
			data: TeamInput,
			maximumTeams?: number,
			beforeCreate?: (
				organization: InferOrganization<O>,
			) => Promise<TeamInput> | TeamInput,
		): Promise<
			| { status: "created"; team: InferTeam<O, false> }
			| { status: "organizationNotFound" }
			| { status: "limitReached" }
			| { status: "transactionRequired" }
		> => {
			if (!(await hasAtomicTeamTransaction())) {
				return { status: "transactionRequired" };
			}
			return runWithTransaction(baseAdapter, async () => {
				const adapter = await getCurrentAdapter(baseAdapter);
				// Lock before the count so an organization deletion cannot interleave
				// with the team insert and leave an orphaned team behind.
				const organization = await adapter.update<InferOrganization<O, false>>({
					model: "organization",
					where: [{ field: "id", value: data.organizationId }],
					update: { updatedAt: new Date() },
				});
				if (!organization) return { status: "organizationNotFound" };
				const preparedData = beforeCreate
					? await beforeCreate(
							filterOrganizationOutput(organization) as InferOrganization<O>,
						)
					: data;
				if (maximumTeams !== undefined) {
					const teams = await adapter.findMany<Team>({
						model: "team",
						where: [
							{ field: "organizationId", value: data.organizationId },
						],
					});
					if (teams.length >= maximumTeams) return { status: "limitReached" };
				}
				const team = await adapter.create<TeamInput, InferTeam<O, false>>({
					model: "team",
					// Hooks can add fields but cannot move this mutation to another org.
					data: { ...preparedData, organizationId: data.organizationId },
					forceAllowId: true,
				});
				return { status: "created", team };
			});
		},
		findTeamById: async <IncludeMembers extends boolean>({
			teamId,
			organizationId,
			includeTeamMembers,
		}: {
			teamId: string;
			organizationId?: string | undefined;
			includeTeamMembers?: IncludeMembers | undefined;
		}): Promise<
			| (InferTeam<O> &
					(IncludeMembers extends true ? { members: TeamMember[] } : {}))
			| null
		> => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const result = await adapter.findOne<
				InferTeam<O> & { teamMember: TeamMember[] }
			>({
				model: "team",
				where: [
					{
						field: "id",
						value: teamId,
					},
					...(organizationId
						? [
								{
									field: "organizationId",
									value: organizationId,
								},
							]
						: []),
				],
				join: {
					// In the future when `join` support is better, we can apply the `membershipLimit` here. Right now we're just querying 100.
					...(includeTeamMembers ? { teamMember: true } : {}),
				},
			});
			if (!result) {
				return null;
			}
			const { teamMember, ...team } = result;

			return {
				...team,
				...(includeTeamMembers ? { members: teamMember } : {}),
			} as any;
		},
		updateTeam: async (
			teamId: string,
			data: {
				name?: string | undefined;
				description?: string | undefined;
				status?: string | undefined;
			},
		) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			if ("id" in data) data.id = undefined;
			const team = await adapter.update<
				InferTeam<O, false> & InferAdditionalFieldsFromPluginOptions<"team", O>
			>({
				model: "team",
				where: [
					{
						field: "id",
						value: teamId,
					},
				],
				update: {
					...data,
				},
			});
			return team;
		},

		deleteTeam: async (data: {
			organizationId: string;
			teamId: string;
			allowRemovingAllTeams: boolean;
			beforeDelete?: (snapshot: {
				organization: InferOrganization<O, false>;
				team: Team;
			}) => Promise<void>;
		}): Promise<
			| { status: "deleted"; organization: InferOrganization<O, false>; team: Team }
			| { status: "organizationNotFound" }
			| { status: "teamNotFound" }
			| { status: "lastTeam" }
			| { status: "transactionRequired" }
		> => {
			if (!(await hasAtomicTeamTransaction())) {
				return { status: "transactionRequired" };
			}
			return runWithTransaction(baseAdapter, async () => {
				const adapter = await getCurrentAdapter(baseAdapter);
				const locked = await lockTeamMembership(adapter, data);
				if (locked.status !== "ready") return locked;
				await data.beforeDelete?.(locked);
				if (!data.allowRemovingAllTeams) {
					const teams = await adapter.findMany<Team>({
						model: "team",
						where: [{ field: "organizationId", value: data.organizationId }],
					});
					if (teams.length <= 1) return { status: "lastTeam" };
				}
				await adapter.deleteMany({
					model: "teamMember",
					where: [{ field: "teamId", value: data.teamId }],
				});
				const invitations = await adapter.findMany<
					InferInvitation<O, false> & { teamId?: string | null }
				>({
					model: "invitation",
					where: [
						{ field: "organizationId", value: data.organizationId },
						{ field: "status", value: "pending" },
					],
				});
				for (const invitation of invitations) {
					if (!invitation.teamId) continue;
					const teamIds = invitation.teamId.split(",");
					if (!teamIds.includes(data.teamId)) continue;
					const remaining = teamIds.filter((id) => id !== data.teamId);
					await adapter.update({
						model: "invitation",
						where: [{ field: "id", value: invitation.id }],
						update: { teamId: remaining.length ? remaining.join(",") : null },
					});
				}
				await adapter.delete<Team>({
					model: "team",
					where: [{ field: "id", value: data.teamId }],
				});
				return {
					status: "deleted",
					organization: locked.organization,
					team: locked.team,
				};
			});
		},

		listTeams: async (organizationId: string) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const teams = await adapter.findMany<InferTeam<O, false>>({
				model: "team",
				where: [
					{
						field: "organizationId",
						value: organizationId,
					},
				],
			});
			return teams;
		},

		createTeamInvitation: async ({
			email,
			role,
			teamId,
			organizationId,
			inviterId,
			expiresIn = 1000 * 60 * 60 * 48, // Default expiration: 48 hours
		}: {
			email: string;
			role: string;
			teamId: string;
			organizationId: string;
			inviterId: string;
			expiresIn?: number | undefined;
		}) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const expiresAt = getDate(expiresIn); // Get expiration date

			const invitation = await adapter.create<
				InvitationInput,
				InferInvitation<O>
			>({
				model: "invitation",
				data: {
					email,
					role,
					organizationId,
					teamId,
					inviterId,
					status: "pending",
					expiresAt,
				},
			});

			return invitation;
		},

		setActiveTeam: async (
			sessionToken: string,
			teamId: string | null,
			ctx: GenericEndpointContext,
		) => {
			const session = await context.internalAdapter.updateSession(
				sessionToken,
				{
					activeTeamId: teamId,
				},
			);
			if (!session) {
				throw new ClearanceError(
					"The presented session is no longer active for this team transition",
				);
			}
			return session as Session;
		},

		listTeamMembers: async (data: { teamId: string }) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const members = await adapter.findMany<TeamMember>({
				model: "teamMember",
				where: [
					{
						field: "teamId",
						value: data.teamId,
					},
				],
			});

			return members;
		},
		countTeamMembers: async (data: { teamId: string }) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const count = await adapter.count({
				model: "teamMember",
				where: [{ field: "teamId", value: data.teamId }],
			});
			return count;
		},
		countMembers: async (data: { organizationId: string }) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const count = await adapter.count({
				model: "member",
				where: [{ field: "organizationId", value: data.organizationId }],
			});
			return count;
		},
		listTeamsByUser: async (data: { userId: string }) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const results = await adapter.findMany<TeamMember & { team: Team }>({
				model: "teamMember",
				where: [
					{
						field: "userId",
						value: data.userId,
					},
				],
				join: {
					team: true,
				},
			});

			return results.map((result) => result.team);
		},

		findTeamMember: async (data: { teamId: string; userId: string }) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const member = await adapter.findOne<TeamMember>({
				model: "teamMember",
				where: [
					{
						field: "teamId",
						value: data.teamId,
					},
					{
						field: "userId",
						value: data.userId,
					},
				],
			});

			return member;
		},
		admitTeamMember: async (data: {
			organizationId: string;
			teamId: string;
			userId: string;
			prepare: (snapshot: {
				organization: InferOrganization<O, false>;
				team: Team;
			}) => Promise<number | undefined>;
		}): Promise<
			| {
					status: "added";
					member: TeamMember;
					organization: InferOrganization<O, false>;
					team: Team;
				  }
			| { status: "limitReached" }
			| { status: "organizationNotFound" }
			| { status: "teamNotFound" }
			| { status: "transactionRequired" }
		> => {
			if (!(await hasAtomicTeamTransaction())) {
				return { status: "transactionRequired" };
			}
			return runWithTransaction(baseAdapter, async () => {
				const adapter = await getCurrentAdapter(baseAdapter);
				const locked = await lockTeamMembership(adapter, data);
				if (locked.status !== "ready") return locked;
				const maximumMembersPerTeam = await data.prepare(locked);
				const membersByUserId = await deduplicateTeamMembers(adapter, data.teamId);
				const existing = membersByUserId.get(data.userId);
				if (existing) return { ...locked, status: "added", member: existing };
				if (
					maximumMembersPerTeam !== undefined &&
					membersByUserId.size >= maximumMembersPerTeam
				) {
					return { status: "limitReached" };
				}
				const member = await adapter.create<Omit<TeamMember, "id">, TeamMember>({
					model: "teamMember",
					data: {
						teamId: data.teamId,
						userId: data.userId,
						createdAt: new Date(),
					},
				});
				return { ...locked, status: "added", member };
			});
		},

		findOrCreateTeamMember: async (data: {
			organizationId: string;
			teamId: string;
			userId: string;
		}): Promise<
			| { status: "added"; member: TeamMember }
			| { status: "organizationNotFound" }
			| { status: "teamNotFound" }
			| { status: "transactionRequired" }
		> => {
			if (!(await hasAtomicTeamTransaction())) {
				return { status: "transactionRequired" };
			}
			return runWithTransaction(baseAdapter, async () => {
				const adapter = await getCurrentAdapter(baseAdapter);
				const locked = await lockTeamMembership(adapter, data);
				if (locked.status !== "ready") return locked;
				const member = await deduplicateTeamMemberPair(adapter, data);
				if (member) return { status: "added", member };
				const created = await adapter.create<Omit<TeamMember, "id">, TeamMember>({
					model: "teamMember",
					data: {
						teamId: data.teamId,
						userId: data.userId,
						createdAt: new Date(),
					},
				});
				return { status: "added", member: created };
			});
		},
		/**
		 * Adds a user to a team only when the team is below its member limit.
		 * Touching the exact team row acquires a portable write lock, so every
		 * distinct-user admission for that team serializes through one transaction
		 * under READ COMMITTED. Existing-member handling remains independent from
		 * capacity accounting.
		 */
		addTeamMemberWithLimit: async (data: {
			organizationId: string;
			teamId: string;
			userId: string;
			maximumMembersPerTeam: number;
		}): Promise<
			| { status: "added"; member: TeamMember }
			| { status: "limitReached" }
			| { status: "organizationNotFound" }
			| { status: "teamNotFound" }
			| { status: "transactionRequired" }
		> => {
			if (!(await hasAtomicTeamTransaction())) {
				return { status: "transactionRequired" };
			}
			return runWithTransaction(baseAdapter, async () => {
				const adapter = await getCurrentAdapter(baseAdapter);
				const locked = await lockTeamMembership(adapter, data);
				if (locked.status !== "ready") return locked;
				const membersByUserId = await deduplicateTeamMembers(
					adapter,
					data.teamId,
				);
				const existing = membersByUserId.get(data.userId);
				if (existing) {
					return { status: "added", member: existing };
				}
				const count = membersByUserId.size;
				if (count >= data.maximumMembersPerTeam) {
					return { status: "limitReached" };
				}
				const member = await adapter.create<Omit<TeamMember, "id">, TeamMember>(
					{
						model: "teamMember",
						data: {
							teamId: data.teamId,
							userId: data.userId,
							createdAt: new Date(),
						},
					},
				);
				return { status: "added", member };
			});
		},
		removeTeamMember: async (data: { teamId: string; userId: string }) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			// use `deleteMany` instead of `delete` since Prisma requires 1 unique field for normal `delete` operations
			// FKs do not count thus breaking the operation. As a solution, we'll use `deleteMany` instead.
			await adapter.deleteMany({
				model: "teamMember",
				where: [
					{
						field: "teamId",
						value: data.teamId,
					},
					{
						field: "userId",
						value: data.userId,
					},
				],
			});
		},
		findInvitationsByTeamId: async (teamId: string) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const invitations = await adapter.findMany<InferInvitation<O, false>>({
				model: "invitation",
				where: [
					{
						field: "teamId",
						value: teamId,
					},
				],
			});
			return invitations;
		},
		listUserInvitations: async (email: string) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const invitations = await adapter.findMany<
				InferInvitation<O, false> & {
					organization: InferOrganization<O, false>;
				}
			>({
				model: "invitation",
				where: [{ field: "email", value: email.toLowerCase() }],
				join: {
					organization: true,
				},
			});
			return invitations.filter(Boolean).map(({ organization, ...inv }) => ({
				...inv,
				organizationName: organization?.name,
			}));
		},
		createInvitation: async ({
			invitation,
			user,
		}: {
			invitation: {
				email: string;
				role: string;
				organizationId: string;
				teamIds: string[];
			} & Record<string, any>; // This represents the additionalFields for the invitation
			user: User;
		}) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const defaultExpiration = 60 * 60 * 48;
			const expiresAt = getDate(
				options?.invitationExpiresIn || defaultExpiration,
				"sec",
			);
			const invite = await adapter.create<
				InvitationInput,
				InferInvitation<O, false>
			>({
				model: "invitation",
				data: {
					status: "pending",
					expiresAt,
					createdAt: new Date(),
					inviterId: user.id,
					...invitation,
					teamId:
						invitation.teamIds.length > 0 ? invitation.teamIds.join(",") : null,
				},
				forceAllowId: true,
			});

			return invite;
		},
		findInvitationById: async (id: string) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const invitation = await adapter.findOne<InferInvitation<O, false>>({
				model: "invitation",
				where: [
					{
						field: "id",
						value: id,
					},
				],
			});
			return invitation;
		},
		findPendingInvitation: async (data: {
			email: string;
			organizationId: string;
		}) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const invitation = await adapter.findMany<InferInvitation<O, false>>({
				model: "invitation",
				where: [
					{
						field: "email",
						value: data.email.toLowerCase(),
					},
					{
						field: "organizationId",
						value: data.organizationId,
					},
					{
						field: "status",
						value: "pending",
					},
				],
			});
			return invitation.filter(
				(invite) => new Date(invite.expiresAt) > new Date(),
			);
		},
		findPendingInvitations: async (data: { organizationId: string }) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const invitations = await adapter.findMany<InferInvitation<O, false>>({
				model: "invitation",
				where: [
					{
						field: "organizationId",
						value: data.organizationId,
					},
					{
						field: "status",
						value: "pending",
					},
				],
			});
			return invitations.filter(
				(invite) => new Date(invite.expiresAt) > new Date(),
			);
		},
		listInvitations: async (data: { organizationId: string }) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const invitations = await adapter.findMany<InferInvitation<O, false>>({
				model: "invitation",
				where: [
					{
						field: "organizationId",
						value: data.organizationId,
					},
				],
			});
			return invitations;
		},
		updateInvitation: async (data: {
			invitationId: string;
			status: "pending" | "accepted" | "canceled" | "rejected";
			/**
			 * Only transition when the invitation is currently in this status. The
			 * guarded update is atomic, so a concurrent caller racing the same
			 * transition gets `null` instead of both proceeding.
			 */
			fromStatus?: "pending";
		}) => {
			const adapter = await getCurrentAdapter(baseAdapter);
			const where = [{ field: "id", value: data.invitationId }];
			if (data.fromStatus) {
				where.push({ field: "status", value: data.fromStatus });
			}
			const invitation = await adapter.incrementOne<InferInvitation<O, false>>({
				model: "invitation",
				where,
				increment: {},
				set: {
					status: data.status,
				},
			});
			return invitation;
		},
	};
};
