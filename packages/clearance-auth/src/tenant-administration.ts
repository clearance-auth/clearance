import { randomUUID } from "node:crypto";
import {
	APIError,
	type ClearancePlugin,
	type DBTransactionAdapter,
	type GenericEndpointContext,
} from "@clearance/runtime";
import { createAuthEndpoint } from "@clearance/runtime/api";
import {
	appendInternalRuntimeAudit,
	attachCapturedInternalRuntimeAudit,
	getRuntimeAuditRequestContext,
	type InternalRuntimeAuditBinding,
} from "@clearance/runtime/internal/runtime-audit";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "../../core/src/context/index.js";
import { withTenantCapability } from "../../runtime/src/plugins/tenant-capability/index.js";
import * as z from "zod";
import {
	PostgresAuthorizationAuthority,
	PostgresAuthorizationAuthorityError,
	type AuthorizationAuthorityRole,
	type AuthorizationAuthorityTransaction,
	type AuthorizationServiceAccount,
	type AuthorizationSubject,
} from "./authorization-authority.js";
import type { TenantProductAdministrationFacade } from "./public-types/index.js";

const identifier = z
	.string()
	.min(1)
	.max(256)
	.refine(
		(value) => value.trim() === value && !value.includes("\0"),
		"Invalid identifier",
	);
const operationId = z
	.string()
	.regex(
		/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
		"operationId must be a canonical lowercase UUID",
	);
const revision = z.string().regex(/^[1-9]\d{0,18}$/);
const roleIds = z
	.array(identifier)
	.max(256)
	.refine((values) => new Set(values).size === values.length, "Duplicate role");
const subject = z.discriminatedUnion("kind", [
	z.object({ kind: z.literal("principal"), id: identifier }).strict(),
	z.object({ kind: z.literal("service_account"), id: identifier }).strict(),
]);
const effectiveBody = z.object({ subject }).strict();
const assignmentListBody = z
	.object({ subject: subject.optional() })
	.strict();
const assignmentReplaceBody = z
	.object({
		subject,
		roleIds,
		expectedRevision: revision.optional(),
		dryRun: z.boolean(),
		confirm: z.boolean(),
	})
	.strict()
	.superRefine((value, context) => {
		if (
			!((value.dryRun === true && value.confirm === false) ||
				(value.dryRun === false && value.confirm === true))
		) {
			context.addIssue({
				code: "custom",
				message:
					"Preview requires dryRun=true and confirm=false; live replacement requires dryRun=false and confirm=true",
			});
		}
	});
const serviceAccountCreateBody = z
	.object({
		name: z.string().min(1).max(255).refine((value) => value.trim() === value),
		roleIds,
		dryRun: z.boolean(),
	})
	.strict();
const previewBody = z.object({ dryRun: z.boolean() }).strict();
const confirmedPreviewBody = z
	.object({ dryRun: z.boolean(), confirm: z.boolean() })
	.strict()
	.superRefine((value, context) => {
		if (value.dryRun === value.confirm) {
			context.addIssue({
				code: "custom",
				message:
					"Preview requires dryRun=true and confirm=false; live mutation requires dryRun=false and confirm=true",
			});
		}
	});
const credentialCreateBody = z
	.object({
		operationId: operationId.optional(),
		expiresAt: z.iso.datetime({ offset: true }).optional(),
		dryRun: z.boolean(),
	})
	.strict()
	.superRefine((value, context) => {
		if (value.dryRun && value.operationId) {
			context.addIssue({ code: "custom", path: ["operationId"], message: "Preview credential creation must omit operationId" });
		}
		if (!value.dryRun && !value.operationId) {
			context.addIssue({ code: "custom", path: ["operationId"], message: "Live credential creation requires a UUID operationId" });
		}
	});
const credentialRotateBody = z
	.object({
		operationId: operationId.optional(),
		expiresAt: z.iso.datetime({ offset: true }).optional(),
		dryRun: z.boolean(),
		confirm: z.boolean(),
	})
	.strict()
	.superRefine((value, context) => {
		if (value.dryRun && value.operationId) {
			context.addIssue({ code: "custom", path: ["operationId"], message: "Preview credential rotation must omit operationId" });
		}
		if (value.dryRun === value.confirm) {
			context.addIssue({
				code: "custom",
				message:
					"Preview requires dryRun=true and confirm=false; live rotation requires dryRun=false and confirm=true",
			});
		}
		if (!value.dryRun && !value.operationId) {
			context.addIssue({ code: "custom", path: ["operationId"], message: "Live credential rotation requires a UUID operationId" });
		}
	});
const productMutationConfirmation = z
	.object({ dryRun: z.boolean(), confirm: z.boolean() })
	.strict()
	.superRefine((value, context) => {
		if (value.dryRun === value.confirm) {
			context.addIssue({
				code: "custom",
				message:
					"Preview requires dryRun=true and confirm=false; live mutation requires dryRun=false and confirm=true",
			});
		}
	});
const ssoSecretReplacementBody = z
	.object({
		operationId: operationId.optional(),
		newClientSecret: z.string().min(1).max(16_384),
		dryRun: z.boolean(),
		confirm: z.boolean(),
	})
	.strict()
	.superRefine((value, context) => {
		if (value.dryRun === value.confirm) {
			context.addIssue({
				code: "custom",
				message:
					"Preview requires dryRun=true and confirm=false; live replacement requires dryRun=false and confirm=true",
			});
		}
		if (!value.dryRun && !value.operationId) {
			context.addIssue({ code: "custom", path: ["operationId"], message: "Live replacement requires a UUID operationId" });
		}
	});
const scimRotateBody = z
	.object({
		operationId: operationId.optional(),
		dryRun: z.boolean(),
		confirm: z.boolean(),
	})
	.strict()
	.superRefine((value, context) => {
		if (value.dryRun === value.confirm) {
			context.addIssue({ code: "custom", message: "Preview requires dryRun=true and confirm=false; live rotation requires dryRun=false and confirm=true" });
		}
		if (!value.dryRun && !value.operationId) {
			context.addIssue({ code: "custom", path: ["operationId"], message: "Live rotation requires a UUID operationId" });
		}
	});
const ssoMutationGate = (
	value: { dryRun: boolean; confirm: boolean },
	context: z.RefinementCtx,
) => {
		if (value.dryRun === value.confirm) {
			context.addIssue({
				code: "custom",
				message:
					"Preview requires dryRun=true and confirm=false; live creation requires dryRun=false and confirm=true",
			});
		}
	};
const ssoCreateBody = z.discriminatedUnion("protocol", [
	z.object({
			protocol: z.literal("oidc"),
			provider: z.string().min(1).max(128).refine((value) => value.trim() === value),
			issuer: z.url(),
			domain: z.string().min(1).max(253).refine((value) => value.trim() === value),
			audience: z.string().min(1).max(512).optional(),
			clientId: z.string().min(1).max(512),
			clientSecret: z.string().min(1).max(16_384),
			dryRun: z.boolean(),
			confirm: z.boolean(),
		}).strict().superRefine(ssoMutationGate),
	z.object({
			protocol: z.literal("saml"),
			provider: z.string().min(1).max(128).refine((value) => value.trim() === value),
			issuer: z.url(),
			domain: z.string().min(1).max(253).refine((value) => value.trim() === value),
			audience: z.string().min(1).max(512).optional(),
			samlEntryPoint: z.url(),
			samlCertificate: z.string().min(1).max(65_536),
			dryRun: z.boolean(),
			confirm: z.boolean(),
		}).strict().superRefine(ssoMutationGate),
]);
const scimCreateBody = z
	.object({
		operationId: operationId.optional(),
		provider: z.string().min(1).max(128).refine((value) => value.trim() === value),
		endpoint: z.url().optional(),
		dryRun: z.boolean(),
		confirm: z.boolean(),
	})
	.strict()
	.superRefine((value, context) => {
		if (value.dryRun === value.confirm) {
			context.addIssue({
				code: "custom",
				message:
					"Preview requires dryRun=true and confirm=false; live creation requires dryRun=false and confirm=true",
			});
		}
		if (!value.dryRun && !value.operationId) {
			context.addIssue({ code: "custom", path: ["operationId"], message: "Live creation requires a UUID operationId" });
		}
	});
const auditListQuery = z
	.object({
		limit: z.coerce.number().int().min(1).max(100).optional(),
		cursor: z.string().min(1).max(4096).optional(),
		action: z.string().min(1).max(256).optional(),
	})
	.strict();

type TenantAdministrationOptions = Readonly<{
	authorization: PostgresAuthorizationAuthority;
	runtimeAudit: InternalRuntimeAuditBinding;
	productAdministration?: TenantProductAdministrationFacade;
}>;

type TenantTransaction = DBTransactionAdapter;

type TenantMutationContext = Readonly<{
	transaction: TenantTransaction & AuthorizationAuthorityTransaction;
	organizationId: string;
	actorId: string;
	actorActions: ReadonlySet<string>;
}>;

type AuditInput = Readonly<{
	action: string;
	subjectType: "principal" | "service_account" | "service_account_credential";
	subjectId: string;
	message: string;
	metadata?: Readonly<Record<string, unknown>>;
}>;

class PreviewRollback<Result> extends Error {
	readonly result: Result;

	constructor(result: Result) {
		super("Tenant administration preview rollback");
		this.name = "TenantAdministrationPreviewRollback";
		this.result = result;
	}
}

function tenantError(
	status:
		| "BAD_REQUEST"
		| "CONFLICT"
		| "FORBIDDEN"
		| "NOT_FOUND"
		| "SERVICE_UNAVAILABLE",
	code: string,
	message: string,
): never {
	throw APIError.fromStatus(status, { code, message });
}

function mapTenantError(error: unknown): never {
	if (error instanceof APIError) throw error;
	if (error instanceof PostgresAuthorizationAuthorityError) {
		switch (error.code) {
			case "AUTHORIZATION_LAST_OWNER_PROTECTED":
				return tenantError(
					"CONFLICT",
					error.code,
					"The final active owner assignment is protected",
				);
			case "AUTHORIZATION_REVISION_STALE":
				return tenantError(
					"CONFLICT",
					error.code,
					"Authorization state changed; reload and retry",
				);
			case "AUTHORIZATION_ROLE_NOT_FOUND":
			case "AUTHORIZATION_ROLE_INACTIVE":
			case "AUTHORIZATION_ROLE_SCOPE_MISMATCH":
			case "AUTHORIZATION_SUBJECT_NOT_FOUND":
			case "AUTHORIZATION_SERVICE_ACCOUNT_NOT_FOUND":
			case "AUTHORIZATION_CREDENTIAL_INVALID":
				return tenantError(
					"NOT_FOUND",
					"TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND",
					"Resource not found",
				);
			case "AUTHORIZATION_INPUT_INVALID":
			case "AUTHORIZATION_REVISION_INVALID":
				return tenantError(
					"BAD_REQUEST",
					"TENANT_ADMINISTRATION_INPUT_INVALID",
					"Request is invalid",
				);
			case "AUTHORIZATION_ORGANIZATION_ARCHIVED":
			case "AUTHORIZATION_REVISION_NOT_FOUND":
				return tenantError(
					"NOT_FOUND",
					"TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND",
					"Resource not found",
				);
			default:
				return tenantError(
					"SERVICE_UNAVAILABLE",
					"TENANT_ADMINISTRATION_UNAVAILABLE",
					"Tenant administration is unavailable",
				);
		}
	}
	return tenantError(
		"SERVICE_UNAVAILABLE",
		"TENANT_ADMINISTRATION_UNAVAILABLE",
		"Tenant administration is unavailable",
	);
}

function mapProductAdministrationError(error: unknown): never {
	if (error instanceof APIError) throw error;
	const status =
		typeof error === "object" &&
		error !== null &&
		"status" in error &&
		typeof error.status === "number"
			? error.status
			: undefined;
	if (status === 400) {
		return tenantError(
			"BAD_REQUEST",
			"TENANT_PRODUCT_INPUT_INVALID",
			"Request is invalid",
		);
	}
	if (status === 403) {
		return tenantError(
			"FORBIDDEN",
			"TENANT_AUTHORIZATION_REQUIRED",
			"Tenant authorization is required",
		);
	}
	if (status === 404) {
		return tenantError(
			"NOT_FOUND",
			"TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND",
			"Resource not found",
		);
	}
	if (status === 409) {
		return tenantError(
			"CONFLICT",
			"TENANT_PRODUCT_CONFLICT",
			"Enterprise configuration changed; reload and retry",
		);
	}
	return tenantError(
		"SERVICE_UNAVAILABLE",
		"TENANT_PRODUCT_ADMINISTRATION_UNAVAILABLE",
		"Enterprise administration is unavailable",
	);
}

function noStore(ctx: GenericEndpointContext): void {
	ctx.setHeader("cache-control", "no-store");
	ctx.setHeader("pragma", "no-cache");
}

function routeIdentifier(value: unknown): string {
	const parsed = identifier.safeParse(value);
	if (!parsed.success) {
		return tenantError(
			"BAD_REQUEST",
			"TENANT_ADMINISTRATION_INPUT_INVALID",
			"Request is invalid",
		);
	}
	return parsed.data;
}

function transactionAuthority(
	transaction: TenantTransaction,
): TenantTransaction & AuthorizationAuthorityTransaction {
	if (typeof transaction.rawTransactionQuery !== "function") {
		return tenantError(
			"SERVICE_UNAVAILABLE",
			"TENANT_ADMINISTRATION_TRANSACTION_REQUIRED",
			"Tenant administration is unavailable",
		);
	}
	return transaction as TenantTransaction & AuthorizationAuthorityTransaction;
}

async function requireLivePrincipal(
	transaction: TenantTransaction,
	organizationId: string,
	principalId: string,
	actor: boolean,
): Promise<void> {
	let member: Record<string, unknown> | null;
	let user: Record<string, unknown> | null;
	if (typeof transaction.rawTransactionQuery === "function") {
		const userRows = await transaction.rawTransactionQuery<
			Record<string, unknown>
		>(
			`SELECT id, banned
			 FROM "user"
			 WHERE id = $1
			 FOR UPDATE`,
			[principalId],
		);
		const memberRows = await transaction.rawTransactionQuery<
			Record<string, unknown>
		>(
			`SELECT id
			 FROM "member"
			 WHERE "organizationId" = $1 AND "userId" = $2
			 FOR UPDATE`,
			[organizationId, principalId],
		);
		member = memberRows.rows[0] ?? null;
		user = userRows.rows[0] ?? null;
	} else {
		[member, user] = await Promise.all([
			transaction.findOne<Record<string, unknown>>({
				model: "member",
				where: [
					{ field: "organizationId", value: organizationId },
					{ field: "userId", value: principalId },
				],
			}),
			transaction.findOne<Record<string, unknown>>({
				model: "user",
				where: [{ field: "id", value: principalId }],
			}),
		]);
	}
	if (!member || !user || user.banned === true) {
		return actor
			? tenantError(
					"FORBIDDEN",
					"TENANT_AUTHORIZATION_REQUIRED",
					"Tenant authorization is required",
				)
			: tenantError(
					"NOT_FOUND",
					"TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND",
					"Resource not found",
				);
	}
}

function actionsForRoles(
	roles: readonly AuthorizationAuthorityRole[],
	requestedRoleIds: readonly string[],
): readonly string[] {
	const available = new Map(
		roles
			.filter((role) => role.status === "active")
			.map((role) => [role.roleId, role] as const),
	);
	const actions = new Set<string>();
	for (const requestedRoleId of requestedRoleIds) {
		const role = available.get(requestedRoleId);
		if (!role) {
			return tenantError(
				"NOT_FOUND",
				"TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND",
				"Resource not found",
			);
		}
		for (const action of role.actions) actions.add(action);
	}
	return Object.freeze([...actions].sort());
}

function requireDominance(
	actorActions: ReadonlySet<string>,
	targetActions: readonly string[],
): void {
	if (!targetActions.every((action) => actorActions.has(action))) {
		return tenantError(
			"FORBIDDEN",
			"TENANT_ADMINISTRATION_ESCALATION_DENIED",
			"Tenant authorization is required",
		);
	}
}

async function ownedServiceAccount(
	authorization: PostgresAuthorizationAuthority,
	transaction: AuthorizationAuthorityTransaction | undefined,
	organizationId: string,
	serviceAccountId: string,
): Promise<AuthorizationServiceAccount> {
	const account = (
		await authorization.listServiceAccounts({
			organizationId,
			...(transaction ? { transaction } : {}),
		})
	).find((candidate) => candidate.serviceAccountId === serviceAccountId);
	if (!account) {
		return tenantError(
			"NOT_FOUND",
			"TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND",
			"Resource not found",
		);
	}
	return account;
}

async function serviceAccountActions(
	authorization: PostgresAuthorizationAuthority,
	transaction: AuthorizationAuthorityTransaction,
	organizationId: string,
	serviceAccountId: string,
): Promise<readonly string[]> {
	await ownedServiceAccount(
		authorization,
		transaction,
		organizationId,
		serviceAccountId,
	);
	const [assignments, roles] = await Promise.all([
		authorization.listSubjectAssignments({
			organizationId,
			subject: { kind: "service_account", id: serviceAccountId },
			transaction,
		}),
		authorization.listRoles({ organizationId, transaction }),
	]);
	return actionsForRoles(
		roles,
		assignments.map((assignment) => assignment.roleId),
	);
}

async function appendTenantAudit(
	ctx: GenericEndpointContext,
	runtimeAudit: InternalRuntimeAuditBinding,
	mutation: TenantMutationContext,
	input: AuditInput,
): Promise<void> {
	const request = await getRuntimeAuditRequestContext();
	if (!request) {
		return tenantError(
			"SERVICE_UNAVAILABLE",
			"TENANT_ADMINISTRATION_AUDIT_UNAVAILABLE",
			"Tenant administration is unavailable",
		);
	}
	if (
		runtimeAudit.identity.projectId.length === 0 ||
		runtimeAudit.identity.environmentId.length === 0
	) {
		return tenantError(
			"SERVICE_UNAVAILABLE",
			"TENANT_ADMINISTRATION_AUDIT_UNAVAILABLE",
			"Tenant administration is unavailable",
		);
	}
	attachCapturedInternalRuntimeAudit(mutation.transaction, runtimeAudit);
	await appendInternalRuntimeAudit(mutation.transaction, {
		actor: mutation.actorId,
		action: input.action,
		subjectType: input.subjectType,
		subjectId: input.subjectId,
		outcome: "success",
		source: "system",
		organizationId: mutation.organizationId,
		message: input.message,
		metadata: input.metadata ?? {},
		request,
	});
	void ctx;
}

async function requireFreshActor(
	authorization: PostgresAuthorizationAuthority,
	transaction: AuthorizationAuthorityTransaction,
	organizationId: string,
	actorId: string,
	requiredAction: string,
): Promise<ReadonlySet<string>> {
	const effective = await authorization.readEffective({
		organizationId,
		subject: { kind: "principal", id: actorId },
		transaction,
	});
	if (!effective.actions.includes(requiredAction)) {
		return tenantError(
			"FORBIDDEN",
			"TENANT_AUTHORIZATION_REQUIRED",
			"Tenant authorization is required",
		);
	}
	return new Set(effective.actions);
}

async function lockLivePrincipals(
	transaction: TenantTransaction,
	organizationId: string,
	actorId: string,
	targetIds: readonly string[],
): Promise<void> {
	/* Canonical lock order shared by tenant mutations: organization, actor,
	 * then deterministic targets. The authorization advisory lock is acquired
	 * by the caller before this function so membership/archive writers cannot
	 * invert the order. */
	await requireLiveOrganization(transaction, organizationId);
	await requireLivePrincipal(transaction, organizationId, actorId, true);
	for (const principalId of [...new Set(targetIds)].filter((id) => id !== actorId).sort()) {
		await requireLivePrincipal(
			transaction,
			organizationId,
			principalId,
			false,
		);
	}
}

async function requireLiveOrganization(
	transaction: TenantTransaction,
	organizationId: string,
): Promise<void> {
	if (typeof transaction.rawTransactionQuery !== "function") {
		return tenantError(
			"SERVICE_UNAVAILABLE",
			"TENANT_ADMINISTRATION_TRANSACTION_REQUIRED",
			"Tenant administration is unavailable",
		);
	}
	const rows = await transaction.rawTransactionQuery<Record<string, unknown>>(
		`SELECT id FROM organization WHERE id = $1 FOR UPDATE`,
		[organizationId],
	);
	if (!rows.rows[0]) {
		return tenantError(
			"NOT_FOUND",
			"TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND",
			"Resource not found",
		);
	}
}

async function withMutation<Result>(
	ctx: GenericEndpointContext,
	options: TenantAdministrationOptions,
	input: Readonly<{
		organizationId: string;
		requiredAction: string;
		preview: boolean;
		principalTargetIds?: readonly string[];
	}>,
	mutate: (context: TenantMutationContext) => Promise<Result>,
): Promise<Result> {
	const organizationId = routeIdentifier(input.organizationId);
	return withTenantCapability(
		ctx,
		{
			organizationId,
			requiredActions: [input.requiredAction],
		},
		async (capability) => {
			try {
				if (
					typeof ctx.context.adapter.options?.adapterConfig.transaction !==
					"function"
				) {
					return tenantError(
						"SERVICE_UNAVAILABLE",
						"TENANT_ADMINISTRATION_TRANSACTION_REQUIRED",
						"Tenant administration is unavailable",
					);
				}
				const result = await runWithTransaction(
					ctx.context.adapter,
					async (): Promise<Result> => {
						const rawTransaction = await getCurrentAdapter(
							ctx.context.adapter,
						);
						const transaction = transactionAuthority(rawTransaction);
						await options.authorization.acquireMutationLock(transaction);
						await lockLivePrincipals(
							transaction,
							capability.organizationId,
							capability.principalId,
							input.principalTargetIds ?? [],
						);
						const actorActions = await requireFreshActor(
							options.authorization,
							transaction,
							capability.organizationId,
							capability.principalId,
							input.requiredAction,
						);
						const mutation = Object.freeze({
							transaction,
							organizationId: capability.organizationId,
							actorId: capability.principalId,
							actorActions,
						});
						const value = await mutate(mutation);
						if (input.preview) throw new PreviewRollback(value);
						return value;
					},
				);
				return result;
			} catch (error) {
				if (error instanceof PreviewRollback) {
					return error.result as Result;
				}
				return mapTenantError(error);
			}
		},
	);
}

async function withRead<Result>(
	ctx: GenericEndpointContext,
	options: TenantAdministrationOptions,
	organizationId: string,
	read: (
		organizationId: string,
		actorId: string,
	) => Promise<Result>,
): Promise<Result> {
	const normalizedOrganizationId = routeIdentifier(organizationId);
	return withTenantCapability(
		ctx,
		{ organizationId: normalizedOrganizationId, requiredActions: ["ac:read"] },
		async (capability) => {
			try {
				await requireLivePrincipal(
					ctx.context.adapter,
					capability.organizationId,
					capability.principalId,
					true,
				);
				return await read(
					capability.organizationId,
					capability.principalId,
				);
			} catch (error) {
				return mapTenantError(error);
			}
		},
	);
}

async function withProductMutation<Result>(
	ctx: GenericEndpointContext,
	options: TenantAdministrationOptions,
	organizationId: string,
	mutate: (
		facade: TenantProductAdministrationFacade,
		organizationId: string,
		actorId: string,
	) => Promise<Result>,
): Promise<Result> {
	const normalizedOrganizationId = routeIdentifier(organizationId);
	const facade = options.productAdministration;
	if (!facade) {
		return tenantError(
			"SERVICE_UNAVAILABLE",
			"TENANT_PRODUCT_ADMINISTRATION_UNAVAILABLE",
			"Enterprise administration is unavailable",
		);
	}
	return withTenantCapability(
		ctx,
		{
			organizationId: normalizedOrganizationId,
			requiredActions: ["organization:update"],
		},
		async (capability) => {
			try {
				if (
					typeof ctx.context.adapter.options?.adapterConfig.transaction !==
					"function"
				) {
					return tenantError(
						"SERVICE_UNAVAILABLE",
						"TENANT_ADMINISTRATION_TRANSACTION_REQUIRED",
						"Tenant administration is unavailable",
					);
				}
				// Preview and commit each get a short, committed runtime preflight.
				// Commit is then revalidated by the management facade inside its own
				// coordinated transaction; retaining this transaction while calling the
				// facade would deadlock on the same authorization advisory lock.
				await runWithTransaction(ctx.context.adapter, async () => {
					const transaction = transactionAuthority(
						await getCurrentAdapter(ctx.context.adapter),
					);
					await options.authorization.acquireMutationLock(transaction);
					await lockLivePrincipals(
						transaction,
						capability.organizationId,
						capability.principalId,
						[],
					);
					await requireFreshActor(
						options.authorization,
						transaction,
						capability.organizationId,
						capability.principalId,
						"organization:update",
					);
				});
				return await mutate(
					facade,
					capability.organizationId,
					capability.principalId,
				);
			} catch (error) {
				return mapProductAdministrationError(error);
			}
		},
	);
}

async function withProductRead<Result>(
	ctx: GenericEndpointContext,
	options: TenantAdministrationOptions,
	organizationId: string,
	read: (
		facade: TenantProductAdministrationFacade,
		organizationId: string,
		actorId: string,
	) => Promise<Result>,
): Promise<Result> {
	const normalizedOrganizationId = routeIdentifier(organizationId);
	const facade = options.productAdministration;
	if (!facade) {
		return tenantError(
			"SERVICE_UNAVAILABLE",
			"TENANT_PRODUCT_ADMINISTRATION_UNAVAILABLE",
			"Enterprise administration is unavailable",
		);
	}
	return withTenantCapability(
		ctx,
		{
			organizationId: normalizedOrganizationId,
			requiredActions: ["ac:read"],
		},
		async (capability) => {
			try {
				await requireLivePrincipal(
					ctx.context.adapter,
					capability.organizationId,
					capability.principalId,
					true,
				);
				return await read(
					facade,
					capability.organizationId,
					capability.principalId,
				);
			} catch (error) {
				return mapProductAdministrationError(error);
			}
		},
	);
}

function assignmentView(
	organizationId: string,
	subject: AuthorizationSubject,
	roleIds: readonly string[],
) {
	return Object.freeze({
		organizationId,
		subject: Object.freeze({ ...subject }),
		roleIds: Object.freeze([...roleIds]),
	});
}

function credentialView(
	credential: Awaited<
		ReturnType<PostgresAuthorizationAuthority["createServiceAccountCredential"]>
	>["credential"],
) {
	return Object.freeze({
		organizationId: credential.organizationId,
		serviceAccountId: credential.serviceAccountId,
		credentialId: credential.credentialId,
		credentialPrefix: credential.credentialPrefix,
		credentialFingerprint: credential.credentialFingerprint,
		expiresAt: credential.expiresAt?.toISOString() ?? null,
		version: credential.version,
	});
}

export function createTenantAdministrationPlugin(
	options: TenantAdministrationOptions,
): ClearancePlugin {
	return {
		id: "clearance-tenant-administration",
		endpoints: {
			tenantProductAuditList: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/audit",
				{
					method: "GET",
					requireHeaders: true,
					query: auditListQuery,
				},
				async (ctx) =>
					ctx.json(
						await withProductRead(
							ctx,
							options,
							ctx.params.organizationId,
							(facade, organizationId, actorId) =>
								facade.listAudit({
									organizationId,
									actorId,
									...(ctx.query.limit === undefined
										? {}
										: { limit: ctx.query.limit }),
									...(ctx.query.cursor
										? { cursor: ctx.query.cursor }
										: {}),
									...(ctx.query.action
										? { action: ctx.query.action }
										: {}),
								}),
						),
					),
			),
			tenantProductSsoList: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/sso",
				{ method: "GET", requireHeaders: true },
				async (ctx) =>
					ctx.json({
						connections: await withProductRead(
							ctx,
							options,
							ctx.params.organizationId,
							(facade, organizationId, actorId) =>
								facade.listSso({ organizationId, actorId }),
						),
					}),
			),
			tenantProductSsoInspect: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/sso/:connectionId",
				{ method: "GET", requireHeaders: true },
				async (ctx) =>
					ctx.json({
						connection: await withProductRead(
							ctx,
							options,
							ctx.params.organizationId,
							(facade, organizationId, actorId) =>
								facade.inspectSso({
									organizationId,
									actorId,
									connectionId: routeIdentifier(
										ctx.params.connectionId,
									),
								}),
						),
					}),
			),
			tenantProductSsoCreate: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/sso",
				{
					method: "POST",
					requireHeaders: true,
					body: ssoCreateBody,
				},
				async (ctx) => {
					const ssoInput = ctx.body;
					const result = await withProductMutation(
						ctx,
						options,
						ctx.params.organizationId,
						async (facade, organizationId, actorId) => {
							if (ssoInput.dryRun) {
								const proposed = ssoInput.protocol === "oidc"
									? {
										organizationId, protocol: ssoInput.protocol,
										provider: ssoInput.provider, issuer: ssoInput.issuer,
										domain: ssoInput.domain, audience: ssoInput.audience ?? null,
										clientId: ssoInput.clientId, hasClientSecret: true,
									}
									: {
										organizationId, protocol: ssoInput.protocol,
										provider: ssoInput.provider, issuer: ssoInput.issuer,
										domain: ssoInput.domain, audience: ssoInput.audience ?? null,
										samlEntryPoint: ssoInput.samlEntryPoint,
										hasSamlCertificate: true,
									};
								return Object.freeze({
									preview: true,
									proposed: Object.freeze(proposed),
									wouldChange: true,
								});
							}
							const connection = await facade.createSso(ssoInput.protocol === "oidc" ? {
								organizationId,
								actorId,
								protocol: ssoInput.protocol, provider: ssoInput.provider,
								issuer: ssoInput.issuer, domain: ssoInput.domain,
								...(ssoInput.audience
									? { audience: ssoInput.audience }
									: {}),
								clientId: ssoInput.clientId, clientSecret: ssoInput.clientSecret,
							} : {
								organizationId, actorId, protocol: ssoInput.protocol,
								provider: ssoInput.provider, issuer: ssoInput.issuer,
								domain: ssoInput.domain,
								...(ssoInput.audience ? { audience: ssoInput.audience } : {}),
								samlEntryPoint: ssoInput.samlEntryPoint,
								samlCertificate: ssoInput.samlCertificate,
							});
							return Object.freeze({ connection });
						},
					);
					noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantProductSsoDisable: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/sso/:connectionId/disable",
				{
					method: "POST",
					requireHeaders: true,
					body: productMutationConfirmation,
				},
				async (ctx) => {
					const connectionId = routeIdentifier(
						ctx.params.connectionId,
					);
					const result = await withProductMutation(
						ctx,
						options,
						ctx.params.organizationId,
						async (facade, organizationId, actorId) => {
							if (ctx.body.dryRun) {
								const connection = await facade.inspectSso({
									organizationId,
									actorId,
									connectionId,
								});
								return Object.freeze({
									preview: true,
									connection,
									wouldChange:
										connection.status !== "disabled",
								});
							}
							return facade.disableSso({
								organizationId,
								actorId,
								connectionId,
							});
						},
					);
					noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantProductSsoTest: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/sso/:connectionId/test",
				{
					method: "POST",
					requireHeaders: true,
					body: productMutationConfirmation,
				},
				async (ctx) => {
					const connectionId = routeIdentifier(ctx.params.connectionId);
					const result = await withProductMutation(
						ctx,
						options,
						ctx.params.organizationId,
						async (facade, organizationId, actorId) => {
							if (ctx.body.dryRun) {
								return Object.freeze({
									preview: true,
									connection: await facade.inspectSso({
										organizationId,
										actorId,
										connectionId,
									}),
									wouldChange: true,
								});
							}
							return facade.testSso({
								organizationId,
								actorId,
								connectionId,
							});
						},
					);
					noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantProductSsoReplaceSecret: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/sso/:connectionId/replace-secret",
				{
					method: "POST",
					requireHeaders: true,
					body: ssoSecretReplacementBody,
				},
				async (ctx) => {
					const connectionId = routeIdentifier(ctx.params.connectionId);
					const result = await withProductMutation(
						ctx,
						options,
						ctx.params.organizationId,
						async (facade, organizationId, actorId) => {
							if (ctx.body.dryRun) {
								return Object.freeze({
									preview: true,
									connection: await facade.inspectSso({
										organizationId,
										actorId,
										connectionId,
									}),
									wouldChange: true,
								});
							}
							return facade.replaceSsoSecret({
								organizationId,
								actorId,
								connectionId,
								operationId: ctx.body.operationId!,
								newClientSecret: ctx.body.newClientSecret,
							});
						},
					);
					noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantProductScimList: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/scim",
				{ method: "GET", requireHeaders: true },
				async (ctx) =>
					ctx.json({
						connections: await withProductRead(
							ctx,
							options,
							ctx.params.organizationId,
							(facade, organizationId, actorId) =>
								facade.listScim({ organizationId, actorId }),
						),
					}),
			),
			tenantProductScimInspect: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/scim/:connectionId",
				{ method: "GET", requireHeaders: true },
				async (ctx) =>
					ctx.json({
						connection: await withProductRead(
							ctx,
							options,
							ctx.params.organizationId,
							(facade, organizationId, actorId) =>
								facade.inspectScim({
									organizationId,
									actorId,
									connectionId: routeIdentifier(
										ctx.params.connectionId,
									),
								}),
						),
					}),
			),
			tenantProductScimCreate: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/scim",
				{
					method: "POST",
					requireHeaders: true,
					body: scimCreateBody,
				},
				async (ctx) => {
					const result = await withProductMutation(
						ctx,
						options,
						ctx.params.organizationId,
						async (facade, organizationId, actorId) => {
							if (ctx.body.dryRun) {
								return Object.freeze({
									preview: true,
									proposed: Object.freeze({
										organizationId,
										provider: ctx.body.provider,
										endpoint: ctx.body.endpoint ?? null,
										bearerTokenGenerated: false,
									}),
									wouldChange: true,
								});
							}
							return facade.createScim({
								organizationId,
								actorId,
								operationId: ctx.body.operationId!,
								provider: ctx.body.provider,
								...(ctx.body.endpoint
									? { endpoint: ctx.body.endpoint }
									: {}),
							});
						},
					);
					noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantProductScimDisable: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/scim/:connectionId/disable",
				{
					method: "POST",
					requireHeaders: true,
					body: productMutationConfirmation,
				},
				async (ctx) => {
					const connectionId = routeIdentifier(
						ctx.params.connectionId,
					);
					const result = await withProductMutation(
						ctx,
						options,
						ctx.params.organizationId,
						async (facade, organizationId, actorId) => {
							if (ctx.body.dryRun) {
								const connection = await facade.inspectScim({
									organizationId,
									actorId,
									connectionId,
								});
								return Object.freeze({
									preview: true,
									connection,
									wouldChange:
										connection.status !== "disabled",
								});
							}
							return facade.disableScim({
								organizationId,
								actorId,
								connectionId,
							});
						},
					);
					noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantProductScimTest: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/scim/:connectionId/test",
				{
					method: "POST",
					requireHeaders: true,
					body: productMutationConfirmation,
				},
				async (ctx) => {
					const connectionId = routeIdentifier(ctx.params.connectionId);
					const result = await withProductMutation(
						ctx,
						options,
						ctx.params.organizationId,
						async (facade, organizationId, actorId) => {
							if (ctx.body.dryRun) {
								return Object.freeze({
									preview: true,
									connection: await facade.inspectScim({
										organizationId,
										actorId,
										connectionId,
									}),
									wouldChange: true,
								});
							}
							return facade.testScim({
								organizationId,
								actorId,
								connectionId,
							});
						},
					);
					noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantProductScimRotate: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/scim/:connectionId/rotate",
				{
					method: "POST",
					requireHeaders: true,
					body: scimRotateBody,
				},
				async (ctx) => {
					const connectionId = routeIdentifier(ctx.params.connectionId);
					const result = await withProductMutation(
						ctx,
						options,
						ctx.params.organizationId,
						async (facade, organizationId, actorId) => {
							if (ctx.body.dryRun) {
								return Object.freeze({
									preview: true,
									connection: await facade.inspectScim({
										organizationId,
										actorId,
										connectionId,
									}),
									wouldChange: true,
								});
							}
							return facade.rotateScim({
								organizationId,
								actorId,
								connectionId,
								operationId: ctx.body.operationId!,
							});
						},
					);
					noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantProductReadiness: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/enterprise/readiness",
				{ method: "GET", requireHeaders: true },
				async (ctx) =>
					ctx.json({
						report: await withProductRead(
							ctx,
							options,
							ctx.params.organizationId,
							(facade, organizationId, actorId) =>
								facade.readiness({
									organizationId,
									actorId,
								}),
						),
					}),
			),
			tenantAuthorizationRoles: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/authorization/roles",
				{ method: "GET", requireHeaders: true },
				async (ctx) =>
					ctx.json(
						await withRead(
							ctx,
							options,
							ctx.params.organizationId,
							(organizationId) =>
								options.authorization.listRoles({ organizationId }),
						),
					),
			),
			tenantAuthorizationEffective: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/authorization/effective",
				{
					method: "POST",
					requireHeaders: true,
					body: effectiveBody,
				},
				async (ctx) =>
					ctx.json(
						await withRead(
							ctx,
							options,
							ctx.params.organizationId,
							async (organizationId) => {
								if (ctx.body.subject.kind === "principal") {
									await requireLivePrincipal(
										ctx.context.adapter,
										organizationId,
										ctx.body.subject.id,
										false,
									);
								} else {
									await ownedServiceAccount(
										options.authorization,
										undefined,
										organizationId,
										ctx.body.subject.id,
									);
								}
								return options.authorization.readEffective({
									organizationId,
									subject: ctx.body.subject,
								});
							},
						),
					),
			),
			tenantAuthorizationAssignments: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/authorization/assignments/list",
				{
					method: "POST",
					requireHeaders: true,
					body: assignmentListBody,
				},
				async (ctx) =>
					ctx.json(
						await withRead(
							ctx,
							options,
							ctx.params.organizationId,
							async (organizationId) => {
								const requestedSubject = ctx.body.subject;
								if (requestedSubject?.kind === "principal") {
									await requireLivePrincipal(
										ctx.context.adapter,
										organizationId,
										requestedSubject.id,
										false,
									);
								} else if (requestedSubject) {
									const accounts =
										await options.authorization.listServiceAccounts({
											organizationId,
										});
									if (
										!accounts.some(
											(account) =>
												account.serviceAccountId === requestedSubject.id,
										)
									) {
										return tenantError(
											"NOT_FOUND",
											"TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND",
											"Resource not found",
										);
									}
								}
								return options.authorization.listSubjectAssignments({
									organizationId,
									...(requestedSubject
										? { subject: requestedSubject }
										: {}),
								});
							},
						),
					),
			),
			tenantAuthorizationAssignmentReplace: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/authorization/assignments/replace",
				{
					method: "POST",
					requireHeaders: true,
					body: assignmentReplaceBody,
				},
				async (ctx) => {
					const result = await withMutation(
						ctx,
						options,
						{
							organizationId: ctx.params.organizationId,
							requiredAction: "ac:update",
							preview: ctx.body.dryRun,
							...(ctx.body.subject.kind === "principal"
								? { principalTargetIds: [ctx.body.subject.id] }
								: {}),
						},
						async (mutation) => {
							if (ctx.body.subject.kind === "principal") {
								const current =
									await options.authorization.readEffective({
										organizationId: mutation.organizationId,
										subject: ctx.body.subject,
										transaction: mutation.transaction,
									});
								requireDominance(
									mutation.actorActions,
									current.actions,
								);
							} else {
								await ownedServiceAccount(
									options.authorization,
									mutation.transaction,
									mutation.organizationId,
									ctx.body.subject.id,
								);
								requireDominance(
									mutation.actorActions,
									await serviceAccountActions(
										options.authorization,
										mutation.transaction,
										mutation.organizationId,
										ctx.body.subject.id,
									),
								);
							}
							const roles = await options.authorization.listRoles({
								organizationId: mutation.organizationId,
								transaction: mutation.transaction,
							});
							requireDominance(
								mutation.actorActions,
								actionsForRoles(roles, ctx.body.roleIds),
							);
							const replaced =
								await options.authorization.replaceSubjectRoles({
									organizationId: mutation.organizationId,
									subject: ctx.body.subject,
									roleIds: ctx.body.roleIds,
									...(ctx.body.expectedRevision
										? {
												expectedRevision:
													ctx.body.expectedRevision,
											}
										: {}),
									transaction: mutation.transaction,
								});
							if (replaced.changed) {
								await appendTenantAudit(ctx, options.runtimeAudit, mutation, {
									action: "tenant.authorization.assignments.replace",
									subjectType: ctx.body.subject.kind,
									subjectId: ctx.body.subject.id,
									message: "Tenant authorization assignments replaced",
									metadata: {
										roleIds: replaced.roleIds,
										previousRevision: replaced.previousRevision,
										revision: replaced.revision,
									},
								});
							}
							return ctx.body.dryRun
								? Object.freeze({
										preview: true,
										assignment: assignmentView(
											mutation.organizationId,
											ctx.body.subject,
											replaced.roleIds,
										),
										wouldChange: replaced.changed,
										currentRevision: replaced.previousRevision,
									})
								: Object.freeze({
										assignment: assignmentView(
											mutation.organizationId,
											ctx.body.subject,
											replaced.roleIds,
										),
										changed: replaced.changed,
										previousRevision: replaced.previousRevision,
										revision: replaced.revision,
									});
					},
				);
					return ctx.json(result);
				},
			),
			tenantServiceAccounts: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/service-accounts",
				{ method: "GET", requireHeaders: true },
				async (ctx) =>
					ctx.json(
						await withRead(
							ctx,
							options,
							ctx.params.organizationId,
							(organizationId) =>
								options.authorization.listServiceAccounts({
									organizationId,
								}),
						),
					),
			),
			tenantServiceAccountInspect: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/service-accounts/:serviceAccountId",
				{ method: "GET", requireHeaders: true },
				async (ctx) =>
					ctx.json(
						await withRead(
							ctx,
							options,
							ctx.params.organizationId,
							async (organizationId) => {
								const serviceAccount = (
									await options.authorization.listServiceAccounts({
										organizationId,
									})
								).find(
									(account) =>
											account.serviceAccountId ===
										routeIdentifier(
											ctx.params.serviceAccountId,
										),
								);
								if (!serviceAccount) {
									return tenantError(
										"NOT_FOUND",
										"TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND",
										"Resource not found",
									);
								}
								const assignments =
									await options.authorization.listSubjectAssignments({
										organizationId,
										subject: {
											kind: "service_account",
											id: serviceAccount.serviceAccountId,
										},
									});
								return Object.freeze({
									serviceAccount,
									assignments,
								});
							},
						),
					),
			),
			tenantServiceAccountCreate: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/service-accounts",
				{
					method: "POST",
					requireHeaders: true,
					body: serviceAccountCreateBody,
				},
				async (ctx) => {
					const serviceAccountId = `svc_${randomUUID()}`;
					const result = await withMutation(
						ctx,
						options,
						{
							organizationId: ctx.params.organizationId,
							requiredAction: "ac:create",
							preview: ctx.body.dryRun,
						},
						async (mutation) => {
							const roles = await options.authorization.listRoles({
								organizationId: mutation.organizationId,
								transaction: mutation.transaction,
							});
							requireDominance(
								mutation.actorActions,
								actionsForRoles(roles, ctx.body.roleIds),
							);
							const created =
								await options.authorization.createServiceAccount({
									organizationId: mutation.organizationId,
									serviceAccountId,
									name: ctx.body.name,
									roleIds: ctx.body.roleIds,
									transaction: mutation.transaction,
								});
							await appendTenantAudit(ctx, options.runtimeAudit, mutation, {
								action: "tenant.service_accounts.create",
								subjectType: "service_account",
								subjectId: serviceAccountId,
								message: "Tenant service account created",
								metadata: {
									roleIds: ctx.body.roleIds,
									previousRevision: created.previousRevision,
									revision: created.revision,
								},
							});
							return ctx.body.dryRun
								? Object.freeze({
										preview: true,
										serviceAccount: {
											organizationId: mutation.organizationId,
											name: ctx.body.name,
											status: "active" as const,
										},
										roleIds: Object.freeze([...ctx.body.roleIds]),
									})
								: created;
						},
					);
					return ctx.json(result);
				},
			),
			tenantServiceAccountEnable: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/service-accounts/:serviceAccountId/enable",
				{ method: "POST", requireHeaders: true, body: previewBody },
				async (ctx) => {
					const serviceAccountId = routeIdentifier(
						ctx.params.serviceAccountId,
					);
					const result = await withMutation(
						ctx,
						options,
						{
							organizationId: ctx.params.organizationId,
							requiredAction: "ac:update",
							preview: ctx.body.dryRun,
						},
						async (mutation) => {
							requireDominance(
								mutation.actorActions,
								await serviceAccountActions(
									options.authorization,
									mutation.transaction,
									mutation.organizationId,
									serviceAccountId,
								),
							);
							const changed =
								await options.authorization.setServiceAccountStatus({
									organizationId: mutation.organizationId,
									serviceAccountId,
									status: "active",
									transaction: mutation.transaction,
								});
							if (changed.previousRevision !== changed.revision) {
								await appendTenantAudit(ctx, options.runtimeAudit, mutation, {
									action: "tenant.service_accounts.enable",
									subjectType: "service_account",
									subjectId: serviceAccountId,
									message: "Tenant service account enabled",
									metadata: {
										previousRevision: changed.previousRevision,
										revision: changed.revision,
									},
								});
							}
							return ctx.body.dryRun
								? Object.freeze({
										preview: true,
										serviceAccount: changed.serviceAccount,
										wouldChange:
											changed.previousRevision !== changed.revision,
										currentRevision: changed.previousRevision,
									})
								: changed;
						},
					);
					return ctx.json(result);
				},
			),
			tenantServiceAccountDisable: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/service-accounts/:serviceAccountId/disable",
				{
					method: "POST",
					requireHeaders: true,
					body: confirmedPreviewBody,
				},
				async (ctx) => {
					const serviceAccountId = routeIdentifier(
						ctx.params.serviceAccountId,
					);
					const result = await withMutation(
						ctx,
						options,
						{
							organizationId: ctx.params.organizationId,
							requiredAction: "ac:delete",
							preview: ctx.body.dryRun,
						},
						async (mutation) => {
							requireDominance(
								mutation.actorActions,
								await serviceAccountActions(
									options.authorization,
									mutation.transaction,
									mutation.organizationId,
									serviceAccountId,
								),
							);
							const changed =
								await options.authorization.setServiceAccountStatus({
									organizationId: mutation.organizationId,
									serviceAccountId,
									status: "disabled",
									transaction: mutation.transaction,
								});
							if (changed.previousRevision !== changed.revision) {
								await appendTenantAudit(ctx, options.runtimeAudit, mutation, {
									action: "tenant.service_accounts.disable",
									subjectType: "service_account",
									subjectId: serviceAccountId,
									message: "Tenant service account disabled",
									metadata: {
										previousRevision: changed.previousRevision,
										revision: changed.revision,
									},
								});
							}
							return ctx.body.dryRun
								? Object.freeze({
										preview: true,
										serviceAccount: changed.serviceAccount,
										wouldChange:
											changed.previousRevision !== changed.revision,
										currentRevision: changed.previousRevision,
									})
								: changed;
						},
					);
					return ctx.json(result);
				},
			),
			tenantCredentialCreate: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/service-accounts/:serviceAccountId/credentials",
				{
					method: "POST",
					requireHeaders: true,
					body: credentialCreateBody,
				},
				async (ctx) => {
					const serviceAccountId = routeIdentifier(
						ctx.params.serviceAccountId,
					);
					const result = await withMutation(
						ctx,
						options,
						{
							organizationId: ctx.params.organizationId,
							requiredAction: "ac:create",
							preview: ctx.body.dryRun,
						},
						async (mutation) => {
							requireDominance(
								mutation.actorActions,
								await serviceAccountActions(
									options.authorization,
									mutation.transaction,
									mutation.organizationId,
									serviceAccountId,
								),
							);
							const created =
								await options.authorization.createServiceAccountCredential({
									organizationId: mutation.organizationId,
									actorId: mutation.actorId,
									operationId:
										ctx.body.operationId ?? randomUUID(),
									serviceAccountId,
									...(ctx.body.expiresAt
										? { expiresAt: new Date(ctx.body.expiresAt) }
										: {}),
									transaction: mutation.transaction,
								});
							if (!created.replayed) await appendTenantAudit(ctx, options.runtimeAudit, mutation, {
								action: "tenant.service_account_credentials.create",
								subjectType: "service_account_credential",
								subjectId: created.credential.credentialId,
								message: "Tenant service account credential created",
								metadata: {
									serviceAccountId,
									previousRevision: created.previousRevision,
									revision: created.revision,
								},
							});
							return ctx.body.dryRun
								? Object.freeze({
										preview: true,
										organizationId: mutation.organizationId,
										serviceAccountId,
										expiresAt: ctx.body.expiresAt ?? null,
										secretGenerated: false,
									})
								: Object.freeze({
										credential: credentialView(created.credential),
										secret: created.secret,
										previousRevision: created.previousRevision,
										revision: created.revision,
									});
						},
					);
					if (!ctx.body.dryRun) noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantCredentialRotate: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/service-accounts/:serviceAccountId/credentials/:credentialId/rotate",
				{
					method: "POST",
					requireHeaders: true,
					body: credentialRotateBody,
				},
				async (ctx) => {
					const serviceAccountId = routeIdentifier(
						ctx.params.serviceAccountId,
					);
					const credentialId = routeIdentifier(ctx.params.credentialId);
					const result = await withMutation(
						ctx,
						options,
						{
							organizationId: ctx.params.organizationId,
							requiredAction: "ac:update",
							preview: ctx.body.dryRun,
						},
						async (mutation) => {
							requireDominance(
								mutation.actorActions,
								await serviceAccountActions(
									options.authorization,
									mutation.transaction,
									mutation.organizationId,
									serviceAccountId,
								),
							);
							const rotated =
								await options.authorization.rotateServiceAccountCredential({
									organizationId: mutation.organizationId,
									actorId: mutation.actorId,
									operationId:
										ctx.body.operationId ?? randomUUID(),
									serviceAccountId,
									credentialId,
									...(ctx.body.expiresAt
										? { expiresAt: new Date(ctx.body.expiresAt) }
										: {}),
									transaction: mutation.transaction,
								});
							if (!rotated.replayed) await appendTenantAudit(ctx, options.runtimeAudit, mutation, {
								action: "tenant.service_account_credentials.rotate",
								subjectType: "service_account_credential",
								subjectId: rotated.credential.credentialId,
								message: "Tenant service account credential rotated",
								metadata: {
									serviceAccountId,
									previousRevision: rotated.previousRevision,
									revision: rotated.revision,
								},
							});
							return ctx.body.dryRun
								? Object.freeze({
										preview: true,
										organizationId: mutation.organizationId,
										serviceAccountId,
										credentialId,
										expiresAt: ctx.body.expiresAt ?? null,
										secretGenerated: false,
									})
								: Object.freeze({
										credential: credentialView(rotated.credential),
										secret: rotated.secret,
										previousRevision: rotated.previousRevision,
										revision: rotated.revision,
									});
						},
					);
					if (!ctx.body.dryRun) noStore(ctx);
					return ctx.json(result);
				},
			),
			tenantCredentialRevoke: createAuthEndpoint(
				"/tenant/v1/organizations/:organizationId/service-accounts/:serviceAccountId/credentials/:credentialId/revoke",
				{
					method: "POST",
					requireHeaders: true,
					body: confirmedPreviewBody,
				},
				async (ctx) => {
					const serviceAccountId = routeIdentifier(
						ctx.params.serviceAccountId,
					);
					const credentialId = routeIdentifier(ctx.params.credentialId);
					const result = await withMutation(
						ctx,
						options,
						{
							organizationId: ctx.params.organizationId,
							requiredAction: "ac:delete",
							preview: ctx.body.dryRun,
						},
						async (mutation) => {
							requireDominance(
								mutation.actorActions,
								await serviceAccountActions(
									options.authorization,
									mutation.transaction,
									mutation.organizationId,
									serviceAccountId,
								),
							);
							const revoked =
								await options.authorization.revokeServiceAccountCredential({
									organizationId: mutation.organizationId,
									serviceAccountId,
									credentialId,
									transaction: mutation.transaction,
								});
							await appendTenantAudit(ctx, options.runtimeAudit, mutation, {
								action: "tenant.service_account_credentials.revoke",
								subjectType: "service_account_credential",
								subjectId: credentialId,
								message: "Tenant service account credential revoked",
								metadata: {
									serviceAccountId,
									previousRevision: revoked.previousRevision,
									revision: revoked.revision,
								},
							});
							return ctx.body.dryRun
								? Object.freeze({
										preview: true,
										organizationId: mutation.organizationId,
										serviceAccountId,
										credentialId,
										wouldChange: true,
									})
								: Object.freeze({
										organizationId: mutation.organizationId,
										serviceAccountId,
										credentialId,
										previousRevision: revoked.previousRevision,
										revision: revoked.revision,
									});
						},
					);
					return ctx.json(result);
				},
			),
		},
	};
}
