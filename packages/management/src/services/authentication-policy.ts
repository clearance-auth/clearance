import type { ClearanceAuthBundle } from "@clearance/auth";
import type { OperationContext } from "../application/context.js";
import { getAuthBundle, ensureAuthMigrated } from "../auth-bridge.js";
import { mutateCoordinatedWithRuntimeSql } from "../store/coordinated-internal.js";
import type {
	InternalManagementCoordinatedMutationContext,
	ManagementStore,
} from "../store/types.js";
import { appendAuditEvent } from "./audit.js";
import { inspectOrganizationAuthoritative } from "./core.js";
import { ClearanceError } from "./errors.js";
import { assertResourceInScope } from "./scope.js";

type AuthenticationPolicyFacade = NonNullable<
	ClearanceAuthBundle["authenticationPolicy"]
>;
type WithoutTransaction<Input> = Input extends unknown
	? Omit<Input, "transaction">
	: never;

export type AuthenticationPolicyGetResult = Awaited<
	ReturnType<AuthenticationPolicyFacade["get"]>
>;
export type AuthenticationPolicyPlanInput = WithoutTransaction<
	Parameters<AuthenticationPolicyFacade["plan"]>[0]
>;
export type AuthenticationPolicyPlanResult = Awaited<
	ReturnType<AuthenticationPolicyFacade["plan"]>
>;
export type AuthenticationPolicyApplyInput = WithoutTransaction<
	Parameters<AuthenticationPolicyFacade["apply"]>[0]
>;
export type AuthenticationPolicyApplyResult = Awaited<
	ReturnType<AuthenticationPolicyFacade["apply"]>
>;
export type AuthenticationUnlockInput = WithoutTransaction<
	Parameters<AuthenticationPolicyFacade["unlock"]>[0]
>;
export type AuthenticationUnlockPreview = Awaited<
	ReturnType<AuthenticationPolicyFacade["planUnlock"]>
>;
export type AuthenticationUnlockResult = Awaited<
	ReturnType<AuthenticationPolicyFacade["unlock"]>
>;

export type AuthenticationPolicyApplyControlResult = Readonly<{
	dryRun: boolean;
	result: AuthenticationPolicyPlanResult | AuthenticationPolicyApplyResult;
}>;

export type AuthenticationUnlockControlResult = Readonly<{
	dryRun: boolean;
	result: AuthenticationUnlockPreview | AuthenticationUnlockResult;
}>;

function policyError(
	code: string,
	message: string,
	stage: string,
	status: number,
	remediation?: string,
): ClearanceError {
	return new ClearanceError({ code, message, stage, status, remediation });
}

function errorCode(error: unknown): string | undefined {
	if (typeof error !== "object" || error === null || !("code" in error)) {
		return undefined;
	}
	return typeof error.code === "string" ? error.code : undefined;
}

function translatePolicyError(error: unknown, stage: string): never {
	if (error instanceof ClearanceError) throw error;
	const code = errorCode(error);
	if (code === "AUTHENTICATION_POLICY_INPUT_INVALID") {
		throw policyError(
			code,
			"Authentication policy input is invalid.",
			stage,
			400,
			"Correct the policy document or identifier and retry the plan.",
		);
	}
	if (code === "AUTHENTICATION_POLICY_REVISION_CONFLICT") {
		throw policyError(
			code,
			"Authentication policy revision changed.",
			stage,
			409,
			"Get the current policy, create a new plan, and retry with its expectedRevision.",
		);
	}
	if (code === "AUTHENTICATION_POLICY_REVISION_OVERFLOW") {
		throw policyError(
			code,
			"Authentication policy revision is exhausted.",
			stage,
			409,
			"Create a new environment authority before another policy mutation.",
		);
	}
	if (
		code === "AUTHENTICATION_POLICY_SCOPE_NOT_FOUND" ||
		code === "AUTHENTICATION_POLICY_ORGANIZATION_NOT_FOUND" ||
		code === "AUTHENTICATION_POLICY_USER_NOT_FOUND"
	) {
		throw policyError(code, "Authentication policy target not found.", stage, 404);
	}
	if (
		code === "AUTHENTICATION_POLICY_AUTHORITY_UNAVAILABLE" ||
		code === "AUTHENTICATION_POLICY_SCHEMA_INCOMPATIBLE"
	) {
		throw policyError(
			code,
			"Authentication policy authority is unavailable.",
			stage,
			503,
			"Run the managed runtime migration and restore the exact authority schema before retrying.",
		);
	}
	throw policyError(
		"AUTHENTICATION_POLICY_OPERATION_FAILED",
		"Authentication policy operation failed.",
		stage,
		500,
		"Inspect the API logs and PostgreSQL authority health before retrying.",
	);
}

function requirePostgres(store: ManagementStore, stage: string): void {
	if (store.backend !== "postgres" || typeof store.mutateCoordinated !== "function") {
		throw policyError(
			"AUTHENTICATION_POLICY_POSTGRES_REQUIRED",
			"Managed authentication policy requires the PostgreSQL management backend.",
			stage,
			400,
			"Configure DATABASE_URL and the explicit CLEARANCE_PROJECT_ID/CLEARANCE_ENV_ID scope.",
		);
	}
}

async function facade(
	store: ManagementStore,
	context: OperationContext,
	stage: string,
): Promise<AuthenticationPolicyFacade> {
	requirePostgres(store, stage);
	const candidate = getAuthBundle().authenticationPolicy;
	if (!candidate) {
		throw policyError(
			"AUTHENTICATION_POLICY_NOT_CONFIGURED",
			"Managed authentication policy is not configured.",
			stage,
			503,
			"Set matching CLEARANCE_PROJECT_ID and CLEARANCE_ENV_ID values, migrate, and restart the API.",
		);
	}
	if (
		candidate.scope.projectId !== context.scope.projectId ||
		candidate.scope.environmentId !== context.scope.environmentId
	) {
		throw policyError(
			"AUTHENTICATION_POLICY_SCOPE_MISMATCH",
			"Managed authentication policy scope does not match the authenticated principal.",
			stage,
			403,
			"Use an API credential bound to the configured policy project and environment.",
		);
	}
	await ensureAuthMigrated();
	return candidate;
}

async function assertOrganizationTarget(
	store: ManagementStore,
	context: OperationContext,
	organizationId: string | undefined,
	stage: string,
): Promise<void> {
	if (organizationId === undefined) return;
	try {
		await inspectOrganizationAuthoritative(store, organizationId, context.scope);
	} catch (error) {
		if (error instanceof ClearanceError && error.code === "ORG_NOT_FOUND") {
			throw policyError(
				"AUTHENTICATION_POLICY_ORGANIZATION_NOT_FOUND",
				"Authentication policy target not found.",
				stage,
				404,
			);
		}
		throw error;
	}
}

async function assertOrganizationTargetInCoordinatedContext(
	context: InternalManagementCoordinatedMutationContext,
	operation: OperationContext,
	organizationId: string | undefined,
	stage: string,
): Promise<void> {
	if (organizationId === undefined) return;
	if (!context.topology) {
		assertResourceInScope(
			context.data.organizations.find(
				(organization) => organization.id === organizationId,
			),
			operation.scope,
			{
				code: "AUTHENTICATION_POLICY_ORGANIZATION_NOT_FOUND",
				stage,
				label: "Organization",
			},
		);
		return;
	}
	const organization = await context.topology.lockOrganization({
		scope: operation.scope,
		id: organizationId,
	});
	if (!organization || organization.status === "archived") {
		throw policyError(
			"AUTHENTICATION_POLICY_ORGANIZATION_NOT_FOUND",
			"Authentication policy target not found.",
			stage,
			404,
		);
	}
}

async function assertUserTarget(
	store: Pick<ManagementStore, "snapshot" | "storeV2Principals">,
	context: OperationContext,
	userId: string,
	stage: string,
): Promise<void> {
	if (store.storeV2Principals?.authoritative) {
		const principal = await store.storeV2Principals.getById({
			scope: context.scope,
			id: userId,
		});
		if (!principal) {
			throw policyError(
				"AUTHENTICATION_POLICY_USER_NOT_FOUND",
				"Authentication policy target not found.",
				stage,
				404,
			);
		}
		return;
	}
	assertResourceInScope(
		store.snapshot.principals.find(
			(principal) => principal.id === userId && principal.status !== "deleted",
		),
		context.scope,
		{
			code: "AUTHENTICATION_POLICY_USER_NOT_FOUND",
			stage,
			label: "User",
		},
	);
}

async function assertUserTargetInCoordinatedContext(
	context: InternalManagementCoordinatedMutationContext,
	operation: OperationContext,
	userId: string,
	stage: string,
): Promise<void> {
	if (context.principals?.authoritative) {
		const principal = await context.principals.getById({
			scope: operation.scope,
			id: userId,
		});
		if (!principal) {
			throw policyError(
				"AUTHENTICATION_POLICY_USER_NOT_FOUND",
				"Authentication policy target not found.",
				stage,
				404,
			);
		}
		return;
	}
	assertResourceInScope(
		context.data.principals.find(
			(principal) => principal.id === userId && principal.status !== "deleted",
		),
		operation.scope,
		{
			code: "AUTHENTICATION_POLICY_USER_NOT_FOUND",
			stage,
			label: "User",
		},
	);
}

function transaction(
	context: InternalManagementCoordinatedMutationContext,
): Parameters<AuthenticationPolicyFacade["apply"]>[0]["transaction"] {
	return {
		rawTransactionQuery: async <
			Row extends Record<string, unknown> = Record<string, unknown>,
		>(text: string, values?: readonly unknown[]) => {
			const result = await context.query(
				text,
				values === undefined ? undefined : [...values],
			);
			return {
				rows: result.rows as Row[],
				rowCount: result.rowCount,
			};
		},
	};
}

function policyPlanInput(
	input: AuthenticationPolicyPlanInput | AuthenticationPolicyApplyInput,
): AuthenticationPolicyPlanInput {
	if ("organizationId" in input && input.organizationId !== undefined) {
		return {
			organizationId: input.organizationId,
			policy: input.policy,
		};
	}
	return { policy: input.policy };
}

function policyApplyInput(
	input: AuthenticationPolicyApplyInput,
	transactionCapability: Parameters<
		AuthenticationPolicyFacade["apply"]
	>[0]["transaction"],
): Parameters<AuthenticationPolicyFacade["apply"]>[0] {
	const candidate = policyPlanInput(input);
	return "organizationId" in candidate
		? {
				...candidate,
				expectedRevision: input.expectedRevision,
				transaction: transactionCapability,
			}
		: {
				...candidate,
				expectedRevision: input.expectedRevision,
				transaction: transactionCapability,
			};
}

export async function getAuthenticationPolicyForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { organizationId?: string },
): Promise<AuthenticationPolicyGetResult> {
	const stage = "authentication_policy.get";
	try {
		await assertOrganizationTarget(store, context, input.organizationId, stage);
		const authority = await facade(store, context, stage);
		return await authority.get(input);
	} catch (error) {
		return translatePolicyError(error, stage);
	}
}

export async function planAuthenticationPolicyForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: AuthenticationPolicyPlanInput,
): Promise<AuthenticationPolicyPlanResult> {
	const stage = "authentication_policy.plan";
	try {
		await assertOrganizationTarget(store, context, input.organizationId, stage);
		const authority = await facade(store, context, stage);
		return await authority.plan(policyPlanInput(input));
	} catch (error) {
		return translatePolicyError(error, stage);
	}
}

export async function applyAuthenticationPolicyForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: AuthenticationPolicyApplyInput & { dryRun?: boolean; confirm?: boolean },
): Promise<AuthenticationPolicyApplyControlResult> {
	const stage = "authentication_policy.apply";
	try {
		await assertOrganizationTarget(store, context, input.organizationId, stage);
		const authority = await facade(store, context, stage);
		if (input.dryRun === true || input.confirm !== true) {
			return {
				dryRun: true,
				result: await authority.plan(policyPlanInput(input)),
			};
		}
		const result = await mutateCoordinatedWithRuntimeSql(
			store,
			async (coordinated) => {
				await assertOrganizationTargetInCoordinatedContext(
					coordinated,
					context,
					input.organizationId,
					stage,
				);
				const applied = await authority.apply(
					policyApplyInput(input, transaction(coordinated)),
				);
				appendAuditEvent(coordinated.data, {
					actor: context.actor,
					action: stage,
					subjectType: input.organizationId ? "organization" : "authentication_policy",
					subjectId:
						input.organizationId ??
						`${context.scope.projectId}:${context.scope.environmentId}`,
					outcome: "success",
					source: context.source,
					projectId: context.scope.projectId,
					environmentId: context.scope.environmentId,
					organizationId: input.organizationId,
					correlationId: context.correlationId,
					message: applied.changed
						? `Applied authentication policy revision ${applied.revision}`
						: `Authentication policy already matched revision ${applied.revision}`,
					metadata: {
						changed: applied.changed,
						previousRevision: applied.previousRevision,
						revision: applied.revision,
						target: applied.target.kind,
					},
				});
				return applied;
			},
		);
		return { dryRun: false, result };
	} catch (error) {
		return translatePolicyError(error, stage);
	}
}

export async function unlockAuthenticationForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: AuthenticationUnlockInput & { dryRun?: boolean; confirm?: boolean },
): Promise<AuthenticationUnlockControlResult> {
	const stage = "authentication_policy.unlock";
	try {
		await assertUserTarget(store, context, input.userId, stage);
		const authority = await facade(store, context, stage);
		if (input.dryRun === true || input.confirm !== true) {
			return {
				dryRun: true,
				result: await authority.planUnlock({
					userId: input.userId,
					kind: input.kind,
				}),
			};
		}
		const result = await mutateCoordinatedWithRuntimeSql(
			store,
			async (coordinated) => {
				await assertUserTargetInCoordinatedContext(
					coordinated,
					context,
					input.userId,
					stage,
				);
				const unlocked = await authority.unlock({
					userId: input.userId,
					kind: input.kind,
					transaction: transaction(coordinated),
				});
				appendAuditEvent(coordinated.data, {
					actor: context.actor,
					action: stage,
					subjectType: "user",
					subjectId: input.userId,
					outcome: "success",
					source: context.source,
					projectId: context.scope.projectId,
					environmentId: context.scope.environmentId,
					correlationId: context.correlationId,
					message: unlocked.changed
						? `Cleared ${input.kind} authentication lockout state`
						: `Authentication lockout state was already clear for ${input.kind}`,
					metadata: {
						changed: unlocked.changed,
						kind: unlocked.kind,
						passwordRows: unlocked.password.wouldChangeRows,
						factorRows: unlocked.factor.wouldChangeRows,
					},
				});
				return unlocked;
			},
		);
		return { dryRun: false, result };
	} catch (error) {
		return translatePolicyError(error, stage);
	}
}
