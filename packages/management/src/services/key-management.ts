/**
 * Scoped key-management lifecycle controls.
 *
 * These calls deliberately use the product facade directly. In particular,
 * status and planning must never bootstrap or run a general runtime migration:
 * the operator needs to be able to inspect an incomplete key migration safely.
 */
import type { ClearanceAuthBundle } from "@clearance/auth";
import type { OperationContext } from "../application/context.js";
import { getAuthBundle } from "../auth-bridge.js";
import { mutateCoordinatedWithRuntimeSql } from "../store/coordinated-internal.js";
import type {
	InternalManagementCoordinatedMutationContext,
	ManagementStore,
} from "../store/types.js";
import { appendAuditEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";

type KeyManagementFacade = ClearanceAuthBundle["keyManagement"];

export type KeyManagementStatusResult = Awaited<
	ReturnType<KeyManagementFacade["status"]>
>;
export type KeyManagementPlanResult = Awaited<
	ReturnType<KeyManagementFacade["planMigration"]>
>;
export type KeyManagementApplyInput = Omit<
	Parameters<KeyManagementFacade["applyMigration"]>[0],
	"transaction"
>;
export type KeyManagementApplyResult = Awaited<
	ReturnType<KeyManagementFacade["applyMigration"]>
>;

export type KeyManagementApplyControlResult =
	| Readonly<{ dryRun: true; result: KeyManagementPlanResult }>
	| Readonly<{ dryRun: false; result: KeyManagementApplyResult }>;

function keyManagementError(
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

function translateKeyManagementError(error: unknown, stage: string): never {
	const code = errorCode(error);
	if (
		error instanceof ClearanceError &&
		(code === "KEY_MANAGEMENT_POSTGRES_REQUIRED" ||
			code === "KEY_MANAGEMENT_SCOPE_MISMATCH" ||
			code === "KEY_MANAGEMENT_INPUT_INVALID")
	) {
		throw error;
	}
	if (code === "KEY_MANAGEMENT_INPUT_INVALID" || code === "KEY_INPUT_INVALID") {
		throw keyManagementError(
			"KEY_MANAGEMENT_INPUT_INVALID",
			"Key management migration input is invalid.",
			stage,
			400,
			"Provide the current plan id and retry.",
		);
	}
	if (code === "KEY_MANAGEMENT_PLAN_STALE") {
		throw keyManagementError(
			code,
			"Key management migration plan is stale.",
			stage,
			409,
			"Run key-management plan again and retry with its planId.",
		);
	}
	if (
		code === "KEY_MANAGEMENT_PROVIDER_NOT_READY" ||
		code === "KEY_PROVIDER_NOT_READY"
	) {
		throw keyManagementError(
			"KEY_MANAGEMENT_PROVIDER_NOT_READY",
			"Key management provider is not ready.",
			stage,
			503,
			"Restore key provider readiness and retry.",
		);
	}
	if (code === "KEY_MANAGEMENT_TRANSACTION_REQUIRED") {
		throw keyManagementError(
			code,
			"Key management migration requires a coordinated PostgreSQL transaction.",
			stage,
			503,
			"Use the PostgreSQL management backend and retry.",
		);
	}
	if (code?.startsWith("KEY_MANAGEMENT_SCHEMA_") || code === "42P01") {
		throw keyManagementError(
			"KEY_MANAGEMENT_SCHEMA_UNAVAILABLE",
			"Key management schema is unavailable.",
			stage,
			503,
			"Apply the required runtime schema migration and retry.",
		);
	}
	throw keyManagementError(
		"KEY_MANAGEMENT_OPERATION_FAILED",
		"Key management operation failed.",
		stage,
		500,
		"Inspect PostgreSQL and key-management service health before retrying.",
	);
}

function requireCoordinatedPostgres(store: ManagementStore, stage: string): void {
	if (store.backend !== "postgres" || typeof store.mutateCoordinated !== "function") {
		throw keyManagementError(
			"KEY_MANAGEMENT_POSTGRES_REQUIRED",
			"Key management requires the coordinated PostgreSQL management backend.",
			stage,
			503,
			"Configure DATABASE_URL and the coordinated PostgreSQL management store.",
		);
	}
}

function facade(
	store: ManagementStore,
	context: OperationContext,
	stage: string,
): KeyManagementFacade {
	requireCoordinatedPostgres(store, stage);
	const authority = getAuthBundle().keyManagement;
	if (
		authority.scope.projectId !== context.scope.projectId ||
		authority.scope.environmentId !== context.scope.environmentId
	) {
		throw keyManagementError(
			"KEY_MANAGEMENT_SCOPE_MISMATCH",
			"Key management scope does not match the authenticated principal.",
			stage,
			403,
			"Use an API credential bound to the configured key management project and environment.",
		);
	}
	return authority;
}

function transaction(
	context: InternalManagementCoordinatedMutationContext,
): Parameters<KeyManagementFacade["applyMigration"]>[0]["transaction"] {
	return {
		rawTransactionQuery: async <
			Row extends Record<string, unknown> = Record<string, unknown>,
		>(text: string, values?: readonly unknown[]) => {
			const result = await context.query(
				text,
				values === undefined ? undefined : [...values],
			);
			return { rows: result.rows as Row[], rowCount: result.rowCount };
		},
	};
}

function assertApplyInput(input: KeyManagementApplyInput, stage: string): void {
	if (
		typeof input !== "object" ||
		input === null ||
		typeof input.expectedPlanId !== "string" ||
		!/^[a-f0-9]{64}$/.test(input.expectedPlanId)
	) {
		throw keyManagementError(
			"KEY_MANAGEMENT_INPUT_INVALID",
			"Key management migration input is invalid.",
			stage,
			400,
			"Provide the current plan id and retry.",
		);
	}
}

export async function getKeyManagementStatusForManagement(
	store: ManagementStore,
	context: OperationContext,
): Promise<KeyManagementStatusResult> {
	const stage = "key_management.status";
	try {
		return await facade(store, context, stage).status();
	} catch (error) {
		return translateKeyManagementError(error, stage);
	}
}

export async function planKeyManagementForManagement(
	store: ManagementStore,
	context: OperationContext,
): Promise<KeyManagementPlanResult> {
	const stage = "key_management.plan";
	try {
		return await facade(store, context, stage).planMigration();
	} catch (error) {
		return translateKeyManagementError(error, stage);
	}
}

export async function applyKeyManagementForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: KeyManagementApplyInput & { dryRun?: boolean; confirm?: boolean },
): Promise<KeyManagementApplyControlResult> {
	const stage = "key_management.apply";
	try {
		assertApplyInput(input, stage);
		const authority = facade(store, context, stage);
		if (input.dryRun !== false || input.confirm !== true) {
			return { dryRun: true, result: await authority.planMigration() };
		}
		const result = await mutateCoordinatedWithRuntimeSql(
			store,
			async (coordinated) => {
				const applied = await authority.applyMigration({
					expectedPlanId: input.expectedPlanId,
					transaction: transaction(coordinated),
				});
				appendAuditEvent(coordinated.data, {
					actor: context.actor,
					action: stage,
					subjectType: "key_management",
					subjectId: `${context.scope.projectId}:${context.scope.environmentId}`,
					outcome: "success",
					source: context.source,
					projectId: context.scope.projectId,
					environmentId: context.scope.environmentId,
					correlationId: context.correlationId,
					message: applied.changed > 0
						? "Applied key management migration batch"
						: "Key management migration already matched the current plan",
					metadata: {
						changed: applied.changed,
						applied: applied.applied,
						previousPlanId: applied.previousPlanId,
						nextPlanId: applied.nextPlanId,
						complete: applied.complete,
					},
				});
				return applied;
			},
		);
		return { dryRun: false, result };
	} catch (error) {
		return translateKeyManagementError(error, stage);
	}
}
