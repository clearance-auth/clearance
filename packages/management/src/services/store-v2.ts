import type {
	ManagementStore,
	StoreV2MigrationControl,
	StoreV2Plan,
	StoreV2Status,
} from "../store/types.js";
import { ClearanceError } from "./errors.js";

const SCHEMA_VERSION = "v1" as const;

export interface StoreV2CommandEnvelope {
	schemaVersion: typeof SCHEMA_VERSION;
	operation:
		| "schema.store-v2.status"
		| "schema.store-v2.plan"
		| "schema.store-v2.apply"
		| "schema.store-v2.verify"
		| "schema.store-v2.rollback"
		| "schema.store-v2.events.cutover"
		| "schema.store-v2.events.rollback"
		| "schema.store-v2.principals.cutover"
		| "schema.store-v2.principals.rollback";
	storeBackend: "postgres";
	dryRun: boolean;
	status?: StoreV2Status;
	plan?: StoreV2Plan;
}

function requireStoreV2(
	store: ManagementStore,
	stage: StoreV2CommandEnvelope["operation"],
): StoreV2MigrationControl {
	if (store.backend !== "postgres" || !store.storeV2) {
		throw new ClearanceError({
			code: "STORE_V2_POSTGRES_REQUIRED",
			message: "Store-v2 requires the Postgres management backend.",
			stage,
			status: 400,
			remediation:
				"Configure DATABASE_URL on the Clearance API, then retry the store-v2 workflow.",
		});
	}
	return store.storeV2;
}

function envelope(
	operation: StoreV2CommandEnvelope["operation"],
	input: Pick<StoreV2CommandEnvelope, "dryRun" | "status" | "plan">,
): StoreV2CommandEnvelope {
	return {
		schemaVersion: SCHEMA_VERSION,
		operation,
		storeBackend: "postgres",
		...input,
	};
}

function requireConfirmation(
	confirm: boolean | undefined,
	stage:
		| "schema.store-v2.apply"
		| "schema.store-v2.rollback"
		| "schema.store-v2.events.cutover"
		| "schema.store-v2.events.rollback"
		| "schema.store-v2.principals.cutover"
		| "schema.store-v2.principals.rollback",
): void {
	if (confirm === true) return;
	const applying = stage === "schema.store-v2.apply";
	const cuttingOverEvents = stage === "schema.store-v2.events.cutover";
	const rollingBackEvents = stage === "schema.store-v2.events.rollback";
	const cuttingOverPrincipals = stage === "schema.store-v2.principals.cutover";
	const rollingBackPrincipals = stage === "schema.store-v2.principals.rollback";
	throw new ClearanceError({
		code: applying
			? "STORE_V2_APPLY_CONFIRMATION_REQUIRED"
			: cuttingOverEvents
				? "STORE_V2_EVENTS_CUTOVER_CONFIRMATION_REQUIRED"
				: rollingBackEvents
					? "STORE_V2_EVENTS_ROLLBACK_CONFIRMATION_REQUIRED"
					: cuttingOverPrincipals
						? "STORE_V2_PRINCIPALS_CUTOVER_CONFIRMATION_REQUIRED"
						: rollingBackPrincipals
							? "STORE_V2_PRINCIPALS_ROLLBACK_CONFIRMATION_REQUIRED"
					: "STORE_V2_ROLLBACK_CONFIRMATION_REQUIRED",
		message: applying
			? "Store-v2 apply requires explicit confirmation."
			: cuttingOverEvents
				? "Store-v2 event cutover requires explicit confirmation."
				: rollingBackEvents
					? "Store-v2 event rollback requires explicit confirmation."
					: cuttingOverPrincipals
						? "Store-v2 principal cutover requires explicit confirmation."
						: rollingBackPrincipals
							? "Store-v2 principal rollback requires explicit confirmation."
					: "Store-v2 rollback requires explicit confirmation.",
		stage,
		status: 400,
		remediation: applying
			? "Review schema store-v2 apply --dry-run, then retry with --yes."
			: cuttingOverEvents
				? "Run schema store-v2 verify, then retry schema store-v2 events cutover with --yes."
				: rollingBackEvents
					? "Review schema store-v2 status, then retry schema store-v2 events rollback with --yes."
					: cuttingOverPrincipals
						? "Run schema store-v2 verify, then retry schema store-v2 principals cutover with --yes."
						: rollingBackPrincipals
							? "Review schema store-v2 status, then retry schema store-v2 principals rollback with --yes."
					: "Review schema store-v2 status, then retry rollback with --yes.",
	});
}

function translateStoreError(
	error: unknown,
	stage: StoreV2CommandEnvelope["operation"],
): never {
	if (error instanceof ClearanceError) throw error;
	const rawCode =
		typeof error === "object" &&
		error !== null &&
		"code" in error &&
		typeof error.code === "string"
			? error.code
			: undefined;
	const code = rawCode?.startsWith("STORE_V2_")
		? rawCode
		: "STORE_V2_OPERATION_FAILED";
	throw new ClearanceError({
		code,
		message:
			code === "STORE_V2_PREFLIGHT_FAILED"
				? "Store-v2 preflight found incompatible snapshot data."
				: "Store-v2 operation failed.",
		stage,
		status: code === "STORE_V2_OPERATION_FAILED" ? 500 : 409,
		remediation:
			code === "STORE_V2_PREFLIGHT_FAILED"
				? "Run schema store-v2 plan, resolve every reported blocker, then retry."
				: "Run schema store-v2 status and doctor, correct the reported storage issue, then retry.",
	});
}

export async function getStoreV2Status(
	store: ManagementStore,
): Promise<StoreV2CommandEnvelope> {
	const operation = "schema.store-v2.status" as const;
	try {
		const status = await requireStoreV2(store, operation).status();
		return envelope(operation, { dryRun: false, status });
	} catch (error) {
		return translateStoreError(error, operation);
	}
}

export async function planStoreV2(
	store: ManagementStore,
): Promise<StoreV2CommandEnvelope> {
	const operation = "schema.store-v2.plan" as const;
	try {
		const plan = await requireStoreV2(store, operation).plan();
		return envelope(operation, { dryRun: true, plan });
	} catch (error) {
		return translateStoreError(error, operation);
	}
}

export async function applyStoreV2(
	store: ManagementStore,
	opts: { dryRun?: boolean; confirm?: boolean },
): Promise<StoreV2CommandEnvelope> {
	const operation = "schema.store-v2.apply" as const;
	try {
		const control = requireStoreV2(store, operation);
		if (opts.dryRun === true) {
			return envelope(operation, {
				dryRun: true,
				plan: await control.plan(),
			});
		}
		requireConfirmation(opts.confirm, operation);
		return envelope(operation, {
			dryRun: false,
			status: await control.apply(),
		});
	} catch (error) {
		return translateStoreError(error, operation);
	}
}

export async function verifyStoreV2(
	store: ManagementStore,
): Promise<StoreV2CommandEnvelope> {
	const operation = "schema.store-v2.verify" as const;
	try {
		const status = await requireStoreV2(store, operation).verify();
		if (status.phase === "absent") {
			throw new ClearanceError({
				code: "STORE_V2_NOT_APPLIED",
				message: "Store-v2 has not been applied.",
				stage: operation,
				status: 409,
				remediation:
					"Run schema store-v2 plan, then schema store-v2 apply --yes.",
			});
		}
		if (!status.consistent) {
			throw new ClearanceError({
				code: "STORE_V2_DIVERGENCE",
				message:
					"Store-v2 relational data diverged from the authoritative snapshot.",
				stage: operation,
				status: 409,
				remediation:
					"Stop mutations, inspect schema store-v2 status, and reconcile before continuing.",
			});
		}
		return envelope(operation, { dryRun: false, status });
	} catch (error) {
		return translateStoreError(error, operation);
	}
}

export async function rollbackStoreV2(
	store: ManagementStore,
	opts: { confirm?: boolean },
): Promise<StoreV2CommandEnvelope> {
	const operation = "schema.store-v2.rollback" as const;
	try {
		const control = requireStoreV2(store, operation);
		requireConfirmation(opts.confirm, operation);
		return envelope(operation, {
			dryRun: false,
			status: await control.disable(),
		});
	} catch (error) {
		return translateStoreError(error, operation);
	}
}

export async function cutoverStoreV2Events(
	store: ManagementStore,
	opts: { confirm?: boolean },
): Promise<StoreV2CommandEnvelope> {
	const operation = "schema.store-v2.events.cutover" as const;
	try {
		const control = requireStoreV2(store, operation);
		requireConfirmation(opts.confirm, operation);
		return envelope(operation, {
			dryRun: false,
			status: await control.cutoverEvents(),
		});
	} catch (error) {
		return translateStoreError(error, operation);
	}
}

export async function rollbackStoreV2Events(
	store: ManagementStore,
	opts: { confirm?: boolean },
): Promise<StoreV2CommandEnvelope> {
	const operation = "schema.store-v2.events.rollback" as const;
	try {
		const control = requireStoreV2(store, operation);
		requireConfirmation(opts.confirm, operation);
		return envelope(operation, {
			dryRun: false,
			status: await control.rollbackEvents(),
		});
	} catch (error) {
		return translateStoreError(error, operation);
	}
}

export async function cutoverStoreV2Principals(
	store: ManagementStore,
	opts: { confirm?: boolean },
): Promise<StoreV2CommandEnvelope> {
	const operation = "schema.store-v2.principals.cutover" as const;
	try {
		const control = requireStoreV2(store, operation);
		requireConfirmation(opts.confirm, operation);
		return envelope(operation, {
			dryRun: false,
			status: await control.cutoverPrincipals(),
		});
	} catch (error) {
		return translateStoreError(error, operation);
	}
}

export async function rollbackStoreV2Principals(
	store: ManagementStore,
	opts: { confirm?: boolean },
): Promise<StoreV2CommandEnvelope> {
	const operation = "schema.store-v2.principals.rollback" as const;
	try {
		const control = requireStoreV2(store, operation);
		requireConfirmation(opts.confirm, operation);
		return envelope(operation, {
			dryRun: false,
			status: await control.rollbackPrincipals(),
		});
	} catch (error) {
		return translateStoreError(error, operation);
	}
}
