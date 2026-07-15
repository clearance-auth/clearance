import type {
	DeliveryControlAction,
	DeliveryControlPreview,
	DeliveryJobPage,
	DeliveryJobState,
	DeliveryQuotaStatus,
	DeliveryReadinessSummary,
	EnqueuedDelivery,
	PublicDeliveryJob,
} from "@clearance/delivery";
import type {
	DeliveryControlAuditContext,
	DeliveryControlScope,
	ManagementDeliveryControlReader,
	ManagementStore,
} from "../store/types.js";
import { ClearanceError } from "./errors.js";

const SCHEMA_VERSION = "v1" as const;

export type ScopedDeliveryJobPage = DeliveryJobPage & {
	schemaVersion: typeof SCHEMA_VERSION;
	scope: DeliveryControlScope;
};

export type ScopedDeliveryJob = {
	schemaVersion: typeof SCHEMA_VERSION;
	scope: DeliveryControlScope;
	job: PublicDeliveryJob;
};

export type DeliveryControlResult = {
	schemaVersion: typeof SCHEMA_VERSION;
	operation: `delivery.jobs.${DeliveryControlAction}`;
	storeBackend: "postgres";
	scope: DeliveryControlScope;
	jobId: string;
	dryRun: boolean;
	preview: DeliveryControlPreview;
	result?: PublicDeliveryJob | EnqueuedDelivery;
};

function requireDeliveryReader(
	store: ManagementStore,
	stage: string,
): ManagementDeliveryControlReader {
	if (store.backend !== "postgres") {
		throw new ClearanceError({
			code: "DELIVERY_POSTGRES_REQUIRED",
			message: "Delivery control requires the PostgreSQL management backend.",
			stage,
			status: 400,
			remediation: "Configure DATABASE_URL, then retry the delivery workflow.",
		});
	}
	if (!store.deliveryControl) {
		throw new ClearanceError({
			code: "DELIVERY_NOT_CONFIGURED",
			message: "Delivery storage and keys are not configured.",
			stage,
			status: 503,
			remediation: "Configure the delivery schema and keyring, then retry.",
		});
	}
	return store.deliveryControl;
}

function notFound(stage: string): ClearanceError {
	return new ClearanceError({
		code: "DELIVERY_JOB_NOT_FOUND",
		message: "Delivery job not found.",
		stage,
		status: 404,
		remediation: "Verify the job id and active project/environment scope.",
	});
}

function translateDeliveryError(error: unknown, stage: string): never {
	if (error instanceof ClearanceError) throw error;
	const candidate = error as {
		code?: unknown;
		message?: unknown;
		httpStatus?: unknown;
	};
	const code = typeof candidate?.code === "string" &&
		candidate.code.startsWith("DELIVERY_")
		? candidate.code
		: "DELIVERY_OPERATION_FAILED";
	const status = typeof candidate?.httpStatus === "number" &&
		Number.isInteger(candidate.httpStatus) &&
		candidate.httpStatus >= 400 &&
		candidate.httpStatus <= 599
		? candidate.httpStatus
		: code === "DELIVERY_OPERATION_FAILED" ? 500 : 400;
	throw new ClearanceError({
		code,
		message: code !== "DELIVERY_OPERATION_FAILED" &&
			typeof candidate?.message === "string"
			? candidate.message
			: "Delivery operation failed.",
		stage,
		status,
		retryable: status === 429 || status >= 500,
		remediation: status === 429
			? "Wait for delivery capacity, then retry."
			: "Inspect delivery readiness and job state, then retry.",
	});
}

export async function listDeliveryJobsForManagement(
	store: ManagementStore,
	input: DeliveryControlScope & {
		limit?: number;
		cursor?: string;
		states?: readonly DeliveryJobState[];
		channel?: "email" | "webhook";
		kind?: string;
	},
): Promise<ScopedDeliveryJobPage> {
	const stage = "delivery.jobs.list";
	try {
		const page = await requireDeliveryReader(store, stage).list(input);
		return {
			schemaVersion: SCHEMA_VERSION,
			scope: { projectId: input.projectId, environmentId: input.environmentId },
			...page,
		};
	} catch (error) {
		return translateDeliveryError(error, stage);
	}
}

export async function inspectDeliveryJobForManagement(
	store: ManagementStore,
	input: DeliveryControlScope & { jobId: string },
): Promise<ScopedDeliveryJob> {
	const stage = "delivery.jobs.inspect";
	try {
		const job = await requireDeliveryReader(store, stage).inspect(input);
		if (!job) throw notFound(stage);
		return {
			schemaVersion: SCHEMA_VERSION,
			scope: { projectId: input.projectId, environmentId: input.environmentId },
			job,
		};
	} catch (error) {
		return translateDeliveryError(error, stage);
	}
}

export async function getDeliveryReadinessForManagement(
	store: ManagementStore,
	input: { now?: Date; staleAfterMs?: number } = {},
): Promise<DeliveryReadinessSummary> {
	const stage = "delivery.readiness";
	try {
		return await requireDeliveryReader(store, stage).readiness(input);
	} catch (error) {
		return translateDeliveryError(error, stage);
	}
}

export async function getDeliveryQuotaForManagement(
	store: ManagementStore,
	input: DeliveryControlScope & { now?: Date },
): Promise<DeliveryQuotaStatus> {
	const stage = "delivery.quotas.get";
	try {
		return await requireDeliveryReader(store, stage).quota(input);
	} catch (error) {
		return translateDeliveryError(error, stage);
	}
}

export async function controlDeliveryJob(
	store: ManagementStore,
	input: DeliveryControlScope & DeliveryControlAuditContext & {
		jobId: string;
		action: DeliveryControlAction;
		now?: Date;
		maxAttempts?: number;
		dryRun?: boolean;
		confirm?: boolean;
	},
): Promise<DeliveryControlResult> {
	const operation = `delivery.jobs.${input.action}` as const;
	try {
		const reader = requireDeliveryReader(store, operation);
		const preview = await reader.preview(input);
		if (!preview) throw notFound(operation);
		const scope = {
			projectId: input.projectId,
			environmentId: input.environmentId,
		};
		const dryRun = input.dryRun === true || input.confirm !== true;
		if (dryRun) {
			return {
				schemaVersion: SCHEMA_VERSION,
				operation,
				storeBackend: "postgres",
				scope,
				jobId: input.jobId,
				dryRun: true,
				preview,
			};
		}
		if (!store.mutateCoordinated) {
			throw new ClearanceError({
				code: "DELIVERY_POSTGRES_REQUIRED",
				message: "Delivery control requires transactional PostgreSQL storage.",
				stage: operation,
				status: 500,
			});
		}
		const result = await store.mutateCoordinated(async (context) => {
			const control = context.controlDelivery;
			if (!control) {
				throw new ClearanceError({
					code: "DELIVERY_NOT_CONFIGURED",
					message: "Delivery storage and keys are not configured.",
					stage: operation,
					status: 503,
				});
			}
			const mutationInput = {
				...scope,
				jobId: input.jobId,
				actor: input.actor,
				source: input.source,
				...(input.correlationId ? { correlationId: input.correlationId } : {}),
				...(input.now ? { now: input.now } : {}),
			};
			if (input.action === "cancel") return control.cancel(mutationInput);
			if (input.action === "retry") return control.retry(mutationInput);
			return control.replay({
				...mutationInput,
				...(input.maxAttempts === undefined ? {} : { maxAttempts: input.maxAttempts }),
			});
		});
		if (!result) throw notFound(operation);
		return {
			schemaVersion: SCHEMA_VERSION,
			operation,
			storeBackend: "postgres",
			scope,
			jobId: input.jobId,
			dryRun: false,
			preview,
			result,
		};
	} catch (error) {
		return translateDeliveryError(error, operation);
	}
}
