import {
	DeliveryControlConflictError,
	DeliveryQuotaExceededError,
	type DeliveryControlPreview,
	type PublicDeliveryJob,
} from "@clearance/delivery";
import { describe, expect, it } from "vitest";
import {
	controlDeliveryJob,
	getDeliveryQuotaForManagement,
	listDeliveryJobsForManagement,
} from "../services/delivery-control.js";
import type {
	ManagementDeliveryControlReader,
	ManagementStore,
} from "../store/types.js";

const job: PublicDeliveryJob = {
	id: "job-1",
	eventId: "event-1",
	kind: "organization.updated",
	projectId: "project-1",
	environmentId: "environment-1",
	organizationId: null,
	channel: "webhook",
	state: "queued",
	cancelRequested: false,
	attemptCount: 0,
	maxAttempts: 5,
	availableAt: "2026-07-15T00:00:00.000Z",
	semanticExpiresAt: "2026-07-16T00:00:00.000Z",
	lastErrorClass: null,
	createdAt: "2026-07-15T00:00:00.000Z",
	updatedAt: "2026-07-15T00:00:00.000Z",
	deliveredAt: null,
	deadAt: null,
	cancelledAt: null,
};

const preview: DeliveryControlPreview = {
	action: "cancel",
	allowed: true,
	reason: null,
	job,
	effect: {
		state: "cancelled",
		cancelRequested: false,
		maxAttempts: null,
		createsEvent: false,
		createsJob: false,
	},
};

function reader(overrides: Partial<ManagementDeliveryControlReader> = {}): ManagementDeliveryControlReader {
	return {
		list: async () => ({ items: [job], nextCursor: null }),
		inspect: async () => job,
		preview: async (input) => ({
			...preview,
			action: input.action,
			effect: {
				...preview.effect,
				maxAttempts: input.action === "replay"
					? input.maxAttempts ?? job.maxAttempts
					: preview.effect.maxAttempts,
			},
		}),
		readiness: async () => ({
			ready: true,
			schema: { owner: "clearance.delivery", installedVersion: 3, expectedVersion: 3, isUpToDate: true },
			jobs: { queued: 1, leased: 0, retry: 0, delivered: 0, dead: 0, cancelled: 0 },
			workers: { total: 1, ready: 1, freshReady: 1, stale: 0, staleAfterMs: 60_000, lastSeenAt: null },
			keys: { checked: true, available: true, missingReferences: 0 },
			webhookEndpoints: { total: 0, active: 0, disabled: 0, untestedActive: 0, testPendingActive: 0, testFailedActive: 0, testSucceededActive: 0, lastTestRequestedAt: null },
			reasons: [],
		}),
		quota: async (scope) => ({
			scope,
			active: { used: 1, limit: 10 },
			backlog: { used: 1, limit: 10 },
			enqueueRate: {
				used: 1,
				limit: 10,
				windowMs: 60_000,
				windowStartedAt: "2026-07-15T00:00:00.000Z",
				resetsAt: null,
			},
		}),
		...overrides,
	};
}

function store(input: {
	reader?: ManagementDeliveryControlReader;
	mutateCoordinated?: ManagementStore["mutateCoordinated"];
} = {}): ManagementStore {
	return {
		backend: "postgres",
		path: "/unused",
		deliveryControl: input.reader ?? reader(),
		...(input.mutateCoordinated ? { mutateCoordinated: input.mutateCoordinated } : {}),
	} as unknown as ManagementStore;
}

const controlInput = {
	projectId: "project-1",
	environmentId: "environment-1",
	jobId: "job-1",
	action: "cancel" as const,
	actor: "operator",
	source: "api" as const,
};

describe("management delivery control service", () => {
	it("previews by default and explicit dry-run wins over confirmation", async () => {
		let mutationCalls = 0;
		const managementStore = store({
			mutateCoordinated: async () => {
				mutationCalls += 1;
				throw new Error("mutation must not run during preview");
			},
		});
		expect(await controlDeliveryJob(managementStore, controlInput)).toMatchObject({
			dryRun: true,
			preview: { allowed: true },
		});
		expect(await controlDeliveryJob(managementStore, {
			...controlInput,
			confirm: true,
			dryRun: true,
		})).toMatchObject({ dryRun: true });
		expect(await controlDeliveryJob(managementStore, {
			...controlInput,
			action: "replay",
			maxAttempts: 12,
		})).toMatchObject({
			operation: "delivery.jobs.replay",
			dryRun: true,
			preview: { action: "replay", effect: { maxAttempts: 12 } },
		});
		expect(mutationCalls).toBe(0);
	});

	it("preserves stable delivery 409 and 429 mappings", async () => {
		const conflictStore = store({
			mutateCoordinated: async (fn) => fn({
				data: {} as never,
				query: async () => ({ rows: [], rowCount: 0 }),
				controlDelivery: {
					cancel: async () => {
						throw new DeliveryControlConflictError("Leased job cannot be retried", "leased");
					},
					retry: async () => null,
					replay: async () => null,
				},
			}),
		});
		await expect(controlDeliveryJob(conflictStore, {
			...controlInput,
			confirm: true,
		})).rejects.toMatchObject({
			code: "DELIVERY_CONTROL_CONFLICT",
			status: 409,
			stage: "delivery.jobs.cancel",
		});

		const quotaStore = store({
			reader: reader({
				quota: async () => {
					throw new DeliveryQuotaExceededError({ quota: "backlog", limit: 10 });
				},
			}),
		});
		await expect(getDeliveryQuotaForManagement(quotaStore, {
			projectId: "project-1",
			environmentId: "environment-1",
		})).rejects.toMatchObject({
			code: "DELIVERY_QUOTA_EXCEEDED",
			status: 429,
			retryable: true,
			stage: "delivery.quotas.get",
		});
	});

	it("sanitizes unknown adapter failures", async () => {
		const secret = "postgres://operator:plaintext-password@database.internal/clearance";
		const managementStore = store({
			reader: reader({ list: async () => { throw new Error(secret); } }),
		});
		let failure: unknown;
		try {
			await listDeliveryJobsForManagement(managementStore, {
				projectId: "project-1",
				environmentId: "environment-1",
			});
		} catch (error) {
			failure = error;
		}
		expect(failure).toMatchObject({
			code: "DELIVERY_OPERATION_FAILED",
			status: 500,
			message: "Delivery operation failed.",
		});
		expect(String(failure)).not.toContain(secret);

		const historicalKeyId = "customer-key-2025-secret-label";
		const unavailableKeyStore = store({
			reader: reader({
				list: async () => {
					throw Object.assign(
						new Error(`Delivery fingerprint key ${historicalKeyId} is unavailable`),
						{ code: "DELIVERY_FINGERPRINT_KEY_UNAVAILABLE" },
					);
				},
			}),
		});
		let keyFailure: unknown;
		try {
			await listDeliveryJobsForManagement(unavailableKeyStore, {
				projectId: "project-1",
				environmentId: "environment-1",
			});
		} catch (error) {
			keyFailure = error;
		}
		expect(keyFailure).toMatchObject({
			code: "DELIVERY_FINGERPRINT_KEY_UNAVAILABLE",
			status: 503,
			retryable: true,
			message: "Delivery service configuration is unavailable.",
		});
		expect(String(keyFailure)).not.toContain(historicalKeyId);
	});
});
