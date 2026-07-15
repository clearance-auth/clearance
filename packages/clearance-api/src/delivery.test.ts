import {
	ClearanceError,
	isClearanceError,
	type ApiKeyView,
	type ManagementStore,
	type ResourceScope,
} from "@clearance/management";
import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import {
	apiKeyRouteIsOperatorOnly,
	requiredApiKeyScope,
	setRequestPrincipal,
} from "./request-auth.js";
import { registerDeliveryRoutes } from "./routes/delivery.js";

const scope: ResourceScope = {
	projectId: "project_delivery",
	environmentId: "environment_delivery",
};
const timestamp = "2026-07-15T00:00:00.000Z";
const job = {
	id: "job_delivery",
	eventId: "event_delivery",
	kind: "organization.updated",
	...scope,
	organizationId: "organization_delivery",
	channel: "webhook" as const,
	state: "queued" as const,
	attemptCount: 0,
	maxAttempts: 5,
	availableAt: timestamp,
	semanticExpiresAt: "2026-07-16T00:00:00.000Z",
	lastErrorClass: null,
	createdAt: timestamp,
	updatedAt: timestamp,
	deliveredAt: null,
	deadAt: null,
	cancelledAt: null,
	destination: "[redacted]" as const,
};

function fakeStore(input: {
	configured?: boolean;
	inspectResult?: typeof job | null;
	previewResult?: null;
	previewError?: unknown;
} = {}) {
	const list = vi.fn(async () => ({ items: [job], nextCursor: "cursor_next" }));
	const inspect = vi.fn(async () => input.inspectResult === undefined ? job : input.inspectResult);
	const preview = vi.fn(async (controlInput: { action: "cancel" | "retry" | "replay" }) => {
		if (input.previewError !== undefined) throw input.previewError;
		if (input.previewResult === null) return null;
		return {
			action: controlInput.action,
			allowed: true,
			reason: null,
			job,
			effect: {
				state: controlInput.action === "replay" ? "queued" as const : "cancelled" as const,
				maxAttempts: 5,
				createsEvent: controlInput.action === "replay",
				createsJob: controlInput.action === "replay",
			},
		};
	});
	const readiness = vi.fn(async () => ({
		ready: true,
		schema: { owner: "clearance.delivery", version: 3, currentVersion: 3, current: true },
		jobs: { queued: 1, leased: 0, retry: 0, delivered: 0, dead: 0, cancelled: 0 },
		workers: {
			total: 1,
			ready: 1,
			freshReady: 1,
			stale: 0,
			staleAfterMs: 60_000,
			lastSeenAt: timestamp,
		},
		keys: { checked: true, available: true, missingReferences: 0 },
		reasons: [],
	}));
	const quota = vi.fn(async () => ({
		scope,
		active: { used: 1, limit: 10_000 },
		backlog: { used: 1, limit: 5_000 },
		enqueueRate: {
			used: 1,
			limit: 1_000,
			windowMs: 60_000,
			windowStartedAt: timestamp,
			resetsAt: null,
		},
	}));
	const cancel = vi.fn(async () => ({
		...job,
		state: "cancelled" as const,
		cancelledAt: timestamp,
	}));
	const retry = vi.fn(async () => ({ ...job, state: "retry" as const }));
	const replay = vi.fn(async () => ({
		eventId: "event_replay",
		jobId: "job_replay",
		kind: job.kind,
		channel: job.channel,
		state: "queued" as const,
		createdAt: timestamp,
		semanticExpiresAt: job.semanticExpiresAt,
	}));
	const ready = vi.fn(async () => undefined);
	const store = {
		backend: "postgres",
		path: "/test/delivery",
		snapshot: {},
		...(input.configured === false ? {} : {
			deliveryControl: { list, inspect, preview, readiness, quota },
		}),
		ready,
		mutateCoordinated: vi.fn(async (callback) => callback({
			data: {},
			query: vi.fn(),
			controlDelivery: { cancel, retry, replay },
		})),
	} as unknown as ManagementStore;
	return {
		store,
		calls: { list, inspect, preview, readiness, quota, cancel, retry, replay, ready },
	};
}

function routeApp(
	store: ManagementStore,
	options: {
		resolveScope?: () => ResourceScope;
		apiKeyId?: string;
	} = {},
): Hono {
	const app = new Hono();
	app.use("*", async (context, next) => {
		context.header("x-request-id", "request_delivery_123");
		if (options.apiKeyId) {
			setRequestPrincipal(context, {
				kind: "api_key",
				id: options.apiKeyId,
				scope,
				scopes: ["delivery:write"],
				apiKey: {
					id: options.apiKeyId,
					...scope,
					name: "Delivery test key",
					scopes: ["delivery:write"],
					prefix: "clr_delivery",
					fingerprint: "delivery-test-key",
					status: "active",
					createdAt: timestamp,
					updatedAt: timestamp,
				} satisfies ApiKeyView,
			});
		}
		await next();
	});
	app.route("/", registerDeliveryRoutes({
		storeForRequest: async () => store,
		scopeForRequest: options.resolveScope ?? (() => scope),
		handleError: (context, error) => {
			if (isClearanceError(error)) return context.json(error.toJSON(), error.status);
			return context.json(new ClearanceError({
				code: "INTERNAL",
				message: "Unexpected test error",
				stage: "api",
				status: 500,
			}).toJSON(), 500);
		},
	}));
	return app;
}

describe("delivery API routes", () => {
	it("lists and filters jobs only in the authenticated scope", async () => {
		const { store, calls } = fakeStore();
		const response = await routeApp(store).request(
			"/v1/delivery/jobs?limit=25&cursor=cursor_current&state=queued&state=retry&channel=webhook&kind=organization.updated",
		);

		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			schemaVersion: "v1",
			scope,
			items: [{ id: job.id, destination: "[redacted]" }],
			nextCursor: "cursor_next",
		});
		expect(calls.list).toHaveBeenCalledWith({
			...scope,
			limit: 25,
			cursor: "cursor_current",
			states: ["queued", "retry"],
			channel: "webhook",
			kind: "organization.updated",
		});
	});

	it("returns 404 for reads and mutations outside the authenticated scope", async () => {
		const { store, calls } = fakeStore({ inspectResult: null, previewResult: null });
		const app = routeApp(store);
		const response = await app.request("/v1/delivery/jobs/job_foreign");

		expect(response.status).toBe(404);
		expect((await response.json()).error.code).toBe("DELIVERY_JOB_NOT_FOUND");
		expect(calls.inspect).toHaveBeenCalledWith({ ...scope, jobId: "job_foreign" });

		const mutation = await app.request("/v1/delivery/jobs/job_foreign/cancel", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ confirm: true }),
		});
		expect(mutation.status).toBe(404);
		expect((await mutation.json()).error.code).toBe("DELIVERY_JOB_NOT_FOUND");
		expect(calls.cancel).not.toHaveBeenCalled();
	});

	it("previews by default and executes only with confirm true", async () => {
		const { store, calls } = fakeStore();
		const app = routeApp(store, { apiKeyId: "key_delivery" });

		const preview = await app.request(`/v1/delivery/jobs/${job.id}/cancel`, {
			method: "POST",
		});
		expect(preview.status).toBe(200);
		expect(await preview.json()).toMatchObject({
			operation: "delivery.jobs.cancel",
			dryRun: true,
			jobId: job.id,
		});
		expect(calls.cancel).not.toHaveBeenCalled();
		expect(calls.ready).not.toHaveBeenCalled();

		const confirmed = await app.request(`/v1/delivery/jobs/${job.id}/cancel`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ confirm: true }),
		});
		expect(confirmed.status).toBe(200);
		expect(await confirmed.json()).toMatchObject({
			operation: "delivery.jobs.cancel",
			dryRun: false,
			result: { id: job.id, state: "cancelled" },
		});
		expect(calls.cancel).toHaveBeenCalledWith(expect.objectContaining({
			...scope,
			jobId: job.id,
			actor: "api-key:key_delivery",
			source: "api",
			correlationId: "request_delivery_123",
		}));
		expect(calls.ready).toHaveBeenCalledOnce();
	});

	it("fails closed when delivery storage and keys are unconfigured", async () => {
		const { store } = fakeStore({ configured: false });
		const response = await routeApp(store).request("/v1/delivery/jobs");

		expect(response.status).toBe(503);
		expect((await response.json()).error.code).toBe("DELIVERY_NOT_CONFIGURED");
	});

	it("maps delivery conflicts and rejects malformed mutation input", async () => {
		const conflict = fakeStore({
			previewError: {
				code: "DELIVERY_CONTROL_CONFLICT",
				message: "The delivery job changed state.",
				httpStatus: 409,
			},
		});
		const conflictResponse = await routeApp(conflict.store).request(
			`/v1/delivery/jobs/${job.id}/retry`,
			{ method: "POST" },
		);
		expect(conflictResponse.status).toBe(409);
		expect((await conflictResponse.json()).error.code).toBe("DELIVERY_CONTROL_CONFLICT");

		const invalidResponse = await routeApp(fakeStore().store).request(
			`/v1/delivery/jobs/${job.id}/replay`,
			{
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ confirm: true, maxAttempts: "5" }),
			},
		);
		expect(invalidResponse.status).toBe(400);
		expect((await invalidResponse.json()).error.code).toBe("API_NUMBER_INVALID");

		const malformed = fakeStore();
		const malformedResponse = await routeApp(malformed.store).request(
			`/v1/delivery/jobs/${job.id}/cancel`,
			{
				method: "POST",
				headers: { "content-type": "application/json" },
				body: "{",
			},
		);
		expect(malformedResponse.status).toBe(400);
		expect((await malformedResponse.json()).error.code).toBe("API_JSON_INVALID");
		expect(malformed.calls.preview).not.toHaveBeenCalled();
		expect(malformed.calls.cancel).not.toHaveBeenCalled();
	});

	it("exposes scoped quota and operator-only global readiness authority", async () => {
		const { store, calls } = fakeStore();
		const quotaResponse = await routeApp(store).request("/v1/delivery/quotas");
		expect(quotaResponse.status).toBe(200);
		expect(calls.quota).toHaveBeenCalledWith(scope);

		const readinessResponse = await routeApp(store, {
			resolveScope: () => {
				throw new Error("readiness must not require project/environment scope");
			},
		}).request("/v1/delivery/readiness?staleAfterMs=5000");
		expect(readinessResponse.status).toBe(200);
		expect(calls.readiness).toHaveBeenCalledWith({ staleAfterMs: 5_000 });

		expect(requiredApiKeyScope("GET", "/v1/delivery/jobs")).toBe("delivery:read");
		expect(requiredApiKeyScope("POST", `/v1/delivery/jobs/${job.id}/retry`)).toBe(
			"delivery:write",
		);
		expect(apiKeyRouteIsOperatorOnly("GET", "/v1/delivery/readiness")).toBe(true);
		expect(apiKeyRouteIsOperatorOnly("GET", "/v1/delivery/quotas")).toBe(false);
	});
});
