import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

const service = vi.hoisted(() => ({
	list: vi.fn(),
	inspect: vi.fn(),
	create: vi.fn(),
	update: vi.fn(),
	rotate: vi.fn(),
	delete: vi.fn(),
	test: vi.fn(),
}));

vi.mock("@clearance/management", async (importOriginal) => {
	const original = await importOriginal<typeof import("@clearance/management")>();
	const operations = await import("../../management/src/contracts/operations.ts");
	return {
		...original,
		WEBHOOK_ENDPOINT_OPERATIONS: operations.WEBHOOK_ENDPOINT_OPERATIONS,
		listWebhookEndpointsForManagement: service.list,
		inspectWebhookEndpointForManagement: service.inspect,
		createWebhookEndpointForManagement: service.create,
		updateWebhookEndpointForManagement: service.update,
		rotateWebhookEndpointForManagement: service.rotate,
		deleteWebhookEndpointForManagement: service.delete,
		testWebhookEndpointForManagement: service.test,
	};
});

import {
	ClearanceError,
	JsonStore,
	type ResourceScope,
} from "@clearance/management";
import { registerWebhookEndpointRoutes } from "./routes/webhook-endpoints.js";

const scope: ResourceScope = {
	projectId: "project_webhooks",
	environmentId: "environment_webhooks",
};

function app() {
	const store = new JsonStore(join(tmpdir(), `clearance-webhook-route-${randomUUID()}.json`));
	const routes = registerWebhookEndpointRoutes({
		storeForRequest: async () => store,
		scopeForRequest: () => scope,
		handleError: (context, error) => {
			if (error instanceof ClearanceError) return context.json(error.toJSON(), error.status);
			return context.json({ error: { code: "INTERNAL" } }, 500);
		},
	});
	const testApp = new Hono();
	testApp.route("/", routes);
	return testApp;
}

describe("webhook endpoint API routes", () => {
	beforeEach(() => vi.clearAllMocks());

	it("maps strict list filters to the scoped service", async () => {
		service.list.mockResolvedValueOnce({ schemaVersion: "v1", scope, items: [], nextCursor: null });
		const response = await app().request(
			"/v1/delivery/webhook-endpoints?limit=25&status=active&status=disabled&eventKind=organization.updated",
		);
		expect(response.status).toBe(200);
		expect(service.list).toHaveBeenLastCalledWith(expect.anything(), {
			...scope,
			limit: 25,
			statuses: ["active", "disabled"],
			eventKind: "organization.updated",
		});
	});

	it("creates through the canonical route with exact fields", async () => {
		service.create.mockResolvedValueOnce({
			schemaVersion: "v1",
			operation: "delivery.webhook_endpoints.create",
			storeBackend: "postgres",
			scope,
			endpoint: { id: "endpoint_1" },
			signingSecret: "whsec_once",
		});
		const response = await app().request("/v1/delivery/webhook-endpoints", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				name: "Audit sink",
				url: "https://hooks.example.test/events",
				eventKinds: ["organization.updated"],
			}),
		});
		expect(response.status).toBe(201);
		expect(service.create).toHaveBeenLastCalledWith(expect.anything(), expect.objectContaining({
			...scope,
			actor: "api",
			source: "api",
			name: "Audit sink",
			url: "https://hooks.example.test/events",
			eventKinds: ["organization.updated"],
		}));
		expect(await response.json()).toMatchObject({ signingSecret: "whsec_once" });
	});

	it("previews versioned controls by default and confirms only explicitly", async () => {
		service.rotate.mockResolvedValue({ dryRun: true });
		let response = await app().request("/v1/delivery/webhook-endpoints/endpoint_1/rotate", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ expectedVersion: 4 }),
		});
		expect(response.status).toBe(200);
		expect(service.rotate).toHaveBeenLastCalledWith(expect.anything(), expect.objectContaining({
			endpointId: "endpoint_1",
			expectedVersion: 4,
			dryRun: false,
			confirm: false,
		}));

		service.delete.mockResolvedValue({ dryRun: false });
		response = await app().request("/v1/delivery/webhook-endpoints/endpoint_1", {
			method: "DELETE",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ expectedVersion: 4, confirm: true }),
		});
		expect(response.status).toBe(200);
		expect(service.delete).toHaveBeenLastCalledWith(expect.anything(), expect.objectContaining({
			endpointId: "endpoint_1",
			expectedVersion: 4,
			confirm: true,
		}));
	});

	it("rejects unknown fields and query parameters before service I/O", async () => {
		let response = await app().request("/v1/delivery/webhook-endpoints?includeSecret=true");
		expect(response.status).toBe(400);
		response = await app().request("/v1/delivery/webhook-endpoints", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				name: "Audit sink",
				url: "https://hooks.example.test/events",
				secret: "client-controlled",
			}),
		});
		expect(response.status).toBe(400);
		expect(service.list).not.toHaveBeenCalled();
		expect(service.create).not.toHaveBeenCalled();
	});
});
