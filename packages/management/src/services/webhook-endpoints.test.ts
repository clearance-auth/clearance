import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { JsonStore } from "../store/json-store.js";
import { listWebhookEndpointsForManagement } from "./webhook-endpoints.js";

describe("webhook endpoint management capability", () => {
	it("fails closed when the audited PostgreSQL capability is unavailable", async () => {
		const store = new JsonStore(join(tmpdir(), `clearance-webhook-service-${randomUUID()}.json`));
		await expect(listWebhookEndpointsForManagement(store, {
			projectId: "project_1",
			environmentId: "environment_1",
		})).rejects.toMatchObject({
			code: "WEBHOOK_ENDPOINT_POSTGRES_REQUIRED",
			status: 400,
			stage: "delivery.webhook_endpoints.list",
		});
	});
});
