import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { parseWorkerConfig, type WorkerConfig } from "./config.js";
import { createJsonLogger } from "./logger.js";
import {
	canonicalWebhookBytes,
	classifyWebhookError,
	createWebhookSender,
	parseOrganizationUpdatedPayload,
	pinnedWebhookRequest,
	verifyWebhookSignature,
	webhookSignature,
	type PinnedWebhookRequest,
} from "./webhook.js";

const secret = "webhook-signing-secret-at-least-32-bytes";
const key = () => randomBytes(32).toString("base64");

function config(overrides: Partial<WorkerConfig["webhook"]> = {}): WorkerConfig {
	const parsed = parseWorkerConfig({
		DATABASE_URL: "postgres://example.test/db",
		CLEARANCE_SMTP_HOST: "smtp.example.test",
		CLEARANCE_EMAIL_FROM: "support@example.test",
		CLEARANCE_DELIVERY_KEY_ID: "current",
		CLEARANCE_DELIVERY_KEYS_JSON: JSON.stringify({ current: key() }),
		CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID: "fingerprint-current",
		CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON: JSON.stringify({ "fingerprint-current": key() }),
		CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY: key(),
	});
	return { ...parsed, webhook: { ...parsed.webhook, ...overrides } };
}

function payload(url = "https://hooks.example.test/events") {
	return {
		version: 1,
		endpoint: { id: "target-1", url, signingSecret: secret },
		event: {
			id: "event-1",
			type: "organization.updated",
			occurredAt: "2026-07-15T00:00:00.000Z",
			context: {
				projectId: "project-1",
				environmentId: "environment-1",
				organizationId: "organization-1",
				actor: "operator-1",
				correlationId: "correlation-1",
			},
			data: {
				organization: { id: "organization-1", name: "Updated\nOrg\t\u0000", slug: "updated-org", status: "active" },
				previous: { name: "Old\r\nOrg", slug: "old-org" },
			},
		},
	};
}

const servers: ReturnType<typeof createServer>[] = [];
afterEach(async () => {
	for (const server of servers.splice(0)) {
		server.closeAllConnections();
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
});

describe("signed webhook transport", () => {
	it("pins a validated DNS answer and signs stable exact bytes for replay", async () => {
		const requests: Parameters<PinnedWebhookRequest>[0][] = [];
		const sender = createWebhookSender(config(), {
			lookup: async (hostname) => {
				expect(hostname).toBe("hooks.example.test");
				return [{ address: "93.184.216.34", family: 4 }];
			},
			request: async (input) => { requests.push(input); return 204; },
			now: () => 1_784_073_600_000,
		});
		await sender.send(payload(), { jobId: "job-1", eventId: "event-1" });
		await sender.send(payload(), { jobId: "job-1", eventId: "event-1" });

		expect(requests).toHaveLength(2);
		const [first, second] = requests as [Parameters<PinnedWebhookRequest>[0], Parameters<PinnedWebhookRequest>[0]];
		expect(first.pinned).toEqual({ address: "93.184.216.34", family: 4 });
		expect(first.url.hostname).toBe("hooks.example.test");
		expect(first.headers["webhook-id"]).toBe("event-1");
		expect(first.headers["idempotency-key"]).toBe("job-1");
		expect(first.body.equals(second.body)).toBe(true);
		expect(first.headers).toEqual(second.headers);
		expect(first.body.equals(canonicalWebhookBytes(parseOrganizationUpdatedPayload(payload())))).toBe(true);
		expect(first.body.toString("utf8")).toContain("Updated\\nOrg\\t\\u0000");
		expect(first.body.toString("utf8")).not.toContain(secret);
		expect(first.headers["webhook-signature"]).toBe(webhookSignature(
			secret,
			"event-1",
			first.headers["webhook-timestamp"]!,
			first.body,
		));
		expect(verifyWebhookSignature(
			secret,
			"event-1",
			first.headers["webhook-timestamp"]!,
			first.body,
			first.headers["webhook-signature"]!,
		)).toBe(true);
	});

	it("rejects the entire DNS result when any answer is non-global", async () => {
		let requestCalled = false;
		const sender = createWebhookSender(config(), {
			lookup: async () => [
				{ address: "93.184.216.34", family: 4 },
				{ address: "127.0.0.1", family: 4 },
			],
			request: async () => { requestCalled = true; return 204; },
		});
		await expect(sender.send(payload(), { jobId: "job-1", eventId: "event-1" })).rejects.toMatchObject({
			code: "WEBHOOK_DESTINATION_FORBIDDEN",
		});
		expect(requestCalled).toBe(false);
	});

	it("bounds DNS resolution before transport starts", async () => {
		let requestCalled = false;
		const sender = createWebhookSender(config({ dnsTimeoutMs: 10 }), {
			lookup: async () => new Promise<never>(() => undefined),
			request: async () => { requestCalled = true; return 204; },
		});
		await expect(sender.send(payload(), { jobId: "job-1", eventId: "event-1" })).rejects.toMatchObject({
			code: "WEBHOOK_DNS_TIMEOUT",
		});
		expect(requestCalled).toBe(false);
	});

	it("requires HTTPS except for explicit loopback development", async () => {
		const localPayload = payload("http://127.0.0.1:8080/events");
		await expect(createWebhookSender(config()).send(localPayload, {
			jobId: "job-1", eventId: "event-1",
		})).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_INVALID" });

		let pinned: { address: string; family: number } | undefined;
		await createWebhookSender(config({ allowInsecureLoopback: true }), {
			request: async (input) => { pinned = input.pinned; return 204; },
		}).send(localPayload, { jobId: "job-1", eventId: "event-1" });
		expect(pinned).toEqual({ address: "127.0.0.1", family: 4 });

		for (const url of [
			"https://user:password@hooks.example.test/events",
			"https://hooks.example.test/events#fragment",
			"http://hooks.example.test/events",
		]) {
			await expect(createWebhookSender(config()).send(payload(url), {
				jobId: "job-1", eventId: "event-1",
			})).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_INVALID" });
		}
	});

	it("refuses redirects and classifies only retry-safe statuses as transient", async () => {
		let requests = 0;
		const sender = createWebhookSender(config(), {
			lookup: async () => [{ address: "93.184.216.34", family: 4 }],
			request: async () => { requests++; return 302; },
		});
		await expect(sender.send(payload(), { jobId: "job-1", eventId: "event-1" })).rejects.toMatchObject({
			code: "WEBHOOK_REDIRECT_REFUSED", status: 302,
		});
		expect(requests).toBe(1);
		for (const status of [408, 425, 429, 500, 503]) expect(classifyWebhookError({ status }).retryable).toBe(true);
		for (const status of [300, 301, 400, 401, 404, 409, 422]) expect(classifyWebhookError({ status }).retryable).toBe(false);
		expect(classifyWebhookError(Object.assign(new Error("private response"), { code: "ECONNRESET" })).retryable).toBe(true);
	});

	it("enforces bounded response bytes and a total post-connect deadline", async () => {
		const server = createServer((request, response) => {
			if (request.url === "/large") {
				response.writeHead(200);
				response.end("12345");
				return;
			}
			response.writeHead(200);
			const interval = setInterval(() => response.write("x"), 10);
			response.on("close", () => clearInterval(interval));
		});
		servers.push(server);
		await new Promise<void>((resolve, reject) => {
			server.once("error", reject);
			server.listen(0, "127.0.0.1", resolve);
		});
		const port = (server.address() as AddressInfo).port;
		const base = {
			pinned: { address: "127.0.0.1", family: 4 as const },
			headers: { "content-type": "application/json" }, body: Buffer.from("{}"),
			connectTimeoutMs: 500, responseTimeoutMs: 500, maxResponseBytes: 4,
		};
		await expect(pinnedWebhookRequest({
			...base, url: new URL(`http://webhook.example:${port}/large`),
		})).rejects.toMatchObject({ code: "WEBHOOK_RESPONSE_TOO_LARGE" });
		await expect(pinnedWebhookRequest({
			...base, url: new URL(`http://webhook.example:${port}/slow`),
			responseTimeoutMs: 50, maxResponseBytes: 1_024,
		})).rejects.toMatchObject({ code: "WEBHOOK_RESPONSE_TIMEOUT" });
	});

	it("does not leak endpoint, secret, body, or response detail through errors and logs", async () => {
		const endpoint = "https://hooks.example.test/private-path";
		const responseDetail = "provider-private-response";
		let caught: unknown;
		try {
			await createWebhookSender(config(), {
				lookup: async () => [{ address: "93.184.216.34", family: 4 }],
				request: async () => { throw Object.assign(new Error(responseDetail), { code: "ECONNRESET" }); },
			}).send(payload(endpoint), { jobId: "job-1", eventId: "event-1" });
		} catch (error) { caught = error; }
		const lines: string[] = [];
		createJsonLogger((line) => lines.push(line)).log("error", "webhook_failed", { error: caught });
		const output = lines.join("\n");
		expect(output).not.toContain(endpoint);
		expect(output).not.toContain(secret);
		expect(output).not.toContain("Updated");
		expect(output).not.toContain(responseDetail);
	});
});
