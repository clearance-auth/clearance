import { describe, expect, it } from "vitest";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { RedactingSpanExporter } from "../src/redaction";

describe("redactSpanForExport", () => {
	it("allows only safe operation attributes through a synthetic exported span", () => {
		let exported: unknown;
		const safeResource = resourceFromAttributes({
			"service.name": "clearance-api",
		});
		const exporter = new RedactingSpanExporter(
			{
				export(
					spans: readonly unknown[],
					callback: (result: { code: number }) => void,
				) {
					exported = spans[0];
					callback({ code: 0 });
				},
				shutdown: async () => {},
			} as never,
			safeResource,
			() => {},
		);

		exporter.export([{
			_privateSecret: "private-span-secret",
			name: "SELECT * FROM accounts WHERE email = 'person@example.com'",
			kind: 2,
			spanContext: () => ({
				traceId: "a".repeat(32),
				spanId: "b".repeat(16),
				traceFlags: 1,
				traceState: { serialize: () => "trace-state-secret" },
			}),
			parentSpanContext: {
				traceId: "c".repeat(32),
				spanId: "d".repeat(16),
				traceFlags: 1,
				traceState: { serialize: () => "parent-trace-state-secret" },
			},
			startTime: [1, 2],
			endTime: [3, 4],
			duration: [2, 2],
			ended: true,
			resource: resourceFromAttributes({ secret: "resource-secret" }),
			instrumentationScope: { name: "scope-secret" },
			attributes: {
				"http.request.method": "POST",
				"http.response.status_code": 500,
				"url.full": "https://clearance.example/sign-in?token=secret-token",
				"http.request.header.authorization": "Bearer secret-header",
				"db.system.name": "postgresql",
				"db.query.text": "SELECT * FROM accounts WHERE email = 'person@example.com'",
				"db.statement": "SELECT * FROM accounts WHERE email = 'person@example.com'",
				"db.operation.name": "SELECT",
				"pg.values": ["person@example.com", "secret-value"],
				"exception.message": "secret exception message",
				"exception.stacktrace": "secret exception stack",
			},
			links: [
				{
					context: {
						traceId: "a".repeat(32),
						spanId: "b".repeat(16),
						traceFlags: 1,
					},
					attributes: { secret: "link-secret" },
				},
			],
			events: [
				{
					name: "exception",
					time: [0, 0],
					attributes: { "exception.message": "event-secret" },
				},
			],
			status: { code: 2, message: "status-secret" },
			droppedAttributesCount: 5,
			droppedEventsCount: 6,
			droppedLinksCount: 7,
		} as never], () => {});

		expect(exported).toMatchObject({
			name: "postgresql SELECT",
			attributes: {
				"http.request.method": "POST",
				"http.response.status_code": 500,
				"db.system.name": "postgresql",
				"db.operation.name": "SELECT",
			},
			links: [],
			events: [],
			status: { code: 2 },
			resource: safeResource,
			instrumentationScope: { name: "@opentelemetry/instrumentation-pg" },
			droppedAttributesCount: 0,
			droppedEventsCount: 0,
			droppedLinksCount: 0,
		});
		expect((exported as { spanContext(): object }).spanContext()).toEqual({
			traceId: "a".repeat(32),
			spanId: "b".repeat(16),
			traceFlags: 1,
		});
		expect((exported as { parentSpanContext: object }).parentSpanContext).toEqual({
			traceId: "c".repeat(32),
			spanId: "d".repeat(16),
			traceFlags: 1,
		});
		const serialized = JSON.stringify(exported);
		for (const secret of [
			"secret-token",
			"secret-header",
			"person@example.com",
			"secret-value",
			"secret exception",
			"event-secret",
			"status-secret",
			"link-secret",
			"private-span-secret",
			"resource-secret",
			"scope-secret",
		]) {
			expect(serialized).not.toContain(secret);
		}
	});
});
