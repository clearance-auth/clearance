import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server } from "node:http";
import { createRequire } from "node:module";
import { afterAll, describe, expect, it } from "vitest";

const DATABASE_URL = process.env.CLEARANCE_TEST_DATABASE_URL ?? process.env.DATABASE_URL ?? "postgres://clearance:clearance@localhost:5434/clearance";

type SpanContext = { traceId: string; spanId: string; traceFlags: number; isRemote?: boolean };
type ReadableSpan = {
	name: string;
	attributes: Readonly<Record<string, unknown>>;
	events: readonly unknown[];
	spanContext(): SpanContext;
	parentSpanContext?: SpanContext;
};

class InMemoryExporter {
	readonly spans: ReadableSpan[] = [];

	export(spans: readonly ReadableSpan[], callback: (result: { code: number }) => void): void {
		this.spans.push(...spans);
		callback({ code: 0 });
	}

	shutdown(): Promise<void> {
		return Promise.resolve();
	}

	forceFlush(): Promise<void> {
		return Promise.resolve();
	}

	clear(): void {
		this.spans.length = 0;
	}
}

const observabilityRequire = createRequire(
	new URL("../../observability-node/src/index.ts", import.meta.url),
);
const { NodeSDK } = observabilityRequire("@opentelemetry/sdk-node") as {
	NodeSDK: new (options: Record<string, unknown>) => { start(): void; shutdown(): Promise<void> };
};
const { PgInstrumentation } = observabilityRequire("@opentelemetry/instrumentation-pg") as {
	PgInstrumentation: new (options?: Record<string, unknown>) => { disable(): void };
};
const { HttpInstrumentation } = observabilityRequire("@opentelemetry/instrumentation-http") as {
	HttpInstrumentation: new (options?: Record<string, unknown>) => { disable(): void };
};
const { resourceFromAttributes } = observabilityRequire("@opentelemetry/resources") as {
	resourceFromAttributes(attributes: Record<string, string>): unknown;
};
const otel = observabilityRequire("@opentelemetry/api") as {
	trace: {
		getTracer(name: string): {
			startActiveSpan<T>(name: string, callback: (span: { spanContext(): SpanContext; end(): void }) => T): T;
		};
		disable(): void;
	};
	context: { disable(): void };
};
const redactionModule = new URL("../../observability-node/src/redaction.ts", import.meta.url).href;
const { RedactingSpanExporter } = await import(/* @vite-ignore */ redactionModule);
const propagationModule = new URL("../../observability-node/src/propagation.ts", import.meta.url).href;
const { inboundOnlyTraceContextPropagator } = await import(/* @vite-ignore */ propagationModule);

const exported = new InMemoryExporter();
const raw: ReadableSpan[] = [];
let collectSpans = true;
const redactingExporter = new RedactingSpanExporter(
	exported as never,
	resourceFromAttributes({ "service.name": "clearance-test" }) as never,
	() => {},
);
const pgInstrumentation = new PgInstrumentation({ enhancedDatabaseReporting: false });
const httpInstrumentation = new HttpInstrumentation({
	ignoreIncomingRequestHook: (request: IncomingMessage) => request.url?.startsWith("/private-webhook") === true,
	headersToSpanAttributes: { client: { requestHeaders: [], responseHeaders: [] }, server: { requestHeaders: [], responseHeaders: [] } },
});
const tracing = new NodeSDK({
	autoDetectResources: false,
	resource: resourceFromAttributes({ "service.name": "clearance-test" }),
	textMapPropagator: inboundOnlyTraceContextPropagator,
	instrumentations: [httpInstrumentation, pgInstrumentation],
	spanProcessors: [{
		onStart: () => {},
		onEnd: (span: ReadableSpan) => {
			if (!collectSpans) return;
			raw.push(span);
			redactingExporter.export([span] as never, () => {});
		},
		shutdown: () => Promise.resolve(),
		forceFlush: () => Promise.resolve(),
	}],
});
tracing.start();

// PgInstrumentation patches CommonJS module loading. Load pg only after the
// SDK has installed that hook; Vite may otherwise pre-evaluate an ESM import.
const workerRequire = createRequire(new URL("./worker.ts", import.meta.url));
const pg = workerRequire("pg") as typeof import("pg").default;
const delivery = await import("@clearance/delivery");
const deliveryKey = randomBytes(32).toString("base64");
const fingerprintKey = randomBytes(32).toString("base64");
const sourceDedupeKey = randomBytes(32).toString("base64");
const deliveryPrefix = `delivery_trace_${process.pid}_${randomUUID().slice(0, 8).replace(/-/g, "")}_`;
Object.assign(process.env, {
	DATABASE_URL,
	CLEARANCE_SECRET: "trace-proof-api-secret-value-not-default",
	CLEARANCE_OPERATOR_TOKEN: "trace-proof-operator-token-32chars",
	CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION: "digest-v1",
	CLEARANCE_DELIVERY_KEY_ID: "trace-current",
	CLEARANCE_DELIVERY_KEYS_JSON: JSON.stringify({ "trace-current": deliveryKey }),
	CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID: "trace-fingerprint",
	CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON: JSON.stringify({ "trace-fingerprint": fingerprintKey }),
	CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY: sourceDedupeKey,
	CLEARANCE_DELIVERY_PREFIX: deliveryPrefix,
});
const { getAuthBundle, closeAuthBundle } = await import("@clearance/management");
const runtimeAuditModule = new URL("../../clearance-auth/src/runtime-audit.ts", import.meta.url).href;
const { createRuntimeAuditOutbox } = await import(/* @vite-ignore */ runtimeAuditModule);
const apiModuleUrl = new URL("../../clearance-api/src/server.ts", import.meta.url).href;
const { nodeRequestHandler } = await import(/* @vite-ignore */ apiModuleUrl);
const { DeliveryWorker } = await import("./worker.js");

const gate = new pg.Pool({ connectionString: DATABASE_URL, connectionTimeoutMillis: 500 });
let available = false;
try {
	await gate.query("SELECT 1");
	available = true;
} catch {
	if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") {
		throw new Error(`Delivery trace propagation test requires ${DATABASE_URL}`);
	}
} finally {
	await gate.end();
}
if (available) await getAuthBundle().migrate();

afterAll(async () => {
	httpInstrumentation.disable();
	pgInstrumentation.disable();
	await closeAuthBundle();
	await tracing.shutdown();
	otel.trace.disable();
	otel.context.disable();
});

function startWebhookFixture(): Promise<{
	port: number;
	requests: Array<{ headers: IncomingHttpHeaders; body: Buffer }>;
	stop(): Promise<void>;
}> {
	const requests: Array<{ headers: IncomingHttpHeaders; body: Buffer }> = [];
	const server: Server = createServer((request, response) => {
		const chunks: Buffer[] = [];
		request.on("data", (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
		request.on("end", () => {
			requests.push({ headers: request.headers, body: Buffer.concat(chunks) });
			response.statusCode = 204;
			response.end();
		});
	});
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			if (!address || typeof address === "string") {
				reject(new Error("Loopback webhook fixture did not bind a TCP port"));
				return;
			}
			resolve({
				port: address.port,
				requests,
				stop: () => new Promise<void>((done) => server.close(() => done())),
			});
		});
	});
}

function startApiFixture(): Promise<{ port: number; stop(): Promise<void> }> {
	const server = createServer(nodeRequestHandler);
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			if (!address || typeof address === "string") return reject(new Error("API fixture did not bind a TCP port"));
			resolve({ port: address.port, stop: () => new Promise<void>((done, fail) => server.close((error) => error ? fail(error) : done())) });
		});
	});
}

describe.skipIf(!available)("delivery trace propagation with PostgreSQL", () => {
	const suffix = `${process.pid}_${randomUUID().slice(0, 8).replace(/-/g, "")}_`;
	const prefix = deliveryPrefix;
	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	const keyring = delivery.resolveDeliveryKeyring(process.env);

	afterAll(async () => {
		const names = delivery.deliveryTableNames({ prefix });
		const cleanupErrors: unknown[] = [];
		for (const name of [names.attempt, names.job, names.payload, names.event, names.webhookEndpoint, names.worker, names.meta]) {
			try {
				await pool.query(`DROP TABLE IF EXISTS ${delivery.quoteIdentifier("public")}.${delivery.quoteIdentifier(name)} CASCADE`);
			} catch (error) { cleanupErrors.push(error); }
		}
		try { await pool.query(`DROP FUNCTION IF EXISTS ${delivery.quoteIdentifier("public")}.${delivery.quoteIdentifier(names.rejectMutationFunction)}()`); } catch (error) { cleanupErrors.push(error); }
		try { await pool.end(); } catch (error) { cleanupErrors.push(error); }
		if (cleanupErrors.length) throw new AggregateError(cleanupErrors, "Trace proof database cleanup failed");
	});

	it("keeps one trace through enqueue, durable claim, worker completion, and a header-free loopback webhook", async () => {
		const webhook = await startWebhookFixture();
		const api = await startApiFixture();
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const worker = new DeliveryWorker({
			mode: "once",
			databaseUrl: DATABASE_URL,
			workerId: `trace-worker-${suffix}`,
			keyring,
			schema: "public",
			prefix,
			smtp: {
				host: "127.0.0.1", port: 1, secure: false, requireTls: false, allowInsecureLoopback: true,
				from: "trace-sender@example.test", connectionTimeoutMs: 1_000, socketTimeoutMs: 1_000, greetingTimeoutMs: 1_000,
			},
			concurrency: 1,
			pollMs: 25,
			leaseMs: 5_000,
			heartbeatMs: 1_000,
			maintenanceMs: 1_000,
			drainTimeoutMs: 5_000,
			maxBodyBytes: 1024 * 1024,
			appName: "Clearance Trace Test",
			allowHttpLinks: false,
			healthHost: "127.0.0.1",
			healthPort: 0,
			processOnceLimit: 1,
			webhook: {
				allowInsecureLoopback: true,
				dnsTimeoutMs: 2_000,
				connectTimeoutMs: 2_000,
				responseTimeoutMs: 2_000,
				maxResponseBytes: 65_536,
			},
		}, { pool: workerPool, logger: { log: () => {} } });
		let workerInitialized = false;

		try {
			const initialized = await fetch(`http://127.0.0.1:${api.port}/v1/init`, {
				method: "POST",
				headers: {
					authorization: "Bearer trace-proof-operator-token-32chars",
					"content-type": "application/json",
				},
				body: JSON.stringify({ name: `Trace Proof ${suffix}` }),
			});
			const initializedPayload = await initialized.text();
			expect(initialized.status, initializedPayload).toBe(200);
			const initializedBody = JSON.parse(initializedPayload) as { project: { id: string }; environment: { id: string } };
			await createRuntimeAuditOutbox(pool, {
				projectId: initializedBody.project.id,
				environmentId: initializedBody.environment.id,
			}).applyMigration();
			const createdEndpoint = await fetch(`http://127.0.0.1:${api.port}/v1/delivery/webhook-endpoints`, {
				method: "POST",
				headers: {
					authorization: "Bearer trace-proof-operator-token-32chars",
					"content-type": "application/json",
				},
				body: JSON.stringify({ name: `Trace sink ${suffix}`, url: "https://example.test/trace", eventKinds: ["organization.updated"] }),
			});
			const createdEndpointPayload = await createdEndpoint.text();
			expect(createdEndpoint.status, createdEndpointPayload).toBe(201);
			const endpointBody = JSON.parse(createdEndpointPayload) as { endpoint: { id: string; resourceVersion: number }; signingSecret: string };
			const destination = `http://127.0.0.1:${webhook.port}/private-webhook`;
			const envelope = delivery.encryptWebhookEndpointConfig(
				{ url: destination, signingSecret: endpointBody.signingSecret },
				{ version: 1, endpointId: endpointBody.endpoint.id, projectId: initializedBody.project.id, environmentId: initializedBody.environment.id, secretVersion: 1 },
				keyring,
			);
			const tables = delivery.qualifiedDeliveryTables({ prefix });
			await pool.query(
				`UPDATE ${tables.webhookEndpoint} SET config_envelope=$1, url_fingerprint=$2 WHERE id=$3`,
				[
					envelope.envelope,
					delivery.fingerprintDestination(destination, keyring, keyring.currentFingerprintKeyId),
					endpointBody.endpoint.id,
				],
			);
			await worker.initialize({ verifyEmail: false });
			workerInitialized = true;
			exported.clear();
			raw.length = 0;

			const remoteTraceId = "1234567890abcdef1234567890abcdef";
			const remoteParentId = "1234567890abcdef";
			let persistedTraceparent: string | null = null;
			let deliveredState: string | undefined;
			let providerRequestId: string | null = null;
			let ambientTraceId: string | undefined;
			const tested = await fetch(`http://127.0.0.1:${api.port}/v1/delivery/webhook-endpoints/${encodeURIComponent(endpointBody.endpoint.id)}/test`, {
				method: "POST",
				headers: {
					authorization: "Bearer trace-proof-operator-token-32chars",
					"content-type": "application/json",
					traceparent: `00-${remoteTraceId}-${remoteParentId}-01`,
					tracestate: "vendor=trace-state-private",
					baggage: "tenant=baggage-private",
				},
				body: JSON.stringify({ expectedVersion: endpointBody.endpoint.resourceVersion, confirm: true }),
			});
			const testedPayload = await tested.text();
			expect(tested.status, testedPayload).toBe(200);
			const testedBody = JSON.parse(testedPayload) as { result: { delivery: { eventId: string; jobId: string } } };
			const eventId = testedBody.result.delivery.eventId;
			const jobId = testedBody.result.delivery.jobId;
			collectSpans = false;
			persistedTraceparent = (await pool.query<{ trace_parent: string | null }>(
				`SELECT trace_parent FROM ${tables.event} WHERE id=$1`, [eventId],
			)).rows[0]?.trace_parent ?? null;
			collectSpans = true;
			expect(persistedTraceparent).toMatch(new RegExp(`^00-${remoteTraceId}-[0-9a-f]{16}-01$`));
			const processed = await otel.trace.getTracer("trace-proof").startActiveSpan(
				"trace-proof-ambient",
				async (ambientSpan) => {
					ambientTraceId = ambientSpan.spanContext().traceId;
					try {
						return await worker.processOnce(1);
					} finally {
						ambientSpan.end();
					}
				},
			);
			expect(processed).toBe(1);
			expect(ambientTraceId).not.toBe(remoteTraceId);
			collectSpans = false;
			const delivered = (await pool.query<{ state: string; provider_request_id: string | null }>(
				`SELECT state, provider_request_id FROM ${tables.job} WHERE id=$1`, [jobId],
			)).rows[0];
			collectSpans = true;
			deliveredState = delivered?.state;
			providerRequestId = delivered?.provider_request_id ?? null;
			expect(deliveredState).toBe("delivered");
			expect(providerRequestId).toMatch(/^[0-9a-f]{64}$/);
			expect(webhook.requests).toHaveLength(1);
			expect(webhook.requests[0]?.headers.traceparent).toBeUndefined();
			expect(webhook.requests[0]?.headers.tracestate).toBeUndefined();
			expect(webhook.requests[0]?.headers.baggage).toBeUndefined();
			expect(webhook.requests[0]?.headers.authorization).toBeUndefined();
			expect(webhook.requests[0]?.headers.cookie).toBeUndefined();
			expect(webhook.requests[0]?.body.toString("utf8")).toContain(eventId);

			const processing = raw.find((span) => span.name === "clearance.delivery.process");
			expect(processing?.parentSpanContext).toMatchObject({
				traceId: remoteTraceId,
				spanId: persistedTraceparent!.split("-")[2],
				isRemote: true,
			});
			expect(raw).not.toHaveLength(0);
			const traceSpans = raw.filter((span) => span.spanContext().traceId === remoteTraceId);
			expect(traceSpans).not.toHaveLength(0);
			expect(traceSpans.some((span) => span.attributes["db.system.name"] === "postgresql")).toBe(true);
			expect(traceSpans.some((span) =>
				span.attributes["http.request.method"] === "POST" ||
				span.attributes["http.method"] === "POST"
			)).toBe(true);

			const exportedTrace = exported.spans.filter((span) => span.spanContext().traceId === remoteTraceId);
			const serializedExport = JSON.stringify(exportedTrace);
			expect(exportedTrace).not.toHaveLength(0);
			for (const span of exportedTrace) {
				expect(span.events).toEqual([]);
				expect(span.spanContext().traceId).toBe(remoteTraceId);
				expect(Object.keys(span.attributes).every((key) => [
					"db.system.name",
					"db.operation.name",
					"http.request.method",
					"http.response.status_code",
				].includes(key))).toBe(true);
			}
			for (const privateValue of [
				eventId, jobId, initializedBody.project.id, initializedBody.environment.id, endpointBody.endpoint.id,
				destination, "private-webhook", endpointBody.signingSecret, providerRequestId!,
				"127.0.0.1", "trace-sender@example.test",
				"clearance-delivery-worker/0.2",
				"trace-state-private", "baggage-private",
			]) {
				expect(serializedExport).not.toContain(privateValue);
			}
		} finally {
			const cleanupErrors: unknown[] = [];
			const cleanups = [
				workerInitialized ? () => worker.stop() : () => workerPool.end(),
				() => api.stop(),
				() => webhook.stop(),
			];
			for (const cleanup of cleanups) {
				try { await cleanup(); } catch (error) { cleanupErrors.push(error); }
			}
			if (cleanupErrors.length) throw new AggregateError(cleanupErrors, "Trace proof runtime cleanup failed");
		}
	});
});
