import net, { type Server, type Socket } from "node:net";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	createDeliveryKeyring,
	createDeliveryTransactionAdapter,
	createWebhookEndpoint,
	DeliveryStore,
	deliveryTableNames,
	enqueueDelivery,
	enqueueWebhookEndpointTestInExistingTransaction,
	qualifiedDeliveryTables,
	quoteIdentifier,
	type DeliveryRawTransaction,
} from "@clearance/delivery";
import type { WorkerConfig } from "./config.js";
import type { EmailSender } from "./smtp.js";
import { verifyWebhookSignature, webhookSignature } from "./webhook.js";
import { DeliveryDrainTimeoutError, DeliveryWorker } from "./worker.js";

const DATABASE_URL = process.env.CLEARANCE_TEST_DATABASE_URL ?? process.env.DATABASE_URL ?? "postgres://clearance:clearance@localhost:5434/clearance";
const gate = new pg.Pool({ connectionString: DATABASE_URL, connectionTimeoutMillis: 500 });
let available = false;
try { await gate.query("SELECT 1"); available = true; } catch {
	if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") throw new Error(`Delivery worker Postgres tests require ${DATABASE_URL}`);
} finally { await gate.end(); }

class SmtpFixture {
	server?: Server;
	messages: string[] = [];
	port = 0;
	async start() {
		this.server = net.createServer((socket) => this.handle(socket));
		await new Promise<void>((resolve, reject) => { this.server!.once("error", reject); this.server!.listen(0, "127.0.0.1", resolve); });
		this.port = (this.server.address() as net.AddressInfo).port;
	}
	private handle(socket: Socket) {
		socket.setEncoding("utf8");
		socket.write("220 fixture ESMTP\r\n");
		let buffer = "";
		let data = false;
		socket.on("data", (chunk: string) => {
			buffer += chunk;
			while (true) {
				if (data) {
					const end = buffer.indexOf("\r\n.\r\n");
					if (end < 0) return;
					this.messages.push(buffer.slice(0, end));
					buffer = buffer.slice(end + 5); data = false; socket.write("250 queued-as fixture-1\r\n");
					continue;
				}
				const end = buffer.indexOf("\r\n");
				if (end < 0) return;
				const line = buffer.slice(0, end); buffer = buffer.slice(end + 2);
				const command = line.split(" ", 1)[0]!.toUpperCase();
				if (command === "EHLO") socket.write("250-fixture\r\n250 SIZE 2097152\r\n");
				else if (command === "HELO" || command === "MAIL" || command === "RCPT" || command === "RSET") socket.write("250 ok\r\n");
				else if (command === "DATA") { data = true; socket.write("354 end with dot\r\n"); }
				else if (command === "QUIT") { socket.write("221 bye\r\n"); socket.end(); }
				else socket.write("502 unsupported\r\n");
			}
		});
	}
	async stop() { if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve())); }
}

class WebhookFixture {
	server?: HttpServer;
	port = 0;
	status = 204;
	requests: Array<{ headers: Record<string, string | string[] | undefined>; body: Buffer }> = [];
	async start() {
		this.server = createHttpServer((request, response) => {
			const chunks: Buffer[] = [];
			request.on("data", (chunk: Buffer | string) => {
				chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
			});
			request.on("end", () => {
				this.requests.push({ headers: request.headers, body: Buffer.concat(chunks) });
				response.statusCode = this.status;
				if (this.status >= 300 && this.status < 400) {
					response.setHeader("location", "http://127.0.0.1/redirect-refused");
				}
				response.end();
			});
		});
		await new Promise<void>((resolve, reject) => {
			this.server!.once("error", reject);
			this.server!.listen(0, "127.0.0.1", resolve);
		});
		this.port = (this.server.address() as net.AddressInfo).port;
	}
	async stop() {
		if (this.server) {
			await new Promise<void>((resolve) => this.server!.close(() => resolve()));
		}
	}
}

async function unusedPort(): Promise<number> {
	const server = net.createServer();
	await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
	const port = (server.address() as net.AddressInfo).port;
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return port;
}

function rawTransaction(client: pg.PoolClient): DeliveryRawTransaction {
	return {
		rawTransactionQuery: async <Row extends Record<string, unknown> = Record<string, unknown>>(
			text: string,
			values: readonly unknown[] = [],
		) => {
			const result = await client.query<Row>(text, [...values]);
			return { rows: result.rows, rowCount: result.rowCount };
		},
	};
}

function presentationTableNames(prefix: string) {
	return {
		senders: `${prefix}product_email_senders`,
		templates: `${prefix}product_email_templates`,
		domains: `${prefix}product_auth_domains`,
		presentations: `${prefix}product_presentations`,
	};
}

async function createPresentationAuthorityFixture(pool: pg.Pool, prefix: string): Promise<void> {
	const names = presentationTableNames(prefix);
	await pool.query(`CREATE TABLE ${quoteIdentifier("public")}.${quoteIdentifier(names.senders)} (
		project_id text, environment_id text, display_name text, address text, domain text, version integer
	)`);
	await pool.query(`CREATE TABLE ${quoteIdentifier("public")}.${quoteIdentifier(names.templates)} (
		project_id text, environment_id text, kind text, subject text, plain_text text, html text,
		variables text[], version integer, content_hash text
	)`);
	await pool.query(`CREATE TABLE ${quoteIdentifier("public")}.${quoteIdentifier(names.domains)} (
		project_id text, environment_id text, hostname text, state text
	)`);
	await pool.query(`CREATE TABLE ${quoteIdentifier("public")}.${quoteIdentifier(names.presentations)} (
		project_id text, environment_id text, product_label text
	)`);
}

describe.skipIf(!available)("delivery worker with Postgres and SMTP", () => {
	const suffix = `${process.pid}_${randomUUID().slice(0, 8).replace(/-/g, "")}_`;
	const prefix = `delivery_worker_${suffix}`;
	const managementPrefix = `dw_mgmt_${suffix}`;
	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	const keyring = createDeliveryKeyring({
		currentKeyId: "current",
		keys: { current: randomBytes(32) },
		currentFingerprintKeyId: "fingerprint-current",
		fingerprintKeys: { "fingerprint-current": randomBytes(32) },
		sourceDedupeKey: randomBytes(32),
	});
	const smtp = new SmtpFixture();
	const webhooks = new WebhookFixture();
	const logs: string[] = [];
	let config: WorkerConfig;

	beforeAll(async () => {
		await smtp.start();
		await webhooks.start();
		await createPresentationAuthorityFixture(pool, managementPrefix);
		config = {
			mode: "once", databaseUrl: DATABASE_URL, workerId: `test-worker-${suffix}`, keyring, schema: "public", prefix,
			managementSchema: "public", managementPrefix,
			smtp: { host: "127.0.0.1", port: smtp.port, secure: false, requireTls: false, allowInsecureLoopback: true, from: "support@example.test", connectionTimeoutMs: 2_000, socketTimeoutMs: 2_000, greetingTimeoutMs: 2_000 },
			concurrency: 2, pollMs: 25, leaseMs: 5_000, heartbeatMs: 1_000, maintenanceMs: 1_000,
			drainTimeoutMs: 5_000, maxBodyBytes: 1024 * 1024, appName: "Clearance Test",
			allowHttpLinks: false,
			healthHost: "127.0.0.1", healthPort: await unusedPort(), processOnceLimit: 10,
			webhook: {
				allowInsecureLoopback: true,
				dnsTimeoutMs: 2_000,
				connectTimeoutMs: 2_000,
				responseTimeoutMs: 2_000,
				maxResponseBytes: 65_536,
			},
		};
	});

	afterAll(async () => {
		await smtp.stop();
		await webhooks.stop();
		const names = deliveryTableNames({ prefix });
		for (const name of [names.attempt, names.job, names.payload, names.event, names.webhookEndpoint, names.worker, names.meta]) {
			await pool.query(`DROP TABLE IF EXISTS ${quoteIdentifier("public")}.${quoteIdentifier(name)} CASCADE`).catch(() => undefined);
		}
		await pool.query(`DROP FUNCTION IF EXISTS ${quoteIdentifier("public")}.${quoteIdentifier(names.rejectMutationFunction)}()`).catch(() => undefined);
		for (const name of Object.values(presentationTableNames(managementPrefix))) {
			await pool.query(`DROP TABLE IF EXISTS ${quoteIdentifier("public")}.${quoteIdentifier(name)} CASCADE`).catch(() => undefined);
		}
		await pool.end();
	});

	async function enqueue(eventId: string, jobId: string, sourceKey: string, payload: unknown = {
		template: "email-verification", to: "person@example.test", userName: "Test User",
		url: "https://app.example.test/verify?token=verification-secret",
	}, enqueueKeyring = keyring) {
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await enqueueDelivery(createDeliveryTransactionAdapter(client), {
				eventId, jobId, sourceKey, kind: "password.reset", projectId: "project-1", environmentId: "env-1",
				channel: "email", destination: "person@example.test",
				payload,
				semanticExpiresAt: new Date(Date.now() + 60_000),
			}, enqueueKeyring, { prefix });
			await client.query("COMMIT");
		} catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
	}

	function templatePayload(label: string) {
		return {
			template: "password-reset",
			to: "person@example.test",
			userName: "Test User",
			url: `https://app.example.test/reset?token=${label}`,
		};
	}

	async function enqueueWebhook(eventId: string, jobId: string, sourceKey: string) {
		const destination = `http://127.0.0.1:${webhooks.port}/events`;
		const signingSecret = "worker-webhook-signing-secret-at-least-32-bytes";
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await enqueueDelivery(createDeliveryTransactionAdapter(client), {
				eventId,
				jobId,
				sourceKey,
				kind: "organization.updated",
				projectId: "project-1",
				environmentId: "env-1",
				organizationId: "organization-1",
				channel: "webhook",
				destination,
				payload: {
					version: 1,
					endpoint: { id: "primary", url: destination, signingSecret },
					event: {
						id: eventId,
						type: "organization.updated",
						occurredAt: "2026-07-15T00:00:00.000Z",
						context: {
							projectId: "project-1",
							environmentId: "env-1",
							organizationId: "organization-1",
							actor: "operator-1",
							correlationId: "correlation-1",
						},
						data: {
							organization: {
								id: "organization-1",
								name: "Updated Org",
								slug: "updated-org",
								status: "active",
							},
							previous: { name: "Old Org", slug: "old-org" },
						},
					},
				},
				semanticExpiresAt: new Date(Date.now() + 60_000),
			}, keyring, { prefix });
			await client.query("COMMIT");
			return { destination, signingSecret };
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}

	it("delivers exact signed webhook bytes and refuses redirects without following them", async () => {
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const webhookLogs: string[] = [];
		const worker = new DeliveryWorker({
			...config,
			workerId: `webhook-${suffix}`,
		}, {
			pool: workerPool,
			logger: { log(level, event, fields) { webhookLogs.push(JSON.stringify({ level, event, fields })); } },
		});
		await worker.initialize();
		const delivered = await enqueueWebhook(
			"event-webhook-delivered",
			"job-webhook-delivered",
			"source-webhook-delivered",
		);
		expect(await worker.processOnce(1)).toBe(1);
		expect((await worker.store.inspectJob("job-webhook-delivered"))?.state).toBe("delivered");
		const request = webhooks.requests.at(-1)!;
		expect(JSON.parse(request.body.toString("utf8"))).toMatchObject({
			version: 1,
			event: { id: "event-webhook-delivered", type: "organization.updated" },
		});
		expect(request.body.toString("utf8")).not.toContain(delivered.signingSecret);
		const timestamp = String(request.headers["webhook-timestamp"]);
		const signature = String(request.headers["webhook-signature"]);
		expect(request.headers["webhook-id"]).toBe("event-webhook-delivered");
		expect(request.headers["idempotency-key"]).toBe("job-webhook-delivered");
		expect(signature).toBe(webhookSignature(
			delivered.signingSecret,
			"event-webhook-delivered",
			timestamp,
			request.body,
		));
		expect({
			valid: verifyWebhookSignature(
				delivered.signingSecret,
				"event-webhook-delivered",
				timestamp,
				request.body,
				signature,
			),
			timestamp,
			signature,
			eventIdHeader: request.headers["webhook-id"],
		}).toMatchObject({ valid: true });

		webhooks.status = 302;
		await enqueueWebhook(
			"event-webhook-redirect",
			"job-webhook-redirect",
			"source-webhook-redirect",
		);
		const beforeRedirect = webhooks.requests.length;
		expect(await worker.processOnce(1)).toBe(1);
		expect(webhooks.requests).toHaveLength(beforeRedirect + 1);
		const redirected = await worker.store.inspectJob("job-webhook-redirect");
		expect(redirected?.state).toBe("dead");
		expect(redirected?.lastErrorClass).toBe("webhook.redirect_refused");
		const tables = qualifiedDeliveryTables({ prefix });
		const persisted = JSON.stringify((await pool.query(
			`SELECT e.*, p.*, j.*, a.* FROM ${tables.event} e JOIN ${tables.payload} p ON p.event_id=e.id JOIN ${tables.job} j ON j.event_id=e.id JOIN ${tables.attempt} a ON a.job_id=j.id WHERE j.id = ANY($1::text[])`,
			[["job-webhook-delivered", "job-webhook-redirect"]],
		)).rows);
		for (const privateValue of [delivered.destination, delivered.signingSecret, "Updated Org", "Old Org"]) {
			expect(persisted).not.toContain(privateValue);
			expect(webhookLogs.join("\n")).not.toContain(privateValue);
		}
		await worker.stop();
	});

	it("delivers an atomically enqueued endpoint test with event-bound signing", async () => {
		webhooks.status = 204;
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const worker = new DeliveryWorker({
			...config,
			workerId: `webhook-test-${suffix}`,
		}, { pool: workerPool });
		await worker.initialize();
		const scope = { projectId: "project-endpoint-test", environmentId: "env-endpoint-test" };
		const destination = `http://127.0.0.1:${webhooks.port}/endpoint-test`;
		const created = await createWebhookEndpoint(pool, {
			...scope,
			id: "endpoint-test",
			name: "Endpoint test",
			url: destination,
			allowInsecureLoopback: true,
		}, keyring, { prefix });
		const client = await pool.connect();
		let enqueued: Awaited<ReturnType<typeof enqueueWebhookEndpointTestInExistingTransaction>>;
		try {
			await client.query("BEGIN");
			enqueued = await enqueueWebhookEndpointTestInExistingTransaction(
				rawTransaction(client),
				{
					...scope,
					endpointId: created.endpoint.id,
					expectedVersion: 1,
					actorId: "operator-endpoint-test",
					correlationId: "correlation-endpoint-test",
				},
				keyring,
				{ prefix },
			);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		expect(enqueued).toMatchObject({
			endpoint: { id: "endpoint-test", status: "disabled", resourceVersion: 2 },
			delivery: { kind: "webhook.endpoint.test", state: "queued" },
		});

		const before = webhooks.requests.length;
		expect(await worker.processOnce(1)).toBe(1);
		expect((await worker.store.inspectJob(enqueued!.delivery.jobId))?.state).toBe("delivered");
		expect(webhooks.requests).toHaveLength(before + 1);
		const request = webhooks.requests.at(-1)!;
		const body = JSON.parse(request.body.toString("utf8")) as {
			event: { id: string; type: string; data: { endpointId: string } };
		};
		expect(body.event).toMatchObject({
			id: enqueued!.delivery.eventId,
			type: "webhook.endpoint.test",
			data: { endpointId: "endpoint-test" },
		});
		expect(request.body.toString("utf8")).not.toContain(destination);
		expect(request.body.toString("utf8")).not.toContain(created.signingSecret);
		const timestamp = String(request.headers["webhook-timestamp"]);
		const signature = String(request.headers["webhook-signature"]);
		expect(request.headers["webhook-id"]).toBe(enqueued!.delivery.eventId);
		expect(request.headers["idempotency-key"]).toBe(enqueued!.delivery.jobId);
		expect(verifyWebhookSignature(
			created.signingSecret,
			enqueued!.delivery.eventId,
			timestamp,
			request.body,
			signature,
		)).toBe(true);
		await worker.stop();
	});

	it("migrates, reports ready, sends through SMTP, records status, and persists/logs no plaintext", async () => {
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const worker = new DeliveryWorker(config, { pool: workerPool, logger: { log(level, event, fields) { logs.push(JSON.stringify({ level, event, fields })); } } });
		await worker.initialize();
		expect((await worker.readiness()).ready).toBe(true);
		await worker.startHealthServer();
		expect((await fetch(`http://${config.healthHost}:${config.healthPort}/live`)).status).toBe(200);
		const readyResponse = await fetch(`http://${config.healthHost}:${config.healthPort}/ready`);
		expect(readyResponse.status).toBe(200);
		expect((await readyResponse.json() as { ready: boolean }).ready).toBe(true);
		const initialMetrics = await fetch(`http://${config.healthHost}:${config.healthPort}/metrics`);
		expect(initialMetrics.status).toBe(200);
		expect(initialMetrics.headers.get("content-type")).toBe("text/plain; version=0.0.4; charset=utf-8");
		expect(await initialMetrics.text()).toContain('clearance_delivery_jobs_claimed_total{channel="email"} 0');
		await enqueue("event-send", "job-send", "source-send");
		await enqueue("event-reset-template", "job-reset-template", "source-reset-template", {
			template: "password-reset", to: "person@example.test", userName: "Reset User",
			url: "https://app.example.test/reset?token=reset-secret",
		});
		await enqueue("event-invite-template", "job-invite-template", "source-invite-template", {
			template: "organization-invitation", to: "person@example.test", role: "admin",
			organizationName: "Example & Co", inviterName: "Owner <Admin>",
			acceptanceUrl: "https://app.example.test/accept?id=invite-1",
		});
		expect(await worker.processOnce()).toBe(3);
		expect(smtp.messages).toHaveLength(3);
		const metrics = await (await fetch(`http://${config.healthHost}:${config.healthPort}/metrics`)).text();
		expect(metrics).toContain('clearance_delivery_jobs_claimed_total{channel="email"} 3');
		expect(metrics).toContain('clearance_delivery_jobs_outcomes_total{channel="email",outcome="delivered"} 3');
		expect(metrics).not.toContain("job-send");
		expect(metrics).not.toContain("event-send");
		const renderedMessages = smtp.messages.join("\n");
		expect(renderedMessages).toContain("verification-secret");
		expect(renderedMessages).toContain("reset-secret");
		expect(renderedMessages).toContain("invite-1");
		const tables = qualifiedDeliveryTables({ prefix });
		const job = await worker.store.inspectJob("job-send");
		expect(job?.state).toBe("delivered");
		const persistedRows = (await pool.query(`SELECT e.*, p.*, j.*, a.* FROM ${tables.event} e JOIN ${tables.payload} p ON p.event_id=e.id JOIN ${tables.job} j ON j.event_id=e.id JOIN ${tables.attempt} a ON a.job_id=j.id`)).rows;
		const persisted = JSON.stringify(persistedRows);
		expect(persistedRows.some((row) => row.provider_status === "250" && /^[0-9a-f]{64}$/.test(row.provider_request_id))).toBe(true);
		expect(persisted).not.toContain("person@example.test");
		expect(persisted).not.toContain("verification-secret");
		expect(persisted).not.toContain("reset-secret");
		expect(persisted).not.toContain("invite-1");
		expect(logs.join("\n")).not.toContain("person@example.test");
		expect(logs.join("\n")).not.toContain("verification-secret");
		expect(logs.join("\n")).not.toContain("reset-secret");
		await worker.stop();
	});

	it("keeps readiness and heartbeat aligned with periodic SMTP verification", async () => {
		let smtpAvailable = false;
		const sender: EmailSender = {
			async verify() { if (!smtpAvailable) throw new Error("smtp unavailable"); },
			async send() { throw new Error("unused"); },
			close() {},
		};
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const worker = new DeliveryWorker({ ...config, workerId: `readiness-${suffix}` }, { pool: workerPool, sender });
		await worker.initialize({ verifySmtp: false });
		expect((await worker.readiness()).smtp).toBe(false);
		const tables = qualifiedDeliveryTables({ prefix });
		expect((await pool.query(`SELECT state FROM ${tables.worker} WHERE id=$1`, [worker.config.workerId])).rows[0].state).toBe("failed");
		const maintain = () => (worker as unknown as { maintenance(): Promise<void> }).maintenance();
		smtpAvailable = true;
		await maintain();
		expect((await worker.readiness()).ready).toBe(true);
		expect((await pool.query(`SELECT state FROM ${tables.worker} WHERE id=$1`, [worker.config.workerId])).rows[0].state).toBe("ready");
		smtpAvailable = false;
		await maintain();
		expect((await worker.readiness()).smtp).toBe(false);
		expect((await pool.query(`SELECT state FROM ${tables.worker} WHERE id=$1`, [worker.config.workerId])).rows[0].state).toBe("failed");
		await worker.stop();
	});

	it("fails readiness when an owned required table disappears after startup", async () => {
		const driftPrefix = `delivery_ready_${suffix}`;
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const worker = new DeliveryWorker({ ...config, prefix: driftPrefix, workerId: `schema-ready-${suffix}` }, { pool: workerPool, sender: {
			async verify() {}, async send() { throw new Error("unused"); }, close() {},
		} });
		await worker.initialize();
		expect((await worker.readiness()).ready).toBe(true);
		const names = deliveryTableNames({ prefix: driftPrefix });
		await pool.query(`DROP TABLE ${quoteIdentifier("public")}.${quoteIdentifier(names.job)} CASCADE`);
		const state = await worker.readiness();
		expect(state.database).toBe(true);
		expect(state.schema).toBe(false);
		expect(state.ready).toBe(false);
		await worker.stop();
		for (const name of [names.attempt, names.payload, names.event, names.webhookEndpoint, names.worker, names.meta]) {
			await pool.query(`DROP TABLE IF EXISTS ${quoteIdentifier("public")}.${quoteIdentifier(name)} CASCADE`);
		}
		await pool.query(`DROP FUNCTION IF EXISTS ${quoteIdentifier("public")}.${quoteIdentifier(names.rejectMutationFunction)}()`);
	});

	it("rechecks referenced fingerprint keys on every readiness probe", async () => {
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const worker = new DeliveryWorker({
			...config,
			workerId: `fingerprint-ready-${suffix}`,
		}, {
			pool: workerPool,
			sender: { async verify() {}, async send() { throw new Error("unused"); }, close() {} },
		});
		await worker.initialize();
		expect((await worker.readiness()).ready).toBe(true);
		const producerKeyring = createDeliveryKeyring({
			currentKeyId: keyring.currentKeyId,
			keys: Object.fromEntries(keyring.keys),
			currentFingerprintKeyId: "fingerprint-next",
			fingerprintKeys: {
				...Object.fromEntries(keyring.fingerprintKeys),
				"fingerprint-next": randomBytes(32),
			},
			sourceDedupeKey: keyring.sourceDedupeKey,
		});
		await enqueue(
			"event-fingerprint-next",
			"job-fingerprint-next",
			"source-fingerprint-next",
			undefined,
			producerKeyring,
		);
		const missing = await worker.readiness();
		expect(missing.schema).toBe(true);
		expect(missing.keyring).toBe(false);
		expect(missing.ready).toBe(false);
		const terminalAt = new Date();
		await worker.store.cancel("job-fingerprint-next", terminalAt);
		expect((await worker.readiness()).keyring).toBe(false);
		expect(await worker.store.eraseTerminalPayloads({
			terminalBefore: terminalAt,
			now: terminalAt,
		})).toBeGreaterThanOrEqual(1);
		const recovered = await worker.readiness();
		expect(recovered.keyring).toBe(true);
		expect(recovered.ready).toBe(true);
		await worker.stop();
	});

	it("retries transient provider failure and fences stale lease ownership", async () => {
		let sends = 0;
		const sender: EmailSender = {
			async verify() {}, close() {},
			async send() { sends++; throw Object.assign(new Error("provider detail must stay private"), { responseCode: 421 }); },
		};
		const worker = new DeliveryWorker({ ...config, workerId: `retry-${suffix}` }, { pool, sender });
		await worker.initialize();
		await enqueue("event-retry", "job-retry", "source-retry", templatePayload("retry-secret"));
		expect(await worker.processOnce(1)).toBe(1);
		expect(sends).toBe(1);
		expect((await worker.store.inspectJob("job-retry"))?.state).toBe("retry");
		const lease = await worker.store.claimNext({ workerId: "fence-owner", now: new Date(Date.now() + 10_000) });
		expect(lease?.id).toBe("job-retry");
		await expect(worker.store.renewLease({ jobId: lease!.id, leaseToken: "wrong", workerId: lease!.leaseOwner, leaseMs: 5_000 })).rejects.toMatchObject({ code: "DELIVERY_STALE_LEASE" });
		await worker.store.dead({ jobId: lease!.id, leaseToken: lease!.leaseToken, workerId: lease!.leaseOwner, errorClass: "test.cleanup" });
	});

	it("completes one accepted send when lease renewal degrades", async () => {
		let sends = 0;
		const renewalLogs: string[] = [];
		const sender: EmailSender = {
			async verify() {}, close() {},
			async send() {
				sends++;
				await new Promise((resolve) => setTimeout(resolve, 1_750));
				return { status: "250", requestId: "fixture-accepted" };
			},
		};
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const worker = new DeliveryWorker({ ...config, workerId: `renewal-degraded-${suffix}` }, {
			pool: workerPool,
			sender,
			logger: { log(_level, event) { renewalLogs.push(event); } },
		});
		await worker.initialize();
		worker.store.renewLease = async () => { throw new Error("renewal unavailable"); };
		await enqueue("event-renewal-degraded", "job-renewal-degraded", "source-renewal-degraded", templatePayload("accepted-secret"));
		expect(await worker.processOnce(1)).toBe(1);
		expect(sends).toBe(1);
		expect((await worker.store.inspectJob("job-renewal-degraded"))?.state).toBe("delivered");
		expect(renewalLogs).toContain("delivery.lease_renewal_degraded");
		expect(renewalLogs).toContain("delivery.delivered");
		await worker.stop();
	});

	it("does not schedule a retry when provider acceptance races a stale completion fence", async () => {
		let sends = 0;
		let retries = 0;
		const events: string[] = [];
		const sender: EmailSender = {
			async verify() {}, close() {},
			async send() { sends++; return { status: "250", requestId: "fixture-ambiguous" }; },
		};
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const worker = new DeliveryWorker({ ...config, workerId: `accepted-stale-${suffix}` }, {
			pool: workerPool,
			sender,
			logger: { log(_level, event) { events.push(event); } },
		});
		await worker.initialize();
		await enqueue("event-accepted-stale", "job-accepted-stale", "source-accepted-stale", templatePayload("accepted-stale-secret"));
		worker.store.complete = async () => { throw new Error("database partition after acceptance marker"); };
		const retry = worker.store.retry.bind(worker.store);
		worker.store.retry = async (input) => { retries++; return retry(input); };
		expect(await worker.processOnce(1)).toBe(1);
		expect(sends).toBe(1);
		expect(retries).toBe(0);
		expect(events).toContain("delivery.provider_accepted_unconfirmed");
		expect((await worker.store.inspectJob("job-accepted-stale"))?.state).toBe("leased");
		expect(await worker.store.reclaimExpired(new Date(Date.now() + 6_000))).toBe(1);
		expect((await worker.store.inspectJob("job-accepted-stale"))?.state).toBe("dead");
		expect((await worker.store.inspectJob("job-accepted-stale"))?.lastErrorClass).toBe("provider_accepted_unconfirmed");
		await worker.stop();
	});

	it("dead-letters a recipient that differs from the audited destination", async () => {
		const worker = new DeliveryWorker({ ...config, workerId: `recipient-${suffix}` }, { pool });
		await worker.initialize();
		await enqueue("event-recipient", "job-recipient", "source-recipient", {
			template: "password-reset", to: "other@example.test", userName: "Other",
			url: "https://app.example.test/reset?token=recipient-secret",
		});
		expect(await worker.processOnce(1)).toBe(1);
		const job = await worker.store.inspectJob("job-recipient");
		expect(job?.state).toBe("dead");
		expect(job?.lastErrorClass).toBe("delivery.destination_mismatch");
	});

	it("drains in-flight work before shutdown", async () => {
		let release!: () => void;
		let started!: () => void;
		const didStart = new Promise<void>((resolve) => { started = resolve; });
		const sender: EmailSender = {
			async verify() {}, close() {},
			async send() { started(); await new Promise<void>((resolve) => { release = resolve; }); return { status: "250", requestId: "fixture-drain" }; },
		};
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const worker = new DeliveryWorker({ ...config, workerId: `drain-${suffix}` }, { pool: workerPool, sender });
		await worker.initialize();
		let renewals = 0;
		const renewLease = worker.store.renewLease.bind(worker.store);
		worker.store.renewLease = async (input) => { renewals++; return renewLease(input); };
		await enqueue("event-drain", "job-drain", "source-drain", templatePayload("drain-secret"));
		const processing = worker.processOnce(1);
		await didStart;
		let drained = false;
		const draining = worker.drain().then(() => { drained = true; });
		await new Promise((resolve) => setTimeout(resolve, 1_750));
		expect(drained).toBe(false);
		expect(renewals).toBeGreaterThan(0);
		release();
		await processing;
		await draining;
		expect((await worker.readiness()).ready).toBe(false);
		await worker.stop();
		expect((await pool.query(`SELECT state FROM ${qualifiedDeliveryTables({ prefix }).job} WHERE id='job-drain'`)).rows[0].state).toBe("delivered");
	});

	it("closes resources even when graceful drain times out", async () => {
		let release!: () => void;
		let started!: () => void;
		let stopped!: () => void;
		let senderClosed = false;
		const didStart = new Promise<void>((resolve) => { started = resolve; });
		const didStop = new Promise<void>((resolve) => { stopped = resolve; });
		const unhandledRejections: unknown[] = [];
		const captureUnhandledRejection = (reason: unknown) => { unhandledRejections.push(reason); };
		const sender: EmailSender = {
			async verify() {},
			async send() { started(); await new Promise<void>((resolve) => { release = resolve; }); return { status: "250" }; },
			close() { senderClosed = true; release(); },
		};
		const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
		const healthPort = await unusedPort();
		const worker = new DeliveryWorker({
			...config, workerId: `drain-timeout-${suffix}`, drainTimeoutMs: 25, healthPort,
		}, {
			pool: workerPool,
			sender,
			logger: { log(_level, event) { if (event === "worker.stopped") stopped(); } },
		});
		process.on("unhandledRejection", captureUnhandledRejection);
		try {
			await worker.initialize();
			await worker.startHealthServer();
			await enqueue("event-drain-timeout", "job-drain-timeout", "source-drain-timeout", templatePayload("drain-timeout-secret"));
			const processing = worker.processOnce(1);
			await didStart;
			await expect(worker.stop()).rejects.toBeInstanceOf(DeliveryDrainTimeoutError);
			expect(senderClosed).toBe(true);
			await processing;
			await didStop;
			const verifier = new DeliveryStore(pool, { schema: "public", prefix });
			expect((await verifier.inspectJob("job-drain-timeout"))?.state).toBe("delivered");
			expect(await verifier.reclaimExpired(new Date(Date.now() + 10_000))).toBe(0);
			expect(await verifier.claimNext({
				workerId: `timeout-reclaim-proof-${suffix}`,
				now: new Date(Date.now() + 10_000),
			})).toBeNull();
			await expect(fetch(`http://127.0.0.1:${healthPort}/live`)).rejects.toThrow();
			await expect(workerPool.query("SELECT 1")).rejects.toThrow();
			await new Promise<void>((resolve) => setImmediate(resolve));
			expect(unhandledRejections).toEqual([]);
		} finally {
			process.off("unhandledRejection", captureUnhandledRejection);
		}
	});
});
