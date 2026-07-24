import http, { type Server } from "node:http";
import pg from "pg";
import { DELIVERY_SCHEMA_VERSION, DeliveryStore, qualifiedDeliveryTables, StaleDeliveryLeaseError } from "@clearance/delivery";
import {
	startObservability,
	type ObservabilityHandle,
} from "@clearance/observability-node";
import type { WorkerConfig } from "./config.js";
import { classifyEmailError, configuredEmailTransport, createEmailSender } from "./email.js";
import { createJsonLogger, type WorkerLogger } from "./logger.js";
import { DeliveryWorkerMetrics, type DeliveryMetricOutcome } from "./metrics.js";
import { renderEmailPayload, type EmailSender } from "./smtp.js";
import {
	classifyWebhookError,
	createWebhookSender,
	webhookDestination,
	type WebhookSender,
} from "./webhook.js";

const VERSION = "0.2.1";
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

class ProviderAcceptedUnconfirmedError extends Error {
	constructor(readonly cause: unknown) {
		super("Provider accepted the delivery but durable completion was not confirmed");
		this.name = "ProviderAcceptedUnconfirmedError";
	}
}

export class DeliveryDrainTimeoutError extends Error {
	constructor(readonly inFlight: number) {
		super(`Delivery worker drain timed out with ${inFlight} job(s) still in flight`);
		this.name = "DeliveryDrainTimeoutError";
	}
}

class DeliveryStopTimeoutError extends Error {
	constructor() {
		super("Delivery worker shutdown timed out");
		this.name = "DeliveryStopTimeoutError";
	}
}

function settleBeforeDeadline<T>(
	operation: () => T | Promise<T>,
	deadline: number,
): Promise<T> {
	const pending = Promise.resolve().then(operation);
	// The deadline race owns the outcome; retain the late rejection so a hung
	// cleanup stage cannot produce an unhandled rejection after shutdown ends.
	void pending.catch(() => undefined);
	return new Promise<T>((resolve, reject) => {
		let settled = false;
		const timeout = setTimeout(() => {
			if (settled) return;
			settled = true;
			reject(new DeliveryStopTimeoutError());
		}, Math.max(0, deadline - Date.now()));
		pending.then(
			(value) => {
				if (settled) return;
				settled = true;
				clearTimeout(timeout);
				resolve(value);
			},
			(error: unknown) => {
				if (settled) return;
				settled = true;
				clearTimeout(timeout);
				reject(error);
			},
		);
	});
}

export type WorkerReadiness = {
	ready: boolean;
	draining: boolean;
	database: boolean;
	schema: boolean;
	keyring: boolean;
	audit: boolean;
	heartbeat: boolean;
	email: boolean;
	emailTransport: "smtp" | "ses";
	smtp: boolean;
	ses: boolean;
	workerId: string;
};

export class DeliveryWorker {
	readonly pool: pg.Pool;
	readonly store: DeliveryStore;
	readonly config: WorkerConfig;
	private readonly sender: EmailSender;
	private readonly webhookSender: WebhookSender;
	private readonly logger: WorkerLogger;
	private stopping = false;
	private stopped = false;
	private draining = false;
	private initialized = false;
	private schemaHealthy = false;
	private emailHealthy = false;
	private lastHeartbeatAt = 0;
	private inFlight = new Set<Promise<unknown>>();
	private healthServer?: Server;
	private readonly metrics = new DeliveryWorkerMetrics();
	private heartbeatTimer?: NodeJS.Timeout;
	private maintenanceTimer?: NodeJS.Timeout;
	private maintenanceRunning = false;
	private observability?: ObservabilityHandle;
	private stopPromise?: Promise<void>;

	constructor(config: WorkerConfig, dependencies: {
		pool?: pg.Pool;
		sender?: EmailSender;
		webhookSender?: WebhookSender;
		logger?: WorkerLogger;
	} = {}) {
		this.config = config;
		this.pool = dependencies.pool ?? new pg.Pool({
			connectionString: config.databaseUrl,
			max: Math.max(4, config.concurrency + 2),
			connectionTimeoutMillis: config.smtp?.connectionTimeoutMs ?? config.ses?.requestTimeoutMs ?? 10_000,
			application_name: `clearance-delivery:${config.workerId}`,
		});
		this.store = new DeliveryStore(this.pool, {
			schema: config.schema,
			prefix: config.prefix,
			legacyFingerprintKeyId: config.legacyFingerprintKeyId,
			...(config.runtimeAudit ? { runtimeAudit: config.runtimeAudit } : {}),
		});
		this.sender = dependencies.sender ?? createEmailSender(config);
		this.webhookSender = dependencies.webhookSender ?? createWebhookSender(config);
		this.logger = dependencies.logger ?? createJsonLogger();
	}

	async initialize(options: { verifyEmail?: boolean; verifySmtp?: boolean } = {}): Promise<void> {
		this.observability = await startObservability();
		await this.store.heartbeat({ workerId: this.config.workerId, version: VERSION, state: "starting" }).catch(() => undefined);
		const result = await this.store.migrate();
		await this.store.assertRuntimeAuditTableReady();
		await this.store.assertFingerprintKeysAvailable(this.config.keyring);
		this.schemaHealthy = result.version === DELIVERY_SCHEMA_VERSION;
		const shouldVerifyEmail = options.verifyEmail ?? options.verifySmtp ?? true;
		if (shouldVerifyEmail) {
			try {
				await this.sender.verify();
				this.emailHealthy = true;
			} catch (error) {
				this.emailHealthy = false;
				await this.writeHeartbeat("failed").catch(() => undefined);
				throw error;
			}
		} else {
			this.emailHealthy = false;
		}
		await this.writeHeartbeat(this.emailHealthy ? "ready" : "failed");
		this.initialized = true;
		const transport = configuredEmailTransport(this.config);
		this.logger.log(this.emailHealthy ? "info" : "warn", this.emailHealthy ? "worker.ready" : `worker.${transport}_unverified`, {
			workerId: this.config.workerId,
			schemaVersion: result.version,
			emailTransport: transport,
		});
	}

	private async writeHeartbeat(state: "ready" | "draining" | "stopped" | "failed"): Promise<void> {
		await this.store.heartbeat({ workerId: this.config.workerId, version: VERSION, state });
		this.lastHeartbeatAt = Date.now();
	}

	async readiness(): Promise<WorkerReadiness> {
		const transport = configuredEmailTransport(this.config);
		let database = false;
		let keyring = false;
		let audit = !this.config.runtimeAudit;
		try { await this.pool.query("SELECT 1"); database = true; } catch { database = false; }
		if (database) {
			try {
				const tables = qualifiedDeliveryTables(this.store.options);
				const expectedTableNames = Object.values(tables.names).filter(
					(name) => name !== tables.names.rejectMutationFunction,
				);
				const result = await this.pool.query<{ version: unknown; table_count: number; function_count: number }>(
					`SELECT
					 (SELECT value FROM ${tables.meta} WHERE key='schema_version') version,
					 (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
					  WHERE n.nspname=$1 AND c.relname=ANY($2::text[]) AND c.relkind IN ('r','p')) table_count,
					 (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
					  WHERE n.nspname=$1 AND p.proname=$3) function_count`,
					[tables.schema, expectedTableNames, tables.names.rejectMutationFunction],
				);
				const row = result.rows[0];
				this.schemaHealthy = Number(row?.version) === DELIVERY_SCHEMA_VERSION &&
					row?.table_count === expectedTableNames.length && row?.function_count === 1;
			} catch { this.schemaHealthy = false; }
			if (this.schemaHealthy) {
				try {
					await this.store.assertFingerprintKeysAvailable(this.config.keyring);
					keyring = true;
				} catch {
					keyring = false;
				}
			}
			if (this.schemaHealthy && this.config.runtimeAudit) {
				try {
					await this.store.assertRuntimeAuditTableReady();
					audit = true;
				} catch {
					audit = false;
				}
			}
		} else {
			this.schemaHealthy = false;
		}
		const heartbeat = this.lastHeartbeatAt > 0 && Date.now() - this.lastHeartbeatAt <= this.config.heartbeatMs * 3;
		return {
			ready: this.initialized && !this.draining && database && this.schemaHealthy && keyring && audit && heartbeat && this.emailHealthy,
			draining: this.draining,
			database,
			schema: this.schemaHealthy,
			keyring,
			audit,
			heartbeat,
			email: this.emailHealthy,
			emailTransport: transport,
			smtp: transport === "smtp" && this.emailHealthy,
			ses: transport === "ses" && this.emailHealthy,
			workerId: this.config.workerId,
		};
	}

	private async processJob(): Promise<boolean> {
		if (this.draining || this.stopping) return false;
		const processed = await this.store.claimNextWithTrace(
			{ workerId: this.config.workerId, leaseMs: this.config.leaseMs },
			async (leased) => {
				const claimedAt = performance.now();
				let metricOutcome: DeliveryMetricOutcome = "finish_failed";
				this.metrics.recordClaim(leased.channel);
				this.logger.log("info", "delivery.claimed", { jobId: leased.id, eventId: leased.eventId, kind: leased.kind, attempt: leased.attemptCount });
				try {
					if (leased.channel !== "email" && leased.channel !== "webhook") {
						await this.store.dead({ jobId: leased.id, leaseToken: leased.leaseToken, workerId: this.config.workerId, errorClass: "transport.unsupported" });
						metricOutcome = "dead";
						return true;
					}
					const payload = await this.store.readLeasedPayload<unknown>({ jobId: leased.id, leaseToken: leased.leaseToken, keyring: this.config.keyring });
					const email = leased.channel === "email"
						? renderEmailPayload(payload, this.config)
						: undefined;
					const destination = email?.to ??
						webhookDestination(payload);
					await this.store.assertLeasedDestination({
						jobId: leased.id,
						leaseToken: leased.leaseToken,
						destination,
						keyring: this.config.keyring,
					});
					const result = await this.sendWithLeaseRenewal(
						leased,
						email
							? () => this.sender.send(email, {
									jobId: leased.id,
									eventId: leased.eventId,
								})
							: () => this.webhookSender.send(payload, {
									jobId: leased.id,
									eventId: leased.eventId,
								}),
					);
					if (leased.channel === "email") this.emailHealthy = true;
					try {
						await this.store.markProviderAccepted({
							jobId: leased.id,
							leaseToken: leased.leaseToken,
							workerId: this.config.workerId,
							providerStatus: result.status,
							providerRequestId: result.requestId,
						});
						await this.store.complete({ jobId: leased.id, leaseToken: leased.leaseToken, workerId: this.config.workerId, providerStatus: result.status, providerRequestId: result.requestId });
					} catch (error) {
						throw new ProviderAcceptedUnconfirmedError(error);
					}
					this.logger.log("info", "delivery.delivered", { jobId: leased.id, eventId: leased.eventId, providerStatus: result.status });
					metricOutcome = "delivered";
				} catch (error) {
					if (error instanceof ProviderAcceptedUnconfirmedError) {
						metricOutcome = "accepted_unconfirmed";
						this.logger.log("error", "delivery.provider_accepted_unconfirmed", {
							jobId: leased.id,
							eventId: leased.eventId,
							error: error.cause,
						});
						return true;
					}
					if (error instanceof StaleDeliveryLeaseError) {
						metricOutcome = "stale_lease";
						this.logger.log("warn", "delivery.stale_lease", { jobId: leased.id, eventId: leased.eventId });
						return true;
					}
					const classified = leased.channel === "webhook"
						? classifyWebhookError(error)
						: classifyEmailError(this.config, error);
					if (leased.channel === "email" && /^(?:smtp|ses)\.(?:transport|timeout)$/.test(classified.errorClass)) {
						this.emailHealthy = false;
					}
					try {
						const result = classified.retryable
							? await this.store.retry({ jobId: leased.id, leaseToken: leased.leaseToken, workerId: this.config.workerId, errorClass: classified.errorClass, providerStatus: classified.providerStatus })
							: await this.store.dead({ jobId: leased.id, leaseToken: leased.leaseToken, workerId: this.config.workerId, errorClass: classified.errorClass, providerStatus: classified.providerStatus });
						this.logger.log(classified.retryable ? "warn" : "error", `delivery.${result.state}`, { jobId: leased.id, eventId: leased.eventId, errorClass: classified.errorClass, providerStatus: classified.providerStatus });
						metricOutcome = result.state === "retry" ? "retry"
							: result.state === "cancelled" ? "cancelled"
							: "dead";
					} catch (finishError) {
						this.logger.log("error", "delivery.finish_failed", { jobId: leased.id, error: finishError });
					}
				} finally {
					this.metrics.recordOutcome(leased.channel, metricOutcome, performance.now() - claimedAt);
				}
				return true;
			},
		);
		return processed ?? false;
	}

	private async sendWithLeaseRenewal(
		leased: { id: string; eventId: string; leaseToken: string },
		send: () => Promise<Awaited<ReturnType<EmailSender["send"]>>>,
	): Promise<Awaited<ReturnType<EmailSender["send"]>>> {
		let stopped = false;
		let renewalFailure: unknown;
		let pending = Promise.resolve();
		const intervalMs = Math.max(1_000, Math.floor(this.config.leaseMs / 3));
		const timer = setInterval(() => {
			pending = pending.then(async () => {
				if (stopped || renewalFailure) return;
				try {
					await this.store.renewLease({
						jobId: leased.id,
						leaseToken: leased.leaseToken,
						workerId: this.config.workerId,
						leaseMs: this.config.leaseMs,
					});
				} catch (error) { renewalFailure = error; }
			});
		}, intervalMs);
		try {
			const result = await send();
			stopped = true;
			clearInterval(timer);
			await pending;
			if (renewalFailure) {
				// Preserve the provider-accepted outcome. The following fenced
				// completion determines whether this worker still owns the lease.
				this.logger.log("warn", "delivery.lease_renewal_degraded", {
					jobId: leased.id,
					error: renewalFailure,
				});
			}
			return result;
		} catch (error) {
			stopped = true;
			clearInterval(timer);
			await pending;
			throw renewalFailure ?? error;
		}
	}

	async processOnce(limit = this.config.processOnceLimit): Promise<number> {
		if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new Error("processOnce limit must be between 1 and 10000");
		let processed = 0;
		while (processed < limit && !this.draining) {
			const batch = Math.min(this.config.concurrency, limit - processed);
			const tasks = Array.from({ length: batch }, () => this.track(this.processJob()));
			const results = await Promise.all(tasks);
			const count = results.filter(Boolean).length;
			processed += count;
			if (count === 0) break;
		}
		return processed;
	}

	private track<T>(promise: Promise<T>): Promise<T> {
		const tracked = promise.finally(() => this.inFlight.delete(tracked));
		this.inFlight.add(tracked);
		return tracked;
	}

	private async maintenance(): Promise<void> {
		if (this.maintenanceRunning) return;
		this.maintenanceRunning = true;
		try {
			const reclaimed = await this.store.reclaimExpired();
			const expired = await this.store.expireAndEraseUndeliverable();
			if (reclaimed || expired.deadJobs || expired.erasedPayloads) this.logger.log("info", "worker.maintenance", { reclaimed, ...expired });
		} catch (error) {
			this.schemaHealthy = false;
			this.logger.log("error", "worker.maintenance_failed", { error });
		}
		const wasHealthy = this.emailHealthy;
		const transport = configuredEmailTransport(this.config);
		try {
			await this.sender.verify();
			this.emailHealthy = true;
			if (!wasHealthy) this.logger.log("info", `worker.${transport}_recovered`);
		} catch (error) {
			this.emailHealthy = false;
			this.logger.log(wasHealthy ? "error" : "warn", `worker.${transport}_unavailable`, { error });
		}
		await this.writeHeartbeat(
			this.draining
				? "draining"
				: this.emailHealthy && this.schemaHealthy
					? "ready"
					: "failed",
		)
			.catch((error) => this.logger.log("error", "worker.heartbeat_failed", { error }));
		this.maintenanceRunning = false;
	}

	private startTimers(): void {
		this.heartbeatTimer = setInterval(() => {
			void this.writeHeartbeat(
				this.draining
					? "draining"
					: this.emailHealthy && this.schemaHealthy
						? "ready"
						: "failed",
			)
				.catch((error) => this.logger.log("error", "worker.heartbeat_failed", { error }));
		}, this.config.heartbeatMs);
		this.heartbeatTimer.unref();
		this.maintenanceTimer = setInterval(() => void this.maintenance(), this.config.maintenanceMs);
		this.maintenanceTimer.unref();
	}

	async startHealthServer(): Promise<void> {
		if (this.healthServer) return;
		this.healthServer = http.createServer(async (request, response) => {
			response.setHeader("cache-control", "no-store");
			if (request.method !== "GET") { response.setHeader("content-type", "application/json"); response.statusCode = 405; response.end('{"error":"method_not_allowed"}'); return; }
			if (request.url === "/live") { response.setHeader("content-type", "application/json"); response.statusCode = this.stopping ? 503 : 200; response.end(JSON.stringify({ live: !this.stopping })); return; }
			if (request.url === "/ready") { response.setHeader("content-type", "application/json"); const state = await this.readiness(); response.statusCode = state.ready ? 200 : 503; response.end(JSON.stringify(state)); return; }
			if (request.url === "/metrics") {
				response.setHeader("content-type", "text/plain; version=0.0.4; charset=utf-8");
				response.statusCode = 200;
				response.end(this.metrics.render({
					inFlight: this.inFlight.size,
					draining: this.draining,
					schemaHealthy: this.schemaHealthy,
					emailHealthy: this.emailHealthy,
					emailTransport: configuredEmailTransport(this.config),
				}));
				return;
			}
			response.setHeader("content-type", "application/json");
			response.statusCode = 404; response.end('{"error":"not_found"}');
		});
		await new Promise<void>((resolve, reject) => { this.healthServer!.once("error", reject); this.healthServer!.listen(this.config.healthPort, this.config.healthHost, resolve); });
	}

	async run(): Promise<void> {
		await this.initialize();
		await this.startHealthServer();
		this.startTimers();
		while (!this.stopping) {
			if (this.draining) { await sleep(25); continue; }
			while (this.inFlight.size < this.config.concurrency && !this.draining) {
				this.track(this.processJob().then(async (worked) => { if (!worked) await sleep(this.config.pollMs); }));
			}
			await Promise.race(this.inFlight);
		}
	}

	async drain(deadline = Date.now() + this.config.drainTimeoutMs): Promise<void> {
		if (!this.draining) {
			this.draining = true;
			this.logger.log("info", "worker.draining", { workerId: this.config.workerId, inFlight: this.inFlight.size });
			await this.writeHeartbeat("draining").catch(() => undefined);
		}
		while (this.inFlight.size && Date.now() < deadline) await Promise.race([Promise.allSettled([...this.inFlight]), sleep(25)]);
		if (this.inFlight.size) {
			this.logger.log("error", "worker.drain_timeout", { inFlight: this.inFlight.size });
			throw new DeliveryDrainTimeoutError(this.inFlight.size);
		}
	}

	async stop(): Promise<void> {
		if (this.stopped) return;
		if (this.stopPromise) return this.stopPromise;
		this.stopPromise = this.stopWithinDeadline();
		return this.stopPromise;
	}

	private async stopWithinDeadline(): Promise<void> {
		const deadline = Date.now() + this.config.drainTimeoutMs;
		let firstError: unknown;
		const recordError = (error: unknown) => {
			firstError ??= error;
		};
		const runCleanup = async (operation: () => unknown | Promise<unknown>) => {
			try {
				await settleBeforeDeadline(operation, deadline);
			} catch (error) {
				recordError(error);
			}
		};
		try {
			await settleBeforeDeadline(() => this.drain(deadline), deadline);
		} catch (error) {
			recordError(error);
		}
		this.stopping = true;
		if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
		if (this.maintenanceTimer) clearInterval(this.maintenanceTimer);
		await runCleanup(() => this.writeHeartbeat("stopped"));
		try {
			if (this.healthServer) {
				await runCleanup(
					() => new Promise<void>((resolve) => this.healthServer!.close(() => resolve())),
				);
			}
			await runCleanup(() => this.sender.close());
			await runCleanup(() => this.pool.end());
		} finally {
			await runCleanup(() => this.observability?.shutdown());
		}
		this.stopped = true;
		this.logger.log("info", "worker.stopped", { workerId: this.config.workerId });
		if (firstError) throw firstError;
	}
}
