export type DeliveryMetricChannel = "email" | "webhook" | "unknown";
export type DeliveryMetricOutcome =
	| "delivered"
	| "retry"
	| "dead"
	| "cancelled"
	| "stale_lease"
	| "accepted_unconfirmed"
	| "finish_failed";

const CHANNELS: readonly DeliveryMetricChannel[] = ["email", "webhook", "unknown"];
const OUTCOMES: readonly DeliveryMetricOutcome[] = [
	"delivered",
	"retry",
	"dead",
	"cancelled",
	"stale_lease",
	"accepted_unconfirmed",
	"finish_failed",
];

function channel(value: string): DeliveryMetricChannel {
	return value === "email" || value === "webhook" ? value : "unknown";
}

/** Low-cardinality, process-local Prometheus metrics for one worker replica. */
export class DeliveryWorkerMetrics {
	private readonly startedAt = Date.now();
	private readonly claimed = new Map<DeliveryMetricChannel, number>();
	private readonly outcomes = new Map<string, number>();
	private durationCount = 0;
	private durationSeconds = 0;

	recordClaim(rawChannel: string): void {
		const normalized = channel(rawChannel);
		this.claimed.set(normalized, (this.claimed.get(normalized) ?? 0) + 1);
	}

	recordOutcome(
		rawChannel: string,
		outcome: DeliveryMetricOutcome,
		durationMs: number,
	): void {
		const normalized = channel(rawChannel);
		const key = `${normalized}|${outcome}`;
		this.outcomes.set(key, (this.outcomes.get(key) ?? 0) + 1);
		this.durationCount += 1;
		this.durationSeconds += Math.max(0, durationMs) / 1_000;
	}

	render(input: {
		inFlight: number;
		draining: boolean;
		schemaHealthy: boolean;
		emailHealthy: boolean;
		emailTransport: "smtp" | "ses";
	}): string {
		const lines = [
			"# HELP clearance_delivery_jobs_claimed_total Delivery jobs claimed by this worker.",
			"# TYPE clearance_delivery_jobs_claimed_total counter",
		];
		for (const value of CHANNELS) {
			lines.push(`clearance_delivery_jobs_claimed_total{channel="${value}"} ${this.claimed.get(value) ?? 0}`);
		}
		lines.push(
			"# HELP clearance_delivery_jobs_outcomes_total Terminal or retry outcomes recorded by this worker.",
			"# TYPE clearance_delivery_jobs_outcomes_total counter",
		);
		for (const channelValue of CHANNELS) {
			for (const outcome of OUTCOMES) {
				lines.push(
					`clearance_delivery_jobs_outcomes_total{channel="${channelValue}",outcome="${outcome}"} ${this.outcomes.get(`${channelValue}|${outcome}`) ?? 0}`,
				);
			}
		}
		lines.push(
			"# HELP clearance_delivery_job_duration_seconds_sum Cumulative claimed-job processing time.",
			"# TYPE clearance_delivery_job_duration_seconds_sum counter",
			`clearance_delivery_job_duration_seconds_sum ${this.durationSeconds}`,
			"# HELP clearance_delivery_job_duration_seconds_count Claimed jobs with a recorded outcome.",
			"# TYPE clearance_delivery_job_duration_seconds_count counter",
			`clearance_delivery_job_duration_seconds_count ${this.durationCount}`,
			"# HELP clearance_delivery_jobs_in_flight Jobs currently processed by this worker.",
			"# TYPE clearance_delivery_jobs_in_flight gauge",
			`clearance_delivery_jobs_in_flight ${input.inFlight}`,
			"# HELP clearance_delivery_worker_draining Whether graceful drain is active.",
			"# TYPE clearance_delivery_worker_draining gauge",
			`clearance_delivery_worker_draining ${input.draining ? 1 : 0}`,
			"# HELP clearance_delivery_schema_healthy Whether the owned delivery schema is current.",
			"# TYPE clearance_delivery_schema_healthy gauge",
			`clearance_delivery_schema_healthy ${input.schemaHealthy ? 1 : 0}`,
			"# HELP clearance_delivery_email_transport_healthy Whether the configured email transport is healthy.",
			"# TYPE clearance_delivery_email_transport_healthy gauge",
			`clearance_delivery_email_transport_healthy{transport="${input.emailTransport}"} ${input.emailHealthy ? 1 : 0}`,
			"# HELP clearance_delivery_worker_uptime_seconds Worker process uptime.",
			"# TYPE clearance_delivery_worker_uptime_seconds gauge",
			`clearance_delivery_worker_uptime_seconds ${Math.max(0, Date.now() - this.startedAt) / 1_000}`,
			"",
		);
		return lines.join("\n");
	}
}
