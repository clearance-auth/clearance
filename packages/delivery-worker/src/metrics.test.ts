import { describe, expect, it } from "vitest";
import { DeliveryWorkerMetrics } from "./metrics.js";

describe("delivery worker metrics", () => {
	it("renders bounded low-cardinality Prometheus metrics without delivery identifiers", () => {
		const metrics = new DeliveryWorkerMetrics();
		metrics.recordClaim("email");
		metrics.recordClaim("tenant-controlled-channel");
		metrics.recordOutcome("email", "delivered", 250);
		metrics.recordOutcome("tenant-controlled-channel", "dead", 500);
		const rendered = metrics.render({
			inFlight: 2,
			draining: false,
			schemaHealthy: true,
			emailHealthy: true,
			emailTransport: "ses",
		});

		expect(rendered).toContain('clearance_delivery_jobs_claimed_total{channel="email"} 1');
		expect(rendered).toContain('clearance_delivery_jobs_claimed_total{channel="unknown"} 1');
		expect(rendered).toContain('clearance_delivery_jobs_outcomes_total{channel="email",outcome="delivered"} 1');
		expect(rendered).toContain('clearance_delivery_email_transport_healthy{transport="ses"} 1');
		expect(rendered).toContain("clearance_delivery_jobs_in_flight 2");
		expect(rendered).not.toContain("tenant-controlled-channel");
		expect(rendered).not.toContain("job-stable-1");
		expect(rendered).not.toContain("event-1");
		expect(rendered).not.toContain("project-1");
	});
});
