import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { HttpInstrumentation } from "@opentelemetry/instrumentation-http";
import { PgInstrumentation } from "@opentelemetry/instrumentation-pg";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { NodeSDK, tracing } from "@opentelemetry/sdk-node";
import type { EnabledObservabilityConfig } from "./config";
import { inboundOnlyTraceContextPropagator } from "./propagation";
import { RedactingSpanExporter } from "./redaction";

export interface RunningObservabilityRuntime {
	shutdown(): Promise<void>;
	hasExporterError(): boolean;
}

function samplerFor(config: EnabledObservabilityConfig): tracing.Sampler {
	if (config.sampler.name === "always_off") return new tracing.AlwaysOffSampler();
	const ratio = config.sampler.ratio;
	if (ratio === undefined) throw new Error("Ratio sampler is missing its ratio");
	const sampler = new tracing.TraceIdRatioBasedSampler(ratio);
	return config.sampler.name === "parentbased_traceidratio"
		? new tracing.ParentBasedSampler({ root: sampler })
		: sampler;
}

/**
 * This module is loaded only after explicit configuration has enabled tracing.
 * Instrumentation-level header capture and enhanced pg reporting are disabled.
 * The exporter wrapper provides the stronger authority boundary: only its
 * allowlisted representation can reach OTLP serialization.
 */
export async function createObservabilityRuntime(
	config: EnabledObservabilityConfig,
): Promise<RunningObservabilityRuntime> {
	let exporterErrored = false;
	const resource = resourceFromAttributes({ "service.name": config.serviceName });
	const exporter = new RedactingSpanExporter(
		new OTLPTraceExporter({
			url: config.exporter.endpoint.toString(),
			headers: config.exporter.headers,
		}),
		resource,
		(result) => {
			if (result.code !== 0) exporterErrored = true;
		},
	);
	const sdk = new NodeSDK({
		autoDetectResources: false,
		resource,
		sampler: samplerFor(config),
		traceExporter: exporter,
		textMapPropagator: inboundOnlyTraceContextPropagator,
		instrumentations: [
			new HttpInstrumentation({
				headersToSpanAttributes: {
					client: { requestHeaders: [], responseHeaders: [] },
					server: { requestHeaders: [], responseHeaders: [] },
				},
			}),
			new PgInstrumentation({ enhancedDatabaseReporting: false }),
		],
	});

	await sdk.start();
	return {
		shutdown: () => sdk.shutdown(),
		hasExporterError: () => exporterErrored,
	};
}
