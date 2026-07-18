import { describe, expect, it } from "vitest";
import {
	ObservabilityConfigurationError,
	parseObservabilityConfig,
} from "../src/config";
import { redactedStatus } from "../src/status";

describe("parseObservabilityConfig", () => {
	it("is disabled by default and does not require or initialize an exporter", () => {
		expect(parseObservabilityConfig({})).toEqual({
			enabled: false,
			shutdownTimeoutMillis: 10_000,
		});
		expect(parseObservabilityConfig({ OTEL_SDK_DISABLED: "true" })).toMatchObject({
			enabled: false,
		});
	});

	it("enables only through OTEL_SDK_DISABLED=false and requires fixed safe inputs", () => {
		expect(() =>
			parseObservabilityConfig({ OTEL_SDK_DISABLED: "maybe" }),
		).toThrow(ObservabilityConfigurationError);
		expect(() =>
			parseObservabilityConfig({ OTEL_SDK_DISABLED: "false" }),
		).toThrow("CLEARANCE_OTEL_SERVICE_NAME");
		expect(() =>
			parseObservabilityConfig({
				OTEL_SDK_DISABLED: "false",
				CLEARANCE_OTEL_SERVICE_NAME: "tenant-controlled-name",
				OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "https://collector.example/v1/traces",
			}),
		).toThrow("CLEARANCE_OTEL_SERVICE_NAME");
		expect(() =>
			parseObservabilityConfig({
				OTEL_SDK_DISABLED: "false",
				CLEARANCE_OTEL_SERVICE_NAME: "clearance-api",
				OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://collector.example/v1/traces",
			}),
		).toThrow("must use HTTPS");
	});

	it("reads the frozen OTEL endpoint, headers, and bounded sampler contract", () => {
		const config = parseObservabilityConfig({
			OTEL_SDK_DISABLED: "false",
			CLEARANCE_OTEL_SERVICE_NAME: "clearance-api",
			OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://127.0.0.1:4318/v1/traces",
			OTEL_EXPORTER_OTLP_HEADERS: "authorization=Bearer secret,x-tenant=ignored-by-status",
			OTEL_TRACES_SAMPLER: "traceidratio",
			OTEL_TRACES_SAMPLER_ARG: "0.25",
		});

		if (!config.enabled) throw new Error("expected enabled configuration");
		expect(config.serviceName).toBe("clearance-api");
		expect(config.exporter.endpoint.toString()).toBe(
			"http://127.0.0.1:4318/v1/traces",
		);
		expect(config.exporter.headers).toEqual({
			authorization: "Bearer secret",
			"x-tenant": "ignored-by-status",
		});
		expect(config.sampler).toEqual({ name: "traceidratio", ratio: 0.25 });
		expect(() =>
			parseObservabilityConfig({
				OTEL_SDK_DISABLED: "false",
				CLEARANCE_OTEL_SERVICE_NAME: "clearance-api",
				OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "https://collector.example/v1/traces",
				OTEL_TRACES_SAMPLER: "traceidratio",
				OTEL_TRACES_SAMPLER_ARG: "1.1",
			}),
		).toThrow("OTEL_TRACES_SAMPLER_ARG");
	});

	it("keeps status to state plus fixed service and instrumentation flags", () => {
		const config = parseObservabilityConfig({
			OTEL_SDK_DISABLED: "false",
			CLEARANCE_OTEL_SERVICE_NAME: "clearance-delivery-worker",
			OTEL_EXPORTER_OTLP_TRACES_ENDPOINT:
				"https://collector.example/private/tenant-path",
			OTEL_EXPORTER_OTLP_HEADERS: "authorization=Bearer secret",
		});

		expect(redactedStatus(config, "configured")).toEqual({
			state: "configured",
			serviceName: "clearance-delivery-worker",
			instrumentations: { http: true, pg: true },
		});
		expect(JSON.stringify(redactedStatus(config, "exporter_error"))).not.toContain(
			"collector.example",
		);
		expect(JSON.stringify(redactedStatus(config, "exporter_error"))).not.toContain(
			"secret",
		);
	});
});
