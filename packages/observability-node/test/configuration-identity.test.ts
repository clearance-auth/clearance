import { describe, expect, it } from "vitest";
import {
	sameObservabilityConfiguration,
	startObservability,
} from "../src/bootstrap";
import {
	canonicalizeObservabilityConfig,
	ObservabilityConfigurationError,
	type EnabledObservabilityConfig,
} from "../src/config";

describe("sameObservabilityConfiguration", () => {
	it("rejects same-origin OTLP exporters with different trace paths", () => {
		const baseline: EnabledObservabilityConfig = {
			enabled: true,
			serviceName: "clearance-api",
			exporter: {
				endpoint: new URL("https://collector.example/v1/traces"),
				headers: {},
			},
			sampler: { name: "always_off" },
			shutdownTimeoutMillis: 10_000,
		};
		const sameOriginDifferentPath: EnabledObservabilityConfig = {
			...baseline,
			exporter: {
				...baseline.exporter,
				endpoint: new URL("https://collector.example/private/traces"),
			},
		};

		expect(sameObservabilityConfiguration(baseline, baseline)).toBe(true);
		expect(
			sameObservabilityConfiguration(baseline, sameOriginDifferentPath),
		).toBe(false);
	});

	it("includes disabled timeout and snapshots all mutable enabled input", () => {
		const caller: EnabledObservabilityConfig = {
			enabled: true,
			serviceName: "clearance-api",
			exporter: {
				endpoint: new URL("https://collector.example/v1/traces"),
				headers: { authorization: "first" },
			},
			sampler: { name: "traceidratio", ratio: 0.25 },
			shutdownTimeoutMillis: 1_000,
		};
		const snapshot = canonicalizeObservabilityConfig(caller);
		caller.exporter.endpoint.pathname = "/mutated";
		(caller.exporter.headers as Record<string, string>).authorization = "second";
		caller.sampler.ratio = 0.75;

		if (!snapshot.enabled) throw new Error("expected enabled snapshot");
		expect(snapshot.exporter.endpoint.href).toBe(
			"https://collector.example/v1/traces",
		);
		expect(snapshot.exporter.headers).toEqual({ authorization: "first" });
		expect(snapshot.sampler.ratio).toBe(0.25);
		expect(
			sameObservabilityConfiguration(
				{ enabled: false, shutdownTimeoutMillis: 100 },
				{ enabled: false, shutdownTimeoutMillis: 200 },
			),
		).toBe(false);
	});

	it("rejects invalid programmatic configuration before startup", () => {
		const valid: EnabledObservabilityConfig = {
			enabled: true,
			serviceName: "clearance-api",
			exporter: {
				endpoint: new URL("https://collector.example/v1/traces"),
				headers: { authorization: "secret" },
			},
			sampler: { name: "traceidratio", ratio: 0.1 },
			shutdownTimeoutMillis: 1_000,
		};
		const tooManyHeaders = Object.fromEntries(
			Array.from({ length: 33 }, (_, index) => [`x-${index}`, "value"]),
		);
		const invalid: unknown[] = [
			{ ...valid, serviceName: "clearance-tenant" },
			{
				...valid,
				exporter: {
					...valid.exporter,
					endpoint: new URL("http://collector.example/v1/traces"),
				},
			},
			{
				...valid,
				exporter: {
					...valid.exporter,
					endpoint: new URL("https://user:secret@collector.example/v1/traces"),
				},
			},
			{
				...valid,
				exporter: {
					...valid.exporter,
					endpoint: new URL("https://collector.example/v1/traces?secret=yes"),
				},
			},
			{ ...valid, exporter: { ...valid.exporter, headers: { "bad name": "value" } } },
			{ ...valid, exporter: { ...valid.exporter, headers: tooManyHeaders } },
			{
				...valid,
				exporter: { ...valid.exporter, headers: { valid: "line\nbreak" } },
			},
			{ ...valid, sampler: { name: "always_on" } },
			{ ...valid, sampler: { name: "traceidratio", ratio: 2 } },
			{ ...valid, shutdownTimeoutMillis: 0 },
		];

		for (const config of invalid) {
			expect(() => startObservability(config as never)).toThrow(
				ObservabilityConfigurationError,
			);
		}
	});
});
