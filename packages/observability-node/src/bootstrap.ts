import {
	canonicalizeObservabilityConfig,
	parseObservabilityConfig,
	type ObservabilityConfig,
} from "./config";
import { redactedStatus, type ObservabilityStatus } from "./status";

export interface ObservabilityHandle {
	readonly status: ObservabilityStatus;
	shutdown(): Promise<ObservabilityStatus>;
}

export type ObservabilityShutdownReason = "failed" | "timed-out";

export class ObservabilityShutdownError extends Error {
	readonly reason: ObservabilityShutdownReason;

	constructor(reason: ObservabilityShutdownReason) {
		super(`Clearance OpenTelemetry shutdown ${reason}`);
		this.name = "ObservabilityShutdownError";
		this.reason = reason;
	}
}

let activeHandle: ObservabilityHandle | undefined;
let startup: Promise<ObservabilityHandle> | undefined;
let startupConfig: ObservabilityConfig | undefined;
let activeConfig: ObservabilityConfig | undefined;

export function sameObservabilityConfiguration(
	left: ObservabilityConfig,
	right: ObservabilityConfig,
): boolean {
	const canonicalLeft = canonicalizeObservabilityConfig(left);
	const canonicalRight = canonicalizeObservabilityConfig(right);
	return sameCanonicalConfiguration(canonicalLeft, canonicalRight);
}

function sameCanonicalConfiguration(
	left: ObservabilityConfig,
	right: ObservabilityConfig,
): boolean {
	if (left.enabled !== right.enabled) return false;
	if (!left.enabled || !right.enabled) {
		return left.shutdownTimeoutMillis === right.shutdownTimeoutMillis;
	}
	return (
		left.serviceName === right.serviceName &&
		left.exporter.endpoint.href === right.exporter.endpoint.href &&
		Object.keys(left.exporter.headers).length === Object.keys(right.exporter.headers).length &&
		Object.entries(left.exporter.headers).every(
			([key, value]) => right.exporter.headers[key] === value,
		) &&
		left.sampler.name === right.sampler.name &&
		left.sampler.ratio === right.sampler.ratio &&
		left.shutdownTimeoutMillis === right.shutdownTimeoutMillis
	);
}

function disabledHandle(config: ObservabilityConfig): ObservabilityHandle {
	const status = redactedStatus(config, "disabled");
	const shutdown = Promise.resolve(status);
	return Object.freeze({
		status,
		shutdown: () => shutdown,
	});
}

export function awaitShutdown(
	shutdown: () => Promise<void>,
	timeoutMillis: number,
): Promise<void> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(
			() => reject(new ObservabilityShutdownError("timed-out")),
			timeoutMillis,
		);
		void Promise.resolve()
			.then(shutdown)
			.then(
			() => {
				clearTimeout(timer);
				resolve();
			},
			() => {
				clearTimeout(timer);
				reject(new ObservabilityShutdownError("failed"));
			},
		);
	});
}

async function startEnabled(config: ObservabilityConfig): Promise<ObservabilityHandle> {
	if (!config.enabled) return disabledHandle(config);

	// Keep all OTel imports behind the explicit enabled gate. Importing this
	// package with its default configuration initializes no SDK or exporter.
	const { createObservabilityRuntime } = await import("./runtime");
	const runtime = await createObservabilityRuntime(config);
	let shutdown: Promise<ObservabilityStatus> | undefined;
	const getStatus = () =>
		redactedStatus(
			config,
			runtime.hasExporterError() ? "exporter_error" : "configured",
		);

	return Object.freeze({
		get status() {
			return getStatus();
		},
		shutdown: () => {
			shutdown ??= awaitShutdown(
				runtime.shutdown,
				config.shutdownTimeoutMillis,
			).then(getStatus);
			return shutdown;
		},
	});
}

/**
 * Starts tracing exactly once for the process. A second call may reuse the
 * exact configuration, while conflicting settings fail before a second global
 * tracer provider can be registered.
 */
export function startObservability(
	config: ObservabilityConfig = parseObservabilityConfig(),
): Promise<ObservabilityHandle> {
	const canonicalConfig = canonicalizeObservabilityConfig(config);
	if (activeHandle) {
		if (
			!activeConfig ||
			!sameCanonicalConfiguration(activeConfig, canonicalConfig)
		) {
			return Promise.reject(
				new Error("Clearance OpenTelemetry was already started with different configuration"),
			);
		}
		return Promise.resolve(activeHandle);
	}
	if (startup) {
		if (
			!startupConfig ||
			!sameCanonicalConfiguration(startupConfig, canonicalConfig)
		) {
			return Promise.reject(
				new Error("Clearance OpenTelemetry is already starting with different configuration"),
			);
		}
		return startup;
	}

	startupConfig = canonicalConfig;
	startup = startEnabled(canonicalConfig).then(
		(handle) => {
			activeHandle = handle;
			activeConfig = canonicalConfig;
			return handle;
		},
		(error: unknown) => {
			startup = undefined;
			startupConfig = undefined;
			throw error;
		},
	);
	return startup;
}
