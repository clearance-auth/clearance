export const SERVICE_NAMES = [
	"clearance-api",
	"clearance-delivery-worker",
] as const;

export type ClearanceServiceName = (typeof SERVICE_NAMES)[number];
export type TraceSamplerName =
	| "always_off"
	| "traceidratio"
	| "parentbased_traceidratio";

export interface DisabledObservabilityConfig {
	enabled: false;
	shutdownTimeoutMillis: number;
}

export interface EnabledObservabilityConfig {
	enabled: true;
	serviceName: ClearanceServiceName;
	exporter: {
		endpoint: URL;
		headers: Readonly<Record<string, string>>;
	};
	sampler: {
		name: TraceSamplerName;
		ratio?: number;
	};
	shutdownTimeoutMillis: number;
}

export type ObservabilityConfig =
	| DisabledObservabilityConfig
	| EnabledObservabilityConfig;

export class ObservabilityConfigurationError extends Error {
	constructor(message: string) {
		super(`Invalid Clearance OpenTelemetry configuration: ${message}`);
		this.name = "ObservabilityConfigurationError";
	}
}

type Environment = Record<string, string | undefined>;

const DEFAULT_SHUTDOWN_TIMEOUT_MILLIS = 10_000;
const DEFAULT_SAMPLER_RATIO = 0.1;
const MIN_SHUTDOWN_TIMEOUT_MILLIS = 100;
const MAX_SHUTDOWN_TIMEOUT_MILLIS = 60_000;
const MAX_HEADERS = 32;
const MAX_HEADER_NAME_LENGTH = 128;
const MAX_HEADER_VALUE_LENGTH = 4_096;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const INVALID_HEADER_VALUE = /[\u0000-\u0008\u000a-\u001f\u007f]/;

function readEnabled(environment: Environment): boolean {
	const value = environment.OTEL_SDK_DISABLED;
	if (value === undefined || value === "true") return false;
	if (value === "false") return true;
	throw new ObservabilityConfigurationError(
		'OTEL_SDK_DISABLED must be exactly "true" or "false"',
	);
}

function readServiceName(environment: Environment): ClearanceServiceName {
	const serviceName = environment.CLEARANCE_OTEL_SERVICE_NAME;
	if (!serviceName || !SERVICE_NAMES.includes(serviceName as ClearanceServiceName)) {
		throw new ObservabilityConfigurationError(
			`CLEARANCE_OTEL_SERVICE_NAME must be one of: ${SERVICE_NAMES.join(", ")}`,
		);
	}
	return serviceName as ClearanceServiceName;
}

function isLoopback(hostname: string): boolean {
	return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function readEndpoint(environment: Environment): URL {
	const raw = environment.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT;
	if (!raw) {
		throw new ObservabilityConfigurationError(
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is required when OTEL_SDK_DISABLED=false",
		);
	}

	let endpoint: URL;
	try {
		endpoint = new URL(raw);
	} catch {
		throw new ObservabilityConfigurationError(
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT must be an absolute URL",
		);
	}

	if (
		endpoint.protocol !== "https:" &&
		!(endpoint.protocol === "http:" && isLoopback(endpoint.hostname))
	) {
		throw new ObservabilityConfigurationError(
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT must use HTTPS, or HTTP on loopback",
		);
	}
	if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
		throw new ObservabilityConfigurationError(
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT cannot contain credentials, query parameters, or fragments",
		);
	}
	return endpoint;
}

function readHeaders(environment: Environment): Readonly<Record<string, string>> {
	const raw = environment.OTEL_EXPORTER_OTLP_HEADERS;
	if (!raw) return Object.freeze({});

	const headers: Record<string, string> = {};
	for (const part of raw.split(",")) {
		const separator = part.indexOf("=");
		if (separator < 1) {
			throw new ObservabilityConfigurationError(
				"OTEL_EXPORTER_OTLP_HEADERS must use comma-separated name=value pairs",
			);
		}
		const name = part.slice(0, separator).trim().toLowerCase();
		const value = part.slice(separator + 1).trim();
		if (!HEADER_NAME.test(name) || !value || value.length > MAX_HEADER_VALUE_LENGTH) {
			throw new ObservabilityConfigurationError(
				"OTEL_EXPORTER_OTLP_HEADERS contains an invalid header",
			);
		}
		if (headers[name] !== undefined || Object.keys(headers).length >= MAX_HEADERS) {
			throw new ObservabilityConfigurationError(
				"OTEL_EXPORTER_OTLP_HEADERS contains duplicate or too many headers",
			);
		}
		headers[name] = value;
	}
	return Object.freeze(headers);
}

function canonicalShutdownTimeout(value: unknown): number {
	if (
		typeof value !== "number" ||
		!Number.isSafeInteger(value) ||
		value < MIN_SHUTDOWN_TIMEOUT_MILLIS ||
		value > MAX_SHUTDOWN_TIMEOUT_MILLIS
	) {
		throw new ObservabilityConfigurationError(
			`shutdownTimeoutMillis must be an integer between ${MIN_SHUTDOWN_TIMEOUT_MILLIS} and ${MAX_SHUTDOWN_TIMEOUT_MILLIS}`,
		);
	}
	return value;
}

function canonicalServiceName(value: unknown): ClearanceServiceName {
	if (
		typeof value !== "string" ||
		!SERVICE_NAMES.includes(value as ClearanceServiceName)
	) {
		throw new ObservabilityConfigurationError(
			`serviceName must be one of: ${SERVICE_NAMES.join(", ")}`,
		);
	}
	return value as ClearanceServiceName;
}

function canonicalEndpoint(value: unknown): URL {
	if (!(value instanceof URL)) {
		throw new ObservabilityConfigurationError("exporter.endpoint must be a URL");
	}
	const endpoint = new URL(value.href);
	if (
		endpoint.protocol !== "https:" &&
		!(endpoint.protocol === "http:" && isLoopback(endpoint.hostname))
	) {
		throw new ObservabilityConfigurationError(
			"exporter.endpoint must use HTTPS, or HTTP on loopback",
		);
	}
	if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
		throw new ObservabilityConfigurationError(
			"exporter.endpoint cannot contain credentials, query parameters, or fragments",
		);
	}
	return endpoint;
}

function canonicalHeaders(value: unknown): Readonly<Record<string, string>> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new ObservabilityConfigurationError("exporter.headers must be an object");
	}
	const entries = Object.entries(value);
	if (entries.length > MAX_HEADERS) {
		throw new ObservabilityConfigurationError(
			`exporter.headers cannot contain more than ${MAX_HEADERS} headers`,
		);
	}

	const headers: Record<string, string> = {};
	for (const [rawName, rawValue] of entries) {
		const name = rawName.toLowerCase();
		if (
			!HEADER_NAME.test(name) ||
			name.length > MAX_HEADER_NAME_LENGTH ||
			typeof rawValue !== "string" ||
			!rawValue ||
			rawValue.length > MAX_HEADER_VALUE_LENGTH ||
			INVALID_HEADER_VALUE.test(rawValue)
		) {
			throw new ObservabilityConfigurationError(
				"exporter.headers contains an invalid header",
			);
		}
		if (headers[name] !== undefined) {
			throw new ObservabilityConfigurationError(
				"exporter.headers contains duplicate case-insensitive names",
			);
		}
		headers[name] = rawValue;
	}
	return Object.freeze(headers);
}

function canonicalSampler(value: unknown): EnabledObservabilityConfig["sampler"] {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new ObservabilityConfigurationError("sampler must be an object");
	}
	const sampler = value as { name?: unknown; ratio?: unknown };
	if (sampler.name === "always_off") {
		if (sampler.ratio !== undefined) {
			throw new ObservabilityConfigurationError(
				"always_off sampler cannot define a ratio",
			);
		}
		return Object.freeze({ name: "always_off" });
	}
	if (
		sampler.name !== "traceidratio" &&
		sampler.name !== "parentbased_traceidratio"
	) {
		throw new ObservabilityConfigurationError(
			"sampler.name must be always_off, traceidratio, or parentbased_traceidratio",
		);
	}
	if (
		typeof sampler.ratio !== "number" ||
		!Number.isFinite(sampler.ratio) ||
		sampler.ratio < 0 ||
		sampler.ratio > 1
	) {
		throw new ObservabilityConfigurationError(
			"sampler.ratio must be between 0 and 1",
		);
	}
	return Object.freeze({ name: sampler.name, ratio: sampler.ratio });
}

/**
 * Validates and snapshots both programmatic and environment-derived input.
 * The returned graph shares no mutable URL, headers, exporter, or sampler
 * objects with the caller.
 */
export function canonicalizeObservabilityConfig(
	value: ObservabilityConfig,
): ObservabilityConfig {
	if (typeof value !== "object" || value === null || typeof value.enabled !== "boolean") {
		throw new ObservabilityConfigurationError("configuration must declare enabled");
	}
	const shutdownTimeoutMillis = canonicalShutdownTimeout(
		value.shutdownTimeoutMillis,
	);
	if (!value.enabled) {
		return Object.freeze({ enabled: false, shutdownTimeoutMillis });
	}

	const exporter = value.exporter as { endpoint?: unknown; headers?: unknown };
	return Object.freeze({
		enabled: true,
		serviceName: canonicalServiceName(value.serviceName),
		exporter: Object.freeze({
			endpoint: canonicalEndpoint(exporter?.endpoint),
			headers: canonicalHeaders(exporter?.headers),
		}),
		sampler: canonicalSampler(value.sampler),
		shutdownTimeoutMillis,
	});
}

function readRatio(environment: Environment): number {
	const raw = environment.OTEL_TRACES_SAMPLER_ARG;
	if (raw === undefined) return DEFAULT_SAMPLER_RATIO;
	if (!/^(?:0(?:\.\d+)?|1(?:\.0+)?)$/.test(raw)) {
		throw new ObservabilityConfigurationError(
			"OTEL_TRACES_SAMPLER_ARG must be a ratio between 0 and 1",
		);
	}
	const ratio = Number(raw);
	if (!Number.isFinite(ratio) || ratio < 0 || ratio > 1) {
		throw new ObservabilityConfigurationError(
			"OTEL_TRACES_SAMPLER_ARG must be a ratio between 0 and 1",
		);
	}
	return ratio;
}

function readSampler(environment: Environment): EnabledObservabilityConfig["sampler"] {
	const name = environment.OTEL_TRACES_SAMPLER ?? "parentbased_traceidratio";
	if (name === "always_off") return { name };
	if (name === "traceidratio" || name === "parentbased_traceidratio") {
		return { name, ratio: readRatio(environment) };
	}
	throw new ObservabilityConfigurationError(
		"OTEL_TRACES_SAMPLER must be always_off, traceidratio, or parentbased_traceidratio",
	);
}

/**
 * Default process behavior is disabled. The only enablement switch is the
 * standard OTEL_SDK_DISABLED=false value; all other configuration is ignored
 * while disabled so importing a default process cannot initialize an SDK.
 */
export function parseObservabilityConfig(
	environment: Environment = process.env,
): ObservabilityConfig {
	if (!readEnabled(environment)) {
		return canonicalizeObservabilityConfig({
			enabled: false,
			shutdownTimeoutMillis: DEFAULT_SHUTDOWN_TIMEOUT_MILLIS,
		});
	}

	return canonicalizeObservabilityConfig({
		enabled: true,
		serviceName: readServiceName(environment),
		exporter: {
			endpoint: readEndpoint(environment),
			headers: readHeaders(environment),
		},
		sampler: readSampler(environment),
		shutdownTimeoutMillis: DEFAULT_SHUTDOWN_TIMEOUT_MILLIS,
	});
}
