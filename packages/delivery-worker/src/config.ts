import { randomUUID } from "node:crypto";
import type { DeliveryKeyring } from "@clearance/delivery";
import { resolveDeliveryKeyring } from "@clearance/delivery";

export type WorkerMode = "run" | "once" | "ready";
export type WorkerConfig = {
	mode: WorkerMode;
	databaseUrl: string;
	workerId: string;
	keyring: DeliveryKeyring;
	schema: string;
	prefix: string;
	legacyFingerprintKeyId?: string;
	smtp: {
		host: string; port: number; secure: boolean; requireTls: boolean; allowInsecureLoopback: boolean; from: string;
		user?: string; password?: string; connectionTimeoutMs: number;
		socketTimeoutMs: number; greetingTimeoutMs: number;
	};
	concurrency: number;
	pollMs: number;
	leaseMs: number;
	heartbeatMs: number;
	maintenanceMs: number;
	drainTimeoutMs: number;
	maxBodyBytes: number;
	appName: string;
	allowHttpLinks: boolean;
	webhook: {
		allowInsecureLoopback: boolean;
		dnsTimeoutMs: number;
		connectTimeoutMs: number;
		responseTimeoutMs: number;
		maxResponseBytes: number;
	};
	healthHost: string;
	healthPort: number;
	processOnceLimit: number;
};

function required(env: NodeJS.ProcessEnv, name: string): string {
	const value = env[name]?.trim();
	if (!value) throw new Error(`${name} is required`);
	return value;
}

function integer(env: NodeJS.ProcessEnv, name: string, fallback: number, min: number, max: number): number {
	const raw = env[name]?.trim();
	if (!raw) return fallback;
	if (!/^[0-9]+$/.test(raw)) throw new Error(`${name} must be an integer between ${min} and ${max}`);
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${name} must be an integer between ${min} and ${max}`);
	return value;
}

function boolean(env: NodeJS.ProcessEnv, name: string, fallback: boolean): boolean {
	const raw = env[name]?.trim().toLowerCase();
	if (!raw) return fallback;
	if (raw === "true" || raw === "1") return true;
	if (raw === "false" || raw === "0") return false;
	throw new Error(`${name} must be true or false`);
}

function identifier(value: string, name: string): string {
	if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(value)) throw new Error(`${name} must be a valid Postgres identifier`);
	return value;
}

function fingerprintKeyId(value: string, name: string): string {
	const normalized = value.trim();
	if (!/^[A-Za-z0-9._-]{1,64}$/.test(normalized)) {
		throw new Error(`${name} must be a valid delivery fingerprint key id`);
	}
	return normalized;
}

function boundedLine(value: string, name: string, max: number): string {
	const normalized = value.trim();
	if (!normalized || normalized.length > max || /[\r\n]/.test(normalized)) {
		throw new Error(`${name} must be a single line between 1 and ${max} characters`);
	}
	return normalized;
}

function mailbox(value: string, name: string): string {
	const normalized = boundedLine(value, name, 320);
	if (!/^[^\s@<>]+@[^\s@<>]+$/.test(normalized)) {
		throw new Error(`${name} must be a single email address`);
	}
	return normalized;
}

export function parseWorkerConfig(env: NodeJS.ProcessEnv = process.env, mode: WorkerMode = "run"): WorkerConfig {
	const user = env.CLEARANCE_SMTP_USER?.trim() || undefined;
	const password = env.CLEARANCE_SMTP_PASSWORD;
	if ((user && !password) || (!user && password)) throw new Error("CLEARANCE_SMTP_USER and CLEARANCE_SMTP_PASSWORD must be provided together");
	const workerId = (env.CLEARANCE_DELIVERY_WORKER_ID?.trim() || `delivery-${randomUUID()}`);
	if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(workerId)) throw new Error("CLEARANCE_DELIVERY_WORKER_ID is invalid");
	const smtpHost = required(env, "CLEARANCE_SMTP_HOST");
	const smtpSecure = boolean(env, "CLEARANCE_SMTP_SECURE", false);
	const smtpRequireTls = boolean(env, "CLEARANCE_SMTP_REQUIRE_TLS", true);
	const allowInsecureLoopback = boolean(env, "CLEARANCE_SMTP_ALLOW_INSECURE_LOOPBACK", false);
	if (!smtpSecure && !smtpRequireTls) {
		if (user) throw new Error("SMTP authentication requires implicit TLS or STARTTLS");
		if (!allowInsecureLoopback || !["localhost", "127.0.0.1", "::1", "[::1]"].includes(smtpHost.toLowerCase())) {
			throw new Error("Plaintext SMTP requires CLEARANCE_SMTP_ALLOW_INSECURE_LOOPBACK=true and a loopback host");
		}
	}
	return {
		mode,
		databaseUrl: required(env, "DATABASE_URL"),
		workerId,
		keyring: resolveDeliveryKeyring(env),
		schema: identifier(env.CLEARANCE_DELIVERY_SCHEMA?.trim() || "public", "CLEARANCE_DELIVERY_SCHEMA"),
		prefix: identifier(env.CLEARANCE_DELIVERY_PREFIX?.trim() || "delivery_", "CLEARANCE_DELIVERY_PREFIX"),
		...(env.CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID?.trim()
			? {
				legacyFingerprintKeyId: fingerprintKeyId(
					env.CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID,
					"CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID",
				),
			}
			: {}),
		smtp: {
			host: smtpHost,
			from: mailbox(required(env, "CLEARANCE_EMAIL_FROM"), "CLEARANCE_EMAIL_FROM"),
			port: integer(env, "CLEARANCE_SMTP_PORT", 587, 1, 65_535),
			secure: smtpSecure,
			requireTls: smtpRequireTls,
			allowInsecureLoopback,
			...(user ? { user, password } : {}),
			connectionTimeoutMs: integer(env, "CLEARANCE_SMTP_CONNECTION_TIMEOUT_MS", 10_000, 1_000, 120_000),
			socketTimeoutMs: integer(env, "CLEARANCE_SMTP_SOCKET_TIMEOUT_MS", 30_000, 1_000, 300_000),
			greetingTimeoutMs: integer(env, "CLEARANCE_SMTP_GREETING_TIMEOUT_MS", 10_000, 1_000, 120_000),
		},
		concurrency: integer(env, "CLEARANCE_DELIVERY_CONCURRENCY", 4, 1, 64),
		pollMs: integer(env, "CLEARANCE_DELIVERY_POLL_MS", 500, 25, 60_000),
		leaseMs: integer(env, "CLEARANCE_DELIVERY_LEASE_MS", 60_000, 5_000, 600_000),
		heartbeatMs: integer(env, "CLEARANCE_DELIVERY_HEARTBEAT_MS", 10_000, 1_000, 60_000),
		maintenanceMs: integer(env, "CLEARANCE_DELIVERY_MAINTENANCE_MS", 30_000, 1_000, 300_000),
		drainTimeoutMs: integer(env, "CLEARANCE_DELIVERY_DRAIN_TIMEOUT_MS", 30_000, 1_000, 300_000),
		maxBodyBytes: integer(env, "CLEARANCE_DELIVERY_MAX_BODY_BYTES", 1_048_576, 1_024, 10_485_760),
		appName: boundedLine(env.CLEARANCE_DELIVERY_APP_NAME?.trim() || "Clearance", "CLEARANCE_DELIVERY_APP_NAME", 120),
		allowHttpLinks: boolean(env, "CLEARANCE_DELIVERY_ALLOW_HTTP_LINKS", false),
		webhook: {
			allowInsecureLoopback: boolean(env, "CLEARANCE_WEBHOOK_ALLOW_INSECURE_LOOPBACK", false),
			dnsTimeoutMs: integer(env, "CLEARANCE_WEBHOOK_DNS_TIMEOUT_MS", 5_000, 250, 60_000),
			connectTimeoutMs: integer(env, "CLEARANCE_WEBHOOK_CONNECT_TIMEOUT_MS", 5_000, 250, 60_000),
			responseTimeoutMs: integer(env, "CLEARANCE_WEBHOOK_RESPONSE_TIMEOUT_MS", 10_000, 250, 120_000),
			maxResponseBytes: integer(env, "CLEARANCE_WEBHOOK_MAX_RESPONSE_BYTES", 65_536, 0, 1_048_576),
		},
		healthHost: env.CLEARANCE_DELIVERY_HEALTH_HOST?.trim() || "127.0.0.1",
		healthPort: integer(env, "CLEARANCE_DELIVERY_HEALTH_PORT", 8091, 1, 65_535),
		processOnceLimit: integer(env, "CLEARANCE_DELIVERY_ONCE_LIMIT", 100, 1, 10_000),
	};
}
