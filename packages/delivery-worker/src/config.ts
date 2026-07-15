import { randomUUID } from "node:crypto";
import type { DeliveryKeyring } from "@clearance/delivery";
import { resolveDeliveryKeyring } from "@clearance/delivery";

export type WorkerMode = "run" | "once" | "ready";
export type EmailTransport = "smtp" | "ses";
export type WorkerConfig = {
	mode: WorkerMode;
	databaseUrl: string;
	workerId: string;
	keyring: DeliveryKeyring;
	schema: string;
	prefix: string;
	legacyFingerprintKeyId?: string;
	/** Omitted by older programmatic callers; SMTP remains the compatibility default. */
	emailTransport?: EmailTransport;
	emailFrom?: string;
	smtp?: {
		host: string; port: number; secure: boolean; requireTls: boolean; allowInsecureLoopback: boolean; from: string;
		user?: string; password?: string; connectionTimeoutMs: number;
		socketTimeoutMs: number; greetingTimeoutMs: number;
	};
	ses?: {
		region: string;
		accessKeyId: string;
		secretAccessKey: string;
		sessionToken?: string;
		requestTimeoutMs: number;
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

function oneOf<T extends string>(
	env: NodeJS.ProcessEnv,
	name: string,
	fallback: T,
	allowed: readonly T[],
): T {
	const value = (env[name]?.trim().toLowerCase() || fallback) as T;
	if (!allowed.includes(value)) throw new Error(`${name} must be one of: ${allowed.join(", ")}`);
	return value;
}

function awsRegion(value: string): string {
	const normalized = value.trim().toLowerCase();
	if (!/^[a-z]{2}(?:-gov)?-[a-z0-9-]{2,24}-[1-9]$/.test(normalized)) {
		throw new Error("CLEARANCE_SES_REGION must be a valid AWS region");
	}
	return normalized;
}

function awsCredential(value: string, name: string, minimum: number, maximum: number): string {
	if (value.length < minimum || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
		throw new Error(`${name} must be a bounded AWS credential value`);
	}
	return value;
}

function awsAccessKeyId(value: string): string {
	if (!/^[A-Za-z0-9]{16,128}$/.test(value)) {
		throw new Error("CLEARANCE_SES_ACCESS_KEY_ID must be a bounded AWS access key id");
	}
	return value;
}

export function parseWorkerConfig(env: NodeJS.ProcessEnv = process.env, mode: WorkerMode = "run"): WorkerConfig {
	const emailTransport = oneOf(env, "CLEARANCE_EMAIL_TRANSPORT", "smtp", ["smtp", "ses"] as const);
	const emailFrom = mailbox(required(env, "CLEARANCE_EMAIL_FROM"), "CLEARANCE_EMAIL_FROM");
	const workerId = (env.CLEARANCE_DELIVERY_WORKER_ID?.trim() || `delivery-${randomUUID()}`);
	if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(workerId)) throw new Error("CLEARANCE_DELIVERY_WORKER_ID is invalid");
	let smtp: WorkerConfig["smtp"];
	let ses: WorkerConfig["ses"];
	if (emailTransport === "smtp") {
		const user = env.CLEARANCE_SMTP_USER?.trim() || undefined;
		const password = env.CLEARANCE_SMTP_PASSWORD;
		if ((user && !password) || (!user && password)) throw new Error("CLEARANCE_SMTP_USER and CLEARANCE_SMTP_PASSWORD must be provided together");
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
		smtp = {
			host: smtpHost,
			from: emailFrom,
			port: integer(env, "CLEARANCE_SMTP_PORT", 587, 1, 65_535),
			secure: smtpSecure,
			requireTls: smtpRequireTls,
			allowInsecureLoopback,
			...(user ? { user, password } : {}),
			connectionTimeoutMs: integer(env, "CLEARANCE_SMTP_CONNECTION_TIMEOUT_MS", 10_000, 1_000, 120_000),
			socketTimeoutMs: integer(env, "CLEARANCE_SMTP_SOCKET_TIMEOUT_MS", 30_000, 1_000, 300_000),
			greetingTimeoutMs: integer(env, "CLEARANCE_SMTP_GREETING_TIMEOUT_MS", 10_000, 1_000, 120_000),
		};
	} else {
		const accessKeyId = env.CLEARANCE_SES_ACCESS_KEY_ID ?? env.AWS_ACCESS_KEY_ID ?? "";
		const secretAccessKey = env.CLEARANCE_SES_SECRET_ACCESS_KEY ?? env.AWS_SECRET_ACCESS_KEY ?? "";
		const sessionToken = env.CLEARANCE_SES_SESSION_TOKEN ?? env.AWS_SESSION_TOKEN;
		const region = env.CLEARANCE_SES_REGION ?? env.AWS_REGION ?? env.AWS_DEFAULT_REGION;
		if (!accessKeyId || !secretAccessKey) {
			throw new Error("SES requires CLEARANCE_SES_ACCESS_KEY_ID and CLEARANCE_SES_SECRET_ACCESS_KEY (or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)");
		}
		if (!region?.trim()) throw new Error("SES requires CLEARANCE_SES_REGION (or AWS_REGION/AWS_DEFAULT_REGION)");
		ses = {
			region: awsRegion(region),
			accessKeyId: awsAccessKeyId(accessKeyId),
			secretAccessKey: awsCredential(secretAccessKey, "CLEARANCE_SES_SECRET_ACCESS_KEY", 20, 256),
			...(sessionToken ? { sessionToken: awsCredential(sessionToken, "CLEARANCE_SES_SESSION_TOKEN", 16, 8_192) } : {}),
			requestTimeoutMs: integer(env, "CLEARANCE_SES_REQUEST_TIMEOUT_MS", 10_000, 1_000, 120_000),
		};
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
		emailTransport,
		emailFrom,
		...(smtp ? { smtp } : {}),
		...(ses ? { ses } : {}),
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
