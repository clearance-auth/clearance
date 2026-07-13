import { existsSync } from "node:fs";
import { createConnection } from "node:net";
import { resolve } from "node:path";
import pg from "pg";
import type { ManagementStore } from "../store/types.js";
import type { DoctorCheck } from "../types/resources.js";
import { STORE_SCHEMA_VERSION } from "../store/json-store.js";
import { recordEvent } from "./audit.js";
import { resolveCredentialKeyring } from "./credentials.js";
import { isForbiddenDefaultSecret } from "./secrets.js";

function tcpReachable(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
	return new Promise((resolvePromise) => {
		const socket = createConnection({ host, port }, () => {
			socket.end();
			resolvePromise(true);
		});
		socket.setTimeout(timeoutMs);
		socket.on("error", () => resolvePromise(false));
		socket.on("timeout", () => {
			socket.destroy();
			resolvePromise(false);
		});
	});
}

async function httpReachable(url: string, timeoutMs = 2000): Promise<boolean> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const response = await fetch(url, { signal: controller.signal });
		return response.ok;
	} catch {
		return false;
	} finally {
		clearTimeout(timer);
	}
}

export async function runDoctor(
	store: ManagementStore,
	opts?: { dataPath?: string; secrets?: Record<string, string | undefined> },
): Promise<{ checks: DoctorCheck[]; ok: boolean; releaseVersion: string }> {
	await store.ready();
	await store.refresh();
	const checks: DoctorCheck[] = [];
	const secrets = { ...process.env, ...opts?.secrets };

	const secret = secrets.CLEARANCE_SECRET;
	if (!secret || secret.length < 16) {
		checks.push({
			id: "secret",
			name: "Application secret",
			status: "fail",
			detail: "CLEARANCE_SECRET missing or shorter than 16 characters",
			remediation: "export CLEARANCE_SECRET=$(openssl rand -base64 32)",
		});
	} else {
		checks.push({
			id: "secret",
			name: "Application secret",
			status: "pass",
			detail: "Secret present and length OK",
		});
	}

	const dataPath = opts?.dataPath ?? store.path;
	if (!existsSync(dataPath) && !store.snapshot.meta.initializedAt) {
		checks.push({
			id: "schema",
			name: "Data store",
			status: "warn",
			detail: `Store not initialized at ${dataPath}`,
			remediation: "Run: clearance init --name my-app",
		});
	} else if (store.snapshot.meta.schemaVersion !== STORE_SCHEMA_VERSION) {
		checks.push({
			id: "schema",
			name: "Data store / schema",
			status: "fail",
			detail: `Schema drift: found v${store.snapshot.meta.schemaVersion}, expected v${STORE_SCHEMA_VERSION}`,
			remediation: "Run clearance schema migrate, then clearance doctor --json",
		});
	} else {
		checks.push({
			id: "schema",
			name: "Data store / schema",
			status: "pass",
			detail: `Schema v${store.snapshot.meta.schemaVersion} at ${dataPath}`,
		});
	}

	if (store.snapshot.projects.length === 0) {
		checks.push({
			id: "project",
			name: "Project",
			status: "fail",
			detail: "No project configured",
			remediation: "Run: clearance init --name my-app",
		});
	} else {
		checks.push({
			id: "project",
			name: "Project",
			status: "pass",
			detail: `Project ${store.snapshot.projects[0].name}`,
		});
	}

	const nodeEnv = secrets.NODE_ENV ?? "development";
	if (nodeEnv === "production") {
		if (!secrets.DATABASE_URL) {
			checks.push({
				id: "database",
				name: "Database URL",
				status: "fail",
				detail: "DATABASE_URL required in production",
				remediation: "Set DATABASE_URL to Postgres connection string",
			});
		} else {
			checks.push({
				id: "database",
				name: "Database URL",
				status: "pass",
				detail: "DATABASE_URL set — Postgres is control-plane source of truth",
			});
		}
		if (isForbiddenDefaultSecret(secret)) {
			checks.push({
				id: "unsafe-secret",
				name: "Production secret safety",
				status: "fail",
				detail: "Default/dev/weak CLEARANCE_SECRET refused in production",
				remediation: "export CLEARANCE_SECRET=$(openssl rand -base64 32)",
			});
		} else {
			checks.push({
				id: "unsafe-secret",
				name: "Production secret safety",
				status: "pass",
				detail: "Secret is not a known default",
			});
		}
		const operatorToken =
			secrets.CLEARANCE_OPERATOR_TOKEN ?? secrets.CLEARANCE_API_TOKEN;
		const credentialKeyring = resolveCredentialKeyring(secrets);
		checks.push({
			id: "operator-token",
			name: "Operator credential",
			status:
				operatorToken && operatorToken.length >= 16 && !isForbiddenDefaultSecret(operatorToken)
					? "pass"
					: "fail",
			detail:
				operatorToken && operatorToken.length >= 16 && !isForbiddenDefaultSecret(operatorToken)
					? "Strong operator credential configured"
					: "Missing, weak, or default CLEARANCE_OPERATOR_TOKEN",
			remediation: "export CLEARANCE_OPERATOR_TOKEN=$(openssl rand -base64 32)",
		});
		checks.push({
			id: "credential-encryption",
			name: "Credential encryption key",
			status: credentialKeyring ? "pass" : "fail",
			detail: credentialKeyring
				? "Versioned credential keyring configured"
				: "CLEARANCE_CREDENTIAL_KEY and CLEARANCE_CREDENTIAL_KEY_ID are required",
			remediation:
				"Set a 32-byte CLEARANCE_CREDENTIAL_KEY and a stable CLEARANCE_CREDENTIAL_KEY_ID",
		});
	} else {
		checks.push({
			id: "database",
			name: "Database URL",
			status: secrets.DATABASE_URL ? "pass" : "warn",
			detail: secrets.DATABASE_URL
				? `DATABASE_URL set (${secrets.DATABASE_URL.replace(/:[^:@/]+@/, ":***@")}); management backend=postgres`
				: "Using local JSON store (OK for development without DATABASE_URL)",
		});
		if (secret && isForbiddenDefaultSecret(secret)) {
			checks.push({
				id: "unsafe-secret",
				name: "Secret hygiene",
				status: "warn",
				detail: "Dev/default secret detected — rotate before production",
				remediation: "export CLEARANCE_SECRET=$(openssl rand -base64 32)",
			});
		}
	}

	checks.push({
		id: "store-backend",
		name: "Management store backend",
		status: "pass",
		detail:
			store.backend === "postgres"
				? "Postgres transactional snapshot (single source of truth)"
				: `JSON file at ${store.path}`,
	});

	if (secrets.DATABASE_URL?.startsWith("postgres")) {
		try {
			const u = new URL(secrets.DATABASE_URL);
			const host = u.hostname;
			const port = Number(u.port || 5432);
			const reachable = await tcpReachable(host, port);
			checks.push({
				id: "database-reachability",
				name: "Database reachability",
				status: reachable ? "pass" : "fail",
				detail: reachable
					? `TCP connect ok to ${host}:${port}`
					: `Cannot reach ${host}:${port}`,
				remediation: reachable
					? undefined
					: "Start Postgres (docker compose up -d postgres) or fix DATABASE_URL",
			});
		} catch (e) {
			checks.push({
				id: "database-reachability",
				name: "Database reachability",
				status: "warn",
				detail: `Could not parse/check DATABASE_URL: ${e instanceof Error ? e.message : String(e)}`,
			});
		}

		const pool = new pg.Pool({
			connectionString: secrets.DATABASE_URL,
			connectionTimeoutMillis: 2000,
			max: 1,
		});
		try {
			const db = await pool.query<{ database: string }>(
				"select current_database() as database",
			);
			const runtime = await pool.query<{
				user_table: string | null;
				session_table: string | null;
				organization_table: string | null;
				member_table: string | null;
				management_table: string | null;
			}>(`select
          to_regclass('public."user"')::text as user_table,
          to_regclass('public.session')::text as session_table,
          to_regclass('public.organization')::text as organization_table,
          to_regclass('public.member')::text as member_table,
          to_regclass('public.clearance_management_snapshot')::text as management_table`);
			const tables = runtime.rows[0];
			const missing = Object.entries(tables ?? {})
				.filter(([, value]) => !value)
				.map(([name]) => name.replace(/_table$/, ""));
			checks.push({
				id: "database-schema",
				name: "Postgres schema",
				status: missing.length === 0 ? "pass" : "fail",
				detail:
					missing.length === 0
						? `Authenticated query succeeded on ${db.rows[0]?.database}; runtime and management tables present`
						: `Missing required tables: ${missing.join(", ")}`,
				remediation:
					missing.length === 0
						? undefined
						: "Run Clearance runtime and management migrations",
			});

			if (missing.length === 0) {
				const runtimeUsers = await pool.query<{ id: string; email: string }>(
					`select id, email from "user" where email <> 'operator@clearance.local'`,
				);
				const runtimeOrgs = await pool.query<{ id: string }>(
					`select id from organization`,
				);
				const runtimeMemberships = await pool.query<{
					organizationId: string;
					userId: string;
				}>(`select "organizationId", "userId" from member`);
				const runtimeUserIds = new Set(runtimeUsers.rows.map((user) => user.id));
				const runtimeOrgIds = new Set(runtimeOrgs.rows.map((org) => org.id));
				const runtimeMembershipKeys = new Set(
					runtimeMemberships.rows.map(
						(member) => `${member.organizationId}:${member.userId}`,
					),
				);
				const managementUserIds = new Set(
					store.snapshot.principals
						.filter((principal) => principal.status !== "deleted")
						.map((principal) => principal.id),
				);
				const managementOrgIds = new Set(
					store.snapshot.organizations
						.filter((organization) => organization.status !== "archived")
						.map((organization) => organization.id),
				);
				const missingUsers = runtimeUsers.rows.filter(
					(user) => !managementUserIds.has(user.id),
				);
				const missingOrgs = runtimeOrgs.rows.filter(
					(org) => !managementOrgIds.has(org.id),
				);
				const managementOnlyUsers = store.snapshot.principals.filter(
					(principal) =>
						principal.status !== "deleted" && !runtimeUserIds.has(principal.id),
				);
				const managementOnlyOrgs = store.snapshot.organizations.filter(
					(organization) =>
						organization.status !== "archived" && !runtimeOrgIds.has(organization.id),
				);
				const missingRuntimeMemberships = store.snapshot.memberships.filter(
					(membership) =>
						membership.status === "active" &&
						!runtimeMembershipKeys.has(
							`${membership.organizationId}:${membership.principalId}`,
						),
				);
				const managementMembershipKeys = new Set(
					store.snapshot.memberships
						.filter((membership) => membership.status === "active")
						.map(
							(membership) =>
								`${membership.organizationId}:${membership.principalId}`,
						),
				);
				const missingManagementMemberships = runtimeMemberships.rows.filter(
					(member) =>
						!managementMembershipKeys.has(
							`${member.organizationId}:${member.userId}`,
						),
				);
				const parityOk =
					missingUsers.length === 0 &&
					missingOrgs.length === 0 &&
					managementOnlyUsers.length === 0 &&
					managementOnlyOrgs.length === 0 &&
					missingRuntimeMemberships.length === 0 &&
					missingManagementMemberships.length === 0;
				checks.push({
					id: "runtime-management-parity",
					name: "Runtime / management parity",
					status: parityOk ? "pass" : "fail",
					detail:
						parityOk
							? `${runtimeUsers.rowCount ?? 0} users, ${runtimeOrgs.rowCount ?? 0} organizations, and ${runtimeMemberships.rowCount ?? 0} memberships match bidirectionally`
							: `Drift: runtime-only users=${missingUsers.length}, orgs=${missingOrgs.length}, memberships=${missingManagementMemberships.length}; management-only users=${managementOnlyUsers.length}, orgs=${managementOnlyOrgs.length}, memberships=${missingRuntimeMemberships.length}`,
					remediation:
						parityOk
							? undefined
							: "Repair the runtime-to-management identity bridge before serving traffic",
				});
			}
		} catch (error) {
			checks.push({
				id: "database-schema",
				name: "Postgres schema",
				status: "fail",
				detail: `Authenticated database/schema check failed: ${error instanceof Error ? error.message : String(error)}`,
				remediation: "Verify DATABASE_URL credentials and run Clearance migrations",
			});
		} finally {
			await pool.end().catch(() => undefined);
		}
	}

	const baseUrl = secrets.CLEARANCE_BASE_URL;
	if (baseUrl) {
		try {
			new URL(baseUrl);
			checks.push({
				id: "base-url",
				name: "Base URL",
				status: "pass",
				detail: baseUrl,
			});
		} catch {
			checks.push({
				id: "base-url",
				name: "Base URL",
				status: "fail",
				detail: `Invalid URL: ${baseUrl}`,
				remediation: "Set CLEARANCE_BASE_URL to a valid absolute URL",
			});
		}
	} else {
		checks.push({
			id: "base-url",
			name: "Base URL",
			status: "warn",
			detail: "CLEARANCE_BASE_URL not set",
			remediation: "export CLEARANCE_BASE_URL=http://localhost:3000",
		});
	}

	for (const [id, label, url] of [
		[
			"api-health",
			"Management API",
			secrets.CLEARANCE_API_HEALTH_URL ?? secrets.CLEARANCE_API_URL,
		],
		[
			"console-health",
			"Console",
			secrets.CLEARANCE_CONSOLE_HEALTH_URL ?? secrets.CLEARANCE_CONSOLE_URL,
		],
	] as const) {
		if (!url) continue;
		let healthUrl: string;
		try {
			healthUrl = new URL(id === "api-health" ? "/health" : "/api/health", url).toString();
		} catch {
			checks.push({
				id,
				name: `${label} health`,
				status: "fail",
				detail: `Invalid ${label} URL: ${url}`,
			});
			continue;
		}
		const reachable = await httpReachable(healthUrl);
		checks.push({
			id,
			name: `${label} health`,
			status: reachable ? "pass" : "fail",
			detail: reachable ? `${healthUrl} reachable` : `${healthUrl} unavailable`,
			remediation: reachable ? undefined : `Start ${label} and verify its configured URL`,
		});
	}

	const wiredSinks = [
		secrets.CLEARANCE_TELEMETRY_ENDPOINT,
		store.snapshot.meta.config.telemetryEndpoint,
	].filter(Boolean) as string[];
	if (wiredSinks.length > 0) {
		checks.push({
			id: "telemetry-sink",
			name: "Telemetry sink",
			status: "fail",
			detail: `Remote telemetry endpoint configured: ${wiredSinks.join(", ")}`,
			remediation:
				"Unset CLEARANCE_TELEMETRY_ENDPOINT; Clearance defaults to no remote telemetry",
		});
	} else {
		checks.push({
			id: "telemetry-sink",
			name: "Telemetry sink",
			status: "pass",
			detail: "No remote telemetry endpoints configured",
		});
	}

	const parent = resolve(dataPath, "..");
	checks.push({
		id: "data-dir",
		name: "Data directory",
		status: "pass",
		detail: `Using ${parent}`,
	});

	const ok = checks.every((c) => c.status !== "fail");
	recordEvent(store, {
		actor: "system",
		action: "doctor.run",
		subjectType: "system",
		outcome: ok ? "success" : "failure",
		source: "cli",
		message: `Doctor completed with ${checks.filter((c) => c.status === "fail").length} failures`,
		metadata: { checks: checks.map((c) => ({ id: c.id, status: c.status })) },
	});
	await store.ready();

	return {
		checks,
		ok,
		releaseVersion: store.snapshot.releaseVersion,
	};
}
