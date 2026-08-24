import { existsSync } from "node:fs";
import { createConnection } from "node:net";
import { resolve } from "node:path";
import pg from "pg";
import type { ManagementStore } from "../store/types.js";
import type {
	DoctorCheck,
	Environment,
	Organization,
	User,
	Project,
} from "../types/resources.js";
import { STORE_SCHEMA_VERSION } from "../store/json-store.js";
import { recordEvent } from "./audit.js";
import { resolveCredentialKeyring } from "./credentials.js";
import { isForbiddenDefaultSecret } from "./secrets.js";

export const DEFAULT_CLEARANCE_BASE_URL = "http://localhost:3000";

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

const DOCTOR_PAGE_SIZE = 1_000;
const DOCTOR_MAX_TOPOLOGY_ITEMS = 50_000;
const DOCTOR_MAX_PRINCIPALS = 50_000;
const DOCTOR_MAX_MEMBERSHIPS = 50_000;
const DOCTOR_MAX_RUNTIME_ITEMS = 50_000;

type DoctorPageItem = { createdAt: string; id: string };

type DoctorReadBudget = {
	maxItems: number;
	remainingItems: number;
};

type DoctorTopology = {
	projects: Project[];
	environments: Environment[];
	organizations: Organization[];
};

function doctorReadBudget(maxItems: number): DoctorReadBudget {
	return {
		maxItems,
		remainingItems: maxItems,
	};
}

function readSnapshotItems<T>(
	label: string,
	items: readonly T[],
	maxItems: number,
): readonly T[] {
	if (items.length > maxItems) {
		throw new Error(`${label} exceeds the doctor read safety cap of ${maxItems} items`);
	}
	return items;
}

function membershipKey(organizationId: string, principalId: string): string {
	return `${organizationId.length}:${organizationId}${principalId.length}:${principalId}`;
}

function cursorAdvances(
	previous: { createdAt: string; id: string },
	next: { createdAt: string; id: string },
): boolean {
	return (
		next.createdAt > previous.createdAt ||
		(next.createdAt === previous.createdAt && next.id > previous.id)
	);
}

async function readDoctorPages<T extends DoctorPageItem>(
	label: string,
	budget: DoctorReadBudget,
	read: (input: {
		limit: number;
		cursor?: { createdAt: string; id: string };
	}) => Promise<{ items: T[]; hasMore: boolean }>,
): Promise<T[]> {
	const items: T[] = [];
	let cursor: { createdAt: string; id: string } | undefined;
	// A traversal gets its own no-progress/page guard. The item budget stays
	// shared across scopes so the category remains capped globally.
	let remainingPages = Math.ceil(budget.maxItems / DOCTOR_PAGE_SIZE);
	do {
		if (remainingPages <= 0) {
			throw new Error(
				`${label} exceeds the doctor read safety cap of ${budget.maxItems} items`,
			);
		}
		// Request one overflow row once the shared cap is reached. That permits
		// exactly the cap while rejecting a 50,001st row without assuming later
		// scopes are empty.
		const limit = Math.min(DOCTOR_PAGE_SIZE, budget.remainingItems + 1);
		const page = await read({
			limit,
			...(cursor ? { cursor } : {}),
		});
		if (page.items.length > limit) {
			throw new Error(`${label} exceeded its requested page limit`);
		}
		remainingPages -= 1;
		if (page.items.length > budget.remainingItems) {
			throw new Error(
				`${label} exceeds the doctor read safety cap of ${budget.maxItems} items`,
			);
		}
		budget.remainingItems -= page.items.length;
		items.push(...page.items);
		const last = page.items[page.items.length - 1];
		if (page.hasMore && !last) {
			throw new Error(`${label} returned a continuation without a cursor item`);
		}
		const nextCursor = page.hasMore && last
			? { createdAt: last.createdAt, id: last.id }
			: undefined;
		if (cursor && nextCursor && !cursorAdvances(cursor, nextCursor)) {
			throw new Error(`${label} returned a non-advancing cursor`);
		}
		cursor = nextCursor;
	} while (cursor);
	return items;
}

async function readRuntimeRows<T extends pg.QueryResultRow>(
	pool: pg.Pool,
	label: string,
	query: string,
): Promise<T[]> {
	const result = await pool.query<T>(`${query} LIMIT $1`, [
		DOCTOR_MAX_RUNTIME_ITEMS + 1,
	]);
	if (result.rows.length > DOCTOR_MAX_RUNTIME_ITEMS) {
		throw new Error(
			`${label} exceeds the doctor read safety cap of ${DOCTOR_MAX_RUNTIME_ITEMS} items`,
		);
	}
	return result.rows;
}

async function topologyForDoctor(
	store: ManagementStore,
): Promise<{ topology: DoctorTopology | null; error?: string }> {
	if (!store.storeV2Topology?.authoritative) {
		try {
			return {
				topology: {
					projects: [...readSnapshotItems(
						"Projects",
						store.snapshot.projects,
						DOCTOR_MAX_TOPOLOGY_ITEMS,
					)],
					environments: [...readSnapshotItems(
						"Environments",
						store.snapshot.environments,
						DOCTOR_MAX_TOPOLOGY_ITEMS,
					)],
					organizations: [...readSnapshotItems(
						"Organizations",
						store.snapshot.organizations,
						DOCTOR_MAX_TOPOLOGY_ITEMS,
					)],
				},
			};
		} catch (error) {
			return {
				topology: null,
				error: error instanceof Error ? error.message : String(error),
			};
		}
	}

	try {
		const topology = store.storeV2Topology;
		const projects = await readDoctorPages(
			"Projects",
			doctorReadBudget(DOCTOR_MAX_TOPOLOGY_ITEMS),
			async (input) => {
				const page = await topology.listProjectsPage(input);
				return { items: page.projects, hasMore: page.hasMore };
			},
		);
		const environments: Environment[] = [];
		const organizations: Organization[] = [];
		const environmentBudget = doctorReadBudget(DOCTOR_MAX_TOPOLOGY_ITEMS);
		for (const project of projects) {
			environments.push(
				...(await readDoctorPages("Environments", environmentBudget, async (input) => {
					const page = await topology.listEnvironmentsPage({
						projectId: project.id,
						...input,
					});
					return { items: page.environments, hasMore: page.hasMore };
				})),
			);
		}
		const organizationBudget = doctorReadBudget(DOCTOR_MAX_TOPOLOGY_ITEMS);
		for (const environment of environments) {
			const scope = {
				projectId: environment.projectId,
				environmentId: environment.id,
			};
			if (
				(await topology.countOrganizations({
					scope,
					includeArchived: true,
				})) === 0
			) {
				continue;
			}
			organizations.push(
				...(await readDoctorPages("Organizations", organizationBudget, async (input) => {
					const page = await topology.listOrganizationsPage({
						scope,
						includeArchived: true,
						...input,
					});
					return { items: page.organizations, hasMore: page.hasMore };
				})),
			);
		}
		return { topology: { projects, environments, organizations } };
	} catch (error) {
		return {
			topology: null,
			error: error instanceof Error ? error.message : String(error),
		};
	}
}

async function principalsForDoctor(
	store: ManagementStore,
	environments: readonly Environment[],
): Promise<User[]> {
	if (!store.storeV2Principals?.authoritative) {
		return readSnapshotItems(
			"Principals",
			store.snapshot.principals,
			DOCTOR_MAX_PRINCIPALS,
		).filter((principal) => principal.status !== "deleted");
	}
	const principals: User[] = [];
	const budget = doctorReadBudget(DOCTOR_MAX_PRINCIPALS);
	for (const environment of environments) {
		principals.push(
			...(await readDoctorPages("Principals", budget, async (input) => {
				const page = await store.storeV2Principals!.listPage({
					scope: {
						projectId: environment.projectId,
						environmentId: environment.id,
					},
					...input,
				});
				return { items: page.principals, hasMore: page.hasMore };
			})),
		);
	}
	return principals;
}

export async function runDoctor(
	store: ManagementStore,
	opts?: { dataPath?: string; secrets?: Record<string, string | undefined> },
): Promise<{ checks: DoctorCheck[]; ok: boolean; releaseVersion: string }> {
	await store.ready();
	await store.refresh();
	const checks: DoctorCheck[] = [];
	const secrets = { ...process.env, ...opts?.secrets };
	const topologyRead = await topologyForDoctor(store);
	const membershipRead = (() => {
		try {
			return {
				ok: true as const,
				memberships: readSnapshotItems(
					"Memberships",
					store.snapshot.memberships,
					DOCTOR_MAX_MEMBERSHIPS,
				),
			};
		} catch (error) {
			return {
				ok: false as const,
				error: error instanceof Error ? error.message : String(error),
			};
		}
	})();

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

	if (!topologyRead.topology) {
		checks.push({
			id: "project",
			name: "Project",
			status: "fail",
			detail: `Normalized topology could not be read: ${topologyRead.error}`,
			remediation: "Run clearance schema store-v2 verify before serving traffic",
		});
	} else if (topologyRead.topology.projects.length === 0) {
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
			detail: `Project ${topologyRead.topology.projects[0].name}`,
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

	if (!membershipRead.ok) {
		checks.push({
			id: "runtime-management-parity",
			name: "Runtime / management parity",
			status: "fail",
			detail: `Cannot evaluate management memberships: ${membershipRead.error}`,
			remediation: "Reduce or repair the management membership snapshot before serving traffic",
		});
	}

	if (store.storeV2) {
		try {
			const status = await store.storeV2.status();
			const collectionSummary = Object.entries(status.collections)
				.map(
					([name, collection]) =>
						`${name}=${collection.snapshotCount}/${collection.relationalCount ?? 0}`,
				)
				.join(", ");
			if (status.phase === "absent") {
				checks.push({
					id: "store-v2-shadow",
					name: "Normalized management shadow",
					status: "warn",
					detail: "Store-v2 has not been applied; the JSONB snapshot remains authoritative",
					remediation:
						"Run clearance schema store-v2 plan, then apply with --yes after review",
				});
			} else if (status.phase === "disabled") {
				checks.push({
					id: "store-v2-shadow",
					name: "Normalized management shadow",
					status: "warn",
					detail: `Store-v2 dual-write is disabled; parity=${status.consistent}; ${collectionSummary}`,
					remediation:
						"Run clearance schema store-v2 plan and reapply with --yes to reconcile and resume dual-write",
				});
			} else if (status.phase === "hybrid") {
				checks.push({
					id: "store-v2-shadow",
					name: "Normalized management store",
					status: status.consistent ? "pass" : "fail",
					detail: status.consistent
						? `Relational authority verified for ${status.authoritativeCollections.join(", ")} at revision ${status.snapshotRevision}; ${collectionSummary}`
						: `Relational-authority divergence detected across ${Object.entries(status.collections)
								.filter(([, collection]) => !collection.consistent)
								.map(([name]) => name)
								.join(", ") || "revision metadata"}`,
					remediation: status.consistent
						? undefined
						: "Stop mutations and run clearance schema store-v2 verify before rollback or reconciliation",
				});
			} else {
				checks.push({
					id: "store-v2-shadow",
					name: "Normalized management shadow",
					status: status.consistent ? "pass" : "fail",
					detail: status.consistent
						? `Shadow parity verified at revision ${status.snapshotRevision}; ${collectionSummary}`
						: `Shadow divergence detected across ${Object.entries(status.collections)
								.filter(([, collection]) => !collection.consistent)
								.map(([name]) => name)
								.join(", ") || "revision metadata"}`,
					remediation: status.consistent
						? undefined
						: "Stop mutations and run clearance schema store-v2 verify before reconciling",
				});
			}
		} catch {
			checks.push({
				id: "store-v2-shadow",
				name: "Normalized management shadow",
				status: "fail",
				detail: "Store-v2 status could not be verified",
				remediation:
					"Run clearance schema store-v2 status and inspect the Postgres schema",
			});
		}
	}

	if (store.deliveryControl) {
		try {
			const readiness = await store.deliveryControl.readiness();
			checks.push({
				id: "delivery-readiness",
				name: "Durable delivery readiness",
				status: readiness.ready ? "pass" : "fail",
				detail: readiness.ready
					? `${readiness.workers.freshReady} fresh workers; webhook endpoints active=${readiness.webhookEndpoints.active}, disabled=${readiness.webhookEndpoints.disabled}, tested=${readiness.webhookEndpoints.testSucceededActive}`
					: `Delivery blockers: ${readiness.reasons.join(", ") || "unknown"}; webhook endpoint tests untested=${readiness.webhookEndpoints.untestedActive}, pending=${readiness.webhookEndpoints.testPendingActive}, failed=${readiness.webhookEndpoints.testFailedActive}, succeeded=${readiness.webhookEndpoints.testSucceededActive}`,
				remediation: readiness.ready
					? undefined
					: readiness.webhookEndpoints.untestedActive > 0 ||
							readiness.webhookEndpoints.testPendingActive > 0 ||
							readiness.webhookEndpoints.testFailedActive > 0
						? "Run clearance delivery endpoints test for every active endpoint and confirm its test job reaches delivered, then restore other reported dependencies"
						: "Run clearance delivery readiness --json and restore the reported worker, schema, or key dependency",
			});
		} catch {
			checks.push({
				id: "delivery-readiness",
				name: "Durable delivery readiness",
				status: "fail",
				detail: "Delivery readiness could not be verified",
				remediation: "Run clearance delivery readiness --json and inspect the PostgreSQL delivery schema",
			});
		}
	}

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
				if (!membershipRead.ok) {
					// The bounded snapshot read above has already recorded the
					// fail-closed parity diagnostic.
				} else if (!topologyRead.topology) {
					checks.push({
						id: "runtime-management-parity",
						name: "Runtime / management parity",
						status: "fail",
						detail: `Cannot evaluate management topology: ${topologyRead.error}`,
						remediation: "Run clearance schema store-v2 verify before serving traffic",
					});
				} else {
					try {
						const managementPrincipals = await principalsForDoctor(
							store,
							topologyRead.topology.environments,
						);
						const runtimeUsers = await readRuntimeRows<{ id: string; email: string }>(
							pool,
							"Runtime users",
							`select id, email from "user" where email <> 'operator@clearance.local' order by id asc`,
						);
						const runtimeOrgs = await readRuntimeRows<{ id: string }>(
							pool,
							"Runtime organizations",
							`select id from organization order by id asc`,
						);
						const runtimeMemberships = await readRuntimeRows<{
							organizationId: string;
							userId: string;
						}>(
							pool,
							"Runtime memberships",
							`select "organizationId", "userId" from member order by "organizationId" asc, "userId" asc`,
						);
						const runtimeUserIds = new Set(runtimeUsers.map((user) => user.id));
						const runtimeOrgIds = new Set(runtimeOrgs.map((org) => org.id));
						const runtimeMembershipKeys = new Set(
							runtimeMemberships.map((member) =>
								membershipKey(member.organizationId, member.userId),
							),
						);
						const managementUserIds = new Set(
							managementPrincipals.map((principal) => principal.id),
						);
						const managementOrgIds = new Set(
							topologyRead.topology.organizations
								.filter((organization) => organization.status !== "archived")
								.map((organization) => organization.id),
						);
						const missingUsers = runtimeUsers.filter(
							(user) => !managementUserIds.has(user.id),
						);
						const missingOrgs = runtimeOrgs.filter(
							(org) => !managementOrgIds.has(org.id),
						);
						const managementOnlyUsers = managementPrincipals.filter(
							(principal) => !runtimeUserIds.has(principal.id),
						);
						const managementOnlyOrgs = topologyRead.topology.organizations.filter(
							(organization) =>
								organization.status !== "archived" && !runtimeOrgIds.has(organization.id),
						);
						const missingRuntimeMemberships = membershipRead.memberships.filter(
							(membership) =>
								membership.status === "active" &&
								!runtimeMembershipKeys.has(
									membershipKey(membership.organizationId, membership.principalId),
								),
						);
						const managementMembershipKeys = new Set(
							membershipRead.memberships
								.filter((membership) => membership.status === "active")
								.map((membership) =>
									membershipKey(membership.organizationId, membership.principalId),
								),
						);
						const missingManagementMemberships = runtimeMemberships.filter(
							(member) =>
								!managementMembershipKeys.has(
									membershipKey(member.organizationId, member.userId),
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
									? `${runtimeUsers.length} users, ${runtimeOrgs.length} organizations, and ${runtimeMemberships.length} memberships match bidirectionally`
									: `Drift: runtime-only users=${missingUsers.length}, orgs=${missingOrgs.length}, memberships=${missingManagementMemberships.length}; management-only users=${managementOnlyUsers.length}, orgs=${managementOnlyOrgs.length}, memberships=${missingRuntimeMemberships.length}`,
							remediation:
								parityOk
									? undefined
									: "Repair the runtime-to-management identity bridge before serving traffic",
						});
					} catch (error) {
						checks.push({
							id: "runtime-management-parity",
							name: "Runtime / management parity",
							status: "fail",
							detail: `Parity check failed: ${error instanceof Error ? error.message : String(error)}`,
							remediation: "Repair the runtime-to-management identity bridge before serving traffic",
						});
					}
				}
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
			remediation: `export CLEARANCE_BASE_URL=${DEFAULT_CLEARANCE_BASE_URL}`,
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
