import type { DataStoreSnapshot } from "../types/resources.js";

export const STORE_SCHEMA_VERSION = 1;
export const CLEARANCE_RELEASE_VERSION = "0.2.1";

export function emptySnapshot(
	config: Record<string, string> = {},
): DataStoreSnapshot {
	return {
		version: STORE_SCHEMA_VERSION,
		releaseVersion: CLEARANCE_RELEASE_VERSION,
		projects: [],
		environments: [],
		principals: [],
		organizations: [],
		memberships: [],
		identityConnections: [],
		directoryConnections: [],
		roles: [],
		events: [],
		traces: [],
		readinessReports: [],
		migrations: [],
		backups: [],
		sessions: [],
		apiKeys: [],
		setupLinks: [],
		meta: {
			schemaVersion: STORE_SCHEMA_VERSION,
			config,
		},
	};
}

/** Normalize older snapshots missing newer collections, preserving identity. */
export function normalizeSnapshot(data: DataStoreSnapshot): DataStoreSnapshot {
	if (!Array.isArray(data.setupLinks)) data.setupLinks = [];
	if (!Array.isArray(data.roles)) data.roles = [];
	if (!Array.isArray(data.apiKeys)) data.apiKeys = [];
	return data;
}

/** Clone with the same JSON semantics used by durable snapshot persistence. */
export function cloneSnapshot(data: DataStoreSnapshot): DataStoreSnapshot {
	return JSON.parse(JSON.stringify(data)) as DataStoreSnapshot;
}

export function snapshotResourceCounts(
	data: DataStoreSnapshot,
): Record<string, number> {
	return {
		projects: data.projects.length,
		environments: data.environments.length,
		principals: data.principals.length,
		organizations: data.organizations.length,
		memberships: data.memberships.length,
		identityConnections: data.identityConnections.length,
		directoryConnections: data.directoryConnections.length,
		roles: data.roles.length,
		setupLinks: data.setupLinks.length,
		events: data.events.length,
		traces: data.traces.length,
		migrations: data.migrations.length,
		sessions: data.sessions.filter((session) => session.status === "active").length,
		apiKeys: data.apiKeys.length,
	};
}
