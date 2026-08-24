import { createHash } from "node:crypto";
import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DataStoreSnapshot, ReadinessCheck, ReadinessReport } from "../types/resources.js";
import { recordEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { inspectOrganization, inspectOrganizationAuthoritative } from "./core.js";
import type { ResourceScope } from "./scope.js";

function fp(obj: unknown): string {
	return createHash("sha256").update(JSON.stringify(obj)).digest("hex").slice(0, 16);
}

/**
 * Canonical state digest for a readiness report. Keep the full normalized
 * enterprise configuration (including credential fingerprints and revisions)
 * rather than a report's display-oriented check summary, so any mutation makes
 * an earlier report provably stale.
 */
export function enterpriseReadinessStateFingerprint(
	snapshot: DataStoreSnapshot,
	organizationId: string,
): string {
	const ordered = <T extends { id: string }>(items: readonly T[]) =>
		items.slice().sort((left, right) => left.id.localeCompare(right.id));
	return createHash("sha256").update(JSON.stringify({
		organizationId,
		sso: ordered(snapshot.ssoConnections.filter((connection) => connection.organizationId === organizationId)).map((connection) => ({
			id: connection.id, protocol: connection.protocol, provider: connection.provider,
			status: connection.status, domains: [...connection.domains].sort(), issuer: connection.issuer ?? null,
			audience: connection.audience ?? null, metadataUrl: connection.metadataUrl ?? null,
			clientId: connection.clientId ?? null, clientSecretFingerprint: connection.clientSecretFingerprint ?? null,
			clientSecretKeyId: connection.clientSecretKeyId ?? null, samlEntryPoint: connection.samlEntryPoint ?? null,
			samlCertificateFingerprint: connection.samlCertificateFingerprint ?? null,
			attributeMapping: connection.attributeMapping, updatedAt: connection.updatedAt,
		})),
		scim: ordered(snapshot.scimConnections.filter((connection) => connection.organizationId === organizationId)).map((connection) => ({
			id: connection.id, provider: connection.provider, status: connection.status, endpoint: connection.endpoint,
			bearerTokenFingerprint: connection.bearerTokenFingerprint ?? null,
			bearerTokenKeyId: connection.bearerTokenKeyId ?? null,
			deprovisioningPolicy: connection.deprovisioningPolicy, updatedAt: connection.updatedAt,
		})),
		memberships: ordered(snapshot.memberships.filter((membership) => membership.organizationId === organizationId)).map((membership) => ({
			id: membership.id, principalId: membership.principalId, role: membership.role,
			status: membership.status, updatedAt: membership.updatedAt,
		})),
		traces: ordered(snapshot.traces.filter((trace) => trace.organizationId === organizationId)).map((trace) => ({
			id: trace.id, connectionId: trace.connectionId, subsystem: trace.subsystem, mode: trace.mode ?? "simulation",
			stage: trace.stage, outcome: trace.outcome, createdAt: trace.createdAt,
		})),
	})).digest("hex");
}

/**
 * Enterprise readiness from control-plane state.
 * Fixture/synthetic SSO+SCIM tests are labeled simulation and never set liveCertified.
 */
export function runReadinessCheck(
	store: ManagementStore,
	organizationId: string,
): ReadinessReport {
	const org = inspectOrganization(store, organizationId);
	const report = buildReadinessReport(store.snapshot, organizationId, org);
	persistReadinessReport(store, report);
	return report;
}

/** Run readiness against normalized topology after cutover. */
export async function runReadinessCheckAuthoritative(
	store: ManagementStore,
	organizationId: string,
	scope: ResourceScope,
): Promise<ReadinessReport> {
	if (!store.storeV2Topology?.authoritative) {
		const org = await inspectOrganizationAuthoritative(store, organizationId, scope);
		const report = buildReadinessReport(store.snapshot, organizationId, org);
		persistReadinessReport(store, report);
		return report;
	}
	if (!store.mutateCoordinated) {
		throw new ClearanceError({
			code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
			message: "Relational topology authority requires a coordinated transaction",
			stage: "readiness.check",
			status: 500,
		});
	}
	return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const org = topology
			? await topology.lockOrganization({ scope, id: organizationId })
			: null;
		if (!org || org.status === "archived") {
			throw new ClearanceError({
				code: "ORG_NOT_FOUND",
				message: "Organization not found",
				stage: "orgs.inspect",
				status: 404,
			});
		}
		const report = buildReadinessReport(data, organizationId, org);
		data.readinessReports.unshift(report);
		appendAudit(readinessAuditInput(report));
		return report;
	});
}

function buildReadinessReport(
	snapshot: DataStoreSnapshot,
	organizationId: string,
	org: { id: string; name: string; slug: string },
): ReadinessReport {
	const enabled = <T extends { status: string }>(connection: T) =>
		connection.status === "active" || connection.status === "testing";
	const sso = snapshot.ssoConnections.filter(
		(c) => c.organizationId === organizationId && enabled(c),
	);
	const scim = snapshot.scimConnections.filter(
		(c) => c.organizationId === organizationId && enabled(c),
	);
	const ssoTraces = snapshot.traces.filter(
		(t) => t.organizationId === organizationId && t.subsystem === "sso",
	);
	const scimTraces = snapshot.traces.filter(
		(t) => t.organizationId === organizationId && t.subsystem === "scim",
	);

	const checks: ReadinessCheck[] = [];

	checks.push({
		id: "org.exists",
		name: "Organization present",
		status: "pass",
		detail: org.name,
		fingerprint: fp({ id: org.id, slug: org.slug }),
	});

	if (sso.length === 0) {
		checks.push({
			id: "sso.connection",
			name: "SSO connection",
			status: "fail",
			detail: "No SSO connection configured",
		});
	} else {
		const primary = sso[0];
		checks.push({
			id: "sso.connection",
			name: "SSO connection",
			status: primary.issuer || primary.protocol === "saml" ? "pass" : "warn",
			detail: `${primary.protocol}/${primary.provider} (${primary.status})`,
			fingerprint: fp({
				id: primary.id,
				issuer: primary.issuer,
				audience: primary.audience,
				domains: primary.domains,
			}),
		});
		const currentTraces = ssoTraces.filter(
			(trace) =>
				trace.connectionId === primary.id &&
				new Date(trace.createdAt).getTime() >= new Date(primary.updatedAt).getTime(),
		);
		const lastTrace = currentTraces[0];
		const lastSimPass = currentTraces.find(
			(t) => t.outcome === "pass" && (t.mode ?? "simulation") === "simulation",
		);
		const lastLivePass = currentTraces.find(
			(t) => t.outcome === "pass" && t.mode === "live",
		);
		if (lastLivePass) {
			checks.push({
				id: "sso.test",
				name: "SSO conformance test",
				status: "pass",
				detail: `Live pass stage ${lastLivePass.stage}`,
				simulation: false,
			});
		} else if (lastSimPass) {
			checks.push({
				id: "sso.test",
				name: "SSO conformance test (simulation)",
				status: "warn",
				detail: `Simulation pass at ${lastSimPass.stage} — not live IdP conformance`,
				simulation: true,
			});
		} else {
			checks.push({
				id: "sso.test",
				name: "SSO conformance test",
				status: "fail",
				detail: lastTrace
					? `Last trace ${lastTrace.outcome} at ${lastTrace.stage}`
					: "No successful SSO test trace",
				simulation: true,
			});
		}
	}

	if (scim.length === 0) {
		checks.push({
			id: "scim.connection",
			name: "SCIM connection",
			status: "fail",
			detail: "No SCIM connection configured",
		});
	} else {
		const primary = scim[0];
		checks.push({
			id: "scim.connection",
			name: "SCIM connection",
			status: "pass",
			detail: `${primary.provider} (${primary.status})`,
			fingerprint: fp({
				id: primary.id,
				endpoint: primary.endpoint,
				policy: primary.deprovisioningPolicy,
			}),
		});
		const currentTraces = scimTraces.filter(
			(trace) =>
				trace.connectionId === primary.id &&
				new Date(trace.createdAt).getTime() >= new Date(primary.updatedAt).getTime(),
		);
		const lastTrace = currentTraces[0];
		const lastSimPass = currentTraces.find(
			(t) => t.outcome === "pass" && (t.mode ?? "simulation") === "simulation",
		);
		const lastLivePass = currentTraces.find(
			(t) => t.outcome === "pass" && t.mode === "live",
		);
		if (lastLivePass) {
			checks.push({
				id: "scim.test",
				name: "SCIM dry-run / test",
				status: "pass",
				detail: `Live pass stage ${lastLivePass.stage}`,
				simulation: false,
			});
		} else if (lastSimPass) {
			checks.push({
				id: "scim.test",
				name: "SCIM dry-run / test (simulation)",
				status: "warn",
				detail: `Simulation pass at ${lastSimPass.stage} — not live directory conformance`,
				simulation: true,
			});
		} else {
			checks.push({
				id: "scim.test",
				name: "SCIM dry-run / test",
				status: "fail",
				detail: lastTrace
					? `Last trace ${lastTrace.outcome} at ${lastTrace.stage}`
					: "No successful SCIM test trace",
				simulation: true,
			});
		}
	}

	const members = snapshot.memberships.filter(
		(m) => m.organizationId === organizationId && m.status === "active",
	);
	checks.push({
		id: "roles.mapping",
		name: "Membership / role mapping",
		status: members.length > 0 ? "pass" : "warn",
		detail:
			members.length > 0
				? `${members.length} active memberships`
				: "No members yet — map groups before production",
	});

	const remainingCustomerActions: string[] = [];
	for (const c of checks) {
		if (c.status === "fail") {
			remainingCustomerActions.push(`Resolve: ${c.name} — ${c.detail}`);
		} else if (c.status === "warn") {
			remainingCustomerActions.push(`Review: ${c.name} — ${c.detail}`);
		}
	}

	const failed = checks.some((c) => c.status === "fail");
	const warned = checks.some((c) => c.status === "warn");
	const overall = failed ? "blocked" : warned ? "attention" : "ready";

	// Fail-closed: synthetic fixture passes never claim live certification
	const liveCertified = checks.every(
		(c) =>
			c.id === "org.exists" ||
			c.id === "roles.mapping" ||
			c.id === "sso.connection" ||
			c.id === "scim.connection" ||
			(c.simulation !== true && c.status === "pass"),
	)
		? checks.some((c) => c.id === "sso.test" && c.simulation === false && c.status === "pass") &&
			checks.some((c) => c.id === "scim.test" && c.simulation === false && c.status === "pass")
		: false;

	const report: ReadinessReport = {
		id: newId("rdy"),
		organizationId,
		generatedAt: nowIso(),
		checks,
		overall,
		conformance: {
			mode: liveCertified ? "live" : "simulation",
			liveCertified: liveCertified as false | true,
			note: liveCertified
				? "Live SSO and SCIM tests recorded"
				: "Fixture/simulation checks do not constitute live IdP or directory conformance",
		},
		remainingCustomerActions,
		reportDigest: fp({ organizationId, checks, overall, liveCertified }),
		stateFingerprint: enterpriseReadinessStateFingerprint(snapshot, organizationId),
	};

	return report;
}

function readinessAuditInput(report: ReadinessReport) {
	return {
		actor: "system",
		action: "readiness.check",
		subjectType: "organization" as const,
		subjectId: report.organizationId,
		outcome: report.overall === "blocked" ? "failure" as const : "success" as const,
		source: "cli" as const,
		organizationId: report.organizationId,
		message: `Readiness ${report.overall} (conformance=${report.conformance.mode}, liveCertified=${report.conformance.liveCertified})`,
		metadata: {
			reportId: report.id,
			overall: report.overall,
			checkCount: report.checks.length,
			liveCertified: report.conformance.liveCertified,
		},
	};
}

function persistReadinessReport(store: ManagementStore, report: ReadinessReport): void {
	store.mutate((data) => {
		data.readinessReports.unshift(report);
	});
	recordEvent(store, readinessAuditInput(report));

}

export function getLatestReadiness(
	store: ManagementStore,
	organizationId: string,
): ReadinessReport {
	const report = store.snapshot.readinessReports.find(
		(r) => r.organizationId === organizationId,
	);
	if (!report) {
		return {
			id: `readiness_not_run_${organizationId}`,
			organizationId,
			generatedAt: new Date(0).toISOString(),
			overall: "blocked",
			conformance: { mode: "simulation", liveCertified: false, note: "Enterprise readiness has not been run for the current state" },
			checks: [{ id: "enterprise.readiness.not_run", name: "Enterprise readiness", status: "fail", detail: "Run readiness after configuring an enabled SSO or SCIM connection" }],
			remainingCustomerActions: ["Run an enterprise readiness check"],
			reportDigest: enterpriseReadinessStateFingerprint(store.snapshot, organizationId),
			stateFingerprint: enterpriseReadinessStateFingerprint(store.snapshot, organizationId),
			state: "not_run",
		};
	}
	const current = enterpriseReadinessStateFingerprint(store.snapshot, organizationId);
	return {
		...report,
		stateFingerprint: current,
		state: report.stateFingerprint === current ? "current" : "stale",
		...(report.stateFingerprint === current ? {} : {
			overall: "blocked" as const,
			remainingCustomerActions: [
				...report.remainingCustomerActions,
				"Run readiness again because enterprise state changed after this report",
			],
		}),
	};
}
