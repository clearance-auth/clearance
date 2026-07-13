import { createHash } from "node:crypto";
import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { ReadinessCheck, ReadinessReport } from "../types/resources.js";
import { recordEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { inspectOrganization } from "./core.js";

function fp(obj: unknown): string {
	return createHash("sha256").update(JSON.stringify(obj)).digest("hex").slice(0, 16);
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
	const sso = store.snapshot.identityConnections.filter(
		(c) => c.organizationId === organizationId,
	);
	const scim = store.snapshot.directoryConnections.filter(
		(c) => c.organizationId === organizationId,
	);
	const ssoTraces = store.snapshot.traces.filter(
		(t) => t.organizationId === organizationId && t.subsystem === "sso",
	);
	const scimTraces = store.snapshot.traces.filter(
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
		const lastTrace = ssoTraces[0];
		const lastSimPass = ssoTraces.find(
			(t) => t.outcome === "pass" && (t.mode ?? "simulation") === "simulation",
		);
		const lastLivePass = ssoTraces.find(
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
		const lastTrace = scimTraces[0];
		const lastSimPass = scimTraces.find(
			(t) => t.outcome === "pass" && (t.mode ?? "simulation") === "simulation",
		);
		const lastLivePass = scimTraces.find(
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

	const members = store.snapshot.memberships.filter(
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
		signature: fp({ organizationId, checks, overall, liveCertified }),
	};

	store.mutate((data) => {
		data.readinessReports.unshift(report);
	});
	recordEvent(store, {
		actor: "system",
		action: "readiness.check",
		subjectType: "organization",
		subjectId: organizationId,
		outcome: overall === "blocked" ? "failure" : "success",
		source: "cli",
		organizationId,
		message: `Readiness ${overall} (conformance=${report.conformance.mode}, liveCertified=${report.conformance.liveCertified})`,
		metadata: {
			reportId: report.id,
			overall,
			checkCount: checks.length,
			liveCertified: report.conformance.liveCertified,
		},
	});

	return report;
}

export function getLatestReadiness(
	store: ManagementStore,
	organizationId: string,
): ReadinessReport {
	const report = store.snapshot.readinessReports.find(
		(r) => r.organizationId === organizationId,
	);
	if (!report) {
		throw new ClearanceError({
			code: "READINESS_NOT_FOUND",
			message: "No readiness report — run clearance readiness check",
			stage: "readiness.report",
			status: 404,
		});
	}
	return report;
}
