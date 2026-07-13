import type { Command } from "commander";
import { ClearanceError } from "@clearance/management";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { requestManagementApi, type ApiSession } from "./api-client.js";
import type { GlobalOpts } from "./output.js";

export const HOST_LOCAL_COMMANDS = new Map<string, string>([
	["dev", "prints and launches host development paths"],
	["users export", "writes a bounded export to a caller-selected host path"],
	["orgs members import", "reads a caller-selected host file"],
	["events export", "writes a bounded export to a caller-selected host path"],
	["events tail", "owns a long-running terminal stream"],
	["import legacy", "reads a migration fixture from the host"],
	["migration plan", "creates host migration artifacts"],
	["migration run", "executes a host migration artifact"],
	["migration verify", "verifies a host migration fixture"],
	["migration rollback", "rolls back a host migration fixture"],
	["migration status", "inspects host migration artifacts"],
	["backup create", "runs database tooling and writes a host backup"],
	["backup verify", "verifies a host backup artifact"],
	["backup restore", "runs database tooling against the selected host"],
	["upgrade check", "inspects host deployment and database state"],
	["upgrade plan", "creates signed host upgrade artifacts"],
	["upgrade apply", "runs host deployment and database upgrade tooling"],
	["upgrade verify", "verifies host upgrade artifacts and database state"],
	["upgrade rollback", "restores or verifies a host database backup"],
	["schema status", "inspects the directly selected runtime database"],
	["schema generate", "writes SQL to a caller-selected host path"],
	["schema migrate", "runs migrations against the directly selected runtime database"],
]);

export const REMOTE_COMMANDS = new Set([
	"init", "doctor", "overview",
	"project list", "project inspect", "project create",
	"env list", "env inspect", "env create", "env promote",
	"users list", "users inspect", "users create", "users update", "users disable", "users delete",
	"orgs list", "orgs inspect", "orgs create", "orgs update", "orgs archive",
	"orgs members list", "orgs members add", "orgs members update", "orgs members remove",
	"events list", "events inspect", "events replay",
	"keys list", "keys create", "keys rotate", "keys revoke",
	"sessions list", "sessions revoke",
	"roles list", "roles validate", "roles create", "roles update",
	"sso create", "sso configure", "sso test", "sso list", "sso setup-link", "sso rotate", "sso disable",
	"scim create", "scim test", "scim list", "scim setup-link", "scim rotate", "scim disable", "scim replay",
	"readiness check", "readiness report",
	"config get", "config set", "config validate", "config diff",
]);

export type CommandExecution = "authentication" | "remote-api" | "host-local" | "unavailable";

export function classifyCommandPath(path: string): CommandExecution {
	if (path === "login" || path === "logout" || path === "whoami") return "authentication";
	if (HOST_LOCAL_COMMANDS.has(path)) return "host-local";
	if (REMOTE_COMMANDS.has(path)) return "remote-api";
	return "unavailable";
}

function error(code: string, message: string, remediation: string): ClearanceError {
	return new ClearanceError({ code, message, stage: "cli.dispatch", remediation });
}

function query(path: string, values: Record<string, unknown>): `/v1/${string}` {
	const params = new URLSearchParams();
	for (const [key, value] of Object.entries(values)) {
		if (value !== undefined && value !== false && value !== "") params.set(key, String(value));
	}
	return `${path}${params.size ? `?${params}` : ""}` as `/v1/${string}`;
}

function body(values: Record<string, unknown>): Record<string, unknown> {
	return Object.fromEntries(Object.entries(values).filter(([, value]) => value !== undefined));
}

export function commandPath(command: Command): string {
	const names: string[] = [];
	let current: Command | null = command;
	while (current?.parent) {
		names.unshift(current.name());
		current = current.parent;
	}
	return names.join(" ");
}

export function isHostLocalCommand(path: string): boolean {
	return HOST_LOCAL_COMMANDS.has(path);
}

function requireRemoteMutation(global: GlobalOpts, path: string): void {
	if (global.dryRun) {
		throw error(
			"CLI_REMOTE_DRY_RUN_UNSUPPORTED",
			`${path} does not yet expose a server-side dry-run contract.`,
			"Use the command without --dry-run, or choose --local-direct for a local development preview.",
		);
	}
}

function requireConfirmation(global: GlobalOpts, code: string, label: string): void {
	if (!global.yes && !global.dryRun) {
		throw error(code, `${label} requires --yes.`, "Review the target, then pass --yes to confirm.");
	}
}

function requireLiveTestMode(global: GlobalOpts, code: string, label: string): void {
	if (global.dryRun) {
		throw error(code, `${label} cannot combine --live with --dry-run.`, "Remove --dry-run, review the live target, then pass --yes to confirm.");
	}
	requireConfirmation(global, code, label);
}

export async function dispatchRemoteCommand(
	session: ApiSession,
	path: string,
	args: unknown[],
	opts: Record<string, unknown>,
	global: GlobalOpts,
): Promise<unknown> {
	const id = typeof args[0] === "string" ? encodeURIComponent(args[0]) : "";
	switch (path) {
		case "init":
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "POST", path: "/v1/init", body: body({ name: opts.name, environment: opts.environment }) });
		case "doctor": return requestManagementApi(session, { path: "/v1/doctor" });
		case "overview": return requestManagementApi(session, { path: "/v1/overview" });
		case "project list": return requestManagementApi(session, { path: "/v1/projects" });
		case "project inspect": return requestManagementApi(session, { path: id ? `/v1/projects/${id}` : "/v1/projects/current" });
		case "project create":
			return requestManagementApi(session, { method: "POST", path: "/v1/projects", body: { name: opts.name, dryRun: global.dryRun } });
		case "env list": return requestManagementApi(session, { path: "/v1/environments" });
		case "env inspect": return requestManagementApi(session, { path: id ? `/v1/environments/${id}` : "/v1/environments/current" });
		case "env create":
			return requestManagementApi(session, { method: "POST", path: "/v1/environments", body: body({ name: opts.name, projectId: opts.projectId, kind: opts.kind, dryRun: global.dryRun }) });
		case "env promote":
			return requestManagementApi(session, { method: "POST", path: "/v1/environments/promote", body: body({ to: opts.to, from: opts.from, dryRun: global.dryRun || !global.yes, confirm: global.yes && !global.dryRun }) });
		case "users list": return requestManagementApi(session, { path: query("/v1/users", { limit: opts.limit, cursor: opts.cursor }) });
		case "users inspect": return requestManagementApi(session, { path: `/v1/users/${id}` });
		case "users create":
			return requestManagementApi(session, { method: "POST", path: "/v1/users", body: body({ email: opts.email, name: opts.name, password: opts.password, dryRun: global.dryRun }) });
		case "users update":
			return requestManagementApi(session, { method: "PATCH", path: `/v1/users/${id}`, body: body({ email: opts.email, name: opts.name, status: opts.status, dryRun: global.dryRun }) });
		case "users disable":
			return requestManagementApi(session, { method: "POST", path: `/v1/users/${id}/disable`, body: { dryRun: global.dryRun } });
		case "users delete":
			requireConfirmation(global, "USER_DELETE_CONFIRM_REQUIRED", "User deletion");
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "DELETE", path: `/v1/users/${id}` });
		case "orgs list": return requestManagementApi(session, { path: query("/v1/organizations", { limit: opts.limit, cursor: opts.cursor }) });
		case "orgs inspect": return requestManagementApi(session, { path: `/v1/organizations/${id}` });
		case "orgs create":
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "POST", path: "/v1/organizations", body: body({ name: opts.name, slug: opts.slug, ownerUserId: opts.ownerUser }) });
		case "orgs update":
			return requestManagementApi(session, { method: "PATCH", path: `/v1/organizations/${id}`, body: body({ name: opts.name, slug: opts.slug, dryRun: global.dryRun }) });
		case "orgs archive":
			return requestManagementApi(session, { method: "POST", path: `/v1/organizations/${id}/archive`, body: { dryRun: global.dryRun || !global.yes, confirm: global.yes && !global.dryRun } });
		case "orgs members list": return requestManagementApi(session, { path: `/v1/organizations/${encodeURIComponent(String(opts.org))}/members` });
		case "orgs members add":
			return requestManagementApi(session, { method: "POST", path: `/v1/organizations/${encodeURIComponent(String(opts.org))}/members`, body: body({ principalId: opts.user, role: opts.role, dryRun: global.dryRun }) });
		case "orgs members update": {
			if (!opts.member) throw error("CLI_REMOTE_MEMBER_ID_REQUIRED", "Remote member update requires --member.", "List organization members and pass the membership id with --member.");
			return requestManagementApi(session, { method: "PATCH", path: `/v1/organizations/${encodeURIComponent(String(opts.org))}/members/${encodeURIComponent(String(opts.member))}`, body: { role: opts.role, dryRun: global.dryRun } });
		}
		case "orgs members remove": {
			requireConfirmation(global, "MEMBER_REMOVE_CONFIRM_REQUIRED", "Membership removal");
			if (!opts.member) throw error("CLI_REMOTE_MEMBER_ID_REQUIRED", "Remote member removal requires --member.", "List organization members and pass the membership id with --member.");
			return requestManagementApi(session, { method: "DELETE", path: `/v1/organizations/${encodeURIComponent(String(opts.org))}/members/${encodeURIComponent(String(opts.member))}`, body: { dryRun: global.dryRun } });
		}
		case "events list": return requestManagementApi(session, { path: query("/v1/events", { limit: opts.limit, cursor: opts.cursor, action: opts.action, actor: opts.actor, outcome: opts.outcome }) });
		case "events inspect": return requestManagementApi(session, { path: `/v1/events/${id}` });
		case "events replay": return requestManagementApi(session, { method: "POST", path: "/v1/events/replay", body: { id: args[0], dryRun: global.dryRun || !global.yes, confirm: global.yes && !global.dryRun } });
		case "keys list": return requestManagementApi(session, { path: query("/v1/keys", { includeRevoked: opts.includeRevoked }) });
		case "keys create":
			return requestManagementApi(session, { method: "POST", path: "/v1/keys", body: { name: opts.name, scopes: opts.scope, dryRun: global.dryRun } });
		case "keys rotate":
			requireConfirmation(global, "API_KEY_CONFIRMATION_REQUIRED", "API key rotation");
			return requestManagementApi(session, { method: "POST", path: `/v1/keys/${id}/rotate`, body: { dryRun: global.dryRun } });
		case "keys revoke":
			requireConfirmation(global, "API_KEY_CONFIRMATION_REQUIRED", "API key revocation");
			return requestManagementApi(session, { method: "POST", path: `/v1/keys/${id}/revoke`, body: { dryRun: global.dryRun } });
		case "sessions list": return requestManagementApi(session, { path: query("/v1/sessions", { limit: opts.limit, cursor: opts.cursor, userId: opts.user, status: opts.status }) });
		case "sessions revoke":
			requireConfirmation(global, "SESSION_REVOKE_CONFIRM_REQUIRED", "Session revocation");
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "POST", path: `/v1/sessions/${id}/revoke` });
		case "roles list": return requestManagementApi(session, { path: "/v1/roles" });
		case "roles validate": return requestManagementApi(session, { method: "POST", path: "/v1/roles/validate", body: body({ name: opts.name, slug: opts.slug, permissions: opts.permission }) });
		case "roles create":
			return requestManagementApi(session, { method: "POST", path: "/v1/roles", body: body({ name: opts.name, slug: opts.slug, description: opts.description, permissions: opts.permission, dryRun: global.dryRun }) });
		case "roles update":
			return requestManagementApi(session, { method: "PATCH", path: `/v1/roles/${id}`, body: body({ name: opts.name, description: opts.description, permissions: opts.permission, dryRun: global.dryRun }) });
		case "sso create":
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "POST", path: "/v1/sso", body: body({ organizationId: opts.org, provider: opts.provider, protocol: opts.protocol, issuer: opts.issuer, audience: opts.audience, domain: opts.domain, samlEntryPoint: opts.entryPoint, samlCertificate: opts.certificate ? readFileSync(resolve(String(opts.certificate)), "utf8") : undefined }) });
		case "sso configure":
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "PATCH", path: `/v1/sso/${id}`, body: body({ issuer: opts.issuer, audience: opts.audience, domain: opts.domain }) });
		case "sso test":
			if (opts.live && opts.fixture) throw error("SSO_TEST_MODE_CONFLICT", "--live and --fixture are mutually exclusive.", "Use one SSO test mode.");
			if (opts.live) requireLiveTestMode(global, "SSO_LIVE_CONFIRM_REQUIRED", "Live SSO conformance");
			return requestManagementApi(session, { method: "POST", path: `/v1/sso/${id}/test`, body: body({ fixture: opts.fixture, live: opts.live }) });
		case "sso list": return requestManagementApi(session, { path: query("/v1/sso", { organizationId: opts.org }) });
		case "sso setup-link":
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "POST", path: "/v1/sso/setup-links", body: { organizationId: opts.org } });
		case "sso rotate":
			requireConfirmation(global, "SSO_CONFIRM_REQUIRED", "SSO credential rotation");
			return requestManagementApi(session, { method: "POST", path: `/v1/sso/${id}/rotate`, body: { dryRun: global.dryRun } });
		case "sso disable":
			requireConfirmation(global, "SSO_DISABLE_CONFIRM_REQUIRED", "SSO disable");
			return requestManagementApi(session, { method: "POST", path: `/v1/sso/${id}/disable`, body: { dryRun: global.dryRun } });
		case "scim create":
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "POST", path: "/v1/scim", body: body({ organizationId: opts.org, provider: opts.provider, endpoint: opts.endpoint }) });
		case "scim test":
			if (opts.live && opts.fixture) throw error("SCIM_TEST_MODE_CONFLICT", "--live and --fixture are mutually exclusive.", "Use one SCIM test mode.");
			if (opts.live) requireLiveTestMode(global, "SCIM_LIVE_CONFIRM_REQUIRED", "Live SCIM conformance");
			return requestManagementApi(session, { method: "POST", path: `/v1/scim/${id}/test`, body: body({ fixture: opts.fixture, live: opts.live, dryRun: !opts.apply }) });
		case "scim list": return requestManagementApi(session, { path: query("/v1/scim", { organizationId: opts.org }) });
		case "scim setup-link":
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "POST", path: "/v1/scim/setup-links", body: { organizationId: opts.org } });
		case "scim rotate":
			requireConfirmation(global, "SCIM_CONFIRM_REQUIRED", "SCIM credential rotation");
			return requestManagementApi(session, { method: "POST", path: `/v1/scim/${id}/rotate`, body: { dryRun: global.dryRun } });
		case "scim disable":
			requireConfirmation(global, "SCIM_DISABLE_CONFIRM_REQUIRED", "SCIM disable");
			return requestManagementApi(session, { method: "POST", path: `/v1/scim/${id}/disable`, body: { dryRun: global.dryRun } });
		case "scim replay":
			return requestManagementApi(session, { method: "POST", path: `/v1/scim/traces/${encodeURIComponent(String(args[0]))}/replay`, body: { dryRun: global.dryRun || !global.yes, confirm: global.yes && !global.dryRun } });
		case "readiness check":
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "POST", path: "/v1/readiness/check", body: { organizationId: opts.org } });
		case "readiness report": return requestManagementApi(session, { path: `/v1/readiness/${encodeURIComponent(String(opts.org))}` });
		case "config get": return requestManagementApi(session, { path: query("/v1/config", { key: args[0] }) });
		case "config set": return requestManagementApi(session, { method: "PATCH", path: `/v1/config/${encodeURIComponent(String(args[0]))}`, body: { value: args[1], dryRun: global.dryRun } });
		case "config validate": {
			const config = opts.file ? JSON.parse(readFileSync(resolve(String(opts.file)), "utf8")) : undefined;
			return requestManagementApi(session, { method: "POST", path: "/v1/config/validate", body: body({ config }) });
		}
		case "config diff": {
			const config = JSON.parse(readFileSync(resolve(String(opts.file)), "utf8"));
			return requestManagementApi(session, { method: "POST", path: "/v1/config/diff", body: { config } });
		}
		default:
			throw error(
				"CLI_REMOTE_COMMAND_UNAVAILABLE",
				`${path} has no versioned management API contract in this release.`,
				"Upgrade the Clearance API, or use --local-direct only for a development or host-local workflow.",
			);
	}
}
