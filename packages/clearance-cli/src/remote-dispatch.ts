import type { Command } from "commander";
import { ClearanceError, parseConfigJson, writeExportArtifact } from "@clearance/management";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { requestManagementApi, type ApiSession } from "./api-client.js";
import { CliExitError, type GlobalOpts } from "./output.js";

export const REMOTE_COMMANDS = new Set([
	"init", "doctor", "dev", "overview",
	"project list", "project inspect", "project create",
	"env list", "env inspect", "env create", "env promote",
	"users list", "users inspect", "users create", "users update", "users disable", "users delete", "users export",
	"orgs list", "orgs inspect", "orgs create", "orgs update", "orgs archive",
	"orgs members list", "orgs members add", "orgs members update", "orgs members remove", "orgs members import",
	"events list", "events tail", "events inspect", "events export", "events replay",
	"keys list", "keys create", "keys rotate", "keys revoke",
	"sessions list", "sessions revoke",
	"roles list", "roles validate", "roles create", "roles update",
	"sso create", "sso configure", "sso test", "sso list", "sso setup-link", "sso rotate", "sso disable",
	"scim create", "scim test", "scim list", "scim setup-link", "scim rotate", "scim disable", "scim replay",
	"readiness check", "readiness report",
	"config get", "config set", "config validate", "config diff",
	"import legacy", "migration plan", "migration run", "migration verify", "migration rollback", "migration status",
	"backup create", "backup verify", "backup restore", "upgrade check", "upgrade plan", "upgrade apply", "upgrade verify", "upgrade rollback",
	"schema status", "schema generate", "schema migrate",
]);

export type CommandExecution = "authentication" | "remote-api" | "unavailable";

export function classifyCommandPath(path: string): CommandExecution {
	if (path === "login" || path === "logout" || path === "whoami") return "authentication";
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

function localFile(path: unknown, code: string, label: string): string {
	try {
		return readFileSync(resolve(String(path)), "utf8");
	} catch {
		throw error(code, `${label} could not be read.`, "Provide a readable local file and retry.");
	}
}

function configCandidate(path: unknown): Record<string, string> {
	let contents: string;
	try {
		contents = readFileSync(resolve(String(path)), "utf8");
	} catch {
		throw new ClearanceError({
			code: "CONFIG_FILE_UNREADABLE",
			message: "Config file could not be read.",
			stage: "config.parse",
			remediation: "Provide a readable JSON config file.",
		});
	}
	return parseConfigJson(contents);
}

function writeRemoteExport(
	envelope: Record<string, unknown>,
	options: Record<string, unknown>,
	collection: "users" | "events",
): Record<string, unknown> {
	const format = options.format === "jsonl" ? "jsonl" : "json";
	const values = Array.isArray(envelope[collection]) ? envelope[collection] : [];
	const contents = format === "jsonl"
		? values.length === 0
			? ""
			: `${values.map((value) => JSON.stringify(value)).join("\n")}\n`
		: `${JSON.stringify(envelope, null, 2)}\n`;
	const outputPath = writeExportArtifact(String(options.output), contents, Boolean(options.force), {
		stage: `${collection}.export`,
		existsCode: `${collection.toUpperCase()}_EXPORT_EXISTS`,
		writeFailedCode: `${collection.toUpperCase()}_EXPORT_WRITE_FAILED`,
	});
	return { ...envelope, outputPath };
}

type RemoteAuditEvent = {
	id: string;
	createdAt: string;
	action: string;
	actor: string;
	outcome: string;
};

function emitTailEvent(json: boolean, event: RemoteAuditEvent): void {
	process.stdout.write(json
		? `${JSON.stringify(event)}\n`
		: `${event.createdAt} ${event.action} actor=${event.actor} outcome=${event.outcome} id=${event.id}\n`);
}

function integerOption(
	value: unknown,
	fallback: number,
	minimum: number,
	maximum: number,
	name: string,
	code = "CLI_OPTION_INVALID",
): number {
	const parsed = value === undefined ? fallback : Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
		throw error(code, `${name} must be an integer from ${minimum} to ${maximum}.`, `Pass a valid --${name} value.`);
	}
	return parsed;
}

async function resolveRemoteMembershipId(
	session: ApiSession,
	organizationId: unknown,
	options: Record<string, unknown>,
): Promise<string> {
	if (typeof options.member === "string" && options.member.trim()) return options.member;
	if (typeof options.user !== "string" || !options.user.trim()) {
		throw error(
			"MEMBER_ID_REQUIRED",
			"Membership update or removal requires --member or --user.",
			"List organization members, then pass a membership id or principal id.",
		);
	}
	const response = await requestManagementApi<{ members?: Array<{ id: string; principalId: string; status: string }> }>(session, {
		path: `/v1/organizations/${encodeURIComponent(String(organizationId))}/members`,
	});
	const membership = (response.members ?? []).find(
		(candidate) => candidate.principalId === options.user && candidate.status !== "removed",
	);
	if (!membership) {
		throw error(
			"MEMBER_NOT_FOUND",
			"Membership not found.",
			"List organization members and verify the principal id.",
		);
	}
	return membership.id;
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

function requireRemoteMutation(global: GlobalOpts, path: string): void {
	if (global.dryRun) {
		throw error(
			"CLI_REMOTE_DRY_RUN_UNSUPPORTED",
			`${path} does not yet expose a server-side dry-run contract.`,
			"Use the command without --dry-run after reviewing the target.",
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
		case "dev": return requestManagementApi(session, { path: "/v1/dev" });
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
		case "users export": {
			const envelope = await requestManagementApi<Record<string, unknown>>(session, {
				method: "POST",
				path: "/v1/users/export",
				body: body({ format: opts.format, limit: opts.limit, status: opts.status }),
			});
			return writeRemoteExport(envelope, opts, "users");
		}
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
			const membershipId = await resolveRemoteMembershipId(session, opts.org, opts);
			return requestManagementApi(session, { method: "PATCH", path: `/v1/organizations/${encodeURIComponent(String(opts.org))}/members/${encodeURIComponent(membershipId)}`, body: { role: opts.role, dryRun: global.dryRun } });
		}
		case "orgs members remove": {
			requireConfirmation(global, "MEMBER_REMOVE_CONFIRM_REQUIRED", "Membership removal");
			const membershipId = await resolveRemoteMembershipId(session, opts.org, opts);
			return requestManagementApi(session, { method: "DELETE", path: `/v1/organizations/${encodeURIComponent(String(opts.org))}/members/${encodeURIComponent(membershipId)}`, body: { dryRun: global.dryRun } });
		}
		case "orgs members import": {
			requireConfirmation(global, "MEMBER_IMPORT_CONFIRMATION_REQUIRED", "Member import");
			const filename = String(opts.file);
			const format = opts.format ?? (filename.toLowerCase().endsWith(".json")
				? "json"
				: filename.toLowerCase().endsWith(".csv")
					? "csv"
					: undefined);
			if (format !== "json" && format !== "csv") {
				throw error("MEMBER_IMPORT_FORMAT_REQUIRED", "Member import format is required.", "Use a .json or .csv file, or pass --format json|csv.");
			}
			return requestManagementApi(session, {
				method: "POST",
				path: `/v1/organizations/${encodeURIComponent(String(opts.org))}/members/import`,
				body: {
					content: localFile(opts.file, "MEMBER_IMPORT_FILE_UNREADABLE", "Member import file"),
					format,
					dryRun: global.dryRun || !global.yes,
					confirm: global.yes && !global.dryRun,
				},
			});
		}
		case "events list": return requestManagementApi(session, { path: query("/v1/events", { limit: opts.limit, cursor: opts.cursor, action: opts.action, organizationId: opts.org }) });
		case "events tail": {
			const limit = integerOption(opts.limit, 20, 1, 1000, "limit", "EVENTS_TAIL_OPTION_INVALID");
			const pollInterval = integerOption(opts.pollInterval, 1000, 100, 60_000, "poll-interval", "EVENTS_TAIL_OPTION_INVALID");
			const maxEvents = integerOption(opts.maxEvents, 0, 0, Number.MAX_SAFE_INTEGER, "max-events", "EVENTS_TAIL_OPTION_INVALID");
			const tailPath = query("/v1/events", { limit, action: opts.action, organizationId: opts.org });
			const seen = new Set<string>();
			let emitted = 0;
			const poll = async () => {
				const response = await requestManagementApi<{ events?: RemoteAuditEvent[] }>(session, { path: tailPath });
				const fresh = (response.events ?? []).filter((event) => !seen.has(event.id)).reverse();
				for (const event of fresh) {
					seen.add(event.id);
					if (maxEvents !== 0 && emitted >= maxEvents) break;
					emitTailEvent(Boolean(global.json), event);
					emitted += 1;
				}
				return response;
			};
			await poll();
			if (opts.once || (maxEvents !== 0 && emitted >= maxEvents)) throw new CliExitError(0);
			while (maxEvents === 0 || emitted < maxEvents) {
				await new Promise((resolveDelay) => setTimeout(resolveDelay, pollInterval));
				await poll();
			}
			throw new CliExitError(0);
		}
		case "events inspect": return requestManagementApi(session, { path: `/v1/events/${id}` });
		case "events export": {
			const envelope = await requestManagementApi<Record<string, unknown>>(session, {
				method: "POST",
				path: "/v1/events/export",
				body: body({ format: opts.format, limit: opts.limit, action: opts.action, organizationId: opts.org, before: opts.before }),
			});
			return writeRemoteExport(envelope, opts, "events");
		}
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
			requireConfirmation(global, "SESSION_CONFIRM_REQUIRED", "Session revocation");
			return requestManagementApi(session, { method: "POST", path: `/v1/sessions/${id}/revoke`, body: { dryRun: global.dryRun } });
		case "roles list": return requestManagementApi(session, { path: "/v1/roles" });
		case "roles validate": {
			const validation = await requestManagementApi(session, { method: "POST", path: "/v1/roles/validate", body: body({ name: opts.name, slug: opts.slug, permissions: opts.permission }) });
			return { validation };
		}
		case "roles create":
			return requestManagementApi(session, { method: "POST", path: "/v1/roles", body: body({ name: opts.name, slug: opts.slug, description: opts.description, permissions: opts.permission, dryRun: global.dryRun }) });
		case "roles update":
			return requestManagementApi(session, { method: "PATCH", path: `/v1/roles/${id}`, body: body({ name: opts.name, description: opts.description, permissions: opts.permission, dryRun: global.dryRun }) });
		case "sso create":
			requireRemoteMutation(global, path);
			return requestManagementApi(session, { method: "POST", path: "/v1/sso", body: body({ organizationId: opts.org, provider: opts.provider, protocol: opts.protocol, issuer: opts.issuer, audience: opts.audience, domain: opts.domain, samlEntryPoint: opts.entryPoint, samlCertificate: opts.certificate ? readFileSync(resolve(String(opts.certificate)), "utf8") : undefined }) });
		case "sso configure":
			return requestManagementApi(session, { method: "PATCH", path: `/v1/sso/${id}`, body: body({ issuer: opts.issuer, audience: opts.audience, domain: opts.domain, dryRun: global.dryRun }) });
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
			requireConfirmation(global, "SSO_CONFIRM_REQUIRED", "SSO disable");
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
		case "import legacy":
			requireConfirmation(global, "CLEARANCE_IMPORT_CONFIRMATION_REQUIRED", "Legacy import");
			return requestManagementApi(session, {
				method: "POST",
				path: "/v1/import/legacy",
				body: {
					fixture: localFile(opts.file, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Legacy import file"),
					dryRun: global.dryRun || !global.yes,
					confirm: global.yes && !global.dryRun,
				},
			});
		case "migration plan":
			return requestManagementApi(session, {
				method: "POST",
				path: "/v1/migrations/plan",
				body: {
					source: opts.source,
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
				},
			});
		case "migration run":
			return requestManagementApi(session, {
				method: "POST",
				path: `/v1/migrations/${encodeURIComponent(String(opts.id))}/run`,
				body: {
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
					dryRun: global.dryRun,
				},
			});
		case "migration verify":
			return requestManagementApi(session, {
				method: "POST",
				path: `/v1/migrations/${encodeURIComponent(String(opts.id))}/verify`,
				body: {
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
				},
			});
		case "migration rollback":
			requireConfirmation(global, "MIGRATION_ROLLBACK_CONFIRM_REQUIRED", "Migration rollback");
			return requestManagementApi(session, {
				method: "POST",
				path: `/v1/migrations/${encodeURIComponent(String(opts.id))}/rollback`,
				body: {
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
					confirm: global.yes && !global.dryRun,
				},
			});
		case "migration status":
			return requestManagementApi(session, { path: `/v1/migrations/${encodeURIComponent(String(opts.id))}` });
		case "backup create":
			if (opts.dir !== undefined) {
				throw error(
					"BACKUP_DIRECTORY_SERVER_MANAGED",
					"Backup storage is configured by the API deployment.",
					"Set CLEARANCE_BACKUP_DIR on the API and mount durable storage there.",
				);
			}
			return requestManagementApi(session, { method: "POST", path: "/v1/backups", body: {} });
		case "backup verify":
			return requestManagementApi(session, { method: "POST", path: `/v1/backups/${encodeURIComponent(String(opts.id))}/verify`, body: {} });
		case "backup restore":
			requireConfirmation(global, "BACKUP_RESTORE_CONFIRM_REQUIRED", "Backup restore");
			return requestManagementApi(session, {
				method: "POST",
				path: `/v1/backups/${encodeURIComponent(String(opts.id))}/restore`,
				body: { target: opts.target, confirm: global.yes && !global.dryRun },
			});
		case "upgrade check":
			return requestManagementApi(session, { path: "/v1/upgrades/check" });
		case "upgrade plan":
			return requestManagementApi(session, {
				method: "POST",
				path: "/v1/upgrades/plan",
				body: body({ target: opts.target, dir: opts.dir, current: opts.current, dryRun: global.dryRun }),
			});
		case "upgrade apply":
			requireConfirmation(global, "UPGRADE_APPLY_CONFIRMATION_REQUIRED", "Upgrade apply");
			return requestManagementApi(session, {
				method: "POST",
				path: "/v1/upgrades/apply",
				body: { plan: opts.plan, dir: opts.dir, dryRun: global.dryRun, confirm: global.yes && !global.dryRun },
			});
		case "upgrade verify":
			return requestManagementApi(session, {
				method: "POST",
				path: "/v1/upgrades/verify",
				body: body({ plan: opts.plan, dir: opts.dir, healthUrl: opts.healthUrl, dryRun: global.dryRun }),
			});
		case "upgrade rollback":
			requireConfirmation(global, "UPGRADE_ROLLBACK_CONFIRMATION_REQUIRED", "Upgrade rollback");
			return requestManagementApi(session, {
				method: "POST",
				path: "/v1/upgrades/rollback",
				body: body({
					plan: opts.plan,
					dir: opts.dir,
					dryRun: global.dryRun,
					confirm: global.yes && !global.dryRun,
					restoreActive: opts.restoreActive,
					activeDatabaseConfirmation: opts.confirm,
					backupDir: opts.backupDir,
				}),
			});
		case "schema status":
			return requestManagementApi(session, { path: "/v1/schema/status" });
		case "schema generate": {
			if (!opts.output) {
				throw error("SCHEMA_GENERATE_OUTPUT_REQUIRED", "schema generate requires an explicit --output path.", "Provide --output <path> for the generated SQL artifact.");
			}
			const result = await requestManagementApi<Record<string, unknown>>(session, {
				method: "POST",
				path: "/v1/schema/generate",
				body: {},
			});
			const { sql, ...metadata } = result;
			if (typeof sql !== "string") {
				throw error("SCHEMA_GENERATE_RESPONSE_INVALID", "The API did not return generated SQL.", "Upgrade the Clearance API and retry.");
			}
			if (global.dryRun) return { ...metadata, dryRun: true };
			const outputPath = writeExportArtifact(String(opts.output), sql, Boolean(opts.force), {
				stage: "schema.generate",
				existsCode: "SCHEMA_GENERATE_EXISTS",
				writeFailedCode: "SCHEMA_GENERATE_WRITE_FAILED",
			});
			return { ...metadata, dryRun: false, outputPath };
		}
		case "schema migrate":
			requireConfirmation(global, "SCHEMA_MIGRATE_CONFIRMATION_REQUIRED", "Schema migration");
			return requestManagementApi(session, {
				method: "POST",
				path: "/v1/schema/migrate",
				body: { dryRun: global.dryRun, confirm: global.yes && !global.dryRun },
			});
		case "config get": return requestManagementApi(session, { path: query("/v1/config", { key: args[0] }) });
		case "config set": return requestManagementApi(session, { method: "PATCH", path: `/v1/config/${encodeURIComponent(String(args[0]))}`, body: { value: args[1], dryRun: global.dryRun } });
		case "config validate": {
			const config = opts.file ? configCandidate(opts.file) : undefined;
			return requestManagementApi(session, { method: "POST", path: "/v1/config/validate", body: body({ config }) });
		}
		case "config diff": {
			const config = configCandidate(opts.file);
			return requestManagementApi(session, { method: "POST", path: "/v1/config/diff", body: { config } });
		}
		default:
			throw error(
				"CLI_REMOTE_COMMAND_UNAVAILABLE",
				`${path} has no versioned management API contract in this release.`,
				"Upgrade the Clearance API to a version that exposes this workflow.",
			);
	}
}
