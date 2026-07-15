#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync } from "node:fs";
import {
	ClearanceError,
	EVENTS_EXPORT_MAX_LIMIT,
	EVENTS_TAIL_MAX_LIMIT,
	USERS_EXPORT_MAX_LIMIT,
} from "@clearance/management";
import { CliExitError, fail, printResult, type GlobalOpts } from "./output.js";
import {
	deleteSavedCredential,
	environmentToken,
	fetchWhoami,
	normalizeApiUrl,
	normalizeProfile,
	readTokenFromStdin,
	validateAndSaveCredential,
} from "./operator-auth.js";
import { resolveApiSession } from "./api-client.js";
import {
	commandPath,
	dispatchRemoteCommand,
	EVENTS_TAIL_MAX_POLL_INTERVAL_MS,
	EVENTS_TAIL_MIN_POLL_INTERVAL_MS,
} from "./remote-dispatch.js";

const VERSION = (
	JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
		version: string;
	}
).version;

function globals(cmd: Command): GlobalOpts {
	const opts = cmd.optsWithGlobals() as GlobalOpts & Record<string, unknown>;
	return {
		json: Boolean(opts.json),
		noInput: Boolean(opts.noInput),
		yes: Boolean(opts.yes),
		dryRun: Boolean(opts.dryRun),
		profile: opts.profile as string | undefined,
		apiUrl: opts.apiUrl as string | undefined,
	};
}

/**
 * Execute one operational command through the authenticated management API.
 * Commander binds `this` to the leaf command, preserving each command's own
 * arguments and options while keeping workflow execution in one place.
 */
async function remoteCommandAction(this: Command): Promise<void> {
	const g = globals(this);
	try {
		const session = await resolveApiSession({
			profile: g.profile,
			apiUrl: g.apiUrl,
		});
		if (!session) {
			throw new ClearanceError({
				code: "CLI_LOGIN_REQUIRED",
				message: "An authenticated Clearance API profile is required.",
				stage: "cli.dispatch",
				remediation:
					"Run clearance login --profile <name> for the intended API origin.",
			});
		}
		const result = await dispatchRemoteCommand(
			session,
			commandPath(this),
			this.processedArgs,
			this.opts() as Record<string, unknown>,
			g,
		);
		printResult(g, result);
	} catch (cause) {
		fail(cause, g);
	}
}

async function main() {
	const program = new Command("clearance");
	program
		.version(VERSION)
		.description("Clearance CLI — open-source auth operations")
		.option("--json", "Stable JSON output", false)
		.option("--no-input", "Disable prompts (CI/agents)", false)
		.option("--yes", "Confirm destructive actions", false)
		.option("--dry-run", "Preview mutations", false)
		.option("--profile <name>", "Saved API profile")
		.option("--api-url <url>", "Clearance management API origin override");

	program
		.command("init")
		.description("Initialize a Clearance project and development environment")
		.option("--name <name>", "Project name", "clearance-app")
		.option("--environment <name>", "Environment name", "development")
		.action(remoteCommandAction);

	program
		.command("doctor")
		.description("Installation and configuration health checks")
		.action(remoteCommandAction);

	program
		.command("dev")
		.description("Show verified local development startup paths")
		.action(remoteCommandAction);

	// project
	const project = program.command("project").description("Project resources");
	project
		.command("list")
		.action(remoteCommandAction);
	project
		.command("inspect")
		.argument("[id]")
		.action(remoteCommandAction);
	project
		.command("create")
		.requiredOption("--name <name>")
		.action(remoteCommandAction);

	// env
	const env = program.command("env").description("Environments");
	env
		.command("list")
		.action(remoteCommandAction);
	env
		.command("inspect")
		.description("Inspect environment and API configuration status (no secrets)")
		.argument("[id]", "Environment id/slug (defaults to operator principal env)")
		.action(remoteCommandAction);
	env
		.command("create")
		.requiredOption("--name <name>")
		.option("--project-id <id>")
		.option("--kind <kind>", "development|preview|production", "development")
		.action(remoteCommandAction);
	env
		.command("promote")
		.description(
			"Plan environment promotion (validated plan/dry-run; apply blocked without Deployment resource)",
		)
		.requiredOption("--to <id>", "Target environment id or slug")
		.option("--from <id>", "Source environment id/slug (defaults to principal env)")
		.action(remoteCommandAction);

	// users
	const users = program.command("users").description("Users / principals");
	users
		.command("list")
		.option("--limit <n>", "Page size (enables keyset cursor pagination)")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(remoteCommandAction);
	users
		.command("inspect")
		.argument("<id>")
		.action(remoteCommandAction);
	users
		.command("create")
		.requiredOption("--email <email>")
		.requiredOption("--name <name>")
		.option("--password <password>", "Explicit initial password; omitted creates an expiring single-use setup token")
		.action(remoteCommandAction);
	users
		.command("update")
		.argument("<id>")
		.option("--name <name>", "Display name")
		.option("--email <email>", "Primary email")
		.option("--status <status>", "active|disabled")
		.action(remoteCommandAction);
	users
		.command("disable")
		.argument("<id>")
		.action(remoteCommandAction);
	users
		.command("delete")
		.argument("<id>")
		.action(remoteCommandAction);
	users
		.command("export")
		.description("Export scoped users (bounded, redacted, deterministic)")
		.requiredOption(
			"--output <path>",
			"Output file path (required; refuse overwrite unless --force)",
		)
		.option("--format <fmt>", "json|jsonl", "json")
		.option("--limit <n>", `Max records (1-${USERS_EXPORT_MAX_LIMIT})`, "100")
		.option("--status <status>", "Filter active|disabled")
		.option("--force", "Overwrite existing output file", false)
		.action(remoteCommandAction);

	// orgs — same canonical management ops as API
	const orgs = program.command("orgs").description("Organizations");
	orgs
		.command("list")
		.option("--limit <n>", "Page size (enables keyset cursor pagination)")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(remoteCommandAction);
	orgs
		.command("inspect")
		.argument("<id>")
		.action(remoteCommandAction);
	orgs
		.command("create")
		.requiredOption("--name <name>")
		.option("--slug <slug>")
		.option("--owner-user <id>", "Runtime owner user id (defaults to first active principal)")
		.action(remoteCommandAction);
	orgs
		.command("update")
		.argument("<id>")
		.option("--name <name>", "Display name")
		.option("--slug <slug>", "URL slug (lowercase)")
		.action(remoteCommandAction);
	orgs
		.command("archive")
		.argument("<id>")
		.description("Archive an organization (requires --yes; supports --dry-run)")
		.action(remoteCommandAction);

	const members = orgs.command("members").description("Organization members");
	members
		.command("import")
		.requiredOption("--org <id>")
		.requiredOption("--file <path>")
		.option("--format <format>", "json|csv (defaults from file extension)")
		.action(remoteCommandAction);
	members
		.command("list")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);
	members
		.command("add")
		.requiredOption("--org <id>")
		.requiredOption("--user <id>")
		.option("--role <role>", "Role slug (default: member)", "member")
		.action(remoteCommandAction);
	members
		.command("update")
		.requiredOption("--org <id>")
		.option("--user <id>", "Principal id of the member")
		.option("--member <id>", "Membership id")
		.requiredOption("--role <role>", "New role slug")
		.action(remoteCommandAction);
	members
		.command("remove")
		.requiredOption("--org <id>")
		.option("--user <id>", "Principal id of the member")
		.option("--member <id>", "Membership id")
		.action(remoteCommandAction);

	// events — list / tail / inspect / export / replay (shared management services)
	const events = program.command("events").description("Audit events");
	events
		.command("list")
		.option("--limit <n>", "50")
		.option("--action <action>", "Filter by action")
		.option("--org <id>", "Filter by organization id")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(remoteCommandAction);
	events
		.command("tail")
		.description("Stream scoped audit events by polling the management API")
		.option("--limit <n>", `Initial history (1-${EVENTS_TAIL_MAX_LIMIT})`, "20")
		.option("--poll-interval <milliseconds>", `Refresh interval (${EVENTS_TAIL_MIN_POLL_INTERVAL_MS}-${EVENTS_TAIL_MAX_POLL_INTERVAL_MS}ms)`, "1000")
		.option("--max-events <n>", "Exit after N events; 0 means unlimited", "0")
		.option("--once", "Emit initial history and exit", false)
		.option("--action <action>", "Filter by action")
		.option("--org <id>", "Filter by organization id")
		.action(remoteCommandAction);
	events
		.command("inspect")
		.argument("<id>", "Event id or diagnostic trace id")
		.action(remoteCommandAction);
	events
		.command("export")
		.description("Export scoped audit events (bounded, redacted, deterministic)")
		.requiredOption("--output <path>", "Output file path (required; refuse overwrite unless --force)")
		.option("--format <fmt>", "json|jsonl", "json")
		.option("--limit <n>", `Max records (1-${EVENTS_EXPORT_MAX_LIMIT})`, "100")
		.option("--action <action>", "Filter by action")
		.option("--org <id>", "Filter by organization id")
		.option(
			"--before <iso-timestamp>",
			"Export only events created strictly before this ISO-8601 timestamp (archival bound)",
		)
		.option("--force", "Overwrite existing output file", false)
		.action(remoteCommandAction);
	events
		.command("replay")
		.description(
			"Re-record a SCIM diagnostic trace (default dry-run; --yes to apply)",
		)
		.argument("<id>", "SCIM diagnostic trace id")
		.action(remoteCommandAction);

	// keys — digest-only project/environment scoped API-key lifecycle
	const keys = program.command("keys").description("Project and environment API keys");
	keys.command("list").option("--include-revoked", "Include revoked keys", false).action(remoteCommandAction);
	keys.command("create").requiredOption("--name <name>", "Human-readable key name")
		.option("--scope <scope>", "Repeatable resource:action scope", (value, previous: string[] = []) => [...previous, value], [])
		.action(remoteCommandAction);
	keys.command("rotate").argument("<id>", "API key id").action(remoteCommandAction);
	keys.command("revoke").argument("<id>", "API key id").action(remoteCommandAction);

	// sessions — list / revoke under principal-derived scope
	const sessions = program.command("sessions").description("Auth sessions");
	sessions
		.command("list")
		.option("--limit <n>", "Max sessions to return (page size)", "100")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(remoteCommandAction);
	sessions
		.command("revoke")
		.argument("<id>", "Stable session id")
		.action(remoteCommandAction);

	// roles — canonical project/environment-scoped role services shared with API/console
	const roles = program.command("roles").description("Custom access-control roles");
	roles
		.command("list")
		.action(remoteCommandAction);
	roles
		.command("validate")
		.option("--name <name>")
		.option("--slug <slug>")
		.option("--permission <permission...>", "One or more resource:action permissions")
		.action(remoteCommandAction);
	roles
		.command("create")
		.requiredOption("--name <name>")
		.option("--slug <slug>")
		.option("--description <description>")
		.requiredOption("--permission <permission...>", "One or more resource:action permissions")
		.action(remoteCommandAction);
	roles
		.command("update")
		.argument("<id>")
		.option("--name <name>")
		.option("--description <description>")
		.option("--permission <permission...>", "Replacement resource:action permissions")
		.action(remoteCommandAction);

	// sso
	const sso = program.command("sso").description("Enterprise SSO connections");
	sso
		.command("create")
		.requiredOption("--org <id>")
		.requiredOption("--provider <name>")
		.option("--protocol <protocol>", "Identity protocol: oidc|saml", "oidc")
			.requiredOption("--issuer <url>")
			.option("--audience <aud>")
			.option("--domain <domain>")
			.option("--entry-point <url>", "SAML identity provider SSO URL")
			.option("--certificate <path>", "SAML identity provider signing certificate PEM")
			.action(remoteCommandAction);
	sso
		.command("configure")
		.argument("<id>")
		.option("--issuer <url>")
		.option("--audience <aud>")
		.option("--domain <domain>")
		.action(remoteCommandAction);
	sso
		.command("test")
		.argument("<id>")
		.option("--fixture <name>", "ok|wrong-issuer|wrong-audience|malformed|expired|clock-skew|replay")
		.option(
			"--live",
			"Probe the REAL configured issuer (read-only discovery/JWKS conformance). Requires --yes, HTTPS, non-loopback.",
			false,
		)
		.action(remoteCommandAction);
	sso
		.command("list")
		.option("--org <id>")
		.action(remoteCommandAction);
	sso
		.command("setup-link")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);
	sso
		.command("rotate")
		.description("Rotate SSO client-secret credential envelope under the current key")
		.argument("<id>", "SSO connection id")
		.action(remoteCommandAction);
	sso
		.command("disable")
		.description("Disable an SSO connection")
		.argument("<id>", "SSO connection id")
		.action(remoteCommandAction);

	// scim
	const scim = program.command("scim").description("SCIM directory connections");
	scim
		.command("create")
		.requiredOption("--org <id>")
		.requiredOption("--provider <name>")
		.option(
			"--endpoint <url>",
			"External SCIM base URL (required for live conformance probes)",
		)
		.action(remoteCommandAction);
	scim
		.command("test")
		.argument("<id>")
		.option("--apply", "Apply instead of dry-run", false)
		.option("--fixture <name>", "ok|malformed|unauthorized")
		.option(
			"--live",
			"Probe the REAL configured SCIM endpoint (read-only GETs). Requires --yes, HTTPS, non-loopback.",
			false,
		)
		.action(remoteCommandAction);
	scim
		.command("list")
		.option("--org <id>")
		.action(remoteCommandAction);
	scim
		.command("setup-link")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);
	scim
		.command("rotate")
		.description("Rotate SCIM bearer credential envelope under the current key")
		.argument("<id>", "SCIM connection id")
		.action(remoteCommandAction);
	scim
		.command("disable")
		.description("Disable a SCIM directory connection")
		.argument("<id>", "SCIM connection id")
		.action(remoteCommandAction);
	scim
		.command("replay")
		.description(
			"Re-record a SCIM diagnostic trace (default dry-run; --yes to apply)",
		)
		.argument("<traceId>", "SCIM diagnostic trace id")
		.action(remoteCommandAction);

	// readiness
	const readiness = program.command("readiness").description("Enterprise readiness");
	readiness
		.command("check")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);
	readiness
		.command("report")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);

	// migration
	const imports = program.command("import").description("Import supported auth exports");
	imports
		.command("legacy")
		.description("Preview or import a validated legacy export")
		.requiredOption("--file <path>", "Local legacy JSON export")
		.action(remoteCommandAction);

	const migration = program.command("migration").description("Tenant migration");
	migration
		.command("plan")
		.requiredOption("--source <source>", "legacy")
		.requiredOption("--fixture <path>")
		.action(remoteCommandAction);
	migration
		.command("run")
		.requiredOption("--id <planId>")
		.requiredOption("--fixture <path>")
		.action(remoteCommandAction);
	migration
		.command("verify")
		.requiredOption("--id <planId>")
		.requiredOption("--fixture <path>")
		.action(remoteCommandAction);
	migration
		.command("rollback")
		.requiredOption("--id <planId>")
		.requiredOption("--fixture <path>")
		.action(remoteCommandAction);
	migration
		.command("status")
		.requiredOption("--id <planId>")
		.action(remoteCommandAction);

	// backup
	const backup = program.command("backup").description("Backup and restore");
	backup
		.command("create")
		.action(remoteCommandAction);
	backup
		.command("verify")
		.requiredOption("--id <backupId>")
		.action(remoteCommandAction);
	backup
		.command("restore")
		.requiredOption("--id <backupId>")
		.option("--target <path>", "API-host restore path or isolated Postgres database name")
		.action(remoteCommandAction);

	// upgrade
	const upgrade = program.command("upgrade").description("Upgrade tooling");
	upgrade
		.command("check")
		.action(remoteCommandAction);
	upgrade
		.command("plan")
		.requiredOption("--target <version>", "Target release version")
		.requiredOption("--dir <path>", "Absolute upgrade artifact directory")
		.option("--current <version>", "Current release version override")
		.action(remoteCommandAction);
	upgrade
		.command("apply")
		.requiredOption("--plan <id-or-path>", "Plan ID or plan path")
		.requiredOption("--dir <path>", "Absolute upgrade artifact directory")
		.action(remoteCommandAction);
	upgrade
		.command("verify")
		.requiredOption("--plan <id-or-path>", "Plan ID or plan path")
		.requiredOption("--dir <path>", "Absolute upgrade artifact directory")
		.option("--health-url <url>", "Optional credential-free HTTP(S) health endpoint")
		.action(remoteCommandAction);
	upgrade
		.command("rollback")
		.description("Verify a rollback in isolation, or explicitly restore the active database")
		.requiredOption("--plan <id-or-path>", "Plan ID or plan path")
		.requiredOption("--dir <path>", "Absolute upgrade artifact directory")
		.option("--restore-active", "Restore the rollback backup into the active database", false)
		.option("--confirm <token>", "Exact RESTORE_ACTIVE:<plan-id>:<database> confirmation")
		.option("--backup-dir <path>", "Absolute directory for the pre-restore safety backup")
		.action(remoteCommandAction);

	// schema
	const schema = program.command("schema").description("Management and runtime schema lifecycle");
	schema
		.command("status")
		.action(remoteCommandAction);
	schema
		.command("generate")
		.description("Compile pending Clearance Postgres SQL without applying it")
		.option("--output <path>", "Output SQL file path (required)")
		.option("--force", "Overwrite an existing output artifact", false)
		.action(remoteCommandAction);
	schema
		.command("migrate")
		.description("Apply pending Clearance migrations and lifecycle compatibility ensures")
		.action(remoteCommandAction);

	// config
	const config = program.command("config").description("Config");
	config
		.command("get")
		.argument("[key]")
		.action(remoteCommandAction);
	config
		.command("set")
		.argument("<key>")
		.argument("<value>")
		.action(remoteCommandAction);
	config
		.command("validate")
		.option("--file <json-file>", "Candidate config JSON file")
		.action(remoteCommandAction);
	config
		.command("diff")
		.requiredOption("--file <json-file>", "Candidate config JSON file")
		.action(remoteCommandAction);

	// overview for console parity
	program
		.command("overview")
		.description("Dashboard overview stats")
		.action(remoteCommandAction);

	program
		.command("login")
		.description("Validate and save an operator credential for API-backed commands")
		.option("--url <url>", "Clearance API URL")
		.option("--token-stdin", "Read an operator token from standard input", false)
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const profile = normalizeProfile(g.profile);
				const apiUrl = normalizeApiUrl(opts.url);
				const token = opts.tokenStdin ? await readTokenFromStdin() : environmentToken();
				if (!token) {
					throw new ClearanceError({
						code: "CLI_TOKEN_REQUIRED",
						message: "An operator token is required for login.",
						stage: "operator-auth.login",
						remediation:
							"Set CLEARANCE_OPERATOR_TOKEN or CLEARANCE_API_TOKEN, or pass --token-stdin.",
					});
				}
				const whoami = await validateAndSaveCredential(apiUrl, token, process.env, profile);
				printResult(g, {
					authenticated: true,
					credentialSaved: true,
					credentialSource: opts.tokenStdin ? "stdin" : "environment",
					profile,
					apiUrl,
					whoami,
				}, `Authenticated to ${apiUrl} as operator (${whoami.projectId}/${whoami.environmentId}).`);
			} catch (e) {
				fail(e, g);
			}
		});

	program
		.command("logout")
		.description("Remove the saved operator credential")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				const profile = normalizeProfile(g.profile);
				const credentialRemoved = await deleteSavedCredential(process.env, profile);
				const environmentCredentialPresent = Boolean(environmentToken());
				const result = {
					credentialRemoved,
					idempotent: !credentialRemoved,
					environmentCredentialPresent,
					credentialSource: environmentCredentialPresent ? "environment" : "none",
					profile,
				};
				const status = credentialRemoved ? "Saved operator credential removed." : "No saved operator credential was present.";
				const environmentNote = environmentCredentialPresent ? " An environment credential remains active." : "";
				printResult(g, result, `${status}${environmentNote}`);
			} catch (e) {
				fail(e, g);
			}
		});

	program
		.command("whoami")
		.description("Verify the current operator credential and scope")
		.option("--url <url>", "Clearance API URL override")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const session = await resolveApiSession({
					...(environmentToken() ? {} : { profile: g.profile }),
					apiUrl: opts.url ?? g.apiUrl,
				});
				if (session) {
					const whoami = await fetchWhoami(session.apiUrl, session.token);
					const via = session.credentialSource === "saved" ? session.profile : "environment";
					printResult(g, {
						authenticated: true,
						credentialSource: session.credentialSource,
						...(session.credentialSource === "saved" ? { profile: session.profile } : {}),
						apiUrl: session.apiUrl,
						...whoami,
					}, `operator ${whoami.projectId}/${whoami.environmentId} via ${via} (${session.apiUrl})`);
					return;
				}
				throw new ClearanceError({
					code: "CLI_LOGIN_REQUIRED",
					message: "No authenticated Clearance API profile is configured.",
					stage: "cli.auth",
					status: 401,
					remediation: "Run clearance login --profile <name> for the intended API origin.",
				});
			} catch (e) {
				fail(e, g);
			}
		});

	await program.parseAsync();
}

main().catch((err) => {
	if (err instanceof CliExitError) {
		process.exitCode = err.exitCode;
		return;
	}
	console.error(err);
	process.exitCode = 1;
});
