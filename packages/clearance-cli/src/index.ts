#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
	addMember,
	addMemberInAuth,
	executeMemberImportPlan,
	planMemberImport,
	type MemberImportFormat,
	archiveOrganization,
	archiveOrganizationInAuth,
	createBackup,
	createEnvironment,
	createProject,
	createOrganization,
	createOrgInAuth,
	createScimConnection,
	createSetupLink,
	createSsoConnection,
	createSsoConnectionReal,
	testSsoConnectionReal,
	testSsoConnectionLive,
	testScimConnectionLive,
	createScimConnectionReal,
	testScimConnectionReal,
	ensureAuthMigrated,
	createPostgresBackup,
	createRole,
	createApiKey,
	verifyPostgresBackup,
	restorePostgresBackup,
	upgradeCheckWithDb,
	createUser,
	createUserInAuth,
	createUserWithPasswordSetupInAuth,
	configureSsoConnection,
	closeAuthBundle,
	deleteUser,
	deleteUserInAuth,
	disableScimConnection,
	disableScimConnectionReal,
	disableSsoConnection,
	disableSsoConnectionReal,
	disableUser,
	disableUserInAuth,
	exportUsers,
	USERS_EXPORT_MAX_LIMIT,
	getLatestReadiness,
	initProject,
	inspectEnvironment,
	inspectApiKey,
	inspectScimConnection,
	inspectSsoConnection,
	inspectSession,
	inspectSessionInAuth,
	inspectOrganization,
	inspectUser,
	listEnvironments,
	listEventsPage,
	exportEvents,
	EVENTS_EXPORT_MAX_LIMIT,
	EVENTS_TAIL_MAX_LIMIT,
	beginEventsTail,
	pollEventsTail,
	inspectEvent,
	replayDiagnosticTrace,
	listMembers,
	listOrganizations,
	listOrganizationsPage,
	listProjects,
	listRoles,
	listApiKeys,
	normalizeAndValidateApiKeyScopes,
	listScimConnections,
	listSessionsPage,
	listSessionsPageInAuth,
	listSsoConnections,
	listUsers,
	listUsersPage,
	ClearanceError,
	promoteEnvironment,
	removeMember,
	removeMemberInAuth,
	resolveMembershipId,
	revokeSession,
	revokeSessionInAuth,
	revokeApiKey,
	rotateScimCredential,
	rotateSsoCredential,
	rotateApiKey,
	updateMember,
	updateMemberInAuth,
	updateOrganization,
	updateOrganizationInAuth,
	updateUser,
	updateUserInAuth,
	loadLegacyFixture,
	migrationStatus,
	overviewStats,
	planMigration,
	previewMigration,
	planEnvironmentCreate,
	planProjectCreate,
	restoreBackup,
	rollbackMigrationDurable,
	runDoctor,
	runMigrationDurable,
	runReadinessCheck,
	testScimConnection,
	testSsoConnection,
	updateRole,
	validateSamlProviderConfig,
	syncRuntimeOrganizationToManagementDurable,
	upgradeCheck,
	verifyBackup,
	verifyMigrationDurable,
	validateRole,
	parseConfigJson,
	publicConfig,
	setConfig,
	validateConfig,
	validateApiKeyName,
	diffConfig,
	generateRuntimeSchema,
	getRuntimeSchemaStatus,
	migrateRuntimeSchema,
} from "@clearance/management";
import { CliExitError, fail, printResult, type GlobalOpts } from "./output.js";
import { closeStores, flushStore, openStore } from "./store.js";
import { applyUpgrade, planUpgrade, rollbackUpgrade, verifyUpgrade } from "./upgrade.js";
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
		dataPath: opts.dataPath as string | undefined,
		profile: opts.profile as string | undefined,
		apiUrl: opts.apiUrl as string | undefined,
	};
}

function readConfigCandidate(path: string) {
	try {
		return parseConfigJson(readFileSync(resolve(path), "utf8"));
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw new ClearanceError({
			code: "CONFIG_FILE_UNREADABLE",
			message: "Config file could not be read.",
			stage: "config.parse",
			remediation: "Provide a readable JSON config file.",
		});
	}
}

const EVENTS_TAIL_MIN_POLL_INTERVAL_MS = 100;
const EVENTS_TAIL_MAX_POLL_INTERVAL_MS = 60_000;

/**
 * Shared fail-closed numeric option parser. Invalid input is a structured
 * error, never a silent coercion. Codes are stage-scoped so shipped contracts
 * (EVENTS_TAIL_OPTION_INVALID) stay stable while new sites get their own.
 */
function parseBoundedInteger(
	value: string | undefined,
	spec: {
		name: string;
		stage: string;
		code: string;
		minimum: number;
		maximum: number;
		defaultValue: number;
	},
): number {
	if (value === undefined) return spec.defaultValue;
	if (!/^(?:0|[1-9]\d*)$/.test(value)) {
		throw new ClearanceError({
			code: spec.code,
			message: `--${spec.name} must be an integer`,
			stage: spec.stage,
			status: 400,
			remediation: `Pass an integer from ${spec.minimum} through ${spec.maximum}`,
		});
	}
	const parsed = Number(value);
	if (
		!Number.isSafeInteger(parsed) ||
		parsed < spec.minimum ||
		parsed > spec.maximum
	) {
		throw new ClearanceError({
			code: spec.code,
			message: `--${spec.name} must be an integer between ${spec.minimum} and ${spec.maximum}`,
			stage: spec.stage,
			status: 400,
			remediation: `Pass an integer from ${spec.minimum} through ${spec.maximum}`,
		});
	}
	return parsed;
}

function parseTailInteger(
	value: string | undefined,
	name: "limit" | "poll-interval" | "max-events",
	minimum: number,
	maximum: number,
	defaultValue: number,
): number {
	return parseBoundedInteger(value, {
		name,
		stage: "events.tail",
		code: "EVENTS_TAIL_OPTION_INVALID",
		minimum,
		maximum,
		defaultValue,
	});
}

function createTailStopSignal() {
	let stopped = false;
	let wake: (() => void) | undefined;
	const stop = () => {
		stopped = true;
		wake?.();
	};
	process.once("SIGINT", stop);
	process.once("SIGTERM", stop);
	return {
		get stopped() {
			return stopped;
		},
		wait(intervalMs: number): Promise<boolean> {
			if (stopped) return Promise.resolve(true);
			return new Promise((resolve) => {
				const timer = setTimeout(() => {
					wake = undefined;
					resolve(false);
				}, intervalMs);
				wake = () => {
					clearTimeout(timer);
					wake = undefined;
					resolve(true);
				};
			});
		},
		dispose() {
			process.removeListener("SIGINT", stop);
			process.removeListener("SIGTERM", stop);
		},
	};
}

function writeTailEvent(json: boolean, event: { createdAt: string; action: string; actor: string; outcome: string; id: string }): void {
	if (json) {
		process.stdout.write(`${JSON.stringify(event)}\n`);
		return;
	}
	process.stdout.write(`${event.createdAt} ${event.action} actor=${event.actor} outcome=${event.outcome} id=${event.id}\n`);
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
		.option("--data-path <path>", "Path to Clearance data store")
		.option("--profile <name>", "Saved API profile")
		.option("--api-url <url>", "Clearance management API origin override");

	program.hook("preAction", async (_root, actionCommand) => {
		const g = globals(actionCommand);
		try {
			const path = commandPath(actionCommand);
			if (path === "login" || path === "logout" || path === "whoami") return;
			const session = await resolveApiSession({ profile: g.profile, apiUrl: g.apiUrl });
			if (!session) {
				throw new ClearanceError({
					code: "CLI_LOGIN_REQUIRED",
					message: "An authenticated Clearance API profile is required.",
					stage: "cli.dispatch",
					remediation: "Run clearance login --profile <name> for the intended API origin.",
				});
			}
			const result = await dispatchRemoteCommand(
				session,
				path,
				actionCommand.processedArgs,
				actionCommand.opts() as Record<string, unknown>,
				g,
			);
			printResult(g, result);
			throw new CliExitError(0);
		} catch (cause) {
			if (cause instanceof CliExitError && cause.exitCode === 0) throw cause;
			fail(cause, g);
		}
	});

	program
		.command("init")
		.description("Initialize a Clearance project and development environment")
		.option("--name <name>", "Project name", "clearance-app")
		.option("--environment <name>", "Environment name", "development")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				if (g.dryRun) {
					printResult(g, { dryRun: true, name: opts.name }, `Would init ${opts.name}`);
					return;
				}
				if (process.env.DATABASE_URL) {
					await ensureAuthMigrated();
				}
				const result = initProject(store, {
					name: opts.name,
					environment: opts.environment,
				});
				await flushStore(store);
				printResult(
					g,
					{
						ok: true,
						...result,
						database: process.env.DATABASE_URL ? "postgres" : store.backend,
						storeBackend: store.backend,
					},
					`Initialized project ${result.project.name} (${result.project.id}) env ${result.environment.slug}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

	program
		.command("doctor")
		.description("Installation and configuration health checks")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const result = await runDoctor(store);
				printResult(g, result, result.ok ? "Doctor: all critical checks passed" : "Doctor: failures detected");
				if (!result.ok) process.exitCode = 2;
			} catch (e) {
				fail(e, g);
			}
		});

	program
		.command("dev")
		.description("Show verified local development startup paths")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			printResult(
				g,
				{
					commands: [
						"clearance init --name my-app",
						"pnpm stack:smoke",
						"pnpm stack:up # persistent; export the required README variables first",
						"pnpm --filter @clearance/sample-b2b dev",
						"pnpm --filter @clearance/api dev",
						"pnpm --filter @clearance/console dev",
					],
				},
				"Validate locally with pnpm stack:smoke; use the README persistent-stack variables with pnpm stack:up.",
			);
		});

	// project
	const project = program.command("project").description("Project resources");
	project
		.command("list")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				printResult(g, { projects: listProjects(store) });
			} catch (e) {
				fail(e, g);
			}
		});
	project
		.command("inspect")
		.argument("[id]")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const projects = listProjects(store);
				const p = id ? projects.find((x) => x.id === id) : projects[0];
				if (id && !p) {
					throw new ClearanceError({
						code: "PROJECT_NOT_FOUND",
						message: "Project not found.",
						stage: "project.inspect",
						status: 404,
						remediation: "Pass an existing project id.",
					});
				}
				printResult(g, { project: p, overview: overviewStats(store) });
			} catch (e) {
				fail(e, g);
			}
		});
	project
		.command("create")
		.requiredOption("--name <name>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				if (g.dryRun) {
					const project = planProjectCreate({ name: opts.name }, store.snapshot.projects);
					printResult(g, { dryRun: true, project }, `Would create project ${project.name}`);
					return;
				}
				const project = createProject(store, { name: opts.name });
				await flushStore(store);
				printResult(g, { project });
			} catch (e) {
				fail(e, g);
			}
		});

	// env
	const env = program.command("env").description("Environments");
	env
		.command("list")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				printResult(g, { environments: listEnvironments(store) });
			} catch (e) {
				fail(e, g);
			}
		});
	env
		.command("inspect")
		.description("Inspect environment and local configuration status (no secrets)")
		.argument("[id]", "Environment id/slug (defaults to operator principal env)")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				const result = inspectEnvironment(store, id);
				printResult(
					g,
					result,
					`Environment ${result.environment.slug} (${result.environment.id})${result.local.active ? " [active]" : ""}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});
	env
		.command("create")
		.requiredOption("--name <name>")
		.option("--project-id <id>")
		.option("--kind <kind>", "development|preview|production", "development")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const projectId =
					opts.projectId ??
					store.snapshot.meta.config.projectId ??
					store.snapshot.projects[0]?.id;
				if (g.dryRun) {
					const preview = planEnvironmentCreate(store, {
						projectId,
						name: opts.name,
						kind: opts.kind,
					});
					printResult(g, { dryRun: true, environment: preview }, `Would create environment ${opts.name}`);
					return;
				}
				const environment = createEnvironment(store, {
					projectId,
					name: opts.name,
					kind: opts.kind,
				});
				await flushStore(store);
				printResult(g, { environment });
			} catch (e) {
				fail(e, g);
			}
		});
	env
		.command("promote")
		.description(
			"Plan environment promotion (validated plan/dry-run; apply blocked without Deployment resource)",
		)
		.requiredOption("--to <id>", "Target environment id or slug")
		.option("--from <id>", "Source environment id/slug (defaults to principal env)")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				// Default dry-run unless --yes. Explicit --dry-run always previews.
				const dryRun = g.dryRun || !g.yes;
				const result = promoteEnvironment(store, {
					to: opts.to,
					...(opts.from ? { from: opts.from } : {}),
					dryRun,
					confirm: g.yes && !g.dryRun,
					actor: "cli",
					source: "cli",
				});
				if (!result.dryRun) {
					await flushStore(store);
				}
				printResult(
					g,
					result,
					result.dryRun
						? result.blocked
							? `Would promote ${result.source.slug} → ${result.target.slug} (blocked: no deployment model)`
							: `Would promote ${result.source.slug} → ${result.target.slug}`
						: result.idempotent
							? `Promote no-op (already ${result.source.slug})`
							: `Promote blocked: deployment model unavailable (${result.source.slug} → ${result.target.slug})`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

	// users — same canonical management ops as API (ManagementStore, not auth runtime tables)
	const users = program.command("users").description("Users / principals");
	users
		.command("list")
		.option("--limit <n>", "Page size (enables keyset cursor pagination)")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				// Without --limit/--cursor the legacy full-list contract is unchanged.
				if (opts.limit !== undefined || opts.cursor !== undefined) {
					const page = listUsersPage(store, {
						...(opts.limit !== undefined ? { limit: Number(opts.limit) } : {}),
						...(opts.cursor !== undefined ? { cursor: opts.cursor } : {}),
					});
					printResult(g, { users: page.users, nextCursor: page.nextCursor });
					return;
				}
				printResult(g, { users: listUsers(store) });
			} catch (e) {
				fail(e, g);
			}
		});
	users
		.command("inspect")
		.argument("<id>")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				printResult(g, { user: inspectUser(store, id) });
			} catch (e) {
				fail(e, g);
			}
		});
	users
		.command("create")
		.requiredOption("--email <email>")
		.requiredOption("--name <name>")
		.option("--password <password>", "Explicit initial password; omitted creates an expiring single-use setup token")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				if (g.dryRun) {
					printResult(g, { dryRun: true, email: opts.email });
					return;
				}
				await store.refresh();
				const provisioned = process.env.DATABASE_URL
					? typeof opts.password === "string" && opts.password.length > 0
						? {
								user: await createUserInAuth({
									email: opts.email,
									name: opts.name,
									password: opts.password,
									managementStore: store,
								}),
								passwordSetup: undefined,
							}
						: await createUserWithPasswordSetupInAuth({
								email: opts.email,
								name: opts.name,
								managementStore: store,
							})
					: { user: createUser(store, {
							email: opts.email,
							name: opts.name,
							source: "cli",
					  }), passwordSetup: undefined };
				await flushStore(store);
				printResult(
					g,
					{
						user: provisioned.user,
						...(provisioned.passwordSetup
							? {
									passwordSetupToken: provisioned.passwordSetup.token,
									passwordSetupExpiresAt: provisioned.passwordSetup.expiresAt,
								}
							: {}),
						storeBackend: store.backend,
					},
					`Created ${provisioned.user.email} (${provisioned.user.id})`,
				);
			} catch (e) {
				fail(e, g);
			}
		});
	users
		.command("update")
		.argument("<id>")
		.option("--name <name>", "Display name")
		.option("--email <email>", "Primary email")
		.option("--status <status>", "active|disabled")
		.action(async (id, opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				// Fail closed before dry-run / mutation (service layer also validates).
				const statusRaw = opts.status as string | undefined;
				if (
					statusRaw !== undefined &&
					statusRaw !== "active" &&
					statusRaw !== "disabled"
				) {
					throw new Error("Invalid --status; use active or disabled");
				}
				const status = statusRaw as "active" | "disabled" | undefined;
				if (g.dryRun) {
					printResult(g, {
						dryRun: true,
						id,
						name: opts.name,
						email: opts.email,
						status,
					});
					return;
				}
				const user = process.env.DATABASE_URL
					? await updateUserInAuth(store, id, {
							name: opts.name,
							email: opts.email,
							status,
							actor: "cli",
							source: "cli",
						})
					: updateUser(store, id, {
							name: opts.name,
							email: opts.email,
							status,
							actor: "cli",
							source: "cli",
						});
				await flushStore(store);
				printResult(g, { user }, `Updated ${user.email} (${user.id})`);
			} catch (e) {
				fail(e, g);
			}
		});
	users
		.command("disable")
		.argument("<id>")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					printResult(g, { dryRun: true, id });
					return;
				}
				const user = process.env.DATABASE_URL
					? await disableUserInAuth(store, id, {
							actor: "cli",
							source: "cli",
						})
					: disableUser(store, id, {
							actor: "cli",
							source: "cli",
						});
				await flushStore(store);
				printResult(g, { user }, `Disabled ${user.email} (${user.id})`);
			} catch (e) {
				fail(e, g);
			}
		});
	users
		.command("delete")
		.argument("<id>")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				if (!g.yes) {
					throw new ClearanceError({
						code: "USER_DELETE_CONFIRM_REQUIRED",
						message:
							"Refusing user delete without --yes (destructive soft-delete)",
						stage: "users.delete",
						status: 400,
						remediation: "Pass --yes to confirm, or --dry-run to preview",
					});
				}
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					printResult(g, { dryRun: true, id });
					return;
				}
				const user = process.env.DATABASE_URL
					? await deleteUserInAuth(store, id, {
							actor: "cli",
							source: "cli",
						})
					: deleteUser(store, id, {
							actor: "cli",
							source: "cli",
						});
				await flushStore(store);
				printResult(g, { user }, `Deleted ${user.email} (${user.id})`);
			} catch (e) {
				fail(e, g);
			}
		});
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
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				const limit = Number(opts.limit);
				const envelope = exportUsers(store, {
					outputPath: opts.output,
					format: opts.format,
					limit,
					force: Boolean(opts.force),
					...(opts.status ? { status: opts.status } : {}),
					actor: "cli",
					source: "cli",
				});
				await flushStore(store);
				printResult(
					g,
					envelope,
					`Exported ${envelope.count} user(s) to ${envelope.outputPath}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

	// orgs — same canonical management ops as API
	const orgs = program.command("orgs").description("Organizations");
	orgs
		.command("list")
		.option("--limit <n>", "Page size (enables keyset cursor pagination)")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				// Without --limit/--cursor the legacy full-list contract is unchanged.
				if (opts.limit !== undefined || opts.cursor !== undefined) {
					const page = listOrganizationsPage(store, {
						...(opts.limit !== undefined ? { limit: Number(opts.limit) } : {}),
						...(opts.cursor !== undefined ? { cursor: opts.cursor } : {}),
					});
					printResult(g, {
						organizations: page.organizations,
						nextCursor: page.nextCursor,
					});
					return;
				}
				printResult(g, { organizations: listOrganizations(store) });
			} catch (e) {
				fail(e, g);
			}
		});
	orgs
		.command("inspect")
		.argument("<id>")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				printResult(g, { organization: inspectOrganization(store, id) });
			} catch (e) {
				fail(e, g);
			}
		});
	orgs
		.command("create")
		.requiredOption("--name <name>")
		.option("--slug <slug>")
		.option("--owner-user <id>", "Runtime owner user id (defaults to first active principal)")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				let organization;
				if (process.env.DATABASE_URL) {
					const ownerUserId =
						opts.ownerUser ??
						store.snapshot.principals.find((p) => p.status === "active")?.id;
					if (!ownerUserId) {
						throw new Error("Create a user first or pass --owner-user for runtime organization ownership");
					}
					const runtimeOrg = await createOrgInAuth({
						name: opts.name,
						slug: opts.slug,
						userId: ownerUserId,
					});
					organization = await syncRuntimeOrganizationToManagementDurable(
						store,
						runtimeOrg,
						ownerUserId,
						{ actor: "cli", role: "owner" },
					);
				} else {
					organization = createOrganization(store, {
						name: opts.name,
						slug: opts.slug,
						source: "cli",
					});
				}
				await flushStore(store);
				printResult(
					g,
					{
						organization,
						storeBackend: store.backend,
					},
					`Created org ${organization.name}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});
	orgs
		.command("update")
		.argument("<id>")
		.option("--name <name>", "Display name")
		.option("--slug <slug>", "URL slug (lowercase)")
		.action(async (id, opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					printResult(g, {
						dryRun: true,
						id,
						name: opts.name,
						slug: opts.slug,
					});
					return;
				}
				const organization = process.env.DATABASE_URL
					? await updateOrganizationInAuth(store, id, {
							name: opts.name,
							slug: opts.slug,
							actor: "cli",
							source: "cli",
						})
					: updateOrganization(store, id, {
							name: opts.name,
							slug: opts.slug,
							actor: "cli",
							source: "cli",
						});
				await flushStore(store);
				printResult(
					g,
					{ organization, storeBackend: store.backend },
					`Updated org ${organization.name} (${organization.id})`,
				);
			} catch (e) {
				fail(e, g);
			}
		});
	orgs
		.command("archive")
		.argument("<id>")
		.description("Archive an organization (requires --yes; supports --dry-run)")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				// Default dry-run unless --yes. Explicit --dry-run always previews.
				// --no-input without --yes stays non-mutating (plan only).
				const dryRun = g.dryRun || !g.yes;
				const result = process.env.DATABASE_URL
					? await archiveOrganizationInAuth(store, id, {
							dryRun,
							confirm: g.yes && !g.dryRun,
							actor: "cli",
							source: "cli",
						})
					: archiveOrganization(store, id, {
							dryRun,
							confirm: g.yes && !g.dryRun,
							actor: "cli",
							source: "cli",
						});
				if (!result.dryRun) {
					await flushStore(store);
				}
				printResult(
					g,
					{ ...result, storeBackend: store.backend },
					result.dryRun
						? result.wouldChange
							? `Would archive organization ${result.organization.name}`
							: `Would archive organization ${result.organization.name} (already archived)`
						: result.idempotent
							? `Organization ${result.organization.name} already archived`
							: `Archived organization ${result.organization.name}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

	const members = orgs.command("members").description("Organization members");
	members
		.command("import")
		.requiredOption("--org <id>")
		.requiredOption("--file <path>")
		.option("--format <format>", "json|csv (defaults from file extension)")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const explicitFormat = opts.format as string | undefined;
				const inferredFormat = opts.file.toLowerCase().endsWith(".json") ? "json" : opts.file.toLowerCase().endsWith(".csv") ? "csv" : undefined;
				const format = explicitFormat ?? inferredFormat;
				if (format !== "json" && format !== "csv") {
					throw new ClearanceError({ code: "MEMBER_IMPORT_FORMAT_REQUIRED", message: "Member import format is required", stage: "orgs.members.import", remediation: "Use a .json or .csv file, or pass --format json|csv." });
				}
				let content: string;
				try { content = readFileSync(resolve(opts.file), "utf8"); } catch {
					throw new ClearanceError({ code: "MEMBER_IMPORT_FILE_UNREADABLE", message: "Member import file could not be read", stage: "orgs.members.import", remediation: "Provide a readable member import file." });
				}
				const store = await openStore(g);
				await store.refresh();
				const plan = planMemberImport(store, { organizationId: opts.org, content, format: format as MemberImportFormat });
				if (g.dryRun) {
					printResult(g, { dryRun: true, ...plan, storeBackend: store.backend }, `Would import ${plan.summary.wouldAdd} members (${plan.summary.idempotent} already members)`);
					return;
				}
				if (!g.yes) {
					throw new ClearanceError({ code: "MEMBER_IMPORT_CONFIRMATION_REQUIRED", message: "Member import requires --yes", stage: "orgs.members.import", remediation: "Review with --dry-run, then rerun with --yes to apply." });
				}
				const result = await executeMemberImportPlan(plan, async (row) => {
					const membership = process.env.DATABASE_URL
						? await addMemberInAuth(store, { organizationId: plan.organizationId, principalId: row.principalId, role: row.role, source: "import", actor: "cli", auditSource: "import" })
						: addMember(store, { organizationId: plan.organizationId, principalId: row.principalId, role: row.role, source: "import", actor: "cli", auditSource: "import" });
					await flushStore(store);
					return membership;
				});
				printResult(g, { ...result, storeBackend: store.backend }, result.partial ? `Imported ${result.success} members; ${result.failure} failed` : `Imported ${result.success} members`);
				if (result.partial) process.exitCode = 1;
			} catch (e) {
				fail(e, g);
			}
		});
	members
		.command("list")
		.requiredOption("--org <id>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				printResult(g, {
					members: listMembers(store, opts.org),
					storeBackend: store.backend,
				});
			} catch (e) {
				fail(e, g);
			}
		});
	members
		.command("add")
		.requiredOption("--org <id>")
		.requiredOption("--user <id>")
		.option("--role <role>", "Role slug (default: member)", "member")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					printResult(g, {
						dryRun: true,
						organizationId: opts.org,
						principalId: opts.user,
						role: opts.role ?? "member",
					});
					return;
				}
				const membership = process.env.DATABASE_URL
					? await addMemberInAuth(store, {
							organizationId: opts.org,
							principalId: opts.user,
							role: opts.role,
							actor: "cli",
							auditSource: "cli",
						})
					: addMember(store, {
							organizationId: opts.org,
							principalId: opts.user,
							role: opts.role,
							actor: "cli",
							auditSource: "cli",
						});
				await flushStore(store);
				printResult(
					g,
					{ membership, storeBackend: store.backend },
					`Added ${opts.user} to ${opts.org} as ${membership.role}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});
	members
		.command("update")
		.requiredOption("--org <id>")
		.option("--user <id>", "Principal id of the member")
		.option("--member <id>", "Membership id")
		.requiredOption("--role <role>", "New role slug")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				const membershipId = resolveMembershipId(
					store,
					{
						organizationId: opts.org,
						principalId: opts.user,
						membershipId: opts.member,
					},
					"orgs.members.update",
				);
				if (g.dryRun) {
					printResult(g, {
						dryRun: true,
						organizationId: opts.org,
						membershipId,
						role: opts.role,
					});
					return;
				}
				const membership = process.env.DATABASE_URL
					? await updateMemberInAuth(store, membershipId, {
							role: opts.role,
							actor: "cli",
							auditSource: "cli",
						})
					: updateMember(store, membershipId, {
							role: opts.role,
							actor: "cli",
							auditSource: "cli",
						});
				await flushStore(store);
				printResult(
					g,
					{ membership, storeBackend: store.backend },
					`Updated membership ${membership.id} → ${membership.role}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});
	members
		.command("remove")
		.requiredOption("--org <id>")
		.option("--user <id>", "Principal id of the member")
		.option("--member <id>", "Membership id")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				if (!g.yes) {
					throw new ClearanceError({
						code: "MEMBER_REMOVE_CONFIRM_REQUIRED",
						message: "Refusing membership remove without --yes (destructive)",
						stage: "orgs.members.remove",
						status: 400,
						remediation: "Pass --yes to confirm removal",
					});
				}
				const store = await openStore(g);
				await store.refresh();
				const membershipId = resolveMembershipId(
					store,
					{
						organizationId: opts.org,
						principalId: opts.user,
						membershipId: opts.member,
					},
					"orgs.members.remove",
				);
				if (g.dryRun) {
					printResult(g, {
						dryRun: true,
						organizationId: opts.org,
						membershipId,
					});
					return;
				}
				const membership = process.env.DATABASE_URL
					? await removeMemberInAuth(store, membershipId, {
							actor: "cli",
							auditSource: "cli",
						})
					: removeMember(store, membershipId, {
							actor: "cli",
							auditSource: "cli",
						});
				await flushStore(store);
				printResult(
					g,
					{ membership, storeBackend: store.backend },
					`Removed membership ${membership.id}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

	// events — list / tail / inspect / export / replay (shared management services)
	const events = program.command("events").description("Audit events");
	events
		.command("list")
		.option("--limit <n>", "50")
		.option("--action <action>", "Filter by action")
		.option("--org <id>", "Filter by organization id")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				const limit = parseBoundedInteger(opts.limit, {
					name: "limit",
					stage: "events.list",
					code: "EVENTS_LIST_OPTION_INVALID",
					minimum: 1,
					maximum: 1000,
					defaultValue: 50,
				});
				const page = listEventsPage(store, {
					limit,
					...(opts.action ? { action: opts.action } : {}),
					...(opts.org ? { organizationId: opts.org } : {}),
					...(opts.cursor !== undefined ? { cursor: opts.cursor } : {}),
				});
				printResult(g, { events: page.events, nextCursor: page.nextCursor });
			} catch (e) {
				fail(e, g);
			}
		});
	events
		.command("tail")
		.description("Stream scoped audit events by polling the shared store")
		.option("--limit <n>", `Initial history (1-${EVENTS_TAIL_MAX_LIMIT})`, "20")
		.option("--poll-interval <milliseconds>", `Refresh interval (${EVENTS_TAIL_MIN_POLL_INTERVAL_MS}-${EVENTS_TAIL_MAX_POLL_INTERVAL_MS}ms)`, "1000")
		.option("--max-events <n>", "Exit after N events; 0 means unlimited", "0")
		.option("--once", "Emit initial history and exit", false)
		.option("--action <action>", "Filter by action")
		.option("--org <id>", "Filter by organization id")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			const stopSignal = createTailStopSignal();
			try {
				const limit = parseTailInteger(opts.limit, "limit", 1, EVENTS_TAIL_MAX_LIMIT, 20);
				const pollInterval = parseTailInteger(
					opts.pollInterval,
					"poll-interval",
					EVENTS_TAIL_MIN_POLL_INTERVAL_MS,
					EVENTS_TAIL_MAX_POLL_INTERVAL_MS,
					1000,
				);
				// 0 is explicitly unlimited; positive values cap every output path.
				const maxEvents = parseTailInteger(opts.maxEvents, "max-events", 0, Number.MAX_SAFE_INTEGER, 0);
				const store = await openStore(g);
				await store.refresh();
				if (stopSignal.stopped) return;
				const { cursor, events: initial } = beginEventsTail(store, {
					limit,
					...(opts.action ? { action: opts.action } : {}),
					...(opts.org ? { organizationId: opts.org } : {}),
				});
				let emitted = 0;
				const emit = (batch: typeof initial): boolean => {
					for (const event of batch) {
						if (maxEvents !== 0 && emitted >= maxEvents) return true;
						writeTailEvent(Boolean(g.json), event);
						emitted += 1;
					}
					return maxEvents !== 0 && emitted >= maxEvents;
				};
				if (emit(initial) || opts.once) return;
				while (true) {
					if (await stopSignal.wait(pollInterval)) return;
					await store.refresh();
					if (stopSignal.stopped) return;
					if (emit(pollEventsTail(store, cursor))) return;
				}
			} catch (e) {
				fail(e, g);
			} finally {
				stopSignal.dispose();
			}
		});
	events
		.command("inspect")
		.argument("<id>", "Event id or diagnostic trace id")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				const result = inspectEvent(store, id);
				printResult(
					g,
					result,
					result.event
						? `Event ${result.event.id}`
						: result.trace
							? `Trace ${result.trace.id}`
							: "Inspect",
				);
			} catch (e) {
				fail(e, g);
			}
		});
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
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				const limit = Number(opts.limit);
				const envelope = exportEvents(store, {
					outputPath: opts.output,
					format: opts.format,
					limit,
					force: Boolean(opts.force),
					...(opts.action ? { action: opts.action } : {}),
					...(opts.org ? { organizationId: opts.org } : {}),
					...(opts.before ? { before: opts.before } : {}),
					actor: "cli",
					source: "cli",
				});
				await flushStore(store);
				printResult(
					g,
					envelope,
					`Exported ${envelope.count} event(s) to ${envelope.outputPath}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});
	events
		.command("replay")
		.description(
			"Re-record a SCIM diagnostic trace (default dry-run; --yes to apply)",
		)
		.argument("<id>", "SCIM diagnostic trace id")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				// Default dry-run unless --yes. Explicit --dry-run always previews.
				const dryRun = g.dryRun || !g.yes;
				const result = replayDiagnosticTrace(store, id, {
					dryRun,
					confirm: g.yes && !g.dryRun,
					actor: "cli",
					source: "cli",
				});
				if (!result.dryRun) {
					await flushStore(store);
				}
				printResult(
					g,
					result,
					result.dryRun
						? `Would replay diagnostic trace ${result.original.id}`
						: result.idempotent
							? `Replay already present for ${result.original.id}`
							: `Replayed diagnostic trace ${result.original.id} → ${result.trace.id}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

	// keys — digest-only project/environment scoped API-key lifecycle
	const keys = program.command("keys").description("Project and environment API keys");
	keys.command("list").option("--include-revoked", "Include revoked keys", false).action(async (opts, cmd) => {
		const g = globals(cmd);
		try {
			const store = await openStore(g);
			await store.refresh();
			const apiKeys = listApiKeys(store, { includeRevoked: Boolean(opts.includeRevoked) });
			printResult(g, { apiKeys }, `API keys: ${apiKeys.length}`);
		} catch (e) { fail(e, g); }
	});
	keys.command("create").requiredOption("--name <name>", "Human-readable key name")
		.option("--scope <scope>", "Repeatable resource:action scope", (value, previous: string[] = []) => [...previous, value], [])
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					const name = validateApiKeyName(opts.name, "keys.create");
					const scopes = normalizeAndValidateApiKeyScopes(opts.scope, "keys.create");
					printResult(g, { dryRun: true, apiKey: { name, scopes }, secretGenerated: false }, `Would create API key ${name}`);
					return;
				}
				const result = await createApiKey(store, { name: opts.name, scopes: opts.scope, actor: "cli", source: "cli" });
				await flushStore(store);
				printResult(
					g,
					result,
					`Created API key ${result.apiKey.id}\nSecret: ${result.secret}\nSave this secret now; it will not be shown again.`,
				);
			} catch (e) { fail(e, g); }
		});
	keys.command("rotate").argument("<id>", "API key id").action(async (id, _, cmd) => {
		const g = globals(cmd);
		try {
			if (!g.yes && !g.dryRun) throw new ClearanceError({ code: "API_KEY_CONFIRMATION_REQUIRED", message: "API key rotate requires confirmation", stage: "keys.rotate", status: 400, remediation: "Pass --yes to rotate, or --dry-run to preview" });
			const store = await openStore(g);
			await store.refresh();
			if (g.dryRun) {
				const apiKey = inspectApiKey(store, id);
				if (apiKey.status === "revoked") throw new ClearanceError({ code: "API_KEY_REVOKED", message: "Revoked API keys cannot be rotated", stage: "keys.rotate", status: 409 });
				printResult(g, { dryRun: true, apiKey, secretGenerated: false }, `Would rotate API key ${id}`);
				return;
			}
			const result = await rotateApiKey(store, id, { actor: "cli", source: "cli" });
			await flushStore(store);
			printResult(
				g,
				result,
				`Rotated API key ${id}\nSecret: ${result.secret}\nSave this secret now; it will not be shown again.`,
			);
		} catch (e) { fail(e, g); }
	});
	keys.command("revoke").argument("<id>", "API key id").action(async (id, _, cmd) => {
		const g = globals(cmd);
		try {
			if (!g.yes && !g.dryRun) throw new ClearanceError({ code: "API_KEY_CONFIRMATION_REQUIRED", message: "API key revoke requires confirmation", stage: "keys.revoke", status: 400, remediation: "Pass --yes to revoke the API key" });
			const store = await openStore(g);
			await store.refresh();
			if (g.dryRun) {
				const apiKey = inspectApiKey(store, id);
				printResult(g, { dryRun: true, apiKey, wouldChange: apiKey.status === "active" }, `Would revoke API key ${id}`);
				return;
			}
			const result = await revokeApiKey(store, id, { actor: "cli", source: "cli" });
			await flushStore(store);
			printResult(g, result, result.idempotent ? `API key ${id} already revoked` : `Revoked API key ${id}`);
		} catch (e) { fail(e, g); }
	});

	// sessions — list / revoke under principal-derived scope (runtime when DATABASE_URL)
	const sessions = program.command("sessions").description("Auth sessions");
	sessions
		.command("list")
		.option("--limit <n>", "Max sessions to return (page size)", "100")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				// Code matches the shipped service-level validator (sessions.ts
				// SESSION_LIMIT_INVALID) so the observable contract is unchanged;
				// this CLI-layer check just fails closed before any store access.
				const limit = parseBoundedInteger(opts.limit, {
					name: "limit",
					stage: "sessions.list",
					code: "SESSION_LIMIT_INVALID",
					minimum: 1,
					maximum: 1000,
					defaultValue: 100,
				});
				const page = process.env.DATABASE_URL
					? await listSessionsPageInAuth(store, {
							limit,
							...(opts.cursor !== undefined ? { cursor: opts.cursor } : {}),
						})
					: listSessionsPage(store, {
							limit,
							...(opts.cursor !== undefined ? { cursor: opts.cursor } : {}),
						});
				printResult(
					g,
					{ sessions: page.sessions, nextCursor: page.nextCursor },
					`Sessions: ${page.sessions.length}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});
	sessions
		.command("revoke")
		.argument("<id>", "Stable session id")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				if (!g.yes && !g.dryRun) {
					throw new ClearanceError({
						code: "SESSION_CONFIRM_REQUIRED",
						message: "Session revoke requires confirmation",
						stage: "sessions.revoke",
						status: 400,
						remediation: "Pass --yes to revoke the session",
					});
				}
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					const session = process.env.DATABASE_URL
						? await inspectSessionInAuth(store, id)
						: inspectSession(store, id);
					printResult(
						g,
						{
							dryRun: true,
							session,
							wouldChange: session.status === "active",
						},
						`Would revoke session ${id}`,
					);
					return;
				}
				const result = process.env.DATABASE_URL
					? await revokeSessionInAuth(store, id, {
							actor: "cli",
							source: "cli",
						})
					: revokeSession(store, id, {
							actor: "cli",
							source: "cli",
						});
				await flushStore(store);
				printResult(
					g,
					result,
					result.idempotent
						? `Session ${result.session.id} already revoked`
						: `Revoked session ${result.session.id}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

	// roles — canonical project/environment-scoped role services shared with API/console
	const roles = program.command("roles").description("Custom access-control roles");
	roles
		.command("list")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				printResult(g, { roles: listRoles(store) });
			} catch (e) {
				fail(e, g);
			}
		});
	roles
		.command("validate")
		.option("--name <name>")
		.option("--slug <slug>")
		.option("--permission <permission...>", "One or more resource:action permissions")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				const validation = validateRole(store, {
					name: opts.name,
					slug: opts.slug,
					permissions: opts.permission,
				});
				printResult(g, { validation }, "Role definition is valid");
			} catch (e) {
				fail(e, g);
			}
		});
	roles
		.command("create")
		.requiredOption("--name <name>")
		.option("--slug <slug>")
		.option("--description <description>")
		.requiredOption("--permission <permission...>", "One or more resource:action permissions")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				const draft = {
					name: opts.name as string,
					slug: opts.slug as string | undefined,
					description: opts.description as string | undefined,
					permissions: opts.permission as string[],
				};
				if (g.dryRun) {
					const validation = validateRole(store, draft);
					printResult(g, { dryRun: true, validation });
					return;
				}
				const role = await createRole(store, {
					...draft,
					actor: "cli",
					source: "cli",
				});
				await flushStore(store);
				printResult(g, { role }, `Created role ${role.slug}`);
			} catch (e) {
				fail(e, g);
			}
		});
	roles
		.command("update")
		.argument("<id>")
		.option("--name <name>")
		.option("--description <description>")
		.option("--permission <permission...>", "Replacement resource:action permissions")
		.action(async (id, opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				const patch = {
					name: opts.name as string | undefined,
					description: opts.description as string | undefined,
					permissions: opts.permission as string[] | undefined,
				};
				if (g.dryRun) {
					const validation = validateRole(store, patch);
					printResult(g, { dryRun: true, id, validation });
					return;
				}
				const role = await updateRole(store, id, {
					...patch,
					actor: "cli",
					source: "cli",
				});
				await flushStore(store);
				printResult(g, { role }, `Updated role ${role.slug}`);
			} catch (e) {
				fail(e, g);
			}
		});

	// sso
	const sso = program.command("sso").description("Enterprise SSO connections");
	sso
		.command("create")
		.requiredOption("--org <id>")
		.requiredOption("--provider <name>")
		.option("--protocol <protocol>", "oidc")
			.requiredOption("--issuer <url>")
			.option("--audience <aud>")
			.option("--domain <domain>")
			.option("--entry-point <url>", "SAML identity provider SSO URL")
			.option("--certificate <path>", "SAML identity provider signing certificate PEM")
			.action(async (opts, cmd) => {
				const g = globals(cmd);
				try {
					const store = await openStore(g);
					const saml = opts.protocol === "saml"
						? validateSamlProviderConfig({
								entryPoint: opts.entryPoint,
								certificate: opts.certificate
									? readFileSync(resolve(opts.certificate), "utf8")
									: undefined,
							})
						: undefined;
					const connection = process.env.DATABASE_URL
					? await createSsoConnectionReal(store, {
							organizationId: opts.org,
							provider: opts.provider,
							protocol: opts.protocol === "saml" ? "saml" : "oidc",
							issuer: opts.issuer ?? "https://login.microsoftonline.com/common/v2.0",
							audience: opts.audience,
								domain: opts.domain,
								samlEntryPoint: saml?.entryPoint,
								samlCertificate: saml?.certificate,
					  })
					: createSsoConnection(store, {
							organizationId: opts.org,
							provider: opts.provider,
							protocol: opts.protocol === "saml" ? "saml" : "oidc",
							issuer: opts.issuer,
							audience: opts.audience,
								domains: opts.domain ? [opts.domain] : [],
								samlEntryPoint: saml?.entryPoint,
								samlCertificate: saml?.certificate,
						  });
				await flushStore(store);
				printResult(g, { connection });
			} catch (e) {
				fail(e, g);
			}
		});
	sso
		.command("configure")
		.argument("<id>")
		.option("--issuer <url>")
		.option("--audience <aud>")
		.option("--domain <domain>")
		.action(async (id, opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				if (g.dryRun) {
					const current = inspectSsoConnection(store, id);
					printResult(g, {
						dryRun: true,
						connection: current,
						proposed: {
							issuer: opts.issuer ?? current.issuer,
							audience: opts.audience ?? current.audience,
							domains: opts.domain ? [opts.domain] : current.domains,
						},
					}, `Would configure SSO connection ${id}.`);
					return;
				}
				const connection = configureSsoConnection(
					store,
					id,
					{
						issuer: opts.issuer,
						audience: opts.audience,
						domains: opts.domain ? [opts.domain] : undefined,
					},
					{ actor: "cli", source: "cli" },
				);
				await flushStore(store);
				printResult(g, { connection });
			} catch (e) {
				fail(e, g);
			}
		});
	sso
		.command("test")
		.argument("<id>")
		.option("--fixture <name>", "ok|wrong-issuer|wrong-audience|malformed|expired|clock-skew|replay")
		.option(
			"--live",
			"Probe the REAL configured issuer (read-only discovery/JWKS conformance). Requires --yes, HTTPS, non-loopback.",
			false,
		)
		.action(async (id, opts, cmd) => {
			const g = globals(cmd);
			try {
				if (opts.live && opts.fixture) {
					throw new ClearanceError({
						code: "SSO_TEST_MODE_CONFLICT",
						message: "--live and --fixture are mutually exclusive",
						stage: "sso.test",
						status: 400,
						remediation: "Use --live for the real tenant, or --fixture for the simulation lab",
					});
				}
				if (opts.live && !g.yes) {
					throw new ClearanceError({
						code: "SSO_LIVE_CONFIRM_REQUIRED",
						message: "Live conformance contacts the real external IdP and requires confirmation",
						stage: "sso.test",
						status: 400,
						remediation: "Pass --yes to arm the live probe (read-only; no tenant mutation)",
					});
				}
				const store = await openStore(g);
				const result = opts.live
					? await testSsoConnectionLive(store, id)
					: process.env.DATABASE_URL
						? testSsoConnectionReal(store, id, { fixture: opts.fixture ?? "ok" })
						: testSsoConnection(store, id, { fixture: opts.fixture ?? "ok" });
				if (opts.live) await flushStore(store);
				printResult(g, result, "SSO test passed");
			} catch (e) {
				fail(e, g);
			}
		});
	sso
		.command("list")
		.option("--org <id>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				printResult(g, { connections: listSsoConnections(store, opts.org) });
			} catch (e) {
				fail(e, g);
			}
		});
	sso
		.command("setup-link")
		.requiredOption("--org <id>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const link = createSetupLink(store, { organizationId: opts.org, kind: "sso" });
				await flushStore(store);
				printResult(g, link);
			} catch (e) {
				fail(e, g);
			}
		});
	sso
		.command("rotate")
		.description("Rotate SSO client-secret credential envelope under the current key")
		.argument("<id>", "SSO connection id")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				if (!g.yes && !g.dryRun) {
					throw new ClearanceError({
						code: "SSO_CONFIRM_REQUIRED",
						message: "SSO credential rotate requires confirmation",
						stage: "sso.rotate",
						status: 400,
						remediation: "Pass --yes to rotate, or --dry-run to preview",
					});
				}
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					const connection = inspectSsoConnection(store, id);
					const hasSecret = Boolean(
						(connection as { hasClientSecret?: boolean }).hasClientSecret ??
							connection.clientSecretFingerprint,
					);
					if (!hasSecret) {
						throw new ClearanceError({
							code: "SSO_NO_SECRET",
							message: "No encrypted client secret to rotate",
							stage: "sso.rotate",
							status: 400,
							remediation: "Configure a client secret before rotating",
						});
					}
					printResult(
						g,
						{
							dryRun: true,
							connection,
							wouldChange: true,
						},
						`Would rotate SSO credential for ${id}`,
					);
					return;
				}
				const connection = rotateSsoCredential(store, id, {
					actor: "cli",
					source: "cli",
				});
				await flushStore(store);
				printResult(g, { connection }, `Rotated SSO credential for ${id}`);
			} catch (e) {
				fail(e, g);
			}
		});
	sso
		.command("disable")
		.description("Disable an SSO connection")
		.argument("<id>", "SSO connection id")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				if (!g.yes && !g.dryRun) {
					throw new ClearanceError({
						code: "SSO_CONFIRM_REQUIRED",
						message: "SSO disable requires confirmation",
						stage: "sso.disable",
						status: 400,
						remediation: "Pass --yes to disable, or --dry-run to preview",
					});
				}
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					const connection = inspectSsoConnection(store, id);
					printResult(
						g,
						{
							dryRun: true,
							connection,
							wouldChange: connection.status !== "disabled",
						},
						`Would disable SSO connection ${id}`,
					);
					return;
				}
				const result = process.env.DATABASE_URL
					? await disableSsoConnectionReal(store, id, {
							actor: "cli",
							source: "cli",
						})
					: disableSsoConnection(store, id, {
							actor: "cli",
							source: "cli",
						});
				await flushStore(store);
				printResult(
					g,
					result,
					result.idempotent
						? `SSO connection ${result.connection.id} already disabled`
						: `Disabled SSO connection ${result.connection.id}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

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
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const connection = process.env.DATABASE_URL
					? await createScimConnectionReal(store, {
							organizationId: opts.org,
							provider: opts.provider,
							...(opts.endpoint ? { endpoint: opts.endpoint } : {}),
					  })
					: createScimConnection(store, {
							organizationId: opts.org,
							provider: opts.provider,
							...(opts.endpoint ? { endpoint: opts.endpoint } : {}),
					  });
				await flushStore(store);
				printResult(g, { connection });
			} catch (e) {
				fail(e, g);
			}
		});
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
		.action(async (id, opts, cmd) => {
			const g = globals(cmd);
			try {
				if (opts.live && opts.fixture) {
					throw new ClearanceError({
						code: "SCIM_TEST_MODE_CONFLICT",
						message: "--live and --fixture are mutually exclusive",
						stage: "scim.test",
						status: 400,
						remediation: "Use --live for the real tenant, or --fixture for the simulation lab",
					});
				}
				if (opts.live && !g.yes) {
					throw new ClearanceError({
						code: "SCIM_LIVE_CONFIRM_REQUIRED",
						message: "Live conformance contacts the real external SCIM endpoint and requires confirmation",
						stage: "scim.test",
						status: 400,
						remediation: "Pass --yes to arm the live probe (read-only; no tenant mutation)",
					});
				}
				const store = await openStore(g);
				const result = opts.live
					? await testScimConnectionLive(store, id)
					: process.env.DATABASE_URL
						? await testScimConnectionReal(store, id, {
								dryRun: !opts.apply,
								fixture: opts.fixture ?? "ok",
						  })
						: testScimConnection(store, id, {
								dryRun: !opts.apply,
								fixture: opts.fixture ?? "ok",
						  });
				if (opts.live) await flushStore(store);
				printResult(g, result, "SCIM test passed");
			} catch (e) {
				fail(e, g);
			}
		});
	scim
		.command("list")
		.option("--org <id>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				printResult(g, { connections: listScimConnections(store, opts.org) });
			} catch (e) {
				fail(e, g);
			}
		});
	scim
		.command("setup-link")
		.requiredOption("--org <id>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const link = createSetupLink(store, { organizationId: opts.org, kind: "scim" });
				await flushStore(store);
				printResult(g, link);
			} catch (e) {
				fail(e, g);
			}
		});
	scim
		.command("rotate")
		.description("Rotate SCIM bearer credential envelope under the current key")
		.argument("<id>", "SCIM connection id")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				if (!g.yes && !g.dryRun) {
					throw new ClearanceError({
						code: "SCIM_CONFIRM_REQUIRED",
						message: "SCIM credential rotate requires confirmation",
						stage: "scim.rotate",
						status: 400,
						remediation: "Pass --yes to rotate, or --dry-run to preview",
					});
				}
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					const connection = inspectScimConnection(store, id);
					const hasToken = Boolean(
						(connection as { hasBearerToken?: boolean }).hasBearerToken ??
							connection.bearerTokenFingerprint,
					);
					if (!hasToken) {
						throw new ClearanceError({
							code: "SCIM_NO_TOKEN",
							message: "No encrypted bearer token to rotate",
							stage: "scim.rotate",
							status: 400,
							remediation: "Recreate the SCIM connection to mint a bearer token",
						});
					}
					printResult(
						g,
						{
							dryRun: true,
							connection,
							wouldChange: true,
						},
						`Would rotate SCIM credential for ${id}`,
					);
					return;
				}
				const connection = rotateScimCredential(store, id, {
					actor: "cli",
					source: "cli",
				});
				await flushStore(store);
				printResult(g, { connection }, `Rotated SCIM credential for ${id}`);
			} catch (e) {
				fail(e, g);
			}
		});
	scim
		.command("disable")
		.description("Disable a SCIM directory connection")
		.argument("<id>", "SCIM connection id")
		.action(async (id, _, cmd) => {
			const g = globals(cmd);
			try {
				if (!g.yes && !g.dryRun) {
					throw new ClearanceError({
						code: "SCIM_CONFIRM_REQUIRED",
						message: "SCIM disable requires confirmation",
						stage: "scim.disable",
						status: 400,
						remediation: "Pass --yes to disable, or --dry-run to preview",
					});
				}
				const store = await openStore(g);
				await store.refresh();
				if (g.dryRun) {
					const connection = inspectScimConnection(store, id);
					printResult(
						g,
						{
							dryRun: true,
							connection,
							wouldChange: connection.status !== "disabled",
						},
						`Would disable SCIM connection ${id}`,
					);
					return;
				}
				const result = process.env.DATABASE_URL
					? await disableScimConnectionReal(store, id, {
							actor: "cli",
							source: "cli",
						})
					: disableScimConnection(store, id, {
							actor: "cli",
							source: "cli",
						});
				await flushStore(store);
				printResult(
					g,
					result,
					result.idempotent
						? `SCIM connection ${result.connection.id} already disabled`
						: `Disabled SCIM connection ${result.connection.id}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});
	scim
		.command("replay")
		.description(
			"Re-record a SCIM diagnostic trace (default dry-run; --yes to apply)",
		)
		.argument("<traceId>", "SCIM diagnostic trace id")
		.action(async (traceId, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				await store.refresh();
				// Shared service: validates scope, defaults to dry-run unless --yes.
				const dryRun = g.dryRun || !g.yes;
				const result = replayDiagnosticTrace(store, traceId, {
					dryRun,
					confirm: g.yes && !g.dryRun,
					actor: "cli",
					source: "cli",
				});
				if (!result.dryRun) {
					await flushStore(store);
				}
				printResult(
					g,
					result,
					result.dryRun
						? `Would replay SCIM trace ${result.original.id}`
						: result.idempotent
							? `Replay already present for ${result.original.id}`
							: `Replayed SCIM trace ${result.original.id} → ${result.trace.id}`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

	// readiness
	const readiness = program.command("readiness").description("Enterprise readiness");
	readiness
		.command("check")
		.requiredOption("--org <id>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const report = runReadinessCheck(store, opts.org);
				await flushStore(store);
				printResult(g, { report });
			} catch (e) {
				fail(e, g);
			}
		});
	readiness
		.command("report")
		.requiredOption("--org <id>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const report = getLatestReadiness(store, opts.org);
				printResult(g, { report });
			} catch (e) {
				fail(e, g);
			}
		});

	// migration
	const imports = program.command("import").description("Import supported auth exports");
	imports
		.command("legacy")
		.description("Preview or import a validated legacy export")
		.requiredOption("--file <path>", "Local legacy JSON export")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const fixture = loadLegacyFixture(resolve(opts.file));
				const store = await openStore(g);
				await store.refresh();
				const preview = previewMigration(store, fixture);
				if (g.dryRun) {
					printResult(
						g,
						{ schemaVersion: "v1", dryRun: true, source: "legacy", preview, storeBackend: store.backend },
						`Would import ${preview.wouldCreate.users} users, ${preview.wouldCreate.organizations} organizations, and ${preview.wouldCreate.members} memberships`,
					);
					return;
				}
				if (!g.yes) {
					throw new ClearanceError({
						code: "CLEARANCE_IMPORT_CONFIRMATION_REQUIRED",
						message: "Legacy import requires --yes",
						stage: "import.legacy",
						remediation: "Review with --dry-run, then rerun with --yes to import.",
					});
				}
				const planned = planMigration(store, fixture);
				await flushStore(store);
				await store.refresh();
				await runMigrationDurable(store, planned.id, fixture);
				const verification = await verifyMigrationDurable(store, planned.id, fixture);
				await flushStore(store);
				const result = {
					schemaVersion: "v1",
					dryRun: false,
					source: "legacy" as const,
					migration: verification.plan,
					preview,
					verification: { reconciled: verification.reconciled, expected: verification.expected, actual: verification.actual },
					storeBackend: store.backend,
				};
				const idempotent = preview.wouldCreate.users + preview.wouldCreate.organizations + preview.wouldCreate.members === 0;
				printResult(g, result, idempotent ? "Legacy import already reconciled" : `Imported legacy export: ${verification.actual.users} users, ${verification.actual.organizations} organizations, ${verification.actual.members} memberships`);
			} catch (e) {
				fail(e, g);
			}
		});

	const migration = program.command("migration").description("Tenant migration");
	migration
		.command("plan")
		.requiredOption("--source <source>", "legacy")
		.requiredOption("--fixture <path>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				if (opts.source !== "legacy") throw new ClearanceError({ code: "CLEARANCE_IMPORT_SOURCE_INVALID", message: "Only legacy imports are supported", stage: "migration.plan", remediation: "Use --source legacy." });
				const fixture = loadLegacyFixture(opts.fixture);
				const plan = planMigration(store, fixture);
				await flushStore(store);
				printResult(g, { plan });
			} catch (e) {
				fail(e, g);
			}
		});
	migration
		.command("run")
		.requiredOption("--id <planId>")
		.requiredOption("--fixture <path>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const fixture = loadLegacyFixture(opts.fixture);
				const plan = await runMigrationDurable(store, opts.id, fixture, {
					dryRun: g.dryRun,
				});
				await flushStore(store);
				printResult(g, { plan });
			} catch (e) {
				fail(e, g);
			}
		});
	migration
		.command("verify")
		.requiredOption("--id <planId>")
		.requiredOption("--fixture <path>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const fixture = loadLegacyFixture(opts.fixture);
				const result = await verifyMigrationDurable(store, opts.id, fixture);
				await flushStore(store);
				printResult(g, result);
			} catch (e) {
				fail(e, g);
			}
		});
	migration
		.command("rollback")
		.requiredOption("--id <planId>")
		.requiredOption("--fixture <path>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				if (!g.yes) {
					throw new ClearanceError({
						code: "MIGRATION_ROLLBACK_CONFIRM_REQUIRED",
						message: "Refusing rollback without --yes",
						stage: "migration.rollback",
						status: 400,
						remediation: "Pass --yes to confirm rollback",
					});
				}
				const store = await openStore(g);
				const fixture = loadLegacyFixture(opts.fixture);
				const plan = await rollbackMigrationDurable(store, opts.id, fixture);
				await flushStore(store);
				printResult(g, { plan });
			} catch (e) {
				fail(e, g);
			}
		});
	migration
		.command("status")
		.requiredOption("--id <planId>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				printResult(g, { plan: migrationStatus(store, opts.id) });
			} catch (e) {
				fail(e, g);
			}
		});

	// backup
	const backup = program.command("backup").description("Backup and restore");
	backup
		.command("create")
		.option("--dir <path>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const record = process.env.DATABASE_URL
					? createPostgresBackup(store, opts.dir)
					: createBackup(store, opts.dir);
				await flushStore(store);
				printResult(g, { backup: record });
			} catch (e) {
				fail(e, g);
			}
		});
	backup
		.command("verify")
		.requiredOption("--id <backupId>")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const backup = process.env.DATABASE_URL
					? await verifyPostgresBackup(store, opts.id)
					: verifyBackup(store, opts.id);
				await flushStore(store);
				printResult(g, { backup });
			} catch (e) {
				fail(e, g);
			}
		});
	backup
		.command("restore")
		.requiredOption("--id <backupId>")
		.option("--target <path>", "Restore target path or isolated Postgres database name")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				if (process.env.DATABASE_URL) {
					const r = await restorePostgresBackup(store, opts.id, opts.target);
					await flushStore(store);
					printResult(g, r);
				} else {
					if (!opts.target) {
						throw new ClearanceError({
							code: "BACKUP_RESTORE_TARGET_REQUIRED",
							message: "A restore target path is required when Postgres is not configured",
							stage: "backup.restore",
							status: 400,
							remediation: "Pass --target <path>",
						});
					}
					const restored = restoreBackup(store, opts.id, opts.target);
					await flushStore(store);
					printResult(g, restored);
				}
			} catch (e) {
				fail(e, g);
			}
		});

	// upgrade
	const upgrade = program.command("upgrade").description("Upgrade tooling");
	upgrade
		.command("check")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const result = process.env.DATABASE_URL
					? await upgradeCheckWithDb(store)
					: upgradeCheck(store);
				await flushStore(store);
				printResult(g, result);
			} catch (e) {
				fail(e, g);
			}
		});
	upgrade
		.command("plan")
		.requiredOption("--target <version>", "Target release version")
		.requiredOption("--dir <path>", "Absolute upgrade artifact directory")
		.option("--current <version>", "Current release version override")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const result = await planUpgrade({ ...opts, dryRun: g.dryRun });
				const human = "id" in result.plan
					? `Upgrade plan ${result.plan.id}: ${result.plan.currentVersion} → ${result.plan.targetVersion}`
					: `Would create upgrade plan for ${opts.target}`;
				printResult(g, result, human);
			} catch (e) {
				fail(e, g);
			}
		});
	upgrade
		.command("apply")
		.requiredOption("--plan <id-or-path>", "Plan ID or plan path")
		.requiredOption("--dir <path>", "Absolute upgrade artifact directory")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const result = await applyUpgrade({ ...opts, dryRun: g.dryRun, yes: g.yes });
				printResult(g, result, g.dryRun ? `Would apply upgrade ${result.plan.id}` : `Applied upgrade ${result.plan.id} (${result.plan.status})`);
			} catch (e) {
				fail(e, g);
			}
		});
	upgrade
		.command("verify")
		.requiredOption("--plan <id-or-path>", "Plan ID or plan path")
		.requiredOption("--dir <path>", "Absolute upgrade artifact directory")
		.option("--health-url <url>", "Optional credential-free HTTP(S) health endpoint")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const result = await verifyUpgrade({ ...opts, dryRun: g.dryRun });
				printResult(g, result, g.dryRun ? `Would verify upgrade ${result.plan.id}` : `Verified upgrade ${result.plan.id} (${result.plan.status})`);
			} catch (e) {
				fail(e, g);
			}
		});
	upgrade
		.command("rollback")
		.description("Verify a rollback in isolation, or explicitly restore the active database")
		.requiredOption("--plan <id-or-path>", "Plan ID or plan path")
		.requiredOption("--dir <path>", "Absolute upgrade artifact directory")
		.option("--restore-active", "Restore the rollback backup into the active database", false)
		.option("--confirm <token>", "Exact RESTORE_ACTIVE:<plan-id>:<database> confirmation")
		.option("--backup-dir <path>", "Absolute directory for the pre-restore safety backup")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const result = await rollbackUpgrade({ ...opts, dryRun: g.dryRun, yes: g.yes });
				printResult(
					g,
					result,
					g.dryRun
						? `Would run ${result.mode} for ${result.plan.id}`
						: result.mode === "active_database_restore"
							? `Restored the active database for ${result.plan.id}; receipt ${result.rollbackReceipt}`
							: `Rollback reference verified for ${result.plan.id}; active database unchanged`,
				);
			} catch (e) {
				fail(e, g);
			}
		});

	// schema
	const schema = program.command("schema").description("Management and runtime schema lifecycle");
	schema
		.command("status")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				printResult(g, {
					management: {
						schemaVersion: store.snapshot.meta.schemaVersion,
						releaseVersion: store.snapshot.releaseVersion,
						initializedAt: store.snapshot.meta.initializedAt,
					},
					runtime: await getRuntimeSchemaStatus(),
				});
			} catch (e) {
				fail(e, g);
			}
		});
	schema
		.command("generate")
		.description("Compile pending Clearance Postgres SQL without applying it")
		.option("--output <path>", "Output SQL file path (required)")
		.option("--force", "Overwrite an existing output artifact", false)
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				if (!opts.output) {
					throw new ClearanceError({
						code: "SCHEMA_GENERATE_OUTPUT_REQUIRED",
						message: "schema generate requires an explicit --output path.",
						stage: "schema.generate",
						remediation: "Provide --output <path> for the generated SQL artifact.",
					});
				}
				printResult(g, await generateRuntimeSchema({
					outputPath: opts.output,
					force: Boolean(opts.force),
					dryRun: Boolean(g.dryRun),
				}));
			} catch (e) {
				fail(e, g);
			}
		});
	schema
		.command("migrate")
		.description("Apply pending Clearance migrations and lifecycle compatibility ensures")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				if (!g.yes && !g.dryRun) {
					throw new ClearanceError({
						code: "SCHEMA_MIGRATE_CONFIRMATION_REQUIRED",
						message: "schema migrate requires --yes before applying changes.",
						stage: "schema.migrate",
						remediation: "Re-run with --dry-run to inspect, or add --yes to apply.",
					});
				}
				printResult(g, await migrateRuntimeSchema({ dryRun: Boolean(g.dryRun) }));
			} catch (e) {
				fail(e, g);
			}
		});

	// config
	const config = program.command("config").description("Config");
	config
		.command("get")
		.argument("[key]")
		.action(async (key, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				printResult(g, publicConfig(store.snapshot.meta.config, key));
			} catch (e) {
				fail(e, g);
			}
		});
	config
		.command("set")
		.argument("<key>")
		.argument("<value>")
		.action(async (key, value, _, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const candidate = { ...store.snapshot.meta.config, [key]: value };
				validateConfig(store, candidate);
				const changed = store.snapshot.meta.config[key] !== value;
				if (g.dryRun) {
					printResult(g, {
						dryRun: true,
						changed,
						key,
						config: publicConfig(candidate).config,
					});
					return;
				}
				const result = setConfig(store, key, value);
				if (result.changed) await flushStore(store);
				printResult(g, {
					ok: true,
					changed: result.changed,
					key,
					config: publicConfig(result.config).config,
				});
			} catch (e) {
				fail(e, g);
			}
		});
	config
		.command("validate")
		.option("--file <json-file>", "Candidate config JSON file")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				let candidate = store.snapshot.meta.config;
				if (opts.file) candidate = readConfigCandidate(opts.file);
				validateConfig(store, candidate);
				const visible = publicConfig(candidate);
				printResult(g, {
					ok: true,
					source: opts.file ? "file" : "current",
					config: visible.config,
					redactedKeys: visible.redactedKeys,
				});
			} catch (e) {
				fail(e, g);
			}
		});
	config
		.command("diff")
		.requiredOption("--file <json-file>", "Candidate config JSON file")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				const candidate = readConfigCandidate(opts.file);
				validateConfig(store, candidate);
				printResult(g, diffConfig(store.snapshot.meta.config, candidate));
			} catch (e) {
				fail(e, g);
			}
		});

	// overview for console parity
	program
		.command("overview")
		.description("Dashboard overview stats")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				const store = await openStore(g);
				printResult(g, overviewStats(store));
			} catch (e) {
				fail(e, g);
			}
		});

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

	try {
		await program.parseAsync();
	} finally {
		await closeStores();
		await closeAuthBundle();
	}
}

main().catch((err) => {
	if (err instanceof CliExitError) {
		process.exitCode = err.exitCode;
		return;
	}
	console.error(err);
	process.exitCode = 1;
});
