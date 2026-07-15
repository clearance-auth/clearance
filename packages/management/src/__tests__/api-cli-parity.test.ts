/**
 * CLI and API use runtime-first lifecycle operations with Postgres and retain
 * the management-only fallback for JSON development stores.
 */
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
	JsonStore,
	createOrganization,
	createUser,
	initProject,
	listOrganizations,
	listUsers,
} from "../index.js";

const dirs: string[] = [];
const here = dirname(fileURLToPath(import.meta.url));
const cliSource = join(here, "..", "..", "..", "clearance-cli", "src", "index.ts");
const remoteDispatchSource = join(
	here,
	"..",
	"..",
	"..",
	"clearance-cli",
	"src",
	"remote-dispatch.ts",
);
const dispatchDir = join(here, "..", "..", "..", "clearance-cli", "src", "dispatch");
const organizationDispatchSource = join(
	here,
	"..",
	"..",
	"..",
	"clearance-cli",
	"src",
	"dispatch",
	"organizations.ts",
);
const accessDispatchSource = join(dispatchDir, "access.ts");
const usersApplicationSource = join(here, "..", "application", "users.ts");
const applicationFactorySource = join(
	here,
	"..",
	"application",
	"management-application.ts",
);
const authRuntimeAdapterSource = join(
	here,
	"..",
	"adapters",
	"auth-bridge-runtime-gateway.ts",
);
const apiSource = join(
	here,
	"..",
	"..",
	"..",
	"clearance-api",
	"src",
	"server.ts",
);
const apiRoutesDir = join(here, "..", "..", "..", "clearance-api", "src", "routes");
const configRoutesSource = join(
	here,
	"..",
	"..",
	"..",
	"clearance-api",
	"src",
	"routes",
	"config.ts",
);
const usersRoutesSource = join(apiRoutesDir, "users.ts");
const organizationRoutesSource = join(apiRoutesDir, "organizations.ts");
const accessRoutesSource = join(apiRoutesDir, "access.ts");

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
});

describe("API/CLI canonical management parity", () => {
	it("keeps CLI transport-only and user creation runtime-first in the application layer", () => {
		const cli = readFileSync(cliSource, "utf8");
		expect(cli).toMatch(/dispatchRemoteCommand/);
		expect(cli).toMatch(/\.action\(remoteCommandAction\)/);
		expect(cli).not.toMatch(/createUserInAuth|createUser\(|openStore|DATABASE_URL/);

		const application = readFileSync(usersApplicationSource, "utf8");
		const applicationFactory = readFileSync(applicationFactorySource, "utf8");
		const authRuntimeAdapter = readFileSync(authRuntimeAdapterSource, "utf8");
		expect(applicationFactory).toMatch(/store\.backend/);
		expect(applicationFactory).toMatch(/AuthRuntimeGateway/);
		expect(application).not.toMatch(/auth-bridge|\w+InAuth/);
		expect(authRuntimeAdapter).toMatch(/createUserInAuth/);
		expect(authRuntimeAdapter).toMatch(/createUserWithPasswordSetupInAuth/);
		expect(authRuntimeAdapter).toMatch(/updateUserInAuth/);
		expect(authRuntimeAdapter).toMatch(/disableUserInAuth/);
		expect(authRuntimeAdapter).toMatch(/deleteUserInAuth/);
		expect(application).toMatch(/withManagementUnitOfWork/);
		expect(application).not.toMatch(/store\.ready\(\)/);

		const api = readFileSync(apiSource, "utf8");
		const remoteDispatch = readFileSync(remoteDispatchSource, "utf8");
		const apiRoutes = [api, ...readdirSync(apiRoutesDir)
			.filter((file) => file.endsWith(".ts"))
			.map((file) => readFileSync(join(apiRoutesDir, file), "utf8"))]
			.join("\n");
		const remoteDispatchers = [remoteDispatch, ...readdirSync(dispatchDir)
			.filter((file) => file.endsWith(".ts"))
			.map((file) => readFileSync(join(dispatchDir, file), "utf8"))]
			.join("\n");
		const organizationDispatch = readFileSync(organizationDispatchSource, "utf8");
		const accessDispatch = readFileSync(accessDispatchSource, "utf8");
		const configRoutes = readFileSync(configRoutesSource, "utf8");
		const usersRoutes = readFileSync(usersRoutesSource, "utf8");
		expect(usersRoutes).not.toMatch(/DATABASE_URL|runtimeDatabaseConfigured|\w+InAuth|auth-bridge/);
		expect(usersRoutes).toMatch(/applicationFor\(store\)\.users\.update/);
		expect(usersRoutes).toMatch(/applicationFor\(store\)\.users\.disable/);
		expect(usersRoutes).toMatch(/applicationFor\(store\)\.users\.delete/);
		const createRoute = usersRoutes.slice(
			usersRoutes.indexOf("routes.post(USER_OPERATIONS.create.http.path"),
			usersRoutes.indexOf("routes.patch(USER_OPERATIONS.update.http.path"),
		);
		expect(createRoute).toMatch(/applicationFor\(store\)\.users\.create/);
		expect(createRoute).not.toMatch(/DATABASE_URL|createUserInAuth|createUser\(|store\.ready/);
		expect(api).toMatch(/app\.route\([\s\S]{0,100}registerPlatformRoutes/);
		expect(api).toMatch(/app\.route\([\s\S]{0,100}registerUserRoutes/);
		expect(api).toMatch(/app\.route\([\s\S]{0,100}registerOrganizationRoutes/);
		expect(api).toMatch(/app\.route\([\s\S]{0,100}registerEventRoutes/);
		expect(api).toMatch(/app\.route\([\s\S]{0,100}registerAccessRoutes/);
		expect(api).toMatch(/app\.route\([\s\S]{0,100}registerEnterpriseRoutes/);
		expect(api).toMatch(/app\.route\([\s\S]{0,100}registerOperationRoutes/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.get\(ORGANIZATION_OPERATIONS\.list\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(MEMBER_OPERATIONS\.import\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.get\(PROJECT_OPERATIONS\.inspect\.http\.currentPath/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(ENVIRONMENT_OPERATIONS\.promote\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(EVENT_OPERATIONS\.export\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(API_KEY_OPERATIONS\.rotate\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.get\(SESSION_OPERATIONS\.list\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.patch\(ROLE_OPERATIONS\.update\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(SSO_OPERATIONS\.test\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(SCIM_OPERATIONS\.replay\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.get\(READINESS_OPERATIONS\.report\.http\.path/);
		expect(api).toMatch(/app\.route\("\/", registerConfigRoutes/);
		expect(configRoutes).toMatch(/\.patch\(CONFIG_OPERATIONS\.set\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(IMPORT_OPERATIONS\.legacy\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(MIGRATION_OPERATIONS\.rollback\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(BACKUP_OPERATIONS\.restore\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(UPGRADE_OPERATIONS\.apply\.http\.path/);
		expect(apiRoutes).toMatch(/(?:app|routes)?\.post\(SCHEMA_OPERATIONS\.migrate\.http\.path/);
		expect(remoteDispatch).toMatch(/dispatchOrganizationCommand/);
		expect(organizationDispatch).toMatch(/case ORGANIZATION_OPERATIONS\.archive\.cliPath/);
		expect(organizationDispatch).toMatch(/case MEMBER_OPERATIONS\.remove\.cliPath/);
		expect(organizationDispatch).toMatch(/resolveOperationPath/);
		expect(remoteDispatchers).toMatch(/case SYSTEM_OPERATIONS\.doctor\.cliPath/);
		expect(remoteDispatchers).toMatch(/case PROJECT_OPERATIONS\.inspect\.cliPath/);
		expect(remoteDispatchers).toMatch(/case EVENT_OPERATIONS\.tail\.cliPath/);
		expect(remoteDispatchers).toMatch(/case API_KEY_OPERATIONS\.revoke\.cliPath/);
		expect(remoteDispatchers).toMatch(/case SESSION_OPERATIONS\.revoke\.cliPath/);
		expect(remoteDispatchers).toMatch(/case ROLE_OPERATIONS\.validate\.cliPath/);
		expect(remoteDispatchers).toMatch(/case SSO_OPERATIONS\.setupLink\.cliPath/);
		expect(remoteDispatchers).toMatch(/case SCIM_OPERATIONS\.replay\.cliPath/);
		expect(remoteDispatchers).toMatch(/case READINESS_OPERATIONS\.check\.cliPath/);
		expect(remoteDispatchers).toMatch(/case CONFIG_OPERATIONS\.diff\.cliPath/);
		expect(remoteDispatchers).toMatch(/case IMPORT_OPERATIONS\.legacy\.cliPath/);
		expect(remoteDispatchers).toMatch(/case MIGRATION_OPERATIONS\.verify\.cliPath/);
		expect(remoteDispatchers).toMatch(/case BACKUP_OPERATIONS\.create\.cliPath/);
		expect(remoteDispatchers).toMatch(/case UPGRADE_OPERATIONS\.rollback\.cliPath/);
		expect(remoteDispatchers).toMatch(/case SCHEMA_OPERATIONS\.generate\.cliPath/);
		expect(remoteDispatch).toMatch(/new Set<string>\(\s*MANAGEMENT_OPERATIONS\.map/);
		const sessionListDispatch = accessDispatch.slice(
			accessDispatch.indexOf("case SESSION_OPERATIONS.list.cliPath"),
			accessDispatch.indexOf("case SESSION_OPERATIONS.revoke.cliPath"),
		);
		expect(sessionListDispatch).not.toMatch(/userId|status/);
		expect(remoteDispatchers).not.toMatch(/return \{ validation \}/);
		expect(remoteDispatchers).toMatch(/dryRun: global\.dryRun \|\| !opts\.apply/);
	});

	it("authenticated resource routes delegate runtime policy to the application gateway", () => {
		const api = readFileSync(apiSource, "utf8");
		const organizations = readFileSync(organizationRoutesSource, "utf8");
		const access = readFileSync(accessRoutesSource, "utf8");
		const adapter = readFileSync(authRuntimeAdapterSource, "utf8");

		expect(organizations).not.toMatch(
			/auth-bridge|\w+InAuth|ensureAuthMigrated|runtimeDatabaseConfigured/,
		);
		expect(access).not.toMatch(
			/auth-bridge|\w+InAuth|ensureAuthMigrated|runtimeDatabaseConfigured/,
		);
		expect(organizations).toMatch(/applicationFor\(store\)\.organizations\.create/);
		expect(organizations).toMatch(/applicationFor\(store\)\.organizations\.update/);
		expect(organizations).toMatch(/applicationFor\(store\)\.organizations\.archive/);
		expect(organizations).toMatch(/applicationFor\(store\)\.members\.add/);
		expect(organizations).toMatch(/applicationFor\(store\)\.members\.update/);
		expect(organizations).toMatch(/applicationFor\(store\)\.members\.remove/);
		expect(access).toMatch(/applicationFor\(store\)\.sessions\.list/);
		expect(access).toMatch(/applicationFor\(store\)\.sessions\.inspect/);
		expect(access).toMatch(/applicationFor\(store\)\.sessions\.revoke/);

		for (const operation of [
			"listSessionsPageInAuth",
			"inspectSessionInAuth",
			"revokeSessionInAuth",
			"createOrgInAuth",
			"updateOrganizationInAuth",
			"archiveOrganizationInAuth",
			"addMemberInAuth",
			"updateMemberInAuth",
			"removeMemberInAuth",
		]) {
			expect(adapter).toContain(operation);
		}
		expect(api).toMatch(/createAuthBridgeRuntimeGateway\(\{ store \}\)/);
		expect(api).toMatch(/registerOrganizationRoutes\([\s\S]*?applicationFor/);
		expect(api).toMatch(/registerAccessRoutes\([\s\S]*?applicationFor/);
	});

	it("same store yields identical user/org IDs for CLI-style and API-style calls", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-parity-"));
		dirs.push(dir);
		const store = new JsonStore(join(dir, "data.json"));
		initProject(store, { name: "Parity App" });

		// CLI-style (source: cli)
		const cliUser = createUser(store, {
			email: "cli@parity.test",
			name: "CLI User",
			source: "cli",
		});
		const cliOrg = createOrganization(store, {
			name: "CLI Org",
			source: "cli",
		});

		// API-style (source: api) — same functions, same ID namespace
		const apiUser = createUser(store, {
			email: "api@parity.test",
			name: "API User",
			source: "api",
		});
		const apiOrg = createOrganization(store, {
			name: "API Org",
			source: "api",
		});

		expect(cliUser.id).toMatch(/^user_/);
		expect(apiUser.id).toMatch(/^user_/);
		expect(cliOrg.id).toMatch(/^org_/);
		expect(apiOrg.id).toMatch(/^org_/);

		// List is shared — both surfaces see the same principal/org rows
		const users = listUsers(store);
		const orgs = listOrganizations(store);
		expect(users.find((u) => u.id === cliUser.id)?.email).toBe("cli@parity.test");
		expect(users.find((u) => u.id === apiUser.id)?.email).toBe("api@parity.test");
		expect(orgs.find((o) => o.id === cliOrg.id)?.name).toBe("CLI Org");
		expect(orgs.find((o) => o.id === apiOrg.id)?.name).toBe("API Org");

		// Management IDs are not Clearance-style bare UUIDs without prefix
		// (auth runtime uses different id shapes via createUserInAuth)
		expect(cliUser.id.startsWith("user_")).toBe(true);
		expect(apiUser.id.startsWith("user_")).toBe(true);
	});
});
