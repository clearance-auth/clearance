/**
 * CLI and API use runtime-first lifecycle operations with Postgres and retain
 * the management-only fallback for JSON development stores.
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
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

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
});

describe("API/CLI canonical management parity", () => {
	it("CLI uses runtime-first create plus canonical bridge when Postgres is configured", () => {
		const src = readFileSync(cliSource, "utf8");
		expect(src).toMatch(/createUserInAuth/);
		expect(src).not.toMatch(/listUsersFromDb/);
		expect(src).toMatch(/createOrgInAuth/);
		expect(src).toMatch(/syncRuntimeOrganizationToManagementDurable/);
		expect(src).not.toMatch(/listOrgsFromDb/);
		// Lifecycle mutations also prefer runtime-coordinated paths with DATABASE_URL.
		expect(src).toMatch(/updateUserInAuth/);
		expect(src).toMatch(/disableUserInAuth/);
		expect(src).toMatch(/deleteUserInAuth/);
		// Sessions: runtime-first when DATABASE_URL, snapshot fallback otherwise.
		// (P2.3.1 moved listing to the cursor-paginated variants; the
		// runtime-vs-snapshot branch invariant is unchanged.)
		expect(src).toMatch(/listSessionsPageInAuth/);
		expect(src).toMatch(/revokeSessionInAuth/);
		expect(src).toMatch(/listSessionsPage\(/);
		expect(src).toMatch(/revokeSession\(/);
		// Membership: runtime-coordinated when DATABASE_URL, management-only otherwise.
		expect(src).toMatch(/addMemberInAuth/);
		expect(src).toMatch(/updateMemberInAuth/);
		expect(src).toMatch(/removeMemberInAuth/);
		expect(src).toMatch(/addMember\(/);
		expect(src).toMatch(/updateMember\(/);
		expect(src).toMatch(/removeMember\(/);
		// Organization update/archive: coordinated when DATABASE_URL.
		expect(src).toMatch(/updateOrganizationInAuth/);
		expect(src).toMatch(/archiveOrganizationInAuth/);
		// JSON development fallback remains supported.
		expect(src).toMatch(/createUser\(/);
		expect(src).toMatch(/listUsers\(/);
		expect(src).toMatch(/createOrganization\(/);
		expect(src).toMatch(/listOrganizations\(/);
		expect(src).toMatch(/updateUser\(/);
		expect(src).toMatch(/disableUser\(/);
		expect(src).toMatch(/deleteUser\(/);
		// Enterprise connection ops share canonical management services.
		expect(src).toMatch(/rotateSsoCredential/);
		expect(src).toMatch(/disableSsoConnection/);
		expect(src).toMatch(/disableSsoConnectionReal/);
		expect(src).toMatch(/rotateScimCredential/);
		expect(src).toMatch(/disableScimConnection/);
		expect(src).toMatch(/disableScimConnectionReal/);
		expect(src).toMatch(/replayDiagnosticTrace/);
		// env inspect/promote, orgs update/archive, users export share management services
		expect(src).toMatch(/inspectEnvironment/);
		expect(src).toMatch(/promoteEnvironment/);
		expect(src).toMatch(/listEnvironments/);
		expect(src).toMatch(/updateOrganization/);
		expect(src).toMatch(/archiveOrganization/);
		expect(src).toMatch(/exportUsers/);
	});

	it("API wires coordinated org update/archive when DATABASE_URL is set", () => {
		const apiSource = join(
			here,
			"..",
			"..",
			"..",
			"clearance-api",
			"src",
			"server.ts",
		);
		const src = readFileSync(apiSource, "utf8");
		expect(src).toMatch(/updateOrganizationInAuth/);
		expect(src).toMatch(/archiveOrganizationInAuth/);
		// Fallbacks for JsonStore offline path remain.
		expect(src).toMatch(/updateOrganization\(/);
		expect(src).toMatch(/archiveOrganization\(/);
		// Branch on DATABASE_URL for org lifecycle (not management-only only).
		expect(src).toMatch(
			/process\.env\.DATABASE_URL[\s\S]*?updateOrganizationInAuth/,
		);
		expect(src).toMatch(
			/process\.env\.DATABASE_URL[\s\S]*?archiveOrganizationInAuth/,
		);
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
