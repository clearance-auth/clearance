import { describe, expect, it } from "vitest";
import { Command } from "commander";
import { MIGRATION_OPERATIONS } from "@clearance/management";
import {
	COMMAND_SPEC_VERSION,
	buildCommandSpecDocument,
	collectCommanderLeaves,
	compareCommanderParity,
	type SupplementalCommandSpec,
} from "./command-spec.js";

function migrationProgram(applyName = "run"): Command {
	const program = new Command("clearance");
	const migration = program.command("migration").description("Tenant migration");
	migration.command("plan").description("Prepare a migration plan");
	migration.command(applyName).description("Apply a migration plan");
	migration.command("verify");
	migration.command("rollback");
	migration.command("status");
	return program;
}

describe("command spec registry", () => {
	it("projects canonical safety semantics and Commander descriptions", () => {
		const document = buildCommandSpecDocument({
			program: migrationProgram("apply"),
			operations: Object.values(MIGRATION_OPERATIONS),
		});
		const apply = document.commands.find((command) => command.path === "migration apply");

		expect(document.specVersion).toBe(COMMAND_SPEC_VERSION);
		expect(document.globalOptions).toEqual([]);
		expect(apply).toMatchObject({
			specVersion: COMMAND_SPEC_VERSION,
			path: "migration apply",
			description: "Apply a migration plan",
			executionClass: "management-api",
			operationId: "migrations.apply",
			mutation: true,
			confirmation: "none",
			supportsDryRun: true,
		});
		expect(apply?.agentNotes).toContain(
			"Use --dry-run to preview the mutation when appropriate.",
		);
	});

	it("makes the registered migration run versus canonical apply drift explicit", () => {
		const report = compareCommanderParity(migrationProgram(), {
			operations: Object.values(MIGRATION_OPERATIONS),
		});

		expect(report.matches).toBe(false);
		expect(report.missingCanonicalPaths).toEqual(["migration apply"]);
		expect(report.unexpectedRegisteredPaths).toEqual(["migration run"]);
		expect(report.pathDrifts).toEqual([{
			parentPath: "migration",
			canonicalPath: "migration apply",
			registeredPath: "migration run",
		}]);
	});

	it("accounts for explicitly described local and authentication commands", () => {
		const program = new Command("clearance");
		program.command("login").description("Authenticate this machine");
		program.command("commands").description("Discover commands");
		const supplementalCommands: readonly SupplementalCommandSpec[] = [
			{
				path: "login",
				executionClass: "authentication",
				mutation: true,
				confirmation: "none",
				supportsDryRun: false,
				agentNotes: ["Writes a credential to the local operator profile."],
			},
			{
				path: "commands",
				executionClass: "discovery",
				mutation: false,
				confirmation: "none",
				supportsDryRun: false,
			},
		];

		const document = buildCommandSpecDocument({
			program,
			operations: [],
			supplementalCommands,
		});
		const report = compareCommanderParity(program, {
			operations: [],
			supplementalCommands,
		});

		expect(document.commands).toEqual([
			expect.objectContaining({
				path: "commands",
				description: "Discover commands",
				executionClass: "discovery",
			}),
			expect.objectContaining({
				path: "login",
				description: "Authenticate this machine",
				executionClass: "authentication",
				agentNotes: ["Writes a credential to the local operator profile."],
			}),
		]);
		expect(report.matches).toBe(true);
	});

	it("collects only leaf paths and excludes the program name", () => {
		expect(collectCommanderLeaves(migrationProgram("apply")).map((leaf) => leaf.path))
			.toEqual([
				"migration apply",
				"migration plan",
				"migration rollback",
				"migration status",
				"migration verify",
			]);
	});
});
