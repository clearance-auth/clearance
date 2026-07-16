/**
 * Runtime schema lifecycle for the real Clearance/Kysely Postgres bundle.
 * JSON management storage remains independent and never implies runtime schema work.
 */
import { createHash, randomUUID } from "node:crypto";
import { existsSync, linkSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { getAuthBundle } from "../auth-bridge.js";
import { ClearanceError } from "./errors.js";

export type RuntimeSchemaPlanResult = {
	pendingTables: number;
	pendingFields: number;
	pendingSecurityMigrations: readonly string[];
	sql: string;
};

type RuntimeSchemaMetadata = Omit<RuntimeSchemaPlanResult, "sql">;

function runtimeError(
	stage: string,
	code: string,
	message: string,
	remediation: string,
): ClearanceError {
	return new ClearanceError({
		code,
		message,
		stage,
		status: 503,
		remediation,
	});
}

function requireRuntime(stage: string) {
	if (!process.env.DATABASE_URL) {
		throw new ClearanceError({
			code: "RUNTIME_DATABASE_URL_REQUIRED",
			message: "DATABASE_URL is required for the runtime schema lifecycle.",
			stage,
			remediation: "Set DATABASE_URL and the Clearance runtime configuration, then retry.",
		});
	}
	try {
		return getAuthBundle();
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw runtimeError(stage, "RUNTIME_CONFIG_INVALID", "Runtime configuration is invalid.", "Set valid CLEARANCE_SECRET and runtime configuration, then retry.");
	}
}

/** Canonical Clearance migration plan used by status, generate, and migrate. */
async function inspectRuntimeSchema(stage: string): Promise<RuntimeSchemaMetadata> {
	const plan = await requireRuntime(stage).planMigrations();
	return {
		pendingTables: plan.pendingTables,
		pendingFields: plan.pendingFields,
		pendingSecurityMigrations: plan.pendingSecurityMigrations,
	};
}

export async function planRuntimeSchema(stage = "schema.plan"): Promise<RuntimeSchemaPlanResult> {
	try {
		const plan = await requireRuntime(stage).planMigrations();
		return {
			pendingTables: plan.pendingTables,
			pendingFields: plan.pendingFields,
			pendingSecurityMigrations: plan.pendingSecurityMigrations,
			sql: await plan.compileSql(),
		};
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw runtimeError(stage, "RUNTIME_SCHEMA_PLAN_FAILED", "Runtime schema planning failed.", "Verify DATABASE_URL is reachable and runtime configuration is valid, then retry.");
	}
}

export async function getRuntimeSchemaStatus(): Promise<
	| { configured: false; state: "unconfigured"; pendingTables: 0; pendingFields: 0; pendingSecurityMigrations: readonly [] }
	| ({ configured: true; state: "configured" | "migration-required" } & RuntimeSchemaMetadata)
> {
	if (!process.env.DATABASE_URL) {
		return { configured: false, state: "unconfigured", pendingTables: 0, pendingFields: 0, pendingSecurityMigrations: [] };
	}
	try {
		const metadata = await inspectRuntimeSchema("schema.status");
		return {
			configured: true,
			state:
				metadata.pendingTables > 0 ||
				metadata.pendingFields > 0 ||
				metadata.pendingSecurityMigrations.length > 0
					? "migration-required"
					: "configured",
			...metadata,
		};
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw runtimeError("schema.status", "RUNTIME_SCHEMA_PLAN_FAILED", "Runtime schema status inspection failed.", "Verify DATABASE_URL is reachable and runtime configuration is valid, then retry.");
	}
}

function artifactId(outputPath: string): string {
	return `schema-${createHash("sha256").update(resolve(outputPath)).digest("hex").slice(0, 16)}`;
}

function writeSchemaArtifact(outputPath: string, sql: string, force: boolean): string {
	const path = resolve(outputPath);
	const id = artifactId(path);
	if (existsSync(path) && !force) {
		throw new ClearanceError({
			code: "SCHEMA_GENERATE_EXISTS",
			message: "Schema output already exists.",
			stage: "schema.generate",
			status: 409,
			remediation: "Choose a new --output path or pass --force to overwrite.",
		});
	}
	try {
		mkdirSync(dirname(path), { recursive: true });
		const tmp = `${path}.${randomUUID()}.tmp`;
		try {
			writeFileSync(tmp, sql, { encoding: "utf8", flag: "wx", mode: 0o600 });
			if (force) renameSync(tmp, path);
			else {
				linkSync(tmp, path);
				unlinkSync(tmp);
			}
		} catch (error) {
			if (existsSync(tmp)) unlinkSync(tmp);
			if ((error as NodeJS.ErrnoException)?.code === "EEXIST") {
				throw new ClearanceError({
					code: "SCHEMA_GENERATE_EXISTS",
					message: "Schema output already exists.",
					stage: "schema.generate",
					status: 409,
					remediation: "Choose a new --output path or pass --force to overwrite.",
				});
			}
			throw error;
		}
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw new ClearanceError({
			code: "SCHEMA_GENERATE_WRITE_FAILED",
			message: "Could not write schema output artifact.",
			stage: "schema.generate",
			status: 500,
			remediation: "Check output directory permissions and free disk space, then retry.",
		});
	}
	return id;
}

export async function generateRuntimeSchema(input: { outputPath: string; force: boolean; dryRun: boolean }) {
	const { sql, ...metadata } = await planRuntimeSchema("schema.generate");
	const outputId = artifactId(input.outputPath);
	if (!input.dryRun) writeSchemaArtifact(input.outputPath, sql, input.force);
	return { kind: "schema.generate", dryRun: input.dryRun, ...metadata, outputId };
}

export async function migrateRuntimeSchema(input: { dryRun: boolean }) {
	if (input.dryRun) {
		const plan = await inspectRuntimeSchema("schema.migrate");
		return { kind: "schema.migrate", dryRun: true, ...plan };
	}
	try {
		const result = await requireRuntime("schema.migrate").migrate();
		return { kind: "schema.migrate", dryRun: false, ...result };
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw runtimeError("schema.migrate", "RUNTIME_SCHEMA_MIGRATE_FAILED", "Runtime schema migration failed.", "Verify database permissions and runtime configuration, then retry.");
	}
}

export async function getCredentialAuthorityStatus() {
	try {
		return await requireRuntime("schema.credential-authority.status")
			.credentialAuthority.status();
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw runtimeError(
			"schema.credential-authority.status",
			"CREDENTIAL_AUTHORITY_STATUS_FAILED",
			"Credential authority status inspection failed.",
			"Verify DATABASE_URL and the credential-authority fence schema, then retry.",
		);
	}
}

export async function armCredentialAuthority(input: {
	deploymentId: string;
	expectedRuntimeCount: number;
}) {
	try {
		return await requireRuntime("schema.credential-authority.arm")
			.credentialAuthority.arm(input);
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw runtimeError(
			"schema.credential-authority.arm",
			"CREDENTIAL_AUTHORITY_ARM_FAILED",
			"Credential authority arm failed.",
			error instanceof Error
				? error.message
				: "Verify the bridge deployment and active runtime lease count, then retry.",
		);
	}
}

export async function drainCredentialAuthority(input: {
	deploymentId: string;
	drainId: string;
}) {
	try {
		return await requireRuntime("schema.credential-authority.drain")
			.credentialAuthority.beginDrain(input);
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw runtimeError(
			"schema.credential-authority.drain",
			"CREDENTIAL_AUTHORITY_DRAIN_FAILED",
			"Credential authority drain failed.",
			error instanceof Error
				? error.message
				: "Verify the armed bridge deployment and drain identity, then retry.",
		);
	}
}

export async function migrateRuntimeSchemaLocally(input: {
	dryRun: boolean;
	drainId?: string;
}) {
	if (input.dryRun) return migrateRuntimeSchema({ dryRun: true });
	try {
		const result = await requireRuntime("schema.migrate.local").migrate({
			drainId: input.drainId,
		});
		return { kind: "schema.migrate.local", dryRun: false, ...result };
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw runtimeError(
			"schema.migrate.local",
			"RUNTIME_SCHEMA_LOCAL_MIGRATE_FAILED",
			"Local runtime schema migration failed.",
			error instanceof Error
				? error.message
				: "Verify DATABASE_URL, the drain id, and migration permissions, then retry.",
		);
	}
}
