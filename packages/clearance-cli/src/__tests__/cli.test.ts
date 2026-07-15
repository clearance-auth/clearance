import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { authenticatedApiEnv, stopAuthenticatedApiServers } from "./api-test-server.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const entry = join(root, "dist", "index.js");
const dirs: string[] = [];

function run(args: string[], dataPath: string): { stdout: string; status: number } {
	try {
		const stdout = execFileSync(process.execPath, [entry, ...args, "--json", "--no-input"], {
			encoding: "utf8",
			env: {
				...process.env,
				// Force JSON backend for CLI unit tests (no Postgres dual-path)
				DATABASE_URL: "",
				...authenticatedApiEnv(dataPath),
				CLEARANCE_SECRET: "unit-test-secret-value-not-default!!",
				CLEARANCE_BASE_URL: "http://localhost:3000",
				CLEARANCE_CREDENTIAL_KEY: "unit-test-credential-key-material-32b!!",
				CLEARANCE_CREDENTIAL_KEY_ID: "k1",
				NODE_ENV: "development",
			},
		});
		return { stdout, status: 0 };
	} catch (err: unknown) {
		const e = err as { stdout?: string; status?: number };
		return { stdout: e.stdout ?? "", status: e.status ?? 1 };
	}
}

afterEach(() => {
	stopAuthenticatedApiServers();
	for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("clearance CLI binary", () => {
	it("refuses to send a saved profile token to an overridden origin", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-whoami-origin-"));
		dirs.push(dir);
		const config = join(dir, "config");
		mkdirSync(config, { mode: 0o700 });
		chmodSync(config, 0o700);
		const credential = join(config, "operator-credentials.production.json");
		writeFileSync(credential, JSON.stringify({
			version: 1,
			apiUrl: "https://production.clearance.test",
			token: "saved-production-operator-token-12345",
		}), { mode: 0o600 });
		chmodSync(credential, 0o600);

		let stdout = "";
		let status = 0;
		try {
			execFileSync(process.execPath, [
				entry,
				"whoami",
				"--url",
				"https://attacker.clearance.test",
				"--profile",
				"production",
				"--json",
				"--no-input",
			], {
				encoding: "utf8",
				env: {
					...process.env,
					CLEARANCE_CLI_CONFIG_DIR: config,
					CLEARANCE_OPERATOR_TOKEN: "",
					CLEARANCE_API_TOKEN: "",
					CLEARANCE_API_URL: "",
				},
			});
		} catch (error: unknown) {
			const failure = error as { stdout?: string; status?: number };
			stdout = failure.stdout ?? "";
			status = failure.status ?? 1;
		}

		expect(status).toBe(1);
		expect(JSON.parse(stdout).error.code).toBe("CLI_CREDENTIAL_ORIGIN_MISMATCH");
	});

	it("manages API keys without persisting or re-listing raw secrets", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-keys-cli-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		run(["init", "--name", "Keys CLI"], data);

		const dry = run(["keys", "create", "--name", "CI", "--scope", "Users:Read", "--dry-run"], data);
		expect(dry.status).toBe(0);
		expect(JSON.parse(dry.stdout)).toMatchObject({ dryRun: true, secretGenerated: false, apiKey: { scopes: ["users:read"] } });

		const created = run(["keys", "create", "--name", "CI", "--scope", "users:read", "--scope", "deploy:write"], data);
		expect(created.status).toBe(0);
		const createdJson = JSON.parse(created.stdout);
		expect(createdJson.secret).toMatch(/^clr_/);
		expect(JSON.stringify(createdJson.apiKey)).not.toContain(createdJson.secret);
		const persisted = readFileSync(data, "utf8");
		expect(persisted).not.toContain(createdJson.secret);
		expect(persisted).toContain("digest");

		const listed = JSON.parse(run(["keys", "list"], data).stdout);
		expect(JSON.stringify(listed)).not.toContain(createdJson.secret);
		expect(JSON.stringify(listed)).not.toContain("digest");
		const missingConfirmation = run(["keys", "revoke", createdJson.apiKey.id], data);
		expect(missingConfirmation.status).toBe(1);
		expect(JSON.parse(missingConfirmation.stdout).error.code).toBe("API_KEY_CONFIRMATION_REQUIRED");

		const rotated = run(["keys", "rotate", createdJson.apiKey.id, "--yes"], data);
		expect(rotated.status).toBe(0);
		const rotatedJson = JSON.parse(rotated.stdout);
		expect(rotatedJson.secret).toMatch(/^clr_/);
		expect(rotatedJson.secret).not.toBe(createdJson.secret);
		const revoked = run(["keys", "revoke", rotatedJson.apiKey.id, "--yes"], data);
		expect(revoked.status).toBe(0);
		const revokedAgain = JSON.parse(run(["keys", "revoke", rotatedJson.apiKey.id, "--yes"], data).stdout);
		expect(revokedAgain.idempotent).toBe(true);
	});

	it("reports JSON management schema separately from an unconfigured runtime", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-schema-status-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		const status = run(["schema", "status"], data);
		expect(status.status).toBe(0);
		expect(JSON.parse(status.stdout)).toMatchObject({
			management: { schemaVersion: 1 },
			runtime: { configured: false, state: "unconfigured", pendingTables: 0, pendingFields: 0 },
		});
	});

	it("gates schema generation output and non-interactive apply before runtime access", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-schema-gates-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		const missingOutput = run(["schema", "generate"], data);
		expect(missingOutput.status).toBe(1);
		expect(JSON.parse(missingOutput.stdout).error.code).toBe("SCHEMA_GENERATE_OUTPUT_REQUIRED");

		const applyWithoutYes = run(["schema", "migrate"], data);
		expect(applyWithoutYes.status).toBe(1);
		expect(JSON.parse(applyWithoutYes.stdout).error.code).toBe("SCHEMA_MIGRATE_CONFIRMATION_REQUIRED");
	});

	it("creates distinct durable projects and keeps environment scope explicit", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-project-contract-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		const initial = JSON.parse(run(["init", "--name", "Primary"], data).stdout);

		const created = run(["project", "create", "--name", "Second Project"], data);
		expect(created.status).toBe(0);
		const second = JSON.parse(created.stdout).project;
		expect(second.id).not.toBe(initial.project.id);

		const persisted = JSON.parse(readFileSync(data, "utf8"));
		expect(persisted.projects.map((project: { id: string }) => project.id)).toEqual([
			initial.project.id,
			second.id,
		]);
		expect(persisted.meta.config).toMatchObject({
			projectId: initial.project.id,
			environmentId: initial.environment.id,
		});

		const inspectCurrent = run(["project", "inspect"], data);
		expect(inspectCurrent.status).toBe(0);
		expect(JSON.parse(inspectCurrent.stdout).project.id).toBe(initial.project.id);
		const inspectOutsideCredentialScope = run(["project", "inspect", second.id], data);
		expect(inspectOutsideCredentialScope.status).toBe(1);
		expect(JSON.parse(inspectOutsideCredentialScope.stdout).error.code).toBe("PROJECT_NOT_FOUND");
		const missing = run(["project", "inspect", "proj_missing"], data);
		expect(missing.status).toBe(1);
		expect(JSON.parse(missing.stdout).error).toMatchObject({
			code: "PROJECT_NOT_FOUND",
			stage: "project.inspect",
		});

		const dryProject = run(["project", "create", "--name", "Dry Project", "--dry-run"], data);
		expect(dryProject.status).toBe(0);
		expect(JSON.parse(dryProject.stdout)).toMatchObject({ dryRun: true, project: { slug: "dry-project" } });
		expect(JSON.parse(readFileSync(data, "utf8")).projects).toHaveLength(2);

		const crossScopeEnv = run(
			["env", "create", "--name", "Second Preview", "--kind", "preview", "--project-id", second.id],
			data,
		);
		expect(crossScopeEnv.status).toBe(1);
		expect(JSON.parse(crossScopeEnv.stdout).error.code).toBe("SCOPE_MISMATCH");
		const env = run(["env", "create", "--name", "Primary Preview", "--kind", "preview"], data);
		expect(env.status).toBe(0);
		expect(JSON.parse(env.stdout).environment.projectId).toBe(initial.project.id);
		const invalidKind = run(["env", "create", "--name", "Bad", "--kind", "invalid"], data);
		expect(invalidKind.status).toBe(1);
		expect(JSON.parse(invalidKind.stdout).error.code).toBe("ENV_KIND_INVALID");
		const beforeDryEnv = JSON.parse(readFileSync(data, "utf8"));
		const dryEnv = run(["env", "create", "--name", "No Write", "--dry-run"], data);
		expect(dryEnv.status).toBe(0);
		expect(JSON.parse(dryEnv.stdout)).toMatchObject({
			dryRun: true,
			environment: { projectId: initial.project.id },
		});
		const afterDryEnv = JSON.parse(readFileSync(data, "utf8"));
		expect(afterDryEnv.environments).toHaveLength(beforeDryEnv.environments.length);
		expect(afterDryEnv.events).toHaveLength(beforeDryEnv.events.length);
	});

	it("runs init, users, orgs, events, doctor", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-"));
		dirs.push(dir);
		const data = join(dir, "data.json");

		const init = run(["init", "--name", "CLI App"], data);
		expect(init.status).toBe(0);
		const initJson = JSON.parse(init.stdout);
		expect(initJson.project.id).toMatch(/^proj_/);

		const user = run(
			["users", "create", "--email", "u@test.com", "--name", "User"],
			data,
		);
		expect(user.status).toBe(0);
		const userJson = JSON.parse(user.stdout);
		expect(userJson.user.email).toBe("u@test.com");

		const org = run(["orgs", "create", "--name", "Org"], data);
		const orgJson = JSON.parse(org.stdout);
		expect(orgJson.organization.id).toMatch(/^org_/);

		const events = run(["events", "list"], data);
		const eventsJson = JSON.parse(events.stdout);
		expect(eventsJson.events.length).toBeGreaterThan(0);

		const doctor = run(["doctor"], data);
		// doctor may exit 2 on warn (default secret hygiene in dev)
		expect([0, 2]).toContain(doctor.status);
		const doctorJson = JSON.parse(doctor.stdout);
		expect(doctorJson.checks.length).toBeGreaterThan(0);
		expect(doctorJson.checks.some((c: { id: string }) => c.id === "secret")).toBe(
			true,
		);
		expect(
			doctorJson.checks.some((c: { id: string }) => c.id === "store-backend"),
		).toBe(true);
	}, 30_000);

	it("env inspect/promote, orgs update/archive, users export contracts", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-contracts-"));
		dirs.push(dir);
		const data = join(dir, "data.json");

		const init = JSON.parse(run(["init", "--name", "Contracts"], data).stdout);
		const envId = init.environment.id;

		const inspect = run(["env", "inspect"], data);
		expect(inspect.status).toBe(0);
		const inspectJson = JSON.parse(inspect.stdout);
		expect(inspectJson.environment.id).toBe(envId);
		expect(inspectJson.local.active).toBe(true);
		expect(inspectJson.local.config.hasClearanceSecret).toBeTypeOf("boolean");
		expect(JSON.stringify(inspectJson)).not.toContain("unit-test-secret-value");

		const promoteDry = run(["env", "promote", "--to", envId, "--dry-run"], data);
		expect(promoteDry.status).toBe(0);
		const promoteJson = JSON.parse(promoteDry.stdout);
		expect(promoteJson.dryRun).toBe(true);
		expect(promoteJson.idempotent).toBe(true);

		const user = JSON.parse(
			run(
				["users", "create", "--email", "export@test.com", "--name", "Export"],
				data,
			).stdout,
		);
		expect(user.user.id).toBeTruthy();

		const out = join(dir, "users.json");
		const exp = run(
			["users", "export", "--output", out, "--format", "json", "--limit", "10"],
			data,
		);
		expect(exp.status).toBe(0);
		const expJson = JSON.parse(exp.stdout);
		expect(expJson.kind).toBe("users.export");
		expect(expJson.count).toBeGreaterThanOrEqual(1);
		expect(existsSync(out)).toBe(true);
		// No-clobber
		const clobber = run(
			["users", "export", "--output", out, "--format", "json"],
			data,
		);
		expect(clobber.status).toBe(1);

		const org = JSON.parse(run(["orgs", "create", "--name", "Live Org"], data).stdout);
		const orgId = org.organization.id;
		const updated = run(
			["orgs", "update", orgId, "--name", "Live Org Renamed", "--slug", "live-org"],
			data,
		);
		expect(updated.status).toBe(0);
		expect(JSON.parse(updated.stdout).organization.name).toBe("Live Org Renamed");

		const archiveDry = run(["orgs", "archive", orgId, "--dry-run"], data);
		expect(archiveDry.status).toBe(0);
		expect(JSON.parse(archiveDry.stdout).dryRun).toBe(true);

		const archive = run(["orgs", "archive", orgId, "--yes"], data);
		expect(archive.status).toBe(0);
		expect(JSON.parse(archive.stdout).organization.status).toBe("archived");

		const archiveAgain = run(["orgs", "archive", orgId, "--yes"], data);
		expect(archiveAgain.status).toBe(0);
		expect(JSON.parse(archiveAgain.stdout).idempotent).toBe(true);
	});

	it("manages config safely, durably, and without secret leakage", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-config-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		const initialized = JSON.parse(run(["init", "--name", "Config"], data).stdout);

		const dry = run(["config", "set", "featureFlag", "on", "--dry-run"], data);
		expect(dry.status).toBe(0);
		expect(JSON.parse(dry.stdout)).toMatchObject({ dryRun: true, changed: true });
		expect(JSON.parse(run(["config", "get", "featureFlag"], data).stdout).config).toEqual({});

		const set = run(["config", "set", "featureFlag", "on"], data);
		expect(set.status).toBe(0);
		expect(JSON.parse(set.stdout)).toMatchObject({ ok: true, changed: true, config: { featureFlag: "on" } });
		expect(JSON.parse(run(["config", "get", "featureFlag"], data).stdout).config).toEqual({ featureFlag: "on" });
		const persisted = JSON.parse(readFileSync(data, "utf8"));
		expect(persisted.meta.config.featureFlag).toBe("on");
		expect(persisted.events.find((event: { action: string }) => event.action === "config.set").metadata).toEqual({ key: "featureFlag" });
		const noOp = run(["config", "set", "featureFlag", "on"], data);
		expect(JSON.parse(noOp.stdout).changed).toBe(false);
		expect(JSON.parse(run(["config", "validate"], data).stdout)).toMatchObject({ ok: true, source: "current" });

		const candidate = join(dir, "candidate.json");
		writeFileSync(candidate, JSON.stringify({
			projectId: initialized.project.id,
			environmentId: initialized.environment.id,
			featureFlag: "off",
			telemetryEndpoint: "https://telemetry.example.test/events",
		}));
		const valid = run(["config", "validate", "--file", candidate], data);
		expect(valid.status).toBe(0);
		expect(JSON.parse(valid.stdout).ok).toBe(true);
		const diff = run(["config", "diff", "--file", candidate], data);
		expect(diff.status).toBe(0);
		expect(JSON.parse(diff.stdout)).toMatchObject({ added: ["telemetryEndpoint"], changed: ["featureFlag"], removed: [] });
		expect(diff.stdout).not.toContain("https://telemetry.example.test/events");

		const malformed = join(dir, "malformed.json");
		writeFileSync(malformed, '{"a":"one","a":"two"}');
		const badFile = run(["config", "validate", "--file", malformed], data);
		expect(badFile.status).toBe(1);
		expect(JSON.parse(badFile.stdout).error).toMatchObject({ code: "CONFIG_FILE_INVALID", stage: "config.parse" });
		const missingPath = join(dir, "contains-sensitive-name", "missing.json");
		const unreadable = run(["config", "validate", "--file", missingPath], data);
		expect(unreadable.status).toBe(1);
		expect(JSON.parse(unreadable.stdout).error).toMatchObject({
			code: "CONFIG_FILE_UNREADABLE",
			stage: "config.parse",
		});
		expect(unreadable.stdout).not.toContain(missingPath);

		const withOtherProject = JSON.parse(readFileSync(data, "utf8"));
		const otherProjectId = "proj_other_config_scope";
		withOtherProject.projects.push({
			id: otherProjectId,
			name: "Other",
			slug: "other",
			createdAt: new Date(0).toISOString(),
			updatedAt: new Date(0).toISOString(),
		});
		writeFileSync(data, JSON.stringify(withOtherProject));
		const mismatch = join(dir, "mismatch.json");
		writeFileSync(
			mismatch,
			JSON.stringify({
				projectId: otherProjectId,
				environmentId: initialized.environment.id,
			}),
		);
		const badScope = run(["config", "validate", "--file", mismatch], data);
		expect(badScope.status).toBe(1);
		expect(JSON.parse(badScope.stdout).error.code).toBe("CONFIG_SCOPE_MISMATCH");

		const submittedSecret = "sk_this-must-never-appear";
		const secret = run(["config", "set", "apiKey", submittedSecret], data);
		expect(secret.status).toBe(1);
		expect(secret.stdout).not.toContain(submittedSecret);
		expect(JSON.parse(secret.stdout).error).toMatchObject({ code: "CONFIG_SECRET_FORBIDDEN", stage: "config.secrets" });

		const legacy = JSON.parse(readFileSync(data, "utf8"));
		legacy.meta.config.legacyToken = submittedSecret;
		writeFileSync(data, JSON.stringify(legacy));
		const redacted = JSON.parse(run(["config", "get"], data).stdout);
		expect(JSON.stringify(redacted)).not.toContain(submittedSecret);
		expect(redacted.redactedKeys).toEqual(["legacyToken"]);
		expect(JSON.parse(run(["config", "get", "legacyToken"], data).stdout)).toMatchObject({ config: {}, redactedKeys: ["legacyToken"] });
	}, 15_000);

	it("enterprise readiness via CLI", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-ent-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		const initialized = run(["init", "--name", "Ent"], data);
		expect(initialized.status).toBe(0);
		const createdOrg = run(["orgs", "create", "--name", "Cust"], data);
		expect(createdOrg.status).toBe(0);
		const org = JSON.parse(createdOrg.stdout);
		const orgId = org.organization.id;
		const sso = JSON.parse(
			run(
				[
					"sso",
					"create",
					"--org",
					orgId,
					"--provider",
					"okta",
					"--protocol",
					"oidc",
					"--issuer",
					"https://okta.example/oauth2/default",
					"--audience",
					"clearance-sp",
				],
				data,
			).stdout,
		);
		const ssoTest = run(["sso", "test", sso.connection.id, "--fixture", "ok"], data);
		expect(ssoTest.status).toBe(0);
		const beforeConfigureDryRun = readFileSync(data, "utf8");
		const configureDryRun = run([
			"sso",
			"configure",
			sso.connection.id,
			"--issuer",
			"https://changed.example.test/oauth2/default",
			"--dry-run",
		], data);
		expect(configureDryRun.status).toBe(0);
		expect(JSON.parse(configureDryRun.stdout)).toMatchObject({
			dryRun: true,
			proposed: { issuer: "https://changed.example.test/oauth2/default" },
		});
		expect(readFileSync(data, "utf8")).toBe(beforeConfigureDryRun);

		const bad = run(
			["sso", "test", sso.connection.id, "--fixture", "wrong-issuer"],
			data,
		);
		expect(bad.status).toBe(1);
		const badJson = JSON.parse(bad.stdout);
		expect(badJson.error.stage).toBe("assertion.issuer");
		expect(badJson.error.remediation).toBeTruthy();

		const samlCertificate = join(
			root,
			"..",
			"..",
			"fixtures",
			"sso",
			"test-certificate.pem",
		);
		const saml = run(
			[
				"sso",
				"create",
				"--org",
				orgId,
				"--provider",
				"okta-saml",
				"--protocol",
				"saml",
				"--issuer",
				"https://customer.okta.test",
				"--entry-point",
				"https://customer.okta.test/app/clearance/sso/saml",
				"--certificate",
				samlCertificate,
			],
			data,
		);
		expect(saml.status).toBe(0);
		expect(JSON.parse(saml.stdout).connection).toMatchObject({
			protocol: "saml",
			samlEntryPoint: "https://customer.okta.test/app/clearance/sso/saml",
		});
		expect(JSON.parse(saml.stdout).connection.samlCertificateFingerprint).toMatch(
			/^[a-f0-9]{64}$/,
		);

		const scim = JSON.parse(
			run(["scim", "create", "--org", orgId, "--provider", "okta"], data).stdout,
		);
		run(["scim", "test", scim.connection.id, "--apply"], data);
		const ready = JSON.parse(
			run(["readiness", "check", "--org", orgId], data).stdout,
		);
		expect(ready.report.checks.length).toBeGreaterThan(0);
		expect(ready.report.signature).toBeTruthy();
		expect(ready.report.conformance.liveCertified).toBe(false);
		expect(ready.report.conformance.mode).toBe("simulation");
	}, 30_000);

	it("sso/scim rotate, disable, replay with --yes and --dry-run", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-ent-ops-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "EntOps"], data).status).toBe(0);
		const orgId = JSON.parse(
			run(["orgs", "create", "--name", "Cust"], data).stdout,
		).organization.id;

		// SSO without secret: rotate dry-run validates target; apply fails closed
		const sso = JSON.parse(
			run(
				[
					"sso",
					"create",
					"--org",
					orgId,
					"--provider",
					"okta",
					"--protocol",
					"oidc",
					"--issuer",
					"https://idp.example/oauth2",
				],
				data,
			).stdout,
		);
		const ssoId = sso.connection.id;

		const noConfirm = run(["sso", "disable", ssoId], data);
		expect(noConfirm.status).toBe(1);
		expect(JSON.parse(noConfirm.stdout).error.code).toBe("SSO_CONFIRM_REQUIRED");

		const dryDisable = run(["sso", "disable", ssoId, "--dry-run"], data);
		expect(dryDisable.status).toBe(0);
		const dryBody = JSON.parse(dryDisable.stdout);
		expect(dryBody.dryRun).toBe(true);
		expect(dryBody.connection.id).toBe(ssoId);
		expect(dryBody.wouldChange).toBe(true);

		const disabled = run(["sso", "disable", ssoId, "--yes"], data);
		expect(disabled.status).toBe(0);
		expect(JSON.parse(disabled.stdout).connection.status).toBe("disabled");
		expect(JSON.parse(disabled.stdout).idempotent).toBe(false);

		const again = run(["sso", "disable", ssoId, "--yes"], data);
		expect(again.status).toBe(0);
		expect(JSON.parse(again.stdout).idempotent).toBe(true);

		const missingDry = run(
			["sso", "disable", "sso_missing", "--dry-run"],
			data,
		);
		expect(missingDry.status).toBe(1);
		expect(JSON.parse(missingDry.stdout).error.code).toBe("SSO_NOT_FOUND");

		// SCIM rotate / disable / replay
		const scim = JSON.parse(
			run(["scim", "create", "--org", orgId, "--provider", "okta"], data).stdout,
		);
		const scimId = scim.connection.id;
		const tested = JSON.parse(
			run(["scim", "test", scimId], data).stdout,
		);
		const traceId = tested.trace.id;

		const scimRotateDry = run(["scim", "rotate", scimId, "--dry-run"], data);
		expect(scimRotateDry.status).toBe(0);
		expect(JSON.parse(scimRotateDry.stdout).dryRun).toBe(true);

		const scimRotate = run(["scim", "rotate", scimId, "--yes"], data);
		expect(scimRotate.status).toBe(0);
		expect(JSON.parse(scimRotate.stdout).connection.bearerTokenFingerprint).toBeTruthy();
		expect(JSON.parse(scimRotate.stdout).connection.bearerTokenEncrypted).toBeUndefined();

		const scimDisable = run(["scim", "disable", scimId, "--yes"], data);
		expect(scimDisable.status).toBe(0);
		expect(JSON.parse(scimDisable.stdout).connection.status).toBe("disabled");

		// Replay defaults to dry-run without --yes; apply with --yes
		const replayDry = run(["scim", "replay", traceId], data);
		expect(replayDry.status).toBe(0);
		expect(JSON.parse(replayDry.stdout).dryRun).toBe(true);

		const replay = run(["scim", "replay", traceId, "--yes"], data);
		expect(replay.status).toBe(0);
		expect(JSON.parse(replay.stdout).dryRun).toBe(false);
		expect(JSON.parse(replay.stdout).trace.id).not.toBe(traceId);

		const events = JSON.parse(run(["events", "list"], data).stdout);
		const actions = events.events.map((e: { action: string }) => e.action);
		expect(actions).toContain("sso.disable");
		expect(actions).toContain("scim.rotate");
		expect(actions).toContain("scim.disable");
		expect(actions).toContain("scim.replay");
	}, 30_000);

	it("users update/disable/delete with JSON, audit, and mutation safety", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-users-"));
		dirs.push(dir);
		const data = join(dir, "data.json");

		expect(run(["init", "--name", "UserOps"], data).status).toBe(0);
		const created = JSON.parse(
			run(
				["users", "create", "--email", "ops@test.com", "--name", "Ops"],
				data,
			).stdout,
		);
		const userId = created.user.id as string;
		expect(userId).toMatch(/^user_/);

		const updated = run(
			["users", "update", userId, "--name", "Ops Renamed", "--email", "ops2@test.com"],
			data,
		);
		expect(updated.status).toBe(0);
		const updatedJson = JSON.parse(updated.stdout);
		expect(updatedJson.user.name).toBe("Ops Renamed");
		expect(updatedJson.user.email).toBe("ops2@test.com");
		expect(updatedJson.user.id).toBe(userId);

		const dry = run(
			["users", "update", userId, "--name", "NoWrite", "--dry-run"],
			data,
		);
		expect(dry.status).toBe(0);
		expect(JSON.parse(dry.stdout).dryRun).toBe(true);
		const still = JSON.parse(run(["users", "inspect", userId], data).stdout);
		expect(still.user.name).toBe("Ops Renamed");

		const disabled = run(["users", "disable", userId], data);
		expect(disabled.status).toBe(0);
		expect(JSON.parse(disabled.stdout).user.status).toBe("disabled");

		const missing = run(["users", "disable", "user_does_not_exist"], data);
		expect(missing.status).toBe(1);
		const missingJson = JSON.parse(missing.stdout);
		expect(missingJson.error.code).toBe("USER_NOT_FOUND");
		expect(missingJson.error.stage).toBe("users.disable");

		const refuseDelete = run(["users", "delete", userId], data);
		expect(refuseDelete.status).toBe(1);

		const deleted = run(["users", "delete", userId, "--yes"], data);
		expect(deleted.status).toBe(0);
		expect(JSON.parse(deleted.stdout).user.status).toBe("deleted");

		const gone = run(["users", "inspect", userId], data);
		expect(gone.status).toBe(1);
		expect(JSON.parse(gone.stdout).error.code).toBe("USER_NOT_FOUND");

		const events = JSON.parse(run(["events", "list", "--limit", "20"], data).stdout);
		const actions = (events.events as Array<{ action: string }>).map((e) => e.action);
		expect(actions).toContain("users.update");
		expect(actions).toContain("users.disable");
		expect(actions).toContain("users.delete");
	});

	it("sessions list/revoke with JSON, confirmation, dry-run, and audit", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-sessions-"));
		dirs.push(dir);
		const data = join(dir, "data.json");

		const init = run(["init", "--name", "Sess CLI"], data);
		expect(init.status).toBe(0);
		const initJson = JSON.parse(init.stdout);
		const environmentId = initJson.environment.id as string;

		const userRes = run(
			["users", "create", "--email", "sess-cli@test.com", "--name", "Sess CLI"],
			data,
		);
		expect(userRes.status).toBe(0);
		const userId = JSON.parse(userRes.stdout).user.id as string;

		// CLI has no session create — seed a management snapshot session for list/revoke.
		const snap = JSON.parse(readFileSync(data, "utf8"));
		const sessionId = `sess_cli_${Date.now()}`;
		snap.sessions = snap.sessions ?? [];
		snap.sessions.push({
			id: sessionId,
			principalId: userId,
			environmentId,
			status: "active",
			createdAt: new Date().toISOString(),
		});
		writeFileSync(data, JSON.stringify(snap, null, 2));

		const listed = JSON.parse(run(["sessions", "list"], data).stdout);
		expect(listed.sessions.some((s: { id: string }) => s.id === sessionId)).toBe(
			true,
		);
		expect(JSON.stringify(listed)).not.toMatch(/"token"/);

		const refuse = run(["sessions", "revoke", sessionId], data);
		expect(refuse.status).not.toBe(0);
		expect(JSON.parse(refuse.stdout).error.code).toBe(
			"SESSION_CONFIRM_REQUIRED",
		);

		const dry = run(["sessions", "revoke", sessionId, "--dry-run"], data);
		expect(dry.status).toBe(0);
		const dryBody = JSON.parse(dry.stdout);
		expect(dryBody.dryRun).toBe(true);
		expect(dryBody.session.id).toBe(sessionId);
		expect(dryBody.wouldChange).toBe(true);

		const missingDry = run(
			["sessions", "revoke", "sess_missing", "--dry-run"],
			data,
		);
		expect(missingDry.status).not.toBe(0);
		expect(JSON.parse(missingDry.stdout).error.code).toBe("SESSION_NOT_FOUND");

		const invalidLimit = run(["sessions", "list", "--limit", "wat"], data);
		expect(invalidLimit.status).not.toBe(0);
		expect(JSON.parse(invalidLimit.stdout).error.code).toBe(
			"SESSION_LIMIT_INVALID",
		);

		const revoked = run(["sessions", "revoke", sessionId, "--yes"], data);
		expect(revoked.status).toBe(0);
		const revBody = JSON.parse(revoked.stdout);
		expect(revBody.session.status).toBe("revoked");
		expect(revBody.idempotent).toBe(false);

		const again = run(["sessions", "revoke", sessionId, "--yes"], data);
		expect(again.status).toBe(0);
		expect(JSON.parse(again.stdout).idempotent).toBe(true);

		const events = JSON.parse(run(["events", "list"], data).stdout);
		const actions = (events.events as { action: string }[]).map((e) => e.action);
		expect(actions).toContain("sessions.revoke");
	});

	it("events export: deterministic bounds, overwrite guard, redaction", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-events-export-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "Export CLI"], data).status).toBe(0);
		expect(
			run(["users", "create", "--email", "ex@test.com", "--name", "Ex"], data)
				.status,
		).toBe(0);

		const out = join(dir, "export.json");
		const exp = run(
			["events", "export", "--output", out, "--format", "json", "--limit", "10"],
			data,
		);
		expect(exp.status).toBe(0);
		const envelope = JSON.parse(exp.stdout);
		expect(envelope.kind).toBe("events.export");
		expect(envelope.count).toBeGreaterThan(0);
		expect(envelope.outputPath).toBe(out);
		expect(existsSync(out)).toBe(true);
		expect(JSON.stringify(envelope)).not.toMatch(/password|Bearer |sk_live/i);

		const refuse = run(
			["events", "export", "--output", out, "--format", "json"],
			data,
		);
		expect(refuse.status).not.toBe(0);
		expect(JSON.parse(refuse.stdout).error.code).toBe("EVENTS_EXPORT_EXISTS");

		const forced = run(
			[
				"events",
				"export",
				"--output",
				out,
				"--format",
				"json",
				"--force",
				"--limit",
				"1",
			],
			data,
		);
		expect(forced.status).toBe(0);
		expect(JSON.parse(forced.stdout).count).toBe(1);
		expect(JSON.parse(forced.stdout).truncated).toBe(true);

		const badLimit = run(
			["events", "export", "--output", join(dir, "bad.json"), "--limit", "0"],
			data,
		);
		expect(badLimit.status).not.toBe(0);
		expect(JSON.parse(badLimit.stdout).error.code).toBe(
			"EVENTS_EXPORT_LIMIT_INVALID",
		);
	});

	it("events tail: once emits JSONL, honors exact max-events, and validates bounds", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-events-tail-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "Tail CLI"], data).status).toBe(0);
		expect(
			run(["users", "create", "--email", "tail@test.com", "--name", "Tail"], data).status,
		).toBe(0);

		const bounded = run(
			["events", "tail", "--once", "--limit", "10", "--max-events", "1"],
			data,
		);
		expect(bounded.status).toBe(0);
		const lines = bounded.stdout.trim().split("\n");
		expect(lines).toHaveLength(1);
		expect(JSON.parse(lines[0]!)).toMatchObject({ id: expect.any(String) });

		const empty = run(
			["events", "tail", "--once", "--action", "does.not.exist"],
			data,
		);
		expect(empty.status).toBe(0);
		expect(empty.stdout).toBe("");

		for (const args of [
			["events", "tail", "--once", "--limit", "0"],
			["events", "tail", "--once", "--poll-interval", "99"],
			["events", "tail", "--once", "--max-events", "-1"],
		]) {
			const invalid = run(args, data);
			expect(invalid.status).toBe(1);
			expect(JSON.parse(invalid.stdout).error.code).toBe("EVENTS_TAIL_OPTION_INVALID");
		}
	});

	it("events replay: default dry-run, --yes apply, idempotent, non-replayable", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-events-replay-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "Replay CLI"], data).status).toBe(0);
		const org = JSON.parse(
			run(["orgs", "create", "--name", "Replay Org"], data).stdout,
		).organization;
		const scim = JSON.parse(
			run(
				["scim", "create", "--org", org.id, "--provider", "okta"],
				data,
			).stdout,
		).connection;
		const tested = JSON.parse(
			run(["scim", "test", scim.id, "--fixture", "ok"], data).stdout,
		);
		const traceId = tested.trace.id as string;

		const dry = run(["events", "replay", traceId], data);
		expect(dry.status).toBe(0);
		const dryBody = JSON.parse(dry.stdout);
		expect(dryBody.dryRun).toBe(true);
		expect(dryBody.wouldChange).toBe(true);

		const applied = run(["events", "replay", traceId, "--yes"], data);
		expect(applied.status).toBe(0);
		const appBody = JSON.parse(applied.stdout);
		expect(appBody.dryRun).toBe(false);
		expect(appBody.idempotent).toBe(false);

		const again = run(["events", "replay", traceId, "--yes"], data);
		expect(again.status).toBe(0);
		expect(JSON.parse(again.stdout).idempotent).toBe(true);

		const audit = JSON.parse(run(["events", "list", "--limit", "30"], data).stdout);
		const actions = (audit.events as { action: string }[]).map((e) => e.action);
		expect(actions).toContain("scim.replay");

		const nonReplay = run(["events", "replay", audit.events[0].id, "--yes"], data);
		expect(nonReplay.status).not.toBe(0);
		const err = JSON.parse(nonReplay.stdout).error.code;
		expect(["EVENT_NOT_REPLAYABLE", "TRACE_NOT_FOUND", "EVENT_NOT_FOUND"]).toContain(
			err,
		);

		const missing = run(["events", "replay", "tr_missing", "--dry-run"], data);
		expect(missing.status).not.toBe(0);
	});

	it("orgs members add/update/remove with role validation, confirmation, dry-run", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-members-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "MemberOps"], data).status).toBe(0);

		const owner = JSON.parse(
			run(
				["users", "create", "--email", "owner@m.test", "--name", "Owner"],
				data,
			).stdout,
		).user;
		const user = JSON.parse(
			run(
				["users", "create", "--email", "u@m.test", "--name", "User"],
				data,
			).stdout,
		).user;
		const org = JSON.parse(
			run(["orgs", "create", "--name", "MemOrg"], data).stdout,
		).organization;

		// Owner so final-owner invariant has a peer when needed
		const ownerAdd = run(
			[
				"orgs",
				"members",
				"add",
				"--org",
				org.id,
				"--user",
				owner.id,
				"--role",
				"owner",
			],
			data,
		);
		expect(ownerAdd.status).toBe(0);

		const dry = run(
			[
				"orgs",
				"members",
				"add",
				"--org",
				org.id,
				"--user",
				user.id,
				"--role",
				"admin",
				"--dry-run",
			],
			data,
		);
		expect(dry.status).toBe(0);
		expect(JSON.parse(dry.stdout).dryRun).toBe(true);

		const added = run(
			[
				"orgs",
				"members",
				"add",
				"--org",
				org.id,
				"--user",
				user.id,
				"--role",
				"admin",
			],
			data,
		);
		expect(added.status).toBe(0);
		const membership = JSON.parse(added.stdout).membership;
		expect(membership.role).toBe("admin");
		expect(membership.principalId).toBe(user.id);

		const badRole = run(
			[
				"orgs",
				"members",
				"add",
				"--org",
				org.id,
				"--user",
				user.id,
				"--role",
				"not-a-role",
			],
			data,
		);
		// Invalid role fails closed even when a membership already exists
		expect(badRole.status).toBe(1);
		expect(JSON.parse(badRole.stdout).error.code).toBe("ROLE_NOT_FOUND");

		const updated = run(
			[
				"orgs",
				"members",
				"update",
				"--org",
				org.id,
				"--user",
				user.id,
				"--role",
				"member",
			],
			data,
		);
		expect(updated.status).toBe(0);
		expect(JSON.parse(updated.stdout).membership.role).toBe("member");

		const refuse = run(
			["orgs", "members", "remove", "--org", org.id, "--user", user.id],
			data,
		);
		expect(refuse.status).toBe(1);

		const removed = run(
			[
				"orgs",
				"members",
				"remove",
				"--org",
				org.id,
				"--user",
				user.id,
				"--yes",
			],
			data,
		);
		expect(removed.status).toBe(0);
		expect(JSON.parse(removed.stdout).membership.status).toBe("removed");

		const invalidUpdate = run(
			[
				"orgs",
				"members",
				"update",
				"--org",
				org.id,
				"--user",
				owner.id,
				"--role",
				"ghost-role",
			],
			data,
		);
		expect(invalidUpdate.status).toBe(1);
		expect(JSON.parse(invalidUpdate.stdout).error.code).toBe("ROLE_NOT_FOUND");
	});

	it("imports JSON and CSV members with safe planning, confirmation, and persisted summaries", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-member-import-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "MemberImport"], data).status).toBe(0);
		const first = JSON.parse(run(["users", "create", "--email", "first@import.test", "--name", "First"], data).stdout).user;
		const second = JSON.parse(run(["users", "create", "--email", "second@import.test", "--name", "Second"], data).stdout).user;
		const org = JSON.parse(run(["orgs", "create", "--name", "ImportOrg"], data).stdout).organization;
		const jsonFile = join(dir, "members.json");
		writeFileSync(jsonFile, JSON.stringify({ members: [{ email: " first@import.test ", role: "admin" }, { principalId: second.id }] }));
		const eventsBeforeDryRun = JSON.parse(readFileSync(data, "utf8")).events.length;

		const dry = run(["orgs", "members", "import", "--org", org.id, "--file", jsonFile, "--dry-run"], data);
		expect(dry.status).toBe(0);
		expect(JSON.parse(dry.stdout)).toMatchObject({ dryRun: true, summary: { total: 2, wouldAdd: 2, idempotent: 0 } });
		expect(JSON.parse(readFileSync(data, "utf8")).events).toHaveLength(eventsBeforeDryRun);

		const blocked = run(["orgs", "members", "import", "--org", org.id, "--file", jsonFile], data);
		expect(blocked.status).toBe(1);
		expect(JSON.parse(blocked.stdout).error.code).toBe("MEMBER_IMPORT_CONFIRMATION_REQUIRED");

		const applied = run(["orgs", "members", "import", "--org", org.id, "--file", jsonFile, "--yes"], data);
		expect(applied.status).toBe(0);
		expect(JSON.parse(applied.stdout)).toMatchObject({ completed: true, partial: false, success: 2, failure: 0 });
		const persisted = JSON.parse(readFileSync(data, "utf8"));
		expect(persisted.memberships.map((member: { role: string }) => member.role)).toEqual(["admin", "member"]);
		const importEvents = persisted.events.filter(
			(event: { action: string }) => event.action === "orgs.members.add",
		);
		expect(importEvents).toHaveLength(2);
		expect(importEvents.every((event: { source: string; actor: string }) => event.source === "import" && event.actor === "api")).toBe(true);

		const rerun = run(["orgs", "members", "import", "--org", org.id, "--file", jsonFile, "--yes"], data);
		expect(rerun.status).toBe(0);
		expect(JSON.parse(rerun.stdout)).toMatchObject({ idempotent: 2, success: 2 });

		const csvFile = join(dir, "members.csv");
		writeFileSync(csvFile, "user,role\n" + first.id + ",admin");
		const csv = run(["orgs", "members", "import", "--org", org.id, "--file", csvFile, "--yes"], data);
		expect(csv.status).toBe(0);
		expect(JSON.parse(csv.stdout).results[0].status).toBe("idempotent");
		expect(JSON.parse(readFileSync(data, "utf8")).memberships.find((member: { principalId: string }) => member.principalId === first.id).role).toBe("admin");

		const duplicateFile = join(dir, "duplicate.json");
		writeFileSync(duplicateFile, JSON.stringify([{ principalId: first.id }, { email: "first@import.test" }]));
		const duplicate = run(["orgs", "members", "import", "--org", org.id, "--file", duplicateFile, "--dry-run"], data);
		expect(duplicate.status).toBe(1);
		expect(JSON.parse(duplicate.stdout).error.code).toBe("MEMBER_IMPORT_DUPLICATE_PRINCIPAL");

		const malformedFile = join(dir, "malformed.csv");
		writeFileSync(malformedFile, "email,unknown\nfirst@import.test,x");
		const malformed = run(["orgs", "members", "import", "--org", org.id, "--file", malformedFile, "--dry-run"], data);
		expect(malformed.status).toBe(1);
		expect(JSON.parse(malformed.stdout).error.code).toBe("MEMBER_IMPORT_CSV_HEADER_INVALID");
	});

	it("roles list/create/validate/update share the canonical role contract", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-roles-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "RoleOps"], data).status).toBe(0);

		const initial = JSON.parse(run(["roles", "list"], data).stdout);
		expect(initial.roles.map((role: { slug: string }) => role.slug)).toEqual([
			"owner",
			"admin",
			"member",
		]);

		const validation = run(
			[
				"roles",
				"validate",
				"--name",
				"Billing Analyst",
				"--permission",
				"billing:read",
				"invoice:read",
			],
			data,
		);
		expect(validation.status).toBe(0);
		expect(JSON.parse(validation.stdout)).toMatchObject({
			ok: true,
			slug: "billing-analyst",
			permissions: ["billing:read", "invoice:read"],
		});

		const created = run(
			[
				"roles",
				"create",
				"--name",
				"Billing Analyst",
				"--permission",
				"invoice:read",
				"billing:read",
			],
			data,
		);
		expect(created.status).toBe(0);
		const role = JSON.parse(created.stdout).role;
		expect(role.slug).toBe("billing-analyst");
		expect(role.permissions).toEqual(["billing:read", "invoice:read"]);

		const updated = run(
			[
				"roles",
				"update",
				role.id,
				"--name",
				"Billing Operator",
				"--permission",
				"billing:write",
			],
			data,
		);
		expect(updated.status).toBe(0);
		expect(JSON.parse(updated.stdout).role).toMatchObject({
			id: role.id,
			name: "Billing Operator",
			slug: "billing-analyst",
			permissions: ["billing:write"],
		});

		const immutable = run(
			["roles", "update", "role_builtin_admin", "--name", "Changed"],
			data,
		);
		expect(immutable.status).toBe(1);
		expect(JSON.parse(immutable.stdout).error.code).toBe("ROLE_BUILT_IN");
	});

	it("migration plan/run/verify/rollback", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-mig-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		const fixture = join(dir, "fixture.json");
		writeFileSync(
			fixture,
			JSON.stringify({
				source: "legacy",
				users: [{ id: "1", email: "m@x.com", name: "M" }],
				organizations: [{ id: "o1", name: "O" }],
				members: [{ userId: "1", organizationId: "o1" }],
			}),
		);
		run(["init", "--name", "M"], data);
		const plan = JSON.parse(
			run(
				["migration", "plan", "--source", "legacy", "--fixture", fixture],
				data,
			).stdout,
		);
		run(
			["migration", "run", "--id", plan.plan.id, "--fixture", fixture],
			data,
		);
		const verify = run(
			["migration", "verify", "--id", plan.plan.id, "--fixture", fixture],
			data,
		);
		expect(verify.status).toBe(0);
		const rb = run(
			[
				"migration",
				"rollback",
				"--id",
				plan.plan.id,
				"--fixture",
				fixture,
				"--yes",
			],
			data,
		);
		expect(rb.status).toBe(0);
	});

	it("imports Clearance through preview, confirmation, verification, and idempotent rerun", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-clearance-cli-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		const fixture = join(dir, "clearance.json");
		writeFileSync(fixture, JSON.stringify({
			source: "legacy",
			users: [{ id: "ba_user_1", email: "better@example.com", name: "Better" }],
			organizations: [{ id: "ba_org_1", name: "Better Org", slug: "better-org" }],
			members: [{ userId: "ba_user_1", organizationId: "ba_org_1", role: "admin" }],
		}));
		run(["init", "--name", "Clearance CLI"], data);
		const preview = JSON.parse(run(["import", "legacy", "--file", fixture, "--dry-run"], data).stdout);
		expect(preview).toMatchObject({ schemaVersion: "v1", dryRun: true, source: "legacy", preview: { wouldCreate: { users: 1, organizations: 1, members: 1 } } });
		expect(JSON.parse(readFileSync(data, "utf8")).migrations).toHaveLength(0);
		const confirmation = run(["import", "legacy", "--file", fixture], data);
		expect(JSON.parse(confirmation.stdout).error.code).toBe("CLEARANCE_IMPORT_CONFIRMATION_REQUIRED");
		const imported = JSON.parse(run(["import", "legacy", "--file", fixture, "--yes"], data).stdout);
		expect(imported).toMatchObject({ schemaVersion: "v1", source: "legacy", verification: { reconciled: true, actual: { users: 1, organizations: 1, members: 1 } }, migration: { status: "verified", checkpoint: { phase: "verified" } } });
		const rerun = JSON.parse(run(["import", "legacy", "--file", fixture, "--yes"], data).stdout);
		expect(rerun.preview.wouldCreate).toEqual({ users: 0, organizations: 0, members: 0 });
		const persisted = JSON.parse(readFileSync(data, "utf8"));
		expect(persisted.principals).toHaveLength(1);
		expect(persisted.organizations).toHaveLength(1);
		expect(persisted.memberships).toHaveLength(1);
		expect(persisted.migrations).toHaveLength(2);
	});

	it("rejects invalid and cross-source Legacy fixtures with structured errors", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-clearance-errors-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		const wrongSource = join(dir, "wrong-source.json");
		const invalidReference = join(dir, "invalid-reference.json");
		writeFileSync(wrongSource, JSON.stringify({ source: "clerk", users: [], organizations: [], members: [] }));
		writeFileSync(invalidReference, JSON.stringify({ source: "legacy", users: [], organizations: [], members: [{ userId: "missing", organizationId: "missing" }] }));
		for (const fixture of [wrongSource, invalidReference]) {
			const result = run(["import", "legacy", "--file", fixture, "--dry-run"], data);
			expect(result.status).toBe(1);
			expect(JSON.parse(result.stdout).error).toMatchObject({ stage: "import.legacy.fixture", retryable: false });
		}
	});
});

describe("cursor pagination CLI parity (P2.3.1)", () => {
	it("users list --limit/--cursor walks to exhaustion with nextCursor in JSON output", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-cursor-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "Cursor CLI"], data).status).toBe(0);
		const created = new Set<string>();
		for (let i = 0; i < 5; i++) {
			const res = run(
				["users", "create", "--email", `cur${i}@t.dev`, "--name", `Cur ${i}`],
				data,
			);
			expect(res.status).toBe(0);
			created.add(JSON.parse(res.stdout).user.id as string);
		}

		// Legacy contract unchanged: no flags → full list, no pagination envelope.
		const legacy = JSON.parse(run(["users", "list"], data).stdout);
		expect(legacy.users.length).toBe(5);
		expect("nextCursor" in legacy).toBe(false);

		const seen = new Set<string>();
		let cursor: string | null = null;
		let pages = 0;
		for (;;) {
			const args = ["users", "list", "--limit", "2"];
			if (cursor) args.push("--cursor", cursor);
			const page = JSON.parse(run(args, data).stdout) as {
				users: Array<{ id: string }>;
				nextCursor: string | null;
			};
			pages += 1;
			expect(pages).toBeLessThan(10);
			for (const u of page.users) {
				expect(seen.has(u.id)).toBe(false); // no duplicates across pages
				seen.add(u.id);
			}
			if (page.nextCursor === null) break;
			cursor = page.nextCursor;
		}
		expect(pages).toBe(3);
		expect(seen).toEqual(created); // no omissions

		// events + sessions list expose nextCursor in JSON output too
		const events = JSON.parse(run(["events", "list", "--limit", "3"], data).stdout);
		expect("nextCursor" in events).toBe(true);
		const sessions = JSON.parse(run(["sessions", "list"], data).stdout);
		expect("nextCursor" in sessions).toBe(true);
	});

	it("garbage --cursor fails closed with structured CURSOR_INVALID on every list", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-cursor-bad-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "Cursor Bad"], data).status).toBe(0);
		for (const args of [
			["users", "list", "--cursor", "garbage"],
			["orgs", "list", "--cursor", "garbage"],
			["events", "list", "--cursor", "garbage"],
			["sessions", "list", "--cursor", "garbage"],
		]) {
			const res = run(args, data);
			expect(res.status, args.join(" ")).toBe(1);
			const doc = JSON.parse(res.stdout) as { error: { code: string } };
			expect(doc.error.code, args.join(" ")).toBe("CURSOR_INVALID");
		}
	});

	it("events export --before bounds the archive and rejects garbage timestamps", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-cli-before-"));
		dirs.push(dir);
		const data = join(dir, "data.json");
		expect(run(["init", "--name", "Before CLI"], data).status).toBe(0);
		expect(
			run(["users", "create", "--email", "b@t.dev", "--name", "B"], data).status,
		).toBe(0);

		const past = run(
			[
				"events",
				"export",
				"--output",
				join(dir, "past.json"),
				"--before",
				"2000-01-01T00:00:00Z",
			],
			data,
		);
		expect(past.status).toBe(0);
		const pastEnvelope = JSON.parse(past.stdout);
		expect(pastEnvelope.count).toBe(0); // nothing predates 2000
		expect(pastEnvelope.filters.before).toBe("2000-01-01T00:00:00.000Z");

		const future = run(
			[
				"events",
				"export",
				"--output",
				join(dir, "future.json"),
				"--before",
				"2100-01-01T00:00:00Z",
			],
			data,
		);
		expect(future.status).toBe(0);
		expect(JSON.parse(future.stdout).count).toBeGreaterThan(0);

		const bad = run(
			[
				"events",
				"export",
				"--output",
				join(dir, "bad.json"),
				"--before",
				"not-a-timestamp",
			],
			data,
		);
		expect(bad.status).toBe(1);
		expect(JSON.parse(bad.stdout).error.code).toBe(
			"EVENTS_EXPORT_BEFORE_INVALID",
		);
		expect(existsSync(join(dir, "bad.json"))).toBe(false);
	});
});
