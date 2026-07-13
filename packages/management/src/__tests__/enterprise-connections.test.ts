/**
 * SSO/SCIM rotate, disable, and SCIM replay under principal-derived scope.
 * JSON store path — no Postgres required.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	JsonStore,
	createOrganization,
	createScimConnection,
	createSsoConnection,
	decryptCredential,
	disableScimConnection,
	disableSsoConnection,
	initProject,
	inspectScimConnection,
	inspectScimTrace,
	inspectSsoConnection,
	listEvents,
	publicDirectoryConnection,
	publicIdentityConnection,
	replayScimTrace,
	rotateScimCredential,
	rotateSsoCredential,
	testScimConnection,
} from "../index.js";
import { ClearanceError } from "../services/errors.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-ent-conn-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

beforeEach(() => {
	process.env.CLEARANCE_CREDENTIAL_KEY =
		"unit-test-credential-key-material-32b!!";
	process.env.CLEARANCE_CREDENTIAL_KEY_ID = "k1";
});

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
	delete process.env.CLEARANCE_CREDENTIAL_KEY;
	delete process.env.CLEARANCE_CREDENTIAL_KEY_ID;
	delete process.env.CLEARANCE_CREDENTIAL_PREVIOUS_KEY;
	delete process.env.CLEARANCE_CREDENTIAL_PREVIOUS_KEY_ID;
	delete process.env.CLEARANCE_PROJECT_ID;
	delete process.env.CLEARANCE_ENV_ID;
});

describe("SSO rotate / disable", () => {
	it("rotates credential envelope, audits, and never returns secrets", () => {
		const store = tempStore();
		initProject(store, { name: "SsoRot" });
		const org = createOrganization(store, { name: "Cust" });
		const secret = "sso-client-secret-plaintext-xyz";
		const sso = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://idp.example/oauth2",
			clientSecret: secret,
		});

		const before = store.snapshot.identityConnections[0]!.clientSecretEncrypted!;
		const rotated = rotateSsoCredential(store, sso.id, {
			actor: "test",
			source: "cli",
		});

		expect((rotated as { clientSecretEncrypted?: string }).clientSecretEncrypted).toBeUndefined();
		expect(rotated.clientSecretFingerprint).toBeTruthy();
		const after = store.snapshot.identityConnections[0]!.clientSecretEncrypted!;
		expect(after).not.toBe(before);
		expect(decryptCredential(after)).toBe(secret);
		expect(JSON.stringify(rotated)).not.toContain(secret);
		expect(JSON.stringify(listEvents(store))).not.toContain(secret);

		const audit = listEvents(store).find(
			(e) => e.action === "sso.rotate" && e.subjectId === sso.id,
		);
		expect(audit?.source).toBe("cli");
		expect(audit?.actor).toBe("test");
		expect(audit?.projectId).toBe(org.projectId);
		expect(audit?.environmentId).toBe(org.environmentId);
		expect(JSON.stringify(audit?.metadata ?? {})).not.toMatch(/clr\$v1\$/);
	});

	it("disables SSO connection idempotently with audit and scope fail-closed", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "SsoDis" });
		const org = createOrganization(store, { name: "Cust" });
		const sso = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://idp.example/oauth2",
		});

		const first = disableSsoConnection(store, sso.id, {
			actor: "test",
			source: "api",
		});
		expect(first.connection.status).toBe("disabled");
		expect(first.idempotent).toBe(false);
		expect(inspectSsoConnection(store, sso.id).status).toBe("disabled");

		const second = disableSsoConnection(store, sso.id, {
			actor: "test",
			source: "api",
		});
		expect(second.idempotent).toBe(true);
		expect(second.connection.status).toBe("disabled");

		const disableAudits = listEvents(store).filter(
			(e) => e.action === "sso.disable" && e.subjectId === sso.id,
		);
		expect(disableAudits.length).toBeGreaterThanOrEqual(2);
		expect(disableAudits.every((e) => e.source === "api")).toBe(true);

		// Cross-scope connection fails closed as not found
		store.mutate((data) => {
			const now = new Date().toISOString();
			data.organizations.push({
				id: "org_foreign",
				projectId: "proj_other",
				environmentId: "env_other",
				name: "Foreign",
				slug: "foreign",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
			data.identityConnections.push({
				id: "sso_foreign",
				organizationId: "org_foreign",
				protocol: "oidc",
				provider: "okta",
				status: "active",
				domains: [],
				attributeMapping: {},
				createdAt: now,
				updatedAt: now,
			});
		});
		const scope = { projectId: project.id, environmentId: environment.id };
		expect(() =>
			disableSsoConnection(store, "sso_foreign", { scope }),
		).toThrow(/not found/i);
		expect(() =>
			rotateSsoCredential(store, "sso_missing", { scope }),
		).toThrow(/not found/i);
		expect(() => inspectSsoConnection(store, "sso_missing", { scope })).toThrow(
			/not found/i,
		);
	});

	it("rotate fails closed when no client secret is stored", () => {
		const store = tempStore();
		initProject(store, { name: "NoSec" });
		const org = createOrganization(store, { name: "Cust" });
		const sso = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://idp.example/oauth2",
		});
		expect(() => rotateSsoCredential(store, sso.id)).toThrow(ClearanceError);
		expect(() => rotateSsoCredential(store, sso.id)).toThrow(/no encrypted/i);
		expect(listEvents(store).some((e) => e.action === "sso.rotate")).toBe(false);
	});
});

describe("SCIM rotate / disable / replay", () => {
	it("rotates SCIM bearer envelope without leaking token", () => {
		const store = tempStore();
		initProject(store, { name: "ScimRot" });
		const org = createOrganization(store, { name: "Cust" });
		const token = "scim-bearer-token-plaintext-abc";
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
			endpoint: "https://scim.example/v2",
			bearerToken: token,
		});
		const before = store.snapshot.directoryConnections[0]!.bearerTokenEncrypted!;
		const rotated = rotateScimCredential(store, scim.id, {
			actor: "test",
			source: "cli",
		});
		expect((rotated as { bearerTokenEncrypted?: string }).bearerTokenEncrypted).toBeUndefined();
		const after = store.snapshot.directoryConnections[0]!.bearerTokenEncrypted!;
		expect(after).not.toBe(before);
		expect(decryptCredential(after)).toBe(token);
		expect(JSON.stringify(rotated)).not.toContain(token);
		expect(JSON.stringify(listEvents(store))).not.toContain(token);
		expect(
			listEvents(store).some(
				(e) => e.action === "scim.rotate" && e.subjectId === scim.id,
			),
		).toBe(true);
	});

	it("disables SCIM connection and rejects cross-scope ids", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "ScimDis" });
		const org = createOrganization(store, { name: "Cust" });
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
		});
		const disabled = disableScimConnection(store, scim.id, {
			actor: "test",
			source: "api",
		});
		expect(disabled.connection.status).toBe("disabled");
		expect(inspectScimConnection(store, scim.id).status).toBe("disabled");
		expect(
			listEvents(store).some(
				(e) => e.action === "scim.disable" && e.source === "api",
			),
		).toBe(true);

		store.mutate((data) => {
			const now = new Date().toISOString();
			data.organizations.push({
				id: "org_f2",
				projectId: "proj_other",
				environmentId: "env_other",
				name: "F",
				slug: "f2",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
			data.directoryConnections.push({
				id: "scim_foreign",
				organizationId: "org_f2",
				provider: "okta",
				status: "active",
				endpoint: "/scim/v2/x",
				deprovisioningPolicy: "disable",
				createdAt: now,
				updatedAt: now,
			});
		});
		const scope = { projectId: project.id, environmentId: environment.id };
		expect(() =>
			disableScimConnection(store, "scim_foreign", { scope }),
		).toThrow(/not found/i);
	});

	it("replays SCIM diagnostic traces under scope without mutating connections", () => {
		const store = tempStore();
		initProject(store, { name: "ScimRep" });
		const org = createOrganization(store, { name: "Cust" });
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
		});
		const tested = testScimConnection(store, scim.id, { dryRun: true });
		const originalId = tested.trace.id;
		const statusBefore = store.snapshot.directoryConnections[0]!.status;
		const tokenBefore =
			store.snapshot.directoryConnections[0]!.bearerTokenEncrypted;

		const inspected = inspectScimTrace(store, originalId);
		expect(inspected.id).toBe(originalId);

		const replay = replayScimTrace(store, originalId, {
			actor: "test",
			source: "cli",
		});
		expect(replay.id).not.toBe(originalId);
		expect(replay.stage).toMatch(/\.replay$/);
		expect(store.snapshot.directoryConnections[0]!.status).toBe(statusBefore);
		expect(store.snapshot.directoryConnections[0]!.bearerTokenEncrypted).toBe(
			tokenBefore,
		);
		expect(
			listEvents(store).some(
				(e) =>
					e.action === "scim.replay" &&
					e.actor === "test" &&
					e.source === "cli",
			),
		).toBe(true);

		expect(() => inspectScimTrace(store, "tr_missing")).toThrow(/not found/i);
		expect(() => replayScimTrace(store, "tr_missing")).toThrow(/not found/i);
	});

	it("public views strip encrypted material", () => {
		const store = tempStore();
		initProject(store, { name: "Pub" });
		const org = createOrganization(store, { name: "Cust" });
		const sso = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://idp.example",
			clientSecret: "secret-value",
		});
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
			bearerToken: "token-value",
		});
		const rawSso = store.snapshot.identityConnections.find((c) => c.id === sso.id)!;
		const rawScim = store.snapshot.directoryConnections.find((c) => c.id === scim.id)!;
		expect(publicIdentityConnection(rawSso).hasClientSecret).toBe(true);
		expect(
			(publicIdentityConnection(rawSso) as { clientSecretEncrypted?: string })
				.clientSecretEncrypted,
		).toBeUndefined();
		expect(publicDirectoryConnection(rawScim).hasBearerToken).toBe(true);
		expect(
			(publicDirectoryConnection(rawScim) as { bearerTokenEncrypted?: string })
				.bearerTokenEncrypted,
		).toBeUndefined();
	});
});
