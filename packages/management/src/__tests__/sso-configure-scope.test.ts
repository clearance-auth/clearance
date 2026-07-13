/**
 * configureSsoConnection scope + atomicity (FOLLOW.md P2.3.5).
 *
 * The audit found configureSsoConnection took no scope, read the snapshot
 * outside the mutation, and recorded audit in a separate non-atomic mutate.
 * These tests pin the fixed contract: cross-scope/missing ids fail closed as
 * SSO_NOT_FOUND with NO write, and configure+audit commit as one mutation.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonStore } from "../store/json-store.js";
import { createOrganization, initProject } from "../services/core.js";
import {
	configureSsoConnection,
	createSsoConnection,
} from "../services/sso.js";

const dirs: string[] = [];

function newStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-sso-configure-"));
	dirs.push(dir);
	const store = new JsonStore(join(dir, "data.json"));
	initProject(store, { name: "SSO Configure App" });
	return store;
}

afterEach(() => {
	for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("configureSsoConnection scope enforcement", () => {
	it("cross-scope configure fails closed as SSO_NOT_FOUND with no write", () => {
		const store = newStore();
		const org = createOrganization(store, { name: "Scoped Org" });
		const conn = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://original.example.com",
		});
		const checksumBefore = store.checksum();

		expect(() =>
			configureSsoConnection(
				store,
				conn.id,
				{ issuer: "https://attacker.example.com" },
				{ scope: { projectId: "proj_other", environmentId: "env_other" } },
			),
		).toThrowError(
			expect.objectContaining({ code: "SSO_NOT_FOUND", status: 404 }),
		);

		// Fail closed means NOTHING was written: no field change, no audit event.
		expect(store.checksum()).toBe(checksumBefore);
		const row = store.snapshot.identityConnections.find((c) => c.id === conn.id);
		expect(row?.issuer).toBe("https://original.example.com");
		expect(
			store.snapshot.events.filter((e) => e.action === "sso.configure"),
		).toEqual([]);
	});

	it("missing ids fail closed as SSO_NOT_FOUND with no write", () => {
		const store = newStore();
		const checksumBefore = store.checksum();
		expect(() =>
			configureSsoConnection(store, "sso_nope", { issuer: "https://x.dev" }),
		).toThrowError(expect.objectContaining({ code: "SSO_NOT_FOUND" }));
		expect(store.checksum()).toBe(checksumBefore);
	});

	it("in-scope configure applies patch and audit atomically in one mutation", () => {
		const store = newStore();
		const org = createOrganization(store, { name: "Atomic Org" });
		const conn = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://before.example.com",
		});

		// Count durable writes: JsonStore.save() runs once per mutate.
		let saves = 0;
		const originalSave = store.save.bind(store);
		store.save = () => {
			saves += 1;
			originalSave();
		};

		const updated = configureSsoConnection(
			store,
			conn.id,
			{ issuer: "https://after.example.com" },
			{ actor: "test-operator", source: "cli" },
		);
		store.save = originalSave;

		expect(saves).toBe(1); // validation + write + audit in ONE mutation
		expect(updated.issuer).toBe("https://after.example.com");
		// Public return never exposes encrypted material
		expect(
			(updated as unknown as Record<string, unknown>).clientSecretEncrypted,
		).toBeUndefined();

		const row = store.snapshot.identityConnections.find((c) => c.id === conn.id);
		expect(row?.issuer).toBe("https://after.example.com");
		const audits = store.snapshot.events.filter(
			(e) => e.action === "sso.configure" && e.subjectId === conn.id,
		);
		expect(audits.length).toBe(1);
		expect(audits[0]!.actor).toBe("test-operator");
		expect(audits[0]!.projectId).toBe(org.projectId);
		expect(audits[0]!.environmentId).toBe(org.environmentId);
	});

	it("configuring a concurrently-deleted connection fails closed with no partial write", () => {
		const store = newStore();
		const org = createOrganization(store, { name: "Rollback Org" });
		const conn = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://keep.example.com",
		});
		// Simulate a concurrent delete between resolve and mutate by removing the
		// row through a raw mutation, then configuring: JsonStore mutates a draft,
		// so the thrown SSO_NOT_FOUND must leave no audit event behind.
		store.mutate((data) => {
			data.identityConnections = data.identityConnections.filter(
				(c) => c.id !== conn.id,
			);
		});
		const before = store.checksum();
		expect(() =>
			configureSsoConnection(store, conn.id, { issuer: "https://x.dev" }),
		).toThrowError(expect.objectContaining({ code: "SSO_NOT_FOUND" }));
		expect(store.checksum()).toBe(before);
		expect(
			store.snapshot.events.filter((e) => e.action === "sso.configure"),
		).toEqual([]);
	});
});
