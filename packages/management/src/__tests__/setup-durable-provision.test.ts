/**
 * Durable idempotent customer-setup provisioning:
 * deterministic attempt ids, crash-after-runtime-insert recovery,
 * single runtime+management row, encrypted storage, concurrent winner.
 */
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const runtimeRows = vi.hoisted(() => ({
	sso: new Map<
		string,
		{
			id: string;
			providerId: string;
			issuer: string;
			domain: string;
			organizationId: string | null;
			protocol: "saml" | "oidc";
			clientId?: string;
			clientSecret?: string;
		}
	>(),
	scim: new Map<
		string,
		{
			id: string;
			providerId: string;
			organizationId: string | null;
			/** Encrypted-at-rest stand-in; tests never put plaintext in management */
			tokenCipher: string;
			baseToken: string;
		}
	>(),
}));

vi.mock("../auth-bridge.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../auth-bridge.js")>();
	return {
		...actual,
		insertSsoProvider: vi.fn(
			async (input: {
				id?: string;
				providerId: string;
				issuer: string;
				domain: string;
				organizationId?: string;
				protocol: "saml" | "oidc";
				oidc?: { clientId: string; clientSecret: string };
			}) => {
				const id = input.id ?? `sso_gen_${runtimeRows.sso.size + 1}`;
				const existing =
					runtimeRows.sso.get(id) ??
					[...runtimeRows.sso.values()].find((r) => r.providerId === input.providerId);
				if (existing) {
					if (existing.id !== id) {
						throw Object.assign(new Error("providerId bound to different id"), {
							code: "SSO_PROVIDER_ID_CONFLICT",
						});
					}
					if (
						existing.providerId !== input.providerId ||
						(existing.organizationId ?? null) !== (input.organizationId ?? null) ||
						existing.issuer !== input.issuer ||
						existing.domain !== input.domain ||
						existing.protocol !== input.protocol ||
						(input.oidc != null &&
							(existing.clientId !== input.oidc.clientId ||
								existing.clientSecret !== input.oidc.clientSecret))
					) {
						throw Object.assign(new Error("scope mismatch"), {
							code: "SSO_PROVIDER_ID_CONFLICT",
						});
					}
					return {
						id: existing.id,
						clientSecretFingerprint: "fp",
						reused: true,
					};
				}
				runtimeRows.sso.set(id, {
					id,
					providerId: input.providerId,
					issuer: input.issuer,
					domain: input.domain,
					organizationId: input.organizationId ?? null,
					protocol: input.protocol,
					clientId: input.oidc?.clientId,
					clientSecret: input.oidc?.clientSecret,
				});
				return {
					id,
					clientSecretFingerprint: "fp",
					reused: false,
				};
			},
		),
		insertScimProvider: vi.fn(
			async (input: {
				id?: string;
				providerId: string;
				organizationId?: string;
				token?: string;
			}) => {
				const id = input.id ?? `scim_gen_${runtimeRows.scim.size + 1}`;
				const existing =
					runtimeRows.scim.get(id) ??
					[...runtimeRows.scim.values()].find((r) => r.providerId === input.providerId);
				if (existing) {
					if (existing.id !== id) {
						throw Object.assign(new Error("providerId bound to different id"), {
							code: "SCIM_PROVIDER_ID_CONFLICT",
						});
					}
					if (
						existing.providerId !== input.providerId ||
						(existing.organizationId ?? null) !== (input.organizationId ?? null)
					) {
						throw Object.assign(new Error("scope mismatch"), {
							code: "SCIM_PROVIDER_ID_CONFLICT",
						});
					}
					const token = Buffer.from(
						`${existing.baseToken}:${existing.providerId}${
							existing.organizationId ? `:${existing.organizationId}` : ""
						}`,
						"utf8",
					).toString("base64url");
					return { id: existing.id, token, reused: true };
				}
				const baseToken = input.token ?? `scimtok_${id}`;
				const token = Buffer.from(
					`${baseToken}:${input.providerId}${
						input.organizationId ? `:${input.organizationId}` : ""
					}`,
					"utf8",
				).toString("base64url");
				runtimeRows.scim.set(id, {
					id,
					providerId: input.providerId,
					organizationId: input.organizationId ?? null,
					tokenCipher: `enc:${baseToken}`,
					baseToken,
				});
				return { id, token, reused: false };
			},
		),
		deleteSsoProviderById: vi.fn(async (id: string) => {
			runtimeRows.sso.delete(id);
		}),
		deleteScimProviderById: vi.fn(async (id: string) => {
			runtimeRows.scim.delete(id);
		}),
	};
});

import {
	JsonStore,
	commitSetupLink,
	createOrganization,
	createScimConnectionReal,
	createSetupLink,
	createSsoConnectionReal,
	deriveSetupConnectionIds,
	deriveSetupReservationId,
	initProject,
	listEvents,
	releaseSetupLink,
	reserveSetupLink,
} from "../index.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-durable-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

function digestToken(token: string): string {
	return createHash("sha256").update(token, "utf8").digest("hex");
}

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
	runtimeRows.sso.clear();
	runtimeRows.scim.clear();
	vi.clearAllMocks();
});

beforeEach(() => {
	process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
	process.env.NODE_ENV = "test";
});

describe("deriveSetupConnectionIds / reservation lineage", () => {
	it("is stable for the same attempt and never embeds the raw token", () => {
		const token = "raw-capability-token-value-secret";
		const digest = digestToken(token);
		const attempt = deriveSetupReservationId(digest);
		expect(attempt).toMatch(/^rsv_/);
		expect(attempt).not.toContain(token);
		expect(JSON.stringify(attempt)).not.toContain(token);

		const a1 = deriveSetupConnectionIds("sso", attempt);
		const a2 = deriveSetupConnectionIds("sso", attempt);
		expect(a1).toEqual(a2);
		expect(a1.connectionId).toMatch(/^sso[0-9a-f]{24}$/);
		expect(a1.providerId).toMatch(/^clr-setup-sso-/);
		expect(JSON.stringify(a1)).not.toContain(token);

		const scim = deriveSetupConnectionIds("scim", attempt);
		expect(scim.connectionId).not.toBe(a1.connectionId);
		expect(scim.providerId).toMatch(/^clr-setup-scim-/);
	});
});

describe("SSO durable setup provision", () => {
	it("uses generated ids without setupAttemptId (CLI path)", async () => {
		const store = tempStore();
		initProject(store, { name: "CLI" });
		const org = createOrganization(store, { name: "Acme" });
		const conn = await createSsoConnectionReal(store, {
			organizationId: org.id,
			provider: "okta",
			protocol: "oidc",
			issuer: "https://dev-example.okta.com/oauth2/default",
			domain: "acme.example",
			clientId: "cid",
			clientSecret: "super-secret-cli",
		});
		expect(conn.id).toMatch(/^sso/);
		expect(runtimeRows.sso.size).toBe(1);
		expect(store.snapshot.identityConnections).toHaveLength(1);
		expect(JSON.stringify(store.snapshot)).not.toContain("super-secret-cli");
	});

	it("crash after runtime insert: lease expiry retry reuses exact id, one row, commit, replay denied", async () => {
		const store = tempStore();
		initProject(store, { name: "Crash" });
		const org = createOrganization(store, { name: "Customer" });
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
			ttlMinutes: 30,
		});

		const reserved1 = await reserveSetupLink(store, {
			token: link.token,
			kind: "sso",
			organizationId: org.id,
			reservationTtlMs: 50,
		});
		const ids = deriveSetupConnectionIds("sso", reserved1.reservationId);

		// Simulate process death after runtime insert, before management + commit.
			runtimeRows.sso.set(ids.connectionId, {
			id: ids.connectionId,
			providerId: ids.providerId,
			issuer: "https://dev-example.okta.com/oauth2/default",
			domain: "customer.example",
			organizationId: org.id,
			protocol: "oidc",
			clientId: "cid",
			clientSecret: "client-secret-value",
		});
		// Leave reservation active until TTL — then expire.
		await new Promise((r) => setTimeout(r, 60));
		const capHeld = store.snapshot.setupLinks.find((c) => c.id === link.capabilityId)!;
		// Force lease expiry in store if timer race
		store.mutate((data) => {
			const idx = data.setupLinks.findIndex((c) => c.id === link.capabilityId);
			if (idx >= 0) {
				data.setupLinks[idx] = {
					...data.setupLinks[idx]!,
					reservationExpiresAt: new Date(0).toISOString(),
				};
			}
		});
		await store.ready();
		void capHeld;

		const reserved2 = await reserveSetupLink(store, {
			token: link.token,
			kind: "sso",
			organizationId: org.id,
		});
		// Same attempt id across re-reserve
		expect(reserved2.reservationId).toBe(reserved1.reservationId);

		const recovered = await createSsoConnectionReal(store, {
			organizationId: org.id,
			provider: "okta",
			protocol: "oidc",
			issuer: "https://dev-example.okta.com/oauth2/default",
			domain: "customer.example",
			clientId: "cid",
			clientSecret: "client-secret-value",
			setupAttemptId: reserved2.reservationId,
			actor: "customer-setup",
		});
		expect(recovered.id).toBe(ids.connectionId);
		expect(runtimeRows.sso.size).toBe(1);
		expect(store.snapshot.identityConnections).toHaveLength(1);
		expect(store.snapshot.identityConnections[0]!.id).toBe(ids.connectionId);
		expect(JSON.stringify(store.snapshot)).not.toContain("client-secret-value");
		expect(JSON.stringify(store.snapshot)).not.toContain(link.token);

		await commitSetupLink(store, {
			token: link.token,
			kind: "sso",
			organizationId: org.id,
			reservationId: reserved2.reservationId,
		});
		const after = store.snapshot.setupLinks.find((c) => c.id === link.capabilityId)!;
		expect(after.useCount).toBe(1);
		expect(after.redeemedAt).toBeTruthy();

		await expect(
			reserveSetupLink(store, { token: link.token, kind: "sso" }),
		).rejects.toThrow(/already used|replay/i);

		// Second provision with same attempt still one row
		const again = await createSsoConnectionReal(store, {
			organizationId: org.id,
			provider: "okta",
			protocol: "oidc",
			issuer: "https://dev-example.okta.com/oauth2/default",
			domain: "customer.example",
			clientId: "cid",
			clientSecret: "client-secret-value",
			setupAttemptId: reserved2.reservationId,
		});
		expect(again.id).toBe(ids.connectionId);
		expect(runtimeRows.sso.size).toBe(1);
		expect(store.snapshot.identityConnections).toHaveLength(1);
	});

	it("fail closed when deterministic id belongs to mismatched organization", async () => {
		const store = tempStore();
		initProject(store, { name: "Mismatch" });
		const orgA = createOrganization(store, { name: "A" });
		const orgB = createOrganization(store, { name: "B" });
		const attempt = "rsv_deadbeefdeadbeefdeadbeef";
		const ids = deriveSetupConnectionIds("sso", attempt);
		runtimeRows.sso.set(ids.connectionId, {
			id: ids.connectionId,
			providerId: ids.providerId,
			issuer: "https://dev-example.okta.com/oauth2/default",
			domain: "a.example",
			organizationId: orgA.id,
			protocol: "oidc",
		});
		await expect(
			createSsoConnectionReal(store, {
				organizationId: orgB.id,
				provider: "okta",
				protocol: "oidc",
				issuer: "https://dev-example.okta.com/oauth2/default",
				domain: "b.example",
				clientId: "cid",
				clientSecret: "sec",
				setupAttemptId: attempt,
			}),
		).rejects.toThrow(/different organization|conflict|mismatch/i);
		expect(store.snapshot.identityConnections).toHaveLength(0);
		expect(runtimeRows.sso.size).toBe(1);
	});

	it("recreates a missing runtime SSO row from the encrypted management secret", async () => {
		const store = tempStore();
		initProject(store, { name: "SsoRuntimeRecovery" });
		const org = createOrganization(store, { name: "Recover" });
		const attempt = "rsv_ssoruntime111111111111";
		const first = await createSsoConnectionReal(store, {
			organizationId: org.id,
			provider: "okta",
			protocol: "oidc",
			issuer: "https://dev-example.okta.com/oauth2/default",
			domain: "recover.example",
			clientId: "stored-client",
			clientSecret: "stored-client-secret",
			setupAttemptId: attempt,
		});
		runtimeRows.sso.delete(first.id);

		await createSsoConnectionReal(store, {
			organizationId: org.id,
			provider: "okta",
			protocol: "oidc",
			issuer: "https://dev-example.okta.com/oauth2/default",
			domain: "recover.example",
			clientId: "stored-client",
			clientSecret: "retry-supplied-secret-must-not-win",
			setupAttemptId: attempt,
		});
		expect(runtimeRows.sso.size).toBe(1);
		expect(runtimeRows.sso.get(first.id)?.clientSecret).toBe(
			"stored-client-secret",
		);
		expect(JSON.stringify(store.snapshot)).not.toContain("stored-client-secret");
	});

	it("concurrent reserves: one winner, same deterministic provision target", async () => {
		const store = tempStore();
		initProject(store, { name: "Race" });
		const org = createOrganization(store, { name: "Org" });
		const link = createSetupLink(store, { organizationId: org.id, kind: "sso" });
		const raced = await Promise.allSettled([
			reserveSetupLink(store, { token: link.token, kind: "sso" }),
			reserveSetupLink(store, { token: link.token, kind: "sso" }),
		]);
		const wins = raced.filter((r) => r.status === "fulfilled");
		const losses = raced.filter((r) => r.status === "rejected");
		expect(wins).toHaveLength(1);
		expect(losses).toHaveLength(1);
		const winner = (wins[0] as PromiseFulfilledResult<{ reservationId: string }>).value;
		const ids = deriveSetupConnectionIds("sso", winner.reservationId);
		const conn = await createSsoConnectionReal(store, {
			organizationId: org.id,
			provider: "okta",
			protocol: "oidc",
			issuer: "https://dev-example.okta.com/oauth2/default",
			domain: "race.example",
			clientId: "cid",
			clientSecret: "secret-race",
			setupAttemptId: winner.reservationId,
		});
		expect(conn.id).toBe(ids.connectionId);
		await commitSetupLink(store, {
			token: link.token,
			kind: "sso",
			reservationId: winner.reservationId,
		});
		expect(store.snapshot.identityConnections).toHaveLength(1);
		expect(runtimeRows.sso.size).toBe(1);
		expect(JSON.stringify(listEvents(store))).not.toContain("secret-race");
		expect(JSON.stringify(listEvents(store))).not.toContain(link.token);
	});
});

describe("SCIM durable setup provision", () => {
	it("crash after runtime insert recovers encrypted handoff once; one row; no plaintext in store", async () => {
		const store = tempStore();
		initProject(store, { name: "ScimCrash" });
		const org = createOrganization(store, { name: "Dir" });
		const link = createSetupLink(store, { organizationId: org.id, kind: "scim" });
		const reserved1 = await reserveSetupLink(store, {
			token: link.token,
			kind: "scim",
			organizationId: org.id,
		});
		const ids = deriveSetupConnectionIds("scim", reserved1.reservationId);

		// Runtime inserted; management missing (process death mid-flight)
		const baseToken = "scimtok_orphan_base";
		runtimeRows.scim.set(ids.connectionId, {
			id: ids.connectionId,
			providerId: ids.providerId,
			organizationId: org.id,
			tokenCipher: `enc:${baseToken}`,
			baseToken,
		});
		// Expire lease
		store.mutate((data) => {
			const idx = data.setupLinks.findIndex((c) => c.id === link.capabilityId);
			data.setupLinks[idx] = {
				...data.setupLinks[idx]!,
				reservationExpiresAt: new Date(0).toISOString(),
			};
		});
		await releaseSetupLink(store, {
			token: link.token,
			kind: "scim",
			reservationId: reserved1.reservationId,
		});

		const reserved2 = await reserveSetupLink(store, {
			token: link.token,
			kind: "scim",
			organizationId: org.id,
		});
		expect(reserved2.reservationId).toBe(reserved1.reservationId);

		const recovered = await createScimConnectionReal(store, {
			organizationId: org.id,
			provider: "okta",
			setupAttemptId: reserved2.reservationId,
			actor: "customer-setup",
		});
		expect(recovered.id).toBe(ids.connectionId);
		// Handoff is composite base64url of baseToken:providerId:org (decrypt path)
		const expectedHandoff = Buffer.from(
			`${baseToken}:${ids.providerId}:${org.id}`,
			"utf8",
		).toString("base64url");
		expect(recovered.bearerTokenOnce).toBe(expectedHandoff);

		expect(runtimeRows.scim.size).toBe(1);
		expect(store.snapshot.directoryConnections).toHaveLength(1);
		const snap = JSON.stringify(store.snapshot);
		expect(snap).not.toContain(expectedHandoff);
		expect(snap).not.toContain(baseToken);
		expect(snap).not.toContain(link.token);
		expect(store.snapshot.directoryConnections[0]!.bearerTokenEncrypted).toMatch(
			/^clr\$v1\$/,
		);

		await commitSetupLink(store, {
			token: link.token,
			kind: "scim",
			organizationId: org.id,
			reservationId: reserved2.reservationId,
		});
		await expect(
			reserveSetupLink(store, { token: link.token, kind: "scim" }),
		).rejects.toThrow(/already used|replay/i);
	});

	it("reuses management row and decrypts handoff only for completion response", async () => {
		const store = tempStore();
		initProject(store, { name: "ScimReuse" });
		const org = createOrganization(store, { name: "Dir2" });
		const attempt = "rsv_scimreuse1111111111111";
		const first = await createScimConnectionReal(store, {
			organizationId: org.id,
			provider: "entra",
			setupAttemptId: attempt,
		});
		const handoff1 = first.bearerTokenOnce!;
		const second = await createScimConnectionReal(store, {
			organizationId: org.id,
			provider: "entra",
			setupAttemptId: attempt,
		});
		expect(second.id).toBe(first.id);
		expect(second.bearerTokenOnce).toBe(handoff1);
		expect(store.snapshot.directoryConnections).toHaveLength(1);
		expect(runtimeRows.scim.size).toBe(1);
		expect(JSON.stringify(store.snapshot)).not.toContain(handoff1);
		expect(JSON.stringify(listEvents(store))).not.toContain(handoff1);
	});

	it("recreates a missing runtime SCIM row with the same encrypted management credential", async () => {
		const store = tempStore();
		initProject(store, { name: "ScimRuntimeRecovery" });
		const org = createOrganization(store, { name: "Directory" });
		const attempt = "rsv_scimruntime11111111111";
		const first = await createScimConnectionReal(store, {
			organizationId: org.id,
			provider: "okta",
			setupAttemptId: attempt,
		});
		const firstHandoff = first.bearerTokenOnce!;
		runtimeRows.scim.delete(first.id);

		const recovered = await createScimConnectionReal(store, {
			organizationId: org.id,
			provider: "okta",
			setupAttemptId: attempt,
		});
		expect(recovered.id).toBe(first.id);
		expect(recovered.bearerTokenOnce).toBe(firstHandoff);
		expect(runtimeRows.scim.size).toBe(1);
		expect(store.snapshot.directoryConnections).toHaveLength(1);
		expect(JSON.stringify(store.snapshot)).not.toContain(firstHandoff);
	});
});
