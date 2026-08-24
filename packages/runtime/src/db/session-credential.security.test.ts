import type { ClearanceOptions } from "@clearance/core";
import { describe, expect, it } from "vitest";
import { clearance } from "../auth/full";
import { getTestInstance } from "../test-utils/test-instance";
import { generateCredentialOperationKey } from "../utils/operation-key";
import { admin } from "../plugins/admin";
import { migrateCredentialAuthorities } from "./credential-authority-migration";
import {
	assertSessionCredentialMigrationComplete,
	getSecondarySessionEpoch,
	recordSecurityMigrationComplete,
	SESSION_CREDENTIAL_MIGRATION_ID,
} from "./session-credential-migration";

describe("session credential authority", async () => {
	const { auth, signInWithTestUser } = await getTestInstance({
		logger: { level: "error" },
	});
	const context = await auth.$context;
	const signedIn = await signInWithTestUser();
	const userId = signedIn.user.id;

	it("persists only credential digests and keeps public session rows secret-free", async () => {
		const issued = await context.internalAdapter.createSession(userId);
		const sessions = await context.adapter.findMany<Record<string, unknown>>({
			model: "session",
			where: [{ field: "id", value: issued.id }],
		});
		const credentials = await context.adapter.findMany<
			Record<string, unknown>
		>({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: issued.id }],
		});

		expect(sessions).toHaveLength(1);
		expect(sessions[0]?.token).toBe(`clr_sid_${sessions[0]?.id}`);
		expect(credentials).toHaveLength(1);
		expect(credentials[0]?.secretDigest).toMatch(/^v1:/);
		expect(JSON.stringify({ sessions, credentials })).not.toContain(issued.token);
	});

	it("derives session authority fields even when an internal override requests them", async () => {
		const injectedToken = "caller-controlled-refresh-authority";
		const issued = await context.internalAdapter.createSession(
			userId,
			undefined,
			{
				id: "caller-controlled-session-id",
				token: injectedToken,
				userId: "caller-controlled-user-id",
			},
			true,
		);
		expect(issued.id).not.toBe("caller-controlled-session-id");
		expect(issued.userId).toBe(userId);
		expect(issued.token).not.toBe(injectedToken);
		const persisted = await context.adapter.findOne<Record<string, unknown>>({
			model: "session",
			where: [{ field: "id", value: issued.id }],
		});
		expect(persisted).toMatchObject({
			id: issued.id,
			userId,
			token: `clr_sid_${issued.id}`,
		});
		expect(await context.internalAdapter.findSession(injectedToken)).toBeNull();
	});

	it("reasserts session authority after untrusted database hooks", async () => {
		const attackerSessionId = "hook-controlled-session-id";
		const attackerUserId = "hook-controlled-user-id";
		const attackerToken = "clr_sid_hook-controlled-token";
		const hooked = await getTestInstance(
			{
				logger: { level: "error" },
				databaseHooks: {
					session: {
						create: {
							before: async (session) => ({
								data: {
									...session,
									id: attackerSessionId,
									userId: attackerUserId,
									token: attackerToken,
								},
							}),
						},
						update: {
							before: async (session) => ({
								data: {
									...session,
									id: attackerSessionId,
									userId: attackerUserId,
									token: attackerToken,
								},
							}),
						},
					},
				},
			},
			{ disableTestUser: true },
		);
		const hookedContext = await hooked.auth.$context;
		const user = await hookedContext.internalAdapter.createUser({
			email: "hook-authority@test.com",
			emailVerified: true,
			name: "hook authority",
			image: null,
		});
		const issued = await hookedContext.internalAdapter.createSession(user.id);

		expect(issued.id).not.toBe(attackerSessionId);
		expect(issued.userId).toBe(user.id);
		await hookedContext.internalAdapter.updateSession(issued.token, {
			ipAddress: "203.0.113.9",
		});
		const persisted = await hookedContext.adapter.findOne<
			Record<string, unknown>
		>({
			model: "session",
			where: [{ field: "id", value: issued.id }],
		});

		expect(persisted).toMatchObject({
			id: issued.id,
			userId: user.id,
			token: `clr_sid_${issued.id}`,
			ipAddress: "203.0.113.9",
		});
		expect(await hookedContext.internalAdapter.findSession(attackerToken)).toBeNull();
	});

	it("returns the same successor when one refresh operation is retried", async () => {
		const issued = await context.internalAdapter.createSession(userId);
		const idempotencyKey = generateCredentialOperationKey();
		const results = await Promise.all(
			Array.from({ length: 32 }, () =>
				context.internalAdapter.rotateSessionCredential(
					issued.token,
					idempotencyKey,
				),
			),
		);
		const successors = results.filter(
			(result): result is NonNullable<typeof result> => result !== null,
		);

		expect(successors).toHaveLength(32);
		expect(new Set(successors.map((result) => result.familyId)).size).toBe(1);
		expect(new Set(successors.map((result) => result.refreshToken)).size).toBe(1);
		expect(new Set(successors.map((result) => result.rotationCounter))).toEqual(
			new Set([1]),
		);

		const familyRows = await context.adapter.findMany<Record<string, unknown>>({
			model: "sessionCredential",
			where: [{ field: "familyId", value: successors[0]!.familyId }],
		});
		expect(familyRows).toHaveLength(2);
		expect(familyRows.map((row) => row.status).sort()).toEqual(
			["active", "consumed"],
		);
		expect(JSON.stringify(familyRows)).not.toContain(successors[0]!.refreshToken);
		expect(
			familyRows.every((row) => row.recoverySecretCiphertext == null),
		).toBe(true);
		expect(
			await context.internalAdapter.findSession(successors[0]!.refreshToken),
		).not.toBeNull();
	});

	it("recovers an exact successor after a committed response is lost", async () => {
		const issued = await context.internalAdapter.createSession(userId);
		const idempotencyKey = generateCredentialOperationKey();
		const first = await context.internalAdapter.rotateSessionCredential(
			issued.token,
			idempotencyKey,
		);
		const retry = await context.internalAdapter.rotateSessionCredential(
			issued.token,
			idempotencyKey,
		);
		expect(retry).toMatchObject({
			refreshToken: first!.refreshToken,
			familyId: first!.familyId,
			rotationCounter: 1,
		});
		expect(
			await context.internalAdapter.findSession(retry!.refreshToken),
		).not.toBeNull();
	});

	it("rejects session resolution, rotation, and recovery for a banned user", async () => {
		const { auth: guardedAuth, db } = await getTestInstance(
			{ plugins: [admin()] },
			{ disableTestUser: true },
		);
		const guardedContext = await guardedAuth.$context;
		const user = await guardedContext.internalAdapter.createUser({
			email: "banned-session-authority@example.test",
			emailVerified: true,
			name: "Banned session authority",
			image: null,
		});
		const issued = await guardedContext.internalAdapter.createSession(user.id);
		const operationKey = generateCredentialOperationKey();
		const rotated = await guardedContext.internalAdapter.rotateSessionCredential(
			issued.token,
			operationKey,
		);
		expect(rotated).not.toBeNull();
		await db.update({
			model: "user",
			where: [{ field: "id", value: user.id }],
			update: { banned: true, updatedAt: new Date() },
		});

		await expect(
			guardedContext.internalAdapter.findSession(rotated!.refreshToken),
		).resolves.toBeNull();
		await expect(
			guardedContext.internalAdapter.rotateSessionCredential(
				rotated!.refreshToken,
				generateCredentialOperationKey(),
			),
		).resolves.toBeNull();
		await expect(
			guardedContext.internalAdapter.recoverSessionCredential(
				issued.token,
				operationKey,
			),
		).resolves.toBeNull();
	});

	it("rejects predictable repeated rotation operation keys", async () => {
		const issued = await context.internalAdapter.createSession(userId);
		await expect(
			context.internalAdapter.rotateSessionCredential(
				issued.token,
					"a".repeat(22),
				),
		).rejects.toThrow("clr_op_v1_<43 canonical base64url characters>");
	});

	it("never authenticates a consumed refresh credential during recovery", async () => {
		const issued = await context.internalAdapter.createSession(userId);
		const operationKey = generateCredentialOperationKey();
		const rotated = await context.internalAdapter.rotateSessionCredential(
			issued.token,
			operationKey,
		);
		expect(rotated).not.toBeNull();
		// Consumed parent must fail closed without revoking the active successor.
		expect(await context.internalAdapter.findSession(issued.token)).toBeNull();
		expect(
			await context.internalAdapter.findSession(rotated!.refreshToken),
		).not.toBeNull();
	});

	it("preserves the family when findSession sees a consumed parent in the recovery window, then recovers the exact successor", async () => {
		const issued = await context.internalAdapter.createSession(userId);
		const operationKey = generateCredentialOperationKey();
		const first = await context.internalAdapter.rotateSessionCredential(
			issued.token,
			operationKey,
		);
		expect(first).not.toBeNull();

		expect(await context.internalAdapter.findSession(issued.token)).toBeNull();
		expect(
			await context.internalAdapter.findSession(first!.refreshToken),
		).not.toBeNull();

		const retry = await context.internalAdapter.rotateSessionCredential(
			issued.token,
			operationKey,
		);
		expect(retry).toMatchObject({
			refreshToken: first!.refreshToken,
			familyId: first!.familyId,
			rotationCounter: first!.rotationCounter,
		});
		expect(
			await context.internalAdapter.findSession(retry!.refreshToken),
		).not.toBeNull();
	});

	it("revokes the family when competing refresh operations race", async () => {
		const issued = await context.internalAdapter.createSession(userId);
		const results = await Promise.all(
			Array.from({ length: 16 }, () =>
				context.internalAdapter.rotateSessionCredential(
					issued.token,
					generateCredentialOperationKey(),
				),
			),
		);
		const winner = results.find((result) => result !== null);
		expect(winner).toBeDefined();
		expect(results.filter((result) => result !== null)).toHaveLength(1);
		const familyRows = await context.adapter.findMany<Record<string, unknown>>({
			model: "sessionCredential",
			where: [{ field: "familyId", value: winner!.familyId }],
		});
		expect(familyRows.every((row) => row.status === "revoked")).toBe(true);
		expect(familyRows.every((row) => row.reuseDetectedAt instanceof Date)).toBe(
			true,
		);
		expect(
			await context.internalAdapter.findSession(winner!.refreshToken),
		).toBeNull();
	});

	it("revokes the family immediately when a consumed parent is rotated with a distinct operation key", async () => {
		const issued = await context.internalAdapter.createSession(userId);
		const operationKey = generateCredentialOperationKey();
		const rotated = await context.internalAdapter.rotateSessionCredential(
			issued.token,
			operationKey,
		);
		expect(rotated).not.toBeNull();
		const distinctKey = generateCredentialOperationKey();
		expect(distinctKey).not.toBe(operationKey);
		expect(
			await context.internalAdapter.rotateSessionCredential(
				issued.token,
				distinctKey,
			),
		).toBeNull();
		expect(
			await context.internalAdapter.findSession(rotated!.refreshToken),
		).toBeNull();
		expect(await context.internalAdapter.findSession(issued.token)).toBeNull();
		const familyRows = await context.adapter.findMany<Record<string, unknown>>({
			model: "sessionCredential",
			where: [{ field: "familyId", value: rotated!.familyId }],
		});
		expect(familyRows.every((row) => row.status === "revoked")).toBe(true);
		expect(familyRows.every((row) => row.reuseDetectedAt instanceof Date)).toBe(
			true,
		);
	});

	it("revokes the family when findSession presents an expired consumed parent", async () => {
		const issued = await context.internalAdapter.createSession(userId);
		const operationKey = generateCredentialOperationKey();
		const rotated = await context.internalAdapter.rotateSessionCredential(
			issued.token,
			operationKey,
		);
		expect(rotated).not.toBeNull();

		const parentRows = await context.adapter.findMany<Record<string, unknown>>({
			model: "sessionCredential",
			where: [
				{ field: "familyId", value: rotated!.familyId },
				{ field: "status", value: "consumed" },
			],
		});
		expect(parentRows).toHaveLength(1);
		const parentId = parentRows[0]!.id as string;
		await context.adapter.update({
			model: "sessionCredential",
			where: [{ field: "id", value: parentId }],
			update: {
				recoveryExpiresAt: new Date(Date.now() - 1),
				updatedAt: new Date(),
			},
		});

		expect(await context.internalAdapter.findSession(issued.token)).toBeNull();
		expect(
			await context.internalAdapter.findSession(rotated!.refreshToken),
		).toBeNull();
		const familyRows = await context.adapter.findMany<Record<string, unknown>>({
			model: "sessionCredential",
			where: [{ field: "familyId", value: rotated!.familyId }],
		});
		expect(familyRows.every((row) => row.status === "revoked")).toBe(true);
		expect(familyRows.every((row) => row.reuseDetectedAt instanceof Date)).toBe(
			true,
		);
	});

	it("rejects reintroduction of a legacy plaintext session after sealing", async () => {
		const legacyToken = "legacy-session-token-with-sufficient-entropy";
		const legacyId = "legacy-session-id";
		const now = new Date();
		await expect(
			context.adapter.create({
				model: "session",
				forceAllowId: true,
				data: {
					id: legacyId,
					userId,
					token: legacyToken,
					expiresAt: new Date(now.getTime() + 60_000),
					createdAt: now,
					updatedAt: now,
				},
			}),
		).rejects.toThrow(
			"Clearance credential authority rejects replayable bearer storage",
		);
	});

	it("retries a failed marker assertion after the migration completes", async () => {
		await context.adapter.delete({
			model: "securityMigration",
			where: [{ field: "key", value: SESSION_CREDENTIAL_MIGRATION_ID }],
		});
		const peer = clearance(auth.options);
		const peerContext = await peer.$context;
		await expect(
			assertSessionCredentialMigrationComplete(
				peerContext.adapter,
				peerContext.options,
			),
		).rejects.toMatchObject({
			status: "SERVICE_UNAVAILABLE",
			statusCode: 503,
			body: { code: "SECURITY_MIGRATION_REQUIRED" },
		});
		await recordSecurityMigrationComplete(
			context.adapter,
			SESSION_CREDENTIAL_MIGRATION_ID,
			auth.options,
		);
		await expect(
			assertSessionCredentialMigrationComplete(
				peerContext.adapter,
				peerContext.options,
			),
		).resolves.toBeUndefined();
	});

	it("fails closed on a missing secondary-storage epoch and retries after repair", async () => {
		const store = new Map<string, string>();
		const secondary = {
			set(key: string, value: string) {
				store.set(key, value);
			},
			get(key: string) {
				return store.get(key) ?? null;
			},
			delete(key: string) {
				store.delete(key);
			},
		};
		const secondaryInstance = await getTestInstance({
			secondaryStorage: secondary,
			logger: { level: "error" },
		});
		const epoch = await getSecondarySessionEpoch(
			secondaryInstance.auth.options,
		);
		expect(store.get(epoch.key)).toBe(JSON.stringify(epoch.value));

		store.delete(epoch.key);
		const peer = clearance(secondaryInstance.auth.options);
		const peerContext = await peer.$context;
		await expect(
			assertSessionCredentialMigrationComplete(
				peerContext.adapter,
				peerContext.options,
			),
		).rejects.toMatchObject({
			status: "SERVICE_UNAVAILABLE",
			statusCode: 503,
			body: { code: "SECURITY_MIGRATION_REQUIRED" },
		});

		store.set(epoch.key, JSON.stringify(epoch.value));
		await expect(
			assertSessionCredentialMigrationComplete(
				peerContext.adapter,
				peerContext.options,
			),
		).resolves.toBeUndefined();
	});

	it("accepts a secondary epoch after retained-secret promotion without re-publish", async () => {
		const store = new Map<string, string>();
		const namespace = "epoch-retained-promote";
		const secondary = {
			namespace,
			set(key: string, value: string) {
				store.set(key, value);
			},
			get(key: string) {
				return store.get(key) ?? null;
			},
			delete(key: string) {
				store.delete(key);
			},
		};
		const oldSecret = "old-primary-secret-with-sufficient-entropy-01";
		const newSecret = "new-primary-secret-with-sufficient-entropy-02";
		const published = await getSecondarySessionEpoch({
			secrets: [{ version: 1, value: oldSecret }],
			secondaryStorage: secondary,
		} as ClearanceOptions);
		store.set(published.key, JSON.stringify(published.value));
		expect(published.value.startsWith("digest-v1:")).toBe(true);
		expect(published.value.split(":")).toHaveLength(2);

		const snapshot = new Map(store);
		const promoted = {
			secrets: [
				{ version: 2, value: newSecret },
				{ version: 1, value: oldSecret },
			],
			secondaryStorage: secondary,
		} as ClearanceOptions;
		// Traffic under the new primary must accept the epoch signed by the
		// retained former primary; assertion must not rewrite storage.
		await expect(
			assertSessionCredentialMigrationComplete(
				{ id: "memory" } as never,
				promoted,
			),
		).resolves.toBeUndefined();
		expect([...store.entries()]).toEqual([...snapshot.entries()]);
	});

	it("fails closed when the signing secret is retired before epoch re-publish", async () => {
		const store = new Map<string, string>();
		const namespace = "epoch-premature-retire";
		const secondary = {
			namespace,
			set(key: string, value: string) {
				store.set(key, value);
			},
			get(key: string) {
				return store.get(key) ?? null;
			},
			delete(key: string) {
				store.delete(key);
			},
		};
		const oldSecret = "retired-primary-secret-with-sufficient-entropy";
		const newSecret = "replacement-primary-secret-with-sufficient-entropy";
		const published = await getSecondarySessionEpoch({
			secrets: [{ version: 1, value: oldSecret }],
			secondaryStorage: secondary,
		} as ClearanceOptions);
		store.set(published.key, JSON.stringify(published.value));

		const retired = {
			secrets: [{ version: 2, value: newSecret }],
			secondaryStorage: secondary,
		} as ClearanceOptions;
		const snapshot = new Map(store);
		await expect(
			assertSessionCredentialMigrationComplete(
				{ id: "memory" } as never,
				retired,
			),
		).rejects.toMatchObject({
			status: "SERVICE_UNAVAILABLE",
			statusCode: 503,
			body: { code: "SECURITY_MIGRATION_REQUIRED" },
		});
		expect([...store.entries()]).toEqual([...snapshot.entries()]);
	});

	it("accepts traffic after explicit epoch republish under the new primary", async () => {
		const store = new Map<string, string>();
		const namespace = "epoch-republish-repair";
		const secondary = {
			namespace,
			set(key: string, value: string) {
				store.set(key, value);
			},
			get(key: string) {
				return store.get(key) ?? null;
			},
			delete(key: string) {
				store.delete(key);
			},
		};
		const oldSecret = "pre-repair-primary-secret-with-sufficient-entropy";
		const newSecret = "post-repair-primary-secret-with-sufficient-entropy";
		const stale = await getSecondarySessionEpoch({
			secrets: [{ version: 1, value: oldSecret }],
			secondaryStorage: secondary,
		} as ClearanceOptions);
		store.set(stale.key, JSON.stringify(stale.value));

		const repairedOptions = {
			secrets: [{ version: 2, value: newSecret }],
			secondaryStorage: secondary,
		} as ClearanceOptions;
		await expect(
			assertSessionCredentialMigrationComplete(
				{ id: "memory" } as never,
				repairedOptions,
			),
		).rejects.toMatchObject({
			body: { code: "SECURITY_MIGRATION_REQUIRED" },
		});

		const repaired = await getSecondarySessionEpoch(repairedOptions);
		expect(repaired.key).toBe(stale.key);
		expect(repaired.value).not.toBe(stale.value);
		expect(repaired.value.startsWith("digest-v1:")).toBe(true);
		store.set(repaired.key, JSON.stringify(repaired.value));
		await expect(
			assertSessionCredentialMigrationComplete(
				{ id: "memory" } as never,
				repairedOptions,
			),
		).resolves.toBeUndefined();
	});

	it("rejects malformed or unsigned secondary epoch values", async () => {
		const store = new Map<string, string>();
		const namespace = "epoch-malformed";
		const secondary = {
			namespace,
			set(key: string, value: string) {
				store.set(key, value);
			},
			get(key: string) {
				return store.get(key) ?? null;
			},
			delete(key: string) {
				store.delete(key);
			},
		};
		const options = {
			secret: "malformed-epoch-secret-with-sufficient-entropy",
			secondaryStorage: secondary,
		} as ClearanceOptions;
		const epoch = await getSecondarySessionEpoch(options);
		const migrationRequired = {
			status: "SERVICE_UNAVAILABLE",
			statusCode: 503,
			body: { code: "SECURITY_MIGRATION_REQUIRED" },
		};

		for (const malformed of [
			"digest-v1",
			"digest-v1:",
			"digest-v1::sig",
			"digest-v1:legacy:not-a-signature",
			"other-gen:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"not-json-and-not-an-epoch",
			JSON.stringify("digest-v1:"),
			JSON.stringify({ generation: "digest-v1" }),
		]) {
			store.set(epoch.key, malformed);
			await expect(
				assertSessionCredentialMigrationComplete(
					{ id: "memory" } as never,
					options,
				),
			).rejects.toMatchObject(migrationRequired);
		}
	});

	it("accepts a secondary epoch under legacy single-secret options", async () => {
		const store = new Map<string, string>();
		const namespace = "epoch-legacy-single-secret";
		const secondary = {
			namespace,
			set(key: string, value: string) {
				store.set(key, value);
			},
			get(key: string) {
				return store.get(key) ?? null;
			},
			delete(key: string) {
				store.delete(key);
			},
		};
		const options = {
			secret: "legacy-single-secret-with-sufficient-entropy",
			secondaryStorage: secondary,
		} as ClearanceOptions;
		const epoch = await getSecondarySessionEpoch(options);
		expect(epoch.value.startsWith("digest-v1:")).toBe(true);
		expect(epoch.value.split(":")).toHaveLength(2);
		store.set(epoch.key, JSON.stringify(epoch.value));
		await expect(
			assertSessionCredentialMigrationComplete(
				{ id: "memory" } as never,
				options,
			),
		).resolves.toBeUndefined();
		// Raw (non-JSON) storage of the signed value remains accepted.
		store.set(epoch.key, epoch.value);
		await expect(
			assertSessionCredentialMigrationComplete(
				{ id: "memory" } as never,
				options,
			),
		).resolves.toBeUndefined();
	});

	it("requires durable proof unless the adapter explicitly declares ephemeral storage", async () => {
		const isolated = await getTestInstance(
			{ logger: { level: "error" } },
			{ disableTestUser: true },
		);
		const isolatedContext = await isolated.auth.$context;
		const isolatedUser = await isolatedContext.internalAdapter.createUser({
			email: "durable-migration-proof@example.test",
			emailVerified: true,
			name: "Durable migration proof",
			image: null,
		});
		await isolatedContext.internalAdapter.createSession(isolatedUser.id);
		await isolatedContext.adapter.delete({
			model: "securityMigration",
			where: [{ field: "key", value: SESSION_CREDENTIAL_MIGRATION_ID }],
		});
		const adapterWithMutableId = isolatedContext.adapter as typeof isolatedContext.adapter & {
			id: string;
		};
		const originalAdapterId = adapterWithMutableId.id;
		adapterWithMutableId.id = "kysely";
		const isolatedOptions = isolated.auth.options as ClearanceOptions;
		await expect(
			migrateCredentialAuthorities(isolatedContext.adapter, isolatedOptions),
		).rejects.toThrow("database-native product migration runner");
		adapterWithMutableId.id = originalAdapterId;
		isolatedContext.adapter.storagePersistence = undefined;
		await expect(
			migrateCredentialAuthorities(
				isolatedContext.adapter,
				isolated.auth.options,
			),
		).rejects.toThrow("database-native product migration runner");
		expect(
			await isolatedContext.adapter.findOne({
				model: "securityMigration",
				where: [{ field: "key", value: SESSION_CREDENTIAL_MIGRATION_ID }],
			}),
		).toBeNull();

		isolatedContext.adapter.storagePersistence = "ephemeral";
		await expect(
			migrateCredentialAuthorities(
				isolatedContext.adapter,
				isolated.auth.options,
			),
		).resolves.toMatchObject({
			migrationIds: [SESSION_CREDENTIAL_MIGRATION_ID],
		});
	});
});
