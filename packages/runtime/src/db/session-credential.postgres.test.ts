import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../test-utils/test-instance";
import { generateCredentialOperationKey } from "../utils/operation-key";
import { admin } from "../plugins/admin";

const hasPostgres = Boolean(
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
		process.env.CLEARANCE_TEST_DATABASE_URL,
);

describe.skipIf(!hasPostgres)(
	"session credential authority with PostgreSQL serial IDs",
	() => {
		it("migrates and rotates with numeric primary and foreign keys", async () => {
			const { auth, signInWithTestUser } = await getTestInstance(
				{
					advanced: { database: { generateId: "serial" } },
					logger: { level: "error" },
				},
				{ testWith: "postgres" },
			);
			const signedIn = await signInWithTestUser();
			const context = await auth.$context;
			const issued = await context.internalAdapter.createSession(
				signedIn.user.id,
			);
			expect(issued.id).toMatch(/^\d+$/);

			const firstRows = await context.adapter.findMany<
				Record<string, unknown>
			>({
				model: "sessionCredential",
				where: [{ field: "sessionId", value: issued.id }],
			});
			expect(firstRows).toHaveLength(1);
			expect(String(firstRows[0]!.id)).toMatch(/^\d+$/);

			const rotated = await context.internalAdapter.rotateSessionCredential(
				issued.token,
				generateCredentialOperationKey(),
			);
			expect(rotated).not.toBeNull();
			const familyRows = await context.adapter.findMany<
				Record<string, unknown>
			>({
				model: "sessionCredential",
				where: [{ field: "familyId", value: rotated!.familyId }],
				sortBy: { field: "rotationCounter", direction: "asc" },
			});
			expect(familyRows).toHaveLength(2);
			expect(String(familyRows[1]!.parentCredentialId)).toBe(
				String(familyRows[0]!.id),
			);
			expect(
				await context.internalAdapter.findSession(rotated!.refreshToken),
			).not.toBeNull();
		});

		it("recovers same-key CAS races and revokes distinct-key reuse", async () => {
			const { auth, signInWithTestUser } = await getTestInstance(
				{ logger: { level: "error" } },
				{ testWith: "postgres" },
			);
			const signedIn = await signInWithTestUser();
			const context = await auth.$context;

			const retryable = await context.internalAdapter.createSession(
				signedIn.user.id,
			);
			const operationKey = generateCredentialOperationKey();
			const retries = await Promise.all(
				Array.from({ length: 16 }, () =>
					context.internalAdapter.rotateSessionCredential(
						retryable.token,
						operationKey,
					),
				),
			);
			expect(retries.every((result) => result !== null)).toBe(true);
			expect(
				new Set(retries.map((result) => result!.refreshToken)).size,
			).toBe(1);
			expect(new Set(retries.map((result) => result!.familyId)).size).toBe(1);
			const retryFamily = await context.adapter.findMany<
				Record<string, unknown>
			>({
				model: "sessionCredential",
				where: [{ field: "familyId", value: retries[0]!.familyId }],
			});
			expect(retryFamily.map((row) => row.status).sort()).toEqual([
				"active",
				"consumed",
			]);

			const contested = await context.internalAdapter.createSession(
				signedIn.user.id,
			);
			const competing = await Promise.all([
				context.internalAdapter.rotateSessionCredential(
					contested.token,
					generateCredentialOperationKey(),
				),
				context.internalAdapter.rotateSessionCredential(
					contested.token,
					generateCredentialOperationKey(),
				),
			]);
			const winner = competing.find((result) => result !== null);
			expect(winner).toBeDefined();
			expect(competing.filter((result) => result !== null)).toHaveLength(1);
			const revokedFamily = await context.adapter.findMany<
				Record<string, unknown>
			>({
				model: "sessionCredential",
				where: [{ field: "familyId", value: winner!.familyId }],
			});
			expect(
				revokedFamily.every(
					(row) => row.status === "revoked" && row.reuseDetectedAt,
				),
			).toBe(true);
			expect(
				await context.internalAdapter.findSession(winner!.refreshToken),
			).toBeNull();
		});

		it("serializes session rotation with an administrator ban", async () => {
			const { auth, signInWithTestUser } = await getTestInstance(
				{
					plugins: [admin()],
					databaseHooks: {
						user: {
							create: {
								before: async (user) => ({
									data: {
										...user,
										emailVerified: true,
										...(user.name === "Admin" ? { role: "admin" } : {}),
									},
								}),
							},
						},
					},
				},
				{ testWith: "postgres", testUser: { name: "Admin" } },
			);
			const { headers } = await signInWithTestUser();
			const context = await auth.$context;
			const target = await context.internalAdapter.createUser({
				name: "Session rotation race target",
				email: `session-rotation-race-${Date.now()}@example.test`,
				emailVerified: true,
				image: null,
			});
			const session = await context.internalAdapter.createSession(target.id);
			let lockedResolve!: () => void;
			const locked = new Promise<void>((resolve) => {
				lockedResolve = resolve;
			});
			let releaseResolve!: () => void;
			const release = new Promise<void>((resolve) => {
				releaseResolve = resolve;
			});
			const originalTransaction = context.adapter.transaction.bind(
				context.adapter,
			);
			const transactionSpy = vi
				.spyOn(context.adapter, "transaction")
				.mockImplementation(async (callback) =>
					originalTransaction(async (trx) => {
						const originalUpdate = trx.update;
						trx.update = async <T>(
							input: Parameters<typeof originalUpdate>[0],
						) => {
							const result = await originalUpdate<T>(input);
							if (
								input.model === "user" &&
								!("banned" in (input.update as Record<string, unknown>))
							) {
								lockedResolve();
								await release;
							}
							return result;
						};
						return callback(trx);
					}),
				);
			try {
				const rotating = context.internalAdapter.rotateSessionCredential(
					session.token,
					generateCredentialOperationKey(),
				);
				await locked;
				let banSettled = false;
				const banning = auth.api
					.banUser({
						headers,
						body: { userId: target.id, banReason: "rotation race" },
					})
					.finally(() => {
						banSettled = true;
					});
				await new Promise((resolve) => setTimeout(resolve, 50));
				expect(banSettled).toBe(false);
				releaseResolve();
				const rotated = await rotating;
				expect(rotated).not.toBeNull();
				await banning;
				await expect(
					context.internalAdapter.findSession(rotated!.refreshToken),
				).resolves.toBeNull();
				const family = await context.adapter.findMany<Record<string, unknown>>({
					model: "sessionCredential",
					where: [{ field: "familyId", value: rotated!.familyId }],
				});
				expect(family).toHaveLength(2);
				expect(family.every((row) => row.status === "revoked")).toBe(true);
			} finally {
				releaseResolve();
				transactionSpy.mockRestore();
			}
		});
	},
);
