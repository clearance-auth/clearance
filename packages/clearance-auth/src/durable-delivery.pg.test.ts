import { createHmac, randomBytes, randomUUID } from "node:crypto";
import {
	createDeliveryKeyring,
	decryptDeliveryPayload,
	qualifiedDeliveryTables,
} from "@clearance/delivery";
import {
	DeliveryWorker,
	type EmailSender,
	type WorkerConfig,
} from "@clearance/delivery-worker";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createClearanceAuth, type ClearanceAuthBundle } from "./create-auth.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const admin = new pg.Pool({
	connectionString: DATABASE_URL,
	connectionTimeoutMillis: 500,
});
let available = false;
try {
	await admin.query("SELECT 1");
	available = true;
} catch {
	if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") {
		throw new Error(`Durable delivery tests require Postgres at ${DATABASE_URL}`);
	}
} finally {
	await admin.end();
}

type EncryptedPayloadRow = {
	envelope: string;
	event_id: string;
	kind: string;
	channel: "email";
	project_id: string;
	environment_id: string;
	destination_fingerprint: string;
	expires_at: Date;
};

describe.sequential.skipIf(!available)(
	"runtime durable delivery transaction wiring",
	() => {
		const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
		const schema = `delivery_runtime_${suffix}`;
		const schemaOptions = { schema, prefix: "delivery_" };
		const keys = {
			currentKeyId: "current",
			keys: { current: randomBytes(32).toString("base64") },
			currentFingerprintKeyId: "fingerprint-current",
			fingerprintKeys: { "fingerprint-current": randomBytes(32).toString("base64") },
			sourceDedupeKey: randomBytes(32).toString("base64"),
		};
		const keyring = createDeliveryKeyring(keys);
		const basePool = new pg.Pool({ connectionString: DATABASE_URL });
		const createdUserIds: string[] = [];
		let bundle: ClearanceAuthBundle;
		let primaryEmail: string;
		let headers: Headers;
		let organizationId: string;
		let invitationId: string;

		beforeAll(async () => {
			await basePool.query(`CREATE SCHEMA "${schema}"`);
			const url = new URL(DATABASE_URL);
			url.searchParams.set("options", `-csearch_path=${schema}`);
			bundle = createClearanceAuth({
				baseURL: "http://localhost:3300/api/auth",
				secret: "durable-delivery-runtime-test-secret!!",
				databaseUrl: url.toString(),
				enableSso: false,
				enableScim: false,
				durableDelivery: {
					projectId: "project-runtime-test",
					environmentId: "environment-runtime-test",
					invitationUrl: (id) =>
						`http://localhost:3300/accept-invitation?invitationId=${encodeURIComponent(id)}`,
					keyring: keys,
					schema,
					prefix: "delivery_",
				},
				onUserCreated: async (user) => {
					createdUserIds.push(user.id);
				},
			});
			await bundle.migrate();
		});

		afterAll(async () => {
			await bundle?.destroy();
			await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
			await basePool.end();
		});

		it("commits five mutations with encrypted delivery payloads", async () => {
			primaryEmail = `owner-${suffix}@example.test`;
			const signup = await bundle.auth.api.signUpEmail({
				body: {
					email: primaryEmail,
					password: "correct-horse-battery",
					name: "Owner",
				},
			});
			expect(signup.token).toBeTruthy();
			const signedToken = encodeURIComponent(
				`${signup.token}.${createHmac(
					"sha256",
					"durable-delivery-runtime-test-secret!!",
				)
					.update(signup.token)
					.digest("base64")}`,
			);
			headers = new Headers({
				cookie: `clearance.session_token=${signedToken}`,
			});

			await bundle.auth.api.sendVerificationEmail({
				body: { email: primaryEmail },
			});
			await bundle.auth.api.requestPasswordReset({
				body: { email: primaryEmail },
			});
			const organization = await bundle.auth.api.createOrganization({
				body: { name: "Delivery Org", slug: `delivery-${suffix}` },
				headers,
			});
			organizationId = organization.id;
			const invitation = await bundle.auth.api.createInvitation({
				body: {
					email: `invite-${suffix}@example.test`,
					role: "member",
					organizationId,
				},
				headers,
			});
			invitationId = invitation.id;
			await bundle.auth.api.createInvitation({
				body: {
					email: invitation.email,
					role: "member",
					organizationId,
					resend: true,
				},
				headers,
			});

			const tables = qualifiedDeliveryTables(schemaOptions);
			const events = await basePool.query<{ kind: string }>(
				`SELECT kind FROM ${tables.event} ORDER BY created_at`,
			);
			expect(events.rows.map((row) => row.kind)).toEqual([
				"email.verification",
				"email.verification",
				"password.reset",
				"organization.invitation",
				"organization.invitation",
			]);
			expect(
				(await basePool.query(`SELECT count(*)::int count FROM ${tables.job}`))
					.rows[0].count,
			).toBe(5);

			const encrypted = await basePool.query<EncryptedPayloadRow>(
				`SELECT p.envelope, p.expires_at, e.id event_id, e.kind, e.project_id,
				 e.environment_id, e.destination_fingerprint, j.channel
				 FROM ${tables.payload} p JOIN ${tables.event} e ON e.id=p.event_id
				 JOIN ${tables.job} j ON j.event_id=e.id WHERE e.kind='password.reset'`,
			);
			const row = encrypted.rows[0]!;
			const plaintext = decryptDeliveryPayload<{
				template: string;
				url: string;
				to: string;
			}>(
				row.envelope,
				{
					version: 1,
					eventId: row.event_id,
					kind: row.kind,
					channel: row.channel,
					projectId: row.project_id,
					environmentId: row.environment_id,
					destinationFingerprint: row.destination_fingerprint,
					expiresAt: row.expires_at.toISOString(),
				},
				keyring,
			);
			expect(plaintext.template).toBe("password-reset");
			expect(JSON.stringify(encrypted.rows)).not.toContain(primaryEmail);
			expect(plaintext.url).toContain("/reset-password/");
			expect(plaintext.to).toBe(primaryEmail);
			expect(createdUserIds).toHaveLength(1);

			const invitationEncrypted = await basePool.query<EncryptedPayloadRow>(
				`SELECT p.envelope, p.expires_at, e.id event_id, e.kind, e.project_id,
				 e.environment_id, e.destination_fingerprint, j.channel
				 FROM ${tables.payload} p JOIN ${tables.event} e ON e.id=p.event_id
				 JOIN ${tables.job} j ON j.event_id=e.id
				 WHERE e.kind='organization.invitation' ORDER BY e.created_at LIMIT 1`,
			);
			const invitationRow = invitationEncrypted.rows[0]!;
			const invitationPayload = decryptDeliveryPayload<Record<string, unknown>>(
				invitationRow.envelope,
				{
					version: 1,
					eventId: invitationRow.event_id,
					kind: invitationRow.kind,
					channel: invitationRow.channel,
					projectId: invitationRow.project_id,
					environmentId: invitationRow.environment_id,
					destinationFingerprint: invitationRow.destination_fingerprint,
					expiresAt: invitationRow.expires_at.toISOString(),
				},
				keyring,
			);
			expect(Object.keys(invitationPayload).sort()).toEqual([
				"acceptanceUrl",
				"inviterName",
				"organizationName",
				"role",
				"template",
				"to",
			]);
			expect(
				Object.values(invitationPayload).every(
					(value) => typeof value === "string",
				),
			).toBe(true);
		});

		it("processes all five jobs through the worker delivery contract", async () => {
			const sent: Array<{ payload: unknown; jobId: string }> = [];
			const sender: EmailSender = {
				async verify() {},
				async send(payload, context) {
					sent.push({ payload, jobId: context.jobId });
					return {
						status: "250",
						requestId: `runtime_${context.jobId}`,
					};
				},
				close() {},
			};
			const workerPool = new pg.Pool({ connectionString: DATABASE_URL });
			const workerConfig: WorkerConfig = {
				mode: "once",
				databaseUrl: DATABASE_URL,
				workerId: `runtime-${suffix}`,
				keyring,
				schema,
				prefix: "delivery_",
				smtp: {
					host: "127.0.0.1",
					port: 25,
					secure: false,
					requireTls: false,
					from: "support@example.test",
					connectionTimeoutMs: 1_000,
					socketTimeoutMs: 1_000,
					greetingTimeoutMs: 1_000,
				},
				concurrency: 2,
				pollMs: 25,
				leaseMs: 5_000,
				heartbeatMs: 1_000,
				maintenanceMs: 1_000,
				drainTimeoutMs: 5_000,
				maxBodyBytes: 1_048_576,
				appName: "Clearance",
				allowHttpLinks: true,
				healthHost: "127.0.0.1",
				healthPort: 8091,
				processOnceLimit: 10,
				webhook: {
					allowInsecureLoopback: true,
					dnsTimeoutMs: 2_000,
					connectTimeoutMs: 2_000,
					responseTimeoutMs: 2_000,
					maxResponseBytes: 65_536,
				},
			};
			const worker = new DeliveryWorker(workerConfig, {
				pool: workerPool,
				sender,
			});
			try {
				await worker.initialize();
				expect(await worker.processOnce(10)).toBe(5);
				expect(sent).toHaveLength(5);
				for (const item of sent) {
					const payload = item.payload as {
						to?: string;
						from?: string;
						subject?: string;
						text?: string;
						html?: string;
					};
					expect(payload.to).toMatch(/@example\.test$/);
					expect(payload.from).toBe("support@example.test");
					expect(payload.subject).toBeTruthy();
					expect(Boolean(payload.text || payload.html)).toBe(true);
				}
				const tables = qualifiedDeliveryTables(schemaOptions);
				expect(
					(
						await basePool.query(
							`SELECT count(*)::int count FROM ${tables.job} WHERE state='delivered'`,
						)
					).rows[0].count,
				).toBe(5);
			} finally {
				await worker.stop();
			}
		});

		it("rolls back product mutations when durable enqueue fails", async () => {
			const tables = qualifiedDeliveryTables(schemaOptions);
			const brokenName = `${tables.names.job}_disabled`;
			const breakDelivery = async (operation: () => Promise<unknown>) => {
				await basePool.query(
					`ALTER TABLE ${tables.job} RENAME TO "${brokenName}"`,
				);
				try {
					await expect(operation()).rejects.toThrow();
				} finally {
					await basePool.query(
						`ALTER TABLE "${schema}"."${brokenName}" RENAME TO "${tables.names.job}"`,
					);
				}
			};

			const failedSignupEmail = `rollback-signup-${suffix}@example.test`;
			await breakDelivery(() =>
				bundle.auth.api.signUpEmail({
					body: {
						email: failedSignupEmail,
						password: "correct-horse-battery",
						name: "Rollback",
					},
				}),
			);
			expect(
				(
					await basePool.query(
						`SELECT count(*)::int count FROM "${schema}"."user" WHERE email=$1`,
						[failedSignupEmail],
					)
				).rows[0].count,
			).toBe(0);
			expect(createdUserIds).toHaveLength(1);

			const eventCount = Number(
				(
					await basePool.query(
						`SELECT count(*) count FROM ${tables.event}`,
					)
				).rows[0].count,
			);
			await breakDelivery(() =>
				bundle.auth.api.sendVerificationEmail({
					body: { email: primaryEmail },
				}),
			);
			expect(
				Number(
					(
						await basePool.query(
							`SELECT count(*) count FROM ${tables.event}`,
						)
					).rows[0].count,
				),
			).toBe(eventCount);
			expect(
				(
					await basePool.query(
						`SELECT "emailVerified" FROM "${schema}"."user" WHERE email=$1`,
						[primaryEmail],
					)
				).rows[0].emailVerified,
			).toBe(false);

			const resetCount = (
				await basePool.query(
					`SELECT count(*)::int count FROM "${schema}".verification WHERE identifier LIKE 'reset-password:%'`,
				)
			).rows[0].count;
			await breakDelivery(() =>
				bundle.auth.api.requestPasswordReset({
					body: { email: primaryEmail },
				}),
			);
			expect(
				(
					await basePool.query(
						`SELECT count(*)::int count FROM "${schema}".verification WHERE identifier LIKE 'reset-password:%'`,
					)
				).rows[0].count,
			).toBe(resetCount);

			const failedInviteEmail = `rollback-invite-${suffix}@example.test`;
			await breakDelivery(() =>
				bundle.auth.api.createInvitation({
					body: {
						email: failedInviteEmail,
						role: "member",
						organizationId,
					},
					headers,
				}),
			);
			expect(
				(
					await basePool.query(
						`SELECT count(*)::int count FROM "${schema}".invitation WHERE email=$1`,
						[failedInviteEmail],
					)
				).rows[0].count,
			).toBe(0);

			const beforeResend = (
				await basePool.query(
					`SELECT "expiresAt" FROM "${schema}".invitation WHERE id=$1`,
					[invitationId],
				)
			).rows[0].expiresAt;
			await breakDelivery(() =>
				bundle.auth.api.createInvitation({
					body: {
						email: `invite-${suffix}@example.test`,
						role: "member",
						organizationId,
						resend: true,
					},
					headers,
				}),
			);
			const afterResend = (
				await basePool.query(
					`SELECT "expiresAt" FROM "${schema}".invitation WHERE id=$1`,
					[invitationId],
				)
			).rows[0].expiresAt;
			expect(new Date(afterResend).toISOString()).toBe(
				new Date(beforeResend).toISOString(),
			);
		});

		it("rolls back delivery and hook effects after a later mutation fails", async () => {
			const tables = qualifiedDeliveryTables(schemaOptions);
			const beforeEvents = Number(
				(
					await basePool.query(
						`SELECT count(*) count FROM ${tables.event}`,
					)
				).rows[0].count,
			);
			const failedEmail = `rollback-after-enqueue-${suffix}@example.test`;
			await basePool.query(
				`ALTER TABLE "${schema}"."session" RENAME TO "session_disabled"`,
			);
			try {
				await expect(
					bundle.auth.api.signUpEmail({
						body: {
							email: failedEmail,
							password: "correct-horse-battery",
							name: "Late rollback",
						},
					}),
				).rejects.toThrow();
			} finally {
				await basePool.query(
					`ALTER TABLE "${schema}"."session_disabled" RENAME TO "session"`,
				);
			}
			expect(
				(
					await basePool.query(
						`SELECT count(*)::int count FROM "${schema}"."user" WHERE email=$1`,
						[failedEmail],
					)
				).rows[0].count,
			).toBe(0);
			expect(
				Number(
					(
						await basePool.query(
							`SELECT count(*) count FROM ${tables.event}`,
						)
					).rows[0].count,
				),
			).toBe(beforeEvents);
			expect(createdUserIds).toHaveLength(1);
		});
	},
);
