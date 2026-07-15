import { createOTP } from "@clearance/utils/otp";
import { describe, expect, it, vi } from "vitest";
import { symmetricDecrypt } from "../../crypto";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import { getTestInstance } from "../../test-utils/test-instance";
import type { Session, User } from "../../types";
import { DEFAULT_SECRET } from "../../utils/constants";
import { twoFactor } from ".";
import type { TwoFactorTable } from "./types";

describe.sequential("TOTP replay and replacement lifecycle", () => {
	it("allows only one concurrent fresh enrollment to establish factor state", async () => {
		const { auth, signInWithTestUser, testUser, db } = await getTestInstance({
			secret: DEFAULT_SECRET,
			plugins: [twoFactor()],
		});
		const { headers } = await signInWithTestUser();
		const user = await db.findOne<User>({
			model: "user",
			where: [{ field: "email", value: testUser.email }],
		});

		const responses = await Promise.all([
			auth.api.enableTwoFactor({
				body: { password: testUser.password },
				headers,
				asResponse: true,
			}),
			auth.api.enableTwoFactor({
				body: { password: testUser.password },
				headers,
				asResponse: true,
			}),
		]);
		expect(responses.map((response) => response.status)).toEqual([200, 200]);
		const enrollments = await Promise.all(
			responses.map((response) => response.json() as Promise<{
				backupCodes: string[];
				totpURI: string;
			}>),
		);
		expect(enrollments[0]).toEqual(enrollments[1]);
		const rows = await db.findMany<TwoFactorTable>({
			model: "twoFactor",
			where: [{ field: "userId", value: user!.id }],
		});
		expect(rows).toHaveLength(1);
	});

	it("consumes each timestep once across independent challenges and accepts the next timestep", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-07-15T12:00:00.000Z"));
		try {
			const { auth, signInWithTestUser, testUser, db } = await getTestInstance({
				secret: DEFAULT_SECRET,
				plugins: [twoFactor()],
			});
			const { headers } = await signInWithTestUser();
			const user = await db.findOne<User>({
				model: "user",
				where: [{ field: "email", value: testUser.email }],
			});
			const enrollment = await auth.api.enableTwoFactor({
				body: { password: testUser.password },
				headers,
			});
			expect(enrollment.totpURI).toBeTruthy();
			const row = await db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "userId", value: user!.id }],
			});
			const secret = await symmetricDecrypt({
				key: DEFAULT_SECRET,
				data: row!.secret,
			});
			await auth.api.verifyTOTP({
				body: { code: await createOTP(secret).totp() },
				headers,
			});

			async function startChallenge(): Promise<Headers> {
				const response = await auth.api.signInEmail({
					body: { email: testUser.email, password: testUser.password },
					asResponse: true,
				});
				expect(response.status).toBe(200);
				return convertSetCookieToCookie(response.headers);
			}

			vi.advanceTimersByTime(30_000);
			const challenges = await Promise.all([startChallenge(), startChallenge()]);
			const replayedCode = await createOTP(secret).totp();
			const results = await Promise.all(
				challenges.map((challengeHeaders) =>
					auth.api.verifyTOTP({
						body: { code: replayedCode },
						headers: challengeHeaders,
						asResponse: true,
					}),
				),
			);
			expect(results.map((result) => result.status).sort()).toEqual([200, 401]);

			const losingIndex = results.findIndex((result) => result.status === 401);
			vi.advanceTimersByTime(30_000);
			const next = await auth.api.verifyTOTP({
				body: { code: await createOTP(secret).totp() },
				headers: challenges[losingIndex]!,
				asResponse: true,
			});
			expect(next.status).toBe(200);

			await db.update({
				model: "twoFactor",
				where: [{ field: "id", value: row!.id }],
				update: { lastUsedTotpCounter: null },
			});
			vi.advanceTimersByTime(30_000);
			const legacyChallenge = await startChallenge();
			const legacy = await auth.api.verifyTOTP({
				body: { code: await createOTP(secret).totp() },
				headers: legacyChallenge,
				asResponse: true,
			});
			expect(legacy.status).toBe(200);
			const normalized = await db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "id", value: row!.id }],
			});
			expect(normalized?.lastUsedTotpCounter).toBeGreaterThan(-1);
			const sessions = await db.findMany<Session>({
				model: "session",
				where: [{ field: "userId", value: user!.id }],
			});
			expect(sessions.length).toBeGreaterThanOrEqual(3);
		} finally {
			vi.useRealTimers();
		}
	});

	it("requires the established factor and swaps staged secrets atomically", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-07-15T13:00:00.000Z"));
		try {
			const { auth, signInWithTestUser, testUser, db } = await getTestInstance({
				secret: DEFAULT_SECRET,
				plugins: [twoFactor()],
			});
			const { headers } = await signInWithTestUser();
			const user = await db.findOne<User>({
				model: "user",
				where: [{ field: "email", value: testUser.email }],
			});
			await auth.api.enableTwoFactor({
				body: { password: testUser.password },
				headers,
			});
			const original = await db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "userId", value: user!.id }],
			});
			const oldSecret = await symmetricDecrypt({
				key: DEFAULT_SECRET,
				data: original!.secret,
			});
			const enrollmentResponse = await auth.api.verifyTOTP({
				body: { code: await createOTP(oldSecret).totp() },
				headers,
				asResponse: true,
			});
			expect(enrollmentResponse.status).toBe(200);
			const activeHeaders = convertSetCookieToCookie(enrollmentResponse.headers);
			await db.update({
				model: "twoFactor",
				where: [{ field: "id", value: original!.id }],
				update: { verified: null as unknown as boolean },
			});

			const missingStepUp = await auth.api.enableTwoFactor({
				body: { password: testUser.password },
				headers: activeHeaders,
				asResponse: true,
			});
			expect(missingStepUp.status).toBe(400);
			const wrongStepUp = await auth.api.enableTwoFactor({
				body: { password: testUser.password, currentCode: "000000" },
				headers: activeHeaders,
				asResponse: true,
			});
			expect(wrongStepUp.status).toBe(401);
			const preserved = await db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "id", value: original!.id }],
			});
			expect(preserved?.secret).toBe(original!.secret);
			expect(preserved?.backupCodes).toBe(original!.backupCodes);
			expect(preserved?.pendingSecret).toBeFalsy();

			vi.advanceTimersByTime(30_000);
			const replacement = await auth.api.enableTwoFactor({
				body: {
					password: testUser.password,
					currentCode: await createOTP(oldSecret).totp(),
				},
				headers: activeHeaders,
			});
			expect(replacement.backupCodes).toHaveLength(10);
			const staged = await db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "id", value: original!.id }],
			});
			expect(staged?.secret).toBe(original!.secret);
			expect(staged?.backupCodes).toBe(original!.backupCodes);
			expect(staged?.pendingSecret).toBeTruthy();
			const newSecret = await symmetricDecrypt({
				key: DEFAULT_SECRET,
				data: staged!.pendingSecret!,
			});

			const wrongNew = await auth.api.verifyTOTP({
				body: { code: "000000" },
				headers: activeHeaders,
				asResponse: true,
			});
			expect(wrongNew.status).toBe(401);
			const beforeSwap = await db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "id", value: original!.id }],
			});
			expect(beforeSwap?.secret).toBe(original!.secret);
			expect(beforeSwap?.pendingSecret).toBe(staged!.pendingSecret);

			const newCode = await createOTP(newSecret).totp();
			const swapped = await Promise.all([
				auth.api.verifyTOTP({
					body: { code: newCode },
					headers: activeHeaders,
					asResponse: true,
				}),
				auth.api.verifyTOTP({
					body: { code: newCode },
					headers: activeHeaders,
					asResponse: true,
				}),
			]);
			expect(swapped.map((result) => result.status).sort()).toEqual([200, 401]);
			const active = await db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "id", value: original!.id }],
			});
			expect(active?.secret).toBe(staged!.pendingSecret);
			expect(active?.backupCodes).toBe(staged!.pendingBackupCodes);
			expect(active?.pendingSecret).toBeFalsy();
			expect(active?.pendingBackupCodes).toBeFalsy();
			expect(active?.verified).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});
});
