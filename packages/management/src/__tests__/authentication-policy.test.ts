import { beforeEach, describe, expect, it, vi } from "vitest";
import { registerInternalCoordinatedExecutor } from "../store/coordinated-internal.js";
import type { ManagementStore } from "../store/types.js";

const mocks = vi.hoisted(() => ({
	planUnlock: vi.fn(),
	unlock: vi.fn(),
	principalRead: vi.fn(),
	coordinatedPrincipalRead: vi.fn(),
}));

vi.mock("../auth-bridge.js", () => ({
	getAuthBundle: () => ({
		authenticationPolicy: {
			scope: {
				projectId: "project_policy",
				environmentId: "environment_policy",
			},
			planUnlock: mocks.planUnlock,
			unlock: mocks.unlock,
		},
	}),
	ensureAuthMigrated: async () => undefined,
}));

import { unlockAuthenticationForManagement } from "../services/authentication-policy.js";

const scope = {
	projectId: "project_policy",
	environmentId: "environment_policy",
};
const principal = {
	id: "user_cutover",
	...scope,
	email: "cutover@example.test",
	name: "Cutover User",
	status: "active" as const,
	createdAt: "2026-07-18T00:00:00.000Z",
	updatedAt: "2026-07-18T00:00:00.000Z",
};

function preview(userId: string, kind: "password" | "factor" | "all") {
	return {
		schemaVersion: "v1" as const,
		userId,
		kind,
		password: {
			matchedRows: 1,
			failedAttemptRows: 1,
			reservationRows: 0,
			lockedRows: 1,
			wouldChangeRows: 1,
		},
		factor: {
			matchedRows: 0,
			failedAttemptRows: 0,
			reservationRows: 0,
			lockedRows: 0,
			wouldChangeRows: 0,
		},
		wouldChange: true,
	};
}

beforeEach(() => {
	mocks.planUnlock.mockReset();
	mocks.unlock.mockReset();
	mocks.principalRead.mockReset();
	mocks.coordinatedPrincipalRead.mockReset();
	mocks.principalRead.mockResolvedValue(principal);
	mocks.coordinatedPrincipalRead.mockResolvedValue(principal);
	mocks.planUnlock.mockImplementation(async ({ userId, kind }) =>
		preview(userId, kind),
	);
	mocks.unlock.mockImplementation(async ({ userId, kind }) => ({
		...preview(userId, kind),
		changed: true,
	}));
});

describe("management authentication-policy", () => {
	it("plans and applies unlocks after principal cutover without snapshot principals", async () => {
		const snapshot = { principals: [], events: [] };
		const store = {
			backend: "postgres",
			snapshot,
			mutateCoordinated: async () => {
				throw new Error("registered executor should be used");
			},
			storeV2Principals: {
				authoritative: true,
				getById: mocks.principalRead,
			},
		} as unknown as ManagementStore;
		registerInternalCoordinatedExecutor(store, async (operation) =>
			operation({
				data: snapshot,
				principals: {
					authoritative: true,
					getById: mocks.coordinatedPrincipalRead,
				},
			} as never),
		);
		const context = { scope, actor: "operator", source: "cli" as const };

		await expect(
			unlockAuthenticationForManagement(store, context, {
				userId: principal.id,
				kind: "all",
				dryRun: true,
			}),
		).resolves.toMatchObject({ dryRun: true, result: { userId: principal.id } });
		await expect(
			unlockAuthenticationForManagement(store, context, {
				userId: principal.id,
				kind: "all",
				confirm: true,
			}),
		).resolves.toMatchObject({ dryRun: false, result: { changed: true } });

		expect(mocks.principalRead).toHaveBeenCalledTimes(2);
		expect(mocks.coordinatedPrincipalRead).toHaveBeenCalledWith({
			scope,
			id: principal.id,
		});
		expect(mocks.planUnlock).toHaveBeenCalledWith({
			userId: principal.id,
			kind: "all",
		});
		expect(mocks.unlock).toHaveBeenCalledWith(
			expect.objectContaining({ userId: principal.id, kind: "all" }),
		);

		const deletedPrincipalStore = {
			backend: "postgres",
			snapshot: { principals: [{ ...principal, status: "deleted" as const }] },
			mutateCoordinated: async () => {
				throw new Error("mutation should not start for a deleted principal");
			},
		} as unknown as ManagementStore;
		await expect(
			unlockAuthenticationForManagement(deletedPrincipalStore, context, {
				userId: principal.id,
				kind: "all",
				dryRun: true,
			}),
		).rejects.toMatchObject({ code: "AUTHENTICATION_POLICY_USER_NOT_FOUND" });
	});
});
