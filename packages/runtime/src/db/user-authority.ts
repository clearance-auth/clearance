import type { User } from "@clearance/core/db";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";

/**
 * Serialize credential issuance with user disable/delete mutations.
 *
 * Callers must already be inside `runWithTransaction`. The same-value write
 * acquires the user row/document write lock without changing public identity
 * metadata. Re-reading on the same transaction makes a disable that won the
 * lock visible before any new bearer authority is created.
 */
export async function lockAndReadUser(
	adapter: DBTransactionAdapter,
	userId: string,
): Promise<(User & { banned?: boolean | null }) | null> {
	const candidate = await adapter.findOne<User>({
		model: "user",
		where: [{ field: "id", value: userId }],
	});
	if (!candidate) return null;

	await adapter.update<User>({
		model: "user",
		where: [{ field: "id", value: userId }],
		update: { createdAt: candidate.createdAt },
	});
	return adapter.findOne<User & { banned?: boolean | null }>({
		model: "user",
		where: [{ field: "id", value: userId }],
	});
}

export async function lockAndReadActiveUser(
	adapter: DBTransactionAdapter,
	userId: string,
): Promise<(User & { banned?: boolean | null }) | null> {
	const locked = await lockAndReadUser(adapter, userId);
	return locked && locked.banned !== true ? locked : null;
}
