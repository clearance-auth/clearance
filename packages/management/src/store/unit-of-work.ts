import type { DataStoreSnapshot } from "../types/resources.js";
import type {
	ManagementStore,
	ManagementUnitOfWork,
} from "./types.js";

function draftUnitOfWork(snapshot: DataStoreSnapshot): ManagementUnitOfWork {
	return {
		get snapshot() {
			return snapshot;
		},
		mutate(mutator) {
			mutator(snapshot);
			return snapshot;
		},
	};
}

/**
 * Execute one synchronous domain transition against the latest durable draft.
 * JsonStore commits its cloned draft atomically; PgStore replays the same
 * transition under its row lock and resolves only after commit.
 */
export function withManagementUnitOfWork<T>(
	store: ManagementStore,
	transition: (unitOfWork: ManagementUnitOfWork) => T,
): Promise<T> {
	return store.mutateDurable((snapshot) => {
		const result = transition(draftUnitOfWork(snapshot));
		if (
			typeof result === "object" &&
			result !== null &&
			"then" in result
		) {
			throw new TypeError("Management unit-of-work transitions must be synchronous");
		}
		return result;
	});
}
