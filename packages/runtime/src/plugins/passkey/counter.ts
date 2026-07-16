import type { DBTransactionAdapter } from "@clearance/core/db/adapter";

/**
 * Guarded compare-and-swap for a WebAuthn signature counter: only the caller
 * that still observes `observedCounter` on the row may advance it to
 * `newCounter`. A concurrent racer that read the same `observedCounter`
 * before either write commits loses this guard once the first writer
 * commits, so exactly one caller among any set of concurrent callers
 * observing the same nonzero counter value wins.
 *
 * Both-zero credentials (multi-device/backed-up credentials that never
 * advance their counter) trivially satisfy the guard on every call, which is
 * the WebAuthn-allowed case: single-use challenge consumption elsewhere is
 * what prevents replay of any one assertion, not the counter.
 *
 * Non-monotonic transitions (`newCounter < observedCounter`, or
 * `newCounter === observedCounter` for a nonzero counter) are rejected before
 * any database access -- the sole exception is the exact `0 -> 0` transition.
 * The same guarded write handles that exception, so row existence and the
 * zero-counter predicate remain authoritative inside the transaction.
 */
export async function advancePasskeyCounter(
	adapter: DBTransactionAdapter<any>,
	passkeyId: string,
	observedCounter: number,
	newCounter: number,
): Promise<boolean> {
	if (observedCounter < 0 || newCounter < observedCounter) {
		return false;
	}
	if (newCounter === observedCounter && observedCounter !== 0) {
		return false;
	}
	// The guarded write also handles the permitted 0 -> 0 case, preserving
	// row existence and locking through the surrounding issuance transaction.
	const result = await adapter.incrementOne({
		model: "passkey",
		where: [
			{ field: "id", value: passkeyId },
			{ field: "counter", value: observedCounter },
		],
		increment: {},
		set: { counter: newCounter },
	});
	return result !== null;
}
