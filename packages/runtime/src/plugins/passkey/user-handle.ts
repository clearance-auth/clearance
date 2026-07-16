import type { GenericEndpointContext } from "@clearance/core";
import { base64Url } from "@clearance/utils/base64";

const USER_HANDLE_FIELD = "passkeyUserHandle";
const USER_HANDLE_BYTE_LENGTH = 32;

/**
 * The single canonical representation of a WebAuthn user handle used
 * everywhere: generated here, stored on the user record, embedded as the
 * WebAuthn `user.id` at registration (after decoding back to raw bytes via
 * {@link decodeCanonicalUserHandle}), and compared byte-for-byte against an
 * authentication assertion's `response.userHandle` (which browsers/libraries
 * also present as base64url) without any re-encoding on either side.
 */
function generateCanonicalUserHandle(): string {
	const bytes = new Uint8Array(USER_HANDLE_BYTE_LENGTH);
	crypto.getRandomValues(bytes);
	return base64Url.encode(bytes, { padding: false });
}

/**
 * Decodes the canonical base64url user handle back to the raw bytes required
 * by `generateRegistrationOptions`'s `userID` parameter. Callers must never
 * pass a differently-encoded (e.g. raw UTF-8 `TextEncoder`) representation of
 * the handle: doing so would desynchronize the WebAuthn credential's
 * `user.id` bytes from the canonical string compared at authentication time.
 */
export function decodeCanonicalUserHandle(handle: string): Uint8Array {
	return base64Url.decode(handle);
}

/**
 * Returns the stable, random, canonical (base64url, no padding) WebAuthn
 * user handle bound to `userId`, initializing it on first use.
 *
 * Concurrent first-enrollment races are resolved with a null-guarded
 * compare-and-swap (`incrementOne` with `passkeyUserHandle: null` as part of
 * the guard): exactly one caller's proposed handle is persisted, and every
 * other concurrent caller re-reads the winning value instead of persisting
 * its own. This mirrors the two-factor session-generation initialization
 * pattern in the internal adapter.
 */
export async function ensurePasskeyUserHandle(
	ctx: GenericEndpointContext,
	userId: string,
): Promise<string> {
	const existing = await ctx.context.adapter.findOne<{
		passkeyUserHandle?: string | null;
	}>({
		model: "user",
		where: [{ field: "id", value: userId }],
		select: [USER_HANDLE_FIELD],
	});
	if (typeof existing?.passkeyUserHandle === "string" && existing.passkeyUserHandle) {
		return existing.passkeyUserHandle;
	}

	const proposed = generateCanonicalUserHandle();
	const initialized = await ctx.context.adapter.incrementOne<{
		passkeyUserHandle?: string | null;
	}>({
		model: "user",
		where: [
			{ field: "id", value: userId },
			{ field: USER_HANDLE_FIELD, value: null },
		],
		increment: {},
		set: { [USER_HANDLE_FIELD]: proposed },
	});
	if (initialized?.passkeyUserHandle) {
		return initialized.passkeyUserHandle;
	}

	// Someone else initialized it concurrently; re-read the winning value.
	const winner = await ctx.context.adapter.findOne<{
		passkeyUserHandle?: string | null;
	}>({
		model: "user",
		where: [{ field: "id", value: userId }],
		select: [USER_HANDLE_FIELD],
	});
	if (typeof winner?.passkeyUserHandle === "string" && winner.passkeyUserHandle) {
		return winner.passkeyUserHandle;
	}

	// Guard failed and re-read still found nothing: extremely unlikely, but
	// fail closed rather than return an unstable value.
	throw new Error("Failed to initialize a stable passkey user handle");
}
