import type { GenericEndpointContext } from "@clearance/core";
import { getCurrentAdapter } from "@clearance/core/context";
import { base64Url } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";

export type PasskeyCeremony = "registration" | "authentication" | "deletion";

/** 2 minutes: short-lived, well within the 5-minute upper bound. */
export const CHALLENGE_TTL_SECONDS = 120;

const RAW_CLIENT_DATA_MAX_LENGTH = 8_000;
const DECODED_CLIENT_DATA_MAX_BYTES = 4_096;
const CHALLENGE_MAX_LENGTH = 512;

export interface ChallengeRecord {
	ceremony: PasskeyCeremony;
	rpID: string;
	origin: string;
	/** Present only for registration: the session user id that initiated it. */
	userId?: string;
	/** Present only for registration: the stable handle embedded as `user.id`. */
	userHandle?: string;
	/** Present only for deletion: the credential row selected for removal. */
	targetPasskeyId?: string;
}

/**
 * A bounded, defensive extraction of the `challenge` field from a WebAuthn
 * response's `clientDataJSON`. Rejects oversized input before decoding or
 * parsing, and returns `null` (never throws) for anything malformed so
 * callers can map every failure to the same generic error.
 */
export function parseClientDataChallenge(
	clientDataJSON: unknown,
): string | null {
	if (
		typeof clientDataJSON !== "string" ||
		clientDataJSON.length === 0 ||
		clientDataJSON.length > RAW_CLIENT_DATA_MAX_LENGTH
	) {
		return null;
	}
	let decodedBytes: Uint8Array;
	try {
		decodedBytes = base64Url.decode(clientDataJSON);
	} catch {
		return null;
	}
	if (decodedBytes.byteLength === 0 || decodedBytes.byteLength > DECODED_CLIENT_DATA_MAX_BYTES) {
		return null;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(new TextDecoder().decode(decodedBytes));
	} catch {
		return null;
	}
	if (typeof parsed !== "object" || parsed === null) {
		return null;
	}
	const challenge = (parsed as Record<string, unknown>).challenge;
	if (
		typeof challenge !== "string" ||
		challenge.length === 0 ||
		challenge.length > CHALLENGE_MAX_LENGTH
	) {
		return null;
	}
	return challenge;
}

/**
 * Derives the opaque, non-reversible storage identifier for a challenge: a
 * SHA-256 digest (base64url, no padding) of the ceremony-namespaced raw
 * challenge. This digest -- never the raw challenge itself -- is the only
 * value ever used as a database index key, a log line, or an error payload.
 * Namespacing by ceremony ensures a registration challenge can never be
 * consumed by the authentication verifier (or vice versa) even if the
 * underlying random challenge string were ever to collide.
 */
async function digestChallengeId(
	ceremony: PasskeyCeremony,
	challenge: string,
): Promise<string> {
	return createHash("SHA-256", "base64urlnopad").digest(
		`passkey:${ceremony}:${challenge}`,
	);
}

/**
 * Persists a single-use challenge to the plugin-owned primary database
 * `passkeyChallenge` model, independent of core `verification` storage or
 * any secondary storage configuration. This is mandatory for passkeys:
 * parallel tabs/ceremonies each mint their own row (no shared challenge
 * cookie), and the row is the sole source of truth for consumption. Only
 * the opaque digest is used as the unique index key; the raw challenge is
 * never persisted, logged, or echoed in an error.
 */
export async function createChallenge(
	ctx: GenericEndpointContext,
	ceremony: PasskeyCeremony,
	challenge: string,
	record: Omit<ChallengeRecord, "ceremony">,
): Promise<void> {
	const now = new Date();
	const digestId = await digestChallengeId(ceremony, challenge);
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	// Bound durable storage without a background worker. The indexed predicate
	// makes cleanup proportional to expired rows, and every new ceremony
	// eventually removes abandoned challenges that clients never return.
	await adapter.deleteMany({
		model: "passkeyChallenge",
		where: [{ field: "expiresAt", operator: "lt", value: now }],
	});
	await adapter.create({
		model: "passkeyChallenge",
		data: {
			digestId,
			ceremony,
			rpID: record.rpID,
			origin: record.origin,
			userId: record.userId,
			userHandle: record.userHandle,
			targetPasskeyId: record.targetPasskeyId,
			expiresAt: new Date(now.getTime() + CHALLENGE_TTL_SECONDS * 1000),
			createdAt: now,
			updatedAt: now,
		},
	});
}

/**
 * Atomically consumes (deletes-and-returns) the matching challenge row from
 * the plugin-owned primary database table *before* any cryptographic
 * verification is attempted, so a concurrently or later replayed response
 * can never reuse it. Consumption is looked up exclusively by the opaque
 * digest derived from the parsed challenge; the row is fetched and deleted
 * in a single atomic `consumeOne` call -- there is no find-then-delete
 * sequence and no fallback path. The caller is expected to have already
 * derived `challenge` via {@link parseClientDataChallenge}. Returns `null`
 * for any failure (unknown/expired/already-consumed challenge, or a
 * challenge minted by the other ceremony) so callers can respond with one
 * generic, redacted error.
 */
export async function consumeChallengeByParsedChallenge(
	ctx: GenericEndpointContext,
	ceremony: PasskeyCeremony,
	challenge: string,
): Promise<ChallengeRecord | null> {
	const digestId = await digestChallengeId(ceremony, challenge);
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const consumed = await adapter.consumeOne<{
		ceremony: string;
		rpID: string;
		origin: string;
		userId?: string | null;
		userHandle?: string | null;
		targetPasskeyId?: string | null;
		expiresAt: Date;
	}>({
		model: "passkeyChallenge",
		where: [{ field: "digestId", value: digestId }],
	});
	if (!consumed) {
		return null;
	}
	if (new Date(consumed.expiresAt).getTime() < Date.now()) {
		return null;
	}
	if (
		consumed.ceremony !== ceremony ||
		typeof consumed.rpID !== "string" ||
		typeof consumed.origin !== "string"
	) {
		return null;
	}
	return {
		ceremony,
		rpID: consumed.rpID,
		origin: consumed.origin,
		userId: consumed.userId ?? undefined,
		userHandle: consumed.userHandle ?? undefined,
		targetPasskeyId: consumed.targetPasskeyId ?? undefined,
	} satisfies ChallengeRecord;
}
