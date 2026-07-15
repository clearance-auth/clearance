import type { GenericEndpointContext } from "@clearance/core";
import { base64Url } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";
import type { Session } from "../../types";

export const defaultKeyHasher = async (token: string) => {
	const hash = await createHash("SHA-256").digest(
		new TextEncoder().encode(token),
	);
	const hashed = base64Url.encode(new Uint8Array(hash), {
		padding: false,
	});
	return hashed;
};

export const trustGenerationMarkerIdentifier = (
	userId: string,
	generation: string,
) => `trust-device-generation-${userId}-${generation}`;

export async function recordTrustGeneration(
	ctx: GenericEndpointContext,
	userId: string,
	generation: string,
	expiresAt: Date,
): Promise<void> {
	await ctx.context.internalAdapter.createVerificationValue({
		identifier: trustGenerationMarkerIdentifier(userId, generation),
		value: `${userId}!${generation}`,
		expiresAt,
	});
}

export async function revokeTrustGeneration(
	ctx: GenericEndpointContext,
	userId: string,
	generation: string | null | undefined,
): Promise<void> {
	if (!generation) return;
	await ctx.context.internalAdapter
		.consumeVerificationValue(
			trustGenerationMarkerIdentifier(userId, generation),
		)
		.catch(() => null);
}

export function preserveSessionLifetime(
	session: Session & Record<string, unknown>,
): Session & Record<string, unknown> {
	return { ...session, __preserveSessionExpiresAt: true };
}
