import type { GenericEndpointContext } from "@clearance/core";
import { base64Url } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";
import { runManagedAuthenticationTransaction } from "../../internal/managed-authentication-transaction";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "../../internal/verification-challenge-context";
import type { Session } from "../../types";

export const TWO_FACTOR_CHALLENGE_PURPOSE = {
	signIn: "two-factor.sign-in",
	attemptBudget: "two-factor.attempt-budget",
	otp: "two-factor.otp",
	trustDevice: "two-factor.trust-device",
	trustGeneration: "two-factor.trust-generation",
} as const;

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
	const identifier = trustGenerationMarkerIdentifier(userId, generation);
	await createInternalVerificationChallenge(
		ctx.context.internalAdapter,
		{
			purpose: TWO_FACTOR_CHALLENGE_PURPOSE.trustGeneration,
			subject: userId,
		},
		{
			identifier,
			value: `${userId}!${generation}`,
			expiresAt,
		},
	);
}

export async function revokeTrustGeneration(
	ctx: GenericEndpointContext,
	userId: string,
	generation: string | null | undefined,
): Promise<void> {
	if (!generation) return;
	const identifier = trustGenerationMarkerIdentifier(userId, generation);
	await runManagedAuthenticationTransaction(ctx, () =>
		consumeInternalVerificationChallenge(ctx.context.internalAdapter, {
			purpose: TWO_FACTOR_CHALLENGE_PURPOSE.trustGeneration,
			subject: userId,
			identifier,
		}),
	);
}

export function preserveSessionLifetime(
	session: Session & Record<string, unknown>,
): Session & Record<string, unknown> {
	return { ...session, __preserveSessionExpiresAt: true };
}
