import { base64Url } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";
import type { GenericEndpointContext } from "@clearance/runtime";
import {
	constantTimeEqual,
	symmetricDecrypt,
	symmetricEncrypt,
} from "@clearance/runtime/crypto";
import type { SCIMOptions, SCIMTokenStorageContext } from "./types";

const MAX_STORAGE_CONTEXT_ID_CHARACTERS = 512;

function validateStorageContextId(value: string, name: string): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_STORAGE_CONTEXT_ID_CHARACTERS ||
		value.trim() !== value ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		throw new Error(`SCIM token storage ${name} is invalid`);
	}
	return value;
}

/**
 * Validates and freezes the exact storage context before a custom provider is
 * called. Keep this narrow: it is an authenticated identity, not a transport
 * payload.
 */
export function createSCIMTokenStorageContext(
	context: SCIMTokenStorageContext,
): SCIMTokenStorageContext {
	const providerId = validateStorageContextId(context.providerId, "providerId");
	const organizationId =
		context.organizationId === undefined
			? undefined
			: validateStorageContextId(context.organizationId, "organizationId");
	return Object.freeze(
		organizationId === undefined ? { providerId } : { providerId, organizationId },
	);
}

const defaultKeyHasher = async (token: string) => {
	const hash = await createHash("SHA-256").digest(
		new TextEncoder().encode(token),
	);
	return base64Url.encode(new Uint8Array(hash), { padding: false });
};

export async function storeSCIMToken(
	ctx: GenericEndpointContext,
	opts: SCIMOptions,
	scimToken: string,
	storageContext: SCIMTokenStorageContext,
) {
	if (opts.storeSCIMToken === "encrypted") {
		return await symmetricEncrypt({
			key: ctx.context.secretConfig,
			data: scimToken,
		});
	}
	if (opts.storeSCIMToken === "hashed") {
		return await defaultKeyHasher(scimToken);
	}
	if (
		typeof opts.storeSCIMToken === "object" &&
		"hash" in opts.storeSCIMToken
	) {
		return await opts.storeSCIMToken.hash(scimToken);
	}
	if (
		typeof opts.storeSCIMToken === "object" &&
		"encrypt" in opts.storeSCIMToken
	) {
		return await opts.storeSCIMToken.encrypt(
			scimToken,
			createSCIMTokenStorageContext(storageContext),
		);
	}

	return scimToken;
}

export async function verifySCIMToken(
	ctx: GenericEndpointContext,
	opts: SCIMOptions,
	storedSCIMToken: string,
	scimToken: string,
	storageContext: SCIMTokenStorageContext,
): Promise<boolean> {
	if (opts.storeSCIMToken === "encrypted") {
		return constantTimeEqual(
			await symmetricDecrypt({
				key: ctx.context.secretConfig,
				data: storedSCIMToken,
			}),
			scimToken,
		);
	}
	if (opts.storeSCIMToken === "hashed") {
		const hashedSCIMToken = await defaultKeyHasher(scimToken);
		return constantTimeEqual(hashedSCIMToken, storedSCIMToken);
	}
	if (
		typeof opts.storeSCIMToken === "object" &&
		"hash" in opts.storeSCIMToken
	) {
		const hashedSCIMToken = await opts.storeSCIMToken.hash(scimToken);
		return constantTimeEqual(hashedSCIMToken, storedSCIMToken);
	}
	if (
		typeof opts.storeSCIMToken === "object" &&
		"decrypt" in opts.storeSCIMToken
	) {
		const decryptedSCIMToken = await opts.storeSCIMToken.decrypt(
			storedSCIMToken,
			createSCIMTokenStorageContext(storageContext),
		);
		return constantTimeEqual(decryptedSCIMToken, scimToken);
	}

	return constantTimeEqual(scimToken, storedSCIMToken);
}
