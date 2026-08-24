import type { Awaitable, GenericEndpointContext } from "@clearance/core";
import { ClearanceError } from "@clearance/core/error";
import { exportJWK, generateKeyPair } from "jose";
import { symmetricEncrypt } from "../../crypto";
import type { TimeString } from "../../utils/time";
import { sec } from "../../utils/time";
import { getJwksAdapter } from "./adapter";
import type { Jwk, JwtOptions, JwtPrivateKeyStorage } from "./types";

export function getPrivateKeyStorage(options?: JwtOptions | undefined) {
	const jwksOptions = options?.jwks;
	if (
		jwksOptions?.privateKeyStorage &&
		jwksOptions.disablePrivateKeyEncryption
	) {
		throw new ClearanceError(
			"jwks.privateKeyStorage cannot be combined with jwks.disablePrivateKeyEncryption",
		);
	}
	return jwksOptions?.privateKeyStorage;
}

async function invokePrivateKeyStorage(
	operation: () => Awaitable<string>,
	failureMessage: string,
) {
	try {
		const privateKey = await operation();
		if (typeof privateKey !== "string") {
			throw new Error("Private key storage returned a non-string value");
		}
		return privateKey;
	} catch {
		throw new ClearanceError(failureMessage);
	}
}

export async function encryptPrivateJwk(
	storage: JwtPrivateKeyStorage,
	privateKey: string,
	publicKey: string,
) {
	return invokePrivateKeyStorage(
		() => storage.encrypt(privateKey, publicKey),
		"Failed to encrypt private key with configured private key storage",
	);
}

export async function decryptPrivateJwk(
	storage: JwtPrivateKeyStorage,
	encryptedPrivateKey: string,
	publicKey: string,
) {
	return invokePrivateKeyStorage(
		() => storage.decrypt(encryptedPrivateKey, publicKey),
		"Failed to decrypt private key with configured private key storage",
	);
}

/**
 * Converts an expirationTime to ISO seconds expiration time (the format of JWT exp)
 *
 * See https://github.com/panva/jose/blob/main/src/lib/jwt_claims_set.ts#L245
 *
 * @param expirationTime - see options.jwt.expirationTime
 * @param iat - the iat time to consolidate on
 * @returns
 */
export function toExpJWT(
	expirationTime: number | Date | string,
	iat: number,
): number {
	if (typeof expirationTime === "number") {
		return expirationTime;
	} else if (expirationTime instanceof Date) {
		return Math.floor(expirationTime.getTime() / 1000);
	} else {
		return iat + sec(expirationTime as TimeString);
	}
}

export async function generateExportedKeyPair(
	options?: JwtOptions | undefined,
) {
	const { alg, ...cfg } = options?.jwks?.keyPairConfig ?? {
		alg: "EdDSA",
		crv: "Ed25519",
	};
	const { publicKey, privateKey } = await generateKeyPair(alg, {
		...cfg,
		extractable: true,
	});

	const publicWebKey = await exportJWK(publicKey);
	const privateWebKey = await exportJWK(privateKey);

	return { publicWebKey, privateWebKey, alg, cfg };
}

/**
 * Creates a Jwk on the database
 *
 * @param ctx
 * @param options
 * @returns
 */
export async function createJwk(
	ctx: GenericEndpointContext,
	options?: JwtOptions | undefined,
) {
	const { publicWebKey, privateWebKey, alg, cfg } =
		await generateExportedKeyPair(options);

	const stringifiedPrivateWebKey = JSON.stringify(privateWebKey);
	const publicKey = JSON.stringify(publicWebKey);
	const privateKeyStorage = getPrivateKeyStorage(options);
	const privateKeyEncryptionEnabled =
		!options?.jwks?.disablePrivateKeyEncryption;
	const jwk: Omit<Jwk, "id"> = {
		alg,
		...(cfg && "crv" in cfg
			? {
					crv: (cfg as { crv: (typeof jwk)["crv"] }).crv,
				}
			: {}),
		publicKey,
		privateKey: privateKeyStorage
			? await encryptPrivateJwk(
					privateKeyStorage,
					stringifiedPrivateWebKey,
					publicKey,
				)
			: privateKeyEncryptionEnabled
			? JSON.stringify(
					await symmetricEncrypt({
						key: ctx.context.secretConfig,
						data: stringifiedPrivateWebKey,
					}),
				)
			: stringifiedPrivateWebKey,
		createdAt: new Date(),
		...(options?.jwks?.rotationInterval
			? {
					expiresAt: new Date(
						Date.now() + options.jwks.rotationInterval * 1000,
					),
				}
			: {}),
	};

	const adapter = getJwksAdapter(ctx.context.adapter, options);
	const key = await adapter.createJwk(ctx, jwk as Jwk);

	return key;
}
