import { base64Url } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";

/**
 * Default client secret hasher using SHA-256
 */
export const defaultClientSecretHasher = async (clientSecret: string) => {
	const hash = await createHash("SHA-256").digest(
		new TextEncoder().encode(clientSecret),
	);
	const hashed = base64Url.encode(new Uint8Array(hash), {
		padding: false,
	});
	return hashed;
};
