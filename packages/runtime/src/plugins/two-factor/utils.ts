import { base64Url } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";

export const defaultKeyHasher = async (token: string) => {
	const hash = await createHash("SHA-256").digest(
		new TextEncoder().encode(token),
	);
	const hashed = base64Url.encode(new Uint8Array(hash), {
		padding: false,
	});
	return hashed;
};
