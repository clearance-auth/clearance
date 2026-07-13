import { base64 } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";

export async function hashToBase64(
	data: string | ArrayBuffer,
): Promise<string> {
	const buffer = await createHash("SHA-256").digest(data);
	return base64.encode(buffer);
}
