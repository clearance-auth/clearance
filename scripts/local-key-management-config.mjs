import { createECDH, createHmac, createPrivateKey } from "node:crypto";

const credentialKey = process.env.CLEARANCE_CREDENTIAL_KEY?.trim();
const keyId = process.env.CLEARANCE_CREDENTIAL_KEY_ID?.trim();

if (!credentialKey || !keyId) {
	throw new Error(
		"CLEARANCE_CREDENTIAL_KEY and CLEARANCE_CREDENTIAL_KEY_ID are required to derive local key management configuration",
	);
}

const root = Buffer.from(credentialKey, "utf8");
const derive = (label) => createHmac("sha256", root)
	.update(`clearance-local-key-management:${label}`)
	.digest("base64url");

function signingKey() {
	for (let counter = 0; counter < 32; counter += 1) {
		const privateBytes = createHmac("sha256", root)
			.update(`clearance-local-key-management:access-token-signer:${counter}`)
			.digest();
		try {
			const ecdh = createECDH("prime256v1");
			ecdh.setPrivateKey(privateBytes);
			const publicKey = ecdh.getPublicKey();
			const privateKey = createPrivateKey({
				key: {
					kty: "EC",
					crv: "P-256",
					d: privateBytes.toString("base64url"),
					x: publicKey.subarray(1, 33).toString("base64url"),
					y: publicKey.subarray(33, 65).toString("base64url"),
				},
				format: "jwk",
			});
			return privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url");
		} catch {
			// Try the next deterministic candidate if this scalar is invalid.
		}
	}
	throw new Error("Could not derive a local ES256 signing key");
}

const encryption = (purpose) => ({
	kind: "local",
	providerId: `local-${purpose}`,
	currentKeyId: keyId,
	keys: { [keyId]: derive(purpose) },
});

process.stdout.write(JSON.stringify({
	"oidc-client-secret": encryption("oidc-client-secret"),
	"scim-bearer-token": encryption("scim-bearer-token"),
	"service-account-credential-replay": encryption("service-account-credential-replay"),
	"access-token-signing-key": encryption("access-token-signing-key"),
	"access-token-signer": {
		kind: "local",
		providerId: "local-access-token-signer",
		currentKeyReference: keyId,
		keys: { [keyId]: signingKey() },
	},
}));
