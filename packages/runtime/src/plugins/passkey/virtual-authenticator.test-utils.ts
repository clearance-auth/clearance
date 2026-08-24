import {
	createHash,
	generateKeyPairSync,
	randomBytes,
	sign as signBytes,
} from "node:crypto";
import { base64Url } from "@clearance/utils/base64";
import { isoCBOR } from "@simplewebauthn/server/helpers";

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
	return Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
}

function uint16(value: number): Uint8Array {
	const result = Buffer.alloc(2);
	result.writeUInt16BE(value);
	return new Uint8Array(result);
}

function uint32(value: number): Uint8Array {
	const result = Buffer.alloc(4);
	result.writeUInt32BE(value);
	return new Uint8Array(result);
}

function sha256(value: string | Uint8Array): Uint8Array<ArrayBuffer> {
	return Uint8Array.from(createHash("sha256").update(value).digest());
}

function encodeClientData(
	origin: string,
	type: "webauthn.create" | "webauthn.get",
	challenge: string,
) {
	const bytes = new TextEncoder().encode(
		JSON.stringify({ type, challenge, origin, crossOrigin: false }),
	);
	return {
		bytes,
		encoded: base64Url.encode(bytes, { padding: false }),
	};
}

export function createVirtualAuthenticator(origin: string, rpID: string) {
	const { publicKey, privateKey } = generateKeyPairSync("ec", {
		namedCurve: "prime256v1",
	});
	const jwk = publicKey.export({ format: "jwk" });
	if (!jwk.x || !jwk.y) {
		throw new Error("Virtual authenticator did not export an EC public key");
	}
	const credentialID = new Uint8Array(randomBytes(32));
	const credentialPublicKey = new Uint8Array(
		isoCBOR.encode(
			new Map<number, unknown>([
				[1, 2],
				[3, -7],
				[-1, 1],
				[-2, base64Url.decode(jwk.x)],
				[-3, base64Url.decode(jwk.y)],
			]) as Parameters<typeof isoCBOR.encode>[0],
		),
	);
	const credentialIDString = base64Url.encode(credentialID, { padding: false });

	return {
		credentialID,
		credentialIDString,
		registrationResponse(
			challenge: string,
			options?: { userVerified?: boolean } | undefined,
		) {
			const authData = concat(
				sha256(rpID),
				new Uint8Array([options?.userVerified === false ? 0x41 : 0x45]),
				// 0x41 = UP + attested credential data; 0x45 also includes UV.
				uint32(0),
				new Uint8Array(16), // AAGUID
				uint16(credentialID.byteLength),
				credentialID,
				credentialPublicKey,
			);
			const attestationObject = new Uint8Array(
				isoCBOR.encode(
					new Map<string, unknown>([
						["fmt", "none"],
						["attStmt", new Map()],
						["authData", authData],
					]) as Parameters<typeof isoCBOR.encode>[0],
				),
			);
			return {
				id: credentialIDString,
				rawId: credentialIDString,
				type: "public-key" as const,
				clientExtensionResults: {},
				authenticatorAttachment: "platform" as const,
				response: {
					clientDataJSON: encodeClientData(
						origin,
						"webauthn.create",
						challenge,
					).encoded,
					attestationObject: base64Url.encode(attestationObject, {
						padding: false,
					}),
					transports: ["internal" as const],
				},
			};
		},
		authenticationResponse(
			challenge: string,
			userHandle: string,
			counter: number,
			options?: { userVerified?: boolean } | undefined,
		) {
			const authData = concat(
				sha256(rpID),
				new Uint8Array([options?.userVerified === false ? 0x01 : 0x05]),
				// 0x01 = UP only; 0x05 also includes UV.
				uint32(counter),
			);
			const clientData = encodeClientData(origin, "webauthn.get", challenge);
			const signedData = concat(authData, sha256(clientData.bytes));
			const signature = signBytes("sha256", Buffer.from(signedData), {
				key: privateKey,
				dsaEncoding: "der",
			});
			return {
				id: credentialIDString,
				rawId: credentialIDString,
				type: "public-key" as const,
				clientExtensionResults: {},
				authenticatorAttachment: "platform" as const,
				response: {
					clientDataJSON: clientData.encoded,
					authenticatorData: base64Url.encode(authData, { padding: false }),
					signature: base64Url.encode(signature, { padding: false }),
					userHandle,
				},
			};
		},
	};
}
