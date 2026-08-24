type JsonRecord = Record<string, unknown>;

const MAX_BASE64URL_LENGTH = 16_384;
const MAX_TEXT_LENGTH = 1_024;
const MAX_TIMEOUT = 600_000;

type VaultPrfValues = Readonly<{ first: string; second?: string }>;

/** The closed JSON-safe WebAuthn extension subset accepted from Clearance. */
export type VaultWebAuthnExtensions = Readonly<{
	appid?: string;
	credProps?: boolean;
	credentialProtectionPolicy?:
		| "userVerificationOptional"
		| "userVerificationOptionalWithCredentialIDList"
		| "userVerificationRequired";
	enforceCredentialProtectionPolicy?: boolean;
	hmacCreateSecret?: boolean;
	largeBlob?: Readonly<{
		read?: boolean;
		support?: "preferred" | "required";
		write?: string;
	}>;
	minPinLength?: boolean;
	prf?: Readonly<{
		eval?: VaultPrfValues;
		evalByCredential?: Readonly<Record<string, VaultPrfValues>>;
	}>;
}>;

export type VaultWebAuthnExtensionResults = Readonly<{
	appid?: boolean;
	credProps?: Readonly<{ rk?: boolean }>;
	hmacCreateSecret?: boolean;
	largeBlob?: Readonly<{ blob?: string; supported?: boolean; written?: boolean }>;
	prf?: Readonly<{
		enabled?: boolean;
		results?: Readonly<{ first: string; second?: string }>;
	}>;
}>;

export type VaultRegistrationOptions = Readonly<{
	challenge: string;
	rp: Readonly<{ id: string; name: string }>;
	user: Readonly<{ id: string; name: string; displayName: string }>;
	pubKeyCredParams: readonly Readonly<{ alg: number; type: "public-key" }>[];
	timeout: number;
	excludeCredentials?: readonly Readonly<{
		id: string;
		type: "public-key";
		transports?: readonly AuthenticatorTransport[];
	}>[];
	authenticatorSelection: Readonly<{
		authenticatorAttachment?: "platform" | "cross-platform";
		residentKey: "required";
		requireResidentKey: true;
		userVerification: "required";
	}>;
	attestation: "none";
	extensions?: VaultWebAuthnExtensions;
}>;

export type VaultDeletionOptions = Readonly<{
	challenge: string;
	rpId: string;
	timeout: number;
	allowCredentials: readonly [
		Readonly<{
			id: string;
			type: "public-key";
			transports?: readonly AuthenticatorTransport[];
		}>,
		...Readonly<{
			id: string;
			type: "public-key";
			transports?: readonly AuthenticatorTransport[];
		}>[],
	];
	userVerification: "required";
	extensions?: VaultWebAuthnExtensions;
}>;
export type VaultAuthenticationOptions = Readonly<{
	challenge: string; rpId: string; timeout: number; userVerification: "required";
	extensions?: VaultWebAuthnExtensions;
}>;

export function parseAuthenticationOptions(value: unknown): VaultAuthenticationOptions {
	const input = exactRecord(value, "passkey authentication options", ["challenge", "rpId", "timeout", "userVerification", "extensions"]);
	if (input.userVerification !== "required") throw new TypeError("Vault received invalid passkey authentication options");
	const extensions = input.extensions === undefined ? undefined : parseExtensions(input.extensions, "passkey authentication extensions");
	return Object.freeze({
		challenge: base64url(input.challenge, "passkey authentication challenge"),
		rpId: text(input.rpId, "passkey authentication rp id"),
		timeout: timeout(input.timeout, "passkey authentication timeout"),
		userVerification: "required",
		...(extensions === undefined ? {} : { extensions }),
	});
}

export type VaultRegistrationResponse = Readonly<{
	id: string;
	rawId: string;
	type: "public-key";
	clientExtensionResults: VaultWebAuthnExtensionResults;
	authenticatorAttachment?: "platform" | "cross-platform";
	response: Readonly<{
		clientDataJSON: string;
		attestationObject: string;
		authenticatorData?: string;
		transports: readonly AuthenticatorTransport[];
		publicKeyAlgorithm?: number;
		publicKey?: string;
	}>;
}>;

export type VaultAuthenticationResponse = Readonly<{
	id: string;
	rawId: string;
	type: "public-key";
	clientExtensionResults: VaultWebAuthnExtensionResults;
	authenticatorAttachment?: "platform" | "cross-platform";
	response: Readonly<{
		clientDataJSON: string;
		authenticatorData: string;
		signature: string;
		userHandle?: string;
	}>;
}>;

function record(value: unknown, label: string): JsonRecord {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new TypeError(`Vault received invalid ${label}`);
	}
	const output: JsonRecord = {};
	for (const [key, entry] of Object.entries(value)) output[key] = entry;
	return output;
}

function exactRecord(
	value: unknown,
	label: string,
	allowed: readonly string[],
): JsonRecord {
	const input = record(value, label);
	for (const key of Object.keys(input)) {
		if (!allowed.includes(key)) {
			throw new TypeError(`Vault received invalid ${label}`);
		}
	}
	return input;
}

function text(value: unknown, label: string, maximum = MAX_TEXT_LENGTH): string {
	if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
		throw new TypeError(`Vault received invalid ${label}`);
	}
	return value;
}

function base64url(value: unknown, label: string): string {
	const encoded = text(value, label, MAX_BASE64URL_LENGTH);
	if (!/^[A-Za-z0-9_-]+$/.test(encoded)) {
		throw new TypeError(`Vault received invalid ${label}`);
	}
	return encoded;
}

function optionalBoolean(value: unknown, label: string): boolean | undefined {
	if (value === undefined) return undefined;
	if (typeof value !== "boolean") throw new TypeError(`Vault received invalid ${label}`);
	return value;
}

function parsePrfValues(value: unknown, label: string): VaultPrfValues {
	const input = exactRecord(value, label, ["first", "second"]);
	return Object.freeze({
		first: base64url(input.first, `${label}.first`),
		...(input.second === undefined ? {} : { second: base64url(input.second, `${label}.second`) }),
	});
}

function parseExtensions(value: unknown, label: string): VaultWebAuthnExtensions {
	const input = exactRecord(value, label, [
		"appid",
		"credProps",
		"credentialProtectionPolicy",
		"enforceCredentialProtectionPolicy",
		"hmacCreateSecret",
		"largeBlob",
		"minPinLength",
		"prf",
	]);
	const credentialProtectionPolicy: VaultWebAuthnExtensions["credentialProtectionPolicy"] = input.credentialProtectionPolicy === undefined
		? undefined
		: input.credentialProtectionPolicy === "userVerificationOptional" ||
			input.credentialProtectionPolicy === "userVerificationOptionalWithCredentialIDList" ||
			input.credentialProtectionPolicy === "userVerificationRequired"
			? input.credentialProtectionPolicy
			: (() => { throw new TypeError(`Vault received invalid ${label}`); })();
	const largeBlob = input.largeBlob === undefined ? undefined : (() => {
		const largeBlobInput = exactRecord(input.largeBlob, `${label}.largeBlob`, ["read", "support", "write"]);
		const support = largeBlobInput.support === undefined
			? undefined
			: largeBlobInput.support === "preferred" || largeBlobInput.support === "required"
				? largeBlobInput.support
				: (() => { throw new TypeError(`Vault received invalid ${label}.largeBlob`); })();
		return Object.freeze({
			...(optionalBoolean(largeBlobInput.read, `${label}.largeBlob.read`) === undefined
				? {}
				: { read: optionalBoolean(largeBlobInput.read, `${label}.largeBlob.read`) }),
			...(support === undefined ? {} : { support }),
			...(largeBlobInput.write === undefined ? {} : { write: base64url(largeBlobInput.write, `${label}.largeBlob.write`) }),
		});
	})();
	const prf = input.prf === undefined ? undefined : (() => {
		const prfInput = exactRecord(input.prf, `${label}.prf`, ["eval", "evalByCredential"]);
		const evalByCredential = prfInput.evalByCredential === undefined ? undefined : (() => {
			const entries = record(prfInput.evalByCredential, `${label}.prf.evalByCredential`);
			if (Object.keys(entries).length > 64) throw new TypeError(`Vault received invalid ${label}.prf.evalByCredential`);
			return Object.freeze(Object.fromEntries(Object.entries(entries).map(([credentialId, values]) => [
				base64url(credentialId, `${label}.prf credential id`),
				parsePrfValues(values, `${label}.prf value`),
			])));
		})();
		if (prfInput.eval === undefined && evalByCredential === undefined) {
			throw new TypeError(`Vault received invalid ${label}.prf`);
		}
		return Object.freeze({
			...(prfInput.eval === undefined ? {} : { eval: parsePrfValues(prfInput.eval, `${label}.prf.eval`) }),
			...(evalByCredential === undefined ? {} : { evalByCredential }),
		});
	})();
	const output = {
		...(input.appid === undefined ? {} : { appid: text(input.appid, `${label}.appid`, 2_048) }),
		...(optionalBoolean(input.credProps, `${label}.credProps`) === undefined ? {} : { credProps: optionalBoolean(input.credProps, `${label}.credProps`) }),
		...(credentialProtectionPolicy === undefined ? {} : { credentialProtectionPolicy }),
		...(optionalBoolean(input.enforceCredentialProtectionPolicy, `${label}.enforceCredentialProtectionPolicy`) === undefined ? {} : { enforceCredentialProtectionPolicy: optionalBoolean(input.enforceCredentialProtectionPolicy, `${label}.enforceCredentialProtectionPolicy`) }),
		...(optionalBoolean(input.hmacCreateSecret, `${label}.hmacCreateSecret`) === undefined ? {} : { hmacCreateSecret: optionalBoolean(input.hmacCreateSecret, `${label}.hmacCreateSecret`) }),
		...(largeBlob === undefined ? {} : { largeBlob }),
		...(optionalBoolean(input.minPinLength, `${label}.minPinLength`) === undefined ? {} : { minPinLength: optionalBoolean(input.minPinLength, `${label}.minPinLength`) }),
		...(prf === undefined ? {} : { prf }),
	};
	return Object.freeze(output);
}

function timeout(value: unknown, label: string): number {
	if (
		typeof value !== "number" ||
		!Number.isInteger(value) ||
		value < 1 ||
		value > MAX_TIMEOUT
	) {
		throw new TypeError(`Vault received invalid ${label}`);
	}
	return value;
}

function attachment(value: unknown, label: string): "platform" | "cross-platform" | undefined {
	if (value === undefined) return undefined;
	if (value !== "platform" && value !== "cross-platform") {
		throw new TypeError(`Vault received invalid ${label}`);
	}
	return value;
}

function transports(value: unknown, label: string): readonly AuthenticatorTransport[] | undefined {
	if (value === undefined) return undefined;
	if (!Array.isArray(value) || value.length > 8) {
		throw new TypeError(`Vault received invalid ${label}`);
	}
	const values: AuthenticatorTransport[] = [];
	for (const item of value) {
		if (
			item !== "ble" &&
			item !== "cable" &&
			item !== "hybrid" &&
			item !== "internal" &&
			item !== "nfc" &&
			item !== "smart-card" &&
			item !== "usb"
		) {
			throw new TypeError(`Vault received invalid ${label}`);
		}
		if (!values.includes(item)) values.push(item);
	}
	return Object.freeze(values);
}

function parseCredentialDescriptor(value: unknown, label: string) {
	const input = exactRecord(value, label, ["id", "type", "transports"]);
	if (input.type !== "public-key") throw new TypeError(`Vault received invalid ${label}`);
	return Object.freeze({
		id: base64url(input.id, `${label}.id`),
		type: "public-key" as const,
		...(input.transports === undefined
			? {}
			: { transports: transports(input.transports, `${label}.transports`) }),
	});
}

export function parseRegistrationOptions(value: unknown): VaultRegistrationOptions {
	const input = exactRecord(value, "passkey registration options", [
		"challenge",
		"rp",
		"user",
		"pubKeyCredParams",
		"timeout",
		"excludeCredentials",
		"authenticatorSelection",
		"attestation",
		"extensions",
	]);
	const rp = exactRecord(input.rp, "passkey registration rp", ["id", "name"]);
	const user = exactRecord(input.user, "passkey registration user", [
		"id",
		"name",
		"displayName",
	]);
	if (!Array.isArray(input.pubKeyCredParams) || input.pubKeyCredParams.length < 1 || input.pubKeyCredParams.length > 8) {
		throw new TypeError("Vault received invalid passkey registration algorithms");
	}
	const pubKeyCredParams = input.pubKeyCredParams.map((value) => {
		const item = exactRecord(value, "passkey registration algorithm", ["alg", "type"]);
		const alg = item.alg;
		if (typeof alg !== "number" || !Number.isSafeInteger(alg) || item.type !== "public-key") {
			throw new TypeError("Vault received invalid passkey registration algorithm");
		}
		return Object.freeze({ alg, type: "public-key" as const });
	});
	const selection = exactRecord(
		input.authenticatorSelection,
		"passkey authenticator selection",
		["authenticatorAttachment", "residentKey", "requireResidentKey", "userVerification"],
	);
	if (
		selection.residentKey !== "required" ||
		selection.requireResidentKey !== true ||
		selection.userVerification !== "required" ||
		input.attestation !== "none"
	) {
		throw new TypeError("Vault received invalid passkey registration options");
	}
	const excludeCredentials =
		input.excludeCredentials === undefined
			? undefined
			: (() => {
				if (!Array.isArray(input.excludeCredentials) || input.excludeCredentials.length > 64) {
					throw new TypeError("Vault received invalid passkey registration credentials");
				}
				return Object.freeze(
					input.excludeCredentials.map((item) =>
						parseCredentialDescriptor(item, "passkey registration credential"),
					),
				);
			})();
	const extensions = input.extensions === undefined
		? undefined
		: parseExtensions(input.extensions, "passkey registration extensions");
	return Object.freeze({
		challenge: base64url(input.challenge, "passkey registration challenge"),
		rp: Object.freeze({ id: text(rp.id, "passkey registration rp id"), name: text(rp.name, "passkey registration rp name") }),
		user: Object.freeze({
			id: base64url(user.id, "passkey registration user id"),
			name: text(user.name, "passkey registration user name"),
			displayName: text(user.displayName, "passkey registration display name"),
		}),
		pubKeyCredParams: Object.freeze(pubKeyCredParams),
		timeout: timeout(input.timeout, "passkey registration timeout"),
		...(excludeCredentials ? { excludeCredentials } : {}),
		authenticatorSelection: Object.freeze({
			...(attachment(selection.authenticatorAttachment, "passkey authenticator attachment")
				? { authenticatorAttachment: attachment(selection.authenticatorAttachment, "passkey authenticator attachment") }
				: {}),
			residentKey: "required" as const,
			requireResidentKey: true as const,
			userVerification: "required" as const,
		}),
		attestation: "none" as const,
		...(extensions === undefined ? {} : { extensions }),
	});
}

export function parseDeletionOptions(value: unknown): VaultDeletionOptions {
	const input = exactRecord(value, "passkey deletion options", [
		"challenge",
		"rpId",
		"timeout",
		"allowCredentials",
		"userVerification",
		"extensions",
	]);
	if (!Array.isArray(input.allowCredentials) || input.allowCredentials.length < 1 || input.allowCredentials.length > 64 || input.userVerification !== "required") {
		throw new TypeError("Vault received invalid passkey deletion options");
	}
	const credentials = input.allowCredentials.map((item) =>
		parseCredentialDescriptor(item, "passkey deletion credential"),
	);
	const [firstCredential, ...remainingCredentials] = credentials;
	if (!firstCredential) {
		throw new TypeError("Vault received invalid passkey deletion options");
	}
	const allowCredentials: VaultDeletionOptions["allowCredentials"] = [
		firstCredential,
		...remainingCredentials,
	];
	const extensions = input.extensions === undefined
		? undefined
		: parseExtensions(input.extensions, "passkey deletion extensions");
	return Object.freeze({
		challenge: base64url(input.challenge, "passkey deletion challenge"),
		rpId: text(input.rpId, "passkey deletion rp id"),
		timeout: timeout(input.timeout, "passkey deletion timeout"),
		allowCredentials: Object.freeze(allowCredentials),
		userVerification: "required" as const,
		...(extensions === undefined ? {} : { extensions }),
	});
}

function decodeBase64URL(value: string): ArrayBuffer {
	try {
		const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
		const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
		const binary = atob(padded);
		const bytes = new Uint8Array(binary.length);
		for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
		return bytes.buffer;
	} catch {
		throw new TypeError("Vault received invalid base64url WebAuthn data");
	}
}

function encodeBase64URL(value: ArrayBuffer): string {
	const bytes = new Uint8Array(value);
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function attachmentFromCredential(value: string | null): "platform" | "cross-platform" | undefined {
	return value === "platform" || value === "cross-platform" ? value : undefined;
}

function extensionBytes(value: ArrayBuffer | ArrayBufferView): string {
	if (value instanceof ArrayBuffer) return encodeBase64URL(value);
	const bytes = new Uint8Array(value.byteLength);
	bytes.set(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
	return encodeBase64URL(bytes.buffer);
}

function encodedExtensionValue(value: unknown, label: string): string | boolean | number | undefined {
	if (value === undefined || typeof value === "boolean" || typeof value === "number") return value;
	if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return extensionBytes(value);
	throw new TypeError(`The browser returned an invalid ${label}`);
}

function extensionResults(value: AuthenticationExtensionsClientOutputs): VaultWebAuthnExtensionResults {
	for (const key of Object.keys(value)) {
		if (!["appid", "credProps", "hmacCreateSecret", "largeBlob", "prf"].includes(key)) {
			throw new TypeError("The browser returned an unsupported passkey extension result");
		}
	}
	const output: Record<string, unknown> = {};
	if (value.appid !== undefined) output.appid = encodedExtensionValue(value.appid, "passkey appid extension");
	if (value.hmacCreateSecret !== undefined) output.hmacCreateSecret = encodedExtensionValue(value.hmacCreateSecret, "passkey hmac extension");
	if (value.credProps !== undefined) {
		const rk = encodedExtensionValue(value.credProps.rk, "passkey credential properties extension");
		if (rk !== undefined && typeof rk !== "boolean") throw new TypeError("The browser returned an invalid passkey credential properties extension");
		output.credProps = Object.freeze({ ...(rk === undefined ? {} : { rk }) });
	}
	if (value.largeBlob !== undefined) {
		const blob = encodedExtensionValue(value.largeBlob.blob, "passkey large blob extension");
		const supported = encodedExtensionValue(value.largeBlob.supported, "passkey large blob extension");
		const written = encodedExtensionValue(value.largeBlob.written, "passkey large blob extension");
		if (
			(blob !== undefined && typeof blob !== "string") ||
			(supported !== undefined && typeof supported !== "boolean") ||
			(written !== undefined && typeof written !== "boolean")
		) throw new TypeError("The browser returned an invalid passkey large blob extension");
		output.largeBlob = Object.freeze({
			...(blob === undefined ? {} : { blob }),
			...(supported === undefined ? {} : { supported }),
			...(written === undefined ? {} : { written }),
		});
	}
	if (value.prf !== undefined) {
		const enabled = encodedExtensionValue(value.prf.enabled, "passkey PRF extension");
		if (enabled !== undefined && typeof enabled !== "boolean") throw new TypeError("The browser returned an invalid passkey PRF extension");
		const results = value.prf.results;
		const first = results === undefined ? undefined : encodedExtensionValue(results.first, "passkey PRF extension");
		const second = results === undefined ? undefined : encodedExtensionValue(results.second, "passkey PRF extension");
		if ((first !== undefined && typeof first !== "string") || (second !== undefined && typeof second !== "string")) {
			throw new TypeError("The browser returned an invalid passkey PRF extension");
		}
		if (results !== undefined && first === undefined) throw new TypeError("The browser returned an invalid passkey PRF extension");
		output.prf = Object.freeze({
			...(enabled === undefined ? {} : { enabled }),
			...(first === undefined ? {} : { results: Object.freeze({ first, ...(second === undefined ? {} : { second }) }) }),
		});
	}
	return Object.freeze(output) as VaultWebAuthnExtensionResults;
}

function browserExtensions(input: VaultWebAuthnExtensions): AuthenticationExtensionsClientInputs {
	const largeBlob = input.largeBlob === undefined ? undefined : {
		...(input.largeBlob.read === undefined ? {} : { read: input.largeBlob.read }),
		...(input.largeBlob.support === undefined ? {} : { support: input.largeBlob.support }),
		...(input.largeBlob.write === undefined ? {} : { write: decodeBase64URL(input.largeBlob.write) }),
	};
	const prf = input.prf === undefined ? undefined : {
		...(input.prf.eval === undefined ? {} : {
			eval: {
				first: decodeBase64URL(input.prf.eval.first),
				...(input.prf.eval.second === undefined ? {} : { second: decodeBase64URL(input.prf.eval.second) }),
			},
		}),
		...(input.prf.evalByCredential === undefined ? {} : {
			evalByCredential: Object.fromEntries(Object.entries(input.prf.evalByCredential).map(([credentialId, values]) => [credentialId, {
				first: decodeBase64URL(values.first),
				...(values.second === undefined ? {} : { second: decodeBase64URL(values.second) }),
			}])),
		}),
	};
	return {
		...(input.appid === undefined ? {} : { appid: input.appid }),
		...(input.credProps === undefined ? {} : { credProps: input.credProps }),
		...(input.credentialProtectionPolicy === undefined ? {} : { credentialProtectionPolicy: input.credentialProtectionPolicy }),
		...(input.enforceCredentialProtectionPolicy === undefined ? {} : { enforceCredentialProtectionPolicy: input.enforceCredentialProtectionPolicy }),
		...(input.hmacCreateSecret === undefined ? {} : { hmacCreateSecret: input.hmacCreateSecret }),
		...(largeBlob === undefined ? {} : { largeBlob }),
		...(input.minPinLength === undefined ? {} : { minPinLength: input.minPinLength }),
		...(prf === undefined ? {} : { prf }),
	};
}

export function registrationCreationOptions(input: VaultRegistrationOptions): PublicKeyCredentialCreationOptions {
	return {
		challenge: decodeBase64URL(input.challenge),
		rp: { id: input.rp.id, name: input.rp.name },
		user: { id: decodeBase64URL(input.user.id), name: input.user.name, displayName: input.user.displayName },
		pubKeyCredParams: input.pubKeyCredParams.map((credential) => ({ alg: credential.alg, type: credential.type })),
		timeout: input.timeout,
		...(input.excludeCredentials
			? { excludeCredentials: input.excludeCredentials.map((credential) => ({ id: decodeBase64URL(credential.id), type: credential.type, ...(credential.transports ? { transports: [...credential.transports] } : {}) })) }
			: {}),
		authenticatorSelection: {
			...input.authenticatorSelection,
		},
		attestation: input.attestation,
		...(input.extensions === undefined ? {} : { extensions: browserExtensions(input.extensions) }),
	};
}

export function deletionRequestOptions(input: VaultDeletionOptions): PublicKeyCredentialRequestOptions {
	return {
		challenge: decodeBase64URL(input.challenge),
		rpId: input.rpId,
		timeout: input.timeout,
		allowCredentials: input.allowCredentials.map((credential) => ({
			id: decodeBase64URL(credential.id),
			type: credential.type,
			...(credential.transports ? { transports: [...credential.transports] } : {}),
		})),
		userVerification: input.userVerification,
		...(input.extensions === undefined ? {} : { extensions: browserExtensions(input.extensions) }),
	};
}

export function authenticationRequestOptions(input: VaultAuthenticationOptions): PublicKeyCredentialRequestOptions {
	return {
		challenge: decodeBase64URL(input.challenge),
		rpId: input.rpId,
		timeout: input.timeout,
		userVerification: input.userVerification,
		...(input.extensions === undefined ? {} : { extensions: browserExtensions(input.extensions) }),
	};
}

export function registrationResponse(credential: PublicKeyCredential): VaultRegistrationResponse {
	const response = credential.response;
	if (typeof AuthenticatorAttestationResponse === "undefined" || !(response instanceof AuthenticatorAttestationResponse)) {
		throw new TypeError("The browser returned an invalid passkey registration response");
	}
	const publicKey = response.getPublicKey?.() ?? undefined;
	const authenticatorData = response.getAuthenticatorData?.();
	return Object.freeze({
		id: text(credential.id, "passkey credential id"),
		rawId: encodeBase64URL(credential.rawId),
		type: "public-key" as const,
		clientExtensionResults: extensionResults(credential.getClientExtensionResults()),
		...(attachmentFromCredential(credential.authenticatorAttachment) ? { authenticatorAttachment: attachmentFromCredential(credential.authenticatorAttachment) } : {}),
		response: Object.freeze({
			clientDataJSON: encodeBase64URL(response.clientDataJSON),
			attestationObject: encodeBase64URL(response.attestationObject),
			transports: transports(response.getTransports(), "passkey response transports") ?? Object.freeze([]),
			...(typeof response.getPublicKeyAlgorithm?.() === "number" ? { publicKeyAlgorithm: response.getPublicKeyAlgorithm() } : {}),
			...(publicKey ? { publicKey: encodeBase64URL(publicKey) } : {}),
			...(authenticatorData ? { authenticatorData: encodeBase64URL(authenticatorData) } : {}),
		}),
	});
}

export function authenticationResponse(credential: PublicKeyCredential): VaultAuthenticationResponse {
	const response = credential.response;
	if (typeof AuthenticatorAssertionResponse === "undefined" || !(response instanceof AuthenticatorAssertionResponse)) {
		throw new TypeError("The browser returned an invalid passkey authentication response");
	}
	return Object.freeze({
		id: text(credential.id, "passkey credential id"),
		rawId: encodeBase64URL(credential.rawId),
		type: "public-key" as const,
		clientExtensionResults: extensionResults(credential.getClientExtensionResults()),
		...(attachmentFromCredential(credential.authenticatorAttachment) ? { authenticatorAttachment: attachmentFromCredential(credential.authenticatorAttachment) } : {}),
		response: Object.freeze({
			clientDataJSON: encodeBase64URL(response.clientDataJSON),
			authenticatorData: encodeBase64URL(response.authenticatorData),
			signature: encodeBase64URL(response.signature),
			...(response.userHandle ? { userHandle: encodeBase64URL(response.userHandle) } : {}),
		}),
	});
}
