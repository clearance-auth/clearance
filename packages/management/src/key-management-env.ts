import type { CreateClearanceAuthOptions } from "@clearance/auth";
import {
	createAwsKmsKeyProvider,
	createAwsKmsSigningProvider,
	createGcpKmsKeyProvider,
	createGcpKmsSigningProvider,
	createKeyProviderRegistry,
	createLocalKeyProvider,
	createLocalSigningProvider,
	KEY_PURPOSES,
	type KeyEncryptionProvider,
	type KeyPurpose,
	type KeySigningProvider,
} from "@clearance/key-management";

type JsonRecord = Record<string, unknown>;

type KeyManagementRuntimeOptions =
	| Pick<CreateClearanceAuthOptions, "keyManagement">
	| {
		keyManagement: NonNullable<CreateClearanceAuthOptions["keyManagement"]> & {
			signingProvider: KeySigningProvider;
		};
	};

function record(value: unknown, label: string): JsonRecord {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error(`${label} must be a JSON object`);
	}
	return value as JsonRecord;
}

function exactKeys(value: JsonRecord, allowed: readonly string[], label: string): void {
	const extras = Object.keys(value).filter((key) => !allowed.includes(key));
	if (extras.length > 0) {
		throw new Error(`${label} contains unsupported fields`);
	}
}

function text(value: unknown, label: string): string {
	if (typeof value !== "string" || !value.trim() || value.trim() !== value) {
		throw new Error(`${label} must be a nonempty trimmed string`);
	}
	return value;
}

function optionalText(value: unknown, label: string): string | undefined {
	return value === undefined ? undefined : text(value, label);
}

function optionalTexts(value: unknown, label: string): readonly string[] | undefined {
	if (value === undefined) return undefined;
	if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
	return Object.freeze(value.map((item, index) => text(item, `${label}[${index}]`)));
}

function optionalInteger(value: unknown, label: string): number | undefined {
	if (value === undefined) return undefined;
	if (typeof value !== "number" || !Number.isInteger(value)) {
		throw new Error(`${label} must be an integer`);
	}
	return value;
}

function localKeys(value: unknown, label: string): Readonly<Record<string, string>> {
	const input = record(value, label);
	return Object.freeze(
		Object.fromEntries(
			Object.entries(input).map(([keyId, material]) => [
				text(keyId, `${label} key id`),
				text(material, `${label} key material`),
			]),
		),
	);
}

function retainedSigningKeys(value: unknown): readonly Readonly<{
	keyReference: string;
	retiredAt: Date;
}>[] | undefined {
	if (value === undefined) return undefined;
	if (!Array.isArray(value)) {
		throw new Error("access-token-signer.retainedKeys must be an array");
	}
	return Object.freeze(value.map((candidate) => {
		const entry = record(candidate, "access-token-signer.retainedKeys entry");
		exactKeys(
			entry,
			["keyReference", "retiredAt"],
			"access-token-signer.retainedKeys entry",
		);
		const retiredAt = text(
			entry.retiredAt,
			"access-token-signer.retainedKeys retiredAt",
		);
		const date = new Date(retiredAt);
		if (!Number.isFinite(date.getTime()) || date.toISOString() !== retiredAt) {
			throw new Error(
				"access-token-signer.retainedKeys retiredAt must be a canonical ISO-8601 date",
			);
		}
		return Object.freeze({
			keyReference: text(
				entry.keyReference,
				"access-token-signer.retainedKeys keyReference",
			),
			retiredAt: date,
		});
	}));
}

function signingProviderFor(value: unknown): KeySigningProvider {
	const config = record(value, "access-token-signer");
	const kind = text(config.kind, "access-token-signer.kind");
	const common = {
		providerId: text(config.providerId, "access-token-signer.providerId"),
		currentKeyReference: text(
			config.currentKeyReference,
			"access-token-signer.currentKeyReference",
		),
		retainedKeys: retainedSigningKeys(config.retainedKeys),
	};
	if (kind === "local") {
		exactKeys(
			config,
			["kind", "providerId", "currentKeyReference", "retainedKeys", "keys"],
			"access-token-signer",
		);
		return createLocalSigningProvider({
			...common,
			keys: localKeys(config.keys, "access-token-signer.keys"),
		});
	}
	if (kind === "aws-kms") {
		exactKeys(
			config,
			[
				"kind",
				"providerId",
				"currentKeyReference",
				"retainedKeys",
				"region",
				"endpoint",
				"allowInsecureLoopbackHttp",
				"timeoutMs",
			],
			"access-token-signer",
		);
		if (
			config.allowInsecureLoopbackHttp !== undefined &&
			typeof config.allowInsecureLoopbackHttp !== "boolean"
		) {
			throw new Error("access-token-signer.allowInsecureLoopbackHttp must be boolean");
		}
		return createAwsKmsSigningProvider({
			...common,
			region: text(config.region, "access-token-signer.region"),
			endpoint: optionalText(config.endpoint, "access-token-signer.endpoint"),
			allowInsecureLoopbackHttp: config.allowInsecureLoopbackHttp as
				| boolean
				| undefined,
			timeoutMs: optionalInteger(config.timeoutMs, "access-token-signer.timeoutMs"),
		});
	}
	if (kind === "gcp-kms") {
		exactKeys(
			config,
			["kind", "providerId", "currentKeyReference", "retainedKeys", "timeoutMs"],
			"access-token-signer",
		);
		return createGcpKmsSigningProvider({
			...common,
			timeoutMs: optionalInteger(config.timeoutMs, "access-token-signer.timeoutMs"),
		});
	}
	throw new Error("access-token-signer.kind is invalid");
}

function providerFor(purpose: KeyPurpose, value: unknown): KeyEncryptionProvider {
	const config = record(value, `key management provider ${purpose}`);
	const kind = text(config.kind, `${purpose}.kind`);
	const common = {
		providerId: text(config.providerId, `${purpose}.providerId`),
		purpose,
		currentKeyId: text(config.currentKeyId, `${purpose}.currentKeyId`),
	};
	if (kind === "local") {
		exactKeys(config, ["kind", "providerId", "currentKeyId", "keys"], purpose);
		return createLocalKeyProvider({
			...common,
			keys: localKeys(config.keys, `${purpose}.keys`),
		});
	}
	if (kind === "aws-kms") {
		exactKeys(
			config,
			[
				"kind",
				"providerId",
				"currentKeyId",
				"retainedKeyIds",
				"region",
				"endpoint",
				"allowInsecureLoopbackHttp",
				"timeoutMs",
			],
			purpose,
		);
		if (
			config.allowInsecureLoopbackHttp !== undefined &&
			typeof config.allowInsecureLoopbackHttp !== "boolean"
		) {
			throw new Error(`${purpose}.allowInsecureLoopbackHttp must be boolean`);
		}
		return createAwsKmsKeyProvider({
			...common,
			region: text(config.region, `${purpose}.region`),
			retainedKeyIds: optionalTexts(
				config.retainedKeyIds,
				`${purpose}.retainedKeyIds`,
			),
			endpoint: optionalText(config.endpoint, `${purpose}.endpoint`),
			allowInsecureLoopbackHttp: config.allowInsecureLoopbackHttp as
				| boolean
				| undefined,
			timeoutMs: optionalInteger(config.timeoutMs, `${purpose}.timeoutMs`),
		});
	}
	if (kind === "gcp-kms") {
		exactKeys(
			config,
			["kind", "providerId", "currentKeyId", "retainedKeyIds", "timeoutMs"],
			purpose,
		);
		return createGcpKmsKeyProvider({
			...common,
			retainedKeyIds: optionalTexts(
				config.retainedKeyIds,
				`${purpose}.retainedKeyIds`,
			),
			timeoutMs: optionalInteger(config.timeoutMs, `${purpose}.timeoutMs`),
		});
	}
	throw new Error(`${purpose}.kind is invalid`);
}

export function keyManagementRuntimeOptions(): KeyManagementRuntimeOptions {
	const production =
		process.env.NODE_ENV === "production" ||
		process.env.CLEARANCE_STRICT_SECRETS === "1";
	const raw = process.env.CLEARANCE_KEY_MANAGEMENT_CONFIG_JSON?.trim();
	if (!raw) {
		if (production) {
			throw new Error(
				"CLEARANCE_KEY_MANAGEMENT_CONFIG_JSON is required in production",
			);
		}
		return {};
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw new Error("CLEARANCE_KEY_MANAGEMENT_CONFIG_JSON must be valid JSON");
	}
	const config = record(parsed, "CLEARANCE_KEY_MANAGEMENT_CONFIG_JSON");
	exactKeys(
		config,
		[...KEY_PURPOSES, "access-token-signer"],
		"CLEARANCE_KEY_MANAGEMENT_CONFIG_JSON",
	);
	const providers = Object.fromEntries(
		KEY_PURPOSES.map((purpose) => [purpose, providerFor(purpose, config[purpose])]),
	) as Record<KeyPurpose, KeyEncryptionProvider>;
	const signingProvider = signingProviderFor(config["access-token-signer"]);
	const projectId = text(
		process.env.CLEARANCE_PROJECT_ID ?? (production ? "" : "proj_default"),
		"CLEARANCE_PROJECT_ID",
	);
	const environmentId = text(
		process.env.CLEARANCE_ENV_ID ?? (production ? "" : "env_default"),
		"CLEARANCE_ENV_ID",
	);
	return {
		keyManagement: {
			projectId,
			environmentId,
			registry: createKeyProviderRegistry(providers),
			signingProvider,
		},
	};
}
