import { appendAuditEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import type { ManagementStore, StoreV2TopologyRepository } from "../store/types.js";
import type { DataStoreSnapshot } from "../types/resources.js";

export type ConfigRecord = Record<string, string>;

const MAX_KEY_LENGTH = 128;
const MAX_VALUE_LENGTH = 4096;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/;
const SECRET_KEY = /(secret|token|password|credential|private[\s_-]*key|api[\s_-]*key|client[\s_-]*secret|database[\s_-]*url)/i;
const SECRET_VALUE = /^(?:sk_[A-Za-z0-9_-]+|Bearer\s+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|clr\$v1\$|(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql):\/\/)/i;
const SECRET_ASSIGNMENT = /(secret|token|password|credential|private[\s_-]*key|api[\s_-]*key|client[\s_-]*secret)\s*[:=]/i;

function hasOwn(record: ConfigRecord, key: string): boolean {
	return Object.prototype.hasOwnProperty.call(record, key);
}

function invalid(message: string): never {
	throw new ClearanceError({
		code: "CONFIG_INVALID",
		message,
		stage: "config.validate",
		remediation: "Use a plain JSON object with short, printable string keys and values.",
	});
}

function isSecretLikeValue(value: string): boolean {
	return SECRET_VALUE.test(value) || SECRET_ASSIGNMENT.test(value);
}

export function isSecretLikeConfigKey(key: string): boolean {
	return SECRET_KEY.test(key);
}

export function isSecretLikeConfigEntry(key: string, value: string): boolean {
	return isSecretLikeConfigKey(key) || isSecretLikeValue(value);
}

/** Parse the deliberately small config-file grammar while detecting duplicate keys. */
export function parseConfigJson(input: string): ConfigRecord {
	let offset = 0;
	const whitespace = () => {
		while (/\s/.test(input[offset] ?? "")) offset += 1;
	};
	const fileError = (message: string): never => {
		throw new ClearanceError({
			code: "CONFIG_FILE_INVALID",
			message,
			stage: "config.parse",
			remediation: "Provide a JSON object whose keys and values are strings, with no duplicate keys.",
		});
	};
	const string = (): string => {
		if (input[offset] !== '"') fileError("Expected a JSON string.");
		const start = offset;
		offset += 1;
		let escaped = false;
		while (offset < input.length) {
			const char = input[offset++]!;
			if (escaped) {
				escaped = false;
				continue;
			}
			if (char === "\\") {
				escaped = true;
				continue;
			}
			if (char === '"') {
				try {
					return JSON.parse(input.slice(start, offset)) as string;
				} catch {
					return fileError("Malformed JSON string.");
				}
			}
			if (char < " ") fileError("JSON strings cannot contain control characters.");
		}
		return fileError("Unterminated JSON string.");
	};

	whitespace();
	if (input[offset] !== "{") fileError("Config file must contain a JSON object.");
	offset += 1;
	whitespace();
	const result: ConfigRecord = Object.create(null) as ConfigRecord;
	if (input[offset] === "}") {
		offset += 1;
	} else {
		for (;;) {
			whitespace();
			const key = string();
			if (hasOwn(result, key)) {
				fileError("Config file contains duplicate keys.");
			}
			whitespace();
			if (input[offset] !== ":") fileError("Expected ':' after config key.");
			offset += 1;
			whitespace();
			if (input[offset] !== '"') fileError("Config values must be JSON strings.");
			result[key] = string();
			whitespace();
			if (input[offset] === "}") {
				offset += 1;
				break;
			}
			if (input[offset] !== ",") fileError("Expected ',' between config entries.");
			offset += 1;
		}
	}
	whitespace();
	if (offset !== input.length) fileError("Unexpected content after config object.");
	return result;
}

export function assertConfigRecord(config: unknown): asserts config is ConfigRecord {
	if (!config || typeof config !== "object" || Array.isArray(config)) {
		invalid("Config must be a JSON object with string values.");
	}
	for (const [key, value] of Object.entries(config)) {
		if (
			!key.trim() ||
			key.length > MAX_KEY_LENGTH ||
			CONTROL_CHARACTERS.test(key) ||
			key === "__proto__" ||
			key === "constructor" ||
			key === "prototype"
		) {
			invalid("Config keys must be non-empty, printable, and within the maximum length.");
		}
		if (typeof value !== "string") {
			invalid("Config values must be JSON strings.");
		}
		if (value.length > MAX_VALUE_LENGTH || CONTROL_CHARACTERS.test(value)) {
			invalid("Config values must be printable and within the maximum length.");
		}
		if (isSecretLikeConfigEntry(key, value)) {
			throw new ClearanceError({
				code: "CONFIG_SECRET_FORBIDDEN",
				message: "Secret-bearing configuration cannot be stored in Clearance config.",
				stage: "config.secrets",
				remediation: "Use the appropriate environment variable or credential command for secrets.",
			});
		}
	}
}

export function validateConfig(store: ManagementStore, config: unknown): ConfigRecord {
	assertConfigRecord(config);
	const hasProjectId = hasOwn(config, "projectId");
	const hasEnvironmentId = hasOwn(config, "environmentId");
	const projectId = config.projectId;
	const environmentId = config.environmentId;
	if (hasProjectId && !store.snapshot.projects.some((project) => project.id === projectId)) {
		throw new ClearanceError({ code: "CONFIG_PROJECT_NOT_FOUND", message: "Configured projectId does not reference an existing project.", stage: "config.scope", remediation: "Select an existing project id." });
	}
	if (hasEnvironmentId) {
		const environment = store.snapshot.environments.find((item) => item.id === environmentId);
		if (!environment) {
			throw new ClearanceError({ code: "CONFIG_ENVIRONMENT_NOT_FOUND", message: "Configured environmentId does not reference an existing environment.", stage: "config.scope", remediation: "Select an existing environment id." });
		}
		const selectedProject = projectId ?? store.snapshot.meta.config.projectId;
		if (!selectedProject || environment.projectId !== selectedProject) {
			throw new ClearanceError({ code: "CONFIG_SCOPE_MISMATCH", message: "Configured environmentId must belong to the selected project.", stage: "config.scope", remediation: "Use an environment from the selected project." });
		}
	}
	if (hasOwn(config, "telemetryEndpoint")) {
		let endpoint: URL;
		try { endpoint = new URL(config.telemetryEndpoint); } catch { invalid("telemetryEndpoint must be a valid http or https URL."); }
		if ((endpoint.protocol !== "http:" && endpoint.protocol !== "https:") || endpoint.username || endpoint.password) {
			invalid("telemetryEndpoint must be a credential-free http or https URL.");
		}
	}
	return config;
}

/**
 * Validate topology-bearing config through relational authority after cutover.
 * The synchronous validator remains the JSON/snapshot contract. The normalized
 * reader only exposes exact, parent-bound lookups, which deliberately treats a
 * missing or cross-project environment as the same scope mismatch.
 */
export async function validateConfigAuthoritative(
	store: ManagementStore,
	config: unknown,
): Promise<ConfigRecord> {
	assertConfigRecord(config);
	const topology = store.storeV2Topology;
	if (!topology?.authoritative) return validateConfig(store, config);
	await validateConfigWithTopology(topology, config, store.snapshot.meta.config);
	if (hasOwn(config, "telemetryEndpoint")) {
		let endpoint: URL;
		try { endpoint = new URL(config.telemetryEndpoint); } catch { invalid("telemetryEndpoint must be a valid http or https URL."); }
		if ((endpoint.protocol !== "http:" && endpoint.protocol !== "https:") || endpoint.username || endpoint.password) {
			invalid("telemetryEndpoint must be a credential-free http or https URL.");
		}
	}
	return config;
}

export function validateCurrentConfig(store: ManagementStore): ConfigRecord {
	return validateConfig(store, store.snapshot.meta.config);
}

export async function validateCurrentConfigAuthoritative(
	store: ManagementStore,
): Promise<ConfigRecord> {
	return validateConfigAuthoritative(store, store.snapshot.meta.config);
}

export function publicConfig(config: ConfigRecord, key?: string): { config: ConfigRecord; redactedKeys: string[] } {
	const entries = Object.entries(config)
		.filter(([entryKey, value]) => !isSecretLikeConfigEntry(entryKey, value))
		.filter(([entryKey]) => key === undefined || entryKey === key)
		.sort(([a], [b]) => a.localeCompare(b));
	const redactedKeys = Object.keys(config)
		.filter((entryKey) => (key === undefined || entryKey === key) && isSecretLikeConfigEntry(entryKey, config[entryKey]!))
		.sort((a, b) => a.localeCompare(b));
	return { config: Object.fromEntries(entries), redactedKeys };
}

export function setConfig(store: ManagementStore, key: string, value: string): { changed: boolean; config: ConfigRecord } {
	const candidate = { ...store.snapshot.meta.config, [key]: value };
	validateConfig(store, candidate);
	return persistConfig(store, key, value, candidate);
}

/** Relational-authority-aware config mutation for production callers. */
export async function setConfigAuthoritative(
	store: ManagementStore,
	key: string,
	value: string,
): Promise<{ changed: boolean; config: ConfigRecord }> {
	const candidate = { ...store.snapshot.meta.config, [key]: value };
	await validateConfigAuthoritative(store, candidate);
	if (store.storeV2Topology?.authoritative) {
		if (!store.mutateCoordinated) {
			throw new ClearanceError({
				code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
				message: "Relational topology authority requires a coordinated transaction",
				stage: "config.set",
				status: 500,
			});
		}
		return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
			if (!topology) {
				throw new ClearanceError({
					code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
					message: "Relational topology authority requires a coordinated transaction",
					stage: "config.set",
					status: 500,
				});
			}
			const current = data.meta.config;
			const transactionCandidate = { ...current, [key]: value };
			await validateConfigWithLockedTopology(topology, transactionCandidate, current);
			if (current[key] === value) return { changed: false, config: transactionCandidate };
			data.meta.config[key] = value;
			appendAudit({
				actor: "operator", action: "config.set", subjectType: "config", subjectId: key,
				outcome: "success", source: "cli", projectId: data.meta.config.projectId,
				environmentId: data.meta.config.environmentId, message: "Updated configuration entry",
				metadata: { key },
			});
			return { changed: true, config: transactionCandidate };
		});
	}
	return persistConfig(store, key, value, candidate);
}

async function validateConfigWithTopology(
	topology: NonNullable<ManagementStore["storeV2Topology"]>,
	config: ConfigRecord,
	current: ConfigRecord,
): Promise<void> {
	const hasProjectId = hasOwn(config, "projectId");
	const hasEnvironmentId = hasOwn(config, "environmentId");
	const projectId = config.projectId;
	const environmentId = config.environmentId;
	if (hasProjectId && !(await topology.getProjectById(projectId))) {
		throw new ClearanceError({ code: "CONFIG_PROJECT_NOT_FOUND", message: "Configured projectId does not reference an existing project.", stage: "config.scope", remediation: "Select an existing project id." });
	}
	if (hasEnvironmentId) {
		const selectedProject = projectId ?? current.projectId;
		const environment = selectedProject
			? await topology.getEnvironment({ projectId: selectedProject, id: environmentId })
			: null;
		if (!environment) {
			throw new ClearanceError({ code: "CONFIG_SCOPE_MISMATCH", message: "Configured environmentId must belong to the selected project.", stage: "config.scope", remediation: "Use an environment from the selected project." });
		}
	}
}

/**
 * Transaction-only topology validation. Locks follow the shared topology
 * order: project before its environment, preventing a concurrent reparent
 * from invalidating the persisted config pair after validation.
 */
async function validateConfigWithLockedTopology(
	topology: StoreV2TopologyRepository,
	config: ConfigRecord,
	current: ConfigRecord,
): Promise<void> {
	const hasProjectId = hasOwn(config, "projectId");
	const hasEnvironmentId = hasOwn(config, "environmentId");
	const projectId = config.projectId;
	const environmentId = config.environmentId;
	const selectedProject = projectId ?? current.projectId;
	if (hasProjectId && !(await topology.lockProject({ id: projectId }))) {
		throw new ClearanceError({ code: "CONFIG_PROJECT_NOT_FOUND", message: "Configured projectId does not reference an existing project.", stage: "config.scope", remediation: "Select an existing project id." });
	}
	if (hasEnvironmentId) {
		const environment = selectedProject
			? await topology.lockEnvironment({ projectId: selectedProject, id: environmentId })
			: null;
		if (!environment) {
			throw new ClearanceError({ code: "CONFIG_SCOPE_MISMATCH", message: "Configured environmentId must belong to the selected project.", stage: "config.scope", remediation: "Use an environment from the selected project." });
		}
	}
}

function persistConfig(
	store: ManagementStore,
	key: string,
	value: string,
	candidate: ConfigRecord,
): { changed: boolean; config: ConfigRecord } {
	if (store.snapshot.meta.config[key] === value) return { changed: false, config: candidate };
	store.mutate((data: DataStoreSnapshot) => {
		data.meta.config[key] = value;
		appendAuditEvent(data, {
			actor: "operator", action: "config.set", subjectType: "config", subjectId: key,
			outcome: "success", source: "cli", projectId: data.meta.config.projectId,
			environmentId: data.meta.config.environmentId, message: "Updated configuration entry",
			metadata: { key },
		});
	});
	return { changed: true, config: candidate };
}

export function diffConfig(current: ConfigRecord, candidate: ConfigRecord): { added: string[]; changed: string[]; removed: string[] } {
	const keys = new Set([...Object.keys(current), ...Object.keys(candidate)]);
	const added: string[] = [], changed: string[] = [], removed: string[] = [];
	for (const key of [...keys].sort((a, b) => a.localeCompare(b))) {
		if (!hasOwn(current, key)) added.push(key);
		else if (!hasOwn(candidate, key)) removed.push(key);
		else if (current[key] !== candidate[key]) changed.push(key);
	}
	return { added, changed, removed };
}
