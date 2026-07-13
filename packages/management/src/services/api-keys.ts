import { createHash, randomBytes } from "node:crypto";
import { newId, nowIso } from "../store/json-store.js";
import type { ManagementStore } from "../store/types.js";
import type { ApiKey } from "../types/resources.js";
import { appendAuditEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { assertResourceInScope, resolveOperatorScope, scopeFilter, type ResourceScope } from "./scope.js";

const SCOPE_RE = /^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_.-]*$/;

export type ApiKeyView = Omit<ApiKey, "digest">;
export type CreatedApiKey = { apiKey: ApiKeyView; secret: string };

function publicView(key: ApiKey): ApiKeyView {
	return {
		id: key.id,
		projectId: key.projectId,
		environmentId: key.environmentId,
		name: key.name,
		scopes: [...key.scopes],
		prefix: key.prefix,
		fingerprint: key.fingerprint,
		status: key.status,
		createdAt: key.createdAt,
		updatedAt: key.updatedAt,
		...(key.revokedAt ? { revokedAt: key.revokedAt } : {}),
		...(key.replacedById ? { replacedById: key.replacedById } : {}),
	};
}

function digest(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex");
}

/** Strict normalized scope validation: lowercase, no empty/malformed/duplicates. */
export function normalizeAndValidateApiKeyScopes(input: unknown, stage: string): string[] {
	if (input === undefined) return [];
	if (!Array.isArray(input)) {
		throw new ClearanceError({ code: "API_KEY_SCOPES_INVALID", message: "API key scopes must be an array of strings", stage, status: 400 });
	}
	const seen = new Set<string>();
	const scopes: string[] = [];
	for (const item of input) {
		if (typeof item !== "string") {
			throw new ClearanceError({ code: "API_KEY_SCOPE_INVALID", message: "Each API key scope must be a string", stage, status: 400 });
		}
		const scope = item.trim().toLowerCase();
		if (!scope || !SCOPE_RE.test(scope) || scope.length > 128) {
			throw new ClearanceError({ code: "API_KEY_SCOPE_INVALID", message: "API key scope is malformed", stage, status: 400, remediation: "Use lowercase resource:action scopes" });
		}
		if (seen.has(scope)) {
			throw new ClearanceError({ code: "API_KEY_SCOPE_DUPLICATE", message: "API key scopes must be unique", stage, status: 400 });
		}
		seen.add(scope);
		scopes.push(scope);
	}
	return scopes.sort();
}

export function validateApiKeyName(value: unknown, stage: string): string {
	if (typeof value !== "string" || !value.trim()) {
		throw new ClearanceError({ code: "API_KEY_NAME_REQUIRED", message: "API key name is required", stage, status: 400 });
	}
	const name = value.trim();
	if (name.length > 128 || /[\x00-\x1f\x7f]/.test(name)) {
		throw new ClearanceError({ code: "API_KEY_NAME_INVALID", message: "API key name must be human-readable and at most 128 characters", stage, status: 400 });
	}
	return name;
}

function newSecret(): string {
	// 32 cryptographically random bytes, base64url encoded. Prefix only identifies type.
	return `clr_${randomBytes(32).toString("base64url")}`;
}

function newRecord(scope: ResourceScope, name: string, scopes: string[], secret: string): ApiKey {
	const fullDigest = digest(secret);
	const now = nowIso();
	return {
		id: newId("key"), projectId: scope.projectId, environmentId: scope.environmentId,
		name, scopes, digest: fullDigest, prefix: secret.slice(0, 12), fingerprint: fullDigest.slice(0, 16),
		status: "active", createdAt: now, updatedAt: now,
	};
}

function appendMutationAudit(data: Parameters<typeof appendAuditEvent>[0], key: ApiKey, action: string, actor: string, source: "cli" | "console" | "api", extra: Record<string, unknown> = {}) {
	appendAuditEvent(data, { actor, action, subjectType: "api_key", subjectId: key.id, outcome: "success", source,
		projectId: key.projectId, environmentId: key.environmentId, message: `${action} API key ${key.id}`,
		metadata: { name: key.name, prefix: key.prefix, fingerprint: key.fingerprint, scopes: key.scopes, ...extra } });
}

export function listApiKeys(store: ManagementStore, input?: { scope?: ResourceScope; includeRevoked?: boolean }): ApiKeyView[] {
	const scope = input?.scope ?? resolveOperatorScope(store);
	return (store.snapshot.apiKeys ?? []).filter(scopeFilter(scope)).filter((key) => input?.includeRevoked || key.status === "active")
		.map(publicView).sort((a, b) => a.createdAt < b.createdAt ? 1 : -1);
}

export function inspectApiKey(store: ManagementStore, id: string, input?: { scope?: ResourceScope }): ApiKeyView {
	const scope = input?.scope ?? resolveOperatorScope(store);
	const key = (store.snapshot.apiKeys ?? []).find((candidate) => candidate.id === id);
	assertResourceInScope(key, scope, { code: "API_KEY_NOT_FOUND", stage: "keys.inspect", label: "API key" });
	return publicView(key);
}

export async function createApiKey(store: ManagementStore, input: { name: unknown; scopes?: unknown; projectId?: string; environmentId?: string; scope?: ResourceScope; actor?: string; source?: "cli" | "console" | "api" }): Promise<CreatedApiKey> {
	const scope = input.scope ?? resolveOperatorScope(store, { projectId: input.projectId, environmentId: input.environmentId });
	const name = validateApiKeyName(input.name, "keys.create");
	const scopes = normalizeAndValidateApiKeyScopes(input.scopes, "keys.create");
	const secret = newSecret();
	const key = newRecord(scope, name, scopes, secret);
	return store.mutateDurable((data) => {
		data.apiKeys ??= [];
		data.apiKeys.push(key);
		appendMutationAudit(data, key, "keys.create", input.actor ?? "operator", input.source ?? "cli");
		return { apiKey: publicView(key), secret };
	});
}

export async function rotateApiKey(store: ManagementStore, id: string, input: { scope?: ResourceScope; actor?: string; source?: "cli" | "console" | "api" } = {}): Promise<CreatedApiKey & { revokedKey: ApiKeyView }> {
	const scope = input.scope ?? resolveOperatorScope(store);
	return store.mutateDurable((data) => {
		data.apiKeys ??= [];
		const original = data.apiKeys.find((key) => key.id === id);
		assertResourceInScope(original, scope, { code: "API_KEY_NOT_FOUND", stage: "keys.rotate", label: "API key" });
		if (original.status === "revoked") throw new ClearanceError({ code: "API_KEY_REVOKED", message: "Revoked API keys cannot be rotated", stage: "keys.rotate", status: 409 });
		const secret = newSecret();
		const replacement = newRecord(scope, original.name, [...original.scopes], secret);
		const now = nowIso();
		original.status = "revoked"; original.revokedAt = now; original.updatedAt = now; original.replacedById = replacement.id;
		data.apiKeys.push(replacement);
		appendMutationAudit(data, original, "keys.rotate", input.actor ?? "operator", input.source ?? "cli", { replacementKeyId: replacement.id });
		return { apiKey: publicView(replacement), secret, revokedKey: publicView(original) };
	});
}

export async function revokeApiKey(store: ManagementStore, id: string, input: { scope?: ResourceScope; actor?: string; source?: "cli" | "console" | "api" } = {}): Promise<{ apiKey: ApiKeyView; idempotent: boolean }> {
	const scope = input.scope ?? resolveOperatorScope(store);
	return store.mutateDurable((data) => {
		data.apiKeys ??= [];
		const key = data.apiKeys.find((candidate) => candidate.id === id);
		assertResourceInScope(key, scope, { code: "API_KEY_NOT_FOUND", stage: "keys.revoke", label: "API key" });
		const idempotent = key.status === "revoked";
		if (!idempotent) { const now = nowIso(); key.status = "revoked"; key.revokedAt = now; key.updatedAt = now; }
		appendMutationAudit(data, key, "keys.revoke", input.actor ?? "operator", input.source ?? "cli", { idempotent });
		return { apiKey: publicView(key), idempotent };
	});
}
