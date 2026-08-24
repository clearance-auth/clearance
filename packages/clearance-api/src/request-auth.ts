import type { ApiKeyView, ManagementStore, ResourceScope } from "@clearance/management";
import type { Context } from "hono";
import { createHash, timingSafeEqual } from "node:crypto";

type StoredApiKey = ApiKeyView & { digest: string; expiresAt?: string };

export type ApiKeyAuthenticationResult =
	| { ok: true; apiKey: ApiKeyView; scope: ResourceScope }
	| { ok: false; reason: "not_found" | "revoked" | "expired" };

function publicApiKey(key: StoredApiKey): ApiKeyView {
	const { digest: _digest, ...view } = key;
	return view;
}

export function authenticateManagementApiKey(
	store: ManagementStore,
	secret: string,
	now = Date.now(),
): ApiKeyAuthenticationResult {
	const supplied = createHash("sha256").update(secret, "utf8").digest();
	let matched: StoredApiKey | undefined;
	for (const candidate of store.snapshot.apiKeys as StoredApiKey[]) {
		const stored = Buffer.from(candidate.digest, "hex");
		if (stored.length === supplied.length && timingSafeEqual(stored, supplied)) {
			matched = candidate;
		}
	}
	if (!matched) return { ok: false, reason: "not_found" };
	if (matched.status !== "active") return { ok: false, reason: "revoked" };
	if (matched.expiresAt) {
		const expiresAt = Date.parse(matched.expiresAt);
		if (!Number.isFinite(expiresAt) || expiresAt <= now) {
			return { ok: false, reason: "expired" };
		}
	}
	return {
		ok: true,
		apiKey: publicApiKey(matched),
		scope: { projectId: matched.projectId, environmentId: matched.environmentId },
	};
}

export type ApiRequestPrincipal =
	| { kind: "operator"; id: "operator" }
	| {
			kind: "api_key";
			id: string;
			scope: ResourceScope;
			scopes: readonly string[];
			apiKey: ApiKeyView;
	  };

const requestPrincipals = new WeakMap<Context, ApiRequestPrincipal>();

export function setRequestPrincipal(
	context: Context,
	principal: ApiRequestPrincipal,
): void {
	requestPrincipals.set(context, principal);
}

export function requestPrincipal(context: Context): ApiRequestPrincipal {
	return requestPrincipals.get(context) ?? { kind: "operator", id: "operator" };
}

export function requestActor(context: Context): string {
	const principal = requestPrincipal(context);
	return principal.kind === "api_key" ? `api-key:${principal.id}` : "operator";
}

export function requiredApiKeyScope(method: string, path: string): string | null {
	const segment = path.split("/").filter(Boolean)[1];
	const resource = segment && ["whoami", "doctor", "dev", "overview"].includes(segment)
		? "system"
		: segment;
	if (!resource) return null;
	return `${resource}:${method === "GET" || method === "HEAD" ? "read" : "write"}`;
}

export function apiKeyRouteIsOperatorOnly(method: string, path: string): boolean {
	if (path === "/v1/init") return true;
	if (path.startsWith("/v1/product-presentation")) return true;
	if (path === "/v1/delivery/readiness") return true;
	if (method === "POST" && path === "/v1/projects") return true;
	if (method === "POST" && path.startsWith("/v1/environments")) return true;
	if (method !== "GET" && path.startsWith("/v1/keys")) return true;
	if (method === "PATCH" && path.startsWith("/v1/config/")) return true;
	if (method === "POST" && /^\/v1\/(?:sso|scim)\/[^/]+\/test$/.test(path)) return true;
	return ["/v1/import", "/v1/migrations", "/v1/backups", "/v1/upgrades", "/v1/schema"].some(
		(prefix) => path.startsWith(prefix),
	);
}
