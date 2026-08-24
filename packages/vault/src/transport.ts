import { configureVaultEndpoints, type VaultEndpointConfig } from "./origins";

export type VaultFetch = (
	input: RequestInfo | URL,
	init?: RequestInit,
) => Promise<Response>;

export type VaultRequestOptions = Readonly<{
	signal?: AbortSignal;
}>;

export class VaultApiError extends Error {
	readonly status: number;
	readonly code: string | undefined;
	readonly requestId: string | undefined;

	constructor(input: {
		message: string;
		status: number;
		code?: string;
		requestId?: string;
	}) {
		super(input.message);
		this.name = "VaultApiError";
		this.status = input.status;
		this.code = input.code;
		this.requestId = input.requestId;
	}
}

function jsonContentType(response: Response): boolean {
	const contentType = response.headers.get("content-type");
	return (
		typeof contentType === "string" &&
		/(?:^|\/|\+)json(?:;|$)/i.test(contentType)
	);
}

function safeError(value: unknown, status: number): { message: string; code?: string } {
	if (!value || typeof value !== "object") {
		return { message: `Request failed with status ${status}` };
	}
	const record = value as Record<string, unknown>;
	const nested =
		record.error && typeof record.error === "object"
			? (record.error as Record<string, unknown>)
			: record;
	const bounded = (input: unknown, maximum: number): string | undefined => {
		if (typeof input !== "string") return undefined;
		const normalized = input.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
		return normalized ? normalized.slice(0, maximum) : undefined;
	};
	const code = bounded(nested.code, 128);
	const known: Record<string, string> = {
		TENANT_AUTHORIZATION_REQUIRED: "You do not have permission for this organization action.",
		TENANT_ADMINISTRATION_RESOURCE_NOT_FOUND: "The requested organization resource was not found.",
		TENANT_PRODUCT_CONFLICT: "This organization resource changed. Reload and try again.",
		FACTOR_STEP_UP_REQUIRED: "A current authenticator or recovery code is required.",
	};
	return {
		message: code && known[code] ? known[code] : `Request failed with status ${status}`,
		...(code ? { code } : {}),
	};
}

export type VaultTransport = Readonly<{
	auth<T>(
		path: `/${string}`,
		init?: Readonly<{
			method?: "GET" | "POST" | "PATCH" | "DELETE";
			body?: unknown;
			signal?: AbortSignal;
		}>,
	): Promise<T>;
	tenant<T>(
		path: `/${string}`,
		init?: Readonly<{
			method?: "GET" | "POST" | "PATCH" | "DELETE";
			body?: unknown;
			signal?: AbortSignal;
		}>,
	): Promise<T>;
}>;

export function createVaultTransport(
	config: VaultEndpointConfig &
		Readonly<{
			fetch?: VaultFetch;
		}> = {},
): VaultTransport {
	const endpoints = configureVaultEndpoints(config);
	const fetcher = config.fetch ?? globalThis.fetch?.bind(globalThis);
	if (!fetcher) throw new TypeError("A browser fetch implementation is required");

	const request = async <T>(
		baseURL: string,
		path: `/${string}`,
		init: Readonly<{
			method?: "GET" | "POST" | "PATCH" | "DELETE";
			body?: unknown;
			signal?: AbortSignal;
		}> = {},
	): Promise<T> => {
		if (!path.startsWith("/") || path.startsWith("//")) {
			throw new TypeError("Vault request paths must be root-relative");
		}
		const url = new URL(`${baseURL.replace(/\/+$/, "")}${path}`);
		const method = init.method ?? "GET";
		const headers = new Headers({ Accept: "application/json" });
		const requestInit: RequestInit = {
			method,
			headers,
			credentials: "same-origin",
			cache: "no-store",
			redirect: "error",
			...(init.signal ? { signal: init.signal } : {}),
		};
		if (init.body !== undefined) {
			headers.set("Content-Type", "application/json");
			requestInit.body = JSON.stringify(init.body);
		}

		// Intentionally one attempt. Mutations are never retried automatically.
		const response = await fetcher(url, requestInit);
		if (!jsonContentType(response)) {
			throw new VaultApiError({
				status: response.status,
				message: response.ok
					? "Vault expected a JSON response"
					: `Request failed with status ${response.status}`,
				requestId: response.headers.get("x-request-id") ?? undefined,
			});
		}
		let payload: unknown;
		try {
			payload = await response.json();
		} catch {
			throw new VaultApiError({
				status: response.status,
				message: "Vault received invalid JSON",
				requestId: response.headers.get("x-request-id") ?? undefined,
			});
		}
		if (!response.ok) {
			const error = safeError(payload, response.status);
			throw new VaultApiError({
				...error,
				status: response.status,
				requestId: response.headers.get("x-request-id") ?? undefined,
			});
		}
		return payload as T;
	};

	return Object.freeze({
		auth: <T>(
			path: `/${string}`,
			init?: Readonly<{
				method?: "GET" | "POST" | "PATCH" | "DELETE";
				body?: unknown;
				signal?: AbortSignal;
			}>,
		) => request<T>(endpoints.authBaseURL, path, init),
		tenant: <T>(
			path: `/${string}`,
			init?: Readonly<{
				method?: "GET" | "POST" | "PATCH" | "DELETE";
				body?: unknown;
				signal?: AbortSignal;
			}>,
		) => request<T>(endpoints.tenantBaseURL, path, init),
	});
}
