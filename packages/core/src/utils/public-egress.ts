import { lookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isPublicRoutableHost } from "./host";

/** Conservative cap for server-side responses fetched from remote providers. */
export const DEFAULT_PUBLIC_EGRESS_MAX_RESPONSE_BYTES = 1_048_576;

export type PublicEgressOptions = {
	/** Maximum response body size accepted before the connection is destroyed. */
	maxResponseBytes?: number;
	/** Allow an operator-approved private endpoint while retaining DNS pinning. */
	allowNonPublicAddresses?: boolean;
};

export type PublicEgressTransport = (
	input: string | URL,
	init?: RequestInit,
) => Promise<Response>;

function responseTooLarge(maxResponseBytes: number): RangeError {
	return new RangeError(
		`Public egress response exceeded the ${maxResponseBytes} byte limit`,
	);
}

function contentLength(headers: Record<string, string | string[] | undefined>): number | undefined {
	const raw = headers["content-length"];
	const value = Array.isArray(raw) ? raw[0] : raw;
	if (!value || !/^\d+$/.test(value.trim())) return undefined;
	const parsed = Number(value);
	return Number.isSafeInteger(parsed) ? parsed : undefined;
}

/** Normalize the small request-body surface used by OAuth token exchanges. */
export function preparePublicEgressRequestBody(
	body: RequestInit["body"],
	headers: Headers,
): string | Uint8Array | undefined {
	if (body == null) return undefined;
	if (typeof body === "string" || body instanceof Uint8Array) return body;
	if (body instanceof URLSearchParams) {
		if (!headers.has("content-type")) {
			headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8");
		}
		return body.toString();
	}
	throw new TypeError("Public egress only supports string, bytes, or URLSearchParams request bodies");
}

/** Collect a response with a hard cap even when Content-Length is absent or false. */
export function readPublicEgressResponse(
	response: NodeJS.ReadableStream & {
		headers: Record<string, string | string[] | undefined>;
		statusCode?: number;
		statusMessage?: string;
		destroy(error?: Error): void;
	},
	request: { destroy(error?: Error): void },
	maxResponseBytes: number,
): Promise<Response> {
	const declaredLength = contentLength(response.headers);
	if (declaredLength !== undefined && declaredLength > maxResponseBytes) {
		const error = responseTooLarge(maxResponseBytes);
		response.destroy();
		request.destroy(error);
		return Promise.reject(error);
	}
	return new Promise<Response>((resolve, reject) => {
		const chunks: Buffer[] = [];
		let bytes = 0;
		let settled = false;
		const finish = (error?: Error) => {
			if (settled) return;
			settled = true;
			response.off("data", onData);
			response.off("end", onEnd);
			response.off("error", onError);
			if (error) reject(error);
			else resolve(new Response(Buffer.concat(chunks), {
				status: response.statusCode ?? 0,
				statusText: response.statusMessage,
				headers: response.headers as HeadersInit,
			}));
		};
		const overflow = () => {
			const error = responseTooLarge(maxResponseBytes);
			response.destroy();
			request.destroy(error);
			finish(error);
		};
		const onData = (chunk: Buffer | string) => {
			const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			if (bytes + buffer.length > maxResponseBytes) return overflow();
			bytes += buffer.length;
			chunks.push(buffer);
		};
		const onEnd = () => finish();
		const onError = (error: Error) => finish(error);
		response.on("data", onData);
		response.once("end", onEnd);
		response.once("error", onError);
	});
}

/** Apply the response-size and redirect policy to an injected fetch transport. */
export async function fetchWithPublicEgressPolicy(
	input: string | URL,
	init: RequestInit = {},
	transport: PublicEgressTransport = fetchPinnedPublic,
	options: PublicEgressOptions = {},
): Promise<Response> {
	const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_PUBLIC_EGRESS_MAX_RESPONSE_BYTES;
	if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1) {
		throw new TypeError("Public egress maxResponseBytes must be a positive integer");
	}
	const response = await transport(input, { ...init, redirect: "manual" });
	if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
		throw new TypeError("Public egress fetches refuse redirects to prevent SSRF");
	}
	const declaredLength = response.headers.get("content-length");
	if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxResponseBytes) {
		throw responseTooLarge(maxResponseBytes);
	}
	if (!response.body) return response;
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let bytes = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (bytes + value.byteLength > maxResponseBytes) {
				await reader.cancel();
				throw responseTooLarge(maxResponseBytes);
			}
			bytes += value.byteLength;
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}
	const body = new Uint8Array(bytes);
	let offset = 0;
	for (const chunk of chunks) {
		body.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
}

/**
 * Fetch an HTTP(S) URL after resolving and pinning its public address.
 *
 * The request retains the URL hostname, so HTTPS SNI and the Host header stay
 * correct, while the custom lookup callback prevents a second DNS resolution
 * from changing the connected address (DNS rebinding).
 */
export async function fetchPinnedPublic(
	input: string | URL,
	init: RequestInit = {},
	options: PublicEgressOptions = {},
): Promise<Response> {
	const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_PUBLIC_EGRESS_MAX_RESPONSE_BYTES;
	if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1) {
		throw new TypeError("Public egress maxResponseBytes must be a positive integer");
	}
	const url = new URL(input);
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		throw new TypeError("Public egress only supports HTTP(S) URLs");
	}
	const addresses = await lookup(url.hostname, { all: true, verbatim: true });
	if (
		!Array.isArray(addresses) ||
		addresses.some(
			({ address, family }) =>
				typeof address !== "string" ||
				address.length === 0 ||
				(family !== 4 && family !== 6),
		)
	) {
		throw new TypeError("Public egress DNS lookup returned an invalid address list");
	}
	if (addresses.length === 0 || (!options.allowNonPublicAddresses && addresses.some(({ address }) => !isPublicRoutableHost(address)))) {
		throw new TypeError("Public egress refused a non-public resolved address");
	}
	const target = addresses[0]! as { address: string; family: 4 | 6 };
	return new Promise<Response>((resolve, reject) => {
		const headers = new Headers(init.headers);
		let body: string | Uint8Array | undefined;
		try {
			body = preparePublicEgressRequestBody(init.body, headers);
		} catch (error) {
			reject(error);
			return;
		}
		let settled = false;
		const abort = () => request.destroy(new DOMException("Aborted", "AbortError"));
		const finish = (callback: () => void) => {
			if (settled) return;
			settled = true;
			init.signal?.removeEventListener("abort", abort);
			callback();
		};
		const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(url, {
			method: init.method ?? "GET",
			headers: Object.fromEntries(headers.entries()),
			lookup: (_hostname, lookupOptions, callback) => {
				// Recent Node releases request `all: true` for connection-family
				// autoselection. Preserve the already validated, pinned address in
				// either callback shape instead of allowing a second DNS lookup.
				if (typeof lookupOptions === "object" && lookupOptions.all) {
					(callback as (
						error: null,
						resolvedAddresses: Array<{ address: string; family: 4 | 6 }>,
					) => void)(
						null,
						[target],
					);
					return;
				}
				(callback as (
					error: null,
					address: string,
					family: 4 | 6,
				) => void)(null, target.address, target.family);
			},
			agent: false,
		}, (response) => {
			readPublicEgressResponse(response, request, maxResponseBytes).then(
				(response) => finish(() => resolve(response)),
				(error) => finish(() => reject(error)),
			);
		});
		if (init.signal) {
			if (init.signal.aborted) abort();
			else init.signal.addEventListener("abort", abort, { once: true });
		}
		request.on("error", (error) => finish(() => reject(error)));
		request.end(body);
	});
}
