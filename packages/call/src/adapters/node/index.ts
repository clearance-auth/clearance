import type { IncomingMessage, ServerResponse } from "node:http";

import {
	DEFAULT_BODY_SIZE_LIMIT,
	getRequest,
	isBodyTooLarge,
	RequestBodyTooLargeError,
	setResponse,
} from "./request";
import type { Router } from "../../router.js";

export interface NodeHandlerOptions {
	/**
	 * The public origin used for the web Request passed to the handler.
	 *
	 * Defaults to `http://localhost` so request-controlled Host headers cannot
	 * become security-sensitive URLs. Configure this in every deployed service.
	 */
	canonicalOrigin?: string;
	/**
	 * Accept X-Forwarded-Host and X-Forwarded-Proto from an authenticated,
	 * immediate reverse proxy. Disabled by default because these headers are
	 * client-controlled on direct connections.
	 */
	trustedProxyHeaders?: boolean;
	/** Maximum raw request-body bytes accepted by the adapter. Defaults to 1 MiB. */
	bodySizeLimit?: number;
}

function normalizeOrigin(origin: string): string {
	const parsed = new URL(origin);
	if (
		parsed.origin === "null" ||
		(parsed.protocol !== "http:" && parsed.protocol !== "https:")
	) {
		throw new TypeError("canonicalOrigin must be an absolute http(s) origin");
	}
	return parsed.origin;
}

function proxyOrigin(req: IncomingMessage, fallback: string): string {
	const host = req.headers["x-forwarded-host"];
	const protocol = req.headers["x-forwarded-proto"];
	// A single immediate trusted proxy supplies exactly one value. Lists have
	// ambiguous append order, so accepting either side would let a client select
	// the effective origin.
	if (
		typeof host !== "string" ||
		typeof protocol !== "string" ||
		host.includes(",") ||
		protocol.includes(",")
	) {
		return fallback;
	}
	try {
		return normalizeOrigin(`${protocol.trim()}://${host.trim()}`);
	} catch {
		return fallback;
	}
}

function payloadTooLarge(res: ServerResponse) {
	res.statusCode = 413;
	res.setHeader("content-type", "text/plain; charset=utf-8");
	res.end("Payload Too Large");
}

export function toNodeHandler(
	handler: Router["handler"],
	options: NodeHandlerOptions = {},
) {
	const bodySizeLimit = options.bodySizeLimit ?? DEFAULT_BODY_SIZE_LIMIT;
	if (!Number.isSafeInteger(bodySizeLimit) || bodySizeLimit < 1) {
		throw new TypeError("bodySizeLimit must be a positive safe integer");
	}
	const canonicalOrigin = normalizeOrigin(
		options.canonicalOrigin ?? "http://localhost",
	);

	return async (req: IncomingMessage, res: ServerResponse) => {
		if (isBodyTooLarge(req, bodySizeLimit)) {
			payloadTooLarge(res);
			return;
		}

		try {
			const base = options.trustedProxyHeaders
				? proxyOrigin(req, canonicalOrigin)
				: canonicalOrigin;
			let rawBodyControl: import("./request").RawBodyControl | undefined;
			const response = await handler(
				getRequest({
					base,
					bodySizeLimit,
					onRawBodyControl: (control) => {
						rawBodyControl = control;
					},
					request: req,
				}),
			);
			// A handler may return without consuming a chunked body. Drain it before
			// responding so the byte limit remains enforceable without buffering it.
			await rawBodyControl?.drain();
			return setResponse(res, response);
		} catch (error) {
			if (error instanceof RequestBodyTooLargeError) {
				payloadTooLarge(res);
				return;
			}
			throw error;
		}
	};
}

export { DEFAULT_BODY_SIZE_LIMIT, getRequest, setResponse };
