import type {
	IncomingHttpHeaders,
	IncomingMessage,
	ServerResponse,
} from "node:http";
import * as set_cookie_parser from "set-cookie-parser";

type NodeRequestWithBody = IncomingMessage & {
	body?: unknown;
};

/** A deliberately conservative limit for public HTTP request bodies. */
export const DEFAULT_BODY_SIZE_LIMIT = 1024 * 1024;

export class RequestBodyTooLargeError extends Error {
	constructor(readonly limit: number) {
		super(`Request body exceeds the ${limit}-byte limit`);
		this.name = "RequestBodyTooLargeError";
	}
}

export type RawBodyControl = {
	/** Drain an unread or partially-read stream without buffering it. */
	drain: () => Promise<void>;
};

const getFirstHeaderValue = (
	header: IncomingHttpHeaders[string],
): string | undefined => {
	if (Array.isArray(header)) {
		return header[0];
	}
	return header;
};

const hasFormUrlEncodedContentType = (
	headers: IncomingHttpHeaders,
): boolean => {
	const contentType = getFirstHeaderValue(headers["content-type"]);
	if (!contentType) {
		return false;
	}
	return contentType
		.toLowerCase()
		.startsWith("application/x-www-form-urlencoded");
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
	if (typeof value !== "object" || value === null) {
		return false;
	}
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
};

const appendFormValue = (
	params: URLSearchParams,
	key: string,
	value: unknown,
) => {
	if (value === undefined) {
		return;
	}
	if (Array.isArray(value)) {
		for (const item of value) {
			appendFormValue(params, key, item);
		}
		return;
	}
	if (value === null) {
		params.append(key, "");
		return;
	}
	if (isPlainObject(value)) {
		params.append(key, JSON.stringify(value));
		return;
	}
	params.append(key, `${value}`);
};

const toFormUrlEncodedBody = (
	body: Readonly<Record<string, unknown>>,
): string => {
	const params = new URLSearchParams();
	for (const [key, value] of Object.entries(body)) {
		appendFormValue(params, key, value);
	}
	return params.toString();
};

const canReadRawBody = (request: IncomingMessage): boolean => {
	return (
		!request.destroyed && request.readableEnded !== true && request.readable
	);
};

const serializeParsedBody = (
	parsedBody: unknown,
	isFormUrlEncoded: boolean,
): string => {
	if (typeof parsedBody === "string") {
		return parsedBody;
	}
	if (parsedBody instanceof URLSearchParams) {
		return parsedBody.toString();
	}
	if (isFormUrlEncoded && isPlainObject(parsedBody)) {
		return toFormUrlEncodedBody(parsedBody);
	}
	return JSON.stringify(parsedBody);
};

export function getContentLength(req: IncomingMessage): number | undefined {
	const value = getFirstHeaderValue(req.headers["content-length"]);
	if (!value) return undefined;
	const length = Number(value);
	return Number.isSafeInteger(length) && length >= 0 ? length : undefined;
}

export function isBodyTooLarge(
	req: IncomingMessage,
	bodySizeLimit = DEFAULT_BODY_SIZE_LIMIT,
): boolean {
	const contentLength = getContentLength(req);
	return contentLength !== undefined && contentLength > bodySizeLimit;
}

function getRawBody(
	req: IncomingMessage,
	bodySizeLimit = DEFAULT_BODY_SIZE_LIMIT,
	onControl?: (control: RawBodyControl) => void,
) {
	const h = req.headers;

	const contentLength = getContentLength(req);

	// check if no request body
	if (
		(req.httpVersionMajor === 1 &&
			contentLength === undefined &&
			h["transfer-encoding"] == null) ||
		contentLength === 0
	) {
		return null;
	}

	if (contentLength !== undefined && contentLength > bodySizeLimit) {
		throw new RequestBodyTooLargeError(bodySizeLimit);
	}

	if (req.destroyed) {
		const readable = new ReadableStream();
		readable.cancel();
		return readable;
	}

	let size = 0;
	let cancelled = false;
	let ended = false;
	let failed: Error | undefined;
	let controller: ReadableStreamDefaultController<Uint8Array> | undefined;

	const onError = (error: Error) => {
		cancelled = true;
		failed = error;
		controller?.error(error);
	};
	const onEnd = () => {
		ended = true;
		if (!cancelled) controller?.close();
	};
	const onData = (chunk: Uint8Array) => {
		if (cancelled) return;
		size += chunk.byteLength;
		if (size > bodySizeLimit) {
			cancelled = true;
			failed = new RequestBodyTooLargeError(bodySizeLimit);
			// Stop retaining bytes immediately. Resuming drains the socket without
			// accumulating the rest of a chunked request in this adapter.
			req.resume();
			controller?.error(failed);
			return;
		}
		controller?.enqueue(chunk);
		if (
			controller?.desiredSize === null ||
			(controller?.desiredSize ?? 0) <= 0
		) {
			req.pause();
		}
	};

	onControl?.({
		drain: () =>
			new Promise<void>((resolve, reject) => {
				if (failed) {
					reject(failed);
					return;
				}
				if (ended || req.readableEnded) {
					resolve();
					return;
				}
				cancelled = true;
				req.off("data", onData);
				req.off("error", onError);
				req.off("end", onEnd);
				controller?.close();
				const onDrainData = (chunk: Uint8Array) => {
					size += chunk.byteLength;
					if (size > bodySizeLimit && !failed) {
						failed = new RequestBodyTooLargeError(bodySizeLimit);
					}
				};
				const onDrainError = (error: Error) => finish(error);
				const onDrainEnd = () => finish(failed);
				const finish = (error?: Error) => {
					req.off("data", onDrainData);
					req.off("error", onDrainError);
					req.off("end", onDrainEnd);
					if (error) reject(error);
					else resolve();
				};
				req.on("data", onDrainData);
				req.once("error", onDrainError);
				req.once("end", onDrainEnd);
				req.resume();
			}),
	});

	return new ReadableStream({
		start(streamController) {
			controller = streamController;
			req.on("error", onError);
			req.on("end", onEnd);
			req.on("data", onData);
		},

		pull() {
			req.resume();
		},

		cancel(reason) {
			cancelled = true;
			req.destroy(reason);
		},
	});
}

function constructRelativeUrl(
	req: IncomingMessage & { baseUrl?: string; originalUrl?: string },
) {
	const baseUrl = req.baseUrl;
	const originalUrl = req.originalUrl;

	if (!baseUrl || !originalUrl) {
		// In express.js sub-routers `req.url` is relative to the mount
		// path (e.g., '/auth/xxx'), and `req.baseUrl` will hold the mount
		// path (e.g., '/api'). Build the full path as baseUrl + url when
		// available to preserve the full route. For application level routes
		// baseUrl will be an empty string
		return baseUrl ? baseUrl + req.url : req.url;
	}

	if (baseUrl + req.url === originalUrl) {
		return baseUrl + req.url;
	}

	// For certain subroutes or when mounting wildcard middlewares in express
	// it is possible `baseUrl + req.url` will result in a url constructed
	// which has a trailing forward slash the original url did not have.
	// Checking the `req.originalUrl` path ending can prevent this issue.

	const originalPathEnding = originalUrl.split("?")[0]!.at(-1);
	return originalPathEnding === "/" ? baseUrl + req.url : baseUrl;
}

export function getRequest({
	request,
	base,
	bodySizeLimit,
	onRawBodyControl,
}: {
	base: string;
	bodySizeLimit?: number;
	onRawBodyControl?: (control: RawBodyControl) => void;
	request: IncomingMessage;
}) {
	// Check if body has already been parsed by Express middleware
	const maybeConsumedReq = request as NodeRequestWithBody;
	const isFormUrlEncoded = hasFormUrlEncodedContentType(request.headers);
	let body = undefined;

	const method = request.method;
	// Request with GET/HEAD method cannot have body.
	if (method !== "GET" && method !== "HEAD") {
		// Raw-first strategy: prefer consuming the original request stream whenever it is still readable.
		if (canReadRawBody(request)) {
			body = getRawBody(request, bodySizeLimit, onRawBodyControl);
		} else if (maybeConsumedReq.body !== undefined) {
			const parsedBody = maybeConsumedReq.body;

			const bodyContent = serializeParsedBody(parsedBody, isFormUrlEncoded);
			if (
				Buffer.byteLength(bodyContent) >
				(bodySizeLimit ?? DEFAULT_BODY_SIZE_LIMIT)
			) {
				throw new RequestBodyTooLargeError(
					bodySizeLimit ?? DEFAULT_BODY_SIZE_LIMIT,
				);
			}
			body = new ReadableStream({
				start(controller) {
					controller.enqueue(new TextEncoder().encode(bodyContent));
					controller.close();
				},
			});
		}
	}

	return new Request(base + constructRelativeUrl(request), {
		// @ts-expect-error
		duplex: "half",
		method: request.method,
		body,
		headers: request.headers as Record<string, string>,
	});
}

export async function setResponse(res: ServerResponse, response: Response) {
	for (const [key, value] of response.headers as any) {
		try {
			res.setHeader(
				key,
				key === "set-cookie"
					? set_cookie_parser.splitCookiesString(
							response.headers.get(key) as string,
						)
					: value,
			);
		} catch (error) {
			res.getHeaderNames().forEach((name) => res.removeHeader(name));
			res.writeHead(500).end(String(error));
			return;
		}
	}

	res.statusCode = response.status;
	res.writeHead(response.status);

	if (!response.body) {
		res.end();
		return;
	}

	if (response.body.locked) {
		res.end(
			"Fatal error: Response body is locked. " +
				"This can happen when the response was already read (for example through 'response.json()' or 'response.text()').",
		);
		return;
	}

	const reader = response.body.getReader();

	if (res.destroyed) {
		reader.cancel();
		return;
	}

	const cancel = (error?: Error) => {
		res.off("close", cancel);
		res.off("error", cancel);

		// If the reader has already been interrupted with an error earlier,
		// then it will appear here, it is useless, but it needs to be catch.
		reader.cancel(error).catch(() => {});
		if (error) res.destroy(error);
	};

	res.on("close", cancel);
	res.on("error", cancel);

	next();
	async function next() {
		try {
			for (;;) {
				const { done, value } = await reader.read();

				if (done) break;

				const writeResult = res.write(value);
				if (!writeResult) {
					// In AWS Lambda/serverless environments, drain events may not work properly
					// Check if we're in a Lambda-like environment and handle differently
					if (
						process.env.AWS_LAMBDA_FUNCTION_NAME ||
						process.env.LAMBDA_TASK_ROOT
					) {
						// In Lambda, continue without waiting for drain
						continue;
					} else {
						// Standard Node.js behavior
						res.once("drain", next);
						return;
					}
				}
			}
			res.end();
		} catch (error) {
			cancel(error instanceof Error ? error : new Error(String(error)));
		}
	}
}
