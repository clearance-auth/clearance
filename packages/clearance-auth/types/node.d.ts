export function toNodeHandler(auth: {
	handler(request: Request): Promise<Response>;
}): (request: unknown, response: unknown) => Promise<void>;

export function fromNodeHeaders(headers: unknown): Headers;
