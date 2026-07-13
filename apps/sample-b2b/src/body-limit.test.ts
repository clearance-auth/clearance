import { createServer, request, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
	createSampleRequestHandler,
	DEFAULT_MAX_REQUEST_BODY_BYTES,
	resolveMaxRequestBodyBytes,
} from "./server.js";

let server: Server | undefined;

afterEach(async () => {
	if (server) {
		await new Promise<void>((resolve) => server!.close(() => resolve()));
		server = undefined;
	}
});

async function startServer(limit: number): Promise<number> {
	server = createServer(createSampleRequestHandler(limit));
	await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (!address || typeof address === "string") throw new Error("missing test address");
	return address.port;
}

function sendOversized(
	port: number,
	mode: "content-length" | "chunked",
): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const req = request(
			{
				host: "127.0.0.1",
				port,
				path: "/api/auth/sign-in/email",
				method: "POST",
				headers:
					mode === "content-length"
						? { "content-length": "2048", "content-type": "application/json" }
						: { "content-type": "application/octet-stream" },
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
				res.on("end", () =>
					resolve({
						status: res.statusCode ?? 0,
						body: Buffer.concat(chunks).toString("utf8"),
					}),
				);
			},
		);
		req.on("error", reject);
		if (mode === "chunked") {
			req.write(Buffer.alloc(700, "a"));
			req.end(Buffer.alloc(700, "b"));
		} else {
			// The declared size is rejected without waiting for the request body.
			req.end();
		}
	});
}

describe("sample request-body streaming limit", () => {
	it("uses the API-consistent 1 MiB default and validates overrides", () => {
		expect(resolveMaxRequestBodyBytes({})).toBe(DEFAULT_MAX_REQUEST_BODY_BYTES);
		expect(resolveMaxRequestBodyBytes({ SAMPLE_APP_MAX_BODY_BYTES: "2048" })).toBe(
			2048,
		);
		expect(() =>
			resolveMaxRequestBodyBytes({ SAMPLE_APP_MAX_BODY_BYTES: "0" }),
		).toThrow(/integer between 1 and 67108864/);
	});

	it("returns 413 from Content-Length before the auth route reads a body", async () => {
		const port = await startServer(1024);
		const response = await sendOversized(port, "content-length");
		expect(response.status).toBe(413);
		expect(JSON.parse(response.body).error).toMatchObject({
			code: "REQUEST_BODY_TOO_LARGE",
			stage: "sample.request_body",
			retryable: false,
			limitBytes: 1024,
		});
	});

	it("stops a chunked auth request when streamed bytes cross the limit", async () => {
		const port = await startServer(1024);
		const response = await sendOversized(port, "chunked");
		expect(response.status).toBe(413);
		expect(JSON.parse(response.body).error.code).toBe("REQUEST_BODY_TOO_LARGE");
	});
});
