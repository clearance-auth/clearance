import { createServer, request, type Server } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";

let server: Server | undefined;

afterEach(async () => {
	if (server) {
		await new Promise<void>((resolve) => server!.close(() => resolve()));
		server = undefined;
	}
	delete process.env.CLEARANCE_API_MAX_BODY_BYTES;
	vi.resetModules();
});

async function startBridge() {
	process.env.CLEARANCE_API_MAX_BODY_BYTES = "1024";
	process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
	process.env.NODE_ENV = "development";
	const { nodeRequestHandler } = await import("./server.js");
	server = createServer(nodeRequestHandler);
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
				path: "/v1/users",
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
			// The server rejects from Content-Length before waiting for or buffering a body.
			req.end();
		}
	});
}

describe("API request body streaming limit", () => {
	it("returns a structured 413 from Content-Length before authentication", async () => {
		const port = await startBridge();
		const response = await sendOversized(port, "content-length");
		expect(response.status).toBe(413);
		expect(JSON.parse(response.body).error).toMatchObject({
			code: "REQUEST_BODY_TOO_LARGE",
			stage: "api.request_body",
			retryable: false,
		});
	});

	it("stops a chunked request as soon as streamed bytes exceed the limit", async () => {
		const port = await startBridge();
		const response = await sendOversized(port, "chunked");
		expect(response.status).toBe(413);
		expect(JSON.parse(response.body).error.code).toBe("REQUEST_BODY_TOO_LARGE");
	});
});
