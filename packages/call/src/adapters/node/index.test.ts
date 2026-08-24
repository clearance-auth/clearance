import { once } from "node:events";
import { createServer, request as nodeRequest } from "node:http";
import type { RequestListener } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { toNodeHandler } from "./index";
import { getRequest, RequestBodyTooLargeError } from "./request";

const servers: ReturnType<typeof createServer>[] = [];

afterEach(async () => {
	await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function start(handler: RequestListener) {
	const server = createServer(handler);
	servers.push(server);
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	const address = server.address();
	if (!address || typeof address === "string") throw new Error("Expected a TCP server address");
	return { port: address.port };
}

async function send(
	port: number,
	options: { headers?: Record<string, string>; body?: string; chunks?: string[] } = {},
) {
	return new Promise<{ status: number; body: string }>((resolve, reject) => {
		const request = nodeRequest({
			host: "127.0.0.1",
			port,
			method: "POST",
			path: "/auth?flow=test",
			headers: options.headers,
		}, (response) => {
			let body = "";
			response.setEncoding("utf8");
			response.on("data", (chunk) => { body += chunk; });
			response.on("end", () => resolve({ status: response.statusCode ?? 0, body }));
		});
		request.on("error", reject);
		if (options.chunks) {
			for (const chunk of options.chunks) request.write(chunk);
			request.end();
			return;
		}
		request.end(options.body);
	});
}

describe("Node handler boundary", () => {
	it("uses its canonical default instead of forged Host or X-Forwarded-Proto", async () => {
		const { port } = await start(toNodeHandler(async (request) => new Response(request.url)));
		const response = await send(port, {
			headers: {
				Host: "attacker.example",
				"X-Forwarded-Host": "forwarded-attacker.example",
				"X-Forwarded-Proto": "https",
			},
		});
		expect(response).toEqual({ status: 200, body: "http://localhost/auth?flow=test" });
	});

	it("uses an explicit canonical origin even when the request forges Host headers", async () => {
		const { port } = await start(toNodeHandler(
			async (request) => new Response(request.url),
			{ canonicalOrigin: "https://auth.clearance.example/some-path" },
		));
		const response = await send(port, {
			headers: { Host: "attacker.example", "X-Forwarded-Proto": "http" },
		});
		expect(response.body).toBe("https://auth.clearance.example/auth?flow=test");
	});

	it("honors forwarded origin headers only with explicit trusted-proxy opt-in", async () => {
		const { port } = await start(toNodeHandler(
			async (request) => new Response(request.url),
			{ canonicalOrigin: "https://auth.clearance.example", trustedProxyHeaders: true },
		));
		const response = await send(port, {
			headers: {
				"X-Forwarded-Host": "edge.clearance.example",
				"X-Forwarded-Proto": "https",
			},
		});
		expect(response.body).toBe("https://edge.clearance.example/auth?flow=test");
	});

	it.each([
		["edge.clearance.example, attacker.example", "https, http"],
		["attacker.example, edge.clearance.example", "http, https"],
	])("rejects ambiguous forwarded lists regardless of append order", async (host, protocol) => {
		const { port } = await start(toNodeHandler(
			async (request) => new Response(request.url),
			{ canonicalOrigin: "https://auth.clearance.example", trustedProxyHeaders: true },
		));
		const response = await send(port, {
			headers: { "X-Forwarded-Host": host, "X-Forwarded-Proto": protocol },
		});
		expect(response.body).toBe("https://auth.clearance.example/auth?flow=test");
	});

	it("rejects an oversized declared body before invoking the handler", async () => {
		let invoked = false;
		const { port } = await start(toNodeHandler(async () => {
			invoked = true;
			return new Response("unexpected");
		}, { bodySizeLimit: 4 }));
		const response = await send(port, {
			headers: { "Content-Length": "5", "Content-Type": "text/plain" },
			body: "12345",
		});
		expect(response).toEqual({ status: 413, body: "Payload Too Large" });
		expect(invoked).toBe(false);
	});

	it("rejects an oversized chunked body while it is read", async () => {
		const { port } = await start(toNodeHandler(async (request) => {
			await request.text();
			return new Response("unexpected");
		}, { bodySizeLimit: 4 }));
		const response = await send(port, {
			headers: { "Content-Type": "text/plain", "Transfer-Encoding": "chunked" },
			chunks: ["1234", "5"],
		});
		expect(response).toEqual({ status: 413, body: "Payload Too Large" });
	});

	it("rejects an oversized chunked body even when the handler does not read it", async () => {
		const { port } = await start(toNodeHandler(
			async () => new Response("unexpected"),
			{ bodySizeLimit: 4 },
		));
		const response = await send(port, {
			headers: { "Content-Type": "text/plain", "Transfer-Encoding": "chunked" },
			chunks: ["1234", "5"],
		});
		expect(response).toEqual({ status: 413, body: "Payload Too Large" });
	});

	it("rejects an oversized body parsed by upstream middleware", () => {
		const parsedRequest = {
			headers: { "content-type": "application/json" },
			method: "POST",
			url: "/auth",
			readable: false,
			readableEnded: true,
			destroyed: false,
			body: { payload: "12345" },
		};
		expect(() => getRequest({
			base: "https://auth.clearance.example",
			bodySizeLimit: 4,
			request: parsedRequest as never,
		})).toThrow(RequestBodyTooLargeError);
	});
});
