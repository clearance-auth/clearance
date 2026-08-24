import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import {
	fetchWithPublicEgressPolicy,
	preparePublicEgressRequestBody,
	readPublicEgressResponse,
} from "./public-egress";

function response(headers: Record<string, string | undefined> = {}) {
	const stream = new PassThrough() as PassThrough & {
		headers: Record<string, string | undefined>;
		statusCode: number;
		statusMessage: string;
	};
	stream.headers = headers;
	stream.statusCode = 200;
	stream.statusMessage = "OK";
	return stream;
}

describe("readPublicEgressResponse", () => {
	it("serializes OAuth token URLSearchParams with the form content type", () => {
		const headers = new Headers();
		expect(
			preparePublicEgressRequestBody(
				new URLSearchParams({ grant_type: "authorization_code", code: "a b" }),
				headers,
			),
		).toBe("grant_type=authorization_code&code=a+b");
		expect(headers.get("content-type")).toBe(
			"application/x-www-form-urlencoded;charset=UTF-8",
		);
	});

	it("enforces size and redirect policy for injected transports", async () => {
		await expect(fetchWithPublicEgressPolicy(
			"https://idp.example.com/discovery",
			{},
			async () => new Response("12345"),
			{ maxResponseBytes: 4 },
		)).rejects.toThrow("4 byte limit");
		await expect(fetchWithPublicEgressPolicy(
			"https://idp.example.com/discovery",
			{},
			async () => new Response("", { status: 302 }),
		)).rejects.toThrow(/refuse redirects/);
	});

	it("returns a normal bounded response", async () => {
		const stream = response({ "content-length": "2" });
		const request = { destroy: vi.fn() };
		const pending = readPublicEgressResponse(stream, request, 4);
		stream.end("ok");
		await expect(pending).resolves.toMatchObject({ status: 200 });
		await expect((await pending).text()).resolves.toBe("ok");
		expect(request.destroy).not.toHaveBeenCalled();
	});

	it("rejects an oversized declared Content-Length before reading", async () => {
		const stream = response({ "content-length": "5" });
		const destroy = vi.spyOn(stream, "destroy");
		const request = { destroy: vi.fn() };
		await expect(readPublicEgressResponse(stream, request, 4)).rejects.toThrow("4 byte limit");
		expect(destroy).toHaveBeenCalled();
		expect(request.destroy).toHaveBeenCalled();
	});

	it("destroys chunked responses when streamed bytes exceed the cap", async () => {
		const stream = response();
		const request = { destroy: vi.fn() };
		const pending = readPublicEgressResponse(stream, request, 4);
		stream.write("1234");
		stream.write("5");
		await expect(pending).rejects.toThrow("4 byte limit");
		expect(request.destroy).toHaveBeenCalled();
	});

	it("does not trust a misleading smaller Content-Length", async () => {
		const stream = response({ "content-length": "1" });
		const request = { destroy: vi.fn() };
		const pending = readPublicEgressResponse(stream, request, 4);
		stream.end("12345");
		await expect(pending).rejects.toThrow("4 byte limit");
		expect(request.destroy).toHaveBeenCalled();
	});

	it("propagates an abort-like request error", async () => {
		const stream = response();
		const request = { destroy: vi.fn() };
		const pending = readPublicEgressResponse(stream, request, 4);
		stream.destroy(new DOMException("Aborted", "AbortError"));
		await expect(pending).rejects.toMatchObject({ name: "AbortError" });
	});
});
