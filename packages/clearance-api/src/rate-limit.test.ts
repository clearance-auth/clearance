/**
 * Rate-limit keying (FOLLOW.md P2.3.3).
 *
 * Default: keyed on the server-derived socket remote address
 * (x-clearance-socket-remote is stamped by the node bridge and unconditionally
 * overwritten, so in these app.request tests setting it simulates the socket).
 * Client-supplied x-forwarded-for must NOT partition the limiter unless
 * CLEARANCE_TRUSTED_PROXY=1, in which case the LAST XFF hop (appended by the
 * trusted console BFF) keys the bucket — so two console operators behind the
 * one BFF socket do not share a bucket.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const dirs: string[] = [];

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
	delete process.env.CLEARANCE_DATA_PATH;
	delete process.env.CLEARANCE_OPERATOR_TOKEN;
	delete process.env.DATABASE_URL;
	delete process.env.CLEARANCE_CORS_ORIGINS;
	delete process.env.CLEARANCE_API_RATE_MAX;
	delete process.env.CLEARANCE_TRUSTED_PROXY;
	vi.resetModules();
});

async function loadAppWith(env: { trustedProxy?: boolean; rateMax: number }) {
	const dir = mkdtempSync(join(tmpdir(), "clr-api-rate-"));
	dirs.push(dir);
	delete process.env.DATABASE_URL;
	process.env.CLEARANCE_DATA_PATH = join(dir, "data.json");
	process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
	process.env.CLEARANCE_OPERATOR_TOKEN = "test-operator-token-32chars!!";
	process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
	process.env.NODE_ENV = "development";
	process.env.CLEARANCE_API_RATE_MAX = String(env.rateMax);
	if (env.trustedProxy) {
		process.env.CLEARANCE_TRUSTED_PROXY = "1";
	} else {
		delete process.env.CLEARANCE_TRUSTED_PROXY;
	}
	vi.resetModules();
	return (await import("./server.js")).app;
}

describe("rate-limit keying — untrusted by default", () => {
	it("spoofed x-forwarded-for from one socket does NOT partition the limiter", async () => {
		const app = await loadAppWith({ rateMax: 3 });
		const socket = { "x-clearance-socket-remote": "203.0.113.7" };
		// Attacker rotates XFF on every request from the same socket.
		for (let i = 0; i < 3; i++) {
			const res = await app.request("/health", {
				headers: { ...socket, "x-forwarded-for": `10.0.0.${i}` },
			});
			expect(res.status).toBe(200);
		}
		const fourth = await app.request("/health", {
			headers: { ...socket, "x-forwarded-for": "10.0.0.99" },
		});
		expect(fourth.status).toBe(429);
		expect((await fourth.json()).error.code).toBe("RATE_LIMITED");

		// x-real-ip spoofing is equally ineffective
		const fifth = await app.request("/health", {
			headers: { ...socket, "x-real-ip": "10.9.9.9" },
		});
		expect(fifth.status).toBe(429);
	});

	it("distinct sockets get distinct buckets", async () => {
		const app = await loadAppWith({ rateMax: 3 });
		for (let i = 0; i < 4; i++) {
			await app.request("/health", {
				headers: { "x-clearance-socket-remote": "198.51.100.1" },
			});
		}
		const exhausted = await app.request("/health", {
			headers: { "x-clearance-socket-remote": "198.51.100.1" },
		});
		expect(exhausted.status).toBe(429);

		const other = await app.request("/health", {
			headers: { "x-clearance-socket-remote": "198.51.100.2" },
		});
		expect(other.status).toBe(200);
	});
});

describe("rate-limit keying — CLEARANCE_TRUSTED_PROXY=1", () => {
	it("two console operators behind the one BFF socket do not share a bucket", async () => {
		const app = await loadAppWith({ trustedProxy: true, rateMax: 3 });
		// Both operators arrive via the same BFF socket; the BFF stamps XFF
		// from each browser's client socket (buildUpstreamHeaders).
		const bffSocket = { "x-clearance-socket-remote": "172.18.0.5" };
		for (let i = 0; i < 3; i++) {
			const res = await app.request("/health", {
				headers: { ...bffSocket, "x-forwarded-for": "192.0.2.10" },
			});
			expect(res.status).toBe(200);
		}
		const operatorAExhausted = await app.request("/health", {
			headers: { ...bffSocket, "x-forwarded-for": "192.0.2.10" },
		});
		expect(operatorAExhausted.status).toBe(429);

		const operatorB = await app.request("/health", {
			headers: { ...bffSocket, "x-forwarded-for": "192.0.2.20" },
		});
		expect(operatorB.status).toBe(200);
	});

	it("keys on the LAST XFF hop — client-prepended hops cannot mint new buckets", async () => {
		const app = await loadAppWith({ trustedProxy: true, rateMax: 3 });
		const bffSocket = { "x-clearance-socket-remote": "172.18.0.5" };
		// Client tried to prepend fake hops; the trusted proxy appended the
		// real client (192.0.2.30) last.
		for (let i = 0; i < 3; i++) {
			const res = await app.request("/health", {
				headers: {
					...bffSocket,
					"x-forwarded-for": `10.0.0.${i}, 192.0.2.30`,
				},
			});
			expect(res.status).toBe(200);
		}
		const fourth = await app.request("/health", {
			headers: {
				...bffSocket,
				"x-forwarded-for": "10.0.0.77, 192.0.2.30",
			},
		});
		expect(fourth.status).toBe(429);
	});
});
