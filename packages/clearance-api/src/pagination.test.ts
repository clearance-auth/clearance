/**
 * API cursor pagination tests (FOLLOW.md P2.3.1).
 *
 * Paginated walk: create more resources than one page, follow nextCursor to
 * exhaustion, assert no duplicates/omissions. Garbage cursors fail with a
 * structured CURSOR_INVALID. Legacy no-param calls stay unchanged.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const dirs: string[] = [];
const OPERATOR = "test-operator-token-32chars!!";

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
	delete process.env.CLEARANCE_DATA_PATH;
	delete process.env.CLEARANCE_OPERATOR_TOKEN;
	delete process.env.DATABASE_URL;
	delete process.env.CLEARANCE_CORS_ORIGINS;
	vi.resetModules();
});

describe("API cursor pagination", () => {
	let authHeaders: Record<string, string>;

	beforeEach(async () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-api-pagination-"));
		dirs.push(dir);
		delete process.env.DATABASE_URL;
		process.env.CLEARANCE_DATA_PATH = join(dir, "data.json");
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
		process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
		process.env.NODE_ENV = "development";

		authHeaders = {
			authorization: `Bearer ${OPERATOR}`,
			"content-type": "application/json",
		};

		const { app } = await import("./server.js");
		const init = await app.request("/v1/init", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Pagination API" }),
		});
		expect(init.status).toBe(200);
	});

	async function loadApp() {
		return (await import("./server.js")).app;
	}

	it("users: paginated walk to exhaustion has no duplicates or omissions", async () => {
		const app = await loadApp();
		const created = new Set<string>();
		for (let i = 0; i < 7; i++) {
			const res = await app.request("/v1/users", {
				method: "POST",
				headers: authHeaders,
				body: JSON.stringify({ email: `walk${i}@t.dev`, name: `Walk ${i}` }),
			});
			expect(res.status).toBe(201);
			created.add((await res.json()).user.id);
		}

		const seen: string[] = [];
		let cursor: string | null = null;
		let pages = 0;
		for (;;) {
			const url: string = cursor
				? `/v1/users?limit=3&cursor=${encodeURIComponent(cursor)}`
				: "/v1/users?limit=3";
			const res = await app.request(url, { headers: authHeaders });
			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body.users.length).toBeLessThanOrEqual(3);
			seen.push(...body.users.map((u: { id: string }) => u.id));
			pages += 1;
			expect(pages).toBeLessThan(10);
			if (body.nextCursor === null) break;
			expect(typeof body.nextCursor).toBe("string");
			cursor = body.nextCursor;
		}
		expect(pages).toBe(3); // 3 + 3 + 1
		expect(seen.length).toBe(7);
		expect(new Set(seen)).toEqual(created);
	});

	it("users: legacy call without params is unchanged (no pagination envelope)", async () => {
		const app = await loadApp();
		for (let i = 0; i < 3; i++) {
			await app.request("/v1/users", {
				method: "POST",
				headers: authHeaders,
				body: JSON.stringify({ email: `legacy${i}@t.dev`, name: `L ${i}` }),
			});
		}
		const res = await app.request("/v1/users", { headers: authHeaders });
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.users.length).toBe(3);
		expect("nextCursor" in body).toBe(false);
	});

	it("organizations: cursor page plus follow-up page covers all orgs", async () => {
		const app = await loadApp();
		const created = new Set<string>();
		for (let i = 0; i < 5; i++) {
			const res = await app.request("/v1/organizations", {
				method: "POST",
				headers: authHeaders,
				body: JSON.stringify({ name: `Org ${i}` }),
			});
			expect(res.status).toBe(201);
			created.add((await res.json()).organization.id);
		}
		const page1 = await (
			await app.request("/v1/organizations?limit=2", { headers: authHeaders })
		).json();
		expect(page1.organizations.length).toBe(2);
		expect(page1.nextCursor).not.toBeNull();
		const seen = new Set<string>(
			page1.organizations.map((o: { id: string }) => o.id),
		);
		let cursor = page1.nextCursor as string;
		for (;;) {
			const res = await app.request(
				`/v1/organizations?limit=2&cursor=${encodeURIComponent(cursor)}`,
				{ headers: authHeaders },
			);
			const body = await res.json();
			for (const o of body.organizations as { id: string }[]) {
				expect(seen.has(o.id)).toBe(false); // no duplicates across pages
				seen.add(o.id);
			}
			if (body.nextCursor === null) break;
			cursor = body.nextCursor;
		}
		expect(seen).toEqual(created);
	});

	it("events: paginated walk newest-first with nextCursor, limit stays page size", async () => {
		const app = await loadApp();
		for (let i = 0; i < 6; i++) {
			await app.request("/v1/users", {
				method: "POST",
				headers: authHeaders,
				body: JSON.stringify({ email: `evt${i}@t.dev`, name: `E ${i}` }),
			});
		}
		const seen: string[] = [];
		let cursor: string | null = null;
		for (;;) {
			const url: string = cursor
				? `/v1/events?limit=4&cursor=${encodeURIComponent(cursor)}`
				: "/v1/events?limit=4";
			const res = await app.request(url, { headers: authHeaders });
			expect(res.status).toBe(200);
			const body = await res.json();
			seen.push(...body.events.map((e: { id: string }) => e.id));
			if (body.nextCursor === null) break;
			cursor = body.nextCursor;
			expect(seen.length).toBeLessThan(100);
		}
		// init + 6 creates = 7 events, all unique
		expect(seen.length).toBe(7);
		expect(new Set(seen).size).toBe(7);
	});

	it("sessions: response carries nextCursor and pages walk cleanly", async () => {
		const app = await loadApp();
		// Seed sessions via management helpers (JSON path)
		const { createManagementStore, createUser, createSession } = await import(
			"@clearance/management"
		);
		const store = await createManagementStore({
			dataPath: process.env.CLEARANCE_DATA_PATH,
		});
		await store.refresh();
		const user = createUser(store, {
			email: "pages@t.dev",
			name: "Pages",
			source: "api",
		});
		const environmentId = store.snapshot.environments[0]!.id;
		const created = new Set<string>();
		for (let i = 0; i < 5; i++) {
			created.add(
				createSession(store, { principalId: user.id, environmentId }).id,
			);
		}
		await store.ready();

		const seen = new Set<string>();
		let cursor: string | null = null;
		for (;;) {
			const url: string = cursor
				? `/v1/sessions?limit=2&cursor=${encodeURIComponent(cursor)}`
				: "/v1/sessions?limit=2";
			const res = await app.request(url, { headers: authHeaders });
			expect(res.status).toBe(200);
			const body = await res.json();
			for (const s of body.sessions as { id: string }[]) {
				expect(seen.has(s.id)).toBe(false);
				seen.add(s.id);
			}
			if (body.nextCursor === null) break;
			cursor = body.nextCursor;
			expect(seen.size).toBeLessThan(100);
		}
		expect(seen).toEqual(created);
	});

	it("garbage cursors fail closed with structured CURSOR_INVALID on every list endpoint", async () => {
		const app = await loadApp();
		for (const path of [
			"/v1/users?cursor=garbage",
			"/v1/organizations?cursor=garbage",
			"/v1/events?cursor=garbage",
			"/v1/sessions?cursor=garbage",
		]) {
			const res = await app.request(path, { headers: authHeaders });
			expect(res.status, path).toBe(400);
			const body = await res.json();
			expect(body.error.code, path).toBe("CURSOR_INVALID");
			expect(body.error.remediation, path).toMatch(/nextCursor/);
		}
		// A users cursor replayed against events is also rejected (cross-surface)
		const users = await (
			await app.request("/v1/users?limit=1", { headers: authHeaders })
		).json();
		// Ensure there is at least one page boundary to mint a cursor
		await app.request("/v1/users", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ email: "c1@t.dev", name: "C1" }),
		});
		await app.request("/v1/users", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ email: "c2@t.dev", name: "C2" }),
		});
		const paged = await (
			await app.request("/v1/users?limit=1", { headers: authHeaders })
		).json();
		if (paged.nextCursor) {
			const cross = await app.request(
				`/v1/events?cursor=${encodeURIComponent(paged.nextCursor)}`,
				{ headers: authHeaders },
			);
			expect(cross.status).toBe(400);
			expect((await cross.json()).error.code).toBe("CURSOR_INVALID");
		}
		void users;
	});

	it("invalid page limits fail closed with stable codes", async () => {
		const app = await loadApp();
		const users = await app.request("/v1/users?limit=wat", {
			headers: authHeaders,
		});
		expect(users.status).toBe(400);
		expect((await users.json()).error.code).toBe("USERS_LIST_LIMIT_INVALID");

		const orgs = await app.request("/v1/organizations?limit=-2", {
			headers: authHeaders,
		});
		expect(orgs.status).toBe(400);
		expect((await orgs.json()).error.code).toBe("ORGS_LIST_LIMIT_INVALID");

		const events = await app.request("/v1/events?limit=wat", {
			headers: authHeaders,
		});
		expect(events.status).toBe(400);
		expect((await events.json()).error.code).toBe("EVENTS_LIST_OPTION_INVALID");

		const sessions = await app.request("/v1/sessions?limit=wat", {
			headers: authHeaders,
		});
		expect(sessions.status).toBe(400);
		expect((await sessions.json()).error.code).toBe("SESSION_LIMIT_INVALID");
	});
});
