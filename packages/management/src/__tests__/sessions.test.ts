/**
 * Management-snapshot sessions list / revoke: scope, idempotency, audit, no tokens.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonStore } from "../store/json-store.js";
import {
	createSession,
	createUser,
	initProject,
	listEvents,
	listSessions,
	revokeSession,
	sanitizeSessionView,
} from "../index.js";
import { ClearanceError } from "../services/errors.js";

const dirs: string[] = [];

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
	delete process.env.CLEARANCE_PROJECT_ID;
	delete process.env.CLEARANCE_ENV_ID;
});

function tempStore() {
	const dir = mkdtempSync(join(tmpdir(), "clr-sessions-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

describe("sessions list / revoke (management snapshot)", () => {
	it("lists active sessions under principal scope and never surfaces tokens", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Sess App" });
		const user = createUser(store, {
			email: "sess@test.com",
			name: "Sess",
		});
		const session = createSession(store, {
			principalId: user.id,
			environmentId: environment.id,
		});

		// Inject a fake token field on the raw record — list must never return it
		store.mutate((data) => {
			const s = data.sessions.find((x) => x.id === session.id) as Record<
				string,
				unknown
			>;
			if (s) {
				s.token = "raw-session-token-must-not-leak";
				s.tokenPrefix = "raw-";
			}
		});

		const listed = listSessions(store, {
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(listed).toHaveLength(1);
		expect(listed[0]?.id).toBe(session.id);
		expect(listed[0]?.principalId).toBe(user.id);
		expect(listed[0]?.projectId).toBe(project.id);
		expect(listed[0]?.status).toBe("active");
		const json = JSON.stringify(listed);
		expect(json).not.toMatch(/raw-session-token/);
		expect(json).not.toMatch(/tokenPrefix/);
		expect(listed[0]).not.toHaveProperty("token");

		// sanitizeSessionView strips credential-like keys
		const dirty = sanitizeSessionView({
			id: "sess_x",
			principalId: user.id,
			projectId: project.id,
			environmentId: environment.id,
			status: "active",
			createdAt: new Date().toISOString(),
			token: "secret",
			sessionToken: "also-secret",
		});
		expect(dirty).not.toHaveProperty("token");
		expect(dirty).not.toHaveProperty("sessionToken");
	});

	it("revokes with audit and is idempotent under authorized contract", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Revoke App" });
		const user = createUser(store, {
			email: "rev@test.com",
			name: "Rev",
		});
		const session = createSession(store, {
			principalId: user.id,
			environmentId: environment.id,
		});

		const first = revokeSession(store, session.id, {
			actor: "test",
			source: "cli",
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(first.idempotent).toBe(false);
		expect(first.session.status).toBe("revoked");
		expect(first.session.revokedAt).toBeTruthy();
		expect(
			store.snapshot.sessions.find((s) => s.id === session.id)?.status,
		).toBe("revoked");

		const second = revokeSession(store, session.id, {
			actor: "test",
			source: "cli",
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(second.idempotent).toBe(true);
		expect(second.session.status).toBe("revoked");

		const audits = listEvents(store, { limit: 50 }).filter(
			(e) => e.action === "sessions.revoke" && e.subjectId === session.id,
		);
		expect(audits.length).toBeGreaterThanOrEqual(2);
		expect(audits.every((e) => e.outcome === "success")).toBe(true);
		expect(audits.every((e) => e.source === "cli")).toBe(true);
		// No credentials in audit metadata
		for (const a of audits) {
			const meta = JSON.stringify(a.metadata ?? {});
			expect(meta).not.toMatch(/token|password|secret/i);
			expect(a.metadata?.principalId).toBe(user.id);
		}

		// Active list excludes revoked
		expect(
			listSessions(store, {
				scope: { projectId: project.id, environmentId: environment.id },
			}),
		).toHaveLength(0);
		expect(
			listSessions(store, {
				scope: { projectId: project.id, environmentId: environment.id },
				includeRevoked: true,
			}),
		).toHaveLength(1);
	});

	it("fails closed for missing and cross-scope sessions", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Scope App" });
		const user = createUser(store, {
			email: "scope@test.com",
			name: "Scope",
		});
		const session = createSession(store, {
			principalId: user.id,
			environmentId: environment.id,
		});

		// Foreign principal + session planted outside scope
		store.mutate((data) => {
			const now = new Date().toISOString();
			data.principals.push({
				id: "user_foreign",
				projectId: "proj_other",
				environmentId: "env_other",
				email: "foreign@x.test",
				name: "Foreign",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
			data.sessions.push({
				id: "sess_foreign",
				principalId: "user_foreign",
				environmentId: "env_other",
				status: "active",
				createdAt: now,
			});
		});

		const scope = { projectId: project.id, environmentId: environment.id };
		expect(() => revokeSession(store, "sess_missing", { scope })).toThrow(
			ClearanceError,
		);
		try {
			revokeSession(store, "sess_foreign", { scope });
			expect.unreachable();
		} catch (e) {
			expect(e).toBeInstanceOf(ClearanceError);
			expect((e as ClearanceError).code).toBe("SESSION_NOT_FOUND");
			expect((e as ClearanceError).status).toBe(404);
		}

		// Foreign session never listed
		const listed = listSessions(store, { scope });
		expect(listed.map((s) => s.id)).toEqual([session.id]);
	});

	it("returns the newest limited sessions and rejects invalid limits", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Limit App" });
		const user = createUser(store, {
			email: "limits@test.com",
			name: "Limits",
		});
		store.mutate((data) => {
			for (const [id, createdAt] of [
				["sess_old", "2026-01-01T00:00:00.000Z"],
				["sess_new", "2026-03-01T00:00:00.000Z"],
				["sess_middle", "2026-02-01T00:00:00.000Z"],
			] as const) {
				data.sessions.push({
					id,
					principalId: user.id,
					environmentId: environment.id,
					status: "active",
					createdAt,
				});
			}
		});
		const scope = { projectId: project.id, environmentId: environment.id };
		expect(listSessions(store, { scope, limit: 2 }).map((s) => s.id)).toEqual([
			"sess_new",
			"sess_middle",
		]);
		expect(() => listSessions(store, { scope, limit: Number.NaN })).toThrowError(
			expect.objectContaining({ code: "SESSION_LIMIT_INVALID" }),
		);
		expect(() => listSessions(store, { scope, limit: 501 })).toThrowError(
			expect.objectContaining({ code: "SESSION_LIMIT_INVALID" }),
		);
	});
});
