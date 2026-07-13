import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	JsonStore,
	createOrganization,
	createScimConnection,
	createUser,
	exportEvents,
	initProject,
	inspectEvent,
	listEvents,
	replayDiagnosticTrace,
	testScimConnection,
	EVENTS_EXPORT_MAX_LIMIT,
	beginEventsTail,
	pollEventsTail,
} from "../index.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-events-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
});

describe("events export", () => {
	it("exports deterministically, redacts secrets, respects bounds and scope", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Export App" });
		createUser(store, { email: "a@ex.test", name: "A" });
		createUser(store, { email: "b@ex.test", name: "B" });
		const org = createOrganization(store, { name: "Org" });

		// Inject a sensitive-looking metadata key that must never leave the export
		store.mutate((data) => {
			if (data.events[0]) {
				data.events[0] = {
					...data.events[0],
					metadata: {
						...(data.events[0].metadata ?? {}),
						clientSecret: "sk_live_should_redact",
						token: "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
						note: "safe",
					},
				};
			}
		});

		const first = exportEvents(store, {
			limit: 10,
			skipAudit: true,
			scope: { projectId: project.id, environmentId: environment.id },
		});
		const second = exportEvents(store, {
			limit: 10,
			skipAudit: true,
			scope: { projectId: project.id, environmentId: environment.id },
		});

		expect(first.schemaVersion).toBe(1);
		expect(first.kind).toBe("events.export");
		expect(first.count).toBeGreaterThan(0);
		expect(first.events.map((e) => e.id)).toEqual(second.events.map((e) => e.id));
		expect(first.events.map((e) => e.createdAt)).toEqual(
			second.events.map((e) => e.createdAt),
		);

		// Ordering: newest first, then id desc
		for (let i = 1; i < first.events.length; i++) {
			const a = first.events[i - 1]!;
			const b = first.events[i]!;
			const ok =
				a.createdAt > b.createdAt ||
				(a.createdAt === b.createdAt && a.id >= b.id);
			expect(ok).toBe(true);
		}

		const serialized = JSON.stringify(first);
		expect(serialized).not.toContain("sk_live_should_redact");
		expect(serialized).not.toContain("Bearer eyJ");
		expect(serialized).toMatch(/\[redacted\]/);

		const bounded = exportEvents(store, {
			limit: 1,
			skipAudit: true,
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(bounded.count).toBe(1);
		expect(bounded.truncated).toBe(true);

		const byAction = exportEvents(store, {
			action: "orgs.create",
			skipAudit: true,
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(byAction.events.every((e) => e.action === "orgs.create")).toBe(true);
		expect(byAction.events.some((e) => e.organizationId === org.id)).toBe(true);

		expect(() =>
			exportEvents(store, {
				limit: EVENTS_EXPORT_MAX_LIMIT + 1,
				skipAudit: true,
			}),
		).toThrow(/limit/i);

		expect(() =>
			exportEvents(store, {
				format: "csv",
				skipAudit: true,
			}),
		).toThrow(/format/i);

		// Wrong scope yields empty (no foreign leakage)
		const foreign = exportEvents(store, {
			skipAudit: true,
			scope: { projectId: "proj_other", environmentId: "env_other" },
		});
		expect(foreign.count).toBe(0);
		expect(foreign.events).toEqual([]);

		// Legacy/unscoped records must not be treated as globally visible.
		store.mutate((data) => {
			data.events.unshift({
				id: "evt_unscoped_secret",
				correlationId: "corr_unscoped",
				actor: "legacy",
				action: "legacy.unscoped",
				subjectType: "legacy",
				outcome: "success",
				source: "system",
				message: "must not cross tenant scope",
				createdAt: new Date().toISOString(),
			});
		});
		const scoped = exportEvents(store, {
			skipAudit: true,
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(scoped.events.some((e) => e.id === "evt_unscoped_secret")).toBe(false);
	});

	it("writes atomic file artifacts and refuses overwrite without force", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "File Export" });
		createUser(store, { email: "f@ex.test", name: "F" });
		const out = join(dirs[0]!, "events-out.json");

		const envelope = exportEvents(store, {
			outputPath: out,
			format: "json",
			limit: 50,
			scope: { projectId: project.id, environmentId: environment.id },
			actor: "test",
			source: "cli",
		});
		expect(envelope.outputPath).toBe(out);
		expect(existsSync(out)).toBe(true);
		const body = JSON.parse(readFileSync(out, "utf8"));
		expect(body.kind).toBe("events.export");
		expect(body.events.length).toBe(envelope.count);

		// Export itself audited
		expect(
			listEvents(store, { limit: 20 }).some((e) => e.action === "events.export"),
		).toBe(true);

		expect(() =>
			exportEvents(store, {
				outputPath: out,
				force: false,
				skipAudit: true,
				scope: { projectId: project.id, environmentId: environment.id },
			}),
		).toThrow(/exists|overwrite/i);

		const again = exportEvents(store, {
			outputPath: out,
			force: true,
			skipAudit: true,
			format: "jsonl",
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(again.format).toBe("jsonl");
		const jsonl = readFileSync(out, "utf8").trim();
		if (again.count > 0) {
			const lines = jsonl.split("\n");
			expect(lines.length).toBe(again.count);
			expect(JSON.parse(lines[0]!).id).toBeTruthy();
		}

		// Empty export is valid machine-readable output
		const emptyPath = join(dirs[0]!, "empty.json");
		const empty = exportEvents(store, {
			outputPath: emptyPath,
			action: "never.matches.this.action",
			skipAudit: true,
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(empty.count).toBe(0);
		expect(JSON.parse(readFileSync(emptyPath, "utf8")).events).toEqual([]);
	});
});

describe("events tail selection", () => {
	it("emits bounded initial history chronologically and polls only new redacted scoped events", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Tail App" });
		const scope = { projectId: project.id, environmentId: environment.id };
		store.mutate((data) => {
			data.events = [
				{
					id: "evt_3", correlationId: "corr_3", ...scope, organizationId: "org_keep", actor: "three", action: "users.create", subjectType: "user", outcome: "success", source: "cli", message: "three", createdAt: "2026-01-01T00:00:03.000Z",
				},
				{
					id: "evt_2", correlationId: "corr_2", ...scope, organizationId: "org_keep", actor: "two", action: "users.create", subjectType: "user", outcome: "success", source: "cli", message: "two", createdAt: "2026-01-01T00:00:02.000Z",
				},
				{
					id: "evt_2", correlationId: "corr_2_duplicate", ...scope, organizationId: "org_keep", actor: "duplicate", action: "users.create", subjectType: "user", outcome: "success", source: "cli", message: "duplicate", createdAt: "2026-01-01T00:00:02.000Z",
				},
				{
					id: "evt_1", correlationId: "corr_1", ...scope, organizationId: "org_keep", actor: "one", action: "users.create", subjectType: "user", outcome: "success", source: "cli", message: "one", createdAt: "2026-01-01T00:00:01.000Z",
				},
				{
					id: "evt_foreign", correlationId: "corr_foreign", projectId: "proj_foreign", environmentId: "env_foreign", organizationId: "org_keep", actor: "foreign", action: "users.create", subjectType: "user", outcome: "success", source: "cli", message: "foreign", createdAt: "2026-01-01T00:00:04.000Z",
				},
			];
		});

		const { cursor, events } = beginEventsTail(store, {
			limit: 2,
			action: "users.create",
			organizationId: "org_keep",
			scope,
		});
		expect(events.map((event) => event.id)).toEqual(["evt_2", "evt_3"]);

		store.mutate((data) => {
			data.events.unshift({
				id: "evt_4", correlationId: "corr_4", ...scope, organizationId: "org_keep", actor: "four", action: "users.create", subjectType: "user", outcome: "success", source: "cli", message: "four", metadata: { token: "secret", safe: "visible" }, createdAt: "2026-01-01T00:00:04.000Z",
			});
			data.events.unshift({
				id: "evt_other_action", correlationId: "corr_other", ...scope, organizationId: "org_keep", actor: "other", action: "orgs.create", subjectType: "org", outcome: "success", source: "cli", message: "other", createdAt: "2026-01-01T00:00:05.000Z",
			});
		});
		const polled = pollEventsTail(store, cursor);
		expect(polled.map((event) => event.id)).toEqual(["evt_4"]);
		expect(polled[0]?.metadata).toEqual({ token: "[redacted]", safe: "visible" });
		expect(pollEventsTail(store, cursor)).toEqual([]);
	});
});

describe("events replay (SCIM diagnostic only)", () => {
	it("dry-run by default, confirm applies, idempotent, non-replayable fail closed", () => {
		const store = tempStore();
		initProject(store, { name: "Replay App" });
		const org = createOrganization(store, { name: "Cust" });
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
		});
		const tested = testScimConnection(store, scim.id, { dryRun: true });
		const traceId = tested.trace.id;

		const dry = replayDiagnosticTrace(store, traceId, { dryRun: true });
		expect(dry.dryRun).toBe(true);
		expect(dry.wouldChange).toBe(true);
		expect(dry.idempotent).toBe(false);
		expect(dry.trace.stage).toMatch(/\.replay$/);
		// Dry-run must not persist a new trace
		expect(store.snapshot.traces.filter((t) => t.stage.endsWith(".replay")).length).toBe(
			0,
		);

		// confirm=false (default) also dry-runs
		const implicit = replayDiagnosticTrace(store, traceId, {});
		expect(implicit.dryRun).toBe(true);

		const applied = replayDiagnosticTrace(store, traceId, {
			confirm: true,
			actor: "tester",
			source: "cli",
		});
		expect(applied.dryRun).toBe(false);
		expect(applied.idempotent).toBe(false);
		expect(applied.trace.id).not.toBe(traceId);
		expect(applied.trace.stage).toMatch(/\.replay$/);
		expect(
			listEvents(store, { limit: 50 }).some((e) => e.action === "scim.replay"),
		).toBe(true);

		const again = replayDiagnosticTrace(store, traceId, {
			confirm: true,
			actor: "tester",
			source: "cli",
		});
		expect(again.idempotent).toBe(true);
		expect(again.trace.id).toBe(applied.trace.id);
		expect(again.wouldChange).toBe(false);

		// Audit event ids are never replayable
		const auditId = listEvents(store, { limit: 5 })[0]!.id;
		expect(() =>
			replayDiagnosticTrace(store, auditId, { confirm: true }),
		).toThrow(/not replayable|not found/i);

		// Missing
		expect(() =>
			replayDiagnosticTrace(store, "tr_missing", { dryRun: true }),
		).toThrow(/not found/i);

		// Already-replay artifact
		expect(() =>
			replayDiagnosticTrace(store, applied.trace.id, { confirm: true }),
		).toThrow(/not replayable|replay artifact/i);
	});

	it("fail closed for wrong scope", () => {
		const store = tempStore();
		initProject(store, { name: "Scope Replay" });
		const org = createOrganization(store, { name: "Scoped" });
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
		});
		const tested = testScimConnection(store, scim.id, { dryRun: true });

		expect(() =>
			replayDiagnosticTrace(store, tested.trace.id, {
				dryRun: true,
				scope: { projectId: "proj_wrong", environmentId: "env_wrong" },
			}),
		).toThrow(/not found/i);

		expect(() =>
			inspectEvent(store, tested.trace.id, {
				scope: { projectId: "proj_wrong", environmentId: "env_wrong" },
			}),
		).toThrow(/not found/i);
	});

	it("inspect distinguishes audit events vs SCIM traces", () => {
		const store = tempStore();
		initProject(store, { name: "Inspect" });
		const org = createOrganization(store, { name: "O" });
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
		});
		const tested = testScimConnection(store, scim.id, { dryRun: true });

		const auditId = listEvents(store, { limit: 5 }).find(
			(e) => e.action === "orgs.create",
		)!.id;
		const evt = inspectEvent(store, auditId);
		expect(evt.event?.id).toBe(auditId);
		expect(evt.replayable).toBe(false);
		expect(evt.replayBlocker).toMatch(/not replayable/i);

		const tr = inspectEvent(store, tested.trace.id);
		expect(tr.trace?.id).toBe(tested.trace.id);
		expect(tr.replayable).toBe(true);
	});
});

describe("events export empty input", () => {
	it("handles empty event log without throwing", () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-empty-evt-"));
		dirs.push(dir);
		const path = join(dir, "data.json");
		// Minimal initialized-like store with zero events
		const store = new JsonStore(path);
		initProject(store, { name: "Empty" });
		store.mutate((d) => {
			d.events = [];
		});
		const out = join(dir, "out.json");
		const envelope = exportEvents(store, {
			outputPath: out,
			skipAudit: true,
		});
		expect(envelope.count).toBe(0);
		expect(envelope.events).toEqual([]);
		expect(JSON.parse(readFileSync(out, "utf8")).events).toEqual([]);
		// Ensure no stray tmp files
		const listing = readFileSync(out, "utf8");
		expect(listing).toBeTruthy();
		expect(existsSync(`${out}.tmp`)).toBe(false);
	});
});
