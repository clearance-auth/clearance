/**
 * Audit retention tests (FOLLOW.md P2.3.4).
 *
 * The 5000-event cap used to truncate silently. Now: the cap is configurable
 * via CLEARANCE_AUDIT_MAX_EVENTS (validated fail-closed), and truncation
 * records exactly one system.audit.pruned marker per prune with the dropped
 * count and oldest-dropped timestamp. The marker itself cannot recurse.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonStore } from "../store/json-store.js";
import {
	AUDIT_MAX_EVENTS_DEFAULT,
	AUDIT_PRUNED_ACTION,
	auditMaxEvents,
	recordEvent,
} from "../services/audit.js";
import { initProject } from "../services/core.js";

const dirs: string[] = [];

function newStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-audit-retention-"));
	dirs.push(dir);
	const store = new JsonStore(join(dir, "data.json"));
	initProject(store, { name: "Retention App" });
	return store;
}

function record(store: JsonStore, n: number): void {
	for (let i = 0; i < n; i++) {
		recordEvent(store, {
			actor: "test",
			action: "test.noise",
			subjectType: "test",
			outcome: "success",
			source: "system",
			message: `noise ${i}`,
		});
	}
}

afterEach(() => {
	delete process.env.CLEARANCE_AUDIT_MAX_EVENTS;
	for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("audit retention cap", () => {
	it("default cap is unchanged at 5000 and env override is honored", () => {
		expect(auditMaxEvents({})).toBe(5000);
		expect(AUDIT_MAX_EVENTS_DEFAULT).toBe(5000);
		expect(auditMaxEvents({ CLEARANCE_AUDIT_MAX_EVENTS: "250" })).toBe(250);
	});

	it("fails closed on a garbage cap instead of silently defaulting", () => {
		for (const bad of ["banana", "0", "9", "-5", "2.5", "10000000000"]) {
			expect(
				() => auditMaxEvents({ CLEARANCE_AUDIT_MAX_EVENTS: bad }),
				bad,
			).toThrowError(
				expect.objectContaining({ code: "AUDIT_MAX_EVENTS_INVALID" }),
			);
		}
		// ...including from the mutation path itself
		const store = newStore();
		process.env.CLEARANCE_AUDIT_MAX_EVENTS = "banana";
		expect(() => record(store, 1)).toThrowError(
			expect.objectContaining({ code: "AUDIT_MAX_EVENTS_INVALID" }),
		);
	});

	it("emits exactly one system.audit.pruned marker per prune with count + oldest timestamp", () => {
		process.env.CLEARANCE_AUDIT_MAX_EVENTS = "20";
		const store = newStore(); // init already recorded 1 event
		const already = store.snapshot.events.length;
		record(store, 20 - already); // exactly at the cap — no prune yet
		expect(store.snapshot.events.length).toBe(20);
		expect(
			store.snapshot.events.filter((e) => e.action === AUDIT_PRUNED_ACTION),
		).toEqual([]);

		const oldest = store.snapshot.events[store.snapshot.events.length - 1]!;
		record(store, 1); // crosses the cap → one prune

		const events = store.snapshot.events;
		expect(events.length).toBe(20); // marker included, cap never exceeded
		const markers = events.filter((e) => e.action === AUDIT_PRUNED_ACTION);
		expect(markers.length).toBe(1);
		const marker = markers[0]!;
		expect(marker.actor).toBe("system");
		expect(marker.metadata?.droppedCount).toBe(2); // cap-1 kept + marker
		expect(marker.metadata?.oldestDroppedCreatedAt).toBe(oldest.createdAt);
		expect(marker.metadata?.cap).toBe(20);
		// Newest-first: marker sits at the head where it was unshifted
		expect(events[0]!.action).toBe(AUDIT_PRUNED_ACTION);
	});

	it("pruning the marker itself never recurses past the cap", () => {
		process.env.CLEARANCE_AUDIT_MAX_EVENTS = "10";
		const store = newStore();
		// Hammer well past the cap repeatedly; length must never exceed cap.
		for (let i = 0; i < 30; i++) {
			record(store, 1);
			expect(store.snapshot.events.length).toBeLessThanOrEqual(10);
		}
		expect(store.snapshot.events.length).toBe(10);
		expect(store.snapshot.events[0]!.action).toBe(AUDIT_PRUNED_ACTION);
	});

	it("steady state keeps EXACTLY ONE rolling marker with a cumulative count — markers must not displace real retention", () => {
		// Adversarial finding M3: the per-prune marker was itself an event that
		// re-overflowed the cap, converging to ~50% marker density and halving
		// effective retention. The rolling marker must stay singular.
		process.env.CLEARANCE_AUDIT_MAX_EVENTS = "10";
		const store = newStore();
		record(store, 40);
		const events = store.snapshot.events;
		expect(events.length).toBe(10);
		const markers = events.filter((e) => e.action === AUDIT_PRUNED_ACTION);
		expect(markers.length).toBe(1); // exactly one, ever
		const real = events.filter((e) => e.action !== AUDIT_PRUNED_ACTION);
		expect(real.length).toBe(9); // cap - 1 real events retained
		// Cumulative count: initProject emitted 1 event, we added 40; 10 slots
		// hold 1 marker + 9 real, so 41 - 9 = 32 real events were dropped.
		const meta = markers[0]!.metadata as { droppedCount: number };
		expect(meta.droppedCount).toBe(32);
	});
});
