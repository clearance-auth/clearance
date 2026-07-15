import { describe, expect, it } from "vitest";
import {
	cloneSnapshot,
	emptySnapshot,
	normalizeSnapshot,
	snapshotResourceCounts,
} from "./snapshot.js";

describe("management snapshot helpers", () => {
	it("clones with JSON semantics and without shared references", () => {
		const source = emptySnapshot({ example: "value" });
		const clone = cloneSnapshot(source);

		expect(JSON.stringify(clone)).toBe(JSON.stringify(source));
		expect(clone).not.toBe(source);
		clone.meta.config.example = "changed";
		expect(source.meta.config.example).toBe("value");
	});

	it("normalizes legacy collections in place", () => {
		const legacy = emptySnapshot() as ReturnType<typeof emptySnapshot> & {
			roles?: never;
			apiKeys?: never;
			setupLinks?: never;
		};
		delete legacy.roles;
		delete legacy.apiKeys;
		delete legacy.setupLinks;

		const normalized = normalizeSnapshot(legacy);
		expect(normalized).toBe(legacy);
		expect(normalized.roles).toEqual([]);
		expect(normalized.apiKeys).toEqual([]);
		expect(normalized.setupLinks).toEqual([]);
	});

	it("uses one stable count surface and counts only active sessions", () => {
		const snapshot = emptySnapshot();
		snapshot.setupLinks.push({} as never);
		snapshot.sessions.push(
			{ status: "active" } as never,
			{ status: "revoked" } as never,
		);

		expect(snapshotResourceCounts(snapshot)).toEqual({
			projects: 0,
			environments: 0,
			principals: 0,
			organizations: 0,
			memberships: 0,
			identityConnections: 0,
			directoryConnections: 0,
			roles: 0,
			setupLinks: 1,
			events: 0,
			traces: 0,
			migrations: 0,
			sessions: 1,
			apiKeys: 0,
		});
	});
});
