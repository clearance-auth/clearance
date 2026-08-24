import { describe, expect, it } from "vitest";
import {
	advancingPrincipalUpdatedAt,
	mapStoreV2PrincipalRow,
	normalizeStoreV2PrincipalCursor,
	translateStoreV2PrincipalError,
} from "./store-v2-principals.js";
import {
	parseStoreV2MetadataInteger,
	storeV2PrincipalEmailUniqueIndex,
	storeV2PrincipalExternalIdUniqueIndex,
	storeV2TableNames,
} from "./store-v2-schema.js";

describe("store-v2 principal mapping", () => {
	it("always advances same-millisecond OCC tokens", () => {
		expect(
			advancingPrincipalUpdatedAt({ proposedUpdatedAt: "2026-07-15T00:00:00.000Z", storedUpdatedAt: "2026-07-15T00:00:00.000Z" }),
		).toBe("2026-07-15T00:00:00.001Z");
		expect(
			advancingPrincipalUpdatedAt({ proposedUpdatedAt: "2026-07-14T23:59:59.999Z", storedUpdatedAt: "2026-07-15T00:00:00.001Z" }),
		).toBe("2026-07-15T00:00:00.002Z");
	});
	it("maps every principal field and normalizes timestamps", () => {
		const principal = mapStoreV2PrincipalRow({
			id: "user_one",
			project_id: "proj_one",
			environment_id: "env_one",
			email: "one@example.test",
			name: "One",
			status: "disabled",
			external_id: "external-one",
			created_at: new Date("2026-07-15T00:00:00Z"),
			updated_at: "2026-07-15T01:00:00+00:00",
		});

		expect(principal).toEqual({
			id: "user_one",
			projectId: "proj_one",
			environmentId: "env_one",
			email: "one@example.test",
			name: "One",
			status: "disabled",
			externalId: "external-one",
			createdAt: "2026-07-15T00:00:00.000Z",
			updatedAt: "2026-07-15T01:00:00.000Z",
		});
	});

	it("omits a null external id", () => {
		const principal = mapStoreV2PrincipalRow({
			id: "user_two",
			project_id: "proj_one",
			environment_id: "env_one",
			email: "two@example.test",
			name: "Two",
			status: "deleted",
			external_id: null,
			created_at: "2026-07-15T00:00:00.000Z",
			updated_at: "2026-07-15T00:00:00.000Z",
		});

		expect(principal).not.toHaveProperty("externalId");
	});

	it("parses metadata integers strictly and rejects unsafe revisions", () => {
		expect(parseStoreV2MetadataInteger(0)).toBe(0);
		expect(parseStoreV2MetadataInteger(Number.MAX_SAFE_INTEGER)).toBe(
			Number.MAX_SAFE_INTEGER,
		);
		expect(parseStoreV2MetadataInteger("42")).toBe(42);
		for (const invalid of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, "-1", "01", "1.5", "", "9007199254740992"]) {
			expect(parseStoreV2MetadataInteger(invalid)).toBeNull();
		}
	});

	it("accepts only canonical principal cursor keys", () => {
		expect(
			normalizeStoreV2PrincipalCursor({
				createdAt: "2026-07-15T01:02:03.004Z",
				id: "user_one",
			}),
		).toEqual({
			createdAt: "2026-07-15T01:02:03.004Z",
			id: "user_one",
		});
		for (const cursor of [
			{ createdAt: "0", id: "user_one" },
			{ createdAt: "2026-07-15T01:02:03Z", id: "user_one" },
			{ createdAt: "2026-07-15T01:02:03.004+00:00", id: "user_one" },
			{ createdAt: "2026-07-15T01:02:03.004Z", id: "bad\0id" },
		]) {
			expect(() => normalizeStoreV2PrincipalCursor(cursor)).toThrow(
				"The principal page cursor is invalid.",
			);
		}
	});

	it("sanitizes PostgreSQL errors using the exact derived email index", () => {
		const tables = storeV2TableNames(`${"p".repeat(30)}_`);
		const emailIndex = storeV2PrincipalEmailUniqueIndex(tables);
		const externalIdIndex = storeV2PrincipalExternalIdUniqueIndex(tables);
		expect(emailIndex.length).toBeLessThanOrEqual(63);
		const email = translateStoreV2PrincipalError(
			{
				code: "23505",
				constraint: emailIndex,
				detail: "Key (email)=(secret@example.test) already exists",
			},
			tables,
		);
		expect(email).toMatchObject({
			code: "STORE_V2_PRINCIPAL_EMAIL_CONFLICT",
		});
		expect(JSON.stringify(email)).not.toContain("secret@example.test");
		expect(translateStoreV2PrincipalError({
			code: "23505",
			constraint: externalIdIndex,
			detail: "Key (external_id)=(secret-provider-id) already exists",
		}, tables)).toMatchObject({
			code: "STORE_V2_PRINCIPAL_EXTERNAL_ID_CONFLICT",
		});
		const unknown = translateStoreV2PrincipalError({
			code: "XX999",
			detail: "internal query text",
		});
		expect(unknown).toMatchObject({ code: "STORE_V2_PRINCIPAL_WRITE_FAILED" });
		expect(JSON.stringify(unknown)).not.toContain("internal query text");
	});
});
