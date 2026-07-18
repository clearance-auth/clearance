import { describe, expect, expectTypeOf, it } from "vitest";
import type { ResourceScope } from "../services/scope.js";
import type { Principal } from "../types/resources.js";
import {
	API_KEY_OPERATIONS,
	AUTHENTICATION_POLICY_OPERATIONS,
	BACKUP_OPERATIONS,
	CONFIG_OPERATIONS,
	DELIVERY_OPERATIONS,
	ENVIRONMENT_OPERATIONS,
	EVENT_OPERATIONS,
	IMPORT_OPERATIONS,
	MANAGEMENT_OPERATIONS,
	MEMBER_OPERATIONS,
	MIGRATION_OPERATIONS,
	ORGANIZATION_OPERATIONS,
	PROJECT_OPERATIONS,
	READINESS_OPERATIONS,
	resolveOperationPath,
	ROLE_OPERATIONS,
	SCIM_OPERATIONS,
	SCHEMA_OPERATIONS,
	STORE_V2_OPERATIONS,
	SESSION_OPERATIONS,
	SSO_OPERATIONS,
	USER_OPERATIONS,
	UPGRADE_OPERATIONS,
	SYSTEM_OPERATIONS,
	WEBHOOK_ENDPOINT_OPERATIONS,
	type OperationOutput,
} from "./operations.js";

describe("management operation contracts", () => {
	it("keeps stable IDs and CLI paths unique", () => {
		const ids = MANAGEMENT_OPERATIONS.map((operation) => operation.id);
		const cliPaths = MANAGEMENT_OPERATIONS.map((operation) => operation.cliPath);
		expect(new Set(ids).size).toBe(ids.length);
		expect(new Set(cliPaths).size).toBe(cliPaths.length);
	});

	it("defines the complete users transport contract", () => {
		expect(Object.values(USER_OPERATIONS)).toHaveLength(7);
		expect(USER_OPERATIONS.create).toMatchObject({
			id: "users.create",
			cliPath: "users create",
			http: { method: "POST", path: "/v1/users" },
			mutation: true,
			supportsDryRun: true,
			confirmation: "none",
		});
		expect(USER_OPERATIONS.delete.confirmation).toBe("client-required");
		expect(USER_OPERATIONS.export.mutation).toBe(true);
		expectTypeOf<OperationOutput<"users.delete">>().toEqualTypeOf<{
			user: Principal;
			scope: ResourceScope;
		}>();
	});

	it("defines organization and nested membership policies explicitly", () => {
		expect(MANAGEMENT_OPERATIONS).toHaveLength(110);
		expect(ORGANIZATION_OPERATIONS.archive).toMatchObject({
			id: "organizations.archive",
			http: { method: "POST", path: "/v1/organizations/:id/archive" },
			mutation: true,
			supportsDryRun: true,
			confirmation: "server-required",
		});
		expect(MEMBER_OPERATIONS.remove.confirmation).toBe("client-required");
		expect(MEMBER_OPERATIONS.import.confirmation).toBe("server-required");
	});

	it("defines revisioned authentication-policy preview and mutation safety", () => {
		expect(Object.values(AUTHENTICATION_POLICY_OPERATIONS)).toHaveLength(4);
		expect(AUTHENTICATION_POLICY_OPERATIONS.get).toMatchObject({
			id: "authentication_policy.get",
			cliPath: "auth-policy get",
			http: { method: "GET", path: "/v1/authentication-policy" },
			mutation: false,
			confirmation: "none",
		});
		expect(AUTHENTICATION_POLICY_OPERATIONS.plan).toMatchObject({
			http: { method: "POST", path: "/v1/authentication-policy/plan" },
			mutation: false,
		});
		for (const action of ["apply", "unlock"] as const) {
			expect(AUTHENTICATION_POLICY_OPERATIONS[action]).toMatchObject({
				mutation: true,
				supportsDryRun: true,
				confirmation: "server-required",
			});
		}
	});

	it("defines the complete webhook endpoint transport and safety contract", () => {
		expect(Object.values(WEBHOOK_ENDPOINT_OPERATIONS)).toHaveLength(7);
		expect(WEBHOOK_ENDPOINT_OPERATIONS.list).toMatchObject({
			id: "delivery.webhook_endpoints.list",
			cliPath: "delivery endpoints list",
			http: { method: "GET", path: "/v1/delivery/webhook-endpoints" },
			mutation: false,
		});
		expect(WEBHOOK_ENDPOINT_OPERATIONS.create).toMatchObject({
			http: { method: "POST", path: "/v1/delivery/webhook-endpoints" },
			mutation: true,
			supportsDryRun: false,
			confirmation: "none",
		});
		expect(WEBHOOK_ENDPOINT_OPERATIONS.update.http.method).toBe("PATCH");
		expect(WEBHOOK_ENDPOINT_OPERATIONS.delete.http.method).toBe("DELETE");
		for (const action of ["rotate", "delete", "test"] as const) {
			expect(WEBHOOK_ENDPOINT_OPERATIONS[action]).toMatchObject({
				mutation: true,
				supportsDryRun: true,
				confirmation: "server-required",
			});
		}
		expect(resolveOperationPath(WEBHOOK_ENDPOINT_OPERATIONS.test, { id: "wh /1" }))
			.toBe("/v1/delivery/webhook-endpoints/wh%20%2F1/test");
	});

	it("defines the complete delivery transport and safety contract", () => {
		expect(Object.values(DELIVERY_OPERATIONS)).toHaveLength(7);
		expect(DELIVERY_OPERATIONS.list).toMatchObject({
			id: "delivery.jobs.list",
			cliPath: "delivery list",
			http: { method: "GET", path: "/v1/delivery/jobs" },
			mutation: false,
		});
		expect(DELIVERY_OPERATIONS.inspect.http.path).toBe("/v1/delivery/jobs/:id");
		expect(DELIVERY_OPERATIONS.readiness.http.path).toBe("/v1/delivery/readiness");
		expect(DELIVERY_OPERATIONS.quotas).toMatchObject({
			id: "delivery.quotas.get",
			cliPath: "delivery quotas",
			http: { method: "GET", path: "/v1/delivery/quotas" },
			mutation: false,
		});
		for (const action of ["cancel", "retry", "replay"] as const) {
			expect(DELIVERY_OPERATIONS[action]).toMatchObject({
				http: {
					method: "POST",
					path: `/v1/delivery/jobs/:id/${action}`,
				},
				mutation: true,
				supportsDryRun: true,
				confirmation: "server-required",
			});
		}
		expect(resolveOperationPath(DELIVERY_OPERATIONS.replay, { id: "job/a b" }))
			.toBe("/v1/delivery/jobs/job%2Fa%20b/replay");
	});

	it("defines the complete operational registry and terminal safety policies", () => {
		expect(IMPORT_OPERATIONS.legacy.confirmation).toBe("server-required");
		expect(MIGRATION_OPERATIONS.verify).toMatchObject({
			mutation: true,
			supportsDryRun: false,
		});
		expect(MIGRATION_OPERATIONS.rollback.confirmation).toBe("server-required");
		expect(BACKUP_OPERATIONS.verify.mutation).toBe(true);
		expect(BACKUP_OPERATIONS.restore).toMatchObject({
			supportsDryRun: false,
			confirmation: "server-required",
		});
		expect(UPGRADE_OPERATIONS.check).toMatchObject({
			http: { method: "GET" },
			mutation: true,
		});
		expect(UPGRADE_OPERATIONS.apply.confirmation).toBe("server-required");
		expect(UPGRADE_OPERATIONS.rollback.confirmation).toBe("server-required");
		expect(SCHEMA_OPERATIONS.generate).toMatchObject({
			mutation: false,
			supportsDryRun: true,
		});
		expect(SCHEMA_OPERATIONS.migrate.confirmation).toBe("server-required");
		expect(STORE_V2_OPERATIONS.apply).toMatchObject({
			http: { method: "POST", path: "/v1/schema/store-v2/apply" },
			mutation: true,
			supportsDryRun: true,
			confirmation: "server-required",
		});
		expect(STORE_V2_OPERATIONS.verify.mutation).toBe(false);
		expect(STORE_V2_OPERATIONS.rollback.confirmation).toBe("server-required");
		expect(STORE_V2_OPERATIONS.eventsCutover).toMatchObject({
			http: { method: "POST", path: "/v1/schema/store-v2/events/cutover" },
			mutation: true,
			confirmation: "server-required",
		});
		expect(STORE_V2_OPERATIONS.eventsRollback.confirmation).toBe("server-required");
		expect(STORE_V2_OPERATIONS.principalsCutover).toMatchObject({
			http: { method: "POST", path: "/v1/schema/store-v2/principals/cutover" },
			confirmation: "server-required",
		});
		expect(STORE_V2_OPERATIONS.principalsRollback).toMatchObject({
			http: { method: "POST", path: "/v1/schema/store-v2/principals/rollback" },
			confirmation: "server-required",
		});
	});

	it("distinguishes readiness evidence writes from config inspection", () => {
		expect(READINESS_OPERATIONS.check).toMatchObject({
			mutation: true,
			supportsDryRun: false,
		});
		expect(READINESS_OPERATIONS.report.mutation).toBe(false);
		expect(CONFIG_OPERATIONS.set).toMatchObject({
			http: { method: "PATCH", path: "/v1/config/:key" },
			mutation: true,
			supportsDryRun: true,
		});
		expect(CONFIG_OPERATIONS.validate.mutation).toBe(false);
		expect(CONFIG_OPERATIONS.diff.mutation).toBe(false);
	});

	it("makes SSO and SCIM evidence and safety semantics visible", () => {
		expect(Object.values(SSO_OPERATIONS)).toHaveLength(7);
		expect(Object.values(SCIM_OPERATIONS)).toHaveLength(7);
		expect(SSO_OPERATIONS.test).toMatchObject({
			mutation: true,
			supportsDryRun: false,
			confirmation: "client-required-when-live",
		});
		expect(SCIM_OPERATIONS.test).toMatchObject({
			mutation: true,
			supportsDryRun: true,
			confirmation: "client-required-when-live",
		});
		expect(SSO_OPERATIONS.setupLink.supportsDryRun).toBe(false);
		expect(SCIM_OPERATIONS.setupLink.supportsDryRun).toBe(false);
		expect(SCIM_OPERATIONS.replay.confirmation).toBe("server-required");
	});

	it("defines event, key, session, and role policies explicitly", () => {
		expect(Object.values(EVENT_OPERATIONS)).toHaveLength(5);
		expect(EVENT_OPERATIONS.tail).toMatchObject({
			id: "events.tail",
			http: EVENT_OPERATIONS.list.http,
			mutation: false,
		});
		expect(EVENT_OPERATIONS.export).toMatchObject({
			mutation: true,
			supportsDryRun: false,
		});
		expect(EVENT_OPERATIONS.replay.confirmation).toBe("server-required");
		expect(API_KEY_OPERATIONS.rotate.confirmation).toBe("client-required");
		expect(API_KEY_OPERATIONS.revoke.confirmation).toBe("client-required");
		expect(SESSION_OPERATIONS.revoke.confirmation).toBe("client-required");
		expect(ROLE_OPERATIONS.validate).toMatchObject({
			http: { method: "POST" },
			mutation: false,
		});
	});

	it("models current-resource routes without splitting stable operations", () => {
		expect(PROJECT_OPERATIONS.inspect.http).toMatchObject({
			method: "GET",
			path: "/v1/projects/:id",
			currentPath: "/v1/projects/current",
		});
		expect(ENVIRONMENT_OPERATIONS.inspect.http.currentPath)
			.toBe("/v1/environments/current");
		expect(ENVIRONMENT_OPERATIONS.promote.confirmation)
			.toBe("server-required");
		expect(SYSTEM_OPERATIONS.doctor).toMatchObject({
			http: { method: "GET" },
			mutation: true,
		});
	});

	it("resolves and encodes path parameters fail-closed", () => {
		expect(resolveOperationPath(USER_OPERATIONS.inspect, { id: "user/a b" }))
			.toBe("/v1/users/user%2Fa%20b");
		expect(() => resolveOperationPath(USER_OPERATIONS.inspect, {}))
			.toThrow(/Missing path parameter id/);
	});
});
