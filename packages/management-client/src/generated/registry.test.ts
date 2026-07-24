import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as z from "zod";
import { MANAGEMENT_OPERATIONS } from "../../../management/src/contracts/operations.ts";
import { createBrowserManagementClient, createServerManagementClient } from "../client.js";
import { resolveOperationPath } from "../spec.js";
import { assembleManagementOperationRegistry, type OperationSchemaDomain } from "./assemble.js";
import { AUTHORIZATION_OPERATION_SCHEMAS } from "./authorization.js";
import { DATA_OPERATION_SCHEMAS } from "./data-operations.js";
import { DELIVERY_OPERATION_SCHEMAS } from "./delivery.js";
import { ENTERPRISE_OPERATION_SCHEMAS } from "./enterprise.js";
import { ENVIRONMENT_OPERATION_SCHEMAS } from "./environments.js";
import { EVENTS_IDENTITY_OPERATION_SCHEMAS } from "./events-identity.js";
import { OPERATION_METADATA } from "./operation-metadata.js";
import { POLICY_CONFIG_OPERATION_SCHEMAS } from "./policy-config.js";
import { PROJECT_OPERATION_SCHEMAS } from "./projects.js";
import { MANAGEMENT_OPERATION_REGISTRY } from "./registry.js";
import { RESOURCE_OPERATION_SCHEMAS } from "./resources.js";
import { SCHEMA_OPERATION_SCHEMAS } from "./schema-operations.js";
import { SYSTEM_OPERATION_SCHEMAS } from "./system.js";

const currentPaths = {
	"projects.inspect": "/v1/projects/current",
	"environments.inspect": "/v1/environments/current",
} as const;

const confirmationWhen = {
	"sso.test": { inputKey: "live", equals: true },
	"scim.test": { inputKey: "live", equals: true },
} as const;

function canonicalMetadata() {
	return MANAGEMENT_OPERATIONS.map((operation) => ({
		id: operation.id,
		http: {
			method: operation.http.method,
			path: operation.http.path,
			...(currentPaths[operation.id as keyof typeof currentPaths]
				? { currentPath: currentPaths[operation.id as keyof typeof currentPaths] }
				: {}),
		},
		mutation: operation.mutation,
		supportsDryRun: operation.supportsDryRun,
		confirmation: operation.confirmation,
		...(confirmationWhen[operation.id as keyof typeof confirmationWhen]
			? { confirmationWhen: confirmationWhen[operation.id as keyof typeof confirmationWhen] }
			: {}),
	}));
}

function metadataWithoutTransportProjection() {
	return OPERATION_METADATA.map(({
		inputKeys: _inputKeys,
		pathParameters: _pathParameters,
		queryParameters: _queryParameters,
		...metadata
	}) => metadata);
}

describe("generated operation registry kernel", () => {
	it("is a complete exact canonical snapshot and preserves alternate inspect paths", () => {
		expect(OPERATION_METADATA).toHaveLength(127);
		expect(new Set(OPERATION_METADATA.map((operation) => operation.id)).size).toBe(127);
		expect(metadataWithoutTransportProjection()).toEqual(canonicalMetadata());
		expect(Object.keys(MANAGEMENT_OPERATION_REGISTRY).sort()).toEqual(
			OPERATION_METADATA.map((operation) => operation.id).sort(),
		);
		const projectsInspect = OPERATION_METADATA.find((operation) => operation.id === "projects.inspect")!;
		const environmentsInspect = OPERATION_METADATA.find((operation) => operation.id === "environments.inspect")!;
		expect(projectsInspect.http.currentPath).toBe("/v1/projects/current");
		expect(environmentsInspect.http.currentPath).toBe("/v1/environments/current");
		expect(OPERATION_METADATA.find((operation) => operation.id === "service-accounts.inspect")!.pathParameters)
			.toEqual({ organizationId: "id", accountId: "accountId" });
		expect(OPERATION_METADATA.find((operation) => operation.id === "organizations.members.remove")!.pathParameters)
			.toEqual({ organizationId: "id", membershipId: "memberId" });
		expect(Object.isFrozen(OPERATION_METADATA[0]!.pathParameters)).toBe(true);
	});

	it("assembles every domain into one browser-safe typed client surface", async () => {
		const domains = [
			SYSTEM_OPERATION_SCHEMAS,
			PROJECT_OPERATION_SCHEMAS,
			ENVIRONMENT_OPERATION_SCHEMAS,
			EVENTS_IDENTITY_OPERATION_SCHEMAS,
			AUTHORIZATION_OPERATION_SCHEMAS,
			ENTERPRISE_OPERATION_SCHEMAS,
			DELIVERY_OPERATION_SCHEMAS,
			POLICY_CONFIG_OPERATION_SCHEMAS,
			DATA_OPERATION_SCHEMAS,
			SCHEMA_OPERATION_SCHEMAS,
			RESOURCE_OPERATION_SCHEMAS,
		];
		expect(new Set(domains.flatMap((domain) => Object.keys(domain))).size).toBe(127);

		const requests: Array<{ url: string; init: RequestInit }> = [];
		const browser = createBrowserManagementClient({
			baseUrl: "/management",
			registry: MANAGEMENT_OPERATION_REGISTRY,
			createIdempotencyKey: () => "registry-proof",
			fetch: async (url, init) => {
				requests.push({ url, init });
				if (url.includes("/organizations/")) {
					return Response.json({
						dryRun: true,
						organizationId: "org/1",
						membershipId: "member 1",
						membership: {
							id: "member 1", organizationId: "org/1", principalId: "user_1", role: "member",
							status: "active", source: "manual", createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-01T00:00:00.000Z",
						},
						scope: { projectId: "project_1", environmentId: "environment_1" },
					});
				}
				return Response.json({
					environments: [{
						id: "environment_1", projectId: "project_1", name: "Production", slug: "production", kind: "production",
						createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-01T00:00:00.000Z",
					}],
					nextCursor: "next",
					scope: { projectId: "project_1", environmentId: "environment_1" },
				});
			},
		});
		expect(() => createServerManagementClient({
			baseUrl: "https://management.example.test",
			bearerToken: "operator-token",
			registry: MANAGEMENT_OPERATION_REGISTRY,
			fetch: async () => Response.json({}),
		})).not.toThrow();

		const environments = await browser.call("environments.list", { limit: 25, cursor: "after" });
		expect(environments.data.nextCursor).toBe("next");
		expect(requests[0]!.url).toBe("/management/v1/environments?limit=25&cursor=after");
		await browser.call("organizations.members.remove", {
			organizationId: "org/1", membershipId: "member 1", dryRun: true,
		});
		expect(requests[1]!.url).toBe("/management/v1/organizations/org%2F1/members/member%201");
		expect(resolveOperationPath(MANAGEMENT_OPERATION_REGISTRY["projects.inspect"]!, { id: undefined }))
			.toBe("/v1/projects/current");
		expect(MANAGEMENT_OPERATION_REGISTRY["sso.test"]!.confirmationWhen)
			.toEqual({ inputKey: "live", equals: true });
		await expect(browser.call("scim.test", { id: "connection_1", dryRun: true }))
			.rejects.toMatchObject({ code: "MANAGEMENT_PROTOCOL_ERROR" });
		expect(requests).toHaveLength(3);
		await expect(browser.call("scim.test", { id: "connection_1", live: true, dryRun: false }))
			.rejects.toMatchObject({ code: "MANAGEMENT_CLIENT_CONFIRMATION_REQUIRED" });
		expect(requests).toHaveLength(3);
	});

	it("maps semantic delivery filters and accepts only exact one-time-secret response branches", async () => {
		const selected = OPERATION_METADATA.filter((operation) => [
			"delivery.jobs.list",
			"delivery.webhook_endpoints.list",
			"delivery.webhook_endpoints.create",
			"delivery.webhook_endpoints.rotate",
		].includes(operation.id));
		const delivery = Object.fromEntries(selected.map((operation) => [
			operation.id,
			DELIVERY_OPERATION_SCHEMAS[operation.id as keyof typeof DELIVERY_OPERATION_SCHEMAS],
		])) as OperationSchemaDomain;
		const registry = assembleManagementOperationRegistry(selected, [delivery]);
		const requests: string[] = [];
		const client = createBrowserManagementClient({
			baseUrl: "/management",
			registry,
			fetch: async (url) => {
				requests.push(url);
				return Response.json({ schemaVersion: "v1", scope: { projectId: "project_1", environmentId: "environment_1" }, items: [], nextCursor: null });
			},
		});
		await client.call("delivery.jobs.list", { states: ["queued", "retry"] });
		await client.call("delivery.webhook_endpoints.list", { statuses: ["active", "disabled"] });
		expect(requests).toEqual([
			"/management/v1/delivery/jobs?state=queued&state=retry",
			"/management/v1/delivery/webhook-endpoints?status=active&status=disabled",
		]);

		const endpoint = {
			id: "endpoint_1", projectId: "project_1", environmentId: "environment_1", name: "Primary",
			url: "https://hooks.example.test", status: "active", eventKinds: ["organization.updated"],
			urlFingerprint: "url_fingerprint", secretFingerprint: "secret_fingerprint", secretVersion: 1,
			resourceVersion: 1, lastTestJobId: null, lastTestRequestedAt: null,
			createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-01T00:00:00.000Z", deletedAt: null,
		};
		const scope = { projectId: "project_1", environmentId: "environment_1" };
		const createFirst = {
			schemaVersion: "v1", operation: "delivery.webhook_endpoints.create", storeBackend: "postgres",
			scope, endpoint, signingSecret: "whsec_create",
		};
		const createReplay = {
			schemaVersion: "v1", operation: "delivery.webhook_endpoints.create", storeBackend: "postgres",
			scope, endpoint, secretAlreadyIssued: true, oneTimeSecretsOmitted: ["signingSecret"],
		};
		const rotateBase = {
			schemaVersion: "v1", operation: "delivery.webhook_endpoints.rotate", storeBackend: "postgres", scope,
			endpointId: "endpoint_1", dryRun: false,
			preview: { action: "rotate", endpoint, expectedVersion: 1, nextResourceVersion: 2, nextSecretVersion: 2, secretGenerated: false },
		};
		const rotateFirst = { ...rotateBase, result: { endpoint, signingSecret: "whsec_rotate" } };
		const rotateReplay = {
			...rotateBase,
			result: { endpoint },
			secretAlreadyIssued: true,
			oneTimeSecretsOmitted: ["result.signingSecret"],
		};
		const createOutput = registry["delivery.webhook_endpoints.create"]!.schemas.output;
		const rotateOutput = registry["delivery.webhook_endpoints.rotate"]!.schemas.output;
		expect(createOutput.safeParse(createFirst).success).toBe(true);
		expect(createOutput.safeParse(createReplay).success).toBe(true);
		expect(createOutput.safeParse({ ...createReplay, signingSecret: "whsec_leak" }).success).toBe(false);
		expect(rotateOutput.safeParse(rotateFirst).success).toBe(true);
		expect(rotateOutput.safeParse(rotateReplay).success).toBe(true);
		expect(rotateOutput.safeParse({ ...rotateReplay, result: { endpoint, signingSecret: "whsec_leak" } }).success).toBe(false);
		const { secretAlreadyIssued: _omittedMarker, ...rotateReplayWithoutMarker } = rotateReplay;
		expect(rotateOutput.safeParse(rotateReplayWithoutMarker).success).toBe(false);
	});

	it("derives semantic transport and fails closed for schema coverage or invalid descriptors", () => {
		const selected = OPERATION_METADATA.filter((operation) =>
			["projects.inspect", "projects.create", "environments.inspect"].includes(operation.id),
		);
		const projects: OperationSchemaDomain = {
			"projects.inspect": PROJECT_OPERATION_SCHEMAS["projects.inspect"],
			"projects.create": PROJECT_OPERATION_SCHEMAS["projects.create"],
		};
		const environments: OperationSchemaDomain = {
			"environments.inspect": ENVIRONMENT_OPERATION_SCHEMAS["environments.inspect"],
		};
		const registry = assembleManagementOperationRegistry(selected, [projects, environments]);
		expect(Object.getPrototypeOf(registry)).toBeNull();
		expect(registry["projects.inspect"]!.transport).toEqual({ path: { id: "id" }, query: {}, body: [] });
		expect(registry["projects.create"]!.transport).toEqual({ path: {}, query: {}, body: ["name", "dryRun"] });
		expect(resolveOperationPath(registry["projects.inspect"]!, { id: undefined })).toBe("/v1/projects/current");
		const membersRemove = OPERATION_METADATA.find((operation) => operation.id === "organizations.members.remove")!;
		const members = assembleManagementOperationRegistry([membersRemove], [{
			"organizations.members.remove": {
				input: z.object({ organizationId: z.string(), membershipId: z.string(), dryRun: z.boolean().optional() }).strict(),
				output: z.object({ membershipId: z.string() }).strict(),
			},
		}]);
		expect(members["organizations.members.remove"]!.transport).toEqual({
			path: { organizationId: "id", membershipId: "memberId" }, query: {}, body: ["dryRun"],
		});
		expect(resolveOperationPath(members["organizations.members.remove"]!, {
			organizationId: "org/1", membershipId: "member 1",
		})).toBe("/v1/organizations/org%2F1/members/member%201");

		expect(() => assembleManagementOperationRegistry(OPERATION_METADATA, [
			SYSTEM_OPERATION_SCHEMAS,
			PROJECT_OPERATION_SCHEMAS,
			ENVIRONMENT_OPERATION_SCHEMAS,
		])).toThrow("missing its schema pair");
		expect(() => assembleManagementOperationRegistry(selected, [projects, environments, {
			"unknown.operation": PROJECT_OPERATION_SCHEMAS["projects.create"],
		}])).toThrow("no canonical metadata");
		expect(() => assembleManagementOperationRegistry([
			{ ...OPERATION_METADATA[0]!, supportsDryRun: true },
		], [{ "system.init": SYSTEM_OPERATION_SCHEMAS["system.init"] }])).toThrow("supportsDryRun");
		expect(() => assembleManagementOperationRegistry([
			{ ...OPERATION_METADATA[0]!, inputKeys: ["name"] },
		], [{ "system.init": SYSTEM_OPERATION_SCHEMAS["system.init"] }])).toThrow("project every logical input key");
		expect(() => assembleManagementOperationRegistry([
			{ ...OPERATION_METADATA.find((operation) => operation.id === "projects.inspect")!, pathParameters: { projectId: "id" } },
		], [{ "projects.inspect": PROJECT_OPERATION_SCHEMAS["projects.inspect"] }]))
			.toThrow("path projection");
	});

	it("rejects non-contract inputs and outputs without importing Management runtime into the browser entry", async () => {
		expect(MANAGEMENT_OPERATION_REGISTRY["environments.list"]!.schemas.input.safeParse({
			limit: 1, unexpected: true,
		}).success).toBe(false);
		const browser = createBrowserManagementClient({
			baseUrl: "/management",
			registry: MANAGEMENT_OPERATION_REGISTRY,
			fetch: async () => Response.json({
				environments: [], nextCursor: null, scope: { projectId: "project_1", environmentId: "environment_1" }, unexpected: true,
			}),
		});
		await expect(browser.call("environments.list", {})).rejects.toMatchObject({
			code: "MANAGEMENT_PROTOCOL_ERROR",
		});
		const browserEntry = readFileSync(new URL("../index.ts", import.meta.url), "utf8");
		const registryEntry = readFileSync(new URL("./registry.ts", import.meta.url), "utf8");
		expect(`${browserEntry}\n${registryEntry}`).not.toMatch(/(?:node:|management\/src|@clearance\/management)/);
	});
});
