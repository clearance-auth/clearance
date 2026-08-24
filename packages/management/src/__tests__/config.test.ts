import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	parseConfigJson,
	setConfig,
	setConfigAuthoritative,
	validateConfig,
	validateConfigAuthoritative,
} from "../services/config.js";
import { initProject } from "../services/core.js";
import { JsonStore } from "../store/json-store.js";
import { resolveOperatorScopeAuthoritative } from "../services/scope.js";
import type { ManagementStore } from "../store/types.js";

const directories: string[] = [];

function thrownCode(fn: () => unknown): string {
	try {
		fn();
	} catch (error) {
		return (error as { code: string }).code;
	}
	throw new Error("Expected a ClearanceError");
}

afterEach(() => {
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("config service", () => {
	it("validates scope, rejects duplicate JSON and stores no config values in audit metadata", () => {
		const directory = mkdtempSync(join(tmpdir(), "clr-config-service-"));
		directories.push(directory);
		const store = new JsonStore(join(directory, "data.json"));
		const initialized = initProject(store, { name: "Config" });

		expect(parseConfigJson('{"feature":"enabled"}')).toEqual({ feature: "enabled" });
		expect(() => parseConfigJson('{"feature":"one","feature":"two"}')).toThrow(/duplicate/i);
		expect(thrownCode(() => validateConfig(store, { apiKey: "safe-looking" }))).toBe("CONFIG_SECRET_FORBIDDEN");
		expect(thrownCode(() => validateConfig(store, { projectId: "missing" }))).toBe("CONFIG_PROJECT_NOT_FOUND");
		expect(thrownCode(() => validateConfig(store, ["not", "an", "object"]))).toBe("CONFIG_INVALID");
		expect(thrownCode(() => validateConfig(store, { feature: true }))).toBe("CONFIG_INVALID");

		const result = setConfig(store, "feature", "enabled");
		expect(result.changed).toBe(true);
		expect(store.snapshot.meta.config.feature).toBe("enabled");
		expect(store.snapshot.events[0]?.metadata).toEqual({ key: "feature" });
		expect(store.snapshot.events[0]?.metadata).not.toHaveProperty("value");
		expect(thrownCode(() => validateConfig(store, {
			projectId: initialized.project.id,
			environmentId: "missing",
		}))).toBe("CONFIG_ENVIRONMENT_NOT_FOUND");
	});

	it("uses exact relational parentage after topology cutover", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clr-config-topology-"));
		directories.push(directory);
		const jsonStore = new JsonStore(join(directory, "data.json"));
		const { project, environment } = initProject(jsonStore, { name: "Topology Config" });
		const otherProject = { ...project, id: "proj_other" };
		const otherEnvironment = {
			...environment,
			id: "env_other",
			projectId: otherProject.id,
		};
		const store = {
			snapshot: {
				...structuredClone(jsonStore.snapshot),
				projects: [],
				environments: [],
				meta: {
					...jsonStore.snapshot.meta,
					config: {},
				},
			},
			storeV2Topology: {
				authoritative: true,
				getProjectById: async (id: string) =>
					[id === project.id ? project : null, id === otherProject.id ? otherProject : null]
						.find(Boolean) ?? null,
				getEnvironment: async ({ projectId, id }: { projectId: string; id: string }) =>
					[environment, otherEnvironment].find(
						(candidate) => candidate.projectId === projectId && candidate.id === id,
					) ?? null,
				listProjectsPage: async () => ({ projects: [project], hasMore: false }),
				listEnvironmentsPage: async ({ projectId }: { projectId: string }) => ({
					environments: projectId === project.id ? [environment] : [],
					hasMore: false,
				}),
			},
		} as unknown as ManagementStore;

		await expect(resolveOperatorScopeAuthoritative(store)).resolves.toEqual({
			projectId: project.id,
			environmentId: environment.id,
		});
		await expect(resolveOperatorScopeAuthoritative(store, {
			projectId: project.id,
			environmentId: otherEnvironment.id,
		})).rejects.toMatchObject({ code: "SCOPE_INVALID", status: 403 });
		await expect(resolveOperatorScopeAuthoritative(store, {
			projectId: "proj_missing",
			environmentId: environment.id,
		})).rejects.toMatchObject({ code: "SCOPE_INVALID", status: 403 });
		await expect(validateConfigAuthoritative(store, {
			projectId: project.id,
			environmentId: environment.id,
		})).resolves.toEqual({ projectId: project.id, environmentId: environment.id });
		await expect(validateConfigAuthoritative(store, {
			projectId: project.id,
			environmentId: otherEnvironment.id,
		})).rejects.toMatchObject({ code: "CONFIG_SCOPE_MISMATCH" });
	});

	it("rechecks topology parentage inside the coordinated config write", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clr-config-atomicity-"));
		directories.push(directory);
		const jsonStore = new JsonStore(join(directory, "data.json"));
		const { project, environment } = initProject(jsonStore, { name: "Atomic Config" });
		const replacementEnvironment = { ...environment, id: "env_replacement" };
		const data = structuredClone(jsonStore.snapshot);
		let auditCount = 0;
		const locks: string[] = [];
		const store = {
			backend: "postgres",
			snapshot: data,
			storeV2Topology: {
				authoritative: true,
				getProjectById: async (id: string) => id === project.id ? project : null,
				getEnvironment: async ({ projectId, id }: { projectId: string; id: string }) =>
					projectId === project.id && id === replacementEnvironment.id ? replacementEnvironment : null,
			},
			mutateCoordinated: async (fn: NonNullable<ManagementStore["mutateCoordinated"]>) =>
				fn({
					data,
					topology: {
						authoritative: true,
						lockProject: async ({ id }: { id: string }) => {
							locks.push(`project:${id}`);
							return id === project.id ? project : null;
						},
						lockEnvironment: async ({ projectId, id }: { projectId: string; id: string }) => {
							locks.push(`environment:${projectId}:${id}`);
							return null;
						},
					},
					appendAudit: () => {
						auditCount += 1;
						return {} as never;
					},
				}),
		} as unknown as ManagementStore;

		await expect(setConfigAuthoritative(store, "environmentId", replacementEnvironment.id))
			.rejects.toMatchObject({ code: "CONFIG_SCOPE_MISMATCH" });
		expect(locks).toEqual([
			`project:${project.id}`,
			`environment:${project.id}:${replacementEnvironment.id}`,
		]);
		expect(data.meta.config.environmentId).toBe(environment.id);
		expect(auditCount).toBe(0);
	});
});
