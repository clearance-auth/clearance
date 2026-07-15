import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseConfigJson, setConfig, validateConfig } from "../services/config.js";
import { initProject } from "../services/core.js";
import { JsonStore } from "../store/json-store.js";

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
});
