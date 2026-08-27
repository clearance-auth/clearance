import { describe, expect, it } from "vitest";
import { buildCommandSpecDocument } from "./command-spec.js";
import {
	buildExperienceManifest,
	EXPERIENCE_MANIFEST_VERSION,
} from "./experience-manifest.js";

describe("experience manifest", () => {
	it("declares one canonical protocol and an exact legacy migration", () => {
		const commands = buildCommandSpecDocument({ operations: [] });
		const manifest = buildExperienceManifest(commands);

		expect(manifest).toMatchObject({
			manifestVersion: EXPERIENCE_MANIFEST_VERSION,
			outputProtocol: {
				name: "clearance.cli.output",
				version: 1,
				canonicalFlag: "--output-format json",
				selectorScope: "envelope",
			},
			legacyJson: {
				flag: "--json",
				status: "deprecated-compatible",
				successShape: "raw-command-result",
				errorShape: "versioned-envelope",
				replacement: "--output-format json",
			},
			operationReceipts: {
				name: "clearance.cli.execution-receipt",
				version: 1,
				outcomes: ["succeeded", "rejected", "failed_before_dispatch", "indeterminate"],
			},
		});
		expect(manifest.commands).toBe(commands);
	});
});
