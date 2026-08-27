import type { CommandSpecDocument } from "./command-spec.js";
import { OUTPUT_PROTOCOL, OUTPUT_PROTOCOL_VERSION } from "./output.js";

export const EXPERIENCE_MANIFEST_VERSION = 1 as const;

export interface ExperienceManifest {
	readonly manifestVersion: typeof EXPERIENCE_MANIFEST_VERSION;
	readonly outputProtocol: {
		readonly name: typeof OUTPUT_PROTOCOL;
		readonly version: typeof OUTPUT_PROTOCOL_VERSION;
		readonly canonicalFlag: "--output-format json";
		readonly selectorScope: "envelope";
	};
	readonly legacyJson: {
		readonly flag: "--json";
		readonly status: "deprecated-compatible";
		readonly successShape: "raw-command-result";
		readonly errorShape: "versioned-envelope";
		readonly replacement: "--output-format json";
	};
	readonly operationReceipts: {
		readonly name: "clearance.cli.execution-receipt";
		readonly version: 1;
		readonly outcomes: readonly [
			"succeeded",
			"rejected",
			"failed_before_dispatch",
			"indeterminate",
		];
	};
	readonly commands: CommandSpecDocument;
}

/**
 * The shared, serializable authority for CLI, agent, and TUI renderers.
 * Callers supply the same command document used by `clearance commands` so
 * parser parity and experience metadata cannot silently diverge.
 */
export function buildExperienceManifest(commands: CommandSpecDocument): ExperienceManifest {
	return Object.freeze({
		manifestVersion: EXPERIENCE_MANIFEST_VERSION,
		outputProtocol: Object.freeze({
			name: OUTPUT_PROTOCOL,
			version: OUTPUT_PROTOCOL_VERSION,
			canonicalFlag: "--output-format json",
			selectorScope: "envelope",
		}),
		legacyJson: Object.freeze({
			flag: "--json",
			status: "deprecated-compatible",
			successShape: "raw-command-result",
			errorShape: "versioned-envelope",
			replacement: "--output-format json",
		}),
		operationReceipts: Object.freeze({
			name: "clearance.cli.execution-receipt",
			version: 1,
			outcomes: Object.freeze([
				"succeeded",
				"rejected",
				"failed_before_dispatch",
				"indeterminate",
			] as const),
		}),
		commands,
	});
}
