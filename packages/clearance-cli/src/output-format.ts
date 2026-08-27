import { InvalidArgumentError } from "commander";

export const OUTPUT_FORMATS = ["human", "json", "jsonl", "quiet"] as const;

export type OutputFormat = (typeof OUTPUT_FORMATS)[number];

export interface OutputFormatOptions {
	/** The canonical format selected by the command-line parser. */
	format?: OutputFormat;
	/** Alias suitable for an `--output <format>` option. */
	output?: OutputFormat | string;
	/** Lowest-priority format inferred from an unattended stdout stream. */
	inferredFormat?: OutputFormat;
	/** Deprecated-compatible `--json`: raw successes, versioned envelope errors. */
	json?: boolean;
	jsonl?: boolean;
	quiet?: boolean;
	/** Built-in selector for machine-readable output. */
	jq?: string;
}

export function isOutputFormat(value: unknown): value is OutputFormat {
	return typeof value === "string" && (OUTPUT_FORMATS as readonly string[]).includes(value);
}

export function parseOutputFormat(value: string): OutputFormat {
	if (isOutputFormat(value)) return value;
	throw new InvalidArgumentError(
		`Unknown output format ${JSON.stringify(value)}. Expected one of: ${OUTPUT_FORMATS.join(", ")}.`,
	);
}

/**
 * Resolve old and new CLI flags to one output mode. `--output-format json` is
 * canonical. Explicit format selectors win so `--json` callers can migrate
 * without changing success payloads until they opt into the envelope.
 */
export function selectOutputFormat(opts: Readonly<OutputFormatOptions>): OutputFormat {
	if (opts.format !== undefined) return opts.format;
	if (opts.output !== undefined) return parseOutputFormat(opts.output);
	if (opts.quiet) return "quiet";
	if (opts.jsonl) return "jsonl";
	if (opts.json || opts.jq) return "json";
	if (opts.inferredFormat !== undefined) return opts.inferredFormat;
	return "human";
}
