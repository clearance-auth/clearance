import { writeExportArtifact } from "@clearance/management";

export function writeRemoteExport(
	envelope: Record<string, unknown>,
	options: Readonly<Record<string, unknown>>,
	collection: "users" | "events",
): Record<string, unknown> {
	const format = options.format === "jsonl" ? "jsonl" : "json";
	const values = Array.isArray(envelope[collection]) ? envelope[collection] : [];
	let contents = `${JSON.stringify(envelope, null, 2)}\n`;
	if (format === "jsonl") {
		contents = values.length === 0
			? ""
			: `${values.map((value) => JSON.stringify(value)).join("\n")}\n`;
	}
	const outputPath = writeExportArtifact(String(options.output), contents, Boolean(options.force), {
		stage: `${collection}.export`,
		existsCode: `${collection.toUpperCase()}_EXPORT_EXISTS`,
		writeFailedCode: `${collection.toUpperCase()}_EXPORT_WRITE_FAILED`,
	});
	return { ...envelope, outputPath };
}
