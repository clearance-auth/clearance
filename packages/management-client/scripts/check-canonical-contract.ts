import { fileURLToPath } from "node:url";
import ts from "typescript";

const contractPath = fileURLToPath(new URL("../src/generated/canonical-output-contract.ts", import.meta.url));
const program = ts.createProgram([contractPath], {
	target: ts.ScriptTarget.ES2022,
	module: ts.ModuleKind.NodeNext,
	moduleResolution: ts.ModuleResolutionKind.NodeNext,
	strict: true,
	skipLibCheck: true,
	noEmit: true,
	types: ["node"],
});
const contract = program.getSourceFile(contractPath);
if (!contract) throw new Error("Unable to read generated canonical management-client contract.");
const diagnostics = [
	...program.getSyntacticDiagnostics(contract),
	...program.getSemanticDiagnostics(contract),
];
if (diagnostics.length > 0) {
	const lines = contract.text.split(/\r?\n/);
	const mismatches = diagnostics.map((diagnostic) => {
		const location = diagnostic.start === undefined
			? undefined
			: contract.getLineAndCharacterOfPosition(diagnostic.start);
		if (!location) return `TS${diagnostic.code}`;
		let assertion = "contract";
		let operation = "operation ids";
		for (let line = location.line; line >= 0; line -= 1) {
			const assertionMatch = lines[line]?.match(/type (_[A-Za-z]+)\d+/);
			if (assertion === "contract" && assertionMatch) assertion = assertionMatch[1]!;
			const match = lines[line]?.match(/^\/\*\* (.+) \*\/$/);
			if (match) {
				operation = match[1]!;
				break;
			}
		}
		return `${operation} ${assertion} (TS${diagnostic.code})`;
	});
	throw new Error(`Canonical management-client contract mismatches:\n${[...new Set(mismatches)]
		.map((mismatch) => `- ${mismatch}`)
		.join("\n")}`);
}
