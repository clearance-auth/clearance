import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { MANAGEMENT_OPERATIONS } from "../../management/src/contracts/operations.ts";

type OperationMetadata = {
	id: string;
	http: { method: "GET" | "POST" | "PATCH" | "DELETE"; path: `/v1/${string}`; currentPath?: `/v1/${string}` };
	mutation: boolean;
	supportsDryRun: boolean;
	confirmation: "none" | "client-required" | "client-required-when-live" | "server-required";
	confirmationWhen?: { inputKey: string; equals: string | number | boolean | null };
	inputKeys: readonly string[];
	pathParameters: Record<string, string>;
	queryParameters: Record<string, string>;
};

type OperationInputContract = {
	keys: ReadonlySet<string>;
	properties: ReadonlyMap<string, ts.Type>;
};

const outputPath = fileURLToPath(new URL("../src/generated/operation-metadata.ts", import.meta.url));
const outputContractPath = fileURLToPath(new URL("../src/generated/canonical-output-contract.ts", import.meta.url));
const operationContractPath = fileURLToPath(new URL("../../management/src/contracts/operations.ts", import.meta.url));

/** These are API-path compatibility details not represented in the canonical operation interface. */
const currentPathSupplements = {
	"projects.inspect": "/v1/projects/current",
	"environments.inspect": "/v1/environments/current",
} as const;

/** These semantic input conditions live with the client schema, rather than server transport policy. */
const confirmationWhenSupplements = {
	"sso.test": { inputKey: "live", equals: true },
	"scim.test": { inputKey: "live", equals: true },
} as const;

/**
 * Semantic input names that intentionally differ from their route placeholder.
 * The generator verifies every entry against ManagementOperationTypes and the
 * canonical HTTP path before emitting it.
 */
const semanticPathSupplements = {
	"authorization.effective.inspect": { organizationId: "id" },
	"authorization.assignments.list": { organizationId: "id" },
	"authorization.assignments.replace": { organizationId: "id" },
	"authorization.reconcile": { organizationId: "id" },
	"service-accounts.list": { organizationId: "id" },
	"service-accounts.inspect": { organizationId: "id" },
	"service-accounts.create": { organizationId: "id" },
	"service-accounts.disable": { organizationId: "id" },
	"service-accounts.enable": { organizationId: "id" },
	"service-accounts.credentials.create": { organizationId: "id" },
	"service-accounts.credentials.rotate": { organizationId: "id" },
	"service-accounts.credentials.revoke": { organizationId: "id" },
	"readiness.report": { organizationId: "orgId" },
	"organizations.members.list": { organizationId: "id" },
	"organizations.members.add": { organizationId: "id" },
	"organizations.members.update": { organizationId: "id", membershipId: "memberId" },
	"organizations.members.remove": { organizationId: "id", membershipId: "memberId" },
	"organizations.members.import": { organizationId: "id" },
} as const;

/**
 * Semantic list filters whose public names deliberately differ from their
 * repeated HTTP query keys. The generator emits identity mappings for every
 * other GET input, so assembly has one complete, validated query contract.
 */
const semanticQuerySupplements = {
	"delivery.jobs.list": { states: "state" },
	"delivery.webhook_endpoints.list": { statuses: "status" },
} as const;
const unresolvedPathParameters: string[] = [];
const API_PATH = /^\/v1(?:\/(?:[A-Za-z0-9._~!$&'()*+,;=@%-]+|:[A-Za-z][A-Za-z0-9_]*))+$/;
const WIRE_KEY = /^[A-Za-z][A-Za-z0-9_]*$/;

function inputContractsByOperation(): ReadonlyMap<string, OperationInputContract> {
	const program = ts.createProgram([operationContractPath], { noEmit: true, skipLibCheck: true });
	const source = program.getSourceFile(operationContractPath);
	if (!source) throw new Error("Unable to read canonical management operation types.");
	const checker = program.getTypeChecker();
	const moduleSymbol = checker.getSymbolAtLocation(source);
	const contractSymbol = moduleSymbol && checker.getExportsOfModule(moduleSymbol)
		.find((symbol) => symbol.getName() === "ManagementOperationTypes");
	if (!contractSymbol) throw new Error("Unable to locate exported ManagementOperationTypes.");
	const contract = checker.getDeclaredTypeOfSymbol(contractSymbol);
	const result = new Map<string, OperationInputContract>();
	for (const operation of checker.getPropertiesOfType(contract)) {
		const id = operation.getName();
		const operationDeclaration = operation.valueDeclaration ?? operation.declarations?.[0] ?? source;
		const operationType = checker.getTypeOfSymbolAtLocation(operation, operationDeclaration);
		const inputType = checker.getTypeOfPropertyOfType(operationType, "input");
		if (!inputType) throw new Error(`${id} is missing a semantic input type.`);
		const properties = new Map<string, ts.Type>();
		for (const branch of inputType.isUnion() ? inputType.types : [inputType]) {
			for (const property of checker.getPropertiesOfType(branch)) {
				if (properties.has(property.getName())) continue;
				properties.set(
					property.getName(),
					checker.getTypeOfSymbolAtLocation(
						property,
						property.valueDeclaration ?? property.declarations?.[0] ?? operationDeclaration,
					),
				);
			}
		}
		result.set(id, { keys: new Set(properties.keys()), properties });
	}
	return result;
}

function assertCanonicalApiPath(value: unknown, label: string): asserts value is `/v1/${string}` {
	if (typeof value !== "string" || !API_PATH.test(value) || value.includes("%")) {
		throw new Error(`${label} must be a canonical /v1 API path.`);
	}
	try {
		decodeURI(value);
		const normalized = new URL(value, "https://clearance.invalid");
		if (normalized.origin !== "https://clearance.invalid" || normalized.search || normalized.hash || normalized.pathname !== value) {
			throw new Error(`${label} must be a canonical /v1 API path.`);
		}
	} catch (error) {
		if (error instanceof Error && error.message.endsWith("canonical /v1 API path.")) throw error;
		throw new Error(`${label} must be a canonical /v1 API path.`);
	}
}

function acceptsConfirmationValue(type: ts.Type, value: string | number | boolean | null): boolean {
	const candidates = type.isUnion() ? type.types : [type];
	return candidates.some((candidate) =>
		(value === null && (candidate.flags & ts.TypeFlags.Null) !== 0) ||
		(typeof value === "boolean" && (candidate.flags & ts.TypeFlags.BooleanLike) !== 0) ||
		(typeof value === "string" && (candidate.flags & ts.TypeFlags.StringLike) !== 0) ||
		(typeof value === "number" && (candidate.flags & ts.TypeFlags.NumberLike) !== 0),
	);
}

function pathParameters(path: string): readonly string[] {
	return [...path.matchAll(/:([A-Za-z][A-Za-z0-9_]*)/g)].map((match) => match[1]!);
}

function semanticPathParameters(
	id: string,
	path: string,
	input: OperationInputContract,
): Record<string, string> {
	const placeholders = pathParameters(path);
	const supplement = semanticPathSupplements[id as keyof typeof semanticPathSupplements] ?? {};
	const mapping: Record<string, string> = {};
	for (const placeholder of placeholders) {
		const semantic = Object.entries(supplement).find(([, route]) => route === placeholder)?.[0] ??
			(input.keys.has(placeholder) ? placeholder : undefined);
		if (!semantic) {
			unresolvedPathParameters.push(`${id} :${placeholder}; inputs: ${[...input.keys].sort().join(", ")}`);
			continue;
		}
		if (!input.keys.has(semantic)) throw new Error(`${id} semantic path key ${semantic} is not declared by ManagementOperationTypes.`);
		if (mapping[semantic] !== undefined) throw new Error(`${id} maps semantic path key ${semantic} more than once.`);
		mapping[semantic] = placeholder;
	}
	for (const [semantic, placeholder] of Object.entries(supplement)) {
		if (!input.keys.has(semantic) || !placeholders.includes(placeholder) || mapping[semantic] !== placeholder) {
			throw new Error(`${id} has an invalid semantic path supplement ${semantic} -> ${placeholder}.`);
		}
	}
	return mapping;
}

function semanticQueryParameters(
	id: string,
	method: OperationMetadata["http"]["method"],
	input: OperationInputContract,
	path: Readonly<Record<string, string>>,
): Record<string, string> {
	const supplement = semanticQuerySupplements[id as keyof typeof semanticQuerySupplements] ?? {};
	if (method !== "GET" && Object.keys(supplement).length > 0) {
		throw new Error(`${id} query mapping supplements are valid only for GET operations.`);
	}
	const mapping: Record<string, string> = {};
	if (method === "GET") {
		for (const semantic of input.keys) {
			if (Object.hasOwn(path, semantic)) continue;
			const wire = supplement[semantic as keyof typeof supplement] ?? semantic;
			if (!WIRE_KEY.test(wire)) throw new Error(`${id} query key ${wire} is invalid.`);
			mapping[semantic] = wire;
		}
	}
	if (new Set(Object.values(mapping)).size !== Object.keys(mapping).length) {
		throw new Error(`${id} maps multiple semantic query inputs to one HTTP query key.`);
	}
	for (const [semantic, wire] of Object.entries(supplement)) {
		if (!input.keys.has(semantic) || Object.hasOwn(path, semantic) || mapping[semantic] !== wire) {
			throw new Error(`${id} has an invalid semantic query supplement ${semantic} -> ${wire}.`);
		}
	}
	return mapping;
}

function assertMetadata(value: readonly OperationMetadata[]): void {
	if (value.length !== 143) throw new Error(`Expected 143 canonical management operations, received ${value.length}.`);
	const ids = new Set(value.map((operation) => operation.id));
	if (ids.size !== value.length) throw new Error("Canonical management operation ids must be unique.");
	for (const operation of value) {
		if (!operation.id || !operation.http.path.startsWith("/v1/")) {
			throw new Error(`Invalid canonical operation metadata for ${operation.id || "<empty>"}.`);
		}
	}
}

function snapshot(): readonly OperationMetadata[] {
	const inputs = inputContractsByOperation();
	const canonicalIds = new Set(MANAGEMENT_OPERATIONS.map((operation) => operation.id));
	for (const id of Object.keys(currentPathSupplements)) {
		if (!canonicalIds.has(id)) throw new Error(`Stale currentPath supplement for ${id}.`);
	}
	for (const id of Object.keys(semanticPathSupplements)) {
		if (!canonicalIds.has(id)) throw new Error(`Stale semantic path supplement for ${id}.`);
	}
	for (const id of Object.keys(semanticQuerySupplements)) {
		if (!canonicalIds.has(id)) throw new Error(`Stale semantic query supplement for ${id}.`);
	}
	for (const [id, supplement] of Object.entries(confirmationWhenSupplements)) {
		if (!canonicalIds.has(id)) throw new Error(`Stale confirmationWhen supplement for ${id}.`);
		const input = inputs.get(id);
		const field = input?.properties.get(supplement.inputKey);
		if (!field || !acceptsConfirmationValue(field, supplement.equals)) {
			throw new Error(`${id} confirmationWhen must bind to a compatible canonical semantic input.`);
		}
	}
	const metadata = MANAGEMENT_OPERATIONS.map((operation) => {
		assertCanonicalApiPath(operation.http.path, `${operation.id} primary path`);
		const currentPath = currentPathSupplements[operation.id as keyof typeof currentPathSupplements];
		const canonicalCurrentPath = (operation.http as { currentPath?: string }).currentPath;
		if (currentPath !== undefined) assertCanonicalApiPath(currentPath, `${operation.id} currentPath supplement`);
		if (canonicalCurrentPath !== undefined) assertCanonicalApiPath(canonicalCurrentPath, `${operation.id} canonical currentPath`);
		if (canonicalCurrentPath !== currentPath) {
			throw new Error(`${operation.id} currentPath supplement no longer matches the canonical operation.`);
		}
		const confirmationWhen = confirmationWhenSupplements[operation.id as keyof typeof confirmationWhenSupplements];
		if (operation.confirmation === "client-required-when-live" && !confirmationWhen) {
			throw new Error(`${operation.id} needs an explicit confirmationWhen supplement.`);
		}
		if (operation.confirmation !== "client-required-when-live" && confirmationWhen) {
			throw new Error(`${operation.id} has an unexpected confirmationWhen supplement.`);
		}
		const input = inputs.get(operation.id);
		if (!input) throw new Error(`${operation.id} is missing from ManagementOperationTypes.`);
		const pathParameters = semanticPathParameters(operation.id, operation.http.path, input);
		return {
			id: operation.id,
			http: {
				method: operation.http.method,
				path: operation.http.path,
				...(currentPath ? { currentPath } : {}),
			},
			mutation: operation.mutation,
			supportsDryRun: operation.supportsDryRun,
			confirmation: operation.confirmation,
			...(confirmationWhen ? { confirmationWhen } : {}),
			inputKeys: [...input.keys],
			pathParameters,
			queryParameters: semanticQueryParameters(operation.id, operation.http.method, input, pathParameters),
		};
	});
	if (unresolvedPathParameters.length > 0) {
		throw new Error(`Missing semantic path mappings:\n${unresolvedPathParameters.join("\n")}`);
	}
	assertMetadata(metadata);
	return metadata;
}

function render(metadata: readonly OperationMetadata[]): string {
	return `// Generated by scripts/generate-operation-metadata.ts. Do not edit.\n` +
		`export type OperationMetadata = Readonly<{\n` +
		`\tid: string;\n\thttp: Readonly<{ method: \"GET\" | \"POST\" | \"PATCH\" | \"DELETE\"; path: \`/v1/\${string}\`; currentPath?: \`/v1/\${string}\` }>;\n` +
		`\tmutation: boolean;\n\tsupportsDryRun: boolean;\n\tconfirmation: \"none\" | \"client-required\" | \"client-required-when-live\" | \"server-required\";\n` +
		`\tconfirmationWhen?: Readonly<{ inputKey: string; equals: string | number | boolean | null }>;\n\tinputKeys: readonly string[];\n\tpathParameters: Readonly<Record<string, string>>;\n\tqueryParameters: Readonly<Record<string, string>>;\n` +
		`}>;\n\n` +
		`const OPERATION_METADATA_VALUES = ${JSON.stringify(metadata, null, "\t")} as const satisfies readonly OperationMetadata[];\n\n` +
		`export const OPERATION_METADATA = Object.freeze(OPERATION_METADATA_VALUES.map((value) => {\n` +
		`\tconst operation: OperationMetadata = value;\n\treturn Object.freeze({\n\t\t...operation,\n\t\thttp: Object.freeze({ ...operation.http }),\n\t\tinputKeys: Object.freeze([...operation.inputKeys]),\n\t\tpathParameters: Object.freeze({ ...operation.pathParameters }),\n\t\tqueryParameters: Object.freeze({ ...operation.queryParameters }),\n` +
		`\t\t...(operation.confirmationWhen ? { confirmationWhen: Object.freeze({ ...operation.confirmationWhen }) } : {}),\n\t});\n` +
		`})) as typeof OPERATION_METADATA_VALUES;\n`;
}

function renderOutputContract(metadata: readonly OperationMetadata[]): string {
	const assertions = metadata.map((operation, index) =>
		`/** ${operation.id} */\n` +
		`type _OutputToCanonical${index} = AssertAssignable<\n` +
		`\tManagementOperationTypes[${JSON.stringify(operation.id)}]["output"],\n` +
		`\tOperationOutput<ManagementOperationRegistry[${JSON.stringify(operation.id)}]>\n` +
		`>;\n` +
		`type _CanonicalToOutput${index} = AssertAssignable<\n` +
		`\tOperationOutput<ManagementOperationRegistry[${JSON.stringify(operation.id)}]>,\n` +
		`\tManagementOperationTypes[${JSON.stringify(operation.id)}]["output"]\n` +
		`>;`,
	);
	return `// Generated by scripts/generate-operation-metadata.ts. Do not edit.\n` +
		`import type { ManagementOperationTypes } from "../../../management/src/contracts/operations.js";\n` +
		`import type { OperationInput, OperationOutput } from "../spec.js";\n` +
		`import type { ManagementOperationRegistry } from "./registry.js";\n\n` +
		`type Exact<Left, Right> =\n` +
		`\t[Left] extends [Right]\n` +
		`\t\t? [Right] extends [Left]\n` +
		`\t\t\t? true\n` +
		`\t\t\t: false\n` +
		`\t\t: false;\n\n` +
		`type AssertTrue<Value extends true> = Value;\n` +
		`type AssertAssignable<Target, Source extends Target> = true;\n` +
		`type _ExactOperationIds = AssertTrue<Exact<\n` +
		`\tkeyof ManagementOperationRegistry,\n` +
		`\tkeyof ManagementOperationTypes\n` +
		`>>;\n\n` +
		metadata.map((operation, index) =>
			`/** ${operation.id} */\n` +
			`type _InputToCanonical${index} = AssertAssignable<\n` +
			`\tManagementOperationTypes[${JSON.stringify(operation.id)}]["input"],\n` +
			`\tOperationInput<ManagementOperationRegistry[${JSON.stringify(operation.id)}]>\n` +
			`>;\n` +
			`type _CanonicalToInput${index} = AssertAssignable<\n` +
			`\tOperationInput<ManagementOperationRegistry[${JSON.stringify(operation.id)}]>,\n` +
			`\tManagementOperationTypes[${JSON.stringify(operation.id)}]["input"]\n` +
			`>;\n\n` +
			assertions[index],
		).join("\n\n") + "\n";
}

const check = process.argv.includes("--check");
const metadata = snapshot();
const expected = render(metadata);
const expectedOutputContract = renderOutputContract(metadata);
const existing = await readFile(outputPath, "utf8").catch(() => undefined);
const existingOutputContract = await readFile(outputContractPath, "utf8").catch(() => undefined);
if (check) {
	if (existing !== expected) throw new Error("Generated operation metadata is out of date. Run pnpm generate:operation-metadata.");
	if (existingOutputContract !== expectedOutputContract) {
		throw new Error("Generated canonical output contract is out of date. Run pnpm generate:operation-metadata.");
	}
} else if (existing !== expected) {
	await writeFile(outputPath, expected, "utf8");
}
if (!check && existingOutputContract !== expectedOutputContract) {
	await writeFile(outputContractPath, expectedOutputContract, "utf8");
}
