import { createBrowserManagementClient } from "../client.js";
import {
	defineOperation,
	defineOperationRegistry,
	type AnyOperationSpec,
	type AnySchema,
	type OperationRegistry,
	type OperationSpec,
	type StrictInputSchema,
} from "../spec.js";
import type { OperationMetadata } from "./operation-metadata.js";

export type OperationSchemaPair = Readonly<{
	input: StrictInputSchema;
	output: AnySchema;
}>;

/** A domain contributes exactly one schema pair for each of its canonical ids. */
export type OperationSchemaDomain = Readonly<Record<string, OperationSchemaPair>>;

type UnionToIntersection<Value> =
	(Value extends unknown ? (argument: Value) => void : never) extends (argument: infer Intersection) => void
		? Intersection
		: never;

type DomainSchemas<Domains extends readonly OperationSchemaDomain[]> = UnionToIntersection<Domains[number]>;

/** The assembled registry retains each domain schema's inferred public types. */
export type AssembledOperationRegistry<Domains extends readonly OperationSchemaDomain[]> = {
	[Id in keyof DomainSchemas<Domains> & string]: DomainSchemas<Domains>[Id] extends OperationSchemaPair
		? OperationSpec<Id, DomainSchemas<Domains>[Id]["input"], DomainSchemas<Domains>[Id]["output"]>
		: never;
};

function routeParameters(path: string): readonly string[] {
	return [...path.matchAll(/:([A-Za-z][A-Za-z0-9_]*)/g)].map((match) => match[1]!);
}

function assertCompleteSchemaCoverage(
	metadata: readonly OperationMetadata[],
	domains: readonly OperationSchemaDomain[],
): ReadonlyMap<string, OperationSchemaPair> {
	const metadataIds = new Set(metadata.map((operation) => operation.id));
	if (metadataIds.size !== metadata.length) throw new Error("Generated operation metadata ids must be unique.");
	const schemas = new Map<string, OperationSchemaPair>();
	for (const domain of domains) {
		for (const [id, pair] of Object.entries(domain)) {
			if (!metadataIds.has(id)) throw new Error(`Schema domain has no canonical metadata for ${id}.`);
			if (schemas.has(id)) throw new Error(`Multiple schema pairs were supplied for ${id}.`);
			schemas.set(id, pair);
		}
	}
	for (const id of metadataIds) {
		if (!schemas.has(id)) throw new Error(`Canonical metadata ${id} is missing its schema pair.`);
	}
	return schemas;
}

/**
 * Derives every wire projection from the canonical route and strict semantic
 * input. Calling the browser client is deliberate: it applies the hardened
 * descriptor validator before this registry can escape the assembler.
 */
export function assembleManagementOperationRegistry<const Domains extends readonly OperationSchemaDomain[]>(
	metadata: readonly OperationMetadata[],
	domains: Domains,
): AssembledOperationRegistry<Domains> {
	const schemas = assertCompleteSchemaCoverage(metadata, domains);
	const registry: Record<string, AnyOperationSpec> = Object.create(null) as Record<string, AnyOperationSpec>;
	for (const descriptor of metadata) {
		const pair = schemas.get(descriptor.id)!;
		const inputKeys = [...descriptor.inputKeys];
		const path = Object.entries(descriptor.pathParameters);
		const placeholders = routeParameters(descriptor.http.path);
		const semanticPathKeys = path.map(([semantic]) => semantic);
		const mappedPlaceholders = path.map(([, placeholder]) => placeholder);
		const query = Object.entries(descriptor.queryParameters);
		const semanticQueryKeys = query.map(([semantic]) => semantic);
		const mappedQueryKeys = query.map(([, wire]) => wire);
		if (new Set(placeholders).size !== placeholders.length || new Set(semanticPathKeys).size !== semanticPathKeys.length ||
			new Set(mappedPlaceholders).size !== mappedPlaceholders.length || placeholders.length !== path.length ||
			placeholders.some((placeholder) => !mappedPlaceholders.includes(placeholder)) ||
			semanticPathKeys.some((key) => !inputKeys.includes(key))) {
			throw new Error(`${descriptor.id} path projection must map each HTTP placeholder to one strict semantic input key.`);
		}
		const remaining = inputKeys.filter((key) => !semanticPathKeys.includes(key));
		if (new Set(semanticQueryKeys).size !== semanticQueryKeys.length || new Set(mappedQueryKeys).size !== mappedQueryKeys.length ||
			semanticQueryKeys.some((key) => !inputKeys.includes(key)) || semanticQueryKeys.some((key) => semanticPathKeys.includes(key)) ||
			(descriptor.http.method === "GET"
				? (semanticQueryKeys.length !== remaining.length || remaining.some((key) => !semanticQueryKeys.includes(key)))
				: semanticQueryKeys.length !== 0)) {
			throw new Error(`${descriptor.id} query projection must map each GET-only strict semantic input key exactly once.`);
		}
		const operation = defineOperation({
			id: descriptor.id,
			http: descriptor.http,
			mutation: descriptor.mutation,
			supportsDryRun: descriptor.supportsDryRun,
			confirmation: descriptor.confirmation,
			...(descriptor.confirmationWhen ? { confirmationWhen: descriptor.confirmationWhen } : {}),
			schemas: pair,
			transport: {
				path: Object.fromEntries(path),
				query: Object.fromEntries(query),
				body: descriptor.http.method === "GET" ? [] : remaining,
			},
		});
		registry[descriptor.id] = operation;
	}
	if (Object.keys(registry).length !== metadata.length) {
		throw new Error("Registry assembly did not retain exactly one own descriptor per metadata id.");
	}
	const complete = defineOperationRegistry(registry);
	createBrowserManagementClient({
		baseUrl: "/",
		registry: complete,
		fetch: async () => new Response(null, { status: 204 }),
	});
	return complete as AssembledOperationRegistry<Domains>;
}
