import * as z from "zod";

export type HttpMethod = "GET" | "POST" | "PATCH" | "DELETE";
export type ConfirmationPolicy =
	| "none"
	| "client-required"
	| "client-required-when-live"
	| "server-required";
export type ApiPath = `/v1/${string}`;
export type ConfirmationLiveValue = string | number | boolean | null;
export type AnySchema = z.ZodType<unknown, unknown, z.core.$ZodTypeInternals<unknown, unknown>>;
/** A schema whose accepted and parsed values are semantic input objects. */
export type StrictInputSchema = z.ZodType<Record<string, unknown>, Record<string, unknown>>;
/** Semantic input keys mapped to HTTP placeholders; arrays retain fixture compatibility. */
export type PathProjection = readonly string[] | Readonly<Record<string, string>>;
/** Semantic input keys mapped to HTTP query keys; arrays retain identity-map fixtures. */
export type QueryProjection = readonly string[] | Readonly<Record<string, string>>;

/**
 * One strict, semantic input object is the public client contract. Transport
 * projection belongs solely to the descriptor so callers never assemble route
 * fragments or wire-shaped `{ path, query, body }` objects.
 */
export interface OperationSpec<
	Id extends string = string,
	Input extends StrictInputSchema = StrictInputSchema,
	Output extends AnySchema = AnySchema,
> {
	readonly id: Id;
	readonly http: {
		readonly method: HttpMethod;
		readonly path: ApiPath;
		/** Alternate path used only when the single semantic path key is absent. */
		readonly currentPath?: ApiPath;
	};
	readonly mutation: boolean;
	readonly supportsDryRun: boolean;
	readonly confirmation: ConfirmationPolicy;
	/** Required only for client-required-when-live; evaluated after input parsing. */
	readonly confirmationWhen?: {
		readonly inputKey: string;
		readonly equals: ConfirmationLiveValue;
	};
	readonly schemas: { readonly input: Input; readonly output: Output };
	readonly transport: {
		readonly path: PathProjection;
		readonly query: QueryProjection;
		readonly body: readonly string[];
	};
}

export type AnyOperationSpec = OperationSpec<string, StrictInputSchema, AnySchema>;
export type OperationRegistry = Readonly<Record<string, AnyOperationSpec>>;
export type OperationInput<Operation extends AnyOperationSpec> = z.input<Operation["schemas"]["input"]>;
export type OperationOutput<Operation extends AnyOperationSpec> = z.output<Operation["schemas"]["output"]>;

export function defineOperation<const Operation extends AnyOperationSpec>(operation: Operation): Operation {
	return Object.freeze({
		...operation,
		http: Object.freeze({ ...operation.http }),
		schemas: Object.freeze({ ...operation.schemas }),
		transport: Object.freeze({
			path: Object.freeze(Array.isArray(operation.transport.path)
				? [...operation.transport.path]
				: { ...operation.transport.path }),
			query: Object.freeze(Array.isArray(operation.transport.query)
				? [...operation.transport.query]
				: { ...operation.transport.query }),
			body: Object.freeze([...operation.transport.body]),
		}),
	}) as Operation;
}

/** Registry keys are stable operation ids accepted by `client.call(id, ...)`. */
export function defineOperationRegistry<const Registry extends OperationRegistry>(registry: Registry): Registry {
	for (const [id, operation] of Object.entries(registry)) {
		if (id !== operation.id) throw new Error(`Registry key ${id} must equal operation id ${operation.id}`);
	}
	return Object.freeze(Object.assign(Object.create(null), registry)) as Registry;
}

export function resolveOperationPath(operation: AnyOperationSpec, pathInput: Record<string, unknown>): ApiPath {
	const path = pathProjectionEntries(operation.transport.path);
	if (operation.http.currentPath) {
		const currentKey = path[0]?.[0];
		if (currentKey && pathInput[currentKey] === undefined) return operation.http.currentPath;
	}
	return operation.http.path.replace(/:([A-Za-z][A-Za-z0-9_]*)/g, (_, name: string) => {
		const semanticKey = path.find(([, placeholder]) => placeholder === name)?.[0];
		const value = semanticKey ? pathInput[semanticKey] : undefined;
		if (typeof value !== "string" || !value) throw new Error(`Missing path parameter ${name} for ${operation.id}`);
		return encodeURIComponent(value);
	}) as ApiPath;
}

function pathProjectionEntries(path: PathProjection): readonly (readonly [string, string])[] {
	return Array.isArray(path)
		? path.map((key) => [key, key] as const)
		: Object.entries(path);
}
