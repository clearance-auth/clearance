import type { InternalAdapter } from "@clearance/core";

const POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807n;
const MAX_ACTIONS = 256;
const ACTION_TOKEN = /^[a-z][a-z0-9._:-]{0,127}$/;

export type InternalAuthorizationSubject = Readonly<{
	kind: "principal";
	id: string;
}>;

export type InternalAuthorizationReadInput = Readonly<{
	organizationId: string;
	subject: InternalAuthorizationSubject;
}>;

/** The only effective-authorization data allowed to cross into runtime. */
export type InternalEffectiveAuthorization = Readonly<{
	organizationId: string;
	subject: InternalAuthorizationSubject;
	revision: string;
	actions: readonly string[];
}>;

export type InternalAuthorizationAuthority = Readonly<{
	readEffectiveAuthorization(
		input: InternalAuthorizationReadInput,
	): Promise<InternalEffectiveAuthorization>;
}>;

export class InvalidInternalAuthorizationAuthorityError extends Error {
	readonly code = "AUTHORIZATION_AUTHORITY_RESPONSE_INVALID" as const;

	constructor() {
		super("Authorization authority returned an invalid response");
		this.name = "InvalidInternalAuthorizationAuthorityError";
	}
}

export class InternalAuthorizationAuthorityUnavailableError extends Error {
	readonly code = "AUTHORIZATION_AUTHORITY_UNAVAILABLE" as const;

	constructor(cause?: unknown) {
		super("Authorization authority is unavailable", { cause });
		this.name = "InternalAuthorizationAuthorityUnavailableError";
	}
}

const authorities = new WeakMap<object, InternalAuthorizationAuthority>();
const capturedAuthorities = new WeakSet<object>();

function invalid(): never {
	throw new InvalidInternalAuthorizationAuthorityError();
}

function dataObject(value: unknown): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		invalid();
	}
	let prototype: object | null;
	let keys: (string | symbol)[];
	try {
		prototype = Object.getPrototypeOf(value);
		keys = Reflect.ownKeys(value);
	} catch {
		return invalid();
	}
	if (prototype !== Object.prototype && prototype !== null) invalid();
	const record: Record<string, unknown> = Object.create(null);
	for (const key of keys) {
		if (typeof key !== "string") invalid();
		let descriptor: PropertyDescriptor | undefined;
		try {
			descriptor = Object.getOwnPropertyDescriptor(value, key);
		} catch {
			return invalid();
		}
		if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
			invalid();
		}
		record[key] = descriptor.value;
	}
	return record;
}

function exactObject(
	value: unknown,
	keys: readonly string[],
): Record<string, unknown> {
	const record = dataObject(value);
	const actual = Object.keys(record);
	if (
		actual.length !== keys.length ||
		actual.some((key) => !keys.includes(key))
	) {
		invalid();
	}
	return record;
}

function identifier(value: unknown): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 1_024 ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		invalid();
	}
	return value;
}

function revision(value: unknown): string {
	if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) invalid();
	let parsed: bigint;
	try {
		parsed = BigInt(value);
	} catch {
		return invalid();
	}
	if (parsed <= 0n || parsed > POSTGRES_BIGINT_MAX) invalid();
	return value;
}

function subject(value: unknown): InternalAuthorizationSubject {
	const input = exactObject(value, ["kind", "id"]);
	if (input.kind !== "principal") invalid();
	return Object.freeze({ kind: "principal", id: identifier(input.id) });
}

function actions(value: unknown): readonly string[] {
	if (!Array.isArray(value) || value.length > MAX_ACTIONS) invalid();
	const normalized = value.map((action) => {
		if (typeof action !== "string" || !ACTION_TOKEN.test(action)) invalid();
		return action;
	});
	if (
		normalized.some(
			(action, index) => index > 0 && action <= normalized[index - 1]!,
		)
	) {
		invalid();
	}
	return Object.freeze(normalized);
}

function readInput(value: unknown): InternalAuthorizationReadInput {
	const input = exactObject(value, ["organizationId", "subject"]);
	return Object.freeze({
		organizationId: identifier(input.organizationId),
		subject: subject(input.subject),
	});
}

function readResult(value: unknown): InternalEffectiveAuthorization {
	const input = exactObject(value, [
		"organizationId",
		"subject",
		"revision",
		"actions",
	]);
	return Object.freeze({
		organizationId: identifier(input.organizationId),
		subject: subject(input.subject),
		revision: revision(input.revision),
		actions: actions(input.actions),
	});
}

/** Attach the private, uncached effective-authorization reader once per adapter. */
export function attachInternalAuthorizationAuthority<Target extends object>(
	internalAdapter: Target,
	authority: InternalAuthorizationAuthority,
): Target {
	if (authorities.has(internalAdapter)) invalid();
	const readEffectiveAuthorization = authority?.readEffectiveAuthorization;
	if (typeof readEffectiveAuthorization !== "function") invalid();
	const captured = Object.freeze({
		readEffectiveAuthorization: readEffectiveAuthorization.bind(authority),
	});
	capturedAuthorities.add(captured);
	authorities.set(internalAdapter, captured);
	return internalAdapter;
}

/** Propagates an already-validated private reader without reattaching it. */
export function attachCapturedInternalAuthorizationAuthority<
	Target extends object,
>(
	target: Target,
	authority: InternalAuthorizationAuthority,
): Target {
	if (!capturedAuthorities.has(authority)) invalid();
	const existing = authorities.get(target);
	if (existing) {
		if (existing !== authority) invalid();
		return target;
	}
	authorities.set(target, authority);
	return target;
}

/**
 * Reads the live authorization source without caching. `undefined` means only
 * that no authority was attached; attached-reader failures always throw.
 */
export async function readInternalEffectiveAuthorization(
	internalAdapter: InternalAdapter,
	input: unknown,
): Promise<InternalEffectiveAuthorization | undefined> {
	const authority = authorities.get(internalAdapter);
	if (!authority) return undefined;
	const normalizedInput = readInput(input);
	let result: InternalEffectiveAuthorization;
	try {
		result = await authority.readEffectiveAuthorization(normalizedInput);
	} catch (error) {
		throw new InternalAuthorizationAuthorityUnavailableError(error);
	}
	const normalizedResult = readResult(result);
	if (
		normalizedResult.organizationId !== normalizedInput.organizationId ||
		normalizedResult.subject.kind !== normalizedInput.subject.kind ||
		normalizedResult.subject.id !== normalizedInput.subject.id
	) {
		invalid();
	}
	return normalizedResult;
}

/** Returns the attached reader so runtime-owned clones can preserve it. */
export function readInternalAuthorizationAuthority(
	target: object,
): InternalAuthorizationAuthority | undefined {
	return authorities.get(target);
}
