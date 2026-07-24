import { isTransactionActive } from "@clearance/core/context";
import type { InternalAdapter } from "@clearance/core";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";

const POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807n;
const MAX_IDENTIFIER_LENGTH = 1_024;
const MAX_ORGANIZATION_NAME_LENGTH = 256;
const MAX_EMAIL_LENGTH = 320;
const MAX_OWNER_NAME_LENGTH = 256;
const ORGANIZATION_SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

declare const activeRawTransaction: unique symbol;

/** An active runtime transaction which can be shared with the product authority. */
export type InternalManagedOrganizationLifecycleActiveRawTransaction =
	DBTransactionAdapter & {
		readonly rawTransactionQuery: NonNullable<
			DBTransactionAdapter["rawTransactionQuery"]
		>;
		readonly [activeRawTransaction]: true;
	};

export type InternalManagedOrganizationLifecycleInput = Readonly<{
	organization: Readonly<{
		id: string;
		name: string;
		slug: string;
		createdAt: Date;
	}>;
	owner: Readonly<{
		id: string;
		email: string;
		name?: string | null;
		createdAt: Date;
		updatedAt: Date;
	}>;
	ownerMembershipId: string;
	authorizationRevision: string;
	transaction: InternalManagedOrganizationLifecycleActiveRawTransaction;
}>;

export type InternalManagedOrganizationLifecycleAuthority = Readonly<{
	finalizeCreatedOrganization(
		input: InternalManagedOrganizationLifecycleInput,
	): Promise<void>;
}>;

export class InvalidInternalManagedOrganizationLifecycleAuthorityError extends Error {
	readonly code = "MANAGED_ORGANIZATION_LIFECYCLE_AUTHORITY_RESPONSE_INVALID" as const;

	constructor() {
		super("Managed organization lifecycle authority received invalid data");
		this.name = "InvalidInternalManagedOrganizationLifecycleAuthorityError";
	}
}

export class InternalManagedOrganizationLifecycleAuthorityUnavailableError extends Error {
	readonly code = "MANAGED_ORGANIZATION_LIFECYCLE_AUTHORITY_UNAVAILABLE" as const;

	constructor(cause?: unknown) {
		super("Managed organization lifecycle authority is unavailable", { cause });
		this.name = "InternalManagedOrganizationLifecycleAuthorityUnavailableError";
	}
}

const authorities = new WeakMap<object, InternalManagedOrganizationLifecycleAuthority>();
const capturedAuthorities = new WeakSet<object>();

function invalid(): never {
	throw new InvalidInternalManagedOrganizationLifecycleAuthorityError();
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
		if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalid();
		record[key] = descriptor.value;
	}
	return record;
}

function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
	const record = dataObject(value);
	const actual = Object.keys(record);
	if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) {
		invalid();
	}
	return record;
}

function optionalObject(
	value: unknown,
	keys: readonly string[],
): Record<string, unknown> {
	const record = dataObject(value);
	if (Object.keys(record).some((key) => !keys.includes(key))) invalid();
	return record;
}

function string(
	value: unknown,
	maximum: number,
	allowEmpty = false,
): string {
	if (
		typeof value !== "string" ||
		value.length > maximum ||
		(!allowEmpty && value.length === 0) ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		invalid();
	}
	return value;
}

function identifier(value: unknown): string {
	return string(value, MAX_IDENTIFIER_LENGTH);
}

function organizationName(value: unknown): string {
	const normalized = string(value, MAX_ORGANIZATION_NAME_LENGTH);
	if (/[\u0000-\u001f\u007f]/.test(normalized)) invalid();
	return normalized;
}

function date(value: unknown): Date {
	if (!(value instanceof Date) || !Number.isFinite(value.getTime())) invalid();
	return new Date(value.getTime());
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

function organization(
	value: unknown,
): InternalManagedOrganizationLifecycleInput["organization"] {
	const input = exactObject(value, ["id", "name", "slug", "createdAt"]);
	const slug = string(input.slug, 48);
	if (!ORGANIZATION_SLUG.test(slug)) invalid();
	return Object.freeze({
		id: identifier(input.id),
		name: organizationName(input.name),
		slug,
		createdAt: date(input.createdAt),
	});
}

function owner(value: unknown): InternalManagedOrganizationLifecycleInput["owner"] {
	const input = optionalObject(value, [
		"id",
		"email",
		"name",
		"createdAt",
		"updatedAt",
	]);
	for (const required of ["id", "email", "createdAt", "updatedAt"]) {
		if (!Object.hasOwn(input, required)) invalid();
	}
	const name = Object.hasOwn(input, "name")
		? input.name === null
			? null
			: string(input.name, MAX_OWNER_NAME_LENGTH)
		: undefined;
	return Object.freeze({
		id: identifier(input.id),
		email: string(input.email, MAX_EMAIL_LENGTH),
		...(name === undefined ? {} : { name }),
		createdAt: date(input.createdAt),
		updatedAt: date(input.updatedAt),
	});
}

function input(value: unknown): InternalManagedOrganizationLifecycleInput {
	const normalized = exactObject(value, [
		"organization",
		"owner",
		"ownerMembershipId",
		"authorizationRevision",
		"transaction",
	]);
	return Object.freeze({
		organization: organization(normalized.organization),
		owner: owner(normalized.owner),
		ownerMembershipId: identifier(normalized.ownerMembershipId),
		authorizationRevision: revision(normalized.authorizationRevision),
		transaction: normalized.transaction as InternalManagedOrganizationLifecycleActiveRawTransaction,
	});
}

/** Attach the private managed-organization lifecycle authority once per adapter. */
export function attachInternalManagedOrganizationLifecycleAuthority<Target extends object>(
	target: Target,
	authority: InternalManagedOrganizationLifecycleAuthority,
): Target {
	if (authorities.has(target)) invalid();
	const finalizeCreatedOrganization = authority?.finalizeCreatedOrganization;
	if (typeof finalizeCreatedOrganization !== "function") invalid();
	const captured = Object.freeze({
		finalizeCreatedOrganization: finalizeCreatedOrganization.bind(authority),
	});
	capturedAuthorities.add(captured);
	authorities.set(target, captured);
	return target;
}

/** Propagates an already-validated authority without reattaching it. */
export function attachCapturedInternalManagedOrganizationLifecycleAuthority<
	Target extends object,
>(
	target: Target,
	authority: InternalManagedOrganizationLifecycleAuthority,
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
 * Finalizes a managed first-organization creation in the caller's active
 * transaction. No authority is an ordinary unmanaged organization creation;
 * any attached authority failure is deliberately observable and rolls back.
 */
export async function finalizeInternalManagedCreatedOrganization(
	internalAdapter: InternalAdapter,
	value: unknown,
): Promise<void | undefined> {
	const authority = authorities.get(internalAdapter);
	if (!authority) return undefined;
	const normalized = input(value);
	const transaction = normalized.transaction;
	if (
		!transaction ||
		typeof transaction.rawTransactionQuery !== "function" ||
		!(await isTransactionActive(transaction))
	) {
		throw new InternalManagedOrganizationLifecycleAuthorityUnavailableError(
			new Error("Managed organization lifecycle finalization requires an active transaction"),
		);
	}
	try {
		await authority.finalizeCreatedOrganization(normalized);
	} catch (error) {
		throw new InternalManagedOrganizationLifecycleAuthorityUnavailableError(error);
	}
}

/** Returns the attached authority so runtime-owned clones can preserve it. */
export function readInternalManagedOrganizationLifecycleAuthority(
	target: object,
): InternalManagedOrganizationLifecycleAuthority | undefined {
	return authorities.get(target);
}
