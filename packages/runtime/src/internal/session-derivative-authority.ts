import type { InternalAdapter } from "@clearance/core";

/** The supported consumers of a managed session-derived credential. */
export type InternalSessionDerivativePurpose =
	| "device"
	| "impersonation"
	| "jwt"
	| "oidc"
	| "mcp";

export type InternalSessionDerivativeCaptureInput =
	| Readonly<{
			purpose: InternalSessionDerivativePurpose;
			sourceSessionToken: string;
	  }>
	| Readonly<{
			purpose: InternalSessionDerivativePurpose;
			sourceSessionId: string;
	  }>;

export type InternalSessionDerivativeValidationExpected = Readonly<{
	purpose: InternalSessionDerivativePurpose;
	subjectId?: string;
	organizationId?: string | null;
}>;

export type InternalSessionDerivativeAuthority = Readonly<{
	sourceSessionId: string;
	sourceSubjectId: string;
	sourceOrganizationId: string | null;
	sourceExpiresAt: number;
	policyProjectId: string;
	policyEnvironmentId: string;
	policyRevision: string;
}>;

/** A canonical, versioned serialized authority binding. */
export type InternalSessionDerivativeAuthorityBinding = string;

export type ManagedSessionDerivativeAuthorityFailureReason =
	| "authority_missing"
	| "authority_invalid"
	| "authority_mismatched"
	| "authority_stale";

/** A stable error surface for managed derivative authority failures. */
export class ManagedSessionDerivativeAuthorityError extends Error {
	readonly code = "MANAGED_SESSION_DERIVATIVE_AUTHORITY_FAILED" as const;

	constructor(readonly reason: ManagedSessionDerivativeAuthorityFailureReason) {
		super("Managed session derivative authority failed closed");
		this.name = "ManagedSessionDerivativeAuthorityError";
	}
}

type AttachedAuthority = Readonly<{
	capture(
		input: InternalSessionDerivativeCaptureInput,
	): Promise<InternalSessionDerivativeAuthority>;
	validate(
		sourceSessionId: string,
	): Promise<InternalSessionDerivativeAuthority>;
	signatureVersion(): number;
	sign(payload: string, signatureVersion: number): Promise<string>;
	verify(
		payload: string,
		signatureVersion: number,
		signature: string,
	): Promise<boolean>;
}>;

const authorities = new WeakMap<object, AttachedAuthority>();
const PURPOSES = new Set<InternalSessionDerivativePurpose>([
	"device",
	"impersonation",
	"jwt",
	"oidc",
	"mcp",
]);

function fail(reason: ManagedSessionDerivativeAuthorityFailureReason): never {
	throw new ManagedSessionDerivativeAuthorityError(reason);
}

function dataObject(value: unknown): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return fail("authority_invalid");
	}
	let prototype: object | null;
	let keys: (string | symbol)[];
	try {
		prototype = Object.getPrototypeOf(value);
		keys = Reflect.ownKeys(value);
	} catch {
		return fail("authority_invalid");
	}
	if (prototype !== Object.prototype && prototype !== null) {
		return fail("authority_invalid");
	}
	const record: Record<string, unknown> = Object.create(null);
	for (const key of keys) {
		if (typeof key !== "string") return fail("authority_invalid");
		let descriptor: PropertyDescriptor | undefined;
		try {
			descriptor = Object.getOwnPropertyDescriptor(value, key);
		} catch {
			return fail("authority_invalid");
		}
		if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
			return fail("authority_invalid");
		}
		record[key] = descriptor.value;
	}
	return record;
}

function exactObject(
	value: unknown,
	required: readonly string[],
	optional: readonly string[] = [],
): Record<string, unknown> {
	const record = dataObject(value);
	const keys = Object.keys(record);
	if (
		required.some((key) => !Object.hasOwn(record, key)) ||
		keys.some((key) => !required.includes(key) && !optional.includes(key))
	) {
		return fail("authority_invalid");
	}
	return record;
}

function identifier(value: unknown, maximum = 1_024): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > maximum ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		return fail("authority_invalid");
	}
	return value;
}

function purpose(value: unknown): InternalSessionDerivativePurpose {
	if (typeof value !== "string" || !PURPOSES.has(value as never)) {
		return fail("authority_invalid");
	}
	return value as InternalSessionDerivativePurpose;
}

function captureInput(value: unknown): InternalSessionDerivativeCaptureInput {
	const base = exactObject(value, ["purpose"], [
		"sourceSessionToken",
		"sourceSessionId",
	]);
	const normalizedPurpose = purpose(base.purpose);
	const hasToken = Object.hasOwn(base, "sourceSessionToken");
	const hasId = Object.hasOwn(base, "sourceSessionId");
	if (hasToken === hasId) return fail("authority_invalid");
	return hasToken
		? Object.freeze({
				purpose: normalizedPurpose,
				sourceSessionToken: identifier(base.sourceSessionToken, 4_096),
			})
		: Object.freeze({
				purpose: normalizedPurpose,
				sourceSessionId: identifier(base.sourceSessionId),
			});
}

function expectedInput(value: unknown): InternalSessionDerivativeValidationExpected {
	const input = exactObject(value, ["purpose"], ["subjectId", "organizationId"]);
	const subjectId = Object.hasOwn(input, "subjectId")
		? identifier(input.subjectId)
		: undefined;
	let organizationId: string | null | undefined;
	if (Object.hasOwn(input, "organizationId")) {
		organizationId = input.organizationId === null ? null : identifier(input.organizationId);
	}
	return Object.freeze({
		purpose: purpose(input.purpose),
		...(subjectId === undefined ? {} : { subjectId }),
		...(organizationId === undefined ? {} : { organizationId }),
	});
}

type UnsignedSerializedAuthority = Readonly<{
	version: 1;
	purpose: InternalSessionDerivativePurpose;
	sourceSessionId: string;
	sourceSubjectId: string;
	sourceOrganizationId: string | null;
	sourceExpiresAt: number;
	policyProjectId: string;
	policyEnvironmentId: string;
	policyRevision: string;
	signatureVersion: number;
}>;

type SerializedAuthority = UnsignedSerializedAuthority &
	Readonly<{ signature: string }>;

function authorityFields(
	value: InternalSessionDerivativeAuthority,
	purposeValue: InternalSessionDerivativePurpose,
	signatureVersion: unknown,
): UnsignedSerializedAuthority {
	if (
		!Number.isSafeInteger(value.sourceExpiresAt) ||
		!Number.isSafeInteger(signatureVersion) ||
		(signatureVersion as number) < -1
	) {
		return fail("authority_invalid");
	}
	return Object.freeze({
		version: 1,
		purpose: purposeValue,
		sourceSessionId: identifier(value.sourceSessionId),
		sourceSubjectId: identifier(value.sourceSubjectId),
		sourceOrganizationId:
			value.sourceOrganizationId === null
				? null
				: identifier(value.sourceOrganizationId),
		sourceExpiresAt: value.sourceExpiresAt,
		policyProjectId: identifier(value.policyProjectId),
		policyEnvironmentId: identifier(value.policyEnvironmentId),
		policyRevision: identifier(value.policyRevision),
		signatureVersion: signatureVersion as number,
	});
}

function signature(value: unknown): string {
	if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
		return fail("authority_invalid");
	}
	return value;
}

function serializedAuthority(value: unknown): SerializedAuthority {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 4_096 ||
		value.trim() !== value
	) {
		return fail("authority_invalid");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(value);
	} catch {
		return fail("authority_invalid");
	}
	const input = exactObject(parsed, [
		"version",
		"purpose",
		"sourceSessionId",
		"sourceSubjectId",
		"sourceOrganizationId",
		"sourceExpiresAt",
		"policyProjectId",
		"policyEnvironmentId",
		"policyRevision",
		"signatureVersion",
		"signature",
	]);
	if (
		input.version !== 1 ||
		!Number.isSafeInteger(input.sourceExpiresAt) ||
		!Number.isSafeInteger(input.signatureVersion) ||
		(input.signatureVersion as number) < -1
	) {
		return fail("authority_invalid");
	}
	const normalized = Object.freeze({
		version: 1 as const,
		purpose: purpose(input.purpose),
		sourceSessionId: identifier(input.sourceSessionId),
		sourceSubjectId: identifier(input.sourceSubjectId),
		sourceOrganizationId:
			input.sourceOrganizationId === null
				? null
				: identifier(input.sourceOrganizationId),
		sourceExpiresAt: input.sourceExpiresAt as number,
		policyProjectId: identifier(input.policyProjectId),
		policyEnvironmentId: identifier(input.policyEnvironmentId),
		policyRevision: identifier(input.policyRevision),
		signatureVersion: input.signatureVersion as number,
	});
	const signed = Object.freeze({ ...normalized, signature: signature(input.signature) });
	if (JSON.stringify(signed) !== value) return fail("authority_invalid");
	return signed;
}

/**
 * Internal-adapter-only attachment point. The authority stays private to the
 * adapter; consumers only receive a canonical serialized binding.
 */
export function attachInternalSessionDerivativeAuthority(
	internalAdapter: InternalAdapter,
	authority: AttachedAuthority,
): void {
	if (authorities.has(internalAdapter)) fail("authority_invalid");
	authorities.set(internalAdapter, Object.freeze({ ...authority }));
}

export async function captureInternalSessionDerivativeAuthority(
	internalAdapter: InternalAdapter,
	input: unknown,
): Promise<InternalSessionDerivativeAuthorityBinding | undefined> {
	const authority = authorities.get(internalAdapter);
	if (!authority) return undefined;
	const normalizedInput = captureInput(input);
	const captured = await authority.capture(normalizedInput);
	const signatureVersion = authority.signatureVersion();
	const fields = authorityFields(
		captured,
		normalizedInput.purpose,
		signatureVersion,
	);
	const payload = JSON.stringify(fields);
	return JSON.stringify({
		...fields,
		signature: await authority.sign(payload, signatureVersion),
	});
}

export async function validateInternalSessionDerivativeAuthority(
	internalAdapter: InternalAdapter,
	serialized: unknown,
	expected: unknown,
): Promise<InternalSessionDerivativeAuthority | undefined> {
	const authority = authorities.get(internalAdapter);
	if (!authority) return undefined;
	if (serialized === undefined || serialized === null || serialized === "") {
		return fail("authority_missing");
	}
	const binding = serializedAuthority(serialized);
	const payload = JSON.stringify({
		version: binding.version,
		purpose: binding.purpose,
		sourceSessionId: binding.sourceSessionId,
		sourceSubjectId: binding.sourceSubjectId,
		sourceOrganizationId: binding.sourceOrganizationId,
		sourceExpiresAt: binding.sourceExpiresAt,
		policyProjectId: binding.policyProjectId,
		policyEnvironmentId: binding.policyEnvironmentId,
		policyRevision: binding.policyRevision,
		signatureVersion: binding.signatureVersion,
	});
	if (
		!(await authority.verify(
			payload,
			binding.signatureVersion,
			binding.signature,
		))
	) {
		return fail("authority_invalid");
	}
	const normalizedExpected = expectedInput(expected);
	if (
		binding.purpose !== normalizedExpected.purpose ||
		(normalizedExpected.subjectId !== undefined &&
			binding.sourceSubjectId !== normalizedExpected.subjectId) ||
		(normalizedExpected.organizationId !== undefined &&
			binding.sourceOrganizationId !== normalizedExpected.organizationId)
	) {
		return fail("authority_mismatched");
	}
	const result = await authority.validate(binding.sourceSessionId);
	const live = authorityFields(
		result,
		binding.purpose,
		binding.signatureVersion,
	);
	if (
		live.purpose !== binding.purpose ||
		live.sourceSessionId !== binding.sourceSessionId ||
		live.sourceSubjectId !== binding.sourceSubjectId ||
		live.sourceOrganizationId !== binding.sourceOrganizationId ||
		live.sourceExpiresAt !== binding.sourceExpiresAt ||
		live.policyProjectId !== binding.policyProjectId ||
		live.policyEnvironmentId !== binding.policyEnvironmentId ||
		live.policyRevision !== binding.policyRevision
	) {
		return fail("authority_stale");
	}
	return Object.freeze({
		sourceSessionId: live.sourceSessionId,
		sourceSubjectId: live.sourceSubjectId,
		sourceOrganizationId: live.sourceOrganizationId,
		sourceExpiresAt: live.sourceExpiresAt,
		policyProjectId: live.policyProjectId,
		policyEnvironmentId: live.policyEnvironmentId,
		policyRevision: live.policyRevision,
	});
}
