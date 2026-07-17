import type {
	AuthenticationFactorMethod,
	AuthenticationPrimaryMethod,
	InternalAdapter,
	SessionIssuanceContext,
	VerifiedAuthenticationEvidence,
} from "@clearance/core";
import type {
	SessionAssuranceRequirement,
	ValidatedSessionAssuranceFields,
} from "../security/session-assurance";

const PRIMARY_METHODS = new Set<AuthenticationPrimaryMethod>([
	"password",
	"password_enrollment",
	"federated",
	"email_link",
	"email_otp",
	"phone_otp",
	"wallet_signature",
	"passkey",
	"anonymous",
	"admin_impersonation",
]);
const FACTOR_METHODS = new Set<AuthenticationFactorMethod>([
	"passkey",
	"totp",
	"otp",
	"recovery_code",
]);

export type InternalSessionIssuanceContext =
	| Readonly<{
			purpose: "interactive" | "impersonation";
			subjectId: string;
			evidence: readonly VerifiedAuthenticationEvidence[];
			targetOrganizationId: string | null;
	  }>
	| Readonly<{
			purpose: "replacement" | "device" | "organization";
			sourceSessionToken: string;
			targetOrganizationId: string | null;
	  }>;

export type ManagedSessionIssuanceFailureReason =
	| "context_required"
	| "context_invalid"
	| "subject_mismatch"
	| "unsupported_purpose"
	| "policy_unsatisfied";

export type CapturedSessionIssuanceAuthority = Readonly<{
	sourceSessionId: string;
	sourceCredentialId: string | null;
	sourceSubjectId: string;
	sourceOrganizationId: string | null;
	sourceExpiresAt: Date;
	sourceAssurance: ValidatedSessionAssuranceFields;
	transactionAdapter: object;
}>;

type SessionIssuanceCaptureAuthority = (
	context: Extract<
		InternalSessionIssuanceContext,
		{ purpose: "replacement" | "device" | "organization" }
	>,
) => Promise<CapturedSessionIssuanceAuthority>;

export class ManagedSessionIssuanceError extends Error {
	readonly code = "MANAGED_SESSION_ISSUANCE_FAILED" as const;

	constructor(
		readonly reason: ManagedSessionIssuanceFailureReason,
		options?: { cause?: unknown; requirement?: SessionAssuranceRequirement },
	) {
		super("Managed session issuance failed closed", { cause: options?.cause });
		this.name = "ManagedSessionIssuanceError";
		this.requirement = options?.requirement
			? Object.freeze({
					...options.requirement,
					allowedFactors: Object.freeze({
						...options.requirement.allowedFactors,
					}),
				})
			: undefined;
	}

	readonly requirement: SessionAssuranceRequirement | undefined;
}

const contexts = new WeakMap<object, InternalSessionIssuanceContext>();
const captureAuthorities = new WeakMap<object, SessionIssuanceCaptureAuthority>();
const capturedAuthorities = new WeakMap<
	object,
	CapturedSessionIssuanceAuthority
>();

function invalid(): never {
	throw new ManagedSessionIssuanceError("context_invalid");
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
		if (typeof key === "symbol") invalid();
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
	requiredKeys: readonly string[],
	optionalKeys: readonly string[] = [],
): Record<string, unknown> {
	const record = dataObject(value);
	const keys = Object.keys(record);
	if (
		requiredKeys.some((key) => !Object.hasOwn(record, key)) ||
		keys.some(
			(key) => !requiredKeys.includes(key) && !optionalKeys.includes(key),
		)
	) {
		invalid();
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
		invalid();
	}
	return value;
}

function targetOrganizationId(value: unknown): string | null {
	return value === undefined || value === null ? null : identifier(value);
}

function evidence(value: unknown): readonly VerifiedAuthenticationEvidence[] {
	if (!Array.isArray(value)) invalid();
	return Object.freeze(
		value.map((item): VerifiedAuthenticationEvidence => {
			const record = dataObject(item);
			if (record.kind === "primary") {
				const primary = exactObject(item, ["kind", "primaryMethod"]);
				if (
					typeof primary.primaryMethod !== "string" ||
					!PRIMARY_METHODS.has(
						primary.primaryMethod as AuthenticationPrimaryMethod,
					)
				) {
					invalid();
				}
				return Object.freeze({
					kind: "primary",
					primaryMethod:
						primary.primaryMethod as AuthenticationPrimaryMethod,
				});
			}
			if (record.kind === "factor") {
				const factor = exactObject(item, ["kind", "factorMethod"]);
				if (
					typeof factor.factorMethod !== "string" ||
					!FACTOR_METHODS.has(
						factor.factorMethod as AuthenticationFactorMethod,
					)
				) {
					invalid();
				}
				return Object.freeze({
					kind: "factor",
					factorMethod: factor.factorMethod as AuthenticationFactorMethod,
				});
			}
			return invalid();
		}),
	);
}

export function createInternalSessionIssuanceContext(
	value: unknown,
): SessionIssuanceContext {
	const base = exactObject(value, ["purpose"], [
		"subjectId",
		"evidence",
		"sourceSessionToken",
		"targetOrganizationId",
	]);
	let normalized: InternalSessionIssuanceContext;
	if (base.purpose === "interactive" || base.purpose === "impersonation") {
		const input = exactObject(value, ["purpose", "subjectId", "evidence"], [
			"targetOrganizationId",
		]);
		normalized = Object.freeze({
			purpose: base.purpose,
			subjectId: identifier(input.subjectId),
			evidence: evidence(input.evidence),
			targetOrganizationId: targetOrganizationId(
				input.targetOrganizationId,
			),
		});
	} else if (
		base.purpose === "replacement" ||
		base.purpose === "device" ||
		base.purpose === "organization"
	) {
		const input = exactObject(value, ["purpose", "sourceSessionToken"], [
			"targetOrganizationId",
		]);
		normalized = Object.freeze({
			purpose: base.purpose,
			sourceSessionToken: identifier(input.sourceSessionToken, 4_096),
			targetOrganizationId: targetOrganizationId(
				input.targetOrganizationId,
			),
		});
	} else {
		return invalid();
	}
	const opaque = normalized as unknown as SessionIssuanceContext;
	contexts.set(opaque, normalized);
	return opaque;
}

export function attachInternalSessionIssuanceCaptureAuthority(
	internalAdapter: InternalAdapter,
	capture: SessionIssuanceCaptureAuthority,
): void {
	if (captureAuthorities.has(internalAdapter)) invalid();
	captureAuthorities.set(internalAdapter, capture);
}

export async function captureInternalSessionIssuanceContext(
	internalAdapter: InternalAdapter,
	value: unknown,
): Promise<SessionIssuanceContext | undefined> {
	const opaque = createInternalSessionIssuanceContext(value);
	const context = readInternalSessionIssuanceContext(opaque);
	if (
		!context ||
		(context.purpose !== "replacement" &&
			context.purpose !== "device" &&
			context.purpose !== "organization")
	) {
		contexts.delete(opaque as object);
		invalid();
	}
	const capture = captureAuthorities.get(internalAdapter);
	if (!capture) {
		contexts.delete(opaque as object);
		return undefined;
	}
	try {
		const authority = await capture(context);
		capturedAuthorities.set(opaque as object, authority);
		return opaque;
	} catch (error) {
		contexts.delete(opaque as object);
		throw error;
	}
}

export function readInternalSessionIssuanceContext(
	value: unknown,
): InternalSessionIssuanceContext | undefined {
	return typeof value === "object" && value !== null
		? contexts.get(value)
		: undefined;
}

export function requireInternalSessionIssuanceContext(
	value: unknown,
): InternalSessionIssuanceContext {
	if (value === undefined) {
		throw new ManagedSessionIssuanceError("context_required");
	}
	const context = readInternalSessionIssuanceContext(value);
	if (!context) throw new ManagedSessionIssuanceError("context_invalid");
	contexts.delete(value as object);
	return context;
}

export function requireCapturedSessionIssuanceAuthority(
	value: unknown,
): CapturedSessionIssuanceAuthority {
	if (typeof value !== "object" || value === null) invalid();
	const authority = capturedAuthorities.get(value);
	if (!authority) {
		throw new ManagedSessionIssuanceError("unsupported_purpose");
	}
	capturedAuthorities.delete(value);
	return authority;
}
