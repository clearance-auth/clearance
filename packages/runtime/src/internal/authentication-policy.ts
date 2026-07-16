import type {
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
	RuntimeAuthenticationPolicyOverride,
	RuntimeAuthenticationPolicyReader,
	RuntimeAuthenticationPolicyReaderInput,
	RuntimeAuthenticationPolicyReaderResult,
} from "@clearance/core";

const POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807n;
const POLICY_KEYS = [
	"passwordLockout",
	"factorLockout",
	"minimumAssurance",
	"allowedFactors",
	"trustedDevice",
	"assuranceMaxAgeSeconds",
] as const;

export class InvalidRuntimeAuthenticationPolicyError extends Error {
	readonly code = "AUTHENTICATION_POLICY_RESPONSE_INVALID" as const;

	constructor() {
		super("Authentication policy authority returned an invalid response");
		this.name = "InvalidRuntimeAuthenticationPolicyError";
	}
}

export class RuntimeAuthenticationPolicyReaderError extends Error {
	readonly code = "AUTHENTICATION_POLICY_READER_UNAVAILABLE" as const;

	constructor(cause?: unknown) {
		super("Authentication policy authority is unavailable", { cause });
		this.name = "RuntimeAuthenticationPolicyReaderError";
	}
}

export type InternalRuntimeAuthenticationPolicyBinding = Readonly<{
	identity: RuntimeAuthenticationPolicyIdentity;
	reader: RuntimeAuthenticationPolicyReader;
}>;

const bindings = new WeakMap<
	object,
	InternalRuntimeAuthenticationPolicyBinding
>();

function invalid(): never {
	throw new InvalidRuntimeAuthenticationPolicyError();
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

function object(
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

function partialObject(
	value: unknown,
	keys: readonly string[],
): Record<string, unknown> {
	const record = dataObject(value);
	if (Object.keys(record).some((key) => !keys.includes(key))) invalid();
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

function boolean(value: unknown): boolean {
	if (typeof value !== "boolean") invalid();
	return value;
}

function integer(value: unknown, minimum: number, maximum: number): number {
	if (
		!Number.isSafeInteger(value) ||
		(value as number) < minimum ||
		(value as number) > maximum
	) {
		invalid();
	}
	return value as number;
}

function revision(value: unknown): string {
	if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) invalid();
	let parsed: bigint;
	try {
		parsed = BigInt(value);
	} catch {
		invalid();
	}
	if (parsed <= 0n || parsed > POSTGRES_BIGINT_MAX) invalid();
	return value;
}

function identity(value: unknown): RuntimeAuthenticationPolicyIdentity {
	const input = object(value, ["projectId", "environmentId"]);
	return Object.freeze({
		projectId: identifier(input.projectId),
		environmentId: identifier(input.environmentId),
	});
}

function lockout(
	value: unknown,
): RuntimeAuthenticationPolicy["passwordLockout"] {
	const input = object(value, [
		"enabled",
		"maxFailedAttempts",
		"durationSeconds",
	]);
	return Object.freeze({
		enabled: boolean(input.enabled),
		maxFailedAttempts: integer(input.maxFailedAttempts, 3, 100),
		durationSeconds: integer(input.durationSeconds, 30, 86_400),
	});
}

function allowedFactors(
	value: unknown,
): RuntimeAuthenticationPolicy["allowedFactors"] {
	const input = object(value, ["totp", "passkey"]);
	return Object.freeze({
		totp: boolean(input.totp),
		passkey: boolean(input.passkey),
	});
}

function trustedDevice(
	value: unknown,
): RuntimeAuthenticationPolicy["trustedDevice"] {
	const input = object(value, ["enabled", "maxAgeSeconds"]);
	const enabled = boolean(input.enabled);
	return Object.freeze({
		enabled,
		maxAgeSeconds: integer(input.maxAgeSeconds, enabled ? 60 : 0, 2_592_000),
	});
}

function minimumAssurance(
	value: unknown,
): RuntimeAuthenticationPolicy["minimumAssurance"] {
	if (
		value !== "single_factor" &&
		value !== "multi_factor" &&
		value !== "phishing_resistant"
	) {
		invalid();
	}
	return value;
}

function maxAge(value: unknown): number | null {
	return value === null ? null : integer(value, 60, 2_592_000);
}

function assertPolicyCrossFields(policy: RuntimeAuthenticationPolicy): void {
	if (
		policy.minimumAssurance !== "single_factor" &&
		!policy.allowedFactors.totp &&
		!policy.allowedFactors.passkey
	) {
		invalid();
	}
	if (
		policy.minimumAssurance === "phishing_resistant" &&
		(!policy.allowedFactors.passkey || policy.trustedDevice.enabled)
	) {
		invalid();
	}
}

export function normalizeRuntimeAuthenticationPolicy(
	value: unknown,
): RuntimeAuthenticationPolicy {
	const input = object(value, POLICY_KEYS);
	const normalized = Object.freeze({
		passwordLockout: lockout(input.passwordLockout),
		factorLockout: lockout(input.factorLockout),
		minimumAssurance: minimumAssurance(input.minimumAssurance),
		allowedFactors: allowedFactors(input.allowedFactors),
		trustedDevice: trustedDevice(input.trustedDevice),
		assuranceMaxAgeSeconds: maxAge(input.assuranceMaxAgeSeconds),
	});
	assertPolicyCrossFields(normalized);
	return normalized;
}

function optionalBoolean(
	record: Record<string, unknown>,
	key: string,
): boolean | undefined {
	return Object.hasOwn(record, key) ? boolean(record[key]) : undefined;
}

function optionalInteger(
	record: Record<string, unknown>,
	key: string,
	minimum: number,
	maximum: number,
): number | undefined {
	return Object.hasOwn(record, key)
		? integer(record[key], minimum, maximum)
		: undefined;
}

function lockoutOverride(
	value: unknown,
): NonNullable<RuntimeAuthenticationPolicyOverride["passwordLockout"]> {
	const input = partialObject(value, [
		"enabled",
		"maxFailedAttempts",
		"durationSeconds",
	]);
	const enabled = optionalBoolean(input, "enabled");
	const maxFailedAttempts = optionalInteger(input, "maxFailedAttempts", 3, 100);
	const durationSeconds = optionalInteger(input, "durationSeconds", 30, 86_400);
	return Object.freeze({
		...(enabled === undefined ? {} : { enabled }),
		...(maxFailedAttempts === undefined ? {} : { maxFailedAttempts }),
		...(durationSeconds === undefined ? {} : { durationSeconds }),
	});
}

function allowedFactorsOverride(
	value: unknown,
): NonNullable<RuntimeAuthenticationPolicyOverride["allowedFactors"]> {
	const input = partialObject(value, ["totp", "passkey"]);
	const totp = optionalBoolean(input, "totp");
	const passkey = optionalBoolean(input, "passkey");
	return Object.freeze({
		...(totp === undefined ? {} : { totp }),
		...(passkey === undefined ? {} : { passkey }),
	});
}

function trustedDeviceOverride(
	value: unknown,
): NonNullable<RuntimeAuthenticationPolicyOverride["trustedDevice"]> {
	const input = partialObject(value, ["enabled", "maxAgeSeconds"]);
	const enabled = optionalBoolean(input, "enabled");
	const minimum = enabled === true ? 60 : 0;
	const maxAgeSeconds = optionalInteger(
		input,
		"maxAgeSeconds",
		minimum,
		2_592_000,
	);
	return Object.freeze({
		...(enabled === undefined ? {} : { enabled }),
		...(maxAgeSeconds === undefined ? {} : { maxAgeSeconds }),
	});
}

export function normalizeRuntimeAuthenticationPolicyOverride(
	value: unknown,
): RuntimeAuthenticationPolicyOverride {
	const input = partialObject(value, POLICY_KEYS);
	return Object.freeze({
		...(Object.hasOwn(input, "passwordLockout")
			? { passwordLockout: lockoutOverride(input.passwordLockout) }
			: {}),
		...(Object.hasOwn(input, "factorLockout")
			? { factorLockout: lockoutOverride(input.factorLockout) }
			: {}),
		...(Object.hasOwn(input, "minimumAssurance")
			? { minimumAssurance: minimumAssurance(input.minimumAssurance) }
			: {}),
		...(Object.hasOwn(input, "allowedFactors")
			? { allowedFactors: allowedFactorsOverride(input.allowedFactors) }
			: {}),
		...(Object.hasOwn(input, "trustedDevice")
			? { trustedDevice: trustedDeviceOverride(input.trustedDevice) }
			: {}),
		...(Object.hasOwn(input, "assuranceMaxAgeSeconds")
			? { assuranceMaxAgeSeconds: maxAge(input.assuranceMaxAgeSeconds) }
			: {}),
	});
}

export function applyRuntimeAuthenticationPolicyOverride(
	environment: RuntimeAuthenticationPolicy,
	override: RuntimeAuthenticationPolicyOverride,
): RuntimeAuthenticationPolicy {
	const normalizedEnvironment =
		normalizeRuntimeAuthenticationPolicy(environment);
	const normalizedOverride =
		normalizeRuntimeAuthenticationPolicyOverride(override);
	return normalizeRuntimeAuthenticationPolicy({
		passwordLockout: {
			...normalizedEnvironment.passwordLockout,
			...normalizedOverride.passwordLockout,
		},
		factorLockout: {
			...normalizedEnvironment.factorLockout,
			...normalizedOverride.factorLockout,
		},
		minimumAssurance:
			normalizedOverride.minimumAssurance ??
			normalizedEnvironment.minimumAssurance,
		allowedFactors: {
			...normalizedEnvironment.allowedFactors,
			...normalizedOverride.allowedFactors,
		},
		trustedDevice: {
			...normalizedEnvironment.trustedDevice,
			...normalizedOverride.trustedDevice,
		},
		assuranceMaxAgeSeconds: Object.hasOwn(
			normalizedOverride,
			"assuranceMaxAgeSeconds",
		)
			? normalizedOverride.assuranceMaxAgeSeconds
			: normalizedEnvironment.assuranceMaxAgeSeconds,
	});
}

function samePolicy(
	left: RuntimeAuthenticationPolicy,
	right: RuntimeAuthenticationPolicy,
): boolean {
	return (
		left.passwordLockout.enabled === right.passwordLockout.enabled &&
		left.passwordLockout.maxFailedAttempts ===
			right.passwordLockout.maxFailedAttempts &&
		left.passwordLockout.durationSeconds ===
			right.passwordLockout.durationSeconds &&
		left.factorLockout.enabled === right.factorLockout.enabled &&
		left.factorLockout.maxFailedAttempts ===
			right.factorLockout.maxFailedAttempts &&
		left.factorLockout.durationSeconds ===
			right.factorLockout.durationSeconds &&
		left.minimumAssurance === right.minimumAssurance &&
		left.allowedFactors.totp === right.allowedFactors.totp &&
		left.allowedFactors.passkey === right.allowedFactors.passkey &&
		left.trustedDevice.enabled === right.trustedDevice.enabled &&
		left.trustedDevice.maxAgeSeconds === right.trustedDevice.maxAgeSeconds &&
		left.assuranceMaxAgeSeconds === right.assuranceMaxAgeSeconds
	);
}

export function normalizeRuntimeAuthenticationPolicyReaderResult(
	value: unknown,
	expectedIdentity: RuntimeAuthenticationPolicyIdentity,
	request: RuntimeAuthenticationPolicyReaderInput,
): RuntimeAuthenticationPolicyReaderResult {
	const normalizedRequest = normalizeReaderInput(request);
	const input = object(value, [
		"scope",
		"subjectId",
		"revision",
		"environment",
		"organizationMembership",
		"organizationOverride",
		"effective",
	]);
	const expectedScope = identity(expectedIdentity);
	const scope = identity(input.scope);
	if (
		scope.projectId !== expectedScope.projectId ||
		scope.environmentId !== expectedScope.environmentId
	) {
		invalid();
	}
	const subjectId = identifier(input.subjectId);
	if (subjectId !== normalizedRequest.subjectId) invalid();
	const currentRevision = revision(input.revision);
	if (normalizedRequest.minimumRevision !== undefined) {
		const minimum = revision(normalizedRequest.minimumRevision);
		if (BigInt(currentRevision) < BigInt(minimum)) invalid();
	}
	const environment = normalizeRuntimeAuthenticationPolicy(input.environment);
	let organizationMembership: RuntimeAuthenticationPolicyReaderResult["organizationMembership"] =
		null;
	if (normalizedRequest.organizationId === undefined) {
		if (input.organizationMembership !== null) invalid();
	} else {
		const membership = object(input.organizationMembership, [
			"subjectId",
			"organizationId",
		]);
		const membershipSubjectId = identifier(membership.subjectId);
		const membershipOrganizationId = identifier(membership.organizationId);
		if (
			membershipSubjectId !== normalizedRequest.subjectId ||
			membershipOrganizationId !== normalizedRequest.organizationId
		) {
			invalid();
		}
		organizationMembership = Object.freeze({
			subjectId: membershipSubjectId,
			organizationId: membershipOrganizationId,
		});
	}
	let organizationOverride: RuntimeAuthenticationPolicyReaderResult["organizationOverride"] =
		null;
	if (input.organizationOverride !== null) {
		if (normalizedRequest.organizationId === undefined) invalid();
		const rawOverride = object(input.organizationOverride, [
			"scope",
			"organizationId",
			"revision",
			"policy",
		]);
		const overrideScope = identity(rawOverride.scope);
		const organizationId = identifier(rawOverride.organizationId);
		const overrideRevision = revision(rawOverride.revision);
		if (
			overrideScope.projectId !== expectedScope.projectId ||
			overrideScope.environmentId !== expectedScope.environmentId ||
			organizationId !== normalizedRequest.organizationId ||
			BigInt(overrideRevision) > BigInt(currentRevision)
		) {
			invalid();
		}
		organizationOverride = Object.freeze({
			scope: overrideScope,
			organizationId,
			revision: overrideRevision,
			policy: normalizeRuntimeAuthenticationPolicyOverride(rawOverride.policy),
		});
	}
	const effective = applyRuntimeAuthenticationPolicyOverride(
		environment,
		organizationOverride?.policy ?? {},
	);
	const claimedEffective = normalizeRuntimeAuthenticationPolicy(
		input.effective,
	);
	if (!samePolicy(effective, claimedEffective)) invalid();
	return Object.freeze({
		scope,
		subjectId,
		revision: currentRevision,
		environment,
		organizationMembership,
		organizationOverride,
		effective,
	});
}

function normalizeReaderInput(
	value: RuntimeAuthenticationPolicyReaderInput,
): RuntimeAuthenticationPolicyReaderInput {
	const input = partialObject(value, [
		"subjectId",
		"organizationId",
		"minimumRevision",
		"transaction",
	]);
	if (!Object.hasOwn(input, "subjectId")) invalid();
	return Object.freeze({
		subjectId: identifier(input.subjectId),
		...(Object.hasOwn(input, "organizationId")
			? { organizationId: identifier(input.organizationId) }
			: {}),
		...(Object.hasOwn(input, "minimumRevision")
			? { minimumRevision: revision(input.minimumRevision) }
			: {}),
		...(Object.hasOwn(input, "transaction")
			? {
					transaction:
						input.transaction as RuntimeAuthenticationPolicyReaderInput["transaction"],
				}
			: {}),
	});
}

export function attachInternalAuthenticationPolicy<Target extends object>(
	target: Target,
	binding: InternalRuntimeAuthenticationPolicyBinding,
): Target {
	const normalizedIdentity = identity(binding.identity);
	if (bindings.has(target)) invalid();
	const readForSubject = binding.reader?.readForSubject;
	if (
		typeof binding.reader !== "object" ||
		binding.reader === null ||
		typeof readForSubject !== "function"
	) {
		invalid();
	}
	const reader = Object.freeze({
		readForSubject: readForSubject.bind(binding.reader),
	});
	bindings.set(target, Object.freeze({ identity: normalizedIdentity, reader }));
	return target;
}

export function readInternalAuthenticationPolicy(
	target: object,
): InternalRuntimeAuthenticationPolicyBinding | undefined {
	return bindings.get(target);
}

export async function resolveRuntimeAuthenticationPolicy(
	target: object,
	request: RuntimeAuthenticationPolicyReaderInput,
): Promise<RuntimeAuthenticationPolicyReaderResult> {
	const binding = bindings.get(target);
	if (!binding) throw new RuntimeAuthenticationPolicyReaderError();
	const normalizedRequest = normalizeReaderInput(request);
	let response: RuntimeAuthenticationPolicyReaderResult;
	try {
		response = await binding.reader.readForSubject(normalizedRequest);
	} catch (error) {
		throw new RuntimeAuthenticationPolicyReaderError(error);
	}
	return normalizeRuntimeAuthenticationPolicyReaderResult(
		response,
		binding.identity,
		normalizedRequest,
	);
}
