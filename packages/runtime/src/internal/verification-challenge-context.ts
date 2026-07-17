import type {
	GenericEndpointContext,
	InternalAdapter,
	VerificationChallengeConsumptionContext,
	VerificationChallengeCreationContext,
} from "@clearance/core";
import { runManagedAuthenticationTransaction } from "./managed-authentication-transaction";

export type InternalVerificationChallengeBinding = Readonly<{
	purpose: string;
	subject: string;
	identifier: string;
}>;

export type InternalVerificationChallengeCreation =
	InternalVerificationChallengeBinding &
		Readonly<{
			value: string;
			expiresAt: Date;
		}>;

export class ManagedVerificationChallengeError extends Error {
	readonly code = "MANAGED_VERIFICATION_CHALLENGE_FAILED" as const;

	constructor(
		readonly reason:
			| "context_required"
			| "context_invalid"
			| "challenge_mismatch"
			| "binding_mismatch",
	) {
		super("Managed verification challenge failed closed");
		this.name = "ManagedVerificationChallengeError";
	}
}

const creationContexts = new WeakMap<
	object,
	InternalVerificationChallengeCreation
>();
const consumptionContexts = new WeakMap<
	object,
	InternalVerificationChallengeBinding
>();

function invalid(): never {
	throw new ManagedVerificationChallengeError("context_invalid");
}

function exactRecord(
	value: unknown,
	keys: readonly string[],
): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return invalid();
	}
	let prototype: object | null;
	let ownKeys: (string | symbol)[];
	try {
		prototype = Object.getPrototypeOf(value);
		ownKeys = Reflect.ownKeys(value);
	} catch {
		return invalid();
	}
	if (
		(prototype !== Object.prototype && prototype !== null) ||
		ownKeys.some((key) => typeof key !== "string" || !keys.includes(key)) ||
		keys.some((key) => !ownKeys.includes(key))
	) {
		return invalid();
	}
	const record: Record<string, unknown> = Object.create(null);
	for (const key of keys) {
		let descriptor: PropertyDescriptor | undefined;
		try {
			descriptor = Object.getOwnPropertyDescriptor(value, key);
		} catch {
			return invalid();
		}
		if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
			return invalid();
		}
		record[key] = descriptor.value;
	}
	return record;
}

function text(value: unknown, maximum: number): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > maximum ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		return invalid();
	}
	return value;
}

function binding(record: Record<string, unknown>) {
	return {
		purpose: text(record.purpose, 128),
		subject: text(record.subject, 4_096),
		identifier: text(record.identifier, 4_096),
	} satisfies InternalVerificationChallengeBinding;
}

export function createInternalVerificationChallengeContext(
	value: unknown,
): VerificationChallengeCreationContext {
	const record = exactRecord(value, [
		"purpose",
		"subject",
		"identifier",
		"value",
		"expiresAt",
	]);
	const expiresAt = record.expiresAt;
	if (
		!(expiresAt instanceof Date) ||
		!Number.isFinite(expiresAt.getTime())
	) {
		return invalid();
	}
	const normalized = Object.freeze({
		...binding(record),
		value: text(record.value, 65_536),
		expiresAt: new Date(expiresAt.getTime()),
	});
	const opaque = normalized as unknown as VerificationChallengeCreationContext;
	creationContexts.set(opaque, normalized);
	return opaque;
}

export function createInternalVerificationConsumptionContext(
	value: unknown,
): VerificationChallengeConsumptionContext {
	const normalized = Object.freeze(
		binding(exactRecord(value, ["purpose", "subject", "identifier"])),
	);
	const opaque =
		normalized as unknown as VerificationChallengeConsumptionContext;
	consumptionContexts.set(opaque, normalized);
	return opaque;
}

export function requireInternalVerificationChallengeContext(
	value: unknown,
): InternalVerificationChallengeCreation {
	if (value === undefined) {
		throw new ManagedVerificationChallengeError("context_required");
	}
	const context =
		typeof value === "object" && value !== null
			? creationContexts.get(value)
			: undefined;
	if (!context) invalid();
	creationContexts.delete(value as object);
	return context;
}

export function requireInternalVerificationConsumptionContext(
	value: unknown,
): InternalVerificationChallengeBinding {
	if (value === undefined) {
		throw new ManagedVerificationChallengeError("context_required");
	}
	const context =
		typeof value === "object" && value !== null
			? consumptionContexts.get(value)
			: undefined;
	if (!context) invalid();
	consumptionContexts.delete(value as object);
	return context;
}

export function createInternalVerificationChallenge(
	adapter: InternalAdapter,
	binding: Readonly<{ purpose: string; subject: string }>,
	data: Parameters<InternalAdapter["createVerificationValue"]>[0],
) {
	return adapter.createVerificationValue(
		data,
		createInternalVerificationChallengeContext({ ...binding, ...data }),
	);
}

export function consumeInternalVerificationChallenge(
	adapter: InternalAdapter,
	binding: Readonly<{
		purpose: string;
		subject: string;
		identifier: string;
	}>,
) {
	return adapter.consumeVerificationValue(
		binding.identifier,
		createInternalVerificationConsumptionContext(binding),
	);
}

export type InternalVerificationChallengeAuthority = Readonly<{
	create: typeof createInternalVerificationChallenge;
	consume: typeof consumeInternalVerificationChallenge;
	runTransaction<R>(
		ctx: GenericEndpointContext,
		fn: () => R,
	): Promise<Awaited<R>>;
}>;

export function createInternalVerificationChallengeAuthority(): InternalVerificationChallengeAuthority {
	return Object.freeze({
		create: createInternalVerificationChallenge,
		consume: consumeInternalVerificationChallenge,
		runTransaction: runManagedAuthenticationTransaction,
	});
}
