import type { GenericEndpointContext, InternalAdapter } from "@clearance/core";

type ChallengeData = Parameters<InternalAdapter["createVerificationValue"]>[0];

export type SSOInternalVerificationChallengeAuthority = Readonly<{
	create(
		adapter: InternalAdapter,
		binding: Readonly<{ purpose: string; subject: string }>,
		data: ChallengeData,
	): ReturnType<InternalAdapter["createVerificationValue"]>;
	consume(
		adapter: InternalAdapter,
		binding: Readonly<{
			purpose: string;
			subject: string;
			identifier: string;
		}>,
	): ReturnType<InternalAdapter["consumeVerificationValue"]>;
	runTransaction<R>(
		ctx: GenericEndpointContext,
		fn: () => R,
	): Promise<Awaited<R>>;
}>;

const authorities = new WeakMap<object, SSOInternalVerificationChallengeAuthority>();

export function attachSSOInternalVerificationChallengeAuthority<
	Target extends object,
>(
	target: Target,
	authority: SSOInternalVerificationChallengeAuthority,
): Target {
	if (authorities.has(target)) {
		throw new Error("SSO verification challenge authority is already attached");
	}
	authorities.set(target, authority);
	return target;
}

export function readSSOInternalVerificationChallengeAuthority(
	target: object | undefined,
): SSOInternalVerificationChallengeAuthority | undefined {
	return target ? authorities.get(target) : undefined;
}

export function createSSOVerificationChallenge(
	options: object | undefined,
	adapter: InternalAdapter,
	binding: Readonly<{ purpose: string; subject: string }>,
	data: ChallengeData,
) {
	const authority = readSSOInternalVerificationChallengeAuthority(options);
	return authority
		? authority.create(adapter, binding, data)
		: adapter.createVerificationValue(data);
}

export function consumeSSOVerificationChallenge(
	options: object | undefined,
	adapter: InternalAdapter,
	binding: Readonly<{
		purpose: string;
		subject: string;
		identifier: string;
	}>,
) {
	const authority = readSSOInternalVerificationChallengeAuthority(options);
	return authority
		? authority.consume(adapter, binding)
		: adapter.consumeVerificationValue(binding.identifier);
}

export function runSSOVerificationTransaction<R>(
	options: object | undefined,
	ctx: GenericEndpointContext,
	fn: () => R,
): Promise<Awaited<R>> {
	const authority = readSSOInternalVerificationChallengeAuthority(options);
	return authority ? authority.runTransaction(ctx, fn) : Promise.resolve(fn());
}
