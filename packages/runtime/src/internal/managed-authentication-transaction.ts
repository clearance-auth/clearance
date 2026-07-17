import type { GenericEndpointContext } from "@clearance/core";
import { runWithTransaction } from "@clearance/core/context";
import { readInternalAuthenticationPolicy } from "./authentication-policy";

const TRANSACTION_REQUIRED_MESSAGE =
	"Managed authentication requires rollback-capable database transactions";

export function usesManagedAuthenticationPolicy(
	ctx: GenericEndpointContext,
): boolean {
	return Boolean(readInternalAuthenticationPolicy(ctx.context.options));
}

export function requireManagedAuthenticationTransaction(
	ctx: GenericEndpointContext,
): boolean {
	const managed = usesManagedAuthenticationPolicy(ctx);
	if (
		managed &&
		typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function"
	) {
		throw new Error(TRANSACTION_REQUIRED_MESSAGE);
	}
	return managed;
}

export async function runManagedAuthenticationTransaction<R>(
	ctx: GenericEndpointContext,
	fn: () => R,
): Promise<Awaited<R>> {
	if (!requireManagedAuthenticationTransaction(ctx)) {
		return await fn();
	}
	return await runWithTransaction(ctx.context.adapter, fn);
}
