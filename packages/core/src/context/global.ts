import type { AsyncLocalStorage } from "@clearance/core/async_hooks";

interface ClearanceGlobal {
	/**
	 * The version of Clearance.
	 */
	version: string;
	/**
	 * Used to track the number of Clearance instances in the same process.
	 *
	 * Debugging purposes only.
	 */
	epoch: number;
	/**
	 * Stores the AsyncLocalStorage instances for each context.
	 */
	context: Record<string, AsyncLocalStorage<unknown>>;
}

const symbol = Symbol.for("clearance:global");
let bind: ClearanceGlobal | null = null;

const __context: Record<string, AsyncLocalStorage<unknown>> = {};
const __clearanceVersion: string = import.meta.env
	.CLEARANCE_VERSION as string;

/**
 * We store context instance in the globalThis.
 *
 * The reason we do this is that some bundlers, web framework, or package managers might
 * create multiple copies of Clearance in the same process intentionally or unintentionally.
 *
 * For example, yarn v1, Next.js, SSR, Vite...
 *
 * @internal
 */
export function __getClearanceGlobal(): ClearanceGlobal {
	if (!(globalThis as any)[symbol]) {
		(globalThis as any)[symbol] = {
			version: __clearanceVersion,
			epoch: 1,
			context: __context,
		};
		bind = (globalThis as any)[symbol] as ClearanceGlobal;
	}
	bind = (globalThis as any)[symbol] as ClearanceGlobal;
	if (bind.version !== __clearanceVersion) {
		bind.version = __clearanceVersion;
		// Different versions of Clearance are loaded in the same process.
		bind.epoch++;
	}
	return (globalThis as any)[symbol] as ClearanceGlobal;
}

export function getClearanceVersion(): string {
	return __getClearanceGlobal().version;
}
