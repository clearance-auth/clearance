const functionIntrinsicKeys = new Set(Reflect.ownKeys(function endpoint() {}));

/**
 * Copy endpoint metadata without redefining the target function's intrinsic
 * properties (`name`, `length`, `caller`, and so on). Endpoint metadata can
 * intentionally be non-enumerable or symbol-keyed, so assignment is not
 * sufficient here.
 */
export function copyEndpointMetadata<T extends Function>(
	target: T,
	source: Function,
): T {
	for (const key of Reflect.ownKeys(source)) {
		if (functionIntrinsicKeys.has(key)) continue;
		const descriptor = Object.getOwnPropertyDescriptor(source, key);
		if (descriptor) Object.defineProperty(target, key, descriptor);
	}
	return target;
}

export const shimContext = <T extends Record<string, any>>(
	originalObject: T,
	newContext: Record<string, any>,
) => {
	const shimmedObj: Record<string | symbol, any> = {};
	for (const key of Reflect.ownKeys(originalObject)) {
		const descriptor = Object.getOwnPropertyDescriptor(originalObject, key);
		if (!descriptor || typeof descriptor.value !== "function") {
			if (descriptor) Object.defineProperty(shimmedObj, key, descriptor);
			continue;
		}

		const endpoint = descriptor.value;
		const shimmedEndpoint = copyEndpointMetadata(
			(ctx: Record<string, any>) =>
				endpoint({
					...ctx,
					context: {
						...newContext,
						...ctx.context,
					},
				}),
			endpoint,
		);
		Object.defineProperty(shimmedObj, key, {
			...descriptor,
			value: shimmedEndpoint,
		});
	}
	return shimmedObj as T;
};
