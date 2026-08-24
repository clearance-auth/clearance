import type {
	ManagementCallOptions,
	ManagementClient,
	ManagementResponse,
} from "../client.js";
import type { OperationOutput, OperationRegistry } from "../spec.js";

/** Typed convenience facade over a generated operation registry. */
export function createOperationResource<Registry extends OperationRegistry>(client: ManagementClient<Registry>) {
	return {
		call<Id extends keyof Registry & string>(
			id: Id,
			input: import("../spec.js").OperationInput<Registry[Id]>,
			options?: ManagementCallOptions<Registry[Id]>,
		): Promise<ManagementResponse<OperationOutput<Registry[Id]>>> {
			return client.call(id, input, options);
		},
	};
}
