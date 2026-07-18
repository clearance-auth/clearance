import type {
	ManagementCallOptions,
	ManagementClient,
	ManagementResponse,
} from "../client.js";
import {
	ORGANIZATION_MEMBER_REMOVE,
	type OrganizationMemberFixtureRegistry,
} from "../fixtures.js";
import type { OperationInput, OperationOutput } from "../spec.js";

type RemoveOperation = OrganizationMemberFixtureRegistry[typeof ORGANIZATION_MEMBER_REMOVE.id];

/**
 * Generated-resource pattern: each method binds its canonical operation id and
 * exact generated types. Consumers choose a client, never an operation id.
 */
export function createOrganizationMemberResource(
	client: ManagementClient<OrganizationMemberFixtureRegistry>,
) {
	return {
		remove(
			input: OperationInput<RemoveOperation>,
			options?: ManagementCallOptions<RemoveOperation>,
		): Promise<ManagementResponse<OperationOutput<RemoveOperation>>> {
			return client.call(ORGANIZATION_MEMBER_REMOVE.id, input, options);
		},
	};
}
