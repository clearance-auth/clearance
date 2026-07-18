import type { User } from "@clearance/runtime";
import type { Team } from "@clearance/runtime/plugins";
import { getResourceURL } from "./utils";
import { SCIMGroupResourceSchema } from "./group-schemas";

export type SCIMGroupBinding = {
	id: string;
	providerId: string;
	organizationId: string;
	teamId: string;
	externalId?: string | null;
	externalIdKey?: string | null;
	createdAt: Date;
	updatedAt?: Date | null;
};

export const createGroupResource = (
	baseURL: string,
	team: Team,
	binding: SCIMGroupBinding,
	members: User[],
) => ({
	id: binding.id,
	externalId: binding.externalId ?? undefined,
	displayName: team.name,
	members: members.map((user) => ({
		value: user.id,
		$ref: getResourceURL(`/scim/v2/Users/${user.id}`, baseURL),
		type: "User",
		display: user.name,
	})),
	meta: {
		resourceType: "Group",
		created: binding.createdAt,
		lastModified: binding.updatedAt ?? binding.createdAt,
		location: getResourceURL(`/scim/v2/Groups/${binding.id}`, baseURL),
	},
	schemas: [SCIMGroupResourceSchema.id],
});
