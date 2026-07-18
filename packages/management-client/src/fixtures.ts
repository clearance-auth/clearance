import * as z from "zod";
import { defineOperation, defineOperationRegistry } from "./spec.js";

/** One nested operation proves the generated descriptor protocol end to end. */
export const ORGANIZATION_MEMBER_REMOVE = defineOperation({
	id: "organizations.members.remove",
	http: { method: "DELETE", path: "/v1/organizations/:id/members/:memberId" },
	mutation: true,
	supportsDryRun: true,
	confirmation: "client-required",
	schemas: {
		input: z.object({
			id: z.string().min(1),
			memberId: z.string().min(1),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.object({
			organizationId: z.string(),
			memberId: z.string(),
			removed: z.boolean(),
		}).strict(),
	},
	transport: { path: ["id", "memberId"], query: [], body: ["dryRun"] },
});

export const ORGANIZATION_MEMBER_FIXTURE_OPERATIONS = defineOperationRegistry({
	[ORGANIZATION_MEMBER_REMOVE.id]: ORGANIZATION_MEMBER_REMOVE,
});

export type OrganizationMemberFixtureRegistry = typeof ORGANIZATION_MEMBER_FIXTURE_OPERATIONS;
