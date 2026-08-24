import * as z from "zod";

export const SCIMGroupResourceSchema = {
	id: "urn:ietf:params:scim:schemas:core:2.0:Group",
	schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
	name: "Group",
	description: "Organization team synchronized through SCIM",
	attributes: [
		{
			name: "id", type: "string", multiValued: false, required: false,
			caseExact: true, mutability: "readOnly", returned: "default", uniqueness: "server",
		},
		{
			name: "externalId", type: "string", multiValued: false, required: false,
			caseExact: true, mutability: "readWrite", returned: "default", uniqueness: "none",
		},
		{
			name: "displayName", type: "string", multiValued: false, required: true,
			caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none",
		},
		{
			name: "members", type: "complex", multiValued: true, required: false,
			mutability: "readWrite", returned: "default", uniqueness: "none",
			subAttributes: [
				{ name: "value", type: "string", multiValued: false, required: false, caseExact: true, mutability: "immutable", returned: "default", uniqueness: "none" },
				{ name: "$ref", type: "reference", referenceTypes: ["User"], multiValued: false, required: false, caseExact: true, mutability: "readOnly", returned: "default", uniqueness: "none" },
				{ name: "type", type: "string", canonicalValues: ["User"], multiValued: false, required: false, caseExact: false, mutability: "immutable", returned: "default", uniqueness: "none" },
				{ name: "display", type: "string", multiValued: false, required: false, caseExact: false, mutability: "readOnly", returned: "default", uniqueness: "none" },
			],
		},
	],
	meta: {
		resourceType: "Schema",
		location: "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group",
	},
} as const;

export const SCIMGroupResourceType = {
	schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
	id: "Group",
	name: "Group",
	endpoint: "/Groups",
	description: "Organization team synchronized through SCIM",
	schema: SCIMGroupResourceSchema.id,
	meta: { resourceType: "ResourceType", location: "/scim/v2/ResourceTypes/Group" },
} as const;

const member = z.object({ value: z.string().min(1), display: z.string().optional() });

export const APIGroupSchema = z.object({
	schemas: z.array(z.string()).optional(),
	externalId: z.string().optional(),
	displayName: z.string().min(1),
	members: z.array(member).optional(),
});

export const GroupPatchSchema = z.object({
	schemas: z.array(z.string()).refine(
		(s) => s.includes("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
		{ message: "Invalid schemas for PatchOp" },
	),
	Operations: z.array(z.object({
		op: z.string().toLowerCase().pipe(z.enum(["add", "replace", "remove"])),
		path: z.string().optional(),
		value: z.unknown().optional(),
	})).min(1),
});

export type APIGroup = z.infer<typeof APIGroupSchema>;
