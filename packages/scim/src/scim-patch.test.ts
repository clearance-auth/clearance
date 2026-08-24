import { sso } from "@clearance/sso";
import { clearance } from "@clearance/runtime";
import { memoryAdapter } from "@clearance/runtime/adapters/memory";
import { createAuthClient } from "@clearance/runtime/client";
import { setCookieToHeader } from "@clearance/runtime/cookies";
import { bearer, organization } from "@clearance/runtime/plugins";
import { describe, expect, it, vi } from "vitest";
import { scim } from ".";
import { scimClient } from "./client";
import {
	assertUserPatchWithinLimits,
	SCIM_USER_PATCH_LIMITS,
} from "./patch-operations";
import type { SCIMOptions } from "./types";

const createTestInstance = (scimOptions?: SCIMOptions) => {
	const testUser = {
		email: "test@email.com",
		password: "password",
		name: "Test User",
	};

	const data = {
		user: [],
		session: [],
		verification: [],
		account: [],
		ssoProvider: [],
		scimProvider: [],
		organization: [],
		member: [],
	};
	const adapterFactory = memoryAdapter(data);
	let adapter: ReturnType<typeof adapterFactory> | undefined;
	const memory = (options: Parameters<typeof adapterFactory>[0]) => {
		adapter = adapterFactory(options);
		return adapter;
	};

	const auth = clearance({
		database: memory,
		baseURL: "http://localhost:3000",
		emailAndPassword: {
			enabled: true,
		},
		plugins: [sso(), scim(scimOptions), organization()],
	});

	const authClient = createAuthClient({
		baseURL: "http://localhost:3000",
		plugins: [bearer(), scimClient()],
		fetchOptions: {
			customFetchImpl: async (url, init) => {
				return auth.handler(new Request(url, init));
			},
		},
	});

	async function getAuthCookieHeaders(
		user: { email: string; password: string; name: string } = testUser,
	) {
		const headers = new Headers();

		await authClient.signUp.email({
			email: user.email,
			password: user.password,
			name: user.name,
		});

		await authClient.signIn.email(user, {
			throw: true,
			onSuccess: setCookieToHeader(headers),
		});

		return headers;
	}

	async function getSCIMToken(
		providerId: string = "the-saml-provider-1",
		organizationId?: string,
	) {
		const headers = await getAuthCookieHeaders();
		const { scimToken } = await auth.api.generateSCIMToken({
			body: {
				providerId,
				organizationId,
			},
			headers,
		});

		return scimToken;
	}

	async function registerOrganization(org: string) {
		const headers = await getAuthCookieHeaders();

		return await auth.api.createOrganization({
			body: {
				slug: `the-${org}`,
				name: `the organization ${org}`,
			},
			headers,
		});
	}

	return {
		auth,
		authClient,
		getAdapter: () => adapter!,
		registerOrganization,
		getSCIMToken,
		getAuthCookieHeaders,
	};
};

describe("SCIM", () => {
	describe("PATCH /scim/v2/users", () => {
		it("rejects max-plus-one operations before any user lookup or mutation", async () => {
			const { auth, getAdapter, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();
			const findOne = vi.spyOn(getAdapter(), "findOne");
			const update = vi.spyOn(getAdapter(), "update");

			await expect(auth.api.patchSCIMUser({
				params: { userId: "never-looked-up" },
				body: {
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: Array.from(
						{ length: SCIM_USER_PATCH_LIMITS.maxOperations + 1 },
						() => ({ op: "replace", path: "/userName", value: "blocked" }),
					),
				},
				headers: { authorization: `Bearer ${scimToken}` },
			})).rejects.toThrowError(expect.objectContaining({
				body: expect.objectContaining({ code: "VALIDATION_ERROR" }),
			}));

			expect(findOne.mock.calls.filter(([input]) =>
				input.model === "account" || input.model === "user",
			)).toHaveLength(0);
			expect(update).not.toHaveBeenCalled();
		});

		it("accepts PATCH complexity limits exactly and rejects each max-plus-one value", () => {
			const { maxCollectionEntries, maxDepth, maxNodes, maxOperations, maxStringBytes } = SCIM_USER_PATCH_LIMITS;
			const operation = { op: "replace" as const, path: "/externalId", value: "value" };

			expect(() => assertUserPatchWithinLimits(Array.from({ length: maxOperations }, () => operation))).not.toThrow();
			expect(() => assertUserPatchWithinLimits(Array.from({ length: maxOperations + 1 }, () => operation))).toThrow("SCIM PATCH request exceeds supported complexity limits");

			let deepestAccepted: Record<string, unknown> | string = "value";
			for (let index = 0; index < maxDepth; index += 1) deepestAccepted = { value: deepestAccepted };
			expect(() => assertUserPatchWithinLimits([{ ...operation, value: deepestAccepted }])).not.toThrow();
			expect(() => assertUserPatchWithinLimits([{ ...operation, value: { value: deepestAccepted } }])).toThrow("SCIM PATCH request exceeds supported complexity limits");

			expect(() => assertUserPatchWithinLimits([{ ...operation, value: "a".repeat(maxStringBytes) }])).not.toThrow();
			expect(() => assertUserPatchWithinLimits([{ ...operation, value: "a".repeat(maxStringBytes + 1) }])).toThrow("SCIM PATCH request exceeds supported complexity limits");

			expect(() => assertUserPatchWithinLimits([{ ...operation, value: Array.from({ length: maxCollectionEntries }, () => "value") }])).not.toThrow();
			expect(() => assertUserPatchWithinLimits([{ ...operation, value: Array.from({ length: maxCollectionEntries + 1 }, () => "value") }])).toThrow("SCIM PATCH request exceeds supported complexity limits");

			const valueEntries = maxNodes - maxCollectionEntries - 2;
			const entriesPerCollection = Math.floor(valueEntries / maxCollectionEntries);
			const collectionsWithOneExtra = valueEntries % maxCollectionEntries;
			const nodeBoundary = Array.from({ length: maxCollectionEntries }, (_, index) =>
				Array.from({
					length: entriesPerCollection + (index < collectionsWithOneExtra ? 1 : 0),
				}, () => "value"),
			);
			expect(() => assertUserPatchWithinLimits([{ ...operation, value: nodeBoundary }])).not.toThrow();
			expect(() => assertUserPatchWithinLimits([{
				...operation,
				value: [...nodeBoundary.slice(0, 99), [...nodeBoundary[99]!, "value"]],
			}])).toThrow("SCIM PATCH request exceeds supported complexity limits");
		});

		it("rejects the former deeply nested PATCH payload through the handler without mutating the user", async () => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();
			const user = await auth.api.createSCIMUser({
				body: { userName: "depth-limit-user" },
				headers: { authorization: `Bearer ${scimToken}` },
			});

			let value: Record<string, unknown> | string = "x";
			for (let index = 0; index < 3_000; index += 1) value = { x: value };
			const response = await auth.handler(new Request(`http://localhost:3000/api/auth/scim/v2/Users/${user.id}`, {
				method: "PATCH",
				headers: {
					authorization: `Bearer ${scimToken}`,
					"content-type": "application/json",
				},
				body: JSON.stringify({
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: [{ op: "replace", path: "/userName", value }],
				}),
			}));

			expect(response.status).toBe(400);
			await expect(response.json()).resolves.toMatchObject({
				detail: "SCIM PATCH request exceeds supported complexity limits",
			});
			const unchanged = await auth.api.getSCIMUser({
				params: { userId: user.id },
				headers: { authorization: `Bearer ${scimToken}` },
			});
			expect(unchanged.userName).toBe("depth-limit-user");
		});

		it.for([
			"replace",
			"add",
		])("should partially update a user resource with %s", async (op) => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "the-username",
					name: {
						formatted: "Juan Perez",
					},
					emails: [{ value: "primary-email@test.com", primary: true }],
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			expect(user).toBeTruthy();
			expect(user.externalId).toBe("the-username");
			expect(user.userName).toBe("primary-email@test.com");
			expect(user.name.formatted).toBe("Juan Perez");
			expect(user.emails[0]?.value).toBe("primary-email@test.com");

			await auth.api.patchSCIMUser({
				params: {
					userId: user.id,
				},
				body: {
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: [
						{ op: op, path: "/externalId", value: "external-username" },
						{ op: op, path: "/userName", value: "other-username" },
						{ op: op, path: "/name/givenName", value: "Daniel" },
					],
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const updatedUser = await auth.api.getSCIMUser({
				params: {
					userId: user.id,
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			expect(updatedUser).toMatchObject({
				active: true,
				displayName: "Daniel Perez",
				emails: [
					{
						primary: true,
						value: "other-username",
					},
				],
				externalId: "external-username",
				id: expect.any(String),
				meta: expect.objectContaining({
					created: expect.any(Date),
					lastModified: expect.any(Date),
					location: expect.stringContaining("/api/auth/scim/v2/Users/"),
					resourceType: "User",
				}),
				name: {
					formatted: "Daniel Perez",
				},
				schemas: expect.arrayContaining([
					"urn:ietf:params:scim:schemas:core:2.0:User",
				]),
				userName: "other-username",
			});
		});

		it("should partially update a user resource with mixed operations", async () => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "the-username",
					name: {
						formatted: "Juan Perez",
					},
					emails: [{ value: "primary-email@test.com", primary: true }],
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			expect(user).toBeTruthy();
			expect(user.externalId).toBe("the-username");
			expect(user.userName).toBe("primary-email@test.com");
			expect(user.name.formatted).toBe("Juan Perez");
			expect(user.emails[0]?.value).toBe("primary-email@test.com");

			await auth.api.patchSCIMUser({
				params: {
					userId: user.id,
				},
				body: {
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: [
						{ op: "add", path: "/externalId", value: "external-username" },
						{ op: "replace", path: "/userName", value: "other-username" },
						{ op: "add", path: "/name/formatted", value: "Daniel Lopez" },
					],
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const updatedUser = await auth.api.getSCIMUser({
				params: {
					userId: user.id,
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			expect(updatedUser).toMatchObject({
				active: true,
				displayName: "Daniel Lopez",
				emails: [
					{
						primary: true,
						value: "other-username",
					},
				],
				externalId: "external-username",
				id: expect.any(String),
				meta: expect.objectContaining({
					created: expect.any(Date),
					lastModified: expect.any(Date),
					location: expect.stringContaining("/api/auth/scim/v2/Users/"),
					resourceType: "User",
				}),
				name: {
					formatted: "Daniel Lopez",
				},
				schemas: expect.arrayContaining([
					"urn:ietf:params:scim:schemas:core:2.0:User",
				]),
				userName: "other-username",
			});
		});

		it.for([
			"replace",
			"add",
		])("should partially update multiple name sub-attributes with %s", async (op) => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "sub-attribute-test-user",
					name: {
						formatted: "Original Name",
					},
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			await auth.api.patchSCIMUser({
				params: { userId: user.id },
				body: {
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: [
						{ op: op, path: "/name/givenName", value: "Updated" },
						{ op: op, path: "/name/familyName", value: "Value" },
					],
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const updatedUser = await auth.api.getSCIMUser({
				params: { userId: user.id },
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			expect(updatedUser.name.formatted).toBe("Updated Value");
		});

		it.for([
			"replace",
			"add",
		])("should %s nested object values with path prefix", async (op) => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "nested-test-user",
					name: { formatted: "Original Name" },
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			await auth.api.patchSCIMUser({
				params: { userId: user.id },
				body: {
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: [
						{
							op: op,
							path: "name",
							value: { givenName: "Nested" },
						},
						{
							op: op,
							path: "name",
							value: { familyName: "User" },
						},
						{
							op: op,
							path: "userName",
							value: "nested-test-user-updated",
						},
					],
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const updatedUser = await auth.api.getSCIMUser({
				params: { userId: user.id },
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			expect(updatedUser.name.formatted).toBe("Nested User");
			expect(updatedUser.displayName).toBe("Nested User");
			expect(updatedUser.userName).toBe("nested-test-user-updated");
		});

		it.for([
			"replace",
			"add",
		])("should support operations without explicit path with %s", async (op) => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "no-path-test-user",
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			await auth.api.patchSCIMUser({
				params: { userId: user.id },
				body: {
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: [
						{
							op: op,
							value: {
								name: { formatted: "No Path Name" },
								userName: "Username",
							},
						},
					],
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const updatedUser = await auth.api.getSCIMUser({
				params: { userId: user.id },
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			expect(updatedUser.name.formatted).toBe("No Path Name");
			expect(updatedUser.userName).toBe("username");
		});

		it("should support dot notation in paths", async () => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "dot-notation-user",
					name: { formatted: "Original Name" },
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			await auth.api.patchSCIMUser({
				params: { userId: user.id },
				body: {
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: [
						{ op: "replace", path: "name.familyName", value: "Dot" },
						{ op: "add", path: "name.givenName", value: "User" },
						{ op: "add", path: "userName", value: "Username" },
					],
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const updatedUser = await auth.api.getSCIMUser({
				params: { userId: user.id },
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			expect(updatedUser.name.formatted).toBe("User Dot");
			expect(updatedUser.userName).toBe("username");
		});

		it.for([
			"replace",
			"add",
		])("should handle %s operation case-insensitively", async (op) => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "user-case-insensitive",
					name: { formatted: "Original" },
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			await auth.api.patchSCIMUser({
				params: { userId: user.id },
				body: {
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: [
						{
							op: op.toUpperCase(),
							path: "name.formatted",
							value: "user-case",
						},
					],
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const updatedUser = await auth.api.getSCIMUser({
				params: { userId: user.id },
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			expect(updatedUser.name.formatted).toBe("user-case");
		});

		it("should skip add operation when value already exists", async () => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "add-same-info-user",
					name: { formatted: "Existing Name" },
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const patchUser = () =>
				auth.api.patchSCIMUser({
					params: { userId: user.id },
					body: {
						schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
						Operations: [
							{ op: "add", path: "/name/formatted", value: "Existing Name" },
						],
					},
					headers: {
						authorization: `Bearer ${scimToken}`,
					},
				});

			await expect(patchUser()).rejects.toThrowError(
				expect.objectContaining({
					message: "No valid fields to update",
					body: {
						detail: "No valid fields to update",
						schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
						status: "400",
					},
				}),
			);
		});

		it.for([
			"replace",
			"add",
		])("should ignore %s on non-existing path", async (op) => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "non-existing-path",
					name: { formatted: "Original Name" },
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const patchUser = () =>
				auth.api.patchSCIMUser({
					params: { userId: user.id },
					body: {
						schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
						Operations: [
							{ op: op, path: "/nonExistentField", value: "Some Value" },
						],
					},
					headers: {
						authorization: `Bearer ${scimToken}`,
					},
				});

			await expect(patchUser()).rejects.toThrowError(
				expect.objectContaining({
					message: "No valid fields to update",
					body: {
						detail: "No valid fields to update",
						schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
						status: "400",
					},
				}),
			);
		});

		it("should ignore non-existing operation", async () => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "non-existing-operation",
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const patchUser = () =>
				auth.api.patchSCIMUser({
					params: { userId: user.id },
					body: {
						schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
						Operations: [
							{ op: "update", path: "userName", value: "Some Value" },
						],
					},
					headers: {
						authorization: `Bearer ${scimToken}`,
					},
				});

			await expect(patchUser()).rejects.toThrowError(
				expect.objectContaining({
					body: {
						code: "VALIDATION_ERROR",
						message:
							'[body.Operations.0.op] Invalid option: expected one of "replace"|"add"|"remove"',
					},
				}),
			);
		});

		it("should return not found for missing users", async () => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const patchUser = () =>
				auth.api.patchSCIMUser({
					params: {
						userId: "missing",
					},
					body: {
						schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
						Operations: [
							{
								op: "replace",
								path: "/externalId",
								value: "external-username",
							},
						],
					},
					headers: {
						authorization: `Bearer ${scimToken}`,
					},
				});

			await expect(patchUser()).rejects.toThrowError(
				expect.objectContaining({
					message: "User not found",
					body: {
						detail: "User not found",
						schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
						status: "404",
					},
				}),
			);
		});

		it("should fail on invalid updates", async () => {
			const { auth, getSCIMToken } = createTestInstance();
			const scimToken = await getSCIMToken();

			const user = await auth.api.createSCIMUser({
				body: {
					userName: "the-username",
				},
				headers: {
					authorization: `Bearer ${scimToken}`,
				},
			});

			const patchUser = () =>
				auth.api.patchSCIMUser({
					params: {
						userId: user.id,
					},
					body: {
						schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
						Operations: [],
					},
					headers: {
						authorization: `Bearer ${scimToken}`,
					},
				});

			await expect(patchUser()).rejects.toThrowError(
				expect.objectContaining({
					message: "No valid fields to update",
					body: {
						detail: "No valid fields to update",
						schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
						status: "400",
					},
				}),
			);
		});

		it("should not allow anonymous access", async () => {
			const { auth } = createTestInstance();

			const patchUser = async () => {
				await auth.api.patchSCIMUser({
					params: {
						userId: "missing",
					},
					body: {
						schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
						Operations: [
							{
								op: "replace",
								path: "/externalId",
								value: "external-username",
							},
						],
					},
				});
			};

			await expect(patchUser()).rejects.toThrowError(
				expect.objectContaining({
					message: "SCIM token is required",
					body: {
						detail: "SCIM token is required",
						schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
						status: "401",
					},
				}),
			);
		});
	});
});
