import {
	ClearanceError,
	MEMBER_OPERATIONS,
	ORGANIZATION_OPERATIONS,
	executeMemberImportPlan,
	inspectMembership,
	inspectOrganization,
	inspectUser,
	listMembers,
	listOrganizations,
	listOrganizationsPage,
	planMemberImport,
	type MemberImportFormat,
} from "@clearance/management";
import { Hono } from "hono";
import {
	apiOperationContext,
	type ApplicationRouteDependencies,
} from "./shared.js";

export interface OrganizationRouteDependencies extends ApplicationRouteDependencies {}

export function registerOrganizationRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
	applicationFor,
}: OrganizationRouteDependencies) {
	const routes = new Hono();

	/**
	 * List organizations. Legacy unpaginated without params; keyset-paginated
	 * (createdAt+id asc) with ?limit=/?cursor=, returning nextCursor.
	 */
	routes.get(ORGANIZATION_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const limitRaw = c.req.query("limit");
			const cursor = c.req.query("cursor");
			if (limitRaw !== undefined || cursor !== undefined) {
				const page = listOrganizationsPage(store, {
					scope,
					...(limitRaw !== undefined ? { limit: Number(limitRaw) } : {}),
					...(cursor !== undefined ? { cursor } : {}),
				});
				return c.json({
					organizations: page.organizations,
					nextCursor: page.nextCursor,
					scope,
				});
			}
			return c.json({
				organizations: listOrganizations(store, { scope }),
				scope,
			});
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(ORGANIZATION_OPERATIONS.inspect.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const organization = inspectOrganization(store, c.req.param("id"), scope);
			return c.json({ organization, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(ORGANIZATION_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json();
			const organization = await applicationFor(store).organizations.create(
				apiOperationContext(scope),
				{ name: body.name, slug: body.slug, ownerUserId: body.ownerUserId },
			);
			return c.json({ organization }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.patch(ORGANIZATION_OPERATIONS.update.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body == null || typeof body !== "object") {
				throw new ClearanceError({
					code: "ORG_UPDATE_EMPTY",
					message: "At least one of name or slug is required",
					stage: "orgs.update",
					status: 400,
				});
			}
			const unknownFields = Object.keys(body).filter(
				(key) => key !== "name" && key !== "slug" && key !== "status" && key !== "dryRun",
			);
			if (unknownFields.length > 0) {
				throw new ClearanceError({
					code: "ORG_UPDATE_FIELD_INVALID",
					message: `Unsupported organization update field: ${unknownFields[0]}`,
					stage: "orgs.update",
					status: 400,
					remediation: "Only name and slug are mutable; use the archive endpoint for status",
				});
			}
			// Reject non-mutable fields explicitly (status goes through archive)
			if ("status" in body) {
				throw new ClearanceError({
					code: "ORG_STATUS_IMMUTABLE",
					message: "Organization status cannot be set via update; use archive",
					stage: "orgs.update",
					status: 400,
					remediation: "POST /v1/organizations/:id/archive with confirm=true",
				});
			}
			const name = "name" in body ? body.name : undefined;
			const slug = "slug" in body ? body.slug : undefined;
			if (name !== undefined && typeof name !== "string") {
				throw new ClearanceError({
					code: "ORG_NAME_REQUIRED",
					message: "Name must be a string",
					stage: "orgs.update",
					status: 400,
				});
			}
			if (slug !== undefined && typeof slug !== "string") {
				throw new ClearanceError({
					code: "ORG_SLUG_INVALID",
					message: "Slug must be a string",
					stage: "orgs.update",
					status: 400,
				});
			}
			if (body.dryRun === true) {
				inspectOrganization(store, c.req.param("id"), scope);
				return c.json({ dryRun: true, id: c.req.param("id"), name, slug, scope });
			}
			const organization = await applicationFor(store).organizations.update(
				apiOperationContext(scope),
				c.req.param("id"),
				{
					...(name !== undefined ? { name } : {}),
					...(slug !== undefined ? { slug } : {}),
				},
			);
			return c.json({ organization, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	/**
	 * Archive organization. Defaults to dry-run unless confirm=true.
	 * Body: { dryRun?: boolean, confirm?: boolean }
	 * When DATABASE_URL is set, uses coordinated runtime+management archive.
	 */
	routes.post(ORGANIZATION_OPERATIONS.archive.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			const dryRun =
				body && typeof body === "object" && "dryRun" in body
					? (body as { dryRun?: unknown }).dryRun
					: undefined;
			const confirm =
				body && typeof body === "object" && "confirm" in body
					? (body as { confirm?: unknown }).confirm
					: undefined;
			if (dryRun !== undefined && typeof dryRun !== "boolean") {
				throw new ClearanceError({
					code: "ORG_ARCHIVE_INPUT_INVALID",
					message: "dryRun must be a JSON boolean",
					stage: "orgs.archive",
					status: 400,
				});
			}
			if (confirm !== undefined && typeof confirm !== "boolean") {
				throw new ClearanceError({
					code: "ORG_ARCHIVE_INPUT_INVALID",
					message: "confirm must be a JSON boolean",
					stage: "orgs.archive",
					status: 400,
				});
			}
			const result = await applicationFor(store).organizations.archive(
				apiOperationContext(scope),
				c.req.param("id"),
				{
					...(dryRun !== undefined ? { dryRun } : {}),
					...(confirm !== undefined ? { confirm } : {}),
				},
			);
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(MEMBER_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const members = listMembers(store, c.req.param("id"), { scope });
			return c.json({ members, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(MEMBER_OPERATIONS.add.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (
				body == null ||
				typeof body !== "object" ||
				typeof body.principalId !== "string" ||
				!body.principalId.trim()
			) {
				throw new ClearanceError({
					code: "MEMBER_PRINCIPAL_REQUIRED",
					message: "principalId is required",
					stage: "orgs.members.add",
					status: 400,
					remediation: "Pass principalId in the request body",
				});
			}
			const principalId = body.principalId.trim();
			const role = body.role !== undefined ? body.role : "member";
			if (body.dryRun === true) {
				inspectOrganization(store, c.req.param("id"), scope);
				inspectUser(store, principalId, scope);
				return c.json({ dryRun: true, organizationId: c.req.param("id"), principalId, role, scope });
			}
			const membership = await applicationFor(store).members.add(
				apiOperationContext(scope),
				{
					organizationId: c.req.param("id"),
					principalId,
					role,
					auditSource: "api",
				},
			);
			return c.json({ membership, scope }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(MEMBER_OPERATIONS.import.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			const format = body.format as MemberImportFormat | undefined;
			if (format !== "json" && format !== "csv") {
				throw new ClearanceError({
					code: "MEMBER_IMPORT_FORMAT_REQUIRED",
					message: "Member import format must be json or csv",
					stage: "orgs.members.import",
					status: 400,
					remediation: "Send format as json or csv.",
				});
			}
			if (typeof body.content !== "string") {
				throw new ClearanceError({
					code: "MEMBER_IMPORT_CONTENT_REQUIRED",
					message: "Member import content is required",
					stage: "orgs.members.import",
					status: 400,
					remediation: "Send the local file contents in the authenticated request.",
				});
			}
			const plan = planMemberImport(store, {
				organizationId: c.req.param("id"),
				content: body.content,
				format,
			});
			if (body.dryRun === true || body.confirm !== true) {
				return c.json({ dryRun: true, ...plan, scope });
			}
			const result = await executeMemberImportPlan(plan, async (row) => {
				return applicationFor(store).members.add(
					apiOperationContext(scope),
					{
						organizationId: plan.organizationId,
						principalId: row.principalId,
						role: row.role,
						source: "import",
						auditSource: "import",
					},
				);
			});
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.patch(MEMBER_OPERATIONS.update.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const orgId = c.req.param("id");
			const memberId = c.req.param("memberId");
			// Ensure org is in scope (cross-scope ids indistinguishable from missing)
			inspectOrganization(store, orgId, scope);
			const existing = inspectMembership(store, memberId, scope);
			if (existing.organizationId !== orgId) {
				// Treat as missing — do not leak cross-org membership existence
				throw new ClearanceError({
					code: "MEMBER_NOT_FOUND",
					message: "Membership not found",
					stage: "orgs.members.update",
					status: 404,
				});
			}
			const body = await c.req.json().catch(() => ({}));
			if (body == null || typeof body !== "object" || body.role === undefined) {
				throw new ClearanceError({
					code: "ROLE_REQUIRED",
					message: "Role is required",
					stage: "orgs.members.update",
					status: 400,
				});
			}
			if (body.dryRun === true) {
				return c.json({ dryRun: true, organizationId: orgId, membershipId: memberId, role: body.role, scope });
			}
			const membership = await applicationFor(store).members.update(
				apiOperationContext(scope),
				memberId,
				{ role: body.role, auditSource: "api" },
			);
			return c.json({ membership, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.delete(MEMBER_OPERATIONS.remove.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const orgId = c.req.param("id");
			const memberId = c.req.param("memberId");
			inspectOrganization(store, orgId, scope);
			const existing = inspectMembership(store, memberId, scope);
			if (existing.organizationId !== orgId) {
				throw new ClearanceError({
					code: "MEMBER_NOT_FOUND",
					message: "Membership not found",
					stage: "orgs.members.remove",
					status: 404,
				});
			}
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				return c.json({ dryRun: true, organizationId: orgId, membershipId: memberId, membership: existing, scope });
			}
			const membership = await applicationFor(store).members.remove(
				apiOperationContext(scope),
				memberId,
				{ auditSource: "api" },
			);
			return c.json({ membership, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	return routes;
}
