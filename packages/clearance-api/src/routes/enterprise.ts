import {
	ClearanceError,
	READINESS_OPERATIONS,
	SCIM_OPERATIONS,
	SSO_OPERATIONS,
	configureSsoConnectionAuthoritative,
	createScimConnectionAuthoritative,
	createScimConnectionReal,
	createSetupLinkAuthoritative,
	createSsoConnectionAuthoritative,
	createSsoConnectionReal,
	disableScimConnectionAuthoritative,
	disableScimConnectionReal,
	disableSsoConnectionAuthoritative,
	disableSsoConnectionReal,
	getLatestReadiness,
	inspectOrganizationAuthoritative,
	inspectScimConnectionAuthoritative,
	inspectSsoConnectionAuthoritative,
	listOrganizationsPageAuthoritative,
	listScimConnections,
	listSsoConnections,
	replayDiagnosticTraceOperational,
	rotateScimCredentialAuthoritative,
	rotateSsoCredentialAuthoritative,
	runReadinessCheckAuthoritative,
	testScimConnectionAuthoritative,
	testScimConnectionLive,
	testScimConnectionReal,
	testSsoConnectionAuthoritative,
	testSsoConnectionLive,
	testSsoConnectionReal,
} from "@clearance/management";
import { randomBytes } from "node:crypto";
import { Hono } from "hono";
import { requestActor } from "../request-auth.js";
import {
	apiOperationContext,
	type ScopedRouteDependencies,
} from "./shared.js";

export interface EnterpriseRouteDependencies extends ScopedRouteDependencies {
	runtimeDatabaseConfigured(): boolean;
}

const ENTERPRISE_SCOPE_ORG_PAGE_SIZE = 1000;
const ENTERPRISE_SCOPE_ORG_MAXIMUM = 50_000;

async function scopedOrganizationIds(store: Parameters<typeof listOrganizationsPageAuthoritative>[0], scope: Parameters<typeof listOrganizationsPageAuthoritative>[1]["scope"]): Promise<Set<string>> {
	const ids = new Set<string>();
	let cursor: string | undefined;
	do {
		const page = await listOrganizationsPageAuthoritative(store, {
			scope,
			limit: ENTERPRISE_SCOPE_ORG_PAGE_SIZE,
			...(cursor ? { cursor } : {}),
		});
		for (const organization of page.organizations) ids.add(organization.id);
		cursor = page.nextCursor ?? undefined;
		if (cursor && ids.size >= ENTERPRISE_SCOPE_ORG_MAXIMUM) {
			throw new ClearanceError({ code: "ORG_LIST_LIMIT_EXCEEDED", message: "Organization scope exceeds the enterprise list limit", stage: "enterprise.list", status: 400 });
		}
	} while (cursor);
	return ids;
}

export function registerEnterpriseRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
	runtimeDatabaseConfigured,
}: EnterpriseRouteDependencies) {
	const routes = new Hono();

	// --- Enterprise routes (scope enforced on org ownership inside services) ---

	routes.get(SSO_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const scopedOrgIds = await scopedOrganizationIds(store, scope);
			const connections = listSsoConnections(store, c.req.query("organizationId")).filter((connection) => scopedOrgIds.has(connection.organizationId));
			return c.json({ connections, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SSO_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json();
			const input = {
				...body,
				protocol: body.protocol ?? "oidc",
				domains: body.domains ?? (body.domain ? [body.domain] : undefined),
				actor: requestActor(c),
				source: "api" as const,
				scope,
			};
			// Fail closed if organizationId is outside principal scope
			await inspectOrganizationAuthoritative(store, input.organizationId, scope);
			const connection = runtimeDatabaseConfigured()
				? await createSsoConnectionReal(store, input)
				: await createSsoConnectionAuthoritative(store, input);
			await store.ready();
			return c.json({ connection }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.patch(SSO_OPERATIONS.configure.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const request = await c.req.json().catch(() => ({}));
			if (request.dryRun === true) {
				const current = await inspectSsoConnectionAuthoritative(store, c.req.param("id"), { scope });
				return c.json({
					dryRun: true,
					connection: current,
					proposed: {
						issuer: request.issuer ?? current.issuer,
						audience: request.audience ?? current.audience,
						domains: request.domain ? [request.domain] : request.domains ?? current.domains,
					},
					scope,
				});
			}
			const connection = await configureSsoConnectionAuthoritative(store, c.req.param("id"), {
				issuer: request.issuer,
				audience: request.audience,
				domains: request.domain ? [request.domain] : request.domains,
			}, apiOperationContext(scope, c));
			await store.ready();
			return c.json({ connection, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SSO_OPERATIONS.setupLink.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const request = await c.req.json();
			const link = await createSetupLinkAuthoritative(store, {
				organizationId: request.organizationId,
				kind: "sso",
				actor: requestActor(c),
				scope,
			});
			await store.ready();
			return c.json({ ...link, scope }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SSO_OPERATIONS.test.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const conn = store.snapshot.identityConnections.find(
				(x) => x.id === c.req.param("id"),
			);
			if (!conn) {
				return c.json(
					{ error: { code: "SSO_NOT_FOUND", message: "SSO connection not found", stage: "sso.test" } },
					404,
				);
			}
			await inspectOrganizationAuthoritative(store, conn.organizationId, scope);
			const body = await c.req.json().catch(() => ({}));
			const testInput = {
				...body,
				actor: requestActor(c),
				source: "api" as const,
				scope,
			};
			const result = body.live === true
				? await testSsoConnectionLive(store, c.req.param("id"), { scope })
				: runtimeDatabaseConfigured()
					? await testSsoConnectionReal(store, c.req.param("id"), testInput)
					: await testSsoConnectionAuthoritative(store, c.req.param("id"), testInput);
			await store.ready();
			return c.json(result);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SSO_OPERATIONS.rotate.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			// Validate scope before mutation (fail closed for missing/cross-scope).
			const current = await inspectSsoConnectionAuthoritative(store, c.req.param("id"), { scope });
			if (body.dryRun === true) {
				if (!(current as { hasClientSecret?: boolean }).hasClientSecret && !current.clientSecretFingerprint) {
					throw new ClearanceError({ code: "SSO_NO_SECRET", message: "No encrypted client secret to rotate", stage: "sso.rotate", status: 400 });
				}
				return c.json({ dryRun: true, connection: current, wouldChange: true, scope });
			}
			const connection = await rotateSsoCredentialAuthoritative(store, c.req.param("id"), {
				actor: requestActor(c),
				source: "api",
				scope,
			});
			await store.ready();
			return c.json({ connection, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SSO_OPERATIONS.disable.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				const connection = await inspectSsoConnectionAuthoritative(store, c.req.param("id"), { scope });
				return c.json({ dryRun: true, connection, wouldChange: connection.status !== "disabled", scope });
			}
			const result = runtimeDatabaseConfigured()
				? await disableSsoConnectionReal(store, c.req.param("id"), {
						actor: requestActor(c),
						source: "api",
						scope,
					})
				: await disableSsoConnectionAuthoritative(store, c.req.param("id"), {
						actor: requestActor(c),
						source: "api",
						scope,
					});
			await store.ready();
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SCIM_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json();
			await inspectOrganizationAuthoritative(store, body.organizationId, scope);
			const developmentBearerToken = runtimeDatabaseConfigured()
				? undefined
				: `scimtok_${randomBytes(24).toString("base64url")}`;
			const input = {
				...body,
				actor: requestActor(c),
				source: "api" as const,
				scope,
			};
			const connection = runtimeDatabaseConfigured()
				? await createScimConnectionReal(store, input)
				: {
						...(await createScimConnectionAuthoritative(store, { ...input, bearerToken: developmentBearerToken })),
						bearerTokenOnce: developmentBearerToken,
					};
			await store.ready();
			return c.json({ connection }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(SCIM_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const scopedOrgIds = await scopedOrganizationIds(store, scope);
			const connections = listScimConnections(store, c.req.query("organizationId")).filter((connection) => scopedOrgIds.has(connection.organizationId));
			return c.json({ connections, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SCIM_OPERATIONS.setupLink.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const request = await c.req.json();
			const link = await createSetupLinkAuthoritative(store, {
				organizationId: request.organizationId,
				kind: "scim",
				actor: requestActor(c),
				scope,
			});
			await store.ready();
			return c.json({ ...link, scope }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SCIM_OPERATIONS.test.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const conn = store.snapshot.directoryConnections.find(
				(x) => x.id === c.req.param("id"),
			);
			if (!conn) {
				return c.json(
					{
						error: {
							code: "SCIM_NOT_FOUND",
							message: "SCIM connection not found",
							stage: "scim.test",
						},
					},
					404,
				);
			}
			await inspectOrganizationAuthoritative(store, conn.organizationId, scope);
			const body = await c.req.json().catch(() => ({}));
			const scenario = body.scenario ?? "users";
			if (scenario !== "users" && scenario !== "group-lifecycle") {
				return c.json(
					{
						error: {
							code: "SCIM_SCENARIO_INVALID",
							message: "SCIM scenario must be users or group-lifecycle",
							stage: "scim.test",
						},
					},
					400,
				);
			}
			if (scenario === "group-lifecycle" && body.live === true) {
				return c.json({ error: { code: "SCIM_SCENARIO_LIVE_CONFLICT", message: "group-lifecycle runs only against the bundled runtime", stage: "scim.test" } }, 400);
			}
			if (scenario === "group-lifecycle" && !runtimeDatabaseConfigured()) {
				return c.json({ error: { code: "SCIM_ATOMIC_APPLY_BACKEND_REQUIRED", message: "group-lifecycle requires the bundled PostgreSQL runtime", stage: "sync.apply" } }, 409);
			}
			const users = body.users;
			if (scenario === "group-lifecycle" && users !== undefined) {
				return c.json({ error: { code: "SCIM_SCENARIO_USERS_FORBIDDEN", message: "group-lifecycle owns its SCIM users", stage: "scim.test" } }, 400);
			}
			if (scenario === "users" && users !== undefined && (!Array.isArray(users) || users.some((user) => !user || typeof user !== "object" || typeof user.userName !== "string" || (user.displayName !== undefined && typeof user.displayName !== "string") || (user.active !== undefined && typeof user.active !== "boolean")))) {
				return c.json({ error: { code: "SCIM_USERS_INVALID", message: "SCIM users must contain userName with optional displayName and active", stage: "scim.test" } }, 400);
			}
			const testInput = {
				dryRun: body.dryRun === true,
				fixture: body.fixture,
				scenario,
				...(scenario === "users" ? { users } : {}),
				actor: requestActor(c),
				source: "api" as const,
				scope,
			};
			const result = body.live === true
				? await testScimConnectionLive(store, c.req.param("id"), { scope })
				: runtimeDatabaseConfigured()
					? await testScimConnectionReal(store, c.req.param("id"), testInput)
					: await testScimConnectionAuthoritative(store, c.req.param("id"), testInput);
			await store.ready();
			return c.json(result);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SCIM_OPERATIONS.rotate.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			const current = await inspectScimConnectionAuthoritative(store, c.req.param("id"), { scope });
			if (body.dryRun === true) {
				if (!(current as { hasBearerToken?: boolean }).hasBearerToken && !current.bearerTokenFingerprint) {
					throw new ClearanceError({ code: "SCIM_NO_TOKEN", message: "No encrypted bearer token to rotate", stage: "scim.rotate", status: 400 });
				}
				return c.json({ dryRun: true, connection: current, wouldChange: true, scope });
			}
			const connection = await rotateScimCredentialAuthoritative(store, c.req.param("id"), {
				actor: requestActor(c),
				source: "api",
				scope,
			});
			await store.ready();
			return c.json({ connection, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SCIM_OPERATIONS.disable.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				const connection = await inspectScimConnectionAuthoritative(store, c.req.param("id"), { scope });
				return c.json({ dryRun: true, connection, wouldChange: connection.status !== "disabled", scope });
			}
			const result = runtimeDatabaseConfigured()
				? await disableScimConnectionReal(store, c.req.param("id"), {
						actor: requestActor(c),
						source: "api",
						scope,
					})
				: await disableScimConnectionAuthoritative(store, c.req.param("id"), {
						actor: requestActor(c),
						source: "api",
						scope,
					});
			await store.ready();
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SCIM_OPERATIONS.replay.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			const dryRun = body.dryRun === true || body.confirm !== true;
			const result = await replayDiagnosticTraceOperational(store, c.req.param("traceId"), {
				dryRun,
				confirm: body.confirm === true && !dryRun,
				actor: requestActor(c),
				source: "api",
				scope,
			});
			if (!result.dryRun) await store.ready();
			return c.json(result);
		} catch (e) {
			return handleError(c, e);
		}
	});

	// --- Readiness routes (scope enforced) ---

	routes.post(READINESS_OPERATIONS.check.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json();
			const report = await runReadinessCheckAuthoritative(store, body.organizationId, scope);
			await store.ready();
			return c.json({ report });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(READINESS_OPERATIONS.report.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			await inspectOrganizationAuthoritative(store, c.req.param("orgId"), scope);
			const report = getLatestReadiness(store, c.req.param("orgId"));
			return c.json({ report });
		} catch (e) {
			return handleError(c, e);
		}
	});

	return routes;
}
