import {
	ClearanceError,
	READINESS_OPERATIONS,
	SCIM_OPERATIONS,
	SSO_OPERATIONS,
	configureSsoConnection,
	createScimConnection,
	createScimConnectionReal,
	createSetupLink,
	createSsoConnection,
	createSsoConnectionReal,
	disableScimConnection,
	disableScimConnectionReal,
	disableSsoConnection,
	disableSsoConnectionReal,
	getLatestReadiness,
	inspectOrganization,
	inspectScimConnection,
	inspectSsoConnection,
	listOrganizations,
	listScimConnections,
	listSsoConnections,
	replayDiagnosticTrace,
	rotateScimCredential,
	rotateSsoCredential,
	runReadinessCheck,
	testScimConnection,
	testScimConnectionLive,
	testScimConnectionReal,
	testSsoConnection,
	testSsoConnectionLive,
	testSsoConnectionReal,
} from "@clearance/management";
import { randomBytes } from "node:crypto";
import { Hono } from "hono";
import {
	apiOperationContext,
	type ScopedRouteDependencies,
} from "./shared.js";

export interface EnterpriseRouteDependencies extends ScopedRouteDependencies {
	runtimeDatabaseConfigured(): boolean;
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
			const scopedOrgIds = new Set(listOrganizations(store, { scope }).map((org) => org.id));
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
			};
			// Fail closed if organizationId is outside principal scope
			inspectOrganization(store, input.organizationId, scope);
			const connection = runtimeDatabaseConfigured()
				? await createSsoConnectionReal(store, input)
				: createSsoConnection(store, input);
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
				const current = inspectSsoConnection(store, c.req.param("id"), { scope });
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
			const connection = configureSsoConnection(store, c.req.param("id"), {
				issuer: request.issuer,
				audience: request.audience,
				domains: request.domain ? [request.domain] : request.domains,
			}, apiOperationContext(scope));
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
			inspectOrganization(store, request.organizationId, scope);
			const link = createSetupLink(store, { organizationId: request.organizationId, kind: "sso", actor: "api" });
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
			inspectOrganization(store, conn.organizationId, scope);
			const body = await c.req.json().catch(() => ({}));
			const result = body.live === true
				? await testSsoConnectionLive(store, c.req.param("id"))
				: runtimeDatabaseConfigured()
					? await testSsoConnectionReal(store, c.req.param("id"), body)
					: testSsoConnection(store, c.req.param("id"), body);
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
			const current = inspectSsoConnection(store, c.req.param("id"), { scope });
			if (body.dryRun === true) {
				if (!(current as { hasClientSecret?: boolean }).hasClientSecret && !current.clientSecretFingerprint) {
					throw new ClearanceError({ code: "SSO_NO_SECRET", message: "No encrypted client secret to rotate", stage: "sso.rotate", status: 400 });
				}
				return c.json({ dryRun: true, connection: current, wouldChange: true, scope });
			}
			const connection = rotateSsoCredential(store, c.req.param("id"), {
				actor: "api",
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
				const connection = inspectSsoConnection(store, c.req.param("id"), { scope });
				return c.json({ dryRun: true, connection, wouldChange: connection.status !== "disabled", scope });
			}
			const result = runtimeDatabaseConfigured()
				? await disableSsoConnectionReal(store, c.req.param("id"), {
						actor: "api",
						source: "api",
						scope,
					})
				: disableSsoConnection(store, c.req.param("id"), {
						actor: "api",
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
			inspectOrganization(store, body.organizationId, scope);
			const developmentBearerToken = runtimeDatabaseConfigured()
				? undefined
				: `scimtok_${randomBytes(24).toString("base64url")}`;
			const connection = runtimeDatabaseConfigured()
				? await createScimConnectionReal(store, body)
				: {
						...createScimConnection(store, { ...body, bearerToken: developmentBearerToken }),
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
			const scopedOrgIds = new Set(listOrganizations(store, { scope }).map((org) => org.id));
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
			inspectOrganization(store, request.organizationId, scope);
			const link = createSetupLink(store, { organizationId: request.organizationId, kind: "scim", actor: "api" });
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
			inspectOrganization(store, conn.organizationId, scope);
			const body = await c.req.json().catch(() => ({}));
			const result = body.live === true
				? await testScimConnectionLive(store, c.req.param("id"))
				: runtimeDatabaseConfigured()
					? await testScimConnectionReal(store, c.req.param("id"), body)
					: testScimConnection(store, c.req.param("id"), body);
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
			const current = inspectScimConnection(store, c.req.param("id"), { scope });
			if (body.dryRun === true) {
				if (!(current as { hasBearerToken?: boolean }).hasBearerToken && !current.bearerTokenFingerprint) {
					throw new ClearanceError({ code: "SCIM_NO_TOKEN", message: "No encrypted bearer token to rotate", stage: "scim.rotate", status: 400 });
				}
				return c.json({ dryRun: true, connection: current, wouldChange: true, scope });
			}
			const connection = rotateScimCredential(store, c.req.param("id"), {
				actor: "api",
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
				const connection = inspectScimConnection(store, c.req.param("id"), { scope });
				return c.json({ dryRun: true, connection, wouldChange: connection.status !== "disabled", scope });
			}
			const result = runtimeDatabaseConfigured()
				? await disableScimConnectionReal(store, c.req.param("id"), {
						actor: "api",
						source: "api",
						scope,
					})
				: disableScimConnection(store, c.req.param("id"), {
						actor: "api",
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
			const result = replayDiagnosticTrace(store, c.req.param("traceId"), {
				dryRun,
				confirm: body.confirm === true && !dryRun,
				actor: "api",
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
			inspectOrganization(store, body.organizationId, scope);
			const report = runReadinessCheck(store, body.organizationId);
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
			inspectOrganization(store, c.req.param("orgId"), scope);
			const report = getLatestReadiness(store, c.req.param("orgId"));
			return c.json({ report });
		} catch (e) {
			return handleError(c, e);
		}
	});

	return routes;
}
