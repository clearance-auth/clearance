import {
	API_KEY_OPERATIONS,
	AUTHORIZATION_OPERATIONS,
	ClearanceError,
	ROLE_OPERATIONS,
	SERVICE_ACCOUNT_OPERATIONS,
	SESSION_OPERATIONS,
	createApiKey,
	createRoleInAuth,
	createRole,
	createServiceAccountCredentialInAuth,
	createServiceAccountInAuth,
	inspectEffectiveAuthorizationInAuth,
	inspectApiKey,
	inspectServiceAccountInAuth,
	listAuthorizationAssignmentsInAuth,
	listApiKeys,
	listRolesFromAuth,
	listRoles,
	listServiceAccountsInAuth,
	normalizeAndValidateApiKeyScopes,
	publicConfig,
	reconcileAuthorizationOrganizationInAuth,
	replaceAuthorizationAssignmentsInAuth,
	revokeApiKey,
	revokeServiceAccountCredentialInAuth,
	rotateApiKey,
	rotateServiceAccountCredentialInAuth,
	setServiceAccountStatusInAuth,
	updateRoleInAuth,
	updateRole,
	validateApiKeyName,
	validateRole,
} from "@clearance/management";
import { Hono } from "hono";
import { requestActor } from "../request-auth.js";
import {
	apiOperationContext,
	type ApplicationRouteDependencies,
} from "./shared.js";

export type AccessRouteDependencies = ApplicationRouteDependencies;

/** Normalized authorization has one PostgreSQL authority. */
function requireAuthorizationPostgres(store: { backend: string }): void {
	if (store.backend === "postgres") return;
	throw new ClearanceError({
		code: "AUTHORIZATION_POSTGRES_REQUIRED",
		message: "Normalized authorization workflows require the PostgreSQL authority",
		stage: "authorization.api",
		status: 400,
	});
}

function authorizationSubjectFilter(
	subjectKind: string | undefined,
	subjectId: string | undefined,
): { kind: "principal" | "service_account"; id: string } | undefined {
	if (subjectKind === undefined && subjectId === undefined) return undefined;
	if (subjectKind === undefined || subjectId === undefined) {
		throw new ClearanceError({
			code: "AUTHORIZATION_SUBJECT_FILTER_INVALID",
			message: "subjectKind and subjectId must be provided together",
			stage: "authorization.assignments.list",
			status: 400,
		});
	}
	if (subjectKind !== "principal" && subjectKind !== "service_account") {
		throw new ClearanceError({
			code: "AUTHORIZATION_SUBJECT_INVALID",
			message: "subject kind is invalid",
			stage: "authorization.assignments.list",
			status: 400,
		});
	}
	return { kind: subjectKind, id: subjectId };
}

function authorizationOperationResult(result: Record<string, unknown>, scope: unknown) {
	const { preview, ...output } = result;
	return preview === true ? { dryRun: true, ...output, scope } : { ...output, scope };
}

function authorizationRequestBody(
	value: unknown,
	stage: string,
	allowedFields: readonly string[],
): Record<string, unknown> {
	if (value === null || typeof value !== "object" || Array.isArray(value)) {
		throw new ClearanceError({
			code: "AUTHORIZATION_INPUT_INVALID",
			message: "Request body must be a JSON object",
			stage,
			status: 400,
		});
	}
	const body = value as Record<string, unknown>;
	const unsupported = Object.keys(body).find((key) => !allowedFields.includes(key));
	if (unsupported) {
		throw new ClearanceError({
			code: "AUTHORIZATION_INPUT_INVALID",
			message: `Unsupported field: ${unsupported}`,
			stage,
			status: 400,
		});
	}
	return body;
}

async function readAuthorizationRequestBody(
	json: Promise<unknown>,
	stage: string,
	allowedFields: readonly string[],
): Promise<Record<string, unknown>> {
	let value: unknown;
	try {
		value = await json;
	} catch {
		throw new ClearanceError({
			code: "AUTHORIZATION_INPUT_INVALID",
			message: "Request body must be valid JSON",
			stage,
			status: 400,
		});
	}
	return authorizationRequestBody(value, stage, allowedFields);
}

function optionalAuthorizationBoolean(
	body: Record<string, unknown>,
	field: string,
	stage: string,
): boolean | undefined {
	const value = body[field];
	if (value === undefined) return undefined;
	if (typeof value === "boolean") return value;
	throw new ClearanceError({
		code: "AUTHORIZATION_INPUT_INVALID",
		message: `${field} must be a JSON boolean`,
		stage,
		status: 400,
	});
}

function optionalAuthorizationString(
	body: Record<string, unknown>,
	field: string,
	stage: string,
): string | undefined {
	const value = body[field];
	if (value === undefined) return undefined;
	if (typeof value === "string") return value;
	throw new ClearanceError({
		code: "AUTHORIZATION_INPUT_INVALID",
		message: `${field} must be a string`,
		stage,
		status: 400,
	});
}

const OPERATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Credential replay authority accepts a caller-chosen UUID only for live mutations. */
function credentialOperationId(
	body: Record<string, unknown>,
	dryRun: true,
	stage: string,
): undefined;
function credentialOperationId(
	body: Record<string, unknown>,
	dryRun: false | undefined,
	stage: string,
): string;
function credentialOperationId(
	body: Record<string, unknown>,
	dryRun: boolean | undefined,
	stage: string,
): string | undefined {
	const value = body.operationId;
	if (dryRun === true) {
		if (value === undefined) return undefined;
		throw new ClearanceError({
			code: "AUTHORIZATION_INPUT_INVALID",
			message: "operationId must be omitted for a dry run",
			stage,
			status: 400,
		});
	}
	if (typeof value !== "string" || !OPERATION_ID.test(value)) {
		throw new ClearanceError({
			code: "TENANT_OPERATION_ID_REQUIRED",
			message: "A UUID operationId is required",
			stage,
			status: 400,
		});
	}
	return value;
}

type CredentialMutationOperation =
	| Readonly<{ dryRun: true; operationId?: never }>
	| Readonly<{ dryRun?: false; operationId: string }>;

export function credentialMutationOperation(
	body: Record<string, unknown>,
	dryRun: boolean | undefined,
	stage: string,
): CredentialMutationOperation {
	if (dryRun === true) {
		credentialOperationId(body, dryRun, stage);
		return { dryRun: true };
	}
	return { operationId: credentialOperationId(body, dryRun, stage) };
}

export function registerAccessRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
	applicationFor,
}: AccessRouteDependencies) {
	const routes = new Hono();

	// --- API keys ---

	routes.get(API_KEY_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json({ apiKeys: listApiKeys(store, { scope, includeRevoked: c.req.query("includeRevoked") === "true" }), scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(API_KEY_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json();
			let expiresAt: string | undefined;
			if (body.expiresAt !== undefined) {
				if (
					typeof body.expiresAt !== "string" ||
					!Number.isFinite(Date.parse(body.expiresAt))
				) {
					throw new ClearanceError({
						code: "API_KEY_EXPIRY_INVALID",
						message: "API key expiry must be an ISO-8601 timestamp",
						stage: "keys.create",
						status: 400,
					});
				}
				expiresAt = new Date(body.expiresAt).toISOString();
				if (Date.parse(expiresAt) <= Date.now()) {
					throw new ClearanceError({
						code: "API_KEY_EXPIRY_INVALID",
						message: "API key expiry must be in the future",
						stage: "keys.create",
						status: 400,
					});
				}
			}
			if (body.dryRun === true) {
				const name = validateApiKeyName(body.name, "keys.create");
				const scopes = normalizeAndValidateApiKeyScopes(body.scopes, "keys.create");
				return c.json({ dryRun: true, apiKey: { name, scopes, ...(expiresAt ? { expiresAt } : {}) }, secretGenerated: false, scope });
			}
			const createInput: Parameters<typeof createApiKey>[1] & { expiresAt?: string } = {
				name: body.name,
				scopes: body.scopes,
				...(expiresAt ? { expiresAt } : {}),
				scope,
				actor: requestActor(c),
				source: "api",
			};
			const result = await createApiKey(store, createInput);
			await store.ready();
			return c.json({ ...result, scope }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(API_KEY_OPERATIONS.rotate.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				const apiKey = inspectApiKey(store, c.req.param("id"), { scope });
				if (apiKey.status === "revoked") throw new ClearanceError({ code: "API_KEY_REVOKED", message: "Revoked API keys cannot be rotated", stage: "keys.rotate", status: 409 });
				if (apiKey.expiresAt && Date.parse(apiKey.expiresAt) <= Date.now()) throw new ClearanceError({ code: "API_KEY_EXPIRED", message: "Expired API keys cannot be rotated", stage: "keys.rotate", status: 409 });
				return c.json({ dryRun: true, apiKey, secretGenerated: false, scope });
			}
			const result = await rotateApiKey(store, c.req.param("id"), apiOperationContext(scope, c));
			await store.ready();
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(API_KEY_OPERATIONS.revoke.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				const apiKey = inspectApiKey(store, c.req.param("id"), { scope });
				return c.json({ dryRun: true, apiKey, wouldChange: apiKey.status === "active", scope });
			}
			const result = await revokeApiKey(store, c.req.param("id"), apiOperationContext(scope, c));
			await store.ready();
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	// --- Sessions (principal-derived scope; never expose tokens) ---

	/**
	 * List sessions, keyset-paginated (createdAt+id desc, newest first). limit
	 * keeps the shipped SESSION_LIMIT_INVALID validation as the page size;
	 * nextCursor walks older sessions. Runtime and JSON paths share the same
	 * documented ordering and opaque cursor format.
	 */
	routes.get(SESSION_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const limitRaw = c.req.query("limit");
			const cursor = c.req.query("cursor");
			const limit = Number(limitRaw ?? 100);
			const page = await applicationFor(store).sessions.list(
				apiOperationContext(scope, c),
				{ limit, ...(cursor !== undefined ? { cursor } : {}) },
			);
			return c.json({
				sessions: page.sessions,
				nextCursor: page.nextCursor,
				scope,
			});
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SESSION_OPERATIONS.revoke.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				const session = await applicationFor(store).sessions.inspect(
					apiOperationContext(scope, c),
					c.req.param("id"),
				);
				return c.json({ dryRun: true, session, wouldChange: session.status === "active", scope });
			}
			const result = await applicationFor(store).sessions.revoke(
				apiOperationContext(scope, c),
				c.req.param("id"),
			);
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	// --- Roles (principal-derived scope; client headers never authority) ---

	routes.get(ROLE_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const roles = store.backend === "postgres"
				? await listRolesFromAuth(store, { scope })
				: listRoles(store, { scope });
			return c.json({ roles, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(ROLE_OPERATIONS.validate.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			const result = validateRole(store, {
				name: (body as { name?: unknown }).name,
				slug: (body as { slug?: unknown }).slug,
				permissions: (body as { permissions?: unknown }).permissions,
				scope,
			});
			return c.json(result);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(ROLE_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json();
			if (body.dryRun === true) {
				return c.json({ dryRun: true, validation: validateRole(store, { name: body.name, slug: body.slug, permissions: body.permissions, scope }), scope });
			}
			const input = {
				name: body.name,
				slug: body.slug,
				description: body.description,
				permissions: body.permissions,
				scope,
				actor: requestActor(c),
				source: "api" as const,
			};
			const role = store.backend === "postgres"
				? await createRoleInAuth(store, input)
				: await createRole(store, input);
			await store.ready();
			return c.json({ role, scope }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.patch(ROLE_OPERATIONS.update.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				return c.json({ dryRun: true, id: c.req.param("id"), validation: validateRole(store, { name: body.name, permissions: body.permissions, scope }), scope });
			}
			const input = {
				name: body.name,
				description: body.description,
				permissions: body.permissions,
				scope,
				actor: requestActor(c),
				source: "api" as const,
			};
			const role = store.backend === "postgres"
				? await updateRoleInAuth(store, c.req.param("id"), input)
				: await updateRole(store, c.req.param("id"), input);
			await store.ready();
			return c.json({ role, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	// --- Normalized authorization (PostgreSQL authority only) ---

	routes.get(AUTHORIZATION_OPERATIONS.effectiveInspect.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const effective = await inspectEffectiveAuthorizationInAuth(store, {
				organizationId: c.req.param("id"),
				subject: { kind: c.req.param("subjectKind") as "principal" | "service_account", id: c.req.param("subjectId") },
				scope,
			});
			return c.json({ effective, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(AUTHORIZATION_OPERATIONS.assignmentsList.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const subject = authorizationSubjectFilter(c.req.query("subjectKind"), c.req.query("subjectId"));
			const assignments = await listAuthorizationAssignmentsInAuth(store, {
				organizationId: c.req.param("id"),
				...(subject ? { subject } : {}),
				scope,
			});
			return c.json({ assignments, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.patch(AUTHORIZATION_OPERATIONS.assignmentsReplace.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const stage = "authorization.assignments.replace";
			const body = await readAuthorizationRequestBody(
				c.req.json(),
				stage,
				["roleIds", "expectedRevision", "dryRun", "confirm"],
			);
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const expectedRevision = optionalAuthorizationString(body, "expectedRevision", stage);
			const dryRun = optionalAuthorizationBoolean(body, "dryRun", stage);
			const confirm = optionalAuthorizationBoolean(body, "confirm", stage);
			const result = await replaceAuthorizationAssignmentsInAuth(store, {
				organizationId: c.req.param("id"),
				subject: { kind: c.req.param("subjectKind") as "principal" | "service_account", id: c.req.param("subjectId") },
				roleIds: body.roleIds as string[],
				...(expectedRevision === undefined ? {} : { expectedRevision }),
				...(dryRun === undefined ? {} : { dryRun }),
				...(confirm === undefined ? {} : { confirm }),
				actor: requestActor(c),
				source: "api",
				scope,
			});
			const output = authorizationOperationResult(result as Record<string, unknown>, scope);
			if (!("dryRun" in output)) await store.ready();
			return c.json(output);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(AUTHORIZATION_OPERATIONS.reconcile.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const stage = "authorization.reconcile";
			const body = await readAuthorizationRequestBody(
				c.req.json(),
				stage,
				["dryRun", "confirm"],
			);
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const dryRun = optionalAuthorizationBoolean(body, "dryRun", stage);
			const confirm = optionalAuthorizationBoolean(body, "confirm", stage);
			const result = await reconcileAuthorizationOrganizationInAuth(store, {
				organizationId: c.req.param("id"),
				...(dryRun === undefined ? {} : { dryRun }),
				...(confirm === undefined ? {} : { confirm }),
				actor: requestActor(c),
				auditSource: "api",
				scope,
			});
			const output = authorizationOperationResult(result as Record<string, unknown>, scope);
			if (!("dryRun" in output)) await store.ready();
			return c.json(output);
		} catch (e) {
			return handleError(c, e);
		}
	});

	// --- Service accounts (same normalized PostgreSQL authority) ---

	routes.get(SERVICE_ACCOUNT_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const serviceAccounts = await listServiceAccountsInAuth(store, { organizationId: c.req.param("id"), scope });
			return c.json({ serviceAccounts, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(SERVICE_ACCOUNT_OPERATIONS.inspect.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const result = await inspectServiceAccountInAuth(store, { organizationId: c.req.param("id"), serviceAccountId: c.req.param("accountId"), scope });
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SERVICE_ACCOUNT_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await readAuthorizationRequestBody(
				c.req.json(),
				"authorization.service_accounts.create",
				["name", "roleIds", "dryRun"],
			);
			if (!Object.hasOwn(body, "roleIds")) {
				throw new ClearanceError({
					code: "AUTHORIZATION_INPUT_INVALID",
					message: "roleIds is required",
					stage: "authorization.service_accounts.create",
					status: 400,
				});
			}
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const dryRun = optionalAuthorizationBoolean(
				body,
				"dryRun",
				"authorization.service_accounts.create",
			);
			const result = await createServiceAccountInAuth(store, {
				organizationId: c.req.param("id"),
				name: body.name as string,
				roleIds: body.roleIds as string[] | undefined,
				...(dryRun === undefined ? {} : { dryRun }),
				actor: requestActor(c),
				source: "api",
				scope,
			});
			const output = authorizationOperationResult(result as Record<string, unknown>, scope);
			if (!("dryRun" in output)) {
				await store.ready();
				return c.json(output, 201);
			}
			return c.json(output);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.patch(SERVICE_ACCOUNT_OPERATIONS.disable.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await readAuthorizationRequestBody(
				c.req.json(),
				"authorization.service_accounts.status",
				["status", "dryRun"],
			);
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const dryRun = optionalAuthorizationBoolean(
				body,
				"dryRun",
				"authorization.service_accounts.status",
			);
			if (body.status !== "active" && body.status !== "disabled") {
				throw new ClearanceError({ code: "AUTHORIZATION_SERVICE_ACCOUNT_STATUS_INVALID", message: "status must be active or disabled", stage: "authorization.service_accounts.status", status: 400 });
			}
			const result = await setServiceAccountStatusInAuth(store, {
				organizationId: c.req.param("id"),
				serviceAccountId: c.req.param("accountId"),
				status: body.status,
				...(dryRun === undefined ? {} : { dryRun }),
				actor: requestActor(c),
				source: "api",
				scope,
			});
			const output = authorizationOperationResult(result as Record<string, unknown>, scope);
			if (!("dryRun" in output)) await store.ready();
			return c.json(output);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SERVICE_ACCOUNT_OPERATIONS.credentialCreate.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await readAuthorizationRequestBody(
				c.req.json(),
				"authorization.credentials.create",
				["expiresAt", "dryRun", "operationId"],
			);
			const expiresAt = optionalAuthorizationString(
				body,
				"expiresAt",
				"authorization.credentials.create",
			);
			const dryRun = optionalAuthorizationBoolean(
				body,
				"dryRun",
				"authorization.credentials.create",
			);
			const credentialOperation = credentialMutationOperation(
				body,
				dryRun,
				"authorization.credentials.create",
			);
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const result = await createServiceAccountCredentialInAuth(store, {
				organizationId: c.req.param("id"), serviceAccountId: c.req.param("accountId"),
				...(expiresAt === undefined ? {} : { expiresAt }),
				...credentialOperation,
				actor: requestActor(c), source: "api", scope,
			});
			const output = authorizationOperationResult(result as Record<string, unknown>, scope);
			if (!("dryRun" in output)) {
				await store.ready();
				c.header("Cache-Control", "no-store");
				c.header("Pragma", "no-cache");
			}
			return c.json(output, "dryRun" in output ? 200 : 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SERVICE_ACCOUNT_OPERATIONS.credentialRotate.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await readAuthorizationRequestBody(
				c.req.json(),
				"authorization.credentials.rotate",
				["expiresAt", "dryRun", "operationId"],
			);
			const expiresAt = optionalAuthorizationString(
				body,
				"expiresAt",
				"authorization.credentials.rotate",
			);
			const dryRun = optionalAuthorizationBoolean(
				body,
				"dryRun",
				"authorization.credentials.rotate",
			);
			const credentialOperation = credentialMutationOperation(
				body,
				dryRun,
				"authorization.credentials.rotate",
			);
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const result = await rotateServiceAccountCredentialInAuth(store, {
				organizationId: c.req.param("id"), serviceAccountId: c.req.param("accountId"), credentialId: c.req.param("credentialId"),
				...(expiresAt === undefined ? {} : { expiresAt }),
				...credentialOperation,
				actor: requestActor(c), source: "api", scope,
			});
			const output = authorizationOperationResult(result as Record<string, unknown>, scope);
			if (!("dryRun" in output)) {
				await store.ready();
				c.header("Cache-Control", "no-store");
				c.header("Pragma", "no-cache");
			}
			return c.json(output);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SERVICE_ACCOUNT_OPERATIONS.credentialRevoke.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await readAuthorizationRequestBody(
				c.req.json(),
				"authorization.credentials.revoke",
				["dryRun"],
			);
			requireAuthorizationPostgres(store);
			const scope = scopeForRequest(store, c);
			const dryRun = optionalAuthorizationBoolean(
				body,
				"dryRun",
				"authorization.credentials.revoke",
			);
			const result = await revokeServiceAccountCredentialInAuth(store, {
				organizationId: c.req.param("id"), serviceAccountId: c.req.param("accountId"), credentialId: c.req.param("credentialId"),
				...(dryRun === undefined ? {} : { dryRun }),
				actor: requestActor(c), source: "api", scope,
			});
			const output = authorizationOperationResult(result as Record<string, unknown>, scope);
			if (!("dryRun" in output)) await store.ready();
			return c.json(output);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get("/v1/settings", async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json({
				...publicConfig(store.snapshot.meta.config),
				schemaVersion: store.snapshot.meta.schemaVersion,
				releaseVersion: store.snapshot.releaseVersion,
				resourceCounts: store.resourceCounts(),
				storeBackend: store.backend,
				scope,
				/** User scope is server-configured; headers are not authority. */
				tokenBoundary: "principal-derived-scope",
				telemetry: { remoteSinks: [], default: "disabled" },
				auth: { mode: "bearer-operator-or-managed-api-key" },
			});
		} catch (e) {
			return handleError(c, e);
		}
	});

	return routes;
}
