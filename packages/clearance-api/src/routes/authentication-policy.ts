import {
	AUTHENTICATION_POLICY_OPERATIONS,
	ClearanceError,
	applyAuthenticationPolicyForManagement,
	getAuthenticationPolicyForManagement,
	planAuthenticationPolicyForManagement,
	unlockAuthenticationForManagement,
	type AuthenticationPolicyApplyInput,
	type AuthenticationPolicyPlanInput,
	type AuthenticationUnlockInput,
} from "@clearance/management";
import { Hono, type Context } from "hono";
import {
	apiOperationContext,
	type ScopedRouteDependencies,
} from "./shared.js";

function inputError(stage: string, message: string, remediation: string): ClearanceError {
	return new ClearanceError({
		code: "AUTHENTICATION_POLICY_INPUT_INVALID",
		message,
		stage,
		status: 400,
		remediation,
	});
}

async function objectBody(context: Context, stage: string): Promise<Record<string, unknown>> {
	let value: unknown;
	try {
		value = await context.req.json();
	} catch {
		throw inputError(stage, "A JSON request body is required.", "Send one JSON object.");
	}
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw inputError(stage, "The request body must be a JSON object.", "Send one JSON object.");
	}
	return value as Record<string, unknown>;
}

function organizationId(value: unknown, stage: string): string | undefined {
	if (value === undefined) return undefined;
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 1_024 ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		throw inputError(
			stage,
			"organizationId must be a non-empty string.",
			"Use an organization id from the active project and environment.",
		);
	}
	return value;
}

function policyInput(
	body: Record<string, unknown>,
	stage: string,
): AuthenticationPolicyPlanInput["policy"] {
	if (!Object.hasOwn(body, "policy")) {
		throw inputError(
			stage,
			"policy is required.",
			"Send a full environment policy, a sparse organization override, or null to delete an override.",
		);
	}
	return body.policy as AuthenticationPolicyPlanInput["policy"];
}

function candidateInput(
	body: Record<string, unknown>,
	stage: string,
): AuthenticationPolicyPlanInput {
	const targetOrganizationId = organizationId(body.organizationId, stage);
	const policy = policyInput(body, stage);
	if (targetOrganizationId !== undefined) {
		return {
			organizationId: targetOrganizationId,
			policy: policy as Extract<
				AuthenticationPolicyPlanInput,
				{ organizationId: string }
			>["policy"],
		};
	}
	return {
		policy: policy as Extract<
			AuthenticationPolicyPlanInput,
			{ organizationId?: never }
		>["policy"],
	};
}

export function registerAuthenticationPolicyRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
}: ScopedRouteDependencies) {
	const routes = new Hono();

	routes.get(AUTHENTICATION_POLICY_OPERATIONS.get.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(await getAuthenticationPolicyForManagement(
				store,
				apiOperationContext(scope, c),
				{
					organizationId: organizationId(
						c.req.query("organizationId"),
						AUTHENTICATION_POLICY_OPERATIONS.get.id,
					),
				},
			));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(AUTHENTICATION_POLICY_OPERATIONS.plan.http.path, async (c) => {
		try {
			const body = await objectBody(c, AUTHENTICATION_POLICY_OPERATIONS.plan.id);
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(await planAuthenticationPolicyForManagement(
				store,
				apiOperationContext(scope, c),
				candidateInput(body, AUTHENTICATION_POLICY_OPERATIONS.plan.id),
			));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.patch(AUTHENTICATION_POLICY_OPERATIONS.apply.http.path, async (c) => {
		try {
			const body = await objectBody(c, AUTHENTICATION_POLICY_OPERATIONS.apply.id);
			if (typeof body.expectedRevision !== "string" || body.expectedRevision === "") {
				throw inputError(
					AUTHENTICATION_POLICY_OPERATIONS.apply.id,
					"expectedRevision is required.",
					"Use the expectedRevision returned by auth-policy get or plan.",
				);
			}
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const candidate = candidateInput(
				body,
				AUTHENTICATION_POLICY_OPERATIONS.apply.id,
			);
			const input: AuthenticationPolicyApplyInput & {
				dryRun?: boolean;
				confirm?: boolean;
			} = {
				...candidate,
				expectedRevision: body.expectedRevision,
				dryRun: body.dryRun === true,
				confirm: body.confirm === true,
			};
			return c.json(await applyAuthenticationPolicyForManagement(
				store,
				apiOperationContext(scope, c),
				input,
			));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(AUTHENTICATION_POLICY_OPERATIONS.unlock.http.path, async (c) => {
		try {
			const body = await objectBody(c, AUTHENTICATION_POLICY_OPERATIONS.unlock.id);
			if (
				typeof body.userId !== "string" ||
				body.userId.length === 0 ||
				body.userId.length > 1_024 ||
				body.userId.trim() !== body.userId ||
				body.userId.includes("\0")
			) {
				throw inputError(
					AUTHENTICATION_POLICY_OPERATIONS.unlock.id,
					"userId is required.",
					"Use a user id from users list.",
				);
			}
			if (body.kind !== "password" && body.kind !== "factor" && body.kind !== "all") {
				throw inputError(
					AUTHENTICATION_POLICY_OPERATIONS.unlock.id,
					"kind must be password, factor, or all.",
					"Choose the exact lockout authority to clear.",
				);
			}
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const input: AuthenticationUnlockInput & {
				dryRun?: boolean;
				confirm?: boolean;
			} = {
				userId: body.userId,
				kind: body.kind,
				dryRun: body.dryRun === true,
				confirm: body.confirm === true,
			};
			return c.json(await unlockAuthenticationForManagement(
				store,
				apiOperationContext(scope, c),
				input,
			));
		} catch (error) {
			return handleError(c, error);
		}
	});

	return routes;
}
