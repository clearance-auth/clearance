import {
	KEY_MANAGEMENT_OPERATIONS,
	ClearanceError,
	applyKeyManagementForManagement,
	getKeyManagementStatusForManagement,
	planKeyManagementForManagement,
	type KeyManagementApplyInput,
} from "@clearance/management";
import { Hono, type Context } from "hono";
import {
	apiOperationContext,
	type ScopedRouteDependencies,
} from "./shared.js";

function inputError(stage: string, message: string, remediation: string): ClearanceError {
	return new ClearanceError({
		code: "KEY_MANAGEMENT_INPUT_INVALID",
		message,
		stage,
		status: 400,
		remediation,
	});
}

async function objectBody(context: Context, stage: string): Promise<Record<string, unknown>> {
	const raw = await context.req.text();
	let value: unknown;
	try {
		value = JSON.parse(raw);
	} catch {
		throw inputError(
			stage,
			"A single JSON object request body is required.",
			"Send exactly one JSON object using the documented key-management fields.",
		);
	}
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw inputError(
			stage,
			"The request body must be a JSON object.",
			"Send exactly one JSON object using the documented key-management fields.",
		);
	}
	return value as Record<string, unknown>;
}

function rejectUnknownFields(
	body: Readonly<Record<string, unknown>>,
	stage: string,
	allowed: readonly string[],
): void {
	const unknown = Object.keys(body).find((field) => !allowed.includes(field));
	if (unknown !== undefined) {
		throw inputError(
			stage,
			`Unknown request field: ${unknown}.`,
			`Remove ${unknown}; use only the documented key-management fields.`,
		);
	}
}

function optionalBoolean(
	body: Readonly<Record<string, unknown>>,
	field: "dryRun" | "confirm",
	stage: string,
): boolean | undefined {
	const value = body[field];
	if (value === undefined) return undefined;
	if (typeof value !== "boolean") {
		throw inputError(
			stage,
			`${field} must be a JSON boolean when provided.`,
			`Send ${field} as true or false without quotes.`,
		);
	}
	return value;
}

function applyInput(body: Readonly<Record<string, unknown>>): KeyManagementApplyInput & {
	dryRun?: boolean;
	confirm?: boolean;
} {
	const stage = KEY_MANAGEMENT_OPERATIONS.apply.id;
	rejectUnknownFields(body, stage, ["expectedPlanId", "dryRun", "confirm"]);
	const expectedPlanId = body.expectedPlanId;
	if (
		typeof expectedPlanId !== "string" ||
		!/^[a-f0-9]{64}$/.test(expectedPlanId)
	) {
		throw inputError(
			stage,
			"expectedPlanId must be a lowercase 64-character hexadecimal plan id.",
			"Run key-management plan and send its current planId as expectedPlanId.",
		);
	}
	const dryRun = optionalBoolean(body, "dryRun", stage);
	const confirm = optionalBoolean(body, "confirm", stage);
	return {
		expectedPlanId,
		...(dryRun === undefined ? {} : { dryRun }),
		...(confirm === undefined ? {} : { confirm }),
	};
}

export function registerKeyManagementRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
}: ScopedRouteDependencies) {
	const routes = new Hono();

	routes.get(KEY_MANAGEMENT_OPERATIONS.status.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(await getKeyManagementStatusForManagement(
				store,
				apiOperationContext(scope, c),
			));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(KEY_MANAGEMENT_OPERATIONS.plan.http.path, async (c) => {
		try {
			const body = await objectBody(c, KEY_MANAGEMENT_OPERATIONS.plan.id);
			rejectUnknownFields(body, KEY_MANAGEMENT_OPERATIONS.plan.id, []);
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(await planKeyManagementForManagement(
				store,
				apiOperationContext(scope, c),
			));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(KEY_MANAGEMENT_OPERATIONS.apply.http.path, async (c) => {
		try {
			const input = applyInput(await objectBody(c, KEY_MANAGEMENT_OPERATIONS.apply.id));
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(await applyKeyManagementForManagement(
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
