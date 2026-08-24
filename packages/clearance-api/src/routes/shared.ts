import type {
	ManagementApplication,
	ManagementStore,
	OperationContext,
	ResourceScope,
} from "@clearance/management";
import type { Context } from "hono";
import { randomUUID } from "node:crypto";
import { requestActor } from "../request-auth.js";

export interface BaseRouteDependencies {
	storeForRequest(): Promise<ManagementStore>;
	handleError(
		context: { json: (body: unknown, status?: number) => Response },
		error: unknown,
	): Response;
}

export interface ScopedRouteDependencies extends BaseRouteDependencies {
	scopeForRequest(store: ManagementStore, context: Context): ResourceScope;
}

export interface ApplicationRouteDependencies extends ScopedRouteDependencies {
	applicationFor(store: ManagementStore): ManagementApplication;
}

type ApiOperationContext = OperationContext & {
	readonly actor: string;
	readonly source: "api";
	readonly correlationId: string;
};

export function apiOperationContext(scope: ResourceScope, context: Context): ApiOperationContext {
	const requestId = context.res.headers.get("x-request-id") ?? "";
	const correlationId = /^[A-Za-z0-9._:-]{1,128}$/.test(requestId)
		? requestId
		: randomUUID();
	return {
		scope,
		actor: requestActor(context),
		source: "api",
		correlationId,
	};
}
