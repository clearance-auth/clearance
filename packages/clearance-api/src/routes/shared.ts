import type {
	ManagementApplication,
	ManagementStore,
	OperationContext,
	ResourceScope,
} from "@clearance/management";
import type { Context } from "hono";
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
};

export function apiOperationContext(scope: ResourceScope, context: Context): ApiOperationContext {
	return { scope, actor: requestActor(context), source: "api" };
}
