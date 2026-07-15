import {
	inspectSession,
	listSessionsPage,
	revokeSession,
	type RevokeSessionResult,
	type SessionView,
} from "../services/sessions.js";
import type { ManagementStore } from "../store/types.js";
import { withManagementUnitOfWork } from "../store/unit-of-work.js";
import type { AuthRuntimeGateway } from "./auth-runtime-gateway.js";
import type { OperationContext } from "./context.js";

export async function listSessionsUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	input: { limit: number; cursor?: string },
): Promise<{ sessions: SessionView[]; nextCursor: string | null }> {
	return authRuntime
		? authRuntime.sessions.listPage(context, input)
		: listSessionsPage(store, {
				scope: context.scope,
				limit: input.limit,
				...(input.cursor !== undefined ? { cursor: input.cursor } : {}),
			});
}

export async function inspectSessionUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	id: string,
): Promise<SessionView> {
	return authRuntime
		? authRuntime.sessions.inspect(context, id)
		: inspectSession(store, id, { scope: context.scope });
}

export async function revokeSessionUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	id: string,
): Promise<RevokeSessionResult> {
	return authRuntime
		? await authRuntime.sessions.revokeCoordinated(context, id)
		: await withManagementUnitOfWork(store, (unitOfWork) =>
				revokeSession(unitOfWork, id, {
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
			);
}
