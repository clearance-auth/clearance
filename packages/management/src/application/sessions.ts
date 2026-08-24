import {
	inspectSession,
	listSessionsPage,
	revokeSession,
	toSessionView,
	type RevokeSessionResult,
	type SessionView,
} from "../services/sessions.js";
import { appendAuditEvent } from "../services/audit.js";
import { ClearanceError } from "../services/errors.js";
import { decodePageCursor, encodePageCursor, normalizePageLimit } from "../services/pagination.js";
import { nowIso } from "../store/json-store.js";
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
	if (!authRuntime && store.storeV2Principals?.authoritative) {
		const limit = normalizePageLimit(input.limit, { stage: "sessions.list", code: "SESSION_LIMIT_INVALID", defaultValue: 100, maximum: 500 });
		const cursor = decodePageCursor(input.cursor, "sessions", "sessions.list");
		const candidates = store.snapshot.sessions
			.filter((session) =>
				session.status === "active" &&
				session.environmentId === context.scope.environmentId &&
				(!cursor ||
					session.createdAt < cursor.createdAt ||
					(session.createdAt === cursor.createdAt && session.id < cursor.id)),
			)
			.sort((a, b) =>
				a.createdAt === b.createdAt
					? b.id.localeCompare(a.id)
					: b.createdAt.localeCompare(a.createdAt),
			)
			.slice(0, limit + 1);
		const resolved = await Promise.all(
			candidates.slice(0, limit).map(async (session) => {
				const principal = await store.storeV2Principals!.getById({
					scope: context.scope,
					id: session.principalId,
				});
				return principal
					? toSessionView(session, principal.projectId)
					: null;
			}),
		);
		const boundary = candidates[limit - 1];
		return {
			sessions: resolved.filter((session): session is SessionView => session !== null),
			nextCursor:
				candidates.length > limit && boundary
					? encodePageCursor("sessions", {
							createdAt: boundary.createdAt,
							id: boundary.id,
						})
					: null,
		};
	}
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
	if (!authRuntime && store.storeV2Principals?.authoritative) {
		const session = store.snapshot.sessions.find((candidate) => candidate.id === id);
		if (!session || session.environmentId !== context.scope.environmentId) {
			throw new ClearanceError({ code: "SESSION_NOT_FOUND", message: "Session not found", stage: "sessions.inspect", status: 404 });
		}
		const principal = await store.storeV2Principals.getById({
			scope: context.scope,
			id: session.principalId,
		});
		if (!principal) {
			throw new ClearanceError({ code: "SESSION_NOT_FOUND", message: "Session not found", stage: "sessions.inspect", status: 404 });
		}
		return toSessionView(session, principal.projectId);
	}
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
	if (!authRuntime && store.storeV2Principals?.authoritative) {
		if (typeof store.mutateCoordinated !== "function") {
			throw new ClearanceError({ code: "STORE_V2_PRINCIPAL_MUTATION_REQUIRED", message: "Relational session revocation requires coordinated storage.", stage: "sessions.revoke", status: 500 });
		}
		return store.mutateCoordinated(async ({ data, principals }) => {
			const session = data.sessions.find((candidate) => candidate.id === id);
			if (!session || session.environmentId !== context.scope.environmentId) {
				throw new ClearanceError({ code: "SESSION_NOT_FOUND", message: "Session not found", stage: "sessions.revoke", status: 404 });
			}
			const principal = await principals?.getById({
				scope: context.scope,
				id: session.principalId,
			});
			if (!principal) {
				throw new ClearanceError({ code: "SESSION_NOT_FOUND", message: "Session not found", stage: "sessions.revoke", status: 404 });
			}
			const idempotent = session.status === "revoked";
			if (!idempotent) {
				session.status = "revoked";
				session.revokedAt = nowIso();
			}
			const view = toSessionView(session, principal.projectId);
			appendAuditEvent(data, {
				actor: context.actor,
				action: "sessions.revoke",
				subjectType: "session",
				subjectId: session.id,
				outcome: "success",
				source: context.source,
				projectId: principal.projectId,
				environmentId: principal.environmentId,
				message: idempotent ? `Session ${session.id} already revoked` : `Revoked session ${session.id}`,
				metadata: { principalId: principal.id, idempotent },
			});
			return { session: view, idempotent };
		});
	}
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
