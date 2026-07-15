import {
	addMember,
	removeMember,
	updateMember,
	type MembershipActorSource,
	type MembershipSource,
} from "../services/members.js";
import type { ManagementStore } from "../store/types.js";
import { withManagementUnitOfWork } from "../store/unit-of-work.js";
import type { Membership } from "../types/resources.js";
import type { AuthRuntimeGateway } from "./auth-runtime-gateway.js";
import type { OperationContext } from "./context.js";

export interface AddMemberUseCaseInput {
	organizationId: string;
	principalId: string;
	role?: string;
	source?: MembershipSource;
	auditSource?: MembershipActorSource;
}

export async function addMemberUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	input: AddMemberUseCaseInput,
): Promise<Membership> {
	return authRuntime
		? await authRuntime.members.addCoordinated(context, input)
		: await withManagementUnitOfWork(store, (unitOfWork) =>
				addMember(unitOfWork, {
					...input,
					actor: context.actor,
					auditSource: input.auditSource ?? context.source,
					scope: context.scope,
				}),
			);
}

export async function updateMemberUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	id: string,
	input: { role: string; auditSource?: MembershipActorSource },
): Promise<Membership> {
	return authRuntime
		? await authRuntime.members.updateCoordinated(context, id, input)
		: await withManagementUnitOfWork(store, (unitOfWork) =>
				updateMember(unitOfWork, id, {
					...input,
					actor: context.actor,
					auditSource: input.auditSource ?? context.source,
					scope: context.scope,
				}),
			);
}

export async function removeMemberUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	id: string,
	input?: { auditSource?: MembershipActorSource },
): Promise<Membership> {
	return authRuntime
		? await authRuntime.members.removeCoordinated(context, id, input)
		: await withManagementUnitOfWork(store, (unitOfWork) =>
				removeMember(unitOfWork, id, {
					...input,
					actor: context.actor,
					auditSource: input?.auditSource ?? context.source,
					scope: context.scope,
				}),
			);
}
