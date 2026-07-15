import {
	archiveOrganization,
	createOrganization,
	updateOrganization,
	type ArchiveOrganizationResult,
} from "../services/core.js";
import type { ManagementStore } from "../store/types.js";
import { withManagementUnitOfWork } from "../store/unit-of-work.js";
import type { Organization } from "../types/resources.js";
import type { AuthRuntimeGateway } from "./auth-runtime-gateway.js";
import type { OperationContext } from "./context.js";

export async function createOrganizationUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	input: { name: string; slug?: string; ownerUserId?: string },
): Promise<Organization> {
	if (authRuntime) {
		const ownerUserId = input.ownerUserId ??
			store.snapshot.principals.find((principal) => principal.status === "active")?.id;
		if (!ownerUserId) throw new Error("Create a user first or provide ownerUserId");
		return await authRuntime.organizations.provision(context, {
			name: input.name,
			...(input.slug !== undefined ? { slug: input.slug } : {}),
			ownerUserId,
		});
	}
	return await withManagementUnitOfWork(store, (unitOfWork) =>
		createOrganization(unitOfWork, {
			name: input.name,
			...(input.slug !== undefined ? { slug: input.slug } : {}),
			projectId: context.scope.projectId,
			environmentId: context.scope.environmentId,
			actor: context.actor,
			source: context.source,
		}),
	);
}

export async function updateOrganizationUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	id: string,
	input: { name?: string; slug?: string },
): Promise<Organization> {
	return authRuntime
		? await authRuntime.organizations.updateCoordinated(context, id, input)
		: await withManagementUnitOfWork(store, (unitOfWork) =>
				updateOrganization(unitOfWork, id, {
					...input,
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
			);
}

export async function archiveOrganizationUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	id: string,
	input: { dryRun?: boolean; confirm?: boolean },
): Promise<ArchiveOrganizationResult> {
	if (authRuntime) {
		return authRuntime.organizations.archiveCoordinated(context, id, input);
	}
	const archiveInput = {
		...input,
		actor: context.actor,
		source: context.source,
		scope: context.scope,
	};
	if (input.dryRun === true || input.confirm !== true) {
		return archiveOrganization(store, id, archiveInput);
	}
	return withManagementUnitOfWork(store, (unitOfWork) =>
		archiveOrganization(unitOfWork, id, archiveInput)
	);
}
