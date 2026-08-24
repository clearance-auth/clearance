import {
	archiveOrganization,
	archiveOrganizationAuthoritative,
	createOrganization,
	createOrganizationAuthoritative,
	updateOrganization,
	updateOrganizationAuthoritative,
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
		const defaultOwner = input.ownerUserId
			? undefined
			: store.storeV2Principals?.authoritative
				? (await store.storeV2Principals.listPage({
						scope: context.scope,
						status: "active",
						limit: 1,
					})).principals[0]
				: store.snapshot.principals.find(
						(principal) =>
							principal.status === "active" &&
							principal.projectId === context.scope.projectId &&
							principal.environmentId === context.scope.environmentId,
					);
		const ownerUserId = input.ownerUserId ?? defaultOwner?.id;
		if (!ownerUserId) throw new Error("Create a user first or provide ownerUserId");
		return await authRuntime.organizations.provision(context, {
			name: input.name,
			...(input.slug !== undefined ? { slug: input.slug } : {}),
			ownerUserId,
		});
	}
	if (store.storeV2Topology?.authoritative) {
		return createOrganizationAuthoritative(store, {
			name: input.name,
			...(input.slug !== undefined ? { slug: input.slug } : {}),
			projectId: context.scope.projectId,
			environmentId: context.scope.environmentId,
			actor: context.actor,
			source: context.source,
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
	if (authRuntime) return await authRuntime.organizations.updateCoordinated(context, id, input);
	if (store.storeV2Topology?.authoritative) {
		return updateOrganizationAuthoritative(store, id, {
			...input,
			actor: context.actor,
			source: context.source,
			scope: context.scope,
		});
	}
	return await withManagementUnitOfWork(store, (unitOfWork) =>
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
		if (store.storeV2Topology?.authoritative) {
			return archiveOrganizationAuthoritative(store, id, archiveInput);
		}
		return archiveOrganization(store, id, archiveInput);
	}
	if (store.storeV2Topology?.authoritative) {
		return archiveOrganizationAuthoritative(store, id, archiveInput);
	}
	return withManagementUnitOfWork(store, (unitOfWork) =>
		archiveOrganization(unitOfWork, id, archiveInput)
	);
}
