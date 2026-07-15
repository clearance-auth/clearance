import {
	createUserInAuth,
	createUserWithPasswordSetupInAuth,
	createOrgInAuth,
	addMemberInAuth,
	archiveOrganizationInAuth,
	deleteUserInAuth,
	disableUserInAuth,
	ensureAuthMigrated,
	inspectSessionInAuth,
	listSessionsPageInAuth,
	removeMemberInAuth,
	revokeSessionInAuth,
	updateMemberInAuth,
	updateOrganizationInAuth,
	updateUserInAuth,
} from "../auth-bridge.js";
import { syncRuntimeOrganizationToManagementDurable } from "../services/identity.js";
import type { AuthRuntimeGateway } from "../application/auth-runtime-gateway.js";
import type { ManagementStore } from "../store/types.js";

export function createAuthBridgeRuntimeGateway(input: {
	store: ManagementStore;
}): AuthRuntimeGateway {
	const { store } = input;
	if (store.backend !== "postgres" || typeof store.mutateCoordinated !== "function") {
		throw new Error("AuthBridgeRuntimeGateway requires a coordinated Postgres management store");
	}

	return {
		users: {
			async provision(context, provisionInput) {
				await ensureAuthMigrated();
				if (provisionInput.password) {
					return {
						user: await createUserInAuth({
							...provisionInput,
							password: provisionInput.password,
							managementStore: store,
							operationContext: context,
						}),
					};
				}
				return createUserWithPasswordSetupInAuth({
					email: provisionInput.email,
					name: provisionInput.name,
					managementStore: store,
					operationContext: context,
				});
			},
			updateCoordinated: (context, id, updateInput) =>
				updateUserInAuth(store, id, {
					...updateInput,
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
			disableCoordinated: (context, id) =>
				disableUserInAuth(store, id, {
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
			deleteCoordinated: (context, id) =>
				deleteUserInAuth(store, id, {
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
		},
		sessions: {
			listPage: (context, listInput) =>
				listSessionsPageInAuth(store, {
					scope: context.scope,
					limit: listInput.limit,
					...(listInput.cursor !== undefined ? { cursor: listInput.cursor } : {}),
				}),
			inspect: (context, id) =>
				inspectSessionInAuth(store, id, { scope: context.scope }),
			revokeCoordinated: (context, id) =>
				revokeSessionInAuth(store, id, {
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
		},
		organizations: {
			async provision(context, provisionInput) {
				await ensureAuthMigrated();
				const runtimeOrganization = await createOrgInAuth({
					name: provisionInput.name,
					...(provisionInput.slug !== undefined ? { slug: provisionInput.slug } : {}),
					userId: provisionInput.ownerUserId,
				});
				return syncRuntimeOrganizationToManagementDurable(
					store,
					runtimeOrganization,
					provisionInput.ownerUserId,
					{
						projectId: context.scope.projectId,
						environmentId: context.scope.environmentId,
						actor: context.actor,
						role: "owner",
					},
				);
			},
			updateCoordinated: (context, id, updateInput) =>
				updateOrganizationInAuth(store, id, {
					...updateInput,
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
			archiveCoordinated: (context, id, archiveInput) =>
				archiveOrganizationInAuth(store, id, {
					...archiveInput,
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
		},
		members: {
			addCoordinated: (context, memberInput) =>
				addMemberInAuth(store, {
					...memberInput,
					actor: context.actor,
					auditSource: memberInput.auditSource ?? context.source,
					scope: context.scope,
				}),
			updateCoordinated: (context, id, memberInput) =>
				updateMemberInAuth(store, id, {
					...memberInput,
					actor: context.actor,
					auditSource: memberInput.auditSource ?? context.source,
					scope: context.scope,
				}),
			removeCoordinated: (context, id, memberInput) =>
				removeMemberInAuth(store, id, {
					...memberInput,
					actor: context.actor,
					auditSource: memberInput?.auditSource ?? context.source,
					scope: context.scope,
				}),
		},
	};
}
