import {
	createUserInAuth,
	createUserWithPasswordSetupInAuth,
	addMemberInAuth,
	archiveOrganizationInAuth,
	deleteUserInAuth,
	disableUserInAuth,
	ensureAuthMigrated,
	provisionOrganizationInAuth,
	inspectSessionInAuth,
	listSessionsPageInAuth,
	removeMemberInAuth,
	revokeSessionInAuth,
	updateMemberInAuth,
	updateOrganizationInAuth,
	updateUserInAuth,
} from "../auth-bridge.js";
import type { AuthRuntimeGateway } from "../application/auth-runtime-gateway.js";
import type { ManagementStore } from "../store/types.js";
import {
	validateManagementWebhookTargets,
	type ManagementWebhookTarget,
} from "../application/delivery.js";

export function createAuthBridgeRuntimeGateway(input: {
	store: ManagementStore;
	webhookTargets?: readonly ManagementWebhookTarget[];
}): AuthRuntimeGateway {
	const { store } = input;
	if (store.backend !== "postgres" || typeof store.mutateCoordinated !== "function") {
		throw new Error("AuthBridgeRuntimeGateway requires a coordinated Postgres management store");
	}
	const webhookTargets = validateManagementWebhookTargets(
		input.webhookTargets ?? [],
	);

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
				return provisionOrganizationInAuth(store, {
					name: provisionInput.name,
					...(provisionInput.slug !== undefined ? { slug: provisionInput.slug } : {}),
					ownerUserId: provisionInput.ownerUserId,
					scope: context.scope,
					actor: context.actor,
				});
			},
			updateCoordinated: (context, id, updateInput) =>
				updateOrganizationInAuth(store, id, {
					...updateInput,
					actor: context.actor,
					source: context.source,
					scope: context.scope,
					...(context.correlationId
						? { correlationId: context.correlationId }
						: {}),
					webhookTargets,
				}),
			archiveCoordinated: (context, id, archiveInput) =>
				archiveOrganizationInAuth(store, id, {
					...archiveInput,
					actor: context.actor,
					source: context.source,
					scope: context.scope,
					...(context.correlationId
						? { correlationId: context.correlationId }
						: {}),
					webhookTargets,
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
