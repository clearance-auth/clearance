import type { ManagementStore } from "../store/types.js";
import type { Membership, Organization, Principal } from "../types/resources.js";
import type { ArchiveOrganizationResult } from "../services/core.js";
import type { MembershipActorSource, MembershipSource } from "../services/members.js";
import type { RevokeSessionResult, SessionView } from "../services/sessions.js";
import type { AuthRuntimeGateway, PasswordSetupGrant } from "./auth-runtime-gateway.js";
import type { OperationContext } from "./context.js";
import {
	createUserUseCase,
	deleteUserUseCase,
	disableUserUseCase,
	updateUserUseCase,
} from "./users.js";
import {
	inspectSessionUseCase,
	listSessionsUseCase,
	revokeSessionUseCase,
} from "./sessions.js";
import {
	archiveOrganizationUseCase,
	createOrganizationUseCase,
	updateOrganizationUseCase,
} from "./organizations.js";
import {
	addMemberUseCase,
	removeMemberUseCase,
	updateMemberUseCase,
} from "./members.js";

export interface CreateUserInput {
	readonly email: string;
	readonly name: string;
	readonly password?: string;
	readonly dryRun?: boolean;
}

export type CreateUserResult =
	| {
			dryRun: true;
			email: string;
			name: string;
		}
	| {
			dryRun: false;
			user: Principal;
			passwordSetup?: PasswordSetupGrant;
		};

export interface UpdateUserInput {
	readonly id: string;
	readonly name?: string;
	readonly email?: string;
	readonly status?: unknown;
	readonly dryRun?: boolean;
}

export type UpdateUserResult =
	| {
			dryRun: true;
			id: string;
			name?: string;
			email?: string;
			status?: "active" | "disabled";
		}
	| { dryRun: false; user: Principal };

export interface DisableUserInput {
	readonly id: string;
	readonly dryRun?: boolean;
}

export type DisableUserResult =
	| { dryRun: true; user: Principal }
	| { dryRun: false; user: Principal };

export interface ManagementApplication {
	readonly users: {
		create(
			context: OperationContext,
			input: CreateUserInput,
		): Promise<CreateUserResult>;
		update(
			context: OperationContext,
			input: UpdateUserInput,
		): Promise<UpdateUserResult>;
		disable(
			context: OperationContext,
			input: DisableUserInput,
		): Promise<DisableUserResult>;
		delete(context: OperationContext, id: string): Promise<Principal>;
	};
	readonly sessions: {
		list(
			context: OperationContext,
			input: { limit: number; cursor?: string },
		): Promise<{ sessions: SessionView[]; nextCursor: string | null }>;
		inspect(context: OperationContext, id: string): Promise<SessionView>;
		revoke(context: OperationContext, id: string): Promise<RevokeSessionResult>;
	};
	readonly organizations: {
		create(
			context: OperationContext,
			input: { name: string; slug?: string; ownerUserId?: string },
		): Promise<Organization>;
		update(
			context: OperationContext,
			id: string,
			input: { name?: string; slug?: string },
		): Promise<Organization>;
		archive(
			context: OperationContext,
			id: string,
			input: { dryRun?: boolean; confirm?: boolean },
		): Promise<ArchiveOrganizationResult>;
	};
	readonly members: {
		add(
			context: OperationContext,
			input: {
				organizationId: string;
				principalId: string;
				role?: string;
				source?: MembershipSource;
				auditSource?: MembershipActorSource;
			},
		): Promise<Membership>;
		update(
			context: OperationContext,
			id: string,
			input: { role: string; auditSource?: MembershipActorSource },
		): Promise<Membership>;
		remove(
			context: OperationContext,
			id: string,
			input?: { auditSource?: MembershipActorSource },
		): Promise<Membership>;
	};
}

export function createManagementApplication(input: {
	store: ManagementStore;
	authRuntime?: AuthRuntimeGateway;
}): ManagementApplication {
	if (input.store.backend === "postgres" && !input.authRuntime) {
		throw new Error("Postgres ManagementApplication requires an AuthRuntimeGateway");
	}
	const authRuntime = input.store.backend === "postgres" ? input.authRuntime : undefined;

	return {
		users: {
			create: (context, createInput) =>
				createUserUseCase(input.store, authRuntime, context, createInput),
			update: (context, updateInput) =>
				updateUserUseCase(input.store, authRuntime, context, updateInput),
			disable: (context, disableInput) =>
				disableUserUseCase(input.store, authRuntime, context, disableInput),
			delete: (context, id) =>
				deleteUserUseCase(input.store, authRuntime, context, id),
		},
		sessions: {
			list: (context, listInput) =>
				listSessionsUseCase(input.store, authRuntime, context, listInput),
			inspect: (context, id) =>
				inspectSessionUseCase(input.store, authRuntime, context, id),
			revoke: (context, id) =>
				revokeSessionUseCase(input.store, authRuntime, context, id),
		},
		organizations: {
			create: (context, createInput) =>
				createOrganizationUseCase(input.store, authRuntime, context, createInput),
			update: (context, id, updateInput) =>
				updateOrganizationUseCase(input.store, authRuntime, context, id, updateInput),
			archive: (context, id, archiveInput) =>
				archiveOrganizationUseCase(input.store, authRuntime, context, id, archiveInput),
		},
		members: {
			add: (context, memberInput) =>
				addMemberUseCase(input.store, authRuntime, context, memberInput),
			update: (context, id, memberInput) =>
				updateMemberUseCase(input.store, authRuntime, context, id, memberInput),
			remove: (context, id, memberInput) =>
				removeMemberUseCase(input.store, authRuntime, context, id, memberInput),
		},
	};
}
