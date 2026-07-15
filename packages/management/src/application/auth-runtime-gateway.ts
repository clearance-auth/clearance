import type { Membership, Organization, Principal } from "../types/resources.js";
import type { ArchiveOrganizationResult } from "../services/core.js";
import type { MembershipActorSource, MembershipSource } from "../services/members.js";
import type { RevokeSessionResult, SessionView } from "../services/sessions.js";
import type { OperationContext } from "./context.js";

export type PasswordSetupGrant = {
	token: string;
	expiresAt: string;
};

export interface AuthRuntimeGateway {
	readonly users: {
		provision(
			context: OperationContext,
			input: { email: string; name: string; password?: string },
		): Promise<{ user: Principal; passwordSetup?: PasswordSetupGrant }>;
		updateCoordinated(
			context: OperationContext,
			id: string,
			input: { name?: string; email?: string; status?: "active" | "disabled" },
		): Promise<Principal>;
		disableCoordinated(context: OperationContext, id: string): Promise<Principal>;
		deleteCoordinated(context: OperationContext, id: string): Promise<Principal>;
	};
	readonly sessions: {
		listPage(
			context: OperationContext,
			input: { limit: number; cursor?: string },
		): Promise<{ sessions: SessionView[]; nextCursor: string | null }>;
		inspect(context: OperationContext, id: string): Promise<SessionView>;
		revokeCoordinated(
			context: OperationContext,
			id: string,
		): Promise<RevokeSessionResult>;
	};
	readonly organizations: {
		provision(
			context: OperationContext,
			input: { name: string; slug?: string; ownerUserId: string },
		): Promise<Organization>;
		updateCoordinated(
			context: OperationContext,
			id: string,
			input: { name?: string; slug?: string },
		): Promise<Organization>;
		archiveCoordinated(
			context: OperationContext,
			id: string,
			input: { dryRun?: boolean; confirm?: boolean },
		): Promise<ArchiveOrganizationResult>;
	};
	readonly members: {
		addCoordinated(
			context: OperationContext,
			input: {
				organizationId: string;
				principalId: string;
				role?: string;
				source?: MembershipSource;
				auditSource?: MembershipActorSource;
			},
		): Promise<Membership>;
		updateCoordinated(
			context: OperationContext,
			id: string,
			input: { role: string; auditSource?: MembershipActorSource },
		): Promise<Membership>;
		removeCoordinated(
			context: OperationContext,
			id: string,
			input?: { auditSource?: MembershipActorSource },
		): Promise<Membership>;
	};
}
