/**
 * Declaration surface for the server-only management bootstrap subpath.
 *
 * This module is deliberately not re-exported from the root public-type barrel:
 * product-owned tenant administration wiring must remain opt-in and server-only.
 */
import type { ClearanceAuthBundle, CreateClearanceAuthOptions, TenantProductAdministrationFacade } from "./index.js";
export type ClearanceManagementAuthOptions = CreateClearanceAuthOptions & {
    tenantProductAdministration: TenantProductAdministrationFacade;
    managedOrganizationLifecycle: ManagedOrganizationLifecycleFacade;
};
export type ManagedOrganizationLifecycleFacade = Readonly<{
    finalizeCreatedOrganization(input: Readonly<{
        organization: Readonly<{
            id: string;
            name: string;
            slug: string;
            createdAt: Date;
        }>;
        owner: Readonly<{
            id: string;
            email: string;
            name?: string | null;
            createdAt: Date;
            updatedAt: Date;
        }>;
        ownerMembershipId: string;
        authorizationRevision: string;
        transaction: import("./index.js").ClearanceTransactionQuery;
    }>): Promise<void>;
    refreshAfterCommit(): Promise<void>;
}>;
export declare function createClearanceManagementAuth(options: ClearanceManagementAuthOptions): ClearanceAuthBundle;
