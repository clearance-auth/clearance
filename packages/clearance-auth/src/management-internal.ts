/**
 * Management bootstrap only. This subpath is intentionally excluded from the
 * root @clearance/auth API: tenant-product authority is process-owned server
 * wiring, never browser-facing application configuration.
 */
export {
	createClearanceManagementAuth,
	type ClearanceManagementAuthOptions,
	type ManagedOrganizationLifecycleFacade,
} from "./create-auth.js";
export type {
	TenantProductAdministrationFacade,
	TenantProductAuditEvent,
	TenantProductReadiness,
	TenantProductScimConnection,
	TenantProductSsoConnection,
} from "./public-types/index.js";
