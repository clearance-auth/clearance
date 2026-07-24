export type VaultRouteId =
	| "sign-in"
	| "sign-up"
	| "recovery"
	| "account"
	| "organizations"
	| "invitations"
	| "access"
	| "service-accounts"
	| "enterprise"
	| "audit";

export type VaultWorkflow = Readonly<{
	id: VaultRouteId;
	label: string;
	visibility: "public" | "authenticated";
	description: string;
}>;

export const VAULT_WORKFLOWS: readonly VaultWorkflow[] = Object.freeze([
	{
		id: "sign-in",
		label: "Sign in",
		visibility: "public",
		description: "Sign in with an email address and password.",
	},
	{
		id: "sign-up",
		label: "Create account",
		visibility: "public",
		description: "Create a new account.",
	},
	{
		id: "recovery",
		label: "Recover account",
		visibility: "public",
		description: "Request a password reset.",
	},
	{
		id: "account",
		label: "Account security",
		visibility: "authenticated",
		description: "Manage sessions, passkeys, TOTP, and recovery codes.",
	},
	{
		id: "organizations",
		label: "Organizations",
		visibility: "authenticated",
		description: "List and switch the active organization.",
	},
	{
		id: "invitations",
		label: "Invitations",
		visibility: "authenticated",
		description: "Accept, reject, send, and cancel invitations.",
	},
	{
		id: "access",
		label: "Access",
		visibility: "authenticated",
		description: "Review roles and replace tenant role assignments.",
	},
	{
		id: "service-accounts",
		label: "Service accounts",
		visibility: "authenticated",
		description: "Manage service accounts and one-time credentials.",
	},
	{
		id: "enterprise",
		label: "Enterprise setup",
		visibility: "authenticated",
		description: "Open provider-guided SSO and directory setup.",
	},
	{
		id: "audit",
		label: "Audit",
		visibility: "authenticated",
		description: "Open the tenant audit log.",
	},
]);

export const VAULT_AUTH_ENDPOINTS = Object.freeze({
	session: { method: "GET", path: "/get-session" },
	signIn: { method: "POST", path: "/sign-in/email" },
	signUp: { method: "POST", path: "/sign-up/email" },
	signOut: { method: "POST", path: "/sign-out" },
	requestPasswordReset: { method: "POST", path: "/request-password-reset" },
	resetPassword: { method: "POST", path: "/reset-password" },
	changePassword: { method: "POST", path: "/change-password" },
	listSessions: { method: "GET", path: "/list-sessions" },
	revokeOtherSessions: { method: "POST", path: "/revoke-other-sessions" },
	listPasskeys: { method: "GET", path: "/passkey/list" },
	passkeyRegistrationOptions: {
		method: "POST",
		path: "/passkey/generate-registration-options",
	},
	passkeyRegistrationVerify: {
		method: "POST",
		path: "/passkey/verify-registration",
	},
	passkeyAuthenticationOptions: { method: "POST", path: "/passkey/generate-authentication-options" },
	passkeyAuthenticationVerify: { method: "POST", path: "/passkey/verify-authentication" },
	passkeyDeleteOptions: {
		method: "POST",
		path: "/passkey/generate-deletion-options",
	},
	passkeyDelete: { method: "POST", path: "/passkey/delete" },
	enableTwoFactor: { method: "POST", path: "/two-factor/enable" },
	verifyTwoFactor: { method: "POST", path: "/two-factor/verify-totp" },
	sendTwoFactorOTP: { method: "POST", path: "/two-factor/send-otp" },
	verifyTwoFactorOTP: { method: "POST", path: "/two-factor/verify-otp" },
	verifyTwoFactorBackupCode: {
		method: "POST",
		path: "/two-factor/verify-backup-code",
	},
	disableTwoFactor: { method: "POST", path: "/two-factor/disable" },
	generateBackupCodes: {
		method: "POST",
		path: "/two-factor/generate-backup-codes",
	},
	createOrganization: { method: "POST", path: "/organization/create" },
	listOrganizations: { method: "GET", path: "/organization/list" },
	setActiveOrganization: { method: "POST", path: "/organization/set-active" },
	listUserInvitations: {
		method: "GET",
		path: "/organization/list-user-invitations",
	},
	listOrganizationInvitations: {
		method: "GET",
		path: "/organization/list-invitations",
	},
	inviteMember: { method: "POST", path: "/organization/invite-member" },
	cancelInvitation: {
		method: "POST",
		path: "/organization/cancel-invitation",
	},
	acceptInvitation: {
		method: "POST",
		path: "/organization/accept-invitation",
	},
	rejectInvitation: {
		method: "POST",
		path: "/organization/reject-invitation",
	},
} as const);

/**
 * Tenant administration is always organization-scoped and browser-session
 * authenticated. These are route templates, not global SSO or SCIM endpoints.
 */
export const VAULT_TENANT_ENDPOINTS = Object.freeze({
	audit: { method: "GET", path: "/v1/organizations/:organizationId/audit" },
	sso: { method: "GET|POST", path: "/v1/organizations/:organizationId/enterprise/sso" },
	ssoConnection: { method: "GET", path: "/v1/organizations/:organizationId/enterprise/sso/:connectionId" },
	ssoTest: { method: "POST", path: "/v1/organizations/:organizationId/enterprise/sso/:connectionId/test" },
	ssoDisable: { method: "POST", path: "/v1/organizations/:organizationId/enterprise/sso/:connectionId/disable" },
	ssoReplaceSecret: { method: "POST", path: "/v1/organizations/:organizationId/enterprise/sso/:connectionId/replace-secret" },
	scim: { method: "GET|POST", path: "/v1/organizations/:organizationId/enterprise/scim" },
	scimConnection: { method: "GET", path: "/v1/organizations/:organizationId/enterprise/scim/:connectionId" },
	scimTest: { method: "POST", path: "/v1/organizations/:organizationId/enterprise/scim/:connectionId/test" },
	scimDisable: { method: "POST", path: "/v1/organizations/:organizationId/enterprise/scim/:connectionId/disable" },
	scimRotate: { method: "POST", path: "/v1/organizations/:organizationId/enterprise/scim/:connectionId/rotate" },
	readiness: { method: "GET", path: "/v1/organizations/:organizationId/enterprise/readiness" },
} as const);
