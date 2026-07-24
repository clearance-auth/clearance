/**
 * Shared CLI ↔ API ↔ Console surface registry.
 * Every management surface that reaches GA must appear here with all three contracts.
 */
import {
	ENVIRONMENT_OPERATIONS,
	EVENT_OPERATIONS,
	AUTHORIZATION_OPERATIONS,
	MEMBER_OPERATIONS,
	ORGANIZATION_OPERATIONS,
	PRODUCT_DOMAIN_OPERATIONS,
	PRODUCT_PRESENTATION_OPERATIONS,
	PRODUCT_SENDER_OPERATIONS,
	PRODUCT_TEMPLATE_OPERATIONS,
	READINESS_OPERATIONS,
	ROLE_OPERATIONS,
	SERVICE_ACCOUNT_OPERATIONS,
	SESSION_OPERATIONS,
	SYSTEM_OPERATIONS,
	USER_OPERATIONS,
} from "./operations.js";
export interface ManagementSurface {
	id: string;
	cliCommand: string;
	apiPath: string;
	/** Route key in packages/clearance-console/public/app.js `routes` */
	consoleRoute: string;
}

function operationApiPath(operation: {
	readonly http: { readonly method: string; readonly path: string };
}): string {
	return `${operation.http.method} ${operation.http.path}`;
}

export const MANAGEMENT_SURFACES: ManagementSurface[] = [
	{
		id: "overview",
		cliCommand: "clearance overview --json",
		apiPath: operationApiPath(SYSTEM_OPERATIONS.overview),
		consoleRoute: "overview",
	},
	{
		id: "users",
		cliCommand: "clearance users list --json",
		apiPath: operationApiPath(USER_OPERATIONS.list),
		consoleRoute: "users",
	},
	{
		id: "users-export",
		cliCommand: "clearance users export --output <path> --format json --json",
		apiPath: operationApiPath(USER_OPERATIONS.export),
		consoleRoute: "users",
	},
	{
		id: "organizations",
		cliCommand: "clearance orgs list --json",
		apiPath: operationApiPath(ORGANIZATION_OPERATIONS.list),
		consoleRoute: "organizations",
	},
	{
		id: "organizations-update",
		cliCommand: "clearance orgs update <id> --name <name> --json",
		apiPath: operationApiPath(ORGANIZATION_OPERATIONS.update),
		consoleRoute: "organizations",
	},
	{
		id: "organizations-archive",
		cliCommand: "clearance orgs archive <id> --yes --json",
		apiPath: operationApiPath(ORGANIZATION_OPERATIONS.archive),
		consoleRoute: "organizations",
	},
	{
		id: "members",
		cliCommand: "clearance orgs members list --org <id> --json",
		apiPath: operationApiPath(MEMBER_OPERATIONS.list),
		consoleRoute: "members",
	},
	{
		id: "members-add",
		cliCommand: "clearance orgs members add --org <id> --user <id> --role member --json",
		apiPath: operationApiPath(MEMBER_OPERATIONS.add),
		consoleRoute: "members",
	},
	{
		id: "members-update",
		cliCommand:
			"clearance orgs members update --org <id> --member <id> --role <role> --json",
		apiPath: operationApiPath(MEMBER_OPERATIONS.update),
		consoleRoute: "members",
	},
	{
		id: "members-remove",
		cliCommand: "clearance orgs members remove --org <id> --member <id> --yes --json",
		apiPath: operationApiPath(MEMBER_OPERATIONS.remove),
		consoleRoute: "members",
	},
	{
		id: "sessions",
		cliCommand: "clearance sessions list --json",
		apiPath: operationApiPath(SESSION_OPERATIONS.list),
		consoleRoute: "sessions",
	},
	{
		id: "sessions-revoke",
		cliCommand: "clearance sessions revoke <id> --yes --json",
		apiPath: operationApiPath(SESSION_OPERATIONS.revoke),
		consoleRoute: "sessions",
	},
	{
		id: "environments",
		cliCommand: "clearance env list --json",
		apiPath: operationApiPath(ENVIRONMENT_OPERATIONS.list),
		consoleRoute: "settings",
	},
	{
		id: "environments-inspect",
		cliCommand: "clearance env inspect --json",
		apiPath: operationApiPath(ENVIRONMENT_OPERATIONS.inspect),
		consoleRoute: "settings",
	},
	{
		id: "environments-promote",
		cliCommand: "clearance env promote --to <id> --json",
		apiPath: operationApiPath(ENVIRONMENT_OPERATIONS.promote),
		consoleRoute: "settings",
	},
	{
		id: "events",
		cliCommand: "clearance events list --json",
		apiPath: operationApiPath(EVENT_OPERATIONS.list),
		consoleRoute: "events",
	},
	{
		id: "events-export",
		cliCommand: "clearance events export --output <path> --format json --json",
		apiPath: operationApiPath(EVENT_OPERATIONS.export),
		consoleRoute: "events",
	},
	{
		id: "events-replay",
		cliCommand: "clearance events replay <traceId> --json",
		apiPath: operationApiPath(EVENT_OPERATIONS.replay),
		consoleRoute: "events",
	},
	{
		id: "settings",
		cliCommand: "clearance doctor --json",
		apiPath: operationApiPath(SYSTEM_OPERATIONS.doctor),
		consoleRoute: "settings",
	},
	{
		id: "readiness",
		cliCommand: "clearance readiness report --org <id> --json",
		apiPath: operationApiPath(READINESS_OPERATIONS.report),
		consoleRoute: "readiness",
	},
	{
		id: ROLE_OPERATIONS.list.id,
		cliCommand: "clearance roles list --json",
		apiPath: operationApiPath(ROLE_OPERATIONS.list),
		consoleRoute: "roles",
	},
	{
		id: ROLE_OPERATIONS.validate.id,
		cliCommand: "clearance roles validate --name <name> --permission <resource:action> --json",
		apiPath: operationApiPath(ROLE_OPERATIONS.validate),
		consoleRoute: "roles",
	},
	{
		id: ROLE_OPERATIONS.create.id,
		cliCommand: "clearance roles create --name <name> --permission <resource:action> --json",
		apiPath: operationApiPath(ROLE_OPERATIONS.create),
		consoleRoute: "roles",
	},
	{
		id: ROLE_OPERATIONS.update.id,
		cliCommand: "clearance roles update <id> --name <name> --permission <resource:action> --json",
		apiPath: operationApiPath(ROLE_OPERATIONS.update),
		consoleRoute: "roles",
	},
	{
		id: AUTHORIZATION_OPERATIONS.effectiveInspect.id,
		cliCommand: "clearance orgs authorization effective --org <id> --subject-kind <principal|service_account> --subject <id> --json",
		apiPath: operationApiPath(AUTHORIZATION_OPERATIONS.effectiveInspect),
		consoleRoute: "authorization",
	},
	{
		id: AUTHORIZATION_OPERATIONS.assignmentsList.id,
		cliCommand: "clearance orgs authorization assignments list --org <id> --json",
		apiPath: operationApiPath(AUTHORIZATION_OPERATIONS.assignmentsList),
		consoleRoute: "authorization",
	},
	{
		id: AUTHORIZATION_OPERATIONS.assignmentsReplace.id,
		cliCommand: "clearance orgs authorization assignments replace --org <id> --subject-kind <principal|service_account> --subject <id> --role <roleId> --yes --json",
		apiPath: operationApiPath(AUTHORIZATION_OPERATIONS.assignmentsReplace),
		consoleRoute: "authorization",
	},
	{
		id: AUTHORIZATION_OPERATIONS.reconcile.id,
		cliCommand: "clearance orgs authorization reconcile --org <id> --yes --json",
		apiPath: operationApiPath(AUTHORIZATION_OPERATIONS.reconcile),
		consoleRoute: "authorization",
	},
	{
		id: SERVICE_ACCOUNT_OPERATIONS.list.id,
		cliCommand: "clearance orgs service-accounts list --org <id> --json",
		apiPath: operationApiPath(SERVICE_ACCOUNT_OPERATIONS.list),
		consoleRoute: "service-accounts",
	},
	{
		id: SERVICE_ACCOUNT_OPERATIONS.inspect.id,
		cliCommand: "clearance orgs service-accounts inspect <accountId> --org <id> --json",
		apiPath: operationApiPath(SERVICE_ACCOUNT_OPERATIONS.inspect),
		consoleRoute: "service-accounts",
	},
	{
		id: SERVICE_ACCOUNT_OPERATIONS.create.id,
		cliCommand: "clearance orgs service-accounts create --org <id> --name <name> --role <roleId> --json",
		apiPath: operationApiPath(SERVICE_ACCOUNT_OPERATIONS.create),
		consoleRoute: "service-accounts",
	},
	{
		id: SERVICE_ACCOUNT_OPERATIONS.disable.id,
		cliCommand: "clearance orgs service-accounts disable <accountId> --org <id> --yes --json",
		apiPath: operationApiPath(SERVICE_ACCOUNT_OPERATIONS.disable),
		consoleRoute: "service-accounts",
	},
	{
		id: SERVICE_ACCOUNT_OPERATIONS.enable.id,
		cliCommand: "clearance orgs service-accounts enable <accountId> --org <id> --json",
		apiPath: operationApiPath(SERVICE_ACCOUNT_OPERATIONS.enable),
		consoleRoute: "service-accounts",
	},
	{
		id: SERVICE_ACCOUNT_OPERATIONS.credentialCreate.id,
		cliCommand: "clearance orgs service-accounts credentials create <accountId> --org <id> --json",
		apiPath: operationApiPath(SERVICE_ACCOUNT_OPERATIONS.credentialCreate),
		consoleRoute: "service-accounts",
	},
	{
		id: SERVICE_ACCOUNT_OPERATIONS.credentialRotate.id,
		cliCommand: "clearance orgs service-accounts credentials rotate <accountId> <credentialId> --org <id> --yes --json",
		apiPath: operationApiPath(SERVICE_ACCOUNT_OPERATIONS.credentialRotate),
		consoleRoute: "service-accounts",
	},
	{
		id: SERVICE_ACCOUNT_OPERATIONS.credentialRevoke.id,
		cliCommand: "clearance orgs service-accounts credentials revoke <accountId> <credentialId> --org <id> --yes --json",
		apiPath: operationApiPath(SERVICE_ACCOUNT_OPERATIONS.credentialRevoke),
		consoleRoute: "service-accounts",
	},
	{
		id: PRODUCT_PRESENTATION_OPERATIONS.get.id,
		cliCommand: "clearance product presentation get --json",
		apiPath: operationApiPath(PRODUCT_PRESENTATION_OPERATIONS.get),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_PRESENTATION_OPERATIONS.plan.id,
		cliCommand: "clearance product presentation plan --file <path> --json",
		apiPath: operationApiPath(PRODUCT_PRESENTATION_OPERATIONS.plan),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_PRESENTATION_OPERATIONS.apply.id,
		cliCommand: "clearance product presentation apply --file <path> --expected-version <version> --yes --json",
		apiPath: operationApiPath(PRODUCT_PRESENTATION_OPERATIONS.apply),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_DOMAIN_OPERATIONS.list.id,
		cliCommand: "clearance product domains list --json",
		apiPath: operationApiPath(PRODUCT_DOMAIN_OPERATIONS.list),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_DOMAIN_OPERATIONS.create.id,
		cliCommand: "clearance product domains create --origin <https-hostname> --json",
		apiPath: operationApiPath(PRODUCT_DOMAIN_OPERATIONS.create),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_DOMAIN_OPERATIONS.reissue.id,
		cliCommand: "clearance product domains reissue --origin <https-hostname> --expected-version <version> --json",
		apiPath: operationApiPath(PRODUCT_DOMAIN_OPERATIONS.reissue),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_DOMAIN_OPERATIONS.verify.id,
		cliCommand: "clearance product domains verify --origin <https-hostname> --json",
		apiPath: operationApiPath(PRODUCT_DOMAIN_OPERATIONS.verify),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_DOMAIN_OPERATIONS.activate.id,
		cliCommand: "clearance product domains activate --origin <https-hostname> --expected-version <version> --yes --json",
		apiPath: operationApiPath(PRODUCT_DOMAIN_OPERATIONS.activate),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_DOMAIN_OPERATIONS.disable.id,
		cliCommand: "clearance product domains disable --origin <https-hostname> --expected-version <version> --yes --json",
		apiPath: operationApiPath(PRODUCT_DOMAIN_OPERATIONS.disable),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_SENDER_OPERATIONS.get.id,
		cliCommand: "clearance product sender get --json",
		apiPath: operationApiPath(PRODUCT_SENDER_OPERATIONS.get),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_SENDER_OPERATIONS.plan.id,
		cliCommand: "clearance product sender plan --file <path> --json",
		apiPath: operationApiPath(PRODUCT_SENDER_OPERATIONS.plan),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_SENDER_OPERATIONS.apply.id,
		cliCommand: "clearance product sender apply --file <path> --expected-version <version> --yes --json",
		apiPath: operationApiPath(PRODUCT_SENDER_OPERATIONS.apply),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_SENDER_OPERATIONS.readiness.id,
		cliCommand: "clearance product sender readiness --json",
		apiPath: operationApiPath(PRODUCT_SENDER_OPERATIONS.readiness),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_TEMPLATE_OPERATIONS.get.id,
		cliCommand: "clearance product templates get <kind> --json",
		apiPath: operationApiPath(PRODUCT_TEMPLATE_OPERATIONS.get),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_TEMPLATE_OPERATIONS.plan.id,
		cliCommand: "clearance product templates plan <kind> --file <path> --json",
		apiPath: operationApiPath(PRODUCT_TEMPLATE_OPERATIONS.plan),
		consoleRoute: "settings",
	},
	{
		id: PRODUCT_TEMPLATE_OPERATIONS.apply.id,
		cliCommand: "clearance product templates apply <kind> --file <path> --expected-version <version> --yes --json",
		apiPath: operationApiPath(PRODUCT_TEMPLATE_OPERATIONS.apply),
		consoleRoute: "settings",
	},
];

export function consoleRoutesFromContract(): string[] {
	return MANAGEMENT_SURFACES.map((s) => s.consoleRoute);
}
