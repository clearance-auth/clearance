/**
 * Shared CLI ↔ API ↔ Console surface registry.
 * Every management surface that reaches GA must appear here with all three contracts.
 */
import {
	ENVIRONMENT_OPERATIONS,
	EVENT_OPERATIONS,
	MEMBER_OPERATIONS,
	ORGANIZATION_OPERATIONS,
	READINESS_OPERATIONS,
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
];

export function consoleRoutesFromContract(): string[] {
	return MANAGEMENT_SURFACES.map((s) => s.consoleRoute);
}
