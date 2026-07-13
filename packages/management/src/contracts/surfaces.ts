/**
 * Shared CLI ↔ API ↔ Console surface registry.
 * Every management surface that reaches GA must appear here with all three contracts.
 */
export interface ManagementSurface {
	id: string;
	cliCommand: string;
	apiPath: string;
	/** Route key in packages/clearance-console/public/app.js `routes` */
	consoleRoute: string;
}

export const MANAGEMENT_SURFACES: ManagementSurface[] = [
	{
		id: "overview",
		cliCommand: "clearance overview --json",
		apiPath: "GET /v1/overview",
		consoleRoute: "overview",
	},
	{
		id: "users",
		cliCommand: "clearance users list --json",
		apiPath: "GET /v1/users",
		consoleRoute: "users",
	},
	{
		id: "users-export",
		cliCommand: "clearance users export --output <path> --format json --json",
		apiPath: "POST /v1/users/export",
		consoleRoute: "users",
	},
	{
		id: "organizations",
		cliCommand: "clearance orgs list --json",
		apiPath: "GET /v1/organizations",
		consoleRoute: "organizations",
	},
	{
		id: "organizations-update",
		cliCommand: "clearance orgs update <id> --name <name> --json",
		apiPath: "PATCH /v1/organizations/:id",
		consoleRoute: "organizations",
	},
	{
		id: "organizations-archive",
		cliCommand: "clearance orgs archive <id> --yes --json",
		apiPath: "POST /v1/organizations/:id/archive",
		consoleRoute: "organizations",
	},
	{
		id: "members",
		cliCommand: "clearance orgs members list --org <id> --json",
		apiPath: "GET /v1/organizations/:id/members",
		consoleRoute: "members",
	},
	{
		id: "members-add",
		cliCommand: "clearance orgs members add --org <id> --user <id> --role member --json",
		apiPath: "POST /v1/organizations/:id/members",
		consoleRoute: "members",
	},
	{
		id: "members-update",
		cliCommand:
			"clearance orgs members update --org <id> --member <id> --role <role> --json",
		apiPath: "PATCH /v1/organizations/:id/members/:memberId",
		consoleRoute: "members",
	},
	{
		id: "members-remove",
		cliCommand: "clearance orgs members remove --org <id> --member <id> --yes --json",
		apiPath: "DELETE /v1/organizations/:id/members/:memberId",
		consoleRoute: "members",
	},
	{
		id: "sessions",
		cliCommand: "clearance sessions list --json",
		apiPath: "GET /v1/sessions",
		consoleRoute: "sessions",
	},
	{
		id: "sessions-revoke",
		cliCommand: "clearance sessions revoke <id> --yes --json",
		apiPath: "POST /v1/sessions/:id/revoke",
		consoleRoute: "sessions",
	},
	{
		id: "environments",
		cliCommand: "clearance env list --json",
		apiPath: "GET /v1/environments",
		consoleRoute: "settings",
	},
	{
		id: "environments-inspect",
		cliCommand: "clearance env inspect --json",
		apiPath: "GET /v1/environments/:id",
		consoleRoute: "settings",
	},
	{
		id: "environments-promote",
		cliCommand: "clearance env promote --to <id> --json",
		apiPath: "POST /v1/environments/promote",
		consoleRoute: "settings",
	},
	{
		id: "events",
		cliCommand: "clearance events list --json",
		apiPath: "GET /v1/events",
		consoleRoute: "events",
	},
	{
		id: "events-export",
		cliCommand: "clearance events export --output <path> --format json --json",
		apiPath: "POST /v1/events/export",
		consoleRoute: "events",
	},
	{
		id: "events-replay",
		cliCommand: "clearance events replay <traceId> --json",
		apiPath: "POST /v1/events/replay",
		consoleRoute: "events",
	},
	{
		id: "settings",
		cliCommand: "clearance doctor --json",
		apiPath: "GET /v1/doctor",
		consoleRoute: "settings",
	},
	{
		id: "readiness",
		cliCommand: "clearance readiness check --org <id> --json",
		apiPath: "GET /v1/readiness/:orgId",
		consoleRoute: "readiness",
	},
];

export function consoleRoutesFromContract(): string[] {
	return MANAGEMENT_SURFACES.map((s) => s.consoleRoute);
}
