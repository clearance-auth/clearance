import { MANAGEMENT_OPERATIONS } from "@clearance/management";
import type { GlobalOpts } from "../output.js";
import type { ActionRisk, WorkflowAction, WorkflowArea, WorkflowField, WorkflowInvocation } from "./types.js";

export const WORKFLOW_AREAS: readonly WorkflowArea[] = [
	"Overview",
	"Users & organizations",
	"Events & delivery",
	"Configuration & enterprise",
];

function quote(value: string): string {
	if (/^[A-Za-z0-9_./:@,+-]+$/.test(value)) return value;
	return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function action(
	id: string,
	area: WorkflowArea,
	label: string,
	description: string,
	path: string,
	expectedRisk: ActionRisk,
	fields: readonly WorkflowField[] = [],
): WorkflowAction {
	const operation = MANAGEMENT_OPERATIONS.find((candidate) => candidate.cliPath === path);
	if (!operation) throw new Error(`TUI workflow has no canonical management operation: ${path}`);
	const risk: ActionRisk = !operation.mutation
		? "read"
		: operation.confirmation === "none" ? "mutation" : "destructive";
	if (risk !== expectedRisk) {
		throw new Error(`TUI workflow safety drift for ${path}: expected ${expectedRisk}, canonical ${risk}`);
	}
	return {
		id,
		area,
		label,
		description,
		path,
		risk,
		mutation: operation.mutation,
		confirmation: operation.confirmation,
		supportsDryRun: operation.supportsDryRun,
		fields,
		invocation(values, inheritedGlobal = {}): WorkflowInvocation {
			const args: string[] = [];
			const opts: Record<string, string | boolean> = {};
			const commandParts = ["clearance"];
			const global: GlobalOpts = { ...inheritedGlobal };
			if (operation.mutation && operation.confirmation !== "none" && !global.dryRun) global.yes = true;
			for (const [flag, value] of [
				["--profile", global.profile],
				["--api-url", global.apiUrl],
			] as const) {
				if (value) commandParts.push(flag, quote(value));
			}
			if (global.dryRun) commandParts.push("--dry-run");
			if (global.yes) commandParts.push("--yes");
			commandParts.push(...path.split(" "));
			for (const field of fields) {
				const value = values[field.key]?.trim();
				if (!value) continue;
				if (field.argument) {
					args.push(value);
					commandParts.push(quote(value));
				} else {
					const flag = field.flag ?? `--${field.key.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)}`;
					opts[field.key] = value;
					commandParts.push(flag, quote(value));
				}
			}
			return {
				path,
				args,
				opts,
				global,
				command: commandParts.join(" "),
			};
		},
	};
}

const arg = (key: string, label: string, placeholder: string, required = true): WorkflowField => ({
	key, label, placeholder, required, argument: true,
});
const opt = (key: string, label: string, placeholder: string, required = false, flag?: string): WorkflowField => ({
	key, label, placeholder, required, flag,
});

export const WORKFLOW_ACTIONS: readonly WorkflowAction[] = [
	action("overview", "Overview", "Environment overview", "Dashboard stats and current environment posture.", "overview", "read"),
action("doctor", "Overview", "Installation health", "Verify installation and configuration health.", "doctor", "mutation"),
	action("readiness-check", "Overview", "Run readiness checks", "Exercise enterprise readiness checks for an organization.", "readiness check", "mutation", [opt("org", "Organization ID", "org_…", true)]),
	action("readiness-report", "Overview", "Readiness report", "Inspect the last enterprise readiness result.", "readiness report", "read", [opt("org", "Organization ID", "org_…", true)]),

	action("users-list", "Users & organizations", "List users", "Browse principals with optional bounded pagination.", "users list", "read", [opt("limit", "Page size", "50"), opt("cursor", "Cursor", "opaque cursor")]),
	action("users-inspect", "Users & organizations", "Inspect user", "Inspect one principal.", "users inspect", "read", [arg("id", "User ID", "usr_…")]),
	action("users-create", "Users & organizations", "Create user", "Create a principal and issue its setup flow.", "users create", "mutation", [opt("email", "Email", "person@example.com", true), opt("name", "Display name", "Ada Lovelace", true)]),
	action("users-update", "Users & organizations", "Update user", "Change a principal's profile or status.", "users update", "mutation", [arg("id", "User ID", "usr_…"), opt("name", "Display name", "optional"), opt("email", "Email", "optional"), opt("status", "Status", "active or disabled")]),
	action("users-disable", "Users & organizations", "Disable user", "Disable sign-in for a principal.", "users disable", "mutation", [arg("id", "User ID", "usr_…")]),
	action("users-delete", "Users & organizations", "Delete user", "Permanently delete a principal.", "users delete", "destructive", [arg("id", "User ID", "usr_…")]),
	action("orgs-list", "Users & organizations", "List organizations", "Browse organizations with optional pagination.", "orgs list", "read", [opt("limit", "Page size", "50"), opt("cursor", "Cursor", "opaque cursor")]),
	action("orgs-inspect", "Users & organizations", "Inspect organization", "Inspect organization settings and state.", "orgs inspect", "read", [arg("id", "Organization ID", "org_…")]),
	action("orgs-create", "Users & organizations", "Create organization", "Create an organization with an optional slug.", "orgs create", "mutation", [opt("name", "Name", "Acme", true), opt("slug", "Slug", "acme")]),
	action("orgs-archive", "Users & organizations", "Archive organization", "Archive an organization and preserve its history.", "orgs archive", "destructive", [arg("id", "Organization ID", "org_…")]),
	action("members-list", "Users & organizations", "List organization members", "Inspect an organization's membership.", "orgs members list", "read", [opt("org", "Organization ID", "org_…", true)]),
	action("members-add", "Users & organizations", "Add organization member", "Add a principal with a role.", "orgs members add", "mutation", [opt("org", "Organization ID", "org_…", true), opt("user", "User ID", "usr_…", true), opt("role", "Role", "member")]),
	action("members-remove", "Users & organizations", "Remove organization member", "Remove a principal's active membership.", "orgs members remove", "destructive", [opt("org", "Organization ID", "org_…", true), opt("user", "User ID", "usr_…", true)]),

	action("events-list", "Events & delivery", "List audit events", "Browse the scoped audit trail.", "events list", "read", [opt("limit", "Limit", "50"), opt("action", "Action filter", "optional"), opt("org", "Organization ID", "optional")]),
	action("events-inspect", "Events & delivery", "Inspect audit event", "Inspect an event or diagnostic trace.", "events inspect", "read", [arg("id", "Event or trace ID", "evt_…")]),
action("events-replay", "Events & delivery", "Replay diagnostic trace", "Re-record a SCIM diagnostic trace.", "events replay", "destructive", [arg("id", "Trace ID", "trace_…")]),
	action("delivery-list", "Events & delivery", "List deliveries", "Browse email and webhook delivery attempts.", "delivery list", "read", [opt("limit", "Limit", "50"), opt("state", "State", "optional"), opt("channel", "Channel", "email or webhook")]),
	action("delivery-readiness", "Events & delivery", "Delivery readiness", "Inspect webhook delivery worker readiness.", "delivery readiness", "read"),
	action("delivery-quotas", "Events & delivery", "Delivery quotas", "Inspect delivery quotas and current usage.", "delivery quotas", "read"),
action("delivery-retry", "Events & delivery", "Retry delivery", "Retry one failed delivery.", "delivery retry", "destructive", [arg("id", "Delivery ID", "del_…")]),
	action("delivery-cancel", "Events & delivery", "Cancel delivery", "Cancel one pending delivery.", "delivery cancel", "destructive", [arg("id", "Delivery ID", "del_…")]),
	action("endpoints-list", "Events & delivery", "List webhook endpoints", "Browse configured webhook endpoints.", "delivery endpoints list", "read"),

	action("config-get", "Configuration & enterprise", "Get configuration", "Inspect all configuration or one key.", "config get", "read", [arg("key", "Configuration key", "leave blank for all", false)]),
	action("config-validate", "Configuration & enterprise", "Validate configuration", "Validate current or file-backed configuration.", "config validate", "read", [opt("file", "Candidate JSON file", "optional path")]),
	action("config-diff", "Configuration & enterprise", "Diff configuration", "Compare a candidate JSON file to current configuration.", "config diff", "read", [opt("file", "Candidate JSON file", "./config.json", true)]),
	action("config-set", "Configuration & enterprise", "Set configuration value", "Set one configuration key.", "config set", "mutation", [arg("key", "Configuration key", "auth.session.ttl"), arg("value", "Value", "3600")]),
	action("sso-list", "Configuration & enterprise", "List SSO connections", "Browse enterprise SSO connections.", "sso list", "read", [opt("org", "Organization ID", "optional")]),
action("sso-test", "Configuration & enterprise", "Test SSO connection", "Run bundled conformance checks against a connection.", "sso test", "destructive", [arg("id", "SSO connection ID", "sso_…"), opt("fixture", "Fixture", "ok")]),
	action("sso-setup-link", "Configuration & enterprise", "Create SSO setup link", "Issue an organization-scoped setup link.", "sso setup-link", "mutation", [opt("org", "Organization ID", "org_…", true)]),
	action("scim-list", "Configuration & enterprise", "List SCIM connections", "Browse enterprise directory connections.", "scim list", "read", [opt("org", "Organization ID", "optional")]),
action("scim-test", "Configuration & enterprise", "Test SCIM connection", "Run a dry-run SCIM conformance scenario.", "scim test", "destructive", [arg("id", "SCIM connection ID", "scim_…"), opt("fixture", "Fixture", "ok"), opt("scenario", "Scenario", "users")]),
action("scim-replay", "Configuration & enterprise", "Replay SCIM trace", "Re-record a SCIM diagnostic trace.", "scim replay", "destructive", [arg("traceId", "Trace ID", "trace_…")]),
];

export function actionsFor(area: WorkflowArea, search = ""): readonly WorkflowAction[] {
	const query = search.trim().toLowerCase();
	return WORKFLOW_ACTIONS.filter((candidate) => {
		if (candidate.area !== area) return false;
		if (!query) return true;
		return `${candidate.label} ${candidate.description} ${candidate.path}`.toLowerCase().includes(query);
	});
}
