import type { Command } from "commander";

export type AuthenticationPolicyCommandAction = (
	this: Command,
) => void | Promise<void>;

/** Register the complete revisioned authentication-policy control surface. */
export function registerAuthenticationPolicyCommands(
	program: Command,
	action: AuthenticationPolicyCommandAction,
): Command {
	const policy = program
		.command("auth-policy")
		.description("Inspect and control managed authentication policy");

	policy
		.command("get")
		.description("Get the exact environment policy and optional organization override")
		.option("--organization-id <id>", "Resolve one organization override and effective policy")
		.action(action);

	policy
		.command("plan")
		.description("Validate and preview a revisioned policy replacement")
		.option("--organization-id <id>", "Target a sparse organization override")
		.option("--file <path>", "JSON policy or sparse organization override")
		.option("--delete-override", "Delete the targeted organization override", false)
		.action(action);

	policy
		.command("apply")
		.description("Preview a revisioned policy replacement; pass --yes to execute")
		.requiredOption("--expected-revision <revision>", "Revision returned by get or plan")
		.option("--organization-id <id>", "Target a sparse organization override")
		.option("--file <path>", "JSON policy or sparse organization override")
		.option("--delete-override", "Delete the targeted organization override", false)
		.action(action);

	policy
		.command("unlock")
		.description("Preview clearing one user's lockout state; pass --yes to execute")
		.argument("<user-id>", "Exact user id in the active project and environment")
		.option("--kind <kind>", "Lockout authority: password|factor|all", "all")
		.action(action);

	return policy;
}
