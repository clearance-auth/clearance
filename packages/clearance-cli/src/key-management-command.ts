import type { Command } from "commander";

export type KeyManagementCommandAction = (this: Command) => void | Promise<void>;

/** Register the noninteractive key-management control surface. */
export function registerKeyManagementCommands(
	program: Command,
	action: KeyManagementCommandAction,
): Command {
	const keyManagement = program
		.command("key-management")
		.description("Operational key control");

	keyManagement
		.command("status")
		.description("Show scoped key-management status")
		.action(action);
	keyManagement
		.command("plan")
		.description("Create a key-management migration plan")
		.action(action);
	keyManagement
		.command("apply")
		.description("Preview a key-management migration; pass --yes to execute")
		.requiredOption("--expected-plan <plan-id>", "Plan ID returned by key-management plan")
		.action(action);

	return keyManagement;
}
