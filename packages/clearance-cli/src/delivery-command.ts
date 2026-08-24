import type { Command } from "commander";

export type DeliveryCommandAction = (this: Command) => void | Promise<void>;

function collect(value: string, previous: string[]): string[] {
	return [...previous, value];
}

/** Register the complete noninteractive delivery control surface. */
export function registerDeliveryCommands(
	program: Command,
	action: DeliveryCommandAction,
): Command {
	const delivery = program
		.command("delivery")
		.description("Inspect and control scoped transactional delivery");

	delivery
		.command("list")
		.description("List redacted delivery jobs in the active project and environment")
		.option("--limit <n>", "Page size (1-200)")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.option(
			"--state <state>",
			"Filter by state; repeat for multiple states",
			collect,
			[],
		)
		.option("--channel <channel>", "Delivery channel: email|webhook")
		.option("--kind <kind>", "Delivery event kind")
		.action(action);
	delivery
		.command("inspect")
		.description("Inspect one redacted delivery job in the active scope")
		.argument("<id>", "Delivery job id")
		.action(action);
	delivery
		.command("readiness")
		.description("Inspect delivery schema, worker, job, and key readiness")
		.option("--stale-after-ms <milliseconds>", "Worker staleness threshold (1000-86400000)")
		.action(action);
	delivery
		.command("quotas")
		.description("Inspect delivery quota usage for the active scope")
		.action(action);
	delivery
		.command("cancel")
		.description("Preview cancellation; pass --yes to execute")
		.argument("<id>", "Delivery job id")
		.action(action);
	delivery
		.command("retry")
		.description("Preview a manual retry; pass --yes to execute")
		.argument("<id>", "Delivery job id")
		.action(action);
	delivery
		.command("replay")
		.description("Preview terminal-job replay; pass --yes to execute")
		.argument("<id>", "Delivery job id")
		.option("--max-attempts <n>", "Attempt limit for the new delivery (1-100)")
		.action(action);

	const endpoints = delivery
		.command("endpoints")
		.description("Manage scoped webhook endpoints");
	endpoints
		.command("list")
		.description("List webhook endpoints in the active project and environment")
		.option("--limit <n>", "Page size (1-200)")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.option("--status <status>", "Filter by status; repeat for multiple statuses", collect, [])
		.option("--event-kind <kind>", "Webhook event kind")
		.action(action);
	endpoints
		.command("inspect")
		.description("Inspect one webhook endpoint in the active scope")
		.argument("<id>", "Webhook endpoint id")
		.action(action);
	endpoints
		.command("create")
		.description("Create a disabled webhook endpoint and issue its signing secret once")
		.requiredOption("--name <name>", "Endpoint name")
		.requiredOption("--url <url>", "HTTPS destination URL")
		.option("--event-kind <kind>", "Webhook event kind; repeat for multiple kinds", collect, [])
		.action(action);
	endpoints
		.command("update")
		.description("Update a webhook endpoint using optimistic concurrency")
		.argument("<id>", "Webhook endpoint id")
		.requiredOption("--expected-version <n>", "Current endpoint resource version")
		.option("--name <name>", "Endpoint name")
		.option("--url <url>", "HTTPS destination URL; changing it disables the endpoint")
		.option("--event-kind <kind>", "Webhook event kind; repeat for multiple kinds", collect, [])
		.option("--status <status>", "Endpoint status: active|disabled")
		.action(action);
	for (const [name, description] of [
		["rotate", "Preview signing-secret rotation; pass --yes to execute"],
		["delete", "Preview endpoint deletion and queued-delivery cancellation; pass --yes to execute"],
		["test", "Preview a signed test delivery; pass --yes to execute"],
	] as const) {
		endpoints
			.command(name)
			.description(description)
			.argument("<id>", "Webhook endpoint id")
			.requiredOption("--expected-version <n>", "Current endpoint resource version")
			.action(action);
	}

	return delivery;
}
