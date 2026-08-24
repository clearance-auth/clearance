import type { Command } from "commander";

export type ProductPresentationCommandAction = (
	this: Command,
) => void | Promise<void>;

/** Register the complete noninteractive product-presentation control surface. */
export function registerProductPresentationCommands(
	program: Command,
	action: ProductPresentationCommandAction,
): Command {
	const product = program
		.command("product")
		.description("Product presentation, domains, sender authority, and email templates");

	const presentation = product
		.command("presentation")
		.description("Versioned product labels and accent");
	presentation.command("get").action(action);
	presentation
		.command("plan")
		.requiredOption("--file <path>", "JSON presentation candidate")
		.action(action);
	presentation
		.command("apply")
		.requiredOption("--file <path>", "JSON presentation candidate")
		.requiredOption("--expected-version <version>", "Version returned by get or plan")
		.action(action);

	const domains = product
		.command("domains")
		.description("Custom authentication-domain verification lifecycle");
	domains.command("list").action(action);
	domains
		.command("create")
		.requiredOption("--origin <origin>", "Canonical origin such as https://auth.example.com")
		.action(action);
	domains
		.command("verify")
		.requiredOption("--origin <origin>", "Canonical origin")
		.action(action);
	domains
		.command("reissue")
		.requiredOption("--origin <origin>", "Canonical origin")
		.requiredOption("--expected-version <version>", "Version returned by list")
		.action(action);
	domains
		.command("activate")
		.requiredOption("--origin <origin>", "Canonical origin")
		.requiredOption("--expected-version <version>", "Version returned by list")
		.action(action);
	domains
		.command("disable")
		.requiredOption("--origin <origin>", "Canonical origin")
		.requiredOption("--expected-version <version>", "Version returned by list")
		.action(action);

	const sender = product
		.command("sender")
		.description("Versioned email sender authority");
	sender.command("get").action(action);
	sender.command("plan").requiredOption("--file <path>", "JSON sender candidate").action(action);
	sender.command("apply").requiredOption("--file <path>", "JSON sender candidate").requiredOption("--expected-version <version>", "Version returned by get or plan").action(action);
	sender
		.command("readiness")
		.option("--stale-after-ms <milliseconds>", "Worker freshness window")
		.action(action);

	const templates = product
		.command("templates")
		.description("Versioned plain-text email templates");
	templates
		.command("get")
		.argument("<kind>", "verification|password-reset|invitation|email-change")
		.action(action);
	templates
		.command("plan")
		.argument("<kind>", "verification|password-reset|invitation|email-change")
		.requiredOption("--file <path>", "JSON template candidate")
		.action(action);
	templates
		.command("apply")
		.argument("<kind>", "verification|password-reset|invitation|email-change")
		.requiredOption("--file <path>", "JSON template candidate")
		.requiredOption("--expected-version <version>", "Version returned by get or plan")
		.action(action);

	return product;
}
