export type DeepLinkResource = "user" | "organization" | "event" | "delivery" | "sso" | "scim";

export interface TuiDeepLinkTarget {
	readonly sectionId: "people" | "security" | "operations";
	readonly resource: DeepLinkResource;
	readonly id: string;
	readonly source: "tui-option" | "remote-command";
}

const RESOURCE_TARGETS: Readonly<Record<DeepLinkResource, TuiDeepLinkTarget["sectionId"]>> = Object.freeze({
	user: "people",
	organization: "people",
	event: "security",
	delivery: "security",
	sso: "security",
	scim: "security",
});

function validId(value: string | undefined): value is string {
	return Boolean(value && /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$/u.test(value));
}

export function parseTuiDeepLink(argv: readonly string[]): TuiDeepLinkTarget | undefined {
	if (argv.includes("--backup")) {
		throw new Error("--backup is not a supported TUI deep-link because Clearance has no read-only backup inspect operation; use the named backup workflows in Production Operations.");
	}
	const optionTargets = ([
		["--user", "user"],
		["--organization", "organization"],
		["--org", "organization"],
		["--event", "event"],
		["--delivery", "delivery"],
		["--sso", "sso"],
		["--scim", "scim"],
	] as const).flatMap(([flag, resource]) => argv.includes(flag) ? [{ flag, resource, index: argv.indexOf(flag) }] : []);
	const openIndex = argv.indexOf("--open");
	const hasRemote = argv.includes("--remote");
	const targetCount = Number(openIndex >= 0) + optionTargets.length + Number(hasRemote);
	if (targetCount > 1) throw new Error("Specify exactly one TUI deep-link target.");
	if (openIndex >= 0) {
		const resource = argv[openIndex + 1] as DeepLinkResource | undefined;
		const id = argv[openIndex + 2];
		if (!resource || !(resource in RESOURCE_TARGETS)) throw new Error("--open expects user, organization, event, delivery, sso, or scim.");
		if (!validId(id)) throw new Error("--open expects a safe resource identifier.");
		if (argv[openIndex + 3] !== undefined) throw new Error("--open expects exactly one resource and one identifier.");
		return Object.freeze({ sectionId: RESOURCE_TARGETS[resource], resource, id, source: "tui-option" });
	}
	for (const { flag, resource, index } of optionTargets) {
		const id = argv[index + 1];
		if (!validId(id)) throw new Error(`${flag} expects a safe resource identifier.`);
		return Object.freeze({ sectionId: RESOURCE_TARGETS[resource], resource, id, source: "tui-option" });
	}
	if (hasRemote) {
		const command = argv.filter((value) => value !== "--remote");
		const rootIndex = command.findIndex((value, index) => command[index + 1] === "inspect" && ["users", "orgs", "events", "delivery"].includes(value));
		const root = command[rootIndex];
		const verb = command[rootIndex + 1];
		const id = command[rootIndex + 2];
		const resource = root === "users" ? "user"
			: root === "orgs" ? "organization"
				: root === "events" ? "event"
					: root === "delivery" ? "delivery"
						: undefined;
		if (!resource || verb !== "inspect" || !validId(id)) throw new Error("--remote requires a supported '<resource> inspect <id>' command.");
		return Object.freeze({ sectionId: RESOURCE_TARGETS[resource], resource, id, source: "remote-command" });
	}
	return undefined;
}
