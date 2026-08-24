import {
	PRODUCT_DOMAIN_OPERATIONS,
	PRODUCT_PRESENTATION_OPERATIONS,
	PRODUCT_SENDER_OPERATIONS,
	PRODUCT_TEMPLATE_OPERATIONS,
	type ProductEmailTemplateKind,
} from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import {
	type DispatchInput,
	body,
	error,
	firstStringArgument,
	localFile,
	managementCallOptions,
} from "./shared.js";

type ProductCommandPath =
	| (typeof PRODUCT_PRESENTATION_OPERATIONS)[keyof typeof PRODUCT_PRESENTATION_OPERATIONS]["cliPath"]
	| (typeof PRODUCT_DOMAIN_OPERATIONS)[keyof typeof PRODUCT_DOMAIN_OPERATIONS]["cliPath"]
	| (typeof PRODUCT_SENDER_OPERATIONS)[keyof typeof PRODUCT_SENDER_OPERATIONS]["cliPath"]
	| (typeof PRODUCT_TEMPLATE_OPERATIONS)[keyof typeof PRODUCT_TEMPLATE_OPERATIONS]["cliPath"];

function jsonFile(
	value: unknown,
	label: string,
	allowed: readonly string[],
): Record<string, unknown> {
	if (typeof value !== "string" || value.trim() === "") {
		throw error(
			"PRODUCT_FILE_REQUIRED",
			`${label} JSON file is required.`,
			"Pass --file <path>.",
		);
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(
			localFile(value, "PRODUCT_FILE_UNREADABLE", `${label} file`),
		);
	} catch (cause) {
		if (
			typeof cause === "object" &&
			cause !== null &&
			"code" in cause &&
			cause.code === "PRODUCT_FILE_UNREADABLE"
		) {
			throw cause;
		}
		throw error(
			"PRODUCT_FILE_INVALID",
			`${label} file is not valid JSON.`,
			"Provide one JSON object.",
		);
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw error(
			"PRODUCT_FILE_INVALID",
			`${label} file must contain one JSON object.`,
			"Provide one JSON object.",
		);
	}
	const record = parsed as Record<string, unknown>;
	const unexpected = Object.keys(record).filter((key) => !allowed.includes(key));
	if (unexpected.length > 0) {
		throw error(
			"PRODUCT_FILE_INVALID",
			`${label} file contains unexpected fields: ${unexpected.sort().join(", ")}.`,
			`Use only: ${allowed.join(", ")}.`,
		);
	}
	for (const key of allowed) {
		if (key === "logoUrl" && (record[key] === undefined || record[key] === null)) continue;
		if (typeof record[key] !== "string") {
			throw error(
				"PRODUCT_FILE_INVALID",
				`${label} field ${key} must be a string.`,
				`Provide ${key} as a JSON string.`,
			);
		}
	}
	return record;
}

function expectedVersion(value: unknown): number {
	const parsed = typeof value === "string" && /^(0|[1-9]\d*)$/.test(value)
		? Number(value)
		: Number.NaN;
	if (!Number.isSafeInteger(parsed)) {
		throw error(
			"PRODUCT_VERSION_INVALID",
			"--expected-version must be a canonical non-negative integer.",
			"Use the expectedVersion returned by get or plan.",
		);
	}
	return parsed;
}

function origin(value: unknown): string {
	if (typeof value !== "string" || value.trim() === "") {
		throw error(
			"PRODUCT_DOMAIN_ORIGIN_REQUIRED",
			"--origin is required.",
			"Pass one canonical HTTPS origin.",
		);
	}
	return value;
}

function kind(value: unknown): ProductEmailTemplateKind {
	if (value === "verification" || value === "password-reset" || value === "invitation" || value === "email-change") {
		return value;
	}
	throw error(
		"PRODUCT_TEMPLATE_KIND_INVALID",
		"Template kind must be verification, password-reset, invitation, or email-change.",
		"Use one allowlisted email template kind.",
	);
}

function staleAfterMs(value: unknown): number | undefined {
	if (value === undefined) return undefined;
	const parsed =
		typeof value === "string" && /^[1-9]\d*$/.test(value)
			? Number(value)
			: Number.NaN;
	if (!Number.isSafeInteger(parsed)) {
		throw error(
			"PRODUCT_SENDER_WINDOW_INVALID",
			"--stale-after-ms must be a positive integer.",
			"Pass a worker freshness window in milliseconds.",
		);
	}
	return parsed;
}

export async function dispatchProductPresentationCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<ProductCommandPath>): Promise<unknown> {
	switch (path) {
		case PRODUCT_PRESENTATION_OPERATIONS.get.cliPath:
			return callManagementOperation(session, "product_presentation.get", {});
		case PRODUCT_PRESENTATION_OPERATIONS.plan.cliPath: {
			const candidate = jsonFile(opts.file, "Presentation", [
				"productLabel",
				"homeLabel",
				"accentColor",
				"logoUrl",
			]);
			return callManagementOperation(
				session,
				"product_presentation.plan",
				candidate as {
					productLabel: string;
					homeLabel: string;
					accentColor: string;
					logoUrl?: string | null;
				},
			);
		}
		case PRODUCT_PRESENTATION_OPERATIONS.apply.cliPath: {
			const candidate = jsonFile(opts.file, "Presentation", [
				"productLabel",
				"homeLabel",
				"accentColor",
				"logoUrl",
			]);
			return callManagementOperation(
				session,
				"product_presentation.apply",
				{
					...(candidate as {
						productLabel: string;
						homeLabel: string;
						accentColor: string;
						logoUrl?: string | null;
					}),
					expectedVersion: expectedVersion(opts.expectedVersion),
					dryRun: global.dryRun || !global.yes,
				},
				managementCallOptions(global),
			);
		}
		case PRODUCT_DOMAIN_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "product_domains.list", {});
		case PRODUCT_DOMAIN_OPERATIONS.create.cliPath:
			return callManagementOperation(session, "product_domains.create", {
				origin: origin(opts.origin),
			});
		case PRODUCT_DOMAIN_OPERATIONS.verify.cliPath:
			return callManagementOperation(session, "product_domains.verify", {
				origin: origin(opts.origin),
			});
		case PRODUCT_DOMAIN_OPERATIONS.reissue.cliPath:
			return callManagementOperation(session, "product_domains.reissue", {
				origin: origin(opts.origin),
				expectedVersion: expectedVersion(opts.expectedVersion),
			});
		case PRODUCT_DOMAIN_OPERATIONS.activate.cliPath:
			return callManagementOperation(
				session,
				"product_domains.activate",
				{
					origin: origin(opts.origin),
					expectedVersion: expectedVersion(opts.expectedVersion),
					dryRun: global.dryRun || !global.yes,
				},
				managementCallOptions(global),
			);
		case PRODUCT_DOMAIN_OPERATIONS.disable.cliPath:
			return callManagementOperation(
				session,
				"product_domains.disable",
				{
					origin: origin(opts.origin),
					expectedVersion: expectedVersion(opts.expectedVersion),
					dryRun: global.dryRun || !global.yes,
				},
				managementCallOptions(global),
			);
		case PRODUCT_SENDER_OPERATIONS.readiness.cliPath:
			return callManagementOperation(
				session,
				"product_sender.readiness",
				body({ staleAfterMs: staleAfterMs(opts.staleAfterMs) }),
			);
		case PRODUCT_SENDER_OPERATIONS.get.cliPath:
			return callManagementOperation(session, "product_sender.get", {});
		case PRODUCT_SENDER_OPERATIONS.plan.cliPath: { const candidate = jsonFile(opts.file, "Sender", ["displayName", "address"]); return callManagementOperation(session, "product_sender.plan", candidate as { displayName: string; address: string }); }
		case PRODUCT_SENDER_OPERATIONS.apply.cliPath: { const candidate = jsonFile(opts.file, "Sender", ["displayName", "address"]); return callManagementOperation(session, "product_sender.apply", { ...(candidate as { displayName: string; address: string }), expectedVersion: expectedVersion(opts.expectedVersion), dryRun: global.dryRun || !global.yes }, managementCallOptions(global)); }
		case PRODUCT_TEMPLATE_OPERATIONS.get.cliPath:
			return callManagementOperation(session, "product_templates.get", {
				kind: kind(firstStringArgument(args)),
			});
		case PRODUCT_TEMPLATE_OPERATIONS.plan.cliPath: {
			const candidate = jsonFile(opts.file, "Template", ["subject", "plainText", "html"]);
			return callManagementOperation(session, "product_templates.plan", {
				kind: kind(firstStringArgument(args)),
				subject: candidate.subject as string,
				plainText: candidate.plainText as string, html: candidate.html as string,
			});
		}
		case PRODUCT_TEMPLATE_OPERATIONS.apply.cliPath: {
			const candidate = jsonFile(opts.file, "Template", ["subject", "plainText", "html"]);
			return callManagementOperation(
				session,
				"product_templates.apply",
				{
					kind: kind(firstStringArgument(args)),
					subject: candidate.subject as string,
					plainText: candidate.plainText as string, html: candidate.html as string,
					expectedVersion: expectedVersion(opts.expectedVersion),
					dryRun: global.dryRun || !global.yes,
				},
				managementCallOptions(global),
			);
		}
	}
}
