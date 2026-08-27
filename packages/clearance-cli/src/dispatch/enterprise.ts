import {
	READINESS_OPERATIONS,
	SCIM_OPERATIONS,
	SSO_OPERATIONS,
} from "@clearance/management";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { callManagementOperation } from "../api-client.js";
import type { GlobalOpts } from "../output.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	managementCallOptions,
	requireConfirmation,
	requireRemoteMutation,
} from "./shared.js";

type EnterpriseCommandPath =
	| CliPathOf<typeof SSO_OPERATIONS>
	| CliPathOf<typeof SCIM_OPERATIONS>
	| CliPathOf<typeof READINESS_OPERATIONS>;

function requireLiveTestMode(
	global: Readonly<GlobalOpts>,
	code: string,
	label: string,
): void {
	if (global.dryRun) {
		throw error(
			code,
			`${label} cannot combine --live with --dry-run.`,
			"Remove --dry-run, review the live target, then pass --yes to confirm.",
		);
	}
	requireConfirmation(global, code, label);
}

export async function dispatchEnterpriseCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<EnterpriseCommandPath>): Promise<unknown> {
	const rawId = firstStringArgument(args);
	switch (path) {
		case SSO_OPERATIONS.create.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(
				session,
				"sso.create",
				body({
					organizationId: opts.org,
					provider: opts.provider,
					protocol: opts.protocol,
					issuer: opts.issuer,
					audience: opts.audience,
					domain: opts.domain,
					samlEntryPoint: opts.entryPoint,
					samlCertificate: opts.certificate
						? readFileSync(resolve(String(opts.certificate)), "utf8")
						: undefined,
				}) as Parameters<typeof callManagementOperation<"sso.create">>[2],
			);
		case SSO_OPERATIONS.configure.cliPath:
			return callManagementOperation(session, "sso.configure", body({
				id: rawId,
				issuer: opts.issuer,
				audience: opts.audience,
				domain: opts.domain,
				dryRun: Boolean(global.dryRun),
			}) as Parameters<typeof callManagementOperation<"sso.configure">>[2], managementCallOptions(global));
		case SSO_OPERATIONS.test.cliPath:
			if (opts.live && opts.fixture) {
				throw error("SSO_TEST_MODE_CONFLICT", "--live and --fixture are mutually exclusive.", "Use one SSO test mode.");
			}
			if (opts.live) requireLiveTestMode(global, "SSO_LIVE_CONFIRM_REQUIRED", "Live SSO conformance");
			else requireRemoteMutation(global, path);
			return callManagementOperation(session, "sso.test", body({
				id: rawId,
				fixture: opts.fixture,
				live: opts.live,
			}) as Parameters<typeof callManagementOperation<"sso.test">>[2], managementCallOptions(global));
		case SSO_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "sso.list", body({
				organizationId: opts.org,
			}));
		case SSO_OPERATIONS.setupLink.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "sso.setupLink.create", {
				organizationId: String(opts.org),
			});
		case SSO_OPERATIONS.rotate.cliPath:
			requireConfirmation(global, "SSO_CONFIRM_REQUIRED", "SSO credential rotation");
			return callManagementOperation(session, "sso.rotate", {
				id: rawId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case SSO_OPERATIONS.disable.cliPath:
			requireConfirmation(global, "SSO_CONFIRM_REQUIRED", "SSO disable");
			return callManagementOperation(session, "sso.disable", {
				id: rawId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case SCIM_OPERATIONS.create.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "scim.create", body({
				organizationId: opts.org,
				provider: opts.provider,
				endpoint: opts.endpoint,
			}) as Parameters<typeof callManagementOperation<"scim.create">>[2]);
		case SCIM_OPERATIONS.test.cliPath:
			if (opts.live && opts.fixture) {
				throw error("SCIM_TEST_MODE_CONFLICT", "--live and --fixture are mutually exclusive.", "Use one SCIM test mode.");
			}
			if (opts.scenario !== undefined && opts.scenario !== "users" && opts.scenario !== "group-lifecycle") {
				throw error("SCIM_SCENARIO_INVALID", "--scenario must be users or group-lifecycle.", "Use --scenario users|group-lifecycle.");
			}
			if (opts.live && opts.scenario === "group-lifecycle") {
				throw error("SCIM_SCENARIO_LIVE_CONFLICT", "--scenario group-lifecycle cannot use --live.", "Remove --live to exercise the bundled runtime.");
			}
			if (opts.live) requireLiveTestMode(global, "SCIM_LIVE_CONFIRM_REQUIRED", "Live SCIM conformance");
			return callManagementOperation(
				session,
				"scim.test",
				(opts.live
					? { id: rawId, live: true, dryRun: false }
					: body({
						id: rawId,
						fixture: opts.fixture,
						live: false,
						dryRun: global.dryRun || !opts.apply,
						scenario: opts.scenario ?? "users",
					})) as Parameters<typeof callManagementOperation<"scim.test">>[2],
				managementCallOptions(global),
			);
		case SCIM_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "scim.list", body({
				organizationId: opts.org,
			}));
		case SCIM_OPERATIONS.setupLink.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "scim.setupLink.create", {
				organizationId: String(opts.org),
			});
		case SCIM_OPERATIONS.rotate.cliPath:
			requireConfirmation(global, "SCIM_CONFIRM_REQUIRED", "SCIM credential rotation");
			return callManagementOperation(session, "scim.rotate", {
				id: rawId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case SCIM_OPERATIONS.disable.cliPath:
			requireConfirmation(global, "SCIM_DISABLE_CONFIRM_REQUIRED", "SCIM disable");
			return callManagementOperation(session, "scim.disable", {
				id: rawId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case SCIM_OPERATIONS.replay.cliPath:
			requireConfirmation(global, "SCIM_REPLAY_CONFIRM_REQUIRED", "SCIM replay");
			return callManagementOperation(session, "scim.replay", {
				traceId: rawId,
				dryRun: Boolean(global.dryRun),
			}, managementCallOptions(global));
		case READINESS_OPERATIONS.check.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "readiness.check", {
				organizationId: String(opts.org),
			});
		case READINESS_OPERATIONS.report.cliPath:
			return callManagementOperation(session, "readiness.report", {
				organizationId: String(opts.org),
			});
	}
}
