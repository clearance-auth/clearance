import {
	READINESS_OPERATIONS,
	resolveOperationPath,
	SCIM_OPERATIONS,
	SSO_OPERATIONS,
} from "@clearance/management";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { requestManagementApi } from "../api-client.js";
import type { GlobalOpts } from "../output.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	previewConfirmation,
	query,
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
			return requestManagementApi(session, {
				method: SSO_OPERATIONS.create.http.method,
				path: SSO_OPERATIONS.create.http.path,
				body: body({
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
				}),
			});
		case SSO_OPERATIONS.configure.cliPath:
			return requestManagementApi(session, {
				method: SSO_OPERATIONS.configure.http.method,
				path: resolveOperationPath(SSO_OPERATIONS.configure, { id: rawId }),
				body: body({ issuer: opts.issuer, audience: opts.audience, domain: opts.domain, dryRun: global.dryRun }),
			});
		case SSO_OPERATIONS.test.cliPath:
			if (opts.live && opts.fixture) {
				throw error("SSO_TEST_MODE_CONFLICT", "--live and --fixture are mutually exclusive.", "Use one SSO test mode.");
			}
			if (opts.live) requireLiveTestMode(global, "SSO_LIVE_CONFIRM_REQUIRED", "Live SSO conformance");
			else requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: SSO_OPERATIONS.test.http.method,
				path: resolveOperationPath(SSO_OPERATIONS.test, { id: rawId }),
				body: body({ fixture: opts.fixture, live: opts.live }),
			});
		case SSO_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: SSO_OPERATIONS.list.http.method,
				path: query(SSO_OPERATIONS.list.http.path, { organizationId: opts.org }),
			});
		case SSO_OPERATIONS.setupLink.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: SSO_OPERATIONS.setupLink.http.method,
				path: SSO_OPERATIONS.setupLink.http.path,
				body: { organizationId: opts.org },
			});
		case SSO_OPERATIONS.rotate.cliPath:
			requireConfirmation(global, "SSO_CONFIRM_REQUIRED", "SSO credential rotation");
			return requestManagementApi(session, {
				method: SSO_OPERATIONS.rotate.http.method,
				path: resolveOperationPath(SSO_OPERATIONS.rotate, { id: rawId }),
				body: { dryRun: global.dryRun },
			});
		case SSO_OPERATIONS.disable.cliPath:
			requireConfirmation(global, "SSO_CONFIRM_REQUIRED", "SSO disable");
			return requestManagementApi(session, {
				method: SSO_OPERATIONS.disable.http.method,
				path: resolveOperationPath(SSO_OPERATIONS.disable, { id: rawId }),
				body: { dryRun: global.dryRun },
			});
		case SCIM_OPERATIONS.create.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: SCIM_OPERATIONS.create.http.method,
				path: SCIM_OPERATIONS.create.http.path,
				body: body({ organizationId: opts.org, provider: opts.provider, endpoint: opts.endpoint }),
			});
		case SCIM_OPERATIONS.test.cliPath:
			if (opts.live && opts.fixture) {
				throw error("SCIM_TEST_MODE_CONFLICT", "--live and --fixture are mutually exclusive.", "Use one SCIM test mode.");
			}
			if (opts.live) requireLiveTestMode(global, "SCIM_LIVE_CONFIRM_REQUIRED", "Live SCIM conformance");
			return requestManagementApi(session, {
				method: SCIM_OPERATIONS.test.http.method,
				path: resolveOperationPath(SCIM_OPERATIONS.test, { id: rawId }),
				body: body({ fixture: opts.fixture, live: opts.live, dryRun: global.dryRun || !opts.apply }),
			});
		case SCIM_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: SCIM_OPERATIONS.list.http.method,
				path: query(SCIM_OPERATIONS.list.http.path, { organizationId: opts.org }),
			});
		case SCIM_OPERATIONS.setupLink.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: SCIM_OPERATIONS.setupLink.http.method,
				path: SCIM_OPERATIONS.setupLink.http.path,
				body: { organizationId: opts.org },
			});
		case SCIM_OPERATIONS.rotate.cliPath:
			requireConfirmation(global, "SCIM_CONFIRM_REQUIRED", "SCIM credential rotation");
			return requestManagementApi(session, {
				method: SCIM_OPERATIONS.rotate.http.method,
				path: resolveOperationPath(SCIM_OPERATIONS.rotate, { id: rawId }),
				body: { dryRun: global.dryRun },
			});
		case SCIM_OPERATIONS.disable.cliPath:
			requireConfirmation(global, "SCIM_DISABLE_CONFIRM_REQUIRED", "SCIM disable");
			return requestManagementApi(session, {
				method: SCIM_OPERATIONS.disable.http.method,
				path: resolveOperationPath(SCIM_OPERATIONS.disable, { id: rawId }),
				body: { dryRun: global.dryRun },
			});
		case SCIM_OPERATIONS.replay.cliPath:
			return requestManagementApi(session, {
				method: SCIM_OPERATIONS.replay.http.method,
				path: resolveOperationPath(SCIM_OPERATIONS.replay, { traceId: rawId }),
				body: previewConfirmation(global),
			});
		case READINESS_OPERATIONS.check.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: READINESS_OPERATIONS.check.http.method,
				path: READINESS_OPERATIONS.check.http.path,
				body: { organizationId: opts.org },
			});
		case READINESS_OPERATIONS.report.cliPath:
			return requestManagementApi(session, {
				method: READINESS_OPERATIONS.report.http.method,
				path: resolveOperationPath(READINESS_OPERATIONS.report, { orgId: String(opts.org) }),
			});
	}
}
