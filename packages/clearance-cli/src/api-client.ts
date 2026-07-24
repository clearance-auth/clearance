import { ClearanceError } from "@clearance/management";
import {
	createServerManagementClient,
	MANAGEMENT_OPERATION_REGISTRY,
	ManagementApiError,
	type ManagementCallOptions,
	type OperationInput,
	type OperationOutput,
} from "@clearance/management-client";
import {
	environmentToken,
	normalizeApiUrl,
	normalizeProfile,
	readSavedCredential,
} from "./operator-auth.js";

const API_TIMEOUT_MS = 15_000;

type ManagementOperationId = keyof typeof MANAGEMENT_OPERATION_REGISTRY & string;
type ManagementOperation<Id extends ManagementOperationId> = (typeof MANAGEMENT_OPERATION_REGISTRY)[Id];

/** Call options intentionally expose only the transport controls the CLI owns. */
export type ManagementOperationCallOptions<Id extends ManagementOperationId> =
	ManagementCallOptions<ManagementOperation<Id>>;

export type ApiSession = {
	apiUrl: string;
	token: string;
	profile: string;
	credentialSource: "environment" | "saved";
};

function cliError(code: string, message: string, remediation: string, retryable = false): ClearanceError {
	return new ClearanceError({ code, message, stage: "cli.api", remediation, retryable });
}

export async function resolveApiSession(options: {
	profile?: string;
	apiUrl?: string;
} = {}): Promise<ApiSession | undefined> {
	const profile = normalizeProfile(options.profile);
	const envToken = environmentToken();
	if (options.profile !== undefined && envToken) {
		throw cliError(
			"CLI_PROFILE_ENV_TOKEN_CONFLICT",
			"An explicit --profile cannot be paired with an unscoped environment token.",
			"Unset CLEARANCE_OPERATOR_TOKEN and CLEARANCE_API_TOKEN to use the saved profile, or omit --profile to use the environment token.",
		);
	}
	if (envToken) {
		if (!options.apiUrl?.trim() && !process.env.CLEARANCE_API_URL?.trim()) {
			throw cliError(
				"CLI_ENV_TOKEN_API_URL_REQUIRED",
				"Environment-token sessions require an explicit Clearance API URL.",
				"Pass --api-url or set CLEARANCE_API_URL to the token's intended API origin.",
			);
		}
		return {
			apiUrl: normalizeApiUrl(options.apiUrl),
			token: envToken,
			profile,
			credentialSource: "environment",
		};
	}
	const saved = await readSavedCredential(process.env, profile);
	if (!saved) return undefined;
	const requestedApiUrl = options.apiUrl ? normalizeApiUrl(options.apiUrl) : undefined;
	if (requestedApiUrl && requestedApiUrl !== saved.apiUrl) {
		throw cliError(
			"CLI_CREDENTIAL_ORIGIN_MISMATCH",
			"The saved profile is bound to a different Clearance API origin.",
			"Use the profile's saved API URL, or log in to the requested origin with a separate profile.",
		);
	}
	return {
		apiUrl: saved.apiUrl,
		token: saved.token,
		profile,
		credentialSource: "saved",
	};
}

/**
 * Calls the complete generated Management API surface from the operator CLI.
 * The descriptor owns paths, query encoding, JSON, idempotency, validation,
 * and server-required confirmation; this adapter owns session binding and the
 * CLI's bounded transport/error contract.
 */
export async function callManagementOperation<Id extends ManagementOperationId>(
	session: ApiSession,
	id: Id,
	input: OperationInput<ManagementOperation<Id>>,
	options: ManagementOperationCallOptions<Id> = {},
): Promise<OperationOutput<ManagementOperation<Id>>> {
	const controller = new AbortController();
	let timedOut = false;
	const abortFromCaller = () => controller.abort(options.signal?.reason);
	if (options.signal?.aborted) abortFromCaller();
	else options.signal?.addEventListener("abort", abortFromCaller, { once: true });
	const timer = setTimeout(() => {
		timedOut = true;
		controller.abort();
	}, API_TIMEOUT_MS);

	try {
		const client = createServerManagementClient({
			baseUrl: session.apiUrl,
			bearerToken: session.token,
			registry: MANAGEMENT_OPERATION_REGISTRY,
		});
		const response = await client.call(id, input, { ...options, signal: controller.signal });
		return response.data;
	} catch (cause) {
		if (timedOut) {
			throw cliError(
				"CLI_API_TIMEOUT",
				"Clearance API request timed out.",
				"Check API reachability and retry.",
				true,
			);
		}
		if (cause instanceof ManagementApiError) {
			if (cause.code === "MANAGEMENT_API_UNREACHABLE") {
				throw cliError(
					"CLI_API_UNREACHABLE",
					"Clearance API could not be reached.",
					"Check the selected profile and network connection.",
					true,
				);
			}
			throw new ClearanceError({
				code: cause.code,
				message: cause.message,
				stage: cause.stage ?? "cli.api",
				remediation: cause.remediation ?? "Check the selected profile, API health, and operator authorization.",
				retryable: cause.retryable,
				status: cause.status,
			});
		}
		throw cliError(
			"CLI_API_UNREACHABLE",
			"Clearance API could not be reached.",
			"Check the selected profile and network connection.",
			true,
		);
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", abortFromCaller);
	}
}
