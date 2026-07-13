import { randomUUID } from "node:crypto";
import { ClearanceError } from "@clearance/management";
import {
	environmentToken,
	normalizeApiUrl,
	normalizeProfile,
	readSavedCredential,
} from "./operator-auth.js";

const API_TIMEOUT_MS = 15_000;

export type ApiSession = {
	apiUrl: string;
	token: string;
	profile: string;
	credentialSource: "environment" | "saved";
};

type ApiRequest = {
	method?: "GET" | "POST" | "PATCH" | "DELETE";
	path: `/v1/${string}`;
	body?: unknown;
	idempotencyKey?: string;
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

export async function requestManagementApi<T>(session: ApiSession, request: ApiRequest): Promise<T> {
	const method = request.method ?? "GET";
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
	const headers: Record<string, string> = {
		authorization: `Bearer ${session.token}`,
		accept: "application/json",
	};
	if (request.body !== undefined) headers["content-type"] = "application/json";
	if (method !== "GET") headers["idempotency-key"] = request.idempotencyKey ?? randomUUID();
	try {
		const response = await fetch(`${session.apiUrl}${request.path}`, {
			method,
			headers,
			...(request.body !== undefined ? { body: JSON.stringify(request.body) } : {}),
			signal: controller.signal,
		});
		const payload = response.status === 204
			? undefined
			: await response.json().catch(() => undefined);
		if (response.ok) return payload as T;
		const remote = payload && typeof payload === "object"
			? (payload as { error?: Record<string, unknown> }).error
			: undefined;
		throw new ClearanceError({
			code: typeof remote?.code === "string" ? remote.code : "CLI_API_REQUEST_FAILED",
			message: typeof remote?.message === "string" ? remote.message : `Clearance API returned HTTP ${response.status}.`,
			stage: typeof remote?.stage === "string" ? remote.stage : "cli.api",
			remediation: typeof remote?.remediation === "string"
				? remote.remediation
				: "Check the selected profile, API health, and operator authorization.",
			retryable: typeof remote?.retryable === "boolean" ? remote.retryable : response.status >= 500,
			status: response.status,
		});
	} catch (cause) {
		if (cause instanceof ClearanceError) throw cause;
		if ((cause as Error).name === "AbortError") {
			throw cliError("CLI_API_TIMEOUT", "Clearance API request timed out.", "Check API reachability and retry.", true);
		}
		throw cliError("CLI_API_UNREACHABLE", "Clearance API could not be reached.", "Check the selected profile and network connection.", true);
	} finally {
		clearTimeout(timer);
	}
}
