export interface ManagementApiProblem {
	readonly code: string;
	readonly message: string;
	readonly stage?: string;
	readonly remediation?: string;
	readonly retryable?: boolean;
	readonly [key: string]: unknown;
}

export interface ManagementApiErrorInit extends ManagementApiProblem {
	readonly status: number;
	readonly requestId?: string;
	readonly idempotencyKey?: string;
}

/** A stable, transport-level representation of a Management API failure. */
export class ManagementApiError extends Error {
	readonly code: string;
	readonly status: number;
	readonly stage?: string;
	readonly remediation?: string;
	readonly retryable: boolean;
	readonly requestId?: string;
	/** Reuse this key with the identical operation to safely retry a mutation. */
	readonly idempotencyKey?: string;

	constructor(init: ManagementApiErrorInit) {
		super(init.message);
		this.name = "ManagementApiError";
		this.code = init.code;
		this.status = init.status;
		this.stage = init.stage;
		this.remediation = init.remediation;
		this.retryable = init.retryable ?? init.status >= 500;
		this.requestId = init.requestId;
		this.idempotencyKey = init.idempotencyKey;
	}
}

function problemFrom(value: unknown, status: number): ManagementApiProblem {
	const error = value && typeof value === "object" && "error" in value
		? (value as { error?: unknown }).error
		: undefined;
	if (!error || typeof error !== "object") {
		return {
			code: "MANAGEMENT_API_REQUEST_FAILED",
			message: `Clearance Management API returned HTTP ${status}.`,
		};
	}
	const record = error as Record<string, unknown>;
	return {
		...record,
		code: typeof record.code === "string" ? record.code : "MANAGEMENT_API_REQUEST_FAILED",
		message: typeof record.message === "string"
			? record.message
			: `Clearance Management API returned HTTP ${status}.`,
		stage: typeof record.stage === "string" ? record.stage : undefined,
		remediation: typeof record.remediation === "string" ? record.remediation : undefined,
		retryable: typeof record.retryable === "boolean" ? record.retryable : status >= 500,
	};
}

export function managementApiErrorFromResponse(
	response: Response,
	payload: unknown,
	context: { idempotencyKey?: string } = {},
): ManagementApiError {
	const problem = problemFrom(payload, response.status);
	return new ManagementApiError({
		...problem,
		status: response.status,
		requestId: response.headers.get("x-request-id") ?? undefined,
		idempotencyKey: context.idempotencyKey,
	});
}
