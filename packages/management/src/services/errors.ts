export class ClearanceError extends Error {
	readonly code: string;
	readonly stage: string;
	readonly retryable: boolean;
	readonly remediation: string;
	readonly status: number;

	constructor(opts: {
		code: string;
		message: string;
		stage: string;
		retryable?: boolean;
		remediation?: string;
		status?: number;
	}) {
		super(opts.message);
		this.name = "ClearanceError";
		this.code = opts.code;
		this.stage = opts.stage;
		this.retryable = opts.retryable ?? false;
		this.remediation = opts.remediation ?? "See documentation or run clearance doctor";
		this.status = opts.status ?? 400;
	}

	toJSON() {
		return {
			error: {
				code: this.code,
				message: this.message,
				stage: this.stage,
				retryable: this.retryable,
				remediation: this.remediation,
			},
		};
	}
}

export function isClearanceError(err: unknown): err is ClearanceError {
	return err instanceof ClearanceError;
}
