export type KeyManagementErrorCode =
	| "KEY_CONTEXT_INVALID"
	| "KEY_CONTEXT_MISMATCH"
	| "KEY_ENVELOPE_INVALID"
	| "KEY_INPUT_INVALID"
	| "KEY_NOT_AVAILABLE"
	| "KEY_OPERATION_FAILED"
	| "KEY_PROVIDER_MISMATCH"
	| "KEY_PROVIDER_NOT_READY"
	| "KEY_PURPOSE_REUSE"
	| "KEY_REGISTRY_INVALID";

export class KeyManagementError extends Error {
	readonly code: KeyManagementErrorCode;

	constructor(code: KeyManagementErrorCode, message: string) {
		super(message);
		this.name = "KeyManagementError";
		this.code = code;
	}
}
