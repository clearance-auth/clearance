export class DeliveryError extends Error {
	readonly code: string;
	readonly httpStatus?: number;

	constructor(code: string, message: string, httpStatus?: number) {
		super(message);
		this.name = "DeliveryError";
		this.code = code;
		this.httpStatus = httpStatus;
	}
}

export type DeliveryQuotaKind = "active" | "backlog" | "enqueue_rate";

export class DeliveryQuotaExceededError extends DeliveryError {
	readonly quota: DeliveryQuotaKind;
	readonly limit: number;
	readonly retryAfterSeconds: number | null;

	constructor(input: {
		quota: DeliveryQuotaKind;
		limit: number;
		retryAfterSeconds?: number | null;
	}) {
		super(
			"DELIVERY_QUOTA_EXCEEDED",
			`Delivery ${input.quota.replace("_", " ")} quota is exhausted`,
			429,
		);
		this.name = "DeliveryQuotaExceededError";
		this.quota = input.quota;
		this.limit = input.limit;
		this.retryAfterSeconds = input.retryAfterSeconds ?? null;
	}
}

export class DeliveryControlConflictError extends DeliveryError {
	readonly state: string;

	constructor(message: string, state: string) {
		super("DELIVERY_CONTROL_CONFLICT", message, 409);
		this.name = "DeliveryControlConflictError";
		this.state = state;
	}
}

export class StaleDeliveryLeaseError extends DeliveryError {
	constructor() {
		super(
			"DELIVERY_STALE_LEASE",
			"The delivery lease expired, was cancelled, or is owned by another worker",
		);
	}
}
