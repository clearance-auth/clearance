export class DeliveryError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "DeliveryError";
		this.code = code;
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
