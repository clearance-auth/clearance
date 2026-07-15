export type DeliveryJobState =
	| "queued"
	| "leased"
	| "retry"
	| "delivered"
	| "dead"
	| "cancelled";

export type DeliveryJobRecord = {
	id: string;
	eventId: string;
	kind: string;
	projectId: string;
	environmentId: string;
	organizationId: string | null;
	channel: "email" | "webhook";
	state: DeliveryJobState;
	attemptCount: number;
	maxAttempts: number;
	availableAt: string;
	semanticExpiresAt: string;
	lastErrorClass: string | null;
	createdAt: string;
	updatedAt: string;
	deliveredAt: string | null;
	deadAt: string | null;
	cancelledAt: string | null;
};

export type PublicDeliveryJob = DeliveryJobRecord & {
	destination: "[redacted]";
};

export function redactedDeliveryJob(record: DeliveryJobRecord): PublicDeliveryJob {
	return { ...record, destination: "[redacted]" };
}

export function safeErrorClass(value: string | undefined | null): string | null {
	if (!value) return null;
	const normalized = value.trim().toLowerCase();
	return /^[a-z0-9][a-z0-9._-]{0,63}$/.test(normalized)
		? normalized
		: "provider_error";
}

/** Accept only documented opaque ids or bounded status codes, never response text. */
export function safeProviderValue(
	value: string | undefined | null,
	kind: "requestId" | "status" = "requestId",
): string | null {
	if (!value) return null;
	const normalized = value.trim();
	if (
		/https?:|[\\/]|(?:token|secret|bearer|authorization)/i.test(normalized) ||
		/^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(normalized)
	) {
		return null;
	}
	if (kind === "status") {
		return /^(?:[245][0-9]{2}|[245]\.[0-9]{1,3}\.[0-9]{1,3}|[A-Z][A-Z0-9_]{0,31})$/.test(
			normalized,
		)
			? normalized
			: null;
	}
	return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(normalized)
		? normalized
		: null;
}
