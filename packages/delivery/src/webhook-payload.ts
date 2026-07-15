import { DeliveryError } from "./errors.js";

export type WebhookPayloadEndpoint = {
	id: string;
	url: string;
	signingSecret: string;
};

export type WebhookPayloadContext = {
	projectId: string;
	environmentId: string;
	organizationId: string | null;
	actor: string | null;
	correlationId: string | null;
};

export type OrganizationUpdatedWebhookPayload = {
	version: 1;
	endpoint: WebhookPayloadEndpoint;
	event: {
		id: string;
		type: "organization.updated";
		occurredAt: string;
		context: WebhookPayloadContext & { organizationId: string };
		data: {
			organization: { id: string; name: string; slug: string; status: string };
			previous: { name: string; slug: string };
		};
	};
};

export type WebhookEndpointTestPayload = {
	version: 1;
	endpoint: WebhookPayloadEndpoint;
	event: {
		id: string;
		type: "webhook.endpoint.test";
		occurredAt: string;
		context: WebhookPayloadContext & { organizationId: null };
		data: { endpointId: string };
	};
};

export type WebhookDeliveryPayload = OrganizationUpdatedWebhookPayload | WebhookEndpointTestPayload;

function invalid(message: string): never {
	throw new DeliveryError("WEBHOOK_PAYLOAD_INVALID", message);
}

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
	if (!value || Array.isArray(value) || typeof value !== "object") invalid(`${label} must be an object`);
	const record = value as Record<string, unknown>;
	if (JSON.stringify(Object.keys(record).sort()) !== JSON.stringify([...keys].sort())) {
		invalid(`${label} fields are invalid`);
	}
	return record;
}

function text(value: unknown, label: string, maximum = 512): string {
	if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\u0000\r\n]/.test(value)) {
		invalid(`${label} is invalid`);
	}
	return value;
}

function jsonText(value: unknown, label: string, maximum = 1_024): string {
	if (typeof value !== "string" || value.length < 1 || value.length > maximum) invalid(`${label} is invalid`);
	return value;
}

function nullableText(value: unknown, label: string): string | null {
	return value === null ? null : text(value, label);
}

function timestamp(value: unknown): string {
	const raw = text(value, "event.occurredAt", 64);
	const parsed = new Date(raw);
	if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== raw) invalid("event.occurredAt is invalid");
	return raw;
}

function endpointPayload(value: unknown): WebhookPayloadEndpoint {
	const endpoint = exactObject(value, ["id", "url", "signingSecret"], "endpoint");
	const signingSecret = text(endpoint.signingSecret, "endpoint.signingSecret", 4_096);
	if (signingSecret.length < 32) invalid("endpoint.signingSecret is invalid");
	return {
		id: text(endpoint.id, "endpoint.id", 4_096),
		url: text(endpoint.url, "endpoint.url", 8_192),
		signingSecret,
	};
}

function contextPayload(value: unknown): WebhookPayloadContext {
	const context = exactObject(
		value,
		["projectId", "environmentId", "organizationId", "actor", "correlationId"],
		"event.context",
	);
	return {
		projectId: text(context.projectId, "event.context.projectId"),
		environmentId: text(context.environmentId, "event.context.environmentId"),
		organizationId: nullableText(context.organizationId, "event.context.organizationId"),
		actor: nullableText(context.actor, "event.context.actor"),
		correlationId: nullableText(context.correlationId, "event.context.correlationId"),
	};
}

export function parseWebhookDeliveryPayload(value: unknown): WebhookDeliveryPayload {
	const root = exactObject(value, ["version", "endpoint", "event"], "payload");
	if (root.version !== 1) invalid("Webhook payload version is invalid");
	const endpoint = endpointPayload(root.endpoint);
	const event = exactObject(root.event, ["id", "type", "occurredAt", "context", "data"], "event");
	const id = text(event.id, "event.id", 4_096);
	const occurredAt = timestamp(event.occurredAt);
	const context = contextPayload(event.context);
	if (event.type === "organization.updated") {
		if (context.organizationId === null) invalid("Organization webhook context is invalid");
		const data = exactObject(event.data, ["organization", "previous"], "event.data");
		const organization = exactObject(
			data.organization,
			["id", "name", "slug", "status"],
			"event.data.organization",
		);
		const previous = exactObject(data.previous, ["name", "slug"], "event.data.previous");
		return {
			version: 1,
			endpoint,
			event: {
				id,
				type: "organization.updated",
				occurredAt,
				context: { ...context, organizationId: context.organizationId },
				data: {
					organization: {
						id: text(organization.id, "event.data.organization.id"),
						name: jsonText(organization.name, "event.data.organization.name"),
						slug: text(organization.slug, "event.data.organization.slug"),
						status: text(organization.status, "event.data.organization.status", 64),
					},
					previous: {
						name: jsonText(previous.name, "event.data.previous.name"),
						slug: text(previous.slug, "event.data.previous.slug"),
					},
				},
			},
		};
	}
	if (event.type === "webhook.endpoint.test") {
		if (context.organizationId !== null) invalid("Endpoint test context is invalid");
		const data = exactObject(event.data, ["endpointId"], "event.data");
		const endpointId = text(data.endpointId, "event.data.endpointId", 4_096);
		if (endpointId !== endpoint.id) invalid("Endpoint test identity is invalid");
		return {
			version: 1,
			endpoint,
			event: {
				id,
				type: "webhook.endpoint.test",
				occurredAt,
				context: { ...context, organizationId: null },
				data: { endpointId },
			},
		};
	}
	invalid("Webhook event type is invalid");
}

export function parseOrganizationUpdatedWebhookPayload(value: unknown): OrganizationUpdatedWebhookPayload {
	const payload = parseWebhookDeliveryPayload(value);
	const event = payload.event;
	if (event.type !== "organization.updated") invalid("Webhook event type is invalid");
	return { version: payload.version, endpoint: payload.endpoint, event };
}

export function parseWebhookEndpointTestPayload(value: unknown): WebhookEndpointTestPayload {
	const payload = parseWebhookDeliveryPayload(value);
	const event = payload.event;
	if (event.type !== "webhook.endpoint.test") invalid("Webhook event type is invalid");
	return { version: payload.version, endpoint: payload.endpoint, event };
}
