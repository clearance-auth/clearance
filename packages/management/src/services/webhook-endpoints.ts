import type {
	EnqueuedDelivery,
	PublicWebhookEndpoint,
	WebhookEndpointPage,
	WebhookEndpointStatus,
	WebhookEventKind,
} from "@clearance/delivery";
import type {
	DeliveryControlAuditContext,
	DeliveryControlScope,
	ManagementStore,
} from "../store/types.js";
import { ClearanceError } from "./errors.js";

const SCHEMA_VERSION: "v1" = "v1";

export type WebhookEndpointDeletionResult = {
	endpoint: PublicWebhookEndpoint;
	erasedPayloads: number;
	jobs: {
		queuedOrRetryCancelled: number;
		leasedCancellationRequested: number;
		leasedDeliveryOutcomeAmbiguous: boolean;
	};
};

export type WebhookEndpointMutationPreview =
	| {
			action: "rotate";
			endpoint: PublicWebhookEndpoint;
			expectedVersion: number;
			nextResourceVersion: number;
			nextSecretVersion: number;
			secretGenerated: false;
	  }
	| {
			action: "delete";
			endpoint: PublicWebhookEndpoint;
			expectedVersion: number;
			nextResourceVersion: number;
			erasedPayloads: number;
			jobs: WebhookEndpointDeletionResult["jobs"];
	  }
	| {
			action: "test";
			endpoint: PublicWebhookEndpoint;
			expectedVersion: number;
			nextResourceVersion: number;
			createsDelivery: true;
	  };

type EndpointTarget = DeliveryControlScope & { endpointId: string };
type VersionedEndpointTarget = EndpointTarget & { expectedVersion: number };
type Audited<T> = T & DeliveryControlAuditContext;

/**
 * PostgreSQL endpoint seam. Mutation implementations append their immutable
 * management audit event in the same transaction as the endpoint change.
 * Versioned controls return the row-locked preview produced immediately before
 * the mutation so callers never execute against a separately observed state.
 */
export interface ManagementWebhookEndpointCapability {
	list(input: DeliveryControlScope & {
		limit?: number;
		cursor?: string;
		statuses?: readonly WebhookEndpointStatus[];
		eventKind?: WebhookEventKind;
	}): Promise<WebhookEndpointPage>;
	inspect(input: EndpointTarget): Promise<PublicWebhookEndpoint | null>;
	create(input: Audited<DeliveryControlScope & {
		name: string;
		url: string;
		eventKinds?: readonly WebhookEventKind[];
	}>): Promise<{ endpoint: PublicWebhookEndpoint; signingSecret: string }>;
	update(input: Audited<VersionedEndpointTarget & {
		name?: string;
		url?: string;
		eventKinds?: readonly WebhookEventKind[];
		status?: "active" | "disabled";
	}>): Promise<PublicWebhookEndpoint | null>;
	preview(input: VersionedEndpointTarget & {
		action: "rotate" | "delete" | "test";
	}): Promise<WebhookEndpointMutationPreview | null>;
	rotate(input: Audited<VersionedEndpointTarget>): Promise<{
		preview: WebhookEndpointMutationPreview;
		endpoint: PublicWebhookEndpoint;
		signingSecret: string;
	} | null>;
	delete(input: Audited<VersionedEndpointTarget>): Promise<{
		preview: WebhookEndpointMutationPreview;
		result: WebhookEndpointDeletionResult;
	} | null>;
	test(input: Audited<VersionedEndpointTarget>): Promise<{
		preview: WebhookEndpointMutationPreview;
		endpoint: PublicWebhookEndpoint;
		delivery: EnqueuedDelivery;
	} | null>;
}

export type ScopedWebhookEndpointPage = WebhookEndpointPage & {
	schemaVersion: typeof SCHEMA_VERSION;
	scope: DeliveryControlScope;
};

export type ScopedWebhookEndpoint = {
	schemaVersion: typeof SCHEMA_VERSION;
	scope: DeliveryControlScope;
	endpoint: PublicWebhookEndpoint;
};

export type WebhookEndpointCreateResult = ScopedWebhookEndpoint & {
	operation: "delivery.webhook_endpoints.create";
	storeBackend: "postgres";
	signingSecret: string;
};

export type WebhookEndpointUpdateResult = ScopedWebhookEndpoint & {
	operation: "delivery.webhook_endpoints.update";
	storeBackend: "postgres";
};

type WebhookEndpointConfirmedResult =
	| { endpoint: PublicWebhookEndpoint; signingSecret: string }
	| WebhookEndpointDeletionResult
	| { endpoint: PublicWebhookEndpoint; delivery: EnqueuedDelivery };

export type WebhookEndpointControlResult = {
	schemaVersion: typeof SCHEMA_VERSION;
	operation:
		| "delivery.webhook_endpoints.rotate"
		| "delivery.webhook_endpoints.delete"
		| "delivery.webhook_endpoints.test";
	storeBackend: "postgres";
	scope: DeliveryControlScope;
	endpointId: string;
	dryRun: boolean;
	preview: WebhookEndpointMutationPreview;
	result?: WebhookEndpointConfirmedResult;
};

function isEndpointCapability(value: unknown): value is ManagementWebhookEndpointCapability {
	return typeof value === "object" && value !== null &&
		"list" in value && typeof value.list === "function" &&
		"inspect" in value && typeof value.inspect === "function" &&
		"create" in value && typeof value.create === "function" &&
		"update" in value && typeof value.update === "function" &&
		"preview" in value && typeof value.preview === "function" &&
		"rotate" in value && typeof value.rotate === "function" &&
		"delete" in value && typeof value.delete === "function" &&
		"test" in value && typeof value.test === "function";
}

function requireEndpointCapability(
	store: ManagementStore,
	stage: string,
): ManagementWebhookEndpointCapability {
	if (store.backend !== "postgres") {
		throw new ClearanceError({
			code: "WEBHOOK_ENDPOINT_POSTGRES_REQUIRED",
			message: "Webhook endpoint management requires the PostgreSQL backend.",
			stage,
			status: 400,
			remediation: "Configure DATABASE_URL, then retry the webhook endpoint workflow.",
		});
	}
	const candidate = "webhookEndpoints" in store ? store.webhookEndpoints : undefined;
	if (!isEndpointCapability(candidate)) {
		throw new ClearanceError({
			code: "WEBHOOK_ENDPOINTS_NOT_CONFIGURED",
			message: "Webhook endpoint management is not configured.",
			stage,
			status: 503,
			retryable: true,
			remediation: "Configure the delivery schema, keyring, and audited endpoint transaction adapter.",
		});
	}
	return candidate;
}

function notFound(stage: string): ClearanceError {
	return new ClearanceError({
		code: "WEBHOOK_ENDPOINT_NOT_FOUND",
		message: "Webhook endpoint not found.",
		stage,
		status: 404,
		remediation: "Verify the endpoint id and active project/environment scope.",
	});
}

const PUBLIC_INPUT_ERRORS = new Set([
	"WEBHOOK_ENDPOINT_CURSOR_INVALID",
	"WEBHOOK_ENDPOINT_DATE_INVALID",
	"WEBHOOK_ENDPOINT_EVENT_KIND_INVALID",
	"WEBHOOK_ENDPOINT_EVENT_KINDS_INVALID",
	"WEBHOOK_ENDPOINT_EVENT_INVALID",
	"WEBHOOK_ENDPOINT_INPUT_INVALID",
	"WEBHOOK_ENDPOINT_LIMIT_INVALID",
	"WEBHOOK_ENDPOINT_STATUS_INVALID",
	"WEBHOOK_ENDPOINT_UPDATE_EMPTY",
	"WEBHOOK_ENDPOINT_URL_INVALID",
	"WEBHOOK_ENDPOINT_VERSION_INVALID",
]);

const CONFLICT_ERRORS = new Set([
	"WEBHOOK_ENDPOINT_DUPLICATE",
	"WEBHOOK_ENDPOINT_NOT_ACTIVE",
	"WEBHOOK_ENDPOINT_VERSION_CONFLICT",
]);

const SERVICE_UNAVAILABLE_ERRORS = new Set([
	"DELIVERY_CURRENT_FINGERPRINT_KEY_MISSING",
	"DELIVERY_CURRENT_KEY_MISSING",
	"DELIVERY_FINGERPRINT_KEY_UNAVAILABLE",
	"DELIVERY_KEY_UNAVAILABLE",
	"DELIVERY_SCHEMA_MISSING",
	"DELIVERY_SCHEMA_VERSION_FUTURE",
	"DELIVERY_SCHEMA_VERSION_OUTDATED",
	"WEBHOOK_ENDPOINT_CONFIG_UNAVAILABLE",
	"WEBHOOK_ENDPOINT_KEYRING_REQUIRED",
]);

function errorProperty(error: unknown, property: "code" | "message" | "httpStatus"): unknown {
	if (typeof error !== "object" || error === null) return undefined;
	if (property === "code" && "code" in error) return error.code;
	if (property === "message" && "message" in error) return error.message;
	if (property === "httpStatus" && "httpStatus" in error) return error.httpStatus;
	return undefined;
}

function translateEndpointError(error: unknown, stage: string): never {
	if (error instanceof ClearanceError) throw error;
	const rawCode = errorProperty(error, "code");
	const code = typeof rawCode === "string" &&
		(rawCode.startsWith("WEBHOOK_ENDPOINT_") || rawCode.startsWith("DELIVERY_"))
		? rawCode
		: "WEBHOOK_ENDPOINT_OPERATION_FAILED";
	const rawStatus = errorProperty(error, "httpStatus");
	const explicitStatus = typeof rawStatus === "number" && Number.isInteger(rawStatus) &&
		rawStatus >= 400 && rawStatus <= 599
		? rawStatus
		: undefined;
	const status = code === "DELIVERY_QUOTA_EXCEEDED" && explicitStatus === 429
		? 429
		: CONFLICT_ERRORS.has(code)
			? 409
			: PUBLIC_INPUT_ERRORS.has(code)
				? 400
				: SERVICE_UNAVAILABLE_ERRORS.has(code)
					? 503
					: 500;
	const rawMessage = errorProperty(error, "message");
	const message = status < 500 && typeof rawMessage === "string"
		? rawMessage
		: status === 503
			? "Webhook endpoint service configuration is unavailable."
			: "Webhook endpoint operation failed.";
	throw new ClearanceError({
		code,
		message,
		stage,
		status,
		retryable: status === 429 || status >= 500,
		remediation: status === 400
			? "Correct the webhook endpoint request and retry."
			: status === 409
				? "Refresh the endpoint and retry with its current resource version."
				: status === 429
					? "Wait for delivery capacity, then retry."
					: "Inspect delivery readiness and restore the required configuration.",
	});
}

function scope(input: DeliveryControlScope): DeliveryControlScope {
	return { projectId: input.projectId, environmentId: input.environmentId };
}

export async function listWebhookEndpointsForManagement(
	store: ManagementStore,
	input: DeliveryControlScope & {
		limit?: number;
		cursor?: string;
		statuses?: readonly WebhookEndpointStatus[];
		eventKind?: WebhookEventKind;
	},
): Promise<ScopedWebhookEndpointPage> {
	const stage = "delivery.webhook_endpoints.list";
	try {
		return {
			schemaVersion: SCHEMA_VERSION,
			scope: scope(input),
			...await requireEndpointCapability(store, stage).list(input),
		};
	} catch (error) {
		return translateEndpointError(error, stage);
	}
}

export async function inspectWebhookEndpointForManagement(
	store: ManagementStore,
	input: EndpointTarget,
): Promise<ScopedWebhookEndpoint> {
	const stage = "delivery.webhook_endpoints.inspect";
	try {
		const endpoint = await requireEndpointCapability(store, stage).inspect(input);
		if (!endpoint) throw notFound(stage);
		return { schemaVersion: SCHEMA_VERSION, scope: scope(input), endpoint };
	} catch (error) {
		return translateEndpointError(error, stage);
	}
}

export async function createWebhookEndpointForManagement(
	store: ManagementStore,
	input: Audited<DeliveryControlScope & {
		name: string;
		url: string;
		eventKinds?: readonly WebhookEventKind[];
	}>,
): Promise<WebhookEndpointCreateResult> {
	const stage = "delivery.webhook_endpoints.create";
	try {
		const created = await requireEndpointCapability(store, stage).create(input);
		return {
			schemaVersion: SCHEMA_VERSION,
			operation: stage,
			storeBackend: "postgres",
			scope: scope(input),
			...created,
		};
	} catch (error) {
		return translateEndpointError(error, stage);
	}
}

export async function updateWebhookEndpointForManagement(
	store: ManagementStore,
	input: Audited<VersionedEndpointTarget & {
		name?: string;
		url?: string;
		eventKinds?: readonly WebhookEventKind[];
		status?: "active" | "disabled";
	}>,
): Promise<WebhookEndpointUpdateResult> {
	const stage = "delivery.webhook_endpoints.update";
	try {
		const endpoint = await requireEndpointCapability(store, stage).update(input);
		if (!endpoint) throw notFound(stage);
		return {
			schemaVersion: SCHEMA_VERSION,
			operation: stage,
			storeBackend: "postgres",
			scope: scope(input),
			endpoint,
		};
	} catch (error) {
		return translateEndpointError(error, stage);
	}
}

async function controlWebhookEndpoint(
	store: ManagementStore,
	input: Audited<VersionedEndpointTarget & {
		action: "rotate" | "delete" | "test";
		dryRun?: boolean;
		confirm?: boolean;
	}>,
): Promise<WebhookEndpointControlResult> {
	const operation: WebhookEndpointControlResult["operation"] =
		`delivery.webhook_endpoints.${input.action}`;
	try {
		const capability = requireEndpointCapability(store, operation);
		const dryRun = input.dryRun === true || input.confirm !== true;
		if (dryRun) {
			const preview = await capability.preview(input);
			if (!preview) throw notFound(operation);
			return {
				schemaVersion: SCHEMA_VERSION,
				operation,
				storeBackend: "postgres",
				scope: scope(input),
				endpointId: input.endpointId,
				dryRun: true,
				preview,
			};
		}
		const common: Omit<WebhookEndpointControlResult, "preview" | "result"> = {
			schemaVersion: SCHEMA_VERSION,
			operation,
			storeBackend: "postgres",
			scope: scope(input),
			endpointId: input.endpointId,
			dryRun: false,
		};
		if (input.action === "rotate") {
			const rotated = await capability.rotate(input);
			if (!rotated) throw notFound(operation);
			return {
				...common,
				preview: rotated.preview,
				result: { endpoint: rotated.endpoint, signingSecret: rotated.signingSecret },
			};
		}
		if (input.action === "delete") {
			const deleted = await capability.delete(input);
			if (!deleted) throw notFound(operation);
			return { ...common, preview: deleted.preview, result: deleted.result };
		}
		const tested = await capability.test(input);
		if (!tested) throw notFound(operation);
		return {
			...common,
			preview: tested.preview,
			result: { endpoint: tested.endpoint, delivery: tested.delivery },
		};
	} catch (error) {
		return translateEndpointError(error, operation);
	}
}

export function rotateWebhookEndpointForManagement(
	store: ManagementStore,
	input: Audited<VersionedEndpointTarget & { dryRun?: boolean; confirm?: boolean }>,
): Promise<WebhookEndpointControlResult> {
	return controlWebhookEndpoint(store, { ...input, action: "rotate" });
}

export function deleteWebhookEndpointForManagement(
	store: ManagementStore,
	input: Audited<VersionedEndpointTarget & { dryRun?: boolean; confirm?: boolean }>,
): Promise<WebhookEndpointControlResult> {
	return controlWebhookEndpoint(store, { ...input, action: "delete" });
}

export function testWebhookEndpointForManagement(
	store: ManagementStore,
	input: Audited<VersionedEndpointTarget & { dryRun?: boolean; confirm?: boolean }>,
): Promise<WebhookEndpointControlResult> {
	return controlWebhookEndpoint(store, { ...input, action: "test" });
}
