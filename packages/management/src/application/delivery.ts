import { randomUUID } from "node:crypto";
import type {
	EnqueuedDelivery,
	EnqueueDeliveryInput,
} from "@clearance/delivery";
import type { Organization } from "../types/resources.js";
import type { OperationContext } from "./context.js";

const TARGET_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const WEBHOOK_TTL_MS = 7 * 24 * 60 * 60 * 1_000;

export type ManagementWebhookTarget = {
	id: string;
	url: string;
	signingSecret: string;
	/** Development-only escape hatch for loopback HTTP fixtures. */
	allowInsecureLoopback?: boolean;
};

export type ValidatedManagementWebhookTarget = Readonly<{
	id: string;
	url: string;
	signingSecret: string;
}>;

export type ManagementDeliveryEnqueue = (
	input: EnqueueDeliveryInput,
) => Promise<EnqueuedDelivery>;

function isLoopback(hostname: string): boolean {
	return hostname === "localhost" ||
		hostname === "127.0.0.1" ||
		hostname === "::1" ||
		hostname === "[::1]";
}

export function validateManagementWebhookTargets(
	targets: readonly ManagementWebhookTarget[],
): readonly ValidatedManagementWebhookTarget[] {
	if (targets.length > 32) {
		throw new Error("Management webhook target count cannot exceed 32");
	}
	const ids = new Set<string>();
	return targets.map((target) => {
		const id = target.id.trim();
		if (!TARGET_ID.test(id) || ids.has(id)) {
			throw new Error(`Invalid or duplicate management webhook target id: ${id}`);
		}
		ids.add(id);
		let parsed: URL;
		try {
			parsed = new URL(target.url);
		} catch {
			throw new Error(`Management webhook target ${id} requires an absolute URL`);
		}
		if (
			parsed.protocol !== "https:" &&
			!(
				target.allowInsecureLoopback === true &&
				parsed.protocol === "http:" &&
				isLoopback(parsed.hostname)
			)
		) {
			throw new Error(
				`Management webhook target ${id} must use HTTPS (loopback HTTP requires explicit development opt-in)`,
			);
		}
		if (parsed.username || parsed.password || parsed.hash) {
			throw new Error(
				`Management webhook target ${id} cannot contain credentials or a fragment`,
			);
		}
		if (
			typeof target.signingSecret !== "string" ||
			target.signingSecret.length < 32 ||
			target.signingSecret.length > 4_096
		) {
			throw new Error(
				`Management webhook target ${id} signing secret must be 32-4096 characters`,
			);
		}
		return Object.freeze({
			id,
			url: parsed.toString(),
			signingSecret: target.signingSecret,
		});
	});
}

export async function enqueueOrganizationUpdatedWebhooks(input: {
	enqueue: ManagementDeliveryEnqueue | undefined;
	targets: readonly ValidatedManagementWebhookTarget[];
	context: OperationContext;
	organization: Organization;
	before: { name: string; slug: string };
	occurredAt: Date;
}): Promise<readonly EnqueuedDelivery[]> {
	if (input.targets.length === 0) return [];
	if (!input.enqueue) {
		throw new Error(
			"Management webhook targets require a configured transactional delivery outbox",
		);
	}
	const occurredAt = input.occurredAt.toISOString();
	const expiresAt = new Date(input.occurredAt.getTime() + WEBHOOK_TTL_MS);
	const deliveries: EnqueuedDelivery[] = [];
	for (const target of input.targets) {
		const eventId = randomUUID();
		const correlationId = input.context.correlationId ?? eventId;
		const sourceGeneration = input.context.correlationId ?? occurredAt;
		deliveries.push(
			await input.enqueue({
				eventId,
				kind: "organization.updated",
				sourceKey: `organization.updated:${input.organization.id}:${sourceGeneration}:${target.id}`,
				projectId: input.context.scope.projectId,
				environmentId: input.context.scope.environmentId,
				organizationId: input.organization.id,
				actorId: input.context.actor,
				correlationId,
				channel: "webhook",
				destination: target.url,
				payload: {
					version: 1,
					endpoint: {
						id: target.id,
						url: target.url,
						signingSecret: target.signingSecret,
					},
					event: {
						id: eventId,
						type: "organization.updated",
						occurredAt,
						context: {
							projectId: input.context.scope.projectId,
							environmentId: input.context.scope.environmentId,
							organizationId: input.organization.id,
							actor: input.context.actor,
							correlationId,
						},
						data: {
							organization: {
								id: input.organization.id,
								name: input.organization.name,
								slug: input.organization.slug,
								status: input.organization.status,
							},
							previous: input.before,
						},
					},
				},
				semanticExpiresAt: expiresAt,
				now: input.occurredAt,
			}),
		);
	}
	return deliveries;
}
