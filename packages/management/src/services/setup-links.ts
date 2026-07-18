/**
 * Setup links are random single-use capabilities.
 * Persist only a digest plus scope/action/resource/expiry/use/revocation metadata.
 * The raw capability token is returned once at creation time.
 *
 * Safe completion uses a bounded reserve → provision → commit/release flow so
 * external SSO/SCIM side effects can fail without consuming the capability or
 * leaving a permanent partial connection when the API compensates.
 */
import { createHash, randomBytes } from "node:crypto";
import type { ManagementStore, StoreV2TopologyRepository } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DataStoreSnapshot, SetupCapability } from "../types/resources.js";
import { appendAuditEvent, recordEvent, type AuditEventInput } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { inspectOrganization, inspectOrganizationAuthoritative } from "./core.js";
import type { ResourceScope } from "./scope.js";

export type SetupKind = "sso" | "scim";

/** Bounded lease so a crashed holder does not permanently burn the capability. */
export const SETUP_RESERVATION_TTL_MS = 120_000;

function digestToken(token: string): string {
	return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Stable reservation / setup-attempt id derived from the capability digest.
 * Same capability always re-leases the same attempt id after expiry so runtime
 * and management rows can be reconciled without exposing the raw token.
 */
export function deriveSetupReservationId(capabilityDigest: string): string {
	return `rsv_${capabilityDigest.slice(0, 24)}`;
}

/**
 * Deterministic runtime PK + unique providerId for a setup attempt.
 * Used only when completing a reserved capability; normal CLI/operator creates
 * keep generated ids. Material is a hash of kind+attempt — never the raw token.
 */
export function deriveSetupConnectionIds(
	kind: SetupKind,
	setupAttemptId: string,
): { connectionId: string; providerId: string } {
	const material = createHash("sha256")
		.update(`clearance:setup:v1:${kind}:${setupAttemptId}`, "utf8")
		.digest("hex");
	if (kind === "sso") {
		return {
			// Match bridge shape: sso{hex} (no underscore after prefix)
			connectionId: `sso${material.slice(0, 24)}`,
			providerId: `clr-setup-sso-${material.slice(0, 28)}`,
		};
	}
	return {
		connectionId: `scim${material.slice(0, 24)}`,
		providerId: `clr-setup-scim-${material.slice(0, 28)}`,
	};
}

function ensureSetupLinksArray(data: { setupLinks?: SetupCapability[] }): SetupCapability[] {
	if (!Array.isArray(data.setupLinks)) {
		data.setupLinks = [];
	}
	return data.setupLinks;
}

function isReservationActive(cap: SetupCapability, nowMs = Date.now()): boolean {
	if (!cap.reservedAt || !cap.reservationId) return false;
	if (!cap.reservationExpiresAt) return true;
	return new Date(cap.reservationExpiresAt).getTime() > nowMs;
}

function clearReservationFields(cap: SetupCapability): SetupCapability {
	const next = { ...cap };
	delete next.reservedAt;
	delete next.reservationId;
	delete next.reservationExpiresAt;
	return next;
}

function assertRedeemableScope(
	cap: SetupCapability,
	input: {
		kind: SetupKind;
		organizationId?: string;
		projectId?: string;
		environmentId?: string;
	},
	reject: (code: string, message: string, status?: number) => never,
): void {
	if (cap.revokedAt) reject("SETUP_LINK_REVOKED", "Setup link has been revoked");
	if (new Date(cap.expiresAt).getTime() <= Date.now()) {
		reject("SETUP_LINK_EXPIRED", "Setup link has expired");
	}
	if (cap.useCount >= cap.maxUses || cap.redeemedAt) {
		reject("SETUP_LINK_REPLAY", "Setup link already used");
	}
	if (cap.kind !== input.kind || cap.action !== "setup") {
		reject("SETUP_LINK_SCOPE", "Setup link kind/action does not match redemption");
	}
	if (input.organizationId && input.organizationId !== cap.organizationId) {
		reject("SETUP_LINK_SCOPE", "Setup link organization does not match");
	}
	if (input.projectId && input.projectId !== cap.projectId) {
		reject("SETUP_LINK_SCOPE", "Setup link project does not match");
	}
	if (input.environmentId && input.environmentId !== cap.environmentId) {
		reject("SETUP_LINK_SCOPE", "Setup link environment does not match");
	}
	if (cap.resourceType !== "organization" || cap.resourceId !== cap.organizationId) {
		reject("SETUP_LINK_SCOPE", "Setup link resource scope is invalid");
	}
}

/**
 * A setup capability stores its scope at mint time, but normalized topology is
 * still the authority for whether that scope remains operable.  Keep this
 * check inside the coordinated transaction that changes the capability: an
 * archive or re-scope that commits first must make the capability unusable,
 * without consuming its lease or use count.
 */
async function assertActiveCapabilityTopology(
	topology: StoreV2TopologyRepository,
	cap: SetupCapability,
	reject: (code: string, message: string, status?: number) => never,
): Promise<void> {
	if (cap.resourceType !== "organization" || cap.resourceId !== cap.organizationId) {
		reject("SETUP_LINK_SCOPE", "Setup link resource scope is invalid");
	}
	const organization = await topology.lockOrganization({
		scope: {
			projectId: cap.projectId,
			environmentId: cap.environmentId,
		},
		id: cap.resourceId,
	});
	if (
		!organization ||
		organization.status === "archived" ||
		organization.id !== cap.organizationId ||
		organization.projectId !== cap.projectId ||
		organization.environmentId !== cap.environmentId
	) {
		reject("SETUP_LINK_SCOPE", "Setup link scope is no longer active");
	}
}

type SetupLinkMutationContext = {
	data: DataStoreSnapshot;
	links: SetupCapability[];
	index: number;
	capability: SetupCapability;
	appendAudit: (input: AuditEventInput) => unknown;
};

/**
 * Locate and change a capability.  Once topology is relational-authoritative,
 * this runs the topology read, capability mutation, and success audit in one
 * transaction.  JSON keeps its existing durable snapshot mutation contract.
 */
async function mutateSetupLink<T>(
	store: ManagementStore,
	digest: string,
	stage: "setup-link.redeem" | "setup-link.reserve" | "setup-link.commit",
	reject: (code: string, message: string, status?: number) => never,
	mutate: (context: SetupLinkMutationContext) => T,
): Promise<T> {
	const prepare = (data: SetupLinkMutationContext["data"]): Omit<SetupLinkMutationContext, "appendAudit"> => {
		const links = ensureSetupLinksArray(data);
		const index = links.findIndex((candidate) => candidate.digest === digest);
		if (index < 0) reject("SETUP_LINK_NOT_FOUND", "Setup link not found or invalid", 404);
		return { data, links, index, capability: links[index]! };
	};

	if (!store.storeV2Topology?.authoritative) {
		return store.mutateDurable((data) =>
			mutate({
				...prepare(data),
				appendAudit: (input) => appendAuditEvent(data, input),
			}),
		);
	}
	if (!store.mutateCoordinated) {
		throw new ClearanceError({
			code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
			message: "Relational topology authority requires a coordinated transaction",
			stage,
			status: 500,
		});
	}
	return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		if (!topology) {
			throw new ClearanceError({
				code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
				message: "Relational topology authority requires a coordinated transaction",
				stage,
				status: 500,
			});
		}
		const prepared = prepare(data);
		await assertActiveCapabilityTopology(topology, prepared.capability, reject);
		return mutate({ ...prepared, appendAudit });
	});
}

async function appendSetupLinkFailureAudit(
	store: ManagementStore,
	input: { actor?: string; kind: SetupKind },
	action: "redeem" | "reserve" | "commit",
	reason: string,
): Promise<void> {
	const audit = {
		actor: input.actor ?? "system",
		action: `${input.kind}.setup-link.${action}`,
		subjectType: "setup_capability" as const,
		outcome: "failure" as const,
		source: "api" as const,
		message: `Setup link ${action} rejected`,
		metadata: { reason },
	};
	if (store.storeV2Topology?.authoritative) {
		if (!store.mutateCoordinated) return;
		await store.mutateCoordinated(({ appendAudit }) => {
			appendAudit(audit);
		});
		return;
	}
	await store.mutateDurable((data) => {
		appendAuditEvent(data, audit);
	});
}

type SetupLinkInput = {
	organizationId: string;
	kind: SetupKind;
	ttlMinutes?: number;
	actor?: string;
	baseUrl?: string;
};
type SetupLink = { url: string; expiresAt: string; token: string; tokenFingerprint: string; capabilityId: string };

function setupLinkAuditInput(
	input: SetupLinkInput,
	org: { id: string; projectId: string; environmentId: string },
	capability: SetupCapability,
	expiresAt: string,
	digest: string,
) {
	return {
		actor: input.actor ?? "operator",
		action: `${input.kind}.setup-link.create`,
		subjectType: "setup_capability" as const,
		subjectId: capability.id,
		outcome: "success" as const,
		source: "cli" as const,
		organizationId: org.id,
		projectId: org.projectId,
		environmentId: org.environmentId,
		message: `Created ${input.kind} setup capability expiring ${expiresAt}`,
		metadata: {
			expiresAt,
			tokenFingerprint: digest.slice(0, 16),
			capabilityId: capability.id,
		},
	};
}

function buildSetupLink(
	input: SetupLinkInput,
	org: { id: string; projectId: string; environmentId: string },
): { capability: SetupCapability; link: SetupLink; expiresAt: string; digest: string } {
	const token = randomBytes(32).toString("base64url");
	const digest = digestToken(token);
	const expiresAt = new Date(
		Date.now() + (input.ttlMinutes ?? 60) * 60_000,
	).toISOString();
	const now = nowIso();
	const capability: SetupCapability = {
		id: newId("cap"),
		digest,
		kind: input.kind,
		action: "setup",
		resourceType: "organization",
		resourceId: org.id,
		organizationId: org.id,
		projectId: org.projectId,
		environmentId: org.environmentId,
		expiresAt,
		maxUses: 1,
		useCount: 0,
		revokedAt: undefined,
		redeemedAt: undefined,
		createdAt: now,
	};

	const base =
		input.baseUrl ??
		process.env.CLEARANCE_CONSOLE_URL ??
		"http://localhost:3100";
	const url = `${base.replace(/\/$/, "")}/setup/${input.kind}?org=${encodeURIComponent(org.id)}&token=${token}`;

	return {
		capability,
		link: { url, expiresAt, token, tokenFingerprint: digest.slice(0, 16), capabilityId: capability.id },
		expiresAt,
		digest,
	};
}

function createSetupLinkResolved(
	store: ManagementStore,
	input: SetupLinkInput,
	org: { id: string; projectId: string; environmentId: string },
): SetupLink {
	const { capability, link, expiresAt, digest } = buildSetupLink(input, org);
	store.mutate((data) => {
		ensureSetupLinksArray(data).push(capability);
		appendAuditEvent(data, setupLinkAuditInput(input, org, capability, expiresAt, digest));
	});
	return link;
}

export function createSetupLink(store: ManagementStore, input: SetupLinkInput): SetupLink {
	return createSetupLinkResolved(store, input, inspectOrganization(store, input.organizationId));
}

/** Create a setup capability from normalized organization authority. */
export async function createSetupLinkAuthoritative(
	store: ManagementStore,
	input: {
		organizationId: string;
		kind: SetupKind;
		ttlMinutes?: number;
		actor?: string;
		baseUrl?: string;
		scope: ResourceScope;
	},
): Promise<SetupLink> {
	if (!store.storeV2Topology?.authoritative) {
		const organization = await inspectOrganizationAuthoritative(
			store,
			input.organizationId,
			input.scope,
		);
		return createSetupLinkResolved(store, input, organization);
	}
	if (!store.mutateCoordinated) {
		throw new ClearanceError({
			code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
			message: "Relational topology authority requires a coordinated transaction",
			stage: "setup-link.create",
			status: 500,
		});
	}
	return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const organization = topology
			? await topology.lockOrganization({ scope: input.scope, id: input.organizationId })
			: null;
		if (!organization || organization.status === "archived") {
			throw new ClearanceError({
				code: "ORG_NOT_FOUND",
				message: "Organization not found",
				stage: "orgs.inspect",
				status: 404,
			});
		}
		const { capability, link, expiresAt, digest } = buildSetupLink(input, organization);
		ensureSetupLinksArray(data).push(capability);
		appendAudit(setupLinkAuditInput(input, organization, capability, expiresAt, digest));
		return link;
	});
}

export type RedeemSetupLinkInput = {
	token: string;
	kind: SetupKind;
	/** When set, must match capability */
	organizationId?: string;
	projectId?: string;
	environmentId?: string;
	actor?: string;
};

/**
 * Atomically consume a setup capability (single durable mutation).
 * Prefer reserve → provision → commit for flows with external side effects.
 */
export async function redeemSetupLink(
	store: ManagementStore,
	input: RedeemSetupLinkInput,
): Promise<SetupCapability> {
	const digest = digestToken(input.token);
	const reject = (code: string, message: string, status = 403): never => {
		throw new ClearanceError({
			code,
			message,
			stage: "setup-link.redeem",
			status,
		});
	};

	try {
		return await mutateSetupLink(store, digest, "setup-link.redeem", reject, ({ links, index, capability: cap, appendAudit }) => {
			assertRedeemableScope(cap, input, reject);
			if (isReservationActive(cap)) {
				reject(
					"SETUP_LINK_IN_PROGRESS",
					"Setup link completion is already in progress",
					409,
				);
			}
			const updated = clearReservationFields({
				...cap,
				useCount: cap.useCount + 1,
				redeemedAt: nowIso(),
			});
			links[index] = updated;
			appendAudit({
				actor: input.actor ?? "system",
				action: `${input.kind}.setup-link.redeem`,
				subjectType: "setup_capability",
				subjectId: cap.id,
				outcome: "success",
				source: "api",
				organizationId: cap.organizationId,
				projectId: cap.projectId,
				environmentId: cap.environmentId,
				message: `Redeemed ${input.kind} setup capability`,
				metadata: { capabilityId: cap.id, resourceId: cap.resourceId },
			});
			return updated;
		});
	} catch (error) {
		const code = error instanceof ClearanceError ? error.code : "SETUP_LINK_REDEEM_FAILED";
		await appendSetupLinkFailureAudit(store, input, "redeem", code).catch(() => undefined);
		throw error;
	}
}

export type ReserveSetupLinkResult = {
	capability: SetupCapability;
	reservationId: string;
};

/**
 * Atomically lease a setup capability for in-flight provisioning.
 * Does not consume the capability; commit does. Concurrent reserves yield
 * one winner and SETUP_LINK_IN_PROGRESS / REPLAY for losers.
 */
export async function reserveSetupLink(
	store: ManagementStore,
	input: RedeemSetupLinkInput & { reservationTtlMs?: number },
): Promise<ReserveSetupLinkResult> {
	const digest = digestToken(input.token);
	const reject = (code: string, message: string, status = 403): never => {
		throw new ClearanceError({
			code,
			message,
			stage: "setup-link.reserve",
			status,
		});
	};

	try {
		return await mutateSetupLink(store, digest, "setup-link.reserve", reject, ({ links, index, capability: cap, appendAudit }) => {
			assertRedeemableScope(cap, input, reject);
			if (isReservationActive(cap)) {
				reject(
					"SETUP_LINK_IN_PROGRESS",
					"Setup link completion is already in progress",
					409,
				);
			}
			const now = Date.now();
			const ttl = input.reservationTtlMs ?? SETUP_RESERVATION_TTL_MS;
			// Deterministic across re-reserves of the same capability (digest lineage).
			const reservationId = deriveSetupReservationId(digest);
			const updated: SetupCapability = {
				...clearReservationFields(cap),
				reservedAt: new Date(now).toISOString(),
				reservationId,
				reservationExpiresAt: new Date(now + ttl).toISOString(),
			};
			links[index] = updated;
			appendAudit({
				actor: input.actor ?? "system",
				action: `${input.kind}.setup-link.reserve`,
				subjectType: "setup_capability",
				subjectId: cap.id,
				outcome: "success",
				source: "api",
				organizationId: cap.organizationId,
				projectId: cap.projectId,
				environmentId: cap.environmentId,
				message: `Reserved ${input.kind} setup capability for completion`,
				metadata: {
					capabilityId: cap.id,
					reservationId,
					reservationExpiresAt: updated.reservationExpiresAt,
				},
			});
			return { capability: updated, reservationId };
		});
	} catch (error) {
		const code = error instanceof ClearanceError ? error.code : "SETUP_LINK_RESERVE_FAILED";
		await appendSetupLinkFailureAudit(store, input, "reserve", code).catch(() => undefined);
		throw error;
	}
}

export type CommitSetupLinkInput = RedeemSetupLinkInput & {
	reservationId: string;
};

/**
 * Atomically consume a previously reserved capability. Replay after commit fails.
 * Never reopens a redeemed capability.
 */
export async function commitSetupLink(
	store: ManagementStore,
	input: CommitSetupLinkInput,
): Promise<SetupCapability> {
	const digest = digestToken(input.token);
	const reject = (code: string, message: string, status = 403): never => {
		throw new ClearanceError({
			code,
			message,
			stage: "setup-link.commit",
			status,
		});
	};

	try {
		return await mutateSetupLink(store, digest, "setup-link.commit", reject, ({ links, index, capability: cap, appendAudit }) => {
			if (cap.useCount >= cap.maxUses || cap.redeemedAt) {
				reject("SETUP_LINK_REPLAY", "Setup link already used");
			}
			if (cap.revokedAt) reject("SETUP_LINK_REVOKED", "Setup link has been revoked");
			if (new Date(cap.expiresAt).getTime() <= Date.now()) {
				reject("SETUP_LINK_EXPIRED", "Setup link has expired");
			}
			if (cap.kind !== input.kind || cap.action !== "setup") {
				reject("SETUP_LINK_SCOPE", "Setup link kind/action does not match");
			}
			assertRedeemableScope(cap, input, reject);
			if (!cap.reservationId || cap.reservationId !== input.reservationId) {
				reject(
					"SETUP_LINK_RESERVATION_MISMATCH",
					"Setup link reservation does not match this completion attempt",
					409,
				);
			}
			if (!isReservationActive(cap)) {
				reject(
					"SETUP_LINK_RESERVATION_EXPIRED",
					"Setup link reservation expired before commit",
					409,
				);
			}
			const updated = clearReservationFields({
				...cap,
				useCount: cap.useCount + 1,
				redeemedAt: nowIso(),
			});
			links[index] = updated;
			appendAudit({
				actor: input.actor ?? "system",
				action: `${input.kind}.setup-link.commit`,
				subjectType: "setup_capability",
				subjectId: cap.id,
				outcome: "success",
				source: "api",
				organizationId: cap.organizationId,
				projectId: cap.projectId,
				environmentId: cap.environmentId,
				message: `Committed ${input.kind} setup capability after successful provisioning`,
				metadata: {
					capabilityId: cap.id,
					reservationId: input.reservationId,
					resourceId: cap.resourceId,
				},
			});
			return updated;
		});
	} catch (error) {
		const code = error instanceof ClearanceError ? error.code : "SETUP_LINK_COMMIT_FAILED";
		await appendSetupLinkFailureAudit(store, input, "commit", code).catch(() => undefined);
		throw error;
	}
}

export type ReleaseSetupLinkInput = {
	token: string;
	kind: SetupKind;
	reservationId: string;
	actor?: string;
};

/**
 * Drop an in-progress reservation after failed provisioning.
 * Never un-consumes a committed (redeemed) capability.
 */
export async function releaseSetupLink(
	store: ManagementStore,
	input: ReleaseSetupLinkInput,
): Promise<SetupCapability | null> {
	const digest = digestToken(input.token);

	return store.mutateDurable((data) => {
		const links = ensureSetupLinksArray(data);
		const index = links.findIndex((candidate) => candidate.digest === digest);
		if (index < 0) return null;
		const cap = links[index]!;
		// Terminal success must stay terminal — never reopen after commit.
		if (cap.useCount >= cap.maxUses || cap.redeemedAt) {
			return cap;
		}
		if (cap.reservationId && cap.reservationId !== input.reservationId) {
			return cap;
		}
		if (!cap.reservationId) {
			return cap;
		}
		const updated = clearReservationFields(cap);
		links[index] = updated;
		appendAuditEvent(data, {
			actor: input.actor ?? "system",
			action: `${input.kind}.setup-link.release`,
			subjectType: "setup_capability",
			subjectId: cap.id,
			outcome: "success",
			source: "api",
			organizationId: cap.organizationId,
			projectId: cap.projectId,
			environmentId: cap.environmentId,
			message: `Released ${input.kind} setup reservation after failed provisioning`,
			metadata: {
				capabilityId: cap.id,
				reservationId: input.reservationId,
			},
		});
		return updated;
	});
}

export function revokeSetupLink(
	store: ManagementStore,
	input: { capabilityId?: string; token?: string; actor?: string },
): SetupCapability {
	if (!input.capabilityId && !input.token) {
		throw new ClearanceError({
			code: "SETUP_LINK_ID_REQUIRED",
			message: "capabilityId or token required to revoke",
			stage: "setup-link.revoke",
		});
	}
	const digest = input.token ? digestToken(input.token) : undefined;
	const links = store.snapshot.setupLinks ?? [];
	const cap = links.find(
		(c) =>
			(input.capabilityId && c.id === input.capabilityId) ||
			(digest && c.digest === digest),
	);
	if (!cap) {
		throw new ClearanceError({
			code: "SETUP_LINK_NOT_FOUND",
			message: "Setup link not found",
			stage: "setup-link.revoke",
			status: 404,
		});
	}
	if (cap.revokedAt) {
		return cap;
	}
	const revokedAt = nowIso();
	store.mutate((data) => {
		const arr = ensureSetupLinksArray(data);
		const idx = arr.findIndex((c) => c.id === cap.id);
		if (idx >= 0) {
			arr[idx] = { ...arr[idx], revokedAt };
		}
	});
	const updated = (store.snapshot.setupLinks ?? []).find((c) => c.id === cap.id)!;
	recordEvent(store, {
		actor: input.actor ?? "operator",
		action: `${cap.kind}.setup-link.revoke`,
		subjectType: "setup_capability",
		subjectId: cap.id,
		outcome: "success",
		source: "cli",
		organizationId: cap.organizationId,
		projectId: cap.projectId,
		environmentId: cap.environmentId,
		message: `Revoked ${cap.kind} setup capability`,
		metadata: { capabilityId: cap.id },
	});
	return updated;
}

export function listSetupLinks(
	store: ManagementStore,
	organizationId?: string,
): Omit<SetupCapability, "digest">[] {
	const links = store.snapshot.setupLinks ?? [];
	return links
		.filter((c) => (organizationId ? c.organizationId === organizationId : true))
		.map(({ digest: _d, ...rest }) => rest);
}
