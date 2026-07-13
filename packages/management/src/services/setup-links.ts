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
import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { SetupCapability } from "../types/resources.js";
import { appendAuditEvent, recordEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { inspectOrganization } from "./core.js";

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

export function createSetupLink(
	store: ManagementStore,
	input: {
		organizationId: string;
		kind: SetupKind;
		ttlMinutes?: number;
		actor?: string;
		/** Absolute console base; defaults to CLEARANCE_CONSOLE_URL */
		baseUrl?: string;
	},
): {
	url: string;
	expiresAt: string;
	/** Raw capability — return once; never persisted */
	token: string;
	tokenFingerprint: string;
	capabilityId: string;
} {
	const org = inspectOrganization(store, input.organizationId);
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

	store.mutate((data) => {
		const links = ensureSetupLinksArray(data);
		links.push(capability);
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: `${input.kind}.setup-link.create`,
			subjectType: "setup_capability",
			subjectId: capability.id,
			outcome: "success",
			source: "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Created ${input.kind} setup capability expiring ${expiresAt}`,
			metadata: {
				expiresAt,
				tokenFingerprint: digest.slice(0, 16),
				capabilityId: capability.id,
			},
		});
	});

	const base =
		input.baseUrl ??
		process.env.CLEARANCE_CONSOLE_URL ??
		"http://localhost:3100";
	const url = `${base.replace(/\/$/, "")}/setup/${input.kind}?org=${encodeURIComponent(org.id)}&token=${token}`;

	return {
		url,
		expiresAt,
		token,
		tokenFingerprint: digest.slice(0, 16),
		capabilityId: capability.id,
	};
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
		return await store.mutateDurable((data) => {
			const links = ensureSetupLinksArray(data);
			const index = links.findIndex((candidate) => candidate.digest === digest);
			if (index < 0) {
				reject("SETUP_LINK_NOT_FOUND", "Setup link not found or invalid", 404);
			}
			const cap = links[index]!;
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
			appendAuditEvent(data, {
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
		await store.mutateDurable((data) => {
			appendAuditEvent(data, {
				actor: input.actor ?? "system",
				action: `${input.kind}.setup-link.redeem`,
				subjectType: "setup_capability",
				outcome: "failure",
				source: "api",
				message: "Setup link redemption rejected",
				metadata: { reason: code },
			});
		});
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
		return await store.mutateDurable((data) => {
			const links = ensureSetupLinksArray(data);
			const index = links.findIndex((candidate) => candidate.digest === digest);
			if (index < 0) {
				reject("SETUP_LINK_NOT_FOUND", "Setup link not found or invalid", 404);
			}
			const cap = links[index]!;
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
			appendAuditEvent(data, {
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
		await store.mutateDurable((data) => {
			appendAuditEvent(data, {
				actor: input.actor ?? "system",
				action: `${input.kind}.setup-link.reserve`,
				subjectType: "setup_capability",
				outcome: "failure",
				source: "api",
				message: "Setup link reservation rejected",
				metadata: { reason: code },
			});
		});
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
		return await store.mutateDurable((data) => {
			const links = ensureSetupLinksArray(data);
			const index = links.findIndex((candidate) => candidate.digest === digest);
			if (index < 0) {
				reject("SETUP_LINK_NOT_FOUND", "Setup link not found or invalid", 404);
			}
			const cap = links[index]!;
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
			if (input.organizationId && input.organizationId !== cap.organizationId) {
				reject("SETUP_LINK_SCOPE", "Setup link organization does not match");
			}
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
			appendAuditEvent(data, {
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
		await store.mutateDurable((data) => {
			appendAuditEvent(data, {
				actor: input.actor ?? "system",
				action: `${input.kind}.setup-link.commit`,
				subjectType: "setup_capability",
				outcome: "failure",
				source: "api",
				message: "Setup link commit rejected",
				metadata: { reason: code },
			});
		});
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
