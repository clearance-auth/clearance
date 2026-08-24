import type { AuthContext, GenericEndpointContext } from "@clearance/core";
import {
	getCurrentAdapter,
	isTransactionActive,
	queueAfterTransactionHook,
	queueBeforeTransactionCommitHook,
} from "@clearance/core/context";
import { createHash } from "@clearance/utils/hash";
import { generateRandomString } from "../crypto/random";
import { rotateFactorSessionGenerations } from "../db/factor-session-generation";
import { lockAndReadActiveUser } from "../db/user-authority";
import {
	takeBackupCodeRecoveryRepairAuthority,
} from "../plugins/two-factor/backup-codes";
import type { TwoFactorTable } from "../plugins/two-factor/types";
import { revokeTrustGeneration } from "../plugins/two-factor/utils";
import { resolveRuntimeAuthenticationPolicy } from "./authentication-policy";
import {
	createStagedAuthenticationRecoveryRepairBridge,
	digestStagedAuthenticationPolicy,
	expireStagedAuthenticationCookie,
	takeStagedAuthenticationRecoveryRepairBridge,
} from "./staged-authentication-context";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "./verification-challenge-context";

export const RECOVERY_FACTOR_REPAIR_TTL_SECONDS = 120;
export const RECOVERY_FACTOR_REPAIR_COOKIE = "recovery_factor_repair";

export const RECOVERY_FACTOR_REPAIR_STAGES = [
	"select_repair",
	"passkey_registration",
	"totp_enrollment_verification",
] as const;

export type RecoveryFactorRepairStage =
	(typeof RECOVERY_FACTOR_REPAIR_STAGES)[number];
export type RecoveryFactorRepairIntent = "passkey" | "totp";

export type RecoveryFactorRepairLineage = Readonly<{
	subjectId: string;
	repairFactor: RecoveryFactorRepairIntent;
	twoFactorTable: string;
	recoveryFactorId: string;
	consumedRecoveryCodeDigest: string;
	trustDeviceGeneration: string;
	stage: RecoveryFactorRepairStage;
	binding: string;
	rootFlowId: string;
	parentDigest: string;
	seedFingerprint: string;
	expiresAt: Date;
}>;

export type RecoveryFactorRepairCompletion = Readonly<{
	status: true;
	recoveryComplete: true;
}>;

type RecoveryMetadata = Readonly<{
	version: 1;
	stage: RecoveryFactorRepairStage;
	binding: string;
	rootFlowId: string;
	parentDigest: string;
	seedFingerprint: string;
	subjectId: string;
	projectId: string;
	environmentId: string;
	organizationId: null;
	repairFactor: RecoveryFactorRepairIntent;
	policyRevision: string;
	policyDigest: string;
	twoFactorTable: string;
	recoveryFactorId: string;
	recoveryProofDigest: string;
	consumedRecoveryCodeDigest: string;
	sourceFactorFingerprint: string;
	sourceSecretDigest: string;
	postConsumeBackupCodesDigest: string;
	passkeySessionGeneration: string;
	twoFactorSessionGeneration: string;
	trustDeviceGeneration: string;
	repairStartedAt: string;
	expiresAt: string;
}>;

type PreloadedRecoveryCapability = Readonly<{
	identifier: string;
	metadataValue: string;
	metadata: RecoveryMetadata;
}>;

type ConsumedRecoveryCapability = PreloadedRecoveryCapability & {
	state: "pending" | "committed";
	transactionAdapter: object;
};

const preloadedCapabilities = new WeakMap<object, PreloadedRecoveryCapability>();
const consumedCapabilities = new WeakMap<object, ConsumedRecoveryCapability>();

const STAGES = new Set<string>(RECOVERY_FACTOR_REPAIR_STAGES);
const INTENTS = new Set<string>(["passkey", "totp"]);
const REVISION = /^[1-9][0-9]*$/;
const DIGEST = /^[A-Za-z0-9_-]{43}$/;
const TABLE = /^[A-Za-z][A-Za-z0-9_]{0,127}$/;
const METADATA_KEYS = [
	"version",
	"stage",
	"binding",
	"rootFlowId",
	"parentDigest",
	"seedFingerprint",
	"subjectId",
	"projectId",
	"environmentId",
	"organizationId",
	"repairFactor",
	"policyRevision",
	"policyDigest",
	"twoFactorTable",
	"recoveryFactorId",
	"recoveryProofDigest",
	"consumedRecoveryCodeDigest",
	"sourceFactorFingerprint",
	"sourceSecretDigest",
	"postConsumeBackupCodesDigest",
	"passkeySessionGeneration",
	"twoFactorSessionGeneration",
	"trustDeviceGeneration",
	"repairStartedAt",
	"expiresAt",
] as const;

function text(value: unknown, maximum = 1_024): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= maximum &&
		value.trim() === value &&
		!value.includes("\0")
	);
}

function exactPlainObject(value: unknown): Record<string, unknown> | null {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return null;
	}
	if (Object.getPrototypeOf(value) !== Object.prototype) return null;
	const keys = Reflect.ownKeys(value);
	if (keys.some((key) => typeof key !== "string")) return null;
	const record: Record<string, unknown> = Object.create(null);
	for (const key of keys as string[]) {
		const descriptor = Object.getOwnPropertyDescriptor(value, key);
		if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
			return null;
		}
		record[key] = descriptor.value;
	}
	return record;
}

function exactKeys(
	value: unknown,
	keys: readonly string[],
): Record<string, unknown> | null {
	const record = exactPlainObject(value);
	if (
		!record ||
		Object.keys(record).length !== keys.length ||
		keys.some((key) => !Object.hasOwn(record, key)) ||
		Object.keys(record).some((key) => !keys.includes(key))
	) {
		return null;
	}
	return record;
}

function parseDate(value: unknown): Date | null {
	if (typeof value !== "string") return null;
	const parsed = new Date(value);
	return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value
		? parsed
		: null;
}

function validDeadline(expiresAt: Date, now = new Date()): boolean {
	return (
		Number.isFinite(expiresAt.getTime()) &&
		expiresAt > now &&
		expiresAt.getTime() - now.getTime() <=
			RECOVERY_FACTOR_REPAIR_TTL_SECONDS * 1_000
	);
}

function parseMetadata(value: unknown, now = new Date()): RecoveryMetadata | null {
	if (typeof value !== "string" || value.length > 8_192) return null;
	let decoded: unknown;
	try {
		decoded = JSON.parse(value);
	} catch {
		return null;
	}
	const record = exactKeys(decoded, METADATA_KEYS);
	if (
		!record ||
		record.version !== 1 ||
		typeof record.stage !== "string" ||
		!STAGES.has(record.stage) ||
		!text(record.binding, 512) ||
		!text(record.rootFlowId, 128) ||
		typeof record.parentDigest !== "string" ||
		!DIGEST.test(record.parentDigest) ||
		typeof record.seedFingerprint !== "string" ||
		!DIGEST.test(record.seedFingerprint) ||
		!text(record.subjectId) ||
		!text(record.projectId) ||
		!text(record.environmentId) ||
		record.organizationId !== null ||
		typeof record.repairFactor !== "string" ||
		!INTENTS.has(record.repairFactor) ||
		typeof record.policyRevision !== "string" ||
		!REVISION.test(record.policyRevision) ||
		typeof record.policyDigest !== "string" ||
		!DIGEST.test(record.policyDigest) ||
		typeof record.twoFactorTable !== "string" ||
		!TABLE.test(record.twoFactorTable) ||
		!text(record.recoveryFactorId, 512) ||
		typeof record.recoveryProofDigest !== "string" ||
		!DIGEST.test(record.recoveryProofDigest) ||
		typeof record.consumedRecoveryCodeDigest !== "string" ||
		!DIGEST.test(record.consumedRecoveryCodeDigest) ||
		typeof record.sourceFactorFingerprint !== "string" ||
		!DIGEST.test(record.sourceFactorFingerprint) ||
		typeof record.sourceSecretDigest !== "string" ||
		!DIGEST.test(record.sourceSecretDigest) ||
		typeof record.postConsumeBackupCodesDigest !== "string" ||
		!DIGEST.test(record.postConsumeBackupCodesDigest) ||
		!text(record.passkeySessionGeneration, 128) ||
		!text(record.twoFactorSessionGeneration, 128) ||
		!text(record.trustDeviceGeneration, 128)
	) {
		return null;
	}
	const repairStartedAt = parseDate(record.repairStartedAt);
	const expiresAt = parseDate(record.expiresAt);
	if (
		!repairStartedAt ||
		!expiresAt ||
		!validDeadline(expiresAt, now) ||
		repairStartedAt >= expiresAt
	) {
		return null;
	}
	return record as unknown as RecoveryMetadata;
}

async function digest(value: string): Promise<string> {
	return createHash("SHA-256", "base64urlnopad").digest(value);
}

async function factorValueDigest(
	label: "secret" | "backup-codes",
	value: string,
): Promise<string> {
	return digest(
		JSON.stringify(["two-factor-recovery-repair-factor:v1", label, value]),
	);
}

async function capabilityIdentifier(bearer: string): Promise<string> {
	return `recovery-factor-repair:v1:${await digest(
		`recovery-factor-repair:v1:${bearer}`,
	)}`;
}

function challengePurpose(stage: RecoveryFactorRepairStage): string {
	return `recovery-factor-repair.${stage}`;
}

function recoveryCookie(context: AuthContext, expiresAt?: Date) {
	const remaining = expiresAt
		? Math.ceil((expiresAt.getTime() - Date.now()) / 1_000)
		: RECOVERY_FACTOR_REPAIR_TTL_SECONDS;
	return context.createAuthCookie(RECOVERY_FACTOR_REPAIR_COOKIE, {
		httpOnly: true,
		sameSite: "lax",
		maxAge: Math.max(
			1,
			Math.min(RECOVERY_FACTOR_REPAIR_TTL_SECONDS, remaining),
		),
	});
}

function lineageView(metadata: RecoveryMetadata): RecoveryFactorRepairLineage {
	return Object.freeze({
		subjectId: metadata.subjectId,
		repairFactor: metadata.repairFactor,
		twoFactorTable: metadata.twoFactorTable,
		recoveryFactorId: metadata.recoveryFactorId,
		consumedRecoveryCodeDigest: metadata.consumedRecoveryCodeDigest,
		trustDeviceGeneration: metadata.trustDeviceGeneration,
		stage: metadata.stage,
		binding: metadata.binding,
		rootFlowId: metadata.rootFlowId,
		parentDigest: metadata.parentDigest,
		seedFingerprint: metadata.seedFingerprint,
		expiresAt: new Date(metadata.expiresAt),
	});
}

export function createRecoveryFactorRepairBinding(
	lineage: RecoveryFactorRepairLineage,
	parts: readonly string[],
): Promise<string> {
	if (
		!text(lineage.subjectId) ||
		!TABLE.test(lineage.twoFactorTable) ||
		!text(lineage.recoveryFactorId, 512) ||
		!DIGEST.test(lineage.consumedRecoveryCodeDigest) ||
		!text(lineage.trustDeviceGeneration, 128) ||
		!text(lineage.rootFlowId, 128) ||
		!DIGEST.test(lineage.parentDigest) ||
		!DIGEST.test(lineage.seedFingerprint) ||
		!Number.isFinite(lineage.expiresAt.getTime()) ||
		parts.length === 0 ||
		parts.some((part) => !text(part, 65_536))
	) {
		throw new Error("Invalid recovery repair lineage");
	}
	return digest(
		JSON.stringify([
			"recovery-factor-repair-binding:v1",
			lineage.subjectId,
			lineage.repairFactor,
			lineage.twoFactorTable,
			lineage.recoveryFactorId,
			lineage.consumedRecoveryCodeDigest,
			lineage.trustDeviceGeneration,
			lineage.rootFlowId,
			lineage.seedFingerprint,
			lineage.expiresAt.toISOString(),
			...parts,
		]),
	);
}

export async function createRecoveryTOTPEnrollmentBinding(
	lineage: RecoveryFactorRepairLineage,
	factor: Pick<
		TwoFactorTable,
		"id" | "pendingSecret" | "pendingBackupCodes" | "trustDeviceGeneration"
	>,
): Promise<string> {
	if (
		factor.id !== lineage.recoveryFactorId ||
		typeof factor.pendingSecret !== "string" ||
		factor.pendingSecret.length === 0 ||
		typeof factor.pendingBackupCodes !== "string" ||
		factor.pendingBackupCodes.length === 0 ||
		factor.trustDeviceGeneration !== lineage.trustDeviceGeneration
	) {
		throw new Error("Invalid recovery TOTP enrollment state");
	}
	const enrollmentDigest = await digest(
		JSON.stringify([
			"recovery-totp-enrollment:v1",
			factor.id,
			factor.pendingSecret,
			factor.pendingBackupCodes,
		]),
	);
	return createRecoveryFactorRepairBinding(lineage, [
		"totp-enrollment:v1",
		factor.id,
		enrollmentDigest,
	]);
}

function assertRecoveryConfiguration(ctx: GenericEndpointContext): void {
	if (
		typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function" ||
		(ctx.context.options.secondaryStorage !== undefined &&
			ctx.context.options.session?.storeSessionInDatabase !== true)
	) {
		throw new Error(
			"Recovery repair requires rollback-capable database-backed sessions",
		);
	}
}

async function policyStillAuthorizesRepair(
	ctx: GenericEndpointContext,
	snapshot: Readonly<{
		subjectId: string;
		projectId: string;
		environmentId: string;
		policyRevision: string;
		policyDigest: string;
		repairFactor: RecoveryFactorRepairIntent;
	}>,
): Promise<boolean> {
	try {
		const adapter = await getCurrentAdapter(ctx.context.adapter);
		const resolved = await resolveRuntimeAuthenticationPolicy(
			ctx.context.options,
			{
				subjectId: snapshot.subjectId,
				minimumRevision: snapshot.policyRevision,
				transaction: adapter,
			},
		);
		return (
			resolved.scope.projectId === snapshot.projectId &&
			resolved.scope.environmentId === snapshot.environmentId &&
			resolved.revision === snapshot.policyRevision &&
			(await digestStagedAuthenticationPolicy(resolved.effective)) ===
				snapshot.policyDigest &&
			resolved.effective.allowedFactors[snapshot.repairFactor] === true &&
			(resolved.effective.minimumAssurance !== "phishing_resistant" ||
				snapshot.repairFactor === "passkey")
		);
	} catch {
		return false;
	}
}

async function recoveryStartStateIsExact(
	ctx: GenericEndpointContext,
	metadata: RecoveryMetadata,
): Promise<boolean> {
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const user = await adapter.findOne<Record<string, unknown>>({
		model: "user",
		where: [{ field: "id", value: metadata.subjectId }],
	});
	const factor = await adapter.findOne<TwoFactorTable>({
		model: metadata.twoFactorTable,
		where: [
			{ field: "id", value: metadata.recoveryFactorId },
			{ field: "userId", value: metadata.subjectId },
		],
	});
	if (
		!user ||
		!factor ||
		user.twoFactorEnabled !== true ||
		user.passkeySessionGeneration !== metadata.passkeySessionGeneration ||
		user.twoFactorSessionGeneration !== metadata.twoFactorSessionGeneration ||
		factor.trustDeviceGeneration !== metadata.trustDeviceGeneration ||
		(typeof factor.secret !== "string" ||
			(await factorValueDigest("secret", factor.secret)) !==
				metadata.sourceSecretDigest) ||
		(typeof factor.backupCodes !== "string" ||
			(await factorValueDigest("backup-codes", factor.backupCodes)) !==
				metadata.postConsumeBackupCodesDigest) ||
		(metadata.repairFactor === "passkey"
			? factor.verified !== true
			: factor.verified !== false ||
				factor.pendingSecret != null ||
				factor.pendingBackupCodes != null)
	) {
		return false;
	}
	if (
		(await adapter.count({
			model: "session",
			where: [{ field: "userId", value: metadata.subjectId }],
		})) !== 0
	) {
		return false;
	}
	return (
		metadata.repairFactor !== "passkey" ||
		(await adapter.count({
			model: "passkey",
			where: [{ field: "userId", value: metadata.subjectId }],
		})) === 0
	);
}

/**
 * Atomically converts primary-plus-recovery-code proof into a recovery-only
 * capability. This operation owns every destructive lifecycle mutation and
 * never creates a session, token, or trusted-device artifact.
 */
export async function startRecoveryFactorRepair(
	ctx: GenericEndpointContext,
	input: Readonly<{
		stagedRecoveryBridge: object;
		recoveryProofAuthority: object;
		repairFactor: RecoveryFactorRepairIntent;
	}>,
): Promise<Readonly<{ status: true; repairFactor: RecoveryFactorRepairIntent; expiresAt: Date }>> {
	assertRecoveryConfiguration(ctx);
	if (
		!(await isTransactionActive(ctx.context.adapter)) ||
		!INTENTS.has(input.repairFactor)
	) {
		throw new Error("Invalid recovery repair transaction");
	}
	const twoFactorPlugin = ctx.context.getPlugin("two-factor");
	const twoFactorOptions = twoFactorPlugin?.options as
		| {
				twoFactorTable?: string | undefined;
				backupCodeOptions?: {
					storeBackupCodes?: unknown;
				};
				accountLockout?: {
					enabled?: unknown;
				};
		  }
		| undefined;
	if (
		!twoFactorPlugin ||
		twoFactorOptions?.backupCodeOptions?.storeBackupCodes !== "hashed" ||
		twoFactorOptions.accountLockout?.enabled === false
	) {
		throw new Error("Recovery repair requires one-way recovery-code storage");
	}
	const configuredTwoFactorTable =
		twoFactorOptions.twoFactorTable ?? "twoFactor";
	const staged = await takeStagedAuthenticationRecoveryRepairBridge(
		ctx,
		input.stagedRecoveryBridge,
	);
	const proof = await takeBackupCodeRecoveryRepairAuthority(
		ctx,
		input.recoveryProofAuthority,
	);
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	if (
		!staged ||
		!proof ||
		staged.transactionAdapter !== adapter ||
		staged.subjectId !== proof.subjectId ||
		staged.repairFactor !== input.repairFactor ||
		!TABLE.test(proof.twoFactorTable) ||
		proof.twoFactorTable !== configuredTwoFactorTable ||
		!validDeadline(
			new Date(
				Math.min(
					staged.expiresAt.getTime(),
					Date.now() + RECOVERY_FACTOR_REPAIR_TTL_SECONDS * 1_000,
				),
			),
		)
	) {
		throw new Error("Invalid recovery repair authority");
	}
	if (!(await policyStillAuthorizesRepair(ctx, staged))) {
		throw new Error("Recovery repair policy changed");
	}
	const user = await lockAndReadActiveUser(adapter, staged.subjectId);
	const factor = await adapter.findOne<TwoFactorTable>({
		model: proof.twoFactorTable,
		where: [
			{ field: "id", value: proof.recoveryFactorId },
			{ field: "userId", value: proof.subjectId },
		],
	});
	if (
		!user ||
		!factor ||
		(user as Record<string, unknown>).twoFactorEnabled !== true ||
		factor.verified !== true ||
		typeof factor.secret !== "string" ||
		typeof factor.backupCodes !== "string" ||
		factor.trustDeviceGeneration !== proof.sourceTrustDeviceGeneration ||
		(await factorValueDigest("secret", factor.secret)) !==
			proof.sourceSecretDigest ||
		(await factorValueDigest("backup-codes", factor.backupCodes)) !==
			proof.postConsumeBackupCodesDigest
	) {
		throw new Error("Recovery factor proof changed");
	}

	const passkeySessionGeneration = generateRandomString(32);
	const twoFactorSessionGeneration = generateRandomString(32);
	const trustDeviceGeneration = generateRandomString(32);
	const rotatedUser = await rotateFactorSessionGenerations(
		adapter,
		staged.subjectId,
		(user as Record<string, unknown>).passkeySessionGeneration as
			| string
			| null
			| undefined,
		(user as Record<string, unknown>).twoFactorSessionGeneration as
			| string
			| null
			| undefined,
		passkeySessionGeneration,
		twoFactorSessionGeneration,
	);
	if (!rotatedUser) throw new Error("Recovery user lifecycle changed");
	const rotatedFactor = await adapter.incrementOne<TwoFactorTable>({
		model: proof.twoFactorTable,
		where: [
			{ field: "id", value: factor.id },
			{ field: "userId", value: staged.subjectId },
			{ field: "secret", value: factor.secret },
			{ field: "backupCodes", value: factor.backupCodes },
			{ field: "verified", value: factor.verified ?? null },
			{
				field: "trustDeviceGeneration",
				value: proof.sourceTrustDeviceGeneration,
			},
		],
		increment: {},
		set: {
			trustDeviceGeneration,
			verified: input.repairFactor === "totp" ? false : true,
			failedVerificationCount: 0,
			activeVerificationReservations: "[]",
			lockedUntil: null,
			...(input.repairFactor === "totp"
				? {
						pendingSecret: null,
						pendingBackupCodes: null,
						lastUsedTotpCounter: -1,
					}
				: {}),
		},
	});
	if (!rotatedFactor) throw new Error("Recovery factor lifecycle changed");

	await revokeTrustGeneration(
		ctx,
		staged.subjectId,
		proof.sourceTrustDeviceGeneration,
	);
	if (
		proof.sourceTrustDeviceGeneration &&
		(!ctx.context.options.secondaryStorage ||
			ctx.context.options.verification?.storeInDatabase === true)
	) {
		await adapter.deleteMany({
			model: "verification",
			where: [
				{
					field: "value",
					value: `${staged.subjectId}!${proof.sourceTrustDeviceGeneration}`,
				},
			],
		});
	}
	await ctx.context.internalAdapter.deleteUserSessions(staged.subjectId);
	if (input.repairFactor === "passkey") {
		await adapter.deleteMany({
			model: "passkey",
			where: [{ field: "userId", value: staged.subjectId }],
		});
	}

	const repairStartedAt = new Date();
	const expiresAt = new Date(
		Math.min(
			staged.expiresAt.getTime(),
			repairStartedAt.getTime() + RECOVERY_FACTOR_REPAIR_TTL_SECONDS * 1_000,
		),
	);
	const bearer = generateRandomString(48);
	const identifier = await capabilityIdentifier(bearer);
	const metadata: RecoveryMetadata = Object.freeze({
		version: 1,
		stage: "select_repair",
		binding: "initial",
		rootFlowId: staged.rootFlowId,
		parentDigest: await digest(
			`recovery-factor-repair-parent:v1:${staged.primaryCapabilityIdentifier}`,
		),
		seedFingerprint: staged.seedFingerprint,
		subjectId: staged.subjectId,
		projectId: staged.projectId,
		environmentId: staged.environmentId,
		organizationId: null,
		repairFactor: input.repairFactor,
		policyRevision: staged.policyRevision,
		policyDigest: staged.policyDigest,
		twoFactorTable: proof.twoFactorTable,
		recoveryFactorId: proof.recoveryFactorId,
		recoveryProofDigest: proof.recoveryProofDigest,
		consumedRecoveryCodeDigest: proof.consumedRecoveryCodeDigest,
		sourceFactorFingerprint: proof.sourceFactorFingerprint,
		sourceSecretDigest: proof.sourceSecretDigest,
		postConsumeBackupCodesDigest: proof.postConsumeBackupCodesDigest,
		passkeySessionGeneration,
		twoFactorSessionGeneration,
		trustDeviceGeneration,
		repairStartedAt: repairStartedAt.toISOString(),
		expiresAt: expiresAt.toISOString(),
	});
	if (!(await recoveryStartStateIsExact(ctx, metadata))) {
		throw new Error("Recovery repair mutation was incomplete");
	}
	await createInternalVerificationChallenge(
		ctx.context.internalAdapter,
		{ purpose: challengePurpose(metadata.stage), subject: metadata.subjectId },
		{ identifier, value: JSON.stringify(metadata), expiresAt },
	);
	await queueBeforeTransactionCommitHook(async () => {
		if (
			!validDeadline(expiresAt) ||
			!(await policyStillAuthorizesRepair(ctx, metadata)) ||
			!(await recoveryStartStateIsExact(ctx, metadata))
		) {
			throw new Error("Recovery repair authority changed before commit");
		}
	}, ctx.context.adapter);
	const cookie = recoveryCookie(ctx.context, expiresAt);
	await queueAfterTransactionHook(async () => {
		await ctx.setSignedCookie(
			cookie.name,
			bearer,
			ctx.context.secret,
			cookie.attributes,
		);
	}, ctx.context.adapter);
	await expireStagedAuthenticationCookie(ctx);
	return Object.freeze({
		status: true,
		repairFactor: input.repairFactor,
		expiresAt: new Date(expiresAt),
	});
}

/**
 * Irreversibly converts a consumed normal staged authority into a recovery-only
 * bridge. The bridge becomes usable only after this transaction commits.
 */
export async function createRecoveryFactorRepairBridge(
	ctx: GenericEndpointContext,
	stagedAuthority: object,
	repairFactor: RecoveryFactorRepairIntent,
): Promise<object> {
	assertRecoveryConfiguration(ctx);
	if (
		!(await isTransactionActive(ctx.context.adapter)) ||
		!INTENTS.has(repairFactor)
	) {
		throw new Error("Invalid recovery repair bridge transaction");
	}
	return createStagedAuthenticationRecoveryRepairBridge(
		ctx,
		stagedAuthority,
		repairFactor,
	);
}

export async function preloadRecoveryFactorRepairCapability(
	ctx: GenericEndpointContext,
	expected: Readonly<{
		stage?: RecoveryFactorRepairStage | undefined;
		stages?: readonly RecoveryFactorRepairStage[] | undefined;
		binding?: string | undefined;
		repairFactor?: RecoveryFactorRepairIntent | undefined;
	}>,
): Promise<object | null> {
	const stages =
		expected.stages ?? (expected.stage === undefined ? [] : [expected.stage]);
	if (
		(expected.stage !== undefined && expected.stages !== undefined) ||
		stages.length === 0 ||
		stages.length > RECOVERY_FACTOR_REPAIR_STAGES.length ||
		stages.some((stage) => !STAGES.has(stage)) ||
		new Set(stages).size !== stages.length ||
		(expected.binding !== undefined && !text(expected.binding, 512)) ||
		(expected.repairFactor !== undefined && !INTENTS.has(expected.repairFactor))
	) {
		return null;
	}
	const cookie = recoveryCookie(ctx.context);
	const bearer = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
	if (!bearer || !text(bearer, 512)) return null;
	const identifier = await capabilityIdentifier(bearer);
	const verification =
		await ctx.context.internalAdapter.findVerificationValueAndPruneExpired(identifier);
	const metadata = parseMetadata(verification?.value);
	if (
		!verification ||
		!metadata ||
		!stages.includes(metadata.stage) ||
		(expected.binding !== undefined && metadata.binding !== expected.binding) ||
		(expected.repairFactor !== undefined &&
			metadata.repairFactor !== expected.repairFactor) ||
		!(verification.expiresAt instanceof Date) ||
		verification.expiresAt.getTime() !== new Date(metadata.expiresAt).getTime()
	) {
		return null;
	}
	const opaque = Object.freeze({});
	preloadedCapabilities.set(opaque, {
		identifier,
		metadataValue: verification.value,
		metadata,
	});
	return opaque;
}

export async function consumePreloadedRecoveryFactorRepairCapability(
	ctx: GenericEndpointContext,
	preloaded: object,
): Promise<object | null> {
	const snapshot = preloadedCapabilities.get(preloaded);
	if (!snapshot) return null;
	preloadedCapabilities.delete(preloaded);
	if (!(await isTransactionActive(ctx.context.adapter))) return null;
	const consumed = await consumeInternalVerificationChallenge(
		ctx.context.internalAdapter,
		{
			purpose: challengePurpose(snapshot.metadata.stage),
			subject: snapshot.metadata.subjectId,
			identifier: snapshot.identifier,
		},
	);
	if (
		!consumed ||
		consumed.value !== snapshot.metadataValue ||
		consumed.expiresAt.getTime() !==
			new Date(snapshot.metadata.expiresAt).getTime() ||
		!parseMetadata(consumed.value)
	) {
		return null;
	}
	const transactionAdapter = await getCurrentAdapter(ctx.context.adapter);
	const opaque = Object.freeze({});
	const authority: ConsumedRecoveryCapability = {
		...snapshot,
		state: "pending",
		transactionAdapter,
	};
	consumedCapabilities.set(opaque, authority);
	await queueAfterTransactionHook(async () => {
		const current = consumedCapabilities.get(opaque);
		if (current === authority && current.state === "pending") {
			current.state = "committed";
		}
	}, ctx.context.adapter);
	return opaque;
}

async function takePendingAuthority(
	ctx: GenericEndpointContext,
	authority: object,
): Promise<ConsumedRecoveryCapability | null> {
	const snapshot = consumedCapabilities.get(authority);
	if (!snapshot || snapshot.state !== "pending") return null;
	consumedCapabilities.delete(authority);
	if (
		!(await isTransactionActive(ctx.context.adapter)) ||
		(await getCurrentAdapter(ctx.context.adapter)) !== snapshot.transactionAdapter
	) {
		return null;
	}
	return snapshot;
}

async function takeCommittedAuthority(
	ctx: GenericEndpointContext,
	authority: object,
): Promise<ConsumedRecoveryCapability | null> {
	const snapshot = consumedCapabilities.get(authority);
	if (!snapshot || snapshot.state !== "committed") return null;
	consumedCapabilities.delete(authority);
	if (!(await isTransactionActive(ctx.context.adapter))) return null;
	return snapshot;
}

export function inspectRecoveryFactorRepairAuthority(
	authority: object,
): RecoveryFactorRepairLineage | null {
	const snapshot = consumedCapabilities.get(authority);
	return snapshot ? lineageView(snapshot.metadata) : null;
}

export async function recoveryFactorRepairSelectionAuthorityIsExact(
	ctx: GenericEndpointContext,
	authority: object,
): Promise<boolean> {
	const snapshot = consumedCapabilities.get(authority);
	if (
		!snapshot ||
		snapshot.state !== "pending" ||
		snapshot.metadata.stage !== "select_repair" ||
		!(await isTransactionActive(ctx.context.adapter)) ||
		(await getCurrentAdapter(ctx.context.adapter)) !== snapshot.transactionAdapter ||
		!validDeadline(new Date(snapshot.metadata.expiresAt)) ||
		!(await policyStillAuthorizesRepair(ctx, snapshot.metadata)) ||
		!(await lockAndReadActiveUser(
			await getCurrentAdapter(ctx.context.adapter),
			snapshot.metadata.subjectId,
		))
	) {
		return false;
	}
	return recoveryStartStateIsExact(ctx, snapshot.metadata);
}

async function recoveryTOTPAttemptStateIsExact(
	ctx: GenericEndpointContext,
	metadata: RecoveryMetadata,
): Promise<boolean> {
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const user = await adapter.findOne<Record<string, unknown>>({
		model: "user",
		where: [{ field: "id", value: metadata.subjectId }],
	});
	const factor = await adapter.findOne<TwoFactorTable>({
		model: metadata.twoFactorTable,
		where: [
			{ field: "id", value: metadata.recoveryFactorId },
			{ field: "userId", value: metadata.subjectId },
		],
	});
	if (
		!user ||
		!factor ||
		user.twoFactorEnabled !== true ||
		user.passkeySessionGeneration !== metadata.passkeySessionGeneration ||
		user.twoFactorSessionGeneration !== metadata.twoFactorSessionGeneration ||
		factor.trustDeviceGeneration !== metadata.trustDeviceGeneration ||
		factor.verified !== false ||
		typeof factor.secret !== "string" ||
		typeof factor.backupCodes !== "string" ||
		typeof factor.pendingSecret !== "string" ||
		typeof factor.pendingBackupCodes !== "string" ||
		factor.lastUsedTotpCounter !== -1 ||
		(await factorValueDigest("secret", factor.secret)) !==
			metadata.sourceSecretDigest ||
		(await factorValueDigest("backup-codes", factor.backupCodes)) !==
			metadata.postConsumeBackupCodesDigest ||
		(await createRecoveryTOTPEnrollmentBinding(lineageView(metadata), factor)) !==
			metadata.binding
	) {
		return false;
	}
	return (
		await adapter.count({
			model: "session",
			where: [{ field: "userId", value: metadata.subjectId }],
		})
	) === 0;
}

export async function recoveryTOTPVerificationAuthorityIsExact(
	ctx: GenericEndpointContext,
	authority: object,
): Promise<boolean> {
	const snapshot = consumedCapabilities.get(authority);
	if (
		!snapshot ||
		snapshot.metadata.stage !== "totp_enrollment_verification" ||
		snapshot.metadata.repairFactor !== "totp" ||
		!(await isTransactionActive(ctx.context.adapter)) ||
		!validDeadline(new Date(snapshot.metadata.expiresAt)) ||
		!(await policyStillAuthorizesRepair(ctx, snapshot.metadata)) ||
		!(await lockAndReadActiveUser(
			await getCurrentAdapter(ctx.context.adapter),
			snapshot.metadata.subjectId,
		))
	) {
		return false;
	}
	return recoveryTOTPAttemptStateIsExact(ctx, snapshot.metadata);
}

/**
 * Replaces a failed one-use TOTP verification capability with another
 * digest-only capability for the exact same recovery enrollment. Failure
 * accounting belongs in this same transaction, so callers cannot publish a
 * retry without first durably settling the attempt reservation.
 */
export async function reissueRecoveryTOTPVerificationCapability(
	ctx: GenericEndpointContext,
	authority: object,
	binding: string,
): Promise<RecoveryFactorRepairLineage> {
	assertRecoveryConfiguration(ctx);
	const snapshot = await takeCommittedAuthority(ctx, authority);
	if (
		!snapshot ||
		snapshot.metadata.stage !== "totp_enrollment_verification" ||
		snapshot.metadata.repairFactor !== "totp" ||
		binding !== snapshot.metadata.binding ||
		!text(binding, 512) ||
		!validDeadline(new Date(snapshot.metadata.expiresAt)) ||
		!(await policyStillAuthorizesRepair(ctx, snapshot.metadata)) ||
		!(await lockAndReadActiveUser(
			await getCurrentAdapter(ctx.context.adapter),
			snapshot.metadata.subjectId,
		)) ||
		!(await recoveryTOTPAttemptStateIsExact(ctx, snapshot.metadata))
	) {
		throw new Error("Invalid recovery TOTP retry authority");
	}

	const bearer = generateRandomString(48);
	const identifier = await capabilityIdentifier(bearer);
	const metadata: RecoveryMetadata = Object.freeze({
		...snapshot.metadata,
		parentDigest: await digest(snapshot.identifier),
	});
	const expiresAt = new Date(metadata.expiresAt);
	await createInternalVerificationChallenge(
		ctx.context.internalAdapter,
		{ purpose: challengePurpose(metadata.stage), subject: metadata.subjectId },
		{ identifier, value: JSON.stringify(metadata), expiresAt },
	);
	await queueBeforeTransactionCommitHook(async () => {
		if (
			!validDeadline(expiresAt) ||
			!(await policyStillAuthorizesRepair(ctx, metadata)) ||
			!(await recoveryTOTPAttemptStateIsExact(ctx, metadata))
		) {
			throw new Error("Recovery TOTP retry authority changed before commit");
		}
	}, ctx.context.adapter);
	const cookie = recoveryCookie(ctx.context, expiresAt);
	await queueAfterTransactionHook(async () => {
		await ctx.setSignedCookie(
			cookie.name,
			bearer,
			ctx.context.secret,
			cookie.attributes,
		);
	}, ctx.context.adapter);
	return lineageView(metadata);
}

/** Returns an ordinary failed WebAuthn proof to the recovery-only options stage. */
export async function restartRecoveryPasskeyRegistrationCapability(
	ctx: GenericEndpointContext,
	authority: object,
): Promise<RecoveryFactorRepairLineage> {
	assertRecoveryConfiguration(ctx);
	const snapshot = await takeCommittedAuthority(ctx, authority);
	if (
		!snapshot ||
		snapshot.metadata.stage !== "passkey_registration" ||
		snapshot.metadata.repairFactor !== "passkey" ||
		!validDeadline(new Date(snapshot.metadata.expiresAt)) ||
		!(await policyStillAuthorizesRepair(ctx, snapshot.metadata)) ||
		!(await lockAndReadActiveUser(
			await getCurrentAdapter(ctx.context.adapter),
			snapshot.metadata.subjectId,
		)) ||
		!(await recoveryStartStateIsExact(ctx, snapshot.metadata))
	) {
		throw new Error("Invalid recovery passkey retry authority");
	}

	const bearer = generateRandomString(48);
	const identifier = await capabilityIdentifier(bearer);
	const metadata: RecoveryMetadata = Object.freeze({
		...snapshot.metadata,
		stage: "select_repair",
		binding: "initial",
		parentDigest: await digest(snapshot.identifier),
	});
	const expiresAt = new Date(metadata.expiresAt);
	await createInternalVerificationChallenge(
		ctx.context.internalAdapter,
		{ purpose: challengePurpose(metadata.stage), subject: metadata.subjectId },
		{ identifier, value: JSON.stringify(metadata), expiresAt },
	);
	await queueBeforeTransactionCommitHook(async () => {
		if (
			!validDeadline(expiresAt) ||
			!(await policyStillAuthorizesRepair(ctx, metadata)) ||
			!(await recoveryStartStateIsExact(ctx, metadata))
		) {
			throw new Error("Recovery passkey retry authority changed before commit");
		}
	}, ctx.context.adapter);
	const cookie = recoveryCookie(ctx.context, expiresAt);
	await queueAfterTransactionHook(async () => {
		await ctx.setSignedCookie(
			cookie.name,
			bearer,
			ctx.context.secret,
			cookie.attributes,
		);
	}, ctx.context.adapter);
	return lineageView(metadata);
}

export async function rotateRecoveryFactorRepairCapability(
	ctx: GenericEndpointContext,
	authority: object,
	next: Readonly<{ stage: RecoveryFactorRepairStage; binding: string }>,
): Promise<RecoveryFactorRepairLineage> {
	const snapshot = await takePendingAuthority(ctx, authority);
	const transition =
		snapshot?.metadata.stage === "select_repair" &&
		((snapshot.metadata.repairFactor === "passkey" &&
			next.stage === "passkey_registration") ||
			(snapshot.metadata.repairFactor === "totp" &&
				next.stage === "totp_enrollment_verification"));
	if (!snapshot || !transition || !text(next.binding, 512)) {
		throw new Error("Invalid recovery repair transition");
	}
	const expiresAt = new Date(snapshot.metadata.expiresAt);
	if (
		!validDeadline(expiresAt) ||
		!(await policyStillAuthorizesRepair(ctx, snapshot.metadata))
	) {
		throw new Error("Recovery repair authority expired");
	}
	const bearer = generateRandomString(48);
	const identifier = await capabilityIdentifier(bearer);
	const metadata: RecoveryMetadata = Object.freeze({
		...snapshot.metadata,
		stage: next.stage,
		binding: next.binding,
		parentDigest: await digest(snapshot.identifier),
	});
	await createInternalVerificationChallenge(
		ctx.context.internalAdapter,
		{ purpose: challengePurpose(metadata.stage), subject: metadata.subjectId },
		{ identifier, value: JSON.stringify(metadata), expiresAt },
	);
	await queueBeforeTransactionCommitHook(async () => {
		if (
			!validDeadline(expiresAt) ||
			!(await policyStillAuthorizesRepair(ctx, metadata))
		) {
			throw new Error("Recovery repair authority expired before commit");
		}
	}, ctx.context.adapter);
	const cookie = recoveryCookie(ctx.context, expiresAt);
	await queueAfterTransactionHook(async () => {
		await ctx.setSignedCookie(
			cookie.name,
			bearer,
			ctx.context.secret,
			cookie.attributes,
		);
	}, ctx.context.adapter);
	return lineageView(metadata);
}

async function recoveryCompletionStateIsExact(
	ctx: GenericEndpointContext,
	metadata: RecoveryMetadata,
	repairedFactorId: string,
	requireNoSessions = true,
): Promise<boolean> {
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const user = await adapter.findOne<Record<string, unknown>>({
		model: "user",
		where: [{ field: "id", value: metadata.subjectId }],
	});
	const factor = await adapter.findOne<TwoFactorTable>({
		model: metadata.twoFactorTable,
		where: [
			{ field: "id", value: metadata.recoveryFactorId },
			{ field: "userId", value: metadata.subjectId },
		],
	});
	if (
		!user ||
		!factor ||
		user.twoFactorEnabled !== true ||
		user.passkeySessionGeneration !== metadata.passkeySessionGeneration ||
		user.twoFactorSessionGeneration !== metadata.twoFactorSessionGeneration ||
		factor.trustDeviceGeneration !== metadata.trustDeviceGeneration
	) {
		return false;
	}
	if (
		requireNoSessions &&
		(await adapter.count({
			model: "session",
			where: [{ field: "userId", value: metadata.subjectId }],
		})) !== 0
	) {
		return false;
	}
	if (metadata.repairFactor === "passkey") {
		const passkey = await adapter.findOne<Record<string, unknown>>({
			model: "passkey",
			where: [
				{ field: "id", value: repairedFactorId },
				{ field: "userId", value: metadata.subjectId },
			],
		});
		const createdAt =
			passkey?.createdAt instanceof Date ? passkey.createdAt : null;
		return (
			Boolean(passkey) &&
			factor.verified === true &&
			typeof factor.secret === "string" &&
			typeof factor.backupCodes === "string" &&
			(await factorValueDigest("secret", factor.secret)) ===
				metadata.sourceSecretDigest &&
			(await factorValueDigest("backup-codes", factor.backupCodes)) ===
				metadata.postConsumeBackupCodesDigest &&
			(!createdAt || createdAt >= new Date(metadata.repairStartedAt)) &&
			(await adapter.count({
				model: "passkey",
				where: [{ field: "userId", value: metadata.subjectId }],
			})) === 1
		);
	}
	return (
		repairedFactorId === metadata.recoveryFactorId &&
		factor.verified === true &&
		factor.pendingSecret == null &&
		factor.pendingBackupCodes == null &&
		typeof factor.secret === "string" &&
		typeof factor.backupCodes === "string" &&
		typeof factor.lastUsedTotpCounter === "number" &&
		Number.isSafeInteger(factor.lastUsedTotpCounter) &&
		factor.lastUsedTotpCounter >= 0 &&
		(await factorValueDigest("secret", factor.secret)) !==
			metadata.sourceSecretDigest &&
		(await factorValueDigest("backup-codes", factor.backupCodes)) !==
			metadata.postConsumeBackupCodesDigest &&
		user.twoFactorEnabled === true
	);
}

export async function completeRecoveryFactorRepair(
	ctx: GenericEndpointContext,
	authority: object,
	input: Readonly<{
		binding: string;
		repairFactor: RecoveryFactorRepairIntent;
		repairedFactorId: string;
	}>,
): Promise<RecoveryFactorRepairCompletion> {
	assertRecoveryConfiguration(ctx);
	const snapshot = await takeCommittedAuthority(ctx, authority);
	const record = exactKeys(input, [
		"binding",
		"repairFactor",
		"repairedFactorId",
	]);
	const expectedStage =
		snapshot?.metadata.repairFactor === "passkey"
			? "passkey_registration"
			: "totp_enrollment_verification";
	if (
		!snapshot ||
		!record ||
		snapshot.metadata.stage !== expectedStage ||
		record.binding !== snapshot.metadata.binding ||
		record.repairFactor !== snapshot.metadata.repairFactor ||
		!text(record.binding, 512) ||
		!text(record.repairedFactorId, 512) ||
		!validDeadline(new Date(snapshot.metadata.expiresAt)) ||
		!(await policyStillAuthorizesRepair(ctx, snapshot.metadata)) ||
		!(await lockAndReadActiveUser(
			await getCurrentAdapter(ctx.context.adapter),
			snapshot.metadata.subjectId,
		)) ||
		!(await recoveryCompletionStateIsExact(
			ctx,
			snapshot.metadata,
			record.repairedFactorId,
			false,
		))
	) {
		throw new Error("Recovery repair completion preconditions failed");
	}

	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const user = await lockAndReadActiveUser(
		adapter,
		snapshot.metadata.subjectId,
	);
	const factor = await adapter.findOne<TwoFactorTable>({
		model: snapshot.metadata.twoFactorTable,
		where: [
			{ field: "id", value: snapshot.metadata.recoveryFactorId },
			{ field: "userId", value: snapshot.metadata.subjectId },
		],
	});
	if (
		!user ||
		!factor ||
		typeof factor.secret !== "string" ||
		typeof factor.backupCodes !== "string"
	) {
		throw new Error("Recovery repair completion authority changed");
	}
	const finalPasskeySessionGeneration = generateRandomString(32);
	const finalTwoFactorSessionGeneration = generateRandomString(32);
	const finalTrustDeviceGeneration = generateRandomString(32);
	const rotatedUser = await rotateFactorSessionGenerations(
		adapter,
		snapshot.metadata.subjectId,
		snapshot.metadata.passkeySessionGeneration,
		snapshot.metadata.twoFactorSessionGeneration,
		finalPasskeySessionGeneration,
		finalTwoFactorSessionGeneration,
	);
	if (!rotatedUser) {
		throw new Error("Recovery repair completion user lifecycle changed");
	}
	const rotatedFactor = await adapter.incrementOne<TwoFactorTable>({
		model: snapshot.metadata.twoFactorTable,
		where: [
			{ field: "id", value: factor.id },
			{ field: "userId", value: snapshot.metadata.subjectId },
			{ field: "secret", value: factor.secret },
			{ field: "backupCodes", value: factor.backupCodes },
			{ field: "verified", value: factor.verified ?? null },
			{
				field: "trustDeviceGeneration",
				value: snapshot.metadata.trustDeviceGeneration,
			},
			{ field: "pendingSecret", value: factor.pendingSecret ?? null },
			{
				field: "pendingBackupCodes",
				value: factor.pendingBackupCodes ?? null,
			},
			{
				field: "lastUsedTotpCounter",
				value: factor.lastUsedTotpCounter ?? null,
			},
		],
		increment: {},
		set: { trustDeviceGeneration: finalTrustDeviceGeneration },
	});
	if (!rotatedFactor) {
		throw new Error("Recovery repair completion factor lifecycle changed");
	}
	await revokeTrustGeneration(
		ctx,
		snapshot.metadata.subjectId,
		snapshot.metadata.trustDeviceGeneration,
	);
	await ctx.context.internalAdapter.deleteUserSessions(
		snapshot.metadata.subjectId,
	);
	const finalMetadata: RecoveryMetadata = Object.freeze({
		...snapshot.metadata,
		passkeySessionGeneration: finalPasskeySessionGeneration,
		twoFactorSessionGeneration: finalTwoFactorSessionGeneration,
		trustDeviceGeneration: finalTrustDeviceGeneration,
	});
	if (
		!(await policyStillAuthorizesRepair(ctx, finalMetadata)) ||
		!(await recoveryCompletionStateIsExact(
			ctx,
			finalMetadata,
			record.repairedFactorId,
		))
	) {
		throw new Error("Recovery repair completion mutation was incomplete");
	}
	await queueBeforeTransactionCommitHook(async () => {
		if (
			!validDeadline(new Date(finalMetadata.expiresAt)) ||
			!(await policyStillAuthorizesRepair(ctx, finalMetadata)) ||
			!(await recoveryCompletionStateIsExact(
				ctx,
				finalMetadata,
				record.repairedFactorId as string,
			))
		) {
			throw new Error("Recovery repair completion changed before commit");
		}
	}, ctx.context.adapter);
	const cookie = recoveryCookie(ctx.context);
	await queueAfterTransactionHook(async () => {
		await ctx.setSignedCookie(cookie.name, "", ctx.context.secret, {
			...cookie.attributes,
			maxAge: 0,
		});
	}, ctx.context.adapter);
	return Object.freeze({ status: true, recoveryComplete: true });
}
