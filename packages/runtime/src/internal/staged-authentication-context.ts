import type {
	AuthContext,
	AuthenticationPrimaryMethod,
	GenericEndpointContext,
	RuntimeAuthenticationPolicy,
	SessionIssuanceContext,
} from "@clearance/core";
import {
	getCurrentAdapter,
	isTransactionActive,
	queueAfterTransactionHook,
	queueBeforeTransactionCommitHook,
} from "@clearance/core/context";
import { createHash } from "@clearance/utils/hash";
import { generateRandomString } from "../crypto/random";
import { lockAndReadActiveUser } from "../db/user-authority";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "./verification-challenge-context";

export const STAGED_AUTHENTICATION_TTL_SECONDS = 120;
export const STAGED_AUTHENTICATION_COOKIE = "managed_authentication_remediation";

export const STAGED_AUTHENTICATION_STAGES = [
	"select_factor",
	"passkey_registration",
	"passkey_authentication",
	"totp_authentication",
	"totp_enrollment_verification",
] as const;

export type StagedAuthenticationStage =
	(typeof STAGED_AUTHENTICATION_STAGES)[number];
export type StagedAuthenticationFactor = "passkey" | "totp";

type StagedContinuationSnapshot = Readonly<{
	subjectId: string;
	projectId: string;
	environmentId: string;
	organizationId: null;
	policyRevision: string;
	policyDigest: string;
	primaryMethod: AuthenticationPrimaryMethod;
	primaryAt: Date;
	dontRememberMe: boolean;
	allowedFactors: readonly StagedAuthenticationFactor[];
	expiresAt: Date;
}>;

type StagedMetadata = Readonly<{
	version: 1;
	stage: StagedAuthenticationStage;
	binding: string;
	rootFlowId: string;
	parentDigest: string;
	seedFingerprint: string;
	subjectId: string;
	projectId: string;
	environmentId: string;
	organizationId: null;
	policyRevision: string;
	policyDigest: string;
	primaryMethod: AuthenticationPrimaryMethod;
	primaryAt: string;
	dontRememberMe: boolean;
	allowedFactors: readonly StagedAuthenticationFactor[];
	expiresAt: string;
}>;

export type StagedAuthenticationLineage = Readonly<{
	subjectId: string;
	stage: StagedAuthenticationStage;
	binding: string;
	rootFlowId: string;
	parentDigest: string;
	seedFingerprint: string;
	expiresAt: Date;
}>;

export type StagedAuthenticationAuthorityView = StagedAuthenticationLineage &
	Readonly<{
		subjectId: string;
		allowedFactors: readonly StagedAuthenticationFactor[];
		dontRememberMe: boolean;
	}>;

type PreloadedSnapshot = Readonly<{
	identifier: string;
	metadataValue: string;
	metadata: StagedMetadata;
}>;

type ConsumedStagedSnapshot = PreloadedSnapshot & {
	state: "pending" | "committed";
	transactionAdapter: object;
};

export type StagedAuthenticationFactorInventory = Readonly<{
	passkey: boolean;
	totp: boolean;
	totpRecord: Readonly<{ id: string; secret: string }> | null;
}>;

type CapturedStagedSessionIssuanceAuthority = Readonly<{
	subjectId: string;
	projectId: string;
	environmentId: string;
	organizationId: null;
	policyRevision: string;
	policyDigest: string;
	primaryMethod: AuthenticationPrimaryMethod;
	primaryAt: Date;
	factorMethod: StagedAuthenticationFactor;
	factorAt: Date;
	dontRememberMe: boolean;
	expiresAt: Date;
	binding: string;
	transactionAdapter: object;
}>;

const continuationSeeds = new WeakMap<Error, StagedContinuationSnapshot>();
const issuedContinuationSeeds = new WeakMap<object, StagedContinuationSnapshot>();
const preloadedCapabilities = new WeakMap<object, PreloadedSnapshot>();
const consumedAuthorities = new WeakMap<object, ConsumedStagedSnapshot>();
const stagedSessionIssuanceAuthorities = new WeakMap<
	object,
	CapturedStagedSessionIssuanceAuthority
>();

const PRIMARY_METHODS = new Set<AuthenticationPrimaryMethod>([
	"password",
	"password_enrollment",
	"federated",
	"email_link",
	"email_otp",
	"phone_otp",
	"wallet_signature",
	"passkey",
]);
const STAGES = new Set<string>(STAGED_AUTHENTICATION_STAGES);
const FACTORS = new Set<string>(["passkey", "totp"]);
const REVISION = /^[1-9][0-9]*$/;
const DIGEST = /^[A-Za-z0-9_-]{43}$/;
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
	"policyRevision",
	"policyDigest",
	"primaryMethod",
	"primaryAt",
	"dontRememberMe",
	"allowedFactors",
	"expiresAt",
] as const;

function identifier(value: unknown, maximum = 1_024): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= maximum &&
		value.trim() === value &&
		!value.includes("\0")
	);
}

function canonicalPolicy(policy: RuntimeAuthenticationPolicy): string {
	return JSON.stringify([
		policy.passwordLockout.enabled,
		policy.passwordLockout.maxFailedAttempts,
		policy.passwordLockout.durationSeconds,
		policy.factorLockout.enabled,
		policy.factorLockout.maxFailedAttempts,
		policy.factorLockout.durationSeconds,
		policy.minimumAssurance,
		policy.allowedFactors.totp,
		policy.allowedFactors.passkey,
		policy.trustedDevice.enabled,
		policy.trustedDevice.maxAgeSeconds,
		policy.assuranceMaxAgeSeconds,
	]);
}

async function digest(value: string): Promise<string> {
	return createHash("SHA-256", "base64urlnopad").digest(value);
}

export function digestStagedAuthenticationPolicy(
	policy: RuntimeAuthenticationPolicy,
): Promise<string> {
	return digest(`managed-authentication-policy:v1:${canonicalPolicy(policy)}`);
}

async function capabilityIdentifier(bearer: string): Promise<string> {
	return `managed-authentication-remediation:v1:${await digest(
		`managed-authentication-remediation:v1:${bearer}`,
	)}`;
}

function challengePurpose(stage: StagedAuthenticationStage): string {
	return `managed-authentication-remediation.${stage}`;
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

function parseDate(value: unknown): Date | null {
	if (typeof value !== "string") return null;
	const parsed = new Date(value);
	return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value
		? parsed
		: null;
}

function parseMetadata(value: unknown, now = new Date()): StagedMetadata | null {
	if (typeof value !== "string" || value.length > 8_192) return null;
	let decoded: unknown;
	try {
		decoded = JSON.parse(value);
	} catch {
		return null;
	}
	const record = exactPlainObject(decoded);
	if (
		!record ||
		Object.keys(record).length !== METADATA_KEYS.length ||
		METADATA_KEYS.some((key) => !Object.hasOwn(record, key)) ||
		Object.keys(record).some(
			(key) => !METADATA_KEYS.includes(key as (typeof METADATA_KEYS)[number]),
		) ||
		record.version !== 1 ||
		typeof record.stage !== "string" ||
		!STAGES.has(record.stage) ||
		!identifier(record.binding, 512) ||
		!identifier(record.rootFlowId, 128) ||
		typeof record.parentDigest !== "string" ||
		!DIGEST.test(record.parentDigest) ||
		typeof record.seedFingerprint !== "string" ||
		!DIGEST.test(record.seedFingerprint) ||
		!identifier(record.subjectId) ||
		!identifier(record.projectId) ||
		!identifier(record.environmentId) ||
		record.organizationId !== null ||
		typeof record.policyRevision !== "string" ||
		!REVISION.test(record.policyRevision) ||
		typeof record.policyDigest !== "string" ||
		!DIGEST.test(record.policyDigest) ||
		typeof record.primaryMethod !== "string" ||
		!PRIMARY_METHODS.has(record.primaryMethod as AuthenticationPrimaryMethod) ||
		typeof record.dontRememberMe !== "boolean" ||
		!Array.isArray(record.allowedFactors) ||
		record.allowedFactors.length === 0 ||
		record.allowedFactors.length > 2 ||
		record.allowedFactors.some(
			(factor) => typeof factor !== "string" || !FACTORS.has(factor),
		) ||
		new Set(record.allowedFactors).size !== record.allowedFactors.length
	) {
		return null;
	}
	if (
		record.allowedFactors.join(",") !==
		[...record.allowedFactors].sort((left, right) =>
			left === right ? 0 : left === "passkey" ? -1 : 1,
		).join(",")
	) {
		return null;
	}
	const primaryAt = parseDate(record.primaryAt);
	const expiresAt = parseDate(record.expiresAt);
	if (
		!primaryAt ||
		!expiresAt ||
		primaryAt > now ||
		expiresAt <= now ||
		expiresAt.getTime() - primaryAt.getTime() >
			STAGED_AUTHENTICATION_TTL_SECONDS * 1_000
	) {
		return null;
	}
	return record as unknown as StagedMetadata;
}

function serializeMetadata(metadata: StagedMetadata): string {
	return JSON.stringify(metadata);
}

function stagedCookie(context: AuthContext, expiresAt?: Date) {
	const maxAge = expiresAt
		? Math.max(1, Math.ceil((expiresAt.getTime() - Date.now()) / 1_000))
		: STAGED_AUTHENTICATION_TTL_SECONDS;
	return context.createAuthCookie(STAGED_AUTHENTICATION_COOKIE, {
		httpOnly: true,
		sameSite: "lax",
		maxAge,
	});
}

export function attachStagedAuthenticationContinuation(
	error: Error,
	input: StagedContinuationSnapshot,
): void {
	if (continuationSeeds.has(error)) throw new Error("Continuation already attached");
	continuationSeeds.set(error, Object.freeze({
		...input,
		primaryAt: new Date(input.primaryAt),
		expiresAt: new Date(input.expiresAt),
		allowedFactors: Object.freeze([...input.allowedFactors]),
	}));
}

export function takeStagedAuthenticationContinuation(
	error: unknown,
): object | null {
	if (!(error instanceof Error)) return null;
	const snapshot = continuationSeeds.get(error);
	if (!snapshot) return null;
	continuationSeeds.delete(error);
	const opaque = Object.freeze({});
	issuedContinuationSeeds.set(opaque, snapshot);
	return opaque;
}

export async function issueInitialStagedAuthenticationCapability(
	context: AuthContext,
	seed: object,
): Promise<{
	bearer: string;
	cookie: ReturnType<AuthContext["createAuthCookie"]>;
	allowedFactors: readonly StagedAuthenticationFactor[];
	expiresAt: Date;
}> {
	const snapshot = issuedContinuationSeeds.get(seed);
	if (!snapshot) throw new Error("Invalid staged authentication continuation");
	issuedContinuationSeeds.delete(seed);
	const now = new Date();
	if (
		snapshot.primaryAt > now ||
		snapshot.expiresAt <= now ||
		snapshot.expiresAt.getTime() - snapshot.primaryAt.getTime() >
			STAGED_AUTHENTICATION_TTL_SECONDS * 1_000
	) {
		throw new Error("Staged authentication continuation expired");
	}
	const bearer = generateRandomString(48);
	const identifier = await capabilityIdentifier(bearer);
	const rootFlowId = generateRandomString(32);
	const seedFingerprint = await digest(
		JSON.stringify([
			"managed-authentication-seed:v1",
			rootFlowId,
			snapshot.subjectId,
			snapshot.projectId,
			snapshot.environmentId,
			snapshot.policyRevision,
			snapshot.policyDigest,
			snapshot.primaryMethod,
			snapshot.primaryAt.toISOString(),
			snapshot.dontRememberMe,
			snapshot.allowedFactors,
			snapshot.expiresAt.toISOString(),
		]),
	);
	const metadata: StagedMetadata = Object.freeze({
		version: 1,
		stage: "select_factor",
		binding: "initial",
		rootFlowId,
		parentDigest: seedFingerprint,
		seedFingerprint,
		subjectId: snapshot.subjectId,
		projectId: snapshot.projectId,
		environmentId: snapshot.environmentId,
		organizationId: null,
		policyRevision: snapshot.policyRevision,
		policyDigest: snapshot.policyDigest,
		primaryMethod: snapshot.primaryMethod,
		primaryAt: snapshot.primaryAt.toISOString(),
		dontRememberMe: snapshot.dontRememberMe,
		allowedFactors: snapshot.allowedFactors,
		expiresAt: snapshot.expiresAt.toISOString(),
	});
	await createInternalVerificationChallenge(
		context.internalAdapter,
		{
			purpose: challengePurpose(metadata.stage),
			subject: metadata.subjectId,
		},
		{
			identifier,
			value: serializeMetadata(metadata),
			expiresAt: new Date(snapshot.expiresAt),
		},
	);
	return {
		bearer,
		cookie: stagedCookie(context, snapshot.expiresAt),
		allowedFactors: snapshot.allowedFactors,
		expiresAt: new Date(snapshot.expiresAt),
	};
}

export async function preloadStagedAuthenticationCapability(
	ctx: GenericEndpointContext,
	expected: Readonly<{
		stage?: StagedAuthenticationStage | undefined;
		stages?: readonly StagedAuthenticationStage[] | undefined;
		binding?: string | undefined;
	}>,
): Promise<object | null> {
	const expectedStages = expected.stages ??
		(expected.stage === undefined ? [] : [expected.stage]);
	if (
		(expected.stage !== undefined && expected.stages !== undefined) ||
		expectedStages.length === 0 ||
		expectedStages.length > STAGED_AUTHENTICATION_STAGES.length ||
		expectedStages.some((stage) => !STAGES.has(stage)) ||
		new Set(expectedStages).size !== expectedStages.length ||
		(expected.binding !== undefined && !identifier(expected.binding, 512))
	) {
		return null;
	}
	const cookie = stagedCookie(ctx.context);
	const bearer = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
	if (!bearer || !identifier(bearer, 512)) return null;
	const identifierValue = await capabilityIdentifier(bearer);
	const verification = await ctx.context.internalAdapter.findVerificationValue(
		identifierValue,
	);
	const metadata = parseMetadata(verification?.value);
	if (
		!verification ||
		!metadata ||
		!expectedStages.includes(metadata.stage) ||
		(expected.binding !== undefined && metadata.binding !== expected.binding) ||
		!(verification.expiresAt instanceof Date) ||
		verification.expiresAt.getTime() !== new Date(metadata.expiresAt).getTime()
	) {
		return null;
	}
	const opaque = Object.freeze({});
	preloadedCapabilities.set(opaque, {
		identifier: identifierValue,
		metadataValue: verification.value,
		metadata,
	});
	return opaque;
}

export async function consumePreloadedStagedAuthenticationCapability(
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
	const authority: ConsumedStagedSnapshot = {
		...snapshot,
		state: "pending",
		transactionAdapter,
	};
	consumedAuthorities.set(opaque, authority);
	await queueAfterTransactionHook(async () => {
		const current = consumedAuthorities.get(opaque);
		if (current === authority && current.state === "pending") {
			current.state = "committed";
		}
	}, ctx.context.adapter);
	return opaque;
}

export function readStagedAuthenticationLineage(
	authority: object,
): StagedAuthenticationLineage | null {
	const snapshot = consumedAuthorities.get(authority);
	if (!snapshot) return null;
	const metadata = snapshot.metadata;
	return Object.freeze({
		subjectId: metadata.subjectId,
		stage: metadata.stage,
		binding: metadata.binding,
		rootFlowId: metadata.rootFlowId,
		parentDigest: metadata.parentDigest,
		seedFingerprint: metadata.seedFingerprint,
		expiresAt: new Date(metadata.expiresAt),
	});
}

export function createStagedAuthenticationBinding(
	lineage: StagedAuthenticationLineage,
	parts: readonly string[],
): Promise<string> {
	if (
		!identifier(lineage.subjectId) ||
		!identifier(lineage.rootFlowId, 128) ||
		!DIGEST.test(lineage.parentDigest) ||
		!DIGEST.test(lineage.seedFingerprint) ||
		!Number.isFinite(lineage.expiresAt.getTime()) ||
		parts.length === 0 ||
		parts.some((part) => !identifier(part, 65_536))
	) {
		throw new Error("Invalid staged authentication lineage");
	}
	return digest(
		JSON.stringify([
			"managed-authentication-binding:v1",
			lineage.subjectId,
			lineage.rootFlowId,
			lineage.seedFingerprint,
			lineage.expiresAt.toISOString(),
			...parts,
		]),
	);
}

/** Compatibility name for factor routes that derive ceremony-bound lineage digests. */
export const digestStagedAuthenticationBinding =
	createStagedAuthenticationBinding;

export function inspectStagedAuthenticationAuthority(
	authority: object,
): StagedAuthenticationAuthorityView | null {
	const snapshot = consumedAuthorities.get(authority);
	if (!snapshot) return null;
	const metadata = snapshot.metadata;
	return Object.freeze({
		subjectId: metadata.subjectId,
		allowedFactors: Object.freeze([...metadata.allowedFactors]),
		dontRememberMe: metadata.dontRememberMe,
		stage: metadata.stage,
		binding: metadata.binding,
		rootFlowId: metadata.rootFlowId,
		parentDigest: metadata.parentDigest,
		seedFingerprint: metadata.seedFingerprint,
		expiresAt: new Date(metadata.expiresAt),
	});
}

export function stagedAuthenticationExpiresAt(authority: object): Date | null {
	const metadata = consumedAuthorities.get(authority)?.metadata;
	return metadata ? new Date(metadata.expiresAt) : null;
}

async function requirePendingStagedAuthority(
	ctx: GenericEndpointContext,
	authority: object,
): Promise<ConsumedStagedSnapshot | null> {
	const snapshot = consumedAuthorities.get(authority);
	if (!snapshot || snapshot.state !== "pending") return null;
	if (!(await isTransactionActive(ctx.context.adapter))) return null;
	return (await getCurrentAdapter(ctx.context.adapter)) === snapshot.transactionAdapter
		? snapshot
		: null;
}

export async function getStagedAuthenticationFactorInventory(
	ctx: GenericEndpointContext,
	authority: object,
): Promise<StagedAuthenticationFactorInventory | null> {
	const snapshot = await requirePendingStagedAuthority(ctx, authority);
	if (!snapshot || snapshot.metadata.stage !== "select_factor") return null;
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const activeUser = await lockAndReadActiveUser(
		adapter,
		snapshot.metadata.subjectId,
	);
	if (!activeUser) return null;
	const passkeyEnabled =
		snapshot.metadata.allowedFactors.includes("passkey") &&
		Boolean(ctx.context.getPlugin("passkey"));
	const twoFactorPlugin = ctx.context.getPlugin("two-factor");
	const totpEnabled =
		snapshot.metadata.allowedFactors.includes("totp") &&
		twoFactorPlugin &&
		(
			twoFactorPlugin.options as
				| { totpOptions?: { disable?: boolean } }
				| undefined
		)?.totpOptions?.disable !== true;
	const twoFactorTable =
		(
			twoFactorPlugin?.options as
				| { twoFactorTable?: string | undefined }
				| undefined
		)?.twoFactorTable ?? "twoFactor";
	const passkey = passkeyEnabled
		? Boolean(
				await adapter.findOne({
					model: "passkey",
					where: [{ field: "userId", value: snapshot.metadata.subjectId }],
				}),
			)
		: false;
	const rawTotp = totpEnabled
		? await adapter.findOne<Record<string, unknown>>({
				model: twoFactorTable,
				where: [{ field: "userId", value: snapshot.metadata.subjectId }],
			})
		: null;
	const totpRecord =
		rawTotp &&
		rawTotp.verified !== false &&
		identifier(rawTotp.id) &&
		identifier(rawTotp.secret, 65_536)
			? Object.freeze({ id: rawTotp.id, secret: rawTotp.secret })
			: null;
	return Object.freeze({
		passkey,
		totp: totpRecord !== null,
		totpRecord,
	});
}

export async function rotateStagedAuthenticationCapability(
	ctx: GenericEndpointContext,
	authority: object,
	next: Readonly<{ stage: StagedAuthenticationStage; binding: string }>,
): Promise<StagedAuthenticationLineage> {
	const snapshot = await requirePendingStagedAuthority(ctx, authority);
	if (!snapshot || !STAGES.has(next.stage) || !identifier(next.binding, 512)) {
		throw new Error("Invalid staged authentication rotation");
	}
	const allowedTransition =
		snapshot.metadata.stage === "select_factor" &&
		(next.stage === "passkey_registration" ||
			next.stage === "passkey_authentication" ||
			next.stage === "totp_authentication" ||
			next.stage === "totp_enrollment_verification");
	if (!allowedTransition) {
		throw new Error("Invalid staged authentication transition");
	}
	if (
		(next.stage.startsWith("passkey_") &&
			!snapshot.metadata.allowedFactors.includes("passkey")) ||
		(next.stage.startsWith("totp_") &&
			!snapshot.metadata.allowedFactors.includes("totp"))
	) {
		throw new Error("Staged authentication factor is unavailable");
	}
	consumedAuthorities.delete(authority);
	const expiresAt = new Date(snapshot.metadata.expiresAt);
	if (expiresAt <= new Date()) throw new Error("Staged authentication expired");
	const bearer = generateRandomString(48);
	const identifierValue = await capabilityIdentifier(bearer);
	const metadata: StagedMetadata = Object.freeze({
		...snapshot.metadata,
		stage: next.stage,
		binding: next.binding,
		parentDigest: await digest(snapshot.identifier),
	});
	await createInternalVerificationChallenge(
		ctx.context.internalAdapter,
		{
			purpose: challengePurpose(metadata.stage),
			subject: metadata.subjectId,
		},
		{
			identifier: identifierValue,
			value: serializeMetadata(metadata),
			expiresAt,
		},
	);
	await queueBeforeTransactionCommitHook(async () => {
		if (expiresAt <= new Date()) {
			throw new Error("Staged authentication expired before commit");
		}
	}, ctx.context.adapter);
	const cookie = stagedCookie(ctx.context, expiresAt);
	await queueAfterTransactionHook(
		async () => {
			await ctx.setSignedCookie(
				cookie.name,
				bearer,
				ctx.context.secret,
				cookie.attributes,
			);
		},
		ctx.context.adapter,
	);
	return Object.freeze({
		subjectId: metadata.subjectId,
		stage: metadata.stage,
		binding: metadata.binding,
		rootFlowId: metadata.rootFlowId,
		parentDigest: metadata.parentDigest,
		seedFingerprint: metadata.seedFingerprint,
		expiresAt: new Date(metadata.expiresAt),
	});
}

export async function createStagedSessionIssuanceContext(
	ctx: GenericEndpointContext,
	authority: object,
	proof: Readonly<{
		factorMethod: StagedAuthenticationFactor;
		factorAt: Date;
		binding: string;
	}>,
): Promise<SessionIssuanceContext> {
	const snapshot = consumedAuthorities.get(authority);
	if (!snapshot || snapshot.state !== "committed") {
		throw new Error("Invalid staged authentication authority");
	}
	const metadata = snapshot.metadata;
	const factorAt = new Date(proof.factorAt);
	const stageMatchesFactor =
		(metadata.stage === "passkey_registration" ||
			metadata.stage === "passkey_authentication")
			? proof.factorMethod === "passkey"
			: metadata.stage === "totp_authentication" ||
					metadata.stage === "totp_enrollment_verification"
				? proof.factorMethod === "totp"
				: false;
	if (
		!FACTORS.has(proof.factorMethod) ||
		!stageMatchesFactor ||
		!metadata.allowedFactors.includes(proof.factorMethod) ||
		proof.binding !== metadata.binding ||
		!Number.isFinite(factorAt.getTime()) ||
		factorAt > new Date() ||
		factorAt < new Date(metadata.primaryAt) ||
		new Date(metadata.expiresAt) <= factorAt ||
		!(await isTransactionActive(ctx.context.adapter))
	) {
		throw new Error("Invalid staged authentication proof");
	}
	const transactionAdapter = await getCurrentAdapter(ctx.context.adapter);
	consumedAuthorities.delete(authority);
	await queueBeforeTransactionCommitHook(async () => {
		if (new Date(metadata.expiresAt) <= new Date()) {
			throw new Error("Staged authentication expired before commit");
		}
	}, ctx.context.adapter);
	const captured: CapturedStagedSessionIssuanceAuthority = Object.freeze({
		subjectId: metadata.subjectId,
		projectId: metadata.projectId,
		environmentId: metadata.environmentId,
		organizationId: null,
		policyRevision: metadata.policyRevision,
		policyDigest: metadata.policyDigest,
		primaryMethod: metadata.primaryMethod,
		primaryAt: new Date(metadata.primaryAt),
		factorMethod: proof.factorMethod,
		factorAt,
		dontRememberMe: metadata.dontRememberMe,
		expiresAt: new Date(metadata.expiresAt),
		binding: metadata.binding,
		transactionAdapter,
	});
	const opaque = Object.freeze({ purpose: "staged" }) as unknown as SessionIssuanceContext;
	stagedSessionIssuanceAuthorities.set(opaque as object, captured);
	return opaque;
}

export function requireStagedSessionIssuanceAuthority(
	value: unknown,
): CapturedStagedSessionIssuanceAuthority | null {
	if (typeof value !== "object" || value === null) return null;
	const captured = stagedSessionIssuanceAuthorities.get(value);
	if (!captured) return null;
	stagedSessionIssuanceAuthorities.delete(value);
	return captured;
}

export async function expireStagedAuthenticationCookie(
	ctx: GenericEndpointContext,
): Promise<void> {
	const cookie = stagedCookie(ctx.context);
	await queueAfterTransactionHook(async () => {
		await ctx.setSignedCookie(cookie.name, "", ctx.context.secret, {
			...cookie.attributes,
			maxAge: 0,
		});
	}, ctx.context.adapter);
}
