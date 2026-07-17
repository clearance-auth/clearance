import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import { generateId } from "@clearance/core/utils/id";
import { base64Url } from "@clearance/utils/base64";
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransportFuture,
	RegistrationResponseJSON,
} from "@simplewebauthn/server";
import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	verifyRegistrationResponse,
} from "@simplewebauthn/server";
import * as z from "zod";
import { sensitiveSessionMiddleware } from "../../api";
import { getAuthoritativeSessionFromCtx } from "../../api/routes/session";
import { setSessionCookie } from "../../cookies";
import { parseSessionOutput, parseUserOutput } from "../../db";
import {
	captureInternalSessionIssuanceContext,
	createInternalSessionIssuanceContext,
} from "../../internal/session-issuance-context";
import {
	consumePreloadedStagedAuthenticationCapability,
	createStagedAuthenticationBinding,
	createStagedSessionIssuanceContext,
	expireStagedAuthenticationCookie,
	getStagedAuthenticationFactorInventory,
	inspectStagedAuthenticationAuthority,
	preloadStagedAuthenticationCapability,
	readStagedAuthenticationLineage,
	rotateStagedAuthenticationCapability,
} from "../../internal/staged-authentication-context";
import {
	PASSKEY_SESSION_GENERATION_FIELD,
	rotatePasskeySessionGeneration,
} from "../../db/passkey-session-generation";
import {
	lockAndReadActiveUser,
	lockAndReadUser,
} from "../../db/user-authority";
import type { Session, User } from "../../types";
import { validatePassword } from "../../utils/password";
import {
	proveFactorStepUp,
	type BackupCodeOptions,
} from "../two-factor/backup-codes";
import type {
	TwoFactorOptions,
	TwoFactorTable,
} from "../two-factor/types";
import {
	CHALLENGE_TTL_SECONDS,
	consumeChallengeByParsedChallenge,
	createChallenge,
	parseClientDataChallenge,
} from "./challenge";
import { advancePasskeyCounter } from "./counter";
import { PASSKEY_ERROR_CODES } from "./error-codes";
import { assertTrustedOrigin, resolveRpID } from "./origin";
import type { Passkey, PasskeyOptions, PublicPasskey } from "./types";
import {
	decodeCanonicalUserHandle,
	ensurePasskeyUserHandle,
	ensurePasskeyUserHandleForAdapter,
} from "./user-handle";

/**
 * Passkey enrollment is a sensitive, security-relevant operation: it must be
 * gated on the *authoritative* session (reloaded from the primary database,
 * bypassing any cookie-cache optimization) rather than whatever session
 * state a prior hook may have cached on `ctx.context.session`, and must
 * additionally enforce session recency exactly like `freshSessionMiddleware`.
 * Registration-options generation and registration verification both use
 * this so the challenge is minted for, and later validated against, an
 * identity the database itself just vouched for.
 */
const freshAuthoritativeSessionMiddleware = createAuthMiddleware(async (ctx) => {
	const session = await getAuthoritativeSessionFromCtx(ctx);
	if (!session?.session) {
		throw APIError.from("UNAUTHORIZED", {
			message: "Unauthorized",
			code: "UNAUTHORIZED",
		});
	}
	if (ctx.context.sessionConfig.freshAge !== 0) {
		const createdAt = new Date(session.session.createdAt).getTime();
		const freshAge = ctx.context.sessionConfig.freshAge * 1000;
		if (Date.now() - createdAt >= freshAge) {
			throw APIError.from("FORBIDDEN", BASE_ERROR_CODES.SESSION_NOT_FRESH);
		}
	}
	return {
		session,
	};
});

const NAME_MAX_LENGTH = 100;

const transportSchema = z.enum([
	"ble",
	"cable",
	"hybrid",
	"internal",
	"nfc",
	"smart-card",
	"usb",
]);

const registrationResponseSchema = z.object({
	id: z.string().min(1).max(1024),
	rawId: z.string().min(1).max(1024),
	type: z.literal("public-key"),
	authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
	clientExtensionResults: z.record(z.string(), z.any()),
	response: z.object({
		clientDataJSON: z.string().min(1).max(8_000),
		attestationObject: z.string().min(1).max(200_000),
		authenticatorData: z.string().max(8_000).optional(),
		transports: z.array(transportSchema).max(10).optional(),
		publicKeyAlgorithm: z.number().optional(),
		publicKey: z.string().max(4_096).optional(),
	}),
});

const authenticationResponseSchema = z.object({
	id: z.string().min(1).max(1024),
	rawId: z.string().min(1).max(1024),
	type: z.literal("public-key"),
	authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
	clientExtensionResults: z.record(z.string(), z.any()),
	response: z.object({
		clientDataJSON: z.string().min(1).max(8_000),
		authenticatorData: z.string().min(1).max(8_000),
		signature: z.string().min(1).max(2_048),
		userHandle: z.string().max(1_024).optional(),
	}),
});

const deletionProofSchema = z.discriminatedUnion("type", [
	z.object({ type: z.literal("password"), password: z.string().min(1).max(1024) }),
	z.object({ type: z.literal("totp"), code: z.string().min(1).max(128) }),
	z.object({
		type: z.literal("recovery-code"),
		code: z.string().min(1).max(256),
	}),
	z.object({ type: z.literal("passkey"), response: authenticationResponseSchema }),
]);

function parseTransports(
	stored: string | null | undefined,
): AuthenticatorTransportFuture[] | undefined {
	if (!stored) return undefined;
	return stored
		.split(",")
		.map((entry) => entry.trim())
		.filter(Boolean) as AuthenticatorTransportFuture[];
}

function toPublicPasskey(passkey: Passkey): PublicPasskey {
	return {
		id: passkey.id,
		name: passkey.name ?? null,
		deviceType: passkey.deviceType,
		backedUp: passkey.backedUp,
		transports: parseTransports(passkey.transports),
		createdAt: passkey.createdAt,
		updatedAt: passkey.updatedAt,
	};
}

function logFailure(ctx: GenericEndpointContext, label: string, error: unknown) {
	// Never log raw responses, challenges, credential IDs, public keys, user
	// handles, or origin/signature failure detail. Only the error's
	// constructor name is retained as a minimal diagnostic signal.
	ctx.context.logger.debug(
		`[passkey] ${label}`,
		error instanceof Error ? error.name : "unknown error",
	);
}

/**
 * A counter advance and the session it authorizes must commit or roll back as
 * one unit. Factory-wrapped adapters expose their real transaction capability
 * here; the sequential fallback is insufficient for passkey authentication.
 */
function assertRollbackCapableAuthentication(ctx: GenericEndpointContext): void {
	if (
		typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function" ||
		(ctx.context.options.secondaryStorage !== undefined &&
			ctx.context.options.session?.storeSessionInDatabase !== true)
	) {
		throw APIError.from(
			"INTERNAL_SERVER_ERROR",
			PASSKEY_ERROR_CODES.CONFIGURATION_ERROR,
		);
	}
}

function assertPasskeyDeletionConfiguration(ctx: GenericEndpointContext): void {
	if (
		typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function" ||
		(ctx.context.options.secondaryStorage !== undefined &&
			ctx.context.options.session?.storeSessionInDatabase !== true)
	) {
		throw APIError.from(
			"INTERNAL_SERVER_ERROR",
			PASSKEY_ERROR_CODES.CONFIGURATION_ERROR,
		);
	}
}

function deletionProofFailed(): never {
	throw APIError.from("UNAUTHORIZED", PASSKEY_ERROR_CODES.DELETION_PROOF_FAILED);
}

function lastFactorProtected(): never {
	throw APIError.from("BAD_REQUEST", PASSKEY_ERROR_CODES.LAST_FACTOR_PROTECTED);
}

function lifecycleConflict(): never {
	throw APIError.from("CONFLICT", PASSKEY_ERROR_CODES.LIFECYCLE_CONFLICT);
}

function remediationFailed(): never {
	throw APIError.from("UNAUTHORIZED", PASSKEY_ERROR_CODES.REMEDIATION_FAILED);
}

async function withPasskeyRemediationFailureBoundary<T>(
	_ctx: GenericEndpointContext,
	operation: () => Promise<T>,
): Promise<T> {
	try {
		return await operation();
	} catch {
		remediationFailed();
	}
}

function setPasskeyRemediationHeaders(ctx: GenericEndpointContext): void {
	ctx.setHeader("cache-control", "no-store");
	ctx.setHeader("pragma", "no-cache");
}

const remediationRegistrationOptionsSchema = z
	.object({
		authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
	})
	.optional();

function exactStagedChallengeLineage(
	authority: object,
	challenge: Awaited<ReturnType<typeof consumeChallengeByParsedChallenge>>,
): boolean {
	const view = inspectStagedAuthenticationAuthority(authority);
	if (!view || !challenge) return false;
	return (
		view.stage !== "select_factor" &&
		view.binding.length > 0 &&
		view.subjectId === challenge.userId &&
		view.subjectId === challenge.stagedSubjectId &&
		view.rootFlowId === challenge.stagedRootFlowId &&
		view.parentDigest === challenge.stagedParentDigest &&
		view.seedFingerprint === challenge.stagedSeedFingerprint &&
		challenge.expiresAt <= view.expiresAt
	);
}

export const generatePasskeyRegistrationOptions = (options: PasskeyOptions | undefined) =>
	createAuthEndpoint(
		"/passkey/generate-registration-options",
		{
			// Browsers reliably attach Origin to same-origin POST requests. They
			// commonly omit it on same-origin GET, and scripts cannot set that
			// forbidden header themselves.
			method: "POST",
			use: [freshAuthoritativeSessionMiddleware],
			body: z
				.object({
					authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
				})
				.optional(),
		},
		async (ctx) => {
			const session = ctx.context.session;
			const rpID = resolveRpID(ctx, options);
			const origin = assertTrustedOrigin(ctx, options, rpID);
			const userHandle = await ensurePasskeyUserHandle(ctx, session.user.id);

			const existingPasskeys = await ctx.context.adapter.findMany<Passkey>({
				model: "passkey",
				where: [{ field: "userId", value: session.user.id }],
				limit: 100,
			});

			const registrationOptions = await generateRegistrationOptions({
				rpName: options?.rpName || ctx.context.appName,
				rpID,
				userID: new Uint8Array(decodeCanonicalUserHandle(userHandle)),
				userName: session.user.email || session.user.id,
				userDisplayName: session.user.name || session.user.email || session.user.id,
				attestationType: "none",
				timeout: CHALLENGE_TTL_SECONDS * 1000,
				excludeCredentials: existingPasskeys.map((passkey) => ({
					id: passkey.credentialID,
					transports: parseTransports(passkey.transports),
				})),
				authenticatorSelection: {
					...options?.authenticatorSelection,
					...(ctx.body?.authenticatorAttachment
						? { authenticatorAttachment: ctx.body.authenticatorAttachment }
						: {}),
					// Never overridable: discoverability and user verification are
					// hard invariants of this plugin, not configurable defaults.
					residentKey: "required",
					requireResidentKey: true,
					userVerification: "required",
				},
			});

			await createChallenge(ctx, "registration", registrationOptions.challenge, {
				rpID,
				origin,
				userId: session.user.id,
				userHandle,
			});

			return ctx.json(registrationOptions);
		},
	);

export const verifyPasskeyRegistration = (options: PasskeyOptions | undefined) =>
	createAuthEndpoint(
		"/passkey/verify-registration",
		{
			method: "POST",
			use: [freshAuthoritativeSessionMiddleware],
			body: z.object({
				response: registrationResponseSchema,
				name: z.string().trim().min(1).max(NAME_MAX_LENGTH).optional(),
			}),
		},
		async (ctx) => {
			const session = ctx.context.session;
			const rpID = resolveRpID(ctx, options);
			let requestOrigin: string;
			try {
				requestOrigin = assertTrustedOrigin(ctx, options, rpID);
			} catch {
				throw APIError.from("BAD_REQUEST", PASSKEY_ERROR_CODES.REGISTRATION_FAILED);
			}

			const challenge = parseClientDataChallenge(
				ctx.body.response.response.clientDataJSON,
			);
			if (!challenge) {
				throw APIError.from("BAD_REQUEST", PASSKEY_ERROR_CODES.REGISTRATION_FAILED);
			}
			const challengeRecord = await consumeChallengeByParsedChallenge(
				ctx,
				"registration",
				challenge,
			);
			if (
				!challengeRecord ||
				challengeRecord.rpID !== rpID ||
				challengeRecord.origin !== requestOrigin ||
				challengeRecord.userId !== session.user.id ||
				!challengeRecord.userHandle
			) {
				throw APIError.from("BAD_REQUEST", PASSKEY_ERROR_CODES.REGISTRATION_FAILED);
			}

			let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
			try {
				verification = await verifyRegistrationResponse({
					response: ctx.body.response as unknown as RegistrationResponseJSON,
					expectedChallenge: challenge,
					expectedOrigin: requestOrigin,
					expectedRPID: rpID,
					requireUserVerification: true,
				});
			} catch (error) {
				logFailure(ctx, "registration verification threw", error);
				throw APIError.from("BAD_REQUEST", PASSKEY_ERROR_CODES.REGISTRATION_FAILED);
			}

			if (!verification.verified || !verification.registrationInfo) {
				throw APIError.from("BAD_REQUEST", PASSKEY_ERROR_CODES.REGISTRATION_FAILED);
			}

			const { aaguid, credential, credentialDeviceType, credentialBackedUp } =
				verification.registrationInfo;
			const transports = ctx.body.response.response.transports;

			let created: Passkey;
			try {
				created = await ctx.context.adapter.create<Omit<Passkey, "id">, Passkey>({
					model: "passkey",
					data: {
						userId: session.user.id,
						name: ctx.body.name,
						credentialID: credential.id,
						publicKey: base64Url.encode(credential.publicKey, { padding: false }),
						userHandle: challengeRecord.userHandle,
						counter: credential.counter,
						deviceType: credentialDeviceType,
						backedUp: credentialBackedUp,
						transports: transports?.join(","),
						aaguid,
						createdAt: new Date(),
						updatedAt: new Date(),
					} as Omit<Passkey, "id">,
				});
			} catch (error) {
				// A duplicate `credentialID` is enforced by a database unique
				// constraint. Confirm that's the cause before treating this as an
				// unexpected failure, and never reveal which account already owns
				// the credential.
				const existing = await ctx.context.adapter.findOne<Passkey>({
					model: "passkey",
					where: [{ field: "credentialID", value: credential.id }],
				});
				if (existing) {
					throw APIError.from("CONFLICT", PASSKEY_ERROR_CODES.REGISTRATION_FAILED);
				}
				logFailure(ctx, "registration create failed", error);
				throw APIError.from("BAD_REQUEST", PASSKEY_ERROR_CODES.REGISTRATION_FAILED);
			}

			return ctx.json(toPublicPasskey(created));
		},
	);

export const generatePasskeyAuthenticationOptions = (
	options: PasskeyOptions | undefined,
) =>
	createAuthEndpoint(
		"/passkey/generate-authentication-options",
		{
			method: "POST",
		},
		async (ctx) => {
			assertRollbackCapableAuthentication(ctx);
			const rpID = resolveRpID(ctx, options);
			const origin = assertTrustedOrigin(ctx, options, rpID);

			// No `allowCredentials`: every authentication ceremony is
			// discoverable/usernameless, so the browser prompts for whichever
			// resident credential the user selects.
			const authOptions = await generateAuthenticationOptions({
				rpID,
				userVerification: "required",
				timeout: CHALLENGE_TTL_SECONDS * 1000,
			});

			await createChallenge(ctx, "authentication", authOptions.challenge, {
				rpID,
				origin,
			});

			return ctx.json(authOptions);
		},
	);

export const verifyPasskeyAuthentication = (options: PasskeyOptions | undefined) =>
	createAuthEndpoint(
		"/passkey/verify-authentication",
		{
			method: "POST",
			body: z.object({
				response: authenticationResponseSchema,
			}),
		},
		async (ctx) => {
			// Check before consuming the one-shot challenge so an unsupported
			// deployment cannot burn valid ceremonies before failing closed.
			assertRollbackCapableAuthentication(ctx);
			const rpID = resolveRpID(ctx, options);
			let requestOrigin: string;
			try {
				requestOrigin = assertTrustedOrigin(ctx, options, rpID);
			} catch {
				throw APIError.from(
					"UNAUTHORIZED",
					PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED,
				);
			}

			const challenge = parseClientDataChallenge(
				ctx.body.response.response.clientDataJSON,
			);
			if (!challenge) {
				throw APIError.from("UNAUTHORIZED", PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED);
			}
			const challengeRecord = await consumeChallengeByParsedChallenge(
				ctx,
				"authentication",
				challenge,
			);
			if (
				!challengeRecord ||
				challengeRecord.rpID !== rpID ||
				challengeRecord.origin !== requestOrigin
			) {
				throw APIError.from("UNAUTHORIZED", PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED);
			}

			const passkey = await ctx.context.adapter.findOne<Passkey>({
				model: "passkey",
				where: [{ field: "credentialID", value: ctx.body.response.id }],
			});
			if (!passkey) {
				throw APIError.from("UNAUTHORIZED", PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED);
			}

			const presentedUserHandle = ctx.body.response.response.userHandle;
			const owner = await ctx.context.adapter.findOne<{
				passkeyUserHandle?: string | null;
			}>({
				model: "user",
				where: [{ field: "id", value: passkey.userId }],
				select: ["passkeyUserHandle"],
			});
			if (
				!presentedUserHandle ||
				!owner?.passkeyUserHandle ||
				owner.passkeyUserHandle !== passkey.userHandle ||
				presentedUserHandle !== owner.passkeyUserHandle
			) {
				throw APIError.from("UNAUTHORIZED", PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED);
			}

			let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
			try {
				verification = await verifyAuthenticationResponse({
					response: ctx.body.response as unknown as AuthenticationResponseJSON,
					expectedChallenge: challenge,
					expectedOrigin: requestOrigin,
					expectedRPID: rpID,
					requireUserVerification: true,
					credential: {
						id: passkey.credentialID,
						publicKey: base64Url.decode(passkey.publicKey),
						counter: passkey.counter,
						transports: parseTransports(passkey.transports),
					},
				});
			} catch (error) {
				logFailure(ctx, "authentication verification threw", error);
				throw APIError.from("UNAUTHORIZED", PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED);
			}

			if (!verification.verified) {
				throw APIError.from("UNAUTHORIZED", PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED);
			}

			const newCounter = verification.authenticationInfo.newCounter;
			type AuthenticationResult = { session: Session; user: User };
			let authenticated: AuthenticationResult | undefined;
			let committedAuthentication: AuthenticationResult | undefined;
			try {
				authenticated = await runWithTransaction(
					ctx.context.adapter,
					async () => {
						const trxAdapter = await getCurrentAdapter(ctx.context.adapter);
						const activeUser = await lockAndReadActiveUser(
							trxAdapter,
							passkey.userId,
						);
						if (!activeUser) {
							throw APIError.from(
								"UNAUTHORIZED",
								PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED,
							);
						}
						const wonCas = await advancePasskeyCounter(
							trxAdapter,
							passkey.id,
							passkey.counter,
							newCounter,
						);
						if (!wonCas) {
							throw APIError.from(
								"UNAUTHORIZED",
								PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED,
							);
						}

						const newSession = await ctx.context.internalAdapter.createSession(
							passkey.userId,
							undefined,
							undefined,
							false,
							createInternalSessionIssuanceContext({
								purpose: "interactive",
								subjectId: passkey.userId,
								evidence: [{ kind: "primary", primaryMethod: "passkey" }],
							}),
						);
						if (!newSession) {
							throw APIError.from(
								"INTERNAL_SERVER_ERROR",
								PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED,
							);
						}
						committedAuthentication = {
							session: newSession,
							user: activeUser,
						};
						return committedAuthentication;
					},
				);
			} catch (error) {
				if (error instanceof AfterTransactionHookError && committedAuthentication) {
					logFailure(ctx, "authentication post-commit publication failed", error);
					authenticated = committedAuthentication;
				} else {
					throw error;
				}
			}
			if (!authenticated) {
				throw APIError.from(
					"INTERNAL_SERVER_ERROR",
					PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED,
				);
			}
			const { session, user } = authenticated;

			await setSessionCookie(ctx, { session, user });

			return ctx.json({
				session: parseSessionOutput(ctx.context.options, session),
				user: parseUserOutput(ctx.context.options, user),
			});
		},
	);

function generatePasskeyRemediationOptions(
	options: PasskeyOptions | undefined,
	mode: "registration" | "authentication",
) {
	const registration = mode === "registration";
	return createAuthEndpoint(
		registration
			? "/passkey/generate-remediation-registration-options"
			: "/passkey/generate-remediation-authentication-options",
		{
			method: "POST",
			body: remediationRegistrationOptionsSchema,
		},
		async (ctx) => {
			setPasskeyRemediationHeaders(ctx);
			return withPasskeyRemediationFailureBoundary(ctx, async () => {
				assertRollbackCapableAuthentication(ctx);
				const preloaded = await preloadStagedAuthenticationCapability(ctx, {
					stages: ["select_factor"],
				});
				if (!preloaded) remediationFailed();
				const rpID = resolveRpID(ctx, options);
				const origin = assertTrustedOrigin(ctx, options, rpID);

				return runWithTransaction(ctx.context.adapter, async () => {
					const authority = await consumePreloadedStagedAuthenticationCapability(
						ctx,
						preloaded,
					);
					if (!authority) remediationFailed();
					const initial = inspectStagedAuthenticationAuthority(authority);
					if (!initial || initial.stage !== "select_factor") remediationFailed();
					const inventory = await getStagedAuthenticationFactorInventory(
						ctx,
						authority,
					);
					if (!inventory) remediationFailed();
					const adapter = await getCurrentAdapter(ctx.context.adapter);
					const user = await lockAndReadActiveUser(adapter, initial.subjectId);
					if (!user || !initial.allowedFactors.includes("passkey")) {
						remediationFailed();
					}
					const anyEligibleFactor = inventory.passkey || inventory.totp;
					if (
						(registration && anyEligibleFactor) ||
						(!registration && !inventory.passkey)
					) {
						remediationFailed();
					}

					const userHandle = await ensurePasskeyUserHandleForAdapter(adapter, user.id);
					const passkeys = await adapter.findMany<Passkey>({
						model: "passkey",
						where: [{ field: "userId", value: user.id }],
						limit: 100,
					});
					if (
						(registration && passkeys.length > 0) ||
						(!registration && passkeys.length === 0)
					) {
						remediationFailed();
					}

					const webauthnOptions = registration
						? await generateRegistrationOptions({
								rpName: options?.rpName || ctx.context.appName,
								rpID,
								userID: new Uint8Array(decodeCanonicalUserHandle(userHandle)),
								userName: user.email || user.id,
								userDisplayName: user.name || user.email || user.id,
								attestationType: "none",
								timeout: CHALLENGE_TTL_SECONDS * 1_000,
								excludeCredentials: passkeys.map((passkey) => ({
									id: passkey.credentialID,
									transports: parseTransports(passkey.transports),
								})),
								authenticatorSelection: {
									...options?.authenticatorSelection,
									...(ctx.body?.authenticatorAttachment
										? {
												authenticatorAttachment:
													ctx.body.authenticatorAttachment,
											}
										: {}),
									residentKey: "required",
									requireResidentKey: true,
									userVerification: "required",
								},
							})
						: await generateAuthenticationOptions({
								rpID,
								userVerification: "required",
								timeout: CHALLENGE_TTL_SECONDS * 1_000,
								allowCredentials: passkeys.map((passkey) => ({
									id: passkey.credentialID,
									transports: parseTransports(passkey.transports),
								})),
							});
					const ceremony = registration ? "registration" : "authentication";
					const issued = await createChallenge(
						ctx,
						ceremony,
						webauthnOptions.challenge,
						{
							rpID,
							origin,
							userId: user.id,
							userHandle,
							stagedRootFlowId: initial.rootFlowId,
							stagedParentDigest: initial.parentDigest,
							stagedSeedFingerprint: initial.seedFingerprint,
							stagedSubjectId: user.id,
							expiresAt: initial.expiresAt,
						},
					);
					const lineage = readStagedAuthenticationLineage(authority);
					if (!lineage) remediationFailed();
					const binding = await createStagedAuthenticationBinding(lineage, [
						ceremony,
						issued.digestId,
					]);
					const successor = await rotateStagedAuthenticationCapability(ctx, authority, {
						stage: registration
							? "passkey_registration"
							: "passkey_authentication",
						binding,
					});
					if (
						successor.subjectId !== user.id ||
						successor.rootFlowId !== initial.rootFlowId ||
						successor.seedFingerprint !== initial.seedFingerprint ||
						successor.expiresAt.getTime() !== initial.expiresAt.getTime()
					) {
						remediationFailed();
					}
					const bound = await adapter.update({
						model: "passkeyChallenge",
						where: [{ field: "digestId", value: issued.digestId }],
						update: {
							stagedRootFlowId: successor.rootFlowId,
							stagedParentDigest: successor.parentDigest,
							stagedSeedFingerprint: successor.seedFingerprint,
							stagedSubjectId: successor.subjectId,
						},
					});
					if (!bound) remediationFailed();
					return webauthnOptions;
				});
			});
		},
	);
}

export const generatePasskeyRemediationRegistrationOptions = (
	options: PasskeyOptions | undefined,
) => generatePasskeyRemediationOptions(options, "registration");

export const generatePasskeyRemediationAuthenticationOptions = (
	options: PasskeyOptions | undefined,
) => generatePasskeyRemediationOptions(options, "authentication");

async function consumePasskeyRemediation(
	ctx: GenericEndpointContext,
	stage: "passkey_registration" | "passkey_authentication",
	ceremony: "registration" | "authentication",
	clientDataJSON: string,
) {
	const challenge = parseClientDataChallenge(clientDataJSON);
	if (!challenge) remediationFailed();
	const preloaded = await preloadStagedAuthenticationCapability(ctx, {
		stages: [stage],
	});
	if (!preloaded) remediationFailed();
	return runWithTransaction(ctx.context.adapter, async () => {
		const authority = await consumePreloadedStagedAuthenticationCapability(
			ctx,
			preloaded,
		);
		if (!authority) remediationFailed();
		const challengeRecord = await consumeChallengeByParsedChallenge(
			ctx,
			ceremony,
			challenge,
		);
		const lineage = readStagedAuthenticationLineage(authority);
		const expectedBinding =
			lineage && challengeRecord
				? await createStagedAuthenticationBinding(lineage, [
						ceremony,
						challengeRecord.digestId,
					])
				: null;
		return {
			authority,
			challenge,
			challengeRecord,
			valid:
				exactStagedChallengeLineage(authority, challengeRecord) &&
				expectedBinding === lineage?.binding,
		};
	});
}

export const verifyPasskeyRemediationRegistration = (
	options: PasskeyOptions | undefined,
) =>
	createAuthEndpoint(
		"/passkey/verify-remediation-registration",
		{
			method: "POST",
			body: z.object({
				response: registrationResponseSchema,
				name: z.string().trim().min(1).max(NAME_MAX_LENGTH).optional(),
			}),
		},
		async (ctx) =>
			withPasskeyRemediationFailureBoundary(ctx, async () => {
				setPasskeyRemediationHeaders(ctx);
				assertRollbackCapableAuthentication(ctx);
				const rpID = resolveRpID(ctx, options);
				const origin = assertTrustedOrigin(ctx, options, rpID);
				const consumed = await consumePasskeyRemediation(
					ctx,
					"passkey_registration",
					"registration",
					ctx.body.response.response.clientDataJSON,
				);
				if (
					!consumed.valid ||
					!consumed.challengeRecord ||
					consumed.challengeRecord.rpID !== rpID ||
					consumed.challengeRecord.origin !== origin ||
					!consumed.challengeRecord.userId ||
					!consumed.challengeRecord.userHandle
				) {
					remediationFailed();
				}
				const record = consumed.challengeRecord;
				let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
				try {
					verification = await verifyRegistrationResponse({
						response: ctx.body.response as unknown as RegistrationResponseJSON,
						expectedChallenge: consumed.challenge,
						expectedOrigin: origin,
						expectedRPID: rpID,
						requireUserVerification: true,
					});
				} catch (error) {
					logFailure(ctx, "remediation registration verification threw", error);
					remediationFailed();
				}
				if (!verification.verified || !verification.registrationInfo) {
					remediationFailed();
				}
				const { aaguid, credential, credentialDeviceType, credentialBackedUp } =
					verification.registrationInfo;
				let committed:
					| { session: Session; user: User; dontRememberMe: boolean }
					| undefined;
				try {
					await runWithTransaction(ctx.context.adapter, async () => {
						const view = inspectStagedAuthenticationAuthority(consumed.authority);
						if (!view) remediationFailed();
						const adapter = await getCurrentAdapter(ctx.context.adapter);
						const user = await lockAndReadActiveUser(adapter, view.subjectId);
						if (!user || user.id !== record.userId) remediationFailed();
						const existingPasskey = await adapter.findOne<Passkey>({
							model: "passkey",
							where: [{ field: "userId", value: user.id }],
						});
						if (existingPasskey) remediationFailed();
						if (view.allowedFactors.includes("totp")) {
							const twoFactorPlugin = ctx.context.getPlugin("two-factor");
							const twoFactorOptions = twoFactorPlugin?.options as
								| TwoFactorOptions
								| undefined;
							if (
								twoFactorPlugin &&
								twoFactorOptions?.totpOptions?.disable !== true
							) {
								const table = twoFactorOptions?.twoFactorTable ?? "twoFactor";
								const totp = await adapter.findOne<TwoFactorTable>({
									model: table,
									where: [{ field: "userId", value: user.id }],
								});
								if (totp && totp.verified !== false) {
									remediationFailed();
								}
							}
						}
						const userHandle = await ensurePasskeyUserHandleForAdapter(adapter, user.id);
						if (userHandle !== record.userHandle) remediationFailed();
						const created = await adapter.create<Omit<Passkey, "id">, Passkey>({
							model: "passkey",
							data: {
								userId: user.id,
								name: ctx.body.name,
								credentialID: credential.id,
								publicKey: base64Url.encode(credential.publicKey, { padding: false }),
								userHandle,
								counter: credential.counter,
								deviceType: credentialDeviceType,
								backedUp: credentialBackedUp,
								transports: ctx.body.response.response.transports?.join(","),
								aaguid,
								createdAt: new Date(),
								updatedAt: new Date(),
							} as Omit<Passkey, "id">,
						});
						if (!created || created.userId !== user.id) remediationFailed();
						const issuanceContext = await createStagedSessionIssuanceContext(
							ctx,
							consumed.authority,
							{
								factorMethod: "passkey",
								factorAt: new Date(),
								binding: view.binding,
							},
						);
						const session = await ctx.context.internalAdapter.createSession(
							user.id,
							view.dontRememberMe,
							undefined,
							false,
							issuanceContext,
						);
						if (!session) remediationFailed();
						committed = { session, user, dontRememberMe: view.dontRememberMe };
						await expireStagedAuthenticationCookie(ctx);
						return committed;
					});
				} catch (error) {
					if (error instanceof AfterTransactionHookError && committed) {
						logFailure(ctx, "remediation registration publication failed", error);
					} else {
						throw error;
					}
				}
				if (!committed) remediationFailed();
				await setSessionCookie(
					ctx,
					{ session: committed.session, user: committed.user },
					committed.dontRememberMe,
				);
				return ctx.json({
					session: parseSessionOutput(ctx.context.options, committed.session),
					user: parseUserOutput(ctx.context.options, committed.user),
				});
			}),
	);

export const verifyPasskeyRemediationAuthentication = (
	options: PasskeyOptions | undefined,
) =>
	createAuthEndpoint(
		"/passkey/verify-remediation-authentication",
		{
			method: "POST",
			body: z.object({ response: authenticationResponseSchema }),
		},
		async (ctx) =>
			withPasskeyRemediationFailureBoundary(ctx, async () => {
				setPasskeyRemediationHeaders(ctx);
				assertRollbackCapableAuthentication(ctx);
				const rpID = resolveRpID(ctx, options);
				const origin = assertTrustedOrigin(ctx, options, rpID);
				const consumed = await consumePasskeyRemediation(
					ctx,
					"passkey_authentication",
					"authentication",
					ctx.body.response.response.clientDataJSON,
				);
				if (
					!consumed.valid ||
					!consumed.challengeRecord ||
					consumed.challengeRecord.rpID !== rpID ||
					consumed.challengeRecord.origin !== origin ||
					!consumed.challengeRecord.userId ||
					!consumed.challengeRecord.userHandle
				) {
					remediationFailed();
				}
				const record = consumed.challengeRecord;
				const passkey = await ctx.context.adapter.findOne<Passkey>({
					model: "passkey",
					where: [
						{ field: "credentialID", value: ctx.body.response.id },
						{ field: "userId", value: record.userId! },
					],
				});
				const presentedUserHandle = ctx.body.response.response.userHandle;
				if (
					!passkey ||
					!presentedUserHandle ||
					passkey.userHandle !== record.userHandle ||
					presentedUserHandle !== passkey.userHandle
				) {
					remediationFailed();
				}
				const owner = await ctx.context.adapter.findOne<{
					passkeyUserHandle?: string | null;
				}>({
					model: "user",
					where: [{ field: "id", value: passkey.userId }],
					select: ["passkeyUserHandle"],
				});
				if (!owner?.passkeyUserHandle || owner.passkeyUserHandle !== passkey.userHandle) {
					remediationFailed();
				}
				let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
				try {
					verification = await verifyAuthenticationResponse({
						response: ctx.body.response as unknown as AuthenticationResponseJSON,
						expectedChallenge: consumed.challenge,
						expectedOrigin: origin,
						expectedRPID: rpID,
						requireUserVerification: true,
						credential: {
							id: passkey.credentialID,
							publicKey: base64Url.decode(passkey.publicKey),
							counter: passkey.counter,
							transports: parseTransports(passkey.transports),
						},
					});
				} catch (error) {
					logFailure(ctx, "remediation authentication verification threw", error);
					remediationFailed();
				}
				if (!verification.verified) remediationFailed();
				const newCounter = verification.authenticationInfo.newCounter;
				let committed:
					| { session: Session; user: User; dontRememberMe: boolean }
					| undefined;
				try {
					await runWithTransaction(ctx.context.adapter, async () => {
						const view = inspectStagedAuthenticationAuthority(consumed.authority);
						if (!view) remediationFailed();
						const adapter = await getCurrentAdapter(ctx.context.adapter);
						const user = await lockAndReadActiveUser(adapter, view.subjectId);
						if (!user || user.id !== passkey.userId) remediationFailed();
						const userHandle = await ensurePasskeyUserHandleForAdapter(adapter, user.id);
						const current = await adapter.findOne<Passkey>({
							model: "passkey",
							where: [{ field: "id", value: passkey.id }],
						});
						if (
							!current ||
							current.userId !== user.id ||
							current.credentialID !== passkey.credentialID ||
							current.publicKey !== passkey.publicKey ||
							current.userHandle !== userHandle ||
							userHandle !== record.userHandle
						) {
							remediationFailed();
						}
						if (
							!(await advancePasskeyCounter(
								adapter,
								current.id,
								passkey.counter,
								newCounter,
							))
						) {
							remediationFailed();
						}
						const issuanceContext = await createStagedSessionIssuanceContext(
							ctx,
							consumed.authority,
							{
								factorMethod: "passkey",
								factorAt: new Date(),
								binding: view.binding,
							},
						);
						const session = await ctx.context.internalAdapter.createSession(
							user.id,
							view.dontRememberMe,
							undefined,
							false,
							issuanceContext,
						);
						if (!session) remediationFailed();
						committed = { session, user, dontRememberMe: view.dontRememberMe };
						await expireStagedAuthenticationCookie(ctx);
						return committed;
					});
				} catch (error) {
					if (error instanceof AfterTransactionHookError && committed) {
						logFailure(ctx, "remediation authentication publication failed", error);
					} else {
						throw error;
					}
				}
				if (!committed) remediationFailed();
				await setSessionCookie(
					ctx,
					{ session: committed.session, user: committed.user },
					committed.dontRememberMe,
				);
				return ctx.json({
					session: parseSessionOutput(ctx.context.options, committed.session),
					user: parseUserOutput(ctx.context.options, committed.user),
				});
			}),
	);

export const generatePasskeyDeletionOptions = (
	options: PasskeyOptions | undefined,
) =>
	createAuthEndpoint(
		"/passkey/generate-deletion-options",
		{
			method: "POST",
			use: [sensitiveSessionMiddleware],
			body: z.object({ id: z.string().min(1).max(255) }),
		},
		async (ctx) => {
			assertPasskeyDeletionConfiguration(ctx);
			const userId = ctx.context.session.user.id;
			const target = await ctx.context.adapter.findOne<Passkey>({
				model: "passkey",
				where: [
					{ field: "id", value: ctx.body.id },
					{ field: "userId", value: userId },
				],
			});
			if (!target) {
				throw APIError.from("NOT_FOUND", PASSKEY_ERROR_CODES.PASSKEY_NOT_FOUND);
			}

			const alternatives = (
				await ctx.context.adapter.findMany<Passkey>({
					model: "passkey",
					where: [{ field: "userId", value: userId }],
					limit: 100,
				})
			).filter((candidate) => candidate.id !== target.id);
			if (alternatives.length === 0) lastFactorProtected();

			const rpID = resolveRpID(ctx, options);
			const origin = assertTrustedOrigin(ctx, options, rpID);
			const authenticationOptions = await generateAuthenticationOptions({
				rpID,
				userVerification: "required",
				timeout: CHALLENGE_TTL_SECONDS * 1000,
				allowCredentials: alternatives.map((passkey) => ({
					id: passkey.credentialID,
					transports: parseTransports(passkey.transports),
				})),
			});

			await createChallenge(ctx, "deletion", authenticationOptions.challenge, {
				rpID,
				origin,
				userId,
				targetPasskeyId: target.id,
			});
			return ctx.json(authenticationOptions);
		},
	);

export const deletePasskey = (options: PasskeyOptions | undefined) =>
	createAuthEndpoint(
		"/passkey/delete",
		{
			method: "POST",
			use: [sensitiveSessionMiddleware],
			body: z.object({
				id: z.string().min(1).max(255),
				proof: deletionProofSchema,
			}),
		},
		async (ctx) => {
			// Configuration must fail before a one-shot recovery proof or WebAuthn
			// challenge is reserved or consumed.
			assertPasskeyDeletionConfiguration(ctx);
			const userId = ctx.context.session.user.id;
			const originalSessionId = ctx.context.session.session.id;
			const presentedSessionToken = ctx.context.session.session.token;
			const originalExpiresAt = new Date(ctx.context.session.session.expiresAt);
			const originalExpiresAtTime = originalExpiresAt.getTime();
			if (
				!Number.isFinite(originalExpiresAtTime) ||
				originalExpiresAtTime <= Date.now()
			) {
				lifecycleConflict();
			}

			const deletionProof = ctx.body.proof;
			let passkeyAuthority: {
				rpID: string;
				requestOrigin: string;
				challenge: string;
			} | null = null;
			if (deletionProof.type === "passkey") {
				try {
					const rpID = resolveRpID(ctx, options);
					const requestOrigin = assertTrustedOrigin(ctx, options, rpID);
					const challenge = parseClientDataChallenge(
						deletionProof.response.response.clientDataJSON,
					);
					if (!challenge) deletionProofFailed();
					const challengeRecord = await consumeChallengeByParsedChallenge(
						ctx,
						"deletion",
						challenge,
					);
					if (
						!challengeRecord ||
						challengeRecord.rpID !== rpID ||
						challengeRecord.origin !== requestOrigin ||
						challengeRecord.userId !== userId ||
						challengeRecord.targetPasskeyId !== ctx.body.id
					) {
						deletionProofFailed();
					}
					passkeyAuthority = {
						rpID,
						requestOrigin,
						challenge,
					};
				} catch {
					deletionProofFailed();
				}
			}

			// A passkey proof is one-shot for every submitted target, including a
			// foreign or nonexistent identifier. Target lookup deliberately follows
			// challenge consumption so an ownership miss cannot preserve the proof.
			const target = await ctx.context.adapter.findOne<Passkey>({
				model: "passkey",
				where: [
					{ field: "id", value: ctx.body.id },
					{ field: "userId", value: userId },
				],
			});
			if (!target) {
				throw APIError.from("NOT_FOUND", PASSKEY_ERROR_CODES.PASSKEY_NOT_FOUND);
			}

			type LifecycleResult =
				| {
						kind: "success";
						replacementSession: Session;
						replacementUser: User;
				  }
				| { kind: "proof-error" };
			let lifecycle: LifecycleResult | undefined;
			let committedLifecycle: Extract<LifecycleResult, { kind: "success" }> | undefined;
			try {
				lifecycle = await runWithTransaction(ctx.context.adapter, async () => {
					const adapter = await getCurrentAdapter(ctx.context.adapter);
					const authoritativeUser = (await lockAndReadUser(
						adapter,
						userId,
					)) as (User & Record<string, unknown>) | null;
					if (!authoritativeUser) lifecycleConflict();
					const authoritative = await ctx.context.internalAdapter.findSession(
						presentedSessionToken,
					);
					if (
						!authoritative ||
						authoritative.session.id !== originalSessionId ||
						authoritative.session.userId !== userId ||
						authoritative.user.id !== userId ||
						new Date(authoritative.session.expiresAt).getTime() !==
							originalExpiresAtTime
					) {
						lifecycleConflict();
					}
					const authoritativeSession = await adapter.findOne<
						Session & Record<string, unknown>
					>({
						model: "session",
						where: [
							{ field: "id", value: originalSessionId },
							{ field: "userId", value: userId },
							{ field: "expiresAt", value: originalExpiresAt },
						],
					});
					if (!authoritativeSession) lifecycleConflict();
					const sessionGeneration =
						authoritativeSession[PASSKEY_SESSION_GENERATION_FIELD];
					const userGeneration =
						authoritativeUser[PASSKEY_SESSION_GENERATION_FIELD];
					if (
						typeof sessionGeneration !== "string" ||
						typeof userGeneration !== "string" ||
						sessionGeneration !== userGeneration
					) {
						lifecycleConflict();
					}
					const replacementIssuanceContext =
						await captureInternalSessionIssuanceContext(
							ctx.context.internalAdapter,
							{
								purpose: "replacement",
								sourceSessionToken: presentedSessionToken,
							},
						);

					const currentTarget = await adapter.findOne<Passkey>({
						model: "passkey",
						where: [
							{ field: "id", value: target.id },
							{ field: "userId", value: userId },
						],
					});
					if (!currentTarget) lifecycleConflict();

					if (deletionProof.type === "password") {
						const accounts = await ctx.context.internalAdapter.findAccounts(userId);
						if (
							!accounts.some(
								(account) =>
									account.providerId === "credential" && Boolean(account.password),
							)
						) {
							lastFactorProtected();
						}
						if (
							!(await validatePassword(ctx, {
								password: deletionProof.password,
								userId,
							}))
						) {
							deletionProofFailed();
						}
					} else if (
						deletionProof.type === "totp" ||
						deletionProof.type === "recovery-code"
					) {
						const twoFactorPlugin = ctx.context.getPlugin("two-factor");
						if (!twoFactorPlugin || authoritativeUser.twoFactorEnabled !== true) {
							lastFactorProtected();
						}
						const pluginOptions = twoFactorPlugin.options as
							| TwoFactorOptions
							| undefined;
						const table = pluginOptions?.twoFactorTable ?? "twoFactor";
						const factor = await adapter.findOne<TwoFactorTable>({
							model: table,
							where: [
								{ field: "userId", value: userId },
								{ field: "verified", value: true },
							],
						});
						if (!factor) lastFactorProtected();
						const backupCodeOptions = {
							storeBackupCodes: "encrypted",
							...pluginOptions?.backupCodeOptions,
						} satisfies BackupCodeOptions;
						let prepared: Awaited<ReturnType<typeof proveFactorStepUp>>;
						try {
							prepared = await proveFactorStepUp(
								ctx,
								adapter,
								table,
								factor,
								deletionProof.type === "totp"
									? { currentCode: deletionProof.code }
									: { recoveryCode: deletionProof.code },
								{
									backupCodeOptions,
									totpOptions: pluginOptions?.totpOptions,
								},
							);
						} catch {
							return { kind: "proof-error" as const };
						}
						const consumed = await adapter.incrementOne<TwoFactorTable>({
							model: table,
							where: [
								{ field: "id", value: factor.id },
								{ field: "userId", value: userId },
								...prepared.where,
							],
							increment: {},
							set: prepared.set,
						});
						await prepared.restoreAttempt();
						if (!consumed) return { kind: "proof-error" as const };
					} else {
						if (!passkeyAuthority) deletionProofFailed();
						const { challenge } = passkeyAuthority;
						const provingPasskey = await adapter.findOne<Passkey>({
							model: "passkey",
							where: [
								{
									field: "credentialID",
									value: deletionProof.response.id,
								},
								{ field: "userId", value: userId },
							],
						});
						if (provingPasskey?.id === currentTarget.id) lastFactorProtected();
						if (!provingPasskey) deletionProofFailed();

						let verification: Awaited<
							ReturnType<typeof verifyAuthenticationResponse>
						>;
						try {
							verification = await verifyAuthenticationResponse({
								response: deletionProof
									.response as unknown as AuthenticationResponseJSON,
								expectedChallenge: challenge,
								expectedOrigin: passkeyAuthority.requestOrigin,
								expectedRPID: passkeyAuthority.rpID,
								requireUserVerification: true,
								credential: {
									id: provingPasskey.credentialID,
									publicKey: base64Url.decode(provingPasskey.publicKey),
									counter: provingPasskey.counter,
									transports: parseTransports(provingPasskey.transports),
								},
							});
						} catch (error) {
							logFailure(ctx, "deletion proof verification threw", error);
							deletionProofFailed();
						}
						if (!verification.verified) deletionProofFailed();
						if (
							!(await advancePasskeyCounter(
								adapter,
								provingPasskey.id,
								provingPasskey.counter,
								verification.authenticationInfo.newCounter,
							))
						) {
							deletionProofFailed();
						}
					}

					const nextGeneration = generateId(32);
					const replacementUser = await rotatePasskeySessionGeneration(
						adapter,
						userId,
						userGeneration,
						nextGeneration,
					);
					if (!replacementUser) lifecycleConflict();

					const deletedTarget = await adapter.consumeOne<Passkey>({
						model: "passkey",
						where: [
							{ field: "id", value: currentTarget.id },
							{ field: "userId", value: userId },
							{ field: "credentialID", value: currentTarget.credentialID },
							{ field: "counter", value: currentTarget.counter },
						],
					});
					if (!deletedTarget) lifecycleConflict();

					await ctx.context.internalAdapter.deleteUserSessions(userId);
					const replacementSession =
						await ctx.context.internalAdapter.createSession(
							userId,
							false,
							{
								expiresAt: originalExpiresAt,
								__preserveSessionExpiresAt: true,
							},
							undefined,
							replacementIssuanceContext,
						);
					if (
						new Date(replacementSession.expiresAt).getTime() !==
						originalExpiresAtTime
					) {
						lifecycleConflict();
					}
					committedLifecycle = {
						kind: "success",
						replacementSession,
						replacementUser: replacementUser as User,
					};
					return committedLifecycle;
				});
			} catch (error) {
				if (error instanceof AfterTransactionHookError && committedLifecycle) {
					logFailure(ctx, "deletion post-commit publication failed", error);
					lifecycle = committedLifecycle;
				} else {
					throw error;
				}
			}

			if (!lifecycle) lifecycleConflict();
			if (lifecycle.kind === "proof-error") deletionProofFailed();
			await setSessionCookie(ctx, {
				session: lifecycle.replacementSession,
				user: lifecycle.replacementUser,
			});
			return ctx.json({ status: true });
		},
	);

export const listPasskeys = createAuthEndpoint(
	"/passkey/list",
	{
		method: "GET",
		use: [sensitiveSessionMiddleware],
	},
	async (ctx) => {
		const rows = await ctx.context.adapter.findMany<Passkey>({
			model: "passkey",
			where: [{ field: "userId", value: ctx.context.session.user.id }],
			sortBy: { field: "createdAt", direction: "desc" },
			limit: 100,
		});
		return ctx.json(rows.map(toPublicPasskey));
	},
);

export const updatePasskey = createAuthEndpoint(
	"/passkey/update",
	{
		method: "POST",
		use: [sensitiveSessionMiddleware],
		body: z.object({
			id: z.string().min(1).max(255),
			name: z.string().trim().min(1).max(NAME_MAX_LENGTH),
		}),
	},
	async (ctx) => {
		const updated = await ctx.context.adapter.update<Passkey>({
			model: "passkey",
			where: [
				{ field: "id", value: ctx.body.id },
				{ field: "userId", value: ctx.context.session.user.id },
			],
			update: { name: ctx.body.name, updatedAt: new Date() },
		});
		if (!updated) {
			throw APIError.from("NOT_FOUND", PASSKEY_ERROR_CODES.PASSKEY_NOT_FOUND);
		}
		return ctx.json(toPublicPasskey(updated));
	},
);
