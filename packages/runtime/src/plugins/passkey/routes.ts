import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
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
	CHALLENGE_TTL_SECONDS,
	consumeChallengeByParsedChallenge,
	createChallenge,
	parseClientDataChallenge,
} from "./challenge";
import { advancePasskeyCounter } from "./counter";
import { PASSKEY_ERROR_CODES } from "./error-codes";
import { assertTrustedOrigin, resolveRpID } from "./origin";
import type { Passkey, PasskeyOptions, PublicPasskey } from "./types";
import { decodeCanonicalUserHandle, ensurePasskeyUserHandle } from "./user-handle";

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
		typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function"
	) {
		throw APIError.from(
			"INTERNAL_SERVER_ERROR",
			PASSKEY_ERROR_CODES.CONFIGURATION_ERROR,
		);
	}
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
			const { session, user } = await runWithTransaction(
				ctx.context.adapter,
				async () => {
					const trxAdapter = await getCurrentAdapter(ctx.context.adapter);
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
					);
					if (!newSession) {
						throw APIError.from(
							"INTERNAL_SERVER_ERROR",
							PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED,
						);
					}
					const sessionUser = await ctx.context.internalAdapter.findUserById(
						passkey.userId,
					);
					if (!sessionUser) {
						throw APIError.from(
							"INTERNAL_SERVER_ERROR",
							PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED,
						);
					}
					return { session: newSession, user: sessionUser };
				},
			);

			await setSessionCookie(ctx, { session, user });

			return ctx.json({
				session: parseSessionOutput(ctx.context.options, session),
				user: parseUserOutput(ctx.context.options, user),
			});
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
