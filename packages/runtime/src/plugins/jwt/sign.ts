import type { GenericEndpointContext } from "@clearance/core";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { ClearanceError } from "@clearance/core/error";
import type { JWTPayload } from "jose";
import { decodeJwt, importJWK, SignJWT } from "jose";
import { symmetricDecrypt } from "../../crypto";
import {
	authenticateInternalServiceAccountCredential,
	readInternalEffectiveAuthorization,
} from "../../internal/authorization-authority";
import {
	captureInternalSessionDerivativeAuthority,
	validateInternalSessionDerivativeAuthority,
} from "../../internal/session-derivative-authority";
import { readInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { getJwksAdapter } from "./adapter";
import type { JwtOptions } from "./types";
import {
	createJwk,
	decryptPrivateJwk,
	getPrivateKeyStorage,
	toExpJWT,
} from "./utils";

type JWTPayloadWithOptional = {
	/**
	 * JWT Issuer
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1 RFC7519#section-4.1.1}
	 */
	iss?: string | undefined;

	/**
	 * JWT Subject
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2 RFC7519#section-4.1.2}
	 */
	sub?: string | undefined;

	/**
	 * JWT Audience
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3 RFC7519#section-4.1.3}
	 */
	aud?: string | string[] | undefined;

	/**
	 * JWT ID
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7 RFC7519#section-4.1.7}
	 */
	jti?: string | undefined;

	/**
	 * JWT Not Before
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5 RFC7519#section-4.1.5}
	 */
	nbf?: number | undefined;

	/**
	 * JWT Expiration Time
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4 RFC7519#section-4.1.4}
	 */
	exp?: number | undefined;

	/**
	 * JWT Issued At
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6 RFC7519#section-4.1.6}
	 */
	iat?: number | undefined;

	/** Any other JWT Claim Set member. */
	[propName: string]: unknown | undefined;
};

export const JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM =
	"urn:clearance:claims:session-derivative-authority";
export const JWT_SESSION_SOURCE_SUBJECT_CLAIM =
	"urn:clearance:claims:session-source-subject";
export const JWT_SESSION_SOURCE_ORGANIZATION_CLAIM =
	"urn:clearance:claims:session-source-organization";
export const JWT_AUTHORIZATION_ACTIONS_CLAIM = "actions";
export const JWT_AUTHORIZATION_REVISION_CLAIM = "authz_revision";
export const JWT_SUBJECT_KIND_CLAIM = "urn:clearance:claims:subject-kind";
export const JWT_ORGANIZATION_ID_CLAIM = "urn:clearance:claims:organization-id";

const JWT_RESERVED_AUTHORITY_CLAIMS = [
	JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM,
	JWT_SESSION_SOURCE_SUBJECT_CLAIM,
	JWT_SESSION_SOURCE_ORGANIZATION_CLAIM,
	JWT_AUTHORIZATION_ACTIONS_CLAIM,
	JWT_AUTHORIZATION_REVISION_CLAIM,
	JWT_SUBJECT_KIND_CLAIM,
	JWT_ORGANIZATION_ID_CLAIM,
] as const;

function equalStringArrays(left: unknown, right: unknown): boolean {
	return (
		Array.isArray(left) &&
		Array.isArray(right) &&
		left.length === right.length &&
		left.every((value, index) => value === right[index])
	);
}

export async function signJWT(
	ctx: GenericEndpointContext,
	config: {
		options?: JwtOptions | undefined;
		payload: JWTPayloadWithOptional;
		maxExpiresAt?: Date | undefined;
	},
) {
	const { options } = config;
	const payload = config.payload as JWTPayload;

	// Iat
	const nowSeconds = Math.floor(Date.now() / 1000);
	const iat = payload.iat!;

	// Exp
	let exp = payload.exp;
	const defaultExp = toExpJWT(
		options?.jwt?.expirationTime ?? "15m",
		iat ?? nowSeconds,
	);
	exp = exp ?? defaultExp;
	if (config.maxExpiresAt) {
		exp = Math.min(exp, Math.floor(config.maxExpiresAt.getTime() / 1000));
	}
	if (config.maxExpiresAt && exp <= nowSeconds) {
		throw new ClearanceError(
			"Cannot issue an access token for an expired session",
		);
	}

	// Nbf
	const nbf = payload.nbf!;

	// At handler-time, options.baseURL is always a resolved string origin
	const baseURLOrigin =
		typeof ctx.context.options.baseURL === "string"
			? ctx.context.options.baseURL
			: "";

	// Iss
	const iss = payload.iss;
	const defaultIss = options?.jwt?.issuer ?? baseURLOrigin;

	// Aud
	const aud = payload.aud;
	const defaultAud = options?.jwt?.audience ?? baseURLOrigin;

	// Custom/remote signing function
	if (options?.jwt?.sign) {
		const jwtPayload: JWTPayload = {
			...payload,
			iat,
			exp,
			nbf,
			iss: iss ?? defaultIss,
			aud: aud ?? defaultAud,
		};
		const token = await options.jwt.sign(jwtPayload);
		if (
			JWT_RESERVED_AUTHORITY_CLAIMS.some(
				(claim) => jwtPayload[claim] !== undefined,
			)
		) {
			const isMachineToken =
				jwtPayload[JWT_SUBJECT_KIND_CLAIM] === "service_account";
			let returnedPayload: JWTPayload;
			try {
				returnedPayload = decodeJwt(token);
			} catch {
				throw new ClearanceError(
					"Custom JWT signer returned an invalid session-bound token",
				);
			}
			if (
				!Number.isFinite(returnedPayload.exp) ||
				!Number.isInteger(returnedPayload.exp) ||
				returnedPayload.exp! > exp ||
				(isMachineToken && returnedPayload.sub !== jwtPayload.sub) ||
				JWT_RESERVED_AUTHORITY_CLAIMS.some((claim) => {
					const expected = jwtPayload[claim];
					const present = Object.hasOwn(returnedPayload, claim);
					if (expected === undefined) return present;
					return (
						!present ||
						(claim === JWT_AUTHORIZATION_ACTIONS_CLAIM
							? !equalStringArrays(returnedPayload[claim], expected)
							: returnedPayload[claim] !== expected)
					);
				})
			) {
				throw new ClearanceError(
					"Custom JWT signer changed session-bound authority",
				);
			}
		}
		return token;
	}

	const currentAdapter = await getCurrentAdapter(ctx.context.adapter);
	const currentCtx =
		currentAdapter === ctx.context.adapter
			? ctx
			: (Object.assign(Object.create(ctx), {
					context: { ...ctx.context, adapter: currentAdapter },
				}) as GenericEndpointContext);
	const adapter = getJwksAdapter(
		currentAdapter as typeof ctx.context.adapter,
		options,
	);
	let key = await adapter.getLatestKey(currentCtx);
	if (!key || (key.expiresAt && key.expiresAt < new Date())) {
		key = await createJwk(currentCtx, options);
	}
	const privateKeyEncryptionEnabled =
		!options?.jwks?.disablePrivateKeyEncryption;
	const privateKeyStorage = getPrivateKeyStorage(options);
	const privateWebKey = privateKeyStorage
		? await decryptPrivateJwk(
					privateKeyStorage,
					key.privateKey,
					key.publicKey,
				)
		: privateKeyEncryptionEnabled
		? await symmetricDecrypt({
				key: ctx.context.secretConfig,
				data: JSON.parse(key.privateKey),
			}).catch(() => {
				throw new ClearanceError(
					"Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption.",
				);
			})
		: key.privateKey;
	const alg = key.alg ?? options?.jwks?.keyPairConfig?.alg ?? "EdDSA";
	const privateKey = await importJWK(JSON.parse(privateWebKey), alg);

	const jwt = new SignJWT(payload)
		.setProtectedHeader({
			alg,
			kid: key.id,
		})
		.setExpirationTime(exp)
		.setIssuer(iss ?? defaultIss)
		.setAudience(aud ?? defaultAud);
	if (iat) jwt.setIssuedAt(iat);
	if (payload.sub) jwt.setSubject(payload.sub);
	if (payload.nbf) jwt.setNotBefore(payload.nbf);
	if (payload.jti) jwt.setJti(payload.jti);
	return await jwt.sign(privateKey);
}

/** Issues a short-lived, revision-bound JWT from a service-account credential. */
export async function issueServiceAccountJWT(
	ctx: GenericEndpointContext,
	options: JwtOptions | undefined,
	input: Readonly<{ secret: string }>,
): Promise<string> {
	try {
		return await runWithTransaction(ctx.context.adapter, async () => {
			const authenticated = await authenticateInternalServiceAccountCredential(
				ctx.context.internalAdapter,
				input.secret,
			);
			if (!authenticated) throw new Error("authority unavailable");
			return signJWT(ctx, {
				options,
				maxExpiresAt: authenticated.expiresAt ?? undefined,
				payload: {
					iat: Math.floor(Date.now() / 1000),
					sub: authenticated.subject.id,
					[JWT_SUBJECT_KIND_CLAIM]: "service_account",
					[JWT_ORGANIZATION_ID_CLAIM]: authenticated.organizationId,
					[JWT_AUTHORIZATION_ACTIONS_CLAIM]: Object.freeze([
						...authenticated.actions,
					]),
					[JWT_AUTHORIZATION_REVISION_CLAIM]: authenticated.revision,
				},
			});
		});
	} catch {
		throw new ClearanceError("Cannot issue an access token");
	}
}

export async function issueJwtAccessToken(
	ctx: GenericEndpointContext,
	options?: JwtOptions | undefined,
	sessionClaims?:
		| {
				sid: string;
				session_family: string;
				session_generation: number;
		  }
		| undefined,
) {
	const currentSession = ctx.context.session ?? ctx.context.newSession;
	if (!currentSession?.session.id) {
		throw new ClearanceError("Cannot issue an access token without a session");
	}
	const sourceSessionId = currentSession.session.id;

	return runWithTransaction(ctx.context.adapter, async () => {
		const live = await ctx.context.internalAdapter.findSessionById(sourceSessionId);
		if (!live || live.session.id !== sourceSessionId) {
			throw new ClearanceError(
				"Cannot issue an access token for an inactive session",
			);
		}
		const sourceExpiresAt = live.session.expiresAt;
		if (
			!(sourceExpiresAt instanceof Date) ||
			!Number.isFinite(sourceExpiresAt.getTime())
		) {
			throw new ClearanceError(
				"Cannot issue an access token for an invalid session",
			);
		}

		const binding = await captureInternalSessionDerivativeAuthority(
			ctx.context.internalAdapter,
			{ purpose: "jwt", sourceSessionId },
		);
		if (!binding && readInternalAuthenticationPolicy(ctx.context.options)) {
			throw new ClearanceError(
				"Cannot issue an access token without session derivative authority",
			);
		}
		const authority = binding
			? await validateInternalSessionDerivativeAuthority(
					ctx.context.internalAdapter,
					binding,
					{ purpose: "jwt", subjectId: live.user.id },
				)
			: undefined;
		if (
			binding &&
			(!authority ||
				authority.sourceSessionId !== sourceSessionId ||
				authority.sourceSubjectId !== live.user.id ||
				authority.sourceExpiresAt !== sourceExpiresAt.getTime())
		) {
			throw new ClearanceError(
				"Cannot issue an access token from stale session authority",
			);
		}

		const liveSession = { session: live.session, user: live.user };
		const payload = !options?.jwt?.definePayload
			? live.user
			: await options.jwt.definePayload(liveSession);
		const authorization =
			authority?.sourceOrganizationId === null || authority === undefined
				? undefined
				: await readInternalEffectiveAuthorization(ctx.context.internalAdapter, {
						organizationId: authority.sourceOrganizationId,
						subject: { kind: "principal", id: authority.sourceSubjectId },
					});
		const reservedClaims = binding
			? {
					[JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM]: binding,
					[JWT_SESSION_SOURCE_SUBJECT_CLAIM]: authority!.sourceSubjectId,
					[JWT_SESSION_SOURCE_ORGANIZATION_CLAIM]:
						authority!.sourceOrganizationId,
				}
			: {
					[JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM]: undefined,
					[JWT_SESSION_SOURCE_SUBJECT_CLAIM]: undefined,
					[JWT_SESSION_SOURCE_ORGANIZATION_CLAIM]: undefined,
				};
		const authorizationClaims = authorization
			? {
					[JWT_AUTHORIZATION_ACTIONS_CLAIM]: Object.freeze([
						...authorization.actions,
					]),
					[JWT_AUTHORIZATION_REVISION_CLAIM]: authorization.revision,
				}
			: {
					[JWT_AUTHORIZATION_ACTIONS_CLAIM]: undefined,
					[JWT_AUTHORIZATION_REVISION_CLAIM]: undefined,
				};

		return signJWT(ctx, {
			options,
			maxExpiresAt: sourceExpiresAt,
			payload: {
				iat: Math.floor(Date.now() / 1000),
				...payload,
				...sessionClaims,
					sub:
						(await options?.jwt?.getSubject?.(liveSession)) ?? live.user.id,
					...reservedClaims,
					...authorizationClaims,
				},
		});
	});
}
