import type { GenericEndpointContext } from "@clearance/core";
import {
	getCurrentAuthContext,
	runWithTransaction,
} from "@clearance/core/context";
import { base64 } from "@clearance/utils/base64";
import type { JWTPayload } from "jose";
import { importJWK, jwtVerify } from "jose";
import { readInternalEffectiveAuthorization } from "../../internal/authorization-authority";
import { validateInternalSessionDerivativeAuthority } from "../../internal/session-derivative-authority";
import { getJwksAdapter } from "./adapter";
import { DEFAULT_JWKS_GRACE_PERIOD_SECONDS } from "./constant";
import {
	JWT_AUTHORIZATION_ACTIONS_CLAIM,
	JWT_AUTHORIZATION_REVISION_CLAIM,
	JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM,
	JWT_SESSION_SOURCE_ORGANIZATION_CLAIM,
	JWT_SESSION_SOURCE_SUBJECT_CLAIM,
} from "./sign";
import type { JwtOptions } from "./types";

const POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807n;
const MAX_AUTHORIZATION_ACTIONS = 256;
const ACTION_TOKEN = /^[a-z][a-z0-9._:-]{0,127}$/;

function validAuthorizationRevision(value: unknown): value is string {
	if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) return false;
	try {
		return BigInt(value) <= POSTGRES_BIGINT_MAX;
	} catch {
		return false;
	}
}

function validAuthorizationActions(value: unknown): value is readonly string[] {
	return (
		Array.isArray(value) &&
		value.length <= MAX_AUTHORIZATION_ACTIONS &&
		value.every(
			(action, index) =>
				typeof action === "string" &&
				ACTION_TOKEN.test(action) &&
				(index === 0 || action > value[index - 1]!),
		)
	);
}

function equalStringArrays(left: readonly string[], right: readonly string[]): boolean {
	return left.length === right.length && left.every((value, index) => value === right[index]);
}

/**
 * Verify a JWT token using the JWKS public keys
 * Returns the payload if valid, null otherwise
 */
export async function verifyJWT<T extends JWTPayload = JWTPayload>(
	token: string,
	options?: JwtOptions,
): Promise<(T & Required<Pick<JWTPayload, "sub" | "aud">>) | null> {
	const ctx = await getCurrentAuthContext();
	try {
		const parts = token.split(".");
		if (parts.length !== 3) {
			return null;
		}

		const headerStr = new TextDecoder().decode(base64.decode(parts[0]!));
		const header = JSON.parse(headerStr);
		const kid = header.kid;

		if (!kid) {
			ctx.context.logger.debug("JWT missing kid in header");
			return null;
		}

		// Get all JWKS keys
		const adapter = getJwksAdapter(ctx.context.adapter, options);
		const keys = await adapter.getAllKeys(ctx as GenericEndpointContext);

		if (!keys || keys.length === 0) {
			ctx.context.logger.debug("No JWKS keys available");
			return null;
		}

		const key = keys.find((k) => k.id === kid);
		if (!key) {
			ctx.context.logger.debug(`No JWKS key found for kid: ${kid}`);
			return null;
		}
		const gracePeriodMs =
			(options?.jwks?.gracePeriod ?? DEFAULT_JWKS_GRACE_PERIOD_SECONDS) *
			1000;
		if (
			key.expiresAt &&
			key.expiresAt.getTime() + gracePeriodMs <= Date.now()
		) {
			ctx.context.logger.debug(`JWKS key is retired: ${kid}`);
			return null;
		}

		const publicKey = JSON.parse(key.publicKey);
		const alg = key.alg ?? options?.jwks?.keyPairConfig?.alg ?? "EdDSA";
		const cryptoKey = await importJWK(publicKey, alg);

		const baseURLOrigin =
			typeof ctx.context.options.baseURL === "string"
				? ctx.context.options.baseURL
				: undefined;
		const { payload } = await jwtVerify(token, cryptoKey, {
			issuer: options?.jwt?.issuer ?? baseURLOrigin,
			audience: options?.jwt?.audience ?? baseURLOrigin,
		});

		if (!payload.sub || !payload.aud) {
			return null;
		}
		const hasAuthorizationActions = Object.hasOwn(
			payload,
			JWT_AUTHORIZATION_ACTIONS_CLAIM,
		);
		const hasAuthorizationRevision = Object.hasOwn(
			payload,
			JWT_AUTHORIZATION_REVISION_CLAIM,
		);
		if (
			hasAuthorizationActions !== hasAuthorizationRevision ||
			(hasAuthorizationActions &&
				(!validAuthorizationActions(
					payload[JWT_AUTHORIZATION_ACTIONS_CLAIM],
				) ||
					!validAuthorizationRevision(
						payload[JWT_AUTHORIZATION_REVISION_CLAIM],
					)))
		) {
			return null;
		}

		const hasAuthority = Object.hasOwn(
			payload,
			JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM,
		);
		const hasSourceSubject = Object.hasOwn(
			payload,
			JWT_SESSION_SOURCE_SUBJECT_CLAIM,
		);
		const hasSourceOrganization = Object.hasOwn(
			payload,
			JWT_SESSION_SOURCE_ORGANIZATION_CLAIM,
		);
		if (
			hasAuthorizationActions &&
			(!hasAuthority || !hasSourceSubject || !hasSourceOrganization)
		) {
			return null;
		}
		if (hasAuthority || hasSourceSubject || hasSourceOrganization) {
			const binding = payload[JWT_SESSION_DERIVATIVE_AUTHORITY_CLAIM];
			const sourceSubject = payload[JWT_SESSION_SOURCE_SUBJECT_CLAIM];
			const sourceOrganization =
				payload[JWT_SESSION_SOURCE_ORGANIZATION_CLAIM];
			if (
				!hasAuthority ||
				!hasSourceSubject ||
				!hasSourceOrganization ||
				typeof binding !== "string" ||
				binding.length === 0 ||
				typeof sourceSubject !== "string" ||
				sourceSubject.length === 0 ||
				(sourceOrganization !== null &&
					typeof sourceOrganization !== "string")
			) {
				return null;
			}
			const authority = await runWithTransaction(
				ctx.context.adapter,
				async () =>
					validateInternalSessionDerivativeAuthority(
						ctx.context.internalAdapter,
						binding,
						{
							purpose: "jwt",
							subjectId: sourceSubject,
							organizationId: sourceOrganization,
						},
					),
			);
			if (
				!authority ||
				!Number.isFinite(payload.exp) ||
				!Number.isInteger(payload.exp) ||
				payload.exp! > Math.floor(authority.sourceExpiresAt / 1000)
			) {
				return null;
			}
			const effective =
				sourceOrganization === null
					? undefined
					: await readInternalEffectiveAuthorization(
							ctx.context.internalAdapter,
							{
								organizationId: sourceOrganization,
								subject: { kind: "principal", id: sourceSubject },
							},
						);
			if (
				hasAuthorizationActions &&
				(sourceOrganization === null ||
					!effective ||
					payload[JWT_AUTHORIZATION_REVISION_CLAIM] !== effective.revision ||
					!equalStringArrays(
						payload[JWT_AUTHORIZATION_ACTIONS_CLAIM] as readonly string[],
						effective.actions,
					))
			) {
				return null;
			}
			if (!hasAuthorizationActions && effective) {
				return null;
			}
		}

		return payload as T & Required<Pick<JWTPayload, "sub" | "aud">>;
	} catch (error) {
		ctx.context.logger.debug("JWT verification failed", error);
		return null;
	}
}
