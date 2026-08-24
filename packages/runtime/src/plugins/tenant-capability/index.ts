import type { GenericEndpointContext } from "@clearance/core";
import { APIError } from "@clearance/core/error";
import { getAuthoritativeSessionFromCtx } from "../../api";
import { parseCookies } from "../../cookies";
import {
	InternalAuthorizationAuthorityUnavailableError,
	InvalidInternalAuthorizationAuthorityError,
	readInternalEffectiveAuthorization,
} from "../../internal/authorization-authority";

/**
 * The only authority this kernel accepts is the original request's signed
 * browser session cookie. It never accepts an Authorization header, bearer
 * token, JWT, operator credential, or service-account credential.
 */
export type TenantCapabilityContext = Readonly<{
	organizationId: string;
	principalId: string;
	revision: string;
}>;

export type RequireTenantCapabilityInput = Readonly<{
	organizationId: string;
	requiredActions: readonly string[];
}>;

function authorizationDenied(): never {
	throw APIError.fromStatus("FORBIDDEN", {
		message: "Tenant authorization is required",
		code: "TENANT_AUTHORIZATION_REQUIRED",
	});
}

function sessionDenied(): never {
	throw APIError.fromStatus("UNAUTHORIZED", {
		message: "A valid session is required",
		code: "UNAUTHORIZED",
	});
}

function authorizationUnavailable(): never {
	throw new APIError("SERVICE_UNAVAILABLE", {
		message: "Tenant authorization is unavailable",
		code: "TENANT_AUTHORIZATION_UNAVAILABLE",
	});
}

function identifier(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= 1_024 &&
		value.trim() === value &&
		!value.includes("\0")
	);
}

function snapshotRequiredActions(value: unknown): readonly string[] {
	if (!Array.isArray(value) || value.length < 1 || value.length > 256) {
		authorizationDenied();
	}
	const snapshot = value.map((action) => {
		if (
			typeof action !== "string" ||
			!/^[a-z][a-z0-9._:-]{0,127}$/.test(action)
		) {
			authorizationDenied();
		}
		return action;
	});
	if (new Set(snapshot).size !== snapshot.length) authorizationDenied();
	return Object.freeze(snapshot.sort());
}

async function getAuthoritativeBrowserSession(ctx: GenericEndpointContext) {
	const requestHeaders = ctx.request?.headers;
	if (!requestHeaders || requestHeaders.has("authorization")) sessionDenied();
	const sessionCookieName = ctx.context.authCookies.sessionToken.name;
	const cookieHeader = requestHeaders.get("cookie");
	if (!cookieHeader || !parseCookies(cookieHeader).has(sessionCookieName)) {
		sessionDenied();
	}
	const signedSessionToken = await ctx.getSignedCookie(
		sessionCookieName,
		ctx.context.secret,
	);
	if (!signedSessionToken) sessionDenied();
	return getAuthoritativeSessionFromCtx<
		{ id: string },
		{ id: string; activeOrganizationId?: string | null }
	>(ctx);
}

/**
 * Re-reads browser-session and tenant authorization state for a route-derived
 * organization, then immediately executes the guarded tenant operation.
 *
 * It has no CSRF/origin-check role. HTTP mutation routes must retain the
 * runtime origin middleware as their independent CSRF authority.
 */
export async function withTenantCapability<Result>(
	ctx: GenericEndpointContext,
	input: RequireTenantCapabilityInput,
	guardedAdapter: (
		context: TenantCapabilityContext,
	) => Result | Promise<Result>,
): Promise<Result> {
	const organizationId = input?.organizationId;
	if (!identifier(organizationId) || typeof guardedAdapter !== "function") {
		authorizationDenied();
	}
	const requiredActions = snapshotRequiredActions(input.requiredActions);
	const session = await getAuthoritativeBrowserSession(ctx);
	if (
		!session ||
		!identifier(session.user.id) ||
		!identifier(session.session.id) ||
		session.session.activeOrganizationId !== organizationId
	) {
		sessionDenied();
	}

	let effective;
	try {
		effective = await readInternalEffectiveAuthorization(
			ctx.context.internalAdapter,
			{
				organizationId,
				subject: { kind: "principal", id: session.user.id },
			},
		);
	} catch (error) {
		if (
			error instanceof InternalAuthorizationAuthorityUnavailableError ||
			error instanceof InvalidInternalAuthorizationAuthorityError
		) {
			authorizationUnavailable();
		}
		throw error;
	}

	if (
		!effective ||
		effective.organizationId !== organizationId ||
		effective.subject.kind !== "principal" ||
		effective.subject.id !== session.user.id ||
		!requiredActions.every((action) => effective.actions.includes(action))
	) {
		authorizationDenied();
	}
	return guardedAdapter(
		Object.freeze({
			organizationId: effective.organizationId,
			principalId: effective.subject.id,
			revision: effective.revision,
		}),
	);
}
