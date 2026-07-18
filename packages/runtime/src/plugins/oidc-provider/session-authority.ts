import type { GenericEndpointContext } from "@clearance/core";
import { APIError } from "@clearance/core/error";
import { getAuthoritativeSessionFromCtx } from "../../api";
import { usesManagedAuthenticationPolicy } from "../../internal/managed-authentication-transaction";
import {
	captureInternalSessionDerivativeAuthority,
	type InternalSessionDerivativeAuthority,
	type InternalSessionDerivativeAuthorityBinding,
	type InternalSessionDerivativePurpose,
	validateInternalSessionDerivativeAuthority,
} from "../../internal/session-derivative-authority";

type SessionWithUser = NonNullable<GenericEndpointContext["context"]["session"]>;

export async function captureOAuthAuthorizationSessionAuthority(
	ctx: GenericEndpointContext,
	purpose: Extract<InternalSessionDerivativePurpose, "oidc" | "mcp">,
	fallbackSession: SessionWithUser,
): Promise<{
	sourceSession: SessionWithUser;
	sessionDerivativeAuthority?: InternalSessionDerivativeAuthorityBinding;
	sourceAuthority?: InternalSessionDerivativeAuthority;
}> {
	const managed = usesManagedAuthenticationPolicy(ctx);
	const sourceSession = managed
		? await getAuthoritativeSessionFromCtx(ctx)
		: fallbackSession;
	if (!sourceSession) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "session authority is unavailable",
			error: "invalid_request",
		});
	}
	const sessionDerivativeAuthority =
		await captureInternalSessionDerivativeAuthority(
			ctx.context.internalAdapter,
			{
				purpose,
				sourceSessionToken: sourceSession.session.token,
			},
		);
	if (managed && !sessionDerivativeAuthority) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "session derivative authority is unavailable",
			error: "invalid_request",
		});
	}
	const sourceAuthority = sessionDerivativeAuthority
		? await validateInternalSessionDerivativeAuthority(
				ctx.context.internalAdapter,
				sessionDerivativeAuthority,
				{
					purpose,
					subjectId: sourceSession.user.id,
					organizationId:
						sourceSession.session.activeOrganizationId ?? null,
				},
			)
		: undefined;
	if (managed && !sourceAuthority) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "session derivative authority is unavailable",
			error: "invalid_request",
		});
	}
	return {
		sourceSession,
		sessionDerivativeAuthority,
		sourceAuthority,
	};
}
