import { base64Url } from "@clearance/utils/base64";
import { createAuthMiddleware } from "@clearance/runtime/api";
import { constantTimeEqual } from "@clearance/runtime/crypto";
import { SCIMAPIError } from "./scim-error";
import { verifySCIMToken } from "./scim-tokens";
import type { SCIMOptions, SCIMProvider } from "./types";

export type AuthMiddleware = ReturnType<typeof authMiddlewareFactory>;

const invalidSCIMToken = () =>
	new SCIMAPIError("UNAUTHORIZED", {
		detail: "Invalid SCIM token",
	});

const isValidBase64Token = (token: string) => {
	const alphabet = token.includes("-") || token.includes("_")
		? /^[A-Za-z0-9_-]*={0,2}$/
		: /^[A-Za-z0-9+/]*={0,2}$/;
	if (!alphabet.test(token)) return false;

	const paddingStart = token.indexOf("=");
	const payload = paddingStart === -1 ? token : token.slice(0, paddingStart);
	const padding = paddingStart === -1 ? "" : token.slice(paddingStart);
	const requiredPadding = (4 - (payload.length % 4)) % 4;

	return payload.length % 4 !== 1 && padding.length === requiredPadding;
};

const decodeSCIMToken = (token: string) => {
	try {
		if (!isValidBase64Token(token)) return null;

		const decodedToken = new TextDecoder("utf-8", { fatal: true }).decode(
			base64Url.decode(token),
		);
		const parts = decodedToken.split(":");
		const [scimToken, providerId] = parts;
		const organizationId = parts.slice(2).join(":");

		if (!scimToken || !providerId) {
			return null;
		}

		return { scimToken, providerId, organizationId };
	} catch {
		return null;
	}
};

/**
 * The middleware forces the endpoint to have a valid token
 */
export const authMiddlewareFactory = (opts: SCIMOptions) =>
	createAuthMiddleware(async (ctx) => {
		const authHeader = ctx.headers?.get("Authorization");
		const authSCIMToken = authHeader?.replace(/^Bearer\s+/i, "");

		if (!authSCIMToken) {
			throw new SCIMAPIError("UNAUTHORIZED", {
				detail: "SCIM token is required",
			});
		}

		const tokenParts = decodeSCIMToken(authSCIMToken);
		if (!tokenParts) throw invalidSCIMToken();

		const { scimToken, providerId, organizationId } = tokenParts;

		let scimProvider: Omit<SCIMProvider, "id"> | null =
			opts.defaultSCIM?.find((p) => {
				if (p.providerId === providerId && !organizationId) {
					return true;
				}

				return !!(
					p.providerId === providerId &&
					organizationId &&
					p.organizationId === organizationId
				);
			}) ?? null;

		if (scimProvider) {
			if (constantTimeEqual(scimProvider.scimToken, scimToken)) {
				return { authSCIMToken: scimProvider.scimToken, scimProvider };
			} else {
				throw invalidSCIMToken();
			}
		}

		scimProvider = await ctx.context.adapter.findOne<SCIMProvider>({
			model: "scimProvider",
			where: [
				{ field: "providerId", value: providerId },
				...(organizationId
					? [{ field: "organizationId", value: organizationId }]
					: []),
			],
		});

		if (!scimProvider) {
			throw invalidSCIMToken();
		}

		const isValidToken = await verifySCIMToken(
			ctx,
			opts,
			scimProvider.scimToken,
			scimToken,
			{
				providerId: scimProvider.providerId,
				organizationId: scimProvider.organizationId,
			},
		);

		if (!isValidToken) {
			throw invalidSCIMToken();
		}

		return { authSCIMToken: scimToken, scimProvider };
	});
