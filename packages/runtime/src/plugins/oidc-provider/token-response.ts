import type { GenericEndpointContext } from "@clearance/core";

export const NO_STORE_TOKEN_RESPONSE_HEADERS = {
	"Cache-Control": "no-store",
	Pragma: "no-cache",
} as const;

export function setNoStoreTokenResponseHeaders(
	ctx: Pick<GenericEndpointContext, "setHeader">,
): void {
	ctx.setHeader(
		"Cache-Control",
		NO_STORE_TOKEN_RESPONSE_HEADERS["Cache-Control"],
	);
	ctx.setHeader("Pragma", NO_STORE_TOKEN_RESPONSE_HEADERS.Pragma);
}
