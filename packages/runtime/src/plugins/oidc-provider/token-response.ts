import type { GenericEndpointContext } from "@clearance/core";

type HeaderState = Readonly<{
	entries: readonly (readonly [string, string])[];
	setCookies: readonly string[];
}>;

export type OAuthResponseHeaderSnapshot = ReadonlyMap<Headers, HeaderState>;

function responseHeaderContainers(ctx: GenericEndpointContext): Headers[] {
	const direct = (ctx as GenericEndpointContext & { responseHeaders?: Headers })
		.responseHeaders;
	return [...new Set([direct, ctx.context.responseHeaders].filter(Boolean))] as Headers[];
}

/** Capture response output before rollback-capable authorization work. */
export function snapshotOAuthResponseHeaders(
	ctx: GenericEndpointContext,
): OAuthResponseHeaderSnapshot {
	return new Map(
		responseHeaderContainers(ctx).map((headers) => [
			headers,
			{
				entries: Array.from(headers.entries()).filter(
					([name]) => name.toLowerCase() !== "set-cookie",
				),
				setCookies:
					typeof headers.getSetCookie === "function"
						? headers.getSetCookie()
						: headers.get("set-cookie")
							? [headers.get("set-cookie")!]
							: [],
			},
		]),
	);
}

/** Remove every header written by a transaction that failed to commit. */
export function restoreOAuthResponseHeaders(
	ctx: GenericEndpointContext,
	snapshot: OAuthResponseHeaderSnapshot,
): void {
	const headers = new Set([
		...snapshot.keys(),
		...responseHeaderContainers(ctx),
	]);
	for (const container of headers) {
		for (const name of Array.from(container.keys())) container.delete(name);
		const prior = snapshot.get(container);
		if (!prior) continue;
		for (const [name, value] of prior.entries) container.append(name, value);
		for (const cookie of prior.setCookies) {
			container.append("set-cookie", cookie);
		}
	}
}

export const NO_STORE_TOKEN_RESPONSE_HEADERS = {
	"Cache-Control": "no-store",
	Pragma: "no-cache",
} as const;

export function oauthExpiresIn(expiresAt: Date, now = Date.now()): number {
	return Math.max(0, Math.ceil((expiresAt.getTime() - now) / 1000));
}

export function setNoStoreTokenResponseHeaders(
	ctx: Pick<GenericEndpointContext, "setHeader">,
): void {
	ctx.setHeader(
		"Cache-Control",
		NO_STORE_TOKEN_RESPONSE_HEADERS["Cache-Control"],
	);
	ctx.setHeader("Pragma", NO_STORE_TOKEN_RESPONSE_HEADERS.Pragma);
}
