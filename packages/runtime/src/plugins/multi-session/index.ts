import type { ClearancePlugin } from "@clearance/core";
import {
	createAuthEndpoint,
	createAuthMiddleware,
} from "@clearance/core/api";
import * as z from "zod";
import { APIError, sessionMiddleware } from "../../api";
import {
	deleteSessionCookie,
	expireCookie,
	parseCookies,
	parseSetCookieHeader,
	SECURE_COOKIE_PREFIX,
	setSessionCookie,
} from "../../cookies";
import { parseSessionOutput, parseUserOutput } from "../../db/schema";
import { PACKAGE_VERSION } from "../../version";

declare module "@clearance/core" {
	interface ClearancePluginRegistry<AuthOptions, Options> {
		"multi-session": {
			creator: typeof multiSession;
		};
	}
}

export interface MultiSessionConfig {
	/**
	 * The maximum number of sessions a user can have
	 * at a time
	 * @default 5
	 */
	maximumSessions?: number | undefined;
}

import { MULTI_SESSION_ERROR_CODES as ERROR_CODES } from "./error-codes";

export { MULTI_SESSION_ERROR_CODES as ERROR_CODES } from "./error-codes";

const setActiveSessionBodySchema = z
	.object({
		sessionId: z.string().optional().meta({
			description: "The stable session identifier to set as active",
		}),
		sessionToken: z.string().optional().meta({
			description: "Deprecated session refresh token compatibility alias",
		}),
	})
	.refine((body) => Boolean(body.sessionId) !== Boolean(body.sessionToken), {
		message: "Provide exactly one of sessionId or sessionToken",
	});

const revokeDeviceSessionBodySchema = setActiveSessionBodySchema;

export const multiSession = (options?: MultiSessionConfig | undefined) => {
	const opts = {
		maximumSessions: 5,
		...options,
	};

	const isMultiSessionCookie = (key: string) => key.includes("_multi-");
	const getMultiSessionCookieName = (baseName: string, sessionId: string) =>
		`${baseName}_multi-${encodeURIComponent(sessionId)}`;

	return {
		id: "multi-session",
		version: PACKAGE_VERSION,
		endpoints: {
			/**
			 * ### Endpoint
			 *
			 * GET `/multi-session/list-device-sessions`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.listDeviceSessions`
			 *
			 * **client:**
			 * `authClient.multiSession.listDeviceSessions`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			listDeviceSessions: createAuthEndpoint(
				"/multi-session/list-device-sessions",
				{
					method: "GET",
					requireHeaders: true,
				},
				async (ctx) => {
					const cookieHeader = ctx.headers?.get("cookie");
					if (!cookieHeader) return ctx.json([]);

					const cookies = Object.fromEntries(parseCookies(cookieHeader));
					const sessionTokens = (
						await Promise.all(
							Object.entries(cookies)
								.filter(([key]) => isMultiSessionCookie(key))
								.map(
									async ([key]) =>
										await ctx.getSignedCookie(key, ctx.context.secret),
								),
						)
					).filter((v) => typeof v === "string");

					if (!sessionTokens.length) return ctx.json([]);
					const sessions = await ctx.context.internalAdapter.findSessions(
						sessionTokens,
						{ onlyActiveSessions: true },
					);
					const validSessions = sessions.filter(
						(session) => session && session.session.expiresAt > new Date(),
					);
					const uniqueUserSessions = validSessions.reduce(
						(acc, session) => {
							if (!acc.find((s) => s.user.id === session.user.id)) {
								acc.push(session);
							}
							return acc;
						},
						[] as typeof validSessions,
					);
					return ctx.json(
						uniqueUserSessions.map((item) => ({
							session: parseSessionOutput(ctx.context.options, item.session),
							user: parseUserOutput(ctx.context.options, item.user),
						})),
					);
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/multi-session/set-active`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.setActiveSession`
			 *
			 * **client:**
			 * `authClient.multiSession.setActive`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			setActiveSession: createAuthEndpoint(
				"/multi-session/set-active",
				{
					method: "POST",
					body: setActiveSessionBodySchema,
					requireHeaders: true,
					metadata: {
						openapi: {
							description: "Set the active session",
							responses: {
								200: {
									description: "Success",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													session: {
														$ref: "#/components/schemas/Session",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					const legacySession = ctx.body.sessionToken
						? (await ctx.context.internalAdapter.findSessionById(
								ctx.body.sessionToken,
							)) ??
							(await ctx.context.internalAdapter.findSession(
								ctx.body.sessionToken,
							))
						: null;
					const sessionId =
						ctx.body.sessionId
							? ctx.body.sessionId
							: legacySession?.session.id;
					if (!sessionId) {
						throw APIError.from("UNAUTHORIZED", ERROR_CODES.INVALID_SESSION_TOKEN);
					}
					const canonicalCookieName = getMultiSessionCookieName(
						ctx.context.authCookies.sessionToken.name,
						sessionId,
					);
					const cookies = Object.fromEntries(
						parseCookies(ctx.headers?.get("cookie") || ""),
					);
					let matchedCookieName: string | undefined;
					let sessionCookie: string | undefined;
					for (const key of [
						canonicalCookieName,
						...Object.keys(cookies).filter(
							(key) =>
								isMultiSessionCookie(key) && key !== canonicalCookieName,
						),
					]) {
						const candidate = await ctx.getSignedCookie(
							key,
							ctx.context.secret,
						);
						if (!candidate) continue;
						const candidateSession =
							await ctx.context.internalAdapter.findSession(candidate);
						if (candidateSession?.session.id !== sessionId) continue;
						matchedCookieName = key;
						sessionCookie = candidate;
						break;
					}
					if (!sessionCookie || !matchedCookieName) {
						throw APIError.from(
							"UNAUTHORIZED",
							ERROR_CODES.INVALID_SESSION_TOKEN,
						);
					}
					// The signed cookie value is the authoritative token; act on it, not
					// on the request body. The signature covers the cookie value, not its
					// name, so a request must not be able to pair a validly-signed cookie
					// with a different token to activate a session it does not hold a
					// cookie for.
					const session =
						await ctx.context.internalAdapter.findSession(sessionCookie);
					if (!session || session.session.expiresAt < new Date()) {
						expireCookie(ctx, {
							name: matchedCookieName,
							attributes: ctx.context.authCookies.sessionToken.attributes,
						});
						throw APIError.from(
							"UNAUTHORIZED",
							ERROR_CODES.INVALID_SESSION_TOKEN,
						);
					}
					if (matchedCookieName !== canonicalCookieName) {
						expireCookie(ctx, {
							name: matchedCookieName,
							attributes: ctx.context.authCookies.sessionToken.attributes,
						});
						await ctx.setSignedCookie(
							canonicalCookieName,
							sessionCookie,
							ctx.context.secret,
							ctx.context.authCookies.sessionToken.attributes,
						);
					}
					await setSessionCookie(ctx, session);
					return ctx.json({
						session: parseSessionOutput(ctx.context.options, session.session),
						user: parseUserOutput(ctx.context.options, session.user),
					});
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/multi-session/revoke`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.revokeDeviceSession`
			 *
			 * **client:**
			 * `authClient.multiSession.revoke`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			revokeDeviceSession: createAuthEndpoint(
				"/multi-session/revoke",
				{
					method: "POST",
					body: revokeDeviceSessionBodySchema,
					requireHeaders: true,
					use: [sessionMiddleware],
					metadata: {
						openapi: {
							description: "Revoke a device session",
							responses: {
								200: {
									description: "Success",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													status: {
														type: "boolean",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					const legacySession = ctx.body.sessionToken
						? (await ctx.context.internalAdapter.findSessionById(
								ctx.body.sessionToken,
							)) ??
							(await ctx.context.internalAdapter.findSession(
								ctx.body.sessionToken,
							))
						: null;
					const sessionId =
						ctx.body.sessionId
							? ctx.body.sessionId
							: legacySession?.session.id;
					if (!sessionId) {
						throw APIError.from("UNAUTHORIZED", ERROR_CODES.INVALID_SESSION_TOKEN);
					}
					const canonicalCookieName = getMultiSessionCookieName(
						ctx.context.authCookies.sessionToken.name,
						sessionId,
					);
					const cookies = Object.fromEntries(
						parseCookies(ctx.headers?.get("cookie") || ""),
					);
					let matchedCookieName: string | undefined;
					let sessionCookie: string | undefined;
					for (const key of [
						canonicalCookieName,
						...Object.keys(cookies).filter(
							(key) =>
								isMultiSessionCookie(key) && key !== canonicalCookieName,
						),
					]) {
						const candidate = await ctx.getSignedCookie(
							key,
							ctx.context.secret,
						);
						if (!candidate) continue;
						const candidateSession =
							await ctx.context.internalAdapter.findSession(candidate);
						if (candidateSession?.session.id !== sessionId) continue;
						matchedCookieName = key;
						sessionCookie = candidate;
						break;
					}
					if (!sessionCookie || !matchedCookieName) {
						throw APIError.from(
							"UNAUTHORIZED",
							ERROR_CODES.INVALID_SESSION_TOKEN,
						);
					}

					// Revoke the session proven by the signed cookie value, not the
					// request-named token, so possession of one valid multi-session
					// cookie cannot revoke a different session.
					await ctx.context.internalAdapter.deleteSessionById(sessionId);
					expireCookie(ctx, {
						name: matchedCookieName,
						attributes: ctx.context.authCookies.sessionToken.attributes,
					});
					const isActive = ctx.context.session?.session.id === sessionId;
					if (!isActive) return ctx.json({ status: true });

					const cookieHeader = ctx.headers?.get("cookie");
					if (cookieHeader) {
						const cookies = Object.fromEntries(parseCookies(cookieHeader));

						const sessionTokens = (
							await Promise.all(
								Object.entries(cookies)
									.filter(([key]) => isMultiSessionCookie(key))
									.map(
										async ([key]) =>
											await ctx.getSignedCookie(key, ctx.context.secret),
									),
							)
						).filter((v) => typeof v === "string");
						const internalAdapter = ctx.context.internalAdapter;

						if (sessionTokens.length > 0) {
							const sessions =
								await internalAdapter.findSessions(sessionTokens);
							const validSessions = sessions.filter(
								(session) => session && session.session.expiresAt > new Date(),
							);

							if (validSessions.length > 0) {
								const nextSession = validSessions[0]!;
								await setSessionCookie(ctx, nextSession);
							} else {
								deleteSessionCookie(ctx);
							}
						} else {
							deleteSessionCookie(ctx);
						}
					} else {
						deleteSessionCookie(ctx);
					}
					return ctx.json({
						status: true,
					});
				},
			),
		},
		hooks: {
			after: [
				{
					matcher: () => true,
					handler: createAuthMiddleware(async (ctx) => {
						const cookieString = ctx.context.responseHeaders?.get("set-cookie");
						if (!cookieString) return;
						const newSession =
							ctx.context.newSession ??
							(ctx.path === "/token" ? ctx.context.session : null);
						if (!newSession) return;

						const sessionCookieConfig = ctx.context.authCookies.sessionToken;
						const sessionToken = newSession.session.token;
						const cookieName = getMultiSessionCookieName(
							sessionCookieConfig.name,
							newSession.session.id,
						);

						const setCookies = parseSetCookieHeader(cookieString);
						const cookies = parseCookies(ctx.headers?.get("cookie") || "");
						if (ctx.path === "/token") {
							const presentedSessionToken = await ctx.getSignedCookie(
								sessionCookieConfig.name,
								ctx.context.secret,
							);
							for (const [key] of cookies) {
								if (!isMultiSessionCookie(key) || key === cookieName) continue;
								const candidate = await ctx.getSignedCookie(
									key,
									ctx.context.secret,
								);
								if (!candidate || candidate !== presentedSessionToken) continue;
								expireCookie(ctx, {
									name: key,
									attributes: sessionCookieConfig.attributes,
								});
							}
							await ctx.setSignedCookie(
								cookieName,
								sessionToken,
								ctx.context.secret,
								sessionCookieConfig.attributes,
							);
							return;
						}
						if (setCookies.get(cookieName)) return;
						if (cookies.get(cookieName)) {
							const currentToken = await ctx.getSignedCookie(
								cookieName,
								ctx.context.secret,
							);
							if (currentToken === sessionToken) return;
							await ctx.setSignedCookie(
								cookieName,
								sessionToken,
								ctx.context.secret,
								sessionCookieConfig.attributes,
							);
							return;
						}

						const multiSessionKeys = Object.keys(
							Object.fromEntries(cookies),
						).filter(isMultiSessionCookie);

						const tokensToDelete: string[] = [];
						const trackedSessions: Array<{
							key: string;
							token: string;
							sessionId: string;
							createdAt: Date;
						}> = [];
						for (const key of multiSessionKeys) {
							const token = await ctx.getSignedCookie(key, ctx.context.secret);
							if (!token) {
								expireCookie(ctx, {
									name: key,
									attributes: sessionCookieConfig.attributes,
								});
								continue;
							}
							const session =
								await ctx.context.internalAdapter.findSession(token);
							if (!session || session.session.expiresAt <= new Date()) {
								tokensToDelete.push(token);
								expireCookie(ctx, {
									name: key,
									attributes: sessionCookieConfig.attributes,
								});
								continue;
							}
							if (session.user.id === newSession.user.id) {
								tokensToDelete.push(token);
								expireCookie(ctx, {
									name: key,
									attributes: sessionCookieConfig.attributes,
								});
								continue;
							}
							trackedSessions.push({
								key,
								token,
								sessionId: session.session.id,
								createdAt: session.session.createdAt,
							});
						}

						const overflow = trackedSessions.length + 1 - opts.maximumSessions;
						if (overflow > 0) {
							const sessionsToEvict = trackedSessions
								.sort((left, right) => {
									const createdAtDelta =
										left.createdAt.getTime() - right.createdAt.getTime();
									return (
										createdAtDelta ||
										left.sessionId.localeCompare(right.sessionId)
									);
								})
								.slice(0, overflow);
							for (const evicted of sessionsToEvict) {
								tokensToDelete.push(evicted.token);
								expireCookie(ctx, {
									name: evicted.key,
									attributes: sessionCookieConfig.attributes,
								});
							}
						}
						if (tokensToDelete.length > 0) {
							await ctx.context.internalAdapter.deleteSessions(tokensToDelete);
						}

						await ctx.setSignedCookie(
							cookieName,
							sessionToken,
							ctx.context.secret,
							sessionCookieConfig.attributes,
						);
					}),
				},
				{
					matcher: (context) => context.path === "/sign-out",
					handler: createAuthMiddleware(async (ctx) => {
						const cookieHeader = ctx.headers?.get("cookie");
						if (!cookieHeader) return;
						const cookies = Object.fromEntries(parseCookies(cookieHeader));
						const multiSessionKeys = Object.keys(cookies).filter((key) =>
							isMultiSessionCookie(key),
						);
						const verifiedTokens = (
							await Promise.all(
								multiSessionKeys.map(async (key) => {
									const verifiedToken = await ctx.getSignedCookie(
										key,
										ctx.context.secret,
									);
									if (verifiedToken) {
										expireCookie(ctx, {
											name: key
												.toLowerCase()
												.replace(
													SECURE_COOKIE_PREFIX.toLowerCase(),
													SECURE_COOKIE_PREFIX,
												),
											attributes:
												ctx.context.authCookies.sessionToken.attributes,
										});
										return verifiedToken;
									}
									return null;
								}),
							)
						).filter((v) => typeof v === "string");
						if (verifiedTokens.length > 0) {
							await ctx.context.internalAdapter.deleteSessions(verifiedTokens);
						}
					}),
				},
			],
		},
		options,
		$ERROR_CODES: ERROR_CODES,
	} satisfies ClearancePlugin;
};
