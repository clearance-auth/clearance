import type { ClearancePlugin, GenericEndpointContext } from "@clearance/core";
import {
	createAuthEndpoint,
	createAuthMiddleware,
} from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
} from "@clearance/core/context";
import * as z from "zod";
import { APIError, sessionMiddleware } from "../../api";
import {
	deleteSessionCookie,
	expireCookie,
	parseCookies,
	parseSetCookieHeader,
	setSessionCookie,
} from "../../cookies";
import { parseSessionOutput, parseUserOutput } from "../../db/schema";
import {
	SESSION_CREDENTIAL_MODEL,
	type SessionCredential,
} from "../../db/session-credential";
import { readInternalCredentialAuthority } from "../../internal/credential-authority";
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
	const maximumCookieInputs = 100;
	const maximumSessions = options?.maximumSessions ?? 5;
	if (
		!Number.isSafeInteger(maximumSessions) ||
		maximumSessions < 1 ||
		maximumSessions > 100
	) {
		throw new TypeError(
			"multiSession maximumSessions must be a safe integer between 1 and 100",
		);
	}

	const getMultiSessionCookieName = (baseName: string, sessionId: string) =>
		`${baseName}_multi-${encodeURIComponent(sessionId)}`;
	const hasMultiSessionCookiePrefix = (baseName: string, key: string) =>
		key.startsWith(`${baseName}_multi-`);
	const getClaimedSessionId = (baseName: string, key: string) => {
		if (!hasMultiSessionCookiePrefix(baseName, key)) return null;
		const suffix = key.slice(`${baseName}_multi-`.length);
		if (!suffix) return null;
		try {
			return decodeURIComponent(suffix) || null;
		} catch {
			return null;
		}
	};
	const getTrackedCookieNames = (ctx: GenericEndpointContext) => {
		const baseName = ctx.context.authCookies.sessionToken.name;
		const names = Array.from(parseCookies(ctx.headers?.get("cookie") || "").keys())
			.filter((key) => hasMultiSessionCookiePrefix(baseName, key))
			.sort((left, right) => left.localeCompare(right));
		if (names.length > maximumCookieInputs) {
			throw APIError.from("BAD_REQUEST", {
				code: "MULTI_SESSION_COOKIE_INPUT_LIMIT_EXCEEDED",
				message: `No more than ${maximumCookieInputs} multi-session cookies may be presented`,
			});
		}
		return { baseName, names };
	};

	const expireMultiSessionCookie = (
		ctx: GenericEndpointContext,
		name: string,
	) => {
		expireCookie(ctx, {
			name,
			attributes: ctx.context.authCookies.sessionToken.attributes,
		});
	};

	type TrackedSessionCookie = {
		key: string;
		token: string;
		claimedSessionId: string | null;
	};
	type TrackedSessionGroup = {
		token: string;
		candidates: TrackedSessionCookie[];
	};

	/**
	 * Verifies every exact-prefix value before interpreting its name, dedupes
	 * verified values, and defers every cookie mutation until callers commit a
	 * completed authority scan.
	 */
	const getTrackedSessionScan = async (
		ctx: GenericEndpointContext,
		preferredCookieName?: string,
	) => {
		const { baseName, names } = getTrackedCookieNames(ctx);
		if (preferredCookieName && names.includes(preferredCookieName)) {
			names.splice(names.indexOf(preferredCookieName), 1);
			names.unshift(preferredCookieName);
		}

		const groups = new Map<string, TrackedSessionGroup>();
		const namesToExpire = new Set<string>();
		for (const key of names) {
			const token = await ctx.getSignedCookie(key, ctx.context.secret);
			if (!token) {
				namesToExpire.add(key);
				continue;
			}
			const claimedSessionId = getClaimedSessionId(baseName, key);
			if (!claimedSessionId) namesToExpire.add(key);
			const group = groups.get(token) ?? { token, candidates: [] };
			group.candidates.push({ key, token, claimedSessionId });
			groups.set(token, group);
		}
		return {
			baseName,
			groups: Array.from(groups.values()),
			namesToExpire,
		};
	};

	type ValidatedTrackedSession = TrackedSessionCookie & {
		session: NonNullable<
			Awaited<ReturnType<GenericEndpointContext["context"]["internalAdapter"]["findSession"]>>
		>;
	};
	type ValidatedTrackedScan = {
		validated: ValidatedTrackedSession[];
		commitCleanup(): void;
	};
	const getValidatedTrackedSessions = async (
		ctx: GenericEndpointContext,
		preferredCookieName?: string,
	): Promise<ValidatedTrackedScan> => {
		const input = await getTrackedSessionScan(ctx, preferredCookieName);
		const validated: ValidatedTrackedSession[] = [];
		for (const group of input.groups) {
			if (
				!group.candidates.some(
					(candidate) => candidate.claimedSessionId !== null,
				)
			) {
				continue;
			}
			const session = await ctx.context.internalAdapter.findSession(group.token);
			if (!session || session.session.expiresAt <= new Date()) {
				for (const candidate of group.candidates) {
					input.namesToExpire.add(candidate.key);
				}
				continue;
			}
			const canonicalName = getMultiSessionCookieName(
				input.baseName,
				session.session.id,
			);
			const legacyName = getMultiSessionCookieName(input.baseName, group.token);
			const selected =
				group.candidates.find((candidate) => candidate.key === canonicalName) ??
				group.candidates.find((candidate) => candidate.key === legacyName);
			for (const candidate of group.candidates) {
				if (candidate !== selected) input.namesToExpire.add(candidate.key);
			}
			if (selected) validated.push({ ...selected, session });
		}
		return {
			validated,
			commitCleanup() {
				for (const name of input.namesToExpire) {
					expireMultiSessionCookie(ctx, name);
				}
			},
		};
	};

	const deleteProvenSessions = async (
		ctx: GenericEndpointContext,
		targets: readonly Pick<ValidatedTrackedSession, "token" | "session">[],
		operation: () => Promise<void>,
	) => {
		if (targets.length === 0) return;
		try {
			await operation();
		} catch (error) {
			if (!(error instanceof AfterTransactionHookError)) throw error;
			const adapter = await getCurrentAdapter(ctx.context.adapter);
			const digestAuthority =
				readInternalCredentialAuthority(ctx.context.options)?.generation !==
				"legacy-v1";
			for (const target of targets) {
				const sessionId = target.session.session.id;
				const rawSession = await adapter.findOne<{ id: string }>({
					model: "session",
					where: [{ field: "id", value: sessionId }],
				});
				if (rawSession) throw error;
				if (digestAuthority) {
					const activeCredential = await adapter.findOne<SessionCredential>({
						model: SESSION_CREDENTIAL_MODEL,
						where: [
							{ field: "sessionId", value: sessionId },
							{ field: "status", value: "active" },
						],
					});
					if (activeCredential) throw error;
				}
			}
		}
	};

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

					const scan = await getValidatedTrackedSessions(ctx);
					scan.commitCleanup();
					const validSessions = scan.validated
						.slice(0, maximumSessions)
						.map((candidate) => candidate.session);
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
					const requestedSession = ctx.body.sessionId ?? ctx.body.sessionToken;
					if (!requestedSession) {
						throw APIError.from("UNAUTHORIZED", ERROR_CODES.INVALID_SESSION_TOKEN);
					}
					const preferredCookieName = getMultiSessionCookieName(
						ctx.context.authCookies.sessionToken.name,
						requestedSession,
					);
					let matchedCookieName: string | undefined;
					let session:
						| Awaited<
								ReturnType<typeof ctx.context.internalAdapter.findSession>
							>
						| undefined;
					const scan = await getValidatedTrackedSessions(
						ctx,
						preferredCookieName,
					);
					const tracked = scan.validated;
					for (const candidate of tracked) {
						const found = candidate.session;
						if (
							found.session.id !== requestedSession &&
							(ctx.body.sessionId !== undefined ||
								candidate.token !== requestedSession)
						) {
							continue;
						}
						if (!session) {
							matchedCookieName = candidate.key;
							session = found;
						}
					}
					scan.commitCleanup();
					if (!session || !matchedCookieName) {
						throw APIError.from("UNAUTHORIZED", ERROR_CODES.INVALID_SESSION_TOKEN);
					}
					const canonicalCookieName = getMultiSessionCookieName(
						ctx.context.authCookies.sessionToken.name,
						session.session.id,
					);
					if (matchedCookieName !== canonicalCookieName) {
						expireMultiSessionCookie(ctx, matchedCookieName);
						await ctx.setSignedCookie(
							canonicalCookieName,
							session.session.token,
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
					const requestedSession = ctx.body.sessionId ?? ctx.body.sessionToken;
					if (!requestedSession) {
						throw APIError.from("UNAUTHORIZED", ERROR_CODES.INVALID_SESSION_TOKEN);
					}
					const preferredCookieName = getMultiSessionCookieName(
						ctx.context.authCookies.sessionToken.name,
						requestedSession,
					);
					let matched: ValidatedTrackedSession | undefined;
					const scan = await getValidatedTrackedSessions(
						ctx,
						preferredCookieName,
					);
					const tracked = scan.validated;
					for (const candidate of tracked) {
						const found = candidate.session;
						if (
							found.session.id !== requestedSession &&
							(ctx.body.sessionId !== undefined ||
								candidate.token !== requestedSession)
						) {
							continue;
						}
						matched ??= candidate;
					}
					if (!matched) {
						scan.commitCleanup();
						throw APIError.from("UNAUTHORIZED", ERROR_CODES.INVALID_SESSION_TOKEN);
					}

					// Revoke the session proven by the signed cookie value, not the
					// request-named token, so possession of one valid multi-session
					// cookie cannot revoke a different session.
					await deleteProvenSessions(ctx, [matched], () =>
						ctx.context.internalAdapter.deleteSessionById(
							matched.session.session.id,
						),
					);
					scan.commitCleanup();
					expireMultiSessionCookie(ctx, matched.key);
					const isActive =
						ctx.context.session?.session.id === matched.session.session.id;
					if (!isActive) return ctx.json({ status: true });

					const cookieHeader = ctx.headers?.get("cookie");
					if (cookieHeader) {
						// A fallback has the same authority requirements as an explicit
						// activation. In particular, do not use findSessions here: it is a
						// listing helper and does not prove each credential is currently
						// usable under managed authentication policy.
						const validSessions = scan.validated
							.filter((candidate) => candidate !== matched)
							.map((candidate) => candidate.session)
							.sort((left, right) => {
								const currentUserId = ctx.context.session?.user.id;
								const userPriority =
									Number(left.user.id !== currentUserId) -
									Number(right.user.id !== currentUserId);
								if (userPriority) return userPriority;
								const createdAtPriority =
									right.session.createdAt.getTime() -
									left.session.createdAt.getTime();
								return (
									createdAtPriority ||
									left.session.id.localeCompare(right.session.id)
								);
							});

						if (validSessions.length > 0) {
							await setSessionCookie(ctx, validSessions[0]!);
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
			before: [
				{
					matcher: () => true,
					handler: createAuthMiddleware(async (ctx) => {
						getTrackedCookieNames(ctx);
					}),
				},
			],
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
						if (
							ctx.path === "/multi-session/set-active" ||
							ctx.path === "/multi-session/revoke"
						) {
							return;
						}

						const sessionCookieConfig = ctx.context.authCookies.sessionToken;
						const sessionToken = newSession.session.token;
						const cookieName = getMultiSessionCookieName(
							sessionCookieConfig.name,
							newSession.session.id,
						);

						const setCookies = parseSetCookieHeader(cookieString);
						if (ctx.path === "/token") {
							const presentedSessionToken = await ctx.getSignedCookie(
								sessionCookieConfig.name,
								ctx.context.secret,
							);
							const scan = await getValidatedTrackedSessions(
								ctx,
								cookieName,
							);
							const tracked = scan.validated;
							const otherSessions = tracked.filter(
								(candidate) => candidate.session.session.id !== newSession.session.id,
							);
							const overflow = Math.max(
								0,
								otherSessions.length + 1 - maximumSessions,
							);
							const sessionsToEvict = [...otherSessions]
								.sort((left, right) => {
									const createdAtDelta =
										left.session.session.createdAt.getTime() -
										right.session.session.createdAt.getTime();
									return (
										createdAtDelta ||
										left.session.session.id.localeCompare(
											right.session.session.id,
										)
									);
								})
								.slice(0, overflow);
							await deleteProvenSessions(ctx, sessionsToEvict, () =>
								ctx.context.internalAdapter.deleteSessions(
									sessionsToEvict.map((candidate) => candidate.token),
								),
							);
							scan.commitCleanup();
							for (const candidate of sessionsToEvict) {
								expireMultiSessionCookie(ctx, candidate.key);
							}
							for (const candidate of tracked) {
								if (
									candidate.key !== cookieName &&
									candidate.token === presentedSessionToken
								) {
									expireMultiSessionCookie(ctx, candidate.key);
								}
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
						if (parseCookies(ctx.headers?.get("cookie") || "").has(cookieName)) {
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

						const scan = await getValidatedTrackedSessions(ctx);
						const tracked = scan.validated;
						const sameUserSessions = tracked.filter(
							(candidate) => candidate.session.user.id === newSession.user.id,
						);
						const otherSessions = tracked.filter(
							(candidate) => candidate.session.user.id !== newSession.user.id,
						);
						const overflow = otherSessions.length + 1 - maximumSessions;
						const sessionsToEvict: ValidatedTrackedSession[] = [];
						if (overflow > 0) {
							sessionsToEvict.push(
								...[...otherSessions]
								.sort((left, right) => {
									const createdAtDelta =
										left.session.session.createdAt.getTime() -
										right.session.session.createdAt.getTime();
									return (
										createdAtDelta ||
										left.session.session.id.localeCompare(
											right.session.session.id,
										)
									);
								})
								.slice(0, overflow),
							);
						}
						const sessionsToDelete = [...sameUserSessions, ...sessionsToEvict];
						await deleteProvenSessions(ctx, sessionsToDelete, () =>
							ctx.context.internalAdapter.deleteSessions(
								sessionsToDelete.map((candidate) => candidate.token),
							),
						);
						scan.commitCleanup();
						for (const candidate of sessionsToDelete) {
							expireMultiSessionCookie(ctx, candidate.key);
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
						const scan = await getValidatedTrackedSessions(ctx);
						await deleteProvenSessions(ctx, scan.validated, () =>
							ctx.context.internalAdapter.deleteSessions(
								scan.validated.map((candidate) => candidate.token),
							),
						);
						scan.commitCleanup();
						for (const candidate of scan.validated) {
							expireMultiSessionCookie(ctx, candidate.key);
						}
					}),
				},
			],
		},
		options,
		$ERROR_CODES: ERROR_CODES,
	} satisfies ClearancePlugin;
};
