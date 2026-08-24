import type {
	ClearancePlugin,
	GenericEndpointContext,
} from "@clearance/core";
import {
	createAuthEndpoint,
	createAuthMiddleware,
} from "@clearance/core/api";
import { runWithTransaction } from "@clearance/core/context";
import * as z from "zod";
import { sessionMiddleware } from "../../api";
import { setSessionCookie, splitSetCookieHeader } from "../../cookies";
import { generateRandomString } from "../../crypto";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "../../internal/verification-challenge-context";
import type { Session, User } from "../../types";
import { PACKAGE_VERSION } from "../../version";
import { defaultKeyHasher } from "./utils";

declare module "@clearance/core" {
	interface ClearancePluginRegistry<AuthOptions, Options> {
		"one-time-token": {
			creator: typeof oneTimeToken;
		};
	}
}

export interface OneTimeTokenOptions {
	/**
	 * Expires in minutes
	 *
	 * @default 3
	 */
	expiresIn?: number | undefined;
	/**
	 * Only allow server initiated requests
	 */
	disableClientRequest?: boolean | undefined;
	/**
	 * Generate a custom token
	 */
	generateToken?:
		| ((
				session: {
					user: User & Record<string, any>;
					session: Session & Record<string, any>;
				},
				ctx: GenericEndpointContext,
		  ) => Promise<string>)
		| undefined;
	/**
	 * Disable setting the session cookie when the token is verified
	 */
	disableSetSessionCookie?: boolean;
	/**
	 * This option allows you to configure how the token is stored in your database.
	 * Note: This will not affect the token that's sent, it will only affect the token stored in your database.
	 *
	 * @default "plain"
	 */
	storeToken?:
		| (
				| "plain"
				| "hashed"
				| { type: "custom-hasher"; hash: (token: string) => Promise<string> }
		  )
		| undefined;
	/**
	 * Set the OTT header on new sessions
	 */
	setOttHeaderOnNewSession?: boolean;
}

const verifyOneTimeTokenBodySchema = z.object({
	token: z.string().meta({
		description: 'The token to verify. Eg: "some-token"',
	}),
});

type CookieHeaderScope = GenericEndpointContext & {
	responseHeaders?: Headers;
};

function responseCookieHeaders(ctx: GenericEndpointContext) {
	const scoped = ctx as CookieHeaderScope;
	const headers = new Set<Headers>();
	if (scoped.responseHeaders) headers.add(scoped.responseHeaders);
	if (scoped.context.responseHeaders) headers.add(scoped.context.responseHeaders);
	return headers;
}

function snapshotResponseCookies(ctx: GenericEndpointContext) {
	return new Map(
		[...responseCookieHeaders(ctx)].map((headers) => [
			headers,
			typeof headers.getSetCookie === "function"
				? headers.getSetCookie()
				: splitSetCookieHeader(headers.get("set-cookie") || ""),
		]),
	);
}

function restoreResponseCookies(
	ctx: GenericEndpointContext,
	snapshot: Map<Headers, string[]>,
) {
	const headers = new Set([...snapshot.keys(), ...responseCookieHeaders(ctx)]);
	for (const responseHeaders of headers) {
		responseHeaders.delete("set-cookie");
		for (const cookie of snapshot.get(responseHeaders) || []) {
			responseHeaders.append("set-cookie", cookie);
		}
	}
}

export const oneTimeToken = (options?: OneTimeTokenOptions | undefined) => {
	const opts = {
		storeToken: "plain",
		...options,
	} satisfies OneTimeTokenOptions;

	async function storeToken(ctx: GenericEndpointContext, token: string) {
		if (opts.storeToken === "hashed") {
			return await defaultKeyHasher(token);
		}
		if (
			typeof opts.storeToken === "object" &&
			"type" in opts.storeToken &&
			opts.storeToken.type === "custom-hasher"
		) {
			return await opts.storeToken.hash(token);
		}

		return token;
	}

	async function generateToken(
		c: GenericEndpointContext,
		session: {
			session: Session;
			user: User;
		},
	) {
		const token = opts?.generateToken
			? await opts.generateToken(session, c)
			: generateRandomString(32);
		const expiresAt = new Date(Date.now() + (opts?.expiresIn ?? 3) * 60 * 1000);
		const storedToken = await storeToken(c, token);
		const identifier = `one-time-token:${storedToken}`;
		await createInternalVerificationChallenge(
			c.context.internalAdapter,
			{ purpose: "one-time-token", subject: identifier },
			{
				value: session.session.token,
				identifier,
			expiresAt,
			},
		);
		return token;
	}

	return {
		id: "one-time-token",
		version: PACKAGE_VERSION,
		endpoints: {
			/**
			 * ### Endpoint
			 *
			 * GET `/one-time-token/generate`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.generateOneTimeToken`
			 *
			 * **client:**
			 * `authClient.oneTimeToken.generate`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			generateOneTimeToken: createAuthEndpoint(
				"/one-time-token/generate",
				{
					method: "GET",
					use: [sessionMiddleware],
				},
				async (c) => {
					//if request exist, it means it's a client request
					if (opts?.disableClientRequest && c.request) {
						throw c.error("BAD_REQUEST", {
							message: "Client requests are disabled",
						});
					}
					const session = c.context.session;
					const token = await generateToken(c, session);
					return c.json({ token });
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/one-time-token/verify`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.verifyOneTimeToken`
			 *
			 * **client:**
			 * `authClient.oneTimeToken.verify`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			verifyOneTimeToken: createAuthEndpoint(
				"/one-time-token/verify",
				{
					method: "POST",
					body: verifyOneTimeTokenBodySchema,
				},
				async (c) => {
					const { token } = c.body;
					const storedToken = await storeToken(c, token);
					const identifier = `one-time-token:${storedToken}`;
					// Commit the challenge consumption independently from source-session
					// authority. Throwing within this transaction would roll the challenge
					// back when the source is no longer usable, making the token reusable.
					const redemption = await runWithTransaction(
						c.context.adapter,
						async () => {
							const verificationValue =
								await consumeInternalVerificationChallenge(
									c.context.internalAdapter,
									{
										purpose: "one-time-token",
										subject: identifier,
										identifier,
									},
								);
							if (!verificationValue) {
								return { kind: "invalid-token" } as const;
							}
							let found: Awaited<
								ReturnType<typeof c.context.internalAdapter.findSession>
							>;
							try {
								found = await c.context.internalAdapter.findSession(
									verificationValue.value,
								);
							} catch (error) {
								return { kind: "authority-error", error } as const;
							}
							if (!found) {
								return { kind: "session-not-found" } as const;
							}
							if (found.session.expiresAt < new Date()) {
								return { kind: "session-expired" } as const;
							}
							return { kind: "success", session: found } as const;
						},
					);
					if (redemption.kind === "authority-error") {
						throw redemption.error;
					}
					if (redemption.kind === "invalid-token") {
						throw c.error("BAD_REQUEST", { message: "Invalid token" });
					}
					if (redemption.kind === "session-not-found") {
						throw c.error("BAD_REQUEST", { message: "Session not found" });
					}
					if (redemption.kind === "session-expired") {
						throw c.error("BAD_REQUEST", { message: "Session expired" });
					}
					const session = redemption.session;
					if (!opts?.disableSetSessionCookie) {
						// setSessionCookie publishes the credential before potentially fallible
						// cache versioning and account-cookie work. Restore the prior cookies if
						// that publication fails so an error response cannot carry credentials.
						const cookieSnapshot = snapshotResponseCookies(c);
						try {
							await setSessionCookie(c, session);
						} catch (error) {
							restoreResponseCookies(c, cookieSnapshot);
							throw error;
						}
					}

					return c.json(session);
				},
			),
		},
		hooks: {
			after: [
				{
					matcher: () => true,
					handler: createAuthMiddleware(async (ctx) => {
						if (ctx.context.newSession) {
							if (!opts?.setOttHeaderOnNewSession) {
								return;
							}
							const exposedHeaders =
								ctx.context.responseHeaders?.get(
									"access-control-expose-headers",
								) || "";
							const headersSet = new Set(
								exposedHeaders
									.split(",")
									.map((header) => header.trim())
									.filter(Boolean),
							);
							headersSet.add("set-ott");
							const token = await generateToken(ctx, ctx.context.newSession);
							ctx.setHeader("set-ott", token);
							ctx.setHeader(
								"Access-Control-Expose-Headers",
								Array.from(headersSet).join(", "),
							);
						}
					}),
				},
			],
		},
		options,
	} satisfies ClearancePlugin;
};
