import { createAuthEndpoint } from "@clearance/core/api";
import { getCurrentAdapter } from "@clearance/core/context";
import { APIError } from "@clearance/core/error";
import * as z from "zod";
import {
	getAuthoritativeSessionFromCtx,
	getSessionFromCtx,
} from "../../api/routes/session";
import { generateRandomString } from "../../crypto";
import {
	runManagedAuthenticationTransaction,
	usesManagedAuthenticationPolicy,
} from "../../internal/managed-authentication-transaction";
import { captureInternalSessionIssuanceContext } from "../../internal/session-issuance-context";
import {
	captureInternalSessionDerivativeAuthority,
	ManagedSessionDerivativeAuthorityError,
	validateInternalSessionDerivativeAuthority,
} from "../../internal/session-derivative-authority";
import { ms } from "../../utils/time";
import type { DeviceAuthorizationOptions } from ".";
import { DEVICE_AUTHORIZATION_ERROR_CODES } from "./error-codes";
import type { DeviceCode } from "./schema";

/* cspell:disable-next-line */
const defaultCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const deviceCodeBodySchema = z.object({
	client_id: z.string().meta({
		description: "The client ID of the application",
	}),
	user_id: z
		.string()
		.meta({
			description: "The user ID to which the device code should be pre-bound.",
		})
		.optional(),
	scope: z
		.string()
		.meta({
			description: "Space-separated list of scopes",
		})
		.optional(),
});

const deviceCodeErrorSchema = z.object({
	error: z.enum(["invalid_request", "invalid_client"]).meta({
		description: "Error code",
	}),
	error_description: z.string().meta({
		description: "Detailed error description",
	}),
});

export const deviceCode = (opts: DeviceAuthorizationOptions) => {
	const generateDeviceCode = async () => {
		if (opts.generateDeviceCode) {
			return opts.generateDeviceCode();
		}
		return defaultGenerateDeviceCode(opts.deviceCodeLength);
	};

	const generateUserCode = async () => {
		if (opts.generateUserCode) {
			return opts.generateUserCode();
		}
		return defaultGenerateUserCode(opts.userCodeLength);
	};
	return createAuthEndpoint(
		"/device/code",
		{
			method: "POST",
			body: deviceCodeBodySchema,
			error: deviceCodeErrorSchema,
			metadata: {
				openapi: {
					description: `Request a device and user code

Follow [rfc8628#section-3.2](https://datatracker.ietf.org/doc/html/rfc8628#section-3.2)`,
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											device_code: {
												type: "string",
												description: "The device verification code",
											},
											user_code: {
												type: "string",
												description: "The user code to display",
											},
											verification_uri: {
												type: "string",
												format: "uri",
												description:
													"The URL for user verification. Defaults to /device if not configured.",
											},
											verification_uri_complete: {
												type: "string",
												format: "uri",
												description:
													"The complete URL with user code as query parameter.",
											},
											expires_in: {
												type: "number",
												description: "Lifetime in seconds of the device code",
											},
											interval: {
												type: "number",
												description: "Minimum polling interval in seconds",
											},
										},
									},
								},
							},
						},
						400: {
							description: "Error response",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											error: {
												type: "string",
												enum: ["invalid_request", "invalid_client"],
											},
											error_description: {
												type: "string",
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
			if (opts.validateClient) {
				const isValid = await opts.validateClient(ctx.body.client_id);
				if (!isValid) {
					throw new APIError("BAD_REQUEST", {
						error: "invalid_client",
						error_description: "Invalid client ID",
					});
				}
			}

			if (opts.onDeviceAuthRequest) {
				await opts.onDeviceAuthRequest(ctx.body.client_id, ctx.body.scope);
			}

			const deviceCode = await generateDeviceCode();
			const userCode = await generateUserCode();
			const expiresIn = ms(opts.expiresIn);
			const expiresAt = new Date(Date.now() + expiresIn);

			await ctx.context.adapter.create({
				model: "deviceCode",
				data: {
					deviceCode,
					userCode,
					userId: ctx.body.user_id || null, // An empty user_id is treated as omitted, per RFC 8628 section 3.1
					expiresAt,
					status: "pending",
					pollingInterval: ms(opts.interval),
					clientId: ctx.body.client_id,
					scope: ctx.body.scope,
				},
			});

			const { verificationUri, verificationUriComplete } =
				buildVerificationUris(
					opts.verificationUri,
					ctx.context.baseURL,
					userCode,
				);

			return ctx.json(
				{
					device_code: deviceCode,
					user_code: userCode,
					verification_uri: verificationUri,
					verification_uri_complete: verificationUriComplete,
					expires_in: Math.floor(expiresIn / 1000),
					interval: Math.floor(ms(opts.interval) / 1000),
				},
				{
					headers: {
						"Cache-Control": "no-store",
					},
				},
			);
		},
	);
};

const deviceTokenBodySchema = z.object({
	grant_type: z.literal("urn:ietf:params:oauth:grant-type:device_code").meta({
		description: "The grant type for device flow",
	}),
	device_code: z.string().meta({
		description: "The device verification code",
	}),
	client_id: z.string().meta({
		description: "The client ID of the application",
	}),
});

const deviceTokenErrorSchema = z.object({
	error: z
		.enum([
			"authorization_pending",
			"slow_down",
			"expired_token",
			"access_denied",
			"invalid_request",
			"invalid_grant",
		])
		.meta({
			description: "Error code",
		}),
	error_description: z.string().meta({
		description: "Detailed error description",
	}),
});

export const deviceToken = (opts: DeviceAuthorizationOptions) =>
	createAuthEndpoint(
		"/device/token",
		{
			method: "POST",
			body: deviceTokenBodySchema,
			error: deviceTokenErrorSchema,
			metadata: {
				openapi: {
					description: `Exchange device code for access token

Follow [rfc8628#section-3.4](https://datatracker.ietf.org/doc/html/rfc8628#section-3.4)`,
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
											user: {
												$ref: "#/components/schemas/User",
											},
										},
									},
								},
							},
						},
						400: {
							description: "Error response",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											error: {
												type: "string",
												enum: [
													"authorization_pending",
													"slow_down",
													"expired_token",
													"access_denied",
													"invalid_request",
													"invalid_grant",
												],
											},
											error_description: {
												type: "string",
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
			const { device_code, client_id } = ctx.body;

			if (opts.validateClient) {
				const isValid = await opts.validateClient(client_id);
				if (!isValid) {
					throw new APIError("BAD_REQUEST", {
						error: "invalid_grant",
						error_description: "Invalid client ID",
					});
				}
			}

			const deviceCodeRecord = await ctx.context.adapter.findOne<DeviceCode>({
				model: "deviceCode",
				where: [
					{
						field: "deviceCode",
						value: device_code,
					},
				],
			});

			if (!deviceCodeRecord) {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_grant",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.INVALID_DEVICE_CODE.message,
				});
			}

			if (
				deviceCodeRecord.clientId &&
				deviceCodeRecord.clientId !== client_id
			) {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_grant",
					error_description: "Client ID mismatch",
				});
			}

			// Check for rate limiting
			if (deviceCodeRecord.lastPolledAt && deviceCodeRecord.pollingInterval) {
				const timeSinceLastPoll =
					Date.now() - new Date(deviceCodeRecord.lastPolledAt).getTime();
				const minInterval = deviceCodeRecord.pollingInterval;

				if (timeSinceLastPoll < minInterval) {
					throw new APIError("BAD_REQUEST", {
						error: "slow_down",
						error_description:
							DEVICE_AUTHORIZATION_ERROR_CODES.POLLING_TOO_FREQUENTLY.message,
					});
				}
			}

			// Claim this polling window against the exact timestamp observed above.
			// Concurrent callers may read the same row, but only one may advance it.
			const polledAt = new Date();
			const claimedPollingWindow =
				await ctx.context.adapter.incrementOne<DeviceCode>({
				model: "deviceCode",
				where: [
					{ field: "id", value: deviceCodeRecord.id },
					{
						field: "lastPolledAt",
						operator: "eq",
						value: deviceCodeRecord.lastPolledAt ?? null,
					},
				],
				increment: {},
				set: { lastPolledAt: polledAt },
			});
			if (!claimedPollingWindow) {
				throw new APIError("BAD_REQUEST", {
					error: "slow_down",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.POLLING_TOO_FREQUENTLY.message,
				});
			}

			if (deviceCodeRecord.expiresAt < new Date()) {
				await ctx.context.adapter.delete({
					model: "deviceCode",
					where: [
						{
							field: "id",
							value: deviceCodeRecord.id,
						},
					],
				});
				throw new APIError("BAD_REQUEST", {
					error: "expired_token",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.EXPIRED_DEVICE_CODE.message,
				});
			}

			if (deviceCodeRecord.status === "pending") {
				throw new APIError("BAD_REQUEST", {
					error: "authorization_pending",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.AUTHORIZATION_PENDING.message,
				});
			}

			if (deviceCodeRecord.status === "denied") {
				await ctx.context.adapter.delete({
					model: "deviceCode",
					where: [
						{
							field: "id",
							value: deviceCodeRecord.id,
						},
					],
				});
				throw new APIError("BAD_REQUEST", {
					error: "access_denied",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.ACCESS_DENIED.message,
				});
			}

			if (deviceCodeRecord.status === "approved" && deviceCodeRecord.userId) {
				const issued = await runManagedAuthenticationTransaction(ctx, async () => {
					const transaction = await getCurrentAdapter(ctx.context.adapter);
					const claimTime = new Date();
					// The claim and session issuance share the rollback boundary. Only
					// the caller that removes the approved row can issue a session.
					const claimedDeviceCode = await transaction.consumeOne<DeviceCode>({
						model: "deviceCode",
						where: [
							{ field: "deviceCode", value: device_code },
							{ field: "status", value: "approved" },
							{ field: "expiresAt", operator: "gt", value: claimTime },
						],
					});

					if (!claimedDeviceCode?.userId) {
						throw new APIError("BAD_REQUEST", {
							error: "invalid_grant",
							error_description:
								DEVICE_AUTHORIZATION_ERROR_CODES.INVALID_DEVICE_CODE.message,
						});
					}
					if (!(claimedDeviceCode.expiresAt > claimTime)) {
						throw new APIError("BAD_REQUEST", {
							error: "expired_token",
							error_description:
								DEVICE_AUTHORIZATION_ERROR_CODES.EXPIRED_DEVICE_CODE.message,
						});
					}
					if (
						claimedDeviceCode.clientId &&
						claimedDeviceCode.clientId !== client_id
					) {
						throw new APIError("BAD_REQUEST", {
							error: "invalid_grant",
							error_description: "Client ID mismatch",
						});
					}

					const managed = usesManagedAuthenticationPolicy(ctx);
					if (managed && !claimedDeviceCode.sessionDerivativeAuthority) {
						throw new ManagedSessionDerivativeAuthorityError("authority_missing");
					}
					const issuanceContext = claimedDeviceCode.sessionDerivativeAuthority
						? await captureInternalSessionIssuanceContext(
								ctx.context.internalAdapter,
								{
									purpose: "device",
									subjectId: claimedDeviceCode.userId,
									sourceSessionDerivativeAuthority:
										claimedDeviceCode.sessionDerivativeAuthority,
									targetOrganizationId:
										claimedDeviceCode.organizationId ?? null,
								},
							)
						: undefined;
					if (managed && !issuanceContext) {
						throw new ManagedSessionDerivativeAuthorityError("authority_missing");
					}

					const user = await ctx.context.internalAdapter.findUserById(
						claimedDeviceCode.userId,
					);
					if (!user) {
						throw new APIError("INTERNAL_SERVER_ERROR", {
							error: "server_error",
							error_description:
								DEVICE_AUTHORIZATION_ERROR_CODES.USER_NOT_FOUND.message,
						});
					}

					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						false,
						undefined,
						false,
						issuanceContext,
					);
					if (!session) {
						throw new APIError("INTERNAL_SERVER_ERROR", {
							error: "server_error",
							error_description:
								DEVICE_AUTHORIZATION_ERROR_CODES.FAILED_TO_CREATE_SESSION.message,
						});
					}
					return { claimedDeviceCode, session, user };
				}).catch((error) => {
					if (error instanceof ManagedSessionDerivativeAuthorityError) {
						throw new APIError("BAD_REQUEST", {
							error: "invalid_grant",
							error_description:
								DEVICE_AUTHORIZATION_ERROR_CODES.INVALID_DEVICE_CODE.message,
						});
					}
					throw error;
				});
				const { claimedDeviceCode, session, user } = issued;

				// Set new session context for hooks and plugins
				// (matches setSessionCookie logic)
				ctx.context.setNewSession({
					session,
					user,
				});

				// Return OAuth 2.0 compliant token response
				return ctx.json(
					{
						access_token: session.token,
						token_type: "Bearer",
						expires_in: Math.floor(
							(new Date(session.expiresAt).getTime() - Date.now()) / 1000,
						),
						scope: claimedDeviceCode.scope || "",
					},
					{
						headers: {
							"Cache-Control": "no-store",
							Pragma: "no-cache",
						},
					},
				);
			}

			throw new APIError("INTERNAL_SERVER_ERROR", {
				error: "server_error",
				error_description:
					DEVICE_AUTHORIZATION_ERROR_CODES.INVALID_DEVICE_CODE_STATUS.message,
			});
		},
	);

export const deviceVerify = createAuthEndpoint(
	"/device",
	{
		method: "GET",
		query: z.object({
			user_code: z.string().meta({
				description: "The user code to verify",
			}),
		}),
		error: z.object({
			error: z.enum(["invalid_request"]).meta({
				description: "Error code",
			}),
			error_description: z.string().meta({
				description: "Detailed error description",
			}),
		}),
		metadata: {
			openapi: {
				description: "Verify user code and get device authorization status",
				responses: {
					200: {
						description: "Device authorization status",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										user_code: {
											type: "string",
											description: "The user code to verify",
										},
										status: {
											type: "string",
											enum: ["pending", "approved", "denied"],
											description: "Current status of the device authorization",
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
		const { user_code } = ctx.query;
		const cleanUserCode = user_code.replace(/-/g, "");

		const deviceCodeRecord = await ctx.context.adapter.findOne<DeviceCode>({
			model: "deviceCode",
			where: [
				{
					field: "userCode",
					value: cleanUserCode,
				},
			],
		});

		if (!deviceCodeRecord) {
			throw new APIError("BAD_REQUEST", {
				error: "invalid_request",
				error_description:
					DEVICE_AUTHORIZATION_ERROR_CODES.INVALID_USER_CODE.message,
			});
		}

		if (deviceCodeRecord.expiresAt < new Date()) {
			throw new APIError("BAD_REQUEST", {
				error: "expired_token",
				error_description:
					DEVICE_AUTHORIZATION_ERROR_CODES.EXPIRED_USER_CODE.message,
			});
		}

		const session = await getSessionFromCtx(ctx);
		if (
			session?.user?.id &&
			!deviceCodeRecord.userId &&
			deviceCodeRecord.status === "pending"
		) {
			const claimedDeviceCodeRecord =
				await ctx.context.adapter.incrementOne<DeviceCode>({
					model: "deviceCode",
					where: [
						{ field: "id", value: deviceCodeRecord.id },
						{ field: "status", value: "pending" },
						{ field: "userId", operator: "eq", value: null },
					],
					increment: {},
					set: { userId: session.user.id },
				});
			if (claimedDeviceCodeRecord) {
				deviceCodeRecord.userId = session.user.id;
			}
		}

		return ctx.json({
			user_code: user_code,
			status: deviceCodeRecord.status,
		});
	},
);

export const deviceApprove = createAuthEndpoint(
	"/device/approve",
	{
		method: "POST",
		body: z.object({
			userCode: z.string().meta({
				description: "The user code to approve",
			}),
		}),
		error: z.object({
			error: z
				.enum([
					"invalid_request",
					"expired_token",
					"device_code_already_processed",
					"unauthorized",
					"access_denied",
				])
				.meta({
					description: "Error code",
				}),
			error_description: z.string().meta({
				description: "Detailed error description",
			}),
		}),
		requireHeaders: true,
		metadata: {
			openapi: {
				description: "Approve device authorization",
				responses: {
					200: {
						description: "Success",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: {
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
		return runManagedAuthenticationTransaction(ctx, async () => {
			const session = usesManagedAuthenticationPolicy(ctx)
				? await getAuthoritativeSessionFromCtx(ctx)
				: await getSessionFromCtx(ctx);
			if (!session) {
				throw new APIError("UNAUTHORIZED", {
					error: "unauthorized",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.AUTHENTICATION_REQUIRED.message,
				});
			}

			const { userCode } = ctx.body;
			const cleanUserCode = userCode.replace(/-/g, "");
			const transaction = await getCurrentAdapter(ctx.context.adapter);
			const deviceCodeRecord = await transaction.findOne<DeviceCode>({
				model: "deviceCode",
				where: [{ field: "userCode", value: cleanUserCode }],
			});

			if (!deviceCodeRecord) {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_request",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.INVALID_USER_CODE.message,
				});
			}

			if (deviceCodeRecord.expiresAt < new Date()) {
				throw new APIError("BAD_REQUEST", {
					error: "expired_token",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.EXPIRED_USER_CODE.message,
				});
			}

			if (deviceCodeRecord.status !== "pending") {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_request",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.DEVICE_CODE_ALREADY_PROCESSED
							.message,
				});
			}

			if (!deviceCodeRecord.userId) {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_request",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.DEVICE_CODE_NOT_CLAIMED.message,
				});
			}

			if (deviceCodeRecord.userId !== session.user.id) {
				throw new APIError("FORBIDDEN", {
					error: "access_denied",
					error_description:
						"You are not authorized to approve this device authorization",
				});
			}

			const sessionDerivativeAuthority =
				await captureInternalSessionDerivativeAuthority(
					ctx.context.internalAdapter,
					{
						purpose: "device",
						sourceSessionToken: session.session.token,
					},
				);
			const sourceAuthority = sessionDerivativeAuthority
				? await validateInternalSessionDerivativeAuthority(
						ctx.context.internalAdapter,
						sessionDerivativeAuthority,
						{
							purpose: "device",
							subjectId: deviceCodeRecord.userId,
						},
					)
				: undefined;
			const approvingUserId =
				sourceAuthority?.sourceSubjectId ?? session.user.id;
			const approved = await transaction.incrementOne<DeviceCode>({
				model: "deviceCode",
				where: [
					{ field: "id", value: deviceCodeRecord.id },
					{ field: "status", value: "pending" },
					{ field: "userId", value: approvingUserId },
				],
				increment: {},
				set: {
					status: "approved",
					userId: approvingUserId,
					...(sessionDerivativeAuthority && sourceAuthority
						? {
								organizationId: sourceAuthority.sourceOrganizationId,
								sessionDerivativeAuthority,
							}
						: {}),
				},
			});
			if (!approved) {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_request",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.DEVICE_CODE_ALREADY_PROCESSED
							.message,
				});
			}

			return ctx.json({ success: true });
		});
	},
);

export const deviceDeny = createAuthEndpoint(
	"/device/deny",
	{
		method: "POST",
		body: z.object({
			userCode: z.string().meta({
				description: "The user code to deny",
			}),
		}),
		error: z.object({
			error: z
				.enum([
					"invalid_request",
					"expired_token",
					"unauthorized",
					"access_denied",
				])
				.meta({
					description: "Error code",
				}),
			error_description: z.string().meta({
				description: "Detailed error description",
			}),
		}),
		requireHeaders: true,
		metadata: {
			openapi: {
				description: "Deny device authorization",
				responses: {
					200: {
						description: "Success",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: {
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
		return runManagedAuthenticationTransaction(ctx, async () => {
			const session = usesManagedAuthenticationPolicy(ctx)
				? await getAuthoritativeSessionFromCtx(ctx)
				: await getSessionFromCtx(ctx);
			if (!session) {
				throw new APIError("UNAUTHORIZED", {
					error: "unauthorized",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.AUTHENTICATION_REQUIRED.message,
				});
			}

			const cleanUserCode = ctx.body.userCode.replace(/-/g, "");
			const transaction = await getCurrentAdapter(ctx.context.adapter);
			const deviceCodeRecord = await transaction.findOne<DeviceCode>({
				model: "deviceCode",
				where: [{ field: "userCode", value: cleanUserCode }],
			});
			if (!deviceCodeRecord) {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_request",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.INVALID_USER_CODE.message,
				});
			}
			if (deviceCodeRecord.expiresAt < new Date()) {
				throw new APIError("BAD_REQUEST", {
					error: "expired_token",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.EXPIRED_USER_CODE.message,
				});
			}
			if (deviceCodeRecord.status !== "pending") {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_request",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.DEVICE_CODE_ALREADY_PROCESSED
							.message,
				});
			}
			if (!deviceCodeRecord.userId) {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_request",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.DEVICE_CODE_NOT_CLAIMED.message,
				});
			}
			if (deviceCodeRecord.userId !== session.user.id) {
				throw new APIError("FORBIDDEN", {
					error: "access_denied",
					error_description:
						"You are not authorized to deny this device authorization",
				});
			}

			const denied = await transaction.incrementOne<DeviceCode>({
				model: "deviceCode",
				where: [
					{ field: "id", value: deviceCodeRecord.id },
					{ field: "status", value: "pending" },
					{ field: "userId", value: session.user.id },
				],
				increment: {},
				set: { status: "denied", userId: session.user.id },
			});
			if (!denied) {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_request",
					error_description:
						DEVICE_AUTHORIZATION_ERROR_CODES.DEVICE_CODE_ALREADY_PROCESSED
							.message,
				});
			}

			return ctx.json({ success: true });
		});
	},
);

/**
 * @internal
 */
const buildVerificationUris = (
	verificationUri: string | undefined,
	baseURL: string,
	userCode: string,
): {
	verificationUri: string;
	verificationUriComplete: string;
} => {
	const uri = verificationUri || "/device";

	let verificationUrl: URL;
	try {
		verificationUrl = new URL(uri);
	} catch {
		verificationUrl = new URL(uri, baseURL);
	}

	const verificationUriCompleteUrl = new URL(verificationUrl);
	verificationUriCompleteUrl.searchParams.set("user_code", userCode);

	const verificationUriString = verificationUrl.toString();
	const verificationUriCompleteString = verificationUriCompleteUrl.toString();

	return {
		verificationUri: verificationUriString,
		verificationUriComplete: verificationUriCompleteString,
	};
};

/**
 * @internal
 */
const defaultGenerateDeviceCode = (length: number) => {
	return generateRandomString(length, "a-z", "A-Z", "0-9");
};

/**
 * @internal
 */
const defaultGenerateUserCode = (length: number) => {
	const chars = new Uint8Array(length);
	return Array.from(crypto.getRandomValues(chars))
		.map((byte) => defaultCharset[byte % defaultCharset.length])
		.join("");
};
