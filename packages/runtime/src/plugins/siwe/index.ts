import type { ClearancePlugin } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import * as z from "zod";
import { APIError } from "../../api";
import { setSessionCookie } from "../../cookies";
import { mergeSchema } from "../../db/schema";
import { readInternalAuthenticationPolicy } from "../../internal/authentication-policy";
import { createInternalSessionIssuanceContext } from "../../internal/session-issuance-context";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "../../internal/verification-challenge-context";
import type { InferOptionSchema, User } from "../../types";
import { toChecksumAddress } from "../../utils/hashing";
import { isAPIError } from "../../utils/is-api-error";
import { getOrigin } from "../../utils/url";
import { PACKAGE_VERSION } from "../../version";
import { normalizeSiweDomain, parseSiweMessage } from "./parse-message";
import type { WalletAddressSchema } from "./schema";
import { schema } from "./schema";
import type {
	ENSLookupArgs,
	ENSLookupResult,
	SIWEVerifyMessageArgs,
	WalletAddress,
} from "./types";

declare module "@clearance/core" {
	interface ClearancePluginRegistry<AuthOptions, Options> {
		siwe: {
			creator: typeof siwe;
		};
	}
}

export interface SIWEPluginOptions {
	domain: string;
	emailDomainName?: string | undefined;
	anonymous?: boolean | undefined;
	getNonce: () => Promise<string>;
	verifyMessage: (args: SIWEVerifyMessageArgs) => Promise<boolean>;
	ensLookup?: ((args: ENSLookupArgs) => Promise<ENSLookupResult>) | undefined;
	schema?: InferOptionSchema<typeof schema> | undefined;
}

const walletAddressInputSchema = z
	.string()
	.regex(/^0[xX][a-fA-F0-9]{40}$/i)
	.length(42);

const getSiweNonceBodySchema = z
	.object({
		walletAddress: walletAddressInputSchema.optional(),
		address: walletAddressInputSchema.optional(),
		chainId: z.number().int().positive().optional().default(1),
	})
	.refine((body) => body.walletAddress || body.address, {
		message: "walletAddress or address is required",
		path: ["walletAddress"],
	});

export const siwe = (options: SIWEPluginOptions) => {
	const challengePurpose = "siwe:sign-in";
	const createSiweNonceEndpoint = (path: "/siwe/nonce" | "/siwe/get-nonce") =>
		createAuthEndpoint(
			path,
			{
				method: "POST",
				body: getSiweNonceBodySchema,
			},
			async (ctx) => {
				const rawWalletAddress = ctx.body.walletAddress ?? ctx.body.address;
				if (!rawWalletAddress) {
					throw APIError.fromStatus("BAD_REQUEST", {
						message: "walletAddress or address is required",
						status: 400,
					});
				}
				const { chainId } = ctx.body;
				const walletAddress = toChecksumAddress(rawWalletAddress);
				const nonce = await options.getNonce();
				const identifier = `siwe:${walletAddress}:${chainId}`;

				// Store nonce with wallet address and chain ID context
				await createInternalVerificationChallenge(
					ctx.context.internalAdapter,
					{ purpose: challengePurpose, subject: identifier },
					{
						identifier,
						value: nonce,
						expiresAt: new Date(Date.now() + 15 * 60 * 1000),
					},
				);

				return ctx.json({ nonce });
			},
		);

	return {
		id: "siwe",
		version: PACKAGE_VERSION,
		schema: mergeSchema(schema, options?.schema) as WalletAddressSchema,
		endpoints: {
			getSiweNonce: createSiweNonceEndpoint("/siwe/nonce"),
			getNonce: createSiweNonceEndpoint("/siwe/get-nonce"),
			verifySiweMessage: createAuthEndpoint(
				"/siwe/verify",
				{
					method: "POST",
					body: z
						.object({
							message: z.string().min(1),
							signature: z.string().min(1),
							walletAddress: z
								.string()
								.regex(/^0[xX][a-fA-F0-9]{40}$/i)
								.length(42),
							chainId: z.number().int().positive().optional().default(1),
							email: z.email().optional(),
						})
						.refine((data) => options.anonymous !== false || !!data.email, {
							message:
								"Email is required when the anonymous plugin option is disabled.",
							path: ["email"],
						}),
					requireRequest: true,
				},
				async (ctx) => {
					const {
						message,
						signature,
						walletAddress: rawWalletAddress,
						chainId,
						email,
					} = ctx.body;
					const walletAddress = toChecksumAddress(rawWalletAddress);
					const isAnon = options.anonymous ?? true;
					const managedPolicy = readInternalAuthenticationPolicy(
						ctx.context.options,
					);
					if (
						managedPolicy &&
						typeof ctx.context.adapter.options?.adapterConfig.transaction !==
							"function"
					) {
						throw APIError.fromStatus("INTERNAL_SERVER_ERROR", {
							message:
								"Managed SIWE authentication requires rollback-capable database transactions",
							status: 500,
						});
					}

					if (!isAnon && !email) {
						throw APIError.fromStatus("BAD_REQUEST", {
							message: "Email is required when anonymous is disabled.",
							status: 400,
						});
					}

					try {
						const nonceIdentifier = `siwe:${walletAddress}:${chainId}`;
						// Unmanaged SIWE retains its historical burn-before-verification
						// behavior. Managed issuance first reads the server nonce without
						// consuming it, then compare-and-consumes that exact row inside the
						// identity/session transaction below. A policy or persistence failure
						// therefore rolls the proof back with every derived mutation.
						const verification = managedPolicy
							? await ctx.context.internalAdapter.findVerificationValue(
									nonceIdentifier,
								)
							: await consumeInternalVerificationChallenge(
									ctx.context.internalAdapter,
									{
										purpose: challengePurpose,
										subject: nonceIdentifier,
										identifier: nonceIdentifier,
									},
								);

						if (!verification) {
							throw APIError.fromStatus("UNAUTHORIZED", {
								message: "Unauthorized: Invalid or expired nonce",
								status: 401,
								code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
							});
						}

						// Verify SIWE message with enhanced parameters
						const { value: nonce } = verification;

						// Bind the *signed* message to server state before accepting the
						// signature. Signature recovery alone (the documented `verifyMessage`
						// using viem) does NOT inspect the message body, so a previously
						// produced signature (stale, for another domain, or over an
						// arbitrary string) could otherwise be presented alongside a freshly
						// minted nonce. Parse the ERC-4361 message ourselves and require the
						// nonce, address, chain id, and domain to match the server-issued
						// values, plus honor the signed time bounds.
						const parsedMessage = parseSiweMessage(message);
						const nonceMatches = parsedMessage.nonce === nonce;
						const addressMatches =
							!!parsedMessage.address &&
							parsedMessage.address.toLowerCase() ===
								walletAddress.toLowerCase();
						const chainMatches = parsedMessage.chainId === chainId;
						const domainMatches =
							!!parsedMessage.domain &&
							normalizeSiweDomain(parsedMessage.domain) ===
								normalizeSiweDomain(options.domain);

						if (
							!nonceMatches ||
							!addressMatches ||
							!chainMatches ||
							!domainMatches
						) {
							throw APIError.fromStatus("UNAUTHORIZED", {
								message:
									"Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID",
								status: 401,
								code: "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
							});
						}

						const now = Date.now();
						if (parsedMessage.expirationTime) {
							const expiresAt = Date.parse(parsedMessage.expirationTime);
							if (!Number.isNaN(expiresAt) && now >= expiresAt) {
								throw APIError.fromStatus("UNAUTHORIZED", {
									message: "Unauthorized: SIWE message has expired",
									status: 401,
									code: "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
								});
							}
						}
						if (parsedMessage.notBefore) {
							const notBefore = Date.parse(parsedMessage.notBefore);
							if (!Number.isNaN(notBefore) && now < notBefore) {
								throw APIError.fromStatus("UNAUTHORIZED", {
									message: "Unauthorized: SIWE message is not yet valid",
									status: 401,
									code: "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
								});
							}
						}

						const verified = await options.verifyMessage({
							message,
							signature,
							address: walletAddress,
							chainId,
							cacao: {
								h: { t: "caip122" },
								p: {
									domain: options.domain,
									aud: options.domain,
									nonce,
									iss: options.domain,
									version: "1",
								},
								s: { t: "eip191", s: signature },
							},
						});

						if (!verified) {
							throw APIError.fromStatus("UNAUTHORIZED", {
								message: "Unauthorized: Invalid SIWE signature",
								status: 401,
							});
						}

						let preparedEnsIdentity: ENSLookupResult | undefined;
						if (managedPolicy && options.ensLookup) {
							const existingAddress = await ctx.context.adapter.findOne({
								model: "walletAddress",
								where: [
									{ field: "address", operator: "eq", value: walletAddress },
								],
							});
							if (!existingAddress) {
								preparedEnsIdentity = await options.ensLookup({ walletAddress });
							}
						}

						const persistIdentityAndSession = async () => {
							if (managedPolicy) {
								const consumed = await consumeInternalVerificationChallenge(
									ctx.context.internalAdapter,
									{
										purpose: challengePurpose,
										subject: nonceIdentifier,
										identifier: nonceIdentifier,
									},
								);
								if (
									!consumed ||
									consumed.id !== verification.id ||
									consumed.value !== verification.value
								) {
									throw APIError.fromStatus("UNAUTHORIZED", {
										message: "Unauthorized: Invalid or expired nonce",
										status: 401,
										code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
									});
								}
							}
							const transaction = await getCurrentAdapter(ctx.context.adapter);
							let user: User | null = null;
							const existingWalletAddress: WalletAddress | null =
								await transaction.findOne({
									model: "walletAddress",
									where: [
										{ field: "address", operator: "eq", value: walletAddress },
										{ field: "chainId", operator: "eq", value: chainId },
									],
								});
							const anyWalletAddress: WalletAddress | null =
								existingWalletAddress ??
								(await transaction.findOne({
									model: "walletAddress",
									where: [
										{ field: "address", operator: "eq", value: walletAddress },
									],
								}));
							if (anyWalletAddress) {
								user = await transaction.findOne({
									model: "user",
									where: [
										{
											field: "id",
											operator: "eq",
											value: anyWalletAddress.userId,
										},
									],
								});
							}

							if (!user) {
								const domain =
									options.emailDomainName ?? getOrigin(ctx.context.baseURL);
								const normalizedEmail = email?.toLowerCase();
								let userEmail = `${walletAddress}@${domain}`;
								if (!isAnon && normalizedEmail) {
									const existingUser =
										await ctx.context.internalAdapter.findUserByEmail(
											normalizedEmail,
										);
									if (!existingUser) userEmail = normalizedEmail;
								}
								const { name, avatar } = managedPolicy
									? (preparedEnsIdentity ?? {})
									: ((await options.ensLookup?.({ walletAddress })) ?? {});
								user = await ctx.context.internalAdapter.createUser({
									name: name ?? walletAddress,
									email: userEmail,
									image: avatar ?? "",
								});
								await transaction.create({
									model: "walletAddress",
									data: {
										userId: user.id,
										address: walletAddress,
										chainId,
										isPrimary: true,
										createdAt: new Date(),
									},
								});
								await ctx.context.internalAdapter.createAccount({
									userId: user.id,
									providerId: "siwe",
									accountId: `${walletAddress}:${chainId}`,
									createdAt: new Date(),
									updatedAt: new Date(),
								});
							} else if (!existingWalletAddress) {
								await transaction.create({
									model: "walletAddress",
									data: {
										userId: user.id,
										address: walletAddress,
										chainId,
										isPrimary: false,
										createdAt: new Date(),
									},
								});
								await ctx.context.internalAdapter.createAccount({
									userId: user.id,
									providerId: "siwe",
									accountId: `${walletAddress}:${chainId}`,
									createdAt: new Date(),
									updatedAt: new Date(),
								});
							}

							const session = await ctx.context.internalAdapter.createSession(
								user.id,
								undefined,
								undefined,
								false,
								createInternalSessionIssuanceContext({
									purpose: "interactive",
									subjectId: user.id,
									evidence: [
										{ kind: "primary", primaryMethod: "wallet_signature" },
									],
								}),
							);
							return { session, user };
						};
						const { session, user } = managedPolicy
							? await runWithTransaction(
									ctx.context.adapter,
									persistIdentityAndSession,
								)
							: await persistIdentityAndSession();

						if (!session) {
							throw APIError.fromStatus("INTERNAL_SERVER_ERROR", {
								message: "Internal Server Error",
								status: 500,
							});
						}

						await setSessionCookie(ctx, { session, user });

						return ctx.json({
							token: session.token,
							success: true,
							user: {
								id: user.id,
								walletAddress,
								chainId,
							},
						});
					} catch (error: unknown) {
						if (isAPIError(error)) throw error;
						throw APIError.fromStatus("UNAUTHORIZED", {
							message: "Something went wrong. Please try again later.",
							error: error instanceof Error ? error.message : "Unknown error",
							status: 401,
						});
					}
				},
			),
		},
		options,
	} satisfies ClearancePlugin;
};
