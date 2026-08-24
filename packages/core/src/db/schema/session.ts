import * as z from "zod";
import type { ClearanceOptions, Prettify } from "../../types";
import type { RuntimeAuthenticationSessionField } from "../../types/authentication-policy";
import type {
	InferDBFieldsFromOptions,
	InferDBFieldsFromPlugins,
} from "../type";
import { coreSchema } from "./shared";

export const sessionSchema = coreSchema.extend({
	userId: z.coerce.string(),
	expiresAt: z.date(),
	token: z.string(),
	ipAddress: z.string().nullish(),
	userAgent: z.string().nullish(),
	authenticationAssuranceVersion: z.number().int().nullish(),
	authenticationPolicyProjectId: z.string().nullish(),
	authenticationPolicyEnvironmentId: z.string().nullish(),
	authenticationPrimaryMethod: z
		.enum([
			"password",
			"password_enrollment",
			"federated",
			"email_link",
			"email_otp",
			"phone_otp",
			"wallet_signature",
			"passkey",
			"anonymous",
			"admin_impersonation",
		])
		.nullish(),
	authenticationPrimaryAt: z.date().nullish(),
	authenticationFactorMethod: z
		.enum(["passkey", "totp", "otp", "recovery_code"])
		.nullish(),
	authenticationFactorAt: z.date().nullish(),
	authenticationPolicyOrganizationId: z.string().nullish(),
	authenticationPolicyRevision: z.string().nullish(),
	authenticationAssuranceExpiresAt: z.date().nullish(),
	authenticationRecoveryRestricted: z.boolean().nullish(),
});

/** Public session shape. Runtime authentication authority fields stay internal. */
export type BaseSession = Omit<
	z.infer<typeof sessionSchema>,
	RuntimeAuthenticationSessionField
>;

/**
 * Session schema type used by clearance, note that it's possible that session could have additional fields
 */
export type Session<
	DBOptions extends ClearanceOptions["session"] = ClearanceOptions["session"],
	Plugins extends ClearanceOptions["plugins"] = ClearanceOptions["plugins"],
> = Prettify<
	BaseSession &
		Omit<
			InferDBFieldsFromOptions<DBOptions>,
			RuntimeAuthenticationSessionField
		> &
		Omit<
			InferDBFieldsFromPlugins<"session", Plugins>,
			RuntimeAuthenticationSessionField
		>
>;
