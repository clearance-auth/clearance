import * as z from "zod";
import { coreSchema } from "./shared";

export const sessionCredentialSchema = coreSchema.extend({
	sessionId: z.string().nullish(),
	familyId: z.string(),
	secretDigest: z.string(),
	digestVersion: z.number(),
	status: z.enum(["active", "consumed", "revoked"]),
	rotationCounter: z.number(),
	parentCredentialId: z.string().nullish(),
	expiresAt: z.date(),
	consumedAt: z.date().nullish(),
	revokedAt: z.date().nullish(),
	reuseDetectedAt: z.date().nullish(),
	rotationNonceDigest: z.string().nullish(),
	recoverySecretCiphertext: z.string().nullish(),
	recoveryExpiresAt: z.date().nullish(),
});

export type BaseSessionCredential = z.infer<typeof sessionCredentialSchema>;
export type SessionCredential = BaseSessionCredential;
