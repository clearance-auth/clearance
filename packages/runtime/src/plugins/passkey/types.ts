import type {
	AuthenticationResponseJSON,
	AuthenticatorSelectionCriteria,
	AuthenticatorTransportFuture,
	CredentialDeviceType,
} from "@simplewebauthn/server";
import type { InferOptionSchema } from "../../types";
import type { schema } from "./schema";

export interface PasskeyOptions {
	/**
	 * The WebAuthn Relying Party ID. Must be an exact registrable domain (no
	 * scheme, no port, no path). When omitted, the RP ID is derived from a
	 * statically configured string `baseURL` only; a dynamic (per-request)
	 * `baseURL` configuration cannot be used to derive it.
	 */
	rpID?: string | undefined;
	/**
	 * Human-readable relying party name shown by platform authenticator UI.
	 * @default the configured `appName`
	 */
	rpName?: string | undefined;
	/**
	 * Additional explicit origins allowed to complete WebAuthn ceremonies,
	 * beyond the exact literal (non-wildcard) entries already present in
	 * `ClearanceOptions.trustedOrigins`. Every entry must be an exact
	 * `scheme://host[:port]` origin compatible with the resolved `rpID`
	 * (the origin's host must equal the RP ID or be a subdomain of it).
	 * `http://` origins are only accepted for loopback/localhost hosts.
	 */
	origin?: string[] | undefined;
	/**
	 * Restrict authenticator attachment during registration. Discoverable
	 * credentials and user verification remain mandatory and cannot be
	 * weakened through configuration.
	 */
	authenticatorSelection?:
		| Pick<AuthenticatorSelectionCriteria, "authenticatorAttachment">
		| undefined;
	/**
	 * Rate limit applied to all `/passkey/*` endpoints.
	 * @default { window: 60, max: 10 }
	 */
	rateLimit?:
		| {
				window?: number | undefined;
				max?: number | undefined;
		  }
		| undefined;
	/**
	 * Custom schema for the passkey plugin.
	 */
	schema?: InferOptionSchema<typeof schema> | undefined;
}

export interface Passkey {
	id: string;
	userId: string;
	name?: string | null | undefined;
	credentialID: string;
	publicKey: string;
	userHandle: string;
	counter: number;
	deviceType: CredentialDeviceType;
	backedUp: boolean;
	transports?: string | null | undefined;
	aaguid?: string | null | undefined;
	createdAt: Date;
	updatedAt: Date;
}

/**
 * The redacted shape returned by list/rename endpoints. Never includes
 * `credentialID`, `publicKey`, `userHandle`, `counter`, or `userId`.
 */
export interface PublicPasskey {
	id: string;
	name?: string | null | undefined;
	deviceType: CredentialDeviceType;
	backedUp: boolean;
	transports?: AuthenticatorTransportFuture[] | undefined;
	createdAt: Date;
	updatedAt: Date;
}

export type PasskeyDeletionProof =
	| { type: "password"; password: string }
	| { type: "totp"; code: string }
	| { type: "recovery-code"; code: string }
	| { type: "passkey"; response: AuthenticationResponseJSON };
