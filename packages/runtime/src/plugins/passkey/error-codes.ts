import { defineErrorCodes } from "@clearance/core/utils/error-codes";

export const PASSKEY_ERROR_CODES = defineErrorCodes({
	INVALID_ORIGIN: "Invalid origin",
	CHALLENGE_NOT_FOUND: "Challenge not found or expired",
	REGISTRATION_FAILED: "Failed to register passkey",
	AUTHENTICATION_FAILED: "Failed to authenticate with passkey",
	PASSKEY_NOT_FOUND: "Passkey not found",
	INVALID_NAME: "Invalid passkey name",
	CONFIGURATION_ERROR: "Passkey plugin is not configured correctly",
});
