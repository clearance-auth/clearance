import { defineErrorCodes } from "@clearance/core/utils/error-codes";

export const TWO_FACTOR_ERROR_CODES = defineErrorCodes({
	OTP_NOT_ENABLED: "OTP not enabled",
	OTP_HAS_EXPIRED: "OTP has expired",
	TOTP_NOT_ENABLED: "TOTP not enabled",
	TWO_FACTOR_NOT_ENABLED: "Two factor isn't enabled",
	BACKUP_CODES_NOT_ENABLED: "Backup codes aren't enabled",
	INVALID_BACKUP_CODE: "Invalid backup code",
	INVALID_CODE: "Invalid code",
	TOTP_REPLACEMENT_REQUIRES_CURRENT_CODE:
		"Replacing an existing TOTP factor requires a current TOTP code",
	FACTOR_STEP_UP_REQUIRED:
		"A current authenticator code or recovery code is required",
	TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE:
		"Too many attempts. Please request a new code.",
	ACCOUNT_TEMPORARILY_LOCKED:
		"Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
	INVALID_TWO_FACTOR_COOKIE: "Invalid two factor cookie",
	LIFECYCLE_CONFIGURATION_ERROR:
		"Two-factor lifecycle requires rollback-capable database-backed sessions",
	LAST_FACTOR_PROTECTED:
		"A password or passkey must remain before two-factor authentication can be disabled",
	LIFECYCLE_CONFLICT: "Recovery factor state changed. Please try again",
});
