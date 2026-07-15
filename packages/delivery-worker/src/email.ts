import type { EmailTransport, WorkerConfig } from "./config.js";
import { classifySesError, createSesSender } from "./ses.js";
import { classifySmtpError, createSmtpSender, type EmailSender } from "./smtp.js";

export function configuredEmailTransport(config: WorkerConfig): EmailTransport {
	return config.emailTransport ?? "smtp";
}

export function createEmailSender(config: WorkerConfig): EmailSender {
	return configuredEmailTransport(config) === "ses"
		? createSesSender(config)
		: createSmtpSender(config);
}

export function classifyEmailError(
	config: WorkerConfig,
	error: unknown,
): { retryable: boolean; errorClass: string; providerStatus?: string } {
	return configuredEmailTransport(config) === "ses"
		? classifySesError(error)
		: classifySmtpError(error);
}
