import { createHash } from "node:crypto";
import nodemailer, { type Transporter } from "nodemailer";
import type { WorkerConfig } from "./config.js";

export type EmailPayload = { to: string; from: string; subject: string; text?: string; html?: string; replyTo?: string };
export type SendResult = { requestId?: string; status: string };
export type EmailSendContext = { jobId: string; eventId: string };
export type EmailSender = { verify(): Promise<void>; send(payload: unknown, context: EmailSendContext): Promise<SendResult>; close(): void };

function header(value: unknown, name: string, max: number): string {
	if (typeof value !== "string" || !value.trim() || value.length > max || /[\r\n]/.test(value)) throw new Error(`invalid_${name}`);
	return value;
}

function mailbox(value: unknown, name: string): string {
	const normalized = header(value, name, 320).trim();
	if (!/^[^\s@<>,;]+@[^\s@<>,;]+$/.test(normalized)) throw new Error(`invalid_${name}`);
	return normalized;
}

export function validateEmailPayload(value: unknown, maxBodyBytes: number): EmailPayload {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_payload");
	const raw = value as Record<string, unknown>;
	const payload: EmailPayload = {
		to: mailbox(raw.to, "to"), from: mailbox(raw.from, "from"), subject: header(raw.subject, "subject", 998),
		...(raw.replyTo === undefined ? {} : { replyTo: mailbox(raw.replyTo, "reply_to") }),
		...(typeof raw.text === "string" ? { text: raw.text } : {}),
		...(typeof raw.html === "string" ? { html: raw.html } : {}),
	};
	if (payload.text === undefined && payload.html === undefined) throw new Error("body_required");
	if (Buffer.byteLength(payload.text ?? "") + Buffer.byteLength(payload.html ?? "") > maxBodyBytes) throw new Error("body_too_large");
	return payload;
}

function boundedText(value: unknown, name: string, max: number, optional = false): string {
	if (optional && (value === undefined || value === null || value === "")) return "";
	if (typeof value !== "string" || !value.trim() || value.length > max) {
		throw new Error(`invalid_${name}`);
	}
	return value.trim();
}

function link(value: unknown, name: string, allowHttp: boolean): string {
	const raw = boundedText(value, name, 8_192);
	let parsed: URL;
	try { parsed = new URL(raw); } catch { throw new Error(`invalid_${name}`); }
	if (parsed.protocol !== "https:" && !(allowHttp && parsed.protocol === "http:")) throw new Error(`invalid_${name}`);
	return parsed.toString();
}

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, (character) => ({
		"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
	})[character]!);
}

function exactKeys(raw: Record<string, unknown>, allowed: readonly string[]): void {
	const allowedSet = new Set(allowed);
	if (Object.keys(raw).some((key) => !allowedSet.has(key))) throw new Error("invalid_template_fields");
}

/** Render the small, versioned set of first-party transactional templates. */
export function renderEmailPayload(value: unknown, config: WorkerConfig): EmailPayload {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_payload");
	const raw = value as Record<string, unknown>;
	if (raw.template === undefined) {
		// Concrete payloads support explicit operator-authored delivery while
		// all first-party auth workflows use the canonical templates below.
		const rendered = validateEmailPayload(value, config.maxBodyBytes);
		const from = config.emailFrom ?? config.smtp?.from;
		if (!from) throw new Error("invalid_from");
		return { ...rendered, from };
	}
	const template = boundedText(raw.template, "template", 64);
	const to = mailbox(raw.to, "to");
	const appName = config.appName;
	let subject: string;
	let text: string;
	let html: string;
	if (["email-verification", "email-change-confirmation", "email-change-verification", "password-reset"].includes(template)) {
		exactKeys(raw, ["template", "to", "userName", "url"]);
		const userName = boundedText(raw.userName, "user_name", 200, true);
		const url = link(raw.url, "url", config.allowHttpLinks);
		const greeting = userName ? `Hi ${userName},\n\n` : "";
		const action = template === "email-verification"
			? "verify your email address"
			: template === "email-change-confirmation"
				? "confirm your email address change"
				: template === "email-change-verification"
					? "verify your new email address"
					: "reset your password";
		subject = template === "email-verification"
			? `Verify your ${appName} email`
			: template === "email-change-confirmation"
				? `Confirm your ${appName} email change`
				: template === "email-change-verification"
					? `Verify your new ${appName} email`
					: `Reset your ${appName} password`;
		text = `${greeting}Use this link to ${action}:\n\n${url}\n\nIf you did not request this, you can ignore this email.`;
		html = `<p>${userName ? `Hi ${escapeHtml(userName)},` : "Hello,"}</p><p>Use this link to ${escapeHtml(action)}:</p><p><a href="${escapeHtml(url)}">${escapeHtml(action)}</a></p><p>If you did not request this, you can ignore this email.</p>`;
	} else if (template === "organization-invitation") {
		exactKeys(raw, ["template", "to", "role", "organizationName", "inviterName", "acceptanceUrl"]);
		const organizationName = boundedText(raw.organizationName, "organization_name", 200);
		const inviterName = boundedText(raw.inviterName, "inviter_name", 200);
		const role = boundedText(raw.role, "role", 200);
		const acceptanceUrl = link(raw.acceptanceUrl, "acceptance_url", config.allowHttpLinks);
		subject = `${inviterName} invited you to ${organizationName}`;
		text = `${inviterName} invited you to join ${organizationName} as ${role}.\n\nAccept the invitation:\n${acceptanceUrl}`;
		html = `<p>${escapeHtml(inviterName)} invited you to join <strong>${escapeHtml(organizationName)}</strong> as ${escapeHtml(role)}.</p><p><a href="${escapeHtml(acceptanceUrl)}">Accept invitation</a></p>`;
	} else {
		throw new Error("invalid_template");
	}
	const from = config.emailFrom ?? config.smtp?.from;
	if (!from) throw new Error("invalid_from");
	return validateEmailPayload({ to, from, subject, text, html }, config.maxBodyBytes);
}

export function createSmtpSender(config: WorkerConfig): EmailSender {
	const smtp = config.smtp;
	if (!smtp || (config.emailTransport ?? "smtp") !== "smtp") {
		throw new Error("SMTP sender requires validated SMTP worker configuration");
	}
	const transport: Transporter = nodemailer.createTransport({
		host: smtp.host, port: smtp.port, secure: smtp.secure,
		requireTLS: smtp.requireTls, opportunisticTLS: false,
		connectionTimeout: smtp.connectionTimeoutMs,
		greetingTimeout: smtp.greetingTimeoutMs,
		socketTimeout: smtp.socketTimeoutMs,
		disableFileAccess: true, disableUrlAccess: true,
		...(smtp.user ? { auth: { user: smtp.user, pass: smtp.password } } : {}),
	});
	return {
		async verify() { await transport.verify(); },
		async send(value, context) {
			const payload = renderEmailPayload(value, config);
			const stableMessageId = createHash("sha256").update(context.jobId).digest("hex");
			const result = await transport.sendMail({
				...payload,
				messageId: `<${stableMessageId}@delivery.clearance.invalid>`,
			});
			const accepted = Array.isArray(result.accepted) ? result.accepted : [];
			const rejected = Array.isArray(result.rejected) ? result.rejected : [];
			if (accepted.length !== 1 || rejected.length !== 0) {
				throw Object.assign(new Error("SMTP did not accept exactly one recipient"), {
					code: "EENVELOPE",
				});
			}
			const status = typeof result.response === "string" && /^\d{3}/.test(result.response)
				? result.response.slice(0, 3)
				: "accepted";
			return {
				requestId: typeof result.messageId === "string"
					? createHash("sha256").update(result.messageId).digest("hex")
					: undefined,
				status,
			};
		},
		close() { transport.close(); },
	};
}

export function classifySmtpError(error: unknown): { retryable: boolean; errorClass: string; providerStatus?: string } {
	const value = error as { code?: unknown; responseCode?: unknown; command?: unknown };
	if (error instanceof Error && /^(?:invalid_|body_)/.test(error.message)) {
		return { retryable: false, errorClass: "payload.invalid" };
	}
	const deliveryCode = typeof value?.code === "string" ? value.code : "";
	if (["DELIVERY_DESTINATION_MISMATCH", "DELIVERY_PAYLOAD_AUTH_FAILED", "DELIVERY_PAYLOAD_TOO_LARGE"].includes(deliveryCode)) {
		return { retryable: false, errorClass: `delivery.${deliveryCode.toLowerCase().replace(/^delivery_/, "")}` };
	}
	const responseCode = typeof value?.responseCode === "number" ? value.responseCode : undefined;
	if (responseCode) {
		return {
			retryable: responseCode >= 400 && responseCode < 500,
			errorClass: responseCode >= 400 && responseCode < 500
				? "smtp.transient"
				: responseCode >= 500 ? "smtp.rejected" : "smtp.protocol",
			providerStatus: String(responseCode),
		};
	}
	const code = typeof value?.code === "string" ? value.code : "";
	if (["ETIMEDOUT", "ECONNRESET", "ECONNREFUSED", "ECONNECTION", "ESOCKET", "ETLS", "EPIPE", "EHOSTUNREACH", "ENETUNREACH", "EDNS"].includes(code)) return { retryable: true, errorClass: "smtp.transport" };
	if (["EAUTH", "EENVELOPE", "EMESSAGE"].includes(code)) return { retryable: false, errorClass: `smtp.${code.toLowerCase()}` };
	return { retryable: true, errorClass: "smtp.provider_error" };
}
