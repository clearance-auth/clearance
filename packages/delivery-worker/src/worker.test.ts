import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseWorkerConfig } from "./config.js";
import { createJsonLogger } from "./logger.js";
import { classifySmtpError, renderEmailPayload, validateEmailPayload } from "./smtp.js";
import {
	canonicalWebhookBytes,
	classifyWebhookError,
	parseOrganizationUpdatedPayload,
	verifyWebhookSignature,
	webhookSignature,
} from "./webhook.js";

const key = () => randomBytes(32).toString("base64");
function env(): NodeJS.ProcessEnv {
	return {
		DATABASE_URL: "postgres://example.test/db",
		CLEARANCE_SMTP_HOST: "smtp.example.test",
		CLEARANCE_EMAIL_FROM: "support@example.test",
		CLEARANCE_DELIVERY_KEY_ID: "current",
		CLEARANCE_DELIVERY_KEYS_JSON: JSON.stringify({ current: key() }),
		CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID: "fingerprint-current",
		CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON: JSON.stringify({ "fingerprint-current": key() }),
		CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY: key(),
	};
}

describe("delivery worker boundaries", () => {
	it("strictly parses bounded environment configuration", () => {
		const config = parseWorkerConfig({ ...env(), CLEARANCE_DELIVERY_CONCURRENCY: "64", CLEARANCE_SMTP_REQUIRE_TLS: "true" });
		expect(config.concurrency).toBe(64);
		expect(config.smtp.requireTls).toBe(true);
		expect(config.allowHttpLinks).toBe(false);
		expect(parseWorkerConfig({
			...env(), CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID: "fingerprint.previous-1",
		}).legacyFingerprintKeyId).toBe("fingerprint.previous-1");
		expect(() => parseWorkerConfig({
			...env(), CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID: "invalid/key",
		})).toThrow(/valid delivery fingerprint key id/);
		expect(() => parseWorkerConfig({ ...env(), CLEARANCE_DELIVERY_CONCURRENCY: "65" })).toThrow(/between 1 and 64/);
		expect(() => parseWorkerConfig({ ...env(), CLEARANCE_SMTP_PASSWORD: "secret" })).toThrow(/provided together/);
		expect(() => parseWorkerConfig({ ...env(), CLEARANCE_SMTP_REQUIRE_TLS: "maybe" })).toThrow(/true or false/);
		expect(() => parseWorkerConfig({ ...env(), CLEARANCE_EMAIL_FROM: "Display <support@example.test>" })).toThrow(/single email address/);
		expect(() => parseWorkerConfig({ ...env(), CLEARANCE_DELIVERY_ALLOW_HTTP_LINKS: "yes" })).toThrow(/true or false/);
		expect(() => parseWorkerConfig({
			...env(), CLEARANCE_SMTP_HOST: "127.0.0.1", CLEARANCE_SMTP_REQUIRE_TLS: "false",
		})).toThrow(/Plaintext SMTP requires/);
		const localPlaintext = parseWorkerConfig({
			...env(), CLEARANCE_SMTP_HOST: "127.0.0.1", CLEARANCE_SMTP_REQUIRE_TLS: "false",
			CLEARANCE_SMTP_ALLOW_INSECURE_LOOPBACK: "true",
		});
		expect(localPlaintext.smtp.allowInsecureLoopback).toBe(true);
		expect(() => parseWorkerConfig({
			...env(), CLEARANCE_SMTP_REQUIRE_TLS: "false", CLEARANCE_SMTP_ALLOW_INSECURE_LOOPBACK: "true",
		})).toThrow(/loopback host/);
		expect(() => parseWorkerConfig({
			...env(), CLEARANCE_SMTP_HOST: "localhost", CLEARANCE_SMTP_REQUIRE_TLS: "false",
			CLEARANCE_SMTP_ALLOW_INSECURE_LOOPBACK: "true", CLEARANCE_SMTP_USER: "user",
			CLEARANCE_SMTP_PASSWORD: "password",
		})).toThrow(/authentication requires/);
	});

	it("validates headers and bounded message bodies", () => {
		expect(validateEmailPayload({ to: "to@example.test", from: "from@example.test", subject: "hello", text: "world" }, 1024).text).toBe("world");
		expect(() => validateEmailPayload({ to: "to@example.test\r\nBcc: x", from: "from@example.test", subject: "x", text: "x" }, 1024)).toThrow(/invalid_to/);
		expect(() => validateEmailPayload({ to: "to@example.test", from: "from@example.test", subject: "x", text: "x".repeat(1025) }, 1024)).toThrow(/body_too_large/);
	});

	it("renders canonical scalar templates with configured sender and escaped HTML", () => {
		const config = parseWorkerConfig(env());
		const verification = renderEmailPayload({
			template: "email-verification", to: "to@example.test", userName: "A <Admin>",
			url: "https://app.example.test/verify?token=secret",
		}, config);
		expect(verification.from).toBe("support@example.test");
		expect(verification.html).toContain("A &lt;Admin&gt;");
		expect(() => renderEmailPayload({
			template: "email-verification", to: "to@example.test",
			url: "https://app.example.test/verify?token=secret", token: "unexpected",
		}, config)).toThrow(/invalid_template_fields/);
		const invitation = renderEmailPayload({
			template: "organization-invitation", to: "to@example.test", role: "admin",
			organizationName: "A & B", inviterName: "I <Owner>",
			acceptanceUrl: "https://app.example.test/invite?id=invite-1",
		}, config);
		expect(invitation.html).toContain("A &amp; B");
		expect(invitation.html).toContain("I &lt;Owner&gt;");
		expect(() => renderEmailPayload({
			template: "organization-invitation", to: "to@example.test", role: "admin",
			organizationName: "Org", inviterName: "Owner", acceptanceUrl: "http://localhost/invite",
		}, config)).toThrow(/invalid_acceptance_url/);
		const localConfig = parseWorkerConfig({ ...env(), CLEARANCE_DELIVERY_ALLOW_HTTP_LINKS: "true" });
		expect(renderEmailPayload({
			template: "organization-invitation", to: "to@example.test", role: "admin",
			organizationName: "Org", inviterName: "Owner", acceptanceUrl: "http://localhost/invite",
		}, localConfig).text).toContain("http://localhost/invite");
		expect(() => renderEmailPayload({
			template: "organization-invitation", to: "to@example.test", role: "admin",
			organizationName: "Org", inviterName: "Owner", acceptanceUrl: "https://example.test/invite",
			token: "unexpected",
		}, config)).toThrow(/invalid_template_fields/);
		const concrete = renderEmailPayload({ to: "to@example.test", from: "ignored@example.test", subject: "Operator notice", text: "body" }, config);
		expect(concrete.from).toBe("support@example.test");
	});

	it("classifies retryable and terminal SMTP failures without response text", () => {
		expect(classifySmtpError({ responseCode: 421 })).toEqual({ retryable: true, errorClass: "smtp.transient", providerStatus: "421" });
		expect(classifySmtpError({ responseCode: 550 })).toEqual({ retryable: false, errorClass: "smtp.rejected", providerStatus: "550" });
		expect(classifySmtpError({ code: "ETIMEDOUT", response: "secret" })).toEqual({ retryable: true, errorClass: "smtp.transport" });
		expect(classifySmtpError({ code: "ETLS" })).toEqual({ retryable: true, errorClass: "smtp.transport" });
		expect(classifySmtpError({ responseCode: 250 })).toEqual({ retryable: false, errorClass: "smtp.protocol", providerStatus: "250" });
		expect(classifySmtpError(new Error("body_too_large"))).toEqual({ retryable: false, errorClass: "payload.invalid" });
	});

	it("canonicalizes and verifies exact webhook bytes with terminal redirect handling", () => {
		const signingSecret = "webhook-signing-secret-at-least-32-bytes";
		const payload = parseOrganizationUpdatedPayload({
			version: 1,
			endpoint: {
				id: "primary",
				url: "https://hooks.example.test/clearance",
				signingSecret,
			},
			event: {
				id: "event-1",
				type: "organization.updated",
				occurredAt: "2026-07-15T00:00:00.000Z",
				context: {
					projectId: "project-1",
					environmentId: "environment-1",
					organizationId: "organization-1",
					actor: "operator-1",
					correlationId: "correlation-1",
				},
				data: {
					organization: {
						id: "organization-1",
						name: "Updated Org",
						slug: "updated-org",
						status: "active",
					},
					previous: { name: "Old Org", slug: "old-org" },
				},
			},
		});
		const body = canonicalWebhookBytes(payload, 16_384);
		expect(body.toString("utf8")).not.toContain(signingSecret);
		expect(body.toString("utf8")).not.toContain("endpoint");
		const timestamp = "1784073600";
		const signature = webhookSignature(signingSecret, payload.event.id, timestamp, body);
		expect(verifyWebhookSignature(signingSecret, payload.event.id, timestamp, body, signature)).toBe(true);
		expect(verifyWebhookSignature(signingSecret, payload.event.id, timestamp, Buffer.from("changed"), signature)).toBe(false);
		expect(classifyWebhookError({ code: "WEBHOOK_REDIRECT_REFUSED", status: 302 })).toEqual({
			retryable: false,
			errorClass: "webhook.redirect_refused",
			providerStatus: "302",
		});
		expect(classifyWebhookError({ code: "WEBHOOK_HTTP_STATUS", status: 503 })).toEqual({
			retryable: true,
			errorClass: "webhook.transient",
			providerStatus: "503",
		});
	});

	it("redacts message and credential fields from structured logs", () => {
		const lines: string[] = [];
		createJsonLogger((line) => lines.push(line)).log("error", "example", {
			password: "smtp-password", payload: { to: "person@example.test", text: "reset-token" }, jobId: "job-1",
		});
		expect(lines[0]).toContain('"jobId":"job-1"');
		expect(lines[0]).not.toContain("smtp-password");
		expect(lines[0]).not.toContain("person@example.test");
		expect(lines[0]).not.toContain("reset-token");
	});
});
