import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseWorkerConfig } from "./config.js";
import { createJsonLogger } from "./logger.js";
import { classifySesError, createSesSender, SesDeliveryError } from "./ses.js";
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

function sesEnv(): NodeJS.ProcessEnv {
	return {
		...env(),
		CLEARANCE_EMAIL_TRANSPORT: "ses",
		CLEARANCE_SMTP_HOST: undefined,
		CLEARANCE_SES_REGION: "us-east-1",
		CLEARANCE_SES_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
		CLEARANCE_SES_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		CLEARANCE_SES_SESSION_TOKEN: "bounded-session-token-value",
	};
}

describe("delivery worker boundaries", () => {
	it("strictly parses bounded environment configuration", () => {
		const config = parseWorkerConfig({ ...env(), CLEARANCE_DELIVERY_CONCURRENCY: "64", CLEARANCE_SMTP_REQUIRE_TLS: "true" });
		expect(config.concurrency).toBe(64);
		expect(config.smtp!.requireTls).toBe(true);
		expect(config.emailTransport).toBe("smtp");
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
		expect(localPlaintext.smtp!.allowInsecureLoopback).toBe(true);
		expect(() => parseWorkerConfig({
			...env(), CLEARANCE_SMTP_REQUIRE_TLS: "false", CLEARANCE_SMTP_ALLOW_INSECURE_LOOPBACK: "true",
		})).toThrow(/loopback host/);
		expect(() => parseWorkerConfig({
			...env(), CLEARANCE_SMTP_HOST: "localhost", CLEARANCE_SMTP_REQUIRE_TLS: "false",
			CLEARANCE_SMTP_ALLOW_INSECURE_LOOPBACK: "true", CLEARANCE_SMTP_USER: "user",
			CLEARANCE_SMTP_PASSWORD: "password",
		})).toThrow(/authentication requires/);
	});

	it("selects SES explicitly and validates its bounded regional credentials", () => {
		const config = parseWorkerConfig(sesEnv());
		expect(config.emailTransport).toBe("ses");
		expect(config.smtp).toBeUndefined();
		expect(config.ses).toMatchObject({ region: "us-east-1", requestTimeoutMs: 10_000 });
		expect(config.emailFrom).toBe("support@example.test");
		expect(() => parseWorkerConfig({ ...sesEnv(), CLEARANCE_EMAIL_TRANSPORT: "queue" })).toThrow(/smtp, ses/);
		expect(() => parseWorkerConfig({ ...sesEnv(), CLEARANCE_SES_REGION: "metadata.internal" })).toThrow(/valid AWS region/);
		expect(() => parseWorkerConfig({ ...sesEnv(), CLEARANCE_SES_SECRET_ACCESS_KEY: "short" })).toThrow(/bounded AWS credential/);
		expect(() => parseWorkerConfig({
			...sesEnv(), CLEARANCE_SES_ACCESS_KEY_ID: undefined, CLEARANCE_SES_SECRET_ACCESS_KEY: undefined,
		})).toThrow(/SES requires/);
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

	it("sends through SES with SigV4, bounded provider identity, and a stable delivery header", async () => {
		const requests: Array<{ url: string; init: RequestInit }> = [];
		const responses = [
			new Response(JSON.stringify({ SendingEnabled: true }), { status: 200 }),
			new Response(JSON.stringify({ MessageId: "provider-message-id-sensitive" }), { status: 200 }),
		];
		const sender = createSesSender(parseWorkerConfig(sesEnv()), {
			now: () => new Date("2026-07-15T00:00:00.000Z"),
			fetchImpl: async (input, init) => {
				requests.push({ url: String(input), init: init! });
				return responses.shift()!;
			},
		});
		await sender.verify();
		const result = await sender.send({
			to: "person@example.test", from: "support@example.test", subject: "Reset",
			text: "one-time-secret", html: "<p>one-time-secret</p>",
		}, { jobId: "job-stable-1", eventId: "event-1" });
		expect(requests.map((request) => [request.init.method, request.url])).toEqual([
			["GET", "https://email.us-east-1.amazonaws.com/v2/email/account"],
			["POST", "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails"],
		]);
		const authorization = new Headers(requests[1]!.init.headers).get("authorization")!;
		expect(authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/20260715\/us-east-1\/ses\/aws4_request,/);
		expect(authorization).not.toContain("wJalrXUtnFEMI");
		const body = JSON.parse(String(requests[1]!.init.body)) as {
			Destination: { ToAddresses: string[] };
			Content: { Simple: { Headers: Array<{ Name: string; Value: string }> } };
		};
		expect(body.Destination.ToAddresses).toEqual(["person@example.test"]);
		expect(body.Content.Simple.Headers).toEqual([{
			Name: "X-Clearance-Delivery-ID",
			Value: "13d9a542dbe78652d1cf6b2f092afaa06f2be13a8100d44d8140d96cd6043c46",
		}]);
		expect(result).toEqual({
			status: "200",
			requestId: "86008d69e474d48759c352d754586344192b26b4cb99c682f7ea36e8430b3978",
		});
	});

	it("checks SES readiness without sending and fails when account sending is disabled", async () => {
		const methods: string[] = [];
		const sender = createSesSender(parseWorkerConfig(sesEnv()), {
			fetchImpl: async (_input, init) => {
				methods.push(init!.method!);
				return new Response(JSON.stringify({ SendingEnabled: false }), { status: 200 });
			},
		});
		await expect(sender.verify()).rejects.toMatchObject({ code: "SES_SENDING_DISABLED", retryable: false });
		expect(methods).toEqual(["GET"]);
	});

	it("classifies SES transient and permanent failures without retaining raw responses", async () => {
		for (const scenario of [
			{ status: 429, body: { name: "TooManyRequestsException", message: "recipient-and-token-secret" }, retryable: true, errorClass: "ses.transient" },
			{ status: 400, body: { name: "MessageRejected", message: "recipient-and-token-secret" }, retryable: false, errorClass: "ses.rejected" },
		] as const) {
			const sender = createSesSender(parseWorkerConfig(sesEnv()), {
				fetchImpl: async () => new Response(JSON.stringify(scenario.body), { status: scenario.status }),
			});
			let thrown: unknown;
			try {
				await sender.send({
					to: "person@example.test", from: "support@example.test", subject: "Reset", text: "token-secret",
				}, { jobId: "job-1", eventId: "event-1" });
			} catch (error) { thrown = error; }
			expect(thrown).toBeInstanceOf(SesDeliveryError);
			expect(JSON.stringify(thrown)).not.toContain("recipient-and-token-secret");
			expect(String((thrown as Error).message)).not.toContain("recipient-and-token-secret");
			expect(classifySesError(thrown)).toEqual({
				retryable: scenario.retryable,
				errorClass: scenario.errorClass,
				providerStatus: String(scenario.status),
			});
		}
		expect(classifySesError(new Error("network response with secret"))).toEqual({
			retryable: true,
			errorClass: "ses.transport",
		});
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
