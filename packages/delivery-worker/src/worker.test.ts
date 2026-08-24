import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseWorkerConfig } from "./config.js";
import { createJsonLogger } from "./logger.js";
import { classifySesError, createSesSender, SesDeliveryError } from "./ses.js";
import { classifySmtpError, renderEmailPayload, validateEmailPayload } from "./smtp.js";
import { probeProductPresentationAuthority, renderWorkerEmailPayload, workerHeartbeatState, type ProductPresentationLoader, type ProductPresentationSnapshot } from "./worker.js";
import {
	canonicalWebhookBytes,
	classifyWebhookError,
	parseOrganizationUpdatedWebhookPayload,
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
		expect(config.managementSchema).toBe("public");
		expect(config.managementPrefix).toBe("mgmt_");
		expect(config.allowLegacyPresentationFallback).toBe(true);
		expect(parseWorkerConfig({ ...env(), NODE_ENV: "production" }).allowLegacyPresentationFallback).toBe(false);
		expect(config.runtimeAudit).toMatchObject({ table: "clearance_runtime_audit_events" });
		expect(parseWorkerConfig({
			...env(),
			CLEARANCE_RUNTIME_AUDIT_SCHEMA: "audit_schema",
			CLEARANCE_RUNTIME_AUDIT_PREFIX: "tenant",
		}).runtimeAudit).toMatchObject({
			schema: "audit_schema",
			table: "tenant_runtime_audit_events",
		});
		expect(parseWorkerConfig({ ...env(), CLEARANCE_RUNTIME_AUDIT: "false" }).runtimeAudit).toBeUndefined();
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

	it("probes normalized presentation authority without a queued job or tenant scope", async () => {
		const queries: Array<readonly unknown[]> = [];
		await probeProductPresentationAuthority({
			async query(...args: unknown[]) {
				queries.push(args);
				return { rows: [] };
			},
		} as never, parseWorkerConfig(env()));
		expect(queries).toHaveLength(1);
		expect(queries[0]).toHaveLength(1);
		expect(String(queries[0]![0])).toContain('"public"."mgmt_product_email_senders"');
		expect(String(queries[0]![0])).toContain("LIMIT 0");
	});

	it("never persists a ready heartbeat while presentation authority is unavailable", () => {
		expect(workerHeartbeatState({
			draining: false, emailHealthy: true, schemaHealthy: true, presentation: "unavailable",
		})).toBe("failed");
		expect(workerHeartbeatState({
			draining: false, emailHealthy: true, schemaHealthy: true, presentation: "available",
		})).toBe("ready");
	});

	it("uses only the leased scope's normalized sender and versioned auth template snapshot", async () => {
		const config = parseWorkerConfig(env());
		const snapshots = new Map<string, ProductPresentationSnapshot>();
		const add = (kind: ProductPresentationSnapshot["template"]["kind"], version: number, subject: string, plainText: string, html: string) => {
			const variables = [...new Set([...subject, ...plainText, ...html].join("").match(/\{\{([a-z_]+)\}\}/g)?.map((item) => item.slice(2, -2)) ?? [])].sort();
			snapshots.set(`project-1:environment-1:${kind}`, {
				productLabel: "Scoped Product",
				sender: { displayName: "Product \"Mail\"", address: "hello@product.example.test", domain: "product.example.test", version: 7 },
				template: { kind, subject, plainText, html, variables, version, hash: "a".repeat(64) },
			});
		};
		add("verification", 11, "Verify {{product_name}} for {{user_name}} v11", "Open {{verification_url}}", "<p>{{verification_url}}</p>");
		add("password-reset", 12, "Reset {{product_name}} for {{user_name}} v12", "Open {{reset_url}}", "<p>{{reset_url}}</p>");
		add("invitation", 13, "{{inviter_name}} invited you as {{role}} v13", "Join {{organization_name}}: {{invitation_url}}", "<p>{{inviter_name}} {{organization_name}} {{invitation_url}}</p>");
		add("email-change", 14, "Confirm {{product_name}} for {{user_name}} v14", "Open {{email_change_url}}", "<p>{{email_change_url}}</p>");
		const calls: Array<{ projectId: string; environmentId: string; kind: string }> = [];
		const loader: ProductPresentationLoader = {
			async load(scope, kind) {
				calls.push({ ...scope, kind });
				return snapshots.get(`${scope.projectId}:${scope.environmentId}:${kind}`) ?? null;
			},
		};
		const cases = [
			["email-verification", { userName: "User", url: "https://app.example.test/verify?q=<inert>" }, "v11"],
			["password-reset", { userName: "User", url: "https://app.example.test/reset?q=<inert>" }, "v12"],
			["organization-invitation", { inviterName: "<Admin>", organizationName: "A & B", role: "admin", acceptanceUrl: "https://app.example.test/invite?q=<inert>" }, "v13"],
			["email-change-confirmation", { userName: "User", url: "https://app.example.test/change?q=<inert>" }, "v14"],
		] as const;
		for (const [template, fields, marker] of cases) {
			const rendered = await renderWorkerEmailPayload({ template, to: "to@example.test", ...fields }, {
				projectId: "project-1", environmentId: "environment-1",
			}, config, loader);
			expect(rendered.presentation).toBe("ready");
			expect(rendered.payload.from).toBe('"Product \\"Mail\\"" <hello@product.example.test>');
			expect(rendered.payload.subject).toContain(marker);
			if (template === "organization-invitation") expect(rendered.payload.subject).toContain("admin");
			else expect(rendered.payload.subject).toContain("User");
			if (template !== "organization-invitation") expect(rendered.payload.subject).toContain("Scoped Product");
			expect(rendered.payload.html).toContain("&lt;inert&gt;");
			expect(rendered.payload.html).not.toContain("<inert>");
		}
		const nameless = await renderWorkerEmailPayload({
			template: "password-reset", to: "to@example.test", url: "https://app.example.test/reset",
		}, { projectId: "project-1", environmentId: "environment-1" }, config, loader);
		expect(nameless.presentation).toBe("ready");
		expect(nameless.payload.subject).toBe("Reset Scoped Product for  v12");
		const foreign = await renderWorkerEmailPayload({ template: "password-reset", to: "to@example.test", userName: "User", url: "https://app.example.test/reset" }, {
			projectId: "other-project", environmentId: "environment-1",
		}, config, loader);
		expect(foreign.presentation).toBe("absent");
		expect(foreign.payload.from).toBe("support@example.test");
		expect(calls.at(-1)).toMatchObject({ projectId: "other-project", environmentId: "environment-1", kind: "password-reset" });
		for (const reason of ["presentation_sender_domain_unverified", "presentation_sender_domain_invalid"]) {
			const stale: ProductPresentationLoader = { async load() { throw new Error(reason); } };
			await expect(renderWorkerEmailPayload({ template: "password-reset", to: "to@example.test", userName: "User", url: "https://app.example.test/reset" }, {
				projectId: "project-1", environmentId: "environment-1",
			}, config, stale)).rejects.toThrow(reason);
		}
		const unavailable: ProductPresentationLoader = { async load() { throw new Error("database unavailable"); } };
		await expect(renderWorkerEmailPayload({ template: "password-reset", to: "to@example.test", userName: "User", url: "https://app.example.test/reset" }, {
			projectId: "project-1", environmentId: "environment-1",
		}, config, unavailable)).rejects.toThrow("presentation_unavailable");
		const productionConfig = parseWorkerConfig({ ...env(), NODE_ENV: "production" });
		const absent: ProductPresentationLoader = { async load() { return null; } };
		await expect(renderWorkerEmailPayload({ template: "password-reset", to: "to@example.test", userName: "User", url: "https://app.example.test/reset" }, {
			projectId: "project-1", environmentId: "environment-1",
		}, productionConfig, absent)).rejects.toThrow("presentation_required");
		const verificationWithCode: ProductPresentationLoader = {
			async load() {
				return {
					productLabel: "Scoped Product",
					sender: { displayName: "Product Mail", address: "hello@product.example.test", domain: "product.example.test", version: 7 },
					template: { kind: "verification", subject: "Code {{code}}", plainText: "Open {{verification_url}}", html: "<p>{{verification_url}}</p>", variables: ["code", "verification_url"], version: 15, hash: "b".repeat(64) },
				};
			},
		};
		await expect(renderWorkerEmailPayload({ template: "email-verification", to: "to@example.test", userName: "User", url: "https://app.example.test/verify" }, {
			projectId: "project-1", environmentId: "environment-1",
		}, config, verificationWithCode)).rejects.toThrow("presentation_template_variables_invalid");
	});

	it("classifies retryable and terminal SMTP failures without response text", () => {
		expect(classifySmtpError({ responseCode: 421 })).toEqual({ retryable: true, errorClass: "smtp.transient", providerStatus: "421" });
		expect(classifySmtpError({ responseCode: 550 })).toEqual({ retryable: false, errorClass: "smtp.rejected", providerStatus: "550" });
		expect(classifySmtpError({ code: "ETIMEDOUT", response: "secret" })).toEqual({ retryable: true, errorClass: "smtp.transport" });
		expect(classifySmtpError({ code: "ETLS" })).toEqual({ retryable: true, errorClass: "smtp.transport" });
		expect(classifySmtpError({ responseCode: 250 })).toEqual({ retryable: false, errorClass: "smtp.protocol", providerStatus: "250" });
		expect(classifySmtpError(new Error("body_too_large"))).toEqual({ retryable: false, errorClass: "payload.invalid" });
		expect(classifySmtpError(new Error("presentation_unavailable"))).toEqual({ retryable: true, errorClass: "presentation.unavailable" });
		expect(classifySesError(new Error("presentation_template_variables_invalid"))).toEqual({ retryable: false, errorClass: "payload.invalid" });
		expect(classifySesError(new Error("presentation_unavailable"))).toEqual({ retryable: true, errorClass: "presentation.unavailable" });
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
		const payload = parseOrganizationUpdatedWebhookPayload({
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
