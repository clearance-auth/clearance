import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import type { WorkerConfig } from "./config.js";
import type { SendResult } from "./smtp.js";

export type WebhookSendContext = { jobId: string; eventId: string };
export type WebhookSender = { send(payload: unknown, context: WebhookSendContext): Promise<SendResult> };
export type WebhookErrorInfo = { retryable: boolean; errorClass: string; providerStatus?: string };

type OrganizationUpdatedPayload = {
	version: 1;
	endpoint: { id: string; url: string; signingSecret: string };
	event: {
		id: string; type: "organization.updated"; occurredAt: string;
		context: { projectId: string; environmentId: string; organizationId: string; actor: string; correlationId: string };
		data: { organization: { id: string; name: string; slug: string; status: string }; previous: { name: string; slug: string } };
	};
};

const blocked = new BlockList();
const publicIpv6 = new BlockList();
publicIpv6.addSubnet("2000::", 3, "ipv6");
for (const [network, prefix] of [
	["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
	["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
	["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
	["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(network, prefix, "ipv4");
for (const [network, prefix] of [
	["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32],
] as const) blocked.addSubnet(network, prefix, "ipv6");

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
	if (!value || Array.isArray(value) || typeof value !== "object") throw webhookError("WEBHOOK_PAYLOAD_INVALID", `${label} must be an object`);
	const record = value as Record<string, unknown>;
	const actual = Object.keys(record).sort();
	const expected = [...keys].sort();
	if (JSON.stringify(actual) !== JSON.stringify(expected)) throw webhookError("WEBHOOK_PAYLOAD_INVALID", `${label} fields are invalid`);
	return record;
}

function jsonText(value: unknown, label: string, max = 512): string {
	if (typeof value !== "string" || !value || value.length > max) {
		throw webhookError("WEBHOOK_PAYLOAD_INVALID", `${label} is invalid`);
	}
	return value;
}

function singleLineText(value: unknown, label: string, max = 512): string {
	const raw = jsonText(value, label, max);
	if (/[\r\n]/.test(raw)) throw webhookError("WEBHOOK_PAYLOAD_INVALID", `${label} is invalid`);
	return raw;
}

function iso(value: unknown, label: string): string {
	const raw = singleLineText(value, label, 64);
	const date = new Date(raw);
	if (!Number.isFinite(date.getTime()) || date.toISOString() !== raw) throw webhookError("WEBHOOK_PAYLOAD_INVALID", `${label} is invalid`);
	return raw;
}

function webhookError(code: string, message: string, extra: Record<string, unknown> = {}): Error {
	return Object.assign(new Error(message), { code, ...extra });
}

export function parseOrganizationUpdatedPayload(value: unknown): OrganizationUpdatedPayload {
	const root = exactObject(value, ["version", "endpoint", "event"], "payload");
	if (root.version !== 1) throw webhookError("WEBHOOK_PAYLOAD_INVALID", "Webhook payload version is invalid");
	const endpoint = exactObject(root.endpoint, ["id", "url", "signingSecret"], "endpoint");
	const event = exactObject(root.event, ["id", "type", "occurredAt", "context", "data"], "event");
	if (event.type !== "organization.updated") throw webhookError("WEBHOOK_PAYLOAD_INVALID", "Webhook event type is invalid");
	const context = exactObject(event.context, ["projectId", "environmentId", "organizationId", "actor", "correlationId"], "context");
	const data = exactObject(event.data, ["organization", "previous"], "data");
	const organization = exactObject(data.organization, ["id", "name", "slug", "status"], "organization");
	const previous = exactObject(data.previous, ["name", "slug"], "previous");
	const signingSecret = jsonText(endpoint.signingSecret, "signingSecret", 4_096);
	if (signingSecret.length < 32) throw webhookError("WEBHOOK_PAYLOAD_INVALID", "Webhook signing secret is too short");
	return {
		version: 1,
		endpoint: { id: singleLineText(endpoint.id, "endpoint.id", 128), url: singleLineText(endpoint.url, "endpoint.url", 8_192), signingSecret },
		event: {
			id: singleLineText(event.id, "event.id", 128), type: "organization.updated", occurredAt: iso(event.occurredAt, "event.occurredAt"),
			context: {
				projectId: singleLineText(context.projectId, "context.projectId"), environmentId: singleLineText(context.environmentId, "context.environmentId"),
				organizationId: singleLineText(context.organizationId, "context.organizationId"), actor: singleLineText(context.actor, "context.actor"),
				correlationId: singleLineText(context.correlationId, "context.correlationId"),
			},
			data: {
				organization: { id: singleLineText(organization.id, "organization.id"), name: jsonText(organization.name, "organization.name", 1_024), slug: singleLineText(organization.slug, "organization.slug"), status: jsonText(organization.status, "organization.status", 64) },
				previous: { name: jsonText(previous.name, "previous.name", 1_024), slug: singleLineText(previous.slug, "previous.slug") },
			},
		},
	};
}

function canonical(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	return `{${Object.keys(value as object).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

export function canonicalWebhookBytes(
	payload: OrganizationUpdatedPayload,
	maxBytes = 1_048_576,
): Buffer {
	const bytes = Buffer.from(canonical({ version: payload.version, event: payload.event }), "utf8");
	if (bytes.length > maxBytes) throw webhookError("WEBHOOK_BODY_TOO_LARGE", "Webhook body exceeds the byte limit");
	return bytes;
}

export function webhookSignature(secret: string, eventId: string, timestamp: string, body: Buffer): string {
	return `v1,${createHmac("sha256", secret).update(eventId).update(".").update(timestamp).update(".").update(body).digest("base64")}`;
}

function normalizeAddress(address: string): { address: string; family: 4 | 6 } {
	const raw = address.startsWith("[") && address.endsWith("]") ? address.slice(1, -1) : address;
	const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(raw);
	if (dotted) return { address: dotted[1]!, family: 4 };
	const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(raw);
	if (hex) {
		const high = Number.parseInt(hex[1]!, 16), low = Number.parseInt(hex[2]!, 16);
		return { address: `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`, family: 4 };
	}
	return { address: raw, family: isIP(raw) === 6 ? 6 : 4 };
}

function isLoopback(address: string): boolean {
	const normalized = normalizeAddress(address);
	return normalized.address === "::1" || normalized.address.startsWith("127.");
}

function assertGlobal(address: string): { address: string; family: 4 | 6 } {
	const normalized = normalizeAddress(address);
	if (isIP(normalized.address) === 0 || blocked.check(normalized.address, normalized.family === 4 ? "ipv4" : "ipv6") || (normalized.family === 6 && !publicIpv6.check(normalized.address, "ipv6"))) {
		throw webhookError("WEBHOOK_DESTINATION_FORBIDDEN", "Webhook destination address is not global-unicast");
	}
	return normalized;
}

type DnsLookup = (hostname: string, options: { all: true; verbatim: true }) => Promise<Array<{ address: string; family: number }>>;

async function resolvePinned(hostname: string, allowLoopback: boolean, lookup: DnsLookup, timeoutMs: number): Promise<{ address: string; family: 4 | 6 }> {
	let answers: Array<{ address: string; family: number }>;
	const literal = normalizeAddress(hostname);
	if (isIP(literal.address)) answers = [{ address: literal.address, family: literal.family }];
	else {
		let timer: NodeJS.Timeout | undefined;
		try {
			answers = await Promise.race([
				lookup(hostname, { all: true, verbatim: true }),
				new Promise<never>((_resolve, reject) => {
					timer = setTimeout(() => reject(webhookError("WEBHOOK_DNS_TIMEOUT", "Webhook DNS resolution timed out")), timeoutMs);
				}),
			]);
		} finally {
			if (timer) clearTimeout(timer);
		}
	}
	if (!answers.length) throw webhookError("WEBHOOK_DNS_FAILED", "Webhook DNS returned no addresses");
	if (allowLoopback) {
		if (!answers.every((answer) => isLoopback(answer.address))) throw webhookError("WEBHOOK_DESTINATION_FORBIDDEN", "Development webhook destination must resolve only to loopback");
		return normalizeAddress(answers[0]!.address);
	}
	const safe = answers.map((answer) => assertGlobal(answer.address));
	return safe[0]!;
}

function validateEndpoint(raw: string, allowInsecureLoopback: boolean): { url: URL; loopback: boolean } {
	let url: URL;
	try { url = new URL(raw); } catch { throw webhookError("WEBHOOK_ENDPOINT_INVALID", "Webhook endpoint is invalid"); }
	if (url.username || url.password || url.hash) throw webhookError("WEBHOOK_ENDPOINT_INVALID", "Webhook endpoint credentials and fragments are refused");
	const loopback = url.protocol === "http:" && allowInsecureLoopback && ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname.toLowerCase());
	if (url.protocol !== "https:" && !loopback) throw webhookError("WEBHOOK_ENDPOINT_INVALID", "Webhook endpoint requires HTTPS");
	return { url, loopback };
}

export function webhookDestination(value: unknown): string {
	return parseOrganizationUpdatedPayload(value).endpoint.url;
}

export type PinnedWebhookRequest = (input: {
	url: URL; pinned: { address: string; family: 4 | 6 }; headers: Record<string, string>; body: Buffer;
	connectTimeoutMs: number; responseTimeoutMs: number; maxResponseBytes: number;
}) => Promise<number>;

export const pinnedWebhookRequest: PinnedWebhookRequest = (input) => new Promise<number>((resolve, reject) => {
	let connected = false;
	let settled = false;
	let responseTimer: NodeJS.Timeout | undefined;
	let connectTimer: NodeJS.Timeout | undefined;
	const clearTimers = () => {
		if (connectTimer) clearTimeout(connectTimer);
		if (responseTimer) clearTimeout(responseTimer);
	};
	const fail = (error: unknown) => {
		if (settled) return;
		settled = true;
		clearTimers();
		reject(error);
	};
	const succeed = (status: number) => {
		if (settled) return;
		settled = true;
		clearTimers();
		resolve(status);
	};
	const tlsHostname = normalizeAddress(input.url.hostname).address;
	const request = (input.url.protocol === "https:" ? httpsRequest : httpRequest)(input.url, {
		method: "POST", headers: input.headers, agent: false,
		...(input.url.protocol === "https:" && isIP(tlsHostname) === 0 ? { servername: tlsHostname } : {}),
		lookup: (_hostname, options, callback) => {
			if (options.all) {
				(callback as (error: NodeJS.ErrnoException | null, addresses: Array<{ address: string; family: number }>) => void)(
					null,
					[input.pinned],
				);
				return;
			}
			(callback as (error: NodeJS.ErrnoException | null, address: string, family: number) => void)(
				null,
				input.pinned.address,
				input.pinned.family,
			);
		},
	}, (response) => {
		let responseBytes = 0;
		response.on("data", (chunk: Buffer | string) => {
			responseBytes += Buffer.byteLength(chunk);
			if (responseBytes > input.maxResponseBytes) {
				fail(webhookError("WEBHOOK_RESPONSE_TOO_LARGE", "Webhook response exceeded the byte limit"));
				response.destroy();
				request.destroy();
			}
		});
		response.on("aborted", () => fail(webhookError("WEBHOOK_RESPONSE_ABORTED", "Webhook response was aborted")));
		response.on("error", fail);
		response.on("end", () => succeed(response.statusCode ?? 0));
	});
	connectTimer = setTimeout(() => request.destroy(webhookError("WEBHOOK_CONNECT_TIMEOUT", "Webhook connection timed out")), input.connectTimeoutMs);
	request.on("socket", (socket) => {
		const onConnected = () => {
			if (connected) return;
			connected = true;
			clearTimeout(connectTimer);
			responseTimer = setTimeout(() => request.destroy(webhookError("WEBHOOK_RESPONSE_TIMEOUT", "Webhook response timed out")), input.responseTimeoutMs);
		};
		socket.once(input.url.protocol === "https:" ? "secureConnect" : "connect", onConnected);
	});
	request.on("error", fail);
	request.end(input.body);
});

export function createWebhookSender(config: WorkerConfig, dependencies: {
	lookup?: DnsLookup; request?: PinnedWebhookRequest; now?: () => number;
} = {}): WebhookSender {
	return { async send(value, context) {
		const payload = parseOrganizationUpdatedPayload(value);
		if (payload.event.id !== context.eventId) throw webhookError("WEBHOOK_PAYLOAD_INVALID", "Webhook event identity differs from delivery identity");
		const { url, loopback } = validateEndpoint(payload.endpoint.url, config.webhook.allowInsecureLoopback);
		const pinned = await resolvePinned(url.hostname, loopback, dependencies.lookup ?? dnsLookup as DnsLookup, config.webhook.dnsTimeoutMs);
		const body = canonicalWebhookBytes(payload, config.maxBodyBytes);
		const timestamp = String(Math.floor((dependencies.now?.() ?? Date.now()) / 1_000));
		const headers = {
			"content-type": "application/json", "content-length": String(body.length), "user-agent": "clearance-delivery-worker/0.2",
			"webhook-id": payload.event.id, "idempotency-key": context.jobId,
			"webhook-timestamp": timestamp,
			"webhook-signature": webhookSignature(payload.endpoint.signingSecret, payload.event.id, timestamp, body),
		};
		const status = await (dependencies.request ?? pinnedWebhookRequest)({
			url, pinned, headers, body, connectTimeoutMs: config.webhook.connectTimeoutMs,
			responseTimeoutMs: config.webhook.responseTimeoutMs, maxResponseBytes: config.webhook.maxResponseBytes,
		});
		if (status >= 300 && status < 400) throw webhookError("WEBHOOK_REDIRECT_REFUSED", "Webhook redirects are refused", { status });
		if (status < 200 || status >= 300) throw webhookError("WEBHOOK_HTTP_STATUS", "Webhook endpoint returned a non-success status", { status });
		return { status: String(status), requestId: createHash("sha256").update(context.jobId).digest("hex") };
	} };
}

export function classifyWebhookError(error: unknown): WebhookErrorInfo {
	const value = error as { code?: unknown; status?: unknown };
	const status = typeof value?.status === "number" ? value.status : undefined;
	if (status !== undefined) return {
		retryable: status === 408 || status === 425 || status === 429 || status >= 500,
		errorClass: status >= 300 && status < 400
			? "webhook.redirect_refused"
			: status >= 400 && status < 500 && ![408, 425, 429].includes(status)
				? "webhook.rejected"
				: "webhook.transient",
		providerStatus: String(status),
	};
	const code = typeof value?.code === "string" ? value.code : "";
	if (["WEBHOOK_PAYLOAD_INVALID", "WEBHOOK_BODY_TOO_LARGE", "WEBHOOK_ENDPOINT_INVALID", "WEBHOOK_DESTINATION_FORBIDDEN", "WEBHOOK_REDIRECT_REFUSED"].includes(code)) return { retryable: false, errorClass: code.toLowerCase().replace(/_/g, ".") };
	return { retryable: true, errorClass: "webhook.transport" };
}

export function verifyWebhookSignature(secret: string, eventId: string, timestamp: string, body: Buffer, signature: string): boolean {
	const expected = Buffer.from(webhookSignature(secret, eventId, timestamp, body));
	const actual = Buffer.from(signature);
	return expected.length === actual.length && timingSafeEqual(expected, actual);
}
