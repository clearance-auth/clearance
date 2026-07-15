import { createHash, createHmac } from "node:crypto";
import type { WorkerConfig } from "./config.js";
import { renderEmailPayload, type EmailPayload, type EmailSender, type SendResult } from "./smtp.js";

const SERVICE = "ses";
const RESPONSE_LIMIT_BYTES = 64 * 1024;

type SesConfig = NonNullable<WorkerConfig["ses"]>;
type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export class SesDeliveryError extends Error {
	constructor(
		readonly code: string,
		readonly retryable: boolean,
		readonly statusCode?: number,
	) {
		super("AWS SES request failed");
		this.name = "SesDeliveryError";
	}
}

type SesDependencies = {
	fetchImpl?: FetchLike;
	now?: () => Date;
};

function sha256(value: string | Buffer): string {
	return createHash("sha256").update(value).digest("hex");
}

function hmac(key: Buffer | string, value: string): Buffer {
	return createHmac("sha256", key).update(value, "utf8").digest();
}

function amzTimestamp(now: Date): { date: string; timestamp: string } {
	if (!Number.isFinite(now.getTime())) throw new SesDeliveryError("SES_CLOCK_INVALID", false);
	const timestamp = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
	return { date: timestamp.slice(0, 8), timestamp };
}

function endpointHost(region: string): string {
	return `email.${region}.${region.startsWith("cn-") ? "amazonaws.com.cn" : "amazonaws.com"}`;
}

function signedHeaders(
	config: SesConfig,
	method: "GET" | "POST",
	path: string,
	body: string,
	now: Date,
): Headers {
	const host = endpointHost(config.region);
	const payloadHash = sha256(body);
	const { date, timestamp } = amzTimestamp(now);
	const canonical: Record<string, string> = {
		"content-type": "application/json",
		host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date": timestamp,
		...(config.sessionToken ? { "x-amz-security-token": config.sessionToken } : {}),
	};
	const names = Object.keys(canonical).sort();
	const canonicalHeaders = names.map((name) => `${name}:${canonical[name]!.trim()}\n`).join("");
	const signedHeaderNames = names.join(";");
	const canonicalRequest = [method, path, "", canonicalHeaders, signedHeaderNames, payloadHash].join("\n");
	const scope = `${date}/${config.region}/${SERVICE}/aws4_request`;
	const stringToSign = ["AWS4-HMAC-SHA256", timestamp, scope, sha256(canonicalRequest)].join("\n");
	const dateKey = hmac(`AWS4${config.secretAccessKey}`, date);
	const regionKey = hmac(dateKey, config.region);
	const serviceKey = hmac(regionKey, SERVICE);
	const signingKey = hmac(serviceKey, "aws4_request");
	const signature = createHmac("sha256", signingKey).update(stringToSign, "utf8").digest("hex");
	return new Headers({
		...canonical,
		authorization: `AWS4-HMAC-SHA256 Credential=${config.accessKeyId}/${scope}, SignedHeaders=${signedHeaderNames}, Signature=${signature}`,
	});
}

async function boundedJson(response: Response): Promise<Record<string, unknown>> {
	if (!response.body) return {};
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.byteLength;
		if (size > RESPONSE_LIMIT_BYTES) {
			await reader.cancel().catch(() => undefined);
			throw new SesDeliveryError("SES_RESPONSE_TOO_LARGE", true, response.status);
		}
		chunks.push(value);
	}
	if (size === 0) return {};
	const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
	try {
		const parsed = JSON.parse(body) as unknown;
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? parsed as Record<string, unknown>
			: {};
	} catch {
		throw new SesDeliveryError("SES_RESPONSE_INVALID", response.status >= 500, response.status);
	}
}

function safeProviderCode(value: unknown): string | undefined {
	if (typeof value !== "string") return undefined;
	const code = value.includes("#") ? value.slice(value.lastIndexOf("#") + 1) : value;
	return /^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(code) ? code : undefined;
}

function responseFailure(status: number, body: Record<string, unknown>): SesDeliveryError {
	const providerCode = safeProviderCode(body.name) ?? safeProviderCode(body.__type) ?? safeProviderCode(body.code);
	const retryableCodes = new Set([
		"InternalFailure",
		"RequestTimeout",
		"ServiceUnavailableException",
		"ThrottlingException",
		"TooManyRequestsException",
	]);
	const retryable = status === 408 || status === 429 || status >= 500 || (providerCode ? retryableCodes.has(providerCode) : false);
	return new SesDeliveryError(providerCode ? `SES_${providerCode.toUpperCase()}` : "SES_HTTP_STATUS", retryable, status);
}

function sendBody(payload: EmailPayload, jobId: string): string {
	const stableDeliveryId = sha256(jobId);
	return JSON.stringify({
		FromEmailAddress: payload.from,
		Destination: { ToAddresses: [payload.to] },
		Content: {
			Simple: {
				Subject: { Data: payload.subject, Charset: "UTF-8" },
				Body: {
					...(payload.text === undefined ? {} : { Text: { Data: payload.text, Charset: "UTF-8" } }),
					...(payload.html === undefined ? {} : { Html: { Data: payload.html, Charset: "UTF-8" } }),
				},
				Headers: [{ Name: "X-Clearance-Delivery-ID", Value: stableDeliveryId }],
			},
		},
		...(payload.replyTo ? { ReplyToAddresses: [payload.replyTo] } : {}),
	});
}

export function classifySesError(error: unknown): { retryable: boolean; errorClass: string; providerStatus?: string } {
	if (!(error instanceof SesDeliveryError)) {
		return { retryable: true, errorClass: "ses.transport" };
	}
	const providerStatus = error.statusCode === undefined ? undefined : String(error.statusCode);
	if (error.retryable) {
		return { retryable: true, errorClass: error.code === "SES_TIMEOUT" ? "ses.timeout" : "ses.transient", providerStatus };
	}
	if (error.statusCode === 401 || error.statusCode === 403 || error.code === "SES_SENDING_DISABLED") {
		return { retryable: false, errorClass: "ses.authorization", providerStatus };
	}
	return { retryable: false, errorClass: "ses.rejected", providerStatus };
}

export function createSesSender(config: WorkerConfig, dependencies: SesDependencies = {}): EmailSender {
	const ses = config.ses;
	if (!ses || (config.emailTransport ?? "smtp") !== "ses") {
		throw new Error("SES sender requires validated SES worker configuration");
	}
	const fetchImpl = dependencies.fetchImpl ?? fetch;
	const now = dependencies.now ?? (() => new Date());
	const request = async (method: "GET" | "POST", path: string, body = ""): Promise<Record<string, unknown>> => {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), ses.requestTimeoutMs);
		try {
			const response = await fetchImpl(`https://${endpointHost(ses.region)}${path}`, {
				method,
				headers: signedHeaders(ses, method, path, body, now()),
				...(method === "POST" ? { body } : {}),
				redirect: "error",
				signal: controller.signal,
			});
			const parsed = await boundedJson(response);
			if (!response.ok) throw responseFailure(response.status, parsed);
			return parsed;
		} catch (error) {
			if (error instanceof SesDeliveryError) throw error;
			if (controller.signal.aborted) throw new SesDeliveryError("SES_TIMEOUT", true);
			throw new SesDeliveryError("SES_TRANSPORT", true);
		} finally {
			clearTimeout(timeout);
		}
	};
	return {
		async verify() {
			const account = await request("GET", "/v2/email/account");
			if (account.SendingEnabled !== true) throw new SesDeliveryError("SES_SENDING_DISABLED", false, 200);
		},
		async send(payload, context): Promise<SendResult> {
			const body = sendBody(renderEmailPayload(payload, config), context.jobId);
			const result = await request("POST", "/v2/email/outbound-emails", body);
			const messageId = typeof result.MessageId === "string" && result.MessageId.length <= 512
				? result.MessageId
				: undefined;
			if (!messageId) throw new SesDeliveryError("SES_RESPONSE_INVALID", false, 200);
			return { status: "200", requestId: sha256(messageId) };
		},
		close() {},
	};
}
