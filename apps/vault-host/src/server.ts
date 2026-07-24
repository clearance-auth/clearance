import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { fileURLToPath } from "node:url";
import {
	closeHostedAuthBundles,
	createManagementStore,
	acquireHostedAuthBundle,
	prepareHostedAuthBundle,
	resolveOperatorScopeAuthoritative,
	type ManagementStore,
	type ProductHostedDomainView,
	type ProductPresentationView,
	type ResourceScope,
} from "@clearance/management";

const port = boundedPort(process.env.CLEARANCE_VAULT_PORT, 3400);
const maxRequestBodyBytes = boundedBodyLimit(
	process.env.CLEARANCE_VAULT_MAX_BODY_BYTES,
	1024 * 1024,
);
const baseURL = exactBaseURL(
	process.env.CLEARANCE_VAULT_URL ??
		`http://localhost:${port}`,
);
const configuredRuntimeBaseURL = process.env.CLEARANCE_BASE_URL?.trim();
if (
	configuredRuntimeBaseURL &&
	new URL(configuredRuntimeBaseURL).origin !== baseURL.origin
) {
	throw new Error(
		"CLEARANCE_BASE_URL must use the same origin as CLEARANCE_VAULT_URL",
	);
}
process.env.CLEARANCE_BASE_URL = baseURL.origin;
const productName = boundedText(
	process.env.CLEARANCE_VAULT_PRODUCT_NAME,
	"Clearance",
	80,
);
const homeLabel = boundedText(
	process.env.CLEARANCE_VAULT_HOME_LABEL,
	`${productName} Vault`,
	120,
);

type HostedPresentation = Readonly<{
	productLabel: string;
	homeLabel: string;
	accentColor: string;
	logoUrl: string | null;
	presentationVersion: string | number;
}>;

type HostedAuthBundle = Awaited<ReturnType<typeof acquireHostedAuthBundle>>["bundle"];

export type HostedRequestContext = Readonly<{
	origin: string;
	hostname: string;
	authority: string;
	scope: ResourceScope;
	presentation: HostedPresentation;
	domainVersion: string | number;
}>;

type ActiveDomainResolver = Pick<
	NonNullable<ManagementStore["productPresentation"]>,
	"resolveActiveHostedDomain"
>;

const vaultRoutes = new Set([
	"sign-in",
	"sign-up",
	"recovery",
	"account",
	"organizations",
	"invitations",
	"access",
	"service-accounts",
	"enterprise",
	"audit",
]);

function boundedPort(raw: string | undefined, fallback: number): number {
	if (raw === undefined || raw.trim() === "") return fallback;
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) {
		throw new Error("CLEARANCE_VAULT_PORT must be an integer from 1 to 65535");
	}
	return value;
}

function boundedBodyLimit(raw: string | undefined, fallback: number): number {
	if (raw === undefined || raw.trim() === "") return fallback;
	const value = Number(raw);
	if (
		!Number.isSafeInteger(value) ||
		value < 1 ||
		value > 16 * 1024 * 1024
	) {
		throw new Error(
			"CLEARANCE_VAULT_MAX_BODY_BYTES must be an integer from 1 to 16777216",
		);
	}
	return value;
}

function exactBaseURL(raw: string): URL {
	const url = new URL(raw);
	if (
		url.username ||
		url.password ||
		url.search ||
		url.hash ||
		url.pathname !== "/"
	) {
		throw new Error(
			"CLEARANCE_VAULT_URL must be an origin without credentials, path, query, or fragment",
		);
	}
	const loopback =
		url.hostname === "localhost" ||
		url.hostname === "127.0.0.1" ||
		url.hostname === "[::1]";
	if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
		throw new Error(
			"CLEARANCE_VAULT_URL must use HTTPS outside loopback development",
		);
	}
	return url;
}

function boundedText(
	raw: string | undefined,
	fallback: string,
	maxLength: number,
): string {
	const value = raw?.trim() || fallback;
	if (value.length > maxLength || /[\0\r\n]/.test(value)) {
		throw new Error("Vault branding text is invalid");
	}
	return value;
}

function exactCanonicalAuthority(raw: string): string | null {
	if (raw !== baseURL.host) return null;
	return raw;
}

/** A custom claim is always a lower-case HTTPS hostname without a port. */
export function customHostnameFromAuthority(authority: string): string | null {
	if (
		authority.length === 0 ||
		authority !== authority.toLowerCase() ||
		authority.includes(",") ||
		/[\s\\/@]/.test(authority)
	) return null;
	try {
		const url = new URL(`https://${authority}`);
		if (
			url.protocol !== "https:" || url.port || url.host !== authority ||
			url.hostname !== authority || !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(authority)
		) return null;
		return authority;
	} catch {
		return null;
	}
}

export function rawHostAuthority(request: Pick<IncomingMessage, "headers" | "rawHeaders">): string {
	const values: string[] = [];
	for (let index = 0; index < request.rawHeaders.length; index += 2) {
		if (request.rawHeaders[index]?.toLowerCase() === "host") {
			values.push(request.rawHeaders[index + 1] ?? "");
		}
	}
	const header = request.headers.host;
	if (
		values.length !== 1 || typeof header !== "string" || values[0] !== header ||
		header.trim() !== header || header.length === 0
	) {
		throw new InvalidHostError();
	}
	return header;
}

function presentationFromDomain(domain: ProductHostedDomainView): HostedPresentation {
	const presentation = domain.presentation;
	if (!/^#[0-9a-f]{6}$/i.test(presentation.accentColor)) {
		throw new Error("Hosted presentation accent is invalid");
	}
	const validLogo = logoOrigin(presentation.logoUrl) ? presentation.logoUrl : null;
	return Object.freeze({
		productLabel: boundedText(presentation.productLabel, productName, 80),
		homeLabel: boundedText(presentation.homeLabel, homeLabel, 120),
		accentColor: presentation.accentColor.toLowerCase(),
		logoUrl: validLogo,
		presentationVersion: presentation.version,
	});
}

function canonicalPresentation(domain: ProductPresentationView): HostedPresentation {
	return presentationFromDomain({
		origin: baseURL.origin,
		hostname: baseURL.hostname,
		scope: { projectId: "canonical", environmentId: "canonical" },
		domainVersion: 0,
		presentation: domain,
	});
}

export async function hostedContextForAuthority(input: Readonly<{
	authority: string;
	canonicalScope: ResourceScope;
	canonicalPresentation: ProductPresentationView;
	resolver?: ActiveDomainResolver;
}>): Promise<HostedRequestContext> {
	if (exactCanonicalAuthority(input.authority)) {
		return Object.freeze({
			origin: baseURL.origin,
			hostname: baseURL.hostname,
			authority: baseURL.host,
			scope: Object.freeze({ ...input.canonicalScope }),
			presentation: canonicalPresentation(input.canonicalPresentation),
			domainVersion: 0,
		});
	}
	const hostname = customHostnameFromAuthority(input.authority);
	if (!hostname || !input.resolver) throw new UnknownHostedDomainError();
	const domain = await input.resolver.resolveActiveHostedDomain(hostname);
	if (!domain || domain.hostname !== hostname) throw new UnknownHostedDomainError();
	const expectedOrigin = `https://${hostname}`;
	if (
		domain.origin !== expectedOrigin || !domain.scope.projectId.trim() ||
		!domain.scope.environmentId.trim()
	) throw new UnknownHostedDomainError();
	return Object.freeze({
		origin: domain.origin,
		hostname,
		authority: hostname,
		scope: Object.freeze({ ...domain.scope }),
		presentation: presentationFromDomain(domain),
		domainVersion: domain.domainVersion,
	});
}

function logoOrigin(logoUrl: string | null): string | null {
	if (!logoUrl) return null;
	try {
		const url = new URL(logoUrl);
		if (
			url.protocol !== "https:" ||
			url.username ||
			url.password ||
			url.hash
		) return null;
		return url.origin;
	} catch {
		return null;
	}
}

export function contentSecurityPolicy(context?: HostedRequestContext): string {
	const imageSource = logoOrigin(context?.presentation.logoUrl ?? null);
	return `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:${imageSource ? ` ${imageSource}` : ""}; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`;
}

function secureHeaders(response: ServerResponse, context?: HostedRequestContext): void {
	response.setHeader("content-security-policy", contentSecurityPolicy(context));
	response.setHeader("referrer-policy", "no-referrer");
	response.setHeader("x-content-type-options", "nosniff");
	response.setHeader("x-frame-options", "DENY");
	response.setHeader(
		"permissions-policy",
		"camera=(), geolocation=(), microphone=(), payment=(), usb=()",
	);
	response.setHeader("cross-origin-opener-policy", "same-origin");
	response.setHeader("cross-origin-resource-policy", "same-origin");
}

function htmlDocument(context: HostedRequestContext): string {
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>${escapeHtml(context.presentation.homeLabel)}</title>
  <link rel="stylesheet" href="/assets/vault.css">
  <link rel="stylesheet" href="/assets/vault-theme.css">
</head>
<body>
  <main id="clearance-vault"></main>
  <noscript>JavaScript is required to use ${escapeHtml(context.presentation.homeLabel)}.</noscript>
  <script type="module" src="/assets/boot.js"></script>
</body>
</html>`;
}

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, (character) => ({
		"&": "&amp;",
		"<": "&lt;",
		">": "&gt;",
		'"': "&quot;",
		"'": "&#39;",
	})[character]!);
}

export function configModule(context: HostedRequestContext): string {
	const development =
		context.origin.startsWith("http://") &&
		(context.hostname === "localhost" ||
			context.hostname === "127.0.0.1" ||
			context.hostname === "[::1]");
	const serialized = JSON.stringify({
		development,
		styleMode: "external",
		branding: {
			productName: context.presentation.productLabel,
			homeLabel: context.presentation.homeLabel,
			...(context.presentation.logoUrl ? { logoUrl: context.presentation.logoUrl } : {}),
		},
		passkeyRpId: context.hostname,
	}).replaceAll("<", "\\u003c");
	return `export default Object.freeze(${serialized});\n`;
}

export function accentStylesheet(context: HostedRequestContext): string {
	return `@layer clearance-vault { .cv-root { --cv-accent: ${context.presentation.accentColor}; } }\n`;
}

const bootModule = `import { mountClearanceVault } from "/assets/vault.js";
import config from "/assets/config.js";
const route = location.pathname.replace(/^\\/+|\\/+$/g, "") || "sign-in";
mountClearanceVault(document.getElementById("clearance-vault"), {
  ...config,
  initialRoute: route,
});
`;

const vaultAssets = Promise.all([
	readFile(fileURLToPath(import.meta.resolve("@clearance/vault"))),
	readFile(fileURLToPath(import.meta.resolve("@clearance/vault/styles.css"))),
]).then(([module, styles]) => Object.freeze({ module, styles }));

function send(
	response: ServerResponse,
	status: number,
	contentType: string,
	body: string | Buffer,
	cacheControl = "no-store",
	context?: HostedRequestContext,
): void {
	secureHeaders(response, context);
	response.statusCode = status;
	response.setHeader("content-type", contentType);
	response.setHeader("cache-control", cacheControl);
	response.setHeader("content-length", String(Buffer.byteLength(body)));
	response.end(body);
}

class RequestBodyTooLargeError extends Error {
	constructor() {
		super("Vault request body is too large");
		this.name = "RequestBodyTooLargeError";
	}
}

class InvalidRequestTargetError extends Error {
	constructor() {
		super("Vault request target must use an origin-form path and query");
		this.name = "InvalidRequestTargetError";
	}
}

class InvalidHostError extends Error {
	constructor() {
		super("Vault request must contain exactly one valid Host authority");
		this.name = "InvalidHostError";
	}
}

class UnknownHostedDomainError extends Error {
	constructor() {
		super("Vault host is not an active hosted domain");
		this.name = "UnknownHostedDomainError";
	}
}

/**
 * Produces the sole URL shape that may be passed to the auth handler.
 * Node exposes the raw request target in `request.url`; URL's relative
 * resolution would otherwise accept absolute and network-path targets.
 */
export function vaultRequestURL(
	rawTarget: string | undefined,
	origin = baseURL.origin,
): URL {
	const target = rawTarget ?? "/";
	const queryStart = target.indexOf("?");
	const pathname = queryStart === -1 ? target : target.slice(0, queryStart);
	if (
		!pathname.startsWith("/") ||
		pathname.startsWith("//") ||
		pathname.includes("//") ||
		target.includes("#")
	) {
		throw new InvalidRequestTargetError();
	}

	const url = new URL(target, origin);
	if (url.origin !== origin) throw new InvalidRequestTargetError();
	return url;
}

async function readBoundedBody(
	request: IncomingMessage,
): Promise<ArrayBuffer | undefined> {
	if (request.method === "GET" || request.method === "HEAD") return undefined;
	const declared = request.headers["content-length"];
	if (
		typeof declared === "string" &&
		/^\d+$/.test(declared) &&
		Number(declared) > maxRequestBodyBytes
	) {
		throw new RequestBodyTooLargeError();
	}
	return new Promise<ArrayBuffer | undefined>((resolve, reject) => {
		const chunks: Buffer[] = [];
		let total = 0;
		const cleanup = () => {
			request.off("data", onData);
			request.off("end", onEnd);
			request.off("aborted", onAborted);
			request.off("error", onError);
		};
		const fail = (error: Error) => {
			cleanup();
			reject(error);
		};
		const onData = (chunk: Buffer | string) => {
			const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			total += buffer.length;
			if (total > maxRequestBodyBytes) {
				cleanup();
				request.resume();
				reject(new RequestBodyTooLargeError());
				return;
			}
			chunks.push(buffer);
		};
		const onEnd = () => {
			cleanup();
			if (total === 0) {
				resolve(undefined);
				return;
			}
			const body = new Uint8Array(total);
			body.set(Buffer.concat(chunks, total));
			resolve(body.buffer);
		};
		const onAborted = () => fail(new Error("Vault request body was aborted"));
		const onError = (error: Error) => fail(error);
		request.on("data", onData);
		request.once("end", onEnd);
		request.once("aborted", onAborted);
		request.once("error", onError);
	});
}

function setCookieValues(headers: Headers): readonly string[] {
	if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
	const combined = headers.get("set-cookie");
	return combined ? [combined] : [];
}

export function canonicalAuthHeaders(
	requestHeaders: IncomingMessage["headers"],
	authority: string,
	clientAddress?: string,
): Headers {
	const headers = new Headers();
	for (const [name, value] of Object.entries(requestHeaders)) {
		const normalized = name.toLowerCase();
		if (
			normalized === "host" || normalized === "forwarded" ||
			normalized === "x-forwarded-host" || normalized === "x-forwarded-proto" ||
			normalized === "x-forwarded-for" || normalized === "x-real-ip"
		) continue;
		if (value === undefined) continue;
		if (Array.isArray(value)) {
			for (const item of value) headers.append(name, item);
		} else {
			headers.set(name, value);
		}
	}
	headers.set("host", authority);
	if (clientAddress && isIP(clientAddress) !== 0) {
		headers.set("x-forwarded-for", clientAddress);
	}
	return headers;
}

async function serveAuth(
	bundle: HostedAuthBundle,
	request: IncomingMessage,
	response: ServerResponse,
	requestURL: URL,
	context: HostedRequestContext,
): Promise<void> {
	const body = await readBoundedBody(request);
	const headers = canonicalAuthHeaders(
		request.headers,
		context.authority,
		request.socket.remoteAddress,
	);
	const authResponse = await bundle.auth.handler(
		new Request(requestURL, {
			method: request.method,
			headers,
			...(body === undefined ? {} : { body }),
		}),
	);
	secureHeaders(response, context);
	response.statusCode = authResponse.status;
	authResponse.headers.forEach((value, name) => {
		if (name.toLowerCase() !== "set-cookie") response.setHeader(name, value);
	});
	const cookies = setCookieValues(authResponse.headers);
	if (cookies.length > 0) response.setHeader("set-cookie", cookies);
	response.end(Buffer.from(await authResponse.arrayBuffer()));
}

/**
 * Operational probes intentionally run before host selection. Liveness proves
 * only that this process can answer HTTP; readiness also proves the store is
 * available, without requiring a tenant domain or presentation lookup.
 */
export async function serveOperationalProbe(
	request: Pick<IncomingMessage, "method" | "url">,
	response: ServerResponse,
	readiness: () => Promise<void>,
): Promise<boolean> {
	if (request.method !== "GET" && request.method !== "HEAD") return false;
	const url = vaultRequestURL(request.url);
	if (url.pathname === "/healthz") {
		send(
			response,
			200,
			"application/json; charset=utf-8",
			JSON.stringify({ ok: true, service: "clearance-vault" }),
		);
		return true;
	}
	if (url.pathname === "/readyz") {
		await readiness();
		send(
			response,
			200,
			"application/json; charset=utf-8",
			JSON.stringify({ ok: true, service: "clearance-vault" }),
		);
		return true;
	}
	return false;
}

async function serveVault(
	url: URL,
	request: IncomingMessage,
	response: ServerResponse,
	context: HostedRequestContext,
): Promise<boolean> {
	if (request.method !== "GET" && request.method !== "HEAD") return false;

	if (url.pathname === "/assets/config.js") {
		send(response, 200, "text/javascript; charset=utf-8", configModule(context), "no-store", context);
		return true;
	}
	if (url.pathname === "/assets/vault-theme.css") {
		send(response, 200, "text/css; charset=utf-8", accentStylesheet(context), "no-store", context);
		return true;
	}
	if (url.pathname === "/assets/boot.js") {
		send(
			response,
			200,
			"text/javascript; charset=utf-8",
			bootModule,
			"public, max-age=300", context,
		);
		return true;
	}
	if (url.pathname === "/assets/vault.js") {
		const assets = await vaultAssets;
		send(
			response,
			200,
			"text/javascript; charset=utf-8",
			assets.module,
			"public, max-age=300", context,
		);
		return true;
	}
	if (url.pathname === "/assets/vault.css") {
		const assets = await vaultAssets;
		send(
			response,
			200,
			"text/css; charset=utf-8",
			assets.styles,
			"public, max-age=300", context,
		);
		return true;
	}
	if (url.pathname === "/") {
		secureHeaders(response, context);
		response.statusCode = 302;
		response.setHeader("location", "/sign-in");
		response.setHeader("cache-control", "no-store");
		response.end();
		return true;
	}
	const route = url.pathname.replace(/^\/+|\/+$/g, "");
	if (vaultRoutes.has(route)) {
		send(response, 200, "text/html; charset=utf-8", htmlDocument(context), "no-store", context);
		return true;
	}
	return false;
}

export async function canonicalScopeForHostedStartup(
	store: ManagementStore,
): Promise<ResourceScope> {
	const projectId = process.env.CLEARANCE_PROJECT_ID?.trim();
	const environmentId = process.env.CLEARANCE_ENV_ID?.trim();
	const strictProduction = process.env.NODE_ENV === "production" ||
		process.env.CLEARANCE_STRICT_SECRETS === "1";
	if (strictProduction && (!projectId || !environmentId)) {
		throw new Error(
			"CLEARANCE_PROJECT_ID and CLEARANCE_ENV_ID are required for the canonical Vault host in production",
		);
	}
	const scope = projectId && environmentId
		? await resolveOperatorScopeAuthoritative(store, { projectId, environmentId })
		: await resolveOperatorScopeAuthoritative(store);
	return Object.freeze(scope);
}

async function destroyManagementStore(store: ManagementStore): Promise<void> {
	const destroy = (store as ManagementStore & { destroy?: unknown }).destroy;
	if (typeof destroy === "function") await destroy.call(store);
}

type VaultHostShutdownSteps = Readonly<{
	closeHttp: () => Promise<void>;
	closeBundles: () => Promise<void>;
	destroyStore: () => Promise<void>;
}>;

/**
 * Each shutdown phase must settle before the next starts: active HTTP handlers
 * can still hold hosted-bundle leases, and bundles can still use the shared
 * management store while they retire. A settled HTTP-close error is still a
 * terminal close result (for example, an already-closed server), so preserve
 * that error while completing the remaining safe cleanup.
 */
export async function closeVaultHostInDependencyOrder(
	steps: VaultHostShutdownSteps,
): Promise<void> {
	const failures: unknown[] = [];
	for (const close of [steps.closeHttp, steps.closeBundles, steps.destroyStore]) {
		try {
			await close();
		} catch (error) {
			failures.push(error);
		}
	}
	if (failures.length === 1) throw failures[0];
	if (failures.length > 1) {
		throw new AggregateError(failures, "Vault host shutdown failed");
	}
}

function closeHttpServer(server: ReturnType<typeof createServer>): Promise<void> {
	return new Promise((resolve, reject) => {
		// `close()` synchronously stops accepting connections; closing idle
		// keep-alives afterward lets its callback represent handler drain.
		server.close((error) => error ? reject(error) : resolve());
		server.closeIdleConnections?.();
	});
}

export async function startVaultHost(): Promise<{
	close(): Promise<void>;
}> {
	const store = await createManagementStore({
		databaseUrl: process.env.DATABASE_URL,
		backend: "postgres",
	});
	try {
	await store.ready();
	const presentationAuthority = store.productPresentation;
	if (!presentationAuthority) {
		throw new Error("Vault host requires normalized product-presentation authority");
	}
	const canonicalScope = await canonicalScopeForHostedStartup(store);
	const initialPresentation = await presentationAuthority.getPresentation(canonicalScope);
	const initialContext = await hostedContextForAuthority({
		authority: baseURL.host,
		canonicalScope,
		canonicalPresentation: initialPresentation,
		resolver: presentationAuthority,
	});
	const canonicalLease = await acquireHostedAuthBundle({
		origin: initialContext.origin,
		hostname: initialContext.hostname,
		scope: initialContext.scope,
		productLabel: initialContext.presentation.productLabel,
		store,
		presentationVersion: initialContext.presentation.presentationVersion,
		domainVersion: initialContext.domainVersion,
	});
	try {
		await prepareHostedAuthBundle(canonicalLease.bundle);
	} finally {
		await canonicalLease.release();
	}
	await vaultAssets;
	const server = createServer(async (request, response) => {
		try {
			if (await serveOperationalProbe(request, response, () => store.ready())) return;
			const authority = rawHostAuthority(request);
			const canonicalPresentation = await presentationAuthority.getPresentation(canonicalScope);
			const context = await hostedContextForAuthority({
				authority,
				canonicalScope,
				canonicalPresentation,
				resolver: presentationAuthority,
			});
			const url = vaultRequestURL(request.url, context.origin);
			if (url.pathname === "/api/auth" || url.pathname.startsWith("/api/auth/")) {
				const lease = await acquireHostedAuthBundle({
					origin: context.origin,
					hostname: context.hostname,
					scope: context.scope,
					productLabel: context.presentation.productLabel,
					store,
					presentationVersion: context.presentation.presentationVersion,
					domainVersion: context.domainVersion,
				});
				try {
					await serveAuth(lease.bundle, request, response, url, context);
				} finally {
					await lease.release();
				}
				return;
			}
			if (await serveVault(url, request, response, context)) return;
			send(response, 404, "text/plain; charset=utf-8", "Not found", "no-store", context);
			} catch (error) {
				if (error instanceof RequestBodyTooLargeError) {
					if (!request.complete) {
						response.setHeader("connection", "close");
						request.resume();
					}
					send(
						response,
					413,
					"application/json; charset=utf-8",
					JSON.stringify({
						error: {
							code: "REQUEST_BODY_TOO_LARGE",
							message: `Request body exceeds ${maxRequestBodyBytes} bytes`,
							},
						}),
					);
					return;
				}
			if (error instanceof InvalidRequestTargetError) {
					send(
						response,
						400,
						"application/json; charset=utf-8",
						JSON.stringify({
							error: {
								code: "INVALID_REQUEST_TARGET",
								message: "Request target must be an origin-form path and query",
							},
						}),
					);
				return;
			}
			if (error instanceof InvalidHostError) {
				send(response, 400, "application/json; charset=utf-8", JSON.stringify({ error: { code: "INVALID_HOST", message: "Host must be one exact authority" } }));
				return;
			}
			if (error instanceof UnknownHostedDomainError) {
				send(response, 404, "text/plain; charset=utf-8", "Not found");
				return;
			}
			if (!response.headersSent) {
				send(
					response,
					500,
					"application/json; charset=utf-8",
					JSON.stringify({
						error: {
							code: "VAULT_HOST_FAILURE",
							message: "Vault request failed",
						},
					}),
				);
			} else {
				response.destroy();
			}
		}
	});
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(port, "0.0.0.0", resolve);
	});
	let shutdown: Promise<void> | undefined;
	return Object.freeze({
		close: () => {
			shutdown ??= closeVaultHostInDependencyOrder({
				closeHttp: () => closeHttpServer(server),
				closeBundles: closeHostedAuthBundles,
				destroyStore: () => destroyManagementStore(store),
			});
			return shutdown;
		},
	});
	} catch (error) {
		await closeVaultHostInDependencyOrder({
			closeHttp: async () => undefined,
			closeBundles: closeHostedAuthBundles,
			destroyStore: () => destroyManagementStore(store),
		}).catch(() => undefined);
		throw error;
	}
}

const isMain =
	process.argv[1]?.endsWith("/server.ts") ||
	process.argv[1]?.endsWith("/server.js");
if (isMain) {
	startVaultHost()
		.then((host) => {
			console.log(`clearance-vault ${baseURL.origin}`);
			let shutdown: Promise<void> | undefined;
			const stop = () => {
				shutdown ??= host.close();
				return shutdown;
			};
			process.once("SIGINT", () => void stop());
			process.once("SIGTERM", () => void stop());
		})
		.catch((error) => {
			console.error(error);
			process.exitCode = 1;
		});
}
