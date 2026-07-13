/**
 * Sample B2B SaaS — real Clearance auth (inherited clearance runtime) on Postgres.
 */
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
	createClearanceAuth,
	socialProvidersFromEnvironment,
} from "@clearance/auth";
import {
	createManagementStore,
	initProject,
	recordEvent,
	syncRuntimeOrganizationToManagementDurable,
	syncRuntimeUserToManagementDurable,
} from "@clearance/management";

const port = Number(process.env.SAMPLE_APP_PORT ?? 3300);
export const DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024;

export function resolveMaxRequestBodyBytes(
	env: Record<string, string | undefined> = process.env,
): number {
	const raw = env.SAMPLE_APP_MAX_BODY_BYTES;
	if (raw === undefined || raw.trim() === "") return DEFAULT_MAX_REQUEST_BODY_BYTES;
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value < 1 || value > 64 * 1024 * 1024) {
		throw new Error(
			"SAMPLE_APP_MAX_BODY_BYTES must be an integer between 1 and 67108864",
		);
	}
	return value;
}

const maxRequestBodyBytes = resolveMaxRequestBodyBytes();
const baseURL = process.env.CLEARANCE_BASE_URL ?? `http://localhost:${port}`;
const secret =
	process.env.CLEARANCE_SECRET ?? "dev-secret-change-me-please-32chars!!";
const databaseUrl =
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const socialProviders = socialProvidersFromEnvironment();
const enabledSocialProviders = Object.keys(socialProviders);

let managementStorePromise: ReturnType<typeof createManagementStore> | undefined;

function getManagementStore() {
	managementStorePromise ??= createManagementStore({
		backend: "postgres",
		databaseUrl,
	}).then(async (managementStore) => {
		if (managementStore.snapshot.projects.length === 0) {
			initProject(managementStore, { name: "sample-b2b", source: "api" });
			await managementStore.ready();
		}
		return managementStore;
	});
	return managementStorePromise;
}

const bundle = createClearanceAuth({
	baseURL,
	secret,
	databaseUrl,
	enableSso: true,
	enableScim: true,
	trustedOrigins: [baseURL, "http://localhost:3100", "http://localhost:3200"],
	socialProviders,
	onUserCreated: async (user) => {
		const managementStore = await getManagementStore();
		await syncRuntimeUserToManagementDurable(managementStore, user, {
			actor: user.email,
			source: "system",
		});
	},
});

class RequestBodyTooLargeError extends Error {
	constructor(readonly limit: number) {
		super(`Request body exceeds the ${limit}-byte limit`);
		this.name = "RequestBodyTooLargeError";
	}
}

async function readBoundedRequestBody(
	req: IncomingMessage,
	limit: number,
): Promise<Buffer | undefined> {
	if (req.method === "GET" || req.method === "HEAD") return undefined;
	const rawContentLength = req.headers["content-length"];
	if (
		typeof rawContentLength === "string" &&
		/^\d+$/.test(rawContentLength) &&
		Number(rawContentLength) > limit
	) {
		throw new RequestBodyTooLargeError(limit);
	}

	const chunks: Buffer[] = [];
	let total = 0;
	for await (const chunk of req) {
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		total += buffer.length;
		if (total > limit) throw new RequestBodyTooLargeError(limit);
		chunks.push(buffer);
	}
	return total > 0 ? Buffer.concat(chunks, total) : undefined;
}

function payloadTooLarge(
	req: IncomingMessage,
	res: ServerResponse,
	limit: number,
): void {
	const body = JSON.stringify({
		error: {
			code: "REQUEST_BODY_TOO_LARGE",
			message: `Request body exceeds the ${limit}-byte limit`,
			stage: "sample.request_body",
			retryable: false,
			limitBytes: limit,
		},
	});
	res.statusCode = 413;
	res.setHeader("content-type", "application/json; charset=utf-8");
	res.setHeader("content-length", String(Buffer.byteLength(body)));
	res.setHeader("connection", "close");
	res.end(body, () => {
		if (!req.complete) req.destroy();
	});
}

async function forwardAuthResponse(
	response: Response,
	res: ServerResponse,
): Promise<void> {
	res.statusCode = response.status;
	response.headers.forEach((value, key) => {
		if (key !== "set-cookie") res.setHeader(key, value);
	});
	const cookies = getSetCookieValues(response.headers);
	if (cookies.length > 0) res.setHeader("Set-Cookie", cookies);
	res.end(Buffer.from(await response.arrayBuffer()));
}

/** HTML-escape all user-provided / untrusted output before interpolation. */
export function escapeHtml(value: unknown): string {
	return String(value ?? "").replace(/[&<>"']/g, (c) =>
		(
			({
				"&": "&amp;",
				"<": "&lt;",
				">": "&gt;",
				'"': "&quot;",
				"'": "&#39;",
			}) as Record<string, string>
		)[c]!,
	);
}

function html(body: string, title = "Sample B2B") {
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><title>${escapeHtml(title)}</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b0d10;color:#e8eaed;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#12151a;border:1px solid #242a33;border-radius:10px;padding:24px;width:380px}
h1{font-size:18px;margin:0 0 12px}label{display:block;font-size:12px;color:#8b939e;margin:10px 0 4px}
input{width:100%;padding:8px;border-radius:6px;border:1px solid #242a33;background:#0b0d10;color:#e8eaed}
button{margin-top:14px;width:100%;padding:10px;border:0;border-radius:6px;background:#e8eaed;color:#0b0d10;font-weight:600;cursor:pointer}
a{color:#66b3ff;font-size:13px}p{font-size:13px;color:#8b939e}.err{color:#f31260}
code{font-size:11px}
</style></head><body><div class="card">${body}</div></body></html>`;
}

export function socialSignInMarkup(providers: string[]): string {
	return providers
		.map(
			(provider) =>
				`<button type="button" data-social-provider="${escapeHtml(provider)}" onclick="socialSignIn('${escapeHtml(provider)}')">Continue with ${escapeHtml(provider[0]?.toUpperCase() + provider.slice(1))}</button>`,
		)
		.join("");
}

/** Only HTTPS IdPs (plus same-origin/loopback HTTP development) may receive navigation. */
export function isAllowedSocialRedirect(value: unknown, appOrigin: string): boolean {
	if (typeof value !== "string" || value.length === 0) return false;
	try {
		const current = new URL(appOrigin);
		const redirect = new URL(value, current);
		if (redirect.protocol === "https:") return true;
		if (redirect.protocol !== "http:" || current.protocol !== "http:") return false;
		return (
			redirect.origin === current.origin ||
			redirect.hostname === "localhost" ||
			redirect.hostname === "127.0.0.1" ||
			redirect.hostname === "[::1]"
		);
	} catch {
		return false;
	}
}

/** Preserve distinct Set-Cookie values, including Expires attributes with commas. */
export function getSetCookieValues(headers: Headers): string[] {
	if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
	const combined = headers.get("set-cookie") ?? "";
	if (!combined) return [];
	const values: string[] = [];
	let start = 0;
	for (let i = 0; i < combined.length; i++) {
		if (combined[i] !== ",") continue;
		let cursor = i + 1;
		while (combined[cursor] === " ") cursor++;
		while (
			cursor < combined.length &&
			combined[cursor] !== "=" &&
			combined[cursor] !== ";" &&
			combined[cursor] !== ","
		) {
			cursor++;
		}
		if (combined[cursor] !== "=") continue;
		const value = combined.slice(start, i).trim();
		if (value) values.push(value);
		start = i + 1;
	}
	const last = combined.slice(start).trim();
	if (last) values.push(last);
	return values;
}

/** Require browser-supplied same-origin evidence before a session mutation. */
export function sameOriginMutationOrigin(
	origin: string | undefined,
	referer: string | undefined,
	expectedURL: string,
): string | null {
	const evidence = origin?.trim() || referer?.trim();
	if (!evidence) return null;
	try {
		const expectedOrigin = new URL(expectedURL).origin;
		const evidenceOrigin = new URL(evidence).origin;
		return evidenceOrigin === expectedOrigin ? evidenceOrigin : null;
	} catch {
		return null;
	}
}

/** Safe public session metadata — never raw bearer/session credentials. */
export type SafeSessionView = {
	user: { id: string; email: string; name: string };
	session: {
		id: string;
		userId: string;
		expiresAt?: string;
		/** Presence only — never the raw token */
		active: true;
	};
};

export function toSafeSessionView(data: {
	session?: {
		token?: string;
		id?: string;
		userId?: string;
		expiresAt?: string | Date;
	};
	user?: { id: string; email: string; name: string };
}): SafeSessionView | null {
	if (!data.user || !data.session) return null;
	const sessionId =
		data.session.id ||
		// If only a token is present, expose a one-way fingerprint.
		(data.session.token
			? `sess_${createHash("sha256").update(data.session.token).digest("hex").slice(0, 16)}`
			: "sess_unknown");
	return {
		user: {
			id: data.user.id,
			email: data.user.email,
			name: data.user.name,
		},
		session: {
			id: sessionId,
			userId: data.session.userId ?? data.user.id,
			expiresAt:
				data.session.expiresAt instanceof Date
					? data.session.expiresAt.toISOString()
					: data.session.expiresAt,
			active: true,
		},
	};
}

async function getSession(req: IncomingMessage) {
	const headers = new Headers();
	if (req.headers.cookie) headers.set("cookie", req.headers.cookie);
	headers.set("origin", baseURL);
	const res = await bundle.auth.handler(
		new Request(`${baseURL}/api/auth/get-session`, { headers }),
	);
	if (!res.ok) return null;
	// clearance's get-session returns a literal JSON `null` body when there
	// is no session; guard it or unauthenticated requests crash the handler.
	const data = (await res.json()) as {
		session?: {
			token?: string;
			id?: string;
			userId?: string;
			expiresAt?: string | Date;
		};
		user?: { id: string; email: string; name: string };
	} | null;
	return data?.session && data?.user ? data : null;
}

async function routeRequest(
	req: IncomingMessage,
	res: ServerResponse,
	requestBody: Buffer | undefined,
) {
	const url = new URL(req.url ?? "/", baseURL);

	if (url.pathname === "/health") {
		res.setHeader("content-type", "application/json");
		res.end(
			JSON.stringify({
				ok: true,
				app: "sample-b2b",
				runtime: "clearance-auth",
				database: "postgres",
			}),
		);
		return;
	}

	if (url.pathname.startsWith("/api/auth")) {
		const headers = new Headers();
		for (const [key, value] of Object.entries(req.headers)) {
			if (value !== undefined) {
				headers.set(key, Array.isArray(value) ? value.join(",") : value);
			}
		}
		const response = await bundle.auth.handler(
			new Request(new URL(req.url ?? "/", baseURL), {
				method: req.method,
				headers,
				body: requestBody ? new Uint8Array(requestBody) : undefined,
			}),
		);
		return forwardAuthResponse(response, res);
	}

	if (url.pathname === "/sign-up" && req.method === "GET") {
		res.setHeader("content-type", "text/html");
		res.end(
			html(`<h1>Create account</h1>
      <form id="f">
        <label>Name</label><input name="name" required />
        <label>Email</label><input name="email" type="email" required />
        <label>Password</label><input name="password" type="password" minlength="8" required />
        <button type="submit">Sign up</button>
      </form>
      <p><a href="/sign-in">Already have an account?</a></p>
      <script>
        document.getElementById('f').addEventListener('submit', async (e) => {
          e.preventDefault();
          const fd = new FormData(e.target);
          const body = Object.fromEntries(fd.entries());
          const r = await fetch('/api/auth/sign-up/email', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
            credentials: 'include',
          });
          if (r.ok) location.href = '/dashboard';
          else { document.body.insertAdjacentHTML('beforeend', '<p class="err">Sign-up failed</p>'); }
        });
      </script>`),
		);
		return;
	}

	if (url.pathname === "/sign-in" && req.method === "GET") {
		res.setHeader("content-type", "text/html");
		res.end(
			html(`<h1>Sign in</h1>
      <form id="f">
        <label>Email</label><input name="email" type="email" required />
        <label>Password</label><input name="password" type="password" required />
        <button type="submit">Sign in</button>
      </form>
	  ${socialSignInMarkup(enabledSocialProviders)}
      <p><a href="/sign-up">Create account</a></p>
      <script>
		async function socialSignIn(provider) {
		  const r = await fetch('/api/auth/sign-in/social', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ provider, callbackURL: '/dashboard' }),
			credentials: 'include',
		  });
		  const payload = await r.json().catch(() => ({}));
		  let redirect;
		  try { redirect = new URL(payload.url, window.location.origin); } catch {}
		  const current = new URL(window.location.origin);
		  const allowed = redirect && (
			redirect.protocol === 'https:' ||
			(redirect.protocol === 'http:' && current.protocol === 'http:' && (
			  redirect.origin === current.origin ||
			  redirect.hostname === 'localhost' ||
			  redirect.hostname === '127.0.0.1' ||
			  redirect.hostname === '[::1]'
			))
		  );
		  if (r.ok && allowed) location.assign(redirect.href);
		  else document.body.insertAdjacentHTML('beforeend', '<p class="err">Social sign-in failed</p>');
		}
        document.getElementById('f').addEventListener('submit', async (e) => {
          e.preventDefault();
          const fd = new FormData(e.target);
          const body = Object.fromEntries(fd.entries());
          const r = await fetch('/api/auth/sign-in/email', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
            credentials: 'include',
          });
          if (r.ok) location.href = '/dashboard';
          else document.body.insertAdjacentHTML('beforeend', '<p class="err">Invalid credentials</p>');
        });
      </script>`),
		);
		return;
	}

	if (url.pathname === "/dashboard") {
		const session = await getSession(req);
		const safe = session ? toSafeSessionView(session) : null;
		if (!safe) {
			res.statusCode = 302;
			res.setHeader("Location", "/sign-in");
			res.end();
			return;
		}
		const user = safe.user;
		let orgNames = "";
		let runtimeOrganizations: Array<{
			id: string;
			name: string;
			slug: string;
			createdAt?: string | Date;
		}> = [];
		try {
			const headers = new Headers({
				cookie: req.headers.cookie ?? "",
				origin: baseURL,
			});
			const list = await bundle.auth.api.listOrganizations({ headers });
			const orgs =
				(list as Array<{
					id: string;
					name: string;
					slug: string;
					createdAt?: string | Date;
				}>) ?? [];
			if (orgs.length === 0) {
				await bundle.auth.api.createOrganization({
					body: {
						name: `${user.name}'s Workspace`,
						slug: `ws-${user.id.slice(0, 8).toLowerCase()}`,
					},
					headers,
				});
				const again = await bundle.auth.api.listOrganizations({ headers });
				runtimeOrganizations =
					(again as typeof runtimeOrganizations) ?? [];
			} else {
				runtimeOrganizations = orgs;
			}
			orgNames = runtimeOrganizations.map((o) => o.name).join(", ");
		} catch {
			orgNames = "(org plugin)";
		}

		const managementStore = await getManagementStore();
		for (const organization of runtimeOrganizations) {
			await syncRuntimeOrganizationToManagementDurable(
				managementStore,
				organization,
				user.id,
				{ actor: user.email, role: "owner" },
			);
		}
		recordEvent(managementStore, {
			actor: user.email,
			action: "auth.dashboard_view",
			subjectType: "session",
			subjectId: safe.session.id,
			outcome: "success",
			source: "system",
			message: "Protected dashboard accessed",
		});
		await managementStore.ready();

		res.setHeader("content-type", "text/html; charset=utf-8");
		res.end(
			html(
				`<h1>Protected dashboard</h1>
        <p>Signed in as <strong>${escapeHtml(user.name)}</strong> (${escapeHtml(user.email)})</p>
        <p>User id: <code>${escapeHtml(user.id)}</code></p>
        <p>Session: <code>${escapeHtml(safe.session.id)}</code> (active)</p>
        <p>Organizations: ${escapeHtml(orgNames || "none")}</p>
        <p data-testid="protected-ok">Access granted — real Clearance session (Postgres).</p>
        <p><a href="/api/me">JSON /api/me</a></p>
		<form method="post" action="/sign-out"><button type="submit">Sign out</button></form>`,
				"Dashboard",
			),
		);
		return;
	}

	if (url.pathname === "/api/me" || url.pathname === "/api/session") {
		const session = await getSession(req);
		res.setHeader("content-type", "application/json; charset=utf-8");
		const safe = session ? toSafeSessionView(session) : null;
		if (!safe) {
			res.statusCode = 401;
			res.end(JSON.stringify({ error: "unauthorized" }));
			return;
		}
		// Never include raw bearer/session token credentials
		res.end(
			JSON.stringify({
				ok: true,
				protected: true,
				runtime: "clearance-auth",
				user: safe.user,
				session: safe.session,
			}),
		);
		return;
	}

	if (url.pathname === "/sign-out") {
		if (req.method !== "POST") {
			res.statusCode = 405;
			res.setHeader("Allow", "POST");
			res.end("Method not allowed");
			return;
		}
		const mutationOrigin = sameOriginMutationOrigin(
			typeof req.headers.origin === "string" ? req.headers.origin : undefined,
			typeof req.headers.referer === "string" ? req.headers.referer : undefined,
			baseURL,
		);
		if (!mutationOrigin) {
			res.statusCode = 403;
			res.setHeader("content-type", "application/json; charset=utf-8");
			res.end(JSON.stringify({ error: "same-origin sign-out required" }));
			return;
		}
		const authResponse = await bundle.auth.handler(
			new Request(`${baseURL}/api/auth/sign-out`, {
				method: "POST",
				headers: {
					cookie: req.headers.cookie ?? "",
					origin: mutationOrigin,
					"content-type": "application/json",
				},
				body: "{}",
			}),
		);
		const cookies = getSetCookieValues(authResponse.headers);
		if (cookies.length > 0) res.setHeader("Set-Cookie", cookies);
		if (!authResponse.ok) {
			res.statusCode = authResponse.status;
			res.setHeader(
				"content-type",
				authResponse.headers.get("content-type") ?? "application/json; charset=utf-8",
			);
			res.end(await authResponse.text());
			return;
		}
		res.statusCode = 302;
		res.setHeader("Location", "/sign-in");
		res.end();
		return;
	}

	if (url.pathname === "/") {
		res.statusCode = 302;
		res.setHeader("Location", "/sign-in");
		res.end();
		return;
	}

	res.statusCode = 404;
	res.end("Not found");
}

export function createSampleRequestHandler(
	limit = maxRequestBodyBytes,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
	return async (req, res) => {
		try {
			const body = await readBoundedRequestBody(req, limit);
			await routeRequest(req, res, body);
		} catch (error) {
			if (error instanceof RequestBodyTooLargeError) {
				payloadTooLarge(req, res, error.limit);
				return;
			}
			throw error;
		}
	};
}

const handler = createSampleRequestHandler();

async function main() {
	await Promise.all([bundle.migrate(), getManagementStore()]);
	createServer(handler).listen(port, () => {
		console.log(
			`sample-b2b http://localhost:${port} (postgres runtime @clearance/auth)`,
		);
	});
}

const isMain =
	process.argv[1] &&
	(process.argv[1].endsWith("server.ts") || process.argv[1].endsWith("server.js"));
if (isMain) {
	main().catch((e) => {
		console.error(e);
		process.exit(1);
	});
}

export { bundle, getManagementStore, getSession, handler, html };
