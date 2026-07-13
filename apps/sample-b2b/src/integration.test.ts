/**
 * Integration: boots the REAL sample app server (src/server.ts handler +
 * @clearance/auth runtime) against a disposable Postgres container and
 * exercises the advertised login e2e surface:
 *
 *   sign-up -> sign-in -> /dashboard (200, "Access granted", org auto-created)
 *   /dashboard without cookie -> 302, /api/me with cookie -> protected:true
 *
 * Gate: replicates the pg-gate tripwire posture from
 * packages/management/src/__tests__/pg-gate.ts inline (cross-package import
 * is not possible): without Docker the suite skips cleanly, but when
 * CLEARANCE_REQUIRE_PG_TESTS=1 (canonical gate) an unavailable Docker THROWS
 * instead of skipping. The container uses an ephemeral host port and a
 * pid-unique name, and is removed in afterAll, so it cannot interfere with
 * other suites or a concurrently running stack.
 */
import { execSync } from "node:child_process";
import { createServer, type Server } from "node:http";
import { createServer as createNetServer } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CONTAINER = `clearance-sample-b2b-it-${process.pid}`;
const PG_USER = "clearance";
const PG_DB = "clearance";

function dockerAvailable(): boolean {
	try {
		execSync("docker info", { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
}

const available = dockerAvailable();
if (!available && process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") {
	throw new Error(
		"sample-b2b integration: CLEARANCE_REQUIRE_PG_TESTS=1 but Docker is unavailable. " +
			"The integration suite must run, not skip, under the canonical gate — start Docker " +
			"or unset CLEARANCE_REQUIRE_PG_TESTS.",
	);
}

function getFreePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const probe = createNetServer();
		probe.listen(0, "127.0.0.1", () => {
			const addr = probe.address();
			const port = typeof addr === "object" && addr ? addr.port : 0;
			probe.close(() => resolve(port));
		});
		probe.on("error", reject);
	});
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/** First cookie pairs from a fetch Response's Set-Cookie headers. */
function cookiesFrom(res: Response): string {
	const raw = res.headers.getSetCookie?.() ?? [];
	return raw.map((c) => c.split(";")[0]).join("; ");
}

describe.skipIf(!available)(
	"sample-b2b login e2e against disposable Postgres (requires docker)",
	() => {
		let server: Server | undefined;
		let baseURL = "";
		let mod: typeof import("./server.js") | undefined;

		const email = `it-${Date.now()}-${process.pid}@example.test`;
		const password = "Integration!Passw0rd42";
		let cookie = "";

		beforeAll(async () => {
			// Self-heal a stale container from a killed prior run, then boot a
			// fresh disposable Postgres on an ephemeral 127.0.0.1 port.
			execSync(`docker rm -f ${CONTAINER} >/dev/null 2>&1 || true`);
			execSync(
				`docker run -d --rm --name ${CONTAINER} ` +
					`-e POSTGRES_USER=${PG_USER} -e POSTGRES_PASSWORD=${PG_USER} -e POSTGRES_DB=${PG_DB} ` +
					"-p 127.0.0.1::5432 postgres:16-alpine",
				{ stdio: "ignore" },
			);
			const portLine = execSync(`docker port ${CONTAINER} 5432/tcp`, {
				encoding: "utf8",
			})
				.trim()
				.split("\n")[0];
			const pgPort = Number(portLine.split(":").pop());
			if (!Number.isInteger(pgPort) || pgPort <= 0) {
				throw new Error(`could not resolve ephemeral container port (${portLine})`);
			}

			// Wait for Postgres over TCP; require two consecutive successes so
			// initdb's temporary bootstrap server cannot fake readiness.
			let ready = 0;
			for (let i = 0; i < 120 && ready < 2; i++) {
				try {
					execSync(
						`docker exec ${CONTAINER} psql -h 127.0.0.1 -U ${PG_USER} -d ${PG_DB} -Atc "select 1"`,
						{ stdio: "ignore" },
					);
					ready += 1;
				} catch {
					ready = 0;
				}
				await sleep(500);
			}
			if (ready < 2) throw new Error("disposable postgres did not become ready");

			// server.ts reads its configuration from the environment at import
			// time, so set env BEFORE the dynamic import.
			const appPort = await getFreePort();
			baseURL = `http://127.0.0.1:${appPort}`;
			process.env.DATABASE_URL = `postgres://${PG_USER}:${PG_USER}@127.0.0.1:${pgPort}/${PG_DB}`;
			process.env.CLEARANCE_SECRET = "sample-b2b-integration-secret-32chars!!";
			process.env.SAMPLE_APP_PORT = String(appPort);
			process.env.CLEARANCE_BASE_URL = baseURL;
			// A half-configured social pair in the caller's env would fail startup.
			delete process.env.CLEARANCE_GITHUB_CLIENT_ID;
			delete process.env.CLEARANCE_GITHUB_CLIENT_SECRET;
			delete process.env.CLEARANCE_GOOGLE_CLIENT_ID;
			delete process.env.CLEARANCE_GOOGLE_CLIENT_SECRET;

			mod = await import("./server.js");
			await mod.bundle.migrate();
			server = createServer(mod.handler);
			await new Promise<void>((resolve, reject) => {
				server!.listen(appPort, "127.0.0.1", () => resolve());
				server!.on("error", reject);
			});
		}, 180_000);

		afterAll(async () => {
			try {
				if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
				if (mod) {
					// End both pg pools while Postgres is still available. Stopping the
					// container first emits a late FATAL error from otherwise-idle clients,
					// which Vitest correctly treats as an unhandled teardown failure.
					try {
						const store = (await mod.getManagementStore()) as {
							destroy?: () => Promise<void>;
						};
						await store.destroy?.();
					} catch {
						// store may never have been created; teardown must not fail the suite
					}
					await mod.bundle.destroy().catch(() => undefined);
				}
			} finally {
				execSync(`docker rm -f ${CONTAINER} >/dev/null 2>&1 || true`);
			}
		}, 60_000);

		it("signs up via POST /api/auth/sign-up/email", async () => {
			const res = await fetch(`${baseURL}/api/auth/sign-up/email`, {
				method: "POST",
				headers: { "content-type": "application/json", origin: baseURL },
				body: JSON.stringify({ name: "Integration Tester", email, password }),
			});
			expect(res.status).toBeLessThan(300);
			const body = (await res.json()) as { user?: { email?: string } };
			expect(body.user?.email).toBe(email);
		}, 30_000);

		it("signs in via POST /api/auth/sign-in/email and receives a session cookie", async () => {
			const res = await fetch(`${baseURL}/api/auth/sign-in/email`, {
				method: "POST",
				headers: { "content-type": "application/json", origin: baseURL },
				body: JSON.stringify({ email, password }),
			});
			expect(res.status).toBe(200);
			cookie = cookiesFrom(res);
			expect(cookie).toMatch(/session_token/);
		}, 30_000);

		it("GET /dashboard without a cookie redirects to sign-in (302)", async () => {
			const res = await fetch(`${baseURL}/dashboard`, { redirect: "manual" });
			expect(res.status).toBe(302);
			expect(res.headers.get("location")).toBe("/sign-in");
		}, 30_000);

		it("GET /dashboard with the session cookie returns 200 'Access granted' and auto-creates an organization", async () => {
			const res = await fetch(`${baseURL}/dashboard`, { headers: { cookie } });
			expect(res.status).toBe(200);
			const html = await res.text();
			expect(html).toContain("Access granted");
			// First authenticated dashboard load auto-creates "<name>'s Workspace"
			expect(html).toContain("Workspace");
			// Assert org auto-creation through the runtime API with the same session
			const orgs = (await mod!.bundle.auth.api.listOrganizations({
				headers: new Headers({ cookie, origin: baseURL }),
			})) as Array<{ name: string }>;
			expect(Array.isArray(orgs)).toBe(true);
			expect(orgs.length).toBeGreaterThanOrEqual(1);
			expect(orgs.some((o) => o.name.includes("Workspace"))).toBe(true);
		}, 30_000);

		it("GET /api/me with the session cookie reports protected:true without raw credentials", async () => {
			const res = await fetch(`${baseURL}/api/me`, { headers: { cookie } });
			expect(res.status).toBe(200);
			const body = (await res.json()) as {
				protected?: boolean;
				user?: { email?: string };
				session?: Record<string, unknown>;
			};
			expect(body.protected).toBe(true);
			expect(body.user?.email).toBe(email);
			expect(body.session?.token).toBeUndefined();
		}, 30_000);

		it("GET /api/me without a cookie is 401", async () => {
			const res = await fetch(`${baseURL}/api/me`);
			expect(res.status).toBe(401);
		}, 30_000);

		it("signs out through POST and forwards the runtime cookie expiration", async () => {
			const get = await fetch(`${baseURL}/sign-out`, { redirect: "manual" });
			expect(get.status).toBe(405);
			expect(get.headers.get("allow")).toBe("POST");
			const missingOrigin = await fetch(`${baseURL}/sign-out`, {
				method: "POST",
				headers: { cookie },
				redirect: "manual",
			});
			expect(missingOrigin.status).toBe(403);
			const crossOrigin = await fetch(`${baseURL}/sign-out`, {
				method: "POST",
				headers: { cookie, origin: "https://evil.example" },
				redirect: "manual",
			});
			expect(crossOrigin.status).toBe(403);

			const signOut = await fetch(`${baseURL}/sign-out`, {
				method: "POST",
				headers: { cookie, origin: baseURL },
				redirect: "manual",
			});
			expect(signOut.status).toBe(302);
			expect(signOut.headers.get("location")).toBe("/sign-in");
			const expired = signOut.headers.getSetCookie();
			expect(expired.some((value) => value.includes("session_token="))).toBe(true);
			expect(
				expired.some(
					(value) => value.includes("Max-Age=0") || value.includes("Expires="),
				),
			).toBe(true);

			const after = await fetch(`${baseURL}/api/me`, { headers: { cookie } });
			expect(after.status).toBe(401);
		}, 30_000);
	},
);
