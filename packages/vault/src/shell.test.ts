import { afterEach, describe, expect, it, vi } from "vitest";
import { mountClearanceVault } from "./shell";
import { VAULT_WORKFLOWS } from "./workflows";

function json(value: unknown, status = 200): Response {
	return new Response(JSON.stringify(value), {
		status,
		headers: { "content-type": "application/json" },
	});
}

async function settle(): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, 0));
	await new Promise((resolve) => setTimeout(resolve, 0));
}

function setInput(root: HTMLElement, id: string, value: string): void {
	const input = root.querySelector<HTMLInputElement>(`#${id}`);
	if (!input) throw new Error(`Missing ${id}`);
	input.value = value;
	input.dispatchEvent(new Event("input", { bubbles: true }));
}

afterEach(() => {
	document.body.replaceChildren();
	window.history.replaceState(null, "", "/");
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("Clearance Vault shell", () => {
	it("renders a validated hosted logo without replacing the home label", async () => {
		const root = document.createElement("div");
		document.body.append(root);
		vi.stubGlobal("fetch", async () => json(null));
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
			branding: {
				productName: "Acme <Auth>",
				homeLabel: "Acme Vault",
				logoUrl: "https://assets.example.test/brand/logo.svg",
			},
		});
		await settle();
		const logo = root.querySelector<HTMLImageElement>("img.cv-brand-logo");
		expect(logo?.src).toBe("https://assets.example.test/brand/logo.svg");
		expect(logo?.alt).toBe("Acme <Auth> logo");
		expect(root.querySelector(".cv-brand")?.textContent).toBe("Acme Vault");
		mount.destroy();
	});

	it("rejects hostile hosted-logo URLs while allowing development loopback HTTP", () => {
		const hostileUrls = [
			"data:image/svg+xml,<svg/>",
			"javascript:alert(1)",
			"https://user:password@assets.example.test/logo.svg",
			"https://assets.example.test/logo.svg#fragment",
			"http://assets.example.test/logo.svg",
		];
		for (const logoUrl of hostileUrls) {
			const root = document.createElement("div");
			document.body.append(root);
			expect(() =>
				mountClearanceVault(root, {
					authBaseURL: "http://localhost:3000/api/auth",
					branding: { logoUrl },
				}),
			).toThrow(/branding\.logoUrl/);
		}

		const root = document.createElement("div");
		document.body.append(root);
		vi.stubGlobal("fetch", async () => json(null));
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
			branding: { logoUrl: "http://127.0.0.1:4173/logo.svg" },
		});
		expect(root.querySelector<HTMLImageElement>("img.cv-brand-logo")?.src).toBe(
			"http://127.0.0.1:4173/logo.svg",
		);
		mount.destroy();
	});

	it("exposes closed workflow navigation with focus and live-region semantics", async () => {
		const root = document.createElement("div");
		document.body.append(root);
		vi.stubGlobal("fetch", async () => json(null));
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});
		await settle();

		const routes = [
			...root.querySelectorAll<HTMLButtonElement>("[data-route]"),
		].map((control) => control.dataset.route);
		expect(routes).toEqual(VAULT_WORKFLOWS.map((item) => item.id));
		const account = root.querySelector<HTMLButtonElement>(
			'[data-route="account"]',
		);
		account?.click();
		expect(root.querySelector("h1")?.textContent).toBe("Account security");
		expect(
			root
				.querySelector<HTMLButtonElement>('[data-route="account"]')
				?.getAttribute("aria-current"),
		).toBe("page");
		expect(document.activeElement).toBe(root.querySelector(".cv-main"));
		expect(root.querySelector('[role="status"]')).not.toBeNull();
		expect(root.textContent).toContain("Sign in required");

		mount.destroy();
		expect(root.childNodes).toHaveLength(0);
	});

	it("shows a service credential once and erases it on dismiss", async () => {
		const storageWrite = vi.spyOn(Storage.prototype, "setItem");
		const requests: Array<{ url: string; body?: Record<string, unknown> }> = [];
		const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			const body =
				typeof init?.body === "string"
					? (JSON.parse(init.body) as Record<string, unknown>)
					: undefined;
			requests.push({ url, ...(body ? { body } : {}) });
			if (url.endsWith("/get-session")) {
				return json({
					user: { id: "user_1", email: "owner@example.test" },
					session: {
						id: "session_1",
						userId: "user_1",
						activeOrganizationId: "org_1",
					},
				});
			}
			if (
				url.endsWith(
					"/tenant/v1/organizations/org_1/service-accounts",
				) &&
				init?.method === "GET"
			) {
				return json([]);
			}
			if (
				url.endsWith(
					"/tenant/v1/organizations/org_1/authorization/roles",
				)
			) {
				return json([]);
			}
			if (url.endsWith("/service-accounts/svc_1/credentials")) {
				if (body?.dryRun === true) {
					return json({
						preview: true,
						organizationId: "org_1",
						serviceAccountId: "svc_1",
						expiresAt: null,
						secretGenerated: false,
					});
				}
				return json({
					credential: {
						organizationId: "org_1",
						serviceAccountId: "svc_1",
						credentialId: "cred_1",
						credentialPrefix: "clr",
						credentialFingerprint: "fingerprint",
						expiresAt: null,
						version: 1,
					},
					secret: "clearance_once_only",
					previousRevision: "1",
					revision: "2",
				});
			}
			throw new Error(`Unexpected request: ${url}`);
		});
		const root = document.createElement("div");
		document.body.append(root);
		vi.stubGlobal("fetch", fetcher);
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
			initialRoute: "service-accounts",
		});
		await settle();

		const serviceId = root.querySelector<HTMLInputElement>(
			"#cv-credential-service",
		);
		expect(serviceId).not.toBeNull();
		serviceId!.value = "svc_1";
		const create = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
			(control) => control.textContent === "Create credential",
		);
		create?.click();
		await settle();
		expect(root.textContent).toContain("Create credential?");
		expect(root.querySelector(".cv-skip")?.getAttribute("aria-hidden")).toBe("true");
		expect((root.querySelector(".cv-skip") as HTMLElement).inert).toBe(true);
		const confirm = [
			...root.querySelectorAll<HTMLButtonElement>("button"),
		].find((control) => control.textContent === "Create credential");
		confirm?.click();
		await settle();

		expect(root.textContent).toContain("clearance_once_only");
		expect(document.activeElement).toBe(
			root.querySelector('[role="region"][aria-label="One-time credential"]'),
		);
		expect(storageWrite).not.toHaveBeenCalled();
		const dismiss = [
			...root.querySelectorAll<HTMLButtonElement>("button"),
		].find((control) => control.textContent?.includes("dismiss"));
		dismiss?.click();
		expect(root.textContent).not.toContain("clearance_once_only");
		expect(
			requests.filter((request) =>
				request.url.endsWith("/service-accounts/svc_1/credentials"),
			).map((request) => request.body),
		).toEqual([
			{ dryRun: true },
			expect.objectContaining({
				dryRun: false,
				operationId: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/),
			}),
		]);

		mount.destroy();
	});

	it("clears account secrets across sign-out and focuses their disclosure", async () => {
		const fetcher = vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.endsWith("/get-session")) {
				return json({
					user: {
						id: "user_1",
						email: "owner@example.test",
						twoFactorEnabled: false,
					},
					session: { id: "session_1", userId: "user_1" },
				});
			}
			if (url.endsWith("/passkey/list")) return json([]);
			if (url.endsWith("/list-sessions")) return json([]);
			if (url.endsWith("/two-factor/enable")) {
				return json({
					totpURI: "otpauth://totp/Clearance:owner",
					backupCodes: ["backup-once"],
				});
			}
			if (url.endsWith("/sign-out")) return json({ status: true });
			throw new Error(`Unexpected request: ${url}`);
		});
		vi.stubGlobal("fetch", fetcher);
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
			initialRoute: "account",
		});
		await settle();

		const password = root.querySelector<HTMLInputElement>("#cv-factor-password");
		expect(password).not.toBeNull();
		password!.value = "correct horse battery staple";
		const setup = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
			(control) => control.textContent === "Set up TOTP",
		);
		setup?.click();
		await settle();
		expect(root.textContent).toContain("backup-once");
		expect(document.activeElement).toBe(
			root.querySelector(
				'[role="region"][aria-label="TOTP setup and recovery codes"]',
			),
		);

		const revokeOthers = [
			...root.querySelectorAll<HTMLButtonElement>("button"),
		].find((control) => control.textContent === "Revoke other sessions");
		revokeOthers?.focus();
		revokeOthers?.click();
		expect(root.textContent).not.toContain("backup-once");
		expect(root.querySelector('[role="alertdialog"]')).not.toBeNull();
		const cancel = [
			...root.querySelectorAll<HTMLButtonElement>("button"),
		].find((control) => control.textContent === "Cancel");
		cancel?.click();
		expect(document.activeElement?.textContent).toBe("Revoke other sessions");

		const signOut = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
			(control) => control.textContent === "Sign out",
		);
		signOut?.click();
		await settle();
		expect(root.querySelector("h1")?.textContent).toBe("Sign in");
		expect(root.textContent).not.toContain("backup-once");
		expect(root.textContent).not.toContain("otpauth://");
		mount.destroy();
	});

	it("consumes recovery callback tokens from the URL before submitting them", async () => {
		window.history.replaceState(
			{ hostState: true },
			"",
			"/vault?clearance_recovery=1&clearance_recovery_token=recovery-once",
		);
		const bodies: Record<string, unknown>[] = [];
		vi.stubGlobal(
			"fetch",
			async (input: RequestInfo | URL, init?: RequestInit) => {
				const url = String(input);
				if (url.endsWith("/get-session")) return json(null);
				if (url.endsWith("/reset-password")) {
					bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
					return json({ status: true });
				}
				throw new Error(`Unexpected request: ${url}`);
			},
		);
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});
		expect(window.location.search).toBe("");
		expect(window.history.state).toEqual({ hostState: true });
		await settle();
		expect(
			root.querySelector<HTMLInputElement>("#cv-recovery-token")?.value,
		).toBe("recovery-once");
		const password = root.querySelector<HTMLInputElement>(
			"#cv-recovery-new-password",
		);
		password!.value = "replacement password";
		const submit = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
			(control) => control.textContent === "Set new password",
		);
		submit?.click();
		await settle();
		expect(bodies).toEqual([
			{ token: "recovery-once", newPassword: "replacement password" },
		]);
		expect(root.textContent).not.toContain("recovery-once");
		mount.destroy();
	});

	it("rejects passkey options for an unexpected relying-party ID before invoking WebAuthn", async () => {
		vi.stubGlobal("PublicKeyCredential", class PublicKeyCredential {});
		const get = vi.fn();
		vi.stubGlobal("navigator", { credentials: { get } });
		vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.endsWith("/get-session")) return json(null);
			if (url.endsWith("/passkey/generate-authentication-options")) {
				return json({ rpId: "attacker.example.test", challenge: "AA", timeout: 1, userVerification: "required" });
			}
			throw new Error(`Unexpected request: ${url}`);
		});
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
			passkeyRpId: "expected.example.test",
		});
		await settle();
		[...root.querySelectorAll<HTMLButtonElement>("button")]
			.find((control) => control.textContent === "Sign in with a passkey")
			?.click();
		await settle();
		expect(get).not.toHaveBeenCalled();
		expect(root.textContent).toContain("unexpected relying party");
		mount.destroy();
	});

	it("clears the authenticated shell when invitation loading returns 401", async () => {
		vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.endsWith("/get-session")) {
				return json({
					user: { id: "user_1", email: "owner@example.test" },
					session: { id: "session_1", userId: "user_1", activeOrganizationId: "org_1" },
				});
			}
			if (url.endsWith("/organization/list-user-invitations")) return json({ error: "expired" }, 401);
			if (url.endsWith("/organization/list-invitations?organizationId=org_1")) return json([], 403);
			throw new Error(`Unexpected request: ${url}`);
		});
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
			initialRoute: "invitations",
		});
		await settle();
		expect(root.textContent).toContain("Sign in required");
		expect(root.textContent).toContain("session expired");
		mount.destroy();
	});

	it("shows the first-organization form and installs the confirmed active organization", async () => {
		const requests: Array<{ url: string; body?: unknown }> = [];
		let sessionReads = 0;
		let organizationReads = 0;
		vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			requests.push({
				url,
				...(init?.body ? { body: JSON.parse(String(init.body)) } : {}),
			});
			if (url.endsWith("/get-session")) {
				sessionReads += 1;
				return json({
					user: { id: "user_1", email: "owner@example.test" },
					session: {
						id: "session_1",
						userId: "user_1",
						...(sessionReads > 1 ? { activeOrganizationId: "org_1" } : {}),
					},
				});
			}
			if (url.endsWith("/organization/list")) {
				organizationReads += 1;
				return json(
					organizationReads > 1
						? [{ id: "org_1", name: "Acme", slug: "acme" }]
						: [],
				);
			}
			if (url.endsWith("/organization/create")) {
				return json({ id: "org_1", name: "Acme", slug: "acme" });
			}
			throw new Error(`Unexpected request: ${url}`);
		});
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
			initialRoute: "organizations",
		});
		await settle();
		expect(root.textContent).toContain("No organizations yet. Create your first organization.");
		expect(root.querySelector("#cv-organization-name")).not.toBeNull();
		expect(root.querySelector("#cv-organization-slug")).not.toBeNull();

		setInput(root, "cv-organization-name", "Acme");
		setInput(root, "cv-organization-slug", "acme");
		[...root.querySelectorAll<HTMLButtonElement>("button")]
			.find((control) => control.textContent === "Create organization")?.click();
		await settle();

		expect(
			requests.find((request) => request.url.endsWith("/organization/create"))?.body,
		).toEqual({ name: "Acme", slug: "acme" });
		expect(root.textContent).toContain("Organization Acme created and active.");
		expect(root.textContent).toContain("Acme (active)");
		expect(root.querySelector<HTMLInputElement>("#cv-organization-name")?.value).toBe("");
		expect(root.querySelector<HTMLInputElement>("#cv-organization-slug")?.value).toBe("");
		mount.destroy();
	});

	it("keeps invalid organization input without posting", async () => {
		vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.endsWith("/get-session")) {
				return json({ user: { id: "user_1", email: "owner@example.test" }, session: { id: "session_1", userId: "user_1" } });
			}
			if (url.endsWith("/organization/list")) return json([]);
			throw new Error(`Unexpected request: ${url}`);
		});
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, { authBaseURL: "http://localhost:3000/api/auth", development: true, initialRoute: "organizations" });
		await settle();
		setInput(root, "cv-organization-name", " Acme");
		setInput(root, "cv-organization-slug", "acme--team");
		[...root.querySelectorAll<HTMLButtonElement>("button")]
			.find((control) => control.textContent === "Create organization")?.click();
		await settle();
		expect(root.textContent).toContain("Organization name must be trimmed");
		expect(root.querySelector<HTMLInputElement>("#cv-organization-name")?.value).toBe(" Acme");
		expect(root.querySelector<HTMLInputElement>("#cv-organization-slug")?.value).toBe("acme--team");
		mount.destroy();
	});

	it("keeps input after a slug conflict and reconciles an ambiguous creation response", async () => {
		let phase: "conflict" | "ambiguous" = "conflict";
		let sessionReads = 0;
		let organizationReads = 0;
		vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.endsWith("/get-session")) {
				sessionReads += 1;
				return json({
					user: { id: "user_1", email: "owner@example.test" },
					session: {
						id: "session_1",
						userId: "user_1",
						...(phase === "ambiguous" && sessionReads > 1
							? { activeOrganizationId: "org_1" }
							: {}),
					},
				});
			}
			if (url.endsWith("/organization/list")) {
				organizationReads += 1;
				return json(
					phase === "ambiguous" && organizationReads > 1
						? [{ id: "org_1", name: "Acme", slug: "acme" }]
						: [],
				);
			}
			if (url.endsWith("/organization/create")) {
				if (phase === "conflict") return json({ error: { code: "SLUG_CONFLICT" } }, 409);
				throw new TypeError("connection dropped after submission");
			}
			throw new Error(`Unexpected request: ${url}`);
		});
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, { authBaseURL: "http://localhost:3000/api/auth", development: true, initialRoute: "organizations" });
		await settle();
		setInput(root, "cv-organization-name", "Acme");
		setInput(root, "cv-organization-slug", "acme");
		const submit = () => [...root.querySelectorAll<HTMLButtonElement>("button")]
			.find((control) => control.textContent === "Create organization")?.click();
		submit();
		await settle();
		expect(root.textContent).toContain("Request failed with status 409");
		expect(root.querySelector<HTMLInputElement>("#cv-organization-name")?.value).toBe("Acme");

		phase = "ambiguous";
		submit();
		await settle();
		expect(root.textContent).toContain("Organization Acme created and active.");
		expect(root.textContent).toContain("Acme (active)");
		expect(root.querySelector<HTMLInputElement>("#cv-organization-slug")?.value).toBe("");
		mount.destroy();
	});

	it("ignores stale completions after navigation and keeps the active request busy", async () => {
		let resolveSession!: (response: Response) => void;
		let resolveOrganizations!: (response: Response) => void;
		const sessionResponse = new Promise<Response>((resolve) => {
			resolveSession = resolve;
		});
		const organizationResponse = new Promise<Response>((resolve) => {
			resolveOrganizations = resolve;
		});
		vi.stubGlobal("fetch", (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.endsWith("/get-session")) return sessionResponse;
			if (url.endsWith("/organization/list")) return organizationResponse;
			throw new Error(`Unexpected request: ${url}`);
		});
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});

		mount.navigate("organizations");
		resolveSession(
			json({
				user: { id: "stale_user", email: "stale@example.test" },
				session: { id: "stale_session", userId: "stale_user" },
			}),
		);
		await settle();
		expect(
			[...root.querySelectorAll<HTMLButtonElement>("button")].every(
				(control) => control.disabled,
			),
		).toBe(true);
		expect(root.textContent).not.toContain("stale@example.test");

		resolveOrganizations(json([]));
		await settle();
		expect(root.textContent).toContain("Sign in required");
		expect(
			[...root.querySelectorAll<HTMLButtonElement>("button")].some(
				(control) => !control.disabled,
			),
		).toBe(true);
		mount.destroy();
	});

	it("uses native tenant audit and enterprise readiness routes without global endpoints", async () => {
		const urls: string[] = [];
		vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			urls.push(url);
			if (url.endsWith("/get-session")) {
				return json({ user: { id: "user_1", email: "owner@example.test" }, session: { id: "session_1", userId: "user_1", activeOrganizationId: "org_1" } });
			}
			if (url.endsWith("/tenant/v1/organizations/org_1/audit?limit=25")) {
				return json({ events: [{ id: "audit_1", correlationId: "correlation_1", action: "sso.tested", outcome: "success", source: "sso", message: "redacted event", createdAt: "2026-07-24T00:00:00.000Z" }], nextCursor: null });
			}
			if (url.endsWith("/tenant/v1/organizations/org_1/enterprise/sso")) return json({ connections: [] });
			if (url.endsWith("/tenant/v1/organizations/org_1/enterprise/scim")) return json({ connections: [] });
			if (url.endsWith("/tenant/v1/organizations/org_1/enterprise/readiness")) return json({ report: { status: "ready" } });
			throw new Error(`Unexpected request: ${url} ${init?.method ?? "GET"}`);
		});
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, { authBaseURL: "http://localhost:3000/api/auth", development: true, initialRoute: "audit" });
		await settle();
		expect(root.textContent).toContain("Redacted tenant audit events");
		expect(root.textContent).toContain("sso.tested");
		mount.navigate("enterprise");
		await settle();
		expect(root.textContent).toContain("Enterprise readiness");
		expect(urls.some((url) => url.includes("/sso/providers") || url.includes("/scim/list-provider-connections"))).toBe(false);
		expect(urls.filter((url) => url.includes("/tenant/v1/organizations/org_1/"))).not.toHaveLength(0);
		mount.destroy();
	});

	it("uses one canonical operation ID for each confirmed live secret operation and reuses it on retry", async () => {
		const requests: Array<{ url: string; body?: Record<string, unknown> }> = [];
		const operationIds = [
			"018f0f51-74a3-7eab-8f8b-8a4db4f3f6c1",
			"018f0f51-74a3-7eab-8f8b-8a4db4f3f6c2",
			"018f0f51-74a3-7eab-8f8b-8a4db4f3f6c3",
		];
		const randomUUID = vi.fn(() => operationIds.shift()!);
		vi.stubGlobal("crypto", { randomUUID });
		let replacementAttempts = 0;
		vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			const body = typeof init?.body === "string"
				? JSON.parse(init.body) as Record<string, unknown>
				: undefined;
			requests.push({ url, ...(body ? { body } : {}) });
			if (url.endsWith("/get-session")) {
				return json({
					user: { id: "user_1", email: "owner@example.test" },
					session: { id: "session_1", userId: "user_1", activeOrganizationId: "org_1" },
				});
			}
			if (url.endsWith("/enterprise/sso")) return json({ connections: [] });
			if (url.endsWith("/enterprise/scim")) {
				return json({ connections: [{
					id: "scim_1", organizationId: "org_1", provider: "okta", status: "active",
					endpoint: "https://example.test/scim/v2", hasBearerToken: true,
					deprovisioningPolicy: "disable", createdAt: "2026-07-24T00:00:00.000Z", updatedAt: "2026-07-24T00:00:00.000Z",
				}] });
			}
			if (url.endsWith("/enterprise/readiness")) return json({ report: {
				overall: "ready", generatedAt: "2026-07-24T00:00:00.000Z",
				conformance: { mode: "simulation", liveCertified: false, note: "ready" },
				checks: [], remainingCustomerActions: [],
			} });
			if (url.endsWith("/replace-secret")) {
				if (body?.dryRun === true) {
					return json({ preview: true, connection: {
						id: "sso_1", organizationId: "org_1", protocol: "oidc", provider: "okta", status: "active",
						domains: ["example.test"], issuer: "https://issuer.example.test", clientId: "client_1", hasClientSecret: true,
						attributeMapping: { email: "email" }, createdAt: "2026-07-24T00:00:00.000Z", updatedAt: "2026-07-24T00:00:00.000Z",
					}, wouldChange: true });
				}
				replacementAttempts += 1;
				if (replacementAttempts === 1) return json({ error: "temporary" }, 503);
				return json({
					id: "sso_1", organizationId: "org_1", protocol: "oidc", provider: "okta", status: "active",
					domains: ["example.test"], issuer: "https://issuer.example.test", clientId: "client_1", hasClientSecret: true,
					attributeMapping: { email: "email" }, createdAt: "2026-07-24T00:00:00.000Z", updatedAt: "2026-07-24T00:00:00.000Z",
				});
			}
			if (url.endsWith("/rotate")) {
				if (body?.dryRun === true) {
					return json({ preview: true, connection: {
						id: "scim_1", organizationId: "org_1", provider: "okta", status: "active",
						endpoint: "https://example.test/scim/v2", hasBearerToken: true, deprovisioningPolicy: "disable",
						createdAt: "2026-07-24T00:00:00.000Z", updatedAt: "2026-07-24T00:00:00.000Z",
					}, wouldChange: true });
				}
				return json({ connection: {
					id: "scim_1", organizationId: "org_1", provider: "okta", status: "active",
					endpoint: "https://example.test/scim/v2", hasBearerToken: true, deprovisioningPolicy: "disable",
					createdAt: "2026-07-24T00:00:00.000Z", updatedAt: "2026-07-24T00:00:00.000Z",
				}, replayed: false, bearerTokenOnce: "scim_once" });
			}
			throw new Error(`Unexpected request: ${url}`);
		});
		const root = document.createElement("div");
		document.body.append(root);
		const mount = mountClearanceVault(root, {
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
			initialRoute: "enterprise",
		});
		await settle();

		const submitReplacement = () => {
			root.querySelector<HTMLInputElement>("#cv-sso-secret-id")!.value = "sso_1";
			root.querySelector<HTMLInputElement>("#cv-sso-secret-value")!.value = "replacement";
			[...root.querySelectorAll<HTMLButtonElement>("button")]
				.find((control) => control.textContent === "Preview secret replacement")?.click();
		};
		const confirm = (label: string) => [...root.querySelectorAll<HTMLButtonElement>("button")]
			.find((control) => control.textContent === label)?.click();

		submitReplacement();
		await settle();
		confirm("Replace secret");
		await settle();
		expect(root.querySelector("[role='alertdialog']")).not.toBeNull();
		confirm("Replace secret");
		await settle();
		submitReplacement();
		await settle();
		confirm("Replace secret");
		await settle();
		const rotate = [...root.querySelectorAll<HTMLButtonElement>("button")]
			.find((control) => control.textContent === "Rotate token");
		expect(rotate).toBeDefined();
		rotate?.click();
		await settle();
		confirm("Rotate token");
		await settle();

		const replacementBodies = requests
			.filter((request) => request.url.endsWith("/replace-secret"))
			.map((request) => request.body);
		expect(replacementBodies).toEqual([
			{ dryRun: true, confirm: false },
			{ newClientSecret: "replacement", operationId: "018f0f51-74a3-7eab-8f8b-8a4db4f3f6c1", dryRun: false, confirm: true },
			{ newClientSecret: "replacement", operationId: "018f0f51-74a3-7eab-8f8b-8a4db4f3f6c1", dryRun: false, confirm: true },
			{ dryRun: true, confirm: false },
			{ newClientSecret: "replacement", operationId: "018f0f51-74a3-7eab-8f8b-8a4db4f3f6c2", dryRun: false, confirm: true },
		]);
		expect(requests.find((request) => request.url.endsWith("/rotate"))?.body).toEqual({ dryRun: true, confirm: false });
		expect(requests.filter((request) => request.url.endsWith("/rotate")).at(-1)?.body).toEqual({
			dryRun: false,
			confirm: true,
			operationId: "018f0f51-74a3-7eab-8f8b-8a4db4f3f6c3",
		});
		expect(randomUUID).toHaveBeenCalledTimes(3);
		mount.destroy();
	});
});
