import type { ClearancePlugin } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import { describe, expect, it, vi } from "vitest";
import { parseCookies } from "../../cookies";
import { attachInternalAuthorizationAuthority } from "../../internal/authorization-authority";
import { organization } from "../organization";
import { getTestInstance } from "../../test-utils/test-instance";
import { withTenantCapability } from ".";

describe("tenant capability kernel", () => {
	it("accepts only current browser-session authorization and immediately runs the guarded adapter", async () => {
		const guardedAdapter = vi.fn();
		const requestedActions = ["tenant.read"];
		const probePlugin: ClearancePlugin = {
			id: "tenant-capability-probe",
			endpoints: {
				probe: createAuthEndpoint(
					"/tenant-capability-probe/:organizationId",
					{ method: "POST" },
					async (ctx) =>
						withTenantCapability(
							ctx,
							{
								organizationId: ctx.params.organizationId,
								requiredActions: requestedActions,
							},
							(authority) => {
								guardedAdapter(authority);
								return ctx.json({ revision: authority.revision });
							},
						),
				),
			},
		};
		const instance = await getTestInstance({
			plugins: [organization(), probePlugin],
			advanced: { disableOriginCheck: false },
			session: {
				cookieCache: { enabled: true, strategy: "compact", maxAge: 60 },
			},
			logger: { level: "error" },
		});
		const authority = {
			revision: "1",
			actions: ["tenant.read"],
			available: true,
			mutateRequiredActions: false,
		};
		const context = await instance.auth.$context;
		attachInternalAuthorizationAuthority(context.internalAdapter, {
			async readEffectiveAuthorization(input) {
				if (!authority.available) throw new Error("authority unavailable");
				if (authority.mutateRequiredActions) {
					requestedActions.splice(0, requestedActions.length, "tenant.write");
				}
				return {
					organizationId: input.organizationId,
					subject: input.subject,
					revision: authority.revision,
					actions: authority.actions,
				};
			},
			async authenticateServiceAccountCredential() {
				throw new Error("not used by tenant capability");
			},
			async initializeOrganizationOwner() { return "1"; },
		});

		const signedIn = await instance.signInWithTestUser();
		const initialSession = await instance.auth.api.getSession({
			headers: signedIn.headers,
		});
		expect(initialSession?.session.id).toBeDefined();
		await instance.db.update({
			model: "session",
			where: [{ field: "id", value: initialSession!.session.id }],
			update: { activeOrganizationId: "tenant-a" },
		});
		await instance.client.getSession({
			fetchOptions: {
				headers: signedIn.headers,
				onSuccess: instance.cookieSetter(signedIn.headers),
			},
		});
		const browserSessionToken = parseCookies(
			signedIn.headers.get("cookie") || "",
		).get("clearance.session_token");
		expect(browserSessionToken).toBeDefined();
		expect(
			await instance.auth.api.getSession({
				headers: new Headers({
					authorization: `Bearer ${browserSessionToken}`,
				}),
			}),
		).toMatchObject({ session: { id: initialSession!.session.id } });

		const request = (
			organizationId = "tenant-a",
			origin = "http://localhost:3000",
		) =>
			instance.auth.handler(
				new Request(
					`http://localhost:3000/api/auth/tenant-capability-probe/${organizationId}`,
					{
						method: "POST",
						headers: new Headers({
							...Object.fromEntries(signedIn.headers.entries()),
							origin,
						}),
					},
				),
			);

		expect(
			(await request("tenant-a", "https://untrusted.example")).status,
		).toBe(403);
		expect(guardedAdapter).not.toHaveBeenCalled();
		const bearerReplay = await instance.auth.handler(
			new Request(
				"http://localhost:3000/api/auth/tenant-capability-probe/tenant-a",
				{
					method: "POST",
					headers: {
						authorization: `Bearer ${browserSessionToken}`,
						origin: "http://localhost:3000",
					},
				},
			),
		);
		expect(bearerReplay.status).toBe(401);
		expect(guardedAdapter).not.toHaveBeenCalled();
		const initial = await request();
		expect(initial.status).toBe(200);
		expect(await initial.json()).toEqual({ revision: "1" });
		expect(guardedAdapter).toHaveBeenLastCalledWith({
			organizationId: "tenant-a",
			principalId: signedIn.user.id,
			revision: "1",
		});
		authority.mutateRequiredActions = true;
		expect((await request()).status).toBe(200);
		authority.mutateRequiredActions = false;
		requestedActions.splice(0, requestedActions.length, "tenant.read");

		authority.revision = "2";
		const revisionChanged = await request();
		expect(revisionChanged.status).toBe(200);
		expect(await revisionChanged.json()).toEqual({ revision: "2" });

		const guardedCalls = guardedAdapter.mock.calls.length;
		requestedActions.splice(0, requestedActions.length, "tenant.read", "tenant.read");
		expect((await request()).status).toBe(403);
		expect(guardedAdapter).toHaveBeenCalledTimes(guardedCalls);
		requestedActions.splice(0, requestedActions.length, "tenant.read");
		authority.actions = [];
		expect((await request()).status).toBe(403);
		expect(guardedAdapter).toHaveBeenCalledTimes(guardedCalls);

		authority.actions = ["tenant.read"];
		await instance.db.update({
			model: "session",
			where: [{ field: "id", value: initialSession!.session.id }],
			update: { activeOrganizationId: "tenant-b" },
		});
		expect((await request()).status).toBe(401);
		expect(guardedAdapter).toHaveBeenCalledTimes(guardedCalls);

		await instance.db.update({
			model: "session",
			where: [{ field: "id", value: initialSession!.session.id }],
			update: { activeOrganizationId: "tenant-a" },
		});
		authority.available = false;
		expect((await request()).status).toBe(503);
		expect(guardedAdapter).toHaveBeenCalledTimes(guardedCalls);

		authority.available = true;
		await context.internalAdapter.deleteSessionById(initialSession!.session.id);
		expect((await request()).status).toBe(401);
		expect(guardedAdapter).toHaveBeenCalledTimes(guardedCalls);

		const unattached = await getTestInstance({
			plugins: [organization(), probePlugin],
			advanced: { disableOriginCheck: false },
			logger: { level: "error" },
		});
		const unattachedSession = await unattached.signInWithTestUser();
		const unattachedCurrentSession = await unattached.auth.api.getSession({
			headers: unattachedSession.headers,
		});
		expect(unattachedCurrentSession?.session.id).toBeDefined();
		await unattached.db.update({
			model: "session",
			where: [{ field: "id", value: unattachedCurrentSession!.session.id }],
			update: { activeOrganizationId: "tenant-a" },
		});
		const unavailable = await unattached.auth.handler(
			new Request(
				"http://localhost:3000/api/auth/tenant-capability-probe/tenant-a",
				{
					method: "POST",
					headers: new Headers({
						...Object.fromEntries(unattachedSession.headers.entries()),
						origin: "http://localhost:3000",
					}),
				},
			),
		);
		expect(unavailable.status).toBe(403);
		expect(guardedAdapter).toHaveBeenCalledTimes(guardedCalls);
	});
});
