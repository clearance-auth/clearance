import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiSession } from "./api-client.js";
import { dispatchRemoteCommand } from "./remote-dispatch.js";

const session: ApiSession = {
	apiUrl: "https://api.clearance.test",
	token: "operator-token",
	profile: "test",
	credentialSource: "saved",
};

afterEach(() => vi.restoreAllMocks());

describe("guarded mutation confirmation", () => {
	it.each([
		["env promote", [], { to: "production" }, "ENVIRONMENT_PROMOTE_CONFIRMATION_REQUIRED"],
		["events replay", ["evt_1"], {}, "EVENT_REPLAY_CONFIRMATION_REQUIRED"],
		["orgs authorization reconcile", [], { org: "org_1" }, "AUTHORIZATION_RECONCILE_CONFIRMATION_REQUIRED"],
		["auth-policy unlock", ["usr_1"], { kind: "password" }, "AUTHENTICATION_POLICY_UNLOCK_CONFIRMATION_REQUIRED"],
		["delivery cancel", ["job_1"], {}, "DELIVERY_CANCEL_CONFIRMATION_REQUIRED"],
		["scim replay", ["trace_1"], {}, "SCIM_REPLAY_CONFIRM_REQUIRED"],
		["key-management apply", [], { expectedPlan: "a".repeat(64) }, "KEY_MANAGEMENT_APPLY_CONFIRMATION_REQUIRED"],
		["orgs archive", ["org_1"], {}, "ORGANIZATION_ARCHIVE_CONFIRMATION_REQUIRED"],
		["product domains activate", [], { origin: "https://auth.example.test", expectedVersion: "1" }, "PRODUCT_DOMAIN_ACTIVATE_CONFIRMATION_REQUIRED"],
	] as const)("fails closed for %s instead of dispatching an implicit dry run", async (path, args, opts, code) => {
		const fetch = vi.spyOn(globalThis, "fetch");

		await expect(dispatchRemoteCommand({
			session,
			path,
			args,
			opts,
			global: {},
		})).rejects.toMatchObject({ code });
		expect(fetch).not.toHaveBeenCalled();
	});
});
