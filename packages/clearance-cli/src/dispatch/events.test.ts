import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@clearance/management", async (importOriginal) => {
	const original = await importOriginal<typeof import("@clearance/management")>();
	const source = await import("../../../management/src/contracts/operations.ts");
	return { ...original, EVENT_OPERATIONS: source.EVENT_OPERATIONS };
});

// This test owns polling projection and lifecycle semantics; the generated
// client suite separately owns strict response-schema conformance.
vi.mock("@clearance/management-client", async (importOriginal) => {
	const original = await importOriginal<typeof import("@clearance/management-client")>();
	const permissiveOutput = { safeParse: (data: unknown) => ({ success: true, data }) };
	return {
		...original,
		MANAGEMENT_OPERATION_REGISTRY: Object.fromEntries(
			Object.entries(original.MANAGEMENT_OPERATION_REGISTRY).map(([id, operation]) => [
				id,
				{ ...operation, schemas: { ...operation.schemas, output: permissiveOutput } },
			]),
		),
	};
});

import type { ApiSession } from "../api-client.js";
import { dispatchEventCommand } from "./events.js";

const session: ApiSession = {
	apiUrl: "https://api.clearance.test",
	token: "operator-token-for-events-tests",
	profile: "test",
	credentialSource: "saved",
};

afterEach(() => vi.unstubAllGlobals());

describe("events tail remote dispatch", () => {
	it("keeps lifecycle controls local while once terminates after one exact list poll", async () => {
		const requests: Array<{ url: string; init: RequestInit }> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			requests.push({ url, init });
			return Response.json({ events: [] });
		}));

		await expect(dispatchEventCommand({
			session,
			path: "events tail",
			args: [],
			opts: {
				limit: "2",
				action: "users.create",
				org: "org_1",
				pollInterval: "250",
				maxEvents: "1",
				once: true,
			},
			global: {},
		})).rejects.toMatchObject({ exitCode: 0 });

		expect(requests).toEqual([{
			url: "https://api.clearance.test/v1/events?limit=2&action=users.create&organizationId=org_1",
			init: expect.objectContaining({ method: "GET" }),
		}]);
	});
});
