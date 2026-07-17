import type { GenericEndpointContext } from "@clearance/core";
import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../test-utils/test-instance";
import {
	requireManagedAuthenticationTransaction,
	runManagedAuthenticationTransaction,
} from "./managed-authentication-transaction";

describe("managed authentication transaction routing", () => {
	it("preserves the direct unmanaged execution path", async () => {
		const { auth } = await getTestInstance(undefined, { disableTestUser: true });
		const context = await auth.$context;
		const ctx = { context } as GenericEndpointContext;
		const operation = vi.fn(async () => "completed");

		expect(requireManagedAuthenticationTransaction(ctx)).toBe(false);
		await expect(
			runManagedAuthenticationTransaction(ctx, operation),
		).resolves.toBe("completed");
		expect(operation).toHaveBeenCalledTimes(1);
	});
});
