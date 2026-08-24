import { describe, expect, it } from "vitest";
import { startObservability } from "../src/bootstrap";

describe("startObservability", () => {
	it("does not register an SDK or exporter for disabled configuration", async () => {
		const caller = {
			enabled: false as const,
			shutdownTimeoutMillis: 10_000,
		};
		const handle = await startObservability(caller);
		caller.shutdownTimeoutMillis = 20_000;

		expect(
			await startObservability({
				enabled: false,
				shutdownTimeoutMillis: 10_000,
			}),
		).toBe(handle);
		await expect(startObservability(caller)).rejects.toThrow(
			"different configuration",
		);
		expect(handle.shutdown()).toBe(handle.shutdown());
		expect(handle.status).toMatchObject({
			state: "disabled",
			instrumentations: { http: false, pg: false },
		});
		expect(await handle.shutdown()).toEqual(handle.status);
	});
});
