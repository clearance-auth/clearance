import { describe, expect, it } from "vitest";
import {
	CLEARANCE_AUTH_VERSION,
	DEFAULT_TELEMETRY_ENDPOINT,
	RUNTIME_BASELINE,
	withClearanceDefaults,
} from "./index.js";

describe("withClearanceDefaults", () => {
	it("forces telemetry off", () => {
		const result = withClearanceDefaults({
			baseURL: "http://localhost:3000",
			telemetry: { enabled: true },
		});
		expect(result.telemetry.enabled).toBe(false);
		expect(result.baseURL).toBe("http://localhost:3000");
	});

	it("exposes Clearance and runtime versions", () => {
		expect(RUNTIME_BASELINE.version).toBe("1.6.23");
		expect(CLEARANCE_AUTH_VERSION).toMatch(/^\d+\.\d+\.\d+/);
		expect(DEFAULT_TELEMETRY_ENDPOINT).toBeUndefined();
	});
});
