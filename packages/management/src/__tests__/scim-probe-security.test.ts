import { describe, expect, it } from "vitest";
import { probeScimEndpoint } from "../services/scim-probe.js";

describe("SCIM probe egress boundary", () => {
	it("refuses local, private, link-local, and IPv4-mapped destinations before I/O", async () => {
		for (const endpoint of [
			"http://127.0.0.1",
			"http://10.0.0.1",
			"http://169.254.169.254",
			"http://192.168.1.1",
			"http://[::1]",
			"http://[::ffff:127.0.0.1]",
			"http://[64:ff9b::a9fe:a9fe]",
			"http://[64:ff9b:1::a9fe:a9fe]",
			"http://[100::1]",
			"http://[fec0::1]",
		]) {
			await expect(probeScimEndpoint({ endpoint })).resolves.toMatchObject({
				ok: false,
				reason: "network",
				message: expect.stringContaining("refuse"),
			});
		}
	});
});
