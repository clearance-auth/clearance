import { describe, expect, it, vi } from "vitest";
import {
	enqueueOrganizationUpdatedWebhooks,
	validateManagementWebhookTargets,
} from "./delivery.js";

describe("management webhook coexistence", () => {
	it("suppresses a legacy target when a managed endpoint owns the canonical destination", async () => {
		const enqueue = vi.fn();
		const targets = validateManagementWebhookTargets([{
			id: "legacy-different-id",
			url: "https://EXAMPLE.test:443/hooks",
			signingSecret: "legacy-signing-secret-with-enough-entropy",
		}]);

		await expect(enqueueOrganizationUpdatedWebhooks({
			enqueue,
			targets,
			excludeTargetIds: new Set(["managed-endpoint-id"]),
			excludeDestinationUrls: new Set(["https://example.test/hooks"]),
			context: {
				scope: { projectId: "project-1", environmentId: "environment-1" },
				actor: "operator-1",
				source: "api",
				correlationId: "correlation-1",
			},
			organization: {
				id: "organization-1",
				projectId: "project-1",
				environmentId: "environment-1",
				name: "Example",
				slug: "example",
				status: "active",
				createdAt: "2026-07-15T00:00:00.000Z",
				updatedAt: "2026-07-15T00:00:00.000Z",
			},
			before: { name: "Before", slug: "before" },
			occurredAt: new Date("2026-07-15T00:00:00.000Z"),
		})).resolves.toEqual([]);
		expect(enqueue).not.toHaveBeenCalled();
	});
});
