import { createHash } from "node:crypto";
import type { ClearanceKeyManagementFacade } from "@clearance/auth";
import { createLocalKeyProvider, parseKeyEnvelope } from "@clearance/key-management";
import { describe, expect, it } from "vitest";
import {
	createScimOperationReplayCipher,
	type ScimOperationReplayTokenBinding,
} from "./scim.js";

const provider = createLocalKeyProvider({
	providerId: "scim-replay-proof",
	purpose: "scim-bearer-token",
	currentKeyId: "current",
	keys: { current: Buffer.alloc(32, 7) },
});

function facade(projectId: string, environmentId: string): ClearanceKeyManagementFacade {
	const scope = Object.freeze({ projectId, environmentId });
	return {
		scope,
		resourceId: (purpose, identity) =>
			`${purpose}:${createHash("sha256").update(JSON.stringify(identity)).digest("hex")}`,
		sealText: async (_purpose, resourceId, plaintext) =>
			provider.seal(Buffer.from(plaintext, "utf8"), { ...scope, resourceId }),
		openText: async (_purpose, resourceId, envelope) =>
			Buffer.from(await provider.open(envelope, { ...scope, resourceId })).toString("utf8"),
		readiness: async () => ({ ready: true, purposes: {} as never }),
		status: async () => ({}) as never,
		planMigration: async () => ({}) as never,
		applyMigration: async () => ({}) as never,
	};
}

function binding(projectId: string, environmentId: string): ScimOperationReplayTokenBinding {
	return {
		projectId,
		environmentId,
		organizationId: "org_replay_proof",
		connectionId: "scim_replay_proof",
		operationId: "33333333-3333-4333-8333-333333333333",
		operationKind: "create",
		actorId: "service-account-replay",
		source: "system",
		provider: "okta",
		endpoint: "https://scim.example.test/v2",
	};
}

describe("SCIM operation replay cipher", () => {
	it("uses the SCIM purpose and rejects a different immutable scope or binding", async () => {
		const left = binding("proj_replay_left", "env_replay_left");
		const leftCipher = createScimOperationReplayCipher(
			facade(left.projectId, left.environmentId),
		);
		const sealed = await leftCipher.seal("scimtok_exact_original", left);
		const envelope = parseKeyEnvelope(sealed.envelope);

		expect(envelope).toMatchObject({
			purpose: "scim-bearer-token",
			projectId: left.projectId,
			environmentId: left.environmentId,
			keyId: sealed.keyId,
		});
		await expect(leftCipher.open(sealed.envelope, left)).resolves.toBe(
			"scimtok_exact_original",
		);

		const right = binding("proj_replay_right", "env_replay_right");
		const rightCipher = createScimOperationReplayCipher(
			facade(right.projectId, right.environmentId),
		);
		await expect(rightCipher.open(sealed.envelope, right)).rejects.toThrow();
		await expect(leftCipher.open(sealed.envelope, {
			...left,
			actorId: "different-actor",
		})).rejects.toThrow();
	});
});
