import type { SessionIssuanceContext } from "@clearance/core";
import { describe, expect, it } from "vitest";
import {
	ManagedSessionIssuanceError,
	createInternalSessionIssuanceContext,
	readInternalSessionIssuanceContext,
	requireInternalSessionIssuanceContext,
} from "./session-issuance-context";

describe("internal session issuance context", () => {
	it("canonicalizes and deeply freezes runtime-derived evidence", () => {
		const context = createInternalSessionIssuanceContext({
			purpose: "interactive",
			subjectId: "user_1",
			evidence: [
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
			targetOrganizationId: "org_1",
		});
		const internal = requireInternalSessionIssuanceContext(context);

		expect(internal).toEqual({
			purpose: "interactive",
			subjectId: "user_1",
			evidence: [
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
			targetOrganizationId: "org_1",
		});
		expect(Object.isFrozen(internal)).toBe(true);
		expect(
			internal.purpose === "interactive" && Object.isFrozen(internal.evidence),
		).toBe(true);
	});

	it("rejects structurally cast and copied opaque contexts", () => {
		const forged = {
			purpose: "interactive",
			subjectId: "user_1",
			evidence: [{ kind: "primary", primaryMethod: "passkey" }],
		} as unknown as SessionIssuanceContext;
		const valid = createInternalSessionIssuanceContext(forged);

		expect(readInternalSessionIssuanceContext(forged)).toBeUndefined();
		expect(() => requireInternalSessionIssuanceContext(forged)).toThrow(
			ManagedSessionIssuanceError,
		);
		expect(() =>
			requireInternalSessionIssuanceContext({ ...valid }),
		).toThrow(ManagedSessionIssuanceError);
		expect(() => requireInternalSessionIssuanceContext(valid)).not.toThrow();
		expect(() => requireInternalSessionIssuanceContext(valid)).toThrow(
			ManagedSessionIssuanceError,
		);
	});

	it.each([
		{
			purpose: "interactive",
			subjectId: "user_1",
			evidence: [
				{
					kind: "primary",
					primaryMethod: "password",
					verifiedAt: new Date(),
				},
			],
		},
		{
			purpose: "interactive",
			subjectId: "user_1",
			evidence: [
				{
					kind: "primary",
					primaryMethod: "password",
					assurance: "phishing_resistant",
				},
			],
		},
		{
			purpose: "interactive",
			subjectId: "user_1",
			evidence: [{ kind: "factor", factorMethod: "sms" }],
		},
		{
			purpose: "replacement",
			sourceSessionToken: " token ",
		},
		{
			purpose: "interactive",
			subjectId: "user_1",
			evidence: [],
			unexpected: true,
		},
	])("rejects non-canonical issuance input %#", (input) => {
		expect(() => createInternalSessionIssuanceContext(input)).toThrow(
			ManagedSessionIssuanceError,
		);
	});

	it("requires interactive evidence to be bound to one subject", () => {
		expect(() =>
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		).toThrow(ManagedSessionIssuanceError);
	});

	it("canonicalizes replacement authority without accepting extra labels", () => {
		const context = createInternalSessionIssuanceContext({
			purpose: "replacement",
			sourceSessionToken: "source-secret",
			targetOrganizationId: null,
		});
		expect(requireInternalSessionIssuanceContext(context)).toEqual({
			purpose: "replacement",
			sourceSessionToken: "source-secret",
			targetOrganizationId: null,
		});
	});
});
