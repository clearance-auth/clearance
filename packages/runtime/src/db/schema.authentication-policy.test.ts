import type { ClearanceOptions } from "@clearance/core";
import { describe, expect, it } from "vitest";
import type { Session } from "../types";
import {
	getSessionDefaultFields,
	parseInternalSessionOutput,
	parseSessionInput,
	parseSessionOutput,
	parseUserInput,
	parseUserOutput,
} from "./schema";

const reservedAuthority = {
	authenticationAssuranceVersion: 1,
	authenticationPolicyProjectId: "project_1",
	authenticationPolicyEnvironmentId: "environment_1",
	authenticationPrimaryMethod: "password",
	authenticationPrimaryAt: new Date("2026-07-17T00:00:00.000Z"),
	authenticationFactorMethod: null,
	authenticationFactorAt: null,
	authenticationPolicyOrganizationId: null,
	authenticationPolicyRevision: "7",
	authenticationAssuranceExpiresAt: new Date("2026-07-17T00:05:00.000Z"),
	authenticationRecoveryRestricted: false,
} as const;

function hostileOptions(): ClearanceOptions {
	return {
		baseURL: "http://localhost:3000",
		secret: "hostile-session-schema-policy-secret",
		session: {
			additionalFields: Object.fromEntries(
				Object.keys(reservedAuthority).map((field) => [
					field,
					{
						type: field.endsWith("At") ? "date" : "string",
						input: true,
						returned: true,
						defaultValue: reservedAuthority[
							field as keyof typeof reservedAuthority
						],
					},
				]),
			),
		},
	} as ClearanceOptions;
}

describe("reserved session assurance projection", () => {
	it("removes authority despite hostile input, output, and default schema overrides", () => {
		const options = hostileOptions();
		const session = {
			id: "session_1",
			token: "presented-secret",
			userId: "user_1",
			expiresAt: new Date("2026-07-18T00:00:00.000Z"),
			createdAt: new Date("2026-07-17T00:00:00.000Z"),
			updatedAt: new Date("2026-07-17T00:00:00.000Z"),
			...reservedAuthority,
		} as unknown as Session;

		for (const result of [
			parseSessionInput(options, reservedAuthority as never, "update"),
			parseSessionOutput(options, session),
			parseInternalSessionOutput(options, session),
			getSessionDefaultFields(options),
		]) {
			for (const field of Object.keys(reservedAuthority)) {
				expect(result).not.toHaveProperty(field);
			}
		}
		expect(parseSessionOutput(options, session).token).toBe(session.id);
		expect(parseInternalSessionOutput(options, session).token).toBe(
			session.token,
		);
	});

	it("keeps shared factor lifecycle generations private and non-writable despite hostile schemas", () => {
		const maliciousFactorFields = Object.fromEntries(
			[
				"passkeySessionGeneration",
				"twoFactorSessionGeneration",
			].map((field) => [
				field,
				{
					type: "json",
					required: true,
					input: true,
					returned: true,
					defaultValue: "attacker-controlled",
					fieldName: `attacker_${field}`,
				},
			]),
		);
		const options = {
			baseURL: "http://localhost:3000",
			secret: "hostile-factor-schema-secret",
			user: { additionalFields: maliciousFactorFields },
			session: { additionalFields: maliciousFactorFields },
			plugins: [
				{
					id: "unrelated-malicious-plugin",
					schema: {
						user: { fields: maliciousFactorFields },
						session: { fields: maliciousFactorFields },
					},
				},
			],
		} as ClearanceOptions;
		const generations = {
			passkeySessionGeneration: "attacker-passkey-generation",
			twoFactorSessionGeneration: "attacker-two-factor-generation",
		};

		expect(() => parseUserInput(options, generations, "update")).toThrow(
			"passkeySessionGeneration is not allowed to be set",
		);
		expect(() => parseSessionInput(options, generations as never, "update")).toThrow(
			"passkeySessionGeneration is not allowed to be set",
		);
		expect(
			parseUserOutput(options, {
				id: "user_1",
				name: "Factor user",
				email: "factor@example.test",
				emailVerified: true,
				image: null,
				createdAt: new Date("2026-07-17T00:00:00.000Z"),
				updatedAt: new Date("2026-07-17T00:00:00.000Z"),
				...generations,
			}),
		).not.toHaveProperty("passkeySessionGeneration");
		expect(
			parseSessionOutput(options, {
				id: "session_1",
				token: "presented-secret",
				userId: "user_1",
				expiresAt: new Date("2026-07-18T00:00:00.000Z"),
				createdAt: new Date("2026-07-17T00:00:00.000Z"),
				updatedAt: new Date("2026-07-17T00:00:00.000Z"),
				...generations,
			} as Session),
		).not.toHaveProperty("twoFactorSessionGeneration");
	});
});
