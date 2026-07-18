import { afterEach, describe, expect, it } from "vitest";
import { readInternalAuthenticationPolicy } from "../../../runtime/src/internal/authentication-policy.js";
import {
	closeAuthBundle,
	getAuthBundle,
	resetAuthBundle,
} from "../auth-bridge.js";

const ENV_KEYS = [
	"NODE_ENV",
	"DATABASE_URL",
	"CLEARANCE_SECRET",
	"CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION",
	"CLEARANCE_DEPLOYMENT_ID",
	"CLEARANCE_INSTANCE_ID",
	"CLEARANCE_PROJECT_ID",
	"CLEARANCE_ENV_ID",
] as const;
const originalEnvironment = Object.fromEntries(
	ENV_KEYS.map((key) => [key, process.env[key]]),
) as Record<(typeof ENV_KEYS)[number], string | undefined>;

afterEach(async () => {
	await closeAuthBundle();
	resetAuthBundle();
	for (const key of ENV_KEYS) {
		const value = originalEnvironment[key];
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
});

describe("management authentication-policy scope", () => {
	it("enables policy only for an explicit immutable project and environment", async () => {
		process.env.NODE_ENV = "production";
		process.env.DATABASE_URL =
			"postgres://clearance:clearance@127.0.0.1:5434/clearance";
		process.env.CLEARANCE_SECRET =
			"management-policy-scope-production-secret!!";
		process.env.CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION = "digest-v1";
		process.env.CLEARANCE_DEPLOYMENT_ID = "deployment-policy-scope";
		process.env.CLEARANCE_INSTANCE_ID = "instance-policy-scope";
		delete process.env.CLEARANCE_PROJECT_ID;
		delete process.env.CLEARANCE_ENV_ID;

		const unscopedBundle = getAuthBundle();
		expect(
			readInternalAuthenticationPolicy(
				(unscopedBundle.auth as unknown as { options: object }).options,
			),
		).toBeUndefined();
		await closeAuthBundle();
		resetAuthBundle();

		process.env.CLEARANCE_PROJECT_ID = "project_policy_scope";
		process.env.CLEARANCE_ENV_ID = "environment_policy_scope";
		const bundle = getAuthBundle();
		const runtimeOptions = (bundle.auth as unknown as { options: object }).options;
		expect(readInternalAuthenticationPolicy(runtimeOptions)?.identity).toEqual(
			{
				projectId: "project_policy_scope",
				environmentId: "environment_policy_scope",
			},
		);
	});
});
