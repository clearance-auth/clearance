import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicyReader,
} from "@clearance/core";
import { ClearanceError } from "@clearance/core/error";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getMigrations } from "../db/get-migration";
import {
	attachInternalAuthenticationPolicy,
	readInternalAuthenticationPolicy,
} from "../internal/authentication-policy";
import { createInternalSessionIssuanceContext } from "../internal/session-issuance-context";
import { init } from "./init";

const identity = Object.freeze({
	projectId: "project_plugin_init",
	environmentId: "environment_plugin_init",
});
const policy = Object.freeze({
	passwordLockout: {
		enabled: true,
		maxFailedAttempts: 10,
		durationSeconds: 900,
	},
	factorLockout: {
		enabled: true,
		maxFailedAttempts: 10,
		durationSeconds: 900,
	},
	minimumAssurance: "single_factor" as const,
	allowedFactors: { totp: true, passkey: true },
	trustedDevice: { enabled: false, maxAgeSeconds: 0 },
	assuranceMaxAgeSeconds: 300,
});

const databases: DatabaseSync[] = [];

function database(): DatabaseSync {
	const value = new DatabaseSync(":memory:");
	databases.push(value);
	return value;
}

function reader(readForSubject = vi.fn()): RuntimeAuthenticationPolicyReader {
	readForSubject.mockImplementation(async (input) => ({
		scope: identity,
		subjectId: input.subjectId,
		revision: "11",
		environment: policy,
		organizationMembership: input.organizationId
			? {
				subjectId: input.subjectId,
				organizationId: input.organizationId,
			}
			: null,
		organizationOverride: null,
		effective: policy,
	}));
	return { readForSubject };
}

afterEach(() => {
	vi.restoreAllMocks();
	for (const value of databases.splice(0)) value.close();
});

describe("plugin-init managed authentication policy normalization", () => {
	it("retains enforcement and live authority on plugin-normalized options", async () => {
		const readForSubject = vi.fn();
		const options = {
			baseURL: "http://localhost:3000",
			secret: "plugin-init-managed-policy-test-secret",
			database: database(),
			plugins: [
				{
					id: "normalizes-options",
					init() {
						return {
							options: {
								session: { expiresIn: 60 * 60 },
							},
						};
					},
				},
			],
		} satisfies ClearanceOptions;
		attachInternalAuthenticationPolicy(options, {
			identity,
			reader: reader(readForSubject),
		});
		const binding = readInternalAuthenticationPolicy(options)!;
		await (await getMigrations(options)).runMigrations();

		const context = await init(options);
		expect(context.options).not.toBe(options);
		expect(readInternalAuthenticationPolicy(context.options)).toBe(binding);
		const user = await context.internalAdapter.createUser({
			email: "plugin-init-managed@example.com",
			name: "Plugin Init Managed User",
		});

		await expect(
			context.internalAdapter.createSession(user.id),
		).rejects.toMatchObject({
			code: "MANAGED_SESSION_ISSUANCE_FAILED",
			reason: "context_required",
		});
		expect(readForSubject).not.toHaveBeenCalled();

		const issuanceContext = createInternalSessionIssuanceContext({
			purpose: "interactive",
			subjectId: user.id,
			evidence: [{ kind: "primary", primaryMethod: "password" }],
		});
		await context.internalAdapter.createSession(
			user.id,
			false,
			undefined,
			false,
			issuanceContext,
		);

		expect(readForSubject).toHaveBeenCalledTimes(2);
		for (const [input] of readForSubject.mock.calls) {
			expect(input).toEqual(
				expect.objectContaining({
					subjectId: user.id,
					transaction: expect.any(Object),
				}),
			);
		}
		expect(
			await context.adapter.findMany<Record<string, unknown>>({
				model: "session",
			}),
		).toEqual([
			expect.objectContaining({
				authenticationAssuranceVersion: 1,
				authenticationPolicyProjectId: identity.projectId,
				authenticationPolicyEnvironmentId: identity.environmentId,
				authenticationPrimaryMethod: "password",
				authenticationPolicyRevision: "11",
			}),
		]);
	});

	it("rejects a plugin options object carrying a different private binding", async () => {
		const pluginOptions = {
			session: { expiresIn: 60 * 60 },
		};
		attachInternalAuthenticationPolicy(pluginOptions, {
			identity: { ...identity, environmentId: "environment_mismatch" },
			reader: reader(),
		});
		const options = {
			baseURL: "http://localhost:3000",
			secret: "plugin-init-mismatched-policy-test-secret",
			database: database(),
			plugins: [
				{
					id: "mismatched-options-authority",
					init() {
						return { options: pluginOptions };
					},
				},
			],
		} satisfies ClearanceOptions;
		attachInternalAuthenticationPolicy(options, {
			identity,
			reader: reader(),
		});

		await expect(init(options)).rejects.toBeInstanceOf(ClearanceError);
	});

	it("leaves plugin-normalized options unmanaged when no binding entered init", async () => {
		const options = {
			baseURL: "http://localhost:3000",
			secret: "plugin-init-unmanaged-policy-test-secret",
			database: database(),
			plugins: [
				{
					id: "unmanaged-options",
					init() {
						return {
							options: { session: { expiresIn: 60 * 60 } },
						};
					},
				},
			],
		} satisfies ClearanceOptions;

		const context = await init(options);
		expect(readInternalAuthenticationPolicy(context.options)).toBeUndefined();
	});

	it("reuses one unbound plugin options object across managed then unmanaged runtimes", async () => {
		const pluginOptions = { session: { expiresIn: 60 * 60 } };
		const plugin = {
			id: "reusable-managed-unmanaged-options",
			init() {
				return { options: pluginOptions };
			},
		};
		const managedOptions = {
			baseURL: "http://localhost:3000",
			secret: "plugin-init-reused-managed-policy-secret",
			database: database(),
			plugins: [plugin],
		} satisfies ClearanceOptions;
		attachInternalAuthenticationPolicy(managedOptions, {
			identity,
			reader: reader(),
		});
		const managedBinding = readInternalAuthenticationPolicy(managedOptions)!;

		const managedContext = await init(managedOptions);
		expect(readInternalAuthenticationPolicy(managedContext.options)).toBe(
			managedBinding,
		);
		expect(readInternalAuthenticationPolicy(pluginOptions)).toBeUndefined();

		const unmanagedOptions = {
			baseURL: "http://localhost:3000",
			secret: "plugin-init-reused-unmanaged-policy-secret",
			database: database(),
			plugins: [plugin],
		} satisfies ClearanceOptions;
		const unmanagedContext = await init(unmanagedOptions);
		expect(
			readInternalAuthenticationPolicy(unmanagedContext.options),
		).toBeUndefined();
		expect(readInternalAuthenticationPolicy(pluginOptions)).toBeUndefined();
	});

	it("reuses one unbound plugin options object across independently managed runtimes", async () => {
		const pluginOptions = { session: { expiresIn: 60 * 60 } };
		const plugin = {
			id: "reusable-managed-options",
			init() {
				return { options: pluginOptions };
			},
		};
		const optionsA = {
			baseURL: "http://localhost:3000",
			secret: "plugin-init-reused-managed-a-secret",
			database: database(),
			plugins: [plugin],
		} satisfies ClearanceOptions;
		attachInternalAuthenticationPolicy(optionsA, {
			identity: { ...identity, environmentId: "environment_a" },
			reader: reader(),
		});
		const bindingA = readInternalAuthenticationPolicy(optionsA)!;

		const optionsB = {
			baseURL: "http://localhost:3000",
			secret: "plugin-init-reused-managed-b-secret",
			database: database(),
			plugins: [plugin],
		} satisfies ClearanceOptions;
		attachInternalAuthenticationPolicy(optionsB, {
			identity: { ...identity, environmentId: "environment_b" },
			reader: reader(),
		});
		const bindingB = readInternalAuthenticationPolicy(optionsB)!;

		const contextA = await init(optionsA);
		expect(readInternalAuthenticationPolicy(contextA.options)).toBe(bindingA);
		expect(readInternalAuthenticationPolicy(pluginOptions)).toBeUndefined();

		const contextB = await init(optionsB);
		expect(readInternalAuthenticationPolicy(contextB.options)).toBe(bindingB);
		expect(readInternalAuthenticationPolicy(contextB.options)).not.toBe(bindingA);
		expect(readInternalAuthenticationPolicy(pluginOptions)).toBeUndefined();
	});
});
