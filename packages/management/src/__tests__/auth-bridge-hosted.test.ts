import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { createManagementAuth } = vi.hoisted(() => ({
	createManagementAuth: vi.fn(),
}));

vi.mock("@clearance/auth/management-internal", () => ({
	createClearanceManagementAuth: createManagementAuth,
}));

import {
	acquireHostedAuthBundle,
	closeAuthBundle,
	closeHostedAuthBundles,
	createManagedOrganizationLifecycleFacade,
	getAuthBundle,
	getHostedAuthBundle,
	hostedAuthBundleCacheStateForTesting,
	invalidateAuthBundles,
} from "../auth-bridge.js";
import type { ManagementStore } from "../store/types.js";
import { testScimConnectionReal } from "../services/scim-real.js";

const scope = { projectId: "proj_hosted", environmentId: "env_hosted" };
const store = {
	backend: "postgres",
	mutateCoordinated: vi.fn(),
} as unknown as ManagementStore;

function hostedInput(overrides: Partial<Parameters<typeof getHostedAuthBundle>[0]> = {}) {
	return {
		origin: "https://auth.example.test",
		hostname: "auth.example.test",
		scope,
		productLabel: "Example",
		store,
		presentationVersion: "presentation-1",
		domainVersion: "domain-1",
		...overrides,
	};
}

function bundle() {
	return {
		destroy: vi.fn().mockResolvedValue(undefined),
		migrate: vi.fn().mockResolvedValue(undefined),
		prepareCredentialAuthorityRuntime: vi.fn().mockResolvedValue(undefined),
	} as never;
}

describe("hosted auth bridge", () => {
	beforeEach(async () => {
		process.env.DATABASE_URL = "postgres://clearance:clearance@127.0.0.1:5434/clearance";
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.NODE_ENV = "development";
		createManagementAuth.mockImplementation(() => bundle());
		await closeAuthBundle();
		await closeHostedAuthBundles();
		createManagementAuth.mockClear();
	});

	afterEach(async () => {
		await closeAuthBundle();
		await closeHostedAuthBundles();
	});

	it("rejects control characters in runtime-managed organization names before any transaction", async () => {
		const lifecycle = createManagedOrganizationLifecycleFacade({ store, scope });
		await expect(lifecycle.finalizeCreatedOrganization({
			organization: {
				id: "org_control_character",
				name: "Invalid\norganization",
				slug: "invalid-organization",
				createdAt: new Date(),
			},
			owner: {
				id: "principal_control_character",
				email: "owner@example.test",
				createdAt: new Date(),
				updatedAt: new Date(),
			},
			ownerMembershipId: "membership_control_character",
			authorizationRevision: "1",
			transaction: {} as never,
		} as never)).rejects.toMatchObject({
			code: "MANAGED_ORGANIZATION_NAME_INVALID",
		});
	});

	it("keeps hosted SCIM checks on the owning scope cipher and runtime", async () => {
		const alphaScope = { projectId: "proj_alpha", environmentId: "env_alpha" };
		const betaScope = { projectId: "proj_beta", environmentId: "env_beta" };
		const now = new Date().toISOString();
		const data = {
			organizations: [
				{ id: "org_alpha", ...alphaScope, name: "Alpha", slug: "alpha", status: "active", createdAt: now, updatedAt: now },
				{ id: "org_beta", ...betaScope, name: "Beta", slug: "beta", status: "active", createdAt: now, updatedAt: now },
			],
			scimConnections: [
				{ id: "scim_alpha", organizationId: "org_alpha", provider: "alpha", status: "draft", endpoint: "/scim/v2/org_alpha", bearerTokenEncrypted: "alpha-envelope", bearerTokenFingerprint: "alpha-fingerprint", bearerTokenKeyId: "alpha-key", deprovisioningPolicy: "disable", createdAt: now, updatedAt: now },
				{ id: "scim_beta", organizationId: "org_beta", provider: "beta", status: "draft", endpoint: "/scim/v2/org_beta", bearerTokenEncrypted: "beta-envelope", bearerTokenFingerprint: "beta-fingerprint", bearerTokenKeyId: "beta-key", deprovisioningPolicy: "disable", createdAt: now, updatedAt: now },
			],
			traces: [],
			events: [],
		};
		const scopedStore = {
			backend: "json",
			snapshot: data,
			mutate: (mutation: (draft: typeof data) => void) => mutation(data),
		} as unknown as ManagementStore;
		const opens: string[] = [];
		const requests: string[] = [];
		const guard = (name: "alpha" | "beta", scope: typeof alphaScope) => ({
			authorizeMutation: vi.fn(),
			credentialCipher: {
				seal: vi.fn(),
				open: vi.fn(async (envelope: string, identity: Readonly<Record<string, string>>) => {
					expect(envelope).toBe(`${name}-envelope`);
					expect(identity).toEqual({ organizationId: `org_${name}`, connectionId: `scim_${name}` });
					opens.push(name);
					return `${name}-token`;
				}),
			},
			scimRuntime: {
				origin: `https://${name}.auth.example.test`,
				handler: vi.fn(async (request: Request) => {
					expect(new URL(request.url).origin).toBe(`https://${name}.auth.example.test`);
					expect(request.headers.get("origin")).toBe(`https://${name}.auth.example.test`);
					expect(request.headers.get("authorization")).toBe(`Bearer ${name}-token`);
					requests.push(name);
					return new Response(JSON.stringify({ schemas: [] }), { status: 200 });
				}),
			},
		}) as never;

		await testScimConnectionReal(scopedStore, "scim_alpha", { scope: alphaScope }, guard("alpha", alphaScope));
		await testScimConnectionReal(scopedStore, "scim_beta", { scope: betaScope }, guard("beta", betaScope));

		expect(opens).toEqual(["alpha", "beta"]);
		expect(requests).toEqual(["alpha", "beta"]);
	});

	it("binds each hosted bundle to the exact origin, RP, and product scope", async () => {
		await getHostedAuthBundle(hostedInput());
		expect(createManagementAuth).toHaveBeenCalledTimes(1);
		expect(createManagementAuth).toHaveBeenCalledWith(expect.objectContaining({
			baseURL: "https://auth.example.test",
			trustedOrigins: ["https://auth.example.test"],
			passkeys: {
				rpID: "auth.example.test",
				rpName: "Example",
				origin: ["https://auth.example.test"],
			},
			runtimeAudit: scope,
			authenticationPolicy: scope,
			authorization: scope,
		}));
		await expect(getHostedAuthBundle(hostedInput({
			origin: "https://AUTH.example.test",
			hostname: "auth.example.test",
		}))).rejects.toThrow(/exactly match/);
		await expect(getHostedAuthBundle(hostedInput({
			origin: "http://auth.example.test",
		}))).rejects.toThrow(/HTTPS/);
	});

	it("keeps hosted tenant facades and lifecycle control paths bound to their owning store", async () => {
		const createStore = (name: string) => {
			const now = new Date().toISOString();
			return {
				backend: "postgres",
				refresh: vi.fn().mockResolvedValue(undefined),
				snapshot: {
					organizations: [{
						id: `org_${name}`,
						...scope,
						name,
						slug: name,
						status: "active",
						createdAt: now,
						updatedAt: now,
					}],
					ssoConnections: [{
						id: `sso_${name}`,
						organizationId: `org_${name}`,
						protocol: "saml",
						provider: name,
						status: "active",
						domains: [`${name}.example.test`],
						attributeMapping: {},
						createdAt: now,
						updatedAt: now,
					}],
				},
			} as unknown as ManagementStore;
		};
		const alphaStore = createStore("alpha");
		const betaStore = createStore("beta");

		const alpha = await getHostedAuthBundle(hostedInput({ store: alphaStore }));
		const alphaAgain = await getHostedAuthBundle(hostedInput({ store: alphaStore }));
		const beta = await getHostedAuthBundle(hostedInput({ store: betaStore }));

		expect(alphaAgain).toBe(alpha);
		expect(beta).not.toBe(alpha);
		expect(createManagementAuth).toHaveBeenCalledTimes(2);

		const [alphaOptions, betaOptions] = createManagementAuth.mock.calls.map(
			([options]) => options as {
				tenantProductAdministration: {
					listSso(input: { organizationId: string }): Promise<Array<{ id: string }>>;
				};
				managedOrganizationLifecycle: {
					refreshAfterCommit(): Promise<void>;
				};
			},
		);

		await expect(alphaOptions.tenantProductAdministration.listSso({
			organizationId: "org_alpha",
		})).resolves.toEqual([expect.objectContaining({ id: "sso_alpha" })]);
		expect(alphaStore.refresh).toHaveBeenCalledTimes(1);
		expect(betaStore.refresh).not.toHaveBeenCalled();

		await alphaOptions.managedOrganizationLifecycle.refreshAfterCommit();
		expect(alphaStore.refresh).toHaveBeenCalledTimes(2);
		expect(betaStore.refresh).not.toHaveBeenCalled();

		await expect(betaOptions.tenantProductAdministration.listSso({
			organizationId: "org_beta",
		})).resolves.toEqual([expect.objectContaining({ id: "sso_beta" })]);
		await betaOptions.managedOrganizationLifecycle.refreshAfterCommit();
		expect(alphaStore.refresh).toHaveBeenCalledTimes(2);
		expect(betaStore.refresh).toHaveBeenCalledTimes(2);
	});

	it("coalesces equivalent creation, destroys retired versions, and evicts bounded cache entries", async () => {
		const first = hostedInput();
		const [one, two] = await Promise.all([
			getHostedAuthBundle(first),
			getHostedAuthBundle(first),
		]);
		expect(one).toBe(two);
		expect(createManagementAuth).toHaveBeenCalledTimes(1);

		const replacement = await getHostedAuthBundle(hostedInput({
			presentationVersion: "presentation-2",
		}));
		expect((one as { destroy: ReturnType<typeof vi.fn> }).destroy).toHaveBeenCalledTimes(1);
		expect(replacement).not.toBe(one);

		for (let index = 0; index < 33; index += 1) {
			await getHostedAuthBundle(hostedInput({
				origin: `https://auth-${index}.example.test`,
				hostname: `auth-${index}.example.test`,
			}));
		}
		expect((replacement as { destroy: ReturnType<typeof vi.fn> }).destroy).toHaveBeenCalledTimes(1);
		await closeHostedAuthBundles();
		expect(createManagementAuth.mock.results.every((result) =>
			(result.value as { destroy: ReturnType<typeof vi.fn> }).destroy.mock.calls.length === 1,
		)).toBe(true);
	});

	it("removes retired bundles from lookup but waits for request leases before destruction", async () => {
		const lease = await acquireHostedAuthBundle(hostedInput());
		const replacement = await getHostedAuthBundle(hostedInput({
			presentationVersion: "presentation-2",
		}));

		expect(replacement).not.toBe(lease.bundle);
		expect((lease.bundle as { destroy: ReturnType<typeof vi.fn> }).destroy).not.toHaveBeenCalled();
		expect(hostedAuthBundleCacheStateForTesting()).toMatchObject({
			cached: 1,
			retired: 1,
		});

		await lease.release();
		expect((lease.bundle as { destroy: ReturnType<typeof vi.fn> }).destroy).toHaveBeenCalledTimes(1);
		expect(hostedAuthBundleCacheStateForTesting()).toMatchObject({ retired: 0 });
	});

	it("invalidates immediately while a hosted request lease defers retirement destruction", async () => {
		let resolveDestruction: (() => void) | undefined;
		const leasedBundle = {
			destroy: vi.fn(() => new Promise<void>((resolve) => {
				resolveDestruction = resolve;
			})),
			migrate: vi.fn().mockResolvedValue(undefined),
			prepareCredentialAuthorityRuntime: vi.fn().mockResolvedValue(undefined),
		} as never;
		createManagementAuth
			.mockImplementationOnce(() => leasedBundle)
			.mockImplementation(() => bundle());

		const lease = await acquireHostedAuthBundle(hostedInput());
		expect(invalidateAuthBundles()).toBeUndefined();
		expect(hostedAuthBundleCacheStateForTesting()).toEqual({
			cached: 0,
			serializations: 0,
			retired: 1,
		});
		expect((lease.bundle as { destroy: ReturnType<typeof vi.fn> }).destroy).not.toHaveBeenCalled();

		const fresh = await getHostedAuthBundle(hostedInput());
		expect(fresh).not.toBe(lease.bundle);
		expect(createManagementAuth).toHaveBeenCalledTimes(2);

		const release = lease.release();
		expect((lease.bundle as { destroy: ReturnType<typeof vi.fn> }).destroy).toHaveBeenCalledTimes(1);
		expect(hostedAuthBundleCacheStateForTesting()).toMatchObject({ retired: 1 });
		resolveDestruction?.();
		await release;
		expect(hostedAuthBundleCacheStateForTesting()).toMatchObject({ retired: 0 });
	});

	it("keeps a failed hosted retirement visible until close reports and clears it", async () => {
		const failure = new Error("hosted destroy failed");
		const leasedBundle = {
			destroy: vi.fn().mockRejectedValue(failure),
			migrate: vi.fn().mockResolvedValue(undefined),
			prepareCredentialAuthorityRuntime: vi.fn().mockResolvedValue(undefined),
		} as never;
		createManagementAuth.mockImplementationOnce(() => leasedBundle);

		const lease = await acquireHostedAuthBundle(hostedInput());
		invalidateAuthBundles();
		await expect(lease.release()).rejects.toBe(failure);
		expect(hostedAuthBundleCacheStateForTesting()).toMatchObject({ retired: 1 });
		await expect(closeHostedAuthBundles()).rejects.toBe(failure);
		expect(hostedAuthBundleCacheStateForTesting()).toMatchObject({ retired: 0 });
	});

	it("keeps a failed singleton retirement visible until close reports it", async () => {
		const failure = new Error("singleton destroy failed");
		createManagementAuth.mockImplementationOnce(() => ({
			destroy: vi.fn().mockRejectedValue(failure),
			migrate: vi.fn().mockResolvedValue(undefined),
			prepareCredentialAuthorityRuntime: vi.fn().mockResolvedValue(undefined),
		}));
		getAuthBundle();
		invalidateAuthBundles();
		await expect(closeAuthBundle()).rejects.toBe(failure);
		await expect(closeAuthBundle()).resolves.toBeUndefined();
	});

	it("never returns an invalidated in-flight creation to concurrent callers", async () => {
		const invalidated = bundle();
		createManagementAuth
			.mockImplementationOnce(() => invalidated)
			.mockImplementation(() => bundle());

		const first = getHostedAuthBundle(hostedInput());
		expect(hostedAuthBundleCacheStateForTesting()).toEqual({
			cached: 0,
			serializations: 1,
			retired: 0,
		});
		invalidateAuthBundles();
		const concurrent = getHostedAuthBundle(hostedInput());
		const [one, two] = await Promise.all([first, concurrent]);

		expect(one).toBe(two);
		expect(one).not.toBe(invalidated);
		expect((invalidated as { destroy: ReturnType<typeof vi.fn> }).destroy).toHaveBeenCalledTimes(1);
		expect(createManagementAuth).toHaveBeenCalledTimes(2);
		expect(hostedAuthBundleCacheStateForTesting()).toEqual({
			cached: 1,
			serializations: 0,
			retired: 0,
		});
	});

	it("discards completed identity serialization state after cache churn", async () => {
		for (let index = 0; index < 40; index += 1) {
			await getHostedAuthBundle(hostedInput({
				origin: `https://auth-${index}.example.test`,
				hostname: `auth-${index}.example.test`,
			}));
		}

		expect(hostedAuthBundleCacheStateForTesting()).toEqual({
			cached: 32,
			serializations: 0,
			retired: 0,
		});
	});

	it("fails closed when the normal bundle has no registered tenant facade", async () => {
		getAuthBundle();
		const options = createManagementAuth.mock.calls[0]?.[0] as {
			tenantProductAdministration: {
				createSso(input: Record<string, string>): Promise<unknown>;
			};
		};
		await expect(options.tenantProductAdministration.createSso({
			organizationId: "org_1",
			actorId: "user_1",
			protocol: "saml",
			provider: "example",
			issuer: "https://idp.example.test",
			domain: "example.test",
		})).rejects.toMatchObject({
			code: "TENANT_PRODUCT_ADMINISTRATION_UNAVAILABLE",
		});
		expect(store.mutateCoordinated).not.toHaveBeenCalled();
	});
});
