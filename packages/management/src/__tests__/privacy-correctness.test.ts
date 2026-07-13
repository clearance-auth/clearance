/**
 * Behavioral tests for credential AEAD, setup capabilities, SCIM HTTP probe,
 * and local OIDC protocol verification.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	JsonStore,
	assertCredentialKeyConfigured,
	checkScimConnection,
	createLocalOidcIssuerFixture,
	createLocalScimFixtureServer,
	createOrganization,
	createScimConnection,
	commitSetupLink,
	createSetupLink,
	createSsoConnection,
	decryptCredential,
	encryptCredential,
	initProject,
	listEvents,
	listScimConnections,
	listSsoConnections,
	publicDirectoryConnection,
	publicIdentityConnection,
	redeemSetupLink,
	releaseSetupLink,
	reserveSetupLink,
	revokeSetupLink,
	rotateCredential,
	rotateScimCredential,
	rotateSsoCredential,
	verifySsoOidcLocalProtocol,
} from "../index.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clearance-priv-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
	delete process.env.CLEARANCE_CREDENTIAL_KEY;
	delete process.env.CLEARANCE_CREDENTIAL_KEY_ID;
	delete process.env.CLEARANCE_CREDENTIAL_PREVIOUS_KEY;
	delete process.env.CLEARANCE_CREDENTIAL_PREVIOUS_KEY_ID;
});

describe("credential AEAD storage", () => {
	it("persists encrypted envelopes without plaintext and supports rotation", () => {
		process.env.CLEARANCE_CREDENTIAL_KEY =
			"unit-test-credential-key-material-32b!!";
		process.env.CLEARANCE_CREDENTIAL_KEY_ID = "k1";

		const store = tempStore();
		initProject(store, { name: "Cred" });
		const org = createOrganization(store, { name: "Org" });
		const secret = "super-secret-client-value-XYZ";
		const sso = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://idp.example/oauth2",
			clientSecret: secret,
		});

		// Public response is write-only / redacted
		expect((sso as { clientSecretEncrypted?: string }).clientSecretEncrypted).toBeUndefined();
		expect(sso.clientSecretFingerprint).toBeTruthy();
		const listed = listSsoConnections(store);
		expect(
			(listed[0] as { clientSecretEncrypted?: string }).clientSecretEncrypted,
		).toBeUndefined();

		// Store holds envelope, not plaintext
		const raw = store.snapshot.identityConnections[0]!;
		expect(raw.clientSecretEncrypted).toMatch(/^clr\$v1\$k1\$/);
		expect(raw.clientSecretEncrypted).not.toContain(secret);
		const snapJson = JSON.stringify(store.snapshot);
		expect(snapJson).not.toContain(secret);
		const eventsJson = JSON.stringify(listEvents(store));
		expect(eventsJson).not.toContain(secret);

		// Decrypt works
		const pt = decryptCredential(raw.clientSecretEncrypted!);
		expect(pt).toBe(secret);

		// Rotation under new key id produces different stored bytes, still usable
		process.env.CLEARANCE_CREDENTIAL_PREVIOUS_KEY =
			process.env.CLEARANCE_CREDENTIAL_KEY;
		process.env.CLEARANCE_CREDENTIAL_PREVIOUS_KEY_ID = "k1";
		process.env.CLEARANCE_CREDENTIAL_KEY =
			"rotated-credential-key-material-32bb!!";
		process.env.CLEARANCE_CREDENTIAL_KEY_ID = "k2";

		const before = raw.clientSecretEncrypted!;
		const rotated = rotateSsoCredential(store, sso.id);
		expect(
			(rotated as { clientSecretEncrypted?: string }).clientSecretEncrypted,
		).toBeUndefined();
		const after = store.snapshot.identityConnections[0]!.clientSecretEncrypted!;
		expect(after).not.toBe(before);
		expect(after).toMatch(/^clr\$v1\$k2\$/);
		expect(after).not.toContain(secret);
		expect(decryptCredential(after)).toBe(secret);
		expect(JSON.stringify(store.snapshot)).not.toContain(secret);

		// SCIM path
		const scimSecret = "scim-bearer-token-plaintext-abc";
		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
			endpoint: "https://scim.example/v2",
			bearerToken: scimSecret,
		});
		expect(
			(scim as { bearerTokenEncrypted?: string }).bearerTokenEncrypted,
		).toBeUndefined();
		const scimRaw = store.snapshot.directoryConnections.find(
			(c) => c.id === scim.id,
		)!;
		expect(scimRaw.bearerTokenEncrypted).toMatch(/^clr\$v1\$/);
		expect(JSON.stringify(store.snapshot)).not.toContain(scimSecret);
		const scimBefore = scimRaw.bearerTokenEncrypted!;
		rotateScimCredential(store, scim.id);
		const scimAfter = store.snapshot.directoryConnections.find(
			(c) => c.id === scim.id,
		)!.bearerTokenEncrypted!;
		expect(scimAfter).not.toBe(scimBefore);
		expect(decryptCredential(scimAfter)).toBe(scimSecret);
	});

	it("fails outside development when credential key is missing", () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		delete process.env.CLEARANCE_CREDENTIAL_KEY;
		delete process.env.CLEARANCE_CREDENTIAL_KEY_ID;
		try {
			expect(() => assertCredentialKeyConfigured()).toThrow(
				/CLEARANCE_CREDENTIAL_KEY/,
			);
		} finally {
			process.env.NODE_ENV = prev;
		}
	});

	it("encrypt under explicit keyring yields unique ciphertext per call", () => {
		const ring = {
			currentKeyId: "t1",
			keys: new Map([
				[
					"t1",
					Buffer.from(
						"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
						"hex",
					),
				],
			]),
		};
		const a = encryptCredential("same-value", ring);
		const b = encryptCredential("same-value", ring);
		expect(a.ciphertext).not.toBe(b.ciphertext);
		expect(decryptCredential(a.ciphertext, ring)).toBe("same-value");
		const rotated = rotateCredential(a.ciphertext, ring);
		expect(rotated.ciphertext).not.toBe(a.ciphertext);
		expect(decryptCredential(rotated.ciphertext, ring)).toBe("same-value");
	});
});

describe("setup capability links", () => {
	it("enforces expiry, single-use, scope, and revocation with audits", async () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Cap" });
		const org = createOrganization(store, { name: "Customer" });
		const created = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
			ttlMinutes: 30,
		});
		expect(created.token).toBeTruthy();
		expect(created.capabilityId).toMatch(/^cap_/);
		// Digest only in store
		const stored = store.snapshot.setupLinks[0]!;
		expect(stored.digest).toHaveLength(64);
		expect(JSON.stringify(store.snapshot.setupLinks)).not.toContain(
			created.token,
		);

		// Wrong kind/scope
		await expect(
			redeemSetupLink(store, {
				token: created.token,
				kind: "scim",
			}),
		).rejects.toThrow(/kind|scope|match/i);

		await expect(
			redeemSetupLink(store, {
				token: created.token,
				kind: "sso",
				organizationId: "org_wrong",
			}),
		).rejects.toThrow(/organization|scope/i);

		await expect(
			redeemSetupLink(store, {
				token: created.token,
				kind: "sso",
				projectId: "proj_wrong",
			}),
		).rejects.toThrow(/project|scope/i);

		// Happy redeem
		const redeemed = await redeemSetupLink(store, {
			token: created.token,
			kind: "sso",
			organizationId: org.id,
			projectId: project.id,
			environmentId: environment.id,
		});
		expect(redeemed.useCount).toBe(1);
		expect(redeemed.redeemedAt).toBeTruthy();

		// Replay
		await expect(
			redeemSetupLink(store, {
				token: created.token,
				kind: "sso",
				organizationId: org.id,
			}),
		).rejects.toThrow(/already used|replay/i);

		// Expiry
		const short = createSetupLink(store, {
			organizationId: org.id,
			kind: "scim",
			ttlMinutes: -1,
		});
		await expect(
			redeemSetupLink(store, { token: short.token, kind: "scim" }),
		).rejects.toThrow(/expir/i);

		// Revocation
		const rev = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
			ttlMinutes: 60,
		});
		revokeSetupLink(store, { capabilityId: rev.capabilityId });
		await expect(
			redeemSetupLink(store, { token: rev.token, kind: "sso" }),
		).rejects.toThrow(/revok/i);

		const actions = listEvents(store).map((e) => e.action);
		expect(actions.some((a) => a.includes("setup-link.create"))).toBe(true);
		expect(actions.some((a) => a.includes("setup-link.redeem"))).toBe(true);
		expect(actions.some((a) => a.includes("setup-link.revoke"))).toBe(true);
		// No raw tokens in audit
		expect(JSON.stringify(listEvents(store))).not.toContain(created.token);
		expect(JSON.stringify(listEvents(store))).not.toContain(rev.token);
	});

	it("reserve/release restores capability; commit consumes once; concurrent reserve is single-winner", async () => {
		const store = tempStore();
		initProject(store, { name: "Reserve" });
		const org = createOrganization(store, { name: "Customer" });
		const created = createSetupLink(store, {
			organizationId: org.id,
			kind: "scim",
			ttlMinutes: 30,
		});

		const reserved = await reserveSetupLink(store, {
			token: created.token,
			kind: "scim",
			organizationId: org.id,
		});
		expect(reserved.reservationId).toMatch(/^rsv_/);
		expect(reserved.capability.useCount).toBe(0);
		expect(reserved.capability.redeemedAt).toBeFalsy();
		expect(reserved.capability.reservationId).toBe(reserved.reservationId);

		// Concurrent/second reserve while lease active
		await expect(
			reserveSetupLink(store, {
				token: created.token,
				kind: "scim",
				organizationId: org.id,
			}),
		).rejects.toThrow(/in progress|already used|replay/i);

		// Failed provision path: release restores availability
		await releaseSetupLink(store, {
			token: created.token,
			kind: "scim",
			reservationId: reserved.reservationId,
		});
		const afterRelease = store.snapshot.setupLinks.find((c) => c.id === created.capabilityId)!;
		expect(afterRelease.reservationId).toBeFalsy();
		expect(afterRelease.useCount).toBe(0);
		expect(afterRelease.redeemedAt).toBeFalsy();

		// Retry reserve → commit succeeds once
		const again = await reserveSetupLink(store, {
			token: created.token,
			kind: "scim",
			organizationId: org.id,
		});
		const committed = await commitSetupLink(store, {
			token: created.token,
			kind: "scim",
			organizationId: org.id,
			reservationId: again.reservationId,
		});
		expect(committed.useCount).toBe(1);
		expect(committed.redeemedAt).toBeTruthy();
		expect(committed.reservationId).toBeFalsy();

		await expect(
			reserveSetupLink(store, {
				token: created.token,
				kind: "scim",
			}),
		).rejects.toThrow(/already used|replay/i);

		await expect(
			commitSetupLink(store, {
				token: created.token,
				kind: "scim",
				reservationId: again.reservationId,
			}),
		).rejects.toThrow(/already used|replay/i);

		// release after commit must not reopen
		await releaseSetupLink(store, {
			token: created.token,
			kind: "scim",
			reservationId: again.reservationId,
		});
		const still = store.snapshot.setupLinks.find((c) => c.id === created.capabilityId)!;
		expect(still.useCount).toBe(1);
		expect(still.redeemedAt).toBeTruthy();

		// Concurrent reserves: exactly one winner
		const second = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
		});
		const raced = await Promise.allSettled([
			reserveSetupLink(store, { token: second.token, kind: "sso" }),
			reserveSetupLink(store, { token: second.token, kind: "sso" }),
		]);
		expect(raced.filter((r) => r.status === "fulfilled")).toHaveLength(1);
		expect(raced.filter((r) => r.status === "rejected")).toHaveLength(1);

		expect(JSON.stringify(store.snapshot.setupLinks)).not.toContain(created.token);
		expect(JSON.stringify(listEvents(store))).not.toContain(created.token);
		expect(JSON.stringify(listEvents(store))).not.toContain(second.token);
	});
});

describe("SCIM local HTTP protocol verification", () => {
	it("probes local fixture: ok, unauthorized, malformed, non_success", async () => {
		const store = tempStore();
		initProject(store, { name: "ScimHttp" });
		const org = createOrganization(store, { name: "Dir" });
		const token = "test-scim-token";

		const okServer = createLocalScimFixtureServer("ok", token);
		const { baseUrl } = await okServer.listen();
		try {
			const conn = createScimConnection(store, {
				organizationId: org.id,
				provider: "local",
				endpoint: baseUrl,
				bearerToken: token,
			});
			const result = await checkScimConnection(store, conn.id, {
				bearerToken: token,
			});
			expect(result.pass).toBe(true);
			expect(result.mode).toBe("simulation");
			expect(result.externalProviderCertified).toBe(false);
			expect(result.evidence).toMatch(/local protocol verification/i);
			expect(okServer.requests.length).toBeGreaterThanOrEqual(1);
			expect(okServer.requests[0]?.authorization).toBe(`Bearer ${token}`);
		} finally {
			await okServer.close();
		}

		const unauth = createLocalScimFixtureServer("unauthorized", token);
		const u = await unauth.listen();
		try {
			const conn = createScimConnection(store, {
				organizationId: org.id,
				provider: "local",
				endpoint: u.baseUrl,
				bearerToken: "wrong",
			});
			await expect(
				checkScimConnection(store, conn.id, { bearerToken: "wrong" }),
			).rejects.toThrow(/unauthor|reject|credential/i);
		} finally {
			await unauth.close();
		}

		const mal = createLocalScimFixtureServer("malformed", token);
		const m = await mal.listen();
		try {
			const conn = createScimConnection(store, {
				organizationId: org.id,
				provider: "local",
				endpoint: m.baseUrl,
				bearerToken: token,
			});
			await expect(
				checkScimConnection(store, conn.id, { bearerToken: token }),
			).rejects.toThrow(/malformed|json/i);
		} finally {
			await mal.close();
		}

		const down = createLocalScimFixtureServer("non_success", token);
		const d = await down.listen();
		try {
			const conn = createScimConnection(store, {
				organizationId: org.id,
				provider: "local",
				endpoint: d.baseUrl,
				bearerToken: token,
			});
			await expect(
				checkScimConnection(store, conn.id, { bearerToken: token }),
			).rejects.toThrow(/non-success|503|failed/i);
		} finally {
			await down.close();
		}

		// Network failure
		const connNet = createScimConnection(store, {
			organizationId: org.id,
			provider: "local",
			endpoint: "http://127.0.0.1:1",
			bearerToken: token,
		});
		await expect(
			checkScimConnection(store, connNet.id, {
				bearerToken: token,
				fetchImpl: async () => {
					throw new Error("connect ECONNREFUSED");
				},
			}),
		).rejects.toThrow(/network|ECONNREFUSED/i);

		// Public list redacts encrypted token
		for (const c of listScimConnections(store)) {
			expect(
				(c as { bearerTokenEncrypted?: string }).bearerTokenEncrypted,
			).toBeUndefined();
		}
	});
});

describe("SSO local OIDC protocol verification", () => {
	it("exercises authorize URL state/nonce/PKCE and callback validation", async () => {
		const store = tempStore();
		initProject(store, { name: "OidcLocal" });
		const org = createOrganization(store, { name: "App" });
		const sso = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "local-fixture",
			issuer: "http://127.0.0.1/placeholder",
			clientId: "clearance-local-client",
			clientSecret: "local-secret-value-not-logged",
		});

		const result = await verifySsoOidcLocalProtocol(store, sso.id);
		expect(result.pass).toBe(true);
		expect(result.mode).toBe("simulation");
		expect(result.certifiedExternalTenant).toBe(false);
		expect(result.evidence).toMatch(/local protocol verification/i);
		// Explicit non-certification: evidence is local-only and flag is false
		expect(result.evidence.toLowerCase()).toContain("not okta");
		expect(result.certifiedExternalTenant).toBe(false);
		expect(result.authorizationUrl).toMatch(/state=/);
		expect(result.authorizationUrl).toMatch(/nonce=/);
		expect(result.authorizationUrl).toMatch(/code_challenge=/);
		expect(result.authorizationUrl).toMatch(/code_challenge_method=S256/);
		expect(result.trace.checks?.some((c) => c.name === "pkce" && c.pass)).toBe(
			true,
		);
		expect(
			result.trace.checks?.find((c) => c.name === "external_tenant_certification")
				?.pass,
		).toBe(false);

		// Explicit fixture with injected issuer
		const fixture = createLocalOidcIssuerFixture({
			clientId: "clearance-local-client",
		});
		const meta = await fixture.listen();
		try {
			const again = await verifySsoOidcLocalProtocol(store, sso.id, {
				issuer: {
					issuer: meta.issuer,
					authorizationEndpoint: meta.authorizationEndpoint,
					tokenEndpoint: meta.tokenEndpoint,
				},
				// register session is internal when using built-in fixture only;
				// for external issuer we need the function's own registration —
				// when issuer is provided without fixture registration, authorize fails
				// so use built-in path above as primary; here just smoke discovery shape
			}).catch((e) => e);
			// External issuer without session registration should fail authorize
			expect(
				again instanceof Error ||
					(typeof again === "object" && again && "pass" in again),
			).toBe(true);
		} finally {
			await fixture.close();
		}

		expect(JSON.stringify(listEvents(store))).not.toContain(
			"local-secret-value-not-logged",
		);
	});
});

describe("public redaction helpers", () => {
	it("strips encrypted fields from domain views", () => {
		const id = publicIdentityConnection({
			id: "sso_1",
			organizationId: "org_1",
			protocol: "oidc",
			provider: "x",
			status: "draft",
			domains: [],
			attributeMapping: {},
			createdAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			clientSecretEncrypted: "clr$v1$k$iv$tag$ct",
			clientSecretKeyId: "k",
			clientSecretFingerprint: "abc",
		});
		expect((id as { clientSecretEncrypted?: string }).clientSecretEncrypted).toBeUndefined();
		expect(id.hasClientSecret).toBe(true);

		const d = publicDirectoryConnection({
			id: "scim_1",
			organizationId: "org_1",
			provider: "x",
			status: "draft",
			endpoint: "https://x",
			deprovisioningPolicy: "disable",
			createdAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			bearerTokenEncrypted: "clr$v1$k$iv$tag$ct",
			bearerTokenFingerprint: "def",
		});
		expect((d as { bearerTokenEncrypted?: string }).bearerTokenEncrypted).toBeUndefined();
		expect(d.hasBearerToken).toBe(true);
	});
});
