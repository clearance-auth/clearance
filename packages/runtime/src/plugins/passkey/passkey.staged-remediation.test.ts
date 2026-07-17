import { serializeSignedCookie } from "@clearance/call";
import { runWithTransaction } from "@clearance/core/context";
import { describe, expect, it } from "vitest";
import {
  attachInternalAuthenticationPolicy,
  type InternalRuntimeAuthenticationPolicyBinding,
} from "../../internal/authentication-policy";
import {
  attachStagedAuthenticationContinuation,
  digestStagedAuthenticationPolicy,
  issueInitialStagedAuthenticationCapability,
  takeStagedAuthenticationContinuation,
} from "../../internal/staged-authentication-context";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import { getTestInstance } from "../../test-utils/test-instance";
import { admin } from "../admin";
import { twoFactor } from "../two-factor";
import { passkey } from ".";
import { createVirtualAuthenticator } from "./virtual-authenticator.test-utils";

const ORIGIN = "http://localhost:3300";
const managedIdentity = Object.freeze({
  projectId: "staged-passkey-project",
  environmentId: "staged-passkey-environment",
});

function managedPolicy(passkey = true, totp = false) {
  return {
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
    minimumAssurance: "multi_factor" as const,
    allowedFactors: { passkey, totp },
    trustedDevice: { enabled: false, maxAgeSeconds: 0 },
    assuranceMaxAgeSeconds: 300,
  };
}

async function setup() {
  const instance = await getTestInstance(
    { baseURL: ORIGIN, plugins: [passkey()] },
    { port: 3300 },
  );
  const signedIn = await instance.signInWithTestUser();
  signedIn.headers.set("origin", ORIGIN);
  return { ...instance, signedIn };
}

async function setupManaged(input?: { customTwoFactor?: boolean; totp?: boolean }) {
  let revision = "1";
  let effective = managedPolicy(true, input?.totp);
	const twoFactorTable = input?.customTwoFactor
		? "stagedCustomTwoFactor"
		: "twoFactor";
	const options = {
		baseURL: ORIGIN,
		plugins: [
			admin(),
			passkey(),
			...(input?.totp ? [twoFactor({ twoFactorTable })] : []),
		],
	};
  attachInternalAuthenticationPolicy(options, {
    identity: managedIdentity,
    reader: {
      async readForSubject(input) {
        return {
          scope: managedIdentity,
          subjectId: input.subjectId,
          revision,
          environment: effective,
          organizationMembership: null,
          organizationOverride: null,
          effective,
        };
      },
    } satisfies InternalRuntimeAuthenticationPolicyBinding["reader"],
  });
  const instance = await getTestInstance(options, {
    port: 3300,
    disableTestUser: true,
  });
  const context = await instance.auth.$context;
  const user = await context.internalAdapter.createUser({
    email: `staged-managed-${Math.random()}@example.test`,
    name: "Staged managed user",
  });
  return {
    instance,
    user,
    policyInput: () => ({
      revision,
      digest: digestStagedAuthenticationPolicy(effective),
    }),
    setRevision(value: string) {
      revision = value;
    },
    setEffective(value: ReturnType<typeof managedPolicy>) {
      effective = value;
    },
		twoFactorTable,
  };
}

async function stagedHeaders(
  instance: Awaited<ReturnType<typeof getTestInstance>>,
  userId: string,
  policy?: Readonly<{ revision: string; digest: Promise<string> }>,
	allowedFactors: readonly ("passkey" | "totp")[] = ["passkey"],
): Promise<Headers> {
  const context = await instance.auth.$context;
  const now = new Date();
  const failure = new Error("staged remediation test");
  attachStagedAuthenticationContinuation(failure, {
    subjectId: userId,
    projectId: "staged-passkey-project",
    environmentId: "staged-passkey-environment",
    organizationId: null,
    policyRevision: policy?.revision ?? "1",
    policyDigest: policy ? await policy.digest : "a".repeat(43),
    primaryMethod: "password",
    primaryAt: now,
    dontRememberMe: false,
    allowedFactors,
    expiresAt: new Date(now.getTime() + 120_000),
  });
  const seed = takeStagedAuthenticationContinuation(failure);
  if (!seed) throw new Error("staged seed was not issued");
  const issued = await runWithTransaction(
    context.adapter,
    () => issueInitialStagedAuthenticationCapability(context, seed),
  );
  const signed = await serializeSignedCookie(
    issued.cookie.name,
    issued.bearer,
    context.secret,
    issued.cookie.attributes,
  );
  return new Headers({
    origin: ORIGIN,
    cookie: signed.slice(0, signed.indexOf(";")),
  });
}

describe("passkey staged remediation", () => {
  it("rejects missing, forged, and wrong-stage cookies before issuing a ceremony", async () => {
    const { auth, signedIn } = await setup();
    await expect(
      (auth.api as any).generatePasskeyRemediationRegistrationOptions({
        headers: new Headers({ origin: ORIGIN }),
      }),
    ).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
    const forged = new Headers({
      origin: ORIGIN,
      cookie: "managed_authentication_remediation=forged.value",
    });
    await expect(
      (auth.api as any).generatePasskeyRemediationRegistrationOptions({
        headers: forged,
      }),
    ).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
    const initial = await stagedHeaders({ auth } as never, signedIn.user.id);
    await expect(
      (auth.api as any).generatePasskeyRemediationAuthenticationOptions({
        headers: initial,
      }),
    ).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
  });

  it("creates the first session only after a digest-bound staged registration commits", async () => {
    const { auth, signedIn } = await setup();
    const initial = await stagedHeaders({ auth } as never, signedIn.user.id);
    const optionsResponse = await (auth.api as any)
      .generatePasskeyRemediationRegistrationOptions({
        headers: initial,
        asResponse: true,
      });
    expect(optionsResponse.status).toBe(200);
    expect(optionsResponse.headers.get("cache-control")).toBe("no-store");
    expect(optionsResponse.headers.get("pragma")).toBe("no-cache");
    const options = await optionsResponse.json();
    const successor = convertSetCookieToCookie(optionsResponse.headers);
    successor.set("origin", ORIGIN);
    const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
    const verified = await (auth.api as any)
      .verifyPasskeyRemediationRegistration({
        headers: successor,
        body: {
          response: authenticator.registrationResponse(options.challenge),
        },
        asResponse: true,
      });
    expect(verified.status).toBe(200);
    expect(verified.headers.get("cache-control")).toBe("no-store");
    expect(verified.headers.get("pragma")).toBe("no-cache");
    expect(verified.headers.get("set-cookie")).toContain("session_token");
    const context = await auth.$context;
    const stored = await context.adapter.findMany({
      model: "passkeyChallenge",
    });
    expect(JSON.stringify(stored)).not.toContain(options.challenge);
  });

  it("globally forbids staged enrollment once an eligible passkey exists", async () => {
    const { auth, signedIn } = await setup();
    const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
    const normalOptions = await auth.api.generatePasskeyRegistrationOptions({
      headers: signedIn.headers,
    });
    await auth.api.verifyPasskeyRegistration({
      headers: signedIn.headers,
      body: {
        response: authenticator.registrationResponse(normalOptions.challenge),
      },
    });
    const initial = await stagedHeaders({ auth } as never, signedIn.user.id);
    await expect(
      (auth.api as any).generatePasskeyRemediationRegistrationOptions({
        headers: initial,
      }),
    ).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
  });

  it("burns the staged capability on an invalid proof and cannot create a session on replay", async () => {
    const { auth, signedIn } = await setup();
    const context = await auth.$context;
    const before = await context.adapter.count({ model: "session" });
    const initial = await stagedHeaders({ auth } as never, signedIn.user.id);
    const optionsResponse = await (auth.api as any)
      .generatePasskeyRemediationRegistrationOptions({
        headers: initial,
        asResponse: true,
      });
    const options = await optionsResponse.json();
    const successor = convertSetCookieToCookie(optionsResponse.headers);
    successor.set("origin", ORIGIN);
    const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
    await expect(
      (auth.api as any).verifyPasskeyRemediationRegistration({
        headers: successor,
        body: {
          response: authenticator.registrationResponse("wrong-challenge"),
        },
      }),
    ).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
    await expect(
      (auth.api as any).verifyPasskeyRemediationRegistration({
        headers: successor,
        body: {
          response: authenticator.registrationResponse(options.challenge),
        },
      }),
    ).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
    expect(await context.adapter.count({ model: "session" })).toBe(before);
  });

	it("creates one staged-authentication session when concurrent assertions race the counter", async () => {
    const { auth, signedIn } = await setup();
    const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
    const registration = await auth.api.generatePasskeyRegistrationOptions({
      headers: signedIn.headers,
    });
    await auth.api.verifyPasskeyRegistration({
      headers: signedIn.headers,
      body: {
        response: authenticator.registrationResponse(registration.challenge),
      },
    });
    const firstInitial = await stagedHeaders(
      { auth } as never,
      signedIn.user.id,
    );
    const secondInitial = await stagedHeaders(
      { auth } as never,
      signedIn.user.id,
    );
    const firstOptionsResponse = await (auth.api as any)
      .generatePasskeyRemediationAuthenticationOptions({
        headers: firstInitial,
        asResponse: true,
      });
    const secondOptionsResponse = await (auth.api as any)
      .generatePasskeyRemediationAuthenticationOptions({
        headers: secondInitial,
        asResponse: true,
      });
    const firstOptions = await firstOptionsResponse.json();
    const secondOptions = await secondOptionsResponse.json();
    const firstHeaders = convertSetCookieToCookie(firstOptionsResponse.headers);
    const secondHeaders = convertSetCookieToCookie(
      secondOptionsResponse.headers,
    );
    firstHeaders.set("origin", ORIGIN);
    secondHeaders.set("origin", ORIGIN);
    const context = await auth.$context;
    const before = await context.adapter.count({ model: "session" });
    const outcomes = await Promise.allSettled([
      (auth.api as any).verifyPasskeyRemediationAuthentication({
        headers: firstHeaders,
        body: {
          response: authenticator.authenticationResponse(
            firstOptions.challenge,
            registration.user.id,
            1,
          ),
        },
      }),
      (auth.api as any).verifyPasskeyRemediationAuthentication({
        headers: secondHeaders,
        body: {
          response: authenticator.authenticationResponse(
            secondOptions.challenge,
            registration.user.id,
            1,
          ),
        },
      }),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled"))
      .toHaveLength(1);
		expect(await context.adapter.count({ model: "session" })).toBe(before + 1);
	});

	it("rolls back registration when a legacy verified custom-table TOTP appears after options", async () => {
		const runtime = await setupManaged({ customTwoFactor: true, totp: true });
		const { instance, user } = runtime;
		const initial = await stagedHeaders(
			instance as never,
			user.id,
			runtime.policyInput(),
			["passkey", "totp"],
		);
		const optionsResponse = await (instance.auth.api as any)
			.generatePasskeyRemediationRegistrationOptions({
				headers: initial,
				asResponse: true,
			});
		const options = await optionsResponse.json();
		const successor = convertSetCookieToCookie(optionsResponse.headers);
		successor.set("origin", ORIGIN);
		const context = await instance.auth.$context;
		await context.adapter.create<Record<string, unknown>>({
			model: runtime.twoFactorTable,
			data: {
				userId: user.id,
				secret: "legacy-ciphertext",
				backupCodes: "legacy-backup-codes",
				verified: null,
			},
		});
		await context.adapter.update({
			model: "user",
			where: [{ field: "id", value: user.id }],
			update: { twoFactorEnabled: false },
		});
		const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		await expect(
			(instance.auth.api as any).verifyPasskeyRemediationRegistration({
				headers: successor,
				body: {
					response: authenticator.registrationResponse(options.challenge),
				},
			}),
		).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
		expect(await context.adapter.count({ model: "passkey" })).toBe(0);
		expect(await context.adapter.count({ model: "session" })).toBe(0);
	});

	it("commits exact managed staged assurance, credential, and one session", async () => {
		const runtime = await setupManaged();
		const { instance, user } = runtime;
		const initial = await stagedHeaders(
			instance as never,
			user.id,
			runtime.policyInput(),
		);
		const optionsResponse = await (instance.auth.api as any)
			.generatePasskeyRemediationRegistrationOptions({
				headers: initial,
				asResponse: true,
			});
		const options = await optionsResponse.json();
		const successor = convertSetCookieToCookie(optionsResponse.headers);
		successor.set("origin", ORIGIN);
		const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		const response = await (instance.auth.api as any)
			.verifyPasskeyRemediationRegistration({
				headers: successor,
				body: { response: authenticator.registrationResponse(options.challenge) },
				asResponse: true,
			});
		expect(response.status).toBe(200);
		const context = await instance.auth.$context;
		expect(await context.adapter.count({ model: "passkey" })).toBe(1);
		expect(await context.adapter.count({ model: "session" })).toBe(1);
		const session = await context.adapter.findOne<Record<string, unknown>>({
			model: "session",
			where: [{ field: "userId", value: user.id }],
		});
		expect(session).toMatchObject({
			authenticationAssuranceVersion: 1,
			authenticationPolicyProjectId: managedIdentity.projectId,
			authenticationPolicyEnvironmentId: managedIdentity.environmentId,
			authenticationPrimaryMethod: "password",
			authenticationFactorMethod: "passkey",
			authenticationPolicyOrganizationId: null,
			authenticationPolicyRevision: "1",
			authenticationRecoveryRestricted: false,
		});
		expect(session?.authenticationPrimaryAt).toBeInstanceOf(Date);
		expect(session?.authenticationFactorAt).toBeInstanceOf(Date);
	});

	it("rejects a subject banned after staged options without credential or session", async () => {
		const runtime = await setupManaged();
		const { instance, user } = runtime;
		const initial = await stagedHeaders(
			instance as never,
			user.id,
			runtime.policyInput(),
		);
		const optionsResponse = await (instance.auth.api as any)
			.generatePasskeyRemediationRegistrationOptions({
				headers: initial,
				asResponse: true,
			});
		const options = await optionsResponse.json();
		const successor = convertSetCookieToCookie(optionsResponse.headers);
		successor.set("origin", ORIGIN);
		const context = await instance.auth.$context;
		await context.adapter.update({
			model: "user",
			where: [{ field: "id", value: user.id }],
			update: { banned: true },
		});
		const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
		await expect(
			(instance.auth.api as any).verifyPasskeyRemediationRegistration({
				headers: successor,
				body: { response: authenticator.registrationResponse(options.challenge) },
			}),
		).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
		expect(await context.adapter.count({ model: "passkey" })).toBe(0);
		expect(await context.adapter.count({ model: "session" })).toBe(0);
	});

	it.each([
    [
      "revision",
      (runtime: Awaited<ReturnType<typeof setupManaged>>) =>
        runtime.setRevision("2"),
    ],
    [
      "policy digest",
      (runtime: Awaited<ReturnType<typeof setupManaged>>) =>
        runtime.setEffective(managedPolicy(false)),
    ],
  ])(
    "creates neither credential nor session when the final managed %s drifts",
    async (_kind, drift) => {
      const runtime = await setupManaged();
      const { instance, user } = runtime;
      const initial = await stagedHeaders(
        instance as never,
        user.id,
        runtime.policyInput(),
      );
      const optionsResponse = await (instance.auth.api as any)
        .generatePasskeyRemediationRegistrationOptions({
          headers: initial,
          asResponse: true,
        });
      const options = await optionsResponse.json();
      const successor = convertSetCookieToCookie(optionsResponse.headers);
      successor.set("origin", ORIGIN);
      drift(runtime);
      const authenticator = createVirtualAuthenticator(ORIGIN, "localhost");
      await expect(
        (instance.auth.api as any).verifyPasskeyRemediationRegistration({
          headers: successor,
          body: {
            response: authenticator.registrationResponse(options.challenge),
          },
        }),
      ).rejects.toMatchObject({ body: { code: "REMEDIATION_FAILED" } });
      const context = await instance.auth.$context;
      expect(await context.adapter.count({ model: "passkey" })).toBe(0);
      expect(await context.adapter.count({ model: "session" })).toBe(0);
    },
  );
});
