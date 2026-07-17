import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	ClearancePlugin,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyReaderInput,
	RuntimeAuthenticationPolicyReaderResult,
} from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import { runWithRequestState } from "@clearance/core/context";
import type { Endpoint } from "@clearance/call";
import { createOTP } from "@clearance/utils/otp";
import { afterEach, describe, expect, it } from "vitest";
import { dispatchAuthEndpoint } from "../../../api/dispatch";
import { init } from "../../../context/init";
import { symmetricDecrypt, symmetricEncrypt } from "../../../crypto";
import { getMigrations } from "../../../db/get-migration";
import {
	attachInternalAuthenticationPolicy,
	type InternalRuntimeAuthenticationPolicyBinding,
} from "../../../internal/authentication-policy";
import { createInternalSessionIssuanceContext } from "../../../internal/session-issuance-context";
import { schema as passkeySchema } from "../../passkey/schema";
import { twoFactor } from "..";
import type { TwoFactorTable } from "../types";

const databases: DatabaseSync[] = [];
const identity = Object.freeze({
	projectId: "managed-totp-project",
	environmentId: "managed-totp-environment",
});

function policy(totpOnly = false): RuntimeAuthenticationPolicy {
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
		minimumAssurance: "multi_factor",
		allowedFactors: { passkey: !totpOnly, totp: true },
		trustedDevice: { enabled: false, maxAgeSeconds: 0 },
		assuranceMaxAgeSeconds: 300,
	};
}

async function setup(input?: {
	customTable?: boolean;
	passkey?: boolean;
	totpOnlyPolicy?: boolean;
	verifiedSecret?: string;
	legacyNull?: boolean;
	twoFactorEnabled?: boolean;
}) {
	const database = new DatabaseSync(":memory:");
	databases.push(database);
	let revision = "7";
	const table = input?.customTable ? "managedTotpFactor" : "twoFactor";
	const twoFactorPlugin = twoFactor({
		twoFactorTable: table,
		accountLockout: { enabled: true, maxFailedAttempts: 2 },
	});
	const plugins = [
		...(input?.passkey
			? [{ id: "passkey", schema: passkeySchema } satisfies ClearancePlugin]
			: []),
		twoFactorPlugin,
	];
	const options = {
		baseURL: "http://localhost:3000",
		secret: "managed-totp-remediation-secret-with-sufficient-length",
		database,
		plugins,
	} satisfies ClearanceOptions;
	const effectivePolicy = policy(input?.totpOnlyPolicy);
	const reader = {
		async readForSubject(
			subjectInput: RuntimeAuthenticationPolicyReaderInput,
		): Promise<RuntimeAuthenticationPolicyReaderResult> {
			return {
				scope: identity,
				subjectId: subjectInput.subjectId,
				revision,
				environment: effectivePolicy,
				organizationMembership: null,
				organizationOverride: null,
				effective: effectivePolicy,
			};
		},
	} satisfies InternalRuntimeAuthenticationPolicyBinding["reader"];
	attachInternalAuthenticationPolicy(options, { identity, reader });
	await (await getMigrations(options)).runMigrations();
	const context = await init(options);
	const user = await context.internalAdapter.createUser({
		email: `managed-totp-${databases.length}@example.test`,
		name: "Managed TOTP user",
	});
	if (input?.verifiedSecret) {
		await context.adapter.create<TwoFactorTable>({
			model: table,
			data: {
				userId: user.id,
				secret: await symmetricEncrypt({
					key: context.secretConfig,
					data: input.verifiedSecret,
				}),
				backupCodes: await symmetricEncrypt({
					key: context.secretConfig,
					data: JSON.stringify(["saved-recovery-code"]),
				}),
				verified: (input.legacyNull ? null : true) as never,
				failedVerificationCount: 0,
				activeVerificationReservations: "[]",
				lastUsedTotpCounter: -1,
				trustDeviceGeneration: "managed-totp-trust-generation",
			},
		});
		if (input.twoFactorEnabled !== false) {
			await context.internalAdapter.updateUser(user.id, {
				twoFactorEnabled: true,
			});
		}
	}
	if (input?.passkey) {
		const now = new Date();
		await context.adapter.create({
			model: "passkey",
			data: {
				userId: user.id,
				name: "Existing passkey",
				credentialID: `credential-${user.id}`,
				publicKey: "public-key",
				userHandle: `handle-${user.id}`,
				counter: 0,
				deviceType: "multiDevice",
				backedUp: true,
				createdAt: now,
				updatedAt: now,
			},
		});
	}
	return {
		context,
		user,
		table,
		begin: twoFactorPlugin.endpoints!.beginStagedTOTP!,
		verify: twoFactorPlugin.endpoints!.verifyStagedTOTP!,
		setRevision(value: string) {
			revision = value;
		},
	};
}

function issuanceEndpoint(userId: string) {
	return createAuthEndpoint(
		"/managed-totp/start",
		{ method: "POST" },
		async (ctx) => {
			await ctx.context.internalAdapter.createSession(
				userId,
				false,
				undefined,
				false,
				createInternalSessionIssuanceContext({
					purpose: "interactive",
					subjectId: userId,
					evidence: [{ kind: "primary", primaryMethod: "password" }],
				}),
			);
			return ctx.json({ unexpected: true });
		},
	);
}

async function dispatch(
	context: Awaited<ReturnType<typeof init>>,
	endpoint: Endpoint,
	cookie?: string,
	body: Record<string, unknown> = {},
): Promise<Response> {
	const headers = new Headers({ "content-type": "application/json" });
	if (cookie) headers.set("cookie", cookie);
	return runWithRequestState(
		new WeakMap(),
		async () =>
			(await dispatchAuthEndpoint(endpoint, {
				context,
				headers,
				body,
				request: new Request(`http://localhost:3000${endpoint.path}`, {
					method: "POST",
					headers,
					body: JSON.stringify(body),
				}),
				asResponse: true,
			})) as Response,
	);
}

function cookie(
	response: Response,
	name = "managed_authentication_remediation",
) {
	const values = response.headers.getSetCookie();
	const value = values.find((entry) =>
		entry.slice(0, entry.indexOf("=")).endsWith(name)
	);
	expect(value).toBeTruthy();
	return value!.split(";", 1)[0]!;
}

function rawBearer(cookieHeader: string) {
	const signed = decodeURIComponent(
		cookieHeader.slice(cookieHeader.indexOf("=") + 1),
	);
	return signed.slice(0, signed.lastIndexOf("."));
}

async function start(runtime: Awaited<ReturnType<typeof setup>>) {
	const response = await dispatch(
		runtime.context,
		issuanceEndpoint(runtime.user.id),
	);
	expect(response.status).toBe(403);
	return cookie(response);
}

async function rows(runtime: Awaited<ReturnType<typeof setup>>) {
	return runtime.context.adapter.findMany<TwoFactorTable>({
		model: runtime.table,
	});
}

afterEach(() => {
	for (const database of databases.splice(0)) database.close();
});

describe.sequential("managed TOTP remediation", () => {
	it("enrolls exactly one encrypted TOTP and rejects replay", async () => {
		const runtime = await setup();
		const initial = await start(runtime);
		const options = await dispatch(runtime.context, runtime.begin, initial);
		expect(options.status).toBe(200);
		expect(options.headers.get("cache-control")).toBe("no-store");
		expect(options.headers.get("pragma")).toBe("no-cache");
		const body = (await options.json()) as {
			mode: string;
			totpURI: string;
			backupCodes: string[];
		};
		expect(body.mode).toBe("enrollment");
		expect(body.backupCodes).toHaveLength(10);
		const successor = cookie(options);
		const factorRows = await rows(runtime);
		expect(factorRows).toHaveLength(1);
		expect(factorRows[0]!.verified).toBe(false);
		const secret = await symmetricDecrypt({
			key: runtime.context.secretConfig,
			data: factorRows[0]!.secret,
		});
		expect(body.totpURI).not.toContain(secret);
		expect(factorRows[0]!.secret).not.toContain(secret);
		expect(JSON.stringify(factorRows)).not.toContain(rawBearer(successor));

		const verified = await dispatch(
			runtime.context,
			runtime.verify,
			successor,
			{
				code: await createOTP(secret).totp(),
			},
		);
		expect(verified.status).toBe(200);
		expect(verified.headers.get("cache-control")).toBe("no-store");
		expect(verified.headers.get("pragma")).toBe("no-cache");
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect((await rows(runtime))[0]!.verified).toBe(true);
		const replay = await dispatch(runtime.context, runtime.verify, successor, {
			code: await createOTP(secret).totp(),
		});
		expect(replay.status).toBe(401);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
	});

	it("uses a legacy-null TOTP in verification-only mode despite a stale user marker", async () => {
		const secret = "verified-custom-table-totp-secret";
		const runtime = await setup({
			customTable: true,
			verifiedSecret: secret,
			twoFactorEnabled: false,
		});
		await runtime.context.adapter.update<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
			update: { verified: null as never },
		});
		const options = await dispatch(
			runtime.context,
			runtime.begin,
			await start(runtime),
		);
		expect(options.status).toBe(200);
		const body = (await options.json()) as Record<string, unknown>;
		expect(body).toMatchObject({ mode: "verification" });
		expect(body).not.toHaveProperty("totpURI");
		const successor = cookie(options);
		const results = await Promise.all([
			dispatch(runtime.context, runtime.verify, successor, {
				code: await createOTP(secret).totp(),
			}),
			dispatch(runtime.context, runtime.verify, successor, {
				code: await createOTP(secret).totp(),
			}),
		]);
		expect(results.filter((response) => response.status === 200)).toHaveLength(
			1,
		);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect((await rows(runtime))[0]!.verified).toBe(true);
		expect(
			(await runtime.context.internalAdapter.findUserById(runtime.user.id) as {
				twoFactorEnabled?: boolean;
			}).twoFactorEnabled,
		).toBe(true);
	});

	it("uses an enabled legacy-null TOTP in verification-only mode", async () => {
		const secret = "enabled-legacy-null-totp-secret";
		const runtime = await setup({ verifiedSecret: secret, legacyNull: true });
		const response = await dispatch(
			runtime.context,
			runtime.begin,
			await start(runtime),
		);
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ mode: "verification" });
	});

	it("replaces an explicitly disabled TOTP instead of accepting it as proof", async () => {
		const runtime = await setup({
			verifiedSecret: "disabled-legacy-null-totp-secret",
			twoFactorEnabled: false,
		});
		await runtime.context.adapter.update<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
			update: { verified: false },
		});
		const options = await dispatch(
			runtime.context,
			runtime.begin,
			await start(runtime),
		);
		expect(options.status, await options.clone().text()).toBe(200);
		expect(await options.clone().json()).toMatchObject({ mode: "enrollment" });
		const factor = (await rows(runtime))[0]!;
		expect(factor.verified).toBe(false);
		const replacementSecret = await symmetricDecrypt({
			key: runtime.context.secretConfig,
			data: factor.secret,
		});
		expect(replacementSecret).not.toBe("disabled-legacy-null-totp-secret");
		const verified = await dispatch(
			runtime.context,
			runtime.verify,
			cookie(options),
			{ code: await createOTP(replacementSecret).totp() },
		);
		expect(verified.status, await verified.clone().text()).toBe(200);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
	});

	it("burns invalid verification and durably records the account failure", async () => {
		const secret = "invalid-attempt-totp-secret";
		const runtime = await setup({ verifiedSecret: secret });
		const options = await dispatch(
			runtime.context,
			runtime.begin,
			await start(runtime),
		);
		const successor = cookie(options);
		const invalid = await dispatch(runtime.context, runtime.verify, successor, {
			code: "saved-recovery-code",
		});
		expect(invalid.status).toBe(401);
		expect(await invalid.json()).toMatchObject({ code: "INVALID_CODE" });
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		expect((await rows(runtime))[0]!.failedVerificationCount).toBe(1);
		const replay = await dispatch(runtime.context, runtime.verify, successor, {
			code: await createOTP(secret).totp(),
		});
		expect(replay.status).toBe(401);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("enforces durable lockout across separately started staged flows", async () => {
		const secret = "durable-lockout-totp-secret";
		const runtime = await setup({ verifiedSecret: secret });
		for (let attempt = 0; attempt < 2; attempt++) {
			const options = await dispatch(
				runtime.context,
				runtime.begin,
				await start(runtime),
			);
			const invalid = await dispatch(
				runtime.context,
				runtime.verify,
				cookie(options),
				{ code: "not-a-totp-code" },
			);
			expect(invalid.status).toBe(401);
			expect(await invalid.json()).toMatchObject({ code: "INVALID_CODE" });
		}
		const factor = (await rows(runtime))[0]!;
		expect(factor.failedVerificationCount).toBe(2);
		expect(factor.activeVerificationReservations).toBe("[]");
		expect(factor.lockedUntil).toBeInstanceOf(Date);

		const thirdOptions = await dispatch(
			runtime.context,
			runtime.begin,
			await start(runtime),
		);
		const denied = await dispatch(
			runtime.context,
			runtime.verify,
			cookie(thirdOptions),
			{ code: await createOTP(secret).totp() },
		);
		expect(denied.status).toBe(429);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("blocks enrollment when an eligible passkey already exists", async () => {
		const runtime = await setup({ passkey: true });
		const response = await dispatch(
			runtime.context,
			runtime.begin,
			await start(runtime),
		);
		expect(response.status).toBe(401);
		expect(await rows(runtime)).toHaveLength(0);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("does not let a passkey block TOTP-only policy enrollment", async () => {
		const runtime = await setup({ passkey: true, totpOnlyPolicy: true });
		const options = await dispatch(
			runtime.context,
			runtime.begin,
			await start(runtime),
		);
		expect(options.status, await options.clone().text()).toBe(200);
		const factor = (await rows(runtime))[0]!;
		const secret = await symmetricDecrypt({
			key: runtime.context.secretConfig,
			data: factor.secret,
		});
		const verified = await dispatch(
			runtime.context,
			runtime.verify,
			cookie(options),
			{ code: await createOTP(secret).totp() },
		);
		expect(verified.status, await verified.clone().text()).toBe(200);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
	});

	it("rolls enrollment and session back on policy revision drift while leaving the stage burned", async () => {
		const runtime = await setup();
		const options = await dispatch(
			runtime.context,
			runtime.begin,
			await start(runtime),
		);
		await options.json();
		const factor = (await rows(runtime))[0]!;
		const secret = await symmetricDecrypt({
			key: runtime.context.secretConfig,
			data: factor.secret,
		});
		const successor = cookie(options);
		runtime.setRevision("8");
		const drifted = await dispatch(runtime.context, runtime.verify, successor, {
			code: await createOTP(secret).totp(),
		});
		expect(drifted.status).toBe(401);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		expect((await rows(runtime))[0]).toMatchObject({
			verified: false,
			failedVerificationCount: 0,
			activeVerificationReservations: "[]",
		});
		const replay = await dispatch(runtime.context, runtime.verify, successor, {
			code: await createOTP(secret).totp(),
		});
		expect(replay.status).toBe(401);
	});
});
