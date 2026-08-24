import { randomUUID } from "node:crypto";
import { expect, vi } from "vitest";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import type { User } from "../../types";
import type { Passkey } from "./types";

const PASSWORD = "adapter-passkey-password";

async function seedPasskey(
	context: any,
	userId: string,
	suffix: string,
): Promise<Passkey> {
	return context.adapter.create({
		model: "passkey",
		data: {
			userId,
			name: suffix,
			credentialID: `adapter-credential-${suffix}-${randomUUID()}`,
			publicKey: "unused-password-proof-key",
			userHandle: `adapter-handle-${suffix}-${randomUUID()}`,
			counter: 0,
			deviceType: "singleDevice",
			backedUp: false,
			createdAt: new Date(),
			updatedAt: new Date(),
		},
	}) as Promise<Passkey>;
}

async function rawDelete(
	auth: any,
	origin: string,
	headers: Headers,
	body: unknown,
): Promise<Response> {
	const requestHeaders = new Headers(headers);
	requestHeaders.set("content-type", "application/json");
	return auth.handler(
		new Request(`${origin}/api/auth/passkey/delete`, {
			method: "POST",
			headers: requestHeaders,
			body: JSON.stringify(body),
		}),
	);
}

export async function assertPasskeyDeletionLifecycleOnAdapter(
	auth: any,
	origin: string,
) {
	const email = `adapter-passkey-${randomUUID()}@example.test`;
	await auth.api.signUpEmail({
		body: { email, password: PASSWORD, name: "Adapter passkey deletion" },
	});
	const signIn = await auth.api.signInEmail({
		body: { email, password: PASSWORD },
		asResponse: true,
	});
	const headers = convertSetCookieToCookie(signIn.headers);
	headers.set("origin", origin);
	const before = await auth.api.getSession({ headers });
	if (!before) throw new Error("adapter deletion session missing");
	const context = await auth.$context;
	const target = await seedPasskey(context, before.user.id, "success");

	const success = await auth.api.deletePasskey({
		headers,
		body: {
			id: target.id,
			proof: { type: "password", password: PASSWORD },
		},
		asResponse: true,
	});
	expect(success.status).toBe(200);
	expect(success.headers.get("set-cookie")).toContain("session_token");
	const replacementHeaders = convertSetCookieToCookie(success.headers);
	replacementHeaders.set("origin", origin);
	const replacement = await auth.api.getSession({ headers: replacementHeaders });
	expect(replacement).not.toBeNull();
	expect(new Date(replacement!.session.expiresAt).getTime()).toBe(
		new Date(before.session.expiresAt).getTime(),
	);
	await expect(auth.api.getSession({ headers })).resolves.toBeNull();
	await expect(
		context.adapter.findOne({
			model: "passkey",
			where: [{ field: "id", value: target.id }],
		}),
	).resolves.toBeNull();

	const rollbackTarget = await seedPasskey(
		context,
		before.user.id,
		"replacement-rollback",
	);
	const beforeRollback = (await context.adapter.findOne({
		model: "user",
		where: [{ field: "id", value: before.user.id }],
	})) as (User & Record<string, unknown>) | null;
	const originalCreateSession = context.internalAdapter.createSession;
	const createSession = vi
		.spyOn(context.internalAdapter, "createSession")
		.mockImplementationOnce(async (...args: Parameters<typeof originalCreateSession>) => {
			await originalCreateSession(...args);
			throw new Error("injected adapter replacement failure");
		});
	let failed: Response;
	try {
		failed = await rawDelete(auth, origin, replacementHeaders, {
			id: rollbackTarget.id,
			proof: { type: "password", password: PASSWORD },
		});
	} finally {
		createSession.mockRestore();
	}
	expect(failed.status).toBeGreaterThanOrEqual(500);
	expect(failed.headers.get("set-cookie")).toBeNull();
	await expect(
		context.adapter.findOne({
			model: "passkey",
			where: [{ field: "id", value: rollbackTarget.id }],
		}),
	).resolves.not.toBeNull();
	await expect(
		auth.api.getSession({ headers: replacementHeaders }),
	).resolves.not.toBeNull();
	const afterRollback = (await context.adapter.findOne({
		model: "user",
		where: [{ field: "id", value: before.user.id }],
	})) as (User & Record<string, unknown>) | null;
	expect(afterRollback?.passkeySessionGeneration).toBe(
		beforeRollback?.passkeySessionGeneration,
	);
	const active = await context.internalAdapter.listSessions(before.user.id, {
		onlyActiveSessions: true,
	});
	expect(active).toHaveLength(1);
	expect(active[0]?.id).toBe(replacement!.session.id);
}
