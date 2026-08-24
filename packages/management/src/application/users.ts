import {
	createUser as createSnapshotUser,
	deleteUser as deleteSnapshotUser,
	disableUser as disableSnapshotUser,
	inspectUser,
	listUsers,
	parseUserStatusInput,
	updateUser as updateSnapshotUser,
} from "../services/core.js";
import { ClearanceError } from "../services/errors.js";
import { appendAuditEvent } from "../services/audit.js";
import { newId, nowIso } from "../store/json-store.js";
import { advancingPrincipalUpdatedAt } from "../store/store-v2-principals.js";
import type { ManagementStore } from "../store/types.js";
import type { User } from "../types/resources.js";
import { withManagementUnitOfWork } from "../store/unit-of-work.js";
import type { AuthRuntimeGateway } from "./auth-runtime-gateway.js";
import type { OperationContext } from "./context.js";
import type {
	CreateUserInput,
	CreateUserResult,
	DisableUserInput,
	DisableUserResult,
	UpdateUserInput,
	UpdateUserResult,
} from "./management-application.js";

type NormalizedCreateUserInput = {
	email: string;
	name: string;
	password?: string;
	dryRun: boolean;
};

function requireRelationalPrincipalMutation(store: ManagementStore) {
	if (typeof store.mutateCoordinated !== "function") {
		throw new ClearanceError({
			code: "STORE_V2_PRINCIPAL_MUTATION_REQUIRED",
			message: "Relational principal authority requires coordinated Postgres mutations.",
			stage: "users.mutate",
			status: 500,
		});
	}
	return store.mutateCoordinated.bind(store);
}

function principalNotFound(stage: string): ClearanceError {
	return new ClearanceError({
		code: "USER_NOT_FOUND",
		message: "User not found",
		stage,
		status: 404,
	});
}

function requirePrincipalWrite<T>(value: T | null, stage: string): T {
	if (value === null) throw principalNotFound(stage);
	return value;
}

async function createRelationalUser(
	store: ManagementStore,
	context: OperationContext,
	input: NormalizedCreateUserInput,
): Promise<User> {
	const mutate = requireRelationalPrincipalMutation(store);
	return mutate(async ({ data, principals }) => {
		if (!principals) throw principalNotFound("users.create");
		const now = nowIso();
		const principal = await principals.insert({
			id: newId("user"),
			projectId: context.scope.projectId,
			environmentId: context.scope.environmentId,
			email: input.email,
			name: input.name,
			status: "active",
			createdAt: now,
			updatedAt: now,
		});
		appendAuditEvent(data, {
			actor: context.actor,
			action: "users.create",
			subjectType: "principal",
			subjectId: principal.id,
			outcome: "success",
			source: context.source,
			projectId: principal.projectId,
			environmentId: principal.environmentId,
			message: `Created user ${principal.email}`,
		});
		return principal;
	});
}

async function updateRelationalUser(
	store: ManagementStore,
	context: OperationContext,
	input: UpdateUserInput,
	status: "active" | "disabled" | undefined,
): Promise<User> {
	const hasName = input.name !== undefined;
	const hasEmail = input.email !== undefined;
	if (!hasName && !hasEmail && status === undefined) {
		throw new ClearanceError({
			code: "USER_UPDATE_EMPTY",
			message: "At least one of name, email, or status is required",
			stage: "users.update",
			status: 400,
		});
	}
	const name = hasName ? String(input.name).trim() : undefined;
	const email = hasEmail ? String(input.email).trim().toLowerCase() : undefined;
	if (hasName && !name) throw new ClearanceError({ code: "USER_NAME_REQUIRED", message: "Name must not be empty", stage: "users.update", status: 400 });
	if (hasEmail && !email) throw new ClearanceError({ code: "USER_EMAIL_REQUIRED", message: "Email must not be empty", stage: "users.update", status: 400 });
	const mutate = requireRelationalPrincipalMutation(store);
	return mutate(async ({ data, principals }) => {
		if (!principals) throw principalNotFound("users.update");
		const current = await principals.getById({ scope: context.scope, id: input.id });
		if (!current) throw principalNotFound("users.update");
		if (email && email !== current.email.toLowerCase()) {
			const conflict = await principals.findActiveByEmail({ scope: context.scope, email });
			if (conflict && conflict.id !== current.id) {
				throw new ClearanceError({ code: "USER_EXISTS", message: `User ${email} already exists`, stage: "users.update", status: 409 });
			}
		}
		const next: User = {
			...current,
			...(name === undefined ? {} : { name }),
			...(email === undefined ? {} : { email }),
			...(status === undefined ? {} : { status }),
			updatedAt: advancingPrincipalUpdatedAt({ proposedUpdatedAt: nowIso(), storedUpdatedAt: current.updatedAt }),
		};
		const updated = requirePrincipalWrite(
			await principals.update(next, { expectedUpdatedAt: current.updatedAt }),
			"users.update",
		);
		appendAuditEvent(data, {
			actor: context.actor,
			action: "users.update",
			subjectType: "principal",
			subjectId: updated.id,
			outcome: "success",
			source: context.source,
			projectId: updated.projectId,
			environmentId: updated.environmentId,
			message: `Updated user ${updated.email}`,
			metadata: { fields: [...(hasName ? ["name"] : []), ...(hasEmail ? ["email"] : []), ...(status === undefined ? [] : ["status"])] },
		});
		return updated;
	});
}

async function disableRelationalUser(
	store: ManagementStore,
	context: OperationContext,
	id: string,
): Promise<User> {
	const mutate = requireRelationalPrincipalMutation(store);
	return mutate(async ({ data, principals }) => {
		if (!principals) throw principalNotFound("users.disable");
		const current = await principals.getById({ scope: context.scope, id });
		if (!current) throw principalNotFound("users.disable");
		const now = nowIso();
		let revokedSessions = 0;
		for (const session of data.sessions) {
			if (session.principalId === id && session.status === "active") {
				session.status = "revoked";
				session.revokedAt = now;
				revokedSessions += 1;
			}
		}
		if (current.status === "disabled") return current;
		const updated = requirePrincipalWrite(
			await principals.disable({
				scope: context.scope,
				id,
				updatedAt: advancingPrincipalUpdatedAt({ proposedUpdatedAt: now, storedUpdatedAt: current.updatedAt }),
				expectedUpdatedAt: current.updatedAt,
			}),
			"users.disable",
		);
		appendAuditEvent(data, {
			actor: context.actor,
			action: "users.disable",
			subjectType: "principal",
			subjectId: id,
			outcome: "success",
			source: context.source,
			projectId: updated.projectId,
			environmentId: updated.environmentId,
			message: `Disabled user ${updated.email}`,
			metadata: { revokedSessions, idempotent: false },
		});
		return updated;
	});
}

async function deleteRelationalUser(
	store: ManagementStore,
	context: OperationContext,
	id: string,
): Promise<User> {
	const mutate = requireRelationalPrincipalMutation(store);
	return mutate(async ({ data, principals }) => {
		if (!principals) throw principalNotFound("users.delete");
		const current = await principals.getById({ scope: context.scope, id });
		if (!current) throw principalNotFound("users.delete");
		const now = nowIso();
		let revokedSessions = 0;
		for (const session of data.sessions) {
			if (session.principalId === id && session.status === "active") {
				session.status = "revoked";
				session.revokedAt = now;
				revokedSessions += 1;
			}
		}
		for (const membership of data.memberships) {
			if (membership.principalId === id && membership.status === "active") {
				membership.status = "removed";
				membership.updatedAt = now;
			}
		}
		const deleted = requirePrincipalWrite(
			await principals.delete({
				scope: context.scope,
				id,
				updatedAt: advancingPrincipalUpdatedAt({ proposedUpdatedAt: now, storedUpdatedAt: current.updatedAt }),
				expectedUpdatedAt: current.updatedAt,
			}),
			"users.delete",
		);
		appendAuditEvent(data, {
			actor: context.actor,
			action: "users.delete",
			subjectType: "principal",
			subjectId: id,
			outcome: "success",
			source: context.source,
			projectId: deleted.projectId,
			environmentId: deleted.environmentId,
			message: `Deleted user ${deleted.email}`,
			metadata: { revokedSessions },
		});
		return deleted;
	});
}

function normalizeInput(input: CreateUserInput): NormalizedCreateUserInput {
	if (typeof input.email !== "string" || !input.email.trim()) {
		throw new ClearanceError({
			code: "USER_EMAIL_REQUIRED",
			message: "Email is required.",
			stage: "users.create",
			status: 400,
		});
	}
	if (typeof input.name !== "string" || !input.name.trim()) {
		throw new ClearanceError({
			code: "USER_NAME_REQUIRED",
			message: "Name is required.",
			stage: "users.create",
			status: 400,
		});
	}

	return {
		email: input.email.trim().toLowerCase(),
		name: input.name.trim(),
		...(typeof input.password === "string" && input.password.length > 0
			? { password: input.password }
			: {}),
		dryRun: input.dryRun === true,
	};
}

async function assertEmailAvailable(
	store: ManagementStore,
	context: OperationContext,
	email: string,
): Promise<void> {
	const exists = store.storeV2Principals?.authoritative
		? (await store.storeV2Principals.findActiveByEmail({
				scope: context.scope,
				email,
			})) !== null
		: listUsers(store, { scope: context.scope }).some(
				(user) => user.email.toLowerCase() === email && user.status !== "deleted",
			);
	if (exists) {
		throw new ClearanceError({
			code: "USER_EXISTS",
			message: `User ${email} already exists`,
			stage: "users.create",
			status: 409,
		});
	}
}

async function prepareInput(
	store: ManagementStore,
	context: OperationContext,
	input: CreateUserInput,
): Promise<NormalizedCreateUserInput> {
	const normalized = normalizeInput(input);
	await assertEmailAvailable(store, context, normalized.email);
	return normalized;
}

async function inspectUserForUseCase(
	store: ManagementStore,
	id: string,
	context: OperationContext,
): Promise<ReturnType<typeof inspectUser>> {
	if (!store.storeV2Principals?.authoritative) {
		return inspectUser(store, id, context.scope);
	}
	const user = await store.storeV2Principals.getById({
		scope: context.scope,
		id,
	});
	if (!user) {
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: "User not found",
			stage: "users.inspect",
			status: 404,
		});
	}
	return user;
}

export async function createUserUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	input: CreateUserInput,
): Promise<CreateUserResult> {
	const normalized = await prepareInput(store, context, input);
	if (normalized.dryRun) {
		return { dryRun: true, email: normalized.email, name: normalized.name };
	}

	const provisioned = authRuntime
		? await authRuntime.users.provision(context, {
				email: normalized.email,
				name: normalized.name,
				...(normalized.password ? { password: normalized.password } : {}),
			})
		: store.storeV2Principals?.authoritative
			? { user: await createRelationalUser(store, context, normalized) }
			: {
				user: await withManagementUnitOfWork(store, (unitOfWork) =>
					createSnapshotUser(unitOfWork, {
						email: normalized.email,
						name: normalized.name,
						projectId: context.scope.projectId,
						environmentId: context.scope.environmentId,
						actor: context.actor,
						source: context.source,
					})
				),
			};
	return {
		dryRun: false,
		user: provisioned.user,
		...(provisioned.passwordSetup
			? { passwordSetup: provisioned.passwordSetup }
			: {}),
	};
}

export async function updateUserUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	input: UpdateUserInput,
): Promise<UpdateUserResult> {
	const status = parseUserStatusInput(input.status, "users.update");
	if (input.dryRun === true) {
		await inspectUserForUseCase(store, input.id, context);
		return {
			dryRun: true,
			id: input.id,
			...(input.name !== undefined ? { name: input.name } : {}),
			...(input.email !== undefined ? { email: input.email } : {}),
			...(status !== undefined ? { status } : {}),
		};
	}

	const user = authRuntime
		? await authRuntime.users.updateCoordinated(context, input.id, {
				...(input.name !== undefined ? { name: input.name } : {}),
				...(input.email !== undefined ? { email: input.email } : {}),
				...(status !== undefined ? { status } : {}),
			})
		: store.storeV2Principals?.authoritative
			? await updateRelationalUser(store, context, input, status)
			: await withManagementUnitOfWork(store, (unitOfWork) =>
				updateSnapshotUser(unitOfWork, input.id, {
					...(input.name !== undefined ? { name: input.name } : {}),
					...(input.email !== undefined ? { email: input.email } : {}),
					...(status !== undefined ? { status } : {}),
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				})
				);
	return { dryRun: false, user };
}

export async function disableUserUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	input: DisableUserInput,
): Promise<DisableUserResult> {
	if (input.dryRun === true) {
		return { dryRun: true, user: await inspectUserForUseCase(store, input.id, context) };
	}

	const user = authRuntime
		? await authRuntime.users.disableCoordinated(context, input.id)
		: store.storeV2Principals?.authoritative
			? await disableRelationalUser(store, context, input.id)
			: await withManagementUnitOfWork(store, (unitOfWork) =>
				disableSnapshotUser(unitOfWork, input.id, {
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				})
				);
	return { dryRun: false, user };
}

export async function deleteUserUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	id: string,
) {
	return authRuntime
		? await authRuntime.users.deleteCoordinated(context, id)
		: store.storeV2Principals?.authoritative
			? await deleteRelationalUser(store, context, id)
			: await withManagementUnitOfWork(store, (unitOfWork) =>
				deleteSnapshotUser(unitOfWork, id, {
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
			);
}
