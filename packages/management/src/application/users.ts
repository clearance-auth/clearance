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
import type { ManagementStore } from "../store/types.js";
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

function assertEmailAvailable(
	store: ManagementStore,
	context: OperationContext,
	email: string,
): void {
	const exists = listUsers(store, { scope: context.scope }).some(
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

function prepareInput(
	store: ManagementStore,
	context: OperationContext,
	input: CreateUserInput,
): NormalizedCreateUserInput {
	const normalized = normalizeInput(input);
	assertEmailAvailable(store, context, normalized.email);
	return normalized;
}

export async function createUserUseCase(
	store: ManagementStore,
	authRuntime: AuthRuntimeGateway | undefined,
	context: OperationContext,
	input: CreateUserInput,
): Promise<CreateUserResult> {
	const normalized = prepareInput(store, context, input);
	if (normalized.dryRun) {
		return { dryRun: true, email: normalized.email, name: normalized.name };
	}

	const provisioned = authRuntime
		? await authRuntime.users.provision(context, {
				email: normalized.email,
				name: normalized.name,
				...(normalized.password ? { password: normalized.password } : {}),
			})
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
		inspectUser(store, input.id, context.scope);
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
		return { dryRun: true, user: inspectUser(store, input.id, context.scope) };
	}

	const user = authRuntime
		? await authRuntime.users.disableCoordinated(context, input.id)
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
		: await withManagementUnitOfWork(store, (unitOfWork) =>
				deleteSnapshotUser(unitOfWork, id, {
					actor: context.actor,
					source: context.source,
					scope: context.scope,
				}),
			);
}
