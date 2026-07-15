import type { ManagementStore } from "../store/types.js";
import { inspectOrganization } from "./core.js";
import { ClearanceError } from "./errors.js";
import {
	resolveOperatorScope,
	type ResourceScope,
} from "./scope.js";

type ScopedEnterpriseConnection = {
	id: string;
	organizationId: string;
};

/** Shared fail-closed identity/directory connection lookup under org scope. */
export function resolveEnterpriseConnection<T extends ScopedEnterpriseConnection>(
	store: ManagementStore,
	id: string,
	input: {
		connections: readonly T[];
		scope?: ResourceScope;
		stage: string;
		label: "SSO" | "SCIM";
		idRequiredCode: string;
		notFoundCode: string;
	},
): T {
	const connectionId = id?.trim();
	if (!connectionId) {
		throw new ClearanceError({
			code: input.idRequiredCode,
			message: `${input.label} connection id is required`,
			stage: input.stage,
			status: 400,
		});
	}
	const connection = input.connections.find(
		(candidate) => candidate.id === connectionId,
	);
	if (!connection) {
		throw connectionNotFound(input, connectionId);
	}
	try {
		inspectOrganization(
			store,
			connection.organizationId,
			input.scope ?? resolveOperatorScope(store),
		);
	} catch (error) {
		if (
			error instanceof ClearanceError &&
			(error.code === "ORG_NOT_FOUND" || error.status === 404)
		) {
			throw connectionNotFound(input, connectionId);
		}
		throw error;
	}
	return connection;
}

function connectionNotFound(
	input: { label: "SSO" | "SCIM"; notFoundCode: string; stage: string },
	id: string,
): ClearanceError {
	return new ClearanceError({
		code: input.notFoundCode,
		message: `${input.label} connection ${id} not found`,
		stage: input.stage,
		status: 404,
	});
}
