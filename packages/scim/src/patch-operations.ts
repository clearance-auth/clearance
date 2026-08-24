import type { User } from "@clearance/runtime";
import { getUserFullName } from "./mappings";
import { SCIMAPIError } from "./scim-error";

type Operation = {
	op: "add" | "remove" | "replace";
	value: any;
	path?: string;
};

type Mapping = {
	target: string;
	resource: "user" | "account";
	map: (user: User, op: Operation, resources: Resources) => any;
};

type Resources = {
	user: Record<string, any>;
	account: Record<string, any>;
};

/**
 * Limits PATCH request complexity before any persistence work begins. These
 * are deliberately exported so deployments and tests can share the exact
 * contract rather than duplicating magic numbers.
 */
export const SCIM_USER_PATCH_LIMITS = {
	maxOperations: 100,
	maxDepth: 32,
	maxNodes: 1_000,
	maxStringBytes: 8 * 1024,
	maxCollectionEntries: 100,
} as const;

const invalidPatchRequest = () =>
	new SCIMAPIError("BAD_REQUEST", {
		detail: "SCIM PATCH request exceeds supported complexity limits",
	});

const identity = (user: User, op: Operation, resources: Resources) => {
	return op.value;
};

const lowerCase = (user: User, op: Operation, resources: Resources) => {
	return op.value.toLowerCase();
};

const givenName = (user: User, op: Operation, resources: Resources) => {
	const currentName = (resources.user.name as string) ?? user.name;
	const familyName = currentName.split(" ").slice(1).join(" ").trim();
	const givenName = op.value;

	return getUserFullName(user.email, {
		givenName,
		familyName,
	});
};

const familyName = (user: User, op: Operation, resources: Resources) => {
	const currentName = (resources.user.name as string) ?? user.name;
	const givenName = (
		currentName.split(" ").slice(0, -1).join(" ") || currentName
	).trim();
	const familyName = op.value;
	return getUserFullName(user.email, {
		givenName,
		familyName,
	});
};

const active = (user: User, op: Operation, resources: Resources) => {
	// SCIM `active:false` deactivates the user; map it to the admin plugin's
	// enforced `banned` state (`banned = !active`). The handler requires the
	// admin plugin and revokes sessions on deactivation.
	return op.value === false || op.value === "false";
};

const userPatchMappings: Record<string, Mapping> = {
	"/active": { resource: "user", target: "banned", map: active },
	"/name/formatted": { resource: "user", target: "name", map: identity },
	"/name/givenName": { resource: "user", target: "name", map: givenName },
	"/name/familyName": {
		resource: "user",
		target: "name",
		map: familyName,
	},
	"/externalId": {
		resource: "account",
		target: "accountId",
		map: identity,
	},
	"/userName": { resource: "user", target: "email", map: lowerCase },
};

const normalizePath = (path: string): string => {
	const withoutLeadingSlash = path.startsWith("/") ? path.slice(1) : path;
	return `/${withoutLeadingSlash.replaceAll(".", "/")}`;
};

const isNestedObject = (value: unknown): value is Record<string, unknown> => {
	return typeof value === "object" && value !== null && !Array.isArray(value);
};

const applyMapping = (
	user: User,
	resources: Resources,
	path: string,
	value: unknown,
	op: "add" | "replace",
) => {
	const normalizedPath = normalizePath(path);
	const mapping = userPatchMappings[normalizedPath];

	if (!mapping) {
		return;
	}

	const newValue = mapping.map(
		user,
		{
			op,
			value,
			path: normalizedPath,
		},
		resources,
	);

	if (op === "add" && mapping.resource === "user") {
		const currentValue = (user as Record<string, unknown>)[mapping.target];
		if (currentValue === newValue) {
			return;
		}
	}

	resources[mapping.resource][mapping.target] = newValue;
};

const applyPatchValue = (
	user: User,
	resources: Resources,
	value: unknown,
	op: "add" | "replace",
	path?: string | undefined,
) => {
	const pending: Array<{ value: unknown; path?: string }> = [{ value, path }];

	while (pending.length > 0) {
		const current = pending.pop();
		if (!current) break;

		if (isNestedObject(current.value)) {
			for (const [key, nestedValue] of Object.entries(current.value)) {
				pending.push({
					value: nestedValue,
					path: current.path ? `${current.path}.${key}` : key,
				});
			}
		} else if (current.path) {
			applyMapping(user, resources, current.path, current.value, op);
		}
	}
};

/** Validate arbitrary PATCH values iteratively, avoiding stack exhaustion. */
export const assertUserPatchWithinLimits = (operations: Operation[]) => {
	if (operations.length > SCIM_USER_PATCH_LIMITS.maxOperations) {
		throw invalidPatchRequest();
	}

	let nodes = 0;
	const seen = new WeakSet<object>();
	const pending: Array<{ value: unknown; depth: number }> = [];

	for (const operation of operations) {
		pending.push({ value: operation.path, depth: 0 });
		pending.push({ value: operation.value, depth: 0 });
	}

	while (pending.length > 0) {
		const current = pending.pop();
		if (!current) break;
		nodes += 1;
		if (nodes > SCIM_USER_PATCH_LIMITS.maxNodes) throw invalidPatchRequest();

		if (typeof current.value === "string") {
			if (new TextEncoder().encode(current.value).byteLength > SCIM_USER_PATCH_LIMITS.maxStringBytes) {
				throw invalidPatchRequest();
			}
			continue;
		}

		if (!current.value || typeof current.value !== "object") continue;
		if (current.depth >= SCIM_USER_PATCH_LIMITS.maxDepth || seen.has(current.value)) {
			throw invalidPatchRequest();
		}
		seen.add(current.value);

		if (Array.isArray(current.value)) {
			if (current.value.length > SCIM_USER_PATCH_LIMITS.maxCollectionEntries) {
				throw invalidPatchRequest();
			}
			for (const entry of current.value) {
				pending.push({ value: entry, depth: current.depth + 1 });
			}
			continue;
		}

		const entries = Object.entries(current.value);
		if (entries.length > SCIM_USER_PATCH_LIMITS.maxCollectionEntries) {
			throw invalidPatchRequest();
		}
		for (const [key, entry] of entries) {
			pending.push({ value: key, depth: current.depth + 1 });
			pending.push({ value: entry, depth: current.depth + 1 });
		}
	}
};

export const buildUserPatch = (user: User, operations: Operation[]) => {
	const userPatch: Record<string, any> = {};
	const accountPatch: Record<string, any> = {};
	const resources: Resources = { user: userPatch, account: accountPatch };

	for (const operation of operations) {
		if (operation.op !== "add" && operation.op !== "replace") {
			continue;
		}

		applyPatchValue(
			user,
			resources,
			operation.value,
			operation.op,
			operation.path,
		);
	}

	return resources;
};
