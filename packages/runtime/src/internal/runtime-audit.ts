import { getAsyncLocalStorage } from "@clearance/core/async_hooks";
import { isTransactionActive } from "@clearance/core/context";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import type { AsyncLocalStorage } from "@clearance/core/async_hooks";

const MAX_IDENTIFIER_LENGTH = 256;
const MAX_ACTION_LENGTH = 160;
const MAX_MESSAGE_LENGTH = 1_024;
const MAX_CORRELATION_ID_LENGTH = 128;
const MAX_OPERATION_ID_LENGTH = 256;
const MAX_ROUTE_LENGTH = 512;
const MAX_METHOD_LENGTH = 16;
const MAX_IP_LENGTH = 64;
const MAX_USER_AGENT_LENGTH = 512;
const MAX_METADATA_DEPTH = 4;
const MAX_METADATA_VALUES = 64;
const MAX_METADATA_KEYS = 64;
const MAX_METADATA_BYTES = 8_192;
const SENSITIVE_METADATA_KEY =
	/(?:authorization|cookie|credential|password|secret|token|bearer|jwt|api[-_]?key)/i;
const ACTION = /^[a-z][a-z0-9_]{0,63}(?:\.[a-z][a-z0-9_]{0,63})+$/;

export class InvalidRuntimeAuditError extends Error {
	readonly code = "RUNTIME_AUDIT_INVALID" as const;

	constructor() {
		super("Runtime audit authority received an invalid binding or draft");
		this.name = "InvalidRuntimeAuditError";
	}
}

export class RuntimeAuditTransactionRequiredError extends Error {
	readonly code = "RUNTIME_AUDIT_TRANSACTION_REQUIRED" as const;

	constructor() {
		super("Runtime audit append requires an active transaction-bound adapter");
		this.name = "RuntimeAuditTransactionRequiredError";
	}
}

export type InternalRuntimeAuditIdentity = Readonly<{
	projectId: string;
	environmentId: string;
}>;

export type InternalRuntimeAuditRequestContext = Readonly<{
	correlationId: string;
	operationId: string;
	route: string;
	method: string;
	clientIp: string | null;
	userAgent: string | null;
}>;

export type InternalRuntimeAuditDraft = Readonly<{
	actor: string;
	action: string;
	subjectType: string | null;
	subjectId: string | null;
	outcome: "success" | "failure" | "pending";
	source: "system" | "sso" | "scim";
	organizationId: string | null;
	message: string;
	metadata: Record<string, unknown>;
	request: InternalRuntimeAuditRequestContext;
}>;

export type InternalRuntimeAuditBinding = Readonly<{
	identity: InternalRuntimeAuditIdentity;
	append: (
		transaction: DBTransactionAdapter,
		draft: InternalRuntimeAuditDraft,
	) => Promise<void>;
}>;

export function classifyRuntimeInteractiveAuthenticationRoute(
	route: string,
):
	| "password"
	| "passkey"
	| "federated"
	| "email_otp"
	| "magic_link"
	| "anonymous"
	| "sso"
	| null {
	switch (route) {
		case "/sign-in/email":
		case "/sign-in/username":
		case "/sign-in/phone-number":
			return "password";
		case "/sign-in/email-otp":
			return "email_otp";
		case "/passkey/verify-authentication":
			return "passkey";
		case "/magic-link/verify":
			return "magic_link";
		case "/sign-in/social":
			return "federated";
		case "/sign-in/anonymous":
			return "anonymous";
		case "/sso/callback":
			return "sso";
	}
	if (/^\/callback\/[^/]+$/.test(route)) return "federated";
	if (/^\/oauth2\/callback\/[^/]+$/.test(route)) return "federated";
	if (/^\/sso\/callback\/[^/]+$/.test(route)) return "sso";
	if (/^\/sso\/saml2\/callback\/[^/]+$/.test(route)) return "sso";
	if (/^\/sso\/saml2\/sp\/acs\/[^/]+$/.test(route)) return "sso";
	return null;
}

const bindings = new WeakMap<object, InternalRuntimeAuditBinding>();
const capturedBindings = new WeakSet<object>();
let requestContextStorage: Promise<
	AsyncLocalStorage<InternalRuntimeAuditRequestContext>
> | undefined;

function invalid(): never {
	throw new InvalidRuntimeAuditError();
}

function dataObject(value: unknown): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return invalid();
	}
	let prototype: object | null;
	let keys: (string | symbol)[];
	try {
		prototype = Object.getPrototypeOf(value);
		keys = Reflect.ownKeys(value);
	} catch {
		return invalid();
	}
	if (prototype !== Object.prototype && prototype !== null) invalid();
	const record: Record<string, unknown> = Object.create(null);
	for (const key of keys) {
		if (typeof key === "symbol") invalid();
		let descriptor: PropertyDescriptor | undefined;
		try {
			descriptor = Object.getOwnPropertyDescriptor(value, key);
		} catch {
			return invalid();
		}
		if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
			invalid();
		}
		record[key] = descriptor.value;
	}
	return record;
}

function exactObject(
	value: unknown,
	keys: readonly string[],
): Record<string, unknown> {
	const record = dataObject(value);
	const actual = Object.keys(record);
	if (
		actual.length !== keys.length ||
		actual.some((key) => !keys.includes(key))
	) {
		invalid();
	}
	return record;
}

function string(
	value: unknown,
	maximum: number,
	{ allowEmpty = false }: { allowEmpty?: boolean } = {},
): string {
	if (
		typeof value !== "string" ||
		value.length > maximum ||
		(!allowEmpty && value.length === 0) ||
		value.trim() !== value ||
		/[\0\r\n]/.test(value)
	) {
		invalid();
	}
	return value;
}

function identifier(value: unknown): string {
	return string(value, MAX_IDENTIFIER_LENGTH);
}

function nullableIdentifier(value: unknown): string | null {
	return value === null ? null : identifier(value);
}

function identity(value: unknown): InternalRuntimeAuditIdentity {
	const input = exactObject(value, ["projectId", "environmentId"]);
	return Object.freeze({
		projectId: identifier(input.projectId),
		environmentId: identifier(input.environmentId),
	});
}

function requestContext(value: unknown): InternalRuntimeAuditRequestContext {
	const input = exactObject(value, [
		"correlationId",
		"operationId",
		"route",
		"method",
		"clientIp",
		"userAgent",
	]);
	const route = string(input.route, MAX_ROUTE_LENGTH);
	if (!route.startsWith("/")) invalid();
	const method = string(input.method, MAX_METHOD_LENGTH);
	if (!/^[A-Z]+$/.test(method)) invalid();
	const clientIp = input.clientIp === null ? null : string(input.clientIp, MAX_IP_LENGTH);
	const userAgent =
		input.userAgent === null
			? null
			: string(input.userAgent, MAX_USER_AGENT_LENGTH, { allowEmpty: true });
	return Object.freeze({
		correlationId: string(input.correlationId, MAX_CORRELATION_ID_LENGTH),
		operationId: string(input.operationId, MAX_OPERATION_ID_LENGTH),
		route,
		method,
		clientIp,
		userAgent,
	});
}

function metadata(value: unknown): Record<string, unknown> {
	const seen = new Set<object>();
	let values = 0;
	let keys = 0;
	const copy = (current: unknown, depth: number): unknown => {
		if (depth > MAX_METADATA_DEPTH || ++values > MAX_METADATA_VALUES) invalid();
		if (
			current === null ||
			typeof current === "boolean" ||
			typeof current === "string"
		) {
			if (typeof current === "string" && current.length > MAX_MESSAGE_LENGTH) {
				invalid();
			}
			return current;
		}
		if (typeof current === "number") {
			if (!Number.isFinite(current)) invalid();
			return current;
		}
		if (typeof current !== "object" || seen.has(current)) invalid();
		seen.add(current);
		try {
			if (Array.isArray(current)) {
				return Object.freeze(current.map((entry) => copy(entry, depth + 1)));
			}
			const record = dataObject(current);
			const normalized: Record<string, unknown> = Object.create(null);
			for (const [key, entry] of Object.entries(record)) {
				if (
					++keys > MAX_METADATA_KEYS ||
					key.length === 0 ||
					key.length > MAX_IDENTIFIER_LENGTH ||
					SENSITIVE_METADATA_KEY.test(key)
				) {
					invalid();
				}
				normalized[key] = copy(entry, depth + 1);
			}
			return Object.freeze(normalized);
		} finally {
			seen.delete(current);
		}
	};
	const normalized = copy(value, 0);
	if (
		typeof normalized !== "object" ||
		normalized === null ||
		Array.isArray(normalized)
	) {
		invalid();
	}
	let bytes: number;
	try {
		bytes = new TextEncoder().encode(JSON.stringify(normalized)).byteLength;
	} catch {
		return invalid();
	}
	if (bytes > MAX_METADATA_BYTES) invalid();
	return normalized as Record<string, unknown>;
}

function draft(value: unknown): InternalRuntimeAuditDraft {
	const input = exactObject(value, [
		"actor",
		"action",
		"subjectType",
		"subjectId",
		"outcome",
		"source",
		"organizationId",
		"message",
		"metadata",
		"request",
	]);
	const action = string(input.action, MAX_ACTION_LENGTH);
	if (!ACTION.test(action)) invalid();
	const subjectType = nullableIdentifier(input.subjectType);
	const subjectId = nullableIdentifier(input.subjectId);
	if ((subjectType === null) !== (subjectId === null)) invalid();
	if (
		input.outcome !== "success" &&
		input.outcome !== "failure" &&
		input.outcome !== "pending"
	) {
		invalid();
	}
	if (input.source !== "system" && input.source !== "sso" && input.source !== "scim") {
		invalid();
	}
	return Object.freeze({
		actor: identifier(input.actor),
		action,
		subjectType,
		subjectId,
		outcome: input.outcome,
		source: input.source,
		organizationId: nullableIdentifier(input.organizationId),
		message: string(input.message, MAX_MESSAGE_LENGTH),
		metadata: metadata(input.metadata),
		request: requestContext(input.request),
	});
}

function ensureRequestContextStorage(): Promise<
	AsyncLocalStorage<InternalRuntimeAuditRequestContext>
> {
	if (!requestContextStorage) {
		requestContextStorage = getAsyncLocalStorage().then(
			(AsyncLocalStorage) => new AsyncLocalStorage<InternalRuntimeAuditRequestContext>(),
		);
	}
	return requestContextStorage;
}

function optionBinding(
	target: object,
): InternalRuntimeAuditBinding | undefined {
	let options: unknown;
	try {
		options = (target as { options?: unknown }).options;
	} catch {
		return undefined;
	}
	return typeof options === "object" && options !== null
		? bindings.get(options)
		: undefined;
}

function bindingFor(target: object): InternalRuntimeAuditBinding | undefined {
	return bindings.get(target) ?? optionBinding(target);
}

export async function runWithRuntimeAuditRequestContext<T>(
	context: InternalRuntimeAuditRequestContext,
	fn: () => T,
): Promise<Awaited<T>> {
	const normalized = requestContext(context);
	return (await ensureRequestContextStorage()).run(normalized, fn) as Awaited<T>;
}

export async function getRuntimeAuditRequestContext(): Promise<
	InternalRuntimeAuditRequestContext | undefined
> {
	return (await ensureRequestContextStorage()).getStore();
}

export function attachInternalRuntimeAudit<Target extends object>(
	target: Target,
	binding: InternalRuntimeAuditBinding,
): Target {
	if (bindings.has(target)) invalid();
	const input = exactObject(binding, ["identity", "append"]);
	if (typeof input.append !== "function") invalid();
	const captured = Object.freeze({
		identity: identity(input.identity),
		append: input.append.bind(binding) as InternalRuntimeAuditBinding["append"],
	});
	capturedBindings.add(captured);
	bindings.set(target, captured);
	return target;
}

export function attachCapturedInternalRuntimeAudit<Target extends object>(
	target: Target,
	binding: InternalRuntimeAuditBinding,
): Target {
	if (!capturedBindings.has(binding)) invalid();
	const existing = bindings.get(target);
	if (existing) {
		if (existing !== binding) invalid();
		return target;
	}
	bindings.set(target, binding);
	return target;
}

export function readInternalRuntimeAudit(
	target: object,
): InternalRuntimeAuditBinding | undefined {
	return bindingFor(target);
}

export async function appendInternalRuntimeAudit(
	targetOrTransaction: object,
	input: InternalRuntimeAuditDraft,
): Promise<void> {
	const transaction = targetOrTransaction as DBTransactionAdapter;
	if (
		typeof transaction.rawTransactionQuery !== "function" ||
		!(await isTransactionActive(transaction))
	) {
		throw new RuntimeAuditTransactionRequiredError();
	}
	const binding = bindingFor(transaction);
	if (!binding) invalid();
	await binding.append(transaction, draft(input));
}
