import type {
	VaultAuthorizationAssignment,
	VaultAuthorizationRole,
	VaultAuthorizationSubject,
	VaultAuditEvent,
	VaultAuditPage,
	VaultConnectionDisableResult,
	VaultCredentialMutation,
	VaultEffectiveAuthorization,
	VaultReadiness,
	VaultScimConnection,
	VaultScimCreatePreview,
	VaultScimMutationPreview,
	VaultScimRotation,
	VaultScimSecretMutation,
	VaultScimTestResult,
	VaultSsoConnection,
	VaultSsoCreatePreview,
	VaultSsoMutationPreview,
	VaultSsoTestResult,
	VaultInvitation,
	InvitationStatus,
	VaultOrganization,
	VaultPasskey,
	VaultServiceAccount,
	VaultServiceAccountCredential,
	VaultSession,
	VaultSessionState,
	VaultTwoFactorMethod,
	VaultUser,
} from "./client";

type JsonRecord = Record<string, unknown>;

export function record(value: unknown, label: string): JsonRecord {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new TypeError(`Vault received an invalid ${label} response`);
	}
	return value as JsonRecord;
}

function closedRecord(
	value: unknown,
	label: string,
	allowed: readonly string[],
): JsonRecord {
	const input = record(value, label);
	for (const key of Object.keys(input)) {
		if (!allowed.includes(key)) {
			throw new TypeError(`Vault received an invalid ${label} response`);
		}
	}
	return input;
}

function string(value: unknown, label: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new TypeError(`Vault received an invalid ${label} response`);
	}
	return value;
}

function optionalString(value: unknown, label: string): string | undefined {
	if (value === undefined) return undefined;
	return string(value, label);
}

function nullableString(
	value: unknown,
	label: string,
): string | null | undefined {
	if (value === undefined || value === null) return value;
	return string(value, label);
}

function nullableSessionMetadata(
	value: unknown,
	label: string,
): string | null | undefined {
	if (value === "") return null;
	return nullableString(value, label);
}

function optionalBoolean(value: unknown, label: string): boolean | undefined {
	if (value === undefined) return undefined;
	if (typeof value !== "boolean") {
		throw new TypeError(`Vault received an invalid ${label} response`);
	}
	return value;
}

function stringArray(value: unknown, label: string): readonly string[] {
	if (!Array.isArray(value)) {
		throw new TypeError(`Vault received an invalid ${label} response`);
	}
	return Object.freeze(value.map((item) => string(item, label)));
}

function boolean(value: unknown, label: string): boolean {
	if (typeof value !== "boolean") {
		throw new TypeError(`Vault received an invalid ${label} response`);
	}
	return value;
}

function oneOf<T extends string>(
	value: unknown,
	values: readonly T[],
	label: string,
): T {
	if (typeof value !== "string" || !values.includes(value as T)) {
		throw new TypeError(`Vault received an invalid ${label} response`);
	}
	return value as T;
}

function stringRecord(value: unknown, label: string): Readonly<Record<string, string>> {
	const input = record(value, label);
	return Object.freeze(
		Object.fromEntries(
			Object.entries(input).map(([key, item]) => [key, string(item, label)]),
		),
	);
}

function sourceArray(value: unknown, keys: readonly string[], label: string): unknown[] {
	if (Array.isArray(value)) return value;
	const source = record(value, label);
	for (const key of keys) {
		if (Array.isArray(source[key])) return source[key];
	}
	throw new TypeError(`Vault received an invalid ${label} response`);
}

export function parseList<T>(
	value: unknown,
	keys: readonly string[],
	label: string,
	parse: (item: unknown) => T,
): readonly T[] {
	return Object.freeze(sourceArray(value, keys, label).map(parse));
}

export function parseUser(value: unknown): VaultUser {
	const input = record(value, "user");
	return Object.freeze({
		id: string(input.id, "user"),
		email: string(input.email, "user"),
		...(input.name !== undefined
			? { name: nullableString(input.name, "user") }
			: {}),
		...(input.image !== undefined
			? { image: nullableString(input.image, "user") }
			: {}),
		...(input.twoFactorEnabled !== undefined
			? { twoFactorEnabled: optionalBoolean(input.twoFactorEnabled, "user") }
			: {}),
	});
}

export function parseSession(value: unknown): VaultSession {
	const input = record(value, "session");
	return Object.freeze({
		id: string(input.id, "session"),
		userId: string(input.userId, "session"),
		...(input.activeOrganizationId !== undefined
			? {
					activeOrganizationId: nullableString(
						input.activeOrganizationId,
						"session",
					),
				}
			: {}),
		...(input.expiresAt !== undefined
			? { expiresAt: string(input.expiresAt, "session") }
			: {}),
		...(input.ipAddress !== undefined
			? { ipAddress: nullableSessionMetadata(input.ipAddress, "session") }
			: {}),
		...(input.userAgent !== undefined
			? { userAgent: nullableSessionMetadata(input.userAgent, "session") }
			: {}),
	});
}

export function parseSessionState(value: unknown): VaultSessionState | null {
	if (value === null) return null;
	const envelope = record(value, "session");
	const input =
		envelope.data && typeof envelope.data === "object"
			? record(envelope.data, "session")
			: envelope;
	if (input.session === null) return null;
	return Object.freeze({
		user: parseUser(input.user),
		session: parseSession(input.session),
	});
}

export function parseOrganization(value: unknown): VaultOrganization {
	const input = record(value, "organization");
	return Object.freeze({
		id: string(input.id, "organization"),
		name: string(input.name, "organization"),
		...(input.slug !== undefined
			? { slug: optionalString(input.slug, "organization") }
			: {}),
		...(input.logo !== undefined
			? { logo: nullableString(input.logo, "organization") }
			: {}),
	});
}

export function parseInvitation(value: unknown): VaultInvitation {
	const input = record(value, "invitation");
	return Object.freeze({
		id: string(input.id, "invitation"),
		email: string(input.email, "invitation"),
		status: oneOf(input.status, ["pending", "accepted", "rejected", "canceled"], "invitation status") as InvitationStatus,
		...(input.role !== undefined
			? { role: string(input.role, "invitation") }
			: {}),
		...(input.organizationId !== undefined
			? { organizationId: string(input.organizationId, "invitation") }
			: {}),
		...(input.organizationName !== undefined
			? { organizationName: string(input.organizationName, "invitation") }
			: {}),
		...(input.expiresAt !== undefined
			? { expiresAt: string(input.expiresAt, "invitation") }
			: {}),
	});
}

export function parsePasskey(value: unknown): VaultPasskey {
	const input = record(value, "passkey");
	return Object.freeze({
		id: string(input.id, "passkey"),
		...(input.name !== undefined
			? { name: nullableString(input.name, "passkey") }
			: {}),
		...(input.createdAt !== undefined
			? { createdAt: string(input.createdAt, "passkey") }
			: {}),
		...(input.deviceType !== undefined
			? { deviceType: string(input.deviceType, "passkey") }
			: {}),
		...(input.backedUp !== undefined
			? { backedUp: optionalBoolean(input.backedUp, "passkey") }
			: {}),
	});
}

export function parseSubject(value: unknown): VaultAuthorizationSubject {
	const input = record(value, "authorization subject");
	const kind = input.kind;
	if (kind !== "principal" && kind !== "service_account") {
		throw new TypeError("Vault received an invalid authorization subject response");
	}
	return Object.freeze({ kind, id: string(input.id, "authorization subject") });
}

export function parseRole(value: unknown): VaultAuthorizationRole {
	const input = record(value, "authorization role");
	const status = input.status;
	if (status !== "active" && status !== "disabled" && status !== "archived") {
		throw new TypeError("Vault received an invalid authorization role response");
	}
	return Object.freeze({
		roleId: string(input.roleId, "authorization role"),
		organizationId:
			input.organizationId === null
				? null
				: string(input.organizationId, "authorization role"),
		slug: string(input.slug, "authorization role"),
		name: string(input.name, "authorization role"),
		description:
			input.description === null
				? null
				: string(input.description, "authorization role"),
		builtIn:
			typeof input.builtIn === "boolean"
				? input.builtIn
				: (() => {
						throw new TypeError(
							"Vault received an invalid authorization role response",
						);
					})(),
		status,
		actions: stringArray(input.actions, "authorization role"),
	});
}

export function parseAssignment(value: unknown): VaultAuthorizationAssignment {
	const input = record(value, "authorization assignment");
	return Object.freeze({
		organizationId: string(input.organizationId, "authorization assignment"),
		subject: parseSubject(input.subject),
		roleId: string(input.roleId, "authorization assignment"),
	});
}

export function parseEffectiveAuthorization(
	value: unknown,
): VaultEffectiveAuthorization {
	const input = record(value, "effective authorization");
	return Object.freeze({
		projectId: string(input.projectId, "effective authorization"),
		environmentId: string(input.environmentId, "effective authorization"),
		organizationId: string(input.organizationId, "effective authorization"),
		subject: parseSubject(input.subject),
		roleIds: stringArray(input.roleIds, "effective authorization"),
		actions: stringArray(input.actions, "effective authorization"),
		revision: string(input.revision, "effective authorization"),
	});
}

export function parseServiceAccount(value: unknown): VaultServiceAccount {
	const input = record(value, "service account");
	if (input.status !== "active" && input.status !== "disabled") {
		throw new TypeError("Vault received an invalid service account response");
	}
	return Object.freeze({
		organizationId: string(input.organizationId, "service account"),
		serviceAccountId: string(input.serviceAccountId, "service account"),
		name: string(input.name, "service account"),
		status: input.status,
	});
}

export function parseCredential(value: unknown): VaultServiceAccountCredential {
	const input = record(value, "credential");
	if (!Number.isInteger(input.version) || (input.version as number) < 1) {
		throw new TypeError("Vault received an invalid credential response");
	}
	return Object.freeze({
		organizationId: string(input.organizationId, "credential"),
		serviceAccountId: string(input.serviceAccountId, "credential"),
		credentialId: string(input.credentialId, "credential"),
		credentialPrefix: string(input.credentialPrefix, "credential"),
		credentialFingerprint: string(input.credentialFingerprint, "credential"),
		expiresAt:
			input.expiresAt === null ? null : string(input.expiresAt, "credential"),
		version: input.version as number,
	});
}

export function parseCredentialMutation(value: unknown): VaultCredentialMutation {
	const input = record(value, "credential");
	return Object.freeze({
		credential: parseCredential(input.credential),
		secret: string(input.secret, "credential"),
		previousRevision: string(input.previousRevision, "credential"),
		revision: string(input.revision, "credential"),
	});
}

export function parseAuditList(value: unknown): VaultAuditPage {
	const input = record(value, "audit list");
	const events = parseList(input.events, [], "audit event list", parseAuditEvent);
	const nextCursor =
		input.nextCursor === null
			? null
			: string(input.nextCursor, "audit list");
	return Object.freeze({ events, nextCursor });
}

function parseAuditEvent(value: unknown): VaultAuditEvent {
	const input = record(value, "audit event");
	return Object.freeze({
		id: string(input.id, "audit event"),
		correlationId: string(input.correlationId, "audit event"),
		action: string(input.action, "audit event"),
		outcome: oneOf(input.outcome, ["success", "failure", "pending"], "audit event"),
		source: oneOf(
			input.source,
			["cli", "console", "api", "system", "migration", "sso", "scim"],
			"audit event",
		),
		message: string(input.message, "audit event"),
		createdAt: string(input.createdAt, "audit event"),
	});
}

export function parseSSOConnection(value: unknown): VaultSsoConnection {
	const input = record(value, "SSO connection");
	return Object.freeze({
		id: string(input.id, "SSO connection"),
		organizationId: string(input.organizationId, "SSO connection"),
		protocol: oneOf(input.protocol, ["saml", "oidc"], "SSO connection"),
		provider: string(input.provider, "SSO connection"),
		status: oneOf(
			input.status,
			["draft", "testing", "active", "disabled"],
			"SSO connection",
		),
		domains: stringArray(input.domains, "SSO connection"),
		...(input.issuer === undefined ? {} : { issuer: string(input.issuer, "SSO connection") }),
		...(input.audience === undefined ? {} : { audience: string(input.audience, "SSO connection") }),
		...(input.metadataUrl === undefined ? {} : { metadataUrl: string(input.metadataUrl, "SSO connection") }),
		...(input.clientId === undefined ? {} : { clientId: string(input.clientId, "SSO connection") }),
		...(input.clientSecretFingerprint === undefined
			? {}
			: { clientSecretFingerprint: string(input.clientSecretFingerprint, "SSO connection") }),
		hasClientSecret: boolean(input.hasClientSecret, "SSO connection"),
		...(input.samlEntryPoint === undefined ? {} : { samlEntryPoint: string(input.samlEntryPoint, "SSO connection") }),
		...(input.samlCertificateFingerprint === undefined
			? {}
			: { samlCertificateFingerprint: string(input.samlCertificateFingerprint, "SSO connection") }),
		attributeMapping: stringRecord(input.attributeMapping, "SSO connection"),
		createdAt: string(input.createdAt, "SSO connection"),
		updatedAt: string(input.updatedAt, "SSO connection"),
	});
}

export function parseScimConnection(value: unknown): VaultScimConnection {
	const input = record(value, "SCIM connection");
	return Object.freeze({
		id: string(input.id, "SCIM connection"),
		organizationId: string(input.organizationId, "SCIM connection"),
		provider: string(input.provider, "SCIM connection"),
		status: oneOf(
			input.status,
			["draft", "testing", "active", "disabled"],
			"SCIM connection",
		),
		endpoint: string(input.endpoint, "SCIM connection"),
		...(input.bearerTokenFingerprint === undefined
			? {}
			: { bearerTokenFingerprint: string(input.bearerTokenFingerprint, "SCIM connection") }),
		hasBearerToken: boolean(input.hasBearerToken, "SCIM connection"),
		deprovisioningPolicy: oneOf(
			input.deprovisioningPolicy,
			["disable", "delete", "suspend"],
			"SCIM connection",
		),
		createdAt: string(input.createdAt, "SCIM connection"),
		updatedAt: string(input.updatedAt, "SCIM connection"),
	});
}

export function parseSSOTest(value: unknown): VaultSsoTestResult {
	const input = closedRecord(value, "SSO test", [
		"connection",
		"pass",
		"evidence",
		"mode",
		"liveCertified",
	]);
	const mode = input.mode === undefined
		? {}
		: { mode: oneOf(input.mode, ["simulation", "live"], "SSO test") };
	return Object.freeze({
		connection: parseSSOConnection(input.connection),
		pass: boolean(input.pass, "SSO test"),
		...(input.evidence === undefined ? {} : { evidence: string(input.evidence, "SSO test") }),
		...mode,
		liveCertified: boolean(input.liveCertified, "SSO test"),
	});
}

export function parseScimTest(value: unknown): VaultScimTestResult {
	const input = closedRecord(value, "SCIM test", [
		"connection",
		"pass",
		"evidence",
		"mode",
		"liveCertified",
		"scenario",
		"groupLifecycle",
	]);
	const mode = input.mode === undefined
		? {}
		: { mode: oneOf(input.mode, ["simulation", "live"], "SCIM test") };
	const scenario = input.scenario === undefined
		? undefined
		: oneOf(input.scenario, ["users", "group-lifecycle"], "SCIM test");
	const groupLifecycle = input.groupLifecycle === undefined
		? undefined
		: (() => {
			const lifecycle = closedRecord(input.groupLifecycle, "SCIM group lifecycle", ["group", "counts"]);
			const group = closedRecord(lifecycle.group, "SCIM group lifecycle", ["id", "status"]);
			const counts = closedRecord(lifecycle.counts, "SCIM group lifecycle", [
				"usersCreated",
				"membersCreated",
				"membersAfterPatch",
			]);
			const count = (entry: unknown): number => {
				if (typeof entry !== "number" || !Number.isSafeInteger(entry) || entry < 0) {
					throw new TypeError("Vault received an invalid SCIM group lifecycle response");
				}
				return entry;
			};
			return Object.freeze({
				group: Object.freeze({
					id: string(group.id, "SCIM group lifecycle"),
					status: oneOf(group.status, ["deleted"], "SCIM group lifecycle"),
				}),
				counts: Object.freeze({
					usersCreated: count(counts.usersCreated),
					membersCreated: count(counts.membersCreated),
					membersAfterPatch: count(counts.membersAfterPatch),
				}),
			});
		})();
	if ((scenario === "group-lifecycle") !== (groupLifecycle !== undefined)) {
		throw new TypeError("Vault received an invalid SCIM test response");
	}
	return Object.freeze({
		connection: parseScimConnection(input.connection),
		pass: boolean(input.pass, "SCIM test"),
		...(input.evidence === undefined ? {} : { evidence: string(input.evidence, "SCIM test") }),
		...mode,
		liveCertified: boolean(input.liveCertified, "SCIM test"),
		...(scenario === undefined ? {} : { scenario }),
		...(groupLifecycle === undefined ? {} : { groupLifecycle }),
	});
}

export function parseSsoMutation(
	value: unknown,
): VaultSsoMutationPreview | VaultSsoConnection | VaultConnectionDisableResult<VaultSsoConnection> {
	const input = record(value, "SSO mutation");
	if (input.preview === true) {
		return Object.freeze({
			preview: true,
			connection: parseSSOConnection(input.connection),
			wouldChange: boolean(input.wouldChange, "SSO mutation"),
		});
	}
	if (input.idempotent !== undefined || input.runtimeRemoved !== undefined) {
		return Object.freeze({
			connection: parseSSOConnection(input.connection),
			idempotent: boolean(input.idempotent, "SSO mutation"),
			runtimeRemoved: boolean(input.runtimeRemoved, "SSO mutation"),
		});
	}
	return parseSSOConnection(input);
}

export function parseSsoCreate(value: unknown): VaultSsoCreatePreview | VaultSsoConnection {
	const input = record(value, "SSO creation");
	if (input.preview !== true) return parseSSOConnection(input.connection);
	const proposed = record(input.proposed, "SSO creation");
	const base = {
		organizationId: string(proposed.organizationId, "SSO creation"),
		provider: string(proposed.provider, "SSO creation"),
		issuer: string(proposed.issuer, "SSO creation"),
		domain: string(proposed.domain, "SSO creation"),
		audience: proposed.audience === null ? null : string(proposed.audience, "SSO creation"),
	};
	const proposal = proposed.protocol === "oidc"
		? Object.freeze({
			...base,
			protocol: "oidc" as const,
			clientId: string(proposed.clientId, "SSO creation"),
			hasClientSecret: proposed.hasClientSecret === true
				? true
				: (() => { throw new TypeError("Vault received an invalid SSO creation response"); })(),
		})
		: proposed.protocol === "saml"
			? Object.freeze({
				...base,
				protocol: "saml" as const,
				samlEntryPoint: string(proposed.samlEntryPoint, "SSO creation"),
				hasSamlCertificate: proposed.hasSamlCertificate === true
					? true
					: (() => { throw new TypeError("Vault received an invalid SSO creation response"); })(),
			})
			: (() => { throw new TypeError("Vault received an invalid SSO creation response"); })();
	return Object.freeze({
		preview: true,
		proposed: proposal,
		wouldChange: boolean(input.wouldChange, "SSO creation"),
	});
}

export function parseScimMutation(
	value: unknown,
): VaultScimCreatePreview | VaultScimMutationPreview | VaultScimSecretMutation | VaultConnectionDisableResult<VaultScimConnection> {
	const input = record(value, "SCIM mutation");
	if (input.preview === true) {
		if (input.bearerTokenOnce !== undefined) {
			throw new TypeError("Vault received a SCIM secret in a preview response");
		}
		if (input.proposed !== undefined) {
			const proposed = record(input.proposed, "SCIM creation");
			return Object.freeze({
				preview: true,
				proposed: Object.freeze({
					organizationId: string(proposed.organizationId, "SCIM creation"),
					provider: string(proposed.provider, "SCIM creation"),
					endpoint: proposed.endpoint === null ? null : string(proposed.endpoint, "SCIM creation"),
					bearerTokenGenerated: proposed.bearerTokenGenerated === false
						? false
						: (() => { throw new TypeError("Vault received an invalid SCIM creation response"); })(),
				}),
				wouldChange: boolean(input.wouldChange, "SCIM creation"),
			});
		}
		return Object.freeze({
			preview: true,
			connection: parseScimConnection(input.connection),
			wouldChange: boolean(input.wouldChange, "SCIM mutation"),
		});
	}
	if (input.idempotent !== undefined || input.runtimeRemoved !== undefined) {
		return Object.freeze({
			connection: parseScimConnection(input.connection),
			idempotent: boolean(input.idempotent, "SCIM mutation"),
			runtimeRemoved: boolean(input.runtimeRemoved, "SCIM mutation"),
		});
	}
	return Object.freeze({
		connection: parseScimConnection(input.connection),
		bearerTokenOnce: string(input.bearerTokenOnce, "SCIM mutation"),
	});
}

export function parseScimRotation(value: unknown): VaultScimRotation {
	const input = closedRecord(value, "SCIM rotation", [
		"connection",
		"replayed",
		"bearerTokenOnce",
	]);
	const replayed = boolean(input.replayed, "SCIM rotation");
	const bearerTokenOnce = input.bearerTokenOnce === undefined
		? undefined
		: string(input.bearerTokenOnce, "SCIM rotation");
	if (!replayed && bearerTokenOnce === undefined) {
		throw new TypeError("Vault received an invalid SCIM rotation response");
	}
	return Object.freeze({
		connection: parseScimConnection(input.connection),
		replayed,
		...(bearerTokenOnce === undefined ? {} : { bearerTokenOnce }),
	});
}

export function parseEnterpriseReadiness(value: unknown): VaultReadiness {
	const envelope = record(value, "enterprise readiness");
	const input = record(envelope.report, "enterprise readiness");
	const overall = oneOf(input.overall, ["ready", "blocked", "attention"], "enterprise readiness");
	const rawState = input.state === undefined
		? "current"
		: oneOf(input.state, ["current", "stale", "not_run"], "enterprise readiness");
	const state = rawState === "not_run"
		? "not_run"
		: rawState === "stale"
			? "stale"
			: overall === "ready"
				? "ready"
				: "blocked";
	const conformance = record(input.conformance, "enterprise readiness");
	return Object.freeze({
		state,
		overall,
		generatedAt: string(input.generatedAt, "enterprise readiness"),
		conformance: Object.freeze({
			mode: oneOf(conformance.mode, ["simulation", "live"], "enterprise readiness"),
			liveCertified: boolean(conformance.liveCertified, "enterprise readiness"),
			note: string(conformance.note, "enterprise readiness"),
		}),
		checks: parseList(input.checks, [], "enterprise readiness checks", (value) => {
			const check = record(value, "enterprise readiness check");
			return Object.freeze({
				id: string(check.id, "enterprise readiness check"),
				name: string(check.name, "enterprise readiness check"),
				status: oneOf(check.status, ["pass", "fail", "warn", "skip"], "enterprise readiness check"),
				detail: string(check.detail, "enterprise readiness check"),
				...(check.simulation === undefined ? {} : { simulation: boolean(check.simulation, "enterprise readiness check") }),
			});
		}),
		remainingCustomerActions: stringArray(input.remainingCustomerActions, "enterprise readiness"),
	});
}

export type ParsedAuthPost =
	| Readonly<{ kind: "cookie"; user: VaultUser }>
	| Readonly<{
			kind: "two_factor";
			methods: readonly VaultTwoFactorMethod[];
	  }>
	| Readonly<{ kind: "verification"; user: VaultUser }>;

export function parseAuthPost(value: unknown): ParsedAuthPost {
	const input = record(value, "authentication");
	if (input.twoFactorRedirect === true) {
		const advertised = stringArray(
			input.twoFactorMethods ?? [],
			"two-factor challenge",
		);
		const methods = advertised.filter(
			(method): method is Exclude<VaultTwoFactorMethod, "backup_code"> =>
				method === "totp" || method === "otp",
		);
		const supported: readonly VaultTwoFactorMethod[] = Object.freeze([
			...methods,
			"backup_code",
		]);
		return Object.freeze({
			kind: "two_factor",
			methods: supported,
		});
	}
	const user = parseUser(input.user);
	if (typeof input.token === "string" && input.token.length > 0) {
		return Object.freeze({ kind: "cookie", user });
	}
	if (input.token === null) {
		return Object.freeze({ kind: "verification", user });
	}
	throw new TypeError("Vault received an invalid authentication response");
}

export function parseStatus(value: unknown, label: string): void {
	const input = record(value, label);
	if (input.status !== true) {
		throw new TypeError(`Vault received an invalid ${label} response`);
	}
}
