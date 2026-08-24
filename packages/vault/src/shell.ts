import {
	createVaultClient,
	type VaultAuthenticationResult,
	type VaultAuthorizationAssignment,
	type VaultAuthorizationRole,
	type VaultClient,
	type VaultClientConfig,
	type VaultInvitation,
	type VaultOrganization,
	type VaultPasskey,
	type VaultPasskeyDeletionProof,
	type VaultServiceAccount,
	type VaultSession,
	type VaultSessionState,
	type VaultTwoFactorMethod,
} from "./client";
import { VAULT_STYLES } from "./styles";
import { VaultApiError } from "./transport";
import {
	authenticationResponse,
	authenticationRequestOptions,
	deletionRequestOptions,
	registrationCreationOptions,
	registrationResponse,
} from "./webauthn";
import {
	VAULT_WORKFLOWS,
	type VaultRouteId,
	type VaultWorkflow,
} from "./workflows";

export type ClearanceVaultConfig = VaultClientConfig &
	Readonly<{
		initialRoute?: VaultRouteId;
		branding?: Readonly<{
			productName?: string;
			homeLabel?: string;
			logoUrl?: string;
		}>;
		theme?: Readonly<{
			accentColor?: `#${string}`;
		}>;
		passkeyRpId?: string;
		recoveryParams?: Readonly<{ marker?: string; token?: string; error?: string }>;
		styleMode?: "inline" | "external";
		/** Nonce supplied by the host's CSP when Vault injects its bundled CSS. */
		styleNonce?: string;
		/** Query parameter used for closed, shareable Vault route links. */
		routeParam?: string;
	}>;

export type ClearanceVaultMount = Readonly<{
	destroy(): void;
	navigate(route: VaultRouteId): void;
}>;

type SecretState = {
	title: string;
	value: string;
};

type OrganizationDraft = {
	name: string;
	slug: string;
};

type ConfirmationState = {
	title: string;
	description: string;
	label: string;
	execute: () => Promise<void>;
	retainOnFailure?: boolean;
};

type ConfirmationFocusTarget = Readonly<{
	tagName: string;
	id: string;
	name: string;
	route: string;
	text: string;
}>;

type TenantIdentity = Readonly<{
	userId: string;
	sessionId: string;
	organizationId: string;
}>;

type SessionIdentity = Readonly<{
	userId: string;
	sessionId: string;
	organizationId?: string;
}>;

type TenantRecord = Readonly<Record<string, unknown>>;

const TENANT_CONTEXT_CHANGED =
	"Your organization context changed. Vault cancelled this action and reloaded the current session.";

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function browserOperationId(): string {
	const value = globalThis.crypto?.randomUUID?.();
	if (!CANONICAL_UUID.test(value ?? "")) {
		throw new TypeError("Browser cryptography must provide a canonical UUID operation ID");
	}
	return value;
}

type ShellState = {
	route: VaultRouteId;
	session: VaultSessionState | null | undefined;
	organizations: readonly VaultOrganization[];
	organizationDraft: OrganizationDraft;
	invitations: readonly VaultInvitation[];
	organizationInvitations: readonly VaultInvitation[];
	organizationInvitationsDenied: boolean;
	passkeys: readonly VaultPasskey[];
	roles: readonly VaultAuthorizationRole[];
	assignments: readonly VaultAuthorizationAssignment[];
	serviceAccounts: readonly VaultServiceAccount[];
	ssoProviders: readonly TenantRecord[];
	scimConnections: readonly TenantRecord[];
	auditEvents: readonly TenantRecord[];
	readiness: TenantRecord | null;
	sessions: readonly VaultSession[];
	twoFactor?: Readonly<{ methods: readonly VaultTwoFactorMethod[] }>;
	busy: boolean;
	status: string;
	error: string;
	secret?: SecretState;
	confirmation?: ConfirmationState;
	destroyed: boolean;
};

function consumeRecoveryCallback(params: Readonly<{ marker: string; token: string; error: string }>): Readonly<{
	tokenRef?: { value: string };
	error?: string;
	redirectTo: string;
}> {
	const url = new URL(window.location.href);
	const marked = url.searchParams.get(params.marker) === "1";
	const token = marked ? url.searchParams.get(params.token) || undefined : undefined;
	const error = marked ? url.searchParams.get(params.error) || undefined : undefined;
	if (marked) {
		url.searchParams.delete(params.marker);
		url.searchParams.delete(params.token);
		url.searchParams.delete(params.error);
		const clean = `${url.pathname}${url.search}${url.hash}`;
		window.history.replaceState(window.history.state, "", clean);
	}
	return Object.freeze({
		...(token ? { tokenRef: { value: token } } : {}),
		...(error ? { error } : {}),
		redirectTo: `${url.origin}${url.pathname}`,
	});
}

function node<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	className?: string,
	text?: string,
): HTMLElementTagNameMap[K] {
	const result = document.createElement(tag);
	if (className) result.className = className;
	if (text !== undefined) result.textContent = text;
	return result;
}

function button(
	label: string,
	onClick: () => void,
	variant: "primary" | "secondary" | "danger" = "primary",
): HTMLButtonElement {
	const result = node(
		"button",
		`cv-button${variant === "secondary" ? " cv-button-secondary" : ""}${variant === "danger" ? " cv-button-danger" : ""}`,
		label,
	);
	result.type = "button";
	result.addEventListener("click", onClick);
	return result;
}

function confirmationFocusTarget(
	element: Element | null,
): ConfirmationFocusTarget | undefined {
	if (!(element instanceof HTMLElement)) return undefined;
	return Object.freeze({
		tagName: element.tagName,
		id: element.id,
		name: element.getAttribute("name") ?? "",
		route: element.dataset.route ?? "",
		text: element.textContent?.trim() ?? "",
	});
}

function matchesConfirmationFocusTarget(
	element: HTMLElement,
	target: ConfirmationFocusTarget,
): boolean {
	return (
		element.tagName === target.tagName &&
		element.id === target.id &&
		(element.getAttribute("name") ?? "") === target.name &&
		(element.dataset.route ?? "") === target.route &&
		(element.textContent?.trim() ?? "") === target.text
	);
}

function field(
	id: string,
	label: string,
	type: string,
	options: Readonly<{
		required?: boolean;
		autocomplete?: string;
		placeholder?: string;
		value?: string;
	}> = {},
): { wrapper: HTMLDivElement; input: HTMLInputElement } {
	const wrapper = node("div", "cv-field");
	const fieldLabel = node("label", undefined, label);
	fieldLabel.htmlFor = id;
	const input = node("input");
	input.id = id;
	input.name = id;
	input.type = type;
	input.required = options.required === true;
	if (options.autocomplete) input.setAttribute("autocomplete", options.autocomplete);
	if (options.placeholder) input.placeholder = options.placeholder;
	if (options.value) input.value = options.value;
	wrapper.append(fieldLabel, input);
	return { wrapper, input };
}

function formCard(title: string): {
	card: HTMLElement;
	form: HTMLFormElement;
} {
	const card = node("section", "cv-card");
	card.append(node("h2", undefined, title));
	const form = node("form", "cv-form");
	card.append(form);
	return { card, form };
}

function activeOrganizationId(state: ShellState): string | undefined {
	return state.session?.session.activeOrganizationId ?? undefined;
}

function errorMessage(error: unknown): string {
	if (error instanceof VaultApiError) {
		return error.requestId
			? `${error.message} (request ${error.requestId})`
			: error.message;
	}
	if (error instanceof DOMException && error.name === "AbortError") {
		return "The request was cancelled.";
	}
	return error instanceof Error ? error.message : "The request could not be completed.";
}

function requireText(input: HTMLInputElement, label: string): string {
	const value = input.value.trim();
	if (!value) throw new TypeError(`${label} is required`);
	return value;
}

function validateAccent(value: string | undefined): string | undefined {
	if (value === undefined) return undefined;
	if (!/^#[0-9a-f]{6}$/i.test(value)) {
		throw new TypeError("theme.accentColor must be a six-digit hex color");
	}
	return value;
}

function isLoopbackHostname(hostname: string): boolean {
	if (hostname === "localhost" || hostname === "::1" || hostname === "[::1]") {
		return true;
	}
	const octets = hostname.split(".");
	return (
		octets.length === 4 &&
		octets[0] === "127" &&
		octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
	);
}

function validateLogoUrl(value: string | undefined, development: boolean): string | undefined {
	if (value === undefined) return undefined;
	const candidate = value.trim();
	if (!candidate || value.length > 2_048) {
		throw new TypeError("branding.logoUrl must be a bounded HTTPS URL");
	}
	let url: URL;
	try {
		url = new URL(candidate);
	} catch {
		throw new TypeError("branding.logoUrl must be a valid URL");
	}
	if (
		url.hash ||
		url.username ||
		url.password ||
		(url.protocol !== "https:" && !(development && url.protocol === "http:" && isLoopbackHostname(url.hostname)))
	) {
		throw new TypeError("branding.logoUrl must be a credential-free HTTPS URL without a fragment");
	}
	return url.href;
}

function publicKeyAvailable(): boolean {
	return (
		typeof navigator !== "undefined" &&
		typeof navigator.credentials?.create === "function" &&
		typeof PublicKeyCredential !== "undefined"
	);
}

function publicKeyAssertionAvailable(): boolean {
	return (
		typeof navigator !== "undefined" &&
		typeof navigator.credentials?.get === "function" &&
		typeof PublicKeyCredential !== "undefined"
	);
}

function workflow(route: VaultRouteId): VaultWorkflow {
	const found = VAULT_WORKFLOWS.find((candidate) => candidate.id === route);
	if (!found) throw new TypeError(`Unknown Vault route: ${route}`);
	return found;
}

function routeFromURL(routeParam: string): VaultRouteId | undefined {
	const candidate = new URL(window.location.href).searchParams.get(routeParam);
	return VAULT_WORKFLOWS.find((item) => item.id === candidate)?.id;
}

function routeParameter(value: string | undefined): string {
	const routeParam = value ?? "vaultRoute";
	if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(routeParam)) {
		throw new TypeError("routeParam must be a URL-safe identifier");
	}
	return routeParam;
}

export function mountClearanceVault(
	root: HTMLElement,
	config: ClearanceVaultConfig = {},
): ClearanceVaultMount {
	if (!(root instanceof HTMLElement)) {
		throw new TypeError("mountClearanceVault requires an HTMLElement root");
	}
	const recoveryParams = {
		marker: config.recoveryParams?.marker ?? "clearance_recovery",
		token: config.recoveryParams?.token ?? "clearance_recovery_token",
		error: config.recoveryParams?.error ?? "clearance_recovery_error",
	};
	const {
		tokenRef: recoveryTokenRef,
		error: recoveryCallbackError,
		redirectTo: recoveryRedirectTo,
	} = consumeRecoveryCallback(recoveryParams);
	const routeParam = routeParameter(config.routeParam);
	const initialRoute = recoveryTokenRef?.value
		? "recovery"
		: (routeFromURL(routeParam) ?? config.initialRoute ?? "sign-in");
	workflow(initialRoute);
	const productName = config.branding?.productName?.trim() || "Clearance";
	const homeLabel = config.branding?.homeLabel?.trim() || `${productName} Vault`;
	const logoUrl = validateLogoUrl(config.branding?.logoUrl, config.development === true);
	const accent = validateAccent(config.theme?.accentColor);
	if (accent && config.styleMode === "external") {
		throw new TypeError(
			"theme.accentColor requires inline Vault styles; use a host CSS token in external mode",
		);
	}
	const client = createVaultClient(config);
	const passkeyRpId = config.passkeyRpId?.trim() || window.location.hostname;
	if (!passkeyRpId || !/^[a-z0-9.-]{1,253}$/i.test(passkeyRpId)) {
		throw new TypeError("passkeyRpId must be an exact relying-party hostname");
	}
	const requireExpectedRpId = (actual: string) => {
		if (actual !== passkeyRpId) {
			throw new TypeError("The passkey options are for an unexpected relying party");
		}
	};
	const controllers = new Set<AbortController>();
	let renderVersion = 0;
	let requestGeneration = 0;
	let pendingFocus: "main" | "confirmation" | "secret" | "status" | undefined;
	let focusStatusAfterRequest = false;
	let confirmationReturnFocusTarget: ConfirmationFocusTarget | undefined;
	const liveStatus = node("div", "cv-status");
	liveStatus.setAttribute("role", "status");
	liveStatus.setAttribute("aria-live", "polite");
	liveStatus.setAttribute("aria-atomic", "true");
	const state: ShellState = {
		route: initialRoute,
		session: undefined,
		organizations: [],
		organizationDraft: { name: "", slug: "" },
		invitations: [],
		organizationInvitations: [],
		organizationInvitationsDenied: false,
		passkeys: [],
		roles: [],
		assignments: [],
		serviceAccounts: [],
		ssoProviders: [],
		scimConnections: [],
		auditEvents: [],
		readiness: null,
		sessions: [],
		busy: false,
		status: recoveryCallbackError
			? "The recovery link is invalid or expired."
			: "",
		error: "",
		destroyed: false,
	};

	const writeRoute = (route: VaultRouteId, mode: "push" | "replace") => {
		const url = new URL(window.location.href);
		url.searchParams.set(routeParam, route);
		const destination = `${url.pathname}${url.search}${url.hash}`;
		window.history[mode === "push" ? "pushState" : "replaceState"](
			{ vaultRoute: route },
			"",
			destination,
		);
	};

	const clearDisplayedSecretWithoutRender = () => {
		if (state.secret) state.secret.value = "";
		state.secret = undefined;
	};

	const clearSecretWithoutRender = () => {
		clearDisplayedSecretWithoutRender();
		if (recoveryTokenRef) recoveryTokenRef.value = "";
	};

	const tenantCall = async <T>(
		name: string,
		...args: readonly unknown[]
	): Promise<T> => {
		const method = (client.tenant as unknown as Record<string, unknown>)[name];
		if (typeof method !== "function") {
			throw new TypeError(`Vault tenant workflow ${name} is unavailable`);
		}
		return (method as (...values: readonly unknown[]) => Promise<T>).apply(
			client.tenant,
			[...args],
		);
	};

	const clearOrganizationScopedState = () => {
		state.roles = [];
		state.assignments = [];
		state.serviceAccounts = [];
		state.ssoProviders = [];
		state.scimConnections = [];
		state.auditEvents = [];
		state.readiness = null;
		state.organizationInvitations = [];
		state.organizationInvitationsDenied = false;
		state.confirmation = undefined;
		confirmationReturnFocusTarget = undefined;
		clearSecretWithoutRender();
	};

	const sessionIdentity = (
		session: VaultSessionState | null | undefined,
	): SessionIdentity | undefined =>
		session
			? Object.freeze({
				userId: session.user.id,
				sessionId: session.session.id,
				...(session.session.activeOrganizationId
					? { organizationId: session.session.activeOrganizationId }
					: {}),
			})
			: undefined;

	const sameSessionIdentity = (
		left: SessionIdentity | undefined,
		right: SessionIdentity | undefined,
	): boolean =>
		left?.userId === right?.userId &&
		left?.sessionId === right?.sessionId &&
		left?.organizationId === right?.organizationId;

	const sessionIdentityIsCurrent = (expected: SessionIdentity | undefined) =>
		sameSessionIdentity(expected, sessionIdentity(state.session));

	const installSession = (session: VaultSessionState | null) => {
		if (!sameSessionIdentity(sessionIdentity(state.session), sessionIdentity(session))) {
			clearOrganizationScopedState();
		}
		state.session = session;
	};

	const requireTenantIdentity = (): TenantIdentity => {
		const organizationId = activeOrganizationId(state);
		const session = state.session;
		if (!session || !organizationId) {
			throw new TypeError("Choose an active organization first.");
		}
		return Object.freeze({
			userId: session.user.id,
			sessionId: session.session.id,
			organizationId,
		});
	};

	const requireCurrentTenantIdentity = async (
		expected: TenantIdentity,
		signal: AbortSignal,
	): Promise<void> => {
		const current = await client.auth.getSession({ signal });
		if (
			current?.user.id === expected.userId &&
			current.session.id === expected.sessionId &&
			current.session.activeOrganizationId === expected.organizationId
		) {
			return;
		}
		installSession(current);
		try {
			const organizations = await client.auth.listOrganizations({ signal });
			if (sessionIdentityIsCurrent(sessionIdentity(current))) {
				state.organizations = organizations;
			}
		} catch {
			state.organizations = [];
		}
		throw new TypeError(TENANT_CONTEXT_CHANGED);
	};

	const tenantMutation = async <T>(
		expected: TenantIdentity,
		signal: AbortSignal,
		work: () => Promise<T>,
	): Promise<T> => {
		await requireCurrentTenantIdentity(expected, signal);
		return work();
	};

	const request = async <T>(
		status: string,
		work: (signal: AbortSignal) => Promise<T>,
		complete?: (value: T) => void,
		options: Readonly<{ preserveRecoveryToken?: boolean }> = {},
	): Promise<void> => {
		if (state.destroyed || state.busy) return;
		if (options.preserveRecoveryToken) {
			clearDisplayedSecretWithoutRender();
		} else {
			clearSecretWithoutRender();
		}
		const controller = new AbortController();
		const generation = ++requestGeneration;
		controllers.add(controller);
		state.busy = true;
		state.error = "";
		state.status = status;
		render();
		try {
			const result = await work(controller.signal);
			if (
				state.destroyed ||
				controller.signal.aborted ||
				generation !== requestGeneration
			) {
				return;
			}
			complete?.(result);
			if (state.status === status) {
				state.status = status.replace(/\u2026$/, "");
			}
		} catch (error) {
			if (!state.destroyed && !controller.signal.aborted) {
				state.status = "";
				state.error = errorMessage(error);
			}
		} finally {
			controllers.delete(controller);
			if (!state.destroyed && generation === requestGeneration) {
				state.busy = false;
				if (focusStatusAfterRequest && !state.secret) {
					pendingFocus = "status";
				}
				focusStatusAfterRequest = false;
				render();
			}
		}
	};

	const confirm = (
		title: string,
		description: string,
		label: string,
		execute: () => Promise<void>,
		options: Readonly<{ retainOnFailure?: boolean }> = {},
	) => {
		confirmationReturnFocusTarget = confirmationFocusTarget(
			document.activeElement,
		);
		clearSecretWithoutRender();
		state.confirmation = { title, description, label, execute, ...options };
		state.error = "";
		pendingFocus = "confirmation";
		render();
	};

	const showSecret = (title: string, value: string) => {
		if (state.secret) state.secret.value = "";
		state.secret = { title, value };
		pendingFocus = "secret";
	};

	const clearSecret = () => {
		clearSecretWithoutRender();
		render();
	};

	const cancelConfirmation = () => {
		if (!state.confirmation) return;
		state.confirmation = undefined;
		clearSecretWithoutRender();
		render();
		const returnFocusTarget = confirmationReturnFocusTarget;
		confirmationReturnFocusTarget = undefined;
		const target = returnFocusTarget
			? [...root.querySelectorAll<HTMLElement>(
				"button, a[href], input, select, textarea, [tabindex]:not([tabindex='-1'])",
			)].find((element) =>
				matchesConfirmationFocusTarget(element, returnFocusTarget),
			)
			: undefined;
		(target ?? root.querySelector<HTMLElement>(".cv-main"))?.focus();
	};

	const refreshSession = async (signal: AbortSignal) => {
		const session = await client.auth.getSession({ signal });
		if (signal.aborted) return;
		installSession(session);
	};

	const refreshOrganizations = async (signal: AbortSignal) => {
		const expected = sessionIdentity(state.session);
		const organizations = await client.auth.listOrganizations({ signal });
		if (signal.aborted || !sessionIdentityIsCurrent(expected)) return;
		state.organizations = organizations;
	};

	const validateOrganizationDraft = (): Readonly<{ name: string; slug: string }> => {
		const { name, slug } = state.organizationDraft;
		if (
			name.length < 1 ||
			name.length > 256 ||
			name.trim() !== name ||
			/[\u0000-\u001f\u007f]/.test(name)
		) {
			throw new TypeError(
				"Organization name must be trimmed, 1–256 characters, and contain no control characters.",
			);
		}
		if (
			slug.length < 1 ||
			slug.length > 48 ||
			!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)
		) {
			throw new TypeError(
				"Organization slug must use lowercase letters or numbers separated by single hyphens.",
			);
		}
		return Object.freeze({ name, slug });
	};

	const indeterminateOrganizationCreation = (slug: string) =>
		new TypeError(
			`Vault could not confirm whether organization “${slug}” was created and made active. Refresh before retrying; only retry after confirming that slug is absent.`,
		);

	const reconcileOrganizationCreation = async (
		slug: string,
		signal: AbortSignal,
	): Promise<Readonly<{ session: VaultSessionState; organizations: readonly VaultOrganization[]; organization: VaultOrganization }>> => {
		let session: VaultSessionState | null;
		let organizations: readonly VaultOrganization[];
		try {
			[session, organizations] = await Promise.all([
				client.auth.getSession({ signal }),
				client.auth.listOrganizations({ signal }),
			]);
		} catch {
			throw indeterminateOrganizationCreation(slug);
		}
		if (signal.aborted || !session) throw indeterminateOrganizationCreation(slug);
		installSession(session);
		state.organizations = organizations;
		const organization = organizations.find((item) => item.slug === slug);
		if (
			!organization ||
			session.session.activeOrganizationId !== organization.id
		) {
			throw indeterminateOrganizationCreation(slug);
		}
		return Object.freeze({ session, organizations, organization });
	};

	const createOrganization = async (
		signal: AbortSignal,
	): Promise<Readonly<{ session: VaultSessionState; organizations: readonly VaultOrganization[]; organization: VaultOrganization }>> => {
		const input = validateOrganizationDraft();
		try {
			const created = await client.auth.createOrganization(input, { signal });
			if (created.slug !== input.slug) {
				throw indeterminateOrganizationCreation(input.slug);
			}
			return await reconcileOrganizationCreation(created.slug, signal);
		} catch (error) {
			if (error instanceof VaultApiError && error.status >= 400 && error.status < 500) {
				throw error;
			}
			return reconcileOrganizationCreation(input.slug, signal);
		}
	};

	const refreshInvitations = async (signal: AbortSignal) => {
		const expected = sessionIdentity(state.session);
		const organizationId = activeOrganizationId(state);
		const [user, organization] = await Promise.allSettled([
			client.auth.listUserInvitations({ signal }),
			organizationId
				? client.auth.listOrganizationInvitations(organizationId, { signal })
				: Promise.resolve([]),
		]);
		if (signal.aborted || !sessionIdentityIsCurrent(expected)) return;
		const invitationUnauthorized = [user, organization].some(
			(result) =>
				result.status === "rejected" &&
				result.reason instanceof VaultApiError &&
				result.reason.status === 401,
		);
		if (invitationUnauthorized) {
			installSession(null);
			state.invitations = [];
			throw new TypeError("Your session expired. Sign in again to view invitations.");
		}
		if (user.status === "fulfilled") state.invitations = user.value;
		if (organization.status === "fulfilled") {
			state.organizationInvitations = organization.value;
			state.organizationInvitationsDenied = false;
		} else {
			state.organizationInvitations = [];
			state.organizationInvitationsDenied =
				organization.reason instanceof VaultApiError && organization.reason.status === 403;
			if (!state.organizationInvitationsDenied) throw organization.reason;
		}
		if (user.status === "rejected") throw user.reason;
	};

	const refreshAccess = async (signal: AbortSignal) => {
		const expected = sessionIdentity(state.session);
		const organizationId = activeOrganizationId(state);
		if (!organizationId || !state.session) {
			state.roles = [];
			state.assignments = [];
			return;
		}
		const subject = { kind: "principal" as const, id: state.session.user.id };
		const [roles, assignments] = await Promise.all([
			client.tenant.listRoles(organizationId, { signal }),
			client.tenant.listAssignments(organizationId, subject, { signal }),
		]);
		if (signal.aborted || !sessionIdentityIsCurrent(expected)) return;
		state.roles = roles;
		state.assignments = assignments;
	};

	const refreshServiceAccounts = async (signal: AbortSignal) => {
		const expected = sessionIdentity(state.session);
		const organizationId = activeOrganizationId(state);
		if (!organizationId) {
			state.serviceAccounts = [];
			state.roles = [];
			return;
		}
		const [serviceAccounts, roles] = await Promise.all([
			client.tenant.listServiceAccounts(organizationId, { signal }),
			client.tenant.listRoles(organizationId, { signal }),
		]);
		if (signal.aborted || !sessionIdentityIsCurrent(expected)) return;
		state.serviceAccounts = serviceAccounts;
		state.roles = roles;
	};

	const refreshEnterprise = async (signal: AbortSignal) => {
		const expected = sessionIdentity(state.session);
		const organizationId = activeOrganizationId(state);
		if (!organizationId) {
			state.ssoProviders = [];
			state.scimConnections = [];
			state.readiness = null;
			return;
		}
		const [ssoProviders, scimConnections, readiness] = await Promise.all([
			tenantCall<readonly TenantRecord[]>("listSso", organizationId, { signal }),
			tenantCall<readonly TenantRecord[]>("listScim", organizationId, { signal }),
			tenantCall<TenantRecord>("getReadiness", organizationId, { signal }),
		]);
		if (signal.aborted || !sessionIdentityIsCurrent(expected)) return;
		state.ssoProviders = ssoProviders;
		state.scimConnections = scimConnections;
		state.readiness = readiness;
	};

	const refreshAudit = async (signal: AbortSignal) => {
		const expected = sessionIdentity(state.session);
		const organizationId = activeOrganizationId(state);
		if (!organizationId) {
			state.auditEvents = [];
			return;
		}
		const result = await tenantCall<
			Readonly<{ events: readonly TenantRecord[]; nextCursor: string | null }>
		>("listAudit", organizationId, { limit: 25 }, { signal });
		if (!signal.aborted && sessionIdentityIsCurrent(expected)) state.auditEvents = result.events;
	};

	const loadRoute = () => {
		switch (state.route) {
			case "account":
				void request(
					"Loading account security…",
						async (signal) => {
							await refreshSession(signal);
							if (signal.aborted) return;
							if (state.session) {
								const [passkeys, sessions] = await Promise.all([
								client.auth.listPasskeys({ signal }),
								client.auth.listSessions({ signal }),
								]);
								if (signal.aborted) return;
								state.passkeys = passkeys;
							state.sessions = sessions;
						}
					},
				);
				break;
			case "organizations":
				void request(
					"Loading organizations…",
					refreshOrganizations,
					() => {
						state.status = state.organizations.length
							? "Organizations loaded."
							: "No organizations yet. Create your first organization.";
					},
				);
				break;
			case "invitations":
				void request("Loading invitations…", refreshInvitations);
				break;
			case "access":
				void request("Loading access…", refreshAccess);
				break;
			case "service-accounts":
				void request("Loading service accounts…", refreshServiceAccounts);
				break;
			case "enterprise":
				void request("Loading enterprise connections…", refreshEnterprise);
				break;
			case "audit":
				void request("Loading redacted audit events…", refreshAudit);
				break;
		}
	};

	const navigate = (
		route: VaultRouteId,
		history: "push" | "replace" | "none" = "push",
	) => {
		workflow(route);
		if (state.route === route && root.childNodes.length > 0) {
			const hadSensitiveState = Boolean(state.secret || state.confirmation);
			clearSecretWithoutRender();
			state.confirmation = undefined;
			if (history !== "none") writeRoute(route, history);
			if (hadSensitiveState) render();
			return;
		}
		requestGeneration += 1;
		for (const controller of controllers) controller.abort();
		controllers.clear();
		state.busy = false;
		state.route = route;
		state.status = "";
		state.error = "";
		state.confirmation = undefined;
		clearSecretWithoutRender();
		if (history !== "none") writeRoute(route, history);
		render();
		const main = root.querySelector<HTMLElement>(".cv-main");
		main?.focus();
		loadRoute();
	};

	const applyAuthentication = (result: VaultAuthenticationResult): boolean => {
		clearSecretWithoutRender();
		if (result.kind === "authenticated") {
			installSession(result.session);
			state.twoFactor = undefined;
			state.route = "organizations";
			writeRoute(state.route, "replace");
			return true;
		}
		installSession(null);
		if (result.kind === "two_factor_required") {
			state.twoFactor = Object.freeze({ methods: result.methods });
			state.status = "Complete two-factor authentication.";
			return false;
		}
		state.twoFactor = undefined;
		state.status =
			"Check your email to verify the account before signing in.";
		return false;
	};

	const appendAuthRequired = (container: HTMLElement): boolean => {
		if (state.session) return false;
		const card = node("section", "cv-card");
		card.append(
			node("h2", undefined, "Sign in required"),
			node(
				"p",
				"cv-muted",
				"Use a valid browser session to access this tenant workflow.",
											),
			button("Go to sign in", () => navigate("sign-in")),
		);
		container.append(card);
		return true;
	};

	const renderSignIn = (container: HTMLElement) => {
		const { card, form } = formCard("Welcome back");
		const email = field("cv-sign-in-email", "Email", "email", {
			required: true,
			autocomplete: "email",
		});
		const password = field("cv-sign-in-password", "Password", "password", {
			required: true,
			autocomplete: "current-password",
		});
		const actions = node("div", "cv-actions");
		const submit = button("Sign in", () => form.requestSubmit());
		submit.type = "submit";
		actions.append(
			submit,
			button(
				"Sign in with a passkey",
				() =>
					void request(
						"Signing in with passkey…",
						async (signal) => {
							if (!publicKeyAssertionAvailable()) {
								throw new TypeError("Passkey authentication is unavailable in this browser");
							}
							const options = await client.auth.beginPasskeyAuthentication({ signal });
							requireExpectedRpId(options.rpId);
							const credential = await navigator.credentials.get({
								publicKey: authenticationRequestOptions(options),
								signal,
							});
							if (!(credential instanceof PublicKeyCredential)) {
								throw new TypeError("Passkey authentication was cancelled");
							}
							return client.auth.finishPasskeyAuthentication(
								{ response: authenticationResponse(credential) },
								{ signal },
							);
						},
						(session) => {
							clearSecretWithoutRender();
							installSession(session);
							state.twoFactor = undefined;
							state.route = "organizations";
							writeRoute(state.route, "replace");
						},
					).then(() => {
						if (state.session) loadRoute();
					}),
				"secondary",
			),
			button("Forgot password?", () => navigate("recovery"), "secondary"),
		);
		form.append(email.wrapper, password.wrapper, actions);
		form.addEventListener("submit", (event) => {
			event.preventDefault();
			const input = {
				email: requireText(email.input, "Email"),
				password: requireText(password.input, "Password"),
			};
			void request(
				"Signing in…",
				(signal) => client.auth.signIn(input, { signal }),
					applyAuthentication,
				).then(() => {
					if (state.session) loadRoute();
				});
			});
			container.append(card);
			if (state.twoFactor) {
				const challenge = formCard("Two-factor authentication");
				const methodWrapper = node("div", "cv-field");
				const methodLabel = node("label", undefined, "Verification method");
				methodLabel.htmlFor = "cv-two-factor-method";
				const method = node("select");
				method.id = "cv-two-factor-method";
				for (const candidate of state.twoFactor.methods) {
					const option = node(
						"option",
						undefined,
						candidate === "backup_code"
							? "Recovery code"
							: candidate === "otp"
								? "Email code"
								: "Authenticator code",
					);
					option.value = candidate;
					method.append(option);
				}
				methodWrapper.append(methodLabel, method);
				const code = field(
					"cv-two-factor-code",
					"Verification code",
					"password",
					{ required: true, autocomplete: "one-time-code" },
				);
				const actions = node("div", "cv-actions");
				const verify = button(
					"Verify",
					() => challenge.form.requestSubmit(),
				);
				verify.type = "submit";
				actions.append(verify);
				if (state.twoFactor.methods.includes("otp")) {
					actions.append(
						button(
							"Send email code",
							() =>
								void request("Sending code…", (signal) =>
									client.auth.sendTwoFactorOTP({ signal }),
								),
							"secondary",
						),
					);
				}
				challenge.form.append(methodWrapper, code.wrapper, actions);
				challenge.form.addEventListener("submit", (event) => {
					event.preventDefault();
					void request(
						"Verifying second factor…",
						(signal) =>
							client.auth.completeTwoFactor(
								{
									method: method.value as VaultTwoFactorMethod,
									code: requireText(code.input, "Verification code"),
								},
								{ signal },
							),
						(session) => {
							clearSecretWithoutRender();
							installSession(session);
							state.twoFactor = undefined;
							state.route = "organizations";
							writeRoute(state.route, "replace");
						},
					).then(() => {
						if (state.session) loadRoute();
					});
				});
				container.append(challenge.card);
			}
		};

	const renderSignUp = (container: HTMLElement) => {
		const { card, form } = formCard("Create your account");
		const name = field("cv-sign-up-name", "Name", "text", {
			required: true,
			autocomplete: "name",
		});
		const email = field("cv-sign-up-email", "Email", "email", {
			required: true,
			autocomplete: "email",
		});
		const password = field("cv-sign-up-password", "Password", "password", {
			required: true,
			autocomplete: "new-password",
		});
		const submit = button("Create account", () => form.requestSubmit());
		submit.type = "submit";
		form.append(name.wrapper, email.wrapper, password.wrapper, submit);
		form.addEventListener("submit", (event) => {
			event.preventDefault();
			const input = {
				name: requireText(name.input, "Name"),
				email: requireText(email.input, "Email"),
				password: requireText(password.input, "Password"),
			};
			void request(
				"Creating account…",
				(signal) => client.auth.signUp(input, { signal }),
					applyAuthentication,
			).then(() => {
				if (state.session) loadRoute();
			});
		});
		container.append(card);
	};

	const renderRecovery = (container: HTMLElement) => {
		const grid = node("div", "cv-grid");
		const { card, form } = formCard("Reset your password");
		card.insertBefore(
			node(
				"p",
				"cv-muted",
				"We will send recovery instructions when the account exists.",
			),
			form,
		);
		const email = field("cv-recovery-email", "Email", "email", {
			required: true,
			autocomplete: "email",
		});
		const submit = button("Send recovery email", () => form.requestSubmit());
		submit.type = "submit";
		form.append(email.wrapper, submit);
		form.addEventListener("submit", (event) => {
			event.preventDefault();
			void request(
				"Requesting recovery…",
					(signal) =>
						client.auth.requestPasswordReset(
							{
								email: requireText(email.input, "Email"),
							redirectTo: recoveryRedirectTo,
							},
							{ signal },
						),
				(result) => {
					state.status =
						result.message || "If the account exists, a recovery email was sent.";
				},
			);
		});
		const complete = formCard("Complete password reset");
			const token = field("cv-recovery-token", "Recovery token", "password", {
				required: true,
				autocomplete: "one-time-code",
				...(recoveryTokenRef?.value ? { value: recoveryTokenRef.value } : {}),
			});
		const newPassword = field(
			"cv-recovery-new-password",
			"New password",
			"password",
			{ required: true, autocomplete: "new-password" },
		);
		const reset = button("Set new password", () => complete.form.requestSubmit());
		reset.type = "submit";
		complete.form.append(token.wrapper, newPassword.wrapper, reset);
		complete.form.addEventListener("submit", (event) => {
			event.preventDefault();
			void request(
				"Resetting password…",
				(signal) =>
					client.auth.resetPassword(
						{
							token: requireText(token.input, "Recovery token"),
							newPassword: requireText(
								newPassword.input,
								"New password",
							),
						},
						{ signal },
					),
					() => {
						clearSecretWithoutRender();
						token.input.value = "";
						state.route = "sign-in";
						writeRoute(state.route, "replace");
					state.status = "Password reset. Sign in with your new password.";
				},
			);
		});
		grid.append(card, complete.card);
		container.append(grid);
	};

	const renderAccount = (container: HTMLElement) => {
		if (appendAuthRequired(container)) return;
		const grid = node("div", "cv-grid");
		const profile = node("section", "cv-card");
		profile.append(
			node("h2", undefined, "Active session"),
			node("p", undefined, state.session?.user.email ?? ""),
		);
		const sessionList = node("ul", "cv-list");
		for (const session of state.sessions) {
			const current = session.id === state.session?.session.id;
			sessionList.append(
				node(
					"li",
					"cv-list-item",
					`${current ? "Current · " : ""}${session.userAgent || "Unknown device"}${session.ipAddress ? ` · ${session.ipAddress}` : ""}`,
				),
			);
		}
		if (!state.sessions.length) {
			sessionList.append(node("li", "cv-muted", "No additional session details."));
		}
		profile.append(sessionList);
		const sessionActions = node("div", "cv-actions");
		sessionActions.append(
			button(
				"Revoke other sessions",
				() =>
					confirm(
						"Revoke other sessions?",
						"All other browser sessions will be signed out. This cannot be undone.",
						"Revoke sessions",
						() =>
							request("Revoking sessions…", (signal) =>
								client.auth.revokeOtherSessions({ signal }),
							),
					),
				"danger",
			),
			button(
				"Sign out",
				() =>
					void request(
						"Signing out…",
							(signal) => client.auth.signOut({ signal }),
							() => {
								clearSecretWithoutRender();
								installSession(null);
								state.twoFactor = undefined;
								state.route = "sign-in";
								writeRoute(state.route, "replace");
							},
					),
				"secondary",
			),
		);
		profile.append(sessionActions);

		const password = formCard("Change password");
		const current = field("cv-current-password", "Current password", "password", {
			required: true,
			autocomplete: "current-password",
		});
		const next = field("cv-new-password", "New password", "password", {
			required: true,
			autocomplete: "new-password",
		});
		const passwordSubmit = button(
			"Change password",
			() => password.form.requestSubmit(),
		);
		passwordSubmit.type = "submit";
		password.form.append(current.wrapper, next.wrapper, passwordSubmit);
		password.form.addEventListener("submit", (event) => {
			event.preventDefault();
			void request("Changing password…", (signal) =>
				client.auth.changePassword(
					{
						currentPassword: requireText(current.input, "Current password"),
						newPassword: requireText(next.input, "New password"),
						revokeOtherSessions: true,
					},
					{ signal },
				),
			);
		});

		const passkeys = node("section", "cv-card");
		passkeys.append(
			node("h2", undefined, "Passkeys"),
			node(
				"p",
				"cv-muted",
				"Passkeys use device-bound phishing-resistant authentication.",
			),
		);
		const passkeyList = node("ul", "cv-list");
		const deleteProofWrapper = node("div", "cv-field");
		const deleteProofLabel = node("label", undefined, "Proof to remove a passkey");
		deleteProofLabel.htmlFor = "cv-passkey-delete-proof";
		const deleteProofType = node("select");
		deleteProofType.id = "cv-passkey-delete-proof";
		for (const [value, label] of [
			["password", "Current password"],
			["totp", "Authenticator code"],
			["recovery-code", "Recovery code"],
			["passkey", "Another passkey"],
		] as const) {
			const option = node("option", undefined, label);
			option.value = value;
			deleteProofType.append(option);
		}
		deleteProofWrapper.append(deleteProofLabel, deleteProofType);
		const deletePassword = field(
			"cv-passkey-delete-password",
			"Current password",
			"password",
			{ autocomplete: "current-password" },
		);
		const deleteTotp = field(
			"cv-passkey-delete-totp",
			"Authenticator code",
			"text",
			{ autocomplete: "one-time-code", placeholder: "123456" },
		);
		const deleteRecovery = field(
			"cv-passkey-delete-recovery",
			"Recovery code",
			"password",
			{ autocomplete: "one-time-code" },
		);
		const deletionProof = async (
			passkey: VaultPasskey,
			signal: AbortSignal,
		): Promise<VaultPasskeyDeletionProof> => {
			switch (deleteProofType.value) {
				case "password":
					return { type: "password", password: requireText(deletePassword.input, "Current password") };
				case "totp":
					return { type: "totp", code: requireText(deleteTotp.input, "Authenticator code") };
				case "recovery-code":
					return { type: "recovery-code", code: requireText(deleteRecovery.input, "Recovery code") };
				case "passkey": {
					if (!publicKeyAssertionAvailable()) {
						throw new TypeError("Passkey authentication is unavailable in this browser");
					}
					const options = await client.auth.beginPasskeyDeletion({ id: passkey.id }, { signal });
					requireExpectedRpId(options.rpId);
					const credential = await navigator.credentials.get({
						publicKey: deletionRequestOptions(options),
						signal,
					});
					if (!(credential instanceof PublicKeyCredential)) {
						throw new TypeError("Passkey authentication was cancelled");
					}
					return { type: "passkey", response: authenticationResponse(credential) };
				}
				default:
					throw new TypeError("Choose a supported passkey deletion proof");
			}
		};
		for (const passkey of state.passkeys) {
			const item = node("li", "cv-list-item");
			item.append(
				node("span", undefined, passkey.name || `Passkey ${passkey.id}`),
				button(
					"Remove",
					() =>
						confirm(
							"Remove passkey?",
							"Another verified authentication factor must remain available.",
							"Remove passkey",
							() =>
								request(
									"Removing passkey…",
									async (signal) =>
										client.auth.deletePasskey(
											{ id: passkey.id, proof: await deletionProof(passkey, signal) },
											{ signal },
										),
									(session) => {
										clearSecretWithoutRender();
										installSession(session);
										state.passkeys = state.passkeys.filter((item) => item.id !== passkey.id);
									},
								),
						),
					"danger",
				),
			);
			passkeyList.append(item);
		}
		if (state.passkeys.length === 0) {
			passkeyList.append(node("li", "cv-muted", "No passkeys enrolled."));
		}
		const addPasskey = button("Add passkey", () => {
			void request(
				"Creating passkey…",
				async (signal) => {
					if (!publicKeyAvailable()) {
						throw new TypeError("Passkeys are unavailable in this browser");
					}
						const options = await client.auth.beginPasskeyRegistration(
						{},
						{ signal },
						);
						requireExpectedRpId(options.rp.id);
					const credential = await navigator.credentials.create({
						publicKey: registrationCreationOptions(options),
						signal,
					});
					if (!(credential instanceof PublicKeyCredential)) {
						throw new TypeError("Passkey creation was cancelled");
					}
					return client.auth.finishPasskeyRegistration(
						{ response: registrationResponse(credential), name: "Passkey" },
						{ signal },
					);
				},
				(passkey) => {
					state.passkeys = [...state.passkeys, passkey];
				},
			);
		});
		addPasskey.disabled = !publicKeyAvailable();
		passkeys.append(
			passkeyList,
			deleteProofWrapper,
			deletePassword.wrapper,
			deleteTotp.wrapper,
			deleteRecovery.wrapper,
			node("div", "cv-actions"),
		);
		passkeys.lastElementChild?.append(addPasskey);

		const twoFactor = formCard("Two-factor authentication");
		const factorPassword = field(
			"cv-factor-password",
			"Current password",
			"password",
			{ required: true, autocomplete: "current-password" },
		);
		const totpCode = field(
			"cv-factor-code",
			"Authenticator code",
			"text",
			{ autocomplete: "one-time-code", placeholder: "123456" },
		);
		const recoveryCode = field(
			"cv-factor-recovery-code",
			"Recovery code",
			"password",
			{ autocomplete: "one-time-code" },
		);
		const optionalText = (input: HTMLInputElement): string | undefined =>
			input.value.trim() || undefined;
		const factorStepUp = (): Readonly<{ password: string }> &
			(
				| Readonly<{ currentCode: string; recoveryCode?: never }>
				| Readonly<{ currentCode?: never; recoveryCode: string }>
			) => {
			const currentCode = optionalText(totpCode.input);
			const recovery = optionalText(recoveryCode.input);
			if (Boolean(currentCode) === Boolean(recovery)) {
				throw new TypeError("Enter exactly one authenticator code or recovery code");
			}
			const password = requireText(factorPassword.input, "Current password");
			return currentCode
				? { password, currentCode }
				: { password, recoveryCode: recovery! };
		};
		const enable = button("Set up TOTP", () => twoFactor.form.requestSubmit());
		enable.type = "submit";
		const backup = button(
			"Replace recovery codes",
			() =>
				confirm(
					"Replace recovery codes?",
					"Existing recovery codes will stop working after replacement.",
					"Replace codes",
					() =>
						request(
							"Replacing recovery codes…",
								(signal) =>
									client.auth.generateBackupCodes(
										factorStepUp(),
										{ signal },
									),
								(result) => {
									installSession(result.session);
									showSecret(
										"New recovery codes",
										result.backupCodes.join("\n"),
									);
								},
						),
				),
			"danger",
		);
		const factorActions = node("div", "cv-actions");
			factorActions.append(
				enable,
				button("Verify TOTP", () => {
					void request(
						"Verifying TOTP…",
						(signal) =>
							client.auth.verifyTwoFactor(
								{ code: requireText(totpCode.input, "Authenticator code") },
								{ signal },
							),
						(session) => {
							clearSecretWithoutRender();
							installSession(session);
						},
					);
				}),
				backup,
				button(
					"Disable two-factor authentication",
					() =>
						confirm(
							"Disable two-factor authentication?",
							"Your account will rely on its remaining password or passkey factors.",
							"Disable two-factor",
							() =>
								request(
									"Disabling two-factor authentication…",
									(signal) =>
										client.auth.disableTwoFactor(
											factorStepUp(),
											{ signal },
										),
									(session) => {
										clearSecretWithoutRender();
										installSession(session);
									},
								),
						),
					"danger",
				),
			);
			twoFactor.form.append(
			factorPassword.wrapper,
			totpCode.wrapper,
			recoveryCode.wrapper,
			factorActions,
		);
		twoFactor.form.addEventListener("submit", (event) => {
			event.preventDefault();
			const password = requireText(factorPassword.input, "Current password");
			const currentCode = optionalText(totpCode.input);
			if (state.session?.user.twoFactorEnabled === true && !currentCode) {
				state.error = "Enter an authenticator code before replacing TOTP.";
				render();
				return;
			}
			void request(
				"Preparing TOTP…",
				(signal) =>
					client.auth.enableTwoFactor(
						{
							password,
							...(currentCode
								? { currentCode }
								: {}),
						},
						{ signal },
					),
				(result) => {
					installSession(result.session);
					showSecret(
						"TOTP setup and recovery codes",
						`${result.totpURI}\n\n${result.backupCodes.join("\n")}`,
					);
				},
			);
		});
		grid.append(profile, password.card, passkeys, twoFactor.card);
		container.append(grid);
	};

	const renderOrganizations = (container: HTMLElement) => {
		if (appendAuthRequired(container)) return;
		const grid = node("div", "cv-grid");
		const card = node("section", "cv-card");
		card.append(node("h2", undefined, "Your organizations"));
		const list = node("ul", "cv-list");
		const active = activeOrganizationId(state);
		for (const organization of state.organizations) {
			const item = node("li", "cv-list-item");
			const label = node(
				"span",
				undefined,
				`${organization.name}${organization.id === active ? " (active)" : ""}`,
			);
			item.append(label);
			if (organization.id !== active) {
				item.append(
					button(
						`Switch to ${organization.name}`,
						() =>
							void request(
								"Switching organization…",
									async (signal) => {
										await client.auth.setActiveOrganization(organization.id, {
											signal,
										});
										const session = await client.auth.getSession({ signal });
										if (!session) {
											throw new TypeError(
												"Vault could not confirm the active organization session",
											);
										}
										return session;
									},
									(session) => {
										clearSecretWithoutRender();
										installSession(session);
									},
							),
						"secondary",
					),
				);
			}
			list.append(item);
		}
		if (state.organizations.length === 0) {
			list.append(node("li", "cv-muted", "No organizations yet. Create your first organization."));
		}
		card.append(list);

		const create = formCard("Create organization");
		const name = field("cv-organization-name", "Organization name", "text", {
			required: true,
			autocomplete: "organization",
			placeholder: "Acme",
			value: state.organizationDraft.name,
		});
		const slug = field("cv-organization-slug", "Organization slug", "text", {
			required: true,
			placeholder: "acme",
			value: state.organizationDraft.slug,
		});
		name.input.addEventListener("input", () => {
			state.organizationDraft.name = name.input.value;
		});
		slug.input.addEventListener("input", () => {
			state.organizationDraft.slug = slug.input.value;
		});
		const submit = button("Create organization", () => create.form.requestSubmit());
		submit.type = "submit";
		create.form.append(name.wrapper, slug.wrapper, submit);
		create.form.addEventListener("submit", (event) => {
			event.preventDefault();
			void request(
				"Creating organization…",
				createOrganization,
				(result) => {
					installSession(result.session);
					state.organizations = result.organizations;
					state.organizationDraft = { name: "", slug: "" };
					state.status = `Organization ${result.organization.name} created and active.`;
				},
			);
		});
		grid.append(card, create.card);
		container.append(grid);
	};

	const invitationActions = (
		invitation: VaultInvitation,
		kind: "incoming" | "outgoing",
	): HTMLElement => {
		const actions = node("div", "cv-actions");
		if (kind === "incoming") {
			actions.append(
				button("Accept", () => {
					void request(
						"Accepting invitation…",
						(signal) =>
							client.auth.acceptInvitation(invitation.id, { signal }),
						() => {
							state.invitations = state.invitations.filter(
								(item) => item.id !== invitation.id,
							);
						},
					);
				}),
				button(
					"Reject",
					() =>
						confirm(
							"Reject invitation?",
							`You will decline the invitation for ${invitation.email}.`,
							"Reject invitation",
							() =>
								request(
									"Rejecting invitation…",
									(signal) =>
										client.auth.rejectInvitation(invitation.id, { signal }),
									() => {
										state.invitations = state.invitations.filter(
											(item) => item.id !== invitation.id,
										);
									},
								),
						),
					"danger",
				),
			);
		} else {
			actions.append(
				button(
					"Cancel",
					() =>
						confirm(
							"Cancel invitation?",
							`The pending invitation for ${invitation.email} will stop working.`,
							"Cancel invitation",
							() =>
								request(
									"Cancelling invitation…",
									(signal) =>
										client.auth.cancelInvitation(invitation.id, { signal }),
									() => {
										state.organizationInvitations =
											state.organizationInvitations.filter(
												(item) => item.id !== invitation.id,
											);
									},
								),
						),
					"danger",
				),
			);
		}
		return actions;
	};

	const renderInvitations = (container: HTMLElement) => {
		if (appendAuthRequired(container)) return;
		const grid = node("div", "cv-grid");
		const incoming = node("section", "cv-card");
		incoming.append(node("h2", undefined, "Invitations for you"));
		const incomingList = node("ul", "cv-list");
		for (const invitation of state.invitations) {
			const item = node("li", "cv-list-item");
			item.append(
				node(
					"span",
					undefined,
					invitation.organizationName || invitation.organizationId || invitation.email,
				),
				invitationActions(invitation, "incoming"),
			);
			incomingList.append(item);
		}
		if (!state.invitations.length)
			incomingList.append(node("li", "cv-muted", "No pending invitations."));
		incoming.append(incomingList);

		const outgoing = node("section", "cv-card");
		outgoing.append(node("h2", undefined, "Organization invitations"));
		const outgoingList = node("ul", "cv-list");
		for (const invitation of state.organizationInvitations) {
			const item = node("li", "cv-list-item");
			item.append(
				node("span", undefined, `${invitation.email} · ${invitation.status}`),
				invitationActions(invitation, "outgoing"),
			);
			outgoingList.append(item);
		}
		if (!state.organizationInvitations.length)
			outgoingList.append(node("li", "cv-muted", "No invitations sent."));
		outgoing.append(outgoingList);

		const invite = formCard("Invite a member");
		const email = field("cv-invite-email", "Email", "email", {
			required: true,
			autocomplete: "email",
		});
		const role = field("cv-invite-role", "Role", "text", {
			required: true,
			placeholder: "member",
			value: "member",
		});
		const send = button("Send invitation", () => invite.form.requestSubmit());
		send.type = "submit";
		invite.form.append(email.wrapper, role.wrapper, send);
		invite.form.addEventListener("submit", (event) => {
			event.preventDefault();
			const organizationId = activeOrganizationId(state);
			if (!organizationId) {
				state.error = "Choose an active organization first.";
				render();
				return;
			}
			void request(
				"Sending invitation…",
				(signal) =>
					client.auth.inviteMember(
						{
							organizationId,
							email: requireText(email.input, "Email"),
							role: requireText(role.input, "Role"),
						},
						{ signal },
					),
				(created) => {
					state.organizationInvitations = [
						...state.organizationInvitations,
						created,
					];
				},
			);
		});
		if (state.organizationInvitationsDenied) {
			const restricted = node("section", "cv-card");
			restricted.append(
				node("h2", undefined, "Organization invitations"),
				node("p", "cv-muted", "Organization invitation controls require organization administrator access."),
			);
			grid.append(incoming, restricted);
		} else {
			grid.append(incoming, outgoing, invite.card);
		}
		container.append(grid);
	};

	const renderAccess = (container: HTMLElement) => {
		if (appendAuthRequired(container)) return;
		if (!state.session) return;
		const organizationId = activeOrganizationId(state);
		if (!organizationId) {
			container.append(
				node(
					"p",
					"cv-card cv-muted",
					"Select an active organization before managing access.",
				),
			);
			return;
		}
		const grid = node("div", "cv-grid");
		const summary = node("section", "cv-card");
		summary.append(node("h2", undefined, "Available roles"));
		const roles = node("ul", "cv-list");
		for (const role of state.roles.filter((item) => item.status === "active")) {
			const item = node("li", "cv-list-item");
			item.append(
				node(
					"span",
					undefined,
					`${role.name} (${role.slug}) · ${role.roleId}`,
				),
				node("span", "cv-muted", `${role.actions.length} actions`),
			);
			roles.append(item);
		}
		summary.append(roles);

		const assigned = node("section", "cv-card");
		assigned.append(node("h2", undefined, "Your assignments"));
		const assignmentList = node("ul", "cv-list");
		const displayedSubject = { kind: "principal" as const, id: state.session.user.id };
		const displayedAssignments = state.assignments.filter(
			(assignment) =>
				assignment.subject.kind === displayedSubject.kind &&
				assignment.subject.id === displayedSubject.id,
		);
		for (const assignment of displayedAssignments) {
			const role = state.roles.find((item) => item.roleId === assignment.roleId);
			assignmentList.append(
				node(
					"li",
					"cv-list-item",
					role?.name || assignment.roleId,
				),
			);
		}
		if (!displayedAssignments.length)
			assignmentList.append(node("li", "cv-muted", "No role assignments."));
		assigned.append(assignmentList);

		const replace = formCard("Replace role assignments");
		const kindWrapper = node("div", "cv-field");
		const kindLabel = node("label", undefined, "Subject type");
		kindLabel.htmlFor = "cv-subject-kind";
		const kind = node("select");
		kind.id = "cv-subject-kind";
		for (const value of ["principal", "service_account"] as const) {
			const option = node("option", undefined, value.replace("_", " "));
			option.value = value;
			kind.append(option);
		}
		kindWrapper.append(kindLabel, kind);
		const currentUserId = state.session.user.id;
		const subject = field("cv-subject-id", "Subject ID", "text", {
			required: true,
			value: currentUserId,
		});
		const roleIds = field(
			"cv-role-ids",
			"Role IDs (comma separated)",
			"text",
		);
		const removeAllWrapper = node("div", "cv-field");
		const removeAll = node("input");
		removeAll.id = "cv-remove-all-roles";
		removeAll.type = "checkbox";
		const removeAllLabel = node("label", undefined, "I understand this removes every role from this subject");
		removeAllLabel.htmlFor = removeAll.id;
		removeAllWrapper.append(removeAll, removeAllLabel);
		const preview = button("Preview replacement", () => replace.form.requestSubmit());
		preview.type = "submit";
		replace.form.append(kindWrapper, subject.wrapper, roleIds.wrapper, removeAllWrapper, preview);
		replace.form.addEventListener("submit", (event) => {
			event.preventDefault();
			const input = {
				subject: {
					kind: kind.value as "principal" | "service_account",
					id: requireText(subject.input, "Subject ID"),
				},
				roleIds: roleIds.input.value
					.split(",")
					.map((value) => value.trim())
					.filter(Boolean),
				dryRun: true as const,
				confirm: false as const,
			};
			if (input.roleIds.length === 0 && !removeAll.checked) {
				state.error = "Confirm that this removes every role before previewing an empty replacement.";
				render();
				return;
			}
			let tenantIdentity: TenantIdentity;
			try {
				tenantIdentity = requireTenantIdentity();
			} catch (error) {
				state.error = errorMessage(error);
				render();
				return;
			}
			void request(
				"Previewing replacement…",
				(signal) => tenantMutation(tenantIdentity, signal, async () => ({
					current: await client.tenant.listAssignments(
						tenantIdentity.organizationId,
						input.subject,
						{ signal },
					),
					result: await client.tenant.replaceAssignments(
						tenantIdentity.organizationId,
						input,
						{ signal },
					),
				})),
				({ result, current }) => {
					if (!("preview" in result)) {
						throw new TypeError("Vault expected an assignment preview");
					}
					const currentRoles = current.map((assignment) => assignment.roleId).join(", ") || "none";
					const candidateRoles = input.roleIds.join(", ") || "no roles (remove all)";
					confirm(
						"Apply role replacement?",
						`Selected subject: ${input.subject.kind} ${input.subject.id}. Current roles: ${currentRoles}. Candidate roles: ${candidateRoles}. ${input.roleIds.length === 0 ? "This removes every role from the selected subject." : "This replaces the complete role set."}`,
						"Apply replacement",
						() =>
							request(
								"Applying replacement…",
								(signal) =>
									tenantMutation(tenantIdentity, signal, () =>
									client.tenant.replaceAssignments(
										tenantIdentity.organizationId,
										{
											...input,
											expectedRevision: result.currentRevision,
											dryRun: false,
											confirm: true,
										},
										{ signal },
									),
									),
								(result) => {
									if (!("assignment" in result)) return;
									if (
										input.subject.kind === "principal" &&
										input.subject.id === displayedSubject.id
									) {
										state.assignments = result.assignment.roleIds.map((roleId) => ({
											organizationId,
											subject: input.subject,
											roleId,
										}));
									}
								},
							),
					);
				},
			);
		});
		grid.append(summary, assigned, replace.card);
		container.append(grid);
	};

	const serviceAccountButton = (
		account: VaultServiceAccount,
		operation: "enable" | "disable",
	): HTMLButtonElement => {
		const organizationId = activeOrganizationId(state)!;
		const tenantIdentity = requireTenantIdentity();
		const enabled = operation === "enable";
		return button(enabled ? "Enable" : "Disable", () => {
			void request(
				enabled ? "Previewing enable…" : "Previewing disable…",
				(signal) => tenantMutation(tenantIdentity, signal, () =>
					enabled
						? client.tenant.enableServiceAccount(organizationId, account.serviceAccountId, { dryRun: true }, { signal })
						: client.tenant.disableServiceAccount(organizationId, account.serviceAccountId, { dryRun: true, confirm: false }, { signal }),
				),
				() => confirm(
					enabled ? "Enable service account?" : "Disable service account?",
					enabled ? `${account.name} will regain tenant access.` : `${account.name} will immediately lose access.`,
					enabled ? "Enable account" : "Disable account",
					() => request(
						enabled ? "Enabling service account…" : "Disabling service account…",
						(signal) => tenantMutation(tenantIdentity, signal, () =>
							enabled
								? client.tenant.enableServiceAccount(organizationId, account.serviceAccountId, { dryRun: false }, { signal })
								: client.tenant.disableServiceAccount(organizationId, account.serviceAccountId, { dryRun: false, confirm: true }, { signal }),
						),
						() => {
							state.serviceAccounts = state.serviceAccounts.map((item) =>
								item.serviceAccountId === account.serviceAccountId
									? { ...item, status: enabled ? "active" : "disabled" }
									: item,
							);
						},
					),
				),
			);
		}, enabled ? "primary" : "danger");
	};

	const renderServiceAccounts = (container: HTMLElement) => {
		if (appendAuthRequired(container)) return;
		const organizationId = activeOrganizationId(state);
		if (!organizationId) {
			container.append(
				node(
					"p",
					"cv-card cv-muted",
					"Select an active organization before managing service accounts.",
				),
			);
			return;
		}
		const grid = node("div", "cv-grid");
		const accounts = node("section", "cv-card");
		accounts.append(node("h2", undefined, "Service accounts"));
		const list = node("ul", "cv-list");
		for (const account of state.serviceAccounts) {
			const item = node("li", "cv-list-item");
			const details = node(
				"span",
				undefined,
				`${account.name} · ${account.serviceAccountId} · ${account.status}`,
			);
			item.append(
				details,
				serviceAccountButton(
					account,
					account.status === "active" ? "disable" : "enable",
				),
			);
			list.append(item);
		}
		if (!state.serviceAccounts.length)
			list.append(node("li", "cv-muted", "No service accounts."));
		accounts.append(list);

		const create = formCard("Create service account");
		if (state.roles.length) {
			create.card.insertBefore(
				node(
					"p",
					"cv-muted",
					`Available role IDs: ${state.roles
						.filter((role) => role.status === "active")
						.map((role) => role.roleId)
						.join(", ")}`,
				),
				create.form,
			);
		}
		const name = field("cv-service-name", "Name", "text", { required: true });
		const roles = field(
			"cv-service-roles",
			"Role IDs (comma separated)",
			"text",
			{ required: true },
		);
		const createPreview = button("Preview create", () => create.form.requestSubmit());
		createPreview.type = "submit";
		create.form.append(name.wrapper, roles.wrapper, createPreview);
		create.form.addEventListener("submit", (event) => {
			event.preventDefault();
			const input = {
				name: requireText(name.input, "Name"),
				roleIds: roles.input.value
					.split(",")
					.map((value) => value.trim())
					.filter(Boolean),
			};
			const tenantIdentity = requireTenantIdentity();
			void request(
				"Previewing service account…",
				(signal) =>
					tenantMutation(tenantIdentity, signal, () => client.tenant.createServiceAccount(
						organizationId,
						{ ...input, dryRun: true },
						{ signal },
										)),
				() =>
					confirm(
						"Create service account?",
						`${input.name} will receive the complete selected role set.`,
						"Create account",
						() =>
							request(
								"Creating service account…",
								(signal) =>
									tenantMutation(tenantIdentity, signal, () => client.tenant.createServiceAccount(
										organizationId,
										{ ...input, dryRun: false },
										{ signal },
									)),
								(result) => {
										state.serviceAccounts = [
											...state.serviceAccounts,
											result.serviceAccount,
										];
									},
												),
					),
			);
		});

		const credential = formCard("Create or rotate credential");
		const serviceId = field(
			"cv-credential-service",
			"Service account ID",
			"text",
			{ required: true },
		);
		const credentialId = field(
			"cv-credential-id",
			"Credential ID (rotation only)",
			"text",
		);
		const expiresAt = field(
			"cv-credential-expiry",
			"Expires at (optional)",
			"datetime-local",
		);
		const credentialActions = node("div", "cv-actions");
		credentialActions.append(
			button("Create credential", () => {
				const accountId = requireText(serviceId.input, "Service account ID");
				const tenantIdentity = requireTenantIdentity();
				const expiry = expiresAt.input.value
					? new Date(expiresAt.input.value).toISOString()
					: undefined;
				void request(
					"Previewing credential…",
					(signal) => tenantMutation(tenantIdentity, signal, () =>
						client.tenant.createCredential(
							organizationId,
							accountId,
							{ ...(expiry ? { expiresAt: expiry } : {}), dryRun: true },
							{ signal },
						)),
					() => {
						let operationId: string | undefined;
						confirm(
							"Create credential?",
							"The secret will be displayed once after creation.",
							"Create credential",
							() => request(
								"Creating credential…",
								(signal) => tenantMutation(tenantIdentity, signal, () =>
									client.tenant.createCredential(
										organizationId,
										accountId,
										{
											...(expiry ? { expiresAt: expiry } : {}),
											operationId: operationId ??= browserOperationId(),
											dryRun: false,
										},
										{ signal },
									)),
									(result) => {
										state.confirmation = undefined;
										showSecret("One-time credential", result.secret);
									},
								),
							{ retainOnFailure: true },
						);
					},
				);
			}),
			button(
				"Rotate credential",
				() => {
					const accountId = requireText(
						serviceId.input,
						"Service account ID",
					);
					const oldCredentialId = requireText(
						credentialId.input,
						"Credential ID",
					);
					const tenantIdentity = requireTenantIdentity();
					const expiry = expiresAt.input.value
						? new Date(expiresAt.input.value).toISOString()
						: undefined;
					void request(
						"Previewing rotation…",
						(signal) => tenantMutation(tenantIdentity, signal, () =>
							client.tenant.rotateCredential(
								organizationId,
								accountId,
								oldCredentialId,
								{
									...(expiry ? { expiresAt: expiry } : {}),
									dryRun: true,
									confirm: false,
								},
								{ signal },
							)),
						() => {
							let operationId: string | undefined;
							confirm(
								"Rotate credential?",
								"The current credential will be revoked and the replacement secret shown once.",
								"Rotate credential",
								() =>
									request(
										"Rotating credential…",
										(signal) => tenantMutation(tenantIdentity, signal, () =>
											client.tenant.rotateCredential(
												organizationId,
												accountId,
												oldCredentialId,
												{
													...(expiry ? { expiresAt: expiry } : {}),
													operationId: operationId ??= browserOperationId(),
													dryRun: false,
													confirm: true,
												},
												{ signal },
											)),
											(result) => {
												state.confirmation = undefined;
												showSecret("One-time credential", result.secret);
											},
										),
								{ retainOnFailure: true },
								);
						},
					);
				},
				"danger",
			),
			button(
				"Revoke credential",
				() => {
					const accountId = requireText(
						serviceId.input,
						"Service account ID",
					);
					const oldCredentialId = requireText(
						credentialId.input,
						"Credential ID",
					);
					const tenantIdentity = requireTenantIdentity();
					void request(
						"Previewing revocation…",
						(signal) => tenantMutation(tenantIdentity, signal, () =>
							client.tenant.revokeCredential(
								organizationId,
								accountId,
								oldCredentialId,
								{ dryRun: true, confirm: false },
								{ signal },
							)),
						() =>
							confirm(
								"Revoke credential?",
								"The credential will immediately stop authenticating.",
								"Revoke credential",
								() =>
									request("Revoking credential…", (signal) => tenantMutation(tenantIdentity, signal, () =>
										client.tenant.revokeCredential(
											organizationId,
											accountId,
											oldCredentialId,
											{ dryRun: false, confirm: true },
											{ signal },
										)),
									),
							),
					);
				},
				"danger",
			),
		);
		credential.form.append(
			serviceId.wrapper,
			credentialId.wrapper,
			expiresAt.wrapper,
			credentialActions,
		);
		grid.append(accounts, create.card, credential.card);
		container.append(grid);
	};

	const renderEnterprise = (container: HTMLElement) => {
		if (appendAuthRequired(container)) return;
		const organizationId = activeOrganizationId(state);
		if (!organizationId) {
			container.append(node("p", "cv-card cv-muted", "Select an active organization before managing enterprise connections."));
			return;
		}
		const value = (entry: TenantRecord, name: string): string =>
			typeof entry[name] === "string" ? entry[name] as string : "";
		const id = (entry: TenantRecord): string => value(entry, "connectionId") || value(entry, "id");
		const testResultStatus = (kind: "SSO" | "SCIM", result: TenantRecord): string => {
			if (result.mode === "live" && result.liveCertified === true) {
				return `${kind} live certification passed.`;
			}
			if (result.mode === "live") return `${kind} live test completed without certification.`;
			return `${kind} simulation completed; no live certification was issued.`;
		};
		const mutate = (
			previewStatus: string,
			confirmTitle: string,
			confirmDescription: string,
			confirmLabel: string,
			identity: TenantIdentity,
			preview: (signal: AbortSignal) => Promise<unknown>,
			apply: (signal: AbortSignal, operationId?: string) => Promise<unknown>,
			onApplied?: (result: unknown) => void,
			operationIdFactory?: () => string,
		) => void request(previewStatus, (signal) => tenantMutation(identity, signal, () => preview(signal)), () => {
			let confirmedOperationId: string | undefined;
			confirm(
				confirmTitle,
				confirmDescription,
				confirmLabel,
				() =>
					request(
						confirmLabel + "…",
						(signal) => {
							const operationId = operationIdFactory
								? (confirmedOperationId ??= operationIdFactory())
								: undefined;
							return tenantMutation(identity, signal, () => apply(signal, operationId));
						},
						(result) => {
							state.confirmation = undefined;
							onApplied?.(result);
						},
					),
				{ retainOnFailure: operationIdFactory !== undefined },
			);
		});
		const grid = node("div", "cv-grid");
		const sso = node("section", "cv-card");
		sso.append(node("h2", undefined, "Single sign-on providers"));
		const ssoList = node("ul", "cv-list");
		for (const provider of state.ssoProviders) {
			const connectionId = id(provider);
			const item = node("li", "cv-list-item");
			item.append(node("span", undefined, `${value(provider, "domain")} · ${(value(provider, "protocol") || value(provider, "type")).toUpperCase()} · ${value(provider, "status") || "active"}`));
			const identity = requireTenantIdentity();
			item.append(
				button("Inspect", () => void request("Inspecting SSO connection…", (signal) => tenantCall<TenantRecord>("inspectSso", organizationId, connectionId, { signal }), (result) => { state.status = `SSO connection ${value(result, "status") || "loaded"}.`; } ), "secondary"),
				button("Preview test", () => mutate("Previewing SSO test…", "Run SSO certification test?", "This simulation checks the current provider configuration without changing it.", "Run test", identity, (signal) => tenantCall("testSso", organizationId, connectionId, { dryRun: true, confirm: false }, { signal }), (signal) => tenantCall("testSso", organizationId, connectionId, { dryRun: false, confirm: true }, { signal }), (result) => { state.status = testResultStatus("SSO", result as TenantRecord); }), "secondary"),
				button("Disable", () => mutate("Previewing SSO disable…", "Disable SSO connection?", "This provider will stop authenticating this organization.", "Disable SSO", identity, (signal) => tenantCall("disableSso", organizationId, connectionId, { dryRun: true, confirm: false }, { signal }), (signal) => tenantCall("disableSso", organizationId, connectionId, { dryRun: false, confirm: true }, { signal }), () => void request("Refreshing enterprise connections…", refreshEnterprise)), "danger"),
			);
			ssoList.append(item);
		}
		if (!state.ssoProviders.length) {
			ssoList.append(node("li", "cv-muted", "No SSO providers configured."));
		}
		sso.append(ssoList);
		const ssoCreate = formCard("Create SSO provider");
		const ssoProtocol = node("select"); ssoProtocol.id = "cv-sso-protocol";
		for (const protocol of ["oidc", "saml"] as const) { const option = node("option", undefined, protocol.toUpperCase()); option.value = protocol; ssoProtocol.append(option); }
		const ssoProtocolLabel = node("label", undefined, "Protocol"); ssoProtocolLabel.htmlFor = ssoProtocol.id;
		const ssoProvider = field("cv-sso-provider", "Provider", "text", { required: true });
		const ssoIssuer = field("cv-sso-issuer", "Issuer", "url", { required: true });
		const ssoDomain = field("cv-sso-domain", "Domain", "text", { required: true });
		const ssoClientId = field("cv-sso-client-id", "OIDC client ID", "text");
		const ssoSecret = field("cv-sso-secret", "OIDC client secret", "password");
		const ssoEntryPoint = field("cv-sso-entry-point", "SAML entry point", "url");
		const ssoCertificate = field("cv-sso-certificate", "SAML certificate", "password");
		const ssoSubmit = button("Preview SSO provider", () => ssoCreate.form.requestSubmit()); ssoSubmit.type = "submit";
		ssoCreate.form.append(ssoProtocolLabel, ssoProtocol, ssoProvider.wrapper, ssoIssuer.wrapper, ssoDomain.wrapper, ssoClientId.wrapper, ssoSecret.wrapper, ssoEntryPoint.wrapper, ssoCertificate.wrapper, ssoSubmit);
		ssoCreate.form.addEventListener("submit", (event) => {
			event.preventDefault();
			const protocol = ssoProtocol.value as "oidc" | "saml";
			const input = protocol === "oidc" ? { protocol, provider: requireText(ssoProvider.input, "Provider"), issuer: requireText(ssoIssuer.input, "Issuer"), domain: requireText(ssoDomain.input, "Domain"), clientId: requireText(ssoClientId.input, "OIDC client ID"), clientSecret: requireText(ssoSecret.input, "OIDC client secret") } : { protocol, provider: requireText(ssoProvider.input, "Provider"), issuer: requireText(ssoIssuer.input, "Issuer"), domain: requireText(ssoDomain.input, "Domain"), samlEntryPoint: requireText(ssoEntryPoint.input, "SAML entry point"), samlCertificate: requireText(ssoCertificate.input, "SAML certificate") };
			const identity = requireTenantIdentity();
			mutate("Previewing SSO provider…", "Create SSO provider?", `Create this strict ${protocol.toUpperCase()} connection for the active organization.`, "Create SSO", identity, (signal) => tenantCall("createSso", organizationId, { ...input, dryRun: true, confirm: false }, { signal }), (signal) => tenantCall("createSso", organizationId, { ...input, dryRun: false, confirm: true }, { signal }), () => { ssoSecret.input.value = ""; ssoCertificate.input.value = ""; void request("Refreshing enterprise connections…", refreshEnterprise); });
		});
		const replaceSecret = formCard("Replace OIDC secret");
		const replaceId = field("cv-sso-secret-id", "SSO connection ID", "text", { required: true });
		const replaceValue = field("cv-sso-secret-value", "New OIDC client secret", "password", { required: true });
		const replaceSubmit = button("Preview secret replacement", () => replaceSecret.form.requestSubmit()); replaceSubmit.type = "submit";
		replaceSecret.form.append(replaceId.wrapper, replaceValue.wrapper, replaceSubmit);
		replaceSecret.form.addEventListener("submit", (event) => { event.preventDefault(); const connectionId = requireText(replaceId.input, "SSO connection ID"); const newClientSecret = requireText(replaceValue.input, "New OIDC client secret"); const identity = requireTenantIdentity(); mutate("Previewing secret replacement…", "Replace OIDC secret?", "The existing OIDC client secret will stop working.", "Replace secret", identity, (signal) => tenantCall("replaceSsoSecret", organizationId, connectionId, { newClientSecret, dryRun: true, confirm: false }, { signal }), (signal, operationId) => tenantCall("replaceSsoSecret", organizationId, connectionId, { newClientSecret, operationId: operationId!, dryRun: false, confirm: true }, { signal }), () => { replaceValue.input.value = ""; }, browserOperationId); });

		const scim = node("section", "cv-card");
		scim.append(node("h2", undefined, "Directory connections"));
		const scimList = node("ul", "cv-list");
		for (const connection of state.scimConnections) {
			const connectionId = id(connection);
			const item = node("li", "cv-list-item");
			item.append(node("span", undefined, `${value(connection, "provider")} · ${connectionId} · ${value(connection, "status") || "active"}`));
			const identity = requireTenantIdentity();
			item.append(button("Inspect", () => void request("Inspecting SCIM connection…", (signal) => tenantCall<TenantRecord>("inspectScim", organizationId, connectionId, { signal }), (result) => { state.status = `SCIM connection ${value(result, "status") || "loaded"}.`; }), "secondary"), button("Preview test", () => mutate("Previewing SCIM test…", "Run SCIM certification test?", "This simulation checks the current directory connection without changing it.", "Run test", identity, (signal) => tenantCall("testScim", organizationId, connectionId, { dryRun: true, confirm: false }, { signal }), (signal) => tenantCall("testScim", organizationId, connectionId, { dryRun: false, confirm: true }, { signal }), (result) => { state.status = testResultStatus("SCIM", result as TenantRecord); }), "secondary"), button("Rotate token", () => mutate("Previewing SCIM token rotation…", "Rotate SCIM bearer token?", "The current bearer token will stop working. A replacement token is shown once only if the server returns one.", "Rotate token", identity, (signal) => tenantCall("rotateScim", organizationId, connectionId, { dryRun: true, confirm: false }, { signal }), (signal, operationId) => tenantCall("rotateScim", organizationId, connectionId, { operationId: operationId!, dryRun: false, confirm: true }, { signal }), (result) => { const secret = (result as TenantRecord).bearerTokenOnce; if (typeof secret === "string" && secret) showSecret("One-time SCIM bearer token", secret); else state.status = "SCIM token rotated. No one-time token was returned."; }, browserOperationId), "danger"), button("Disable", () => mutate("Previewing SCIM disable…", "Disable SCIM connection?", "This directory connection will stop provisioning the organization.", "Disable SCIM", identity, (signal) => tenantCall("disableScim", organizationId, connectionId, { dryRun: true, confirm: false }, { signal }), (signal) => tenantCall("disableScim", organizationId, connectionId, { dryRun: false, confirm: true }, { signal }), () => void request("Refreshing enterprise connections…", refreshEnterprise)), "danger"));
			scimList.append(item);
		}
		if (!state.scimConnections.length) {
			scimList.append(
				node("li", "cv-muted", "No SCIM directory connections configured."),
			);
		}
		scim.append(scimList);

		const scimCreate = formCard("Create SCIM directory connection");
		const scimProvider = field("cv-scim-provider", "Provider", "text", { required: true });
		const scimEndpoint = field("cv-scim-endpoint", "Endpoint (optional)", "url");
		const scimSubmit = button("Preview SCIM connection", () => scimCreate.form.requestSubmit()); scimSubmit.type = "submit";
		scimCreate.form.append(scimProvider.wrapper, scimEndpoint.wrapper, scimSubmit);
		scimCreate.form.addEventListener("submit", (event) => { event.preventDefault(); const input = { provider: requireText(scimProvider.input, "Provider"), ...(scimEndpoint.input.value.trim() ? { endpoint: scimEndpoint.input.value.trim() } : {}) }; const identity = requireTenantIdentity(); mutate("Previewing SCIM connection…", "Create SCIM connection?", "A bearer token is shown once only if the server returns one after creation.", "Create SCIM", identity, (signal) => tenantCall("createScim", organizationId, { ...input, dryRun: true, confirm: false }, { signal }), (signal, operationId) => tenantCall("createScim", organizationId, { ...input, operationId: operationId!, dryRun: false, confirm: true }, { signal }), (result) => { const secret = (result as TenantRecord).bearerTokenOnce; if (typeof secret === "string" && secret) showSecret("One-time SCIM bearer token", secret); else state.status = "SCIM connection created. No one-time token was returned."; void request("Refreshing enterprise connections…", refreshEnterprise); }, browserOperationId); });
		const readiness = node("section", "cv-card");
		readiness.append(node("h2", undefined, "Enterprise readiness"), node("pre", "cv-muted", state.readiness ? JSON.stringify(state.readiness, null, 2) : "No readiness report is available."));
		grid.append(sso, ssoCreate.card, replaceSecret.card, scim, scimCreate.card, readiness);
		container.append(grid);
	};

	function render(): void {
		if (state.destroyed) return;
		const restoreMainFocus =
			document.activeElement instanceof HTMLElement &&
			document.activeElement.classList.contains("cv-main");
		renderVersion += 1;
		const version = renderVersion;
		const style = node("style");
		style.textContent = `${VAULT_STYLES}${
			accent
				? `\n@layer clearance-vault { .cv-root { --cv-accent: ${accent}; } }`
				: ""
		}`;
		if (config.styleNonce) style.nonce = config.styleNonce;
		const app = node("div", "cv-root");
		app.setAttribute("aria-busy", String(state.busy));
		const skip = node("a", "cv-skip", "Skip to content");
		skip.href = `#cv-main-${version}`;
		const layout = node("div", "cv-layout");
		let modal: HTMLElement | undefined;
		const sidebar = node("aside", "cv-sidebar");
		if (logoUrl) {
			const logo = node("img", "cv-brand-logo");
			logo.src = logoUrl;
			logo.alt = `${productName} logo`;
			sidebar.append(logo);
		}
		sidebar.append(node("p", "cv-brand", homeLabel));
		const nav = node("nav", "cv-nav");
		nav.setAttribute("aria-label", "Vault");
		for (const item of VAULT_WORKFLOWS) {
			const control = node("button", undefined, item.label);
			control.type = "button";
			control.dataset.route = item.id;
			if (item.id === state.route) control.setAttribute("aria-current", "page");
			control.addEventListener("click", () => navigate(item.id));
			nav.append(control);
		}
		sidebar.append(nav);
		const main = node("main", "cv-main");
		main.id = `cv-main-${version}`;
		main.tabIndex = -1;
		const selected = workflow(state.route);
		const header = node("header", "cv-header");
		header.append(
			node("h1", undefined, selected.label),
			node("p", "cv-muted", selected.description),
		);
		main.append(header);
		liveStatus.textContent = state.status;
		liveStatus.tabIndex = -1;
			main.append(liveStatus);
		if (state.error) {
			const error = node("p", "cv-error", state.error);
			error.setAttribute("role", "alert");
			main.append(error);
		}
			if (state.secret) {
				const secret = node("section", "cv-card");
				secret.tabIndex = -1;
				secret.setAttribute("role", "region");
				secret.setAttribute("aria-label", state.secret.title);
			secret.append(
				node("h2", undefined, state.secret.title),
				node(
					"p",
					"cv-muted",
					"Copy this value now. It is erased from this view when dismissed.",
				),
				node("pre", "cv-secret", state.secret.value),
			);
			const actions = node("div", "cv-actions");
			actions.append(
				button("Copy", () => {
					const value = state.secret?.value;
					if (!value) return;
					void navigator.clipboard
						.writeText(value)
						.then(() => {
							if (!state.destroyed) {
								state.status = "Copied.";
								render();
							}
						})
						.catch(() => {
							if (!state.destroyed) {
								state.error = "Clipboard access was denied. Select and copy the value.";
								render();
							}
						});
				}),
				button("I saved it — dismiss", clearSecret, "danger"),
			);
			secret.append(actions);
			main.append(secret);
		}
		const content = node("div");
		switch (state.route) {
			case "sign-in":
				renderSignIn(content);
				break;
			case "sign-up":
				renderSignUp(content);
				break;
			case "recovery":
				renderRecovery(content);
				break;
			case "account":
				renderAccount(content);
				break;
			case "organizations":
				renderOrganizations(content);
				break;
			case "invitations":
				renderInvitations(content);
				break;
			case "access":
				renderAccess(content);
				break;
			case "service-accounts":
				renderServiceAccounts(content);
				break;
			case "enterprise":
				renderEnterprise(content);
				break;
			case "audit":
				if (!appendAuthRequired(content)) {
					const audit = node("section", "cv-card");
					audit.append(node("h2", undefined, "Redacted tenant audit events"));
					const events = node("ul", "cv-list");
					for (const event of state.auditEvents) {
						events.append(node("li", "cv-list-item", JSON.stringify(event)));
					}
					if (!state.auditEvents.length) events.append(node("li", "cv-muted", "No audit events are available."));
					audit.append(events);
					content.append(audit);
				}
				break;
		}
		main.append(content);
		layout.append(sidebar, main);
		if (state.confirmation) {
			const pending = state.confirmation;
			skip.inert = true;
			skip.setAttribute("aria-hidden", "true");
			layout.inert = true;
			layout.setAttribute("aria-hidden", "true");
			const overlay = node("div", "cv-modal");
			const confirmation = node("section", "cv-card cv-confirm");
			confirmation.tabIndex = -1;
			confirmation.setAttribute("role", "alertdialog");
			confirmation.setAttribute("aria-modal", "true");
			const title = node("h2", undefined, pending.title);
			title.id = `cv-confirmation-title-${version}`;
			const description = node("p", undefined, pending.description);
			description.id = `cv-confirmation-description-${version}`;
			confirmation.setAttribute("aria-labelledby", title.id);
			confirmation.setAttribute("aria-describedby", description.id);
			const actions = node("div", "cv-actions");
			const approve = button(pending.label, () => {
				if (!pending.retainOnFailure) {
					state.confirmation = undefined;
					confirmationReturnFocusTarget = undefined;
				}
				clearSecretWithoutRender();
				focusStatusAfterRequest = true;
				void pending.execute();
			}, "danger");
			const cancel = button("Cancel", cancelConfirmation, "secondary");
			actions.append(approve, cancel);
			confirmation.append(title, description, actions);
			confirmation.addEventListener("keydown", (event) => {
				if (event.key === "Escape") {
					event.preventDefault();
					cancelConfirmation();
					return;
				}
				if (event.key !== "Tab") return;
				const controls = [approve, cancel].filter((control) => !control.disabled);
				const index = controls.indexOf(document.activeElement as HTMLButtonElement);
				if (event.shiftKey && (index <= 0 || index === -1)) {
					event.preventDefault();
					controls.at(-1)?.focus();
				} else if (!event.shiftKey && index === controls.length - 1) {
					event.preventDefault();
					controls[0]?.focus();
				}
			});
			overlay.append(confirmation);
			modal = overlay;
		}
		if (modal) app.append(modal);
		app.append(skip, layout);
		root.replaceChildren(
			...(config.styleMode === "external" ? [app] : [style, app]),
		);
		for (const control of root.querySelectorAll<HTMLButtonElement>("button")) {
			if (state.busy) control.disabled = true;
		}
		if (restoreMainFocus) {
			root.querySelector<HTMLElement>(".cv-main")?.focus();
		}
		if (pendingFocus) {
			const target =
				pendingFocus === "secret"
					? root.querySelector<HTMLElement>('[role="region"][aria-label]')
					: pendingFocus === "confirmation"
						? root.querySelector<HTMLElement>('[role="alertdialog"]')
					: pendingFocus === "status"
						? root.querySelector<HTMLElement>("[role='status']")
						: root.querySelector<HTMLElement>(".cv-main");
			pendingFocus = undefined;
			target?.focus();
		}
	}

	const onPopState = () => {
		navigate(routeFromURL(routeParam) ?? "sign-in", "none");
	};
	const onPageHide = () => {
		clearSecretWithoutRender();
		state.confirmation = undefined;
		confirmationReturnFocusTarget = undefined;
		if (!state.destroyed) render();
	};
	window.addEventListener("popstate", onPopState);
	window.addEventListener("pagehide", onPageHide);

	if (!recoveryTokenRef?.value) writeRoute(state.route, "replace");
	render();
	void request(
		"Checking your session…",
		refreshSession,
		() => {
			if (
				state.session &&
				!recoveryTokenRef?.value &&
				["sign-in", "sign-up", "recovery"].includes(state.route)
			) {
					state.route = "organizations";
					writeRoute(state.route, "replace");
			}
		},
		{ preserveRecoveryToken: true },
	).then(loadRoute);

	return Object.freeze({
		destroy() {
			if (state.destroyed) return;
			state.destroyed = true;
			requestGeneration += 1;
			for (const controller of controllers) controller.abort();
			controllers.clear();
			clearSecretWithoutRender();
			state.confirmation = undefined;
			confirmationReturnFocusTarget = undefined;
			window.removeEventListener("popstate", onPopState);
			window.removeEventListener("pagehide", onPageHide);
			root.replaceChildren();
		},
		navigate,
	});
}
