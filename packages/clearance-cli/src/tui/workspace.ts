import type { GlobalOpts } from "../output.js";
import type { ActionRisk, WorkflowAction, WorkflowField, WorkflowInvocation } from "./types.js";

export type WorkspaceSectionId =
	| "overview"
	| "people"
	| "security"
	| "operations";

type LegacyWorkspaceSectionId =
	| "users"
	| "organizations-access"
	| "events-delivery"
	| "enterprise"
	| "production-operations";

export interface WorkspaceSectionDefinition {
	readonly id: WorkspaceSectionId;
	readonly label: string;
	readonly description: string;
	readonly resourceKinds: readonly string[];
	readonly emptyState: string;
}

export const WORKSPACE_SECTIONS: readonly WorkspaceSectionDefinition[] = Object.freeze([
	Object.freeze({ id: "overview", label: "Overview", description: "Health and recent activity.", resourceKinds: ["overview"], emptyState: "Run an overview to begin." }),
	Object.freeze({ id: "people", label: "People", description: "Users, organizations, access, and sessions.", resourceKinds: ["user", "organization", "membership", "role", "session"], emptyState: "No people or organizations match this view." }),
	Object.freeze({ id: "security", label: "Security", description: "Audit, delivery, SSO, SCIM, and authentication policy.", resourceKinds: ["event", "delivery", "endpoint", "sso", "scim", "configuration"], emptyState: "No security activity or connections match this view." }),
	Object.freeze({ id: "operations", label: "Operations", description: "Readiness, backup, migration, upgrade, and schema work.", resourceKinds: ["readiness", "backup", "upgrade", "schema"], emptyState: "No operation history is available." }),
]);

export function normalizeWorkspaceSection(section: string | undefined): WorkspaceSectionId {
	if (section === "users" || section === "organizations-access") return "people";
	if (section === "events-delivery" || section === "enterprise") return "security";
	if (section === "production-operations") return "operations";
	if (section === "overview" || section === "people" || section === "security" || section === "operations") return section;
	return "overview";
}

export interface ManifestWorkspaceOperation {
	readonly path: string;
	readonly operationId?: string;
	readonly description?: string;
	readonly mutation: boolean;
	readonly confirmation: string;
	readonly supportsDryRun: boolean;
	readonly arguments?: readonly {
		readonly name: string;
		readonly description?: string;
		readonly required: boolean;
		readonly inputKind?: "value" | "file" | "secret" | "secret-file";
	}[];
	readonly options?: readonly {
		readonly flags: string;
		readonly description?: string;
		readonly required: boolean;
		readonly inputKind?: "value" | "file" | "secret" | "secret-file";
		readonly valueType?: "boolean" | "string" | "number" | "string-array";
		readonly defaultValue?: unknown;
	}[];
	readonly presentation?: {
		readonly section?: WorkspaceSectionId | LegacyWorkspaceSectionId;
		readonly resource?: string;
		readonly resultShape?: "list" | "detail" | "diff" | "receipt" | "stream" | "artifact";
	};
}

export interface TuiOperationSafety {
	readonly safe: boolean;
	readonly reason?: "stream" | "artifact";
}

const NON_INTERACTIVE_TUI_OPERATIONS: Readonly<Record<string, "stream" | "artifact">> = Object.freeze({
	"events tail": "stream",
	"events export": "artifact",
	"users export": "artifact",
	"schema generate": "artifact",
});

/**
 * Full-screen rendering owns stdout and must never dispatch commands that stream
 * directly to it or write an artifact as an incidental action.
 */
export function tuiOperationSafety(operation: ManifestWorkspaceOperation): TuiOperationSafety {
	const declaredShape = operation.presentation?.resultShape;
	if (declaredShape === "stream" || declaredShape === "artifact") {
		return Object.freeze({ safe: false, reason: declaredShape });
	}
	const reason = NON_INTERACTIVE_TUI_OPERATIONS[operation.path];
	return reason ? Object.freeze({ safe: false, reason }) : Object.freeze({ safe: true });
}

export function tuiSafeManifestOperations(
	manifest: readonly ManifestWorkspaceOperation[],
): readonly ManifestWorkspaceOperation[] {
	return Object.freeze(manifest.filter((operation) => tuiOperationSafety(operation).safe));
}

function quote(value: string): string {
	if (/^[A-Za-z0-9_./:@,+-]+$/u.test(value)) return value;
	return `'${value.replace(/'/gu, `'"'"'`)}'`;
}

export interface WorkspaceResourceRow {
	readonly id: string;
	readonly kind: string;
	readonly label: string;
	readonly description?: string;
	readonly status?: string;
	readonly data: Readonly<Record<string, unknown>>;
}

export interface WorkspacePage {
	readonly rows: readonly WorkspaceResourceRow[];
	readonly cursor?: string;
	readonly nextCursor?: string;
	readonly previousCursor?: string;
	readonly total?: number;
}

export interface SelectedRowAction {
	readonly actionId: string;
	readonly label: string;
	readonly risk: ActionRisk;
	readonly command: string;
	readonly invocation: WorkflowInvocation;
}

export interface WorkspaceSectionAdapter {
	readonly definition: WorkspaceSectionDefinition;
	readonly operations: readonly ManifestWorkspaceOperation[];
	readonly operationPaths: readonly string[];
	resourcePage(value: unknown, kind?: string): WorkspacePage;
	rowActions(row: WorkspaceResourceRow, actions: readonly WorkflowAction[], global?: Readonly<GlobalOpts>): readonly SelectedRowAction[];
}

function normalizedFieldKey(value: string): string {
	return value.replace(/[<>\[\]]/gu, "").replace(/^--/u, "").replace(/-([a-z])/gu, (_match, letter: string) => letter.toUpperCase());
}

function isRepeatableOption(option: NonNullable<ManifestWorkspaceOperation["options"]>[number]): boolean {
	return option.valueType === "string-array"
		|| Array.isArray(option.defaultValue)
		|| /\brepeat(?:able|ed)?\b/iu.test(option.description ?? "");
}

/** Adapts the shared command/experience manifest into form fields without copying parser metadata. */
export function manifestWorkflowFields(operation: ManifestWorkspaceOperation): readonly WorkflowField[] {
	const arguments_ = (operation.arguments ?? []).map((argument): WorkflowField => Object.freeze({
		key: normalizedFieldKey(argument.name),
		label: argument.description ?? argument.name.replace(/[<>\[\]]/gu, ""),
		required: argument.required,
		argument: true,
		placeholder: argument.required ? argument.name : "optional",
		secret: argument.inputKind === "secret" || argument.inputKind === "secret-file",
	}));
	const options = (operation.options ?? []).flatMap((option): WorkflowField[] => {
		const flag = option.flags.split(/[ ,|]+/u).find((candidate) => candidate.startsWith("--"));
		if (!flag) return [];
		const value = option.flags.match(/<([^>]+)>|\[([^\]]+)\]/u)?.[1] ?? option.flags.match(/<([^>]+)>|\[([^\]]+)\]/u)?.[2];
		const repeatable = isRepeatableOption(option);
		return [Object.freeze({
			key: normalizedFieldKey(flag),
			label: option.description ?? flag.slice(2),
			required: option.required,
			flag,
			placeholder: repeatable ? "value-one, value-two" : value ?? "true or false",
			repeatable,
			secret: option.inputKind === "secret" || option.inputKind === "secret-file",
		})];
	});
	return Object.freeze([...arguments_, ...options]);
}

/** Creates executable TUI actions directly from the shared experience manifest. */
export function workflowActionsFromManifest(manifest: readonly ManifestWorkspaceOperation[]): readonly WorkflowAction[] {
	return Object.freeze(tuiSafeManifestOperations(manifest).map((operation): WorkflowAction => {
		const sectionId = normalizeWorkspaceSection(operation.presentation?.section ?? inferredSection(operation.path));
		const definition = WORKSPACE_SECTIONS.find((section) => section.id === sectionId) ?? WORKSPACE_SECTIONS[0]!;
		const fields = manifestWorkflowFields(operation);
		const id = operation.operationId ?? operation.path.replace(/\s+/gu, "-");
		const label = conciseActionLabel(operation.path);
		const risk: ActionRisk = !operation.mutation ? "read" : operation.confirmation === "none" ? "mutation" : "destructive";
		return Object.freeze({
			id,
			area: definition.label as WorkflowAction["area"],
			label,
			description: operation.description?.trim() || `Run clearance ${operation.path}.`,
			path: operation.path,
			risk,
			mutation: operation.mutation,
			confirmation: operation.confirmation as WorkflowAction["confirmation"],
			supportsDryRun: operation.supportsDryRun,
			fields,
			invocation(values, inheritedGlobal = {}) {
				const args: string[] = [];
				const opts: Record<string, string | boolean | readonly string[]> = {};
				const command = ["clearance"];
				const global: GlobalOpts = { ...inheritedGlobal };
				if (operation.mutation && operation.confirmation !== "none" && !global.dryRun) global.yes = true;
				if (global.profile) command.push("--profile", quote(global.profile));
				if (global.apiUrl) command.push("--api-url", quote(global.apiUrl));
				if (global.dryRun) command.push("--dry-run");
				if (global.yes) command.push("--yes");
				command.push(...operation.path.split(" "));
				for (const field of fields) {
					const value = values[field.key]?.trim();
					if (!value) continue;
					if (field.argument) {
						args.push(value);
						command.push(quote(value));
					} else {
						const option = operation.options?.find((candidate) => candidate.flags.includes(field.flag ?? ""));
						const bool = option?.valueType === "boolean";
						const repeatable = option ? isRepeatableOption(option) : field.repeatable === true;
						if (repeatable) {
							const values = value.split(",").map((candidate) => candidate.trim()).filter(Boolean);
							if (!values.length) continue;
							opts[field.key] = Object.freeze(values);
							command.push(field.flag ?? `--${field.key}`, ...values.map(quote));
						} else {
							opts[field.key] = bool ? value !== "false" : value;
							if (!bool || value !== "false") command.push(field.flag ?? `--${field.key}`, ...(bool ? [] : [quote(value)]));
						}
					}
				}
				return { path: operation.path, args, opts, global, command: command.join(" ") };
			},
		});
	}));
}

function conciseActionLabel(path: string): string {
	const parts = path.trim().split(/\s+/u);
	if (parts.length === 1) return titleWords(parts[0] ?? "Action");
	const verb = parts.at(-1) ?? "open";
	const subject = parts.at(-2) ?? parts[0] ?? "item";
	const verbs: Readonly<Record<string, string>> = Object.freeze({
		list: "List",
		inspect: "View",
		create: "Create",
		update: "Update",
		disable: "Disable",
		delete: "Delete",
		archive: "Archive",
		add: "Add",
		remove: "Remove",
		replay: "Replay",
		retry: "Retry",
		cancel: "Cancel",
		get: "View",
		validate: "Validate",
		diff: "Compare",
		set: "Set",
		test: "Test",
		check: "Check",
		report: "View",
		verify: "Verify",
		restore: "Restore",
		plan: "Plan",
		apply: "Apply",
		status: "View",
	});
	if (verb === "setup-link") return "Create setup link";
	if (verb === "readiness") return `Check ${titleWords(subject).toLowerCase()} readiness`;
	if (verb === "quotas") return `View ${titleWords(subject).toLowerCase()} quotas`;
	const action = verbs[verb];
	return action ? `${action} ${titleWords(subject).toLowerCase()}` : parts.map(titleWords).join(" ");
}

function titleWords(value: string): string {
	return value.replace(/[-_]+/gu, " ").replace(/\b\p{L}/gu, (letter) => letter.toUpperCase());
}

function inferredSection(path: string): WorkspaceSectionId {
	const root = path.split(" ")[0];
	if (["users", "orgs", "roles", "sessions", "keys"].includes(root)) return "people";
	if (["events", "delivery", "sso", "scim", "auth-policy", "product", "config"].includes(root)) return "security";
	if (["readiness", "backup", "upgrade", "schema", "migration", "import", "key-management"].includes(root)) return "operations";
	return "overview";
}

function inferredResource(path: string): string {
	const root = path.split(" ")[0];
	return root === "users" ? "user"
		: root === "orgs" ? "organization"
			: root === "events" ? "event"
				: root === "delivery" ? "delivery"
					: root;
}

function asRecord(value: unknown): Readonly<Record<string, unknown>> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Readonly<Record<string, unknown>> : undefined;
}

function firstString(record: Readonly<Record<string, unknown>>, keys: readonly string[]): string | undefined {
	for (const key of keys) if (typeof record[key] === "string" && record[key]) return String(record[key]);
	return undefined;
}

const COLLECTION_KEYS = Object.freeze([
	"items",
	"data",
	"results",
	"users",
	"organizations",
	"members",
	"memberships",
	"assignments",
	"events",
	"recentEvents",
	"deliveries",
	"jobs",
	"endpoints",
	"connections",
	"sessions",
	"roles",
	"apiKeys",
	"serviceAccounts",
	"projects",
	"environments",
	"domains",
	"templates",
	"backups",
] as const);

const RESOURCE_OBJECT_KEYS = Object.freeze([
	"user",
	"organization",
	"membership",
	"event",
	"delivery",
	"job",
	"endpoint",
	"connection",
	"session",
	"role",
	"apiKey",
	"serviceAccount",
	"project",
	"environment",
	"domain",
	"template",
	"backup",
] as const);

function kindForResourceKey(key: string | undefined, fallbackKind: string): string {
	if (!key || key === "items" || key === "data" || key === "results") return fallbackKind;
	if (key === "users" || key === "user") return "user";
	if (key === "organizations" || key === "organization") return "organization";
	if (key === "members" || key === "memberships" || key === "membership") return "membership";
	if (key === "assignments") return "authorization-assignment";
	if (key === "recentEvents") return "event";
	if (key === "deliveries" || key === "jobs" || key === "delivery" || key === "job") return "delivery";
	if (key === "endpoints" || key === "endpoint") return "endpoint";
	if (key === "apiKeys" || key === "apiKey") return "api-key";
	if (key === "serviceAccounts" || key === "serviceAccount") return "service-account";
	if (key === "domains" || key === "domain") return "domain";
	if (key === "connections" || key === "connection") return fallbackKind === "sso" || fallbackKind === "scim" ? fallbackKind : "connection";
	return key.endsWith("s") ? key.slice(0, -1) : key;
}

function resourceCandidates(
	value: unknown,
	fallbackKind: string,
): { readonly values: readonly unknown[]; readonly kind: string; readonly container?: Readonly<Record<string, unknown>> } {
	if (Array.isArray(value)) return { values: value, kind: fallbackKind };
	const container = asRecord(value);
	if (!container) return { values: [], kind: fallbackKind };
	for (const key of COLLECTION_KEYS) {
		if (Array.isArray(container[key])) {
			return { values: container[key] as readonly unknown[], kind: kindForResourceKey(key, fallbackKind), container };
		}
	}
	for (const key of RESOURCE_OBJECT_KEYS) {
		if (asRecord(container[key])) {
			return { values: [container[key]], kind: kindForResourceKey(key, fallbackKind), container };
		}
	}
	return { values: [container], kind: fallbackKind, container };
}

function stableResourceId(record: Readonly<Record<string, unknown>>): string | undefined {
	const subject = asRecord(record.subject);
	const subjectKind = subject && firstString(subject, ["kind"]);
	const subjectId = subject && firstString(subject, ["id"]);
	const roleId = firstString(record, ["roleId"]);
	if (subjectKind && subjectId && roleId) return `${subjectKind}:${subjectId}:${roleId}`;
	const direct = firstString(record, [
		"id", "membershipId", "eventId", "deliveryId", "jobId", "endpointId", "connectionId", "sessionId",
		"apiKeyId", "serviceAccountId", "credentialId", "backupId", "traceId", "userId", "principalId", "organizationId",
		"roleId", "origin",
	]);
	return direct;
}

export function resourcePageFrom(value: unknown, fallbackKind = "resource"): WorkspacePage {
	const { values, kind: candidateKind, container } = resourceCandidates(value, fallbackKind);
	const rows = values.flatMap((item): WorkspaceResourceRow[] => {
		const record = asRecord(item);
		if (!record) return [];
		const id = stableResourceId(record);
		if (!id) return [];
		const kind = firstString(record, ["kind", "resourceType"]) ?? candidateKind;
		const label = firstString(record, ["name", "displayName", "email", "action", "slug", "origin", "id"]) ?? id;
		const description = firstString(record, ["description", "summary", "message"]);
		const status = firstString(record, ["status", "state", "phase"]);
		return [Object.freeze({ id, kind, label, ...(description ? { description } : {}), ...(status ? { status } : {}), data: record })];
	});
	return Object.freeze({
		rows: Object.freeze(rows),
		...(typeof container?.cursor === "string" ? { cursor: container.cursor } : {}),
		...(typeof container?.nextCursor === "string" ? { nextCursor: container.nextCursor } : {}),
		...(typeof container?.previousCursor === "string" ? { previousCursor: container.previousCursor } : {}),
		...(typeof container?.total === "number" ? { total: container.total }
			: typeof container?.count === "number" ? { total: container.count } : {}),
	});
}

const ROW_ACTIONS: Readonly<Record<string, readonly string[]>> = Object.freeze({
	user: Object.freeze(["users-inspect", "users-update", "users-disable", "users-delete"]),
	organization: Object.freeze(["orgs-inspect", "members-list", "members-add", "orgs-archive"]),
	event: Object.freeze(["events-inspect", "events-replay"]),
	delivery: Object.freeze(["delivery-inspect", "delivery-retry", "delivery-cancel"]),
	sso: Object.freeze(["sso-test"]),
	scim: Object.freeze(["scim-test", "scim-replay"]),
	backup: Object.freeze(["backup-verify", "backup-restore"]),
});

function valuesForRow(action: WorkflowAction, row: WorkspaceResourceRow): Readonly<Record<string, string>> {
	const values: Record<string, string> = {};
	for (const field of action.fields) {
		if (field.key === "id" || field.key === "traceId") values[field.key] = row.id;
		else if (field.key === "org") values[field.key] = row.id;
	}
	return values;
}

function rowActions(row: WorkspaceResourceRow, actions: readonly WorkflowAction[], global: Readonly<GlobalOpts> = {}): readonly SelectedRowAction[] {
	const allowed = new Set(ROW_ACTIONS[row.kind] ?? []);
	return Object.freeze(actions.filter((action) => allowed.has(action.id)).map((action) => {
		const invocation = action.invocation(valuesForRow(action, row), global);
		return Object.freeze({ actionId: action.id, label: action.label, risk: action.risk, command: invocation.command, invocation });
	}));
}

export function createWorkspaceAdapters(
	manifest: readonly ManifestWorkspaceOperation[],
): readonly WorkspaceSectionAdapter[] {
	const safeManifest = tuiSafeManifestOperations(manifest);
	return Object.freeze(WORKSPACE_SECTIONS.map((definition) => {
		const relevant = safeManifest.filter((operation) => normalizeWorkspaceSection(operation.presentation?.section ?? inferredSection(operation.path)) === definition.id);
		return Object.freeze({
			definition,
			operations: Object.freeze(relevant),
			operationPaths: Object.freeze(relevant.map((operation) => operation.path)),
			resourcePage(value: unknown, kind?: string) {
				const inferred = kind ?? relevant[0]?.presentation?.resource ?? (relevant[0] ? inferredResource(relevant[0].path) : definition.resourceKinds[0]);
				return resourcePageFrom(value, inferred);
			},
			rowActions,
		});
	}));
}

export type WorkspaceViewMode = "list" | "detail" | "actions" | "raw";

export interface SectionWorkspaceState {
	readonly mode: WorkspaceViewMode;
	readonly page: WorkspacePage;
	readonly selectedIndex: number;
	readonly selectedId?: string;
	readonly cursorHistory: readonly (string | undefined)[];
	readonly scrollOffset: number;
	readonly actionIndex: number;
}

export interface ResourceWorkspaceState {
	readonly sectionId: WorkspaceSectionId;
	readonly sections: Readonly<Record<WorkspaceSectionId, SectionWorkspaceState>>;
}

function emptySectionState(): SectionWorkspaceState {
	return Object.freeze({ mode: "list", page: Object.freeze({ rows: Object.freeze([]) }), selectedIndex: 0, cursorHistory: Object.freeze([]), scrollOffset: 0, actionIndex: 0 });
}

export function initialResourceWorkspace(sectionId: WorkspaceSectionId = "overview"): ResourceWorkspaceState {
	return Object.freeze({
		sectionId,
		sections: Object.freeze(Object.fromEntries(WORKSPACE_SECTIONS.map((section) => [section.id, emptySectionState()])) as unknown as Record<WorkspaceSectionId, SectionWorkspaceState>),
	});
}

export function activateWorkspaceSection(state: ResourceWorkspaceState, sectionId: WorkspaceSectionId): ResourceWorkspaceState {
	return Object.freeze({ ...state, sectionId });
}

export function updateWorkspacePage(state: ResourceWorkspaceState, sectionId: WorkspaceSectionId, page: WorkspacePage): ResourceWorkspaceState {
	const current = state.sections[sectionId];
	const preservedIndex = current.selectedId ? page.rows.findIndex((row) => row.id === current.selectedId) : -1;
	const selectedIndex = preservedIndex >= 0 ? preservedIndex : Math.min(current.selectedIndex, Math.max(0, page.rows.length - 1));
	const selectedId = page.rows[selectedIndex]?.id;
	return Object.freeze({
		...state,
		sections: Object.freeze({
			...state.sections,
			[sectionId]: Object.freeze({ ...current, page, selectedIndex, ...(selectedId ? { selectedId } : { selectedId: undefined }) }),
		}),
	});
}

export function selectWorkspaceRow(state: ResourceWorkspaceState, sectionId: WorkspaceSectionId, index: number): ResourceWorkspaceState {
	const current = state.sections[sectionId];
	const selectedIndex = Math.min(Math.max(0, index), Math.max(0, current.page.rows.length - 1));
	const selectedId = current.page.rows[selectedIndex]?.id;
	return Object.freeze({
		...state,
		sections: Object.freeze({ ...state.sections, [sectionId]: Object.freeze({ ...current, selectedIndex, selectedId, scrollOffset: 0, actionIndex: 0 }) }),
	});
}

export function setWorkspaceMode(state: ResourceWorkspaceState, sectionId: WorkspaceSectionId, mode: WorkspaceViewMode): ResourceWorkspaceState {
	const current = state.sections[sectionId];
	return Object.freeze({ ...state, sections: Object.freeze({ ...state.sections, [sectionId]: Object.freeze({ ...current, mode }) }) });
}

export function scrollWorkspaceDetail(state: ResourceWorkspaceState, sectionId: WorkspaceSectionId, delta: number): ResourceWorkspaceState {
	const current = state.sections[sectionId];
	const scrollOffset = Math.max(0, current.scrollOffset + delta);
	return Object.freeze({ ...state, sections: Object.freeze({ ...state.sections, [sectionId]: Object.freeze({ ...current, scrollOffset }) }) });
}

export function selectWorkspaceAction(state: ResourceWorkspaceState, sectionId: WorkspaceSectionId, index: number, count: number): ResourceWorkspaceState {
	if (count < 1) return state;
	const current = state.sections[sectionId];
	const actionIndex = (index + count) % count;
	return Object.freeze({ ...state, sections: Object.freeze({ ...state.sections, [sectionId]: Object.freeze({ ...current, actionIndex }) }) });
}

export function advanceWorkspaceCursor(state: ResourceWorkspaceState, sectionId: WorkspaceSectionId): ResourceWorkspaceState {
	const current = state.sections[sectionId];
	if (!current.page.nextCursor) return state;
	const cursorHistory = [...current.cursorHistory, current.page.cursor];
	return Object.freeze({
		...state,
		sections: Object.freeze({ ...state.sections, [sectionId]: Object.freeze({ ...current, cursorHistory: Object.freeze(cursorHistory), page: Object.freeze({ ...current.page, cursor: current.page.nextCursor }) }) }),
	});
}

export function retreatWorkspaceCursor(state: ResourceWorkspaceState, sectionId: WorkspaceSectionId): ResourceWorkspaceState {
	const current = state.sections[sectionId];
	if (!current.cursorHistory.length && !current.page.previousCursor) return state;
	const cursor = current.cursorHistory.length ? current.cursorHistory.at(-1) : current.page.previousCursor;
	return Object.freeze({
		...state,
		sections: Object.freeze({
			...state.sections,
			[sectionId]: Object.freeze({
				...current,
				cursorHistory: Object.freeze(current.cursorHistory.slice(0, -1)),
				page: Object.freeze({ ...current.page, cursor }),
			}),
		}),
	});
}
