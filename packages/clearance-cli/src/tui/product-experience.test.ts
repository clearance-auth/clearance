import { describe, expect, it, vi } from "vitest";
import { WORKFLOW_ACTIONS } from "./catalog.js";
import { parseTuiDeepLink } from "./deep-link.js";
import { closeModal, contextualHelp, initialFeedbackState, pushToast, showModal, upsertNotice } from "./feedback.js";
import { initialPollingRefreshState, markPollingRefreshFailed, markPollingRefreshStarted, markPollingRefreshSucceeded, setVisiblePanel } from "./live.js";
import { createMemoryPreferenceStore, DEFAULT_TUI_PREFERENCES, parseTuiPreferences } from "./preferences.js";
import { initialTuiState, TuiController } from "./model.js";
import { renderTui } from "./render.js";
import { cellWidth, resolveTerminalAppearance, sanitizeTerminalText, truncateCells, wrapCells } from "./terminal.js";
import { renderStructuredView, structuredViewFor } from "./views.js";
import { advanceWorkspaceCursor, createWorkspaceAdapters, initialResourceWorkspace, manifestWorkflowFields, normalizeWorkspaceSection, resourcePageFrom, retreatWorkspaceCursor, scrollWorkspaceDetail, selectWorkspaceRow, tuiOperationSafety, workflowActionsFromManifest, updateWorkspacePage, WORKSPACE_SECTIONS } from "./workspace.js";

describe("resource workspace", () => {
	it("defines four task-oriented product sections and adapts legacy manifest sections", () => {
		expect(WORKSPACE_SECTIONS.map((section) => section.label)).toEqual([
			"Overview", "People", "Security", "Operations",
		]);
		const adapters = createWorkspaceAdapters([
			{ path: "users list", mutation: false, confirmation: "none", supportsDryRun: false, presentation: { section: "users" } },
			{ path: "backup restore", mutation: true, confirmation: "server-required", supportsDryRun: false, presentation: { section: "production-operations" } },
		]);
		expect(adapters.find((adapter) => adapter.definition.id === "people")?.operationPaths).toEqual(["users list"]);
		expect(adapters.find((adapter) => adapter.definition.id === "operations")?.operationPaths).toEqual(["backup restore"]);
		expect(normalizeWorkspaceSection("organizations-access")).toBe("people");
		expect(normalizeWorkspaceSection("enterprise")).toBe("security");
		expect(manifestWorkflowFields({
			path: "keys create",
			mutation: true,
			confirmation: "none",
			supportsDryRun: false,
			arguments: [],
			options: [{ flags: "--secret <value>", description: "Secret", required: true, inputKind: "secret" }],
		})).toEqual([expect.objectContaining({ key: "secret", flag: "--secret", secret: true })]);
	});

	it("retains every value from repeatable manifest options", () => {
		const [action] = workflowActionsFromManifest([{
			path: "roles create",
			operationId: "roles.create",
			mutation: true,
			confirmation: "none",
			supportsDryRun: true,
			options: [
				{ flags: "--name <name>", required: true, valueType: "string" },
				{ flags: "--permission <permission...>", description: "Permissions", required: true, valueType: "string-array" },
			],
		}]);
		expect(action?.fields[1]).toMatchObject({ key: "permission", repeatable: true, placeholder: "value-one, value-two" });
		expect(action?.invocation({ name: "Operator", permission: "users:read, orgs:write" })).toMatchObject({
			opts: { name: "Operator", permission: ["users:read", "orgs:write"] },
			command: "clearance roles create --name Operator --permission users:read orgs:write",
		});
		const [serviceAccount] = workflowActionsFromManifest([{
			path: "orgs service-accounts create",
			mutation: true,
			confirmation: "none",
			supportsDryRun: true,
			options: [{ flags: "--role <id>", description: "Role id; repeat for each assignment", required: false, valueType: "string", defaultValue: [] }],
		}]);
		expect(serviceAccount?.invocation({ role: "role_a, role_b" }).opts.role).toEqual(["role_a", "role_b"]);
		expect(action?.label).toBe("Create roles");
		expect(serviceAccount?.label).toBe("Create service accounts");
	});

	it("preserves selected resource identity across pages and exposes exact row commands", () => {
		let state = initialResourceWorkspace("people");
		state = updateWorkspacePage(state, "people", resourcePageFrom([{ id: "usr_1", email: "one@example.com" }, { id: "usr_2", email: "two@example.com" }], "user"));
		state = selectWorkspaceRow(state, "people", 1);
		state = updateWorkspacePage(state, "people", resourcePageFrom([{ id: "usr_0" }, { id: "usr_2", email: "updated@example.com" }], "user"));
		expect(state.sections.people.selectedId).toBe("usr_2");
		expect(state.sections.people.selectedIndex).toBe(1);
		const adapter = createWorkspaceAdapters([{ path: "users list", mutation: false, confirmation: "none", supportsDryRun: false }])[1];
		const actions = adapter?.rowActions(state.sections.people.page.rows[1]!, WORKFLOW_ACTIONS, { profile: "prod" }) ?? [];
		expect(actions.find((action) => action.actionId === "users-delete")?.command).toBe("clearance --profile prod --yes users delete usr_2");
		state = updateWorkspacePage(state, "people", { ...state.sections.people.page, cursor: "page-1", nextCursor: "page-2" });
		state = advanceWorkspaceCursor(state, "people");
		expect(state.sections.people.page.cursor).toBe("page-2");
		state = retreatWorkspaceCursor(state, "people");
		expect(state.sections.people.page.cursor).toBe("page-1");
	});

	it("unwraps canonical collection envelopes into resource rows with real identities", () => {
		expect(resourcePageFrom({ users: [{ id: "usr_1", email: "one@example.com" }], nextCursor: "next", count: 7 }, "user"))
			.toMatchObject({ rows: [{ id: "usr_1", kind: "user", label: "one@example.com" }], nextCursor: "next", total: 7 });
		expect(resourcePageFrom({ organizations: [{ id: "org_1", name: "Acme" }] }, "organization").rows)
			.toMatchObject([{ id: "org_1", kind: "organization", label: "Acme" }]);
		expect(resourcePageFrom({ members: [{ membershipId: "mem_1", principalId: "usr_1", role: "admin" }] }, "organization").rows)
			.toMatchObject([{ id: "mem_1", kind: "membership" }]);
		expect(resourcePageFrom({ connections: [{ connectionId: "sso_1", status: "active" }] }, "sso").rows)
			.toMatchObject([{ id: "sso_1", kind: "sso", status: "active" }]);
		expect(resourcePageFrom({ user: { id: "usr_2", email: "two@example.com" }, scope: { projectId: "proj_1" } }, "user").rows)
			.toMatchObject([{ id: "usr_2", kind: "user", label: "two@example.com", data: { id: "usr_2" } }]);
		expect(resourcePageFrom({ serviceAccounts: [{ organizationId: "org_1", serviceAccountId: "svc_1", name: "Worker" }] }, "service-account").rows)
			.toMatchObject([{ id: "svc_1", kind: "service-account", label: "Worker" }]);
		expect(resourcePageFrom({ domains: [{ origin: "https://login.example.com", hostname: "login.example.com", state: "verified" }] }, "domain").rows)
			.toMatchObject([{ id: "https://login.example.com", kind: "domain", label: "https://login.example.com" }]);
		expect(resourcePageFrom({ assignments: [{ organizationId: "org_1", subject: { kind: "principal", id: "usr_1" }, roleId: "role_admin" }] }, "authorization-assignment").rows)
			.toMatchObject([{ id: "principal:usr_1:role_admin", kind: "authorization-assignment" }]);
		expect(resourcePageFrom({ result: "summary without identity" }, "result").rows).toEqual([]);
	});

	it("keeps streams and artifact writers out of generated TUI actions and adapters", () => {
		const manifest = [
			{ path: "events list", mutation: false, confirmation: "none", supportsDryRun: false },
			{ path: "events tail", mutation: false, confirmation: "none", supportsDryRun: false },
			{ path: "events export", mutation: true, confirmation: "none", supportsDryRun: false },
			{ path: "users export", mutation: true, confirmation: "none", supportsDryRun: false },
			{ path: "schema generate", mutation: true, confirmation: "none", supportsDryRun: true },
			{ path: "custom stream", mutation: false, confirmation: "none", supportsDryRun: false, presentation: { resultShape: "stream" as const } },
			{ path: "custom artifact", mutation: false, confirmation: "none", supportsDryRun: false, presentation: { resultShape: "artifact" as const } },
		] as const;
		expect(tuiOperationSafety(manifest[1])).toEqual({ safe: false, reason: "stream" });
		expect(tuiOperationSafety(manifest[2])).toEqual({ safe: false, reason: "artifact" });
		expect(workflowActionsFromManifest(manifest).map((action) => action.path)).toEqual(["events list"]);
		expect(createWorkspaceAdapters(manifest).flatMap((adapter) => adapter.operationPaths)).toEqual(["events list"]);
	});

	it("drives the live controller from a list result into resource detail and raw views", async () => {
		const manifest = [{ path: "users list", mutation: false, confirmation: "none", supportsDryRun: false }] as const;
		const execute = Object.assign(async () => ({ users: [{ id: "usr_1", email: "one@example.com" }, { id: "usr_2", email: "two@example.com" }] }), { global: {} });
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			actions: WORKFLOW_ACTIONS,
			adapters: createWorkspaceAdapters(manifest),
		});
		controller.handleKey("\u001b[C");
		controller.handleKey("\r");
		controller.handleKey("\r");
		controller.handleKey("\r");
		await controller.waitForIdle();
		expect(controller.state.workspaceFocus).toBe("resources");
		expect(controller.state.workspace.sections.people.page.rows.map((row) => row.id)).toEqual(["usr_1", "usr_2"]);
		controller.handleKey("j");
		controller.handleKey("\r");
		controller.handleKey("v");
		expect(controller.state.workspace.sections.people.selectedId).toBe("usr_2");
		expect(controller.state.workspace.sections.people.mode).toBe("detail");
		expect(controller.state.preferences.rawJson).toBe(true);
		const frame = renderTui(controller.state, controller.visibleActions, { color: false, width: 100, height: 30 });
		expect(frame).toContain("two@example.com");
		expect(frame).not.toContain("clearance users inspect usr_2");
		controller.state.mode = "help";
		expect(renderTui(controller.state, controller.visibleActions, { color: false, width: 100, height: 30 })).toContain("clearance users inspect usr_2");
	});

	it("executes an initial deep-link inspect and opens its returned detail", async () => {
		const target = parseTuiDeepLink(["tui", "--organization", "org_123"]);
		const execute = vi.fn(async () => ({ id: "org_123", name: "Acme" }));
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			actions: WORKFLOW_ACTIONS,
			adapters: createWorkspaceAdapters([{ path: "orgs inspect", mutation: false, confirmation: "none", supportsDryRun: false }]),
			initialTarget: target,
		});
		await Promise.resolve();
		await controller.waitForIdle();
		expect(execute).toHaveBeenCalledWith(expect.objectContaining({ path: "orgs inspect", args: ["org_123"] }), expect.anything());
		expect(controller.state.workspace.sectionId).toBe("people");
		expect(controller.state.workspace.sections.people).toMatchObject({ mode: "detail", selectedId: "org_123" });
	});

	it("resolves list-backed deep links to the requested resource", async () => {
		const target = parseTuiDeepLink(["tui", "--sso", "sso_123"]);
		const execute = vi.fn(async () => ({ items: [{ id: "sso_other" }, { id: "sso_123", status: "active" }] }));
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			actions: WORKFLOW_ACTIONS,
			adapters: createWorkspaceAdapters([{ path: "sso list", mutation: false, confirmation: "none", supportsDryRun: false }]),
			initialTarget: target,
		});
		await Promise.resolve();
		await controller.waitForIdle();
		expect(execute).toHaveBeenCalledWith(expect.objectContaining({ path: "sso list" }), expect.anything());
		expect(controller.state.workspace.sections.security).toMatchObject({ mode: "detail", selectedId: "sso_123" });
	});

	it("dispatches selected-row actions and fetches next and previous pages", async () => {
		const execute = vi.fn(async (invocation: { readonly path: string; readonly args: readonly string[]; readonly opts: Readonly<Record<string, string | boolean>> }) => {
			if (invocation.path === "users inspect") return { id: invocation.args[0], email: "one@example.com" };
			if (invocation.opts.cursor === "page-2") return { items: [{ id: "usr_2", email: "two@example.com" }], previousCursor: "page-1", total: 2 };
			return { items: [{ id: "usr_1", email: "one@example.com" }], nextCursor: "page-2", total: 2 };
		});
		const manifest = [
			{ path: "users list", mutation: false, confirmation: "none", supportsDryRun: false },
			{ path: "users inspect", mutation: false, confirmation: "none", supportsDryRun: false },
		] as const;
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			actions: WORKFLOW_ACTIONS,
			adapters: createWorkspaceAdapters(manifest),
		});
		controller.handleKey("\u001b[C");
		controller.handleKey("\r");
		controller.handleKey("\r");
		controller.handleKey("\r");
		await controller.waitForIdle();
		controller.handleKey("a");
		expect(controller.state.workspace.sections.people.mode).toBe("actions");
		controller.handleKey("\r");
		await controller.waitForIdle();
		expect(execute.mock.calls.at(-1)?.[0]).toMatchObject({ path: "users inspect", args: ["usr_1"] });

		controller.handleKey("n");
		await controller.waitForIdle();
		expect(execute.mock.calls.at(-1)?.[0]).toMatchObject({ path: "users list", opts: { cursor: "page-2" } });
		expect(controller.state.workspace.sections.people.selectedId).toBe("usr_2");
		controller.handleKey("p");
		await controller.waitForIdle();
		expect(execute.mock.calls.at(-1)?.[0]).toMatchObject({ path: "users list", opts: {} });
		expect(controller.state.workspace.sections.people.selectedId).toBe("usr_1");
	});

	it("keeps long resource lists and details navigable within a small viewport", () => {
		const state = initialTuiState();
		state.workspace = updateWorkspacePage(state.workspace, "people", resourcePageFrom(Array.from({ length: 30 }, (_, index) => ({
			id: `usr_${index + 1}`,
			email: `person-${index + 1}@example.com`,
			description: "A long resource detail ".repeat(12),
		})), "user"));
		state.workspace = selectWorkspaceRow(state.workspace, "people", 24);
		state.workspace = { ...state.workspace, sectionId: "people" };
		state.workspaceFocus = "resources";
		const initialFrame = renderTui(state, WORKFLOW_ACTIONS.filter((action) => action.area === "People"), { color: false, width: 90, height: 16 });
		expect(initialFrame).toContain("person-25@example.com");
		expect(initialFrame).not.toContain("person-1@example.com");
		state.workspace = scrollWorkspaceDetail(state.workspace, "people", 8);
		const scrolledFrame = renderTui(state, WORKFLOW_ACTIONS.filter((action) => action.area === "People"), { color: false, width: 90, height: 16 });
		expect(scrolledFrame).not.toBe(initialFrame);
		expect(scrolledFrame).toContain("A long resource detail");
	});
});

describe("structured views and terminal geometry", () => {
	it("renders width-aware lists, details, diffs, and raw JSON", () => {
		const list = renderStructuredView(structuredViewFor([{ id: "usr_1", name: "東京", status: "active" }]), { width: 40 });
		expect(list.join("\n")).toContain("東京");
		expect(list.every((line) => cellWidth(line) <= 40)).toBe(true);
		const diff = renderStructuredView(structuredViewFor({ before: { enabled: false }, after: { enabled: true } }), { width: 60 });
		expect(diff.join("\n")).toContain("false → true");
		const raw = renderStructuredView(structuredViewFor({ id: "usr_1" }, { raw: true }), { width: 60 });
		expect(raw.join("\n")).toContain('"id": "usr_1"');
		const connections = renderStructuredView(structuredViewFor({ connections: [{ id: "sso_1", status: "active" }] }), { width: 60 });
		expect(connections.join("\n")).toContain("sso_1");
	});

	it("measures graphemes and sanitizes terminal control content", () => {
		expect(cellWidth("東京")).toBe(4);
		expect(cellWidth("e\u0301")).toBe(1);
		expect(cellWidth(truncateCells("東京abc", 5))).toBeLessThanOrEqual(5);
		expect(wrapCells("東京 account", 8)).toEqual(["東京", "account"]);
		expect(sanitizeTerminalText("a\u001b[31mb\u202ec")).toBe("abc");
		expect(resolveTerminalAppearance({ env: { NO_COLOR: "1" }, requestedColor: true, isTTY: true }).color).toBe(false);
	});
});

describe("feedback, live refresh, preferences, and deep links", () => {
	it("keeps successful automatic refreshes quiet while retaining failure feedback", async () => {
		const execute = vi.fn()
			.mockResolvedValueOnce({ items: [{ id: "usr_1" }] })
			.mockResolvedValueOnce({ items: [{ id: "usr_1", status: "active" }] })
			.mockRejectedValueOnce(Object.assign(new Error("offline"), { code: "CLI_API_UNREACHABLE" }));
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			actions: WORKFLOW_ACTIONS,
			adapters: createWorkspaceAdapters([{ path: "users list", mutation: false, confirmation: "none", supportsDryRun: false }]),
		});
		controller.handleKey("\u001b[C");
		controller.handleKey("\r");
		controller.handleKey("\r");
		controller.handleKey("\r");
		await controller.waitForIdle();
		controller.state.feedback = initialFeedbackState();
		controller.state.notice = undefined;
		controller.refreshVisibleWorkspace();
		await controller.waitForIdle();
		expect(controller.state.feedback.toasts).toEqual([]);
		expect(controller.state.notice).toBeUndefined();
		controller.refreshVisibleWorkspace();
		await controller.waitForIdle();
		expect(controller.state.feedback.modal?.title).toBe("Refresh failed");
		expect(controller.state.feedback.notices.at(-1)?.severity).toBe("error");
			expect(controller.state.refresh.status).toBe("offline");
	});

	it("separates transient, persistent, and blocking feedback", () => {
		let state = initialFeedbackState();
		state = pushToast(state, { id: "done", message: "Saved", severity: "success" }, 100);
		state = upsertNotice(state, { id: "offline", message: "Offline", severity: "warning" });
		state = showModal(state, { id: "retry", title: "Refresh failed", message: "Retry?", severity: "error", actions: [{ id: "retry", label: "Retry", primary: true }] });
		expect(state.toasts[0]?.expiresAt).toBe(4_100);
		expect(state.notices[0]?.id).toBe("offline");
		expect(closeModal(state, "retry").modal).toBeUndefined();
		expect(contextualHelp("resource-detail").map((binding) => binding.label)).toContain("help");
		expect(contextualHelp("action-list")).toEqual(expect.arrayContaining([
			expect.objectContaining({ keys: "Enter", label: "open" }),
			expect.objectContaining({ keys: "?", label: "help" }),
		]));
	});

	it("tracks the interval poller without implying a push connection", () => {
		let state = setVisiblePanel(initialPollingRefreshState(), "security");
		expect(state).toMatchObject({ status: "polling", visiblePanel: "security" });
		state = markPollingRefreshStarted(state, 10);
		expect(state).toMatchObject({ status: "refreshing", lastAttemptAt: 10 });
		state = markPollingRefreshFailed(state, { unreachable: true, now: 100 });
		expect(state).toMatchObject({ status: "offline", staleSince: 100 });
		state = markPollingRefreshStarted(state, 200);
		state = markPollingRefreshSucceeded(state, 210);
		expect(state).toMatchObject({ status: "polling", lastAttemptAt: 200, lastSuccessfulAt: 210 });
		expect(state.staleSince).toBeUndefined();
	});

	it("persists normalized preferences through the store contract", async () => {
		const store = createMemoryPreferenceStore();
		await store.save(parseTuiPreferences({ theme: "light", color: "never", refreshIntervalMs: 1, rawJson: true }));
		expect(await store.load()).toMatchObject({ theme: "light", color: "never", refreshIntervalMs: 2_000, rawJson: true });
		expect(DEFAULT_TUI_PREFERENCES.version).toBe(1);
	});

	it("parses CLI-to-TUI deep links and rejects unsafe identifiers", () => {
		expect(parseTuiDeepLink(["tui", "--user", "usr_123"])).toMatchObject({ sectionId: "people", id: "usr_123" });
		expect(parseTuiDeepLink(["--profile", "prod", "events", "inspect", "evt_123", "--remote"])).toMatchObject({ sectionId: "security", source: "remote-command" });
		expect(parseTuiDeepLink(["tui", "--sso", "sso_123"])).toMatchObject({ sectionId: "security", resource: "sso" });
		expect(() => parseTuiDeepLink(["tui", "--user", "$(unsafe)"])).toThrow(/safe resource identifier/);
		expect(() => parseTuiDeepLink(["tui", "--user", "usr_1", "--org", "org_1"])).toThrow(/exactly one/);
		expect(() => parseTuiDeepLink(["tui", "--backup", "backup_1"])).toThrow(/supported.*deep-link|exactly one|safe resource identifier/i);
		expect(() => parseTuiDeepLink(["tui", "--open", "backup", "backup_1"])).toThrow(/expects user, organization, event, delivery, sso, or scim/);
		expect(() => parseTuiDeepLink(["sso", "inspect", "sso_123", "--remote"])).toThrow(/supported/);
	});
});
