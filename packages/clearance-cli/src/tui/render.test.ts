import { describe, expect, it } from "vitest";
import { actionsFor } from "./catalog.js";
import { initialTuiState } from "./model.js";
import { renderTui } from "./render.js";

describe("renderTui", () => {
	it("keeps the default workspace quiet and task-oriented", () => {
		const state = initialTuiState();
		state.snapshots.overview = { data: { users: 7 } };
		const frame = renderTui(state, actionsFor("Overview"), {
			color: false,
			width: 100,
			height: 28,
			global: { profile: "production", apiUrl: "https://api.example" },
		});
		expect(frame).toContain("Overview");
		expect(frame).toContain("People");
		expect(frame).toContain("Security");
		expect(frame).toContain("Operations");
		expect(frame).toContain("7");
		expect(frame).toContain("↑/↓ select • Enter open • ? help");
		expect(frame).not.toMatch(/Target:|credential|https:\/\/api\.example|VERIFIED|POLLING/u);
		expect(frame).not.toMatch(/Exact CLI command|Last good result|clearance overview/u);
	});

	it("shows only exceptional refresh state in normal browsing", () => {
		const state = initialTuiState();
		expect(renderTui(state, actionsFor("Overview"), { color: false })).not.toMatch(/POLLING|Refreshing|Offline/u);
		state.refresh = { ...state.refresh, status: "refreshing", lastAttemptAt: 10 };
		expect(renderTui(state, actionsFor("Overview"), { color: false })).toContain("Refreshing…");
		state.refresh = { ...state.refresh, status: "offline", staleSince: 10 };
		const frame = renderTui(state, actionsFor("Overview"), { color: false });
		expect(frame).toContain("Offline • showing saved data • retrying in 15s");
		expect(frame).not.toMatch(/LIVE|CONNECTED|RECONNECTING/u);
	});

	it("renders an exact mutation preview before dispatch", () => {
		const state = initialTuiState();
		state.mode = "preview";
		state.areaIndex = 1;
		state.formValues = { __action: "users-delete", id: "usr_123" };
		state.confirmationInput = "users-";
		const frame = renderTui(state, actionsFor("People"), { color: false });
		expect(frame).toContain("Destructive action");
		expect(frame).toContain("clearance --yes users delete usr_123");
		expect(frame).toContain("No request has been sent");
		expect(frame).toContain("Type users-delete");
	});

	it("discloses target and CLI details only through help", () => {
		const state = initialTuiState();
		state.identity = {
			verified: true,
			verifiedAt: 1,
			apiUrl: "https://verified.example.com",
			credentialSource: "saved",
			profile: "production",
			projectId: "proj_live",
			environmentId: "env_live",
			operatorId: "op_1",
			operatorType: "operator",
		};
		const browse = renderTui(state, actionsFor("Overview"), { color: false, width: 120 });
		expect(browse).not.toMatch(/production|verified\.example|proj_live|env_live|clearance overview/u);
		state.mode = "help";
		const help = renderTui(state, actionsFor("Overview"), { color: false, width: 120 });
		expect(help).toContain("Connection");
		expect(help).toContain("Profile       production");
		expect(help).toContain("Endpoint      https://verified.example.com");
		expect(help).toContain("Environment   env_live");
		expect(help).toContain("Project       proj_live");
		expect(help).toContain("clearance overview");
		expect(help).not.toContain("credential environment token");
	});

	it("keeps verified target safety in mutation preview", () => {
		const state = initialTuiState();
		state.identity = {
			verified: true,
			verifiedAt: 1,
			apiUrl: "https://verified.example.com",
			credentialSource: "saved",
			profile: "production",
			projectId: "proj_live",
			environmentId: "env_live",
			operatorId: "op_1",
			operatorType: "operator",
		};
		state.mode = "preview";
		state.areaIndex = 1;
		state.formValues = { __action: "users-delete", id: "usr_123" };
		const frame = renderTui(state, actionsFor("People"), { color: false, width: 120 });
		expect(frame).toContain("Verified target: profile production");
		expect(frame).toContain("project proj_live • environment env_live");
	});

	it("supports narrow terminals and result scrolling", () => {
		const state = initialTuiState();
		state.resultOffset = 10;
		state.snapshots.overview = { data: Array.from({ length: 30 }, (_, index) => `row-${index}`) };
		const frame = renderTui(state, actionsFor("Overview"), { color: false, width: 40, height: 16 });
		expect(frame.split("\n")).toHaveLength(16);
		expect(frame.split("\n").every((line) => line.length <= 40)).toBe(true);
		expect(frame).toMatch(/row-(8|9|10)/);
	});

	it("sanitizes server-controlled text and aligns wide Unicode by terminal cell", () => {
		const state = initialTuiState();
		state.snapshots.overview = { data: { name: "東京", message: "unsafe\u001b[31mred\u001b[0m" } };
		const frame = renderTui(state, actionsFor("Overview"), { color: false, width: 60, height: 20 });
		expect(frame).toContain("東京");
		expect(frame).not.toContain("\u001b");
		expect(frame.split("\n").every((line) => line.length <= 60)).toBe(true);
	});
});
