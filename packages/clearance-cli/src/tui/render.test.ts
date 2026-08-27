import { describe, expect, it } from "vitest";
import { actionsFor } from "./catalog.js";
import { initialTuiState } from "./model.js";
import { renderTui } from "./render.js";

describe("renderTui", () => {
	it("shows navigation, exact CLI mapping, and last-good state", () => {
		const state = initialTuiState();
		state.snapshots.overview = { data: { users: 7 } };
		const frame = renderTui(state, actionsFor("Overview"), { color: false, width: 100, height: 28 });
		expect(frame).toContain("Users & organizations");
		expect(frame).toContain("clearance overview");
		expect(frame).toContain('"users": 7');
	});

	it("renders an exact mutation preview before dispatch", () => {
		const state = initialTuiState();
		state.mode = "preview";
		state.areaIndex = 1;
		state.formValues = { __action: "users-delete", id: "usr_123" };
		state.confirmationInput = "users-";
		const frame = renderTui(state, actionsFor("Users & organizations"), { color: false });
		expect(frame).toContain("Destructive action");
		expect(frame).toContain("clearance --yes users delete usr_123");
		expect(frame).toContain("No request has been sent");
		expect(frame).toContain("Type users-delete");
	});

	it("identifies and renders the active target context in every command", () => {
		const state = initialTuiState();
		const frame = renderTui(state, actionsFor("Overview"), {
			color: false,
			width: 100,
			height: 28,
			global: { profile: "production", apiUrl: "https://api.example" },
		});
		expect(frame).toContain("Target: profile production • API https://api.example");
		expect(frame).toContain("clearance --profile production --api-url");
		expect(frame).toContain("https://api.example overview");
	});

	it("supports narrow terminals and result scrolling", () => {
		const state = initialTuiState();
		state.resultOffset = 10;
		state.snapshots.overview = { data: Array.from({ length: 30 }, (_, index) => `row-${index}`) };
		const frame = renderTui(state, actionsFor("Overview"), { color: false, width: 40, height: 16 });
		expect(frame.split("\n").every((line) => line.length <= 40)).toBe(true);
		expect(frame).toContain("row-9");
	});
});
