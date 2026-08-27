import { describe, expect, it } from "vitest";
import {
	HumanHelpTopicError,
	findHumanHelpTopic,
	listHumanHelpTopics,
	renderHumanHelp,
} from "./human-help.js";

describe("curated human help", () => {
	it("provides the dedicated operator topics", () => {
		const ids = listHumanHelpTopics().map((topic) => topic.id);
		expect(ids).toEqual(expect.arrayContaining(["getting-started", "profiles", "output", "environment", "safety", "exit-codes", "tui", "completion"]));
		expect(renderHumanHelp()).toContain("Getting started");
	});

	it("looks up a topic and wraps it through a width callback", () => {
		expect(findHumanHelpTopic("profiles").title).toBe("Profiles");
		const rendered = renderHumanHelp("getting-started", () => 40);
		expect(rendered).toContain("Examples:");
		expect(rendered.split("\n").every((line) => line.length <= 40)).toBe(true);
		expect(renderHumanHelp(undefined, 40).split("\n").every((line) => line.length <= 40)).toBe(true);
	});

	it("returns a safe, typed error for unknown topics", () => {
		expect(() => findHumanHelpTopic("<bad\ninput>")).toThrow(HumanHelpTopicError);
		try { findHumanHelpTopic("<bad\ninput>"); } catch (error) {
			expect(error).toMatchObject({ code: "CLI_HELP_TOPIC_NOT_FOUND", message: "Unknown help topic: badinput" });
		}
	});

	it("documents distinct authentication and permission exit codes", () => {
		const rendered = renderHumanHelp("exit-codes");
		expect(rendered).toContain("77 authentication");
		expect(rendered).toContain("78 permission");
		expect(rendered).not.toContain("authentication or permission");
	});
});
