import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { readMaskedSecret, runFirstRunExperience, runGuidedInteraction } from "./interactive.js";

function terminal(): PassThrough & { isTTY: boolean } {
	const stream = new PassThrough() as PassThrough & { isTTY: boolean };
	stream.isTTY = true;
	return stream;
}

describe("guided interaction", () => {
	it("writes prompts and the selected command only to stderr", async () => {
		const input = terminal();
		const output = terminal();
		const error = terminal();
		let stderr = "";
		let stdout = "";
		error.on("data", (chunk) => { stderr += String(chunk); });
		output.on("data", (chunk) => { stdout += String(chunk); });
		const resultPromise = runGuidedInteraction({ io: { input, output, error }, env: {} });
		// Feed each response after the preceding readline interface has closed.
		await new Promise((resolve) => setImmediate(resolve));
		input.write("3\n");
		await new Promise((resolve) => setImmediate(resolve));
		input.write("my'app\n");
		await new Promise((resolve) => setImmediate(resolve));
		input.end("staging\n");

		const result = await resultPromise;
		expect(result).toEqual({
			status: "completed",
			command: "clearance init --name 'my'\"'\"'app' --environment 'staging'",
		});
		expect(stderr).toContain("clearance init --name 'my'\"'\"'app' --environment 'staging'");
		expect(stdout).toBe("");
	});

	it("permits cancelling the flow", async () => {
		const input = terminal();
		input.end("q\n");
		expect(await runGuidedInteraction({ io: { input, output: terminal(), error: terminal() }, env: {} }))
			.toEqual({ status: "cancelled" });
	});
});

async function feedAnswers(input: PassThrough, answers: readonly string[]): Promise<void> {
	for (const answer of answers) {
		await new Promise((resolve) => setImmediate(resolve));
		input.write(`${answer}\n`);
	}
}

describe("first-run experience", () => {
	it("resumes a verified saved profile without repeating setup", async () => {
		const input = terminal();
		const error = terminal();
		let rendered = "";
		error.on("data", (chunk) => { rendered += String(chunk); });
		const calls: string[] = [];
		const result = await runFirstRunExperience({
			io: { input, output: terminal(), error },
			env: {},
			callbacks: {
				resumeProfile: async () => ({
					apiUrl: "https://auth.example.com",
					profile: "production",
					verification: { summary: "operator project/env at https://auth.example.com" },
				}),
				verifyConnection: async () => { calls.push("verify"); throw new Error("unexpected setup"); },
				saveProfile: async () => { calls.push("save"); },
				previewFirstOperation: async ({ profile }) => ({
					summary: "List users",
					command: `clearance --profile ${profile} users list`,
				}),
			},
		});

		expect(result).toMatchObject({
			status: "completed",
			profile: "production",
			firstOperation: "previewed",
		});
		expect(calls).toEqual([]);
		expect(rendered).toContain("Connected profile: production");
		expect(rendered).toContain("clearance --profile production users list");
		expect(rendered).not.toContain("Operator token");
		expect(rendered).not.toContain("Welcome to Clearance");
	});

	it("verifies before saving, installs optional tooling, and runs a first operation", async () => {
		const input = terminal();
		const output = terminal();
		const error = terminal();
		let stderr = "";
		let stdout = "";
		error.on("data", (chunk) => { stderr += String(chunk); });
		output.on("data", (chunk) => { stdout += String(chunk); });
		const calls: string[] = [];
		const secret = "operator-secret-never-rendered";
		const resultPromise = runFirstRunExperience({
			io: { input, output, error },
			env: {},
			shell: "/bin/zsh",
			readSecret: async () => secret,
			callbacks: {
				verifyConnection: async (connection) => {
					calls.push(`verify:${connection.token}`);
					return { summary: "operator\u001b[31m verified", projectId: "project-1" };
				},
				saveProfile: async (connection) => { calls.push(`save:${connection.profile}`); },
				installCompletion: async (shell) => {
					calls.push(`completion:${shell}`);
					return { summary: "Completion installed." };
				},
				installSkill: async () => {
					calls.push("skill");
					return { summary: "Skill installed." };
				},
				previewFirstOperation: async ({ profile }) => {
					calls.push("preview");
					return { summary: "List users", command: `clearance --profile '${profile}' users list` };
				},
				runFirstOperation: async () => {
					calls.push("run");
					return { summary: "Connection ready." };
				},
			},
		});
		void feedAnswers(input, ["", "", "", "n", ""]);

		const result = await resultPromise;
		expect(result).toMatchObject({
			status: "completed",
			profile: "default",
			apiUrl: "http://localhost:13200",
			completion: "installed",
			skill: "skipped",
			firstOperation: "executed",
		});
		expect(calls).toEqual([
			`verify:${secret}`,
			"save:default",
			"completion:zsh",
			"preview",
			"run",
		]);
		expect(stderr).toContain("Connected: operator verified");
		expect(stderr).not.toContain("\u001b[31m");
		expect(stderr).not.toContain("\u202e");
		expect(stderr).not.toContain(secret);
		expect(stdout).toBe("");
	});

	it("does not save a profile when verification fails", async () => {
		const input = terminal();
		const error = terminal();
		let saved = false;
		const resultPromise = runFirstRunExperience({
			io: { input, output: terminal(), error },
			env: {},
			readSecret: async () => "operator-secret-never-rendered",
			callbacks: {
				verifyConnection: async () => { throw new Error("rejected"); },
				saveProfile: async () => { saved = true; },
				previewFirstOperation: async () => ({ summary: "List users", command: "clearance users list" }),
			},
		});
		void feedAnswers(input, ["", ""]);

		await expect(resultPromise).rejects.toThrow("rejected");
		expect(saved).toBe(false);
	});

	it("reports optional installer conflicts and continues to the first-operation preview", async () => {
		const input = terminal();
		const resultPromise = runFirstRunExperience({
			io: { input, output: terminal(), error: terminal() },
			env: {},
			shell: "zsh",
			readSecret: async () => "operator-secret-never-rendered",
			callbacks: {
				verifyConnection: async () => ({ summary: "verified" }),
				saveProfile: async () => undefined,
				installCompletion: async () => ({ summary: "Completion conflict.", state: "conflict" }),
				previewFirstOperation: async () => ({ summary: "List users", command: "clearance users list" }),
			},
		});
		void feedAnswers(input, ["", "", ""]);

		await expect(resultPromise).resolves.toMatchObject({
			status: "completed",
			completion: "conflict",
			firstOperation: "previewed",
		});
	});

	it("reads a terminal secret without echoing it", async () => {
		const input = terminal();
		const error = terminal();
		let rendered = "";
		error.on("data", (chunk) => { rendered += String(chunk); });
		const secretPromise = readMaskedSecret("Token:", { input, output: terminal(), error });
		await new Promise((resolve) => setImmediate(resolve));
		input.end("secret-value\n");

		expect(await secretPromise).toBe("secret-value");
		expect(rendered).toContain("Token:");
		expect(rendered).not.toContain("secret-value");
	});
});
