import { afterEach, describe, expect, it, vi } from "vitest";
import { ClearanceError } from "@clearance/management";
import {
	CLI_EXIT_CODE,
	CliExitError,
	errorEnvelope,
	exitCodeForClearanceError,
	fail,
	printResult,
	renderHumanData,
	selectOutputFormat,
	successEnvelope,
} from "./output.js";

afterEach(() => vi.restoreAllMocks());

describe("output protocol", () => {
	it("builds a stable success envelope without collapsing empty arrays", () => {
		expect(successEnvelope({ users: [] }, { summary: "No users", next: ["Create one"] })).toEqual({
			protocol: "clearance.cli.output",
			protocolVersion: 1,
			ok: true,
			data: { users: [] },
			summary: "No users",
			notice: null,
			next: ["Create one"],
			actions: [{
				action: "follow-up",
				command: null,
				description: "Create one",
				mutation: null,
				confirmationRequired: null,
			}],
			meta: {},
		});
	});

	it("writes one compact envelope to stdout for jsonl", () => {
		const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		printResult({ format: "jsonl" }, [], "Nothing found");

		expect(stdout).toHaveBeenCalledOnce();
		expect(stdout).toHaveBeenCalledWith(
			'{"protocol":"clearance.cli.output","protocolVersion":1,"ok":true,"data":[],"summary":"Nothing found","notice":null,"next":[],"actions":[],"meta":{}}\n',
		);
		expect(stderr).not.toHaveBeenCalled();
	});

	it("keeps legacy json selection and suppresses successful quiet output", () => {
		const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		expect(selectOutputFormat({ json: true })).toBe("json");
		printResult({ json: true }, { changed: true });
		expect(stdout).toHaveBeenLastCalledWith('{\n  "changed": true\n}\n');
		printResult({ quiet: true }, { changed: true });
		expect(stdout).toHaveBeenCalledOnce();
	});

	it("gives explicit output controls priority over piped-stdout inference", () => {
		expect(selectOutputFormat({ inferredFormat: "json", quiet: true })).toBe("quiet");
		expect(selectOutputFormat({ inferredFormat: "json", jsonl: true })).toBe("jsonl");
		expect(selectOutputFormat({ inferredFormat: "json", jq: ".data" })).toBe("json");
		expect(selectOutputFormat({ inferredFormat: "json", output: "human" })).toBe("human");
	});

	it("routes human errors to stderr with a typed exit status", () => {
		const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		const error = new ClearanceError({
			code: "CLI_LOGIN_REQUIRED",
			message: "Login required.",
			stage: "cli.auth",
			status: 401,
			remediation: "Run clearance login.",
		});

		expect(() => fail(error, {})).toThrowError(
			expect.objectContaining({ exitCode: CLI_EXIT_CODE.authentication }),
		);
		expect(stderr).toHaveBeenCalledWith(
			"Error [CLI_LOGIN_REQUIRED] stage=cli.auth: Login required.\nRemediation: Run clearance login.\n",
		);
		expect(stdout).not.toHaveBeenCalled();
	});

	it("routes structured machine errors to stdout only", () => {
		const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

		try {
			fail(new Error("boom"), { format: "jsonl" });
		} catch (error) {
			expect(error).toBeInstanceOf(CliExitError);
			expect((error as CliExitError).exitCode).toBe(CLI_EXIT_CODE.internal);
		}
		expect(JSON.parse(String(stdout.mock.calls[0]?.[0]))).toEqual(errorEnvelope(new Error("boom")));
		expect(stderr).not.toHaveBeenCalled();
	});

	it("preserves execution receipt metadata on machine failures", () => {
		const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		const receipt = { receiptId: "receipt_1", outcome: "indeterminate", commitState: "unknown" };
		try {
			fail(new Error("transport failed"), { format: "json" }, { receipt });
		} catch (error) {
			expect(error).toBeInstanceOf(CliExitError);
		}
		expect(JSON.parse(String(stdout.mock.calls[0]?.[0]))).toMatchObject({
			ok: false,
			meta: { receipt },
		});
	});

	it("turns error remediation into a structured next action", () => {
		const envelope = errorEnvelope(new ClearanceError({
			code: "CLI_LOGIN_REQUIRED",
			message: "Login required.",
			stage: "cli.auth",
			status: 401,
			remediation: "clearance login --profile production",
		}));
		expect(envelope.actions).toEqual([{
			action: "run-command",
			command: "clearance login --profile production",
			description: null,
			mutation: null,
			confirmationRequired: null,
		}]);
	});

	it("does not emit again while an existing CLI exit unwinds", () => {
		const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		const exiting = new CliExitError(CLI_EXIT_CODE.checkFailed);

		expect(() => fail(exiting, { format: "json" })).toThrow(exiting);
		expect(stdout).not.toHaveBeenCalled();
		expect(stderr).not.toHaveBeenCalled();
	});

	it("renders empty collections explicitly for humans", () => {
		expect(renderHumanData({ users: [], settings: {} })).toBe("Users:\n  []\nSettings:\n  {}");
	});

	it("distinguishes missing resources and conflicts from invalid input", () => {
		expect(exitCodeForClearanceError({ status: 404, retryable: false })).toBe(CLI_EXIT_CODE.notFound);
		expect(exitCodeForClearanceError({ status: 409, retryable: false })).toBe(CLI_EXIT_CODE.conflict);
	});

	it("uses distinct authentication and permission exit codes", () => {
		expect(exitCodeForClearanceError({ status: 401, retryable: false })).toBe(CLI_EXIT_CODE.authentication);
		expect(exitCodeForClearanceError({ status: 403, retryable: false })).toBe(CLI_EXIT_CODE.permission);
		expect(CLI_EXIT_CODE.authentication).not.toBe(CLI_EXIT_CODE.permission);
	});
});
