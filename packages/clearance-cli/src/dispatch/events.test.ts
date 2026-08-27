import { afterEach, describe, expect, it, vi } from "vitest";
import { callManagementOperation } from "../api-client.js";
import {
	dispatchEventCommand,
	isEventStreamResult,
	isStreamingEventCommandPath,
} from "./events.js";
import type { ApiSession } from "../api-client.js";

vi.mock("../api-client.js", () => ({
	callManagementOperation: vi.fn(),
}));

const session: ApiSession = {
	apiUrl: "https://api.clearance.test",
	token: "operator-token",
	profile: "test",
	credentialSource: "saved",
};

const event = {
	id: "evt_1",
	createdAt: "2026-08-27T10:00:00.000Z",
	action: "user.created",
	actor: "operator_1",
	outcome: "succeeded",
};

afterEach(() => {
	vi.restoreAllMocks();
	vi.mocked(callManagementOperation).mockReset();
});

describe("events tail stream", () => {
	it("sanitizes every untrusted field in human output and returns tagged completion", async () => {
		vi.mocked(callManagementOperation).mockResolvedValueOnce({
			events: [{
				...event,
				id: "evt\n_1",
				action: "user.\u001b[31mcreated",
				actor: "operator\rspoofed",
				outcome: "succeeded\u202efailed",
			}],
			nextCursor: null,
			scope: {},
		} as never);
		const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

		const result = await dispatchEventCommand({
			session,
			path: "events tail",
			args: [],
			opts: { once: true },
			global: { output: "human" },
		});

		expect(stdout).toHaveBeenCalledOnce();
		expect(stdout).toHaveBeenCalledWith(
			"2026-08-27T10:00:00.000Z user.created actor=operatorspoofed outcome=succeededfailed id=evt_1\n",
		);
		expect(isEventStreamResult(result)).toBe(true);
		expect(result).toEqual({ eventStreamResult: true, stream: "events.tail", emitted: 1, stopped: "once" });
	});

	it("emits one compact versioned JSONL envelope per event for explicit machine output", async () => {
		vi.mocked(callManagementOperation).mockResolvedValueOnce({ events: [event], nextCursor: null, scope: {} } as never);
		const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

		await dispatchEventCommand({
			session,
			path: "events tail",
			args: [],
			opts: { once: true },
			global: { output: "json" },
		});

		expect(stdout).toHaveBeenCalledOnce();
		const line = String(stdout.mock.calls[0]?.[0]);
		expect(line.endsWith("\n")).toBe(true);
		expect(line.slice(0, -1)).not.toContain("\n");
		expect(JSON.parse(line)).toMatchObject({
			protocol: "clearance.cli.output",
			protocolVersion: 1,
			ok: true,
			data: event,
			meta: { stream: "events.tail" },
		});
	});

	it("keeps deprecated --json as one raw event per JSONL record", async () => {
		vi.mocked(callManagementOperation).mockResolvedValueOnce({ events: [event], nextCursor: null, scope: {} } as never);
		const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

		await dispatchEventCommand({
			session,
			path: "events tail",
			args: [],
			opts: { once: true },
			global: { json: true },
		});

		expect(JSON.parse(String(stdout.mock.calls[0]?.[0]))).toEqual(event);
	});

	it("passes cancellation to polling and completes cleanly while waiting", async () => {
		vi.mocked(callManagementOperation).mockResolvedValueOnce({ events: [], nextCursor: null, scope: {} } as never);
		const controller = new AbortController();
		const running = dispatchEventCommand({
			session,
			path: "events tail",
			args: [],
			opts: { pollInterval: 60_000 },
			global: { signal: controller.signal, quiet: true },
		});
		await vi.waitFor(() => expect(callManagementOperation).toHaveBeenCalledOnce());
		expect(vi.mocked(callManagementOperation).mock.calls[0]?.[3]).toMatchObject({ signal: controller.signal });

		controller.abort(new Error("TUI request cancelled"));

		await expect(running).resolves.toEqual({
			eventStreamResult: true,
			stream: "events.tail",
			emitted: 0,
			stopped: "cancelled",
		});
	});

	it("treats cancellation of an in-flight poll as clean stream completion", async () => {
		vi.mocked(callManagementOperation).mockImplementationOnce((_session, _id, _input, options) =>
			new Promise((_resolve, reject) => {
				options.signal?.addEventListener("abort", () => reject(options.signal?.reason), { once: true });
			}) as never,
		);
		const controller = new AbortController();
		const running = dispatchEventCommand({
			session,
			path: "events tail",
			args: [],
			opts: { once: true },
			global: { signal: controller.signal, quiet: true },
		});
		await vi.waitFor(() => expect(callManagementOperation).toHaveBeenCalledOnce());

		controller.abort(new Error("request cancelled"));

		await expect(running).resolves.toMatchObject({
			eventStreamResult: true,
			emitted: 0,
			stopped: "cancelled",
		});
	});

	it("classifies the streaming path for hosts that own stdout", () => {
		expect(isStreamingEventCommandPath("events tail")).toBe(true);
		expect(isStreamingEventCommandPath("events list")).toBe(false);
	});
});
