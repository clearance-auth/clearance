import { describe, expect, it, vi } from "vitest";
import {
	awaitShutdown,
	type ObservabilityHandle,
} from "../src/bootstrap";
import {
	installObservabilityShutdownHandlers,
	type ObservabilityShutdownTarget,
} from "../src/shutdown-signals";

describe("observability shutdown", () => {
	it("distinguishes complete, failed, and timed-out shutdown", async () => {
		await expect(awaitShutdown(async () => {}, 100)).resolves.toBeUndefined();
		await expect(
			awaitShutdown(async () => {
				throw new Error("private failure");
			}, 100),
		).rejects.toMatchObject({
			name: "ObservabilityShutdownError",
			reason: "failed",
		});
		await expect(
			awaitShutdown(() => new Promise(() => {}), 5),
		).rejects.toMatchObject({
			name: "ObservabilityShutdownError",
			reason: "timed-out",
		});
	});

	it("flushes once and restores the first signal's normal termination path", async () => {
		const listeners = new Map<string, () => void>();
		const terminated: string[] = [];
		const status: ObservabilityHandle["status"] = {
			state: "configured",
			serviceName: "clearance-api",
			instrumentations: { http: true, pg: true },
		};
		let completeShutdown: (() => void) | undefined;
		const shutdown = vi.fn(
			() => new Promise<ObservabilityHandle["status"]>((resolve) => {
				completeShutdown = () => resolve(status);
			}),
		);
		const target: ObservabilityShutdownTarget = {
			once: (event, listener) => {
				listeners.set(event, listener);
			},
			removeListener: (event, listener) => {
				if (listeners.get(event) === listener) listeners.delete(event);
			},
			terminate: (signal) => {
				terminated.push(signal);
			},
		};
		installObservabilityShutdownHandlers(
			{
				status,
				shutdown,
			},
			target,
		);

		expect(listeners.has("beforeExit")).toBe(true);
		listeners.get("beforeExit")?.();
		listeners.get("SIGTERM")?.();
		listeners.get("SIGINT")?.();
		expect(shutdown).toHaveBeenCalledTimes(1);
		completeShutdown?.();
		await Promise.resolve();
		await Promise.resolve();

		expect(terminated).toEqual(["SIGTERM"]);
		expect(listeners.size).toBe(0);
	});
});
