#!/usr/bin/env node
import { parseWorkerConfig, type WorkerMode } from "./config.js";
import { createJsonLogger } from "./logger.js";
import { DeliveryWorker } from "./worker.js";

let activeWorker: DeliveryWorker | undefined;

function parseArgs(argv: string[]): { mode: WorkerMode; limit?: number } {
	let mode: WorkerMode = "run";
	let limit: number | undefined;
	for (let index = 0; index < argv.length; index++) {
		const arg = argv[index];
		if (arg === "--ready") mode = "ready";
		else if (arg === "--once") mode = "once";
		else if (arg === "--limit") {
			const raw = argv[++index];
			if (!raw || !/^[0-9]+$/.test(raw)) throw new Error("--limit requires a positive integer");
			limit = Number(raw);
		} else throw new Error(`Unknown argument: ${arg}`);
	}
	if (limit !== undefined && mode !== "once") throw new Error("--limit requires --once");
	return { mode, limit };
}

async function main(): Promise<void> {
	const args = parseArgs(process.argv.slice(2));
	const config = parseWorkerConfig(process.env, args.mode);
	const logger = createJsonLogger();
	const worker = new DeliveryWorker(config, { logger });
	activeWorker = worker;
	let stopping = false;
	const stop = () => {
		if (stopping) return;
		stopping = true;
		void worker.stop().then(() => { process.exitCode = 0; }, () => { process.exitCode = 1; });
	};
	process.once("SIGTERM", stop);
	process.once("SIGINT", stop);
	if (args.mode === "run") { await worker.run(); return; }
	await worker.initialize();
	if (args.mode === "ready") {
		const state = await worker.readiness();
		process.stdout.write(`${JSON.stringify(state)}\n`);
		process.exitCode = state.ready ? 0 : 1;
	} else {
		const processed = await worker.processOnce(args.limit);
		process.stdout.write(`${JSON.stringify({ processed })}\n`);
	}
	await worker.stop();
}

main().catch(async (error) => {
	const code = error && typeof error === "object" && "code" in error && /^[A-Z0-9_]{1,64}$/.test(String(error.code))
		? String(error.code)
		: "WORKER_FATAL";
	process.stderr.write(`${JSON.stringify({ level: "error", event: "worker.fatal", errorClass: code })}\n`);
	await activeWorker?.stop().catch(() => undefined);
	process.exitCode = 1;
});
