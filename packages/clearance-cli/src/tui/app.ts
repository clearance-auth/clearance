import type { ApiSession } from "../api-client.js";
import type { GlobalOpts } from "../output.js";
import { dispatchRemoteCommand } from "../remote-dispatch.js";
import { TuiController } from "./model.js";
import { renderTui } from "./render.js";
import type { TuiIO, WorkflowExecutor } from "./types.js";

export function createRemoteWorkflowExecutor(
	session: ApiSession,
	global: Readonly<GlobalOpts> = {},
): WorkflowExecutor {
	const executor: WorkflowExecutor = async (invocation, context) => {
		if (context.signal.aborted) throw context.signal.reason;
		const result = await dispatchRemoteCommand({
			session,
			path: invocation.path,
			args: invocation.args,
			opts: invocation.opts,
			global: invocation.global,
		});
		if (context.signal.aborted) throw context.signal.reason;
		return result;
	};
	Object.defineProperty(executor, "global", { value: Object.freeze({ ...global }), enumerable: true });
	return executor;
}

export function decodeInput(data: Buffer | string): string[] {
	const value = typeof data === "string" ? data : data.toString("utf8");
	const keys: string[] = [];
	for (let index = 0; index < value.length;) {
		const arrow = value.slice(index).match(/^\u001b\[[ABCD]/)?.[0];
		if (arrow) {
			keys.push(arrow);
			index += arrow.length;
			continue;
		}
		keys.push(value[index]);
		index += 1;
	}
	return keys;
}

export async function runTerminalUi(options: {
	readonly executor: WorkflowExecutor;
	readonly io?: TuiIO;
	readonly title?: string;
}): Promise<void> {
	const io: TuiIO = options.io ?? { input: process.stdin, output: process.stdout };
	if (!io.input.isTTY || !io.output.isTTY || !io.input.setRawMode) {
		throw new Error("Clearance workflows require an interactive TTY. Use the displayed CLI commands in automation.");
	}

	let finished = false;
	let resolveFinished: () => void = () => {};
	const done = new Promise<void>((resolve) => { resolveFinished = resolve; });
	let controller: TuiController;
	const draw = () => {
		if (finished) return;
		const frame = renderTui(controller.state, controller.visibleActions, {
			width: io.output.columns,
			height: io.output.rows,
			title: options.title,
			global: options.executor.global,
			color: true,
		});
		io.output.write(`\u001b[H\u001b[2J${frame}`);
		if (controller.state.quit) cleanup();
	};
	controller = new TuiController(options.executor, draw);

	const onData = (data: Buffer | string) => {
		for (const key of decodeInput(data)) {
			controller.handleKey(key);
			if (controller.state.quit) break;
		}
	};
	const cleanup = () => {
		if (finished) return;
		finished = true;
		io.input.off("data", onData);
		io.output.off?.("resize", draw);
		io.input.setRawMode?.(false);
		io.input.pause();
		io.output.write("\u001b[?25h\u001b[0m\u001b[?1049l");
		resolveFinished();
	};

	io.output.write("\u001b[?1049h\u001b[?25l");
	io.input.setRawMode(true);
	io.input.resume();
	io.input.on("data", onData);
	io.output.on?.("resize", draw);
	draw();
	await done;
}
