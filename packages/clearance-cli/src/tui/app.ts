import { homedir } from "node:os";
import { join } from "node:path";
import type { ApiSession } from "../api-client.js";
import type { GlobalOpts } from "../output.js";
import type { ExperienceManifest } from "../experience-manifest.js";
import { fetchWhoami, normalizeApiUrl } from "../operator-auth.js";
import { OperationRunner } from "../operation-runner.js";
import type { ExecutionReceiptStore } from "../execution-receipt.js";
import { dispatchRemoteCommand } from "../remote-dispatch.js";
import { isStreamingEventCommandPath } from "../dispatch/events.js";
import { sanitizeTerminalText } from "../terminal-sanitize.js";
import { ClearanceError, MANAGEMENT_OPERATIONS } from "@clearance/management";
import { TerminalInputDecoder, decodeInput } from "./input.js";
import { TuiController } from "./model.js";
import { renderTui } from "./render.js";
import { FileOperationReceiptJournal } from "./safety.js";
import { attachTerminalSignals, TerminalSession } from "./terminal-session.js";
import { WORKFLOW_ACTIONS } from "./catalog.js";
import type { TuiDeepLinkTarget } from "./deep-link.js";
import { createFilePreferenceStore, createMemoryPreferenceStore, DEFAULT_TUI_PREFERENCES, type TuiPreferenceStore } from "./preferences.js";
import { createWorkspaceAdapters, tuiOperationSafety, tuiSafeManifestOperations, workflowActionsFromManifest } from "./workspace.js";
import type {
	OperationReceiptJournal,
	RevealedSecret,
	TuiIO,
	TuiProcessSignals,
	VerifiedStartupIdentity,
	WorkflowExecutor,
} from "./types.js";

export { decodeInput } from "./input.js";

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
	if (signal.aborted) return Promise.reject(signal.reason);
	return new Promise<T>((resolve, reject) => {
		const aborted = () => reject(signal.reason);
		signal.addEventListener("abort", aborted, { once: true });
		promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", aborted));
	});
}

export function createRemoteWorkflowExecutor(
	session: ApiSession,
	global: Readonly<GlobalOpts> = {},
	options: {
		readonly receiptCoordinator?: OperationReceiptJournal & ExecutionReceiptStore;
	} = {},
): WorkflowExecutor {
	const receiptCoordinator = options.receiptCoordinator ?? new FileOperationReceiptJournal();
	const executor: WorkflowExecutor = async (invocation, context) => {
		if (context.signal.aborted) throw context.signal.reason;
		if (isStreamingEventCommandPath(invocation.path)) {
			throw new Error(`${invocation.path} is a streaming command. Run its displayed CLI command outside the TUI.`);
		}
		const operation = MANAGEMENT_OPERATIONS.find((candidate) => candidate.cliPath === invocation.path);
		if (!operation) throw new Error(`No canonical operation exists for ${invocation.path}.`);
		const safety = tuiOperationSafety({
			path: operation.cliPath,
			mutation: operation.mutation,
			confirmation: operation.confirmation,
			supportsDryRun: operation.supportsDryRun,
		});
		if (!safety.safe) {
			const kind = safety.reason === "artifact" ? "an artifact-writing" : "a streaming";
			throw new Error(`${invocation.path} is ${kind} command. Run its displayed CLI command outside the TUI.`);
		}
		if (context.lifecycle && (
			context.lifecycle.operationId !== operation.id ||
			context.lifecycle.path !== operation.cliPath
		)) {
			throw new Error(`TUI lifecycle identity does not match ${operation.cliPath}.`);
		}
		let firstTimestamp = true;
		const runner = new OperationRunner({
			receiptStore: receiptCoordinator,
			...(context.lifecycle ? {
				createReceiptId: () => context.lifecycle!.receiptId,
				now: () => {
					if (!firstTimestamp) return new Date();
					firstTimestamp = false;
					return new Date(context.lifecycle!.startedAt);
				},
			} : {}),
		});
		return runner.run({
			operation: {
				id: operation.id,
				path: operation.cliPath,
				mutation: operation.mutation,
				confirmation: operation.confirmation,
			},
			command: invocation.command,
			target: context.lifecycle?.target ?? {
				principal: session.credentialSource === "saved" ? session.profile : "environment",
				apiOrigin: session.apiUrl,
			},
			dryRun: invocation.global.dryRun,
			confirmed: invocation.global.yes,
			signal: context.signal,
			execute: async ({ signal, markDispatched }) => {
				if (invocation.global.dryRun && !operation.supportsDryRun) {
					throw new ClearanceError({
						code: "CLI_REMOTE_DRY_RUN_UNSUPPORTED",
						message: `${operation.cliPath} does not expose a server-side dry-run contract.`,
						stage: "cli.dispatch",
						status: 400,
						remediation: "Leave the TUI dry-run session and review the exact command before running this operation live.",
					});
				}
				const priorObserver = session.operationObserver;
				const dispatchSession: ApiSession = {
					...session,
					operationObserver: {
						onDispatch() {
							priorObserver?.onDispatch();
							const dispatchedAt = new Date().toISOString();
							markDispatched({ dispatchedAt });
							context.updateReceiptMetadata?.({ dispatchedAt });
						},
						onMetadata(metadata) {
							priorObserver?.onMetadata(metadata);
							markDispatched(metadata);
							context.updateReceiptMetadata?.(metadata);
						},
					},
				};
				const data = await dispatchRemoteCommand({
					session: dispatchSession,
					path: invocation.path,
					args: invocation.args,
					opts: invocation.opts,
					global: { ...invocation.global, signal },
				});
				return { data };
			},
		});
	};
	const verifyIdentity = async (signal: AbortSignal): Promise<VerifiedStartupIdentity> => {
		const whoami = await abortable(fetchWhoami(session.apiUrl, session.token), signal);
		return {
			verified: true,
			verifiedAt: Date.now(),
			apiUrl: session.apiUrl,
			credentialSource: session.credentialSource,
			profile: session.credentialSource === "saved" ? session.profile : "environment",
			projectId: whoami.projectId,
			environmentId: whoami.environmentId,
			operatorId: whoami.operator.id,
			operatorType: whoami.operator.type,
		};
	};
	Object.defineProperties(executor, {
		global: { value: Object.freeze({ ...global }), enumerable: true },
		verifyIdentity: { value: verifyIdentity, enumerable: true },
		receiptJournal: { value: receiptCoordinator, enumerable: false },
	});
	return executor;
}

export async function runTerminalUi(options: {
	readonly executor: WorkflowExecutor;
	readonly io?: TuiIO;
	readonly signals?: TuiProcessSignals;
	readonly title?: string;
	readonly verifyIdentity?: (signal: AbortSignal) => Promise<VerifiedStartupIdentity>;
	readonly receiptJournal?: OperationReceiptJournal;
	readonly revealSecret?: (secret: RevealedSecret) => void | Promise<void>;
	readonly escapeTimeoutMs?: number;
	readonly manifest?: ExperienceManifest;
	readonly initialTarget?: TuiDeepLinkTarget;
	readonly preferenceStore?: TuiPreferenceStore;
}): Promise<void> {
	const io: TuiIO = options.io ?? { input: process.stdin, output: process.stdout };
	if (!io.input.isTTY || !io.output.isTTY || !io.input.setRawMode) {
		throw new Error("Clearance workflows require an interactive TTY. Use the displayed CLI commands in automation.");
	}
	const verifier = options.verifyIdentity ?? options.executor.verifyIdentity;
	if (!verifier) throw new Error("Clearance workflows require verified startup identity before terminal control is acquired.");
	const identityController = new AbortController();
	const identity = await verifier(identityController.signal);
	if (!identity.verified || !identity.projectId || !identity.environmentId || !identity.apiUrl) {
		throw new Error("Clearance could not verify the target principal and environment.");
	}
	if (options.executor.global?.apiUrl && normalizeApiUrl(options.executor.global.apiUrl, {}) !== normalizeApiUrl(identity.apiUrl, {})) {
		throw new Error("Verified startup identity does not match the selected API origin.");
	}
	if (options.executor.global?.profile && options.executor.global.profile !== identity.profile) {
		throw new Error("Verified startup identity does not match the selected profile.");
	}
	const preferencePath = join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "clearance", "tui.json");
	const preferenceStore = options.preferenceStore ?? (options.io ? createMemoryPreferenceStore() : createFilePreferenceStore(preferencePath));
	let preferences = DEFAULT_TUI_PREFERENCES;
	let preferenceLoadError: unknown;
	try { preferences = await preferenceStore.load(); } catch (cause) { preferenceLoadError = cause; }
	const manifestOperations = tuiSafeManifestOperations(
		(options.manifest?.commands.commands ?? []).filter((operation) => operation.executionClass === "management-api"),
	);
	const adapters = createWorkspaceAdapters(manifestOperations);
	const curatedPaths = new Set(WORKFLOW_ACTIONS.map((action) => action.path));
	const actions = Object.freeze([...WORKFLOW_ACTIONS, ...workflowActionsFromManifest(manifestOperations).filter((action) => !curatedPaths.has(action.path))]);

	let decoder = new TerminalInputDecoder();
	const terminal = new TerminalSession(io);
	const signals = options.signals ?? process;
	let escapeTimer: ReturnType<typeof setTimeout> | undefined;
	let terminatingSignal: "SIGINT" | "SIGTERM" | undefined;
	let revealOverlay: { readonly draw: () => void; readonly acknowledge: () => void } | undefined;
	let finished = false;
	let preferenceSave = Promise.resolve();
	let savedPreferences = JSON.stringify(preferences);
	let rejectFinished: (cause: unknown) => void = () => {};
	let resolveFinished: () => void = () => {};
	const done = new Promise<void>((resolve, reject) => {
		resolveFinished = resolve;
		rejectFinished = reject;
	});
	const finish = (cause?: unknown) => {
		if (finished) return;
		finished = true;
		if (cause === undefined) resolveFinished();
		else rejectFinished(cause);
	};

	let controller: TuiController;
	const draw = () => {
		if (finished) return;
		try {
			const requestedColor = controller.state.preferences.color === "always" ? true : controller.state.preferences.color === "never" ? false : undefined;
			const frame = renderTui(controller.state, controller.visibleActions, {
				width: io.output.columns,
				height: io.output.rows,
				title: options.title,
				global: options.executor.global,
				color: requestedColor,
				theme: controller.state.preferences.theme,
				rawResult: controller.state.preferences.rawJson,
			});
			io.output.write(`\u001b[H\u001b[2J${frame}`);
			if (controller.state.quit && !terminatingSignal) finish();
		} catch (cause) {
			finish(cause);
		}
	};
	const revealOnce = options.revealSecret ?? ((secret: RevealedSecret) => new Promise<void>((resolve) => {
		const path = sanitizeTerminalText(secret.path);
		const value = sanitizeTerminalText(secret.value);
		let acknowledged = false;
		const drawReveal = () => {
			io.output.write(`\u001b[H\u001b[2JOne-time secret\n\n${path}: ${value}\n\nThis value will not be retained. Press any key to hide it.`);
		};
		revealOverlay = {
			draw: drawReveal,
			acknowledge: () => {
				if (acknowledged) return;
				acknowledged = true;
				revealOverlay = undefined;
				io.output.write("\u001b[H\u001b[2J");
				draw();
				resolve();
			},
		};
		drawReveal();
	}));
	const changed = () => {
		draw();
		const serialized = JSON.stringify(controller.state.preferences);
		if (serialized !== savedPreferences) {
			savedPreferences = serialized;
			preferenceSave = preferenceSave.then(() => preferenceStore.save(controller.state.preferences)).catch(() => undefined);
		}
	};
	controller = new TuiController(options.executor, changed, undefined, undefined, {
		identity,
		receiptJournal: options.receiptJournal ?? options.executor.receiptJournal ?? new FileOperationReceiptJournal(),
		revealSecret: revealOnce,
		actions,
		adapters,
		preferences,
		initialTarget: options.initialTarget,
	});
	if (preferenceLoadError) controller.state.notice = `Preferences could not be loaded: ${sanitizeTerminalText(preferenceLoadError instanceof Error ? preferenceLoadError.message : String(preferenceLoadError))}`;

	const dispatchKeys = (keys: readonly string[]) => {
		for (const key of keys) {
			controller.handleKey(key);
			if (controller.state.quit || finished) break;
		}
	};
	const onData = (data: Buffer | string) => {
		try {
			if (escapeTimer) clearTimeout(escapeTimer);
			if (revealOverlay) {
				decoder.reset();
				decoder = new TerminalInputDecoder();
				revealOverlay.acknowledge();
				return;
			}
			dispatchKeys(decoder.push(data));
			if (decoder.hasPendingInput) {
				escapeTimer = setTimeout(() => {
					try {
						dispatchKeys(decoder.flush());
					} catch (cause) {
						finish(cause);
					}
				}, options.escapeTimeoutMs ?? 25);
			}
		} catch (cause) {
			finish(cause);
		}
	};
	const onResize = () => revealOverlay?.draw() ?? draw();
	const refreshTimer = setInterval(() => controller.refreshVisibleWorkspace(), preferences.refreshIntervalMs);
	refreshTimer.unref?.();
	const detachSignals = attachTerminalSignals(signals, (signal) => {
		if (terminatingSignal) return;
		terminatingSignal = signal;
		void controller.detachAndQuit(signal).then(
			() => finish(new Error(`Clearance TUI terminated by ${signal}.`)),
			finish,
		);
	});

	try {
		terminal.enter();
		io.input.on("data", onData);
		io.output.on?.("resize", onResize);
		draw();
		await done;
	} finally {
		if (escapeTimer) clearTimeout(escapeTimer);
		decoder.reset();
		io.input.off("data", onData);
		io.output.off?.("resize", onResize);
		detachSignals();
		clearInterval(refreshTimer);
		terminal.restore();
		await preferenceSave;
	}
	if (terminal.restoreErrors.length) throw new AggregateError(terminal.restoreErrors, "Clearance could not fully restore terminal state.");
}
