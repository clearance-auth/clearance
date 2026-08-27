import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, isAbsolute } from "node:path";

export const TUI_PREFERENCES_VERSION = 1 as const;

export interface TuiPreferences {
	readonly version: typeof TUI_PREFERENCES_VERSION;
	readonly theme: "auto" | "dark" | "light";
	readonly color: "auto" | "always" | "never";
	readonly refreshIntervalMs: number;
	readonly sectionId?: string;
	readonly rawJson: boolean;
}

export const DEFAULT_TUI_PREFERENCES: TuiPreferences = Object.freeze({
	version: TUI_PREFERENCES_VERSION,
	theme: "auto",
	color: "auto",
	refreshIntervalMs: 15_000,
	rawJson: false,
});

export interface TuiPreferenceStore {
	load(): Promise<TuiPreferences>;
	save(preferences: TuiPreferences): Promise<void>;
}

export function parseTuiPreferences(value: unknown): TuiPreferences {
	if (!value || typeof value !== "object") return DEFAULT_TUI_PREFERENCES;
	const record = value as Record<string, unknown>;
	const theme = record.theme === "dark" || record.theme === "light" ? record.theme : "auto";
	const color = record.color === "always" || record.color === "never" ? record.color : "auto";
	const refresh = typeof record.refreshIntervalMs === "number" && Number.isFinite(record.refreshIntervalMs)
		? Math.min(300_000, Math.max(2_000, Math.round(record.refreshIntervalMs)))
		: DEFAULT_TUI_PREFERENCES.refreshIntervalMs;
	return Object.freeze({
		version: TUI_PREFERENCES_VERSION,
		theme,
		color,
		refreshIntervalMs: refresh,
		...(typeof record.sectionId === "string" && record.sectionId.trim() ? { sectionId: record.sectionId.trim() } : {}),
		rawJson: record.rawJson === true,
	});
}

export function createFilePreferenceStore(path: string): TuiPreferenceStore {
	if (!isAbsolute(path)) throw new Error("TUI preference path must be absolute.");
	return {
		async load() {
			try {
				return parseTuiPreferences(JSON.parse(await readFile(path, "utf8")));
			} catch (cause) {
				const code = cause && typeof cause === "object" && "code" in cause ? String(cause.code) : "";
				if (code === "ENOENT" || cause instanceof SyntaxError) return DEFAULT_TUI_PREFERENCES;
				throw cause;
			}
		},
		async save(preferences) {
			const normalized = parseTuiPreferences(preferences);
			await mkdir(dirname(path), { recursive: true, mode: 0o700 });
			const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
			await writeFile(temporary, `${JSON.stringify(normalized, null, 2)}\n`, { mode: 0o600 });
			await rename(temporary, path);
		},
	};
}

export function createMemoryPreferenceStore(initial: unknown = DEFAULT_TUI_PREFERENCES): TuiPreferenceStore {
	let value = parseTuiPreferences(initial);
	return {
		async load() { return value; },
		async save(next) { value = parseTuiPreferences(next); },
	};
}
