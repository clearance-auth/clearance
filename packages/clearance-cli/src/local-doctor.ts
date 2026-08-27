import {
	DEFAULT_LOCAL_DOCTOR_TIMEOUT_MS,
	DEFAULT_MANAGEMENT_API_ORIGIN,
} from "./cli-defaults.js";
import { sanitizeTerminalText } from "./terminal-sanitize.js";

export type LocalDoctorCheckStatus = "pass" | "warn" | "fail";

export interface LocalDoctorCheck {
	readonly id: "cli" | "config" | "profile" | "api" | "skill" | "completion";
	readonly status: LocalDoctorCheckStatus;
	readonly summary: string;
	readonly detail?: string;
}

export interface LocalConfigInspection {
	readonly state: "ready" | "absent" | "unsafe";
	readonly detail?: string;
}

export interface LocalProfileInspection {
	readonly state: "configured" | "absent" | "unsafe";
	/** A non-secret API origin only. It is normalized before it is rendered. */
	readonly apiOrigin?: string;
}

export interface LocalFeatureInspection {
	readonly state: "installed" | "missing" | "conflict" | "unavailable";
	readonly detail?: string;
}

export interface LocalDoctorDependencies {
	readonly cliVersion: () => string;
	readonly inspectConfig: () => Promise<LocalConfigInspection>;
	readonly inspectProfile: (profile: string) => Promise<LocalProfileInspection>;
	readonly inspectSkill: () => Promise<LocalFeatureInspection>;
	readonly inspectCompletion: () => Promise<LocalFeatureInspection>;
	readonly fetch?: typeof fetch;
	readonly timeoutMs?: number;
}

export interface LocalDoctorOptions {
	readonly profile?: string;
	readonly apiOrigin?: string;
}

export interface LocalDoctorResult {
	readonly profile: string;
	readonly apiOrigin: string;
	readonly checks: readonly LocalDoctorCheck[];
	readonly ok: boolean;
}

function safeText(value: unknown, fallback = "unavailable"): string {
	if (typeof value !== "string") return fallback;
	const cleaned = sanitizeTerminalText(value).replace(/\s+/gu, " ").trim();
	return cleaned ? cleaned.slice(0, 160) : fallback;
}

function safeProfile(value: string | undefined): string {
	const normalized = value?.trim() || "default";
	return /^[a-z0-9-]{1,64}$/u.test(normalized) ? normalized : "invalid-profile";
}

function safeOrigin(value: string | undefined): string {
	try {
		const parsed = new URL(value ?? DEFAULT_MANAGEMENT_API_ORIGIN);
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("unsupported protocol");
		return parsed.origin;
	} catch {
		return DEFAULT_MANAGEMENT_API_ORIGIN;
	}
}

function featureCheck(id: "skill" | "completion", name: string, inspection: LocalFeatureInspection): LocalDoctorCheck {
	const detail = inspection.detail ? safeText(inspection.detail) : undefined;
	if (inspection.state === "installed") return { id, status: "pass", summary: `${name} installed`, ...(detail ? { detail } : {}) };
	if (inspection.state === "missing") return { id, status: "warn", summary: `${name} not installed`, ...(detail ? { detail } : {}) };
	return { id, status: "fail", summary: `${name} inspection unavailable`, ...(detail ? { detail } : {}) };
}

async function healthCheck(origin: string, fetcher: typeof fetch | undefined, timeoutMs: number): Promise<LocalDoctorCheck> {
	if (!fetcher) return { id: "api", status: "fail", summary: "API health probe unavailable" };
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		// Deliberately omit credentials: local health must be useful before login.
		const response = await fetcher(`${origin}/health`, { method: "GET", signal: controller.signal });
		return response.ok
			? { id: "api", status: "pass", summary: "Management API health check passed" }
			: { id: "api", status: "fail", summary: `Management API health returned HTTP ${response.status}` };
	} catch (cause) {
		const timedOut = controller.signal.aborted || (cause instanceof Error && cause.name === "AbortError");
		return { id: "api", status: "fail", summary: timedOut ? "Management API health check timed out" : "Management API is unreachable" };
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Check only local setup plus the unauthenticated management health endpoint.
 * Inspectors make filesystem state and shell-specific state explicit to callers.
 */
export async function runLocalDoctor(
	options: Readonly<LocalDoctorOptions>,
	dependencies: Readonly<LocalDoctorDependencies>,
): Promise<LocalDoctorResult> {
	const profile = safeProfile(options.profile);
	const configuredOrigin = safeOrigin(options.apiOrigin);
	const checks: LocalDoctorCheck[] = [{ id: "cli", status: "pass", summary: `Clearance CLI ${safeText(dependencies.cliVersion(), "unknown version")}` }];
	try {
		const config = await dependencies.inspectConfig();
		const detail = config.detail ? safeText(config.detail) : undefined;
		if (config.state === "ready") {
			checks.push({ id: "config", status: "pass", summary: "Local configuration directory is ready", ...(detail ? { detail } : {}) });
		} else if (config.state === "absent") {
			checks.push({ id: "config", status: "warn", summary: "Local configuration has not been created", ...(detail ? { detail } : {}) });
		} else {
			checks.push({ id: "config", status: "fail", summary: "Local configuration is unsafe", ...(detail ? { detail } : {}) });
		}
	} catch {
		checks.push({ id: "config", status: "fail", summary: "Local configuration could not be inspected safely" });
	}
	let apiOrigin = configuredOrigin;
	try {
		const inspection = await dependencies.inspectProfile(profile);
		if (inspection.state === "configured") {
			apiOrigin = safeOrigin(options.apiOrigin ?? inspection.apiOrigin);
			checks.push({ id: "profile", status: "pass", summary: `Profile ${profile} is configured` });
		} else if (inspection.state === "absent") {
			checks.push({ id: "profile", status: "warn", summary: `Profile ${profile} is not configured` });
		} else {
			checks.push({ id: "profile", status: "fail", summary: `Profile ${profile} is unsafe to read` });
		}
	} catch {
		checks.push({ id: "profile", status: "fail", summary: `Profile ${profile} could not be inspected safely` });
	}
	checks.push(await healthCheck(apiOrigin, dependencies.fetch ?? globalThis.fetch, dependencies.timeoutMs ?? DEFAULT_LOCAL_DOCTOR_TIMEOUT_MS));
	for (const [id, name, inspect] of [
		["skill", "Agent skill", dependencies.inspectSkill],
		["completion", "Shell completion", dependencies.inspectCompletion],
	] as const) {
		try { checks.push(featureCheck(id, name, await inspect())); }
		catch { checks.push({ id, status: "fail", summary: `${name} could not be inspected safely` }); }
	}
	return { profile, apiOrigin, checks, ok: checks.every((check) => check.status !== "fail") };
}

/** Safe, line-oriented rendering for interactive terminals. */
export function renderLocalDoctor(result: Readonly<LocalDoctorResult>): string {
	const heading = `Local doctor for profile ${safeText(result.profile)} at ${safeText(result.apiOrigin)}`;
	return [heading, ...result.checks.map((check) => `[${check.status.toUpperCase()}] ${safeText(check.summary)}${check.detail ? `: ${safeText(check.detail)}` : ""}`)].join("\n");
}
