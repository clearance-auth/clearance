import { randomBytes } from "node:crypto";
import {
	chmod,
	lstat,
	mkdir,
	open,
	rename,
	unlink,
} from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { constants } from "node:fs";
import { ClearanceError } from "@clearance/management";

const CREDENTIAL_FILENAME = "operator-credentials.json";
const CREDENTIAL_VERSION = 1;
const WHOAMI_TIMEOUT_MS = 5_000;
const MAX_STDIN_TOKEN_BYTES = 16 * 1024;
const MIN_TOKEN_BYTES = 16;
const MAX_CREDENTIAL_FILE_BYTES = 32 * 1024;

export type OperatorCredential = {
	version: 1;
	apiUrl: string;
	token: string;
};

export type OperatorWhoami = {
	operator: { id: string; type: "operator"; authenticated: true };
	projectId: string;
	environmentId: string;
	storeBackend: "json" | "postgres";
};

type AuthEnvironment = Partial<Pick<
	NodeJS.ProcessEnv,
	| "CLEARANCE_CLI_CONFIG_DIR"
	| "XDG_CONFIG_HOME"
	| "HOME"
	| "CLEARANCE_API_URL"
	| "CLEARANCE_OPERATOR_TOKEN"
	| "CLEARANCE_API_TOKEN"
	| "CLEARANCE_PROFILE"
>>;

function error(code: string, message: string, remediation: string, retryable = false): ClearanceError {
	return new ClearanceError({
		code,
		message,
		stage: "operator-auth",
		remediation,
		retryable,
	});
}

function credentialIoError(cause: unknown): ClearanceError {
	if (cause instanceof ClearanceError) return cause;
	return error(
		"CLI_CREDENTIAL_IO",
		"Saved credential storage could not be accessed safely.",
		"Check CLEARANCE_CLI_CONFIG_DIR permissions and try again.",
	);
}

function fileMode(mode: number): number {
	return mode & 0o777;
}

async function requirePrivateDirectory(path: string, create: boolean): Promise<void> {
	try {
		const stat = await lstat(path);
		if (stat.isSymbolicLink() || !stat.isDirectory()) {
			throw error(
				"CLI_CREDENTIAL_DIRECTORY_UNSAFE",
				"Credential directory is not a regular private directory.",
				"Remove the unsafe credential directory and run clearance login again.",
			);
		}
		if (fileMode(stat.mode) !== 0o700) {
			throw error(
				"CLI_CREDENTIAL_DIRECTORY_UNSAFE",
				"Credential directory permissions must be 0700.",
				"Restrict the credential directory to its owner and run clearance login again.",
			);
		}
		return;
	} catch (cause) {
		if (cause instanceof ClearanceError) throw cause;
		if ((cause as NodeJS.ErrnoException).code !== "ENOENT" || !create) throw cause;
	}

	await mkdir(path, { recursive: true, mode: 0o700 });
	const beforeChmod = await lstat(path);
	if (beforeChmod.isSymbolicLink() || !beforeChmod.isDirectory()) {
		throw error(
			"CLI_CREDENTIAL_DIRECTORY_UNSAFE",
			"Credential directory could not be secured.",
			"Set a private CLEARANCE_CLI_CONFIG_DIR and retry.",
		);
	}
	await chmod(path, 0o700);
	const stat = await lstat(path);
	if (stat.isSymbolicLink() || !stat.isDirectory() || fileMode(stat.mode) !== 0o700) {
		throw error(
			"CLI_CREDENTIAL_DIRECTORY_UNSAFE",
			"Credential directory could not be secured.",
			"Set a private CLEARANCE_CLI_CONFIG_DIR and retry.",
		);
	}
}

async function requirePrivateCredentialFile(path: string): Promise<void> {
	const stat = await lstat(path);
	if (stat.isSymbolicLink() || !stat.isFile() || fileMode(stat.mode) !== 0o600) {
		throw error(
			"CLI_CREDENTIAL_FILE_UNSAFE",
			"Saved credential file is not a regular file with mode 0600.",
			"Remove the unsafe credential file and log in again.",
		);
	}
}

export function credentialDirectory(env: AuthEnvironment = process.env): string {
	const explicit = env.CLEARANCE_CLI_CONFIG_DIR?.trim();
	if (explicit) return resolve(explicit);
	const xdg = env.XDG_CONFIG_HOME?.trim();
	if (xdg) return resolve(xdg, "clearance");
	return join(env.HOME?.trim() || homedir(), ".config", "clearance");
}

export function normalizeProfile(profile: string | undefined, env: AuthEnvironment = process.env): string {
	const value = profile?.trim() || env.CLEARANCE_PROFILE?.trim() || "default";
	if (!/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(value)) {
		throw error(
			"CLI_PROFILE_INVALID",
			"Clearance profile names must be lowercase letters, numbers, or hyphens.",
			"Choose a profile slug such as default, staging, or production-us.",
		);
	}
	return value;
}

export function credentialPath(env: AuthEnvironment = process.env, profile?: string): string {
	const selected = normalizeProfile(profile, env);
	const filename = selected === "default" ? CREDENTIAL_FILENAME : `operator-credentials.${selected}.json`;
	return join(credentialDirectory(env), filename);
}

function isLoopbackHost(hostname: string): boolean {
	const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
	return host === "localhost" || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host);
}

export function normalizeApiUrl(candidate: string | undefined, env: AuthEnvironment = process.env): string {
	const value = candidate?.trim() || env.CLEARANCE_API_URL?.trim() || "http://localhost:3200";
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		throw error("CLI_API_URL_INVALID", "Clearance API URL is invalid.", "Pass a valid --url or set CLEARANCE_API_URL.");
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") {
		throw error("CLI_API_URL_INVALID", "Clearance API URL must use HTTPS or local HTTP.", "Use an HTTPS URL or a localhost loopback HTTP URL.");
	}
	if (url.protocol === "http:" && !isLoopbackHost(url.hostname)) {
		throw error("CLI_API_URL_INSECURE", "Remote Clearance API URLs must use HTTPS.", "Use HTTPS for remote APIs; HTTP is allowed only for localhost loopback.");
	}
	if (url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
		throw error("CLI_API_URL_INVALID", "Clearance API URL must be an origin without credentials, path, query, or fragment.", "Pass the API origin, for example https://api.example.com.");
	}
	return url.origin;
}

export function environmentToken(env: AuthEnvironment = process.env): string | undefined {
	return env.CLEARANCE_OPERATOR_TOKEN?.trim() || env.CLEARANCE_API_TOKEN?.trim() || undefined;
}

function validateOperatorToken(token: string): string {
	const size = Buffer.byteLength(token, "utf8");
	if (size < MIN_TOKEN_BYTES || size > MAX_STDIN_TOKEN_BYTES || /\s/.test(token)) {
		throw error(
			"CLI_TOKEN_INVALID",
			"Operator token is invalid.",
			"Provide a bearer token between 16 bytes and 16 KiB without whitespace.",
		);
	}
	return token;
}

function parseCredential(raw: string): OperatorCredential {
	let value: unknown;
	try {
		value = JSON.parse(raw);
	} catch {
		throw error("CLI_CREDENTIAL_INVALID", "Saved credential file is not valid JSON.", "Log in again to create a new credential file.");
	}
	if (
		!value ||
		typeof value !== "object" ||
		Array.isArray(value) ||
		Object.keys(value).length !== 3 ||
		!["version", "apiUrl", "token"].every((key) => Object.prototype.hasOwnProperty.call(value, key))
	) {
		throw error("CLI_CREDENTIAL_INVALID", "Saved credential file has an invalid schema.", "Log in again to create a new credential file.");
	}
	const credential = value as Record<string, unknown>;
	if (
		credential.version !== CREDENTIAL_VERSION ||
		typeof credential.apiUrl !== "string" ||
		typeof credential.token !== "string"
	) {
		throw error("CLI_CREDENTIAL_INVALID", "Saved credential file has an invalid schema.", "Log in again to create a new credential file.");
	}
	try {
		validateOperatorToken(credential.token);
	} catch {
		throw error("CLI_CREDENTIAL_INVALID", "Saved credential file has an invalid schema.", "Log in again to create a new credential file.");
	}
	return {
		version: CREDENTIAL_VERSION,
		apiUrl: normalizeApiUrl(credential.apiUrl, {}),
		token: credential.token,
	};
}

export async function readSavedCredential(env: AuthEnvironment = process.env, profile?: string): Promise<OperatorCredential | undefined> {
	const directory = credentialDirectory(env);
	const path = credentialPath(env, profile);
	try {
		await requirePrivateDirectory(directory, false);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw credentialIoError(cause);
	}
	try {
		const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		try {
			const stat = await handle.stat();
			if (!stat.isFile() || fileMode(stat.mode) !== 0o600 || stat.size > MAX_CREDENTIAL_FILE_BYTES) {
				throw error(
					"CLI_CREDENTIAL_FILE_UNSAFE",
					"Saved credential file is not a regular, bounded file with mode 0600.",
					"Remove the unsafe credential file and log in again.",
				);
			}
			return parseCredential(await handle.readFile("utf8"));
		} finally {
			await handle.close();
		}
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw credentialIoError(cause);
	}
}

export async function writeSavedCredential(
	credential: Omit<OperatorCredential, "version">,
	env: AuthEnvironment = process.env,
	profile?: string,
): Promise<void> {
	const directory = credentialDirectory(env);
	const selectedProfile = normalizeProfile(profile, env);
	const path = credentialPath(env, selectedProfile);
	try {
		await requirePrivateDirectory(directory, true);
	} catch (cause) {
		throw credentialIoError(cause);
	}
	try {
		await requirePrivateCredentialFile(path);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw credentialIoError(cause);
	}
	const normalized: OperatorCredential = {
		version: CREDENTIAL_VERSION,
		apiUrl: normalizeApiUrl(credential.apiUrl, {}),
		token: validateOperatorToken(credential.token),
	};
	const temporary = join(directory, `.${selectedProfile}.${CREDENTIAL_FILENAME}.${randomBytes(16).toString("hex")}.tmp`);
	let handle: Awaited<ReturnType<typeof open>> | undefined;
	try {
		handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
		await handle.writeFile(`${JSON.stringify(normalized)}\n`, "utf8");
		await handle.sync();
		await handle.close();
		handle = undefined;
		await rename(temporary, path);
		await requirePrivateCredentialFile(path);
	} catch (cause) {
		await handle?.close().catch(() => undefined);
		await unlink(temporary).catch(() => undefined);
		throw credentialIoError(cause);
	}
}

export async function deleteSavedCredential(env: AuthEnvironment = process.env, profile?: string): Promise<boolean> {
	const directory = credentialDirectory(env);
	const path = credentialPath(env, profile);
	try {
		await requirePrivateDirectory(directory, false);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw credentialIoError(cause);
	}
	try {
		await requirePrivateCredentialFile(path);
		await unlink(path);
		return true;
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw credentialIoError(cause);
	}
}

export async function readTokenFromStdin(): Promise<string> {
	let input = "";
	for await (const chunk of process.stdin) {
		input += typeof chunk === "string" ? chunk : chunk.toString("utf8");
		if (Buffer.byteLength(input, "utf8") > MAX_STDIN_TOKEN_BYTES) {
			throw error("CLI_TOKEN_INVALID", "Operator token input is too large.", "Provide one bearer token on standard input.");
		}
	}
	return validateOperatorToken(input.trim());
}

function parseWhoami(value: unknown): OperatorWhoami {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw error("CLI_WHOAMI_INVALID_RESPONSE", "Clearance API returned an invalid whoami response.", "Upgrade the Clearance API or check the configured API URL.");
	}
	const response = value as Record<string, unknown>;
	const operator = response.operator as Record<string, unknown> | undefined;
	if (
		!operator ||
		operator.id !== "operator" ||
		operator.type !== "operator" ||
		operator.authenticated !== true ||
		typeof response.projectId !== "string" ||
		!response.projectId ||
		typeof response.environmentId !== "string" ||
		!response.environmentId ||
		(response.storeBackend !== "json" && response.storeBackend !== "postgres")
	) {
		throw error("CLI_WHOAMI_INVALID_RESPONSE", "Clearance API returned an invalid whoami response.", "Upgrade the Clearance API or check the configured API URL.");
	}
	return {
		operator: { id: "operator", type: "operator", authenticated: true },
		projectId: response.projectId,
		environmentId: response.environmentId,
		storeBackend: response.storeBackend,
	};
}

export async function fetchWhoami(apiUrl: string, token: string): Promise<OperatorWhoami> {
	const validatedToken = validateOperatorToken(token);
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), WHOAMI_TIMEOUT_MS);
	try {
		const response = await fetch(`${normalizeApiUrl(apiUrl, {})}/v1/whoami`, {
			headers: { authorization: `Bearer ${validatedToken}`, accept: "application/json" },
			signal: controller.signal,
		});
		if (response.status === 401) {
			throw error("CLI_AUTH_UNAUTHORIZED", "Clearance API rejected the operator credential.", "Provide a valid operator token and try again.");
		}
		if (!response.ok) {
			throw error("CLI_WHOAMI_FAILED", "Clearance API could not verify the operator credential.", "Check the API URL and operator access, then try again.", response.status >= 500);
		}
		return parseWhoami(await response.json());
	} catch (cause) {
		if (cause instanceof ClearanceError) throw cause;
		if ((cause as Error).name === "AbortError") {
			throw error("CLI_API_TIMEOUT", "Clearance API verification timed out.", "Check API reachability and try again.", true);
		}
		throw error("CLI_API_UNREACHABLE", "Clearance API could not be reached.", "Check the API URL and network connection, then try again.", true);
	} finally {
		clearTimeout(timer);
	}
}

export async function validateAndSaveCredential(
	apiUrl: string,
	token: string,
	env: AuthEnvironment = process.env,
	profile?: string,
): Promise<OperatorWhoami> {
	const whoami = await fetchWhoami(apiUrl, token);
	await writeSavedCredential({ apiUrl, token }, env, profile);
	return whoami;
}
