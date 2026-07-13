/**
 * Atomic export file writer shared by events.export and users.export.
 * Mode 0o600, refuse-overwrite by default, no partial final artifacts.
 */
import {
	existsSync,
	linkSync,
	mkdirSync,
	renameSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { ClearanceError } from "./errors.js";

export type WriteExportArtifactCodes = {
	/** Audit/export stage string (e.g. events.export) */
	stage?: string;
	/** Error code when destination exists and force is false */
	existsCode?: string;
	/** Error code when write fails for other reasons */
	writeFailedCode?: string;
};

/**
 * Write export body atomically. Refuses to overwrite unless force.
 * On failure leaves no partial final artifact at outputPath.
 * Mode 0o600 — owner read/write only.
 */
export function writeExportArtifact(
	outputPath: string,
	body: string,
	force: boolean,
	codes: WriteExportArtifactCodes = {},
): string {
	const stage = codes.stage ?? "events.export";
	const existsCode = codes.existsCode ?? "EVENTS_EXPORT_EXISTS";
	const writeFailedCode = codes.writeFailedCode ?? "EVENTS_EXPORT_WRITE_FAILED";
	const path = resolve(outputPath);
	if (existsSync(path) && !force) {
		throw new ClearanceError({
			code: existsCode,
			message: `Export path already exists: ${path}`,
			stage,
			status: 409,
			remediation: "Choose a new --output path or pass --force to overwrite",
		});
	}
	mkdirSync(dirname(path), { recursive: true });
	const tmp = `${path}.${randomUUID()}.tmp`;
	try {
		writeFileSync(tmp, body, { encoding: "utf8", flag: "wx", mode: 0o600 });
		if (force) {
			renameSync(tmp, path);
		} else {
			// Atomic no-clobber publish: hard-link creation fails with EEXIST if a
			// concurrent exporter wins after the initial advisory exists check.
			linkSync(tmp, path);
			unlinkSync(tmp);
		}
	} catch (err) {
		try {
			if (existsSync(tmp)) unlinkSync(tmp);
		} catch {
			/* best-effort tmp cleanup */
		}
		if ((err as NodeJS.ErrnoException)?.code === "EEXIST") {
			throw new ClearanceError({
				code: existsCode,
				message: `Export path already exists: ${path}`,
				stage,
				status: 409,
				remediation: "Choose a new --output path or pass --force to overwrite",
			});
		}
		if (err instanceof ClearanceError) throw err;
		throw new ClearanceError({
			code: writeFailedCode,
			message: `Failed to write export artifact: ${err instanceof Error ? err.message : String(err)}`,
			stage,
			status: 500,
			remediation: "Check path permissions and free disk space, then retry",
		});
	}
	return path;
}
