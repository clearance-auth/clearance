import type { ManagementStore } from "../store/types.js";
import type { Membership, Organization, Principal } from "../types/resources.js";
import { ClearanceError, isClearanceError } from "./errors.js";
import { resolveAssignableRole } from "./roles.js";
import { resolveOperatorScope } from "./scope.js";

const MAX_ROWS = 1000;
const FIELDS = new Set(["principalId", "user", "email", "role"]);

export type MemberImportFormat = "json" | "csv";

export type MemberImportPlanRow = {
	row: number;
	principalId: string;
	role: string;
	idempotent: boolean;
};

export type MemberImportPlan = {
	organizationId: string;
	format: MemberImportFormat;
	rows: MemberImportPlanRow[];
	summary: { total: number; wouldAdd: number; idempotent: number };
};

export type MemberImportRowResult = {
	row: number;
	principalId: string;
	status: "success" | "idempotent" | "failure";
	error?: { code: string; stage: string; retryable: boolean };
};

export type MemberImportResult = MemberImportPlan["summary"] & {
	completed: true;
	partial: boolean;
	results: MemberImportRowResult[];
	success: number;
	failure: number;
};

type ImportRow = { row: number; principalId?: string; user?: string; email?: string; role?: string };

function inputError(code: string, remediation: string): never {
	throw new ClearanceError({
		code,
		message: "Member import file is invalid",
		stage: "orgs.members.import.parse",
		remediation,
	});
}

function trimRow(row: Record<string, unknown>, position: number): ImportRow {
	for (const key of Object.keys(row)) {
		if (!FIELDS.has(key)) inputError("MEMBER_IMPORT_FIELD_INVALID", "Use only principalId, user, email, and role columns.");
	}
	const value = (key: "principalId" | "user" | "email" | "role") => {
		const raw = row[key];
		if (raw == null) return undefined;
		if (typeof raw !== "string") inputError("MEMBER_IMPORT_VALUE_INVALID", "Use string values for member import fields.");
		return raw.trim() || undefined;
	};
	return { row: position, principalId: value("principalId"), user: value("user"), email: value("email"), role: value("role") };
}

function parseJson(content: string): ImportRow[] {
	let parsed: unknown;
	try { parsed = JSON.parse(content); } catch { inputError("MEMBER_IMPORT_JSON_INVALID", "Provide valid JSON containing an array or an object with a members array."); }
	const rows = Array.isArray(parsed)
		? parsed
		: parsed && typeof parsed === "object" && !Array.isArray(parsed) && Object.keys(parsed).length === 1 && Array.isArray((parsed as { members?: unknown }).members)
			? (parsed as { members: unknown[] }).members
			: inputError("MEMBER_IMPORT_JSON_SHAPE_INVALID", "Provide an array or an object with only a members array.");
	if (rows.length > MAX_ROWS) inputError("MEMBER_IMPORT_LIMIT_EXCEEDED", "Import at most 1000 members at a time.");
	if (rows.length === 0) inputError("MEMBER_IMPORT_EMPTY", "Provide at least one member to import.");
	return rows.map((value, index) => {
		if (!value || typeof value !== "object" || Array.isArray(value)) inputError("MEMBER_IMPORT_ROW_INVALID", "Each member entry must be an object.");
		return trimRow(value as Record<string, unknown>, index + 1);
	});
}

function parseCsvRecords(content: string): string[][] {
	const records: string[][] = [];
	let record: string[] = [];
	let field = "";
	let quoted = false;
	for (let i = 0; i < content.length; i += 1) {
		const char = content[i]!;
		if (quoted) {
			if (char === '"' && content[i + 1] === '"') { field += '"'; i += 1; }
			else if (char === '"') quoted = false;
			else field += char;
			continue;
		}
		if (char === '"') { if (field !== "") inputError("MEMBER_IMPORT_CSV_INVALID", "Use valid CSV quoting."); quoted = true; }
		else if (char === ",") { record.push(field); field = ""; }
		else if (char === "\n") { record.push(field); records.push(record); record = []; field = ""; }
		else if (char !== "\r") field += char;
	}
	if (quoted) inputError("MEMBER_IMPORT_CSV_INVALID", "Use valid CSV quoting.");
	if (field !== "" || record.length > 0) { record.push(field); records.push(record); }
	return records;
}

function parseCsv(content: string): ImportRow[] {
	const records = parseCsvRecords(content);
	const header = records.shift();
	if (!header || header.length === 0) inputError("MEMBER_IMPORT_CSV_HEADER_INVALID", "Provide a CSV header with one identity column.");
	const headers = header.map((value) => value.trim());
	if (headers.some((header, index) => !header || !FIELDS.has(header) || headers.indexOf(header) !== index)) inputError("MEMBER_IMPORT_CSV_HEADER_INVALID", "Use unique principalId, user, email, and role CSV headers.");
	if (!headers.some((header) => header === "principalId" || header === "user" || header === "email")) inputError("MEMBER_IMPORT_CSV_HEADER_INVALID", "Provide principalId, user, or email in the CSV header.");
	if (records.length > MAX_ROWS) inputError("MEMBER_IMPORT_LIMIT_EXCEEDED", "Import at most 1000 members at a time.");
	if (records.length === 0) inputError("MEMBER_IMPORT_EMPTY", "Provide at least one member to import.");
	return records.map((values, index) => {
		if (values.length !== headers.length) inputError("MEMBER_IMPORT_CSV_ROW_INVALID", "Each CSV row must match the header column count.");
		return trimRow(Object.fromEntries(headers.map((header, column) => [header, values[column]!])), index + 2);
	});
}

function requireOrganization(store: ManagementStore, id: string): Organization {
	const scope = resolveOperatorScope(store);
	const org = store.snapshot.organizations.find((candidate) => candidate.id === id && candidate.status !== "archived" && candidate.projectId === scope.projectId && candidate.environmentId === scope.environmentId);
	if (!org) throw new ClearanceError({ code: "ORG_NOT_FOUND", message: "Organization not found", stage: "orgs.members.import", status: 404 });
	return org;
}

function resolvePrincipal(store: ManagementStore, org: Organization, row: ImportRow): Principal {
	const identities = [row.principalId, row.user, row.email].filter((value): value is string => Boolean(value));
	if (identities.length !== 1) inputError("MEMBER_IMPORT_IDENTITY_INVALID", "Each row must specify exactly one of principalId, user, or email.");
	const principal = row.email
		? store.snapshot.principals.find((candidate) => candidate.email.toLowerCase() === row.email!.toLowerCase())
		: store.snapshot.principals.find((candidate) => candidate.id === identities[0]);
	if (!principal || principal.status === "deleted" || principal.projectId !== org.projectId || principal.environmentId !== org.environmentId) throw new ClearanceError({ code: "USER_NOT_FOUND", message: "User not found", stage: "orgs.members.import", status: 404 });
	return principal;
}

export function planMemberImport(store: ManagementStore, input: { organizationId: string; content: string; format: MemberImportFormat }): MemberImportPlan {
	const org = requireOrganization(store, input.organizationId.trim());
	const parsed = input.format === "json" ? parseJson(input.content) : parseCsv(input.content);
	const seen = new Set<string>();
	const resolvedRows = parsed.map((row) => {
		const principal = resolvePrincipal(store, org, row);
		if (seen.has(principal.id)) inputError("MEMBER_IMPORT_DUPLICATE_PRINCIPAL", "Each principal may appear only once in an import.");
		seen.add(principal.id);
		return { row, principal };
	});
	const rows = resolvedRows.map(({ row, principal }) => {
		const resolved = resolveAssignableRole(store, row.role ?? "member", { scope: { projectId: org.projectId, environmentId: org.environmentId }, organizationId: org.id, stage: "orgs.members.import" });
		const existing = store.snapshot.memberships.find(
			(membership) =>
				membership.organizationId === org.id &&
				membership.principalId === principal.id &&
				membership.status === "active",
		);
		if (existing && existing.role !== resolved.slug) {
			throw new ClearanceError({
				code: "MEMBER_IMPORT_ROLE_CONFLICT",
				message: "Existing membership has a different role",
				stage: "orgs.members.import",
				status: 409,
				remediation: "Update the existing membership role before retrying the import.",
			});
		}
		const idempotent = Boolean(existing);
		return { row: row.row, principalId: principal.id, role: resolved.slug, idempotent };
	});
	const idempotent = rows.filter((row) => row.idempotent).length;
	return { organizationId: org.id, format: input.format, rows, summary: { total: rows.length, wouldAdd: rows.length - idempotent, idempotent } };
}

/** Applies a fully validated plan in deterministic file order. Each callback is durable before the next row. */
export async function executeMemberImportPlan(plan: MemberImportPlan, apply: (row: MemberImportPlanRow) => Promise<Membership>): Promise<MemberImportResult> {
	const results: MemberImportRowResult[] = [];
	for (const row of plan.rows) {
		try {
			await apply(row);
			results.push({ row: row.row, principalId: row.principalId, status: row.idempotent ? "idempotent" : "success" });
		} catch (error) {
			results.push({
				row: row.row,
				principalId: row.principalId,
				status: "failure",
				error: isClearanceError(error) ? { code: error.code, stage: error.stage, retryable: error.retryable } : { code: "MEMBER_IMPORT_ROW_FAILED", stage: "orgs.members.import.apply", retryable: false },
			});
		}
	}
	const failure = results.filter((result) => result.status === "failure").length;
	return { ...plan.summary, completed: true, partial: failure > 0, results, success: results.length - failure, failure };
}
