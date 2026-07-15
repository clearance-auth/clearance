/**
 * Structural durability guard (FOLLOW.md P2.2.2).
 *
 * PgStore.mutate() is fire-and-forget: a queued write's failure surfaces only
 * at the next ready(). The CLI is transport-only. Application use cases commit
 * through withManagementUnitOfWork; remaining API-owned workflows must resolve
 * durability before returning.
 *
 * How it works (static source walk, no DB required):
 *  1. Derive the known-mutating service list from the management package's own
 *     sources: every exported function in src/services/*.ts and auth-bridge.ts
 *     whose body (directly or transitively) calls store.mutate(...). Functions
 *     that only use mutateDurable / mutateCoordinated / requireCoordinated, or
 *     that `await store.ready()` themselves, are "durable": their awaited
 *     promise already rejects on write failure, so callers need no extra flush.
 *     New services are covered automatically — nothing here is a hardcoded
 *     service list.
 *  2. Assert packages/clearance-cli/src/index.ts has no direct management
 *     mutations; operational commands dispatch through the API.
 *  3. Walk packages/clearance-api/src/server.ts and src/routes/*.ts: every route handler that
 *     calls a queued-mutating service must `await store.ready()` after its
 *     last mutating call (durable-only handlers are exempt by construction).
 *
 * JsonStore.mutate persists synchronously before returning, so this hazard is
 * Postgres-only; the guard still applies uniformly because both surfaces can
 * run against either backend.
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../../..");
const servicesDir = resolve(here, "../services");
const applicationDir = resolve(here, "../application");
const authBridgePath = resolve(here, "../auth-bridge.ts");
const cliPath = join(repoRoot, "packages/clearance-cli/src/index.ts");
const apiPath = join(repoRoot, "packages/clearance-api/src/server.ts");
const apiRoutesDir = join(repoRoot, "packages/clearance-api/src/routes");

type FnInfo = {
	file: string;
	body: string;
	kind: "queued" | "durable" | "none";
};

/**
 * Split a module into top-level declaration segments and return exported
 * function bodies. Segment boundaries are top-level declaration keywords, so
 * object-literal return type annotations and nested braces cannot truncate a
 * body (a brace-counting parser gets those wrong).
 */
function exportedFunctionSegments(source: string): Map<string, string> {
	const out = new Map<string, string>();
	const boundary =
		/^(?:export\s+)?(?:async\s+)?function\s+\w+|^export\s+(?:const|let|type|interface|class|enum)\s|^const\s|^let\s|^type\s|^interface\s|^class\s/gm;
	const marks: number[] = [];
	let m: RegExpExecArray | null = boundary.exec(source);
	while (m) {
		marks.push(m.index);
		m = boundary.exec(source);
	}
	marks.push(source.length);
	for (let i = 0; i < marks.length - 1; i++) {
		const seg = source.slice(marks[i], marks[i + 1]);
		const name = /^export\s+(?:async\s+)?function\s+(\w+)/.exec(seg);
		if (name) out.set(name[1] as string, seg);
	}
	return out;
}

function classify(body: string): FnInfo["kind"] {
	const durable =
		/\.mutateDurable\b|\.mutateCoordinated\b|withManagementUnitOfWork\(|requireCoordinated(?:Store)?\(|await\s+store\.ready\(\)/.test(
			body,
		);
	const queued = /\bstore\.mutate\(/.test(body);
	if (queued && !durable) return "queued";
	if (queued || durable) return "durable";
	return "none";
}

function deriveMutatingServices(): Map<string, FnInfo> {
	const fns = new Map<string, FnInfo>();
	const files = readdirSync(servicesDir)
		.filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
		.map((f) => join(servicesDir, f));
	files.push(
		...readdirSync(applicationDir)
			.filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
			.map((f) => join(applicationDir, f)),
	);
	files.push(authBridgePath);
	for (const file of files) {
		const source = readFileSync(file, "utf8");
		for (const [name, body] of exportedFunctionSegments(source)) {
			fns.set(name, { file, body, kind: classify(body) });
		}
	}
	// Transitive closure: a function that calls a queued mutator is itself
	// queued unless it awaits durability (store.ready / coordinated tx).
	let changed = true;
	while (changed) {
		changed = false;
		for (const info of fns.values()) {
			if (info.kind !== "none") continue;
			for (const [otherName, other] of fns) {
				if (other.kind !== "queued" && other.kind !== "durable") continue;
				if (!new RegExp(`\\b${otherName}\\(`).test(info.body)) continue;
				const escape =
					/\.mutateDurable\b|\.mutateCoordinated\b|withManagementUnitOfWork\(|requireCoordinated(?:Store)?\(|await\s+store\.ready\(\)/.test(
						info.body,
					);
				const next =
					other.kind === "queued" && !escape ? "queued" : "durable";
				if (info.kind !== next) {
					info.kind = next;
					changed = true;
				}
				if (info.kind === "queued") break;
			}
		}
	}
	return fns;
}

type SurfaceBlock = { label: string; body: string };

/** CLI: one block per `.command("name")` chain (covers grouped subcommands). */
function cliCommandBlocks(source: string): SurfaceBlock[] {
	const re = /\.command\(\s*"([^"]+)"/g;
	const hits: { name: string; index: number }[] = [];
	let m: RegExpExecArray | null = re.exec(source);
	while (m) {
		hits.push({ name: m[1] as string, index: m.index });
		m = re.exec(source);
	}
	return hits.map((hit, i) => ({
		label: hit.name,
		body: source.slice(hit.index, hits[i + 1]?.index ?? source.length),
	}));
}

/** API: one block per root or feature-router verb registration. */
function apiRouteBlocks(source: string): SurfaceBlock[] {
	const re = /^\s*(?:app|routes)?\.(get|post|patch|put|delete|all)\(\s*\n?\s*([^,\n]+)/gm;
	const hits: { label: string; index: number }[] = [];
	let m: RegExpExecArray | null = re.exec(source);
	while (m) {
		hits.push({ label: `${(m[1] as string).toUpperCase()} ${(m[2] as string).trim()}`, index: m.index });
		m = re.exec(source);
	}
	return hits.map((hit, i) => ({
		label: hit.label,
		body: source.slice(hit.index, hits[i + 1]?.index ?? source.length),
	}));
}

function queuedCallsIn(body: string, queuedNames: string[]): string[] {
	return queuedNames.filter((name) => new RegExp(`\\b${name}\\(`).test(body));
}

function lastCallIndex(body: string, names: string[]): number {
	return Math.max(...names.map((name) => body.lastIndexOf(`${name}(`)));
}

const fns = deriveMutatingServices();
const queuedNames = [...fns.entries()]
	.filter(([, info]) => info.kind === "queued")
	.map(([name]) => name);
const durableNames = [...fns.entries()]
	.filter(([, info]) => info.kind === "durable")
	.map(([name]) => name);

describe("durability structural guard (P2.2)", () => {
	it("derives a plausible mutating-service list from management sources", () => {
		// Tripwire against parser regressions: an empty or implausible derived
		// list would make the surface checks below vacuously green.
		expect(queuedNames).toContain("createUser");
		expect(queuedNames).toContain("createOrganization");
		expect(queuedNames).toContain("recordEvent");
		expect(durableNames).toContain("createApiKey");
		expect(durableNames).toContain("reserveSetupLink");
		expect(queuedNames.length).toBeGreaterThan(15);
		expect(durableNames.length).toBeGreaterThan(5);
		// Migrated in P2.2: must stay durable, not regress to queued.
		expect(durableNames).toContain("verifyPostgresBackup");
		expect(durableNames).toContain("createUserUseCase");
		expect(durableNames).toContain("updateUserUseCase");
		expect(durableNames).toContain("disableUserUseCase");
		expect(durableNames).toContain("deleteUserUseCase");
		for (const file of ["users.ts", "organizations.ts", "members.ts", "sessions.ts"]) {
			const source = readFileSync(join(applicationDir, file), "utf8");
			expect(source).toMatch(/withManagementUnitOfWork/);
			expect(source).not.toMatch(/store\.ready\(\)/);
		}
	});

	it("keeps the API-only CLI free of direct management mutations", () => {
		const source = readFileSync(cliPath, "utf8");
		const blocks = cliCommandBlocks(source);
		expect(blocks.length).toBeGreaterThan(30);
		const directCalls = blocks.flatMap((block) => [
			...queuedCallsIn(block.body, queuedNames),
			...queuedCallsIn(block.body, durableNames),
		]);
		expect(directCalls).toEqual([]);
		expect(source).toMatch(/dispatchRemoteCommand/);
		expect(source).not.toMatch(/flushStore|openStore|DATABASE_URL/);
	});

	it("every mutating API route awaits store.ready() (or is durable-only) before responding", () => {
		const sources = [
			{ file: "server.ts", source: readFileSync(apiPath, "utf8") },
			...readdirSync(apiRoutesDir)
				.filter((file) => file.endsWith(".ts"))
				.map((file) => ({ file: `routes/${file}`, source: readFileSync(join(apiRoutesDir, file), "utf8") })),
		];
		const blocks = sources.flatMap(({ file, source }) =>
			apiRouteBlocks(source).map((block) => ({ ...block, label: `${file}: ${block.label}` })),
		);
		expect(blocks.length).toBeGreaterThan(20);

		const failures: string[] = [];
		let mutatingRoutes = 0;
		for (const block of blocks) {
			const calls = queuedCallsIn(block.body, queuedNames);
			if (calls.length === 0) continue;
			mutatingRoutes += 1;
			const last = lastCallIndex(block.body, calls);
			const readyAt = block.body.indexOf("await store.ready()", last);
			if (readyAt === -1) {
				failures.push(
					`API route "${block.label}" calls ${calls.join(", ")} but does not await store.ready() afterwards — the response could claim success for a write that then fails`,
				);
			}
		}
		expect(mutatingRoutes).toBeGreaterThan(5);
		expect(failures).toEqual([]);
	});
});
