/**
 * Shared availability gate for Postgres-backed suites.
 *
 * Default behavior: probe the database and let the suite skip when it is
 * unreachable (casual local runs stay green without Docker).
 *
 * Tripwire behavior: when CLEARANCE_REQUIRE_PG_TESTS=1 (set by
 * scripts/test-with-postgres.sh and the canonical verify-real.sh gate), an
 * unreachable database THROWS at module load instead of skipping. The
 * 2026-07-13 audit found the canonical gate had never executed these suites
 * because they skipped silently; under the tripwire, silent skip is
 * impossible. New Pg suites must gate through this helper, not an inline
 * describe.skipIf probe, so they inherit the tripwire by construction.
 */
import pg from "pg";

export async function gatePostgresSuite(
	databaseUrl: string,
	suiteName: string,
): Promise<boolean> {
	const pool = new pg.Pool({
		connectionString: databaseUrl,
		connectionTimeoutMillis: 2000,
	});
	let available = false;
	try {
		await pool.query("select 1");
		available = true;
	} catch {
		available = false;
	} finally {
		await pool.end().catch(() => undefined);
	}
	if (!available && process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") {
		const redacted = databaseUrl.replace(/\/\/[^@]*@/, "//<redacted>@");
		throw new Error(
			`${suiteName}: CLEARANCE_REQUIRE_PG_TESTS=1 but Postgres is unreachable at ${redacted}. ` +
				"The Pg suites must run, not skip, under the canonical gate — start the database " +
				"(scripts/test-with-postgres.sh) or unset CLEARANCE_REQUIRE_PG_TESTS.",
		);
	}
	return available;
}
