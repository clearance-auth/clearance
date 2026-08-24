import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import {
	archiveOrganizationAuthoritative,
	createOrganizationAuthoritative,
	initProject,
} from "../services/core.js";
import {
	commitSetupLink,
	createSetupLinkAuthoritative,
	redeemSetupLink,
	reserveSetupLink,
} from "../services/setup-links.js";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import { storeV2TableNames } from "../store/store-v2-schema.js";
import { gatePostgresSuite } from "./pg-gate.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const TABLE = `clearance_setup_links_topology_${process.pid}`;
const PREFIX = `${TABLE}_n_`;
const RACE_TABLE = `${TABLE}_race`;
const RACE_PREFIX = `${RACE_TABLE}_n_`;
const TABLES = storeV2TableNames(PREFIX);
const RACE_TABLES = storeV2TableNames(RACE_PREFIX);
const available = await gatePostgresSuite(DATABASE_URL, "setup-links-topology-pg");

describe.skipIf(!available)("setup capabilities with normalized topology authority", () => {
	const stores: PgStore[] = [];

	afterAll(async () => {
		for (const store of stores) await store.destroy().catch(() => undefined);
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			for (const table of [
				TABLES.productEmailTemplates, TABLES.productEmailSenders,
				TABLES.productAuthDomains, TABLES.productPresentations,
				`${PREFIX}events`, `${PREFIX}principals`, `${PREFIX}organizations`,
				`${PREFIX}environments`, `${PREFIX}projects`, `${PREFIX}meta`,
				`${TABLE}_principal_email`, `${TABLE}_organization_slug`,
				`${TABLE}_idempotency`, TABLE,
				RACE_TABLES.productEmailTemplates, RACE_TABLES.productEmailSenders,
				RACE_TABLES.productAuthDomains, RACE_TABLES.productPresentations,
				`${RACE_PREFIX}events`, `${RACE_PREFIX}principals`, `${RACE_PREFIX}organizations`,
				`${RACE_PREFIX}environments`, `${RACE_PREFIX}projects`, `${RACE_PREFIX}meta`,
				`${RACE_TABLE}_principal_email`, `${RACE_TABLE}_organization_slug`,
				`${RACE_TABLE}_idempotency`, RACE_TABLE,
			]) await pool.query(`DROP TABLE IF EXISTS ${table}`);
		} finally {
			await pool.end();
		}
	});

	it("rejects setup transitions after archive without consuming a reserved capability", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: TABLE,
			normalizedPrefix: PREFIX,
		});
		stores.push(store);
		const initialized = initProject(store, { name: "Setup capability topology" });
		await store.ready();
		await store.storeV2!.apply();
		await store.storeV2!.cutoverEvents();
		await store.storeV2!.cutoverTopology();
		const scope = {
			projectId: initialized.project.id,
			environmentId: initialized.environment.id,
		};
		const organization = await createOrganizationAuthoritative(store, { name: "Archived customer" });
		const reservedLink = await createSetupLinkAuthoritative(store, {
			organizationId: organization.id,
			kind: "sso",
			scope,
		});
		const untouchedLink = await createSetupLinkAuthoritative(store, {
			organizationId: organization.id,
			kind: "scim",
			scope,
		});
		const reservation = await reserveSetupLink(store, {
			token: reservedLink.token,
			kind: "sso",
			organizationId: organization.id,
		});

		await archiveOrganizationAuthoritative(store, organization.id, { scope, confirm: true });

		await expect(commitSetupLink(store, {
			token: reservedLink.token,
			kind: "sso",
			organizationId: organization.id,
			reservationId: reservation.reservationId,
			reservationFencingToken: reservation.reservationFencingToken,
		})).rejects.toMatchObject({ code: "SETUP_LINK_SCOPE" });
		await expect(redeemSetupLink(store, {
			token: untouchedLink.token,
			kind: "scim",
			organizationId: organization.id,
		})).rejects.toMatchObject({ code: "SETUP_LINK_SCOPE" });
		await expect(reserveSetupLink(store, {
			token: untouchedLink.token,
			kind: "scim",
			organizationId: organization.id,
		})).rejects.toMatchObject({ code: "SETUP_LINK_SCOPE" });

		await store.refresh();
		const held = store.snapshot.setupLinks.find((link) => link.id === reservedLink.capabilityId)!;
		const untouched = store.snapshot.setupLinks.find((link) => link.id === untouchedLink.capabilityId)!;
		expect(held).toMatchObject({
			useCount: 0,
			reservationId: reservation.reservationId,
		});
		expect(untouched.useCount).toBe(0);
		expect(untouched.redeemedAt).toBeFalsy();
	});

	it("serializes an in-flight setup reservation before a concurrent archive", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: RACE_TABLE,
			normalizedPrefix: RACE_PREFIX,
		});
		stores.push(store);
		const initialized = initProject(store, { name: "Setup lock ordering" });
		await store.ready();
		await store.storeV2!.apply();
		await store.storeV2!.cutoverEvents();
		await store.storeV2!.cutoverTopology();
		const scope = {
			projectId: initialized.project.id,
			environmentId: initialized.environment.id,
		};
		const organization = await createOrganizationAuthoritative(store, { name: "Locked customer" });
		const link = await createSetupLinkAuthoritative(store, {
			organizationId: organization.id,
			kind: "sso",
			scope,
		});
		const archiveStore = await createPgStore(DATABASE_URL, {
			tableName: RACE_TABLE,
			normalizedPrefix: RACE_PREFIX,
		});
		stores.push(archiveStore);
		await archiveStore.refresh();

		const originalCoordinated = store.mutateCoordinated!.bind(store);
		const originalTopologyMutation = archiveStore.mutateStoreV2Topology!.bind(archiveStore);
		let releaseSetupLock!: () => void;
		let signalSetupLocked!: () => void;
		let signalArchiveMutation!: () => void;
		const setupLockReleased = new Promise<void>((resolve) => { releaseSetupLock = resolve; });
		const setupLocked = new Promise<void>((resolve) => { signalSetupLocked = resolve; });
		const archiveMutationStarted = new Promise<void>((resolve) => { signalArchiveMutation = resolve; });
		let holdFirstSetupLock = true;
		let archiveCompleted = false;
		let coordinatedEntered = false;
		let topologyMutationEntered = false;
		let setupLockWasReleased = false;

		// The service receives an opaque transaction repository. Hold exactly after
		// its SELECT FOR UPDATE; the real archive below then contends on that same
		// organization row until the reservation transaction commits.
		store.mutateCoordinated = (fn) => originalCoordinated(async (context) => {
			coordinatedEntered = true;
			if (!context.topology || !holdFirstSetupLock) return fn(context);
			const lockOrganization = context.topology.lockOrganization.bind(context.topology);
			const topology = Object.create(context.topology) as typeof context.topology;
			Object.defineProperty(topology, "lockOrganization", {
				value: async (input: { scope: typeof scope; id: string }) => {
					const locked = await lockOrganization(input);
					if (holdFirstSetupLock) {
						holdFirstSetupLock = false;
						signalSetupLocked();
						await setupLockReleased;
					}
					return locked;
				},
			});
			return fn({ ...context, topology });
		});
		archiveStore.mutateStoreV2Topology = (fn) => {
			topologyMutationEntered = true;
			signalArchiveMutation();
			return originalTopologyMutation(fn);
		};

		try {
			const reservation = reserveSetupLink(store, {
				token: link.token,
				kind: "sso",
				organizationId: organization.id,
			});
			await Promise.race([
				setupLocked,
				new Promise<never>((_, reject) => setTimeout(
					() => reject(new Error(`setup lock hook was not reached (coordinated=${coordinatedEntered})`)),
					1_000,
				)),
			]);
			const archive = archiveOrganizationAuthoritative(archiveStore, organization.id, { scope, confirm: true })
				.then((result) => {
					archiveCompleted = true;
					return result;
				});
			await Promise.race([
				archiveMutationStarted,
				new Promise<never>((_, reject) => setTimeout(
					() => reject(new Error(`archive mutation did not start (topologyMutation=${topologyMutationEntered})`)),
					1_000,
				)),
			]);
			await Promise.resolve();
			expect(archiveCompleted).toBe(false);
			releaseSetupLock();
			setupLockWasReleased = true;
			const reserved = await reservation;
			await archive;

			await expect(commitSetupLink(store, {
				token: link.token,
				kind: "sso",
				organizationId: organization.id,
				reservationId: reserved.reservationId,
				reservationFencingToken: reserved.reservationFencingToken,
			})).rejects.toMatchObject({ code: "SETUP_LINK_SCOPE" });
		} finally {
			if (!setupLockWasReleased) releaseSetupLock();
			store.mutateCoordinated = originalCoordinated;
			archiveStore.mutateStoreV2Topology = originalTopologyMutation;
		}
	});
});
