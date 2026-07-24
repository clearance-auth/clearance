import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { emptySnapshot } from "../store/snapshot.js";
import type {
	ProductAuthDomainView,
	ProductPresentationRepository,
} from "../store/product-presentation-authority.js";
import type { ManagementStore } from "../store/types.js";
import {
	applyProductSenderForManagement,
	createProductDomainForManagement,
	getProductTemplateForManagement,
	planProductTemplateForManagement,
	planProductSenderForManagement,
	verifyProductDomainForManagement,
} from "./product-presentation.js";

describe("normalized product presentation authority", () => {
	it("persists an owned sender with a scoped CAS version and redacted audit metadata", async () => {
		const scope = { projectId: "project_sender", environmentId: "env_sender" };
		let sender: import("../store/product-presentation-authority.js").ProductEmailSenderView | null = null;
		const audits: unknown[] = [];
		const domain: ProductAuthDomainView = { origin: "https://auth.example.com", hostname: "auth.example.com", dnsName: "_clearance.auth.example.com", state: "verified", version: 2, verifiedAt: "2026-07-24T00:00:00.000Z", updatedAt: "2026-07-24T00:00:00.000Z" };
		const repository = {
			async getSender() { return sender; },
			async listDomains() { return [domain]; },
			async getDomainForUpdate() { return { ...domain, challengeDigest: Buffer.alloc(32) }; },
			async replaceSender(_scope: typeof scope, input: { displayName: string; address: string; domain: string; expectedVersion: number }) {
				if ((sender?.version ?? 0) !== input.expectedVersion) return null;
				sender = { displayName: input.displayName, address: input.address, domain: input.domain, version: input.expectedVersion + 1, updatedAt: "2026-07-24T00:01:00.000Z" };
				return sender;
			},
		} as unknown as ProductPresentationRepository;
		const snapshot = emptySnapshot({ storeBackend: "postgres" });
		const store = { backend: "postgres", productPresentation: repository, snapshot, mutateCoordinated: async (fn: (context: unknown) => unknown) => fn({ data: snapshot, productPresentation: repository, appendAudit: (input: unknown) => { audits.push(structuredClone(input)); return input; } }) } as unknown as ManagementStore;
		const context = { scope, actor: "operator:test", source: "api" as const, correlationId: "corr_sender" };
		const plan = await planProductSenderForManagement(store, context, { displayName: "Clearance", address: "security@auth.example.com" });
		expect(plan).toMatchObject({ expectedVersion: 0, wouldChange: true, candidate: { domain: "auth.example.com", version: 1 } });
		const dry = await applyProductSenderForManagement(store, context, { displayName: "Clearance", address: "security@auth.example.com", expectedVersion: 0 });
		expect(dry).toMatchObject({ dryRun: true, result: { wouldChange: true } });
		expect(sender).toBeNull();
		const applied = await applyProductSenderForManagement(store, context, { displayName: "Clearance", address: "security@auth.example.com", expectedVersion: 0, confirm: true });
		expect(applied).toMatchObject({ dryRun: false, result: { changed: true, version: 1, candidate: { address: "security@auth.example.com" } } });
		expect(JSON.stringify(audits)).not.toContain("security@auth.example.com");
	});

	it("issues a one-time DNS value, persists only its digest, verifies observed DNS, and audits sanitized metadata", async () => {
		const scope = { projectId: "project_product", environmentId: "env_product" };
		let storedDigest: Buffer | null = null;
		let domain: ProductAuthDomainView | null = null;
		const audits: unknown[] = [];
		const repository = {
			async listDomains() {
				return domain ? [domain] : [];
			},
			async createDomain(
				_scope: typeof scope,
				input: {
					origin: string;
					hostname: string;
					dnsName: string;
					challengeDigest: Buffer;
				},
			) {
				if (domain) return null;
				storedDigest = Buffer.from(input.challengeDigest);
				domain = {
					origin: input.origin,
					hostname: input.hostname,
					dnsName: input.dnsName,
					state: "pending",
					version: 1,
					verifiedAt: null,
					updatedAt: "2026-07-24T00:00:00.000Z",
				};
				return domain;
			},
			async getDomainForUpdate() {
				return domain && storedDigest
					? { ...domain, challengeDigest: Buffer.from(storedDigest) }
					: null;
			},
			async setDomainState(
				_scope: typeof scope,
				_origin: string,
				_expectedVersion: number,
				state: ProductAuthDomainView["state"],
			) {
				if (!domain) return null;
				domain = {
					...domain,
					state,
					version: domain.version + 1,
					verifiedAt: "2026-07-24T00:01:00.000Z",
				};
				return domain;
			},
		} as unknown as ProductPresentationRepository;
		const snapshot = emptySnapshot({ storeBackend: "postgres" });
		const store = {
			backend: "postgres",
			productPresentation: repository,
			snapshot,
			mutateCoordinated: async (fn: (context: unknown) => unknown) =>
				fn({
					data: snapshot,
					productPresentation: repository,
					appendAudit: (input: unknown) => {
						audits.push(structuredClone(input));
						return input;
					},
				}),
		} as unknown as ManagementStore;
		const context = {
			scope,
			actor: "operator:test",
			source: "api" as const,
			correlationId: "corr_product",
		};

		const created = await createProductDomainForManagement(store, context, {
			origin: "https://auth.example.com",
		});
		expect("dnsChallenge" in created).toBe(true);
		if (!("dnsChallenge" in created)) throw new Error("expected one-time challenge");
		expect(created.dnsChallenge.name).toBe("_clearance.auth.example.com");
		expect(storedDigest).toEqual(
			createHash("sha256").update(created.dnsChallenge.value).digest(),
		);
		expect(storedDigest?.toString("utf8")).not.toContain(
			created.dnsChallenge.value,
		);

		const replay = await createProductDomainForManagement(store, context, {
			origin: "https://auth.example.com",
		});
		expect(replay).toMatchObject({
			challengeAlreadyIssued: true,
			oneTimeSecretsOmitted: ["dnsChallenge.value"],
		});
		const priorTarget = process.env.CLEARANCE_CUSTOM_DOMAIN_TARGET;
		process.env.CLEARANCE_CUSTOM_DOMAIN_TARGET = "edge.clearance.example";
		let verified: Awaited<ReturnType<typeof verifyProductDomainForManagement>>;
		try {
			verified = await verifyProductDomainForManagement(
				store,
				context,
				{ origin: "https://auth.example.com" },
				{ resolveTxt: async () => [[created.dnsChallenge.value]], resolveCname: async () => ["edge.clearance.example"] },
			);
		} finally {
			if (priorTarget === undefined) delete process.env.CLEARANCE_CUSTOM_DOMAIN_TARGET;
			else process.env.CLEARANCE_CUSTOM_DOMAIN_TARGET = priorTarget;
		}
		expect(verified).toMatchObject({
			operation: "verify",
			wouldChange: true,
			domain: { state: "verified", version: 2 },
		});
		expect(JSON.stringify(audits)).not.toContain(created.dnsChallenge.value);
		expect(audits).toHaveLength(2);
	});

	it("allows only durable delivery template variables and defaults verification to its queued URL", async () => {
		const scope = { projectId: "project_templates", environmentId: "env_templates" };
		const snapshot = emptySnapshot({ storeBackend: "postgres" });
		const store = {
			backend: "postgres",
			snapshot,
			productPresentation: { async getTemplate() { return null; } },
			mutateCoordinated: async (fn: (context: unknown) => unknown) => fn({ data: snapshot }),
		} as unknown as ManagementStore;
		const context = { scope, actor: "operator:test", source: "api" as const, correlationId: "corr_templates" };
		const verification = await getProductTemplateForManagement(store, context, { kind: "verification" });
		expect(verification.template).toMatchObject({
			plainText: "Verify your email: {{verification_url}}",
			html: "<p>Verify your email: {{verification_url}}</p>",
			variables: ["verification_url"],
		});
		const candidates = await Promise.all([
			planProductTemplateForManagement(store, context, { kind: "verification", subject: "{{product_name}}", plainText: "{{user_name}} {{verification_url}}", html: "<p>{{verification_url}}</p>" }),
			planProductTemplateForManagement(store, context, { kind: "password-reset", subject: "{{product_name}}", plainText: "{{user_name}} {{reset_url}}", html: "<p>{{reset_url}}</p>" }),
			planProductTemplateForManagement(store, context, { kind: "email-change", subject: "{{product_name}}", plainText: "{{user_name}} {{email_change_url}}", html: "<p>{{email_change_url}}</p>" }),
			planProductTemplateForManagement(store, context, { kind: "invitation", subject: "{{product_name}}", plainText: "{{invitation_url}} {{inviter_name}} {{organization_name}} {{role}}", html: "<p>{{role}}</p>" }),
		]);
		expect(candidates.map((candidate) => candidate.candidate.variables)).toEqual([
			["product_name", "user_name", "verification_url"],
			["product_name", "reset_url", "user_name"],
			["email_change_url", "product_name", "user_name"],
			["invitation_url", "inviter_name", "organization_name", "product_name", "role"],
		]);
		await expect(planProductTemplateForManagement(store, context, { kind: "verification", subject: "Code", plainText: "{{code}}", html: "<p>{{code}}</p>" }))
			.rejects.toMatchObject({ code: "PRODUCT_TEMPLATE_VARIABLE_INVALID" });
	});
});
