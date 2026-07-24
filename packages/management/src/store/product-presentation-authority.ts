import type { ResourceScope } from "../services/scope.js";
import type { ManagementCoordinatedQuery } from "./types.js";
import type { StoreV2TableNames } from "./store-v2-schema.js";

export const PRODUCT_EMAIL_TEMPLATE_KINDS = [
	"verification",
	"password-reset",
	"invitation",
	"email-change",
] as const;

export type ProductEmailTemplateKind =
	(typeof PRODUCT_EMAIL_TEMPLATE_KINDS)[number];

export type ProductPresentationView = Readonly<{
	productLabel: string;
	homeLabel: string;
	accentColor: string;
	logoUrl: string | null;
	version: number;
	updatedAt: string | null;
}>;

export type ProductEmailSenderView = Readonly<{
	displayName: string;
	address: string;
	domain: string;
	version: number;
	updatedAt: string | null;
}>;

export type ProductAuthDomainState =
	| "pending"
	| "verified"
	| "active"
	| "disabled";

export type ProductAuthDomainView = Readonly<{
	origin: string;
	hostname: string;
	dnsName: string;
	state: ProductAuthDomainState;
	version: number;
	verifiedAt: string | null;
	updatedAt: string;
}>;

/** Server-resolved hosted authority; scope comes only from the active claim. */
export type ProductHostedDomainView = Readonly<{
	origin: string;
	hostname: string;
	scope: ResourceScope;
	domainVersion: number;
	presentation: ProductPresentationView;
}>;

export type ProductEmailTemplateView = Readonly<{
	kind: ProductEmailTemplateKind;
	subject: string;
	plainText: string;
	html: string;
	variables: string[];
	version: number;
	hash: string;
	updatedAt: string | null;
}>;

type Query = ManagementCoordinatedQuery;

const DEFAULT_PRESENTATION: ProductPresentationView = Object.freeze({
	productLabel: "Clearance",
	homeLabel: "Home",
	accentColor: "#2563eb",
	logoUrl: null,
	version: 0,
	updatedAt: null,
});

function iso(value: unknown): string {
	if (value instanceof Date) return value.toISOString();
	if (typeof value === "string") return new Date(value).toISOString();
	throw new Error("PRODUCT_PRESENTATION_TIMESTAMP_INVALID");
}

function number(value: unknown): number {
	const parsed = typeof value === "number" ? value : Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 0) {
		throw new Error("PRODUCT_PRESENTATION_VERSION_INVALID");
	}
	return parsed;
}

function presentation(row: Record<string, unknown> | undefined): ProductPresentationView {
	if (!row) return DEFAULT_PRESENTATION;
	return {
		productLabel: String(row.product_label),
		homeLabel: String(row.home_label),
		accentColor: String(row.accent_color),
		logoUrl: row.logo_url === null || row.logo_url === undefined ? null : String(row.logo_url),
		version: number(row.version),
		updatedAt: iso(row.updated_at),
	};
}

function sender(row: Record<string, unknown> | undefined): ProductEmailSenderView | null {
	if (!row) return null;
	return { displayName: String(row.display_name), address: String(row.address), domain: String(row.domain), version: number(row.version), updatedAt: iso(row.updated_at) };
}

function domain(row: Record<string, unknown>): ProductAuthDomainView {
	const state = String(row.state);
	if (!["pending", "verified", "active", "disabled"].includes(state)) {
		throw new Error("PRODUCT_DOMAIN_STATE_INVALID");
	}
	return {
		origin: String(row.origin),
		hostname: String(row.hostname),
		dnsName: String(row.dns_name),
		state: state as ProductAuthDomainState,
		version: number(row.version),
		verifiedAt: row.verified_at === null ? null : iso(row.verified_at),
		updatedAt: iso(row.updated_at),
	};
}

function template(row: Record<string, unknown> | undefined): ProductEmailTemplateView | null {
	if (!row) return null;
	const kind = String(row.kind);
	if (!(PRODUCT_EMAIL_TEMPLATE_KINDS as readonly string[]).includes(kind)) {
		throw new Error("PRODUCT_TEMPLATE_KIND_INVALID");
	}
	if (!Array.isArray(row.variables) || !row.variables.every((item) => typeof item === "string")) {
		throw new Error("PRODUCT_TEMPLATE_VARIABLES_INVALID");
	}
	return {
		kind: kind as ProductEmailTemplateKind,
		subject: String(row.subject),
		plainText: String(row.plain_text),
		html: String(row.html ?? ""),
		variables: [...row.variables].sort(),
		version: number(row.version),
		hash: String(row.content_hash),
		updatedAt: iso(row.updated_at),
	};
}

export class ProductPresentationRepository {
	constructor(
		private readonly query: Query,
		private readonly tables: StoreV2TableNames,
	) {}

	async getPresentation(scope: ResourceScope): Promise<ProductPresentationView> {
		const result = await this.query(
			`SELECT product_label, home_label, accent_color, logo_url, version, updated_at
			 FROM ${this.tables.productPresentations}
			 WHERE project_id = $1 AND environment_id = $2`,
			[scope.projectId, scope.environmentId],
		);
		return presentation(result.rows[0]);
	}

	async resolveActiveHostedDomain(
		hostname: string,
	): Promise<ProductHostedDomainView | null> {
		const result = await this.query(
			`SELECT auth_domain.origin, auth_domain.hostname, auth_domain.project_id, auth_domain.environment_id,
			        auth_domain.version AS domain_version,
			        presentation.product_label, presentation.home_label,
			        presentation.accent_color, presentation.logo_url,
			        presentation.version, presentation.updated_at
			 FROM ${this.tables.productAuthDomains} AS auth_domain
			 LEFT JOIN ${this.tables.productPresentations} AS presentation
			   ON presentation.project_id = auth_domain.project_id
			  AND presentation.environment_id = auth_domain.environment_id
			 WHERE auth_domain.hostname = $1 AND auth_domain.state = 'active'`,
			[hostname.toLowerCase()],
		);
		const row = result.rows[0];
		if (!row) return null;
		return {
			origin: String(row.origin),
			hostname: String(row.hostname),
			scope: { projectId: String(row.project_id), environmentId: String(row.environment_id) },
			domainVersion: number(row.domain_version),
			presentation: row.product_label === null || row.product_label === undefined
				? DEFAULT_PRESENTATION
				: presentation(row),
		};
	}

	async replacePresentation(
		scope: ResourceScope,
		input: Omit<ProductPresentationView, "version" | "updatedAt"> & {
			expectedVersion: number;
		},
	): Promise<ProductPresentationView | null> {
		const result = await this.query(
			`INSERT INTO ${this.tables.productPresentations}
				(project_id, environment_id, product_label, home_label, accent_color, logo_url, version, updated_at)
			 SELECT $1, $2, $3, $4, $5, $6, 1, now()
			 WHERE $7 = 0
			 ON CONFLICT (project_id, environment_id) DO UPDATE
			 SET product_label = EXCLUDED.product_label,
			     home_label = EXCLUDED.home_label,
			     accent_color = EXCLUDED.accent_color,
			     logo_url = EXCLUDED.logo_url,
			     version = ${this.tables.productPresentations}.version + 1,
			     updated_at = now()
			 WHERE ${this.tables.productPresentations}.version = $7
			 RETURNING product_label, home_label, accent_color, logo_url, version, updated_at`,
			[
				scope.projectId,
				scope.environmentId,
				input.productLabel,
				input.homeLabel,
				input.accentColor,
				input.logoUrl,
				input.expectedVersion,
			],
		);
		return result.rows[0] ? presentation(result.rows[0]) : null;
	}

	async getSender(scope: ResourceScope): Promise<ProductEmailSenderView | null> {
		const result = await this.query(`SELECT display_name, address, domain, version, updated_at FROM ${this.tables.productEmailSenders} WHERE project_id = $1 AND environment_id = $2`, [scope.projectId, scope.environmentId]);
		return sender(result.rows[0]);
	}

	async replaceSender(scope: ResourceScope, input: Omit<ProductEmailSenderView, "version" | "updatedAt"> & { expectedVersion: number }): Promise<ProductEmailSenderView | null> {
		const result = await this.query(`INSERT INTO ${this.tables.productEmailSenders} (project_id, environment_id, display_name, address, domain, version, updated_at) SELECT $1, $2, $3, $4, $5, 1, now() WHERE $6 = 0 ON CONFLICT (project_id, environment_id) DO UPDATE SET display_name = EXCLUDED.display_name, address = EXCLUDED.address, domain = EXCLUDED.domain, version = ${this.tables.productEmailSenders}.version + 1, updated_at = now() WHERE ${this.tables.productEmailSenders}.version = $6 RETURNING display_name, address, domain, version, updated_at`, [scope.projectId, scope.environmentId, input.displayName, input.address, input.domain, input.expectedVersion]);
		return sender(result.rows[0]);
	}

	async listDomains(scope: ResourceScope): Promise<ProductAuthDomainView[]> {
		const result = await this.query(
			`SELECT origin, hostname, dns_name, state, version, verified_at, updated_at
			 FROM ${this.tables.productAuthDomains}
			 WHERE project_id = $1 AND environment_id = $2
			 ORDER BY origin ASC`,
			[scope.projectId, scope.environmentId],
		);
		return result.rows.map(domain);
	}

	async getDomainForUpdate(
		scope: ResourceScope,
		origin: string,
	): Promise<(ProductAuthDomainView & { challengeDigest: Buffer }) | null> {
		const result = await this.query(
			`SELECT origin, hostname, dns_name, state, version, verified_at, updated_at,
			        challenge_digest
			 FROM ${this.tables.productAuthDomains}
			 WHERE project_id = $1 AND environment_id = $2 AND origin = $3
			 FOR UPDATE`,
			[scope.projectId, scope.environmentId, origin],
		);
		const row = result.rows[0];
		if (!row || !Buffer.isBuffer(row.challenge_digest)) return null;
		return { ...domain(row), challengeDigest: Buffer.from(row.challenge_digest) };
	}

	async createDomain(
		scope: ResourceScope,
		input: {
			origin: string;
			hostname: string;
			dnsName: string;
			challengeDigest: Buffer;
		},
	): Promise<ProductAuthDomainView | null> {
		const result = await this.query(
			`INSERT INTO ${this.tables.productAuthDomains}
				(project_id, environment_id, origin, hostname, dns_name, challenge_digest,
				 state, version, verified_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, 'pending', 1, NULL, now())
				ON CONFLICT (project_id, environment_id, origin) DO NOTHING
				RETURNING origin, hostname, dns_name, state, version, verified_at, updated_at`,
			[
				scope.projectId,
				scope.environmentId,
				input.origin,
				input.hostname,
				input.dnsName,
				input.challengeDigest,
			],
		);
		return result.rows[0] ? domain(result.rows[0]) : null;
	}

	async reissueDisabledDomain(
		scope: ResourceScope,
		origin: string,
		expectedVersion: number,
		challengeDigest: Buffer,
	): Promise<ProductAuthDomainView | null> {
		const result = await this.query(
			`UPDATE ${this.tables.productAuthDomains}
			 SET challenge_digest = $4,
			     state = 'pending',
			     version = version + 1,
			     verified_at = NULL,
			     updated_at = now()
			 WHERE project_id = $1 AND environment_id = $2 AND origin = $3
			   AND version = $5 AND state = 'disabled'
			 RETURNING origin, hostname, dns_name, state, version, verified_at, updated_at`,
			[scope.projectId, scope.environmentId, origin, challengeDigest, expectedVersion],
		);
		return result.rows[0] ? domain(result.rows[0]) : null;
	}

	async setDomainState(
		scope: ResourceScope,
		origin: string,
		expectedVersion: number,
		state: ProductAuthDomainState,
	): Promise<ProductAuthDomainView | null> {
		const result = await this.query(
			`UPDATE ${this.tables.productAuthDomains}
			 SET state = $4,
			     version = version + 1,
			     verified_at = CASE
			       WHEN $4 = 'verified' AND verified_at IS NULL THEN now()
			       ELSE verified_at
			     END,
			     updated_at = now()
			 WHERE project_id = $1 AND environment_id = $2
			   AND origin = $3 AND version = $5
			 RETURNING origin, hostname, dns_name, state, version, verified_at, updated_at`,
			[
				scope.projectId,
				scope.environmentId,
				origin,
				state,
				expectedVersion,
			],
		);
		return result.rows[0] ? domain(result.rows[0]) : null;
	}

	async getTemplate(
		scope: ResourceScope,
		kind: ProductEmailTemplateKind,
	): Promise<ProductEmailTemplateView | null> {
		const result = await this.query(
			`SELECT kind, subject, plain_text, html, variables, version, content_hash, updated_at
			 FROM ${this.tables.productEmailTemplates}
			 WHERE project_id = $1 AND environment_id = $2 AND kind = $3`,
			[scope.projectId, scope.environmentId, kind],
		);
		return template(result.rows[0]);
	}

	async replaceTemplate(
		scope: ResourceScope,
		input: Omit<ProductEmailTemplateView, "updatedAt"> & {
			expectedVersion: number;
		},
	): Promise<ProductEmailTemplateView | null> {
		const result = await this.query(
			`INSERT INTO ${this.tables.productEmailTemplates}
				(project_id, environment_id, kind, subject, plain_text, html, variables,
				 version, content_hash, updated_at)
			 SELECT $1, $2, $3, $4, $5, $6, $7::jsonb, 1, $8, now()
			 WHERE $9 = 0
			 ON CONFLICT (project_id, environment_id, kind) DO UPDATE
			 SET subject = EXCLUDED.subject,
			     plain_text = EXCLUDED.plain_text,
			     html = EXCLUDED.html,
			     variables = EXCLUDED.variables,
			     version = ${this.tables.productEmailTemplates}.version + 1,
			     content_hash = EXCLUDED.content_hash,
			     updated_at = now()
			 WHERE ${this.tables.productEmailTemplates}.version = $9
			 RETURNING kind, subject, plain_text, html, variables, version, content_hash, updated_at`,
			[
				scope.projectId,
				scope.environmentId,
				input.kind,
				input.subject,
				input.plainText,
				input.html,
				JSON.stringify(input.variables),
				input.hash,
				input.expectedVersion,
			],
		);
		return template(result.rows[0]);
	}
}

export type ProductPresentationAuthorityReader = Pick<
	ProductPresentationRepository,
	"getPresentation" | "getSender" | "listDomains" | "getTemplate" | "resolveActiveHostedDomain"
>;
