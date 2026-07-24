import { resolveCname, resolveTxt } from "node:dns/promises";
import {
	ClearanceError,
	PRODUCT_DOMAIN_OPERATIONS,
	PRODUCT_PRESENTATION_OPERATIONS,
	PRODUCT_SENDER_OPERATIONS,
	PRODUCT_TEMPLATE_OPERATIONS,
	activateProductDomainForManagement,
	applyProductPresentationForManagement,
	applyProductSenderForManagement,
	applyProductTemplateForManagement,
	createProductDomainForManagement,
	disableProductDomainForManagement,
	getProductPresentationForManagement,
	getProductSenderForManagement,
	getProductSenderReadinessForManagement,
	getProductTemplateForManagement,
	listProductDomainsForManagement,
	planProductPresentationForManagement,
	planProductSenderForManagement,
	planProductTemplateForManagement,
	reissueProductDomainForManagement,
	verifyProductDomainForManagement,
	type ProductDomainResolver,
	type ProductEmailTemplateKind,
} from "@clearance/management";
import { Hono, type Context } from "hono";
import { apiOperationContext, type ScopedRouteDependencies } from "./shared.js";

function inputError(stage: string, message: string, remediation: string): ClearanceError {
	return new ClearanceError({
		code: "PRODUCT_PRESENTATION_INPUT_INVALID",
		message,
		stage,
		status: 400,
		remediation,
	});
}

async function objectBody(
	context: Context,
	stage: string,
	allowed: readonly string[],
): Promise<Record<string, unknown>> {
	let parsed: unknown;
	try {
		parsed = await context.req.json();
	} catch {
		throw inputError(stage, "A JSON request body is required.", "Send one JSON object.");
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw inputError(stage, "The request body must be a JSON object.", "Send one JSON object.");
	}
	const body = parsed as Record<string, unknown>;
	const unexpected = Object.keys(body).filter((key) => !allowed.includes(key));
	if (unexpected.length > 0) {
		throw inputError(
			stage,
			`Unexpected request fields: ${unexpected.sort().join(", ")}.`,
			"Send only fields declared by the canonical operation.",
		);
	}
	return body;
}

function string(body: Record<string, unknown>, name: string, stage: string): string {
	const value = body[name];
	if (typeof value !== "string") {
		throw inputError(stage, `${name} is required.`, `Send ${name} as a JSON string.`);
	}
	return value;
}

function version(body: Record<string, unknown>, stage: string): number {
	const value = body.expectedVersion;
	if (!Number.isSafeInteger(value) || (value as number) < 0) {
		throw inputError(
			stage,
			"expectedVersion must be a non-negative integer.",
			"Use the expectedVersion returned by get or plan.",
		);
	}
	return value as number;
}

function boolean(body: Record<string, unknown>, name: string, stage: string): boolean {
	const value = body[name];
	if (value === undefined) return false;
	if (typeof value !== "boolean") {
		throw inputError(stage, `${name} must be a JSON boolean.`, `Send ${name} as true or false.`);
	}
	return value;
}

function kind(value: unknown, stage: string): ProductEmailTemplateKind {
	if (value !== "verification" && value !== "password-reset" && value !== "invitation" && value !== "email-change") {
		throw inputError(
			stage,
			"kind must be verification, password-reset, invitation, or email-change.",
			"Use one allowlisted email template kind.",
		);
	}
	return value;
}

const defaultResolver: ProductDomainResolver = {
	resolveTxt: (name) => resolveTxt(name),
	resolveCname: (name) => resolveCname(name),
};

export function registerProductPresentationRoutes(
	{
		storeForRequest,
		scopeForRequest,
		handleError,
	}: ScopedRouteDependencies,
	resolver: ProductDomainResolver = defaultResolver,
) {
	const routes = new Hono();

	routes.get(PRODUCT_PRESENTATION_OPERATIONS.get.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(
				await getProductPresentationForManagement(
					store,
					apiOperationContext(scope, c),
				),
			);
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(PRODUCT_PRESENTATION_OPERATIONS.plan.http.path, async (c) => {
		try {
			const stage = PRODUCT_PRESENTATION_OPERATIONS.plan.id;
			const body = await objectBody(c, stage, [
				"productLabel",
				"homeLabel",
				"accentColor",
				"logoUrl",
			]);
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(
				await planProductPresentationForManagement(
					store,
					apiOperationContext(scope, c),
					{
						productLabel: string(body, "productLabel", stage),
						homeLabel: string(body, "homeLabel", stage),
					accentColor: string(body, "accentColor", stage),
					logoUrl: body.logoUrl === undefined || body.logoUrl === null ? body.logoUrl as null | undefined : string(body, "logoUrl", stage),
					},
				),
			);
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.patch(PRODUCT_PRESENTATION_OPERATIONS.apply.http.path, async (c) => {
		try {
			const stage = PRODUCT_PRESENTATION_OPERATIONS.apply.id;
			const body = await objectBody(c, stage, [
				"productLabel",
				"homeLabel",
				"accentColor",
				"logoUrl",
				"expectedVersion",
				"dryRun",
				"confirm",
			]);
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(
				await applyProductPresentationForManagement(
					store,
					apiOperationContext(scope, c),
					{
						productLabel: string(body, "productLabel", stage),
						homeLabel: string(body, "homeLabel", stage),
						accentColor: string(body, "accentColor", stage),
						logoUrl: body.logoUrl === undefined || body.logoUrl === null ? body.logoUrl as null | undefined : string(body, "logoUrl", stage),
						expectedVersion: version(body, stage),
						dryRun: boolean(body, "dryRun", stage),
						confirm: boolean(body, "confirm", stage),
					},
				),
			);
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.get(PRODUCT_DOMAIN_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(
				await listProductDomainsForManagement(store, apiOperationContext(scope, c)),
			);
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(PRODUCT_DOMAIN_OPERATIONS.create.http.path, async (c) => {
		try {
			const stage = PRODUCT_DOMAIN_OPERATIONS.create.id;
			const body = await objectBody(c, stage, ["origin"]);
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			c.header("cache-control", "no-store");
			c.header("pragma", "no-cache");
			return c.json(
				await createProductDomainForManagement(
					store,
					apiOperationContext(scope, c),
					{ origin: string(body, "origin", stage) },
				),
				201,
			);
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(PRODUCT_DOMAIN_OPERATIONS.reissue.http.path, async (c) => {
		try {
			const stage = PRODUCT_DOMAIN_OPERATIONS.reissue.id;
			const body = await objectBody(c, stage, ["origin", "expectedVersion"]);
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			c.header("cache-control", "no-store");
			c.header("pragma", "no-cache");
			return c.json(
				await reissueProductDomainForManagement(
					store,
					apiOperationContext(scope, c),
					{ origin: string(body, "origin", stage), expectedVersion: version(body, stage) },
				),
			);
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(PRODUCT_DOMAIN_OPERATIONS.verify.http.path, async (c) => {
		try {
			const stage = PRODUCT_DOMAIN_OPERATIONS.verify.id;
			const body = await objectBody(c, stage, ["origin"]);
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(
				await verifyProductDomainForManagement(
					store,
					apiOperationContext(scope, c),
					{ origin: string(body, "origin", stage) },
					resolver,
				),
			);
		} catch (error) {
			return handleError(c, error);
		}
	});

	for (const [operation, descriptor, control] of [
		["activate", PRODUCT_DOMAIN_OPERATIONS.activate, activateProductDomainForManagement],
		["disable", PRODUCT_DOMAIN_OPERATIONS.disable, disableProductDomainForManagement],
	] as const) {
		routes.post(descriptor.http.path, async (c) => {
			try {
				const body = await objectBody(c, descriptor.id, [
					"origin",
					"expectedVersion",
					"dryRun",
					"confirm",
				]);
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				return c.json(
					await control(store, apiOperationContext(scope, c), {
						origin: string(body, "origin", descriptor.id),
						expectedVersion: version(body, descriptor.id),
						dryRun: boolean(body, "dryRun", descriptor.id),
						confirm: boolean(body, "confirm", descriptor.id),
					}),
				);
			} catch (error) {
				return handleError(c, error);
			}
		});
	void operation;
	}

	routes.get(PRODUCT_SENDER_OPERATIONS.get.http.path, async (c) => { try { const store = await storeForRequest(); const scope = scopeForRequest(store, c); return c.json(await getProductSenderForManagement(store, apiOperationContext(scope, c))); } catch (error) { return handleError(c, error); } });
	routes.post(PRODUCT_SENDER_OPERATIONS.plan.http.path, async (c) => { try { const stage = PRODUCT_SENDER_OPERATIONS.plan.id; const body = await objectBody(c, stage, ["displayName", "address"]); const store = await storeForRequest(); const scope = scopeForRequest(store, c); return c.json(await planProductSenderForManagement(store, apiOperationContext(scope, c), { displayName: string(body, "displayName", stage), address: string(body, "address", stage) })); } catch (error) { return handleError(c, error); } });
	routes.patch(PRODUCT_SENDER_OPERATIONS.apply.http.path, async (c) => { try { const stage = PRODUCT_SENDER_OPERATIONS.apply.id; const body = await objectBody(c, stage, ["displayName", "address", "expectedVersion", "dryRun", "confirm"]); const store = await storeForRequest(); const scope = scopeForRequest(store, c); return c.json(await applyProductSenderForManagement(store, apiOperationContext(scope, c), { displayName: string(body, "displayName", stage), address: string(body, "address", stage), expectedVersion: version(body, stage), dryRun: boolean(body, "dryRun", stage), confirm: boolean(body, "confirm", stage) })); } catch (error) { return handleError(c, error); } });

	routes.get(PRODUCT_SENDER_OPERATIONS.readiness.http.path, async (c) => {
		try {
			const raw = c.req.query("staleAfterMs");
			const staleAfterMs = raw === undefined ? undefined : Number(raw);
			if (
				staleAfterMs !== undefined &&
				(!Number.isSafeInteger(staleAfterMs) || staleAfterMs < 1)
			) {
				throw inputError(
					PRODUCT_SENDER_OPERATIONS.readiness.id,
					"staleAfterMs must be a positive integer.",
					"Pass a bounded worker freshness window in milliseconds.",
				);
			}
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(
				await getProductSenderReadinessForManagement(
					store,
					apiOperationContext(scope, c),
					staleAfterMs === undefined ? {} : { staleAfterMs },
				),
			);
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.get(PRODUCT_TEMPLATE_OPERATIONS.get.http.path, async (c) => {
		try {
			const stage = PRODUCT_TEMPLATE_OPERATIONS.get.id;
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(
				await getProductTemplateForManagement(
					store,
					apiOperationContext(scope, c),
					{ kind: kind(c.req.param("kind"), stage) },
				),
			);
		} catch (error) {
			return handleError(c, error);
		}
	});

	for (const [descriptor, apply] of [
		[PRODUCT_TEMPLATE_OPERATIONS.plan, false],
		[PRODUCT_TEMPLATE_OPERATIONS.apply, true],
	] as const) {
		const handler = async (c: Context) => {
			try {
				const allowed = [
					"subject",
					"plainText", "html",
					...(apply ? ["expectedVersion", "dryRun", "confirm"] : []),
				];
				const request = await objectBody(c, descriptor.id, allowed);
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const candidate = {
					kind: kind(c.req.param("kind"), descriptor.id),
					subject: string(request, "subject", descriptor.id),
					plainText: string(request, "plainText", descriptor.id), html: string(request, "html", descriptor.id),
				};
				const result = apply
					? await applyProductTemplateForManagement(
							store,
							apiOperationContext(scope, c),
							{
								...candidate,
								expectedVersion: version(request, descriptor.id),
								dryRun: boolean(request, "dryRun", descriptor.id),
								confirm: boolean(request, "confirm", descriptor.id),
							},
						)
					: await planProductTemplateForManagement(
							store,
							apiOperationContext(scope, c),
							candidate,
						);
				return c.json(result);
			} catch (error) {
				return handleError(c, error);
			}
		};
		if (apply) routes.patch(descriptor.http.path, handler);
		else routes.post(descriptor.http.path, handler);
	}

	return routes;
}
