import { assembleManagementOperationRegistry } from "./assemble.js";
import { AUTHORIZATION_OPERATION_SCHEMAS } from "./authorization.js";
import { DATA_OPERATION_SCHEMAS } from "./data-operations.js";
import { DELIVERY_OPERATION_SCHEMAS } from "./delivery.js";
import { ENTERPRISE_OPERATION_SCHEMAS } from "./enterprise.js";
import { ENVIRONMENT_OPERATION_SCHEMAS } from "./environments.js";
import { EVENTS_IDENTITY_OPERATION_SCHEMAS } from "./events-identity.js";
import { OPERATION_METADATA } from "./operation-metadata.js";
import { POLICY_CONFIG_OPERATION_SCHEMAS } from "./policy-config.js";
import { PROJECT_OPERATION_SCHEMAS } from "./projects.js";
import { PRODUCT_PRESENTATION_OPERATION_SCHEMAS } from "./product-presentation.js";
import { RESOURCE_OPERATION_SCHEMAS } from "./resources.js";
import { SCHEMA_OPERATION_SCHEMAS } from "./schema-operations.js";
import { SYSTEM_OPERATION_SCHEMAS } from "./system.js";

const OPERATION_SCHEMA_DOMAINS = [
	SYSTEM_OPERATION_SCHEMAS,
	PROJECT_OPERATION_SCHEMAS,
	PRODUCT_PRESENTATION_OPERATION_SCHEMAS,
	ENVIRONMENT_OPERATION_SCHEMAS,
	EVENTS_IDENTITY_OPERATION_SCHEMAS,
	AUTHORIZATION_OPERATION_SCHEMAS,
	ENTERPRISE_OPERATION_SCHEMAS,
	DELIVERY_OPERATION_SCHEMAS,
	POLICY_CONFIG_OPERATION_SCHEMAS,
	DATA_OPERATION_SCHEMAS,
	SCHEMA_OPERATION_SCHEMAS,
	RESOURCE_OPERATION_SCHEMAS,
] as const;

/**
 * The single browser-safe, complete Management API descriptor surface.
 * Operation metadata provides HTTP facts; domain schemas provide the public
 * semantic input/output types; the assembler verifies their exact coverage.
 */
export const MANAGEMENT_OPERATION_REGISTRY = assembleManagementOperationRegistry(
	OPERATION_METADATA,
	OPERATION_SCHEMA_DOMAINS,
);

export type ManagementOperationRegistry = typeof MANAGEMENT_OPERATION_REGISTRY;
