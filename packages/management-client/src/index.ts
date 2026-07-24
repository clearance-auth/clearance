export {
	createBrowserManagementClient,
	createServerManagementClient,
	type BrowserManagementClientOptions,
	type FetchLike,
	type ManagementCallOptions,
	type ManagementClient,
	type ManagementResponse,
	type ServerManagementClientOptions,
} from "./client.js";
export {
	ManagementApiError,
	managementApiErrorFromResponse,
	type ManagementApiErrorInit,
	type ManagementApiProblem,
} from "./error.js";
export {
	defineOperation,
	defineOperationRegistry,
	type AnyOperationSpec,
	type ApiPath,
	type ConfirmationPolicy,
	type HttpMethod,
	type AnySchema,
	type OperationInput,
	type OperationOutput,
	type PathProjection,
	type OperationRegistry,
	type OperationSpec,
} from "./spec.js";
export { createOperationResource } from "./resources/operations.js";
export { createOrganizationMemberResource } from "./resources/organizations.js";
export {
	assembleManagementOperationRegistry,
	type OperationSchemaDomain,
	type OperationSchemaPair,
} from "./generated/assemble.js";
export { OPERATION_METADATA, type OperationMetadata } from "./generated/operation-metadata.js";
export {
	MANAGEMENT_OPERATION_REGISTRY,
	type ManagementOperationRegistry,
} from "./generated/registry.js";
export { SYSTEM_OPERATION_SCHEMAS } from "./generated/system.js";
export { PROJECT_OPERATION_SCHEMAS } from "./generated/projects.js";
export { ENVIRONMENT_OPERATION_SCHEMAS } from "./generated/environments.js";
export { EVENTS_IDENTITY_OPERATION_SCHEMAS } from "./generated/events-identity.js";
export { AUTHORIZATION_OPERATION_SCHEMAS } from "./generated/authorization.js";
export { ENTERPRISE_OPERATION_SCHEMAS } from "./generated/enterprise.js";
export { DELIVERY_OPERATION_SCHEMAS } from "./generated/delivery.js";
export { POLICY_CONFIG_OPERATION_SCHEMAS } from "./generated/policy-config.js";
export { DATA_OPERATION_SCHEMAS } from "./generated/data-operations.js";
export { SCHEMA_OPERATION_SCHEMAS } from "./generated/schema-operations.js";
export { RESOURCE_OPERATION_SCHEMAS } from "./generated/resources.js";
export {
	ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
	ORGANIZATION_MEMBER_REMOVE,
	type OrganizationMemberFixtureRegistry,
} from "./fixtures.js";
