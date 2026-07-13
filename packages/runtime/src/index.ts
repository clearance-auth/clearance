//#region Re-exports necessaries from core module
export type { StandardSchemaV1 } from "@clearance/core";
export * from "@clearance/core";
export { getCurrentAdapter } from "@clearance/core/context";
export * from "@clearance/core/db";
export * from "@clearance/core/env";
export * from "@clearance/core/error";
export * from "@clearance/core/oauth2";
export * from "@clearance/core/utils/error-codes";
export * from "@clearance/core/utils/id";
export * from "@clearance/core/utils/json";
//#endregion
export { clearance } from "./auth/full";
// @ts-expect-error
export * from "./types";
export * from "./utils";

// export this as we are referencing OAuth2Tokens in the `refresh-token` api as return type

// telemetry exports for CLI and consumers
export {
	createTelemetry,
	getTelemetryAuthConfig,
	type TelemetryEvent,
} from "@clearance/telemetry";
// re-export third party types
// @ts-expect-error
export type * from "@clearance/call";
export type { JSONWebKeySet, JWTPayload } from "jose";
export type * from "zod";
export { APIError } from "./api";
