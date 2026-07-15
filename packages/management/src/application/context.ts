import type { AuditEvent } from "../types/resources.js";
import type { ResourceScope } from "../services/scope.js";

export type OperationSource = AuditEvent["source"];

export interface OperationContext {
	readonly scope: ResourceScope;
	readonly actor: string;
	readonly source: OperationSource;
}
