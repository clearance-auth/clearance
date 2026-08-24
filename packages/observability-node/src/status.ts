import type { ClearanceServiceName, ObservabilityConfig } from "./config";

export type ObservabilityState = "disabled" | "configured" | "exporter_error";

export interface ObservabilityStatus {
	state: ObservabilityState;
	serviceName?: ClearanceServiceName;
	instrumentations: Readonly<{
		http: boolean;
		pg: boolean;
	}>;
}

export function redactedStatus(
	config: ObservabilityConfig,
	state: ObservabilityState,
): ObservabilityStatus {
	if (!config.enabled) {
		return Object.freeze({
			state: "disabled",
			instrumentations: Object.freeze({ http: false, pg: false }),
		});
	}
	return Object.freeze({
		state,
		serviceName: config.serviceName,
		instrumentations: Object.freeze({ http: true, pg: true }),
	});
}
