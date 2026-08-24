import { startObservability } from "./bootstrap";
import { parseObservabilityConfig } from "./config";
import { installObservabilityShutdownHandlers } from "./shutdown-signals";

// Parse before creating a promise so malformed explicitly enabled preload
// configuration aborts module evaluation and therefore process startup.
const config = parseObservabilityConfig();
const handle = await startObservability(config);
if (handle.status.state !== "disabled") {
	installObservabilityShutdownHandlers(handle);
}
