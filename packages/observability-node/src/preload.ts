import { startObservability } from "./bootstrap";

// Intended for process owners via `node --import`. Starting here happens before
// application imports; process owners retain shutdown ordering and signal policy.
await startObservability();
