#!/usr/bin/env node

export {};

await import("@clearance/observability-node/preload");
await import("./cli.js");
