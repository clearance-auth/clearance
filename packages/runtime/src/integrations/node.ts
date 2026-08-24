import type { IncomingHttpHeaders } from "node:http";
import { toNodeHandler as toNode } from "@clearance/call/node";
import type { NodeHandlerOptions } from "@clearance/call/node";
import type { Auth } from "../types";

export type { NodeHandlerOptions } from "@clearance/call/node";

export const toNodeHandler = (
	auth:
		| {
				handler: Auth["handler"];
		  }
		| Auth["handler"],
	options?: NodeHandlerOptions,
) => {
	return "handler" in auth ? toNode(auth.handler, options) : toNode(auth, options);
};

export function fromNodeHeaders(nodeHeaders: IncomingHttpHeaders): Headers {
	const webHeaders = new Headers();
	for (const [key, value] of Object.entries(nodeHeaders)) {
		if (value !== undefined) {
			if (Array.isArray(value)) {
				value.forEach((v) => webHeaders.append(key, v));
			} else {
				webHeaders.set(key, value);
			}
		}
	}
	return webHeaders;
}
