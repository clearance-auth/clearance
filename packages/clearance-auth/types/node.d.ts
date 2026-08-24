import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";
export type ClearanceRequestHandler = (request: Request) => Promise<Response>;
export interface NodeHandlerOptions {
    /** The configured public origin. Defaults to http://localhost. */
    canonicalOrigin?: string;
    /** Trust X-Forwarded-Host and X-Forwarded-Proto from an immediate proxy. */
    trustedProxyHeaders?: boolean;
    /** Maximum raw request-body size in bytes. Defaults to 1 MiB. */
    bodySizeLimit?: number;
}
export declare function toNodeHandler(auth: {
    handler: ClearanceRequestHandler;
} | ClearanceRequestHandler, options?: NodeHandlerOptions): (request: IncomingMessage, response: ServerResponse<IncomingMessage>) => Promise<void>;
export declare function fromNodeHeaders(headers: IncomingHttpHeaders): Headers;
