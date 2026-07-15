import type {
	IncomingHttpHeaders,
	IncomingMessage,
	ServerResponse,
} from "node:http";

export type ClearanceRequestHandler = (request: Request) => Promise<Response>;

export declare function toNodeHandler(auth: {
	handler: ClearanceRequestHandler;
} | ClearanceRequestHandler): (
	request: IncomingMessage,
	response: ServerResponse<IncomingMessage>,
) => Promise<void>;

export declare function fromNodeHeaders(headers: IncomingHttpHeaders): Headers;
