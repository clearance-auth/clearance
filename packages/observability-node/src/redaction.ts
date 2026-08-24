import type { Resource } from "@opentelemetry/resources";
import type { tracing } from "@opentelemetry/sdk-node";

const HTTP_METHOD_ATTRIBUTES = ["http.request.method", "http.method"] as const;
const HTTP_STATUS_ATTRIBUTES = [
	"http.response.status_code",
	"http.status_code",
] as const;
const DATABASE_SYSTEM_ATTRIBUTES = ["db.system.name", "db.system"] as const;
const DATABASE_OPERATION_ATTRIBUTES = [
	"db.operation.name",
	"db.operation",
] as const;
const METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]);
const OPERATIONS = new Set([
	"SELECT",
	"INSERT",
	"UPDATE",
	"DELETE",
	"BEGIN",
	"COMMIT",
	"ROLLBACK",
	"CREATE",
	"ALTER",
	"DROP",
	"TRUNCATE",
]);
type ExportResult = Parameters<
	Parameters<tracing.SpanExporter["export"]>[1]
>[0];

function copyTime(value: tracing.ReadableSpan["startTime"]): [number, number] {
	return [value[0], value[1]];
}

function copyContext(
	context: ReturnType<tracing.ReadableSpan["spanContext"]>,
): ReturnType<tracing.ReadableSpan["spanContext"]> {
	return Object.freeze({
		traceId: context.traceId,
		spanId: context.spanId,
		traceFlags: context.traceFlags,
		...(context.isRemote === true ? { isRemote: true } : {}),
	});
}

function readStringAttribute(
	attributes: tracing.ReadableSpan["attributes"],
	keys: readonly string[],
): string | undefined {
	for (const key of keys) {
		const value = attributes[key];
		if (typeof value === "string") return value;
	}
	return undefined;
}

function readStatusAttribute(
	attributes: tracing.ReadableSpan["attributes"],
	keys: readonly string[],
): number | undefined {
	for (const key of keys) {
		const value = attributes[key];
		if (typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 599) {
			return value;
		}
	}
	return undefined;
}

function operationFrom(value: string | undefined): string | undefined {
	if (!value) return undefined;
	const candidate = value.trim().split(/\s/, 1)[0]?.toUpperCase();
	return candidate && OPERATIONS.has(candidate) ? candidate : undefined;
}

/**
 * Produces the only span representation that can reach the OTLP exporter.
 * It deliberately uses an allowlist, which makes instrumenter upgrades safe by
 * default: unknown attributes, event payloads, link attributes, status text,
 * query text, URLs, headers, and exception details are all discarded.
 */
export function redactSpanForExport(
	span: tracing.ReadableSpan,
	resource: Resource,
): tracing.ReadableSpan {
	const attributes: tracing.ReadableSpan["attributes"] = {};
	const method = readStringAttribute(span.attributes, HTTP_METHOD_ATTRIBUTES)?.toUpperCase();
	const status = readStatusAttribute(span.attributes, HTTP_STATUS_ATTRIBUTES);
	const databaseSystem = readStringAttribute(span.attributes, DATABASE_SYSTEM_ATTRIBUTES);
	const operation =
		operationFrom(readStringAttribute(span.attributes, DATABASE_OPERATION_ATTRIBUTES)) ??
		operationFrom(span.name);

	if (method && METHODS.has(method)) attributes["http.request.method"] = method;
	if (status !== undefined) attributes["http.response.status_code"] = status;
	if (databaseSystem === "postgresql") attributes["db.system.name"] = databaseSystem;
	if (operation) attributes["db.operation.name"] = operation;

	const name = databaseSystem === "postgresql"
		? `postgresql ${operation ?? "operation"}`
		: method && METHODS.has(method)
			? `HTTP ${method}`
			: "clearance.operation";

	const spanContext = copyContext(span.spanContext());
	const parentSpanContext = span.parentSpanContext
		? copyContext(span.parentSpanContext)
		: undefined;
	const kind = Number.isInteger(span.kind) && span.kind >= 0 && span.kind <= 4
		? span.kind
		: 0;
	const statusCode = Number.isInteger(span.status.code) && span.status.code >= 0 && span.status.code <= 2
		? span.status.code
		: 0;

	return Object.freeze({
		name,
		kind,
		spanContext: () => spanContext,
		...(parentSpanContext ? { parentSpanContext } : {}),
		startTime: copyTime(span.startTime),
		endTime: copyTime(span.endTime),
		duration: copyTime(span.duration),
		ended: true,
		resource,
		instrumentationScope: Object.freeze({
			name: databaseSystem === "postgresql"
				? "@opentelemetry/instrumentation-pg"
				: method && METHODS.has(method)
					? "@opentelemetry/instrumentation-http"
					: "@clearance/observability-node",
		}),
		attributes,
		links: [],
		events: [],
		status: Object.freeze({ code: statusCode }),
		droppedAttributesCount: 0,
		droppedEventsCount: 0,
		droppedLinksCount: 0,
	});
}

export class RedactingSpanExporter implements tracing.SpanExporter {
	constructor(
		private readonly delegate: tracing.SpanExporter,
		private readonly resource: Resource,
		private readonly onResult: (result: { code: number }) => void,
	) {}

	export(
		spans: tracing.ReadableSpan[],
		resultCallback: Parameters<tracing.SpanExporter["export"]>[1],
	): void {
		try {
			this.delegate.export(
				spans.map((span) => redactSpanForExport(span, this.resource)),
				(result) => {
					this.onResult(result);
					resultCallback(result);
				},
			);
		} catch {
			const failure = { code: 1 } as unknown as ExportResult;
			this.onResult(failure);
			resultCallback(failure);
		}
	}

	shutdown(): Promise<void> {
		return this.delegate.shutdown();
	}

	forceFlush(): Promise<void> {
		return this.delegate.forceFlush?.() ?? Promise.resolve();
	}
}
