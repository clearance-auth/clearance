import {
	context,
	ROOT_CONTEXT,
	trace,
	type Context,
	type SpanContext,
	type TextMapGetter,
	type TextMapPropagator,
	type TextMapSetter,
} from "@opentelemetry/api";

const TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$/;
const ZERO_TRACE_ID = "00000000000000000000000000000000";
const ZERO_SPAN_ID = "0000000000000000";
const deliveryTraceCarrierBrand: unique symbol = Symbol("delivery-trace-carrier");

/** The only durable tracing carrier used by Clearance delivery. */
export type DeliveryTraceCarrier = Readonly<{
	traceparent: string;
	readonly [deliveryTraceCarrierBrand]: true;
}>;

export type DeliveryProcessingChannel = "email" | "webhook";
export type DeliveryProcessingTransport = "postgres";

function parseTraceparent(value: string): SpanContext | undefined {
	const match = TRACEPARENT.exec(value);
	if (!match) return undefined;
	const [, traceId, spanId, flags] = match;
	if (traceId === undefined || spanId === undefined || flags === undefined) return undefined;
	if (traceId === ZERO_TRACE_ID || spanId === ZERO_SPAN_ID) return undefined;
	return {
		traceId,
		spanId,
		traceFlags: flags === "01" ? 1 : 0,
		isRemote: true,
	};
}

function traceparentFromCarrier<Carrier>(carrier: Carrier, getter: TextMapGetter<Carrier>): string | undefined {
	const value = getter.get(carrier, "traceparent");
	if (typeof value === "string") return value;
	return Array.isArray(value) && value.length === 1 ? value[0] : undefined;
}

/**
 * Process-wide propagation authority: accept one exact inbound W3C parent,
 * retain no baggage or tracestate, and never inject customer-bound headers.
 */
export const inboundOnlyTraceContextPropagator: TextMapPropagator = Object.freeze({
	inject<Carrier>(_context: Context, _carrier: Carrier, _setter: TextMapSetter<Carrier>): void {},
	extract<Carrier>(
		_context: Context,
		carrier: Carrier,
		getter: TextMapGetter<Carrier>,
	): Context {
		const traceparent = traceparentFromCarrier(carrier, getter);
		const spanContext = traceparent === undefined ? undefined : parseTraceparent(traceparent);
		return spanContext === undefined ? ROOT_CONTEXT : trace.setSpanContext(ROOT_CONTEXT, spanContext);
	},
	fields: () => [],
});

/** Accept only a version-00 W3C traceparent with nonzero IDs and valid flags. */
export function isDeliveryTraceparent(value: unknown): value is string {
	return typeof value === "string" && parseTraceparent(value) !== undefined;
}

/** Convert untrusted persisted data into the opaque delivery-only carrier. */
export function extractDeliveryTraceCarrier(value: unknown): DeliveryTraceCarrier | undefined {
	if (!isDeliveryTraceparent(value)) return undefined;
	return Object.freeze({
		traceparent: value,
		[deliveryTraceCarrierBrand]: true as const,
	});
}

function parentContext(carrier: DeliveryTraceCarrier | undefined): Context {
	if (!carrier) return ROOT_CONTEXT;
	const spanContext = parseTraceparent(carrier.traceparent);
	return spanContext ? trace.setSpanContext(ROOT_CONTEXT, spanContext) : ROOT_CONTEXT;
}

/**
 * Resume the persisted delivery parent, or deliberately create a new local root.
 * The closed input prevents callers from attaching arbitrary attributes or IDs.
 */
export function withDeliveryProcessingSpan<T>(
	input: Readonly<{
		carrier?: DeliveryTraceCarrier;
		channel: DeliveryProcessingChannel;
		transport: DeliveryProcessingTransport;
	}>,
	operation: () => T | Promise<T>,
): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		trace.getTracer("@clearance/observability-node").startActiveSpan(
			"clearance.delivery.process",
			{
				attributes: {
					"clearance.delivery.channel": input.channel,
					"clearance.delivery.transport": input.transport,
				},
			},
			parentContext(input.carrier),
			(span) => {
				let result: T | Promise<T>;
				try {
					result = operation();
				} catch (error) {
					span.end();
					reject(error);
					return;
				}
				void Promise.resolve(result)
					.then(resolve, reject)
					.finally(() => span.end());
			},
		);
	});
}
