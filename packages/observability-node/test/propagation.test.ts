import {
	context,
	ROOT_CONTEXT,
	trace,
	type Context,
	type ContextManager,
	type SpanContext,
	type Tracer,
	type TracerProvider,
} from "@opentelemetry/api";
import { afterEach, describe, expect, it } from "vitest";
import {
	extractDeliveryTraceCarrier,
	isDeliveryTraceparent,
	withDeliveryProcessingSpan,
} from "../src/propagation";

const parent: SpanContext = {
	traceId: "1234567890abcdef1234567890abcdef",
	spanId: "1234567890abcdef",
	traceFlags: 1,
	isRemote: true,
};

afterEach(() => {
	trace.disable();
	context.disable();
});

describe("delivery trace propagation", () => {
	it("persists only valid traceparent and resumes it for a bounded worker span", async () => {
		let observedParent: SpanContext | undefined;
		let activeContext = ROOT_CONTEXT;
		context.setGlobalContextManager({
			active: () => activeContext,
			with: <T>(value: Context, fn: (...args: never[]) => T, _thisArg?: unknown, ...args: never[]) => {
				const previous = activeContext;
				activeContext = value;
				try {
					return fn(...args);
				} finally {
					activeContext = previous;
				}
			},
			bind: <T>(target: T) => target,
			enable: () => undefined,
			disable: () => undefined,
		} as unknown as ContextManager);
		trace.disable();
		trace.setGlobalTracerProvider({
			getTracer: () => ({
				startActiveSpan: (
					_name: string,
					_options: unknown,
					parentContext: Context,
					callback: (span: ReturnType<typeof trace.wrapSpanContext>) => void,
				) => {
					observedParent = trace.getSpanContext(parentContext);
					const span = trace.wrapSpanContext({
						traceId: observedParent?.traceId ?? "abcdef1234567890abcdef1234567890",
						spanId: "fedcba0987654321",
						traceFlags: 1,
					});
					return context.with(trace.setSpan(parentContext, span), () => callback(span));
				},
			} as unknown as Tracer),
		} as TracerProvider);

		const carrier = extractDeliveryTraceCarrier(
			"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
		);
		expect(carrier?.traceparent).toBe("00-1234567890abcdef1234567890abcdef-1234567890abcdef-01");
		expect(isDeliveryTraceparent("00-00000000000000000000000000000000-1234567890abcdef-01")).toBe(false);
		expect(extractDeliveryTraceCarrier("00-1234567890abcdef1234567890abcdef-1234567890abcdef-ff")).toBeUndefined();

		await withDeliveryProcessingSpan(
			{ carrier, channel: "webhook", transport: "postgres" },
			() => {
				expect(trace.getSpanContext(context.active())?.traceId).toBe(parent.traceId);
			},
		);
		expect(observedParent).toMatchObject(parent);
	});
});
