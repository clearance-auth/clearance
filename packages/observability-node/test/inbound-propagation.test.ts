import {
	propagation,
	ROOT_CONTEXT,
	trace,
	type TextMapGetter,
	type TextMapSetter,
} from "@opentelemetry/api";
import { describe, expect, it } from "vitest";
import { inboundOnlyTraceContextPropagator } from "../src/propagation";

type HeaderCarrier = Record<string, string>;

const getter: TextMapGetter<HeaderCarrier> = {
	get: (carrier, key) => carrier[key],
	keys: (carrier) => Object.keys(carrier),
};
const setter: TextMapSetter<HeaderCarrier> = {
	set: (carrier, key, value) => {
		carrier[key] = value;
	},
};

describe("inbound-only trace propagation", () => {
	it("extracts one valid traceparent, drops tracestate and baggage, and never injects", () => {
		const incoming = {
			traceparent: "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
			tracestate: "vendor=private",
			baggage: "customer.id=private",
		};
		const inheritedBaggage = propagation.setBaggage(
			ROOT_CONTEXT,
			propagation.createBaggage({ "customer.id": { value: "private" } }),
		);
		const extracted = inboundOnlyTraceContextPropagator.extract(inheritedBaggage, incoming, getter);

		expect(trace.getSpanContext(extracted)).toMatchObject({
			traceId: "1234567890abcdef1234567890abcdef",
			spanId: "1234567890abcdef",
			traceFlags: 1,
			isRemote: true,
		});
		expect(trace.getSpanContext(extracted)?.traceState).toBeUndefined();
		expect(propagation.getBaggage(extracted)).toBeUndefined();

		const outbound: HeaderCarrier = { "x-existing": "preserved" };
		inboundOnlyTraceContextPropagator.inject(extracted, outbound, setter);
		expect(outbound).toEqual({ "x-existing": "preserved" });
	});
});
