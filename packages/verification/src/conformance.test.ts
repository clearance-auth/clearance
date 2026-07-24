import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import {
	ClearanceVerificationError,
	createRemoteVerifier,
	verifyWithJwks,
} from "./index";

interface Fixture {
	readonly now: number;
	readonly issuer: string;
	readonly audience: string;
	readonly jwks: unknown;
	readonly rotated_jwks: unknown;
	readonly jwks_cases: readonly {
		readonly name: string;
		readonly error: string;
		readonly token: string;
		readonly jwks_json: string;
	}[];
	readonly remote_cases: readonly {
		readonly name: string;
		readonly token: string;
		readonly sequential_token?: string;
		readonly concurrent_requests?: number;
		readonly expected_fetches?: number;
		readonly cache_ttl_seconds?: number;
		readonly normal_refresh_after_seconds?: number;
		readonly cooldown_seconds?: number;
		readonly repeated_requests_after_seconds?: number;
		readonly repeated_requests_inside_cooldown?: number;
		readonly expected_fetches_before_normal_refresh?: number;
		readonly expected_fetches_after_repeated_requests?: number;
		readonly expected_fetches_after_normal_refresh?: number;
		readonly expected_fetches_after_rotation?: number;
		readonly error: string;
	}[];
	readonly cases: readonly {
		readonly name: string;
		readonly valid: boolean;
		readonly kind?: "human" | "service_account";
		readonly error?: string;
		readonly token: string;
	}[];
}

const fixture = JSON.parse(
	await readFile(
		new URL("../../../sdks/conformance/fixture.json", import.meta.url),
		"utf8",
	),
) as Fixture;

describe("shared verification conformance", () => {
	for (const example of fixture.cases) {
		it(example.name, async () => {
			const result = verifyWithJwks(example.token, fixture.jwks, {
				issuer: fixture.issuer,
				audience: fixture.audience,
				now: fixture.now,
				clockSkewSeconds: 0,
			});
			if (example.valid) {
				await expect(result).resolves.toMatchObject({ kind: example.kind });
			} else {
				await expect(result).rejects.toEqual(
					expect.objectContaining<
						Partial<ClearanceVerificationError>
					>({ code: example.error }),
				);
			}
		});
	}

	for (const example of fixture.jwks_cases) {
		it(example.name, async () => {
			const verifier = createRemoteVerifier({
				issuer: fixture.issuer,
				audience: fixture.audience,
				now: fixture.now,
				clockSkewSeconds: 0,
				fetch: async () => new Response(example.jwks_json),
			});
			await expect(verifier.verify(example.token)).rejects.toMatchObject({
				code: example.error,
			});
		});
	}

	it("uses Clearance's default auth JWKS endpoint", async () => {
		let requestedUrl: string | undefined;
		const verifier = createRemoteVerifier({
			issuer: fixture.issuer,
			audience: fixture.audience,
			now: fixture.now,
			clockSkewSeconds: 0,
			fetch: async (input) => {
				requestedUrl = input.toString();
				return new Response(JSON.stringify(fixture.jwks));
			},
		});
		await expect(verifier.verify(fixture.cases[0]!.token)).resolves.toMatchObject({
			kind: "human",
		});
		expect(requestedUrl).toBe(`${fixture.issuer}/api/auth/jwks`);
	});

	it("returns only closed normalized claims", async () => {
		const claims = await verifyWithJwks(fixture.cases[0]!.token, fixture.jwks, {
			issuer: fixture.issuer,
			audience: fixture.audience,
			now: fixture.now,
			clockSkewSeconds: 0,
		});
		expect(claims.raw).toEqual({});
		expect(Object.isFrozen(claims.raw)).toBe(true);
		expect(Object.hasOwn(claims, "sourceSubjectId")).toBe(true);
		expect(Object.hasOwn(claims, "urn:clearance:claims:session-source-subject")).toBe(false);
	});

	it("bounds chunked JWKS responses before buffering", async () => {
		const verifier = createRemoteVerifier({
			issuer: fixture.issuer,
			audience: fixture.audience,
			now: fixture.now,
			clockSkewSeconds: 0,
			maxResponseBytes: 1_024,
			fetch: async () =>
				new Response(
					new ReadableStream<Uint8Array>({
						start(controller) {
							controller.enqueue(new Uint8Array(768));
							controller.enqueue(new Uint8Array(768));
							controller.close();
						},
					}),
				),
		});
		await expect(verifier.verify(fixture.cases[0]!.token)).rejects.toMatchObject({
			code: "jwks_unavailable",
		});
	});

	it("requires an explicit loopback-development opt-in", () => {
		let rejected: unknown;
		try {
			createRemoteVerifier({
				issuer: "http://127.0.0.1:8787",
				audience: "https://api.clearance.test",
			});
		} catch (error) {
			rejected = error;
		}
		expect(rejected).toEqual(
			expect.objectContaining<Partial<ClearanceVerificationError>>({
				code: "configuration_invalid",
			}),
		);
		expect(() =>
			createRemoteVerifier({
				issuer: "http://127.0.0.1:8787",
				audience: "https://api.clearance.test",
				allowInsecureLoopback: true,
			}),
		).not.toThrow();
		expect(() =>
			createRemoteVerifier({
				issuer: "http://127.attacker.example:8787",
				audience: "https://api.clearance.test",
				allowInsecureLoopback: true,
			}),
		).toThrow();
		expect(() =>
			createRemoteVerifier({
				issuer: "http://sdk.localhost:8787",
				audience: "https://api.clearance.test",
				allowInsecureLoopback: true,
			}),
		).toThrow();
	});

	it("singleflights unknown kids globally and blocks sequential kid amplification", async () => {
		let requests = 0;
		const verifier = createRemoteVerifier({
			issuer: fixture.issuer,
			audience: fixture.audience,
			now: fixture.now,
			clockSkewSeconds: 0,
			fetch: async () => {
				requests += 1;
				return new Response(JSON.stringify(fixture.jwks));
			},
		});
		const scenario = fixture.remote_cases.find(
			(example) => example.name === "unknown_kid_global_cooldown",
		)!;
		const outcomes = await Promise.allSettled(
			Array.from({ length: scenario.concurrent_requests! }, () =>
				verifier.verify(scenario.token),
			),
		);
		expect(outcomes.every((outcome) => outcome.status === "rejected")).toBe(
			true,
		);
		expect(requests).toBe(scenario.expected_fetches);
		await expect(verifier.verify(scenario.sequential_token!)).rejects.toMatchObject({
			code: scenario.error,
		});
		expect(requests).toBe(scenario.expected_fetches);
	});

	it("allows TTL refreshes during cooldown and recovers a rotated kid after it", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(0);
		try {
			const scenario = fixture.remote_cases.find(
				(example) => example.name === "post_cooldown_rotation_recovery",
			)!;
			let requests = 0;
			let body = fixture.jwks;
			const verifier = createRemoteVerifier({
				issuer: fixture.issuer,
				audience: fixture.audience,
				now: fixture.now,
				clockSkewSeconds: 0,
				cacheTtlSeconds: scenario.cache_ttl_seconds,
				fetch: async () => {
					requests += 1;
					return new Response(JSON.stringify(body));
				},
			});
			await expect(verifier.verify(scenario.token)).rejects.toMatchObject({
				code: scenario.error,
			});
			expect(requests).toBe(scenario.expected_fetches_before_normal_refresh);
			vi.advanceTimersByTime(scenario.normal_refresh_after_seconds! * 1_000);
			await expect(verifier.verify(fixture.cases[0]!.token)).resolves.toMatchObject({
				kind: "human",
			});
			expect(requests).toBe(scenario.expected_fetches_after_normal_refresh);
			vi.advanceTimersByTime(
				(scenario.repeated_requests_after_seconds! - scenario.normal_refresh_after_seconds!) * 1_000,
			);
			for (let request = 0; request < scenario.repeated_requests_inside_cooldown!; request += 1) {
				await expect(verifier.verify(scenario.token)).rejects.toMatchObject({
					code: scenario.error,
				});
			}
			expect(requests).toBe(scenario.expected_fetches_after_repeated_requests);
			body = fixture.rotated_jwks;
			vi.advanceTimersByTime(
				(scenario.cooldown_seconds! - scenario.repeated_requests_after_seconds!) * 1_000,
			);
			await expect(verifier.verify(scenario.token)).resolves.toMatchObject({
				kind: "human",
			});
			expect(requests).toBe(scenario.expected_fetches_after_rotation);
		} finally {
			vi.useRealTimers();
		}
	});

	it("rejects duplicate protected-header members before verification", async () => {
		const valid = fixture.cases.find((example) => example.valid)!.token;
		const [, payload, signature] = valid.split(".");
		const duplicateHeader = Buffer.from(
			'{"alg":"ES256","alg":"ES256","kid":"fixture-es256-2026-01"}',
		).toString("base64url");
		await expect(
			verifyWithJwks(
				`${duplicateHeader}.${payload}.${signature}`,
				fixture.jwks,
				{
					issuer: fixture.issuer,
					audience: fixture.audience,
					now: fixture.now,
				},
			),
		).rejects.toMatchObject({ code: "token_malformed" });
	});
});
