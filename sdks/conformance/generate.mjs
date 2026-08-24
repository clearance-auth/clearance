/**
 * TEST-ONLY fixture generator.
 *
 * The private key exists only in this process and is never written. The checked-in
 * fixture contains the corresponding public JWKS and signed negative/positive
 * examples so every SDK verifies identical bytes.
 */
import { generateKeyPairSync, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const issuer = "https://auth.clearance.test";
const audience = "https://api.clearance.test";
const now = 2_000_000_000;
const kid = "fixture-es256-2026-01";
const unknownKid = "fixture-unknown-2026-01";
const secondUnknownKid = "fixture-unknown-2026-02";
const rotatedKid = "fixture-es256-2026-02";

const { privateKey, publicKey } = generateKeyPairSync("ec", {
	namedCurve: "prime256v1",
});
const publicJwk = publicKey.export({ format: "jwk" });
const { privateKey: rotatedPrivateKey, publicKey: rotatedPublicKey } =
	generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const rotatedPublicJwk = rotatedPublicKey.export({ format: "jwk" });

const b64url = (value) => Buffer.from(value).toString("base64url");
const encodedJson = (value) => b64url(JSON.stringify(value));
const baseClaims = {
	iss: issuer,
	aud: audience,
	iat: now - 60,
	nbf: now - 60,
	exp: now + 240,
};
const humanAuthority = {
	"urn:clearance:claims:session-derivative-authority": "binding_test_human",
	"urn:clearance:claims:session-source-subject": "user_test_human",
	"urn:clearance:claims:session-source-organization": "org_test",
	actions: ["organization.read", "organization.write"],
	authz_revision: "7",
};
const serviceAuthority = {
	"urn:clearance:claims:subject-kind": "service_account",
	"urn:clearance:claims:organization-id": "org_test",
	actions: ["organization.read", "organization.write"],
	authz_revision: "7",
};

function token(payload, headerKid = kid, signingKey = privateKey) {
	const protectedHeader = encodedJson({
		alg: "ES256",
		kid: headerKid,
		typ: "JWT",
	});
	const encodedPayload = encodedJson(payload);
	const signingInput = `${protectedHeader}.${encodedPayload}`;
	const signature = sign("sha256", Buffer.from(signingInput), {
		key: signingKey,
		dsaEncoding: "ieee-p1363",
	});
	return `${signingInput}.${b64url(signature)}`;
}

function rawToken(
	payloadJson,
	protectedHeader = { alg: "ES256", kid, typ: "JWT" },
) {
	const encodedHeader = encodedJson(protectedHeader);
	const encodedPayload = b64url(payloadJson);
	const signingInput = `${encodedHeader}.${encodedPayload}`;
	const signature = sign("sha256", Buffer.from(signingInput), {
		key: privateKey,
		dsaEncoding: "ieee-p1363",
	});
	return `${signingInput}.${b64url(signature)}`;
}

const validHuman = token({
	...baseClaims,
	sub: "user_test_human",
	...humanAuthority,
});
const validServiceAccount = token({
	...baseClaims,
	sub: "service_test_machine",
	...serviceAuthority,
});
const tamperedParts = validHuman.split(".");
const tamperedPayload = {
	...JSON.parse(Buffer.from(tamperedParts[1], "base64url").toString("utf8")),
	sub: "attacker",
};
const tamperedSignature = [
	tamperedParts[0],
	encodedJson(tamperedPayload),
	tamperedParts[2],
].join(".");

const fixture = {
	schema_version: 1,
	now,
	issuer,
	audience,
	jwks: {
		keys: [
			{
				kty: "EC",
				crv: "P-256",
				x: publicJwk.x,
				y: publicJwk.y,
				kid,
				use: "sig",
				alg: "ES256",
				key_ops: ["verify"],
			},
		],
	},
	rotated_jwks: {
		keys: [
			{
				kty: "EC",
				crv: "P-256",
				x: rotatedPublicJwk.x,
				y: rotatedPublicJwk.y,
				kid: rotatedKid,
				use: "sig",
				alg: "ES256",
				key_ops: ["verify"],
			},
		],
	},
	jwks_cases: [
		{
			name: "duplicate_jwk_member",
			error: "jwks_invalid",
			token: validHuman,
			jwks_json: `{"keys":[{"kty":"EC","crv":"P-256","x":"${publicJwk.x}","y":"${publicJwk.y}","kid":"${kid}","kid":"${kid}","use":"sig","alg":"ES256","key_ops":["verify"]}]}`,
		},
		{
			name: "unexpected_jwk_member",
			error: "jwks_invalid",
			token: validHuman,
			jwks_json: `{"keys":[{"kty":"EC","crv":"P-256","x":"${publicJwk.x}","y":"${publicJwk.y}","kid":"${kid}","use":"sig","alg":"ES256","key_ops":["verify"],"issuer":"attacker"}]}`,
		},
		{
			name: "nan_jwks_value",
			error: "jwks_invalid",
			token: validHuman,
			jwks_json: '{"keys":NaN}',
		},
		{
			name: "wrong_jwk_type",
			error: "jwks_invalid",
			token: validHuman,
			jwks_json: `{"keys":[{"kty":"RSA","crv":"P-256","x":"${publicJwk.x}","y":"${publicJwk.y}","kid":"${kid}","use":"sig","alg":"ES256"}]}`,
		},
		{
			name: "wrong_jwk_curve",
			error: "jwks_invalid",
			token: validHuman,
			jwks_json: `{"keys":[{"kty":"EC","crv":"P-384","x":"${publicJwk.x}","y":"${publicJwk.y}","kid":"${kid}","use":"sig","alg":"ES256"}]}`,
		},
		{
			name: "wrong_jwk_operations",
			error: "jwks_invalid",
			token: validHuman,
			jwks_json: `{"keys":[{"kty":"EC","crv":"P-256","x":"${publicJwk.x}","y":"${publicJwk.y}","kid":"${kid}","use":"sig","alg":"ES256","key_ops":["sign"]}]}`,
		},
		{
			name: "off_curve_jwk",
			error: "jwks_invalid",
			token: validHuman,
			jwks_json: `{"keys":[{"kty":"EC","crv":"P-256","x":"${"A".repeat(43)}","y":"${"A".repeat(43)}","kid":"${kid}","use":"sig","alg":"ES256"}]}`,
		},
	],
	remote_cases: [
		{
			name: "unknown_kid_global_cooldown",
			token: token(
				{ ...baseClaims, sub: "user_test_human", ...humanAuthority },
				unknownKid,
			),
			sequential_token: token(
				{ ...baseClaims, sub: "user_test_human", ...humanAuthority },
				secondUnknownKid,
			),
			concurrent_requests: 10,
			expected_fetches: 2,
			error: "key_not_found",
		},
		{
			name: "post_cooldown_rotation_recovery",
			token: token(
				{ ...baseClaims, sub: "user_test_human", ...humanAuthority },
				rotatedKid,
				rotatedPrivateKey,
			),
			cache_ttl_seconds: 2,
			normal_refresh_after_seconds: 2,
			cooldown_seconds: 30,
			repeated_requests_after_seconds: 29,
			repeated_requests_inside_cooldown: 3,
			expected_fetches_before_normal_refresh: 2,
			expected_fetches_after_normal_refresh: 3,
			expected_fetches_after_repeated_requests: 4,
			expected_fetches_after_rotation: 5,
			error: "key_not_found",
		},
	],
	cases: [
		{
			name: "valid_human",
			valid: true,
			kind: "human",
			token: validHuman,
		},
		{
			name: "valid_service_account",
			valid: true,
			kind: "service_account",
			token: validServiceAccount,
		},
		{
			name: "expired",
			valid: false,
			error: "token_expired",
			token: token({
				...baseClaims,
				sub: "user_test_human",
				exp: now - 1,
				...humanAuthority,
			}),
		},
		{
			name: "wrong_issuer",
			valid: false,
			error: "issuer_mismatch",
			token: token({
				...baseClaims,
				iss: "https://wrong.clearance.test",
				sub: "user_test_human",
				...humanAuthority,
			}),
		},
		{
			name: "wrong_audience",
			valid: false,
			error: "audience_mismatch",
			token: token({
				...baseClaims,
				aud: "https://wrong-api.clearance.test",
				sub: "user_test_human",
				...humanAuthority,
			}),
		},
		{
			name: "valid_audience_array",
			valid: true,
			kind: "human",
			token: token({
				...baseClaims,
				aud: ["https://other.clearance.test", audience],
				sub: "user_test_human",
				...humanAuthority,
			}),
		},
		{
			name: "algorithm_rejected",
			valid: false,
			error: "algorithm_rejected",
			token: rawToken(
				JSON.stringify({ ...baseClaims, sub: "user_test_human", ...humanAuthority }),
				{ alg: "HS256", kid, typ: "JWT" },
			),
		},
		{
			name: "noncanonical_base64url",
			valid: false,
			error: "token_malformed",
			token: `${validHuman}=`,
		},
		{
			name: "duplicate_token_member",
			valid: false,
			error: "token_malformed",
			token: rawToken(
				`{"iss":"${issuer}","aud":"${audience}","iat":${baseClaims.iat},"nbf":${baseClaims.nbf},"exp":${baseClaims.exp},"sub":"user_test_human","sub":"attacker"}`,
			),
		},
		{
			name: "issued_in_future",
			valid: false,
			error: "token_not_active",
			token: token({
				...baseClaims,
				iat: now + 1,
				nbf: now - 60,
				exp: now + 240,
				sub: "user_test_human",
				...humanAuthority,
			}),
		},
		{
			name: "not_before_in_future",
			valid: false,
			error: "token_not_active",
			token: token({
				...baseClaims,
				nbf: now + 1,
				sub: "user_test_human",
				...humanAuthority,
			}),
		},
		{
			name: "unordered_actions",
			valid: false,
			error: "claims_invalid",
			token: token({
				...baseClaims,
				sub: "user_test_human",
				...humanAuthority,
				actions: ["organization.write", "organization.read"],
			}),
		},
		{
			name: "invalid_revision",
			valid: false,
			error: "claims_invalid",
			token: token({
				...baseClaims,
				sub: "user_test_human",
				...humanAuthority,
				authz_revision: "0",
			}),
		},
		{
			name: "unknown_kid",
			valid: false,
			error: "key_not_found",
			token: token(
				{ ...baseClaims, sub: "user_test_human", ...humanAuthority },
				unknownKid,
			),
		},
		{
			name: "tampered_signature",
			valid: false,
			error: "signature_invalid",
			token: tamperedSignature,
		},
		{
			name: "partial_authority",
			valid: false,
			error: "claims_invalid",
			token: token({
				...baseClaims,
				sub: "user_test_human",
				actions: ["organization.read"],
			}),
		},
		{
			name: "token_lifetime_exceeds_five_minutes",
			valid: false,
			error: "claims_invalid",
			token: token({
				...baseClaims,
				sub: "user_test_human",
				exp: baseClaims.iat + 301,
				...humanAuthority,
			}),
		},
		{
			name: "human_actions_without_organization",
			valid: false,
			error: "claims_invalid",
			token: token({
				...baseClaims,
				sub: "user_test_human",
				...humanAuthority,
				"urn:clearance:claims:session-source-organization": null,
			}),
		},
		{
			name: "nan_numeric_claim",
			valid: false,
			error: "token_malformed",
			token: rawToken(
				`{"iss":"${issuer}","aud":"${audience}","iat":NaN,"nbf":${baseClaims.nbf},"exp":${baseClaims.exp},"sub":"user_test_human"}`,
			),
		},
		{
			name: "mixed_authority",
			valid: false,
			error: "claims_invalid",
			token: token({
				...baseClaims,
				sub: "service_test_machine",
				...serviceAuthority,
				"urn:clearance:claims:session-derivative-authority":
					"binding_must_not_exist",
				"urn:clearance:claims:session-source-subject":
					"service_test_machine",
				"urn:clearance:claims:session-source-organization": "org_test",
			}),
		},
	],
};

writeFileSync(
	fileURLToPath(new URL("./fixture.json", import.meta.url)),
	`${JSON.stringify(fixture, null, 2)}\n`,
);
