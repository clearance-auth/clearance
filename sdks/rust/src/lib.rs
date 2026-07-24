//! Strict Clearance ES256 access-token verification.
#![doc = include_str!("../README.md")]
//!
//! This crate deliberately accepts only the Clearance JWT/JWKS profile: ES256,
//! P-256 public verification keys, canonical base64url, and the canonical human
//! or service-account authority claim grammar.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::Read,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use url::{Host, Url};

pub const SESSION_DERIVATIVE_AUTHORITY: &str = "urn:clearance:claims:session-derivative-authority";
pub const SESSION_SOURCE_SUBJECT: &str = "urn:clearance:claims:session-source-subject";
pub const SESSION_SOURCE_ORGANIZATION: &str = "urn:clearance:claims:session-source-organization";
pub const SUBJECT_KIND: &str = "urn:clearance:claims:subject-kind";
pub const ORGANIZATION_ID: &str = "urn:clearance:claims:organization-id";
pub const ACTIONS: &str = "actions";
pub const AUTHORIZATION_REVISION: &str = "authz_revision";

const MAX_TOKEN_BYTES: usize = 16_384;
const MAX_JSON_BYTES: usize = 12_288;
const MAX_KEYS: usize = 32;
const MAX_ACTIONS: usize = 256;
const UNKNOWN_MISS_TTL: Duration = Duration::from_secs(30);
const MAX_UNKNOWN_MISSES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    TokenMalformed,
    AlgorithmRejected,
    KeyNotFound,
    JwksInvalid,
    JwksUnavailable,
    SignatureInvalid,
    IssuerMismatch,
    AudienceMismatch,
    TokenExpired,
    TokenNotActive,
    ClaimsInvalid,
    ConfigurationInvalid,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenMalformed => "token_malformed",
            Self::AlgorithmRejected => "algorithm_rejected",
            Self::KeyNotFound => "key_not_found",
            Self::JwksInvalid => "jwks_invalid",
            Self::JwksUnavailable => "jwks_unavailable",
            Self::SignatureInvalid => "signature_invalid",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::AudienceMismatch => "audience_mismatch",
            Self::TokenExpired => "token_expired",
            Self::TokenNotActive => "token_not_active",
            Self::ClaimsInvalid => "claims_invalid",
            Self::ConfigurationInvalid => "configuration_invalid",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::TokenMalformed => "Access token is malformed",
            Self::AlgorithmRejected => "Access token algorithm is not allowed",
            Self::KeyNotFound => "Access token verification key was not found",
            Self::JwksInvalid => "Verification key set is invalid",
            Self::JwksUnavailable => "Verification key set is unavailable",
            Self::SignatureInvalid => "Access token signature is invalid",
            Self::IssuerMismatch => "Access token issuer does not match",
            Self::AudienceMismatch => "Access token audience does not match",
            Self::TokenExpired => "Access token has expired",
            Self::TokenNotActive => "Access token is not active",
            Self::ClaimsInvalid => "Access token claims are invalid",
            Self::ConfigurationInvalid => "Verifier configuration is invalid",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationError {
    pub code: ErrorCode,
}

impl VerificationError {
    const fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.message())
    }
}

impl std::error::Error for VerificationError {}

type Result<T> = std::result::Result<T, VerificationError>;

fn fail<T>(code: ErrorCode) -> Result<T> {
    Err(VerificationError::new(code))
}

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub issuer: String,
    pub audience: String,
    pub clock_skew: Duration,
    /// A deterministic time source for tests. `None` uses the current Unix time.
    pub now: Option<SystemTime>,
}

impl VerifyOptions {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            clock_skew: Duration::from_secs(30),
            now: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedClaims {
    pub subject: String,
    pub kind: SubjectKind,
    pub issuer: String,
    pub audience: Vec<String>,
    pub expires_at: i64,
    pub issued_at: i64,
    pub not_before: Option<i64>,
    pub organization_id: Option<String>,
    pub actions: Vec<String>,
    pub authorization_revision: Option<String>,
    pub session_derivative_authority: Option<String>,
    pub source_subject_id: Option<String>,
    pub source_organization_id: Option<String>,
    pub raw: Map<String, Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKind {
    Human,
    ServiceAccount,
}

#[derive(Clone, Debug)]
struct ParsedToken {
    kid: String,
    payload: Map<String, Value>,
    signing_input: Vec<u8>,
    signature: [u8; 64],
}

#[derive(Clone)]
struct PublicKey {
    kid: String,
    key: VerifyingKey,
}

/// Verify one token using an already trusted, bounded JWKS JSON document.
pub fn verify(
    token: &str,
    jwks: impl AsRef<[u8]>,
    options: &VerifyOptions,
) -> Result<VerifiedClaims> {
    let now = validate_options(options)?;
    let parsed = parse_token(token)?;
    let keys = parse_jwks(jwks.as_ref())?;
    verify_parsed(&parsed, &keys, options, now)
}

fn validate_options(options: &VerifyOptions) -> Result<i64> {
    if options.issuer.is_empty()
        || options.audience.is_empty()
        || options.clock_skew > Duration::from_secs(300)
    {
        return fail(ErrorCode::ConfigurationInvalid);
    }
    let time = options.now.unwrap_or_else(SystemTime::now);
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VerificationError::new(ErrorCode::ConfigurationInvalid))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| VerificationError::new(ErrorCode::ConfigurationInvalid))
}

fn decode_base64url(value: &str, code: ErrorCode) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.contains('=')
        || value.len() % 4 == 1
        || !value.bytes().all(|byte| {
            byte.is_ascii_uppercase()
                || byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'_'
                || byte == b'-'
        })
    {
        return fail(code);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| VerificationError::new(code))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return fail(code);
    }
    Ok(decoded)
}

fn parse_token(token: &str) -> Result<ParsedToken> {
    if token.len() > MAX_TOKEN_BYTES || !token.is_ascii() {
        return fail(ErrorCode::TokenMalformed);
    }
    let mut pieces = token.split('.');
    let (Some(header_segment), Some(payload_segment), Some(signature), None) =
        (pieces.next(), pieces.next(), pieces.next(), pieces.next())
    else {
        return fail(ErrorCode::TokenMalformed);
    };
    if header_segment.is_empty() || payload_segment.is_empty() || signature.is_empty() {
        return fail(ErrorCode::TokenMalformed);
    }
    let header = parse_json_object(
        &decode_limited_segment(header_segment, ErrorCode::TokenMalformed)?,
        ErrorCode::TokenMalformed,
    )?;
    if header.get("alg") != Some(&Value::String("ES256".into())) {
        return fail(ErrorCode::AlgorithmRejected);
    }
    let Some(kid) = header.get("kid").and_then(Value::as_str) else {
        return fail(ErrorCode::TokenMalformed);
    };
    if !valid_kid(kid)
        || header
            .get("typ")
            .is_some_and(|value| value != &Value::String("JWT".into()))
        || header
            .keys()
            .any(|key| !matches!(key.as_str(), "alg" | "kid" | "typ"))
    {
        return fail(ErrorCode::TokenMalformed);
    }
    let payload = parse_json_object(
        &decode_limited_segment(payload_segment, ErrorCode::TokenMalformed)?,
        ErrorCode::TokenMalformed,
    )?;
    let signature_bytes = decode_base64url(signature, ErrorCode::TokenMalformed)?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| VerificationError::new(ErrorCode::SignatureInvalid))?;
    Ok(ParsedToken {
        kid: kid.to_owned(),
        payload,
        signing_input: format!("{header_segment}.{payload_segment}").into_bytes(),
        signature,
    })
}

fn decode_limited_segment(value: &str, code: ErrorCode) -> Result<Vec<u8>> {
    let decoded = decode_base64url(value, code)?;
    if decoded.len() > MAX_JSON_BYTES {
        return fail(code);
    }
    Ok(decoded)
}

/// `serde_json::Value` accepts duplicate object members. JWT and JWKS parsing
/// must reject them at every nesting level, so this visitor builds the value
/// while tracking each object key.
struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: de::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJson;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(Number::from(value))))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(Number::from(value))))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(|number| StrictJson(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::String(value)))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictJson(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, StrictJson(value))) = map.next_entry::<String, StrictJson>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object member"));
                    }
                }
                Ok(StrictJson(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn parse_json_object(bytes: &[u8], code: ErrorCode) -> Result<Map<String, Value>> {
    let StrictJson(value) =
        serde_json::from_slice(bytes).map_err(|_| VerificationError::new(code))?;
    match value {
        Value::Object(object) => Ok(object),
        _ => fail(code),
    }
}

fn valid_kid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn parse_jwks(bytes: &[u8]) -> Result<Vec<PublicKey>> {
    let root = parse_json_object(bytes, ErrorCode::JwksInvalid)?;
    let Some(values) = root.get("keys").and_then(Value::as_array) else {
        return fail(ErrorCode::JwksInvalid);
    };
    if values.is_empty() || values.len() > MAX_KEYS {
        return fail(ErrorCode::JwksInvalid);
    }
    let mut seen = HashSet::with_capacity(values.len());
    let mut keys = Vec::with_capacity(values.len());
    for value in values {
        let Some(jwk) = value.as_object() else {
            return fail(ErrorCode::JwksInvalid);
        };
        if jwk.keys().any(|member| {
            !matches!(
                member.as_str(),
                "kty" | "crv" | "x" | "y" | "kid" | "use" | "alg" | "key_ops"
            )
        }) {
            return fail(ErrorCode::JwksInvalid);
        }
        let (Some(kid), Some(x), Some(y)) = (
            jwk.get("kid").and_then(Value::as_str),
            jwk.get("x").and_then(Value::as_str),
            jwk.get("y").and_then(Value::as_str),
        ) else {
            return fail(ErrorCode::JwksInvalid);
        };
        if jwk.get("kty") != Some(&Value::String("EC".into()))
            || jwk.get("crv") != Some(&Value::String("P-256".into()))
            || jwk.get("use") != Some(&Value::String("sig".into()))
            || jwk.get("alg") != Some(&Value::String("ES256".into()))
            || jwk.contains_key("d")
            || !valid_kid(kid)
            || !seen.insert(kid.to_owned())
        {
            return fail(ErrorCode::JwksInvalid);
        }
        if let Some(operations) = jwk.get("key_ops") {
            if !matches!(operations.as_array(), Some(values) if values.len() == 1 && values[0] == Value::String("verify".into()))
            {
                return fail(ErrorCode::JwksInvalid);
            }
        }
        let x = decode_base64url(x, ErrorCode::JwksInvalid)?;
        let y = decode_base64url(y, ErrorCode::JwksInvalid)?;
        if x.len() != 32 || y.len() != 32 {
            return fail(ErrorCode::JwksInvalid);
        }
        let mut sec1 = [0_u8; 65];
        sec1[0] = 4;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..].copy_from_slice(&y);
        let key = VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|_| VerificationError::new(ErrorCode::JwksInvalid))?;
        keys.push(PublicKey {
            kid: kid.to_owned(),
            key,
        });
    }
    Ok(keys)
}

fn verify_parsed(
    parsed: &ParsedToken,
    keys: &[PublicKey],
    options: &VerifyOptions,
    now: i64,
) -> Result<VerifiedClaims> {
    let Some(key) = keys.iter().find(|key| key.kid == parsed.kid) else {
        return fail(ErrorCode::KeyNotFound);
    };
    let signature = Signature::from_slice(&parsed.signature)
        .map_err(|_| VerificationError::new(ErrorCode::SignatureInvalid))?;
    // p256's verifier hashes ES256 input with SHA-256 as specified by JWS.
    key.key
        .verify(&parsed.signing_input, &signature)
        .map_err(|_| VerificationError::new(ErrorCode::SignatureInvalid))?;
    validate_claims(&parsed.payload, options, now)
}

fn non_empty_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn exact_i64(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

fn valid_action(action: &str) -> bool {
    let mut bytes = action.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && action.len() <= 128
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn parse_actions(value: &Value) -> Result<Vec<String>> {
    let Some(values) = value.as_array() else {
        return fail(ErrorCode::ClaimsInvalid);
    };
    if values.len() > MAX_ACTIONS {
        return fail(ErrorCode::ClaimsInvalid);
    }
    let mut actions = Vec::with_capacity(values.len());
    for value in values {
        let Some(action) = value.as_str() else {
            return fail(ErrorCode::ClaimsInvalid);
        };
        if !valid_action(action)
            || actions
                .last()
                .is_some_and(|prior: &String| prior.as_str() >= action)
        {
            return fail(ErrorCode::ClaimsInvalid);
        }
        actions.push(action.to_owned());
    }
    Ok(actions)
}

fn parse_revision(value: &Value) -> Result<String> {
    let Some(revision) = value.as_str() else {
        return fail(ErrorCode::ClaimsInvalid);
    };
    if revision.is_empty()
        || revision.len() > 19
        || revision.starts_with('0')
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
        || revision
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
    {
        return fail(ErrorCode::ClaimsInvalid);
    }
    Ok(revision.to_owned())
}

fn validate_claims(
    payload: &Map<String, Value>,
    options: &VerifyOptions,
    now: i64,
) -> Result<VerifiedClaims> {
    if payload.get("iss") != Some(&Value::String(options.issuer.clone())) {
        return fail(ErrorCode::IssuerMismatch);
    }
    let audience = match payload.get("aud") {
        Some(Value::String(value)) if !value.is_empty() => vec![value.clone()],
        Some(Value::Array(values)) if !values.is_empty() => values
            .iter()
            .map(|value| non_empty_string(Some(value)).map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or(VerificationError::new(ErrorCode::AudienceMismatch))?,
        _ => return fail(ErrorCode::AudienceMismatch),
    };
    if !audience.iter().any(|value| value == &options.audience) {
        return fail(ErrorCode::AudienceMismatch);
    }
    let (Some(subject), Some(expires_at), Some(issued_at)) = (
        non_empty_string(payload.get("sub")),
        exact_i64(payload.get("exp")),
        exact_i64(payload.get("iat")),
    ) else {
        return fail(ErrorCode::ClaimsInvalid);
    };
    let not_before = match payload.get("nbf") {
        Some(value) => {
            Some(exact_i64(Some(value)).ok_or(VerificationError::new(ErrorCode::ClaimsInvalid))?)
        }
        None => None,
    };
    if expires_at <= issued_at || expires_at - issued_at > 300 {
        return fail(ErrorCode::ClaimsInvalid);
    }
    let skew = i64::try_from(options.clock_skew.as_secs())
        .map_err(|_| VerificationError::new(ErrorCode::ConfigurationInvalid))?;
    if expires_at <= now.saturating_sub(skew) {
        return fail(ErrorCode::TokenExpired);
    }
    if not_before.is_some_and(|value| value > now.saturating_add(skew))
        || issued_at > now.saturating_add(skew)
    {
        return fail(ErrorCode::TokenNotActive);
    }

    let has_actions = payload.contains_key(ACTIONS);
    let has_revision = payload.contains_key(AUTHORIZATION_REVISION);
    if has_actions != has_revision {
        return fail(ErrorCode::ClaimsInvalid);
    }
    let (actions, authorization_revision) = if has_actions {
        (
            parse_actions(&payload[ACTIONS])?,
            Some(parse_revision(&payload[AUTHORIZATION_REVISION])?),
        )
    } else {
        (Vec::new(), None)
    };

    let has_kind = payload.contains_key(SUBJECT_KIND);
    let has_organization = payload.contains_key(ORGANIZATION_ID);
    if has_kind != has_organization {
        return fail(ErrorCode::ClaimsInvalid);
    }
    let derivative_flags = [
        payload.contains_key(SESSION_DERIVATIVE_AUTHORITY),
        payload.contains_key(SESSION_SOURCE_SUBJECT),
        payload.contains_key(SESSION_SOURCE_ORGANIZATION),
    ];
    if derivative_flags.windows(2).any(|pair| pair[0] != pair[1]) {
        return fail(ErrorCode::ClaimsInvalid);
    }
    let has_derivative = derivative_flags[0];

    let (kind, organization_id, binding, source_subject, source_organization) = if has_kind {
        let organization = non_empty_string(payload.get(ORGANIZATION_ID));
        if payload.get(SUBJECT_KIND) != Some(&Value::String("service_account".into()))
            || organization.is_none()
            || !has_actions
            || has_derivative
        {
            return fail(ErrorCode::ClaimsInvalid);
        }
        (
            SubjectKind::ServiceAccount,
            organization.map(str::to_owned),
            None,
            None,
            None,
        )
    } else {
        if has_actions && !has_derivative {
            return fail(ErrorCode::ClaimsInvalid);
        }
        let (binding, source_subject, source_organization) = if has_derivative {
            let binding = non_empty_string(payload.get(SESSION_DERIVATIVE_AUTHORITY));
            let source_subject = non_empty_string(payload.get(SESSION_SOURCE_SUBJECT));
            let source_organization = match payload.get(SESSION_SOURCE_ORGANIZATION) {
                Some(Value::Null) => None,
                Some(value) => Some(
                    non_empty_string(Some(value))
                        .ok_or(VerificationError::new(ErrorCode::ClaimsInvalid))?
                        .to_owned(),
                ),
                None => return fail(ErrorCode::ClaimsInvalid),
            };
            let (Some(binding), Some(source_subject)) = (binding, source_subject) else {
                return fail(ErrorCode::ClaimsInvalid);
            };
            if has_actions && source_organization.is_none() {
                return fail(ErrorCode::ClaimsInvalid);
            }
            (
                Some(binding.to_owned()),
                Some(source_subject.to_owned()),
                source_organization,
            )
        } else {
            (None, None, None)
        };
        (
            SubjectKind::Human,
            None,
            binding,
            source_subject,
            source_organization,
        )
    };

    Ok(VerifiedClaims {
        subject: subject.to_owned(),
        kind,
        issuer: options.issuer.clone(),
        audience,
        expires_at,
        issued_at,
        not_before,
        organization_id,
        actions,
        authorization_revision,
        session_derivative_authority: binding,
        source_subject_id: source_subject,
        source_organization_id: source_organization,
        raw: payload.clone(),
    })
}

#[derive(Clone, Debug)]
pub struct RemoteOptions {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: Option<String>,
    pub clock_skew: Duration,
    pub fetch_timeout: Duration,
    pub max_response_bytes: usize,
    pub cache_ttl: Duration,
    /// Enables HTTP only for literal `localhost` and parsed loopback IP addresses.
    pub allow_loopback_http: bool,
}

impl RemoteOptions {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            jwks_url: None,
            clock_skew: Duration::from_secs(30),
            fetch_timeout: Duration::from_secs(3),
            max_response_bytes: 1_048_576,
            cache_ttl: Duration::from_secs(300),
            allow_loopback_http: false,
        }
    }
}

struct Cache {
    keys: Vec<PublicKey>,
    expires_at: SystemTime,
    generation: u64,
    next_unknown_refresh_at: SystemTime,
    unknown_misses: HashMap<String, SystemTime>,
}

pub struct RemoteVerifier {
    options: VerifyOptions,
    jwks_url: Url,
    fetch_timeout: Duration,
    max_response_bytes: usize,
    cache_ttl: Duration,
    client: ureq::Agent,
    cache: Mutex<Option<Cache>>,
    #[cfg(test)]
    now: Mutex<SystemTime>,
}

impl RemoteVerifier {
    pub fn new(remote: RemoteOptions) -> Result<Self> {
        let options = VerifyOptions {
            issuer: remote.issuer,
            audience: remote.audience,
            clock_skew: remote.clock_skew,
            now: None,
        };
        validate_options(&options)?;
        let issuer = secure_url(&options.issuer, remote.allow_loopback_http)?;
        let jwks_url = match remote.jwks_url {
            Some(value) => secure_url(&value, remote.allow_loopback_http)?,
            None => issuer
                .join("/api/auth/jwks")
                .map_err(|_| VerificationError::new(ErrorCode::ConfigurationInvalid))?,
        };
        if remote.fetch_timeout < Duration::from_millis(100)
            || remote.fetch_timeout > Duration::from_secs(30)
            || !(1_024..=4_194_304).contains(&remote.max_response_bytes)
            || remote.cache_ttl < Duration::from_secs(1)
            || remote.cache_ttl > Duration::from_secs(3600)
        {
            return fail(ErrorCode::ConfigurationInvalid);
        }
        let client = ureq::AgentBuilder::new()
            .timeout(remote.fetch_timeout)
            .redirects(0)
            .build();
        Ok(Self {
            options,
            jwks_url,
            fetch_timeout: remote.fetch_timeout,
            max_response_bytes: remote.max_response_bytes,
            cache_ttl: remote.cache_ttl,
            client,
            cache: Mutex::new(None),
            #[cfg(test)]
            now: Mutex::new(SystemTime::now()),
        })
    }

    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            *cache = None;
        }
    }

    pub fn verify(&self, token: &str) -> Result<VerifiedClaims> {
        let parsed = parse_token(token)?;
        let (mut keys, generation, _) = self.load()?;
        if !keys.iter().any(|key| key.kid == parsed.kid) {
            keys = self.load_unknown(&parsed.kid, generation)?;
        }
        let mut options = self.options.clone();
        options.now = Some(self.now());
        let now = validate_options(&options)?;
        verify_parsed(&parsed, &keys, &options, now)
    }

    fn load(&self) -> Result<(Vec<PublicKey>, u64, bool)> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| VerificationError::new(ErrorCode::JwksUnavailable))?;
        if let Some(existing) = cache.as_ref() {
            if self.now() < existing.expires_at {
                return Ok((existing.keys.clone(), existing.generation, false));
            }
        }
        let keys = self.fetch_locked(&mut cache)?;
        let generation = cache.as_ref().expect("fetch populates cache").generation;
        Ok((keys, generation, true))
    }

    fn load_unknown(&self, kid: &str, observed_generation: u64) -> Result<Vec<PublicKey>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| VerificationError::new(ErrorCode::JwksUnavailable))?;
        let now = self.now();
        let Some(existing) = cache.as_mut() else {
            return fail(ErrorCode::JwksUnavailable);
        };
        if existing.keys.iter().any(|key| key.kid == kid) {
            return Ok(existing.keys.clone());
        }
        prune_unknown_misses(existing, now);
        if existing
            .unknown_misses
            .get(kid)
            .is_some_and(|until| now < *until)
        {
            return fail(ErrorCode::KeyNotFound);
        }
        if existing.generation != observed_generation || now < existing.next_unknown_refresh_at {
            remember_unknown_miss(existing, kid, now);
            return fail(ErrorCode::KeyNotFound);
        }
        existing.next_unknown_refresh_at = now
            .checked_add(UNKNOWN_MISS_TTL)
            .ok_or(VerificationError::new(ErrorCode::JwksUnavailable))?;
        let keys = self.fetch_locked(&mut cache)?;
        let refreshed = cache.as_mut().expect("fetch populates cache");
        if !keys.iter().any(|key| key.kid == kid) {
            remember_unknown_miss(refreshed, kid, now);
        }
        Ok(keys)
    }

    fn fetch_locked(&self, cache: &mut Option<Cache>) -> Result<Vec<PublicKey>> {
        let response = self
            .client
            .get(self.jwks_url.as_str())
            .set("Accept", "application/json")
            .call()
            .map_err(|_| VerificationError::new(ErrorCode::JwksUnavailable))?;
        if !(200..300).contains(&response.status()) {
            return fail(ErrorCode::JwksUnavailable);
        }
        if response
            .header("Content-Length")
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|size| size > self.max_response_bytes)
        {
            return fail(ErrorCode::JwksUnavailable);
        }
        let mut body = Vec::with_capacity(self.max_response_bytes.min(8192));
        response
            .into_reader()
            .take(u64::try_from(self.max_response_bytes + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut body)
            .map_err(|_| VerificationError::new(ErrorCode::JwksUnavailable))?;
        if body.len() > self.max_response_bytes {
            return fail(ErrorCode::JwksUnavailable);
        }
        let keys = parse_jwks(&body)?;
        let now = self.now();
        let expires_at = now
            .checked_add(self.cache_ttl)
            .ok_or(VerificationError::new(ErrorCode::JwksUnavailable))?;
        let generation = cache
            .as_ref()
            .map_or(1, |existing| existing.generation.saturating_add(1));
        let next_unknown_refresh_at = cache
            .as_ref()
            .map_or(UNIX_EPOCH, |existing| existing.next_unknown_refresh_at);
        let unknown_misses = cache
            .as_ref()
            .map_or_else(HashMap::new, |existing| existing.unknown_misses.clone());
        *cache = Some(Cache {
            keys: keys.clone(),
            expires_at,
            generation,
            next_unknown_refresh_at,
            unknown_misses,
        });
        Ok(keys)
    }

    pub fn fetch_timeout(&self) -> Duration {
        self.fetch_timeout
    }

    fn now(&self) -> SystemTime {
        #[cfg(test)]
        return *self.now.lock().expect("test clock lock");
        #[cfg(not(test))]
        SystemTime::now()
    }

    #[cfg(test)]
    fn set_now_for_test(&self, now: SystemTime) {
        *self.now.lock().expect("test clock lock") = now;
    }
}

fn prune_unknown_misses(cache: &mut Cache, now: SystemTime) {
    cache.unknown_misses.retain(|_, until| now < *until);
}

fn remember_unknown_miss(cache: &mut Cache, kid: &str, now: SystemTime) {
    prune_unknown_misses(cache, now);
    if cache.unknown_misses.contains_key(kid) {
        return;
    }
    if !cache.unknown_misses.contains_key(kid) && cache.unknown_misses.len() >= MAX_UNKNOWN_MISSES {
        if let Some(candidate) = cache.unknown_misses.keys().next().cloned() {
            cache.unknown_misses.remove(&candidate);
        }
    }
    if let Some(until) = now.checked_add(UNKNOWN_MISS_TTL) {
        cache.unknown_misses.insert(kid.to_owned(), until);
    }
}

fn secure_url(value: &str, allow_loopback_http: bool) -> Result<Url> {
    let parsed =
        Url::parse(value).map_err(|_| VerificationError::new(ErrorCode::ConfigurationInvalid))?;
    if parsed.host().is_none() {
        return fail(ErrorCode::ConfigurationInvalid);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return fail(ErrorCode::ConfigurationInvalid);
    }
    let loopback = match parsed.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.octets()[0] == 127,
        Some(Host::Ipv6(address)) => address == std::net::Ipv6Addr::LOCALHOST,
        None => false,
    };
    if parsed.scheme() != "https" && !(allow_loopback_http && parsed.scheme() == "http" && loopback)
    {
        return fail(ErrorCode::ConfigurationInvalid);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{
        io::Write as _,
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
    };

    #[derive(Deserialize)]
    struct Fixture {
        now: i64,
        issuer: String,
        audience: String,
        jwks: Value,
        rotated_jwks: Value,
        #[serde(default)]
        jwks_cases: Vec<FixtureJwksCase>,
        #[serde(default)]
        remote_cases: Vec<FixtureRemoteCase>,
        cases: Vec<FixtureCase>,
    }

    #[derive(Deserialize)]
    struct FixtureCase {
        name: String,
        valid: bool,
        kind: Option<String>,
        error: Option<String>,
        token: String,
    }

    #[derive(Deserialize)]
    struct FixtureJwksCase {
        name: String,
        error: String,
        token: String,
        jwks_json: String,
    }

    #[derive(Deserialize)]
    struct FixtureRemoteCase {
        name: String,
        token: String,
        #[serde(default)]
        sequential_token: String,
        #[serde(default)]
        concurrent_requests: usize,
        #[serde(default)]
        expected_fetches: usize,
        #[serde(default)]
        cache_ttl_seconds: u64,
        #[serde(default)]
        normal_refresh_after_seconds: u64,
        #[serde(default)]
        cooldown_seconds: u64,
        #[serde(default)]
        repeated_requests_after_seconds: u64,
        #[serde(default)]
        repeated_requests_inside_cooldown: usize,
        #[serde(default)]
        expected_fetches_before_normal_refresh: usize,
        #[serde(default)]
        expected_fetches_after_repeated_requests: usize,
        #[serde(default)]
        expected_fetches_after_normal_refresh: usize,
        #[serde(default)]
        expected_fetches_after_rotation: usize,
        error: String,
    }

    #[test]
    fn shared_conformance_fixture() {
        let fixture: Fixture = serde_json::from_str(include_str!("../../conformance/fixture.json"))
            .expect("shared fixture must be valid JSON");
        let jwks = serde_json::to_vec(&fixture.jwks).expect("fixture JWKS serializes");
        for case in &fixture.cases {
            let options = VerifyOptions {
                issuer: fixture.issuer.clone(),
                audience: fixture.audience.clone(),
                clock_skew: Duration::ZERO,
                now: Some(UNIX_EPOCH + Duration::from_secs(fixture.now as u64)),
            };
            let outcome = verify(&case.token, &jwks, &options);
            if case.valid {
                let claims = outcome.unwrap_or_else(|error| panic!("{}: {error}", case.name));
                let expected = match case.kind.as_deref() {
                    Some("human") => SubjectKind::Human,
                    Some("service_account") => SubjectKind::ServiceAccount,
                    _ => panic!("{}: unexpected valid kind", case.name),
                };
                assert_eq!(claims.kind, expected, "{}", case.name);
            } else {
                let error = outcome.expect_err(&format!("{} should fail", case.name));
                assert_eq!(
                    error.code.as_str(),
                    case.error.as_deref().unwrap(),
                    "{}",
                    case.name
                );
            }
        }
        for case in &fixture.jwks_cases {
            let options = VerifyOptions {
                issuer: fixture.issuer.clone(),
                audience: fixture.audience.clone(),
                clock_skew: Duration::ZERO,
                now: Some(UNIX_EPOCH + Duration::from_secs(fixture.now as u64)),
            };
            let error = verify(&case.token, case.jwks_json.as_bytes(), &options)
                .expect_err(&format!("{} should fail", case.name));
            assert_eq!(error.code.as_str(), case.error, "{}", case.name);
        }
    }

    #[test]
    fn remote_unknown_kid_is_singleflight_and_lookalike_hosts_are_rejected() {
        assert!(secure_url("http://127.attacker.example:8787", true).is_err());
        assert!(secure_url("http://127.0.0.1:8787", true).is_ok());
        assert!(secure_url("http://api.localhost:8787", true).is_err());
        assert!(secure_url("http://[::1]:8787", true).is_ok());
        assert!(secure_url("http://[::ffff:127.0.0.1]:8787", true).is_err());

        let fixture: Fixture = serde_json::from_str(include_str!("../../conformance/fixture.json"))
            .expect("shared fixture must be valid JSON");
        assert_eq!(fixture.remote_cases.len(), 2, "remote fixture scenarios");
        let remote_case = &fixture.remote_cases[0];
        let body = Arc::new(Mutex::new(
            serde_json::to_vec(&fixture.jwks).expect("fixture JWKS serializes"),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener
            .set_nonblocking(true)
            .expect("make test server nonblocking");
        let address = listener.local_addr().expect("test server address");
        let requests = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let server_requests = Arc::clone(&requests);
        let server_done = Arc::clone(&done);
        let server_body = Arc::clone(&body);
        let server = thread::spawn(move || {
            while !server_done.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut request = [0_u8; 4096];
                        let _ = stream.read(&mut request);
                        server_requests.fetch_add(1, Ordering::SeqCst);
                        let body = server_body.lock().expect("server body lock").clone();
                        let response = format!(
                            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                            body.len(),
                        );
                        stream
                            .write_all(response.as_bytes())
                            .expect("write response headers");
                        stream.write_all(&body).expect("write response body");
                        stream.flush().expect("flush response");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("test server failed: {error}"),
                }
            }
        });

        let mut remote = RemoteOptions::new(fixture.issuer.clone(), fixture.audience.clone());
        remote.jwks_url = Some(format!("http://{address}"));
        remote.allow_loopback_http = true;
        remote.clock_skew = Duration::ZERO;
        let verifier = Arc::new(RemoteVerifier::new(remote).expect("create verifier"));
        let workers: Vec<_> = (0..remote_case.concurrent_requests)
            .map(|_| {
                let verifier = Arc::clone(&verifier);
                let token = remote_case.token.clone();
                let expected_error = remote_case.error.clone();
                thread::spawn(move || {
                    let error = verifier.verify(&token).expect_err("unknown kid must fail");
                    assert_eq!(error.code.as_str(), expected_error);
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("verification worker");
        }
        assert_eq!(
            requests.load(Ordering::SeqCst),
            remote_case.expected_fetches,
            "remote scenario {} requests",
            remote_case.name,
        );
        assert_eq!(
            verifier
                .verify(&remote_case.sequential_token)
                .expect_err("sequential unknown kid")
                .code,
            ErrorCode::KeyNotFound,
        );
        assert_eq!(
            requests.load(Ordering::SeqCst),
            remote_case.expected_fetches
        );

        let rotation_case = &fixture.remote_cases[1];
        requests.store(0, Ordering::SeqCst);
        *body.lock().expect("server body lock") =
            serde_json::to_vec(&fixture.jwks).expect("fixture JWKS serializes");
        let mut rotation_remote =
            RemoteOptions::new(fixture.issuer.clone(), fixture.audience.clone());
        rotation_remote.jwks_url = Some(format!("http://{address}"));
        rotation_remote.allow_loopback_http = true;
        rotation_remote.clock_skew = Duration::ZERO;
        rotation_remote.cache_ttl = Duration::from_secs(rotation_case.cache_ttl_seconds);
        let rotation_verifier =
            RemoteVerifier::new(rotation_remote).expect("create rotation verifier");
        let start = UNIX_EPOCH + Duration::from_secs(fixture.now as u64);
        rotation_verifier.set_now_for_test(start);
        assert_eq!(
            rotation_verifier
                .verify(&rotation_case.token)
                .expect_err("initial rotated kid missing")
                .code,
            ErrorCode::KeyNotFound,
        );
        assert_eq!(
            requests.load(Ordering::SeqCst),
            rotation_case.expected_fetches_before_normal_refresh,
        );
        rotation_verifier.set_now_for_test(
            start + Duration::from_secs(rotation_case.normal_refresh_after_seconds),
        );
        rotation_verifier
            .verify(&fixture.cases[0].token)
            .expect("normal TTL refresh must work during cooldown");
        assert_eq!(
            requests.load(Ordering::SeqCst),
            rotation_case.expected_fetches_after_normal_refresh,
        );
        rotation_verifier.set_now_for_test(
            start + Duration::from_secs(rotation_case.repeated_requests_after_seconds),
        );
        for _ in 0..rotation_case.repeated_requests_inside_cooldown {
            assert_eq!(
                rotation_verifier
                    .verify(&rotation_case.token)
                    .expect_err("repeated rotated kid remains cooled down")
                    .code,
                ErrorCode::KeyNotFound,
            );
        }
        assert_eq!(
            requests.load(Ordering::SeqCst),
            rotation_case.expected_fetches_after_repeated_requests,
        );
        *body.lock().expect("server body lock") =
            serde_json::to_vec(&fixture.rotated_jwks).expect("rotated JWKS serializes");
        rotation_verifier
            .set_now_for_test(start + Duration::from_secs(rotation_case.cooldown_seconds));
        rotation_verifier
            .verify(&rotation_case.token)
            .unwrap_or_else(|error| {
                panic!(
                    "rotated key must recover after cooldown ({error}, requests={})",
                    requests.load(Ordering::SeqCst)
                )
            });
        assert_eq!(
            requests.load(Ordering::SeqCst),
            rotation_case.expected_fetches_after_rotation,
        );
        done.store(true, Ordering::SeqCst);
        server.join().expect("test server");
    }
}
