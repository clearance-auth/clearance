"""Strict Clearance ES256 access-token verification."""

from __future__ import annotations

import base64
import ipaddress
import json
import math
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

SESSION_DERIVATIVE = "urn:clearance:claims:session-derivative-authority"
SOURCE_SUBJECT = "urn:clearance:claims:session-source-subject"
SOURCE_ORGANIZATION = "urn:clearance:claims:session-source-organization"
SUBJECT_KIND = "urn:clearance:claims:subject-kind"
ORGANIZATION_ID = "urn:clearance:claims:organization-id"
ACTIONS = "actions"
AUTHORIZATION_REVISION = "authz_revision"

_ERROR_MESSAGES = {
    "token_malformed": "Access token is malformed",
    "algorithm_rejected": "Access token algorithm is not allowed",
    "key_not_found": "Access token verification key was not found",
    "jwks_invalid": "Verification key set is invalid",
    "jwks_unavailable": "Verification key set is unavailable",
    "signature_invalid": "Access token signature is invalid",
    "issuer_mismatch": "Access token issuer does not match",
    "audience_mismatch": "Access token audience does not match",
    "token_expired": "Access token has expired",
    "token_not_active": "Access token is not active",
    "claims_invalid": "Access token claims are invalid",
    "configuration_invalid": "Verifier configuration is invalid",
}


class VerificationError(ValueError):
    """Stable, non-secret token-verification failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True)
class VerifiedClaims:
    subject: str
    kind: str
    issuer: str
    audience: str | tuple[str, ...]
    expires_at: int
    issued_at: int
    not_before: int | None
    organization_id: str | None
    actions: tuple[str, ...]
    authorization_revision: str | None
    session_derivative_authority: str | None
    source_subject_id: str | None
    source_organization_id: str | None
    raw: Mapping[str, Any]


_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_KID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ACTION = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_REVISION = re.compile(r"^[1-9][0-9]*$")
_MAX_BIGINT = 9_223_372_036_854_775_807
_MAX_TOKEN = 16_384
_MAX_JSON = 12_288
_MAX_ACTIONS = 256
_MAX_KEYS = 32
_MAX_TOKEN_LIFETIME_SECONDS = 300
_UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS = 30.0
_MAX_UNKNOWN_KID_MISSES = 64


def _fail(code: str) -> None:
    raise VerificationError(code)


def _b64decode(value: str, code: str = "token_malformed") -> bytes:
    if (
        not value
        or "=" in value
        or _B64URL.fullmatch(value) is None
        or len(value) % 4 == 1
    ):
        _fail(code)
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        _fail(code)
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        _fail(code)
    return decoded


def _object_no_duplicates(
    pairs: Sequence[tuple[str, Any]], code: str
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(code)
        result[key] = value
    return result


def _json_object(raw: bytes, code: str) -> dict[str, Any]:
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=lambda pairs: _object_no_duplicates(pairs, code),
            parse_constant=lambda _value: _fail(code),
        )
    except VerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        _fail(code)
    if not isinstance(parsed, dict):
        _fail(code)
    return parsed


def _json_segment(value: str) -> dict[str, Any]:
    raw = _b64decode(value)
    if len(raw) > _MAX_JSON:
        _fail("token_malformed")
    return _json_object(raw, "token_malformed")


def _parse_token(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    if not isinstance(token, str) or len(token.encode("utf-8")) > _MAX_TOKEN:
        _fail("token_malformed")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        _fail("token_malformed")
    header = _json_segment(parts[0])
    if header.get("alg") != "ES256":
        _fail("algorithm_rejected")
    if (
        set(header) - {"alg", "kid", "typ"}
        or not isinstance(header.get("kid"), str)
        or _KID.fullmatch(header["kid"]) is None
        or ("typ" in header and header["typ"] != "JWT")
    ):
        _fail("token_malformed")
    signature = _b64decode(parts[2])
    if len(signature) != 64:
        _fail("signature_invalid")
    return header, _json_segment(parts[1]), f"{parts[0]}.{parts[1]}".encode(), signature


def _parse_jwks(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
        _fail("jwks_invalid")
    candidates = value["keys"]
    if not 1 <= len(candidates) <= _MAX_KEYS:
        _fail("jwks_invalid")
    seen: set[str] = set()
    keys: list[dict[str, Any]] = []
    allowed_members = {"kty", "crv", "x", "y", "kid", "use", "alg", "key_ops"}
    for candidate in candidates:
        if (
            not isinstance(candidate, dict)
            or set(candidate) - allowed_members
            or candidate.get("kty") != "EC"
            or candidate.get("crv") != "P-256"
            or candidate.get("use") != "sig"
            or candidate.get("alg") != "ES256"
            or not isinstance(candidate.get("kid"), str)
            or _KID.fullmatch(candidate["kid"]) is None
            or not isinstance(candidate.get("x"), str)
            or not isinstance(candidate.get("y"), str)
            or "d" in candidate
            or candidate.get("key_ops", ["verify"]) != ["verify"]
            or candidate["kid"] in seen
        ):
            _fail("jwks_invalid")
        x_bytes = _b64decode(candidate["x"], "jwks_invalid")
        y_bytes = _b64decode(candidate["y"], "jwks_invalid")
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            _fail("jwks_invalid")
        x, y = int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big")
        try:
            public_key = ec.EllipticCurvePublicNumbers(
                x, y, ec.SECP256R1()
            ).public_key()
        except ValueError:
            _fail("jwks_invalid")
        seen.add(candidate["kid"])
        keys.append({**candidate, "_public_key": public_key})
    return tuple(keys)


def _verify_signature(key: Mapping[str, Any], message: bytes, signature: bytes) -> None:
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        der_signature = utils.encode_dss_signature(r, s)
        public_key = key["_public_key"]
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            _fail("jwks_invalid")
        public_key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        _fail("signature_invalid")


def _actions(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_ACTIONS
        or any(
            not isinstance(action, str)
            or _ACTION.fullmatch(action) is None
            or (index and action <= value[index - 1])
            for index, action in enumerate(value)
        )
    ):
        _fail("claims_invalid")
    return tuple(value)


def _revision(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _REVISION.fullmatch(value) is None
        or len(value) > len(str(_MAX_BIGINT))
        or int(value) > _MAX_BIGINT
    ):
        _fail("claims_invalid")
    return value


def _non_empty(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _claims(
    payload: dict[str, Any],
    *,
    issuer: str,
    audience: str,
    now: int,
    clock_skew_seconds: int,
) -> VerifiedClaims:
    if payload.get("iss") != issuer:
        _fail("issuer_mismatch")
    audiences = payload.get("aud")
    if isinstance(audiences, str):
        audience_values = (audiences,)
    elif (
        isinstance(audiences, list)
        and audiences
        and all(_non_empty(item) for item in audiences)
    ):
        audience_values = tuple(audiences)
    else:
        _fail("audience_mismatch")
    if audience not in audience_values:
        _fail("audience_mismatch")

    sub, exp, iat, nbf = (
        payload.get("sub"),
        payload.get("exp"),
        payload.get("iat"),
        payload.get("nbf"),
    )
    if (
        not _non_empty(sub)
        or isinstance(exp, bool)
        or not isinstance(exp, int)
        or isinstance(iat, bool)
        or not isinstance(iat, int)
        or (nbf is not None and (isinstance(nbf, bool) or not isinstance(nbf, int)))
        or exp <= iat
        or exp - iat > _MAX_TOKEN_LIFETIME_SECONDS
    ):
        _fail("claims_invalid")
    if exp <= now - clock_skew_seconds:
        _fail("token_expired")
    if (nbf is not None and nbf > now + clock_skew_seconds) or iat > now + clock_skew_seconds:
        _fail("token_not_active")

    has_actions, has_revision = ACTIONS in payload, AUTHORIZATION_REVISION in payload
    if has_actions != has_revision:
        _fail("claims_invalid")
    actions = _actions(payload[ACTIONS]) if has_actions else ()
    revision = _revision(payload[AUTHORIZATION_REVISION]) if has_revision else None

    has_kind, has_org = SUBJECT_KIND in payload, ORGANIZATION_ID in payload
    if has_kind != has_org:
        _fail("claims_invalid")
    derivative_flags = tuple(
        claim in payload
        for claim in (SESSION_DERIVATIVE, SOURCE_SUBJECT, SOURCE_ORGANIZATION)
    )
    if len(set(derivative_flags)) != 1:
        _fail("claims_invalid")
    has_derivative = derivative_flags[0]

    if has_kind:
        if (
            payload[SUBJECT_KIND] != "service_account"
            or not _non_empty(payload[ORGANIZATION_ID])
            or not has_actions
            or has_derivative
        ):
            _fail("claims_invalid")
        kind, organization_id = "service_account", payload[ORGANIZATION_ID]
        binding = source_subject = source_organization = None
    else:
        if has_actions and not has_derivative:
            _fail("claims_invalid")
        if has_derivative and (
            not _non_empty(payload[SESSION_DERIVATIVE])
            or not _non_empty(payload[SOURCE_SUBJECT])
            or (
                payload[SOURCE_ORGANIZATION] is not None
                and not _non_empty(payload[SOURCE_ORGANIZATION])
            )
        ):
            _fail("claims_invalid")
        if has_actions and not _non_empty(payload[SOURCE_ORGANIZATION]):
            _fail("claims_invalid")
        kind, organization_id = "human", None
        binding = payload.get(SESSION_DERIVATIVE)
        source_subject = payload.get(SOURCE_SUBJECT)
        source_organization = payload.get(SOURCE_ORGANIZATION)

    return VerifiedClaims(
        subject=sub,
        kind=kind,
        issuer=issuer,
        audience=audience_values[0] if len(audience_values) == 1 else audience_values,
        expires_at=exp,
        issued_at=iat,
        not_before=nbf,
        organization_id=organization_id,
        actions=actions,
        authorization_revision=revision,
        session_derivative_authority=binding,
        source_subject_id=source_subject,
        source_organization_id=source_organization,
        raw=MappingProxyType(payload.copy()),
    )


def verify(
    token: str,
    jwks: Any,
    *,
    issuer: str,
    audience: str,
    now: int | None = None,
    clock_skew_seconds: int = 30,
) -> VerifiedClaims:
    """Verify one token against an already trusted JWKS document."""
    _validate_configuration(issuer, audience, now, clock_skew_seconds)
    header, payload, signing_input, signature = _parse_token(token)
    keys = _parse_jwks(jwks)
    key = next((item for item in keys if item["kid"] == header["kid"]), None)
    if key is None:
        _fail("key_not_found")
    _verify_signature(key, signing_input, signature)
    return _claims(
        payload,
        issuer=issuer,
        audience=audience,
        now=int(time.time()) if now is None else now,
        clock_skew_seconds=clock_skew_seconds,
    )


def _validate_configuration(
    issuer: str, audience: str, now: int | None, clock_skew_seconds: int
) -> None:
    if (
        not _non_empty(issuer)
        or not _non_empty(audience)
        or isinstance(clock_skew_seconds, bool)
        or not isinstance(clock_skew_seconds, int)
        or not 0 <= clock_skew_seconds <= 300
        or (
            now is not None
            and (isinstance(now, bool) or not isinstance(now, int) or now < 0)
        )
    ):
        _fail("configuration_invalid")


def _secure_url(value: str, *, allow_insecure_loopback: bool) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError:
        _fail("configuration_invalid")
    host = (parsed.hostname or "").lower()
    try:
        loopback_ip = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback_ip = False
    loopback = host == "localhost" or loopback_ip
    if (
        not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.scheme not in ("http", "https")
        or (
            parsed.scheme == "http"
            and (not allow_insecure_loopback or not loopback)
        )
    ):
        _fail("configuration_invalid")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


@dataclass
class _CachedJWKS:
    expires_at: float
    generation: int
    keys: tuple[dict[str, Any], ...]
    unknown_kid_misses: dict[str, float]


class RemoteVerifier:
    """Bounded remote-JWKS verifier with one unknown-kid refresh."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str | None = None,
        allow_insecure_loopback: bool = False,
        clock_skew_seconds: int = 30,
        fetch_timeout_seconds: float = 3.0,
        max_response_bytes: int = 1_048_576,
        cache_ttl_seconds: int = 300,
    ) -> None:
        _validate_configuration(issuer, audience, None, clock_skew_seconds)
        if not isinstance(allow_insecure_loopback, bool):
            _fail("configuration_invalid")
        self.issuer = _secure_url(
            issuer, allow_insecure_loopback=allow_insecure_loopback
        )
        self.audience = audience
        self.jwks_url = _secure_url(
            jwks_url
            or urllib.parse.urljoin(issuer.rstrip("/") + "/", "/api/auth/jwks"),
            allow_insecure_loopback=allow_insecure_loopback,
        )
        if (
            not isinstance(fetch_timeout_seconds, (int, float))
            or isinstance(fetch_timeout_seconds, bool)
            or not math.isfinite(fetch_timeout_seconds)
            or not 0.1 <= fetch_timeout_seconds <= 30
            or isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or not 1_024 <= max_response_bytes <= 4_194_304
            or isinstance(cache_ttl_seconds, bool)
            or not isinstance(cache_ttl_seconds, int)
            or not 1 <= cache_ttl_seconds <= 3_600
        ):
            _fail("configuration_invalid")
        self.clock_skew_seconds = clock_skew_seconds
        self.fetch_timeout_seconds = float(fetch_timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: _CachedJWKS | None = None
        self._generation = 0
        self._next_unknown_refresh_at = 0.0
        self._lock = threading.Lock()
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._monotonic = time.monotonic
        self._time = time.time

    def clear_cache(self) -> None:
        with self._lock:
            self._cache = None
            self._generation += 1
            self._next_unknown_refresh_at = 0.0

    def _load(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            monotonic_now = self._monotonic()
            if self._cache and self._cache.expires_at > monotonic_now:
                return self._cache.keys
            return self._fetch_locked({})

    def _current_generation(self) -> int:
        with self._lock:
            return self._generation

    def _remember_unknown_kid(
        self, cache: _CachedJWKS, kid: str, monotonic_now: float
    ) -> bool:
        for missed_kid, expires_at in tuple(cache.unknown_kid_misses.items()):
            if expires_at <= monotonic_now:
                del cache.unknown_kid_misses[missed_kid]
        cooldown_until = cache.unknown_kid_misses.get(kid)
        if cooldown_until is not None and monotonic_now < cooldown_until:
            return False
        if (
            cooldown_until is None
            and len(cache.unknown_kid_misses) >= _MAX_UNKNOWN_KID_MISSES
        ):
            return False
        cache.unknown_kid_misses[kid] = (
            monotonic_now + _UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS
        )
        return True

    def _load_unknown(
        self, kid: str, observed_generation: int
    ) -> tuple[dict[str, Any], ...]:
        with self._lock:
            monotonic_now = self._monotonic()
            cache = self._cache
            if cache is None:
                return self._fetch_locked({})
            if any(key["kid"] == kid for key in cache.keys):
                return cache.keys
            if cache.generation != observed_generation:
                self._remember_unknown_kid(cache, kid, monotonic_now)
                return cache.keys
            if monotonic_now < self._next_unknown_refresh_at:
                self._remember_unknown_kid(cache, kid, monotonic_now)
                _fail("key_not_found")
            if not self._remember_unknown_kid(cache, kid, monotonic_now):
                _fail("key_not_found")
            self._next_unknown_refresh_at = (
                monotonic_now + _UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS
            )
            return self._fetch_locked({kid: cache.unknown_kid_misses[kid]})

    def _fetch_locked(
        self, unknown_kid_misses: Mapping[str, float]
    ) -> tuple[dict[str, Any], ...]:
        preserved_misses = (
            dict(self._cache.unknown_kid_misses) if self._cache else {}
        )
        preserved_misses.update(unknown_kid_misses)
        request = urllib.request.Request(
            self.jwks_url,
            method="GET",
            headers={"Accept": "application/json"},
        )
        try:
            with self._opener.open(request, timeout=self.fetch_timeout_seconds) as response:
                declared = response.headers.get("Content-Length")
                if declared is not None and int(declared) > self.max_response_bytes:
                    _fail("jwks_unavailable")
                body = response.read(self.max_response_bytes + 1)
                if len(body) > self.max_response_bytes:
                    _fail("jwks_unavailable")
        except VerificationError:
            raise
        except (OSError, ValueError, urllib.error.HTTPError, urllib.error.URLError):
            _fail("jwks_unavailable")
        value = _json_object(body, "jwks_invalid")
        keys = _parse_jwks(value)
        self._generation += 1
        self._cache = _CachedJWKS(
            expires_at=self._monotonic() + self.cache_ttl_seconds,
            generation=self._generation,
            keys=keys,
            unknown_kid_misses=preserved_misses,
        )
        return keys

    def verify(self, token: str) -> VerifiedClaims:
        header, payload, signing_input, signature = _parse_token(token)
        keys = self._load()
        observed_generation = self._current_generation()
        key = next((item for item in keys if item["kid"] == header["kid"]), None)
        if key is None:
            keys = self._load_unknown(header["kid"], observed_generation)
            key = next((item for item in keys if item["kid"] == header["kid"]), None)
        if key is None:
            _fail("key_not_found")
        _verify_signature(key, signing_input, signature)
        return _claims(
            payload,
            issuer=self.issuer,
            audience=self.audience,
            now=int(self._time()),
            clock_skew_seconds=self.clock_skew_seconds,
        )


__all__ = [
    "RemoteVerifier",
    "VerificationError",
    "VerifiedClaims",
    "verify",
]
