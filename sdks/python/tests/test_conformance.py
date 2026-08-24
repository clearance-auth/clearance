import json
import pathlib
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[1] / "src")
)

from clearance_verification import RemoteVerifier, VerificationError, verify
from clearance_verification import _json_object, _revision


class _StaticResponse:
    def __init__(self, body: bytes) -> None:
        self.headers = {"Content-Length": str(len(body))}
        self._body = body

    def __enter__(self) -> "_StaticResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._body


class _StaticOpener:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.requests = 0
        self._lock = threading.Lock()

    def open(self, *_: object, **__: object) -> _StaticResponse:
        with self._lock:
            self.requests += 1
            body = self._body
        return _StaticResponse(body)

    def set_body(self, body: bytes) -> None:
        with self._lock:
            self._body = body


class ConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_path = (
            pathlib.Path(__file__).resolve().parents[2]
            / "conformance"
            / "fixture.json"
        )
        cls.fixture = json.loads(fixture_path.read_text())

    def test_shared_fixture(self) -> None:
        fixture = self.fixture
        for example in fixture["cases"]:
            with self.subTest(example["name"]):
                if example["valid"]:
                    claims = verify(
                        example["token"],
                        fixture["jwks"],
                        issuer=fixture["issuer"],
                        audience=fixture["audience"],
                        now=fixture["now"],
                        clock_skew_seconds=0,
                    )
                    self.assertEqual(example["kind"], claims.kind)
                else:
                    with self.assertRaises(VerificationError) as caught:
                        verify(
                            example["token"],
                            fixture["jwks"],
                            issuer=fixture["issuer"],
                            audience=fixture["audience"],
                            now=fixture["now"],
                            clock_skew_seconds=0,
                        )
                    self.assertEqual(example["error"], caught.exception.code)

    def test_duplicate_jwks_fixture(self) -> None:
        fixture = self.fixture
        for example in fixture["jwks_cases"]:
            with self.subTest(example["name"]):
                verifier = RemoteVerifier(
                    issuer=fixture["issuer"], audience=fixture["audience"]
                )
                verifier._opener = _StaticOpener(example["jwks_json"].encode())
                with self.assertRaises(VerificationError) as caught:
                    verifier.verify(example["token"])
                self.assertEqual(example["error"], caught.exception.code)

    def test_rejects_off_curve_and_bounded_signatures(self) -> None:
        fixture = self.fixture
        valid_token = fixture["cases"][0]["token"]
        off_curve = json.loads(json.dumps(fixture["jwks"]))
        off_curve["keys"][0]["x"] = "A" * 43
        with self.assertRaises(VerificationError) as caught:
            verify(
                valid_token,
                off_curve,
                issuer=fixture["issuer"],
                audience=fixture["audience"],
                now=fixture["now"],
                clock_skew_seconds=0,
            )
        self.assertEqual("jwks_invalid", caught.exception.code)

        header, payload, _signature = valid_token.split(".")
        zero_signature = f"{header}.{payload}.{'A' * 86}"
        with self.assertRaises(VerificationError) as caught:
            verify(
                zero_signature,
                fixture["jwks"],
                issuer=fixture["issuer"],
                audience=fixture["audience"],
                now=fixture["now"],
                clock_skew_seconds=0,
            )
        self.assertEqual("signature_invalid", caught.exception.code)

        oversized_signature = f"{header}.{payload}.{'A' * 16_384}"
        with self.assertRaises(VerificationError) as caught:
            verify(
                oversized_signature,
                fixture["jwks"],
                issuer=fixture["issuer"],
                audience=fixture["audience"],
                now=fixture["now"],
                clock_skew_seconds=0,
            )
        self.assertEqual("token_malformed", caught.exception.code)

    def test_loopback_validation_parses_the_host(self) -> None:
        with self.assertRaises(VerificationError) as caught:
            RemoteVerifier(
                issuer="http://127.attacker.example:8787",
                audience="https://api.clearance.test",
                allow_insecure_loopback=True,
            )
        self.assertEqual("configuration_invalid", caught.exception.code)
        RemoteVerifier(
            issuer="http://127.0.0.1:8787",
            audience="https://api.clearance.test",
            allow_insecure_loopback=True,
        )
        with self.assertRaises(VerificationError):
            RemoteVerifier(
                issuer="http://sdk.localhost:8787",
                audience="https://api.clearance.test",
                allow_insecure_loopback=True,
            )
        RemoteVerifier(
            issuer="http://[::1]:8787",
            audience="https://api.clearance.test",
            allow_insecure_loopback=True,
        )

    def test_malformed_json_numbers_and_revisions_have_stable_codes(self) -> None:
        for raw in (
            b'{"keys":NaN}',
            b'{"keys":Infinity}',
            b'{"keys":-Infinity}',
            b'{"keys":' + b"9" * 5_000 + b"}",
        ):
            with self.subTest(raw=raw), self.assertRaises(VerificationError) as caught:
                _json_object(raw, "jwks_invalid")
            self.assertEqual("jwks_invalid", caught.exception.code)

        for revision in ("0", "9" * 20, "x", 1):
            with self.subTest(revision=revision), self.assertRaises(VerificationError) as caught:
                _revision(revision)
            self.assertEqual("claims_invalid", caught.exception.code)

    def test_unknown_kid_refresh_is_global_and_coalesced(self) -> None:
        fixture = self.fixture
        opener = _StaticOpener(json.dumps(fixture["jwks"]).encode())
        verifier = RemoteVerifier(
            issuer=fixture["issuer"], audience=fixture["audience"]
        )
        verifier._opener = opener
        scenario = next(
            case
            for case in fixture["remote_cases"]
            if case["name"] == "unknown_kid_global_cooldown"
        )
        unknown = scenario["token"]
        def attempt() -> str:
            try:
                verifier.verify(unknown)
            except VerificationError as error:
                return error.code
            return "unexpected_success"

        verifier._load()
        self.assertEqual(1, opener.requests)
        with ThreadPoolExecutor(max_workers=scenario["concurrent_requests"]) as executor:
            self.assertEqual(
                [scenario["error"]] * scenario["concurrent_requests"],
                list(
                    executor.map(
                        lambda _: attempt(), range(scenario["concurrent_requests"])
                    )
                ),
            )
        self.assertEqual(scenario["expected_fetches"], opener.requests)
        with self.assertRaises(VerificationError) as caught:
            verifier.verify(scenario["sequential_token"])
        self.assertEqual(scenario["error"], caught.exception.code)
        self.assertEqual(scenario["expected_fetches"], opener.requests)

    def test_rotation_recovers_after_global_cooldown_without_blocking_ttl_refresh(self) -> None:
        fixture = self.fixture
        scenario = next(
            case
            for case in fixture["remote_cases"]
            if case["name"] == "post_cooldown_rotation_recovery"
        )
        clock = [0.0]
        opener = _StaticOpener(json.dumps(fixture["jwks"]).encode())
        verifier = RemoteVerifier(
            issuer=fixture["issuer"],
            audience=fixture["audience"],
            cache_ttl_seconds=scenario["cache_ttl_seconds"],
        )
        verifier._opener = opener
        verifier._monotonic = lambda: clock[0]
        verifier._time = lambda: fixture["now"] + clock[0]
        with self.assertRaises(VerificationError) as caught:
            verifier.verify(scenario["token"])
        self.assertEqual(scenario["error"], caught.exception.code)
        self.assertEqual(scenario["expected_fetches_before_normal_refresh"], opener.requests)
        clock[0] += scenario["normal_refresh_after_seconds"]
        self.assertEqual("human", verifier.verify(fixture["cases"][0]["token"]).kind)
        self.assertEqual(scenario["expected_fetches_after_normal_refresh"], opener.requests)
        clock[0] = float(scenario["repeated_requests_after_seconds"])
        for _ in range(scenario["repeated_requests_inside_cooldown"]):
            with self.assertRaises(VerificationError) as caught:
                verifier.verify(scenario["token"])
            self.assertEqual(scenario["error"], caught.exception.code)
        self.assertEqual(scenario["expected_fetches_after_repeated_requests"], opener.requests)
        opener.set_body(json.dumps(fixture["rotated_jwks"]).encode())
        clock[0] = float(scenario["cooldown_seconds"])
        self.assertEqual("human", verifier.verify(scenario["token"]).kind)
        self.assertEqual(scenario["expected_fetches_after_rotation"], opener.requests)


if __name__ == "__main__":
    unittest.main()
