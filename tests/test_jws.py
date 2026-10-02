"""Unit tests for acme_adcs_ra.jws — JWS and EAB verification only (no signing)."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from acme_adcs_ra.jws import (
    JWSValidationError,
    UnsupportedAlgorithmError,
    _base64url_encode,
    _public_key_from_jwk,
    verify_eab_jws,
    verify_flattened_jws,
)


def _b64url_encode_dict(obj: dict) -> str:
    return _base64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _make_jws_payload(payload: dict) -> str:
    return _b64url_encode_dict(payload)


@pytest.fixture()
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


class TestJWSVerify:
    def test_valid_rs256(self, rsa_key: rsa.RSAPrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "RS256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = rsa_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature),
        }
        result = verify_flattened_jws(jws, rsa_key.public_key())
        assert json.loads(result) == payload

    def test_valid_es256(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "ES256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        # cryptography returns DER; our verifier expects raw R||S.
        der_sig = ec_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        raw_sig = _der_to_raw(der_sig, 32)
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(raw_sig),
        }
        result = verify_flattened_jws(jws, ec_key.public_key())
        assert json.loads(result) == payload

    def test_invalid_signature_rs256(self, rsa_key: rsa.RSAPrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "RS256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = rsa_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature + b"\x00"),
        }
        with pytest.raises(JWSValidationError, match="signature verification failed"):
            verify_flattened_jws(jws, rsa_key.public_key())

    def test_wrong_alg_rs256_vs_es256(self, rsa_key: rsa.RSAPrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "ES256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        # Sign as RS256 but claim ES256.
        signature = rsa_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature),
        }
        with pytest.raises(JWSValidationError):
            verify_flattened_jws(jws, rsa_key.public_key())

    def test_unsupported_alg(self, rsa_key: rsa.RSAPrivateKey) -> None:
        payload = {"hello": "world"}
        protected_b64 = _b64url_encode_dict({"alg": "PS256"})
        payload_b64 = _make_jws_payload(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = rsa_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature),
        }
        with pytest.raises(UnsupportedAlgorithmError):
            verify_flattened_jws(jws, rsa_key.public_key())

    def test_non_utf8_protected_header_rejected(
        self, rsa_key: rsa.RSAPrivateKey
    ) -> None:
        jws = {
            "protected": _base64url_encode(b"\xff"),
            "payload": _make_jws_payload({"hello": "world"}),
            "signature": _base64url_encode(b"bogus"),
        }
        with pytest.raises(JWSValidationError, match="not valid JSON"):
            verify_flattened_jws(jws, rsa_key.public_key())

    def test_non_object_protected_header_rejected(
        self, rsa_key: rsa.RSAPrivateKey
    ) -> None:
        jws = {
            "protected": _base64url_encode(b"[]"),
            "payload": _make_jws_payload({"hello": "world"}),
            "signature": _base64url_encode(b"bogus"),
        }
        with pytest.raises(JWSValidationError, match="must be a JSON object"):
            verify_flattened_jws(jws, rsa_key.public_key())

    def test_algorithm_name_must_be_exact(self, rsa_key: rsa.RSAPrivateKey) -> None:
        """A made-up RS* name must not inherit SHA-256 by suffix."""
        protected_b64 = _b64url_encode_dict({"alg": "RSanything256"})
        payload_b64 = _make_jws_payload({"hello": "world"})
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = rsa_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature),
        }
        with pytest.raises(UnsupportedAlgorithmError):
            verify_flattened_jws(jws, rsa_key.public_key())

    def test_es_algorithm_must_match_curve(self) -> None:
        key = ec.generate_private_key(ec.SECP384R1())
        protected_b64 = _b64url_encode_dict({"alg": "ES256"})
        payload_b64 = _make_jws_payload({"hello": "world"})
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(_der_to_raw(der_sig, 48)),
        }
        with pytest.raises(JWSValidationError, match="not valid for EC curve"):
            verify_flattened_jws(jws, key.public_key())

    def test_weak_rsa_account_key_rejected(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with pytest.raises(JWSValidationError, match="2048-bit minimum"):
            _public_key_from_jwk(_jwk(key))

    def test_public_key_from_jwk_rsa(self, rsa_key: rsa.RSAPrivateKey) -> None:
        pub = rsa_key.public_key()
        numbers = pub.public_numbers()
        jwk = {
            "kty": "RSA",
            "n": _base64url_encode(
                numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
            ),
            "e": _base64url_encode(
                numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
            ),
        }
        rebuilt = _public_key_from_jwk(jwk)
        assert isinstance(rebuilt, rsa.RSAPublicKey)
        assert rebuilt.public_numbers() == numbers

    def test_public_key_from_jwk_ec(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        pub = ec_key.public_key()
        numbers = pub.public_numbers()
        coordinate_len = (pub.curve.key_size + 7) // 8
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url_encode(numbers.x.to_bytes(coordinate_len, "big")),
            "y": _base64url_encode(numbers.y.to_bytes(coordinate_len, "big")),
        }
        rebuilt = _public_key_from_jwk(jwk)
        assert isinstance(rebuilt, ec.EllipticCurvePublicKey)

    def test_oversized_rsa_modulus_rejected(self) -> None:
        # A 64 KiB JWS body admits a modulus far larger than any real key.
        # Reject it on the raw integer, before RSAPublicNumbers.public_key()
        # or any verify runs — the newAccount DoS bound must not depend on the
        # crypto backend rejecting the key for us.
        oversized_n = (1 << 16384) | 1  # 16385 bits, one over the maximum
        jwk = {
            "kty": "RSA",
            "n": _base64url_encode(
                oversized_n.to_bytes((oversized_n.bit_length() + 7) // 8, "big")
            ),
            "e": _base64url_encode((65537).to_bytes(3, "big")),
        }
        with pytest.raises(JWSValidationError, match="exceeds the 16384-bit maximum"):
            _public_key_from_jwk(jwk)

    def test_unsupported_rsa_exponent_rejected(self) -> None:
        # A large attacker-chosen exponent is the other asymmetric-work lever;
        # reject anything outside the allowlist before the key is built.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n = key.public_key().public_numbers().n
        huge_e = (1 << 4096) | 1  # well-formed but not 3 or 65537
        jwk = {
            "kty": "RSA",
            "n": _base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")),
            "e": _base64url_encode(huge_e.to_bytes((huge_e.bit_length() + 7) // 8, "big")),
        }
        with pytest.raises(JWSValidationError, match="not a supported value"):
            _public_key_from_jwk(jwk)

    def test_standard_rsa_exponents_accepted(self) -> None:
        # 65537 (universal) and 3 (retained compatibility choice) must both
        # still build; the allowlist targets only the oversized exponent.
        for public_exponent in (3, 65537):
            key = rsa.generate_private_key(
                public_exponent=public_exponent, key_size=2048
            )
            numbers = key.public_key().public_numbers()
            jwk = {
                "kty": "RSA",
                "n": _base64url_encode(
                    numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
                ),
                "e": _base64url_encode(
                    numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
                ),
            }
            rebuilt = _public_key_from_jwk(jwk)
            assert isinstance(rebuilt, rsa.RSAPublicKey)


class TestEABVerify:
    def test_valid_eab_hs256(self, rsa_key: rsa.RSAPrivateKey) -> None:
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        eab_jws = _make_eab_jws(account_jwk, "kid-001-0123456789abcdef", mac_key)
        assert verify_eab_jws(eab_jws, account_jwk, mac_key) == "kid-001-0123456789abcdef"

    def test_unknown_alg_rejected(self, rsa_key: rsa.RSAPrivateKey) -> None:
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        protected_b64 = _b64url_encode_dict({"alg": "HS128", "kid": "kid-001-0123456789abcdef"})
        payload_b64 = _b64url_encode_dict(account_jwk)
        eab_jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(b"bogus"),
        }
        with pytest.raises(JWSValidationError, match="unsupported EAB algorithm"):
            verify_eab_jws(eab_jws, account_jwk, mac_key)

    def test_wrong_mac_rejected(self, rsa_key: rsa.RSAPrivateKey) -> None:
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        eab_jws = _make_eab_jws(account_jwk, "kid-001-0123456789abcdef", mac_key)
        with pytest.raises(JWSValidationError, match="MAC verification failed"):
            verify_eab_jws(eab_jws, account_jwk, b"wrong-key-32-bytes-long!!!!!!!")

    def test_payload_mismatch_rejected(self, rsa_key: rsa.RSAPrivateKey) -> None:
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        eab_jws = _make_eab_jws(account_jwk, "kid-001-0123456789abcdef", mac_key)
        other_jwk = dict(account_jwk)
        other_jwk["n"] = other_jwk["n"][:-1] + "X"
        with pytest.raises(JWSValidationError, match="does not match"):
            verify_eab_jws(eab_jws, other_jwk, mac_key)

    def test_url_binding_mismatch_rejected(self, rsa_key: rsa.RSAPrivateKey) -> None:
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        eab_jws = _make_eab_jws(account_jwk, "kid-001-0123456789abcdef", mac_key)
        protected = json.loads(
            __import__("base64").urlsafe_b64decode(
                eab_jws["protected"] + "=" * (-len(eab_jws["protected"]) % 4)
            )
        )
        protected["url"] = "https://other.example/acme/new-acct"
        protected_b64 = _b64url_encode_dict(protected)
        payload_b64 = eab_jws["payload"]
        import hmac
        signature = hmac.new(
            mac_key,
            f"{protected_b64}.{payload_b64}".encode("ascii"),
            "sha256",
        ).digest()
        eab_jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _base64url_encode(signature),
        }
        with pytest.raises(JWSValidationError, match="url does not match"):
            verify_eab_jws(
                eab_jws,
                account_jwk,
                mac_key,
                expected_url="https://ra.example/acme/new-acct",
            )

    def test_jwks_differing_only_in_alg_are_equal(self, rsa_key: rsa.RSAPrivateKey) -> None:
        """M1: JWKs that differ only in the optional 'alg' field must be treated as equal.

        Per ACME §7.1.3, 'alg' is optional in the JWK; its presence/absence
        must not flip the comparison result.
        """
        account_jwk = _jwk(rsa_key)
        mac_key = b"super-secret-key-32-bytes-long!!"
        # EAB JWS payload contains the bare JWK (no alg).
        eab_jws = _make_eab_jws(account_jwk, "kid-001-0123456789abcdef", mac_key)
        # account_jwk_with_alg has an extra 'alg' field — must still match.
        account_jwk_with_alg = dict(account_jwk, alg="RS256")
        result = verify_eab_jws(eab_jws, account_jwk_with_alg, mac_key)
        assert result == "kid-001-0123456789abcdef"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _jwk(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> dict[str, object]:
    pub = key.public_key()
    if isinstance(key, rsa.RSAPrivateKey):
        numbers = pub.public_numbers()
        return {
            "kty": "RSA",
            "n": _base64url_encode(
                numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
            ),
            "e": _base64url_encode(
                numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
            ),
        }
    numbers = pub.public_numbers()
    coordinate_len = (pub.curve.key_size + 7) // 8
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _base64url_encode(numbers.x.to_bytes(coordinate_len, "big")),
        "y": _base64url_encode(numbers.y.to_bytes(coordinate_len, "big")),
    }


def _make_eab_jws(
    account_jwk: dict[str, object],
    kid: str,
    mac_key: bytes,
    alg: str = "HS256",
) -> dict[str, str]:
    import hmac

    protected_b64 = _b64url_encode_dict({"alg": alg, "kid": kid})
    payload_b64 = _b64url_encode_dict(account_jwk)
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    hash_name = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}[alg]
    mac = hmac.new(mac_key, signing_input, hash_name).digest()
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": _base64url_encode(mac),
    }


def _der_to_raw(der_sig: bytes, coordinate_len: int) -> bytes:
    if der_sig[0] != 0x30:
        raise ValueError("not a sequence")
    seq_len = der_sig[1]
    offset = 2
    if seq_len & 0x80:
        len_bytes = seq_len & 0x7F
        seq_len = int.from_bytes(der_sig[offset : offset + len_bytes], "big")
        offset += len_bytes

    def _parse_int() -> int:
        nonlocal offset
        if der_sig[offset] != 0x02:
            raise ValueError("expected INTEGER")
        int_len = der_sig[offset + 1]
        offset += 2
        value = int.from_bytes(der_sig[offset : offset + int_len], "big")
        offset += int_len
        return value

    r = _parse_int()
    s = _parse_int()
    return r.to_bytes(coordinate_len, "big") + s.to_bytes(coordinate_len, "big")


class TestJwkThumbprint:
    def test_rfc7638_known_vector(self) -> None:
        # The canonical example from RFC 7638 §3.1.
        from acme_adcs_ra.jws import jwk_thumbprint

        jwk = {
            "kty": "RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z"
                "wu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY"
                "4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            ),
            "e": "AQAB",
        }
        assert jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    # Full-width P-256 coordinates. Short placeholders used to do here, but
    # jwk_thumbprint now enforces the RFC 7518 §6.2.1.2 fixed width (F5) —
    # a JWK with several accepted spellings is a key with several accounts.
    _EC_X = "kUm9uR-yiOQA2rZV6LVg1yKLBKu4PbJlxggQfYcdY8A"
    _EC_Y = "ee9pb8ELn0dH9t_3S8-ZnJgNjisKfV66YFp6XWc1Zjw"

    def test_key_order_independent(self) -> None:
        from acme_adcs_ra.jws import jwk_thumbprint

        a = {"kty": "EC", "crv": "P-256", "x": self._EC_X, "y": self._EC_Y}
        b = {"y": self._EC_Y, "x": self._EC_X, "kty": "EC", "crv": "P-256"}
        assert jwk_thumbprint(a) == jwk_thumbprint(b)

    def test_alg_member_ignored(self) -> None:
        from acme_adcs_ra.jws import jwk_thumbprint

        base = {"kty": "EC", "crv": "P-256", "x": self._EC_X, "y": self._EC_Y}
        with_alg = {**base, "alg": "ES256"}
        assert jwk_thumbprint(base) == jwk_thumbprint(with_alg)

    def test_unsupported_kty_raises(self) -> None:
        from acme_adcs_ra.jws import UnsupportedAlgorithmError, jwk_thumbprint

        with pytest.raises(UnsupportedAlgorithmError):
            jwk_thumbprint({"kty": "oct", "k": "secret"})
