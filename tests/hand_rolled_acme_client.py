"""A minimal hand-rolled ACME client for integration tests.

This module lives under ``tests/`` and is allowed to **sign** JWS because it
simulates Certify the Web.  It is NOT scanned by the architecture guardrail.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

JOSE_HEADERS = {"Content-Type": "application/jose+json"}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding_needed = (-len(data)) % 4
    return base64.urlsafe_b64decode(data + ("=" * padding_needed))


def _der_to_raw_ecdsa(der_signature: bytes, coordinate_byte_length: int) -> bytes:
    """Convert an ASN.1 DER ECDSA signature to raw R||S."""
    # Minimal DER parser: expect SEQUENCE { INTEGER r, INTEGER s }
    if der_signature[0] != 0x30:
        raise ValueError("invalid DER signature: not a sequence")
    seq_len = der_signature[1]
    offset = 2
    if seq_len & 0x80:
        len_bytes = seq_len & 0x7F
        seq_len = int.from_bytes(der_signature[offset : offset + len_bytes], "big")
        offset += len_bytes

    def _parse_int() -> int:
        nonlocal offset
        if der_signature[offset] != 0x02:
            raise ValueError("expected INTEGER")
        int_len = der_signature[offset + 1]
        offset += 2
        value = int.from_bytes(der_signature[offset : offset + int_len], "big")
        offset += int_len
        return value

    r = _parse_int()
    s = _parse_int()
    return r.to_bytes(coordinate_byte_length, "big") + s.to_bytes(coordinate_byte_length, "big")


def _coordinate_length(key: ec.EllipticCurvePrivateKey) -> int:
    return (key.curve.key_size + 7) // 8


def jwk_from_private_key(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    pub = key.public_key()
    if isinstance(key, rsa.RSAPrivateKey):
        pub_numbers = pub.public_numbers()
        return {
            "kty": "RSA",
            "n": b64url_encode(pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64url_encode(pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")),
        }
    if isinstance(key, ec.EllipticCurvePrivateKey):
        pub_numbers = pub.public_numbers()
        coordinate_len = _coordinate_length(key)
        curve_name = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
        }[key.curve.name]
        return {
            "kty": "EC",
            "crv": curve_name,
            "x": b64url_encode(pub_numbers.x.to_bytes(coordinate_len, "big")),
            "y": b64url_encode(pub_numbers.y.to_bytes(coordinate_len, "big")),
        }
    raise TypeError(f"unsupported key type: {type(key)}")


def sign_jws(
    payload: dict[str, Any] | None,
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    protected: dict[str, Any],
) -> dict[str, str]:
    """Sign a flattened JSON JWS."""
    protected_b64 = b64url_encode(json.dumps(protected, separators=(",", ":")).encode("utf-8"))
    payload_b64 = (
        b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        if payload is not None
        else ""
    )
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")

    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        signature = _der_to_raw_ecdsa(der_sig, _coordinate_length(key))
    else:
        raise TypeError(f"unsupported key type: {type(key)}")

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url_encode(signature),
    }


def make_eab_jws(
    account_jwk: dict[str, Any],
    kid: str,
    mac_key: bytes,
    *,
    alg: str = "HS256",
    url: str,
) -> dict[str, str]:
    """Create an externalAccountBinding JWS MAC'd with mac_key."""
    import hmac as _hmac

    protected = {"alg": alg, "kid": kid, "url": url}
    payload = account_jwk
    protected_b64 = b64url_encode(json.dumps(protected, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    hash_callable = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}[alg]
    mac = _hmac.new(mac_key, signing_input, hash_callable).digest()
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url_encode(mac),
    }


class HandRolledAcmeClient:
    """Tiny ACME client wired to a httpx TestClient or similar."""

    def __init__(
        self,
        http_client: Any,
        base_url: str,
        account_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    ) -> None:
        self.http = http_client
        self.base_url = base_url.rstrip("/")
        self.account_key = account_key
        self.account_jwk = jwk_from_private_key(account_key)
        self.account_url: str | None = None
        self._nonce: str | None = None

    def _fresh_nonce(self) -> str:
        resp = self.http.head(f"{self.base_url}/acme/new-nonce")
        resp.raise_for_status()
        nonce = resp.headers["Replay-Nonce"]
        return nonce

    def _nonce_for(self) -> str:
        if self._nonce is None:
            self._nonce = self._fresh_nonce()
        nonce = self._nonce
        self._nonce = None
        return nonce

    def _post_jws(
        self,
        url: str,
        payload: dict[str, Any] | None,
        *,
        is_new_account: bool = False,
    ) -> Any:
        protected: dict[str, Any] = {
            "alg": "RS256" if isinstance(self.account_key, rsa.RSAPrivateKey) else "ES256",
            "nonce": self._nonce_for(),
            "url": url,
        }
        if is_new_account:
            protected["jwk"] = self.account_jwk
        else:
            if self.account_url is None:
                raise RuntimeError("account URL not known; call new_account first")
            protected["kid"] = self.account_url
        body = sign_jws(payload, self.account_key, protected)
        # RFC 8555 §6.2: JWS POSTs are application/jose+json (the RA answers
        # anything else with 415). httpx's json= would send application/json.
        resp = self.http.post(url, content=json.dumps(body), headers=JOSE_HEADERS)
        # Save nonce for next request if present.
        if "Replay-Nonce" in resp.headers:
            self._nonce = resp.headers["Replay-Nonce"]
        return resp

    def new_account(self, eab_kid: str, eab_mac_key: bytes, contact: list[str] | None = None) -> Any:
        url = f"{self.base_url}/acme/new-acct"
        eab_jws = make_eab_jws(
            self.account_jwk,
            eab_kid,
            eab_mac_key,
            url=url,
        )
        payload = {
            "externalAccountBinding": eab_jws,
            "termsOfServiceAgreed": True,
            "contact": contact or ["mailto:test@example.com"],
        }
        resp = self._post_jws(url, payload, is_new_account=True)
        if resp.status_code in (200, 201):
            self.account_url = resp.headers["Location"]
        return resp

    def new_order(self, identifiers: list[str]) -> Any:
        url = f"{self.base_url}/acme/new-order"
        payload = {
            "identifiers": [{"type": "dns", "value": name} for name in identifiers],
        }
        return self._post_jws(url, payload)

    def get_authorization(self, authz_url: str) -> Any:
        # The plain unauthenticated GET form was removed (2026-08-15 review,
        # finding 4). Reading an authorization is now POST-as-GET, so this
        # helper does what a conforming client does; the name is intent, not
        # HTTP method.
        return self.post_as_get(authz_url)

    def post_as_get(self, url: str) -> Any:
        """RFC 8555 §6.3 POST-as-GET: a signed request with an EMPTY payload.

        ``sign_jws(None, ...)`` produces ``payload: ""`` — the empty *string*
        the RFC specifies, not an empty object.
        """
        return self._post_jws(url, None)

    def deactivate_account(self) -> Any:
        """RFC 8555 §7.3.6 account deactivation."""
        if self.account_url is None:
            raise RuntimeError("account URL not known; call new_account first")
        return self._post_jws(self.account_url, {"status": "deactivated"})

    def validate_challenge(self, challenge_url: str) -> Any:
        return self._post_jws(challenge_url, {})

    def finalize_order(self, finalize_url: str, csr_der: bytes) -> Any:
        payload = {"csr": b64url_encode(csr_der)}
        return self._post_jws(finalize_url, payload)

    def get_certificate(self, cert_url: str) -> Any:
        # Plain GET removed (2026-08-15 review, finding 4); downloading the
        # certificate is now POST-as-GET (RFC 8555 §7.4.2).
        return self.post_as_get(cert_url)

    def revoke_certificate(
        self,
        cert_der: bytes,
        reason: int | None = None,
        field_name: str = "certificate",
    ) -> Any:
        """Revoke a certificate (RFC 8555 §7.6).

        ``field_name`` defaults to the RFC spelling, ``certificate``. It used to
        send ``cert``, which is what the server read -- so client and server
        shared one non-standard dialect and every revocation test passed while
        real ACME clients were refused outright. The parameter exists so the
        deprecated ``cert`` alias stays covered; it is not something a caller
        should normally set.
        """
        url = f"{self.base_url}/acme/revoke-cert"
        payload: dict[str, Any] = {field_name: b64url_encode(cert_der)}
        if reason is not None:
            payload["reason"] = reason
        return self._post_jws(url, payload)

    def key_change(
        self,
        new_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    ) -> Any:
        """Perform an account key rollover (RFC 8555 §7.3.5).

        The outer JWS is signed by the current (old) account key. Its
        payload is the inner JWS, signed by *new_key*. The inner payload
        carries the account URL and the old key JWK.
        """
        url = f"{self.base_url}/acme/key-change"
        if self.account_url is None:
            raise RuntimeError("account URL not known; call new_account first")

        new_jwk = jwk_from_private_key(new_key)
        old_jwk = self.account_jwk

        # RFC 8555 §7.3.5: "The inner JWS MUST omit the 'nonce' header
        # parameter." This client used to send one, which is exactly the
        # server's old non-standard dialect (item 27) -- so every rollover test
        # passed while every conformant client failed.
        inner_protected: dict[str, Any] = {
            "alg": "RS256" if isinstance(new_key, rsa.RSAPrivateKey) else "ES256",
            "url": url,
            "jwk": new_jwk,
        }
        inner_payload: dict[str, Any] = {
            "account": self.account_url,
            "oldKey": old_jwk,
        }
        inner_jws = sign_jws(inner_payload, new_key, inner_protected)

        return self._post_jws(url, inner_jws)
