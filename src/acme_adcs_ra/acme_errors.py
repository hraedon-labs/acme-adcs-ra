"""ACME problem+json errors (RFC 8555 §6.7).

No signing primitives live here — just structured exception types that the
FastAPI exception handler converts to problem documents.
"""

from __future__ import annotations


class AcmeError(Exception):
    """Base for ACME protocol errors."""

    def __init__(
        self,
        typ: str,
        detail: str,
        status: int = 400,
        title: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.typ = typ
        self.detail = detail
        self.status = status
        self.title = title or typ.rsplit(":", 1)[-1]
        self.headers = headers or {}
        super().__init__(detail)

    def to_problem(self) -> dict[str, str | int]:
        return {
            "type": self.typ,
            "title": self.title,
            "detail": self.detail,
            "status": self.status,
        }


BAD_NONCE_TYPE = "urn:ietf:params:acme:error:badNonce"

# Interop accommodation, not protocol: acme.sh (3.1.6) retries a badNonce only
# when the problem *detail* contains Boulder's wording, not on the error type
# RFC 8555 §6.5 defines. Leading with that phrase costs nothing and lets acme.sh
# take the retry path every other client takes on the type alone.
_BAD_NONCE_DETAIL_PREFIX = "JWS has an invalid anti-replay nonce"


def bad_nonce(detail: str = "invalid or missing nonce") -> AcmeError:
    return AcmeError(
        BAD_NONCE_TYPE,
        f"{_BAD_NONCE_DETAIL_PREFIX}: {detail}",
        status=400,
    )


def unauthorized(detail: str = "unauthorized") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:unauthorized",
        detail,
        status=401,
    )


def malformed(detail: str = "malformed request") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:malformed",
        detail,
        status=400,
    )


def bad_public_key(detail: str = "invalid account key") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:badPublicKey",
        detail,
        status=400,
    )


def bad_csr(detail: str = "invalid CSR") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:badCSR",
        detail,
        status=400,
    )


def rejected_identifier(detail: str = "identifier rejected by policy") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:rejectedIdentifier",
        detail,
        status=400,
    )


def bad_external_account_binding(detail: str = "invalid external account binding") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:badExternalAccountBinding",
        detail,
        status=400,
    )


def server_internal(detail: str = "internal server error") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:serverInternal",
        detail,
        status=500,
    )


def issuance_halted(detail: str = "issuance is halted") -> AcmeError:
    """503 for the one-way post-issuance-orphan latch (see IssuanceHalt).

    ``serverInternal`` is the correct URN — RFC 8555 defines no "temporarily
    refusing" type and inventing one would break clients that switch on it —
    but the STATUS is 503, not 500, because the condition is an operator-
    clearable outage rather than a bug in this request. A conformant client
    treats 503 as retryable, which is right: the order is still ``processing``
    at the CA's expense and retrying after a restart is exactly what should
    happen. ``Retry-After`` is deliberately omitted: nothing here can estimate
    when a human will fix a disk, and a number that is always wrong is worse
    than no number.
    """
    return AcmeError(
        "urn:ietf:params:acme:error:serverInternal",
        detail,
        status=503,
    )


def unsupported_identifier(detail: str = "unsupported identifier") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:unsupportedIdentifier",
        detail,
        status=400,
    )


def bad_revocation_reason(detail: str = "invalid revocation reason") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:badRevocationReason",
        detail,
        status=400,
    )


def not_found(detail: str = "resource not found") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:notFound",
        detail,
        status=404,
    )


def account_does_not_exist(detail: str = "account does not exist") -> AcmeError:
    return AcmeError(
        "urn:ietf:params:acme:error:accountDoesNotExist",
        detail,
        status=400,
    )


def rate_limited(
    detail: str = "rate limited",
    *,
    retry_after: int | None = None,
) -> AcmeError:
    headers: dict[str, str] = {}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return AcmeError(
        "urn:ietf:params:acme:error:rateLimited",
        detail,
        status=429,
        headers=headers,
    )
