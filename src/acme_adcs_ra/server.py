"""FastAPI ACME server (RFC 8555 subset) for the ADCS Registration Authority.

This module is the composition root — it wires the app, includes routers,
and sets up the exception handler. Route logic lives in routes/, shared
state in app_state.py, finalize helpers in finalize.py, CSR validation in
csr_validation.py, and JSON serializers in serializers.py.

This module only **verifies** JWS signatures and CSRs; it never signs anything.
The enrollment leg (``EnrollmentLeg``) forwards accepted CSRs to ADCS.
"""

from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from acme_adcs_ra.acme_errors import BAD_NONCE_TYPE, AcmeError, rate_limited
from acme_adcs_ra.app_state import (
    ServerContext,
    _default_nonce_bucket,
    _default_siem_emitter,
    logger,
)
from acme_adcs_ra.audit_coalesce import DenialCoalescer
from acme_adcs_ra.audit_retention import assert_retention_above_floor, log_footprint
from acme_adcs_ra.eab_kid_floor import assert_eab_kids_meet_floor
from acme_adcs_ra.routes.acme import router as acme_router
from acme_adcs_ra.routes.admin import router as admin_router
from acme_adcs_ra.siem import SiemEmitter

__all__ = ["ServerContext", "create_app"]


def _package_version() -> str:
    """The installed distribution version, or a marker when running unpackaged."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("acme-adcs-ra")
    except PackageNotFoundError:  # pragma: no cover - source checkout without install
        return "0+unknown"


class ReplayNonceMiddleware:
    """Attach a fresh ``Replay-Nonce`` to ACME POST responses (item 28).

    RFC 8555 §6.5: the server MUST include ``Replay-Nonce`` "in every
    successful response to a POST request", and a ``badNonce`` error MUST carry
    one "that the server will accept in a retry". The RA used to set it only on
    ``new-nonce`` — so certbot (acme-python raises ``MissingNonce``) could not
    even register, and Posh-ACME re-sent its spent nonce and failed every POST
    after new-account.

    The decision is driven by one request-state flag, never by path:
    ``acme_nonce_consumed`` (set by ``server_jws._parse_jws_header`` once a
    nonce has been spent). Non-JWS routes (directory, admin) never set it and
    are untouched. ``badNonce`` — the one error owed a nonce although none was
    spent — is minted by the ``AcmeError`` handler itself, which also decides
    what to say when it cannot mint one; the middleware leaves any response
    that already carries ``Replay-Nonce`` alone.

    **Which mints may bypass the nonce bucket.** The bucket exists so that an
    unauthenticated flood cannot hold SQLite's single writer (directory.py). A
    successful POST response has, by construction, verified a JWS — the caller
    is an authenticated account, or a new account that passed EAB — so it gets
    its nonce unbucketed: one spent, one minted, and the RFC's MUST holds even
    when the bucket is dry. Every handled ERROR response draws from the bucket
    exactly as ``new-nonce`` does, because an error may come from an unauthenticated
    peer: without that, "send a garbage signature with a valid nonce, receive a
    fresh nonce in the 401" would be an unbounded nonce chain around the
    bucket. A dry bucket on an error simply omits the header (a SHOULD-level
    nonce), except for ``badNonce``, where the nonce is a MUST — see the
    exception handler, which answers ``rateLimited`` + ``Retry-After`` rather
    than send a nonce-less badNonce.

    A mint that fails (unwritable store) is logged and the header omitted: the
    request's own effects have already committed, and turning a completed
    operation into a 500 after the fact would be worse than a missing nonce.
    The mint is a SQLite write, so it runs in the threadpool rather than on the
    event loop: under writer contention it can wait out the 5 s busy timeout,
    and it must not stall every other request while it does (Daybreak Blue,
    round 1). So do the badNonce handler mint and, since round 4, the
    new-nonce route (routes/directory.py).
    """

    def __init__(self, app: ASGIApp, context: ServerContext) -> None:
        self.app = app
        self.context = context

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state: dict[str, Any] = scope.setdefault("state", {})

        async def send_with_nonce(message: Message) -> None:
            if message["type"] == "http.response.start" and self._owed_nonce(
                message, state
            ):
                nonce = await self._mint()
                if nonce is not None:
                    headers = list(message.get("headers", []))
                    headers.append((b"replay-nonce", nonce.encode("ascii")))
                    message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_nonce)

    def _owed_nonce(self, message: Message, state: dict[str, Any]) -> bool:
        if any(k.lower() == b"replay-nonce" for k, _v in message.get("headers", [])):
            return False
        consumed = bool(state.get("acme_nonce_consumed"))
        status = int(message["status"])
        if status < 400:
            return consumed
        if not consumed:
            return False
        bucket = self.context.nonce_bucket
        return bucket is None or bucket.take()

    async def _mint(self) -> str | None:
        try:
            return await run_in_threadpool(self.context.store.create_nonce)
        # Deliberately broad (like emit_audit_hook): this runs after the
        # request's effects have committed — e.g. an irreversible key rollover
        # — so ANY failure here must cost only the header, never turn a
        # completed operation into a 500 (DeepSeek, round 6).
        except Exception:  # noqa: BLE001
            logger.exception("could not mint a Replay-Nonce for an ACME response")
            return None


def create_app(context: ServerContext) -> FastAPI:
    """Build a FastAPI app wired to the supplied server context."""
    # Defense in depth for callers that mutate or construct a config without
    # normal Pydantic validation. The library sweep is intentionally not wired:
    # the SIEM exporter has no per-row delivery watermark, so a health probe
    # cannot prove the rows selected for deletion have an off-box copy.
    if context.config.audit_prune_enabled:
        raise RuntimeError(
            "audit_prune_enabled is not available without acknowledged per-row "
            "off-box delivery; refusing to start rather than silently ignore the "
            "setting or delete the only copy of audit evidence"
        )

    # Wire the default SIEM emitter when no test/operator hook is supplied.
    _siem_emitter: SiemEmitter | None = None
    if context.audit_hook is None:
        _siem_emitter = _default_siem_emitter(context.config)
        # `audit_offbox_required` validates the configured sink *name*, which is
        # not the same question as whether events actually leave the box. An
        # emitter disables itself when its config is unusable — empty
        # syslog_host, an HEC URL that is not https or carries embedded
        # credentials, an empty HEC token, a failed syslog handler setup — and
        # the app used to start anyway with the disabled hook installed. The
        # operator would then believe the production off-box audit gate was
        # satisfied while the only audit evidence lived on the host an attacker
        # is assumed to control. Assert the constructed emitter, not the name.
        if context.config.audit_offbox_required and not _siem_emitter.enabled:
            raise RuntimeError(
                "audit_offbox_required is set, but the "
                f"{context.config.siem_sink!r} SIEM emitter failed to initialise "
                "and is disabled, so no audit event would leave this host. "
                "Check the sink's configuration (syslog_host, or an https "
                "hec_url without embedded credentials plus a non-empty "
                "hec_token); the RA is refusing to start rather than run "
                "without the off-box audit trail it was told to require."
            )
        if context.config.audit_offbox_required:
            # Constructed is not the same as working (2026-08-18 wave 3 F2). A
            # revoked HEC token, a wrong index, or an endpoint that answers 403
            # to everything passed every check above, so the RA started and
            # issued certificates believing an off-box trail was in force while
            # nothing left the host. "Required" has to mean demonstrated.
            ok, detail = _siem_emitter.probe_offbox_delivery()
            if not ok:
                raise RuntimeError(
                    "audit_offbox_required is set, but the startup delivery "
                    f"probe to the {context.config.siem_sink!r} sink failed: "
                    f"{detail}. The RA is refusing to start rather than issue "
                    "certificates while the off-box audit trail it was told to "
                    "require is not actually working."
                )
            logger.info("off-box audit delivery probe succeeded: %s", detail)
            if context.config.audit_offbox_allow_unauthenticated_syslog:
                # An accepted trade has to stay visible for as long as it is in
                # force. A one-time decision recorded only in a config file is
                # invisible to whoever reads the audit trail later and assumes
                # "required" meant authenticated.
                logger.warning(
                    "UNAUTHENTICATED OFF-BOX AUDIT: audit_offbox_required is "
                    "satisfied by plain TCP syslog to %s:%s because "
                    "audit_offbox_allow_unauthenticated_syslog is set. The "
                    "collector is not authenticated and events are not "
                    "protected in transit; anyone on the path can read this "
                    "trail or forge events into the SIEM. Prefer the "
                    "authenticated HTTPS HEC sink.",
                    context.config.siem_syslog_host,
                    context.config.siem_syslog_port,
                )
        context.audit_hook = _siem_emitter.export
    if context.nonce_bucket is None:
        context.nonce_bucket = _default_nonce_bucket(context.config)
    if context.denial_coalescer is None:
        context.denial_coalescer = DenialCoalescer(
            context.config.audit_denial_coalesce_window_seconds
        )
    context.crl_evidence_gate.set_limits(
        max_workers=context.config.revocation_confirm_crl_max_workers,
        max_pending=context.config.revocation_confirm_crl_max_pending,
    )
    context.enrollment_gate.set_limits(
        max_workers=context.config.adcs_enrollment_max_workers,
        max_pending=context.config.adcs_enrollment_max_pending,
    )

    # Retention floor, then footprint. The floor is a refusal rather than a
    # warning: retaining for less than a certificate's own lifetime means a
    # certificate can be valid and servable while the record of how it was
    # issued has been deleted, which is an evidence hole rather than a tuning
    # choice. The footprint report is the half every deployment gets, including
    # the local-only ones that will never delete a row.
    assert_retention_above_floor(context.config, context.store)
    assert_eab_kids_meet_floor(context.config, context.store)
    log_footprint(
        context.config,
        context.store,
        _siem_emitter.jsonl_bytes() if _siem_emitter is not None else 0,
    )

    # H-3: shut down the SIEM emitter pool on app shutdown via lifespan.
    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> Any:
        yield
        if _siem_emitter is not None:
            _siem_emitter.close()
        # Same reason: the CRL-evidence pool is the RA's own, so nothing else
        # reclaims its threads at shutdown.
        context.crl_evidence_gate.close()
        context.enrollment_gate.close()
        if context.denial_coalescer is not None:
            context.denial_coalescer.close()

    app = FastAPI(
        title="acme-adcs-ra",
        # Read from installed package metadata rather than a second hand-
        # maintained literal — this string drifted to 1.6.0 while pyproject
        # said 1.7.0, and it is the version an operator reads when working out
        # which build is actually deployed.
        version=_package_version(),
        lifespan=_lifespan,
        # The interactive docs publish the full route inventory — including
        # every /acme/admin/* endpoint — to any unauthenticated caller that can
        # reach the RA. That undoes the same intent as web.config's
        # removeServerHeader. ACME is a machine protocol; there is no operator
        # workflow that needs Swagger on an issuance-path host.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.context = context

    def _problem(err: AcmeError, extra_headers: dict[str, str] | None = None) -> JSONResponse:
        return JSONResponse(
            status_code=err.status,
            content=err.to_problem(),
            headers={
                "Content-Type": "application/problem+json",
                **err.headers,
                **(extra_headers or {}),
            },
        )

    @app.exception_handler(AcmeError)
    async def acme_exception_handler(request: Request, exc: AcmeError) -> JSONResponse:
        if exc.typ != BAD_NONCE_TYPE:
            return _problem(exc)
        # RFC 8555 §6.5: a badNonce MUST carry a fresh nonce. The decision and
        # the mint both happen HERE, so "every badNonce has a nonce" holds by
        # construction: either this response carries one, or it is not a
        # badNonce. The token is drawn from the nonce bucket (the only bound
        # on unauthenticated nonce issuance); if the bucket is dry, or the mint
        # itself fails (e.g. the writer lock outlasting the busy timeout under
        # a garbage-nonce flood), the RA answers what is true — rateLimited
        # with Retry-After, as new-nonce would — instead of a nonce-less
        # badNonce. Daybreak Blue (round 2) found the dry-bucket case and
        # DeepSeek (round 3) the failed-mint case.
        bucket = context.nonce_bucket
        nonce: str | None = None
        if bucket is None or bucket.take():
            try:
                nonce = await run_in_threadpool(context.store.create_nonce)
            except (sqlite3.Error, OSError):
                logger.exception("could not mint a Replay-Nonce for a badNonce error")
        if nonce is None:
            # Reached with a bucket (dry, or drawn and then the mint failed);
            # with buckets disabled only a failed mint gets here.
            retry = bucket.retry_after_seconds() if bucket is not None else 1
            return _problem(
                rate_limited(
                    "nonce issuance is temporarily unavailable; retry after the "
                    f"delay (the request also failed nonce validation: {exc.detail})",
                    retry_after=retry,
                )
            )
        return _problem(exc, {"Replay-Nonce": nonce})

    app.include_router(acme_router)
    app.include_router(admin_router)
    app.add_middleware(ReplayNonceMiddleware, context=context)

    return app
