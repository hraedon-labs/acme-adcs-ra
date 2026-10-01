"""``scripts/verify_crl_publication.py`` — the teardown check for UNFILED item 26.

The bug this closes is not that a revocation failed; it is that the teardown
*said* it had republished the CRL and nothing checked. Thirty certificates sat
revoked-but-unpublished for five and a half hours and would have stayed that way
for close to a week, and the only reason it was noticed is that an unrelated
publication made the entry count jump.

So what is worth testing here is not that the tool can read a CRL. It is that
its verdicts cannot be reached by accident:

* a serial the CA revoked but never published must FAIL, not read as fine;
* a stale CRL still being served must FAIL even though every serial it does
  list is genuinely listed;
* a negative control that turns up listed must FAIL, because a lookup that
  matches everything makes "found" worthless;
* an unreachable CDP must be INDETERMINATE, not a verdict in either direction;
* a run with nothing to check must not print a verification banner;
* a CRL that is not authentic (wrong signer, wrong issuer), not current
  (expired), not a base CRL (delta), or that lists a serial only as
  ``removeFromCRL`` must FAIL, and a run without its controls must not reach a
  verdict at all (2026-10-01 cross-lineage review of PR #18: all of these
  printed the verified banner before).

**Mutation-proved.** Each guard was removed in turn and this file re-run:

* the ``number <= prior_crl_number`` comparison → ``test_a_stale_crl_fails``
  and (``<=`` relaxed to ``<``) ``test_the_prior_crl_itself_fails``;
* the signature check → ``test_a_crl_signed_by_another_key_fails``;
* the issuer-name check → ``test_a_crl_from_another_ca_fails``;
* the expiry check → ``test_an_expired_crl_fails``;
* the delta check → ``test_a_delta_crl_fails``;
* the removeFromCRL filter → ``test_a_remove_from_crl_entry_is_not_a_revocation``;
* the controls-required check → ``test_missing_controls_are_not_a_verdict``;
* the negative-control branch → ``test_a_negative_control_that_is_listed_fails``;
* the ``MISSING``/failure append → ``test_an_unpublished_serial_fails``;
* case/width normalization in ``parse_serial`` →
  ``test_serial_spellings_are_the_same_number``.
"""

from __future__ import annotations

import datetime
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

REPO_ROOT = Path(__file__).resolve().parent.parent
_NOW = datetime.datetime.now(datetime.UTC)


@pytest.fixture(scope="module")
def verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "verify_crl_publication_under_test",
        REPO_ROOT / "scripts" / "verify_crl_publication.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def ca() -> tuple[rsa.RSAPrivateKey, x509.Name]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CONTOSO-CA01-CA")])
    return key, name


def _ca_cert(
    ca: tuple[rsa.RSAPrivateKey, x509.Name],
    *,
    is_ca: bool = True,
    crl_sign: bool | None = True,
) -> bytes:
    """The issuing CA certificate, ADCS-shaped by default.

    ADCS CA certificates carry critical BasicConstraints CA=true and critical
    KeyUsage digitalSignature + keyCertSign + cRLSign. ``crl_sign=None`` omits
    KeyUsage entirely.
    """
    key, name = ca
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if crl_sign is not None:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=crl_sign,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


_CONTROLS = ("--absent", "5AFF", "--prior-crl-number", "130")


def _crl(
    ca: tuple[rsa.RSAPrivateKey, x509.Name],
    *,
    number: int | None,
    serials: list[int],
    age_hours: int = 1,
    next_update_hours: int = 7 * 24,
    signer: rsa.RSAPrivateKey | None = None,
    issuer_name: x509.Name | None = None,
    delta_of: int | None = None,
    remove_from_crl: tuple[int, ...] = (),
    this_update: datetime.datetime | None = None,
    extra_extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    entry_issuer: tuple[int, ...] = (),
) -> bytes:
    key, name = ca
    last = this_update or (_NOW - datetime.timedelta(hours=age_hours))
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_name or name)
        .last_update(last)
        .next_update(_NOW + datetime.timedelta(hours=next_update_hours))
    )
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    if delta_of is not None:
        builder = builder.add_extension(x509.DeltaCRLIndicator(delta_of), critical=True)
    for extension, critical in extra_extensions:
        builder = builder.add_extension(extension, critical=critical)
    for serial in serials:
        entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(last)
        if serial in remove_from_crl:
            entry = entry.add_extension(
                x509.CRLReason(x509.ReasonFlags.remove_from_crl), critical=False
            )
        if serial in entry_issuer:
            other = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OTHER-CA")])
            entry = entry.add_extension(
                x509.CertificateIssuer([x509.DirectoryName(other)]), critical=True
            )
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(signer or key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER
    )


def _run(
    verifier: ModuleType,
    body: bytes,
    tmp_path: Path,
    *args: str,
    ca: tuple[rsa.RSAPrivateKey, x509.Name] | None = None,
    issuer_pem: bytes | None = None,
) -> int:
    path = tmp_path / "ca.crl"
    path.write_bytes(body)
    issuer = tmp_path / "issuer.cer"
    assert ca is not None or issuer_pem is not None
    issuer.write_bytes(issuer_pem if issuer_pem is not None else _ca_cert(ca))  # type: ignore[arg-type]
    return int(verifier.main(["--file", str(path), "--issuer", str(issuer), *args]))


class TestSerialSpelling:
    def test_serial_spellings_are_the_same_number(self, verifier: ModuleType) -> None:
        """certutil prints lowercase; the RA prints uppercase, zeros stripped.

        A comparison that is case- or width-sensitive reports a genuinely
        listed serial as missing, and on this path that reads as "the CA did
        not publish it" — the exact wrong conclusion, reached confidently.
        """
        assert (
            verifier.parse_serial("5a00000123")
            == verifier.parse_serial("5A00000123")
            == verifier.parse_serial("0x005A00000123")
            == verifier.parse_serial(" 5A:00:00:01:23 ")
        )

    def test_an_unparseable_serial_is_a_usage_error_not_a_verdict(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name]
    ) -> None:
        assert _run(verifier, _crl(ca, number=5, serials=[]), tmp_path,
                    "--revoked", "not-hex", *_CONTROLS, ca=ca) == 2

    @pytest.mark.parametrize("text", ["-5", "1_000", "\u0661\u0662", "5A 01x"])
    def test_int_permissiveness_is_not_a_serial(
        self, verifier: ModuleType, text: str
    ) -> None:
        """``int(x, 16)`` takes a sign, underscores and non-ASCII digits."""
        with pytest.raises(ValueError):
            verifier.parse_serial(text)


class TestVerdicts:
    def test_a_published_revocation_verifies(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01, 0x5A02, 0x5A03])
        rc = _run(verifier, body, tmp_path,
                  "--revoked", "5A01", "--revoked", "5a02",
                  "--absent", "5AFF", "--prior-crl-number", "130", ca=ca)
        assert rc == 0
        out = capsys.readouterr().out
        assert "CRL-PUBLICATION-VERIFIED serials=2" in out
        assert "CRL-SIGNATURE=valid" in out
        assert "LISTED 5A01" in out
        assert "NEGATIVE-CONTROL=5AFF absent" in out
        assert "CRL-ENTRY-COUNT=3" in out

    def test_an_unpublished_serial_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The item-26 case exactly: revoked at the CA, absent from the CRL."""
        body = _crl(ca, number=131, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", "--revoked", "5A02",
                  *_CONTROLS, ca=ca)
        assert rc == 1
        captured = capsys.readouterr()
        assert "MISSING 5A02" in captured.out
        assert "NOT on the published CRL" in captured.err
        assert "CRL-PUBLICATION-VERIFIED" not in captured.out

    def test_a_stale_crl_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Every serial asked about IS listed, and it still must not pass.

        This is a pre-revocation CRL that happens to contain the session's
        earlier revocations — served from a cache or a lagging replica. Without
        the CRL-Number floor it verifies cleanly and certifies a publication
        that never happened.
        """
        body = _crl(ca, number=129, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        assert rc == 1
        assert "is not greater than the prior number" in capsys.readouterr().err

    def test_the_prior_crl_itself_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The CRL observed BEFORE the republish must not pass as the new one.

        An earlier ``--min-crl-number`` accepted equality, so the document the
        operator read before republishing satisfied its own floor.
        """
        body = _crl(ca, number=130, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        assert rc == 1
        assert "CRL-PUBLICATION-VERIFIED" not in capsys.readouterr().out

    def test_a_crl_with_no_number_cannot_satisfy_a_floor(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        body = _crl(ca, number=None, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        assert rc == 1
        assert "carries none" in capsys.readouterr().err

    def test_a_negative_control_that_is_listed_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """If the control is 'found', a 'found' verdict means nothing.

        A lookup that matches everything is indistinguishable from a correct
        one when you only ask it about things that should match.
        """
        body = _crl(ca, number=131, serials=[0x5A01, 0x5AFF])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", "--absent", "5AFF",
                  "--prior-crl-number", "130", ca=ca)
        assert rc == 1
        captured = capsys.readouterr()
        assert "NEGATIVE-CONTROL=5AFF PRESENT" in captured.out
        assert "proves nothing" in captured.err

    def test_nothing_to_check_does_not_claim_a_verification(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """An empty check reporting success is how a green gate stops meaning anything."""
        rc = _run(verifier, _crl(ca, number=131, serials=[]), tmp_path, ca=ca)
        assert rc == 0
        out = capsys.readouterr().out
        assert "NO-SERIALS-SUPPLIED" in out
        assert "CRL-PUBLICATION-VERIFIED" not in out

    def test_an_unreachable_cdp_is_indeterminate_not_a_verdict(
        self, verifier: ModuleType, capsys: pytest.CaptureFixture[str],
        tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
    ) -> None:
        """A fetch failure says nothing about the serials, and must claim nothing.

        Exit 2, distinct from the exit 1 that means "checked, and the CRL does
        not carry them" — a teardown that treated the two alike would report a
        network problem as an unpublished revocation, or worse, the reverse.
        """
        issuer = tmp_path / "issuer.cer"
        issuer.write_bytes(_ca_cert(ca))
        rc = verifier.main(
            ["--url", "http://127.0.0.1:9/ca.crl", "--issuer", str(issuer),
             "--revoked", "5A01", *_CONTROLS, "--timeout", "1"]
        )
        assert rc == 2
        assert "CRL-PUBLICATION-INDETERMINATE" in capsys.readouterr().err

    def test_a_body_that_is_not_a_crl_is_indeterminate(
        self, verifier: ModuleType, tmp_path: Path,
        capsys: pytest.CaptureFixture[str], ca: tuple[rsa.RSAPrivateKey, x509.Name],
    ) -> None:
        rc = _run(verifier, b"this is not a CRL", tmp_path, "--revoked", "5A01",
                  *_CONTROLS, ca=ca)
        assert rc == 2
        assert "CRL-PUBLICATION-INDETERMINATE" in capsys.readouterr().err


class TestAuthenticity:
    """A membership answer from a document nobody vouches for proves nothing."""

    def test_a_crl_signed_by_another_key_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        body = _crl(ca, number=131, serials=[0x5A01], signer=attacker)
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        captured = capsys.readouterr()
        assert rc == 1
        assert "CRL-SIGNATURE=invalid" in captured.out
        assert "CRL-PUBLICATION-VERIFIED" not in captured.out

    def test_a_crl_from_another_ca_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        other = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OTHER-CA")])
        body = _crl(ca, number=131, serials=[0x5A01], issuer_name=other)
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        captured = capsys.readouterr()
        assert rc == 1
        assert "CRL-SIGNATURE=issuer-mismatch" in captured.out

    def test_an_expired_crl_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01], age_hours=48, next_update_hours=-1)
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        assert rc == 1
        assert "expired" in capsys.readouterr().err

    def test_a_delta_crl_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01], delta_of=129)
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        assert rc == 1
        assert "delta CRL" in capsys.readouterr().err

    def test_a_remove_from_crl_entry_is_not_a_revocation(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """removeFromCRL is the UN-revoke marker; listing it is not revoking."""
        body = _crl(ca, number=131, serials=[0x5A01], remove_from_crl=(0x5A01,))
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        assert rc == 1
        assert "MISSING 5A01" in capsys.readouterr().out

    @pytest.mark.parametrize(
        "controls",
        [("--prior-crl-number", "130"), ("--absent", "5AFF"), ()],
        ids=["no-negative-control", "no-prior-number", "neither"],
    )
    def test_missing_controls_are_not_a_verdict(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str], controls: tuple[str, ...],
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *controls, ca=ca)
        captured = capsys.readouterr()
        assert rc == 2
        assert "requires at least one" in captured.err
        assert "CRL-PUBLICATION-VERIFIED" not in captured.out


class TestInterpretability:
    """Second review round (2026-10-01): documents that verify but do not prove."""

    def _expect_fail(
        self, verifier: ModuleType, tmp_path: Path,
        ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str], body: bytes, needle: str,
    ) -> None:
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        captured = capsys.readouterr()
        assert rc == 1
        assert needle in captured.err
        assert "CRL-PUBLICATION-VERIFIED" not in captured.out

    def test_a_future_dated_crl_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01],
                    this_update=_NOW + datetime.timedelta(hours=24))
        self._expect_fail(verifier, tmp_path, ca, capsys, body, "in the future")

    def test_an_indirect_crl_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        idp = x509.IssuingDistributionPoint(
            full_name=None, relative_name=None, only_contains_user_certs=False,
            only_contains_ca_certs=False, only_some_reasons=None,
            indirect_crl=True, only_contains_attribute_certs=False,
        )
        body = _crl(ca, number=131, serials=[0x5A01], extra_extensions=((idp, True),))
        self._expect_fail(verifier, tmp_path, ca, capsys, body, "indirect CRL")

    def test_an_entry_naming_another_issuer_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01], entry_issuer=(0x5A01,))
        self._expect_fail(verifier, tmp_path, ca, capsys, body, "cannot be attributed")

    def test_an_unknown_critical_extension_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        unknown = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00"
        )
        body = _crl(ca, number=131, serials=[0x5A01], extra_extensions=((unknown, True),))
        self._expect_fail(verifier, tmp_path, ca, capsys, body, "does not understand")

    def test_an_unknown_non_critical_extension_is_fine(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
    ) -> None:
        """ADCS adds non-critical Microsoft extensions (CA Version, Next CRL Publish)."""
        unknown = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.4.1.311.21.1"), b"\x02\x01\x00"
        )
        body = _crl(ca, number=131, serials=[0x5A01], extra_extensions=((unknown, False),))
        assert _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca) == 0

    @pytest.mark.parametrize(
        ("is_ca", "crl_sign"), [(False, True), (True, False)],
        ids=["not-a-ca", "no-crl-sign"],
    )
    def test_an_issuer_that_cannot_sign_crls_is_refused(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str], is_ca: bool, crl_sign: bool,
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS,
                  issuer_pem=_ca_cert(ca, is_ca=is_ca, crl_sign=crl_sign))
        captured = capsys.readouterr()
        assert rc == 2
        assert "not a CA able to sign CRLs" in captured.err
        assert "CRL-PUBLICATION-VERIFIED" not in captured.out

    def test_an_issuer_without_key_usage_is_accepted(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01])
        assert _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS,
                    issuer_pem=_ca_cert(ca, crl_sign=None)) == 0

    def test_a_multi_certificate_issuer_file_is_refused(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS,
                  issuer_pem=_ca_cert(ca) + _ca_cert(ca))
        assert rc == 2
        assert "holds 2 certificates" in capsys.readouterr().err


class TestThirdRound:
    """Third review round (2026-10-01)."""

    def test_a_reason_scoped_crl_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        idp = x509.IssuingDistributionPoint(
            full_name=None, relative_name=None, only_contains_user_certs=False,
            only_contains_ca_certs=False,
            only_some_reasons=frozenset({x509.ReasonFlags.key_compromise}),
            indirect_crl=False, only_contains_attribute_certs=False,
        )
        body = _crl(ca, number=131, serials=[0x5A01], extra_extensions=((idp, True),))
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca)
        assert rc == 1
        assert "some revocation reasons only" in capsys.readouterr().err

    def test_a_full_name_only_idp_still_verifies(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
    ) -> None:
        """ADCS can publish a critical IDP carrying only the CDP's fullName."""
        idp = x509.IssuingDistributionPoint(
            full_name=[x509.UniformResourceIdentifier("http://ca.example/ca.crl")],
            relative_name=None, only_contains_user_certs=False,
            only_contains_ca_certs=False, only_some_reasons=None,
            indirect_crl=False, only_contains_attribute_certs=False,
        )
        body = _crl(ca, number=131, serials=[0x5A01], extra_extensions=((idp, True),))
        assert _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS, ca=ca) == 0

    def test_pem_followed_by_der_is_refused(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        pem = _ca_cert(ca)
        der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
        body = _crl(ca, number=131, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS,
                  issuer_pem=pem + der)
        assert rc == 2
        assert "PEM certificate blocks only" in capsys.readouterr().err

    def test_an_expired_issuer_certificate_is_refused(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        key, name = ca
        expired = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(2)
            .not_valid_before(_NOW - datetime.timedelta(days=30))
            .not_valid_after(_NOW - datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        ).public_bytes(serialization.Encoding.PEM)
        body = _crl(ca, number=131, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", *_CONTROLS,
                  issuer_pem=expired)
        assert rc == 2
        assert "not currently valid" in capsys.readouterr().err
