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
* a run with nothing to check must not print a verification banner.

**Mutation-proved.** Each guard was removed in turn and this file re-run:

* the ``number < min_crl_number`` comparison → ``test_a_stale_crl_fails``;
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


def _crl(
    ca: tuple[rsa.RSAPrivateKey, x509.Name],
    *,
    number: int | None,
    serials: list[int],
    age_hours: int = 1,
) -> bytes:
    key, name = ca
    last = _NOW - datetime.timedelta(hours=age_hours)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(last)
        .next_update(_NOW + datetime.timedelta(days=7))
    )
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    for serial in serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(last)
            .build()
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _run(verifier: ModuleType, body: bytes, tmp_path: Path, *args: str) -> int:
    path = tmp_path / "ca.crl"
    path.write_bytes(body)
    return int(verifier.main(["--file", str(path), *args]))


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
                    "--revoked", "not-hex") == 2


class TestVerdicts:
    def test_a_published_revocation_verifies(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        body = _crl(ca, number=131, serials=[0x5A01, 0x5A02, 0x5A03])
        rc = _run(verifier, body, tmp_path,
                  "--revoked", "5A01", "--revoked", "5a02",
                  "--absent", "5AFF", "--min-crl-number", "131")
        assert rc == 0
        out = capsys.readouterr().out
        assert "CRL-PUBLICATION-VERIFIED serials=2" in out
        assert "LISTED 5A01" in out
        assert "NEGATIVE-CONTROL=5AFF absent" in out
        assert "CRL-ENTRY-COUNT=3" in out

    def test_an_unpublished_serial_fails(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The item-26 case exactly: revoked at the CA, absent from the CRL."""
        body = _crl(ca, number=131, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", "--revoked", "5A02")
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
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01",
                  "--min-crl-number", "130")
        assert rc == 1
        assert "is below the required minimum" in capsys.readouterr().err

    def test_a_crl_with_no_number_cannot_satisfy_a_floor(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        body = _crl(ca, number=None, serials=[0x5A01])
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01",
                  "--min-crl-number", "130")
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
        rc = _run(verifier, body, tmp_path, "--revoked", "5A01", "--absent", "5AFF")
        assert rc == 1
        captured = capsys.readouterr()
        assert "NEGATIVE-CONTROL=5AFF PRESENT" in captured.out
        assert "proves nothing" in captured.err

    def test_nothing_to_check_does_not_claim_a_verification(
        self, verifier: ModuleType, tmp_path: Path, ca: tuple[rsa.RSAPrivateKey, x509.Name],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """An empty check reporting success is how a green gate stops meaning anything."""
        rc = _run(verifier, _crl(ca, number=131, serials=[]), tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert "NO-SERIALS-SUPPLIED" in out
        assert "CRL-PUBLICATION-VERIFIED" not in out

    def test_an_unreachable_cdp_is_indeterminate_not_a_verdict(
        self, verifier: ModuleType, capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A fetch failure says nothing about the serials, and must claim nothing.

        Exit 2, distinct from the exit 1 that means "checked, and the CRL does
        not carry them" — a teardown that treated the two alike would report a
        network problem as an unpublished revocation, or worse, the reverse.
        """
        rc = verifier.main(
            ["--url", "http://127.0.0.1:9/ca.crl", "--revoked", "5A01",
             "--timeout", "1"]
        )
        assert rc == 2
        assert "CRL-PUBLICATION-INDETERMINATE" in capsys.readouterr().err

    def test_a_body_that_is_not_a_crl_is_indeterminate(
        self, verifier: ModuleType, tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        rc = _run(verifier, b"this is not a CRL", tmp_path, "--revoked", "5A01")
        assert rc == 2
        assert "CRL-PUBLICATION-INDETERMINATE" in capsys.readouterr().err
