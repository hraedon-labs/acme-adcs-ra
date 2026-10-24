# Contributing to acme-adcs-ra

This is issuance-path infrastructure. Read `AGENTS.md` for the hard rules before
changing anything, and `docs/handover.md` for how the pieces fit. The short
version of the rules: no signing key, ever; no stored ADCS credentials;
issuance policy is plain code; every issuance is audited.

## Set up

You need Python 3.12 or later and [`uv`](https://docs.astral.sh/uv/). For the
PowerShell tests you need `pwsh` and Pester 5.7.1.

```bash
uv sync --locked --extra dev
```

Install the git hooks once per clone:

```bash
scripts/install-git-hooks.sh
```

## Checks to run before you push

These are what CI runs. Run them all.

```bash
.venv/bin/ruff check .
.venv/bin/mypy src            # strict
.venv/bin/pytest -q
```

```powershell
Import-Module Pester -RequiredVersion 5.7.1 -Force
$config = New-PesterConfiguration
$config.Run.Path = "tests/pester"
$config.Run.Exit = $true
Invoke-Pester -Configuration $config
```

If you changed anything under `scripts/` or the installer, the Pester suite must
also pass under **Windows PowerShell 5.1**, which is what production uses. A pass
under `pwsh` 7 on Linux is not enough: the two differ in ways that have hidden
real defects. CI has a job for it.

If you changed the ACME surface, also run the stock-client harness. It needs
Docker and network access:

```bash
interop/run.sh
```

If you change dependencies, change `pyproject.toml`, then `uv lock`, and
update the hash-pinned `deploy/*.lock.txt` files deliberately (not yet
documented: the exact command that generates them). CI installs with
`--locked`, so a mismatch with `uv.lock` fails.

## What a change needs

- **A test that fails without the change.** For a security fix, show it fails
  against the old code (the existing `tests/test_security_review_*.py` files are
  the pattern). A test that cannot fail proves nothing; see the 2026-09-21
  entry in `docs/status-log-2026.md` for a real example.
- **A `CHANGELOG.md` entry under `[Unreleased]`.** Say what changed for an
  operator and flag anything breaking.
- **Doc updates in the same change.** If behavior, a setting, or an operator
  step changes, update `docs/configuration.md`, `docs/operations.md` or the
  README with it.
- **Placeholders, not real names.** Committed files use `CA01`,
  `WORK-DOMAIN.local` and similar. Real CA names, hostnames, template names, EAB
  keys and domain accounts never go in a commit or a commit message.
- **Independent review for anything that touches issuance, authentication,
  revocation or the installer.** The project's practice has been two separate
  reviews, with at least one that runs the code.
- **A live re-proof for any change to the issuance leg.** CI cannot reach a CA.
  See `docs/live-reproof-runbook.md`. Say in the pull request whether the
  re-proof was run, and on which commit.

## Identifier gate and publication guard

Two guards protect against publishing work-domain identifiers. Read this before
your first commit in a copy of the repository.

- **Identifier gate** (`scripts/check_committed_identifiers.py`, the pre-commit
  and commit-msg hooks, and the `identifier-gate` CI job). It scans tracked
  files and commit messages for the identifiers in a denylist you provide, in
  `$FORBIDDEN_IDENTIFIERS`, in a gitignored `.identifiers-denylist.local` at the
  repository root, or in `~/.config/agent-suite/forbidden-identifiers`. The
  denylist itself is never committed. Without one, the hooks on a repository
  declared public refuse the commit; the only bypass is
  `GATE_ALLOW_NO_DENYLIST=1`, which prints a warning each time. In CI the secret
  is `FORBIDDEN_IDENTIFIERS`.
- **Publication guard** (`publication.toml`, the pre-push hook). It declares the
  repository owner a push must go to, the author email addresses allowed, and
  the visibility. **As committed it names the upstream owner and author.** In a
  copy under a different organisation, the pre-push hook will refuse to push
  and the CI gate will fail for a missing denylist, until you edit
  `publication.toml` to match your organisation, authors and visibility, and set
  the CI secret. Make that edit deliberately, in its own commit, and keep it
  through upstream syncs.

## Conventions

- Treat every code path that can issue or revoke a certificate as
  security-critical.
- Failure should close, not open. When choosing how strict a check should be,
  choose stricter: loosening later is cheaper than tightening.
- Do not add a switch that silently does nothing. A security-relevant setting
  that cannot take effect should refuse startup (see `audit_prune_enabled`).
- Keep operator-facing text plain and specific: what happens, why, and what to
  do. Keep the warnings and the "must" and "never" statements.

## Reporting a vulnerability

Do not open a public issue. See `SECURITY.md`.
