# Upgrading and rolling back

How to move an installed RA to a new version, and how to go back. It is built
from what the installer does (`scripts/install-windows.ps1`) and from the
changelog. Where the repository does not say, this page says so.

Before any upgrade:

- Read the `CHANGELOG.md` entries between your version and the target. Look for
  **Breaking** and **Upgrade if** notes. Examples: 1.10.0 changed the token
  parameters of `Sync-Revocations.ps1` into switches; 1.11.0 changed the
  `revokeCert` response shape; 1.12.0 changed which audit rows appear, so SIEM
  rules that count rows need a look.
- Check the README's Status section. An upgrade to anything newer than the last
  live-proven build needs the live re-proof
  ([`live-reproof-runbook.md`](live-reproof-runbook.md)) before it serves
  production.
- Take a backup (`operations.md`, "Backup and restore"): the database, the env
  file, and the SIEM JSONL file. Use SQLite's online backup or stop the pool.
  The installer never touches the database, but a schema migration runs on the
  next start.

## Upgrade

1. Put the release tree for the target version in an administrator-only local
   directory (not `C:\Temp`). The installer refuses a tree another user can
   write to ([`operator-requirements.md`](operator-requirements.md), 3.6).
2. Run the same `install-windows.ps1` command you used before, from an elevated
   PowerShell. It is safe to re-run. It never overwrites `acme-ra.env` or an
   existing `web.config`, so settings survive. If a new version adds a setting,
   add it yourself (see [`configuration.md`](configuration.md)).
3. The installer stops the pool, rebuilds the runtime tree from scratch from the
   hash-pinned dependency lists, verifies ownership and ACLs, and starts again.
   The code tree is replaced on every install; the state tree is kept.
4. Copy the new `scripts/` directory, including `scripts/lib/`, to the
   administrator-only location your scheduled revocation tasks run from, and
   re-register the tasks if the changelog says their parameters changed. The
   installer does not place this copy for you (`operations.md`, "Automated
   revocation").
5. Verify: [`operator-requirements.md`](operator-requirements.md) section 5, then
   `GET /directory`. On first start the store migrates its schema. One migration
   refuses to start if it cannot derive a serial for every certificate row; the
   database is left unchanged, so you can fix the rows and start again
   (`operations.md`, "Upgrading: the schema migration can refuse to start").

The version string is not a reliable marker of what is deployed when running a
commit between releases (`pyproject.toml` stays at the last released version).
Confirm what is running by checking for a file or default that you know the
change added.

## Rollback

There are two cases.

**The install fails while building.** The installer restores the previous
runtime tree automatically and re-proves the state tree, then reports the
error. If it prints that nothing could be restored, the host has no runtime
until a later install succeeds.

**The install succeeded and you want the old version back.** The installer
removes the previous runtime once the new one is built, so there is no
automatic way back after that point. This is deliberate: a failed proof of the
new tree means something on the host is interfering, and the right response is
to stop, not to serve the old runtime quietly. To go back:

1. Stop the pool.
2. Check out the previous release tag into an administrator-only directory and
   run its installer, as in the upgrade above.
3. If the newer version migrated the database schema, restore the database
   backup taken before the upgrade. Certificates issued and audit rows written
   after that backup are then missing from the RA store; reconcile them against
   the CA database and the SIEM copy (`operations.md`, restore step 7).

Not yet documented: whether an older version can open a database that a newer
version has already migrated. Do not assume it can; restore the backup.
