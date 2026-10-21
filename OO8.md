# oo8 maintenance and rollout

oo8 is an independently maintained fork of [linux-credentials/oo7](https://github.com/linux-credentials/oo7). The existing Secret Service, keyring storage, credential name, binaries, and D-Bus contracts stay compatible until changes are separately validated. The original MIT license and upstream authorship remain intact.

## Immediate scope

- Prevent the daemon from claiming `org.freedesktop.secrets` until its internal connection and collections are initialized.
- Confirm a disposable `oo7.keyring-encryption-password` provided through `CREDENTIALS_DIRECTORY` unlocks the default keyring under a passwordless desktop login model.
- Treat a panic in any service worker as a regression, even if the process remains running.
- Maintain an independent Arch package for the complete service, PAM module, portal, and helpers, published directly as assets on GitHub Releases (no separate pacman repository).
- Continue to incorporate upstream security and compatibility updates. `credentialsd` and `libwebauthn` are separate projects, not oo8 dependencies.

## Safety gates before local installation

1. GitHub CI must pass for the exact commit being packaged.
2. A local package must be built without installing it, then inspected for file conflicts and manifest completeness.
3. Exercise the package with private D-Bus and temporary keyrings; no integration tests may use real keyring data.
4. Back up encrypted keyring files and record existing package and service state before any replacement.
5. Verify replacement and rollback paths; no deletion of original encrypted keyrings, Edge profiles, or systemd credentials.
6. Package installation remains an explicit separate action; successful CI never automatically updates a user's machine.
7. Only version tags in the form `v0.7.0.oo8.1` trigger publication to GitHub Releases; ordinary commits create temporary CI artifacts, not releases. A tagged package must pass manifest checks and the isolated startup regression first.

### Regression gate

`tests/oo8-startup-race.sh` launches the daemon repeatedly in a fresh private D-Bus session with disposable on-disk keyrings and an artificial credential directory. It rapidly queries the Secret Service during startup, checks the default collection is unlocked, and rejects worker panics.

Run through `bash tests/oo8-startup-race.sh` after building `oo7-daemon`. This test is Linux-specific and needs `dbus-run-session` and `dbus-send`.

### Current status

This fork begins from upstream main commit `901e7406`. Do not treat the current source tree as production-validated or claim that a browser's lost tabs were necessarily caused by the daemon. The startup regression gate and packaging validation must finish before advising an installation.

## Upstream workflow

Work on the existing `main` branch. Preserve the ability to compare and synchronize with upstream. Review upstream changes for compatibility and security before releasing an oo8 package. Use Rust edition 2024 throughout the workspace unless a particular crate has a documented compatibility requirement.
