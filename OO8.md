# oo8 maintenance and rollout

oo8 is an independently maintained fork of [linux-credentials/oo7](https://github.com/linux-credentials/oo7). The existing Secret Service, keyring storage, credential name, binaries, and D-Bus contracts stay compatible until changes are separately validated. The original MIT license and upstream authorship remain intact.

## Immediate scope

- Prevent the daemon from claiming `org.freedesktop.secrets` until its internal connection and collections are initialized.
- Confirm a disposable `oo7.keyring-encryption-password` provided through `CREDENTIALS_DIRECTORY` unlocks the default keyring under a passwordless desktop login model.
- Treat a panic in any service worker as a regression, even if the process remains running.
- Build independent, versioned Linux executable archives on GitHub Releases and let Soar track them. Preserve a stable user-service executable symlink so installation and systemd configuration are each one-time tasks.
- Treat PAM/portal integration as a distinct compatibility milestone, since Soar cannot install privileged PAM modules or register a portal automatically.
- Continue to incorporate upstream security and compatibility updates. `credentialsd` and `libwebauthn` are separate projects, not oo8 dependencies.

## Safety gates before local installation

1. GitHub CI must pass for the exact commit being packaged.
2. Build a standalone Soar-compatible executable archive, inspect its contents and executable paths, and test the exact daemon before publication.
3. Exercise the daemon with private D-Bus and temporary keyrings; no integration tests may use real keyring data.
4. Back up encrypted keyring files and record existing package and service state before any replacement.
5. Verify replacement and rollback paths. Keep separate `oo7-daemon.service` and `oo8-daemon.service` units and route the D-Bus activation alias to only the selected provider; never delete original encrypted keyrings, Edge profiles, or systemd credentials.
6. The first Soar installation and user-service setup require a separate explicit rollout; GitHub CI never installs on anyone's computer. After installation, user-initiated `soar update` fetches new stable releases.
7. Version tags `v*` trigger GitHub Releases; ordinary commits produce temporary CI artifacts, not releases. Tagged archives must pass content checks and isolated startup tests.

### Regression gate

`tests/oo8-startup-race.sh` launches the daemon repeatedly in a fresh private D-Bus session with disposable on-disk keyrings and an artificial credential directory. It rapidly queries the Secret Service during startup, checks the default collection is unlocked, and rejects worker panics.

Run through `bash tests/oo8-startup-race.sh` after building `oo7-daemon`. This test is Linux-specific and needs `dbus-run-session` and `dbus-send`.

### Current status

This fork begins from upstream main commit `901e7406`. Do not treat the current source tree as production-validated or claim that a browser's lost tabs were necessarily caused by the daemon. The startup regression gate and Soar archive release validation must finish before advising an installation.

## Dependencies and security audits

- The [dependency refresh workflow](.github/workflows/dependency-refresh.yml) runs a compatible `cargo update`, replaces the yanked `inout 0.2.3` with `0.2.2`, verifies workspace compilation and daemon tests, then commits only the updated lockfile to `main`. There is no force-push. Cargo dependencies still constrained to older major versions require a separate source migration and corresponding tests.
- The current RustSec *unmaintained* advisories concern `zvariant`, `zvariant_derive`, and `zbus_names`, retained through `zbus 5`. `zbus 6` consolidates those APIs, but the current `ashpd 0.13` integration uses `zbus 5`. Upgrading only one side creates incompatible D-Bus types. Coordinate the `zbus` and `ashpd` upgrades with source changes and keep the audit gate visible until the migration passes.
- CI uses `cargo-deny` with `unmaintained = "workspace"`: **all known vulnerabilities still fail**, and crates maintained as direct workspace dependencies fail when marked unmaintained. The three zbus-5-era **transitive** unmaintained crates are deferred, not resolved. This is an explicit policy scope, not a claim of a clean full-tree advisory database. Migration to zbus 6 and compatible ashpd remains open.
- Do not globally ignore vulnerability advisories or label a dependency-only release production-safe without passing the isolated credential regression and normal Rust CI.

## Upstream workflow

Work on the existing `main` branch. Preserve the ability to compare and synchronize with upstream. Review upstream changes for compatibility and security before releasing an oo8 package. Use Rust edition 2024 throughout the workspace unless a particular crate has a documented compatibility requirement.
