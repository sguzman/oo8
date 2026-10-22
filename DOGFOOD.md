# oo8: first dogfood gates

Begin with an isolated canary of the exact release archive. A passing CI run
does not by itself authorize switching the live desktop credential service.

## Gate 0: disposable archive canary

1. From a successful **oo8 Soar release** GitHub Actions run, download the
   development artifact named `oo8-soar-<commit>`. It contains
   `oo8-x86_64-linux.tar.gz` and its `.sha256` file. A published GitHub Release
   may provide the same files after the actual tagged-release gate passes.
2. Place the archive and `.sha256` file beside each other.
3. In an oo8 source checkout, run as an ordinary user:

   ```sh
   bash tests/oo8-archive-canary.sh /path/to/oo8-x86_64-linux.tar.gz
   ```

The canary verifies the SHA-256, exact archive entries, and executable files.
It exercises the **unpacked** daemon and CLI on isolated D-Bus sessions with
temporary keyrings and PAM sockets, including startup, persistence, incorrect
credentials, recovery, competing owners, explicit replacement and stress.
It does not install a systemd unit or claim the real Secret Service bus name.
The Arch release workflow also runs this exact canary before saving artifacts
or publishing a tagged release.

## Gate 1: controlled live daemon trial (separate opt-in)

Before replacing the current daemon:

- Record the current executable, package version, D-Bus owner, and effective
  `systemctl --user cat oo7-daemon.service` output.
- Back up the existing **encrypted** keyrings separately, and preserve the
  encrypted systemd credential and original vendor user unit. Never log or
  upload passwords or private keyring contents.
- Confirm the exact packaged executable, service-unit `ExecStart`, and
  credential import. Test the **actual shipped unit** in a disposable systemd
  user manager; a minimal transient unit is not an equivalent test.
- Choose either Soar release or Cargo development installation; never run
  both as the live `org.freedesktop.secrets` owner.
- Do not change PAM, portal registration, or kernel/package integration as
  part of a daemon-only trial. Switch only at a controlled login or an
  explicitly authorized time, not during a live browser session.

Rollback: stop the new service, restore/remove only the oo8 user unit
override, reload the user manager and restore the previous service.
Do not delete or recreate encrypted keyrings during rollback.

The shipped Soar and Cargo user-service units deliberately avoid
capability-dropping directives that can fail with `218/CAPABILITIES` inside
unprivileged systemd managers. Restrictions retained in the unit are subject
to host kernel namespace support; verify their effective behavior on the
target computer separately. The CI disposable systemd test exercises the
actual Soar template, rather than assuming a transient unit is equivalent.

## Gate 2: follow-on compatibility

Privileged PAM installation, portal registration, and the coordinated
`zbus 6`/`ashpd` migration are separate from first daemon dogfooding.

## Trial record

Record commit SHA, archive SHA-256, exact CI run, canary result, selected
executable path and rollback readiness. Never include actual credentials.
