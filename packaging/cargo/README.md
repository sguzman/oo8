# Development installs directly from main with Cargo

This is the **unreleased-development channel** for oo8. It does not need
GitHub Releases, a Soar manifest, a PKGBUILD, or a pacman repository.
The release channel remains GitHub Releases + Soar. Choose **one** daemon
source for your active systemd user service; never start both simultaneously.

## Install from the local oo8 source checkout

Run from the oo8 repository root after updating the checkout.

```fish
cargo install --path ./server --locked
```

The `oo8-daemon` Cargo package builds two distinct oo8 binaries,
`oo8-daemon` and `oo8-daemon-login`, into the default Cargo binary directory,
`~/.cargo/bin`. If you use a customized `CARGO_HOME` or
`CARGO_INSTALL_ROOT`, the directory may differ.

## Reinstall current local changes, without publishing a release

```fish
cargo install --path ./server --locked --force
```

Re-run that command to install updated code from your local checkout. Cargo
does **not** automatically watch the branch or rebuild an already installed
binary when new commits land. `--force` makes a reinstall reliable even
when the crate's semantic version has not changed. You can automate this
command separately, but avoid unattended restarts of a credential service.

Cargo installs the daemon executable, **not** privileged PAM modules,
desktop portal registration, or a systemd unit. The daemon itself can unlock
the keyring through the existing systemd credential without requiring PAM.
It still needs the one-time systemd service configuration below.

## One-time systemd integration (development channel only)

The [Cargo user-service template](oo8-daemon.service) points to
`%h/.cargo/bin/oo8-daemon`. It retains the `org.freedesktop.secrets`
D-Bus name and the `oo7.keyring-encryption-password` systemd credential.

Before replacing the live system service:

1. Confirm the executable exists at the configured location.
2. Back up the encrypted keyrings and preserve the existing service unit.
3. Exercise the exact binary in an isolated D-Bus session against disposable
   keyrings and verify rollback.
4. Install the template at `~/.config/systemd/user/oo8-daemon.service`.
5. At the controlled switchover, disable `oo7-daemon.service` and enable
   `oo8-daemon.service` (without `--now` when staging for the next reboot).
   Enabling oo8 installs its `dbus-org.freedesktop.secrets.service` alias.
6. Verify the alias resolves to oo8, and confirm the new service started after
   the next full reboot. Do not assume logging out restarts a lingering user manager.

The oo8 unit has a **distinct name** from the distribution's `oo7-daemon.service`.
Cargo and Soar provide alternative contents for the **same** `oo8-daemon.service`
unit: choose one source, never both. The `[Install]` D-Bus alias
`dbus-org.freedesktop.secrets.service` is created by `systemctl --user enable`,
not by hand. Disable upstream oo7 before enabling oo8 so this alias does not
keep pointing at the old daemon. This changes only startup policy; disabling
an active oo7 service does **not** stop it. D-Bus may activate oo8 earlier
than the planned reboot if oo7 unexpectedly exits after changing the alias.
There is only one `org.freedesktop.secrets` bus owner at a time.

After future Cargo rebuilds, the configured `ExecStart` path is unchanged.
The running daemon uses the new executable after the next service restart
or login. There is no need to modify systemd for every update.

Rollback: disable `oo8-daemon.service`, re-enable `oo7-daemon.service`,
reload the user manager and restart the provider at a controlled time.
Do not delete existing encrypted keyring data. Check local `systemctl --user cat`
and the D-Bus alias before relying on the rollback.

See [the release-oriented Soar path](../soar/README.md) for installing
versioned releases instead of current `main`.

The `oo8-*` names are distinct from distribution-provided upstream executables. The Cargo package, process executable, and new user service are all named `oo8-daemon`. The **stored** credential filename `oo7.keyring-encryption-password` stays unchanged, deliberately, so existing encrypted keyrings can be unlocked. Neither Cargo nor this unit changes PAM configuration.

## Example staged switch (not a live-restart command)

Run from the updated oo8 checkout **only after** verifying the current unit, D-Bus activation configuration, encrypted-keyring backup, and rollback path. Do not use `--now` or `restart` mid-session:

```fish
install -Dm644 packaging/cargo/oo8-daemon.service ~/.config/systemd/user/oo8-daemon.service
systemctl --user daemon-reload
systemctl --user disable oo7-daemon.service
systemctl --user enable oo8-daemon.service
systemctl --user is-enabled oo8-daemon.service
systemctl --user cat dbus-org.freedesktop.secrets.service
```

The old oo7 process can keep running until reboot. Unit/alias changes may affect automatic restarts or bus activation **before** reboot, so stage close to the planned reboot. The distro's D-Bus activation file may have its own `SystemdService=` mapping: inspect it first rather than assuming the alias is sufficient. Do not modify the vendor's files. The standard oo7 credential filename and `org.freedesktop.secrets` remain shared for compatibility.
