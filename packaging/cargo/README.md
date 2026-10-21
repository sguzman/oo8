# Development installs directly from main with Cargo

This is the **unreleased-development channel** for oo8. It does not need
GitHub Releases, a Soar manifest, a PKGBUILD, or a pacman repository.
The release channel remains GitHub Releases + Soar. Choose **one** daemon
source for your active systemd user service; never start both simultaneously.

## Install current main

```fish
cargo install --git https://github.com/sguzman/oo8.git --branch main --package oo7-daemon --locked
```

The `oo7-daemon` Cargo package builds two binaries, `oo7-daemon` and
`oo7-daemon-login`, into the default Cargo binary directory,
`~/.cargo/bin`. If you use a customized `CARGO_HOME` or
`CARGO_INSTALL_ROOT`, the directory may differ.

## Update to latest main, without publishing a release

```fish
cargo install --git https://github.com/sguzman/oo8.git --branch main --package oo7-daemon --locked --force
```

Re-run that command whenever you want the latest development commit. Cargo
does **not** automatically watch the branch or rebuild an already installed
binary when new commits land. `--force` makes a reinstall reliable even
when the crate's semantic version has not changed. You can automate this
command separately, but avoid unattended restarts of a credential service.

Cargo installs the daemon executable, **not** privileged PAM modules,
desktop portal registration, or a systemd unit. The daemon itself can unlock
the keyring through the existing systemd credential without requiring PAM.
It still needs the one-time systemd service configuration below.

## One-time systemd integration (development channel only)

The [Cargo user-service template](oo7-daemon.service) points to
`%h/.cargo/bin/oo7-daemon`. It retains the `org.freedesktop.secrets`
D-Bus name and the `oo7.keyring-encryption-password` systemd credential.

Before replacing the live system service:

1. Confirm the executable exists at the configured location.
2. Back up the encrypted keyrings and preserve the existing service unit.
3. Exercise the exact binary in an isolated D-Bus session against disposable
   keyrings and verify rollback.
4. Install the template at `~/.config/systemd/user/oo7-daemon.service`,
   reload the user manager, and switch at a controlled login/restart.

A user-level unit at that path shadows the system-installed user unit.
If you have already installed the Soar unit there, **do not install a second
unit with the same name**. Choose either Soar or Cargo, then change
`ExecStart` **once** if switching. Both installation channels use the same
Secret Service bus name, so only one daemon instance may own it.

After future Cargo rebuilds, the configured `ExecStart` path is unchanged.
The running daemon uses the new executable after the next service restart
or login. There is no need to modify systemd for every update.

Rollback: restore the previous user service or remove this override and
reload the user manager; do not delete existing encrypted keyring data.

See [the release-oriented Soar path](../soar/README.md) for installing
versioned releases instead of current `main`.
