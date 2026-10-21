# oo8

oo8 is an independently maintained fork of [oo7](https://github.com/linux-credentials/oo7), a Linux [Secret Service](https://specifications.freedesktop.org/secret-service-spec/latest/) provider.

**Status: development.** The live desktop must not be switched over until a fully tested standalone release exists. Existing encrypted keyrings, systemd credentials, and upstream MIT attribution are preserved.

## Canonical installation, updates, and service management

**oo8 is distributed from this GitHub repository through GitHub Releases and managed on Linux with Soar.** This is the expected install and update workflow, not an optional alternative to pacman.

1. **Install (once):** After the initial tested release, register oo8 with Soar using the [Soar package declaration](packaging/soar/packages.toml). Soar downloads and manages the released executables.
2. **Configure systemd (once):** Install the [user-service unit](packaging/soar/oo7-daemon.service) and reload/enable it. It must target a stable Soar-managed executable link and preserve `org.freedesktop.secrets` plus the existing `oo7.keyring-encryption-password` credential.
3. **Publish new versions:** Develop on `main`; version tags publish tested GitHub Releases. Routine commits alone are not installed releases.
4. **Update:** Run `soar update`. New releases replace the managed executables without editing the user-service unit or Soar declaration. The running daemon takes the new executable after the next service restart/login.
5. **Maintain:** Keep upstream oo7 compatibility, encrypted keyrings, release validation, and rollback instructions. System-installed PAM modules and desktop portal registration are separately managed; Soar does not install those privileged/system integration files.

**No pacman repository registration, PKGBUILD updates, AUR publishing, or extra GitHub repository is required for oo8's normal release/install/update lifecycle.** Do not swap the live daemon until the initial Soar release, command paths, and safe rollback procedure have been verified. The setup templates are a rollout plan, not evidence that the machine is already migrated.

Full procedure: [Soar and systemd setup](packaging/soar/README.md).

- [One-time Soar + user-service setup](packaging/soar/README.md)
- [Soar declarative package fragment](packaging/soar/packages.toml)
- [User service template](packaging/soar/oo7-daemon.service)
- [Independent GitHub release builder](.github/workflows/oo8-soar.yml)
- [Reproducible isolated D-Bus startup regression](tests/oo8-startup-race.sh)
- [Maintenance and rollout policy](OO8.md)
- [Download releases](https://github.com/sguzman/oo8/releases)

**Distribution:** GitHub Releases -> Soar -> fixed user-service executable link. Soar tracks and updates released binaries through `soar update`; no pacman registration, manually maintained PKGBUILD, separate GitHub repo, or repeated systemd edits. A running daemon uses the new executable after the next service restart/login.

Soar does not manage PAM modules or desktop portal registration. The first rollout focuses on the user daemon and existing systemd encrypted-credential unlock. Other integration is explicitly a separate tested milestone.

---

## Upstream oo7 usage and developer documentation

### OO7

[![docs](https://docs.rs/oo7/badge.svg)](https://docs.rs/oo7/) [![crates.io](https://img.shields.io/crates/v/oo7)](https://crates.io/crates/oo7) ![CI](https://github.com/linux-credentials/oo7/workflows/CI/badge.svg) [![Coverage](https://linux-credentials.github.io/oo7/coverage/badges/flat.svg)](https://linux-credentials.github.io/oo7/coverage/)

James Bond went on a new mission and this time as a [Secret Service provider](https://specifications.freedesktop.org/secret-service-spec/latest/).

The repository consists of the following projects:

- [cargo-credential](./cargo-credential/): a [cargo credential](https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html#registry-authentication) provider
- [cli](./cli/): a secret-tool replacement
- [client](./client/): the client side library
- [git-credential](./git-credential/): a [git credential helper](https://git-scm.com/docs/gitcredentials), replacement for git-credential-libsecret
- [pam](./pam/): PAM integration for the server implementation
- [portal](./portal/): [org.freedesktop.impl.portal.Secret](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.Secret.html) implementation
- [server](./server/): [org.freedesktop.secrets](https://specifications.freedesktop.org/secret-service-spec/latest/) server implementation
- [kwallet/cli](./kwallet/cli): a simple CLI to read KWallet `.kwl` files
- [kwallet/parser](./kwallet//parser): Parse Kwallet `.kwl` files, used for automatic migration on the server side.

## Hacking on oo7 services

### Testing oo7-daemon

The daemon can be testing by simply compiling and running the binary with

```sh
cargo run --bin oo7-daemon -- --verbose --replace --login
```

Note however that if `gnome-keyring-daemon` is running, it will need to be
killed directly before running `oo7-daemon`, as it is not running as a systemd
service.

### Testing oo7-portal

The oo7-portal service can be tested using [systemd-sysext][systemd-sysext].
Directly running the binary is possible, but without a `oo7-portal.portal` file,
`xdg-desktop-portal` will ignore it.

First build the services on its subdirectory:

```sh
cd portal
meson setup --prefix=/usr _build
meson compile -C _build
DESTDIR=oo7-extension meson install -C _build
```

This will create a `oo7-extension` directory under `portal/_build`.

> [!WARNING]
> In systems with SELinux, the sysext directory must be relabeled with their system context so that it doesn't break.
> ```
> setfiles -r "_build/oo7-extension" "/etc/selinux/targeted/contexts/files/file_contexts" "_build/oo7-extension"
> chcon --user=system_u --recursive "_build/oo7-extension"
> ```

Move the build directory to a directory recognized by `systemd-sysext` like `/run/extensions`, afterwards extensions can be reloaded via

```sh
systemd-sysext refresh --force
```

The portal can be then started with:
```sh
/usr/libexec/oo7-portal --replace --verbose
```

In order for `xdg-desktop-portal` to use `oo7-portal` as a server for
`org.freedesktop.impl.portal.Secret` it needs to be configured via a
[portals.conf][portals.conf] file at `/etc/xdg-desktop-portal/portals.conf`, see
the `portals.conf(5)` man page.

This can be achieved by creating a file at
`~/.config/xdg-desktop-portal/gnome-portals.conf` with contents:

```desktop
[preferred]
default=gnome;gtk;
org.freedesktop.impl.portal.Secret=oo7-portal;gnome-keyring;
```

and then, restarting `xdg-desktop-portal` via

```sh
systemctl restart --user xdg-desktop-portal
```

If more output is required, the later can be replaced with:

```sh
/usr/libexec/xdg-desktop-portal --replace --verbose
```

## Translations

Helping to translate oo7 or add support to a new language is very welcome. You
can find everything you need at:
[l10n.gnome.org/module/oo7/](https://l10n.gnome.org/module/oo7/)

## License

The project is released under the MIT license.

[portals.conf]: https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html
[systemd-sysext]: https://www.freedesktop.org/software/systemd/man/latest/systemd-sysext.html
