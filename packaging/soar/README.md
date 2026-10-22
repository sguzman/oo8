# oo8 installation with Soar

oo8 is delivered directly from [this repository's GitHub Releases](https://github.com/sguzman/oo8/releases). One GitHub repo. No AUR entry, PKGBUILD maintenance, pacman source registration or second GitHub repo.

**Release status:** Do not migrate an active password store before a tested release exists and an isolated daemon + credential test has passed. Never delete or reset existing keyrings, Edge profiles, or encrypted systemd credentials.

## Managed binaries

The release artifact `oo8-x86_64-linux.tar.gz` is built from the Rust workspace on Arch CI and contains executables under `bin/`. Soar's native GitHub forge integration tracks new stable releases and places links for the supplied executables in its managed bin directory.

The one-time [Soar declaration](packages.toml) can be **merged into** an existing `~/.config/soar/packages.toml`. Do not overwrite other installed packages in that file. Then `soar apply` installs the current tested release. Subsequent `soar update` commands update it from GitHub Releases. The Soar declaration never needs a new version number and stays unpinned. Soar's normal update does not itself restart a running service.

## One-time user service

[oo8-daemon.service](oo8-daemon.service) is a complete **user-level** systemd unit. Once installed at `~/.config/systemd/user/oo8-daemon.service`, it provides a separately named user unit; the distro's `oo7-daemon.service` remains available for rollback. It preserves the well-known `org.freedesktop.secrets` D-Bus name and imports the existing `oo7.keyring-encryption-password` systemd user credential. It invokes the fixed Soar symlink path `%h/.local/share/soar/bin/oo8-daemon`. No service rewrite is needed when the executable is updated.

After installing the unit, reload the user manager, disable `oo7-daemon.service`, and enable `oo8-daemon.service` without `--now` for a controlled next-reboot switch. Enabling oo8 also installs the `dbus-org.freedesktop.secrets.service` activation alias. Inspect any vendor D-Bus `SystemdService=` mapping and the effective alias first. Make the service switch only after verifying the Soar symlink and backing up the encrypted keyrings; preferably activate it at next login rather than restarting a live browser session. A daemon already running stays on its previous binary until the next service restart/login. This is an intentional limitation, not repeated configuration work.

**Important:** Soar installs user-space binaries. It does *not* install privileged PAM modules, D-Bus portal registration files, or system-level units. The current personal auto-login flow uses the systemd credential, so it does not require changing PAM to make the daemon work. Full replacement of all upstream desktop integration is a separate tested milestone, not part of this initial migration. Until then the existing distribution package may still provide those integration files, and pacman may continue upgrading that package without controlling the oo8 user daemon.

## Validation and rollback

- GitHub CI builds and tests an isolated daemon under a private D-Bus with disposable encrypted keyrings before making a release.
- Keep encrypted keyring files intact and make a backup before switching the live desktop.
- Check that `soar` links `oo8-daemon` correctly and that the user unit resolves `ExecStart` before switching services.
- To revert, disable the new `oo8-daemon.service`, re-enable `oo7-daemon.service`, reload the user manager, and switch at a controlled restart. Keep Soar binaries and encrypted keyrings intact while diagnosing.
- The packaged binaries are dynamically linked against a compatible Linux userspace; build and test on Arch/EndeavourOS before using elsewhere.

## Release naming

A version tag `v...` runs the GitHub release workflow. Commits to `main` produce CI artifacts but do not change the installed copy. A release is published only after its packaged standalone daemon passes the isolated D-Bus test. Do not tag a production release until the initial integration testing is complete.

The release archives contain distinct `oo8-*` and `*-oo8` executable names. During daemon-only adoption `oo8-daemon.service` is distinct from the distribution's `oo7-daemon.service`; do not enable both. The oo8 D-Bus alias routes activation through its own unit when selected. The D-Bus service name and stored systemd credential filename remain unchanged.
