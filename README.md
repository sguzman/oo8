# oo8

oo8 is an independently maintained fork of [oo7](https://github.com/linux-credentials/oo7), a Linux [Secret Service](https://specifications.freedesktop.org/secret-service-spec/latest/) provider.

**Status:** development. Do not replace a working system keyring using an unvalidated build. This fork preserves oo7's data formats, service identifiers, binaries, and license while adding independent reliability checks and Arch packaging.

- [Maintenance and safe rollout](OO8.md)
- [Isolated D-Bus startup regression](tests/oo8-startup-race.sh)
- [Arch package recipe](packaging/arch/PKGBUILD)
- [Upstream project documentation](https://github.com/linux-credentials/oo7#readme)

## Development

The repository retains the full upstream Rust workspace. It uses Rust edition 2024, with per-crate requirements inherited from upstream.

Build and test the source using Cargo. The oo8 startup test additionally needs `dbus-run-session` and `dbus-send`; it runs exclusively against disposable keyring files. CI builds a staging Arch package that supplies the existing `org.freedesktop.secrets` interface and oo7-compatible filenames. CI does **not** install or deploy the package to any user's computer.

## License

MIT, preserving the original upstream notices and contributors.
