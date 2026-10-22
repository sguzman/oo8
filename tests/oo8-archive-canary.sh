#!/usr/bin/env bash
# Test the distributed artifact without touching a live desktop Secret Service.
set -euo pipefail

fail() { printf 'FAIL: oo8 archive canary: %s\n' "$*" >&2; exit 1; }
[[ "$EUID" -ne 0 ]] || fail "run as an unprivileged user, not root"
[[ "$#" -eq 1 ]] || fail "usage: bash tests/oo8-archive-canary.sh path/to/oo8-x86_64-linux.tar.gz"
for command in dbus-run-session dbus-send tar sha256sum mktemp; do
    command -v "$command" >/dev/null || fail "missing dependency: $command"
done

archive="$1"
[[ "$archive" == /* ]] || archive="$PWD/$archive"
[[ -f "$archive" && ! -L "$archive" ]] || fail "archive missing or a symlink"
[[ "$(basename "$archive")" == oo8-x86_64-linux.tar.gz ]] || fail "unexpected archive name"
checksum_file="$archive.sha256"
[[ -f "$checksum_file" && ! -L "$checksum_file" ]] || fail "matching .sha256 file required"
read -r expected_hash recorded_name < "$checksum_file"
[[ "$expected_hash" =~ ^[[:xdigit:]]{64}$ ]] || fail "invalid SHA-256 value"
[[ "$recorded_name" == "$(basename "$archive")" ]] || fail "checksum refers to a different archive"
actual_hash="$(sha256sum "$archive" | cut -d ' ' -f 1)"
[[ "$actual_hash" == "$expected_hash" ]] || fail "archive checksum mismatch"

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
root="$(cd -- "$script_dir/.." && pwd)"
scratch="$(mktemp -d)"
chmod 700 "$scratch"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -m 700 -p "$scratch/home" "$scratch/home/.config" "$scratch/home/.cache" "$scratch/unpacked"

expected="$(printf '%s\n' \
    'LICENSE' 'bin/' 'bin/oo7-daemon' 'bin/oo7-daemon-login' \
    'bin/oo7-portal' 'bin/oo7-cli' 'bin/git-credential-oo7' \
    'bin/cargo-credential-oo7' | LC_ALL=C sort)"
actual="$(tar -tzf "$archive" | LC_ALL=C sort)"
[[ "$actual" == "$expected" ]] || fail "archive contains unexpected or missing paths"

tar -xzf "$archive" -C "$scratch/unpacked" --no-same-owner --no-same-permissions
[[ -d "$scratch/unpacked/bin" && ! -L "$scratch/unpacked/bin" ]] || fail "invalid bin directory"
[[ -f "$scratch/unpacked/LICENSE" && ! -L "$scratch/unpacked/LICENSE" ]] || fail "license missing"
for name in oo7-daemon oo7-daemon-login oo7-portal oo7-cli git-credential-oo7 cargo-credential-oo7; do
    file="$scratch/unpacked/bin/$name"
    [[ -f "$file" && ! -L "$file" && -x "$file" ]] || fail "invalid executable: $name"
done

daemon="$scratch/unpacked/bin/oo7-daemon"
cli="$scratch/unpacked/bin/oo7-cli"
export HOME="$scratch/home"
export XDG_CONFIG_HOME="$scratch/home/.config"
export XDG_CACHE_HOME="$scratch/home/.cache"
export XDG_DATA_HOME="$scratch/home/.local/share"
export OO7_PAM_SOCKET="$scratch/pam.sock"
export OO8_STARTUP_ITERATIONS=4
export OO8_REPLACE_ITERATIONS=3

# Every integration script creates a distinct private D-Bus and temporary data.
# Clear inherited session addresses and internal recursion markers.
run_isolated() {
    env -u DBUS_SESSION_BUS_ADDRESS -u DBUS_STARTER_ADDRESS -u DBUS_STARTER_BUS_TYPE \
        -u CREDENTIALS_DIRECTORY -u OO8_LIFECYCLE_INSIDE \
        -u OO8_REPLACE_INSIDE -u OO8_OWNERSHIP_INSIDE -u OO8_STRESS_INSIDE \
        bash "$@"
}

printf 'oo8 canary: private-bus startup\n'
run_isolated "$root/tests/oo8-startup-race.sh" unused "$daemon"
printf 'oo8 canary: persistent encrypted keyring and recovery\n'
run_isolated "$root/tests/oo8-keyring-lifecycle.sh" "$daemon" "$cli"
printf 'oo8 canary: competing owners\n'
run_isolated "$root/tests/oo8-dbus-ownership.sh" "$daemon" "$cli"
printf 'oo8 canary: explicit replacement\n'
run_isolated "$root/tests/oo8-explicit-replace.sh" "$daemon" "$cli"
printf 'oo8 canary: concurrent replacement traffic\n'
run_isolated "$root/tests/oo8-replacement-stress.sh" "$daemon" "$cli"
printf 'PASS: archive contents, isolated startup, keyring recovery and handoffs\n'
