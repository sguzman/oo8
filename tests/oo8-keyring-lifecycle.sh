#!/usr/bin/env bash
# Exercise a persistent encrypted keyring through multiple daemon lifetimes.
# All data and credentials are generated here; no host keyrings are accessed.
set -euo pipefail

daemon="${1:-target/debug/oo7-daemon}"
cli="${2:-target/debug/oo7-cli}"
[[ "$daemon" == /* ]] || daemon="$PWD/$daemon"
[[ "$cli" == /* ]] || cli="$PWD/$cli"

if [[ "${OO8_LIFECYCLE_INSIDE:-}" != 1 ]]; then
    exec dbus-run-session -- env OO8_LIFECYCLE_INSIDE=1 bash "$0" "$daemon" "$cli"
fi

case_dir="$(mktemp -d)"
daemon_pid=""
phase=""
cleanup() {
    if [[ -n "$daemon_pid" ]]; then
        kill "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
        daemon_pid=""
    fi
    rm -rf "$case_dir"
}
trap cleanup EXIT

fail() {
    echo "FAIL: ${phase:-lifecycle}: $*" >&2
    if [[ -f "$case_dir/daemon.log" ]]; then
        cat "$case_dir/daemon.log" >&2
    fi
    exit 1
}

mkdir -m 700 -p "$case_dir/data" "$case_dir/credentials"
credential="$case_dir/credentials/oo7.keyring-encryption-password"
correct_password="oo8-disposable-lifecycle-key"
wrong_password="oo8-disposable-incorrect-key"
test_secret="oo8-disposable-persisted-secret"
test_attribute="oo8-test=$(basename "$case_dir")"

# On real user units, systemd populates CREDENTIALS_DIRECTORY. Simulate its
# contents with a private throwaway directory and no PAM involvement.
start_daemon() {
    phase="$1"
    local password="$2"
    if [[ "$password" == "__absent__" ]]; then
        rm -f "$credential"
    else
        printf '%s' "$password" > "$credential"
        chmod 600 "$credential"
    fi
    XDG_DATA_HOME="$case_dir/data" \
    CREDENTIALS_DIRECTORY="$case_dir/credentials" \
    OO7_PAM_SOCKET="$case_dir/pam.sock" \
        "$daemon" > "$case_dir/daemon.log" 2>&1 &
    daemon_pid=$!

    local ready=0
    for _ in {1..150}; do
        if ! kill -0 "$daemon_pid" 2>/dev/null; then
            fail "daemon exited before advertising the Secret Service"
        fi
        if dbus-send --session --print-reply --reply-timeout=150 \
            --dest=org.freedesktop.secrets /org/freedesktop/secrets \
            org.freedesktop.DBus.Properties.Get \
            string:org.freedesktop.Secret.Service string:Collections \
            > /dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.02
    done
    [[ "$ready" == 1 ]] || fail "daemon did not become ready"
}

stop_daemon() {
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    daemon_pid=""
}

collection_path() {
    dbus-send --session --print-reply --reply-timeout=500 \
        --dest=org.freedesktop.secrets /org/freedesktop/secrets \
        org.freedesktop.Secret.Service.ReadAlias string:default |
        sed -n 's/.*object path "\(\/org\/freedesktop\/secrets\/collection\/[^"]*\)".*/\1/p' |
        head -n 1
}

expect_lock_state() {
    local expected="$1" collection reply
    collection="$(collection_path)" || fail "could not resolve default collection"
    [[ -n "$collection" ]] || fail "default collection missing"
    reply="$(dbus-send --session --print-reply --reply-timeout=500 \
        --dest=org.freedesktop.secrets "$collection" \
        org.freedesktop.DBus.Properties.Get \
        string:org.freedesktop.Secret.Collection string:Locked)" \
        || fail "collection lock query failed"
    [[ "$reply" == *"boolean $expected"* ]] \
        || fail "expected Locked=$expected, got: $reply"
}

start_daemon "create" "$correct_password"
expect_lock_state false
printf '%s\n' "$test_secret" |
    "$cli" store "oo8 ephemeral test" "$test_attribute" \
    || fail "could not store a disposable item"
found="$("$cli" lookup --secret-only "$test_attribute")" \
    || fail "could not retrieve the stored disposable item"
[[ "$found" == "$test_secret" ]] || fail "stored item does not match"
stop_daemon

# A real persistent keyring must be present after the first process exits.
keyring="$case_dir/data/keyrings/v1/login.keyring"
[[ -s "$keyring" ]] || fail "persistent Login keyring file missing after shutdown"
before="$(sha256sum "$keyring" | cut -d' ' -f1)"

start_daemon "wrong credential" "$wrong_password"
expect_lock_state true
stop_daemon
[[ "$(sha256sum "$keyring" | cut -d' ' -f1)" == "$before" ]] \
    || fail "wrong credential changed existing encrypted keyring"

start_daemon "missing credential" "__absent__"
expect_lock_state true
stop_daemon
[[ "$(sha256sum "$keyring" | cut -d' ' -f1)" == "$before" ]] \
    || fail "missing credential changed existing encrypted keyring"

start_daemon "recover" "$correct_password"
expect_lock_state false
found="$("$cli" lookup --secret-only "$test_attribute")" \
    || fail "could not retrieve item after restoring the correct credential"
[[ "$found" == "$test_secret" ]] \
    || fail "previously stored secret changed across restarts"
stop_daemon
echo "PASS: persistent item, wrong/missing credential lock state, data integrity, and recovery"
