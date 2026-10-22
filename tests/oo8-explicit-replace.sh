#!/usr/bin/env bash
# Explicit --replace must retire the old daemon, hand over its PAM socket,
# and preserve a disposable persistent keyring. Never uses live credentials.
set -euo pipefail

daemon="${1:-target/debug/oo7-daemon}"
cli="${2:-target/debug/oo7-cli}"
[[ "$daemon" == /* ]] || daemon="$PWD/$daemon"
[[ "$cli" == /* ]] || cli="$PWD/$cli"
[[ -x "$daemon" && -x "$cli" ]] || { echo "FAIL: missing executables" >&2; exit 1; }

if [[ "${OO8_REPLACE_INSIDE:-}" != 1 ]]; then
    exec dbus-run-session -- env OO8_REPLACE_INSIDE=1 bash "$0" "$daemon" "$cli"
fi

sandbox="$(mktemp -d)"
primary_pid=""
replacement_pid=""
cleanup() {
    for pid in "$primary_pid" "$replacement_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$sandbox"
}
trap cleanup EXIT
fail() {
    echo "FAIL: $*" >&2
    for log in "$sandbox"/*.log; do
        if [[ -f "$log" ]]; then
            echo "--- $(basename "$log") ---" >&2
            cat "$log" >&2
        fi
    done
    exit 1
}

mkdir -m 700 -p "$sandbox/data" "$sandbox/credentials"
printf '%s' "oo8-disposable-replace-password" \
    > "$sandbox/credentials/oo7.keyring-encryption-password"
chmod 600 "$sandbox/credentials/oo7.keyring-encryption-password"

launch() {
    local label="$1"
    shift
    XDG_DATA_HOME="$sandbox/data" \
    CREDENTIALS_DIRECTORY="$sandbox/credentials" \
    OO7_PAM_SOCKET="$sandbox/pam.sock" \
        "$daemon" "$@" > "$sandbox/$label.log" 2>&1 &
    last_pid=$!
}

owner() {
    dbus-send --session --print-reply --reply-timeout=500 \
        --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.GetNameOwner string:org.freedesktop.secrets \
        2>/dev/null | sed -n 's/.*string "\([^"]*\)".*/\1/p' | head -1
}
wait_for_owner_change() {
    local previous="$1" target_pid="$2" result
    for _ in {1..150}; do
        kill -0 "$target_pid" 2>/dev/null || fail "new daemon exited during replacement"
        result="$(owner)"
        if [[ -n "$result" && "$result" != "$previous" ]]; then
            printf '%s' "$result"
            return
        fi
        sleep 0.02
    done
    fail "new daemon did not acquire the Secret Service name"
}

launch primary
primary_pid="$last_pid"
primary_owner="$(wait_for_owner_change "" "$primary_pid")"
[[ -S "$sandbox/pam.sock" ]] || fail "primary PAM listener missing"
attr="oo8-replace-test=$(basename "$sandbox")"
value="oo8-replace-secret"
printf '%s\n' "$value" | "$cli" store "oo8 replace test" "$attr" \
    || fail "primary couldn't store a disposable item"

launch replacement --replace
replacement_pid="$last_pid"
replacement_owner="$(wait_for_owner_change "$primary_owner" "$replacement_pid")"
[[ "$replacement_owner" != "$primary_owner" ]] || fail "owner did not change"

# Losing ownership must terminate the first service: a D-Bus connection
# can stay live after losing a *well-known name*, so connection.closed()
# alone is not enough.
retired=0
for _ in {1..150}; do
    if ! kill -0 "$primary_pid" 2>/dev/null; then
        retired=1
        break
    fi
    # Child may be a zombie pending wait after clean exit.
    state="$(ps -o stat= -p "$primary_pid" 2>/dev/null || true)"
    if [[ "$state" == Z* ]]; then
        retired=1
        break
    fi
    sleep 0.02
done
[[ "$retired" == 1 ]] || fail "old daemon stayed alive after --replace"
wait "$primary_pid" 2>/dev/null || true
primary_pid=""

# Replacement must eventually take over the PAM socket, not just the
# D-Bus service name, and must never erase or replace the secret.
switched=0
for _ in {1..150}; do
    # A freshly bound Unix socket may reuse the old inode. Check the
    # replacement daemon's own successful bind log instead of inode identity.
    if [[ -S "$sandbox/pam.sock" ]] &&
        grep -Fq "PAM listener started on $sandbox/pam.sock" "$sandbox/replacement.log"; then
        switched=1
        break
    fi
    sleep 0.02
done
[[ "$switched" == 1 ]] || fail "replacement did not acquire PAM socket"
kill -0 "$replacement_pid" || fail "replacement died after acquiring the name"
[[ "$(owner)" == "$replacement_owner" ]] || fail "replacement lost D-Bus ownership"
[[ "$("$cli" lookup --secret-only "$attr")" == "$value" ]] \
    || fail "replacement lost the persisted secret"

for log in "$sandbox"/*.log; do
    if grep -Eq "panicked at|thread .* panicked|called .*unwrap" "$log"; then
        fail "a daemon panicked during the handoff"
    fi
done
echo "PASS: --replace retired old process, replaced PAM listener, preserved encrypted item"
