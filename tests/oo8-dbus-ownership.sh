#!/usr/bin/env bash
# Ensure competing oo8 daemons cannot silently replace a running Secret Service.
# Tests use an isolated D-Bus session, throwaway credentials and keyrings only.
set -euo pipefail

daemon="${1:-target/debug/oo7-daemon}"
cli="${2:-target/debug/oo7-cli}"
[[ "$daemon" == /* ]] || daemon="$PWD/$daemon"
[[ "$cli" == /* ]] || cli="$PWD/$cli"
[[ -x "$daemon" && -x "$cli" ]] || { echo "FAIL: executable missing" >&2; exit 1; }

if [[ "${OO8_OWNERSHIP_INSIDE:-}" != 1 ]]; then
    exec dbus-run-session -- env OO8_OWNERSHIP_INSIDE=1 bash "$0" "$daemon" "$cli"
fi

case_dir="$(mktemp -d)"
first_pid=""
successor_pid=""
cleanup() {
    for pid in "$first_pid" "$successor_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$case_dir"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for log in "$case_dir"/*.log; do
        if [[ -f "$log" ]]; then
            echo "--- $(basename "$log") ---" >&2
            cat "$log" >&2
        fi
    done
    exit 1
}

mkdir -m 700 -p "$case_dir/data" "$case_dir/credentials"
printf '%s' 'oo8-disposable-ownership-password' \
    > "$case_dir/credentials/oo7.keyring-encryption-password"
chmod 600 "$case_dir/credentials/oo7.keyring-encryption-password"

# Keep each candidate's PAM socket inside the disposable directory so a
# second process cannot interfere with the first daemon's listener.
launch() {
    local label="$1"
    XDG_DATA_HOME="$case_dir/data" \
    CREDENTIALS_DIRECTORY="$case_dir/credentials" \
    OO7_PAM_SOCKET="$case_dir/$label-pam.sock" \
        "$daemon" > "$case_dir/$label.log" 2>&1 &
    launched_pid=$!
}

owner() {
    dbus-send --session --print-reply --reply-timeout=500 \
        --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.GetNameOwner string:org.freedesktop.secrets \
        2>/dev/null | sed -n 's/.*string "\([^"]*\)".*/\1/p' | head -1
}

wait_ready() {
    local pid="$1" result=""
    for _ in {1..150}; do
        kill -0 "$pid" 2>/dev/null || fail "daemon exited before ready"
        if dbus-send --session --print-reply --reply-timeout=150 \
            --dest=org.freedesktop.secrets /org/freedesktop/secrets \
            org.freedesktop.DBus.Properties.Get \
            string:org.freedesktop.Secret.Service string:Collections \
            >/dev/null 2>&1; then
            result="$(owner)"
            if [[ -n "$result" ]]; then
                printf '%s' "$result"
                return
            fi
        fi
        sleep 0.02
    done
    fail "Secret Service never became ready"
}

launch "primary"
first_pid="$launched_pid"
first_owner="$(wait_ready "$first_pid")"
[[ -n "$first_owner" ]] || fail "primary owner missing"
attribute="oo8-owner-test=$(basename "$case_dir")"
secret="oo8-disposable-secret"
printf '%s\n' "$secret" | "$cli" store "oo8 ownership test" "$attribute" \
    || fail "could not write disposable item to first owner"
[[ "$("$cli" lookup --secret-only "$attribute")" == "$secret" ]] \
    || fail "could not retrieve disposable item from first owner"

# The default invocation must reject an existing owner and return a failure.
# It must NEVER take over the Secret Service implicitly.
set +e
XDG_DATA_HOME="$case_dir/data" \
CREDENTIALS_DIRECTORY="$case_dir/credentials" \
OO7_PAM_SOCKET="$case_dir/contender-pam.sock" \
    timeout 12s "$daemon" > "$case_dir/contender.log" 2>&1
contender_status=$?
set -e
[[ "$contender_status" != 0 && "$contender_status" != 124 && "$contender_status" != 137 ]] \
    || fail "contender did not reject the existing D-Bus owner"
grep -q "There is an instance already running" "$case_dir/contender.log" \
    || fail "contender exited for a reason other than D-Bus ownership"
[[ "$(owner)" == "$first_owner" ]] \
    || fail "contender displaced the active Secret Service"
kill -0 "$first_pid" 2>/dev/null || fail "primary daemon died after contested startup"
[[ "$("$cli" lookup --secret-only "$attribute")" == "$secret" ]] \
    || fail "contender damaged an existing secret"

# A controlled handoff must work without any destructive reset.
kill "$first_pid"
wait "$first_pid" 2>/dev/null || true
first_pid=""
launch "successor"
successor_pid="$launched_pid"
new_owner="$(wait_ready "$successor_pid")"
[[ -n "$new_owner" && "$new_owner" != "$first_owner" ]] \
    || fail "successor did not acquire a fresh D-Bus owner"
[[ "$("$cli" lookup --secret-only "$attribute")" == "$secret" ]] \
    || fail "persisted item unavailable after handoff"
for log in "$case_dir"/*.log; do
    if grep -Eq 'panicked at|thread .* panicked|called .*unwrap' "$log"; then
        fail "a daemon logged a panic during ownership transition"
    fi
done
echo "PASS: contender rejected without replacement, original owner survived, clean handoff preserved secret"
