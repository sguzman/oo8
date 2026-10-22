#!/usr/bin/env bash
# Regression: Secret Service must not advertise itself before initialization
# finishes. Every iteration uses its own disposable keyring and fake systemd
# credential directory, isolated on a private D-Bus session.
set -euo pipefail

daemon="${2:-target/debug/oo8-daemon}"
if [[ "$daemon" != /* ]]; then
    daemon="$PWD/$daemon"
fi

if [[ "${1:-}" != "--inside" ]]; then
    exec dbus-run-session -- bash "$0" --inside "$daemon"
fi

iterations="${OO8_STARTUP_ITERATIONS:-12}"
case_dir=""
daemon_pid=""

cleanup() {
    if [[ -n "$daemon_pid" ]]; then
        kill "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
        daemon_pid=""
    fi
    if [[ -n "$case_dir" ]]; then
        rm -rf "$case_dir"
        case_dir=""
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    if [[ -n "$case_dir" && -f "$case_dir/daemon.log" ]]; then
        cat "$case_dir/daemon.log" >&2
    fi
    exit 1
}

for ((run = 1; run <= iterations; run++)); do
    case_dir="$(mktemp -d)"
    mkdir -p "$case_dir/data" "$case_dir/credentials"
    printf 'oo8-throwaway-ci-keyring-password-%s' "$run" > "$case_dir/credentials/oo7.keyring-encryption-password"

    XDG_DATA_HOME="$case_dir/data" \
    CREDENTIALS_DIRECTORY="$case_dir/credentials" \
    OO7_PAM_SOCKET="$case_dir/pam.sock" \
        "$daemon" > "$case_dir/daemon.log" 2>&1 &
    daemon_pid=$!

    ready=0
    # Probe immediately while the service is coming up. The old ordering
    # exposed its bus name before its internal connection was initialized.
    for attempt in {1..150}; do
        if ! kill -0 "$daemon_pid" 2>/dev/null; then
            fail "daemon exited during startup, iteration $run"
        fi

        if dbus-send --session --print-reply --reply-timeout=150 \
            --dest=org.freedesktop.secrets \
            /org/freedesktop/secrets \
            org.freedesktop.DBus.Properties.Get \
            string:org.freedesktop.Secret.Service string:Collections \
            > "$case_dir/collections.txt" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.02
    done

    [[ "$ready" == 1 ]] || fail "Secret Service did not become ready, iteration $run"

    alias_reply="$(dbus-send --session --print-reply --reply-timeout=500 \
        --dest=org.freedesktop.secrets /org/freedesktop/secrets \
        org.freedesktop.Secret.Service.ReadAlias string:default)" \
        || fail "ReadAlias failed, iteration $run"

    collection="$(printf '%s\n' "$alias_reply" | sed -n 's/.*object path "\(\/org\/freedesktop\/secrets\/collection\/[^"]*\)".*/\1/p' | head -n 1)"
    [[ -n "$collection" ]] || fail "default collection missing, iteration $run"

    locked_reply="$(dbus-send --session --print-reply --reply-timeout=500 \
        --dest=org.freedesktop.secrets "$collection" \
        org.freedesktop.DBus.Properties.Get \
        string:org.freedesktop.Secret.Collection string:Locked)" \
        || fail "default collection lock-state query failed, iteration $run"

    # The 0.6.0 historical baseline creates a locked collection even when
    # supplied a credential. Its race probe needs to check bus readiness and
    # panic logs independently of that separate lock-state behavior.
    if [[ "${OO8_EXPECT_UNLOCKED:-1}" == 1 ]]; then
        [[ "$locked_reply" == *"boolean false"* ]] \
            || fail "disposable systemd credential did not unlock default collection, iteration $run"
    fi

    if grep -Eq "panicked at|thread .* panicked|called .*unwrap" "$case_dir/daemon.log"; then
        fail "daemon logged a panic, iteration $run"
    fi

    cleanup
    echo "PASS startup $run/$iterations"
done

echo "PASS: no early D-Bus exposure, missing unlocks, or worker panics across $iterations starts"
