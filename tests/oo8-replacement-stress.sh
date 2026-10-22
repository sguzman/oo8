#!/usr/bin/env bash
# Repeated --replace under concurrent Secret Service client traffic.
# Uses an isolated D-Bus session, disposable credentials, and temporary data.
set -euo pipefail

daemon="${1:-target/debug/oo8-daemon}"
cli="${2:-target/debug/oo8-cli}"
[[ "$daemon" == /* ]] || daemon="$PWD/$daemon"
[[ "$cli" == /* ]] || cli="$PWD/$cli"
[[ -x "$daemon" && -x "$cli" ]] || { echo "FAIL: executables not found" >&2; exit 1; }

if [[ "${OO8_STRESS_INSIDE:-}" != 1 ]]; then
    exec dbus-run-session -- env OO8_STRESS_INSIDE=1 bash "$0" "$daemon" "$cli"
fi

iterations="${OO8_REPLACE_ITERATIONS:-6}"
[[ "$iterations" =~ ^[1-9][0-9]*$ && "$iterations" -le 20 ]] \
    || { echo "FAIL: OO8_REPLACE_ITERATIONS must be 1..20" >&2; exit 2; }

sandbox="$(mktemp -d)"
active_pid=""
candidate_pid=""
reader_pids=()
cleanup() {
    touch "$sandbox/stop-readers" 2>/dev/null || true
    for pid in "${reader_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "$candidate_pid" "$active_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    for pid in "${reader_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$sandbox"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for report in "$sandbox"/reader-*.failure; do
        if [[ -s "$report" ]]; then
            echo "--- $(basename "$report") ---" >&2
            cat "$report" >&2
        fi
    done
    for log in "$sandbox"/*.log; do
        if [[ -f "$log" ]]; then
            echo "--- $(basename "$log") ---" >&2
            tail -n 20 "$log" >&2
        fi
    done
    exit 1
}

mkdir -m 700 -p "$sandbox/data" "$sandbox/credentials"
printf '%s' 'oo8-disposable-stress-password' \
    > "$sandbox/credentials/oo7.keyring-encryption-password"
chmod 600 "$sandbox/credentials/oo7.keyring-encryption-password"
socket="$sandbox/pam.sock"
attribute="oo8-stress=$(basename "$sandbox")"
secret="oo8-stress-seed-secret"

launch() {
    local label="$1"
    shift
    XDG_DATA_HOME="$sandbox/data" \
    CREDENTIALS_DIRECTORY="$sandbox/credentials" \
    OO7_PAM_SOCKET="$socket" \
        "$daemon" "$@" > "$sandbox/$label.log" 2>&1 &
    launched_pid=$!
}
owner() {
    dbus-send --session --print-reply --reply-timeout=700 \
        --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.GetNameOwner string:org.freedesktop.secrets \
        2>/dev/null | sed -n 's/.*string "\([^"]*\)".*/\1/p' | head -1 || true
}
wait_owner() {
    local former="$1" pid="$2" current
    for _ in {1..200}; do
        kill -0 "$pid" 2>/dev/null || fail "candidate daemon died during replacement"
        current="$(owner)"
        if [[ -n "$current" && "$current" != "$former" ]]; then
            new_owner="$current"
            return
        fi
        sleep 0.02
    done
    fail "replacement did not acquire new D-Bus owner"
}
wait_retired() {
    local pid="$1" state
    for _ in {1..200}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return
        fi
        state="$(ps -o stat= -p "$pid" 2>/dev/null || true)"
        if [[ "$state" == Z* ]]; then
            wait "$pid" 2>/dev/null || true
            return
        fi
        sleep 0.02
    done
    fail "displaced daemon did not terminate"
}
wait_pam() {
    local label="$1" pid="$2"
    for _ in {1..200}; do
        kill -0 "$pid" 2>/dev/null || fail "replacement died before PAM was ready"
        if [[ -S "$socket" ]] &&
            grep -Fq "PAM listener started on $socket" "$sandbox/$label.log"; then
            return
        fi
        sleep 0.02
    done
    fail "replacement never recovered PAM listener"
}
get_secret() {
    timeout 4s "$cli" lookup --secret-only "$attribute"
}

launch primary
active_pid="$launched_pid"
wait_owner "" "$active_pid"
active_owner="$new_owner"
wait_pam primary "$active_pid"
printf '%s\n' "$secret" | "$cli" store "oo8 concurrent stress" "$attribute" \
    || fail "could not write seed secret"
[[ "$(get_secret)" == "$secret" ]] || fail "seed secret is not readable"
# Machine-readable stdout must remain clean even with diagnostic logging.
verbose_result="$(timeout 4s "$cli" --verbose lookup --secret-only "$attribute" \
    2>"$sandbox/cli-verbose.log")" || fail "verbose secret lookup failed"
[[ "$verbose_result" == "$secret" ]] \
    || fail "verbose CLI polluted machine-readable stdout"

# Readers race with each successive handoff. Transient failures during the
# name transfer are permissible; a successful response with a WRONG secret is
# never permissible. Readers record their outcomes for final assertions.
reader() {
    local number="$1" ok=0 transient=0 result
    while [[ ! -e "$sandbox/stop-readers" ]]; do
        local owner_before owner_after
        owner_before="$(owner)"
        if result="$(get_secret 2>/dev/null)"; then
            if [[ "$result" != "$secret" ]]; then
                owner_after="$(owner)"
                printf 'unexpected successful lookup: result=%q owner_before=%q owner_after=%q\n' \
                    "$result" "$owner_before" "$owner_after" \
                    > "$sandbox/reader-$number.failure"
                return 1
            fi
            ok=$((ok+1))
        else
            transient=$((transient+1))
        fi
        sleep 0.02
    done
    printf '%s %s\n' "$ok" "$transient" > "$sandbox/reader-$number.stats"
}
for n in 1 2; do
    reader "$n" > "$sandbox/reader-$n.log" 2>&1 &
    reader_pids+=("$!")
done

for ((cycle=1; cycle<=iterations; cycle++)); do
    label="replacement-$cycle"
    launch "$label" --replace
    candidate_pid="$launched_pid"
    wait_owner "$active_owner" "$candidate_pid"
    successor_owner="$new_owner"
    wait_retired "$active_pid"
    active_pid=""
    wait_pam "$label" "$candidate_pid"
    [[ "$(owner)" == "$successor_owner" ]] \
        || fail "replacement $cycle lost Secret Service name"
    [[ "$(get_secret)" == "$secret" ]] \
        || fail "replacement $cycle lost seed secret"

    # A committed write with a fresh attribute must remain readable through
    # all later replacements, even while independent clients are reading.
    cycle_attribute="oo8-cycle-$cycle=$(basename "$sandbox")"
    cycle_secret="oo8-disposable-cycle-$cycle"
    printf '%s\n' "$cycle_secret" |
        "$cli" store "oo8 cycle $cycle" "$cycle_attribute" \
        || fail "could not store item in cycle $cycle"
    [[ "$("$cli" lookup --secret-only "$cycle_attribute")" == "$cycle_secret" ]] \
        || fail "could not read item stored during cycle $cycle"

    active_pid="$candidate_pid"
    candidate_pid=""
    active_owner="$successor_owner"
    echo "PASS replacement $cycle/$iterations"
done

# Check all committed values against the final daemon instance.
for ((cycle=1; cycle<=iterations; cycle++)); do
    cycle_attribute="oo8-cycle-$cycle=$(basename "$sandbox")"
    [[ "$("$cli" lookup --secret-only "$cycle_attribute")" == "oo8-disposable-cycle-$cycle" ]] \
        || fail "committed item from cycle $cycle lost after later replacements"
done

touch "$sandbox/stop-readers"
for pid in "${reader_pids[@]}"; do
    wait "$pid" || fail "concurrent reader failed"
done
reader_pids=()
for n in 1 2; do
    [[ ! -f "$sandbox/reader-$n.failure" ]] \
        || fail "reader $n observed a corrupted secret"
    [[ -s "$sandbox/reader-$n.stats" ]] \
        || fail "reader $n did not report results"
    read -r ok transient < "$sandbox/reader-$n.stats"
    (( ok > 0 )) || fail "reader $n never received a successful response"
    echo "Reader $n: $ok successful lookups, $transient transient failures"
done
for log in "$sandbox"/primary.log "$sandbox"/replacement-*.log; do
    if grep -Eq 'panicked at|thread .* panicked|called .*unwrap' "$log"; then
        fail "daemon panicked while serving concurrent clients"
    fi
done

echo "PASS: $iterations explicit replacements; 2 concurrent readers; every committed secret recovered"
