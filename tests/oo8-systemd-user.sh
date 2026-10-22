#!/usr/bin/env bash
# GitHub-hosted Linux CI ONLY: exercise LoadCredential + Type=dbus in a
# disposable systemd user manager. Never access the runner's own keyrings.
set -euo pipefail
daemon="${1:?absolute daemon executable path required}"
cli="${2:?absolute CLI executable path required}"
template="$(cd -- "$(dirname -- "$0")/.." && pwd)/packaging/soar/oo7-daemon.service"
[[ "$daemon" == /* && "$cli" == /* ]] || { echo "Use absolute binary paths" >&2; exit 2; }
[[ -f "$template" ]] || { echo "Packaged service unit missing" >&2; exit 2; }
[[ "${GITHUB_ACTIONS:-}" == true && -n "${GITHUB_RUN_ID:-}" ]] || {
    echo "FAIL: real systemd account test is GitHub CI only" >&2
    exit 2
}

# Unlike the private D-Bus test, this deliberately needs a real host systemd
# PID1 to create an actual user manager and credential delivery directory.
[[ "$(cat /proc/1/comm)" == systemd ]] || {
    echo "FAIL: test requires real systemd PID1" >&2
    exit 1
}
[[ "$(id -u)" == 0 ]] || { echo "FAIL: run as root in disposable CI" >&2; exit 1; }
user="oo8-ci-${GITHUB_RUN_ID:-test}"
# Unix names must be short and stable; GitHub run IDs are numeric.
uid=""
data=""
cleanup() {
    if [[ -n "$uid" ]]; then
        runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
            systemctl --user stop oo8-regression.service oo8-packaged.service >/dev/null 2>&1 || true
    fi
    loginctl disable-linger "$user" >/dev/null 2>&1 || true
    if [[ -n "$uid" ]]; then
        systemctl stop "user@$uid.service" >/dev/null 2>&1 || true
    fi
    userdel -r "$user" >/dev/null 2>&1 || true
}
trap cleanup EXIT
useradd --create-home --shell /bin/bash "$user"
uid="$(id -u "$user")"
data="/home/$user/oo8-test"
install -d -m 0700 -o "$user" -g "$user" "$data" "$data/data" "$data/credentials" "$data/bin"
# GitHub runner's workspace is not traversable by another account. Copy the
# exact just-built executables into the throwaway account, preserving versions.
install -m 0755 -o "$user" -g "$user" "$daemon" "$data/bin/oo7-daemon"
install -m 0755 -o "$user" -g "$user" "$cli" "$data/bin/oo7-cli"
daemon="$data/bin/oo7-daemon"
cli="$data/bin/oo7-cli"
credential="$data/credentials/oo7.keyring-encryption-password"
secret="oo8-ci-systemd-disposable-secret"
attr="oo8-systemd-test=${GITHUB_RUN_ID:-local}"
printf '%s' "oo8-ci-systemd-password" > "$credential"
chown "$user:$user" "$credential"
chmod 600 "$credential"

loginctl enable-linger "$user"
systemctl start "user@$uid.service"
for attempt in {1..80}; do
    [[ -S "/run/user/$uid/bus" ]] && break
    sleep 0.1
done
[[ -S "/run/user/$uid/bus" ]] || { echo "FAIL: user bus did not start" >&2; exit 1; }

as_user() {
    runuser -u "$user" -- env \
        XDG_RUNTIME_DIR="/run/user/$uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
        HOME="/home/$user" \
        "$@"
}
dump_failure() {
    systemctl status "user@$uid.service" --no-pager || true
    journalctl -b --no-pager _UID="$uid" -n 90 || true
}
fail() { echo "FAIL: $*" >&2; dump_failure; exit 1; }

# GitHub's Ubuntu runner can put the *runner* XDG_RUNTIME_DIR in
# /etc/environment, even for another PAM user session. Override the manager
# environment before launching the disposable service; otherwise zbus tries
# /run/user/1001/bus instead of this user's own bus.
as_user systemctl --user set-environment \
    "XDG_RUNTIME_DIR=/run/user/$uid" \
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" \
    "HOME=/home/$user"

# Run the real binary through the disposable user's systemd manager.
# LoadCredential creates CREDENTIALS_DIRECTORY automatically and passes the
# named credential securely into the service's per-unit credential directory.
as_user systemd-run --user --unit=oo8-regression --collect \
    --property=Type=dbus \
    --property=BusName=org.freedesktop.secrets \
    --property=Restart=no \
    --property="LoadCredential=oo7.keyring-encryption-password:$credential" \
    --property="Environment=XDG_DATA_HOME=$data/data" \
    --property="Environment=OO7_PAM_SOCKET=$data/pam.sock" \
    --property="Environment=XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" \
    "$daemon" || fail "systemd-run could not launch daemon"

wait_ready() {
    local ready=0
    for attempt in {1..100}; do
        if as_user dbus-send --session --print-reply --reply-timeout=250 \
            --dest=org.freedesktop.secrets /org/freedesktop/secrets \
            org.freedesktop.DBus.Properties.Get \
            string:org.freedesktop.Secret.Service string:Collections \
            >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.1
    done
    [[ "$ready" == 1 ]] || fail "Secret Service did not come up under systemd"
}
state() {
    local path
    path="$(as_user dbus-send --session --print-reply --reply-timeout=1000 \
        --dest=org.freedesktop.secrets /org/freedesktop/secrets \
        org.freedesktop.Secret.Service.ReadAlias string:default |
        sed -n 's/.*object path "\(\/org\/freedesktop\/secrets\/collection\/[^"]*\)".*/\1/p' |
        head -1)"
    [[ -n "$path" ]] || fail "default collection missing"
    as_user dbus-send --session --print-reply --reply-timeout=1000 \
        --dest=org.freedesktop.secrets "$path" \
        org.freedesktop.DBus.Properties.Get \
        string:org.freedesktop.Secret.Collection string:Locked
}
wait_ready
[[ "$(state)" == *"boolean false"* ]] || fail "LoadCredential did not unlock keyring"
printf '%s\n' "$secret" | as_user "$cli" store "oo8 systemd disposable" "$attr" \
    || fail "could not store a secret"
[[ "$(as_user "$cli" lookup --secret-only "$attr")" == "$secret" ]] \
    || fail "could not read the stored secret"

keyring="$data/data/keyrings/v1/login.keyring"
[[ -s "$keyring" ]] || fail "keyring was not persisted"
before="$(sha256sum "$keyring" | cut -d' ' -f1)"

# Changing the credential source exercises systemd's own credential reload
# (it is not read directly by the daemon after systemd has launched it).
printf '%s' 'oo8-ci-wrong-password' > "$credential"
as_user systemctl --user restart oo8-regression.service || fail "restart with wrong secret failed"
wait_ready
[[ "$(state)" == *"boolean true"* ]] || fail "wrong secret did not leave keyring locked"
[[ "$(sha256sum "$keyring" | cut -d' ' -f1)" == "$before" ]] \
    || fail "wrong secret altered the encrypted keyring"

printf '%s' 'oo8-ci-systemd-password' > "$credential"
as_user systemctl --user restart oo8-regression.service || fail "recovery restart failed"
wait_ready
[[ "$(state)" == *"boolean false"* ]] || fail "correct secret did not unlock keyring"
[[ "$(as_user "$cli" lookup --secret-only "$attr")" == "$secret" ]] \
    || fail "persisted secret was lost after restarting through systemd"
# The transient systemd-run check is not sufficient for desktop rollout.
# Also exercise the unmodified production hardening and ExecStart from the
# distributed user service template, in this disposable CI account only.
as_user systemctl --user stop oo8-regression.service || fail "could not stop transient service"
home="/home/$user"
unit_dir="$home/.config/systemd/user"
install -d -m 0755 -o "$user" -g "$user" "$unit_dir" "$home/.local/share/soar/bin"
install -m 0755 -o "$user" -g "$user" "$daemon" "$home/.local/share/soar/bin/oo7-daemon"
unit="$unit_dir/oo8-packaged.service"
install -m 0644 -o "$user" -g "$user" "$template" "$unit"
# Only the source of the disposable credential and data directory differ
# from the published template; all service sandbox options are preserved.
cat >> "$unit" <<EOF

[Service]
LoadCredential=oo7.keyring-encryption-password:$credential
Environment=XDG_DATA_HOME=$data/data
Environment=OO7_PAM_SOCKET=$data/packaged-pam.sock
Environment=XDG_RUNTIME_DIR=/run/user/$uid
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus
EOF
as_user systemctl --user daemon-reload || fail "could not load shipped service template"
as_user systemctl --user start oo8-packaged.service || fail "shipped service template did not start"
wait_ready
[[ "$(state)" == *"boolean false"* ]] || fail "shipped service did not import keyring credential"
[[ "$(as_user "$cli" lookup --secret-only "$attr")" == "$secret" ]] \
    || fail "shipped service failed to read the existing encrypted item"

printf '%s' 'oo8-ci-wrong-password' > "$credential"
as_user systemctl --user restart oo8-packaged.service || fail "shipped unit restart with wrong password failed"
wait_ready
[[ "$(state)" == *"boolean true"* ]] || fail "shipped unit did not lock on wrong credential"
[[ "$(sha256sum "$keyring" | cut -d' ' -f1)" == "$before" ]] \
    || fail "shipped unit modified encrypted keyring on wrong credential"

printf '%s' 'oo8-ci-systemd-password' > "$credential"
as_user systemctl --user restart oo8-packaged.service || fail "shipped unit recovery restart failed"
wait_ready
[[ "$(state)" == *"boolean false"* ]] || fail "shipped unit failed to unlock on correct credential"
[[ "$(as_user "$cli" lookup --secret-only "$attr")" == "$secret" ]] \
    || fail "shipped unit failed to recover the persisted secret"

echo "PASS: isolated systemd manager, shipped unit, credential import, sandbox, persistent data and recovery"
