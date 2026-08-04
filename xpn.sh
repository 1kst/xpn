#!/bin/bash
set -euo pipefail

INSTALL_DIR="/opt/xpn"
SERVICE_NAME="xpn-node"
REPO="1kst/xpn"
VERSION_FILE="${INSTALL_DIR}/VERSION"
LATEST_TAG_CACHE=""
LATEST_TAG_CACHE_AT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: run as root${PLAIN}"
        exit 1
    fi
}

# Refreshes LATEST_TAG_CACHE in place. This MUST be called directly, never inside
# $( ), because a command substitution runs in a subshell and every assignment
# made there is discarded — which is why the previous cache never took effect and
# the menu queried the GitHub API on every redraw, burning through the 60
# requests/hour anonymous limit. Read the result from $LATEST_TAG_CACHE.
# Pass "force" to bypass the TTL.
refresh_latest_tag() {
    local now fetched force="${1:-}"
    now="$(date +%s)"
    if [ "${force}" != "force" ] && [ -n "${LATEST_TAG_CACHE}" ] && (( now - LATEST_TAG_CACHE_AT < 300 )); then
        return 0
    fi
    fetched="$(curl -fsSL --connect-timeout 3 --max-time 6 "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1 || true)"
    if [ -n "${fetched}" ]; then
        LATEST_TAG_CACHE="${fetched}"
        LATEST_TAG_CACHE_AT="${now}"
        return 0
    fi
    return 1
}

normalize_version() {
    local v="$1"
    v="${v#v}"
    v="$(echo "$v" | sed -E 's/[^0-9.].*$//')"
    if [ -z "$v" ]; then
        echo "0.0.0"
    else
        echo "$v"
    fi
}

version_gt() {
    local a b IFS=.
    local -a va vb
    a="$(normalize_version "$1")"
    b="$(normalize_version "$2")"
    read -r -a va <<< "$a"
    read -r -a vb <<< "$b"
    for i in 0 1 2; do
        local ai="${va[$i]:-0}"
        local bi="${vb[$i]:-0}"
        if ((10#$ai > 10#$bi)); then return 0; fi
        if ((10#$ai < 10#$bi)); then return 1; fi
    done
    return 1
}

read_local_version() {
    if [ -f "${VERSION_FILE}" ]; then
        cat "${VERSION_FILE}"
    else
        echo "v0.0.0"
    fi
}

show_status() {
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo -e "Service: ${GREEN}running${PLAIN}"
    else
        echo -e "Service: ${RED}stopped${PLAIN}"
    fi
}

# Reads the cache only; it never goes to the network. Drawing the menu used to
# trigger an API request every time, so a few minutes of navigating hit the rate
# limit and left the version permanently "unavailable".
show_versions() {
    local local_ver
    local_ver="$(read_local_version)"
    echo -e "Local Version: ${YELLOW}${local_ver}${PLAIN}"
    if [ -n "${LATEST_TAG_CACHE}" ]; then
        echo -e "Latest Version: ${YELLOW}${LATEST_TAG_CACHE}${PLAIN}"
    else
        echo -e "Latest Version: ${YELLOW}not checked (use option 5)${PLAIN}"
    fi
}

# Service actions report failure and return non-zero instead of letting `set -e`
# kill the whole menu, which looked to the user like the script had crashed.
run_service_action() {
    local action="$1" ok_msg="$2"
    if systemctl "${action}" "${SERVICE_NAME}"; then
        echo -e "${GREEN}${ok_msg}${PLAIN}"
        return 0
    fi
    echo -e "${RED}failed to ${action} ${SERVICE_NAME}${PLAIN}"
    echo -e "${YELLOW}check: systemctl status ${SERVICE_NAME} -l --no-pager${PLAIN}"
    return 1
}

start_service() { run_service_action start "started"; }
stop_service() { run_service_action stop "stopped"; }
restart_service() { run_service_action restart "restarted"; }
# journalctl exits non-zero when interrupted with Ctrl+C, which is the documented
# way to leave this view, so that must not abort the script either.
show_logs() { echo -e "${BLUE}Press Ctrl+C to exit logs${PLAIN}"; journalctl -u "${SERVICE_NAME}" -f || true; }

uninstall() {
    read -r -p "Confirm uninstall? [y/n]: " res
    if [[ "$res" == "y" ]]; then
        # Every step tolerates failure. Without this, a service that was never
        # enabled (or whose unit file was already removed by hand) made
        # systemctl return non-zero, `set -e` killed the script, and none of the
        # rm lines below ever ran — leaving the binary, database and symlink
        # behind while the user believed the uninstall had succeeded.
        systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
        systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service" || true
        systemctl daemon-reload 2>/dev/null || true
        systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true
        rm -rf "${INSTALL_DIR}" || true
        rm -f /usr/local/bin/xpn || true

        local leftovers=()
        [ -e "${INSTALL_DIR}" ] && leftovers+=("${INSTALL_DIR}")
        [ -e /usr/local/bin/xpn ] && leftovers+=("/usr/local/bin/xpn")
        if [ ${#leftovers[@]} -gt 0 ]; then
            echo -e "${YELLOW}uninstalled, but these paths remain and need manual removal:${PLAIN}"
            printf '  %s\n' "${leftovers[@]}"
        else
            echo -e "${GREEN}uninstalled${PLAIN}"
        fi
        exit 0
    fi
}

# Private scratch directory for the update download, cleaned up on every exit
# path. Never reuse a predictable name under /tmp: see fetch_verified_setup.
UPDATE_TMP_DIR=""
cleanup_update_tmp() {
    if [ -n "${UPDATE_TMP_DIR}" ] && [ -d "${UPDATE_TMP_DIR}" ]; then
        rm -rf "${UPDATE_TMP_DIR}"
    fi
    UPDATE_TMP_DIR=""
}

# Downloads setup.sh for the given tag into UPDATE_TMP_DIR and verifies its
# sha256. A fixed path such as /tmp/xpn-setup.sh is unsafe here: /tmp is
# world-writable (mode 1777) and this script runs as root, so any local user
# could pre-create that name as a symlink to an arbitrary file and have root's
# `curl -o` follow it and overwrite the target.
fetch_verified_setup() {
    local tag="$1" setup_url setup_sha_url expected_sha actual_sha
    setup_url="https://github.com/${REPO}/releases/download/${tag}/setup.sh"
    setup_sha_url="${setup_url}.sha256"

    UPDATE_TMP_DIR="$(mktemp -d /tmp/xpn-setup.XXXXXX)" || {
        echo -e "${RED}failed to create temporary directory${PLAIN}"
        return 1
    }

    if ! curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 5 --max-time 120 \
            -o "${UPDATE_TMP_DIR}/setup.sh" "$setup_url"; then
        echo -e "${RED}failed to download setup.sh for tag ${tag}${PLAIN}"
        return 1
    fi

    expected_sha="$(curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 5 --max-time 30 "$setup_sha_url" \
        | awk '{print $1}' | head -n1 | tr -d '\r\n' || true)"
    actual_sha="$(sha256sum "${UPDATE_TMP_DIR}/setup.sh" | awk '{print $1}')"
    if [[ ! "$expected_sha" =~ ^[A-Fa-f0-9]{64}$ ]] || [ "$actual_sha" != "$expected_sha" ]; then
        echo -e "${RED}setup.sh sha256 verification failed for ${tag}${PLAIN}"
        return 1
    fi
    return 0
}

do_update() {
    local latest_tag local_tag
    # Called directly, not in $( ), so the cache actually persists.
    refresh_latest_tag force || true
    latest_tag="${LATEST_TAG_CACHE}"
    if [ -z "$latest_tag" ]; then
        echo -e "${RED}failed to resolve latest release tag${PLAIN}"
        return 1
    fi

    local_tag="$(read_local_version)"
    if ! version_gt "$latest_tag" "$local_tag"; then
        echo -e "${GREEN}already latest: ${local_tag}${PLAIN}"
        return 0
    fi

    PANEL=""
    TOKEN=""
    EXEC_LINE="$(grep "^ExecStart=" "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || true)"
    # The `|| true` is required on each pipeline: grep exits 1 when the flag is
    # absent, and under `set -euo pipefail` that aborted the whole script at the
    # assignment, so the "cannot extract" message below was unreachable and the
    # user just saw the menu vanish.
    PANEL="$(echo "$EXEC_LINE" | grep -oP '(?<=-panel )("[^"]+"|\S+)' | head -n1 | sed 's/^"//;s/"$//' || true)"
    TOKEN="$(echo "$EXEC_LINE" | grep -oP '(?<=-token )("[^"]+"|\S+)' | head -n1 | sed 's/^"//;s/"$//' || true)"
    if [ -z "$PANEL" ] || [ -z "$TOKEN" ]; then
        echo -e "${RED}cannot extract --panel/--token from service${PLAIN}"
        return 1
    fi

    echo -e "${BLUE}updating ${local_tag} -> ${latest_tag}${PLAIN}"

    # do_update is a function, so an EXIT trap would not fire on return; the
    # trap covers signals and the explicit cleanup calls cover the return paths.
    trap cleanup_update_tmp EXIT INT TERM
    if ! fetch_verified_setup "${latest_tag}"; then
        cleanup_update_tmp
        trap - EXIT INT TERM
        return 1
    fi

    bash "${UPDATE_TMP_DIR}/setup.sh" --panel "$PANEL" --token "$TOKEN" --version "${latest_tag}"
    local rc=$?
    cleanup_update_tmp
    trap - EXIT INT TERM
    return $rc
}

show_menu() {
    if [ ! -t 0 ] || [ ! -t 1 ]; then
        echo -e "${YELLOW}xpn menu requires an interactive TTY.${PLAIN}"
        echo "Run it directly in a terminal session: xpn"
        return 0
    fi

    while true; do
        if [ -t 1 ]; then
            clear || true
        fi
        echo -e "\n  ${BLUE}======================================${PLAIN}"
        echo -e "  ${GREEN}             XPN Node Menu           ${PLAIN}"
        echo -e "  ${BLUE}======================================${PLAIN}"
        echo -e "  ${YELLOW} 1.${PLAIN} Start service"
        echo -e "  ${YELLOW} 2.${PLAIN} Stop service"
        echo -e "  ${YELLOW} 3.${PLAIN} Restart service"
        echo -e "  ${YELLOW} 4.${PLAIN} Show logs"
        echo -e "  ${BLUE}--------------------------------------${PLAIN}"
        echo -e "  ${YELLOW} 5.${PLAIN} Update program"
        echo -e "  ${YELLOW} 6.${PLAIN} Uninstall"
        echo -e "  ${BLUE}--------------------------------------${PLAIN}"
        echo -e "  ${YELLOW} 0.${PLAIN} Exit"

        show_status
        show_versions
        echo -ne "\nEnter [0-6]: "
        if ! read -r num; then
            echo
            return 0
        fi

        # Every branch tolerates a non-zero return. These functions report their
        # own failures; without `|| true` a failed action would trip `set -e` and
        # make the whole menu vanish with no explanation.
        case "$num" in
            1) start_service || true ;;
            2) stop_service || true ;;
            3) restart_service || true ;;
            4) show_logs || true ;;
            5) do_update || true ;;
            6) uninstall || true ;;
            0) exit 0 ;;
            *) echo -e "${RED}invalid input${PLAIN}" ;;
        esac
        echo
        read -r -p "Press Enter to continue..." _
    done
}

check_root
show_menu
