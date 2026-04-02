#!/bin/bash
set -euo pipefail

INSTALL_DIR="/opt/xpn"
SERVICE_NAME="xpn-node"
REPO="1kst/xpn"
VERSION_FILE="${INSTALL_DIR}/VERSION"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

check_root() {
    [[ $EUID -ne 0 ]] && echo -e "${RED}Error: run as root${PLAIN}" && exit 1
}

resolve_latest_tag() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1
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

show_versions() {
    local local_ver latest_ver
    local_ver="$(read_local_version)"
    latest_ver="$(resolve_latest_tag || true)"
    echo -e "Local Version: ${YELLOW}${local_ver}${PLAIN}"
    if [ -n "$latest_ver" ]; then
        echo -e "Latest Version: ${YELLOW}${latest_ver}${PLAIN}"
    else
        echo -e "Latest Version: ${RED}unavailable${PLAIN}"
    fi
}

start_service() { systemctl start "${SERVICE_NAME}"; echo -e "${GREEN}started${PLAIN}"; }
stop_service() { systemctl stop "${SERVICE_NAME}"; echo -e "${YELLOW}stopped${PLAIN}"; }
restart_service() { systemctl restart "${SERVICE_NAME}"; echo -e "${GREEN}restarted${PLAIN}"; }
show_logs() { echo -e "${BLUE}Press Ctrl+C to exit logs${PLAIN}"; journalctl -u "${SERVICE_NAME}" -f; }

uninstall() {
    read -r -p "Confirm uninstall? [y/n]: " res
    if [[ "$res" == "y" ]]; then
        systemctl stop "${SERVICE_NAME}"
        systemctl disable "${SERVICE_NAME}"
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        rm -rf "${INSTALL_DIR}"
        rm -f /usr/local/bin/xpn
        echo -e "${GREEN}uninstalled${PLAIN}"
        exit 0
    fi
}

do_update() {
    local latest_tag local_tag
    latest_tag="$(resolve_latest_tag)"
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
    PANEL="$(echo "$EXEC_LINE" | grep -oP '(?<=-panel )("[^"]+"|\S+)' | head -n1 | sed 's/^"//;s/"$//')"
    TOKEN="$(echo "$EXEC_LINE" | grep -oP '(?<=-token )("[^"]+"|\S+)' | head -n1 | sed 's/^"//;s/"$//')"
    if [ -z "$PANEL" ] || [ -z "$TOKEN" ]; then
        echo -e "${RED}cannot extract --panel/--token from service${PLAIN}"
        return 1
    fi

    echo -e "${BLUE}updating ${local_tag} -> ${latest_tag}${PLAIN}"
    setup_url="https://github.com/${REPO}/releases/download/${latest_tag}/setup.sh"
    setup_sha_url="${setup_url}.sha256"
    if ! curl -fsSL --retry 3 --retry-delay 1 -o /tmp/xpn-setup.sh "$setup_url"; then
        echo -e "${RED}failed to download setup.sh for tag ${latest_tag}${PLAIN}"
        return 1
    fi
    expected_sha="$(curl -fsSL --retry 3 --retry-delay 1 "$setup_sha_url" | awk '{print $1}' | head -n1 | tr -d '\r\n')"
    actual_sha="$(sha256sum /tmp/xpn-setup.sh | awk '{print $1}')"
    if [[ ! "$expected_sha" =~ ^[A-Fa-f0-9]{64}$ ]] || [ "$actual_sha" != "$expected_sha" ]; then
        echo -e "${RED}setup.sh sha256 verification failed for ${latest_tag}${PLAIN}"
        return 1
    fi

    bash /tmp/xpn-setup.sh --panel "$PANEL" --token "$TOKEN" --version "${latest_tag}"
}

show_menu() {
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
        read -r num

        case "$num" in
            1) start_service ;;
            2) stop_service ;;
            3) restart_service ;;
            4) show_logs ;;
            5) do_update ;;
            6) uninstall ;;
            0) exit 0 ;;
            *) echo -e "${RED}invalid input${PLAIN}" ;;
        esac
        echo
        read -r -p "Press Enter to continue..." _
    done
}

check_root
show_menu
