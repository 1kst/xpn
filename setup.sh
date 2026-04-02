#!/bin/bash
set -euo pipefail

REPO="1kst/xpn"
INSTALL_DIR="/opt/xpn"
SERVICE_NAME="xpn-node"
VERSION_FILE="${INSTALL_DIR}/VERSION"

systemd_escape_arg() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/%/%%/g'
}

resolve_latest_tag() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command not found: ${cmd}"
        exit 1
    fi
}

download_file() {
    local url="$1"
    local out="$2"
    curl -fsSL --retry 3 --retry-delay 1 -o "$out" "$url"
}

verify_sha256() {
    local file_path="$1"
    local sha_url="$2"
    local expected actual

    expected="$(curl -fsSL --retry 3 --retry-delay 1 "$sha_url" | awk '{print $1}' | head -n1 | tr -d '\r\n')"
    if [[ ! "$expected" =~ ^[A-Fa-f0-9]{64}$ ]]; then
        echo "Error: invalid sha256 content from ${sha_url}"
        return 1
    fi

    actual="$(sha256sum "$file_path" | awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "Error: sha256 mismatch for $(basename "$file_path")"
        echo "Expected: ${expected}"
        echo "Actual:   ${actual}"
        return 1
    fi
}

ARG_PANEL=""
ARG_TOKEN=""
ARG_VERSION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --panel) ARG_PANEL="$2"; shift 2 ;;
        --token) ARG_TOKEN="$2"; shift 2 ;;
        --version) ARG_VERSION="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [ -z "$ARG_PANEL" ] || [ -z "$ARG_TOKEN" ]; then
    echo "Error: requires --panel and --token"
    exit 1
fi

require_cmd curl
require_cmd tar
require_cmd sha256sum
require_cmd systemctl

if [ -n "$ARG_VERSION" ]; then
    VERSION_TAG="$ARG_VERSION"
else
    VERSION_TAG="$(resolve_latest_tag)"
fi

if [ -z "$VERSION_TAG" ]; then
    echo "Error: failed to resolve latest release tag"
    exit 1
fi

BASE_RELEASE_URL="https://github.com/${REPO}/releases/download/${VERSION_TAG}"
BINARY_URL="${BASE_RELEASE_URL}/xpn-node-linux-amd64.tar.gz"
BINARY_SHA_URL="${BINARY_URL}.sha256"
SCRIPT_URL="${BASE_RELEASE_URL}/xpn.sh"
SCRIPT_SHA_URL="${SCRIPT_URL}.sha256"

mkdir -p "${INSTALL_DIR}"
tmp_dir="$(mktemp -d /tmp/xpn-setup.XXXXXX)"
trap 'rm -rf "${tmp_dir}"' EXIT

download_file "${BINARY_URL}" "${tmp_dir}/xpn-node.tar.gz"
verify_sha256 "${tmp_dir}/xpn-node.tar.gz" "${BINARY_SHA_URL}"

tar -zxf "${tmp_dir}/xpn-node.tar.gz" -C "${tmp_dir}"
if [ ! -f "${tmp_dir}/xpn-node" ]; then
    echo "Error: package does not contain xpn-node"
    exit 1
fi
chmod +x "${tmp_dir}/xpn-node"

download_file "${SCRIPT_URL}" "${tmp_dir}/xpn.sh"
verify_sha256 "${tmp_dir}/xpn.sh" "${SCRIPT_SHA_URL}"
chmod +x "${tmp_dir}/xpn.sh"

cp -f "${tmp_dir}/xpn-node" "${INSTALL_DIR}/xpn-node.new"
chmod +x "${INSTALL_DIR}/xpn-node.new"
mv -f "${INSTALL_DIR}/xpn-node.new" "${INSTALL_DIR}/xpn-node"

cp -f "${tmp_dir}/xpn.sh" "${INSTALL_DIR}/xpn.sh.new"
chmod +x "${INSTALL_DIR}/xpn.sh.new"
mv -f "${INSTALL_DIR}/xpn.sh.new" "${INSTALL_DIR}/xpn.sh"
# Important: old installs may have /usr/local/bin/xpn as a symlink to /opt/xpn/xpn.sh.
# If we redirect into a symlink path, shell writes to target and corrupts xpn.sh.
if [ -L /usr/local/bin/xpn ]; then
    rm -f /usr/local/bin/xpn
fi
cat > /usr/local/bin/xpn <<EOF
#!/bin/bash
exec ${INSTALL_DIR}/xpn.sh "\$@"
EOF
chmod +x /usr/local/bin/xpn

echo "${VERSION_TAG}" > "${VERSION_FILE}"

PANEL_ESC="$(systemd_escape_arg "$ARG_PANEL")"
TOKEN_ESC="$(systemd_escape_arg "$ARG_TOKEN")"

cat <<EOF > /etc/systemd/system/${SERVICE_NAME}.service
[Unit]
Description=XPN Node Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/xpn-node -mode node -panel "${PANEL_ESC}" -token "${TOKEN_ESC}"
Restart=always
RestartSec=5
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

echo "Install complete. Service=${SERVICE_NAME}, Version=${VERSION_TAG}"
