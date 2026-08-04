#!/bin/bash
set -euo pipefail

APP_NAME="xpn-node"
DIST_DIR="dist"

# Target architecture comes from $1 or $GOARCH, defaulting to amd64. The produced
# archive name must stay in lockstep with the URL setup.sh builds from its
# `uname -m` detection (xpn-node-linux-<arch>.tar.gz).
TARGET_ARCH="${1:-${GOARCH:-amd64}}"
case "${TARGET_ARCH}" in
    amd64|arm64) ;;
    *)
        echo "Error: unsupported target arch: ${TARGET_ARCH} (supported: amd64, arm64)"
        exit 1
        ;;
esac

TAR_NAME="xpn-node-linux-${TARGET_ARCH}.tar.gz"

echo "Building ${APP_NAME} release package for linux/${TARGET_ARCH}..."
CGO_ENABLED=0 GOOS=linux GOARCH="${TARGET_ARCH}" go build -ldflags="-s -w" -o ${APP_NAME} ./cmd/node

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

cp "${APP_NAME}" "${DIST_DIR}/${APP_NAME}"
cp setup.sh "${DIST_DIR}/setup.sh"
cp xpn.sh "${DIST_DIR}/xpn.sh"

tar -C "${DIST_DIR}" -czf "${TAR_NAME}" "${APP_NAME}"
echo "Created ${TAR_NAME}"
