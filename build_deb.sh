#!/bin/bash
set -euo pipefail

APP_NAME="xpn-node"
DIST_DIR="dist"
TAR_NAME="xpn-node-linux-amd64.tar.gz"

echo "Building ${APP_NAME} release package..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ${APP_NAME} ./cmd/node

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

cp "${APP_NAME}" "${DIST_DIR}/${APP_NAME}"
cp setup.sh "${DIST_DIR}/setup.sh"
cp xpn.sh "${DIST_DIR}/xpn.sh"

tar -C "${DIST_DIR}" -czf "${TAR_NAME}" "${APP_NAME}"
echo "Created ${TAR_NAME}"
