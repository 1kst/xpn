#!/bin/bash
set -euo pipefail

echo "Building xpn node binary..."
go mod tidy

GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o xpn-node-linux-amd64 ./cmd/node
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o xpn-node-windows-amd64.exe ./cmd/node

echo
echo "Build complete:"
ls -lh xpn-node-*-amd64*
