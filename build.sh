#!/usr/bin/env bash
# Build the osm binary into ./bin.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p bin
go build -o bin/osm .
echo "built bin/osm"
