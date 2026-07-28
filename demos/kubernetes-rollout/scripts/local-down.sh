#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
docker compose -f "$root/compose.local.yaml" down

echo "Stopped the local demo containers."
echo "The Kind cluster and replay state volume were preserved."
