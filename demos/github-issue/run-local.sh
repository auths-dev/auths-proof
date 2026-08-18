#!/usr/bin/env bash
set -euo pipefail

demo_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$demo_directory/../.." && pwd)"
mode="${1:-preview}"

case "$mode" in
  preview)
    preview_port="${AUTHS_GITHUB_PREVIEW_PORT:-4173}"
    echo "Auths GitHub guided preview: http://127.0.0.1:${preview_port}"
    echo "This mode explains boundaries but does not execute Auths or GitHub actions."
    cd "$demo_directory/web"
    exec python3 -m http.server "$preview_port" --bind 127.0.0.1
    ;;
  live)
    live_port="${PORT:-8080}"
    echo "Auths GitHub live demo: http://127.0.0.1:${live_port}"
    echo "Live mode requires the documented AUTHS_GITHUB_* environment."
    cd "$repository_root"
    exec cargo run --locked -p auths-github-demo
    ;;
  *)
    echo "usage: $0 [preview|live]" >&2
    exit 2
    ;;
esac
