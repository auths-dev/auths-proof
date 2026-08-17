#!/usr/bin/env bash
# Build the Auths-Proof formal semantics paper and place the final PDF at the
# repository's conventional output location.
set -euo pipefail
cd "$(dirname "$0")"

SRC="${1:-auths-proof-formal-semantics.md}"
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 1; }

NAME="${SRC%.md}"
LOCAL_OUT="${NAME}.pdf"
FINAL_DIR="../../../output/pdf"
FINAL_OUT="${FINAL_DIR}/${NAME}.pdf"

command -v pandoc >/dev/null || { echo "pandoc is required" >&2; exit 1; }
command -v xelatex >/dev/null || { echo "xelatex is required" >&2; exit 1; }

pandoc "$SRC" \
  --from markdown+raw_tex \
  --output "$LOCAL_OUT" \
  --pdf-engine=xelatex \
  --include-in-header=preamble.tex \
  --citeproc \
  --bibliography=references.bib \
  -V geometry:margin=0.82in \
  -V fontsize=10pt \
  -V colorlinks=true \
  --highlight-style=tango

mkdir -p "$FINAL_DIR"
cp "$LOCAL_OUT" "$FINAL_OUT"
echo "wrote $FINAL_OUT"
