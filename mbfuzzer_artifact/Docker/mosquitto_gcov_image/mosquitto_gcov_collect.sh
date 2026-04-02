#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-/opt/mosquitto-gcov}"
OUT_DIR="${2:-/coverage}"

mkdir -p "$OUT_DIR"
cd "$SRC_DIR"

summary_file="$OUT_DIR/gcovr-summary.txt"
summary_json="$OUT_DIR/gcovr-summary.json"
html_file="$OUT_DIR/index.html"
xml_file="$OUT_DIR/coverage.xml"

gcovr -r . --branches --txt-summary | tee "$summary_file"
gcovr -r . --branches --json-summary-pretty --output "$summary_json"
gcovr -r . --branches --html-details --output "$html_file"
gcovr -r . --branches --xml-pretty --output "$xml_file"

echo "Saved branch coverage artifacts to $OUT_DIR"
