#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# mosquitto_gcov_collect.sh
#
# Collect gcov branch + line coverage from a gcov-instrumented mosquitto
# build tree.  Called inside Docker containers after fuzzing completes.
#
# Alignment with ChatAFL (cov_script.sh):
#   ChatAFL reports BOTH line and branch coverage:
#     "Time,l_per,l_abs,b_per,b_abs"
#   We collect both metrics too, via gcovr summary JSON.
#
# Output files:
#   gcovr-summary.json  — machine-readable (branch + line)
#   gcovr-summary.txt   — human-readable text
#   index.html          — HTML detail report
#   coverage.xml        — Cobertura XML
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

SRC_DIR="${1:-/opt/mosquitto-gcov}"
OUT_DIR="${2:-/coverage}"

mkdir -p "$OUT_DIR"
cd "$SRC_DIR"

summary_txt="$OUT_DIR/gcovr-summary.txt"
summary_json="$OUT_DIR/gcovr-summary.json"
html_file="$OUT_DIR/index.html"
xml_file="$OUT_DIR/coverage.xml"

# ─── Detect gcovr capabilities ──────────────────────────────────────────
# gcovr >=6.0 supports --merge-mode-functions
# gcovr >=7.0 supports --gcov-ignore-errors
GCOVR_VER="$(gcovr --version 2>/dev/null | head -1 | grep -oP '[0-9]+\.[0-9]+' || echo '0.0')"
GCOVR_MAJOR="${GCOVR_VER%%.*}"

GCOVR_COMPAT_FLAGS=""
if (( GCOVR_MAJOR >= 6 )); then
  GCOVR_COMPAT_FLAGS="--merge-mode-functions=merge-use-line-0"
fi
if (( GCOVR_MAJOR >= 7 )); then
  GCOVR_COMPAT_FLAGS="${GCOVR_COMPAT_FLAGS} --gcov-ignore-errors=no_working_dir_found"
fi

# ─── Single gcovr invocation (all outputs at once) ──────────────────────
# Collect BOTH line and branch coverage (no --branches-only flag).
# This matches ChatAFL's `gcovr -r . -s` which reports both.
#
# IMPORTANT: gcovr 7.x treats `-o` as a GLOBAL output flag, NOT a
# per-format output flag.  Each format needs its own output argument:
#   --txt FILE               (not --txt -o FILE)
#   --json-summary FILE      (not --json-summary-pretty -o FILE)
#   --html-details FILE      (not --html-details -o FILE)
#   --xml FILE               (not --xml-pretty -o FILE)
# Previously the script used `-o` per format, which caused gcovr to
# only write the LAST format (XML), leaving JSON/HTML/TXT empty.

if (( GCOVR_MAJOR >= 5 )); then
  # gcovr >=5.0: supports --txt, --json-summary, --json-summary-pretty
  gcovr -r . \
    ${GCOVR_COMPAT_FLAGS} \
    --txt "$summary_txt" \
    --json-summary "$summary_json" --json-summary-pretty \
    --html-details "$html_file" \
    --xml "$xml_file" --xml-pretty \
    2>&1 | tee -a "$OUT_DIR/gcovr.log"
else
  # gcovr <5.0 (e.g., 4.2): no --txt, no --json-summary
  # Generate only XML + HTML; we'll derive JSON from XML below.
  gcovr -r . \
    --html-details --output "$html_file" \
    2>&1 | tee -a "$OUT_DIR/gcovr.log"
  gcovr -r . \
    --xml-pretty --output "$xml_file" \
    2>&1 | tee -a "$OUT_DIR/gcovr.log"
  gcovr -r . -s > "$summary_txt" 2>&1 || true
fi

# ─── Fallback: Generate JSON from Cobertura XML if JSON is missing ───
if [[ ! -s "$summary_json" && -s "$xml_file" ]]; then
  python3 - "$xml_file" "$summary_json" <<'XMLTOJSON'
import xml.etree.ElementTree as ET, json, sys
tree = ET.parse(sys.argv[1])
root = tree.getroot()
lr = float(root.attrib.get('line-rate', 0))
br = float(root.attrib.get('branch-rate', 0))
lv = int(root.attrib.get('lines-valid', 0))
lc = int(root.attrib.get('lines-covered', 0))
bv = int(root.attrib.get('branches-valid', 0))
bc = int(root.attrib.get('branches-covered', 0))
d = {
    'branch_percent': round(br * 100, 2),
    'branch_covered': bc,
    'branch_total': bv,
    'line_percent': round(lr * 100, 2),
    'line_covered': lc,
    'line_total': lv,
    '_source': 'coverage.xml (fallback)'
}
with open(sys.argv[2], 'w') as f:
    json.dump(d, f, indent=2)
print(f'Generated JSON summary from coverage.xml')
XMLTOJSON
  echo "(fallback) Generated $summary_json from $xml_file" >> "$OUT_DIR/gcovr.log"
fi

echo "" >> "$OUT_DIR/gcovr.log"
echo "gcovr version: ${GCOVR_VER}" >> "$OUT_DIR/gcovr.log"
echo "Saved coverage artifacts (line + branch) to $OUT_DIR"
