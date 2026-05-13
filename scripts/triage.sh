#!/usr/bin/env bash
# triage.sh — minimize each crash with afl-tmin and dump a symbolized ASan trace.
#
# Output:
#   triage/<crash-id>/min.png        — minimized crashing input
#   triage/<crash-id>/trace.txt      — ASan output with source-level stack
#   triage/summary.txt               — one line per crash: crash-id  size_orig→size_min  top-frame
#
# Usage:
#   bash scripts/triage.sh [crashes-dir] [harness-binary]

set -euo pipefail

CRASHES_DIR="${1:-findings/default/crashes}"
HARNESS="${2:-build/png_fuzz}"
OUT_DIR="triage"

if [[ ! -d "$CRASHES_DIR" ]]; then
    echo "no such directory: $CRASHES_DIR"; exit 1
fi
if [[ ! -x "$HARNESS" ]]; then
    echo "harness not executable: $HARNESS"; exit 1
fi

mkdir -p "$OUT_DIR"
: > "$OUT_DIR/summary.txt"

# detect_leaks=0 because libpng's longjmp recovery can leave technically-leaked allocations that
# are not memory-safety bugs and would noise the reports.
# symbolize=1 + abort_on_error=1 + halt_on_error=1 give us the cleanest single trace.
export ASAN_OPTIONS="detect_leaks=0:symbolize=1:abort_on_error=1:halt_on_error=1:color=never:print_module_map=1"

shopt -s nullglob
crashes=("$CRASHES_DIR"/id:*)
if [[ ${#crashes[@]} -eq 0 ]]; then
    echo "no crash files found in $CRASHES_DIR"
    exit 0
fi

i=0
for crash in "${crashes[@]}"; do
    name=$(basename "$crash")
    i=$((i+1))
    work="$OUT_DIR/$name"
    mkdir -p "$work"

    # 1) Confirm reproducibility on the original input.
    "$HARNESS" "$crash" > "$work/orig-stdout.txt" 2> "$work/orig-trace.txt" || true

    # 2) Minimize. afl-tmin keeps the crash signal but shrinks the input greedily.
    afl-tmin -i "$crash" -o "$work/min.png" -- "$HARNESS" @@ \
        > "$work/tmin.log" 2>&1 || true

    if [[ ! -s "$work/min.png" ]]; then
        # afl-tmin failed; fall back to the original.
        cp "$crash" "$work/min.png"
    fi

    orig_size=$(stat -c '%s' "$crash" 2>/dev/null || stat -f '%z' "$crash")
    min_size=$(stat -c '%s' "$work/min.png" 2>/dev/null || stat -f '%z' "$work/min.png")

    # 3) Re-run on the minimized input with full symbolization.
    "$HARNESS" "$work/min.png" > "$work/min-stdout.txt" 2> "$work/trace.txt" || true

    # 4) Pull the top non-runtime frame for clustering.
    top_frame=$(grep -m1 -oE '#0 0x[0-9a-f]+ in [^ ]+' "$work/trace.txt" 2>/dev/null \
                | sed 's/^#0 0x[0-9a-f]\+ in //' || true)
    [[ -z "$top_frame" ]] && top_frame=$(grep -m1 -oE 'in [^ ]+ ' "$work/trace.txt" || true)
    [[ -z "$top_frame" ]] && top_frame="(no asan trace)"

    bug_type=$(grep -m1 -oE 'AddressSanitizer: [^ ]+' "$work/trace.txt" \
               || grep -m1 -oE 'UndefinedBehaviorSanitizer: [^ ]+' "$work/trace.txt" \
               || echo "(no sanitizer report)")

    printf '%-40s %6s -> %6s  %s | %s\n' \
        "$name" "$orig_size" "$min_size" "$bug_type" "$top_frame" \
        | tee -a "$OUT_DIR/summary.txt"
done

echo
echo "[OK] $i crash(es) triaged -> $OUT_DIR/"
echo "Summary: $OUT_DIR/summary.txt"
