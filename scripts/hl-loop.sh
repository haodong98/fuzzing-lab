#!/usr/bin/env bash
# hl-loop.sh — minimal Heuristic Learning loop (per the plan §2.5).
#
# Two-clock architecture:
#   - Fast clock: AFL++ kernel, byte-level mutation, ~10^3-10^4 exec/s.
#   - Slow clock: this script wakes between rounds, reads the campaign artifacts
#     (plot_data, fuzzer_stats, queue), and either invokes an LLM coding agent
#     (if available) OR applies a pre-prepared patch representing what the agent
#     would produce. The patch can change harness, dictionary, or custom mutator.
#
# Subcommands:
#   round1                  — fuzz from clean seeds with the baseline harness/dict
#   introspect              — emit a structured prompt + plot summary for the LLM
#   apply-patch <patch>     — apply a patch (harness+dict) and rebuild
#   apply-baked             — use the pre-baked Round 2 patch we ship in patches/hl-round2.diff
#   round2                  — resume fuzzing from Round 1 corpus with patched harness
#   eval                    — compare edge slopes before/after; emit verdict
#
# Usage:
#   bash scripts/hl-loop.sh round1 [DURATION_SEC=900]
#   bash scripts/hl-loop.sh introspect
#   bash scripts/hl-loop.sh apply-baked
#   bash scripts/hl-loop.sh round2 [DURATION_SEC=900]
#   bash scripts/hl-loop.sh eval

set -euo pipefail

ROUND1=findings-hl-round1
ROUND2=findings-hl-round2
INTRO=hl-introspect
HARNESS_SRC=src/harness.c
DICT=dict/png-extended.dict
SEEDS=seeds
BUILD=build
HARNESS_BIN=$BUILD/png_fuzz
BAKED_PATCH=patches/hl-round2.diff

AFL_ENV=(AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 \
         ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0)

cmd=${1:-help}
shift || true

case "$cmd" in
  round1)
    DUR=${1:-900}
    mkdir -p "$ROUND1"
    echo "[round1] running baseline for ${DUR}s -> $ROUND1"
    env "${AFL_ENV[@]}" timeout "$DUR" afl-fuzz \
        -i "$SEEDS" -o "$ROUND1" -x "$DICT" \
        -- "$HARNESS_BIN" @@ || true
    ;;

  introspect)
    mkdir -p "$INTRO"
    if [[ ! -f "$ROUND1/default/plot_data" ]]; then
      echo "[introspect] no $ROUND1/default/plot_data — run round1 first"; exit 1
    fi
    # Slope analysis: last 5 minutes vs full run.
    python3 - <<'PY' "$ROUND1/default/plot_data" "$INTRO/slope.txt"
import sys, csv
plot_path, out = sys.argv[1], sys.argv[2]
rows = []
with open(plot_path) as f:
    for line in f:
        if line.startswith('#') or not line.strip():
            continue
        parts = [p.strip() for p in line.split(',')]
        # AFL++ plot_data columns evolve; common: unix_time, cycles_done, cur_item, corpus_count,
        # pending_total, pending_favs, map_size, saved_crashes, saved_hangs, max_depth, execs_per_sec,
        # edges_found
        try:
            rows.append({
              't': int(parts[0]),
              'corpus_count': int(parts[3]),
              'edges_found': int(parts[-1]),
              'execs_per_sec': float(parts[10]) if len(parts) > 10 else 0.0,
            })
        except (ValueError, IndexError):
            continue
if len(rows) < 2:
    print("not enough rows")
    sys.exit(0)
t0 = rows[0]['t']; tN = rows[-1]['t']
duration = tN - t0
overall_slope = (rows[-1]['edges_found'] - rows[0]['edges_found']) / max(1, duration)
# Last 5 min slope
cutoff = tN - 300
tail = [r for r in rows if r['t'] >= cutoff]
if len(tail) >= 2:
    tail_slope = (tail[-1]['edges_found'] - tail[0]['edges_found']) / max(1, tail[-1]['t']-tail[0]['t'])
else:
    tail_slope = 0
plateau = "PLATEAU" if tail_slope < 0.1 * overall_slope and tail_slope < 0.5 else "still climbing"
with open(out, 'w') as f:
    f.write(f"duration={duration}s edges_found={rows[-1]['edges_found']} "
            f"corpus={rows[-1]['corpus_count']} "
            f"overall_slope={overall_slope:.3f}/s tail_slope={tail_slope:.3f}/s "
            f"verdict={plateau}\n")
print(open(out).read().strip())
PY
    # Build the LLM prompt (would be sent to a coding agent in production).
    cat > "$INTRO/prompt.md" <<EOF
# HL Round 2 Prompt — libpng AFL++ campaign

You are a coding agent maintaining a fuzzing harness. The current harness has plateaued.

## Round 1 stats
$(cat "$INTRO/slope.txt")

## Top 10 queue items by depth (proxy for hard-to-reach paths)
$(ls -lS "$ROUND1/default/queue/" 2>/dev/null | head -11 || echo '(no queue)')

## Crashes so far
$(ls -1 "$ROUND1/default/crashes/" 2>/dev/null | head -10 || echo '(none)')

## Current harness (src/harness.c)
\`\`\`c
$(cat "$HARNESS_SRC")
\`\`\`

## Current dictionary entry count
$(grep -cE '^[a-zA-Z_]+=' "$DICT" || echo 0)

## Task
Propose a unified diff that:
  1. Enables additional png_set_* transformations to widen coverage.
  2. Adds dictionary entries for any unimplemented chunk types you can identify
     in libpng source (cf. /opt/libpng-1.2.56/pngrutil.c).
  3. (Optional) Defines a custom mutator skeleton at src/png_custom_mutator.c.

Output ONLY the diff in patches/hl-round2.diff.
EOF
    echo "[introspect] prompt written to $INTRO/prompt.md"
    echo "[introspect] In production: feed $INTRO/prompt.md to a coding agent."
    echo "[introspect] In this lab: use 'apply-baked' to apply the pre-prepared patch."
    ;;

  apply-baked)
    if [[ ! -f "$BAKED_PATCH" ]]; then
      echo "[apply-baked] no $BAKED_PATCH"; exit 1
    fi
    git diff --quiet --exit-code "$HARNESS_SRC" "$DICT" 2>/dev/null || \
      cp "$HARNESS_SRC" "$HARNESS_SRC.before-hl"
    cp "$DICT" "$DICT.before-hl"
    patch -p1 < "$BAKED_PATCH"
    echo "[apply-baked] patched. Rebuilding..."
    make -B "$BUILD/png_fuzz"
    ;;

  round2)
    DUR=${1:-900}
    mkdir -p "$ROUND2"
    if [[ -d "$ROUND1/default/queue" ]]; then
      # Resume by seeding Round 2 from Round 1's queue (the corpus we already evolved).
      echo "[round2] seeding from Round 1 queue (size=$(ls "$ROUND1/default/queue" | wc -l))"
      RESUME_SEEDS=hl-round2-seeds
      rm -rf "$RESUME_SEEDS"
      mkdir -p "$RESUME_SEEDS"
      cp "$ROUND1/default/queue/"* "$RESUME_SEEDS/" 2>/dev/null || true
    else
      echo "[round2] no Round 1 corpus, starting from $SEEDS"
      RESUME_SEEDS="$SEEDS"
    fi
    env "${AFL_ENV[@]}" timeout "$DUR" afl-fuzz \
        -i "$RESUME_SEEDS" -o "$ROUND2" -x "$DICT" \
        -- "$HARNESS_BIN" @@ || true
    ;;

  eval)
    if [[ ! -f "$ROUND1/default/plot_data" || ! -f "$ROUND2/default/plot_data" ]]; then
      echo "[eval] need both rounds' plot_data"; exit 1
    fi
    python3 - <<'PY' "$ROUND1/default/plot_data" "$ROUND2/default/plot_data"
import sys
def slope_at_tail(path, window=300):
    rows = []
    with open(path) as f:
        for line in f:
            if line.startswith('#') or not line.strip(): continue
            p = [x.strip() for x in line.split(',')]
            try:
                rows.append((int(p[0]), int(p[-1])))
            except Exception:
                continue
    if len(rows) < 2: return None, None
    t0, tN = rows[0][0], rows[-1][0]
    cutoff = tN - window
    tail = [r for r in rows if r[0] >= cutoff]
    overall = (rows[-1][1]-rows[0][1]) / max(1, tN-t0)
    if len(tail) >= 2:
        tail_s = (tail[-1][1]-tail[0][1]) / max(1, tail[-1][0]-tail[0][0])
    else:
        tail_s = 0
    return overall, tail_s

r1_overall, r1_tail = slope_at_tail(sys.argv[1])
r2_overall, r2_tail = slope_at_tail(sys.argv[2])

print(f"Round 1: overall={r1_overall:.3f} edges/s, last-5min={r1_tail:.3f} edges/s")
print(f"Round 2: overall={r2_overall:.3f} edges/s, last-5min={r2_tail:.3f} edges/s")
if r2_overall > r1_tail * 1.2:
    print("[VERDICT] HL Round 2 slope > 1.2x Round 1 tail slope — plateau broken.")
elif r2_overall > r1_tail:
    print("[VERDICT] HL Round 2 slope marginally higher — weak signal.")
else:
    print("[VERDICT] HL Round 2 did NOT beat Round 1 tail. Negative finding — report it.")
PY
    ;;

  *)
    sed -n '1,30p' "$0"
    ;;
esac
