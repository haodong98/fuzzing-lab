#!/usr/bin/env bash
# reproduce.sh — one-shot replay of the entire CS-412 fuzzing lab.
#
# Usage:
#   ./reproduce.sh quick    # ~12 min total: 60s campaigns, 60s HL rounds
#   ./reproduce.sh full     # ~95 min total: 30-min Q4+Q7, 15-min HL rounds
#   ./reproduce.sh stage <name>   # run a single stage (see list below)
#
# Stages (in order):
#   docker-build   in-container-build  smoke   bench
#   fuzz           fuzz-qemu                       # Q4 + Q7 campaigns
#   q5-synthetic-bug                               # Q5 Plan B
#   hl-round1      hl-round2                       # HL feedback loop
#   plots          status-screens                  # appendix artifacts
#   pdf
#
# Idempotent: each stage cleans its own outputs before running.
#
# Prereqs:
#   - Docker Desktop running (linux/amd64 emulation; on Apple Silicon this uses Rosetta)
#   - pdflatex (TeX Live) on the host for the final compile step
#   - python3 + pip + pillow + pyte on the host for status-screen rendering
#
# Tunables (env vars):
#   FUZZ_TIME       (default: 1800)   seconds per Q4/Q7 campaign
#   FUZZ_TIME_HL    (default: 900)    seconds per HL round
#   FUZZ_TIME_SYN   (default: 60)     seconds for the Q5 AFL++ run
#   CAP_TIME        (default: 30)     seconds for the status-screen captures

set -euo pipefail

# ---- Configuration -------------------------------------------------------
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

CONTAINER=libpng-fuzz-runner
IMAGE=libpng-fuzz
PLATFORM=linux/amd64
# Path fix is essential: image's PATH puts /opt/AFLplusplus first, which makes
# vanilla gcc invoke afl-as in a loop.
SAFE_PATH=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

MODE=${1:-full}
case "$MODE" in
  quick)
    FUZZ_TIME=${FUZZ_TIME:-60}
    FUZZ_TIME_HL=${FUZZ_TIME_HL:-60}
    FUZZ_TIME_SYN=${FUZZ_TIME_SYN:-30}
    CAP_TIME=${CAP_TIME:-15}
    STAGES_DEFAULT="docker-build in-container-build smoke bench fuzz fuzz-qemu q5-synthetic-bug hl-round1 hl-round2 plots status-screens pdf"
    ;;
  full)
    FUZZ_TIME=${FUZZ_TIME:-1800}
    FUZZ_TIME_HL=${FUZZ_TIME_HL:-900}
    FUZZ_TIME_SYN=${FUZZ_TIME_SYN:-60}
    CAP_TIME=${CAP_TIME:-30}
    STAGES_DEFAULT="docker-build in-container-build smoke bench fuzz fuzz-qemu q5-synthetic-bug hl-round1 hl-round2 plots status-screens pdf"
    ;;
  stage)
    shift
    if [[ $# -eq 0 ]]; then
      echo "usage: $0 stage <stage-name>" >&2; exit 1
    fi
    STAGES_DEFAULT="$1"
    FUZZ_TIME=${FUZZ_TIME:-1800}
    FUZZ_TIME_HL=${FUZZ_TIME_HL:-900}
    FUZZ_TIME_SYN=${FUZZ_TIME_SYN:-60}
    CAP_TIME=${CAP_TIME:-30}
    ;;
  -h|--help|help)
    sed -n '1,40p' "$0"; exit 0 ;;
  *)
    echo "unknown mode: $MODE (use 'quick', 'full', or 'stage <name>')" >&2; exit 1 ;;
esac

# ---- Helpers -------------------------------------------------------------
log() { printf '\n\033[1;94m[reproduce.sh]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;91m[reproduce.sh]\033[0m %s\n' "$*" >&2; exit 1; }

pip_install() {
  if pip3 install --help 2>/dev/null | grep -q -- '--break-system-packages'; then
    pip3 install --break-system-packages "$@" >/dev/null
  else
    pip3 install --user "$@" >/dev/null
  fi
}

require_docker() {
  command -v docker >/dev/null || die "docker not found"
  docker info >/dev/null 2>&1 || die "docker daemon not reachable — start Docker Desktop first"
}

ensure_container() {
  if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    log "starting fresh container ($CONTAINER)"
    docker run -d --platform "$PLATFORM" --name "$CONTAINER" \
      -v "$PWD":/work -w /work --ulimit core=0:0 \
      "$IMAGE" tail -f /dev/null >/dev/null
  fi
}

dx() { docker exec -e "$SAFE_PATH" "$CONTAINER" bash -lc "unset AFL_HOME AFL_TAG; $*"; }

# ---- Stages --------------------------------------------------------------
stage_docker_build() {
  require_docker
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "docker image already present — skipping build (delete with 'docker rmi $IMAGE' to force)"
    return
  fi
  log "building docker image (one-time, ~10-20 min)"
  docker build --platform "$PLATFORM" -t "$IMAGE" .
}

stage_in_container_build() {
  require_docker; ensure_container
  log "building libpng × 3 + harnesses × 4 (~5-10 min)"
  dx 'make build'
}

stage_smoke() {
  require_docker; ensure_container
  log "smoke test (all seeds should exit 0)"
  dx 'make smoke'
}

stage_bench() {
  require_docker; ensure_container
  log "Q8 exec-speed bench (3 × 60s)"
  dx 'make bench'
}

stage_fuzz() {
  require_docker; ensure_container
  log "Q4 instrumented fuzz (${FUZZ_TIME}s)"
  dx "rm -rf findings && make fuzz FUZZ_TIME=${FUZZ_TIME}"
  dx 'grep -E "execs_per_sec|corpus_count|edges_found|stability|saved_crashes" findings/default/fuzzer_stats'
}

stage_fuzz_qemu() {
  require_docker; ensure_container
  log "Q7 QEMU fuzz (${FUZZ_TIME}s)"
  dx "rm -rf findings-qemu && make fuzz-qemu FUZZ_TIME=${FUZZ_TIME}"
  dx 'grep -E "execs_per_sec|corpus_count|edges_found|stability|saved_crashes" findings-qemu/default/fuzzer_stats'
}

stage_q5_synthetic_bug() {
  require_docker; ensure_container
  log "Q5 Plan B: apply synthetic bug + ${FUZZ_TIME_SYN}s AFL++ + triage"
  dx "
    patch -p1 < patches/synthetic-bug.patch
    rm -f build/png_fuzz_syn
    AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast \
      -I build/install-instrumented/include -L build/install-instrumented/lib \
      -g -O1 src/harness.c -lpng12 -lz -lm -o build/png_fuzz_syn
    rm -rf findings-syn
    AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 \
      ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0 \
      timeout ${FUZZ_TIME_SYN} afl-fuzz -i seeds -o findings-syn -x dict/png-extended.dict \
        -- build/png_fuzz_syn @@ >/dev/null 2>&1 || true
    echo 'crashes saved:'
    ls findings-syn/default/crashes/ | grep -v README | wc -l
  "
  log "triage: afl-tmin + ASan symbolize"
  dx "
    mkdir -p triage-syn
    CRASH=\$(ls findings-syn/default/crashes/id:000000* 2>/dev/null | head -1)
    if [[ -z \"\$CRASH\" ]]; then echo 'no crashes — synthetic bug may not have triggered' >&2; exit 0; fi
    afl-tmin -i \"\$CRASH\" -o triage-syn/aflfuzz-min.png -- build/png_fuzz_syn @@ 2>/dev/null
    ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=0 \
      build/png_fuzz_syn triage-syn/aflfuzz-min.png > /dev/null 2> triage-syn/aflfuzz-trace.txt
    awk '/AddressSanitizer/ {k=1} k && /^Shadow bytes around/ {exit} k {print}' \
      triage-syn/aflfuzz-trace.txt > triage-syn/aflfuzz-trace-trimmed.txt
    head -4 triage-syn/aflfuzz-trace-trimmed.txt
  "
  log "restoring harness.c"
  dx 'patch -p1 -R < patches/synthetic-bug.patch'
}

stage_hl_round1() {
  require_docker; ensure_container
  log "HL Round 1 baseline (${FUZZ_TIME_HL}s)"
  dx "rm -rf findings-hl-round1 && make hl-round1 FUZZ_TIME_HL=${FUZZ_TIME_HL}"
}

stage_hl_round2() {
  require_docker; ensure_container
  log "HL introspect + apply baked patch + rebuild + Round 2 (${FUZZ_TIME_HL}s)"
  dx 'bash scripts/hl-loop.sh introspect'
  # Apply patch only if not already applied (idempotent)
  if ! dx 'grep -q "png_set_palette_to_rgb" src/harness.c'; then
    dx 'bash scripts/hl-loop.sh apply-baked'
  fi
  dx 'rm -f build/png_fuzz && make /work/build/png_fuzz'
  dx "rm -rf findings-hl-round2 && make hl-round2 FUZZ_TIME_HL=${FUZZ_TIME_HL}"
  dx 'bash scripts/hl-loop.sh eval'
}

stage_plots() {
  require_docker; ensure_container
  log "generate all afl-plot graphs"
  dx '
    rm -rf plot_output plot_output_qemu plot_output_hl_round1 plot_output_hl_round2
    [ -f findings/default/plot_data ] && afl-plot findings/default plot_output
    [ -f findings-qemu/default/plot_data ] && afl-plot findings-qemu/default plot_output_qemu
    [ -f findings-hl-round1/default/plot_data ] && afl-plot findings-hl-round1/default plot_output_hl_round1
    [ -f findings-hl-round2/default/plot_data ] && afl-plot findings-hl-round2/default plot_output_hl_round2
    ls -d plot_output*
  '
}

stage_status_screens() {
  require_docker; ensure_container
  log "capture live AFL++ status screen (${CAP_TIME}s × 2) and render to PNG"
  command -v python3 >/dev/null || die "python3 required on host"
  python3 -c 'import pyte' 2>/dev/null || pip_install pyte pillow
  python3 -c 'from PIL import Image' 2>/dev/null || pip_install pillow

  dx "
    rm -rf /tmp/cap-findings1 /tmp/cap-findings2 /tmp/cap-*.txt
    script -q -c 'timeout ${CAP_TIME} env AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0 afl-fuzz -i seeds -o /tmp/cap-findings1 -x dict/png-extended.dict -- build/png_fuzz @@' /tmp/cap-instrumented.txt >/dev/null 2>&1 || true
    script -q -c 'timeout ${CAP_TIME} env AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 afl-fuzz -Q -i seeds -o /tmp/cap-findings2 -x dict/png-extended.dict -- build/png_fuzz_qemu @@' /tmp/cap-qemu.txt >/dev/null 2>&1 || true
    ls -la /tmp/cap-*.txt
  "
  docker cp "$CONTAINER":/tmp/cap-instrumented.txt /tmp/cap-instrumented.txt
  docker cp "$CONTAINER":/tmp/cap-qemu.txt /tmp/cap-qemu.txt
  mkdir -p plot_output/status plot_output_qemu/status
  python3 scripts/render-afl-status.py /tmp/cap-instrumented.txt plot_output/status/afl_status_instrumented.png 130 32
  python3 scripts/render-afl-status.py /tmp/cap-qemu.txt          plot_output_qemu/status/afl_status_qemu.png    130 32
}

stage_pdf() {
  command -v pdflatex >/dev/null || die "pdflatex not found — install TeX Live"
  log "two-pass pdflatex compile"
  pdflatex -interaction=nonstopmode report.tex > /tmp/pdflatex1.log 2>&1
  pdflatex -interaction=nonstopmode report.tex > /tmp/pdflatex2.log 2>&1
  rm -f report.aux report.log report.out report.toc
  log "PDF stats:"
  pdfinfo report.pdf | grep -E 'Pages|Page size|File size'
}

# ---- Dispatcher ----------------------------------------------------------
run_stage() {
  case "$1" in
    docker-build)       stage_docker_build ;;
    in-container-build) stage_in_container_build ;;
    smoke)              stage_smoke ;;
    bench)              stage_bench ;;
    fuzz)               stage_fuzz ;;
    fuzz-qemu)          stage_fuzz_qemu ;;
    q5-synthetic-bug)   stage_q5_synthetic_bug ;;
    hl-round1)          stage_hl_round1 ;;
    hl-round2)          stage_hl_round2 ;;
    plots)              stage_plots ;;
    status-screens)     stage_status_screens ;;
    pdf)                stage_pdf ;;
    *)                  die "unknown stage: $1" ;;
  esac
}

START=$(date +%s)
log "MODE=$MODE  FUZZ_TIME=$FUZZ_TIME  FUZZ_TIME_HL=$FUZZ_TIME_HL  FUZZ_TIME_SYN=$FUZZ_TIME_SYN  CAP_TIME=$CAP_TIME"
for stage in $STAGES_DEFAULT; do
  log "▶ stage: $stage"
  run_stage "$stage"
done
ELAPSED=$(( $(date +%s) - START ))
log "✅ done in $(printf '%dm %ds' $((ELAPSED/60)) $((ELAPSED%60)))"
log "artifacts: findings/ findings-qemu/ findings-hl-round1/ findings-hl-round2/ findings-syn/"
log "           plot_output*/  triage-syn/  report.pdf  METRICS.txt"
log "(container '$CONTAINER' left running for ad-hoc inspection; 'docker rm -f $CONTAINER' to stop)"
