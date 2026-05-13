# EPFL CS-412 Fuzzing Lab — libpng + AFL++ Makefile
# Run inside the Docker container (see Dockerfile). All paths assume /work mount.

LIBPNG_SRC      := /opt/libpng-1.2.56
AFL_HOME        := /opt/AFLplusplus
NOCRC_PATCH     := $(AFL_HOME)/utils/libpng_no_checksum/libpng-nocrc.patch

WORK            := $(CURDIR)
BUILD           := $(WORK)/build
SEEDS           := $(WORK)/seeds
DICT            := $(WORK)/dict/png-extended.dict
SRC             := $(WORK)/src
FINDINGS        := $(WORK)/findings
FINDINGS_QEMU   := $(WORK)/findings-qemu
FINDINGS_PERS   := $(WORK)/findings-persistent
BENCH_RESULTS   := $(WORK)/bench-results

# Configurable. Override on the command line:  make fuzz FUZZ_TIME=120
FUZZ_TIME      ?= 1800
FUZZ_TIME_HL   ?= 900
JOBS           ?= $(shell nproc 2>/dev/null || echo 4)

# Three libpng builds:
#   instrumented        : afl-clang-fast + ASan + UBSan       — main fuzzing target (Q1-Q5, Q8)
#   instrumented-noasan : afl-clang-fast, no sanitizer        — Q8 baseline (perf upper bound)
#   vanilla             : gcc, no instrumentation, no ASan    — Q7 QEMU-mode target
INSTR_PREFIX        := $(BUILD)/install-instrumented
NOASAN_PREFIX       := $(BUILD)/install-noasan
VANILLA_PREFIX      := $(BUILD)/install-vanilla

INSTR_LIB           := $(INSTR_PREFIX)/lib/libpng12.a
NOASAN_LIB          := $(NOASAN_PREFIX)/lib/libpng12.a
VANILLA_LIB         := $(VANILLA_PREFIX)/lib/libpng12.a

# AFL++ env defaults. AFL_SKIP_CPUFREQ silences the cpufreq warning in Docker. AFL_NO_AFFINITY lets
# AFL++ pick any free core. ASAN_OPTIONS=detect_leaks=0 avoids leak-detection false positives in
# fuzzing (we re-enable for triage).
AFL_ENV := AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0

.PHONY: all build build-libs build-harnesses smoke seeds clean clean-fuzz clean-build help

all: build smoke

help:
	@echo "Targets:"
	@echo "  build              — build all libs + all harnesses"
	@echo "  seeds              — generate seed corpus (PIL-based)"
	@echo "  smoke              — sanity-check png_fuzz on a known-good seed"
	@echo "  fuzz               — instrumented + ASan, $(FUZZ_TIME)s"
	@echo "  fuzz-persistent    — persistent mode, $(FUZZ_TIME)s"
	@echo "  fuzz-qemu          — QEMU mode (vanilla binary), $(FUZZ_TIME)s"
	@echo "  bench              — Q8: 60s exec-speed bench across (no-asan/asan-fork/asan-persistent)"
	@echo "  hl-round1 hl-round2 — HL feedback loop (15 min each)"
	@echo "  triage             — afl-tmin + ASan symbolize on findings/default/crashes/"
	@echo "  plot               — afl-plot for both campaigns"
	@echo "  edge-counts        — Q8: whole-library probe vs final harness binary edges"
	@echo "  clean / clean-fuzz / clean-build"

build: build-libs build-harnesses
build-libs:      $(INSTR_LIB) $(NOASAN_LIB) $(VANILLA_LIB)
build-harnesses: $(BUILD)/png_fuzz $(BUILD)/png_fuzz_noasan $(BUILD)/png_fuzz_persistent $(BUILD)/png_fuzz_qemu $(BUILD)/png_edge_lib_all

# === libpng builds ===

# (1) Instrumented + ASan + UBSan. AFL_USE_ASAN/UBSAN are the recommended way — they wire up the
# right libclang_rt and set sane defaults, vs. naked -fsanitize=... which can miss runtime libs in
# static-link mode.
$(INSTR_LIB):
	mkdir -p $(BUILD)
	rm -rf $(BUILD)/libpng-instrumented $(INSTR_PREFIX)
	cp -r $(LIBPNG_SRC) $(BUILD)/libpng-instrumented
	cd $(BUILD)/libpng-instrumented && patch -p0 < $(NOCRC_PATCH)
	cd $(BUILD)/libpng-instrumented && \
	  AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
	  CC=afl-clang-fast \
	  CFLAGS="-g -O1 -fno-omit-frame-pointer" \
	  ./configure --disable-shared --prefix=$(INSTR_PREFIX) >/dev/null && \
	  $(MAKE) -j$(JOBS) >/dev/null && \
	  $(MAKE) install >/dev/null
	@echo "[OK] $(INSTR_LIB)"

# (2) Instrumented but no sanitizer — Q8 perf upper bound for fork mode
$(NOASAN_LIB):
	mkdir -p $(BUILD)
	rm -rf $(BUILD)/libpng-noasan $(NOASAN_PREFIX)
	cp -r $(LIBPNG_SRC) $(BUILD)/libpng-noasan
	cd $(BUILD)/libpng-noasan && patch -p0 < $(NOCRC_PATCH)
	cd $(BUILD)/libpng-noasan && \
	  CC=afl-clang-fast \
	  CFLAGS="-g -O1" \
	  ./configure --disable-shared --prefix=$(NOASAN_PREFIX) >/dev/null && \
	  $(MAKE) -j$(JOBS) >/dev/null && \
	  $(MAKE) install >/dev/null
	@echo "[OK] $(NOASAN_LIB)"

# (3) Vanilla libpng — gcc, no instrumentation, no ASan. Keep CRC patch (PDF §6.2 rationale).
$(VANILLA_LIB):
	mkdir -p $(BUILD)
	rm -rf $(BUILD)/libpng-vanilla $(VANILLA_PREFIX)
	cp -r $(LIBPNG_SRC) $(BUILD)/libpng-vanilla
	cd $(BUILD)/libpng-vanilla && patch -p0 < $(NOCRC_PATCH)
	cd $(BUILD)/libpng-vanilla && \
	  CC=gcc \
	  CFLAGS="-g -O1" \
	  ./configure --disable-shared --prefix=$(VANILLA_PREFIX) >/dev/null && \
	  $(MAKE) -j$(JOBS) >/dev/null && \
	  $(MAKE) install >/dev/null
	@echo "[OK] $(VANILLA_LIB)"

# === Harness binaries ===

$(BUILD)/png_fuzz: $(SRC)/harness.c $(INSTR_LIB)
	AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast \
	  -I $(INSTR_PREFIX)/include \
	  -L $(INSTR_PREFIX)/lib \
	  -g -O1 -fno-omit-frame-pointer \
	  $(SRC)/harness.c \
	  -lpng12 -lz -lm \
	  -o $@
	@echo "[OK] $@"

$(BUILD)/png_fuzz_noasan: $(SRC)/harness.c $(NOASAN_LIB)
	afl-clang-fast \
	  -I $(NOASAN_PREFIX)/include \
	  -L $(NOASAN_PREFIX)/lib \
	  -g -O1 \
	  $(SRC)/harness.c \
	  -lpng12 -lz -lm \
	  -o $@
	@echo "[OK] $@"

$(BUILD)/png_fuzz_persistent: $(SRC)/harness_persistent.c $(INSTR_LIB)
	AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast \
	  -I $(INSTR_PREFIX)/include \
	  -L $(INSTR_PREFIX)/lib \
	  -g -O1 -fno-omit-frame-pointer \
	  $(SRC)/harness_persistent.c \
	  -lpng12 -lz -lm \
	  -o $@
	@echo "[OK] $@"

$(BUILD)/png_fuzz_qemu: $(SRC)/harness.c $(VANILLA_LIB)
	gcc \
	  -I $(VANILLA_PREFIX)/include \
	  -L $(VANILLA_PREFIX)/lib \
	  -g -O1 \
	  $(SRC)/harness.c \
	  -lpng12 -lz -lm \
	  -o $@
	@echo "[OK] $@"

$(BUILD)/png_edge_lib_all: $(SRC)/edge_probe.c $(INSTR_LIB)
	AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast \
	  -I $(INSTR_PREFIX)/include \
	  -g -O1 -fno-omit-frame-pointer \
	  $(SRC)/edge_probe.c \
	  -Wl,--whole-archive $(INSTR_LIB) -Wl,--no-whole-archive \
	  -lz -lm \
	  -o $@
	@echo "[OK] $@"

# === Seeds ===

seeds: $(SEEDS)/.stamp
$(SEEDS)/.stamp: scripts/gen-seeds.py
	mkdir -p $(SEEDS)
	python3 scripts/gen-seeds.py
	# afl-cmin needs a built harness. Fall back to no minimization on first build.
	@if [ -x $(BUILD)/png_fuzz ]; then \
	  afl-cmin -i $(SEEDS) -o $(SEEDS).min -- $(BUILD)/png_fuzz @@ 2>/dev/null && \
	  rm -rf $(SEEDS) && mv $(SEEDS).min $(SEEDS); \
	fi
	touch $@

# === Smoke test ===

smoke: $(BUILD)/png_fuzz seeds
	@for s in $(SEEDS)/*.png; do \
	  out=$$($(BUILD)/png_fuzz $$s 2>&1; echo "exit=$$?"); \
	  echo "[smoke] $$s -> $$(echo $$out | grep -oE 'exit=[0-9]+')"; \
	done

# === Fuzz campaigns ===

.PHONY: fuzz fuzz-persistent fuzz-qemu

fuzz: $(BUILD)/png_fuzz seeds
	mkdir -p $(FINDINGS)
	$(AFL_ENV) timeout $(FUZZ_TIME) afl-fuzz \
	  -i $(SEEDS) -o $(FINDINGS) -x $(DICT) \
	  -- $(BUILD)/png_fuzz @@ || true

fuzz-persistent: $(BUILD)/png_fuzz_persistent seeds
	mkdir -p $(FINDINGS_PERS)
	$(AFL_ENV) timeout $(FUZZ_TIME) afl-fuzz \
	  -i $(SEEDS) -o $(FINDINGS_PERS) -x $(DICT) \
	  -- $(BUILD)/png_fuzz_persistent @@ || true

fuzz-qemu: $(BUILD)/png_fuzz_qemu seeds
	mkdir -p $(FINDINGS_QEMU)
	$(AFL_ENV) timeout $(FUZZ_TIME) afl-fuzz -Q \
	  -i $(SEEDS) -o $(FINDINGS_QEMU) -x $(DICT) \
	  -- $(BUILD)/png_fuzz_qemu @@ || true

# === Q8: exec-speed benchmarks ===

.PHONY: bench
bench: $(BUILD)/png_fuzz_noasan $(BUILD)/png_fuzz $(BUILD)/png_fuzz_persistent seeds
	@rm -rf /tmp/bench-noasan /tmp/bench-asan /tmp/bench-persistent
	@rm -rf $(BENCH_RESULTS)
	@mkdir -p $(BENCH_RESULTS)
	@echo ""
	@echo "=== Q8: exec speed comparison (60s each) ==="
	@echo "--- (1) no sanitizer + fork mode ---"
	-$(AFL_ENV) timeout 60 afl-fuzz -i $(SEEDS) -o /tmp/bench-noasan -x $(DICT) -- $(BUILD)/png_fuzz_noasan @@ >/dev/null 2>&1 || true
	@grep -h 'execs_per_sec' /tmp/bench-noasan/default/fuzzer_stats 2>/dev/null || echo "  (no stats)"
	@cp /tmp/bench-noasan/default/fuzzer_stats $(BENCH_RESULTS)/noasan-fork.fuzzer_stats 2>/dev/null || true
	@echo "--- (2) ASan + UBSan + fork mode ---"
	-$(AFL_ENV) timeout 60 afl-fuzz -i $(SEEDS) -o /tmp/bench-asan -x $(DICT) -- $(BUILD)/png_fuzz @@ >/dev/null 2>&1 || true
	@grep -h 'execs_per_sec' /tmp/bench-asan/default/fuzzer_stats 2>/dev/null || echo "  (no stats)"
	@cp /tmp/bench-asan/default/fuzzer_stats $(BENCH_RESULTS)/asan-fork.fuzzer_stats 2>/dev/null || true
	@echo "--- (3) ASan + UBSan + persistent ---"
	-$(AFL_ENV) timeout 60 afl-fuzz -i $(SEEDS) -o /tmp/bench-persistent -x $(DICT) -- $(BUILD)/png_fuzz_persistent @@ >/dev/null 2>&1 || true
	@grep -h 'execs_per_sec' /tmp/bench-persistent/default/fuzzer_stats 2>/dev/null || echo "  (no stats)"
	@cp /tmp/bench-persistent/default/fuzzer_stats $(BENCH_RESULTS)/asan-persistent.fuzzer_stats 2>/dev/null || true

# === Q8: edge counts (library only vs harness binary) ===

.PHONY: edge-counts
edge-counts: $(BUILD)/png_edge_lib_all $(BUILD)/png_fuzz seeds
	@echo ""
	@echo "=== Q8 (a): whole libpng archive linked into a probe ==="
	@rm -rf /tmp/edge-lib
	@timeout 5 afl-fuzz -V 1 -i $(SEEDS) -o /tmp/edge-lib -- $(BUILD)/png_edge_lib_all @@ >/dev/null 2>&1 || true
	@grep -h 'total_edges' /tmp/edge-lib/default/fuzzer_stats 2>/dev/null || echo "  (no stats)"
	@echo ""
	@echo "=== Q8 (b): harness binary instrumented edges ==="
	@rm -rf /tmp/edge-harness
	@timeout 5 afl-fuzz -V 1 -i $(SEEDS) -o /tmp/edge-harness -x $(DICT) -- $(BUILD)/png_fuzz @@ >/dev/null 2>&1 || true
	@grep -h 'total_edges' /tmp/edge-harness/default/fuzzer_stats 2>/dev/null || echo "  (no stats)"

# === Plot ===

.PHONY: plot
plot:
	@if [ -f $(FINDINGS)/default/plot_data ]; then \
	  afl-plot $(FINDINGS)/default plot_output && echo "[OK] plot_output/"; \
	else echo "[skip] no findings/default/plot_data"; fi
	@if [ -f $(FINDINGS_QEMU)/default/plot_data ]; then \
	  afl-plot $(FINDINGS_QEMU)/default plot_output_qemu && echo "[OK] plot_output_qemu/"; \
	else echo "[skip] no findings-qemu/default/plot_data"; fi

# === Triage ===

.PHONY: triage
triage:
	bash scripts/triage.sh $(FINDINGS)/default/crashes $(BUILD)/png_fuzz

# === HL feedback loop ===

.PHONY: hl-round1 hl-round2 hl-round3-eval

hl-round1: $(BUILD)/png_fuzz seeds
	bash scripts/hl-loop.sh round1 $(FUZZ_TIME_HL)

hl-round2: $(BUILD)/png_fuzz seeds
	bash scripts/hl-loop.sh round2 $(FUZZ_TIME_HL)

hl-round3-eval:
	bash scripts/hl-loop.sh eval

# === Cleanup ===

clean-fuzz:
	rm -rf $(FINDINGS) $(FINDINGS_QEMU) $(FINDINGS_PERS) $(BENCH_RESULTS) plot_output plot_output_qemu /tmp/bench-* findings-hl-*

clean-build:
	rm -rf $(BUILD)

clean: clean-fuzz clean-build
	rm -f $(SEEDS)/.stamp
