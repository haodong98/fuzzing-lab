# CS-412 Fuzzing Lab: libpng + AFL++

This directory contains the complete fuzzing environment and report artifacts for
the EPFL CS-412 fuzzing lab.

## Reproduce

Build the Docker image, rebuild all targets, run the campaigns, regenerate plots,
and compile the report:

```sh
./reproduce.sh full
```

For a shorter smoke run:

```sh
./reproduce.sh quick
```

Single stages can be run with:

```sh
./reproduce.sh stage in-container-build
./reproduce.sh stage bench
./reproduce.sh stage fuzz
./reproduce.sh stage fuzz-qemu
./reproduce.sh stage q5-synthetic-bug
./reproduce.sh stage plots
./reproduce.sh stage pdf
```

## Important Targets

- `make build`: build instrumented, no-sanitizer, vanilla/QEMU, persistent, and
  edge-probe binaries.
- `make fuzz FUZZ_TIME=1800`: run the instrumented ASan/UBSan campaign.
- `make fuzz-qemu FUZZ_TIME=1800`: run the vanilla binary under AFL++ QEMU mode.
- `make bench`: run the three Q8 60-second speed measurements.
- `make edge-counts`: measure whole-library and final-harness edge counts.
- `make plot`: regenerate AFL plot outputs for the two main campaigns.

## Main Artifacts

- `report.pdf`, `report.tex`: final report source and PDF.
- `src/harness.c`: baseline fork-mode libpng read harness.
- `src/harness_persistent.c`: persistent-mode variant for Q8.
- `src/edge_probe.c`: whole-archive edge-count probe for Q8.
- `dict/png-extended.dict`: PNG dictionary.
- `patches/`: synthetic bug and HL patches used in the report; the CRC patch is
  applied from AFL++'s bundled `utils/libpng_no_checksum/` directory.
- `findings/`, `findings-qemu/`: main campaign outputs (run for at least 30 minutes).
- `plot_output/`, `plot_output_qemu/`: AFL plot outputs and status screenshots.
