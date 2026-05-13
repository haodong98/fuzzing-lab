# CS-412 Fuzzing Lab Submission Manifest

This archive contains the reproducible libpng fuzzing environment, report
source/PDF, campaign data, plots, patches, and triage artifacts referenced by
the report.

Core files:
- `Dockerfile`
- `Makefile`
- `README.md`
- `reproduce.sh`
- `report.tex`
- `report.pdf`
- `usenix2019_v3.sty`

Source and fuzzing inputs:
- `src/`
- `dict/`
- `seeds/`
- `patches/`
- `scripts/`

Campaign artifacts:
- `findings/`
- `findings-qemu/`
- `findings-hl-round1/`
- `findings-hl-round2/`
- `findings-syn/`
- `plot_output/`
- `plot_output_qemu/`
- `plot_output_hl_round1/`
- `plot_output_hl_round2/`
- `bench-results/`
- `triage-syn/`
- `hl-introspect/`
- `hl-round2-seeds/`

Generated binaries under `build/` are intentionally omitted from the archive;
they are reproducible through the provided Dockerfile/Makefile/reproduce.sh
workflow.
