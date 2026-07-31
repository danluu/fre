# Search V26 fresh-disjoint development gate

This directory implements the result-blind gate frozen in
`../preregistration-v1.json`. It consumes only the independently generated V26
synthetic population. It does not read V25 result cells, Rebar, or LLVM output.

`gate-contract-v1.json` freezes the complete lattice, long-scan fixture
geometry, measurement orders, estimators, shard boundaries, and thresholds.
The source identity and cell-manifest hash deliberately remain `AWAITING`
until the coherent-relabel successor core and result-blind materializer are
reviewed. Timing authority must remain unavailable while either placeholder
exists.

The 7,776 cells are:

```
27 widths × 3 outputs × 16 accepted literals × 6 window shapes
```

Shards are equal and disjoint: widths 6–14, 15–23, and 24–32, with 2,592
cells each. Every long-scan fixture has a 2 MiB search window and is generated
one cell at a time. The first-legal-position fixture is intentionally only one
literal wide and measures call/setup overhead.

Planned files:

- `materialize_cells.rs`: canonical result-blind cell manifest.
- `runner.rs`: one-shard native/KIR correctness and timing runner.
- `analyze_v26_gate.py`: exact closure and frozen-threshold analyzer.
- `test_analyze_v26_gate.py`: synthetic analyzer tests only.
- `seal_v26_gate.py`: final immutable identity receipt creation.
- `launch_v26_gate_once.py`: fail-closed concurrent one-shot launcher.

No command in this directory may launch timing until the seal has status
`READY`, contains no placeholder, and authenticates the exact successor
source, runner binary, contract, cell manifest, and launcher bytes.
