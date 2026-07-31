# Qualification contract

This document describes the commands to use only after build and timing
admission is explicitly available. It is not authorization to bypass a live
resource fence.

## Build subject

Build from a clean, source-bound revision with a private target directory and
the checked-in standalone lock:

```sh
FRE_SEARCH_V8_SUBJECT_REVISION="$revision" \
  cargo build \
  --manifest-path research/aot/search-v8-bakeoff/Cargo.toml \
  --release --locked --offline
```

The build script rejects non-arm64-macOS targets and a missing or malformed
revision. Its `OUT_DIR` contains:

- `fre_search_v8_span.o`
- `fre_search_v8_span_receipt.tsv`
- `fre_search_v8_span_bindings.rs`
- `fre_search_v8_span.h`
- `fre_search_v8_span.map`

The object, v2 build receipt, generated bindings, and executable must all come
from the same build. The receipt includes the source-first compiler's
object-binding and canonical compiler-receipt identities. Do not recover
symbol names from an untrusted object or final image; use the receipt-derived
names.

## Linked-image evidence

After the final executable exists, run the read-only linked-image qualifier:

```sh
bash qualify_linked_image.sh \
  "$receipt" "$object" "$binary" "$link_map" "$new_link_evidence_dir"
```

`$object` must contain the exact complete object bytes named by the receipt.
`$link_map` must be the exact absolute map path named by the receipt, because
that original object path is used only as the map's corroborating provider
label. The timing runner retains and verifies its own object copy before
calling the qualifier; it does not accept caller-selected substitutes.

The verifier parses bounded regular files only. It directly parses the final
Mach-O header, bounded load commands, segments, sections, `LC_SYMTAB`, and
string table. It fails on symlinks, hard-linked aliases, a non-ARM64 or
non-`MH_EXECUTE` file, malformed ranges, duplicate fields or symbols,
section-size drift, protection drift, address drift, and payload or metadata
byte drift. It never executes the subject. `nm`, `otool`, and the exact
receipt-path link map are retained corroboration, not authority for facts
available from final bytes.

Its canonical 24-row receipt is
`fre-search-v8-bakeoff-linked-image-v2`. Its provider label is
`exact-receipt-derived-final-bytes`; it deliberately does not claim that final
bytes prove historical linker-input provenance. A PASS still describes only
a benchmark-local raw static provider.

## Timing evidence

With an already-held reviewed timing admission:

```sh
FRE_RESOURCE_HOLDER_KIND=timing \
FRE_RESOURCE_HOLDER_DIR="$holder_dir" \
FRE_RESOURCE_HOLDER_TOKEN="$holder_token" \
  bash run_qualification.sh \
    "$binary" "$receipt" "$new_results_dir"
```

The runner is single-threaded. It proceeds while other CPU work exists and
does not kill, renice, pause, or wait indefinitely for unrelated work. It
rejects a timing-holder token unless it is exactly 64 lowercase hexadecimal
characters.

Before its first metadata or measured invocation, the runner copies the input
binary to `subject-bin`, qualifies it, and then executes only that retained
copy. It checks the retained digest at every phase boundary. The closed bundle
contains:

| File | Contract |
|---|---|
| `build-receipt.tsv` | Exact build-script identity receipt |
| `subject.o` | Complete retained object, hash-bound to the receipt |
| `subject-bin` | Exact retained executable used by every subject invocation |
| `linked-image/` | Exact map/captures plus byte-rederived linked-image receipt |
| `metadata.tsv` | 38 fixed v3 subject facts, including the closed lifecycle grids and AOT exclusion |
| `hot.csv` | Header plus 1,944 rows |
| `cold.csv` | Header plus 84 rows |
| `first-call.csv` | Header plus 240 rows |
| `lifecycle.csv` | Header plus 1,920 portable/JIT lifecycle rows |
| `summary.csv` | Header plus 54 raw-derived cell summaries |
| `lifecycle-summary.csv` | Header plus 40 strict per-call-count gate rows |
| `lifecycle-break-even.csv` | Header plus four empirical/advisory break-even rows |
| `sequence.tsv` | 1,860 process paths and complete-output hashes |
| four process directories | 648 hot, 12 cold, 240 first-call, and 960 lifecycle outputs |
| `environment.tsv` | Binary/build identities, timing authority, and lifecycle cache policy |
| `completion.tsv` | Closed cardinality receipt |
| `runtime-cwd/` | Empty isolated working directory used by every process |

`verify_results.py verify` rejects any extra or missing bundle path. It
directly re-verifies `subject-bin`, requires the retained linked receipt to be
the exact rederived bytes, and requires the environment binary digest, linked
executable digest, and retained binary digest to be equal. It checks every row
against the build receipt, reconstructs every process-row stream, requires
exact matrices, enforces fixed routes and authority labels, checks same-cell
semantic values and checksums, and byte-compares the raw-derived summary.
The completion receipt also fixes one retained binary, four linked-evidence
files, and 24 linked-receipt rows.

The hot performance gate is:

1. for all 54 cells, both `portable / raw-static-aot` and
   `portable / strict-wx-jit` geomeans are greater than 1.0; and
2. across all 648 same-process pairs per native engine, at least 95% are
   strict native wins.

No performance threshold is applied to cold or ready-first-call observations.
Final-link latency is also not included. If link latency is measured later,
precompile the fixed C driver and label the timed phase
`final-image-link-only`; do not combine C compilation, Cargo compilation, or
program startup with it.

## Portable/JIT lifecycle break-even

The lifecycle schema compares construction plus repeated public calls for the
portable engine and strict-W^X JIT only. Its closed cases are:

- 64 KiB absent;
- 64 KiB adaptive-secondary-dense-primary-absent;
- 1 MiB tail; and
- 1 MiB natural-text.

The 64 KiB call grid is
`0,1,2,4,8,16,32,64,128,256,512,1024`; the 1 MiB grid is
`0,1,2,4,8,16,32,64`. Thus no timed cell performs more than 64 MiB of public
search calls. Every case/call-count/repetition is a fresh process. Each
process emits exactly two rows, ordered portable/JIT for even repetitions and
JIT/portable for odd repetitions. There are 24 repetitions, so the two orders
are exactly balanced.

The timed portable stage is `portable-builder-plus-public-calls` on route
`portable-lifecycle`. The timed native stage is
`plan-kir-emit-strict-wx-plus-public-calls` on route
`strict-wx-jit-lifecycle`. Fixture and independent-oracle construction occur
before either timer; engine construction and all requested public calls occur
inside it; destruction occurs after it. A call count of zero therefore
measures construction alone. Raw static AOT is explicitly excluded as
`excluded-until-safe-static-adopter`: the benchmark-local direct ABI is not a
safe static adopter and must not be presented as an end-to-end AOT lifecycle.

For every case and call count, the strict empirical gate uses the 24 paired
same-process ratios `strict_wx_jit_total_ns / portable_total_ns`. A cell passes
only when their geomean is at most `0.98` and JIT is strictly faster in at
least 20 of 24 pairs. The empirical sustained break-even is the smallest
measured call count whose cell and every later cell in that size's grid pass.
The verifier rejects a purported completed qualification if any of the four
cases has no sustained break-even in its closed grid.
The two derive commands still write per-cell and break-even diagnostics for a
structurally valid losing run. The runner then applies the strict lifecycle
gate before writing `environment.tsv` or `completion.tsv`; failure leaves only
diagnostic material, never a purported completed qualification.

`lifecycle-break-even.csv` also reports a deliberately separate advisory
model. It takes the median zero-call total as setup cost and estimates
per-call cost from the median maximum-grid total. When the fitted JIT
per-call cost is lower, the modeled crossing is
`ceil((jit_setup - portable_setup) /
(portable_per_call - jit_per_call))`; already-cheaper setup yields zero,
non-decreasing/invalid slopes are labeled rather than forced into a crossing.
This endpoint model never changes an empirical PASS or FAIL.

The runner does not flush caches and does not discard or trim samples.
Operating-system page-cache state is explicitly uncontrolled. These facts,
and the fresh-process policy, are closed fields in
`fre-search-v8-bakeoff-environment-v3`.

## Tamper suites

The two Python unittest sources cover:

- receipt ordering and identity-derived symbol names;
- malformed timing-holder tokens;
- hot route, identity, order, checksum, semantic, alignment, iteration, and
  performance tampering;
- cold phase/scope tampering;
- first-call authority tampering;
- lifecycle schema, lifecycle-only routes, engine exclusion, call grid,
  AB/BA order, stage, checksum, semantic, alignment, and timing tampering;
- lifecycle paired-ratio, 20-of-24 win, and sustained-break-even failures;
- object bytes;
- retained/linked/timing binary identity;
- direct Mach-O CPU type, file type, load-command ranges, section alignment,
  displacement and overlap, and exact symbol type/table;
- final payload and metadata bytes;
- final-image protections;
- `nm`, `otool`, and link-map corroboration;
- entry/payload address equality; and
- exact section size.

They are source-bound by `benchmark-source-files.txt`. Run them only when test
execution is admitted:

```sh
python3 -m unittest \
  test_results_verifier.py test_linked_image_verifier.py
```

Passing tests and measurements do not populate either empty Search
source-qualification table or turn this deliberately raw benchmark into a
safe-adoption qualification. The static-adoption architecture exists, but
production remains fail-closed until an exact row, final-image evidence, and
the separate adoption contract are qualified and promoted.
