# Public Rebar true-native census control

This directory contains a correctness census, not a benchmark. It answers two
separate questions without inspecting pattern or haystack contents:

1. Did the compiler emit and reproducibly link an AOT artifact?
2. Did the requested Rebar operation actually enter that artifact without
   calling any semantic runtime helper?

The first answer is never substituted for the second.

## Denominators

The canonical population is the de-duplicated public Rust/Rebar job set. The
current public corpus contains 344 jobs: 33 `compile` jobs and exactly 311
runtime jobs. The sealed plan refuses any other counts by default. Comparator
and first/steady replication produces a larger raw schedule-point population;
the plan seals those exact point IDs and their hash separately and never uses
that raw count in place of 311.

Every runtime job remains in the headline denominator. Unsupported models,
build/link failures, timeouts, missing receipts, wrong answers, helper-backed
execution, and failed controls are nonnative outcomes. The summary reports:

- authenticated native search cores / all 311 runtime jobs;
- strict whole-operation native jobs / all 311 runtime jobs;
- native search cores / successfully executed jobs (diagnostic only); and
- the raw runtime schedule-point denominator for comparison with older runs.

Fallback `count-spans` direct-entry or Span-fill iteration, multi-pattern
per-line `grep`, the static uniform capture multiplier route, the helper-free
exact-span participation route, the selector-negative/stock-positive capture
route, and the strict native `capture_next` route can
authenticate a native search or search/capture core while retaining a checked
Rust adapter outer loop. They are excluded from the strict whole-operation
numerator. Single-pattern `grep` instead enters the authenticated generated
whole-operation reducer once, so its LF/CRLF split and checked scalar reduction
do not retain that Rust outer loop. The uniform route is labelled separately
from both a fused capture
operation and capture-offset materialization: its native entries select spans;
the adapter applies an independently sealed per-row participation count. The
exact-span route separately traps both its ordinary native selector and its
architecture-specific native participation replay entry; it publishes only a
checked group count for the selector's exact span. The strict route
materializes group-zero-inclusive slots natively, then validates and reduces
those slots in Rust. The selector-negative route receives credit only for an
input on which its authenticated native selector proves every line negative;
its explicitly named stock-positive fallback marker is armed and must remain
unreached. A positive input remains correct through stock captures but is
classified nonnative rather than receiving credit for a partially native
operation.

`grep`, `count-captures`, and `grep-captures` with 1..4096 source expressions
are exact adapter *shapes*. This admits them to the sealed qualification
population; it does not turn either build-time proof into an assumption. A
uniform-proof semantic decline may use an independently authenticated
one-pattern exact-span participation route, followed by the stricter
`capture_next` route on an authenticated participation decline. Every parse,
allocation, resource, emission,
authentication, multi-source, or remaining semantic decline fails the
all-or-nothing build and must receive a `record-failure` receipt. It remains in
the 311-job denominator as nonnative rather than disappearing as unsupported.

The strict whole-operation boundary is a closed route classification, not a
route-name suffix convention. A scalar `count-spans` artifact receives that
classification only when its exact `Some(NativeFused)` or
`Some(NativeOrderedNfaFused)` receipt is selected through
`linked-native-span-sum-reducer`. A Span-fill entry still leaves refill,
validation, and reduction in Rust and therefore remains an adapter-loop route.
An unknown route, or a helper-backed or unknown aggregate strategy claiming
the native SpanSum reducer iteration, is rejected rather than inferred native.

## Privacy boundary and static dry run

The controller accepts only files underneath an explicitly supplied public KLV
root. Paths containing a holdout or query-history component are rejected. The
plan stores public benchmark/job/point IDs, option flags, expected scalar
values, relative KLV paths, and SHA-256 identities. It never writes patterns,
haystacks, process output, stderr, or free-form failure text. Process streams
are represented only by byte counts and hashes.

Each schedule and its expected file digest must be named explicitly. Repeated
`--schedule` pairs may merge a primary public schedule and public supplemental
jobs; conflicting IDs fail closed. `--dry-run` validates the source freeze,
schedule identities, public path containment, KLV hashes, and the 344/33/311
denominators without writing output, invoking Cargo, building, running a test,
or executing a benchmark:

```sh
python3 tools/aot-rebar-runner/census/true_native_census.py plan \
  --schedule /public/control/schedule-timing.json \
  --schedule-sha256 EXPECTED_SHA256 \
  --public-klv-root /public/corpus/klv \
  --recorded-public-klv-root public-corpus/klv \
  --public-corpus-label public-rebar-CORPUS_ID \
  --source-dir /clean/fre-source \
  --source-commit EXPECTED_COMMIT \
  --source-tree EXPECTED_TREE \
  --target aarch64-linux \
  --features asimd,sve,sve2 \
  --dry-run
```

`--skip-klv-hashing` is available only with `--dry-run`; a sealed plan must
hash every public KLV byte stream. Remove `--dry-run` and add `--output` to
write the immutable `fre.aot-rebar.true-native-plan.v2` manifest. Version 2
also seals the canonical target-feature bit mask and the complete job/point
topology, so qualification cannot reinterpret feature names or detach a point
from the job whose input identity it carries.

## Later qualification run

Do not perform these steps while a timing holdout needs an idle machine. They
are documented so the committed controller is runnable later without another
design step.

Build every exact-adapter job twice in independent, empty target directories,
with the plan's commit/tree, target, feature set, public build KLV, locked
dependencies, and `CARGO_INCREMENTAL=0`. The final runner must export its
symbols to the dynamic symbol table (`-Wl,--export-dynamic` on ELF;
`-Wl,-export_dynamic` on Mach-O), because inability to arm a symbol is a failed
qualification, not permission to omit it. Preserve each runner and
`aot-rebar-artifact.o` separately.

Build `runtime_symbol_trap.c` as a shared library for the same target. The
source supports AArch64 (`BRK`) and x86-64 (`UD2`) on Linux and macOS. Then run
one receipt per exact-adapter job:

```sh
python3 tools/aot-rebar-runner/census/true_native_census.py qualify-job \
  --plan census-plan.json \
  --job-id PUBLIC_FRE_JOB_ID \
  --public-klv-root /public/corpus/klv \
  --primary-runner /build-a/fre-aot-rebar-runner \
  --replica-runner /build-b/fre-aot-rebar-runner \
  --primary-object /build-a/aot-rebar-artifact.o \
  --replica-object /build-b/aot-rebar-artifact.o \
  --trap-library /control/runtime_symbol_trap.so \
  --output receipts/PUBLIC_FRE_JOB_ID.json
```

Repeat `--primary-object` and `--replica-object` in component ordinal order for
a composite v3 runner or the single-component strict-capture v4 runner. Its
normalized provenance must match every supplied object digest in both builds.
Native-row v3 additionally seals the complete
source-to-artifact map, each retained artifact's first source ordinal, source
cardinality, total object bytes, and the exact composite boundary. Every row
now also seals its selector automaton hash and the explicit
`uniform_capture_bridge` boolean. Ordinary rows must publish `false`.
An additive mixed V15 route may retain both ordinary helper-free entries and
prepared native Ordered-NFA entries. Each row then seals its exact engine,
capability/config/operation flags, complete runtime-symbol set, prepared bulk
strategy, serialized-program symbol and extent, Span-fill identity, and
ordinary/prepared state. The top-level record seals the 8 MiB handle and
scratch ceilings and two-million-unit setup-work ceiling. A scalar prepared
`grep` seals the same V15 ABI, program extent, native entry/Span-fill/program
identity, and distinct compatibility-reducer identity in normalized v2
provenance. The final-binary inventory must find every named text or data
identity; a provenance-only serialized program is not evidence.
Uniform-capture rows must publish `true`, the exact
`static-uniform-multiplier` resolution and native-search-core boundary, positive
proof identity/work/stack/minimum-width/count fields, one value per source, and
the three selector digest lists. Each source automaton/program/object digest is
checked against the component selected by `source_to_artifact`. Unrecognized or
missing raw v3 fields are rejected rather than silently discarded.

Native-capture v4 publishes exactly one source, artifact, and component. The
exact-span variant closes its selector, capture program, DFA geometry, bundle,
object, architecture-specific strategy, and three distinct selector/bundle/
replay symbols; its semantic-runtime-call count and final-binary helper
inventory must both be empty. Strict-capture v4's
sole component entry is an identity-suffixed native `capture_next`, its declared
runtime-symbol list is empty, and its object/program identities agree with the
component receipt. The closed record also seals group count and nullability,
source/selector/capture/plan/bundle/artifact digests, and the distinct native
materializer and ordinary selector symbols. Prepared V15 adds only the closed
typed proof objects described above; `strict_capture` exists only on normalized
v4. The
independent final-binary inventory must also contain zero semantic runtime
symbols for this strict route; an unused-but-linked helper is a failed strict
qualification rather than a trap-only allowance.

The closed selector-capture-fallback v4 variant is deliberately narrower. It
binds one helper-free native Span selector, the exact fixed-cap
`DfaStates`/`BuildWork` exhaustion that prevented direct participation, the
pinned stock capture profile, and one stable executable fallback marker. The
marker is part of the independent final-binary inventory and trap set even
though it is not an FRE runtime symbol. Only a normal run with that marker
armed and untriggered authenticates a native negative certificate.

The controller requires identical runner/object hashes and normalized
provenance from both builds. It inventories local, global, weak, and imported
executable runtime-symbol references in the final binary independently of
`required_runtime_symbols`, while separately requiring each claimed operation
entry to be defined text and every route-bound program identity to be defined
data. Every executable `fre_aot_regex_runtime_*` symbol
except the explicit prepare/destroy control plane is a semantic helper and is
armed. Provenance-declared helpers must be a subset of this independent
inventory.

Three fresh processes authenticate each job:

1. The unmodified `--quiet` runner must exit zero after its independent Rust
   oracle comparison.
2. When semantic helpers or a declared conditional stock-fallback marker
   exist, a copy with every such symbol armed must still exit zero. The marker
   records every image-relative patch offset and before/after instruction
   bytes. Repeated exact offset strings within one marker retain their closed
   symbol order and count: the first record at an offset must authenticate
   non-trap original bytes, while every later record at that exact offset must
   observe the trap bytes installed by the first record. This is sequential
   patch evidence for the closed marker, not a general cross-image identity
   claim based on equal numeric offsets. A trap in the first record, a second
   set of non-trap bytes, or a non-canonical offset is rejected. An
   independently empty final-binary helper inventory is itself the
   closed proof surface and does not manufacture a trap phase. For the mixed
   selector-capture route, reaching the stock fallback trap makes that job
   nonnative without compromising its stock-oracle correctness result.
3. A fresh copy for each selected operation entry must exit with the dedicated
   trap status and name that exact entry. For `count` this is the reducer; for
   bulk `count-spans` it is Span-fill; for direct `count-spans` and `grep` it is
   the ordinary entry. Composite v3 provenance is normalized into a closed
   component list whose every `component_N_native` claim is true. Scalar
   prepared `grep` traps its native Span-fill entry. A mixed row bridge traps
   each ordinary search entry or prepared exclusive-search entry; its
   Span-fill and serialized program remain independently inventoried closure
   evidence rather than substituted operation entries.
   `regex-redux` must publish exactly 15 component entries,
   per-component runtime-symbol lists, and program/object hashes; the
   controller runs 15 independent negative controls so a trap in the first
   stage cannot stand in for proof that the other 14 entries execute.
   The variable-width native-row bridge and uniform-capture row bridge receive
   the same independent negative control for every retained row artifact. The
   exact-span participation v4 runs two independent negative controls: one for
   its ordinary selector and one for its participation replay. A positive job
   is not credited merely because the selector ran while the replay remained
   unexercised. Selector-capture-fallback v4 traps its sole selector entry and
   separately arms the positive-fallback marker in phase 2. Strict-capture v4
   instead traps its sole `capture_next` component entry;
   patching the ordinary selector or materializer is not accepted as evidence
   that the timed capture iterator executed. These routes are reported as
   native search or search/capture cores with an adapter outer loop. The uniform
   route uses `uniform-capture-row-bridge-v1` and
   `linked-uniform-capture-row-adapter-loop`; strict capture uses
   `strict-capture-next-v1` and `linked-strict-capture-next-adapter-loop`.
   Neither inflates the stricter wholly fused-operation numerator.

Thus a `RuntimeHelper` route fails phase 2. A mixed
`*WithRuntimeHelper` artifact is judged at the requested operation boundary:
an unused helper is harmless, while any helper actually reached by the job is
nonnative. The same rule applies to prepared V15 objects: their selected native
loop receives credit only if every linked compatibility helper is armed and
remains untriggered for the complete public job. The uniform multiplier receipt is not capture replay or capture
materialization: stock Rust captures remain the correctness comparator, while
only the helper-free native Span selection core is credited here.

If a job cannot reach qualification, seal it rather than deleting it:

```sh
python3 tools/aot-rebar-runner/census/true_native_census.py record-failure \
  --plan census-plan.json --job-id PUBLIC_FRE_JOB_ID \
  --stage build --outcome timeout \
  --output receipts/PUBLIC_FRE_JOB_ID.json
```

Optional precomputed `--evidence-sha256` and `--evidence-bytes` fields can bind
an external log without letting the controller open or retain it. No diagnostic
contents enter the receipt.

Finally, summarize the complete population:

```sh
python3 tools/aot-rebar-runner/census/true_native_census.py summarize \
  --plan census-plan.json --receipts receipts --output summary.json
```

The summary retains all 311 runtime job IDs, every numerator ID, hashes of each
ID set, per-job dispositions, and a receipt-manifest hash. It cannot report
100% while any runtime job is unsupported, failed, timed out, missing, helper
On read-back it revalidates the sealed source/schedule/job topology and derives
every classification from artifact, route, helper, and architecture-specific
trap evidence; stored classification booleans are never authoritative.
