# General AOT public Rebar runner

This is a distinct, job-specialized Rebar engine for the general
`fre-aot-regex` compiler. It does not replace or rename
`tools/rebar-compare/examples/fre_rebar_runner.rs`, which measures the public
portable FRE facade.

The checked-in build script consumes one public Rebar KLV file. Scalar models
compile and link one single-pattern general-AOT artifact. The fixed
`regex-redux` model has no external patterns; it compiles and links the exact
15 public Rebar stage patterns as independent ordinary Span artifacts. The
additive multi-pattern `count`/`count-spans` route compiles an ordinary
Optimizing+Span object for each distinct source row and links the deduplicated
helper-free native objects. A build with no KLV remains a harmless
unconfigured workspace binary.

```sh
rebar klv --max-iters 9 --max-warmup-iters 1 \
  --max-time 1s --max-warmup-time 100ms \
  curated/01-literal/sherlock-en > /tmp/fre-aot-public.klv

FRE_AOT_REBAR_KLV=/tmp/fre-aot-public.klv \
  FRE_AOT_REBAR_SOURCE_COMMIT="$(git rev-parse HEAD)" \
  FRE_AOT_REBAR_SOURCE_TREE="$(git rev-parse 'HEAD^{tree}')" \
  CARGO_TARGET_DIR=/tmp/fre-aot-rebar-target \
  cargo build --release -p fre-aot-rebar-runner

/tmp/fre-aot-rebar-target/release/fre-aot-rebar-runner \
  < /tmp/fre-aot-public.klv
```

`FRE_AOT_REBAR_FEATURES` optionally names the exact target facts made available
to lowering (`sse2,avx2`, `asimd`, and so on). It defaults to `none`; the
receipt never infers host features silently.

Formal runs also set `FRE_AOT_REBAR_SOURCE_COMMIT` and
`FRE_AOT_REBAR_SOURCE_TREE` to the exact clean HEAD under test. Development
builds remain possible without them but report `unbound-development` and are
not admissible evidence.

## Operation contract

The adapter supports the public `count`, `count-spans`, and `grep` models for
one pattern, ordered multi-pattern `count` and `count-spans`, and the
zero-external-pattern `regex-redux` model. Dispatch depends only on the typed
model and pattern cardinality, not on a benchmark name. It deliberately rejects
`compile`: emitting a relocatable object is not the Rebar operation of
constructing a regex that is ready to search. Object-emission timing belongs to
a separately named compiler-stage benchmark.

- Count calls the artifact's identity-suffixed prepared Count symbol exactly
  once per timed sample.
- `count-spans` obtains every non-overlapping `{start,end}` record from the
  identity-suffixed linked optimizing object and sums `end-start` in the
  runner with checked per-record bounds, ordering, and arithmetic. Every
  warmup or timed operation resets its iterator state. Runtime-backed and
  retained-row objects repeatedly refill a 64-record stack buffer through
  their generated stateful Span-fill entry until it reports exhaustion;
  fully direct objects repeatedly call their native ordinary entry over
  absolute full-haystack windows. Both routes implement Rebar's byte-wise
  empty-match progress and adjacent-empty suppression. The compiler may still
  emit an unused `SpanSum` export to provision the shared prepared
  program/handle, but that scalar export is not called by this model.
- grep iterates every LF/CRLF line domain and invokes the linked artifact's
  ordinary public search entry exactly once per line, counting the lines whose
  call reports a match. The prepared whole-haystack `GrepCount` export may be
  linked to provision the shared program/handle, but is never called by the
  timed Rebar grep operation.
- `regex-redux` runs the pinned flatten expression, all nine variant counts,
  and all five ordered substitutions through their separately linked ordinary
  Span entries. Rust owns only checked stage sequencing, replacement copies,
  and scalar accounting. Every stage must return an in-window nonempty Span;
  invalid, backward, empty, or non-success results fail the complete sample.
  This is an AOT runtime-execution boundary, not a claim that precompiled
  object construction is timing-equivalent to Rebar's per-call compilation.

For a multi-pattern scalar job, exact duplicate source rows are compiled once;
distinct source spellings that produce the same complete entry/object are also
linked once. The retained artifacts remain ordered by their first source
ordinal. On every iterator window the runner calls every row's ordinary native
Span entry, validates every result (including losing rows), selects the lowest
match start, and uses the lowest source ordinal to break a start tie. The
winning row's own leftmost-first endpoint is authoritative. The outer iterator
then applies the same byte-wise empty progress and adjacent-empty suppression
as pinned `regex-automata::meta::Regex::build_many`. Count and SpanSum stay in
local checked state and are published only after the complete traversal.

This bridge has no prepared handle, serialized runtime program, scalar helper,
or input-dependent deoptimization edge. Build-time admission rejects the
entire job when any row has an unresolved runtime function, a helper-backed
receipt, a prepared entry/program, a missing/zero-sized public native entry, or
any prepared aggregate state. It also rejects more than 4,096 source rows or
more than 256 MiB of distinct row objects before linking. These are explicit
fail-closed resource limits; the bridge never mixes native rows with a portable
semantic fallback.

One exclusive handle is prepared from the exact linked program before every
warmup/timed loop and destroyed after all samples. Handle preparation,
result comparison, and destruction are outside every measured duration. The
compiler receipt selects the preparation ABI without consulting a benchmark
name. Incumbent objects use the unchanged 64-byte V2 config. An object whose
explicit receipt requires `OrderedNfaV15` uses the additive 112-byte V3 config,
sets that exact required-capability bit, and must publish its authenticated
exclusive Pike scratch transactionally; preparation failure cannot silently
enter the compatibility helper path.

The `fre.aot.rebar-runner.v2` provenance record separates the compiler's real
aggregate strategy from the physical `count-spans` iteration route and binds
`prepare_config_version`, `required_prepare_capabilities`, and every V3 cap.
For a V2 object the Ordered-NFA handle, scratch, and setup-work cap fields are
zero (not applicable). For a required V3 object they are the actual generic
defaults used to construct the config: 8 MiB whole handle, 8 MiB scratch, and
2,000,000 setup-work units. `required_runtime_symbols` remains an honest link
surface: compatibility helpers may be unresolved even though a successfully
prepared required-V15 benchmark operation cannot invoke them.

The independent Rust oracle is deliberately constructed only after all AOT samples
so it cannot warm the candidate's first-call path. The normal output remains Rebar's
`nanoseconds,value` format. `--provenance` emits the adapter, compiler and
optimizer versions, target/features, engine/aggregate strategy, exact symbols,
required runtime surface, and program/object SHA-256 identities.

## Qualification before using results

1. Run every statically eligible public single-pattern row against the pinned
   Rust 1.12.4 Rebar runner and require exact values for both first-call
   (`max-warmup-iters=0`) and steady (`max-warmup-iters>0`) schedules.
2. Retain explicit nullable/empty-match, empty-haystack, invalid-byte, CRLF,
   lone-CR, trailing-LF and no-final-LF fixtures.
3. Run the linked ABI tests in `fre-aot-regex`, including wrong-artifact
   rejection before source access and transactional scalar output.
4. Rebuild every admitted artifact twice and require identical program,
   object, symbol and receipt identities.
5. Compare paired fresh-process operation samples against both Rust and the
   former repeated-search/per-line adapters. Report the recorded
   `PreparedAggregateStrategy`; do not call a runtime-helper row native.

The four public rows that returned linked status 3 in the dd6 report are a
mandatory named diagnostic, not exclusions that can count as success:

```sh
cargo build -p fre-aot-regex-runtime --lib
FRE_REBAR_BIN=/absolute/rebar \
FRE_REBAR_BENCH_DIR=/absolute/rebar/benchmarks \
  cargo test -p fre-aot-rebar-runner \
  --test public_dd6_status3 \
  public_dd6_status3_exclusions_pass_first_and_steady_on_current_main \
  -- --ignored --exact --nocapture
```

That diagnostic compiles and statically links current-main artifacts for
`curated/03-date/unicode`,
`hyperscan/fixed-length-words-unicode-nosom`,
`unicode/codepoints/letters-lower-or-upper`, and `wild/url/search`. Each exact
public haystack must return status zero and the Rust-oracle value on both the
first and second call through one exclusive handle. The matrix covers both the
base target and the executable host SIMD tier (explicit ASIMD on AArch64, AVX2
when the x86-64 host reports it), prints every selected aggregate strategy, and
accepts only exact oracle-correct results. It rejects an empty runtime archive
or one older than the current runtime/compiler dependency sources, so an old
manually built `.a` cannot silently qualify a row.

This diagnostic is a correctness gate, not a performance-green claim. The
current investigation has not completed its full matrix: a development
`wild/url/search` run exceeded 13 minutes and remains a bounded performance
HOLD. A separate release `curated/10-bounded-repeat/letters-ru` Count check
measured the existing AOT `RuntimeHelper` at about 576.7 ms per call versus
about 0.692 ms for the standard portable FRE route. Consequently, a
`RuntimeHelper` receipt is not treated as proof of portable performance, and
the experimental classifier that selected it is outside the correctness
landing.

An interrupted development run can resume one public row or one executable
host tier with `FRE_AOT_REBAR_BENCHMARK_FILTER=<exact-name>` and
`FRE_AOT_REBAR_TARGET_FILTER=base|asimd|avx2`. With neither variable set, the
mandatory default remains the complete four-row, base-plus-SIMD correctness
matrix.

Capture replay, RegexSet all-ID publication and future `MatchStats` remain
separate typed extensions. They must not be emulated by benchmark-name
recognition or silently folded into these contracts. The native-row bridge
implements Rebar's ordered `build_many` single-match stream; it is not an
all-matching RegexSet and does not claim a shared-scan automaton. Regex-redux is
admitted only by its typed zero-pattern model and exact fixed public stage
table; it is not recognized by benchmark name.

For native-coverage evidence, a linked regex-redux component is native only
when an independent binary audit finds no semantic runtime-helper edge, the
complete operation still succeeds after all semantic helpers are trap-patched,
and patching that component's claimed entry traps a fixture that reaches it.
The v3 provenance record publishes component-indexed entry symbols, runtime
symbol surfaces and program/object hashes. Merely linking all 15 objects does
not count helper-backed components as native.

## HEAD campaign reporting

The source-only [public true-native census control](census/README.md) keeps the
canonical 311-job runtime denominator distinct from raw comparator/boundary
schedule points and authenticates runtime routing with comprehensive helper
traps plus claimed-entry negative controls. It performs no timing.

A complete rerun treats the runner's successful sample output and nonzero
process/build outcomes as raw observations; it does not prefilter the report to
wins. The published table must retain every scheduled point as exactly one of
executed, unsupported, compile failure, link failure, or runtime failure.
Status 3 is a runtime failure. Coverage totals and speed summaries are
separate, and failures/unsupported rows never enter the speed denominator.

For each executed operation point, publish the benchmark name, model, first or
steady boundary, Count/SpanSum/GrepCount strategy, compile cost, all raw paired
samples, and both AOT/Rust and AOT/current-FRE-runtime ratios wherever those
reference arms are available. Publish pointwise rows before any family or
overall geomean; a geomean cannot conceal a regression. The source commit/tree,
object/program identities and exact adapter label from `--provenance` bind a
HEAD campaign and prevent dd6 samples from being reused as current evidence.
