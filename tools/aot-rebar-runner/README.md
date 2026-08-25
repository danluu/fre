# General AOT public Rebar runner

This is a distinct, job-specialized Rebar engine for the general
`fre-aot-regex` compiler. It does not replace or rename
`tools/rebar-compare/examples/fre_rebar_runner.rs`, which measures the public
portable FRE facade.

The checked-in build script consumes one public Rebar KLV file. Scalar models
compile and link one single-pattern general-AOT artifact. The fixed
`regex-redux` model has no external patterns; it compiles and links the exact
15 public Rebar stage patterns as independent ordinary Span artifacts plus
one helper-free whole-operation reducer object. The reducer owns flattening,
all exhaustive count/substitution traversals, replacement copies, receipt and
report publication, and calls only those 15 direct entries. The
additive multi-pattern `count`/`count-spans`/`grep` route compiles an
Optimizing+Span object for each distinct source row and links the deduplicated
native objects. Each row is either an ordinary helper-free native entry or,
only when that exact ordinary incumbent reports the typed Ordered-NFA need, an
independently authenticated V15 prepared native search entry. A build with
no KLV remains a harmless unconfigured workspace binary.
For multi-pattern `grep`, the row table additionally selects a native wrapper
that owns the complete LF/CRLF line traversal, calls and validates every
distinct row on every line, and publishes the checked line count
transactionally. An all-ordinary table retains the legacy helper-free ABI; a
mixed table uses a distinct one-slot-per-row handle ABI. Only the wrapper's
typed object-byte cap decline retains the exact pre-existing Rust line/row
adapter.

A configured build has two validation modes. With both
`FRE_AOT_REBAR_EXPECTED_VALUE` and `FRE_AOT_REBAR_EXPECTED_COMPARATOR` absent,
the existing pinned Rust oracle remains authoritative; provenance marks this
mode `stock-rust-unsealed-v1`, and the formal census rejects it. With both set,
the build requires canonical unsigned decimal plus one safe versioned
comparator identifier, then seals them together with the SHA-256 of the exact
standard Rebar KLV. Runtime requires that byte-for-byte KLV and authenticates
the combined binding before preparing or invoking the artifact. In this
`frozen-public-schedule-v1` mode the sealed expected value is authoritative;
the pinned Rust run is retained as a structured, report-only diagnostic.
Setting only one variable, malformed metadata, a changed KLV, or a tampered or
missing digest fails closed. This is one general input contract with no
benchmark-name or pattern exception. Later references to a stock-authoritative
oracle describe the backwards-compatible unsealed mode.

`count-captures` and `grep-captures` have an additional all-or-nothing route.
The compiler proves from the same canonical HIR that every nonempty match has
one uniform group-zero-inclusive participation count. For an exact one-pattern
job, a generated reducer then owns the complete match traversal (and, for
`grep-captures`, the LF/CRLF line traversal), multiplies the checked match count
by that proved participation count, and publishes one transactional result.
The helper-free `NativeFused` form is a strict whole-operation-native route;
the one-call `NativeOrderedNfaFused` form remains separately classified as
semantic-helper-backed. If the one-call reducer declines, the existing route
seals the same proof to the exact ordinary native Span selector. Rust selects
spans and adds the winning row's compile-time count; it does not materialize
capture offsets.
If that theorem specifically declines for an exact one-pattern job, the build
next tries an independently authenticated native exact-span participation
artifact. The ordinary Span selector remains authoritative for match choice;
one helper-free DFA export replays that selected span and proves its exact
participating group count. A selected participation artifact is then sealed
into a new helper-free reducer that owns the complete match traversal and, for
`grep-captures`, the exact `bstr::ByteSlice::lines` LF/CRLF domain. An
authenticated participation semantic negative may independently select the
strict `capture_next` source; that source is sealed into the same typed
whole-operation ABI with private receipt-sized iterator state and result slots.
The retained source route remains explicit in the final receipt. Parse,
lowering, allocation, unrelated resource, emission, arithmetic, finalization,
and authentication failures are terminal and are never converted into another
source route. The adapter permits one fixed numeric retry only after the exact
default participation DFA-state cap; that retry changes the state and
dependent construction-work ceilings and nothing else.
If that fixed retry itself exhausts exactly its `DfaStates` or `BuildWork`
ceiling for a one-source `grep-captures` operation, one final mixed adapter may
retain the helper-free ordinary Span selector already emitted by the uniform
transaction. Per LF-free line, a native `NO_MATCH` is an exact negative
certificate and returns zero without capture work. A native positive invokes
the pinned stock Rust capture implementation, preceded by the stable exported
marker `fre_aot_rebar_runner_stock_capture_positive_fallback_v1`. The marker is
an atomic side effect, remains visible under optimization, and makes every
used positive fallback nonnative to trap-based qualification. This adapter is
never selected for allocation, object, authentication, arithmetic, nonnumeric
resource, multi-source, or non-grep failures.

```sh
rebar klv --max-iters 9 --max-warmup-iters 1 \
  --max-time 1s --max-warmup-time 100ms \
  curated/01-literal/sherlock-en > /tmp/fre-aot-public.klv

FRE_AOT_REBAR_KLV=/tmp/fre-aot-public.klv \
  FRE_AOT_REBAR_EXPECTED_VALUE=123 \
  FRE_AOT_REBAR_EXPECTED_COMPARATOR=re2-2025-11-05 \
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

The adapter supports the public `count`, `count-spans`, `count-captures`,
`grep`, and `grep-captures` models, ordered multi-pattern scalar/capture
selection, and the zero-external-pattern `regex-redux` model. Dispatch depends
only on the typed model and pattern cardinality, not on a benchmark name. It
deliberately rejects `compile`: emitting a relocatable object is not the Rebar
operation of constructing a regex that is ready to search. Object-emission
timing belongs to a separately named compiler-stage benchmark.

- Count calls the artifact's identity-suffixed prepared Count symbol exactly
  once per timed sample.
- `count-spans` calls the identity-suffixed whole-operation `SpanSum` reducer
  once when the compile receipt selects exactly `NativeFused` or
  `NativeOrderedNfaFused`. The runner authenticates that strategy, operation,
  capability, and reducer symbol before session preparation or execution.
  Other receipts retain the checked adapter: runtime-backed objects refill a
  64-record stack buffer through their stateful Span-fill entry, while fully
  direct objects repeat the ordinary native entry over absolute full-haystack
  windows. Those adapter routes validate every span and implement Rebar's
  byte-wise empty-match progress and adjacent-empty suppression; they are
  reported as adapter loops rather than whole-operation-native execution.
- `grep` calls its identity-suffixed native `GrepCount` reducer
  exactly once per sample. That generated reducer owns Rebar's LF/CRLF line
  domain, including empty input, lone CR, trailing LF, and checked
  transactional `u64` publication, and calls only its authenticated
  object-local search. When an ordinary GrepCount incumbent needs the prepared
  Ordered-NFA V15 route, the runner first requests the closed scalar-operation
  surface: its sole global function is GrepCount, its search and capability
  gate are object-local, and it has no unresolved runtime functions. Only a
  typed unsupported, native-data-byte, or object-byte decline preserves the
  exact incumbent; allocation, lowering, emission, and authentication errors
  remain terminal. Multiple patterns first use one shared ordered automaton
  and one whole-operation reducer under the same closed authentication. On its
  typed decline, an all-ordinary table instead links one identity-suffixed
  helper-free reducer. It implements the same LF/CRLF
  line domain, invokes and validates every retained row even after a prior row
  matches, and stores its `u64` result only after all lines succeed. Its exact
  source map, row identities, relocations, code/object identities, and total
  object envelope are sealed at build time; runtime reauthenticates the source
  and artifact identities, and formal qualification rehashes every object. A
  A mixed ordinary/prepared table instead links a distinct five-argument
  reducer. Its authenticated one-slot-per-row handle table is passed once per
  operation, and the native wrapper invokes ordinary rows with the ordinary
  ABI and prepared rows with the exclusive-handle ABI. Prepared handles are
  constructed before warmup and timed loops. Only the final numeric reducer
  object-cap decline retains the older per-line/per-row adapter; allocator,
  lowering, emission, and authentication failures remain terminal.
- An exact one-pattern `count-captures` or `grep-captures` job first attempts
  one identity-suffixed uniform-capture reducer. The reducer owns the complete
  operation and returns a checked `u64` through the same exclusive-session
  scalar ABI as Count, SpanSum, and GrepCount. Runtime authentication binds the
  exact uniform-language proof, operation, aggregate strategy, reducer symbol,
  program/object identities, preparation caps, and dependency surface before
  the call. A helper-free `NativeFused` reducer has no Rust adapter loop and is
  admitted to the strict whole-operation-native census numerator. An ordered
  V15 operation-only reducer likewise enters that numerator only with
  `PreparedScalarReduceV1`, one COUNT child equal to the module entry, no bulk,
  SpanFill, prepared-search, or runtime-symbol surface, the exact V15 caps,
  and a distinct multiplier wrapper. The compatibility prepared-SpanFill
  reducer remains available only after a typed V15 unsupported, native-data,
  or object-byte decline and keeps its declared semantic helpers. Typed
  semantic or exact lower-work
  decline alone may continue into the pre-existing capture portfolio; parse,
  allocation, emission, authentication, and unrelated resource failures are
  terminal. The independent stock Rust captures oracle remains authoritative
  for the published benchmark value.
- A multi-pattern capture job also first attempts one shared reducer when every
  independently parsed source proves the same positive participation
  multiplier. The compiler binds source order, caller IDs, exact source bytes,
  Rust profile, every proof fact, the selected shared program and its
  pre-wrapper object into one composite proof identity. It then appends one
  Count/GrepCaptures wrapper to the full shared ordered-many Count portfolio.
  Only helper-free `NativeFused` or scalar-operation-only V15 closure is
  published: no SpanFill, runtime helper, or Rust row loop remains. When all
  sources still prove uniform participation, a typed shared-reducer decline
  next retains the independently authenticated ordinary Span rows and emits a
  separate helper-free weighted reducer. This covers unequal multipliers as
  well as an equal-multiplier shared representation, native-data, or object
  envelope decline. The reducer resolves leftmost/first-source priority,
  checked-adds each winning component's proved multiplier, and owns the whole
  CountCaptures or exact LF/CRLF GrepCaptures traversal in one call. Its
  receipt closes the source map, first ordinals, equal or unequal weights,
  component program/object hashes, reducer identities, and exact
  PLT32/Branch26 component relocations. Only its fixed numeric object-cap
  decline preserves the pre-existing Rust row adapter; allocation, arithmetic,
  lowering, object, and authentication failures are terminal.
- The final fallback `count-captures` route repeatedly invokes the helper-free Span row table and adds
  the selected row's proved group-zero-inclusive participation count with
  checked arithmetic. `grep-captures` restarts that complete Span iteration on
  every Rebar line domain. Every source must prove a positive minimum width and
  uniform participation; one nullable/nonuniform decline rejects the complete
  build. Runtime authentication rechecks proof versions, positive widths,
  source/row cardinalities, priority mapping, and automaton/program/object
  hashes. An independently constructed Rust captures oracle remains
  authoritative for the final value.
  After a uniform-proof decline, an exact one-pattern job may instead select a
  helper-free exact-span participation DFA. The final native reducer owns the
  selector iteration, exact-span replay, empty-match byte progress, checked
  accumulation, and transactional output. Its private participation scratch is
  exactly the receipt's 16 bytes and is never caller-owned. `grep-captures`
  performs LF splitting, strips one preceding CR, emits no line for empty input,
  and emits no extra line after a final LF inside that same native call.
  An authenticated participation semantic decline may select the stricter
  native `capture_next` source instead. Its final reducer owns private iterator
  state and the exact checked `group_count * slot_width` allocation, validates
  every participating slot internally, and publishes only the complete scalar.
  Both source routes expose zero runtime helpers and use the non-handle
  `fre_aot_regex_{count,grep}_captures_v1_<identity>` ABI exactly once per
  benchmark operation. The runner authenticates the final symbol hash, source
  and final object identities, operation/domain, route-private schema, and
  fixed object cap before dispatch. The independent stock Rust captures oracle
  remains authoritative for the final value.
  If the fixed direct-participation construction envelope is exhausted, the
  one-source grep-only selector-first adapter instead calls that exact native
  selector once per line. Negative lines are complete native certificates;
  only positive lines enter the declared stock capture fallback. The selector
  status/span is checked before fallback, stock remains authoritative for all
  positive captures, and the final independent Rust oracle remains
  authoritative for the operation. A runtime consistency receipt also
  requires zero marker calls whenever every timed result is zero, and at least
  one marker call whenever a positive result is published. This is an honest
  conditional mixed route, not a claim that positive capture materialization
  became native.
- `regex-redux` runs the pinned flatten expression, all nine variant counts,
  and all five ordered substitutions in exactly one call to the linked native
  reducer. Two `floor(3 * input_len / 2)` scratch buffers, the 1,024-byte report
  buffer, and the 144-byte receipt are allocated once outside warmup and timed
  loops. The reducer leaves final bytes in scratch B and transactionally
  publishes the canonical report and 18-word receipt only after every stage
  succeeds. Rust validates the sealed ABI and ranges around the call; after
  timing, the independent stock translation must reproduce every receipt
  field, every report byte, and every final byte exactly.

For a multi-pattern scalar job, exact duplicate source rows are compiled once;
distinct source spellings that produce the same complete route and object are
also linked once. The retained artifacts remain ordered by their first source
ordinal. On every iterator window the runner calls every row's ordinary or
prepared native search entry, validates every result
(including losing rows), selects the lowest match start, and uses the lowest
source ordinal to break a start tie. The winning row's own leftmost-first
endpoint is authoritative. The outer iterator then applies the same byte-wise
empty progress and adjacent-empty suppression as pinned
`regex-automata::meta::Regex::build_many`. Count and SpanSum stay in local
checked state and are published only after the complete traversal.

Multi-pattern Grep uses the same ordered, deduplicated row table but does not
apply the ordered-many match-selection reduction: only whether any row matches
each byte line is relevant. When every row is ordinary, its native reducer
owns that complete line/row loop in one call while still invoking every row so
a losing row's malformed status or span remains terminal. Its child relocation
closure is exactly the distinct row entries. Prepared V15 rows retain the old
semantics through a distinct five-argument reducer ABI: one authenticated table
slot per row is passed once, ordinary slots are null, and prepared slots hold
already-prepared exclusive handles. Handle lifecycle remains outside warmup
and samples. The only safe decline is the exact remaining `ObjectBytes`
ceiling after charging all row objects. Allocation, arithmetic, lowering,
emission, and authentication failures are terminal.

Count, SpanSum, and GrepCount first attempt an additive shared ordered-many
route for 2..=4,096 rows. That route independently parses every source,
preserves source order in one ordered-NFA program, and invokes one generated
whole-operation reducer per benchmark operation. GrepCount applies the shared
union once per LF/CRLF byte line instead of rescanning every independent row.
The exact combined raw plan first runs through the full ordinary optimizing
portfolio. An authenticated `NativeFused`
incumbent has zero required prepare capabilities and no unresolved relocation
from the selected reducer or unresolved runtime symbol anywhere in the object;
provenance names it
`linked-shared-ordered-many-helper-free-reducer`, and the census admits it to
the strict whole-operation-native numerator only after the ordinary oracle,
semantic-helper traps, and selected-entry trap all agree.

If the ordinary optimizer does not publish that exact helper-free reducer, the
same semantic plan may select the additive scalar-operation-only V15 route.
That object has `entry_abi=PreparedScalarReduceV1`: the sole global function is
the Count, SpanSum, or single-pattern GrepCount reducer, its search and
required-capability gate are local,
and its runtime-function surface is empty. A legacy or wrongly prepared handle
fails closed instead of entering a compatibility reducer. The older prepared
V15 search API and its entry/SpanFill/helper topology remain unchanged for row
and capture consumers. Typed V15 unsupported and byte-limit declines
retain the independent-row incumbent byte-for-byte; allocation, invariant,
emission, semantic-identity, and authentication failures remain terminal. An
ordinary program/object representation cap may consult that same reported V15
transaction, whose success, typed decline, or terminal error remains
authoritative.

The mixed bridge admits a prepared row only after exact receipt and linked
symbol authentication: Ordered-NFA engine, native loop strategy, V15
capability/config, entry/Span-fill/program identity, and the complete three
symbol runtime surface. Every other admitted row retains the strict ordinary
helper-free contract. The single-pattern selector preserves its ordinary
incumbent byte-for-byte on a safe typed V15 decline; a per-row V15 decline
rejects the complete multi-pattern bridge. Allocation, emission,
authentication, and unrelated resource errors are terminal. The bridge has no
scalar helper, portable semantic fallback, or input-dependent deoptimization
edge. It rejects more than 4,096 source rows or more than 256 MiB of distinct
row objects before linking.
The selector-first capture route remains the sole explicitly named conditional
stock-positive route; its positive fallback profile and trap marker are sealed
into generated bindings and provenance rather than hidden in a native row's
dependency surface.

One exclusive handle is prepared from each exact linked program before every
warmup/timed loop that needs it and destroyed after all samples; ordinary rows
retain an invalid sentinel and allocate no handle. Handle preparation, result
comparison, and destruction are outside every measured duration. The compiler
receipt selects the preparation ABI without consulting a benchmark name.
Incumbent single-object routes use the unchanged 64-byte V2 config. An object
or retained row whose explicit receipt requires `OrderedNfaV15` uses the
additive 112-byte V3 config, sets that exact required-capability bit, and must
publish its authenticated exclusive Pike scratch transactionally. Generated
receipts bind the handle, scratch, and setup-work ceilings checked by the
runtime adapter; preparation failure cannot silently enter a compatibility
helper path.

The `fre.aot.rebar-runner.v2` provenance record separates the compiler's real
aggregate strategy from the physical `count-spans` iteration route and binds
`entry_abi`, `prepare_config_version`, `required_prepare_capabilities`, and
every V3 cap.
For a V2 object the Ordered-NFA handle, scratch, and setup-work cap fields are
zero (not applicable). For a required V3 object they are the actual generic
defaults used to construct the config: 8 MiB whole handle, 8 MiB scratch, and
2,000,000 setup-work units. `required_runtime_symbols` remains an honest link
surface. Legacy V15 search objects report their compatibility helpers; a
scalar-operation-only V15 object must report an empty surface.

The independent Rust oracle is deliberately constructed only after all AOT
samples so it cannot warm the candidate's first-call path. It is fatal and
authoritative in the unsealed compatibility mode. A schedule runner may pass
its independently obtained selected-comparator scalar as
`--expected-value=<u64>`; a frozen build requires that argument to equal its
sealed value. In either schedule-authoritative mode, stock scalar,
availability, and regex-redux receipt differences are emitted on stderr as
`fre.aot.rebar-runner.stock-comparator.v1` records without replacing the sealed
or supplied answer. The expectation must never be derived from the candidate
itself. The normal output remains Rebar's `nanoseconds,value` format.
`--provenance` emits validation authority, sealed value/comparator, exact KLV
and combined-binding SHA-256 identities, stock divergence policy, adapter,
compiler and optimizer versions, target/features, engine/aggregate strategy,
exact symbols, required runtime surface, and program/object identities.
The mixed selector-first route uses schema `fre.aot.rebar-runner.v4` and also
publishes `selector_capture_fallback_bridge`, `capture_resolution`, the stock
positive-fallback profile/symbol, and the exact direct-participation resource,
required value, and limit that selected the route.
The helper-free nonuniform one-source reducer uses schema
`fre.aot.rebar-runner.v5`. It publishes one reducer operation entry plus the
retained participation or `capture_next` child closure as identity inventory,
keeps source-object and final-object hashes distinct, and seals the operation,
LF/CRLF domain, empty progress, private schema, reducer-symbol hash, fixed
object cap, and final artifact identity. Child entries are never counted as
benchmark operation entries.

## Qualification before using results

1. Freeze a scalar and versioned independent comparator for every public
   first-call (`max-warmup-iters=0`) and steady (`max-warmup-iters>0`) KLV
   before building. Set both expected env vars and require exact candidate
   agreement. The schedule runner may also pass that same scalar with
   `--expected-value=<u64>`; a mismatch with the frozen value fails closed.
   Also run pinned Rust 1.12.4 and retain every structured divergence; it
   cannot override the sealed schedule. Unsealed builds are
   development/compatibility runs and are ineligible for the formal census.
2. Retain explicit nullable/empty-match, empty-haystack, invalid-byte, CRLF,
   lone-CR, trailing-LF and no-final-LF fixtures.
3. Run the linked ABI tests in `fre-aot-regex`, including wrong-artifact
   rejection before source access and transactional scalar output.
4. Rebuild every admitted artifact twice and require identical program,
   object, symbol and receipt identities.
5. Compare paired fresh-process operation samples against the selected
   comparator, current FRE, and the former repeated-search/per-line adapters.
   Report the recorded
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

Exact one-source capture participation replay is the narrow typed route above;
general capture materialization, RegexSet all-ID publication and future
`MatchStats` remain separate typed extensions. They must not be emulated by
benchmark-name recognition or silently folded into these contracts. The
native-row bridge
implements Rebar's ordered `build_many` single-match stream; it is not an
all-matching RegexSet and does not claim a shared-scan automaton. Regex-redux is
admitted only by its typed zero-pattern model and exact fixed public stage
table; it is not recognized by benchmark name.

Multi-pattern `count` and `count-spans` first attempt the genuine shared
ordered-many compiler. If that compiler returns one of its typed declines, an
independent Span-row table may be sealed into one native row-scalar wrapper.
An all-ordinary table keeps the original three-argument ABI. A table containing
authenticated Ordered-NFA V15 rows uses the additive mixed ABI: it receives an
exact handle slot for every row once, requires ordinary slots to be null and
prepared slots to be non-null, and statically seals which child call ABI owns
each slot. Handle preparation and destruction remain outside warmup and timed
samples. The wrapper owns the complete ordered match loop, keeps the lowest
source row on equal starts, performs Rebar's byte-wise empty-match progress,
and transactionally publishes either a checked match count or checked
matched-byte sum. Only the wrapper's final numeric object cap retains the prior
checked Rust row adapter; allocation, lowering, emission, and authentication
failures remain terminal. The retained Rust adapter is also the differential
semantic oracle for the native wrapper.

Multi-pattern `grep` uses the same authenticated direct/prepared native rows,
restarts every selector for each Rebar byte-line, and reduces only whether any
row matched that line. An all-ordinary table selects
`native-independent-span-row-whole-grep-reducer-v1`, with one native wrapper
owning both loops. A table containing a prepared V15 row selects the distinct
`native-independent-mixed-prepared-span-row-whole-grep-reducer-v1` wrapper and
passes its authenticated handle table once. Every row is still called and
validated after a match, each matching line is counted once, and publication
remains transactional. Only the final numeric wrapper object-cap decline is
reported as the corresponding `per-line-native-independent-*` Rust adapter.
Neither route scans across a line boundary or substitutes one whole-haystack
match stream for Rebar's per-line model.

The build fails closed unless every linked regex-redux component has no
prepared program/entry and no semantic runtime-helper relocation, and unless
the reducer's unresolved link closure is exactly the 15 component entries.
Native coverage additionally requires an independent final-binary audit,
complete operation success after all semantic helpers are trap-patched, and a
trap when the claimed whole-operation reducer entry is patched.
The v3 provenance record publishes a separate native flag, entry symbol,
runtime-symbol surface, and program/object hash for every numbered regex-redux
component or retained native row. For regex-redux it additionally seals the
operation identity, reducer symbol/code/data/object digests, exact relocation
and component-link surfaces, empty semantic-helper surface, request/receipt/
report extents, scratch formula, and report/receipt schemas. The census counts
this route as whole-operation native only when the one reducer entry and all
of those closures authenticate.
For `native-row-scalar-reducer-v1`, v3 additionally seals the Count/SpanSum
operation, ordered-source digest and source-to-row map, every row receipt and
entry, the final wrapper symbol/code/object identities, its exact
architecture-specific call relocations, zero semantic runtime calls, and the
row-plus-wrapper object envelope. Mixed receipts additionally seal the exact
handle count and ordinary/prepared route vector under distinct operation,
artifact, and symbol domains. The census admits only the final wrapper as the
operation entry; child row entries remain identity-defined link targets. A
mixed wrapper is still classified as semantic-helper-backed because each V15
child retains its authenticated runtime-symbol surface, rather than being
misreported in the helper-free whole-operation numerator.
`native-multi-grep-reducer-v1` uses the same mixed route vector and handle-table
closure under its own Grep-specific operation, artifact, symbol, and ABI
domains. Its final reducer is one native operation call, but the census labels
the mixed form semantic-helper-backed because prepared children retain their
closed V15 runtime-helper surface.
Uniform-capture v3 row-adapter routes additionally publish `capture_resolution` as
`static-uniform-multiplier`, both proof-identity versions, every source's
multiplier/minimum/census/accounting, and the selector digests that bind it to
the retained row. They are reported separately from capture-materializing
engines and remain outside the strict wholly-native-operation numerator.
The v6 weighted-capture record carries those same per-source proofs but closes
them into one helper-free operation entry. It additionally seals source and
component priority, equal or unequal component weights, the LF terminator,
final reducer and artifact identities, fixed object cap, and every
architecture-specific child call relocation; the census therefore admits that
exact route to the strict whole-operation numerator.
The additive v4 strict-capture record instead binds the native `capture_next`,
materializer, and selector symbols plus the source, selector, capture program,
plan, bundle, object, and complete artifact identities. It reports
`capture_resolution=native-onepass-capture-next-v1`; stock Rust remains the
independent value oracle. Census qualification requires empty declared and
independently inventoried semantic runtime-symbol surfaces, and
trap-authenticates `capture_next` itself as the sole component entry. The route
counts as a native search/capture core with a checked Rust adapter loop, never
as a wholly fused native operation.
The mutually exclusive v4 participation record binds the source, selector,
capture program, sealed replay bundle, build-work extent, all three exported
symbols, and complete object/artifact identities. It reports
`capture_resolution=native-exact-span-participation-dfa-v1`, an empty semantic
runtime dependency surface, and the exact replay geometry. It has the same
native-core-with-checked-adapter classification and never claims a wholly fused
operation.

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
