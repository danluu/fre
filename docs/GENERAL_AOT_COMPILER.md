# General optimizing AOT regex compiler

`fre-aot-compiler::general` is FRE's source-independent AOT entry point. A
pattern reaches this compiler when, and only when, the pinned Rust syntax
frontend can lower its capture-free semantics to a validated prioritized
Thompson automaton within the caller's resource limits.

Invocation is currently explicit. Calling ordinary `fre::Regex` construction
does not silently run this slower compiler. A caller chooses the general API
below or the `compile_general_aot` example, and may therefore choose Fast or
Optimizing compilation as a policy decision.

There is no literal-width table, benchmark-name test, corpus identifier,
pattern hash allowlist, or source-string comparison in admission or plan
selection. Exact literals and class runs can still receive specialized code,
but only as graph-derived optimization outcomes after general admission.

## Invocation

```rust
use fre_aot_compiler::general::{
    compile, CompileMode, CompileRequest, OutputContract, Target,
};

let compiled = compile(
    CompileRequest::new(r"(?:[A-Za-z_][A-Za-z0-9_]*::)+item", Target::x86_64_linux())
        .output(OutputContract::Span)
        .mode(CompileMode::Optimizing),
)?;
std::fs::write("item.o", compiled.object())?;
```

`CompileMode::Fast` performs syntax lowering, validation, canonicalization, and
ordered-TNFA freezing. `CompileMode::Optimizing` may spend substantially more
time on complete ordered determinization, reverse-machine construction,
alphabet reduction, machine lowering, and object layout. Both modes accept the
same language and must return identical results. A resource limit can change
the selected engine or produce a typed refusal; it cannot make compiler
eligibility depend on a regex recipe.

Every source request enters the same parser, general nullable-repetition
lowerer, automaton validator, and artifact pipeline. The target-neutral engine
choice is:

| Request/graph condition | Engine | Receipt reason | Native object path |
|---|---|---|---|
| Fast mode, structurally eligible Span graph | ordered TNFA | `FastMode` | ordinary runtime adapter plus object-local native prepared Ordered-TNFA iterator |
| Fast mode, other output/structural refusal | ordered TNFA | `FastMode` | runtime adapter |
| Optimizing, assertion-free, determinization completes | ordered DFA | `CompleteDfa` | direct native loop |
| Optimizing, supported byte-local context assertions, contextual determinization completes | ordered contextual DFA | `CompleteContextDfa` | direct native loop |
| Optimizing, contextual determinization is unsupported or reaches a limit and Span is structurally eligible | ordered TNFA | `ContextAssertions` | ordinary runtime adapter plus object-local native prepared Ordered-TNFA iterator |
| Optimizing, state/transition/work/allocation limit reached and Span is structurally eligible | ordered TNFA | `DeterminizationResourceLimit` | ordinary runtime adapter plus object-local native prepared Ordered-TNFA iterator |

Every runtime-adapter object keeps the ordinary serialized-program entry for
ABI compatibility and also exports an additive exclusive-handle entry. A
consumer can prepare the object's exact exported runtime program once with
`fre_aot_regex_runtime_prepare_exclusive_v1`, reuse that handle for matching,
and destroy it with `fre_aot_regex_runtime_destroy_exclusive_v1`. On x86-64
and AArch64 the generated prepared entry is an ABI-preserving tail branch to
the versioned exclusive runtime helper, so program reconstruction and
workspace allocation stay outside steady-state matching. This applies to the
general runtime-adapter route, including contextual and resource declines; it
does not depend on a pattern recipe. The generated entry and that exact
exported program form an inseparable ABI pair; a handle prepared from another
program is outside the entry contract. The public runtime helper itself accepts
any live exclusive handle and does not infer which generated entry called it.

Syntax errors, hard lowering limits, and program/object byte limits are typed
compilation errors. Capture outputs are outside this capture-free API's
contract; grouping itself is erased and does not prevent compilation. These
conditions are not silent non-invocations. A determinization report retains
the requested and effective limits, attempted and completed stages, work and
machine dimensions reached, and the exact state, transition, work, or
allocation decline at the stage where it occurred.

The receipt records the semantic automaton digest, exact serialized-program
and object SHA-256 digests, target and feature facts, mode, output, selected
engine and reason, the ordinary and contextual determinization reports,
Thompson and DFA dimensions, executed passes, required runtime dependency,
configured line terminator, selected start accelerator, bounded graph-derived
prefix facts, actual emitted prefix-filter depth, and
program/code/data/object sizes. A contextual report contains either the
completed forward/reverse machine dimensions or the exact unsupported
assertion, state, transition, work, or allocation decline.
Optimizer identity 15 also covers the source-independent selected-workspace,
Span start-recovery tier policy, and explicit Ordered-TNFA publication policy
used by prepared entries. This
receipt identity is deliberately separate from stable serialized-program
bytes: program SHA-256 continues to bind the exact semantic wire payload, and
the workspace policy does not rewrite that payload.
Digests provide integrity only when compared with a trusted receipt. These
fields support a future owner that compiles on another thread and atomically
cuts matching over after validation. Background compilation and cutover policy
are runtime work, not compiler eligibility.

### Whole-haystack reducers

Count and matched-byte `SpanSum` are additive operations over a Span artifact;
they are not single-search output contracts. A caller opts into their object
entries explicitly:

```rust
use fre_aot_compiler::general::{
    compile_with_prepared_aggregate_exports, CompileMode, CompileRequest,
    OutputContract, PreparedAggregateExports, Target,
};

let compiled = compile_with_prepared_aggregate_exports(
    CompileRequest::new(r"[A-Za-z_][A-Za-z0-9_]*", Target::x86_64_linux())
        .output(OutputContract::Span)
        .mode(CompileMode::Optimizing),
    PreparedAggregateExports::ALL,
)?;
let count_entry = compiled
    .module()
    .prepared_count_symbol()
    .expect("requested Count entry");
```

The identity-suffixed Count and `SpanSum` entries accept one exclusive runtime
handle, a complete haystack pointer/length, and a writable `u64`. Status zero
publishes the complete value, including zero; every error leaves the output
untouched. Count follows the same non-overlapping Rust-byte iteration as
`regex::bytes::Regex::find_iter`. `SpanSum` adds each selected half-open match
width, so empty matches contribute zero while retaining byte-wise progress and
repeated-empty suppression.

The wrappers are available even when the main object is a fully direct DFA and
does not need a prepared-search entry. The handle is prepared from the exact
serialized Span program with `fre_aot_regex_runtime_prepare_exclusive_v1`.
When the module already has an unbounded native prepared Span loop or a
self-contained direct ordinary Span entry, Count and `SpanSum` keep the
complete iterator and scalar accumulator in one generated frame. They locally
call the exact artifact-specific prepared target or ordinary native entry and
publish the `u64` only after complete success. Runtime-adapter modules and
trusted-window Span loops whose large remainder requires a runtime bulk edge
retain the identity-authenticated whole-operation helper.
An eligible residual Ordered-TNFA Span module instead serializes a sealed
object-local SoA graph (plus the pinned Unicode-word range table only when it
is needed) and emits a table-driven prepared Pike iterator on both x86-64 and
AArch64. Its Count, `SpanSum`, and 64-record Span-fill wrappers classify the
handle exactly once before any output or iterator mutation. A V3 handle that
requires `OrderedNfaV15` must authenticate the graph, complete 664-byte header,
four scratch pointer mirrors, capacities, nonce, and artifact identity before
source access; it then calls only the private native iterator. An authenticated
legacy V1/V2 handle takes one whole-operation compatibility helper edge.
Any V15 marker makes the claim sticky, so malformed or revoked V15 state
returns status 3 and never falls back mid-loop.

`PreparedAggregateStrategy` distinguishes `NativeFused`, `RuntimeHelper`, the
exact `NativeFusedWithRuntimeHelper` case where GrepCount remains a helper, and
the two explicit `NativeOrderedNfaFused*` variants. The module and compile
receipt expose `required_prepare_capabilities`; a consumer uses prepare V3 with
the matching `OrderedNfaV15` bit only for those objects. Compile-time
structural/data/object-cap refusal rebuilds the incumbent module
transactionally. The unresolved compatibility symbols remain an honest link
surface even though a required-V15 aggregate/fill operation cannot invoke
them.

Both routes reject a handle prepared from another program before source access,
workspace mutation, or result publication. Aggregate symbol identities bind
the final appended code, data, symbols, and relocations; the compile receipt
also hashes the final object. Linkers can enumerate the exact undefined helper
surface with `CompiledModule::required_runtime_symbols`.

### Ordered multi-pattern programs

`fre-aot-regex::compile_ordered_many` is an additive target-neutral operation
for ordered Rust-byte pattern rows. It is deliberately not another
`OutputContract`: one ordinary search result cannot represent the selected
PatternID stream. It is also not RegexSet's all-matching-ID operation. At the
globally earliest start, source row order selects exactly one pattern; that
row's own leftmost-first endpoint remains authoritative. Caller PatternIDs are
payload only, so duplicate or out-of-order values never alter priority.

Each row first becomes a complete Span semantic program. Up to 128 rows may
then publish one shared owner-tagged selector. Owner-count, graph-shape, or
bounded tagged-cost refusals retain exact k-way selection over the independent
programs, including rows with zero-width cycles. Malformed graph/projection,
arithmetic, allocation, and internal tagged failures remain terminal compiler
errors instead of being hidden by that fallback.

`OrderedManyProgram::prepare_session` creates caller-owned storage for one
fixed source length before source access. Repeated `fill` calls reuse either
the tagged trace workspace or one semantic workspace per fallback row. A fill
always traverses to the exact selected-match total even after the output slice
is full, reports the written prefix and truncation separately, advances one
byte after an empty match, and suppresses an empty match immediately adjacent
to the preceding nonempty match. Zero source rows are a valid always-empty
program. This foundation does not yet claim a stable combined wire format or
native multi-row object ABI; those remain separate additive layers.

### All-matching regex sets

`fre_aot_regex::compile_regex_set` is the separate all-matching-ID operation.
After pinned whole-set admission, every source row becomes an independent
Exists semantic program; there is no tagged-owner ceiling, duplicates retain
distinct source-index bits, and zero rows are valid. A prepared session owns
one authenticated workspace per row plus exactly `ceil(patterns / 64)` staging
words. Runs validate the set lineage, every row workspace, output shape,
resource limits, and the original-haystack search window before source access.
Only a complete successful run copies staging to the caller bitset, with all
unused tail bits zero. The stable [`CompiledProgram`] wire and
[`OutputContract`] remain unchanged. Row/staging limits and the compile graph
and program ceilings are the current resource envelope; exact aggregate
retained-workspace-byte accounting remains a future extension. See
[`AOT_REGEX_SET.md`](AOT_REGEX_SET.md) for the API and next-layer boundary.

## Semantic pipeline

```text
pinned Rust byte syntax
  -> capture-free HIR
  -> general nullable-repetition Thompson construction
  -> validated prioritized Thompson automaton
  -> canonical automaton digest
  -> bounded required-prefix analysis over the graph
  -> fast ordered-TNFA plan
       or
     optimizing ordered forward DFA + all-matches reverse DFA
       -> deterministic forward/reverse state minimization
       -> whole-machine alphabet-column coalescing
       or
     optimizing context-parameterized forward + reverse DFA
  -> target module
  -> ELF64LE or Mach-O 64 relocatable object
```

The forward DFA preserves Rust leftmost-first semantics. Ordered epsilon
closure stops at the first accept, thereby discarding lower-priority threads.
The accept becomes part of the DFA state as a pending-result mode; while it is
pending, lower-priority start states are not injected. Execution follows all
higher-priority survivors until they die, then commits the pending end.

Exact span recovery is deliberately a different construction. The reverse
machine ignores priority, starts from every accept, and scans backward from the
selected end. It retains the earliest start that can reach the original
forward start state. Reusing forward priority in the reverse machine is
incorrect and is covered by differential tests.

Alphabet classes are derived from all byte-range endpoints in the automaton.
They reduce every transition row without inspecting the source pattern.
Complete determinization is bounded by explicit state, transition, and work
limits. Program and object byte limits are enforced at their later artifact
stages. A determinization limit or fallible-storage decline selects the
universal ordered-TNFA engine rather than a pattern-specific portable escape.

`DeterminizeLimits::unlimited()` means the maximum supported by the stable,
canonically replayable artifact contract, not unbounded process work. Its
public ceiling is `MAX_STABLE_DFA_BUILD_WORK` (500,000,000 charged
operations); requested values above the stable state, transition, or work
ceilings remain visible in the receipt alongside the effective values.
Graph-sized optimizer storage uses fallible reservations, so allocation
failure is another recorded optimization decline rather than a process abort.

The optimizer performs deterministic partition refinement over complete
forward and reverse machines, including observable result flags and the dead
transition sentinel. It canonically renumbers the quotient from initial state
zero, then coalesces columns that are equivalent across the entire minimized
machine. Output specialization removes the reverse machine unless exact spans
need it. Native lowering strength-reduces row addressing to retained absolute
row offsets, specializes constants and outputs, assigns a fixed ABI-aware
register plan, resolves checked branch fixups, and lays out
position-independent code and immutable tables. These are implemented
self-contained passes; the compiler invokes no LLVM, assembler, C compiler,
linker, or subprocess.

The required-prefix analysis explores bounded epsilon closures from the
Thompson start and unions the byte ranges every surviving path can consume at
each of up to eight positions. The position sets are conservative necessary
conditions, not a reconstructed literal: correlations between alternatives
are intentionally discarded. Native lowering deterministically chooses the
most selective representable position by byte cardinality, interval cost, and
then offset. It scans that offset while retaining the semantic candidate-start
cursor, checks the remaining selective positions with compact membership
predicates, and enters the DFA only after those necessary conditions hold. A
failed candidate advances exactly one semantic start byte and returns to the
initial DFA state. Early acceptance, unknown graph structures, or the fixed
work ceiling disable this optional filter without changing semantics or
compiler eligibility. Context assertions are traversed conservatively; the
contextual lowering reuses only facts that remain valid at every boundary.

Context-sensitive patterns take a separate graph-general determinization
route. Boundary context (the adjacent byte classes plus absolute-haystack
edge facts) is part of each deterministic state key. Whole-haystack,
configured-line, CRLF-line, and ASCII word/start/end/half assertions can
therefore lower to a self-contained native contextual DFA. Unicode word
assertions currently produce a typed `UnsupportedAssertion` decline and keep
the universal ordered-TNFA runtime path. Contextual state/transition/work or
allocation limits behave the same way. Neither case skips general
compilation.

The contextual machine and its construction report are fresh-compilation
sidecars. Stable V2 program serialization intentionally remains unchanged and
stores the universal ordered-TNFA form. Deserializing and re-lowering such a
program therefore produces the runtime adapter; it cannot claim or recreate
the omitted contextual optimizer. A fresh receipt reports
`OrderedContextDfa`/`CompleteContextDfa`, while the restored artifact reports
only the ordered-NFA facts actually present on the wire.

## Targets and features

The target is an explicit pair, never inferred from the compiler host:

| Architecture | Linux | macOS |
|---|---:|---:|
| x86-64 | ELF64 | Mach-O 64 |
| AArch64 | ELF64 | Mach-O 64 |

The scalar ordered-DFA loop is the universal baseline. A graph-derived start
scanner uses the most selective representable required-prefix column when one
is available; otherwise it can use bytes whose initial transition is not a
nonaccepting self-loop. It skips only while execution remains in the initial
row with no pending result, and nullable patterns are excluded. A cost model
selects scalar, x86 SSE2, explicit AVX2, explicit AVX-512F+BW, Arm ASIMD, or
Linux Arm SVE/SVE2 lowering. Compact 256-bit membership predicates reject
false candidates against every other selective required-prefix position
before the full DFA. SSE2 and AVX2 retain their lane masks, select the first
hit directly, and unroll four no-hit vectors. ASIMD candidate sets of at most
four bytes batch four vectors into one 64-byte no-hit reduction; broader sets
retain the 16-byte loop. Base SVE scans graph-derived primary filters with a
vector-length-agnostic four-vector loop; SVE2 uses `MATCH` for exact byte
sets. A Linux object requesting both ASIMD and SVE contains graph-equivalent
primary scanners and uses `CNTB` to select ASIMD at a 16-byte runtime vector
length and scalable SVE above it. Unsupported SVE route shapes retain their
ASIMD or scalar fallback, and macOS never selects SVE because this backend has
no macOS SVE execution contract. Offset-aware vector and scalar bounds prevent
reads beyond the requested search window. No source spelling participates.

The feature model is a set rather than a "highest tier": SSE2, AVX2,
AVX-512F, AVX-512BW, and AVX-512VL are independent x86 facts; ASIMD, SVE, and
SVE2 are independent Arm facts. Validation still enforces architectural
dependencies: AVX-512BW and AVX-512VL require AVX-512F, and SVE2 requires SVE.
The emitted object executes selected feature instructions unconditionally. A
loader must dispatch only after checking CPU support and required OS
extended-state support. The current 64-byte scanner needs AVX-512F+BW, not VL.
AVX-512 is static-disassembly validated only because no available host exposes
it; there is no AVX-512 performance claim.

Each object keeps code and immutable program data in separate sections,
exports an identity-suffixed entry symbol, and carries only target-defined
position-independent relocations (x86 PC-relative or AArch64 page-relative
plus page-offset pairs). Entry identity binds the semantic program, complete
target/feature tuple, lowering version, code, data, relocations, and runtime
dependency. The object serializers consume a generic compiled module and
never inspect regex shapes.

## Runtime-backed programs

Direct byte-local and contextual DFA objects implement the five-argument C
search ABI entirely in native code and have no runtime-helper relocation.
Fast programs, unsupported or resource-declined assertion programs, and
ordinary determinization-resource fallbacks retain the universal ordered-TNFA
artifact and tail-call `fre_aot_regex_runtime_search_v1`.

The raw compatibility helper validates and owns the serialized program on each
call because a raw address is not a safe lifetime identity. Repeated callers
should instead use the stable prepared lifecycle:

```text
fre_aot_regex_runtime_prepare_v1
fre_aot_regex_runtime_search_prepared_v1
fre_aot_regex_runtime_destroy_prepared_v1
```

Preparation canonical-validates and owns the program and allocates its
workspace once. The source bytes may then be released. Opaque `u64` handles
reject stale and double-destroy use; searches are exclusive per handle and
different handles can execute concurrently. The checked-in
[`fre_aot_regex_runtime_v1.h`](../crates/fre-aot-regex-runtime/include/fre_aot_regex_runtime_v1.h)
and the identical `C_API_V1_HEADER` constant contain the C and C++
declarations. Runtime-backed objects export a target/code-bound global alias
over the exact serialized bytes. `CompiledModule::required_runtime_program`
returns that symbol and its length, so a linked consumer can pass the object
data directly to `prepare_v1`. Direct DFA modules without an additive
handle-based export return `None`; requesting Count or `SpanSum` adds the exact
serialized preparation blob even when ordinary search remains fully direct.

Exclusive runtime-handle callers that know their operation can instead use
`fre_aot_regex_runtime_prepare_exclusive_v2` with the fixed 64-byte
`FreAotRegexPrepareConfigV2`. Declared Search, Count, and SpanSum settle the
source-free K0 start-filter policy under an explicit work cap; declared
GrepCount eagerly allocates its fixed workspace under an explicit logical
fixed-store payload byte cap. That cap covers the three `u64` payload stores,
not their `Vec` owners or allocator overhead. Count and SpanSum require a Span
program. V1 preparation remains lazy, and undeclared V2 operations retain that
behavior while still honoring the V2 handle's GrepCount byte cap. These
guarantees cover runtime handle operations. A linked native-fused reducer may
also bind an object-specific descriptor on its first source call; that storage
is outside V2 and may allocate until a later object-aware preparation ABI
defines it. The additive declarations and exact layout assertions live in
[`fre_aot_regex_runtime_v2.h`](../crates/fre-aot-regex-runtime/include/fre_aot_regex_runtime_v2.h)
and `C_API_V2_HEADER`.

## Capture-preserving composition

`compile_captures` is an additive operation, not another `OutputContract`.
One parse transaction lowers the exact same canonical Rust-bytes HIR into an
ordinary capture-free `Span` selector and a separately stable
`CaptureProgramV1`. A composite receipt binds both semantic digests, line
semantics, and the complete `All` schema without changing either wire format.
Each artifact can be deserialized and authenticated independently; the
composite identity then rejects a selector/capture substitution.
`CaptureCompileLimits` exposes both the selector's ordinary limits and its
independent `selector_slow_aot` envelope; the latter is copied into the
capture receipt and passed unchanged to optimizing selector compilation.
Only a configured one-pass resource refusal or a proved non-one-pass graph can
select the History route. Allocation, arithmetic, malformed-program, and
invariant failures are terminal.

A caller-owned `CaptureSession` first derives the complete OnePass or History
workspace usage plus both result-array extents without allocation. It enforces
`max_capture_persistent_bytes` before preparing any retained workspace, then
allocates the selector, exact-capacity result arrays, and exactly one replay
route. A complete one-pass sidecar is used when its worst-case configured span
fits. Otherwise a fixed persistent-history workspace preallocates exact
capacities for three state frontiers, seen marks, the outer history-chunk
table, every history chunk, and raw capture slots for
`save_states * (max_window_bytes + 1)` nodes. Any allocator overcapacity is a
typed terminal allocation failure instead of an undercounted receipt.
Execution never switches routes after the selector starts and performs no
allocation. Group zero must equal the selected span. Every group pair is
validated before an infallible commit; errors leave the prior session result
unchanged. Unmatched groups use the typed `SIZE_MAX/SIZE_MAX` representation.

## Scope

The base selector language is the complete capture-free Rust-byte subset implemented
by `fre-lower`: empty expressions, byte literals and classes, Unicode scalar
classes lowered to UTF-8 paths, concatenation, ordered alternation, greedy and
lazy repetition, whole-haystack and line assertions, and ASCII/Unicode word
assertions. The additive capture operation preserves group zero and all
explicit numeric/named groups for the pinned high-level Rust-bytes profile.

This is not yet a complete RE2 frontend. Capture projections smaller than
`All` and a native capture-object ABI remain typed integration gaps rather
than special-case failures in the selector backend.

Current optimization gaps are direct native TNFA lowering, native Unicode-word
assertion handling, stable contextual-sidecar serialization, broader
required-substring analysis, correlated/vectorized prefix predicates,
compressed cache-aware DFA tables, and automatic multiversion CPU dispatch.
These are performance or integration gaps; they do not change which
capture-free patterns enter the general compiler.

## Generated evidence

The broad generated semantic audit currently covers 673 assertion-free
patterns and 1,098 generated byte haystacks. All 673 patterns compile, all 673
select the default optimizing DFA, and 5,060,960 valid windows agree across
Fast, Optimizing, reusable workspaces, serialized round trips, and the pinned
Rust regex oracle. The nullable-repetition refusal count is zero. A forced
limit matrix adds 37,660 fallback comparisons (20 DFA and 50 NFA compilation
variants). Malformed artifacts and inconsistent raw/DFA payloads are rejected.
The exact generator and cardinality assertions are checked in as
[`generated_semantic_audit.rs`](../crates/fre-aot-regex/tests/generated_semantic_audit.rs)
and run with:

```sh
cargo test -p fre-aot-regex --test generated_semantic_audit \
  --release -- --ignored --nocapture --test-threads=1
```

The checked-in deterministic benchmark generates 10 structural strata:
literal, class, concatenation, alternation, greedy and lazy repetition,
nullable repetition, Unicode, line assertions, and word assertions. It
publishes Fast/Optimizing compile time, engine route, machine dimensions,
required-prefix facts, program/code/data/object size, reusable portable
execution, and checked native execution. Assertion strata remain in the
denominator: supported byte-local assertions may select the direct contextual
DFA route, while Unicode-word or bounded construction declines remain on the
prepared ordered-NFA route.

The broader
[`generated_aot_performance_matrix`](../crates/fre-aot-regex/examples/generated_aot_performance_matrix.rs)
is distribution-oriented evidence rather than one-case-per-stratum evidence.
It crosses six graph shapes, three window sizes, four match positions, five
candidate densities, producing 360 paired cells, each validated over four
independently rotated generated haystacks. Fast and native results are
validated before timing; warmed trials report minimum and median absolute
latency and throughput, alongside a non-inlined C-ABI no-op floor. The raw
harness deliberately reports per-cell measurements rather than an aggregate.

A matched generated-only before/after run on one Apple M5 AArch64 macOS host
used ASIMD objects, 32-, 4,096-, and 65,536-byte windows, the four match
positions `none`, `start`, `middle`, and `end`, the five candidate densities
`zero`, `1_per_256`, `1_per_32`, `1_per_4`, and `dense`, and the six graph
shapes `literal_depth_3`, `literal_depth_6`, `small_class`, `range_pair`,
`sparse_pair`, and `branching_pair`. Each configuration used four rotations,
five timed trials after eight warm-up rounds, a 262,144-byte nominal trial
budget, and at least 1,024 searches. All 360 Fast/native pairs validated in
both runs.

The table summarizes the per-cell median ratio
`Fast ns/search / native ns/search`; a ratio above 1 means native is faster.
Percentiles use the lower ranked observation.

| Statistic across 360 paired cells | Initial-column scanner | Selective necessary-prefix-column scanner |
|---|---:|---:|
| Native regressions (ratio below 1) | 144 | 46 |
| Ratio below 0.75 | 125 | 8 |
| Ratio below 0.50 | 108 | 1 |
| Ratio below 0.25 | 97 | 0 |
| Minimum | 0.0052 | 0.4819 |
| p10 | 0.0157 | 0.9455 |
| p25 | 0.1000 | 1.2385 |
| Median | 2.1812 | 3.9488 |
| p75 | 9.6304 | 10.5229 |
| p90 | 13.8161 | 12.9106 |
| Geometric mean | 1.0012 | 3.6396 |

The remaining worst generated cell is `literal_depth_6` on a 65,536-byte
window with the match at the end and `1_per_256` candidate density: its ratio
is 0.4819, so native is about 2.1 times slower there. This distribution
supports the graph-derived column-selection change on that Apple ASIMD host;
it is not a performance claim for the other operating-system, architecture,
or feature combinations.

The same final source and exact matrix flags also ran on remote benchmark host x86-64
Linux with AVX2 and Graviton5 AArch64 Linux with ASIMD. Every host produced 360
valid Fast/native pairs with identical paired checksums. These figures remain
host-specific measurements, not hard compiler admission gates.

| Final generated matrix host | Minimum | Median | Geometric mean | Regressions | Below 0.75 | Below 0.50 |
|---|---:|---:|---:|---:|---:|---:|
| Apple M5, macOS AArch64, ASIMD | 0.482 | 3.949 | 3.640 | 46 | 8 | 1 |
| AMD EPYC Milan, x86-64 Linux, AVX2 | 0.555 | 3.548 | 3.999 | 76 | 38 | 0 |
| AWS Graviton5/Neoverse V3, AArch64 Linux, ASIMD | 0.533 | 4.458 | 3.827 | 69 | 8 | 0 |

Native all-window differential bundles execute on:

- Apple AArch64 macOS, scalar and ASIMD;
- x86-64 macOS under Rosetta, SSE2;
- remote benchmark host x86-64 Linux, scalar/SSE2 and AVX2;
- Graviton5 AArch64 Linux, scalar and ASIMD.

AVX-512F+BW one- and four-candidate objects are generated and disassembled to
their ZMM/k-mask loops, but are not executed. All development measurements use
generated inputs. The separate ripgrep workload is a sealed holdout and is not
consulted for optimization or for the evidence above.
