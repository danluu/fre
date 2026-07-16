# FRE implementation architecture

This document describes code that exists in the workspace. The broader target
architecture and release gates remain in `WORLD_FASTEST_REGEX_DESIGN.md`.

## Dependency and test boundaries

```text
fre-re2-syntax ──> fre-syntax                                  │
                       │                                       │
                       ├────────────> fre-kernels ──────────────┤
                       └─> fre-lower ──> fre-automata ──────────┼──> fre
      │              │              │                          │
      └──────────────┴──────────────┼──> fre-conformance       │
                                    │                          │
fre-reference (independent oracle) ─┘                          │
                                                               │
fre-iterator-lab       isolated aggregate-iteration research   │
  └─> fre-aggregate    production zero/progress graduation     │
fre-re2-syntax         isolated direct RE2 parser              │
fre-capture-lab        isolated submatch-history research       │
fre-kernel-ir          verified native-kernel contract/oracle  │
  ├─> fre-jit-aarch64  bounded immutable native images          │
  │     └─> fre-jit-runtime  guarded strict-W^X publication      │
  │             └─> fre-jit-cache  bounded typed mapping cache   │
  └─> fre-jit-x86_64   bounded immutable native images          │
fre-required-literal-lab  isolated proved fast-plan research    │
rebar tools            isolated qualification tooling ─────────┘ (receipts only)
fre ──> fre-capi       versioned C11 ABI and C++17 RAII wrapper
```

The independent oracle must not call syntax HIR lowering, production automata,
planning, or native code. Production executors must not turn oracle evaluation
into a fallback. Conformance adapters may depend on both sides, but no
production crate may depend on `fre-conformance` or `fre-reference`.

## Implemented layers

| Crate | Input | Output | Current proof/test responsibility |
|---|---|---|---|
| `fre-syntax` | pattern bytes, versioned compatibility profile, admission policy, hard safety envelope | canonical Rust HIR, direct RE2 AST, or RE2 literal plus resource summary and cache identity | parser/profile identity, bounded accounting, typed exact diagnostics, and explicit constructor-admission status |
| `fre-lower` | Rust HIR and operation semantics | raw or independently validated prioritized byte automaton | iterative checked construction, explicit feature refusal, parse-to-search differentials |
| `fre-automata` | CSR structure-of-arrays Thompson graph | typed exists, selected-end, or span report | structural validation, nonrecursive K0 execution, fixed reusable scratch, checked setup/transition work, priority/anchor tests |
| `fre-reference` | small direct semantic AST | exact small-case matches, captures, and global sequences | independent semantics and fuel/resource failures; never performance |
| `fre-conformance` | canonical cases and adapters | replayable differential records | cross-layer equality, unsupported classification, deterministic generation and minimization |
| `fre-iterator-lab` | restricted capture-free byte models | whole-operation candidate traces | prove/falsify exact bounded iteration; never silently become production |
| `fre-aggregate` | bounded canonical Rust byte HIR subset, with explicit whole-match capture erasure | complete non-overlapping spans and checked reducers | production zero/progress compiler, same-boundary DAG certificate, forced full-table/reverse-row strategies, exact limits, and 242,910 sequence differentials; operation-typed facade/Rebar integration preserves fixed strategy and accounting |
| `fre-kernels` | certified finite literals or proved `CLASS+ SUFFIX`, search range, and operation-typed aggregate plans | exact literal/ordered-set/required-literal/forward-anchored search plus exact, scalar-class/run, or ordered-literal whole-operation count/span sum | theorem-gated native primitives and forced resource/differential tests; the scalar-run reducer handles canonical greedy/lazy root `CLASS+` in one UTF-8 traversal with zero dynamic scratch; forward has 1,534,572 comparisons, exact aggregate 232,050, and ordered reverse AC/DP 31,218 exhaustive cases with exact `N` transitions; packed ordered search is explicitly research-only pending fallible owned construction |
| `fre` | profile, pattern, limits, haystack, and aggregate operation type | subset public matcher plus aggregate count/span-sum plans and reports | two-pass bounded search planning, operation-specific aggregate construction, charged whole-match capture erasure, honest plan/cache identity, forced parity, and no post-selection fallback |
| `fre-re2-syntax` | pinned RE2 pattern/options | checked typed RE2 AST or exact diagnostic | source-mapped iterative parser and pinned direct C++ oracle slice; program admission/lowering still open |
| `fre-capture-lab` | restricted tagged capture AST | two canonical capture traces | bounded independent history formulations and upstream differentials; its repeated aggregate search remains an oracle, not production |
| `fre-required-literal-lab` | proved `CLASS+ SUFFIX` byte shape | bounded candidate/confirmation plan | 196,740 direct span comparisons, window/limit proofs, and retained wins/losses; production required-literal and distinct forward-anchored promotions are separately forced and tested |
| `fre-kernel-ir` | proven fast-plan shape | validated structured kernel plus portable oracle result | deterministic identity, CFG/bounds validation, 728,420 differential/malformed cases, and normative ISA contract |
| `fre-jit-aarch64` | validated Kernel IR plus AAPCS64 target stamp | immutable code/rodata/relocation image and address-free AOT artifact | 455,916 decoded-machine differentials, independent authenticity audit, exact limits; executable publication remains separate |
| `fre-jit-x86_64` | validated Kernel IR plus SysV target stamp | immutable code/data/relocation image and address-free AOT artifact | 276,309 scalar/SSE external instruction executions, independent audit, exact limits; AVX2 and production publication remain open |
| `fre-jit-runtime` | audited AArch64 native image plus typed output contract | immutable reference-counted callable mapping | strict `PROT_NONE` to RW to RX lifecycle with guards, exact accounting, rollback and concurrency tests, and 663,084 actual-hardware/oracle comparisons; planner integration remains open |
| `fre-jit-cache` | immutable AArch64 image, typed output contract, fixed publication/cache limits | callable lease plus exact current/peak/event snapshot | same-key single-flight, different-key concurrency, deterministic LRU, unique-token retirement, outstanding-lease accounting, O(1) precomputed full-AOT identity, forced races/failures, and 14 cache tests; process-local only and no speed claim |
| `fre-capi` | caller-owned versioned C records and byte views | opaque retained matcher plus plan/exists/end/span results | ten ABI/lifetime/failure/plan-tag tests and debug/release exact-symbol C11/C++17 smokes; only the current Rust-bytes portable subset is advertised and admission remains upstream-oracle-pending |
| `fre-holdout` | authenticated frozen visible suite/schema/digests | deterministic correctness receipts plus separate diagnostic timing | 1,014 hot/one-shot operation comparisons, canonical cross-architecture framing, tamper/resource/fault gates, and byte-identical 1,014-pass/zero-unsupported/zero-failure reruns; not blind or performance qualification |
| `rebar-manifest` | retained canonical Rebar inventory | deterministic qualification manifest and summary | runner provenance/configuration; semantic and performance results are separate gates |
| `rebar-expand` | pinned Rebar definitions and source inputs | content-addressed expanded target jobs | exact static transformations/provenance; runtime receipts remain a later gate |
| `rebar-compare` | expanded jobs, pinned sources, exact adapters | deterministic semantic receipts | 973 receipts: RE2 285/285, Rust 342 plus two reproduced reverse-suffix optimizer failures, FRE 144 pass plus 200 explicit unsupported outcomes and no fail/fault; 24 exact-literal, 113 continuation-program, and seven portable candidate-selected routes; byte-identical reruns |

## Contracts between layers

1. Syntax identity includes upstream revision, Unicode version, every relevant
   facade option, admission policy, and hard safety envelope. Strict local
   parsing remains `UpstreamOraclePending` until the pinned constructor oracle
   agrees.
2. Lowering either emits an exact graph for the declared operation or returns a
   typed unsupported/resource error. Capture erasure is permitted only for a
   capture-free operation. Nullable unbounded repetition is currently rejected
   because ordinary generation dedup is not an adequate priority proof.
3. `fre-automata` validates all table dimensions and payloads before freezing a
   plan. One-shot calls report cold setup; reusable calls require a fixed-shape
   `K0Workspace`, allocate nothing, charge reset plus transition work, retain
   original-haystack assertion context, and recover cleanly after errors.
4. A plan is operation-typed. Exists, selected-end, span, capture, aggregate
   iteration, replacement, and set matching are distinct contracts even when a
   future planner shares an executor.
5. An optimization may be selected only after forced-plan comparison against
   the semantic oracle and K0, with its own checked compile/runtime/code bounds.
6. The facade reports which plan was selected. Finite-language extraction uses
   a shape/peak preflight before materialization and is restricted to exact
   literals, concatenation, ordered alternation, capture erasure, and bounded
   byte/Unicode classes. Plan ineligibility is resolved during construction; a
   selected-plan search failure is returned, never retried through a different
   engine.

## Adding a production engine

A new execution strategy belongs behind a typed canonical-plan contract. Its
crate must provide:

- a machine-checkable eligibility predicate and explicit refusal reasons;
- checked compile work, peak memory, persistent data, native code, and runtime
  work estimates;
- forced-plan entry points so differential tests cannot accidentally exercise
  a fallback;
- deterministic construction under a fixed profile and target stamp;
- exact result traces for every supported operation;
- adversarial, allocation-failure, boundary, and scaling tests;
- evidence on cold construction, first call, warm reuse, code size, and the
  frozen non-Rebar holdout before planner promotion.

Native JIT code also requires a verified relocation/branch target model,
W^X publication lifecycle, instruction-cache synchronization, target-feature
checks, bounded code-cache behavior, and parity tests against the Kernel IR and
K0. A native loop over regex bytecode is not accepted as JIT specialization.

## Qualification status language

Use these terms precisely:

- **implemented**: code exists and its local tests pass;
- **conformant**: the applicable pinned upstream differential suite passes;
- **bounded**: checked counters and scaling evidence support the declared bound;
- **qualified**: all required correctness, resource, platform, and benchmark
  gates pass on declared hardware;
- **fastest**: the complete pointwise Rebar and frozen-holdout speed gates pass.

At present only small components are implemented. The engine is neither fully
conformant nor qualified, and no speed-leadership claim has been made.
