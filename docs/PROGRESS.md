# FRE implementation progress

This is the live implementation ledger for the active goal. Design-stage
claims are not implementation results.

Correctness, resource, benchmark, JIT, and API blockers are tracked separately
in [`RISK_REGISTER.md`](RISK_REGISTER.md); a milestone checkbox never overrides
an open P0 row.

## Current milestone: bounded fast-plan portfolio

- [x] Architecture and adversarial review corpus completed.
- [x] Long-running implementation goal created.
- [x] Root Rust workspace, pinned toolchain, formatting, lint, and release
  profiles established.
- [x] `fre-reference`: independent, fuel-bounded byte-semantics oracle for the
  first capture/priority/iteration subset.
- [x] `fre-syntax`: versioned Rust and RE2 profile identities, bounded Rust HIR
  admission, and the direct pinned RE2 AST integrated without claiming program
  construction admission.
- [x] `fre-automata`: bounded table-structured K0 search floor for capture-free
  byte NFAs, plus fixed-capacity reusable scratch with separate setup and
  transition accounting.
- [x] `rebar-manifest`: deterministic 3,859-job runner inventory and audited
  Rust-regex/RE2 adapter metadata, with exact target-job execution retained in
  the separate comparison report.
- [x] `fre-lower`: checked Rust HIR-to-K0 lowering for the certified subset,
  with explicit refusal of nullable/unknown-minimum unbounded loops.
- [x] `fre-conformance`: canonical cross-layer records, deterministic generated
  cases, persisted replay seeds, and explicit unsupported/refused outcomes.
- [x] `fre`: an honest subset facade with checked finite-language planning,
  exact-literal, packed ordered-literal, DFA, and K0 forced plans, and no
  search-time fallback after plan selection.
- [x] `fre-kernels`: bounded exact-literal and ordered finite-literal plans over
  pinned native/SIMD-aware primitives, with forced small differentials and
  separate build/search accounting.
- [x] `fre-simd-kernels`: exact 16/32-byte runtime-dispatched byte-set
  classification now includes an independently forceable AVX-512F/BW/VL YMM
  leaf, exact receipts and fallback-lattice tests. Generic dispatch retains
  AVX2 preference pending the mandatory provider-neutral native qualification
  described in
  [`SIMD_X86_AVX512_QUALIFICATION.md`](SIMD_X86_AVX512_QUALIFICATION.md).
- [x] Proof-restricted required-literal production plan: exact HIR extraction,
  distinct cache/accounting identity, no search fallback, 590,220 forced
  operation comparisons and retained positive/negative release evidence.
- [x] Proof-restricted forward anchored class-plus-suffix plan: exact HIR
  extraction, direct and native-prefilter executors, checked rescan accounting,
  1,534,572 forced operation comparisons, and retained wins and losses.
- [x] Exact-literal whole-operation reducer: one bounded non-overlapping
  `memmem` traversal (or checked empty-byte-boundary formula), 232,050 forced
  count/span-sum comparisons, exact limits, and retained release wins/losses.
- [x] `fre-iterator-lab`: an exact capture-free Strategy A and independent
  guarded cross-check agree with 168,120 complete upstream sequences; the
  production integration and capture extension remain open.
- [x] `fre-re2-syntax`: iterative source-mapped RE2 parser plus an initial
  pinned C++ oracle slice (45 constructor records and seven match spans).
- [x] `rebar-expand`: all 629 target jobs, 3,039 pattern blobs, source recipes,
  adapter identities, and static timing/model contracts materialized exactly.
- [x] `rebar-compare`: 973 deterministic receipts over all 629 target jobs;
  RE2 passes 285/285, the exact Rust adapter passes 342/344 with two reproduced
  reverse-suffix optimizer failures, and the current operation-typed FRE
  facade passes 144/344 while retaining 200 explicit unsupported outcomes and
  no failure or fault.
- [x] `fre-capture-lab`: two bounded submatch-history formulations agree on the
  isolated corpus. Production capture-sensitive aggregate integration remains
  open and the repeated-search lab iterator is explicitly non-production.
- [x] `fre-kernel-ir`: validated structured exact-literal and proved
  class-plus-suffix kernels, deterministic identity, bounded portable oracle,
  malformed-program rejection, and backend contract.
- [x] `fre-jit-aarch64`: bounded immutable AAPCS64 images, typed relocations,
  deterministic AOT identity, independent decoder/auditor, exact branch and
  resource boundaries, and 455,916 decoded-machine/oracle comparisons.
- [x] `fre-jit-x86_64`: bounded immutable SysV images, scalar/SSE2/AVX2
  confirmation tiers, typed relocations, deterministic AOT, independent audit,
  and 276,309 bounded scalar/SSE external instruction executions. AVX2 actual
  execution remains explicitly open.
- [x] `fre-aot-compiler`: source-authenticated custom direct-machine-code
  emission into deterministic Mach-O or ELF objects, with typed
  source/KIR/native/object receipts and no LLVM regex-codegen dependency. The
  Linux `SelectedEnd` P2b slice packages the same sealed tag-21 ABI2 image as
  JIT, adds exact hidden direct-call glue/declarations/receipts, and has no
  function-pointer API, `x4` result pointer, or result slot. Compiler output
  remains inert: runtime authority and post-link observation are absent.
- [x] `fre-aggregate`: production capture-free zero/progress compilation for
  arbitrary nested finite/open repetition, forced full-table and reverse-row
  whole-operation strategies, exact resource accounting, and 242,910 complete
  sequence differentials. Operation-typed count/span-sum facade and exact Rebar
  integration are complete; capture syntax is erased only for whole-match
  outputs with explicit traversal/work accounting.
- [x] Deterministic Unicode scalar-run aggregate candidate: canonical root
  `CLASS+` and `CLASS+?` count/span reducers use one scalar traversal, retain
  greediness in executable identity, charge at most `N+1` run transitions,
  use zero dynamic scratch, and preserve forced continuation and neighboring
  routes.
- [x] `fre-jit-runtime`: strict-W^X AArch64 publication now has a separate
  `SelectedEnd` register-return ABI2 type for V8 and tag 21. Publication
  exposes no direct call; invocation is session-only. V8 opens a session
  without an SVE syscall, while Linux tag 21 observes the calling thread's SVE
  vector length once at session creation and requires VL16. The explicit
  16-byte `QualifiedExactSearch` large-window/reuse leaf remains a Candidate:
  all four current qualification atoms are `Candidate`, legacy V7 is hard
  `Candidate`, and no current Search JIT leaf is performance-qualified.
- [x] `fre-jit-cache`: bounded typed single-flight publication, deterministic
  eviction, exact live mapping/code/data accounting across leases, forced
  retirement-race recovery, and O(1) allocation-free image identity access;
  36 focused emitter/runtime/cache tests pass on host AArch64.
- [x] `fre-capi`: versioned C11 records/symbols and a move-only nonthrowing
  C++17 wrapper for the current Rust-bytes single-search subset. Nine Rust
  tests plus debug/release exact-symbol and C/C++ compile/link/run smokes pass;
  every unimplemented profile/operation feature bit remains off.
- [x] `fre-holdout`: frozen visible non-Rebar v1 correctness gate with canonical
  cross-architecture digest framing, 1,014 deterministic receipts, strict
  fail/fault gating, and byte-identical reruns (1,014 pass, zero unsupported,
  zero fail/fault). Timing remains separate and non-normative.
- [ ] Root workspace builds, tests, formats, and lints cleanly.

Every completed package has passed its focused tests and strict Clippy/rustdoc
gate. The exact normal-test total will be regenerated at the next stable
whole-workspace integration point instead of retaining the obsolete 138-test
count while two native backend crates are changing concurrently.

## Active ownership

| Track | Owned paths | Current objective |
|---|---|---|
| Primary/integration | root manifests, `.cargo/`, `docs/` | Keep interfaces coherent; integrate, measure, and continuously test. |
| Aggregate value API/Rebar | `crates/fre/`, `tools/rebar-compare/`, `research/rebar/comparison/`, `research/aggregate/`, `research/performance/literal-aggregate-rebar/` | Remove report construction from explicitly value-only calls, then retain pointwise Rebar timing wins and losses. |
| Continuation assertions | `crates/fre-aggregate/` plus assertion evidence | Add exact ASCII word-boundary and LF-anchor predicates to both bounded aggregate strategies, with absolute-haystack range semantics. |
| Native aggregate JIT | `crates/fre-kernel-ir/`, `crates/fre-jit-aarch64/`, `crates/fre-jit-runtime/`, `crates/fre-jit-cache/`, `crates/fre-jit/`, `research/jit/native-aggregate/` | Give exact-literal count/span-sum a typed one-call native ABI and compare it against per-match JIT and portable reducers. |

Completed crates are unowned between integration points and may be changed only
after their public contracts and tests are rechecked.

## Implemented boundary and open gaps

The current public search path is deliberately small. `PortableRegex` admits a
bounded capture-free Rust-bytes subset. A two-pass checked planner can enumerate
finite literal languages (including bounded byte/Unicode classes) without
exceeding logical peak word/byte or work caps, then select exact substring,
packed leftmost-first SIMD, proof-restricted required-literal or forward
anchored class-plus-suffix, bounded DFA, or immutable CSR/SoA K0 execution. It
exposes typed exists, selected-end, span, and windowed operations. The standalone
`fre-aggregate` crate computes exact complete non-overlapping sequences and
reducers without repeated suffix searches; count and span-sum are exposed by
operation-typed facade plans and the exact Rebar semantic adapter. General
match-sequence exposure remains separate. Pattern-specialized AArch64 code can
be published under a strict audited W^X lifecycle through the explicit
qualified-search API, but every V8/tag-21 ABI2 call requires a same-thread
session and no default portable facade selects it. There is still no capture
API, general Unicode execution, qualified `SelectedEnd` AOT authority, or
compatibility-qualified embedding surface. The P2b source-first AOT compiler
and deterministic object/glue/receipt bundle are implemented as inert source;
they provide neither a post-link observation nor a runtime adopter. The
retained Search V1 adopter/default-off binding is a different ABI and cannot
authorize P2b. A small implemented C11/C++17 surface exists for the current
portable subset and reports `UPSTREAM_ORACLE_PENDING` in every plan record.

Seven-process diagnostic medians put exact literals and packed literal
alternation at parity within noise; the retained literal-set DFA cross-check is
4.42x slower. The promoted theorem-gated required-literal plan wins by
2.18--3.93x on positive, adversarial, multibyte and end-anchored rows, while
the negative row is parity/slightly slower and start-only/forced-both anchors
lose by about 1.53--1.54x. The distinct forward anchored plan closes the former
K0 cliff on its proved shape: on the recorded Apple AArch64 diagnostic it takes
about 4.10 us for a 64 KiB anchored span versus 14.53 us for Rust regex and
870.99 us for the prior K0 route. It still loses short-exists and arbitrary
class rows (about 1.25x and 1.12--1.17x respectively), and 30/32 paired
no-boundary processes are only a narrow win. All rows remain diagnostic rather
than qualification evidence and every losing row is retained.

The broad Rebar inventory still retains 2,769 unavailable jobs as literal
`ERROR` records instead of hiding them. The exact target expander materializes
629 Rust-regex/RE2 jobs and 3,039 transformed pattern blobs. The semantic gate
now contains 973 receipts: 285/285 RE2 passes, 342 Rust passes plus two retained
reverse-suffix optimizer failures reproduced through Rebar's own adapter, and
144 FRE passes plus 200 explicit unsupported outcomes with no FRE failure or
fault. Two full generations were byte-identical; the report SHA-256 is
`6a9e599ef7b3e2edeeec42dbad208e4a10f206a321f8f36e76bff3871f26b336`.
The two Rust failures retain expected count 1 and actual count 2, while an
independent fuel-bounded reference interpreter and both FRE aggregate
strategies select the canonical single span `0..4`. This closes
semantic-runner and initial aggregate-facade uncertainty, not performance or
broad FRE coverage; `research/rebar/comparison/COVERAGE_FRONTIER.md` lists the
remaining operation and syntax gaps. No Rebar job selects the required-literal
plan, so its outside-Rebar evidence is not a corpus-tuned shortcut.

The frozen visible non-Rebar v1 suite authenticates 19 specifications, 169
expanded inputs, and 1,014 comparisons with a canonical tagged-`u64` digest.
Two independent local executions were byte-identical at 1,014 pass, zero
unsupported, zero fail, and zero fault, with receipt SHA-256
`8f6a1c803f3ffb2e0dd64aecb71b46682f1dda095715abab5bf9a1e77e92104a`.
It covers both hot-reuse and one-shot boundaries and machine-visible future
dimensions, but is not blind, is not a performance qualification, and still
requires x86-64 execution and the declared broader APIs.

The distinct exact-literal aggregate kernel agrees with pinned Rust regex on
232,050 exhaustive reducers and makes one whole-haystack traversal without an
operation allocation or suffix restart. On the authenticated Sherlock
representative, five-process medians are 22.07 us versus 23.63 us for count and
21.88 us versus 23.67 us for span sum. Dense/overlap/empty rows improve more,
but a 64 KiB negative span-sum row is retained as a 0.033% loss. This is a
forced-kernel screening result, not facade routing or Rebar qualification.

The exact-literal plan is now selected by the operation-typed facade for 24
authenticated Rebar receipts, including 16.0 MiB Twain, 7.4 MiB Folly inputs,
long needles, and invalid bytes. Five fresh-process measurements at the full
public result/report boundary produce 10 wins, 13 losses, and one integer-ns
tie against pinned Rust regex. Text-heavy wins reach about 1.20--1.91x, while
four tiny inputs lose 1.6--3.3x because each successful call constructs and
drops a complete execution report and clones its shared syntax key. Explicit
value-only count and span-sum calls now retain the same selected plan, preflight,
limits, typed failures, and no-fallback contract while skipping successful
report/cache-identity construction and the shared-key clone. Five authenticated
processes over the same 24 jobs produce 12 wins and 12 losses from the
median-of-process medians; tiny FRE calls fall to about 16--17 ns but remain
behind Rust at 10--13 ns. The scan executor is unchanged, all five stable
losers are retained, and the plan remains semantically promoted but not
performance-qualified.

Ordered finite literal languages now have a distinct whole-operation research
portfolio. A reverse byte-class-compressed AC DFA plus initial/progressed DP
ring performs exactly `N` transitions and `N+1` reducer positions, including
ordered duplicates, prefixes, invalid bytes, and empty-match suppression; all
44 `fre-kernels` tests pass. On the joint `[a^(N/2)b,a]` adversary it scales
approximately 2x when both dimensions double, while restarted Rust and AC
iterators scale about 4x. It is nevertheless 10--22x slower on ordinary sparse
or Sherlock text. A separately theorem-capped packed leaf retains three
campaigns, including one negative count result and sparse losses; its internal
third-party construction allocations are infallible. Thus the reverse plan is
a correctness/resource floor and the packed leaf remains research-only, with
neither integrated into facade selection.

The first actual-hardware native bakeoff retains a complete unoptimized
baseline on the Apple M5 Max: 90 fixed cells, five fresh processes per cell,
4,500 synthetic timing rows, and 20 authenticated Sherlock rows. Hot direct
JIT calls win 16 cells, lose 71, and integer-nanosecond-tie three against Rust
regex; they win six, lose 82, and tie two against the existing shared kernels.
Authenticated Sherlock count is about 18.5x behind Rust regex and 20.1x behind
the exact-literal aggregate kernel. The decoded images expose the causes:
short literals use no SIMD, exact scanning filters only the first byte before
full confirmation, and class-plus-suffix scans class membership bytewise. This
baseline falsifies the current code shapes as production speed plans while
providing a reproducible target for theorem-preserving replacements.

The bounded replacement first added a 16-start SIMD literal candidate filter
and lazy first/last-position intersection. A later theorem-gated suffix-first
kernel handles unanchored singleton `CLASS+SUFFIX` only when the validated
suffix-leading byte is outside the class and the suffix is at most 32 bytes.
Its full five-process matrix wins 33, loses 50, and ties seven cells against
Rust regex, and wins 30, loses 57, and ties three against the shared kernels.
It improves 83/90 cells versus the original JIT with no regression, and all 45
changed class cells improve; versus the prior retained JIT, 73 improve, seven
regress, and ten tie. Authenticated Sherlock remains about 10.8x behind Rust
because it is an exact-literal 513-call loop, not the optimized class shape.
All 107 reference-relative losses are retained. Repeated naive confirmation
remains capped at 32 bytes; larger shapes require a proved-linear Two-Way or
automaton plan.

Historical Search V7 evidence from exact Q commit
`88e9c22c4ac382531bc1026ca0e25587905f5206` retained a complete 90-cell main
run, the 54-cell alternating adversarial run, the targeted 30-process retry,
frozen semantic replay, and independent execution/evidence review. That
historical source recorded 60/60 facade gates below the portable kernel
(maximum ratio `0.939701493`), all 18 adversarial gates at maximum
`0.152542373`, and the targeted gate at `0.971576447`. Its direct child bound
external canonical bundle SHA-256
`de084ff0564acdb89889f28b9dcfddce9b6f0955a1b2aead30d75770039e0453`.
Those results and that historical atom are non-authoritative for this composed
tree: legacy V7 is hard `Candidate`, all four current qualification atoms are
`Candidate`, and no Search JIT execution or speed promotion is current.

The current native tracks remain direct machine code, not LLVM regex
compilation. FRE's typed KIR and custom AArch64 emitters produce the regex
payloads; LLVM may only support `rustc`/host tooling, and the system linker can
only package already-emitted bytes. V8 and tag 21 now share the `SelectedEnd`
register-return ABI2 in JIT; tag-21 P2b AOT retains the same sealed image in a
deterministic ELF/direct-hidden-glue bundle. P2b still has
`RuntimeAuthority::Absent`, no completed post-link observation, and no
callable adopter.

The public JIT bakeoff source has moved to 48-column V3 session/value-call
rows. Its evidence verifier now requires an external ABI2 artifact witness and
binds the V8 policy, target, ABI, and no-VL facts instead of trusting a
self-consistent row rewrite. No V3 execution result is claimed here. The
checked-in three-engine harness still targets Search V1 Span; a replacement
P2b AOT/JIT/portable benchmark is in progress and deferred until its direct
call is observed after link and a private adopter exists. No current
correctness, lifecycle, benchmark, AOT promotion, or speed claim follows from
this source checkpoint.

## Non-negotiable gates

1. No compatibility claim while required API rows are planned or excluded
   without documentation.
2. No production algorithm without a checked work/memory bound and forced-plan
   differential tests.
3. No final compatible aggregate iterator using quadratic repeated search.
4. No speed claim from mismatched Rebar semantics, omitted failures, caches,
   or deferred work outside timing.
5. No optimization promotion without correctness, resource, cold/hot, code
   size, and frozen-holdout evidence.

## Monitoring cadence

At each integration point:

1. inspect active-agent status and redirect stalled/overlapping work;
2. run formatting, workspace tests, all-feature checks, and Clippy;
3. update this ledger with concrete results and known gaps;
4. choose the next independent tracks from the critical path;
5. keep the goal active unless all release gates pass or the same external
   blocker has been independently confirmed across three goal turns.
