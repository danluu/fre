# Production aggregate integration

Status as of 2026-07-14: the production `fre` facade construction-selects either
the exact-literal whole-operation reducer from `fre-kernels` or the bounded
`fre-aggregate` continuation program for one-pattern Rust-byte `count` and
`count-spans`. The integration is a correctness/coverage result, not a claim
that either path is faster than Rust regex or RE2 on every workload.

## Modular production boundary

The design keeps parsing, bounded compilation, operation admission, storage
strategy, facade policy, and Rebar reduction independently testable:

1. `fre-syntax` parses under a complete versioned Rust profile and returns the
   original source/cache identity plus HIR counters.
2. An allocation-free canonical-HIR inspection peels only direct root captures
   and proves exact-literal eligibility only when the remaining root is one
   `Literal` or `Empty` node. `fre-kernels::LiteralAggregatePlan` owns one
   needle and exposes distinct count/span-sum identities.
3. Ineligible HIR is validated and compiled by `fre-aggregate` into a
   prioritized continuation program with exact work, state, temporary-state,
   and retained program-capacity accounting.
4. Distinct facade types expose only one operation each:
   `AggregateSpansRegex`, `AggregateCountRegex`, and
   `AggregateSpanSumRegex`. Operation and storage strategy are fixed before
   compilation and included in reports/cache identity. Count and span-sum
   additionally expose value-only hot APIs; their audited result/report APIs
   remain unchanged.
5. The facade always runs aggregate operations on `0..haystack.len()`. Absolute
   anchors therefore retain original-haystack context; it never implements
   global iteration by repeatedly searching sliced suffixes.
6. `CurrentFreAdapter` compiles exactly once and executes exactly once for an
   admitted one-pattern `count` or `count-spans` job. Unsupported models and
   build-many are rejected before candidate compilation. Existing portable
   single-search/grep routing is unchanged.

`AggregatePlanSelection::{Auto,ForceExactLiteral,ForceContinuation}` makes the
plan seam testable. `Auto` publishes an eligible literal build refusal instead
of falling through; a selected execution refusal never invokes the other plan.
Exact-literal reports contain no continuation strategy label.

## Capture and profile contract

The default `CompiledRegex::from_hir` remains capture-rejecting. The explicit
`from_hir_erasing_captures_for_whole_match` entry point treats a capture node's
child transparently inside the existing bounded validation/lowering
traversals. It does not clone the HIR or allocate a capture-free copy.

Compiler accounting records both unique annotations erased and transparent
capture-node traversal work. The facade exposes that mode only through
whole-match spans/count/span-sum types; no capture group value or history is
available. Capture-equivalent source patterns may share a semantic program ID,
but their syntax keys and complete cache identities remain distinct.

For an exact literal, only root capture nodes are peeled and charged; any other
canonical root is ineligible. Capture-equivalent exact sources share the
operation/plan identity but retain distinct source/cache identities.

The production aggregate boundary is Rust bytes with Unicode disabled. Unicode
`true` is a typed refusal before parsing even for an empty or ASCII-only
pattern. Case-insensitive mode is admitted when Rust syntax lowering produces
an HIR inside the byte subset. No profile is inferred from an ASCII-looking
HIR.

## Whole-operation resource contract

Every selected plan retains a no-partial-output contract:

- `ExactLiteral` uses one `memmem::Finder::find_iter` traversal for a nonempty
  needle and a checked `N + 1` byte-boundary formula for an empty needle.
  Count and span sum are separate stable operation identities.

- `FullTable` materializes one endpoint word per `(boundary, state)`.
- `ReverseSequentialRows` retains two state rows and a fixed split/root record
  per boundary, written in reverse and replayed through a forward-only logical
  reader.

`AggregateCountRegex::count_value` and
`AggregateSpanSumRegex::span_sum_value` share the exact selected-engine
execution functions used by `count` and `span_sum`. They therefore perform the
same operation-specific preflight, enforce the same limits, and never fall
back. A successful value-only call returns `u64` before execution-report/cache
identity construction and does not clone the source-key `Arc`; failures retain
the normal typed `AggregateExecutionError` and complete identity. The audited
APIs still construct and return their complete reports.

Compiler work, execution work, output/match events, table cells,
random-access/scratch/log/sequential/output/peak bytes, span sum, allocation
capacity, program identity, operation identity, strategy, profile, source,
build limits, and execution limits are present in typed reports, errors, or
cache identity. A resource refusal never triggers the other strategy.

Literal construction separately accounts needle bytes, preprocessing work,
temporary allocation capacity, selected-kernel persistent bytes, and
selected-kernel construction peak. Literal execution accounts linear terms,
possible events/count/span sum, reducer steps, scratch, and selected-kernel
peak. The reported retained capacity is narrowly the selected engine's storage;
it does not include the facade's source/`Arc<CacheKey>` allocation or the
parser/HIR peak, so it is not an end-to-end compiler-memory claim.

The Rebar adapter fixes `ReverseSequentialRows` for continuation programs. It
maps every literal planner/build/reducer quota and constructs every
continuation `AggregateOperationLimits` field explicitly from authenticated
input, selected-plan accounting, the reducer limit, and named `RunLimits`
quotas. It grants zero continuation table cells. Resource and
unsupported-feature refusals become `unsupported` receipts; arithmetic,
allocation, and invariant failures become `fault`. The current full report
contains no FRE fault.

## Qualification evidence

Facade integration tests compare spans, count, and span sum with pinned
`regex::bytes` under both strategies for empty/nullable repetition, greedy and
lazy priority, late fallback, captures, invalid bytes, case-insensitive ASCII,
and anchors. Separate tests establish:

- exact compile-limit success and one-below refusal with captures;
- fixed strategy and operation identities, full-haystack certificate ranges,
  retained program capacity, and execution accounting;
- Unicode-on refusal for both empty and ASCII patterns;
- capture-equivalent program IDs but distinct source/cache identities;
- no execution fallback after a one-below storage refusal; and
- unchanged portable single-search plan selection.

Forced exact/continuation differentials additionally cover empty needles,
overlap, invalid bytes, nested captures, canonical eligibility, distinct
count/span-sum identities, and every nonzero literal construction/execution
quota at its exact value and one below. The same cases exercise the value-only
APIs under `Auto`, forced exact, and forced continuation selection. Dedicated
checks prove value/audited parity, typed identity/source parity at one-below
resource limits, and unchanged source-key `Arc` strong counts on successful
hot calls for both selected engines.

The two Rebar reverse-suffix bug cases have stronger independent evidence. A
hand-built, fuel-bounded `fre-reference` AST interpreter shares no parser, HIR,
planner, or executor with production and selects one span `0..4` for both
patterns on `zabb`. Both aggregate strategies return count 1. Pinned Rust
1.12.4 returns 2 through its unsound optimization; exact receipts deliberately
retain those Rust failures while FRE passes the canonical definitions.

The exact Rebar report now contains:

- FRE: 144 pass, 200 unsupported, 0 fail, 0 fault;
- aggregate contribution: 48/133 `count` and 89/129 `count-spans` pass;
- executed plan labels: 24 exact literal, 113 continuation, 7 portable grep;
- pinned Rust: 342 pass, two retained reverse-suffix failures; and
- pinned RE2: 285/285 pass.

All admitted quadratic/no-quadratic adversaries pass. Of the 125 remaining
aggregate refusals, 78 require Unicode, five require ordered build-many, 14
require assertions outside the current subset, and 28 cross explicit compile
or execution quotas. Exact IDs and reasons are in
`../rebar/comparison/report.json` and `../rebar/comparison/COVERAGE_FRONTIER.md`.

Two complete report generations were byte-identical. Report SHA-256:
`6a9e599ef7b3e2edeeec42dbad208e4a10f206a321f8f36e76bff3871f26b336`;
receipts SHA-256:
`23b072ac9cbcd6798bf76eaa39ffc7d45aea26115036f18dd2c185566f40f3d4`.

Five fresh local timing processes cover all 24 exact-literal rows at the full
public facade boundary. Median-of-five-process medians classify 10 jobs as FRE
wins, 13 as losses, and one as an integer-nanosecond tie. Six are repeatable
5/5 wins and seven are repeatable 0/5 losses; many others are near noise. Tiny
inputs expose a clear fixed report/`Arc` cost. Raw samples, environment,
binary/report hashes, the aggregation rule, and the explicit boundary are
retained in `../performance/literal-aggregate-rebar/README.md`.

A separate five-process corpus measures the value-only boundary over the same
authenticated 24 receipts without modifying or replacing that full-report
evidence. Median-of-five-process medians classify 12 wins and 12 losses; seven
are 5/5 wins and five are 0/5 losses. The smallest FRE operations fall from
roughly 33--34 ns to 16--17 ns, but still lose to Rust at 10--13 ns. Because
the executor and scan kernel are identical, long-input changes between the two
independent batches are noise rather than a scan improvement. Both corpora
reject a strict faster-everywhere or performance-promotion claim.

## Remaining promotion gates

1. Reduce the remaining value-only call/preflight fixed cost and test
   differentiated substring kernels. Keep both the value-only and audited
   result/report boundaries explicit in measurement. The current wrapper
   around a shared class of SIMD primitive cannot establish strict
   superiority.
2. Add Unicode byte-mode lowering and the missing assertion semantics with
   independent differentials.
3. Add ordered build-many and capture-history operation families instead of
   widening whole-match erasure beyond its proof boundary.
4. Keep compile-model verification and AOT/JIT timing work visible; never hide
   compilation or fallback work outside the measured contract.
5. Preserve the general continuation plan as the bounded semantic backstop,
   while improving its constants or replacing it only at a typed plan boundary.
