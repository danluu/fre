# Forward anchored class/suffix kernel

This plan is motivated by retained production evidence, not a new syntax
normalization. Current `RequiredLiteral` loses about 1.53x on `\A C+ S` and its
forced both-anchor form loses about 1.54x; withholding both anchors routes to
K0 and loses 59.46x. The new plan must remain a distinct forced identity.

## Eligibility theorem

Admit exactly `\A CLASS+ SUFFIX` with optional absolute `\z`, after capture
erasure for capture-free outputs, when:

- `CLASS` and `SUFFIX` are nonempty;
- `SUFFIX[0]` is not a member of `CLASS`;
- every class member consumes exactly one byte under the selected byte profile.

An unbordered suffix is not required. Starting at absolute byte zero, any
successful match has one possible repetition boundary: the first byte not in
`CLASS`. Disjointness makes that boundary the only possible first suffix byte,
so no repetition backtracking or suffix-candidate overlap is involved. The
kernel scans the class prefix forward, requires at least one member, confirms
the fixed suffix at the boundary, and, for `\z`, checks the selected end against
the original haystack length. A restricted window that does not contain byte
zero has no match; assertions always retain original-haystack context.

This proof applies to greedy and lazy `+` because the suffix boundary is
unique, but initial production admission may keep greedy-only until a forced
differential explicitly covers lazy source semantics.

## Implementation portfolio

1. Safe scalar bitset membership is the correctness floor.
2. A single inclusive ASCII range gets a separate, inspectable loop that LLVM
   can vectorize; generated assembly and fixed-P/fixed-N scaling must confirm
   what was actually emitted.
3. The AArch64 JIT should lower arbitrary byte classes to a NEON nibble-table
   or equivalent proved membership mask and use the first non-member lane.
   Scalar class membership in generated code is not called SIMD merely because
   suffix confirmation is vectorized.
4. x86-64 tiers use SSSE3/AVX2 nibble lookup or range comparisons with exact
   feature stamps and scalar guarded tails.

No implementation may read before the start or beyond the checked window.
Every vector tail must be tested next to guard pages.

## Promotion gate

- Separate plan/cache/accounting identity. Runtime drivers obtain the exact ID
  from the selected plan instance and therefore report the same strategy
  identity used for cache keys; they do not reconstruct it from the plan-family
  tag.
- Exact build/search/code/work/scratch/persistent/peak bounds and one-below
  refusal tests; no allocation or fallback during search.
- Exhaustive exists/end/span/window differentials against pinned Rust regex,
  Kernel IR, and the existing required-literal forced plan where both apply.
- Arbitrary bytes, empty/one-byte prefixes, suffix mismatch, bordered suffixes,
  both anchor forms, invalid windows, and original-haystack assertion context.
- Release trials must retain all rows and beat both the current plan and Rust
  on the motivating start-only/both-anchor cases before default selection.
- JIT promotion additionally requires decoded and actual-hardware execution,
  guard pages, code size, cold/warm compile economics, Rebar and frozen-holdout
  evidence.

## Status

The portable forward candidate and its exact auto route are implemented and
qualified against FRE's previous correct routes. See `RESULTS.md` for exhaustive
differentials, retained release wins and losses, and the deliberately still-open
project-wide pointwise gate. See `ASSEMBLY.md` for exact partial-vectorization
evidence. Arbitrary-class SIMD JIT work remains unpromoted.

## Forced absolute-end fixed-boundary strategy

The separate forced-only strategy for `\A CLASS+ SUFFIX \z` has stable runtime
identity
`anchored-class-suffix.absolute-end-fixed-suffix-first-hybrid.v2`. Both
absolute anchors and the fixed literal width determine the only split:
`p = H.len() - SUFFIX.len()`. For a full original-haystack window and
`H.len() > SUFFIX.len()`, the verifier compares the final suffix first, then
visits `H[..p]` once through the inherited canonical inclusive-range,
Pair/Triple/Quad, or arbitrary-class bitset leaf. A block leaf conservatively
preflights its possible 32-byte failed-block rescan, so for `r = 32` when
`p >= 32` on a specialized leaf and `r = 0` otherwise, its certified suffix,
prefix, and total bounds are `M`, `p + r`, and `N + r`. It has no candidate
search, prefilter, scratch, search allocation, or fallback.

This path is selected only by `ForceForwardAnchored` when extraction proves an
absolute end. Forced start-only construction retains
`anchored-class-suffix.short72-forward-middle-equality5-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v5`, and `Auto`
retains its pre-existing strategy for both shapes. The direct legacy kernel
constructor is unchanged.

Extraction borrows the suffix from the parsed HIR and preserves its checked
planner-work charge. The selected fixed plan performs one preflighted exact
copy with `capacity == len`, stores one immutable plan, and accounts
`persistent = size_of::<AbsoluteEndFixedPlan>() + suffix capacity`, zero
scratch, and equal persistent/peak bytes. Every suffix, work, scratch,
persistent, and peak cap is checked before that copy. The optional cache-key
snapshot occurs after construction and is not construction scratch, a second
plan, or search allocation.

This source qualification makes no speed or promotion claim. Independent
hostile source acceptance, the fixed code-size bounds, and any later separately
authorized measurement remain mandatory.
