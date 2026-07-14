# Suffix-first theorem for the bounded `CLASS+ SUFFIX` kernel

Status: proof and admission contract for a research backend shape. It does not
authorize facade promotion.

## Semantics being preserved

For byte class `C`, non-empty suffix `S`, haystack `H`, and half-open search
window `W = [w0, w1)`, the Kernel IR shape denotes the greedy concatenation
`C+ S`. Its existing builder proves `S[0] ∉ C` and its interpreter:

1. selects the first class byte at or after the cursor;
2. extends to the maximal contiguous class run;
3. checks `S` immediately at the run end;
4. on rejection resumes at that run end.

Rust regex 1.12.4 constructs byte regexes with
`MatchKind::LeftmostFirst` in `regex-1.12.4/src/builders.rs`, and ordinary `+`
is greedy unless swap-greed or `+?` syntax is requested. FRE lowers only the
greedy canonical shape into this Kernel IR.

## Proposed mechanically checked admission

The suffix-first AArch64 implementation is admitted only when all of these are
true:

1. the raw program is the already validated canonical class/suffix CFG;
2. `C` has cardinality exactly one, and the emitter extracts that byte from
   the normalized 256-bit class;
3. `S` is non-empty and the validated IR proves `S[0] ∉ C`;
4. the match is not start anchored;
5. `|S| <= MAX_REPEATED_CONFIRM_BYTES == 32`.

Start-anchored programs retain the existing one-run lowering. Non-singleton
classes retain the existing bounded lowering until a separately proved vector
class representation exists. Any unanchored suffix longer than 32 bytes is
already typed-refused with `EmitError::ConfirmationLengthLimit` and requires a
proved-linear planner fallback.

No condition depends on the Rebar job, haystack contents, or measured timing.

## Whole-match and greediness proof

Call `p` a valid suffix candidate when:

- `w0 < p`;
- `p + |S| <= w1`;
- `H[p..p+|S|] == S`;
- `H[p-1] ∈ C`.

Let `q(p)` be the beginning of the maximal contiguous `C` run ending at `p`.

Lemma 1 — candidate yields the greedy match:

- Every byte in `H[q(p)..p]` belongs to `C`.
- Either `q(p) == w0` or `H[q(p)-1] ∉ C`, so this is the earliest start of
  that run within the search window.
- `H[p] == S[0] ∉ C`, so greedy `C+` must stop exactly at `p`; it cannot consume
  into `S`, and giving back a class byte cannot make `S[0]` match.
- Therefore the unique greedy match for this run is
  `[q(p), p + |S|)`.

Lemma 2 — suffix order is whole-match start order:

Take two valid candidates `p1 < p2`. Since `H[p1] == S[0] ∉ C`, the contiguous
class run immediately before `p2` cannot cross `p1`. Thus
`q(p2) > p1 > q(p1)`. Candidate order strictly preserves whole-match start
order. The first valid suffix candidate is therefore the leftmost-first match.

Lemma 3 — rejection is complete:

- A suffix occurrence whose predecessor is outside `C` cannot terminate any
  `C+ S` match.
- A pair-filter false positive is rejected by full suffix comparison.
- With absolute end anchoring, a suffix whose end is not `H.len()` cannot be a
  match and scanning may continue. The only candidate that receives backward
  class confirmation is the candidate ending at `H.len()`.

Together these lemmas prove the same whole-match start, greedy end, and
leftmost-first selection as the current interpreter for admitted programs.

## Aggregate-work theorem

Let `N = w1 - w0` and `M = |S|`.

Forward suffix search visits candidate starts monotonically. Each start is
examined at most once. The vector loop handles 16 starts per iteration; a
pair-filter hit may inspect at most those 16 starts scalar. Full confirmation
reads at most `M <= 32` bytes per scalar candidate. Therefore forward work is
at most a fixed implementation constant times `N`, not `N*M` for an unbounded
`M`.

Backward singleton-class confirmation begins only after a complete suffix and
a class predecessor. Without end anchoring the first such candidate is the
answer, so there is one backward scan. With end anchoring only the suffix ending
at the absolute haystack end is scanned backward. It reads each byte in that
class run once, in 16-byte vectors plus a scalar block of at most 15 bytes, for
at most `N` additional byte visits.

Construction examines four class words and at most 32 suffix bytes, uses no
dynamic scratch, and emits a constant-size image. Search is thus `O(N + M)` for
the admitted family, with constant search scratch and no input-dependent state
growth.

## Load-safety obligations

- A forward vector iteration is entered only when 16 complete candidate starts
  remain. If `x5 + 15 <= w1 - M`, the first-byte load and the load offset by
  `M - 1` both end before `w1`.
- Scalar suffix confirmation is entered only for `p <= w1 - M`.
- A predecessor load is entered only for `p > w0`.
- A backward vector load is entered only when `cursor - w0 >= 16`, and loads
  exactly `[cursor-16, cursor)`.
- The scalar backward tail checks `cursor > w0` before loading `cursor-1`.

Actual-hardware tests must exercise every alignment, 0--31-byte tails, narrow
windows, and inaccessible pages adjacent to both sides of the haystack.

## Deliberate refusals and counterexamples

- If `S[0] ∈ C`, a suffix start is not a run delimiter; greediness and suffix
  order no longer imply the same match. Kernel IR already rejects this.
- Without the 32-byte cap, bounded pair filtering followed by naive full
  confirmation admits `N*M` work when selected bytes are dense. This backend
  refuses instead of claiming linearity.
- An arbitrary 256-bit class cannot use singleton vector equality. This first
  implementation does not guess a range or silently change class semantics.
- A native count kernel is outside this proof. Repeated calls to a first-match
  kernel remain a separate aggregate strategy.
