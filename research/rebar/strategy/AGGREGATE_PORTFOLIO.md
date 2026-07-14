# Aggregate execution portfolio

Status: planning evidence derived from the authenticated Rebar expansion and
the deterministic pre-operation admission report. This document does not
change planner routing and is not a performance result.

## Why one whole-operation strategy is insufficient

The production `fre-aggregate` zero/progress recurrence is the exact bounded
floor for nullable priority cases that can make repeated suffix searches
quadratic. Its two strategies deliberately cost `O(QN)`. That is acceptable as
a correctness/resource certificate, but not as the only performance path.

Among the Rust jobs that the current single-search facade builds, the
`count`/`count-spans` input includes 16,013,977-byte haystacks. A full table for
even a modest program would exceed the default cell quota, while reverse rows
would still execute every admitted state at every byte boundary. Refusal is
correct; pretending this is the final fast path is not.

The authenticated admission snapshot currently contains:

| Model | Current single-search plan | Unicode | Jobs | Total haystack bytes | Largest haystack |
|---|---|---:|---:|---:|---:|
| count | exact literal | off | 8 | 33,028,998 | 16,013,977 |
| count | packed literal set | off | 6 | 32,927,194 | 16,013,977 |
| count | literal-set DFA | off | 14 | 16,094,004 | 16,013,977 |
| count | K0 | off | 36 | 228,879,841 | 16,013,977 |
| count-spans | exact literal | off | 16 | 6,655,380 | 1,048,602 |
| count-spans | packed literal set | off | 7 | 2,379,901 | 594,933 |
| count-spans | literal-set DFA | off | 1 | 51 | 51 |
| count-spans | K0 | off | 54 | 40,868,757 | 16,013,977 |

Unicode-on rows are excluded from this table because `fre-aggregate`'s only
current profile is explicitly Unicode-off. An ASCII-looking HIR is not enough
to erase that profile distinction: empty-match advancement over invalid UTF-8
can differ.

## Required operation-specific plans

1. **General nullable floor.** Use the existing full-table or reverse-row
   recurrence only after complete compile and operation admission. It remains
   the semantic oracle/fallback for the subset; it never silently changes
   strategy after execution begins.
2. **Finite-horizon/deterministic streaming automaton.** Minimum match width
   greater than zero bounds the number of outputs, but does *not* bound how far
   a higher-priority alternative must look before a shorter fallback becomes
   final. On `(?:a+b|a)` over `a^N`, a suffix-restarted matcher can inspect the
   remaining input to reject `a+b` before returning each one-byte `a`, for a
   quadratic total. Admit online iteration only when analysis proves finite
   maximum decision delay, finite maximum width, deterministic commit, or an
   equivalent whole-operation ledger. Merely looping a single-search API is
   not sufficient.
3. **Literal reducer.** Count and span-sum for a nonempty exact literal should
   scan the haystack once with a preprocessed/pattern-specialized candidate
   loop and advance by the selected non-overlapping match end. Empty literals
   require a separate direct boundary formula with checked output/count
   arithmetic.
4. **Ordered literal-set reducer.** A repeated leftmost-first Aho-Corasick
   `find_iter` is not admissible: its next step restarts a fresh search at the
   previous match end, and the family `[a^(N/2)b, a]` over `a^N` exhibits
   quadratic work. Use a custom reversed dense Aho-Corasick transducer instead:
   consume each haystack byte once from right to left, retain the lowest pattern
   index ending at each original start, and feed a bounded
   `maximum_literal_width + 1` recurrence ring. The recurrence has distinct
   initial and progressed modes so that an empty winner at a position consumes
   one boundary of progress and suppresses every lower-priority nonempty match
   at that same position. Construction, transition-table bytes, output bytes,
   recurrence scratch, arithmetic, and every transition must be bounded and
   charged before execution; no repeated-search fallback is permitted.
5. **Deterministic/one-pass reducer.** Where a bounded full DFA or one-pass
   automaton is admitted, generate a loop that emits and resets at selected
   match boundaries without per-match allocation. Cache/code size and compile
   time are part of the plan certificate.
6. **Native reducers.** Add distinct Kernel IR and native ABI operation tags
   for count and checked span-sum. A native single-search kernel called from a
   Rust suffix loop is not automatically a native aggregate plan and must not
   be labelled as one.

## Promotion order

- First connect the general aggregate engine to exact semantic receipts, with
  all resource refusals visible.
- Add forced literal and finite-horizon/deterministic streaming strategies and compare
  complete sequences/reducers against both pinned Rust regex and the general
  recurrence on their shared admitted domain.
- Measure cold construction, first operation, hot reuse, memory traffic, and
  code size. Retain losing rows.
- Consult the frozen non-Rebar holdout only at the stated qualification point;
  do not tune thresholds or shapes against its individual cases.
- Promote a default route only if it wins the declared gate without weakening
  syntax/profile identity, priority, bounds, or failure publication rules.

The final pointwise Rebar requirement may need several strategies. Multiple
strategies are acceptable; hidden semantic fallback and benchmark-name routing
are not.
