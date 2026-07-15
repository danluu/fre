# Shared finite-language aggregate DFA

`PORTFOLIO_PROFILE=shared-resource-trie-c-r009`

## Scope and selection

The aggregate `Auto` planner now selects `FiniteLiteralDfa` for Unicode-off
finite HIR in Compile, Count, and SpanSum. Exact literals remain on
`ExactLiteral`, Unicode root classes remain on `UnicodeScalarClass`, complete
span materialization remains on the continuation engine, and assertions or
unbounded repetitions remain on the continuation frontier. `ForceContinuation`
is unchanged and exists only for semantic qualification.

Finite extraction preserves HIR alternation order, duplicates, empty words,
capture-transparent whole-match semantics, case-folded canonical bytes, and
arbitrary invalid bytes. The selected kernel builds one byte-class-compressed
reversed Aho--Corasick DFA. One right-to-left transition determines the first
ordered word beginning at each byte. A bounded initial/progressed DP ring then
implements leftmost-first non-overlap and adjacent-empty suppression without
restarting the search.

## Certificate and bounds

Let:

- `N` be haystack bytes;
- `Q` be total finite-language pattern bytes plus alternatives;
- `T` be the checked, one-time trie/failure-link/dense-transition construction
  charged in `build_work_upper_bound`.

Construction is bounded by the public pattern, pattern-byte, trie-state, DFA
cell, work, scratch, persistent, and peak limits. Persistent storage is
`O(Q * C)`, where `C <= 256` is the byte-class count. Construction scratch is
`O(Q)`, and `T` is bounded by the admitted trie and dense-DFA cells.

Execution performs exactly `N` DFA transitions and `N + 1` reducer steps. It
initializes at most `min(N, L) + 1` ring entries, where `L` is the longest
word. Thus time is `O(N + L)`, scratch is `O(min(N, L))`, and no production
counter contains `N * alternatives`, `N * trie states`, or a live state set.
The immutable DFA is shared by Count, SpanSum, and compile-artifact
verification; each operation has its own plan identity and exact debit limits.

The semantic invariant at reducer position `i` is: the two ring states equal
the final aggregate for regex iteration beginning at `i`, respectively before
any prior match and after a match ending at `i`. The DFA output is the lowest
HIR alternative ordinal matching at `i`. The recurrence either accepts that
word and jumps to its end, suppresses an adjacent empty and advances one byte,
or advances to `i + 1`. This establishes ownership, leftmost-first priority,
non-overlap, and empty progress. Full-haystack aggregate calls have no shifted
anchor context; anchored/windowed and span-materializing neighbors deliberately
retain the continuation route.

## Structural gate

`finite_dfa_n_2n_and_query_scaling_rejects_input_times_alternatives` uses
absent invalid-byte haystacks at `N` and `2N`, with 16 and 64 alternatives. It
requires transition counts of exactly `N`/`2N`, reducer counts of exactly
`N+1`/`2N+1`, and identical execution work for both alternative counts at a
fixed `N`. The semantic tests also cover early, late, absent, ordered-prefix,
empty, capture, case-folded, and invalid-byte cases, plus exact work-limit
refusal.

## Preregistered pointwise timing matrix (not run by workers)

Window 3 should retain each FRE artifact and construct Rust regex and RE2
artifacts before timing. RE2 cells that cannot express raw-byte syntax are
recorded unavailable rather than dropped.

| Family/model | Pattern stratum | Input | FRE route | Rust | RE2 |
| --- | --- | --- | --- | --- | --- |
| Compile affected | 64 finite alternatives | retained artifact | finite DFA | build | build |
| Count affected | ordered prefix + empty | early | finite DFA | bytes find-iter | pointwise |
| Count affected | 64 finite alternatives | late | finite DFA | bytes find-iter | pointwise |
| Count affected | 64 finite alternatives | absent | finite DFA | bytes find-iter | pointwise |
| SpanSum affected | ordered prefix + empty | early | finite DFA | bytes find-iter | pointwise |
| SpanSum affected | 64 finite alternatives | late | finite DFA | bytes find-iter | pointwise |
| SpanSum affected | raw `\\xFF` alternatives | absent/invalid bytes | finite DFA | bytes find-iter | unavailable |
| Count neighbor | exact literal | early/late/absent | exact literal | bytes find-iter | pointwise |
| Count neighbor | Unicode root scalar class | early/late/absent | Unicode scalar | bytes find-iter | unavailable for invalid bytes |
| Count neighbor | unbounded repetition | early/late/absent | continuation | bytes find-iter | pointwise |
| Spans neighbor | finite alternation | early/late/absent | continuation | bytes find-iter | pointwise |
| Count neighbor | anchored finite alternation | early/late/absent | continuation | bytes find-iter | pointwise |

No timing result or speed claim is recorded here.
