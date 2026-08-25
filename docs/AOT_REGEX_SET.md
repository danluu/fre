# AOT regex-set foundation

`fre_aot_regex::compile_regex_set` provides the target-neutral correctness
layer for Rust byte `RegexSet` semantics. It is intentionally distinct from
ordered-many matching: every source pattern that matches anywhere in the
requested search window contributes its own source-index bit. Pattern order
defines IDs, duplicate patterns retain separate IDs, and an empty pattern list
is a valid always-empty set.

## Compilation and identity

The complete source list first passes the pinned high-level
`regex::bytes::RegexSet` aggregate admission. This preserves its indexed first
syntax error and its unindexed combined-program size refusal. Only after that
transaction succeeds does FRE allocate the exact-capacity row table and build
one complete `OutputContract::Exists` semantic program per row. The compile
limits independently bound pattern count, source bytes, each stable program,
their total stable bytes, lowering, and determinization. The pattern-count
limit is configurable and is not the ordered-many tagged selector's 128-owner
ceiling.

The set artifact identity is a domain-separated SHA-256 over the identity
version, row count, every source ordinal, and the corresponding stable Exists
program digest in source order. Recompiling the same artifact produces the
same digest. A second process-local identity distinguishes independent
constructions; clones retain that local lineage.

## Prepared execution

`RegexSetProgram::prepare_session` retains exact-capacity `Vec`s containing one
`ProgramWorkspace` per row and `ceil(patterns / 64)` private staging words. It
does not convert those vectors to boxed slices or perform a shrink allocation.
Session limits bound workspace rows, staging words, and admitted haystack
bytes. Together with the compile-time graph and stable-program ceilings these
are the current resource envelope. An exact aggregate ceiling over every
row workspace's complete retained byte footprint is not exposed yet; adding
that prospective accounting is future work and must precede any claim of a
single total session-byte limit.

`fill_matches_with_session` accepts an exact-length caller-owned `&mut [u64]`.
Before any row inspects the haystack it validates:

- the stable set digest and process-local clone lineage;
- program, workspace, and staging shapes and capacities;
- caller output word count and source-byte limit;
- the complete search window; and
- every row workspace against its own semantic program.

The run clears only private staging, executes all Exists rows, and publishes
the complete word slice with one final copy after every row succeeds. Errors
therefore leave caller output unchanged. Unused high bits in the final word
are always zero. `matching_pattern_ids` validates a completed bitset and
iterates set bits in ascending source-ID order without allocating.

Search windows retain surrounding haystack context. In particular, callers
must pass a `SearchWindow` over the original bytes instead of slicing when
anchors or word boundaries can observe bytes outside the window.

## Opt-in exact64 shared-scan substrate

`compile_regex_set_exact64_reported` is a separate experimental entry; the
existing compiler and its defaults do not request this optimization. It first
builds the same complete independent-row incumbent. An Optimizing request with
2 through 64 rows can then select a target-neutral shared Aho-Corasick graph
only when current authenticated HIR facts independently prove that every row
is one nonempty, assertion-free exact byte string. Semantic proof refusal,
including nullable, assertive, and multi-string rows, returns the incumbent
with an indexed decline.

Before applying the caller's literal-byte ceiling, an allocation-free
canonical-HIR exact-literal proof establishes singleton shape and exact width.
The bounded finite-language facts then independently authenticate the same
assertion-free bytes; the two proofs' materializations must agree. This keeps
semantic row declines ahead of literal/state/transition resource declines
without retaining an over-limit witness.

The shared graph assigns one `u64` bit to every source ordinal. Terminal masks
retain duplicate rows, and failure-link masks inherit suffix matches, so
prefix, suffix, and overlapping literals are all reported by one scan. Its
receipt binds the ordered incumbent artifact, exact literal-to-source mapping,
current canonical exact-literal and HIR-fact algorithm/accounting identities,
graph dimensions, transitions, failure links, and output masks. Before
publication, construction replays every independently digested proof byte
through direct trie edges to its exact source terminal. The portable oracle
reauthenticates the retained receipt and graph before reading the haystack,
scans exactly the requested window, and publishes the caller word only after
success.

Explicit literal-byte, state, transition, and failure-work ceilings are the
only resource declines after proof. Allocation, arithmetic, construction
invariant, and authentication failures are terminal. The aggregate
literal-byte ceiling is charged while witnesses are captured: its first
crossing stops later optional fact work, and each finite-language proof is
bounded by the remaining allowance after the allocation-free exact-width
proof, so an oversized literal is not first retained as an optional witness. A
decline does not bypass completion of the authoritative incumbent or any later
indexed semantic error.

### Opt-in AArch64 dense lowering

`compile_regex_set_exact64_aot_v1` is a second explicit step that consumes an
already-selected `RegexSetExact64Program` by value. It reauthenticates the
complete graph, expands it under separate transition-cell and data-byte caps
to a dense 256-way Aho-Corasick table, and emits one scalar AArch64 entry. The
table stores a `u32` next-state token for every state/byte pair and the exact
inherited `u64` output mask for every state. The entry scans the requested
window once, accumulates all source bits, and stores the caller's word only on
success. It has no runtime-helper symbol.

The effective data limit is also bounded by the published AArch64 ADRP/ADD
addressability ceiling, even if a caller raises its own cap. Transition cell
address formation uses the full address width; only authenticated state tokens
remain `u32`.

A valid x86-64 target or an explicit dense-cell, dense-data, code, or final
object byte ceiling returns the exact input program unchanged with a typed
decline. Target incoherence, graph/data malformation, allocation refusal,
arithmetic overflow, and object failure are terminal. The receipt binds the
portable graph and incumbent identities, target tuple, dense-data digest and
geometry, generated code, relocation-closed object, and every ceiling. This
entry remains opt-in; `compile_regex_set`, `compile_regex_set_exact64_reported`,
and all of their defaults are unchanged.

### Additive first-any-position lowering

`compile_regex_set_exact64_first_any_aot_v1` is a separate opt-in consumer of
the same target-neutral exact64 program. It does not change or wrap the v1
complete-mask entry. Before allocating dense data, it reauthenticates every
source-terminal parent chain and declines with the unchanged program if any
exact singleton contains LF. Nonempty exact-singleton admission is inherited
from the target-neutral exact64 proof.

The helper-free AArch64 ABI is:

```text
u32 entry(const u8 *haystack, usize len, usize start, usize end, u64 *position)
```

Status zero publishes exactly one word. `u64::MAX` means no row matched.
Otherwise the word is the original-haystack offset of the final byte consumed
by the first graph state, in forward scan order, whose authenticated owner
mask is nonzero. It is therefore a byte inside at least one match and, because
all source literals are nonempty and LF-free, inside its matching LF-delimited
line. It is not a selected span, a leftmost-start result, or a source-pattern
priority result. A raw-argument failure leaves the output word unchanged.

The new receipt binds the source graph, LF exclusion, position semantics,
no-match sentinel, target, dense geometry and data, code, relocation-closed
object, and all resource ceilings. Unsupported architecture, LF presence, and
the four numeric ceilings are the only safe declines. Authentication,
allocation, arithmetic, target incoherence, construction, and object failures
remain terminal. A future ripgrep adapter may use the returned byte only as a
`Candidate`; stock matching remains responsible for verification, spans, and
captures.

## Next layer

The native object is deliberately a separate exact64 artifact rather than a
new `CompiledProgram` wire-format variant. A future registry/runtime adapter
can bind its identity-suffixed C symbol without changing `OutputContract`, the
stable ordinary program format, or the authoritative independent-row
fallback.
