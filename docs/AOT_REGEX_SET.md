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
invariant, and authentication failures are terminal. This substrate does not
yet claim a generated entry point or native object route. The aggregate
literal-byte ceiling is charged while witnesses are captured: its first
crossing stops later optional fact work, and each finite-language proof is
bounded by the remaining allowance after the allocation-free exact-width
proof, so an oversized literal is not first retained as an optional witness. A
decline does not bypass completion of the authoritative incumbent or any later
indexed semantic error.

## Next layer

This foundation deliberately adds no combined stable wire format, object
layout, generated multi-row loop, or C ABI. Those can be added independently
without changing `OutputContract` or the stable `CompiledProgram` format. A
native set lowering should preserve the same ordered artifact identity,
pre-source authentication, strict bitset geometry, zero tail, and
transactional publication contract.
