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

## Next layer

This foundation deliberately adds no combined stable wire format, object
layout, generated multi-row loop, or C ABI. Those can be added independently
without changing `OutputContract` or the stable `CompiledProgram` format. A
native set lowering should preserve the same ordered artifact identity,
pre-source authentication, strict bitset geometry, zero tail, and
transactional publication contract.
