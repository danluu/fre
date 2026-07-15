# Bounded capture-history candidate

Status: source-only candidate recomposed on exact canonical base
`f85cdfda7bc3968f6910d122bb4cffe32db47dbd` (tree
`260ab9e1ca6d3e4979e50dcf5deab3a572d57c8b`). No compiler, formatter,
executable test, report generation, assembly, or timing command was run in this
lane. The candidate adapter identity advances to
`fre-current-aggregate-v10` for the combined breadth-plus-capture-plus-redux-plus-boundary route. The
direct Unicode scalar, compile-only Unicode fallback, finite reducer, portable
Unicode scalar-class, ordered build-many, and timing surfaces retain their
existing plan, schema, route, and timing identities; the separately typed
regex-redux and positive Unicode-word routes are additive. No combined report has
been generated. The separately authenticated direct-scalar frontier remains
214 pass / 130 unsupported, while the breadth source retains only its documented
overlap-aware projected ceiling. Capture adds a bounded evaluation universe of
at most 22 rows, not authenticated coverage or 22 projected passes.

## Semantic boundary

The default continuation compiler still rejects capture HIR, and the existing
whole-match entry point still erases annotations only for whole-match values.
The new `CompiledCaptureRegex` is a distinct construction mode. It retains
zero-width capture start/end instructions without changing the certified
whole-match recurrence, plan selection, or operation quotas.

Capture execution first admits the complete non-overlapping whole-match
sequence through the existing operation. Each already-selected exact span is
then replayed through the same prioritized program. Preferred split branches
are visited first; a `(position, program state)` cell is accepted only on its
first visit. History reconstruction therefore cannot select a different whole
match or fall back to a lower-priority capture path. Absolute operation ranges,
optional groups, repeated-group last captures, empty-match progress, and group
zero remain explicit directed witnesses.

The capture-specific preflight independently checks:

- capture slots, including group zero;
- replay cells, exactly `program states * (longest selected match + 1)`;
- the equal history-node upper bound;
- returned group arrays plus capture-match records;
- replay scratch, retained whole-match output, and combined peak bytes; and
- `selected matches * (3 * replay cells + 1)` replay/materialization work.

The certificate publishes both the preflight work bound and actual work.
Capture replay scratch and group-output allocations use the shared fallible
exact-layout policy after logical preflight. Their actual visited, stack,
history, match, group, and temporary-offset capacities are rechecked against
the named replay/history/output/peak bounds and supply the certificate's
physical peak; every push is capacity-guarded and full before boxed conversion.
Allocation failures remain typed. A selected
capture build or execution refusal never invokes exact-literal, direct Unicode
scalar, build-many, or capture-erasing fallback.

The Rebar route is intentionally narrower than the reusable engine API:
exactly one pattern, Unicode disabled, and only `count-captures` or
`grep-captures`. Grep reconstructs each line independently while charging one
cumulative event/work budget. Unicode capture execution, multi-pattern capture
reducers, capture spans as a public Rebar value, and every syntax/resource
shape outside the bounded continuation proof remain typed unsupported.

## Exact projected job universe

The immutable 344-row manifest contains 37 capture-model rows: 15
`count-captures` and 22 `grep-captures`. Static profile/cardinality preflight
excludes 14 Unicode-on rows and one 88-pattern row. The exact maximum candidate
universe is therefore 22 rows (11 per model), before syntax or resource
classification:

- `captures/contiguous-letters@rust/regex`
- `curated/04-ruff-noqa/real@rust/regex`
- `curated/04-ruff-noqa/tweaked@rust/regex`
- `curated/05-lexer-veryl/single@rust/regex`
- `curated/07-unicode-character-data/parse-line@rust/regex`
- `curated/09-aws-keys/full@rust/regex`
- `curated/11-unstructured-to-json/extract@rust/regex`
- `opt/backtrack/words-english@rust/regex`
- `opt/onepass/first-three-words-english@rust/regex`
- `opt/onepass/fn-predicate@rust/regex`
- `opt/onepass/word-boundary-english@rust/regex`
- `opt/prefilter/rust-functions@rust/regex`
- `test/model/count-captures@rust/regex`
- `test/model/grep-captures@rust/regex`
- `unicode/overlapping-words/ascii@rust/regex`
- `wild/caddy/caddy@rust/regex`
- `wild/dot-star-capture/rust-src-tools@rust/regex`
- `wild/parol-veryl/ascii@rust/regex`
- `wild/rustsec-cargo-audit/both-alternate@rust/regex`
- `wild/rustsec-cargo-audit/both-slashes@rust/regex`
- `wild/rustsec-cargo-audit/original-unix@rust/regex`
- `wild/rustsec-cargo-audit/original-windows@rust/regex`

This is a bounded evaluation universe, not 22 projected passes. A fresh exact
report must retain every prior receipt byte-for-byte by disposition/value,
publish every capture refusal reason, and classify these rows without inferring
support from static eligibility.

## Red-first witnesses and required gates

The directed engine tests precede implementation in source history. They kill
fallback-first replay with `(a|(ab))(b)?`, require repeated-group last-capture
semantics, optional nonparticipation, absolute offsets, and empty progress.
Separate exact-limit/one-below cases cover slots, replay cells, history nodes,
output bytes, work, and peak bytes. Comparator tests precede routing and require
both capture reducers plus typed Unicode and multi-pattern refusals.

Qualification must run focused capture tests, full owned-crate tests, strict
Clippy, formatting, and two byte-identical full reports. Any prior
whole-match/build-many/Unicode/portable disposition change, wrong capture
count, fault, untyped refusal, or quota bypass rejects the candidate.
