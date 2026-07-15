# Unicode-mode nonempty exact-literal proof

Status: admission proof for one deliberately narrow Rust-bytes operation
family. It is not a proof for general Unicode regex execution, captures,
assertions, case folding, alternation, classes, empty matching, or text
haystacks.

## Pinned contract and eligibility

The comparator executes `count` and `count-spans` with pinned `regex` 1.12.4 /
`regex-automata` 0.4.14 byte semantics. The Rebar Rust runner configures syntax
with `utf8(false)` and the requested `unicode` bit, and configures
`utf8_empty(false)`. Haystacks are therefore arbitrary bytes even when Unicode
syntax is enabled.

The direct reducer is eligible only when all of the following are proved at
construction:

1. the compatibility profile is Rust bytes with Unicode enabled;
2. case-insensitive syntax lowering is disabled;
3. the operation is count or matched-byte span sum;
4. canonical HIR is exactly one `Literal` node, with no peeled capture nodes;
5. the literal byte sequence is nonempty; and
6. the HIR literal is a valid UTF-8 encoding.

Conditions 4 and 5 exclude empty nodes, captures, classes, assertions,
repetition, concatenation nodes not canonicalized into one literal, and
alternation. Condition 2 excludes even a source whose case-folded result might
happen to simplify. Escaped Unicode scalars and escaped regex metacharacters
are admitted only when the parser canonicalizes the complete expression to the
same single nonempty literal form.

A globally Unicode-enabled pattern may locally disable Unicode, for example
`(?-u:\xFF)`. The pinned bytes oracle accepts that syntax and its canonical HIR
can be one invalid-UTF-8 literal. This is valid syntax, not an engine invariant
failure, but it is outside condition 6 and receives the typed
`UnicodeLiteralNotUtf8` forced-exact ineligibility (or the ordinary Auto
Unicode admission-scope refusal). It remains available to a future separately
proved raw-byte mode.

Admission follows canonical HIR, not source spelling. In particular,
`(?-u:\xC3\xA9)` canonicalizes to the valid UTF-8 literal bytes for `é` and is
eligible. Conversely, `(?i:a)` does not canonicalize to one exact literal and
is refused. A globally case-insensitive profile with local `(?-i:a)` remains
conservatively refused because the global case-insensitive policy bit is part
of this slice's eligibility rule. A root capture also remains refused even
when its child is a literal.

Unicode-off behavior retains its existing, broader direct-root capture peeling
and empty-byte-boundary semantics. Successful plans in the two modes have
distinct facade identities in build reports, cache identities, and execution
reports. Construction failures such as syntax errors do not carry a selected
plan's syntax/semantic identity, so this proof makes no no-alias claim for
typed errors.

## Equivalence argument

Let `L` be the nonempty byte sequence in the eligible HIR and `H` any byte
haystack, including invalid UTF-8.

The pinned Unicode parser can produce this eligible HIR only when `L` is a
concatenation of complete UTF-8 scalar encodings. The first byte of each scalar
is ASCII or a UTF-8 leading byte, never a continuation byte. UTF-8 is
self-synchronizing: an occurrence of `L` cannot begin inside the continuation
bytes of a different valid scalar. Every raw occurrence of `L` is itself a
valid scalar sequence even when the bytes immediately before or after it are
invalid, truncated, overlong, surrogate encodings, or unrelated continuation
bytes.

For this HIR, the pinned regex automaton accepts exactly `L`; there is no
assertion or neighboring context to inspect. It therefore reports exactly the
same start offsets as raw byte substring search. Both iterators resume at the
end of the previous nonempty match, so their complete left-to-right
non-overlapping match sequences are equal. Count follows immediately. Every
selected match has length `L.len()`, so the checked matched-byte sum is equal as
well.

Invalid bytes elsewhere in `H` do not invalidate the argument. A false raw
match would have to start on a continuation byte or accept a byte sequence
other than `L`; the first is excluded by the leading byte of `L`, and the
second by exact byte equality. An invalid prefix or suffix cannot affect a
context-free literal match.

## Input spans and ranges

The production aggregate API searches the full original range
`0..H.len()`. For a valid pinned `regex-automata::Input` span `a..b`, the same
argument applies to occurrences wholly contained in that span. `Input::span`
preserves original-haystack offsets and outside context, but eligible literals
have no assertions that can observe that context. Starting or ending the span
inside another UTF-8 encoding cannot create an occurrence of `L`: the search
still needs all bytes of `L` inside the span and its first byte cannot be a
continuation byte. Slicing `H[a..b]` and adding `a` to raw-match offsets is
therefore equivalent for this subset. Invalid ranges remain outside both APIs'
contracts.

This range claim is characterized independently against pinned
`regex-automata` using its byte configuration; it is not used to widen the
current whole-haystack facade.

## Empty-pattern correction and conservative exclusion

The text/meta default restricts empty matches to UTF-8 scalar boundaries, but
that is **not** the pinned bytes/Rebar behavior. Pinned `regex::bytes::Regex`
and the Rebar runner explicitly set `utf8_empty(false)`, so a Unicode-enabled
empty byte regex currently reports every byte boundary, including boundaries
inside a valid multi-byte scalar.

Unicode-enabled empty HIR is nevertheless refused in this promotion. Empty
iteration is controlled by a separate engine configuration rather than the
nonempty UTF-8 self-synchronization proof, and the existing kernel identity
names Unicode-off byte-boundary semantics. Keeping it out prevents this narrow
admission from silently becoming a broader Unicode-empty compatibility claim.
A future promotion may add a separately named and tested identity after the
profile contract explicitly records `utf8_empty(false)`.

## Required executable evidence

The proof is guarded by differentials against pinned Rust over:

- representative ASCII, two-, three-, and four-byte literals;
- escaped Unicode forms and escaped metacharacters;
- every possible one-byte haystack and every possible two-byte haystack;
- every possible immediate prefix/suffix byte around each literal;
- every one-byte mutation at every literal position;
- invalid/truncated UTF-8 surroundings and embedded near misses;
- locally Unicode-disabled invalid-UTF-8 raw literals such as
  `(?-u:\xFF)`, retained as typed ineligible, while the valid-UTF-8 raw form
  `(?-u:\xC3\xA9)` is admitted;
- full and ranged input searches;
- count and span sum, audited and value-only APIs, Auto and forced exact; and
- exact resource limits and one-below typed refusals.

The five projected Rebar jobs form a separate authenticated affected-family
sentinel. Any additional coverage change, unexpected refusal, semantic
disagreement, identity alias, or resource mismatch rejects this admission
before canonical report regeneration.

## Frozen affected-family checkpoint

`unicode-exact-literal-sentinel.json` authenticates the unchanged canonical
report (`6a9e599e...f26b336`) and expanded manifest, then projects the current FRE
candidate over all 79 formerly unsupported Unicode `count`/`count-spans` jobs.
Exactly the five closed-set job IDs become passing `aggregate-exact-literal`
executions; the other 74 remain typed unsupported. Separate pinned-Rust and
FRE receipts for the five jobs are all passes, producing ten closed-set
receipts. The retained legacy sentinel schema v2 pins every retained job's exact refusal reason and
complete receipt, with digests `9e8a2d9e...a835c4a` and
`fd31d8f0...f3ec70`. The embedded complete-frontier and closed receipt digests
are respectively `c7be610a...5e40218` and `e49a0d8d...07d6056`.

Two executions were byte-identical. The retained artifact SHA-256 is
`2254f8151e2a685c63f84dcd2cd56c30cbd2b742bc64f738c9719498e6e4eaeb`.
The canonical report was read and authenticated but not regenerated or
rewritten.

Reproduce the semantic checkpoint with:

```text
target/debug/examples/unicode_literal_sentinel \
  research/rebar/expanded/manifest.json \
  /tmp/rebar-fre \
  research/rebar/comparison/report.json \
  OUTPUT.json
```

This checkpoint contains no timing evidence and makes no Unicode-continuation
or performance-promotion claim.

## Profile identity

The facade now has separate typed high-level and Rebar profiles for the released
`regex` 1.12.4, `regex-automata` 0.4.14 and `regex-syntax` 0.8.11 stack. Each
component records its crates.io checksum and independent packaged VCS revision.
The Rebar profile additionally records revision `463d00f`, dependency features,
ordered leftmost-first meta construction, `syntax.utf8=false`,
`utf8_empty=false`, the 100 MiB Thompson NFA limit, Unicode 16.0.0, and pending
upstream admission. Comparator and admission-frontier paths select that profile
explicitly; the 100 MiB upstream setting is identity only and does not widen an
FRE safety envelope or quota.

`fre-syntax` schema 2 prevents the corrected component/configuration stamp from
aliasing the former shape. Aggregate schema 4 additionally distinguishes the
complete compile-artifact operation from count/span operations. The comparator
remains report schema v2 with candidate adapter `fre-current-aggregate-v4`.
The Unicode sentinel itself remains schema v3 and semantic-domain v2 while
reading the retained canonical frontier through an explicit legacy
`fre-current-aggregate-v2` identity.

The retained sentinel above remains diagnostic evidence only. All semantic,
identity, resource, deterministic-sentinel, comparator, and holdout gates must
be rerun before canonical report regeneration, timing, or promotion.
