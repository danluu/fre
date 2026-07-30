# External `regex` 1.12.4 AOT qualification preregistration

This checkpoint freezes selection, partitioning, fixture construction, overlap
handling, timing, and gates before any held-out case is materialized. It is an
external generalization layer, not another Rebar-derived workload.

The machine-readable contract is
`preregistration-v1.json`. Later tools and reports must authenticate its exact
bytes and this Git commit. A failed held-out gate cannot be tuned and rerun
under this preregistration version.

## Source authentication

The only corpus source is the locally cached published `regex` 1.12.4 package
under `$CARGO_HOME/registry/src/*/regex-1.12.4`. Exactly one package root is
accepted. Its `.cargo_vcs_info.json` revision, package version, complete
`testdata` file set, every file byte length and SHA-256, every decoded case,
and every canonical case SHA-256 must reproduce the checked-in authenticated
inventory at `research/upstream-regex/regex-1.12.4-inventory.json`. The
inventory payload SHA-256 is frozen in the machine contract. Symlinks,
additional or missing files, unknown TOML fields, or an inventory mismatch
fail closed.

Only `rust-regex-suite` cases participate. `regex-lite.toml` remains
authenticated provenance but is not a candidate source.

## Candidate admission

Admission never inspects upstream expected matches, upstream haystack contents,
or timing. A case must have one pattern, declare successful compilation,
unanchored full-range leftmost-first search, no match limit, no case folding,
and no custom search policy.

FRE then compiles the source pattern with its exact upstream semantic options
under `ForceExactLiteral`. Admission requires an authenticated nonempty exact
literal. A second compilation of the canonical byte spelling
`(?-u:\xHH\xHH...)` must recover identical literal bytes. Internal failures,
ambiguous finite languages, look-around, anchors embedded in the pattern,
classes, repetition, alternation, case folding, or a transformed-spelling
disagreement are explicit refusals.

Search admits literal widths 1 through 32. Count is a separately labelled
subset requiring `unicode=false`, `case_insensitive=false`,
`AggregateBuildLimits::aot_count_exact_literal_v1()`, and the complete Count
AOT eligibility receipt. Selection receipts preserve:

- upstream source path, source-file SHA-256, case ID, ordinal and case SHA-256;
- raw pattern SHA-256 and canonical semantic-options SHA-256;
- authenticated literal bytes SHA-256 and exact-candidate identity;
- every Search and Count applicability or refusal reason.

Cases with the same semantic-options SHA-256 and literal SHA-256 form one
duplicate group. The representative is the lexicographically smallest tuple
of upstream case SHA-256 and case ID. All member provenance remains in the
inventory; only the representative is timed.

## Development and held-out split

Partitioning occurs after semantic deduplication and before fixtures exist.
For each representative, decode its already authenticated 32-byte upstream
case SHA-256 and compute:

```text
SHA256("fre.aot.external-regex-1.12.4.partition.v1\0" || case_sha256_bytes)
```

The group is held out when byte zero is below 64 and development otherwise.
Thus the split is a fixed 25/75 content-hash rule. A semantic duplicate group
can never cross partitions. Empty development or held-out applicability for an
engine is a failed qualification, not permission to change the rule.

Development may diagnose and change an algorithm. Held-out source is
materialized and timed only after the final engine source, algorithm/backend
identity, runner, and development result are frozen. Any post-held-out code or
policy change requires a new preregistration version.

## Rebar contamination exclusion

Before either partition is timed, a closed contamination inventory must cover:

1. the accepted expanded Rebar manifest authenticated by
   `tested-source-a1a87d11-contract.json`; and
2. every source-bound Rebar pattern or literal inventory used by the final AOT
   evidence campaign.

The inventory records each input path and SHA-256 and derives the complete set
of raw pattern SHA-256s, declared literal SHA-256s, and literals authenticated
by the same FRE exact-literal admission used here. Missing evidence inputs or
an unparseable pattern fail closed.

An upstream candidate overlapping any of those sets is retained as a labelled
`corroboration` row but is excluded from every independent-generalization
performance gate. Reports give counts and identities for independent,
corroboration, and refused rows separately. This prevents a regex spelling
change from hiding literal-level leakage.

## Fixtures

Every fixture is exactly 1 MiB. Its alignment is fixed from the candidate and
scenario hashes before timing. Background data comes from a SHA-256 counter
stream mapped to printable ASCII, so it is valid UTF-8 even for Unicode-source
patterns. A deterministic left-to-right repair replaces any accidental literal
with a printable sentinel byte absent from the literal; a scalar verification
must then find zero matches.

The five frozen scenarios are:

- `absent`: repaired background with no match;
- `early`: the sole match starts at byte 64;
- `middle`: the sole match starts at
  `floor((1 MiB - width) / 2)`;
- `tail`: the sole match starts at `1 MiB - width`;
- `dense`: non-overlapping literal repetitions from byte zero, with a sentinel
  suffix.

For sole-match fixtures, up to `width - 1` bytes on either side are replaced
with the sentinel before insertion, preventing overlap-created matches. A
scalar leftmost-span and non-overlapping-count oracle verifies every fixture.
Fixture bytes and SHA-256 are persistent evidence; no fixture is selected,
discarded, or altered based on a measurement.

## Engine contracts

Search binds commit `8854592e`: nonempty exact literal, `Span`, full half-open
window, tag 22/policy 9, ASIMD/AAPCS64/OutSlotV1. Width one or windows below
4,093 bytes use portable search. Otherwise portable search authoritatively owns
the first 256 candidate starts; only a prefix miss invokes V9 on the disjoint
suffix. Construction and publication are outside steady-state timing.

Count development binds commit `5a58bf03` and the Count owner’s complete
identity/eligibility schemas. Held-out Count timing is forbidden until the
accepted algorithm and backend version are bumped and a final source identity
is frozen.

The host matrix is local Apple AArch64 ASIMD plus the zstd-eval EC2 AArch64
host, where Count additionally qualifies SVE2 at VL=16. Host, compiler family,
runner, plan, object, registry, and evidence digests are mandatory report
inputs.

## Timing and gates

Each pair uses identical fixture bytes on one pinned logical CPU with
alternating variant order. Both variants are piloted; iterations are derived
from the faster pilot so both target 500 ms and must reach at least 400 ms.
There are six repetitions. Independent cells may run in parallel only on
distinct CPUs admitted by measured headroom. Unrelated CPU work is never
stopped or killed.

All correctness comparisons are exact. Search suffix-owned independent cells
must have candidate/baseline geometric mean at most 0.80; non-target Search
groups must be at most 1.05. Count independent aggregate geometric mean must be
at most 0.80, with every scenario at most 1.05. Raw pairs, order, CPU, duration,
route, semantic outputs, identities, and group summaries are retained.

These external gates supplement, and cannot replace, the requested long-running
compiled Rebar gate.
