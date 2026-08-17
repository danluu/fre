# Rebar candidate integrity guard

The candidate integrity guard is a fail-closed provenance, known-invalid
surface, and benchmark-source-policy check for source candidates. It does
**not** establish regex semantic correctness, benchmark relevance, or
acceptable performance. Those decisions still require source review, focused
adversaries, full Rebar qualification, and pointwise timing where applicable.

The required safe baseline for the current campaign is
`bf53ce82a17df0351d9e7a936271e5ebfa8c9635`. Run the gate from a trusted checkout
of the guard, not from an unreviewed candidate:

```sh
tools/rebar-compare/scripts/candidate-integrity.sh \
  /absolute/path/to/fre \
  bf53ce82a17df0351d9e7a936271e5ebfa8c9635 \
  refs/heads/lane/candidate \
  /absolute/path/to/candidate-worktree
```

The four inputs are explicit: canonical repository top, full required baseline
SHA, a full SHA or real Git ref, and the candidate worktree top. The gate
rejects the candidate unless all of the following remain true across two
identity snapshots:

- the repository and candidate worktree are valid tops sharing one Git common
  directory;
- the ref resolves to the candidate worktree's exact commit and tree;
- the required safe baseline is an ancestor of that commit;
- the worktree is clean and is not in a merge, cherry-pick, revert, or rebase;
- `crates/fre/src/unicode_compile.rs` is absent;
- `fre_unicode_compile_verify` and `UnicodeCompileArtifact` are absent from
  tracked Rust source under production `crates/` and `tools/` trees;
- production Rust changed since the required baseline contains no newly
  visible dispatch on an exact raw regex spelling, benchmark/job identity,
  pinned source fingerprint, compile-time included fixture, or reachable
  expected-answer/report constant;
- the candidate ref, HEAD, tree, repository identity, and clean state are
  unchanged after the content checks.

Success prints one tab-delimited receipt to stdout. It records the baseline and
candidate commit/tree SHAs, normalized ref and paths, every boolean check, the
guard and source-policy SHA-256 values, and a SHA-256 of the receipt payload.
Failure prints a machine-readable policy diagnostic followed by the guard's
`result=FAIL` line. Receipts are control output: do not commit them, reports,
logs, binaries, or build products.

The known-invalid check specifically prevents recurrence of the inert Unicode
compile artifact whose Rebar verifier executed Rust regex instead of an
executable FRE artifact. The additional source policy is pattern- and
taint-based rather than a denylist of the removed symbol names. It scans
committed candidate blobs, removes `cfg(test)` items, follows recognizable raw
source and fingerprint identities, and checks exact comparisons, string
content dispatch, keyed lookups, match dispatch, and expected-answer constant
uses. Parsing/lowering declassifies source into structural regex semantics.
Unconditional regex-redux stage patterns are model definitions and remain
allowed. Dynamic artifact source-identity comparisons and cache lookups by a
source fingerprint remain allowed; comparison to a pinned literal or constant
does not.

This remains a conservative lexical guard, not compiler-backed information
flow. Obfuscated names, helper calls that conceal dataflow, macro expansion,
build-script generated code, or a malicious value stored behind an otherwise
legitimate semantic cache can evade it. Conventional out-of-line `tests.rs`
modules are excluded, and the required baseline is trusted. Review and
held-out semantic qualification remain mandatory.

Run the focused selftest with:

```sh
tools/rebar-compare/scripts/candidate-integrity-selftest.sh
```

The selftest builds synthetic commits that accept model-defining regex-redux
patterns, artifact source binding, and test-only fixtures, then reject exact
source comparisons, renamed comparison constants, job IDs, benchmark names,
pinned source hashes, included text fixtures, and reachable expected answers.
When the historical objects are available, it also accepts the exact safe
baseline, rejects contaminated commits `3100146` and `7900359`, rejects a dirty
worktree, and exercises live safe branches that descend from the baseline.
