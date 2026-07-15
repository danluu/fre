# Rebar candidate integrity guard

The candidate integrity guard is a fail-closed provenance and known-invalid
surface check for source candidates. It does **not** establish regex semantic
correctness, benchmark relevance, or acceptable performance. Those decisions
still require source review, focused adversaries, full Rebar qualification, and
pointwise timing where applicable.

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
- the candidate ref, HEAD, tree, repository identity, and clean state are
  unchanged after the content checks.

Success prints one tab-delimited receipt to stdout. It records the baseline and
candidate commit/tree SHAs, normalized ref and paths, every boolean check, the
guard source SHA-256, and a SHA-256 of the receipt payload. Failure prints a
single `result=FAIL` line with a machine-readable reason to stderr. Receipts are
control output: do not commit them, reports, logs, binaries, or build products.

The known-invalid check specifically prevents recurrence of the inert Unicode
compile artifact whose Rebar verifier executed Rust regex instead of an
executable FRE artifact. It is intentionally a denylist, not a general proof:
renaming the same defect, introducing a different semantic shortcut, or adding
an asymptotically bad engine can still pass this mechanical gate and must be
caught by review and qualification.

Run the focused selftest with:

```sh
tools/rebar-compare/scripts/candidate-integrity-selftest.sh
```

It accepts the exact safe baseline, rejects contaminated commits `3100146` and
`7900359` both by current-baseline ancestry and by their invalid surface from a
safe earlier ancestor, rejects a dirty worktree, and accepts the live safe
Unicode/capture branches when those refs exist and descend from the required
baseline.
