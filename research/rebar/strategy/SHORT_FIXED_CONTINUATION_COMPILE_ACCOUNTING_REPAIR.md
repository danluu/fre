# Short fixed-continuation compile-accounting repair

## Scope

- Tracker task: `FRE-U10-REPAIR-SHORT-COMPILE-ACCOUNTING-R1`
- Exact parent candidate: `6f52189d7a358d2ccb56c7b41d8a5495df203b4c`
- Isolated branch: `repair/u10-short-compile-accounting-r1`
- Canonical `main` remained at `9bd833eafba01f04abcf9c43fbef42f80f634e24`.
- The parent candidate worktree was not modified.

This repair changes compiler work accounting only. It does not broaden the
fixed-continuation theorem, alter its executor comparison census, change the
strict runtime cost gate, change route priority, or recognize a benchmark,
point ID, or source value.

No SSH, remote access, remote benchmark host, timing, integration, push, or canonical mutation
was performed.

## Repaired accounting model

The fixed theorem now charges each data-dependent proof traversal where it is
observed:

- equal `ByteSet` values require four charged word comparisons;
- membership requires one charged word access;
- emptiness, subset, and overlap charge each visited word, up to four;
- each admitted fixed-literal byte is separately checked and charged against
  the body class;
- class reconstruction remains `sum(range width + one range visit)`; and
- retention charges `token count + sum(retained literal lengths)` before its
  allocation.

The proof census carries retained literal-copy bytes separately from executor
`comparison_bytes`. A class contributes one executor comparison byte but zero
retained literal-copy bytes. Consequently, retention cannot mask earlier
proof work and `record_copy` remains construction-effect evidence rather than
a second compile-work charge.

The bounded retention work is admitted atomically before allocation. A
retention refusal therefore reports the complete required work while retaining
only completed theorem work as actual, with zero allocations, copies,
initialized bytes, or live construction bytes. Class reconstruction after
allocation remains separately metered, with the existing abandonable-byte
receipt behavior on a later refusal.

## Hand-derived adversaries

The max-width test uses two distinct 16-byte literals:

```text
proof =
  2 token visits
  + 2 * 16 body-membership comparisons
  + 1 pair visit
  + 16 prefix comparisons
  = 51

retention =
  2 token visits
  + 2 * 16 literal-copy bytes
  = 34

combined = 85
metadata = (tokens 2, comparison work 34, comparison bytes 32, copy bytes 32)
```

Work `85` succeeds. Work `84` refuses with required work `85`, proof-only
actual work `51`, and no construction effects.

The maximum-alternative test uses 128 pairwise prefix-free two-byte literals:

```text
pairs = 128 * 127 / 2 = 8,128

proof =
  128 token visits
  + 128 * 2 body-membership comparisons
  + 8,128 * (1 pair visit + 2 prefix comparisons)
  = 24,768

retention =
  128 token visits
  + 128 * 2 literal-copy bytes
  = 384

combined = 25,152
metadata = (tokens 128, comparison work 384, comparison bytes 256, copy bytes 256)
```

Work `25,152` succeeds. Work `25,151` refuses with required work `25,152`,
proof-only actual work `24,768`, and no construction effects.

Two additional exact ledgers cover the four-word helpers and their class
call-site:

- `25` work for two equalities, membership, two emptiness scans, subset, and
  overlap; and
- `13` work for one high-word two-byte class token: token visit `1`, class
  construction `3`, anchor membership `1`, emptiness `4`, and subset `4`.

Both exact-minus-one receipts close at the caller ceiling.

## Preserved semantics and identities

- The complete admitted HIR remains `T+ C* S? (P* D* D* A D*)`.
- The retained executor fields and comparison census are unchanged.
- The strict fixed-work-less-than-dense-work gate is unchanged.
- The public plan remains `aggregate-continuation-program`; the internal
  physical route remains `Candidate`.
- Existing plan IDs, allocation order and seven fixed-plan allocation fault
  ordinals remain unchanged.
- Near misses remain on the generic dense continuation.
- Priority, LF/dot behavior, invalid-byte behavior, exact limits, and
  Count/SpanSum accounting remain covered by the existing focused and
  differential matrices.

A permanent source-independent guard uses a different token language and a
different 107-byte source to assert `SpanSum 107` on the fixed Candidate
route. A separate temporary no-clock diagnostic also exercised the original
107-byte residual and returned exact `SpanSum 107`; that diagnostic was
removed before commit, so no exact input recognition remains.

## Validation

All commands were local, locked, offline where applicable, and clock-free:

```text
cargo fmt --all -- --check
cargo check --locked --offline --workspace --all-targets --all-features
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline -p fre-aggregate
cargo test --locked --offline -p fre
cargo test --locked --offline -p fre-exact-alloc
cargo test --locked --offline -p fre-unsafe-lint-boundary
git diff --check
```

The aggregate suite passed 116 unit tests and 51 differential tests, with only
the repository's expected opt-in tests ignored. The complete `fre` package
unit, integration, exhaustive facade, and doc-test suites passed without a
failure.

The fail-closed unsafe-boundary audit was also run against workspace metadata:

```text
PASS metadata-packages=25 local-exceptions=3 kernel-targets=14 protected-nonlib=13
```

Independent accounting and final blocking reviews were requested against the
isolated diff.
