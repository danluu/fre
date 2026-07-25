# Short fixed-continuation evidence

## Scope

- Tracker task: `FRE-U10-SHORT-FIXED-CONTINUATION`
- Isolated branch: `perf/u10-short-fixed-continuation-r1`
- Exact base: `9bd833eafba01f04abcf9c43fbef42f80f634e24`
- Residual point: `0244b950a3f672d428784361`
- Public aggregate plan remains `aggregate-continuation-program`.
- No remote run, remote benchmark host run, integration, push, or formal timing was performed.

The implementation contains no benchmark-name, point-ID, or source-byte
recognition. It also does not use the independent required-internal-anchor
class-topology proof.

## Construction proof

The compiler admits only canonical Unicode-off byte HIR with the complete
shape

```text
T+ C* S? (P* D* D* A D*)
```

where:

- `T` and `P` are nonempty, deterministic, pairwise prefix-free languages of
  bounded fixed literals or byte classes;
- `C` and `S` are fixed singleton punctuation bytes;
- all `D` repetitions are the same greedy byte class;
- `A` is one required singleton in `D`, is the independently derived global
  candidate byte, and is disjoint from every `T` first-byte set;
- the start-relative candidate interval is at most seven bytes; and
- captures are erased only at the existing typed whole-match boundary.

These facts make prioritized execution equivalent to two backward endpoint
recurrences: one for the greedy `P*` plus required-anchor body, and one for
greedy `T+` through the optional punctuation. The forward publication pass
then preserves leftmost-first non-overlapping iteration. A class still carries
its exact bytes, so default dot excludes LF while a `P` whitespace token may
cross LF exactly as the original HIR permits.

Every failed theorem check retains the ordinary continuation. Proof-present
execution is selected only when

```text
fixed worst-case work < unavoidable dense construction-and-scan work
```

with strict inequality. The fixed route has no post-publication fallback.

## Resource and identity evidence

- The fixed reducer allocates two exact endpoint arrays.
- Its scratch proof is `2 * boundaries * size_of::<usize>()`.
- Work and random source reads include every ordered token dispatch and every
  possible literal-byte comparison.
- Count and SpanSum enforce exact observed work; receipt-bearing observed
  calls clamp published work to the caller ceiling and retain bounded partial
  actual accounting on one-below refusal.
- Construction receipts cover all seven candidate-plan allocations: draft,
  entry, two bucket tables, both token tables, and the tagged proof owner.
- The optional proof is held by a fallible exact one-word tagged owner, keeping
  `candidate::Plan` at its pre-change object size.
- The tagged owner's three new unsafe sites are confined to
  `fre-exact-alloc`; the fail-closed unsafe-boundary audit pins all six
  reviewed sites and the complete allocator source digest
  `7e11b98d4220ff7bdc7755f9153934d21575ba711379021dc87927ba1a0d3411`.
- Ordinary candidate identities retain the v1 domain and payload. A fixed
  proof uses a v2 domain and hashes its body class, anchor, punctuation, token
  languages, comparison census, and retained shape.

## Exact local residual diagnostic

The supplied baseline was `166458 ns`. The final rebuilt local runner produced:

```text
108583,107
```

This was a single cold correctness diagnostic with one iteration and no
warmup, not a formal timing sample. It authenticated benchmark/model/plan and
the expected SpanSum `107`.

The instrumented receipt diagnostic for the 107-byte operation was:

| Quantity | Result |
|---|---:|
| Physical route | `Candidate` |
| SpanSum | 107 |
| Fixed actual work | 5,907 |
| Fixed prospective work | 17,552 |
| Dense unavoidable work floor | 123,336 |
| Execution allocations | 2 |
| Scratch bytes | 1,728 |

For comparison, the reproduced base dense execution used 122,655 actual work
over the full 506-state-by-108-boundary product.

## Validation

Focused validation covers:

- priority, greedy punctuation, missing/multiple anchors, CRLF, LF-sensitive
  dot behavior, LF-crossing prefix tokens, NUL, and invalid bytes;
- upstream byte-regex parity plus forced full-table parity for Count and
  SpanSum;
- exhaustive short-source parity for a different `:` anchor and a different
  token language;
- proof near-misses and generic dense fallback;
- strict cost-gate equality/loss rejection;
- exact prospective replay, exact observed-work replay, one-below work and
  scratch refusal, zero-output no-match limits, and all construction
  allocation fault ordinals; and
- an alternate-anchor facade case across Count, SpanSum, and Spans.

Completed gates:

```text
cargo fmt --all -- --check
cargo check --locked --offline --workspace --all-targets --all-features
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline -p fre-exact-alloc
cargo test --locked --offline -p fre-aggregate
cargo test --locked --offline -p fre
cargo test --locked --offline -p fre-unsafe-lint-boundary
cargo metadata --locked --offline --format-version 1 --no-deps |
  target/debug/fre-unsafe-lint-boundary
```

The affected full suites passed, including the exact-literal facade stack
canary and all non-ignored aggregate differential tests. The unsafe-boundary
audit reported `PASS` for 25 packages, three local exceptions, 14 kernel
targets, and 13 protected non-library targets.
