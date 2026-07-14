# Unsupported cases and unresolved obligations

The current positive result applies only to the public `fre_iterator_lab::Ast`.
Nothing below is silently approximated.

## Syntax and semantics not implemented

- Symbolic compact counters beyond the checked default bound of 1,000. General
  nested `*`, `+`, `?`, finite/open ranges are semantically admitted, but
  finite copies and nested progress products can hit explicit program limits.
- Captures, capture resets, capture iteration and exact-end capture replay.
- UTF-8/scalar iteration, Unicode classes, Unicode word boundaries, invalid
  UTF-8 policy beyond raw byte matching, and profile Unicode-version pinning.
- Line anchors, multiline/CRLF modes, ASCII/Unicode word assertions, local
  boundaries, look-around and subrange searches with original context.
- Multiple patterns and pattern IDs.
- RE2 `longest_match`, RE2 option combinations, RE2 consume/global-replace
  wrappers and Rust text-mode empty advancement.
- Split, replacement, visitor streaming, captures iteration and caller-driven
  overlapping `find_at` composition.

## Algorithmic obligations not proved

- The paper's tightly bit-packed sequential lean log. Fixed-row replay now has
  a proved reverse-sequential position schedule and one-row random buffer, but
  its store has per-row padding and is still represented by a resident `Vec`.
- Online or bounded-delay output. All aggregate candidates are whole-input/offline.
- A compact checkpoint/recomputation variant between `QU` words and `SU` bits.
- A compact production treatment of same-boundary SCCs. Strategy A removes
  them with a progress product; Strategy B keys explicit progress guards but
  has `Q U (U+1)^R` worst-case storage.
- Capture-erased selection followed by exact anchored capture reconstruction.
- General local assertions, whose recurrence key may require surrounding
  context or a richer boundary alphabet.
- RE2 longest whole-match selection and its submatch policy.

## Engineering limitations

- This is scalar research code, not a JIT/SIMD backend and not benchmarked
  against RE2 or Rust `regex` for throughput.
- The wall-clock samples are single-process illustrative measurements without
  pinning, warm-up statistics, confidence intervals or hardware metadata.
- Execution-sized table/log/row/output buffers are preflighted and fallibly
  reserved. Some small compiler/validation auxiliary collections still use the
  host allocator normally; the crate does not claim a fully closed OOM model.
- The full DP and both log candidates intentionally share the progress-product
  compiler and recurrence. The independently compiled guarded DP and upstream
  comparator reduce, but do not eliminate, correlated-model risk.
- The checked lowering recursion is depth bounded, but it is not yet replaced
  by the production compiler's explicit work stack.

Any newly supported item must be removed from this file, added to the model,
given directed regressions and included in an exhaustive or upstream
differential corpus. A mismatch is a retained counterexample, not permission
to weaken leftmost-first or empty-iteration semantics.
