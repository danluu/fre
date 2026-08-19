# Automatic portable K0 scratch: C9g diagnostic

Commit `176252757328ff88d1b1a8fd38b892b908eef925` makes the ordinary
`PortableRegex` value APIs automatically retain and reuse bounded K0 scratch.
Callers use `find_value`, `is_match_value`, or `selected_end_value` with
`SearchLimits::default()`; they do not construct or manage a search session.
The accounting-producing diagnostic methods remain unchanged.

This gives the ordinary result API the same scratch lifetime that
`regex::bytes::Regex` already provides through its internal cache pool. A cold
call still constructs and charges its workspace, custom finite limits retain
the canonical one-shot path, and concurrent calls can construct independent
bounded workspaces rather than serializing the search behind the pool lock.

## Holdout result

The frozen 19-case non-Rebar holdout ran on a 32-vCPU AWS C9g instance with
Rust 1.93.0, Rust-regex 1.12.4, and RE2 2025-11-05. It used three warmups and
nine measurements per exact input. Correctness passed 1,014/1,014 FRE
comparisons, 507/507 Rust-regex comparisons, and 507/507 RE2 comparisons.

Ratios are reference/FRE, so larger is better for FRE. Primary metrics include
only `find` and `exists`; selected-end remains diagnostic.

| Comparator | Metric | Prior independent C9g run | Automatic scratch | Change |
| --- | --- | ---: | ---: | ---: |
| Rust-regex | hot primary | 0.233728 | 0.447566 | +91.5% |
| RE2 | hot primary | 0.436204 | 0.843327 | +93.3% |
| Rust-regex | primary common API | 0.373954 | 0.506574 | +35.5% |
| RE2 | primary common API | 0.279647 | 0.379803 | +35.8% |
| Rust-regex | one-shot primary | 0.598309 | 0.573361 | -4.2% |
| RE2 | one-shot primary | 0.179279 | 0.171049 | -4.6% |

The hot result is the intended effect: scratch construction is amortized
without an explicit session. One-shot still includes cold construction and
therefore does not receive that benefit. FRE remains slower than both
comparators on the aggregate holdout; automatic scratch closes a large part of
the hot-call gap but does not fix the remaining K0 algorithmic losses.

The prior run used the accounting-producing direct FRE methods, while this run
uses performance schema v3's result-only methods. That boundary change is
intentional: Rust's public methods return values without constructing FRE-style
accounting reports. The deterministic correctness file, including its plan and
work receipts, is byte-identical between the prior and current runs
(`1a37d607...`).

## Rebar regression result

The normal Rebar suite was run after the holdout, with fresh preflight and the
slowest points first. It retained 1,152 of 1,220 prepared points, ran one
adjacent pair per point, produced 2,304 successful arms with zero timing
errors, and balanced 576 AB with 576 BA points.

| Scope | Prior independent C9g run | Current | Change |
| --- | ---: | ---: | ---: |
| Overall | 2.056767 | 2.177035 | +5.8% |
| Rust-regex | 1.321688 | 1.386788 | +4.9% |
| RE2 | 3.554169 | 3.802923 | +7.0% |

Rebar has only one pair per point, so these are descriptive regression checks,
not estimates of variance or proof that this change caused the difference.

## Reproduction and limits

The machine-readable aggregate record is
[`automatic-portable-k0-scratch-c9g32-2026-08-19.json`](automatic-portable-k0-scratch-c9g32-2026-08-19.json).
The compact external evidence archive is
`fre-auto-pool-17625275-c9g32-results.tgz`, SHA-256
`9ac7d3877a46ce75ea3a9be08d6c0f1ed06c6bd2764a2c72204404b3962c29f4`.
Raw performance samples remain external because holdout timing is diagnostic,
not committed qualification evidence.

The before and after runs used independent C9g instances and different source
revisions, so this is not a randomized same-machine A/B. The exact correctness
receipt and plan selection are unchanged, but host variance and unrelated
source changes can still affect timing. AOT was not rerun: the changed code is
confined to the portable runtime K0 value facade and is not linked into AOT
execution.
