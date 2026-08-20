# Rust-style ordinary search: C9g diagnostic

Commit `2a7befbf4128b712e946d0e0580e397c9941fcc5` (tree
`9e469f48072633257ea152beb2034b98b8c439bd`) makes FRE's ordinary
`find` and `is_match` APIs match Rust-regex's policy: they have no
caller-supplied search-work quota, automatically reuse
construction-bounded implementation scratch, and return values directly.
Callers that need recoverable finite refusal or exact accounting use the
separately named `*_with_limits` or `*_accounted` methods.

The holdout performance-v4 adapter consequently times the same public call
shape on FRE and Rust-regex. Both use ordinary `find` and `is_match`; the
selected-end diagnostic invokes ordinary `find` exactly once and projects the
end on both engines. Finite-limit and accounting checks remain in the untimed
correctness pass.

## Validation before timing

The exact source passed 754 FRE library tests (5 ignored), 8 holdout unit
tests, 4 frozen-suite tests, 290 Rebar library tests (24 ignored), 15
`fre-capi` tests, and 180 Rust-regex conformance tests (10 ignored), with no
failures. The stack-heavy Rebar and conformance runs used the established
`RUST_MIN_STACK=33554432` after libtest's default worker stack overflowed;
there was no assertion failure, and the setting changes only the test-harness
thread stack.

## Normal holdout result

The frozen 19-case holdout ran first on the persistent 32-vCPU C9g host with
Rust 1.93.0, Rust-regex 1.12.4, and RE2 2025-11-05. It used three warmups and
nine measurements per exact input. Correctness passed 1,014/1,014 FRE
comparisons, 507/507 Rust-regex comparisons, and 507/507 RE2 comparisons.

Ratios are reference/FRE, so larger is better for FRE. Primary metrics include
only `find` and `exists`; selected-end remains diagnostic.

| Comparator | Metric | Owner-fast baseline | Rust-style ordinary | Change |
| --- | --- | ---: | ---: | ---: |
| Rust-regex | hot primary | 0.533072 | 0.791246 | +48.43% |
| RE2 | hot primary | 0.996946 | 1.418177 | +42.25% |
| Rust-regex | primary common API | 0.550743 | 0.653632 | +18.68% |
| RE2 | primary common API | 0.412149 | 0.478060 | +15.99% |
| Rust-regex | one-shot primary | 0.568999 | 0.539953 | -5.10% |
| RE2 | one-shot primary | 0.170387 | 0.161151 | -5.42% |

The hot gain is concentrated in K0. Classifying cases by the authenticated
correctness plan gives this diagnostic split:

| Comparator | Plan class | Primary hot points | Baseline | Current | Change |
| --- | --- | ---: | ---: | ---: | ---: |
| Rust-regex | K0 | 174 | 0.279495 | 0.570694 | +104.19% |
| Rust-regex | non-K0 | 164 | 1.057539 | 1.119109 | +5.82% |
| RE2 | K0 | 174 | 0.387250 | 0.756750 | +95.42% |
| RE2 | non-K0 | 164 | 2.718905 | 2.761479 | +1.57% |

The K0 concentration is consistent with ordinary unbounded calls admitting
accelerators that the old default finite-work boundary bypassed. It is not an
isolated measurement of that API change: intervening commit `62ccd74c`
(`perf(automata): bypass large warm-owner checkout moves`) also directly
changes exact pooled K0 `exists`/span hot paths. The observed K0 gain therefore
combines ordinary accelerator admission with the warm-owner move bypass; the
non-K0 split only shows that the movement is K0-specific.

FRE is now about `1 / 0.791 = 1.26x` slower than Rust-regex on the hot primary
aggregate and `1.418x` faster than RE2. One-shot still pays fresh construction
and moved the other direction, particularly for K0 (`-10.64%` versus
Rust-regex and `-11.07%` versus RE2). These are independent runs and source
revisions, so neither the large K0 gain nor the smaller changes should be
treated as isolated causal effects.

## Normal Rebar regression result

Normal Rebar ran after holdout, with fresh preflight and the slowest points
first. The successful run started from 1,226 raw points, excluded 6
anonymous-description/raw-plan points, preflighted 1,220 points, and retained
1,152. It produced 2,304 successful arms with zero timing errors and balanced
576 AB with 576 BA points.

The current and owner-fast runs have exactly the same 1,152 executed tuples
under the comparison identity `(comparator, model, boundary, benchmark)`. The
sorted tuple files both hash to
`9a9b67e0d375eac6ed03734a3fa8ae748f8e6250077f2953cef6a2d9148ac793`;
their point IDs are also exactly equal. Full schedule hashes differ, as
expected for distinct source and run identities. Direct plan comparison shows
that only the 38 plain-grep entries changed adapter plan; the executed tuple
and point-ID populations remain equal.

| Scope | Owner-fast baseline | Rust-style ordinary | Change |
| --- | ---: | ---: | ---: |
| Overall | 2.172796 | 2.126565 | -2.13% |
| Rust-regex | 1.389277 | 1.366449 | -1.64% |
| RE2 | 3.777989 | 3.675087 | -2.72% |

Among Rebar timing boundaries, only plain grep intentionally changed API. Its
old adapter prepared one explicit session, kept its workspace checked out, and
lazily prepared and bound `PortableIsMatchValueToken` direct-accelerator routes
once for the operation. The fair Rust-style adapter instead builds one matcher
before timing and calls ordinary `is_match` once per `ByteSlice::lines`
domain, just as the Rust-regex adapter does.

| Comparator | Plain-grep boundary | Points | Baseline | Current | Change |
| --- | --- | ---: | ---: | ---: | ---: |
| Rust-regex | first | 10 | 0.538925 | 0.254358 | -52.80% |
| Rust-regex | steady | 10 | 0.538946 | 0.255229 | -52.64% |
| RE2 | first | 9 | 1.342479 | 0.597013 | -55.53% |
| RE2 | steady | 9 | 1.360491 | 0.603061 | -55.67% |

The regression is concentrated in K0, rather than being a uniform cost of the
automatic pool:

| FRE runtime class | Points | Baseline | Current | Change |
| --- | ---: | ---: | ---: | ---: |
| K0 | 28 | 0.721128 | 0.250697 | -65.24% |
| exact literal | 4 | 1.897512 | 2.049578 | +8.01% |
| ASCII word run | 4 | 1.153316 | 1.206787 | +4.64% |
| Unicode word run | 2 | 0.631159 | 0.490630 | -22.27% |

Two K0 benchmarks dominate. FRE's `whole-line` operation moved from about
3.2--3.4 ms to 284--291 ms, while `email` moved from about 20.3--20.7 ms to
231--234 ms. Removing their eight comparator/boundary points reduces the
30-point plain-grep change to `-6.54%` (0.599211 to 0.560021).

The primary missing mechanism is therefore automatic prepared/direct-
accelerator caching. The old session could select and retain specialized K0
routes such as its bound line-total and byte-class-delimiter matchers; the
ordinary pooled-value path does not yet expose the full route family. A
general fix is to move equivalent lazy, matcher-owned preparation behind the
ordinary API, without requiring callers to request a session. Each ordinary
line call also performs dispatch/admission and pool checkout/return, which may
explain part of the residual gap, but this run does not isolate those costs.
Rust-regex likewise accesses its hidden cache on every ordinary call.

As a control, the other 1,114 points retain their prior adapter boundaries.
Their overall geomean moved from 2.245026 to 2.254766 (`+0.43%`), with
Rust-regex `+0.72%` and RE2 `+0.08%`. The 38 changed plain-grep points explain
the direction of the full Rebar aggregate. Every Rebar point has only one
adjacent pair, so all of these Rebar comparisons are descriptive and do not
estimate run-to-run variance.

## Controller retry

The initial Rebar attempt built the candidate, then failed during KLV prepare
before preflight or timing. The controller had omitted `rebar klv -d .`, so
Rebar defaulted to its mini benchmark directory and could not match a
full-corpus benchmark definition. The retry changed only that controller
argument, preserved the exact source, workload manifest, semantic inventory,
and comparator binaries, then completed all 1,152 timing points. The failed
attempt contributes no measurements.

## Reproduction and limits

The machine-readable aggregate record is
[`rust-style-ordinary-search-c9g32-2026-08-19.json`](rust-style-ordinary-search-c9g32-2026-08-19.json).
The compact external evidence archive is
`c9g-normal-results-2a7befbf-20260819-r2-r3.tar.gz` (5,872,271 bytes),
SHA-256
`bf04c0f73ce88b0eb8aae97c4f9e07397903cdc662c4bce02d062aa601585dec`.
Its 183-file inclusion manifest hashes to
`b83f588740aa9b5fbc0648fec07968fff4dad1c38f2c62d4f1fb31a6536f1fbb`.
The exact source archive is `fre-2a7befbf-source.tar.gz`, SHA-256
`22ee7e648242aa2f85a8becf4805c35ec0908dc9205c379d0f0cdb3c9fac3b8e`.
The initial sequence bundle hashes to
`0fc0ed9e93253f5aff4764589c0deb4e0b234c09695a8bad0060a71c31d5d004`;
the corrected Rebar retry bundle hashes to
`0b0c09c974b8c1d0650b5dc91fb1eefe5913096d42a6c51b58c52f0ec8dccc02`.

The compact package retains raw holdout samples, Rebar preflight and timing
journals, schedules, receipts, provenance, logs, and independently reproduced
analyses. It excludes full source/build trees, copied executables, comparator
build caches, and 1,031 content-addressed prepared KLV cache files. Their
source/binary hashes and receipts remain, and every excluded KLV file is listed
in `EXCLUDED-KLV-INVENTORY.tsv`; each scheduled KLV was rehashed on the host.
All 48 ordinary packaged holdout-manifest entries match. The packaged
`driver.log` is the documented special case: its manifest hash matches the
prefix before the driver appended its final `COMPLETE` line, and the complete
log has a separately recorded hash.

The benchmark host is the persistent Spot instance `i-07141b3a31001d798`
(`c9g.8xlarge`, `us-east-1c`), and it was intentionally left running after the
campaign. The owner-fast baseline and this run are independent C9g runs rather
than a randomized same-process A/B, and source movement between the revisions
can affect points outside the API change.

AOT was not rerun. This report makes no combined normal/AOT headline: those
are different execution and lifecycle boundaries and must remain separately
labeled.
