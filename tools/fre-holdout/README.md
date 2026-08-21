# `fre-holdout`

`fre-holdout` is the standalone runner for the frozen non-Rebar qualification corpus in `../../research/holdout`.

Its modules are kept as explicit stages analogous to a regex implementation pipeline:

1. deserialize and semantically validate the suite contract;
2. deterministically expand explicit, seeded-byte, and repeated-byte generators;
3. authenticate raw files, canonical expansion, and exact counts;
4. execute the pinned Rust-regex byte oracle;
5. adapt the FRE portable facade and classify typed refusals versus faults;
6. emit deterministic per-operation correctness receipts and enforce the semantic gate;
7. optionally emit a separate, non-normative two-engine timing report.

The separate `run-aot-selected-end` command exercises a different candidate
boundary. It compiles `OutputContract::SelectedEnd` in optimizing mode,
publishes the self-contained object directly in memory through the strict-W^X
loader, and invokes only that native entry. It never substitutes the portable
FRE facade when compilation or publication declines.

The stages are public where packaging or integration needs them (`authenticate_*`, `expand_manifest`, `run_correctness`, `run_performance`, and `enforce_strict_gate`) and otherwise small private functions with focused unit tests. The candidate adapter is the only layer coupled to FRE error families; generators, authentication, oracle values, coverage, and report schemas can be tested independently.

Performance schema v4 treats the suite's warmup and measurement counts as repetitions per expanded input for operation timing. Both phases execute complete input sweeps. Each measured operation record carries its case (from the containing series), input ordinal, and repetition index, so FRE and Rust-regex samples can be matched on the same haystack before computing ratios. Build series still apply the policy counts once per case pattern because builds do not consume a haystack.

Schema v4 times the equivalent ordinary APIs on both engines: `find` for spans, `is_match` for existence, and one `find` followed by match-end projection for the selected-end diagnostic. Neither API accepts a per-search work quota, and no FRE facade accounting report is constructed inside those clock samples. An engine may still maintain implementation-private counters internally. The deterministic correctness pass remains finite and accounted, and additionally checks every ordinary FRE result against its finite accounted result and the Rust-regex oracle outside the timing boundary.

The runner intentionally does not contain Rebar integration, benchmark tuning, JIT control, or a hidden corpus. Read `../../research/holdout/README.md` for the exact frozen identity, semantic and timing boundaries, current coverage, limitations, and integration commands.

## Native AOT SelectedEnd adapter

Native correctness has its own clock-free
`fre.holdout.aot-selected-end.correctness.v1` schema. There is one build receipt
per frozen pattern and exactly two comparison receipts per expanded input: its
exact full window and a deterministic derived haystack with a bounded,
nonzero-start midscan window. The frozen 169-input suite therefore has exactly
338 authenticated search-window receipts. The derived form is
`MIDSCAN_PREFIX || authenticated_input || MIDSCAN_SUFFIX`, with the exact
interior window `[prefix_bytes, prefix_bytes + input_bytes)`. The loader passes
the full derived haystack length plus the bounded start/end, exactly matching
the same compiled artifact's portable `SearchWindow` contract. Thus the suffix
remains visible to `\z`, the prefix remains visible to `\A`, and neither
interior boundary is silently redefined as a text boundary.
Successful patterns retain compiler route, object identity, machine geometry,
optimization-pass, and executable-mapping accounting. Compile/publication
declines and faults remain attached to every affected input; they are not
dropped and do not fall back to a portable engine. Every applicable native
result must equal `CompiledRegex::search()` on the same artifact, full haystack,
and `SearchWindow`. Full windows additionally equal pinned
`regex::bytes` 1.12.4. Bounded windows additionally use regex-automata 0.4.15
`Input::span` over the full haystack. This preserves absolute `\A` and `\z`
context, so every one of the 169 bounded windows receives an independent
comparison as well as mandatory native-versus-portable same-artifact parity.

The report records the exact compiler target and feature bits, current-thread
SVE vector length when SVE is enabled, source/build/executable/host provenance,
the explicit effective compiler and in-memory publication ceilings, and a
digest binding those receipts to all case and window results. Structural
validation recomputes the authenticated matrix, oracle expectations, terminal
closure, coverage maps, limit policy, and digest. Allocation, invariant, and
impossible post-host failures are faults; explicit resource/capability limits
remain declines.
The build embeds separate SHA-256 digests of exact Git status bytes, the tracked
binary diff with external diff and text conversion disabled, and framed
untracked path/content bytes. Any snapshot-command failure aborts instead of
becoming digest input. Runtime must reproduce all three before correctness or
timing begins; equal `dirty` labels with different patches are rejected.

Run that correctness gate without clocks:

```sh
cargo run --release -p fre-holdout -- run-aot-selected-end \
  research/holdout/suite.json \
  research/holdout/schema.json \
  research/holdout/digests.json \
  /tmp/fre-holdout-aot-selected-end-correctness.json
```

The strict gate rejects semantic mismatches and implementation faults.
Capability or resource declines remain visible coverage gaps.

Adding `--performance OUTPUT` emits the separate non-normative
`fre.holdout.aot-selected-end.performance.v1` report. For each identical
authenticated full or midscan window and repetition it pairs:

- a fresh AOT compile, in-memory publish, first native scan, and enclosing
  compile-plus-publish-plus-first-scan transaction with a fresh
  regex-automata meta compile and first full-haystack `Input::span` scan; and
- a call on one AOT matcher published outside the hot loop with a call on one
  regex-automata meta matcher built outside that loop. Every authenticated
  bounded window, including patterns containing `\A`, is measured.

Before any clock starts, the runner revalidates correctness, enforces the
mismatch/fault gate and a native-readiness floor, reconstructs the exact
correctness target, and verifies current host features and SVE vector length.
It also computes a checked maximum of 65,536 timing observations before timing
schedule or receipt allocation. The frozen 338-window, 19-case, 3-warmup,
9-measurement campaign accounts for 16,262 paired-engine and hot-setup
observations, and the exact budget is serialized and revalidated.
Every warmup and measurement sweep is a recorded SHA-256-seeded permutation of
all 338 windows; adjacent sweeps use a permutation and its exact reverse, while
engine-first order alternates per input. Warmup and measured observations both
retain declines, mismatches, and faults. The report separately exposes cold and
published-hot points, recomputable coverage, and a timing-receipt digest.

With the frozen 3-warmup/9-measurement policy this command performs a fresh
pair of builds for every search window in every cold sweep, so it is
intentionally much longer than the correctness-only command:

```sh
cargo run --release -p fre-holdout -- run-aot-selected-end \
  research/holdout/suite.json \
  research/holdout/schema.json \
  research/holdout/digests.json \
  /tmp/fre-holdout-aot-selected-end-correctness.json \
  --performance /tmp/fre-holdout-aot-selected-end-performance.json
```

Neither this report nor its engine labels describe portable FRE timing.

## Default-off V2 policy comparison

`run-aot-selected-end-v2-experiment` is a separate opt-in command. It does not
change `run-aot-selected-end`, `run`, or any production compiler default. For
every one of the 19 frozen cases it independently issues explicit
`CompileRequestV2` requests for `Automatic` and
`ForceStructurallyEligible`, publishes each successful artifact, and retains
compile/publication declines, faults, and forced requests that returned only
their incumbent fallback.

The clock-free report has two policy receipts for each of the 338 authenticated
full/bounded windows. Each ready artifact must agree with its own portable
`CompiledRegex::search` result and the independent full or bounded oracle. The
supplemental schema and optimizer version, requested policy, selection basis,
route-binding digest, semantic-program artifact identity, module/object
identity, and published identity are all bound into the case and report
digests. Forced evidence is rejected if it appears in the stable V1 receipt.

A case enters the frozen eligible list only when the forced supplemental
receipt contains an authenticated `ForcedStructuralEligibility` report.
Automatic selection, compile or publication duration, publication success,
and search results do not participate in eligibility. A successful forced
request without that report is explicitly `structurally-ineligible`; it is not
renamed as the forced route. The eligibility digest covers all eligible,
ineligible, declined, and faulted cases before any timing clock is read.

Run only the clock-free comparison:

```sh
cargo run --release -p fre-holdout -- \
  run-aot-selected-end-v2-experiment \
  research/holdout/suite.json \
  research/holdout/schema.json \
  research/holdout/digests.json \
  /tmp/fre-holdout-aot-selected-end-v2-correctness.json
```

The optional `--performance OUTPUT` path validates the correctness report,
strict gate, frozen eligibility digest, target/SVE evidence, source and
executable provenance, two-policy readiness, and a checked 65,536-observation
cap before its first clock. It constructs one matcher per policy and eligible
case, records compile and publish durations only as separate setup fields, and
then runs deterministic paired hot sweeps over the eligible full/bounded
windows. Adjacent sweeps use a permutation and its reverse, and first-policy
order alternates for every input. Timing remains non-normative and cannot
change correctness or eligibility.

An empty frozen eligible set makes `--performance` inadmissible: the command
returns an error before constructing any timing clock and writes no performance
report. Incumbent fallbacks therefore cannot silently enter a timing cohort.
