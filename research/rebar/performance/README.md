# Immutable tested-source Rebar performance contract

`tested-source-a1a87d11-contract.json` is an executable historical coverage
and reporting contract, not a timing result and not a gate on the current live
`refs/heads/main`. It binds the immutable tested source commit and tree, its
independently reproduced semantic receipt set, all 344 Rust-target rows, all
seven Rebar models, and the lifecycle boundaries that must be reported for
each supported row. The command resolves that exact commit object in the
provided repository; advancing `main` neither invalidates nor silently
retargets this evidence. A new source frontier requires a new contract.

Existing observation, schedule, and packet wire schemas retain the field names
`canonical_commit` and `canonical_tree` for compatibility. In a v2 contract
those fields carry the immutable `tested_source` identity; they are never
re-resolved from the live canonical ref.

The contract deliberately keeps all 87 unsupported rows in the denominator.
A pointwise observation artifact has exactly one row for every semantic FRE
receipt. Supported rows report every required lifecycle boundary against Rust
regex and RE2; an absent or semantically nonpassing reference remains an
explicit `not-comparable` point with a reason. Unsupported rows retain their
exact semantic reason. A qualification artifact cannot contain `pending`
points, and no aggregate can substitute for a missing or failed point.

Validate only the contract and immutable tested-source identity:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  validate-contract \
  research/rebar/performance/tested-source-a1a87d11-contract.json \
  /Users/danluu/dev/fre
```

Authenticate the bound full semantic report and its exact 344-row universe:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  validate-semantic \
  research/rebar/performance/tested-source-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json
```

Generate a new coverage-complete pending draft without running timing:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  generate-draft \
  research/rebar/performance/tested-source-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json \
  /new/path/tested-source-draft.json
```

Generation refuses to overwrite an existing output. The compact JSON contains
exactly 344 sorted semantic job IDs. Each supported row has its contracted
lifecycle boundaries and an explicit Rust/RE2 placeholder. A passing semantic
reference is `pending`; a missing or nonpassing reference is
`not-comparable` with a reason. The generator validates its own output before
publication.

Generate the canonical all-model fresh-process pair schedule without running
any benchmark:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  generate-pair-schedule \
  research/rebar/performance/tested-source-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json \
  /new/path/tested-source-pair-schedule.json
```

For the accepted tested-source report this produces 5,772 six-pair slots and
11,544 fresh-process arms across 962 available lifecycle/comparator points.
The other 66 points remain explicit unavailable records with their exact
semantic reasons. The schedule covers every supported model and boundary;
`regex-redux` has no slots because its sole current FRE row is semantically
unsupported. Schedule publication is canonical, deterministic, and
non-overwriting.

Generate the deterministic current-FRE runner admission manifest without
executing a benchmark:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  generate-runner-manifest \
  research/rebar/performance/tested-source-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json \
  /new/path/tested-source-runner-manifest.json
```

For the accepted report this binds all 257 supported rows to an exact runner
family: 234 one-pattern aggregate rows, four ordered multi-pattern aggregate
rows, 11 portable grep rows, and eight capture rows. The four multi-pattern
rows are the dictionary compile/count pair, the Nosey Parker compile row, and
the literal-alternation pattern-per-word count row. Candidate plan names and
pattern multiplicity are checked together, so an unknown plan or a
single/multi alias fails closed. The manifest also recomputes the exact 5,772
pair slots and 66 unavailable points from the semantic universe. This is an
execution admission artifact; it does not itself run timing.

Each scheduled arm has one canonical `fre.rebar.performance-raw.v2` record.
It binds the exact contract/tested-source/semantic identity, job, model, lifecycle
boundary, comparator and candidate/reference role, complete input and reducer,
candidate plan where applicable, exact cold/allocator-initialized/built/primed
process-artifact preparation, lifecycle prime count, one measured operation,
and a unique fresh-process token. The all-model converter requires
the exact 5,772 schedule slots in order, rejects missing/reordered arms or any
token reuse, and deterministically replaces all 962 available timing
placeholders while preserving all 66 unavailable points and every independent
resource field. Fixed-duration fixtures exercise this complete conversion
without reading a clock.

Validate a coverage-complete draft or final pointwise observation file:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  validate-observations \
  research/rebar/performance/tested-source-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json \
  /absolute/path/to/observations.json
```

These units do not execute a benchmark. The FRE KLV runner now has
authenticated, already-built lifecycle producers for the three supported
`count-captures` rows and five supported `grep-captures` rows: the first call
is the first-operation boundary and repeated calls on the same artifact are
steady-operation boundaries. Capture runner invocations now require an exact
boundary plus contract/tested-source/semantic/job identity. They emit canonical
`fre.rebar.capture-lifecycle-raw.v1` JSON: first-operation records have no
prime; steady-operation records authenticate one untimed successful prime
before their single measured call, and every arm carries a unique fresh-process
token. Raw records can be checked with:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  validate-capture-observation \
  research/rebar/performance/tested-source-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json \
  /absolute/path/to/raw-capture.json
```

The deterministic capture scheduler expands the current semantic frontier to
192 six-pair slots (384 unique process arms): eight supported rows, two
boundaries, and both passing comparators. It alternates candidate/reference
order and rejects missing, extra, reordered, identity-mismatched, or
process-token-reusing evidence. Complete fixed-duration evidence converts 32
pending capture comparison points to measured points in the original 344-row
draft. Semantically missing/nonpassing comparators receive no slots and remain
explicitly `not-comparable`.

Observation schema v2 keeps timing and resource state independent at every
exact job/boundary/comparator point. Each candidate and reference arm reports
allocator-call count, allocated bytes, bytes still live after the boundary,
and process peak RSS through an expected collector ID and immutable collector
digest. The canonical `fre.rebar.performance-resource-raw.v1` record also binds
tested-source/semantic/input/result, candidate plan or reference role, exact
lifecycle preparation and priming, and a unique process token. On the accepted
frontier, 46,176 raw metric samples (5,772 pairs times two arms times four
metrics) convert to 7,696 measured resource summaries while the 66 semantic
unavailable points retain 528 distinct `not-comparable` arm/metric summaries.
The complete synthetic frontier converts all 8,224 summaries.
Each metric can be explicitly unavailable for one engine without fabricating a
zero or erasing other measured metrics; mixed states or inconsistent reasons
inside a six-sample set are rejected. Cold compile, allocator-warm compile,
first-operation, steady-operation, and composite resource medians remain
distinct lifecycle observations.

The FRE KLV candidate runner accepts ordered multi-pattern inputs for
`compile`, `count`, and `count-spans`, uses the same authenticated builder,
limits, source-order/profile checks, and selected-plan labels as semantic
qualification, and preserves fresh construction for compile versus retained
construction for operation models. Other models remain exactly one-pattern.
Its legacy mode remains separate.
The shared aggregate lifecycle API additionally defers every compile
construction so it can be measured before untimed verification, while
`count`/`count-spans` retain one authenticated single- or multi-pattern
artifact that can be called once for first-operation or primed once and called
again for steady-operation. Input length, pattern order, profile, operation,
selected plan, and derived limits remain bound at each step.
The all-model candidate raw producer rejects malformed identity and invalid
model/boundary combinations before invoking its measurement closure, derives
the exact preparation/prime state, and emits canonical
`fre.rebar.performance-raw.v2` with ordered input hashes, comparator, plan,
selected grep runtime when applicable, result digest, and fresh-process token.
The runner is never given the semantic reducer. It copies the measured reducer
into the raw compatibility fields, and only the trusted contract validator
joins that value to the independently authenticated semantic row.
Fixed-duration tests prove its output passes the complete semantic-contract
validator. Explicit `--performance-raw`
runner mode connects these seams for all 257 supported rows and all 5,772
candidate pair-slot arms: cold compile constructs once; allocator-warm
compile constructs and drops a distinct sacrificial artifact before measuring
a fresh one; first operation uses a built artifact with no prime; steady
operation performs exactly one untimed prime on the same artifact and requires
the prime and measured reducers to agree.
Formal count operations and post-timing compile verification enumerate every
complete match bound instead of accepting a count-only shortcut. Capture
first/steady boundaries materialize every capture array, inspect every slot,
and use the same retained history lifecycle and exact prime rule while
emitting the generic all-model schema.
Grep retains one constructed matcher/session across its first or primed steady
whole-line operation and records the construction-selected K0 or linear
ASCII/Unicode word-run runtime after checking it against the expected runtime.
The emitted record binds every required identity and recomputes the ordered
input hashes from KLV bytes.

In all-model raw mode, the authenticated candidate runner derives that grep
runtime from the artifact it actually constructed and emits it in the raw arm.
An optional runtime expectation can reject a mismatch, but the executor does
not need a benchmark-name alias table to manufacture the selected runtime.

`reference_rebar_runner` emits the matching reference arm by authenticating an
internally pinned upstream runner digest and version, copying the authenticated
bounded bytes to a new private mode-0500 executable, and invoking that copy as
a fresh process. It validates the exact LF-terminated nonzero sample set and
every reducer, rehashes the private executable afterward, and removes its
mode-0700 staging directory before accepting output. The upstream shared timer's
one-iteration policy implements cold compile or first operation. For
allocator-warm compile and steady operation, the wrapper instead requires two
visible iterations with no hidden warmup and a maximum duration that cannot
terminate the fixed two-iteration loop: it requires both emitted reducers to
agree, discards the first duration, and publishes the second. The independently
authenticated semantic validator subsequently checks that published reducer.
Compile consumes and drops the first artifact before constructing the
second; operation models retain the same artifact across both calls. This
avoids treating the upstream timer's unreported warmup reducer as a verified
prime. The wrapper rejects any other lifecycle KLV and emits the same
canonical all-model raw schema without a candidate plan or runtime.
Rust-regex accepts the admitted ordered multi-pattern rows; the pinned RE2
runner is exactly single-pattern, so the semantic contract keeps those RE2
points explicitly unavailable. Fixed-duration tests exercise every
model/boundary without launching a runner or reading a clock.

The pair executor remains responsible for deriving the KLV from the
authenticated semantic row, supplying independently authenticated non-answer
identity fields and a unique process token, and running the complete raw-arm
contract validator before accepting wrapper output; caller strings alone do
not admit a result. It must also enforce a wall/process-group deadline around
each fresh process. The wrapper drains child output concurrently with bounded
retention, but an exact binary that never exits is an executor-level timeout,
not a valid raw arm. Unix owner-only staging prevents accidental cross-worker
path reuse and detects persistent inode/ownership/mode changes; adversarial
same-UID mutation between the final pathname check and `exec` is outside this
wrapper's threat boundary and requires executor isolation or descriptor-based
execution.

The canonical `fre.rebar.performance-execution-packet.v1` closes the
authorization boundary before that executor runs. Its independently published
digest binds the exact contract, accepted semantic report, expanded Rebar
manifest, complete pair schedule, runner manifest, executor, candidate and
reference wrappers, per-comparator upstream runtimes and versions, timing
authority, and hard process/I/O limits. Validation recomputes every
contract-derived digest and requires each reference runtime to equal the
matching semantic adapter; accepting a packet and an expected hash from one
unauthenticated command line is explicitly insufficient. A separate canonical
`fre.rebar.performance-pair-task.v1` declares two distinct process tokens for
one exact schedule sequence and attempt ID. A still-required atomic executor
ledger must reserve and consume those tokens, reject replay, and require a new
prepublished task for every retry. These records are source-only admission
primitives; the executor must authenticate the lease and binaries, derive the
two lifecycle-specific KLV forms, run each arm in exact counterbalanced order,
and publish a provenance envelope rather than accepting naked pair JSON.

The performance gate still needs the authenticated pair executor and resource
collector, and `regex-redux` after semantic support exists.
