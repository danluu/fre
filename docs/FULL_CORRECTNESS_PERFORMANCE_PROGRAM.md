# FRE full-correctness and performance program

Status: executable program contract, version 1

Program base: `a1a87d11f923973c4148743fcaddb119965c518b`

Rust compatibility target: `regex` 1.12.4, upstream Git
`7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1`

Rust component pins: `regex-automata` 0.4.14, `regex-syntax` 0.8.11

RE2 compatibility is a separate profile and a separate completion ledger.

This document turns the broad design in `WORLD_FASTEST_REGEX_DESIGN.md` into
an ordered, measurable execution program. Rebar is one semantic and performance
workload. It is not the definition of regex correctness.

## 1. Completion definitions

### 1.1 Full Rust correctness

FRE may claim full correctness for the Rust 1.12.4 profile only when all of the
following are true on an authenticated source head:

1. The complete pinned upstream inventory is present and hash-authenticated:
   `regex-test`, all TOML and Fowler data, all high-level integration tests,
   regressions, replacement/searcher tests, doctests, and declared feature
   configurations.
2. Every applicable expanded case has a receipt. There are no silent skips,
   missing cases, unclassified outcomes, mismatches, or faults.
3. There are no `unsupported` outcomes for the declared full Rust surface.
   Unsupported is useful as an intermediate capability state but is not a pass.
4. Rust text and bytes profiles agree on constructor acceptance, error class,
   match spans, complete non-overlapping iteration, every capture slot,
   empty-match progress, names/indices, Unicode and invalid-byte behavior.
5. Text and byte `RegexSet`, builder options, replacement/replacen, split/splitn,
   ranged searches, and stable public API behavior pass their upstream tests.
6. Every selectable production executor passes the common semantic corpus when
   forced directly. Planner reachability is not evidence of executor parity.
7. Every accepted plan has checked construction, persistent-memory, scratch,
   and execution-work bounds, with boundary and scaling tests.
8. Exhaustive small-case and persistent fuzz regressions are clean on the
   declared platform matrix.

An explicitly smaller product profile must use a different name and denominator.
It may not be reported as full Rust compatibility.

### 1.2 Full RE2 correctness

RE2 Perl/POSIX syntax, UTF-8/Latin-1 encoding, options, longest-match behavior,
sets, captures, replacement/consume operations, diagnostics, and `max_mem`
admission have a separate versioned ledger. Rust results cannot stand in for an
RE2 result. RE2 completion uses the same zero-mismatch, zero-fault, zero-silent-
skip rule for the surface FRE declares compatible.

### 1.3 Good performance

Performance is measured only after semantic identity for the measured operation
is authenticated. Construction, first call, steady execution, and whole-
operation reducers are separate boundaries.

The program has three performance thresholds:

1. **Cliff removal:** no fixed-corpus cell exceeds 2.0x the Rust baseline, and
   no comparable RE2 cell exceeds 2.0x RE2, outside declared noise. This is an
   interim engineering gate, not a speed claim.
2. **Competitive:** at least 90% of fixed cells are within 1.25x Rust, each
   operation-class geomean is no slower than Rust, and no material resource or
   tail-latency regression is hidden by aggregation.
3. **Good/final:** the sealed ordinary-workload geomean is at least 20% faster
   than Rust regex and no case is more than 5% slower outside noise. The literal
   strict gate additionally requires the lower confidence bound of the paired
   speed ratio to exceed 1.0 on every preregistered same-semantics Rebar cell.

Every report includes the denominator, supported count, every point result,
p50/p90/worst ratio, failures, unavailable comparators, allocations, peak and
persistent bytes, code bytes, and charged work counters. A geomean without this
information is invalid.

## 2. Current authenticated baseline

- Canonical `a1a87d11` supports 257 of 344 Rust-target Rebar jobs and returns 87
  typed unsupported outcomes.
- Private candidate `bdf1ca60` has sealed no-clock evidence for 296 pass and 48
  unsupported, with 39 gains and no lost base pass. It remains outside canonical
  main pending an authorized integration decision.
- The visible non-Rebar holdout has 1,014 receipts and current main produces
  1,014 exact passes with no unsupported outcome, but it is deliberately
  bytes-only, Unicode-off, capture-free, and non-normative for performance.
- `fre-conformance` is a small byte-only capture-free gate. It is not the
  upstream Rust suite.
- No imported complete upstream Rust test inventory or product-wide capability
  ledger currently exists.
- Existing broad performance evidence is incomplete and includes severe
  continuation and line-loop losses. There is no current-main whole-supported-
  matrix performance result.

These facts are the starting point, not release claims.

## 3. Ordered milestones

### C0: preserve and decide already-qualified work

Deliverables:

- independent disposition for every already-qualified candidate;
- immutable bundle, base/head/tree/diff and evidence hashes;
- explicit integrate, reject, or blocked reason;
- no candidate left indefinitely between qualification and decision.

Exit: every current qualified candidate has a final authenticated disposition.
This track runs concurrently with C1 and must not block it.

### C1: complete upstream Rust inventory and diagnostic runner

Deliverables:

- exact upstream source identity and file digest manifest;
- immutable inventory of the 23 packaged TOML corpora, the additional Fowler
  inputs referenced by the upstream runner, integration modules, doctests, and
  feature configurations;
- stable receipt schema with case ID, profile, operation, source digest,
  expected outcome, actual outcome, capability ID, and terminal class;
- adapters for Rust text, Rust bytes, text set, and byte set;
- explicit outcomes: `pass`, `expected-invalid`, `unsupported`, `mismatch`,
  `resource-mismatch`, `fault`, and `harness-error`;
- diagnostic current-main baseline with zero omitted applicable cases.

Exit: inventory authentication and runner selftests pass, every applicable case
is represented exactly once, and the baseline can be regenerated byte-for-byte.
Unsupported remains visible and counts against full completion.

### C2: broad portable semantic floor

Implement one bounded general executor and facade before adding more isolated
benchmark leaves. Work is divided by reusable semantic contract:

1. constructor/parser/admission and exact diagnostics;
2. text and arbitrary-byte single-pattern search;
3. complete iteration with adjacent-empty progress and original-haystack range
   context;
4. capture-preserving execution and capture metadata;
5. string and byte sets with exact pattern-ID semantics;
6. replacement/replacen and split/splitn;
7. checked resource admission and reusable scratch.

The portable floor may be slower than a specialized plan, but it must be
correct, bounded, and reusable. It may not execute Rust regex as part of FRE.

Exit: all upstream cases admitted by the implemented surface pass through the
portable floor; every remaining unsupported case has one stable capability ID,
an owner, and a closure test.

### C3: close the full high-level Rust suite

Prioritize unsupported clusters by number of upstream cases and architectural
fanout, not Rebar row count. Close in this order unless the inventory proves a
different dependency order:

1. constructor, syntax, flags, errors, Unicode and byte/text separation;
2. match selection, anchors/ranges, empty progress and iteration;
3. capture histories and metadata;
4. sets and multi-pattern behavior;
5. replacement and split APIs;
6. limits, large programs, regressions and API integration behavior.

Exit: 100% upstream inventory classified, zero mismatch/fault/harness error,
and zero unsupported for the declared full Rust profile.

### C4: independent and adversarial correctness

Deliverables:

- relevant `regex-syntax` acceptance/error suites;
- shared `regex-automata` corpus run against each forced FRE executor;
- exhaustive small AST/haystack records for text and arbitrary bytes;
- persistent fuzz targets for parser, lowerer, planner, iterator, captures,
  sets, replacement and artifact validation;
- allocation-failure, tiny-stack, malformed-artifact, cancellation and
  concurrency tests;
- macOS/Linux/Windows and x86-64/AArch64 qualification, plus sanitizer/Miri
  jobs where applicable.

Exit: all required gates pass on the declared platform matrix with retained,
reproducible evidence.

### P0: current-main complete performance runner

Deliverables:

- exact-current-main semantic manifest;
- all seven Rebar models: compile, count, count-spans, count-captures, grep,
  grep-captures, and regex-redux;
- arbitrary pattern-count support where required by the workload;
- Rust and RE2 comparators only for exact same-semantics cells;
- separate cold construction, allocator-warm construction, first execution,
  steady execution, whole-iteration/reducer and capture boundaries;
- coverage-denominator and pointwise report validation;
- deterministic dry-run/selftest that never invokes timing.

Exit: every semantically supported current-main cell is runnable, every omitted
or unavailable comparator is explicit, and report validation rejects hidden
rows or mixed boundaries.

### P1: eliminate architectural cliffs

Cluster losses by selected plan and hot path. Initial high-fanout priorities are:

- a reusable bounded Thompson/sparse-or-lazy-DFA path;
- literal and required-literal prefilters that retain exact priority;
- one-pass or otherwise linear aggregate iteration;
- reusable capture storage/history;
- value-only hot APIs that do not construct diagnostic reports in the timed
  boundary;
- construction and cache behavior for large pattern sets.

Each cluster receives multiple independent source attempts. Cheap semantic,
resource and work-counter screens run in parallel. Only qualifying finalists
enter serialized quiet timing.

Exit: the cliff-removal gate passes on the full fixed corpus.

### P2: competitive and good-performance qualification

Use Rebar plus a sealed companion suite covering:

- 4 KiB, 64 KiB, 1 MiB and 16 MiB inputs;
- early, late, absent and dense matches;
- ASCII, Unicode and invalid bytes;
- tiny/large patterns and small/large pattern sets;
- one-shot and reused construction;
- changing buffers, cold data, streaming/chunk boundaries and short-input
  batches;
- grep/search, captures, sets, replacement/split, regex-redux and aggregate
  operations;
- adversarial scaling and real text/source/log corpora.

Run on at least two x86-64 and two AArch64 microarchitectures. Freeze suite and
planner thresholds before final qualification.

Exit: competitive, then good/final thresholds in section 1.3 pass.

## 4. Continuous execution topology

The normal operating set is deliberately small in control-plane roles but
parallel in useful work:

- one coordinator/integrator owns canonical decisions;
- two current-main source implementers own independent branches;
- one independent qualification executor owns no-clock builds/tests and quiet
  timing only when authorized;
- one liveness watchdog owns no product source and may launch one bounded repair
  Codex when progress is blocked or stale.

Build and semantic test shards may use all safe cores concurrently. Independent
source attempts use private branches/worktrees and never share dirty state.
Timing remains serialized only because it requires a quiet machine.

At least one source/correctness task must remain runnable while timing or an
integration decision is pending. Waiting for a benchmark, verifier, or canonical
decision is never a reason to leave all source and semantic compute idle.

## 5. Admission and integration rules

1. Every source lane starts from exact current canonical main.
2. Every job declares a capability cluster or performance-loss cluster, expected
   invariant, focused tests, and affected upstream/Rebar identities.
3. Source commits never include binaries, targets, raw timing output, credentials
   or mutable live state.
4. A candidate must pass format, focused tests, strict Clippy, affected upstream
   cases, neighboring cases and resource/scaling gates before broad fanout.
5. Integration is single-writer exact-head compare-and-swap. A receipt says
   integrated only if its commit is an ancestor of canonical main.
6. Stale or conflicting work is checkpointed and parked, never destructively
   discarded without authorization.
7. No optimization may reduce the upstream-pass set, Rebar-pass set, resource
   guarantees, or forced-executor parity.
8. Every timed case records its case ID, exact phase, canonical head and
   toolchain, available wall and CPU elapsed observations (explicitly marking
   an unavailable clock), completion state (`completed`, `timeout`, or
   `cancelled`), any configured cutoff, and last substantive progress. A
   timeout or cancellation is a censored observation and is never reported as
   a completed build duration. Watchdog service levels, including the 20-minute
   slow-progress threshold below, are operational incident thresholds rather
   than benchmark measurements.

## 6. Liveness and utilization contract

Progress evidence is one of:

- a source commit or authenticated dirty checkpoint;
- a new test/inventory capability delta;
- a completed focused/broad semantic gate;
- a completed performance measurement with an immutable result;
- a final candidate disposition or integration receipt;
- a precise blocker with owner, scope, created time, expiry and authorized clear.

Chat messages, worker counts and control receipts without a product/evidence
delta are not progress.

The watchdog applies these service levels:

- `BLOCKED`: open an incident and invoke repair immediately;
- `ACTIVE` without a heartbeat for 5 minutes: record a stalled-owner incident;
- `ACTIVE` with heartbeats but no progress evidence for 20 minutes: record a
  slow-progress incident and invoke repair;
- no runnable source/correctness work while the machine is materially idle for
  10 minutes: invoke backlog-refill repair;
- a monitor heartbeat older than 2 minutes is itself a failure.

The watchdog is generation/state-hash deduplicated, singleton-locked and
cooldown-bounded. It may invoke at most one repair Codex at a time. The repair
Codex works only in a dedicated private worktree and may inspect evidence,
repair control code there, or start the next bounded source/correctness unit.
It may not move canonical main, clear benchmark stops, mutate live queues,
perform timing, or bypass an existing owner-scoped stop.

Every incident records trigger, observed state hash, age, machine utilization,
Codex command identity, launch/result timestamps and disposition. Malformed or
symlinked state fails closed.

## 7. Dashboard and cadence

The single dashboard is keyed to exact canonical head and contains:

- upstream Rust expanded pass/unsupported/mismatch/fault totals by profile,
  operation and capability ID;
- Rebar pass/unsupported totals as a secondary workload column;
- forced-executor parity totals;
- fuzz/exhaustive/platform gate status;
- performance coverage denominator, per-operation geomeans, p90 and worst case;
- current active lanes, last substantive progress age, blockers and watchdog
  incidents;
- qualified candidates awaiting disposition.

Cadence:

- focused affected tests on every source checkpoint;
- upstream shard and workspace checks on every integration candidate;
- complete upstream semantic run at each canonical integration point;
- current-main stratified performance run nightly once P0 is ready and timing is
  authorized;
- full all-row/all-platform qualification at milestones.

## 8. Initial work issued from this program

The first concurrent units are:

1. upstream Rust 1.12.4 inventory, receipt schema and no-silent-skip adapter
   scaffold on `correctness/upstream-regex-conformance`;
2. all-seven-model, exact-current-main performance contract and dry-run validator
   on `performance/current-main-all-model-gate`;
3. strict watchdog, fake-Codex selftests and persistent deployment on
   `program/full-correctness-performance-control`;
4. preserve the sealed 296/344 candidate and obtain an authorized final
   disposition without blocking units 1--3.

The next source unit is selected from the upstream diagnostic baseline by
largest reusable capability cluster. Until that baseline exists, additional
Rebar-only leaf support is not the primary correctness priority.
