# Continuous breadth and performance execution

Status: effective execution directive for the 189-pass Rebar frontier. This
replaces the stale 161-pass pool allocation in the private July 15 breadth
override. It does not relax semantic, resource, benchmark-authentication, disk,
or source-only Git rules.

## Authenticated starting point

The latest full semantic report was generated from source `35b22ac` and has
SHA-256 `132e6c75034fe6ff720af3511eca8779ebb0dd9266c243dbc9061a5157209607`.
It records 189 pass and 155 typed unsupported Rust-target jobs, with no FRE
failure or fault:

| model | pass | unsupported |
| --- | ---: | ---: |
| compile | 17 | 16 |
| count | 62 | 71 |
| count-spans | 101 | 28 |
| count-captures | 0 | 15 |
| grep | 9 | 2 |
| grep-captures | 0 | 22 |
| regex-redux | 0 | 1 |

Canonical main `816c5ac` contains the same qualified engine frontier plus the
source for the authenticated stratified timing runner. The two ordered
build-many passes account for only two rows and therefore remain a performance
screening target, not the center of the implementation portfolio.

## Objective and selection rule

Maximize correct, broadly fast semantics per wall-clock hour. Select work by
the product of reusable semantic fanout, benchmark-family diversity, operation-
model diversity, and plausible asymptotic quality, discounted by integration
and correctness risk. Raw row count is evidence, not the objective. A small
initial unlock is worthwhile only when it establishes a shared mechanism with
a concrete near-term path to more families or models.

Do not implement job-name branches, fixture recognition, cached answers,
benchmark-specific parsers, or verification through a competing engine. A
`compile` result must be an executable FRE artifact; untimed semantic
verification must execute that artifact. Constructing an inert FRE object and
using Rust regex to verify the haystack is a failed candidate, regardless of
the reported support count.

At least four of the six rolling implementation slots must attack shared engine
mechanisms. At most one slot may tune an already-supported leaf family, and
only when the change applies to a material supported or soon-supported cluster.
The sixth slot is a rotating contrarian implementation, not another manager.

## Engine direction

Keep construction-selected specialized paths for shapes where they are
materially faster. Add a small number of shared compiled or streaming
mechanisms for the long tail; do not grow a collection of operation-specific
interpreters.

The current high-fanout mechanisms, in order, are:

1. direct or shared Unicode scalar-class execution with one forward pass over
   valid and invalid UTF-8, reusable by compile, count, span, and grep surfaces;
2. leftmost-first capture selection followed by exact-span tagged replay, so
   capture history work is linear in the haystack plus selected spans rather
   than restarting a Pike simulation at every byte;
3. finite-language or shared-state aggregate plans that remove the 45 bounded
   resource refusals without merely increasing a quota;
4. ordered multi-pattern construction whose priority semantics and retained
   storage remain bounded on large dictionaries and adverse shared prefixes;
5. the composite regex-redux surface after its constituent execution and
   replacement primitives are independently real.

A broad production path must publish its asymptotic work and persistent/scratch
space. In particular, an `O(haystack_bytes * query_states)` Unicode or capture
path is research substrate, not a production coverage win when a one-pass
alternative is available. Preserve existing plan identity and specialized
dispatch unless pointwise evidence justifies a change.

## Execution topology

The loop has five independently progressing roles:

1. **G0 integrator/implementer.** Window 3 always owns one concrete current-main
   high-fanout implementation or integration. It never waits for an Ultra
   thought process, audit, pool cohort, or benchmark result when another safe
   source step is available.
2. **Continuous blind implementation pool.** Keep three High and three Ultra
   Codex sessions active in isolated worktrees with distinct nonces and
   personas. Initial assignments cover two Unicode mechanisms, two capture
   mechanisms, resource/finite-language, ordered build-many, regex-redux,
   timing adapters, and broad contrarian designs. Refill a terminal slot within
   60 seconds. Exhausting a numbered wave automatically starts fresh independent
   attempts on the highest-value unresolved mechanisms until an explicit stop
   or base-refresh sentinel appears.
3. **Candidate-local qualification.** A worker compiles and runs focused tests
   before returning `SCREEN` or `KILL`. Builds and semantic tests use isolated
   build directories and authenticated concurrent resource holders. A long
   source-only phase is forbidden: it transfers compile failures to G0 and
   recreates the integration bottleneck.
4. **Out-of-band audits.** Contrarian correctness, performance, and benchmark-
   integrity reviews run concurrently. They may block a candidate only with a
   reproducible semantic violation, invalid benchmark boundary, asymptotic
   failure, or resource-safety failure. Routine review prose never blocks G0.
5. **Evidence lanes.** Focused gates start first. Independent full semantic
   reports may run two at a time when the coordinator proves disk/RAM safety;
   they need not be serialized merely because each runner is single-threaded.
   Noisy performance timing remains isolated and serialized. Artifact builds,
   semantic reports, source implementation, and out-of-band reasoning continue
   while timing runs.

Candidates are consumed as soon as they become ready; there is no cohort
barrier. G0 performs a bounded source/provenance review, replays the candidate
onto current main, runs its focused gates, and either launches full evidence or
records a specific kill reason. A candidate that needs a redesign goes back to
an implementation lane rather than occupying the integrator indefinitely.

## Qualification and performance

Every assignment and promotion records:

- exact clean base and source-only commit SHA;
- affected unsupported rows, families, and operation models;
- shared mechanism and semantic invariant;
- worst-case time, persistent space, and scratch space;
- focused positive, rejection, invalid-byte, empty-match, window/anchor, and
  leftmost-first adversaries as applicable;
- a scaling counter that distinguishes linear from quadratic work;
- projected support before a report and authenticated support only afterward;
- pointwise performance cells and explicit remaining uncertainty.

For shared execution changes, the timing matrix includes exact literal,
class/alternation, repetition, Unicode, and capture or multi-pattern shapes as
applicable; early, late, and absent matches; at least two haystack sizes; cold
construction and hot execution; and unchanged neighboring plans. Compare with
Rust regex 1.12.4 and the pinned RE2 adapter wherever the Rebar row has that
target. Report every pointwise ratio and coverage count. A geomean may summarize
a complete, explicitly included set, but it cannot hide a material regression
or stand in for unmeasured count/span/capture execution.

The first authenticated compile slice covers five strata. Its FRE/Rust time-
ratio geomean is 0.367 and its FRE/RE2 ratio geomean is 1.196; FRE wins four of
five Rust points and two of five RE2 points. This is compile evidence only, not
an overall performance result. Count and span timing, especially for Unicode
and ordered build-many, remains a promotion gate.

## Non-idling and recovery

- Commit coherent source/tests/docs checkpoints at least every 20 minutes while
  committable work exists. Never commit binaries, targets, logs, generated
  reports, timing data, or control state.
- G0 produces or consumes a source-bearing decision every 30 minutes. The pool
  targets at least two tested source checkpoints and four dispositions per hour.
- When a plausible built candidate exists, keep a focused or full semantic gate
  active or pending. When timing evidence is needed and the isolated timing lane
  is free, start it without waiting for another user prompt.
- If there is no source-bearing decision for 30 minutes, automatically put G0
  and two fresh blind workers on independent implementations of the highest-
  fanout unresolved mechanism. Suspend coordination-only work until one reaches
  a focused gate.
- Every two hours, compare authenticated coverage, tested attempts, integration
  decisions, and benchmark duty cycle with the former single-agent goal-mode
  floor. If the parallel system does not exceed it, remove manager/audit layers
  before reducing direct implementers.
- Deep reasoning is always out of band. An Ultra session may keep thinking, but
  it may not reserve G0, a build holder, or the benchmark lane while idle.

Keep Gutenberg running. Preserve at least 20 GiB free. Never interrupt an
active timed benchmark. Reclaim only disposable build/cache artifacts with
authenticated ownership; never remove source worktrees or evidence needed by an
active candidate. Keep canonical main clean except during a bounded integration
and recover an unmerged state before launching full reports.

## Immediate portfolio

G0's immediate source priority is the linear streaming-capture replay already
past its focused structural gate, followed by current-main qualification. A
separate direct Unicode-scalar lane owns the one-pass non-singleton class path.
The continuous pool supplies independent Unicode, capture, finite-language,
multi-pattern, regex-redux, timing-adapter, and contrarian attempts. Ordered
build-many receives adverse timing and resource screening, but its two-row gain
does not displace Unicode, captures, or the resource frontier.

The next canonical frontier is accepted only after two independently generated
full reports agree byte-for-byte, report zero failures/faults, and preserve all
189 existing passes. Performance promotion remains pointwise and cannot be
inferred from semantic coverage.
