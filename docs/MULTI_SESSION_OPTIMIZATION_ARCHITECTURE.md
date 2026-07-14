# FRE multi-session optimization architecture

This document defines the agent and execution architecture used to search for,
falsify, implement, and qualify FRE optimizations. It is a process contract,
not an implementation or performance claim. Engine status remains in
[`PROGRESS.md`](PROGRESS.md), code boundaries remain in
[`IMPLEMENTATION_ARCHITECTURE.md`](IMPLEMENTATION_ARCHITECTURE.md), and open
release blockers remain in [`RISK_REGISTER.md`](RISK_REGISTER.md).

## Objective

Optimization attempts made by language models have high outcome variance. A
single attempt, or even a small council discussing one attempt, is therefore a
poor search strategy. FRE uses many blind independent attempts to improve the
chance of finding a good design, followed by increasingly narrow correctness
and measurement gates.

If one independent attempt has probability `p` of finding a useful candidate,
the probability that at least one of `N` attempts succeeds is
`1 - (1 - p)^N`. For example, at `p = 0.10`, four attempts give about a 34%
chance, sixteen give about 81%, and thirty-two give about 97%. Real attempts
are correlated, so FRE varies personas, context, and proposed mechanisms as
well as random sampling.

The system is intentionally:

- wide during read-only discovery, falsification, and audit;
- narrower during source mutation and prototype construction;
- serialized during local validation and performance measurement;
- evidence-driven at every reduction step.

The steady-state pipeline overlaps four generations of work:

```text
benchmark N-1 | validate and audit N | implement N+1 | research N+2
```

No global barrier waits for every session. A candidate may wait inside its own
lane while unrelated lanes continue.

## Top-level session architecture

These are independent top-level Codex sessions with explicit model and
reasoning settings. They are not children of the integration session. This
prevents all roles from inheriting Ultra latency and keeps audit contexts
independent of implementation narration.

| Session | Reasoning/persona | Authority and responsibility |
|---|---|---|
| `D0` dispatcher | Medium or High pragmatic project lead | Own the dependency-aware queue, issue immutable job packets, keep lanes supplied, and perform no implementation. |
| `I0` canonical integrator, currently Window 3 | High release engineer | Own the canonical branch, canonical Git index, integration decisions, and promotion state. |
| `W1` native writer | High compiler engineer | Own Kernel IR, AArch64, native aggregate, and runtime work in an isolated worktree. |
| `W2` semantic writer | High regex engineer | Own Unicode, assertions, compatibility identity, and admission work in an isolated worktree. |
| `W3` optional tooling writer | High tooling engineer | Exist only when assigned paths are disjoint from both primary writers. |
| `V0` validation marshal | Medium execution operator | Sole scheduler for builds, focused tests, differential tests, exhaustive tests, and fuzzing. |
| `B0` benchmark marshal | Medium measurement operator | Sole authority for timed runs and canonical performance conclusions. |
| `U*` research and audit pool | Ultra, read-only personas | Run independent blind attempts against immutable inputs and return structured evidence. |

The canonical integrator remains the sole owner of the integration branch.
Under the current repository directive, writing sessions do not stage or
commit; the integrator checkpoints their worktrees. If that handoff becomes a
measured serial bottleneck, it must be reported rather than silently weakening
the Git rule.

## Optimization tournament

Every material optimization target runs as a staged best-of-many tournament.
The counts are starting ranges, not hard ceilings. Account or service limits
may require waves rather than one simultaneous launch.

### Stage 1: discovery, 16 to 32 Ultra attempts

All attempts receive the same immutable base SHA, semantic contract, resource
contract, benchmark family, and forbidden shortcuts. They do not see other
answers and do not modify files or run heavy local commands.

Divide the attempts approximately into thirds:

1. Blind replications receive the same neutral prompt. These sample ordinary
   stochastic variation without immediately returning a cached answer.
2. Specialist personas attack the problem from compiler, automata, SIMD,
   memory-layout, API-boundary, algorithmic, or measurement perspectives.
3. Contrarian and greenfield personas assume that the proposed direction is a
   sunk-cost trap and search for a smaller or categorically different design.

Every discovery result must include:

- the proposed mechanism and the invariant that makes it correct;
- affected operations, profiles, and benchmark jobs;
- expected construction and execution costs;
- the smallest discriminating experiment;
- likely failure modes and an explicit kill criterion;
- the evidence that would change the recommendation.

### Stage 2: reduction and prototype selection

The dispatcher clusters mechanically equivalent proposals without exposing
authors or persona labels to the selector. A proposal advances because it is
distinct, testable, and plausible under the declared contracts, not because
its prose is confident.

Select several distinct mechanisms, not merely several descriptions of the
same mechanism. When practical, run two independent implementations of each
leading mechanism. A normal tournament has six to ten prototype attempts in
isolated worktrees. Implementation attempts do not see competing patches.

### Stage 3: automated screening

The validation marshal evaluates every prototype with the same ordered gates:

1. compile and focused structural tests;
2. forced-plan semantic differentials and exact-limit tests;
3. exhaustive, randomized, or fuzz checks appropriate to the contract;
4. cheap noncanonical performance screening;
5. resource, code-size, and construction-cost screening.

Failures and losses remain in the result record. Only the strongest two or
three candidates receive expensive canonical timing.

### Stage 4: canonical qualification

The benchmark marshal measures an immutable integration SHA under the
exclusive benchmark lease. Selection among many noisy candidates creates a
winner's curse, so the final gate uses fresh processes and held-out jobs,
haystack shapes, lengths, and operation boundaries that did not drive
discovery. A lucky minimum on the discovery set is not a speed result.

The normal promotion flow is:

```text
independent ideas
  -> isolated prototypes
  -> correctness and resource screening
  -> relevant Ultra audit
  -> integration SHA
  -> held-out quiet-machine qualification
  -> promote or reject with retained evidence
```

## Audit swarm

A critical finalist receives twelve to twenty blind Ultra audit attempts. The
pool contains both repeated neutral audits and distinct threat-model personas.
At minimum, cover the following personas when their domain applies:

| Persona | Required hostile assumption |
|---|---|
| Native-code falsifier | Machine code, register liveness, tails, ABI behavior, decoded CFG authentication, or W^X handling is unsound. |
| Semantic prosecutor | Observable behavior differs from the pinned Rust or RE2 profile on flags, Unicode, invalid bytes, captures, assertions, or ranges. |
| Resource accountant | Construction or execution hides allocations, unmetered hashing, nonlinear work, or an incomplete limit API. |
| Measurement skeptic | The speedup is noise, cache/order bias, API-boundary mismatch, shifted construction work, or selective coverage. |
| Simplicity reviewer | The implementation is unnecessarily complex and a smaller certified mechanism should replace it. |
| Contrarian portfolio killer | The entire optimization should be abandoned in favor of another use of engineering and benchmark budget. |
| Look-ahead optimizer | A design one or two milestones ahead dominates the current local optimum. This persona advises the queue and does not gate the current slice. |

Contrarian rhetoric is not evidence. Each audit returns a compact decision
record containing:

- `GO`, `REVISE`, or `STOP`;
- the exact SHA and reviewed paths;
- severity and the violated invariant;
- a minimal reproducer, falsifying test, or other concrete artifact;
- the smallest acceptable correction;
- confidence and evidence that would change the conclusion;
- paths or invariant changes that expire the review.

Any reproducible critical defect blocks promotion. Speculative disagreement
does not. An alleged defect is independently reproduced before it reaches the
integrator as a blocker. A deterministic valid reproducer does not require a
majority vote. When concrete findings conflict, a fresh neutral Ultra arbiter
receives the artifacts after the blind first round; reviewers do not conduct
an all-to-all debate.

## Adaptive replication

Launch discovery and audit attempts in waves of eight. Continue while a wave
produces a new viable mechanism, a new confirmed defect class, or a materially
different discriminating experiment. Stop or redirect after two consecutive
waves produce none of those outcomes, or when validation and measurement are
the demonstrated bottleneck.

This is an adaptive stopping rule, not permission to stop after an arbitrary
small number of attempts. Four Ultra sessions are a minimum live pool during
transitions, not an adequate sample for an important optimization decision.

Track the marginal yield of each wave:

- distinct viable mechanisms found;
- candidates surviving correctness and resource gates;
- confirmed findings rather than raw allegations;
- supported benchmark coverage added;
- promoted wins and retained losses;
- wall-clock time from ticket creation to evidence-backed decision.

Raw agent count and confident prose are not throughput metrics.

## Immutable packets and one-way handoffs

Coordination state lives outside Git under `/tmp/fre-control/` with separate
`jobs`, `results`, `handoffs`, and `leases` directories. Each session reads one
immutable job packet and writes one unique result. Sessions do not edit a
shared status document or communicate all-to-all. Reports are evidence, not
votes.

Every job packet records:

- ticket ID, base SHA, and owning worktree when applicable;
- exact objective or audit question;
- exclusive paths and forbidden actions;
- semantic, resource, and performance acceptance criteria;
- requested validation and required audit personas;
- expected benchmark family and API boundary;
- timebox, expiry conditions, and kill criterion.

Every implementation handoff records:

- base and result SHA, or exact uncommitted worktree state;
- changed paths;
- claimed invariants;
- tests requested and tests already passed;
- known limitations and unresolved risks;
- the recommended next action.

Formal audits bind to one immutable SHA. Before the repository has its
bootstrap `HEAD`, research may instead bind to a recorded snapshot digest, but
such research cannot approve promotion. A change to a reviewed path,
dependency, or claimed invariant expires the relevant approval and triggers a
delta review.

## Git and worktree rules

The first prerequisite is a coherent, tested, source-only bootstrap commit. A
checkpoint records recoverable state; it does not claim that an optimization
is promoted. The checkpoint must still obey the rule against broken or
half-integrated source.

After that checkpoint:

- each writing lane uses a separate branch and worktree;
- path ownership is explicit and overlapping integration files belong to the
  canonical integrator;
- auditors use a detached read-only snapshot of the exact candidate SHA;
- source, tests, manifests, intentional documentation, and small hand-written
  fixtures are eligible for commits;
- targets, binaries, caches, logs, generated reports, raw timings,
  disassembly, receipts, and other reproducible output remain outside Git;
- conflicts return to the original writer instead of being improvised by the
  integrator.

## Local execution and benchmark leases

Remote reasoning can fan out widely, but the local machine is a separately
scheduled resource. Writers and Ultra readers submit execution requests to the
validation marshal rather than launching competing heavy commands.

Outside benchmark windows, the local priority order is:

1. an eligible canonical benchmark;
2. focused validation requested by a writer;
3. broader differential and integration testing;
4. fuzzing, exhaustive testing, sanitizers, or the broader test matrix.

The benchmark marshal alone may acquire the global benchmark lease. It must:

- freeze and record the exact candidate SHA and configuration;
- pause builds, tests, fuzzing, and other material local CPU or I/O work;
- verify idle load, thermal stability, and disk headroom;
- randomize or counterbalance engine order;
- retain pinned engine versions and raw samples outside Git;
- release the lease before validation resumes.

Never run two timed performance jobs concurrently. Independent Ultra sessions
may continue remote deliberation during timing but must not issue local heavy
commands.

While disk space is constrained, the validation marshal owns one reusable
Cargo target directory. Do not create a target directory per worktree, and do
not let audit or research sessions build locally.

## Waiting and failure handling

The dispatcher and integrator should not globally wait merely because one
agent is thinking. Waiting is justified only for:

- a required correctness audit on the slice being promoted;
- an immutable integration SHA before canonical timing;
- contradictory reproducible findings needing adjudication;
- the Git integration or benchmark lease;
- an external decision that materially changes scope;
- a genuine shared blocker with no independent ready work.

Cancel stale attempts rather than letting them audit superseded state. Bound
the question and output of every Ultra session. Do not permit recursive
fan-out by audit sessions. If account concurrency or rate limits prevent the
desired width, run the same independent attempts in waves and report the
actual achieved sample count.

## Initial deployment

1. Finish the two currently owned atomic slices and obtain a green source-only
   bootstrap SHA.
2. Create isolated native and semantic worktrees.
3. Keep at least sixteen read-only optimization or audit attempts queued for
   every major decision, launched in waves allowed by service limits.
4. Start the validation marshal and make it the only ordinary owner of local
   build and test execution.
5. Start the benchmark marshal, but do not time candidates until correctness,
   resource, and immutable-SHA gates pass.
6. Record wave yield and adjust replication upward or downward from evidence,
   not convenience.

## Rationale and references

The high-variance and persona policy is motivated by the repeated optimization
experiments, independent repro checking, and contrarian-persona observations
described in [Agentic test processes, LLM benchmarks, and other notes on
agentic coding](https://danluu.com/ai-coding/).

The clean read-only session mechanics and the distinction between evidence and
votes are consistent with [`research/RUN_METHOD.md`](../research/RUN_METHOD.md).

The separation between wide read-heavy delegation and carefully isolated
write-heavy work follows the current [Codex subagent
guidance](https://learn.chatgpt.com/docs/agent-configuration/subagents.md).
