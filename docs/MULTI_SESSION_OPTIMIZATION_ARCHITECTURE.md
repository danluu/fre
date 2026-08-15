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

## Control-plane correction

The first deployment of this architecture exposed a contradiction in the
original process contract. It required broad independent sampling but also
described launches as waves whose yield was clustered between waves. Window 3
correctly created sixteen immutable discovery packets, but waited for the last
result in the first group of eight before launching any job in the second
group. During the tail of that wait, one Ultra process ran while eight
compatible jobs were ready. The machine and account could support eight
simultaneous sessions.

That was an architecture failure, not an individual-agent failure. The
original control directory was a passive mailbox: a ready packet did not cause
a launch, prose timeboxes did not enforce deadlines, and there was no durable
job state, scheduler heartbeat, refill rule, fairness rule, or atomic
completion protocol. Window 3 remained the dispatcher, process supervisor,
poller, integrator, and result interpreter, so scheduling advanced only when
its Ultra reasoning turn reached the next launch command.

The corrected architecture makes liveness mechanical:

- a deterministic non-LLM supervisor owns claiming, launching, reaping,
  timeout enforcement, retry classification, and continuous refill;
- groups of eight are analysis cohorts only and never launch barriers;
- policy agents create sealed campaign manifests but do not supervise
  processes;
- Window 3 integrates and promotes but is not responsible for queue liveness;
- validation commands run through a deterministic runner, with Codex invoked
  to diagnose failures rather than to type known commands;
- deployment proceeds through replay, shadow, canary, and gradual ramp stages
  before the supervisor receives broad authority.

The rest of this document specifies those enforcement mechanisms. A prompt
claiming that they will be followed is not an implementation of them.

## Top-level session architecture

These are independent top-level Codex sessions with explicit model and
reasoning settings. They are not children of the integration session. This
prevents all roles from inheriting Ultra latency and keeps audit contexts
independent of implementation narration.

| Session | Reasoning/persona | Authority and responsibility |
|---|---|---|
| `S0` supervisor | Deterministic non-LLM process | Own the durable sample and execution state machines, resource semaphores, launch/reap loop, atomic completion, retry classification, and liveness metrics. It makes no technical decisions. |
| `P0` provider frontend | Trusted deterministic broker | Hold one-execution-scoped provider credentials and provider-only egress; submit sealed prompts and mediate model events without exposing its capability to model-authored tools. |
| `T0` tool broker | Deterministic OS-sandbox broker | Execute approved model tool calls in the untrusted containment domain with no provider credential, provider socket, or provider egress. |
| `D0` policy dispatcher | Medium or High pragmatic project lead | Propose sealed campaign manifests, dependencies, priorities, acceptance criteria, and budgets. It never launches, waits for, or polls individual processes, and its proposals have no authority until approved. |
| `I0` canonical integrator, currently Window 3 | High release engineer | Own the canonical branch, canonical Git index, integration decisions, and promotion state. |
| `W1` native writer | High compiler engineer | Own Kernel IR, AArch64, native aggregate, and runtime work in an isolated worktree. |
| `W2` semantic writer | High regex engineer | Own Unicode, assertions, compatibility identity, and admission work in an isolated worktree. |
| `W3` optional tooling writer | High tooling engineer | Exist only when assigned paths are disjoint from both primary writers. |
| `V0` validation runner | Deterministic non-LLM process | Authenticate source and machine-readable command manifests, acquire local leases, execute validation groups, and emit complete failure bundles. |
| `VD` validation diagnostician | Medium or High debugging persona | Run only after `V0` fails; interpret the complete failure bundle and produce one bounded correction ticket. |
| `B0` benchmark runner | Deterministic non-LLM process | Enforce exclusive timed-run preconditions and record raw evidence. A separate measurement reviewer interprets results. |
| `U*` research and audit pool | Ultra, read-only personas | Run independent blind attempts against immutable inputs and return structured evidence. |

The canonical integrator remains the sole owner of the integration branch.
Under the current repository directive, writing sessions do not stage or
commit; the integrator checkpoints their worktrees. If that handoff becomes a
measured serial bottleneck, it must be reported rather than silently weakening
the Git rule. Neither the integrator nor the policy dispatcher is a fallback
process supervisor when `S0` is unavailable: new automatic launches stop while
already-running jobs are preserved.

Campaign authority is capability-based, not inferred from model-written text.
An operator-controlled signing tool, or a separately trusted approval broker,
issues one versioned authorization object. It binds a unique nonce, manifest
digest, immutable input, model and reasoning setting, OS sandbox profile, fixed
runner template, maximum logical samples, maximum executions, maximum
concurrency, worst-case token/process-hour/control-disk reservation, expiry,
and revocation generation. `S0` holds only the verification key. The signing
secret or non-inherited broker capability is unavailable to `S0`, `D0`, `I0`,
research workers, and their sandboxes; `I0` may propose but cannot forge an
approval. `S0` rejects any revoked, replayed, expired, or out-of-envelope launch.
Repeated finite campaigns therefore cannot evade the global ceiling.

A separate signed live-activation manifest binds the exact `S0` and wrapper
binary and source digests, ledger schema/migration set, OS containment backend
and profile, provider frontend, runner/template, budget and fairness policy,
configuration, and verification-key generation. Each campaign authorization
references that activation digest. A material implementation or configuration
change revokes the activation and resets the applicable replay, review, and
clean-soak gates; a valid campaign object cannot authorize a swapped deployment.

## Optimization tournament

Every material optimization target runs as a staged best-of-many tournament.
The counts are starting ranges, not hard ceilings. Account or service limits
may reduce rolling concurrency, but they do not introduce cohort barriers.

### Stage 1: discovery, 16 to 32 Ultra attempts

All attempts receive the same immutable base SHA, semantic contract, resource
contract, benchmark family, and forbidden shortcuts. They do not see other
answers and do not modify files or run heavy local commands.

A campaign separately declares:

- `min_attempts`, normally 16;
- `max_attempts`, normally 32;
- `target_concurrency`, initially canaried and normally no more than 8;
- per-attempt and campaign wall-time limits;
- explicit token, attempt, or process-hour budgets;
- campaign epoch, base SHA, dependency digest, and result schema.

The account-wide envelope also limits active processes, total reserved
executions, worst-case tokens or an explicitly conservative substitute when
exact usage is unavailable, process-hours, and any metered cost. A logical
sample consumes the campaign sample budget once. Every original execution,
retry, and hedge separately consumes execution, token, time, and cost budget.
All reservations and releases are ledger transactions; checking a limit and
then launching is never split into two operations.

All attempts through `min_attempts` become eligible immediately. `S0` fills
the configured slots continuously and launches the next eligible attempt after
any completion, failure, or enforced timeout. Attempt numbers and later groups
of eight are labels for analysis; completion of one group is never a
prerequisite for launching another attempt inside the already-authorized
minimum.

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

The policy dispatcher clusters mechanically equivalent proposals without exposing
authors or persona labels to the selector. A proposal advances because it is
distinct, testable, and plausible under the declared contracts, not because
its prose is confident.

Select several distinct mechanisms, not merely several descriptions of the
same mechanism. When practical, run two independent implementations of each
leading mechanism. A normal tournament has six to ten prototype attempts in
isolated worktrees. Implementation attempts do not see competing patches.

### Stage 3: automated screening

The deterministic validation runner evaluates every prototype with the same
ordered gates:

1. compile and focused structural tests;
2. forced-plan semantic differentials and exact-limit tests;
3. exhaustive, randomized, or fuzz checks appropriate to the contract;
4. cheap noncanonical performance screening;
5. resource, code-size, and construction-cost screening.

Failures and losses remain in the result record. Only the strongest two or
three candidates receive expensive canonical timing.

### Stage 4: canonical qualification

The deterministic benchmark runner measures an immutable integration SHA under
the exclusive benchmark lease. Selection among many noisy candidates creates
a winner's curse, so the final gate uses fresh processes and held-out jobs,
haystack shapes, lengths, and operation boundaries that did not drive
discovery. A lucky minimum on the discovery set is not a speed result.

The normal promotion flow is:

```text
independent ideas
  -> isolated prototypes
  -> correctness and resource screening
  -> integration SHA
  -> full validation and relevant Ultra audit of that exact SHA
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

## Rolling replication and portfolio fairness

Replication uses a work-conserving rolling reservoir, not execution waves.
When compatible work is ready and a permitted slot is free, `S0` launches it
without waiting for another attempt, reducer, persona, or campaign. The first
sixteen authorized attempts therefore flow through the reservoir continuously.

Completed results are divided into analytical blocks of eight by completion
order. Those blocks exist only to measure marginal yield. After the mandatory
minimum completes, a reducer may authorize attempts 17--24 and later 25--32.
While that reducer works, `S0` fills remote capacity from other eligible audit,
discovery, reproduction, or look-ahead campaigns. A campaign-specific decision
may pause that campaign, but it must not idle the global pool.

No logical sample at or below `min_attempts` may depend on a cohort result or
reducer. Optional samples above the minimum may depend on one sealed reducer
authorization that names the completed analytical block and remaining budget.
That dependency blocks only the optional samples in that campaign; it is not a
global-pool dependency.

Continue an optional block while completed blocks produce a new viable
mechanism, a new confirmed defect class, or a materially different
discriminating experiment. Stop or redirect after two completed blocks produce
none of those outcomes, the campaign budget is exhausted, or validation and
measurement are the demonstrated bottleneck. Sixteen attempts remain the
normal minimum for an important optimization decision; a small live pool
during migration does not satisfy that sample requirement.

`S0` applies deterministic weighted deficit round-robin between ready
campaigns, with priority aging and a stable campaign-ID tie break. For an
eight-slot Ultra pool, the initial policy reserves three slots for optimization
discovery, three for current-candidate audit or reproduction, one for
contrarian or look-ahead work, and one for hedge or overflow. An idle class may
lend its slots. Once that class has compatible ready work, further loans stop,
its visible loan debt increases its dispatch deficit, and it receives the next
compatible naturally released slot. Because reasoning jobs are non-preemptive,
fairness is measured at dispatch opportunities: the class must launch within
thirty seconds of the first compatible release, not within a fixed interval of
becoming ready. A hard wall-clock reservation would require either no lending
or a genuinely safe preemption mechanism.

Track marginal yield by completed analytical block:

- distinct viable mechanisms found;
- candidates surviving correctness and resource gates;
- confirmed findings rather than raw allegations;
- supported benchmark coverage added;
- promoted wins and retained losses;
- wall-clock time from ticket creation to evidence-backed decision.

Raw agent count and confident prose are not throughput metrics.

Mechanically equivalent proposals are one discovery cluster even when many
sessions repeat them. The ledger records both raw attempts and distinct
mechanism/invariant fingerprints. Repeated audits can still add confidence,
but identical prose is not independent evidence. Campaign policy may stop
optional attempts when the unique-cluster yield collapses, but never before
the declared minimum or required audit coverage.

## Supervisor state machine and liveness

`S0` is a single deterministic process. `FRE_CONTROL_STATE` names an absolute,
persistent, non-Git state root; on the current host its default is
`$HOME/Library/Application Support/fre-control-v2/`. It contains the
transactional ledger, an authoritative event-journal table in that same
database, content-addressed sealed packet and finalized-result blobs, and launch
receipts. Any external append-only event log is a rebuildable transactional-
outbox projection, not an independently committed authority. The state root and
its final blob directories are on one filesystem. `/tmp/fre-control-v2/`
contains only unique partial outputs, copied logs, and disposable projections.
A digest in a ledger cannot substitute for the durable bytes it names.

The state root is mode `0700` under a dedicated supervisor OS principal or an
equivalent proven mandatory capability boundary that denies every model session
direct write access. Only `S0` opens the ledger and blob namespace. Trusted
wrappers receive only preopened, child-inaccessible, unique receipt/result
descriptors and cannot choose state paths; workers inherit none of them. `D0`, `I0`, status
clients, and operators use narrow authenticated proposal/status/control sockets
with operation-specific capabilities. Running all roles as the same unrestricted
filesystem user is not an acceptable live deployment.

The ledger separates a requested independent observation from the OS processes
used to obtain it:

```text
logical sample:
planned -> blocked -> eligible -> active
        -> succeeded | failed | stale | cancelled

execution:
reserved -> launching -> running -> straggling -> terminating
         -> exited -> validating
         -> accepted | transient-failed | permanent-failed
         | timed-out | lost | superseded | cancelled
```

Each logical sample has one idempotency key binding its sample nonce, campaign
epoch, job ID, persona, model and reasoning effort, sandbox and readable-path
set, runner and prompt-template versions, packet digest, base SHA, dependency
digest, and result schema. Retries and tail hedges receive distinct execution
IDs and launch nonces underneath that sample. The first valid execution wins a
compare-and-swap; every later valid completion is retained as `superseded` and
does not increase the sample count. An intentionally independent replication
requires a new logical sample nonce and an atomic sample-budget reservation.

Execution success and technical judgment are different fields. A clean audit
that returns `STOP`, or a validator that correctly reports `FAIL`, has
`execution_status=accepted` and a negative `domain_verdict`; it is not an
infrastructure failure and is not automatically retried. A logical sample is
`succeeded` when one execution produces an accepted artifact regardless of its
domain verdict. It becomes `failed` only when no execution can produce an
accepted artifact within its authorization and budgets.

Every execution terminal transition and its logical-sample effect occurs in
one ledger transaction:

| Execution outcome | Logical-sample effect |
|---|---|
| `accepted` and winner CAS succeeds | Set the sample `succeeded`, record exactly one winning execution, prohibit new executions, and request bounded termination of every sibling. |
| Valid artifact after another winner, epoch expiry, or sample cancellation | Retain the artifact and mark the execution `superseded`; never increment completed-sample count. |
| `transient-failed`, `lost`, or `timed-out` | Permanently debit the execution and incurred usage. Keep the sample `active` while a sibling runs; otherwise move it to backoff/`eligible` only if retry authorization and budgets remain, or to `failed`. |
| `permanent-failed` | Keep the sample `active` while a sibling runs; otherwise mark it `failed`. A changed packet or source requires a new authorized logical sample. |
| `cancelled` | Mark the execution terminal. Mark the sample `cancelled` only for sample/campaign cancellation; a sibling cancelled after a winner leaves the sample `succeeded`. |
| Active epoch/dependency invalidated | Atomically mark the sample `stale`, prohibit new executions, and terminate or supersede siblings. |

Only `succeeded` logical samples with durable accepted artifacts count toward
`min_attempts`, including accepted negative domain verdicts. `failed`, `stale`,
and `cancelled` samples consume their authorization and budgets but do not meet
the evidence minimum; an authorized replacement uses a new sample nonce.

The ledger records both IDs, campaign and resource class, state, timestamps,
wrapper and `P0` PIDs/birth identities, outer containment and active `T0`
domain identities, wrapper session ID, heartbeat,
launch nonce, command and packet digests, partial path, base and dependency
digests, exit classification, output digest, observed or reserved tokens,
failure fingerprint, domain verdict, resource reservations, and scheduler
fencing token. One leader holds the operating-system lock and a monotonically
increasing fencing token. Every side-effecting launcher, lease service, `V0`,
and `B0` request rejects a stale token. No child may mutate the ledger.

Packet admission precedes eligibility. `S0` canonicalizes the approved manifest
and packet into a unique temporary file in the persistent state filesystem,
fsyncs it, hashes it, installs it into the content-addressed store without
replacement, verifies any already-existing blob byte-for-byte, and fsyncs the
parent directory. Only then may one ledger transaction reference the packet,
consume a logical-sample authorization, and set the sample blocked or eligible.
A committed reference to a missing or corrupt input blob is ledger corruption
and enters `PAUSE`.

### Launch, recovery, and fencing

A launch uses this durable protocol:

1. One ledger transaction reserves the logical-sample budget if needed,
   execution budget, pool slot, resource leases, execution ID, launch nonce,
   unique partial path, and current fencing token.
2. `S0` creates and directory-fsyncs one exclusive per-execution receipt slot,
   then passes its trusted wrapper only a preopened descriptor that is closed
   from every child before launch.
   The wrapper appends checksum-framed and fsynced `wrapper-start`,
   `frontend-start`, `provider-start` when a request ID becomes known,
   `tool-start`/`tool-exit` for each `T0` domain, heartbeat, and exit records.
   `frontend-start` is the authoritative execution-start frame and binds the
   `P0` PID/birth identity, outer kill-domain identity, signed activation
   digest, launch nonce, packet/command digests, partial-result identity, and
   fence. `provider-start` binds the provider request/session ID to that frame.
   A torn frame is never a receipt. The wrapper cannot choose a state path and
   stays outside the domain it may need to terminate.
3. The wrapper invokes `P0` through one reviewed launcher template with a fixed
   model and reasoning setting. It preallocates the outer containment identity
   and spawns `P0` stopped at a capability-free startup gate. Only after the
   complete `frontend-start` frame is fsynced does the wrapper transfer a non-
   inherited, one-execution-scoped provider capability and unblock `P0`.
   `P0` alone receives provider-endpoint-only egress. It submits the sealed
   prompt, records the provider request ID, and streams a bounded final response
   back to the wrapper. The wrapper writes that response through its preopened
   unique partial-result descriptor; model code and tool processes never
   receive the descriptor.
4. When tools are enabled, every model-authored tool request goes through `T0`
   under a lower OS principal/capability and the declared immutable input,
   working directory, path, environment, network, and tool policy. A `T0`
   domain is likewise preallocated and its process starts blocked and
   capability-free; the wrapper fsyncs `tool-start` before `T0` receives the
   bounded request capability and is unblocked. A `T0` process inherits neither
   provider credentials nor the `P0` socket and has no provider egress.
   Model-authored text cannot add capabilities. Neither `P0` nor `T0` has
   ledger, lease, Git, validation, or benchmark authority.

“Read-only” means an implemented OS capability profile, not a prompt or a
launcher flag. The research-tool profile exposes an immutable sanitized source
export rather than a live worktree; supplies an ephemeral empty `HOME`; scrubs
credentials, inherited descriptors, agent sockets, and environment; denies
keychain and secret-store access; and enforces explicit file-read, result-
channel-write, network, tool, child-process, CPU, memory, wall-time, and output
quotas. The containment backend must keep all descendants in a kill-all domain
(for example a cgroup/job/VM or a proven platform equivalent) or forbid the
worker from spawning tools. Startup fails closed when a required control is
unavailable. Escape tests cover symlink and `/tmp` substitution, environment
and keychain reads, network access, `fork`/`setsid`/daemon escape, signal and
debug interfaces, output flooding, and writes outside the result channel.
It also proves that a model-issued tool cannot read, inherit, connect to, or use
the provider frontend capability. The cap-one canary starts tools-disabled with
prepacked immutable input. Tools-enabled research is a separate feature gate
and remains off until the `P0`/`T0` privilege and egress split passes these
escape tests.

On restart, `S0` enters recovery before launching. It reconciles ledger rows,
receipts, partials, and finalized blobs; verifies PID *and process birth time*
to prevent PID-reuse adoption; and adopts only when the wrapper, authoritative
`frontend-start`, signed activation digest, nonce, command/packet digests,
outer containment identity, every unclosed `T0` domain, optional provider
request, and fence all match. A `launching` execution
without a live verified wrapper becomes `lost` and retry-eligible only after the
configured grace and proof that no valid `frontend-start` frame or provider
request exists, or after its exact containment domain is empty *and* provider
cancellation/usage receives the required disposition. A valid or uncertain
`frontend-start` remains active, terminating, or quarantined; it retains slot
and provider reservations and prohibits retry. `S0` neither relaunches nor kills
an ambiguous process automatically. An operator may clear it only after
proving the full containment domain empty or explicitly adopting its exact
identity. An expired heartbeat alone never permits lease reclamation.

A process or containment domain observed before its corresponding complete
start frame is never assumed inert or absent: recovery quarantines it, retains
all reservations, and prohibits retry until that exact domain is verified
empty. Start-frame-before-unblock is the only permitted side-effect boundary.

After acquiring the leader lock and proving the prior leader's PID/birth
identity dead, the new leader may atomically adopt a fully verified execution
and all of its leases into the new fencing generation while retaining its
original launch nonce. The adoption record binds old and new fences and is
accepted by every side-effecting service. Failure to prove the old leader dead,
verify the wrapper/`P0`/`T0`/provider identity, or transfer every lease quarantines that
execution and its resources; partial fence transfer is forbidden.

The supervisor must satisfy these observable invariants whenever no circuit
breaker, cooldown, backoff, drain, incompatible resource lease, or hard budget
is blocking the relevant class:

- a compatible eligible job and free reserved slot launches within thirty
  seconds;
- completion, capacity failure, or enforced timeout triggers refill within
  thirty seconds;
- with a backlog larger than the pool, rolling five-minute remote-slot
  utilization is at least 85%;
- scheduler heartbeat age stays below fifteen seconds, with fail-closed
  restart or operator alert at thirty seconds;
- no logical sample at or below its campaign minimum has an analytical-cohort
  or reducer launch dependency;
- queue status reports logical jobs, not the wrapper and binary processes that
  happen to implement one Codex session;
- oldest eligible age, per-class occupancy, retries, late jobs, rate errors,
  token observations, local leases, disk reserve, and checkpoint age are
  visible without asking a model to infer them.

`S0` launches workers in independent kill-all containment domains so a Window 3 restart does
not terminate or orphan queue ownership. It never blocks waiting for a
specific worker. It reaps all exits asynchronously and polls its whole process
set on every event-loop iteration. A slot or lease is not released until the
wrapper has exited and the containment domain, not merely its original process
group, is verified empty. The wrapper records the provider request/session ID
when exposed and requests provider cancellation at a hard timeout. Provider
capacity, token, and cost reservations remain outstanding until cancellation
is acknowledged and usage reconciled; when the provider exposes neither, the
full worst-case reservation becomes consumed and a conservative capacity
cooldown remains in force.

### Atomic completion

File existence or nonzero size is not completion. Partial and final names
reject traversal and symlinks; files are precreated with exclusive/no-follow
semantics and strict ownership, mode, and size limits. Each execution has a
different partial path. Finalization has one required order:

1. The wrapper and `P0` exit, all inherited descriptors close, every started
   `T0` domain is accounted and empty, the outer containment domain is empty,
   and the provider request is completed or receives the required cancellation
   and usage disposition.
2. `S0` validates exit classification and the bounded result, including its
   execution ID, launch nonce, packet, base SHA, epoch, dependencies, and
   schema. It extracts `domain_verdict` separately.
3. `S0` writes the result to the persistent content-addressed store, fsyncs the
   bytes, atomically installs it without replacing an existing blob, and
   fsyncs the parent directory. If the destination already exists, `S0`
   rehashes and byte-verifies it before reuse; a mismatch enters `PAUSE` and is
   never referenced.
4. One ledger transaction appends the digest-bearing event, records the
   execution result, and compare-and-swaps the logical sample to its terminal
   state. Only that transaction makes the result consumable.

Recovery recognizes a durable blob created before its ledger transaction and
can complete or discard it after revalidation. A committed ledger reference to
a missing or invalid blob is corruption and enters `PAUSE`. Reducers consume
only terminal logical samples with durable accepted artifacts.

Results from an expired epoch are marked stale and retained as research. They
cannot satisfy an audit, promotion, or sample-count gate. Promotion acceptance
uses a compare-and-swap against the active epoch and dependency digest.

### Stragglers, retries, and hedges

Timeboxes are enforced by the supervisor, not written only in prose. A slow
execution never blocks refill of another free slot. The initial soft deadline
is:

```text
min(hard_deadline - termination_grace,
    max(10 minutes, 2 * median_same_class_model_and_effort))
```

If no trustworthy median exists, the sealed campaign supplies a conservative
soft deadline. At that point a campaign may launch a hedge execution under the
same logical sample from the reserved overflow slot, provided the execution,
token, time, and global budgets permit. The original remains eligible to win
until its hard deadline and epoch expiry. Hedging is disabled while a rate,
capacity, or transport circuit breaker is open.

An execution reservation persists both an absolute hard-deadline timestamp and
the current boot identifier plus monotonic deadline. Within the same boot the
monotonic deadline is authoritative; after restart recovery uses the persisted
absolute deadline and never recomputes a fresh duration from recovery time. A
manifest is rejected unless the hard deadline is later than reservation by
more than its termination grace and every soft deadline is at or before
`hard_deadline - termination_grace`.

At the hard deadline the wrapper requests cancellation, sends `SIGTERM` to the
owned containment domain, waits a bounded termination grace, sends `SIGKILL`
where applicable, and verifies the domain empty before releasing local process
reservations. Provider reservations follow the separate acknowledgement rule
above. A timed-out local process is never allowed to keep consuming resources
after refill.

Automatic retries apply only to classified transient infrastructure failures
such as a capacity or transport error. They use a new execution ID under the
same logical sample, honor `Retry-After`, add bounded jittered exponential
backoff, and consume the infrastructure-retry budget. A semantic failure,
audit `REVISE` or `STOP`, test verdict, or unchanged non-transient source or
validation failure is never retried without a changed packet, source diff, or
explicit adjudication. The same unchanged non-transient failure signature
twice, or three writer-correction cycles for one candidate, moves the item to a
dead-letter queue for diagnosis. Repeated capacity, rate, transport, or
service failures instead feed their pool circuit breaker and never trigger the
source-failure dead-letter rule.

Repeated rate or service failures reduce the remote concurrency limit rather
than creating a retry storm. A configured threshold opens a circuit breaker
that pauses new launches while preserving completed and running artifacts.
Recovery uses a configured cooldown and a one-slot ramp before restoring wider
concurrency.

### Budgets and kill controls

Every campaign reserves explicit maxima for logical samples, executions
(including retries and hedges), concurrent sessions, wall time, process-hours,
worst-case tokens, and metered cost if applicable. The account-wide envelope
reserves the same dimensions across every active campaign. If exact token use
is unavailable, the configured per-execution maximum remains reserved until
completion. No optional campaign launches without finite sample, execution,
and wall-time caps. At a soft threshold optional samples stop; at a hard
threshold every new execution stops. Increasing either envelope requires a new
signed authorization, not an automatic retry or another campaign.

Logical-sample creation, execution start, retry/hedge counts, and incurred
token, time, or cost usage are permanent debits. Active concurrency and unused
worst-case token/time/cost reservations are refundable reservations. Admission
is one transaction enforcing, for every dimension,
`consumed + outstanding_reservations + new_worst_case <= hard_cap`; completion
converts actual usage to consumed and releases only the unused remainder.
Unknown usage consumes its full conservative reservation. Sequential retries
therefore cannot regain execution or usage budget merely because the prior
process exited.

Every execution also reserves worst-case persistent control bytes for its
packet, receipts, bounded stdout/stderr, partial and final result, journal rows,
and indexes. The store has aggregate and per-artifact caps plus an emergency
filesystem reserve. Output is bounded at the source; an overrun terminates or
quarantines the execution and enters `PAUSE` before consuming the reserve.
Retention and garbage collection are versioned operator policies that may
archive or delete only authenticated, unreferenced terminal artifacts after
their retention gate. They never remove a ledger-referenced blob, receipt
needed for recovery, raw qualification evidence, or the emergency reserve.

The control plane exposes three operator controls:

- `PAUSE`: start no new work but let running jobs finish;
- `DRAIN`: start no new work and exit after running jobs finish;
- `ABORT`: terminate owned containment domains after a grace period and record
  cancellation artifacts.

An unclear leader, corrupted ledger, source-digest mismatch, unexpected writer
overlap, exhausted hard budget, or benchmark contamination automatically
enters `PAUSE`.

## Immutable packets and one-way handoffs

Sealed packets, finalized results, handoffs, receipts, the journal, and the
ledger live in the persistent `FRE_CONTROL_STATE` outside Git. Packet and
result blobs are content addressed and immutable; mutable indexes refer to
their digests. `/tmp/fre-control-v2/` is a lossy staging and log area and must
be reconstructible from durable state plus currently verified processes. Each
session reads one sealed packet and writes one unique partial result for
supervisor finalization. Sessions do not edit a shared status document or
communicate all-to-all. Reports are evidence, not votes.

`D0` proposes a schema-validated, content-addressed campaign manifest rather
than manually launching nearly identical commands. A manifest contains the
shared contract once and small per-sample overlays for persona, sample nonce,
and deliberately varied question. The trusted signer or approval broker issues
the authorization object described above; an unsigned database field or
model-written approval text has no authority. `S0` expands and authenticates
only approved overlays through reviewed runner templates.

Every job packet records:

- ticket ID, base SHA, and owning worktree when applicable;
- campaign epoch, dependency/path digest, logical-sample nonce and idempotency
  key, runner/template version, and output schema;
- exact objective or audit question;
- exclusive paths and forbidden actions;
- semantic, resource, and performance acceptance criteria;
- requested validation and required audit personas;
- expected benchmark family and API boundary;
- enforced timebox, retry class, expiry conditions, and kill criterion;
- campaign sample, execution, retry/hedge, concurrency, wall-time, and
  token/process-hour budgets.

Every implementation handoff records:

- base and result SHA, or a complete uncommitted-state snapshot manifest;
- changed paths;
- claimed invariants;
- tests requested and tests already passed;
- known limitations and unresolved risks;
- the recommended next action.

A complete uncommitted-state manifest binds the base commit, submodules, every
included path's bytes and mode, symlink target, and the explicit allowlist of
included untracked files. It is materialized as an authenticated read-only
export; a pathname list or `git diff` alone is not an identity. `V0` binds its
receipt to that export digest, recipe, toolchain, environment, and inputs, and
`I0` later requires the committed tree to equal the validated source manifest.

Formal promotion audit approval initially binds to the whole immutable
integration SHA, its submodule/toolchain inputs, packet digest, and declared
dependency digest. Cross-SHA approval reuse is disabled until a separately
implemented dependency-closure verifier is approved; a model declaration of a
“complete closure” is insufficient. The audit wrapper authenticates the
detached worktree's `HEAD`, clean status, reviewed tree objects, packet, and
dependencies both before and after the audit. Earlier prototype audits may
guide integration but do not satisfy the gating audit. Before the repository
has its bootstrap `HEAD`, research may instead bind to a recorded snapshot
digest, but such research cannot approve promotion. The ledger tombstones
queued work from an old epoch and marks late results stale; it never silently
counts them toward a new epoch.

## Git and worktree rules

The first prerequisite is a coherent, tested, source-only bootstrap commit. A
checkpoint records recoverable state; it does not claim that an optimization
is promoted. The checkpoint must still obey the rule against broken or
half-integrated source.

After that checkpoint:

- each writing lane uses a separate branch and worktree;
- path ownership is explicit and overlapping integration files belong to the
  canonical integrator;
- each writer holds an atomic worktree and path-set lease with a fencing token,
  owner identity, heartbeat, and expected starting digest;
- auditors use a detached read-only snapshot of the exact candidate SHA;
- source, tests, manifests, intentional documentation, and small hand-written
  fixtures are eligible for commits;
- targets, binaries, caches, logs, generated reports, raw timings,
  disassembly, receipts, and other reproducible output remain outside Git;
- conflicts return to the original writer instead of being improvised by the
  integrator.

Until writer automation is separately approved, writer sandboxes or filesystem
capabilities make `.git` technically read-only and only `I0` can receive the
canonical-Git capability. A writer handoff freezes its lane, authenticates the
starting digest and exact diff, releases the write lease into a validation
freeze, and names the validation receipt. `I0` acquires the canonical-Git
lease, reauthenticates that unchanged diff and receipt, checkpoints it, and
reauthenticates `HEAD`, tree, index, and lane cleanliness after the commit. A
time target never bypasses these gates.

If mutation is later automated, only fenced broker wrappers receive kernel-
enforced write access; the model, arbitrary tools, and unfenced processes do
not. The broker constrains writes to leased path/inode identities and keeps
`.git`, the index, and unrelated worktrees read-only. Before any checkpoint it
validates the staged tree against source/path, size, file-mode, symlink,
binary/generated-artifact, and forbidden-output allowlists. Every filesystem or
Git operation is rejected unless its lease and fencing generation are current.

The resource service implements this minimum compatibility matrix:

| Lease/reservation | Capacity and exclusion |
|---|---|
| shared `local-activity` admission | Held by every local-capable actor; unavailable during drain or benchmark. |
| `benchmark-drain` / `benchmark` | Exclusive global state; excludes shared local activity and Git mutation. |
| `canonical-git` | Capacity one; `I0` only. |
| `worktree-write:<lane>` | Capacity one; excludes that lane's freeze. |
| `worktree-freeze:<lane>` | Excludes the lane writer while validation or checkpoint authentication runs. |
| `cargo-target` | Capacity one for the shared target directory. |
| `local-heavy` | Capacity one unless later machine evidence raises it. |
| `disk-reservation` | Atomically counted bytes against the global safe reserve. |

The displayed order is the canonical key order for one atomic, all-or-nothing
resource transaction, not a sequence of locks held while waiting:

```text
benchmark-drain
-> canonical-git
-> worktree
-> cargo-target
-> local-heavy
-> disk-reservation
```

Admission either reserves the complete compatible set or reserves nothing.
Failed admission releases every provisional reservation in the same
transaction. Shared local-activity admission is a normal state; the exclusive
`benchmark-draining` state first blocks new shared admissions, waits without
holding unrelated partial locks, then transitions atomically to `benchmark`.

An expired heartbeat is an alert, not permission to steal a lease. No lease is
reclaimed until its exact owner containment domain is verified empty and the new
owner has a higher fencing token accepted by every side-effecting service.
Unexpected overlapping ownership or source drift pauses the affected lanes,
preserves both diffs, and requires explicit adjudication.

Git quiescence is lane-local. End-to-end checkpoint age begins when a frozen,
authenticated, green handoff arrives. Status separately reports ready age,
canonical-Git lease-wait age and current holder age, `I0` response age, and the
mechanical commit duration, so lease starvation cannot hide the queue. `I0`
acquires the canonical-Git lease only for authentication and the mechanical
checkpoint and targets starting within five minutes of handoff. A miss is an
SLO violation, never authority for a second committer or weaker authentication.
A feature checkpoint is not planner promotion. Canonical integration can wait
for its own dependency gates; recoverable source history must not.

## Local execution and benchmark leases

Remote reasoning can fan out widely, but the local machine is a separately
scheduled resource. Writers and readers request validation through an approved
job; they cannot submit executable authority directly to `V0` or launch
competing heavy commands. `V0` accepts only an authorized execution ID, current
fence, authenticated source-export digest, and named recipe after one atomic
local-resource and disk reservation. It executes reviewed recipes directly; a
fresh Codex session is not required to authenticate a packet and type
`cargo test`.

Validation manifests select named, versioned, reviewed command recipes rather
than supplying arbitrary shell text or argv. Each recipe fixes or strictly
allowlists the executable, arguments, environment, working directory, readable
and writable paths, pinned toolchain, input digests, network denial, subprocess
group, memory, disk, and time limits, and result schema. Cargo build scripts and
tests run against an authenticated read-only source snapshot with only declared
scratch and the serialized shared target writable. A cheap diagnostic group
may collect multiple independent formatting, compile, Clippy, and focused test
failures before stopping. Expensive differential, exhaustive, or workspace-wide
groups run only after required cheap groups are green. This prevents
one-error-per-Codex-session ping-pong without running evidence on an invalid
prerequisite state.

Before `V0` authority, malicious-fixture tests must attempt secret and keychain
reads, writes outside scratch, network use, `fork`/`setsid`/daemon escape,
signals and tracing, disk fill, output flood, and leaked subprocesses from both
Cargo build scripts and tests. The runner must contain and classify them,
authenticate the shared target's provenance, and finish with a clean source and
process-domain check.

On failure, `V0` preserves complete stdout, stderr, exit status, duration, and
source authentication for every attempted command. One `VD` agent receives the
complete bundle and writes one scoped correction ticket that includes the
necessary regression. An unchanged diff plus the same failure fingerprint is
not another correction attempt; it is dead-lettered.

Outside benchmark windows, the local priority order is:

1. an eligible canonical benchmark;
2. focused validation requested by a writer;
3. broader differential and integration testing;
4. fuzzing, exhaustive testing, sanitizers, or the broader test matrix.

Before benchmark automation is promoted, one explicitly named manual benchmark
marshal may acquire the same global lease under the existing quiet-machine
procedure. After promotion, `B0` alone may acquire it. In either mode the owner
must:

- freeze and record the exact candidate SHA and configuration;
- enter `benchmark-draining`, block all new supervisor-issued local commands
  and Git mutations, and wait for builds, tests, fuzzing, validation, Git, and
  tool-capable local Codex clients to drain;
- verify idle load, thermal stability, and disk headroom;
- randomize or counterbalance engine order;
- retain pinned engine versions and raw samples outside Git;
- record sealed holdout access and consumption so qualification data cannot
  silently become discovery data;
- release the lease before validation resumes.

The benchmark receipt binds the candidate source and binary digests, build
receipt, harness and configuration, dataset/holdout, baseline engines,
toolchain, environment, randomized order, raw samples, contamination monitor,
thermal/load preconditions, and post-run cooldown evidence.

Never run two timed performance jobs concurrently. A dedicated quiet benchmark
host is preferred. All local-capable actors, including manual commands and
Codex clients, participate in shared local-activity admission. On the shared
host the default is to drain every local Codex client; a process is exempt only
on a separate host or after measured CPU/I/O isolation and affinity proves
noninterference. Every Cargo, fuzz, exhaustive, and benchmark manifest passes
through the same lease service. `B0` monitors load and process contamination
throughout timing; an unexpected competitor invalidates the complete run, not
merely one sample. Holdout and contaminated-rerun budgets are finite,
preventing qualification from becoming retry-until-lucky.

`V0` owns one reusable Cargo target directory. Do not create a target directory
per worktree, and do not let audit or research sessions build locally. Each
local manifest atomically reserves expected peak growth plus a safety margin
before launch. The central disk accountant begins with a conservative floor
and raises or lowers it only from retained peak-growth evidence and operating-
system headroom. Crossing the soft floor blocks new artifact-producing work;
crossing the hard floor blocks *all* new local jobs, including nominally
mandatory ones, until an explicit reserve calculation passes. Cleanup is never
automatic during a measurement campaign.

A hard-floor incident exposes one narrowly scoped, operator-authorized recovery
recipe. It may delete only hash-authenticated disposable caches and incomplete
scratch artifacts named by policy, never Git/worktrees, the control ledger or
blobs, recovery receipts, source snapshots, raw timing/qualification evidence,
or anything during a benchmark campaign. It reserves no artifact growth,
records every deletion, and rechecks the filesystem reserve before ordinary
admission resumes.

## Waiting and failure handling

The policy dispatcher and integrator must not call a blocking wait on an
individual reasoning process. They consume supervisor events and may await a
logical gate while continuing unrelated work. Waiting is justified only for:

- a required correctness audit on the slice being promoted;
- an immutable integration SHA before canonical timing;
- contradictory reproducible findings needing adjudication;
- the Git integration or benchmark lease;
- an external decision that materially changes scope;
- a genuine shared blocker with no independent ready work.

Cancel or archive stale attempts through `S0` rather than letting them approve
superseded state. Bound the question and output of every Ultra session. Do not
permit recursive fan-out by audit sessions. If account concurrency or rate
limits prevent the desired width, reduce the rolling concurrency limit and
report the actual achieved sample count; do not reintroduce batch barriers.

## Safe deployment and rollback

The enforcement layer is introduced as a new reliability component. Window 3
must not improvise it while simultaneously integrating engine changes, and a
new prompt is not sufficient evidence that the failure is fixed.

### Phase 0: preserve current work

- Let already-running read-only audits and the current bounded validation or
  writer tasks finish; do not kill them merely to change schedulers.
- Checkpoint every independently green lane without waiting for unrelated
  worktrees or discovery reduction.
- At the first safe Git boundary, transfer canonical ownership through an
  authenticated handoff to a fresh High-reasoning `I0`; do not wait for remote
  children to finish. The old Ultra Window 3 becomes legacy-reaper-only until
  its children exit and relinquishes Git, policy, and launch authority. Ultra
  research/audit sessions remain out of band, and recoverability checkpoints do
  not await their deliberation.
- Start no new all-at-once cohort. Before any transitional refill, freeze every
  manual/model launcher and record an exclusive singleton launch lease and
  epoch. If legacy ready packets require refill before the canary, a dedicated
  High control-plane writer—not Window 3—implements a tiny deterministic
  fail-idle shim and a separate reader reviews it. It receives a fixed digest-
  verified packet list, exact launcher commands, hard concurrency/budget cap,
  and an inventory of existing PID, birth time, containment domain, command,
  and packet digests. After fake heterogeneous-child tests, it initially fills
  `min(ready packets, cap - authenticated active processes)` and thereafter
  refills every authenticated exit immediately. It writes durable launch
  receipts and has no retries, adoption, killing, interpretation, source
  mutation, or restart recovery. Any unknown process, ownership change, lock
  loss, capacity ambiguity, or shim failure makes it fail idle and alert. If the
  exact legacy launcher has not already proved OS-enforced read-only inputs,
  one unique bounded output, a mechanically finite deadline, no heavy/local or
  mutation capability, and descendant containment, the shim remains disabled
  and accepts temporary idle capacity. Prompt/command review alone is not that
  proof. Window 3 never polls or owns queue liveness.
- Close canonical benchmarking only for the short ownership inventory and
  cutover freeze. The existing manual quiet-machine path may reopen once
  legacy local processes drain and its existing preconditions pass; benchmark
  *automation* remains a later authority.

The supervisor project does not become a global engine-work prerequisite.
After the interim disk/capacity fail-safe clears and ownership is authenticated,
the fresh High `I0` may continue already-approved isolated writer corrections,
source-only checkpoints, one serialized legacy validation, and the existing
manual benchmark path. These bounded actions use their current lane and local-
resource rules; they do not make `I0` a rolling research poller and do not grant
`S0` premature authority. Broad remote refill uses the proven shim or waits for
the relevant canary gate.

### Phase 1: preserve and classify legacy control state

Before replay or live launch, migrate without disturbing legacy processes:

1. Do not rename, move, delete, symlink, or rewrite `/tmp/fre-control/` while
   any legacy command may reference it.
2. Create the persistent v2 state root and copy every legacy packet, result,
   handoff, and receipt into an immutable `legacy-import` area with source path,
   size, timestamp, and cryptographic digest. Copy; never move.
3. Scan live processes twice across a settling interval. Match command,
   packet/output paths, process birth time, and available digests. Import only
   unambiguous matches as `legacy-running`, consuming observed capacity but
   granting `S0` no kill authority.
4. Authenticate a complete result as terminal only when no matched producer is
   still live and legacy final-output evidence is present. Classify a packet
   with neither a result nor a live process as inventory-only queued. An
   imported packet is never directly eligible: relaunch requires a new v2
   logical-sample ID and nonce, newly sealed packet, current source/dependency
   authentication, budget reservation, and signed authorization. Quarantine
   every ambiguous item rather than guessing or relaunching it.
5. Continue shadow reconciliation through Phase 3. Only a legacy process that
   conflicts with the canary's account slot, path, or local resource blocks that
   resource. A straggler reaching its legacy hard deadline plus disposition
   grace requires an operator to keep it visibly accounted, cancel it through
   its original owner, or quarantine the resource; one unrelated hung reader is
   not a global barrier. New v2 IDs never reuse a legacy ID or partial path.
6. Preserve the old tree as a read-only archive after drain. Rollback stops v2
   launches and leaves legacy state, worktrees, Git, Cargo targets, and running
   processes untouched.

### Phase 2: implement the cap-one core without authority

Assign one dedicated High control-plane writer an isolated worktree and path
set. A deterministic fake-provider/process harness drives tests, while several
blind read-only Ultra reviewers attack the design and implementation in
parallel. `I0` only authenticates handoffs, checkpoints green source, and
promotes gates; it is not the scheduler author, test driver, or poller.

The first useful slice contains only the persistent ledger/blob store, signed
authorization verification, sample/execution transitions, a single leader,
static atomic budgets, fixed OS-contained read-only wrapper, durable receipts
and recovery/refencing, result CAS, hard timeout, `PAUSE`/`DRAIN`/`ABORT`, and a
status CLI. It is fixed at one active execution and one active campaign.
It uses prepacked immutable input with `T0` tools disabled. Retries, hedges,
borrowing, multi-campaign fairness, a dashboard, local
validation, writer, Git, and benchmark authority are disabled. Initially it has
no permission to launch Codex at all.

Before the cap-one live canary, deterministic tests must cover:

- durable packet admission, signed/revoked authorization, permanent versus
  refundable budget accounting, and simultaneous admission races;
- duplicate launch requests, PID reuse, supervisor restart, exact orphan
  adoption/refencing, lost launch recovery, and ambiguous-owner quarantine;
- a crash between every wrapper, frontend, provider, and tool-domain receipt
  and result-finalization step,
- crashes after spawning stopped `P0`/`T0` but before the start frame and after
  the fsynced start frame but before capability transfer/unblock,
  including an orphan blob and a missing ledger-referenced blob;
- partial, overwritten, empty, oversized, malformed, traversal, symlink, late,
  and wrong-nonce results, plus a schema-valid negative domain verdict;
- hard timeout, kill-domain escape attempts, provider cancellation/accounting,
  stale epoch/dependency rejection, and no release before containment is empty;
- launcher-template, immutable-export, sandbox, working-directory, path,
  environment, secret, network, process, output, and control-disk rejection;
- `PAUSE`, `DRAIN`, and `ABORT`, versioned ledger migration, backup/restore,
  event-journal replay, and status reporting.

Additional features have independent gates and cannot hold the cap-one core:

- Before limit two, enable multi-execution refill and test sixteen queued
  samples with heterogeneous durations and a ten-times-slower straggler. Keep
  retries/hedges off and use one campaign.
- Before two campaigns or limit four, enable deterministic deficit fairness and
  test an idle lender followed by demand for the borrowed slot.
- Before any automatic retry, enable its permanent execution/usage budgets,
  `Retry-After`, jittered backoff, failure classification, and pool breaker,
  then test repeated transient versus unchanged source failures and recovery
  ramp. Limit eight requires this gate; retry may otherwise remain disabled.
- Before any hedge, test simultaneous original/hedge completion, sibling
  termination, overflow fairness, and nonrefundable hedge accounting. Hedging
  is optional and need not delay limit eight.
- A dashboard and all local-resource automation remain later conveniences; the
  status CLI and machine-readable event stream are sufficient for remote
  launch authority.
- Before enabling model-authored tools, implement and adversarially verify the
  `P0`/`T0` credential, egress, descriptor, principal, and containment split.
  Prepacked tools-disabled research continues safely if that gate is not ready.

### Phase 3: replay and shadow

Replay cap-one crash, receipt, completion, timeout, budget, and control traces
through `S0`, plus at least 100 seeded cap-one schedules containing restarts,
ties, delays, and resource conflicts with deterministic outcomes. Multi-slot
first-deployment replay belongs to the limit-two feature gate and does not hold
the cap-one canary.

Then run `S0` in observation-only shadow mode against the imported legacy view
for at least thirty minutes and through disposition of every conflicting legacy
resource. It must classify at least twenty transitions; if fewer live
transitions remain, feed authenticated recorded transitions through the same
observation interface. A nonconflicting quarantined legacy reader remains
visibly capacity-accounted but does not extend this global gate. Shadow mode
launches, kills, and releases nothing. Any ownership disagreement, unexplained
state, or non-deterministic replay is a blocker, not something to repair
automatically.

### Phase 4: read-only canary and ramp

Grant launch authority only for representative Ultra read-only research against
one immutable SHA and a signed global envelope. The concurrency levels and
minimum clean exposure are:

| Limit | Minimum clean evidence before increasing |
|---:|---|
| 1 | Four accepted logical samples and one supervisor restart with exact adoption. |
| 2 | Eight accepted logical samples and one injected lost-launch recovery. |
| 4 | Sixteen accepted logical samples across two campaigns, including a demanded borrowed slot and an injected straggler. |
| 8 | Thirty-two accepted logical samples across at least two campaigns and sixty minutes of operation, including a restart and circuit-breaker recovery. |

Before raising from one to two, replay the recorded first-deployment sequence
and at least 100 seeded multi-slot schedules. They must show attempts 9--16
launching as slots complete, with the final first-block straggler unable to
block them. Later feature gates add fairness, retry, and hedge fault schedules
before those mechanisms are enabled.

At every level there must be zero duplicate sample acceptance, stale
acceptance, budget oversubscription, unknown process ownership, unbounded
retry, or liveness/fencing violation. Qualifying intervals require a ready
backlog, actual target occupancy, and observed automatic refill; cheap fake jobs
may test faults but cannot replace representative Ultra exposure. Evidence
binds the exact supervisor binary/source SHA, ledger schema, wrapper and sandbox
versions, launcher template, budget/fairness policy, and configuration. A
material change resets the affected clean window. A versioned backup/restore
test and an independent read-only review of bound evidence are required before
the first live launch and before eight-slot authority.

`I0` is the named rollback owner. Automatic rollback first enters `PAUSE`, keeps
heartbeats, reservations, ownership, and reaping for every active v2 execution,
and returns to observation-only mode only after they drain. `ABORT` remains a
separate explicit action with containment and provider-accounting rules.

At this phase `S0` still cannot launch writers, run validation, touch Git, or
open the benchmark lease. Rollback never mutates worktrees, Git, Cargo targets,
legacy archives, or processes it cannot authenticate.

### Phase 5: rolling research campaigns

After the eight-slot canary passes, allow `S0` to run discovery and audit
campaigns with `min_attempts=16`, `max_attempts=32`, weighted fairness, finite
global and campaign budgets, and analytical blocks of eight. Record achieved
concurrency and distinct-cluster yield. Do not increase beyond eight active
Ultra sessions until rate, budget, ingestion, and evidence-quality data justify
a separately approved change.

### Phase 6: deterministic validation

Only after remote scheduling survives the required restart and fault exposure
should `V0` receive local command authority. Canary one focused validation
recipe in a read-only snapshot, then the cheap diagnostic group, and only then
broader test groups. Keep writer launch, Git mutation, and benchmark automation
manual. Compare `V0` evidence with the existing validated command receipts
before retiring the Codex-mediated validation path. Require twelve clean focused
recipe executions across at least three source snapshots, including restart,
failure-bundle, disk, and malicious-fixture cases, followed by six clean cheap-
diagnostic groups before broad authority. A material runner, recipe, sandbox,
schema, toolchain, or resource-policy change resets the applicable count. A
separate independent review and named rollback owner gate this transition.

### Phase 7: later authority

Automating writer launch, Git mutation, or benchmark execution is a separate
promotion. It requires path-lease and stale-fence fault tests, source-drift
containment, exact diff/receipt authentication, dynamic disk-reservation races,
benchmark drain and contamination injection, holdout-accounting tests, an
independent review, and explicit operator approval. Relevant minimum soak gates
are twenty brokered source-only checkpoints across two lanes plus ten injected
stale-fence/path/artifact failures before Git authority; ten bounded writer
handoffs plus five containment/drift failures before writer launch authority;
and five dry-run benchmark cycles containing at least three injected
contaminations, followed by three clean representative quiet-machine cycles,
before benchmark authority. Each receipt binds the exact implementation and
configuration, and material changes reset the corresponding gate. There is no
requirement to automate these roles merely because remote reasoning scheduling
works.

Regardless of automation, promotion requires complete `V0` qualification and
the gating Ultra audits on the exact immutable integration SHA/export. `B0`
authenticates those receipts before accepting a timed result.

Throughout deployment, report green checkpoints, validated findings,
distinct-mechanism yield, queue age, slot utilization, retries, spend/budget,
and SLO violations. High utilization is not success if evidence quality or
source safety falls.

## Rationale and references

The high-variance and persona policy is motivated by the repeated optimization
experiments, independent repro checking, and contrarian-persona observations
described in [Agentic test processes, LLM benchmarks, and other notes on
agentic coding](https://danluu.com/ai-coding/).

The clean read-only session mechanics preserve the distinction between
evidence and votes.

The separation between wide read-heavy delegation and carefully isolated
write-heavy work follows the current [Codex subagent
guidance](https://learn.chatgpt.com/docs/agent-configuration/subagents.md).
