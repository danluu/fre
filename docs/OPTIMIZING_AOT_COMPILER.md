# Self-contained optimizing AOT compiler

Status: source-design Candidate

This document defines the optimization, safety, evidence, and production-routing
contract for FRE's slower, optimization-focused AOT compiler. It does not grant
runtime authority and it does not claim a current speed result.

## Objective

The compiler may spend substantially more deterministic work than the JIT, but
it must remain:

- self-contained: LLVM, Cranelift, Inkwell, a C compiler, an assembler, and a
  subprocess are not regex-code-generation dependencies;
- deterministic: output is a pure function of semantic input, target contract,
  tuning class, optimizer version, cost-model version, and explicit limits;
- bounded: candidates, work, scratch, persistent storage, code, data, labels,
  and relocations have checked hard and caller-selected limits;
- independently auditable: optimizer preference is never trusted for semantic,
  ABI, ISA, control-flow, memory, or resource correctness;
- fail-closed: compilation, object production, static adoption, qualification,
  and production authority are distinct transactions;
- evidence-gated: no AOT route is selected merely because an object exists.

The first production objective is deliberately narrower than general regex
compilation:

> Compile exact-literal, whole-haystack, non-overlapping Count programs to
> AArch64 ASIMD code and enable only a target/workload envelope that proves
> greater than 20% speedup across long-running compiled Rebar cases, while also
> passing a frozen non-Rebar holdout and adversarial matrix.

The broader objective is a typed regex Machine IR capable of compiling
fixed-width windows, literal sets, class runs, small one-pass machines, and
capture-free DFAs without changing the JIT's cheap-template role.

## Why the first slice is a recipe portfolio

Count-v2 is already a strong specialized compiler. It uses rare-column SIMD
filters, content-adaptive absent/single/dense paths, grouped sparse scans,
vector confirmation, and a successor-match run. Historical measurements show
that whole-operation specialization can beat the portable Count path
substantially.

Count-v2 nevertheless emits one general adaptive template. It always retains
runtime branches and confirmation machinery for distributions that a
pattern-only analysis can sometimes rule unlikely or make needlessly costly.
An AOT compiler can enumerate several closed kernels, price them against a
versioned robust scenario model, and emit only the selected kernel.

The first optimizer therefore chooses a `CountRecipeV3`, not arbitrary machine
instructions. A recipe names a reviewed code shape:

```text
CountRecipeV3 {
    scan_strategy,
    filter_offsets,
    sparse_group_blocks,
    dense_strategy,
    successor_strategy,
    confirmation_strategy,
    unroll,
    constant_placement,
    tail_strategy,
    schedule_id,
    register_plan_id,
}
```

The initial portfolio contains:

1. an authenticated incumbent-control recipe;
2. sparse rare-column recipes with two through four filter offsets;
3. endpoint-dense recipes;
4. periodic/successor-run recipes for certified self-overlapping literals;
5. width-specialized confirmation for 2--8, 9--16, and 17--32 bytes;
6. finite unroll, block-layout, constant-placement, schedule, and register-plan
   variants.

Empty and one-byte Count retain dedicated formulas.

Every recipe has a new backend/schema/algorithm identity. Count-v1 and Count-v2
types, identities, expected instruction streams, and object bytes remain
immutable.

## Pattern facts

Selection may inspect only the semantic program, explicit target/tuning
contract, and optional authenticated workload summary. It may not inspect:

- a benchmark name;
- a haystack path or contents under the default policy;
- prior timing results;
- host features not present in the target contract;
- wall-clock time;
- environment-dependent iteration order.

The default optimizer derives bounded facts from the literal:

- length and distinct-byte count;
- pinned general byte-frequency ranks;
- candidate filter offset/value combinations;
- prefix/suffix relations;
- KMP failure function;
- minimum period and self-overlap;
- confirmation chunks and tail;
- estimated register pressure;
- exact or conservative code and data size.

Optional profile-guided selection, if later implemented, consumes only a
content-addressed, explicitly supplied corpus summary. It may select only among
already verified recipes, and the summary identity becomes part of the
artifact identity. Profile-free production qualification remains a separate
atom.

## Deterministic portfolio search

Legal candidates are enumerated under exact integer fuel. No phase stops
because a duration elapsed. Candidate identity and every worklist have total
orders.

Each candidate receives a fixed-width integer cost vector:

```text
[sparse, dense, false_positive, match_heavy, tail, code_size]
```

The cost table is versioned by target tuning class. Feature legality and tuning
preference remain separate: a feature authorizes instructions; a tuning class
only changes ranking among legal recipes.

The optimizer removes dominated candidates and chooses the minimum minimax
regret candidate under the generic policy. Exact ties resolve by canonical
recipe encoding. A wrong cost estimate may reduce performance but cannot
change semantics or safety.

The receipt records:

- semantic program identity;
- target and tuning identities;
- optimizer, recipe schema, and cost-model versions;
- exact limits and observed work;
- literal facts;
- candidates considered, rejected, and Pareto-retained;
- selected recipe and canonical recipe identity;
- source-derived code/resource upper bounds.

## Count-v3 backend and audit

Count-v3 targets the existing three-argument direct Count ABI. The emitted
entry is a stackless leaf unless a future recipe explicitly adds a separately
reviewed stack contract.

The emitter lowers one sealed recipe through a closed AArch64 macro-assembler.
Initial recipes use ASIMD. Future SVE/SVE2 recipes are distinct target tuples;
VL16 availability never changes ASIMD legality and does not imply a
performance win.

The independent auditor:

1. authenticates the sealed exact-Count KIR and recipe receipt;
2. independently recomputes literal facts and legal recipe membership;
3. decodes every instruction word;
4. rejects instructions outside the declared target feature set;
5. validates ABI register effects and forbids unreviewed callee-saved or stack
   effects;
6. reconstructs CFG edges, relocation targets, and backward-edge progress;
7. validates every memory-access range against the reviewed recipe;
8. independently lowers the selected canonical recipe and requires exact
   decoded-stream and label equality;
9. recomputes exact resource and artifact identities.

The auditor does not need to agree that the optimizer chose the fastest legal
recipe. Preference is a performance property. It must agree that the recipe is
legal and that the bytes implement it exactly.

## Object and static deployment

The focused compiler packages Count-v3 code as a deterministic relocatable
object with hidden identity-suffixed entry, payload, metadata, and expectation
symbols. Object production does not link or execute the code.

One source-bound final-image transaction must prove:

- linked payload and metadata bytes equal the authenticated object;
- the retained hot callsite reaches the exact hidden entry;
- no PLT or unreviewed indirect-call boundary is charged as the AOT hot path;
- no writable-executable segment or executable stack exists;
- the target feature and tuning contract matches the deployment row;
- the production row pins every non-circular compiler/object/expectation
  identity.

Compiler output, a linker success, a benchmark result, and a qualification row
are not production authority individually.

## Non-overfitting evidence protocol

The evidence corpus has three disjoint classes:

1. **training** -- visible historical Count and selected Rebar development
   cases;
2. **validation** -- independently generated pattern/data combinations used to
   revise the versioned model;
3. **final holdout** -- frozen non-Rebar patterns and haystacks opened once
   after selection policy, cost tables, routing envelope, and source are frozen.

The final holdout never changes the compiler. A failure creates a new optimizer
version and requires a new unopened holdout.

The matrix crosses:

- widths 0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 24, 31, and 32;
- distinct, repeated, periodic, self-overlapping, natural, and binary literals;
- absent, sparse, tail, dense true-match, rare-filter false-positive,
  endpoint-false-positive, natural, and binary data;
- every relevant base-pointer alignment;
- at least 64-KiB and 1-MiB haystacks.

All timing comparisons are paired, rotate all six three-engine orders, and run
each retained engine sample in a fresh process. Correctness, guard-page,
resource, object, and final-image gates run before performance. Every retained
engine row runs for at least one second and searches at least one GiB; compile,
link, load, adoption, and portable-plan construction stay outside that steady
state boundary for all three arms.

## Production performance gates

An exact semantic/target/workload row may be promoted only if all of the
following hold on the frozen source and artifacts:

- zero semantic, checksum, native-fault, guard-page, audit, object, or resource
  failures;
- at least 30 retained repetitions per cell and engine, with all raw elapsed
  rows retained;
- on every target and separately in training, validation, and final holdout,
  the equal-cell geometric-mean Count-v3/portable latency ratio is strictly
  below `0.80`, establishing greater than 20% lower latency;
- in each of those target/partition slices, the equal-cell geometric-mean
  Count-v3/faster-of-(Count-v2, portable) ratio is at most `0.75`;
- every cell's geometric-mean Count-v3/faster-control ratio is at most `1.03`;
- Count-v3 strictly beats the faster control in at least 24 of 30 paired
  repetitions in every cell;
- the independently committed and frozen final holdout passes without any
  post-reveal optimizer feedback or source change;
- code size and instruction-cache costs remain inside the frozen routing
  envelope;
- Apple ASIMD and EC2 target evidence are separate; neither authorizes the
  other.

An LLVM- or clang-optimized equivalent kernel may be built as a diagnostic
performance ceiling. It is never a regex compiler dependency or authority
input.

## Runtime routing

Until qualification, all Count-v3 authority atoms and production row tables
are empty. A v3 object retains the complete fixed-width literal manifest,
optimizer recipe manifest, target contract, and their identities. Those are
not trusted merely because the compiler emitted them: static adoption
independently reconstructs the exact program and recipe, re-lowers the reviewed
template, and compares the complete mapped instruction stream before creating a
callable handle.

After qualification, routing remains construction-time and fail-closed:

1. normal semantic planning proves exact-literal whole-operation Count;
2. literal width, operation, target, feature, tuning, and workload gates match a
   reviewed production row;
3. the production row authenticates the qualified compiler/backend/auditor,
   semantic envelope, target contract, and held-out evidence bundle rather than
   enumerating Rebar job or artifact identities;
4. static adoption authenticates the linked object and expectation, validates
   the full literal and recipe manifests, and independently re-lowers and
   compares the mapped code;
5. the matcher retains the verified handle;
6. the value-only hot operation invokes the static entry;
7. every other case retains the current portable route.

There is no per-call ISA dispatch, artifact lookup, code generation, or
authority mutation.

## Broader regex AOT

Count-v3 deliberately does not pretend that the current Kernel IR represents a
general regex. A later version adds a regex-specific typed KIR2 and Machine IR:

```text
canonical HIR + operation-aware facts
  -> semantic Plan IR
  -> algorithm/shape portfolio
  -> typed SSA-like KIR2
  -> target Machine IR
  -> instruction selection
  -> deterministic no-hot-spill register allocation
  -> bounded scheduling/layout search
  -> translation validation
  -> audited object
```

Priority, greediness, captures, assertions, and empty-match progress are
semantic inputs. Language-equivalent rewrites are insufficient when they
change any of those observations.

The plan-family order is:

1. exact literals and whole-operation reducers;
2. fixed-width predicate windows and required-literal verification;
3. finite literal sets using decision trees, tries, Teddy/FDR, or
   Aho--Corasick;
4. vector class runs and delimiter scans;
5. small direct one-pass machines;
6. capture-free DFA with alphabet reduction and hybrid direct/table states;
7. tagged one-pass and bounded TDFA;
8. certified bit-state or ordered sparse TNFA;
9. Unicode ASCII fast paths with exact scalar side exits.

Machine IR uses typed haystack/data/scratch/output pointers, guarded indices,
fixed and scalable vectors, predicates, candidate masks, table operations, tag
operations, and operation-specific results. Hot scan loops reject spills.

The JIT continues to use cheap reviewed templates. Expensive analysis,
portfolio search, multiversion object production, and broader machine
optimization belong to AOT.

## Current execution status

The implementation work is isolated from canonical source. The previously
published admission fence still prohibits starting builds, tests, disassembly,
timing, coordinator commands, or remote evaluation until the exact live-helper
cutover GO is published. Source implementation and static review can proceed;
no source checkpoint is a dynamic correctness or speed claim.
