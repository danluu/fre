# JIT/AOT composition status

Last updated: 2026-07-28 (America/Vancouver)

This document describes implementation source sealed at
`0bd0f5d085d01d2b21d06845af9b461d01c963d3`, tree
`f23cebd1ca60a960978e495be7914d447e93f8ca`. Its immediately relevant
succession is:

```text
d8be7786  SVE tag 19 moved to SelectedEnd register ABI2
  -> 0bd0f5d0  source-bound tag-19 ABI2 qualification producers
```

Protocol/docs child
`63225a1dbf812159449cd4420386ff236f1197f7` adds a Candidate-rooted
executable verifier and documentation, but no runtime/compiler implementation
or dynamic evidence. Git content cannot embed the identity of its own
containing commit; the verifier therefore authenticates the externally
supplied exact final Candidate commit and tree at run time. Review or evidence
from an ancestor does not authorize that composed tree.

## Compiler boundary

LLVM is not, and cannot become through these paths, the regex compiler. FRE's
typed Kernel IR feeds custom direct machine-code emitters:

- Search JIT and Search AOT use `fre-jit-aarch64`. The qualified facade's
  V8/tag-19/tag-21 `SelectedEnd` ABI2 paths consume the same sealed typed image
  contract. JIT
  gives that image to `fre-jit-runtime` for strict-W^X publication; AOT
  revalidates and packages the already-emitted tag-21 payload as deterministic
  ELF bytes.
- Count-v2 AOT uses the separate focused direct-Count emitter in
  `fre-aot-aarch64`, then deterministic object and final-image glue layers.

LLVM may be used only underneath `rustc` or another host/toolchain component
that compiles FRE's host and tool code. A system linker may package the
already-emitted payload in a final executable. Neither LLVM nor the linker
selects, optimizes, or generates the regex machine-code payload.

## Current JIT authority

The current exact-search facade keeps backend authority separate for Search
V8, tag 10, tag 19, and tag 21. All four production qualification atoms in
`crates/fre/src/qualified_exact_search_qualification.rs` are `Candidate`.
Candidate is not authorization: with no qualified atom the facade reports an
unqualified native status before host probing, emission, or publication.

The qualified exact-search facade routes V8, SVE tag 19, and SVE2 tag 21
through the sealed four-argument `SelectedEnd` register-return ABI2. The
haystack and half-open window occupy `x0` through `x3`; `x0` returns zero for
no match or the absolute exclusive match end. ABI2 has no `x4` result pointer
and no caller-owned result slot. The strict-W^X publication handle has no
direct call method: every generated-code call must pass through its
neither-`Send`-nor-`Sync` current-thread session. Sessionless facade calls use
the retained portable owner. Versioned low-level Search-v1 tag-19 emit/publish
APIs remain distinct research/compatibility surfaces; their result-slot
evidence cannot authorize this facade ABI2 route.

For default publication limits, those ABI2 routes now consult one bounded
process-local pre-emission cache only after the literal-width, workload,
qualification, ABI, and host-support gates pass. A hit skips KIR construction,
emission, image audit, executable mapping, and publication. The matcher owns a
cache lease, and its plan-bound current-thread session borrows the retained
publication; no cache lookup, mutex, or lease clone occurs in a repeated hot
search. Cache construction/admission/accounting failures remain typed,
observable portable fallbacks. Kernel-IR and emission errors remain build
errors, publication errors retain the existing unavailable status, and
nondefault publication limits retain the direct owned-publication path. This
source checkpoint has not been built or benchmarked under the active admission
fence.

When independently authorized, automatic selection prefers tag 21 on an
admitted Arm `0x41/0xd84` ASIMD+SVE+SVE2 host, then considers tag 10, tag 19,
and V8 under their own authority. Tags 19 and 21 do not pin or query VL at
publication. Each observes the calling thread's SVE vector length exactly once
when the callable session opens and requires VL16; calls inside that session
perform no VL query. Tag 19 requires ASIMD+SVE, tag 21 requires
ASIMD+SVE+SVE2, and both retain the exact Arm `0x41/0xd84` tuning envelope.
V8 session creation performs no SVE syscall. An atom for one backend cannot
authorize another.

Private scoped Candidate execution exists for tests and qualification source.
It does not manufacture a production `Qualified` atom or expose a
caller-controlled production setter. No historical JIT result is a deployment
or speed claim for this composed tree.

## Current AOT authority

The Linux P2b AOT compiler is source-first and inert. It rebuilds typed
`SelectedEnd` KIR and retains the same sealed tag-21 ABI2 image used by the
JIT route, then emits a deterministic ELF implementation object, neutral
expectation, exact hidden identity-suffixed declarations, a deterministic
four-instruction direct-call glue object, and signer-free receipts binding the
source/KIR/image/object/glue tuple. The glue's sole relocation is
`R_AARCH64_CALL26` on a direct `bl`.

The declarations expose no generic alias or function-pointer typedef. The
glue and receipt contracts reject `blr`, a PLT target, any ABI `x4` argument,
and any caller-owned result slot. These are source-level requirements until a
linked-image inspection passes. The receipt reports
`observation_complete = false`, every P2b value reports runtime authority
`Absent`, and there is still no ABI2 authority row or completed post-link
observation. There is now a default-off qualification-private safe consumer:
the generated bind consumes the static-runtime current-thread token, compares
its embedded literal with one external portable plan, records its hardcoded
private compile-identity key, then owns that token inside a generated
artifact-private nominal type. The generated type structurally fixes that key
without claiming a separate runtime key comparison. Repeated preflighted calls
use only plan identity rather than re-comparing literal bytes or the artifact
key, and no callable address is stored.

The retained Count-v2 and Search V1 Span adoption paths are separate
contracts. Their features, registries, or linked symbols cannot authorize the
new ABI2 path; the retained Search V1 production and qualification-private
tables also remain empty.

## Evidence status

The public JIT bakeoff source now emits 48-column `fre-jit-bakeoff-v3` rows for
the explicit V8 register-return ABI2 policy. It opens one current-thread
session outside each hot search timer and uses the value-only session call.
The evidence repair adds an external, independently named `abi2_identity`
witness for the exact ASIMD V8 target/backend/ABI/no-VL tuple. V3 verification
requires that witness, binds the backend policy, target, ABI and VL facts into
the evidence identity, and rejects rows whose self-reported artifact and
evidence hashes were rewritten together. Historical V2 rows retain their
legacy Span identity rules. This is implemented harness/verifier source, not
a claim that a V3 run passed or produced performance evidence.

Tag 19 now has separate source-bound ABI2 evidence producers: a low-level
correctness executable for the exact four-argument image/session boundary and
a V5 fresh-process facade campaign that compares public portable and
Candidate-guarded NativeJit routes. Its Candidate-extracted verifier parses
the retained raw rows, reconstructs correctness and performance summaries,
and permits tag-19 authority only beside an independently verified V8
fallback. No producer has been run at this checkpoint, so this is not
qualification or a speed result.

The checked-in Linux three-engine harness now consumes the exact deterministic
P2b `SelectedEnd` ABI2 deployment binding and compares that safe static AOT
route with the byte-identical strict-WX tag21 JIT and portable plan. The JIT
benchmark session is bound once to that exact portable literal plan, matching
the qualified facade's one-pointer hot-path identity check. The harness
persists the compiler binding and deployment receipt separately from benchmark
metadata and exposes an exact hidden consumer hot-loop symbol for a
benchmark-specific post-link proof. This checkpoint is source/static-only:
the binding, owning sessions, verifier, and campaign updates have not been
built or run, so there is no completed linked-image observation, retained
campaign, speed result, or production authority to report.

Historical macOS Count and Search evidence remains development evidence only
for its exact source/artifact tuples. No Search row is promoted and no current
AOT performance or deployment claim is made.

An absolute temporary admission fence currently forbids new coordinator or
headroom-coordinator builds and timings until explicit live-cutover GO. This
docs checkpoint used source/static inspection only; it makes no build, test,
runtime, or performance claim. After GO, fresh evidence must bind one exact
composed commit, tree, source closure, toolchain, binary, linked image,
authority row, and retained raw result set before any promotion or speed
claim.

See [`AOT_TRACK_STATUS.md`](AOT_TRACK_STATUS.md) for the bounded Count/Search
scope and [`SEARCH_AOT_FACADE_BINDING.md`](SEARCH_AOT_FACADE_BINDING.md) for
the retained Search V1 explicit binding contract; that binding is not an ABI2
adopter.
