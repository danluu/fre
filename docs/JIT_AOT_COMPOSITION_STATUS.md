# JIT/AOT composition status

Last updated: 2026-07-28 (America/Vancouver)

This document describes implementation Candidate
`ec6651f767561d65524d1190b6afd52157bad545`, tree
`fd89927138f0a64f934a01debf3d78a87d07f904`. Its relevant composed
succession is:

```text
65f4910a  Linux SelectedEnd ABI2 AOT qualification bundle
  -> 8ae82e80  public JIT bakeoff migrated to register ABI2 sessions
  -> 1fb7d684  V3 evidence bound to an external ABI2 witness
  -> ec6651f7  hidden direct-call AOT declarations hardened
```

The documentation child adds no implementation or dynamic evidence. Review or
evidence from an ancestor does not authorize this exact composed tree.

## Compiler boundary

LLVM is not, and cannot become through these paths, the regex compiler. FRE's
typed Kernel IR feeds custom direct machine-code emitters:

- Search JIT and Search AOT use `fre-jit-aarch64`. The current V8/tag-21
  `SelectedEnd` ABI2 paths consume the same sealed typed image contract. JIT
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

V8, SVE tag 19, and SVE2 tag 21 use the sealed four-argument `SelectedEnd`
register-return ABI2. The haystack and half-open window occupy `x0` through
`x3`; `x0` returns zero for no match or the absolute exclusive match end.
ABI2 has no `x4` result pointer and no caller-owned result slot. The strict-W^X
publication handle has no direct call method: every generated-code call must
pass through its neither-`Send`-nor-`Sync` current-thread session. Sessionless
facade calls use the retained portable owner.

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
glue and receipt contracts reject `blr`, a PLT target, any `x4` argument, and
any caller-owned result slot. These are source-level requirements for a future
linked-image inspection. The receipt reports `observation_complete = false`,
every P2b value reports runtime authority `Absent`, and this source contains
no ABI2 runtime adopter, authority row, mapped callable, or completed
post-link observation.

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

The existing checked-in Linux three-engine harness still measures the retained
Search V1 Span adoption/raw-Span-JIT contract. A replacement that exercises
the P2b `SelectedEnd` ABI2 AOT/JIT/portable tuple is in progress and remains
deferred at this Candidate: there is no sealed ABI2 three-engine source,
linked image, runtime adopter, post-link observation, retained run, or result
bundle to report.

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
