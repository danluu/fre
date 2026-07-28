# FRE JIT/AOT architecture and AOT production track

Last updated: 2026-07-28 (America/Vancouver)

## Current composition and temporary admission fence

This document describes implementation Candidate
`ec6651f767561d65524d1190b6afd52157bad545`, tree
`fd89927138f0a64f934a01debf3d78a87d07f904`. That exact source contains the
V8/tag-21 register-return JIT, Linux tag-21 `SelectedEnd` P2b AOT bundle,
public bakeoff V3 migration/evidence repair, and hardened hidden AOT
declarations. Source review or evidence from an ancestor does not qualify this
composed tree.

An absolute temporary admission fence is still in force. No new
build, test, timing, or coordinator command may start without explicit
live-cutover GO. This documentation checkpoint therefore uses source/static
inspection only and makes no build, test, dynamic-correctness, or performance
claim.

## Architecture: LLVM is not the regex compiler

The regex compiler has no LLVM code-generation path. Search JIT and Search AOT
share FRE's typed Kernel IR and custom direct AArch64 machine-code emitter in
`fre-jit-aarch64`. The Count-v2 AOT slice uses the separate custom direct-Count
emitter in `fre-aot-aarch64`. Both produce immutable pattern-specialized
instruction bytes, data, relocations, ABI/target contracts, resource
statistics, and identities. Their generated entries are ordinary AAPCS64
machine code, not regex bytecode or interpreter dispatch loops.

The paths diverge only after emission:

- the JIT route gives the sealed image to `fre-jit-runtime`, which checks the
  backend/host/output/ABI contract, copies and byte-compares the complete
  writable payload, performs the strict-W^X transition and instruction-cache
  maintenance, and owns the resulting mapping;
- the Search AOT route revalidates the same sealed image and writes
  deterministic ELF bytes. Count-v2 uses its independently typed direct-Count
  image and deterministic Mach-O layers. A linker can only package those
  already-generated payloads.

LLVM may be used only underneath `rustc` or another host/toolchain component
that compiles FRE's host and tool code. Apple clang/ld or the Linux system
linker may package an object into an executable. Neither LLVM nor the linker
selects, optimizes, or generates the regex payload; FRE's custom emitters have
already generated it. An LLVM reference in a host toolchain record therefore
does not describe FRE's regex-codegen architecture.

## Retained Count-v2 production-track scope

The retained Count-v2 production-track AOT Candidate is deliberately narrow
and separate from the Linux `SelectedEnd` ABI2 work:

| Dimension | Current Candidate | Not implemented or qualified here |
| --- | --- | --- |
| Operation | Whole-haystack, non-overlapping `Count-v2` | Generic search/find, captures, replace, split, or arbitrary aggregates |
| Pattern | Private qualification Candidate row: exact byte literal `needle`, selector 11. The production table is empty while its promotion atom is all-zero. The focused compiler itself accepts exact byte literals from 0 through 32 bytes. | Other literals are not production-qualified; general regex syntax such as alternation, repetition, classes, or Unicode semantics is not lowered by this compiler. |
| Code generator | FRE's direct custom AArch64 Count emitter | LLVM, Inkwell, Cranelift, x86-64, or other native backends |
| Production object and host | arm64 Mach-O on macOS | Linux retains a separate Search V1 qualification architecture, while the current `SelectedEnd` ABI2 P2b ELF bundle has no adopter or authority row. COFF/Windows, other operating systems, and cross-host deployment are not implemented here. |
| Deployment | Statically linked implementation and final-image glue, immutable mapped-image verification, authenticated process-static handle | General artifact discovery, cache/distribution, dynamic loading, or runtime code generation |
| Promotion | One reviewed manifest digest in the C5 `support.rs` atom | Automatic qualification or registration of arbitrary compiler output |

`rustc` may itself use LLVM and Apple clang/ld performs the final Mach-O link.
Neither is the Count compiler: the Count instruction bytes and Mach-O object
contents are emitted by FRE's focused compiler.

This is real machine-code AOT for a bounded exact-literal Count-v2 compiler,
with one exact `needle`/selector-11 private Candidate row and no current
production row; it is not “full regex AOT.” Compiler support for another
0-through-32-byte literal does not authorize runtime adoption of that literal.
The intended broader architecture still needs independently measured and
reviewed search and aggregate row types, general regex lowering and native
backends, additional hosts, and production artifact lifecycle integration.
The Search and Count AOT slices described in this document are exact-literal
slices, not a general-regex AOT compiler.

## Current Linux `SelectedEnd` ABI2 P2b slice

The current Linux AArch64 P2b slice is an inert exact-literal
`SelectedEnd` compiler/bundle path:

- source-first planning rebuilds typed `SelectedEnd` KIR and asks
  `fre-jit-aarch64` for the sealed
  `SEARCH_SVE2_FIXED16_V2`/tag-21 register-return image under the exact
  ASIMD+SVE+SVE2, 16-byte-literal, VL16 contract;
- the compiler retains that same sealed image and wraps it in a deterministic
  ELF64LE relocatable with hidden, identity-suffixed entry, payload, and
  metadata symbols;
- the ABI has exactly four arguments: `x0` through `x3` carry the haystack and
  half-open search window, and `x0` returns zero or the absolute exclusive
  selected end. There is no fifth argument, `x4` result pointer, caller-owned
  result slot, or generic callable alias;
- a neutral expectation and compiler receipt bind source, semantic plan, KIR,
  sealed native artifact, payload, metadata, object, resources, and identities;
  and
- the qualification bundle adds deterministic assembly/C declarations and a
  canonical four-instruction hidden wrapper. Its sole relocation is
  `R_AARCH64_CALL26` on a direct `bl` to the exact identity-suffixed entry.

The glue receipt carries mandatory future final-image checks: the call must
remain a direct `bl`, may not resolve through a PLT, and the linked wrapper
must contain no `blr`, `x4` argument, or result slot; all implementation and
wrapper bindings must remain hidden and identity-suffixed. The checked-in
receipt is not that observation. Its `observation_complete` field is false,
every exposed P2b value reports `SelectedEndAotRuntimeAuthorityV2::Absent`,
and this Candidate contains no ABI2 static adopter, authority row, mapped
callable, linked-image inspection receipt, or deployment path.

This is the AOT half of the same native-image architecture as JIT, not a second
optimizer: JIT publishes the sealed image under strict W^X, while P2b stops
after deterministic packaging and diagnostic receipts. The generated
qualification-private binding compares its embedded literal with the portable
plan once, then uses its private compile-identity key and plan identity for
repeated scalar-preflighted hot calls.

## Retained inert Search V1 slice

The workspace also retains the older source-first nonempty exact-literal
Search V1 compiler candidate. This remains compiler groundwork, not an
expansion of the production scope above and not an adopter for ABI2:

- it starts from the normal portable facade's live exact-literal plan rather
  than accepting an unauthenticated literal-only bypass;
- it rebuilds typed `Exists`, `SelectedEnd`, or `Span` Kernel IR and emits the
  audited custom AArch64 Search V8 machine image;
- it wraps that image in a deterministic arm64 Mach-O object and returns a
  receipt binding the source/profile/report, literal, manifest, Kernel IR,
  native artifact, object metadata, and object identities;
- for `Span`, it can also emit deterministic final-image glue containing the
  fixed authenticated expectation and an unsigned receipt binding the
  compiler, implementation object, compiler receipt, expectation, glue, and
  code identities;
- its runtime-authority field is unconditionally `Absent`; it does not invoke
  a linker, map executable memory, discover a symbol, or call generated code.

The facade's qualified JIT surface is a default-on
`qualified-exact-search-jit` feature so existing `fre` users keep the same API
and behavior. `fre-aot-compiler` explicitly disables that default feature: its
facade dependency therefore supplies portable planning and the authenticated
candidate handoff without pulling in `fre-jit-runtime`. The compiler still
depends directly on `fre-jit-aarch64` because that crate is the bounded custom
machine-code emitter; it does not publish executable memory.

Search V1's three output kinds do not share one result-store rule. `Exists`
writes neither result word, `SelectedEnd` writes only `end`, and `Span` writes
both `start` and `end`. The static-runtime crate therefore has a typed inert
decoder for these exact rules, while the old generic C-header success wording
is treated as directly applicable only to `Span`.

The source-first static `Span` adopter is now implemented, but neither of its
literal authority tables contains a row. It resolves the row before touching a
final-image address, copies and authenticates the fixed expectation and
metadata from maximally read-only mappings, verifies the payload in a
maximally RX mapping, checks the exact ASIMD/entry/alignment/digest contract,
and returns only a registry-owned safe handle. Production and private
qualification registries and symbols are disjoint. Enabling either Cargo
feature cannot manufacture a row, and the compiler's
`RuntimeAuthority::Absent` receipt remains insufficient for adoption. This is
a real fail-closed static-link architecture, not a production activation.

One final image may contain at most one Search glue object for a given compile
identity. Glue and expectation definitions are suffixed by that identity;
attempting to link multiple row selectors, or both production and private
adopters, for the same implementation intentionally creates duplicate strong
definitions and must be rejected by the linker. That duplicate-link refusal
still needs post-fence validation.

The retained standalone Search V8 bakeoff source and checked-in Linux
three-engine harness exercise the Search V1 Span contracts: raw or privately
adopted static AOT, raw strict-W^X Span JIT, and the portable plan. They do not
exercise the new `SelectedEnd` ABI2 P2b bundle and cannot serve as its
qualification evidence.

### Public bakeoff V3 and deferred ABI2 three-engine work

The current public JIT bakeoff source emits 48-column
`fre-jit-bakeoff-v3` rows for explicit V8 `SelectedEnd` ABI2. It establishes
one current-thread session before each search-only timer and calls only the
value-returning session method in the hot loop. Full-workload rows include
owner/session construction once and then the declared value-only workload.

The evidence repair makes the measured native identity externally
checkable. The exact-Span inspection sidecar retains its legacy `identity=`
field for historical V2 rows and adds a distinct `abi2_identity=` witness for
the ASIMD V8 target, backend, register ABI2, and no-VL contract. V3 verification
requires that external witness, binds backend policy, target, ABI and VL facts
into the evidence identity, and rejects a row whose artifact, canonical
binding, and evidence hash were rewritten together. This Candidate contains
that source repair; this checkpoint did not run it and records no V3
correctness or performance result.

The new P2b three-engine benchmark must compare the exact same sealed tag-21
artifact through authenticated static AOT, strict-W^X session-only JIT, and
the portable semantic owner. That benchmark is still in progress and deferred
at this Candidate. The checked-in Linux three-engine harness is for Search V1
Span, not the register-return ABI2 path. P2b currently has neither a completed
post-link observation nor a runtime adopter, so there is no honest callable
AOT engine to time and no sealed ABI2 three-engine result bundle.

The remaining ABI2 closure order is therefore:

1. independently review and freeze one exact source/tree and P2b artifact
   tuple;
2. after explicit admission, build/link it and issue the missing post-link
   observation only after all direct-call, hidden-binding, no-PLT, no-`blr`,
   no-`x4`, and no-result-slot checks pass;
3. add and review a qualification-private adopter without changing the empty
   production authority state;
4. complete separately bound tag-21 public-facade evidence for the same sealed
   artifact; and
5. seal and run the replacement ABI2 AOT/JIT/portable benchmark before making
   any runtime, lifecycle, or performance claim.

No benchmark source, result, private-row proposal, compiler receipt, or linked
symbol is production authority by itself.

## Retained Count-v2 Candidate architecture

```text
exact literal + untrusted planning claims
  -> locally rebuilt typed exact-aggregate Count KIR
  -> bounded custom AArch64 emission and independent audit
  -> deterministic implementation.o + final-image-glue.o
  -> static final image with immutable __FRE_CONST ranges
  -> literal source qualification row
  -> mapped-image, identity, payload, metadata, and resource checks
  -> registry-owned VerifiedStaticCountV2
  -> bounded Count-v2 calls
```

The measured C5 Candidate uses a separately named unsafe qualification glue,
candidate table, and private registry. Ordinary safe production adoption uses
only the production table, which remains empty while the promotion atom is
all-zero. The promotion transaction is a direct-child, exact-atom source
change tied to a Candidate-extracted bundle verifier and an independently
pinned review receipt. A combined JIT+AOT promotion may delegate the global
two-path union to a Candidate-rooted top-level verifier, but the AOT verifier
still owns the exact `support.rs` rendering and all AOT receipts.

## Evidence status: macOS Count

Earlier macOS Count compiler, object, runtime, and timing results are retained
as historical development evidence only. In particular:

- the July-26 resource-gate records describe an earlier admission state;
- C3/C4 results predate the final C5 production/private-registry split;
- pre-freeze C5 smoke timing established feasibility but is not promotion
  evidence;
- retained C5 objects remain useful exact inputs, but the final Candidate
  source identity changed when the promotion trust root and correctness gate
  were added.

Fresh final evidence is pending after authenticated build admission:

1. runtime and focused compiler tests, formatting, Clippy, and unsafe-boundary
   audit;
2. all four production feature modes and private-symbol isolation;
3. two byte-identical release builds and complete evidence regeneration;
4. three fresh-process C5 timing runs and raw-derived performance gates;
5. closed-bundle replay plus raw and bundle tamper suites;
6. candidate-rooted promotion and trust-root regression;
7. atom-only Candidate-versus-Promoted safe-adapter correctness in all four
   feature modes.

Until those complete against one exact frozen commit/tree/source/binary tuple,
no fresh result should be described as final qualification or promotion
evidence. The Linux `SelectedEnd` ABI2 lane has the distinct, still-unrun
closure sequence above; neither lane's evidence can authorize the other.

## Next actions after live-cutover GO

For the macOS Count lane:

1. Admit correctness and reproducibility jobs through the authenticated
   replacement coordinator.
2. Freeze the exact Candidate commit, tree, v2 benchmark-source identity, and
   byte-identical binary.
3. Run the sealed three-process qualification wave when headroom is available;
   do not require all unrelated CPU work to stop.
4. Obtain an independently pinned measured review receipt outside the bundle.
5. Run the Candidate-rooted promotion verifier and adversarial trust-root
   suite.
6. Run the correctness-only production glue on both the all-zero Candidate and
   atom-promoted direct child.
7. Treat broader search/aggregate/full-regex AOT as separate future
   qualification work, not as an inference from C5.

For Linux `SelectedEnd` ABI2, follow the frozen-source, post-link observation,
qualification-private adopter, same-artifact public-facade, and replacement
three-engine sequence above. The two lanes may proceed independently once
each job has authenticated admission, but neither may bypass its own evidence
chain.
