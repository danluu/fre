# FRE JIT/AOT architecture and AOT production track

Last updated: 2026-07-27 (America/Vancouver)

## Current composition and temporary admission fence

This document describes the AOT core composed as a path-scoped child of the
current JIT/VL16 source: `96b1465e4da959f2954e1b333619d43ff169d3df`
followed by `1b6d25636fd7b2509e19459e99a868ae8aa59f1e`. Source review of an
ancestor or imported path does not qualify the composed tree or transfer its
dynamic evidence.

An absolute temporary admission fence is still in force. No new
resource-coordinator or headroom-coordinator build or timing command may start
until the controller publishes explicit live-cutover GO for the reviewed
candidate helper whose SHA-256 begins `85c1ce3a`. A source checkpoint, an
installed helper, or an earlier deployment record is not that GO. This docs
composition therefore uses source/static checks only and makes no new dynamic
correctness or performance claim.

Future Linux c9g/m9g work remains bound to the disjoint same-host
`linux-target-cpu-local-v1` source at commit
`ed6e50ee3f04d5c446779d3abb42ad9b803b883c`, tree
`1aa73701fbd944d1a278dde717080683fe5f2f56`, helper SHA-256
`d28346610e8060c16dec861bd37f1169992905c7659e89242ef6658734d3f4cf`,
and registered-child SHA-256
`2d7c67d20d57e46ce1e30f46404ce4460d8c54a78ac12545a3d0250dc0f54b56`.
Those pins are retained inputs, not permission to run while the fence is
active. After explicit GO, a single-threaded benchmark may coexist with other
CPU work when a bounded headroom sample admits the selected CPU; it must not
wait indefinitely for global idleness or stop unrelated work.

## Architecture: LLVM is not the regex compiler

The original direct-machine-code design has not been replaced by an
LLVM-based regex compiler. Search JIT and Search AOT share the typed Kernel IR
and FRE's custom AArch64 emitter in `fre-jit-aarch64`. The Count-v2 AOT slice
uses the separate custom direct-Count emitter in `fre-aot-aarch64`. Both
emitters produce immutable pattern-specialized instruction bytes, data,
relocations, ABI/target contracts, resource statistics, and identities. Their
generated entries are ordinary AAPCS64 machine code, not regex bytecode and
not interpreter dispatch loops.

The paths diverge only after emission:

- the fresh-emission JIT route gives a private `AuditedNativeImage` capability
  to `fre-jit-runtime`. That path retains the emitter's completed independent
  audit instead of repeating its three full-image decode passes, while still
  checking the backend/host/output contract, copying and byte-comparing the
  complete writable payload, performing the strict-W^X transition and
  instruction-cache maintenance, and publishing a typed callable whose
  mappings remain owned by the runtime. Generic publication from a plain
  `NativeImage` continues to run the independent runtime audits;
- the Search AOT route revalidates the same Search image, while Count-v2 uses
  its independently typed direct-Count image. Both routes write deterministic
  Mach-O or ELF object bytes. A system linker packages those already-generated
  bytes in a final executable, and a source-qualified static adopter must
  authenticate the retained payload, metadata, immutable mappings, and an
  exact registry row before exposing a safe callable.

`rustc` may use LLVM to compile FRE's Rust host code and build tooling. Apple
clang/ld or the Linux system linker may package an object into an executable.
Those tools do not select, optimize, or generate the regex payload: FRE's
custom emitters have already generated it. Accordingly, an LLVM reference in a
host toolchain record is not evidence that the regex compiler architecture
changed.

## Exact production scope

The current production-track AOT Candidate is deliberately narrow:

| Dimension | Current Candidate | Not implemented or qualified here |
| --- | --- | --- |
| Operation | Whole-haystack, non-overlapping `Count-v2` | Generic search/find, captures, replace, split, or arbitrary aggregates |
| Pattern | Private qualification Candidate row: exact byte literal `needle`, selector 11. The production table is empty while its promotion atom is all-zero. The focused compiler itself accepts exact byte literals from 0 through 32 bytes. | Other literals are not production-qualified; general regex syntax such as alternation, repetition, classes, or Unicode semantics is not lowered by this compiler. |
| Code generator | FRE's direct custom AArch64 Count emitter | LLVM, Inkwell, Cranelift, x86-64, or other native backends |
| Production object and host | arm64 Mach-O on macOS | Linux AArch64 ELF has separately source-gated Search qualification and production-atom slices described below; neither compiler output nor a private row creates production authority. COFF/Windows, other operating systems, and cross-host deployment are not implemented here. |
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

## Inert Search compiler slice

The workspace now also contains a source-first nonempty exact-literal Search V1
compiler candidate. This is compiler groundwork, not an expansion of the
production scope above:

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

The standalone Search bakeoff source compares the same V8 image
through three honestly named routes: raw statically linked AOT with
benchmark-local ABI decoding, strict-W^X JIT publication, and the portable
exact-literal plan. Its results are not qualification evidence until the
temporary admission fence is lifted and the sealed correctness, linked-image,
tamper, and timing checks run.

### Linux AArch64 ELF Search qualification slice

The composed source also contains a deliberately inert Linux AArch64 ELF
slice for exact-literal Search `Span`. It can:

- emit the direct-machine-code `SEARCH_SVE2_FIXED16_V2` image (tag 21) under
  the exact ASIMD+SVE+SVE2, VL=16 contract;
- wrap that `NativeImage` in a deterministic ELF relocatable object and
  identity-derived final-image glue;
- independently inspect the linked ELF image; and
- route a successfully authenticated row through the disjoint
  qualification-private static adopter.

This is an implemented qualification path, so “ELF/Linux is unimplemented” is
no longer an accurate description. It is not by itself a Linux production
activation. At the source-preparation checkpoint described here, the
production Search table and qualification-private Search table both begin
literal-empty. The first reviewed transaction may replace only the private
atom; a later, separately reviewed transaction may replace only the production
atom. A compiler receipt, feature flag, linked symbol, proposal, or private row
cannot manufacture production authority.

The path-scoped AOT core import includes the reopened-object payload-binding
repair: the source-reconstructed `NativeImage` is authoritative over complete
ELF code, padding, rodata, layout, statistics, metadata, and identities. That
source property closes the internally self-consistent substituted-payload gap,
but it still needs validation on one frozen composed Candidate after the
admission fence. Its presence is not a claim of a completed build or test.

The remaining Linux closure work is explicit:

1. independently review the composed successor, including executable forged
   build-holder refusal and wrong registered-child refusal, then freeze its
   canonical source lock together with the full-image binding repair;
2. only after both that source re-audit GO and the live deployment GO, build
   and validate one exact
   commit/tree/source/dependency/toolchain/binary tuple;
3. complete the full 3,317-task tag-21 hardware qualification: 2,160 direct
   five-engine timing cells, 1,152 process-bound public-facade cells, and the
   five closed setup/verification/sealing tasks. Its sealed
   `tag21_artifact_sha256` must equal the AOT Candidate's native artifact
   identity; tag-10, tag-19, V8, partial, or losing evidence cannot substitute;
4. only then export, independently review, and pin the exact
   qualification-private row; that private transaction must leave the
   production table byte-exact empty;
5. use that safe private adopter for the closed three-engine
   AOT/JIT/portable timing matrix and its correctness, lifecycle, and
   performance gates; and
6. consider production promotion only from the complete reviewed evidence
   chain.

No benchmark result, private-row proposal, or source-complete implementation
is promotion authority by itself. No production Search row may be added
before that evidence.

## Current Candidate architecture

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
evidence. The Linux Search lane has its separate, still-unrun closure sequence
above; neither lane's evidence can authorize the other.

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

For Linux Search, follow the source/build closure, full 3,317-task tag-21
prerequisite (including both the 2,160 direct cells and 1,152 facade cells),
reviewed qualification-private row, and three-engine timing sequence above.
The two lanes may proceed independently once each job has authenticated
admission, but neither may bypass its own evidence chain.
