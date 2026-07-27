# FRE runtime SIMD dispatch

## Contract

FRE ships portable binaries and makes immutable dispatch decisions outside hot
loops. `fre-target-features` owns the process-wide hardware/OS snapshot and the
variant-selection contract. `fre-simd-kernels` owns safe, compiled kernel
handles whose private `#[target_feature]` leaves cannot be called without a
successful selection.

Target-specific deployments may replace runtime detection with a compiler
specialized snapshot. Build every crate with the same target flags and enable
the top-level `static-dispatch` Cargo feature; `fre-target-features::host()`
then uses only compiler-set `cfg(target_feature)` facts. The
`static-dispatch-arm-41-d84` feature declares the Arm implementer and part used
by the qualified Neoverse V3 preference rules. It requires little-endian Linux
AArch64 with compiler-enabled NEON, SVE, and SVE2. Cargo rejects misspelled or
unsupported profile names instead of silently producing a generic build.
Static handles retain neither a function pointer nor a CPU-feature dispatch
discriminant.
Their operation methods compile to a direct call to the profile-selected
scalar, NEON, SVE/SVE2, SSE/AVX, or AVX-512 leaf. Selection tables replace
function pointers with zero-sized metadata and are entered only when a
non-automatic policy or masked snapshot must authenticate the fixed leaf. The
common host-plus-`Auto` path does not walk a selection table. A policy or
masked capability snapshot is accepted only when it selects that same
compiler-fixed leaf; a policy that would retarget the operation returns
`UnsupportedRequiredFeatures`.

Static handles also retain no `SelectionReceipt`. Their `selection()` methods
const-reconstruct the compiler profile's normalized `Auto` receipt. A
same-leaf custom policy is therefore a construction-time assertion, not
per-handle provenance; use a runtime profile when exact forced-policy
provenance must remain attached to the handle. On 64-bit targets this keeps
the byte-set classifier, run scanner, and word/space classifier at 32, 56, and
32 bytes respectively instead of carrying 160-byte receipts. Use a runtime
profile for portable/forced-ISA qualification in one binary. The tuned V3 run
scanner still makes one set-dependent choice between its NEON path and its
small-set NEON/SVE2 hybrid, but it performs no CPU-feature dispatch at the
operation boundary. Out-of-line assembly leaves remain ordinary direct calls,
not inlineable Rust.

Static ISA and declared tuning remain separate evidence. Tuning never adds a
feature, and generic static profiles map all stable compiler-exposed members of
the current feature vocabulary. Stateful SME remains excluded. Because Rust's
runtime feature macros short-circuit for compiler-enabled features, they cannot
verify such a binary independently. Use a separately baseline-compiled
deployment gate to prevent launching a target-specific executable on
incompatible hardware; it may execute target instructions before `main`.

For performance comparisons, pass target flags globally (for example through
`CARGO_ENCODED_RUSTFLAGS`) so dependency crates see the same features. Runtime
and static candidates must use identical `-C target-cpu`/`-C target-feature`
flags; only the FRE static-dispatch cfg may differ. Do not prewarm dispatch in
the benchmark runner: cold-process measurements include initialization that
the public operation actually performs.

Compile-time dispatch does not erase an operating system's SIMD-state
activation cost. In particular, Linux can trap a thread's first SVE
instruction to allocate and initialize SVE state. A target-specific deployment
may amortize that naturally elsewhere, but qualification must not move the
cost out of a cold public-operation boundary with a benchmark-only warmup.
The state is per-thread, and the kernel may re-enable trapping across system
calls. Compare a NEON-selected control when first-use latency matters, but
classify it as a different-ISA experiment: removing SVE from only FRE's
selection is not enough if global target flags, the loader, or another library
can execute SVE before the measured boundary. Record the selected receipts and
inspect the complete binaries' instruction envelopes.

Instruction safety and performance tuning are separate:

- a variant lists every ISA feature required to enter it;
- runtime detection supplies only features that the current OS makes usable;
- in runtime profiles, a policy can remove features or require real features,
  but cannot invent them;
- in static profiles, a policy can validate the fixed leaf but cannot retarget
  it, and the resulting handle reports the compiler profile's normalized
  `Auto` receipt rather than retaining custom-policy provenance;
- a tuning predicate may change preference or thresholds, but cannot authorize
  instructions; and
- runtime selections retain a receipt containing the exact variant, feature
  evidence, caller policy, tuning identity, vector shape, and operation width;
  static handles const-reconstruct the equivalent compiler-profile receipt.

Apple CPU-family values, Arm implementer/part values, and x86
vendor/family/model values are therefore tuning identities, not proxy feature
checks. This also avoids generation-name assumptions when a processor revision,
VM, OS, or translation environment exposes a different feature set.

## Current matrix

| Architecture | Detection | Qualified compiled leaf | Detected but not yet executable |
| --- | --- | --- | --- |
| Apple AArch64 | stable Rust probes plus `sysctlbyname`; raw CPU family retained for tuning | scalar and 16-byte NEON ASCII byte-set masks | SME/SME2/SME2.1 and subfeatures are reported but excluded from `usable` until their state/ABI boundary is qualified |
| Little-endian Linux AArch64 | stable Rust runtime probes; complete homogeneous `/proc/cpuinfo` implementer/part retained for tuning | scalar, 16-byte NEON, and vector-length-agnostic SVE2 32-byte ASCII byte-set masks; automatic policy selects a distinct Neoverse V3 entry only for Arm implementer `0x41`, part `0xd84`, with both SVE and SVE2 OS-usable | Other Arm tuning identities retain the conservative NEON automatic preference; generic SVE2 remains independently force-selectable for qualification |
| Big-endian Linux AArch64 | stable Rust runtime probes; complete homogeneous `/proc/cpuinfo` implementer/part retained for tuning | scalar and 16-byte NEON ASCII byte-set masks | positional predicate serialization is little-endian, so SVE2 fails closed to NEON/scalar |
| x86-64 | stable Rust runtime probes, including OS AVX state; CPUID vendor/family/model retained for tuning | scalar, 16-byte SSSE3, and 32-byte AVX2 ASCII byte-set masks | AVX-512 feature combinations are facts available to future operation-specific variants |

The existing x86 JIT tier mapping now consumes the same non-linear feature
facts through a pure adapter. Its deterministic emitter still requires an
explicit target from a publisher; host detection is deliberately not hidden in
cross-target emission.

Upstream `memchr` and Aho-Corasick dependencies continue to use their own
qualified runtime dispatch. FRE does not interpose on those implementations.

## Production adoption

The Unicode-off literal/class-run/literal aggregate plan captures one
`SimdDispatchContext` before its accounted build transaction and compiles one
ASCII classifier into the retained plan. Runs first prove 32 scalar member
bytes, then consume complete 32-byte blocks with the selected positional-mask
leaf. Short runs and non-ASCII classes retain the original scalar behavior.
The aggregate schema and cache identity include the narrow, wide, and delegated
variant IDs, so artifacts compiled under different host selections cannot
silently claim the same identity.

## Adding a kernel

1. Define one safe operation boundary with an invariant input width or another
   construction-time invariant. A retained decision must never be based on one
   varying haystack length.
2. Keep scalar and ISA-specific leaves private. Fixed-width array references
   should prove every vector load width at the safe boundary.
3. Register each leaf in an operation-local `KernelVariant` table with an exact
   architecture, complete independent feature set, vector shape, minimum
   operation width, and preference.
4. If measurements justify microarchitecture-specific thresholds, add a
   `when_tuning` predicate without weakening the feature requirements.
5. Select once when compiling the operation. Runtime profiles retain only the
   selected qualified function pointer and receipt. Static profiles must add a
   mutually exclusive `cfg(target_feature)` direct-call definition, a const
   compiler-profile receipt, and no entry, discriminant, or receipt field in
   the handle. Hot calls must not repeat detection or ISA dispatch.
6. Add runtime-profile forced-portable and forced-supported-feature parity
   tests, static-profile fixed-leaf and retarget-rejection tests, arbitrary
   alignment and boundary tests, native-host tests, and fail-closed release
   instruction-shape authentication.
7. Add every unsafe leaf and complete source digest to
   `fre-unsafe-lint-boundary`; source drift must fail until re-reviewed.

`scripts/check-simd-codegen.sh` authenticates the emitted NEON, SVE2, SSSE3, or
AVX2 leaves on the native build host.
`scripts/qualify-simd-host.sh` is the repeatable native-host gate: it runs
semantic and production-consumer tests in both profiles, strict linting,
unsafe-boundary authentication, instruction-shape authentication, and prints
the exact host capability and selected-variant receipts.

## Remaining native backends

The SVE2 byte-set leaf is vector-length agnostic and uses a sealed private
assembly boundary because the pinned stable Rust toolchain detects SVE2 but
does not provide stable SVE2 intrinsics. It predicates exact loads, loops by
`cntb`, and serializes predicates through a fixed maximum-size stack slot with
constant-CFA unwind metadata. Native c9g qualification with five million calls
per sample and nine alternating samples measured a 4.602377 ns SVE2 median
against 5.411637 ns for the delegated split-NEON implementation
(`SVE2/NEON = 0.850459`). That evidence promotes SVE2 only for the retained
Neoverse V3 implementer/part tuning identity; the independent SVE and SVE2
feature facts still authorize entry. The broader SVE2 work queue still owns
additional literal-comparison and reducer leaves and qualification at vector
lengths above the 128-bit configuration exposed by the current c9g host.

Apple SME similarly requires explicit qualification of streaming mode, vector
length, OS context switching, calls, unwinding, and thread migration before it
can move from `reported` to `usable`. Until then, NEON is the strongest
qualified Apple leaf even on hardware that reports SME2.

x86 AVX-512 variants must list the operation-specific combination (for example
`AVX512F+AVX512BW+AVX512VL`) and retain down-clock-aware tuning thresholds.
Presence of one AVX-512 bit is not a linear “highest SIMD tier.”
