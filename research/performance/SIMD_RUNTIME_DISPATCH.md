# FRE runtime SIMD dispatch

## Contract

FRE ships portable binaries and makes immutable dispatch decisions outside hot
loops. `fre-target-features` owns the process-wide hardware/OS snapshot and the
variant-selection contract. `fre-simd-kernels` owns safe, compiled kernel
handles whose private `#[target_feature]` leaves cannot be called without a
successful selection.

Instruction safety and performance tuning are separate:

- a variant lists every ISA feature required to enter it;
- runtime detection supplies only features that the current OS makes usable;
- a policy can remove features or require real features, but cannot invent
  them;
- a tuning predicate may change preference or thresholds, but cannot authorize
  instructions; and
- every selection produces a receipt containing the exact variant, feature
  evidence, policy, tuning identity, vector shape, and operation width.

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
5. Select once when compiling the operation and retain only the selected entry
   point plus its receipt. Hot calls must not repeat feature detection.
6. Add forced-portable and forced-supported-feature parity tests, arbitrary
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
