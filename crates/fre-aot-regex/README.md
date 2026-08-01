# `fre-aot-regex`

`fre-aot-regex` is FRE's general, self-contained AOT compiler for
capture-free regular expressions. It lowers the validated automaton rather
than recognizing a list of pattern spellings, and emits relocatable object
files without invoking LLVM, a C compiler, an assembler, or a linker.

## Targets and CPU features

The target operating system, architecture, and CPU features are explicit
compiler inputs. The compiler does not inspect the build host or automatically
detect the deployment CPU. A caller that enables a feature is responsible for
running the emitted object only on CPUs that provide it.

The code generator currently selects instruction sets as follows:

- On x86-64, an empty feature set (or just `X86Sse2`) uses the SSE2 baseline.
  `X86Avx2` selects AVX2. AVX-512 lowering is selected only when both
  `X86Avx512F` and `X86Avx512Bw` are present.
- On AArch64, an empty feature set uses scalar lowering. `Aarch64Asimd`
  selects ASIMD lowering.

`X86Avx512Vl`, `Aarch64Sve`, and `Aarch64Sve2` are accepted target facts but
are reserved for future lowering and do not currently select different code.
Feature-set validation still enforces dependencies: AVX512BW and AVX512VL
require AVX512F, and SVE2 requires SVE.

## Stable semantic programs

`CompiledProgram::serialize` produces a stable, target-neutral semantic
runtime artifact, not a cache of the optimizing compiler's native IR. The
format intentionally omits target-native code and transient optimizer
sidecars and provenance. In particular, a fresh contextual DFA is serialized
as its universal ordered-NFA representation, so deserialization does not
restore the contextual DFA.

Compile the original pattern again in `CompileMode::Optimizing` for the
desired explicit target to regain optimized native or contextual lowering.
An object emitted by that fresh compilation already contains its selected
native lowering and does not depend on the omitted sidecars.
