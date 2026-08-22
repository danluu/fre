# `fre-aot-regex`

`fre-aot-regex` is FRE's general, self-contained AOT compiler for
capture-free regular expressions. It lowers the validated automaton rather
than recognizing a list of pattern spellings, and emits relocatable object
files without invoking LLVM, a C compiler, an assembler, or a linker.

For latency-sensitive same-process use, the companion
[`fre-aot-regex-loader`](../fre-aot-regex-loader/README.md) consumes a
self-contained optimizing `Span` result and publishes its retained typed
module under strict W^X. Compilation still emits the real relocatable object;
the loader removes only temporary-file, external-linker, and dynamic-loader
work. Runtime-helper-backed artifacts are rejected rather than routed through
the portable executor.

## Targets and CPU features

The target operating system, architecture, and CPU features are explicit
compiler inputs. The compiler does not inspect the build host or automatically
detect the deployment CPU. A caller that enables a feature is responsible for
running the emitted object only on CPUs that provide it.

The code generator currently selects instruction sets as follows:

- On x86-64, an empty feature set (or just `X86Sse2`) uses the SSE2 baseline.
  `X86Avx2` selects AVX2. AVX-512 lowering is selected only when both
  `X86Avx512F` and `X86Avx512Bw` are present.
- On AArch64, an empty feature set uses scalar lowering and `Aarch64Asimd`
  selects ASIMD lowering. On Linux, an `Aarch64Sve` request without ASIMD
  selects a vector-length-agnostic scanner for graph-derived primary byte
  filters; `Aarch64Sve2` additionally uses `MATCH` for exact byte sets. If
  ASIMD and SVE are both requested, supported primary scanners contain both
  graph-equivalent lowerings: a runtime `CNTB` dispatch selects ASIMD at a
  16-byte vector length and scalable SVE above it. Shapes without an SVE
  lowering retain ASIMD, while other accelerators make their independent
  graph-derived choices. Other accelerators in an SVE-only object retain their
  scalar fallback.

`X86Avx512Vl` remains an accepted target fact reserved for future lowering.
Feature-set validation enforces dependencies: AVX512BW and AVX512VL require
AVX512F, and SVE2 requires SVE. Unsupported SVE target/plan combinations
fall back deterministically, and the compilation receipt reports the
accelerator actually emitted. In particular, an SVE feature fact does not
legalize SVE on macOS: there is no supported macOS SVE execution contract in
this backend, so macOS keeps its ASIMD or scalar lowering instead of risking
an illegal instruction.

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

The additive [AOT regex-set foundation](../../docs/AOT_REGEX_SET.md) compiles
each source row as an independent Exists program and transactionally fills an
exact caller-owned bitset. It keeps all-matching-ID semantics separate from
ordered-many priority and does not change the stable single-program wire.

## Uniform capture participation

`compile_uniform_capture_selector` accepts an already canonical
`fre_syntax::RustParsed` value. It does not reparse source or implement a
second capture theorem: `fre-lower` proves uniform nonempty capture
participation and produces the ordinary capture-free `RawPlan` in one paired
transaction. FRE then compiles that plan as the unchanged ordinary Span
selector. A positive receipt binds the proof to the selector automaton,
stable program, final object, target, and line terminator; a semantic proof
decline remains explicit. Proof/lowering/compiler failures are terminal, and
the API rejects selectors with runtime or prepared-handle dependencies so a
consumer cannot mistake a fallback for a helper-free native entry.
