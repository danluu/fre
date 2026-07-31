# Search V8 static-AOT/JIT/portable bakeoff

This standalone arm64-macOS subject compares three implementations of one
fixed Rust-bytes exact-literal `Span` search:

- `raw-static-aot`: the source-first `fre-aot-compiler` Search V8 `MH_OBJECT`
  generated at build time and linked into the benchmark executable;
- `strict-wx-jit`: the byte-identical Search V8 native image published through
  `fre-jit-runtime`'s audited guard-page and strict-W^X path; and
- `portable`: the facade-selected exact-literal implementation.

The regular-expression native payload is produced by FRE's custom AArch64
emitter. LLVM is not a regex compiler or payload generator here. Rust may use
LLVM to compile the build script and benchmark host program, and Apple's
linker places the already generated payload in the final executable.

## Authority boundary

The static AOT route is deliberately named
`raw-statically-linked-aot`. Search V1 now has an authenticated expectation,
deterministic final-image glue, strict mapped-image inspection, disjoint
production/private registries, and a registry-owned safe adopted handle.
However, both source-qualified row tables are empty, so no safe handle can be
instantiated. This benchmark deliberately links and calls its raw provider
instead of consuming the safe adopter. Its benchmark-local wrapper checks
status, poisoned-result behavior, and returned Span bounds, but it is not a
production adopter and cannot manufacture a qualified row.

Consequently:

- `aot_authority` is always `benchmark-local-raw-abi-no-adoption`;
- `qualification_state` is `candidate`;
- `production_activation` is `absent`; and
- passing this bakeoff cannot by itself authorize deployment.

The linked-image verifier proves the retained raw provider and bytes. It does
not change that authority boundary.

## Identity closure

`build.rs` requires `FRE_SEARCH_V8_SUBJECT_REVISION` to be exactly 40 lowercase
hexadecimal digits. It then:

1. compiles `0123456789abcdef` through the source-first
   `fre-aot-compiler` entry point;
2. retains the compiler's domain-separated object-binding identity and
   canonical compiler-receipt identity;
3. independently rebuilds the same fixed-policy facade candidate,
   `ValidatedProgram<Span>`, and explicit `SearchBackendPolicy::AsimdV8`
   native image;
4. validates the compiler-produced Mach-O object against that independently
   rebuilt image and the compiler receipt;
5. checks the payload bytes and every source/KIR/native/object identity; and
6. emits a closed benchmark receipt plus identity-derived Rust and C symbol
   bindings.

The receipt binds the benchmark-source, semantic, compiler object-binding,
canonical compiler-receipt, Kernel IR source, native artifact, Mach-O compile,
complete object, payload, and metadata identities.
This is build-receipt schema v2; v1 receipts are intentionally rejected
because they described the benchmark-local low-level object wrapper rather
than the source-first compiler output.
Native-route preparation independently reconstructs the candidate, KIR,
image, and object and checks every identity; only strict-WX preparation
publishes the JIT image. Portable ready-first-call preparation stops after its
candidate/KIR identity checks, while raw-static-AOT preparation never
publishes a JIT. Thus the JIT and static AOT subjects carry exactly the same
native artifact identity. Object and final-image identity remain separately
named.

The standalone manifest disables `fre`'s default
`qualified-exact-search-jit` feature. It imports `fre-jit-aarch64` and
`fre-jit-runtime` directly, so the benchmark's strict-WX engine is explicit
and the facade dependency remains the portable/candidate handoff.

## Measurement matrix

Hot measurements are `Span` only and use a complete-haystack window.

- Sizes: 64 KiB and 1 MiB.
- Named cases: present, absent, dense, tail, both asymmetric adaptive-filter
  cases, pair-dense absent, triple-dense absent, distant match after a false
  pair, binary, and natural text.
- Alignment cases: base address residues 0 through 15.
- Total: `2 × (11 + 16) = 54` cells.
- Repetitions: 12 per cell.
- Each repetition measures all three engines in one of the six possible
  orders; every order occurs twice.
- Each engine receives complete-haystack search windows totaling exactly
  64 MiB per hot sample.

The raw verifier requires every AOT and JIT cell geomean to beat portable and
requires at least 95% strict same-process wins globally for each native route.
It reports AOT/JIT ratios but does not require either byte-identical native
route to beat the other.

Construction and first-call observations never mix with hot rows:

- the cold schema has seven explicitly scoped phases, separating portable
  construction, KIR construction, native emission, strict-WX publication,
  Mach-O wrapping, and the two source-to-ready/object paths; the AOT
  source-to-object phase invokes the real source-first compiler rather than
  reconstructing its stages in benchmark code;
- final linking is outside the Rust cold schema; and
- ready-first-call uses a fresh process for each engine/case/repetition and
  excludes all engine setup from its one-call timer.

Ready-first-call is not end-to-end latency. Static AOT adoption latency is
unmeasured because this benchmark deliberately stays on the raw route and no
source-qualified Search row currently permits safe adoption.

The separate lifecycle matrix measures the actual end-to-end portable and
strict-W^X JIT choices:

- cases are 64 KiB absent, 64 KiB
  adaptive-secondary-dense-primary-absent, 1 MiB tail, and 1 MiB natural
  text;
- 64 KiB uses call counts
  `0,1,2,4,8,16,32,64,128,256,512,1024`, while 1 MiB uses
  `0,1,2,4,8,16,32,64`;
- every case/call-count/repetition runs in a fresh process and emits the
  portable and JIT observations together;
- 24 repetitions alternate portable/JIT and JIT/portable, giving 12 of each
  order; and
- the largest cell performs 64 MiB of public search calls.

The `portable-lifecycle` timer includes portable construction plus the
requested calls. The `strict-wx-jit-lifecycle` timer includes planning, KIR,
machine-code emission, strict-W^X publication, and the requested calls.
Fixture/oracle preparation is outside both timers, as is destruction. Zero
calls isolates construction. Raw static AOT is excluded until there is a safe
static adopter; calling the benchmark-local raw ABI would not represent the
real AOT architecture.

For each case and call count, the verifier computes the geomean of the 24
paired JIT/portable total-time ratios. PASS requires a ratio at most 0.98 and
at least 20 strict JIT wins. Sustained empirical break-even is the first grid
point that passes together with every later point. A separate endpoint model
uses median zero-call setup and median maximum-grid totals to report an
advisory crossing; it cannot override empirical evidence.
Summary derivation remains available when a structurally valid run loses, so
optimization can use the exact failing cells. A separate strict lifecycle
admission then stops before `environment.tsv` or `completion.tsv` is emitted
if any case lacks an observed sustained crossing; a partial output from that
failure is not qualification evidence.

The lifecycle evidence retains every sample without outlier removal or cache
flushing. OS page-cache state is uncontrolled and recorded as such. This
policy measures fresh engine processes, not a manufactured cold OS cache.

## Final-image glue invariant

Each final image may contain at most one Search glue object for one compile
identity. The two defined glue symbols are suffixed by compile identity, while
the selected row and production/private adopter remain receipt-bound inputs.
Different compiled implementations therefore have different symbol names.
Attempting to link multiple selectors, or both the production and private
qualification glue, for the same compile identity creates duplicate strong
definitions and must fail closed at link time. Post-fence linker validation
must prove that duplicate refusal.

## Files and later execution

`run_qualification.sh` consumes an already built binary and build receipt. It
copies the binary to the closed bundle before the first subject invocation,
qualifies that retained `subject-bin`, and executes only that copy. It hashes
the copy before and after every measured phase, retains the complete linked
evidence, and rederives that evidence during final bundle verification. It
does not build, link, invoke a coordinator, wait for idle CPUs, or stop other
work. It refuses to run unless the caller already supplies a reviewed
`FRE_RESOURCE_HOLDER_KIND=timing` holder with the coordinator's exact
64-lowercase-hexadecimal token form.

The completed bundle contains 960 lifecycle process captures and 1,920 raw
lifecycle rows in addition to the existing 648 hot, 12 cold, and 240
ready-first-call invocations. `lifecycle-summary.csv` is the exact raw-derived
40-cell gate table; `lifecycle-break-even.csv` contains one empirical and
advisory result per closed case. The completion receipt is
`fre-search-v8-bakeoff-completion-v3`, and the environment receipt is
`fre-search-v8-bakeoff-environment-v3`. Subject metadata uses
`fre-search-v8-bakeoff-metadata-v3`.

`qualify_linked_image.sh` is read-only with respect to the executable. It
captures `nm` and `otool` output, but the verifier derives its authoritative
facts directly from bounded final Mach-O bytes. It proves:

- the final file is one little-endian ARM64 `MH_EXECUTE` with bounded,
  structurally valid load commands and symbol/string tables;
- each identity-derived symbol is one exact external `N_SECT` definition at
  the start of its receipt-bound section;
- entry and payload addresses are equal;
- `__TEXT,__fre_image` is exactly the payload and is max/current RX;
- `__FRE_CONST,__fre_meta` is exactly the metadata and is max/current R--; and
- bytes extracted from the final executable match the payload and metadata
  receipt hashes, including the source, artifact, compiler object-binding,
  payload, and compile identities embedded in metadata.

`nm`, `otool`, and the exact receipt-path link map must corroborate those
byte-derived facts. They are not authority for addresses, protections, or
historical input-object provenance. The resulting provider claim is therefore
`exact-receipt-derived-final-bytes`, not a claim that final bytes alone prove
which linker input supplied them.

See [QUALIFICATION.md](QUALIFICATION.md) for the evidence schemas and command
sequence. No benchmark result should be accepted without both verifier suites
and the linked-image receipt.
