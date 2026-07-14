# FRE kernel IR v1

Status: implemented semantic/validation layer; no executable-memory backend yet.

`fre-kernel-ir` is a deliberately small IR for pattern-specialized native
kernels. It is not a regex bytecode format and the portable executor is not a
production dispatch path. A native backend should turn each validated block
into ordinary target control flow, unrolled comparisons and vector scan loops.

## Implemented shapes

1. Exact literal, with optional absolute start/end anchors.
2. Greedy `[byte-class]+literal-suffix`, with optional absolute anchors.
   Admission requires a non-empty class and suffix, and proves that the first
   suffix byte is outside the class. This delimiter proof makes the maximal
   class run the selected leftmost-first candidate; rejection advances
   monotonically and never backtracks.

The second restriction is intentional. `[a-z]+a`, for example, needs a
different kernel because the suffix overlaps the greedy repetition. Treating
it as the delimiter kernel would silently select the wrong end. Such programs
are rejected by the independent validator, not accepted with a slow fallback.

## Modules and trust boundaries

- `ir.rs`: untrusted numbered blocks and immutable data blobs.
- `lower.rs`: allocation-checked builders for the two proven shapes.
- `validate.rs`: version/output checks, all target and data checks, path-state
  validation, reachability, canonical topology, cycle/progress and explicit
  dominance checks, plus resource and cost envelopes.
- `serialize.rs`: hand-written endian-independent bytes and a SHA-256 semantic
  cache identity. Serialization includes schema, semantic and ABI versions,
  output contract, anchors, every block edge and every data byte.
- `interpret.rs`: safe, work-metered semantic oracle only.
- `contract.rs`: compile-time `Exists`, `SelectedEnd` and `Span` outputs.

Raw programs are limited to 64 blocks/instructions and 64 data blobs even if a caller asks
for looser limits. Every validator loop is iterative. Potentially quadratic
duplicate-data and dominance work is explicitly metered, and fixed validator
scratch is separately bounded. Search work has a checked conservative bound of
`8 + (window_width + 1) * work_factor`; the interpreter charges every block,
candidate, membership test and compared byte.

## Current evidence

- 61,380 exact-literal results against an independent direct definition.
- 626,232 class/suffix results against an independent direct definition.
- 36,712 forced-kernel results against `fre-automata` K0, including every
  window over a bounded corpus and all four anchor combinations.
- Adversarial tests for corrupt versions, output confusion, invalid targets,
  flow-state confusion, wrong data kinds, unreachable/cyclic blocks, empty or
  overlapping class/suffix shapes, invalid windows and all declared limits.
- A deterministic 4,096-program malformed-IR corpus is wrapped in panic
  detection to exercise the validator's totality boundary.
- An exact inclusive-limit test and a fixed SHA-256 serialization test vector.
- Strict formatting, Clippy and rustdoc warning gates.

The fixed-pattern work samples in `scaling.csv` double closely when haystack
length doubles. These are logical oracle work counts, not timing results and
not a claim that the interpreter is fast.

## Non-claims and next gates

- This does not yet cover alternation, captures, Unicode decoding, general
  Thompson confirmation or overlapping greedy delimiters.
- `estimated_code_bytes` is an admission envelope for future emitters, not an
  assertion about the size of code that has not been emitted.
- No JIT, AOT object writer, executable memory, unsafe code or performance win
  exists in this crate today.
- A native backend is acceptable only after the obligations in
  `BACKEND_CONTRACT.md`, cross-backend differential tests, disassembly audits,
  guard-page tail tests and Rebar plus frozen-holdout measurements pass.
