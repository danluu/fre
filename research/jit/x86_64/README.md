# FRE x86-64 backend research

This directory records the first bounded x86-64 backend for Kernel IR v1. The
Rust crate emits immutable, pattern-specialized native images; it does not
allocate executable memory or call them. The current admitted shapes are exact
literal search and proved-disjoint `[class]+suffix` search.

## Honest status

- Scalar and SSE2-effective images passed 276,309 external x86-64 executions
  against an independent model: 276 images, every anchor combination, search
  windows (including invalid windows), sparse and dense classes, short/long
  constants, exhaustive short haystacks, targeted matches/mismatches and 4 KiB
  scans.
- The 24 AVX2-effective images are byte-decoded by the independent Rust audit
  and their instruction forms were checked against Clang's x86-64 assembler,
  but Unicorn 2.1.4 reports AVX2 as unsupported. They are **not** counted as
  semantically executed.
- This is an initial confirmation backend, not a performance victory. Long
  literals still scan candidates scalarly and use SIMD for confirmation. A
  vector candidate prefilter and a qualified publisher are still required.
- The custom AOT artifact is a deterministic cache container, not ELF, Mach-O
  or COFF. OS object writers remain future work.

The emulator run found two real register-allocation bugs before this evidence
was accepted: short class suffixes clobbered the R11 run end, and long literal
confirmation clobbered the R10 last-candidate bound. Both have golden regression
tests. This is why decoder authenticity alone is not a semantic qualification.

## Reproduce

```sh
cargo test -p fre-jit-x86_64 --all-targets
cargo clippy -p fre-jit-x86_64 --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p fre-jit-x86_64 --no-deps
cargo run -q -p fre-jit-x86_64 --example qualify_bundle -- /tmp/fre-x86.bundle
python3 -m venv /tmp/fre-unicorn-venv
/tmp/fre-unicorn-venv/bin/pip install 'unicorn==2.1.4'
/tmp/fre-unicorn-venv/bin/python research/jit/x86_64/qualify_unicorn.py /tmp/fre-x86.bundle
```

Expected final line:

```text
records=300 executed=276 skipped=24 comparisons=276309
```

The qualification bundle is deterministic. Its accepted SHA-256 is
`539a9c630ef832a46291c607f2e580d092839c776d110b0a6b8762e20d727169`.
The bundle is generated rather than checked in so that the exact compiler under
test remains part of the provenance.

`bundle_to_asm` can turn the same images into assembly and a C entry table for
load-time/AOT testing on real x86-64 hardware. `qualify.c` supports that mode
with `-DFRE_AOT_QUALIFICATION`. On the available Apple-silicon host, early
unsigned-executable-memory probes wedged Rosetta before an AOT run could finish;
even the six-byte smoke image did not return. No Rosetta result is counted. The
checked-in raw-mprotect diagnostics now refuse to run in a translated process
so the failure is not casually reproduced.
Apple's current documentation says translated JITs are supported but requires
careful `MAP_JIT`, write-protection and instruction-cache handling:

- <https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment>
- <https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon>

## Files

- `BACKEND_CONTRACT.md`: ABI, image and boundedness contract.
- `instruction_shape.tsv`: deterministic emitted-size/shape sample.
- `qualification.tsv`: accepted external execution record.
- `qualify_unicorn.py`: bounded external semantic executor.
- `qualify.c`: native/Rosetta external qualifier (not production code).
- `jit_smoke.c`: minimal host JIT diagnostic (not production code).

None of the C/Python files is linked into FRE.
