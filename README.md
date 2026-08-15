# FRE

FRE is an experimental safe native regular-expression engine for Rust. The
workspace explores operation-specific compilation, bounded engine selection,
portable SIMD kernels, and native AOT/JIT backends for x86-64 and AArch64.

The implementation targets Rust-regex-compatible and RE2-style semantic
profiles. It includes portable fallback engines, automata and lowering crates,
native code generators, conformance tooling, and research prototypes. The
design and qualification criteria are described in
[WORLD_FASTEST_REGEX_DESIGN.md](WORLD_FASTEST_REGEX_DESIGN.md).

## Build

The workspace pins its Rust toolchain in `rust-toolchain.toml`.

```sh
cargo check --locked --offline --workspace
cargo test --locked --offline --workspace
```

Some native backends are target-specific. Cross-target or all-feature checks
must be run on a compatible host with the required target features.

## Workspace layout

- `crates/fre`: primary Rust facade
- `crates/fre-automata`, `crates/fre-kernels`, `crates/fre-lower`: planning
  and portable execution layers
- `crates/fre-aot-*`: ahead-of-time compilation and runtime support
- `crates/fre-jit-*`: native JIT backends and runtime support
- `crates/fre-syntax`, `crates/fre-re2-syntax`: syntax profiles
- `tools/`: conformance, comparison, manifest, and promotion utilities
- `docs/` and `research/`: architecture notes and experimental records

## Project status

FRE is a research codebase under active development, not a published stable
crate. Several workspace-wide release gates remain stricter than the default
local build, and some target-specific checks require Linux AArch64 hardware.
