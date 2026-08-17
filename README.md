# FRE (fast regex) 

FRE is an LLM-generated regex engine made with minimal human intervention. It appears to be overfitted to BurntSushi's rebar benchmarks and doesn't have great general performance, although there are some uses cases where it's actually pretty fast. See [this post](https://danluu.com/benchpocalypse/) for more details

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

FRE is an alpha codebase under active development, not a published stable
crate. Several workspace-wide release gates remain stricter than the default
local build, and some target-specific checks require Linux AArch64 hardware.
