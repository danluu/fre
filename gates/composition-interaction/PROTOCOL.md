# Sealed protocol

The gate source is frozen before either optimization candidate is inspected.
The only FRE source consulted while designing and validating it is accepted
cursor commit `a48a2f4439747a230c230a3b7815467d4c8435aa`, tree
`371a48a30691f6bc443c21d0b785926b835bf5b6`.

## Authentication and build

Build base and candidate from exact isolated source trees with the same
toolchain, feature set, `RUSTFLAGS`, Cargo job count, and gate commit. The
controller records each FRE manifest hash, Git commit/tree when available,
whether `crates/` differs from that commit, and the resulting binary hash.
Remote Arm builds use `static-dispatch-arm-41-d84`; no host-specific source is
generated.

Before timing, run the clock-free verifier for both binaries. Preserve the
complete receipts. The evaluator requires exact equality of public semantics,
finite-schedule outcomes, iterator search-call schedules, and pinned Rust
results. Accounting and setup facts remain fully visible; candidate setup
retained bytes are bounded by the precommitted policy rather than required to
be byte-identical to the base.

## Timing

The binary itself owns the frozen pattern/input generator, iteration counts,
operation catalog, and checksums. The controller obtains and compares the
catalog from both binaries, expands every point without exclusion, applies
four repetitions, and shuffles once with the committed seed before writing the
schedule. It then launches exactly one process per scheduled point.

Use at most 96 controller workers on the 192-core evaluation host. The
controller performs no pinning, affinity changes, cgroup operations, retries,
or exclusions. A failed process invalidates the campaign. Base FRE, candidate
FRE, base Rust, and candidate Rust records remain separate so Rust-control
drift cannot masquerade as a FRE change.

Cold-to-warm transition points are reported separately from the primary
steady-state aggregate. The primary candidate/base decision has overall,
tail, cohort, family, and native-control floors. Rust-relative decisions have
both absolute cohort floors and preservation relative to the base, plus a
Rust-control drift bound.

## Closure

Run `analyze.py` only on the complete `timings.jsonl` and both complete
verification receipts. Its exit status is zero only for `PASS`. Preserve the
policy, catalog, schedule, completion record, receipts, raw timings, analysis,
source identities, binaries or binary hashes, gate commit/tree, source
archive, and a SHA-256 manifest as one evidence unit.
