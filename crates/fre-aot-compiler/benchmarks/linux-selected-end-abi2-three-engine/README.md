# Linux SelectedEnd ABI2 three-engine diagnostic

This source-only benchmark compares one exact 16-byte Search program through
three execution routes on a little-endian Linux/AArch64 Arm `0x41/0xd84` host:

1. the hidden identity-suffixed AOT entry, compiled offline and statically
   linked;
2. the byte-identical tag21 ABI2 image emitted at runtime and published through
   strict W^X; and
3. the portable preprocessed exact-literal plan.

It is diagnostic scaffolding, not promotion or deployment authority. Every
metadata and sample row says `promotion_authority=absent`, and the deterministic
P2b bundle itself says `runtime_authority=absent`.

## Static AOT construction

`build.rs` deterministically runs
`plan_and_compile_linux_aarch64_selected_end_v2` and
`build_linux_selected_end_qualification_bundle_v2` for
`0123456789abcdef`. It writes the implementation object, canonical P2b
direct-glue object, expectation, receipts, header, exact Rust symbol bindings,
and a post-link contract into Cargo's private `OUT_DIR`, then links the two
objects into this binary.

The primary AOT hot route calls the exact hidden implementation entry directly.
It does not use a function pointer, PLT entry, x4 argument, or result slot. The
canonical P2b `stp/bl/ldp/ret` wrapper stays linked and is exercised during
correctness qualification, but its avoidable extra call is not charged to the
primary AOT hot sample.

The AOT compiler and linker run before process start. Their cost is explicitly
`offline-excluded`; it is never folded into an AOT runtime-lifecycle sample.
JIT lifecycle rows include literal/KIR planning, tag21 ABI2 emission,
strict-WX publication, scalar preflight, session construction, and first call.
AOT lifecycle rows include literal planning, scalar preflight, session
construction, and first call. Portable lifecycle rows include literal planning,
scalar preflight, and first call.

Those three `stage=lifecycle` rows deliberately measure a common safe frontend,
not pure precompiled startup: the current architecture obtains its
non-forgeable window/resource certificate from a `LiteralPlan`. To expose the
other useful boundary without mislabeling it, each lifecycle command also emits
`stage=aot-activation`. That row prepares the authoritative plan/preflight
outside the timer and measures only AOT VL16 session activation plus the first
direct-entry call. It still excludes offline compiler and linker work.

## Thread and vector-length contract

Both native routes require OS-usable ASIMD, SVE, and SVE2 on the admitted
homogeneous Arm `0x41/0xd84` host class. The benchmark never changes the
calling thread's vector length.

The AOT route exposes no call without `AotThreadSession`. That token contains an
`Rc` marker, so it is neither `Send` nor `Sync`; construction checks process
features/tuning and observes `PR_SVE_GET_VL == 16` once on the calling thread.
The JIT route uses the runtime's own non-transferable tag21 ABI2 session and its
independent VL16 check.

Hot cells construct both sessions outside the timer and reuse one authoritative
scalar preflight token. Lifecycle cells construct each applicable session
inside the timer. Native hot calls make no vector-length syscall.

## Semantics and timing

All three engines receive the same checked haystack/window and the same
`LiteralSearchPreflight`. Results use ABI2's `x0 = 0` miss or absolute match-end
encoding and are decoded against the exact window. A separate scalar
`windows(16)` oracle checks every fixture. Qualification covers present,
absent, dense filter near-misses, tail, included-window, excluded-window, and
four realized pointer alignments. The P2b wrapper is also compared in every
qualification case.

Hot samples calibrate to a target duration, warm every route, rotate all six
engine permutations by `repetition % 6`, retain CPU-affinity observations, and
consume match-dependent checksums. Lifecycle samples use the same six-order
rotation and emit the individual plan, emit, publish, preflight, session, and
first-call stage totals.

The runtime refuses unless its freshly emitted JIT artifact identity is exactly
the build-time AOT artifact identity. Rows bind source commit, source tree,
helper SHA-256, profile, artifact identity, compile identity, object identities,
and bundle identity.

## Deferred post-fence gates

No Cargo command or timing command was run while the resource-coordinator
admission fence was active. In particular, this nested workspace intentionally
does not yet have a generated `Cargo.lock`. It is not correct to claim
`--locked` build readiness until the following post-GO gates complete:

1. generate and review `Cargo.lock` without updating unrelated dependencies;
2. build the exact source commit/tree with the four required binding variables;
3. run `verify_post_link.py` against the final executable and the exact
   `OUT_DIR` implementation/glue/contract paths;
4. run correctness qualification;
5. only then run controlled, source-bound hot and lifecycle cells.

Required build variables:

```text
FRE_ABI2_THREE_ENGINE_SOURCE_COMMIT=<40 lowercase hex>
FRE_ABI2_THREE_ENGINE_SOURCE_TREE=<40 lowercase hex>
FRE_ABI2_THREE_ENGINE_HELPER_SHA256=<64 lowercase hex>
FRE_ABI2_THREE_ENGINE_PROFILE=linux-target-cpu-local-v1
```

The binary's `metadata` command prints the exact object and contract paths for
the verifier. Invoke the verifier with isolated Python:

```text
python3 -I -B verify_post_link.py \
  --binary <exact-final-executable> \
  --implementation <metadata-implementation-object-path> \
  --glue <metadata-direct-glue-object-path> \
  --contract <metadata-post-link-contract-path> \
  --source-commit <exact-commit> \
  --source-tree <exact-tree>
```

The verifier parses the original glue relocation and final ELF image. It
requires exactly one glue `R_AARCH64_CALL26` to the identity-suffixed entry,
the exact four-instruction wrapper, a resolved direct `bl` with no PLT, and a
separate direct `bl` from the primary benchmark path. It independently hashes
the implementation object and the domain-separated glue object, and requires
the final entry instruction bytes to equal the implementation object's entry
range. It rejects `blr`, x4 in the wrapper, result-slot contracts, RWX load
segments, and executable stack. Its successful output is still an observation with
`runtime_authority=absent` and `promotion_authority=absent`.
