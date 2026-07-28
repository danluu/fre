# SelectedEnd ABI2 qualification-private static-link candidate

The Linux tag21 `SelectedEnd` P2b implementation object and direct-glue object
are the real AOT boundary. They contain the custom-emitted machine-code payload
and one hidden identity-suffixed `R_AARCH64_CALL26` wrapper. LLVM is not the
regex compiler, and a runtime address adopter is not part of this ABI2 route.

The reusable qualification-private source candidate is split deliberately:

- `fre-aot-compiler` deterministically emits a Rust module with literal
  identity-suffixed `extern` names for the exact entry and diagnostic wrapper.
  The primary call is present as a normal direct symbol reference for the
  static linker. Its companion signer-free deployment receipt binds the
  generated source digest, exact source and literal, semantic binding, KIR,
  emitted artifact, compile and implementation object, compiler receipt,
  expectation, complete payload digest and extent, glue source/header/code and
  object, and P2b bundle.
  The binding exposes its exact hidden identity-suffixed proof-callsite symbol
  so a qualification build can retain it explicitly for post-link inspection;
  the hot safe route bypasses that proof copy and calls the exact entry.
- `fre-aot-static-runtime` exposes no ABI2 production row, address, callable
  pointer, registry, or generic adopter. Its default-off
  `selected-end-qualification-private-v2` feature provides only a
  neither-`Send`-nor-`Sync` current-thread token, exact-literal scalar
  preflight, and strict `x0` end-or-zero decoding. Successful session creation
  admits Arm `0x41/0xd84` with ASIMD+SVE+SVE2 and observes the calling thread's
  SVE vector length once, requiring 16 bytes. Calls inside the session perform
  no VL query. This correctness-first candidate still compares the exact
  16-byte literal during each call preflight; replacing that comparison with a
  plan-identity fast path is a post-admission optimization, not part of this
  source-only candidate.

The retained Search V1 Span adopter is intentionally not reused. Its ABI has a
fifth `x4` output-slot argument and its final verification step converts a
verified load address with `mem::transmute` into a stored function pointer.
Calling that value necessarily introduces an indirect call boundary (normally
`blr` on AArch64), even when the pointer was authenticated. Mechanically
porting it would therefore defeat the ABI2 requirements of four arguments,
`x0` return, no result slot, and a post-link-provable direct call.

All generated values report runtime authority `Absent`; the static-runtime
feature is qualification-private and default-off, and there is no production
authority table for ABI2. A signer-free receipt detects mismatch but grants no
authority.

After build/timing admission reopens, each exact consumer must still retain the
implementation payload and metadata symbols and run an independent final-image
check. That check must reopen the implementation, glue, expectation, compiler,
bundle, deployment receipt, generated source, and final executable; validate
their bounded canonical forms and identities; and prove:

- the P2b wrapper and retained compiler-generated proof callsite each use a
  direct `bl` to the exact hidden identity-suffixed entry;
- those two proof callsites contain no `blr`, `x4`, or caller-owned result
  slot, and the exact entry has no PLT spelling or disassembler-annotated
  entry-targeting `blr`;
- the final entry, complete code/padding/literal payload, and metadata bytes
  equal the validated implementation object;
- metadata's complete-payload digest and compile identity are authentic; and
- the final ELF has no writable-executable load segment or executable stack.

The proof callsite is intentionally not the safe hot API. The reusable checker
therefore reports `primary_hot_route_final_observed=false`: it checks that the
generated hot-route source calls the exact entry, but does not infer a final
hot callsite from an unrelated direct call. Each consumer must expose and
externally pin a stable symbol covering its actual hot route and add a
consumer-specific final-image disassembly proof.

Until that exact-tree consumer proof and separate qualification review exist,
this candidate is diagnostic source infrastructure, not a complete deployment
closure or performance claim.
