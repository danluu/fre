# SelectedEnd ABI2 public adopter and static-link candidate

The Linux tag21 `SelectedEnd` P2b implementation object and direct-glue object
are the real AOT boundary. They contain the custom-emitted machine-code payload
and one hidden identity-suffixed `R_AARCH64_CALL26` wrapper. LLVM is not the
regex compiler, and a runtime address adopter is not part of this ABI2 route.

The reusable public-adopter and qualification source candidate is split
deliberately:

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
- `fre-aot-static-runtime` exposes no ABI2 address, callable pointer, symbol
  lookup, or registry. Its default-off `linked-search-selected-end-v2`
  feature exposes a lookup-only adopter whose input is the complete set of 17
  non-circular compiler/bundle/payload identities, the exact payload extent,
  and the embedded literal. The sole production authority atom is a private
  child module containing a literal, source-reviewed table. That table is
  empty and compile-time constrained to remain empty in this source revision.
  Empty authority returns typed `ProductionAuthorityAbsent` plus
  `Candidate`; a nonmatching artifact in a future nonempty table returns typed
  `ArtifactUnqualified`. The generated seam turns either status into an
  executable portable `LiteralPlan` fallback and performs no host probe or
  native work. The separate `selected-end-qualification-private-v2` feature
  depends on the public feature but grants no production row.
- The generated module owns the safe public facade. Its adopter accepts only
  the exact `LiteralPlan`; it accepts no address, function pointer, symbol,
  selector, callback, or authority setter. A production match yields only an
  opaque owner. That owner must admit the current thread and then pass through
  the generated module's private exact-plan bind to construct its public but
  field-private nominal session. Thus a future row cannot bypass the
  identity-suffixed direct-symbol declaration or mint a nominal session for a
  different generated artifact.
- The shared runtime boundary supplies a neither-`Send`-nor-`Sync`
  current-thread token, exact-literal scalar preflight, and strict `x0`
  end-or-zero decoding. The generated binding
  compares its embedded 16-byte literal with the portable `LiteralPlan` once,
  records its hardcoded private compile-identity key, and consumes the
  current-thread token into an owning plan-bound session. The generated module
  encloses that value in a nominal type with a private field, structurally
  fixing the key without claiming a separate runtime key comparison. The type
  borrows only the external owner and plan, so a consumer can store it without
  a self-reference. Repeated hot calls then
  authenticate the private preflight token with only plan identity. Equal bytes
  owned by another plan are rejected, while the distinct generated type
  prevents a plan session bound by another module from entering the call.
  Successful session creation admits Arm
  `0x41/0xd84` with ASIMD+SVE+SVE2 and observes the calling thread's SVE vector
  length once, requiring 16 bytes. Calls inside the session perform no VL
  query and no literal-byte comparison.

The retained Search V1 Span adopter is intentionally not reused. Its ABI has a
fifth `x4` output-slot argument and its final verification step converts a
verified load address with `mem::transmute` into a stored function pointer.
Calling that value necessarily introduces an indirect call boundary (normally
`blr` on AArch64), even when the pointer was authenticated. Mechanically
porting it would therefore defeat the ABI2 requirements of four arguments,
`x0` return, no result slot, and a post-link-provable direct call.

All generated values continue to report compiler/runtime authority `Absent`.
The source qualification remains `Candidate`, and the public runtime feature
is default-off. Enabling either feature cannot populate the empty production
table. A signer-free receipt detects mismatch but grants no authority.

The generated binding cannot contain its own SHA-256 or deployment-receipt
identity without a circular source hash. The production row therefore pins
every non-circular identity embedded by the compiler, including the complete
payload identity and extent and the bundle identity. Review of the generated
Rust-binding source identity, that binding's SHA-256 identity, and the
deployment-receipt identity remains an external source-review and final-image
qualification obligation; runtime lookup does not pretend to establish a
self-hash.

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
hot callsite from an unrelated direct call. The default-off three-engine
consumer now supplies the required consumer-specific half: it includes the
exact generated binding, emits and externally pins a stable hidden
`inline(never)` symbol on its actual timed AOT loop, and its separate verifier
authenticates the binding/deployment receipt before disassembling that exact
symbol. This source implementation does not itself make the deferred
final-image observation true.

Until that exact-tree consumer proof actually passes and receives separate
qualification review, this candidate is diagnostic source infrastructure, not
a complete deployment closure or performance claim.
