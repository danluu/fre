# Linux SelectedEnd ABI2 private post-link checker

This is the reusable, qualification-private final-image checker for one exact
P2b `SelectedEnd` ABI2 consumer. It is diagnostic source infrastructure:
successful output keeps production/runtime authority absent and
`observation_complete=false`.

The caller must create a canonical LF-terminated two-column TSV contract with
these fields in this exact order:

```text
schema
evidence_class
production_authority
runtime_authority
observation_complete
target
backend
abi
argument_count
return_register
result_slot_bytes
required_vector_bytes
literal_hex
manifest_identity
source_identity
semantic_binding_identity
literal_identity
kir_identity
artifact_identity
object_binding_identity
compile_identity
implementation_object_identity
compiler_receipt_identity
expectation_identity
full_payload_sha256
glue_source_identity
direct_header_identity
glue_code_identity
glue_object_identity
bundle_identity
binding_identity
deployment_receipt_identity
final_binary_sha256
wrapper_symbol
primary_callsite_symbol
entry_symbol
payload_symbol
metadata_symbol
required_relocation
required_final_call
reject_plt
reject_blr
reject_x4_argument
```

All identities and symbols must be externally pinned from one reviewed source
closure, not copied from the final executable being checked. Fixed values are:

```text
schema	fre-aot-selected-end-abi2-private-link-contract-v2
evidence_class	diagnostic-nonpromotion
production_authority	absent
runtime_authority	absent
observation_complete	false
target	aarch64-unknown-linux-little-endian-lp64
backend	tag21-sve2-fixed16
abi	selected-end-register-v2
argument_count	4
return_register	x0
result_slot_bytes	0
required_vector_bytes	16
required_relocation	R_AARCH64_CALL26
required_final_call	direct-bl-exact-entry
reject_plt	true
reject_blr	true
reject_x4_argument	true
```

The three `reject_*` contract rows are requirements for the exact P2b wrapper
and retained compiler proof callsite. The checker separately establishes that
the exact entry has no PLT spelling or disassembler-annotated `blr` reference
elsewhere; it does not turn either result into evidence about an unobserved hot
consumer callsite.

The remaining values come from the validated P2b bundle, generated deployment
receipt/binding, and an independently hashed final executable. In particular,
`binding_identity` is the domain-separated, length-prefixed identity returned
by `LinuxSelectedEndQualificationRustBindingV2::identity`, not a plain file
hash; `object_binding_identity` is the compiler's distinct ELF-object binding
claim. `literal_identity`, `glue_code_identity`, and `glue_object_identity`
are also checked against their canonical domain-separated digests.

The generated binding also emits an identity-suffixed primary proof callsite
and marks it hidden. The final link must retain it (for GNU-compatible linkers,
pass `--undefined=<primary_callsite_symbol>`). Its retained copy makes the
entry `bl` independently inspectable, but it is deliberately not the safe hot
API. The safe qualification source first consumes a non-transferable,
qualification-only current-thread token through the separately named private
bind while binding the exact portable literal plan and one private
compile-identity key, then encloses the owning session in a module-private
nominal type. The source-qualified production token is nominally distinct,
carries its matched compile identity, and cannot enter this qualification
bind. That
value borrows only the external qualification owner and plan, so consumers can
store it without a self-reference. Repeated calls use only allocation-free plan
pointer identity before naming the exact entry directly. The checker validates
that generated hot-route source; it does not claim that route survived final
optimization.
Every real consumer must separately expose and externally pin a stable symbol
covering its actual hot callsite, then inspect that exact symbol in its final
image. Until that consumer-specific proof exists,
`primary_hot_route_final_observed=false` and this evidence cannot be described
as a complete deployment closure.

Run only on the isolated Linux qualification host with a trusted, fixed
interpreter. The contract's lowercase SHA-256 must arrive through an
independent reviewed channel; deriving it from the unchecked contract at
invocation time defeats the pin.

```sh
/usr/bin/python3 -I -B verify_post_link.py \
  --binary FINAL_ELF \
  --implementation IMPLEMENTATION.o \
  --glue DIRECT_GLUE.o \
  --binding linked_selected_end_v2.rs \
  --compiler-receipt compiler-receipt-v2.bin \
  --bundle-receipt bundle-receipt-v2.bin \
  --deployment-receipt deployment-receipt-v2.bin \
  --expectation expectation-v2.bin \
  --contract externally-pinned-contract-v2.tsv \
  --expected-contract-sha256 EXTERNALLY_REVIEWED_CONTRACT_SHA256
```

The checker reads bounded regular files through lexical paths while refusing a
symlink as the file itself, validates the independently pinned contract,
receipt correlations, and generated source, then gives fixed-path `readelf`
and `objdump` sealed memfd snapshots with bounded output and deadlines. It
proves exact `GLOBAL HIDDEN` symbols, the wrapper CALL26 relocation and target,
the retained proof callsite's exact-entry direct call, no `blr`/x4 in those
proof callsites, no exact-entry PLT spelling or disassembler-annotated
entry-targeting `blr`, exact entry/full-payload/metadata bytes, authentic
payload and compile identities, and non-RWX/non-executable-stack ELF program
headers. It never runs the binary or generated code and grants no production
or runtime authority.
