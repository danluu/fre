# Inert Search V26/tag39 production contract

This directory freezes source-only production-readiness policy for a future
Search V26/tag39 qualification. It grants no runtime authority, adds no
production-family row, enables no Cargo feature, links no object, and changes
no default route.

V25 is terminal and cannot be promoted. Its development transaction failed
its frozen maximum-cell gate. A V26 authorization must bind that terminal
decision and a fresh, disjoint V26 development and held-out transaction; V25
performance receipts are not V26 production evidence.

## Prospectively frozen width split

The V26 compiler candidate may admit exact literals of width 6..=32 under one
tag39 wire identity. Production is narrower:

- `portable_max_literal_bytes = 8`;
- `family.minimum_literal_bytes = 9`;
- `family.maximum_literal_bytes = 32`; and
- `portable_max_literal_bytes + 1 == family.minimum_literal_bytes`.

Widths 6..=8 retain the existing non-V26 route. Although tag39 internally
selects a byte-identical V17 graph for that short class, production must not
invent a V17/tag30 authority row or relabel a tag39 object as tag30. Only the
tag39 width-9..=32 family can be proposed after fresh qualification.

The split is one prospective algorithmic class boundary. It is not selected
per literal, topology, corpus, target, or benchmark cell. Rebar is not an
input to this contract or its qualification.

The neutral constants and predicate live in `fre-aot-search-contract`:

- `SEARCH_V26_MIN_LITERAL_BYTES_V1`;
- `SEARCH_V26_PORTABLE_MAX_LITERAL_BYTES_V1`;
- `SEARCH_V26_PRODUCTION_MIN_LITERAL_BYTES_V1`;
- `SEARCH_V26_MAX_LITERAL_BYTES_V1`; and
- `search_v26_production_literal_width_is_valid_v1`.

These constants are routing facts, not authority.

## Locks required before a future promotion

A future source revision may add a V26 production atom only if every lock
below is closed in one independently reviewed transaction:

1. tag39 and its exact magic `0x27` are present in the neutral contract,
   compiler, expectation decoder, static-runtime reconstruction, and final
   image under one source identity;
2. the reviewed authorization has the exact canonical shape in
   `authorization-v1.json.template`, with `production_authority: true`;
3. the authorization binds V25's terminal failure and fresh disjoint V26
   development-PASS, two-host correctness-PASS, held-out-PASS, architecture,
   production-review, target-build, and final-image receipts;
4. the only V26 family envelope is tag39 width 9..=32, with the exact
   authenticated input floor, prefix split, manifest, plan, analyzer, and
   evidence identities from the fresh V26 transaction;
5. every linked source is in the reviewed source inventory and independently
   rebuilds its literal, KIR, tag39 payload, expectation, implementation,
   glue, and final-image identities on each target;
6. the runtime family table and the separate V26 authorization atom are both
   absent before the direct promotion and both are required afterward;
7. the default feature set, JIT `CURRENT`, ordinary `PortableRegex`, and every
   width outside 9..=32 remain unchanged; and
8. automatic binding repeats the authenticated family literal-envelope check
   before publishing a static route.

Any missing, malformed, zero, stale, cross-target-copied, or mismatched field
must leave the V26 authority atom absent and the production family table
without tag39.

`validate_authorization.py` is a read-only validator for the checked-in
template and for eventual reviewed inputs. Reviewed authorization and
inventory files must be absolute, physical, owned, mode 0600, singly linked,
regular files and must match independently supplied SHA-256 digests. The tool
rejects duplicate JSON keys, schema drift, the wrong width split, V25 evidence
laundering, LLVM regex-code generation, cross-target copying, noncanonical
source order, short-width inventory entries, and glue/compile-identity drift.
It does not render or install an authority atom.

## Exact future deployment sequence

This sequence is intentionally blocked today at step 1.

1. Obtain terminal PASS receipts from a fresh disjoint V26 development gate
   and held-out gate. Stop permanently on either FAIL.
2. Build and inspect independent macOS/AArch64 and Linux/AArch64 tag39
   implementation/glue pairs for every reviewed source. Materialize the
   source inventory in canonical semantic-identity/source-digest order.
3. Have an independent reviewer populate the authorization from the exact
   receipts, confirm the 8+1=9 split, confirm `regex_codegen_uses_llvm: false`,
   and publish the authorization-file and inventory-file SHA-256 digests out
   of band. The files bind the review decisions rather than each other's file
   digests, avoiding a cyclic self-hash contract.
4. In a clean isolated worktree rooted at the reviewed candidate, add only
   the separate V26 authorization atom and target-conditional tag39 family
   rows. Keep both changes behind a new default-off V26 production feature.
5. Require the authorization atom to match the complete tag39 family tuple
   and both independently supplied file digests. Require each supported target
   to contain exactly one width-9..=32 V26 row and every other target to
   contain none.
6. Build without the V26 feature and prove no V26 row/callable exists. Build
   with the feature on unsupported targets and prove it remains empty. Build
   on both supported targets and prove malformed/missing authorization,
   selectors, source objects, and final-image receipts fail before pointer
   inspection.
7. Run exact correctness and route-boundary tests at widths 8, 9, and 32,
   below/at the authenticated input floor, and on invalid windows. Width 8
   must never acquire a V26 handle; width 9 may use tag39 only after complete
   adoption.
8. Independently review the direct promotion delta and final images, then
   enable the V26 feature only in consumers that link the exact reviewed
   source-specific glue.

No step permits activation from the V25 authorization template or the
default-off V25 feature.
