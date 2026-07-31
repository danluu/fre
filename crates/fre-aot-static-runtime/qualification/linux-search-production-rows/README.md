# Production Linux Search qualification-row promotion

This directory prepares, but does not itself perform, the first production
Search-v1 Span authority promotion. Its source-preparation commit isolates
`src/search_support/production_rows.rs` as one canonical empty authority atom.
That child atom owns the sole non-public `production` constructor, so Rust
privacy keeps the constructor inaccessible even to the parent and the
private-row sibling. Compile-time canonical and empty assertions preserve the
pre-promotion fail-closed runtime behavior.

The source-preparation commit contains no production authorization, proposal,
evidence bundle, or reviewed digest. Files under `templates/` contain
deliberately invalid placeholders and cannot be accepted by the parser. A
later verified one-file promotion embeds only the externally reviewed
authorization digest and its exact row projection in the production atom; it
does not check in or manufacture the authorization or evidence. Build output,
environment variables, runtime values, private qualification, and this
documentation do not create production authority.

## Closed authorization

`production_row_tool.py` accepts only the exact 27-field
`fre-aot-linux-search-span-production-authorization-v1` TSV. It binds:

- one selector, live width, and the existing eleven independent source-row
  identities;
- the exact parent and commit of the already-reviewed one-file private
  promotion, plus the private proposal SHA-256;
- fresh post-private evidence to that exact private promotion commit and Git
  tree; and
- independently reviewed manifest, receipt, bundle, and final-image SHA-256
  identities for that post-private evidence.

The private promotion commit and post-private evidence commit must be
identical. Every commit, tree, and SHA-256 field is fixed-width, lowercase,
nonzero hexadecimal. The authorization must be an absolute, owned, singly
linked, mode-0600 regular file. It is read twice through one `O_NOFOLLOW` and
`O_NONBLOCK` descriptor while all relevant file identity and extent fields
remain stable.

Canonical parsing alone does not authorize rendering. The production renderer
also requires the independently published SHA-256 of the complete
authorization. It writes the complete one-row `production_rows.rs` file to
stdout and cannot edit the repository.

## Shortest production transaction

This flow begins only after the private row has been promoted and fresh
correctness, linked-image, and single-threaded performance evidence has been
collected on that exact private-promotion tree. An independent reviewer then
populates the authorization and publishes its SHA-256 outside the candidate
being promoted.

```sh
tool=crates/fre-aot-static-runtime/qualification/linux-search-production-rows/production_row_tool.py
atom=crates/fre-aot-static-runtime/src/search_support/production_rows.rs
authorization=/absolute/reviewed/production-authorization.tsv

"$tool" render-reviewed-production-module \
  "$authorization" REVIEWED_AUTHORIZATION_SHA256 > "$atom"
git add -- "$atom"
git commit -m 'aot: promote reviewed Linux Search production row'

verifier=crates/fre-aot-static-runtime/qualification/linux-search-production-rows/verify-promotion-delta.sh
"$verifier" \
  /absolute/physical/repository \
  PRIVATE_PROMOTION_AND_POST_PRIVATE_EVIDENCE_COMMIT \
  PRODUCTION_PROMOTION_COMMIT \
  "$authorization" \
  REVIEWED_AUTHORIZATION_SHA256
```

The verifier is candidate-rooted: it extracts both parser/renderer and verifier
from the private-promotion candidate and requires the running verifier to equal
that exact candidate blob. It then proves both transactions:

1. The production candidate is a direct, single-parent, exactly-one-file
   private-row promotion from the authorization’s named private candidate. The
   old private atom is canonical empty and the new private atom is the exact row
   and proposal digest bound by the authorization.
2. The production promotion is a direct, single-parent, exactly-one-file
   replacement of `production_rows.rs`. The candidate atom is canonical empty
   and the promoted atom is the exact reviewed renderer output.

The verifier independently checks the candidate Git tree against the
post-private evidence binding. The exactly-one-file rule keeps every other
path byte-identical; explicit protected-blob checks additionally name the
private row, routing, mapped Linux verifier, raw output contract, expected
identity projection, runtime facade, and Search identity/tag21 contract. Thus
the existing SVE/SVE2 feature envelope and fixed VL=16 tag21 checks cannot
change in either the production transaction or its renderer output.

This tranche does not add a `fre` facade integration, a `SelectedEnd` API, a
new route, or a different output/identity contract. Those require separate
reviewed changes and cannot be smuggled into the one-file authority promotion.

## Tests

`test_production_row_tool.py` covers the closed grammar, renderer, inert
templates, bounded FIFO-substitution refusal, source layout, and tamper
refusals. Candidate verification remains byte-exact against the empty atom. A
separate clearly non-authoritative live-source classifier accepts only the
renderer’s exact empty or exact one-row syntax so tests remain meaningful
after promotion; it does not validate review, evidence, history, or runtime
authority.

`test_promotion_delta.sh` constructs a synthetic private promotion followed by
a production promotion and requires refusal for wrong review hashes,
noncanonical output, indirect history, stale evidence trees, wrong private
parents, and private/routing/mapped-verifier/tag21-contract path changes.

Under an active build/timing admission fence, inspect these files only with
Python AST parsing and `bash -n`; run the tests only after an explicit fence
release. They invoke Git and Python but no Cargo build, compiler, linker, or
benchmark.
