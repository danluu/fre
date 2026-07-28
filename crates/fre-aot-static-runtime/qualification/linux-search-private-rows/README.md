# Private Linux Search qualification-row promotion

This directory owns the source-only boundary between an inert Linux Search
`source-row-proposal.tsv` and the feature-gated private runtime table. It does
not promote production Search authority.

The source-preparation candidate checks in
`src/search_support/private_rows.rs` as a literal empty slice. With
`search-span-qualification-private-v1` enabled, that preparation state returns
`NoQualifiedStaticSearchSpanRowV1`. The reviewed private transaction replaces
only this complete atom with one canonical row; without the feature, neither
the module nor its non-test const constructor exists.

The private-promotion verifier separately requires the candidate
`src/search_support/production_rows.rs` atom to be the exact canonical empty
module. A later production promotion may replace only that production atom
through its own reviewed transaction. Neither transaction can manufacture or
modify the other authority domain.

`source_row_tool.py` accepts only the exporter’s exact 18-field v1 TSV:

- `proposal-only`, `private-qualification-input`, and runtime authority
  `absent`;
- canonical bounded decimal selector and live width;
- exactly eleven nonzero lowercase 32-byte identities in fixed order; and
- owned, singly linked, mode-0600 input read twice from one `O_NOFOLLOW` and
  `O_NONBLOCK` descriptor with stable device, inode, owner, mode, size, mtime,
  and ctime.

The renderer writes to stdout only. With no proposal it renders the exact
source-preparation empty module. With one proposal it renders the complete
one-row module, including the proposal SHA-256 as a non-authoritative review
comment. Only that reviewed, checked-in private module can invoke the
constructor; a build-generated file, build script, environment variable, or
runtime value cannot.

## First private-row promotion

Do this only after the exact closed candidate has passed correctness and
single-threaded qualification on the intended Linux AArch64 host and an
independent reviewer has published the exact proposal SHA-256. The proposal
digest supplied to the verifier must come from that review boundary, not from
the candidate bundle being promoted.

```sh
tool=crates/fre-aot-static-runtime/qualification/linux-search-private-rows/source_row_tool.py
atom=crates/fre-aot-static-runtime/src/search_support/private_rows.rs

"$tool" render-private-module /absolute/candidate/source-row-proposal.tsv \
  > "$atom"
git add -- "$atom"
git commit -m 'aot: privately qualify reviewed Linux Search row'

verifier=crates/fre-aot-static-runtime/qualification/linux-search-private-rows/verify-promotion-delta.sh
"$verifier" \
  /absolute/repository \
  CANDIDATE_COMMIT \
  PROMOTED_COMMIT \
  /absolute/candidate/source-row-proposal.tsv \
  REVIEWED_PROPOSAL_SHA256
```

The verifier executes the parser/renderer extracted from `CANDIDATE_COMMIT`,
requires the running verifier itself to equal the candidate blob, requires a
direct single-parent promotion, and accepts exactly one changed path: the
complete private-row module rendered from the externally hash-pinned
proposal. The proposal is opened once: the external digest is checked and the
Rust module is rendered from that same in-memory parse. It separately proves
that `search_support.rs`, the isolated production atom, and
`search_linked/mod.rs` are unchanged. Its source audit requires the candidate
production atom to equal the complete canonical empty module byte for byte,
requires the isolated production atom to own its sole private production
constructor, requires the parent support source to contain zero production
constructors and one private-feature-only constructor, and refuses an inline
production table.

This verifier deliberately supports only the first empty-to-one-row private
promotion. Adding or replacing rows requires a separately reviewed extension;
it must not weaken the one-path rule or authorize the production table.

## Tests

`test_source_row_tool.py` covers canonical rendering, bounded FIFO-substitution
refusal, and parser/layout tampering. Its candidate audit remains byte-exact
empty, while a clearly non-authoritative test helper recognizes only the exact
empty or exact one-row production renderer shape in a live checkout; that
classification grants no authority. `test_promotion_delta.sh` constructs
private synthetic Git commits and requires refusal for extra paths, production
atom/support/routing edits, a noncanonical module, an indirect promotion, and
a mismatched proposal identity.

Under an active build/timing admission fence, inspect these tests only with
Python AST parsing and `bash -n`. Run them after the fence is explicitly
released; they invoke no Cargo build, compiler, linker, or benchmark.
