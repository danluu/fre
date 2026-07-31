# Inert Search V25/tag38 production-integration scaffold

This directory describes the source atoms that a later, separately reviewed
V25 production promotion must close. It contains no qualification result,
review decision, selector, manifest identity, linked object, or runtime
authority.

The scaffold has four independent locks:

1. `search_support/production_v25_authorization.rs` contains `None` and a
   compile-time assertion that it remains absent.
2. `search_support/production_families.rs` contains no production family.
3. `linked-search-v25-production-v1` is default-off and is required in
   addition to the generic Search Span link feature.
4. `fre`'s `compiled-search-v25-aot` facade accepts only a handle already
   admitted by the production registry. It invokes a source-specific adopter
   at most once and caches every missing-authority, selector, backend, or
   semantic-binding refusal as a portable route.

Enabling either feature alone therefore cannot select tag38. Linking a tag38
implementation/glue pair alone also cannot select it: the production raw
adopter looks up the selector before inspecting any supplied final-image
address.

## Later activation transaction

A production change must be based on the exact V25 source identity that passed
development and the 308-cell two-host held-out transaction. Independent review
must bind all fields in `authorization-v1.json.template`, including:

- the development-PASS decision;
- frozen campaign contract and correctness-stage binding;
- two-host correctness gate;
- terminal held-out analysis;
- independent production-review decision;
- both target build receipts and manifest identities;
- the exact family selector, literal envelope, window floor, portable-prefix
  split, and plan/analyzer/evidence identities.

Only after those artifacts exist may a direct reviewed change:

1. replace the `None` authorization atom and remove its absence assertion;
2. insert the two target-conditional rows in `production_families.rs`;
3. materialize the exact per-source inventory using
   `build_macos_aarch64_search_v25_production_source_v1` or
   `build_linux_aarch64_search_v25_production_source_v1`;
4. link each source's implementation object and identity-suffixed production
   glue object, retain the exact glue entry, enable the explicit V25 link
   feature in that consumer, and invoke the entry only through the facade's
   safe production-adopter boundary; and
5. independently inspect the final image before treating it as deployable.

The two build helpers are deterministic object-pair constructors only. Their
return values report `SearchAotRuntimeAuthorityV1::Absent`; they cannot edit an
authority table, link an image, or call generated code.

## Default invariants

This scaffold does not alter `SearchBackendPolicy::CURRENT`,
`BackendVersion::SEARCH_CURRENT`, either AOT compiler's `Default`/`new`
selection, or `fre`'s default feature set. JIT `CURRENT` and default AOT
compilation remain V8. No ordinary `PortableRegex` method consults this seam.
