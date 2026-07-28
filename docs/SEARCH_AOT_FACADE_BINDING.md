# Explicit Search AOT facade binding

The `fre` crate's default-off `explicit-search-span-aot` feature provides one
safe composition boundary:

```text
PortableRegex
  └─ exact_literal_search_aot_candidate()
       ├─ complete facade semantic identity ─┐
       └─ live literal width ────────────────┼─> SearchExactLiteralAotV1
                                             │
already-adopted VerifiedStaticSearchSpanV1 ──┘
```

`SearchExactLiteralAotV1::bind` recomputes the opaque candidate from the live
immutable portable owner. It compares the candidate's complete semantic
binding identity and exact literal width with the independently authenticated
static expectation. The wrapper retains borrows of both the portable owner and
the verified runtime handle for its complete lifetime.

This is deliberately not an adoption or deployment API. The feature:

- does not enable `fre-aot-static-runtime` linking or qualification features;
- cannot inspect or accept raw addresses;
- cannot add a production or private qualification row;
- cannot compile or link an object;
- does not reuse a JIT qualification atom;
- does not change any `PortableRegex` method or default route; and
- never falls back from an explicit AOT call to the portable executor.

The caller must obtain `VerifiedStaticSearchSpanV1` from a separately
source-qualified static-runtime adoption path. This facade feature contributes
and selects no production or qualification-private row; handle availability
depends entirely on the independently reviewed row atoms in the exact runtime
source candidate and on successful authenticated adoption.

`find` and `find_window` delegate once to the verified runtime boundary. That
boundary performs the sole checked literal resource/window preflight before
the native entry. The result is projected into the ordinary `fre::Match` and
`fre::SearchAccounting::ExactLiteral` contracts without a second search.

Tag21 remains same-thread-only. `begin_current_thread_session` asks the static
runtime to check exact SVE VL16 once and returns a token that is neither `Send`
nor `Sync`; its `find` and `find_window` methods do not make a per-call
vector-length syscall. Changing that thread's vector length invalidates the
session contract and requires a new token.

Before deployment, the composed source still requires feature-matrix builds,
identity/width refusal tests against an actually adopted private fixture,
window/resource/native-fault differentials, tag21 thread-affinity and VL
tests, release assembly inspection proving one preflight and one native entry,
and fresh private-then-production qualification evidence. This source API
creates none of that authority.
