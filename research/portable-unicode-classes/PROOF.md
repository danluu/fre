# Portable Unicode scalar-class lowering

Status: accepted source at exact qualified head
`509682249461cd16d2d11fbbc98c72f68b1624d6` (tree
`aced3773a7e9278e883315792673ae99ff10ed54`). The complete directed and facade
suites, strict affected Clippy, workspace formatting check, and a full Rebar
generation all pass. No benchmark was run and this checkpoint makes no
performance claim.

## Reusable mechanism

`fre-lower` now accepts `regex_syntax::hir::Class::Unicode` without adding a
Unicode-aware executor operation. For each inclusive HIR scalar range it uses
the workspace-pinned `regex-syntax` 0.8.11 `Utf8Sequences` iterator to produce
disjoint sequences of one to four inclusive byte ranges. Each sequence becomes
a concatenation of existing K0 `ByteRange` states; all sequences become an
ordered Thompson alternation.

The byte paths encode exactly Unicode scalar values in the HIR class. They do
not accept invalid lead or continuation bytes, overlong encodings, UTF-16
surrogates, truncated scalars, or valid scalars outside the class. K0 still
searches arbitrary bytes: an invalid byte can be skipped while looking for a
later match but cannot be consumed by a Unicode class. Search-window boundaries
and absolute match offsets are unchanged because the graph consumes the
original haystack one byte at a time.

No string, benchmark, or haystack identity influences lowering. Byte classes
retain their one-state lowering, and every existing K0 edge and executor
predicate is unchanged.

## Bounded construction and refusal boundary

Each scalar range conservatively precharges the pinned iterator's fixed-width
partition work, and every generated UTF-8 sequence is charged before graph
construction. Sequence-fragment and class-branch vectors use the existing
checked growth accounting and fallible reservations. Every emitted state,
edge, patch, final table item, validator operation, and requested table byte
continues through the existing work/state/edge/storage/validation limits. A
large expansion therefore returns the same typed `LowerError::ResourceLimit`
or allocation error rather than raising a quota or selecting a fallback.

`Utf8Sequences` uses a private stack bounded by UTF-8's fixed four-byte width;
it does not create an input-sized side structure. Lowering remains iterative
and contains no unsafe code.

This mechanism does not implement Unicode boundary classification.
`StartCRLF`, `EndCRLF`, all Unicode word looks, capture-sensitive operations,
and uncertified nullable unbounded repetition retain their existing typed
`UnsupportedFeature` errors. In particular, no Unicode word look is treated as
ASCII and no malformed UTF-8 byte is treated as a scalar.

## Directed source specifications

The lowering tests specify Greek ranges, a four-byte scalar, invalid,
truncated, overlong, and surrogate UTF-8, the exact Ruff pattern, and a
state-limit refusal. The portable facade specification compares `.`,
`[α-ω]+`, and the exact Ruff pattern with the pinned `regex-automata`
configuration over every search window of valid and invalid byte haystacks.
Separate assertions retain exact typed refusals for Unicode word and CRLF
looks.

The specifications were committed red-first. The qualified head passes all 13
`fre-lower` tests, all nine portable facade assertions, and all 20 comparator
library tests. The exact Ruff comparator identity test also passes directly.

## Exact Rebar projection

The immutable expanded manifest is
`fre.rebar.expanded.v1`, SHA-256
`09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43`,
from clean Rebar revision `463d00f31887e84c38467805b9e3122c314b9521`.

The mechanism projects one newly admissible row:

- `wild/ruff/unnecessary-coding-comment@rust/regex`, pattern
  `^[ \t\f]*#.*?coding[:=][ \t]*utf-?8`, pattern blob SHA-256
  `84e0cc3593d33caadf1514b2a9812333cec9688400c213294aac9f13871dc131`.
  Its invalid-UTF-8 haystack SHA-256 is
  `1aaf33e0e5d90f0b350c5e04c3817c6c12b9e1ee0cecf2433c8ee6a7bae176d2`;
  the authenticated expected grep count is 16.

The other unsupported portable row is not projected:

- `grep/long-words-unicode@rust/regex`, pattern `\b\w{25,}\b`, pattern blob
  SHA-256
  `fc8ac2dd7d0956da04a9837cc773ef39fcc597b02a9baee03733d2bf3ce3d5fd`.
  Although `\w` now has a scalar-class representation, both `\b` assertions
  remain typed Unicode-word refusals.

Starting from the authenticated 236/108 frontier, the fresh complete generation
admits exactly this row and removes no prior pass. The authenticated result is
therefore 237 pass / 107 unsupported overall, `grep` 10/1, and `wild` 3/22.
FRE has no fail or fault receipt.

The raw report is
`/tmp/fre-control/results/G0-REBAR-PORTABLE-UNICODE-5096822-FRONTIER-001.json`,
SHA-256
`0bda3dcb0cff6fbe5756f148045f413a645ac2017d3dffd111346cc20a1dca2b`.
Its sorted-receipts SHA-256 is
`fed904ca1ff5f62dba13345e8327bb7939d1b53ea8dd1758be162f0ed0ec72cc`.
The exact comparator executable SHA-256 is
`78c254b69b932cfcc1dd4e6f387619a508a373c5ec291c99bbbe28c94ea4c640`.
