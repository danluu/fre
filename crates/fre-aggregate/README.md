# fre-aggregate

`fre-aggregate` is FRE's bounded whole-operation engine for Rust byte regex
iteration. It is integrated into the production facade for operation-specific
whole-match spans, count, and matched-byte sum.

The input contract is canonical `regex-syntax` 0.8.11 HIR plus an explicit
`RustByteProfile` token. `PINNED_1_12_4` asserts Unicode-off `regex::bytes`
semantics. `PINNED_1_12_4_UNICODE_ON_BYTE_STABLE` asserts the pinned
Unicode-on, `utf8(false)`, byte-boundary-empty profile. The exact admitted
subset is:

- empty, byte literals, byte classes, and Unicode scalar classes lowered to
  bounded canonical one- through four-byte UTF-8 paths;
- concatenation and ordered alternation;
- absolute, LF-aware and CRLF-aware line assertions, all six ASCII word
  assertions, and all six Unicode word assertions;
- arbitrary nested finite or open greedy/lazy repetitions.

The default compiler entry point rejects capture nodes. The explicit
whole-match entry point treats capture children transparently inside the
bounded validation/lowering traversals and reports exact erased annotations
and work; it does not implement a capture API. CRLF-aware line and all Unicode
word assertion forms use audited contextual predicates. This crate makes no
RE2 or capture-history claim.

## Construction

Unbounded nullable repetition uses two repetition modes in addition to the
per-body zero/progress product. A zero-width body success exits while the
repetition has made no progress. Once any earlier iteration consumed, that
zero-width path fails, permitting lower-priority consuming body paths to run
before the loop exit. This matches Rust's empty-loop guard and fixes the
single-loop construction retained in the research lab.

Every cycle in the final program crosses a byte-consuming instruction. A
Kahn-style certificate rejects any same-boundary cycle. HIR traversal first
checks depth iteratively; only then may lowering recurse within that proven
bound. Repetition expansion, states, temporary states, program bytes, and all
compiler work are checked.

## Execution

Both strategies compute one global recurrence over the operation range:

- `FullTable`: one endpoint word for every `(boundary, state)`;
- `ReverseSequentialRows`: two random-access rows plus fixed-size split/root
  records written right-to-left and read monotonically left-to-right.

Neither strategy performs repeated suffix searches or runtime fallback.
Admission checks boundaries, table cells, semantic work, random-access and
scratch bytes, log bytes, sequential traffic, match events, output, span-sum,
and peak resident logical buffers. Allocation is fallible. A span pull handle
is returned only after the full sequence has executed twice identically and
its exact output reservation has succeeded. Pulling is then an infallible
slice traversal, so calls cannot evade whole-operation limits.

The low-level operation range follows Rust regex `Input::span` semantics.
Consuming transitions cannot read outside the range, returned offsets remain
absolute, and every assertion observes the original haystack at the absolute
boundary. Thus `Start`/`End` mean byte offsets zero/full-length, while LF and
ASCII word predicates may inspect the adjacent byte just outside the range.

Qualification, production integration, exact Rebar coverage, and scaling
evidence are in `../../research/aggregate` and
`../../research/rebar/comparison`.
