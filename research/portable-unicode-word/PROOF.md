# Portable positive Unicode word boundaries

Status: source checkpoint from exact canonical base
`60e97792ae69c00b052ae268ba99470cf87bf995`. Tests were committed red-first at
`0419762`; implementation and dependency checkpoints are `a9ce782` and
`8150eca`. Validation is pending resource admission because host free space was
below the mandatory 20 GiB floor. No benchmark or generated Rebar report has
been run for this checkpoint.

## Reusable mechanism

K0 has one new zero-width edge, `AssertWordUnicode`. At an absolute haystack
position it decodes at most one canonical UTF-8 scalar ending immediately
before the position and one beginning immediately after it. Each valid scalar
is classified with `regex-syntax` 0.8.11's pinned UTS#18 Annex C Perl-word
table. The assertion succeeds exactly when the classifications differ.

Invalid, overlong, truncated, surrogate, stray-continuation, and out-of-range
encodings decode as non-word context. This is the same positive-boundary rule
used by the pinned `regex-automata` oracle: `\b` can delimit a valid word next
to an invalid byte, but cannot split a valid scalar. The implementation does
not admit `\B` or Unicode start/end/half assertions, whose behavior inside
invalid UTF-8 requires an additional validity condition. Those variants and
CRLF looks retain typed refusals.

The assertion performs constant bounded work and allocates nothing: it
examines at most four bytes on each side plus one lookup per decoded scalar.
Scalar-class consumption remains the already-qualified canonical UTF-8 K0
graph. Existing exact-literal and native construction dispatch is unchanged.

## Directed specifications

The automata specification covers Alphabetic, Mark, Connector_Punctuation,
Join_Control, emoji/non-word scalars, scalar-interior byte positions, stray and
truncated bytes, overlong encodings, and valid words surrounded by invalid
bytes. Lowering specifies the distinct edge identity and retains a typed
refusal for `WordUnicodeNegate`.

The portable facade compares `\b`, `\b\w{2,}\b`, and `\b\w{25,}\b` against
the pinned `regex-automata` meta engine over every search window of valid and
invalid byte haystacks. This includes the exact remaining Rebar pattern shape.

## Exact projected Rebar delta

The candidate projects exactly one newly supported row and no removed pass:

- `grep/long-words-unicode@rust/regex`, pattern `\b\w{25,}\b`, pattern
  SHA-256
  `fc8ac2dd7d0956da04a9837cc773ef39fcc597b02a9baee03733d2bf3ce3d5fd`;
  haystack SHA-256
  `7d43cc8dfd053b083b809bd7ce7d4a074f2fd24a6b7ec38908b3966f3324fa36`;
  7,384,531 haystack bytes; authenticated expected grep count 5,075.

If focused semantics, strict affected Clippy, formatting, and fresh complete
generation pass, the projected frontier is 238 pass / 106 unsupported, with
`grep` 11/0. Promotion additionally requires a representative performance
receipt because this broad K0 path is not assumed fast merely because it is
correct.
