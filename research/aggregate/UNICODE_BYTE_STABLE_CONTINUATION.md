# Unicode-on byte-stable continuation admission

Status: candidate implementation. Focused differentials, full canonical Rebar
regeneration, and the coordinated performance gate named below must pass before
this is a promoted coverage claim. The checked-in canonical report remains the
baseline until those gates finish.

## Contract

The pinned Rebar Rust adapter searches byte haystacks with syntax
`unicode=true`, `utf8=false`, and empty-match filtering `utf8_empty=false`.
Consequently, Unicode syntax does not by itself require scalar-boundary
iteration: empty matches occur at every byte boundary. The continuation engine
may execute canonical HIR when every transition is already byte-stable:

- empty expressions and literals, including UTF-8-expanded Unicode literals;
- byte classes and Unicode classes whose ranges are all ASCII;
- absolute, LF-aware, and explicitly ASCII word assertions;
- capture-transparent whole-match composition, ordered alternation,
  concatenation, and bounded or unbounded greedy/lazy repetition.

Non-ASCII Unicode classes, Unicode word assertions, and CRLF assertions remain
typed compiler refusals. This excludes variable-width scalar decoding, Unicode
case-folding classes, Unicode `.` classes, and Unicode word-boundary state.
There is no fallback after a continuation plan is selected.

The direct compiler requires an explicit
`PINNED_1_12_4_UNICODE_ON_BYTE_STABLE` proof token. Its stable program identity
uses a new profile-specific hash domain. Unicode-off programs retain their old
hash domain and IDs exactly. The facade identity also records the Unicode-on
byte-stable semantic proof, so equal instruction graphs constructed under the
two profiles cannot alias in reports or caches. The changed facade identity
shape advances the aggregate explain/cache schema to 4, and the comparator
candidate adapter identity advances to `fre-current-aggregate-v4`.

## Equivalence argument

Canonical HIR literals are finite byte strings after parsing. Byte classes and
the admitted ASCII-only Unicode classes consume exactly one byte. Every
admitted assertion is a constant-time predicate of the absolute byte boundary
and at most its adjacent bytes. Composition and repetition therefore operate
over the same ordered byte transitions as the existing certified Unicode-off
continuation program.

The only profile-dependent iteration detail not retained in HIR is empty-match
filtering. The pinned bytes/Rebar configuration sets `utf8_empty=false`, so its
next search begins at the following byte boundary after an empty match. That is
the continuation engine's existing rule. Thus executing an admitted HIR over
all byte boundaries preserves Rust's ordered, non-overlapping whole-match
sequence. Count and matched-byte sum are reductions of that same sequence.

Validation refuses every HIR node for which this byte-transition argument is
insufficient. The proof token is an assertion about the parser and empty-match
configuration; it is not a general license to reinterpret arbitrary Unicode
HIR as bytes.

## Required gates

Before promotion:

1. run focused span/count/span-sum differentials under both continuation
   strategies, including invalid UTF-8, empty matches, local `(?-u:...)`,
   captures, anchors, alternation, and repetition;
2. confirm profile-separated plan identities while preserving a pinned
   Unicode-off identity;
3. regenerate the full authenticated Rebar comparison into a temporary
   artifact, require zero new fail/fault receipts, and record the exact newly
   executable job/model/family set;
4. run the existing aggregate test suite and comparator tests through the
   shared build coordinator; and
5. use the benchmark queue for the preregistered timing screen below. No
   uncoordinated timing result is promotion evidence.

## Preregistered performance screen

Compare FRE's continuation plan with pinned Rust regex on identical compiled
patterns and haystacks for:

- Unicode literal alternation/repetition on Russian and Chinese text;
- ASCII classes/repetition with Unicode syntax enabled;
- empty matching over valid UTF-8 and invalid-byte haystacks; and
- a local raw-byte `(?-u:\xFF+)` adversary.

Use at least 4 KiB, 64 KiB, and 1 MiB inputs, record per-case ratios as well as
the geomean, and reject promotion if any newly admitted high-volume Rebar row
shows a severe predictable regression. A failed timing gate does not justify
reverting semantic support silently: retain the typed, tested mechanism behind
a named performance qualification or add a faster execution path with the same
identity and semantic evidence.
