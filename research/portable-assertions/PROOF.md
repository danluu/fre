# Portable LF and ASCII-word assertion slice

Status: source proof with focused validation complete. The mechanism checkpoint
is `253445a`; the only executable-source changes after that checkpoint were
applied by `cargo fmt` before the gates below.

## Validation record

All commands ran through the resource coordinator with isolated target
`/tmp/fre-builds/validate-portable-assertions-253445a`:

- `fre-automata --test k0`: 19/19 passed;
- `fre-lower --test lowering`: 11/11 passed;
- `fre --test portable_assertions`: 4/4 passed;
- targeted all-target clippy with `--no-deps -D warnings`: passed; and
- the three affected packages' all-target test gate: passed.

The dependency-inclusive clippy attempt stopped on pre-existing warnings in
unchanged `fre-syntax` and `fre-kernels` sources; targeted no-dependency clippy
then authenticated the changed crates without modifying those unrelated paths.
The all-target test command also executed the repository's harnessless
`portable_baseline` bench binary. Its incidental timing stdout was not produced
under a timing-wave lease and is explicitly not retained or used as performance
evidence.

## Admitted semantics

The portable K0 graph now has distinct zero-width edge kinds for the two
LF-aware line assertions and all six ASCII word assertions. Lowering maps one
HIR assertion to one edge without inspecting a pattern string, benchmark name,
haystack, or search range:

| HIR look | K0 edge | Predicate at absolute byte boundary `p` |
|---|---|---|
| `StartLF` | `AssertLineStartLf` | `p == 0` or the byte before `p` is LF |
| `EndLF` | `AssertLineEndLf` | `p == len` or the byte at `p` is LF |
| `WordAscii` | `AssertWordAscii` | `left_word != right_word` |
| `WordAsciiNegate` | `AssertWordAsciiNegate` | `left_word == right_word` |
| `WordStartAscii` | `AssertWordStartAscii` | `!left_word && right_word` |
| `WordEndAscii` | `AssertWordEndAscii` | `left_word && !right_word` |
| `WordStartHalfAscii` | `AssertWordStartHalfAscii` | `!left_word` |
| `WordEndHalfAscii` | `AssertWordEndHalfAscii` | `!right_word` |

Here `len` is the length of the original haystack. `left_word` classifies the
byte at `p - 1`, when present, and `right_word` classifies the byte at `p`, when
present. The only word bytes are `[A-Za-z0-9_]`. Every high byte, including an
invalid UTF-8 byte, is non-word. The only line terminator is byte `0x0A`.
Profiles that select another line terminator remain a typed facade refusal when
the HIR contains a line assertion; assertion-free patterns are unaffected.

Absolute `Start` and `End` retain their existing edge kinds and remain defined
as `p == 0` and `p == len` respectively. Together these ten edge kinds are the
complete assertion set admitted by this slice.

At this historical checkpoint, `StartCRLF`, `EndCRLF`, and all six Unicode word
looks remained typed `UnsupportedFeature::LookAssertion` errors. The later
source-only `research/portable-unicode-word-boundary/PROOF.md` mechanism
projects exact support for positive `WordUnicode` only. In particular,
`(?mR:$)` must lower to `Look::EndCRLF` and be refused; it must never be
approximated by the LF predicate. No Unicode assertion is approximated by
inspecting one byte or by assuming the haystack is ASCII.

Admission follows the HIR look variant rather than the profile's global flag.
Thus a locally ASCII `(?-u:\b)` remains exact inside a Unicode-enabled profile,
while an ordinary Unicode `\b` in that profile remains refused.

## Range and context proof

For a valid search window `[s, e)`, K0 visits only absolute boundaries
`s..=e`. Its consuming phase is reached only when the current position is less
than `e`, and that phase reads exactly `haystack[position]`. Therefore no
consuming transition reads before `s` or at/after `e`.

Assertion evaluation receives the full original haystack and the current
absolute position. It may read the adjacent byte at `p - 1` or `p` even when
that byte lies outside `[s, e)`. This is intentional and matches Rust
`Input::span` semantics. Match starts and ends are the same absolute positions;
there is no sliced-haystack rebasing. An empty range can consequently satisfy a
zero-width assertion at its sole boundary but can never satisfy a consuming
edge.

Closure expansion rejects `p > len` as an internal invariant failure before it
evaluates any assertion edge. The public search-window validation establishes
`s <= e <= len`, and the executor increments positions only while
`position < e`, so every normal call satisfies that precondition.

## Bounded-execution proof

Each assertion check performs at most two checked adjacent-byte lookups and a
constant number of byte/Boolean operations. It allocates no memory and enters
no input-dependent loop. A split edge is still charged once by the existing
work meter before its predicate is evaluated. Thus replacing an unconditional
zero-width edge test with an admitted assertion does not add an uncharged work
category.

All assertion edges are classified as zero-width by the existing plan
validator and workspace calculation. They use the same explicit closure stack,
per-boundary state deduplication, checked counters, and fixed-capacity workspace
as epsilon and absolute-anchor edges. No assertion adds a consuming cycle or a
backtracking stack. The existing conservative linear-in-window-and-plan-size
work bound and checked scratch bound therefore continue to apply.

## Modular evidence boundary

The implementation is split at three independently testable interfaces:

1. `fre-automata::EdgeKind` is the portable graph interchange vocabulary.
2. `fre-lower` performs an exhaustive HIR-look-to-edge mapping and owns typed
   refusals.
3. K0 owns one shared absolute-boundary predicate used by every search entry
   point.

The focused evidence is likewise layered:

- automata tests compare all ten edge predicates with a separate byte oracle
  over the empty haystack, every possible singleton byte, representative byte
  pairs, every boundary, empty windows, and consuming range confinement;
- lowering tests cover composed syntax, all newly admitted HIR variants,
  invalid bytes, context just outside a range, and exact CRLF/Unicode refusals;
- the portable-facade test compares every assertion over every range of 649
  short arbitrary-byte haystacks with both an independent oracle and pinned
  `regex-automata` 0.4.14, then compares assertion-plus-consumption patterns and
  production auto routing.

This boundary is suitable for a later JIT or AOT backend: it can consume the
same assertion vocabulary and differential corpus without inheriting K0's
execution representation.

## Reusable operation-local workspace

`PortableRegex::search_session` exposes the existing K0 caller-owned workspace
contract at the facade boundary. Session construction allocates and fully
initializes exactly one fixed-capacity K0 workspace under explicit setup-work
and retained-scratch limits. Repeated `is_match`, `selected_end`, `find`, and
ranged `find_window` calls reuse that workspace without reserve, resize, or
allocation. Each call resets only logical lengths and retains the same
operation-specific K0 output contract and per-invocation work limit as the
one-shot method.

Construction accounting is reported separately from invocation accounting.
The constructor record identifies allocated, initialized, and retained bytes;
each successful reused K0 call reports `reused = true` and zero newly allocated
bytes. Native exact-literal, packed-literal, literal-set, required-literal, and
forward-anchored plans retain their existing dispatch and allocate no session
storage.

The workspace remains `O(states + edges)` and its layout is fixed by the
validated automaton. Reuse changes neither assertion context nor input work:
each line is still a distinct complete haystack for grep, so LF and ASCII-word
predicates see exactly the same adjacent bytes as a cold call. Tests compare
cold and reused operation outputs and transition counters over every range of
arbitrary-byte assertion inputs, require one tight setup allocation, require
zero allocation on reused calls, and preserve native-plan identity.

## Rebar projection, not benchmark evidence

The generic admission change is expected to remove the syntax/lowering refusal
for `grep/long-words-ascii@rust/regex` and
`opt/accelerate/whole-line@rust/regex`. It does not contain a route keyed by
either job. The first uses ASCII word boundaries and the second uses LF-aware
line boundaries, so they exercise the same semantics as arbitrary user
patterns.

At this historical checkpoint, `grep/long-words-unicode@rust/regex` remained
refused because Unicode word classification and variable-width Unicode scalar
lowering were both outside this slice. The later qualified
`research/portable-unicode-classes/PROOF.md` mechanism supplies the scalar-class
half and projects `wild/ruff/unnecessary-coding-comment@rust/regex`. The later
positive-boundary mechanism supplies the other half for `long-words-unicode`.
Their source-only composition projects that row without changing this
historical checkpoint's evidence.

After source validation, representative performance work should measure the
two newly admitted rows against pinned Rust and against RE2 where that row has a
matching RE2 definition. Admission alone is not a speed claim: K0 supplies the
correct portable baseline, while a future specialized JIT/AOT plan must earn
production routing through separate correctness and performance evidence.
