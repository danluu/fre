# Prefix/class alternation ordinary-search proof grid

This document freezes the semantic and resource acceptance envelope for an
automatic ordinary-search route for exactly
`L0 C0+ | L1 C1+`. It is intentionally independent of any benchmark corpus.

## Admission

| Property | Accepted | Refused |
| --- | --- | --- |
| Root | Exactly two ordered alternatives | Any other root or branch count |
| Branch | Literal followed by one greedy positive byte-class repetition | Prefix/suffix omissions, extra atoms, lazy or bounded repetition |
| Literal | At least two bytes; first byte absent from the remainder | Width 0 or 1; self-overlap not excluded by this sufficient proof |
| Class | Non-empty canonical byte class | Unicode scalar class, empty/non-canonical class |
| Semantics | Rust bytes, Unicode disabled, case-sensitive, unanchored | Unicode/case folding/assertions/anchors |
| Selection | `Auto` only | Every forced selection, including `ForceK0` |

The width-two gate is a regret gate, not a semantic requirement of the shared
kernel. It keeps one-byte literals on the incumbent planner because dense
single-byte candidate streams can erase the specialization's expected benefit.

## Selection proof

The kernel owns one persistent forward `Finder` for each literal. Admission
proves that a literal's first byte does not occur in its remainder, so its
occurrences do not overlap. Both occurrence streams are monotone. At every
step the smaller start wins; an equal start chooses branch zero. This is
exactly Rust's leftmost-first ordering for the two admitted branches.

For a selected literal occurrence, the byte immediately after the literal
must belong to that branch's class. A successful probe is greedily extended
through the maximal class run. The resulting span is the selected match.
Because the admitted language is positive, advancing the non-overlapping
iterator cursor to that end preserves the same ordering proof on every later
window.

| Projection | Required result | Early-stop rule |
| --- | --- | --- |
| Exists | Whether any admitted branch matches | Return at the first viable merged candidate |
| Selected end | End of Rust's selected leftmost-first match | Return the greedy end of the first viable merged candidate |
| Selected span | Start and greedy end | Return the first viable merged candidate's span |
| Earliest end | Smallest accepting end over all starts and branches | Merge candidates in start order, track the smallest `literal_end + 1`, and stop only when the next candidate start cannot precede the incumbent accepting end |

Earliest-end is not the selected match's greedy end. For `Li Ci+`, its first
accepting end is exactly one class byte after `Li`; candidates beginning before
the current best accepting end can still improve it, while later candidates
cannot. Equal accepting ends need no source-order distinction because this
projection returns only the end offset.

## Windows and repeated calls

Every operation validates `start <= end <= haystack.len()` before source
access. Finder service is restricted to the exact window and a match is
returned only when its complete span lies inside it. Assertions are absent, so
slice-relative and original-haystack context are equivalent for the admitted
shape. No continuation state is retained by the plan: iterators and sessions
repeat the operation on progressively smaller windows. Consequently calls on
different immutable plans cannot share state, and mutating bytes at the same
address between calls cannot reuse stale candidates.

## Resource envelope

Construction reuses `PrefixClassAlternationPlan` and its exact two-prefix
allocation, copied-byte, Finder-preprocessing, bitmap, build-work, persistent,
and peak accounting. Planner traversal is charged cumulatively using the
existing prefix/class inspector. Publication charges source bytes, capture-name
metadata, and the kernel's reported persistent bytes before the plan becomes
observable.

Before any haystack access, each ordinary operation derives a source-independent
bound from the window length and retained shape. It covers two complete Finder
services, all yielded candidates, merge arbitration, first-class probes,
greedy extension, earliest-end bookkeeping, result publication, and constant
state. Operation allocation and scratch are zero; retained persistent bytes are
the immutable plan's exact build accounting. Exact counters are checked against
the published envelope on every success.

## Static acceptance grid

The source/test stack must cover:

- both branch orders, equal-start priority, duplicate literals, distinct and
  overlapping classes, absent and end-of-window candidates;
- dense rejected candidates and long greedy class runs;
- selected span/end, earliest end, existence, full windows, subwindows,
  repeated non-overlapping iteration, value-only calls, and reusable sessions;
- invalid windows and one-below work/scratch limits without fallback;
- `ForceK0` bypass;
- width-one, self-overlapping literal, non-byte/Unicode class, lazy/bounded
  repeat, extra atom, anchors, and wrong branch count refusal;
- alternating calls across two plans and same-address haystack mutation.

No benchmark or holdout result is an admission criterion.
