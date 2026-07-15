# ASCII word assertions in capture replay

The capture selector already evaluates the six byte-profile ASCII word
assertions. This checkpoint carries the same assertion vocabulary into the
tagged program used to replay selector-certified spans. It adds no fallback
engine and does not change the selector, match order, or replay interval.

At a byte boundary `p`, let `before` be true exactly when `p` is after the
logical window start and byte `p - 1` is `[A-Za-z0-9_]`. Let `after` be true
exactly when `p` is before the logical window end and byte `p` is in that same
set. Bytes outside the window and every non-ASCII or malformed byte are
non-word. The six predicates are:

| HIR assertion | Predicate |
|---|---|
| `WordAscii` | `before != after` |
| `WordAsciiNegate` | `before == after` |
| `WordStartAscii` | `!before && after` |
| `WordEndAscii` | `before && !after` |
| `WordStartHalfAscii` | `!before` |
| `WordEndHalfAscii` | `!after` |

Assertions are epsilon states. They consume no byte, allocate no history
node, and enter the existing state-visit accounting before testing the
predicate. Both the inline laboratory executor and the persistent-history
production executor share the immutable assertion kind and evaluate it from
the original haystack plus logical window. Exact-span replay therefore retains
the context used by the whole-operation selector rather than treating the
selected span as a new haystack.

The qualification matrix compares every assertion form against pinned
`regex::bytes` behavior, covers window edges, ASCII word and non-word bytes,
and invalid bytes, and runs facade reductions through selector plus exact-span
history replay. Unicode capture lowering and all remaining unsupported look
assertions stay typed construction refusals.
