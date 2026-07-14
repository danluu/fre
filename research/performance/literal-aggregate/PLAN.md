# Exact-literal whole-operation reducer

Status: implemented and measured as a distinct forced kernel API. It is not
wired into `fre`, a Rebar adapter, or automatic routing.

The admitted language is one exact byte literal under Unicode-disabled byte
semantics. Count returns the number of successive leftmost non-overlapping
matches. Span sum returns the checked sum of `end - start` for the same match
sequence. A nonempty literal uses one whole-haystack pinned
`memchr::memmem::Finder::find_iter`; it is not a loop of restarted black-box
suffix searches. An empty literal uses the explicit byte-boundary formulas
`count = N + 1` and `span_sum = 0`.

Promotion requires a separate facade proof, Rebar adapter receipts, and the
project's pointwise performance gate. None is claimed by this bounded work.
