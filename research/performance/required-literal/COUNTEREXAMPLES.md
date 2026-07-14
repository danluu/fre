# Retained refusal counterexamples

These cases explain why the v1 admission conditions are required.

## Bordered suffix

- Class: `{b}`
- Suffix: `aba`
- Haystack: `ababa`
- Correct `b+aba` span: `1..5`

The occurrences of `aba` start at 0 and 2. A non-overlapping literal iterator
reports only offset 0, but only the overlapping occurrence at 2 has the
required preceding class byte. V1 rejects the suffix because its longest
proper border has length one.

## Non-disjoint boundary

- Class: `{a}`
- Suffix: `a`
- Haystack: `aaa`
- Correct greedy `a+a` span: `0..3`

Treating the first suffix occurrence as a barrier would return `0..2`, while
greedy `+` must leave the last `a` for the suffix. V1 rejects the suffix first
byte because it belongs to the class.

## Window/anchor distinction

For `\Aa+Z` on `aaaZ`, a window `1..4` must not reinterpret byte 1 as the
absolute start. V1 returns no match. For unanchored `a+Z`, the same window
selects `1..4`; the permitted-start boundary truncates the preceding class
run. Directed and exhaustive window tests retain both behaviors.
