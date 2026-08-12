# Rust regex algorithm audit

Scope: primary source from the locally pinned `regex-automata` and
`aho-corasick` revisions. This audit deliberately does not inspect rebar,
ripgrep, or any holdout benchmark or result.

## Strategy map

Rust's meta engine first attempts an exact literal-only bypass. Depending on
the graph-derived literal language, it chooses memchr/memchr2/memchr3, memmem,
Teddy, byte-set scanning, or Aho-Corasick. A very large plain-literal
alternation has a separate Aho-Corasick bypass because ordinary heuristic
literal extraction is bounded.

Otherwise it builds a core portfolio: full DFA when it fits, then hybrid DFA,
with one-pass DFA, bounded backtracker, and PikeVM as no-fail fallbacks. A
prefilter is attached to specialized start states only when literal extraction
finds a suitable mandatory prefix. The hot full-DFA loop is four-way unrolled
and tests special states only after each transition.

If the ordinary prefix prefilter is not believed fast, Rust can replace the
core search with one of three reverse strategies:

- reverse anchored for end-anchored expressions;
- reverse suffix: scan a fast longest-common suffix, run a bounded reverse DFA
  to recover the earliest start, then run the forward DFA to resolve greed and
  endpoint semantics;
- reverse inner: scan graph-required inner literal alternatives, run a reverse
  DFA for the prefix before the factor, then confirm forward.

Both reverse strategies prove that an earlier complete match cannot be skipped
and use monotone lower bounds to prevent quadratic rescanning. Rust's hybrid
DFA also has cache-efficiency quit controls; its meta layer falls through to a
no-fail engine after a quit.

## FRE coverage and gaps

FRE already has target-native single-byte/range scanners, independent vector
columns, correlated pairs, exact-product guards, seeded reverse machines,
complete and retained-partial DFA rows, and a semantic ordered fallback. Its
required-literal analysis is graph based and can expose suffix or interior
factors beyond Rust's HIR-shape extraction. The retained lazy-DFA cache now
keeps bounded generations, directly addressing Rust hybrid cache churn without
pattern-specific policy.

The material gaps identified by this audit are:

1. No general native multi-literal Teddy layer. Independent byte columns lose
   correlation and can create many more exact-verifier entries. The planned
   replacement derives 3/4-byte, 8/16-bucket nibble masks exclusively from a
   graph-authenticated `RequiredLiteralSet`; target lowering is AVX2,
   AVX-512BW/VL (conservative AVX2-width byte shuffles until VBMI exists in the
   feature vocabulary), ASIMD TBL, or SVE TBL. SVE2 uses the same TBL cost;
   MATCH predicates do not preserve bucket identities. Every false candidate
   resumes monotonically and an exact DFA/reverse machine remains authority.

2. Exact finite languages still reached the generic ordered fallback after
   higher-priority native DFA routes exhausted resources. The replacement is
   a target-neutral ordered Aho-Corasick IR derived from authenticated finite-
   language facts and a call-free scalar x86-64/AArch64 leaf. Fixed-stride
   row-offset tokens remove state multiplication from the hot loop; output
   width and source ordinal preserve leftmost/source priority. This is a
   general finite-language compiler, not a literal identity table.

3. Correlated mandatory interior factors can lose their bounded restart when
   only retained-partial rows fit. The retained-pair work is auditing the
   complete graph's maximum-before/maximum-through facts against the partial
   publication path. This corresponds to Rust reverse-inner's bounded reverse
   prefix recovery, but uses whole-graph distance facts instead of HIR shape.

4. FRE's dense scalar DFA loop is not generally four-way unrolled. Rust's
   unrolling reduces loop-control and special-state tests on ordinary rows.
   Any FRE version must preserve cold accepted/dead/partial-hole handling and
   be selected by target/layout cost rather than source identity. This remains
   an independent next candidate after the current correctness matrices.

## Rejected or already-covered ideas

- A small adaptive complete-DFA cache was previously evaluated on a sealed
  independent matrix and regressed broad throughput; reviving it without a
  materially cheaper compact executor is not justified.
- Sparse default-slot compression, AVX2/AVX-512 sparse lookup, and ASIMD/SVE
  sparse lookup already exist on the current branch; the older implementation
  is not a missing Rust advantage.
- Simply increasing a cache or DFA cap is not a general answer. It moves the
  resource cliff and can increase cold memory/code cost. Retained generations,
  exact finite-language lowering, and graph-derived prefilters improve the
  execution algorithm after a resource decline.

## Qualification policy

Changes are admitted only by structural graph/target costs and exact semantic
tests. Performance matrices use independently generated structural axes,
frozen seeds/warmups/trials/byte budgets/order, and sealed artifacts. No
partial matrix is scored, and the forbidden benchmark suites remain unseen.
