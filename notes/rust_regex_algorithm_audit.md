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

4. Rust's dense scalar DFA loop is four-way unrolled, while FRE's ordinary
   loop is rotated but not generally unrolled. This is not a missing win that
   can be copied mechanically. A sealed 11,520-cell ASIMD forced-resource
   experiment for two-pair dense V13 unrolling regressed the geometric mean to
   0.945502 of baseline; every route and output contract regressed. A separate
   fully sealed scanner-free mutable-row pair-unroll experiment regressed the
   forced-resource aggregate to 0.751491 of baseline. Its unforced aggregate
   was order-discordant and, critically, the resource-fallback stratum was
   0.687236. Those implementations duplicated FRE's packed-cell classification
   and cold exits, unlike Rust's cheap special-state test. A future attempt
   needs a lower-cost special-state representation or trace/supertransition
   composition, not another copy of those unrolled bodies.

5. The finite-language leaf is not yet the equivalent of Rust's exact-literal
   bypass. Rust selects, in order, memchr/memchr2/memchr3 for one-byte
   languages, memmem for one literal, packed Teddy for a small literal set,
   byte-set search for the remaining one-byte case, and Aho-Corasick. Its
   Aho-Corasick choice is a DFA through 500 needles and a contiguous NFA above
   that point. FRE's current finite leaf is one scalar dense Aho-Corasick loop
   with a class-map load, transition load, and output-record load on every
   byte. It is a valuable exact resource fallback, but it cannot generally
   beat a minimized complete FRE DFA and is not selected while that DFA fits.

   The target-neutral planning layer now retains authenticated exact literals
   only when it can offer a competing vector byte-set, single-needle memmem,
   or bounded 3/4-byte Teddy candidate. Languages that decline those choices
   retain no second corpus: their existing ordered Aho-Corasick graph remains
   authoritative. Target lowering is the next slice. The x86 backends need
   baseline SSE2, AVX2, and an explicit AVX-512 plan (without assuming VBMI);
   AArch64 needs ASIMD and Linux SVE/SVE2 plans, with scalar tails on every
   target. Teddy hits must use direct source-order literal confirmation. Exact
   bytes and source ordinal, rather than a pattern identity, remain the
   semantic authority. A structural cost must compare the final scanner,
   confirmation work, and target data image against the already selected DFA.
   In particular, lowering must intersect all retained correlated columns,
   preserve each surviving bucket bit, map buckets to source-ordinal sets, and
   verify only those exact literals monotonically. An independent pair hash or
   bitmap after a one-byte scan is not an equivalent correlated traversal.

## Rejected or already-covered ideas

- A small adaptive complete-DFA cache was previously evaluated on a sealed
  independent matrix and regressed broad throughput; reviving it without a
  materially cheaper compact executor is not justified.
- Dense/scanner-free pair unrolling has likewise been rejected by sealed broad
  matrices as described above. Those exact implementations should not be
  revived.
- Per-candidate native bounded-suffix density accounting has also been
  rejected. A sealed four-phase, 2,304-row ASIMD nested-grammar crossover
  measured the candidate at 0.734145 of baseline overall (dense 0.735206,
  zero-candidate 0.735360). Charging and comparing a retry budget on the hot
  path, plus retaining an extra counter register, cost far more than the
  avoided adversarial retries and regressed rows that never saw a candidate.
  A future density policy must reuse already-produced batch masks/progress or
  select a different executor without adding per-call/per-candidate work to
  ordinary sparse and no-hit paths.
- Sparse default-slot compression, AVX2/AVX-512 sparse lookup, and ASIMD/SVE
  sparse lookup already exist on the current branch; the older implementation
  is not a missing Rust advantage.
- Attaching the existing bit-parallel `Exists` executor to every complete DFA
  is not justified. A compact direct DFA transition needs one table load (a
  class-mapped row needs two), while the one-word bit-parallel recurrence adds
  a classifier load and one dependent mask load for every four consuming
  Thompson states, plus shifts, unions, acceptance, and root-restoration
  tests. Its multiword form is strictly heavier. Both routes derive the same
  exact root-skip opportunity, so bit-parallel execution does not improve the
  dominant sparse-miss loop. A one-word recurrence can have a smaller image
  than a determinized resource-row table, but the graphs that expand that
  table also increase its nibble count. It should enter a future simultaneous
  scheduler only with an exact final-layout comparison that proves fewer hot
  operations or a materially smaller bounded-hot image; engine kind alone is
  not such a proof.
- Simply increasing a cache or DFA cap is not a general answer. It moves the
  resource cliff and can increase cold memory/code cost. Retained generations,
  exact finite-language lowering, and graph-derived prefilters improve the
  execution algorithm after a resource decline.

## Qualification policy

Changes are admitted only by structural graph/target costs and exact semantic
tests. Performance matrices use independently generated structural axes,
frozen seeds/warmups/trials/byte budgets/order, and sealed artifacts. No
partial matrix is scored, and the forbidden benchmark suites remain unseen.
