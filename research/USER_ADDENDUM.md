# User addendum for review rounds

Added after round 1 had already started; do not restart or alter those independent runs.

- The result should accept the same syntax and provide the same safety guarantees as RE2 and Rust's `regex` crate.
- RE2 and Rust `regex` are not identical in syntax, defaults, Unicode behavior, APIs, or exact edge-case semantics. The design must therefore inventory those differences and provide explicit, tested compatibility profiles (or explain any genuinely impossible conflict). It may not silently weaken either guarantee.
- When several strategies are reasonable, retain multiple bounded candidates, prototype them, and compare them with controlled measurements before selecting or dispatching among them. Avoid prematurely collapsing uncertain design choices into one mechanism.
- The implementation must be modular and independently testable in the spirit of the architecture described in <https://burntsushi.net/regex-internals/>. The exact decomposition may differ because FRE has JIT and AOT paths, but syntax/HIR, semantic automata, analyses/planning, specialized matchers, machine-independent native-kernel IR, per-ISA emitters, executable-memory/runtime support, AOT artifacts, high-level APIs/C ABI, and conformance/benchmark tooling should have explicit boundaries.
- Each optimized executor and rewrite must be differentially testable against a small semantic reference engine. Planning and code generation must be inspectable/testable without executing arbitrary generated code; per-ISA encoders need disassembly/golden/property tests; JIT, AOT, and no-JIT executors need the same shared corpus and oracle.

## Lead hypothesis for the next review round

Scrutinize this possible construction for the exact non-quadratic iterator;
accept it only if the proof really works. Compile the complete
`find_iter(R)` operation into a prioritized total-input transducer. Its
`SEARCH` state tries an anchored `R` before consuming one profile boundary and
retrying. Match tags delimit results, and a finite post-match state reproduces
the profile's precise adjacent-empty suppression rule (including discarding an
empty higher-priority result rather than trying a lower-priority nonempty
alternative). If this wrapper's single greedy parse is equivalent to the
complete non-overlapping match sequence, the two-pass lean-log algorithm could
execute it in `O(PN)` time with `O(P)` random-access words and `kN` sequential
log bits. Reviewers must test whether the construction actually satisfies the
paper's assumptions under nullable loops, assertions, captures, UTF-8 boundary
advancement, unanchored starts, and both compatibility profiles. Compare it
fairly with suffix DP/checkpoint and persistent-history transducer candidates;
do not assume it wins.
