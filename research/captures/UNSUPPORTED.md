# Unsupported and pending boundary

The capture lab currently accepts only its explicit byte AST. It does not
claim complete Rust syntax parsing, Unicode classes, case folding, word/line
assertions, CRLF/multiline modes, dot modes, or multi-pattern capture semantics.
Only logical-window `Start` and `End` assertions are present. Capture indices
must be contiguous opening-parenthesis order; names are unique ASCII
identifiers.

The single-search candidates are research implementations, not optimized
kernels or JIT targets. The aggregate iterator intentionally has a quadratic
upper bound and is retained only as a bounded semantic oracle. No facade path
may select it as a performance fallback.

The typed `Re2Commit972a15Pending` profile always returns
`BuildError::ProfilePending`. Enabling it requires all of the following:

1. pin the complete RE2 option/profile identity and syntax adapter;
2. adapt upstream RE2 capture results to the same canonical absolute spans;
3. run the generated and directed corpora, including range/window behavior;
4. add differential cases for both RE2 named-capture spellings and anchor
   semantics;
5. preserve any disagreements as minimized counterexamples;
6. only then make the profile admissible (or introduce explicit semantic
   lowering differences).

Rust evidence must never be counted as RE2 evidence.
