# fre-syntax

`fre-syntax` freezes syntax and admission identities before FRE constructs any
automaton. It currently provides a pinned Rust-regex parser path and an honest
RE2 scaffold.

The Rust path names two exact release-stack profiles. The default high-level
profile records `regex` 1.12.4, `regex-automata` 0.4.14 and `regex-syntax`
0.8.11 with independent crates.io checksums and packaged VCS revisions while
preserving the 10 MiB NFA and 2 MiB hybrid-cache defaults. The Rebar profile
records its pinned revision, dependency features, ordered leftmost-first meta
construction, `syntax.utf8=false`, `utf8_empty=false`, and 100 MiB Thompson NFA
limit. The high-level profile records its text (`true`) and bytes (`false`)
syntax/empty-boundary UTF-8 settings separately. Both use Unicode 16.0.0. Traversal is iterative and every source,
HIR-node, work and pending-stack dimension is checked; constructor limits do
not alter FRE's independent safety envelopes.

The RE2 path preserves all fields in `RE2::Options`, including the surprising
`log_errors = true` default. Literal mode is represented; general Perl/POSIX
parsing, exact diagnostics, captures, QuoteMeta and rewrite grammar remain
explicitly `NotYetImplemented`. This crate never sends RE2 syntax through the
Rust parser and calls the result compatible.

`StrictAdmission` and `QuotaBounded` are disjoint contracts. Quota failures use
`FreResourceLimit`. A hard FRE cap encountered in strict mode is a
`StrictQualificationFailure`, not an upstream error. Full strict constructor
admission still requires the pinned upstream oracle outside this syntax crate.
