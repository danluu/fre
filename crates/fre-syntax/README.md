# fre-syntax

`fre-syntax` freezes syntax and admission identities before FRE constructs any
automaton. It currently provides a pinned Rust-regex parser path and an honest
RE2 scaffold.

The Rust path uses `regex-syntax` 0.8.11 with the complete public builder
configuration and separate text/bytes UTF-8 contracts. Traversal is iterative
and every source, HIR-node, work and pending-stack dimension is checked.

The RE2 path preserves all fields in `RE2::Options`, including the surprising
`log_errors = true` default. Literal mode is represented; general Perl/POSIX
parsing, exact diagnostics, captures, QuoteMeta and rewrite grammar remain
explicitly `NotYetImplemented`. This crate never sends RE2 syntax through the
Rust parser and calls the result compatible.

`StrictAdmission` and `QuotaBounded` are disjoint contracts. Quota failures use
`FreResourceLimit`. A hard FRE cap encountered in strict mode is a
`StrictQualificationFailure`, not an upstream error. Full strict constructor
admission still requires the pinned upstream oracle outside this syntax crate.
