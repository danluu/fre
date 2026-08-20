# fre-syntax

`fre-syntax` freezes syntax and constructor identities before FRE constructs
any automaton. It currently provides a pinned Rust-regex parser path and an
honest RE2 scaffold; it does not construct an upstream shadow matcher for
resource admission.

The Rust path names two exact release-stack profiles. The default high-level
profile records `regex` 1.12.4, `regex-automata` 0.4.14 and `regex-syntax`
0.8.11 with independent crates.io checksums and packaged VCS revisions while
preserving the 10 MiB size-limit and 2 MiB DFA-size identity defaults. The
10 MiB value becomes the default cap on FRE's charged persistent compiled
representation; it is not an exact upstream NFA-admission threshold. The Rebar
profile records its pinned revision and historical comparator configuration,
including ordered leftmost-first behavior, `syntax.utf8=false`,
`utf8_empty=false`, and the comparator's 100 MiB Thompson NFA limit, without
building that meta matcher inside `fre-syntax`. The high-level profile records
its text (`true`) and bytes (`false`)
syntax/empty-boundary UTF-8 settings separately. Both use Unicode 16.0.0. Traversal is iterative and every source,
HIR-node, work and pending-stack dimension is checked; constructor limits do
not alter FRE's independent safety envelopes.

The RE2 path preserves all fields in `RE2::Options`, including the surprising
`log_errors = true` default. Literal mode is represented; general Perl/POSIX
parsing, exact diagnostics, captures, QuoteMeta and rewrite grammar remain
explicitly `NotYetImplemented`. This crate never sends RE2 syntax through the
Rust parser and calls the result compatible.

`StrictAdmission` and `QuotaBounded` are disjoint contracts. A successful
strict parse is `StrictChecked`: grammar, configuration, and non-resource
diagnostics have been validated locally. It does not promise the pinned
constructor's resource threshold. Quota failures use `FreResourceLimit`, while
the `fre` facade reports its compiled-representation ceiling through native
`PersistentBytesLimit`/set `PersistentLimit` errors.
