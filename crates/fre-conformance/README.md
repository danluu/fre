# FRE conformance gate

This crate compares two deliberately separate paths over a small capture-free
byte language:

1. `fre-reference` directly interprets a semantic AST with mandatory fuel.
2. The production-floor adapter independently lowers the case AST to a checked
   `fre-automata::RawPlan` and executes typed K0 entry points.

Every record contains boolean existence, selected end, selected span, and the
complete Rust-style non-overlapping match sequence. The production sequence is
currently a repeated-single-search compatibility adapter. It is correctness
evidence only, not a claim that aggregate iteration is linear time.

`Outcome::Unsupported`, `Outcome::Refused`, and `Outcome::Fault` are distinct
from both no-match and success. Any such result produces
`Agreement::NotComparable`; only complete equal values produce
`Agreement::Equal`.

Every search call has its own work limit. Before execution, the harness also
computes a checked conservative upper bound on all calls made by the first
match paths and both repeated-search adapters. It multiplies that count by the
per-search budget and refuses the whole comparison if it exceeds
`max_total_search_work`. Generated-corpus reservation failure is an explicit
`RefusalKind::Allocation`; cap truncation is separately recorded by
`GeneratedCorpus::truncated`.

## Reproduction

Run:

```text
cargo test -p fre-conformance --all-targets
```

The finite grammar test enumerates 96 patterns and all 31 `{a,b}` haystacks of
length zero through four: 2,976 full output-record comparisons. Its stable seed
and the hand-minimized semantic gates are stored under `research/conformance`.

The pinned `regex` 1.12.4 dev dependency is labelled a secondary upstream
comparator. It is not the semantic oracle and cannot break an oracle tie.

## Honest limitations ledger

- This is a byte-only, capture-free small-case gate, not full Rust or RE2 syntax
  conformance.
- The direct adapter bypasses `fre-syntax` and `fre-lower`; the boundary is
  isolated so a public lowerer can replace it without changing records.
- The reference API has no bounded end offset. Queries whose end precedes the
  original haystack end are explicitly unsupported by that adapter. Ranged
  starts still retain original anchor context and are compared.
- A simple Thompson graph plus per-boundary epsilon-state deduplication cannot
  in general preserve ordered semantics for nullable unbounded loops. These
  cases are explicit gates, not rewritten or counted as passing.
- Global production results use repeated K0 search and can be quadratic. The
  aggregate iterator research crate must discharge the operation-level bound.
- The generator covers a declared finite grammar. A capped/truncated corpus is
  marked `truncated` and must not be reported as exhaustive.
- No capture histories, Unicode/UTF-8 boundary semantics, word boundaries,
  multiline modes, diagnostics, or RE2 option profiles are compared yet.
