# Aggregate assertion admission projection

Status: projected only, 2026-07-14. This is not a regenerated Rebar receipt or
an admission claim. It inventories the existing
`research/rebar/comparison/report.json` receipts whose sole recorded
continuation-compiler refusal is an assertion now implemented inside
`fre-aggregate`. Facade routing and canonical report regeneration are deferred.

| Existing Rust job | Model | Recorded look refusal |
|---|---|---|
| `curated/08-words/all-english@rust/regex` | count-spans | `WordAscii` |
| `curated/08-words/long-english@rust/regex` | count-spans | `WordAscii` |
| `curated/13-noseyparker/single@rust/regex` | count | `WordAscii` |
| `hyperscan/literal-inner-nosom@rust/regex` | count | `WordAscii` |
| `hyperscan/literal-inner-som@rust/regex` | count-spans | `WordAscii` |
| `imported/leipzig/word-ending-nn@rust/regex` | count | `WordAscii` |
| `imported/sherlock/line-boundary-sherlock-holmes@rust/regex` | count-spans | `EndLF` |
| `imported/sherlock/word-ending-n@rust/regex` | count-spans | `WordAscii` |
| `reported/i787-keywords/ascii@rust/regex` | count-spans | `WordAscii` |
| `reported/i787-keywords/opt-ascii@rust/regex` | count-spans | `WordAscii` |
| `test/unicode/word-boundary/ascii-only@rust/regex` | count | `WordAscii` |
| `unicode/word/around-holmes-english@rust/regex` | count-spans | `WordAscii` |
| `unicode/word/boundary-any-english@rust/regex` | count-spans | `WordAscii` |
| `unicode/word/boundary-long-english@rust/regex` | count-spans | `WordAscii` |

Projected engine-level delta: 14 former assertion refusals become eligible for
continuation compilation (13 `WordAscii`, one `EndLF`). This projection does
not account for integration regressions or operation limits and must not be
substituted for fresh end-to-end receipts.
