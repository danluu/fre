# Rebar-blind ripgrep application qualification v2

This directory freezes a real application workload for Search tag 29 before
tag-29 timing. Its only membership authority is authenticated ripgrep source
at commit `f9c05a949d1a0dc8e16dee28ca9605d38611faeb`. No Rebar inventory,
corpus-overlap label, benchmark result, or timing result is an input to source
selection, fixture construction, structural classification, or a gate.

The source projection finds direct default `RegexMatcher::new` calls with one
static printable-ASCII exact literal of width 1 through 32. All eleven unique
source-derived literals participate. This is a lexical projection across
tracked Rust files, including test and documentation contexts; it is not
claimed to represent execution-frequency distribution. The fixture algorithm gives every
candidate seven common scenarios plus one dense exact near-miss at every
literal offset. Thus all 11 candidates and all 154 one-megabyte fixtures gate;
there is no result-derived exclusion path.

## Frozen structural classification

The separately frozen phase-unique selector classifies five candidates and 85
fixtures as eligible for tag 29:

- `Watson` (width 6)
- `NO MATCH` and `Sherlock` (width 8)
- `DOES NOT MATCH` and `Doctor Watsons` (width 14)

The two width-one, width-three, and width-five candidates are below the frozen
minimum width. The uniform width-eight and width-nine candidates fail the
cyclic phase-unique predicate. Those six candidates and their 69 fixtures are
not discarded: they gate exact structural refusal, ordinary portable routing,
correctness, and the frozen non-target overhead bound.

`freeze-v2.json` binds the source and fixture identities, the independent
selector implementation and per-candidate classification, tag 29 / policy 15,
the non-LLVM AArch64 static backend, production routing, both hosts, timing
protocol, completeness, and gates. On each host, every one of the 75 fixtures
that actually invokes the tag-29 static tail must have a ratio strictly below
0.80 versus the same compiled literal using portable search. The ten eligible
fixtures whose match returns from the authoritative portable prefix instead
have a 1.05 ceiling, as do the 69 structurally ineligible portable-fallback
fixtures. A fixture ratio is the median of exactly six order-paired ratios,
defined after sorting as `(ratio[2] + ratio[3]) / 2` without pre-rounding. Both
variants in every pair must use the same iteration count and independently
reach the minimum elapsed time. Candidate and aggregate results are diagnostic
only and cannot rescue a failing fixture.

Compile and route dispositions gate independently of output correctness. All
five eligible candidates must emit tag-29 objects and all six ineligible
candidates must reproduce their frozen structural refusal. For eligible
fixtures, `early` and `dense` return from the authoritative portable prefix
without invoking static code; the remaining 75 rows must invoke the static
tail exactly once. All 69 ineligible rows must invoke static code zero times.
The desired `alignment_offset` is realized as the actual checked-window pointer
modulo 16 using readable sentinel padding; it is not merely reported.

This application layer complements the much larger procedural topology matrix.
It does not authorize removal of a source candidate or fixture after
measurement. A failed cell refuses the broad tag-29 family under this freeze.

## Reproduction

With an exact ripgrep checkout and a new output directory:

```sh
python3 research/aot/search-ripgrep-application-independent-v2/validate_inventory.py \
  research/aot/search-ripgrep-application-independent-v2/inventory-v2.json \
  /path/to/ripgrep

python3 research/aot/search-ripgrep-application-independent-v2/materialize_fixtures.py \
  research/aot/search-ripgrep-application-independent-v2/inventory-v2.json \
  research/aot/search-ripgrep-application-independent-v2/fixture-algorithm-v2.json \
  /path/to/ripgrep \
  /new/fixture-directory

python3 research/aot/search-ripgrep-application-independent-v2/validate_freeze.py \
  research/aot/search-ripgrep-application-independent-v2/freeze-v2.json \
  . \
  /path/to/ripgrep \
  /new/fixture-directory
```

The committed freeze expects fixture-manifest SHA-256
`b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca`
and manifest-payload SHA-256
`1cbda700087f5506daa91b0657070cbf39fac68222ff84e273d1d83c09f6ebfd`.
