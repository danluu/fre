# Evidence packet: a fastest-safe-regex design

This packet is the common factual baseline for independent architecture reviews. It is deliberately not a proposed design. Reviewers should inspect the source material themselves and distinguish measured facts from hypotheses.

## Scope and hard requirements

- Implementation language: Rust.
- Primary execution should be native code produced by a low-latency JIT, not a regex bytecode interpreter.
- SIMD must be a first-class optimization, at least on x86-64 and AArch64.
- Ahead-of-time regex compilation may spend substantially more time optimizing.
- Matching and compilation must have explicit resource bounds. No catastrophic backtracking, unbounded determinization, unbounded generated-code growth, recursion overflow, or silent loss of the promised complexity bound.
- The library should be straightforward to embed from Rust and C/C++, in the spirit of RE2.
- The performance target is to beat both RE2 and Rust's `regex` crate, while the broader aspiration is the fastest general safe regex library. A design document cannot establish that claim; it must state a falsifiable performance contract and a measurement program.

## Pinned source trees

All are shallow clones made on 2026-07-13. Reviewers may inspect them read-only.

| Project | Local path | Pinned commit |
|---|---|---|
| Rebar | `/tmp/rebar-fre` | `463d00f31887e84c38467805b9e3122c314b9521` |
| Rust regex | `/tmp/regex-src-rust-regex` | `926af2e68eca3ce089815790541cf50759ba2c59` |
| RE2 | `/tmp/regex-src-re2` | `972a15cedd008d846f1a39b2e88ce48d7f166cbd` |
| Hyperscan | `/tmp/regex-src-hyperscan` | `828b4fef341759e05292741a6c89cb66055986f8` |
| Vectorscan | `/tmp/regex-src-vectorscan` | `a1c107ed92b6cc811a6fbd6b7dfcc7f181e5ab85` |
| PCRE2 | `/tmp/regex-src-pcre2` | `ff92e0b9cea5b5ae3af12ba930d03556684f098b` |
| re2c | `/tmp/regex-src-re2c` | `f1a46ca73a0855ea750d4f36c15747a99ae542f9` |

## Rebar surface

The pinned Rebar revision contains 68 TOML definition files. Expanding the currently available Rust runners produces 360 distinct benchmark names and 848 benchmark/engine jobs. The high-level `rust/regex` runner participates in 344 of the 360 cases.

The 360 cases by top-level family are:

| Family | Cases |
|---|---:|
| imported | 107 |
| curated | 52 |
| test | 50 |
| opt | 35 |
| wild | 25 |
| unicode | 22 |
| reported | 22 |
| hyperscan | 15 |
| aho-corasick | 13 |
| dictionary | 7 |
| slow | 4 |
| folly | 4 |
| grep | 3 |
| captures | 1 |

Across the 848 Rust-runner jobs, the model mix is 324 `count`, 280 `count-spans`, 118 `compile`, 68 `grep-captures`, 30 `count-captures`, 25 `grep`, and 3 `regex-redux`. Distinct names have fewer duplicated model entries; use `rebar measure --list` rather than assuming the job counts are unique tests.

Read these files in full before making benchmark claims:

- `/tmp/rebar-fre/METHODOLOGY.md`
- `/tmp/rebar-fre/MODELS.md`
- `/tmp/rebar-fre/BIAS.md`
- `/tmp/rebar-fre/benchmarks/definitions/README.md`
- every relevant TOML under `/tmp/rebar-fre/benchmarks/definitions`

The current curated suite has 52 cases: 21 `count`, 14 `compile`, 10 `count-spans`, 5 `grep-captures`, 1 `grep`, and 1 `count-captures`. Its groups cover literals; literal alternations; ASCII and Unicode dates; Ruff's `noqa` extraction; a Veryl lexer as one regex and many regexes; Cloudflare-style ReDoS; UnicodeData parsing; English and Russian words; AWS keys; bounded repeats; unstructured-log parsing; dictionaries; Nosey Parker secret patterns; and a deliberately quadratic leftmost-first `find_iter` case.

The rest of Rebar is not optional coverage. In particular it probes:

- imported Leipzig, Sherlock, Rust/Go, regex-redux, URI/email/IP, and other legacy corpora;
- literal acceleration, backtracking, fixed-length analysis, one-pass matching, prefilters, sparse NFAs, and forward/reverse inner/suffix optimization;
- Unicode properties, word boundaries, invalid UTF-8, all-codepoint scans, case folding, and overlapping word extraction;
- very large patterns, huge Unicode classes, large bounded repetitions, keyword lists, large dictionaries, grapheme regexes, URL/bibliography/security patterns, compilation hot spots, and patterns reported by users;
- exact functional semantics such as leftmost-first, non-greedy matching, empty matches, anchors, dot/newline behavior, captures, and byte versus Unicode modes.

## Recorded performance envelope

Rebar's latest committed curated recordings are in `/tmp/rebar-fre/record/curated/2025-12-19`. They were recorded on one machine and are clues, not universal truth.

Search-time summary scores in the generated Rebar README place Hyperscan at 2.37, Rust regex at 3.08, .NET compiled at 3.60, PCRE2 JIT at 6.00, and RE2 at 10.39. Lower is better; engines do not all participate in the same cases. Pairwise on the 31 search cases shared by Rust regex and RE2, Rust scores 1.02 versus RE2's 4.37. On their ten shared compile cases, RE2 scores 1.13 versus Rust's 1.85.

Across all 52 curated cases, the fastest recorded engine per case is distributed as follows: Hyperscan 13, Rust regex 12, PCRE2 9 (all compile cases), PCRE2 JIT 8, .NET compiled 3, Rust regex-old 2, and one each for .NET non-backtracking, JavaScript/V8, ICU, regress, and D/LDC. Some one-nanosecond results reveal optimizer or benchmark artifacts and must not be treated as physical lower bounds.

Important gaps to study:

- Hyperscan dominates several multi-pattern dictionary/Nosey Parker cases by roughly 34x-44x versus Rust regex, but it does not provide ordinary leftmost-first/capture semantics.
- PCRE2 JIT is often best on capture-heavy parsing and Unicode word cases, despite having a backtracking worst case outside the requested safety contract.
- Rust regex is already dramatically ahead of RE2 on much of the curated search suite, especially Unicode literals, dictionary alternations, and simplified ReDoS cases.
- Rust loses narrowly to RE2 on some long-word, bounded-capital, unstructured-log, and quadratic cases. It loses by much more to the per-case oracle on some capture, multi-pattern, bounded-repeat, Unicode, and quadratic workloads.
- Compile-time leaders are usually non-JIT paths. Current recorded medians include sub-microsecond trivial compiles and low-microsecond moderate compiles. A heavyweight general compiler cannot win this model without a genuinely cheap tier, lazy compilation, kernel binding, caching, or a revised explicit contract. Rebar times construction only; it validates the returned regex outside the timed interval.
- PCRE2's current JIT source contains explicit SIMD fast-forward machinery, but its x86 AVX2 fast-forward path is disabled in `src/pcre2_jit_simd_inc.h` at the pinned revision. This is an opportunity, not proof that enabling AVX2 wins.

To regenerate the current inventory:

```sh
cd /tmp/rebar-fre
cargo build --release
./target/release/rebar build -e '^rust/'
./target/release/rebar measure --list -e '^rust/' --ignore-missing-engines
```

## Semantic and complexity traps

- RE2 promises linear match time in haystack length for a fixed compiled regex, limits parser/compiler/executor memory, avoids recursion, and rejects constructs such as backreferences for which its safety contract is unavailable.
- Rust regex's general fallback is a Pike VM with `O(m*n)` search for regex size `m` and haystack size `n`. Its full DFA can require `O(2^m)` construction; its lazy DFA caps memory and falls back. Its meta engine combines literal prefilters, one-pass, bounded backtracking, lazy/full DFA, reverse scans, and Pike VM.
- A bounded attempt at determinization is acceptable only if the bound, fallback, and total compilation work are explicit. "Usually small" is not a worst-case guarantee.
- Leftmost-first, greedy semantics can make repeated `find` calls quadratic even when each individual call is linear. Rebar's `curated/14-quadratic` explains `.*[^A-Z]|[A-Z]` on `A^n`: each match can require looking to the end before returning a one-byte alternative at the beginning. Hyperscan stays linear there because it reports earliest matches and does not implement the same semantics. A proposed solution must either preserve leftmost-first semantics with a fused/global algorithm and state its time/space bound, or admit a different semantic mode. It may not compare different semantics as if they were interchangeable.
- Prefilter plus verifier designs can rescan overlapping regions quadratically. Rebar includes reverse-inner and reverse-suffix regression cases specifically for this. Every candidate path needs a progress invariant or a bounded-work bailout.
- SIMD does not remove a DFA's loop-carried state dependency. Useful SIMD roles include literal/set filtering, multiple pattern lanes, bit-parallel NFA state, UTF-8/classification, and verifying fixed-width windows. Claims of processing many arbitrary DFA input bytes in parallel require a real algorithm and cost model.
- Captures, match start recovery, empty matches, Unicode word boundaries, invalid UTF-8, streaming across chunk boundaries, and multi-pattern IDs all change viable engine choices.

## Primary references

- Rebar repository and methodology: <https://github.com/BurntSushi/rebar>
- Rust regex internals: <https://burntsushi.net/regex-internals/>
- `regex-automata` engine documentation: <https://docs.rs/regex-automata/latest/regex_automata/>
- RE2 safety/performance contract: <https://github.com/google/re2>
- Hyperscan NSDI paper: <https://www.usenix.org/conference/nsdi19/presentation/wang-xiang>
- Hyperscan performance guide: <https://intel.github.io/hyperscan/dev-reference/performance.html>
- Hyperscan implementation overview: <https://www.intel.com/content/www/us/en/collections/libraries/hyperscan/regular-expression-match.html>
- Packed/Teddy-style substring search: <https://docs.rs/aho-corasick/latest/aho_corasick/packed/index.html>
- PCRE2 JIT documentation: <https://www.pcre.org/current/doc/html/pcre2jit.html>
- .NET regex JIT/source-generation/vectorization discussion: <https://devblogs.microsoft.com/dotnet/regular-expression-improvements-in-dotnet-7/>
- re2c generated-code manual: <https://re2c.org/manual/manual_c.html>
- Tagged DFA study: <https://re2c.org/2022_borsotti_trofimovich_a_closer_look_at_tdfa.pdf>
- Cranelift JIT/AOT overview: <https://cranelift.dev/>
- Apple JIT memory restrictions: <https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon>
- Windows executable-memory/cache-coherency requirements: <https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect>

## Non-Rebar workloads that must be designed and tested

At minimum, reviewers should cover changing haystacks rather than warmed identical inputs; tiny one-shot regexes; long-lived hot regexes; thousands to millions of patterns; streaming and chunk boundaries; ropes/discontiguous buffers; replacement and split; capture-name lookup; tokenization with anchored multi-pattern longest/priority semantics; incremental log/network scanning; no-match and match-dense data; adversarial regex and haystack pairs; memory pressure; concurrent use; fork/exec; NUMA; cold instruction/data caches; binary data; every valid Unicode scalar plus invalid UTF-8 byte mode; JIT-forbidden platforms; cross-compilation; sandboxed executable-memory callbacks; serialization/cache invalidation; and code-size/i-cache behavior from large regex fleets.

## Required standard of analysis

Every proposed fast path needs: applicable semantics, compile cost, steady-state cost, memory and code-size cost, SIMD ISA coverage, bailout/progress rule, worst-case bound, and the Rebar/non-Rebar workloads that validate it. Label estimates as estimates. Do not claim strict superiority until implemented measurements with confidence intervals and correctness differential tests support it.
