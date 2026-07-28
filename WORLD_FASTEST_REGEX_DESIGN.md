# FRE: design for a fastest safe native regex library

## Executive conclusion

The plausible route is not a better single DFA. It is a **semantics-indexed,
operation-specific native compiler** with a small, bounded engine portfolio:

1. parse either the Rust-regex or RE2 language into profile-specific semantics;
2. lower to a canonical prioritized/tagged representation;
3. select a plan for the requested output—existence, end, span, captures, set
   membership, events, or streaming;
4. begin on a cheap precompiled native kernel or a tiny copy-and-patch kernel;
5. JIT genuinely profitable, pattern-specific code on x86-64 or AArch64;
6. fall back monotonically to a prioritized Thompson-NFA executor whenever a
   speculative filter, DFA, TDFA, or JIT budget is exhausted; and
7. use a distinct, higher-fuel but still bounded AOT pipeline.

The differentiators over Rust regex and RE2 must be direct native capture
kernels, better multi-pattern decomposition, per-operation specialization, and
an exact whole-iterator algorithm that avoids repeated-search quadratic work.
Merely translating either library's existing state loop to machine code is
unlikely to win enough.

This is a buildable research program, not proof that an implementation is
already fastest. Four gates precede a full build:

- exact Rust and RE2 compatibility profiles and an independent oracle;
- a proved and tested global leftmost-first iterator bound;
- capture algorithms that close the large PCRE2-JIT performance gap without
  losing safety; and
- a two-ISA JIT whose native-ready latency, code size, and warm speed beat a
  precompiled native kernel at a useful reuse point.

If any gate fails, narrow the product or the claim. Do not hide the failure by
changing match semantics, excluding hard benchmarks, moving JIT work outside a
timed interval, or calling a table interpreter a JIT.

## 1. What “world's fastest” can honestly mean

A universal pointwise claim—faster for every pattern, haystack, operation,
machine, and lifecycle—is physically implausible. A one-byte literal can
already be limited by memory bandwidth; two implementations may call the same
optimal primitive; secure native-code publication has nonzero cost; and
measurement noise makes an infinitesimal “strict” difference unknowable.
Hyperscan also obtains some wins by returning events rather than ordinary
leftmost-first matches.

The literal user requirement should nevertheless be retained as a falsifiable
qualification gate, rather than weakened rhetorically.

### 1.1 Hard qualification gates

For a frozen release candidate, pin source revisions, compiler flags, CPU
governors, benchmark definitions, semantic profiles, and a hardware matrix
containing at least two x86-64 and two AArch64 microarchitectures.

| Gate | Pass condition |
|---|---|
| Correctness | Zero known syntax, non-resource error, span, capture, iteration, Unicode, byte, replacement, or chunk-boundary mismatches against the applicable upstream profile; zero resource-admission mismatches in `StrictAdmission`. `QuotaBounded` results are labeled separately. |
| Complexity | Every accepted plan has a checked work/resource certificate. Doubling tests and counters agree with its analytic bound. No uncapped exponential construction or execution exists; optional subset/tag construction is bounded by explicit `K`/transition/tag caps that may not auto-scale exponentially with pattern size. |
| Literal strict gate | On every preregistered, same-semantics Rebar case shared with Rust regex or RE2, the lower confidence bound for the paired baseline/FRE speed ratio is greater than 1.0 on every qualification CPU. A result inside the noise floor is not a win. |
| Practical ordinary-search gate | At least 20% faster geometric mean than Rust regex on a sealed ordinary holdout, with no case more than 5% slower outside noise; report every case as well as aggregates. |
| Lifecycle | Constructor, native-ready, first search, amortized search, peak compile memory, persistent data, scratch, and code bytes all meet declared budgets. |
| Native-execution authenticity | The headline path contains no regex-opcode bytecode loop. Every result labeled “JIT” executes pattern-specific code that removes measured generic work; shared native primitives and data-driven safety-floor time are labeled separately, and the qualification report publishes their CPU-time shares. |
| Captures | Beat both safe baselines on the capture cohort and approach PCRE2 JIT on deterministic cases; PCRE2 is a speed ceiling, not a safety-equivalent comparator. |
| Event scanning | Compare only the event contract; do not claim Hyperscan leadership until FRE beats it with the same SOM, ordering, streaming, and reporting requirements. |
| AOT | Compare same-semantics lexers and anchored matchers with re2c and source-generated engines, including build time and artifact size. |

Failing the literal strict gate means the implementation does not satisfy the
literal “strictly faster” wording. The practical gate is useful for engineering
decisions but is not a substitute for it.

For a “JIT-primary” release label, use a provisional additional threshold:
after excluding operations that optimally bind an exact shared primitive
(such as one-byte `memchr`) and hosts that forbid JIT, pattern-specific
generated entries should execute at least 70% of held-out ordinary-search
input bytes and account for at least 80% of its sampled search CPU cycles.
Otherwise the product may still be fast, but it is honestly a static/table
engine with a JIT side tier.

### 1.2 What the current evidence says

The pinned Rebar tree contains 68 definition files. Expanding the current Rust
runners yields 360 distinct benchmark names and 848 engine jobs. The latest
committed curated recording puts Hyperscan, Rust regex, .NET compiled, PCRE2
JIT, and RE2 at very different points of the envelope; participation differs,
so their aggregate scores are not interchangeable. On the 31 search cases
shared by Rust regex and RE2, Rust is already far ahead. Across all 52 curated
cases, no engine owns a majority of per-case wins. See the pinned inventory and
record analysis in [the evidence packet](research/EVIDENCE.md).

The implication is important: FRE needs a portfolio and must primarily beat
Rust regex, not merely RE2. The largest opportunities are dense captures,
Unicode boundaries/classes, bounded repeats, large literal/regex databases,
and exact global iteration. Several simple literal paths are already close to
the machine's bandwidth limit.

[Rebar](https://github.com/BurntSushi/rebar) is intentionally a “biased
barometer,” not a population model of all regex use. Qualification therefore
includes the missing-workload suite in section 11 and a sealed planner holdout.

## 2. Compatibility is a set of profiles, not one dialect

Rust regex and RE2 overlap substantially, but identical spellings sometimes
mean different things. One undifferentiated “compatible” mode is impossible.
FRE should expose a Rust-compatible facade by default and a separate RE2-style
facade, both lowered to shared internal semantics after parsing.

### 2.1 Required profiles

| Profile | Required behavior |
|---|---|
| `RustText` | Rust-regex grammar and defaults on `&str`; Unicode-aware `\d`, `\s`, `\w`, `\b`; leftmost-first; no match boundary inside a UTF-8 scalar; Rust captures, names, errors, empty iteration, replacement, and split. |
| `RustBytes` | Rust's bytes grammar on arbitrary `&[u8]`; still Unicode-aware by default, with scoped `(?-u:...)` raw-byte matching and Rust's exact empty-match behavior. |
| `Re2 { syntax, encoding, options, pinned_re2, pinned_ucd }` | The complete orthogonal RE2 product: Perl or POSIX syntax; UTF-8 or Latin-1; `longest_match`, `literal`, newline, capture, case, memory and POSIX-only class/boundary options; exact RE2 errors, guaranteed input domain, byte spans and submatches. Convenience constructors may name common combinations, but are not substitute semantic profiles. `longest_match` applies independently of syntax and retains RE2's own backtracking-like submatch policy, not generic POSIX submatch disambiguation or lexer longest. |

The incompatibilities are semantic inputs to lowering, not parser trivia:

| Axis | Rust-regex surface | RE2 surface | FRE rule |
|---|---|---|---|
| Perl classes/boundaries | Unicode-aware by default, including `\w`/`\b` | ASCII Perl classes and word boundary | Profile-stamped class/property IDs; never share a cache entry merely because pattern bytes match. |
| Text and bytes | `&str` plus a byte facade that remains Unicode-aware unless `u` is disabled locally | UTF-8 or Latin-1 option; `\C` can consume one byte | Separate input validators, boundary advance, and class lowering. |
| Extra grammar | Nested class algebra and Rust flags/boundaries | Octal, `\Q...\E`, RE2 options and POSIX syntax | Separate versioned parsers feeding a common semantic HIR only after meaning is fixed. |
| Repetition/data | Configurable compiled-size limits; richer/current Unicode tables | Counted-repeat ceiling of 1,000; independently versioned Unicode tables | Preserve the upstream acceptance/error and Unicode version in each profile. |
| Names/submatches | Rust capture-name and nullable-participation rules | Different duplicate-name and nullable-submatch behavior; optional longest policy | Oracle and tag policy are selected by profile, including unmatched versus participating-empty slots. |
| Sets and iteration | Rust `RegexSet` returns matching IDs in declaration order and uses Rust's adjacent-empty iterator rule | RE2 `Set` anchor modes return IDs whose order callers must not assume; RE2 operations have distinct progress/submatch behavior | Distinct public contracts and conformance suites; shared executors only after result semantics agree. |
| Replacement/consumption | Rust replacers expand `$N`, `$name`, `${...}` and `$$`, plus split iterators and closure APIs | RE2 exposes `Rewrite`, `Replace`, `GlobalReplace`, `Consume`, and `FindAndConsume`; rewrites accept only `\0`–`\9` and `\\`, with operation-specific empty progress | Separate facade-level operation state machines; share selected matches only after proving the transformation contract identical. |

In particular, repeated RE2 `FindAndConsume` removes a prefix from its input
view, so anchors and match context are evaluated against the remaining view;
it is not merely Rust `find_at` with an incremented absolute offset.

The RE2 identity is the product of syntax, encoding, and the complete option
record. It mirrors `posix_syntax`, `longest_match`, `log_errors`, `max_mem`,
`literal`, `never_nl`, `dot_nl`, `never_capture`, `case_sensitive`, and the
POSIX-syntax-only Perl-class, word-boundary, and one-line controls. These axes
must not be collapsed into three enum variants: for example, longest matching
is available with the default syntax and POSIX syntax can use Latin-1.

The Rust identities likewise include the complete string/bytes builder
configuration, not just a dialect name: Unicode, case, multi-line, dot/newline,
CRLF and line terminator, greed swap, whitespace, octal, size/DFA-size and
nesting controls, plus their pinned defaults and error behavior. Options that
only affect resource selection still matter to compatibility and lifecycle
tests even when they do not alter the selected match.

The pinned targets also differ in Unicode data (RE2 15.1 and Rust 16.0),
duplicate capture-name handling, class set algebra, special word-boundary
forms, flags, invalid-byte behavior, and counted-repeat policy. Profile identity
therefore includes parser version, Unicode version, encoding, options, match
policy, capture-name rules, limit policy, and iterator rules. It is part of
cache keys and AOT artifacts.

Compatibility has two independent axes that must never be conflated:

| Axis/policy | Contract |
|---|---|
| Semantic profile | Grammar, non-resource diagnostics, selected matches, captures, names, offsets, iteration/progress, replacement, and set behavior for the pinned upstream revision and declared valid-input domain. |
| `StrictAdmission` (`ExactCompat`) | Reproduce the pinned upstream constructor's own limit accounting and resource error by invoking it as an admission oracle or by a separately validated faithful emulator. An upstream-accepted pattern that FRE cannot represent within its internal hard safety caps is a FRE qualification failure, not a compatible rejection. |
| `QuotaBounded` | Apply explicit FRE source, compiler, code, scratch, history, and tenant quotas and return the distinct `FreResourceLimit` category. This is useful for services and hostile tenants, but is not error-compatible and cannot enter an `ExactCompat` score. |

Rust's `size_limit` and RE2's `max_mem` constrain upstream-specific
representations, so similarly named FRE arena limits cannot reproduce their
thresholds. No FRE cap failure is relabeled `CompiledTooBig` or
`ErrorPatternTooLarge` without the admission oracle. Exact qualification of
RE2 `Set` runtime DFA-OOM behavior either delegates that resource decision to
the pinned RE2 implementation or excludes the operation from semantic and
performance qualification; ordinary successful set results remain a separate
semantic obligation. Rust-compatible post-construction methods remain
infallible. A quota-returning search is exposed only by a separately named
fallible API.

RE2 rejects counted bounds above 1,000, supports UTF-8 and Latin-1 plus options
such as `longest_match`, `never_nl`, `literal`, `never_capture`, and
`max_mem`. Rust supports nested class intersection/difference/symmetric
difference, `R/u/x` flags, richer Unicode properties and boundaries, and a
separate arbitrary-byte facade. The source references are RE2's
[syntax](https://github.com/google/re2/wiki/Syntax) and
[options/safety contract](https://github.com/google/re2), and Rust regex's
[documented syntax and Unicode behavior](https://docs.rs/regex/latest/regex/#syntax).

RE2-compatible inputs and results are byte spans. In particular, `\C` may end
inside a UTF-8 scalar, so that facade never constructs an `&str` for a match
without separately validating the selected range. `RustText` alone can expose
borrowed string slices by construction.

RE2's UTF-8 contract interprets the input as UTF-8 but applies GIGO behavior
to malformed haystacks in operations such as `GlobalReplace`; FRE therefore
does not invent a cross-version semantic promise for invalid UTF-8. The pinned
adapter records observed behavior for differential testing, while the public
profile marks valid UTF-8 as the compatibility domain. Invalid input must
still remain memory-safe and within the declared work bound; callers needing
defined arbitrary-byte semantics use RE2 Latin-1 or `RustBytes`.

### 2.2 Ordinary match semantics

For first-match profiles, the semantic reference is an ordered backtracking
interpretation implemented without backtracking explosion:

1. choose the smallest permissible start;
2. at that start, prefer an earlier alternation;
3. greedy repetition tries continuation before exit and lazy repetition does
   the reverse;
4. capture tags do not change path priority;
5. repeated captures contain the last participation of the selected path;
6. distinguish an unmatched group from a participating empty group; and
7. reproduce each profile's suppression/advance rule for adjacent empty
   iterator matches.

For Rust, this last rule is not “always advance after an empty match.” The
iterator suppresses an empty match adjacent to the preceding match and then
continues after one byte boundary; for example, `a|(?:)` on `a` yields only
`[0,1)`. The direct reference, upstream adapter and every executor all carry
this as an explicit regression. The public facades then apply their boundary
contract: `RustText` never returns an empty result inside a UTF-8 scalar,
whereas `RustBytes` can return empty matches at every byte offset even though
Unicode atoms remain enabled by default.

Capture tags are profile semantics, not incidental annotations. A slot changes
only when the selected path executes a profile-specific open, close, or reset
action; absence from a later repetition is not itself a reset. Repetition
lowering must therefore retain the exact tag actions, including any explicit
negative/absent reset required by that profile. Language-equivalent repeat
expansion is not sufficient evidence of capture equivalence.

The compatibility corpus also pins intentional cross-profile differences. For
example, `(a*)*` on `x` leaves Rust's inner capture participating empty while
RE2 treats it as not participating; a shared capture executor must select its
tag policy from the profile rather than “fixing” one side.

No optimization may reorder a literal trie, factor an alternation, use an
earliest end, or replay captures unless it preserves that selected path.
RE2 POSIX-syntax and `longest_match` behavior use their stamped options and a
different reference policy; a future true-POSIX submatch product would be
separate again.

### 2.3 Supported and separate features

The union of regular constructs supported by the two profiles is required:
literals, classes and their profile-specific operations, concatenation,
ordered alternation, greedy/lazy repetition, captures, names, anchors, local
flags, Unicode/simple folding, raw bytes where the profile permits them, and
RE2's POSIX/longest options.

Both targets reject backreferences, recursion, arbitrary lookaround, embedded
code, conditionals, and other constructs for which their finite-automata safety
contract does not apply. FRE should reject them too. Future bounded extensions
must live in a new profile and cannot dilute compatibility claims.

Several other contracts remain separate even when they share compiled pieces:

- `RustRegexSet`: every pattern ID that matches anywhere, without offsets;
- `Re2Set(anchor)`: RE2's set membership under its unanchored, start-anchored,
  or full-anchor mode, including its compile/search error behavior;
- `OrderedSet`: one ordinary ordered alternation when the caller actually wants
  leftmost-first priority and a single selected match;
- `EventDb`: Hyperscan-like end events, optional SOM, block/vectored/streaming
  modes, explicit duplicate/order/callback rules, and `O(output)` cost;
- `Lexer`: anchored maximal munch, then rule priority; and
- `ExactStream`: ordinary matching with finality and history rules.

In particular, Rebar's Veryl multi-pattern benchmark is not a maximal-munch
lexer benchmark, and Hyperscan events are not ordinary matches.

## 3. Complexity and resource contract

Let `p` be source length, `P` the number of effective configurations in the
accepted production representation (including any repeat-counter product),
`N` the input bytes, `G` the requested capture/tag slots, `T` the maximum
executed tag commands on a deterministic transition, and `Z` the number of
reported results.

### 3.1 Compilation

- Parsing is iterative and bounded by source/nesting policy.
- HIR retains counted repeats and Unicode sets symbolically. Interval-set
  operations, literal extraction, factoring, ambiguity analysis, and size
  estimation each consume explicit fuel.
- A mandatory bounded semantic plan must fit FRE's hard representation safety
  envelope. Under `QuotaBounded`, a configured shortfall returns the distinct
  `FreResourceLimit`. Under `StrictAdmission`, the pinned upstream oracle alone
  decides compatible resource acceptance/error; if it accepts but FRE's floor
  cannot fit, the build is disqualified rather than mapping the FRE shortfall
  to an upstream error. The floor is the prioritized NFA for a general pattern,
  but a proved exact finite/literal set may use its trie/AC representation
  directly rather than first expanding a giant redundant NFA.
- Construct and validate that portable plan before spending optional
  determinization/JIT fuel. Each optional attempt uses a reservation-backed
  arena, and its peak allocation/work is charged even when the attempt is
  abandoned; a cap failure releases the reservation without invalidating the
  portable plan.
- Full/lazy DFA and TDFA construction have state, transition, tag-command,
  memory, and work caps. Hitting an optimization cap selects the portable plan;
  it does not reject an otherwise compatible pattern.
- Kernel-IR nodes, emitted code, relocations, read-only tables, temporary heap,
  and deterministic compiler work have hard caps; a wall-clock deadline is an
  outer cancellation mechanism, not the complexity certificate.
- AOT has larger configurable caps, never unlimited determinization.
- Every pass over an untrusted-size AST, HIR, automaton, epsilon graph, SCC,
  tagged graph, Kernel-IR CFG, relocation graph, or serialized artifact uses an
  explicit work stack/queue. A recursive helper is legal only after a checked
  maximum depth is proved before entry; fuel alone does not prevent a native
  stack overflow.

The compiler certificate reports a vector of concrete counters—source bytes,
AST/HIR nodes, interval endpoints/merge steps, logical states/edges, bitset
words processed, transition cells, tag commands, hash bytes/probes, allocation
bytes, Kernel-IR nodes, relocations, and emitted bytes. A single undefined
“work token” or weighted `P` is not used to conceal a pass whose cost has a
different slope; every pass reserves before allocating or iterating.

In particular, if `K` deterministic configurations and `A` alphabet classes
are admitted, subset construction is charged at least for the concrete
`K·A·ceil(P/word_bits)` membership work plus transition/tag work. `K` is an
independent hard input to the resource policy, not `2^P` chosen implicitly;
once it is spent, determinization stops permanently and the already-valid
portable plan remains.

Use this provisional Phase-0 policy to make prototypes comparable; every
number is an estimate to falsify, not an upstream semantic limit:

| Resource | Initial runtime/JIT cap | Higher AOT experiment cap |
|---|---:|---:|
| Pattern/set source | 8 MiB | 32 MiB |
| Mandatory semantic compiler arena | 128 MiB | 2 GiB worker limit |
| Effective ordered-NFA configurations | 262,144 | 1,000,000 |
| Optional deterministic states / transitions | 4,096 / 1,000,000 | 100,000 / 10,000,000 |
| Optional deterministic tables | 2 MiB | 256 MiB |
| Candidate plans / Kernel-IR operations per entry | 32 / 8,192 | 256 / 1,000,000 |
| Aggregate native code per regex | 64 KiB hard, 16 KiB target | 4 MiB aggregate artifact code |
| Ordinary per-call scratch | 8 MiB | manifest-selected |
| Fallible global-batch in-memory log | 64 MiB default, caller-declared/preflighted | manifest-selected |
| Exact-stream retained history | 8 MiB unless the caller selects another policy | manifest-selected |
| Live context executable code | 64 MiB, including evicted-but-referenced slabs | artifact/database cap |

Profile-configured limits such as RE2 `max_mem` and Rust builder size limits
remain inputs to `StrictAdmission`; the table above describes FRE's
`QuotaBounded` prototype policy and optional-optimization caps, not upstream
errors. The qualification policy must also admit every
applicable giant-pattern and full-dictionary Rebar definition; if a provisional
cap does not, raise it or report the row as failed rather than deleting it.
Database-scale `EventDb` has a separate explicitly reported data/state budget,
because pretending a million-pattern database is one ordinary regex makes the
cap meaningless.

The native-code row is aggregate across every resident operation entry,
prepared variant and CPU-feature version for one compiled regex. It includes
entry stubs, jump islands, relocations that occupy executable pages, unwind and
CFG entry metadata, and page-rounded RX extents. Read-only tables are metered
separately. Prepared-entry count is capped, and reservation failure leaves the
entry on K0. The 4 MiB AOT code cap has the same aggregate meaning across all
multiversioned operations in the artifact.

Counted repeats deserve special treatment. Deterministic fixed/run forms may
use compact counters. Nested or ambiguous counters must expose their effective
configuration product; otherwise expand under the normal compiled-size limit
or reject. “Non-backtracking” by itself is not a ReDoS proof: bounded repeats
have produced attacks on non-backtracking engines, as documented in
[Counting in Regexes Considered Harmful](https://www.usenix.org/conference/usenixsecurity22/presentation/turonova).

### 3.2 Execution

The portable floor is a nonrecursive prioritized Thompson/Pike scan. Its
general capture implementation keeps a fixed capture-slot vector per live
ordered state (or an equivalent bounded sparse representation), so it does not
depend on an input-growing tag-history log:

- existence/end/span: at most `O(PN)` transition work and `O(P)` live-state
  storage;
- general captures: a declared bound such as `O(PGN)` work and `O(PG)` live
  storage; persistent tag histories are only an optimization, and may bail out
  only by materializing the current fixed slots without restarting input;
- capture-free DFA: `O(N + Z)` after bounded construction; tagged one-pass or
  TDFA: `O((1+T)N + ZG)`, with tag-command count/data included in its compile,
  scratch, and dispatch budget;
- event databases: `O(PN + Z)` under the selected representation; and
- every filter/reverse/verifier/lazy-build path adds only a configured constant
  multiple before a one-way fallback.

A scan maintains a committed input frontier and an operation-wide work ledger.
Candidate verification charges actual transitions, not just candidate count.
Reverse scans have a low-water mark. Lazy states retain the underlying NFA set
needed to continue. Once a speculative budget is exhausted, execution switches
once at the earliest unresolved frontier; it cannot oscillate or repeatedly
restart over the same suffix.

Accounting need not add an atomic branch to every byte. A kernel reserves a
bounded block of credits into a register, decrements locally, and reconciles at
well-defined safepoints; its certificate proves that the maximum unreported
work is that reservation. Cancellation and tenant quotas use the same
safepoints. A bailout carries the exact unresolved frontier and semantic state,
not merely an input offset.

Concretely, an adaptive plan is legal only if it (a) continuously maintains a
shadow portable state, (b) retains a complete checkpoint plus a proved finite
dependency horizon, or (c) performs one charged restart from the earliest
possibly unresolved start and then disables the optimization. A literal hit
position or “current cursor” alone cannot prove that no earlier-started match
crosses the handoff. Sharded event plans obey the same rule.

### 3.3 The exact global-iteration gate

Rust documents `find_iter`/`captures_iter` as worst-case `O(PN^2)` because each
successive search can scan the remaining suffix. Rebar's
`.*[^A-Z]|[A-Z]` on `A^N` exposes it. Hyperscan is linear there because it
returns different events, which is not a valid solution.

FRE cannot claim “no worst-case blowup” for the complete compatible API until
one of these bounded, exact candidates is proved and implemented:

1. **Ordered suffix DP.** Compute the highest-priority successful continuation
   for each `(input boundary, priority-expanded configuration)` backwards,
   retain root endpoints, and emit nonoverlapping matches forwards. A plain
   Boolean `V[nfa_state, position]` is rejected: the key must include relevant
   epsilon-visitation/order, counter valuation, assertion/profile context and
   operation-wrapper state. Use full tables as the simple oracle; test block
   checkpoints and hierarchical recomputation as memory/time variants. Resolve
   nullable epsilon SCCs and every assertion explicitly without erasing
   priority-bearing edges.
2. **Whole-operation transducer plus a two-pass lean log.** Compile
   `find_iter(R)` itself, rather than repeatedly invoking `find(R)`. A
   prioritized `SEARCH` state first tries an anchored copy of `R`; only if that
   has no selected match does it consume one profile boundary and remain in
   `SEARCH`. Match-entry/exit tags delimit every result. A finite
   `AFTER_MATCH` state reproduces the profile's exact rule for suppressing an
   empty result adjacent to the previous result, including the important case
   where an empty higher-priority result is discarded instead of trying a
   lower-priority nonempty alternative. The wrapper consumes the complete
   input, so one greedy parse should encode the same match sequence by
   induction on emitted matches. Run the published ordered-NFA two-pass
   algorithm once over this total-input transducer, write branch decisions to
   a sequential lean log, and replay captures/results. Including materialized
   capture output, the target is `O(PN + ZG)`. For one greedy parse, the paper
   gives `O(PN)` parsing time, `O(P)` random-access words, and `kN` sequential
   log bits where `k` is the number of choice/star sites (`k < P/3` in its
   construction). FRE still needs a proof that the wrapper construction, nullable-loop
   normalization, local assertions, UTF-8 boundary skips, captures, and each
   profile's empty rule meet the paper's premises. See [Two-Pass Greedy Regular
   Expression Parsing](https://www.diku.dk/kmc/documents/ghnr2013.pdf).
3. **Fused prioritized transducer.** Scan once while retaining compact,
   persistent histories for unresolved starts, then emit once choices become
   final. Bound history, EOF delay, capture resets, and output replay.

For capture-heavy output, a capture-erased global pass may choose exact spans,
then an anchored tagged executor replays each selected, nonoverlapping span
with the original surrounding context and required group-0 end. Total replayed
input is at most `N`; empty matches add at most `O(PN)` work. This is a
hypothesis until profile-specific differential tests establish capture identity.
The resolver must impose that end as an internal exact-end constraint; it may
not slice the haystack or append an ordinary `$`, either of which can change
line anchors, boundaries, and assertion context.

The go/no-go test exhausts small ASTs, captures, assertions, nullable loops,
lazy/greedy forms, invalid bytes, and empty iteration against upstream behavior,
then verifies work and memory slopes while doubling `P` and `N`. Until it
passes, the old quadratic iterator is an honest reference behavior—not a
shippable fulfillment of the stated goal.

The lean-log result is a candidate for the first-match profiles, not an
automatic proof for an RE2 configuration with `longest_match`. RE2's longest
whole match plus its own submatch ordering needs its own
total-input tagged DP or bounded TDFA construction and the same aggregate
iteration proof. FRE cannot silently run the Perl-priority wrapper when the
RE2 profile requests longest behavior.

Three contracts prevent the research candidate from being mistaken for a
finished resource story:

| Contract | Current status and resource behavior |
|---|---|
| `find_iter_reference` / `captures_iter_reference` | Stage-0 exact compatibility oracle using repeated search, with the upstream sequence and documented `O(PN^2)` worst case. It may support prototypes, but it is neither the final facade nor evidence for the no-blowup goal. |
| `find_all_bounded` / fallible `SearchSession` | Candidate batch API. The caller declares maximum input boundaries and history/storage bytes. FRE computes and reserves the complete requirement before scanning or publishing output; insufficient capacity returns `HistoryLimit`. It may use an explicitly supplied sequential store. No partial sequence precedes admission. |
| `find_iter_compatible` / `captures_iter_compatible` | Required final infallible facade, but prohibited from production until an exact aggregate theorem and implementation pass the gate below. It returns the pinned sequence and may not add `HistoryLimit`, spill implicitly, or fall back to repeated search. If no candidate qualifies, FRE must narrow the API or the no-blowup claim rather than ship this name. |

The compile certificate for a lean-log candidate must expose `k`, the exact
maximum decision bits per profile input boundary, plus fixed header/index and
replay-buffer terms. For `U` addressable boundaries, preflight computes with
checked integer arithmetic:

```text
decision_bits = checked_mul(k, U + 1)
log_bytes     = checked_add(ceil_div(decision_bits, 8), headers + index_bytes)
peak_bytes    = checked_add(random_state_bytes(P,G),
                            log_bytes + replay_bytes(P,G) + output_buffer_bytes)
```

The proof must also state total forward log writes and reverse/sequential
replay reads in bytes, replayed input bytes, output work, peak random-access
memory, retained input lifetime, time to first result and time to each later
result. Its target bound is `O(PU + ZG)` work, `O(P+G)` random-access words,
the checked `log_bytes` sequential storage, and at most one exact-end capture
replay over each byte of the nonoverlapping selected spans. Nullable SCCs,
local assertions, Rust byte/scalar boundary rules, captures, subranges with
original context, and RE2 longest mode each need a proof or a separately
typed algorithm; testing cannot fill a missing case in the theorem.

For the future `StrictAdmission` compatible facade, the explicit allocation
policy is an overflow-checked, one-shot reservation from the ordinary process
allocator for `peak_bytes` when the aggregate pass becomes necessary. It has
no 64 MiB FRE quota and never opens or spills to a file. Allocation failure
follows the host language's ordinary OOM/capacity-failure policy, just as other
infallible collection-producing APIs do; it is not converted into a semantic
result. `QuotaBounded` callers instead use `find_all_bounded`, whose declared
memory/store limit is preflighted. This is a resource contract, not a claim
that the lean-log construction is already correct.

The candidate is offline: it sees the relevant EOF and replays a decision log
before yielding later results in forward order. It may return the first result
with the normal bounded single-search plan; on a request for the second, it can
initialize the total transducer at that result's exact `AFTER_MATCH` state and
solve the unresolved suffix once. The theorem must count both passes and cover
an empty first result, adjacent-empty suppression, early drop, subranges and
captures. The second `next()` may consume the remaining suffix, so latency and
input retention are public, measured properties. If upstream compatibility is
found to require a stronger per-`next` latency/allocation guarantee, this
candidate fails.

Once proved, the aggregate guarantee applies only to library operations that
own their state: `find_iter`, `captures_iter`, `count`, `split`, replacement,
and `SearchSession`. A caller can still compose independent `find_at` calls on
overlapping suffixes into quadratic application work; no regex object can
recover discarded state. Until the theorem passes, the production facade and
schedule must not rely on the `O(PN)` claim, and the final product remains
blocked on this gate.

## 4. Modular architecture and dependency direction

The architecture follows the composability/testing lesson of
[Rust regex internals](https://burntsushi.net/regex-internals/) while accounting
for native code. Workspace crates are independently testable; they need not all
be frozen as stable public APIs.

```text
 profile parsers + Unicode tables ------> direct profile-AST reference
              |
       canonical semantics/HIR --------> simple HIR evaluator
              |
      prioritized/tagged automata
              |
          bounded analyses
              |
       pure planner + certificates
         /        |          \
 literals   typed Kernel IR   AOT planner
                 / | \
       interpreter x64 AArch64
                 \ | /
       runtime: scratch, code/cache, execmem
                    |
        Rust facade / stable C ABI / C++ wrapper
```

Suggested ownership—not necessarily one public crate per box:

| Component | Responsibility and test seam |
|---|---|
| `fre-syntax` | Versioned Rust/RE2 parsers, Unicode tables, AST and semantic HIR. Parser conformance is tested without automata. |
| `fre-reference` | Small, fuel-bounded direct evaluator of the frozen profile AST and operation rules, plus a separate simple HIR evaluator. The direct path does not consume canonical HIR or production epsilon/tag lowering; neither path depends on production automata, planning, or JIT. |
| `fre-automata` | Canonical prioritized/tagged NFA, tag semantics, repeat representation, deterministic derivatives. |
| `fre-analysis` | Width/nullability, literals, one-pass, alphabet, capture liveness, ambiguity, progress, stream horizon, and resource estimates. |
| `fre-global` | Whole-operation iterator transducers, full/checkpoint DP, lean-log and persistent-history candidates, post-match profile state, preflight/spill contracts, and their sequence-level oracle comparisons. |
| `fre-eventdb` | Separately staged set/event database planning, literal roles, SOM/stream state, output contracts, and database-scale tests; it cannot supply an ordinary-match plan merely because it shares HIR or literal engines. |
| `fre-plan` | Pure candidate enumeration, capability/output typing, fallback DAG, work/resource certificates, versioned cost model, and `explain`. |
| `fre-kernel-ir` | Narrow typed native IR, structural/memory verifier, interpreter, text form, and optimizer properties. |
| `fre-codegen-x64`, `fre-codegen-aarch64` | ISA lowering only; encoding, relocation, ABI, disassembly, guard-page and register-canary tests. |
| `fre-portable` | Precompiled scalar/SIMD automaton kernels and the fixed-slot ordered Pike/Thompson production safety floor. No regex bytecode opcode loop. |
| `fre-runtime` | Explicit contexts, CPU dispatch, scratch, immutable code slabs, cache/eviction, executable-memory policy, background compilation. |
| `fre-aot` | High-fuel planning, target multiversioning, object/data artifact generation, linking and validation. |
| `fre`, `fre-capi` | Thin safe Rust API, opaque versioned C ABI, and header-only C++ RAII wrapper. |
| `fre-conformance`, `fre-debug`, `fre-rebar` | Shared corpus, exhaustive/fuzz adapters, layer inspection, benchmark runners, plan/disassembly/work-counter tooling. |

Semantic crates may not depend on runtime or code generation. ISA emitters only
accept validated Kernel IR. The planner and Kernel IR can be snapshot-tested
without executable memory. A canonical `MatchRecord`—pattern ID, group-0 span,
participation bits, and capture spans—lets every executor run the same corpus;
individual APIs project only what they request.

The conformance seam is a versioned, engine-neutral case record containing
profile/options, pattern bytes, operation and input span, haystack bytes,
optional chunk/vector partition, expected compile error, and the complete
`MatchRecord` stream. The reference engine, portable executor, forced planner
candidates, Kernel-IR interpreter, both ISA backends, AOT objects, Rust facade,
and C facade consume the same records. This makes a backend independently
testable without importing the production parser's expected result or another
executor's internal state.

Plans are typed by `(profile, operation, input contract, output capability)`;
for example a `SelectedEnd` plan cannot be installed in a `ShortestEnd` or
`Span` entry slot, and an
event fallback cannot inhabit an ordinary leftmost-first slot. Fallback edges
must preserve that type and carry a machine-checkable transfer schema. This
removes semantic mode flags from hot kernels and makes invalid planner DAGs
rejectable without executing generated code.

The workspace denies `unsafe` in syntax, semantics, automata, analysis,
planning, reference, and public safe-facade crates. Audited `unsafe` is confined
to ISA encoding/publication, OS executable-memory glue, low-level SIMD loads
with proved tails, and FFI shims; each such module has a written invariant and
Miri/sanitizer/guard-page coverage where the tool can exercise it.

The test oracle is deliberately not the production NFA executor. Sharing the
same canonical HIR, automaton construction, or priority closure would
correlate the most dangerous bugs, which is why the direct small-case oracle
interprets profile AST and operation rules. The simpler HIR evaluator isolates
post-lowering executor tests. Upstream differential tests additionally catch
parser acceptance, diagnostic, or profile-rule mistakes shared by internal
code.

## 5. Planner and bounded engine portfolio

The planner compiles operations, not just patterns. Its output contract is one
of `Exists`, `RangedExists`, `SelectedEnd`, `ShortestEnd`, `Span`,
`RangedMatch`, `Captures`, `PatternCaptures`, `PatternMembership`,
`RangedMembership`, `ReplaceFirst`, `ReplaceN`, `ReplaceAll`, `Split`,
`SplitN`, or `Events`. `SelectedEnd` is the end of the profile-selected
leftmost match. `ShortestEnd` retains Rust's historical public method name but
is not a mathematical shortest/earliest-end promise: it returns the point at
which the selected internal executor has established a match and may vary with
documented engine heuristics, exactly as the pinned API permits. It is still a
distinct output contract and cannot be silently implemented as `SelectedEnd`.
`PatternCaptures` returns the selected pattern ID and that pattern's capture
layout. `count` may erase captures and starts; Rebar `count-spans` needs only a
running sum of selected group-0 lengths; a capture-count operation needs
participation, including group 0, but not offsets or owned substrings. These
distinctions are both benchmark requirements and real API optimizations.

Each candidate declares:

- profiles and output contracts it implements;
- compile work, persistent data, code, and scratch upper bounds;
- execution complexity and progress potential;
- required CPU features and minimum safe input length;
- exact bailout continuation and fallback; and
- the measurements that produced its cost parameters.

The fallback graph is acyclic. All candidates remain force-selectable in tests
and benchmarks. Planner snapshots explain why alternatives were rejected, and
planner regret is measured against the best valid forced plan on a sealed
holdout.

### 5.1 Initial dispatch order

1. **Constants and exact finite languages.** Detect impossible, empty-only,
   anchored fixed answers, exact literals, and small exact finite sets before
   constructing a general NFA. Derive fixed captures when possible.
2. **Literal kernels.** One byte uses the platform's best `memchr`-shaped
   kernel; substrings use tuned `memmem`/Two-Way/vector candidates. Small sets
   bake off Teddy-style nibble filters, medium sets an FDR-like filter plus
   trie confirmation, and large sets dense/sparse Aho-Corasick. These are data
   structures, not one threshold guessed from Rebar.
3. **Fixed-width windows and runs.** Candidate masks compare rare/fixed bytes
   in parallel, then verify a bounded window. Deterministic repetitions use
   counters or vector class runs. Every load has an in-bounds or guarded-tail
   form. “Fixed width” here means a proved byte width for the selected input
   profile, not merely a fixed number of Unicode scalars: for example,
   `\p{L}{256}` consumes exactly 256 scalar values but between 256 and 1,024
   UTF-8 bytes, so it is a scalar run or byte-automaton case rather than a
   256-byte SIMD window.
4. **One-pass tagged machine.** One-pass determinism is an anchored property.
   Use it directly for anchored/full matching and as an exact capture resolver
   after another bounded plan has selected the start/end with original
   assertion context. Direct unanchored search is admitted only for separately
   proved restart-safe/failure-function or finite-window forms; it is not
   inferred from anchored one-pass eligibility. Eligible small machines use
   direct branches and capture registers/scratch; larger ones use a
   constant-size native table loop.
5. **Memoized bounded backtracker.** For short-input capture and sparse-state
   regions, preflight the complete `Q·(N+1)` visited bitmap (plus captures and
   stack) with checked arithmetic before search. If it does not fit the
   operation's admitted workspace, choose Pike before consuming input; never
   fail or restart halfway through the haystack.
6. **Bounded TDFA/full DFA.** Attempt only within state, tag-register, table,
   compile-work, and code estimates. AOT receives more fuel. Tagged
   determinization is never assumed small.
7. **Lazy DFA.** Useful directly for capture-free existence/end. A `Span` plan
   must additionally name an exact reverse-start DFA, tagged-start transducer,
   or retained-history mechanism; a forward end alone is not a span. Bound
   cache creation and retain the ordered-NFA subset at the current frontier so
   exhaustion can continue without repeated cache flushing or a full restart.
   A force-selectable run-skip variant may replace a proved DFA self-loop with
   a `memchr`/class scan only when the skipped bytes have no acceptance, tag,
   assertion, progress, or event effect.
8. **Portable prioritized/tagged NFA.** Universal production floor, using
   bounded per-state capture slots rather than an unbounded input history.
   Small qualifying Glushkov/position machines may use word/SIMD bitsets, but
   eligibility includes the number of shift groups, exceptional edges,
   assertions, counters, tag side exits, and active-set density. State count
   alone and a general “bit-parallel” label are not proofs of applicability.
   Reverse, profile-aware Pike/backtrack/one-pass variants are force-selectable
   for exact start recovery and Unicode-boundary workloads. They retain the
   original haystack context, reverse assertion semantics and the same global
   work ledger; a sliced or context-free reverse search is inadmissible.
9. **Global iterator layer.** Use ordinary repeated search only when maximum
   width, deterministic streaming, or the operation ledger proves aggregate
   progress. Otherwise invoke the validated global algorithm from section 3.3.

This is a menu of bounded representations, not a mandate to ship all of them
at once. The v1 core should include literals/sets, fixed width, one-pass,
lazy/bounded DFA, and the NFA floor. Full TDFA, bounded bit-state backtracking,
general bit-parallel NFA, and newer SIMD-DFA schemes enter only after bakeoffs.

### 5.2 Captures: retain four credible strategies

Capture performance is a project-defining risk. FRE should implement a common
tag semantic model and compare:

| Candidate | Best region | Principal risk |
|---|---|---|
| Direct one-pass | Deterministic parsing, logs, dates, many lexers | Eligibility is narrow; assertion and reset details. |
| Register or multi-pass TDFA | Reused/AOT patterns with manageable tagged state space | State and tag-command explosion. |
| Locate span then anchored replay | Sparse matches, fast DFA/literal location | Dense matches duplicate work; replay must use original context and exact end. |
| Fixed-slot ordered Pike NFA | General ambiguous captures and mandatory fallback | `P×G` copy/update constants. |
| Persistent-history tagged NFA | Ambiguous captures when histories reduce copying | Comparison/reclamation proof and exact transfer into fixed slots. |

For every operation, measure capture density, tag writes/copies, peak history,
and output cost. The certificate separately caps `sum(live_slots(state))`,
simultaneously materialized slot cells, tag-copy/update operations, and history
nodes; a weighted state count cannot hide a `states × groups` allocation. A
sanity check shows why: 100,000 states × 2,048 offsets (1,024 groups) × 8 bytes
is 1,638,400,000 bytes, about 1.53 GiB for one dense table and about 3.05 GiB
for two—not a viable 8 MiB scratch plan. A
literal prefilter plus replay must surrender to direct NFA
execution when candidate work reaches its ledger. The UnicodeData and
unstructured-log Rebar cases are capture go/no-go tests, not minor benchmarks.

The re2c tagged-DFA work demonstrates that deterministic submatch extraction
is a serious AOT candidate, not that arbitrary TDFA construction is safe or
small. See [A closer look at TDFA](https://re2c.org/2022_borsotti_trofimovich_a_closer_look_at_tdfa.pdf).

### 5.3 Unicode and bytes

Keep Unicode classes as interned interval/property objects in HIR. The planner
chooses between two exact lowerings:

- a minimal UTF-8 byte automaton when its state estimate is small; or
- an ASCII vector fast loop with scalar UTF-8 decode/classification on side
  exits, retaining scalar boundaries and simple case-fold rules.

The second lowering is directly sufficient only when all concurrent states
advance in scalar units. `RustBytes` may mix raw one-byte edges with Unicode
edges that consume a 1–4-byte scalar, and RE2 UTF-8 has the same mixed-width
problem when `\C` appears beside scalar constructs. For those configurations
retain two bounded candidates: lower Unicode edges into capped UTF-8 byte
automata, or use a byte-indexed NFA scheduler in which a validated scalar edge
enqueues its target at `i + utf8_len` while raw edges enqueue at `i + 1`. The
direct reference models this mixed schedule, including malformed prefixes and
chunk splits. For RE2 UTF-8 those malformed cases test safety, bounds, and the
pinned implementation rather than creating a new compatibility guarantee;
production still cannot replace the schedule with one global “decode then
advance” loop.

The UTF-8 byte automaton is the universal correctness candidate. A bucketed
mixed-width scheduler is eligible only after a proof that its future buckets,
deduplication and merges preserve canonical path priority when byte and scalar
paths of different widths converge at the same offset; every queued item must
retain the required priority/start/tag provenance. A scalar-only whole-machine
lowering is permitted only when analysis proves every consuming path remains
scalar-aligned. Otherwise planner uncertainty selects the byte automaton.

Look assertions are profile operations, not Boolean shorthand over one shared
classifier. In particular, Rust's Unicode-aware `\B` behavior in arbitrary
byte haystacks is not generally implemented as a naive `!\b` around invalid
UTF-8; exhaustive invalid-prefix and chunk-split cases compare each look kind
directly with the pinned upstream byte API.

Unicode word-boundary kernels classify adjacent scalars directly and run an
ASCII-specialized loop until a high byte appears. Class set algebra uses
linear interval merges with fuel. Case-fold expansion is budgeted. No
normalization is performed because neither compatibility target promises it.

An ASCII fast loop is a subloop, not a separate search restart. Its non-ASCII
side exit transfers the complete ordered/tagged automaton state, previous
boundary classification, decoder state, and earliest unresolved start to the
scalar/mixed executor; a match such as `a+é` spanning that exit cannot be
lost or reinterpreted.

`RustText` may rely on `&str` validity. `RustBytes` must reproduce scoped
Unicode/raw-byte semantics on invalid input. RE2 UTF-8 and Latin-1 have their
own lowering rules, including `\C`. The plan never silently bails from a
Unicode assertion to ASCII semantics.

### 5.4 Multi-pattern and streaming plans

For set membership and event scanning, use Hyperscan's useful architectural
idea—decompose patterns around automatically selected mandatory literals and
connect the roles to small finite-automata verifiers—without importing its
semantics into ordinary `Regex`. The Hyperscan paper describes this combination
of graph decomposition, string matching, automata, and SIMD
([NSDI 2019](https://www.usenix.org/conference/nsdi19/presentation/wang-xiang)).

- small literal sets: Teddy candidate;
- medium/large literal sets: FDR-like or Aho-Corasick candidate;
- literal-triggered regexes: Rose-like role graph with bounded left/right
  verification and one operation-wide ledger;
- triggerless regexes: shared bit/state-set machines;
- large repeats: proved counter/run components, never hidden expansion; and
- output-dense databases: `O(Z)` reporting is charged explicitly and callbacks
  may request termination.

An ordinary ordered union retains alternation priority. `RustRegexSet` and
`Re2Set` can exploit event machinery because only membership is visible, but
their anchor, error, and result contracts remain profile-specific. `EventDb`
defines result order, duplicate behavior, SOM horizon, empty events, callback
termination, and block, vectored, and streaming offsets precisely.

For a fair Hyperscan comparison, `EventDb::Unordered` promises the same event
set but no stable ordering among events at the same end and does not sort IDs.
`EventDb::Deterministic` is a stronger wrapper with a defined `(end,id)` order;
its buffering/sorting cost is charged and reported separately. SOM and
finite-horizon streaming are likewise separate compile contracts, not free
flags on an end-only result.

Exact streaming may emit early only when a match is irrevocable. A finite
maximum/decision horizon gives bounded delay. An unbounded greedy expression
may require EOS and retained branch history. The fallible stream API accepts a
history/spill budget and returns `HistoryLimit` without changing the result.
Event streaming uses fixed compile-time state where its contract permits it.

Vectored and rope input uses a segment cursor and retains the actual
literal/automaton/UTF-8 state across segment boundaries. A bounded scratch
coalescing window may feed a SIMD kernel, but correctness never assumes that a
whole literal fits in one segment or in a small two-segment seam; a megabyte
literal split across one-byte iovecs follows the same state machine as the
concatenated block input.

## 6. Native JIT and SIMD

### 6.1 Tiers

FRE does not compile regex bytecode. It uses three honestly named native tiers:

1. **K0 portable kernel.** Precompiled Rust scalar/SIMD loops consume typed
   automaton/literal tables. There is no opcode dispatch. This path is ready
   immediately, supports no-JIT hosts, and is the correctness/safety floor.
   A general TNFA is normalized into typed structure-of-arrays edge/tag/look
   regions; fixed phase loops traverse those regions rather than switching on
   a regex instruction kind for every active state. This is still honestly a
   data-driven table runtime, not pattern-specialized JIT code.
2. **J0 direct JIT.** Tiny copy-and-patch stencils or a macroassembler specialize
   pointers, constants, output shape, CPU features, fixed checks, and small
   control-flow structures. It is counted as JIT only when the emitted trace
   removes material generic work; cheap eligible patterns may receive it at
   construction.
3. **J1 hot JIT.** A call/byte threshold asynchronously or synchronously lowers
   validated Kernel IR to more specialized code. Entry slots are atomically
   replaced between calls; published code is never patched.

An entry replacement must preserve the operation/profile type, continuation
schema, and pre-negotiated scratch layout, and its required scratch cannot
exceed the capacity attached to that entry. A specialization needing a larger
layout is exposed through explicit `prepare_*`/new-scratch negotiation rather
than being installed behind an existing caller's pointer.

Automatic promotion needs an uncertainty margin, not just a call count. A
starting rule is to JIT only when the lower confidence bound on expected
future savings is at least twice parse/lower/emit/seal/install cost; explicit
eager preparation can override that economic policy without changing resource
caps.

Shared native binding is the right answer for a one-byte literal or a
million-pattern fleet if unique code cannot pay back its publication and
instruction-cache cost. Report the fraction of work using genuinely
pattern-specialized code; do not relabel a wrapper around a table kernel as an
optimization.

Code/data cache keys include the full canonical semantic representation,
profile/options and Unicode versions, operation/output type, planner/KIR
schema, target ABI, and CPU features. Hashes select a bucket; reuse requires
full canonical equality, so a collision cannot bind the wrong semantics or
native entry. Runtime caches use a per-context keyed hash and cap/probe or
rehash pathological buckets, so attacker-chosen patterns cannot turn correct
collision handling into an unbounded cache-lookup chain. Reproducible AOT
content IDs use a separate stable digest and still verify canonical equality.

Every high-level operation has an independent lazy entry slot. Asking for
`is_match` does not eagerly compile capture code. A regex/context owns
immutable plan data; caller-owned or pooled scratch owns mutable state.

### 6.2 Kernel IR

Kernel IR is a deliberately narrow, typed CFG rather than a general compiler
IR. It includes checked/guarded cursor loads, class and mask tests, bounded
loops, state-bit operations, table lookups, tag writes, result construction,
callback exits, work accounting, and explicit bailout edges. Regions and
alignment are typed. Loops carry a termination/progress invariant.

The verifier checks region provenance, load range/tail guards, integer
overflow, branch targets, loop bounds, output capacity, scratch layout, CPU
feature requirements, and bailout compatibility. Its interpreter is the
first executable implementation and is differentially tested before either
ISA emitter exists. That interpreter is a bring-up/oracle tool, not the
production fallback or a benchmarked “JIT” path; K0 supplies production
no-JIT execution without a Kernel-IR bytecode loop.

An internal call can use an ABI resembling:

```text
kernel(plan_data, input_ptr, input_len, start,
       scratch_ptr, output_ptr, output_capacity) -> status
```

Real entry points are operation-specific to eliminate flags. The checked
runtime trampoline validates the plan/scratch compatibility cookie, operation,
alignment, input span, and output capacity before generated code runs.
For C callers this validation can check integer overflow, lengths, alignment,
layout cookies and internally owned ranges; it cannot prove that an arbitrary
foreign pointer denotes readable memory for the stated length. Pointer
validity, aliasing and lifetime remain documented C preconditions.

### 6.3 Concrete SIMD shapes

SIMD is valuable where lanes are independent:

- byte/rare-pair/subsequence masks for literal candidates;
- Teddy/FDR-style multiple-literal filters;
- fixed-width class windows and delimiter scans;
- multiple NFA states in bitsets;
- ASCII detection, UTF-8 validation/classification, and boundary side exits;
- multiple independent short haystacks in a batch API; and
- event-database pattern lanes.

The initial emitted shapes are concrete and force-selectable:

| Shape | Inner loop | Exactness/bailout |
|---|---|---|
| Rare pair / fixed offsets | Load one or more vectors, compare bytes/classes at compile-time offsets, AND shifted masks, enumerate set bits with `ctz`/equivalent. | Candidate mask is only a filter unless the whole fixed window was proved; verifier work spends the shared ledger. |
| Fixed-width class window | Form a mask per position constraint and combine a bounded Boolean mask DAG after lane shifts; record group offsets arithmetically. Correlated branches remain `OR(AND(a0,b1), AND(c0,d1))`, never the weaker `AND(OR(a0,c0), OR(b1,d1))`. | Only for a proved fixed width and boundary policy; scalar guarded tail is identical. |
| Small position automaton | Keep eligible Glushkov/Shift-Or states in one or several machine/SIMD words; update with precomputed class masks. | Eligibility proves epsilon/tag/priority handling; otherwise select sparse/dense Pike kernels. |
| One-pass tagged machine | A state block loads/classifies, branches directly to the next block, and writes only live capture registers/slots. | Code-size estimator switches large machines to a constant-size table kernel before emission. |
| Ordered sparse TNFA | Partition closure work by finite boundary context, specialize active-list widths and live-tag layouts, and emit direct closure/state fragments while the code estimate fits. Larger native entries use dimension-specialized loops over structure-of-arrays transitions, with no state-kind opcode switch. | Priority, assertion, merge, capture-update, and fallback rules come from the canonical TNFA. Direct fragments stop at the code cap; the fixed-slot Pike kernel remains the independently tested floor and is not credited as JIT specialization. |
| Ordered dense TNFA | Emit a fixed sequence of proved closure/transition word operations, unrolled to the selected word count; inline small live-tag moves and use a bounded typed scatter/copy loop for large tag sets. | Only a lowering certificate that preserves ordered merges and assertions permits this shape. An arbitrary epsilon graph is not silently called a bit NFA. |
| Large DFA/table machine | A native loop classifies `b` and performs `state = table[state,class]`; acceptance/result logic is operation-specific. | This is honestly reported as a table automaton, not credited as pattern-specific JIT speedup. |

An arbitrary DFA's next state depends on the preceding byte. FRE makes no
blanket claim to process many bytes of that DFA in parallel. Speculative block
function composition or newer SIMD-DFA schemes may be AOT experiments, measured
against their table and setup cost.

x86-64 variants initially cover scalar/SSE2 and AVX2; SSSE3 is relevant to
shuffle filters, and AVX-512 is selected only after measuring frequency and
code-size effects. AArch64 gets scalar and NEON from the first supported
release; SVE2 is optional. NEON candidate extraction must be designed and
measured rather than transliterating x86 `movemask`. All tails and page
boundaries are tested with guard pages; no undocumented overread is allowed.

### 6.4 Backend bakeoff and initial budgets

This section records research options from the original design, not the
current compiler architecture. FRE's current Search JIT and Search AOT share
the custom direct `fre-jit-aarch64` machine-code emitter, while Count-v2 AOT
uses the separate custom direct `fre-aot-aarch64` emitter.

Compare the same Kernel IR through:

- precompiled static kernels;
- copy-and-patch stencils, motivated by the low-latency technique in
  [Copy-and-Patch Compilation](https://fredrikbk.com/publications/copy-and-patch.pdf);
- a tiny custom macroassembler; and
- Cranelift as a control/possible larger hot tier.

LLVM was proposed only as an optional offline AOT research experiment, not as
FRE's current regex compiler or payload generator. No such LLVM AOT backend is
implemented in the current source.
Choose a Pareto frontier, not a backend by taste. Measure process-cold p50/p99
parse, plan, emit, seal, first call, steady cycles/byte, code bytes, and reuse
break-even on both ISAs.

Starting hypotheses to validate are a 64 KiB aggregate hard per-regex JIT-code
cap, a 16 KiB typical aggregate target, a bounded 64 MiB context code cache,
and sub-millisecond p99 native readiness for a moderate (roughly 512-state)
eligible kernel. “Aggregate” has the section 3.1 meaning: all operations, CPU
variants, stubs, islands, unwind/CFG data and page-rounded RX mappings compete
for it, with a separate RO-table account and prepared-entry-count cap. These
are estimates, not compatibility limits or promises.

For declared simple direct shapes, use the sharper Phase-0 falsification gate
of at most 20 µs p50 and 100 µs p99 for lower, emit, seal and publication on
the named reference machines. Missing it does not change semantics; it keeps
the plan on K0 and falsifies that JIT shape's cold/lower-reuse region.

The context limit applies to all still-mapped executable slabs, including code
evicted from lookup tables but retained by an active regex or in-flight call;
cache eviction alone does not release the charge. Code publication reserves
against the live context/tenant budget before allocation and keeps the
portable entry point if it cannot reserve. Separate cumulative compiler-work
and queue-rate quotas prevent an attacker from staying below the resident cap
while churning unlimited native code.

Rebar's full-engine compile rows time construction to a search-ready object and
validate later; its AST, HIR, NFA and prepared-executor rows stop at different
named artifacts. The FRE runner records the exact artifact plus
constructor-ready, native-ready, first-search and amortized costs where those
states exist. Cache is disabled where the model recompiles a pattern; untimed
validation may not trigger deferred JIT and manufacture a false win.

## 7. AOT pipeline

AOT shares profile semantics, automata, plan certificates, Kernel IR, and the
test corpus. It receives substantially more but finite fuel for:

- full DFA or register/multi-pass TDFA attempts;
- alphabet and state minimization that respects tags and priorities;
- tag-register allocation/copy elimination;
- literal/trie factoring;
- direct-branch, bitmap, computed-dispatch, or table layout selection;
- code/data placement and branch relaxation;
- CPU multiversioning; and
- optional representative-input PGO.

The re2c model of generated conditional control flow is an important ceiling
([manual](https://re2c.org/manual/manual_c.html)), particularly for lexers.
FRE additionally needs ordinary search, both compatibility-profile families, bounded
construction, and stable embedding.

The in-tree AOT planner and direct emitters obey deterministic counters. A
hypothetical future experiment with a general compiler such as LLVM would have
to run as an OS-limited worker with explicit memory, CPU, output, and
cancellation limits; its failure could not invalidate the already constructed
bounded plan. That experiment is not implemented and is not part of FRE's
current JIT or AOT compiler architecture. Wall time would be an outer watchdog,
never the resource proof for an internal pass.

`fre-build` should consume a manifest and produce a normal object/static
library, immutable data, a small metadata record, Rust bindings, and a C
header. Artifacts record semantic/profile version, Unicode version, source and
option hash, target/CPU features, compiler schema, resource certificate, and
fallback plan. The platform loader handles trusted native objects and code
signing.

Portable cache artifacts contain validated semantic/plan IR and tables—not raw
process-native code—and regenerate code locally. Native artifacts are accepted
only through an authenticated build/link path. When AOT optimization fuel is
exhausted, emit the portable bounded plan or return a requested
`OptimizationRequired` error; never continue exponential construction.

## 8. Rust, C/C++, runtime, and JIT security

### 8.1 Rust surface

The high-level facade should feel familiar:

```rust
let re = fre::Regex::new(r"(?P<key>AKIA[0-9A-Z]{16})")?; // RustText
let m = re.find(haystack);

let bre = fre::bytes::Regex::new(r"(?-u:\xFF+)")?;       // RustBytes
let r2 = fre::re2::RegexBuilder::new(pattern)
    .encoding(fre::re2::Encoding::Latin1)
    .longest_match(true)
    .build()?;

let mut scratch = re.create_scratch()?;
let m = re.find_with(&mut scratch, haystack)?;
```

The convenience facade supplies Rust-compatible `is_match`, `find`,
`captures`, iterators, sets, capture-name lookup, replacement, split, and
builders. It may use a bounded thread-local scratch pool. The expert facade
accepts explicit scratch, input spans/anchoring, operation preparation,
cancellation/work quotas, plan inspection, batch/vectored input, and fallible
global/stream searches.

No compatibility label is earned from that summary alone. The API ledger is
normative; “required direct” means the operation receives its own typed plan,
“required emulation” means a facade state machine may call typed plans while
preserving the exact wrapper contract, and “not promised” is an explicit v1
exclusion. These are implementation obligations, not claims that code already
exists:

| Pinned public operation | Planner/output contract | v1 disposition |
|---|---|---|
| Rust/bytes construction and configuration: `Regex::new`, both `RegexBuilder` families, `as_str`, capture-name/count/static-count/location metadata | profile construction and metadata | Required direct or metadata emulation; every builder option participates in the profile/cache key |
| Rust `is_match` | `Exists` | Required direct |
| Rust `is_match_at` | `RangedExists` | Required direct with original context and exact panic boundary |
| Rust `find`, `find_at` | `Span`, `RangedMatch` | Required direct; ranged assertions and boundaries see the original haystack, never a sliced substitute |
| Rust `shortest_match`, `shortest_match_at` | `ShortestEnd`, ranged variant | Required direct; engine-detected end under the documented guarantee, neither necessarily shortest nor earliest, and never assumed equal to `SelectedEnd` |
| Rust `captures`, `captures_at`, `captures_read`, `captures_read_at`, `read_captures_at`, `CaptureLocations`/`locations` | `Captures`, `RangedMatch` | Required direct, including allocation reuse and unset versus empty slots |
| Rust `Match`/`Captures`/subcapture accessors, `extract`, `expand`, and iterators | typed result views | Required facade emulation with identical byte offsets, borrowing, indexing and panic behavior |
| Rust `find_iter`, `captures_iter` | exact aggregate iterator | Required but blocked on section 3.3; repeated search is reference-only |
| Rust `replace`/`replacen`/`replace_all` and closure replacers | `ReplaceFirst`, `ReplaceN`, aggregate replacement | Required emulation with Rust expansion/progress; `ReplaceN(n=1)` is distinct from all |
| Rust `split`, `splitn` | `Split`, `SplitN` | Required emulation over the exact aggregate sequence |
| Rust/bytes `RegexSet::is_match`, `is_match_at` | `Exists`, `RangedExists` over a set | Required direct; may stop after any member is proved and preserves original ranged context |
| Rust/bytes `RegexSet::matches`, `matches_at`, `matches_read_at`, `read_matches_at`, builders/`empty`, patterns/length, and `SetMatches` queries/iteration | `PatternMembership`, `RangedMembership` and result views | Required direct/facade emulation; enumerate every matching ID in declaration order and preserve original ranged context |
| Rust utility `escape` and documented error/display types | syntax utility/diagnostic | Required emulation for a crate-level compatibility claim |
| Rebar ordered `build_many` search | `Span` or `PatternCaptures` over an ordered union | Required only in the benchmark adapter; it is not `RegexSet` |
| RE2 constructors, complete `Options`, `ok`/error fields, pattern/options and capture-name/count metadata | RE2 profile construction/metadata | Required direct or metadata emulation |
| RE2 `PartialMatch`, `FullMatch` | unanchored/full `Span`/`Captures` | Required direct |
| RE2 `PartialMatchN`, `FullMatchN` and typed `Arg` extraction | `Span`/`Captures` plus conversion | Required emulation in the C++ wrapper, including conversion failure behavior |
| RE2 ranged `Match` with three anchors | `RangedMatch` | Required direct with original range and anchor context |
| RE2 `Consume[N]`, `FindAndConsume[N]` | consume-wrapper state machine | Required emulation; preserve typed extraction, zero-byte empty behavior and remaining-view anchors |
| RE2 `Rewrite`, `Replace`, `GlobalReplace`, `Extract`, `CheckRewriteString`, `MaxSubmatch` | profile-specific replacement/extraction | Required emulation; RE2 rewrite grammar and operation-specific progress only |
| RE2 `QuoteMeta` | syntax utility | Required emulation |
| RE2 `Set(anchor)` construction/add/compile/match | profile-specific `PatternMembership` | Required direct for successful semantics; exact runtime DFA-OOM is delegated or explicitly not promised under `StrictAdmission` |
| RE2 representation access/diagnostics `Regexp()`, `ProgramSize`, reverse size/fanout and `PossibleMatchRange` | upstream-representation introspection | Not promised by v1; FRE cannot expose RE2's raw internal `re2::Regexp*`, and the RE2-style facade is not advertised as source-API compatible for these methods |
| Backreferences, arbitrary lookaround, callbacks in generated code | none | Not promised/rejected, matching the relevant upstream syntax or the JIT trust boundary |

The generated conformance ledger marks each pinned method `implemented`,
`emulated`, or `not promised` for the actual build. A release cannot call a
facade compatible while any required row remains merely planned.

`SearchSession`/`StreamSession` make output backpressure resumable. An
`OutputFull` return retains the exact next event/match and decoder/capture
state; resumption neither duplicates nor skips output. Callbacks run outside
internal locks and have specified reentrancy/cancellation behavior. A two-pass
global iterator may need to finish or spill its first pass before yielding,
which is exposed as latency rather than disguised as online streaming.

Compiled programs are immutable, `Send + Sync`, and contain no per-search
lock. Scratch is reusable, non-reentrant, and not `Sync`. Prepared searches do
not allocate except for caller-requested owned output or documented global
history. Once the section 3.3 gate passes, the final iterator must remain
ergonomically compatible; the separately named lower-level iterator exposes
explicit history/cancellation errors. Before that gate, only the quadratic
reference iterator and experimental fallible batch contract exist.

`plan().explain()` reports profile, output contracts, chosen/fallback plans,
complexity, scratch/data/code estimates, CPU requirements, JIT state, and cost
model version. It is diagnostic/versioned, not a promise that internal types
never change.

### 8.2 Stable C ABI and C++ wrapper

Use opaque handles and versioned symbols. Every extensible input struct begins
with `struct_size`, `abi_version`, and reserved-zero fields. Strings are
pointer-plus-length, spans use fixed-width integers, unmatched captures have a
defined sentinel, and no Rust layout or unwind crosses the boundary.

```c
fre_status_t fre_v1_context_create(
    const fre_context_options_v1*, fre_context_t**, fre_error_v1*);
fre_status_t fre_v1_compile(
    fre_context_t*, const uint8_t *pattern, uint64_t length,
    const fre_compile_options_v1*, fre_regex_t**, fre_error_v1*);
fre_status_t fre_v1_scratch_create(
    const fre_regex_t*, fre_scratch_t**, fre_error_v1*);
fre_status_t fre_v1_scratch_layout(
    const fre_regex_t*, fre_operation_v1, uint64_t max_haystack,
    const fre_search_limits_v1*, fre_scratch_layout_v1*, fre_error_v1*);
fre_status_t fre_v1_find(
    const fre_regex_t*, fre_scratch_t*, const fre_input_v1*, fre_match_v1*);
fre_status_t fre_v1_find_all_bounded(
    const fre_regex_t*, fre_scratch_t*, const fre_input_v1*,
    const fre_search_limits_v1*, fre_match_callback_v1, void *user);
void fre_v1_regex_retain(fre_regex_t*);
void fre_v1_regex_release(fre_regex_t*);
void fre_v1_scratch_destroy(fre_scratch_t*);
void fre_v1_context_destroy(fre_context_t*);
```

Scratch negotiation is operation-specific: ordinary `find`, captures,
set/events, streaming, and a global iterator can have radically different
layouts, and the latter may depend on a declared maximum haystack or spill
policy. A small core scratch always supports the portable single-search floor;
the API never pretends one size estimate covers a 64 MiB iterator log and a
small one-pass match equally.

The context installs general allocators, executable-memory callbacks, code and
scratch quotas, optional compilation executor, logging/metrics, cancellation,
and spill storage before objects are created. Callback reentrancy, ownership,
error lifetime, allocator provenance, and “never call user code under an
internal lock” are specified. Generated code never calls an arbitrary user
callback directly: it fills a bounded result ring and returns `OutputFull` or
another status to the checked runtime, which invokes the callback between
kernel entries and resumes from the exact continuation. This keeps foreign
unwind, reentrancy, and callback latency outside the native-code trust
boundary. A header-only C++ layer adds RAII,
`string_view`/`span`, and RE2-style convenience without making C++ the ABI.

There are no hidden compiler threads: automatic background promotion exists
only when the embedder supplies a compilation executor/scheduler. Otherwise
promotion is explicit or runs synchronously under the documented policy.

FRE never opens an implicit temporary file for an iterator log. A spill-capable
embedder supplies a quota-bounded, sequential-write/reverse-read store and
owns its confidentiality, cancellation, crash cleanup, and lifetime policy;
otherwise the plan is in-memory only. Required capacity is preflighted before
a fallible batch operation publishes output.

### 8.3 Executable memory and hostile patterns

Patterns can influence native control flow, so “written in Rust” does not make
the JIT safe. Every executable extent follows one irreversible publication
transaction:

```text
WritableUnpublished -> Validated -> SealedExecutable -> Retired
```

It never moves backward, and published bytes are never live-patched. Retirement
waits for reference/epoch reclamation before an extent can be unmapped or a
fresh generation can reuse its storage. An embedder executable-memory callback
is part of the trusted computing base: it must attest that no concurrent
writable alias exists, enforce the transition and cache-maintenance rules, and
reject writes overlapping published extents. FRE disables JIT if platform
conformance probes or the host callback cannot establish that contract.
Required controls are:

- no thread may write and execute a slab concurrently: conventional hosts use
  RW→RX, while the Apple exception uses the allocator protocol below;
- immutable reference-counted slabs and safe epoch/ownership-based eviction;
- checked trampoline plus independent Kernel-IR and emitted-code validation;
- literal/pattern bytes remain read-only data, never copied as opcodes;
- hard per-pattern, context, tenant, compiler-queue, and scratch quotas;
- register/stack/landing-pad validation, no unwind from a generated kernel;
- guard-page, encoder, relocation, concurrent-eviction, and allocation-failure
  fuzzing; and
- an optional brokered compiler as defense in depth, never a substitute for
  in-process validation.

Decoding a generated instruction stream can reject instructions, targets, or
memory forms outside the restricted backend contract, but it cannot prove that
an incorrect emitter implemented the intended Kernel IR. The emitter remains
in the TCB; randomized interpreter differentials, template proofs, encoder
properties, and real-ISA guard-page tests reduce that risk rather than being
described as formal equivalence.

Linux/BSD use RW→RX and the platform `__clear_cache`/equivalent sequence;
AArch64 publication must perform the required data-cache clean,
instruction-cache invalidation, and barriers before the release-store of the
entry. On supported hardened macOS configurations, `AppleJitAllocator` uses
one host-created `MAP_JIT` arena with page-granular extents in states
`unpublished-writable -> validated -> published-executable -> retired`.
Published extents cannot be written or reused until epoch reclamation. Its
platform matrix distinguishes the sanctioned callback allow-list mode, the
per-thread write-protect-toggle mode, and no-JIT; entitlement or policy cannot
be granted by the library, so any missing prerequisite selects K0. Other Apple
OS/version combinations are admitted only after a named conformance probe,
not by an “Apple silicon” assumption. Windows probes dynamic-code policy, uses
`VirtualProtect` plus `FlushInstructionCache`, makes CFG pages
invalid-by-default and registers only valid entries. Generated
kernels are leaf functions where possible; any Windows x64 kernel with a frame
or helper call registers correct dynamic unwind metadata, while helpers return
status and no Rust panic/unwind crosses the frame. Emit CET/IBT or
BTI landing sequences and arm64e ABI pointer-authentication prologues where
required. Register allocation is ABI-specific: in particular, a backend cannot
treat every vector register as caller-clobbered on Windows x64 or ARM64, and
must honor their callee-saved vector portions plus x64 shadow-space rules. If
policy forbids code generation,
`PreferJit` falls back identically, `ForbidJit` never requests executable
memory, and `RequireJit` fails explicitly.

The host-facing constraints come from Apple's
[JIT guidance](https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon)
and Microsoft's contracts for
[`VirtualProtect`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
and
[`SetProcessValidCallTargets`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessvalidcalltargets),
not from assumptions made by the Rust wrapper.

After a multithreaded POSIX `fork`, the child may call no FRE API—including
K0—before `exec`; regex search is not async-signal-safe, and quiescing FRE alone
does not change that rule. Continued matching is supported only when the
process was genuinely single-threaded at `fork`, or by a separately named
platform extension whose host guarantees are documented and tested. In that
case inherited JIT compilation, cache reclamation and cache mutation still
remain disabled until explicit runtime reinitialization, and FRE never tries
to repair mutexes whose owner vanished.

## 9. Rebar coverage plan

Coverage and comparison are generated from a job ledger, not inferred from an
engine label. Every expanded job is keyed by:

```text
(definition and case,
 transformed pattern list and haystack identity,
 runner revision,
 constructor + configuration + limits,
 operation wrapper + empty/progress rule,
 output reducer,
 timed boundary,
 warmup and cache state)
```

The ledger records acceptance, exact semantic profile, output capability,
baseline API and a written comparability reason. In particular, Rebar's Rust
headline is named `RebarRustMetaBytes100MBuildMany`: it uses
`regex_automata::meta::Regex`, byte-oriented syntax/empty handling with
`utf8_empty(false)`, a 100 MiB NFA limit and `build_many`. Its multi-pattern
jobs are an `OrderedUnion`, not `RegexSet`. The adapter's RE2 loop is named
`RebarRe2MatchLoopByteAdvance`, including its actual options and one-byte
adjacent-empty progress. Separate runners exercise default public `RustText`,
`RustBytes`, and each RE2 public operation. Only manifest-approved pairs with
the same complete key enter a strict speed gate; an adapter win is never
credited as public-facade superiority.

The pinned inventory has 360 distinct current Rust-runner names:

| Family | Cases | Primary obligation |
|---|---:|---|
| imported | 107 | Broad legacy/real patterns, regex-redux, anchors, near misses, URI/email/IP, Leipzig/Sherlock. |
| curated | 52 | Fourteen focused groups, detailed below. |
| test | 50 | Normative greediness, leftmost-first, empty, anchor, dot/newline, Unicode and invalid-byte semantics. |
| opt | 35 | Literal, one-pass, sparse/bit-state, fixed length, prefilter, reverse-inner/suffix and fallback mechanics. |
| wild | 25 | Large real parsers, URLs, bibliography, graphemes, Veryl, Ruff, RustSec. |
| unicode | 22 | Every scalar, properties, huge classes/repeats, boundaries and overlapping words. |
| reported | 22 | User-reported compile/search cliffs, large repetitions/classes/keywords. |
| hyperscan | 15 | SOM/end-only, literals, fixed length, suffix/inner, Unicode; compare exact model outputs only. |
| aho-corasick | 13 | NFA/DFA AC, dictionaries, keywords, Teddy and case-insensitive variants. |
| dictionary | 7 | Tiny/full/minimum-length databases and compilation. |
| slow | 4 | Known pattern- and haystack-quadratic ordinary iteration. |
| folly | 4 | Frequent misleading candidates and verifier/reverse rescans. |
| grep | 3 | Per-line overhead, CRLF stripping, line-local anchors/context and words. |
| captures | 1 | Match-dense 26-way capture participation. |

Across 848 current jobs, the models include `count`, `count-spans`, `compile`,
`grep`, `grep-captures`, `count-captures`, and `regex-redux`. The FRE runner must implement
each model exactly. It may use an end-only count entry point because the model
allows it; it may not turn per-line grep into a whole-buffer search unless it
proves identical line context and includes the same line work.

| Rebar model | FRE contract |
|---|---|
| `count` | Count ordinary nonoverlapping results; erase start/captures only when the model permits. |
| `count-spans` | Timed result is only the sum of selected group-0 byte/code-unit lengths. A plan must recover enough start/end information to add the correct lengths, but must not be charged for materializing or hashing full tuples. |
| `count-captures` | Timed result is the number of participating groups, including group 0; these definitions guarantee nonempty matches. Offsets and unmatched/empty distinctions remain in the untimed conformance trace, not the timed reducer. |
| `compile` | Construct exactly the artifact named by the job ledger with cross-iteration caches disabled. Full constructors are search-ready; stage microbenchmarks stop at their named AST/HIR/NFA artifact. |
| `grep` | Use Rebar's line splitting/terminator contract and line-local context exactly. |
| `grep-captures` | Under Rebar's timed line splitting and CR stripping, sum participating groups including group 0. Exact capture offsets are checked only by the untimed trace; a fused public line API is a separate scoreboard. |
| `regex-redux` | With Unicode disabled, serially perform 15 fresh regex constructions, repeated suffix-slice `find` loops, literal replacement insertion with string allocation/copying, nine-count formatting, and output verification inside each timed sample, byte-for-byte with Rebar's shared helper. This is not replacement-template expansion. |

Compile results use separate artifact scoreboards: `ParseAST(pattern)`,
`TranslateHIR(prebuilt_ast)`, `CompileNFA(prebuilt_hir)`, full meta-engine
construction, full public-facade construction, Hyperscan database construction
without scratch, and AC literal-set construction. Stage inputs are prepared
outside timing exactly as their runner does, and downstream validation remains
untimed. Forced AC/DFA/Pike/backtracker executor rows are also labeled prepared
executor microbenchmarks; none is aggregated into facade-constructor
leadership.

The `wild/parol-veryl` multi-pattern capture rows require
`PatternCaptures`: the selected ordered-union pattern ID plus that pattern's
capture layout. Membership, group-0-only span, or captures for a synthetic
outer alternation are not substitutable.

### 9.1 All curated groups

| Group | Required mechanism and decision |
|---|---|
| 01 literal | Direct single/substring kernels, enumerated bounded folds, safe tails. Aim for within measurement noise of specialized primitives; do not force unique JIT code. |
| 02 literal alternation | Teddy/FDR/AC/trie bakeoff preserving ordered ordinary alternatives. |
| 03 ASCII/Unicode dates | Fixed-width/one-pass/TDFA candidates; symbolic Unicode construction and compile latency are central. |
| 04 Ruff `noqa` | Certified reverse-inner/prefix scan plus direct tags; false-candidate work uses the global ledger. |
| 05 Veryl | Ordinary single-capture and multi-pattern Rebar contracts remain ordinary. A true maximal-munch AOT lexer is an additional workload, never a substitution. |
| 06 Cloudflare ReDoS | Bounded DFA/lazy-DFA/NFA with no depth-first catastrophic path; include honest tiny-input timing. |
| 07 UnicodeData | Match-dense direct one-pass/TDFA captures; avoid locate-and-replay when it doubles every line. |
| 08 English/Russian words | ASCII vector loop, Unicode scalar side exits, direct word-boundary state and run specialization. |
| 09 AWS keys | Literal/prefix candidates, fixed-offset captures where proved, and very cheap construction. Reproduce Rebar's line model exactly: its cross-line “full” expression can yield zero when evaluated per line. Whole-buffer/cross-line secret scanning is a separate production row. |
| 10 bounded repeats | Fixed windows and safe counters; adversarial counter-product tests; never blind expansion. |
| 11 unstructured-to-JSON | Direct capture go/no-go: one-pass, bounded TDFA, then native tagged NFA. PCRE2 JIT is the speed ceiling. |
| 12 dictionary | Ordered ordinary union uses literal-set kernels; true database/event mode is measured separately against Hyperscan. |
| 13 Nosey Parker | Highest-value Rose-like mandatory-literal/role-graph prototype, with literal-free and all-trigger adversaries. Preserve the semantic split: a pinned headline definition expects 241 Hyperscan end events versus 55 ordinary Rust matches, so those rows cannot share a speed claim. |
| 14 quadratic | Exact global-iterator correctness and `O(PN)` work gate; an earliest/event answer is disallowed. |

All 360 current Rust-runner names run before qualification, as does every
additional definition/engine-specific variant in the 68-file corpus whose
operation is accepted by a FRE profile. The definition files—not one runner's
participation list—are the coverage universe. Unsupported results are permitted
only where the selected upstream profile truly rejects the syntax/operation,
and that exclusion is published rather than omitted from an aggregate.
Failures count as failures, not missing samples.

Rebar engine labels are not compatibility oracles: some runners use lower-level
builders and non-default limits/UTF-8 settings. Every FRE job records its
actual syntax profile and output tuple, while upstream public-API conformance
is tested independently of Rebar.

The qualification configuration also publishes every pattern/source/HIR,
state, database-count, data, code, and scratch limit. Those limits must admit
the corpus's full English dictionary (1,185,564 bytes, about 1.13 MiB, and
123,115 entries at the
pinned revision) and giant-pattern cases; a default that quietly
excludes a definition because it exceeds a convenient 1 MiB or 100,000-pattern
threshold is a failed case, not a safety success. Smaller embedder defaults may
exist only as separately named policies.

## 10. Workloads Rebar does not cover well

Create a companion suite with correctness digests, lifecycle measurements,
resident/code/scratch memory, and work counters:

| Dimension | Scenarios |
|---|---|
| Input reuse | Warm identical input, changing buffers with identical distribution, adversarial distribution shift, randomized addresses, cold data and I-cache. |
| Lifetime | One-shot tiny patterns; reuse counts `1,2,4,…`; long-lived hot patterns; eager, lazy, background and AOT readiness. |
| Fleets | 1, 100, 10,000 and 1,000,000 compiled patterns with uniform and Zipf access, cache eviction, plugin unload/reload and tenant quotas. |
| Pattern databases | 10–1,000,000 literals/regexes, shared prefixes, no mandatory literals, all triggers firing, sparse and output-dense matches, incremental replacement. |
| Short-input batch | Thousands of independent strings/packets/fields so SIMD can operate across haystacks. |
| Streaming/vectored | Every short chunk partition, randomized large chunks, ropes/iovecs, cross-boundary literals/UTF-8/captures, finite and infinite decision horizons. |
| API work | `is_match`, anchored/full match, capture-name lookup, replacement expansion, split/splitn, tokenization, routing, adjacent matches, and iterators consumed with `take(1)`, `take(2)`, early drop, or to completion. |
| Length/offset boundaries | Empty/tiny inputs, page and SIMD-tail edges, and logical offsets around 2 GiB, 4 GiB and the `u64`/host-`usize` conversion boundary, using sparse/mapped fixtures where full allocation is impractical. |
| Text/binary | Every Unicode scalar, multiple Unicode versions, case folds and boundaries; all byte values and generated invalid UTF-8; no normalization assumption. |
| Adversarial | Determinization/tag-history/counter bombs, dense false literals, reverse overlap, lazy-cache churn, huge captures, empty/nullable loops and cancellation. |
| Production | Rotating logs, source search, IDS databases/packet traces, language-server lexing, secrets scanning, mmap/NUMA, 1–64 threads. |
| Deployment | Linux/macOS/Windows; x86-64/AArch64 plus 32-bit length/offset rejection paths; heterogeneous cores; no-JIT policy; cross-compiled AOT; fork/exec; alloc failure; sandbox callbacks; code signing; serialization invalidation; compiler/cache stampedes. |

No-match and match-dense inputs are separate axes. Include throughput, tail
latency, energy/frequency where practical, branches, instructions, L1I/LLC
misses, and compiler queue delay.

## 11. Correctness, testability, and measurement

### 11.1 Layer-by-layer tests

1. Import the complete pinned Rust-regex and RE2 parse/search corpora under
   their profiles, including accepted/rejected patterns and error categories.
2. Exhaustively generate small ASTs and haystacks over tiny Unicode/byte
   alphabets. Compare full match sequences, pattern IDs, every capture slot,
   empty suppression, replacement/split, and compile errors.
   Include repeated-participation regressions such as `(a|(b))+` on `ba`:
   capture slots update when their tag path is traversed, and a later
   iteration that does not traverse a nested capture must not be assumed to
   clear it. Test unmatched versus participating-empty slots separately under
   each profile. Under RE2, include `(^|a)+` on `a`: priority-bearing
   alternation instructions inside an epsilon cycle cannot be coalesced away
   merely because the recognized language is unchanged; doing so changes the
   captured empty-versus-nonempty path. Also pin `(a*)*` on `x`,
   `(?:A+){1000}|`, and `.abb|b`/reverse-overlap cases for profile capture,
   repeat/empty, and exact-start-recovery failures.

   The canonical corpus stores complete records rather than test names. For
   example (byte offsets shown):

   | Pattern/input | Profile | Expected `[group0, group1, ...]` |
   |---|---|---|
   | `(a|(b))+` / `ba` | RustText, RustBytes, default RE2 | `[[0,2), [1,2), [0,1)]`; group 2 retains its last participating `b` |
   | `(a*)*` / `x` | RustText, RustBytes | `[[0,0), [0,0)]`; the inner group participates empty |
   | `(a*)*` / `x` | default RE2 | `[[0,0), UNSET]` |
   | `(a)?(b*)` / empty | all three ordinary profiles | `[[0,0), UNSET, [0,0)]`; unmatched and participating-empty are distinct |

   RE2 option variants receive their own records whenever selection changes;
   generated cases never copy an expected capture vector across profiles merely
   because the language is the same.
3. Run at least million-scale generated/fuzz cases per profile and continuous
   fuzzing of parsers, rewrites, counters, planners and executors.
4. Force every production executor rather than trusting planner reachability:
   reference ↔ portable NFA ↔ each literal/one-pass/DFA/TDFA candidate ↔ Kernel
   IR interpreter ↔ x64 ↔ AArch64 ↔ AOT.
5. Treat planner transformations as proof obligations. Property-test ordered
   tries/factoring, capture erasure/replay, class lowering, reverse scans and
   fallback continuation.
6. Validate each ISA encoder with disassembly, randomized KIR, an independent
   interpreter, register canaries, ABI/unwind checks, guard pages, tails,
   feature masking, QEMU where useful and real hardware.
7. Inject failure into every allocation/publication step; fuzz concurrent JIT,
   eviction, scratch misuse, cancellation, callback termination and malformed
   portable artifacts.
8. Run every untrusted graph traversal on tiny native thread stacks with long
   concatenations and epsilon chains, deep but admitted CFGs, malformed cyclic
   artifacts, and cancellation at every work-stack pop. A stack overflow is a
   correctness/security failure even if the fuel counter would eventually end.
9. Assert work counters for `slow`, Folly, reverse-inner/suffix, counter
   products, dense triggers and cache churn in three independent scaling
   series: fixed `P` while doubling `N` (expected product-work ratio about 2),
   fixed `N` while doubling `P` (about 2), and both doubled (about 4 for
   `O(PN)`). Report raw charged counters and output work separately from wall
   throughput; do not apply a 2× threshold to Rebar's joint-scaling witness.

`fre-debug` prints AST, semantic HIR, ordered/tagged NFA, analysis facts,
candidate plans and rejection reasons, Kernel IR, machine disassembly, resource
certificate and per-path work counters. This is the native-code analogue of
`regex-cli` and makes a benchmark regression traceable to a layer.

### 11.2 Benchmark discipline

- Build all engines comparably and publish commits, commands, raw samples and
  failures.
- Validate outputs in a separate untimed conformance run and use each model's
  exact opaque reducer inside timing to prevent optimizer deletion.
- Rebar's published checksum may collapse different event streams to one
  count/sum. An untimed shadow conformance adapter hashes the complete canonical
  stream of pattern IDs, spans, participation bits, and captures before any two
  rows are declared semantically comparable. That tracing work is never
  charged only to FRE or inserted into `count-spans`/capture timing.
- Interleave paired competitors to reduce drift; pin cores and record CPU
  state. Treat repeated timings of one case as technical replicates, not new
  workload samples. Bootstrap paired workload/application clusters, use
  simultaneous intervals for the many per-case strict comparisons, publish a
  power/noise analysis, and declare a practical noise floor.
- Show individual cases, operation/family aggregates, and memory/code metrics;
  report both raw emitted bytes and page-rounded live RX bytes, and do not rely
  on one geometric mean.
- Freeze planner thresholds before holdout qualification. Later Rebar/user
  cases are forward tests, not new training data disguised as validation.
- Measure cache-off repeated compilation, process-cold start, first-ever JIT,
  cache hit, native-ready, first search and amortized reuse separately.
- The headline `fre/regex` row constructs the full profile-compatible regex
  facade, as the Rust/RE2 facade does. Explicit `Prepared<Exists>` or
  no-capture/set types may erase capabilities, but they appear as separately
  named rows; their cheaper compile cannot be credited to the full object.
- Compare semantics explicitly. PCRE2 JIT, Hyperscan, .NET, and re2c are useful
  ceilings even when they cannot enter the same safety/semantic score.

## 12. Staged program, staffing, and stop conditions

The requested full scope needs roughly 10–12 senior engineers plus dedicated
fuzz/CI-release and security/platform support for 36–48 months. It requires
two-person review coverage for every unsafe emitter, loader and executable-
memory backend. A six-person, 24–30 month team could plausibly deliver only the
ordinary compatible matcher, bounded portable floor and two-ISA runtime-JIT
core; EventDb/Hyperscan competition, exact streaming, AOT objects and a stable
cross-platform ABI would move to later funded milestones.

### Phase 0A: weeks 0–16—semantic and iterator feasibility

Build an immutable per-job benchmark manifest, one restricted-but-growing Rust
profile, a direct AST oracle and K0 floor, then specify and prototype the exact
aggregate iterator with a full-table oracle, lean log and at least one
suffix/checkpoint/history alternative. Exhaustive differentials, checked
resource formulas and the three scaling series are the deliverables. These are
spikes using upstream adapters, not finished parsers or production emitters.

Stop or narrow the final API/claim if no iterator candidate achieves the exact
sequence and promised bound with acceptable memory and latency.

### Phase 0B: weeks 16–32—capture and first-JIT economics

Run one-pass, TDFA/replay, fixed-slot and persistent-history capture bakeoffs on
UnicodeData, unstructured logs, Veryl and adversarial cases. Implement a
minimal Kernel IR/interpreter plus one literal/fixed-window/small-one-pass
x86-64 shape and compare K0, template/custom and Cranelift economics. Add RE2
option/admission adapters and semantic spikes, but do not pretend the full
surface is complete. Stop JIT-primary positioning if pattern-specific code has
no useful payback region.

### Phase 1: months 6–14—portable compatible core

Finish both profile surfaces, the production NFA floor, symbolic limits,
operation contracts, scratch/context model, work ledger, exhaustive/fuzz
harness, and Rebar runner. This is a portable-core milestone, not the final
compatible facade while the aggregate iterator remains gated; it is correct
and bounded for the operations it exposes before it is called fast.

### Phase 2: months 10–20—native specialization

Ship literal/set and fixed-window kernels, one-pass captures, bounded lazy DFA,
Kernel-IR verifier, W^X runtime, two ISA backends and no-JIT parity. Establish
measured break-even dispatch and code-cache/fleet behavior.

### Phase 3: months 16–28—hard cases

Integrate the winning global iterator and capture strategies, Unicode-boundary
fast paths, counters, reverse/filter continuation, replacement/split, and
production lifecycle APIs. The safe ordinary benchmark gate becomes possible
here.

### Phase 4: months 24–36—databases and streaming

Implement Rust/RE2 set, event, ordered-union, and lexer separation,
Teddy/FDR/AC and Rose-like
decomposition, exact and event streaming, vectored/rope input and batch APIs.
Do not claim Hyperscan competition unless the event gate passes.

### Phase 5: months 30–48—AOT and hardening

Add high-fuel TDFA/DFA/layout optimization, object artifacts and multiversion,
stable C/C++ ABI, sandbox/JIT-policy integrations, cross-platform/fork/code
cache hardening, long-running fuzzing and release qualification.

At every phase, delete or demote a specialized engine whose holdout benefit
does not pay for code, compile time, memory and maintenance. A portfolio is a
means to win measured regions, not a license for permanent complexity.

## 13. Principal failure modes and rejected shortcuts

1. The exact global iterator may need too much history or fail subtle capture
   equivalence. If so, the strongest complexity requirement is unmet.
2. TDFA/tag histories can explode; the general capture floor may remain far
   behind friendly depth-first PCRE2 JIT execution.
3. Secure publication makes cold JIT slower than non-JIT construction. Shared
   kernels and AOT reduce but cannot erase that fact.
4. Rust regex is already a mature portfolio. Native code that only removes an
   opcode dispatch may not produce material end-to-end wins.
5. Hyperscan's largest advantages rely on multi-pattern event semantics; exact
   ordinary semantics can preclude those wins.
6. Unicode versions, word boundaries, invalid bytes, capture resets and empty
   iteration can invalidate apparently harmless rewrites.
7. Large fleets turn unique code into an I-cache and memory liability.
8. Two production-quality ISA backends, AOT, a stable ABI and two compatibility
   surfaces are a multi-year maintenance commitment.

Rejected shortcuts include unbounded full determinization, catastrophic
backtracking, comparing earliest events with greedy ordinary matches, silently
falling back to ASCII, per-state code for huge machines, filter/verifier
restarts without a global ledger, compile-cache gaming, JITing trivial patterns
solely to satisfy a label, accepting unauthenticated native cache code, and
declaring “strictly faster” from one aggregate on one machine.

## 14. Review traceability

The evidence baseline, exact runner protocol, and requirement mapping are in
[EVIDENCE.md](research/EVIDENCE.md), [RUN_METHOD.md](research/RUN_METHOD.md),
and [REQUIREMENTS_MATRIX.md](research/REQUIREMENTS_MATRIX.md). The study uses
eleven independent first-round reports, paired constructive/contrarian reviews,
and a second independent paired adjudication. Raw reports and logs are under
`research/personas/round1`, `round2`, and `round3`; the integrated decision log
is [PERSONA_SYNTHESIS.md](research/PERSONA_SYNTHESIS.md).

Two clean final audits produced the actionable correction lists in
`research/audit/architecture.md` and `red_team.md`. A clean full correction
verifier then found 19 resolved findings and one partial API-ledger issue; two
focused rechecks retained chronologically under `research/audit/` drove that
last item to `STATUS: RESOLVED`. Thus the design-stage brief has no outstanding
audit blocker/high finding, while its algorithmic and performance gates remain
explicitly unproved.

The first reviews consistently preserve the bounded portfolio, semantic-mode
separation, work ledger, restrained SIMD scope, and explicit streaming limits.
They consistently reject an undifferentiated compatibility dialect, an
unproved global iterator, JIT-at-any-cost, a production NFA serving as its own
oracle, and semantic substitutions in Rebar. Final decisions are based on
source evidence or experiments, not vote count.

One disagreement is intentionally not averaged away. The independent
synthesis recommends keeping Rust's quadratic compatible iterator and exposing
linear enumeration only as a fallible batch operation. That is a coherent
Stage-0/reference architecture, but it does not satisfy this task's explicit
no-worst-case-blowup requirement. FRE may retain repeated search as an oracle
during prototyping; it may not ship the final compatibility facade or claim
completion until one exact bounded aggregate iterator candidate passes the
gate in section 3.3. If none does, the project must narrow the product/claim.
