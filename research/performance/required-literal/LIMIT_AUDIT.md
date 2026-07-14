# Limit and accounting audit

## Construction

| resource | checked expression | checked before allocation/work | equality tested |
| --- | --- | --- | --- |
| suffix input | `P` | yes | yes |
| build work | `12P + 32` | yes | yes |
| KMP scratch | `P * size_of::<usize>()` | yes | yes |
| persistent logical bytes | `size_of::<RequiredLiteralPlan>() + P` | yes | yes |
| conservative logical peak | persistent + KMP scratch | yes | yes |

Every expression uses checked arithmetic and fallible integer conversion. The
KMP prefix vector and owned-suffix vector use `try_reserve_exact`; a failure is
typed. The prefix vector is dropped before the owned finder is constructed.
The plan deliberately does not implement `Clone`, because cloning the owned
finder would introduce an unmetered allocation. Allocator metadata and
size-class rounding are explicitly outside the portable logical-byte contract.

The class has a fixed 32-byte normalized bitmap before plan construction, so
class cardinality takes four fixed word counts. Frontend work used to lower a
source character class is not hidden in this kernel's certificate and must
remain charged by the caller's parser/lowerer.

## Search

The window is validated before slicing. Scratch needed is zero and is checked
against the scratch cap. If an absolute anchor makes a window impossible, the
plan reports zero work and preserves the caller's window length in accounting.
Otherwise, candidate count, finder calls, repeated needle terms, backward
terms, structural terms and their total are computed with checked arithmetic
and compared with limits before the first native call.

Actual finder calls, candidates and backward examinations use checked counters.
The exhaustive comparator additionally asserts each actual counter is at most
its preflight bound. Exact-limit success and one-below-limit refusal are tested
for build work, scratch, persistent bytes, peak bytes, search work and candidate
visits. An invalid window is a typed error. Search performs no allocation and
there is no fallback path.

## Native iterator audit

The exact `memchr 2.8.3` pin matters. Its `memmem::FindIter::next` starts at its
saved position and advances by the full non-empty needle length after a match.
V1 proves full suffix occurrences cannot overlap. Consecutive searched
portions therefore partition the window; a suffix-length term is charged for
every possible iterator call, including final exhaustion. The native
implementation's online packed-pair, one-byte, Rabin-Karp and Two-Way paths
return the first occurrence and have their preprocessing retained in the owned
finder. Updating `memchr`, changing iterator advancement, or changing the
suffix admission proof requires a new audit and plan identity.
