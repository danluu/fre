# Proof and resource model

## Selected-span theorem

Let `C` be a non-empty byte set and `L` a non-empty literal. The source
pattern is `C+L` with greedy `+`, ordered leftmost-first search, and optional
absolute anchors. Admission proves `L[0]` is not in `C` and `L` is unbordered.

An unbordered word cannot occur at overlapping offsets: an overlap would make
the overlapped prefix equal a proper suffix, which is a border. Therefore the
non-overlapping `memmem::Finder::find_iter` enumerates every occurrence of
`L` in increasing order.

For a candidate at `p`, `L[0]` is a non-`C` barrier. A match ending at that
candidate exists exactly when the byte before `p` is in `C`; its start is the
beginning of the maximal `C` run immediately preceding `p`, truncated at the
allowed window start. The split is unique because `C+` cannot consume
`L[0]`. Greediness therefore selects that same split.

For two increasing candidates, the earlier candidate's first byte is a
non-`C` barrier. The later candidate's backward scan cannot cross it. Thus
backward confirmation intervals are disjoint, and the first candidate that
passes confirmation and anchors has the earliest possible start. It is the
leftmost-first selected match. Failed candidates also partition away all
starts in the preceding class run, so advancing to the next candidate cannot
skip a match.

Absolute anchors refer to the original haystack. A window only restricts
allowed match spans. If `\A` lies before the window or `\z` lies after it,
the result is immediately impossible.

## Search bound

For window length `N` and suffix length `P > 0`, overlap freedom gives at most
`floor(N/P)` candidates. The iterator makes at most one additional exhaustion
call. The preflight certificate charges:

```
candidate_upper = floor(N / P)
finder_calls_upper = candidate_upper + 1
finder_work_upper = N + finder_calls_upper * P
backward_work_upper = N
structural_work_upper = 6 * candidate_upper + 2
total = finder_work_upper + backward_work_upper + structural_work_upper
```

The `P` charge on every finder call explicitly covers repeated invocation
setup instead of assuming it is free. The searched portions plus boundary
charges are covered by the `N` term. Since candidates do not overlap,
`candidate_upper * P <= N`; the complete certificate is linear in `N + P`.
Backward bytes are counted at runtime and are at most `N` by the barrier
argument. Search allocates no scratch.

All additions, multiplications, divisions and offset conversions used in
admission/accounting are checked. Candidate and work limits are checked before
the finder runs. Accounting uses logical payload bytes; allocator metadata and
allocator size-class rounding are outside this portable contract.

## Construction bound

The longest proper border is computed with a KMP prefix function in linear
time. The conservative build certificate is `12P + 32` work units. Logical
scratch is `P * size_of::<usize>()`; persistent bytes are the Rust plan object
plus `P` owned suffix bytes; peak is their checked sum. Every quantity has an
independent caller cap and the prefix vector uses fallible reservation.

The plan identity is
`required-literal.class-plus-unbordered-suffix.v1`. Any relaxation requires a
new proof/identity, differential corpus and bound audit.
