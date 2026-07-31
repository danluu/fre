//! Deterministic Count-v2 adversaries for a future timing harness.
//!
//! Fixture construction belongs outside the timed region. Pair candidates
//! occupy every other start (eight lanes per full SIMD block); triple
//! candidates occupy every third start (five or six lanes). The pair-dense
//! input fails the third selected byte; the triple-dense input fails the
//! fourth.

pub(crate) const LITERAL: &[u8] = b"0123456789abcdef";
pub(crate) const FILTER_OFFSETS: [u8; 4] = [7, 6, 8, 5];
pub(crate) const HAYSTACK_BYTES: usize = 64 * 1024;
pub(crate) const PAIR_INTENTIONAL_HITS: usize = HAYSTACK_BYTES / 2;
pub(crate) const TRIPLE_INTENTIONAL_HITS: usize = (HAYSTACK_BYTES + 2) / 3;

#[must_use]
pub(crate) fn pair_dense_absent() -> Vec<u8> {
    dense_absent(2, 2)
}

#[must_use]
pub(crate) fn triple_dense_absent() -> Vec<u8> {
    dense_absent(3, 3)
}

fn dense_absent(matching_filter_bytes: usize, candidate_stride: usize) -> Vec<u8> {
    let mut haystack = vec![b'x'; HAYSTACK_BYTES + LITERAL.len()];
    for start in (0..HAYSTACK_BYTES).step_by(candidate_stride) {
        for offset in FILTER_OFFSETS.iter().copied().take(matching_filter_bytes) {
            haystack[start + usize::from(offset)] = LITERAL[usize::from(offset)];
        }
    }
    haystack
}
