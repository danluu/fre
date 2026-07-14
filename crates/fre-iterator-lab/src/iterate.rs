//! Shared operation-level empty-match suppression.

use crate::accounting::{Accounting, checked_mul, enforce};
use crate::compile::CompileLimits;
use crate::{Error, ResourceKind};

/// Half-open byte span.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Span {
    /// Inclusive byte start.
    pub start: usize,
    /// Exclusive byte end.
    pub end: usize,
}

pub(crate) fn collect_sequence<F>(
    haystack_len: usize,
    limits: CompileLimits,
    accounting: &mut Accounting,
    mut matches: Vec<Span>,
    mut selected_at: F,
) -> Result<Vec<Span>, Error>
where
    F: FnMut(usize, &mut Accounting) -> Result<Option<usize>, Error>,
{
    let mut cursor = 0_usize;
    let mut previous_end = None;
    while cursor <= haystack_len {
        let mut start = cursor;
        let found = loop {
            if start > haystack_len {
                break None;
            }
            accounting.charge_root(limits.max_work)?;
            if let Some(end) = selected_at(start, accounting)? {
                break Some(Span { start, end });
            }
            start = start.saturating_add(1);
        };
        let Some(found) = found else {
            break;
        };
        if found.start == found.end && previous_end == Some(found.start) {
            let Some(next) = found.start.checked_add(1) else {
                break;
            };
            cursor = next;
            continue;
        }
        accounting.emit(limits.max_output_matches)?;
        matches.push(found);
        previous_end = Some(found.end);
        cursor = found.end;
    }
    Ok(matches)
}

pub(crate) fn reserve_output(
    boundaries: usize,
    limits: CompileLimits,
) -> Result<(Vec<Span>, usize), Error> {
    let capacity = boundaries.min(limits.max_output_matches);
    let bytes = checked_mul(
        capacity,
        core::mem::size_of::<Span>(),
        ResourceKind::OutputBytes,
    )?;
    enforce(bytes, limits.max_output_bytes, ResourceKind::OutputBytes)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| Error::AllocationFailed {
            kind: ResourceKind::OutputBytes,
        })?;
    Ok((output, bytes))
}
