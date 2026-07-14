//! Deliberately repeated-search test oracle.

use crate::accounting::{Accounting, RunReport, checked_add, checked_mul, enforce};
use crate::full_dp::{decode, table_index};
use crate::iterate::reserve_output;
use crate::{CompiledRegex, Error, ResourceKind, Span};

impl CompiledRegex {
    /// Run exact repeated search as a test comparator.
    ///
    /// A fresh `Q * U` suffix table is built for every logical `find` call.
    /// Dense output can therefore require `O(Q * U^2)` work. This function is
    /// never called by either candidate executor and is not a production
    /// fallback.
    pub fn find_all_oracle(&self, haystack: &[u8]) -> Result<RunReport, Error> {
        let started = std::time::Instant::now();
        let boundaries = self.boundaries(haystack)?;
        let mut accounting = Accounting {
            program_states: self.insts.len(),
            boundaries,
            ..Accounting::default()
        };
        let maximum_searches = checked_add(
            checked_mul(boundaries, 2, ResourceKind::Work)?,
            1,
            ResourceKind::Work,
        )?;
        let build_work = checked_mul(
            self.maximum_build_work(boundaries)?,
            maximum_searches,
            ResourceKind::Work,
        )?;
        let root_work = checked_mul(boundaries, 2, ResourceKind::Work)?;
        enforce(
            checked_add(build_work, root_work, ResourceKind::Work)?,
            self.limits.max_work,
            ResourceKind::Work,
        )?;
        let (mut matches, output_reserved_bytes) = reserve_output(boundaries, self.limits)?;
        accounting.output_reserved_bytes = output_reserved_bytes;
        let mut cursor = 0_usize;
        let mut previous_end = None;
        while cursor <= haystack.len() {
            let table = self.build_full_table(haystack, &mut accounting)?;
            let mut start = cursor;
            let found = loop {
                if start > haystack.len() {
                    break None;
                }
                accounting.charge_root(self.limits.max_work)?;
                let encoded = table[table_index(start, self.entry, self.insts.len())?];
                if let Some(end) = decode(encoded) {
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
            accounting.emit(self.limits.max_output_matches)?;
            matches.push(found);
            previous_end = Some(found.end);
            cursor = found.end;
        }
        accounting.elapsed = started.elapsed();
        Ok(RunReport {
            matches,
            accounting,
        })
    }
}
