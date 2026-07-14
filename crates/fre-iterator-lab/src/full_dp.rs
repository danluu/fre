//! Full suffix/priority table candidate.

use crate::accounting::{Accounting, RunReport, checked_add, checked_mul, enforce};
use crate::compile::{CompiledRegex, Inst};
use crate::iterate::{collect_sequence, reserve_output};
use crate::{Error, ResourceKind};

impl CompiledRegex {
    /// Compute every `(program state, input boundary)` priority result once,
    /// then emit the complete Rust-style non-overlapping sequence.
    ///
    /// For the declared subset, this uses `O(Q * U + Z)` work and `O(Q * U)`
    /// random-access words, where `Q` is [`Self::state_count`], `U` is the
    /// number of input boundaries and `Z` is the number of returned spans.
    pub fn find_all_full_dp(&self, haystack: &[u8]) -> Result<RunReport, Error> {
        let started = std::time::Instant::now();
        let boundaries = self.boundaries(haystack)?;
        let mut accounting = Accounting {
            program_states: self.insts.len(),
            boundaries,
            ..Accounting::default()
        };
        let root_work = checked_mul(boundaries, 2, ResourceKind::Work)?;
        let maximum_work = checked_add(
            self.maximum_build_work(boundaries)?,
            root_work,
            ResourceKind::Work,
        )?;
        enforce(maximum_work, self.limits.max_work, ResourceKind::Work)?;
        let (output, output_reserved_bytes) = reserve_output(boundaries, self.limits)?;
        accounting.output_reserved_bytes = output_reserved_bytes;
        let table = self.build_full_table(haystack, &mut accounting)?;
        let states = self.insts.len();
        let entry = self.entry;
        let matches = collect_sequence(
            haystack.len(),
            self.limits,
            &mut accounting,
            output,
            |start, _| Ok(decode(table[table_index(start, entry, states)?])),
        )?;
        accounting.elapsed = started.elapsed();
        Ok(RunReport {
            matches,
            accounting,
        })
    }

    pub(crate) fn build_full_table(
        &self,
        haystack: &[u8],
        accounting: &mut Accounting,
    ) -> Result<Vec<usize>, Error> {
        let boundaries = self.boundaries(haystack)?;
        let cells = checked_mul(self.insts.len(), boundaries, ResourceKind::TableCells)?;
        enforce(cells, self.limits.max_table_cells, ResourceKind::TableCells)?;
        let bytes = checked_mul(cells, core::mem::size_of::<usize>(), ResourceKind::Bytes)?;
        enforce(
            bytes,
            self.limits.max_random_access_bytes,
            ResourceKind::RandomAccessBytes,
        )?;
        enforce(
            self.maximum_build_work(boundaries)?,
            self.limits.max_work,
            ResourceKind::Work,
        )?;
        accounting.table_cells = accounting.table_cells.max(cells);
        accounting.random_access_peak_bytes = accounting.random_access_peak_bytes.max(bytes);
        accounting.table_builds = checked_add(accounting.table_builds, 1, ResourceKind::Work)?;
        let mut table = Vec::new();
        table
            .try_reserve_exact(cells)
            .map_err(|_| Error::AllocationFailed {
                kind: ResourceKind::RandomAccessBytes,
            })?;
        table.resize(cells, 0_usize);
        let states = self.insts.len();
        for position in (0..boundaries).rev() {
            let row = checked_mul(position, states, ResourceKind::TableCells)?;
            for &pc in &self.epsilon_order {
                accounting.charge_state(self.limits.max_work)?;
                let value = match self.insts[pc] {
                    Inst::Match => encode(position)?,
                    Inst::Byte { expected, next } => {
                        accounting.charge_transition(self.limits.max_work)?;
                        if position < haystack.len()
                            && expected.is_none_or(|byte| byte == haystack[position])
                        {
                            let next_position = checked_add(position, 1, ResourceKind::Boundaries)?;
                            table[table_index(next_position, next, states)?]
                        } else {
                            0
                        }
                    }
                    Inst::AssertStart { next } => {
                        accounting.charge_transition(self.limits.max_work)?;
                        if position == 0 {
                            table[checked_add(row, next, ResourceKind::TableCells)?]
                        } else {
                            0
                        }
                    }
                    Inst::AssertEnd { next } => {
                        accounting.charge_transition(self.limits.max_work)?;
                        if position == haystack.len() {
                            table[checked_add(row, next, ResourceKind::TableCells)?]
                        } else {
                            0
                        }
                    }
                    Inst::Split {
                        preferred,
                        fallback,
                    } => {
                        accounting.charge_transition(self.limits.max_work)?;
                        let selected =
                            table[checked_add(row, preferred, ResourceKind::TableCells)?];
                        if selected != 0 {
                            selected
                        } else {
                            accounting.charge_transition(self.limits.max_work)?;
                            table[checked_add(row, fallback, ResourceKind::TableCells)?]
                        }
                    }
                };
                let index = checked_add(row, pc, ResourceKind::TableCells)?;
                table[index] = value;
            }
        }
        Ok(table)
    }
}

pub(crate) fn encode(end: usize) -> Result<usize, Error> {
    checked_add(end, 1, ResourceKind::Boundaries)
}

pub(crate) fn decode(value: usize) -> Option<usize> {
    value.checked_sub(1)
}

pub(crate) fn table_index(position: usize, state: usize, states: usize) -> Result<usize, Error> {
    checked_add(
        checked_mul(position, states, ResourceKind::TableCells)?,
        state,
        ResourceKind::TableCells,
    )
}
