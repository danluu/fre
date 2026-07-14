//! Row-streaming whole-operation decision-log candidate.

use crate::accounting::{Accounting, RunReport, checked_add, checked_mul, enforce};
use crate::compile::{CompiledRegex, Inst};
use crate::full_dp::encode;
use crate::iterate::{collect_sequence, reserve_output};
use crate::{Error, ResourceKind};

#[derive(Clone, Debug)]
struct BitLog {
    words: Vec<u64>,
    split_count: usize,
    root_base: usize,
}

impl BitLog {
    fn new(split_count: usize, root_base: usize, words: usize) -> Result<Self, Error> {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(words)
            .map_err(|_| Error::AllocationFailed {
                kind: ResourceKind::ResidentLogBytes,
            })?;
        storage.resize(words, 0);
        Ok(Self {
            words: storage,
            split_count,
            root_base,
        })
    }

    fn decision_index(&self, position: usize, split_rank: usize) -> Result<usize, Error> {
        checked_add(
            checked_mul(position, self.split_count, ResourceKind::Bytes)?,
            split_rank,
            ResourceKind::Bytes,
        )
    }

    fn set_decision(
        &mut self,
        position: usize,
        split_rank: usize,
        preferred: bool,
    ) -> Result<(), Error> {
        let index = self.decision_index(position, split_rank)?;
        self.set(index, preferred)
    }

    fn decision(&self, position: usize, split_rank: usize) -> Result<bool, Error> {
        self.get(self.decision_index(position, split_rank)?)
    }

    fn set_root(&mut self, position: usize, succeeds: bool) -> Result<(), Error> {
        self.set(
            checked_add(self.root_base, position, ResourceKind::Bytes)?,
            succeeds,
        )
    }

    fn root(&self, position: usize) -> Result<bool, Error> {
        self.get(checked_add(self.root_base, position, ResourceKind::Bytes)?)
    }

    fn set(&mut self, index: usize, value: bool) -> Result<(), Error> {
        let word = self
            .words
            .get_mut(index / 64)
            .ok_or(Error::InvalidDecisionLog)?;
        if value {
            *word |= 1_u64 << (index % 64);
        }
        Ok(())
    }

    fn get(&self, index: usize) -> Result<bool, Error> {
        let word = self
            .words
            .get(index / 64)
            .ok_or(Error::InvalidDecisionLog)?;
        Ok(word & (1_u64 << (index % 64)) != 0)
    }
}

#[derive(Clone, Copy, Debug)]
struct LogAdmission {
    decision_bits: usize,
    logical_bytes: usize,
    words: usize,
    resident_bytes: usize,
    row_bytes: usize,
}

impl CompiledRegex {
    /// Evaluate one input row at a time from right to left, logging one branch
    /// bit per split/boundary plus one root-success bit per boundary, then
    /// replay only selected paths to emit the complete sequence.
    ///
    /// For the declared subset, forward construction uses `O(Q * U)` work,
    /// `O(Q)` random-access words and `(S + 1) * U` logical log bits, where `S`
    /// is the number of split states. Replay adds at most `O(Q * U + Z)` work.
    /// The prototype keeps its packed log resident and randomly addressable;
    /// it does not yet establish a sequential-store lean-log theorem.
    pub fn find_all_decision_log(&self, haystack: &[u8]) -> Result<RunReport, Error> {
        let started = std::time::Instant::now();
        let boundaries = self.boundaries(haystack)?;
        let mut accounting = Accounting {
            program_states: self.insts.len(),
            boundaries,
            ..Accounting::default()
        };
        let admission = self.admit_log(boundaries)?;
        let (output, output_reserved_bytes) = reserve_output(boundaries, self.limits)?;
        accounting.output_reserved_bytes = output_reserved_bytes;
        let mut log = BitLog::new(self.split_count, admission.decision_bits, admission.words)?;
        accounting.sequential_log_bytes = admission.logical_bytes;
        accounting.resident_log_bytes = admission.resident_bytes;
        accounting.random_access_peak_bytes = admission.row_bytes;
        let mut next_row = zeroed_words(self.insts.len())?;
        let mut row = zeroed_words(self.insts.len())?;
        self.populate_log(
            haystack,
            boundaries,
            &mut log,
            &mut row,
            &mut next_row,
            &mut accounting,
        )?;
        let matches = collect_sequence(
            haystack.len(),
            self.limits,
            &mut accounting,
            output,
            |start, accounting| {
                if !log.root(start)? {
                    return Ok(None);
                }
                self.replay(haystack, start, &log, accounting).map(Some)
            },
        )?;
        accounting.elapsed = started.elapsed();
        Ok(RunReport {
            matches,
            accounting,
        })
    }

    fn admit_log(&self, boundaries: usize) -> Result<LogAdmission, Error> {
        let decision_bits = checked_mul(self.split_count, boundaries, ResourceKind::Bytes)?;
        let logical_bits = checked_add(decision_bits, boundaries, ResourceKind::Bytes)?;
        let logical_bytes = ceil_div(logical_bits, 8)?;
        enforce(
            logical_bytes,
            self.limits.max_log_bytes,
            ResourceKind::LogBytes,
        )?;
        let words = ceil_div(logical_bits, 64)?;
        let resident_bytes = checked_mul(
            words,
            core::mem::size_of::<u64>(),
            ResourceKind::ResidentLogBytes,
        )?;
        enforce(
            resident_bytes,
            self.limits.max_resident_log_bytes,
            ResourceKind::ResidentLogBytes,
        )?;
        let row_bytes = checked_mul(
            checked_mul(self.insts.len(), 2, ResourceKind::Bytes)?,
            core::mem::size_of::<usize>(),
            ResourceKind::Bytes,
        )?;
        enforce(
            row_bytes,
            self.limits.max_random_access_bytes,
            ResourceKind::RandomAccessBytes,
        )?;
        let build_work = self.maximum_build_work(boundaries)?;
        let root_work = checked_mul(boundaries, 2, ResourceKind::Work)?;
        let replay_work = checked_mul(
            checked_mul(self.insts.len(), boundaries, ResourceKind::Work)?,
            4,
            ResourceKind::Work,
        )?;
        let maximum_work = checked_add(
            checked_add(build_work, root_work, ResourceKind::Work)?,
            replay_work,
            ResourceKind::Work,
        )?;
        enforce(maximum_work, self.limits.max_work, ResourceKind::Work)?;
        Ok(LogAdmission {
            decision_bits,
            logical_bytes,
            words,
            resident_bytes,
            row_bytes,
        })
    }

    fn populate_log(
        &self,
        haystack: &[u8],
        boundaries: usize,
        log: &mut BitLog,
        row: &mut [usize],
        next_row: &mut [usize],
        accounting: &mut Accounting,
    ) -> Result<(), Error> {
        for position in (0..boundaries).rev() {
            for &pc in &self.epsilon_order {
                accounting.charge_state(self.limits.max_work)?;
                let value = match self.insts[pc] {
                    Inst::Match => encode(position)?,
                    Inst::Byte { expected, next } => {
                        accounting.charge_transition(self.limits.max_work)?;
                        if position < haystack.len()
                            && expected.is_none_or(|byte| byte == haystack[position])
                        {
                            next_row[next]
                        } else {
                            0
                        }
                    }
                    Inst::AssertStart { next } => {
                        accounting.charge_transition(self.limits.max_work)?;
                        if position == 0 { row[next] } else { 0 }
                    }
                    Inst::AssertEnd { next } => {
                        accounting.charge_transition(self.limits.max_work)?;
                        if position == haystack.len() {
                            row[next]
                        } else {
                            0
                        }
                    }
                    Inst::Split {
                        preferred,
                        fallback,
                    } => {
                        accounting.charge_transition(self.limits.max_work)?;
                        let preferred_value = row[preferred];
                        let rank = self.split_rank[pc].ok_or(Error::InvalidDecisionLog)?;
                        if preferred_value != 0 {
                            log.set_decision(position, rank, true)?;
                            preferred_value
                        } else {
                            accounting.charge_transition(self.limits.max_work)?;
                            row[fallback]
                        }
                    }
                };
                row[pc] = value;
            }
            log.set_root(position, row[self.entry] != 0)?;
            row.swap_with_slice(next_row);
        }
        Ok(())
    }

    fn replay(
        &self,
        haystack: &[u8],
        start: usize,
        log: &BitLog,
        accounting: &mut Accounting,
    ) -> Result<usize, Error> {
        let mut pc = self.entry;
        let mut position = start;
        loop {
            accounting.charge_replay(self.limits.max_work)?;
            match self.insts[pc] {
                Inst::Match => return Ok(position),
                Inst::Byte { expected, next } => {
                    if position >= haystack.len()
                        || expected.is_some_and(|byte| byte != haystack[position])
                    {
                        return Err(Error::InvalidDecisionLog);
                    }
                    position = checked_add(position, 1, ResourceKind::Boundaries)?;
                    pc = next;
                }
                Inst::AssertStart { next } => {
                    if position != 0 {
                        return Err(Error::InvalidDecisionLog);
                    }
                    pc = next;
                }
                Inst::AssertEnd { next } => {
                    if position != haystack.len() {
                        return Err(Error::InvalidDecisionLog);
                    }
                    pc = next;
                }
                Inst::Split {
                    preferred,
                    fallback,
                } => {
                    let rank = self.split_rank[pc].ok_or(Error::InvalidDecisionLog)?;
                    pc = if log.decision(position, rank)? {
                        preferred
                    } else {
                        fallback
                    };
                }
            }
        }
    }
}

fn ceil_div(value: usize, divisor: usize) -> Result<usize, Error> {
    let adjustment = divisor.checked_sub(1).ok_or(Error::InvalidDecisionLog)?;
    checked_add(value, adjustment, ResourceKind::Bytes)?
        .checked_div(divisor)
        .ok_or(Error::InvalidDecisionLog)
}

fn zeroed_words(length: usize) -> Result<Vec<usize>, Error> {
    let mut words = Vec::new();
    words
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed {
            kind: ResourceKind::RandomAccessBytes,
        })?;
    words.resize(length, 0);
    Ok(words)
}
