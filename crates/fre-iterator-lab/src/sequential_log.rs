//! Reverse-sequential fixed-row decision-log prototype.

use crate::accounting::{Accounting, RunReport, checked_add, checked_mul, enforce};
use crate::compile::{CompiledRegex, Inst};
use crate::full_dp::encode;
use crate::iterate::{collect_sequence, reserve_output};
use crate::{Error, ResourceKind};

#[derive(Clone, Copy, Debug)]
struct RowAdmission {
    record_len: usize,
    store_len: usize,
    scratch_bytes: usize,
}

#[derive(Debug)]
struct ReverseRowReader<'a> {
    store: &'a [u8],
    buffer: Vec<u8>,
    record_bytes: usize,
    split_count: usize,
    current_position: Option<usize>,
}

impl ReverseRowReader<'_> {
    fn root(&mut self, position: usize, accounting: &mut Accounting) -> Result<bool, Error> {
        self.ensure(position, accounting)?;
        read_bit(&self.buffer, self.split_count)
    }

    fn decision(
        &mut self,
        position: usize,
        split_rank: usize,
        accounting: &mut Accounting,
    ) -> Result<bool, Error> {
        self.ensure(position, accounting)?;
        read_bit(&self.buffer, split_rank)
    }

    fn ensure(&mut self, position: usize, accounting: &mut Accounting) -> Result<(), Error> {
        if self.current_position == Some(position) {
            return Ok(());
        }
        if self
            .current_position
            .is_some_and(|current| position < current)
        {
            return Err(Error::InvalidDecisionLog);
        }
        let records_traversed = match self.current_position {
            Some(current) => position
                .checked_sub(current)
                .ok_or(Error::InvalidDecisionLog)?,
            None => checked_add(position, 1, ResourceKind::LogBytes)?,
        };
        let traversed_bytes =
            checked_mul(records_traversed, self.record_bytes, ResourceKind::LogBytes)?;
        accounting.sequential_log_read_bytes = checked_add(
            accounting.sequential_log_read_bytes,
            traversed_bytes,
            ResourceKind::LogBytes,
        )?;
        let ordinal = checked_add(position, 1, ResourceKind::LogBytes)?;
        let from_end = checked_mul(ordinal, self.record_bytes, ResourceKind::LogBytes)?;
        let start = self
            .store
            .len()
            .checked_sub(from_end)
            .ok_or(Error::InvalidDecisionLog)?;
        let end = checked_add(start, self.record_bytes, ResourceKind::LogBytes)?;
        let record = self
            .store
            .get(start..end)
            .ok_or(Error::InvalidDecisionLog)?;
        self.buffer.copy_from_slice(record);
        self.current_position = Some(position);
        Ok(())
    }
}

impl CompiledRegex {
    /// Write fixed-size decision rows while evaluating boundaries right to
    /// left, then read those rows strictly backward while matches move left to
    /// right.
    ///
    /// Replay holds only one `ceil((S + 1) / 8)` row buffer and may inspect
    /// split bits in arbitrary control-flow order within that row. The current
    /// prototype uses a resident `Vec<u8>` as its sequential store, but its
    /// reader rejects any position regression and accounts every byte traversed.
    pub fn find_all_sequential_row_log(&self, haystack: &[u8]) -> Result<RunReport, Error> {
        let started = std::time::Instant::now();
        let boundaries = self.boundaries(haystack)?;
        let admission = self.admit_row_log(boundaries)?;
        let mut accounting = Accounting {
            program_states: self.insts.len(),
            boundaries,
            sequential_log_bytes: admission.store_len,
            resident_log_bytes: admission.store_len,
            random_access_peak_bytes: admission.scratch_bytes,
            ..Accounting::default()
        };
        let (output, output_reserved_bytes) = reserve_output(boundaries, self.limits)?;
        accounting.output_reserved_bytes = output_reserved_bytes;
        let mut store = zeroed_bytes(admission.store_len, ResourceKind::ResidentLogBytes)?;
        let mut record = zeroed_bytes(admission.record_len, ResourceKind::RandomAccessBytes)?;
        let mut row = zeroed_usizes(self.insts.len())?;
        let mut next_row = zeroed_usizes(self.insts.len())?;
        self.populate_row_store(
            haystack,
            boundaries,
            &mut store,
            &mut record,
            &mut row,
            &mut next_row,
            &mut accounting,
        )?;
        let reader_buffer = zeroed_bytes(admission.record_len, ResourceKind::RandomAccessBytes)?;
        let mut reader = ReverseRowReader {
            store: &store,
            buffer: reader_buffer,
            record_bytes: admission.record_len,
            split_count: self.split_count,
            current_position: None,
        };
        let matches = collect_sequence(
            haystack.len(),
            self.limits,
            &mut accounting,
            output,
            |start, accounting| {
                if !reader.root(start, accounting)? {
                    return Ok(None);
                }
                self.replay_row_log(haystack, start, &mut reader, accounting)
                    .map(Some)
            },
        )?;
        accounting.elapsed = started.elapsed();
        Ok(RunReport {
            matches,
            accounting,
        })
    }

    fn admit_row_log(&self, boundaries: usize) -> Result<RowAdmission, Error> {
        let bits_per_record = checked_add(self.split_count, 1, ResourceKind::LogBytes)?;
        let record_bytes = ceil_div(bits_per_record, 8)?;
        let store_bytes = checked_mul(record_bytes, boundaries, ResourceKind::LogBytes)?;
        enforce(
            store_bytes,
            self.limits.max_log_bytes,
            ResourceKind::LogBytes,
        )?;
        enforce(
            store_bytes,
            self.limits.max_resident_log_bytes,
            ResourceKind::ResidentLogBytes,
        )?;
        let row_words = checked_mul(self.insts.len(), 2, ResourceKind::RandomAccessBytes)?;
        let row_word_bytes = checked_mul(
            row_words,
            core::mem::size_of::<usize>(),
            ResourceKind::RandomAccessBytes,
        )?;
        let row_scratch_bytes = checked_add(
            row_word_bytes,
            checked_mul(record_bytes, 2, ResourceKind::RandomAccessBytes)?,
            ResourceKind::RandomAccessBytes,
        )?;
        enforce(
            row_scratch_bytes,
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
        enforce(
            checked_add(
                checked_add(build_work, root_work, ResourceKind::Work)?,
                replay_work,
                ResourceKind::Work,
            )?,
            self.limits.max_work,
            ResourceKind::Work,
        )?;
        Ok(RowAdmission {
            record_len: record_bytes,
            store_len: store_bytes,
            scratch_bytes: row_scratch_bytes,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "separate admitted buffers make ownership explicit"
    )]
    fn populate_row_store(
        &self,
        haystack: &[u8],
        boundaries: usize,
        store: &mut [u8],
        record: &mut [u8],
        row: &mut [usize],
        next_row: &mut [usize],
        accounting: &mut Accounting,
    ) -> Result<(), Error> {
        let mut write_offset = 0_usize;
        for position in (0..boundaries).rev() {
            record.fill(0);
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
                            set_bit(record, rank)?;
                            preferred_value
                        } else {
                            accounting.charge_transition(self.limits.max_work)?;
                            row[fallback]
                        }
                    }
                };
                row[pc] = value;
            }
            if row[self.entry] != 0 {
                set_bit(record, self.split_count)?;
            }
            let write_end = checked_add(write_offset, record.len(), ResourceKind::LogBytes)?;
            store
                .get_mut(write_offset..write_end)
                .ok_or(Error::InvalidDecisionLog)?
                .copy_from_slice(record);
            accounting.sequential_log_write_bytes = checked_add(
                accounting.sequential_log_write_bytes,
                record.len(),
                ResourceKind::LogBytes,
            )?;
            write_offset = write_end;
            row.swap_with_slice(next_row);
        }
        if write_offset != store.len() {
            return Err(Error::InvalidDecisionLog);
        }
        Ok(())
    }

    fn replay_row_log(
        &self,
        haystack: &[u8],
        start: usize,
        reader: &mut ReverseRowReader<'_>,
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
                    pc = if reader.decision(position, rank, accounting)? {
                        preferred
                    } else {
                        fallback
                    };
                }
            }
        }
    }
}

fn set_bit(bytes: &mut [u8], index: usize) -> Result<(), Error> {
    let byte = bytes.get_mut(index / 8).ok_or(Error::InvalidDecisionLog)?;
    *byte |= 1_u8 << (index % 8);
    Ok(())
}

fn read_bit(bytes: &[u8], index: usize) -> Result<bool, Error> {
    let byte = bytes.get(index / 8).ok_or(Error::InvalidDecisionLog)?;
    Ok(byte & (1_u8 << (index % 8)) != 0)
}

fn ceil_div(value: usize, divisor: usize) -> Result<usize, Error> {
    let adjustment = divisor.checked_sub(1).ok_or(Error::InvalidDecisionLog)?;
    checked_add(value, adjustment, ResourceKind::LogBytes)?
        .checked_div(divisor)
        .ok_or(Error::InvalidDecisionLog)
}

fn zeroed_bytes(length: usize, kind: ResourceKind) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed { kind })?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn zeroed_usizes(length: usize) -> Result<Vec<usize>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed {
            kind: ResourceKind::RandomAccessBytes,
        })?;
    values.resize(length, 0);
    Ok(values)
}
