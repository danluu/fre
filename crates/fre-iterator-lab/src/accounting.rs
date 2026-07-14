//! Executor accounting kept separate from semantic output.

use std::time::Duration;

use crate::{Error, ResourceKind, Span};

/// Checked work and storage counters for one complete operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Accounting {
    /// Wall-clock duration including preflight, allocation, execution and output.
    pub elapsed: Duration,
    /// Number of compiled states.
    pub program_states: usize,
    /// Number of original input boundaries.
    pub boundaries: usize,
    /// Dynamic-program state evaluations.
    pub state_evaluations: usize,
    /// Same-boundary or consuming transition inspections.
    pub transition_checks: usize,
    /// Entry-success probes while finding the next match start.
    pub root_probes: usize,
    /// State steps while replaying a logged successful path.
    pub replay_steps: usize,
    /// Full table builds. Candidates use zero or one; the oracle uses many.
    pub table_builds: usize,
    /// Full word-sized table cells materialized at peak.
    pub table_cells: usize,
    /// Guard-keyed recurrence cells materialized.
    pub guarded_configurations: usize,
    /// Peak explicit guarded solver frames used.
    pub guarded_peak_frames: usize,
    /// Peak executor scratch excluding the packed sequential decision log.
    pub random_access_peak_bytes: usize,
    /// Logical packed branch/root decision bytes.
    pub sequential_log_bytes: usize,
    /// Actual resident bytes reserved for the word-packed log.
    pub resident_log_bytes: usize,
    /// Bytes appended to a sequential decision store.
    pub sequential_log_write_bytes: usize,
    /// Bytes traversed while replaying a sequential decision store.
    pub sequential_log_read_bytes: usize,
    /// Work directly proportional to emitted spans.
    pub output_work: usize,
    /// Bytes occupied by the returned span vector, excluding allocator slack.
    pub output_bytes: usize,
    /// Bytes pre-reserved for the returned span vector.
    pub output_reserved_bytes: usize,
    /// Sum of all instrumented work categories.
    pub total_work: usize,
}

impl Accounting {
    pub(crate) fn charge_state(&mut self, maximum: usize) -> Result<(), Error> {
        self.state_evaluations = checked_add(self.state_evaluations, 1, ResourceKind::Work)?;
        self.charge_total(1, maximum)
    }

    pub(crate) fn charge_transition(&mut self, maximum: usize) -> Result<(), Error> {
        self.transition_checks = checked_add(self.transition_checks, 1, ResourceKind::Work)?;
        self.charge_total(1, maximum)
    }

    pub(crate) fn charge_root(&mut self, maximum: usize) -> Result<(), Error> {
        self.root_probes = checked_add(self.root_probes, 1, ResourceKind::Work)?;
        self.charge_total(1, maximum)
    }

    pub(crate) fn charge_replay(&mut self, maximum: usize) -> Result<(), Error> {
        self.replay_steps = checked_add(self.replay_steps, 1, ResourceKind::Work)?;
        self.charge_total(1, maximum)
    }

    pub(crate) fn emit(&mut self, maximum: usize) -> Result<(), Error> {
        let required = checked_add(self.output_work, 1, ResourceKind::OutputMatches)?;
        if required > maximum {
            return Err(Error::ResourceLimit {
                kind: ResourceKind::OutputMatches,
                required,
                limit: maximum,
            });
        }
        self.output_work = required;
        self.output_bytes = checked_mul(
            self.output_work,
            core::mem::size_of::<Span>(),
            ResourceKind::Bytes,
        )?;
        Ok(())
    }

    fn charge_total(&mut self, amount: usize, maximum: usize) -> Result<(), Error> {
        let required = checked_add(self.total_work, amount, ResourceKind::Work)?;
        if required > maximum {
            return Err(Error::ResourceLimit {
                kind: ResourceKind::Work,
                required,
                limit: maximum,
            });
        }
        self.total_work = required;
        Ok(())
    }
}

/// Complete semantic output and independent accounting for one executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunReport {
    /// Exact non-overlapping match sequence.
    pub matches: Vec<Span>,
    /// Checked work/storage counters.
    pub accounting: Accounting,
}

pub(crate) fn checked_add(left: usize, right: usize, kind: ResourceKind) -> Result<usize, Error> {
    left.checked_add(right).ok_or(Error::ResourceLimit {
        kind,
        required: usize::MAX,
        limit: usize::MAX - 1,
    })
}

pub(crate) fn checked_mul(left: usize, right: usize, kind: ResourceKind) -> Result<usize, Error> {
    left.checked_mul(right).ok_or(Error::ResourceLimit {
        kind,
        required: usize::MAX,
        limit: usize::MAX - 1,
    })
}

pub(crate) fn enforce(required: usize, limit: usize, kind: ResourceKind) -> Result<(), Error> {
    if required > limit {
        return Err(Error::ResourceLimit {
            kind,
            required,
            limit,
        });
    }
    Ok(())
}
