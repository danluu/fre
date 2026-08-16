//! Prepared whole-haystack plain-grep Count over the canonical AOT graph.
//!
//! This is an additive operation. It does not change the search output
//! contract or the stable serialized program. One caller-owned workspace is
//! prepared from immutable graph facts and then reused by the allocation-free
//! [`fre_automata::p16_grep_stream`] executor.

use core::{fmt, mem::size_of};

use fre_automata::p16_grep_stream::{self as grep_stream, GrepStreamError};

use crate::CompiledProgram;

/// Stable operation identity for prepared AOT plain-grep Count.
pub const GREP_COUNT_ACCOUNTING_ID: &str = "fre.aot-regex.grep-count.v1";
/// Algorithm version bound by [`GREP_COUNT_ACCOUNTING_ID`].
pub const GREP_COUNT_ALGORITHM_VERSION: u32 = 1;
/// Accounting version bound by [`GREP_COUNT_ACCOUNTING_ID`].
pub const GREP_COUNT_ACCOUNTING_VERSION: u32 = 1;
/// Default maximum fixed storage owned by one prepared grep workspace.
pub const DEFAULT_GREP_COUNT_MAX_WORKSPACE_BYTES: usize = 67_108_864;

/// Construction limit for one caller-owned prepared grep workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrepCountWorkspaceLimits {
    /// Maximum bytes in the three fixed `u64` stores.
    pub max_workspace_bytes: usize,
}

impl GrepCountWorkspaceLimits {
    /// An envelope accepting every representable fixed workspace.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_workspace_bytes: usize::MAX,
        }
    }
}

impl Default for GrepCountWorkspaceLimits {
    fn default() -> Self {
        Self {
            max_workspace_bytes: DEFAULT_GREP_COUNT_MAX_WORKSPACE_BYTES,
        }
    }
}

/// Exact immutable shape and identity of a prepared grep workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrepCountConstructionReceipt {
    artifact_identity: [u8; 32],
    structural_plan_identity: [u8; 16],
    line_state_cells: usize,
    generation_cells: usize,
    candidate_cells: usize,
    workspace_bytes: usize,
}

impl GrepCountConstructionReceipt {
    /// Stable semantic-program SHA-256 identity.
    #[must_use]
    pub const fn artifact_identity(self) -> [u8; 32] {
        self.artifact_identity
    }

    /// Complete identity of the validated automaton consumed by the reducer.
    #[must_use]
    pub const fn structural_plan_identity(self) -> [u8; 16] {
        self.structural_plan_identity
    }

    /// Cells in the combined current-thread and closure-stack store.
    #[must_use]
    pub const fn line_state_cells(self) -> usize {
        self.line_state_cells
    }

    /// Cells in the state-generation table.
    #[must_use]
    pub const fn generation_cells(self) -> usize {
        self.generation_cells
    }

    /// Cells in the consuming-candidate store.
    #[must_use]
    pub const fn candidate_cells(self) -> usize {
        self.candidate_cells
    }

    /// Exact bytes in all three fixed stores.
    #[must_use]
    pub const fn workspace_bytes(self) -> usize {
        self.workspace_bytes
    }
}

/// Failure while preparing one fixed grep workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GrepCountPrepareError {
    /// The p16 source-independent shape derivation failed.
    Prospective(GrepStreamError),
    /// Fixed-workspace arithmetic was not representable.
    ArithmeticOverflow {
        /// Stable failing computation.
        computation: &'static str,
    },
    /// The exact fixed storage exceeds the caller's construction envelope.
    Resource {
        /// Requested maximum bytes.
        limit: usize,
        /// Exact required bytes.
        required: usize,
    },
    /// A fallible fixed-store allocation was refused.
    Allocation {
        /// Stable store name.
        storage: &'static str,
        /// Exact logical cell count requested.
        cells: usize,
    },
}

impl fmt::Display for GrepCountPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prospective(error) => write!(formatter, "grep workspace shape failed: {error}"),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "grep workspace arithmetic overflow at {computation}"
                )
            }
            Self::Resource { limit, required } => write!(
                formatter,
                "grep workspace requires {required} bytes, limit is {limit}"
            ),
            Self::Allocation { storage, cells } => write!(
                formatter,
                "grep workspace allocation for {storage} ({cells} cells) failed"
            ),
        }
    }
}

impl std::error::Error for GrepCountPrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Prospective(error) => Some(error),
            Self::ArithmeticOverflow { .. } | Self::Resource { .. } | Self::Allocation { .. } => {
                None
            }
        }
    }
}

/// Failure from one prepared whole-haystack grep Count.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GrepCountError {
    /// The workspace belongs to another program lineage or graph.
    WorkspaceBinding,
    /// Source-independent admission derivation failed before source access.
    Prospective(GrepStreamError),
    /// The selected one-pass executor failed. No fallback is attempted.
    Execution(GrepStreamError),
}

impl fmt::Display for GrepCountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceBinding => {
                formatter.write_str("grep workspace does not belong to this AOT program")
            }
            Self::Prospective(error) => write!(formatter, "grep admission failed: {error}"),
            Self::Execution(error) => write!(formatter, "grep execution failed: {error}"),
        }
    }
}

impl std::error::Error for GrepCountError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WorkspaceBinding => None,
            Self::Prospective(error) | Self::Execution(error) => Some(error),
        }
    }
}

/// Successful whole-haystack grep Count and exact execution accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrepCountReceipt {
    artifact_identity: [u8; 32],
    structural_plan_identity: [u8; 16],
    generation_reset_cells: usize,
    report: grep_stream::GrepStreamReport,
}

impl GrepCountReceipt {
    /// Stable operation accounting identity.
    #[must_use]
    pub const fn accounting_id(self) -> &'static str {
        GREP_COUNT_ACCOUNTING_ID
    }

    /// Algorithm version bound by [`Self::accounting_id`].
    #[must_use]
    pub const fn algorithm_version(self) -> u32 {
        GREP_COUNT_ALGORITHM_VERSION
    }

    /// Accounting version bound by [`Self::accounting_id`].
    #[must_use]
    pub const fn accounting_version(self) -> u32 {
        GREP_COUNT_ACCOUNTING_VERSION
    }

    /// Number of matching semantic LF/CRLF line domains.
    #[must_use]
    pub const fn count(self) -> u64 {
        self.report.matched().count()
    }

    /// Number of semantic line domains examined.
    #[must_use]
    pub const fn source_line_domains(self) -> u64 {
        self.report.actual().domains_examined()
    }

    /// Stable semantic-program SHA-256 identity.
    #[must_use]
    pub const fn artifact_identity(self) -> [u8; 32] {
        self.artifact_identity
    }

    /// Complete validated-automaton identity.
    #[must_use]
    pub const fn structural_plan_identity(self) -> [u8; 16] {
        self.structural_plan_identity
    }

    /// Generation cells cleared during preflight before source access.
    ///
    /// This is zero on ordinary warm calls. A nonzero value records the exact
    /// fixed-table work needed to retire an exhausted generation epoch.
    #[must_use]
    pub const fn generation_reset_cells(self) -> usize {
        self.generation_reset_cells
    }

    /// Complete source-independent and exact execution report from p16.
    #[must_use]
    pub const fn execution(self) -> grep_stream::GrepStreamReport {
        self.report
    }
}

/// Caller-owned fixed storage for repeated whole-haystack grep Counts.
#[derive(Debug)]
pub struct GrepCountWorkspace {
    program_instance: u64,
    construction: GrepCountConstructionReceipt,
    line_state: Vec<u64>,
    generations: Vec<u64>,
    candidates: Vec<u64>,
    next_generation: u64,
}

impl GrepCountWorkspace {
    /// Exact immutable construction receipt.
    #[must_use]
    pub const fn construction_receipt(&self) -> GrepCountConstructionReceipt {
        self.construction
    }

    fn reserve_generation_interval(&mut self, required: u64) -> (u64, usize) {
        if required == 0 {
            return (self.next_generation.max(1), 0);
        }
        let final_offset = required.saturating_sub(1);
        let mut first = self.next_generation;
        let mut reset_cells = 0;
        if first == 0 || first.checked_add(final_offset).is_none() {
            self.generations.fill(0);
            first = 1;
            reset_cells = self.generations.len();
        }
        // A range ending at u64::MAX is valid. The zero sentinel forces a
        // complete fixed-table reset before the following source is admitted.
        self.next_generation = first.checked_add(required).unwrap_or(0);
        (first, reset_cells)
    }
}

#[derive(Clone, Copy)]
struct WorkspaceLayout {
    line_state_cells: usize,
    generation_cells: usize,
    candidate_cells: usize,
    workspace_bytes: usize,
}

fn workspace_layout(program: &CompiledProgram) -> Result<WorkspaceLayout, GrepCountPrepareError> {
    let prospective = grep_stream::prospective(program.grep_count_automaton(), 0)
        .map_err(GrepCountPrepareError::Prospective)?;
    let total_cells = prospective
        .line_state_cells()
        .checked_add(prospective.generation_cells())
        .and_then(|cells| cells.checked_add(prospective.candidate_cells()))
        .ok_or(GrepCountPrepareError::ArithmeticOverflow {
            computation: "fixed cell total",
        })?;
    let workspace_bytes = total_cells.checked_mul(size_of::<u64>()).ok_or(
        GrepCountPrepareError::ArithmeticOverflow {
            computation: "fixed storage bytes",
        },
    )?;
    Ok(WorkspaceLayout {
        line_state_cells: prospective.line_state_cells(),
        generation_cells: prospective.generation_cells(),
        candidate_cells: prospective.candidate_cells(),
        workspace_bytes,
    })
}

fn allocate_cells(storage: &'static str, cells: usize) -> Result<Vec<u64>, GrepCountPrepareError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(cells)
        .map_err(|_| GrepCountPrepareError::Allocation { storage, cells })?;
    if values.capacity() != cells {
        return Err(GrepCountPrepareError::Allocation { storage, cells });
    }
    values.resize(cells, 0);
    Ok(values)
}

impl CompiledProgram {
    /// Prepare fixed caller-owned storage for whole-haystack grep Count.
    ///
    /// This operation is independent of [`crate::OutputContract`]. It uses
    /// the same validated capture-free graph for every output contract.
    pub fn prepare_grep_count_workspace(
        &self,
    ) -> Result<GrepCountWorkspace, GrepCountPrepareError> {
        self.prepare_grep_count_workspace_with_limits(GrepCountWorkspaceLimits::default())
    }

    /// Prepare fixed caller-owned grep storage under an explicit byte limit.
    pub fn prepare_grep_count_workspace_with_limits(
        &self,
        limits: GrepCountWorkspaceLimits,
    ) -> Result<GrepCountWorkspace, GrepCountPrepareError> {
        let layout = workspace_layout(self)?;
        if layout.workspace_bytes > limits.max_workspace_bytes {
            return Err(GrepCountPrepareError::Resource {
                limit: limits.max_workspace_bytes,
                required: layout.workspace_bytes,
            });
        }
        let structural_plan_identity =
            grep_stream::structural_plan_identity(self.grep_count_automaton());
        let construction = GrepCountConstructionReceipt {
            artifact_identity: self.artifact_identity(),
            structural_plan_identity,
            line_state_cells: layout.line_state_cells,
            generation_cells: layout.generation_cells,
            candidate_cells: layout.candidate_cells,
            workspace_bytes: layout.workspace_bytes,
        };
        Ok(GrepCountWorkspace {
            program_instance: self.grep_count_program_instance(),
            construction,
            line_state: allocate_cells("line state", layout.line_state_cells)?,
            generations: allocate_cells("generation table", layout.generation_cells)?,
            candidates: allocate_cells("candidate state", layout.candidate_cells)?,
            next_generation: 1,
        })
    }

    /// Count matching LF/CRLF line domains with prepared fixed storage.
    ///
    /// Empty input and the position after a trailing LF do not create a line.
    /// A single CR immediately before LF is excluded from line content; every
    /// other CR remains content. All admission and workspace checks precede
    /// source access, and an execution failure is terminal without fallback.
    pub fn grep_count_with_workspace(
        &self,
        haystack: &[u8],
        workspace: &mut GrepCountWorkspace,
    ) -> Result<GrepCountReceipt, GrepCountError> {
        let automaton = self.grep_count_automaton();
        if workspace.program_instance != self.grep_count_program_instance()
            || workspace.construction.artifact_identity != self.artifact_identity()
        {
            return Err(GrepCountError::WorkspaceBinding);
        }
        // Program lineage is immutable and shared intentionally by Clone.
        // The structural digest was derived once at construction; recomputing
        // it here would add an O(graph) pre-pass to every warm operation.
        let structural_plan_identity = workspace.construction.structural_plan_identity;
        let required = grep_stream::prospective(automaton, haystack.len())
            .map_err(GrepCountError::Prospective)?;
        if workspace.line_state.len() != required.line_state_cells()
            || workspace.generations.len() != required.generation_cells()
            || workspace.candidates.len() != required.candidate_cells()
        {
            return Err(GrepCountError::WorkspaceBinding);
        }
        let (first_generation, generation_reset_cells) =
            workspace.reserve_generation_interval(required.required_generations());
        let report = grep_stream::count_matching_lines(
            automaton,
            haystack,
            required,
            first_generation,
            &mut workspace.line_state,
            &mut workspace.generations,
            &mut workspace.candidates,
        )
        .map_err(GrepCountError::Execution)?;
        Ok(GrepCountReceipt {
            artifact_identity: self.artifact_identity(),
            structural_plan_identity,
            generation_reset_cells,
            report,
        })
    }
}

#[cfg(test)]
mod tests {
    use regex::bytes::Regex;

    use super::{GrepCountError, GrepCountPrepareError, GrepCountWorkspaceLimits};
    use crate::{CompileRequest, OutputContract, Target, compile};

    fn compile_program(pattern: &str, output: OutputContract) -> crate::CompiledProgram {
        compile(CompileRequest::new(pattern, Target::x86_64_linux()).output(output))
            .expect("compile grep fixture")
            .program()
            .clone()
    }

    fn semantic_lines(haystack: &[u8]) -> Vec<&[u8]> {
        let mut lines = Vec::new();
        let mut start = 0;
        for (index, byte) in haystack.iter().copied().enumerate() {
            if byte != b'\n' {
                continue;
            }
            let mut end = index;
            if end > start && haystack[end.saturating_sub(1)] == b'\r' {
                end = end.saturating_sub(1);
            }
            lines.push(&haystack[start..end]);
            start = index.saturating_add(1);
        }
        if start < haystack.len() {
            lines.push(&haystack[start..]);
        }
        lines
    }

    fn oracle(pattern: &str, haystack: &[u8]) -> u64 {
        let regex = Regex::new(pattern).expect("compile independent regex oracle");
        semantic_lines(haystack)
            .into_iter()
            .filter(|line| regex.is_match(line))
            .count()
            .try_into()
            .expect("small oracle count")
    }

    #[test]
    fn prepared_grep_matches_independent_line_searches() {
        let patterns = [
            "",
            "a",
            "^$",
            "^a+$",
            "(?:foo|bar)+",
            r"\b\w+\b",
            "[[:alpha:]]+",
        ];
        let haystacks: &[&[u8]] = &[
            b"",
            b"\n",
            b"\n\n",
            b"a",
            b"a\n",
            b"a\r\n",
            b"a\r",
            b"\r\r\n",
            b"foo\nxxbarxx\r\nnone\n",
            b"caf\xc3\xa9\ninvalid-\xff-word\n",
        ];
        for pattern in patterns {
            let program = compile_program(pattern, OutputContract::Span);
            let mut workspace = program
                .prepare_grep_count_workspace()
                .expect("prepare fixed grep workspace");
            for haystack in haystacks {
                let receipt = program
                    .grep_count_with_workspace(haystack, &mut workspace)
                    .expect("one-pass grep Count");
                assert_eq!(
                    receipt.count(),
                    oracle(pattern, haystack),
                    "pattern={pattern:?}, haystack={haystack:?}"
                );
                assert_eq!(
                    receipt.source_line_domains(),
                    u64::try_from(semantic_lines(haystack).len()).unwrap()
                );
                assert_eq!(receipt.execution().actual().allocations(), 0);
            }
        }
    }

    #[test]
    fn grep_is_output_independent_and_does_not_change_wire_bytes() {
        let haystack = b"a\nno\r\naaa\n";
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let program = compile_program("^a+$", output);
            let before = program.serialize().expect("serialize before preparation");
            let mut workspace = program
                .prepare_grep_count_workspace()
                .expect("prepare output-independent grep");
            assert_eq!(
                program
                    .grep_count_with_workspace(haystack, &mut workspace)
                    .expect("grep every output contract")
                    .count(),
                2
            );
            assert_eq!(
                program.serialize().expect("serialize after execution"),
                before
            );
        }
    }

    #[test]
    fn workspace_accepts_clone_lineage_and_rejects_foreign_program() {
        let program = compile_program("a+", OutputContract::Span);
        let clone = program.clone();
        let foreign = compile_program("b+", OutputContract::Span);
        let mut workspace = program
            .prepare_grep_count_workspace()
            .expect("prepare owned workspace");
        assert_eq!(
            clone
                .grep_count_with_workspace(b"a\nb\n", &mut workspace)
                .expect("clone lineage authenticates")
                .count(),
            1
        );
        assert!(matches!(
            foreign.grep_count_with_workspace(b"b\n", &mut workspace),
            Err(GrepCountError::WorkspaceBinding)
        ));
    }

    #[test]
    fn construction_limit_refuses_before_allocating_workspace() {
        let program = compile_program("a+", OutputContract::Span);
        let error = program
            .prepare_grep_count_workspace_with_limits(GrepCountWorkspaceLimits {
                max_workspace_bytes: 0,
            })
            .expect_err("nonempty graph needs fixed storage");
        assert!(matches!(
            error,
            GrepCountPrepareError::Resource {
                limit: 0,
                required
            } if required > 0
        ));
    }

    #[test]
    fn generation_epoch_reset_is_preflighted_and_receipted() {
        let program = compile_program("a", OutputContract::Span);
        let mut workspace = program
            .prepare_grep_count_workspace()
            .expect("prepare fixed grep workspace");
        workspace.next_generation = u64::MAX;
        let receipt = program
            .grep_count_with_workspace(b"a", &mut workspace)
            .expect("roll over before source execution");
        assert_eq!(receipt.count(), 1);
        assert_eq!(
            receipt.generation_reset_cells(),
            workspace.construction_receipt().generation_cells()
        );
        let warm = program
            .grep_count_with_workspace(b"a", &mut workspace)
            .expect("next epoch is warm");
        assert_eq!(warm.generation_reset_cells(), 0);
    }
}
