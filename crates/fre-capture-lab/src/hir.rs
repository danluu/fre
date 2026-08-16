//! Checked lowering from pinned Rust regex HIR into capture programs.
//!
//! This adapter deliberately stops at the capture laboratory's immutable
//! [`Program`](crate::Program). Syntax parsing, admission policy, and any
//! operation-specific planning remain the caller's responsibility.

use regex_syntax::{
    hir::{Class, ClassUnicode, Hir, HirKind, Look},
    utf8::Utf8Sequences,
};

use crate::{Assertion, Ast, BuildError, BuildLimits, BuildReport, Greed, Program};

/// Checked accounting for one HIR-to-capture-program lowering.
///
/// A caller that performs other metered traversals over the same HIR may pass
/// its current ledger to [`build_program_from_hir_with_accounting`]. The
/// returned ledger then preserves one cumulative construction budget.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HirBuildAccounting {
    /// HIR nodes converted.
    pub hir_nodes: usize,
    /// Maximum conversion recursion depth.
    pub hir_depth: usize,
    /// Literal bytes copied into byte atoms.
    pub literal_bytes: usize,
    /// Byte-class ranges copied.
    pub class_ranges: usize,
    /// Numeric user-capture slots implied by the greatest surviving HIR index.
    /// A nonzero initial value must describe this same HIR: it is bounded by
    /// [`BuildLimits::max_captures`] and authenticated against the compiled
    /// program schema before publication.
    pub capture_slots: usize,
    /// Metered conversion work, including any caller-supplied initial work.
    pub work: usize,
}

/// Independent limits for checked HIR lowering and capture-program building.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HirProgramBuildLimits {
    /// Maximum cumulative HIR conversion work.
    pub max_hir_work: usize,
    /// Maximum HIR conversion depth. The root has depth one.
    pub max_hir_depth: usize,
    /// Capture AST admission and immutable-program compiler limits.
    pub program: BuildLimits,
}

impl Default for HirProgramBuildLimits {
    fn default() -> Self {
        Self {
            max_hir_work: 1_000_000,
            max_hir_depth: 250,
            program: BuildLimits::default(),
        }
    }
}

/// Resource dimension refused while lowering canonical HIR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HirBuildResource {
    /// Metered conversion work.
    Work,
    /// Conversion recursion depth.
    Depth,
    /// Converted HIR node accounting.
    Nodes,
    /// Literal bytes copied into byte atoms.
    LiteralBytes,
    /// Byte-class ranges copied into byte atoms.
    ClassRanges,
    /// Numeric user-capture slots in the canonical HIR schema.
    CaptureSlots,
}

impl HirBuildResource {
    /// Stable facade-compatible resource name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Depth => "depth",
            Self::Nodes => "nodes",
            Self::LiteralBytes => "literal bytes",
            Self::ClassRanges => "class ranges",
            Self::CaptureSlots => "capture slots",
        }
    }
}

/// Allocation site refused while lowering canonical HIR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HirBuildAllocation {
    /// Exact literal byte atoms.
    Literal,
    /// One ordinary byte-class range vector.
    ClassRange,
    /// Byte atoms for one UTF-8 sequence.
    UnicodeClassSequence,
    /// The singleton range vector for one UTF-8 byte interval.
    UnicodeByteRange,
    /// One UTF-8 sequence branch.
    UnicodeClassBranch,
    /// Child ASTs for a concatenation or alternation.
    Child,
}

impl HirBuildAllocation {
    /// Stable facade-compatible allocation-site name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::ClassRange => "class range",
            Self::UnicodeClassSequence => "Unicode class sequence",
            Self::UnicodeByteRange => "Unicode byte range",
            Self::UnicodeClassBranch => "Unicode class branch",
            Self::Child => "child",
        }
    }
}

/// Checked HIR-to-capture-program failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HirProgramBuildError {
    /// A lowering resource ceiling would be exceeded.
    Resource {
        /// Limited resource dimension.
        resource: HirBuildResource,
        /// Required amount, or [`usize::MAX`] after checked overflow.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A lowering allocation failed after resource admission.
    Allocation {
        /// Structure whose reservation failed.
        structure: HirBuildAllocation,
        /// Requested item count.
        items: usize,
    },
    /// The lowered capture AST was refused by the bounded program compiler.
    Program(BuildError),
    /// A canonical-HIR or compiler invariant did not hold.
    InternalInvariant(&'static str),
}

impl core::fmt::Display for HirProgramBuildError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "capture HIR {} needs {required}, exceeding {limit}",
                resource.as_str()
            ),
            Self::Allocation { structure, items } => write!(
                formatter,
                "capture HIR failed to reserve {items} {} items",
                structure.as_str()
            ),
            Self::Program(error) => write!(formatter, "capture program build failed: {error}"),
            Self::InternalInvariant(detail) => {
                write!(formatter, "capture HIR build invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for HirProgramBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Program(error) => Some(error),
            Self::Resource { .. } | Self::Allocation { .. } | Self::InternalInvariant(_) => None,
        }
    }
}

/// Complete accounting for one successful HIR-to-capture-program build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HirProgramBuildReport {
    /// Cumulative checked HIR lowering accounting.
    pub hir: HirBuildAccounting,
    /// Capture AST admission and immutable-program compiler accounting.
    pub program: BuildReport,
}

/// One successfully lowered immutable capture program and its accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HirProgramBuild {
    program: Program,
    report: HirProgramBuildReport,
}

impl HirProgramBuild {
    /// Borrow the immutable prioritized tagged capture program.
    #[must_use]
    pub const fn program(&self) -> &Program {
        &self.program
    }

    /// Borrow complete lowering and program-build accounting.
    #[must_use]
    pub const fn report(&self) -> &HirProgramBuildReport {
        &self.report
    }

    /// Consume the result and return its immutable capture program.
    #[must_use]
    pub fn into_program(self) -> Program {
        self.program
    }

    /// Consume the result and return both the program and its report.
    #[must_use]
    pub fn into_parts(self) -> (Program, HirProgramBuildReport) {
        (self.program, self.report)
    }
}

/// Build one pinned Rust-regex byte-profile capture program from canonical HIR.
///
/// `line_terminator` supplies the parse-profile byte needed to preserve the
/// exact meaning of the HIR's generic `StartLF` and `EndLF` look variants.
/// Every other look variant is translated directly to the capture program's
/// pinned assertion vocabulary. The capture program is always compiled for
/// [`crate::CaptureProfile::RustRegexBytes1_12_4`].
///
/// # Errors
///
/// Returns [`HirProgramBuildError`] for a lowering limit or allocation
/// refusal, a capture-program compiler failure, or a violated schema
/// invariant.
pub fn build_program_from_hir(
    hir: &Hir,
    line_terminator: u8,
    limits: HirProgramBuildLimits,
) -> Result<HirProgramBuild, HirProgramBuildError> {
    build_program_from_hir_with_accounting(
        hir,
        line_terminator,
        limits,
        HirBuildAccounting::default(),
    )
}

/// Build a capture program while continuing a caller-owned HIR ledger.
///
/// This is equivalent to [`build_program_from_hir`] when `accounting` is the
/// default value. It exists for construction owners that charge several
/// bounded analyses of the same canonical HIR to one cumulative work ceiling.
/// Every initial dimension is validated before lowering or allocation. A
/// nonzero `capture_slots` value must describe this same HIR; a value above
/// the program capture limit is a resource refusal, while disagreement with
/// the eventual compiled schema is an invariant failure.
///
/// # Errors
///
/// Returns the same typed failures as [`build_program_from_hir`].
pub fn build_program_from_hir_with_accounting(
    hir: &Hir,
    line_terminator: u8,
    limits: HirProgramBuildLimits,
    mut accounting: HirBuildAccounting,
) -> Result<HirProgramBuild, HirProgramBuildError> {
    validate_initial_accounting(accounting, limits)?;
    let ast = lower_hir(hir, 1, line_terminator, limits, &mut accounting)?;
    let program = Program::compile(&ast, limits.program).map_err(HirProgramBuildError::Program)?;
    let program_report = program.build_report().clone();
    if program_report.captures != accounting.capture_slots {
        return Err(HirProgramBuildError::InternalInvariant(
            "capture compiler schema differs from parsed HIR",
        ));
    }
    Ok(HirProgramBuild {
        program,
        report: HirProgramBuildReport {
            hir: accounting,
            program: program_report,
        },
    })
}

fn validate_initial_accounting(
    accounting: HirBuildAccounting,
    limits: HirProgramBuildLimits,
) -> Result<(), HirProgramBuildError> {
    for (resource, required, limit) in [
        (HirBuildResource::Work, accounting.work, limits.max_hir_work),
        (
            HirBuildResource::Depth,
            accounting.hir_depth,
            limits.max_hir_depth,
        ),
        (
            HirBuildResource::Nodes,
            accounting.hir_nodes,
            limits.max_hir_work,
        ),
        (
            HirBuildResource::LiteralBytes,
            accounting.literal_bytes,
            limits.max_hir_work,
        ),
        (
            HirBuildResource::ClassRanges,
            accounting.class_ranges,
            limits.max_hir_work,
        ),
        (
            HirBuildResource::CaptureSlots,
            accounting.capture_slots,
            limits.program.max_captures,
        ),
    ] {
        if required > limit {
            return Err(HirProgramBuildError::Resource {
                resource,
                required,
                limit,
            });
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete checked HIR-to-capture-AST mapping remains locally auditable"
)]
fn lower_hir(
    hir: &Hir,
    depth: usize,
    line_terminator: u8,
    limits: HirProgramBuildLimits,
    accounting: &mut HirBuildAccounting,
) -> Result<Ast, HirProgramBuildError> {
    if depth > limits.max_hir_depth {
        return Err(HirProgramBuildError::Resource {
            resource: HirBuildResource::Depth,
            required: depth,
            limit: limits.max_hir_depth,
        });
    }
    accounting.hir_depth = accounting.hir_depth.max(depth);
    charge_hir(accounting, 1, limits.max_hir_work)?;
    accounting.hir_nodes =
        accounting
            .hir_nodes
            .checked_add(1)
            .ok_or(HirProgramBuildError::Resource {
                resource: HirBuildResource::Nodes,
                required: usize::MAX,
                limit: limits.max_hir_work,
            })?;
    match hir.kind() {
        HirKind::Empty => Ok(Ast::Empty),
        HirKind::Literal(literal) => {
            charge_hir(accounting, literal.0.len(), limits.max_hir_work)?;
            accounting.literal_bytes = checked_dimension_add(
                accounting.literal_bytes,
                literal.0.len(),
                HirBuildResource::LiteralBytes,
                limits.max_hir_work,
            )?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(literal.0.len()).map_err(|_| {
                HirProgramBuildError::Allocation {
                    structure: HirBuildAllocation::Literal,
                    items: literal.0.len(),
                }
            })?;
            bytes.extend(literal.0.iter().copied().map(Ast::Byte));
            Ok(concat_or_empty(bytes))
        }
        HirKind::Class(Class::Bytes(class)) => {
            let ranges_len = class.ranges().len();
            charge_hir(accounting, ranges_len, limits.max_hir_work)?;
            accounting.class_ranges = checked_dimension_add(
                accounting.class_ranges,
                ranges_len,
                HirBuildResource::ClassRanges,
                limits.max_hir_work,
            )?;
            let mut ranges = Vec::new();
            ranges
                .try_reserve_exact(ranges_len)
                .map_err(|_| HirProgramBuildError::Allocation {
                    structure: HirBuildAllocation::ClassRange,
                    items: ranges_len,
                })?;
            ranges.extend(
                class
                    .ranges()
                    .iter()
                    .map(|range| (range.start(), range.end())),
            );
            Ok(Ast::Class(ranges))
        }
        HirKind::Class(Class::Unicode(class)) => lower_unicode_class(class, limits, accounting),
        HirKind::Look(Look::Start) => Ok(Ast::Start),
        HirKind::Look(Look::End) => Ok(Ast::End),
        HirKind::Look(Look::StartLF) if line_terminator == b'\n' => {
            Ok(Ast::Assert(Assertion::StartLf))
        }
        HirKind::Look(Look::EndLF) if line_terminator == b'\n' => Ok(Ast::Assert(Assertion::EndLf)),
        HirKind::Look(Look::StartLF) => Ok(Ast::Assert(Assertion::StartLine(line_terminator))),
        HirKind::Look(Look::EndLF) => Ok(Ast::Assert(Assertion::EndLine(line_terminator))),
        HirKind::Look(Look::WordAscii) => Ok(Ast::Assert(Assertion::WordAscii)),
        HirKind::Look(Look::WordAsciiNegate) => Ok(Ast::Assert(Assertion::WordAsciiNegate)),
        HirKind::Look(Look::WordStartAscii) => Ok(Ast::Assert(Assertion::WordStartAscii)),
        HirKind::Look(Look::WordEndAscii) => Ok(Ast::Assert(Assertion::WordEndAscii)),
        HirKind::Look(Look::WordStartHalfAscii) => Ok(Ast::Assert(Assertion::WordStartHalfAscii)),
        HirKind::Look(Look::WordEndHalfAscii) => Ok(Ast::Assert(Assertion::WordEndHalfAscii)),
        HirKind::Look(Look::WordUnicode) => Ok(Ast::Assert(Assertion::WordUnicode)),
        HirKind::Look(Look::StartCRLF) => Ok(Ast::Assert(Assertion::StartCrlf)),
        HirKind::Look(Look::EndCRLF) => Ok(Ast::Assert(Assertion::EndCrlf)),
        HirKind::Look(Look::WordUnicodeNegate) => Ok(Ast::Assert(Assertion::WordUnicodeNegate)),
        HirKind::Look(Look::WordStartUnicode) => Ok(Ast::Assert(Assertion::WordStartUnicode)),
        HirKind::Look(Look::WordEndUnicode) => Ok(Ast::Assert(Assertion::WordEndUnicode)),
        HirKind::Look(Look::WordStartHalfUnicode) => {
            Ok(Ast::Assert(Assertion::WordStartHalfUnicode))
        }
        HirKind::Look(Look::WordEndHalfUnicode) => Ok(Ast::Assert(Assertion::WordEndHalfUnicode)),
        HirKind::Capture(capture) => {
            accounting.capture_slots =
                accounting
                    .capture_slots
                    .max(usize::try_from(capture.index).map_err(|_| {
                        HirProgramBuildError::InternalInvariant("capture index does not fit usize")
                    })?);
            Ok(Ast::Capture {
                index: capture.index,
                name: capture.name.as_ref().map(ToString::to_string),
                child: Box::new(lower_hir(
                    capture.sub.as_ref(),
                    next_depth(depth)?,
                    line_terminator,
                    limits,
                    accounting,
                )?),
            })
        }
        HirKind::Repetition(repetition) => Ok(Ast::Repeat {
            child: Box::new(lower_hir(
                repetition.sub.as_ref(),
                next_depth(depth)?,
                line_terminator,
                limits,
                accounting,
            )?),
            min: repetition.min,
            max: repetition.max,
            greed: if repetition.greedy {
                Greed::Greedy
            } else {
                Greed::Lazy
            },
        }),
        HirKind::Concat(children) => lower_children(
            children,
            depth,
            line_terminator,
            limits,
            accounting,
            Ast::Concat,
        ),
        HirKind::Alternation(children) => lower_children(
            children,
            depth,
            line_terminator,
            limits,
            accounting,
            Ast::Alt,
        ),
    }
}

fn lower_unicode_class(
    class: &ClassUnicode,
    limits: HirProgramBuildLimits,
    accounting: &mut HirBuildAccounting,
) -> Result<Ast, HirProgramBuildError> {
    let mut branches = Vec::new();
    for scalar_range in class.ranges() {
        charge_hir(accounting, 1, limits.max_hir_work)?;
        for sequence in Utf8Sequences::new(scalar_range.start(), scalar_range.end()) {
            charge_hir(accounting, 1, limits.max_hir_work)?;
            let byte_ranges = sequence.as_slice();
            charge_hir(accounting, byte_ranges.len(), limits.max_hir_work)?;
            let mut parts = Vec::new();
            parts.try_reserve_exact(byte_ranges.len()).map_err(|_| {
                HirProgramBuildError::Allocation {
                    structure: HirBuildAllocation::UnicodeClassSequence,
                    items: byte_ranges.len(),
                }
            })?;
            for range in byte_ranges {
                accounting.class_ranges = checked_dimension_add(
                    accounting.class_ranges,
                    1,
                    HirBuildResource::ClassRanges,
                    limits.max_hir_work,
                )?;
                let mut ranges = Vec::new();
                ranges
                    .try_reserve_exact(1)
                    .map_err(|_| HirProgramBuildError::Allocation {
                        structure: HirBuildAllocation::UnicodeByteRange,
                        items: 1,
                    })?;
                ranges.push((range.start, range.end));
                parts.push(Ast::Class(ranges));
            }
            branches
                .try_reserve(1)
                .map_err(|_| HirProgramBuildError::Allocation {
                    structure: HirBuildAllocation::UnicodeClassBranch,
                    items: 1,
                })?;
            branches.push(concat_or_empty(parts));
        }
    }
    Ok(match branches.len() {
        0 => Ast::Class(Vec::new()),
        1 => branches
            .into_iter()
            .next()
            .unwrap_or(Ast::Class(Vec::new())),
        _ => Ast::Alt(branches),
    })
}

fn lower_children(
    children: &[Hir],
    depth: usize,
    line_terminator: u8,
    limits: HirProgramBuildLimits,
    accounting: &mut HirBuildAccounting,
    construct: fn(Vec<Ast>) -> Ast,
) -> Result<Ast, HirProgramBuildError> {
    let mut lowered = Vec::new();
    lowered
        .try_reserve_exact(children.len())
        .map_err(|_| HirProgramBuildError::Allocation {
            structure: HirBuildAllocation::Child,
            items: children.len(),
        })?;
    let child_depth = next_depth(depth)?;
    for child in children {
        lowered.push(lower_hir(
            child,
            child_depth,
            line_terminator,
            limits,
            accounting,
        )?);
    }
    Ok(construct(lowered))
}

fn concat_or_empty(children: Vec<Ast>) -> Ast {
    match children.len() {
        0 => Ast::Empty,
        1 => children.into_iter().next().unwrap_or(Ast::Empty),
        _ => Ast::Concat(children),
    }
}

fn next_depth(depth: usize) -> Result<usize, HirProgramBuildError> {
    depth.checked_add(1).ok_or(HirProgramBuildError::Resource {
        resource: HirBuildResource::Depth,
        required: usize::MAX,
        limit: usize::MAX,
    })
}

fn charge_hir(
    accounting: &mut HirBuildAccounting,
    amount: usize,
    limit: usize,
) -> Result<(), HirProgramBuildError> {
    let required = accounting
        .work
        .checked_add(amount)
        .ok_or(HirProgramBuildError::Resource {
            resource: HirBuildResource::Work,
            required: usize::MAX,
            limit,
        })?;
    if required > limit {
        return Err(HirProgramBuildError::Resource {
            resource: HirBuildResource::Work,
            required,
            limit,
        });
    }
    accounting.work = required;
    Ok(())
}

fn checked_dimension_add(
    current: usize,
    amount: usize,
    resource: HirBuildResource,
    limit: usize,
) -> Result<usize, HirProgramBuildError> {
    let required = current
        .checked_add(amount)
        .ok_or(HirProgramBuildError::Resource {
            resource,
            required: usize::MAX,
            limit,
        })?;
    if required > limit {
        return Err(HirProgramBuildError::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(required)
}
