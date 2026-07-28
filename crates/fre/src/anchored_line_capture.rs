//! Generic allocation-free `grep-captures` reduction for deterministic lines.
//!
//! Construction parses the pinned Rust byte HIR and accepts only an absolute
//! start followed by a bounded inline sequence of literal bytes, byte classes,
//! and greedy single-byte repetitions. Explicit captures must be mandatory
//! children of the root concatenation, but may participate with an empty span.
//! An optional terminal absolute End assertion is retained in the plan.
//! Variable repetition boundaries are certified by the native kernel before
//! the plan is published.

use core::{fmt, mem::size_of};

use fre_kernels::{
    ANCHORED_LINE_CAPTURE_COUNT_OPERATION_ID, ANCHORED_LINE_CAPTURE_MAX_ATOMS,
    ANCHORED_LINE_CAPTURE_PLAN_ID, AnchoredLineCaptureAtom,
    AnchoredLineCaptureBuildAccounting as KernelBuildAccounting,
    AnchoredLineCaptureBuildError as KernelBuildError,
    AnchoredLineCaptureBuildLimits as KernelBuildLimits, AnchoredLineCaptureByteMask,
    AnchoredLineCaptureCountResult, AnchoredLineCaptureOperationIdentity,
    AnchoredLineCapturePlan as KernelPlan, AnchoredLineCaptureRunError,
    AnchoredLineCaptureRunLimits,
};
use fre_syntax::{
    AdmissionPolicy, CanonicalPattern, CompatibilityProfile, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{Class, Hir, HirKind, Look, Repetition};

pub const ANCHORED_LINE_CAPTURE_ALGORITHM_VERSION: u32 = 2;
pub const ANCHORED_LINE_CAPTURE_ACCOUNTING_VERSION: u32 = 1;

const INSPECTION_STACK_CAPACITY: usize = 64;
const DIGEST_OFFSET_A: u64 = 0xcbf2_9ce4_8422_2325;
const DIGEST_OFFSET_B: u64 = 0x8422_2325_cbf2_9ce4;
const DIGEST_PRIME_A: u64 = 0x0000_0100_0000_01b3;
const DIGEST_PRIME_B: u64 = 0x0000_0100_0000_01cf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredLineCaptureBuildLimits {
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
    pub max_inspection_work: usize,
    pub max_hir_nodes: usize,
    pub max_stack_items: usize,
    pub max_class_ranges: usize,
    pub max_literal_bytes: usize,
    pub max_repetitions: usize,
    pub max_atoms: usize,
    pub max_captures: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for AnchoredLineCaptureBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_inspection_work: 8_192,
            max_hir_nodes: 1_024,
            max_stack_items: INSPECTION_STACK_CAPACITY,
            max_class_ranges: 1_024,
            max_literal_bytes: 4_096,
            max_repetitions: ANCHORED_LINE_CAPTURE_MAX_ATOMS,
            max_atoms: ANCHORED_LINE_CAPTURE_MAX_ATOMS,
            max_captures: 64,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredLineCaptureHirAccounting {
    pub hir_nodes: usize,
    pub max_stack_items: usize,
    pub class_ranges: usize,
    pub literal_bytes: usize,
    pub repetitions: usize,
    pub captures: usize,
    pub emitted_atoms: usize,
    pub inspection_work: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredLineCapturePlanIdentity {
    pub profile: RustProfile,
    pub source_digest: [u64; 2],
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub kernel: AnchoredLineCaptureOperationIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredLineCaptureBuildReport {
    pub identity: AnchoredLineCapturePlanIdentity,
    pub hir: AnchoredLineCaptureHirAccounting,
    pub minimum_match_bytes: usize,
    pub explicit_captures: usize,
    pub groups_per_match: usize,
    pub kernel: KernelBuildAccounting,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum AnchoredLineCaptureBuildError {
    Syntax(fre_syntax::ParseError),
    Unsupported(&'static str),
    Resource {
        resource: &'static str,
        needed: usize,
        limit: usize,
    },
    Kernel(KernelBuildError),
    ArithmeticOverflow(&'static str),
    InternalInvariant(&'static str),
}

impl fmt::Display for AnchoredLineCaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "anchored line-capture syntax: {error}"),
            Self::Unsupported(reason) => {
                write!(
                    formatter,
                    "unsupported anchored line-capture shape: {reason}"
                )
            }
            Self::Resource {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "anchored line-capture {resource} needs {needed}, limit is {limit}"
            ),
            Self::Kernel(error) => write!(formatter, "anchored line-capture kernel: {error}"),
            Self::ArithmeticOverflow(computation) => write!(
                formatter,
                "anchored line-capture overflow while computing {computation}"
            ),
            Self::InternalInvariant(message) => {
                write!(formatter, "anchored line-capture invariant: {message}")
            }
        }
    }
}

impl std::error::Error for AnchoredLineCaptureBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Kernel(error) => Some(error),
            Self::Unsupported(_)
            | Self::Resource { .. }
            | Self::ArithmeticOverflow(_)
            | Self::InternalInvariant(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AnchoredLineCaptureBuilder {
    pattern: String,
    profile: RustProfile,
    limits: AnchoredLineCaptureBuildLimits,
}

impl AnchoredLineCaptureBuilder {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: AnchoredLineCaptureBuildLimits::default(),
        }
    }

    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: AnchoredLineCaptureBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build(self) -> Result<AnchoredLineCapturePlan, AnchoredLineCaptureBuildError> {
        if self.profile.options.unicode {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "Unicode mode must be disabled",
            ));
        }
        if self.profile.options.case_insensitive {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "case-insensitive mode is not deterministic byte identity",
            ));
        }
        let profile = self.profile;
        let parsed = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(
                self.pattern,
                CompatibilityProfile::RustBytes(profile.clone()),
            )
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(AnchoredLineCaptureBuildError::Syntax)?;
        let source_digest = digest_source(parsed.key.pattern.as_bytes());
        let summary = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(AnchoredLineCaptureBuildError::InternalInvariant(
                "Rust byte request produced a non-Rust HIR",
            ));
        };
        let mut inspection = Inspector::new(self.limits, source_digest);
        inspection.root(&rust.hir)?;
        let explicit_captures = usize::try_from(summary.captures)
            .map_err(|_| AnchoredLineCaptureBuildError::ArithmeticOverflow("explicit captures"))?;
        if explicit_captures != inspection.accounting.captures {
            return Err(AnchoredLineCaptureBuildError::InternalInvariant(
                "parse summary capture count differs from inspected mandatory captures",
            ));
        }
        if explicit_captures == 0 {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "capture reducer requires at least one explicit capture",
            ));
        }
        let kernel = KernelPlan::new(
            inspection.atoms,
            inspection.accounting.emitted_atoms,
            explicit_captures,
            inspection.require_line_end,
            inspection.digest.finish(),
            KernelBuildLimits {
                max_atoms: self.limits.max_atoms,
                max_captures: self.limits.max_captures,
                max_build_work: self.limits.max_inspection_work,
                max_persistent_bytes: self.limits.max_persistent_bytes,
                max_peak_bytes: self.limits.max_peak_bytes,
            },
        )
        .map_err(map_kernel_build_error)?;
        let kernel_accounting = kernel.build_accounting();
        let persistent_bytes = size_of::<AnchoredLineCapturePlan>();
        enforce_resource(
            "persistent bytes",
            persistent_bytes,
            self.limits.max_persistent_bytes,
        )?;
        enforce_resource("peak bytes", persistent_bytes, self.limits.max_peak_bytes)?;
        let kernel_identity = kernel.identity();
        if kernel_identity.plan_id != ANCHORED_LINE_CAPTURE_PLAN_ID
            || kernel_identity.operation_id != ANCHORED_LINE_CAPTURE_COUNT_OPERATION_ID
            || kernel_identity.atom_count != inspection.accounting.emitted_atoms
            || kernel_identity.explicit_captures != explicit_captures
        {
            return Err(AnchoredLineCaptureBuildError::InternalInvariant(
                "kernel identity differs from inspected HIR",
            ));
        }
        let report = AnchoredLineCaptureBuildReport {
            identity: AnchoredLineCapturePlanIdentity {
                profile,
                source_digest,
                algorithm_version: ANCHORED_LINE_CAPTURE_ALGORITHM_VERSION,
                accounting_version: ANCHORED_LINE_CAPTURE_ACCOUNTING_VERSION,
                kernel: kernel_identity,
            },
            hir: inspection.accounting,
            minimum_match_bytes: kernel_identity.minimum_match_bytes,
            explicit_captures,
            groups_per_match: kernel_identity.groups_per_match,
            kernel: kernel_accounting,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        };
        Ok(AnchoredLineCapturePlan { kernel, report })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredLineCapturePlan {
    kernel: KernelPlan,
    report: AnchoredLineCaptureBuildReport,
}

impl AnchoredLineCapturePlan {
    #[must_use]
    pub const fn build_report(&self) -> &AnchoredLineCaptureBuildReport {
        &self.report
    }

    pub fn grep_capture_count(
        &self,
        haystack: &[u8],
        limits: AnchoredLineCaptureRunLimits,
    ) -> Result<AnchoredLineCaptureCountResult, AnchoredLineCaptureRunError> {
        self.kernel.count(haystack, limits)
    }
}

fn enforce_resource(
    resource: &'static str,
    needed: usize,
    limit: usize,
) -> Result<(), AnchoredLineCaptureBuildError> {
    if needed > limit {
        return Err(AnchoredLineCaptureBuildError::Resource {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn map_kernel_build_error(error: KernelBuildError) -> AnchoredLineCaptureBuildError {
    match error {
        KernelBuildError::AtomLimit { needed, limit } => AnchoredLineCaptureBuildError::Resource {
            resource: "atoms",
            needed,
            limit,
        },
        KernelBuildError::CaptureLimit { needed, limit } => {
            AnchoredLineCaptureBuildError::Resource {
                resource: "captures",
                needed,
                limit,
            }
        }
        KernelBuildError::WorkLimit { needed, limit } => AnchoredLineCaptureBuildError::Resource {
            resource: "kernel build work",
            needed,
            limit,
        },
        KernelBuildError::PersistentLimit { needed, limit } => {
            AnchoredLineCaptureBuildError::Resource {
                resource: "kernel persistent bytes",
                needed,
                limit,
            }
        }
        KernelBuildError::PeakLimit { needed, limit } => AnchoredLineCaptureBuildError::Resource {
            resource: "kernel peak bytes",
            needed,
            limit,
        },
        KernelBuildError::ArithmeticOverflow { computation } => {
            AnchoredLineCaptureBuildError::ArithmeticOverflow(computation)
        }
        KernelBuildError::EmptyPlan
        | KernelBuildError::EmptyMask { .. }
        | KernelBuildError::InvalidRepeat { .. }
        | KernelBuildError::ZeroWidthMatch
        | KernelBuildError::AmbiguousBoundary { .. }
        | KernelBuildError::NonPositiveBoundary { .. }
        | KernelBuildError::ReversedRange { .. } => AnchoredLineCaptureBuildError::Unsupported(
            "kernel rejected a non-deterministic or nullable atom sequence",
        ),
        other => AnchoredLineCaptureBuildError::Kernel(other),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StructuralDigest {
    words: [u64; 2],
}

impl StructuralDigest {
    const fn new(source: [u64; 2]) -> Self {
        Self { words: source }
    }

    fn byte(&mut self, byte: u8) {
        self.words[0] = (self.words[0] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_A);
        self.words[1] = (self.words[1] ^ u64::from(byte)).wrapping_mul(DIGEST_PRIME_B);
    }

    fn u32(&mut self, value: u32) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    fn usize(&mut self, value: usize) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    const fn finish(self) -> [u64; 2] {
        self.words
    }
}

fn digest_source(source: &[u8]) -> [u64; 2] {
    let mut digest = StructuralDigest {
        words: [DIGEST_OFFSET_A, DIGEST_OFFSET_B],
    };
    digest.byte(0x53);
    digest.usize(source.len());
    for &byte in source {
        digest.byte(byte);
    }
    digest.finish()
}

#[derive(Debug)]
struct Inspector {
    limits: AnchoredLineCaptureBuildLimits,
    atoms: [AnchoredLineCaptureAtom; ANCHORED_LINE_CAPTURE_MAX_ATOMS],
    accounting: AnchoredLineCaptureHirAccounting,
    require_line_end: bool,
    digest: StructuralDigest,
}

impl Inspector {
    fn new(limits: AnchoredLineCaptureBuildLimits, source_digest: [u64; 2]) -> Self {
        Self {
            limits,
            atoms: [AnchoredLineCaptureAtom::default(); ANCHORED_LINE_CAPTURE_MAX_ATOMS],
            accounting: AnchoredLineCaptureHirAccounting {
                hir_nodes: 0,
                max_stack_items: 0,
                class_ranges: 0,
                literal_bytes: 0,
                repetitions: 0,
                captures: 0,
                emitted_atoms: 0,
                inspection_work: 0,
            },
            require_line_end: false,
            digest: StructuralDigest::new(source_digest),
        }
    }

    fn root(&mut self, hir: &Hir) -> Result<(), AnchoredLineCaptureBuildError> {
        self.node()?;
        let HirKind::Concat(children) = hir.kind() else {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "root must be a concatenation",
            ));
        };
        let Some((first, body)) = children.split_first() else {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "root concatenation is empty",
            ));
        };
        self.node()?;
        if !matches!(first.kind(), HirKind::Look(Look::Start)) {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "root must begin with absolute Start",
            ));
        }
        self.digest.byte(0x01);
        let (body, require_line_end) = body
            .split_last()
            .filter(|(last, _)| matches!(last.kind(), HirKind::Look(Look::End)))
            .map_or((body, false), |(_, prefix)| (prefix, true));
        self.require_line_end = require_line_end;
        self.digest.byte(u8::from(require_line_end));
        for child in body {
            match child.kind() {
                HirKind::Capture(capture) => {
                    self.node()?;
                    self.accounting.captures = self.accounting.captures.checked_add(1).ok_or(
                        AnchoredLineCaptureBuildError::ArithmeticOverflow("capture count"),
                    )?;
                    enforce_resource(
                        "captures",
                        self.accounting.captures,
                        self.limits.max_captures,
                    )?;
                    self.charge(1)?;
                    self.digest.byte(0x02);
                    self.digest.u32(capture.index);
                    self.flatten(capture.sub.as_ref())?;
                    self.digest.byte(0x03);
                }
                _ => self.flatten(child)?,
            }
        }
        if self.accounting.emitted_atoms == 0 {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "root has no consuming atoms",
            ));
        }
        Ok(())
    }

    fn flatten(&mut self, root: &Hir) -> Result<(), AnchoredLineCaptureBuildError> {
        let stack_limit = self.limits.max_stack_items.min(INSPECTION_STACK_CAPACITY);
        if stack_limit == 0 {
            return Err(AnchoredLineCaptureBuildError::Resource {
                resource: "inspection stack items",
                needed: 1,
                limit: 0,
            });
        }
        let mut stack: [Option<&Hir>; INSPECTION_STACK_CAPACITY] =
            [None; INSPECTION_STACK_CAPACITY];
        stack[0] = Some(root);
        let mut stack_len = 1_usize;
        self.accounting.max_stack_items = self.accounting.max_stack_items.max(stack_len);
        while stack_len != 0 {
            stack_len = stack_len.checked_sub(1).ok_or(
                AnchoredLineCaptureBuildError::InternalInvariant(
                    "nonempty inspection stack underflowed",
                ),
            )?;
            let current =
                stack[stack_len]
                    .take()
                    .ok_or(AnchoredLineCaptureBuildError::InternalInvariant(
                        "inspection stack slot was empty",
                    ))?;
            self.node()?;
            match current.kind() {
                HirKind::Literal(literal) => {
                    self.literal(literal.0.as_ref())?;
                }
                HirKind::Class(Class::Bytes(class)) => {
                    let mask = self.byte_class(
                        class
                            .ranges()
                            .iter()
                            .map(|range| (range.start(), range.end())),
                    )?;
                    self.emit(AnchoredLineCaptureAtom::new(mask, 1, Some(1)))?;
                }
                HirKind::Repetition(repetition) => {
                    self.repetition(repetition)?;
                }
                HirKind::Concat(children) if !children.is_empty() => {
                    let needed = stack_len.checked_add(children.len()).ok_or(
                        AnchoredLineCaptureBuildError::ArithmeticOverflow("inspection stack items"),
                    )?;
                    if needed > stack_limit {
                        return Err(AnchoredLineCaptureBuildError::Resource {
                            resource: "inspection stack items",
                            needed,
                            limit: stack_limit,
                        });
                    }
                    for child in children.iter().rev() {
                        stack[stack_len] = Some(child);
                        stack_len = stack_len.checked_add(1).ok_or(
                            AnchoredLineCaptureBuildError::ArithmeticOverflow(
                                "inspection stack items",
                            ),
                        )?;
                    }
                    self.accounting.max_stack_items =
                        self.accounting.max_stack_items.max(stack_len);
                    self.digest.byte(0x30);
                    self.digest.usize(children.len());
                }
                HirKind::Empty => {
                    return Err(AnchoredLineCaptureBuildError::Unsupported(
                        "empty constructs are not admitted",
                    ));
                }
                HirKind::Class(Class::Unicode(_)) => {
                    return Err(AnchoredLineCaptureBuildError::Unsupported(
                        "Unicode classes are not byte masks",
                    ));
                }
                HirKind::Look(_) => {
                    return Err(AnchoredLineCaptureBuildError::Unsupported(
                        "only the leading absolute Start look is admitted",
                    ));
                }
                HirKind::Capture(_) => {
                    return Err(AnchoredLineCaptureBuildError::Unsupported(
                        "captures must be direct root-concatenation children",
                    ));
                }
                HirKind::Alternation(_) => {
                    return Err(AnchoredLineCaptureBuildError::Unsupported(
                        "alternation is not a deterministic atom sequence",
                    ));
                }
                HirKind::Concat(_) => {
                    return Err(AnchoredLineCaptureBuildError::Unsupported(
                        "empty concatenations are not admitted",
                    ));
                }
            }
        }
        Ok(())
    }

    fn repetition(&mut self, repetition: &Repetition) -> Result<(), AnchoredLineCaptureBuildError> {
        if !repetition.greedy {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "lazy repetitions are not deterministic greedy atoms",
            ));
        }
        self.accounting.repetitions = self.accounting.repetitions.checked_add(1).ok_or(
            AnchoredLineCaptureBuildError::ArithmeticOverflow("repetition count"),
        )?;
        enforce_resource(
            "repetitions",
            self.accounting.repetitions,
            self.limits.max_repetitions,
        )?;
        self.charge(2)?;
        self.digest.byte(0x20);
        self.digest.u32(repetition.min);
        self.digest.u32(repetition.max.unwrap_or(u32::MAX));
        self.node()?;
        let mask = match repetition.sub.kind() {
            HirKind::Literal(literal) if literal.0.len() == 1 => {
                self.account_literal_bytes(1)?;
                AnchoredLineCaptureByteMask::singleton(literal.0[0])
            }
            HirKind::Class(Class::Bytes(class)) => self.byte_class(
                class
                    .ranges()
                    .iter()
                    .map(|range| (range.start(), range.end())),
            )?,
            _ => {
                return Err(AnchoredLineCaptureBuildError::Unsupported(
                    "repetition body must be one literal byte or byte class",
                ));
            }
        };
        self.emit(AnchoredLineCaptureAtom::new(
            mask,
            repetition.min,
            repetition.max,
        ))
    }

    fn literal(&mut self, bytes: &[u8]) -> Result<(), AnchoredLineCaptureBuildError> {
        if bytes.is_empty() {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "empty literals are not admitted",
            ));
        }
        self.account_literal_bytes(bytes.len())?;
        self.digest.byte(0x10);
        self.digest.usize(bytes.len());
        for &byte in bytes {
            self.digest.byte(byte);
            self.emit(AnchoredLineCaptureAtom::new(
                AnchoredLineCaptureByteMask::singleton(byte),
                1,
                Some(1),
            ))?;
        }
        Ok(())
    }

    fn account_literal_bytes(&mut self, count: usize) -> Result<(), AnchoredLineCaptureBuildError> {
        self.accounting.literal_bytes = self.accounting.literal_bytes.checked_add(count).ok_or(
            AnchoredLineCaptureBuildError::ArithmeticOverflow("literal bytes"),
        )?;
        enforce_resource(
            "literal bytes",
            self.accounting.literal_bytes,
            self.limits.max_literal_bytes,
        )?;
        self.charge(count)
    }

    fn byte_class(
        &mut self,
        ranges: impl Iterator<Item = (u8, u8)>,
    ) -> Result<AnchoredLineCaptureByteMask, AnchoredLineCaptureBuildError> {
        let mut mask = AnchoredLineCaptureByteMask::empty();
        let mut saw_range = false;
        self.digest.byte(0x11);
        for (start, end) in ranges {
            saw_range = true;
            self.accounting.class_ranges = self.accounting.class_ranges.checked_add(1).ok_or(
                AnchoredLineCaptureBuildError::ArithmeticOverflow("class ranges"),
            )?;
            enforce_resource(
                "class ranges",
                self.accounting.class_ranges,
                self.limits.max_class_ranges,
            )?;
            self.charge(1)?;
            self.digest.byte(start);
            self.digest.byte(end);
            mask.insert_range(start, end)
                .map_err(AnchoredLineCaptureBuildError::Kernel)?;
        }
        if !saw_range {
            return Err(AnchoredLineCaptureBuildError::Unsupported(
                "empty byte classes are not admitted",
            ));
        }
        Ok(mask)
    }

    fn emit(&mut self, atom: AnchoredLineCaptureAtom) -> Result<(), AnchoredLineCaptureBuildError> {
        let needed = self.accounting.emitted_atoms.checked_add(1).ok_or(
            AnchoredLineCaptureBuildError::ArithmeticOverflow("emitted atoms"),
        )?;
        let limit = self.limits.max_atoms.min(ANCHORED_LINE_CAPTURE_MAX_ATOMS);
        if needed > limit {
            return Err(AnchoredLineCaptureBuildError::Resource {
                resource: "atoms",
                needed,
                limit,
            });
        }
        self.atoms[self.accounting.emitted_atoms] = atom;
        self.accounting.emitted_atoms = needed;
        self.charge(1)?;
        self.digest.byte(0x40);
        self.digest.u32(atom.minimum());
        self.digest.u32(atom.maximum().unwrap_or(u32::MAX));
        for word in atom.mask().words() {
            for byte in word.to_le_bytes() {
                self.digest.byte(byte);
            }
        }
        Ok(())
    }

    fn node(&mut self) -> Result<(), AnchoredLineCaptureBuildError> {
        self.accounting.hir_nodes = self.accounting.hir_nodes.checked_add(1).ok_or(
            AnchoredLineCaptureBuildError::ArithmeticOverflow("HIR nodes"),
        )?;
        enforce_resource(
            "HIR nodes",
            self.accounting.hir_nodes,
            self.limits.max_hir_nodes,
        )?;
        self.charge(1)
    }

    fn charge(&mut self, amount: usize) -> Result<(), AnchoredLineCaptureBuildError> {
        let needed = self.accounting.inspection_work.checked_add(amount).ok_or(
            AnchoredLineCaptureBuildError::ArithmeticOverflow("inspection work"),
        )?;
        if needed > self.limits.max_inspection_work {
            return Err(AnchoredLineCaptureBuildError::Resource {
                resource: "inspection work",
                needed,
                limit: self.limits.max_inspection_work,
            });
        }
        self.accounting.inspection_work = needed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::RegexBuilder;

    const TARGET: &str = r"^ *(\w+) +(\w+) +(\w+)";
    const DELIMITED_TARGET: &str = r"^([A-Z0-9]+);([^;]+);([^;]+);([0-9]+);([^;]+);([^;]*);([0-9]*);([0-9]*);([-0-9/]*);([YN]);([^;]*);([^;]*);([^;]*);([^;]*);([^;]*)$";

    fn build(pattern: &str) -> AnchoredLineCapturePlan {
        AnchoredLineCaptureBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .case_insensitive(false)
            .build()
            .unwrap()
    }

    fn line_ranges(haystack: &[u8], mut visit: impl FnMut(&[u8])) {
        let mut start = 0_usize;
        for (index, &byte) in haystack.iter().enumerate() {
            if byte != b'\n' {
                continue;
            }
            let mut end = index;
            let previous = end.checked_sub(1);
            if end > start && previous.is_some_and(|position| haystack[position] == b'\r') {
                end = previous.expect("positive line end has a predecessor");
            }
            visit(&haystack[start..end]);
            start = index
                .checked_add(1)
                .expect("enumerated byte index has a following boundary");
        }
        if start < haystack.len() {
            visit(&haystack[start..]);
        }
    }

    fn oracle(pattern: &str, haystack: &[u8]) -> usize {
        let regex = RegexBuilder::new(pattern)
            .unicode(false)
            .case_insensitive(false)
            .build()
            .unwrap();
        let mut count = 0_usize;
        line_ranges(haystack, |line| {
            for captures in regex.captures_iter(line) {
                count = count
                    .checked_add(captures.iter().flatten().count())
                    .expect("test oracle capture count fits usize");
            }
        });
        count
    }

    #[test]
    fn target_is_selected_without_source_special_casing() {
        let plan = build(TARGET);
        let report = plan.build_report();
        assert_eq!(report.explicit_captures, 3);
        assert_eq!(report.groups_per_match, 4);
        assert_eq!(report.minimum_match_bytes, 5);
        assert_eq!(report.hir.emitted_atoms, 6);
        assert_eq!(
            report.identity.kernel.operation_id,
            ANCHORED_LINE_CAPTURE_COUNT_OPERATION_ID
        );
        assert_eq!(report.kernel.allocations, 0);
        assert_eq!(report.kernel.scratch_bytes, 0);
    }

    #[test]
    fn generated_admissible_patterns_match_regex_bytes() {
        let patterns = [
            TARGET,
            r"^ *(a+) +(b+)",
            r"^([ab]{1,3}) +(z+)",
            r"^(ab)( +)([0-9]{2,4})",
            r"^(a*)b",
            r"^x{2}([A-Z]+)",
            r"^(.+)",
            r"^(a*);(b*)$",
        ];
        let alphabet = [
            b'a', b'b', b'z', b'0', b'9', b'A', b'Z', b'_', b' ', b'\r', b'\n', 0xFF,
        ];
        let alphabet_len = u64::try_from(alphabet.len()).unwrap();
        for pattern in patterns {
            let plan = build(pattern);
            for seed in 0_u64..256 {
                let mut state = seed.wrapping_add(1);
                let mut haystack = Vec::with_capacity(96);
                for _ in 0..96 {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    let index = usize::try_from(state % alphabet_len).unwrap();
                    haystack.push(alphabet[index]);
                }
                let actual = plan
                    .grep_capture_count(&haystack, AnchoredLineCaptureRunLimits::default())
                    .unwrap()
                    .capture_count;
                assert_eq!(
                    actual,
                    oracle(pattern, &haystack),
                    "{pattern:?} seed={seed}"
                );
            }
        }
    }

    #[test]
    fn delimited_empty_fields_and_terminal_end_match_regex_bytes() {
        let plan = build(DELIMITED_TARGET);
        let report = plan.build_report();
        assert_eq!(report.explicit_captures, 15);
        assert_eq!(report.groups_per_match, 16);
        assert!(report.identity.kernel.require_line_end);
        let haystack = b"0041;LATIN CAPITAL LETTER A;Lu;0;L;;;;;N;;;;0061;\n\
                         0000;<control>;Cc;0;BN;;;;;N;NULL;;;;\r\n\
                         BAD;missing;fields\n\
                         0042;LATIN CAPITAL LETTER B;Lu;0;L;;;;;N;;;;0062;;extra";
        let actual = plan
            .grep_capture_count(haystack, AnchoredLineCaptureRunLimits::default())
            .unwrap()
            .capture_count;
        assert_eq!(actual, oracle(DELIMITED_TARGET, haystack));
        assert_eq!(actual, 32);
    }

    #[test]
    fn raw_line_edge_cases_and_malformed_bytes_match_oracle() {
        let patterns = [TARGET, r"^(.+)"];
        let haystacks = [
            b"".as_slice(),
            b"\n".as_slice(),
            b"\r\n".as_slice(),
            b"a b c\n".as_slice(),
            b"a b c\r\n".as_slice(),
            b"a b c\r".as_slice(),
            b"\xFF x y\n\xC0\x80\r\n".as_slice(),
            b"\n\ntrailing".as_slice(),
        ];
        for pattern in patterns {
            let plan = build(pattern);
            for haystack in haystacks {
                let actual = plan
                    .grep_capture_count(haystack, AnchoredLineCaptureRunLimits::default())
                    .unwrap()
                    .capture_count;
                assert_eq!(
                    actual,
                    oracle(pattern, haystack),
                    "{pattern:?} {haystack:?}"
                );
            }
        }
    }

    #[test]
    fn unsupported_semantic_boundaries_are_typed_refusals() {
        for pattern in [
            r"(\w+)",
            r"^((a+))",
            r"^(a+|b+)",
            r"^(a+?) b",
            r"^(a+)a",
            r"^a*(?:b*)c",
            r"^(\w+)\b$",
        ] {
            assert!(
                matches!(
                    AnchoredLineCaptureBuilder::new(pattern)
                        .profile(RustProfile::rebar_1_12_4())
                        .unicode(false)
                        .build(),
                    Err(AnchoredLineCaptureBuildError::Unsupported(_)
                        | AnchoredLineCaptureBuildError::Kernel(_))
                ),
                "{pattern:?}"
            );
        }
        assert!(matches!(
            AnchoredLineCaptureBuilder::new(TARGET)
                .profile(RustProfile::rebar_1_12_4())
                .unicode(true)
                .build(),
            Err(AnchoredLineCaptureBuildError::Unsupported(_))
        ));
        assert!(matches!(
            AnchoredLineCaptureBuilder::new(TARGET)
                .profile(RustProfile::rebar_1_12_4())
                .unicode(false)
                .case_insensitive(true)
                .build(),
            Err(AnchoredLineCaptureBuildError::Unsupported(_))
        ));
    }

    #[test]
    fn build_caps_admit_exact_and_reject_one_below() {
        let exact = build(TARGET);
        let report = exact.build_report();
        let base = AnchoredLineCaptureBuildLimits::default();
        for limits in [
            AnchoredLineCaptureBuildLimits {
                max_inspection_work: report.hir.inspection_work - 1,
                ..base
            },
            AnchoredLineCaptureBuildLimits {
                max_hir_nodes: report.hir.hir_nodes - 1,
                ..base
            },
            AnchoredLineCaptureBuildLimits {
                max_stack_items: report.hir.max_stack_items - 1,
                ..base
            },
            AnchoredLineCaptureBuildLimits {
                max_class_ranges: report.hir.class_ranges - 1,
                ..base
            },
            AnchoredLineCaptureBuildLimits {
                max_atoms: report.hir.emitted_atoms - 1,
                ..base
            },
            AnchoredLineCaptureBuildLimits {
                max_captures: report.explicit_captures - 1,
                ..base
            },
            AnchoredLineCaptureBuildLimits {
                max_persistent_bytes: report.persistent_bytes - 1,
                ..base
            },
            AnchoredLineCaptureBuildLimits {
                max_peak_bytes: report.peak_bytes - 1,
                ..base
            },
        ] {
            assert!(matches!(
                AnchoredLineCaptureBuilder::new(TARGET)
                    .profile(RustProfile::rebar_1_12_4())
                    .unicode(false)
                    .limits(limits)
                    .build(),
                Err(AnchoredLineCaptureBuildError::Resource { .. }
                    | AnchoredLineCaptureBuildError::Kernel(_))
            ));
        }
    }
}
