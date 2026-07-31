//! Inert source-first AOT compilation for proved byte-class runs.
//!
//! This is the first Search AOT source surface beyond exact literals. It
//! accepts only capture-free Rust-bytes patterns whose canonical HIR is:
//!
//! ```text
//! (\A)? BYTE_CLASS+ NONEMPTY_LITERAL_SUFFIX (\z)?
//! ```
//!
//! The first suffix byte must be outside the class. That disjoint-delimiter
//! proof makes the greedy run's maximal endpoint the leftmost-first match and
//! permits the existing monotonic Kernel IR/AArch64 lowering. Unsupported
//! patterns are typed refusals; this compiler never falls back to another
//! engine.
//!
//! The emitted payload is direct `AArch64` machine code produced by FRE's custom
//! emitter. This module does not invoke LLVM, a linker, executable-memory
//! publication, or runtime routing. Both object targets remain inert and
//! default-off.

use core::fmt;

#[cfg(test)]
use fre::PortableRegex;
use fre::{BuildError as PortableBuildError, BuildLimits, PortableBuilder, RustProfile};
use fre_aot_elf::{
    BindingIdentity as ElfBindingIdentity, BindingIdentityError as ElfBindingIdentityError,
    BuiltSearchObjectV1, ElfObjectError, ObjectLimitsV1,
};
use fre_aot_macho::{
    BindingIdentity as MachoBindingIdentity, BindingIdentityError as MachoBindingIdentityError,
    BuiltObject, ObjectError, ObjectLimits,
};
use fre_jit_aarch64::{
    ArtifactIdentity, BackendVersion, EmitError, EmitLimits, ImageStats, SearchBackendPolicy,
    emit_audited_with_backend,
};
use fre_kernel_ir::{
    AnchorFlags, BuildError as KernelBuildError, ByteClass, CacheIdentity, ProgramStats, Span,
    ValidateLimits, ValidatedProgram, build_class_suffix,
};
use fre_syntax::{
    AdmissionPolicy, CanonicalPattern, CompatibilityProfile, ParseError, ParseRequest,
    QuotaBounded, SafetyEnvelope, SyntaxQuotas,
};
use regex_syntax::hir::{Class, Hir, HirKind, Look};
use sha2::{Digest as _, Sha256};

use crate::SearchAotRuntimeAuthorityV1;

pub const AOT_CLASS_SUFFIX_COMPILER_VERSION_V1: u16 = 1;
pub const CLASS_SUFFIX_MAX_SOURCE_BYTES_V1: u64 = 4_096;
pub const CLASS_SUFFIX_MAX_SUFFIX_BYTES_V1: usize = 32;
pub const CLASS_SUFFIX_MAX_CLASS_RANGES_V1: usize = 32;
pub const CLASS_SUFFIX_MAX_HIR_NODES_V1: u64 = 64;
const CLASS_SUFFIX_MAX_NESTING_V1: u64 = 32;
const CLASS_SUFFIX_MAX_PARSE_WORK_V1: u64 = 16_384;
const CLASS_SUFFIX_MAX_TRAVERSAL_STACK_V1: u64 = 128;
const CLASS_SUFFIX_MAX_PLANNER_WORK_V1: u64 = 65_536;
const CLASS_SUFFIX_MAX_PORTABLE_BYTES_V1: usize = 8 << 20;
const BINDING_DOMAIN_V1: &[u8] = b"FRE-AOT-CLASS-SUFFIX-BINDING-V1\0\x01";
const SOURCE_DOMAIN_V1: &[u8] = b"FRE-AOT-CLASS-SUFFIX-SOURCE-V1\0\x01";

/// Inert object target. Neither variant grants runtime or routing authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassSuffixAotTargetV1 {
    MacosAarch64,
    LinuxAarch64,
}

impl ClassSuffixAotTargetV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::MacosAarch64 => 1,
            Self::LinuxAarch64 => 2,
        }
    }
}

/// Exact bounded HIR-shape refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClassSuffixShapeRefusalV1 {
    CapturesUnsupported,
    ShapeUnsupported,
    GreedyOneOrMoreRequired,
    ByteClassRequired,
    EmptyByteClass,
    TooManyClassRanges { observed: usize, limit: usize },
    EmptySuffix,
    SuffixTooLong { observed: usize, limit: usize },
    SuffixOverlapsClass { byte: u8 },
    ShapeWorkOverflow,
}

/// Typed compiler failure. There is no semantic fallback.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClassSuffixAotCompileErrorV1 {
    SourceBytesLimit { required: u64, limit: u64 },
    SourceCapacityLimit { required: u64, limit: u64 },
    InvalidUtf8Source,
    Syntax(ParseError),
    Portable(PortableBuildError),
    Shape(ClassSuffixShapeRefusalV1),
    Kernel(KernelBuildError),
    Emit(EmitError),
    MachoBinding(MachoBindingIdentityError),
    ElfBinding(ElfBindingIdentityError),
    MachoObject(ObjectError),
    ElfObject(ElfObjectError),
    ArithmeticOverflow { at: &'static str },
    ValidationMismatch { at: &'static str },
}

impl fmt::Display for ClassSuffixAotCompileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE class-suffix AOT compilation refused: {self:?}"
        )
    }
}

impl std::error::Error for ClassSuffixAotCompileErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Portable(error) => Some(error),
            Self::Kernel(error) => Some(error),
            Self::Emit(error) => Some(error),
            Self::MachoBinding(error) => Some(error),
            Self::ElfBinding(error) => Some(error),
            Self::MachoObject(error) => Some(error),
            Self::ElfObject(error) => Some(error),
            Self::SourceBytesLimit { .. }
            | Self::SourceCapacityLimit { .. }
            | Self::InvalidUtf8Source
            | Self::Shape(_)
            | Self::ArithmeticOverflow { .. }
            | Self::ValidationMismatch { .. } => None,
        }
    }
}

impl From<ParseError> for ClassSuffixAotCompileErrorV1 {
    fn from(error: ParseError) -> Self {
        Self::Syntax(error)
    }
}

impl From<PortableBuildError> for ClassSuffixAotCompileErrorV1 {
    fn from(error: PortableBuildError) -> Self {
        Self::Portable(error)
    }
}

impl From<KernelBuildError> for ClassSuffixAotCompileErrorV1 {
    fn from(error: KernelBuildError) -> Self {
        Self::Kernel(error)
    }
}

impl From<EmitError> for ClassSuffixAotCompileErrorV1 {
    fn from(error: EmitError) -> Self {
        Self::Emit(error)
    }
}

impl From<MachoBindingIdentityError> for ClassSuffixAotCompileErrorV1 {
    fn from(error: MachoBindingIdentityError) -> Self {
        Self::MachoBinding(error)
    }
}

impl From<ElfBindingIdentityError> for ClassSuffixAotCompileErrorV1 {
    fn from(error: ElfBindingIdentityError) -> Self {
        Self::ElfBinding(error)
    }
}

impl From<ObjectError> for ClassSuffixAotCompileErrorV1 {
    fn from(error: ObjectError) -> Self {
        Self::MachoObject(error)
    }
}

impl From<ElfObjectError> for ClassSuffixAotCompileErrorV1 {
    fn from(error: ElfObjectError) -> Self {
        Self::ElfObject(error)
    }
}

/// Platform object bytes retained without any executable publication handle.
#[derive(Debug, Eq, PartialEq)]
pub enum ClassSuffixAotObjectV1 {
    Macos(BuiltObject),
    Linux(BuiltSearchObjectV1),
}

impl ClassSuffixAotObjectV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Macos(object) => object.as_bytes(),
            Self::Linux(object) => object.as_bytes(),
        }
    }

    #[must_use]
    pub const fn target(&self) -> ClassSuffixAotTargetV1 {
        match self {
            Self::Macos(_) => ClassSuffixAotTargetV1::MacosAarch64,
            Self::Linux(_) => ClassSuffixAotTargetV1::LinuxAarch64,
        }
    }

    #[must_use]
    pub fn entry_symbol(&self) -> String {
        match self {
            Self::Macos(object) => object.exported_symbols().entry().as_str().to_owned(),
            Self::Linux(object) => object.exported_symbols().entry().as_str().to_owned(),
        }
    }

    #[must_use]
    pub fn metadata_symbol(&self) -> String {
        match self {
            Self::Macos(object) => object.exported_symbols().metadata().as_str().to_owned(),
            Self::Linux(object) => object.exported_symbols().metadata().as_str().to_owned(),
        }
    }

    #[must_use]
    pub const fn c_header(&self) -> &'static str {
        match self {
            Self::Macos(_) => fre_aot_macho::C_HEADER,
            Self::Linux(_) => fre_aot_elf::C_HEADER_V1,
        }
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Macos(object) => object.into_bytes(),
            Self::Linux(object) => object.into_bytes(),
        }
    }
}

/// Stable, allocation-free compiler receipt for one inert object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassSuffixAotReceiptV1 {
    target: ClassSuffixAotTargetV1,
    source_identity: [u8; 32],
    source_bytes: u64,
    anchors: AnchorFlags,
    class_lanes: [u64; 4],
    class_ranges: u16,
    class_members: u16,
    suffix_bytes: u16,
    kir_identity: CacheIdentity,
    kir_blocks: u16,
    kir_data_bytes: u16,
    artifact_identity: ArtifactIdentity,
    binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    object_bytes: u64,
    native_stats: ImageStats,
}

impl ClassSuffixAotReceiptV1 {
    #[must_use]
    pub const fn target(self) -> ClassSuffixAotTargetV1 {
        self.target
    }

    #[must_use]
    pub const fn source_identity(self) -> [u8; 32] {
        self.source_identity
    }

    #[must_use]
    pub const fn source_bytes(self) -> u64 {
        self.source_bytes
    }

    #[must_use]
    pub const fn anchors(self) -> AnchorFlags {
        self.anchors
    }

    #[must_use]
    pub const fn class_lanes(self) -> [u64; 4] {
        self.class_lanes
    }

    #[must_use]
    pub const fn class_ranges(self) -> u16 {
        self.class_ranges
    }

    #[must_use]
    pub const fn class_members(self) -> u16 {
        self.class_members
    }

    #[must_use]
    pub const fn suffix_bytes(self) -> u16 {
        self.suffix_bytes
    }

    #[must_use]
    pub const fn kir_identity(self) -> CacheIdentity {
        self.kir_identity
    }

    #[must_use]
    pub const fn artifact_identity(self) -> ArtifactIdentity {
        self.artifact_identity
    }

    #[must_use]
    pub const fn binding_identity(self) -> [u8; 32] {
        self.binding_identity
    }

    #[must_use]
    pub const fn compile_identity(self) -> [u8; 32] {
        self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(self) -> [u8; 32] {
        self.object_identity
    }

    #[must_use]
    pub const fn object_bytes(self) -> u64 {
        self.object_bytes
    }

    #[must_use]
    pub const fn native_stats(self) -> ImageStats {
        self.native_stats
    }

    #[must_use]
    pub const fn runtime_authority(self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }
}

/// Result of a full source reparse, KIR rebuild, native audit, object rebuild,
/// and byte-for-byte comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassSuffixAotValidationV1 {
    pub target: ClassSuffixAotTargetV1,
    pub source_identity: [u8; 32],
    pub object_identity: [u8; 32],
    pub object_bytes: u64,
}

/// Inert compiled object plus its closed receipt.
#[derive(Debug, Eq, PartialEq)]
pub struct ClassSuffixAotCompiledObjectV1 {
    object: ClassSuffixAotObjectV1,
    receipt: ClassSuffixAotReceiptV1,
}

impl ClassSuffixAotCompiledObjectV1 {
    #[must_use]
    pub const fn object(&self) -> &ClassSuffixAotObjectV1 {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> ClassSuffixAotReceiptV1 {
        self.receipt
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    /// Reparse the exact source, rebuild every compiler stage, independently
    /// audit the reconstructed image/object, and compare the supplied bytes.
    pub fn validate_object_bytes(
        &self,
        source: &[u8],
        object_bytes: &[u8],
    ) -> Result<ClassSuffixAotValidationV1, ClassSuffixAotCompileErrorV1> {
        let rebuilt = compile_for_target(self.receipt.target, source.to_vec())?;
        if rebuilt.receipt != self.receipt {
            return Err(ClassSuffixAotCompileErrorV1::ValidationMismatch {
                at: "compiler receipt",
            });
        }
        if rebuilt.object.as_bytes() != object_bytes {
            return Err(ClassSuffixAotCompileErrorV1::ValidationMismatch {
                at: "canonical object bytes",
            });
        }
        Ok(ClassSuffixAotValidationV1 {
            target: self.receipt.target,
            source_identity: self.receipt.source_identity,
            object_identity: self.receipt.object_identity,
            object_bytes: self.receipt.object_bytes,
        })
    }

    /// Validate the retained object against the original source.
    pub fn validate_against_source(
        &self,
        source: &[u8],
    ) -> Result<ClassSuffixAotValidationV1, ClassSuffixAotCompileErrorV1> {
        self.validate_object_bytes(source, self.object.as_bytes())
    }

    #[must_use]
    pub fn into_object_bytes(self) -> Vec<u8> {
        self.object.into_bytes()
    }
}

/// Compile one bounded Rust-bytes class-run pattern into inert Mach-O.
pub fn compile_macos_aarch64_class_suffix_span_v1(
    source: Vec<u8>,
) -> Result<ClassSuffixAotCompiledObjectV1, ClassSuffixAotCompileErrorV1> {
    compile_for_target(ClassSuffixAotTargetV1::MacosAarch64, source)
}

/// Compile one bounded Rust-bytes class-run pattern into inert ELF64LE.
pub fn compile_linux_aarch64_class_suffix_span_v1(
    source: Vec<u8>,
) -> Result<ClassSuffixAotCompiledObjectV1, ClassSuffixAotCompileErrorV1> {
    compile_for_target(ClassSuffixAotTargetV1::LinuxAarch64, source)
}

struct PreparedSource {
    source_identity: [u8; 32],
    source_bytes: u64,
    anchors: AnchorFlags,
    class: ByteClass,
    class_ranges: u16,
    class_members: u16,
    suffix_bytes: u16,
    program: ValidatedProgram<Span>,
    #[cfg(test)]
    portable: PortableRegex,
}

fn compile_for_target(
    target: ClassSuffixAotTargetV1,
    source: Vec<u8>,
) -> Result<ClassSuffixAotCompiledObjectV1, ClassSuffixAotCompileErrorV1> {
    let prepared = prepare_source(source)?;
    let kir_identity = prepared.program.cache_identity();
    let kir_stats = prepared.program.stats();
    let image = emit_audited_with_backend(
        &prepared.program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )?;
    let image = image.as_image();
    if image.backend_version() != BackendVersion::SEARCH_V8
        || image.source_identity() != kir_identity
    {
        return Err(ClassSuffixAotCompileErrorV1::ValidationMismatch {
            at: "audited native image",
        });
    }
    let binding_identity = binding_identity(
        target,
        prepared.source_identity,
        kir_identity,
        image.artifact_identity(),
        prepared.anchors,
        prepared.class.lanes(),
        prepared.suffix_bytes,
    );
    let (object, compile_identity, object_identity, object_bytes) = match target {
        ClassSuffixAotTargetV1::MacosAarch64 => {
            let binding = MachoBindingIdentity::new(binding_identity)?;
            let object =
                fre_aot_macho::emit_search_object(image, binding, ObjectLimits::default())?;
            fre_aot_macho::validate_search_object(
                image,
                binding,
                object.as_bytes(),
                ObjectLimits::default(),
            )?;
            let compile_identity = *object.compile_identity().as_bytes();
            let object_identity = *object.object_identity().as_bytes();
            let object_bytes = usize_u64(object.as_bytes().len(), "Mach-O object bytes")?;
            (
                ClassSuffixAotObjectV1::Macos(object),
                compile_identity,
                object_identity,
                object_bytes,
            )
        }
        ClassSuffixAotTargetV1::LinuxAarch64 => {
            let binding = ElfBindingIdentity::new(binding_identity)?;
            let object =
                fre_aot_elf::emit_search_object_v1(image, binding, ObjectLimitsV1::default())?;
            fre_aot_elf::validate_search_object_v1(
                image,
                binding,
                object.as_bytes(),
                ObjectLimitsV1::default(),
            )?;
            let compile_identity = *object.compile_identity().as_bytes();
            let object_identity = *object.object_identity().as_bytes();
            let object_bytes = usize_u64(object.as_bytes().len(), "ELF object bytes")?;
            (
                ClassSuffixAotObjectV1::Linux(object),
                compile_identity,
                object_identity,
                object_bytes,
            )
        }
    };
    let receipt = ClassSuffixAotReceiptV1 {
        target,
        source_identity: prepared.source_identity,
        source_bytes: prepared.source_bytes,
        anchors: prepared.anchors,
        class_lanes: prepared.class.lanes(),
        class_ranges: prepared.class_ranges,
        class_members: prepared.class_members,
        suffix_bytes: prepared.suffix_bytes,
        kir_identity,
        kir_blocks: usize_u16(kir_stats.blocks(), "KIR blocks")?,
        kir_data_bytes: usize_u16(kir_stats.data_bytes(), "KIR data bytes")?,
        artifact_identity: image.artifact_identity(),
        binding_identity,
        compile_identity,
        object_identity,
        object_bytes,
        native_stats: image.stats(),
    };
    if !receipt_closes(&receipt, kir_stats) || object.target() != target {
        return Err(ClassSuffixAotCompileErrorV1::ValidationMismatch {
            at: "fresh class-suffix receipt",
        });
    }
    Ok(ClassSuffixAotCompiledObjectV1 { object, receipt })
}

fn prepare_source(source: Vec<u8>) -> Result<PreparedSource, ClassSuffixAotCompileErrorV1> {
    let source_bytes = usize_u64(source.len(), "source bytes")?;
    let source_capacity = usize_u64(source.capacity(), "source capacity")?;
    if source_bytes > CLASS_SUFFIX_MAX_SOURCE_BYTES_V1 {
        return Err(ClassSuffixAotCompileErrorV1::SourceBytesLimit {
            required: source_bytes,
            limit: CLASS_SUFFIX_MAX_SOURCE_BYTES_V1,
        });
    }
    if source_capacity > CLASS_SUFFIX_MAX_SOURCE_BYTES_V1 {
        return Err(ClassSuffixAotCompileErrorV1::SourceCapacityLimit {
            required: source_capacity,
            limit: CLASS_SUFFIX_MAX_SOURCE_BYTES_V1,
        });
    }
    let source_identity = source_identity(&source);
    let source =
        String::from_utf8(source).map_err(|_| ClassSuffixAotCompileErrorV1::InvalidUtf8Source)?;
    let profile = bytes_profile();
    let admission = syntax_admission();
    let safety = syntax_safety();
    let parsed = fre_syntax::parse(
        ParseRequest::rust(
            source.clone(),
            CompatibilityProfile::RustBytes(profile.clone()),
        )
        .with_admission(admission)
        .with_safety_envelope(safety),
    )?;
    if parsed.summary.hir_nodes > CLASS_SUFFIX_MAX_HIR_NODES_V1 {
        return Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::ShapeUnsupported,
        ));
    }
    let _portable = PortableBuilder::new(source)
        .profile(profile)
        .limits(portable_build_limits())
        .build()?;
    let captures = parsed.summary.captures;
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return Err(ClassSuffixAotCompileErrorV1::ValidationMismatch {
            at: "Rust-bytes parser returned non-Rust HIR",
        });
    };
    if captures != 0 {
        return Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::CapturesUnsupported,
        ));
    }
    let shape = extract_shape(&parsed.hir)?;
    let program = build_class_suffix::<Span>(
        shape.class,
        &shape.suffix,
        shape.anchors,
        ValidateLimits::default(),
    )?;
    Ok(PreparedSource {
        source_identity,
        source_bytes,
        anchors: shape.anchors,
        class: shape.class,
        class_ranges: shape.class_ranges,
        class_members: shape.class_members,
        suffix_bytes: usize_u16(shape.suffix.len(), "suffix bytes")?,
        program,
        #[cfg(test)]
        portable: _portable,
    })
}

struct ExtractedShape {
    anchors: AnchorFlags,
    class: ByteClass,
    class_ranges: u16,
    class_members: u16,
    suffix: Vec<u8>,
}

fn extract_shape(hir: &Hir) -> Result<ExtractedShape, ClassSuffixAotCompileErrorV1> {
    let children = match hir.kind() {
        HirKind::Concat(children) => children.as_slice(),
        _ => {
            return Err(ClassSuffixAotCompileErrorV1::Shape(
                ClassSuffixShapeRefusalV1::ShapeUnsupported,
            ));
        }
    };
    let mut first = 0_usize;
    let mut last = children.len();
    let start = children
        .first()
        .is_some_and(|child| matches!(child.kind(), HirKind::Look(Look::Start)));
    if start {
        first = first
            .checked_add(1)
            .ok_or(ClassSuffixAotCompileErrorV1::Shape(
                ClassSuffixShapeRefusalV1::ShapeWorkOverflow,
            ))?;
    }
    let end = children
        .last()
        .is_some_and(|child| matches!(child.kind(), HirKind::Look(Look::End)));
    if end {
        last = last
            .checked_sub(1)
            .ok_or(ClassSuffixAotCompileErrorV1::Shape(
                ClassSuffixShapeRefusalV1::ShapeWorkOverflow,
            ))?;
    }
    let body = children
        .get(first..last)
        .ok_or(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::ShapeUnsupported,
        ))?;
    let [repeat_hir, suffix_hir] = body else {
        return Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::ShapeUnsupported,
        ));
    };
    let HirKind::Repetition(repetition) = repeat_hir.kind() else {
        return Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::GreedyOneOrMoreRequired,
        ));
    };
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::GreedyOneOrMoreRequired,
        ));
    }
    let (class, class_ranges, class_members) = byte_class(repetition.sub.as_ref())?;
    let HirKind::Literal(literal) = suffix_hir.kind() else {
        return Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::ShapeUnsupported,
        ));
    };
    if literal.0.is_empty() {
        return Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::EmptySuffix,
        ));
    }
    if literal.0.len() > CLASS_SUFFIX_MAX_SUFFIX_BYTES_V1 {
        return Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::SuffixTooLong {
                observed: literal.0.len(),
                limit: CLASS_SUFFIX_MAX_SUFFIX_BYTES_V1,
            },
        ));
    }
    if class.contains(literal.0[0]) {
        return Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::SuffixOverlapsClass { byte: literal.0[0] },
        ));
    }
    Ok(ExtractedShape {
        anchors: AnchorFlags { start, end },
        class,
        class_ranges,
        class_members,
        suffix: literal.0.to_vec(),
    })
}

fn byte_class(hir: &Hir) -> Result<(ByteClass, u16, u16), ClassSuffixAotCompileErrorV1> {
    match hir.kind() {
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            Ok((ByteClass::from_bytes(&literal.0), 1, 1))
        }
        HirKind::Class(Class::Bytes(class)) => {
            if class.ranges().is_empty() {
                return Err(ClassSuffixAotCompileErrorV1::Shape(
                    ClassSuffixShapeRefusalV1::EmptyByteClass,
                ));
            }
            if class.ranges().len() > CLASS_SUFFIX_MAX_CLASS_RANGES_V1 {
                return Err(ClassSuffixAotCompileErrorV1::Shape(
                    ClassSuffixShapeRefusalV1::TooManyClassRanges {
                        observed: class.ranges().len(),
                        limit: CLASS_SUFFIX_MAX_CLASS_RANGES_V1,
                    },
                ));
            }
            let mut members = Vec::new();
            members.try_reserve_exact(256).map_err(|_| {
                ClassSuffixAotCompileErrorV1::ValidationMismatch {
                    at: "bounded byte-class member allocation",
                }
            })?;
            for range in class.ranges() {
                for byte in range.start()..=range.end() {
                    members.push(byte);
                }
            }
            if members.is_empty() || members.len() > 256 {
                return Err(ClassSuffixAotCompileErrorV1::Shape(
                    ClassSuffixShapeRefusalV1::EmptyByteClass,
                ));
            }
            Ok((
                ByteClass::from_bytes(&members),
                usize_u16(class.ranges().len(), "class ranges")?,
                usize_u16(members.len(), "class members")?,
            ))
        }
        _ => Err(ClassSuffixAotCompileErrorV1::Shape(
            ClassSuffixShapeRefusalV1::ByteClassRequired,
        )),
    }
}

fn bytes_profile() -> RustProfile {
    let mut profile = RustProfile::regex_1_12_4();
    profile.options.unicode = false;
    profile.options.nest_limit =
        u32::try_from(CLASS_SUFFIX_MAX_NESTING_V1).expect("fixed nesting limit fits u32");
    profile
}

const fn syntax_quotas() -> SyntaxQuotas {
    SyntaxQuotas {
        max_pattern_bytes: CLASS_SUFFIX_MAX_SOURCE_BYTES_V1,
        max_nesting: CLASS_SUFFIX_MAX_NESTING_V1,
        max_hir_nodes: CLASS_SUFFIX_MAX_HIR_NODES_V1,
        max_parse_work: CLASS_SUFFIX_MAX_PARSE_WORK_V1,
        max_traversal_stack: CLASS_SUFFIX_MAX_TRAVERSAL_STACK_V1,
    }
}

const fn syntax_admission() -> AdmissionPolicy {
    AdmissionPolicy::Quota(QuotaBounded {
        syntax: syntax_quotas(),
    })
}

const fn syntax_safety() -> SafetyEnvelope {
    SafetyEnvelope {
        max_pattern_bytes: CLASS_SUFFIX_MAX_SOURCE_BYTES_V1,
        max_nesting: CLASS_SUFFIX_MAX_NESTING_V1,
        max_hir_nodes: CLASS_SUFFIX_MAX_HIR_NODES_V1,
        max_parse_work: CLASS_SUFFIX_MAX_PARSE_WORK_V1,
        max_traversal_stack: CLASS_SUFFIX_MAX_TRAVERSAL_STACK_V1,
    }
}

fn portable_build_limits() -> BuildLimits {
    BuildLimits {
        admission: syntax_admission(),
        syntax_safety: syntax_safety(),
        max_planner_work: CLASS_SUFFIX_MAX_PLANNER_WORK_V1,
        max_persistent_bytes: CLASS_SUFFIX_MAX_PORTABLE_BYTES_V1,
        ..BuildLimits::default()
    }
}

fn source_identity(source: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_DOMAIN_V1);
    hasher.update(
        u64::try_from(source.len())
            .expect("source hard limit fits u64")
            .to_le_bytes(),
    );
    hasher.update(source);
    hasher.finalize().into()
}

fn binding_identity(
    target: ClassSuffixAotTargetV1,
    source_identity: [u8; 32],
    kir_identity: CacheIdentity,
    artifact_identity: ArtifactIdentity,
    anchors: AnchorFlags,
    class_lanes: [u64; 4],
    suffix_bytes: u16,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN_V1);
    hasher.update(AOT_CLASS_SUFFIX_COMPILER_VERSION_V1.to_le_bytes());
    hasher.update([target.tag(), u8::from(anchors.start), u8::from(anchors.end)]);
    hasher.update(source_identity);
    hasher.update(kir_identity.as_bytes());
    hasher.update(artifact_identity.as_bytes());
    for lane in class_lanes {
        hasher.update(lane.to_le_bytes());
    }
    hasher.update(suffix_bytes.to_le_bytes());
    hasher.finalize().into()
}

fn receipt_closes(receipt: &ClassSuffixAotReceiptV1, stats: ProgramStats) -> bool {
    receipt.source_bytes <= CLASS_SUFFIX_MAX_SOURCE_BYTES_V1
        && receipt.class_ranges != 0
        && usize::from(receipt.class_ranges) <= CLASS_SUFFIX_MAX_CLASS_RANGES_V1
        && receipt.class_members != 0
        && receipt.class_members <= 256
        && receipt.suffix_bytes != 0
        && usize::from(receipt.suffix_bytes) <= CLASS_SUFFIX_MAX_SUFFIX_BYTES_V1
        && receipt.kir_blocks == 7
        && usize::from(receipt.kir_blocks) == stats.blocks()
        && usize::from(receipt.kir_data_bytes) == stats.data_bytes()
        && receipt.native_stats.code_bytes != 0
        && receipt.native_stats.data_bytes >= u32::from(receipt.suffix_bytes).saturating_add(32)
        && receipt.object_bytes != 0
        && receipt.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, ClassSuffixAotCompileErrorV1> {
    u64::try_from(value).map_err(|_| ClassSuffixAotCompileErrorV1::ArithmeticOverflow { at })
}

fn usize_u16(value: usize, at: &'static str) -> Result<u16, ClassSuffixAotCompileErrorV1> {
    u16::try_from(value).map_err(|_| ClassSuffixAotCompileErrorV1::ArithmeticOverflow { at })
}

#[cfg(test)]
mod tests {
    use fre::{SearchLimits, SearchWindow as FreSearchWindow};
    use fre_kernel_ir::{ExecutionLimits, MatchSpan, SearchWindow as KirSearchWindow};

    use super::*;

    #[test]
    fn both_targets_are_deterministic_inert_and_independently_reopen() {
        let source = br"\A[0-3_]+END\z";
        for compile in [
            compile_macos_aarch64_class_suffix_span_v1
                as fn(Vec<u8>) -> Result<_, ClassSuffixAotCompileErrorV1>,
            compile_linux_aarch64_class_suffix_span_v1,
        ] {
            let first = compile(source.to_vec()).expect("first class-suffix object");
            let second = compile(source.to_vec()).expect("second class-suffix object");
            assert_eq!(first, second);
            assert_eq!(
                first.runtime_authority(),
                SearchAotRuntimeAuthorityV1::Absent
            );
            assert_eq!(
                first.receipt().runtime_authority(),
                SearchAotRuntimeAuthorityV1::Absent
            );
            assert_eq!(
                first.receipt().anchors(),
                AnchorFlags {
                    start: true,
                    end: true
                }
            );
            assert_eq!(first.receipt().suffix_bytes(), 3);
            assert_eq!(first.receipt().class_ranges(), 2);
            let validation = first
                .validate_against_source(source)
                .expect("source-bound independent validation");
            assert_eq!(
                validation.object_identity,
                first.receipt().object_identity()
            );
            let mut changed = first.object().as_bytes().to_vec();
            let changed_index = changed.len() / 2;
            changed[changed_index] ^= 1;
            assert!(first.validate_object_bytes(source, &changed).is_err());
            assert!(first.validate_against_source(br"\A[0-4_]+END\z").is_err());
        }

        let vector_suffix = format!("[A-F]+{}", "z".repeat(CLASS_SUFFIX_MAX_SUFFIX_BYTES_V1));
        for compile in [
            compile_macos_aarch64_class_suffix_span_v1
                as fn(Vec<u8>) -> Result<_, ClassSuffixAotCompileErrorV1>,
            compile_linux_aarch64_class_suffix_span_v1,
        ] {
            let compiled = compile(vector_suffix.as_bytes().to_vec())
                .expect("full-width confirmation class-suffix object");
            assert_eq!(
                compiled.receipt().suffix_bytes(),
                u16::try_from(CLASS_SUFFIX_MAX_SUFFIX_BYTES_V1).expect("fixed suffix width")
            );
            compiled
                .validate_against_source(vector_suffix.as_bytes())
                .expect("full-width source-bound independent validation");
        }
    }

    #[test]
    fn typed_refusals_cover_unsafe_or_broader_shapes() {
        for source in [
            br"[a-z]+apple".as_slice(),
            br"[a-z]*Z",
            br"[a-z]+?Z",
            br"([a-z]+)Z",
            br"(?:[a-z]+Z)|(?:[0-9]+Q)",
            br"[a-z]+[0-9]",
        ] {
            assert!(
                matches!(
                    compile_macos_aarch64_class_suffix_span_v1(source.to_vec()),
                    Err(ClassSuffixAotCompileErrorV1::Shape(_))
                ),
                "{source:?}"
            );
        }
        let long_suffix = format!("[a]+Z{}", "q".repeat(CLASS_SUFFIX_MAX_SUFFIX_BYTES_V1));
        assert!(matches!(
            compile_macos_aarch64_class_suffix_span_v1(long_suffix.into_bytes()),
            Err(ClassSuffixAotCompileErrorV1::Shape(
                ClassSuffixShapeRefusalV1::SuffixTooLong { .. }
            ))
        ));
        let mut over_capacity = Vec::with_capacity(
            usize::try_from(CLASS_SUFFIX_MAX_SOURCE_BYTES_V1).expect("limit fits usize") + 1,
        );
        over_capacity.extend_from_slice(b"[a]+Z");
        assert!(matches!(
            compile_macos_aarch64_class_suffix_span_v1(over_capacity),
            Err(ClassSuffixAotCompileErrorV1::SourceCapacityLimit { .. })
        ));
    }

    #[test]
    fn unseen_pattern_matrix_matches_portable_semantics_for_every_window() {
        let patterns = [
            r"[a-c]+Z",
            r"[0-7_]+END",
            r"\A[\x80-\x83]+!",
            r"[^\x00-\xfe]+\x00",
            r"[ab]+Q\z",
            r"\A[13579]+even\z",
            r"[A-F0-3]+g",
            r"\x7f+\x00tail",
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for pattern in patterns {
            let prepared = prepare_source(pattern.as_bytes().to_vec()).expect(pattern);
            for length in 0..48 {
                let mut haystack = Vec::with_capacity(length);
                for _ in 0..length {
                    seed ^= seed << 7;
                    seed ^= seed >> 9;
                    seed ^= seed << 8;
                    haystack.push(seed.to_le_bytes()[0]);
                }
                for start in 0..=length {
                    for end in start..=length {
                        let portable = prepared
                            .portable
                            .find_window(
                                &haystack,
                                FreSearchWindow::new(start, end),
                                SearchLimits::unlimited(),
                            )
                            .expect("portable bounded search")
                            .0
                            .map(|matched| MatchSpan::new(matched.start(), matched.end()));
                        let kir = prepared
                            .program
                            .execute(
                                &haystack,
                                KirSearchWindow::new(start, end),
                                ExecutionLimits::unlimited(),
                            )
                            .expect("KIR bounded search")
                            .into_output();
                        assert_eq!(
                            kir, portable,
                            "pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                        );
                    }
                }
            }
        }
    }
}
