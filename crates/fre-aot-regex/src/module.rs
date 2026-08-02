//! Target description and the object-writer-neutral compiled module.
//!
//! Fast semantic programs are frozen in read-only data behind a small ABI
//! adapter to the versioned runtime. Complete optimized DFAs instead lower to
//! self-contained PIC machine code and compact transition tables. Native
//! optimizations are derived from DFA structure, including a start-state byte
//! filter selected solely from non-accepting self-loop behavior.

use core::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::{
    CompileError, ObjectError,
    bounded_suffix_retry::{
        BoundedSuffixRetryPlan, select_bounded_interior_retry, select_bounded_suffix_retry,
    },
    prefix_block::{self, PREFIX_BLOCK_ALIGNMENT, PREFIX_BLOCK_SERIALIZED_BYTES, PrefixBlockPlan},
    prefix_fast_forward,
    prefix_predicate::{
        AARCH64_SCALAR_PREFIX_COSTS, PrefixPredicateInput, ScalarPrefixConjunctionPlan,
        ScalarPrefixMembership, ScalarPrefixPredicateCosts, ScalarPrefixRangePlan,
        X86_64_SCALAR_PREFIX_COSTS, plan_scalar_prefix_predicates,
    },
    prefix_relation::{self, PrefixRelation},
    program::{
        AnchoredByteSet, CompiledProgram, MAX_ANCHORED_PREFIX_BYTES, NativeContextProgramView,
        NativeProgramView, OutputContract,
    },
    required_literals::{MaximumConsumedDistance, RequiredInteriorCandidate, RequiredLiteralSet},
    seeded_reverse::{
        SeededReverseBuild, SeededReverseDfa, SeededReverseLimits, SeededReverseSeed,
        build_seeded_reverse_exact,
    },
};

#[path = "module_context.rs"]
mod module_context;
#[path = "module_dfa_loop_skip.rs"]
mod module_dfa_loop_skip;
#[path = "module_seeded_reverse_aarch64.rs"]
mod module_seeded_reverse_aarch64;
#[path = "module_suffix_retry.rs"]
mod module_suffix_retry;

/// Machine architecture accepted by the general AOT object pipeline.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Architecture {
    X86_64,
    Aarch64,
}

/// Operating system whose object and symbol conventions are requested.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperatingSystem {
    Linux,
    Macos,
}

/// C calling convention used by the emitted entry point.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CallAbi {
    /// The AMD64 System V ABI used by Linux and macOS.
    SystemV,
    /// The `AArch64` procedure call standard used by Linux and macOS.
    Aapcs64,
}

/// One independently represented target CPU feature.
///
/// This is a vocabulary, not an ordered list of optimization levels. In
/// particular, AVX-512 subfeatures remain separate facts so a future lowering
/// can request exactly the instructions it emits.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CpuFeature {
    X86Sse2 = 0,
    X86Avx2 = 1,
    X86Avx512F = 2,
    X86Avx512Bw = 3,
    X86Avx512Vl = 4,
    Aarch64Asimd = 32,
    Aarch64Sve = 33,
    Aarch64Sve2 = 34,
}

impl CpuFeature {
    const fn bit(self) -> u64 {
        match self {
            Self::X86Sse2 => 1_u64 << 0,
            Self::X86Avx2 => 1_u64 << 1,
            Self::X86Avx512F => 1_u64 << 2,
            Self::X86Avx512Bw => 1_u64 << 3,
            Self::X86Avx512Vl => 1_u64 << 4,
            Self::Aarch64Asimd => 1_u64 << 32,
            Self::Aarch64Sve => 1_u64 << 33,
            Self::Aarch64Sve2 => 1_u64 << 34,
        }
    }
}

/// A non-linear set of CPU feature facts.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct FeatureSet(u64);

impl FeatureSet {
    pub const EMPTY: Self = Self(0);

    const KNOWN_BITS: u64 = CpuFeature::X86Sse2.bit()
        | CpuFeature::X86Avx2.bit()
        | CpuFeature::X86Avx512F.bit()
        | CpuFeature::X86Avx512Bw.bit()
        | CpuFeature::X86Avx512Vl.bit()
        | CpuFeature::Aarch64Asimd.bit()
        | CpuFeature::Aarch64Sve.bit()
        | CpuFeature::Aarch64Sve2.bit();

    /// Construct a set containing one feature.
    #[must_use]
    pub const fn of(feature: CpuFeature) -> Self {
        Self(feature.bit())
    }

    /// Decode a feature mask, rejecting unknown vocabulary bits.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !Self::KNOWN_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Return the stable bit representation.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Return whether this set has no features.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return a copy with `feature` present.
    #[must_use]
    pub const fn with(self, feature: CpuFeature) -> Self {
        Self(self.0 | feature.bit())
    }

    /// Return the union of two independent feature sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Return whether every bit in `required` is present.
    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    const fn is_for_architecture(self, architecture: Architecture) -> bool {
        let x86 = CpuFeature::X86Sse2.bit()
            | CpuFeature::X86Avx2.bit()
            | CpuFeature::X86Avx512F.bit()
            | CpuFeature::X86Avx512Bw.bit()
            | CpuFeature::X86Avx512Vl.bit();
        let aarch64 = CpuFeature::Aarch64Asimd.bit()
            | CpuFeature::Aarch64Sve.bit()
            | CpuFeature::Aarch64Sve2.bit();
        match architecture {
            Architecture::X86_64 => self.0 & !x86 == 0,
            Architecture::Aarch64 => self.0 & !aarch64 == 0,
        }
    }

    const fn has(self, feature: CpuFeature) -> bool {
        self.0 & feature.bit() != 0
    }
}

impl core::fmt::Debug for FeatureSet {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FeatureSet")
            .field("bits", &format_args!("{:#018x}", self.0))
            .finish()
    }
}

/// Complete native compilation target.
///
/// `features` records capabilities made available to lowering. The scalar
/// runtime adapter emitted today does not itself require any optional feature.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Target {
    pub architecture: Architecture,
    pub operating_system: OperatingSystem,
    pub abi: CallAbi,
    pub features: FeatureSet,
}

impl Target {
    /// Construct a validated target, deriving its ABI from the architecture.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::UnsupportedTarget`] for cross-architecture
    /// features or an invalid feature dependency.
    pub fn new(
        architecture: Architecture,
        operating_system: OperatingSystem,
        features: FeatureSet,
    ) -> Result<Self, ObjectError> {
        let abi = match architecture {
            Architecture::X86_64 => CallAbi::SystemV,
            Architecture::Aarch64 => CallAbi::Aapcs64,
        };
        Self::from_parts(architecture, operating_system, abi, features)
    }

    /// Construct and validate every explicit target component.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::UnsupportedTarget`] when the ABI, feature
    /// architecture, or feature dependencies are inconsistent.
    pub fn from_parts(
        architecture: Architecture,
        operating_system: OperatingSystem,
        abi: CallAbi,
        features: FeatureSet,
    ) -> Result<Self, ObjectError> {
        let target = Self {
            architecture,
            operating_system,
            abi,
            features,
        };
        target.validate()?;
        Ok(target)
    }

    /// Portable x86-64 Linux target.
    #[must_use]
    pub const fn x86_64_linux() -> Self {
        Self {
            architecture: Architecture::X86_64,
            operating_system: OperatingSystem::Linux,
            abi: CallAbi::SystemV,
            features: FeatureSet::EMPTY,
        }
    }

    /// Portable x86-64 macOS target.
    #[must_use]
    pub const fn x86_64_macos() -> Self {
        Self {
            architecture: Architecture::X86_64,
            operating_system: OperatingSystem::Macos,
            abi: CallAbi::SystemV,
            features: FeatureSet::EMPTY,
        }
    }

    /// Portable `AArch64` Linux target.
    #[must_use]
    pub const fn aarch64_linux() -> Self {
        Self {
            architecture: Architecture::Aarch64,
            operating_system: OperatingSystem::Linux,
            abi: CallAbi::Aapcs64,
            features: FeatureSet::EMPTY,
        }
    }

    /// Portable `AArch64` macOS target.
    #[must_use]
    pub const fn aarch64_macos() -> Self {
        Self {
            architecture: Architecture::Aarch64,
            operating_system: OperatingSystem::Macos,
            abi: CallAbi::Aapcs64,
            features: FeatureSet::EMPTY,
        }
    }

    /// Return this target with a validated capability set.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::UnsupportedTarget`] for features belonging to a
    /// different architecture or for an incomplete dependency set.
    pub fn with_features(mut self, features: FeatureSet) -> Result<Self, ObjectError> {
        self.features = features;
        self.validate()?;
        Ok(self)
    }

    /// Validate the target tuple and explicit feature dependencies.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::UnsupportedTarget`] for an incoherent tuple.
    pub fn validate(self) -> Result<(), ObjectError> {
        let abi_matches = matches!(
            (self.architecture, self.abi),
            (Architecture::X86_64, CallAbi::SystemV) | (Architecture::Aarch64, CallAbi::Aapcs64)
        );
        if !abi_matches || !self.features.is_for_architecture(self.architecture) {
            return Err(ObjectError::UnsupportedTarget);
        }

        // These are explicit extension dependencies, not a linear feature
        // tier. AVX2 and AVX-512F, for example, remain independent facts.
        if self.features.has(CpuFeature::X86Avx512Bw) && !self.features.has(CpuFeature::X86Avx512F)
        {
            return Err(ObjectError::UnsupportedTarget);
        }
        if self.features.has(CpuFeature::X86Avx512Vl) && !self.features.has(CpuFeature::X86Avx512F)
        {
            return Err(ObjectError::UnsupportedTarget);
        }
        if self.features.has(CpuFeature::Aarch64Sve2) && !self.features.has(CpuFeature::Aarch64Sve)
        {
            return Err(ObjectError::UnsupportedTarget);
        }
        Ok(())
    }
}

/// Logical kind of a module section.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SectionKind {
    Text,
    ReadOnlyData,
}

/// Start-state accelerator actually emitted in a native module.
///
/// `None` means either the program uses the runtime adapter or the complete DFA
/// did not satisfy the graph-derived filter cost model.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StartAccelerator {
    None,
    Scalar,
    X86Sse2,
    X86Avx2,
    X86Avx512Bw,
    Aarch64Asimd,
}

/// One independent section before object-format layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleSection {
    pub name: &'static str,
    pub kind: SectionKind,
    pub alignment: u64,
    pub data: Box<[u8]>,
}

impl ModuleSection {
    /// Return the immutable section payload.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Linker visibility for a module symbol.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SymbolBinding {
    Local,
    Global,
}

/// Linker type for a module symbol.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SymbolKind {
    Function,
    Object,
}

/// One defined or undefined object symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleSymbol {
    pub name: String,
    pub binding: SymbolBinding,
    pub kind: SymbolKind,
    /// Defining section index, or `None` for an undefined external symbol.
    pub section: Option<usize>,
    /// Section-relative value. Undefined symbols must use zero.
    pub offset: u64,
    pub size: u64,
}

/// Relocation operation understood by both generic object writers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RelocationKind {
    /// AMD64 signed 32-bit PC-relative data address.
    X86PcRelative32,
    /// AMD64 signed 32-bit PLT-capable branch.
    X86PltRelative32,
    /// `AArch64` page-relative ADRP immediate.
    Aarch64Page21,
    /// `AArch64` low-12-bit ADD immediate paired with an ADRP.
    Aarch64PageOff12,
    /// `AArch64` unconditional 26-bit branch.
    Aarch64Branch26,
}

/// One unresolved, section-relative relocation.
///
/// Addends use the ELF mathematical convention (`S + A - P`). Object writers
/// whose relocation implicitly uses the end of an encoded field must translate
/// from this representation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ModuleRelocation {
    /// Index in [`CompiledModule::sections`].
    pub section: usize,
    /// Offset of the relocation field or instruction within `section`.
    pub offset: u64,
    pub kind: RelocationKind,
    /// Index in [`CompiledModule::symbols`].
    pub symbol: usize,
    pub addend: i64,
}

/// Object-format-neutral native module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledModule {
    target: Target,
    sections: Box<[ModuleSection]>,
    symbols: Box<[ModuleSymbol]>,
    relocations: Box<[ModuleRelocation]>,
    entry_symbol_index: usize,
    runtime_symbol_index: Option<usize>,
    runtime_program_symbol_index: Option<usize>,
    start_accelerator: StartAccelerator,
    anchored_prefix_filter_bytes: u8,
}

const TEXT_SECTION: usize = 0;
const PROGRAM_SECTION: usize = 1;
const ENTRY_SYMBOL: usize = 0;
const PROGRAM_SYMBOL: usize = 1;
const RUNTIME_SYMBOL: usize = 2;
const RUNTIME_PROGRAM_SYMBOL: usize = 3;

const RUNTIME_SYMBOL_NAME: &str = "fre_aot_regex_runtime_search_v1";
const ENTRY_SYMBOL_PREFIX: &str = "fre_aot_regex_search_v1_";
const PROGRAM_SYMBOL_PREFIX: &str = "fre_aot_regex_program_v1_";
const RUNTIME_PROGRAM_SYMBOL_PREFIX: &str = "fre_aot_regex_runtime_program_v1_";
const NATIVE_LOWERING_VERSION: u32 = 1;
const NATIVE_MODULE_IDENTITY_DOMAIN: &[u8] = b"fre-aot-regex/native-module-identity\0";

struct NativeLowering {
    code: Vec<u8>,
    data: Vec<u8>,
    relocations: Vec<ModuleRelocation>,
    needs_runtime: bool,
    start_accelerator: StartAccelerator,
    anchored_prefix_filter_bytes: u8,
}

impl CompiledModule {
    /// Lower a complete target-neutral program to a relocatable native module.
    ///
    /// The baseline entry ABI is:
    ///
    /// `status = entry(haystack, length, window_start, window_end, result_out)`.
    ///
    /// The runtime has the same arguments with an immutable program pointer
    /// inserted first. The emitted leaf adapter performs only that shuffle and
    /// a tail branch, so it owns no stack frame and preserves the platform C
    /// ABI.
    ///
    /// # Errors
    ///
    /// Returns a typed compiler error if serialization fails, the target is
    /// incoherent, or section/symbol dimensions overflow their representation.
    pub fn lower(program: &CompiledProgram, target: Target) -> Result<Self, CompileError> {
        target.validate()?;
        let program_bytes = program.serialize()?;
        let native = program.native_dfa_view();
        let native_context = program.native_context_program_view();
        Self::lower_serialized(program_bytes, native, native_context, target)
            .map_err(CompileError::from)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "native/runtime section, symbol, relocation, and identity construction is one transaction"
    )]
    fn lower_serialized(
        program_bytes: Vec<u8>,
        native: Option<NativeProgramView<'_>>,
        native_context: Option<NativeContextProgramView<'_>>,
        target: Target,
    ) -> Result<Self, ObjectError> {
        let program_digest = Sha256::digest(&program_bytes);
        let program_name = identity_symbol(PROGRAM_SYMBOL_PREFIX, program_digest.as_slice())?;
        let (lowering, native_digest) = if let Some(view) = native {
            let lowering = lower_native_dfa(view, target)?;
            let native_digest = native_module_digest(&program_bytes, target, &lowering)?;
            (lowering, native_digest)
        } else if let Some(view) = native_context {
            let lowering = module_context::lower_native_context(view, target)?;
            let native_digest = native_module_digest(&program_bytes, target, &lowering)?;
            (lowering, native_digest)
        } else {
            let (code, relocations) = match target.architecture {
                Architecture::X86_64 => lower_x86_64_runtime_adapter()?,
                Architecture::Aarch64 => lower_aarch64_runtime_adapter()?,
            };
            let lowering = NativeLowering {
                code,
                data: program_bytes,
                relocations,
                needs_runtime: true,
                start_accelerator: StartAccelerator::None,
                anchored_prefix_filter_bytes: 0,
            };
            let native_digest = native_module_digest(&lowering.data, target, &lowering)?;
            (lowering, native_digest)
        };
        let entry_name = identity_symbol(ENTRY_SYMBOL_PREFIX, &native_digest)?;
        let runtime_program_name = lowering
            .needs_runtime
            .then(|| identity_symbol(RUNTIME_PROGRAM_SYMBOL_PREFIX, &native_digest))
            .transpose()?;

        let code_size = u64::try_from(lowering.code.len())
            .map_err(|_| ObjectError::ArithmeticOverflow("module code size"))?;
        let program_size = u64::try_from(lowering.data.len())
            .map_err(|_| ObjectError::ArithmeticOverflow("module program size"))?;

        let sections = vec![
            ModuleSection {
                name: ".text",
                kind: SectionKind::Text,
                alignment: match target.architecture {
                    Architecture::X86_64 => 16,
                    Architecture::Aarch64 => 4,
                },
                data: lowering.code.into_boxed_slice(),
            },
            ModuleSection {
                name: ".rodata.fre.regex",
                kind: SectionKind::ReadOnlyData,
                alignment: 16,
                data: lowering.data.into_boxed_slice(),
            },
        ]
        .into_boxed_slice();
        let mut symbols = vec![
            ModuleSymbol {
                name: entry_name,
                binding: SymbolBinding::Global,
                kind: SymbolKind::Function,
                section: Some(TEXT_SECTION),
                offset: 0,
                size: code_size,
            },
            ModuleSymbol {
                name: program_name,
                binding: SymbolBinding::Local,
                kind: SymbolKind::Object,
                section: Some(PROGRAM_SECTION),
                offset: 0,
                size: program_size,
            },
        ];
        let (runtime_symbol_index, runtime_program_symbol_index) = if lowering.needs_runtime {
            symbols.push(ModuleSymbol {
                name: RUNTIME_SYMBOL_NAME.to_owned(),
                binding: SymbolBinding::Global,
                kind: SymbolKind::Function,
                section: None,
                offset: 0,
                size: 0,
            });
            symbols.push(ModuleSymbol {
                name: runtime_program_name.ok_or(ObjectError::InvalidModule(
                    "runtime program alias identity was not constructed",
                ))?,
                binding: SymbolBinding::Global,
                kind: SymbolKind::Object,
                section: Some(PROGRAM_SECTION),
                offset: 0,
                size: program_size,
            });
            (Some(RUNTIME_SYMBOL), Some(RUNTIME_PROGRAM_SYMBOL))
        } else {
            (None, None)
        };

        Ok(Self {
            target,
            sections,
            symbols: symbols.into_boxed_slice(),
            relocations: lowering.relocations.into_boxed_slice(),
            entry_symbol_index: ENTRY_SYMBOL,
            runtime_symbol_index,
            runtime_program_symbol_index,
            start_accelerator: lowering.start_accelerator,
            anchored_prefix_filter_bytes: lowering.anchored_prefix_filter_bytes,
        })
    }

    /// Return the requested target tuple.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// Return all sections in deterministic object order.
    #[must_use]
    pub fn sections(&self) -> &[ModuleSection] {
        &self.sections
    }

    /// Return all symbols in deterministic order.
    #[must_use]
    pub fn symbols(&self) -> &[ModuleSymbol] {
        &self.symbols
    }

    /// Return all unresolved relocations in deterministic section order.
    #[must_use]
    pub fn relocations(&self) -> &[ModuleRelocation] {
        &self.relocations
    }

    /// Return the unique exported entry symbol.
    #[must_use]
    pub fn entry_symbol(&self) -> &str {
        &self.symbols[self.entry_symbol_index].name
    }

    /// Return the fixed versioned runtime helper symbol.
    #[must_use]
    pub fn runtime_symbol(&self) -> &str {
        self.runtime_symbol_index
            .map_or(RUNTIME_SYMBOL_NAME, |index| {
                self.symbols
                    .get(index)
                    .map_or(RUNTIME_SYMBOL_NAME, |symbol| symbol.name.as_str())
            })
    }

    /// Return the exported serialized-program object required for preparation.
    ///
    /// Runtime-backed modules define the returned symbol over the exact
    /// serialized program byte extent. A C integrator can pass that symbol's
    /// address and returned length to `fre_aot_regex_runtime_prepare_v1`.
    /// Direct DFA modules are self-contained and return `None`.
    #[must_use]
    pub fn required_runtime_program(&self) -> Option<(&str, usize)> {
        let index = self.runtime_program_symbol_index?;
        let symbol = self.symbols.get(index)?;
        let program = self.sections.get(PROGRAM_SECTION)?;
        Some((symbol.name.as_str(), program.data.len()))
    }

    /// Return the number of emitted native text bytes.
    #[must_use]
    pub fn code_bytes(&self) -> usize {
        self.sections
            .get(TEXT_SECTION)
            .map_or(0, |section| section.data.len())
    }

    /// Return the graph-derived start-state accelerator actually emitted.
    #[must_use]
    pub const fn start_accelerator(&self) -> StartAccelerator {
        self.start_accelerator
    }

    /// Return the fixed anchored-prefix depth checked before a start candidate
    /// enters the complete DFA.
    ///
    /// Zero means that no multi-byte candidate filter was emitted. This
    /// reports emitted native code, not merely a target-neutral analysis fact.
    #[must_use]
    pub const fn anchored_prefix_filter_bytes(&self) -> u8 {
        self.anchored_prefix_filter_bytes
    }
}

fn native_module_digest(
    program_bytes: &[u8],
    target: Target,
    lowering: &NativeLowering,
) -> Result<[u8; 32], ObjectError> {
    fn update_bytes(
        digest: &mut Sha256,
        bytes: &[u8],
        site: &'static str,
    ) -> Result<(), ObjectError> {
        let length =
            u64::try_from(bytes.len()).map_err(|_| ObjectError::ArithmeticOverflow(site))?;
        digest.update(length.to_le_bytes());
        digest.update(bytes);
        Ok(())
    }

    fn architecture_tag(architecture: Architecture) -> u8 {
        match architecture {
            Architecture::X86_64 => 1,
            Architecture::Aarch64 => 2,
        }
    }

    fn operating_system_tag(operating_system: OperatingSystem) -> u8 {
        match operating_system {
            OperatingSystem::Linux => 1,
            OperatingSystem::Macos => 2,
        }
    }

    fn abi_tag(abi: CallAbi) -> u8 {
        match abi {
            CallAbi::SystemV => 1,
            CallAbi::Aapcs64 => 2,
        }
    }

    fn relocation_kind_tag(kind: RelocationKind) -> u8 {
        match kind {
            RelocationKind::X86PcRelative32 => 1,
            RelocationKind::X86PltRelative32 => 2,
            RelocationKind::Aarch64Page21 => 3,
            RelocationKind::Aarch64PageOff12 => 4,
            RelocationKind::Aarch64Branch26 => 5,
        }
    }

    let mut digest = Sha256::new();
    digest.update(NATIVE_MODULE_IDENTITY_DOMAIN);
    digest.update(NATIVE_LOWERING_VERSION.to_le_bytes());
    digest.update([
        architecture_tag(target.architecture),
        operating_system_tag(target.operating_system),
        abi_tag(target.abi),
    ]);
    digest.update(target.features.bits().to_le_bytes());
    update_bytes(&mut digest, program_bytes, "program identity byte length")?;
    update_bytes(&mut digest, &lowering.code, "code identity byte length")?;
    update_bytes(&mut digest, &lowering.data, "data identity byte length")?;
    digest.update([u8::from(lowering.needs_runtime)]);
    digest.update([start_accelerator_tag(lowering.start_accelerator)]);
    digest.update([lowering.anchored_prefix_filter_bytes]);
    if lowering.needs_runtime {
        update_bytes(
            &mut digest,
            RUNTIME_SYMBOL_NAME.as_bytes(),
            "runtime symbol identity byte length",
        )?;
    }
    let relocation_count = u64::try_from(lowering.relocations.len())
        .map_err(|_| ObjectError::ArithmeticOverflow("relocation identity count"))?;
    digest.update(relocation_count.to_le_bytes());
    for relocation in &lowering.relocations {
        let section = u64::try_from(relocation.section)
            .map_err(|_| ObjectError::ArithmeticOverflow("relocation identity section"))?;
        let symbol = u64::try_from(relocation.symbol)
            .map_err(|_| ObjectError::ArithmeticOverflow("relocation identity symbol"))?;
        digest.update(section.to_le_bytes());
        digest.update(relocation.offset.to_le_bytes());
        digest.update([relocation_kind_tag(relocation.kind)]);
        digest.update(symbol.to_le_bytes());
        digest.update(relocation.addend.to_le_bytes());
    }
    Ok(digest.finalize().into())
}

const fn start_accelerator_tag(accelerator: StartAccelerator) -> u8 {
    match accelerator {
        StartAccelerator::None => 0,
        StartAccelerator::Scalar => 1,
        StartAccelerator::X86Sse2 => 2,
        StartAccelerator::X86Avx2 => 3,
        StartAccelerator::X86Avx512Bw => 4,
        StartAccelerator::Aarch64Asimd => 5,
    }
}

fn identity_symbol(prefix: &str, digest: &[u8]) -> Result<String, ObjectError> {
    let hex_bytes = digest
        .len()
        .checked_mul(2)
        .ok_or(ObjectError::ArithmeticOverflow("identity hex length"))?;
    let capacity = prefix
        .len()
        .checked_add(hex_bytes)
        .ok_or(ObjectError::ArithmeticOverflow("identity symbol length"))?;
    let mut symbol = String::with_capacity(capacity);
    symbol.push_str(prefix);
    for byte in digest {
        write!(&mut symbol, "{byte:02x}")
            .map_err(|_| ObjectError::InvalidModule("could not format identity symbol"))?;
    }
    Ok(symbol)
}

fn push_bytes(code: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ObjectError> {
    code.len()
        .checked_add(bytes.len())
        .ok_or(ObjectError::ArithmeticOverflow("native code length"))?;
    code.extend_from_slice(bytes);
    Ok(())
}

fn offset_u64(offset: usize, site: &'static str) -> Result<u64, ObjectError> {
    u64::try_from(offset).map_err(|_| ObjectError::ArithmeticOverflow(site))
}

const CLASS_MAP_BYTES: usize = 256;
const DIRECT_BYTE_ROW_CELLS: usize = 256;
const DIRECT_BYTE_ROW_BYTES: usize = DIRECT_BYTE_ROW_CELLS * core::mem::size_of::<u32>();
const AARCH64_FIRST_LANE_INDEX: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// Direct rows deliberately stay below a conservative share of a typical
/// 32-KiB L1 data cache. Prefix filters and unrelated caller data retain the
/// remaining capacity; larger machines keep their compact class mapping.
const DIRECT_BYTE_TABLE_BUDGET: usize = 24 * 1024;
const CELL_ACCEPTS: u32 = 1_u32 << 31;
/// The forward table uses this target-derived hint to enter the compact
/// accelerator dispatcher. Reverse cells deliberately leave it clear.
const CELL_ACCELERATED: u32 = 1_u32 << 30;
const CELL_NEXT_MASK: u32 = CELL_ACCELERATED - 1;
/// Subtracting the live-token bias turns every ordinary transition into its
/// absolute row offset. This upper bound is derived entirely from the packed
/// cell layout: dead and either flagged form lie outside the inclusive range.
const CELL_ORDINARY_DECODED_MAX: u32 = CELL_NEXT_MASK - 1;
const NO_DFA_STATE: u32 = u32::MAX;
/// Optional reverse sidecars remain a bounded optimization artifact. The
/// portable constructor accounts for eight-byte logical cells, while native
/// packing uses four-byte cells; these independent caps keep both compile-time
/// memory and emitted cold data proportional without consulting regex source.
const MAX_NATIVE_SEEDED_REVERSE_CELLS: usize = 4 * 1024 * 1024;
const MAX_NATIVE_SEEDED_REVERSE_MEMORY_BYTES: usize = 64 * 1024 * 1024;
/// Storage for exact fragmented byte sets. The vector lowering has eight
/// dedicated constant registers on x86-64 and an equivalent bounded ASIMD
/// allocation. Non-exact inclusive ranges retain the former four-range cap
/// because each one consumes two constants and substantially more hot-loop
/// instructions.
const MAX_START_FILTER_RANGES: usize = 8;
const MAX_NON_EXACT_START_FILTER_RANGES: usize = 4;
const MAX_START_FILTER_CANDIDATE_BYTES: u16 = 64;
/// Private source-identical A/B switch for exact five-to-eight-alternative
/// scanners. Selection is derived solely from byte membership; disabling it
/// restores the original four-range admission rule.
const ENABLE_FRAGMENTED_EXACT_START_FILTER: bool = true;
/// Narrow fallback for finite `Exists` machines whose exact initial
/// membership is cheap but too fragmented for the ordinary representation.
/// Kept as one private switch so source-identical optimizer A/B builds can
/// validate the graph-only cost gate.
const ENABLE_NATIVE_COALESCED_INITIAL_FILTER: bool = true;
/// At most 128 disjoint ranges can occur in a 256-bit byte-membership set
/// (the alternating-byte case). Keeping the coalescer's workspace on the
/// stack makes its resource use fixed and independent of regex source shape.
const MAX_EXACT_BYTE_MEMBERSHIP_RANGES: usize = 128;
/// A restart complement is inspected only while walking backward from a
/// graph-required candidate. It can therefore afford more disjoint ranges
/// than the hot forward SIMD filter while remaining explicitly bounded.
const MAX_SUFFIX_RESET_NON_RESET_RANGES: usize = 16;
const MAX_VECTOR_FILTER_COLUMNS: usize = 3;
const MAX_VECTOR_FILTER_CONSTANTS: usize = 4;
const MAX_VECTOR_FILTER_INSTRUCTION_UNITS: u16 = 8;
const VECTOR_FILTER_COST_BLOCK_BYTES: u64 = 64;
/// Stable expected-hit budgets for branch-amortized candidate scanning.
///
/// Frequency units use [`BYTE_FREQUENCY_DENOMINATOR`] as their denominator.
/// A four-vector x86 batch deliberately accepts only rare primaries: a hit
/// leaves the bandwidth path and rescans the bounded block scalarly. The
/// established 64-byte ASIMD batch extracts its exact first lane without
/// rescanning and can therefore tolerate more hits.
const MAX_SPARSE_RESCAN_EXPECTED_HITS: u16 = 2;
const MAX_ASIMD_BATCH_EXPECTED_HITS: u16 = 4;
const AARCH64_BATCH_BYTES: u16 = 64;
const X86_MASK_BATCH_VECTORS: u16 = 4;
/// Keep an optional post-return cold tail from changing the cache-line
/// placement of text sections linked after this self-contained object.
/// The hot section starts at a 16-byte object alignment, while preserving its
/// size modulo a 64-byte instruction-cache line also preserves every stronger
/// 32-byte fetch/decode placement used by the supported x86 implementations.
const X86_COLD_LINK_ALIGNMENT_BYTES: usize = 64;
/// A suffix prepass has a fixed setup cost and is primarily useful for large
/// windows. Smaller windows enter the ordinary prefix/forward path directly.
const SUFFIX_PREFILTER_MIN_WINDOW_BYTES: u16 = 128;
/// Private source-identical A/B switch for deferring SIMD suffix constants
/// until after the runtime short-window bypass.
///
/// The graph decision is unchanged. On short windows the complete DFA is the
/// selected kernel, so materializing constants for a prefilter that will not
/// run is pure fixed overhead.
const ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS: bool = true;
const BYTE_FREQUENCY_DENOMINATOR: u16 = 256;
const MAX_LAZY_SECONDARY_FREQUENCY_UNITS: u16 = 64;
const MAX_LAZY_SECONDARY_COST_UNITS: u64 = 128;
/// A scalar aligned refinement is paid after every primary SIMD hit. Retain
/// it only when the stable byte-frequency model predicts at most one such hit
/// per 16 scanned bytes; broader primaries use the ordinary proven restart.
const MAX_SCALAR_REFINEMENT_PRIMARY_FREQUENCY_UNITS: u16 = 16;
/// Stable offline byte-frequency ranks for the native rare-byte cost model.
///
/// Lower ranks are rarer. The table is deliberately target, pattern-name and
/// input independent; it is the conventional ranking used by mature
/// substring prefilters. Absolute probabilities are conservatively bucketed
/// below because rank gaps are ordinal, not linear frequencies.
#[rustfmt::skip]
const BYTE_FREQUENCY_RANK: [u8; 256] = [
     55,  52,  51,  50,  49,  48,  47,  46,  45, 103, 242,  66,  67, 229,  44,  43,
     42,  41,  40,  39,  38,  37,  36,  35,  34,  33,  56,  32,  31,  30,  29,  28,
    255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122, 232, 202, 215, 224,
    208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174, 126,
    120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167,
    186, 112, 175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223,
    151, 249, 216, 238, 236, 253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244,
    231, 139, 245, 243, 251, 235, 201, 196, 240, 214, 152, 182, 205, 181, 127,  27,
    212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105,  80,  98,  96,  97,  81,
    207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111,  82, 108,
    118, 141, 113, 129, 119, 125, 165, 117,  92, 106,  83,  72,  99,  93,  65,  79,
    166, 237, 163, 199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];
const PREFIX_BITMAP_BYTES: usize = 32;
const PREFIX_RELATION_BITMAP_BYTES: usize = 256 * 256 / 8;
/// Exact relation rectangles that can be evaluated directly in one SIMD
/// probe. The target-specific constant and instruction budgets below are the
/// real admission limits; this fixed cap only bounds code size and stack use.
const MAX_NATIVE_PREFIX_RELATION_RECTANGLES: usize = prefix_relation::MAX_PREFIX_RELATION_GROUPS;
const MAX_X86_PREFIX_RELATION_CONSTANTS: u8 = 8;
const MAX_AARCH64_PREFIX_RELATION_CONSTANTS: u8 = 6;
const MAX_X86_PREFIX_RELATION_INSTRUCTION_UNITS: u16 = 32;
const MAX_AARCH64_PREFIX_RELATION_INSTRUCTION_UNITS: u16 = 24;
const MAX_NATIVE_PREFIX_PREDICATES: usize = MAX_ANCHORED_PREFIX_BYTES;
const ENABLE_NATIVE_PREFIX_FAST_FORWARD: bool = true;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionLayout {
    /// A 256-byte map selects one of the DFA's equivalence-class cells.
    ClassMapped,
    /// Every state has one packed cell per possible input byte. This removes
    /// the dependent class-map load while preserving the same DFA graph.
    DirectByte,
}

impl TransitionLayout {
    const fn row_cells(self, class_count: usize) -> usize {
        match self {
            Self::ClassMapped => class_count,
            Self::DirectByte => DIRECT_BYTE_ROW_CELLS,
        }
    }

    const fn table_prefix_bytes(self) -> usize {
        match self {
            Self::ClassMapped => CLASS_MAP_BYTES,
            Self::DirectByte => 0,
        }
    }
}

fn select_transition_layout(
    forward_states: usize,
    retained_reverse_states: usize,
) -> TransitionLayout {
    // One dependency is removed from every forward and reverse transition.
    // Bound the complete expanded working set solely from DFA structure;
    // overflow or a larger machine deterministically retains compact rows.
    let direct_bytes = forward_states
        .checked_add(retained_reverse_states)
        .and_then(|states| states.checked_mul(DIRECT_BYTE_ROW_BYTES));
    if direct_bytes.is_some_and(|bytes| bytes <= DIRECT_BYTE_TABLE_BUDGET) {
        TransitionLayout::DirectByte
    } else {
        TransitionLayout::ClassMapped
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeByteRange {
    start: u8,
    end: u8,
}

const EMPTY_NATIVE_BYTE_RANGE: NativeByteRange = NativeByteRange { start: 0, end: 0 };
const EMPTY_NATIVE_RESET_FILTER: NativeResetFilter = NativeResetFilter {
    ranges: [EMPTY_NATIVE_BYTE_RANGE; MAX_SUFFIX_RESET_NON_RESET_RANGES],
    range_count: 0,
    candidate_bytes: 0,
};
const EMPTY_NATIVE_START_FILTER: NativeStartFilter = NativeStartFilter {
    ranges: [EMPTY_NATIVE_BYTE_RANGE; MAX_START_FILTER_RANGES],
    range_count: 0,
    candidate_bytes: 0,
    scan_offset: 0,
    from_anchored_prefix: false,
};

/// A graph-derived filter for bytes that can leave the initial DFA state.
///
/// Every byte outside `ranges` has a non-accepting transition from state
/// zero back to state zero. Consequently, while the machine is in its initial
/// state and has no pending accept, any run of those bytes can be consumed
/// without executing the full transition loop. The fixed-size representation
/// and candidate cardinality form a source-independent cost model: exact
/// alternatives may use up to eight singleton intervals, inclusive ranges
/// use up to four, and sets wider than 64 candidate bytes use the ordinary
/// DFA loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeStartFilter {
    ranges: [NativeByteRange; MAX_START_FILTER_RANGES],
    range_count: u8,
    candidate_bytes: u16,
    /// Required-prefix byte inspected relative to the semantic candidate
    /// start. Advancing the scanner still advances the candidate start, not
    /// this offset address.
    scan_offset: u8,
    /// Whether `ranges` exactly encode one graph-derived anchored-prefix
    /// column. The prefix bitmap guard may omit this already-validated column.
    from_anchored_prefix: bool,
}

/// Exact complement of a DFA-proven all-state reset set.
///
/// Unlike [`NativeStartFilter`], this is not used to form SIMD constants and
/// has no position offset. A larger fixed range budget prevents fragmented
/// but tiny alphabets (for example, several literal bytes separated in ASCII)
/// from disabling an otherwise universal synchronizing restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeResetFilter {
    ranges: [NativeByteRange; MAX_SUFFIX_RESET_NON_RESET_RANGES],
    range_count: u8,
    candidate_bytes: u16,
}

impl NativeResetFilter {
    fn ranges(&self) -> &[NativeByteRange] {
        &self.ranges[..usize::from(self.range_count)]
    }
}

impl NativeStartFilter {
    fn ranges(&self) -> &[NativeByteRange] {
        &self.ranges[..usize::from(self.range_count)]
    }

    fn is_exact(self) -> bool {
        self.ranges().iter().all(|range| range.start == range.end)
    }

    fn constant_count(self) -> usize {
        if self.is_exact() {
            self.ranges().len()
        } else {
            self.ranges().len().saturating_mul(2)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeVectorFilter {
    columns: [NativeStartFilter; MAX_VECTOR_FILTER_COLUMNS],
    column_count: u8,
}

/// A necessary byte at the acceptance boundary of every non-empty match.
///
/// The scanner position is the base of the graph-proven suffix. The primary
/// is the sparsest representable required column; its `scan_offset` retains
/// chronological alignment, and optional lazy columns retain the same base.
/// If the first aligned candidate base is `b`, a bounded language cannot begin before
/// `b - (maximum_width - minimum_width)`. An unbounded language may instead
/// restart immediately after the nearest graph-proven synchronizing byte in
/// the preceding 64-byte interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeSuffixFilter {
    filter: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    /// Extra aligned columns checked after a primary SIMD hit when their
    /// constants are too expensive to keep live in the vector loop.
    scalar_filter: Option<NativeVectorFilter>,
    minimum_width: u8,
    restart: NativeSuffixRestart,
    /// Bounded false-candidate verification selected by a source-independent
    /// overlap cost model. Currently specialized only for `Exists`.
    retry: Option<BoundedSuffixRetryPlan>,
    /// The graph has a finite `Exists` retry shape, but the bounded verifier's
    /// overlap model rejected it as too expensive. This distinguishes a cost
    /// rejection from semantically ineligible suffixes without encoding any
    /// source- or benchmark-specific policy.
    retry_cost_rejected: bool,
    /// Exact raw-graph boundary proved by this mandatory factor. Native
    /// lowering may use it to recover candidate match starts with an
    /// independently determinized reverse sidecar. No source identity or
    /// literal recipe participates in selecting this seed.
    reverse_seed: NativeSuffixReverseSeed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeSuffixReverseSeed {
    /// The mandatory suffix ends at `base + minimum_width`.
    AcceptBoundary,
    /// The mandatory interior factor begins at this consuming state and its
    /// reverse boundary is the candidate base itself.
    RootState(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeSeededReverseLayout {
    class_map_offset: u32,
    initial_row_offset: u32,
    /// Candidate-base displacement of the graph boundary used to seed the
    /// reverse machine. It is the mandatory suffix width for Accept seeds and
    /// zero for interior-root seeds.
    boundary_offset: u8,
    initial_reaches_start: bool,
    /// Accept-seeded verification proves a complete match and can return
    /// immediately for the Exists contract. Root-seeded verification proves
    /// only the prefix through an interior boundary and must replay forward.
    proves_match: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeSeededReverseMachine {
    dfa: SeededReverseDfa,
    boundary_offset: u8,
    proves_match: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeSuffixRestart {
    /// The maximum-width proof raises the start to `base - backtrack`.
    Bounded { backtrack: u64 },
    /// Bytes outside this small exact complement synchronize every DFA state
    /// to a fresh search. The lowering scans backward at most 64 bytes from
    /// the first suffix base and restarts immediately after the nearest one.
    Synchronizing { non_reset: NativeResetFilter },
    /// Universal unbounded-language fallback. Candidate absence still proves
    /// no match; a first candidate simply enters the ordinary DFA from the
    /// untouched semantic window start.
    OriginalStart,
}

impl NativeVectorFilter {
    fn columns(&self) -> &[NativeStartFilter] {
        &self.columns[..usize::from(self.column_count)]
    }

    fn max_scan_offset(self) -> u8 {
        self.columns()
            .iter()
            .map(|column| column.scan_offset)
            .max()
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativePrefixPredicate {
    /// Byte offset from the candidate start.
    position: u8,
    membership: ScalarPrefixMembership,
    /// Table-relative offset of a 256-bit little-endian membership bitmap.
    /// This is zero and ignored for exact range/reject plans.
    bitmap_offset: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativePrefixFilter {
    predicates: [NativePrefixPredicate; MAX_NATIVE_PREFIX_PREDICATES],
    predicate_count: u8,
    /// Fixed minimum byte length proven by the graph analysis.
    guaranteed_bytes: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativePrefixRelationFilter {
    /// Table-relative offset of a bit matrix indexed by the little-endian
    /// two-byte word `first | (second << 8)`.
    bitmap_offset: u32,
    vector_plan: Option<NativePrefixRelationVectorPlan>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativePrefixRelationPredicate {
    filter: NativeStartFilter,
    negated: bool,
    any: bool,
    /// First target vector register occupied by this predicate's constants.
    /// Zero is reserved for `any`, which emits no comparison.
    first_constant: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativePrefixRelationRectangle {
    first: NativePrefixRelationPredicate,
    second: NativePrefixRelationPredicate,
}

/// Transactionally verified union of exact `first-set x second-set`
/// rectangles. Leaves use the same bounded exact/range representation as the
/// ordinary vector scanner and may use a small exact complement when cheaper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativePrefixRelationVectorPlan {
    rectangles: [NativePrefixRelationRectangle; MAX_NATIVE_PREFIX_RELATION_RECTANGLES],
    rectangle_count: u8,
    constant_count: u8,
    instruction_units: u16,
}

const EMPTY_NATIVE_PREFIX_RELATION_PREDICATE: NativePrefixRelationPredicate =
    NativePrefixRelationPredicate {
        filter: EMPTY_NATIVE_START_FILTER,
        negated: false,
        any: false,
        first_constant: 0,
    };
const EMPTY_NATIVE_PREFIX_RELATION_RECTANGLE: NativePrefixRelationRectangle =
    NativePrefixRelationRectangle {
        first: EMPTY_NATIVE_PREFIX_RELATION_PREDICATE,
        second: EMPTY_NATIVE_PREFIX_RELATION_PREDICATE,
    };

impl NativePrefixRelationVectorPlan {
    fn rectangles(&self) -> &[NativePrefixRelationRectangle] {
        &self.rectangles[..usize::from(self.rectangle_count)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativePrefixFastForward {
    /// Bytes whose DFA transitions are proved by the candidate guard.
    consumed_bytes: u8,
    /// Absolute table offset of the unique live, non-accepting state reached
    /// after those transitions.
    target_row_offset: u32,
}

/// Serialized constants for one graph-derived 16-byte singleton-lane guard.
///
/// The expected bytes and byte mask are adjacent and independently addressed
/// so the same target-neutral data serves SSE2/VEX and AArch64 ASIMD lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativePrefixBlockGuard {
    expected_offset: u32,
    byte_mask_offset: u32,
    lane_mask: u16,
}

impl NativePrefixBlockGuard {
    const fn covers_position(self, position: u8) -> bool {
        position < 16 && self.lane_mask & (1_u16 << position) != 0
    }
}

impl NativePrefixFilter {
    fn predicates(&self) -> &[NativePrefixPredicate] {
        &self.predicates[..usize::from(self.predicate_count)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeDfaLayout {
    transitions: TransitionLayout,
    forward_offset: u32,
    reverse_offset: u32,
    /// Table-relative address of `[0, 1, ..., 15]` used only by the `AArch64`
    /// ASIMD exact first-lane lowering.
    asimd_lane_index_offset: Option<u32>,
    initial_pending: bool,
    initial_terminal: bool,
    has_reverse: bool,
    /// A graph-proven fixed width for a non-empty span search. When present,
    /// the selected end determines the start without a reverse DFA traversal.
    exact_span_width: Option<u64>,
    /// A stronger DFA-product proof that the complete anchored byte-set
    /// product is exactly the language. A successful prefix guard may return
    /// without replaying these bytes through the scalar DFA.
    exact_prefix_match_width: Option<u8>,
    output: OutputContract,
    start_filter: Option<NativeStartFilter>,
    suffix_filter: Option<NativeSuffixFilter>,
    /// A complete graph-derived RootState reverse proof was omitted because
    /// its initial row already reaches the search start and cannot reject the
    /// aligned mandatory-factor candidate. This fact is independent of the
    /// output contract and target lowering.
    declined_redundant_root_reverse: bool,
    seeded_reverse: Option<NativeSeededReverseLayout>,
    loop_skip: Option<module_dfa_loop_skip::NativeDfaLoopSkip>,
    vector_filter: Option<NativeVectorFilter>,
    prefix_filter: Option<NativePrefixFilter>,
    prefix_relation: Option<NativePrefixRelationFilter>,
    prefix_block: Option<NativePrefixBlockGuard>,
    prefix_fast_forward: Option<NativePrefixFastForward>,
}

impl NativeDfaLayout {
    const fn has_prefix_guard(self) -> bool {
        self.prefix_filter.is_some()
            || self.prefix_relation.is_some()
            || self.prefix_block.is_some()
            || self.exact_prefix_match_width.is_some()
    }

    fn prefix_guaranteed_bytes(self) -> Result<u8, ObjectError> {
        if let (Some(prefix), Some(width)) = (self.prefix_filter, self.exact_prefix_match_width)
            && prefix.guaranteed_bytes != width
        {
            return Err(ObjectError::InvalidModule(
                "exact-prefix width disagrees with prefix guard",
            ));
        }
        let predicate_bytes = self
            .prefix_filter
            .map_or(0, |prefix| prefix.guaranteed_bytes);
        let relation_bytes = if self.prefix_relation.is_some() { 2 } else { 0 };
        let block_bytes = if self.prefix_block.is_some() { 16 } else { 0 };
        let exact_bytes = self.exact_prefix_match_width.unwrap_or(0);
        let guaranteed = predicate_bytes
            .max(relation_bytes)
            .max(block_bytes)
            .max(exact_bytes);
        if guaranteed == 0 {
            return Err(ObjectError::InvalidModule("prefix guard has no byte bound"));
        }
        Ok(guaranteed)
    }
}

/// Prefix facts already established by the exact candidate mask for one
/// vector block. This is deliberately target-neutral: target lowerings may
/// retain a mask only when this proof leaves a rejectable residual guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeVectorGuardCoverage {
    prefix_positions: u16,
    relation: bool,
    guaranteed_bytes: u8,
}

impl NativeVectorGuardCoverage {
    fn covers_position(self, position: u8) -> bool {
        position < 16 && self.prefix_positions & (1_u16 << u32::from(position)) != 0
    }

    fn has_rejectable_residual(self, layout: NativeDfaLayout) -> Result<bool, ObjectError> {
        if self.guaranteed_bytes < layout.prefix_guaranteed_bytes()? {
            return Ok(true);
        }
        if layout.prefix_relation.is_some() && !self.relation {
            return Ok(true);
        }
        if layout
            .prefix_block
            .is_some_and(|block| block.lane_mask & !self.prefix_positions != 0)
        {
            return Ok(true);
        }
        Ok(layout.prefix_filter.is_some_and(|prefix| {
            prefix
                .predicates()
                .iter()
                .any(|predicate| !self.covers_position(predicate.position))
        }))
    }
}

/// Transactionally prove which scalar prefix checks an exact vector mask
/// subsumes. Any inconsistent lowering metadata declines to the established
/// scalar recheck path instead of publishing partial coverage.
fn derive_native_vector_guard_coverage(
    layout: NativeDfaLayout,
    relation_vector: bool,
    vector_filter: Option<NativeVectorFilter>,
) -> Option<NativeVectorGuardCoverage> {
    let start_filter = layout
        .start_filter
        .filter(|filter| !filter.ranges().is_empty())?;
    if !layout.has_prefix_guard() {
        return None;
    }
    if relation_vector {
        let relation = layout.prefix_relation?;
        relation.vector_plan?;
        if vector_filter.is_some() {
            return None;
        }
        return Some(NativeVectorGuardCoverage {
            prefix_positions: 0b11,
            relation: true,
            guaranteed_bytes: 2,
        });
    }

    let mut positions = 0_u16;
    let mut guaranteed_bytes = start_filter.scan_offset.checked_add(1)?;
    let mut record = |filter: NativeStartFilter| -> Option<()> {
        guaranteed_bytes = guaranteed_bytes.max(filter.scan_offset.checked_add(1)?);
        if filter.from_anchored_prefix {
            let bit = 1_u16.checked_shl(u32::from(filter.scan_offset))?;
            positions |= bit;
        }
        Some(())
    };
    if let Some(vector_filter) = vector_filter {
        if vector_filter.columns().first().copied() != Some(start_filter) {
            return None;
        }
        for &column in vector_filter.columns() {
            record(column)?;
        }
    } else {
        record(start_filter)?;
    }
    Some(NativeVectorGuardCoverage {
        prefix_positions: positions,
        relation: false,
        guaranteed_bytes,
    })
}

fn lower_native_dfa(
    view: NativeProgramView<'_>,
    target: Target,
) -> Result<NativeLowering, ObjectError> {
    let (data, layout) = build_native_dfa_table_for_architecture(view, target.architecture)?;
    let (code, relocations) = match target.architecture {
        Architecture::X86_64 => lower_x86_64_dfa(layout, target.features)?,
        Architecture::Aarch64 => lower_aarch64_dfa_for_operating_system(
            layout,
            target.features,
            target.operating_system,
        )?,
    };
    Ok(NativeLowering {
        code,
        data,
        relocations,
        needs_runtime: false,
        start_accelerator: selected_start_accelerator(layout, target),
        anchored_prefix_filter_bytes: layout
            .prefix_filter
            .map_or(0, |filter| filter.guaranteed_bytes),
    })
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the copyable lowering layout is already consumed by the adjacent target selectors"
)]
const fn selected_start_accelerator(layout: NativeDfaLayout, target: Target) -> StartAccelerator {
    let filter = match layout.start_filter {
        Some(filter) => Some(filter),
        None => match layout.suffix_filter {
            Some(suffix) => Some(suffix.filter),
            None => None,
        },
    };
    let Some(filter) = filter else {
        return StartAccelerator::None;
    };
    if filter.candidate_bytes == 0 {
        return StartAccelerator::Scalar;
    }
    match target.architecture {
        Architecture::X86_64 => {
            if target.features.has(CpuFeature::X86Avx512F)
                && target.features.has(CpuFeature::X86Avx512Bw)
            {
                StartAccelerator::X86Avx512Bw
            } else if target.features.has(CpuFeature::X86Avx2) {
                StartAccelerator::X86Avx2
            } else {
                StartAccelerator::X86Sse2
            }
        }
        Architecture::Aarch64 => {
            if target.features.has(CpuFeature::Aarch64Asimd) {
                StartAccelerator::Aarch64Asimd
            } else {
                StartAccelerator::Scalar
            }
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "native table validation, checked layout, and packing form one auditable transaction"
)]
#[cfg(test)]
fn build_native_dfa_table(
    view: NativeProgramView<'_>,
) -> Result<(Vec<u8>, NativeDfaLayout), ObjectError> {
    build_native_dfa_table_for_architecture(view, Architecture::X86_64)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "checked table layout and fixed power-of-two alignment stay contiguous for auditability"
)]
fn build_native_dfa_table_for_architecture(
    view: NativeProgramView<'_>,
    architecture: Architecture,
) -> Result<(Vec<u8>, NativeDfaLayout), ObjectError> {
    let dfa = view.dfa;
    if dfa.initial_state != 0 || dfa.class_count == 0 || dfa.class_count > 256 {
        return Err(ObjectError::InvalidModule("invalid native DFA alphabet"));
    }
    if dfa.byte_classes.len() != CLASS_MAP_BYTES
        || dfa.class_representatives.len() != dfa.class_count
        || dfa
            .byte_classes
            .iter()
            .any(|&class| usize::from(class) >= dfa.class_count)
        || dfa.forward_cells.is_empty()
        || !dfa.forward_cells.len().is_multiple_of(dfa.class_count)
    {
        return Err(ObjectError::InvalidModule("invalid native DFA table shape"));
    }
    let span_needs_start = view.output == OutputContract::Span && !dfa.initial_pending;
    if span_needs_start
        && (dfa.reverse_initial != Some(0)
            || dfa.reverse_cells.is_empty()
            || !dfa.reverse_cells.len().is_multiple_of(dfa.class_count))
    {
        return Err(ObjectError::InvalidModule(
            "span-native DFA has no complete reverse table",
        ));
    }
    if !span_needs_start && (!dfa.reverse_cells.is_empty() || dfa.reverse_initial.is_some()) {
        return Err(ObjectError::InvalidModule(
            "native DFA has an unexpected reverse table",
        ));
    }
    let exact_span_width = if span_needs_start {
        view.exact_match_width
            .map(|width| {
                u64::try_from(width)
                    .map_err(|_| ObjectError::ArithmeticOverflow("native exact match width"))
            })
            .transpose()?
    } else {
        None
    };
    let wants_reverse = span_needs_start && exact_span_width.is_none();

    let forward_states = dfa
        .forward_cells
        .len()
        .checked_div(dfa.class_count)
        .ok_or(ObjectError::InvalidModule("native forward state count"))?;
    let retained_reverse_states = if wants_reverse {
        dfa.reverse_cells
            .len()
            .checked_div(dfa.class_count)
            .ok_or(ObjectError::InvalidModule("native reverse state count"))?
    } else {
        0
    };
    let transitions = select_transition_layout(forward_states, retained_reverse_states);
    let row_cells = transitions.row_cells(dfa.class_count);
    let row_bytes = row_cells
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(ObjectError::ArithmeticOverflow("native DFA row bytes"))?;
    let forward_bytes =
        forward_states
            .checked_mul(row_bytes)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native forward table bytes",
            ))?;
    let reverse_bytes =
        retained_reverse_states
            .checked_mul(row_bytes)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native reverse table bytes",
            ))?;
    let exact_start_filter = derive_start_filter(view)?;
    let mut selected_suffix_filter = derive_suffix_filter(view)?;
    let coalesced_start_filter =
        if ENABLE_NATIVE_COALESCED_INITIAL_FILTER && exact_start_filter.is_none() {
            derive_coalesced_initial_start_filter(view)?
        } else {
            None
        };
    let start_filter = exact_start_filter.or(coalesced_start_filter);
    // Both accelerators skip the same initial-state self-loop bytes. Once the
    // coalesced scanner is admitted, retaining a cost-rejected suffix prepass
    // would pay two moving scans before the ordinary DFA and recreate the
    // pathological overlap cost this fallback is intended to avoid.
    if coalesced_start_filter.is_some()
        && selected_suffix_filter.is_some_and(|suffix| suffix.retry_cost_rejected)
    {
        selected_suffix_filter = None;
    }
    let suffix_filter = selected_suffix_filter;
    let forward_offset = transitions.table_prefix_bytes();
    let loop_skip = module_dfa_loop_skip::derive_native_dfa_loop_skip(
        &dfa,
        view.output,
        forward_offset,
        row_bytes,
    )?;
    let retains_asimd_candidate_mask = architecture == Architecture::Aarch64
        && (start_filter.is_some_and(|filter| !filter.ranges().is_empty())
            || suffix_filter.is_some_and(|suffix| !suffix.filter.ranges().is_empty())
            || loop_skip.is_some());
    let reverse_offset =
        forward_offset
            .checked_add(forward_bytes)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native reverse table offset",
            ))?;
    let machine_bytes = reverse_offset
        .checked_add(reverse_bytes)
        .ok_or(ObjectError::ArithmeticOverflow("native DFA data bytes"))?;
    let vector_filter = derive_vector_filter(start_filter, view.anchored_prefix.sets())?;
    let filtered_prefix_position = start_filter
        .filter(|filter| filter.from_anchored_prefix)
        .map(|filter| usize::from(filter.scan_offset));
    let candidate_guard_active = start_filter
        .is_some_and(|filter| filter.candidate_bytes != 0 && !filter.ranges().is_empty());
    let prefix_block_plan = candidate_guard_active
        .then(|| prefix_block::derive(view.anchored_prefix.sets()))
        .flatten();
    let prefix_relation = derive_native_prefix_relation(view, start_filter);
    let prefix_relation_vector = prefix_relation
        .as_ref()
        .and_then(|relation| derive_native_prefix_relation_vector(relation, architecture));
    let selective_prefix_positions = view
        .anchored_prefix
        .sets()
        .iter()
        .filter(|set| set.cardinality() < 256)
        .count();
    let prefix_plan = derive_native_prefix_plan(
        view.anchored_prefix.sets(),
        filtered_prefix_position,
        candidate_guard_active,
        architecture,
        prefix_relation.is_some(),
    )?;
    let prefix_predicates = prefix_plan.predicates().len();
    let scanner_prefix_positions = usize::from(filtered_prefix_position.is_some());
    let exact_prefix_match_width = derive_exact_prefix_product_width(view).filter(|_| {
        selective_prefix_positions != 0
            && candidate_guard_active
            && prefix_predicates
                .checked_add(scanner_prefix_positions)
                .is_some_and(|covered| covered == selective_prefix_positions)
    });
    let prefix_fast_forward = if ENABLE_NATIVE_PREFIX_FAST_FORWARD
        && candidate_guard_active
        && exact_prefix_match_width.is_none()
    {
        prefix_fast_forward::derive(view, prefix_relation.is_some())
            .map(|plan| {
                if plan.consumed_bytes == 0 {
                    return Err(ObjectError::InvalidModule(
                        "native prefix fast-forward consumed no bytes",
                    ));
                }
                let target_state = usize::try_from(plan.target_state)
                    .map_err(|_| ObjectError::ArithmeticOverflow("native prefix target state"))?;
                let target_row_offset = target_state
                    .checked_mul(row_bytes)
                    .and_then(|offset| forward_offset.checked_add(offset))
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "native prefix target row offset",
                    ))?;
                Ok(NativePrefixFastForward {
                    consumed_bytes: plan.consumed_bytes,
                    target_row_offset: u32::try_from(target_row_offset).map_err(|_| {
                        ObjectError::ArithmeticOverflow("native prefix target row offset")
                    })?,
                })
            })
            .transpose()?
    } else {
        None
    };
    let prefix_bitmap_count = usize::from(prefix_plan.bitmap_count());
    let prefix_padding = if prefix_bitmap_count == 0 && prefix_relation.is_none() {
        0
    } else {
        let aligned = machine_bytes
            .checked_add(7)
            .ok_or(ObjectError::ArithmeticOverflow("native prefix alignment"))?
            & !7;
        aligned
            .checked_sub(machine_bytes)
            .ok_or(ObjectError::ArithmeticOverflow("native prefix padding"))?
    };
    let prefix_bytes = prefix_bitmap_count
        .checked_mul(PREFIX_BITMAP_BYTES)
        .and_then(|bytes| {
            bytes.checked_add(if prefix_relation.is_some() {
                PREFIX_RELATION_BITMAP_BYTES
            } else {
                0
            })
        })
        .ok_or(ObjectError::ArithmeticOverflow(
            "native prefix bitmap bytes",
        ))?;
    let prefix_total = machine_bytes
        .checked_add(prefix_padding)
        .and_then(|bytes| bytes.checked_add(prefix_bytes))
        .ok_or(ObjectError::ArithmeticOverflow("native DFA data bytes"))?;
    let (asimd_lane_index_offset, lane_index_padding) = if retains_asimd_candidate_mask {
        let aligned = prefix_total
            .checked_add(AARCH64_FIRST_LANE_INDEX.len() - 1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "AArch64 lane-index alignment",
            ))?
            & !(AARCH64_FIRST_LANE_INDEX.len() - 1);
        let padding = aligned
            .checked_sub(prefix_total)
            .ok_or(ObjectError::ArithmeticOverflow(
                "AArch64 lane-index padding",
            ))?;
        (
            Some(
                u32::try_from(aligned)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 lane-index offset"))?,
            ),
            padding,
        )
    } else {
        (None, 0)
    };
    let auxiliary_total = prefix_total
        .checked_add(lane_index_padding)
        .and_then(|bytes| {
            bytes.checked_add(if retains_asimd_candidate_mask {
                AARCH64_FIRST_LANE_INDEX.len()
            } else {
                0
            })
        })
        .ok_or(ObjectError::ArithmeticOverflow("native DFA data bytes"))?;
    let maximum_table_bytes = usize::try_from(CELL_NEXT_MASK)
        .map_err(|_| ObjectError::ArithmeticOverflow("native table address limit"))?;
    let remaining_sidecar_bytes = maximum_table_bytes
        .checked_sub(auxiliary_total)
        .and_then(|remaining| remaining.checked_sub(CLASS_MAP_BYTES))
        .unwrap_or(0);
    let mut seeded_limits = SeededReverseLimits::default();
    seeded_limits.max_cells = seeded_limits
        .max_cells
        .min(MAX_NATIVE_SEEDED_REVERSE_CELLS)
        .min(remaining_sidecar_bytes / core::mem::size_of::<u32>());
    seeded_limits.max_memory_bytes = seeded_limits
        .max_memory_bytes
        .min(MAX_NATIVE_SEEDED_REVERSE_MEMORY_BYTES)
        .min(remaining_sidecar_bytes);
    seeded_limits.max_addressable_bytes = seeded_limits
        .max_addressable_bytes
        .min(remaining_sidecar_bytes);
    let mut seeded_reverse_machine = suffix_filter.and_then(|suffix| {
        (seeded_limits.max_cells != 0 && seeded_limits.max_memory_bytes != 0)
            .then(|| build_native_seeded_reverse(view, suffix, seeded_limits))
            .flatten()
    });
    // Preserve the target- and output-independent graph fact even when this
    // output contract never requested the optional native reverse sidecar.
    let declined_redundant_root_reverse = suffix_filter.is_some_and(|suffix| {
        let NativeSuffixReverseSeed::RootState(root) = suffix.reverse_seed else {
            return false;
        };
        matches!(
            build_seeded_reverse_exact(
                view.raw,
                SeededReverseSeed::RootState(root),
                SeededReverseLimits::default(),
            ),
            SeededReverseBuild::Complete(dfa) if dfa.initial_reaches_start()
        )
    });
    if seeded_reverse_machine
        .as_ref()
        .is_some_and(|machine| !machine.proves_match && machine.dfa.initial_reaches_start())
    {
        // A root seed whose initial reverse row already reaches the search
        // start cannot reject its aligned mandatory-factor candidate. The
        // non-proving lowering would nevertheless retain the sidecar's
        // global-minimum collection pass before replaying the forward DFA.
        // Keep the independently selected suffix scanner, but decline this
        // strictly redundant reverse proof. Accept-seeded proofs still return
        // a complete Exists match, and root seeds whose initial row cannot
        // reach the start can still reject false candidates.
        seeded_reverse_machine = None;
    }
    if seeded_reverse_machine.as_ref().is_some_and(|machine| {
        machine
            .dfa
            .cells()
            .len()
            .checked_mul(core::mem::size_of::<u32>())
            .and_then(|bytes| bytes.checked_add(CLASS_MAP_BYTES))
            .is_none_or(|bytes| bytes > maximum_table_bytes.saturating_sub(auxiliary_total))
    }) {
        // Optional analysis must never turn an otherwise valid native module
        // into a table-address failure.
        seeded_reverse_machine = None;
    }
    let (mut seeded_reverse, seeded_reverse_bytes) =
        if let Some(machine) = seeded_reverse_machine.as_ref() {
            let class_map_offset = auxiliary_total;
            let initial_row_offset = class_map_offset.checked_add(CLASS_MAP_BYTES).ok_or(
                ObjectError::ArithmeticOverflow("native seeded reverse class map"),
            )?;
            if !initial_row_offset.is_multiple_of(core::mem::align_of::<u32>()) {
                return Err(ObjectError::InvalidModule(
                    "native seeded reverse rows are not aligned",
                ));
            }
            let cell_bytes = machine
                .dfa
                .cells()
                .len()
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(ObjectError::ArithmeticOverflow(
                    "native seeded reverse cells",
                ))?;
            let bytes =
                CLASS_MAP_BYTES
                    .checked_add(cell_bytes)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "native seeded reverse bytes",
                    ))?;
            (
                Some(NativeSeededReverseLayout {
                    class_map_offset: u32::try_from(class_map_offset).map_err(|_| {
                        ObjectError::ArithmeticOverflow("native seeded reverse class map offset")
                    })?,
                    initial_row_offset: u32::try_from(initial_row_offset).map_err(|_| {
                        ObjectError::ArithmeticOverflow("native seeded reverse row offset")
                    })?,
                    boundary_offset: machine.boundary_offset,
                    initial_reaches_start: machine.dfa.initial_reaches_start(),
                    proves_match: machine.proves_match,
                }),
                bytes,
            )
        } else {
            (None, 0)
        };
    let mut total = auxiliary_total
        .checked_add(seeded_reverse_bytes)
        .ok_or(ObjectError::ArithmeticOverflow("native DFA data bytes"))?;
    let forward_offset_u32 = u32::try_from(forward_offset)
        .map_err(|_| ObjectError::ArithmeticOverflow("native forward table offset"))?;
    let reverse_offset_u32 = u32::try_from(reverse_offset)
        .map_err(|_| ObjectError::ArithmeticOverflow("native reverse table offset"))?;
    // Two high cell bits are reserved for acceptance and accelerator dispatch.
    // Keeping the complete compact table below 1 GiB makes every absolute
    // next-row token fit the remaining low bits on both native backends.
    if total > maximum_table_bytes {
        return Err(ObjectError::Resource {
            resource: crate::CompileResource::ProgramBytes,
            limit: maximum_table_bytes,
            required: total,
        });
    }

    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(total).is_err() {
        if seeded_reverse.is_some() {
            // The sidecar is optional. Retry the exact baseline reservation
            // transactionally instead of converting optimizer memory pressure
            // into a compilation failure.
            seeded_reverse_machine = None;
            seeded_reverse = None;
            total = auxiliary_total;
            bytes
                .try_reserve_exact(total)
                .map_err(|_| ObjectError::InvalidModule("native DFA allocation failed"))?;
        } else {
            return Err(ObjectError::InvalidModule("native DFA allocation failed"));
        }
    }
    if transitions == TransitionLayout::ClassMapped {
        bytes.extend_from_slice(dfa.byte_classes);
    }
    match transitions {
        TransitionLayout::ClassMapped => {
            for &cell in dfa.forward_cells {
                bytes.extend_from_slice(
                    &pack_native_forward_cell(
                        cell.next,
                        cell.accepted,
                        forward_offset,
                        row_bytes,
                        forward_states,
                        start_filter.is_some(),
                        loop_skip.map(|plan| plan.state),
                    )?
                    .to_le_bytes(),
                );
            }
        }
        TransitionLayout::DirectByte => {
            for state in 0..forward_states {
                let row = state
                    .checked_mul(dfa.class_count)
                    .ok_or(ObjectError::ArithmeticOverflow("native forward row"))?;
                for &class in dfa.byte_classes {
                    let cell = *dfa
                        .forward_cells
                        .get(
                            row.checked_add(usize::from(class))
                                .ok_or(ObjectError::ArithmeticOverflow("native forward cell"))?,
                        )
                        .ok_or(ObjectError::InvalidModule("native forward cell"))?;
                    bytes.extend_from_slice(
                        &pack_native_forward_cell(
                            cell.next,
                            cell.accepted,
                            forward_offset,
                            row_bytes,
                            forward_states,
                            start_filter.is_some(),
                            loop_skip.map(|plan| plan.state),
                        )?
                        .to_le_bytes(),
                    );
                }
            }
        }
    }
    if wants_reverse {
        match transitions {
            TransitionLayout::ClassMapped => {
                for &cell in dfa.reverse_cells {
                    bytes.extend_from_slice(
                        &pack_native_cell(
                            cell.next,
                            cell.reaches_start,
                            reverse_offset,
                            row_bytes,
                            retained_reverse_states,
                        )?
                        .to_le_bytes(),
                    );
                }
            }
            TransitionLayout::DirectByte => {
                for state in 0..retained_reverse_states {
                    let row = state
                        .checked_mul(dfa.class_count)
                        .ok_or(ObjectError::ArithmeticOverflow("native reverse row"))?;
                    for &class in dfa.byte_classes {
                        let cell =
                            *dfa.reverse_cells
                                .get(row.checked_add(usize::from(class)).ok_or(
                                    ObjectError::ArithmeticOverflow("native reverse cell"),
                                )?)
                                .ok_or(ObjectError::InvalidModule("native reverse cell"))?;
                        bytes.extend_from_slice(
                            &pack_native_cell(
                                cell.next,
                                cell.reaches_start,
                                reverse_offset,
                                row_bytes,
                                retained_reverse_states,
                            )?
                            .to_le_bytes(),
                        );
                    }
                }
            }
        }
    }
    if bytes.len() != machine_bytes {
        return Err(ObjectError::InvalidModule(
            "native DFA table emitted an unexpected size",
        ));
    }
    bytes.resize(
        bytes
            .len()
            .checked_add(prefix_padding)
            .ok_or(ObjectError::ArithmeticOverflow("native prefix padding"))?,
        0,
    );
    let prefix_filter =
        append_native_prefix_filter(&mut bytes, prefix_plan, view.anchored_prefix.sets().len())?;
    let prefix_relation = prefix_relation
        .as_ref()
        .map(|relation| append_native_prefix_relation(&mut bytes, relation, prefix_relation_vector))
        .transpose()?;
    if let Some(offset) = asimd_lane_index_offset {
        bytes.resize(
            usize::try_from(offset)
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 lane-index offset"))?,
            0,
        );
        bytes.extend_from_slice(&AARCH64_FIRST_LANE_INDEX);
    }
    if let (Some(machine), Some(sidecar)) = (seeded_reverse_machine.as_ref(), seeded_reverse) {
        if bytes.len()
            != usize::try_from(sidecar.class_map_offset).map_err(|_| {
                ObjectError::ArithmeticOverflow("native seeded reverse class map offset")
            })?
        {
            return Err(ObjectError::InvalidModule(
                "native seeded reverse class map moved during lowering",
            ));
        }
        bytes.extend_from_slice(machine.dfa.byte_classes());
        if bytes.len()
            != usize::try_from(sidecar.initial_row_offset)
                .map_err(|_| ObjectError::ArithmeticOverflow("native seeded reverse row offset"))?
        {
            return Err(ObjectError::InvalidModule(
                "native seeded reverse row table moved during lowering",
            ));
        }
        let class_count = machine.dfa.class_count();
        let row_bytes = class_count.checked_mul(core::mem::size_of::<u32>()).ok_or(
            ObjectError::ArithmeticOverflow("native seeded reverse row bytes"),
        )?;
        for &cell in machine.dfa.cells() {
            bytes.extend_from_slice(
                &pack_native_cell(
                    cell.next,
                    cell.reaches_start,
                    usize::try_from(sidecar.initial_row_offset).map_err(|_| {
                        ObjectError::ArithmeticOverflow("native seeded reverse row offset")
                    })?,
                    row_bytes,
                    machine.dfa.state_count(),
                )?
                .to_le_bytes(),
            );
        }
    }
    if bytes.len() != total {
        return Err(ObjectError::InvalidModule(
            "native auxiliary table emitted an unexpected size",
        ));
    }
    let prefix_block = prefix_block_plan
        .map(|plan| append_native_prefix_block(&mut bytes, plan, maximum_table_bytes))
        .transpose()?
        .flatten();
    Ok((
        bytes,
        NativeDfaLayout {
            transitions,
            forward_offset: forward_offset_u32,
            reverse_offset: reverse_offset_u32,
            asimd_lane_index_offset,
            initial_pending: dfa.initial_pending,
            initial_terminal: dfa.initial_terminal,
            has_reverse: wants_reverse,
            exact_span_width,
            exact_prefix_match_width,
            output: view.output,
            start_filter,
            suffix_filter,
            declined_redundant_root_reverse,
            seeded_reverse,
            loop_skip,
            vector_filter,
            prefix_filter,
            prefix_relation,
            prefix_block,
            prefix_fast_forward,
        },
    ))
}

fn derive_native_prefix_plan(
    sets: &[AnchoredByteSet],
    filtered_position: Option<usize>,
    enabled: bool,
    architecture: Architecture,
    relation_covers_first_two: bool,
) -> Result<ScalarPrefixConjunctionPlan, ObjectError> {
    let mut inputs = Vec::new();
    if enabled {
        inputs
            .try_reserve_exact(sets.len())
            .map_err(|_| ObjectError::InvalidModule("native prefix-plan allocation failed"))?;
        for (position, set) in sets.iter().copied().enumerate() {
            if (relation_covers_first_two && position < 2)
                || Some(position) == filtered_position
                || set.cardinality() == 256
            {
                continue;
            }
            inputs.push(PrefixPredicateInput::new(
                u8::try_from(position)
                    .map_err(|_| ObjectError::ArithmeticOverflow("native prefix position"))?,
                set.words(),
            ));
        }
    }
    let costs: ScalarPrefixPredicateCosts = match architecture {
        Architecture::X86_64 => X86_64_SCALAR_PREFIX_COSTS,
        Architecture::Aarch64 => AARCH64_SCALAR_PREFIX_COSTS,
    };
    let mut byte_weights = [0_u16; 256];
    for byte in u8::MIN..=u8::MAX {
        byte_weights[usize::from(byte)] = estimated_byte_frequency_units(byte);
    }
    plan_scalar_prefix_predicates(&inputs, costs, &byte_weights)
        .map_err(|_| ObjectError::InvalidModule("native prefix predicate plan failed"))
}

fn derive_native_prefix_relation(
    view: NativeProgramView<'_>,
    start_filter: Option<NativeStartFilter>,
) -> Option<PrefixRelation> {
    // The pair guard is entered only from a real moving scanner. Requiring an
    // anchored primary bounds both its invocation frequency and the subset of
    // the 8-KiB matrix that can become hot.
    let primary = start_filter.filter(|filter| {
        filter.from_anchored_prefix && filter.candidate_bytes != 0 && !filter.ranges().is_empty()
    })?;
    let sets = view.anchored_prefix.sets();
    let [first, second, ..] = sets else {
        return None;
    };
    // The pair matrix has one 32-byte row per first byte. Bound its reachable
    // hot working set to at most 2 KiB independently of which pair position
    // supplied the primary scanner candidate.
    if first.cardinality() > 64 {
        return None;
    }
    let relation = prefix_relation::derive(view.raw)?;
    let independent_pairs =
        u32::from(first.cardinality()).checked_mul(u32::from(second.cardinality()))?;
    let correlated_pairs = relation.pair_count();
    if correlated_pairs == 0 || correlated_pairs >= independent_pairs {
        return None;
    }

    // A matrix lookup replaces the independent predicates for positions zero
    // and one. Admit it when correlation removes at least one quarter of their
    // Cartesian product, a target-neutral cost gate that pays for the extra
    // table footprint without consulting source text or benchmark data.
    if correlated_pairs.checked_mul(4)? > independent_pairs.checked_mul(3)? {
        return None;
    }
    // When the scanner primary is beyond the pair, every matrix row could be
    // touched independently of that primary. Keep the compact working-set
    // proof local to one of the two bytes represented by the matrix.
    if primary.scan_offset >= 2 {
        return None;
    }
    Some(relation)
}

fn anchored_set_contains(set: AnchoredByteSet, byte: u8) -> bool {
    let index = usize::from(byte);
    set.words()[index / 64] & (1_u64 << (index % 64)) != 0
}

fn prefix_relation_contains(relation: &PrefixRelation, first: u8, second: u8) -> bool {
    relation.groups().iter().any(|group| {
        anchored_set_contains(group.first(), first) && anchored_set_contains(group.second(), second)
    })
}

fn native_prefix_relation_filter_from_words(
    words: [u64; 4],
    position: u8,
) -> Option<NativeStartFilter> {
    let candidate_bytes = words.iter().try_fold(0_u16, |count, word| {
        count.checked_add(u16::try_from(word.count_ones()).ok()?)
    })?;
    if candidate_bytes == 0 || candidate_bytes == 256 {
        return None;
    }
    let mut ranges = [EMPTY_NATIVE_BYTE_RANGE; MAX_START_FILTER_RANGES];
    let mut range_count = 0_usize;
    for byte in u8::MIN..=u8::MAX {
        let index = usize::from(byte);
        if words[index / 64] & (1_u64 << (index % 64)) == 0 {
            continue;
        }
        if let Some(last) = range_count
            .checked_sub(1)
            .and_then(|index| ranges.get_mut(index))
            && last.end.checked_add(1) == Some(byte)
        {
            last.end = byte;
            continue;
        }
        let slot = ranges.get_mut(range_count)?;
        *slot = NativeByteRange {
            start: byte,
            end: byte,
        };
        range_count = range_count.checked_add(1)?;
    }
    let exact = ranges[..range_count]
        .iter()
        .all(|range| range.start == range.end);
    if !exact && range_count > MAX_NON_EXACT_START_FILTER_RANGES {
        return None;
    }
    Some(NativeStartFilter {
        ranges,
        range_count: u8::try_from(range_count).ok()?,
        candidate_bytes,
        scan_offset: position,
        from_anchored_prefix: false,
    })
}

fn native_prefix_relation_predicate(
    set: AnchoredByteSet,
    position: u8,
) -> Option<NativePrefixRelationPredicate> {
    let words = set.words();
    let cardinality = words.iter().map(|word| word.count_ones()).sum::<u32>();
    if cardinality == 0 {
        return None;
    }
    if cardinality == 256 {
        return Some(NativePrefixRelationPredicate {
            any: true,
            ..EMPTY_NATIVE_PREFIX_RELATION_PREDICATE
        });
    }

    let positive = native_prefix_relation_filter_from_words(words, position).map(|filter| {
        NativePrefixRelationPredicate {
            filter,
            negated: false,
            any: false,
            first_constant: 0,
        }
    });
    let complement_words = words.map(|word| !word);
    let negative =
        native_prefix_relation_filter_from_words(complement_words, position).map(|filter| {
            NativePrefixRelationPredicate {
                filter,
                negated: true,
                any: false,
                first_constant: 0,
            }
        });
    [positive, negative]
        .into_iter()
        .flatten()
        .min_by_key(|predicate| {
            (
                predicate.filter.constant_count(),
                vector_filter_instruction_units(predicate.filter)
                    .saturating_add(u16::from(predicate.negated)),
                predicate.negated,
            )
        })
}

fn native_prefix_relation_predicate_contains(
    predicate: NativePrefixRelationPredicate,
    byte: u8,
) -> bool {
    if predicate.any {
        return true;
    }
    let contained = predicate
        .filter
        .ranges()
        .iter()
        .any(|range| range.start <= byte && byte <= range.end);
    contained ^ predicate.negated
}

fn native_prefix_relation_vector_contains(
    plan: NativePrefixRelationVectorPlan,
    first: u8,
    second: u8,
) -> bool {
    plan.rectangles().iter().any(|rectangle| {
        native_prefix_relation_predicate_contains(rectangle.first, first)
            && native_prefix_relation_predicate_contains(rectangle.second, second)
    })
}

/// Lower the graph pass's canonical disjoint-row rectangles directly to a
/// bounded target SIMD plan. Each leaf is an exact union of singleton/range
/// comparisons, or the exact complement of one when that uses fewer
/// constants. Admission is transactional: the complete 65,536-pair relation
/// is reconstructed before publishing the optional vector form, while the
/// scalar bitmap remains available for every declined relation.
fn derive_native_prefix_relation_vector(
    relation: &PrefixRelation,
    architecture: Architecture,
) -> Option<NativePrefixRelationVectorPlan> {
    if relation.pair_count() == 0
        || relation.groups().is_empty()
        || relation.groups().len() > MAX_NATIVE_PREFIX_RELATION_RECTANGLES
    {
        return None;
    }
    let (constant_limit, instruction_limit) = match architecture {
        Architecture::X86_64 => (
            MAX_X86_PREFIX_RELATION_CONSTANTS,
            MAX_X86_PREFIX_RELATION_INSTRUCTION_UNITS,
        ),
        Architecture::Aarch64 => (
            MAX_AARCH64_PREFIX_RELATION_CONSTANTS,
            MAX_AARCH64_PREFIX_RELATION_INSTRUCTION_UNITS,
        ),
    };
    let mut rectangles =
        [EMPTY_NATIVE_PREFIX_RELATION_RECTANGLE; MAX_NATIVE_PREFIX_RELATION_RECTANGLES];
    let mut constant_count = 0_u8;
    let mut instruction_units = 0_u16;
    for (index, group) in relation.groups().iter().copied().enumerate() {
        let mut first = native_prefix_relation_predicate(group.first(), 0)?;
        let mut second = native_prefix_relation_predicate(group.second(), 1)?;
        for predicate in [&mut first, &mut second] {
            if predicate.any {
                continue;
            }
            predicate.first_constant = constant_count.checked_add(1)?;
            constant_count = constant_count
                .checked_add(u8::try_from(predicate.filter.constant_count()).ok()?)?;
            instruction_units = instruction_units
                .checked_add(vector_filter_instruction_units(predicate.filter))?
                .checked_add(u16::from(predicate.negated))?;
        }
        if !first.any && !second.any {
            instruction_units = instruction_units.checked_add(1)?;
        }
        if index != 0 {
            instruction_units = instruction_units.checked_add(1)?;
        }
        rectangles[index] = NativePrefixRelationRectangle { first, second };
    }
    if constant_count > constant_limit || instruction_units > instruction_limit {
        return None;
    }
    let plan = NativePrefixRelationVectorPlan {
        rectangles,
        rectangle_count: u8::try_from(relation.groups().len()).ok()?,
        constant_count,
        instruction_units,
    };
    for first in u8::MIN..=u8::MAX {
        for second in u8::MIN..=u8::MAX {
            if native_prefix_relation_vector_contains(plan, first, second)
                != prefix_relation_contains(relation, first, second)
            {
                return None;
            }
        }
    }
    Some(plan)
}

fn append_native_prefix_relation(
    bytes: &mut Vec<u8>,
    relation: &PrefixRelation,
    vector_plan: Option<NativePrefixRelationVectorPlan>,
) -> Result<NativePrefixRelationFilter, ObjectError> {
    if !bytes.len().is_multiple_of(core::mem::size_of::<u64>()) {
        return Err(ObjectError::InvalidModule(
            "native prefix relation is not word aligned",
        ));
    }
    let bitmap_offset = u32::try_from(bytes.len())
        .map_err(|_| ObjectError::ArithmeticOverflow("native prefix relation offset"))?;
    let end = bytes
        .len()
        .checked_add(PREFIX_RELATION_BITMAP_BYTES)
        .ok_or(ObjectError::ArithmeticOverflow(
            "native prefix relation bytes",
        ))?;
    bytes.resize(end, 0);
    let start = usize::try_from(bitmap_offset)
        .map_err(|_| ObjectError::ArithmeticOverflow("native prefix relation bitmap offset"))?;
    let bitmap = bytes.get_mut(start..end).ok_or(ObjectError::InvalidModule(
        "native prefix relation bitmap extent",
    ))?;
    for group in relation.groups() {
        for first in u8::MIN..=u8::MAX {
            if !anchored_set_contains(group.first(), first) {
                continue;
            }
            for second in u8::MIN..=u8::MAX {
                if !anchored_set_contains(group.second(), second) {
                    continue;
                }
                let pair = usize::from(first) | (usize::from(second) << 8);
                bitmap[pair / 8] |= 1_u8 << (pair % 8);
            }
        }
    }
    Ok(NativePrefixRelationFilter {
        bitmap_offset,
        vector_plan,
    })
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the fixed-size copyable plan is consumed while appending its serialized predicates"
)]
fn append_native_prefix_filter(
    bytes: &mut Vec<u8>,
    plan: ScalarPrefixConjunctionPlan,
    guaranteed_bytes: usize,
) -> Result<Option<NativePrefixFilter>, ObjectError> {
    if plan.predicates().is_empty() {
        return Ok(None);
    }
    let empty = NativePrefixPredicate {
        position: 0,
        membership: ScalarPrefixMembership::RejectAll,
        bitmap_offset: 0,
    };
    let mut predicates = [empty; MAX_NATIVE_PREFIX_PREDICATES];
    let mut count = 0_usize;
    for planned in plan.predicates().iter().copied() {
        let slot = predicates.get_mut(count).ok_or(ObjectError::InvalidModule(
            "too many native prefix predicates",
        ))?;
        let bitmap_offset = if planned.membership() == ScalarPrefixMembership::Bitmap256 {
            let offset = u32::try_from(bytes.len())
                .map_err(|_| ObjectError::ArithmeticOverflow("native prefix bitmap offset"))?;
            for word in planned.words() {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            offset
        } else {
            0
        };
        *slot = NativePrefixPredicate {
            position: planned.position(),
            membership: planned.membership(),
            bitmap_offset,
        };
        count = count.checked_add(1).ok_or(ObjectError::ArithmeticOverflow(
            "native prefix predicate count",
        ))?;
    }
    if count != plan.predicates().len() {
        return Err(ObjectError::InvalidModule(
            "native prefix predicate count changed during lowering",
        ));
    }
    Ok(Some(NativePrefixFilter {
        predicates,
        predicate_count: u8::try_from(count)
            .map_err(|_| ObjectError::ArithmeticOverflow("native prefix predicate count"))?,
        guaranteed_bytes: u8::try_from(guaranteed_bytes)
            .map_err(|_| ObjectError::ArithmeticOverflow("native prefix length"))?,
    }))
}

/// Append one optional block guard without exposing a partial layout.
///
/// The semantic scalar predicates remain installed regardless of this result,
/// so address-space or allocation pressure can decline the optimization after
/// the complete mandatory DFA and optional reverse sidecar have been built.
fn append_native_prefix_block(
    bytes: &mut Vec<u8>,
    plan: PrefixBlockPlan,
    maximum_table_bytes: usize,
) -> Result<Option<NativePrefixBlockGuard>, ObjectError> {
    let aligned = bytes.len().checked_add(PREFIX_BLOCK_ALIGNMENT - 1).ok_or(
        ObjectError::ArithmeticOverflow("native prefix-block alignment"),
    )? & !(PREFIX_BLOCK_ALIGNMENT - 1);
    let end = aligned
        .checked_add(PREFIX_BLOCK_SERIALIZED_BYTES)
        .ok_or(ObjectError::ArithmeticOverflow("native prefix-block bytes"))?;
    if end > maximum_table_bytes {
        return Ok(None);
    }
    let additional = end
        .checked_sub(bytes.len())
        .ok_or(ObjectError::ArithmeticOverflow("native prefix-block bytes"))?;
    if bytes.try_reserve_exact(additional).is_err() {
        return Ok(None);
    }
    let expected_offset = u32::try_from(aligned)
        .map_err(|_| ObjectError::ArithmeticOverflow("native prefix-block expected offset"))?;
    let byte_mask_offset = aligned
        .checked_add(prefix_block::PREFIX_BLOCK_BYTES)
        .and_then(|offset| u32::try_from(offset).ok())
        .ok_or(ObjectError::ArithmeticOverflow(
            "native prefix-block mask offset",
        ))?;
    bytes.resize(aligned, 0);
    bytes.extend_from_slice(&plan.expected());
    bytes.extend_from_slice(&plan.byte_mask());
    if bytes.len() != end {
        return Err(ObjectError::InvalidModule(
            "native prefix-block constants changed extent",
        ));
    }
    Ok(Some(NativePrefixBlockGuard {
        expected_offset,
        byte_mask_offset,
        lane_mask: plan.lane_mask(),
    }))
}

fn derive_start_filter(
    view: NativeProgramView<'_>,
) -> Result<Option<NativeStartFilter>, ObjectError> {
    let anchored = derive_anchored_prefix_start_filter(view.anchored_prefix.sets())?;
    let initial = derive_initial_start_filter(view)?;
    Ok(match (anchored, initial) {
        (Some(anchored), Some(initial)) => {
            if filter_selection_key(anchored) <= filter_selection_key(initial) {
                Some(anchored)
            } else {
                Some(initial)
            }
        }
        (Some(filter), None) | (None, Some(filter)) => Some(filter),
        (None, None) => None,
    })
}

fn derive_suffix_filter(
    view: NativeProgramView<'_>,
) -> Result<Option<NativeSuffixFilter>, ObjectError> {
    if view.dfa.initial_pending {
        return Ok(None);
    }
    let mut best = derive_terminal_suffix_filter(view)?;
    let mut best_is_terminal = best.is_some();
    for candidate in view.required_literals.interior().candidates() {
        let Some(interior) = derive_interior_filter(view, candidate)? else {
            continue;
        };
        let replace = best.is_none_or(|current| {
            let interior_key = mandatory_filter_selection_key(interior);
            let current_key = mandatory_filter_selection_key(current);
            interior_key.0 < current_key.0 || (!best_is_terminal && interior_key < current_key)
        });
        if replace {
            best = Some(interior);
            best_is_terminal = false;
        }
    }
    Ok(best)
}

/// Build an independently determinized reverse proof for mandatory factors in
/// the Exists contract. It can return directly for an Accept seed and can use
/// one ordered forward replay for an interior seed after raising the semantic
/// lower bound. The admission rule depends only on graph facts and the
/// existing target-neutral candidate cost model. A proven synchronizing
/// restart remains on its cheaper bounded backward scan.
fn build_native_seeded_reverse(
    view: NativeProgramView<'_>,
    suffix: NativeSuffixFilter,
    limits: SeededReverseLimits,
) -> Option<NativeSeededReverseMachine> {
    if view.output != OutputContract::Exists
        || suffix.retry.is_some()
        || suffix.filter.candidate_bytes == 0
        || suffix.filter.ranges().is_empty()
        || matches!(suffix.restart, NativeSuffixRestart::Synchronizing { .. })
    {
        return None;
    }
    let (seed, boundary_offset, proves_match) = match suffix.reverse_seed {
        NativeSuffixReverseSeed::AcceptBoundary => {
            (SeededReverseSeed::AcceptStates, suffix.minimum_width, true)
        }
        NativeSuffixReverseSeed::RootState(root) => (SeededReverseSeed::RootState(root), 0, false),
    };
    match build_seeded_reverse_exact(view.raw, seed, limits) {
        SeededReverseBuild::Complete(dfa) => Some(NativeSeededReverseMachine {
            dfa,
            boundary_offset,
            proves_match,
        }),
        SeededReverseBuild::Declined(_) => None,
    }
}

fn derive_terminal_suffix_filter(
    view: NativeProgramView<'_>,
) -> Result<Option<NativeSuffixFilter>, ObjectError> {
    let suffix_sets = view.anchored_suffix.sets();
    if suffix_sets.is_empty() {
        return Ok(None);
    }
    let minimum_width = u8::try_from(suffix_sets.len())
        .map_err(|_| ObjectError::ArithmeticOverflow("native minimum suffix width"))?;

    let mut forward_sets = Vec::new();
    forward_sets
        .try_reserve_exact(suffix_sets.len())
        .map_err(|_| ObjectError::InvalidModule("native suffix-filter allocation failed"))?;
    forward_sets.extend(suffix_sets.iter().rev().copied());
    let Some((filter, vector_filter, scalar_filter)) =
        derive_aligned_mandatory_filter(&forward_sets)?
    else {
        return Ok(None);
    };
    let restart = if let Some(maximum_width) = view.max_match_width {
        let maximum_width = u64::try_from(maximum_width)
            .map_err(|_| ObjectError::ArithmeticOverflow("native maximum match width"))?;
        if maximum_width < u64::from(minimum_width) {
            return Err(ObjectError::InvalidModule(
                "native maximum width is below its anchored suffix",
            ));
        }
        NativeSuffixRestart::Bounded {
            backtrack: maximum_width.checked_sub(u64::from(minimum_width)).ok_or(
                ObjectError::InvalidModule("native suffix backtrack underflow"),
            )?,
        }
    } else if let Some(reset) = view
        .dfa
        .synchronizing_reset_bytes()
        .filter(|reset| reset.cardinality != 0)
    {
        let complement = reset.membership.words.map(|word| !word);
        if let Some(non_reset) = reset_filter_from_membership_words(complement)? {
            NativeSuffixRestart::Synchronizing { non_reset }
        } else {
            NativeSuffixRestart::OriginalStart
        }
    } else {
        NativeSuffixRestart::OriginalStart
    };
    let retry = select_bounded_suffix_retry(
        view.output,
        view.dfa.initial_pending,
        minimum_width,
        view.max_match_width,
        estimated_filter_frequency_units(filter),
    );
    let retry_cost_rejected = retry.is_none()
        && view.output == OutputContract::Exists
        && !view.dfa.initial_pending
        && view.max_match_width.is_some_and(|maximum| {
            u64::try_from(maximum).is_ok_and(|maximum| maximum >= u64::from(minimum_width))
        });
    Ok(Some(NativeSuffixFilter {
        filter,
        vector_filter,
        scalar_filter,
        minimum_width,
        restart,
        retry,
        retry_cost_rejected,
        reverse_seed: NativeSuffixReverseSeed::AcceptBoundary,
    }))
}

fn derive_interior_filter(
    view: NativeProgramView<'_>,
    candidate: &RequiredInteriorCandidate,
) -> Result<Option<NativeSuffixFilter>, ObjectError> {
    let forward_sets = aligned_sets_from_required_literals(candidate.literal_set())?;
    let minimum_width = u8::try_from(forward_sets.len())
        .map_err(|_| ObjectError::ArithmeticOverflow("native interior-filter width"))?;
    if minimum_width == 0 {
        return Ok(None);
    }
    let Some((filter, vector_filter, scalar_filter)) =
        derive_aligned_mandatory_filter(&forward_sets)?
    else {
        return Ok(None);
    };
    let restart = match candidate.max_before_root() {
        MaximumConsumedDistance::Finite(backtrack) => NativeSuffixRestart::Bounded {
            backtrack: u64::from(backtrack),
        },
        MaximumConsumedDistance::Unbounded => derive_unbounded_mandatory_restart(view)?,
    };
    let finite_retry_shape = match (candidate.max_before_root(), candidate.max_through_accept()) {
        (
            MaximumConsumedDistance::Finite(_),
            MaximumConsumedDistance::Finite(max_through_accept),
        ) => {
            view.output == OutputContract::Exists
                && !view.dfa.initial_pending
                && u64::from(max_through_accept) >= u64::from(minimum_width)
        }
        _ => false,
    };
    let retry = match (candidate.max_before_root(), candidate.max_through_accept()) {
        (
            MaximumConsumedDistance::Finite(max_before_root),
            MaximumConsumedDistance::Finite(max_through_accept),
        ) => select_bounded_interior_retry(
            view.output,
            view.dfa.initial_pending,
            minimum_width,
            max_before_root,
            max_through_accept,
            estimated_filter_frequency_units(filter),
        ),
        _ => None,
    };
    Ok(Some(NativeSuffixFilter {
        filter,
        vector_filter,
        scalar_filter,
        minimum_width,
        restart,
        retry,
        retry_cost_rejected: finite_retry_shape && retry.is_none(),
        reverse_seed: NativeSuffixReverseSeed::RootState(candidate.root_state()),
    }))
}

fn aligned_sets_from_required_literals(
    literals: &RequiredLiteralSet,
) -> Result<Vec<AnchoredByteSet>, ObjectError> {
    let depth = literals.depth();
    if depth == 0 || literals.literals().is_empty() {
        return Ok(Vec::new());
    }
    let mut words = Vec::new();
    words
        .try_reserve_exact(depth)
        .map_err(|_| ObjectError::InvalidModule("native interior-filter allocation failed"))?;
    words.resize(depth, [0_u64; 4]);
    for literal in literals.literals() {
        let bytes = literal.as_bytes();
        if bytes.len() != depth {
            return Err(ObjectError::InvalidModule(
                "native interior literal depths disagree",
            ));
        }
        for (position, &byte) in bytes.iter().enumerate() {
            let index = usize::from(byte);
            words[position][index / 64] |= 1_u64 << (index % 64);
        }
    }
    Ok(words.into_iter().map(AnchoredByteSet::from_words).collect())
}

#[allow(
    clippy::type_complexity,
    reason = "the tuple mirrors the primary, vector, and scalar filter stages at its sole call site"
)]
fn derive_aligned_mandatory_filter(
    forward_sets: &[AnchoredByteSet],
) -> Result<
    Option<(
        NativeStartFilter,
        Option<NativeVectorFilter>,
        Option<NativeVectorFilter>,
    )>,
    ObjectError,
> {
    let mut filter = None;
    for (position, set) in forward_sets.iter().copied().enumerate() {
        let Some(mut candidate) = start_filter_from_anchored_set(set, position)? else {
            continue;
        };
        candidate.from_anchored_prefix = false;
        let candidate_key = filter_selection_key(candidate);
        let replace = filter
            .is_none_or(|current: NativeStartFilter| candidate_key < filter_selection_key(current));
        if replace {
            filter = Some(candidate);
        }
    }
    let Some(filter) = filter else {
        return Ok(None);
    };
    let mut vector_filter = derive_vector_filter(Some(filter), forward_sets)?;
    if let Some(columns) = &mut vector_filter {
        for column in &mut columns.columns[..usize::from(columns.column_count)] {
            column.from_anchored_prefix = false;
        }
    }
    let scalar_filter = if vector_filter.is_none()
        && estimated_filter_frequency_units(filter) <= MAX_SCALAR_REFINEMENT_PRIMARY_FREQUENCY_UNITS
    {
        derive_scalar_aligned_filter(filter, forward_sets)?
    } else {
        None
    };
    Ok(Some((filter, vector_filter, scalar_filter)))
}

fn derive_scalar_aligned_filter(
    primary: NativeStartFilter,
    sets: &[AnchoredByteSet],
) -> Result<Option<NativeVectorFilter>, ObjectError> {
    let mut candidates = [EMPTY_NATIVE_START_FILTER; MAX_ANCHORED_PREFIX_BYTES];
    let mut candidate_count = 0_usize;
    for (position, set) in sets.iter().copied().enumerate() {
        let Some(mut candidate) = start_filter_from_anchored_set(set, position)? else {
            continue;
        };
        candidate.from_anchored_prefix = false;
        if candidate.ranges().is_empty()
            || (candidate.scan_offset == primary.scan_offset
                && candidate.ranges() == primary.ranges())
        {
            continue;
        }
        let slot = candidates
            .get_mut(candidate_count)
            .ok_or(ObjectError::InvalidModule("too many scalar-filter columns"))?;
        *slot = candidate;
        candidate_count = candidate_count
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native scalar-filter columns",
            ))?;
    }
    if candidate_count == 0 {
        return Ok(None);
    }
    candidates[..candidate_count].sort_unstable_by_key(|candidate| {
        (
            filter_selection_key(*candidate),
            vector_filter_instruction_units(*candidate),
        )
    });
    let mut columns = [EMPTY_NATIVE_START_FILTER; MAX_VECTOR_FILTER_COLUMNS];
    columns[0] = primary;
    let retained = candidate_count.min(MAX_VECTOR_FILTER_COLUMNS.saturating_sub(1));
    columns[1..=retained].copy_from_slice(&candidates[..retained]);
    Ok(Some(NativeVectorFilter {
        columns,
        column_count: u8::try_from(retained.saturating_add(1))
            .map_err(|_| ObjectError::ArithmeticOverflow("native scalar-filter columns"))?,
    }))
}

fn derive_unbounded_mandatory_restart(
    view: NativeProgramView<'_>,
) -> Result<NativeSuffixRestart, ObjectError> {
    if let Some(reset) = view
        .dfa
        .synchronizing_reset_bytes()
        .filter(|reset| reset.cardinality != 0)
    {
        let complement = reset.membership.words.map(|word| !word);
        if let Some(non_reset) = reset_filter_from_membership_words(complement)? {
            return Ok(NativeSuffixRestart::Synchronizing { non_reset });
        }
    }
    Ok(NativeSuffixRestart::OriginalStart)
}

fn mandatory_filter_selection_key(
    filter: NativeSuffixFilter,
) -> (u64, bool, u64, (u16, u16, u16, u8, u8)) {
    let mut probability = 1_u64;
    let refinement = filter.vector_filter.or(filter.scalar_filter);
    let column_count = if let Some(vector) = refinement {
        for &column in vector.columns() {
            probability =
                probability.saturating_mul(u64::from(estimated_filter_frequency_units(column)));
        }
        vector.columns().len()
    } else {
        probability = u64::from(estimated_filter_frequency_units(filter.filter));
        1
    };
    for _ in column_count..MAX_VECTOR_FILTER_COLUMNS {
        probability = probability.saturating_mul(u64::from(BYTE_FREQUENCY_DENOMINATOR));
    }
    (
        probability,
        filter.retry.is_none(),
        filter
            .retry
            .map_or(u64::MAX, BoundedSuffixRetryPlan::estimated_transition_units),
        filter_selection_key(filter.filter),
    )
}

fn estimated_byte_frequency_units(byte: u8) -> u16 {
    match BYTE_FREQUENCY_RANK[usize::from(byte)] {
        255 => 32,
        248..=254 => 24,
        240..=247 => 16,
        224..=239 => 8,
        192..=223 => 4,
        128..=191 => 2,
        _ => 1,
    }
}

fn estimated_filter_frequency_units(filter: NativeStartFilter) -> u16 {
    let mut units = 0_u16;
    for range in filter.ranges() {
        for byte in range.start..=range.end {
            units = units.saturating_add(estimated_byte_frequency_units(byte));
        }
    }
    units.min(BYTE_FREQUENCY_DENOMINATOR)
}

fn filter_frequency_rank_sum(filter: NativeStartFilter) -> u16 {
    let mut sum = 0_u16;
    for range in filter.ranges() {
        for byte in range.start..=range.end {
            sum = sum.saturating_add(u16::from(BYTE_FREQUENCY_RANK[usize::from(byte)]));
        }
    }
    sum
}

fn filter_selection_key(filter: NativeStartFilter) -> (u16, u16, u16, u8, u8) {
    (
        estimated_filter_frequency_units(filter),
        filter.candidate_bytes,
        filter_frequency_rank_sum(filter),
        filter.range_count,
        u8::MAX.saturating_sub(filter.scan_offset),
    )
}

/// Relative vector instructions needed to form one exact lane-membership
/// mask, excluding the common load. Exact alternatives use equality plus OR;
/// inclusive ranges use two unsigned bounds, AND and accumulation.
fn vector_filter_instruction_units(filter: NativeStartFilter) -> u16 {
    let ranges = u16::from(filter.range_count);
    if filter.is_exact() {
        ranges.saturating_mul(2).saturating_sub(1)
    } else {
        ranges.saturating_mul(4)
    }
}

/// Decide a SIMD batching policy from graph-derived membership and a stable
/// offline byte-frequency model. This deliberately does not inspect regex
/// source identity, benchmark identity or runtime samples.
fn filter_fits_expected_hit_budget(
    filter: NativeStartFilter,
    scanned_bytes: u16,
    maximum_expected_hits: u16,
) -> bool {
    if filter.ranges().is_empty()
        || vector_filter_instruction_units(filter) > MAX_VECTOR_FILTER_INSTRUCTION_UNITS
    {
        return false;
    }
    u64::from(estimated_filter_frequency_units(filter)) * u64::from(scanned_bytes)
        <= u64::from(maximum_expected_hits) * u64::from(BYTE_FREQUENCY_DENOMINATOR)
}

fn use_aarch64_filter_batch(filter: NativeStartFilter) -> bool {
    filter_fits_expected_hit_budget(filter, AARCH64_BATCH_BYTES, MAX_ASIMD_BATCH_EXPECTED_HITS)
}

#[allow(
    clippy::too_many_lines,
    reason = "selection, register budgeting and probability accounting form one auditable cost decision"
)]
fn derive_vector_filter(
    primary: Option<NativeStartFilter>,
    sets: &[AnchoredByteSet],
) -> Result<Option<NativeVectorFilter>, ObjectError> {
    let Some(primary) = primary.filter(|filter| {
        !filter.ranges().is_empty()
            && filter.constant_count() <= MAX_VECTOR_FILTER_CONSTANTS
            && vector_filter_instruction_units(*filter) <= MAX_VECTOR_FILTER_INSTRUCTION_UNITS
    }) else {
        return Ok(None);
    };
    let mut candidates = [EMPTY_NATIVE_START_FILTER; MAX_ANCHORED_PREFIX_BYTES];
    let mut candidate_count = 0_usize;
    for (position, set) in sets.iter().copied().enumerate() {
        let Some(candidate) = start_filter_from_anchored_set(set, position)? else {
            continue;
        };
        if candidate.ranges().is_empty()
            || (candidate.scan_offset == primary.scan_offset
                && candidate.ranges() == primary.ranges())
        {
            continue;
        }
        let slot = candidates
            .get_mut(candidate_count)
            .ok_or(ObjectError::InvalidModule("too many vector-filter columns"))?;
        *slot = candidate;
        candidate_count = candidate_count
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native vector-filter columns",
            ))?;
    }
    candidates[..candidate_count].sort_unstable_by_key(|candidate| {
        (
            filter_selection_key(*candidate),
            vector_filter_instruction_units(*candidate),
        )
    });

    let mut columns = [EMPTY_NATIVE_START_FILTER; MAX_VECTOR_FILTER_COLUMNS];
    columns[0] = primary;
    let mut column_count = 1_usize;
    let mut constants = primary.constant_count();
    let mut instruction_units = vector_filter_instruction_units(primary);
    let mut probability_numerator = u64::from(estimated_filter_frequency_units(primary));
    let mut probability_denominator = u64::from(BYTE_FREQUENCY_DENOMINATOR);
    let sparse_primary = probability_numerator
        .checked_mul(VECTOR_FILTER_COST_BLOCK_BYTES)
        .ok_or(ObjectError::ArithmeticOverflow(
            "native vector-filter probability",
        ))?
        <= probability_denominator;
    for candidate in candidates[..candidate_count].iter().copied() {
        if column_count == MAX_VECTOR_FILTER_COLUMNS {
            break;
        }
        if !sparse_primary
            && probability_numerator
                .checked_mul(VECTOR_FILTER_COST_BLOCK_BYTES)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "native vector-filter probability",
                ))?
                <= probability_denominator
        {
            break;
        }
        let Some(next_constants) = constants.checked_add(candidate.constant_count()) else {
            continue;
        };
        if next_constants > MAX_VECTOR_FILTER_CONSTANTS {
            continue;
        }
        let candidate_instruction_units = vector_filter_instruction_units(candidate);
        let Some(next_instruction_units) =
            instruction_units.checked_add(candidate_instruction_units)
        else {
            continue;
        };
        if next_instruction_units > MAX_VECTOR_FILTER_INSTRUCTION_UNITS {
            continue;
        }
        let candidate_units = u64::from(estimated_filter_frequency_units(candidate));
        let lazy_instruction_units = u64::from(candidate_instruction_units).saturating_add(2);
        // One avoided scalar candidate entails loads, branches and often a
        // prefix/DFA refinement. Three simple vector operations approximate
        // that unit while still charging range masks more than singleton
        // equality masks.
        let lazy_cost_quanta = lazy_instruction_units.saturating_add(2) / 3;
        if sparse_primary
            && (candidate_units > u64::from(MAX_LAZY_SECONDARY_FREQUENCY_UNITS)
                || candidate_units.saturating_mul(lazy_instruction_units)
                    > MAX_LAZY_SECONDARY_COST_UNITS)
        {
            continue;
        }
        let rejected_units = u64::from(BYTE_FREQUENCY_DENOMINATOR)
            .checked_sub(candidate_units)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native vector-filter selectivity",
            ))?;
        let avoided_candidates = VECTOR_FILTER_COST_BLOCK_BYTES
            .checked_mul(probability_numerator)
            .and_then(|value| value.checked_mul(rejected_units))
            .ok_or(ObjectError::ArithmeticOverflow(
                "native vector-filter benefit",
            ))?;
        let next_denominator = probability_denominator
            .checked_mul(u64::from(BYTE_FREQUENCY_DENOMINATOR))
            .ok_or(ObjectError::ArithmeticOverflow(
                "native vector-filter probability",
            ))?;
        if !sparse_primary
            && avoided_candidates
                < next_denominator.checked_mul(lazy_cost_quanta).ok_or(
                    ObjectError::ArithmeticOverflow("native vector-filter instruction cost"),
                )?
        {
            continue;
        }
        columns[column_count] = candidate;
        column_count = column_count
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native vector-filter columns",
            ))?;
        constants = next_constants;
        instruction_units = next_instruction_units;
        probability_numerator = probability_numerator.checked_mul(candidate_units).ok_or(
            ObjectError::ArithmeticOverflow("native vector-filter probability"),
        )?;
        probability_denominator = next_denominator;
    }
    if column_count == 1 {
        return Ok(None);
    }
    Ok(Some(NativeVectorFilter {
        columns,
        column_count: u8::try_from(column_count)
            .map_err(|_| ObjectError::ArithmeticOverflow("native vector-filter columns"))?,
    }))
}

/// Prove that the Cartesian product of the graph-derived anchored byte sets
/// is exactly the fixed-width language accepted from DFA state zero.
///
/// The anchored sets alone are necessary conditions and may lose correlations
/// at graph joins. Propagating every admitted byte through every reachable DFA
/// state restores that information: every intermediate transition must remain
/// live and non-accepting, and every final transition must be live and
/// accepting. Allocation failure or malformed state relations simply decline
/// this optional fast path.
fn derive_exact_prefix_product_width(view: NativeProgramView<'_>) -> Option<u8> {
    let width = view.exact_match_width?;
    let sets = view.anchored_prefix.sets();
    if width == 0
        || width != sets.len()
        || width > MAX_ANCHORED_PREFIX_BYTES
        || view.dfa.initial_pending
        || view.dfa.initial_state != 0
        || view.dfa.class_count == 0
        || !view
            .dfa
            .forward_cells
            .len()
            .is_multiple_of(view.dfa.class_count)
    {
        return None;
    }
    let states = view
        .dfa
        .forward_cells
        .len()
        .checked_div(view.dfa.class_count)?;
    if states == 0 {
        return None;
    }

    let mut current = Vec::new();
    current.try_reserve_exact(states).ok()?;
    current.push(0_u32);
    let mut next = Vec::new();
    next.try_reserve_exact(states).ok()?;
    let mut seen = Vec::new();
    seen.try_reserve_exact(states).ok()?;
    seen.resize(states, false);

    for (depth, set) in sets.iter().copied().enumerate() {
        if set.cardinality() == 0 {
            return None;
        }
        let final_depth = depth.checked_add(1)? == width;
        next.clear();
        seen.fill(false);
        let words = set.words();
        for &state in &current {
            let state = usize::try_from(state).ok()?;
            let row = state.checked_mul(view.dfa.class_count)?;
            for byte in u8::MIN..=u8::MAX {
                let byte_index = usize::from(byte);
                if words[byte_index / 64] & (1_u64 << (byte_index % 64)) == 0 {
                    continue;
                }
                let class = usize::from(*view.dfa.byte_classes.get(byte_index)?);
                let cell = *view.dfa.forward_cells.get(row.checked_add(class)?)?;
                if final_depth {
                    if !cell.accepted {
                        return None;
                    }
                    // A terminal accepted transition may use the dead-state
                    // sentinel because no successor is semantically visited.
                    // Any concrete successor must nevertheless be valid.
                    if cell.next != NO_DFA_STATE {
                        let target = usize::try_from(cell.next).ok()?;
                        seen.get(target)?;
                    }
                } else {
                    if cell.accepted || cell.next == NO_DFA_STATE {
                        return None;
                    }
                    let target = usize::try_from(cell.next).ok()?;
                    let target_seen = seen.get_mut(target)?;
                    if !*target_seen {
                        *target_seen = true;
                        next.push(cell.next);
                    }
                }
            }
        }
        if final_depth {
            return u8::try_from(width).ok();
        }
        if next.is_empty() {
            return None;
        }
        core::mem::swap(&mut current, &mut next);
    }
    None
}

fn derive_anchored_prefix_start_filter(
    sets: &[AnchoredByteSet],
) -> Result<Option<NativeStartFilter>, ObjectError> {
    let mut selected = None;
    for (position, set) in sets.iter().copied().enumerate() {
        let Some(candidate) = start_filter_from_anchored_set(set, position)? else {
            continue;
        };
        let candidate_score = filter_selection_key(candidate);
        let replace = selected.is_none_or(|current: NativeStartFilter| {
            candidate_score < filter_selection_key(current)
        });
        if replace {
            selected = Some(candidate);
        }
    }
    Ok(selected)
}

fn start_filter_from_anchored_set(
    set: AnchoredByteSet,
    position: usize,
) -> Result<Option<NativeStartFilter>, ObjectError> {
    let candidate_bytes = set.cardinality();
    if candidate_bytes == 0 {
        return Ok(None);
    }
    let words = set.words();
    filter_from_membership_words(words, position, true)
}

fn filter_from_membership_words(
    words: [u64; 4],
    position: usize,
    from_anchored_prefix: bool,
) -> Result<Option<NativeStartFilter>, ObjectError> {
    let candidate_bytes = words
        .iter()
        .map(|word| u16::try_from(word.count_ones()).unwrap_or(u16::MAX))
        .sum();
    if candidate_bytes > MAX_START_FILTER_CANDIDATE_BYTES {
        return Ok(None);
    }
    let empty_range = NativeByteRange { start: 0, end: 0 };
    let mut ranges = [empty_range; MAX_START_FILTER_RANGES];
    let mut range_count = 0_usize;
    for byte in u8::MIN..=u8::MAX {
        let index = usize::from(byte);
        if words[index / 64] & (1_u64 << (index % 64)) == 0 {
            continue;
        }
        if let Some(last) = range_count
            .checked_sub(1)
            .and_then(|index| ranges.get_mut(index))
            && last.end.checked_add(1) == Some(byte)
        {
            last.end = byte;
            continue;
        }
        if range_count == MAX_START_FILTER_RANGES {
            return Ok(None);
        }
        ranges[range_count] = NativeByteRange {
            start: byte,
            end: byte,
        };
        range_count = range_count
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native membership-filter ranges",
            ))?;
    }
    let exact = ranges[..range_count]
        .iter()
        .all(|range| range.start == range.end);
    if range_count > MAX_NON_EXACT_START_FILTER_RANGES
        && (!ENABLE_FRAGMENTED_EXACT_START_FILTER || !exact)
    {
        return Ok(None);
    }
    Ok(Some(NativeStartFilter {
        ranges,
        range_count: u8::try_from(range_count)
            .map_err(|_| ObjectError::ArithmeticOverflow("native membership-filter ranges"))?,
        candidate_bytes,
        scan_offset: u8::try_from(position)
            .map_err(|_| ObjectError::ArithmeticOverflow("native start-filter offset"))?,
        from_anchored_prefix,
    }))
}

fn reset_filter_from_membership_words(
    words: [u64; 4],
) -> Result<Option<NativeResetFilter>, ObjectError> {
    let candidate_bytes = words
        .iter()
        .map(|word| u16::try_from(word.count_ones()).unwrap_or(u16::MAX))
        .sum();
    if candidate_bytes > MAX_START_FILTER_CANDIDATE_BYTES {
        return Ok(None);
    }
    let mut filter = EMPTY_NATIVE_RESET_FILTER;
    let mut range_count = 0_usize;
    for byte in u8::MIN..=u8::MAX {
        let index = usize::from(byte);
        if words[index / 64] & (1_u64 << (index % 64)) == 0 {
            continue;
        }
        if let Some(last) = range_count
            .checked_sub(1)
            .and_then(|index| filter.ranges.get_mut(index))
            && last.end.checked_add(1) == Some(byte)
        {
            last.end = byte;
            continue;
        }
        if range_count == MAX_SUFFIX_RESET_NON_RESET_RANGES {
            return Ok(None);
        }
        filter.ranges[range_count] = NativeByteRange {
            start: byte,
            end: byte,
        };
        range_count = range_count
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native reset-complement ranges",
            ))?;
    }
    filter.range_count = u8::try_from(range_count)
        .map_err(|_| ObjectError::ArithmeticOverflow("native reset-complement ranges"))?;
    filter.candidate_bytes = candidate_bytes;
    Ok(Some(filter))
}

/// Return the exact byte set whose transition from the initial DFA state can
/// affect matching. Bytes outside this set are proven non-accepting self
/// loops and may be skipped by a moving scanner.
fn initial_start_membership_words(
    view: NativeProgramView<'_>,
) -> Result<Option<[u64; 4]>, ObjectError> {
    let dfa = view.dfa;
    if dfa.initial_pending {
        return Ok(None);
    }
    let initial_row = dfa
        .forward_cells
        .get(..dfa.class_count)
        .ok_or(ObjectError::InvalidModule("native DFA has no initial row"))?;
    let mut words = [0_u64; 4];
    for byte in u8::MIN..=u8::MAX {
        let byte_index = usize::from(byte);
        let class = usize::from(dfa.byte_classes[byte_index]);
        let cell = initial_row
            .get(class)
            .ok_or(ObjectError::InvalidModule("native DFA initial class"))?;
        if !cell.accepted && cell.next == dfa.initial_state {
            continue;
        }
        words[byte_index / 64] |= 1_u64 << (byte_index % 64);
    }
    Ok(Some(words))
}

fn derive_initial_start_filter(
    view: NativeProgramView<'_>,
) -> Result<Option<NativeStartFilter>, ObjectError> {
    let Some(words) = initial_start_membership_words(view)? else {
        return Ok(None);
    };
    filter_from_membership_words(words, 0, false)
}

/// Approximate a fragmented initial-state departure set by at most four
/// inclusive ranges. Merging fills gaps, so this can create only false scanner
/// candidates: the exact DFA transition and retained prefix predicates still
/// decide semantics. Gaps are merged greedily by stable estimated byte
/// frequency, then width, then left position; no source identity or runtime
/// sample enters the decision.
fn derive_coalesced_initial_start_filter(
    view: NativeProgramView<'_>,
) -> Result<Option<NativeStartFilter>, ObjectError> {
    let Some(words) = initial_start_membership_words(view)? else {
        return Ok(None);
    };
    coalesced_initial_filter_from_membership_words(words)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "loop bounds and fixed range capacity prove the adjacent indices and decrement"
)]
fn coalesced_initial_filter_from_membership_words(
    words: [u64; 4],
) -> Result<Option<NativeStartFilter>, ObjectError> {
    coalesced_filter_from_membership_words(words, 0, false)
}

/// Cover a graph-required byte set by at most four inclusive scanner ranges.
///
/// The cover may add false candidates but never removes a required byte. The
/// exact DFA transition (or an anchored verifier) remains the semantic
/// authority. This generalized form is shared by the ordinary initial-state
/// fallback and contextual candidate scanners at a nonzero prefix offset.
fn coalesced_filter_from_membership_words(
    words: [u64; 4],
    position: usize,
    from_anchored_prefix: bool,
) -> Result<Option<NativeStartFilter>, ObjectError> {
    let exact_candidate_bytes: u16 = words
        .iter()
        .map(|word| u16::try_from(word.count_ones()).unwrap_or(u16::MAX))
        .sum();
    if exact_candidate_bytes == 0 || exact_candidate_bytes > MAX_START_FILTER_CANDIDATE_BYTES {
        return Ok(None);
    }

    let mut ranges = [EMPTY_NATIVE_BYTE_RANGE; MAX_EXACT_BYTE_MEMBERSHIP_RANGES];
    let mut range_count = 0_usize;
    for byte in u8::MIN..=u8::MAX {
        let byte_index = usize::from(byte);
        if words[byte_index / 64] & (1_u64 << (byte_index % 64)) == 0 {
            continue;
        }
        if let Some(last) = range_count
            .checked_sub(1)
            .and_then(|index| ranges.get_mut(index))
            && last.end.checked_add(1) == Some(byte)
        {
            last.end = byte;
            continue;
        }
        let slot = ranges
            .get_mut(range_count)
            .ok_or(ObjectError::InvalidModule(
                "initial membership has too many exact ranges",
            ))?;
        *slot = NativeByteRange {
            start: byte,
            end: byte,
        };
        range_count = range_count
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "coalesced initial-filter range count",
            ))?;
    }

    while range_count > MAX_NON_EXACT_START_FILTER_RANGES {
        let mut selected_gap = None;
        for gap_index in 0..range_count.saturating_sub(1) {
            let left = ranges[gap_index];
            let right = ranges[gap_index + 1];
            let gap_start = u16::from(left.end) + 1;
            let gap_end = u16::from(right.start).saturating_sub(1);
            let gap_bytes = gap_end
                .checked_sub(gap_start)
                .and_then(|width| width.checked_add(1))
                .ok_or(ObjectError::InvalidModule(
                    "coalesced initial-filter ranges overlap",
                ))?;
            let mut frequency_units = 0_u16;
            for byte in gap_start..=gap_end {
                frequency_units = frequency_units.saturating_add(estimated_byte_frequency_units(
                    u8::try_from(byte).map_err(|_| {
                        ObjectError::ArithmeticOverflow("coalesced initial-filter gap byte")
                    })?,
                ));
            }
            let key = (frequency_units, gap_bytes, gap_index);
            if selected_gap.is_none_or(|(_, current_key)| key < current_key) {
                selected_gap = Some((gap_index, key));
            }
        }
        let (gap_index, _) = selected_gap.ok_or(ObjectError::InvalidModule(
            "coalesced initial filter has no mergeable gap",
        ))?;
        ranges[gap_index].end = ranges[gap_index + 1].end;
        ranges.copy_within(gap_index + 2..range_count, gap_index + 1);
        range_count -= 1;
    }

    let candidate_bytes = ranges[..range_count].iter().try_fold(0_u16, |sum, range| {
        let width = u16::from(range.end)
            .checked_sub(u16::from(range.start))
            .and_then(|width| width.checked_add(1))
            .ok_or(ObjectError::InvalidModule(
                "coalesced initial-filter range is reversed",
            ))?;
        sum.checked_add(width)
            .ok_or(ObjectError::ArithmeticOverflow(
                "coalesced initial-filter candidate bytes",
            ))
    })?;
    if candidate_bytes > MAX_START_FILTER_CANDIDATE_BYTES {
        return Ok(None);
    }
    let mut compact_ranges = [EMPTY_NATIVE_BYTE_RANGE; MAX_START_FILTER_RANGES];
    compact_ranges[..range_count].copy_from_slice(&ranges[..range_count]);
    Ok(Some(NativeStartFilter {
        ranges: compact_ranges,
        range_count: u8::try_from(range_count)
            .map_err(|_| ObjectError::ArithmeticOverflow("coalesced initial-filter ranges"))?,
        candidate_bytes,
        scan_offset: u8::try_from(position)
            .map_err(|_| ObjectError::ArithmeticOverflow("coalesced filter offset"))?,
        from_anchored_prefix,
    }))
}

fn encode_native_next(
    next: u32,
    machine_offset: usize,
    row_bytes: usize,
    states: usize,
) -> Result<usize, ObjectError> {
    if next == NO_DFA_STATE {
        Ok(0)
    } else {
        let next = usize::try_from(next)
            .map_err(|_| ObjectError::ArithmeticOverflow("native DFA next state"))?;
        if next >= states {
            return Err(ObjectError::InvalidModule(
                "native DFA next state is outside its table",
            ));
        }
        let row_offset = next
            .checked_mul(row_bytes)
            .and_then(|offset| machine_offset.checked_add(offset))
            .ok_or(ObjectError::ArithmeticOverflow(
                "native DFA next row offset",
            ))?;
        let encoded = row_offset
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "native DFA encoded next row",
            ))?;
        Ok(encoded)
    }
}

fn pack_native_cell(
    next: u32,
    flag: bool,
    machine_offset: usize,
    row_bytes: usize,
    states: usize,
) -> Result<u32, ObjectError> {
    pack_native_cell_with_acceleration(next, flag, machine_offset, row_bytes, states, false)
}

fn pack_native_forward_cell(
    next: u32,
    flag: bool,
    machine_offset: usize,
    row_bytes: usize,
    states: usize,
    initial_scannable: bool,
    loop_state: Option<u32>,
) -> Result<u32, ObjectError> {
    let accelerated =
        next != NO_DFA_STATE && ((initial_scannable && next == 0) || loop_state == Some(next));
    pack_native_cell_with_acceleration(next, flag, machine_offset, row_bytes, states, accelerated)
}

fn pack_native_cell_with_acceleration(
    next: u32,
    flag: bool,
    machine_offset: usize,
    row_bytes: usize,
    states: usize,
    accelerated: bool,
) -> Result<u32, ObjectError> {
    let encoded_next = u32::try_from(encode_native_next(next, machine_offset, row_bytes, states)?)
        .map_err(|_| ObjectError::ArithmeticOverflow("native DFA encoded next row"))?;
    if encoded_next > CELL_NEXT_MASK {
        return Err(ObjectError::InvalidModule(
            "native DFA state exceeds packed cell",
        ));
    }
    if accelerated && encoded_next == 0 {
        return Err(ObjectError::InvalidModule(
            "dead native DFA cell cannot enter accelerator dispatch",
        ));
    }
    Ok(encoded_next
        | if accelerated { CELL_ACCELERATED } else { 0 }
        | if flag { CELL_ACCEPTS } else { 0 })
}

type X86Label = usize;

#[derive(Clone, Copy, Debug)]
struct X86Fixup {
    displacement: usize,
    label: X86Label,
}

struct X86Assembler {
    code: Vec<u8>,
    labels: Vec<Option<usize>>,
    fixups: Vec<X86Fixup>,
    instruction_offsets: Vec<usize>,
}

impl X86Assembler {
    fn new() -> Self {
        Self {
            code: Vec::with_capacity(256),
            labels: Vec::new(),
            fixups: Vec::new(),
            instruction_offsets: Vec::new(),
        }
    }

    fn label(&mut self) -> Result<X86Label, ObjectError> {
        let label = self.labels.len();
        self.labels
            .try_reserve(1)
            .map_err(|_| ObjectError::InvalidModule("x86 label allocation failed"))?;
        self.labels.push(None);
        Ok(label)
    }

    fn bind(&mut self, label: X86Label) -> Result<(), ObjectError> {
        let slot = self
            .labels
            .get_mut(label)
            .ok_or(ObjectError::InvalidModule("x86 label index"))?;
        if slot.is_some() {
            return Err(ObjectError::InvalidModule("x86 label bound twice"));
        }
        *slot = Some(self.code.len());
        Ok(())
    }

    fn instruction(&mut self, bytes: &[u8]) -> Result<usize, ObjectError> {
        let offset = self.code.len();
        self.instruction_offsets
            .try_reserve(1)
            .map_err(|_| ObjectError::InvalidModule("x86 audit allocation failed"))?;
        self.instruction_offsets.push(offset);
        push_bytes(&mut self.code, bytes)?;
        Ok(offset)
    }

    fn branch(&mut self, opcode: &[u8], label: X86Label) -> Result<(), ObjectError> {
        // Once a target is bound, use the compact rel8 form whenever the
        // displacement fits. All such edges are backward, so their size
        // cannot move the target or invalidate an earlier fixup. Forward
        // edges retain the fixed-width rel32 representation and are resolved
        // transactionally by `finish`.
        let short_opcode = match opcode {
            [0xe9] => Some(0xeb),
            [0x0f, condition @ 0x80..=0x8f] => condition.checked_sub(0x10),
            _ => None,
        };
        if let (Some(short_opcode), Some(target)) =
            (short_opcode, self.labels.get(label).copied().flatten())
            && (target == self.code.len()
                || self.instruction_offsets.binary_search(&target).is_ok())
        {
            let after = self
                .code
                .len()
                .checked_add(2)
                .ok_or(ObjectError::ArithmeticOverflow("x86 short branch base"))?;
            let target = i64::try_from(target)
                .map_err(|_| ObjectError::ArithmeticOverflow("x86 short branch target"))?;
            let after = i64::try_from(after)
                .map_err(|_| ObjectError::ArithmeticOverflow("x86 short branch base"))?;
            let delta = target
                .checked_sub(after)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "x86 short branch displacement",
                ))?;
            if let Ok(delta) = i8::try_from(delta) {
                self.instruction(&[short_opcode, delta.to_le_bytes()[0]])?;
                return Ok(());
            }
        }
        self.instruction(opcode)?;
        let displacement = self.code.len();
        push_bytes(&mut self.code, &[0; 4])?;
        self.fixups
            .try_reserve(1)
            .map_err(|_| ObjectError::InvalidModule("x86 fixup allocation failed"))?;
        self.fixups.push(X86Fixup {
            displacement,
            label,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, ObjectError> {
        self.instruction_offsets.push(self.code.len());
        for fixup in &self.fixups {
            let target = self
                .labels
                .get(fixup.label)
                .copied()
                .flatten()
                .ok_or(ObjectError::InvalidModule("unbound x86 branch label"))?;
            if self.instruction_offsets.binary_search(&target).is_err() {
                return Err(ObjectError::InvalidModule(
                    "x86 branch target is not an instruction boundary",
                ));
            }
            let after = fixup
                .displacement
                .checked_add(4)
                .ok_or(ObjectError::ArithmeticOverflow("x86 branch base"))?;
            let target = i64::try_from(target)
                .map_err(|_| ObjectError::ArithmeticOverflow("x86 branch target"))?;
            let after = i64::try_from(after)
                .map_err(|_| ObjectError::ArithmeticOverflow("x86 branch base"))?;
            let delta = target
                .checked_sub(after)
                .ok_or(ObjectError::ArithmeticOverflow("x86 branch displacement"))?;
            let delta = i32::try_from(delta)
                .map_err(|_| ObjectError::InvalidModule("x86 branch is out of range"))?;
            let end = fixup
                .displacement
                .checked_add(4)
                .ok_or(ObjectError::ArithmeticOverflow("x86 fixup extent"))?;
            self.code
                .get_mut(fixup.displacement..end)
                .ok_or(ObjectError::InvalidModule("x86 fixup outside code"))?
                .copy_from_slice(&delta.to_le_bytes());
        }
        Ok(self.code)
    }
}

/// Emit Intel-recommended NOP encodings into unreachable post-return space.
/// Nine-byte chunks keep the instruction audit explicit without bloating the
/// compiler, and the exact remainder covers every power-of-two alignment.
fn x86_emit_unreachable_nops(
    assembler: &mut X86Assembler,
    mut bytes: usize,
) -> Result<(), ObjectError> {
    const NOP9: &[u8] = &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
    while bytes >= NOP9.len() {
        assembler.instruction(NOP9)?;
        bytes = bytes
            .checked_sub(NOP9.len())
            .ok_or(ObjectError::ArithmeticOverflow("x86 cold padding"))?;
    }
    let tail = match bytes {
        0 => &[][..],
        1 => &[0x90][..],
        2 => &[0x66, 0x90][..],
        3 => &[0x0f, 0x1f, 0x00][..],
        4 => &[0x0f, 0x1f, 0x40, 0x00][..],
        5 => &[0x0f, 0x1f, 0x44, 0x00, 0x00][..],
        6 => &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00][..],
        7 => &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00][..],
        8 => &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00][..],
        _ => return Err(ObjectError::InvalidModule("x86 cold padding remainder")),
    };
    if !tail.is_empty() {
        assembler.instruction(tail)?;
    }
    Ok(())
}

fn x86_emit_table_lookup(
    assembler: &mut X86Assembler,
    transitions: TransitionLayout,
) -> Result<(), ObjectError> {
    // eax = haystack[position]
    assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?;
    match transitions {
        TransitionLayout::ClassMapped => {
            assembler.instruction(&[0x41, 0x0f, 0xb6, 0x04, 0x01])?; // eax = class_map[eax]
            assembler.instruction(&[0x41, 0x8b, 0x04, 0x82])?; // eax = packed_row[class]
        }
        TransitionLayout::DirectByte => {
            assembler.instruction(&[0x41, 0x8b, 0x04, 0x82])?; // eax = packed_row[byte]
        }
    }
    Ok(())
}

/// Classify the packed cell and materialize its next row on the ordinary-live
/// path. `packed - 1 <= CELL_NEXT_MASK - 1` exactly describes an unflagged,
/// non-dead cell, so the common path needs only one conditional branch. EAX
/// holds the decoded absolute row offset after the subtraction.
fn x86_emit_ordinary_live_row(
    assembler: &mut X86Assembler,
    exceptional: X86Label,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0xff, 0xc8])?; // dec eax (remove the live-token bias)
    let mut compare = vec![0x3d]; // cmp eax, maximum ordinary decoded row
    compare.extend_from_slice(&CELL_ORDINARY_DECODED_MAX.to_le_bytes());
    assembler.instruction(&compare)?;
    assembler.branch(&[0x0f, 0x87], exceptional)?; // ja
    assembler.instruction(&[0x4d, 0x8d, 0x14, 0x01])?; // lea (r9, rax), r10
    Ok(())
}

fn x86_set_row(assembler: &mut X86Assembler, table_offset: u32) -> Result<(), ObjectError> {
    let mut instruction = vec![0x4d, 0x8d, 0x91];
    instruction.extend_from_slice(&table_offset.to_le_bytes());
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_emit_exact_span_start(assembler: &mut X86Assembler, width: u64) -> Result<(), ObjectError> {
    assembler.instruction(&[0x4c, 0x89, 0xd8])?; // start = selected end
    if let Ok(width) = u8::try_from(width)
        && width <= 0x7f
    {
        assembler.instruction(&[0x48, 0x83, 0xe8, width])?; // sub rax, imm8
    } else if let Ok(width) = i32::try_from(width) {
        let mut instruction = vec![0x48, 0x2d]; // sub rax, imm32
        instruction.extend_from_slice(&width.to_le_bytes());
        assembler.instruction(&instruction)?;
    } else {
        let mut load = vec![0x49, 0xba]; // movabs r10, width
        load.extend_from_slice(&width.to_le_bytes());
        assembler.instruction(&load)?;
        assembler.instruction(&[0x4c, 0x29, 0xd0])?; // sub rax, r10
    }
    Ok(())
}

fn x86_emit_exact_prefix_match(
    assembler: &mut X86Assembler,
    width: u8,
    output: OutputContract,
    matched: X86Label,
) -> Result<(), ObjectError> {
    if width == 0 || usize::from(width) > MAX_ANCHORED_PREFIX_BYTES {
        return Err(ObjectError::InvalidModule(
            "invalid x86 exact-prefix match width",
        ));
    }
    if output != OutputContract::Exists {
        assembler.instruction(&[0x48, 0x8d, 0x42, width])?; // end = candidate + width
        if output == OutputContract::Span {
            assembler.instruction(&[0x49, 0x89, 0x10])?; // result.start = candidate
        } else {
            assembler.instruction(&[0x49, 0x89, 0x00])?; // result.start = end
        }
        assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?; // result.end = end
    }
    assembler.branch(&[0xe9], matched)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum X86StartFilterKind {
    /// SSE2 is an architectural baseline capability of x86-64.
    Sse2,
    /// AVX2 is emitted only when explicitly present in [`Target::features`].
    Avx2,
    /// The 64-byte path needs AVX-512F and AVX-512BW, but not AVX-512VL.
    Avx512Bw,
}

/// Location of the exact lane mask produced by one x86 vector filter.
///
/// SSE2 and AVX2 materialize their masks in `eax`. AVX-512BW comparisons
/// produce 64 lane bits directly in an opmask register: exact membership uses
/// `k1`, range membership uses `k4`, and a graph-proven multi-column
/// intersection uses `k5`. Keeping that distinction explicit prevents a
/// 64-lane mask from accidentally taking a 32-bit `pmovmskb`/`bsf` path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum X86CandidateMask {
    MovemaskEax,
    Avx512K1,
    Avx512K4,
    Avx512K5,
    /// Four-vector sparse-filter accumulator. K6 is outside the candidate and
    /// lazy-intersection bank and remains caller-saved on supported targets.
    Avx512K6,
}

impl X86CandidateMask {
    fn for_filter(filter: NativeStartFilter, kind: X86StartFilterKind) -> Self {
        match kind {
            X86StartFilterKind::Sse2 | X86StartFilterKind::Avx2 => Self::MovemaskEax,
            X86StartFilterKind::Avx512Bw if filter.is_exact() => Self::Avx512K1,
            X86StartFilterKind::Avx512Bw => Self::Avx512K4,
        }
    }

    const fn for_intersection(kind: X86StartFilterKind) -> Self {
        match kind {
            X86StartFilterKind::Sse2 | X86StartFilterKind::Avx2 => Self::MovemaskEax,
            X86StartFilterKind::Avx512Bw => Self::Avx512K5,
        }
    }

    const fn opmask_register(self) -> Option<u8> {
        match self {
            Self::MovemaskEax => None,
            Self::Avx512K1 => Some(1),
            Self::Avx512K4 => Some(4),
            Self::Avx512K5 => Some(5),
            Self::Avx512K6 => Some(6),
        }
    }
}

fn x86_emit_candidate_nonzero(
    assembler: &mut X86Assembler,
    mask: X86CandidateMask,
) -> Result<(), ObjectError> {
    if let Some(register) = mask.opmask_register() {
        // KORTESTQ kN, kN. The opmask is deliberately retained for the rare
        // taken branch, where KMOVQ+BSFQ selects one of all 64 lanes.
        assembler.instruction(&[0xc4, 0xe1, 0xf8, 0x98, 0xc0 | (register << 3) | register])?;
    } else {
        assembler.instruction(&[0x85, 0xc0])?; // test eax, eax
    }
    Ok(())
}

fn x86_emit_first_candidate_lane(
    assembler: &mut X86Assembler,
    mask: X86CandidateMask,
) -> Result<(), ObjectError> {
    if let Some(register) = mask.opmask_register() {
        // KMOVQ rax, kN followed by BSFQ preserves every AVX-512 lane,
        // including lanes 32..63. The caller has already proved nonzero.
        assembler.instruction(&[0xc4, 0xe1, 0xfb, 0x93, 0xc0 | register])?;
        assembler.instruction(&[0x48, 0x0f, 0xbc, 0xc0])?;
    } else {
        assembler.instruction(&[0x0f, 0xbc, 0xc0])?; // bsf eax, eax
    }
    Ok(())
}

fn x86_emit_retain_candidate_mask(
    assembler: &mut X86Assembler,
    mask: X86CandidateMask,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x49, 0x89, 0xd4])?; // r12 = vector block base
    if let Some(register) = mask.opmask_register() {
        // Preserve all 64 AVX-512 lanes before any scalar guard can clobber
        // RAX or the temporary opmask bank.
        assembler.instruction(&[0xc4, 0xe1, 0xfb, 0x93, 0xc0 | register])?; // rax = kN
        assembler.instruction(&[0x49, 0x89, 0xc5])?; // r13 = rax
    } else {
        assembler.instruction(&[0x41, 0x89, 0xc5])?; // r13d = eax
    }
    Ok(())
}

fn x86_emit_first_retained_candidate(assembler: &mut X86Assembler) -> Result<(), ObjectError> {
    assembler.instruction(&[0x49, 0x0f, 0xbc, 0xc5])?; // bsf rax, r13
    assembler.instruction(&[0x49, 0x8d, 0x14, 0x04])?; // position = r12 + rax
    Ok(())
}

fn x86_emit_clear_first_retained_candidate(
    assembler: &mut X86Assembler,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x49, 0x8d, 0x45, 0xff])?; // rax = r13 - 1
    assembler.instruction(&[0x49, 0x21, 0xc5])?; // r13 &= rax
    assembler.instruction(&[0x4d, 0x85, 0xed])?; // test r13, r13
    Ok(())
}

fn x86_emit_advance_retained_block(
    assembler: &mut X86Assembler,
    width: u8,
) -> Result<(), ObjectError> {
    if !matches!(width, 16 | 32 | 64) {
        return Err(ObjectError::InvalidModule("x86 retained-mask vector width"));
    }
    assembler.instruction(&[0x49, 0x8d, 0x54, 0x24, width])?; // position = base + width
    Ok(())
}

fn x86_emit_avx512_copy_mask_to_k5(
    assembler: &mut X86Assembler,
    source: X86CandidateMask,
) -> Result<(), ObjectError> {
    let register = source.opmask_register().ok_or(ObjectError::InvalidModule(
        "AVX-512 intersection primary is not an opmask",
    ))?;
    if !matches!(register, 1 | 4) {
        return Err(ObjectError::InvalidModule(
            "AVX-512 intersection primary opmask register",
        ));
    }
    // KORQ k5, kN, kN. VEX.vvvv selects the first source and ModRM.r/m the
    // second; both are the source mask, so this is an exact copy.
    let vex = 0xfc_u8 & !(register << 3);
    assembler.instruction(&[0xc4, 0xe1, vex, 0x45, 0xe8 | register])?;
    Ok(())
}

fn x86_emit_avx512_intersect_k5(
    assembler: &mut X86Assembler,
    source: X86CandidateMask,
) -> Result<(), ObjectError> {
    let register = source.opmask_register().ok_or(ObjectError::InvalidModule(
        "AVX-512 intersection secondary is not an opmask",
    ))?;
    if !matches!(register, 1 | 4) {
        return Err(ObjectError::InvalidModule(
            "AVX-512 intersection secondary opmask register",
        ));
    }
    // KANDQ k5, k5, kN.
    assembler.instruction(&[0xc4, 0xe1, 0xd4, 0x41, 0xe8 | register])?;
    Ok(())
}

fn x86_start_filter_kind(features: FeatureSet) -> X86StartFilterKind {
    if features.has(CpuFeature::X86Avx512F) && features.has(CpuFeature::X86Avx512Bw) {
        X86StartFilterKind::Avx512Bw
    } else if features.has(CpuFeature::X86Avx2) {
        X86StartFilterKind::Avx2
    } else {
        X86StartFilterKind::Sse2
    }
}

impl X86StartFilterKind {
    const fn width(self) -> u8 {
        match self {
            Self::Sse2 => 16,
            Self::Avx2 => 32,
            Self::Avx512Bw => 64,
        }
    }

    const fn needs_vzeroupper(self) -> bool {
        !matches!(self, Self::Sse2)
    }
}

fn x86_use_sparse_filter_mask_batch(filter: NativeStartFilter, kind: X86StartFilterKind) -> bool {
    filter_fits_expected_hit_budget(
        filter,
        u16::from(kind.width()).saturating_mul(X86_MASK_BATCH_VECTORS),
        MAX_SPARSE_RESCAN_EXPECTED_HITS,
    )
}

fn x86_filter_constant_register(
    first_register: u8,
    logical_index: usize,
) -> Result<u8, ObjectError> {
    let logical_index = u8::try_from(logical_index)
        .map_err(|_| ObjectError::ArithmeticOverflow("x86 filter constant register"))?;
    let register =
        first_register
            .checked_add(logical_index)
            .ok_or(ObjectError::ArithmeticOverflow(
                "x86 filter constant register",
            ))?;
    if register == 0 || register > 8 {
        return Err(ObjectError::InvalidModule("x86 filter constant register"));
    }
    Ok(register)
}

fn x86_emit_start_filter_constants(
    assembler: &mut X86Assembler,
    filter: NativeStartFilter,
    kind: X86StartFilterKind,
    first_register: u8,
) -> Result<(), ObjectError> {
    for (index, range) in filter.ranges().iter().enumerate() {
        if filter.is_exact() {
            let register = x86_filter_constant_register(first_register, index)?;
            x86_emit_splat_byte(assembler, register, range.start, kind)?;
        } else {
            let logical_low = index.checked_mul(2).ok_or(ObjectError::ArithmeticOverflow(
                "x86 range-filter low register",
            ))?;
            let low_register = x86_filter_constant_register(first_register, logical_low)?;
            let high_register = x86_filter_constant_register(
                first_register,
                logical_low
                    .checked_add(1)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "x86 range-filter high register",
                    ))?,
            )?;
            x86_emit_splat_byte(assembler, low_register, range.start, kind)?;
            x86_emit_splat_byte(assembler, high_register, range.end, kind)?;
        }
    }
    Ok(())
}

fn x86_emit_prefix_relation_constants(
    assembler: &mut X86Assembler,
    plan: NativePrefixRelationVectorPlan,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    if plan.constant_count > MAX_X86_PREFIX_RELATION_CONSTANTS {
        return Err(ObjectError::InvalidModule(
            "x86 prefix-relation constant budget",
        ));
    }
    for rectangle in plan.rectangles() {
        for predicate in [rectangle.first, rectangle.second] {
            if !predicate.any {
                x86_emit_start_filter_constants(
                    assembler,
                    predicate.filter,
                    kind,
                    predicate.first_constant,
                )?;
            }
        }
    }
    Ok(())
}

fn x86_emit_sse2_binary(
    assembler: &mut X86Assembler,
    opcode: u8,
    destination: u8,
    source: u8,
) -> Result<(), ObjectError> {
    if destination > 15 || source > 15 {
        return Err(ObjectError::InvalidModule(
            "x86 prefix-relation SSE2 register",
        ));
    }
    let rex = 0x40 | u8::from(destination >= 8) << 2 | u8::from(source >= 8);
    let mut instruction = vec![0x66];
    if rex != 0x40 {
        instruction.push(rex);
    }
    instruction.extend_from_slice(&[0x0f, opcode, 0xc0 | ((destination & 7) << 3) | (source & 7)]);
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_emit_avx2_binary(
    assembler: &mut X86Assembler,
    opcode: u8,
    destination: u8,
    left: u8,
    right: u8,
) -> Result<(), ObjectError> {
    if [destination, left, right]
        .iter()
        .any(|register| *register > 15)
    {
        return Err(ObjectError::InvalidModule(
            "x86 prefix-relation AVX2 binary register",
        ));
    }
    let mut vex2 = 0xe1_u8;
    if destination >= 8 {
        vex2 &= !0x80;
    }
    if right >= 8 {
        vex2 &= !0x20;
    }
    let vex3 = 0x7d_u8 & !(left << 3);
    assembler.instruction(&[
        0xc4,
        vex2,
        vex3,
        opcode,
        0xc0 | ((destination & 7) << 3) | (right & 7),
    ])?;
    Ok(())
}

fn x86_emit_avx2_move(
    assembler: &mut X86Assembler,
    destination: u8,
    source: u8,
) -> Result<(), ObjectError> {
    if destination > 15 || source > 15 {
        return Err(ObjectError::InvalidModule(
            "x86 prefix-relation AVX2 move register",
        ));
    }
    let mut vex2 = 0xe1_u8;
    if destination >= 8 {
        vex2 &= !0x80;
    }
    if source >= 8 {
        vex2 &= !0x20;
    }
    assembler.instruction(&[
        0xc4,
        vex2,
        0x7d,
        0x6f,
        0xc0 | ((destination & 7) << 3) | (source & 7),
    ])?;
    Ok(())
}

fn x86_emit_k_binary(
    assembler: &mut X86Assembler,
    opcode: u8,
    destination: u8,
    left: u8,
    right: u8,
) -> Result<(), ObjectError> {
    if destination == 0 || left == 0 || right == 0 || destination > 7 || left > 7 || right > 7 {
        return Err(ObjectError::InvalidModule(
            "x86 prefix-relation opmask register",
        ));
    }
    let vex = 0xfc_u8 & !(left << 3);
    assembler.instruction(&[0xc4, 0xe1, vex, opcode, 0xc0 | (destination << 3) | right])?;
    Ok(())
}

fn x86_emit_prefix_relation_predicate(
    assembler: &mut X86Assembler,
    predicate: NativePrefixRelationPredicate,
    kind: X86StartFilterKind,
    destination: u8,
) -> Result<(), ObjectError> {
    match kind {
        X86StartFilterKind::Sse2 => {
            if predicate.any {
                return x86_emit_sse2_binary(assembler, 0x74, destination, destination);
            }
            x86_emit_start_filter_vector_candidates(
                assembler,
                predicate.filter,
                kind,
                predicate.first_constant,
            )?;
            if predicate.negated {
                x86_emit_sse2_binary(assembler, 0x74, 14, 14)?;
                x86_emit_sse2_binary(assembler, 0xef, 12, 14)?;
            }
            x86_emit_sse2_binary(assembler, 0x6f, destination, 12)
        }
        X86StartFilterKind::Avx2 => {
            if predicate.any {
                return x86_emit_avx2_binary(
                    assembler,
                    0x74,
                    destination,
                    destination,
                    destination,
                );
            }
            x86_emit_start_filter_vector_candidates(
                assembler,
                predicate.filter,
                kind,
                predicate.first_constant,
            )?;
            if predicate.negated {
                x86_emit_avx2_binary(assembler, 0x74, 14, 14, 14)?;
                x86_emit_avx2_binary(assembler, 0xef, 12, 12, 14)?;
            }
            x86_emit_avx2_move(assembler, destination, 12)
        }
        X86StartFilterKind::Avx512Bw => {
            if predicate.any {
                return x86_emit_k_binary(assembler, 0x45, destination, 7, 7);
            }
            x86_emit_start_filter_vector_candidates(
                assembler,
                predicate.filter,
                kind,
                predicate.first_constant,
            )?;
            let source = X86CandidateMask::for_filter(predicate.filter, kind)
                .opmask_register()
                .ok_or(ObjectError::InvalidModule(
                    "AVX-512 prefix-relation predicate mask",
                ))?;
            x86_emit_k_binary(
                assembler,
                if predicate.negated { 0x47 } else { 0x45 },
                destination,
                source,
                if predicate.negated { 7 } else { source },
            )
        }
    }
}

/// Emit the exact graph-derived union of byte-set rectangles for one vector.
/// The result stays in EAX for SSE2/AVX2 and K5 for AVX-512BW, so the shared
/// first-lane extraction observes every lane, including AVX-512 lanes 32..63.
fn x86_emit_prefix_relation_vector_test(
    assembler: &mut X86Assembler,
    plan: NativePrefixRelationVectorPlan,
    kind: X86StartFilterKind,
) -> Result<X86CandidateMask, ObjectError> {
    if plan.rectangles().is_empty() {
        return Err(ObjectError::InvalidModule(
            "empty x86 prefix-relation vector plan",
        ));
    }
    if kind == X86StartFilterKind::Avx512Bw {
        x86_emit_k_binary(assembler, 0x46, 7, 7, 7)?; // k7 = all ones
    }
    for (index, rectangle) in plan.rectangles().iter().copied().enumerate() {
        let first_destination = if kind == X86StartFilterKind::Avx512Bw {
            6
        } else {
            13
        };
        x86_emit_prefix_relation_predicate(assembler, rectangle.first, kind, first_destination)?;
        if !rectangle.second.any {
            let second_destination = if kind == X86StartFilterKind::Avx512Bw {
                1
            } else {
                12
            };
            x86_emit_prefix_relation_predicate(
                assembler,
                rectangle.second,
                kind,
                second_destination,
            )?;
            match kind {
                X86StartFilterKind::Sse2 => {
                    x86_emit_sse2_binary(assembler, 0xdb, 13, 12)?;
                }
                X86StartFilterKind::Avx2 => {
                    x86_emit_avx2_binary(assembler, 0xdb, 13, 13, 12)?;
                }
                X86StartFilterKind::Avx512Bw => {
                    x86_emit_k_binary(assembler, 0x41, 6, 6, 1)?;
                }
            }
        }
        match kind {
            X86StartFilterKind::Sse2 => {
                x86_emit_sse2_binary(assembler, if index == 0 { 0x6f } else { 0xeb }, 15, 13)?
            }
            X86StartFilterKind::Avx2 => {
                if index == 0 {
                    x86_emit_avx2_move(assembler, 15, 13)?;
                } else {
                    x86_emit_avx2_binary(assembler, 0xeb, 15, 15, 13)?;
                }
            }
            X86StartFilterKind::Avx512Bw => {
                x86_emit_k_binary(assembler, 0x45, 5, if index == 0 { 6 } else { 5 }, 6)?;
            }
        }
    }
    let mask = match kind {
        X86StartFilterKind::Sse2 => {
            x86_emit_sse2_binary(assembler, 0x6f, 12, 15)?;
            assembler.instruction(&[0x66, 0x41, 0x0f, 0xd7, 0xc4])?;
            X86CandidateMask::MovemaskEax
        }
        X86StartFilterKind::Avx2 => {
            x86_emit_avx2_move(assembler, 12, 15)?;
            assembler.instruction(&[0xc4, 0xc1, 0x7d, 0xd7, 0xc4])?;
            X86CandidateMask::MovemaskEax
        }
        X86StartFilterKind::Avx512Bw => X86CandidateMask::Avx512K5,
    };
    x86_emit_candidate_nonzero(assembler, mask)?;
    Ok(mask)
}

fn x86_emit_splat_byte(
    assembler: &mut X86Assembler,
    register: u8,
    byte: u8,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    if register == 0 || register > 8 {
        return Err(ObjectError::InvalidModule(
            "x86 start-filter constant register",
        ));
    }
    let mut load_immediate = vec![0xb8];
    load_immediate.extend_from_slice(&u32::from(byte).to_le_bytes());
    assembler.instruction(&load_immediate)?;
    let low_register = register & 7;
    let self_modrm = 0xc0 | (low_register << 3) | low_register;
    match (kind, register < 8) {
        (X86StartFilterKind::Sse2, true) => {
            assembler.instruction(&[0x66, 0x0f, 0x6e, 0xc0 | (register << 3)])?;
        }
        (X86StartFilterKind::Sse2, false) => {
            assembler.instruction(&[0x66, 0x44, 0x0f, 0x6e, 0xc0])?;
        }
        // Keep AVX and AVX-512 setup entirely VEX/EVEX encoded. A legacy MOVD
        // after an earlier full-width broadcast can otherwise trigger an
        // AVX-to-SSE transition assist while initializing multi-range filters.
        (X86StartFilterKind::Avx2 | X86StartFilterKind::Avx512Bw, true) => {
            assembler.instruction(&[0xc5, 0xf9, 0x6e, 0xc0 | (register << 3)])?;
        }
        (X86StartFilterKind::Avx2 | X86StartFilterKind::Avx512Bw, false) => {
            assembler.instruction(&[0xc5, 0x79, 0x6e, 0xc0])?;
        }
    }
    match kind {
        X86StartFilterKind::Sse2 if register < 8 => {
            assembler.instruction(&[0x66, 0x0f, 0x60, self_modrm])?;
            assembler.instruction(&[0xf2, 0x0f, 0x70, self_modrm, 0])?;
            assembler.instruction(&[0x66, 0x0f, 0x70, self_modrm, 0])?;
        }
        X86StartFilterKind::Sse2 => {
            assembler.instruction(&[0x66, 0x45, 0x0f, 0x60, self_modrm])?;
            assembler.instruction(&[0xf2, 0x45, 0x0f, 0x70, self_modrm, 0])?;
            assembler.instruction(&[0x66, 0x45, 0x0f, 0x70, self_modrm, 0])?;
        }
        X86StartFilterKind::Avx2 if register < 8 => {
            assembler.instruction(&[0xc4, 0xe2, 0x7d, 0x78, self_modrm])?;
        }
        X86StartFilterKind::Avx2 => {
            assembler.instruction(&[0xc4, 0x42, 0x7d, 0x78, self_modrm])?;
        }
        X86StartFilterKind::Avx512Bw if register < 8 => {
            assembler.instruction(&[0x62, 0xf2, 0x7d, 0x48, 0x78, self_modrm])?;
        }
        X86StartFilterKind::Avx512Bw => {
            assembler.instruction(&[0x62, 0x52, 0x7d, 0x48, 0x78, self_modrm])?;
        }
    }
    Ok(())
}

fn x86_emit_start_filter_vector_load(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
    scan_offset: u8,
) -> Result<(), ObjectError> {
    let mut instruction = match kind {
        X86StartFilterKind::Sse2 => vec![0xf3, 0x0f, 0x6f],
        X86StartFilterKind::Avx2 => vec![0xc5, 0xfe, 0x6f],
        X86StartFilterKind::Avx512Bw => vec![0x62, 0xf1, 0x7f, 0x48, 0x6f],
    };
    if scan_offset == 0 {
        instruction.extend_from_slice(&[0x04, 0x17]);
    } else if kind == X86StartFilterKind::Avx512Bw {
        // EVEX disp8 is compressed and scales by the 64-byte ZMM tuple size.
        // Prefix/suffix byte-column offsets are ordinary byte displacements,
        // so encode them as an unscaled disp32.
        instruction.extend_from_slice(&[0x84, 0x17]);
        instruction.extend_from_slice(&i32::from(scan_offset).to_le_bytes());
    } else {
        instruction.extend_from_slice(&[0x44, 0x17, scan_offset]);
    }
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_emit_start_filter_scalar_load(
    assembler: &mut X86Assembler,
    scan_offset: u8,
) -> Result<(), ObjectError> {
    if scan_offset == 0 {
        assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?;
    } else {
        assembler.instruction(&[0x0f, 0xb6, 0x44, 0x17, scan_offset])?;
    }
    Ok(())
}

fn x86_emit_start_filter_scalar_bound(
    assembler: &mut X86Assembler,
    scan_offset: u8,
    exhausted: X86Label,
) -> Result<(), ObjectError> {
    if scan_offset == 0 {
        assembler.instruction(&[0x48, 0x39, 0xca])?; // candidate >= end
    } else {
        assembler.instruction(&[0x48, 0x8d, 0x42, scan_offset])?;
        assembler.instruction(&[0x48, 0x39, 0xc8])?; // candidate + offset >= end
    }
    assembler.branch(&[0x0f, 0x83], exhausted)?;
    Ok(())
}

fn x86_emit_range_start_filter_vector_candidates(
    assembler: &mut X86Assembler,
    filter: NativeStartFilter,
    kind: X86StartFilterKind,
    first_register: u8,
) -> Result<(), ObjectError> {
    if filter.ranges().is_empty() || filter.is_exact() {
        return Err(ObjectError::InvalidModule(
            "non-range x86 filter reached range vector lowering",
        ));
    }
    x86_emit_start_filter_vector_load(assembler, kind, filter.scan_offset)?;
    if kind == X86StartFilterKind::Avx512Bw {
        assembler.instruction(&[0xc4, 0xe1, 0xdc, 0x47, 0xe4])?; // kxorq k4, k4, k4
    }
    for (index, _) in filter.ranges().iter().enumerate() {
        let logical_low = index.checked_mul(2).ok_or(ObjectError::ArithmeticOverflow(
            "x86 range-filter low register",
        ))?;
        let low = x86_filter_constant_register(first_register, logical_low)?;
        let high = x86_filter_constant_register(
            first_register,
            logical_low
                .checked_add(1)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "x86 range-filter high register",
                ))?,
        )?;
        match kind {
            X86StartFilterKind::Sse2 => {
                assembler.instruction(&[0x66, 0x44, 0x0f, 0x6f, 0xd0])?; // xmm10 = source
                assembler.instruction(&[
                    0x66,
                    if low < 8 { 0x44 } else { 0x45 },
                    0x0f,
                    0xde,
                    0xd0 | (low & 7),
                ])?;
                assembler.instruction(&[0x66, 0x44, 0x0f, 0x74, 0xd0])?;
                assembler.instruction(&[0x66, 0x44, 0x0f, 0x6f, 0xd8])?; // xmm11 = source
                assembler.instruction(&[
                    0x66,
                    if high < 8 { 0x44 } else { 0x45 },
                    0x0f,
                    0xda,
                    0xd8 | (high & 7),
                ])?;
                assembler.instruction(&[0x66, 0x44, 0x0f, 0x74, 0xd8])?;
                assembler.instruction(&[0x66, 0x45, 0x0f, 0xdb, 0xd3])?; // xmm10 &= xmm11
                if index == 0 {
                    assembler.instruction(&[0x66, 0x45, 0x0f, 0x6f, 0xca])?; // xmm9 = xmm10
                } else {
                    assembler.instruction(&[0x66, 0x45, 0x0f, 0xeb, 0xca])?; // xmm9 |= xmm10
                }
            }
            X86StartFilterKind::Avx2 => {
                if low < 8 {
                    assembler.instruction(&[0xc5, 0x7d, 0xde, 0xd0 | low])?;
                } else {
                    assembler.instruction(&[0xc5, 0x3d, 0xde, 0xd0 | (low & 7)])?;
                }
                assembler.instruction(&[0xc5, 0x2d, 0x74, 0xd0])?;
                if high < 8 {
                    assembler.instruction(&[0xc5, 0x7d, 0xda, 0xd8 | high])?;
                } else {
                    assembler.instruction(&[0xc5, 0x3d, 0xda, 0xd8 | (high & 7)])?;
                }
                assembler.instruction(&[0xc5, 0x25, 0x74, 0xd8])?;
                assembler.instruction(&[0xc4, 0x41, 0x2d, 0xdb, 0xd3])?;
                if index == 0 {
                    assembler.instruction(&[0xc4, 0x41, 0x2d, 0xeb, 0xca])?; // ymm9 = ymm10
                } else {
                    assembler.instruction(&[0xc4, 0x41, 0x2d, 0xeb, 0xc9])?; // ymm9 |= ymm10
                }
            }
            X86StartFilterKind::Avx512Bw => {
                let low_evex = if low < 8 { 0xf3 } else { 0xd3 };
                let high_evex = if high < 8 { 0xf3 } else { 0xd3 };
                assembler.instruction(&[0x62, low_evex, 0x7d, 0x48, 0x3e, 0xc8 | (low & 7), 5])?; // vpcmpnltub k1, zmm0, zmm(low)
                assembler.instruction(&[
                    0x62,
                    high_evex,
                    0x7d,
                    0x48,
                    0x3e,
                    0xd0 | (high & 7),
                    2,
                ])?; // vpcmpleub k2, zmm0, zmm(high)
                assembler.instruction(&[0xc4, 0xe1, 0xf4, 0x41, 0xda])?; // k3 = k1 & k2
                assembler.instruction(&[0xc4, 0xe1, 0xdc, 0x45, 0xe3])?; // k4 |= k3
            }
        }
    }
    match kind {
        X86StartFilterKind::Sse2 => {
            assembler.instruction(&[0x66, 0x45, 0x0f, 0x6f, 0xe1])?; // xmm12 = xmm9
        }
        X86StartFilterKind::Avx2 => {
            assembler.instruction(&[0xc4, 0x41, 0x7d, 0x6f, 0xe1])?; // ymm12 = ymm9
        }
        X86StartFilterKind::Avx512Bw => {}
    }
    Ok(())
}

fn x86_emit_exact_start_filter_vector_candidates(
    assembler: &mut X86Assembler,
    filter: NativeStartFilter,
    kind: X86StartFilterKind,
    first_register: u8,
) -> Result<(), ObjectError> {
    if filter.ranges().is_empty() || !filter.is_exact() {
        return Err(ObjectError::InvalidModule(
            "non-exact x86 filter reached exact vector lowering",
        ));
    }
    let ranges = filter.ranges();
    match kind {
        X86StartFilterKind::Sse2 => {
            x86_emit_start_filter_vector_load(assembler, kind, filter.scan_offset)?;
            // XMM1..8 may all be constants for a fragmented exact set. Keep
            // masks in reserved XMM11/XMM12 so processing the fifth byte does
            // not overwrite a still-live constant.
            assembler.instruction(&[0x66, 0x44, 0x0f, 0x6f, 0xe0])?; // xmm12 = source
            assembler.instruction(&[
                0x66,
                if first_register < 8 { 0x44 } else { 0x45 },
                0x0f,
                0x74,
                0xe0 | (first_register & 7),
            ])?;
            for index in 1..ranges.len() {
                let register = x86_filter_constant_register(first_register, index)?;
                assembler.instruction(&[0x66, 0x44, 0x0f, 0x6f, 0xd8])?; // xmm11 = source
                assembler.instruction(&[
                    0x66,
                    if register < 8 { 0x44 } else { 0x45 },
                    0x0f,
                    0x74,
                    0xd8 | (register & 7),
                ])?;
                assembler.instruction(&[0x66, 0x45, 0x0f, 0xeb, 0xe3])?; // xmm12 |= xmm11
            }
        }
        X86StartFilterKind::Avx2 => {
            x86_emit_start_filter_vector_load(assembler, kind, filter.scan_offset)?;
            if first_register < 8 {
                assembler.instruction(&[0xc5, 0x7d, 0x74, 0xe0 | first_register])?;
            } else {
                // Equality is commutative: use YMM8 as VEX.vvvv and keep the
                // ModRM source at YMM0 for the compact high-register form.
                assembler.instruction(&[0xc5, 0x3d, 0x74, 0xe0])?;
            }
            for index in 1..ranges.len() {
                let register = x86_filter_constant_register(first_register, index)?;
                if register < 8 {
                    assembler.instruction(&[0xc5, 0x7d, 0x74, 0xd8 | register])?;
                } else {
                    assembler.instruction(&[0xc5, 0x3d, 0x74, 0xd8])?;
                }
                assembler.instruction(&[0xc4, 0x41, 0x1d, 0xeb, 0xe3])?; // ymm12 |= ymm11
            }
        }
        X86StartFilterKind::Avx512Bw => {
            x86_emit_start_filter_vector_load(assembler, kind, filter.scan_offset)?;
            let first_evex = if first_register < 8 { 0xf1 } else { 0xd1 };
            assembler.instruction(&[
                0x62,
                first_evex,
                0x7d,
                0x48,
                0x74,
                0xc8 | (first_register & 7),
            ])?;
            for index in 1..ranges.len() {
                let register = x86_filter_constant_register(first_register, index)?;
                let evex = if register < 8 { 0xf1 } else { 0xd1 };
                assembler.instruction(&[0x62, evex, 0x7d, 0x48, 0x74, 0xd0 | (register & 7)])?;
                assembler.instruction(&[0xc4, 0xe1, 0xf4, 0x45, 0xca])?;
            }
        }
    }
    // SSE2/AVX2 build the exact mask directly in XMM/YMM12. AVX-512 keeps it
    // in k1, as described by X86CandidateMask.
    Ok(())
}

fn x86_emit_start_filter_vector_candidates(
    assembler: &mut X86Assembler,
    filter: NativeStartFilter,
    kind: X86StartFilterKind,
    first_register: u8,
) -> Result<(), ObjectError> {
    if filter.is_exact() {
        x86_emit_exact_start_filter_vector_candidates(assembler, filter, kind, first_register)
    } else {
        x86_emit_range_start_filter_vector_candidates(assembler, filter, kind, first_register)
    }
}

fn x86_emit_start_filter_vector_test(
    assembler: &mut X86Assembler,
    filter: NativeStartFilter,
    kind: X86StartFilterKind,
) -> Result<X86CandidateMask, ObjectError> {
    if filter.ranges().is_empty() {
        return Err(ObjectError::InvalidModule(
            "empty x86 start filter reached vector lowering",
        ));
    }
    if !filter.is_exact() && kind == X86StartFilterKind::Avx512Bw {
        x86_emit_start_filter_range_vector_test(assembler, filter, kind)?;
        return Ok(X86CandidateMask::Avx512K4);
    }
    x86_emit_start_filter_vector_candidates(assembler, filter, kind, 1)?;
    let mask = X86CandidateMask::for_filter(filter, kind);
    match kind {
        X86StartFilterKind::Sse2 => {
            assembler.instruction(&[0x66, 0x41, 0x0f, 0xd7, 0xc4])?;
        }
        X86StartFilterKind::Avx2 => {
            assembler.instruction(&[0xc4, 0xc1, 0x7d, 0xd7, 0xc4])?;
        }
        X86StartFilterKind::Avx512Bw => {
            x86_emit_candidate_nonzero(assembler, mask)?;
            return Ok(mask);
        }
    }
    x86_emit_candidate_nonzero(assembler, mask)?;
    Ok(mask)
}

/// Intersect the already-materialized primary candidates with every remaining
/// graph-required vector column. SSE2/AVX2 leave the exact lane set in
/// XMM/YMM7; AVX-512BW leaves all lane bits in K5.
fn x86_emit_vector_filter_secondary_candidates(
    assembler: &mut X86Assembler,
    vector_filter: NativeVectorFilter,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    if vector_filter.columns().len() < 2 {
        return Err(ObjectError::InvalidModule(
            "unsupported x86 vector-filter intersection",
        ));
    }
    match kind {
        X86StartFilterKind::Sse2 => {
            assembler.instruction(&[0x66, 0x41, 0x0f, 0x6f, 0xfc])?; // xmm7 = primary xmm12
        }
        X86StartFilterKind::Avx2 => {
            assembler.instruction(&[0xc4, 0xc1, 0x7d, 0x6f, 0xfc])?; // ymm7 = primary ymm12
        }
        X86StartFilterKind::Avx512Bw => x86_emit_avx512_copy_mask_to_k5(
            assembler,
            X86CandidateMask::for_filter(vector_filter.columns()[0], kind),
        )?,
    }
    let primary_constants = vector_filter.columns()[0].constant_count();
    let mut first_register = 1_u8
        .checked_add(
            u8::try_from(primary_constants)
                .map_err(|_| ObjectError::ArithmeticOverflow("x86 vector-filter constants"))?,
        )
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 vector-filter constants",
        ))?;
    for &filter in &vector_filter.columns()[1..] {
        x86_emit_start_filter_vector_candidates(assembler, filter, kind, first_register)?;
        match kind {
            X86StartFilterKind::Sse2 => {
                assembler.instruction(&[0x66, 0x41, 0x0f, 0xdb, 0xfc])?; // xmm7 &= xmm12
            }
            X86StartFilterKind::Avx2 => {
                assembler.instruction(&[0xc4, 0xc1, 0x45, 0xdb, 0xfc])?; // ymm7 &= ymm12
            }
            X86StartFilterKind::Avx512Bw => {
                x86_emit_avx512_intersect_k5(
                    assembler,
                    X86CandidateMask::for_filter(filter, kind),
                )?;
            }
        }
        first_register = first_register
            .checked_add(
                u8::try_from(filter.constant_count())
                    .map_err(|_| ObjectError::ArithmeticOverflow("x86 vector-filter constants"))?,
            )
            .ok_or(ObjectError::ArithmeticOverflow(
                "x86 vector-filter constants",
            ))?;
    }
    Ok(())
}

fn x86_emit_vector_filter_intersection_test(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    match kind {
        X86StartFilterKind::Sse2 => {
            assembler.instruction(&[0x66, 0x0f, 0xd7, 0xc7])?;
        }
        X86StartFilterKind::Avx2 => {
            assembler.instruction(&[0xc5, 0xfd, 0xd7, 0xc7])?;
        }
        X86StartFilterKind::Avx512Bw => {
            x86_emit_candidate_nonzero(assembler, X86CandidateMask::for_intersection(kind))?;
        }
    }
    if kind != X86StartFilterKind::Avx512Bw {
        x86_emit_candidate_nonzero(assembler, X86CandidateMask::MovemaskEax)?;
    }
    Ok(())
}

fn x86_emit_vector_filter_secondary_test(
    assembler: &mut X86Assembler,
    vector_filter: NativeVectorFilter,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    x86_emit_vector_filter_secondary_candidates(assembler, vector_filter, kind)?;
    x86_emit_vector_filter_intersection_test(assembler, kind)
}

fn x86_emit_start_filter_vector_candidate(
    assembler: &mut X86Assembler,
    filter: NativeStartFilter,
    kind: X86StartFilterKind,
    vector_hit: X86Label,
) -> Result<(), ObjectError> {
    let _mask = x86_emit_start_filter_vector_test(assembler, filter, kind)?;
    // The no-hit case is the scanner's hot path, so leave it as fallthrough
    // and share one out-of-line first-lane stub across every unrolled vector.
    // `position` has not advanced when this rare branch is taken.
    assembler.branch(&[0x0f, 0x85], vector_hit)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum X86SparseBatchCandidate {
    Primary(NativeStartFilter),
    Intersection,
}

impl X86SparseBatchCandidate {
    const fn vector_register(self) -> u8 {
        match self {
            Self::Primary(_) => 12,
            Self::Intersection => 7,
        }
    }

    fn mask(self, kind: X86StartFilterKind) -> X86CandidateMask {
        match self {
            Self::Primary(filter) => X86CandidateMask::for_filter(filter, kind),
            Self::Intersection => X86CandidateMask::for_intersection(kind),
        }
    }
}

/// XMM/YMM15 and K6 are caller-saved and disjoint from the vector-filter
/// constants and intersection banks. R10/R11 remain untouched.
fn x86_emit_sparse_batch_accumulator_clear(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    match kind {
        X86StartFilterKind::Sse2 => x86_emit_sse2_binary(assembler, 0xef, 15, 15)?,
        X86StartFilterKind::Avx2 => x86_emit_avx2_binary(assembler, 0xef, 15, 15, 15)?,
        X86StartFilterKind::Avx512Bw => {
            x86_emit_k_binary(assembler, 0x47, 6, 6, 6)?; // kxorq k6, k6, k6
        }
    }
    Ok(())
}

fn x86_emit_sparse_batch_accumulate(
    assembler: &mut X86Assembler,
    candidate: X86SparseBatchCandidate,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    match kind {
        X86StartFilterKind::Sse2 => {
            x86_emit_sse2_binary(assembler, 0xeb, 15, candidate.vector_register())?;
        }
        X86StartFilterKind::Avx2 => {
            x86_emit_avx2_binary(assembler, 0xeb, 15, 15, candidate.vector_register())?;
        }
        X86StartFilterKind::Avx512Bw => {
            let source =
                candidate
                    .mask(kind)
                    .opmask_register()
                    .ok_or(ObjectError::InvalidModule(
                        "AVX-512 sparse batch candidate has no opmask",
                    ))?;
            x86_emit_k_binary(assembler, 0x45, 6, 6, source)?; // k6 |= source
        }
    }
    Ok(())
}

fn x86_emit_sparse_batch_accumulator_test(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    match kind {
        X86StartFilterKind::Sse2 => {
            assembler.instruction(&[0x66, 0x41, 0x0f, 0xd7, 0xc7])?; // pmovmskb eax, xmm15
            x86_emit_candidate_nonzero(assembler, X86CandidateMask::MovemaskEax)?;
        }
        X86StartFilterKind::Avx2 => {
            assembler.instruction(&[0xc4, 0xc1, 0x7d, 0xd7, 0xc7])?; // vpmovmskb eax, ymm15
            x86_emit_candidate_nonzero(assembler, X86CandidateMask::MovemaskEax)?;
        }
        X86StartFilterKind::Avx512Bw => {
            x86_emit_candidate_nonzero(assembler, X86CandidateMask::Avx512K6)?;
        }
    }
    Ok(())
}

/// Test four adjacent vector blocks with one conditional branch. Primary
/// masks are ORed by lane; a hit rewinds the complete bounded group.
fn x86_emit_sparse_filter_mask_batch(
    assembler: &mut X86Assembler,
    filter: NativeStartFilter,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    x86_emit_sparse_batch_accumulator_clear(assembler, kind)?;
    for _ in 0..X86_MASK_BATCH_VECTORS {
        x86_emit_start_filter_vector_candidates(assembler, filter, kind, 1)?;
        x86_emit_sparse_batch_accumulate(
            assembler,
            X86SparseBatchCandidate::Primary(filter),
            kind,
        )?;
        assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    }
    x86_emit_sparse_batch_accumulator_test(assembler, kind)
}

/// Test four adjacent vector blocks with the complete graph-required column
/// intersection. The caller starts at the group base; both outcomes leave RDX
/// just beyond the group, and a hit can rewind for exact scalar replay.
fn x86_emit_sparse_vector_filter_mask_batch(
    assembler: &mut X86Assembler,
    vector_filter: NativeVectorFilter,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    if vector_filter.columns().len() < 2 {
        return Err(ObjectError::InvalidModule(
            "unsupported x86 sparse vector-filter intersection",
        ));
    }
    x86_emit_sparse_batch_accumulator_clear(assembler, kind)?;
    for _ in 0..X86_MASK_BATCH_VECTORS {
        x86_emit_start_filter_vector_candidates(assembler, vector_filter.columns()[0], kind, 1)?;
        x86_emit_vector_filter_secondary_candidates(assembler, vector_filter, kind)?;
        x86_emit_sparse_batch_accumulate(assembler, X86SparseBatchCandidate::Intersection, kind)?;
        assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    }
    x86_emit_sparse_batch_accumulator_test(assembler, kind)
}

fn x86_emit_rewind_sparse_filter_mask_batch(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    let bytes = u16::from(kind.width())
        .checked_mul(X86_MASK_BATCH_VECTORS)
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 sparse-filter batch width",
        ))?;
    if bytes <= 0x7f {
        assembler.instruction(&[
            0x48,
            0x83,
            0xea,
            u8::try_from(bytes)
                .map_err(|_| ObjectError::ArithmeticOverflow("x86 sparse-filter rewind"))?,
        ])?;
    } else {
        let mut instruction = vec![0x48, 0x81, 0xea]; // sub rdx, imm32
        instruction.extend_from_slice(&u32::from(bytes).to_le_bytes());
        assembler.instruction(&instruction)?;
    }
    Ok(())
}

fn x86_emit_suffix_lower_bound(
    assembler: &mut X86Assembler,
    backtrack: u64,
) -> Result<(), ObjectError> {
    if backtrack == 0 {
        return Ok(());
    }
    let clamp = assembler.label()?;
    let done = assembler.label()?;
    assembler.instruction(&[0x48, 0x89, 0xd0])?; // distance = suffix base
    assembler.instruction(&[0x48, 0x29, 0xf0])?; // distance -= window start
    if let Ok(immediate) = i32::try_from(backtrack) {
        let mut compare = vec![0x48, 0x3d]; // cmp distance, backtrack
        compare.extend_from_slice(&immediate.to_le_bytes());
        assembler.instruction(&compare)?;
        assembler.branch(&[0x0f, 0x86], clamp)?; // distance <= backtrack
        if let Ok(short) = u8::try_from(backtrack)
            && short <= 0x7f
        {
            assembler.instruction(&[0x48, 0x83, 0xea, short])?; // position -= backtrack
        } else {
            let mut subtract = vec![0x48, 0x81, 0xea];
            subtract.extend_from_slice(&immediate.to_le_bytes());
            assembler.instruction(&subtract)?;
        }
    } else {
        let mut load = vec![0x49, 0xba]; // movabs r10, backtrack
        load.extend_from_slice(&backtrack.to_le_bytes());
        assembler.instruction(&load)?;
        assembler.instruction(&[0x4c, 0x39, 0xd0])?; // cmp distance, r10
        assembler.branch(&[0x0f, 0x86], clamp)?;
        assembler.instruction(&[0x4c, 0x29, 0xd2])?; // position -= r10
    }
    assembler.branch(&[0xe9], done)?;
    assembler.bind(clamp)?;
    assembler.instruction(&[0x48, 0x89, 0xf2])?; // position = window start
    assembler.bind(done)?;
    Ok(())
}

fn x86_emit_suffix_reset_restart(
    assembler: &mut X86Assembler,
    non_reset: NativeResetFilter,
) -> Result<(), ObjectError> {
    let scan = assembler.label()?;
    let non_reset_byte = assembler.label()?;
    let no_reset = assembler.label()?;
    let done = assembler.label()?;
    assembler.instruction(&[0x49, 0x89, 0xd2])?; // cursor = suffix base
    assembler.instruction(&[0x41, 0xbb, 64, 0, 0, 0])?; // remaining = 64
    assembler.bind(scan)?;
    assembler.instruction(&[0x49, 0x39, 0xf2])?; // cursor <= window start
    assembler.branch(&[0x0f, 0x86], no_reset)?;
    assembler.instruction(&[0x49, 0xff, 0xca])?; // --cursor
    assembler.instruction(&[0x42, 0x0f, 0xb6, 0x04, 0x17])?; // haystack[cursor]
    for range in non_reset.ranges() {
        assembler.instruction(&[0x3c, range.start])?;
        if range.start == range.end {
            assembler.branch(&[0x0f, 0x84], non_reset_byte)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch(&[0x0f, 0x82], next_range)?;
            assembler.instruction(&[0x3c, range.end])?;
            assembler.branch(&[0x0f, 0x86], non_reset_byte)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.instruction(&[0x49, 0x8d, 0x52, 1])?; // start = reset + 1
    assembler.branch(&[0xe9], done)?;

    assembler.bind(non_reset_byte)?;
    assembler.instruction(&[0x49, 0xff, 0xcb])?; // --remaining
    assembler.branch(&[0x0f, 0x85], scan)?;
    assembler.bind(no_reset)?;
    assembler.instruction(&[0x48, 0x89, 0xf2])?; // restore original start
    assembler.bind(done)?;
    Ok(())
}

fn x86_emit_suffix_restart(
    assembler: &mut X86Assembler,
    restart: NativeSuffixRestart,
) -> Result<(), ObjectError> {
    match restart {
        NativeSuffixRestart::Bounded { backtrack } => {
            x86_emit_suffix_lower_bound(assembler, backtrack)
        }
        NativeSuffixRestart::Synchronizing { non_reset } => {
            x86_emit_suffix_reset_restart(assembler, non_reset)
        }
        NativeSuffixRestart::OriginalStart => {
            assembler.instruction(&[0x48, 0x89, 0xf2])?; // restore original start
            Ok(())
        }
    }
}

/// Scan every graph-required factor candidate and prove candidate starts with
/// an independently determinized reverse machine. Total reverse-table work is
/// capped by one byte transition per input byte; exhausting that fuel falls
/// back to the untouched ordinary forward DFA. Candidate scanning itself is
/// still the same SIMD/scalar mandatory-factor proof used by the established
/// suffix prepass.
#[allow(
    clippy::large_types_passed_by_value,
    clippy::too_many_lines,
    reason = "the factor scanner and reverse-proof control flow form one auditable native loop"
)]
fn x86_emit_seeded_reverse_prepass(
    assembler: &mut X86Assembler,
    suffix: NativeSuffixFilter,
    reverse: NativeSeededReverseLayout,
    kind: X86StartFilterKind,
    layout: NativeDfaLayout,
    no_match: X86Label,
    matched: X86Label,
) -> Result<(), ObjectError> {
    let vector = assembler.label()?;
    let single_vector = assembler.label()?;
    let scalar = assembler.label()?;
    let scalar_columns = assembler.label()?;
    let scalar_reject = assembler.label()?;
    let primary_hit = assembler.label()?;
    let vector_hit = assembler.label()?;
    let sparse_batch_hit = assembler.label()?;
    let candidate = assembler.label()?;
    let reverse_loop = assembler.label()?;
    let record_start = assembler.label()?;
    let reverse_continue = assembler.label()?;
    let reverse_done = assembler.label()?;
    let finalize = assembler.label()?;
    let global_minimum = assembler.label()?;
    let fallback = assembler.label()?;
    let done = assembler.label()?;
    let filter = suffix.filter;
    if suffix.minimum_width == 0 {
        return Err(ObjectError::InvalidModule(
            "x86 seeded reverse filter has zero minimum width",
        ));
    }
    if layout.seeded_reverse != Some(reverse) {
        return Err(ObjectError::InvalidModule(
            "x86 seeded reverse layout changed during lowering",
        ));
    }

    let lazy_vector_filter = suffix.vector_filter;
    let scalar_filter = suffix.vector_filter.or(suffix.scalar_filter);
    let maximum_filter_offset =
        scalar_filter.map_or(filter.scan_offset, NativeVectorFilter::max_scan_offset);
    let maximum_scan_offset = maximum_filter_offset.max(reverse.boundary_offset.saturating_sub(1));
    let use_sparse_batch = x86_use_sparse_filter_mask_batch(filter, kind);
    let emit_constants = |assembler: &mut X86Assembler| -> Result<(), ObjectError> {
        if let Some(vector_filter) = lazy_vector_filter {
            let mut first_register = 1_u8;
            for &column in vector_filter.columns() {
                x86_emit_start_filter_constants(assembler, column, kind, first_register)?;
                first_register = first_register
                    .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                        ObjectError::ArithmeticOverflow("x86 seeded reverse constants")
                    })?)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "x86 seeded reverse constants",
                    ))?;
            }
        } else {
            x86_emit_start_filter_constants(assembler, filter, kind, 1)?;
        }
        Ok(())
    };
    if !ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS {
        emit_constants(assembler)?;
    }

    // R12 is reverse fuel, R13 the minimum proved start, R14 the next factor
    // base, and R15 the reverse cursor. The outer lowering preserves all four.
    assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
    let mut minimum = vec![0x48, 0x3d];
    minimum.extend_from_slice(&u32::from(SUFFIX_PREFILTER_MIN_WINDOW_BYTES).to_le_bytes());
    assembler.instruction(&minimum)?;
    assembler.branch(&[0x0f, 0x82], done)?;
    assembler.instruction(&[0x49, 0x89, 0xc4])?; // fuel = window bytes
    assembler.instruction(&[0x49, 0xc7, 0xc5, 0xff, 0xff, 0xff, 0xff])?; // min = none
    if ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS {
        emit_constants(assembler)?;
    }

    assembler.bind(vector)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?;
    assembler.instruction(&[0x48, 0x29, 0xd0])?;
    let unrolled_bytes = u32::from(kind.width())
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(u32::from(maximum_scan_offset)))
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 seeded reverse filter width",
        ))?;
    let mut compare_unrolled = vec![0x48, 0x3d];
    compare_unrolled.extend_from_slice(&unrolled_bytes.to_le_bytes());
    assembler.instruction(&compare_unrolled)?;
    assembler.branch(&[0x0f, 0x82], single_vector)?;
    let vector_candidate_hit = if lazy_vector_filter.is_some() {
        primary_hit
    } else {
        vector_hit
    };
    if use_sparse_batch {
        x86_emit_sparse_filter_mask_batch(assembler, filter, kind)?;
        assembler.branch(&[0x0f, 0x85], sparse_batch_hit)?;
    } else {
        for _ in 0..X86_MASK_BATCH_VECTORS {
            x86_emit_start_filter_vector_candidate(assembler, filter, kind, vector_candidate_hit)?;
            assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
        }
    }
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(sparse_batch_hit)?;
    x86_emit_rewind_sparse_filter_mask_batch(assembler, kind)?;
    assembler.branch(&[0xe9], scalar)?;

    assembler.bind(single_vector)?;
    let single_vector_bytes =
        kind.width()
            .checked_add(maximum_scan_offset)
            .ok_or(ObjectError::ArithmeticOverflow(
                "x86 seeded reverse filter width",
            ))?;
    assembler.instruction(&[0x48, 0x83, 0xf8, single_vector_bytes])?;
    assembler.branch(&[0x0f, 0x82], scalar)?;
    x86_emit_start_filter_vector_candidate(assembler, filter, kind, vector_candidate_hit)?;
    assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(scalar)?;
    x86_emit_start_filter_scalar_bound(assembler, maximum_scan_offset, finalize)?;
    x86_emit_start_filter_scalar_load(assembler, filter.scan_offset)?;
    let scalar_candidate = if scalar_filter.is_some() {
        scalar_columns
    } else {
        candidate
    };
    for range in filter.ranges() {
        assembler.instruction(&[0x3c, range.start])?;
        if range.start == range.end {
            assembler.branch(&[0x0f, 0x84], scalar_candidate)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch(&[0x0f, 0x82], next_range)?;
            assembler.instruction(&[0x3c, range.end])?;
            assembler.branch(&[0x0f, 0x86], scalar_candidate)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], scalar)?;

    if let Some(vector_filter) = scalar_filter {
        assembler.bind(scalar_columns)?;
        for &column in &vector_filter.columns()[1..] {
            x86_emit_scalar_filter_membership(assembler, column, scalar_reject)?;
        }
        assembler.branch(&[0xe9], candidate)?;
        assembler.bind(scalar_reject)?;
        assembler.instruction(&[0x48, 0xff, 0xc2])?;
        assembler.branch(&[0xe9], vector)?;

        if let Some(lazy_filter) = lazy_vector_filter {
            assembler.bind(primary_hit)?;
            x86_emit_vector_filter_secondary_test(assembler, lazy_filter, kind)?;
            assembler.branch(&[0x0f, 0x85], vector_hit)?;
            assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
            assembler.branch(&[0xe9], vector)?;
        } else {
            assembler.bind(primary_hit)?;
            assembler.branch(&[0xe9], scalar)?;
        }
    } else {
        assembler.bind(scalar_columns)?;
        assembler.branch(&[0xe9], candidate)?;
        assembler.bind(scalar_reject)?;
        assembler.branch(&[0xe9], scalar)?;
        assembler.bind(primary_hit)?;
        assembler.branch(&[0xe9], scalar)?;
    }

    assembler.bind(vector_hit)?;
    let vector_hit_mask = if lazy_vector_filter.is_some() {
        X86CandidateMask::for_intersection(kind)
    } else {
        X86CandidateMask::for_filter(filter, kind)
    };
    x86_emit_first_candidate_lane(assembler, vector_hit_mask)?;
    assembler.instruction(&[0x48, 0x01, 0xc2])?; // position += first lane

    assembler.bind(candidate)?;
    assembler.instruction(&[0x4c, 0x8d, 0x72, 0x01])?; // next base = candidate + 1
    if reverse.boundary_offset == 0 {
        assembler.instruction(&[0x49, 0x89, 0xd7])?; // cursor = candidate
    } else {
        assembler.instruction(&[0x4c, 0x8d, 0x7a, reverse.boundary_offset])?; // cursor = candidate + boundary
    }
    let mut class_map = vec![0x4d, 0x8d, 0x99]; // lea class-map(r9), r11
    class_map.extend_from_slice(&reverse.class_map_offset.to_le_bytes());
    assembler.instruction(&class_map)?;
    x86_set_row(assembler, reverse.initial_row_offset)?;

    // A start reachable without consuming a reverse byte is recorded before
    // entering the table loop. It must not flow through `reverse_continue`,
    // whose EAX cell exists only after a table load.
    if reverse.initial_reaches_start {
        if reverse.proves_match && layout.output == OutputContract::Exists {
            assembler.branch(&[0xe9], matched)?;
        } else {
            assembler.instruction(&[0x4d, 0x39, 0xef])?; // cursor >= minimum
            assembler.branch(&[0x0f, 0x83], reverse_loop)?;
            assembler.instruction(&[0x4d, 0x89, 0xfd])?; // minimum = cursor
            assembler.instruction(&[0x49, 0x39, 0xf5])?; // minimum == window start
            assembler.branch(&[0x0f, 0x84], global_minimum)?;
        }
    }

    assembler.bind(reverse_loop)?;
    assembler.instruction(&[0x49, 0x39, 0xf7])?; // cursor <= window start
    assembler.branch(&[0x0f, 0x86], reverse_done)?;
    assembler.instruction(&[0x4d, 0x85, 0xe4])?; // test fuel
    assembler.branch(&[0x0f, 0x84], fallback)?;
    assembler.instruction(&[0x49, 0xff, 0xcf])?; // --cursor
    assembler.instruction(&[0x49, 0xff, 0xcc])?; // --fuel
    assembler.instruction(&[0x42, 0x0f, 0xb6, 0x04, 0x3f])?; // byte [haystack+cursor]
    assembler.instruction(&[0x41, 0x0f, 0xb6, 0x04, 0x03])?; // exact raw class
    assembler.instruction(&[0x41, 0x8b, 0x04, 0x82])?; // packed reverse cell
    assembler.instruction(&[0xa9, 0x00, 0x00, 0x00, 0x80])?;
    assembler.branch(&[0x0f, 0x88], record_start)?;

    assembler.bind(reverse_continue)?;
    assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x7f])?;
    assembler.branch(&[0x0f, 0x84], reverse_done)?;
    assembler.instruction(&[0x4d, 0x8d, 0x54, 0x01, 0xff])?;
    assembler.branch(&[0xe9], reverse_loop)?;

    assembler.bind(record_start)?;
    if reverse.proves_match && layout.output == OutputContract::Exists {
        assembler.branch(&[0xe9], matched)?;
    } else {
        assembler.instruction(&[0x4d, 0x39, 0xef])?; // cursor >= minimum
        assembler.branch(&[0x0f, 0x83], reverse_continue)?;
        assembler.instruction(&[0x4d, 0x89, 0xfd])?; // minimum = cursor
        assembler.instruction(&[0x49, 0x39, 0xf5])?; // minimum == window start
        assembler.branch(&[0x0f, 0x84], global_minimum)?;
        assembler.branch(&[0xe9], reverse_continue)?;
    }

    assembler.bind(reverse_done)?;
    assembler.instruction(&[0x4c, 0x89, 0xf2])?; // position = next base
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(finalize)?;
    assembler.instruction(&[0x49, 0x83, 0xfd, 0xff])?;
    assembler.branch(&[0x0f, 0x84], no_match)?;
    assembler.bind(global_minimum)?;
    assembler.instruction(&[0x4c, 0x89, 0xea])?; // position = minimum proved start
    assembler.branch(&[0xe9], done)?;

    assembler.bind(fallback)?;
    assembler.instruction(&[0x48, 0x89, 0xf2])?; // untouched semantic start
    assembler.bind(done)?;
    Ok(())
}

/// Scan aligned graph-proven suffix columns before entering the forward
/// machine. The terminal column is primary; other selective columns are
/// loaded only in primary-hit blocks. Absence of any aligned candidate proves
/// that no match exists. The first candidate either applies the bounded-width
/// lower bound or restarts after a nearby all-state synchronizing byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct X86AdaptiveSuffixColdPlan {
    joint_vector: X86Label,
    adaptive_scalar: X86Label,
    adaptive_scalar_columns: X86Label,
    adaptive_scalar_reject: X86Label,
    sparse_batch_hit: X86Label,
    single_vector: X86Label,
    apply: X86Label,
    no_match: X86Label,
    filter: NativeStartFilter,
    vector_filter: NativeVectorFilter,
    kind: X86StartFilterKind,
    maximum_scan_offset: u8,
    unrolled_bytes: u32,
}

#[allow(
    clippy::large_types_passed_by_value,
    clippy::too_many_lines,
    reason = "aligned vector batches, lazy intersections and scalar tails form one suffix proof"
)]
fn x86_emit_suffix_prepass(
    assembler: &mut X86Assembler,
    suffix: NativeSuffixFilter,
    kind: X86StartFilterKind,
    layout: NativeDfaLayout,
    no_match: X86Label,
    matched: X86Label,
) -> Result<Option<X86AdaptiveSuffixColdPlan>, ObjectError> {
    if let Some(reverse) = layout.seeded_reverse {
        x86_emit_seeded_reverse_prepass(
            assembler, suffix, reverse, kind, layout, no_match, matched,
        )?;
        return Ok(None);
    }
    let vector = assembler.label()?;
    let single_vector = assembler.label()?;
    let scalar = assembler.label()?;
    let scalar_columns = assembler.label()?;
    let scalar_reject = assembler.label()?;
    let primary_hit = assembler.label()?;
    let vector_hit = assembler.label()?;
    let sparse_batch_hit = assembler.label()?;
    let joint_vector = assembler.label()?;
    let adaptive_scalar = assembler.label()?;
    let adaptive_scalar_columns = assembler.label()?;
    let adaptive_scalar_reject = assembler.label()?;
    let apply = assembler.label()?;
    let done = assembler.label()?;
    let filter = suffix.filter;
    if suffix.minimum_width == 0 {
        return Err(ObjectError::InvalidModule(
            "x86 suffix filter has zero minimum width",
        ));
    }

    // Every retained column is a graph-required aligned predicate. AVX-512
    // keeps their 64-lane intersection in k5, so the same proof used by the
    // SSE2/AVX2 lazy-secondary path applies without scalar refinement.
    let lazy_vector_filter = suffix.vector_filter;
    let scalar_filter = suffix.vector_filter.or(suffix.scalar_filter);
    let maximum_scan_offset =
        scalar_filter.map_or(filter.scan_offset, NativeVectorFilter::max_scan_offset);
    let use_sparse_batch = x86_use_sparse_filter_mask_batch(filter, kind);
    // The initial suffix scan is exactly the baseline primary-only sparse
    // batch. Only a witnessed scalar secondary rejection after such a hit
    // changes CFG mode: subsequent complete groups use all retained columns.
    // No runtime mode flag or additional live register is required.
    let adaptive_joint_filter = (layout.declined_redundant_root_reverse && use_sparse_batch)
        .then_some(lazy_vector_filter)
        .flatten();
    let emit_constants = |assembler: &mut X86Assembler| -> Result<(), ObjectError> {
        if let Some(vector_filter) = lazy_vector_filter {
            let mut first_register = 1_u8;
            for &column in vector_filter.columns() {
                x86_emit_start_filter_constants(assembler, column, kind, first_register)?;
                first_register = first_register
                    .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                        ObjectError::ArithmeticOverflow("x86 suffix-filter constants")
                    })?)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "x86 suffix-filter constants",
                    ))?;
            }
        } else {
            x86_emit_start_filter_constants(assembler, filter, kind, 1)?;
        }
        Ok(())
    };
    if !ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS {
        emit_constants(assembler)?;
    }
    assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
    let mut minimum = vec![0x48, 0x3d];
    minimum.extend_from_slice(&u32::from(SUFFIX_PREFILTER_MIN_WINDOW_BYTES).to_le_bytes());
    assembler.instruction(&minimum)?;
    assembler.branch(&[0x0f, 0x82], done)?;
    if ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS {
        emit_constants(assembler)?;
    }

    assembler.bind(vector)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?;
    assembler.instruction(&[0x48, 0x29, 0xd0])?;
    let unrolled_bytes = u32::from(kind.width())
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(u32::from(maximum_scan_offset)))
        .ok_or(ObjectError::ArithmeticOverflow("x86 suffix-filter width"))?;
    let mut compare_unrolled = vec![0x48, 0x3d];
    compare_unrolled.extend_from_slice(&unrolled_bytes.to_le_bytes());
    assembler.instruction(&compare_unrolled)?;
    assembler.branch(&[0x0f, 0x82], single_vector)?;
    let vector_candidate_hit = if lazy_vector_filter.is_some() {
        primary_hit
    } else {
        vector_hit
    };
    if use_sparse_batch {
        x86_emit_sparse_filter_mask_batch(assembler, filter, kind)?;
        assembler.branch(&[0x0f, 0x85], sparse_batch_hit)?;
    } else {
        for _ in 0..X86_MASK_BATCH_VECTORS {
            x86_emit_start_filter_vector_candidate(assembler, filter, kind, vector_candidate_hit)?;
            assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
        }
    }
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(sparse_batch_hit)?;
    x86_emit_rewind_sparse_filter_mask_batch(assembler, kind)?;
    assembler.branch(
        &[0xe9],
        if adaptive_joint_filter.is_some() {
            adaptive_scalar
        } else {
            scalar
        },
    )?;

    assembler.bind(single_vector)?;
    let single_vector_bytes = kind
        .width()
        .checked_add(maximum_scan_offset)
        .ok_or(ObjectError::ArithmeticOverflow("x86 suffix-filter width"))?;
    assembler.instruction(&[0x48, 0x83, 0xf8, single_vector_bytes])?;
    assembler.branch(&[0x0f, 0x82], scalar)?;
    x86_emit_start_filter_vector_candidate(assembler, filter, kind, vector_candidate_hit)?;
    assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(scalar)?;
    x86_emit_start_filter_scalar_bound(assembler, maximum_scan_offset, no_match)?;
    x86_emit_start_filter_scalar_load(assembler, filter.scan_offset)?;
    let scalar_candidate = if scalar_filter.is_some() {
        scalar_columns
    } else {
        apply
    };
    for range in filter.ranges() {
        assembler.instruction(&[0x3c, range.start])?;
        if range.start == range.end {
            assembler.branch(&[0x0f, 0x84], scalar_candidate)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch(&[0x0f, 0x82], next_range)?;
            assembler.instruction(&[0x3c, range.end])?;
            assembler.branch(&[0x0f, 0x86], scalar_candidate)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], scalar)?;

    if let Some(vector_filter) = scalar_filter {
        assembler.bind(scalar_columns)?;
        for &column in &vector_filter.columns()[1..] {
            x86_emit_scalar_filter_membership(assembler, column, scalar_reject)?;
        }
        assembler.branch(&[0xe9], apply)?;
        assembler.bind(scalar_reject)?;
        assembler.instruction(&[0x48, 0xff, 0xc2])?;
        assembler.branch(&[0xe9], vector)?;

        if let Some(lazy_filter) = lazy_vector_filter {
            assembler.bind(primary_hit)?;
            x86_emit_vector_filter_secondary_test(assembler, lazy_filter, kind)?;
            assembler.branch(&[0x0f, 0x85], vector_hit)?;
            assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
            assembler.branch(&[0xe9], vector)?;
        } else {
            assembler.bind(primary_hit)?;
            assembler.branch(&[0xe9], scalar)?;
        }
    } else {
        assembler.bind(scalar_columns)?;
        assembler.branch(&[0xe9], apply)?;
        assembler.bind(scalar_reject)?;
        assembler.branch(&[0xe9], scalar)?;
        assembler.bind(primary_hit)?;
        assembler.branch(&[0xe9], scalar)?;
    }

    assembler.bind(vector_hit)?;
    let vector_hit_mask = if lazy_vector_filter.is_some() {
        X86CandidateMask::for_intersection(kind)
    } else {
        X86CandidateMask::for_filter(filter, kind)
    };
    x86_emit_first_candidate_lane(assembler, vector_hit_mask)?;
    assembler.instruction(&[0x48, 0x01, 0xc2])?;
    assembler.branch(&[0xe9], apply)?;

    assembler.bind(apply)?;
    if let Some(retry) = suffix.retry {
        module_suffix_retry::x86_emit_bounded_suffix_retry(
            assembler, layout, retry, vector, no_match, matched,
        )?;
    } else {
        x86_emit_suffix_restart(assembler, suffix.restart)?;
    }
    assembler.bind(done)?;
    Ok(
        adaptive_joint_filter.map(|vector_filter| X86AdaptiveSuffixColdPlan {
            joint_vector,
            adaptive_scalar,
            adaptive_scalar_columns,
            adaptive_scalar_reject,
            sparse_batch_hit,
            single_vector,
            apply,
            no_match,
            filter,
            vector_filter,
            kind,
            maximum_scan_offset,
            unrolled_bytes,
        }),
    )
}

/// Emit the adaptive joint-group and exact-replay paths after the function's
/// ordinary return. They are reachable only through explicit branches from
/// the suffix prepass, so keeping them cold preserves every dormant scanner
/// byte and offset except the one rel32 edge that enters this region.
fn x86_emit_adaptive_suffix_cold(
    assembler: &mut X86Assembler,
    plan: X86AdaptiveSuffixColdPlan,
) -> Result<(), ObjectError> {
    assembler.bind(plan.joint_vector)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
    let mut compare_unrolled = vec![0x48, 0x3d];
    compare_unrolled.extend_from_slice(&plan.unrolled_bytes.to_le_bytes());
    assembler.instruction(&compare_unrolled)?;
    // Once fewer than four complete blocks remain there is no full group to
    // optimize; the baseline single-vector/tail handles the remainder.
    assembler.branch(&[0x0f, 0x82], plan.single_vector)?;
    x86_emit_sparse_vector_filter_mask_batch(assembler, plan.vector_filter, plan.kind)?;
    assembler.branch(&[0x0f, 0x85], plan.sparse_batch_hit)?;
    assembler.branch(&[0xe9], plan.joint_vector)?;

    // Exact scalar replay begins at the rewound group base. The first false
    // secondary advances exactly one byte, then permanently resumes the joint
    // group CFG without any runtime mode flag or extra live register.
    assembler.bind(plan.adaptive_scalar)?;
    x86_emit_start_filter_scalar_bound(assembler, plan.maximum_scan_offset, plan.no_match)?;
    x86_emit_start_filter_scalar_load(assembler, plan.filter.scan_offset)?;
    for range in plan.filter.ranges() {
        assembler.instruction(&[0x3c, range.start])?;
        if range.start == range.end {
            assembler.branch(&[0x0f, 0x84], plan.adaptive_scalar_columns)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch(&[0x0f, 0x82], next_range)?;
            assembler.instruction(&[0x3c, range.end])?;
            assembler.branch(&[0x0f, 0x86], plan.adaptive_scalar_columns)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], plan.adaptive_scalar)?;

    assembler.bind(plan.adaptive_scalar_columns)?;
    for &column in &plan.vector_filter.columns()[1..] {
        x86_emit_scalar_filter_membership(assembler, column, plan.adaptive_scalar_reject)?;
    }
    assembler.branch(&[0xe9], plan.apply)?;
    assembler.bind(plan.adaptive_scalar_reject)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], plan.joint_vector)?;
    Ok(())
}

fn x86_emit_prefix_predicate(
    assembler: &mut X86Assembler,
    predicate: NativePrefixPredicate,
    failed: X86Label,
) -> Result<(), ObjectError> {
    match predicate.membership {
        ScalarPrefixMembership::RejectAll => assembler.branch(&[0xe9], failed)?,
        ScalarPrefixMembership::Bitmap256 => {
            // eax = haystack[position + anchored offset]
            assembler.instruction(&[0x0f, 0xb6, 0x44, 0x17, predicate.position])?;
            // CF = bitmap[eax]. `btq` treats memory as a bit string, so the
            // byte value directly selects one of the membership bits.
            let mut test = vec![0x49, 0x0f, 0xa3, 0x81];
            test.extend_from_slice(&predicate.bitmap_offset.to_le_bytes());
            assembler.instruction(&test)?;
            assembler.branch(&[0x0f, 0x83], failed)?; // jnc
        }
        ScalarPrefixMembership::Ranges(ranges) => {
            x86_emit_prefix_ranges(assembler, predicate.position, ranges, failed)?;
        }
    }
    Ok(())
}

fn x86_emit_prefix_relation(
    assembler: &mut X86Assembler,
    relation: NativePrefixRelationFilter,
    failed: X86Label,
) -> Result<(), ObjectError> {
    // A little-endian halfword is exactly the matrix bit index
    // `first | (second << 8)`. `btq` treats the table as one contiguous bit
    // string, avoiding per-group dispatch on the candidate path.
    assembler.instruction(&[0x0f, 0xb7, 0x04, 0x17])?; // movzx eax, word [rdi+rdx]
    let mut test = vec![0x49, 0x0f, 0xa3, 0x81]; // btq rax, disp32[r9]
    test.extend_from_slice(&relation.bitmap_offset.to_le_bytes());
    assembler.instruction(&test)?;
    assembler.branch(&[0x0f, 0x83], failed)?; // jnc
    Ok(())
}

fn x86_emit_prefix_block(
    assembler: &mut X86Assembler,
    block: NativePrefixBlockGuard,
    kind: X86StartFilterKind,
    failed: X86Label,
) -> Result<(), ObjectError> {
    if block.lane_mask == 0
        || block.byte_mask_offset
            != block
                .expected_offset
                .checked_add(
                    u32::try_from(prefix_block::PREFIX_BLOCK_BYTES).map_err(|_| {
                        ObjectError::ArithmeticOverflow("x86 prefix-block constant width")
                    })?,
                )
                .ok_or(ObjectError::ArithmeticOverflow(
                    "x86 prefix-block mask offset",
                ))?
    {
        return Err(ObjectError::InvalidModule(
            "x86 prefix-block constants are malformed",
        ));
    }
    match kind {
        X86StartFilterKind::Sse2 => {
            assembler.instruction(&[0xf3, 0x0f, 0x6f, 0x04, 0x17])?; // movdqu xmm0, [rdi+rdx]
            let mut compare = vec![0x66, 0x41, 0x0f, 0x74, 0x81]; // pcmpeqb xmm0, [r9+disp32]
            compare.extend_from_slice(&block.expected_offset.to_le_bytes());
            assembler.instruction(&compare)?;
            assembler.instruction(&[0x66, 0x0f, 0xd7, 0xc0])?; // pmovmskb eax, xmm0
        }
        X86StartFilterKind::Avx2 | X86StartFilterKind::Avx512Bw => {
            // Keep the 128-bit block VEX-encoded when the surrounding scanner
            // uses wide registers, avoiding an AVX-to-legacy-SSE transition.
            assembler.instruction(&[0xc5, 0xfa, 0x6f, 0x04, 0x17])?; // vmovdqu xmm0, [rdi+rdx]
            let mut compare = vec![0xc4, 0xc1, 0x79, 0x74, 0x81]; // vpcmpeqb xmm0, xmm0, [r9+disp32]
            compare.extend_from_slice(&block.expected_offset.to_le_bytes());
            assembler.instruction(&compare)?;
            assembler.instruction(&[0xc5, 0xf9, 0xd7, 0xc0])?; // vpmovmskb eax, xmm0
        }
    }
    let lane_mask = u32::from(block.lane_mask);
    if block.lane_mask != u16::MAX {
        assembler.instruction(&[0x25, lane_mask as u8, (lane_mask >> 8) as u8, 0, 0])?; // and eax, lane mask
    }
    let mut compare_mask = vec![0x3d]; // cmp eax, lane mask
    compare_mask.extend_from_slice(&lane_mask.to_le_bytes());
    assembler.instruction(&compare_mask)?;
    assembler.branch(&[0x0f, 0x85], failed)?;
    Ok(())
}

fn x86_emit_prefix_guard_path(
    assembler: &mut X86Assembler,
    layout: NativeDfaLayout,
    kind: X86StartFilterKind,
    vector_coverage: Option<NativeVectorGuardCoverage>,
    predicate_failed: X86Label,
    terminal_bound_failed: X86Label,
    prefix_verified: X86Label,
) -> Result<(), ObjectError> {
    let guaranteed_bytes = layout.prefix_guaranteed_bytes()?;
    if vector_coverage.is_none_or(|coverage| coverage.guaranteed_bytes < guaranteed_bytes) {
        assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
        assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
        assembler.instruction(&[0x48, 0x83, 0xf8, guaranteed_bytes])?;
        assembler.branch(&[0x0f, 0x82], terminal_bound_failed)?;
    }
    if let Some(relation) = layout.prefix_relation
        && vector_coverage.is_none_or(|coverage| !coverage.relation)
    {
        x86_emit_prefix_relation(assembler, relation, predicate_failed)?;
    }
    let checked_block = layout.prefix_block.filter(|block| {
        vector_coverage.is_none_or(|coverage| block.lane_mask & !coverage.prefix_positions != 0)
    });
    if let Some(block) = checked_block {
        x86_emit_prefix_block(assembler, block, kind, predicate_failed)?;
    }
    if let Some(prefix) = layout.prefix_filter {
        for &predicate in prefix.predicates() {
            if checked_block.is_some_and(|block| block.covers_position(predicate.position)) {
                continue;
            }
            if vector_coverage.is_some_and(|coverage| coverage.covers_position(predicate.position))
            {
                continue;
            }
            x86_emit_prefix_predicate(assembler, predicate, predicate_failed)?;
        }
    }
    assembler.branch(&[0xe9], prefix_verified)?;
    Ok(())
}

fn x86_emit_prefix_ranges(
    assembler: &mut X86Assembler,
    position: u8,
    ranges: ScalarPrefixRangePlan,
    failed: X86Label,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x0f, 0xb6, 0x44, 0x17, position])?;
    let passed = assembler.label()?;
    for range in ranges.ranges() {
        assembler.instruction(&[0x3c, range.start()])?;
        if range.is_singleton() {
            assembler.branch(&[0x0f, 0x84], passed)?;
        } else {
            let next = assembler.label()?;
            assembler.branch(&[0x0f, 0x82], next)?;
            assembler.instruction(&[0x3c, range.end()])?;
            assembler.branch(&[0x0f, 0x86], passed)?;
            assembler.bind(next)?;
        }
    }
    assembler.branch(&[0xe9], failed)?;
    assembler.bind(passed)?;
    Ok(())
}

fn x86_emit_scalar_filter_membership(
    assembler: &mut X86Assembler,
    filter: NativeStartFilter,
    failed: X86Label,
) -> Result<(), ObjectError> {
    if filter.ranges().is_empty() {
        return Err(ObjectError::InvalidModule(
            "x86 scalar membership has no candidates",
        ));
    }
    x86_emit_start_filter_scalar_load(assembler, filter.scan_offset)?;
    let passed = assembler.label()?;
    for range in filter.ranges() {
        assembler.instruction(&[0x3c, range.start])?;
        if range.start == range.end {
            assembler.branch(&[0x0f, 0x84], passed)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch(&[0x0f, 0x82], next_range)?;
            assembler.instruction(&[0x3c, range.end])?;
            assembler.branch(&[0x0f, 0x86], passed)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.branch(&[0xe9], failed)?;
    assembler.bind(passed)?;
    Ok(())
}

/// Return an exact anchored-product match at the original window start before
/// a large-window suffix prepass. The normal prefix guard omits the column
/// already validated by the moving start scanner; this entry probe has not run
/// that scanner, so it must test that primary column explicitly.
#[allow(
    clippy::large_types_passed_by_value,
    reason = "the probe consumes the same copyable layout value as the surrounding lowering"
)]
fn x86_emit_exact_start_probe(
    assembler: &mut X86Assembler,
    layout: NativeDfaLayout,
    kind: X86StartFilterKind,
    failed: X86Label,
    matched: X86Label,
) -> Result<(), ObjectError> {
    let width = layout
        .exact_prefix_match_width
        .ok_or(ObjectError::InvalidModule(
            "x86 exact-start width is absent",
        ))?;
    let primary = layout.start_filter.ok_or(ObjectError::InvalidModule(
        "x86 exact-start probe has no primary",
    ))?;
    if primary.scan_offset >= width {
        return Err(ObjectError::InvalidModule(
            "x86 exact-start primary is outside its product",
        ));
    }
    if layout
        .prefix_filter
        .is_some_and(|prefix| prefix.guaranteed_bytes != width)
    {
        return Err(ObjectError::InvalidModule(
            "x86 exact-start width disagrees with prefix guard",
        ));
    }

    assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= original start
    let mut large_window = vec![0x48, 0x3d];
    large_window.extend_from_slice(&u32::from(SUFFIX_PREFILTER_MIN_WINDOW_BYTES).to_le_bytes());
    assembler.instruction(&large_window)?;
    assembler.branch(&[0x0f, 0x82], failed)?;
    assembler.instruction(&[0x48, 0x83, 0xf8, width])?;
    assembler.branch(&[0x0f, 0x82], failed)?;
    if let Some(block) = layout.prefix_block {
        x86_emit_prefix_block(assembler, block, kind, failed)?;
    }
    if layout
        .prefix_block
        .is_none_or(|block| !block.covers_position(primary.scan_offset))
    {
        x86_emit_scalar_filter_membership(assembler, primary, failed)?;
    }
    if let Some(prefix) = layout.prefix_filter {
        for &predicate in prefix.predicates() {
            if layout
                .prefix_block
                .is_some_and(|block| block.covers_position(predicate.position))
            {
                continue;
            }
            x86_emit_prefix_predicate(assembler, predicate, failed)?;
        }
    }
    x86_emit_exact_prefix_match(assembler, width, layout.output, matched)
}

fn x86_emit_start_filter_range_vector_test(
    assembler: &mut X86Assembler,
    filter: NativeStartFilter,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    if kind != X86StartFilterKind::Avx512Bw {
        return Err(ObjectError::InvalidModule(
            "non-AVX-512 filter reached opmask range test",
        ));
    }
    x86_emit_range_start_filter_vector_candidates(assembler, filter, kind, 1)?;
    x86_emit_candidate_nonzero(assembler, X86CandidateMask::Avx512K4)
}

#[allow(
    clippy::large_types_passed_by_value,
    clippy::too_many_lines,
    reason = "the specialized forward/reverse control-flow graph is kept contiguous for auditing"
)]
fn lower_x86_64_dfa(
    layout: NativeDfaLayout,
    features: FeatureSet,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = X86Assembler::new();
    let scan = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let scalar_transition = assembler.label()?;
    let exceptional_transition = assembler.label()?;
    let accelerated_transition = assembler.label()?;
    let prefix_check = assembler.label()?;
    let prefix_vector_check = assembler.label()?;
    let prefix_verified = assembler.label()?;
    let prefix_apply = assembler.label()?;
    let prefix_fail = assembler.label()?;
    let prefix_retained_fail = assembler.label()?;
    let prefix_terminal = assembler.label()?;
    let filter_vector = assembler.label()?;
    let filter_single_vector = assembler.label()?;
    let filter_scalar = assembler.label()?;
    let filter_scalar_columns = assembler.label()?;
    let filter_scalar_reject = assembler.label()?;
    let filter_vector_primary_hit = assembler.label()?;
    let filter_vector_hit = assembler.label()?;
    let filter_sparse_batch_hit = assembler.label()?;
    let filter_retained_exhausted = assembler.label()?;
    let accept = assembler.label()?;
    let after_accept = assembler.label()?;
    let finish = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid = assembler.label()?;
    let done = assembler.label()?;
    let reverse_loop = assembler.label()?;
    let reverse_exceptional_transition = assembler.label()?;
    let record_reverse_start = assembler.label()?;
    let reverse_continue = assembler.label()?;
    let reverse_finish = assembler.label()?;
    let exact_start_probe_failed = assembler.label()?;

    let instruction_filter = layout
        .start_filter
        .filter(|filter| !filter.ranges().is_empty())
        .or_else(|| {
            layout
                .suffix_filter
                .map(|suffix| suffix.filter)
                .filter(|filter| !filter.ranges().is_empty())
        })
        .or_else(|| layout.loop_skip.map(|skip| skip.filter));
    let filter_kind = instruction_filter.map(|_| x86_start_filter_kind(features));
    let prefix_relation_vector = layout
        .prefix_relation
        .and_then(|relation| relation.vector_plan);
    // This exact mask subsumes independent columns zero and one. Keeping their
    // Cartesian SIMD conjunction would recreate precisely the false lanes the
    // relation proves impossible.
    let vector_filter = if prefix_relation_vector.is_some() {
        None
    } else {
        filter_kind.and(layout.vector_filter)
    };
    let candidate = if layout.has_prefix_guard() {
        prefix_check
    } else if layout.prefix_fast_forward.is_some() {
        prefix_apply
    } else {
        scalar_scan
    };
    let vector_coverage = derive_native_vector_guard_coverage(
        layout,
        prefix_relation_vector.is_some(),
        vector_filter,
    );
    let retain_vector_candidates = vector_coverage
        .map(|coverage| coverage.has_rejectable_residual(layout))
        .transpose()?
        .unwrap_or(false);
    let use_sparse_start_batch = !retain_vector_candidates
        && prefix_relation_vector.is_none()
        && layout.start_filter.is_some_and(|filter| {
            filter_kind.is_some_and(|kind| x86_use_sparse_filter_mask_batch(filter, kind))
        });

    let uses_seeded_reverse = layout.seeded_reverse.is_some();
    if retain_vector_candidates || uses_seeded_reverse {
        // R12/R13 are callee-saved under both supported x86-64 ABIs. Every
        // status exit converges on `done`, which restores them in reverse.
        assembler.instruction(&[0x41, 0x54])?; // push r12
        assembler.instruction(&[0x41, 0x55])?; // push r13
    }
    if uses_seeded_reverse {
        assembler.instruction(&[0x41, 0x56])?; // push r14
        assembler.instruction(&[0x41, 0x57])?; // push r15
    }

    // Validate start <= end <= length before touching result memory.
    assembler.instruction(&[0x48, 0x85, 0xf6])?; // test length sign bit
    assembler.branch(&[0x0f, 0x88], invalid)?;
    assembler.instruction(&[0x48, 0x39, 0xf1])?; // cmp rcx, rsi
    assembler.branch(&[0x0f, 0x87], invalid)?; // ja
    assembler.instruction(&[0x48, 0x39, 0xca])?; // cmp rdx, rcx
    assembler.branch(&[0x0f, 0x87], invalid)?;
    assembler.instruction(&[0x4d, 0x85, 0xc0])?; // test r8, r8
    assembler.branch(&[0x0f, 0x84], invalid)?;
    assembler.instruction(&[0x41, 0xf6, 0xc0, 0x07])?; // test result alignment
    assembler.branch(&[0x0f, 0x85], invalid)?;
    assembler.instruction(&[0x48, 0x85, 0xff])?; // test rdi, rdi
    assembler.branch(&[0x0f, 0x84], invalid)?;
    assembler.instruction(&[0x48, 0x89, 0xd6])?; // mov rsi, rdx (window start)
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;

    // lea table(%rip), r9
    assembler.instruction(&[0x4c, 0x8d, 0x0d])?;
    let table_displacement = assembler.code.len();
    push_bytes(&mut assembler.code, &[0; 4])?;
    if layout.suffix_filter.is_some() && layout.exact_prefix_match_width.is_some() {
        let kind = filter_kind.ok_or(ObjectError::InvalidModule(
            "x86 exact-start prefix block has no instruction selection",
        ))?;
        x86_emit_exact_start_probe(
            &mut assembler,
            layout,
            kind,
            exact_start_probe_failed,
            matched,
        )?;
        assembler.bind(exact_start_probe_failed)?;
    }
    let adaptive_suffix_cold = if let Some(suffix) = layout.suffix_filter {
        let kind = filter_kind.ok_or(ObjectError::InvalidModule(
            "x86 suffix filter has no instruction selection",
        ))?;
        x86_emit_suffix_prepass(&mut assembler, suffix, kind, layout, no_match, matched)?
    } else {
        None
    };
    if layout.output != OutputContract::Exists {
        assembler.instruction(&[0x49, 0xc7, 0xc3, 0xff, 0xff, 0xff, 0xff])?; // r11 = none
    }
    x86_set_row(&mut assembler, layout.forward_offset)?;
    if let (Some(filter), Some(kind)) = (layout.start_filter, filter_kind) {
        if let Some(plan) = prefix_relation_vector {
            x86_emit_prefix_relation_constants(&mut assembler, plan, kind)?;
        } else if let Some(vector_filter) = vector_filter {
            let mut first_register = 1_u8;
            for &column in vector_filter.columns() {
                x86_emit_start_filter_constants(&mut assembler, column, kind, first_register)?;
                first_register = first_register
                    .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                        ObjectError::ArithmeticOverflow("x86 vector-filter constants")
                    })?)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "x86 vector-filter constants",
                    ))?;
            }
        } else {
            x86_emit_start_filter_constants(&mut assembler, filter, kind, 1)?;
        }
    }

    if layout.initial_pending {
        if layout.output == OutputContract::Exists {
            assembler.branch(&[0xe9], matched)?;
        } else {
            assembler.instruction(&[0x49, 0x89, 0xd3])?;
            if layout.initial_terminal {
                assembler.branch(&[0xe9], finish)?;
            }
        }
    }

    assembler.bind(scan)?;
    if let Some(filter) = layout.start_filter {
        // Start-state skipping is valid only while both pieces of semantic
        // state match their initial values: row zero and no pending accept.
        // Exists returns on the first accepting transition, so every scan it
        // can resume necessarily has no pending accept.
        if layout.output != OutputContract::Exists {
            assembler.instruction(&[0x49, 0x83, 0xfb, 0xff])?; // cmp r11, -1
            assembler.branch(&[0x0f, 0x85], scalar_scan)?;
        }
        let mut initial_row = vec![0x49, 0x8d, 0x81]; // lea offset(r9), rax
        initial_row.extend_from_slice(&layout.forward_offset.to_le_bytes());
        assembler.instruction(&initial_row)?;
        assembler.instruction(&[0x49, 0x39, 0xc2])?; // cmp r10, rax
        assembler.branch(&[0x0f, 0x85], scalar_scan)?;

        if filter.ranges().is_empty() {
            assembler.instruction(&[0x48, 0x89, 0xca])?; // position = end
            assembler.branch(&[0xe9], finish)?;
        } else {
            let kind = filter_kind.ok_or(ObjectError::InvalidModule(
                "x86 start filter has no instruction selection",
            ))?;
            let maximum_scan_offset = prefix_relation_vector.map_or_else(
                || vector_filter.map_or(filter.scan_offset, NativeVectorFilter::max_scan_offset),
                |_| 1,
            );
            let vector_candidate_hit = if vector_filter.is_some() {
                filter_vector_primary_hit
            } else {
                filter_vector_hit
            };
            assembler.bind(filter_vector)?;
            assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
            assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
            let unrolled_bytes = u32::from(kind.width())
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(u32::from(maximum_scan_offset)))
                .ok_or(ObjectError::ArithmeticOverflow(
                    "x86 unrolled start-filter width",
                ))?;
            let mut compare_unrolled = vec![0x48, 0x3d]; // cmp rax, imm32
            compare_unrolled.extend_from_slice(&unrolled_bytes.to_le_bytes());
            assembler.instruction(&compare_unrolled)?;
            assembler.branch(&[0x0f, 0x82], filter_single_vector)?;
            if use_sparse_start_batch {
                x86_emit_sparse_filter_mask_batch(&mut assembler, filter, kind)?;
                assembler.branch(&[0x0f, 0x85], filter_sparse_batch_hit)?;
            } else {
                for _ in 0..X86_MASK_BATCH_VECTORS {
                    if let Some(plan) = prefix_relation_vector {
                        x86_emit_prefix_relation_vector_test(&mut assembler, plan, kind)?;
                        assembler.branch(&[0x0f, 0x85], vector_candidate_hit)?;
                    } else {
                        x86_emit_start_filter_vector_candidate(
                            &mut assembler,
                            filter,
                            kind,
                            vector_candidate_hit,
                        )?;
                    }
                    assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
                }
            }
            assembler.branch(&[0xe9], filter_vector)?;

            assembler.bind(filter_sparse_batch_hit)?;
            x86_emit_rewind_sparse_filter_mask_batch(&mut assembler, kind)?;
            assembler.branch(&[0xe9], filter_scalar)?;

            assembler.bind(filter_single_vector)?;
            let single_vector_bytes = kind.width().checked_add(maximum_scan_offset).ok_or(
                ObjectError::ArithmeticOverflow("x86 start-filter vector width"),
            )?;
            assembler.instruction(&[0x48, 0x83, 0xf8, single_vector_bytes])?;
            assembler.branch(&[0x0f, 0x82], filter_scalar)?; // remaining < width
            if let Some(plan) = prefix_relation_vector {
                x86_emit_prefix_relation_vector_test(&mut assembler, plan, kind)?;
                assembler.branch(&[0x0f, 0x85], vector_candidate_hit)?;
            } else {
                x86_emit_start_filter_vector_candidate(
                    &mut assembler,
                    filter,
                    kind,
                    vector_candidate_hit,
                )?;
            }
            assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
            assembler.branch(&[0xe9], filter_vector)?;

            // Every instruction selection uses the scalar loop only for the
            // sub-vector tail; full AVX-512 blocks retain their exact mask.
            assembler.bind(filter_scalar)?;
            x86_emit_start_filter_scalar_bound(&mut assembler, maximum_scan_offset, finish)?;
            x86_emit_start_filter_scalar_load(&mut assembler, filter.scan_offset)?;
            let scalar_candidate = if vector_filter.is_some() {
                filter_scalar_columns
            } else {
                candidate
            };
            for range in filter.ranges() {
                assembler.instruction(&[0x3c, range.start])?;
                if range.start == range.end {
                    assembler.branch(&[0x0f, 0x84], scalar_candidate)?;
                } else {
                    let next_range = assembler.label()?;
                    assembler.branch(&[0x0f, 0x82], next_range)?;
                    assembler.instruction(&[0x3c, range.end])?;
                    assembler.branch(&[0x0f, 0x86], scalar_candidate)?;
                    assembler.bind(next_range)?;
                }
            }
            assembler.instruction(&[0x48, 0xff, 0xc2])?;
            assembler.branch(&[0xe9], filter_scalar)?;

            if let Some(vector_filter) = vector_filter {
                assembler.bind(filter_scalar_columns)?;
                for &column in &vector_filter.columns()[1..] {
                    x86_emit_scalar_filter_membership(
                        &mut assembler,
                        column,
                        filter_scalar_reject,
                    )?;
                }
                assembler.branch(&[0xe9], candidate)?;
                assembler.bind(filter_scalar_reject)?;
                assembler.instruction(&[0x48, 0xff, 0xc2])?;
                assembler.branch(&[0xe9], filter_scalar)?;

                assembler.bind(filter_vector_primary_hit)?;
                // Preserve the primary candidate vector across the hot-path
                // branch and pay for secondary loads only after that primary
                // vector actually hits. A false intersection skips the whole
                // block, avoiding repeated scalar/prefix refinement.
                x86_emit_vector_filter_secondary_test(&mut assembler, vector_filter, kind)?;
                assembler.branch(&[0x0f, 0x85], filter_vector_hit)?;
                assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
                assembler.branch(&[0xe9], filter_vector)?;
            }

            assembler.bind(filter_vector_hit)?;
            // The vector branch preserved the exact lane mask and base
            // position for this block. Select its first lane without scalar
            // rescanning, including AVX-512 lanes 32..63.
            let vector_hit_mask = if prefix_relation_vector.is_some() || vector_filter.is_some() {
                X86CandidateMask::for_intersection(kind)
            } else {
                X86CandidateMask::for_filter(filter, kind)
            };
            if retain_vector_candidates {
                x86_emit_retain_candidate_mask(&mut assembler, vector_hit_mask)?;
                x86_emit_first_retained_candidate(&mut assembler)?;
            } else {
                x86_emit_first_candidate_lane(&mut assembler, vector_hit_mask)?;
                assembler.instruction(&[0x48, 0x01, 0xc2])?; // position += first lane
            }
            assembler.branch(
                &[0xe9],
                if vector_coverage.is_some() {
                    prefix_vector_check
                } else {
                    candidate
                },
            )?;
        }
    }

    if layout.has_prefix_guard() {
        let kind = filter_kind.ok_or(ObjectError::InvalidModule(
            "x86 prefix guard has no instruction selection",
        ))?;
        assembler.bind(prefix_check)?;
        x86_emit_prefix_guard_path(
            &mut assembler,
            layout,
            kind,
            None,
            prefix_fail,
            prefix_terminal,
            prefix_verified,
        )?;
        assembler.bind(prefix_fail)?;
        // A rejected anchored start says nothing about the immediately
        // following start. Advance exactly one byte and rescan from the
        // untouched initial DFA state.
        assembler.instruction(&[0x48, 0xff, 0xc2])?;
        x86_set_row(&mut assembler, layout.forward_offset)?;
        assembler.branch(&[0xe9], scan)?;

        if let Some(coverage) = vector_coverage {
            assembler.bind(prefix_vector_check)?;
            x86_emit_prefix_guard_path(
                &mut assembler,
                layout,
                kind,
                Some(coverage),
                if retain_vector_candidates {
                    prefix_retained_fail
                } else {
                    prefix_fail
                },
                prefix_terminal,
                prefix_verified,
            )?;
        }
        if retain_vector_candidates {
            assembler.bind(prefix_retained_fail)?;
            x86_emit_clear_first_retained_candidate(&mut assembler)?;
            assembler.branch(&[0x0f, 0x84], filter_retained_exhausted)?;
            x86_emit_first_retained_candidate(&mut assembler)?;
            x86_set_row(&mut assembler, layout.forward_offset)?;
            assembler.branch(&[0xe9], prefix_vector_check)?;

            assembler.bind(filter_retained_exhausted)?;
            let kind = filter_kind.ok_or(ObjectError::InvalidModule(
                "x86 retained mask has no instruction selection",
            ))?;
            x86_emit_advance_retained_block(&mut assembler, kind.width())?;
            x86_set_row(&mut assembler, layout.forward_offset)?;
            assembler.branch(&[0xe9], filter_vector)?;
        }

        assembler.bind(prefix_terminal)?;
        assembler.branch(&[0xe9], finish)?;

        assembler.bind(prefix_verified)?;
        if let Some(width) = layout.exact_prefix_match_width {
            x86_emit_exact_prefix_match(&mut assembler, width, layout.output, matched)?;
        } else {
            assembler.branch(&[0xe9], prefix_apply)?;
        }
    }

    assembler.bind(prefix_apply)?;
    x86_set_row(&mut assembler, layout.forward_offset)?;
    if let Some(plan) = layout.prefix_fast_forward {
        assembler.instruction(&[0x48, 0x83, 0xc2, plan.consumed_bytes])?;
        x86_set_row(&mut assembler, plan.target_row_offset)?;
    }
    assembler.bind(scalar_scan)?;
    if let Some(plan) = layout.loop_skip {
        let kind = filter_kind.ok_or(ObjectError::InvalidModule(
            "x86 loop skip has no instruction selection",
        ))?;
        module_dfa_loop_skip::x86_emit_dfa_loop_skip(
            &mut assembler,
            plan,
            &layout,
            vector_filter,
            kind,
            scalar_transition,
            finish,
        )?;
    }
    assembler.bind(scalar_transition)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?;
    assembler.branch(&[0x0f, 0x83], finish)?; // position >= end
    x86_emit_table_lookup(&mut assembler, layout.transitions)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?; // position += 1
    x86_emit_ordinary_live_row(&mut assembler, exceptional_transition)?;
    // The overwhelmingly common live edge resumes table execution directly.
    assembler.branch(&[0xe9], scalar_transition)?;

    assembler.bind(exceptional_transition)?;
    assembler.instruction(&[0xff, 0xc0])?; // restore the packed cell in eax
    assembler.instruction(&[0xa9, 0x00, 0x00, 0x00, 0x80])?;
    assembler.branch(&[0x0f, 0x88], accept)?;
    assembler.bind(after_accept)?;
    assembler.instruction(&[0xa9, 0x00, 0x00, 0x00, 0x40])?;
    assembler.branch(&[0x0f, 0x85], accelerated_transition)?;
    assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x3f])?;
    assembler.branch(&[0x0f, 0x84], finish)?;
    assembler.instruction(&[0x4d, 0x8d, 0x54, 0x01, 0xff])?;
    assembler.branch(&[0xe9], scalar_transition)?;

    assembler.bind(accelerated_transition)?;
    assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x3f])?;
    assembler.branch(&[0x0f, 0x84], finish)?;
    assembler.instruction(&[0x4d, 0x8d, 0x54, 0x01, 0xff])?;
    // `scan` selects the initial scanner when its semantic preconditions hold,
    // then falls through the selected interior-loop row guard otherwise.
    assembler.branch(&[0xe9], scan)?;

    assembler.bind(accept)?;
    if layout.output == OutputContract::Exists {
        assembler.branch(&[0xe9], matched)?;
    } else {
        assembler.instruction(&[0x49, 0x89, 0xd3])?;
        assembler.branch(&[0xe9], after_accept)?;
    }

    assembler.bind(finish)?;
    if layout.output == OutputContract::Exists {
        // All accepting paths have already returned directly through
        // `matched`; reaching the ordinary exit proves no match.
        assembler.branch(&[0xe9], no_match)?;
    } else {
        assembler.instruction(&[0x49, 0x83, 0xfb, 0xff])?;
        assembler.branch(&[0x0f, 0x84], no_match)?;
    }
    if layout.output == OutputContract::Span && !layout.initial_pending {
        if layout.exact_span_width.is_none() && !layout.has_reverse {
            return Err(ObjectError::InvalidModule(
                "native span lowering has no reverse table",
            ));
        }
    } else {
        if layout.output == OutputContract::Span {
            assembler.instruction(&[0x49, 0x89, 0x30])?; // result.start = window_start
            assembler.instruction(&[0x4d, 0x89, 0x58, 0x08])?;
        } else if layout.output == OutputContract::SelectedEnd {
            assembler.instruction(&[0x4d, 0x89, 0x18])?; // result.start = selected end
            assembler.instruction(&[0x4d, 0x89, 0x58, 0x08])?;
        }
        assembler.branch(&[0xe9], matched)?;
    }

    if layout.output == OutputContract::Span && !layout.initial_pending {
        assembler.instruction(&[0x4d, 0x89, 0x58, 0x08])?; // preserve selected end
        if let Some(width) = layout.exact_span_width {
            if layout.has_reverse {
                return Err(ObjectError::InvalidModule(
                    "fixed-width native span unexpectedly retained a reverse table",
                ));
            }
            x86_emit_exact_span_start(&mut assembler, width)?;
            assembler.instruction(&[0x49, 0x89, 0x00])?; // result.start = selected end - width
            assembler.branch(&[0xe9], matched)?;
        } else {
            assembler.instruction(&[0x4c, 0x89, 0xda])?; // cursor = selected end
            assembler.instruction(&[0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff])?; // no candidate
            x86_set_row(&mut assembler, layout.reverse_offset)?;
            assembler.bind(reverse_loop)?;
            assembler.instruction(&[0x48, 0x39, 0xf2])?;
            assembler.branch(&[0x0f, 0x86], reverse_finish)?; // cursor <= window_start
            assembler.instruction(&[0x48, 0xff, 0xca])?;
            x86_emit_table_lookup(&mut assembler, layout.transitions)?;
            x86_emit_ordinary_live_row(&mut assembler, reverse_exceptional_transition)?;
            assembler.branch(&[0xe9], reverse_loop)?;

            assembler.bind(reverse_exceptional_transition)?;
            assembler.instruction(&[0xff, 0xc0])?; // restore the packed cell in eax
            assembler.instruction(&[0xa9, 0x00, 0x00, 0x00, 0x80])?;
            assembler.branch(&[0x0f, 0x88], record_reverse_start)?;
            assembler.bind(reverse_continue)?;
            // Reverse cells never set acceleration, but their canonical
            // absolute-row payload still occupies only the low 30 bits.
            assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x3f])?;
            assembler.branch(&[0x0f, 0x84], reverse_finish)?;
            assembler.instruction(&[0x4d, 0x8d, 0x54, 0x01, 0xff])?;
            assembler.branch(&[0xe9], reverse_loop)?;

            assembler.bind(record_reverse_start)?;
            assembler.instruction(&[0x48, 0x89, 0xd1])?;
            assembler.branch(&[0xe9], reverse_continue)?;

            assembler.bind(reverse_finish)?;
            assembler.instruction(&[0x48, 0x83, 0xf9, 0xff])?;
            assembler.branch(&[0x0f, 0x84], invalid)?;
            assembler.instruction(&[0x49, 0x89, 0x08])?;
            assembler.branch(&[0xe9], matched)?;
        }
    }

    assembler.bind(no_match)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.branch(&[0xe9], done)?;
    assembler.bind(matched)?;
    assembler.instruction(&[0xb8, 0x01, 0x00, 0x00, 0x00])?;
    assembler.branch(&[0xe9], done)?;
    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 0x02, 0x00, 0x00, 0x00])?;
    assembler.bind(done)?;
    if uses_seeded_reverse {
        assembler.instruction(&[0x41, 0x5f])?; // pop r15
        assembler.instruction(&[0x41, 0x5e])?; // pop r14
    }
    if retain_vector_candidates || uses_seeded_reverse {
        assembler.instruction(&[0x41, 0x5d])?; // pop r13
        assembler.instruction(&[0x41, 0x5c])?; // pop r12
    }
    if filter_kind.is_some_and(X86StartFilterKind::needs_vzeroupper) {
        assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    }
    assembler.instruction(&[0xc3])?;
    if let Some(plan) = adaptive_suffix_cold {
        let cold_start = assembler.code.len();
        x86_emit_adaptive_suffix_cold(&mut assembler, plan)?;
        let cold_bytes =
            assembler
                .code
                .len()
                .checked_sub(cold_start)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "x86 adaptive suffix cold size",
                ))?;
        let aligned_cold_bytes = cold_bytes
            .checked_add(X86_COLD_LINK_ALIGNMENT_BYTES - 1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "x86 adaptive suffix cold alignment",
            ))?
            & !(X86_COLD_LINK_ALIGNMENT_BYTES - 1);
        let padding =
            aligned_cold_bytes
                .checked_sub(cold_bytes)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "x86 adaptive suffix cold padding",
                ))?;
        x86_emit_unreachable_nops(&mut assembler, padding)?;
    }

    let code = assembler.finish()?;
    Ok((
        code,
        vec![ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(table_displacement, "x86 DFA table relocation offset")?,
            kind: RelocationKind::X86PcRelative32,
            symbol: PROGRAM_SYMBOL,
            addend: -4,
        }],
    ))
}

fn lower_x86_64_runtime_adapter() -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = X86Assembler::new();
    let invalid = assembler.label()?;

    assembler.instruction(&[0x48, 0x85, 0xf6])?;
    assembler.branch(&[0x0f, 0x88], invalid)?;
    assembler.instruction(&[0x48, 0x39, 0xf1])?;
    assembler.branch(&[0x0f, 0x87], invalid)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?;
    assembler.branch(&[0x0f, 0x87], invalid)?;
    assembler.instruction(&[0x4d, 0x85, 0xc0])?;
    assembler.branch(&[0x0f, 0x84], invalid)?;
    assembler.instruction(&[0x41, 0xf6, 0xc0, 0x07])?;
    assembler.branch(&[0x0f, 0x85], invalid)?;
    assembler.instruction(&[0x48, 0x85, 0xff])?;
    assembler.branch(&[0x0f, 0x84], invalid)?;

    // Shift five public arguments right by one register:
    // r8 -> r9, rcx -> r8, rdx -> rcx, rsi -> rdx, rdi -> rsi.
    assembler.instruction(&[0x4d, 0x89, 0xc1])?;
    assembler.instruction(&[0x49, 0x89, 0xc8])?;
    assembler.instruction(&[0x48, 0x89, 0xd1])?;
    assembler.instruction(&[0x48, 0x89, 0xf2])?;
    assembler.instruction(&[0x48, 0x89, 0xfe])?;

    // lea program(%rip), %rdi
    assembler.instruction(&[0x48, 0x8d, 0x3d])?;
    let program_displacement = assembler.code.len();
    push_bytes(&mut assembler.code, &[0; 4])?;

    // jmp runtime@PLT -- a tail call preserves the caller's return address.
    assembler.instruction(&[0xe9])?;
    let runtime_displacement = assembler.code.len();
    push_bytes(&mut assembler.code, &[0; 4])?;

    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 0x02, 0, 0, 0])?;
    assembler.instruction(&[0xc3])?;
    let code = assembler.finish()?;

    Ok((
        code,
        vec![
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(program_displacement, "x86 program relocation offset")?,
                kind: RelocationKind::X86PcRelative32,
                symbol: PROGRAM_SYMBOL,
                // ELF PC32 defines P as the relocation field address, while
                // the ISA displacement is relative to the end of that field.
                addend: -4,
            },
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(runtime_displacement, "x86 runtime relocation offset")?,
                kind: RelocationKind::X86PltRelative32,
                symbol: RUNTIME_SYMBOL,
                addend: -4,
            },
        ],
    ))
}

type Aarch64Label = usize;

#[derive(Clone, Copy, Debug)]
enum Aarch64FixupKind {
    Branch26,
    Conditional19,
    CompareBranch19,
    TestBit14,
}

#[derive(Clone, Copy, Debug)]
struct Aarch64Fixup {
    instruction: usize,
    label: Aarch64Label,
    kind: Aarch64FixupKind,
}

struct Aarch64Assembler {
    code: Vec<u8>,
    labels: Vec<Option<usize>>,
    fixups: Vec<Aarch64Fixup>,
}

impl Aarch64Assembler {
    fn new() -> Self {
        Self {
            code: Vec::with_capacity(256),
            labels: Vec::new(),
            fixups: Vec::new(),
        }
    }

    fn label(&mut self) -> Result<Aarch64Label, ObjectError> {
        let label = self.labels.len();
        self.labels
            .try_reserve(1)
            .map_err(|_| ObjectError::InvalidModule("AArch64 label allocation failed"))?;
        self.labels.push(None);
        Ok(label)
    }

    fn bind(&mut self, label: Aarch64Label) -> Result<(), ObjectError> {
        let slot = self
            .labels
            .get_mut(label)
            .ok_or(ObjectError::InvalidModule("AArch64 label index"))?;
        if slot.is_some() {
            return Err(ObjectError::InvalidModule("AArch64 label bound twice"));
        }
        *slot = Some(self.code.len());
        Ok(())
    }

    fn instruction(&mut self, instruction: u32) -> Result<usize, ObjectError> {
        let offset = self.code.len();
        aarch64_instruction(&mut self.code, instruction)?;
        Ok(offset)
    }

    fn branch(&mut self, label: Aarch64Label) -> Result<(), ObjectError> {
        self.branch_placeholder(0x1400_0000, label, Aarch64FixupKind::Branch26)
    }

    fn branch_cond(&mut self, condition: u8, label: Aarch64Label) -> Result<(), ObjectError> {
        if condition > 0x0f {
            return Err(ObjectError::InvalidModule(
                "AArch64 condition code is invalid",
            ));
        }
        self.branch_placeholder(
            0x5400_0000 | u32::from(condition),
            label,
            Aarch64FixupKind::Conditional19,
        )
    }

    fn branch_zero_w(&mut self, register: u8, label: Aarch64Label) -> Result<(), ObjectError> {
        self.branch_placeholder(
            0x3400_0000 | aarch64_reg(register, 0)?,
            label,
            Aarch64FixupKind::CompareBranch19,
        )
    }

    fn branch_nonzero_w(&mut self, register: u8, label: Aarch64Label) -> Result<(), ObjectError> {
        self.branch_placeholder(
            0x3500_0000 | aarch64_reg(register, 0)?,
            label,
            Aarch64FixupKind::CompareBranch19,
        )
    }

    fn branch_bit_set_w(
        &mut self,
        register: u8,
        bit: u8,
        label: Aarch64Label,
    ) -> Result<(), ObjectError> {
        if bit > 31 {
            return Err(ObjectError::InvalidModule(
                "AArch64 W-register test bit is invalid",
            ));
        }
        self.branch_placeholder(
            0x3700_0000 | (u32::from(bit) << 19) | aarch64_reg(register, 0)?,
            label,
            Aarch64FixupKind::TestBit14,
        )
    }

    fn branch_bit_clear_w(
        &mut self,
        register: u8,
        bit: u8,
        label: Aarch64Label,
    ) -> Result<(), ObjectError> {
        if bit > 31 {
            return Err(ObjectError::InvalidModule(
                "AArch64 W-register test bit is invalid",
            ));
        }
        self.branch_placeholder(
            0x3600_0000 | (u32::from(bit) << 19) | aarch64_reg(register, 0)?,
            label,
            Aarch64FixupKind::TestBit14,
        )
    }

    fn branch_placeholder(
        &mut self,
        instruction: u32,
        label: Aarch64Label,
        kind: Aarch64FixupKind,
    ) -> Result<(), ObjectError> {
        let offset = self.instruction(instruction)?;
        self.fixups
            .try_reserve(1)
            .map_err(|_| ObjectError::InvalidModule("AArch64 fixup allocation failed"))?;
        self.fixups.push(Aarch64Fixup {
            instruction: offset,
            label,
            kind,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, ObjectError> {
        if !self.code.len().is_multiple_of(4) {
            return Err(ObjectError::InvalidModule(
                "AArch64 code is not instruction aligned",
            ));
        }
        for fixup in &self.fixups {
            let target = self
                .labels
                .get(fixup.label)
                .copied()
                .flatten()
                .ok_or(ObjectError::InvalidModule("unbound AArch64 branch label"))?;
            if !target.is_multiple_of(4) || target > self.code.len() {
                return Err(ObjectError::InvalidModule(
                    "AArch64 branch target is not an instruction boundary",
                ));
            }
            let target = i64::try_from(target)
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 branch target"))?;
            let source = i64::try_from(fixup.instruction)
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 branch source"))?;
            let delta = target
                .checked_sub(source)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 branch displacement",
                ))?;
            if delta % 4 != 0 {
                return Err(ObjectError::InvalidModule(
                    "AArch64 branch displacement is unaligned",
                ));
            }
            let words = delta / 4;
            let (bits, shift, opcode_mask) = match fixup.kind {
                Aarch64FixupKind::Branch26 => (26_u8, 0_u8, 0xfc00_0000_u32),
                Aarch64FixupKind::Conditional19 => (19, 5, 0xff00_001f),
                Aarch64FixupKind::CompareBranch19 => (19, 5, 0xff00_001f),
                Aarch64FixupKind::TestBit14 => (14, 5, 0xfff8_001f),
            };
            let sign_bit = bits
                .checked_sub(1)
                .ok_or(ObjectError::InvalidModule("AArch64 branch bit width"))?;
            let magnitude = 1_i64
                .checked_shl(u32::from(sign_bit))
                .ok_or(ObjectError::ArithmeticOverflow("AArch64 branch range"))?;
            let minimum = magnitude
                .checked_neg()
                .ok_or(ObjectError::ArithmeticOverflow("AArch64 branch minimum"))?;
            let maximum = magnitude
                .checked_sub(1)
                .ok_or(ObjectError::ArithmeticOverflow("AArch64 branch maximum"))?;
            if words < minimum || words > maximum {
                return Err(ObjectError::InvalidModule("AArch64 branch is out of range"));
            }
            let end = fixup
                .instruction
                .checked_add(4)
                .ok_or(ObjectError::ArithmeticOverflow("AArch64 fixup extent"))?;
            let encoded = self
                .code
                .get(fixup.instruction..end)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(u32::from_le_bytes)
                .ok_or(ObjectError::InvalidModule(
                    "AArch64 fixup outside native code",
                ))?;
            let immediate_mask = 1_u32
                .checked_shl(u32::from(bits))
                .and_then(|value| value.checked_sub(1))
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 branch immediate mask",
                ))?;
            let immediate = u32::try_from(words & i64::from(immediate_mask))
                .map_err(|_| ObjectError::InvalidModule("AArch64 branch encoding"))?;
            let patched = (encoded & opcode_mask) | (immediate << shift);
            self.code[fixup.instruction..end].copy_from_slice(&patched.to_le_bytes());
        }
        Ok(self.code)
    }
}

const AARCH64_EQ: u8 = 0;
const AARCH64_NE: u8 = 1;
const AARCH64_MI: u8 = 4;
const AARCH64_HI: u8 = 8;
const AARCH64_LS: u8 = 9;
const AARCH64_HS: u8 = 2;
const AARCH64_LO: u8 = 3;

fn aarch64_reg(register: u8, shift: u8) -> Result<u32, ObjectError> {
    if register > 31 || shift > 31 {
        return Err(ObjectError::InvalidModule("AArch64 register field"));
    }
    Ok(u32::from(register) << shift)
}

fn aarch64_mov_x(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0xaa00_03e0 | aarch64_reg(source, 16)? | aarch64_reg(destination, 0)?)
}

fn aarch64_cmp_x(left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(0xeb00_001f | aarch64_reg(right, 16)? | aarch64_reg(left, 5)?)
}

fn aarch64_cmp_w_zero(register: u8) -> Result<u32, ObjectError> {
    Ok(0x7100_001f | aarch64_reg(register, 5)?)
}

fn aarch64_cmp_w_imm(register: u8, immediate: u16) -> Result<u32, ObjectError> {
    if immediate > 0x0fff {
        return Err(ObjectError::InvalidModule("AArch64 CMP W immediate"));
    }
    Ok(0x7100_001f | (u32::from(immediate) << 10) | aarch64_reg(register, 5)?)
}

fn aarch64_cmp_x_imm(register: u8, immediate: u16) -> Result<u32, ObjectError> {
    if immediate > 0x0fff {
        return Err(ObjectError::InvalidModule("AArch64 CMP X immediate"));
    }
    Ok(0xf100_001f | (u32::from(immediate) << 10) | aarch64_reg(register, 5)?)
}

fn aarch64_csel_x(
    destination: u8,
    when_true: u8,
    when_false: u8,
    condition: u8,
) -> Result<u32, ObjectError> {
    if condition > 15 {
        return Err(ObjectError::InvalidModule("AArch64 CSEL condition"));
    }
    Ok(0x9a80_0000
        | aarch64_reg(when_false, 16)?
        | (u32::from(condition) << 12)
        | aarch64_reg(when_true, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_add_x_reg(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x8b00_0000
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_sub_x_reg(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0xcb00_0000
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_add_x_imm(destination: u8, source: u8, immediate: u16) -> Result<u32, ObjectError> {
    if immediate > 0x0fff {
        return Err(ObjectError::InvalidModule("AArch64 ADD immediate"));
    }
    Ok(0x9100_0000
        | (u32::from(immediate) << 10)
        | aarch64_reg(source, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_sub_x_imm(destination: u8, source: u8, immediate: u16) -> Result<u32, ObjectError> {
    if immediate > 0x0fff {
        return Err(ObjectError::InvalidModule("AArch64 SUB immediate"));
    }
    Ok(0xd100_0000
        | (u32::from(immediate) << 10)
        | aarch64_reg(source, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_sub_w_imm(destination: u8, source: u8, immediate: u16) -> Result<u32, ObjectError> {
    if immediate > 0x0fff {
        return Err(ObjectError::InvalidModule("AArch64 SUB immediate"));
    }
    Ok(0x5100_0000
        | (u32::from(immediate) << 10)
        | aarch64_reg(source, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_store_x(source: u8, base: u8, byte_offset: u16) -> Result<u32, ObjectError> {
    if !byte_offset.is_multiple_of(8) || byte_offset / 8 > 0x0fff {
        return Err(ObjectError::InvalidModule("AArch64 STR offset"));
    }
    Ok(0xf900_0000
        | (u32::from(byte_offset / 8) << 10)
        | aarch64_reg(base, 5)?
        | aarch64_reg(source, 0)?)
}

fn aarch64_load_byte_reg(destination: u8, base: u8, index: u8) -> Result<u32, ObjectError> {
    Ok(
        0x3860_6800
            | aarch64_reg(index, 16)?
            | aarch64_reg(base, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_load_halfword_reg(destination: u8, base: u8, index: u8) -> Result<u32, ObjectError> {
    Ok(
        0x7860_6800
            | aarch64_reg(index, 16)?
            | aarch64_reg(base, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_load_byte_imm(destination: u8, base: u8, byte_offset: u16) -> Result<u32, ObjectError> {
    if byte_offset > 0x0fff {
        return Err(ObjectError::InvalidModule("AArch64 LDRB offset"));
    }
    Ok(0x3940_0000
        | (u32::from(byte_offset) << 10)
        | aarch64_reg(base, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_lsr_x_imm(destination: u8, source: u8, shift: u8) -> Result<u32, ObjectError> {
    if shift > 63 {
        return Err(ObjectError::InvalidModule("AArch64 LSR immediate"));
    }
    Ok(0xd340_fc00
        | (u32::from(shift) << 16)
        | aarch64_reg(source, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_load_x_lsl3(destination: u8, base: u8, index: u8) -> Result<u32, ObjectError> {
    Ok(
        0xf860_7800
            | aarch64_reg(index, 16)?
            | aarch64_reg(base, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_lsrv_x(destination: u8, source: u8, shift: u8) -> Result<u32, ObjectError> {
    Ok(0x9ac0_2400
        | aarch64_reg(shift, 16)?
        | aarch64_reg(source, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_load_w_uxtw(destination: u8, base: u8, index: u8) -> Result<u32, ObjectError> {
    Ok(
        0xb860_5800
            | aarch64_reg(index, 16)?
            | aarch64_reg(base, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_emit_prefix_predicate(
    assembler: &mut Aarch64Assembler,
    predicate: NativePrefixPredicate,
    failed: Aarch64Label,
) -> Result<(), ObjectError> {
    match predicate.membership {
        ScalarPrefixMembership::RejectAll => assembler.branch(failed)?,
        ScalarPrefixMembership::Bitmap256 => {
            assembler.instruction(aarch64_add_x_reg(12, 0, 2)?)?;
            assembler.instruction(aarch64_load_byte_imm(8, 12, u16::from(predicate.position))?)?;
            assembler.instruction(aarch64_lsr_x_imm(10, 8, 6)?)?;
            aarch64_set_table_address(assembler, 12, predicate.bitmap_offset)?;
            assembler.instruction(aarch64_load_x_lsl3(10, 12, 10)?)?;
            assembler.instruction(aarch64_lsrv_x(10, 10, 8)?)?;
            assembler.instruction(aarch64_and_low_x(10, 10, 1)?)?;
            assembler.instruction(aarch64_cmp_w_zero(10)?)?;
            assembler.branch_cond(AARCH64_EQ, failed)?;
        }
        ScalarPrefixMembership::Ranges(ranges) => {
            aarch64_emit_prefix_ranges(assembler, predicate.position, ranges, failed)?;
        }
    }
    Ok(())
}

fn aarch64_emit_prefix_relation(
    assembler: &mut Aarch64Assembler,
    relation: NativePrefixRelationFilter,
    failed: Aarch64Label,
) -> Result<(), ObjectError> {
    // All supported AArch64 targets are little-endian, so the halfword is the
    // exact bit-matrix index `first | (second << 8)`.
    assembler.instruction(aarch64_load_halfword_reg(8, 0, 2)?)?;
    assembler.instruction(aarch64_lsr_x_imm(10, 8, 6)?)?;
    aarch64_set_table_address(assembler, 12, relation.bitmap_offset)?;
    assembler.instruction(aarch64_load_x_lsl3(10, 12, 10)?)?;
    assembler.instruction(aarch64_lsrv_x(10, 10, 8)?)?;
    assembler.instruction(aarch64_and_low_x(10, 10, 1)?)?;
    assembler.instruction(aarch64_cmp_w_zero(10)?)?;
    assembler.branch_cond(AARCH64_EQ, failed)?;
    Ok(())
}

fn aarch64_emit_prefix_block(
    assembler: &mut Aarch64Assembler,
    block: NativePrefixBlockGuard,
    failed: Aarch64Label,
) -> Result<(), ObjectError> {
    if block.lane_mask == 0
        || block.byte_mask_offset
            != block
                .expected_offset
                .checked_add(
                    u32::try_from(prefix_block::PREFIX_BLOCK_BYTES).map_err(|_| {
                        ObjectError::ArithmeticOverflow("AArch64 prefix-block constant width")
                    })?,
                )
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 prefix-block mask offset",
                ))?
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 prefix-block constants are malformed",
        ));
    }

    // V24 can hold the retained candidate mask across this guard. V29..V31
    // are the persistent exact-lane constants and V1..V23 may hold scanner
    // constants, so use only caller-saved V25..V27 for this transient check.
    assembler.instruction(aarch64_add_x_reg(12, 0, 2)?)?;
    assembler.instruction(aarch64_load_q(25, 12)?)?;
    aarch64_set_table_address(assembler, 12, block.expected_offset)?;
    assembler.instruction(aarch64_load_q(26, 12)?)?;
    assembler.instruction(aarch64_eor_16b(25, 25, 26)?)?;
    if block.lane_mask != u16::MAX {
        aarch64_set_table_address(assembler, 12, block.byte_mask_offset)?;
        assembler.instruction(aarch64_load_q(27, 12)?)?;
        assembler.instruction(aarch64_and_16b(25, 25, 27)?)?;
    }
    assembler.instruction(aarch64_umaxv_16b(25, 25)?)?;
    assembler.instruction(aarch64_umov_b0(12, 25)?)?;
    assembler.instruction(aarch64_cmp_w_zero(12)?)?;
    assembler.branch_cond(AARCH64_NE, failed)?;
    Ok(())
}

fn aarch64_emit_prefix_guard_path(
    assembler: &mut Aarch64Assembler,
    layout: NativeDfaLayout,
    use_prefix_block: bool,
    vector_coverage: Option<NativeVectorGuardCoverage>,
    predicate_failed: Aarch64Label,
    terminal_bound_failed: Aarch64Label,
    prefix_verified: Aarch64Label,
) -> Result<(), ObjectError> {
    let guaranteed_bytes = layout.prefix_guaranteed_bytes()?;
    if vector_coverage.is_none_or(|coverage| coverage.guaranteed_bytes < guaranteed_bytes) {
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x_imm(12, u16::from(guaranteed_bytes))?)?;
        assembler.branch_cond(AARCH64_LO, terminal_bound_failed)?;
    }
    if let Some(relation) = layout.prefix_relation
        && vector_coverage.is_none_or(|coverage| !coverage.relation)
    {
        aarch64_emit_prefix_relation(assembler, relation, predicate_failed)?;
    }
    let checked_block = use_prefix_block
        .then_some(layout.prefix_block)
        .flatten()
        .filter(|block| {
            vector_coverage.is_none_or(|coverage| block.lane_mask & !coverage.prefix_positions != 0)
        });
    if let Some(block) = checked_block {
        aarch64_emit_prefix_block(assembler, block, predicate_failed)?;
    }
    if let Some(prefix) = layout.prefix_filter {
        for &predicate in prefix.predicates() {
            if checked_block.is_some_and(|block| block.covers_position(predicate.position)) {
                continue;
            }
            if vector_coverage.is_some_and(|coverage| coverage.covers_position(predicate.position))
            {
                continue;
            }
            aarch64_emit_prefix_predicate(assembler, predicate, predicate_failed)?;
        }
    }
    assembler.branch(prefix_verified)?;
    Ok(())
}

fn aarch64_emit_prefix_ranges(
    assembler: &mut Aarch64Assembler,
    position: u8,
    ranges: ScalarPrefixRangePlan,
    failed: Aarch64Label,
) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_add_x_reg(12, 0, 2)?)?;
    assembler.instruction(aarch64_load_byte_imm(8, 12, u16::from(position))?)?;
    let passed = assembler.label()?;
    for range in ranges.ranges() {
        assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.start()))?)?;
        if range.is_singleton() {
            assembler.branch_cond(AARCH64_EQ, passed)?;
        } else {
            let next = assembler.label()?;
            assembler.branch_cond(AARCH64_LO, next)?;
            assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.end()))?)?;
            assembler.branch_cond(AARCH64_LS, passed)?;
            assembler.bind(next)?;
        }
    }
    assembler.branch(failed)?;
    assembler.bind(passed)?;
    Ok(())
}

fn aarch64_emit_scalar_filter_membership(
    assembler: &mut Aarch64Assembler,
    filter: NativeStartFilter,
    failed: Aarch64Label,
) -> Result<(), ObjectError> {
    if filter.ranges().is_empty() {
        return Err(ObjectError::InvalidModule(
            "AArch64 scalar membership has no candidates",
        ));
    }
    aarch64_emit_start_filter_scalar_load(assembler, filter.scan_offset)?;
    let passed = assembler.label()?;
    for range in filter.ranges() {
        assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.start))?)?;
        if range.start == range.end {
            assembler.branch_cond(AARCH64_EQ, passed)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch_cond(AARCH64_LO, next_range)?;
            assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.end))?)?;
            assembler.branch_cond(AARCH64_LS, passed)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.branch(failed)?;
    assembler.bind(passed)?;
    Ok(())
}

/// `AArch64` counterpart of the exact-product probe at the untouched window
/// start. It explicitly validates the anchored column omitted from the normal
/// prefix bitmap guard because no moving scanner has run yet.
#[allow(
    clippy::large_types_passed_by_value,
    reason = "the probe consumes the same copyable layout value as the surrounding lowering"
)]
fn aarch64_emit_exact_start_probe(
    assembler: &mut Aarch64Assembler,
    layout: NativeDfaLayout,
    use_prefix_block: bool,
    failed: Aarch64Label,
    matched: Aarch64Label,
) -> Result<(), ObjectError> {
    let width = layout
        .exact_prefix_match_width
        .ok_or(ObjectError::InvalidModule(
            "AArch64 exact-start width is absent",
        ))?;
    let primary = layout.start_filter.ok_or(ObjectError::InvalidModule(
        "AArch64 exact-start probe has no primary",
    ))?;
    if primary.scan_offset >= width {
        return Err(ObjectError::InvalidModule(
            "AArch64 exact-start primary is outside its product",
        ));
    }
    if layout
        .prefix_filter
        .is_some_and(|prefix| prefix.guaranteed_bytes != width)
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 exact-start width disagrees with prefix guard",
        ));
    }

    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    assembler.instruction(aarch64_cmp_x_imm(12, SUFFIX_PREFILTER_MIN_WINDOW_BYTES)?)?;
    assembler.branch_cond(AARCH64_LO, failed)?;
    assembler.instruction(aarch64_cmp_x_imm(12, u16::from(width))?)?;
    assembler.branch_cond(AARCH64_LO, failed)?;
    if use_prefix_block && let Some(block) = layout.prefix_block {
        aarch64_emit_prefix_block(assembler, block, failed)?;
    }
    if !use_prefix_block
        || layout
            .prefix_block
            .is_none_or(|block| !block.covers_position(primary.scan_offset))
    {
        aarch64_emit_scalar_filter_membership(assembler, primary, failed)?;
    }
    if let Some(prefix) = layout.prefix_filter {
        for &predicate in prefix.predicates() {
            if use_prefix_block
                && layout
                    .prefix_block
                    .is_some_and(|block| block.covers_position(predicate.position))
            {
                continue;
            }
            aarch64_emit_prefix_predicate(assembler, predicate, failed)?;
        }
    }
    aarch64_emit_exact_prefix_match(assembler, width, layout.output, matched)
}

fn aarch64_and_low_w(destination: u8, source: u8, bits: u8) -> Result<u32, ObjectError> {
    let mask_end = bits
        .checked_sub(1)
        .filter(|&value| value < 31)
        .ok_or(ObjectError::InvalidModule("AArch64 low-bit mask"))?;
    Ok(0x1200_0000
        | (u32::from(mask_end) << 10)
        | aarch64_reg(source, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_and_low_x(destination: u8, source: u8, bits: u8) -> Result<u32, ObjectError> {
    let mask_end = bits
        .checked_sub(1)
        .filter(|&value| value < 63)
        .ok_or(ObjectError::InvalidModule("AArch64 low-bit mask"))?;
    Ok(0x9240_0000
        | (u32::from(mask_end) << 10)
        | aarch64_reg(source, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_movz_w(destination: u8, immediate: u16) -> Result<u32, ObjectError> {
    Ok(0x5280_0000 | (u32::from(immediate) << 5) | aarch64_reg(destination, 0)?)
}

fn aarch64_movz_x(destination: u8, immediate: u16, halfword: u8) -> Result<u32, ObjectError> {
    if halfword > 3 {
        return Err(ObjectError::InvalidModule("AArch64 MOVZ halfword"));
    }
    Ok(0xd280_0000
        | (u32::from(halfword) << 21)
        | (u32::from(immediate) << 5)
        | aarch64_reg(destination, 0)?)
}

fn aarch64_movk_x(destination: u8, immediate: u16, halfword: u8) -> Result<u32, ObjectError> {
    if halfword > 3 {
        return Err(ObjectError::InvalidModule("AArch64 MOVK halfword"));
    }
    Ok(0xf280_0000
        | (u32::from(halfword) << 21)
        | (u32::from(immediate) << 5)
        | aarch64_reg(destination, 0)?)
}

fn aarch64_load_u32_constant(
    assembler: &mut Aarch64Assembler,
    destination: u8,
    value: u32,
) -> Result<(), ObjectError> {
    let low = u16::try_from(value & 0xffff)
        .map_err(|_| ObjectError::InvalidModule("AArch64 constant low half"))?;
    let high = u16::try_from(value >> 16)
        .map_err(|_| ObjectError::InvalidModule("AArch64 constant high half"))?;
    assembler.instruction(aarch64_movz_x(destination, low, 0)?)?;
    if high != 0 {
        assembler.instruction(aarch64_movk_x(destination, high, 1)?)?;
    }
    Ok(())
}

fn aarch64_load_u64_constant(
    assembler: &mut Aarch64Assembler,
    destination: u8,
    value: u64,
) -> Result<(), ObjectError> {
    let low = u16::try_from(value & 0xffff)
        .map_err(|_| ObjectError::InvalidModule("AArch64 constant low half"))?;
    assembler.instruction(aarch64_movz_x(destination, low, 0)?)?;
    for halfword in 1_u8..4 {
        let shift = u32::from(halfword) * 16;
        let part = u16::try_from((value >> shift) & 0xffff)
            .map_err(|_| ObjectError::InvalidModule("AArch64 constant half"))?;
        if part != 0 {
            assembler.instruction(aarch64_movk_x(destination, part, halfword)?)?;
        }
    }
    Ok(())
}

fn aarch64_emit_exact_span_start(
    assembler: &mut Aarch64Assembler,
    width: u64,
) -> Result<(), ObjectError> {
    if let Ok(width) = u16::try_from(width)
        && width <= 0x0fff
    {
        assembler.instruction(aarch64_sub_x_imm(6, 7, width)?)?;
    } else {
        aarch64_load_u64_constant(assembler, 6, width)?;
        assembler.instruction(aarch64_sub_x_reg(6, 7, 6)?)?;
    }
    Ok(())
}

fn aarch64_emit_exact_prefix_match(
    assembler: &mut Aarch64Assembler,
    width: u8,
    output: OutputContract,
    matched: Aarch64Label,
) -> Result<(), ObjectError> {
    if width == 0 || usize::from(width) > MAX_ANCHORED_PREFIX_BYTES {
        return Err(ObjectError::InvalidModule(
            "invalid AArch64 exact-prefix match width",
        ));
    }
    if output != OutputContract::Exists {
        assembler.instruction(aarch64_add_x_imm(6, 2, u16::from(width))?)?;
        if output == OutputContract::Span {
            assembler.instruction(aarch64_store_x(2, 4, 0)?)?;
        } else {
            assembler.instruction(aarch64_store_x(6, 4, 0)?)?;
        }
        assembler.instruction(aarch64_store_x(6, 4, 8)?)?;
    }
    assembler.branch(matched)?;
    Ok(())
}

fn aarch64_set_table_address(
    assembler: &mut Aarch64Assembler,
    destination: u8,
    table_offset: u32,
) -> Result<(), ObjectError> {
    if let Ok(immediate) = u16::try_from(table_offset)
        && immediate <= 0x0fff
    {
        assembler.instruction(aarch64_add_x_imm(destination, 5, immediate)?)?;
    } else {
        aarch64_load_u32_constant(assembler, destination, table_offset)?;
        assembler.instruction(aarch64_add_x_reg(destination, 5, destination)?)?;
    }
    Ok(())
}

fn aarch64_set_row_base(
    assembler: &mut Aarch64Assembler,
    table_offset: u32,
) -> Result<(), ObjectError> {
    aarch64_set_table_address(assembler, 11, table_offset)
}

fn aarch64_emit_table_lookup(
    assembler: &mut Aarch64Assembler,
    transitions: TransitionLayout,
) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_load_byte_reg(8, 0, 2)?)?;
    match transitions {
        TransitionLayout::ClassMapped => {
            assembler.instruction(aarch64_load_byte_reg(8, 5, 8)?)?;
            assembler.instruction(aarch64_load_w_uxtw(8, 11, 8)?)?;
        }
        TransitionLayout::DirectByte => {
            assembler.instruction(aarch64_load_w_uxtw(8, 11, 8)?)?;
        }
    }
    Ok(())
}

/// Decode an ordinary live packed cell and materialize its absolute next row.
/// After subtracting the live-token bias, every packable exceptional cell has
/// a nonzero value above the payload bits. The sole excluded bit pattern is an
/// accelerated dead cell, which packing rejects before native data is emitted.
fn aarch64_emit_ordinary_live_row(
    assembler: &mut Aarch64Assembler,
    exceptional: Aarch64Label,
) -> Result<(), ObjectError> {
    let flag_shift = u8::try_from(CELL_ACCELERATED.trailing_zeros())
        .map_err(|_| ObjectError::ArithmeticOverflow("packed-cell flag shift"))?;
    // The W-form subtraction deliberately zero-extends decoded into X6 for
    // both the following X-form shift and the 64-bit table-base addition.
    assembler.instruction(aarch64_sub_w_imm(6, 8, 1)?)?;
    assembler.instruction(aarch64_lsr_x_imm(12, 6, flag_shift)?)?;
    assembler.branch_nonzero_w(12, exceptional)?;
    assembler.instruction(aarch64_add_x_reg(11, 5, 6)?)?;
    Ok(())
}

fn aarch64_movi_16b(destination: u8, immediate: u8) -> Result<u32, ObjectError> {
    Ok(0x4f00_e400
        | (u32::from(immediate & 0x1f) << 5)
        | (u32::from(immediate & 0xe0) << 11)
        | aarch64_reg(destination, 0)?)
}

fn aarch64_dup_16b_from_w(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0x4e01_0c00 | aarch64_reg(source, 5)? | aarch64_reg(destination, 0)?)
}

fn aarch64_cmeq_16b(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x6e20_8c00
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_cmhs_16b(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x6e20_3c00
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_and_16b(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x4e20_1c00
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_orr_16b(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x4ea0_1c00
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_eor_16b(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x6e20_1c00
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_bsl_16b(destination: u8, when_set: u8, when_clear: u8) -> Result<u32, ObjectError> {
    Ok(0x6e60_1c00
        | aarch64_reg(when_clear, 16)?
        | aarch64_reg(when_set, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_add_16b(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x4e20_8400
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_umin_16b(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x6e20_6c00
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_umaxv_16b(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0x6e30_a800 | aarch64_reg(source, 5)? | aarch64_reg(destination, 0)?)
}

fn aarch64_uminv_16b(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0x6e31_a800 | aarch64_reg(source, 5)? | aarch64_reg(destination, 0)?)
}

fn aarch64_umov_b0(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0x0e01_3c00 | aarch64_reg(source, 5)? | aarch64_reg(destination, 0)?)
}

fn aarch64_load_q(destination: u8, base: u8) -> Result<u32, ObjectError> {
    Ok(0x3dc0_0000 | aarch64_reg(base, 5)? | aarch64_reg(destination, 0)?)
}

fn aarch64_ld1_four_16b(first_destination: u8, base: u8) -> Result<u32, ObjectError> {
    if first_destination > 28 {
        return Err(ObjectError::InvalidModule(
            "AArch64 four-register LD1 wraps the vector file",
        ));
    }
    Ok(0x4c40_2000 | aarch64_reg(base, 5)? | aarch64_reg(first_destination, 0)?)
}

fn aarch64_ext_16b(
    destination: u8,
    low: u8,
    high: u8,
    byte_offset: u8,
) -> Result<u32, ObjectError> {
    if byte_offset > 15 {
        return Err(ObjectError::InvalidModule("AArch64 EXT byte offset"));
    }
    Ok(0x6e00_0000
        | aarch64_reg(high, 16)?
        | (u32::from(byte_offset) << 11)
        | aarch64_reg(low, 5)?
        | aarch64_reg(destination, 0)?)
}

const AARCH64_EXACT_FILTER_SCRATCH: u8 = 28;
const AARCH64_VECTOR_FILTER_FIRST_CONSTANT: u8 = 1;
const AARCH64_STANDALONE_FILTER_FIRST_CONSTANT: u8 = 16;

const fn aarch64_caller_saved_simd(register: u8) -> bool {
    register <= 7 || register >= 16
}

/// Translate one bounded filter-constant slot to a caller-saved SIMD register.
///
/// Retained multi-column filters have a four-constant global cap and occupy
/// V1..V4. Standalone exact and range filters occupy V16..V23. The two banks
/// match their callers' complementary source/candidate allocations, avoid the
/// ABI-preserved V8..V15 bank, and leave V7 exclusively available for the
/// persistent loop's horizontal candidate reduction.
fn aarch64_filter_constant_register(first_register: u8, index: usize) -> Result<u8, ObjectError> {
    let logical = index
        .checked_add(usize::from(first_register))
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(ObjectError::ArithmeticOverflow(
            "ASIMD filter constant register",
        ))?;
    let register = match logical {
        1..=4 | 16..=23 => logical,
        _ => {
            return Err(ObjectError::InvalidModule(
                "ASIMD filter constant escaped caller-saved register banks",
            ));
        }
    };
    Ok(register)
}

fn aarch64_prefix_relation_constant_register(
    first_register: u8,
    index: usize,
) -> Result<u8, ObjectError> {
    let register = index
        .checked_add(usize::from(first_register))
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(ObjectError::ArithmeticOverflow(
            "ASIMD prefix-relation constant register",
        ))?;
    if !(1..=MAX_AARCH64_PREFIX_RELATION_CONSTANTS).contains(&register) {
        return Err(ObjectError::InvalidModule(
            "ASIMD prefix-relation constant escaped V1..V6",
        ));
    }
    Ok(register)
}

fn aarch64_emit_first_lane_constants(
    assembler: &mut Aarch64Assembler,
    table_offset: u32,
) -> Result<(), ObjectError> {
    if table_offset == 0 {
        assembler.instruction(aarch64_load_q(29, 5)?)?;
    } else {
        aarch64_set_table_address(assembler, 12, table_offset)?;
        assembler.instruction(aarch64_load_q(29, 12)?)?;
    }
    // Candidate comparisons produce exact 0xff/0x00 bytes. v29 is the lane
    // ramp, v30 advances it between 16-byte blocks, and v31 is a sentinel
    // larger than every lane in a four-vector batch.
    assembler.instruction(aarch64_movi_16b(30, 16)?)?;
    assembler.instruction(aarch64_movi_16b(31, 64)?)?;
    Ok(())
}

fn aarch64_emit_candidate_any(
    assembler: &mut Aarch64Assembler,
    candidates: u8,
) -> Result<(), ObjectError> {
    // Keep the exact mask intact for the rare hit edge. Caller-saved v7 is
    // outside every bounded filter-constant and candidate allocation;
    // v29-v31 remain the persistent first-lane constants.
    assembler.instruction(aarch64_umaxv_16b(7, candidates)?)?;
    assembler.instruction(aarch64_umov_b0(12, 7)?)?;
    assembler.instruction(aarch64_cmp_w_zero(12)?)?;
    Ok(())
}

fn aarch64_emit_candidate_batch_any(
    assembler: &mut Aarch64Assembler,
    first_candidates: u8,
) -> Result<(), ObjectError> {
    let second = first_candidates
        .checked_add(1)
        .ok_or(ObjectError::ArithmeticOverflow("AArch64 batch candidates"))?;
    let third = first_candidates
        .checked_add(2)
        .ok_or(ObjectError::ArithmeticOverflow("AArch64 batch candidates"))?;
    let fourth = first_candidates
        .checked_add(3)
        .ok_or(ObjectError::ArithmeticOverflow("AArch64 batch candidates"))?;
    // Pairwise reduction preserves all four exact lane masks for a rare hit
    // while shortening the overwhelmingly hot miss path by one ORR.
    assembler.instruction(aarch64_orr_16b(28, first_candidates, second)?)?;
    assembler.instruction(aarch64_orr_16b(7, third, fourth)?)?;
    assembler.instruction(aarch64_orr_16b(28, 28, 7)?)?;
    aarch64_emit_candidate_any(assembler, 28)
}

fn aarch64_emit_first_candidate_lane(
    assembler: &mut Aarch64Assembler,
    candidates: u8,
) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_bsl_16b(candidates, 29, 31)?)?;
    assembler.instruction(aarch64_uminv_16b(candidates, candidates)?)?;
    assembler.instruction(aarch64_umov_b0(12, candidates)?)?;
    assembler.instruction(aarch64_add_x_reg(2, 2, 12)?)?;
    Ok(())
}

fn aarch64_emit_first_retained_candidate_lane(
    assembler: &mut Aarch64Assembler,
    candidates: u8,
    block_base: u8,
) -> Result<(), ObjectError> {
    // Retained V24 must survive scalar prefix checks. Refine a caller-saved
    // copy in V28 and address the selected lane from caller-saved X14.
    assembler.instruction(aarch64_orr_16b(28, candidates, candidates)?)?;
    assembler.instruction(aarch64_bsl_16b(28, 29, 31)?)?;
    assembler.instruction(aarch64_uminv_16b(28, 28)?)?;
    assembler.instruction(aarch64_umov_b0(12, 28)?)?;
    assembler.instruction(aarch64_add_x_reg(2, block_base, 12)?)?;
    Ok(())
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the preceding checked register bound proves all fixed offsets remain in range"
)]
fn aarch64_emit_first_candidate_in_batch(
    assembler: &mut Aarch64Assembler,
    first_candidates: u8,
) -> Result<(), ObjectError> {
    let last_candidates =
        first_candidates
            .checked_add(3)
            .ok_or(ObjectError::ArithmeticOverflow(
                "AArch64 batch candidate register",
            ))?;
    if last_candidates >= 28 {
        return Err(ObjectError::InvalidModule(
            "AArch64 batch candidates overlap first-lane temporaries",
        ));
    }

    // Convert each exact mask into its absolute lane number, using 64 for
    // absent lanes. Pairwise unsigned minima then select the first candidate
    // over the complete 64-byte batch without a scalar rescan or a chain of
    // unpredictable per-block branches.
    assembler.instruction(aarch64_orr_16b(28, 29, 29)?)?;
    for block in 0_u8..4 {
        let candidates =
            first_candidates
                .checked_add(block)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 batch candidate register",
                ))?;
        assembler.instruction(aarch64_bsl_16b(candidates, 28, 31)?)?;
        if block < 3 {
            assembler.instruction(aarch64_add_16b(28, 28, 30)?)?;
        }
    }
    assembler.instruction(aarch64_umin_16b(
        first_candidates,
        first_candidates,
        first_candidates + 1,
    )?)?;
    assembler.instruction(aarch64_umin_16b(
        first_candidates + 2,
        first_candidates + 2,
        first_candidates + 3,
    )?)?;
    assembler.instruction(aarch64_umin_16b(
        first_candidates,
        first_candidates,
        first_candidates + 2,
    )?)?;
    assembler.instruction(aarch64_uminv_16b(first_candidates, first_candidates)?)?;
    assembler.instruction(aarch64_umov_b0(12, first_candidates)?)?;
    assembler.instruction(aarch64_add_x_reg(2, 2, 12)?)?;
    Ok(())
}

fn aarch64_emit_start_filter_constants(
    assembler: &mut Aarch64Assembler,
    filter: NativeStartFilter,
    first_register: u8,
) -> Result<(), ObjectError> {
    for (index, range) in filter.ranges().iter().enumerate() {
        if filter.is_exact() {
            let register = aarch64_filter_constant_register(first_register, index)?;
            assembler.instruction(aarch64_movi_16b(register, range.start)?)?;
        } else {
            let logical_low = index.checked_mul(2).ok_or(ObjectError::ArithmeticOverflow(
                "ASIMD range-filter low register",
            ))?;
            let logical_high =
                logical_low
                    .checked_add(1)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "ASIMD range-filter high register",
                    ))?;
            let low_register = aarch64_filter_constant_register(first_register, logical_low)?;
            let high_register = aarch64_filter_constant_register(first_register, logical_high)?;
            assembler.instruction(aarch64_movi_16b(low_register, range.start)?)?;
            assembler.instruction(aarch64_movi_16b(high_register, range.end)?)?;
        }
    }
    Ok(())
}

fn aarch64_emit_prefix_relation_constants(
    assembler: &mut Aarch64Assembler,
    plan: NativePrefixRelationVectorPlan,
) -> Result<(), ObjectError> {
    if plan.constant_count > MAX_AARCH64_PREFIX_RELATION_CONSTANTS {
        return Err(ObjectError::InvalidModule(
            "AArch64 prefix-relation constant budget",
        ));
    }
    for rectangle in plan.rectangles() {
        for predicate in [rectangle.first, rectangle.second] {
            if predicate.any {
                continue;
            }
            for (index, range) in predicate.filter.ranges().iter().enumerate() {
                if predicate.filter.is_exact() {
                    let register =
                        aarch64_prefix_relation_constant_register(predicate.first_constant, index)?;
                    assembler.instruction(aarch64_movi_16b(register, range.start)?)?;
                } else {
                    let logical_low = index.checked_mul(2).ok_or(
                        ObjectError::ArithmeticOverflow("AArch64 prefix-relation range constant"),
                    )?;
                    let low = aarch64_prefix_relation_constant_register(
                        predicate.first_constant,
                        logical_low,
                    )?;
                    let high = aarch64_prefix_relation_constant_register(
                        predicate.first_constant,
                        logical_low
                            .checked_add(1)
                            .ok_or(ObjectError::ArithmeticOverflow(
                                "AArch64 prefix-relation range constant",
                            ))?,
                    )?;
                    assembler.instruction(aarch64_movi_16b(low, range.start)?)?;
                    assembler.instruction(aarch64_movi_16b(high, range.end)?)?;
                }
            }
        }
    }
    Ok(())
}

fn aarch64_emit_prefix_relation_predicate(
    assembler: &mut Aarch64Assembler,
    predicate: NativePrefixRelationPredicate,
    source: u8,
    destination: u8,
) -> Result<(), ObjectError> {
    if predicate.any {
        assembler.instruction(aarch64_cmeq_16b(destination, source, source)?)?;
        return Ok(());
    }
    if predicate.filter.is_exact() {
        let first = aarch64_prefix_relation_constant_register(predicate.first_constant, 0)?;
        assembler.instruction(aarch64_cmeq_16b(destination, source, first)?)?;
        for index in 1..predicate.filter.ranges().len() {
            let constant =
                aarch64_prefix_relation_constant_register(predicate.first_constant, index)?;
            assembler.instruction(aarch64_cmeq_16b(19, source, constant)?)?;
            assembler.instruction(aarch64_orr_16b(destination, destination, 19)?)?;
        }
    } else {
        for (index, _) in predicate.filter.ranges().iter().enumerate() {
            let logical_low = index.checked_mul(2).ok_or(ObjectError::ArithmeticOverflow(
                "AArch64 prefix-relation range constant",
            ))?;
            let low =
                aarch64_prefix_relation_constant_register(predicate.first_constant, logical_low)?;
            let high = aarch64_prefix_relation_constant_register(
                predicate.first_constant,
                logical_low
                    .checked_add(1)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "AArch64 prefix-relation range constant",
                    ))?,
            )?;
            assembler.instruction(aarch64_cmhs_16b(18, source, low)?)?;
            assembler.instruction(aarch64_cmhs_16b(19, high, source)?)?;
            assembler.instruction(aarch64_and_16b(18, 18, 19)?)?;
            if index == 0 {
                assembler.instruction(aarch64_orr_16b(destination, 18, 18)?)?;
            } else {
                assembler.instruction(aarch64_orr_16b(destination, destination, 18)?)?;
            }
        }
    }
    if predicate.negated {
        assembler.instruction(aarch64_cmeq_16b(17, source, source)?)?;
        assembler.instruction(aarch64_eor_16b(destination, destination, 17)?)?;
    }
    Ok(())
}

/// Produce one exact rectangle-union mask without reducing it. V17..V21 are
/// caller-saved temporaries and V1..V6 are bounded constants; the
/// ABI-preserved V8..V15 bank is never touched.
fn aarch64_emit_prefix_relation_mask(
    assembler: &mut Aarch64Assembler,
    plan: NativePrefixRelationVectorPlan,
    first_source: u8,
    second_source: u8,
    destination: u8,
) -> Result<(), ObjectError> {
    if plan.rectangles().is_empty() {
        return Err(ObjectError::InvalidModule(
            "empty AArch64 prefix-relation vector plan",
        ));
    }
    for (index, rectangle) in plan.rectangles().iter().copied().enumerate() {
        aarch64_emit_prefix_relation_predicate(assembler, rectangle.first, first_source, 20)?;
        if !rectangle.second.any {
            aarch64_emit_prefix_relation_predicate(assembler, rectangle.second, second_source, 21)?;
            assembler.instruction(aarch64_and_16b(20, 20, 21)?)?;
        }
        if index == 0 {
            assembler.instruction(aarch64_orr_16b(destination, 20, 20)?)?;
        } else {
            assembler.instruction(aarch64_orr_16b(destination, destination, 20)?)?;
        }
    }
    Ok(())
}

/// Produce the exact 16-lane rectangle-union mask in V24 and leave condition
/// flags ready for the shared hit edge.
fn aarch64_emit_prefix_relation_vector_test(
    assembler: &mut Aarch64Assembler,
    plan: NativePrefixRelationVectorPlan,
) -> Result<(), ObjectError> {
    aarch64_emit_start_filter_address(assembler, 0)?;
    assembler.instruction(aarch64_load_q(0, 12)?)?;
    aarch64_emit_start_filter_address(assembler, 1)?;
    assembler.instruction(aarch64_load_q(16, 12)?)?;
    aarch64_emit_prefix_relation_mask(assembler, plan, 0, 16, 24)?;
    aarch64_emit_candidate_any(assembler, 24)
}

/// Produce four exact adjacent relation masks in V24..V27. The first byte
/// column is loaded once; EXT forms the overlapping second column for the
/// first three blocks, and one final load supplies byte 64 for the last.
fn aarch64_emit_prefix_relation_batch_candidates(
    assembler: &mut Aarch64Assembler,
    plan: NativePrefixRelationVectorPlan,
) -> Result<u8, ObjectError> {
    const FIRST_CANDIDATES: u8 = 24;
    aarch64_emit_start_filter_address(assembler, 0)?;
    assembler.instruction(aarch64_ld1_four_16b(FIRST_CANDIDATES, 12)?)?;
    for block in 0_u8..4 {
        let candidates =
            FIRST_CANDIDATES
                .checked_add(block)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 relation batch candidates",
                ))?;
        assembler.instruction(aarch64_orr_16b(0, candidates, candidates)?)?;
        if block < 3 {
            assembler.instruction(aarch64_ext_16b(16, candidates, candidates + 1, 1)?)?;
        } else {
            aarch64_emit_start_filter_address(assembler, 49)?;
            assembler.instruction(aarch64_load_q(16, 12)?)?;
        }
        aarch64_emit_prefix_relation_mask(assembler, plan, 0, 16, candidates)?;
    }
    Ok(FIRST_CANDIDATES)
}

fn aarch64_emit_start_filter_vector_candidates(
    assembler: &mut Aarch64Assembler,
    filter: NativeStartFilter,
    source: u8,
    destination: u8,
    first_register: u8,
) -> Result<(), ObjectError> {
    if filter.ranges().is_empty() {
        return Err(ObjectError::InvalidModule(
            "empty AArch64 start filter reached vector lowering",
        ));
    }
    if !aarch64_caller_saved_simd(source)
        || !aarch64_caller_saved_simd(destination)
        || source == AARCH64_EXACT_FILTER_SCRATCH
        || destination == AARCH64_EXACT_FILTER_SCRATCH
    {
        return Err(ObjectError::InvalidModule(
            "ASIMD filter operands overlap an ABI-preserved or reserved register",
        ));
    }
    if filter.is_exact() {
        let first_constant = aarch64_filter_constant_register(first_register, 0)?;
        assembler.instruction(aarch64_cmeq_16b(destination, source, first_constant)?)?;
        for index in 1..filter.ranges().len() {
            let register = aarch64_filter_constant_register(first_register, index)?;
            // V28 is dead until the caller reduces the completed candidate
            // masks. Keeping the union scratch there avoids ABI-preserved
            // V8..V15 without consuming another persistent constant register.
            assembler.instruction(aarch64_cmeq_16b(
                AARCH64_EXACT_FILTER_SCRATCH,
                source,
                register,
            )?)?;
            assembler.instruction(aarch64_orr_16b(
                destination,
                destination,
                AARCH64_EXACT_FILTER_SCRATCH,
            )?)?;
        }
    } else {
        for (index, _) in filter.ranges().iter().enumerate() {
            let logical_low = index.checked_mul(2).ok_or(ObjectError::ArithmeticOverflow(
                "ASIMD range-filter low register",
            ))?;
            let logical_high =
                logical_low
                    .checked_add(1)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "ASIMD range-filter high register",
                    ))?;
            let low_register = aarch64_filter_constant_register(first_register, logical_low)?;
            let high_register = aarch64_filter_constant_register(first_register, logical_high)?;
            assembler.instruction(aarch64_cmhs_16b(5, source, low_register)?)?;
            assembler.instruction(aarch64_cmhs_16b(6, high_register, source)?)?;
            assembler.instruction(aarch64_and_16b(5, 5, 6)?)?;
            if index == 0 {
                assembler.instruction(aarch64_orr_16b(destination, 5, 5)?)?;
            } else {
                assembler.instruction(aarch64_orr_16b(destination, destination, 5)?)?;
            }
        }
    }
    Ok(())
}

fn aarch64_emit_start_filter_vector_test(
    assembler: &mut Aarch64Assembler,
    filter: NativeStartFilter,
    source: u8,
    candidates: u8,
) -> Result<(), ObjectError> {
    let first_register = AARCH64_STANDALONE_FILTER_FIRST_CONSTANT;
    aarch64_emit_start_filter_vector_candidates(
        assembler,
        filter,
        source,
        candidates,
        first_register,
    )?;
    assembler.instruction(aarch64_umaxv_16b(candidates, candidates)?)?;
    assembler.instruction(aarch64_umov_b0(12, candidates)?)?;
    assembler.instruction(aarch64_cmp_w_zero(12)?)?;
    Ok(())
}

fn aarch64_emit_start_filter_address(
    assembler: &mut Aarch64Assembler,
    scan_offset: u8,
) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_add_x_reg(12, 0, 2)?)?;
    if scan_offset != 0 {
        assembler.instruction(aarch64_add_x_imm(12, 12, u16::from(scan_offset))?)?;
    }
    Ok(())
}

fn aarch64_emit_vector_filter_secondary_candidates_at(
    assembler: &mut Aarch64Assembler,
    vector_filter: NativeVectorFilter,
    block_offset: u8,
    primary_candidates: u8,
) -> Result<(), ObjectError> {
    if vector_filter.columns().len() < 2 {
        return Err(ObjectError::InvalidModule(
            "AArch64 vector-filter intersection has one column",
        ));
    }
    let mut first_register = AARCH64_VECTOR_FILTER_FIRST_CONSTANT
        .checked_add(
            u8::try_from(vector_filter.columns()[0].constant_count())
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 vector-filter constants"))?,
        )
        .ok_or(ObjectError::ArithmeticOverflow(
            "AArch64 vector-filter constants",
        ))?;
    for &column in &vector_filter.columns()[1..] {
        let load_offset =
            block_offset
                .checked_add(column.scan_offset)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 vector-filter load offset",
                ))?;
        aarch64_emit_start_filter_address(assembler, load_offset)?;
        assembler.instruction(aarch64_load_q(0, 12)?)?;
        aarch64_emit_start_filter_vector_candidates(assembler, column, 0, 25, first_register)?;
        assembler.instruction(aarch64_and_16b(primary_candidates, primary_candidates, 25)?)?;
        first_register =
            first_register
                .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                    ObjectError::ArithmeticOverflow("AArch64 vector-filter constants")
                })?)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 vector-filter constants",
                ))?;
    }
    Ok(())
}

fn aarch64_emit_vector_filter_secondary_batch(
    assembler: &mut Aarch64Assembler,
    vector_filter: NativeVectorFilter,
) -> Result<(), ObjectError> {
    if vector_filter.columns().len() < 2 {
        return Err(ObjectError::InvalidModule(
            "AArch64 vector-filter intersection has one column",
        ));
    }
    let mut first_register = AARCH64_VECTOR_FILTER_FIRST_CONSTANT
        .checked_add(
            u8::try_from(vector_filter.columns()[0].constant_count())
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 vector-filter constants"))?,
        )
        .ok_or(ObjectError::ArithmeticOverflow(
            "AArch64 vector-filter constants",
        ))?;
    for &column in &vector_filter.columns()[1..] {
        aarch64_emit_start_filter_address(assembler, column.scan_offset)?;
        assembler.instruction(aarch64_ld1_four_16b(16, 12)?)?;
        for lane in 0_u8..4 {
            let source = 16_u8
                .checked_add(lane)
                .ok_or(ObjectError::ArithmeticOverflow("AArch64 LD1 source"))?;
            let secondary_candidates =
                20_u8
                    .checked_add(lane)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "AArch64 secondary candidates",
                    ))?;
            let primary_candidates =
                24_u8
                    .checked_add(lane)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "AArch64 primary candidates",
                    ))?;
            aarch64_emit_start_filter_vector_candidates(
                assembler,
                column,
                source,
                secondary_candidates,
                first_register,
            )?;
            assembler.instruction(aarch64_and_16b(
                primary_candidates,
                primary_candidates,
                secondary_candidates,
            )?)?;
        }
        first_register =
            first_register
                .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                    ObjectError::ArithmeticOverflow("AArch64 vector-filter constants")
                })?)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 vector-filter constants",
                ))?;
    }
    Ok(())
}

fn aarch64_emit_start_filter_batch_candidates(
    assembler: &mut Aarch64Assembler,
    filter: NativeStartFilter,
    first_register: u8,
) -> Result<u8, ObjectError> {
    let (first_source, first_candidates) = match first_register {
        AARCH64_VECTOR_FILTER_FIRST_CONSTANT..=4 => (16_u8, 24_u8),
        AARCH64_STANDALONE_FILTER_FIRST_CONSTANT => (24_u8, 0_u8),
        _ => {
            return Err(ObjectError::InvalidModule(
                "ASIMD batch filter has an invalid constant allocation",
            ));
        }
    };
    aarch64_emit_start_filter_address(assembler, filter.scan_offset)?;
    assembler.instruction(aarch64_ld1_four_16b(first_source, 12)?)?;
    for lane in 0_u8..4 {
        let source = first_source
            .checked_add(lane)
            .ok_or(ObjectError::ArithmeticOverflow("AArch64 LD1 source"))?;
        let candidates = first_candidates
            .checked_add(lane)
            .ok_or(ObjectError::ArithmeticOverflow("AArch64 batch candidates"))?;
        aarch64_emit_start_filter_vector_candidates(
            assembler,
            filter,
            source,
            candidates,
            first_register,
        )?;
    }
    Ok(first_candidates)
}

fn aarch64_emit_start_filter_scalar_bound(
    assembler: &mut Aarch64Assembler,
    scan_offset: u8,
    exhausted: Aarch64Label,
) -> Result<(), ObjectError> {
    if scan_offset == 0 {
        assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    } else {
        assembler.instruction(aarch64_add_x_imm(12, 2, u16::from(scan_offset))?)?;
        assembler.instruction(aarch64_cmp_x(12, 3)?)?;
    }
    assembler.branch_cond(AARCH64_HS, exhausted)?;
    Ok(())
}

fn aarch64_emit_start_filter_scalar_load(
    assembler: &mut Aarch64Assembler,
    scan_offset: u8,
) -> Result<(), ObjectError> {
    if scan_offset == 0 {
        assembler.instruction(aarch64_load_byte_reg(8, 0, 2)?)?;
    } else {
        assembler.instruction(aarch64_add_x_reg(12, 0, 2)?)?;
        assembler.instruction(aarch64_load_byte_imm(8, 12, u16::from(scan_offset))?)?;
    }
    Ok(())
}

fn aarch64_emit_suffix_lower_bound(
    assembler: &mut Aarch64Assembler,
    backtrack: u64,
) -> Result<(), ObjectError> {
    if backtrack == 0 {
        return Ok(());
    }
    let clamp = assembler.label()?;
    let done = assembler.label()?;
    assembler.instruction(aarch64_sub_x_reg(12, 2, 9)?)?; // suffix base - window start
    if let Ok(immediate) = u16::try_from(backtrack)
        && immediate <= 0x0fff
    {
        assembler.instruction(aarch64_cmp_x_imm(12, immediate)?)?;
        assembler.branch_cond(AARCH64_LS, clamp)?;
        assembler.instruction(aarch64_sub_x_imm(2, 2, immediate)?)?;
    } else {
        aarch64_load_u64_constant(assembler, 6, backtrack)?;
        assembler.instruction(aarch64_cmp_x(12, 6)?)?;
        assembler.branch_cond(AARCH64_LS, clamp)?;
        assembler.instruction(aarch64_sub_x_reg(2, 2, 6)?)?;
    }
    assembler.branch(done)?;
    assembler.bind(clamp)?;
    assembler.instruction(aarch64_mov_x(2, 9)?)?;
    assembler.bind(done)?;
    Ok(())
}

fn aarch64_emit_suffix_reset_restart(
    assembler: &mut Aarch64Assembler,
    non_reset: NativeResetFilter,
) -> Result<(), ObjectError> {
    let scan = assembler.label()?;
    let non_reset_byte = assembler.label()?;
    let no_reset = assembler.label()?;
    let done = assembler.label()?;
    assembler.instruction(aarch64_mov_x(10, 2)?)?; // cursor = suffix base
    assembler.instruction(aarch64_movz_w(6, 64)?)?;
    assembler.bind(scan)?;
    assembler.instruction(aarch64_cmp_x(10, 9)?)?;
    assembler.branch_cond(AARCH64_LS, no_reset)?;
    assembler.instruction(aarch64_sub_x_imm(10, 10, 1)?)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, 10)?)?;
    for range in non_reset.ranges() {
        assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.start))?)?;
        if range.start == range.end {
            assembler.branch_cond(AARCH64_EQ, non_reset_byte)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch_cond(AARCH64_LO, next_range)?;
            assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.end))?)?;
            assembler.branch_cond(AARCH64_LS, non_reset_byte)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.instruction(aarch64_add_x_imm(2, 10, 1)?)?; // start = reset + 1
    assembler.branch(done)?;

    assembler.bind(non_reset_byte)?;
    assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
    assembler.instruction(aarch64_cmp_w_zero(6)?)?;
    assembler.branch_cond(AARCH64_NE, scan)?;
    assembler.bind(no_reset)?;
    assembler.instruction(aarch64_mov_x(2, 9)?)?;
    assembler.bind(done)?;
    Ok(())
}

fn aarch64_emit_suffix_restart(
    assembler: &mut Aarch64Assembler,
    restart: NativeSuffixRestart,
) -> Result<(), ObjectError> {
    match restart {
        NativeSuffixRestart::Bounded { backtrack } => {
            aarch64_emit_suffix_lower_bound(assembler, backtrack)
        }
        NativeSuffixRestart::Synchronizing { non_reset } => {
            aarch64_emit_suffix_reset_restart(assembler, non_reset)
        }
        NativeSuffixRestart::OriginalStart => {
            assembler.instruction(aarch64_mov_x(2, 9)?)?;
            Ok(())
        }
    }
}

#[allow(
    clippy::large_types_passed_by_value,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "aligned vector batches, lazy intersections and scalar tails form one suffix proof"
)]
fn aarch64_emit_suffix_prepass(
    assembler: &mut Aarch64Assembler,
    suffix: NativeSuffixFilter,
    use_asimd: bool,
    use_asimd_batch: bool,
    use_exact_asimd_lane: bool,
    layout: NativeDfaLayout,
    no_match: Aarch64Label,
    matched: Aarch64Label,
) -> Result<(), ObjectError> {
    if let Some(reverse) = layout.seeded_reverse {
        return module_seeded_reverse_aarch64::aarch64_emit_seeded_reverse_prepass(
            assembler,
            suffix,
            reverse,
            use_asimd,
            use_asimd_batch,
            use_exact_asimd_lane,
            layout,
            no_match,
            matched,
        );
    }
    let vector = assembler.label()?;
    let single_vector = assembler.label()?;
    let scalar = assembler.label()?;
    let scalar_columns = assembler.label()?;
    let scalar_reject = assembler.label()?;
    let batch_primary_hit = assembler.label()?;
    let single_primary_hit = assembler.label()?;
    let batch_hit = assembler.label()?;
    let single_hit = assembler.label()?;
    let apply = assembler.label()?;
    let done = assembler.label()?;
    let filter = suffix.filter;
    let scalar_filter = suffix.vector_filter.or(suffix.scalar_filter);
    let maximum_scan_offset =
        scalar_filter.map_or(filter.scan_offset, NativeVectorFilter::max_scan_offset);
    if suffix.minimum_width == 0 {
        return Err(ObjectError::InvalidModule(
            "AArch64 suffix filter has zero minimum width",
        ));
    }
    let mut batch_first_candidates = None;
    let emit_constants = |assembler: &mut Aarch64Assembler| -> Result<(), ObjectError> {
        if use_asimd {
            if let Some(vector_filter) = suffix.vector_filter {
                let mut first_register = AARCH64_VECTOR_FILTER_FIRST_CONSTANT;
                for &column in vector_filter.columns() {
                    aarch64_emit_start_filter_constants(assembler, column, first_register)?;
                    first_register = first_register
                        .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                            ObjectError::ArithmeticOverflow("AArch64 suffix-filter constants")
                        })?)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "AArch64 suffix-filter constants",
                        ))?;
                }
            } else {
                let first_register = AARCH64_STANDALONE_FILTER_FIRST_CONSTANT;
                aarch64_emit_start_filter_constants(assembler, filter, first_register)?;
            }
        }
        Ok(())
    };
    if !ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS {
        emit_constants(assembler)?;
    }
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    assembler.instruction(aarch64_cmp_x_imm(12, SUFFIX_PREFILTER_MIN_WINDOW_BYTES)?)?;
    assembler.branch_cond(AARCH64_LO, done)?;
    if ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS {
        emit_constants(assembler)?;
    }

    if use_asimd {
        assembler.bind(vector)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        if use_asimd_batch {
            let batch_bytes = u16::from(maximum_scan_offset)
                .checked_add(AARCH64_BATCH_BYTES)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 suffix-filter width",
                ))?;
            assembler.instruction(aarch64_cmp_x_imm(12, batch_bytes)?)?;
            assembler.branch_cond(AARCH64_LO, single_vector)?;
            let first_register = if suffix.vector_filter.is_some() {
                AARCH64_VECTOR_FILTER_FIRST_CONSTANT
            } else {
                AARCH64_STANDALONE_FILTER_FIRST_CONSTANT
            };
            let first_candidates =
                aarch64_emit_start_filter_batch_candidates(assembler, filter, first_register)?;
            batch_first_candidates = Some(first_candidates);
            aarch64_emit_candidate_batch_any(assembler, first_candidates)?;
            assembler.branch_cond(
                AARCH64_NE,
                if suffix.vector_filter.is_some() {
                    batch_primary_hit
                } else if use_exact_asimd_lane {
                    batch_hit
                } else {
                    scalar
                },
            )?;
            assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES)?)?;
            assembler.branch(vector)?;
        }

        assembler.bind(single_vector)?;
        let vector_bytes = u16::from(maximum_scan_offset).checked_add(16).ok_or(
            ObjectError::ArithmeticOverflow("AArch64 suffix-filter width"),
        )?;
        assembler.instruction(aarch64_cmp_x_imm(12, vector_bytes)?)?;
        assembler.branch_cond(AARCH64_LO, scalar)?;
        aarch64_emit_start_filter_address(assembler, filter.scan_offset)?;
        assembler.instruction(aarch64_load_q(0, 12)?)?;
        if suffix.vector_filter.is_some() {
            aarch64_emit_start_filter_vector_candidates(
                assembler,
                filter,
                0,
                24,
                AARCH64_VECTOR_FILTER_FIRST_CONSTANT,
            )?;
            aarch64_emit_candidate_any(assembler, 24)?;
            assembler.branch_cond(AARCH64_NE, single_primary_hit)?;
        } else {
            let first_register = AARCH64_STANDALONE_FILTER_FIRST_CONSTANT;
            aarch64_emit_start_filter_vector_candidates(assembler, filter, 0, 24, first_register)?;
            aarch64_emit_candidate_any(assembler, 24)?;
            assembler.branch_cond(
                AARCH64_NE,
                if use_exact_asimd_lane {
                    single_hit
                } else {
                    scalar
                },
            )?;
        }
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        assembler.branch(vector)?;

        if let Some(vector_filter) = suffix.vector_filter {
            assembler.bind(batch_primary_hit)?;
            if use_asimd_batch {
                aarch64_emit_vector_filter_secondary_batch(assembler, vector_filter)?;
                aarch64_emit_candidate_batch_any(assembler, 24)?;
                assembler.branch_cond(
                    AARCH64_NE,
                    if use_exact_asimd_lane {
                        batch_hit
                    } else {
                        scalar
                    },
                )?;
                assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES)?)?;
                assembler.branch(vector)?;
            } else {
                assembler.branch(scalar)?;
            }

            assembler.bind(single_primary_hit)?;
            aarch64_emit_vector_filter_secondary_candidates_at(assembler, vector_filter, 0, 24)?;
            aarch64_emit_candidate_any(assembler, 24)?;
            assembler.branch_cond(
                AARCH64_NE,
                if use_exact_asimd_lane {
                    single_hit
                } else {
                    scalar
                },
            )?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
            assembler.branch(vector)?;
        } else {
            assembler.bind(batch_primary_hit)?;
            assembler.branch(scalar)?;
            assembler.bind(single_primary_hit)?;
            assembler.branch(scalar)?;
        }

        let selected = if suffix.vector_filter.is_some() || suffix.scalar_filter.is_none() {
            apply
        } else {
            scalar_columns
        };
        assembler.bind(batch_hit)?;
        if use_exact_asimd_lane && let Some(first_candidates) = batch_first_candidates {
            aarch64_emit_first_candidate_in_batch(assembler, first_candidates)?;
            assembler.branch(selected)?;
        } else {
            assembler.branch(scalar)?;
        }
        assembler.bind(single_hit)?;
        if use_exact_asimd_lane {
            aarch64_emit_first_candidate_lane(assembler, 24)?;
            assembler.branch(selected)?;
        } else {
            assembler.branch(scalar)?;
        }
    } else {
        // Keep the labels complete even when the target deliberately omits
        // ASIMD and uses the scalar acceptance-boundary scan.
        assembler.bind(vector)?;
        assembler.branch(scalar)?;
        assembler.bind(single_vector)?;
        assembler.branch(scalar)?;
        assembler.bind(batch_primary_hit)?;
        assembler.branch(scalar)?;
        assembler.bind(single_primary_hit)?;
        assembler.branch(scalar)?;
        assembler.bind(batch_hit)?;
        assembler.branch(scalar)?;
        assembler.bind(single_hit)?;
        assembler.branch(scalar)?;
    }

    assembler.bind(scalar)?;
    aarch64_emit_start_filter_scalar_bound(assembler, maximum_scan_offset, no_match)?;
    aarch64_emit_start_filter_scalar_load(assembler, filter.scan_offset)?;
    let scalar_candidate = if scalar_filter.is_some() {
        scalar_columns
    } else {
        apply
    };
    for range in filter.ranges() {
        assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.start))?)?;
        if range.start == range.end {
            assembler.branch_cond(AARCH64_EQ, scalar_candidate)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch_cond(AARCH64_LO, next_range)?;
            assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.end))?)?;
            assembler.branch_cond(AARCH64_LS, scalar_candidate)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(scalar)?;

    if let Some(vector_filter) = scalar_filter {
        assembler.bind(scalar_columns)?;
        for &column in &vector_filter.columns()[1..] {
            aarch64_emit_scalar_filter_membership(assembler, column, scalar_reject)?;
        }
        assembler.branch(apply)?;
        assembler.bind(scalar_reject)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        assembler.branch(vector)?;
    } else {
        assembler.bind(scalar_columns)?;
        assembler.branch(apply)?;
        assembler.bind(scalar_reject)?;
        assembler.branch(scalar)?;
    }

    assembler.bind(apply)?;
    if let Some(retry) = suffix.retry {
        module_suffix_retry::aarch64_emit_bounded_suffix_retry(
            assembler, layout, retry, vector, no_match, matched,
        )?;
    } else {
        aarch64_emit_suffix_restart(assembler, suffix.restart)?;
    }
    assembler.bind(done)?;
    Ok(())
}

#[allow(
    clippy::large_types_passed_by_value,
    clippy::too_many_lines,
    reason = "the specialized forward/reverse control-flow graph is kept contiguous for auditing"
)]
#[cfg(test)]
fn lower_aarch64_dfa(
    layout: NativeDfaLayout,
    features: FeatureSet,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    lower_aarch64_dfa_for_operating_system(layout, features, OperatingSystem::Linux)
}

const fn aarch64_use_exact_first_lane(_operating_system: OperatingSystem) -> bool {
    true
}

#[allow(
    clippy::large_types_passed_by_value,
    clippy::too_many_lines,
    reason = "the specialized forward/reverse control-flow graph is kept contiguous for auditing"
)]
fn lower_aarch64_dfa_for_operating_system(
    layout: NativeDfaLayout,
    features: FeatureSet,
    operating_system: OperatingSystem,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = Aarch64Assembler::new();
    let scan = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let scalar_transition = assembler.label()?;
    let exceptional_transition = assembler.label()?;
    let accelerated_transition = assembler.label()?;
    let prefix_check = assembler.label()?;
    let prefix_vector_check = assembler.label()?;
    let prefix_verified = assembler.label()?;
    let prefix_apply = assembler.label()?;
    let prefix_fail = assembler.label()?;
    let prefix_retained_fail = assembler.label()?;
    let prefix_terminal = assembler.label()?;
    let filter_vector = assembler.label()?;
    let filter_single_vector = assembler.label()?;
    let filter_batch_primary_hit = assembler.label()?;
    let filter_single_primary_hit = assembler.label()?;
    let filter_batch_hit = assembler.label()?;
    let filter_single_hit = assembler.label()?;
    let filter_retained_exhausted = assembler.label()?;
    let filter_scalar = assembler.label()?;
    let filter_scalar_columns = assembler.label()?;
    let filter_scalar_reject = assembler.label()?;
    let accept = assembler.label()?;
    let after_accept = assembler.label()?;
    let finish = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid = assembler.label()?;
    let done = assembler.label()?;
    let reverse_scan = assembler.label()?;
    let reverse_exceptional_transition = assembler.label()?;
    let record_reverse_start = assembler.label()?;
    let reverse_continue = assembler.label()?;
    let reverse_finish = assembler.label()?;
    let exact_start_probe_failed = assembler.label()?;

    assembler.instruction(0xf100_003f)?; // cmp length, #0
    assembler.branch_cond(AARCH64_MI, invalid)?;
    assembler.instruction(aarch64_cmp_x(3, 1)?)?;
    assembler.branch_cond(AARCH64_HI, invalid)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HI, invalid)?;
    assembler.instruction(0xf100_009f)?; // cmp x4, #0
    assembler.branch_cond(AARCH64_EQ, invalid)?;
    assembler.instruction(aarch64_and_low_x(5, 4, 3)?)?;
    assembler.instruction(0xf100_00bf)?; // cmp alignment scratch, #0
    assembler.branch_cond(AARCH64_NE, invalid)?;
    assembler.instruction(0xf100_001f)?; // cmp x0, #0
    assembler.branch_cond(AARCH64_EQ, invalid)?;
    assembler.instruction(aarch64_mov_x(9, 2)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;

    let table_page = assembler.instruction(0x9000_0005)?;
    let table_page_offset = assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?;
    let use_asimd_filter = features.has(CpuFeature::Aarch64Asimd)
        && layout
            .start_filter
            .is_some_and(|filter| !filter.ranges().is_empty());
    let use_asimd_suffix = features.has(CpuFeature::Aarch64Asimd)
        && layout
            .suffix_filter
            .is_some_and(|suffix| !suffix.filter.ranges().is_empty());
    let use_asimd_suffix_batch = use_asimd_suffix
        && layout
            .suffix_filter
            .is_some_and(|suffix| use_aarch64_filter_batch(suffix.filter));
    let use_asimd_loop = features.has(CpuFeature::Aarch64Asimd) && layout.loop_skip.is_some();
    let prefix_relation_vector = layout
        .prefix_relation
        .and_then(|relation| relation.vector_plan);
    // Exact lane extraction wins on Apple Silicon, while generic Linux
    // AArch64 retains SIMD block rejection and refines a hit scalarly. This
    // target cost policy applies to every graph-derived filter uniformly.
    let use_exact_asimd_lane = aarch64_use_exact_first_lane(operating_system);
    let vector_filter = if prefix_relation_vector.is_some() {
        None
    } else {
        layout.vector_filter
    };
    let vector_coverage = use_asimd_filter
        .then(|| {
            derive_native_vector_guard_coverage(
                layout,
                prefix_relation_vector.is_some(),
                vector_filter,
            )
        })
        .flatten();
    let retain_vector_candidates = vector_coverage
        .map(|coverage| coverage.has_rejectable_residual(layout))
        .transpose()?
        .unwrap_or(false);
    // A 64-byte reduction pays when the graph-derived initial candidate set
    // is sparse. A rejectable residual guard needs its exact 16-lane mask and
    // therefore declines batching transactionally; fully proved masks retain
    // the established four-vector path.
    let use_asimd_relation_batch = use_asimd_filter
        && !retain_vector_candidates
        && prefix_relation_vector.is_some()
        && vector_coverage.is_some()
        && layout.start_filter.is_some_and(use_aarch64_filter_batch);
    let use_asimd_batch = use_asimd_filter
        && !retain_vector_candidates
        && (prefix_relation_vector.is_none() || use_asimd_relation_batch)
        && layout.start_filter.is_some_and(use_aarch64_filter_batch);
    if use_exact_asimd_lane && (use_asimd_filter || use_asimd_suffix || use_asimd_loop) {
        let lane_index_offset =
            layout
                .asimd_lane_index_offset
                .ok_or(ObjectError::InvalidModule(
                    "ASIMD candidate lowering has no lane-index table",
                ))?;
        aarch64_emit_first_lane_constants(&mut assembler, lane_index_offset)?;
    }
    let candidate = if layout.has_prefix_guard() {
        prefix_check
    } else if layout.prefix_fast_forward.is_some() {
        prefix_apply
    } else {
        scalar_scan
    };
    let use_prefix_block = features.has(CpuFeature::Aarch64Asimd) && layout.prefix_block.is_some();
    if layout.suffix_filter.is_some() && layout.exact_prefix_match_width.is_some() {
        aarch64_emit_exact_start_probe(
            &mut assembler,
            layout,
            use_prefix_block,
            exact_start_probe_failed,
            matched,
        )?;
        assembler.bind(exact_start_probe_failed)?;
    }
    if let Some(suffix) = layout.suffix_filter {
        aarch64_emit_suffix_prepass(
            &mut assembler,
            suffix,
            use_asimd_suffix,
            use_asimd_suffix_batch,
            use_exact_asimd_lane,
            layout,
            no_match,
            matched,
        )?;
    }
    aarch64_set_row_base(&mut assembler, layout.forward_offset)?;
    if layout.output != OutputContract::Exists {
        assembler.instruction(0x9280_000d)?; // movn x13, #0
        assembler.instruction(aarch64_mov_x(7, 13)?)?;
    }
    if use_asimd_filter {
        let filter = layout.start_filter.ok_or(ObjectError::InvalidModule(
            "ASIMD start filter has no graph filter",
        ))?;
        if let Some(plan) = prefix_relation_vector {
            aarch64_emit_prefix_relation_constants(&mut assembler, plan)?;
        } else if let Some(vector_filter) = vector_filter {
            let mut first_register = AARCH64_VECTOR_FILTER_FIRST_CONSTANT;
            for &column in vector_filter.columns() {
                aarch64_emit_start_filter_constants(&mut assembler, column, first_register)?;
                first_register = first_register
                    .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                        ObjectError::ArithmeticOverflow("AArch64 vector-filter constants")
                    })?)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "AArch64 vector-filter constants",
                    ))?;
            }
        } else {
            let first_register = AARCH64_STANDALONE_FILTER_FIRST_CONSTANT;
            aarch64_emit_start_filter_constants(&mut assembler, filter, first_register)?;
        }
    }
    let mut filter_batch_first_candidates = None;

    if layout.initial_pending {
        if layout.output == OutputContract::Exists {
            assembler.branch(matched)?;
        } else {
            assembler.instruction(aarch64_mov_x(7, 2)?)?;
            if layout.initial_terminal {
                assembler.branch(finish)?;
            }
        }
    }

    assembler.bind(scan)?;
    if let Some(filter) = layout.start_filter {
        if layout.output != OutputContract::Exists {
            assembler.instruction(aarch64_cmp_x(7, 13)?)?;
            assembler.branch_cond(AARCH64_NE, scalar_scan)?;
        }
        aarch64_set_table_address(&mut assembler, 12, layout.forward_offset)?;
        assembler.instruction(aarch64_cmp_x(11, 12)?)?;
        assembler.branch_cond(AARCH64_NE, scalar_scan)?;

        if filter.ranges().is_empty() {
            assembler.instruction(aarch64_mov_x(2, 3)?)?;
            assembler.branch(finish)?;
        } else {
            let maximum_scan_offset = prefix_relation_vector.map_or_else(
                || vector_filter.map_or(filter.scan_offset, NativeVectorFilter::max_scan_offset),
                |_| 1,
            );
            if use_asimd_filter {
                assembler.bind(filter_vector)?;
                assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
                if use_asimd_batch {
                    let batch_bytes = u16::from(maximum_scan_offset)
                        .checked_add(AARCH64_BATCH_BYTES)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "ASIMD batch start-filter width",
                        ))?;
                    assembler.instruction(aarch64_cmp_x_imm(12, batch_bytes)?)?;
                    assembler.branch_cond(AARCH64_LO, filter_single_vector)?;
                    let first_candidates = if let Some(plan) = prefix_relation_vector {
                        if !use_asimd_relation_batch {
                            return Err(ObjectError::InvalidModule(
                                "ASIMD relation batch escaped its proof gate",
                            ));
                        }
                        aarch64_emit_prefix_relation_batch_candidates(&mut assembler, plan)?
                    } else {
                        let first_register = if vector_filter.is_some() {
                            AARCH64_VECTOR_FILTER_FIRST_CONSTANT
                        } else {
                            AARCH64_STANDALONE_FILTER_FIRST_CONSTANT
                        };
                        aarch64_emit_start_filter_batch_candidates(
                            &mut assembler,
                            filter,
                            first_register,
                        )?
                    };
                    filter_batch_first_candidates = Some(first_candidates);
                    aarch64_emit_candidate_batch_any(&mut assembler, first_candidates)?;
                    assembler.branch_cond(
                        AARCH64_NE,
                        if vector_filter.is_some() {
                            filter_batch_primary_hit
                        } else if use_exact_asimd_lane {
                            filter_batch_hit
                        } else {
                            filter_scalar
                        },
                    )?;
                    assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES)?)?;
                    assembler.branch(filter_vector)?;
                }
                assembler.bind(filter_single_vector)?;
                let vector_bytes = u16::from(maximum_scan_offset).checked_add(16).ok_or(
                    ObjectError::ArithmeticOverflow("ASIMD start-filter vector width"),
                )?;
                assembler.instruction(aarch64_cmp_x_imm(12, vector_bytes)?)?;
                assembler.branch_cond(AARCH64_LO, filter_scalar)?;
                if let Some(plan) = prefix_relation_vector {
                    aarch64_emit_prefix_relation_vector_test(&mut assembler, plan)?;
                } else {
                    aarch64_emit_start_filter_address(&mut assembler, filter.scan_offset)?;
                    assembler.instruction(aarch64_load_q(0, 12)?)?;
                }
                if prefix_relation_vector.is_some() {
                    // The exact relation helper already reduced V24 and left
                    // condition flags ready for the shared hit branch.
                } else if vector_filter.is_some() {
                    aarch64_emit_start_filter_vector_candidates(
                        &mut assembler,
                        filter,
                        0,
                        24,
                        AARCH64_VECTOR_FILTER_FIRST_CONSTANT,
                    )?;
                    aarch64_emit_candidate_any(&mut assembler, 24)?;
                } else {
                    let first_register = AARCH64_STANDALONE_FILTER_FIRST_CONSTANT;
                    aarch64_emit_start_filter_vector_candidates(
                        &mut assembler,
                        filter,
                        0,
                        24,
                        first_register,
                    )?;
                    aarch64_emit_candidate_any(&mut assembler, 24)?;
                }
                assembler.branch_cond(
                    AARCH64_NE,
                    if vector_filter.is_some() {
                        filter_single_primary_hit
                    } else if use_exact_asimd_lane {
                        filter_single_hit
                    } else {
                        filter_scalar
                    },
                )?;
                assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
                assembler.branch(filter_vector)?;

                if let Some(vector_filter) = vector_filter {
                    if use_asimd_batch {
                        assembler.bind(filter_batch_primary_hit)?;
                        aarch64_emit_vector_filter_secondary_batch(&mut assembler, vector_filter)?;
                        aarch64_emit_candidate_batch_any(&mut assembler, 24)?;
                        assembler.branch_cond(
                            AARCH64_NE,
                            if use_exact_asimd_lane {
                                filter_batch_hit
                            } else {
                                filter_scalar
                            },
                        )?;
                        assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES)?)?;
                        assembler.branch(filter_vector)?;
                    }

                    assembler.bind(filter_single_primary_hit)?;
                    aarch64_emit_vector_filter_secondary_candidates_at(
                        &mut assembler,
                        vector_filter,
                        0,
                        24,
                    )?;
                    aarch64_emit_candidate_any(&mut assembler, 24)?;
                    assembler.branch_cond(
                        AARCH64_NE,
                        if use_exact_asimd_lane {
                            filter_single_hit
                        } else {
                            filter_scalar
                        },
                    )?;
                    assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
                    assembler.branch(filter_vector)?;
                }

                assembler.bind(filter_batch_hit)?;
                if use_exact_asimd_lane
                    && let Some(first_candidates) = filter_batch_first_candidates
                {
                    aarch64_emit_first_candidate_in_batch(&mut assembler, first_candidates)?;
                    assembler.branch(if vector_coverage.is_some() {
                        prefix_vector_check
                    } else {
                        candidate
                    })?;
                } else {
                    assembler.branch(filter_scalar)?;
                }
                assembler.bind(filter_single_hit)?;
                if use_exact_asimd_lane {
                    if retain_vector_candidates {
                        assembler.instruction(aarch64_mov_x(14, 2)?)?;
                        aarch64_emit_first_retained_candidate_lane(&mut assembler, 24, 14)?;
                    } else {
                        aarch64_emit_first_candidate_lane(&mut assembler, 24)?;
                    }
                    assembler.branch(if vector_coverage.is_some() {
                        prefix_vector_check
                    } else {
                        candidate
                    })?;
                } else {
                    assembler.branch(filter_scalar)?;
                }
            }

            assembler.bind(filter_scalar)?;
            aarch64_emit_start_filter_scalar_bound(&mut assembler, maximum_scan_offset, finish)?;
            aarch64_emit_start_filter_scalar_load(&mut assembler, filter.scan_offset)?;
            let scalar_candidate = if vector_filter.is_some() {
                filter_scalar_columns
            } else {
                candidate
            };
            for range in filter.ranges() {
                assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.start))?)?;
                if range.start == range.end {
                    assembler.branch_cond(AARCH64_EQ, scalar_candidate)?;
                } else {
                    let next_range = assembler.label()?;
                    assembler.branch_cond(AARCH64_LO, next_range)?;
                    assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.end))?)?;
                    assembler.branch_cond(AARCH64_LS, scalar_candidate)?;
                    assembler.bind(next_range)?;
                }
            }
            assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
            assembler.branch(filter_scalar)?;

            if let Some(vector_filter) = vector_filter {
                assembler.bind(filter_scalar_columns)?;
                for &column in &vector_filter.columns()[1..] {
                    aarch64_emit_scalar_filter_membership(
                        &mut assembler,
                        column,
                        filter_scalar_reject,
                    )?;
                }
                assembler.branch(candidate)?;
                assembler.bind(filter_scalar_reject)?;
                assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
                assembler.branch(filter_scalar)?;
            }
        }
    }

    if layout.has_prefix_guard() {
        assembler.bind(prefix_check)?;
        aarch64_emit_prefix_guard_path(
            &mut assembler,
            layout,
            use_prefix_block,
            None,
            prefix_fail,
            prefix_terminal,
            prefix_verified,
        )?;
        assembler.bind(prefix_fail)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        aarch64_set_row_base(&mut assembler, layout.forward_offset)?;
        assembler.branch(scan)?;

        if let Some(coverage) = vector_coverage {
            assembler.bind(prefix_vector_check)?;
            aarch64_emit_prefix_guard_path(
                &mut assembler,
                layout,
                use_prefix_block,
                Some(coverage),
                if retain_vector_candidates {
                    prefix_retained_fail
                } else {
                    prefix_fail
                },
                prefix_terminal,
                prefix_verified,
            )?;
        }
        if retain_vector_candidates {
            assembler.bind(prefix_retained_fail)?;
            // Keep V24 intact. Form an exact `lane >= rejected + 1` mask in
            // V28, intersect it with the retained candidates, and select the
            // next lane relative to caller-saved X14.
            assembler.instruction(aarch64_add_x_imm(12, 2, 1)?)?;
            assembler.instruction(aarch64_sub_x_reg(12, 12, 14)?)?;
            assembler.instruction(aarch64_dup_16b_from_w(28, 12)?)?;
            assembler.instruction(aarch64_cmhs_16b(28, 29, 28)?)?;
            assembler.instruction(aarch64_and_16b(28, 28, 24)?)?;
            aarch64_emit_candidate_any(&mut assembler, 28)?;
            assembler.branch_cond(AARCH64_EQ, filter_retained_exhausted)?;
            aarch64_emit_first_retained_candidate_lane(&mut assembler, 28, 14)?;
            aarch64_set_row_base(&mut assembler, layout.forward_offset)?;
            assembler.branch(prefix_vector_check)?;

            assembler.bind(filter_retained_exhausted)?;
            assembler.instruction(aarch64_add_x_imm(2, 14, 16)?)?;
            aarch64_set_row_base(&mut assembler, layout.forward_offset)?;
            assembler.branch(filter_vector)?;
        }

        assembler.bind(prefix_terminal)?;
        assembler.branch(finish)?;

        assembler.bind(prefix_verified)?;
        if let Some(width) = layout.exact_prefix_match_width {
            aarch64_emit_exact_prefix_match(&mut assembler, width, layout.output, matched)?;
        } else {
            assembler.branch(prefix_apply)?;
        }
    }

    assembler.bind(prefix_apply)?;
    aarch64_set_row_base(&mut assembler, layout.forward_offset)?;
    if let Some(plan) = layout.prefix_fast_forward {
        assembler.instruction(aarch64_add_x_imm(2, 2, u16::from(plan.consumed_bytes))?)?;
        aarch64_set_row_base(&mut assembler, plan.target_row_offset)?;
    }
    assembler.bind(scalar_scan)?;
    if let Some(plan) = layout.loop_skip {
        module_dfa_loop_skip::aarch64_emit_dfa_loop_skip(
            &mut assembler,
            plan,
            &layout,
            vector_filter,
            use_asimd_loop,
            use_exact_asimd_lane,
            scalar_transition,
            finish,
        )?;
    }
    assembler.bind(scalar_transition)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, finish)?;
    aarch64_emit_table_lookup(&mut assembler, layout.transitions)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    aarch64_emit_ordinary_live_row(&mut assembler, exceptional_transition)?;
    assembler.branch(scalar_transition)?;

    assembler.bind(exceptional_transition)?;
    assembler.branch_bit_set_w(8, 31, accept)?;
    assembler.bind(after_accept)?;
    assembler.branch_bit_set_w(8, 30, accelerated_transition)?;
    assembler.instruction(aarch64_and_low_w(6, 8, 30)?)?;
    assembler.branch_zero_w(6, finish)?;
    assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
    assembler.instruction(
        0x8b00_0000 | aarch64_reg(6, 16)? | aarch64_reg(5, 5)? | aarch64_reg(11, 0)?,
    )?;
    assembler.branch(scalar_transition)?;

    assembler.bind(accelerated_transition)?;
    assembler.instruction(aarch64_and_low_w(6, 8, 30)?)?;
    assembler.branch_zero_w(6, finish)?;
    assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
    assembler.instruction(
        0x8b00_0000 | aarch64_reg(6, 16)? | aarch64_reg(5, 5)? | aarch64_reg(11, 0)?,
    )?;
    assembler.branch(scan)?;

    assembler.bind(accept)?;
    if layout.output == OutputContract::Exists {
        assembler.branch(matched)?;
    } else {
        assembler.instruction(aarch64_mov_x(7, 2)?)?;
        assembler.branch(after_accept)?;
    }

    assembler.bind(finish)?;
    if layout.output == OutputContract::Exists {
        assembler.branch(no_match)?;
    } else {
        assembler.instruction(aarch64_cmp_x(7, 13)?)?;
        assembler.branch_cond(AARCH64_EQ, no_match)?;
    }
    if layout.output == OutputContract::Span && !layout.initial_pending {
        if layout.exact_span_width.is_none() && !layout.has_reverse {
            return Err(ObjectError::InvalidModule(
                "AArch64 span lowering has no reverse table",
            ));
        }
    } else {
        if layout.output == OutputContract::Span {
            assembler.instruction(aarch64_store_x(9, 4, 0)?)?;
            assembler.instruction(aarch64_store_x(7, 4, 8)?)?;
        } else if layout.output == OutputContract::SelectedEnd {
            assembler.instruction(aarch64_store_x(7, 4, 0)?)?;
            assembler.instruction(aarch64_store_x(7, 4, 8)?)?;
        }
        assembler.branch(matched)?;
    }

    if layout.output == OutputContract::Span && !layout.initial_pending {
        assembler.instruction(aarch64_store_x(7, 4, 8)?)?;
        if let Some(width) = layout.exact_span_width {
            if layout.has_reverse {
                return Err(ObjectError::InvalidModule(
                    "fixed-width AArch64 span unexpectedly retained a reverse table",
                ));
            }
            aarch64_emit_exact_span_start(&mut assembler, width)?;
            assembler.instruction(aarch64_store_x(6, 4, 0)?)?;
            assembler.branch(matched)?;
        } else {
            assembler.instruction(aarch64_mov_x(2, 7)?)?;
            assembler.instruction(aarch64_mov_x(10, 13)?)?;
            aarch64_set_row_base(&mut assembler, layout.reverse_offset)?;
            assembler.bind(reverse_scan)?;
            assembler.instruction(aarch64_cmp_x(2, 9)?)?;
            assembler.branch_cond(AARCH64_LS, reverse_finish)?;
            assembler.instruction(aarch64_sub_x_imm(2, 2, 1)?)?;
            aarch64_emit_table_lookup(&mut assembler, layout.transitions)?;
            aarch64_emit_ordinary_live_row(&mut assembler, reverse_exceptional_transition)?;
            assembler.branch(reverse_scan)?;

            assembler.bind(reverse_exceptional_transition)?;
            assembler.branch_bit_set_w(8, 31, record_reverse_start)?;
            assembler.bind(reverse_continue)?;
            // Keep the same low-30-bit payload contract as forward cells;
            // reverse packing proves the acceleration flag is clear.
            assembler.instruction(aarch64_and_low_w(6, 8, 30)?)?;
            assembler.branch_zero_w(6, reverse_finish)?;
            assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
            assembler.instruction(
                0x8b00_0000 | aarch64_reg(6, 16)? | aarch64_reg(5, 5)? | aarch64_reg(11, 0)?,
            )?;
            assembler.branch(reverse_scan)?;

            assembler.bind(record_reverse_start)?;
            assembler.instruction(aarch64_mov_x(10, 2)?)?;
            assembler.branch(reverse_continue)?;

            assembler.bind(reverse_finish)?;
            assembler.instruction(aarch64_cmp_x(10, 13)?)?;
            assembler.branch_cond(AARCH64_EQ, invalid)?;
            assembler.instruction(aarch64_store_x(10, 4, 0)?)?;
            assembler.branch(matched)?;
        }
    }

    assembler.bind(no_match)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.branch(done)?;
    assembler.bind(matched)?;
    assembler.instruction(aarch64_movz_w(0, 1)?)?;
    assembler.branch(done)?;
    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.bind(done)?;
    assembler.instruction(0xd65f_03c0)?;

    let code = assembler.finish()?;
    Ok((
        code,
        vec![
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(table_page, "AArch64 DFA ADRP relocation offset")?,
                kind: RelocationKind::Aarch64Page21,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(table_page_offset, "AArch64 DFA ADD relocation offset")?,
                kind: RelocationKind::Aarch64PageOff12,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
        ],
    ))
}

fn aarch64_instruction(code: &mut Vec<u8>, instruction: u32) -> Result<(), ObjectError> {
    push_bytes(code, &instruction.to_le_bytes())
}

fn aarch64_mov(destination: u8, source: u8) -> u32 {
    // MOV Xd, Xm aliases ORR Xd, XZR, Xm.
    0xaa00_03e0 | (u32::from(source) << 16) | u32::from(destination)
}

fn lower_aarch64_runtime_adapter() -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = Aarch64Assembler::new();
    let invalid = assembler.label()?;

    assembler.instruction(0xf100_003f)?; // cmp length, #0
    assembler.branch_cond(AARCH64_MI, invalid)?;
    assembler.instruction(aarch64_cmp_x(3, 1)?)?;
    assembler.branch_cond(AARCH64_HI, invalid)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HI, invalid)?;
    assembler.instruction(0xf100_009f)?; // cmp x4, #0
    assembler.branch_cond(AARCH64_EQ, invalid)?;
    assembler.instruction(aarch64_and_low_x(5, 4, 3)?)?;
    assembler.instruction(0xf100_00bf)?; // cmp alignment scratch, #0
    assembler.branch_cond(AARCH64_NE, invalid)?;
    assembler.instruction(0xf100_001f)?; // cmp x0, #0
    assembler.branch_cond(AARCH64_EQ, invalid)?;

    // Shift x0..x4 to x1..x5, from high to low to avoid clobbering.
    assembler.instruction(aarch64_mov(5, 4))?;
    assembler.instruction(aarch64_mov(4, 3))?;
    assembler.instruction(aarch64_mov(3, 2))?;
    assembler.instruction(aarch64_mov(2, 1))?;
    assembler.instruction(aarch64_mov(1, 0))?;

    // adrp x0, program@PAGE
    let program_page = assembler.instruction(0x9000_0000)?;
    // add x0, x0, program@PAGEOFF
    let program_page_offset = assembler.instruction(0x9100_0000)?;
    // b runtime -- tail branch; no link register update.
    let runtime_branch = assembler.instruction(0x1400_0000)?;

    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.instruction(0xd65f_03c0)?;
    let code = assembler.finish()?;

    Ok((
        code,
        vec![
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(program_page, "AArch64 ADRP relocation offset")?,
                kind: RelocationKind::Aarch64Page21,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(program_page_offset, "AArch64 ADD relocation offset")?,
                kind: RelocationKind::Aarch64PageOff12,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(runtime_branch, "AArch64 branch relocation offset")?,
                kind: RelocationKind::Aarch64Branch26,
                symbol: RUNTIME_SYMBOL,
                addend: 0,
            },
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompileMode, CompileRequest, EngineKind, MatchResult, ObjectFormat, SearchWindow, compile,
        emit_object,
    };

    fn identity_target_matrix() -> Vec<Target> {
        let x86_features = [
            FeatureSet::of(CpuFeature::X86Sse2),
            FeatureSet::of(CpuFeature::X86Avx2),
            FeatureSet::of(CpuFeature::X86Avx512F)
                .with(CpuFeature::X86Avx512Bw)
                .with(CpuFeature::X86Avx512Vl),
        ];
        let aarch64_features = [
            FeatureSet::of(CpuFeature::Aarch64Asimd),
            FeatureSet::of(CpuFeature::Aarch64Sve),
            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
        ];
        let mut targets = vec![
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ];
        for base in [Target::x86_64_linux(), Target::x86_64_macos()] {
            for features in x86_features {
                targets.push(base.with_features(features).unwrap());
            }
        }
        for base in [Target::aarch64_linux(), Target::aarch64_macos()] {
            for features in aarch64_features {
                targets.push(base.with_features(features).unwrap());
            }
        }
        targets
    }

    fn x86_test_branch_target(code: &[u8], instruction: usize) -> Option<(usize, usize)> {
        let opcode = *code.get(instruction)?;
        let (length, displacement) = match opcode {
            0xeb | 0x70..=0x7f => {
                let displacement = i8::from_le_bytes([*code.get(instruction.checked_add(1)?)?]);
                (2_usize, isize::from(displacement))
            }
            0xe9 => {
                let start = instruction.checked_add(1)?;
                let end = start.checked_add(4)?;
                let displacement = i32::from_le_bytes(code.get(start..end)?.try_into().ok()?);
                (5_usize, isize::try_from(displacement).ok()?)
            }
            0x0f if matches!(code.get(instruction.checked_add(1)?), Some(0x80..=0x8f)) => {
                let start = instruction.checked_add(2)?;
                let end = start.checked_add(4)?;
                let displacement = i32::from_le_bytes(code.get(start..end)?.try_into().ok()?);
                (6_usize, isize::try_from(displacement).ok()?)
            }
            _ => return None,
        };
        let after = isize::try_from(instruction.checked_add(length)?).ok()?;
        let target = after.checked_add(displacement)?;
        Some((usize::try_from(target).ok()?, length))
    }

    fn aarch64_test_branch_target(instructions: &[u32], instruction: usize) -> Option<usize> {
        let word = *instructions.get(instruction)?;
        let (raw_immediate, bits) = if word & 0x7e00_0000 == 0x3400_0000 {
            ((word >> 5) & 0x7_ffff, 19_u32) // CBZ/CBNZ
        } else if word & 0xfc00_0000 == 0x1400_0000 {
            (word & 0x03ff_ffff, 26_u32) // B/BL
        } else {
            return None;
        };
        let signed = (i64::from(raw_immediate) << (64 - bits)) >> (64 - bits);
        let source = i64::try_from(instruction).ok()?;
        usize::try_from(source.checked_add(signed)?).ok()
    }

    #[test]
    fn target_matrix_has_the_platform_abi() {
        let cases = [
            (
                Target::x86_64_linux(),
                Architecture::X86_64,
                OperatingSystem::Linux,
                CallAbi::SystemV,
            ),
            (
                Target::x86_64_macos(),
                Architecture::X86_64,
                OperatingSystem::Macos,
                CallAbi::SystemV,
            ),
            (
                Target::aarch64_linux(),
                Architecture::Aarch64,
                OperatingSystem::Linux,
                CallAbi::Aapcs64,
            ),
            (
                Target::aarch64_macos(),
                Architecture::Aarch64,
                OperatingSystem::Macos,
                CallAbi::Aapcs64,
            ),
        ];
        for (target, architecture, operating_system, abi) in cases {
            assert_eq!(target.architecture, architecture);
            assert_eq!(target.operating_system, operating_system);
            assert_eq!(target.abi, abi);
            assert_eq!(target.validate(), Ok(()));
        }
    }

    #[test]
    fn aarch64_compare_and_test_branch_fixups_have_exact_encodings() {
        let mut assembler = Aarch64Assembler::new();
        let target = assembler.label().unwrap();
        assembler.branch_bit_set_w(8, 31, target).unwrap();
        assembler.branch_zero_w(6, target).unwrap();
        assembler.instruction(0xd503_201f).unwrap(); // nop
        assembler.bind(target).unwrap();
        let words = assembler
            .finish()
            .unwrap()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(words, [0x37f8_0068, 0x3400_0046, 0xd503_201f]);

        let mut invalid = Aarch64Assembler::new();
        let label = invalid.label().unwrap();
        assert!(invalid.branch_bit_set_w(8, 32, label).is_err());
        assert!(invalid.branch_bit_clear_w(8, 32, label).is_err());
    }

    #[test]
    #[allow(
        clippy::items_after_statements,
        reason = "the local lane oracle is kept beside the exact encoding assertions it models"
    )]
    fn aarch64_first_candidate_lowering_has_exact_encodings_and_lane_oracle() {
        assert_eq!(aarch64_bsl_16b(24, 29, 31).unwrap(), 0x6e7f_1fb8);
        assert_eq!(aarch64_bsl_16b(24, 28, 31).unwrap(), 0x6e7f_1f98);
        assert_eq!(aarch64_add_16b(28, 28, 30).unwrap(), 0x4e3e_879c);
        assert_eq!(aarch64_umin_16b(24, 24, 25).unwrap(), 0x6e39_6f18);
        assert_eq!(aarch64_uminv_16b(24, 24).unwrap(), 0x6e31_ab18);
        assert_eq!(aarch64_csel_x(7, 7, 2, AARCH64_EQ).unwrap(), 0x9a82_00e7);

        let mut assembler = Aarch64Assembler::new();
        aarch64_emit_first_candidate_in_batch(&mut assembler, 24).unwrap();
        let words = assembler
            .finish()
            .unwrap()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            words,
            [
                aarch64_orr_16b(28, 29, 29).unwrap(),
                aarch64_bsl_16b(24, 28, 31).unwrap(),
                aarch64_add_16b(28, 28, 30).unwrap(),
                aarch64_bsl_16b(25, 28, 31).unwrap(),
                aarch64_add_16b(28, 28, 30).unwrap(),
                aarch64_bsl_16b(26, 28, 31).unwrap(),
                aarch64_add_16b(28, 28, 30).unwrap(),
                aarch64_bsl_16b(27, 28, 31).unwrap(),
                aarch64_umin_16b(24, 24, 25).unwrap(),
                aarch64_umin_16b(26, 26, 27).unwrap(),
                aarch64_umin_16b(24, 24, 26).unwrap(),
                aarch64_uminv_16b(24, 24).unwrap(),
                aarch64_umov_b0(12, 24).unwrap(),
                aarch64_add_x_reg(2, 2, 12).unwrap(),
            ]
        );

        fn lowered_first_lane(masks: &[[u8; 16]]) -> Option<usize> {
            let mut selected = 64_u8;
            for (block, mask) in masks.iter().enumerate() {
                for (lane, &candidate) in mask.iter().enumerate() {
                    let absolute = u8::try_from(block * 16 + lane).unwrap();
                    let lowered = if candidate == 0xff { absolute } else { 64 };
                    selected = selected.min(lowered);
                }
            }
            (usize::from(selected) < masks.len() * 16).then_some(usize::from(selected))
        }

        for blocks in [1_usize, 2, 4] {
            let empty = vec![[0_u8; 16]; blocks];
            assert_eq!(lowered_first_lane(&empty), None);
            for expected in 0..blocks * 16 {
                let mut masks = empty.clone();
                masks[expected / 16][expected % 16] = 0xff;
                if expected + 7 < blocks * 16 {
                    masks[(expected + 7) / 16][(expected + 7) % 16] = 0xff;
                }
                assert_eq!(lowered_first_lane(&masks), Some(expected));
            }
        }

        let compiled = compile(
            CompileRequest::new("[abcd]", Target::aarch64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let (data, layout) = build_native_dfa_table_for_architecture(
            compiled.program().native_dfa_view().unwrap(),
            Architecture::Aarch64,
        )
        .unwrap();
        let offset = usize::try_from(layout.asimd_lane_index_offset.unwrap()).unwrap();
        assert_eq!(offset % AARCH64_FIRST_LANE_INDEX.len(), 0);
        assert_eq!(
            &data[offset..offset + AARCH64_FIRST_LANE_INDEX.len()],
            &AARCH64_FIRST_LANE_INDEX
        );
        assert_eq!(data.len(), offset + AARCH64_FIRST_LANE_INDEX.len());
    }

    #[test]
    fn x86_assembler_relaxes_only_bound_in_range_branches() {
        let mut assembler = X86Assembler::new();
        let near = assembler.label().unwrap();
        assembler.bind(near).unwrap();
        assembler.instruction(&[0x90]).unwrap();
        assembler.branch(&[0xe9], near).unwrap();
        assembler.branch(&[0x0f, 0x85], near).unwrap();

        let far = assembler.label().unwrap();
        assembler.bind(far).unwrap();
        for _ in 0..128 {
            assembler.instruction(&[0x90]).unwrap();
        }
        assembler.branch(&[0xe9], far).unwrap();

        let forward = assembler.label().unwrap();
        assembler.branch(&[0xe9], forward).unwrap();
        assembler.bind(forward).unwrap();

        let code = assembler.finish().unwrap();
        assert_eq!(&code[..5], &[0x90, 0xeb, 0xfd, 0x75, 0xfb]);
        assert_eq!(&code[133..138], &[0xe9, 0x7b, 0xff, 0xff, 0xff]);
        assert_eq!(&code[138..], &[0xe9, 0, 0, 0, 0]);
    }

    #[test]
    fn sparse_batch_admission_uses_stable_frequency_and_instruction_cost() {
        let one_range = |start: u8, end: u8| {
            let mut filter = EMPTY_NATIVE_START_FILTER;
            filter.ranges[0] = NativeByteRange { start, end };
            filter.range_count = 1;
            filter.candidate_bytes = u16::from(end) - u16::from(start) + 1;
            filter
        };

        let rare = one_range(1, 1);
        assert_eq!(estimated_filter_frequency_units(rare), 1);
        assert!(use_aarch64_filter_batch(rare));
        for kind in [
            X86StartFilterKind::Sse2,
            X86StartFilterKind::Avx2,
            X86StartFilterKind::Avx512Bw,
        ] {
            assert!(x86_use_sparse_filter_mask_batch(rare, kind));
        }

        // Cardinality alone used to reject this five-byte range. The stable
        // model assigns two units to each digit, making it cheap enough for
        // the exact-lane 64-byte batch.
        let digits = one_range(b'3', b'7');
        assert_eq!(digits.candidate_bytes, 5);
        assert_eq!(estimated_filter_frequency_units(digits), 10);
        assert!(use_aarch64_filter_batch(digits));

        let common = one_range(b'e', b'e');
        assert_eq!(estimated_filter_frequency_units(common), 24);
        assert!(!use_aarch64_filter_batch(common));

        let mut expensive = EMPTY_NATIVE_START_FILTER;
        for (index, byte) in (1_u8..=8).enumerate() {
            expensive.ranges[index] = NativeByteRange {
                start: byte,
                end: byte,
            };
        }
        expensive.range_count = 8;
        expensive.candidate_bytes = 8;
        assert!(estimated_filter_frequency_units(expensive) <= 8);
        assert!(vector_filter_instruction_units(expensive) > MAX_VECTOR_FILTER_INSTRUCTION_UNITS);
        assert!(!use_aarch64_filter_batch(expensive));
    }

    #[test]
    fn x86_sparse_mask_batch_helpers_have_exact_abi_safe_encodings() {
        let mut filter = EMPTY_NATIVE_START_FILTER;
        filter.ranges[0] = NativeByteRange { start: 1, end: 1 };
        filter.range_count = 1;
        filter.candidate_bytes = 1;

        let x86_cases = [
            (
                X86StartFilterKind::Sse2,
                &[0x66, 0x45, 0x0f, 0xef, 0xff][..],
                &[0x66, 0x45, 0x0f, 0xeb, 0xfc][..],
                &[0x66, 0x41, 0x0f, 0xd7, 0xc7, 0x85, 0xc0][..],
            ),
            (
                X86StartFilterKind::Avx2,
                &[0xc4, 0x41, 0x05, 0xef, 0xff][..],
                &[0xc4, 0x41, 0x05, 0xeb, 0xfc][..],
                &[0xc4, 0xc1, 0x7d, 0xd7, 0xc7, 0x85, 0xc0][..],
            ),
            (
                X86StartFilterKind::Avx512Bw,
                &[0xc4, 0xe1, 0xcc, 0x47, 0xf6][..],
                &[0xc4, 0xe1, 0xcc, 0x45, 0xf1][..],
                &[0xc4, 0xe1, 0xf8, 0x98, 0xf6][..],
            ),
        ];
        for (kind, clear, merge, reduce) in x86_cases {
            let mut assembler = X86Assembler::new();
            x86_emit_sparse_filter_mask_batch(&mut assembler, filter, kind).unwrap();
            let code = assembler.finish().unwrap();
            assert!(code.starts_with(clear));
            assert_eq!(
                code.windows(merge.len())
                    .filter(|window| *window == merge)
                    .count(),
                usize::from(X86_MASK_BATCH_VECTORS)
            );
            assert!(code.windows(reduce.len()).any(|window| window == reduce));
        }
    }

    #[test]
    fn x86_adaptive_suffix_cfg_has_exact_cross_isa_edges() {
        fn offsets(code: &[u8], instruction: &[u8]) -> Vec<usize> {
            code.windows(instruction.len())
                .enumerate()
                .filter_map(|(offset, window)| (window == instruction).then_some(offset))
                .collect()
        }

        const PATTERNS: [&str; 2] = [
            r"(?:(?:(?:(?:(?:(?:QtJHg[I-K])){2,3}){1,3}?)+?9(?:(?:[J-M]){2,3}?){1,4}?)(?-u:[\x00-\xFF]))",
            r"(?:(?:(?:(?:(?:(?:QtJHg[I-L])){2,3}){1,3}?)+?8(?:(?:[J-N]){2,3}?){1,4}?)(?-u:[\x00-\xFF]))",
        ];
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let cases = [
            (
                Target::x86_64_linux(),
                &[0x66, 0x45, 0x0f, 0xef, 0xff][..],
                &[0x66, 0x45, 0x0f, 0xeb, 0xfc][..],
                &[0x66, 0x44, 0x0f, 0xeb, 0xff][..],
                &[0x66, 0x41, 0x0f, 0xd7, 0xc7, 0x85, 0xc0][..],
                &[0x48, 0x83, 0xea, 64][..],
            ),
            (
                Target::x86_64_linux()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                &[0xc4, 0x41, 0x05, 0xef, 0xff][..],
                &[0xc4, 0x41, 0x05, 0xeb, 0xfc][..],
                &[0xc4, 0x61, 0x05, 0xeb, 0xff][..],
                &[0xc4, 0xc1, 0x7d, 0xd7, 0xc7, 0x85, 0xc0][..],
                &[0x48, 0x81, 0xea, 128, 0, 0, 0][..],
            ),
            (
                Target::x86_64_linux().with_features(avx512).unwrap(),
                &[0xc4, 0xe1, 0xcc, 0x47, 0xf6][..],
                &[0xc4, 0xe1, 0xcc, 0x45, 0xf1][..],
                &[0xc4, 0xe1, 0xcc, 0x45, 0xf5][..],
                &[0xc4, 0xe1, 0xf8, 0x98, 0xf6][..],
                &[0x48, 0x81, 0xea, 0, 1, 0, 0][..],
            ),
        ];

        for pattern in PATTERNS {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                for (target, clear, primary_merge, joint_merge, reduce, rewind) in cases {
                    let compiled = compile(
                        CompileRequest::new(pattern, target)
                            .mode(CompileMode::Optimizing)
                            .output(output),
                    )
                    .unwrap();
                    let code = compiled.module().sections()[TEXT_SECTION].bytes();
                    let clears = offsets(code, clear);
                    let primary_merges = offsets(code, primary_merge);
                    let joint_merges = offsets(code, joint_merge);
                    let reductions = offsets(code, reduce);
                    let rewinds = offsets(code, rewind);
                    assert_eq!(clears.len(), 2, "{target:?} {output:?}");
                    assert_eq!(primary_merges.len(), 4, "{target:?} {output:?}");
                    assert_eq!(joint_merges.len(), 4, "{target:?} {output:?}");
                    assert_eq!(reductions.len(), 2, "{target:?} {output:?}");
                    assert!(!rewinds.is_empty(), "{target:?} {output:?}");

                    // Both loops have the same 18-byte remaining/bounds
                    // prelude before their accumulator clear.
                    let primary_loop = clears[0] - 18;
                    let joint_loop = clears[1] - 18;
                    let primary_hit_branch = reductions[0] + reduce.len();
                    let (rewind_block, _) =
                        x86_test_branch_target(code, primary_hit_branch).unwrap();
                    assert!(primary_hit_branch < rewind_block);
                    assert_eq!(
                        &code[rewind_block..rewind_block + rewind.len()],
                        rewind,
                        "{target:?} {output:?}"
                    );
                    for (index, loop_start) in
                        [(reductions[0], primary_loop), (reductions[1], joint_loop)]
                    {
                        let hit_branch = index + reduce.len();
                        assert_eq!(&code[hit_branch..hit_branch + 2], &[0x0f, 0x85]);
                        let (_, hit_length) = x86_test_branch_target(code, hit_branch).unwrap();
                        assert_eq!(
                            x86_test_branch_target(code, hit_branch).unwrap().0,
                            rewind_block
                        );
                        let miss_branch = hit_branch + hit_length;
                        assert_eq!(
                            x86_test_branch_target(code, miss_branch).unwrap().0,
                            loop_start
                        );
                        assert!(miss_branch > loop_start);
                    }
                    assert!(reductions[1] > rewind_block);

                    // The shared hit block performs exactly one rewind and
                    // enters the duplicated scalar replay. The only inc/jmp
                    // edge back to the joint loop is its secondary rejection.
                    let replay_branch = rewind_block + rewind.len();
                    assert_eq!(code[replay_branch], 0xe9);
                    let (replay, _) = x86_test_branch_target(code, replay_branch).unwrap();
                    assert!(replay_branch < replay);
                    assert!(replay > joint_loop);
                    assert_eq!(&code[replay..replay + 4], &[0x48, 0x8d, 0x42, 0x06]);
                    let adaptive_rejections = (0..code.len().saturating_sub(3))
                        .filter(|&offset| {
                            code[offset..].starts_with(&[0x48, 0xff, 0xc2])
                                && x86_test_branch_target(code, offset + 3)
                                    .is_some_and(|(target, _)| target == joint_loop)
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(adaptive_rejections.len(), 1, "{target:?} {output:?}");
                    assert!(adaptive_rejections[0] > joint_loop);
                }
            }
        }
    }

    #[test]
    fn x86_adaptive_suffix_cold_split_preserves_dormant_hot_layout() {
        fn offsets(code: &[u8], instruction: &[u8]) -> Vec<usize> {
            code.windows(instruction.len())
                .enumerate()
                .filter_map(|(offset, window)| (window == instruction).then_some(offset))
                .collect()
        }

        fn rel32_target(code: &[u8], instruction: usize, displacement: usize, len: usize) -> usize {
            let start = instruction + displacement;
            let relative = i32::from_le_bytes(code[start..start + 4].try_into().unwrap());
            usize::try_from(
                isize::try_from(instruction + len).unwrap() + isize::try_from(relative).unwrap(),
            )
            .unwrap()
        }

        fn assert_canonical_nop_padding(mut code: &[u8]) {
            const NOP9: &[u8] = &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
            while code.len() >= NOP9.len() {
                assert!(code.starts_with(NOP9));
                code = &code[NOP9.len()..];
            }
            let expected = match code.len() {
                0 => &[][..],
                1 => &[0x90][..],
                2 => &[0x66, 0x90][..],
                3 => &[0x0f, 0x1f, 0x00][..],
                4 => &[0x0f, 0x1f, 0x40, 0x00][..],
                5 => &[0x0f, 0x1f, 0x44, 0x00, 0x00][..],
                6 => &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00][..],
                7 => &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00][..],
                8 => &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00][..],
                _ => unreachable!(),
            };
            assert_eq!(code, expected);
        }

        const PATTERNS: [&str; 2] = [
            r"(?:(?:(?:(?:(?:(?:QtJHg[I-K])){2,3}){1,3}?)+?9(?:(?:[J-M]){2,3}?){1,4}?)(?-u:[\x00-\xFF]))",
            r"(?:(?:(?:(?:(?:(?:QtJHg[I-L])){2,3}){1,3}?)+?8(?:(?:[J-N]){2,3}?){1,4}?)(?-u:[\x00-\xFF]))",
        ];
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let cases = [
            (
                FeatureSet::EMPTY,
                &[0x66, 0x41, 0x0f, 0xd7, 0xc7, 0x85, 0xc0][..],
                &[0x48, 0x83, 0xea, 64][..],
            ),
            (
                FeatureSet::of(CpuFeature::X86Avx2),
                &[0xc4, 0xc1, 0x7d, 0xd7, 0xc7, 0x85, 0xc0][..],
                &[0x48, 0x81, 0xea, 128, 0, 0, 0][..],
            ),
            (
                avx512,
                &[0xc4, 0xe1, 0xf8, 0x98, 0xf6][..],
                &[0x48, 0x81, 0xea, 0, 1, 0, 0][..],
            ),
        ];

        assert!(SUFFIX_PREFILTER_MIN_WINDOW_BYTES > 64);
        for pattern in PATTERNS {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let compiled = compile(
                    CompileRequest::new(pattern, Target::x86_64_linux())
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                let adaptive = build_native_dfa_table_for_architecture(
                    compiled.program().native_dfa_view().expect("native DFA"),
                    Architecture::X86_64,
                )
                .unwrap()
                .1;
                assert!(adaptive.declined_redundant_root_reverse);
                let mut baseline = adaptive;
                baseline.declined_redundant_root_reverse = false;

                for (features, reduce, rewind) in cases {
                    let baseline_code = lower_x86_64_dfa(baseline, features).unwrap().0;
                    let adaptive_code = lower_x86_64_dfa(adaptive, features).unwrap().0;
                    assert_eq!(baseline_code.last(), Some(&0xc3));
                    assert_eq!(adaptive_code[baseline_code.len() - 1], 0xc3);
                    assert!(adaptive_code.len() > baseline_code.len());
                    assert_eq!(
                        (adaptive_code.len() - baseline_code.len()) % X86_COLD_LINK_ALIGNMENT_BYTES,
                        0,
                        "{features:?} {output:?}"
                    );

                    let reductions = offsets(&baseline_code, reduce);
                    assert_eq!(reductions.len(), 1, "{features:?} {output:?}");
                    let primary_hit = reductions[0] + reduce.len();
                    assert_eq!(&baseline_code[primary_hit..primary_hit + 2], &[0x0f, 0x85]);
                    let rewind_block = rel32_target(&baseline_code, primary_hit, 2, 6);
                    assert_eq!(
                        &baseline_code[rewind_block..rewind_block + rewind.len()],
                        rewind
                    );
                    let replay_branch = rewind_block + rewind.len();
                    assert_eq!(baseline_code[replay_branch], 0xe9);
                    assert_eq!(adaptive_code[replay_branch], 0xe9);
                    assert!(
                        rel32_target(&baseline_code, replay_branch, 1, 5) < baseline_code.len()
                    );
                    assert!(
                        rel32_target(&adaptive_code, replay_branch, 1, 5) >= baseline_code.len()
                    );

                    // Disabling only the graph marker is the exact c29 code
                    // shape. Once the dormant sparse-hit displacement is
                    // restored, every byte through its final ret is identical.
                    let mut normalized = adaptive_code[..baseline_code.len()].to_vec();
                    normalized[replay_branch + 1..replay_branch + 5]
                        .copy_from_slice(&baseline_code[replay_branch + 1..replay_branch + 5]);
                    assert_eq!(normalized, baseline_code, "{features:?} {output:?}");

                    let adaptive_reductions = offsets(&adaptive_code, reduce);
                    assert_eq!(adaptive_reductions.len(), 2);
                    let joint_hit = adaptive_reductions[1] + reduce.len();
                    assert_eq!(&adaptive_code[joint_hit..joint_hit + 2], &[0x0f, 0x85]);
                    let joint_miss = joint_hit + 6;
                    assert_eq!(adaptive_code[joint_miss], 0xe9);
                    let joint_loop = rel32_target(&adaptive_code, joint_miss, 1, 5);
                    let rejections = adaptive_code
                        .windows(8)
                        .enumerate()
                        .filter_map(|(offset, window)| {
                            (window.starts_with(&[0x48, 0xff, 0xc2, 0xe9])
                                && rel32_target(&adaptive_code, offset + 3, 1, 5) == joint_loop)
                                .then_some(offset)
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(rejections.len(), 1);
                    let padding = &adaptive_code[rejections[0] + 8..];
                    assert!(padding.len() < X86_COLD_LINK_ALIGNMENT_BYTES);
                    assert_canonical_nop_padding(padding);
                }
            }
        }

        // The alignment rule is scoped to a genuinely emitted adaptive cold
        // plan. Forcing the marker on unrelated sparse-start and seeded-
        // reverse layouts must remain byte-identical on every x86 tier.
        for pattern in [
            r"(?-u:\x01)",
            r"(?:(?:(?:(?:(?:(?:[R-U])+?){1,4}?)+?|sYZ|[j-l])){2,3}?(?-u:[\x00-\xFF]))",
        ] {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let compiled = compile(
                    CompileRequest::new(pattern, Target::x86_64_linux())
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                let layout = build_native_dfa_table_for_architecture(
                    compiled.program().native_dfa_view().expect("native DFA"),
                    Architecture::X86_64,
                )
                .unwrap()
                .1;
                assert!(!layout.declined_redundant_root_reverse);
                let mut forced_marker = layout;
                forced_marker.declined_redundant_root_reverse = true;
                for (features, _, _) in cases {
                    assert_eq!(
                        lower_x86_64_dfa(layout, features).unwrap().0,
                        lower_x86_64_dfa(forced_marker, features).unwrap().0,
                        "{pattern:?} {features:?} {output:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn x86_sparse_mask_batch_is_graph_selected_and_emitted_on_every_simd_tier() {
        let pattern = r"(?-u:\x01)";
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let x86_cases = [
            (
                Target::x86_64_linux(),
                X86StartFilterKind::Sse2,
                &[0x66, 0x45, 0x0f, 0xef, 0xff][..],
                &[0x66, 0x45, 0x0f, 0xeb, 0xfc][..],
                &[0x48, 0x83, 0xea, 64][..],
            ),
            (
                Target::x86_64_linux()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                X86StartFilterKind::Avx2,
                &[0xc4, 0x41, 0x05, 0xef, 0xff][..],
                &[0xc4, 0x41, 0x05, 0xeb, 0xfc][..],
                &[0x48, 0x81, 0xea, 128, 0, 0, 0][..],
            ),
            (
                Target::x86_64_linux().with_features(avx512).unwrap(),
                X86StartFilterKind::Avx512Bw,
                &[0xc4, 0xe1, 0xcc, 0x47, 0xf6][..],
                &[0xc4, 0xe1, 0xcc, 0x45, 0xf1][..],
                &[0x48, 0x81, 0xea, 0, 1, 0, 0][..],
            ),
        ];
        for (target, kind, clear, merge, rewind) in x86_cases {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let layout = build_native_dfa_table_for_architecture(
                compiled.program().native_dfa_view().unwrap(),
                Architecture::X86_64,
            )
            .unwrap()
            .1;
            let filter = layout.start_filter.expect("rare graph start filter");
            assert_eq!(estimated_filter_frequency_units(filter), 1);
            assert!(
                layout
                    .prefix_relation
                    .and_then(|relation| relation.vector_plan)
                    .is_none()
            );
            assert!(x86_use_sparse_filter_mask_batch(filter, kind));
            let code = compiled.module().sections()[TEXT_SECTION].bytes();
            assert!(code.windows(clear.len()).any(|window| window == clear));
            assert!(code.windows(merge.len()).any(|window| window == merge));
            assert!(code.windows(rewind.len()).any(|window| window == rewind));
        }

        let avx512_range = compile(
            CompileRequest::new(
                r"(?-u:[\x01-\x02])",
                Target::x86_64_linux().with_features(avx512).unwrap(),
            )
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        )
        .unwrap();
        let layout = build_native_dfa_table_for_architecture(
            avx512_range.program().native_dfa_view().unwrap(),
            Architecture::X86_64,
        )
        .unwrap()
        .1;
        let range_filter = layout.start_filter.expect("rare range start filter");
        assert!(!range_filter.is_exact());
        assert!(x86_use_sparse_filter_mask_batch(
            range_filter,
            X86StartFilterKind::Avx512Bw
        ));
        assert!(
            avx512_range.module().sections()[TEXT_SECTION]
                .bytes()
                .windows(5)
                .any(|window| window == [0xc4, 0xe1, 0xcc, 0x45, 0xf4]),
            "AVX-512 range masks from k4 must aggregate into k6"
        );
    }

    #[test]
    fn initially_reaching_non_proving_seeded_reverse_is_declined() {
        let pattern = r"(?:(?:[2-4](?:6){1,2}[o-s])(?:tL|e))";
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let asimd = FeatureSet::of(CpuFeature::Aarch64Asimd);
        let targets = [
            Target::x86_64_linux(),
            Target::x86_64_linux()
                .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap(),
            Target::x86_64_linux().with_features(avx512).unwrap(),
            Target::aarch64_linux(),
            Target::aarch64_linux().with_features(asimd).unwrap(),
        ];

        for target in targets {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap();
            let view = compiled.program().native_dfa_view().unwrap();
            let suffix = derive_suffix_filter(view)
                .unwrap()
                .expect("bounded interior factor");
            assert!(matches!(
                suffix.reverse_seed,
                NativeSuffixReverseSeed::RootState(_)
            ));
            assert!(suffix.retry.is_none());
            let machine = build_native_seeded_reverse(view, suffix, SeededReverseLimits::default())
                .expect("independent reverse proof is structurally derivable");
            assert!(machine.dfa.initial_reaches_start());
            assert!(!machine.proves_match);

            let layout = build_native_dfa_table_for_architecture(view, target.architecture)
                .unwrap()
                .1;
            assert_eq!(layout.suffix_filter, Some(suffix));
            assert!(
                layout.seeded_reverse.is_none(),
                "a reverse initial row that already reaches start cannot reject a factor candidate"
            );
        }

        let terminal = compile(
            CompileRequest::new("(?s:.+)z", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let terminal_layout = build_native_dfa_table(terminal.program().native_dfa_view().unwrap())
            .unwrap()
            .1;
        assert!(terminal_layout.suffix_filter.is_some_and(|suffix| matches!(
            suffix.reverse_seed,
            NativeSuffixReverseSeed::AcceptBoundary
        )));
        assert!(
            terminal_layout
                .seeded_reverse
                .is_some_and(|reverse| reverse.proves_match)
        );

        let rejecting_root = compile(
            CompileRequest::new("(?s:.+)MAGIC(?s:.*)", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let rejecting_view = rejecting_root.program().native_dfa_view().unwrap();
        let rejecting_suffix = derive_suffix_filter(rejecting_view)
            .unwrap()
            .expect("mandatory interior factor");
        assert!(matches!(
            rejecting_suffix.reverse_seed,
            NativeSuffixReverseSeed::RootState(_)
        ));
        let rejecting_machine = build_native_seeded_reverse(
            rejecting_view,
            rejecting_suffix,
            SeededReverseLimits::default(),
        )
        .expect("rejecting root reverse proof");
        assert!(!rejecting_machine.dfa.initial_reaches_start());
        assert!(!rejecting_machine.proves_match);
        let rejecting_layout = build_native_dfa_table(rejecting_view).unwrap().1;
        assert_eq!(rejecting_layout.suffix_filter, Some(rejecting_suffix));
        assert!(
            rejecting_layout
                .seeded_reverse
                .is_some_and(|reverse| !reverse.proves_match)
        );
    }

    #[test]
    fn generated_unbounded_concat_forms_keep_suffix_but_decline_degenerate_root_sidecar() {
        // Independently generated/spelled witnesses of the same graph shape:
        // an unbounded outer concat, a sparse mandatory interior factor, and
        // a terminal wildcard. Selection below depends only on those graph
        // facts and on the reverse machine, never on either source identity.
        let patterns = [
            r"(?:(?:(?:(?:(?:(?:QtJHg[I-K])){2,3}){1,3}?)+?9(?:(?:[J-M]){2,3}?){1,4}?)(?-u:[\x00-\xFF]))",
            r"(?:(?:(?:(?:(?:(?:QtJHg[I-L])){2,3}){1,3}?)+?8(?:(?:[J-N]){2,3}?){1,4}?)(?-u:[\x00-\xFF]))",
        ];
        for pattern in patterns {
            for target in [
                Target::x86_64_linux(),
                Target::aarch64_linux()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap(),
            ] {
                let compiled = compile(
                    CompileRequest::new(pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::Exists),
                )
                .unwrap();
                let view = compiled.program().native_dfa_view().unwrap();
                let suffix = derive_suffix_filter(view)
                    .unwrap()
                    .expect("mandatory interior factor");
                assert!(matches!(
                    suffix.reverse_seed,
                    NativeSuffixReverseSeed::RootState(_)
                ));
                assert_eq!(suffix.restart, NativeSuffixRestart::OriginalStart);
                assert!(suffix.retry.is_none());
                let machine =
                    build_native_seeded_reverse(view, suffix, SeededReverseLimits::default())
                        .expect("root reverse proof");
                assert!(
                    machine.dfa.initial_reaches_start(),
                    "reverse initial row did not reach start for {pattern:?} on {target:?}"
                );
                assert!(!machine.proves_match);

                let layout = build_native_dfa_table_for_architecture(view, target.architecture)
                    .unwrap()
                    .1;
                assert_eq!(layout.suffix_filter, Some(suffix));
                assert!(layout.seeded_reverse.is_none());
                assert!(
                    layout
                        .start_filter
                        .is_some_and(|filter| { filter.from_anchored_prefix && filter.is_exact() })
                );
                assert!(
                    layout
                        .vector_filter
                        .is_some_and(|columns| columns.columns().len() >= 2)
                );
            }
        }
    }

    #[test]
    fn declined_root_marker_is_output_target_and_spelling_independent_and_scoped() {
        const EQUIVALENT: [&str; 2] = [
            r"(?:(?:(?:(?:(?:(?:QtJHg[I-K])){2,3}){1,3}?)+?9(?:(?:[J-M]){2,3}?){1,4}?)(?-u:[\x00-\xFF]))",
            r"(?:(?:(?:(?:(?:(?:QtJHg[I-L])){2,3}){1,3}?)+?8(?:(?:[J-N]){2,3}?){1,4}?)(?-u:[\x00-\xFF]))",
        ];
        const BOUNDED_ACCEPT_SEED: &str =
            r"(?:(?:(?:(?:(?:(?:[R-U])+?){1,4}?)+?|sYZ|[j-l])){2,3}?(?-u:[\x00-\xFF]))";
        const NO_SUFFIX: &str =
            r"(?:(?:(?:(?:(?:(?:vK)+|P|[2-4])|Ww|k5E)){2,5})+(?-u:[\x00-\xFF]))";
        let outputs = [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ];
        let targets = [Target::x86_64_linux(), Target::aarch64_linux()];

        for pattern in EQUIVALENT {
            for target in targets {
                for output in outputs {
                    let compiled = compile(
                        CompileRequest::new(pattern, target)
                            .mode(CompileMode::Optimizing)
                            .output(output),
                    )
                    .unwrap();
                    let layout = build_native_dfa_table_for_architecture(
                        compiled.program().native_dfa_view().expect("native DFA"),
                        target.architecture,
                    )
                    .unwrap()
                    .1;
                    assert!(
                        layout.declined_redundant_root_reverse,
                        "graph marker changed for {target:?} {output:?}"
                    );
                    assert!(layout.seeded_reverse.is_none());
                    let suffix = layout.suffix_filter.expect("mandatory interior factor");
                    assert_eq!(suffix.restart, NativeSuffixRestart::OriginalStart);
                    assert!(suffix.retry.is_none());
                    assert!(matches!(
                        suffix.reverse_seed,
                        NativeSuffixReverseSeed::RootState(_)
                    ));
                    let columns = suffix.vector_filter.expect("joint suffix columns");
                    assert!(columns.columns().len() >= 2);
                    for kind in [
                        X86StartFilterKind::Sse2,
                        X86StartFilterKind::Avx2,
                        X86StartFilterKind::Avx512Bw,
                    ] {
                        assert!(x86_use_sparse_filter_mask_batch(suffix.filter, kind));
                    }
                }
            }
        }

        for (pattern, has_suffix) in [(BOUNDED_ACCEPT_SEED, true), (NO_SUFFIX, false)] {
            for output in outputs {
                let compiled = compile(
                    CompileRequest::new(pattern, Target::x86_64_linux())
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                let layout = build_native_dfa_table_for_architecture(
                    compiled.program().native_dfa_view().expect("native DFA"),
                    Architecture::X86_64,
                )
                .unwrap()
                .1;
                assert!(!layout.declined_redundant_root_reverse);
                assert_eq!(layout.suffix_filter.is_some(), has_suffix);
                if let Some(suffix) = layout.suffix_filter {
                    assert!(matches!(
                        suffix.reverse_seed,
                        NativeSuffixReverseSeed::AcceptBoundary
                    ));
                    assert!(suffix.vector_filter.is_none());
                }
            }
        }
    }

    #[test]
    fn feature_sets_are_independent_and_architecture_checked() {
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F)
            .with(CpuFeature::X86Avx512Bw)
            .with(CpuFeature::X86Avx512Vl);
        assert_eq!(
            Target::x86_64_linux()
                .with_features(avx512)
                .map(|target| target.features),
            Ok(avx512)
        );
        assert_eq!(
            Target::x86_64_linux().with_features(FeatureSet::of(CpuFeature::X86Avx512Bw)),
            Err(ObjectError::UnsupportedTarget)
        );
        assert_eq!(
            Target::aarch64_linux().with_features(FeatureSet::of(CpuFeature::X86Avx2)),
            Err(ObjectError::UnsupportedTarget)
        );
        assert_eq!(
            Target::aarch64_linux().with_features(FeatureSet::of(CpuFeature::Aarch64Sve2)),
            Err(ObjectError::UnsupportedTarget)
        );
    }

    #[test]
    fn x86_adapter_has_exact_shuffle_and_tail_jump() {
        let (code, relocations) = lower_x86_64_runtime_adapter().unwrap();
        let tail_adapter = [
            0x4d, 0x89, 0xc1, // mov r8, r9
            0x49, 0x89, 0xc8, // mov rcx, r8
            0x48, 0x89, 0xd1, // mov rdx, rcx
            0x48, 0x89, 0xf2, // mov rsi, rdx
            0x48, 0x89, 0xfe, // mov rdi, rsi
            0x48, 0x8d, 0x3d, 0, 0, 0, 0, // lea program(%rip), rdi
            0xe9, 0, 0, 0, 0, // jmp runtime
        ];
        assert!(
            code.windows(tail_adapter.len())
                .any(|window| window == tail_adapter)
        );
        assert_eq!(&code[code.len() - 6..], &[0xb8, 2, 0, 0, 0, 0xc3]);
        assert_eq!(relocations.len(), 2);
        let program = usize::try_from(relocations[0].offset).unwrap();
        let runtime = usize::try_from(relocations[1].offset).unwrap();
        assert_eq!(&code[program - 3..program], &[0x48, 0x8d, 0x3d]);
        assert_eq!(code[runtime - 1], 0xe9);
        assert_eq!(relocations[0].addend, -4);
        assert_eq!(relocations[1].addend, -4);
    }

    #[test]
    fn aarch64_adapter_has_exact_shuffle_and_tail_branch() {
        let (code, relocations) = lower_aarch64_runtime_adapter().unwrap();
        let instructions: Vec<u32> = code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect();
        let tail_adapter = [
            0xaa04_03e5,
            0xaa03_03e4,
            0xaa02_03e3,
            0xaa01_03e2,
            0xaa00_03e1,
            0x9000_0000,
            0x9100_0000,
            0x1400_0000,
        ];
        assert!(
            instructions
                .windows(tail_adapter.len())
                .any(|window| window == tail_adapter)
        );
        assert_eq!(
            &instructions[instructions.len() - 2..],
            &[0x5280_0040, 0xd65f_03c0]
        );
        assert_eq!(
            relocations
                .iter()
                .map(|relocation| relocation.kind)
                .collect::<Vec<_>>(),
            [
                RelocationKind::Aarch64Page21,
                RelocationKind::Aarch64PageOff12,
                RelocationKind::Aarch64Branch26,
            ]
        );
    }

    #[test]
    fn identity_symbol_is_full_and_deterministic() {
        let digest = [0xab; 32];
        let symbol = identity_symbol("p_", &digest).unwrap();
        assert_eq!(symbol.len(), 2 + 64);
        assert_eq!(
            symbol,
            "p_abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn entry_identity_binds_target_features_and_lowered_artifact() {
        let request_for = |target| {
            CompileRequest::new("(?:ab|a)+z", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span)
        };
        let targets = [
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ];
        let compiled = targets.map(|target| compile(request_for(target)).unwrap());
        let mut entry_symbols = compiled
            .iter()
            .map(|artifact| artifact.module().entry_symbol())
            .collect::<Vec<_>>();
        entry_symbols.sort_unstable();
        entry_symbols.dedup();
        assert_eq!(entry_symbols.len(), targets.len());

        let program_symbol = &compiled[0].module().symbols()[PROGRAM_SYMBOL].name;
        assert!(compiled.iter().all(|artifact| {
            &artifact.module().symbols()[PROGRAM_SYMBOL].name == program_symbol
        }));

        let avx2_target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let avx2 = compile(request_for(avx2_target)).unwrap();
        assert_ne!(
            compiled[0].module().sections()[TEXT_SECTION].data,
            avx2.module().sections()[TEXT_SECTION].data
        );
        assert_eq!(
            compiled[0].module().start_accelerator(),
            StartAccelerator::X86Sse2
        );
        assert_eq!(avx2.module().start_accelerator(), StartAccelerator::X86Avx2);
        assert_ne!(
            compiled[0].module().entry_symbol(),
            avx2.module().entry_symbol()
        );
        assert_eq!(
            compiled[0].module().symbols()[PROGRAM_SYMBOL].name,
            avx2.module().symbols()[PROGRAM_SYMBOL].name
        );

        let repeated = compile(request_for(Target::x86_64_linux())).unwrap();
        assert_eq!(
            compiled[0].module().entry_symbol(),
            repeated.module().entry_symbol()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one cross-target matrix audits the complete runtime-program object contract"
    )]
    fn runtime_program_alias_is_target_bound_global_exact_and_object_safe() {
        let targets = identity_target_matrix();
        let mut aliases = Vec::with_capacity(targets.len());
        let mut semantic_program_name = None;

        for target in targets.iter().copied() {
            let request = || CompileRequest::new("[ab]+z", target).mode(CompileMode::Fast);
            let compiled = compile(request()).unwrap();
            let repeated = compile(request()).unwrap();
            assert_eq!(compiled.receipt().engine, EngineKind::OrderedNfa);

            let module = compiled.module();
            let serialized = compiled.program().serialize().unwrap();
            let (alias_name, alias_size) = module.required_runtime_program().unwrap();
            assert_eq!(
                repeated.module().required_runtime_program(),
                Some((alias_name, alias_size))
            );
            assert_eq!(repeated.object(), compiled.object());

            let identity = alias_name
                .strip_prefix(RUNTIME_PROGRAM_SYMBOL_PREFIX)
                .unwrap();
            assert_eq!(identity.len(), 64);
            assert!(
                identity
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            assert_eq!(
                module
                    .entry_symbol()
                    .strip_prefix(ENTRY_SYMBOL_PREFIX)
                    .unwrap(),
                identity
            );

            assert_eq!(module.symbols().len(), 4);
            let semantic = &module.symbols()[PROGRAM_SYMBOL];
            assert_eq!(semantic.binding, SymbolBinding::Local);
            assert_eq!(semantic.kind, SymbolKind::Object);
            assert_eq!(semantic.section, Some(PROGRAM_SECTION));
            assert_eq!(semantic.offset, 0);
            assert_eq!(usize::try_from(semantic.size).unwrap(), serialized.len());
            assert_eq!(
                semantic_program_name
                    .get_or_insert_with(|| semantic.name.clone())
                    .as_str(),
                semantic.name
            );

            let runtime = &module.symbols()[RUNTIME_SYMBOL];
            assert_eq!(runtime.name, RUNTIME_SYMBOL_NAME);
            assert_eq!(runtime.binding, SymbolBinding::Global);
            assert_eq!(runtime.kind, SymbolKind::Function);
            assert_eq!(runtime.section, None);

            let alias = &module.symbols()[RUNTIME_PROGRAM_SYMBOL];
            assert_eq!(alias.name, alias_name);
            assert_eq!(alias.binding, SymbolBinding::Global);
            assert_eq!(alias.kind, SymbolKind::Object);
            assert_eq!(alias.section, Some(PROGRAM_SECTION));
            assert_eq!(alias.offset, 0);
            assert_eq!(usize::try_from(alias.size).unwrap(), serialized.len());
            assert_eq!(alias_size, serialized.len());
            assert_eq!(module.sections()[PROGRAM_SECTION].bytes(), serialized);

            assert!(
                module
                    .relocations()
                    .iter()
                    .any(|relocation| relocation.symbol == RUNTIME_SYMBOL)
            );
            assert!(
                module
                    .relocations()
                    .iter()
                    .all(|relocation| relocation.symbol != RUNTIME_PROGRAM_SYMBOL)
            );
            let mut names = module
                .symbols()
                .iter()
                .map(|symbol| symbol.name.as_str())
                .collect::<Vec<_>>();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), module.symbols().len());

            let emitted =
                emit_object(module, ObjectFormat::for_target(target), usize::MAX).unwrap();
            assert_eq!(emitted, compiled.object());
            assert!(
                emitted
                    .windows(alias_name.len())
                    .any(|bytes| bytes == alias_name.as_bytes())
            );
            aliases.push(alias_name.to_owned());
        }

        aliases.sort_unstable();
        aliases.dedup();
        assert_eq!(aliases.len(), targets.len());
    }

    #[test]
    fn direct_dfa_has_no_runtime_program_alias_on_any_target_or_feature() {
        for target in identity_target_matrix() {
            let compiled =
                compile(CompileRequest::new("[ab]+z", target).mode(CompileMode::Optimizing))
                    .unwrap();
            assert_eq!(compiled.receipt().engine, EngineKind::OrderedDfa);
            let module = compiled.module();
            assert_eq!(module.required_runtime_program(), None);
            assert_eq!(module.symbols().len(), 2);
            assert!(
                module
                    .symbols()
                    .iter()
                    .all(|symbol| !symbol.name.starts_with(RUNTIME_PROGRAM_SYMBOL_PREFIX))
            );
            assert!(
                module
                    .relocations()
                    .iter()
                    .all(|relocation| relocation.symbol != RUNTIME_SYMBOL)
            );

            let emitted =
                emit_object(module, ObjectFormat::for_target(target), usize::MAX).unwrap();
            assert_eq!(emitted, compiled.object());
            assert!(
                !emitted
                    .windows(RUNTIME_PROGRAM_SYMBOL_PREFIX.len())
                    .any(|bytes| bytes == RUNTIME_PROGRAM_SYMBOL_PREFIX.as_bytes())
            );
        }
    }

    #[test]
    fn native_module_identity_binds_every_lowering_field() {
        let program = b"semantic program";
        let target = Target::x86_64_linux();
        let mut lowering = NativeLowering {
            code: vec![1, 2, 3],
            data: vec![4, 5, 6],
            relocations: Vec::new(),
            needs_runtime: false,
            start_accelerator: StartAccelerator::None,
            anchored_prefix_filter_bytes: 0,
        };
        let base = native_module_digest(program, target, &lowering).unwrap();
        assert_ne!(
            base,
            native_module_digest(b"semantic program!", target, &lowering).unwrap()
        );
        for distinct_target in [
            Target {
                architecture: Architecture::Aarch64,
                ..target
            },
            Target {
                operating_system: OperatingSystem::Macos,
                ..target
            },
            Target {
                abi: CallAbi::Aapcs64,
                ..target
            },
            Target {
                features: FeatureSet::of(CpuFeature::X86Avx2),
                ..target
            },
        ] {
            assert_ne!(
                base,
                native_module_digest(program, distinct_target, &lowering).unwrap()
            );
        }

        lowering.code.push(7);
        assert_ne!(
            base,
            native_module_digest(program, target, &lowering).unwrap()
        );
        lowering.code.pop();
        lowering.data.push(8);
        assert_ne!(
            base,
            native_module_digest(program, target, &lowering).unwrap()
        );
        lowering.data.pop();
        lowering.relocations.push(ModuleRelocation {
            section: TEXT_SECTION,
            offset: 1,
            kind: RelocationKind::X86PcRelative32,
            symbol: PROGRAM_SYMBOL,
            addend: -4,
        });
        assert_ne!(
            base,
            native_module_digest(program, target, &lowering).unwrap()
        );
        lowering.relocations.clear();
        lowering.needs_runtime = true;
        let runtime = native_module_digest(program, target, &lowering).unwrap();
        assert_ne!(base, runtime);
        assert_ne!(
            runtime,
            native_module_digest(b"semantic program!", target, &lowering).unwrap()
        );
        lowering.needs_runtime = false;
        lowering.start_accelerator = StartAccelerator::X86Sse2;
        assert_ne!(
            base,
            native_module_digest(program, target, &lowering).unwrap()
        );
        lowering.start_accelerator = StartAccelerator::None;
        lowering.anchored_prefix_filter_bytes = 4;
        assert_ne!(
            base,
            native_module_digest(program, target, &lowering).unwrap()
        );
    }

    #[test]
    fn complete_dfa_has_inline_code_and_no_runtime_dependency() {
        for target in [
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ] {
            let compiled = compile(
                CompileRequest::new("(?:ab|a)+z", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            assert_eq!(compiled.receipt().engine, EngineKind::OrderedDfa);
            assert!(
                compiled
                    .module()
                    .symbols()
                    .iter()
                    .all(|symbol| symbol.name != RUNTIME_SYMBOL_NAME)
            );
            assert!(compiled.module().relocations().iter().all(|relocation| {
                relocation.symbol == PROGRAM_SYMBOL
                    && relocation.kind != RelocationKind::X86PltRelative32
                    && relocation.kind != RelocationKind::Aarch64Branch26
            }));
            match target.architecture {
                Architecture::X86_64 => {
                    assert_eq!(compiled.module().relocations().len(), 1);
                    assert!(compiled.module().code_bytes() > 80);
                }
                Architecture::Aarch64 => {
                    assert_eq!(compiled.module().relocations().len(), 2);
                    assert!(compiled.module().code_bytes() > 100);
                    for instruction in compiled.module().sections()[TEXT_SECTION]
                        .data
                        .chunks_exact(4)
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    {
                        if instruction & 0xfc00_0000 == 0x1400_0000 {
                            assert_ne!(instruction & 0x03ff_ffff, 0);
                        }
                        if instruction & 0xff00_0010 == 0x5400_0000 {
                            assert_ne!((instruction >> 5) & 0x7_ffff, 0);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn x86_splat_setup_uses_family_exact_movd_for_low_and_extended_registers() {
        let emit = |kind| {
            let mut assembler = X86Assembler::new();
            x86_emit_splat_byte(&mut assembler, 1, b'a', kind).unwrap();
            x86_emit_splat_byte(&mut assembler, 8, b'z', kind).unwrap();
            assembler.finish().unwrap()
        };
        let has_legacy_movd = |code: &[u8]| {
            code.windows(3).any(|bytes| bytes == [0x66, 0x0f, 0x6e])
                || code
                    .windows(4)
                    .any(|bytes| bytes == [0x66, 0x44, 0x0f, 0x6e])
        };

        let sse2 = emit(X86StartFilterKind::Sse2);
        assert!(
            sse2.windows(4)
                .any(|bytes| bytes == [0x66, 0x0f, 0x6e, 0xc8])
        );
        assert!(
            sse2.windows(5)
                .any(|bytes| bytes == [0x66, 0x44, 0x0f, 0x6e, 0xc0])
        );

        for kind in [X86StartFilterKind::Avx2, X86StartFilterKind::Avx512Bw] {
            let code = emit(kind);
            assert!(
                code.windows(4)
                    .any(|bytes| bytes == [0xc5, 0xf9, 0x6e, 0xc8])
            );
            assert!(
                code.windows(4)
                    .any(|bytes| bytes == [0xc5, 0x79, 0x6e, 0xc0])
            );
            assert!(!has_legacy_movd(&code));
        }
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "the bounded 64-lane oracle uses checked loop bounds and one-bit masks"
    )]
    fn avx512_candidate_masks_have_exact_encodings_and_first_lane_oracle() {
        let exact = NativeStartFilter {
            ranges: [
                NativeByteRange {
                    start: b'a',
                    end: b'a',
                },
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
            ],
            range_count: 1,
            candidate_bytes: 1,
            scan_offset: 0,
            from_anchored_prefix: false,
        };
        let range = NativeStartFilter {
            ranges: [
                NativeByteRange {
                    start: b'd',
                    end: b'g',
                },
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
            ],
            range_count: 1,
            candidate_bytes: 4,
            scan_offset: 1,
            from_anchored_prefix: false,
        };

        let emit = |filter, mask| {
            let mut assembler = X86Assembler::new();
            x86_emit_start_filter_constants(
                &mut assembler,
                filter,
                X86StartFilterKind::Avx512Bw,
                1,
            )
            .unwrap();
            assert_eq!(
                x86_emit_start_filter_vector_test(
                    &mut assembler,
                    filter,
                    X86StartFilterKind::Avx512Bw,
                )
                .unwrap(),
                mask
            );
            x86_emit_first_candidate_lane(&mut assembler, mask).unwrap();
            assembler.finish().unwrap()
        };

        let exact_code = emit(exact, X86CandidateMask::Avx512K1);
        assert!(
            exact_code
                .windows(5)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xf8, 0x98, 0xc9])
        ); // kortestq k1, k1
        assert!(
            exact_code
                .windows(9)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xfb, 0x93, 0xc1, 0x48, 0x0f, 0xbc, 0xc0])
        ); // kmovq rax, k1; bsfq rax, rax

        let range_code = emit(range, X86CandidateMask::Avx512K4);
        assert!(
            range_code
                .windows(5)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xf8, 0x98, 0xe4])
        ); // kortestq k4, k4
        assert!(
            range_code
                .windows(9)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xfb, 0x93, 0xc4, 0x48, 0x0f, 0xbc, 0xc0])
        ); // kmovq rax, k4; bsfq rax, rax

        let vector_filter = NativeVectorFilter {
            columns: [exact, range, EMPTY_NATIVE_START_FILTER],
            column_count: 2,
        };
        let mut assembler = X86Assembler::new();
        x86_emit_start_filter_constants(&mut assembler, exact, X86StartFilterKind::Avx512Bw, 1)
            .unwrap();
        x86_emit_start_filter_constants(&mut assembler, range, X86StartFilterKind::Avx512Bw, 2)
            .unwrap();
        assert_eq!(
            x86_emit_start_filter_vector_test(&mut assembler, exact, X86StartFilterKind::Avx512Bw,)
                .unwrap(),
            X86CandidateMask::Avx512K1
        );
        x86_emit_vector_filter_secondary_test(
            &mut assembler,
            vector_filter,
            X86StartFilterKind::Avx512Bw,
        )
        .unwrap();
        x86_emit_first_candidate_lane(&mut assembler, X86CandidateMask::Avx512K5).unwrap();
        let intersection = assembler.finish().unwrap();
        for instruction in [
            &[0xc4, 0xe1, 0xf4, 0x45, 0xe9][..], // korq k5, k1, k1
            &[0xc4, 0xe1, 0xd4, 0x41, 0xec][..], // kandq k5, k5, k4
            &[0xc4, 0xe1, 0xf8, 0x98, 0xed][..], // kortestq k5, k5
            &[0xc4, 0xe1, 0xfb, 0x93, 0xc5][..], // kmovq rax, k5
        ] {
            assert!(
                intersection
                    .windows(instruction.len())
                    .any(|bytes| bytes == instruction),
                "missing {instruction:02x?}"
            );
        }

        // KMOVQ preserves the complete opmask and BSFQ selects its least
        // significant set bit. Exercise every lane alone and with later hits.
        let lowered_first_lane =
            |mask: u64| (mask != 0).then(|| usize::try_from(mask.trailing_zeros()).unwrap());
        assert_eq!(lowered_first_lane(0), None);
        for expected in 0..64 {
            let one = 1_u64 << expected;
            assert_eq!(lowered_first_lane(one), Some(expected));
            let with_later = if expected < 63 {
                one | (1_u64 << 63)
            } else {
                one
            };
            assert_eq!(lowered_first_lane(with_later), Some(expected));
        }
    }

    #[test]
    fn avx512_exact_compare_encodes_extended_zmm_source_bit() {
        let mut filter = EMPTY_NATIVE_START_FILTER;
        filter.ranges[0] = NativeByteRange {
            start: b'a',
            end: b'a',
        };
        filter.ranges[1] = NativeByteRange {
            start: b'b',
            end: b'b',
        };
        filter.range_count = 2;
        filter.candidate_bytes = 2;

        let mut assembler = X86Assembler::new();
        x86_emit_exact_start_filter_vector_candidates(
            &mut assembler,
            filter,
            X86StartFilterKind::Avx512Bw,
            7,
        )
        .unwrap();
        let code = assembler.finish().unwrap();
        assert!(
            code.windows(6)
                .any(|bytes| bytes == [0x62, 0xf1, 0x7d, 0x48, 0x74, 0xcf])
        ); // vpcmpeqb k1, zmm0, zmm7
        assert!(
            code.windows(6)
                .any(|bytes| bytes == [0x62, 0xd1, 0x7d, 0x48, 0x74, 0xd0])
        ); // vpcmpeqb k2, zmm0, zmm8
        assert!(
            !code
                .windows(6)
                .any(|bytes| bytes == [0x62, 0xf1, 0x7d, 0x48, 0x74, 0xd0]),
            "EVEX.B must select zmm8 instead of wrapping to zmm0"
        );
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "exhaustive small boundary windows are indexed only after explicit bounds"
    )]
    fn avx512_intersection_model_matches_scalar_at_every_vector_boundary() {
        let contains = |byte: u8, start: u8, end: u8| (start..=end).contains(&byte);
        let scalar = |haystack: &[u8]| {
            (0..haystack.len().saturating_sub(1)).find(|&position| {
                haystack[position] == b'a' && contains(haystack[position + 1], b'd', b'g')
            })
        };
        let modeled = |haystack: &[u8]| {
            let mut position = 0_usize;
            while haystack.len().saturating_sub(position) >= 65 {
                let mut mask = 0_u64;
                for lane in 0..64 {
                    if haystack[position + lane] == b'a'
                        && contains(haystack[position + lane + 1], b'd', b'g')
                    {
                        mask |= 1_u64 << lane;
                    }
                }
                if mask != 0 {
                    return Some(position + usize::try_from(mask.trailing_zeros()).unwrap());
                }
                position += 64;
            }
            (position..haystack.len().saturating_sub(1)).find(|&candidate| {
                haystack[candidate] == b'a' && contains(haystack[candidate + 1], b'd', b'g')
            })
        };

        // This exhausts every tail width around both 64-byte blocks, every
        // possible first lane, and no-hit/false-primary cases.
        for length in 0..=130 {
            let empty = vec![0_u8; length];
            assert_eq!(modeled(&empty), scalar(&empty), "empty length {length}");
            for expected in 0..length.saturating_sub(1) {
                let mut haystack = empty.clone();
                if expected != 0 {
                    haystack[0] = b'a'; // rejected primary before the true pair
                }
                haystack[expected] = b'a';
                haystack[expected + 1] = b'e';
                assert_eq!(
                    modeled(&haystack),
                    scalar(&haystack),
                    "length {length}, lane {expected}"
                );
                assert_eq!(modeled(&haystack), Some(expected));
            }
        }
    }

    #[test]
    fn retained_candidate_iteration_is_exact_for_all_16_bit_masks_and_every_x86_lane() {
        let iterate = |mut mask: u64| {
            let mut lanes = Vec::new();
            while mask != 0 {
                lanes.push(usize::try_from(mask.trailing_zeros()).unwrap());
                mask &= mask - 1;
            }
            lanes
        };

        for mask in 0_u64..=u64::from(u16::MAX) {
            let expected = (0..16)
                .filter(|&lane| mask & (1_u64 << lane) != 0)
                .collect::<Vec<_>>();
            assert_eq!(iterate(mask), expected);
            for threshold in 0..=16 {
                let retained = mask
                    & if threshold == 16 {
                        0
                    } else {
                        u64::from(u16::MAX) << threshold
                    };
                let expected_after = expected
                    .iter()
                    .copied()
                    .filter(|&lane| lane >= threshold)
                    .collect::<Vec<_>>();
                assert_eq!(iterate(retained), expected_after);
            }
        }

        for width in [16_usize, 32, 64] {
            let all = if width == 64 {
                u64::MAX
            } else {
                (1_u64 << width) - 1
            };
            assert_eq!(iterate(all), (0..width).collect::<Vec<_>>());
            for accepted_lane in 0..width {
                let mut candidates = 1_u64 << accepted_lane;
                if accepted_lane != 0 {
                    candidates |= (1_u64 << accepted_lane) - 1;
                }
                if accepted_lane + 1 < width {
                    candidates |= 1_u64 << (width - 1);
                }
                let selected = iterate(candidates)
                    .into_iter()
                    .find(|&lane| lane == accepted_lane);
                assert_eq!(selected, Some(accepted_lane));
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the retained-mask audit covers every native ISA tier and proof route together"
    )]
    fn retained_prefix_masks_have_exact_cross_isa_code_shapes_and_proof_coverage() {
        let relation_pattern = "(?:ab|cd)[A-Z].*";
        let independent_pattern = "[a-f][0-3]QZMORE";
        let x86_tiers = [
            FeatureSet::of(CpuFeature::X86Sse2),
            FeatureSet::of(CpuFeature::X86Avx2),
            FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw),
        ];
        for features in x86_tiers {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let target = Target::x86_64_linux().with_features(features).unwrap();
                let compiled = compile(
                    CompileRequest::new(relation_pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                let view = compiled.program().native_dfa_view().unwrap();
                let (_, layout) =
                    build_native_dfa_table_for_architecture(view, Architecture::X86_64).unwrap();
                let coverage = derive_native_vector_guard_coverage(layout, true, None).unwrap();
                assert!(coverage.relation);
                assert!(coverage.has_rejectable_residual(layout).unwrap());
                let code = compiled.module().sections()[TEXT_SECTION].bytes();
                assert_eq!(&code[..4], &[0x41, 0x54, 0x41, 0x55]);
                assert!(code.windows(3).any(|bytes| bytes == [0x49, 0x89, 0xd4]));
                assert!(
                    code.windows(4)
                        .any(|bytes| bytes == [0x49, 0x0f, 0xbc, 0xc5])
                );
                assert!(
                    code.windows(4)
                        .any(|bytes| bytes == [0x49, 0x8d, 0x45, 0xff])
                );
                assert!(code.windows(3).any(|bytes| bytes == [0x49, 0x21, 0xc5]));
                assert!(
                    code.windows(4)
                        .any(|bytes| bytes == [0x41, 0x5d, 0x41, 0x5c])
                );
                assert_eq!(
                    code.windows(4)
                        .filter(|bytes| *bytes == [0x0f, 0xb7, 0x04, 0x17])
                        .count(),
                    1,
                    "only the scalar tail may consult the relation bitmap"
                );
                if features.has(CpuFeature::X86Avx512Bw) {
                    assert!(
                        code.windows(5)
                            .any(|bytes| bytes == [0xc4, 0xe1, 0xfb, 0x93, 0xc5])
                    );
                    assert!(code.windows(3).any(|bytes| bytes == [0x49, 0x89, 0xc5]));
                } else {
                    assert!(code.windows(3).any(|bytes| bytes == [0x41, 0x89, 0xc5]));
                }
            }

            let target = Target::x86_64_linux().with_features(features).unwrap();
            let compiled = compile(
                CompileRequest::new(independent_pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let view = compiled.program().native_dfa_view().unwrap();
            let (_, layout) =
                build_native_dfa_table_for_architecture(view, Architecture::X86_64).unwrap();
            assert!(layout.prefix_relation.is_none());
            let vector = layout.vector_filter.expect("independent vector columns");
            let coverage =
                derive_native_vector_guard_coverage(layout, false, Some(vector)).unwrap();
            assert!(coverage.has_rejectable_residual(layout).unwrap());
            assert!(
                compiled.module().sections()[TEXT_SECTION]
                    .bytes()
                    .starts_with(&[0x41, 0x54, 0x41, 0x55])
            );
        }

        let asimd = FeatureSet::of(CpuFeature::Aarch64Asimd);
        for operating_system in [OperatingSystem::Linux, OperatingSystem::Macos] {
            let target = match operating_system {
                OperatingSystem::Linux => Target::aarch64_linux(),
                OperatingSystem::Macos => Target::aarch64_macos(),
            }
            .with_features(asimd)
            .unwrap();
            let compiled = compile(
                CompileRequest::new(relation_pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let words = compiled.module().sections()[TEXT_SECTION]
                .bytes()
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            assert!(words.contains(&aarch64_mov_x(14, 2).unwrap()));
            assert!(words.contains(&aarch64_orr_16b(28, 24, 24).unwrap()));
            assert!(words.contains(&aarch64_dup_16b_from_w(28, 12).unwrap()));
            assert!(words.contains(&aarch64_cmhs_16b(28, 29, 28).unwrap()));
            assert!(words.contains(&aarch64_and_16b(28, 28, 24).unwrap()));
            assert_eq!(
                words
                    .iter()
                    .filter(|&&word| word == aarch64_load_halfword_reg(8, 0, 2).unwrap())
                    .count(),
                1,
                "only the scalar tail may consult the relation bitmap"
            );

            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let fully_proved_relation = compile(
                    CompileRequest::new("(?:ab|cd)", target)
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                let view = fully_proved_relation.program().native_dfa_view().unwrap();
                let (_, layout) =
                    build_native_dfa_table_for_architecture(view, Architecture::Aarch64).unwrap();
                let coverage = derive_native_vector_guard_coverage(layout, true, None)
                    .expect("fully proved relation coverage");
                assert!(coverage.relation);
                assert!(!coverage.has_rejectable_residual(layout).unwrap());
                let words = fully_proved_relation.module().sections()[TEXT_SECTION]
                    .bytes()
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                assert!(words.contains(&aarch64_ld1_four_16b(24, 12).unwrap()));
                for block in 0_u8..3 {
                    assert!(
                        words.contains(&aarch64_ext_16b(16, 24 + block, 25 + block, 1).unwrap())
                    );
                }
                assert!(words.contains(&aarch64_add_x_imm(12, 12, 49).unwrap()));
                assert!(!words.contains(&aarch64_mov_x(14, 2).unwrap()));
            }
        }

        let fully_proved = compile(
            CompileRequest::new(
                "[3-7]",
                Target::aarch64_linux().with_features(asimd).unwrap(),
            )
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        )
        .unwrap();
        let fully_proved_words = fully_proved.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(fully_proved_words.contains(&aarch64_ld1_four_16b(24, 12).unwrap()));
        assert!(!fully_proved_words.contains(&aarch64_mov_x(14, 2).unwrap()));
    }

    #[test]
    fn x86_feature_matrix_selects_avx512_only_with_f_and_bw() {
        for bits in 0_u8..16 {
            let mut features = FeatureSet::EMPTY;
            if bits & 1 != 0 {
                features = features.with(CpuFeature::X86Avx2);
            }
            if bits & 2 != 0 {
                features = features.with(CpuFeature::X86Avx512F);
            }
            if bits & 4 != 0 {
                features = features.with(CpuFeature::X86Avx512Bw);
            }
            if bits & 8 != 0 {
                features = features.with(CpuFeature::X86Avx512Vl);
            }
            let expected = if bits & 0b110 == 0b110 {
                X86StartFilterKind::Avx512Bw
            } else if bits & 1 != 0 {
                X86StartFilterKind::Avx2
            } else {
                X86StartFilterKind::Sse2
            };
            assert_eq!(x86_start_filter_kind(features), expected, "bits {bits:04b}");
        }
    }

    #[test]
    fn avx512_direct_objects_are_self_contained_on_the_four_supported_targets() {
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let asimd = FeatureSet::of(CpuFeature::Aarch64Asimd);
        let targets = [
            Target::x86_64_linux().with_features(avx512).unwrap(),
            Target::x86_64_macos().with_features(avx512).unwrap(),
            Target::aarch64_linux().with_features(asimd).unwrap(),
            Target::aarch64_macos().with_features(asimd).unwrap(),
        ];

        for target in targets {
            let compiled = compile(
                CompileRequest::new(r"(?-u:\x01[\x03-\x06])", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap();
            assert_eq!(compiled.receipt().engine, EngineKind::OrderedDfa);
            assert!(
                compiled
                    .module()
                    .symbols()
                    .iter()
                    .all(|symbol| symbol.name != RUNTIME_SYMBOL_NAME)
            );
            assert!(
                compiled
                    .module()
                    .relocations()
                    .iter()
                    .all(|relocation| relocation.symbol == PROGRAM_SYMBOL)
            );
            match target.operating_system {
                OperatingSystem::Linux => assert!(compiled.object().starts_with(b"\x7fELF")),
                OperatingSystem::Macos => {
                    assert!(compiled.object().starts_with(&[0xcf, 0xfa, 0xed, 0xfe]));
                }
            }

            if target.architecture == Architecture::X86_64 {
                let code = compiled.module().sections()[TEXT_SECTION].bytes();
                assert!(
                    code.windows(5)
                        .any(|bytes| bytes == [0xc4, 0xe1, 0xf8, 0x98, 0xed]),
                    "graph-derived columns must intersect in k5"
                );
                assert!(
                    code.windows(5)
                        .any(|bytes| bytes == [0xc4, 0xe1, 0xfb, 0x93, 0xc5]),
                    "the intersected 64-lane mask must reach a GPR"
                );
                assert_eq!(
                    code.windows(3)
                        .filter(|bytes| *bytes == [0xc5, 0xf8, 0x77])
                        .count(),
                    1,
                    "one shared epilogue must issue VZEROUPPER"
                );
                assert!(code.ends_with(&[0xc5, 0xf8, 0x77, 0xc3]));
            }
        }
    }

    #[test]
    fn avx512_accepting_loop_preserves_pending_end_for_lane_zero() {
        let target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw))
            .unwrap();
        for (pattern, expected_mask) in [
            (r"(?-u:[^Z]*)", X86CandidateMask::Avx512K1),
            (r"(?-u:[^A-F]*)", X86CandidateMask::Avx512K4),
        ] {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1;
            let loop_skip = layout.loop_skip.expect("accepting loop skip");
            assert!(loop_skip.accepting);
            assert_eq!(
                X86CandidateMask::for_filter(loop_skip.filter, X86StartFilterKind::Avx512Bw),
                expected_mask
            );

            let register = expected_mask.opmask_register().unwrap();
            let kmov = [0xc4, 0xe1, 0xfb, 0x93, 0xc0 | register];
            let code = compiled.module().sections()[TEXT_SECTION].bytes();
            let offset = code
                .windows(kmov.len())
                .position(|bytes| bytes == kmov)
                .expect("loop mask KMOVQ");
            assert_eq!(&code[offset + 5..offset + 9], &[0x48, 0x0f, 0xbc, 0xc0]);
            assert_eq!(&code[offset + 9..offset + 12], &[0x48, 0x85, 0xc0]);
            assert_eq!(&code[offset + 12..offset + 14], &[0x0f, 0x84]);
            assert_eq!(&code[offset + 18..offset + 21], &[0x48, 0x01, 0xc2]);
            assert_eq!(&code[offset + 21..offset + 24], &[0x49, 0x89, 0xd3]);
        }
    }

    #[test]
    fn avx512_suffix_keeps_graph_proven_intersection_and_bounded_retry() {
        let target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw))
            .unwrap();
        let compiled = compile(
            CompileRequest::new(r"(?:MQw|[d-e]|r74){2,3}[j-k]Q", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let suffix = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
            .unwrap()
            .1
            .suffix_filter
            .expect("mandatory suffix");
        assert!(suffix.vector_filter.is_some());
        assert!(suffix.retry.is_some());

        let code = compiled.module().sections()[TEXT_SECTION].bytes();
        assert!(
            code.windows(5)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xf8, 0x98, 0xed])
        ); // kortestq k5, k5
        assert!(
            code.windows(9)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xfb, 0x93, 0xc5, 0x48, 0x0f, 0xbc, 0xc0])
        ); // kmovq k5 + bsfq
        assert!(
            code.windows(7)
                .any(|bytes| bytes == [0x48, 0x8d, 0x42, 1, 0x49, 0x89, 0x00]),
            "bounded retry must retain the next mandatory base"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one generated structural matrix audits selection and exact ISA sequences"
    )]
    fn start_filter_selection_is_graph_derived_and_feature_exact() {
        let compile_for = |pattern: &str, target| {
            compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .unwrap()
        };

        let sse2 = compile_for("a", Target::x86_64_linux());
        assert_eq!(sse2.module().start_accelerator(), StartAccelerator::X86Sse2);
        let sse2_code = sse2.module().sections()[TEXT_SECTION].bytes();
        assert!(
            sse2_code
                .windows(5)
                .any(|bytes| bytes == [0xf3, 0x0f, 0x6f, 0x04, 0x17])
        );
        assert!(
            sse2_code
                .windows(5)
                .any(|bytes| bytes == [0x66, 0x41, 0x0f, 0xd7, 0xc4])
        );
        assert!(
            sse2_code
                .windows(3)
                .any(|bytes| bytes == [0x0f, 0xbc, 0xc0])
        );
        assert!(
            sse2_code
                .windows(4)
                .any(|bytes| bytes == [0x66, 0x0f, 0x6e, 0xc8]),
            "the SSE2 setup must retain legacy MOVD"
        );

        let avx2_target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let avx2 = compile_for("(?i:a)", avx2_target);
        assert_eq!(avx2.module().start_accelerator(), StartAccelerator::X86Avx2);
        let avx2_code = avx2.module().sections()[TEXT_SECTION].bytes();
        assert!(
            avx2_code
                .windows(5)
                .any(|bytes| bytes == [0xc5, 0xfe, 0x6f, 0x04, 0x17])
        );
        assert!(
            avx2_code
                .windows(3)
                .any(|bytes| bytes == [0xc5, 0xf8, 0x77])
        );
        assert!(
            avx2_code
                .windows(3)
                .any(|bytes| bytes == [0x0f, 0xbc, 0xc0])
        );
        assert!(
            avx2_code
                .windows(4)
                .any(|bytes| bytes == [0xc5, 0xf9, 0x6e, 0xc8]),
            "the AVX2 setup must use VEX VMOVD"
        );
        assert!(
            !avx2_code
                .windows(3)
                .any(|bytes| bytes == [0x66, 0x0f, 0x6e])
                && !avx2_code
                    .windows(4)
                    .any(|bytes| bytes == [0x66, 0x44, 0x0f, 0x6e]),
            "the AVX2 setup must not mix in legacy MOVD"
        );

        let avx512_features = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let avx512 = compile_for(
            "[abcd]",
            Target::x86_64_linux()
                .with_features(avx512_features)
                .unwrap(),
        );
        assert_eq!(
            avx512.module().start_accelerator(),
            StartAccelerator::X86Avx512Bw
        );
        let avx512_code = avx512.module().sections()[TEXT_SECTION].bytes();
        assert!(
            avx512_code
                .windows(7)
                .any(|bytes| bytes == [0x62, 0xf1, 0x7f, 0x48, 0x6f, 0x04, 0x17])
        );
        assert!(
            avx512_code
                .windows(7)
                .any(|bytes| bytes == [0x62, 0xf3, 0x7d, 0x48, 0x3e, 0xc9, 5])
        );
        assert!(
            avx512_code
                .windows(5)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xf8, 0x98, 0xe4])
        );
        assert!(
            avx512_code
                .windows(4)
                .any(|bytes| bytes == [0xc5, 0xf9, 0x6e, 0xc8]),
            "the AVX-512 setup must use VEX VMOVD"
        );
        assert!(
            !avx512_code
                .windows(3)
                .any(|bytes| bytes == [0x66, 0x0f, 0x6e])
                && !avx512_code
                    .windows(4)
                    .any(|bytes| bytes == [0x66, 0x44, 0x0f, 0x6e]),
            "the AVX-512 setup must not mix in legacy MOVD"
        );

        let scalar = compile_for("a", Target::aarch64_linux());
        assert_eq!(
            scalar.module().start_accelerator(),
            StartAccelerator::Scalar
        );
        assert!(aarch64_use_exact_first_lane(OperatingSystem::Macos));
        assert!(aarch64_use_exact_first_lane(OperatingSystem::Linux));
        let asimd_target = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let asimd = compile_for("[3-7]", asimd_target);
        assert_eq!(
            asimd.module().start_accelerator(),
            StartAccelerator::Aarch64Asimd
        );
        let asimd_words = asimd.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(asimd_words.contains(&0x3dc0_0180)); // ldr q0, [x12]
        assert!(asimd_words.contains(&aarch64_ld1_four_16b(24, 12).unwrap()));
        assert!(!asimd_words.contains(&0x3dc0_019a)); // no four-LDR batch
        assert!(!asimd_words.contains(&0x3dc0_019b));
        assert!(!asimd_words.contains(&0x3dc0_019c));
        assert!(
            asimd_words
                .iter()
                .filter(|word| **word & 0xffff_ffe0 == 0x3dc0_0180)
                .all(|word| !matches!(word & 0x1f, 8..=15)),
            "frameless AArch64 scanner must not load into callee-saved v8-v15"
        );
        assert!(asimd_words.contains(&0x6e30_3c05)); // cmhs v5.16b, v0.16b, v16.16b
        assert!(asimd_words.contains(&0x6e20_3e26)); // cmhs v6.16b, v17.16b, v0.16b
        assert!(asimd_words.contains(&aarch64_umaxv_16b(7, 24).unwrap()));
        assert!(asimd_words.contains(&aarch64_bsl_16b(0, 28, 31).unwrap()));
        assert!(asimd_words.contains(&aarch64_uminv_16b(24, 24).unwrap()));

        let fragmented_asimd = compile_for("[ACEGIKMO]", asimd_target);
        let fragmented_layout =
            build_native_dfa_table(fragmented_asimd.program().native_dfa_view().unwrap())
                .unwrap()
                .1;
        assert_eq!(
            fragmented_layout
                .start_filter
                .expect("fragmented ASIMD start filter")
                .ranges()
                .len(),
            8
        );
        let fragmented_words = fragmented_asimd.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(fragmented_words.contains(&aarch64_movi_16b(23, b'O').unwrap()));
        assert!(
            fragmented_words
                .contains(&aarch64_cmeq_16b(AARCH64_EXACT_FILTER_SCRATCH, 0, 23).unwrap())
        );
        for preserved in 8_u8..=15 {
            for &byte in b"ACEGIKMO" {
                assert!(
                    !fragmented_words.contains(&aarch64_movi_16b(preserved, byte).unwrap()),
                    "ordinary ASIMD entry writes ABI-preserved V{preserved}"
                );
            }
        }
        for source in [0_u8, 24, 25, 26, 27] {
            for constant in 1_u8..=8 {
                assert!(
                    !fragmented_words.contains(&aarch64_cmeq_16b(15, source, constant).unwrap()),
                    "ordinary ASIMD entry retains the former V15 scratch"
                );
            }
        }

        let linux_asimd = compile_for(
            "[3-7]",
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        );
        assert_eq!(
            linux_asimd.module().start_accelerator(),
            StartAccelerator::Aarch64Asimd
        );
        let linux_asimd_words = linux_asimd.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(linux_asimd_words.contains(&0x3dc0_0180)); // ldr q0, [x12]
        assert!(linux_asimd_words.contains(&aarch64_ld1_four_16b(24, 12).unwrap()));
        assert!(linux_asimd_words.contains(&aarch64_bsl_16b(0, 28, 31).unwrap()));
        assert!(linux_asimd_words.contains(&aarch64_uminv_16b(24, 24).unwrap()));
        assert!(linux_asimd_words.contains(&aarch64_movi_16b(30, 16).unwrap()));
        assert!(linux_asimd_words.contains(&aarch64_movi_16b(31, 64).unwrap()));

        let broad_asimd = compile_for("[A-F0-9_]", asimd_target);
        assert_eq!(
            broad_asimd.module().start_accelerator(),
            StartAccelerator::Aarch64Asimd
        );
        let broad_asimd_words = broad_asimd.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(
            !broad_asimd_words.contains(&aarch64_ld1_four_16b(24, 12).unwrap()),
            "broad candidate sets must retain the 16-byte ASIMD cost path"
        );

        let selective_pattern = "[acegik][02468]QZ";
        let selective = compile_for(selective_pattern, Target::x86_64_linux());
        let (_, selective_layout) =
            build_native_dfa_table(selective.program().native_dfa_view().unwrap()).unwrap();
        let selective_filter = selective_layout.start_filter.unwrap();
        assert_eq!(selective_filter.scan_offset, 2);
        assert!(selective_filter.from_anchored_prefix);
        assert_eq!(selective_filter.candidate_bytes, 1);
        assert_eq!(
            selective_filter.ranges(),
            [NativeByteRange {
                start: b'Q',
                end: b'Q'
            }]
        );
        assert_eq!(
            selective_layout
                .prefix_filter
                .unwrap()
                .predicates()
                .iter()
                .map(|predicate| predicate.position)
                .collect::<Vec<_>>(),
            [3, 1, 0]
        );
        let selective_x86 = selective.module().sections()[TEXT_SECTION].bytes();
        assert!(
            selective_x86
                .windows(6)
                .any(|bytes| bytes == [0xf3, 0x0f, 0x6f, 0x44, 0x17, 2]),
            "SSE2 scanner must load the selected offset column"
        );
        assert!(
            selective_x86
                .windows(5)
                .any(|bytes| bytes == [0x0f, 0xb6, 0x44, 0x17, 2]),
            "x86 scalar tail must load the selected offset column"
        );
        let selective_avx512 = compile_for(
            selective_pattern,
            Target::x86_64_linux()
                .with_features(avx512_features)
                .unwrap(),
        );
        let selective_avx512_code = selective_avx512.module().sections()[TEXT_SECTION].bytes();
        assert!(
            selective_avx512_code
                .windows(11)
                .any(|bytes| { bytes == [0x62, 0xf1, 0x7f, 0x48, 0x6f, 0x84, 0x17, 2, 0, 0, 0,] })
        );
        assert!(
            !selective_avx512_code
                .windows(8)
                .any(|bytes| bytes == [0x62, 0xf1, 0x7f, 0x48, 0x6f, 0x44, 0x17, 2]),
            "EVEX disp8 would scale the two-byte column offset by 64"
        );

        let selective_asimd = compile_for(selective_pattern, asimd_target);
        let selective_asimd_words = selective_asimd.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(selective_asimd_words.contains(&aarch64_add_x_imm(12, 12, 2).unwrap()));
        assert!(selective_asimd_words.contains(&aarch64_cmp_x_imm(12, 67).unwrap()));
        assert!(selective_asimd_words.contains(&aarch64_cmp_x_imm(12, 19).unwrap()));
        assert!(
            selective_asimd_words.contains(&aarch64_load_byte_imm(8, 12, 2).unwrap()),
            "ASIMD scalar tail must load the selected offset column"
        );

        let four_ranges = compile_for("[0-9A-F_a-f]", Target::x86_64_linux());
        let filter = derive_start_filter(four_ranges.program().native_dfa_view().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            filter.ranges(),
            [
                NativeByteRange {
                    start: b'0',
                    end: b'9'
                },
                NativeByteRange {
                    start: b'A',
                    end: b'F'
                },
                NativeByteRange {
                    start: b'_',
                    end: b'_'
                },
                NativeByteRange {
                    start: b'a',
                    end: b'f'
                },
            ]
        );
        assert_eq!(filter.candidate_bytes, 23);

        for target in [
            Target::x86_64_linux(),
            Target::aarch64_linux(),
            asimd_target,
        ] {
            assert_eq!(
                compile_for("[abcde]", target).module().start_accelerator(),
                match target.architecture {
                    Architecture::X86_64 => StartAccelerator::X86Sse2,
                    Architecture::Aarch64 if target.features.has(CpuFeature::Aarch64Asimd) => {
                        StartAccelerator::Aarch64Asimd
                    }
                    Architecture::Aarch64 => StartAccelerator::Scalar,
                }
            );
            assert_eq!(
                compile_for("[acegi]", target).module().start_accelerator(),
                match target.architecture {
                    Architecture::X86_64 => StartAccelerator::X86Sse2,
                    Architecture::Aarch64 if target.features.has(CpuFeature::Aarch64Asimd) => {
                        StartAccelerator::Aarch64Asimd
                    }
                    Architecture::Aarch64 => StartAccelerator::Scalar,
                }
            );
            assert_eq!(
                compile_for("(?-u:[\\x00-\\x80])", target)
                    .module()
                    .start_accelerator(),
                StartAccelerator::None
            );
            assert_eq!(
                compile_for("a*", target).module().start_accelerator(),
                StartAccelerator::None
            );
        }
    }

    #[test]
    fn vector_filter_cost_model_is_frequency_ranked_and_lazy_for_sparse_primaries() {
        let layout_for = |pattern: &str| {
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap();
            build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1
        };

        let common = layout_for("eats");
        let common_columns = common.vector_filter.unwrap();
        assert_eq!(
            common_columns
                .columns()
                .iter()
                .map(|column| (column.scan_offset, column.ranges()[0].start))
                .collect::<Vec<_>>(),
            [(3, b's'), (1, b'a')]
        );

        let sparse = layout_for("qeee");
        assert_eq!(sparse.start_filter.unwrap().scan_offset, 0);
        assert_eq!(
            sparse
                .vector_filter
                .unwrap()
                .columns()
                .iter()
                .map(|column| column.scan_offset)
                .collect::<Vec<_>>(),
            [0, 3, 2]
        );

        let tied = layout_for("qq");
        assert_eq!(tied.start_filter.unwrap().scan_offset, 1);

        let expensive_secondary = layout_for("q[ et]");
        assert!(expensive_secondary.vector_filter.is_none());

        let range_pair = layout_for(r"(?-u:[\x01-\x02][\x03-\x06])")
            .vector_filter
            .unwrap();
        assert!(range_pair.columns().iter().all(|column| !column.is_exact()));
        assert_eq!(
            range_pair
                .columns()
                .iter()
                .map(|column| column.constant_count())
                .sum::<usize>(),
            4
        );
        assert_eq!(
            range_pair
                .columns()
                .iter()
                .map(|column| vector_filter_instruction_units(*column))
                .sum::<u16>(),
            MAX_VECTOR_FILTER_INSTRUCTION_UNITS
        );

        let broad_range = layout_for(r"(?-u:\x01[ -_])");
        assert!(
            broad_range.vector_filter.is_none(),
            "a representable but costly broad range must not win unconditionally"
        );
    }

    #[test]
    fn exact_initial_departure_competes_with_anchored_prefix_columns() {
        // Generated independently as a structural witness. The selection
        // policy below depends only on graph-derived filters and their stable
        // cost keys, never on this source spelling.
        let pattern = r"(?:(?:(?:(?:(?:(?:(?:[p-s])+?[3-7]X))?w)){1,4}?[D-E](?:(?:Gq){2,4}|[3-5]|CR))(?-u:[\x00-\xFF]))";
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let view = compiled.program().native_dfa_view().unwrap();
        assert_eq!(
            view.anchored_prefix
                .sets()
                .iter()
                .map(|set| set.cardinality())
                .collect::<Vec<_>>(),
            [5, 12, 15, 256]
        );
        let anchored = derive_anchored_prefix_start_filter(view.anchored_prefix.sets())
            .unwrap()
            .unwrap();
        let initial = derive_initial_start_filter(view).unwrap().unwrap();
        assert_eq!(anchored.candidate_bytes, 5);
        assert!(anchored.from_anchored_prefix);
        assert_eq!(initial.candidate_bytes, 1);
        assert!(!initial.from_anchored_prefix);
        assert!(filter_selection_key(initial) < filter_selection_key(anchored));

        let (_, layout) = build_native_dfa_table(view).unwrap();
        assert_eq!(layout.start_filter, Some(initial));
        let prefix = layout.prefix_filter.unwrap();
        assert_eq!(prefix.guaranteed_bytes, 4);
        assert_eq!(prefix.predicates().len(), 3);
        assert_eq!(
            prefix
                .predicates()
                .iter()
                .map(|predicate| predicate.position)
                .collect::<Vec<_>>(),
            [0, 1, 2],
            "an initial-departure scanner must retain every selective anchored predicate"
        );
    }

    #[test]
    fn coalesced_initial_membership_is_a_deterministic_bounded_superset() {
        let membership_words = |bytes: &[u8]| {
            let mut words = [0_u64; 4];
            for &byte in bytes {
                let index = usize::from(byte);
                words[index / 64] |= 1_u64 << (index % 64);
            }
            words
        };
        let contains = |filter: NativeStartFilter, byte: u8| {
            filter
                .ranges()
                .iter()
                .any(|range| range.start <= byte && byte <= range.end)
        };

        let original = membership_words(&[1, 3, 5, 7, 20, 24, 28, 32, 36]);
        let first = coalesced_initial_filter_from_membership_words(original)
            .unwrap()
            .unwrap();
        let second = coalesced_initial_filter_from_membership_words(original)
            .unwrap()
            .unwrap();
        assert_eq!(first, second, "coalescing must be reproducible");
        assert!(first.ranges().len() <= MAX_START_FILTER_RANGES);
        assert!(first.candidate_bytes <= MAX_START_FILTER_CANDIDATE_BYTES);
        for byte in u8::MIN..=u8::MAX {
            let index = usize::from(byte);
            let was_member = original[index / 64] & (1_u64 << (index % 64)) != 0;
            assert!(
                !was_member || contains(first, byte),
                "coalescing lost exact member {byte}"
            );
        }

        // All four gaps have equal width and equal frequency bucket. The
        // stable left-position tie break must merge the first one.
        let tied = coalesced_initial_filter_from_membership_words(membership_words(&[
            192, 194, 196, 198, 200,
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(
            tied.ranges(),
            [
                NativeByteRange {
                    start: 192,
                    end: 194
                },
                NativeByteRange {
                    start: 196,
                    end: 196
                },
                NativeByteRange {
                    start: 198,
                    end: 198
                },
                NativeByteRange {
                    start: 200,
                    end: 200
                },
            ]
        );

        assert!(
            coalesced_initial_filter_from_membership_words(membership_words(&[
                0, 64, 128, 192, 255,
            ]))
            .unwrap()
            .is_none(),
            "range merging must not exceed the fixed 64-byte candidate cap"
        );
    }

    #[test]
    fn coalesced_initial_fallback_is_general_and_preserves_stronger_suffixes() {
        let layout_for = |pattern: &str, output| {
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            let view = compiled.program().native_dfa_view().unwrap();
            let exact_start = derive_start_filter(view).unwrap();
            let selected_suffix = derive_suffix_filter(view).unwrap();
            let coalesced = derive_coalesced_initial_start_filter(view).unwrap();
            let layout = build_native_dfa_table(view).unwrap().1;
            (exact_start, selected_suffix, coalesced, layout)
        };

        let fragmented = r"(?:A|C|E|G|I|K|M|O|Q).{0,8}[ ]";
        let (exact, selected, coalesced, layout) = layout_for(fragmented, OutputContract::Exists);
        assert!(exact.is_none());
        assert!(
            selected.is_some_and(|suffix| { suffix.retry.is_none() && suffix.retry_cost_rejected })
        );
        let coalesced = coalesced.expect("bounded coalesced initial membership");
        assert_eq!(layout.start_filter, Some(coalesced));
        assert!(layout.suffix_filter.is_none());
        assert!(!coalesced.from_anchored_prefix);
        assert_eq!(coalesced.scan_offset, 0);

        // Independently generated structural witness from the development
        // seed suite. Its spelling is test data only; admission above depends
        // exclusively on the DFA membership and finite retry cost facts.
        let generated =
            r"(?:(?:(?:(?:(?:(?:[o-p]SXF[C-G])|Ts|rY)){1,4}|3G2|ECb)){2,4}?(?-u:[\x00-\xFF]))";
        let (exact, selected, coalesced, layout) = layout_for(generated, OutputContract::Exists);
        assert!(exact.is_some());
        assert!(selected.is_some_and(|suffix| suffix.retry_cost_rejected));
        assert!(
            coalesced.is_some(),
            "the older approximation remains derivable"
        );
        assert_eq!(layout.start_filter, exact);
        assert!(layout.suffix_filter.is_some());

        let (exact, selected, _, layout) =
            layout_for(r"[\x20-\x3F].{0,8}[ ]", OutputContract::Exists);
        assert!(exact.is_some());
        assert!(selected.is_some_and(|suffix| suffix.retry_cost_rejected));
        assert_eq!(layout.start_filter, exact);
        assert!(
            layout.suffix_filter.is_some(),
            "an exact start scanner must retain the independently selected suffix"
        );

        let (exact, selected, coalesced, layout) = layout_for(
            r"(?-u:(?:A|C|E|G|I|K|M|O|Q).{0,1}[ ])",
            OutputContract::Exists,
        );
        assert!(exact.is_none());
        assert!(selected.is_some_and(|suffix| suffix.retry.is_some()));
        assert!(
            coalesced.is_some(),
            "the approximation itself is representable"
        );
        assert_eq!(layout.start_filter, coalesced);
        assert!(layout.suffix_filter.is_some());

        let far_apart = r"(?-u:[\x00-\x0B\x40-\x4B\x80-\x8B\xC0-\xCB\xF4-\xFF].{0,8}[ ])";
        let (exact, selected, coalesced, layout) = layout_for(far_apart, OutputContract::Exists);
        assert!(exact.is_none());
        assert!(selected.is_some_and(|suffix| suffix.retry_cost_rejected));
        assert!(coalesced.is_none());
        assert!(layout.start_filter.is_none());
        assert!(layout.suffix_filter.is_some());

        // This fragmented initial alphabet has no useful mandatory suffix.
        // The cover is therefore admitted independently of suffix analysis,
        // for every native output contract.
        let no_suffix = r"(?:A|C|E|G|I|K|M|O|Q)+";
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let (exact, selected, coalesced, layout) = layout_for(no_suffix, output);
            assert!(exact.is_none());
            assert!(selected.is_none());
            let coalesced = coalesced.expect("fragmented initial cover");
            assert_eq!(layout.start_filter, Some(coalesced));
            assert!(layout.suffix_filter.is_none());
        }

        // An acceptance-boundary suffix remains independently useful: the
        // coalesced initial cover must not displace a suffix that was not a
        // rejected finite-retry candidate.
        let proving = r"(?:A|C|E|G|I|K|M|O|Q)+Z";
        let (exact, selected, coalesced, layout) = layout_for(proving, OutputContract::Exists);
        assert!(exact.is_none());
        assert!(coalesced.is_some());
        assert!(selected.is_some_and(|suffix| matches!(
            suffix.reverse_seed,
            NativeSuffixReverseSeed::AcceptBoundary
        )));
        assert_eq!(layout.start_filter, coalesced);
        assert_eq!(layout.suffix_filter, selected);
    }

    #[test]
    fn vector_secondary_columns_keep_exact_membership_under_coalescing() {
        let words_for = |bytes: &[u8]| {
            let mut words = [0_u64; 4];
            for &byte in bytes {
                let index = usize::from(byte);
                words[index / 64] |= 1_u64 << (index % 64);
            }
            words
        };
        let fragmented_words = words_for(b"ACEGI");
        assert!(
            coalesced_initial_filter_from_membership_words(fragmented_words)
                .unwrap()
                .is_some()
        );
        let sets = [
            AnchoredByteSet::from_words(fragmented_words),
            AnchoredByteSet::from_words(words_for(b"Q")),
            AnchoredByteSet::from_words(words_for(b"Z")),
        ];
        let fragmented_exact = start_filter_from_anchored_set(sets[0], 0)
            .unwrap()
            .expect("five singleton anchored alternatives are represented exactly");
        assert!(fragmented_exact.is_exact());
        assert_eq!(fragmented_exact.ranges().len(), 5);
        let primary = start_filter_from_anchored_set(sets[1], 1).unwrap().unwrap();
        let vector = derive_vector_filter(Some(primary), &sets).unwrap().unwrap();
        assert_eq!(vector.columns()[0], primary);
        for &secondary in &vector.columns()[1..] {
            let exact = start_filter_from_anchored_set(
                sets[usize::from(secondary.scan_offset)],
                usize::from(secondary.scan_offset),
            )
            .unwrap()
            .unwrap();
            assert_eq!(secondary, exact);
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table test covers aligned columns and every graph-proven restart category"
    )]
    fn suffix_filter_uses_aligned_graph_columns_and_proven_restarts() {
        let layout_for = |pattern: &str| {
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1
        };

        let literal = layout_for("abcde").suffix_filter.unwrap();
        assert_eq!(literal.filter.scan_offset, 1);
        assert!(!literal.filter.from_anchored_prefix);
        assert_eq!(literal.minimum_width, 5);
        assert_eq!(
            literal.restart,
            NativeSuffixRestart::Bounded { backtrack: 0 }
        );
        assert_eq!(
            literal.filter.ranges(),
            [NativeByteRange {
                start: b'b',
                end: b'b'
            }]
        );
        let literal_columns = literal.vector_filter.unwrap();
        assert_eq!(literal_columns.columns()[0], literal.filter);
        assert!(literal_columns.columns().len() >= 2);
        assert!(
            literal_columns.columns()[1..]
                .iter()
                .all(|column| column.scan_offset < literal.minimum_width
                    && *column != literal.filter)
        );

        let variable = layout_for("ab(?:c)?d").suffix_filter.unwrap();
        assert_eq!(variable.minimum_width, 3);
        assert_eq!(variable.filter.scan_offset, 1);
        assert_eq!(
            variable.restart,
            NativeSuffixRestart::Bounded { backtrack: 0 }
        );
        assert_eq!(
            variable.filter.ranges(),
            [NativeByteRange {
                start: b'b',
                end: b'b'
            }]
        );

        let unbounded = layout_for("abc+d").suffix_filter.unwrap();
        assert_eq!(
            unbounded.restart,
            NativeSuffixRestart::Bounded { backtrack: 0 },
            "the mandatory interior prefix has a finite distance even though the complete language is unbounded"
        );
        assert!(layout_for("a?b?").suffix_filter.is_none());
        let fragmented_terminal = layout_for("[acegi]").suffix_filter.unwrap();
        assert_eq!(fragmented_terminal.filter.candidate_bytes, 5);
        assert!(fragmented_terminal.filter.is_exact());

        let terminal_class = layout_for("x[a-d]").suffix_filter.unwrap();
        assert_eq!(terminal_class.filter.scan_offset, 0);
        assert_eq!(terminal_class.filter.candidate_bytes, 1);
        assert_eq!(
            terminal_class.filter.ranges(),
            [NativeByteRange {
                start: b'x',
                end: b'x'
            }]
        );

        let broad = layout_for("[a-e]").suffix_filter.unwrap();
        assert_eq!(broad.filter.candidate_bytes, 5);
        assert_eq!(
            broad.filter.ranges(),
            [NativeByteRange {
                start: b'a',
                end: b'e'
            }]
        );

        let any_terminal = layout_for("q(?-u:[\\x00-\\xff])").suffix_filter.unwrap();
        assert_eq!(any_terminal.minimum_width, 2);
        assert_eq!(any_terminal.filter.scan_offset, 0);
        assert_eq!(
            any_terminal.filter.ranges(),
            [NativeByteRange {
                start: b'q',
                end: b'q'
            }]
        );

        let unbounded_without_reset = layout_for("(?s:.+)z").suffix_filter.unwrap();
        assert_eq!(
            unbounded_without_reset.restart,
            NativeSuffixRestart::OriginalStart
        );

        let correlated = layout_for(r"(?:QX|zY|jW)(?-u:[\x00-\xFF])")
            .suffix_filter
            .unwrap();
        assert!(correlated.vector_filter.is_none());
        assert!(
            correlated
                .scalar_filter
                .is_some_and(|columns| columns.columns().len() >= 2),
            "expensive SIMD constants should retain a cold aligned scalar refinement"
        );
    }

    #[test]
    fn suffix_scalar_secondary_rejection_reenters_vector_prepass() {
        let pattern = r"(?:QX|zY|jW)(?-u:[\x00-\xFF])";
        let layout_for = |target| {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1
        };

        let x86_layout = layout_for(Target::x86_64_linux());
        let x86_suffix = x86_layout.suffix_filter.unwrap();
        assert!(x86_suffix.vector_filter.is_none());
        assert!(x86_suffix.scalar_filter.is_some());
        let mut x86 = X86Assembler::new();
        let x86_no_match = x86.label().unwrap();
        let x86_matched = x86.label().unwrap();
        let x86_vector = x86.labels.len();
        x86_emit_suffix_prepass(
            &mut x86,
            x86_suffix,
            X86StartFilterKind::Sse2,
            x86_layout,
            x86_no_match,
            x86_matched,
        )
        .unwrap();
        assert!(x86.fixups.iter().any(|fixup| {
            fixup.label == x86_vector
                && fixup.displacement >= 4
                && x86.code.get(fixup.displacement - 4..fixup.displacement - 1)
                    == Some(&[0x48, 0xff, 0xc2][..])
        }));
        x86.bind(x86_no_match).unwrap();
        x86.bind(x86_matched).unwrap();
        x86.finish().unwrap();

        let asimd_target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let aarch64_layout = layout_for(asimd_target);
        let aarch64_suffix = aarch64_layout.suffix_filter.unwrap();
        assert!(aarch64_suffix.vector_filter.is_none());
        assert!(aarch64_suffix.scalar_filter.is_some());
        let mut aarch64 = Aarch64Assembler::new();
        let aarch64_no_match = aarch64.label().unwrap();
        let aarch64_matched = aarch64.label().unwrap();
        let aarch64_vector = aarch64.labels.len();
        aarch64_emit_suffix_prepass(
            &mut aarch64,
            aarch64_suffix,
            true,
            true,
            false,
            aarch64_layout,
            aarch64_no_match,
            aarch64_matched,
        )
        .unwrap();
        let increment = aarch64_add_x_imm(2, 2, 1).unwrap().to_le_bytes();
        assert!(aarch64.fixups.iter().any(|fixup| {
            fixup.label == aarch64_vector
                && matches!(fixup.kind, Aarch64FixupKind::Branch26)
                && fixup.instruction >= 4
                && aarch64.code.get(fixup.instruction - 4..fixup.instruction)
                    == Some(&increment[..])
        }));
        aarch64.bind(aarch64_no_match).unwrap();
        aarch64.bind(aarch64_matched).unwrap();
        aarch64.finish().unwrap();
    }

    #[test]
    fn mandatory_interior_filter_selects_a_sparse_nonterminal_sequence() {
        let compiled = compile(
            CompileRequest::new(
                r"(?:(?:(?:(?:(?:p)+?|rdj|D))+7L7(?:3tG)*?)[a-b])",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        )
        .unwrap();
        let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
            .unwrap()
            .1;
        let mandatory = layout.suffix_filter.expect("mandatory interior filter");
        assert!(mandatory.minimum_width >= 3);
        let columns = mandatory.vector_filter.expect("aligned interior columns");
        for byte in [b'7', b'L'] {
            assert!(columns.columns().iter().any(|column| {
                column.ranges()
                    == [NativeByteRange {
                        start: byte,
                        end: byte,
                    }]
            }));
        }
        assert!(matches!(
            mandatory.restart,
            NativeSuffixRestart::Synchronizing { .. }
        ));
        assert!(mandatory.retry.is_none());
    }

    #[test]
    fn bounded_suffix_retry_is_selected_from_graph_width_and_filter_cost() {
        let layout_for = |output| {
            let compiled = compile(
                CompileRequest::new(r"(?:MQw|[d-e]|r74){2,3}[j-k]Q", Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1
        };

        let exists = layout_for(OutputContract::Exists).suffix_filter.unwrap();
        let retry = exists.retry.expect("sparse bounded suffix must retry");
        assert_eq!(retry.maximum_width(), 11);
        assert_eq!(retry.backtrack(), 7);
        assert_eq!(retry.minimum_width(), 4);
        assert!(retry.estimated_transition_units() <= 128);
        assert_eq!(
            exists.restart,
            NativeSuffixRestart::Bounded { backtrack: 7 }
        );

        for output in [OutputContract::SelectedEnd, OutputContract::Span] {
            assert!(layout_for(output).suffix_filter.unwrap().retry.is_none());
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact-complement proof enumerates all reset and non-reset byte classes"
    )]
    fn synchronizing_suffix_restart_is_an_exact_small_complement() {
        let compiled = compile(
            CompileRequest::new("x*abc+d", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let view = compiled.program().native_dfa_view().unwrap();
        let reset = view.dfa.synchronizing_reset_bytes().unwrap();
        let layout = build_native_dfa_table(view).unwrap().1;
        let NativeSuffixRestart::Synchronizing { non_reset } =
            layout.suffix_filter.unwrap().restart
        else {
            panic!("unbounded suffix did not select a synchronizing restart");
        };

        assert_eq!(
            reset.cardinality + non_reset.candidate_bytes,
            u16::from(u8::MAX) + 1
        );
        for byte in u8::MIN..=u8::MAX {
            let index = usize::from(byte);
            let is_reset = reset.membership.words[index / 64] & (1_u64 << (index % 64)) != 0;
            let is_non_reset = non_reset
                .ranges()
                .iter()
                .any(|range| (range.start..=range.end).contains(&byte));
            assert_eq!(is_non_reset, !is_reset, "byte {byte:#04x}");
        }
        assert_eq!(
            non_reset.ranges(),
            [NativeByteRange {
                start: b'a',
                end: b'd'
            }]
        );

        let all_reset = reset_filter_from_membership_words([0; 4]).unwrap().unwrap();
        assert_eq!(all_reset.candidate_bytes, 0);
        assert!(all_reset.ranges().is_empty());
        assert!(
            reset_filter_from_membership_words([u64::MAX; 4])
                .unwrap()
                .is_none(),
            "an empty reset set has a full complement and must miss the bounded encoder"
        );

        let mut fragmented = [0_u64; 4];
        for byte in [b'A', b'C', b'E', b'G', b'I', b'K', b'M', b'X', b'Z'] {
            let byte = usize::from(byte);
            fragmented[byte / 64] |= 1_u64 << (byte % 64);
        }
        assert!(
            filter_from_membership_words(fragmented, 0, false)
                .unwrap()
                .is_none(),
            "the hot SIMD filter deliberately retains its four-range cap"
        );
        let fragmented = reset_filter_from_membership_words(fragmented)
            .unwrap()
            .expect("a tiny fragmented reset complement uses the cold-path budget");
        assert_eq!(fragmented.candidate_bytes, 9);
        assert_eq!(fragmented.ranges().len(), 9);

        let mut x86 = X86Assembler::new();
        x86_emit_suffix_reset_restart(&mut x86, non_reset).unwrap();
        let x86 = x86.finish().unwrap();
        assert!(x86.starts_with(&[
            0x49, 0x89, 0xd2, // cursor = suffix base
            0x41, 0xbb, 64, 0, 0, 0, // exactly 64 candidate bytes
            0x49, 0x39, 0xf2, // compare before decrement: base is excluded
            0x0f, 0x86,
        ]));
        assert!(x86.windows(5).any(|bytes| {
            bytes == [0x42, 0x0f, 0xb6, 0x04, 0x17] // haystack[--cursor]
        }));
        assert!(x86.windows(4).any(|bytes| {
            bytes == [0x49, 0x8d, 0x52, 1] // restart = reset + 1
        }));
        assert!(x86.windows(3).any(|bytes| {
            bytes == [0x48, 0x89, 0xf2] // no reset restores original start
        }));

        let mut aarch64 = Aarch64Assembler::new();
        aarch64_emit_suffix_reset_restart(&mut aarch64, non_reset).unwrap();
        let words = aarch64
            .finish()
            .unwrap()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(words[0], aarch64_mov_x(10, 2).unwrap());
        assert_eq!(words[1], aarch64_movz_w(6, 64).unwrap());
        assert_eq!(words[2], aarch64_cmp_x(10, 9).unwrap());
        assert_eq!(words[4], aarch64_sub_x_imm(10, 10, 1).unwrap());
        assert_eq!(words[5], aarch64_load_byte_reg(8, 0, 10).unwrap());
        assert!(words.contains(&aarch64_add_x_imm(2, 10, 1).unwrap()));
        assert!(words.contains(&aarch64_mov_x(2, 9).unwrap()));

        let mut x86 = X86Assembler::new();
        x86_emit_suffix_restart(&mut x86, NativeSuffixRestart::OriginalStart).unwrap();
        assert_eq!(x86.finish().unwrap(), [0x48, 0x89, 0xf2]);
        let mut aarch64 = Aarch64Assembler::new();
        aarch64_emit_suffix_restart(&mut aarch64, NativeSuffixRestart::OriginalStart).unwrap();
        assert_eq!(
            aarch64.finish().unwrap(),
            aarch64_mov_x(2, 9).unwrap().to_le_bytes()
        );
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "the bounded 16/32/64-lane oracle and its exact/range witnesses stay together"
    )]
    fn vector_filter_masks_match_scalar_intersection_for_every_byte_pair() {
        fn contains(filter: NativeStartFilter, byte: u8) -> bool {
            filter
                .ranges()
                .iter()
                .any(|range| (range.start..=range.end).contains(&byte))
        }

        fn scalar_matches(filter: NativeVectorFilter, haystack: &[u8], position: usize) -> bool {
            filter.columns().iter().all(|column| {
                contains(
                    *column,
                    haystack[position + usize::from(column.scan_offset)],
                )
            })
        }

        fn emulated_vector_mask(filter: NativeVectorFilter, haystack: &[u8], width: usize) -> u64 {
            let mut intersection = u64::MAX;
            for column in filter.columns() {
                let mut column_mask = 0_u64;
                for lane in 0..width {
                    let byte = haystack[lane + usize::from(column.scan_offset)];
                    if contains(*column, byte) {
                        column_mask |= 1_u64 << lane;
                    }
                }
                intersection &= column_mask;
            }
            intersection
        }

        fn assert_all_lanes(filter: NativeVectorFilter) {
            assert_eq!(filter.columns().len(), 2);
            for width in [16_usize, 32, 64] {
                let mut haystack = vec![0_u8; width + usize::from(filter.max_scan_offset())];
                let probe_lane = width / 2;
                for first in u8::MIN..=u8::MAX {
                    for second in u8::MIN..=u8::MAX {
                        haystack.fill(0);
                        haystack[probe_lane + usize::from(filter.columns()[0].scan_offset)] = first;
                        haystack[probe_lane + usize::from(filter.columns()[1].scan_offset)] =
                            second;
                        let mask = emulated_vector_mask(filter, &haystack, width);
                        for lane in 0..width {
                            assert_eq!(
                                mask & (1_u64 << lane) != 0,
                                scalar_matches(filter, &haystack, lane)
                            );
                        }
                    }
                }
            }
        }

        let compiled = compile(
            CompileRequest::new("eats", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let filter = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
            .unwrap()
            .1
            .vector_filter
            .unwrap();
        assert_all_lanes(filter);

        let suffix = compile(
            CompileRequest::new("needle", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let suffix_filter = build_native_dfa_table(suffix.program().native_dfa_view().unwrap())
            .unwrap()
            .1
            .suffix_filter
            .unwrap()
            .vector_filter
            .unwrap();
        assert_all_lanes(suffix_filter);

        let any_terminal = compile(
            CompileRequest::new("qk(?-u:[\\x00-\\xff])", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let any_terminal =
            build_native_dfa_table(any_terminal.program().native_dfa_view().unwrap())
                .unwrap()
                .1
                .suffix_filter
                .unwrap();
        assert_eq!(any_terminal.minimum_width, 3);
        assert!(any_terminal.filter.scan_offset < 2);
        assert_all_lanes(any_terminal.vector_filter.unwrap());

        for pattern in [
            r"(?-u:\x01[\x03-\x06])",
            r"(?-u:[\x01-\x02]e)",
            r"(?-u:[\x01-\x02][\x03-\x06])",
        ] {
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap();
            let filter = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1
                .vector_filter
                .unwrap();
            assert!(
                filter.columns().iter().any(|column| !column.is_exact()),
                "{pattern} must retain a range column"
            );
            assert_all_lanes(filter);
        }
    }

    #[test]
    fn lazy_vector_intersection_and_four_register_ld1_have_exact_encodings() {
        let x86 = compile(
            CompileRequest::new("eats", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let x86_code = x86.module().sections()[TEXT_SECTION].bytes();
        assert!(
            x86_code
                .windows(5)
                .any(|bytes| bytes == [0x66, 0x41, 0x0f, 0xdb, 0xfc]),
            "SSE2 lazy secondary path must intersect xmm7 with xmm12"
        );
        assert!(
            x86_code
                .windows(4)
                .any(|bytes| bytes == [0x66, 0x0f, 0xd7, 0xc7]),
            "SSE2 lazy secondary path must extract the intersected mask"
        );

        let asimd_target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let aarch64 = compile(
            CompileRequest::new("eats", asimd_target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let words = aarch64.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(aarch64_ld1_four_16b(24, 12).unwrap(), 0x4c40_2198);
        assert_eq!(aarch64_ld1_four_16b(16, 12).unwrap(), 0x4c40_2190);
        assert_eq!(aarch64_ext_16b(16, 24, 25, 1).unwrap(), 0x6e19_0b10);
        assert_eq!(aarch64_ext_16b(16, 25, 26, 1).unwrap(), 0x6e1a_0b30);
        assert!(aarch64_ext_16b(16, 24, 25, 16).is_err());
        assert!(words.contains(&aarch64_ld1_four_16b(16, 12).unwrap()));
        assert!(words.contains(&aarch64_and_16b(24, 24, 20).unwrap()));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "three ISA encodings and the AVX-512 conservative refinement are audited together"
    )]
    fn lazy_range_intersections_have_exact_x86_and_asimd_encodings() {
        let pattern = r"(?-u:\x01[\x03-\x06])";
        let compile_for = |target| {
            compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap()
        };

        let sse2 = compile_for(Target::x86_64_linux());
        let layout = build_native_dfa_table(sse2.program().native_dfa_view().unwrap())
            .unwrap()
            .1;
        let columns = layout.vector_filter.unwrap();
        assert!(columns.columns()[0].is_exact());
        assert!(!columns.columns()[1].is_exact());
        assert_eq!(columns.columns()[1].scan_offset, 1);
        let code = sse2.module().sections()[TEXT_SECTION].bytes();
        assert!(
            code.windows(6)
                .any(|bytes| { bytes == [0xf3, 0x0f, 0x6f, 0x44, 0x17, 1] })
        );
        assert!(
            code.windows(5)
                .any(|bytes| { bytes == [0x66, 0x44, 0x0f, 0xde, 0xd2] })
        );
        assert!(
            code.windows(5)
                .any(|bytes| { bytes == [0x66, 0x44, 0x0f, 0xda, 0xdb] })
        );
        assert!(
            code.windows(5)
                .any(|bytes| { bytes == [0x66, 0x45, 0x0f, 0x6f, 0xca] })
        );
        assert!(
            code.windows(5)
                .any(|bytes| { bytes == [0x66, 0x45, 0x0f, 0x6f, 0xe1] })
        );
        assert!(
            code.windows(5)
                .any(|bytes| { bytes == [0x66, 0x41, 0x0f, 0xdb, 0xfc] })
        );

        let avx2_target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let avx2 = compile_for(avx2_target);
        let code = avx2.module().sections()[TEXT_SECTION].bytes();
        assert!(
            code.windows(4)
                .any(|bytes| { bytes == [0xc5, 0x7d, 0xde, 0xd2] })
        );
        assert!(
            code.windows(5)
                .any(|bytes| { bytes == [0xc4, 0x41, 0x2d, 0xeb, 0xca] })
        );
        assert!(
            code.windows(5)
                .any(|bytes| { bytes == [0xc4, 0x41, 0x7d, 0x6f, 0xe1] })
        );
        assert!(
            code.windows(5)
                .any(|bytes| { bytes == [0xc4, 0xc1, 0x45, 0xdb, 0xfc] })
        );

        let asimd_target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let aarch64 = compile_for(asimd_target);
        let words = aarch64.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(words.contains(&aarch64_cmhs_16b(5, 0, 2).unwrap()));
        assert!(words.contains(&aarch64_cmhs_16b(6, 3, 0).unwrap()));
        assert!(words.contains(&aarch64_and_16b(5, 5, 6).unwrap()));
        assert!(words.contains(&aarch64_orr_16b(25, 5, 5).unwrap()));
        assert!(words.contains(&aarch64_and_16b(24, 24, 25).unwrap()));

        let range_primary = compile(
            CompileRequest::new(r"(?-u:[\x01-\x02]e)", asimd_target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let range_primary_layout =
            build_native_dfa_table(range_primary.program().native_dfa_view().unwrap())
                .unwrap()
                .1;
        assert!(!range_primary_layout.vector_filter.unwrap().columns()[0].is_exact());
        let words = range_primary.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(words.contains(&aarch64_cmhs_16b(5, 0, 1).unwrap()));
        assert!(words.contains(&aarch64_cmhs_16b(6, 2, 0).unwrap()));
        assert!(words.contains(&aarch64_orr_16b(24, 5, 5).unwrap()));

        let avx512_features = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let avx512 = compile_for(
            Target::x86_64_linux()
                .with_features(avx512_features)
                .unwrap(),
        );
        let avx512_layout = build_native_dfa_table(avx512.program().native_dfa_view().unwrap())
            .unwrap()
            .1;
        assert!(
            avx512_layout
                .vector_filter
                .unwrap()
                .columns()
                .iter()
                .any(|column| !column.is_exact())
        );
        assert_eq!(
            avx512.module().start_accelerator(),
            StartAccelerator::X86Avx512Bw
        );
        let code = avx512.module().sections()[TEXT_SECTION].bytes();
        assert!(
            code.windows(5)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xd4, 0x41, 0xec]),
            "AVX-512 must intersect the range secondary from k4 into k5"
        );
        assert!(
            code.windows(5)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xfb, 0x93, 0xc5]),
            "AVX-512 must select the exact intersected lane"
        );
    }

    fn maximum_x86_range_filter() -> NativeStartFilter {
        NativeStartFilter {
            ranges: [
                NativeByteRange {
                    start: b'0',
                    end: b'2',
                },
                NativeByteRange {
                    start: b'A',
                    end: b'B',
                },
                NativeByteRange {
                    start: b'_',
                    end: b'_',
                },
                NativeByteRange {
                    start: b'e',
                    end: b'f',
                },
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
            ],
            range_count: 4,
            candidate_bytes: 8,
            scan_offset: 0,
            from_anchored_prefix: false,
        }
    }

    #[test]
    fn aarch64_filter_constant_banks_are_disjoint_from_live_scanner_registers() {
        let vector_constants = (0..MAX_VECTOR_FILTER_CONSTANTS)
            .map(|index| {
                aarch64_filter_constant_register(AARCH64_VECTOR_FILTER_FIRST_CONSTANT, index)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let standalone_constants = (0..MAX_START_FILTER_RANGES)
            .map(|index| {
                aarch64_filter_constant_register(AARCH64_STANDALONE_FILTER_FIRST_CONSTANT, index)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let relation_constants = (0..usize::from(MAX_AARCH64_PREFIX_RELATION_CONSTANTS))
            .map(|index| {
                aarch64_prefix_relation_constant_register(
                    AARCH64_VECTOR_FILTER_FIRST_CONSTANT,
                    index,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(vector_constants, [1, 2, 3, 4]);
        assert_eq!(relation_constants, [1, 2, 3, 4, 5, 6]);
        assert_eq!(standalone_constants, [16, 17, 18, 19, 20, 21, 22, 23]);
        assert!(aarch64_filter_constant_register(AARCH64_VECTOR_FILTER_FIRST_CONSTANT, 4).is_err());
        assert!(
            aarch64_prefix_relation_constant_register(AARCH64_VECTOR_FILTER_FIRST_CONSTANT, 6)
                .is_err()
        );
        assert!(
            aarch64_filter_constant_register(AARCH64_STANDALONE_FILTER_FIRST_CONSTANT, 8).is_err()
        );

        // Multi-column filters keep constants in V1..V4. The relation
        // lowering may extend that bank through V6, but uses V17..V21 rather
        // than the ordinary range helper's V5/V6 scratch. Standalone
        // exact/range filters reverse the allocation: V16..V23 hold constants,
        // V24..V27 sources and V0..V3 masks. Every allocation leaves V7's
        // reduction scratch and the ABI-preserved bank untouched.
        let vector_live = [
            5_u8, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let standalone_live = [0_u8, 1, 2, 3, 5, 6, 7, 24, 25, 26, 27, 28, 29, 30, 31];
        let relation_live = [0_u8, 7, 16, 17, 18, 19, 20, 21, 24, 29, 30, 31];
        assert!(
            vector_constants
                .iter()
                .all(|register| !vector_live.contains(register))
        );
        assert!(
            standalone_constants
                .iter()
                .all(|register| !standalone_live.contains(register))
        );
        assert!(
            relation_constants
                .iter()
                .all(|register| !relation_live.contains(register))
        );
        assert!(
            vector_constants
                .iter()
                .chain(&relation_constants)
                .chain(&standalone_constants)
                .all(|register| !matches!(register, 8..=15))
        );
    }

    #[test]
    fn aarch64_fragmented_exact_model_and_code_shape_cover_every_byte() {
        for singleton_count in [7_usize, 8] {
            for member in u8::MIN..=u8::MAX {
                let mut membership = [0_u64; 4];
                for step in 0..singleton_count {
                    let byte = member.wrapping_add(u8::try_from(step * 2).unwrap());
                    let index = usize::from(byte);
                    membership[index / 64] |= 1_u64 << (index % 64);
                }
                let filter = filter_from_membership_words(membership, 0, false)
                    .unwrap()
                    .expect("seven/eight separated bytes fit the exact scanner");
                assert!(filter.is_exact());
                assert_eq!(filter.ranges().len(), singleton_count);
                for byte in u8::MIN..=u8::MAX {
                    let index = usize::from(byte);
                    let expected = membership[index / 64] & (1_u64 << (index % 64)) != 0;
                    let modeled = filter
                        .ranges()
                        .iter()
                        .any(|range| range.start == byte && range.end == byte);
                    assert_eq!(modeled, expected, "member={member:#04x}, byte={byte:#04x}");
                }

                let mut assembler = Aarch64Assembler::new();
                aarch64_emit_start_filter_constants(
                    &mut assembler,
                    filter,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )
                .unwrap();
                for pass in 0..2 {
                    aarch64_emit_start_filter_vector_candidates(
                        &mut assembler,
                        filter,
                        24,
                        0,
                        AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                    )
                    .unwrap();
                    if pass == 0 {
                        aarch64_emit_candidate_any(&mut assembler, 0).unwrap();
                    }
                }
                let words = assembler
                    .finish()
                    .unwrap()
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                assert!(words.contains(&aarch64_umaxv_16b(7, 0).unwrap()));
                for (index, range) in filter.ranges().iter().enumerate() {
                    let register = aarch64_filter_constant_register(
                        AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                        index,
                    )
                    .unwrap();
                    assert!(!matches!(register, 7..=15 | 24..=31));
                    assert!(words.contains(&aarch64_movi_16b(register, range.start).unwrap()));
                    let destination = if index == 0 {
                        0
                    } else {
                        AARCH64_EXACT_FILTER_SCRATCH
                    };
                    let compare = aarch64_cmeq_16b(destination, 24, register).unwrap();
                    assert_eq!(words.iter().filter(|word| **word == compare).count(), 2);
                }
            }
        }
    }

    #[test]
    fn x86_filter_register_allocation_keeps_constants_out_of_all_work_registers() {
        let filter = maximum_x86_range_filter();
        assert_eq!(filter.constant_count(), 8);
        let maximum_constants = (0..filter.constant_count())
            .map(|index| x86_filter_constant_register(1, index).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(maximum_constants, (1_u8..=8).collect::<Vec<_>>());
        for work_register in [9_u8, 10, 11, 12] {
            assert!(!maximum_constants.contains(&work_register));
        }

        let exact_pair = NativeStartFilter {
            ranges: [
                NativeByteRange {
                    start: b'a',
                    end: b'a',
                },
                NativeByteRange {
                    start: b'z',
                    end: b'z',
                },
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
            ],
            range_count: 2,
            candidate_bytes: 2,
            scan_offset: 0,
            from_anchored_prefix: false,
        };
        let exact_one = NativeStartFilter {
            ranges: [
                NativeByteRange {
                    start: b'q',
                    end: b'q',
                },
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
                EMPTY_NATIVE_BYTE_RANGE,
            ],
            range_count: 1,
            candidate_bytes: 1,
            scan_offset: 1,
            from_anchored_prefix: false,
        };
        let maximum_columns = NativeVectorFilter {
            columns: [exact_pair, exact_one, exact_one],
            column_count: 3,
        };
        let mut next_register = 1_u8;
        let mut column_constants = Vec::new();
        for column in maximum_columns.columns() {
            for index in 0..column.constant_count() {
                column_constants.push(x86_filter_constant_register(next_register, index).unwrap());
            }
            next_register = next_register
                .checked_add(u8::try_from(column.constant_count()).unwrap())
                .unwrap();
        }
        assert_eq!(column_constants, [1, 2, 3, 4]);
        for work_register in [9_u8, 10, 11, 12] {
            assert!(!column_constants.contains(&work_register));
        }
    }

    #[test]
    fn fragmented_exact_start_filter_uses_reserved_masks_on_every_vector_isa() {
        let membership = |bytes: &[u8]| {
            let mut words = [0_u64; 4];
            for &byte in bytes {
                let index = usize::from(byte);
                words[index / 64] |= 1_u64 << (index % 64);
            }
            words
        };
        let filter = filter_from_membership_words(membership(b"ACEGI"), 2, true)
            .unwrap()
            .expect("five exact alternatives fit the bounded vector representation");
        assert!(filter.is_exact());
        assert_eq!(filter.ranges().len(), 5);
        assert_eq!(filter.constant_count(), 5);
        assert_eq!(filter.scan_offset, 2);
        let maximum_filter = filter_from_membership_words(membership(b"ACEGIKMO"), 1, true)
            .unwrap()
            .expect("eight exact alternatives fill the register budget");
        assert_eq!(maximum_filter.ranges().len(), 8);

        assert!(
            filter_from_membership_words(membership(b"ABDEGHJKMN"), 0, false)
                .unwrap()
                .is_none(),
            "five non-exact ranges retain the four-range cost ceiling"
        );
        assert!(
            filter_from_membership_words(membership(b"ACEGIKMOQ"), 0, false)
                .unwrap()
                .is_none(),
            "nine exact alternatives exceed the fixed register budget"
        );

        for kind in [
            X86StartFilterKind::Sse2,
            X86StartFilterKind::Avx2,
            X86StartFilterKind::Avx512Bw,
        ] {
            let mut assembler = X86Assembler::new();
            x86_emit_start_filter_constants(&mut assembler, maximum_filter, kind, 1).unwrap();
            x86_emit_start_filter_vector_candidates(&mut assembler, maximum_filter, kind, 1)
                .unwrap();
            let code = assembler.finish().unwrap();
            match kind {
                X86StartFilterKind::Sse2 => {
                    assert!(
                        code.windows(5)
                            .any(|bytes| bytes == [0x66, 0x44, 0x0f, 0x6f, 0xe0])
                    );
                    assert!(
                        code.windows(5)
                            .any(|bytes| bytes == [0x66, 0x45, 0x0f, 0xeb, 0xe3])
                    );
                    assert!(
                        !code
                            .windows(4)
                            .any(|bytes| bytes == [0x66, 0x0f, 0x6f, 0xe8])
                    );
                    assert!(
                        code.windows(5)
                            .any(|bytes| bytes == [0x66, 0x45, 0x0f, 0x74, 0xd8]),
                        "the eighth SSE2 constant must retain its extended register bit"
                    );
                }
                X86StartFilterKind::Avx2 => {
                    assert!(
                        code.windows(5)
                            .any(|bytes| bytes == [0xc4, 0x41, 0x1d, 0xeb, 0xe3])
                    );
                    assert!(
                        code.windows(4)
                            .any(|bytes| bytes == [0xc5, 0x3d, 0x74, 0xd8]),
                        "the eighth AVX2 constant must use the commuted high-register form"
                    );
                }
                X86StartFilterKind::Avx512Bw => {
                    assert_eq!(
                        X86CandidateMask::for_filter(maximum_filter, kind),
                        X86CandidateMask::Avx512K1
                    );
                }
            }
        }

        let mut aarch64 = Aarch64Assembler::new();
        aarch64_emit_start_filter_constants(
            &mut aarch64,
            maximum_filter,
            AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
        )
        .unwrap();
        aarch64_emit_start_filter_vector_candidates(
            &mut aarch64,
            maximum_filter,
            24,
            0,
            AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
        )
        .unwrap();
        let words = aarch64
            .finish()
            .unwrap()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(
            words.contains(&aarch64_movi_16b(23, b'O').unwrap())
                && words.contains(&aarch64_cmeq_16b(AARCH64_EXACT_FILTER_SCRATCH, 24, 23).unwrap()),
            "the eighth ASIMD constant and exact-union scratch must stay caller-saved"
        );
        assert!(
            words.iter().all(|word| !matches!(word & 0x1f, 8..=15)),
            "ASIMD filter helpers must not write ABI-preserved V8..V15"
        );
    }

    #[test]
    fn x86_filter_candidate_carrier_is_disjoint_from_maximum_constants() {
        let filter = maximum_x86_range_filter();
        let emit = |kind| {
            let mut assembler = X86Assembler::new();
            x86_emit_start_filter_constants(&mut assembler, filter, kind, 1).unwrap();
            x86_emit_range_start_filter_vector_candidates(&mut assembler, filter, kind, 1).unwrap();
            assembler.finish().unwrap()
        };
        let sse2 = emit(X86StartFilterKind::Sse2);
        assert!(
            sse2.windows(5)
                .any(|bytes| bytes == [0x66, 0x45, 0x0f, 0x6f, 0xca])
        );
        assert!(
            sse2.windows(5)
                .any(|bytes| bytes == [0x66, 0x45, 0x0f, 0xeb, 0xca])
        );
        assert!(
            sse2.windows(5)
                .any(|bytes| bytes == [0x66, 0x45, 0x0f, 0x6f, 0xe1])
        );
        assert!(
            !sse2
                .windows(5)
                .any(|bytes| bytes == [0x66, 0x41, 0x0f, 0x6f, 0xea])
        );

        let avx2 = emit(X86StartFilterKind::Avx2);
        assert!(
            avx2.windows(5)
                .any(|bytes| bytes == [0xc4, 0x41, 0x2d, 0xeb, 0xca])
        );
        assert!(
            avx2.windows(5)
                .any(|bytes| bytes == [0xc4, 0x41, 0x2d, 0xeb, 0xc9])
        );
        assert!(
            avx2.windows(5)
                .any(|bytes| bytes == [0xc4, 0x41, 0x7d, 0x6f, 0xe1])
        );
        assert!(
            !avx2
                .windows(4)
                .any(|bytes| bytes == [0xc5, 0x7d, 0x7f, 0xd5])
        );

        let avx512 = emit(X86StartFilterKind::Avx512Bw);
        assert!(
            avx512
                .windows(7)
                .any(|bytes| bytes == [0x62, 0xd3, 0x7d, 0x48, 0x3e, 0xd0, 2]),
            "the fourth range high endpoint must compare against zmm8"
        );
        assert!(
            avx512
                .windows(5)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xdc, 0x45, 0xe3])
        ); // korq k4, k4, k3
    }

    #[test]
    fn anchored_prefix_filter_is_emitted_only_with_structural_candidate_proofs() {
        for target in [
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ] {
            let literal = compile(
                CompileRequest::new("abcde", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            assert_eq!(
                literal.program().anchored_prefix_stats().guaranteed_bytes,
                5
            );
            assert_eq!(literal.module().anchored_prefix_filter_bytes(), 5);

            let variable = compile(
                CompileRequest::new("ab(?:c)?d", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .unwrap();
            assert_eq!(variable.module().anchored_prefix_filter_bytes(), 3);

            // A one-byte proof adds nothing after the existing candidate
            // scanner. Nullable graphs and overly broad initial candidate sets
            // also keep the multi-byte precheck disabled.
            for pattern in ["a", "a*", "(?:a|bc)", "(?-u:[\\x00-\\xff])z"] {
                let compiled = compile(
                    CompileRequest::new(pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::SelectedEnd),
                )
                .unwrap();
                assert_eq!(
                    compiled.module().anchored_prefix_filter_bytes(),
                    0,
                    "{pattern}"
                );
            }

            let text = literal.module().sections()[TEXT_SECTION].bytes();
            match target.architecture {
                Architecture::X86_64 => assert!(
                    text.windows(4)
                        .any(|bytes| bytes == [0x49, 0x0f, 0xa3, 0x81])
                ),
                Architecture::Aarch64 => {
                    let words = text
                        .chunks_exact(4)
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                        .collect::<Vec<_>>();
                    assert!((b'a'..=b'e').any(|byte| {
                        words.contains(&aarch64_cmp_w_imm(8, u16::from(byte)).unwrap())
                    }));
                }
            }
        }
    }

    #[test]
    fn sixteen_byte_prefix_block_is_transactional_and_has_exact_cross_isa_lowering() {
        let pattern = "abcdefghijklmnop";
        let layout_for = |architecture| {
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            build_native_dfa_table_for_architecture(
                compiled.program().native_dfa_view().unwrap(),
                architecture,
            )
            .unwrap()
        };

        let (x86_data, x86_layout) = layout_for(Architecture::X86_64);
        let x86_block = x86_layout
            .prefix_block
            .expect("sixteen graph singleton columns select one block guard");
        assert_eq!(x86_layout.prefix_guaranteed_bytes().unwrap(), 16);
        assert_eq!(x86_layout.exact_prefix_match_width, Some(16));
        assert!(x86_layout.suffix_filter.is_some());
        assert_eq!(x86_block.lane_mask, u16::MAX);
        assert_eq!(x86_block.expected_offset % 16, 0);
        assert_eq!(
            x86_block.byte_mask_offset,
            x86_block.expected_offset + u32::try_from(prefix_block::PREFIX_BLOCK_BYTES).unwrap()
        );
        let expected = usize::try_from(x86_block.expected_offset).unwrap();
        let mask = usize::try_from(x86_block.byte_mask_offset).unwrap();
        assert_eq!(&x86_data[expected..expected + 16], pattern.as_bytes());
        assert_eq!(&x86_data[mask..mask + 16], &[u8::MAX; 16]);
        assert_eq!(x86_data.len(), mask + 16);

        for (features, load, compare) in [
            (
                FeatureSet::EMPTY,
                &[0xf3, 0x0f, 0x6f, 0x04, 0x17][..],
                &[0x66, 0x41, 0x0f, 0x74, 0x81][..],
            ),
            (
                FeatureSet::of(CpuFeature::X86Avx2),
                &[0xc5, 0xfa, 0x6f, 0x04, 0x17][..],
                &[0xc4, 0xc1, 0x79, 0x74, 0x81][..],
            ),
            (
                FeatureSet::of(CpuFeature::X86Avx512F)
                    .union(FeatureSet::of(CpuFeature::X86Avx512Bw)),
                &[0xc5, 0xfa, 0x6f, 0x04, 0x17][..],
                &[0xc4, 0xc1, 0x79, 0x74, 0x81][..],
            ),
        ] {
            let code = lower_x86_64_dfa(x86_layout, features).unwrap().0;
            assert!(
                code.windows(load.len())
                    .filter(|bytes| *bytes == load)
                    .count()
                    >= 2,
                "the entry exact-start probe and moving guard must both load the block"
            );
            assert!(
                code.windows(compare.len())
                    .filter(|bytes| *bytes == compare)
                    .count()
                    >= 2
            );
        }

        let (aarch64_data, aarch64_layout) = layout_for(Architecture::Aarch64);
        let aarch64_block = aarch64_layout.prefix_block.unwrap();
        let expected = usize::try_from(aarch64_block.expected_offset).unwrap();
        let mask = usize::try_from(aarch64_block.byte_mask_offset).unwrap();
        assert_eq!(&aarch64_data[expected..expected + 16], pattern.as_bytes());
        assert_eq!(&aarch64_data[mask..mask + 16], &[u8::MAX; 16]);
        assert_eq!(aarch64_data.len(), mask + 16);

        let scalar = lower_aarch64_dfa(aarch64_layout, FeatureSet::EMPTY)
            .unwrap()
            .0;
        let scalar_words = scalar
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(
            !scalar_words.contains(&aarch64_eor_16b(25, 25, 26).unwrap()),
            "the feature-free target must retain exact scalar predicates"
        );

        let asimd = lower_aarch64_dfa(aarch64_layout, FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap()
            .0;
        let asimd_words = asimd
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(
            asimd_words
                .iter()
                .filter(|&&word| word == aarch64_eor_16b(25, 25, 26).unwrap())
                .count()
                >= 2
        );
        assert!(
            !asimd_words.contains(&aarch64_and_16b(25, 25, 27).unwrap()),
            "an all-singleton block has no inactive lanes to mask"
        );
        assert!(asimd_words.contains(&aarch64_umaxv_16b(25, 25).unwrap()));
        assert!(asimd_words.contains(&aarch64_umov_b0(12, 25).unwrap()));

        let mut partial = Aarch64Assembler::new();
        let partial_failed = partial.label().unwrap();
        aarch64_emit_prefix_block(
            &mut partial,
            NativePrefixBlockGuard {
                expected_offset: 0x100,
                byte_mask_offset: 0x110,
                lane_mask: 0x800f,
            },
            partial_failed,
        )
        .unwrap();
        partial.bind(partial_failed).unwrap();
        let partial_words = partial
            .finish()
            .unwrap()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(partial_words.contains(&aarch64_load_q(27, 12).unwrap()));
        assert!(partial_words.contains(&aarch64_and_16b(25, 25, 27).unwrap()));
        assert!(
            !partial_words.contains(&aarch64_eor_16b(24, 24, 26).unwrap())
                && !partial_words.contains(&aarch64_and_16b(24, 24, 27).unwrap()),
            "the retained V24 candidate mask is never a block destination"
        );

        let singleton = |byte: u8| {
            let mut words = [0_u64; 4];
            let index = usize::from(byte);
            words[index / 64] |= 1_u64 << (index % 64);
            AnchoredByteSet::from_words(words)
        };
        let sets: [AnchoredByteSet; prefix_block::PREFIX_BLOCK_BYTES] =
            core::array::from_fn(|index| singleton(u8::try_from(index).unwrap()));
        let plan = prefix_block::derive(&sets).unwrap();
        let mut too_small = vec![0_u8; 7];
        let before = too_small.clone();
        assert_eq!(
            append_native_prefix_block(&mut too_small, plan, 47).unwrap(),
            None
        );
        assert_eq!(too_small, before, "a declined optional guard is atomic");
        let installed = append_native_prefix_block(&mut too_small, plan, 48)
            .unwrap()
            .unwrap();
        assert_eq!(installed.expected_offset, 16);
        assert_eq!(installed.byte_mask_offset, 32);
        assert_eq!(too_small.len(), 48);
    }

    #[test]
    fn exact_prefix_product_proof_accepts_only_complete_uncorrelated_products() {
        let compile_view = |pattern: &str| {
            compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap()
        };
        for (pattern, width) in [
            ("a", 1_u8),
            ("abc", 3),
            ("[a-c][0-2]", 2),
            ("(?:ab|ac)", 2),
            ("(?:ab|cb)", 2),
        ] {
            let compiled = compile_view(pattern);
            let view = compiled.program().native_dfa_view().unwrap();
            assert_eq!(
                derive_exact_prefix_product_width(view),
                Some(width),
                "{pattern}"
            );
            let (_, layout) = build_native_dfa_table(view).unwrap();
            assert_eq!(layout.exact_prefix_match_width, Some(width), "{pattern}");
        }

        let correlated = compile_view("(?:ab|cd)");
        let correlated_view = correlated.program().native_dfa_view().unwrap();
        assert_eq!(derive_exact_prefix_product_width(correlated_view), None);
        assert_eq!(
            build_native_dfa_table(correlated_view)
                .unwrap()
                .1
                .exact_prefix_match_width,
            None
        );

        let all_bytes = compile_view("(?-u:[\\x00-\\xff])");
        let all_bytes_view = all_bytes.program().native_dfa_view().unwrap();
        assert_eq!(derive_exact_prefix_product_width(all_bytes_view), Some(1));
        assert_eq!(
            build_native_dfa_table(all_bytes_view)
                .unwrap()
                .1
                .exact_prefix_match_width,
            None,
            "an all-byte product has no safe selective scanner"
        );

        let empty = compile_view("");
        let empty_view = empty.program().native_dfa_view().unwrap();
        assert_eq!(empty_view.exact_match_width, Some(0));
        assert_eq!(derive_exact_prefix_product_width(empty_view), None);
    }

    #[test]
    fn correlated_prefix_relation_is_exact_and_lowers_on_both_isas() {
        let compiled = compile(
            CompileRequest::new("(?:ab|cd)", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let (data, layout) =
            build_native_dfa_table(compiled.program().native_dfa_view().unwrap()).unwrap();
        let relation = layout
            .prefix_relation
            .expect("the two alternatives have a non-Cartesian prefix");
        let vector_plan = relation
            .vector_plan
            .expect("two singleton rectangles fit every target budget");
        assert_eq!(vector_plan.rectangles().len(), 2);
        let bitmap = &data[usize::try_from(relation.bitmap_offset).unwrap()..];
        let contains = |first: u8, second: u8| {
            let pair = usize::from(first) | (usize::from(second) << 8);
            bitmap[pair / 8] & (1_u8 << (pair % 8)) != 0
        };
        assert!(contains(b'a', b'b'));
        assert!(contains(b'c', b'd'));
        assert!(!contains(b'a', b'd'));
        assert!(!contains(b'c', b'b'));
        assert!(
            layout
                .prefix_filter
                .is_none_or(|prefix| prefix.predicates().iter().all(|p| p.position >= 2)),
            "the exact pair matrix subsumes both independent columns"
        );

        let (x86, _) = lower_x86_64_dfa(layout, FeatureSet::EMPTY).unwrap();
        assert!(
            x86.windows(4)
                .any(|bytes| bytes == [0x0f, 0xb7, 0x04, 0x17]),
            "x86 must form the pair index with one little-endian halfword load"
        );
        let (aarch64, _) = lower_aarch64_dfa(layout, FeatureSet::EMPTY).unwrap();
        let words = aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(words.contains(&aarch64_load_halfword_reg(8, 0, 2).unwrap()));
    }

    #[test]
    fn prefix_relation_vector_plan_is_general_exact_and_budget_driven() {
        let raw_relation = |pattern: &str| {
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            prefix_relation::derive(compiled.program().native_dfa_view().unwrap().raw)
                .expect("structural two-byte relation")
        };

        // This is one non-singleton rectangle, not a list of enumerated byte
        // pairs: {a,d} x [b-c]. It remains useful as a direct lowering proof
        // even though the complete compiler correctly recognizes the same
        // relation as an independent Cartesian product.
        let rectangle = raw_relation("(?:a[bc]|d[bc])");
        assert_eq!(rectangle.groups().len(), 1);
        for architecture in [Architecture::X86_64, Architecture::Aarch64] {
            let plan = derive_native_prefix_relation_vector(&rectangle, architecture)
                .expect("one exact/range rectangle fits the target budget");
            assert_eq!(plan.rectangles().len(), 1);
            assert_eq!(plan.rectangles()[0].first.filter.ranges().len(), 2);
            assert_eq!(
                plan.rectangles()[0].second.filter.ranges(),
                &[NativeByteRange {
                    start: b'b',
                    end: b'c'
                }]
            );
            for first in u8::MIN..=u8::MAX {
                for second in u8::MIN..=u8::MAX {
                    assert_eq!(
                        native_prefix_relation_vector_contains(plan, first, second),
                        prefix_relation_contains(&rectangle, first, second)
                    );
                }
            }
        }

        let complement = raw_relation(r"(?-u:(?:[^a]X|aY))");
        let complement_plan =
            derive_native_prefix_relation_vector(&complement, Architecture::X86_64)
                .expect("a dense leaf is represented by its exact complement");
        assert!(
            complement_plan
                .rectangles()
                .iter()
                .any(|rectangle| { rectangle.first.negated || rectangle.second.negated })
        );

        let structural =
            raw_relation(r"(?:(?:(?:(?:(?:(?:Kh|UZ|GX8)){1,4}){1,2}?)+?)+(?-u:[\x00-\xFF]))");
        assert_eq!(structural.groups().len(), 3);
        assert!(derive_native_prefix_relation_vector(&structural, Architecture::X86_64).is_some());
        assert!(derive_native_prefix_relation_vector(&structural, Architecture::Aarch64).is_some());

        // Five distinct rows exceed both targets because their measured leaf
        // constant demand is ten, not because the fixed plan can hold only a
        // benchmark-shaped number of rectangles. Capacity follows the graph
        // analysis's 32-group resource limit.
        let five = raw_relation("(?:ab|cd|ef|gh|ij)");
        assert_eq!(five.groups().len(), 5);
        assert!(five.groups().len() <= MAX_NATIVE_PREFIX_RELATION_RECTANGLES);
        let required_constants = five
            .groups()
            .iter()
            .copied()
            .map(|group| {
                native_prefix_relation_predicate(group.first(), 0)
                    .unwrap()
                    .filter
                    .constant_count()
                    + native_prefix_relation_predicate(group.second(), 1)
                        .unwrap()
                        .filter
                        .constant_count()
            })
            .sum::<usize>();
        assert_eq!(required_constants, 10);
        assert!(required_constants > usize::from(MAX_X86_PREFIX_RELATION_CONSTANTS));
        assert!(required_constants > usize::from(MAX_AARCH64_PREFIX_RELATION_CONSTANTS));
        assert!(derive_native_prefix_relation_vector(&five, Architecture::X86_64).is_none());
        assert!(derive_native_prefix_relation_vector(&five, Architecture::Aarch64).is_none());
    }

    #[test]
    fn avx512_prefix_relation_retains_the_complete_k5_lane_mask() {
        let target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw))
            .unwrap();
        let compiled = compile(
            CompileRequest::new("(?:ab|cd|ef)", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
            .unwrap()
            .1;
        assert_eq!(
            layout
                .prefix_relation
                .and_then(|relation| relation.vector_plan)
                .unwrap()
                .rectangles()
                .len(),
            3
        );
        let code = compiled.module().sections()[TEXT_SECTION].bytes();
        assert!(
            code.windows(9)
                .any(|bytes| bytes == [0xc4, 0xe1, 0xfb, 0x93, 0xc5, 0x48, 0x0f, 0xbc, 0xc0]),
            "KMOVQ K5 followed by BSFQ must inspect all 64 candidate lanes"
        );
    }

    #[test]
    fn guarded_prefix_reconvergence_skips_proved_dfa_transitions_on_both_isas() {
        let compiled = compile(
            CompileRequest::new("(?:qb|rd)[A-Za-z0-9]", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let (_, layout) =
            build_native_dfa_table(compiled.program().native_dfa_view().unwrap()).unwrap();
        let fast_forward = layout
            .prefix_fast_forward
            .unwrap_or_else(|| panic!("the exact pair guard must reconverge: {layout:#?}"));
        assert_eq!(fast_forward.consumed_bytes, 2);
        assert_ne!(fast_forward.target_row_offset, layout.forward_offset);

        let (x86, _) = lower_x86_64_dfa(layout, FeatureSet::EMPTY).unwrap();
        assert!(
            x86.windows(4)
                .any(|bytes| bytes == [0x48, 0x83, 0xc2, 0x02]),
            "x86 must advance past the graph-proved pair"
        );
        let mut target_row = vec![0x4d, 0x8d, 0x91];
        target_row.extend_from_slice(&fast_forward.target_row_offset.to_le_bytes());
        assert!(
            x86.windows(target_row.len())
                .any(|bytes| bytes == target_row)
        );

        let (aarch64, _) = lower_aarch64_dfa(layout, FeatureSet::EMPTY).unwrap();
        let words = aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(words.contains(&aarch64_add_x_imm(2, 2, 2).unwrap()));
    }

    #[test]
    fn exact_prefix_success_has_direct_contract_encodings_on_both_isas() {
        let compile_layout = |target, output| {
            let compiled = compile(
                CompileRequest::new("q", target)
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1
        };

        let x86_span = lower_x86_64_dfa(
            compile_layout(Target::x86_64_linux(), OutputContract::Span),
            FeatureSet::EMPTY,
        )
        .unwrap()
        .0;
        let x86_span_success = [
            0x48, 0x8d, 0x42, 1, // end = candidate + 1
            0x49, 0x89, 0x10, // result.start = candidate
            0x49, 0x89, 0x40, 0x08, // result.end = end
        ];
        assert!(
            x86_span
                .windows(x86_span_success.len())
                .any(|window| window == x86_span_success)
        );

        let x86_selected = lower_x86_64_dfa(
            compile_layout(Target::x86_64_linux(), OutputContract::SelectedEnd),
            FeatureSet::EMPTY,
        )
        .unwrap()
        .0;
        let x86_selected_success = [
            0x48, 0x8d, 0x42, 1, // end = candidate + 1
            0x49, 0x89, 0x00, // result.start = end
            0x49, 0x89, 0x40, 0x08, // result.end = end
        ];
        assert!(
            x86_selected
                .windows(x86_selected_success.len())
                .any(|window| window == x86_selected_success)
        );

        let aarch64_span = lower_aarch64_dfa(
            compile_layout(Target::aarch64_linux(), OutputContract::Span),
            FeatureSet::EMPTY,
        )
        .unwrap()
        .0;
        let aarch64_words = aarch64_span
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let aarch64_span_success = [
            aarch64_add_x_imm(6, 2, 1).unwrap(),
            aarch64_store_x(2, 4, 0).unwrap(),
            aarch64_store_x(6, 4, 8).unwrap(),
        ];
        assert!(
            aarch64_words
                .windows(aarch64_span_success.len())
                .any(|window| window == aarch64_span_success)
        );
    }

    #[test]
    fn exact_start_probe_rechecks_the_scanner_primary_before_suffixing() {
        let layout_for = |target| {
            let compiled = compile(
                CompileRequest::new("abcde", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1
        };

        let x86_layout = layout_for(Target::x86_64_linux());
        assert_eq!(x86_layout.exact_prefix_match_width, Some(5));
        assert!(x86_layout.suffix_filter.is_some());
        let primary = x86_layout.start_filter.unwrap();
        assert!(primary.from_anchored_prefix);
        let prefix_predicates = x86_layout.prefix_filter.unwrap().predicates().len();
        let x86 = lower_x86_64_dfa(x86_layout, FeatureSet::EMPTY).unwrap().0;
        let direct_span = [
            0x48, 0x8d, 0x42, 5, 0x49, 0x89, 0x10, 0x49, 0x89, 0x40, 0x08,
        ];
        assert_eq!(
            x86.windows(direct_span.len())
                .filter(|window| *window == direct_span)
                .count(),
            2,
            "the untouched-start probe and moving prefix guard each need one exact return"
        );
        let primary_load = if primary.scan_offset == 0 {
            vec![0x0f, 0xb6, 0x04, 0x17, 0x3c, primary.ranges()[0].start]
        } else {
            vec![
                0x0f,
                0xb6,
                0x44,
                0x17,
                primary.scan_offset,
                0x3c,
                primary.ranges()[0].start,
            ]
        };
        assert!(
            x86.windows(primary_load.len())
                .filter(|window| *window == primary_load)
                .count()
                >= 2,
            "the entry probe must not rely on a scanner validation that has not happened"
        );
        let relation_vector = x86_layout
            .prefix_relation
            .and_then(|relation| relation.vector_plan);
        let vector_filter = relation_vector
            .is_none()
            .then_some(x86_layout.vector_filter)
            .flatten();
        let vector_coverage = derive_native_vector_guard_coverage(
            x86_layout,
            relation_vector.is_some(),
            vector_filter,
        )
        .unwrap();
        let vector_residual_predicates = x86_layout
            .prefix_filter
            .unwrap()
            .predicates()
            .iter()
            .filter(|predicate| !vector_coverage.covers_position(predicate.position))
            .count();
        assert_eq!(
            x86.windows(4)
                .filter(|bytes| *bytes == [0x49, 0x0f, 0xa3, 0x81])
                .count(),
            prefix_predicates * 2 + vector_residual_predicates
        );

        let aarch64_layout = layout_for(Target::aarch64_linux());
        let primary = aarch64_layout.start_filter.unwrap();
        let aarch64 = lower_aarch64_dfa(aarch64_layout, FeatureSet::EMPTY)
            .unwrap()
            .0;
        let words = aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let direct_span = [
            aarch64_add_x_imm(6, 2, 5).unwrap(),
            aarch64_store_x(2, 4, 0).unwrap(),
            aarch64_store_x(6, 4, 8).unwrap(),
        ];
        assert_eq!(
            words
                .windows(direct_span.len())
                .filter(|window| *window == direct_span)
                .count(),
            2
        );
        let primary_load = if primary.scan_offset == 0 {
            aarch64_load_byte_reg(8, 0, 2).unwrap()
        } else {
            aarch64_load_byte_imm(8, 12, u16::from(primary.scan_offset)).unwrap()
        };
        assert!(words.iter().filter(|word| **word == primary_load).count() >= 2);
    }

    #[test]
    fn interior_self_loop_skip_is_graph_selected_and_feature_exact() {
        let layout = |pattern, output, architecture| {
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            build_native_dfa_table_for_architecture(
                compiled.program().native_dfa_view().unwrap(),
                architecture,
            )
            .unwrap()
            .1
        };
        let nonaccepting = layout(
            "A(?-u:[^Z])*Z",
            OutputContract::Exists,
            Architecture::X86_64,
        );
        let nonaccepting_plan = nonaccepting.loop_skip.expect("nonaccepting interior loop");
        assert!(!nonaccepting_plan.accepting);
        assert_eq!(nonaccepting_plan.filter.candidate_bytes, 1);
        assert_eq!(nonaccepting_plan.filter.ranges()[0].start, b'Z');

        let accepting = layout("(?-u:[^Z]*)", OutputContract::Span, Architecture::Aarch64);
        let accepting_plan = accepting.loop_skip.expect("accepting initial loop");
        assert!(accepting_plan.accepting);

        for (features, minimum_remaining) in [
            (FeatureSet::EMPTY, 32_u32),
            (FeatureSet::of(CpuFeature::X86Avx2), 64),
            (
                FeatureSet::of(CpuFeature::X86Avx512F)
                    .union(FeatureSet::of(CpuFeature::X86Avx512Bw)),
                128,
            ),
        ] {
            let code = lower_x86_64_dfa(nonaccepting, features).unwrap().0;
            let mut entry_gate = vec![0x48, 0x3d]; // cmp remaining, 2 * vector width
            entry_gate.extend_from_slice(&minimum_remaining.to_le_bytes());
            entry_gate.extend_from_slice(&[0x0f, 0x82]);
            assert!(
                code.windows(entry_gate.len())
                    .any(|window| window == entry_gate)
            );

            let mut row_guard = vec![0x49, 0x8d, 0x81];
            row_guard.extend_from_slice(&nonaccepting_plan.row_offset.to_le_bytes());
            row_guard.extend_from_slice(&[0x49, 0x39, 0xc2, 0x0f, 0x85]);
            assert!(
                code.windows(row_guard.len())
                    .any(|window| window == row_guard)
            );
        }

        let nonaccepting_aarch64 = layout(
            "A(?-u:[^Z])*Z",
            OutputContract::Exists,
            Architecture::Aarch64,
        );
        let scalar_aarch64 = lower_aarch64_dfa(nonaccepting_aarch64, FeatureSet::EMPTY)
            .unwrap()
            .0;
        let scalar_words = scalar_aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(scalar_words.contains(&aarch64_cmp_x_imm(12, 8).unwrap()));

        let asimd_aarch64 = lower_aarch64_dfa(accepting, FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap()
            .0;
        let asimd_words = asimd_aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(asimd_words.contains(&aarch64_cmp_x_imm(12, 32).unwrap()));
        assert!(asimd_words.contains(&aarch64_ld1_four_16b(16, 12).unwrap()));
    }

    #[test]
    fn absolute_row_offsets_remove_hot_multiply_and_reverse_is_dead_when_unused() {
        let selected_layout = NativeDfaLayout {
            transitions: TransitionLayout::ClassMapped,
            forward_offset: 256,
            reverse_offset: 512,
            asimd_lane_index_offset: None,
            initial_pending: false,
            initial_terminal: false,
            has_reverse: false,
            exact_span_width: None,
            exact_prefix_match_width: None,
            output: OutputContract::SelectedEnd,
            start_filter: None,
            suffix_filter: None,
            declined_redundant_root_reverse: false,
            seeded_reverse: None,
            loop_skip: None,
            vector_filter: None,
            prefix_filter: None,
            prefix_relation: None,
            prefix_block: None,
            prefix_fast_forward: None,
        };
        let (x86_code, _) = lower_x86_64_dfa(selected_layout, FeatureSet::EMPTY).unwrap();
        assert!(
            x86_code
                .windows(4)
                .any(|bytes| bytes == [0x41, 0x8b, 0x04, 0x82])
        );
        assert!(
            x86_code
                .windows(5)
                .any(|bytes| bytes == [0x4d, 0x8d, 0x54, 0x01, 0xff])
        );
        assert!(!x86_code.windows(3).any(|bytes| bytes == [0x45, 0x69, 0xd2]));
        assert!(!x86_code.windows(3).any(|bytes| bytes == [0x41, 0xc1, 0xe2]));

        let (aarch64_code, _) = lower_aarch64_dfa(selected_layout, FeatureSet::EMPTY).unwrap();
        let aarch64_words = aarch64_code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(aarch64_words.contains(&0xb868_5968));
        assert!(aarch64_words.contains(&0x8b06_00ab));

        let selected = lower_x86_64_dfa(selected_layout, FeatureSet::EMPTY)
            .unwrap()
            .0;
        let span = lower_x86_64_dfa(
            NativeDfaLayout {
                has_reverse: true,
                output: OutputContract::Span,
                ..selected_layout
            },
            FeatureSet::EMPTY,
        )
        .unwrap()
        .0;
        assert!(span.len() > selected.len());
    }

    #[test]
    fn ordinary_live_cell_classifier_is_exhaustive_over_packable_layouts() {
        // Exhaust every value in reduced packed layouts, not merely selected
        // regex tables. The same algebra scales to the production 30-bit
        // payload because neither classifier depends on a state or pattern.
        for payload_bits in 1_u32..=16 {
            let payload_mask = (1_u32 << payload_bits) - 1;
            let decoded_maximum = payload_mask - 1;
            for packed in 0_u32..(4_u32 << payload_bits) {
                let payload = packed & payload_mask;
                let flags = packed >> payload_bits;
                let accelerated = flags & 1 != 0;
                let packable = !(accelerated && payload == 0);
                if !packable {
                    continue;
                }

                let expected_ordinary = flags == 0 && payload != 0;
                let decoded = packed.wrapping_sub(1);
                let x86_classification = decoded <= decoded_maximum;
                let aarch64_classification = decoded >> payload_bits == 0;
                assert_eq!(x86_classification, expected_ordinary);
                assert_eq!(aarch64_classification, expected_ordinary);
            }
        }

        assert_eq!(CELL_ORDINARY_DECODED_MAX, CELL_NEXT_MASK - 1);
        for flags in [
            0,
            CELL_ACCELERATED,
            CELL_ACCEPTS,
            CELL_ACCELERATED | CELL_ACCEPTS,
        ] {
            for payload in [0, 1, 2, CELL_NEXT_MASK - 1, CELL_NEXT_MASK] {
                if flags & CELL_ACCELERATED != 0 && payload == 0 {
                    continue;
                }
                let packed = flags | payload;
                let decoded = packed.wrapping_sub(1);
                let expected_ordinary = flags == 0 && payload != 0;
                assert_eq!(decoded <= CELL_ORDINARY_DECODED_MAX, expected_ordinary);
                assert_eq!(
                    decoded >> CELL_ACCELERATED.trailing_zeros() == 0,
                    expected_ordinary
                );
            }
        }

        // Accelerator-only dead is the sole subtract-and-shift alias. Packing
        // rejects it, and consistently rejects its accepting-tagged variant.
        for accepts in [false, true] {
            assert!(
                pack_native_cell_with_acceleration(NO_DFA_STATE, accepts, 0, 4, 1, true).is_err()
            );
        }
    }

    #[test]
    fn packed_native_cell_model_exhaustively_preserves_flags_and_absolute_tokens() {
        let machine_offsets = [0_usize, CLASS_MAP_BYTES, 4096];
        let row_widths = [4_usize, 20, DIRECT_BYTE_ROW_BYTES];
        for states in 1_usize..=17 {
            for machine_offset in machine_offsets {
                for row_bytes in row_widths {
                    for next_index in 0..=states {
                        let next = if next_index == states {
                            NO_DFA_STATE
                        } else {
                            u32::try_from(next_index).unwrap()
                        };
                        let encoded =
                            encode_native_next(next, machine_offset, row_bytes, states).unwrap();
                        for flag in [false, true] {
                            for accelerated in [false, true] {
                                let packed = pack_native_cell_with_acceleration(
                                    next,
                                    flag,
                                    machine_offset,
                                    row_bytes,
                                    states,
                                    accelerated,
                                );
                                if next == NO_DFA_STATE && accelerated {
                                    assert!(packed.is_err());
                                    continue;
                                }
                                let packed = packed.unwrap();
                                assert_eq!(
                                    packed & CELL_NEXT_MASK,
                                    u32::try_from(encoded).unwrap()
                                );
                                assert_eq!(packed & CELL_ACCEPTS != 0, flag);
                                assert_eq!(packed & CELL_ACCELERATED != 0, accelerated);
                                assert_eq!(
                                    packed & !(CELL_ACCEPTS | CELL_ACCELERATED | CELL_NEXT_MASK),
                                    0
                                );
                            }
                        }
                    }
                    let outside = u32::try_from(states).unwrap();
                    assert!(
                        pack_native_cell(outside, false, machine_offset, row_bytes, states)
                            .is_err()
                    );
                }
            }
        }

        let maximum_offset = usize::try_from(CELL_NEXT_MASK).unwrap() - 1;
        assert_eq!(
            pack_native_cell(0, false, maximum_offset, 4, 1).unwrap(),
            CELL_NEXT_MASK
        );
        assert!(pack_native_cell(0, false, maximum_offset + 1, 4, 1).is_err());

        for next in core::iter::once(NO_DFA_STATE).chain(0_u32..=8) {
            for initial_scannable in [false, true] {
                for loop_state in core::iter::once(None).chain((0_u32..=8).map(Some)) {
                    let packed = pack_native_forward_cell(
                        next,
                        false,
                        0,
                        4,
                        9,
                        initial_scannable,
                        loop_state,
                    )
                    .unwrap();
                    let expected = next != NO_DFA_STATE
                        && ((initial_scannable && next == 0) || loop_state == Some(next));
                    assert_eq!(packed & CELL_ACCELERATED != 0, expected);
                }
            }
        }
    }

    #[test]
    fn forward_cells_tag_exact_graph_accelerator_targets_and_reverse_cells_do_not() {
        let compiled = compile(
            CompileRequest::new("A(?-u:[^Z])*Z", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let view = compiled.program().native_dfa_view().unwrap();
        let (data, layout) = build_native_dfa_table(view).unwrap();
        let loop_state = layout.loop_skip.map(|plan| plan.state);
        assert!(layout.start_filter.is_some());
        assert!(loop_state.is_some());
        assert!(layout.has_reverse);

        let row_cells = layout.transitions.row_cells(view.dfa.class_count);
        let row_bytes = row_cells * core::mem::size_of::<u32>();
        let forward_states = view.dfa.forward_cells.len() / view.dfa.class_count;
        let forward_offset = usize::try_from(layout.forward_offset).unwrap();
        for state in 0..forward_states {
            for physical_column in 0..row_cells {
                let class = match layout.transitions {
                    TransitionLayout::ClassMapped => physical_column,
                    TransitionLayout::DirectByte => {
                        usize::from(view.dfa.byte_classes[physical_column])
                    }
                };
                let cell = view.dfa.forward_cells[state * view.dfa.class_count + class];
                let offset = forward_offset + state * row_bytes + physical_column * 4;
                let packed = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                let expected_tag = cell.next != NO_DFA_STATE
                    && ((cell.next == 0 && layout.start_filter.is_some())
                        || loop_state == Some(cell.next));
                assert_eq!(packed & CELL_ACCELERATED != 0, expected_tag);
                assert_eq!(packed & CELL_ACCEPTS != 0, cell.accepted);
                assert_eq!(
                    packed & CELL_NEXT_MASK,
                    u32::try_from(
                        encode_native_next(cell.next, forward_offset, row_bytes, forward_states,)
                            .unwrap()
                    )
                    .unwrap()
                );
            }
        }

        let reverse_states = view.dfa.reverse_cells.len() / view.dfa.class_count;
        let reverse_offset = usize::try_from(layout.reverse_offset).unwrap();
        for state in 0..reverse_states {
            for physical_column in 0..row_cells {
                let class = match layout.transitions {
                    TransitionLayout::ClassMapped => physical_column,
                    TransitionLayout::DirectByte => {
                        usize::from(view.dfa.byte_classes[physical_column])
                    }
                };
                let cell = view.dfa.reverse_cells[state * view.dfa.class_count + class];
                let offset = reverse_offset + state * row_bytes + physical_column * 4;
                let packed = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                assert_eq!(packed & CELL_ACCELERATED, 0);
                assert_eq!(packed & CELL_ACCEPTS != 0, cell.reaches_start);
                assert_eq!(
                    packed & CELL_NEXT_MASK,
                    u32::try_from(
                        encode_native_next(cell.next, reverse_offset, row_bytes, reverse_states,)
                            .unwrap()
                    )
                    .unwrap()
                );
            }
        }
    }

    #[test]
    fn transition_layout_selection_is_cache_bounded_and_graph_only() {
        assert_eq!(
            select_transition_layout(DIRECT_BYTE_TABLE_BUDGET / DIRECT_BYTE_ROW_BYTES, 0),
            TransitionLayout::DirectByte
        );
        assert_eq!(
            select_transition_layout(DIRECT_BYTE_TABLE_BUDGET / DIRECT_BYTE_ROW_BYTES + 1, 0),
            TransitionLayout::ClassMapped
        );
        assert_eq!(
            select_transition_layout(12, 12),
            TransitionLayout::DirectByte
        );
        assert_eq!(
            select_transition_layout(12, 13),
            TransitionLayout::ClassMapped
        );

        let compile_span = |pattern: &str| {
            compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap()
        };
        let direct = compile_span("abc");
        let direct_view = direct.program().native_dfa_view().unwrap();
        let (direct_data, direct_layout) = build_native_dfa_table(direct_view).unwrap();
        assert_eq!(direct_layout.transitions, TransitionLayout::DirectByte);
        assert_eq!(direct_layout.forward_offset, 0);

        let states = direct_view.dfa.forward_cells.len() / direct_view.dfa.class_count;
        let direct_row_bytes = DIRECT_BYTE_ROW_BYTES;
        for state in 0..states {
            for byte in 0..DIRECT_BYTE_ROW_CELLS {
                let class = usize::from(direct_view.dfa.byte_classes[byte]);
                let cell =
                    direct_view.dfa.forward_cells[state * direct_view.dfa.class_count + class];
                let expected = pack_native_forward_cell(
                    cell.next,
                    cell.accepted,
                    0,
                    direct_row_bytes,
                    states,
                    direct_layout.start_filter.is_some(),
                    direct_layout.loop_skip.map(|plan| plan.state),
                )
                .unwrap();
                let offset = state * direct_row_bytes + byte * core::mem::size_of::<u32>();
                let actual =
                    u32::from_le_bytes(direct_data[offset..offset + 4].try_into().unwrap());
                assert_eq!(actual, expected, "state {state}, byte {byte}");
            }
        }

        let variable = compile_span("a+");
        let variable_view = variable.program().native_dfa_view().unwrap();
        let (variable_data, variable_layout) = build_native_dfa_table(variable_view).unwrap();
        assert_eq!(variable_layout.transitions, TransitionLayout::DirectByte);
        assert!(variable_layout.has_reverse);
        assert_eq!(variable_layout.exact_span_width, None);
        let reverse_states = variable_view.dfa.reverse_cells.len() / variable_view.dfa.class_count;
        let reverse_offset = usize::try_from(variable_layout.reverse_offset).unwrap();
        for state in 0..reverse_states {
            for byte in 0..DIRECT_BYTE_ROW_CELLS {
                let class = usize::from(variable_view.dfa.byte_classes[byte]);
                let source_index = state
                    .checked_mul(variable_view.dfa.class_count)
                    .and_then(|row| row.checked_add(class))
                    .unwrap();
                let cell = variable_view.dfa.reverse_cells[source_index];
                let expected = pack_native_cell(
                    cell.next,
                    cell.reaches_start,
                    reverse_offset,
                    direct_row_bytes,
                    reverse_states,
                )
                .unwrap();
                let offset = reverse_offset
                    .checked_add(state.checked_mul(direct_row_bytes).unwrap())
                    .and_then(|row| {
                        row.checked_add(byte.checked_mul(core::mem::size_of::<u32>()).unwrap())
                    })
                    .unwrap();
                let actual =
                    u32::from_le_bytes(variable_data[offset..offset + 4].try_into().unwrap());
                assert_eq!(actual, expected, "reverse state {state}, byte {byte}");
            }
        }

        let class_mapped =
            compile_span("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-");
        let class_view = class_mapped.program().native_dfa_view().unwrap();
        let (class_data, class_layout) = build_native_dfa_table(class_view).unwrap();
        assert_eq!(class_layout.transitions, TransitionLayout::ClassMapped);
        assert_eq!(
            class_layout.forward_offset,
            u32::try_from(CLASS_MAP_BYTES).unwrap()
        );
        assert_eq!(&class_data[..CLASS_MAP_BYTES], class_view.dfa.byte_classes);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the encoding audit compares both row layouts on both native architectures"
    )]
    fn transition_layouts_have_exact_x86_and_aarch64_lookup_encodings() {
        let compile_layout = |pattern: &str| {
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1
        };
        let direct = compile_layout("abc");
        let direct_reverse = compile_layout("a+");
        let class_mapped =
            compile_layout("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-");
        assert_eq!(direct.transitions, TransitionLayout::DirectByte);
        assert_eq!(direct_reverse.transitions, TransitionLayout::DirectByte);
        assert!(direct_reverse.has_reverse);
        assert_eq!(class_mapped.transitions, TransitionLayout::ClassMapped);

        let direct_x86 = lower_x86_64_dfa(direct, FeatureSet::EMPTY).unwrap().0;
        let direct_lookup = [
            0x0f, 0xb6, 0x04, 0x17, // movzx eax, haystack[position]
            0x41, 0x8b, 0x04, 0x82, // mov eax, packed_row[byte]
        ];
        assert!(
            direct_x86
                .windows(direct_lookup.len())
                .any(|window| window == direct_lookup)
        );
        assert!(
            direct_x86
                .windows(5)
                .any(|bytes| bytes == [0xa9, 0x00, 0x00, 0x00, 0x40]),
            "direct dispatch must test the accelerator bit"
        );
        assert!(
            direct_x86
                .windows(5)
                .any(|bytes| bytes == [0x25, 0xff, 0xff, 0xff, 0x3f]),
            "direct cells must clear both flag bits before row addressing"
        );
        let x86_dispatch = direct_x86
            .windows(5)
            .position(|bytes| bytes == [0xa9, 0x00, 0x00, 0x00, 0x40])
            .unwrap();
        let accelerated_branch = x86_dispatch + 5;
        assert_eq!(
            &direct_x86[accelerated_branch..accelerated_branch + 2],
            &[0x0f, 0x85]
        );
        let (accelerated_transition, accelerated_branch_bytes) =
            x86_test_branch_target(&direct_x86, accelerated_branch).unwrap();
        assert_eq!(accelerated_branch_bytes, 6);

        let ordinary_mask = accelerated_branch + accelerated_branch_bytes;
        assert_eq!(
            &direct_x86[ordinary_mask..ordinary_mask + 5],
            &[0x25, 0xff, 0xff, 0xff, 0x3f]
        );
        assert_eq!(
            &direct_x86[ordinary_mask + 5..ordinary_mask + 7],
            &[0x0f, 0x84]
        );
        let ordinary_row = ordinary_mask + 11;
        assert_eq!(
            &direct_x86[ordinary_row..ordinary_row + 5],
            &[0x4d, 0x8d, 0x54, 0x01, 0xff]
        );
        let ordinary_branch = ordinary_row + 5;
        let (ordinary_target, ordinary_branch_bytes) =
            x86_test_branch_target(&direct_x86, ordinary_branch).unwrap();
        assert_eq!(ordinary_branch_bytes, 2, "ordinary hot edge must relax");
        assert!(
            ordinary_target < ordinary_branch,
            "ordinary edge must loop directly"
        );
        assert_eq!(
            &direct_x86[ordinary_target..ordinary_target + 3],
            &[0x48, 0x39, 0xca]
        );

        let accelerated_mask = ordinary_branch + ordinary_branch_bytes;
        assert_eq!(accelerated_transition, accelerated_mask);
        assert_eq!(
            &direct_x86[accelerated_mask..accelerated_mask + 5],
            &[0x25, 0xff, 0xff, 0xff, 0x3f]
        );
        let accelerated_row = accelerated_mask + 11;
        assert_eq!(
            &direct_x86[accelerated_row..accelerated_row + 5],
            &[0x4d, 0x8d, 0x54, 0x01, 0xff]
        );
        let tagged_branch = accelerated_row + 5;
        let (tagged_target, _) = x86_test_branch_target(&direct_x86, tagged_branch).unwrap();
        assert!(
            tagged_target < tagged_branch,
            "tagged edge must re-enter dispatch"
        );

        let class_x86 = lower_x86_64_dfa(class_mapped, FeatureSet::EMPTY).unwrap().0;
        let class_lookup = [
            0x0f, 0xb6, 0x04, 0x17, // movzx eax, haystack[position]
            0x41, 0x0f, 0xb6, 0x04, 0x01, // movzx eax, class_map[eax]
            0x41, 0x8b, 0x04, 0x82, // mov eax, packed_row[class]
        ];
        assert!(
            class_x86
                .windows(class_lookup.len())
                .any(|window| window == class_lookup)
        );
        assert!(
            class_x86
                .windows(5)
                .any(|bytes| bytes == [0xa9, 0x00, 0x00, 0x00, 0x40])
        );
        assert!(
            class_x86
                .windows(5)
                .any(|bytes| bytes == [0x25, 0xff, 0xff, 0xff, 0x3f])
        );

        let direct_aarch64 = lower_aarch64_dfa(direct, FeatureSet::EMPTY).unwrap().0;
        let direct_words = direct_aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let direct_lookup = [
            aarch64_load_byte_reg(8, 0, 2).unwrap(),
            aarch64_load_w_uxtw(8, 11, 8).unwrap(),
        ];
        assert!(
            direct_words
                .windows(direct_lookup.len())
                .any(|window| window == direct_lookup)
        );
        assert!(direct_words.contains(&aarch64_and_low_w(6, 8, 30).unwrap()));
        let aarch64_dispatch = direct_words
            .iter()
            .position(|&word| word & 0xfff8_001f == 0x37f0_0008)
            .unwrap();
        assert_eq!(
            direct_words[aarch64_dispatch + 1],
            aarch64_and_low_w(6, 8, 30).unwrap()
        );
        assert_eq!(
            direct_words[aarch64_dispatch + 2] & 0xff00_001f,
            0x3400_0006
        );
        assert_eq!(
            direct_words[aarch64_dispatch + 3],
            aarch64_sub_w_imm(6, 6, 1).unwrap()
        );
        assert_eq!(direct_words[aarch64_dispatch + 4], 0x8b06_00ab);
        assert_eq!(
            direct_words[aarch64_dispatch + 5] & 0xfc00_0000,
            0x1400_0000
        );
        assert_ne!(direct_words[aarch64_dispatch + 5] & 0x0200_0000, 0);
        assert_eq!(
            direct_words[aarch64_dispatch + 6],
            aarch64_and_low_w(6, 8, 30).unwrap()
        );
        assert_eq!(
            direct_words[aarch64_dispatch + 7] & 0xff00_001f,
            0x3400_0006
        );
        assert_eq!(direct_words[aarch64_dispatch + 9], 0x8b06_00ab);
        assert_eq!(
            direct_words[aarch64_dispatch + 10] & 0xfc00_0000,
            0x1400_0000
        );
        assert_ne!(direct_words[aarch64_dispatch + 10] & 0x0200_0000, 0);

        let class_aarch64 = lower_aarch64_dfa(class_mapped, FeatureSet::EMPTY)
            .unwrap()
            .0;
        let class_words = class_aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let class_lookup = [
            aarch64_load_byte_reg(8, 0, 2).unwrap(),
            aarch64_load_byte_reg(8, 5, 8).unwrap(),
            aarch64_load_w_uxtw(8, 11, 8).unwrap(),
        ];
        assert!(
            class_words
                .windows(class_lookup.len())
                .any(|window| window == class_lookup)
        );
        assert!(
            class_words
                .iter()
                .any(|&word| word & 0xfff8_001f == 0x37f0_0008)
        );
        assert!(class_words.contains(&aarch64_and_low_w(6, 8, 30).unwrap()));

        let direct_reverse_x86 = lower_x86_64_dfa(direct_reverse, FeatureSet::EMPTY)
            .unwrap()
            .0;
        assert_eq!(
            direct_reverse_x86
                .windows(4)
                .filter(|bytes| *bytes == [0x41, 0x8b, 0x04, 0x82])
                .count(),
            2 + usize::from(direct_reverse.seeded_reverse.is_some()),
            "forward, span-reverse, and optional seeded-reverse scans use dword cells"
        );
        let direct_reverse_aarch64 = lower_aarch64_dfa(direct_reverse, FeatureSet::EMPTY)
            .unwrap()
            .0
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            direct_reverse_aarch64
                .iter()
                .filter(|&&word| word == aarch64_load_w_uxtw(8, 11, 8).unwrap())
                .count(),
            2 + usize::from(direct_reverse.seeded_reverse.is_some())
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact forward/reverse instruction audit covers both native ISAs"
    )]
    fn ordinary_live_cells_have_one_branch_hot_paths_and_ordered_cold_paths() {
        let layout = NativeDfaLayout {
            transitions: TransitionLayout::ClassMapped,
            forward_offset: 256,
            reverse_offset: 512,
            asimd_lane_index_offset: None,
            initial_pending: false,
            initial_terminal: false,
            has_reverse: true,
            exact_span_width: None,
            exact_prefix_match_width: None,
            output: OutputContract::Span,
            start_filter: None,
            suffix_filter: None,
            declined_redundant_root_reverse: false,
            seeded_reverse: None,
            loop_skip: None,
            vector_filter: None,
            prefix_filter: None,
            prefix_relation: None,
            prefix_block: None,
            prefix_fast_forward: None,
        };

        let x86 = lower_x86_64_dfa(layout, FeatureSet::EMPTY).unwrap().0;
        let mut x86_classifier_prefix = vec![0xff, 0xc8, 0x3d];
        x86_classifier_prefix.extend_from_slice(&CELL_ORDINARY_DECODED_MAX.to_le_bytes());
        x86_classifier_prefix.extend_from_slice(&[0x0f, 0x87]);
        let x86_classifiers = x86
            .windows(x86_classifier_prefix.len())
            .enumerate()
            .filter_map(|(offset, bytes)| {
                (bytes == x86_classifier_prefix.as_slice()).then_some(offset)
            })
            .collect::<Vec<_>>();
        assert_eq!(x86_classifiers.len(), 2, "forward and span-reverse");

        let mut x86_exceptional = Vec::new();
        for (index, &classifier) in x86_classifiers.iter().enumerate() {
            let exceptional_branch = classifier + 7;
            let (exceptional, exceptional_branch_bytes) =
                x86_test_branch_target(&x86, exceptional_branch).unwrap();
            assert_eq!(exceptional_branch_bytes, 6);
            x86_exceptional.push(exceptional);

            let hot_row = exceptional_branch + exceptional_branch_bytes;
            assert_eq!(&x86[hot_row..hot_row + 4], &[0x4d, 0x8d, 0x14, 0x01]);
            let (loop_target, loop_branch_bytes) =
                x86_test_branch_target(&x86, hot_row + 4).unwrap();
            assert_eq!(loop_branch_bytes, 2, "hot backedge must relax");
            let expected_loop_head = if index == 0 {
                &[0x48, 0x39, 0xca][..]
            } else {
                &[0x48, 0x39, 0xf2][..]
            };
            assert_eq!(
                &x86[loop_target..loop_target + expected_loop_head.len()],
                expected_loop_head
            );
            assert_eq!(exceptional, hot_row + 4 + loop_branch_bytes);
            assert_eq!(
                &x86[exceptional..exceptional + 9],
                &[0xff, 0xc0, 0xa9, 0, 0, 0, 0x80, 0x0f, 0x88]
            );
        }

        let forward_exceptional = x86_exceptional[0];
        let forward_after_accept = forward_exceptional + 13;
        assert_eq!(
            &x86[forward_after_accept..forward_after_accept + 7],
            &[0xa9, 0, 0, 0, 0x40, 0x0f, 0x85],
            "forward exceptional order must be accept then accelerator"
        );
        let (_, accelerator_branch_bytes) =
            x86_test_branch_target(&x86, forward_after_accept + 5).unwrap();
        let forward_dead = forward_after_accept + 5 + accelerator_branch_bytes;
        assert_eq!(
            &x86[forward_dead..forward_dead + 7],
            &[0x25, 0xff, 0xff, 0xff, 0x3f, 0x0f, 0x84],
            "dead handling must follow both flag handlers"
        );

        let reverse_exceptional = x86_exceptional[1];
        let reverse_after_accept = reverse_exceptional + 13;
        assert_eq!(
            &x86[reverse_after_accept..reverse_after_accept + 7],
            &[0x25, 0xff, 0xff, 0xff, 0x3f, 0x0f, 0x84],
            "span-reverse dead handling must follow acceptance"
        );

        let aarch64 = lower_aarch64_dfa(layout, FeatureSet::EMPTY).unwrap().0;
        let aarch64 = aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let flag_shift = u8::try_from(CELL_ACCELERATED.trailing_zeros()).unwrap();
        let subtract_bias = aarch64_sub_w_imm(6, 8, 1).unwrap();
        let classify_flags = aarch64_lsr_x_imm(12, 6, flag_shift).unwrap();
        let hot_row = aarch64_add_x_reg(11, 5, 6).unwrap();
        assert_eq!(subtract_bias, 0x5100_0506); // sub w6, w8, #1; zero-extends x6
        assert_eq!(classify_flags, 0xd35e_fccc); // lsr x12, x6, #30
        assert_eq!(hot_row, 0x8b06_00ab); // add x11, x5, x6
        assert_eq!(aarch64_and_low_w(6, 8, 30).unwrap(), 0x1200_7506);
        let aarch64_classifiers = aarch64
            .windows(5)
            .enumerate()
            .filter_map(|(offset, words)| {
                (words[0] == subtract_bias
                    && words[1] == classify_flags
                    && words[2] & 0xff00_001f == 0x3500_000c
                    && words[3] == hot_row
                    && words[4] & 0xfc00_0000 == 0x1400_0000)
                    .then_some(offset)
            })
            .collect::<Vec<_>>();
        assert_eq!(aarch64_classifiers.len(), 2, "forward and span-reverse");

        let mut aarch64_exceptional = Vec::new();
        for (index, &classifier) in aarch64_classifiers.iter().enumerate() {
            assert_eq!(
                aarch64[classifier + 2],
                0x3500_006c,
                "cbnz w12 must skip ADD and B to the adjacent cold path"
            );
            let exceptional = aarch64_test_branch_target(&aarch64, classifier + 2).unwrap();
            let loop_target = aarch64_test_branch_target(&aarch64, classifier + 4).unwrap();
            aarch64_exceptional.push(exceptional);
            assert_eq!(
                aarch64[loop_target],
                if index == 0 {
                    aarch64_cmp_x(2, 3).unwrap()
                } else {
                    aarch64_cmp_x(2, 9).unwrap()
                }
            );
            assert_eq!(exceptional, classifier + 5);
            assert_eq!(
                aarch64[exceptional] & 0xfff8_001f,
                0x37f8_0008,
                "acceptance must be the first exceptional test"
            );
        }

        let forward_exceptional = aarch64_exceptional[0];
        assert_eq!(
            aarch64[forward_exceptional + 1] & 0xfff8_001f,
            0x37f0_0008,
            "accelerator handling must follow acceptance"
        );
        assert_eq!(
            aarch64[forward_exceptional + 2],
            aarch64_and_low_w(6, 8, 30).unwrap()
        );
        assert_eq!(
            aarch64[forward_exceptional + 3] & 0xff00_001f,
            0x3400_0006,
            "dead handling must follow both flag handlers"
        );

        let reverse_exceptional = aarch64_exceptional[1];
        assert_eq!(
            aarch64[reverse_exceptional + 1],
            aarch64_and_low_w(6, 8, 30).unwrap()
        );
        assert_eq!(
            aarch64[reverse_exceptional + 2] & 0xff00_001f,
            0x3400_0006,
            "span-reverse dead handling must follow acceptance"
        );
    }

    #[test]
    fn direct_dword_cells_are_emitted_on_all_targets_and_avx512() {
        for target in [
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ] {
            let compiled = compile(
                CompileRequest::new("a+", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let (data, layout) = build_native_dfa_table_for_architecture(
                compiled.program().native_dfa_view().unwrap(),
                target.architecture,
            )
            .unwrap();
            assert_eq!(layout.transitions, TransitionLayout::DirectByte);
            assert!(layout.has_reverse);
            assert_eq!(usize::try_from(layout.forward_offset).unwrap(), 0);
            assert!(data.len() >= DIRECT_BYTE_ROW_BYTES);

            let code = compiled.module().sections()[TEXT_SECTION].bytes();
            match target.architecture {
                Architecture::X86_64 => assert!(
                    code.windows(4)
                        .any(|bytes| bytes == [0x41, 0x8b, 0x04, 0x82])
                ),
                Architecture::Aarch64 => assert!(code.chunks_exact(4).any(|bytes| {
                    u32::from_le_bytes(bytes.try_into().unwrap())
                        == aarch64_load_w_uxtw(8, 11, 8).unwrap()
                })),
            }
        }

        let avx512_features = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let avx512 = compile(
            CompileRequest::new(
                "q+",
                Target::x86_64_linux()
                    .with_features(avx512_features)
                    .unwrap(),
            )
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        )
        .unwrap();
        assert_eq!(
            avx512.module().start_accelerator(),
            StartAccelerator::X86Avx512Bw
        );
        assert!(
            avx512.module().sections()[TEXT_SECTION]
                .bytes()
                .windows(4)
                .any(|bytes| bytes == [0x41, 0x8b, 0x04, 0x82])
        );
    }

    #[test]
    fn hot_native_miss_and_nonaccept_paths_have_exact_fallthrough_encodings() {
        let span_layout = NativeDfaLayout {
            transitions: TransitionLayout::ClassMapped,
            forward_offset: 256,
            reverse_offset: 512,
            asimd_lane_index_offset: None,
            initial_pending: false,
            initial_terminal: false,
            has_reverse: true,
            exact_span_width: None,
            exact_prefix_match_width: None,
            output: OutputContract::Span,
            start_filter: None,
            suffix_filter: None,
            declined_redundant_root_reverse: false,
            seeded_reverse: None,
            loop_skip: None,
            vector_filter: None,
            prefix_filter: None,
            prefix_relation: None,
            prefix_block: None,
            prefix_fast_forward: None,
        };
        let (x86_span, _) = lower_x86_64_dfa(span_layout, FeatureSet::EMPTY).unwrap();
        let accept_test = [0xa9, 0, 0, 0, 0x80];
        let accept_branches = x86_span
            .windows(accept_test.len() + 2)
            .filter(|window| window.starts_with(&accept_test))
            .map(|window| &window[accept_test.len()..])
            .collect::<Vec<_>>();
        assert_eq!(accept_branches.len(), 2); // forward and reverse
        assert!(accept_branches.iter().all(|branch| *branch == [0x0f, 0x88])); // js rare accept

        let filter_layout = NativeDfaLayout {
            has_reverse: false,
            output: OutputContract::SelectedEnd,
            start_filter: Some(NativeStartFilter {
                ranges: [
                    NativeByteRange {
                        start: b'q',
                        end: b'q',
                    },
                    NativeByteRange { start: 0, end: 0 },
                    NativeByteRange { start: 0, end: 0 },
                    NativeByteRange { start: 0, end: 0 },
                    NativeByteRange { start: 0, end: 0 },
                    NativeByteRange { start: 0, end: 0 },
                    NativeByteRange { start: 0, end: 0 },
                    NativeByteRange { start: 0, end: 0 },
                ],
                range_count: 1,
                candidate_bytes: 1,
                scan_offset: 0,
                from_anchored_prefix: true,
            }),
            ..span_layout
        };
        let (x86_filter, _) = lower_x86_64_dfa(filter_layout, FeatureSet::EMPTY).unwrap();
        assert!(
            x86_filter
                .windows(9)
                .any(|bytes| bytes == [0x66, 0x41, 0x0f, 0xd7, 0xc4, 0x85, 0xc0, 0x0f, 0x85]),
            "SSE2 candidate masks must branch only on the rare hit"
        );
        assert!(
            !x86_filter
                .windows(9)
                .any(|bytes| bytes == [0x66, 0x41, 0x0f, 0xd7, 0xc4, 0x85, 0xc0, 0x0f, 0x84]),
            "SSE2 no-hit must remain the fallthrough"
        );

        let (aarch64_span, _) = lower_aarch64_dfa(span_layout, FeatureSet::EMPTY).unwrap();
        let words = aarch64_span
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let accept_branches = words
            .iter()
            .filter(|&&word| word & 0xfff8_001f == 0x37f8_0008)
            .count();
        assert_eq!(accept_branches, 2); // forward and reverse
    }

    #[test]
    fn exists_lowering_omits_pending_end_dataflow_on_both_isas() {
        let start_filter = NativeStartFilter {
            ranges: [
                NativeByteRange {
                    start: b'q',
                    end: b'q',
                },
                NativeByteRange { start: 0, end: 0 },
                NativeByteRange { start: 0, end: 0 },
                NativeByteRange { start: 0, end: 0 },
                NativeByteRange { start: 0, end: 0 },
                NativeByteRange { start: 0, end: 0 },
                NativeByteRange { start: 0, end: 0 },
                NativeByteRange { start: 0, end: 0 },
            ],
            range_count: 1,
            candidate_bytes: 1,
            scan_offset: 0,
            from_anchored_prefix: false,
        };
        let layout = NativeDfaLayout {
            transitions: TransitionLayout::ClassMapped,
            forward_offset: 256,
            reverse_offset: 0,
            asimd_lane_index_offset: None,
            initial_pending: false,
            initial_terminal: false,
            has_reverse: false,
            exact_span_width: None,
            exact_prefix_match_width: None,
            output: OutputContract::Exists,
            start_filter: Some(start_filter),
            suffix_filter: None,
            declined_redundant_root_reverse: false,
            seeded_reverse: None,
            loop_skip: None,
            vector_filter: None,
            prefix_filter: None,
            prefix_relation: None,
            prefix_block: None,
            prefix_fast_forward: None,
        };

        let (x86, _) = lower_x86_64_dfa(layout, FeatureSet::EMPTY).unwrap();
        for removed in [
            &[0x49, 0xc7, 0xc3, 0xff, 0xff, 0xff, 0xff][..],
            &[0x49, 0x89, 0xd3][..],
            &[0x49, 0x83, 0xfb, 0xff][..],
        ] {
            assert!(
                !x86.windows(removed.len()).any(|window| window == removed),
                "Exists must not materialize or test a pending selected end"
            );
        }

        let (aarch64, _) = lower_aarch64_dfa(layout, FeatureSet::EMPTY).unwrap();
        let words = aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        for removed in [
            0x9280_000d,
            aarch64_mov_x(7, 13).unwrap(),
            aarch64_mov_x(7, 2).unwrap(),
            aarch64_cmp_x(7, 13).unwrap(),
        ] {
            assert!(
                !words.contains(&removed),
                "Exists must not materialize or test a pending selected end"
            );
        }
    }

    #[test]
    fn fixed_width_spans_omit_reverse_machine_and_encode_direct_start() {
        let compiled = compile(
            CompileRequest::new("abc", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let view = compiled.program().native_dfa_view().unwrap();
        assert_eq!(view.exact_match_width, Some(3));
        assert!(!view.dfa.reverse_cells.is_empty());
        let (data, layout) = build_native_dfa_table(view).unwrap();
        assert_eq!(layout.exact_span_width, Some(3));
        assert!(!layout.has_reverse);
        let prefix_bytes = layout
            .prefix_filter
            .map_or(0, |filter| filter.predicates().len() * PREFIX_BITMAP_BYTES);
        let machine_bytes = usize::try_from(layout.reverse_offset).unwrap();
        let prefix_padding = if prefix_bytes == 0 {
            0
        } else {
            ((machine_bytes + 7) & !7) - machine_bytes
        };
        assert_eq!(data.len(), machine_bytes + prefix_padding + prefix_bytes);

        let (x86, _) = lower_x86_64_dfa(layout, FeatureSet::EMPTY).unwrap();
        assert!(x86.windows(14).any(|bytes| {
            bytes
                == [
                    0x4d, 0x89, 0x58, 0x08, // result.end = selected end
                    0x4c, 0x89, 0xd8, // mov start, selected end
                    0x48, 0x83, 0xe8, 3, // sub start, exact width
                    0x49, 0x89, 0x00, // result.start = start
                ]
        }));

        let (aarch64, _) = lower_aarch64_dfa(layout, FeatureSet::EMPTY).unwrap();
        let words = aarch64
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(words.windows(3).any(|instructions| {
            instructions
                == [
                    aarch64_store_x(7, 4, 8).unwrap(),
                    aarch64_sub_x_imm(6, 7, 3).unwrap(),
                    aarch64_store_x(6, 4, 0).unwrap(),
                ]
        }));
    }

    #[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    #[ignore = "links and executes post-first-block seven/eight-singleton ASIMD witnesses"]
    fn linked_aarch64_fragmented_exact_constants_survive_no_hit_batches() {
        use std::{fmt::Write as _, fs, process::Command};

        let base = if cfg!(target_os = "linux") {
            Target::aarch64_linux()
        } else {
            Target::aarch64_macos()
        };
        let target = base
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let mut seven = vec![b'x'; 192];
        seven[150] = b'M';
        let mut eight = vec![b'x'; 192];
        eight[150] = b'O';
        let cases = [("[ACEGIKM]", seven), ("[ACEGIKMO]", eight)];
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-aarch64-fragmented-exact-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut source = String::from("#include <stdint.h>\n#include <stddef.h>\n");
        let mut objects = Vec::new();
        let mut symbols = Vec::new();

        for (index, (pattern, haystack)) in cases.iter().enumerate() {
            let compiled = compile(
                CompileRequest::new(*pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            assert_eq!(
                compiled.receipt().engine_selection_reason,
                crate::EngineSelectionReason::CompleteDfa
            );
            assert!(compiled.module().required_runtime_symbol().is_none());
            assert_eq!(
                compiled.module().start_accelerator(),
                StartAccelerator::Aarch64Asimd
            );
            let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1;
            let filter = layout
                .start_filter
                .expect("fragmented ordinary start filter");
            assert!(filter.is_exact());
            assert_eq!(filter.ranges().len(), index + 7);
            assert!(layout.vector_filter.is_none());
            assert_eq!(
                compiled
                    .search(haystack, SearchWindow::full(haystack))
                    .unwrap(),
                MatchResult::Span(Some((150, 151)))
            );

            let object = directory.join(format!("case{index}.o"));
            fs::write(&object, compiled.object()).unwrap();
            objects.push(object);
            let symbol = compiled.module().entry_symbol().to_owned();
            let bytes = haystack
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            writeln!(
                source,
                "extern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);"
            )
            .unwrap();
            writeln!(
                source,
                "static const unsigned char h{index}[] = {{{bytes}}};"
            )
            .unwrap();
            symbols.push(symbol);
        }
        source.push_str("int main(void) { size_t r[2]; uint32_t s;\n");
        for (index, symbol) in symbols.iter().enumerate() {
            writeln!(
                source,
                "r[0]=99;r[1]=99;s={symbol}(h{index},sizeof(h{index}),0,sizeof(h{index}),r);if(s!=1||r[0]!=150||r[1]!=151)return {};",
                70 + index
            )
            .unwrap();
        }
        source.push_str("return 0;}\n");
        let c_path = directory.join("regression.c");
        let executable = directory.join("regression");
        fs::write(&c_path, source).unwrap();
        let compiler = if cfg!(target_os = "macos") {
            "clang"
        } else {
            "cc"
        };
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .args(&objects)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap();
        assert!(status.success());
        let output = Command::new(&executable).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    #[test]
    #[ignore = "links and executes x86-64 seeded-reverse objects natively"]
    #[allow(
        clippy::too_many_lines,
        reason = "the opt-in cross-ISA differential keeps object production and execution together"
    )]
    fn linked_x86_64_macos_seeded_reverse_agrees_with_portable_program() {
        use std::{fmt::Write as _, fs, process::Command};

        let mut terminal = vec![b'x'; 144];
        terminal[67] = b'z';
        terminal[143] = b'z';
        let mut interior = vec![b'x'; 144];
        interior[59..64].copy_from_slice(b"MAGIC");
        interior[131..136].copy_from_slice(b"MAGIC");
        let absent = vec![b'x'; 144];
        let fixtures = [
            ("(?s:.+)z", terminal),
            ("(?s:.+)MAGIC(?s:.*)", interior),
            ("(?s:.+)y", absent),
        ];
        let directory =
            std::env::temp_dir().join(format!("fre-aot-x86-seeded-reverse-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let mut source = String::from("#include <stdint.h>\n#include <stddef.h>\n");
        let mut calls = String::from("int main(void){size_t r[2];uint32_t s;\n");
        let mut objects = Vec::new();
        let mut case_index = 0_usize;
        let mut saw_accept_seed = false;
        let mut saw_root_seed = false;

        for (fixture, (pattern, haystack)) in fixtures.iter().enumerate() {
            let bytes = haystack
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            writeln!(
                source,
                "static const unsigned char h{fixture}[]={{{bytes}}};"
            )
            .unwrap();
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let compiled = compile(
                    CompileRequest::new(*pattern, Target::x86_64_macos())
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                let layout = build_native_dfa_table_for_architecture(
                    compiled.program().native_dfa_view().unwrap(),
                    Architecture::X86_64,
                )
                .unwrap()
                .1;
                if output == OutputContract::Exists {
                    let reverse = layout.seeded_reverse.unwrap_or_else(|| {
                        panic!("missing seeded reverse for {pattern:?} {output:?}")
                    });
                    saw_accept_seed |= reverse.proves_match;
                    saw_root_seed |= !reverse.proves_match;
                } else {
                    assert!(layout.seeded_reverse.is_none());
                }
                let symbol = compiled.module().entry_symbol();
                writeln!(
                    source,
                    "extern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);"
                )
                .unwrap();
                let object = directory.join(format!("case{case_index}.o"));
                fs::write(&object, compiled.object()).unwrap();
                objects.push(object);
                let mut windows = Vec::new();
                for start in 0..=haystack.len() {
                    windows.push((start, haystack.len()));
                    windows.push((start, start.saturating_add(127).min(haystack.len())));
                }
                for end in 0..=haystack.len() {
                    windows.push((0, end));
                }
                let boundaries = [
                    0_usize, 1, 2, 31, 58, 59, 60, 66, 67, 68, 100, 130, 131, 135, 142, 143, 144,
                ];
                for &start in &boundaries {
                    for &end in &boundaries {
                        if start <= end && end <= haystack.len() {
                            windows.push((start, end));
                        }
                    }
                }
                windows.sort_unstable();
                windows.dedup();
                for (start, end) in windows {
                    let expected = compiled
                        .search(haystack, SearchWindow::new(start, end))
                        .unwrap();
                    writeln!(
                        calls,
                        "r[0]=99;r[1]=99;s={symbol}(h{fixture},{},{start},{end},r);",
                        haystack.len()
                    )
                    .unwrap();
                    match expected {
                        MatchResult::Exists(found) => writeln!(
                            calls,
                            "if(s!={}||r[0]!=0||r[1]!=0)return {};",
                            u8::from(found),
                            case_index + 10
                        )
                        .unwrap(),
                        MatchResult::SelectedEnd(Some(selected_end)) => writeln!(
                            calls,
                            "if(s!=1||r[0]!={selected_end}||r[1]!={selected_end})return {};",
                            case_index + 10
                        )
                        .unwrap(),
                        MatchResult::Span(Some((match_start, match_end))) => writeln!(
                            calls,
                            "if(s!=1||r[0]!={match_start}||r[1]!={match_end})return {};",
                            case_index + 10
                        )
                        .unwrap(),
                        MatchResult::SelectedEnd(None) | MatchResult::Span(None) => writeln!(
                            calls,
                            "if(s!=0||r[0]!=0||r[1]!=0)return {};",
                            case_index + 10
                        )
                        .unwrap(),
                    }
                }
                case_index += 1;
            }
        }
        assert!(saw_accept_seed && saw_root_seed);
        calls.push_str("return 0;}\n");
        source.push_str(&calls);
        let c_path = directory.join("seeded.c");
        let executable = directory.join("seeded");
        fs::write(&c_path, source).unwrap();
        let status = Command::new("clang")
            .arg("-arch")
            .arg("x86_64")
            .arg("-O0")
            .arg(&c_path)
            .args(&objects)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap();
        assert!(status.success());
        let output = Command::new(&executable).output().unwrap();
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    #[ignore = "opt-in native linker/execution smoke test"]
    #[allow(
        clippy::too_many_lines,
        reason = "the opt-in linker smoke test keeps object production and execution together"
    )]
    fn linked_aarch64_dfa_agrees_with_portable_program() {
        use std::{fs, process::Command};

        let scalar_long = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaabzq";
        let asimd_long =
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaaaaaaaa";
        let asimd_no_match =
            b"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
        let scalar_range = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx7z";
        let asimd_four_ranges =
            b"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy_Z";
        let asimd_prefix_retry =
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxabXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxabcde";
        let mut matrix_range = vec![b'a'; 72];
        matrix_range.extend_from_slice(b"aQXbQZ");
        let mut matrix_two_classes = vec![b'a'; 72];
        matrix_two_classes.extend_from_slice(b"a0QXf3QZ");
        let mut matrix_sparse_classes = vec![b'a'; 72];
        matrix_sparse_classes.extend_from_slice(b"a0QXk8QZ");
        let mut matrix_alternation = vec![b'a'; 72];
        matrix_alternation.extend_from_slice(b"abQXefQZ");
        let mut retained_relation = vec![b'x'; 144];
        retained_relation[34..37].copy_from_slice(b"ab!");
        retained_relation[50..53].copy_from_slice(b"cd?");
        retained_relation[55..58].copy_from_slice(b"abQ");
        let mut suffix_false_then_match = vec![b'x'; 144];
        suffix_false_then_match[8] = b'e';
        suffix_false_then_match[130..135].copy_from_slice(b"xbcde");
        let mut suffix_variable_width = vec![b'x'; 144];
        suffix_variable_width[9] = b'd';
        suffix_variable_width[131..135].copy_from_slice(b"abcd");
        let suffix_absent = vec![b'x'; 144];
        let mut suffix_nullable = vec![b'x'; 144];
        suffix_nullable[132..134].copy_from_slice(b"ab");
        let mut suffix_self_overlap = b"needlx".repeat(24);
        suffix_self_overlap[138..144].copy_from_slice(b"needle");
        let mut reset_false_then_match = vec![b'x'; 144];
        reset_false_then_match[8] = b'd';
        reset_false_then_match[130..136].copy_from_slice(b"abcccd");
        let mut reset_base_minus_one = vec![b'x'; 144];
        reset_base_minus_one[130] = b'z';
        reset_base_minus_one[139..143].copy_from_slice(b"aaaz");
        let mut reset_base_minus_64 = vec![b'x'; 144];
        reset_base_minus_64[67..130].fill(b'b');
        reset_base_minus_64[130] = b'z';
        let mut reset_base_minus_65 = vec![b'x'; 144];
        reset_base_minus_65[66..130].fill(b'c');
        reset_base_minus_65[130] = b'z';
        let mut reset_absent_in_cap = vec![b'd'; 144];
        reset_absent_in_cap[130] = b'z';
        let mut reset_candidate_at_window_start = vec![b'x'; 144];
        reset_candidate_at_window_start[9] = b'e';
        reset_candidate_at_window_start[10] = b'z';
        let mut exact_match_at_start = vec![b'x'; 144];
        exact_match_at_start[..5].copy_from_slice(b"abcde");
        let mut selective_before_any_terminal = vec![b'x'; 144];
        selective_before_any_terminal[130..133].copy_from_slice(b"qk\xff");
        let mut unbounded_before_any_terminal = vec![b'x'; 144];
        unbounded_before_any_terminal[130..134].copy_from_slice(b"qqq\xff");
        let mut lazy_exact_range = vec![1_u8; 144];
        lazy_exact_range[131] = 4;
        let mut lazy_range_exact = vec![1_u8; 144];
        lazy_range_exact[131] = b'e';
        let mut lazy_range_range = vec![1_u8; 144];
        lazy_range_range[131] = 5;
        let mut loop_nonaccepting = vec![b'x'; 144];
        loop_nonaccepting[0] = b'A';
        loop_nonaccepting[143] = b'Z';
        let mut loop_accepting = vec![b'x'; 144];
        loop_accepting[73] = b'Z';
        let mut tagged_retry = vec![b'F'; 64];
        tagged_retry[32] = b'!';
        let tagged_retry_fixture = b"FuZWguCtFuZWguCtFuZWguCtoAAAmPc";
        tagged_retry[33..].copy_from_slice(tagged_retry_fixture);
        let mut relation_batch = vec![b'x'; 70];
        relation_batch[14..16].copy_from_slice(b"ad");
        relation_batch[30..32].copy_from_slice(b"cb");
        relation_batch[63..65].copy_from_slice(b"cd");
        let mut prefix_block_hay = vec![b'x'; 96];
        prefix_block_hay[31..47].copy_from_slice(b"abcdefghijklmnop");
        // False primary hits straddle several 64-byte batches. The first true
        // two-column match crosses the 255/256 boundary, exercising the
        // ordinary batch loop and its scalar refinement at a block edge.
        let mut sparse_batch_boundaries = vec![b'x'; 288];
        for position in [0_usize, 63, 64, 127, 128, 191, 192, 254] {
            sparse_batch_boundaries[position] = 1;
        }
        sparse_batch_boundaries[255] = 1;
        sparse_batch_boundaries[256] = b'5';
        sparse_batch_boundaries[286] = 1;
        sparse_batch_boundaries[287] = b'4';
        let cases = [
            (
                "(?:ab|a)+z",
                OutputContract::Span,
                scalar_long.as_slice(),
                0,
                scalar_long.len(),
                false,
            ),
            (
                "a+?",
                OutputContract::SelectedEnd,
                asimd_long.as_slice(),
                0,
                asimd_long.len(),
                true,
            ),
            (
                "(?:ab|cd)+z",
                OutputContract::Exists,
                asimd_no_match.as_slice(),
                0,
                asimd_no_match.len(),
                true,
            ),
            (
                "[0-9]z",
                OutputContract::Span,
                scalar_range.as_slice(),
                0,
                scalar_range.len(),
                false,
            ),
            ("q", OutputContract::Exists, b"xxqz".as_slice(), 0, 4, true),
            (
                "[0-9A-F_a-f]Z",
                OutputContract::SelectedEnd,
                asimd_four_ranges.as_slice(),
                0,
                asimd_four_ranges.len(),
                true,
            ),
            (
                "abcde",
                OutputContract::Span,
                asimd_prefix_retry.as_slice(),
                0,
                asimd_prefix_retry.len(),
                true,
            ),
            (
                "(?:abcd|abef)Z",
                OutputContract::SelectedEnd,
                b"abXabefZ".as_slice(),
                0,
                8,
                true,
            ),
            (
                "ab(?:c)?d",
                OutputContract::Span,
                b"abXabd".as_slice(),
                0,
                6,
                true,
            ),
            (
                "ab+c+d",
                OutputContract::Exists,
                b"abXabcccd".as_slice(),
                0,
                9,
                true,
            ),
            (
                "ab(?:|c)d",
                OutputContract::Span,
                b"abXabcd".as_slice(),
                0,
                7,
                true,
            ),
            (
                "[a-c]QZ",
                OutputContract::Span,
                matrix_range.as_slice(),
                0,
                matrix_range.len(),
                true,
            ),
            (
                "[a-f][0-3]QZ",
                OutputContract::SelectedEnd,
                matrix_two_classes.as_slice(),
                0,
                matrix_two_classes.len(),
                true,
            ),
            (
                "[acegik][02468]QZ",
                OutputContract::Exists,
                matrix_sparse_classes.as_slice(),
                0,
                matrix_sparse_classes.len(),
                true,
            ),
            (
                "(?:ab|cd|ef)QZ",
                OutputContract::Span,
                matrix_alternation.as_slice(),
                0,
                matrix_alternation.len(),
                true,
            ),
            (
                "(?:ab|cd)[A-Z].*",
                OutputContract::Exists,
                retained_relation.as_slice(),
                0,
                retained_relation.len(),
                true,
            ),
            (
                "(?:ab|cd)[A-Z].*",
                OutputContract::SelectedEnd,
                retained_relation.as_slice(),
                1,
                139,
                true,
            ),
            (
                "(?:ab|cd)[A-Z].*",
                OutputContract::Span,
                retained_relation.as_slice(),
                17,
                141,
                true,
            ),
            (
                "xbcde",
                OutputContract::Span,
                suffix_false_then_match.as_slice(),
                0,
                suffix_false_then_match.len(),
                true,
            ),
            (
                "ab(?:c)?d",
                OutputContract::SelectedEnd,
                suffix_variable_width.as_slice(),
                0,
                suffix_variable_width.len(),
                false,
            ),
            (
                "xyZ",
                OutputContract::Exists,
                suffix_absent.as_slice(),
                0,
                suffix_absent.len(),
                true,
            ),
            (
                "a?b?",
                OutputContract::Span,
                suffix_nullable.as_slice(),
                0,
                suffix_nullable.len(),
                true,
            ),
            (
                "needle",
                OutputContract::Exists,
                suffix_self_overlap.as_slice(),
                0,
                suffix_self_overlap.len(),
                true,
            ),
            (
                "x*abc+d",
                OutputContract::Exists,
                reset_false_then_match.as_slice(),
                0,
                reset_false_then_match.len(),
                true,
            ),
            (
                "a+?z",
                OutputContract::SelectedEnd,
                reset_base_minus_one.as_slice(),
                0,
                reset_base_minus_one.len(),
                true,
            ),
            (
                "b+z",
                OutputContract::Span,
                reset_base_minus_64.as_slice(),
                0,
                reset_base_minus_64.len(),
                true,
            ),
            (
                "c+?z",
                OutputContract::Span,
                reset_base_minus_65.as_slice(),
                0,
                reset_base_minus_65.len(),
                true,
            ),
            (
                "d+z",
                OutputContract::Span,
                reset_absent_in_cap.as_slice(),
                0,
                reset_absent_in_cap.len(),
                true,
            ),
            (
                "e+z",
                OutputContract::Span,
                reset_candidate_at_window_start.as_slice(),
                10,
                reset_candidate_at_window_start.len(),
                true,
            ),
            (
                "abcde",
                OutputContract::SelectedEnd,
                exact_match_at_start.as_slice(),
                0,
                exact_match_at_start.len(),
                true,
            ),
            (
                "qk(?-u:[\\x00-\\xff])",
                OutputContract::Exists,
                selective_before_any_terminal.as_slice(),
                0,
                selective_before_any_terminal.len(),
                true,
            ),
            (
                "q+(?-u:[\\x00-\\xff])",
                OutputContract::Span,
                unbounded_before_any_terminal.as_slice(),
                0,
                unbounded_before_any_terminal.len(),
                true,
            ),
            (
                "(?-u:\\x01[\\x03-\\x06])",
                OutputContract::Exists,
                lazy_exact_range.as_slice(),
                0,
                lazy_exact_range.len(),
                true,
            ),
            (
                "(?-u:[\\x01-\\x02]e)",
                OutputContract::SelectedEnd,
                lazy_range_exact.as_slice(),
                0,
                lazy_range_exact.len(),
                true,
            ),
            (
                "(?-u:[\\x01-\\x02][\\x03-\\x06])",
                OutputContract::Span,
                lazy_range_range.as_slice(),
                0,
                lazy_range_range.len(),
                true,
            ),
            (
                "A(?-u:[^Z])*Z",
                OutputContract::Exists,
                loop_nonaccepting.as_slice(),
                0,
                loop_nonaccepting.len(),
                true,
            ),
            (
                "(?-u:[^Z]*)",
                OutputContract::Span,
                loop_accepting.as_slice(),
                0,
                loop_accepting.len(),
                true,
            ),
            (
                "(?:FuZWguCt){2,5}[n-r]A{2,3}mPc",
                OutputContract::Exists,
                tagged_retry.as_slice(),
                0,
                tagged_retry.len(),
                true,
            ),
            (
                "(?:ab|cd)",
                OutputContract::Exists,
                relation_batch.as_slice(),
                0,
                relation_batch.len(),
                true,
            ),
            (
                "(?:ab|cd)",
                OutputContract::SelectedEnd,
                relation_batch.as_slice(),
                0,
                relation_batch.len(),
                true,
            ),
            (
                "(?:ab|cd)",
                OutputContract::Span,
                relation_batch.as_slice(),
                0,
                relation_batch.len(),
                true,
            ),
            (
                "abcdefghijklmnop",
                OutputContract::Span,
                prefix_block_hay.as_slice(),
                0,
                prefix_block_hay.len(),
                true,
            ),
            (
                r"(?-u:\x01[3-7])",
                OutputContract::Span,
                sparse_batch_boundaries.as_slice(),
                0,
                sparse_batch_boundaries.len(),
                true,
            ),
            ("a*", OutputContract::Span, b"xxaaa".as_slice(), 1, 5, true),
        ];
        let scratch = std::env::temp_dir().join(format!("fre-aot-native-{}", std::process::id()));
        fs::create_dir_all(&scratch).unwrap();
        let mut source =
            String::from("#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n");
        let mut expected = Vec::new();
        let mut compiled_programs = Vec::new();
        let mut objects = Vec::new();
        let mut symbols = Vec::new();
        for (index, (pattern, output, haystack, _start, _end, asimd)) in cases.iter().enumerate() {
            let target = if *asimd {
                Target::aarch64_macos()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap()
            } else {
                Target::aarch64_macos()
            };
            let compiled = compile(
                CompileRequest::new(*pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(*output),
            )
            .unwrap();
            assert_eq!(compiled.receipt().engine, EngineKind::OrderedDfa);
            if haystack.len() >= usize::from(SUFFIX_PREFILTER_MIN_WINDOW_BYTES)
                && matches!(*pattern, "x*abc+d")
            {
                let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                    .unwrap()
                    .1;
                assert!(matches!(
                    layout.suffix_filter.unwrap().restart,
                    NativeSuffixRestart::Synchronizing { .. }
                ));
            }
            if pattern.contains("(?-u:[\\x00-\\xff])") {
                let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                    .unwrap()
                    .1;
                let suffix = layout.suffix_filter.unwrap();
                assert!(
                    suffix
                        .filter
                        .scan_offset
                        .checked_add(1)
                        .is_some_and(|offset| offset < suffix.minimum_width)
                );
                if pattern.starts_with("q+") {
                    assert_eq!(suffix.restart, NativeSuffixRestart::OriginalStart);
                }
            }
            if matches!(
                *pattern,
                "(?-u:\\x01[\\x03-\\x06])"
                    | "(?-u:[\\x01-\\x02]e)"
                    | "(?-u:[\\x01-\\x02][\\x03-\\x06])"
            ) {
                let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                    .unwrap()
                    .1;
                let vector = layout.vector_filter.unwrap();
                assert!(vector.columns().iter().any(|column| !column.is_exact()));
            }
            if matches!(*pattern, "A(?-u:[^Z])*Z" | "(?-u:[^Z]*)") {
                let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                    .unwrap()
                    .1;
                let loop_skip = layout.loop_skip.expect("graph-derived native loop skip");
                assert_eq!(loop_skip.accepting, *pattern == "(?-u:[^Z]*)");
            }
            if *pattern == "(?:FuZWguCt){2,5}[n-r]A{2,3}mPc" {
                let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                    .unwrap()
                    .1;
                assert!(
                    layout
                        .suffix_filter
                        .is_some_and(|suffix| suffix.retry.is_some()),
                    "tagged-cell regression must execute the bounded forward retry verifier"
                );
            }
            if *pattern == "abcdefghijklmnop" {
                let layout = build_native_dfa_table_for_architecture(
                    compiled.program().native_dfa_view().unwrap(),
                    Architecture::Aarch64,
                )
                .unwrap()
                .1;
                assert!(layout.prefix_block.is_some());
            }
            if *pattern == r"(?-u:\x01[3-7])" {
                let layout = build_native_dfa_table_for_architecture(
                    compiled.program().native_dfa_view().unwrap(),
                    Architecture::Aarch64,
                )
                .unwrap()
                .1;
                let filter = layout.start_filter.expect("rare start filter");
                assert!(use_aarch64_filter_batch(filter));
                let words = compiled.module().sections()[TEXT_SECTION]
                    .bytes()
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                assert!(words.contains(&aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES).unwrap()));
            }
            if *pattern == "(?:ab|cd)[A-Z].*" {
                let layout = build_native_dfa_table_for_architecture(
                    compiled.program().native_dfa_view().unwrap(),
                    Architecture::Aarch64,
                )
                .unwrap()
                .1;
                let coverage = derive_native_vector_guard_coverage(layout, true, None)
                    .expect("retained exact relation coverage");
                assert!(coverage.has_rejectable_residual(layout).unwrap());
            }
            let expected_accelerator = if matches!(*pattern, "a*" | "a?b?" | "(?-u:[^Z]*)") {
                StartAccelerator::None
            } else if *asimd {
                StartAccelerator::Aarch64Asimd
            } else {
                StartAccelerator::Scalar
            };
            assert_eq!(compiled.module().start_accelerator(), expected_accelerator);
            if matches!(
                *pattern,
                "abcde"
                    | "(?:abcd|abef)Z"
                    | "ab(?:c)?d"
                    | "abc+d"
                    | "ab(?:|c)d"
                    | "[a-c]QZ"
                    | "[a-f][0-3]QZ"
                    | "[acegik][02468]QZ"
                    | "(?:ab|cd|ef)QZ"
            ) {
                assert!(compiled.module().anchored_prefix_filter_bytes() >= 2);
            }
            let object = scratch.join(format!("case{index}.o"));
            fs::write(&object, compiled.object()).unwrap();
            objects.push(object);
            let symbol = compiled.module().entry_symbol().to_owned();
            writeln!(
                source,
                "extern uint32_t {symbol}(const unsigned char*, size_t, size_t, size_t, size_t*);"
            )
            .unwrap();
            let bytes = haystack
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            writeln!(
                source,
                "static const unsigned char h{index}[] = {{{bytes}}};"
            )
            .unwrap();
            symbols.push(symbol);
            compiled_programs.push(compiled);
        }
        source.push_str("int main(void) { size_t r[2]; uint32_t s;\n");
        for (index, ((_, _, haystack, _, _, _), compiled)) in
            cases.iter().zip(&compiled_programs).enumerate()
        {
            let symbol = &symbols[index];
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    writeln!(
                        source,
                        "r[0]=99;r[1]=99;s={symbol}(h{index},{},{start},{end},r);printf(\"%u %zu %zu\\n\",s,r[0],r[1]);",
                        haystack.len()
                    )
                    .unwrap();
                    expected.push(
                        compiled
                            .search(haystack, SearchWindow::new(start, end))
                            .unwrap(),
                    );
                }
            }
        }
        let first_symbol = &symbols[0];
        writeln!(
            source,
            "r[0]=99;r[1]=99;s={first_symbol}((const unsigned char*)0,7,0,7,r);if(s!=2||r[0]!=99||r[1]!=99)return 90;"
        )
        .unwrap();
        writeln!(
            source,
            "r[0]=99;r[1]=99;s={first_symbol}((const unsigned char*)0,0,0,0,r);if(s!=2||r[0]!=99||r[1]!=99)return 91;"
        )
        .unwrap();
        writeln!(
            source,
            "s={first_symbol}(h0,7,0,7,(size_t*)0);if(s!=2)return 92;"
        )
        .unwrap();
        writeln!(
            source,
            "r[0]=99;r[1]=99;s={first_symbol}(h0,7,6,2,r);if(s!=2||r[0]!=99||r[1]!=99)return 93;"
        )
        .unwrap();
        writeln!(
            source,
            "r[0]=99;r[1]=99;s={first_symbol}(h0,7,0,7,(size_t*)((unsigned char*)r+1));if(s!=2||r[0]!=99||r[1]!=99)return 94;"
        )
        .unwrap();
        writeln!(
            source,
            "r[0]=99;r[1]=99;s={first_symbol}(h0,((size_t)1<<(sizeof(size_t)*8-1)),0,0,r);if(s!=2||r[0]!=99||r[1]!=99)return 95;"
        )
        .unwrap();
        source.push_str("return 0;}\n");
        let c_path = scratch.join("smoke.c");
        let executable = scratch.join("smoke");
        fs::write(&c_path, source).unwrap();
        let status = Command::new("clang")
            // The explicit all-window C calls need no wrapper optimization;
            // the AOT objects under test are already final native code.
            .arg("-O0")
            .arg(&c_path)
            .args(&objects)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap();
        assert!(status.success());
        let output = Command::new(&executable).output().unwrap();
        assert!(output.status.success());
        let lines = String::from_utf8(output.stdout).unwrap();
        for (line, expected) in lines.lines().zip(expected) {
            let values = line
                .split_ascii_whitespace()
                .map(|part| part.parse::<usize>().unwrap())
                .collect::<Vec<_>>();
            match expected {
                MatchResult::Exists(found) => {
                    assert_eq!(values, [usize::from(found), 0, 0]);
                }
                MatchResult::SelectedEnd(found) => match found {
                    Some(end) => assert_eq!(values, [1, end, end]),
                    None => assert_eq!(values[0], 0),
                },
                MatchResult::Span(found) => match found {
                    Some((start, end)) => assert_eq!(values, [1, start, end]),
                    None => assert_eq!(values[0], 0),
                },
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn dev_root_unbounded_greedy_near_miss_witness() -> Vec<u8> {
        const SEED: u64 = 0x9b05_688c_2b3e_6c1f;
        const GENERATION_ID: usize = 200_021;
        const ROTATION: usize = 1;
        const STRIDE: usize = 32;
        const SAFE_BYTES: &[u8] = b"~!@#%&*+=:;?";
        const ENGLISHISH_BYTES: &[u8] = b"          eeeeeeeeeeeetttttttttaaaaaaaaaooooooooiiiiiiiinnnnnnnsssssshhhhhhrrrrrrddddllluuummccffyywwggppbbvvkkxjqz\n\n\t.,'";
        const FIXTURE: &[u8] = b"JWDJWDs";

        fn seed_component(seed: u64, shift: u32) -> usize {
            usize::try_from((seed >> shift) & 0xffff).unwrap()
        }

        fn distribution_hash(seed: u64, generation_id: usize, index: usize) -> u64 {
            let mut value = seed
                ^ (generation_id as u64).wrapping_mul(0xa076_1d64_78bd_642f)
                ^ (index as u64).wrapping_mul(0xe703_7ed1_a0b4_28db)
                ^ (ROTATION as u64).wrapping_mul(0x8ebc_6af0_9c88_c6e3);
            value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        }

        let mut haystack = (0..4 * 1024)
            .map(|index| {
                let value = distribution_hash(SEED, GENERATION_ID, index);
                let alphabet_index =
                    usize::try_from(value % u64::try_from(ENGLISHISH_BYTES.len()).unwrap())
                        .unwrap();
                ENGLISHISH_BYTES[alphabet_index]
            })
            .collect::<Vec<_>>();
        let phase = ROTATION
            .wrapping_mul(17 + seed_component(SEED, 4) % 16)
            .wrapping_add(GENERATION_ID.wrapping_mul(23 + seed_component(SEED, 20) % 16))
            .wrapping_add(seed_component(SEED, 16))
            % STRIDE;
        let mut index = phase;
        while index + FIXTURE.len() <= haystack.len() {
            haystack[index..index + FIXTURE.len()].copy_from_slice(FIXTURE);
            haystack[index + FIXTURE.len() - 1] =
                SAFE_BYTES[(index + ROTATION + seed_component(SEED, 48)) % SAFE_BYTES.len()];
            index = index.saturating_add(STRIDE);
        }
        haystack
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    #[ignore = "links and executes the fallback after declining a redundant reverse sidecar"]
    fn linked_x86_declined_initial_seeded_reverse_regression() {
        use std::{fs, process::Command};

        const PATTERN: &str = r"(?:(?:[2-4](?:6){1,2}[o-s])(?:tL|e))";
        const SEED: u64 = 0x1f83_d9ab_fb41_bd6b;
        const GENERATION_ID: u64 = 200_008;
        const ROTATION: u64 = 3;
        let haystack = (0_u64..4 * 1024)
            .map(|index| {
                let mut value = SEED
                    ^ GENERATION_ID.wrapping_mul(0xa076_1d64_78bd_642f)
                    ^ index.wrapping_mul(0xe703_7ed1_a0b4_28db)
                    ^ ROTATION.wrapping_mul(0x8ebc_6af0_9c88_c6e3);
                value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
                value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                u8::try_from((value ^ (value >> 31)) & u64::from(u8::MAX)).unwrap()
            })
            .collect::<Vec<_>>();
        let base = if cfg!(target_os = "linux") {
            Target::x86_64_linux()
        } else {
            Target::x86_64_macos()
        };
        let mut targets = vec![base];
        if std::is_x86_feature_detected!("avx2") {
            targets.push(
                base.with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
            );
        }

        for target in targets {
            let compiled = compile(
                CompileRequest::new(PATTERN, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap();
            let layout = build_native_dfa_table_for_architecture(
                compiled.program().native_dfa_view().unwrap(),
                Architecture::X86_64,
            )
            .unwrap()
            .1;
            assert!(layout.suffix_filter.is_some());
            assert!(layout.seeded_reverse.is_none());
            assert_eq!(
                compiled
                    .search(&haystack, SearchWindow::full(&haystack))
                    .unwrap(),
                MatchResult::Exists(false),
            );

            let directory = std::env::temp_dir().join(format!(
                "fre-aot-x86-initial-seeded-reverse-{}-{:x}",
                std::process::id(),
                target.features.bits(),
            ));
            fs::create_dir_all(&directory).unwrap();
            let object = directory.join("regex.o");
            fs::write(&object, compiled.object()).unwrap();
            let bytes = haystack
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let symbol = compiled.module().entry_symbol();
            let source = format!(
                "#include <stdint.h>\n#include <stddef.h>\n\
                 extern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\n\
                 static const unsigned char hay[] = {{{bytes}}};\n\
                 int main(void) {{ size_t result[2] = {{99,99}}; \
                 uint32_t status = {symbol}(hay,sizeof(hay),0,sizeof(hay),result); \
                 return status == 0 && result[0] == 0 && result[1] == 0 ? 0 : 70; }}\n"
            );
            let c_path = directory.join("regression.c");
            let executable = directory.join("regression");
            fs::write(&c_path, source).unwrap();
            let compiler = if cfg!(target_os = "macos") {
                "clang"
            } else {
                "cc"
            };
            let status = Command::new(compiler)
                .arg("-O0")
                .arg(&c_path)
                .arg(&object)
                .arg("-o")
                .arg(&executable)
                .status()
                .unwrap();
            assert!(status.success());
            let output = Command::new(&executable).output().unwrap();
            assert!(
                output.status.success(),
                "target={target:?}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    #[ignore = "links and executes the exact generated x86 near-miss regression"]
    fn linked_x86_dev_root_unbounded_greedy_near_miss_regression() {
        use std::{fs, process::Command};

        let pattern = r"(?:(?:(?:(?:JWD){1,3}|[3-6]|k))+[r-s])";
        let haystack = dev_root_unbounded_greedy_near_miss_witness();
        let base = if cfg!(target_os = "linux") {
            Target::x86_64_linux()
        } else {
            Target::x86_64_macos()
        };
        let mut targets = vec![base];
        if std::is_x86_feature_detected!("avx2") {
            targets.push(
                base.with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
            );
        }

        for target in targets {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            assert_eq!(compiled.receipt().engine, EngineKind::OrderedDfa);
            let expected = compiled
                .search(&haystack, SearchWindow::full(&haystack))
                .unwrap();
            assert_eq!(expected, MatchResult::Span(Some((1_211, 1_213))));

            let directory = std::env::temp_dir().join(format!(
                "fre-aot-x86-dev-root-near-miss-{}-{:x}",
                std::process::id(),
                target.features.bits(),
            ));
            fs::create_dir_all(&directory).unwrap();
            let object = directory.join("regex.o");
            fs::write(&object, compiled.object()).unwrap();
            let bytes = haystack
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let symbol = compiled.module().entry_symbol();
            let source = format!(
                "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n\
                 extern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\n\
                 static const unsigned char hay[] = {{{bytes}}};\n\
                 int main(void) {{ size_t result[2] = {{99,99}}; \
                 uint32_t status = {symbol}(hay,sizeof(hay),0,sizeof(hay),result); \
                 printf(\"%u %zu %zu\\n\",status,result[0],result[1]); \
                 return status == 1 && result[0] == 1211 && result[1] == 1213 ? 0 : 70; }}\n"
            );
            let c_path = directory.join("regression.c");
            let executable = directory.join("regression");
            fs::write(&c_path, source).unwrap();
            let compiler = if cfg!(target_os = "macos") {
                "clang"
            } else {
                "cc"
            };
            let status = Command::new(compiler)
                .arg("-O0")
                .arg(&c_path)
                .arg(&object)
                .arg("-o")
                .arg(&executable)
                .status()
                .unwrap();
            assert!(status.success());
            let output = Command::new(&executable).output().unwrap();
            assert!(
                output.status.success(),
                "target={target:?}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    #[ignore = "links and executes post-first-block witnesses for range constants 5 through 8"]
    fn linked_x86_range_filter_high_constant_regression() {
        use std::{fs, process::Command};

        let pattern = r"(?-u:[\x10-\x11\x20-\x21\x30-\x31\x40-\x41])";
        let mut haystacks = [[0xff_u8; 96]; 4];
        for (haystack, byte) in haystacks.iter_mut().zip([0x30, 0x31, 0x40, 0x41]) {
            haystack[70] = byte;
        }
        let base = if cfg!(target_os = "linux") {
            Target::x86_64_linux()
        } else {
            Target::x86_64_macos()
        };
        let mut targets = vec![base];
        if std::is_x86_feature_detected!("avx2") {
            targets.push(
                base.with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
            );
        }

        for target in targets {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            assert_eq!(compiled.receipt().engine, EngineKind::OrderedDfa);
            let layout = build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
                .unwrap()
                .1;
            let filter = layout.start_filter.expect("four-range start filter");
            assert_eq!(filter.ranges().len(), 4);
            assert_eq!(filter.constant_count(), 8);
            for haystack in &haystacks {
                assert_eq!(
                    compiled
                        .search(haystack, SearchWindow::full(haystack))
                        .unwrap(),
                    MatchResult::Span(Some((70, 71))),
                );
            }
            if target.features.has(CpuFeature::X86Avx2) {
                assert!(
                    compiled.module().sections()[TEXT_SECTION]
                        .bytes()
                        .windows(3)
                        .any(|bytes| bytes == [0xc5, 0xf8, 0x77]),
                    "AVX2 return paths must retain vzeroupper",
                );
            }

            let directory = std::env::temp_dir().join(format!(
                "fre-aot-x86-range-constants-{}-{:x}",
                std::process::id(),
                target.features.bits(),
            ));
            fs::create_dir_all(&directory).unwrap();
            let object = directory.join("regex.o");
            fs::write(&object, compiled.object()).unwrap();
            let symbol = compiled.module().entry_symbol();
            let mut source = format!(
                "#include <stdint.h>\n#include <stddef.h>\n\
                 extern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\n"
            );
            for (index, haystack) in haystacks.iter().enumerate() {
                let bytes = haystack
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                writeln!(
                    source,
                    "static const unsigned char hay{index}[] = {{{bytes}}};"
                )
                .unwrap();
            }
            source.push_str("int main(void) { size_t result[2]; uint32_t status;\n");
            for index in 0..haystacks.len() {
                writeln!(
                    source,
                    "result[0]=99;result[1]=99;status={symbol}(hay{index},sizeof(hay{index}),0,sizeof(hay{index}),result);if(status!=1||result[0]!=70||result[1]!=71)return {};",
                    70 + index,
                )
                .unwrap();
            }
            source.push_str("return 0;}\n");
            let c_path = directory.join("regression.c");
            let executable = directory.join("regression");
            fs::write(&c_path, source).unwrap();
            let compiler = if cfg!(target_os = "macos") {
                "clang"
            } else {
                "cc"
            };
            let status = Command::new(compiler)
                .arg("-O0")
                .arg(&c_path)
                .arg(&object)
                .arg("-o")
                .arg(&executable)
                .status()
                .unwrap();
            assert!(status.success());
            let output = Command::new(&executable).output().unwrap();
            assert!(
                output.status.success(),
                "target={target:?}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the remote bundle records generated objects and their portable expectations"
    )]
    fn generate_differential_bundle(
        target: Target,
        environment: &str,
        fallback: &str,
        success_marker: &str,
    ) {
        use std::fs;

        let single_candidate_hay =
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxneedle!";
        let four_candidate_hay =
            b"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyycdtail!";
        let no_match_hay = b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let four_range_hay = b"wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww_Z!";
        let mut third_range_hay = vec![b'x'; 80];
        third_range_hay[79] = b'_';
        let mut fourth_range_hay = vec![b'x'; 80];
        fourth_range_hay[79] = b'g';
        let mut matrix_range = vec![b'a'; 72];
        matrix_range.extend_from_slice(b"aQXbQZ");
        let mut matrix_two_classes = vec![b'a'; 72];
        matrix_two_classes.extend_from_slice(b"a0QXf3QZ");
        let mut matrix_sparse_classes = vec![b'a'; 72];
        matrix_sparse_classes.extend_from_slice(b"a0QXk8QZ");
        let mut matrix_alternation = vec![b'a'; 72];
        matrix_alternation.extend_from_slice(b"abQXefQZ");
        let mut retained_relation = vec![b'x'; 144];
        retained_relation[34..37].copy_from_slice(b"ab!");
        retained_relation[50..53].copy_from_slice(b"cd?");
        retained_relation[55..58].copy_from_slice(b"abQ");
        let mut suffix_false_then_match = vec![b'x'; 144];
        suffix_false_then_match[8] = b'e';
        suffix_false_then_match[130..135].copy_from_slice(b"xbcde");
        let mut suffix_variable_width = vec![b'x'; 144];
        suffix_variable_width[9] = b'd';
        suffix_variable_width[131..135].copy_from_slice(b"abcd");
        let suffix_absent = vec![b'x'; 144];
        let mut suffix_nullable = vec![b'x'; 144];
        suffix_nullable[132..134].copy_from_slice(b"ab");
        let mut suffix_self_overlap = b"needlx".repeat(24);
        suffix_self_overlap[138..144].copy_from_slice(b"needle");
        let mut reset_false_then_match = vec![b'x'; 144];
        reset_false_then_match[8] = b'd';
        reset_false_then_match[130..136].copy_from_slice(b"abcccd");
        let mut reset_base_minus_one = vec![b'x'; 144];
        reset_base_minus_one[130] = b'z';
        reset_base_minus_one[139..143].copy_from_slice(b"aaaz");
        let mut reset_base_minus_64 = vec![b'x'; 144];
        reset_base_minus_64[67..130].fill(b'b');
        reset_base_minus_64[130] = b'z';
        let mut reset_base_minus_65 = vec![b'x'; 144];
        reset_base_minus_65[66..130].fill(b'c');
        reset_base_minus_65[130] = b'z';
        let mut reset_absent_in_cap = vec![b'd'; 144];
        reset_absent_in_cap[130] = b'z';
        let mut reset_candidate_at_window_start = vec![b'x'; 144];
        reset_candidate_at_window_start[9] = b'e';
        reset_candidate_at_window_start[10] = b'z';
        let mut exact_match_at_start = vec![b'x'; 144];
        exact_match_at_start[..5].copy_from_slice(b"abcde");
        let mut selective_before_any_terminal = vec![b'x'; 144];
        selective_before_any_terminal[130..133].copy_from_slice(b"qk\xff");
        let mut unbounded_before_any_terminal = vec![b'x'; 144];
        unbounded_before_any_terminal[130..134].copy_from_slice(b"qqq\xff");
        let mut lazy_exact_range = vec![1_u8; 144];
        lazy_exact_range[131] = 4;
        let mut lazy_range_exact = vec![1_u8; 144];
        lazy_range_exact[131] = b'e';
        let mut lazy_range_range = vec![1_u8; 144];
        lazy_range_range[131] = 5;
        let mut loop_nonaccepting = vec![b'x'; 65];
        loop_nonaccepting[0] = b'A';
        loop_nonaccepting[64] = b'Z';
        let mut loop_accepting = vec![b'x'; 65];
        loop_accepting[33] = b'Z';
        let mut seeded_accept = vec![b'x'; 144];
        seeded_accept[67] = b'z';
        seeded_accept[143] = b'z';
        let mut sparse_batch_boundaries = vec![b'x'; 288];
        for position in [0_usize, 63, 64, 127, 128, 191, 192, 254] {
            sparse_batch_boundaries[position] = 1;
        }
        sparse_batch_boundaries[255] = 1;
        sparse_batch_boundaries[256] = b'5';
        sparse_batch_boundaries[286] = 1;
        sparse_batch_boundaries[287] = b'4';
        let cases = [
            (
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
                OutputContract::Span,
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-".as_slice(),
                0,
                64,
            ),
            (
                "(?:ab|a)+z",
                OutputContract::Span,
                b"xxaabzq".as_slice(),
                0,
                7,
            ),
            (
                "a+?",
                OutputContract::SelectedEnd,
                b"xxaaa".as_slice(),
                0,
                5,
            ),
            (
                "(?:ab|cd)+z",
                OutputContract::Exists,
                b"xxababz".as_slice(),
                0,
                7,
            ),
            ("a*", OutputContract::Span, b"xxaaa".as_slice(), 1, 5),
            (
                "[A-Za-z_][A-Za-z0-9_]*",
                OutputContract::Span,
                b"$id_42!".as_slice(),
                0,
                7,
            ),
            (
                "(?:ab|a)b?",
                OutputContract::Span,
                b"xxabb!".as_slice(),
                0,
                6,
            ),
            (
                "(?:a|aa)+?b",
                OutputContract::Span,
                b"xxaaaabx".as_slice(),
                0,
                8,
            ),
            (
                "[0-9]{3}",
                OutputContract::Span,
                b"no digits".as_slice(),
                0,
                9,
            ),
            (
                "(?:foo|bar){2,4}",
                OutputContract::SelectedEnd,
                b"..foobarbar!".as_slice(),
                2,
                11,
            ),
            (
                "(?-u:[\\x80-\\xff]+)",
                OutputContract::Exists,
                b"x\x80\xffz".as_slice(),
                0,
                4,
            ),
            (
                "[ab]{2,5}c",
                OutputContract::Span,
                b"zzababc!".as_slice(),
                2,
                8,
            ),
            (
                "[a-fA-F0-9_:/.-]{4,20}END",
                OutputContract::Span,
                b"!!aF_9:/dead-beef.END?".as_slice(),
                0,
                22,
            ),
            (
                "needle",
                OutputContract::Span,
                single_candidate_hay.as_slice(),
                0,
                single_candidate_hay.len(),
            ),
            (
                "[ABcd]tail",
                OutputContract::SelectedEnd,
                four_candidate_hay.as_slice(),
                3,
                four_candidate_hay.len(),
            ),
            (
                "[0-9A-F_a-f]Z",
                OutputContract::Span,
                four_range_hay.as_slice(),
                0,
                four_range_hay.len(),
            ),
            (
                "(?-u:[0-2A-B_e-f])",
                OutputContract::Exists,
                third_range_hay.as_slice(),
                0,
                third_range_hay.len(),
            ),
            (
                "(?-u:[3-5C-D_g-h])",
                OutputContract::Exists,
                fourth_range_hay.as_slice(),
                0,
                fourth_range_hay.len(),
            ),
            (
                "q",
                OutputContract::Exists,
                no_match_hay.as_slice(),
                1,
                no_match_hay.len().checked_sub(1).unwrap(),
            ),
            ("q", OutputContract::SelectedEnd, b"xxqz".as_slice(), 0, 4),
            // Each of these exercises the bounded structural prefix filter.
            // The first candidate in the haystack fails after byte zero and a
            // later valid start lies inside/after that rejected prefix.
            ("abcde", OutputContract::Span, b"abXabcde".as_slice(), 0, 8),
            (
                "(?:abcd|abef)Z",
                OutputContract::SelectedEnd,
                b"abXabefZ".as_slice(),
                0,
                8,
            ),
            (
                "ab(?:c)?d",
                OutputContract::Span,
                b"abXabd".as_slice(),
                0,
                6,
            ),
            (
                "ab+c+d",
                OutputContract::Exists,
                b"abXabcccd".as_slice(),
                0,
                9,
            ),
            (
                "ab(?:|c)d",
                OutputContract::Span,
                b"abXabcd".as_slice(),
                0,
                7,
            ),
            (
                "[a-c]QZ",
                OutputContract::Span,
                matrix_range.as_slice(),
                0,
                matrix_range.len(),
            ),
            (
                "[a-f][0-3]QZ",
                OutputContract::SelectedEnd,
                matrix_two_classes.as_slice(),
                0,
                matrix_two_classes.len(),
            ),
            (
                "[acegik][02468]QZ",
                OutputContract::Exists,
                matrix_sparse_classes.as_slice(),
                0,
                matrix_sparse_classes.len(),
            ),
            (
                "(?:ab|cd|ef)QZ",
                OutputContract::Span,
                matrix_alternation.as_slice(),
                0,
                matrix_alternation.len(),
            ),
            (
                "(?:ab|cd)[A-Z].*",
                OutputContract::Exists,
                retained_relation.as_slice(),
                0,
                retained_relation.len(),
            ),
            (
                "(?:ab|cd)[A-Z].*",
                OutputContract::SelectedEnd,
                retained_relation.as_slice(),
                1,
                139,
            ),
            (
                "(?:ab|cd)[A-Z].*",
                OutputContract::Span,
                retained_relation.as_slice(),
                17,
                141,
            ),
            (
                "xbcde",
                OutputContract::Span,
                suffix_false_then_match.as_slice(),
                0,
                suffix_false_then_match.len(),
            ),
            (
                "ab(?:c)?d",
                OutputContract::SelectedEnd,
                suffix_variable_width.as_slice(),
                0,
                suffix_variable_width.len(),
            ),
            (
                "xyZ",
                OutputContract::Exists,
                suffix_absent.as_slice(),
                0,
                suffix_absent.len(),
            ),
            (
                "a?b?",
                OutputContract::Span,
                suffix_nullable.as_slice(),
                0,
                suffix_nullable.len(),
            ),
            (
                "needle",
                OutputContract::Exists,
                suffix_self_overlap.as_slice(),
                0,
                suffix_self_overlap.len(),
            ),
            (
                "x*abc+d",
                OutputContract::Exists,
                reset_false_then_match.as_slice(),
                0,
                reset_false_then_match.len(),
            ),
            (
                "a+?z",
                OutputContract::SelectedEnd,
                reset_base_minus_one.as_slice(),
                0,
                reset_base_minus_one.len(),
            ),
            (
                "b+z",
                OutputContract::Span,
                reset_base_minus_64.as_slice(),
                0,
                reset_base_minus_64.len(),
            ),
            (
                "c+?z",
                OutputContract::Span,
                reset_base_minus_65.as_slice(),
                0,
                reset_base_minus_65.len(),
            ),
            (
                "d+z",
                OutputContract::Span,
                reset_absent_in_cap.as_slice(),
                0,
                reset_absent_in_cap.len(),
            ),
            (
                "e+z",
                OutputContract::Span,
                reset_candidate_at_window_start.as_slice(),
                10,
                reset_candidate_at_window_start.len(),
            ),
            (
                "abcde",
                OutputContract::SelectedEnd,
                exact_match_at_start.as_slice(),
                0,
                exact_match_at_start.len(),
            ),
            (
                "qk(?-u:[\\x00-\\xff])",
                OutputContract::Exists,
                selective_before_any_terminal.as_slice(),
                0,
                selective_before_any_terminal.len(),
            ),
            (
                "q+(?-u:[\\x00-\\xff])",
                OutputContract::Span,
                unbounded_before_any_terminal.as_slice(),
                0,
                unbounded_before_any_terminal.len(),
            ),
            (
                "(?-u:\\x01[\\x03-\\x06])",
                OutputContract::Exists,
                lazy_exact_range.as_slice(),
                0,
                lazy_exact_range.len(),
            ),
            (
                "(?-u:[\\x01-\\x02]e)",
                OutputContract::SelectedEnd,
                lazy_range_exact.as_slice(),
                0,
                lazy_range_exact.len(),
            ),
            (
                "(?-u:[\\x01-\\x02][\\x03-\\x06])",
                OutputContract::Span,
                lazy_range_range.as_slice(),
                0,
                lazy_range_range.len(),
            ),
            (
                "A(?-u:[^Z])*Z",
                OutputContract::Exists,
                loop_nonaccepting.as_slice(),
                0,
                loop_nonaccepting.len(),
            ),
            (
                "(?-u:[^Z]*)",
                OutputContract::Span,
                loop_accepting.as_slice(),
                0,
                loop_accepting.len(),
            ),
            (
                "(?s:.+)z",
                OutputContract::Exists,
                seeded_accept.as_slice(),
                0,
                seeded_accept.len(),
            ),
            (
                "(?s:.+)z",
                OutputContract::SelectedEnd,
                seeded_accept.as_slice(),
                0,
                seeded_accept.len(),
            ),
            (
                "(?s:.+)z",
                OutputContract::Span,
                seeded_accept.as_slice(),
                0,
                seeded_accept.len(),
            ),
            (
                r"(?-u:\x01[3-7])",
                OutputContract::Span,
                sparse_batch_boundaries.as_slice(),
                0,
                sparse_batch_boundaries.len(),
            ),
        ];
        let directory = std::env::var_os(environment).map_or_else(
            || std::env::temp_dir().join(format!("{fallback}-{}", std::process::id())),
            std::path::PathBuf::from,
        );
        fs::create_dir_all(&directory).unwrap();
        let mut source = String::from(
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n\
                 #define FAIL(c,i,a,b) do { fprintf(stderr,\"case %u window %zu..%zu: status %u result %zu..%zu\\n\",(unsigned)(i),(size_t)(a),(size_t)(b),(unsigned)s,r[0],r[1]); return (c); } while(0)\n",
        );
        let mut calls = String::from("int main(void) { size_t r[2]; uint32_t s;\n");
        let mut first_symbol = None;
        let mut saw_direct_rows = false;
        let mut saw_class_mapped_rows = false;
        let mut saw_exact_prefix_match = false;
        let mut saw_correlated_prefix_decline = false;
        let mut saw_prefix_block = false;
        for (index, (pattern, output, haystack, _start, _end)) in cases.iter().enumerate() {
            let failure_code = index.checked_add(10).unwrap();
            let compiled = compile(
                CompileRequest::new(*pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(*output),
            )
            .unwrap();
            assert_eq!(compiled.receipt().engine, EngineKind::OrderedDfa);
            let native_view = compiled.program().native_dfa_view().unwrap();
            let (_, native_layout) = build_native_dfa_table(native_view).unwrap();
            if *pattern == "(?s:.+)z" && *output == OutputContract::Exists {
                assert!(
                    native_layout
                        .seeded_reverse
                        .is_some_and(|reverse| reverse.proves_match),
                    "terminal seeded-reverse differential must reach the native sidecar",
                );
            }
            if haystack.len() >= usize::from(SUFFIX_PREFILTER_MIN_WINDOW_BYTES)
                && matches!(*pattern, "x*abc+d")
            {
                assert!(matches!(
                    native_layout.suffix_filter.unwrap().restart,
                    NativeSuffixRestart::Synchronizing { .. }
                ));
            }
            if pattern.contains("(?-u:[\\x00-\\xff])") {
                let suffix = native_layout.suffix_filter.unwrap();
                assert!(
                    suffix
                        .filter
                        .scan_offset
                        .checked_add(1)
                        .is_some_and(|offset| offset < suffix.minimum_width)
                );
                if pattern.starts_with("q+") {
                    assert_eq!(suffix.restart, NativeSuffixRestart::OriginalStart);
                }
            }
            if matches!(
                *pattern,
                "(?-u:\\x01[\\x03-\\x06])"
                    | "(?-u:[\\x01-\\x02]e)"
                    | "(?-u:[\\x01-\\x02][\\x03-\\x06])"
            ) {
                let vector = native_layout.vector_filter.unwrap();
                assert!(vector.columns().iter().any(|column| !column.is_exact()));
            }
            if matches!(*pattern, "A(?-u:[^Z])*Z" | "(?-u:[^Z]*)") {
                let loop_skip = native_layout
                    .loop_skip
                    .expect("differential loop-skip plan");
                assert_eq!(loop_skip.accepting, *pattern == "(?-u:[^Z]*)");
            }
            if *pattern == "(?:ab|cd)[A-Z].*" {
                let layout =
                    build_native_dfa_table_for_architecture(native_view, target.architecture)
                        .unwrap()
                        .1;
                let coverage = derive_native_vector_guard_coverage(layout, true, None)
                    .expect("retained exact relation coverage");
                assert!(coverage.has_rejectable_residual(layout).unwrap());
            }
            if *pattern == r"(?-u:\x01[3-7])" {
                let layout =
                    build_native_dfa_table_for_architecture(native_view, target.architecture)
                        .unwrap()
                        .1;
                let filter = layout.start_filter.expect("rare start filter");
                let code = compiled.module().sections()[TEXT_SECTION].bytes();
                match target.architecture {
                    Architecture::X86_64 => {
                        let kind = x86_start_filter_kind(target.features);
                        assert!(x86_use_sparse_filter_mask_batch(filter, kind));
                        let clear = match kind {
                            X86StartFilterKind::Sse2 => &[0x66, 0x45, 0x0f, 0xef, 0xff][..],
                            X86StartFilterKind::Avx2 => &[0xc4, 0x41, 0x05, 0xef, 0xff][..],
                            X86StartFilterKind::Avx512Bw => &[0xc4, 0xe1, 0xcc, 0x47, 0xf6][..],
                        };
                        assert!(code.windows(clear.len()).any(|window| window == clear));
                    }
                    Architecture::Aarch64 => {
                        assert!(use_aarch64_filter_batch(filter));
                        let words = code
                            .chunks_exact(4)
                            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                            .collect::<Vec<_>>();
                        assert!(
                            words.contains(&aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES).unwrap())
                        );
                    }
                }
            }
            match native_layout.transitions {
                TransitionLayout::ClassMapped => saw_class_mapped_rows = true,
                TransitionLayout::DirectByte => saw_direct_rows = true,
            }
            saw_exact_prefix_match |= native_layout.exact_prefix_match_width.is_some();
            saw_prefix_block |= native_layout.prefix_block.is_some();
            saw_correlated_prefix_decline |= native_view.exact_match_width
                == Some(native_view.anchored_prefix.sets().len())
                && derive_exact_prefix_product_width(native_view).is_none();
            if matches!(
                *pattern,
                "abcde"
                    | "(?:abcd|abef)Z"
                    | "ab(?:c)?d"
                    | "abc+d"
                    | "ab(?:|c)d"
                    | "[a-c]QZ"
                    | "[a-f][0-3]QZ"
                    | "[acegik][02468]QZ"
                    | "(?:ab|cd|ef)QZ"
                    | "xbcde"
            ) {
                assert!(
                    compiled.module().anchored_prefix_filter_bytes() >= 2,
                    "{pattern}"
                );
            }
            let symbol = compiled.module().entry_symbol();
            first_symbol.get_or_insert_with(|| symbol.to_owned());
            fs::write(directory.join(format!("case{index}.o")), compiled.object()).unwrap();
            writeln!(
                source,
                "extern uint32_t {symbol}(const unsigned char*, size_t, size_t, size_t, size_t*);"
            )
            .unwrap();
            let bytes = haystack
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            writeln!(
                source,
                "static const unsigned char h{index}[] = {{{bytes}}};"
            )
            .unwrap();
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = compiled
                        .search(haystack, SearchWindow::new(start, end))
                        .unwrap();
                    writeln!(
                        calls,
                        "r[0]=99;r[1]=99;s={symbol}(h{index},{},{start},{end},r);",
                        haystack.len()
                    )
                    .unwrap();
                    match expected {
                        MatchResult::Exists(found) => {
                            writeln!(
                                calls,
                                "if (s != {} || r[0]!=0 || r[1]!=0) FAIL({failure_code},{index},{start},{end});",
                                u8::from(found)
                            )
                            .unwrap();
                        }
                        MatchResult::SelectedEnd(found) => match found {
                            Some(selected_end) => writeln!(
                                calls,
                                "if (s!=1 || r[0]!={selected_end} || r[1]!={selected_end}) FAIL({failure_code},{index},{start},{end});"
                            )
                            .unwrap(),
                            None => writeln!(
                                calls,
                                "if (s!=0 || r[0]!=0 || r[1]!=0) FAIL({failure_code},{index},{start},{end});"
                            )
                            .unwrap(),
                        },
                        MatchResult::Span(found) => match found {
                            Some((match_start, match_end)) => writeln!(
                                calls,
                                "if (s!=1 || r[0]!={match_start} || r[1]!={match_end}) FAIL({failure_code},{index},{start},{end});"
                            )
                            .unwrap(),
                            None => writeln!(
                                calls,
                                "if (s!=0 || r[0]!=0 || r[1]!=0) FAIL({failure_code},{index},{start},{end});"
                            )
                            .unwrap(),
                        },
                    }
                }
            }
        }
        assert!(
            saw_direct_rows,
            "differential bundle must cover direct rows"
        );
        assert!(
            saw_class_mapped_rows,
            "differential bundle must cover class-mapped rows"
        );
        assert!(
            saw_exact_prefix_match,
            "differential bundle must cover exact-prefix fast matches"
        );
        assert!(
            saw_correlated_prefix_decline,
            "differential bundle must cover correlated-prefix declines"
        );
        assert!(
            saw_prefix_block,
            "differential bundle must cover a graph-derived 16-byte prefix block"
        );
        let first_symbol = first_symbol.unwrap();
        writeln!(
            calls,
            "r[0]=99;r[1]=99;s={first_symbol}(h0,7,6,2,r);if(s!=2||r[0]!=99||r[1]!=99)return 90;"
        )
        .unwrap();
        writeln!(
            calls,
            "r[0]=99;r[1]=99;s={first_symbol}(h0,7,0,8,r);if(s!=2||r[0]!=99||r[1]!=99)return 91;"
        )
        .unwrap();
        writeln!(
            calls,
            "s={first_symbol}(h0,7,0,7,(size_t*)0);if(s!=2)return 92;"
        )
        .unwrap();
        writeln!(
            calls,
            "r[0]=99;r[1]=99;s={first_symbol}((const unsigned char*)0,7,0,7,r);if(s!=2||r[0]!=99||r[1]!=99)return 93;"
        )
        .unwrap();
        writeln!(
            calls,
            "r[0]=99;r[1]=99;s={first_symbol}((const unsigned char*)0,0,0,0,r);if(s!=2||r[0]!=99||r[1]!=99)return 94;"
        )
        .unwrap();
        writeln!(
            calls,
            "r[0]=99;r[1]=99;s={first_symbol}(h0,7,0,7,(size_t*)((unsigned char*)r+1));if(s!=2||r[0]!=99||r[1]!=99)return 95;"
        )
        .unwrap();
        writeln!(
            calls,
            "r[0]=99;r[1]=99;s={first_symbol}(h0,((size_t)1<<(sizeof(size_t)*8-1)),0,0,r);if(s!=2||r[0]!=99||r[1]!=99)return 96;"
        )
        .unwrap();
        writeln!(calls, "puts(\"{success_marker}\"); return 0; }}").unwrap();
        source.push_str(&calls);
        fs::write(directory.join("harness.c"), source).unwrap();
        fs::write(
            directory.join("README.txt"),
            "Generated only from source patterns and portable compiler expectations.\n",
        )
        .unwrap();
        println!("{}", directory.display());
    }

    #[test]
    #[ignore = "generates an x86-64 Linux linker/execution bundle"]
    fn generate_x86_64_linux_differential_bundle() {
        generate_differential_bundle(
            Target::x86_64_linux(),
            "FRE_AOT_X86_BUNDLE",
            "fre-aot-x86-bundle",
            "native-x86-linux-differential-ok",
        );
    }

    #[test]
    #[ignore = "generates an AVX2 x86-64 Linux linker/execution bundle"]
    fn generate_x86_64_linux_avx2_differential_bundle() {
        generate_differential_bundle(
            Target::x86_64_linux()
                .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap(),
            "FRE_AOT_X86_AVX2_BUNDLE",
            "fre-aot-x86-avx2-bundle",
            "native-x86-linux-avx2-differential-ok",
        );
    }

    #[test]
    #[ignore = "generates an AVX-512BW x86-64 Linux static-validation bundle"]
    fn generate_x86_64_linux_avx512bw_bundle() {
        let features = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        generate_differential_bundle(
            Target::x86_64_linux().with_features(features).unwrap(),
            "FRE_AOT_X86_AVX512_BUNDLE",
            "fre-aot-x86-avx512-bundle",
            "native-x86-linux-avx512-differential-ok",
        );
    }

    #[test]
    #[ignore = "generates an AArch64 Linux linker/execution bundle"]
    fn generate_aarch64_linux_differential_bundle() {
        generate_differential_bundle(
            Target::aarch64_linux(),
            "FRE_AOT_AARCH64_BUNDLE",
            "fre-aot-aarch64-bundle",
            "native-aarch64-linux-differential-ok",
        );
    }

    #[test]
    #[ignore = "generates an ASIMD AArch64 Linux linker/execution bundle"]
    fn generate_aarch64_linux_asimd_differential_bundle() {
        generate_differential_bundle(
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
            "FRE_AOT_AARCH64_ASIMD_BUNDLE",
            "fre-aot-aarch64-asimd-bundle",
            "native-aarch64-linux-asimd-differential-ok",
        );
    }

    #[test]
    #[ignore = "generates an x86-64 macOS linker/execution bundle"]
    fn generate_x86_64_macos_differential_bundle() {
        generate_differential_bundle(
            Target::x86_64_macos(),
            "FRE_AOT_X86_MACOS_BUNDLE",
            "fre-aot-x86-macos-bundle",
            "native-x86-macos-differential-ok",
        );
    }
}
