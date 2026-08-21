//! In-process publication for self-contained general FRE AOT regex modules.
//!
//! [`fre_aot_regex::compile`] always emits a deterministic relocatable object,
//! but it also retains the object-format-neutral sections, symbols, and
//! relocations that produced that object. This crate publishes those retained
//! module parts directly: it rejects every undefined symbol, applies the same
//! local relocations in private memory, verifies the complete copy, changes
//! text from RW to RX and read-only data from RW to R, synchronizes the
//! instruction cache, and only then exposes a typed [`PublishedSpan`].
//!
//! No portable executor or runtime helper is selected on refusal. A grep
//! integration can compile and publish on a background thread, atomically
//! share the returned cloneable handle at a file boundary, and retain its
//! stock matcher for every [`PublicationError`].

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(unsafe_code)]

mod error;
#[allow(
    unsafe_code,
    reason = "mmap, page protection, instruction-cache maintenance, and owned unmapping are isolated in the platform boundary"
)]
mod platform;

use core::{ffi::c_void, ptr::NonNull};
use std::sync::Arc;

use fre_aot_regex::{
    Architecture, CompileRequest, CompiledModule, CompiledRegex, CpuFeature, EntryAbi, FeatureSet,
    ModuleRelocation, OutputContract, RelocationKind, SearchWindow, SectionKind, SymbolBinding,
    SymbolKind, Target, compile,
};
use fre_target_features::{Feature as HostFeature, host as host_cpu_features};

pub use error::{BuildError, CallError, PublicationError, PublicationResource, PublicationStage};

const DEFAULT_MAX_SECTIONS: usize = 16;
const DEFAULT_MAX_RELOCATIONS: usize = 8_388_608;
const DEFAULT_MAX_CODE_BYTES: usize = 536_870_912;
const DEFAULT_MAX_READ_ONLY_DATA_BYTES: usize = 536_870_912;
const DEFAULT_MAX_SCRATCH_BYTES: usize = 536_870_912;
const DEFAULT_MAX_MAPPED_BYTES: usize = 1_073_741_824;
const SPAN_ENTRY_SYMBOL_PREFIX: &str = "fre_aot_regex_search_v1_";

/// Explicit ceilings for one direct-native publication transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationLimits {
    pub max_sections: usize,
    pub max_relocations: usize,
    pub max_code_bytes: usize,
    pub max_read_only_data_bytes: usize,
    /// Maximum exact section bytes cloned while address-dependent relocations
    /// are applied before the verified mapping copy.
    pub max_scratch_bytes: usize,
    /// Complete reservation including guards, aligned section pages, and
    /// internal protection-boundary padding.
    pub max_mapped_bytes: usize,
}

impl Default for PublicationLimits {
    fn default() -> Self {
        Self {
            max_sections: DEFAULT_MAX_SECTIONS,
            max_relocations: DEFAULT_MAX_RELOCATIONS,
            max_code_bytes: DEFAULT_MAX_CODE_BYTES,
            max_read_only_data_bytes: DEFAULT_MAX_READ_ONLY_DATA_BYTES,
            max_scratch_bytes: DEFAULT_MAX_SCRATCH_BYTES,
            max_mapped_bytes: DEFAULT_MAX_MAPPED_BYTES,
        }
    }
}

/// Exact memory and relocation accounting for a published module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationAccounting {
    page_bytes: usize,
    section_count: usize,
    relocation_count: usize,
    code_bytes: usize,
    read_only_data_bytes: usize,
    scratch_bytes: usize,
    padding_bytes: usize,
    guard_bytes: usize,
    payload_mapped_bytes: usize,
    total_mapped_bytes: usize,
}

impl PublicationAccounting {
    #[must_use]
    pub const fn page_bytes(self) -> usize {
        self.page_bytes
    }

    #[must_use]
    pub const fn section_count(self) -> usize {
        self.section_count
    }

    #[must_use]
    pub const fn relocation_count(self) -> usize {
        self.relocation_count
    }

    #[must_use]
    pub const fn code_bytes(self) -> usize {
        self.code_bytes
    }

    #[must_use]
    pub const fn read_only_data_bytes(self) -> usize {
        self.read_only_data_bytes
    }

    #[must_use]
    pub const fn scratch_bytes(self) -> usize {
        self.scratch_bytes
    }

    #[must_use]
    pub const fn padding_bytes(self) -> usize {
        self.padding_bytes
    }

    #[must_use]
    pub const fn guard_bytes(self) -> usize {
        self.guard_bytes
    }

    #[must_use]
    pub const fn payload_mapped_bytes(self) -> usize {
        self.payload_mapped_bytes
    }

    #[must_use]
    pub const fn total_mapped_bytes(self) -> usize {
        self.total_mapped_bytes
    }
}

/// Stable identity of the exact compiler-produced object represented by a
/// published mapping.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublicationIdentity([u8; 32]);

impl PublicationIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Validated half-open match returned by a direct native `Span` entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpanMatch {
    start: usize,
    end: usize,
}

impl SpanMatch {
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    #[must_use]
    pub const fn range(self) -> core::ops::Range<usize> {
        self.start..self.end
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[repr(C)]
struct RawSpan {
    start: usize,
    end: usize,
}

type NativeSearch = unsafe extern "C" fn(*const u8, usize, usize, usize, *mut RawSpan) -> u32;

struct PublishedInner {
    #[allow(
        dead_code,
        reason = "the owned mapping's Drop controls executable-page lifetime"
    )]
    mapping: platform::Mapping,
    entry: NativeSearch,
    identity: PublicationIdentity,
    accounting: PublicationAccounting,
    target: Target,
}

impl core::fmt::Debug for PublishedInner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PublishedInner")
            .field("identity", &self.identity)
            .field("accounting", &self.accounting)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

/// Immutable, reentrant, direct-native `Span` matcher.
///
/// Cloning increments one `Arc`; calls themselves do not allocate, lock,
/// detect CPU features, resolve symbols, or modify shared state.
#[derive(Clone, Debug)]
pub struct PublishedSpan {
    inner: Arc<PublishedInner>,
}

impl PublishedSpan {
    /// Search one checked half-open window with the compiler-produced native
    /// entry.
    #[inline]
    #[allow(
        unsafe_code,
        reason = "one hidden call boundary invokes the authenticated compiler-produced Span entry and reads its status-initialized result"
    )]
    pub fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<SpanMatch>, CallError> {
        let start = window.start();
        let end = window.end();
        if start > end || end > haystack.len() {
            return Err(CallError::InvalidWindow {
                start,
                end,
                haystack_len: haystack.len(),
            });
        }
        let mut slot = RawSpan {
            start: usize::MAX,
            end: usize::MAX,
        };
        // SAFETY: publication decoded this exact five-argument Span entry only
        // after all module bytes became immutable and executable. This borrow
        // keeps the Arc-owned mapping live; the checked haystack/window and
        // aligned disjoint result slot remain valid for the complete call.
        let status = unsafe {
            (self.inner.entry)(haystack.as_ptr(), haystack.len(), start, end, &raw mut slot)
        };
        match status {
            0 => Ok(None),
            1 => {
                if start <= slot.start
                    && slot.start <= slot.end
                    && slot.end <= end
                    && slot.end <= haystack.len()
                {
                    Ok(Some(SpanMatch {
                        start: slot.start,
                        end: slot.end,
                    }))
                } else {
                    Err(CallError::InvalidSpan {
                        start: slot.start,
                        end: slot.end,
                        window_start: start,
                        window_end: end,
                        haystack_len: haystack.len(),
                    })
                }
            }
            status => Err(CallError::NativeStatus { status }),
        }
    }

    /// Search from `at` through the end of `haystack`.
    #[inline]
    pub fn find_at(&self, haystack: &[u8], at: usize) -> Result<Option<SpanMatch>, CallError> {
        self.search(haystack, SearchWindow::new(at, haystack.len()))
    }

    /// Search the complete haystack.
    #[inline]
    pub fn find(&self, haystack: &[u8]) -> Result<Option<SpanMatch>, CallError> {
        self.search(haystack, SearchWindow::full(haystack))
    }

    /// Iterate non-overlapping matches with Rust-regex empty-match progress.
    #[must_use]
    pub fn find_iter<'matcher, 'haystack>(
        &'matcher self,
        haystack: &'haystack [u8],
    ) -> SpanMatches<'matcher, 'haystack> {
        SpanMatches {
            matcher: self,
            haystack,
            next_start: 0,
            window_end: haystack.len(),
            last_match_end: None,
            pending_empty_progress: false,
            finished: false,
        }
    }

    /// Iterate non-overlapping matches inside one checked half-open window.
    pub fn find_iter_in<'matcher, 'haystack>(
        &'matcher self,
        haystack: &'haystack [u8],
        window: SearchWindow,
    ) -> Result<SpanMatches<'matcher, 'haystack>, CallError> {
        let start = window.start();
        let end = window.end();
        if start > end || end > haystack.len() {
            return Err(CallError::InvalidWindow {
                start,
                end,
                haystack_len: haystack.len(),
            });
        }
        Ok(SpanMatches {
            matcher: self,
            haystack,
            next_start: start,
            window_end: end,
            last_match_end: None,
            pending_empty_progress: false,
            finished: false,
        })
    }

    #[must_use]
    pub fn identity(&self) -> PublicationIdentity {
        self.inner.identity
    }

    #[must_use]
    pub fn accounting(&self) -> PublicationAccounting {
        self.inner.accounting
    }

    #[must_use]
    pub fn target(&self) -> Target {
        self.inner.target
    }
}

/// Borrowing iterator returned by [`PublishedSpan::find_iter`].
#[derive(Debug)]
pub struct SpanMatches<'matcher, 'haystack> {
    matcher: &'matcher PublishedSpan,
    haystack: &'haystack [u8],
    next_start: usize,
    window_end: usize,
    last_match_end: Option<usize>,
    pending_empty_progress: bool,
    finished: bool,
}

impl Iterator for SpanMatches<'_, '_> {
    type Item = Result<SpanMatch, CallError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished {
            if self.pending_empty_progress {
                self.pending_empty_progress = false;
                if self.next_start == self.window_end {
                    self.finished = true;
                    return None;
                }
                self.next_start = self
                    .next_start
                    .checked_add(1)
                    .expect("iterator progress remains inside its validated window");
            }
            let found = match self.matcher.search(
                self.haystack,
                SearchWindow::new(self.next_start, self.window_end),
            ) {
                Ok(Some(found)) => found,
                Ok(None) => {
                    self.finished = true;
                    return None;
                }
                Err(error) => {
                    self.finished = true;
                    return Some(Err(error));
                }
            };
            if found.is_empty() && self.last_match_end == Some(found.end()) {
                self.pending_empty_progress = true;
                continue;
            }
            self.next_start = found.end();
            self.last_match_end = Some(found.end());
            self.pending_empty_progress = found.is_empty();
            return Some(Ok(found));
        }
        None
    }
}

impl std::iter::FusedIterator for SpanMatches<'_, '_> {}

/// Detect the complete compiler target tuple available to this process.
///
/// The returned feature set can be passed directly to [`CompileRequest`].
/// Publication independently checks the requested set again before mapping.
pub fn host_target() -> Result<Target, PublicationError> {
    if !platform::supported() {
        return Err(PublicationError::UnsupportedHost);
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    let base = Target::x86_64_linux();
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    let base = Target::x86_64_macos();
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    let base = Target::aarch64_linux();
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    let base = Target::aarch64_macos();

    let features = detected_host_features();

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    return base
        .with_features(features)
        .map_err(|_| PublicationError::InvalidModule {
            at: "detected host target",
        });

    #[allow(
        unreachable_code,
        reason = "unsupported targets retain the typed error tail after cfg-selected host returns"
    )]
    Err(PublicationError::UnsupportedHost)
}

fn detected_host_features() -> FeatureSet {
    let usable = host_cpu_features().usable();
    let mut features = FeatureSet::EMPTY;
    for (host, compiler) in [
        (HostFeature::X86Sse2, CpuFeature::X86Sse2),
        (HostFeature::X86Avx2, CpuFeature::X86Avx2),
        (HostFeature::X86Avx512F, CpuFeature::X86Avx512F),
        (HostFeature::X86Avx512Bw, CpuFeature::X86Avx512Bw),
        (HostFeature::X86Avx512Vl, CpuFeature::X86Avx512Vl),
        (HostFeature::ArmNeon, CpuFeature::Aarch64Asimd),
        (HostFeature::ArmSve, CpuFeature::Aarch64Sve),
        (HostFeature::ArmSve2, CpuFeature::Aarch64Sve2),
    ] {
        if usable.contains(host) {
            features = features.with(compiler);
        }
    }
    features
}

/// Publish one compiler-owned `Span` result without accepting external symbols
/// or invoking FRE's portable runtime.
///
/// The compiler artifact is consumed so its retained portable program, object
/// bytes, and object-format-neutral module are released before this function
/// returns. The published handle owns only immutable native pages and compact
/// publication metadata.
#[allow(
    clippy::needless_pass_by_value,
    reason = "consumption releases the portable program, module, and emitted object after native publication"
)]
pub fn publish_span(
    compiled: CompiledRegex,
    limits: PublicationLimits,
) -> Result<PublishedSpan, PublicationError> {
    publish_span_impl(&compiled, limits)
}

/// Compile and publish one direct-native `Span` matcher in the calling thread.
///
/// This convenience operation still includes normal relocatable-object
/// emission inside [`compile`]. It replaces only the filesystem, external
/// linker, and dynamic-loader transaction.
pub fn compile_and_publish_span(
    request: CompileRequest,
    limits: PublicationLimits,
) -> Result<PublishedSpan, BuildError> {
    let compiled = compile(request)?;
    Ok(publish_span(compiled, limits)?)
}

#[derive(Clone, Copy, Debug)]
struct SectionPlan {
    offset: usize,
    mapped_bytes: usize,
    kind: SectionKind,
}

#[derive(Debug)]
struct LoadPlan {
    sections: Vec<SectionPlan>,
    entry_offset: usize,
    accounting: PublicationAccounting,
}

#[allow(
    unsafe_code,
    reason = "publication performs checked copies, target cache synchronization, and one post-RX function-pointer decode"
)]
fn publish_span_impl(
    compiled: &CompiledRegex,
    limits: PublicationLimits,
) -> Result<PublishedSpan, PublicationError> {
    let receipt = compiled.receipt();
    if receipt.output != OutputContract::Span {
        return Err(PublicationError::OutputMismatch {
            expected: OutputContract::Span,
            actual: receipt.output,
        });
    }
    if receipt.entry_abi != EntryAbi::SpanSearchV1 {
        return Err(PublicationError::EntryAbiMismatch {
            expected: EntryAbi::SpanSearchV1,
            actual: receipt.entry_abi,
        });
    }
    let module = compiled.module();
    validate_target(module.target())?;
    if receipt.target != module.target() {
        return Err(PublicationError::InvalidModule {
            at: "receipt target",
        });
    }
    if let Some(symbol) = module
        .symbols()
        .iter()
        .find(|symbol| symbol.section.is_none())
    {
        return Err(PublicationError::RuntimeHelperRequired {
            symbol: symbol.name.clone(),
        });
    }
    if receipt.runtime_helper_required {
        return Err(PublicationError::InvalidModule {
            at: "runtime-helper receipt",
        });
    }

    let page_bytes = platform::page_size()
        .map_err(|errno| system_error(PublicationStage::PageSize, errno, false))?;
    if page_bytes == 0 || !page_bytes.is_power_of_two() {
        return Err(PublicationError::InvalidModule {
            at: "host page size",
        });
    }
    let plan = plan_module(module, receipt, page_bytes, limits)?;
    let mut staging = clone_sections(module, plan.accounting.scratch_bytes)?;
    let mapping = platform::Mapping::reserve(plan.accounting.total_mapped_bytes)
        .map_err(|errno| system_error(PublicationStage::Reserve, errno, false))?;
    apply_relocations(module, &plan.sections, &mut staging, mapping.address())?;

    for section in &plan.sections {
        if section.mapped_bytes != 0 {
            mapping
                .make_writable(section.offset, section.mapped_bytes)
                .map_err(|errno| system_error(PublicationStage::MakeWritable, errno, false))?;
        }
    }
    for (section, bytes) in plan.sections.iter().zip(&staging) {
        // SAFETY: the exact planned section range is RW, initialized source
        // bytes are disjoint heap storage, and every extent was checked.
        unsafe { mapping.copy_from(section.offset, bytes) };
    }
    verify_copy(&mapping, &plan.sections, &staging)?;

    for (section, original) in plan.sections.iter().zip(module.sections()) {
        if section.mapped_bytes == 0 {
            continue;
        }
        match section.kind {
            SectionKind::Text => mapping
                .make_executable(section.offset, section.mapped_bytes)
                .map_err(|errno| system_error(PublicationStage::ProtectText, errno, true))?,
            SectionKind::ReadOnlyData => mapping
                .make_read_only(section.offset, section.mapped_bytes)
                .map_err(|errno| {
                    system_error(PublicationStage::ProtectReadOnlyData, errno, false)
                })?,
        }
        if section.kind == SectionKind::Text && !original.data.is_empty() {
            let pointer =
                mapping
                    .pointer(section.offset)
                    .ok_or(PublicationError::InvalidModule {
                        at: "text mapping address",
                    })?;
            // SAFETY: this is the exact initialized text range after its final
            // RX transition and before any callable is exposed.
            unsafe {
                platform::synchronize_instruction_cache(pointer.as_ptr(), original.data.len());
            }
        }
    }

    let entry_pointer =
        mapping
            .pointer(plan.entry_offset)
            .ok_or(PublicationError::InvalidModule {
                at: "entry mapping address",
            })?;
    // SAFETY: planning resolved the unique compiler-produced function symbol
    // in a Text section. The target/ABI/output tuple was checked and every
    // byte and relocation reached its immutable final protection first.
    let entry = unsafe { decode_entry(entry_pointer) };
    let inner = PublishedInner {
        mapping,
        entry,
        identity: PublicationIdentity(receipt.object_sha256),
        accounting: plan.accounting,
        target: receipt.target,
    };
    Ok(PublishedSpan {
        inner: Arc::new(inner),
    })
}

#[allow(
    unsafe_code,
    reason = "the private helper is the sole conversion from an authenticated RX entry address to its exact C ABI"
)]
unsafe fn decode_entry(pointer: NonNull<c_void>) -> NativeSearch {
    // SAFETY: caller authenticated the code symbol and exact C ABI before
    // asking for this one-time function-pointer conversion.
    unsafe { core::mem::transmute::<*mut c_void, NativeSearch>(pointer.as_ptr()) }
}

fn validate_target(target: Target) -> Result<(), PublicationError> {
    let host = host_target()?;
    if target.architecture != host.architecture
        || target.operating_system != host.operating_system
        || target.abi != host.abi
    {
        return Err(PublicationError::TargetMismatch {
            requested: target,
            host,
        });
    }
    if host.features.contains(target.features) {
        return Ok(());
    }
    for feature in [
        CpuFeature::X86Sse2,
        CpuFeature::X86Avx2,
        CpuFeature::X86Avx512F,
        CpuFeature::X86Avx512Bw,
        CpuFeature::X86Avx512Vl,
        CpuFeature::Aarch64Asimd,
        CpuFeature::Aarch64Sve,
        CpuFeature::Aarch64Sve2,
    ] {
        let selected = FeatureSet::of(feature);
        if target.features.contains(selected) && !host.features.contains(selected) {
            return Err(PublicationError::CpuFeatureUnavailable { feature });
        }
    }
    Err(PublicationError::InvalidModule {
        at: "unrecognized unavailable target feature",
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "layout, admission, resource accounting, and entry resolution are one fail-before-mmap transaction"
)]
fn plan_module(
    module: &CompiledModule,
    receipt: &fre_aot_regex::CompileReceipt,
    page_bytes: usize,
    limits: PublicationLimits,
) -> Result<LoadPlan, PublicationError> {
    enforce(
        PublicationResource::Sections,
        module.sections().len(),
        limits.max_sections,
    )?;
    enforce(
        PublicationResource::Relocations,
        module.relocations().len(),
        limits.max_relocations,
    )?;
    if module.sections().is_empty() {
        return Err(PublicationError::InvalidModule {
            at: "empty section list",
        });
    }
    if module.sections().len() != 2
        || module.sections()[0].kind != SectionKind::Text
        || module.sections()[1].kind != SectionKind::ReadOnlyData
    {
        return Err(PublicationError::InvalidModule {
            at: "canonical text and read-only-data sections",
        });
    }
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(module.sections().len())
        .map_err(|_| PublicationError::AllocationFailed {
            at: "section layout",
        })?;
    let mut cursor = page_bytes;
    let mut code_bytes = 0_usize;
    let mut read_only_data_bytes = 0_usize;
    let mut has_text = false;
    for section in module.sections() {
        let alignment = usize::try_from(section.alignment).map_err(|_| {
            PublicationError::ArithmeticOverflow {
                at: "section alignment",
            }
        })?;
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(PublicationError::InvalidModule {
                at: "section alignment",
            });
        }
        if alignment > page_bytes {
            return Err(PublicationError::InvalidModule {
                at: "section over-alignment",
            });
        }
        cursor = align_up(cursor, page_bytes.max(alignment), "section start")?;
        let mapped_bytes = if section.data.is_empty() {
            0
        } else {
            align_up(section.data.len(), page_bytes, "section page extent")?
        };
        sections.push(SectionPlan {
            offset: cursor,
            mapped_bytes,
            kind: section.kind,
        });
        cursor = cursor
            .checked_add(mapped_bytes)
            .ok_or(PublicationError::ArithmeticOverflow {
                at: "section layout",
            })?;
        match section.kind {
            SectionKind::Text => {
                has_text = true;
                code_bytes = code_bytes
                    .checked_add(section.data.len())
                    .ok_or(PublicationError::ArithmeticOverflow { at: "code bytes" })?;
            }
            SectionKind::ReadOnlyData => {
                read_only_data_bytes = read_only_data_bytes.checked_add(section.data.len()).ok_or(
                    PublicationError::ArithmeticOverflow {
                        at: "read-only data bytes",
                    },
                )?;
            }
        }
    }
    if !has_text || code_bytes == 0 {
        return Err(PublicationError::InvalidModule { at: "text section" });
    }
    if code_bytes != receipt.code_bytes || read_only_data_bytes != receipt.data_bytes {
        return Err(PublicationError::InvalidModule {
            at: "receipt section accounting",
        });
    }
    enforce(
        PublicationResource::CodeBytes,
        code_bytes,
        limits.max_code_bytes,
    )?;
    enforce(
        PublicationResource::ReadOnlyDataBytes,
        read_only_data_bytes,
        limits.max_read_only_data_bytes,
    )?;
    let scratch_bytes = code_bytes.checked_add(read_only_data_bytes).ok_or(
        PublicationError::ArithmeticOverflow {
            at: "scratch bytes",
        },
    )?;
    enforce(
        PublicationResource::ScratchBytes,
        scratch_bytes,
        limits.max_scratch_bytes,
    )?;
    let payload_mapped_bytes =
        cursor
            .checked_sub(page_bytes)
            .ok_or(PublicationError::ArithmeticOverflow {
                at: "payload mapped bytes",
            })?;
    let total_mapped_bytes = cursor
        .checked_add(page_bytes)
        .ok_or(PublicationError::ArithmeticOverflow { at: "guard pages" })?;
    enforce(
        PublicationResource::MappedBytes,
        total_mapped_bytes,
        limits.max_mapped_bytes,
    )?;
    let guard_bytes = page_bytes
        .checked_mul(2)
        .ok_or(PublicationError::ArithmeticOverflow { at: "guard bytes" })?;
    let padding_bytes = payload_mapped_bytes.checked_sub(scratch_bytes).ok_or(
        PublicationError::ArithmeticOverflow {
            at: "section padding bytes",
        },
    )?;

    validate_symbols_and_relocations(module, &sections)?;
    let entry_offset = resolve_entry(module, &sections)?;
    Ok(LoadPlan {
        sections,
        entry_offset,
        accounting: PublicationAccounting {
            page_bytes,
            section_count: module.sections().len(),
            relocation_count: module.relocations().len(),
            code_bytes,
            read_only_data_bytes,
            scratch_bytes,
            padding_bytes,
            guard_bytes,
            payload_mapped_bytes,
            total_mapped_bytes,
        },
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "symbol, relocation, target-section, and architecture checks form one fail-before-mmap admission pass"
)]
fn validate_symbols_and_relocations(
    module: &CompiledModule,
    sections: &[SectionPlan],
) -> Result<(), PublicationError> {
    for symbol in module.symbols() {
        let section_index =
            symbol
                .section
                .ok_or_else(|| PublicationError::RuntimeHelperRequired {
                    symbol: symbol.name.clone(),
                })?;
        let section =
            module
                .sections()
                .get(section_index)
                .ok_or(PublicationError::InvalidModule {
                    at: "symbol section",
                })?;
        let offset =
            usize::try_from(symbol.offset).map_err(|_| PublicationError::ArithmeticOverflow {
                at: "symbol offset",
            })?;
        let size = usize::try_from(symbol.size)
            .map_err(|_| PublicationError::ArithmeticOverflow { at: "symbol size" })?;
        if offset > section.data.len()
            || offset
                .checked_add(size)
                .is_none_or(|end| end > section.data.len())
        {
            return Err(PublicationError::InvalidModule {
                at: "symbol extent",
            });
        }
    }
    for (index, relocation) in module.relocations().iter().enumerate() {
        let source =
            module
                .sections()
                .get(relocation.section)
                .ok_or(PublicationError::InvalidModule {
                    at: "relocation source section",
                })?;
        if source.kind != SectionKind::Text {
            return Err(PublicationError::InvalidModule {
                at: "relocation outside text",
            });
        }
        let _source_plan =
            sections
                .get(relocation.section)
                .ok_or(PublicationError::InvalidModule {
                    at: "relocation source layout",
                })?;
        let symbol =
            module
                .symbols()
                .get(relocation.symbol)
                .ok_or(PublicationError::InvalidModule {
                    at: "relocation symbol",
                })?;
        let target_section =
            symbol
                .section
                .ok_or_else(|| PublicationError::RuntimeHelperRequired {
                    symbol: symbol.name.clone(),
                })?;
        let target =
            module
                .sections()
                .get(target_section)
                .ok_or(PublicationError::InvalidModule {
                    at: "relocation target section",
                })?;
        let target_len =
            u64::try_from(target.data.len()).map_err(|_| PublicationError::ArithmeticOverflow {
                at: "relocation target section length",
            })?;
        if target.data.is_empty() || symbol.offset >= target_len {
            return Err(PublicationError::InvalidModule {
                at: "relocation target extent",
            });
        }
        let offset = usize::try_from(relocation.offset).map_err(|_| {
            PublicationError::ArithmeticOverflow {
                at: "relocation offset",
            }
        })?;
        if offset
            .checked_add(4)
            .is_none_or(|end| end > source.data.len())
        {
            return Err(PublicationError::RelocationOutOfRange {
                index,
                kind: relocation.kind,
            });
        }
        match module.target().architecture {
            Architecture::X86_64
                if !matches!(
                    relocation.kind,
                    RelocationKind::X86PcRelative32 | RelocationKind::X86PltRelative32
                ) =>
            {
                return Err(PublicationError::InvalidModule {
                    at: "x86-64 relocation kind",
                });
            }
            Architecture::Aarch64
                if !matches!(
                    relocation.kind,
                    RelocationKind::Aarch64Page21
                        | RelocationKind::Aarch64PageOff12
                        | RelocationKind::Aarch64Branch26
                ) || !offset.is_multiple_of(4) =>
            {
                return Err(PublicationError::InvalidModule {
                    at: "AArch64 relocation kind or alignment",
                });
            }
            _ => {}
        }
    }
    Ok(())
}

fn resolve_entry(
    module: &CompiledModule,
    sections: &[SectionPlan],
) -> Result<usize, PublicationError> {
    let mut matches = module
        .symbols()
        .iter()
        .filter(|symbol| symbol.name == module.entry_symbol());
    let symbol = matches
        .next()
        .ok_or(PublicationError::InvalidModule { at: "entry symbol" })?;
    if !symbol.name.starts_with(SPAN_ENTRY_SYMBOL_PREFIX)
        || matches.next().is_some()
        || symbol.binding != SymbolBinding::Global
        || symbol.kind != SymbolKind::Function
    {
        return Err(PublicationError::InvalidModule {
            at: "unique global function entry",
        });
    }
    let section_index = symbol.section.ok_or(PublicationError::InvalidModule {
        at: "defined entry symbol",
    })?;
    let section = module
        .sections()
        .get(section_index)
        .ok_or(PublicationError::InvalidModule {
            at: "entry section",
        })?;
    if section.kind != SectionKind::Text {
        return Err(PublicationError::InvalidModule {
            at: "entry text section",
        });
    }
    let offset = usize::try_from(symbol.offset)
        .map_err(|_| PublicationError::ArithmeticOverflow { at: "entry offset" })?;
    let size = usize::try_from(symbol.size)
        .map_err(|_| PublicationError::ArithmeticOverflow { at: "entry size" })?;
    let alignment =
        usize::try_from(section.alignment).map_err(|_| PublicationError::ArithmeticOverflow {
            at: "entry alignment",
        })?;
    if size == 0
        || offset >= section.data.len()
        || offset
            .checked_add(size)
            .is_none_or(|end| end > section.data.len())
        || !offset.is_multiple_of(alignment)
    {
        return Err(PublicationError::InvalidModule {
            at: "entry extent or alignment",
        });
    }
    sections[section_index]
        .offset
        .checked_add(offset)
        .ok_or(PublicationError::ArithmeticOverflow {
            at: "mapped entry offset",
        })
}

fn clone_sections(
    module: &CompiledModule,
    scratch_bytes: usize,
) -> Result<Vec<Box<[u8]>>, PublicationError> {
    let mut staging = Vec::new();
    staging
        .try_reserve_exact(module.sections().len())
        .map_err(|_| PublicationError::AllocationFailed {
            at: "staging section list",
        })?;
    let mut copied = 0_usize;
    for section in module.sections() {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(section.data.len()).map_err(|_| {
            PublicationError::AllocationFailed {
                at: "staging section bytes",
            }
        })?;
        bytes.extend_from_slice(&section.data);
        copied = copied
            .checked_add(bytes.len())
            .ok_or(PublicationError::ArithmeticOverflow {
                at: "staging copy bytes",
            })?;
        staging.push(bytes.into_boxed_slice());
    }
    if copied != scratch_bytes {
        return Err(PublicationError::InvalidModule {
            at: "staging accounting",
        });
    }
    Ok(staging)
}

fn apply_relocations(
    module: &CompiledModule,
    sections: &[SectionPlan],
    staging: &mut [Box<[u8]>],
    mapping_base: usize,
) -> Result<(), PublicationError> {
    for (index, relocation) in module.relocations().iter().enumerate() {
        let source_plan =
            sections
                .get(relocation.section)
                .ok_or(PublicationError::InvalidModule {
                    at: "relocation source plan",
                })?;
        let source_offset = usize::try_from(relocation.offset).map_err(|_| {
            PublicationError::ArithmeticOverflow {
                at: "relocation source offset",
            }
        })?;
        let symbol =
            module
                .symbols()
                .get(relocation.symbol)
                .ok_or(PublicationError::InvalidModule {
                    at: "relocation target symbol",
                })?;
        let target_section =
            symbol
                .section
                .ok_or_else(|| PublicationError::RuntimeHelperRequired {
                    symbol: symbol.name.clone(),
                })?;
        let target_plan = sections
            .get(target_section)
            .ok_or(PublicationError::InvalidModule {
                at: "relocation target plan",
            })?;
        let symbol_offset =
            usize::try_from(symbol.offset).map_err(|_| PublicationError::ArithmeticOverflow {
                at: "relocation symbol offset",
            })?;
        let place = mapping_base
            .checked_add(source_plan.offset)
            .and_then(|value| value.checked_add(source_offset))
            .ok_or(PublicationError::ArithmeticOverflow {
                at: "relocation place address",
            })?;
        let symbol_address = mapping_base
            .checked_add(target_plan.offset)
            .and_then(|value| value.checked_add(symbol_offset))
            .ok_or(PublicationError::ArithmeticOverflow {
                at: "relocation symbol address",
            })?;
        if module.target().architecture == Architecture::Aarch64 {
            let target_start = mapping_base.checked_add(target_plan.offset).ok_or(
                PublicationError::ArithmeticOverflow {
                    at: "relocation target section address",
                },
            )?;
            let target_end = target_start
                .checked_add(module.sections()[target_section].data.len())
                .ok_or(PublicationError::ArithmeticOverflow {
                    at: "relocation target section extent",
                })?;
            let effective = i128::try_from(symbol_address)
                .expect("usize fits i128")
                .checked_add(i128::from(relocation.addend))
                .ok_or(PublicationError::ArithmeticOverflow {
                    at: "AArch64 effective relocation target",
                })?;
            let target_start = i128::try_from(target_start).expect("usize fits i128");
            let target_end = i128::try_from(target_end).expect("usize fits i128");
            if !(target_start..target_end).contains(&effective) {
                return Err(PublicationError::RelocationOutOfRange {
                    index,
                    kind: relocation.kind,
                });
            }
        }
        let source =
            staging
                .get_mut(relocation.section)
                .ok_or(PublicationError::InvalidModule {
                    at: "relocation staging section",
                })?;
        apply_relocation(
            index,
            relocation,
            source,
            source_offset,
            place,
            symbol_address,
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "keeping all five architecture fixups adjacent makes their shared bounds and opcode checks auditable"
)]
fn apply_relocation(
    index: usize,
    relocation: &ModuleRelocation,
    source: &mut [u8],
    offset: usize,
    place: usize,
    symbol: usize,
) -> Result<(), PublicationError> {
    let field_end = offset
        .checked_add(4)
        .ok_or(PublicationError::RelocationOutOfRange {
            index,
            kind: relocation.kind,
        })?;
    let field =
        source
            .get_mut(offset..field_end)
            .ok_or(PublicationError::RelocationOutOfRange {
                index,
                kind: relocation.kind,
            })?;
    let target = i128::try_from(symbol)
        .expect("usize fits i128")
        .checked_add(i128::from(relocation.addend))
        .ok_or(PublicationError::ArithmeticOverflow {
            at: "relocation target plus addend",
        })?;
    let target_address =
        usize::try_from(target).map_err(|_| PublicationError::RelocationOutOfRange {
            index,
            kind: relocation.kind,
        })?;
    let target = i128::try_from(target_address).expect("usize fits i128");
    let place = i128::try_from(place).expect("usize fits i128");
    match relocation.kind {
        RelocationKind::X86PcRelative32 | RelocationKind::X86PltRelative32 => {
            let delta = target
                .checked_sub(place)
                .ok_or(PublicationError::ArithmeticOverflow {
                    at: "x86 PC-relative relocation",
                })?;
            let value =
                i32::try_from(delta).map_err(|_| PublicationError::RelocationOutOfRange {
                    index,
                    kind: relocation.kind,
                })?;
            field.copy_from_slice(&value.to_le_bytes());
        }
        RelocationKind::Aarch64Page21 => {
            let target_page = target_address & !0xfff;
            let place_page = usize::try_from(place).expect("mapped place is nonnegative") & !0xfff;
            let pages = i128::try_from(target_page)
                .expect("usize fits i128")
                .checked_sub(i128::try_from(place_page).expect("usize fits i128"))
                .ok_or(PublicationError::ArithmeticOverflow {
                    at: "AArch64 page relocation",
                })?
                / 4096;
            if !(-(1_i128 << 20)..(1_i128 << 20)).contains(&pages) {
                return Err(PublicationError::RelocationOutOfRange {
                    index,
                    kind: relocation.kind,
                });
            }
            let mut word = u32::from_le_bytes(field.try_into().expect("four-byte field"));
            if word & 0x9f00_0000 != 0x9000_0000 {
                return Err(PublicationError::InvalidModule {
                    at: "AArch64 ADRP relocation opcode",
                });
            }
            let immediate = u32::try_from(pages & 0x1f_ffff).expect("signed 21-bit immediate");
            word &= !((0x3 << 29) | (0x7_ffff << 5));
            word |= (immediate & 0x3) << 29;
            word |= ((immediate >> 2) & 0x7_ffff) << 5;
            field.copy_from_slice(&word.to_le_bytes());
        }
        RelocationKind::Aarch64PageOff12 => {
            let mut word = u32::from_le_bytes(field.try_into().expect("four-byte field"));
            if word & 0xffc0_0000 != 0x9100_0000 {
                return Err(PublicationError::InvalidModule {
                    at: "AArch64 64-bit unshifted ADD-immediate relocation opcode",
                });
            }
            word &= !(0xfff << 10);
            word |= u32::try_from(target_address & 0xfff).expect("12-bit page offset") << 10;
            field.copy_from_slice(&word.to_le_bytes());
        }
        RelocationKind::Aarch64Branch26 => {
            let delta = target
                .checked_sub(place)
                .ok_or(PublicationError::ArithmeticOverflow {
                    at: "AArch64 branch relocation",
                })?;
            if delta % 4 != 0 {
                return Err(PublicationError::RelocationOutOfRange {
                    index,
                    kind: relocation.kind,
                });
            }
            let immediate = delta / 4;
            if !(-(1_i128 << 25)..(1_i128 << 25)).contains(&immediate) {
                return Err(PublicationError::RelocationOutOfRange {
                    index,
                    kind: relocation.kind,
                });
            }
            let mut word = u32::from_le_bytes(field.try_into().expect("four-byte field"));
            if word & 0xfc00_0000 != 0x1400_0000 {
                return Err(PublicationError::InvalidModule {
                    at: "AArch64 B relocation opcode",
                });
            }
            word &= !0x03ff_ffff;
            word |= u32::try_from(immediate & 0x03ff_ffff).expect("signed 26-bit immediate");
            field.copy_from_slice(&word.to_le_bytes());
        }
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "verification borrows the exact initialized readable mapping ranges planned and populated by this transaction"
)]
fn verify_copy(
    mapping: &platform::Mapping,
    sections: &[SectionPlan],
    staging: &[Box<[u8]>],
) -> Result<(), PublicationError> {
    for (section, expected) in sections.iter().zip(staging) {
        if section.mapped_bytes == 0 {
            continue;
        }
        // SAFETY: every section range is still RW/readable and initialized by
        // the preceding exact copy; the mapping remains exclusively owned.
        let actual = unsafe { mapping.bytes(section.offset, section.mapped_bytes) };
        if actual.get(..expected.len()) != Some(expected.as_ref())
            || !actual[expected.len()..].iter().all(|byte| *byte == 0)
        {
            return Err(PublicationError::CopyVerificationFailed);
        }
    }
    Ok(())
}

fn enforce(
    resource: PublicationResource,
    needed: usize,
    limit: usize,
) -> Result<(), PublicationError> {
    if needed > limit {
        return Err(PublicationError::Resource {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn align_up(value: usize, alignment: usize, at: &'static str) -> Result<usize, PublicationError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(PublicationError::InvalidModule { at })?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(PublicationError::ArithmeticOverflow { at })
}

fn system_error(
    stage: PublicationStage,
    errno: i32,
    executable_transition: bool,
) -> PublicationError {
    if executable_transition && matches!(errno, libc::EACCES | libc::EPERM) {
        PublicationError::JitDenied { stage, errno }
    } else {
        PublicationError::SystemCall { stage, errno }
    }
}

#[cfg(test)]
mod tests;
