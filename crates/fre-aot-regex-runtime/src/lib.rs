//! Stable runtime helper for general FRE AOT regex objects.
//!
//! Runtime-backed object entries have the C ABI
//! `entry(haystack, haystack_len, window_start, window_end, result_out)` and
//! tail-call [`fre_aot_regex_runtime_search_v1`] after inserting their
//! immutable program address as the first argument.
//!
//! For search calls, status `0` means no match, `1` means match, `2` means an
//! invalid null or misaligned pointer or invalid search window, and `3` means
//! a malformed program or runtime search failure. Prepared searches can also
//! return `4` when another search or a concurrent destroy owns the handle
//! state and `5` for an invalidated or unknown handle. On search status `0` or
//! `1`, `result_out` is initialized as follows:
//!
//! - `Exists`: both fields are zero; only status carries semantic information.
//! - `SelectedEnd`: both fields equal the selected match end.
//! - `Span`: the fields are the selected half-open match span.
//!
//! No result value is promised for status `2` through `5`. Lifecycle calls use
//! status `0` for success. All offsets are relative to the original haystack,
//! including when a sub-window is searched.
//!
//! Runtime-backed callers that search repeatedly can prepare an owned handle
//! once with [`fre_aot_regex_runtime_prepare_v1`], search it with
//! [`fre_aot_regex_runtime_search_prepared_v1`], and release it with
//! [`fre_aot_regex_runtime_destroy_prepared_v1`]. A handle owns its decoded
//! program and workspace; it never borrows the input artifact.
//!
//! Callers that can guarantee exclusive single-threaded ownership may instead
//! use [`fre_aot_regex_runtime_prepare_exclusive_v1`],
//! [`fre_aot_regex_runtime_search_exclusive_v1`], and
//! [`fre_aot_regex_runtime_destroy_exclusive_v1`]. That explicitly unsafe
//! lifecycle passes an opaque allocation pointer directly and therefore pays
//! no registry, reference-count, thread-local, or mutex cost per search.
//! Current compiler-emitted retained-row entries use
//! [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`] before
//! native rows execute. That call settles the prior local completion, runs
//! suffix then cut, and combines adaptive admission with exact-window handoff
//! or in-helper K0 completion. A compiler that proves its emitted vectorized
//! root scanner should own an admitted search can instead use
//! [`fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1`];
//! that authenticated call admits first and runs the portable proofs only on
//! a decline. If a native scan then reaches a partial-DFA hole, the current
//! compiler continues the same exclusive session through
//! [`fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2`].
//! Its single-use preflight ticket replaces repeated program and window
//! authentication and supplies pending mode from the compact canonical
//! resume-state index before K0 continues without replaying the prefix. The
//! fully authenticating
//! [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`] remains available
//! for older generated objects.
//! A resource-bounded slow compiler can keep a larger transient native prefix
//! outside the stable program format. Its V2 static-prefix preflight binds the
//! emitted exact frontier descriptor once; a native hole then consumes the
//! synchronous ticket through the compact static-prefix continuation without
//! replaying completed rows. Older V1 static-prefix objects remain supported.
//! A variable-width Span table that completes locally with only its selected
//! endpoint uses
//! [`fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1`] to
//! authenticate the preflight window and recover only the selected start.
//! A variable-width dynamic-row entry uses the parallel
//! [`fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1`]
//! postflight after selecting its authoritative endpoint natively. Mutable
//! rows and legacy V1/V2 headers authenticate a single-use preflight window;
//! an active immutable V3--V14 owner instead authenticates that same
//! reverse-only postflight directly and remains reusable after success.
//! [`fre_aot_regex_runtime_prepared_partial_should_enter_v1`] remains exported
//! only for compatibility with older generated objects.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(unsafe_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};

use fre_aot_regex::{
    CompileError, CompiledProgram, FrozenCompactLoopScanner, FrozenDynamicRowsStorageV3,
    FrozenPreparedHeaderV6, FullyPrefilledFallbackReceipt, MatchResult, OutputContract,
    PROGRAM_HEADER_LEN, ProgramFormatError, ProgramWorkspace, RetainedPartialPreflight,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAX_BYTES, SearchWindow,
};
#[cfg(test)]
use fre_aot_regex::{FrozenPreparedHeaderV2, FrozenPreparedHeaderV3};

/// No match was selected.
pub const STATUS_NO_MATCH: u32 = 0;
/// A match was selected and `result_out` was initialized.
pub const STATUS_MATCH: u32 = 1;
/// A pointer or search-window precondition was invalid.
pub const STATUS_INVALID_ARGUMENT: u32 = 2;
/// Program validation or portable execution failed.
pub const STATUS_RUNTIME_FAILURE: u32 = 3;
/// Another search or a concurrent destroy owns this handle's mutable state.
pub const STATUS_HANDLE_BUSY: u32 = 4;
/// A prepared handle was zero, unknown, destroyed, or concurrently invalidated.
pub const STATUS_INVALID_HANDLE: u32 = 5;
/// Native retained rows were admitted on the returned exact search window.
pub const STATUS_PARTIAL_PREFLIGHT_ENTER: u32 = 6;
/// Successful status for prepare and destroy lifecycle operations.
pub const STATUS_SUCCESS: u32 = 0;
/// Bytes in the exact SHA-256 semantic-artifact identity accepted by resume.
pub const ARTIFACT_IDENTITY_BYTES: usize = 32;
/// The prepared native retained-row entry should use the ordinary executor.
pub const PARTIAL_ENTRY_BYPASS: u32 = 0;
/// The prepared native retained-row entry should execute its authenticated rows.
pub const PARTIAL_ENTRY_ENTER: u32 = 1;

/// C declarations for the complete stable V1 runtime ABI.
///
/// The declarations use a process-local integer token rather than exposing a
/// Rust allocation address. Copying a token is allowed, but it is not a
/// security credential and becomes invalid after a successful destroy.
pub const C_API_V1_HEADER: &str = include_str!("../include/fre_aot_regex_runtime_v1.h");

/// C-layout result shared by runtime-backed and directly lowered AOT entries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexResultV1 {
    pub start: usize,
    pub end: usize,
}

/// C-layout exact search window returned to an admitted native retained table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexSearchWindowV1 {
    pub start: usize,
    pub end: usize,
}

/// Exact admitted window and identity-authenticated ordinary K0 rows.
///
/// This private record carries the immutable, process-unique workspace cache
/// identity separately. The `cache_generation` field name is retained for the
/// private V1 ABI layout, but the value is neither a mutable generation counter
/// nor a single-use ticket. V1, V2, and V3 producers initialize it for older
/// private callers. V4 and V5 leave it untouched; generated code instead
/// reloads the same identity from the trusted descriptor only on a continuation
/// side exit. The
/// descriptor and its exposed-provenance addresses are valid only for the
/// synchronous native scan admitted by this preflight and must not survive a
/// helper call or re-entry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexDynamicRowsPreflightV1 {
    pub start: usize,
    pub end: usize,
    pub native_rows_address: usize,
    pub cache_generation: u64,
}

/// Compiler-private V6 dynamic-row preflight return registers.
///
/// The two native words map to the ordinary C aggregate return registers:
/// RAX/RDX on x86-64 SysV and Darwin, and X0/X1 on AAPCS64. The descriptor is
/// nonzero only when `status` is [`STATUS_PARTIAL_PREFLIGHT_ENTER`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexDynamicRowsPreflightResultV6 {
    pub status: usize,
    pub native_rows_address: usize,
}

/// Compiler-private payload for one exact first-unpublished-cell handoff.
///
/// The exact admitted window remains in the search helper's ordinary arguments.
/// This record carries only the dynamic cache frontier and committed endpoint;
/// generated code allocates it in its synchronous call frame.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexDynamicRowsContinuationV1 {
    pub current_row: usize,
    pub resume_position: usize,
    /// Low bit: pending endpoint present. Upper bits: emitted root-scanner
    /// hits whose extra logical reads precede the unread DFA cell.
    pub pending_valid: usize,
    pub pending_end: usize,
    pub cache_identity: u64,
}

/// One selected half-open byte match borrowing its original haystack.
///
/// Offsets and [`Self::as_bytes`] always refer to the complete haystack used to
/// construct the match, whether through [`Self::from_span`],
/// [`PreparedAotRegex::find`], [`PreparedAotRegex::find_at`], or
/// [`PreparedAotRegex::find_iter`].
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AotMatch<'h> {
    haystack: &'h [u8],
    start: usize,
    end: usize,
}

impl<'h> AotMatch<'h> {
    /// Construct a borrowed match after checking its half-open span.
    ///
    /// Returns `None` unless `start <= end <= haystack.len()`.
    #[must_use]
    pub const fn from_span(haystack: &'h [u8], start: usize, end: usize) -> Option<Self> {
        if start <= end && end <= haystack.len() {
            Some(Self {
                haystack,
                start,
                end,
            })
        } else {
            None
        }
    }

    /// Start byte offset in the original haystack.
    #[must_use]
    pub const fn start(&self) -> usize {
        self.start
    }

    /// Exclusive end byte offset in the original haystack.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }

    /// Length of this match in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether this match contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Half-open byte range in the original haystack.
    #[must_use]
    pub const fn range(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }

    /// Bytes selected from the original haystack.
    #[must_use]
    pub fn as_bytes(&self) -> &'h [u8] {
        &self.haystack[self.start..self.end]
    }
}

impl std::fmt::Debug for AotMatch<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AotMatch")
            .field("start", &self.start())
            .field("end", &self.end())
            .field("bytes", &DebugMatchBytes(self.as_bytes()))
            .finish()
    }
}

struct DebugMatchBytes<'a>(&'a [u8]);

impl std::fmt::Debug for DebugMatchBytes<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("\"")?;
        let mut bytes = self.0;
        while !bytes.is_empty() {
            match std::str::from_utf8(bytes) {
                Ok(valid) => {
                    write_debug_match_str(formatter, valid)?;
                    bytes = &[];
                }
                Err(error) => {
                    let valid_up_to = error.valid_up_to();
                    let valid = std::str::from_utf8(&bytes[..valid_up_to])
                        .expect("UTF-8 error's valid prefix must decode");
                    write_debug_match_str(formatter, valid)?;
                    write!(formatter, r"\x{:02x}", bytes[valid_up_to])?;
                    bytes = &bytes[valid_up_to.saturating_add(1)..];
                }
            }
        }
        formatter.write_str("\"")
    }
}

fn write_debug_match_str(formatter: &mut std::fmt::Formatter<'_>, valid: &str) -> std::fmt::Result {
    for character in valid.chars() {
        match character {
            '\0' => formatter.write_str("\\0")?,
            '\u{1}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{19}' | '\u{7f}' => {
                write!(formatter, "\\x{:02x}", u32::from(character))?;
            }
            _ => write!(formatter, "{}", character.escape_debug())?,
        }
    }
    Ok(())
}

impl<'h> From<AotMatch<'h>> for &'h [u8] {
    fn from(matched: AotMatch<'h>) -> Self {
        matched.as_bytes()
    }
}

impl From<AotMatch<'_>> for std::ops::Range<usize> {
    fn from(matched: AotMatch<'_>) -> Self {
        matched.range()
    }
}

/// Failure while using a prepared artifact as a span finder.
#[derive(Debug)]
pub enum AotRegexFindError {
    /// The artifact was compiled for a result other than [`OutputContract::Span`].
    OutputContract { actual: OutputContract },
    /// The reusable semantic program rejected or failed a search.
    Search(CompileError),
}

impl std::fmt::Display for AotRegexFindError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutputContract { actual } => write!(
                formatter,
                "prepared AOT find requires Span output, artifact uses {actual:?}"
            ),
            Self::Search(error) => write!(formatter, "prepared AOT find failed: {error}"),
        }
    }
}

impl std::error::Error for AotRegexFindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OutputContract { .. } => None,
            Self::Search(error) => Some(error),
        }
    }
}

impl From<CompileError> for AotRegexFindError {
    fn from(value: CompileError) -> Self {
        Self::Search(value)
    }
}

/// Process-local opaque identifier for owned prepared runtime state.
///
/// The zero value is always invalid. Handles may be copied and sent between
/// threads, but a handle permits only one mutable search at a time. It is an
/// opaque lifecycle token, not an authentication secret.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct FreAotRegexPreparedHandleV1(u64);

impl FreAotRegexPreparedHandleV1 {
    /// The stable invalid/null handle representation.
    pub const INVALID: Self = Self(0);

    /// Return whether this is the invalid/null handle.
    #[must_use]
    pub const fn is_invalid(self) -> bool {
        self.0 == 0
    }
}

/// Exclusively owned prepared runtime state for the direct-pointer ABI.
///
/// The null value is invalid. Unlike [`FreAotRegexPreparedHandleV1`], this
/// handle must not be copied for concurrent use, sent to another thread while
/// a call is active, searched after destruction, or destroyed more than once.
/// Those lifecycle rules are safety preconditions rather than recoverable
/// status checks, which permits a synchronization-free hot path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct FreAotRegexExclusiveHandleV1(*mut std::ffi::c_void);

impl FreAotRegexExclusiveHandleV1 {
    /// The stable invalid/null handle representation.
    pub const INVALID: Self = Self(std::ptr::null_mut());

    /// Return whether this is the invalid/null handle.
    #[must_use]
    pub const fn is_invalid(self) -> bool {
        self.0.is_null()
    }
}

impl Default for FreAotRegexExclusiveHandleV1 {
    fn default() -> Self {
        Self::INVALID
    }
}

/// Owned, reusable runtime state for fair steady-state execution.
///
/// Construction validates and deserializes the artifact once and initializes
/// the program's fixed-capacity workspace once. Repeated [`Self::search`]
/// calls neither deserialize the program nor allocate executor workspace.
#[derive(Debug)]
#[repr(C)]
pub struct PreparedAotRegex {
    frozen_header: FrozenPreparedHeaderV6,
    program: CompiledProgram,
    workspace: ProgramWorkspace,
    frozen_dynamic_rows: Option<FrozenDynamicRowsStorageV3>,
    fully_prefilled_fallback: Option<FullyPrefilledFallbackReceipt>,
}

const _: () = assert!(std::mem::offset_of!(PreparedAotRegex, frozen_header) == 0);

// A complete compact sidecar is optional setup-only storage. Retain the
// established K0-size admission and independently bound its final immutable
// copy; larger programs keep the ordinary adaptive executor and one live
// workspace.
const FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES: usize = 512 * 1024;
const FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES: usize = 512 * 1024;

impl PreparedAotRegex {
    /// Validate, own, and prepare one serialized AOT semantic program.
    ///
    /// # Errors
    ///
    /// Returns a strict format error for malformed artifacts or a compiler
    /// error if fixed-capacity executor workspace cannot be prepared. No
    /// reference into `bytes` is retained.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PrepareError> {
        let program = CompiledProgram::deserialize(bytes).map_err(PrepareError::Format)?;
        Self::from_program(program)
    }

    fn from_program(program: CompiledProgram) -> Result<Self, PrepareError> {
        let mut workspace = program
            .prepare_workspace()
            .map_err(PrepareError::Workspace)?;
        let fully_prefilled_fallback = program
            .compiler_private_try_prefill_retained_fallback_with_workspace_receipt(&mut workspace)
            .map_err(PrepareError::Workspace)?;
        // A retained-partial receipt is still valuable to every ordinary or
        // continuation fallback, but it need not force the generated entry
        // to execute the older wide K0 projection. The header publishers keep
        // their established rule that a receipt wins when both candidates are
        // supplied; this runtime owner instead copies the compact projection
        // from that same completed live cache and presents only the compact
        // owner first. A compact construction or publication decline then
        // presents the retained receipt alone and recovers the established V1
        // capability. Every retained proof remains immutable until revocation.
        let mut frozen_dynamic_rows = program
            .compiler_private_frozen_dynamic_rows_storage_v3_with_fallback_receipt(
                &mut workspace,
                fully_prefilled_fallback,
                FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES,
                FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES,
            );
        let mut frozen_header = if frozen_dynamic_rows.is_some() {
            program.compiler_private_frozen_prepared_header_v6(
                &workspace,
                None,
                frozen_dynamic_rows.as_ref(),
            )
        } else {
            program.compiler_private_frozen_prepared_header_v6(
                &workspace,
                fully_prefilled_fallback,
                None,
            )
        };
        if frozen_dynamic_rows.is_some() && !frozen_header.has_dynamic_rows() {
            frozen_dynamic_rows = None;
            frozen_header = program.compiler_private_frozen_prepared_header_v6(
                &workspace,
                fully_prefilled_fallback,
                None,
            );
        }
        if !frozen_header.has_dynamic_rows() {
            frozen_dynamic_rows = None;
        }
        Ok(Self {
            frozen_header,
            program,
            workspace,
            frozen_dynamic_rows,
            fully_prefilled_fallback,
        })
    }

    #[inline]
    fn deactivate_frozen_header(&mut self) {
        debug_assert!(
            !self.frozen_header.has_dynamic_rows() || self.frozen_dynamic_rows.is_some(),
            "an active compact header must retain its immutable payload owner"
        );
        if self.frozen_header.is_active() {
            self.frozen_header.deactivate();
        }
    }

    /// Execute without re-deserializing or allocating executor workspace.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-window or portable executor failure.
    pub fn search(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .search_optimized_with_workspace(haystack, window, &mut self.workspace)
    }

    #[inline]
    fn search_exclusive(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .search_exclusive_optimized_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    receipt,
                )
        } else {
            self.program.search_exclusive_optimized_with_workspace(
                haystack,
                window,
                &mut self.workspace,
            )
        }
    }

    fn search_from_retained_partial_resume(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .search_from_retained_partial_resume_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    resume_state,
                    resume_position,
                    pending_end,
                    receipt,
                )
        } else {
            self.program.search_from_retained_partial_resume_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    fn search_from_preflight_retained_partial_resume(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .search_from_preflight_retained_partial_resume_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    resume_state,
                    resume_position,
                    pending_end,
                    receipt,
                )
        } else {
            self.program
                .search_from_preflight_retained_partial_resume_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    fn search_from_preflight_retained_partial_resume_ticket(
        &mut self,
        haystack: &[u8],
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .search_from_preflight_retained_partial_resume_ticket_with_fully_prefilled_fallback_workspace(
                    haystack,
                    &mut self.workspace,
                    resume_state,
                    resume_position,
                    pending_end,
                    receipt,
                )
        } else {
            self.program
                .search_from_preflight_retained_partial_resume_ticket_with_workspace(
                haystack,
                &mut self.workspace,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    fn search_from_preflight_retained_partial_resume_ticket_inferred(
        &mut self,
        haystack: &[u8],
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .search_from_preflight_retained_partial_resume_ticket_inferred_with_fully_prefilled_fallback_workspace(
                    haystack,
                    &mut self.workspace,
                    resume_state,
                    resume_position,
                    pending_end,
                    receipt,
                )
        } else {
            self.program
                .search_from_preflight_retained_partial_resume_ticket_inferred_with_workspace(
                haystack,
                &mut self.workspace,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    fn prepared_partial_should_enter(
        &mut self,
        input_bytes: usize,
    ) -> Result<bool, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .prepared_partial_should_enter_with_workspace(&mut self.workspace, input_bytes)
    }

    fn preflight_retained_partial(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<RetainedPartialPreflight, CompileError> {
        self.deactivate_frozen_header();
        self.program.preflight_retained_partial_with_workspace(
            haystack,
            window,
            &mut self.workspace,
            expected_artifact_identity,
        )
    }

    fn recover_retained_partial_span_from_selected_end(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .recover_retained_partial_span_from_selected_end_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                    receipt,
                )
        } else {
            self.program
                .recover_retained_partial_span_from_selected_end_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
                selected_end,
            )
        }
    }

    fn recover_static_prefix_span_from_selected_end(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .recover_static_prefix_span_from_selected_end_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                    receipt,
                )
        } else {
            self.program
                .recover_static_prefix_span_from_selected_end_with_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                )
        }
    }

    fn preflight_static_prefix_resume(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        descriptor_binding: usize,
        descriptor: &[u32],
    ) -> Result<RetainedPartialPreflight, CompileError> {
        self.deactivate_frozen_header();
        self.program.preflight_static_prefix_resume_with_workspace(
            haystack,
            window,
            &mut self.workspace,
            expected_artifact_identity,
            descriptor_binding,
            descriptor,
        )
    }

    fn search_from_static_prefix_resume_ticket(
        &mut self,
        haystack: &[u8],
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .search_from_static_prefix_resume_ticket_with_workspace(
                haystack,
                &mut self.workspace,
                resume_state,
                resume_position,
                pending_end,
            )
    }

    fn recover_bound_static_prefix_span_from_selected_end(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .recover_bound_static_prefix_span_from_selected_end_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
                selected_end,
            )
    }

    fn preflight_retained_partial_native_root(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<RetainedPartialPreflight, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .preflight_retained_partial_native_root_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
            )
    }

    fn preflight_dynamic_native_rows(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<(RetainedPartialPreflight, usize, u64), CompileError> {
        self.deactivate_frozen_header();
        self.program.preflight_dynamic_native_rows_with_workspace(
            haystack,
            window,
            &mut self.workspace,
            expected_artifact_identity,
        )
    }

    fn compiler_private_preflight_dynamic_native_rows_v3(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<(RetainedPartialPreflight, usize, u64), CompileError> {
        self.deactivate_frozen_header();
        self.program
            .compiler_private_preflight_dynamic_native_rows_v3_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
            )
    }

    fn search_after_dynamic_native_rows_deopt(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .search_after_dynamic_native_rows_deopt_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                self.fully_prefilled_fallback,
            )
    }

    fn settle_dynamic_native_rows_local_completion(&mut self) {
        self.deactivate_frozen_header();
        self.program
            .settle_dynamic_native_rows_local_completion_with_workspace(&mut self.workspace);
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the compiler-private continuation retains its full authentication payload"
    )]
    fn search_from_dynamic_native_rows_hole(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        continuation: FreAotRegexDynamicRowsContinuationV1,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .search_from_dynamic_native_rows_hole_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
                continuation.current_row,
                continuation.resume_position,
                continuation.pending_valid,
                continuation.pending_end,
                continuation.cache_identity,
            )
    }

    fn recover_dynamic_native_rows_span_from_selected_end(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> Result<MatchResult, CompileError> {
        // Mint the no-preflight mode before any legacy revocation. The token
        // proves an active V3--V14 header whose published row pointer matches
        // this exact immutable owner. Reverse K0 receives only `workspace`, a
        // disjoint field whose allocations were prepared independently from
        // every header and sidecar allocation.
        let compact_capability = self.frozen_dynamic_rows.as_ref().and_then(|owner| {
            self.frozen_header
                .compiler_private_active_span_capability(
                    owner,
                    expected_artifact_identity,
                )
        });
        let used_compact_capability = compact_capability.is_some();
        let recovered = if let Some(capability) = compact_capability {
            self.program
                .recover_frozen_dynamic_rows_span_from_selected_end_with_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                    capability,
                )
        } else {
            // Legacy V1/V2 and mutable dynamic rows retain the original
            // revoke-then-consume single-use preflight transaction.
            self.deactivate_frozen_header();
            self.program
                .recover_dynamic_native_rows_span_from_selected_end_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
                selected_end,
            )
        };
        if recovered.is_err() && used_compact_capability {
            // A rejected compact postflight cannot leave a reusable capability
            // behind for a later endpoint or fallback invocation.
            self.deactivate_frozen_header();
        }
        recovered
    }

    /// Find the first selected span in `haystack`.
    ///
    /// # Errors
    ///
    /// Returns an output-contract error unless this artifact was compiled for
    /// [`OutputContract::Span`], or a search error if execution fails.
    pub fn find<'h>(
        &mut self,
        haystack: &'h [u8],
    ) -> Result<Option<AotMatch<'h>>, AotRegexFindError> {
        self.find_at(haystack, 0)
    }

    /// Find the first selected span at or after `start` in the original
    /// `haystack`.
    ///
    /// Passing the complete haystack preserves absolute and contextual
    /// assertions while only the search window advances.
    ///
    /// # Errors
    ///
    /// Returns an output-contract error unless this artifact was compiled for
    /// [`OutputContract::Span`]. An out-of-bounds `start` and executor failures
    /// are returned as [`AotRegexFindError::Search`].
    pub fn find_at<'h>(
        &mut self,
        haystack: &'h [u8],
        start: usize,
    ) -> Result<Option<AotMatch<'h>>, AotRegexFindError> {
        self.require_span_output()?;
        self.find_span_at(haystack, start)
    }

    /// Iterate over non-overlapping byte matches in the original haystack.
    ///
    /// Empty matches use byte-wise progress and an empty match at the previous
    /// match end is suppressed, matching `regex::bytes::Regex::find_iter`.
    /// The iterator exclusively borrows this prepared matcher so its reusable
    /// workspace remains attached for the complete iteration.
    ///
    /// # Errors
    ///
    /// Returns an output-contract error unless this artifact was compiled for
    /// [`OutputContract::Span`]. Execution failures are yielded by the
    /// iterator, which becomes fused after its first failure.
    pub fn find_iter<'p, 'h>(
        &'p mut self,
        haystack: &'h [u8],
    ) -> Result<PreparedAotMatches<'p, 'h>, AotRegexFindError> {
        self.require_span_output()?;
        Ok(PreparedAotMatches {
            prepared: self,
            haystack,
            start: 0,
            last_match_end: None,
            pending_empty_progress: false,
            finished: false,
        })
    }

    fn scan_frozen_loop(&self, scanner_address: usize, source: &[u8]) -> Option<usize> {
        if !self.frozen_header.is_active() || !self.frozen_header.has_dynamic_rows() {
            return None;
        }
        let artifact_identity = *self.frozen_header.artifact_identity();
        self.frozen_dynamic_rows
            .as_ref()?
            .compiler_private_scan_frozen_loop(artifact_identity, scanner_address, source)
    }

    fn require_span_output(&self) -> Result<(), AotRegexFindError> {
        let actual = self.program.output_contract();
        if actual == OutputContract::Span {
            Ok(())
        } else {
            Err(AotRegexFindError::OutputContract { actual })
        }
    }

    fn find_span_at<'h>(
        &mut self,
        haystack: &'h [u8],
        start: usize,
    ) -> Result<Option<AotMatch<'h>>, AotRegexFindError> {
        let result = self
            .search(haystack, SearchWindow::new(start, haystack.len()))
            .map_err(AotRegexFindError::Search)?;
        let MatchResult::Span(span) = result else {
            return Err(AotRegexFindError::OutputContract {
                actual: self.program.output_contract(),
            });
        };
        span.map(|(match_start, match_end)| {
            if match_start < start {
                return Err(AotRegexFindError::Search(CompileError::InternalInvariant(
                    "span program returned a match before its search start",
                )));
            }
            AotMatch::from_span(haystack, match_start, match_end).ok_or(AotRegexFindError::Search(
                CompileError::InternalInvariant(
                    "span program returned a match outside its haystack",
                ),
            ))
        })
        .transpose()
    }
}

/// Failure result returned by the fully validating private V1 loop helper.
///
/// Current generated code calls the trusted V2 helper and still compares its
/// result with the unchanged requested length before advancing position. Older
/// V1 callers observe this sentinel after any recoverable boundary failure.
pub const FROZEN_LOOP_SCAN_FAILURE: usize = usize::MAX;

/// Scan one immutable graph-proved loop member prefix.
///
/// This is a private generated-object ABI. The opaque scanner address is never
/// dereferenced directly: it must match the exact pointer retained by the live
/// prepared handle, whose artifact identity and active header are checked by
/// the safe owner method. A mismatch, panic, invalid extent, or inactive owner
/// returns [`FROZEN_LOOP_SCAN_FAILURE`].
///
/// # Safety
///
/// `handle` must name the live exclusive prepared session that entered the
/// generated matcher. `source_ptr` must be non-null and readable for exactly
/// `source_len` bytes during this call. No mutable operation may overlap the
/// call or release either owner.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the generated loop helper validates its raw handle and source at the C ABI boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_scan_frozen_loop_v1(
    handle: FreAotRegexExclusiveHandleV1,
    scanner_address: usize,
    source_ptr: *const u8,
    source_len: usize,
) -> usize {
    if handle.is_invalid()
        || scanner_address == 0
        || source_ptr.is_null()
        || source_len > isize::MAX.unsigned_abs()
    {
        return FROZEN_LOOP_SCAN_FAILURE;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the function contract supplies both live extents. The
        // prepared owner validates the opaque scanner address before following
        // its own independently retained pointer.
        let prepared = unsafe { &*handle.0.cast::<PreparedAotRegex>() };
        // SAFETY: the caller guarantees this exact readable source extent.
        let source = unsafe { std::slice::from_raw_parts(source_ptr, source_len) };
        prepared
            .scan_frozen_loop(scanner_address, source)
            .filter(|&consumed| consumed <= source_len)
            .unwrap_or(FROZEN_LOOP_SCAN_FAILURE)
    }))
    .unwrap_or(FROZEN_LOOP_SCAN_FAILURE)
}

/// Scan one already-authenticated immutable loop member prefix.
///
/// This private V2 generated-object ABI deliberately takes no prepared handle.
/// Generated V6/V7 code has already authenticated the exclusive active
/// capability, selected an in-range frozen plan, checked the plan's canonical
/// state against the live table key, and loaded the non-null scanner address
/// published by that immutable owner. Omitting the handle prevents repeating
/// owner/header/identity/plan-list validation and panic framing inside every
/// profitable loop scan. The source pointer is first in this private ABI so
/// both supported ISAs can form it in place while retaining the authenticated
/// scanner in their second argument register.
///
/// The V1 helper remains the fully validating boundary for older generated
/// objects and callers that do not carry the active-capability proof.
///
/// # Safety
///
/// `scanner` must be non-null, aligned, and point to the exact
/// [`FrozenCompactLoopScanner`] retained by the live exclusive prepared owner
/// whose V6/V7 capability was authenticated by the calling generated entry.
/// That owner must remain exclusively live and immutable for the complete
/// call. `source_ptr` must be non-null and readable for exactly `source_len`
/// bytes, `source_len` must not exceed `isize::MAX`, and the extent must remain
/// live for the complete call. Violating this trusted private ABI is undefined
/// behavior.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "authenticated generated code supplies one typed immutable scanner and exact readable source extent"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_scan_frozen_loop_v2(
    source_ptr: *const u8,
    scanner: *const FrozenCompactLoopScanner,
    source_len: usize,
) -> usize {
    // SAFETY: the private V2 contract supplies the exact live typed owner and
    // readable byte extent. `scan_prefix` is total for every byte sequence and
    // returns a value no greater than the supplied source length.
    let scanner = std::ptr::with_exposed_provenance::<FrozenCompactLoopScanner>(scanner.addr());
    let scanner = unsafe { &*scanner };
    // SAFETY: guaranteed by the same private V2 contract.
    let source = unsafe { std::slice::from_raw_parts(source_ptr, source_len) };
    scanner.scan_prefix(source)
}

/// Fallible iterator over non-overlapping matches from a prepared AOT Span
/// artifact.
#[derive(Debug)]
pub struct PreparedAotMatches<'p, 'h> {
    prepared: &'p mut PreparedAotRegex,
    haystack: &'h [u8],
    start: usize,
    last_match_end: Option<usize>,
    pending_empty_progress: bool,
    finished: bool,
}

impl PreparedAotMatches<'_, '_> {
    fn fail<'h>(&mut self, error: AotRegexFindError) -> Result<AotMatch<'h>, AotRegexFindError> {
        self.finished = true;
        Err(error)
    }

    fn advance_past_repeated_empty(&mut self) -> bool {
        if self.start == self.haystack.len() {
            self.finished = true;
            return false;
        }
        self.start = self.start.saturating_add(1);
        true
    }
}

impl<'h> Iterator for PreparedAotMatches<'_, 'h> {
    type Item = Result<AotMatch<'h>, AotRegexFindError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished {
            if self.pending_empty_progress {
                self.pending_empty_progress = false;
                if !self.advance_past_repeated_empty() {
                    return None;
                }
            }

            let matched = match self.prepared.find_span_at(self.haystack, self.start) {
                Ok(Some(matched)) => matched,
                Ok(None) => {
                    self.finished = true;
                    return None;
                }
                Err(error) => return Some(self.fail(error)),
            };

            if matched.is_empty() && self.last_match_end == Some(matched.end()) {
                if !self.advance_past_repeated_empty() {
                    return None;
                }
                continue;
            }

            self.start = matched.end();
            self.last_match_end = Some(matched.end());
            self.pending_empty_progress = matched.is_empty();
            return Some(Ok(matched));
        }
        None
    }
}

impl std::iter::FusedIterator for PreparedAotMatches<'_, '_> {}

struct PreparedHandleState {
    prepared: Mutex<Option<PreparedAotRegex>>,
}

struct PreparedRegistry {
    next_token: u64,
    entries: HashMap<u64, Arc<PreparedHandleState>>,
}

impl PreparedRegistry {
    fn new() -> Self {
        Self {
            next_token: 1,
            entries: HashMap::new(),
        }
    }

    fn insert(&mut self, prepared: PreparedAotRegex) -> Result<FreAotRegexPreparedHandleV1, ()> {
        let token = self.next_token;
        let Some(next_token) = token.checked_add(1) else {
            return Err(());
        };
        if token == 0 || self.entries.contains_key(&token) {
            return Err(());
        }
        self.next_token = next_token;
        self.entries.insert(
            token,
            Arc::new(PreparedHandleState {
                prepared: Mutex::new(Some(prepared)),
            }),
        );
        Ok(FreAotRegexPreparedHandleV1(token))
    }
}

fn prepared_registry() -> &'static Mutex<PreparedRegistry> {
    static REGISTRY: OnceLock<Mutex<PreparedRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(PreparedRegistry::new()))
}

fn prepared_entry(
    handle: FreAotRegexPreparedHandleV1,
) -> Result<Option<Arc<PreparedHandleState>>, ()> {
    prepared_registry()
        .lock()
        .map(|registry| registry.entries.get(&handle.0).cloned())
        .map_err(|_| ())
}

thread_local! {
    /// One bounded per-thread registry hit. Repeated searches normally use one
    /// prepared program, so retaining its state owner removes the global map
    /// mutex and `Arc` increment from the hot path. Tokens are never reused,
    /// and destroy clears the state behind every retained owner before it
    /// returns, so a cached entry cannot revive an invalidated handle.
    static PREPARED_ENTRY_CACHE: RefCell<Option<(u64, Arc<PreparedHandleState>)>> =
        const { RefCell::new(None) };
}

fn with_cached_prepared_entry<T>(
    handle: FreAotRegexPreparedHandleV1,
    use_entry: impl FnOnce(&PreparedHandleState) -> T,
) -> Result<Option<T>, ()> {
    PREPARED_ENTRY_CACHE
        .try_with(|cache| {
            let mut cache = cache.try_borrow_mut().map_err(|_| ())?;
            if cache.as_ref().is_none_or(|(token, _)| *token != handle.0) {
                let Some(entry) = prepared_entry(handle)? else {
                    return Ok(None);
                };
                *cache = Some((handle.0, entry));
            }
            Ok(cache.as_ref().map(|(_, entry)| use_entry(entry.as_ref())))
        })
        .map_err(|_| ())?
}

fn remove_prepared_entry(
    handle: FreAotRegexPreparedHandleV1,
) -> Result<Option<Arc<PreparedHandleState>>, ()> {
    prepared_registry()
        .lock()
        .map(|mut registry| registry.entries.remove(&handle.0))
        .map_err(|_| ())
}

fn register_prepared(prepared: PreparedAotRegex) -> Result<FreAotRegexPreparedHandleV1, ()> {
    prepared_registry().lock().map_err(|_| ())?.insert(prepared)
}

/// Failure while constructing owned reusable runtime state.
#[derive(Debug)]
pub enum PrepareError {
    Format(ProgramFormatError),
    Workspace(CompileError),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(error) => write!(formatter, "program preparation failed: {error}"),
            Self::Workspace(error) => write!(formatter, "workspace preparation failed: {error}"),
        }
    }
}

impl std::error::Error for PrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::Workspace(error) => Some(error),
        }
    }
}

/// Validate, own, and prepare one exact serialized program for repeated C ABI
/// searches.
///
/// On status [`STATUS_SUCCESS`], `handle_out` is initialized to a new
/// process-local handle and the caller may immediately release or reuse the
/// source bytes. On every failure status, `handle_out` is left untouched.
///
/// # Thread safety
///
/// Preparation is thread-safe. The returned token may be copied to other
/// threads, subject to the exclusive-search contract documented on
/// [`fre_aot_regex_runtime_search_prepared_v1`].
///
/// # Safety
///
/// `program_ptr` must be non-null and readable for exactly `program_len`
/// bytes for this call; that extent must reside in one allocated object and be
/// no larger than `isize::MAX`. `handle_out` must be non-null, properly
/// aligned, and writable for one [`FreAotRegexPreparedHandleV1`]. The output
/// storage must not overlap the program extent.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepare_v1(
    program_ptr: *const u8,
    program_len: usize,
    handle_out: *mut FreAotRegexPreparedHandleV1,
) -> u32 {
    if program_ptr.is_null()
        || handle_out.is_null()
        || !handle_out.is_aligned()
        || program_len > isize::MAX.unsigned_abs()
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the function contract supplies the readable source extent and
    // aligned, writable, non-overlapping output. The checked helper borrows
    // the source only for deserialization and writes the output last.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        prepare_checked_pointers(program_ptr, program_len, handle_out)
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

#[allow(
    unsafe_code,
    reason = "slice construction and the final disjoint handle write are confined to this audited helper"
)]
unsafe fn prepare_checked_pointers(
    program_ptr: *const u8,
    program_len: usize,
    handle_out: *mut FreAotRegexPreparedHandleV1,
) -> u32 {
    // SAFETY: guaranteed by the exported prepare contract and checked length.
    let program_bytes = unsafe { std::slice::from_raw_parts(program_ptr, program_len) };
    let Ok(prepared) = PreparedAotRegex::deserialize(program_bytes) else {
        return STATUS_RUNTIME_FAILURE;
    };
    let Ok(handle) = register_prepared(prepared) else {
        return STATUS_RUNTIME_FAILURE;
    };
    // SAFETY: guaranteed aligned, writable, and disjoint by the exported
    // prepare contract. No borrow of `program_bytes` survives preparation.
    unsafe { handle_out.write(handle) };
    STATUS_SUCCESS
}

/// Validate, own, and prepare one serialized program as an exclusively owned
/// direct-pointer session.
///
/// On success, `handle_out` receives a non-null handle and the source bytes
/// may immediately be released. Unlike the registry-backed prepared ABI, the
/// returned handle has no recoverable stale-handle or concurrent-use checks.
///
/// # Safety
///
/// The pointer requirements are identical to
/// [`fre_aot_regex_runtime_prepare_v1`]. After success, the caller must retain
/// exclusive ownership of the returned handle, pass it only to the exclusive
/// search and destroy functions, and destroy it exactly once.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepare_exclusive_v1(
    program_ptr: *const u8,
    program_len: usize,
    handle_out: *mut FreAotRegexExclusiveHandleV1,
) -> u32 {
    if program_ptr.is_null()
        || handle_out.is_null()
        || !handle_out.is_aligned()
        || program_len > isize::MAX.unsigned_abs()
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the function contract supplies the readable source extent and
    // aligned, writable, non-overlapping output.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let program_bytes = std::slice::from_raw_parts(program_ptr, program_len);
        let Ok(prepared) = PreparedAotRegex::deserialize(program_bytes) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let allocation = Box::into_raw(Box::new(prepared)).cast::<std::ffi::c_void>();
        handle_out.write(FreAotRegexExclusiveHandleV1(allocation));
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Search an owned prepared program without reconstructing it or allocating
/// executor workspace.
///
/// Status and result conventions are identical to
/// [`fre_aot_regex_runtime_search_v1`]. Additionally,
/// [`STATUS_HANDLE_BUSY`] reports overlapping mutable searches or a destroy
/// that has acquired the handle state, and
/// [`STATUS_INVALID_HANDLE`] reports a zero, unknown, destroyed, or
/// concurrently invalidated handle. Every failure leaves `result_ptr`
/// untouched.
///
/// # Thread safety
///
/// Tokens may be passed between threads, but the workspace is mutable and
/// exclusive: at most one search per handle may execute at a time. Overlap is
/// rejected without waiting. Different handles may search concurrently.
/// Destroy waits for a search that already acquired the handle. A search
/// racing with destroy can complete first, observe [`STATUS_INVALID_HANDLE`],
/// or observe [`STATUS_HANDLE_BUSY`] while destroy owns the state mutex.
///
/// # Safety
///
/// `haystack_ptr` must be non-null and readable for `haystack_len` bytes for
/// this call. `result_ptr` must be non-null, properly aligned, and writable
/// for one [`FreAotRegexResultV1`]. The two extents must not overlap, each
/// extent must reside in one allocated object, and `haystack_len` must be no
/// greater than `isize::MAX`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_prepared_v1(
    handle: FreAotRegexPreparedHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the function contract supplies the readable haystack and
    // aligned, writable, non-overlapping result extent.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        search_prepared_checked_pointers(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
        )
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

#[allow(
    unsafe_code,
    reason = "slice construction and the final disjoint result write are confined to this audited helper"
)]
unsafe fn search_prepared_checked_pointers(
    handle: FreAotRegexPreparedHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    let searched = with_cached_prepared_entry(handle, |entry| {
        let mut state = match entry.prepared.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(STATUS_HANDLE_BUSY),
            Err(TryLockError::Poisoned(_)) => return Err(STATUS_RUNTIME_FAILURE),
        };
        let Some(prepared) = state.as_mut() else {
            return Err(STATUS_INVALID_HANDLE);
        };
        // SAFETY: guaranteed by the exported prepared-search contract and
        // checked length.
        let haystack = unsafe { std::slice::from_raw_parts(haystack_ptr, haystack_len) };
        execute_search(prepared, haystack, window_start, window_end)
            .map_err(|_| STATUS_RUNTIME_FAILURE)
    });
    let (status, result) = match searched {
        Ok(Some(Ok(found))) => found,
        Ok(Some(Err(status))) => return status,
        Ok(None) => return STATUS_INVALID_HANDLE,
        Err(()) => return STATUS_RUNTIME_FAILURE,
    };
    // SAFETY: guaranteed aligned, writable, and disjoint by the exported
    // prepared-search contract.
    unsafe { result_ptr.write(result) };
    status
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicNativeRowsFallbackOutcome {
    LocalCompletion,
    Deopt,
}

#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the shared implementation validates and executes one raw exclusive-search ABI"
)]
fn search_exclusive_with_dynamic_rows_outcome(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    dynamic_rows_outcome: DynamicNativeRowsFallbackOutcome,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: each exported caller requires the live exclusively owned
    // session plus readable haystack and writable disjoint result extents.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let searched = match dynamic_rows_outcome {
            DynamicNativeRowsFallbackOutcome::LocalCompletion => {
                prepared.settle_dynamic_native_rows_local_completion();
                prepared.search_exclusive(
                    haystack,
                    SearchWindow::new(window_start, window_end),
                )
            }
            DynamicNativeRowsFallbackOutcome::Deopt => prepared
                .search_after_dynamic_native_rows_deopt(
                    haystack,
                    SearchWindow::new(window_start, window_end),
                ),
        };
        let Ok(found) = searched else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Search an exclusively owned direct-pointer prepared session.
///
/// Status and result conventions are identical to
/// [`fre_aot_regex_runtime_search_v1`]. This path performs no registry lookup,
/// reference counting, thread-local access, or synchronization.
///
/// # Safety
///
/// `handle` must be a live value returned by
/// [`fre_aot_regex_runtime_prepare_exclusive_v1`], with no overlapping search
/// or destroy call on any copy. It must not have been destroyed. Haystack and
/// result pointer requirements are identical to
/// [`fre_aot_regex_runtime_search_prepared_v1`].
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    search_exclusive_with_dynamic_rows_outcome(
        handle,
        haystack_ptr,
        haystack_len,
        window_start,
        window_end,
        result_ptr,
        DynamicNativeRowsFallbackOutcome::LocalCompletion,
    )
}

/// Authenticate one compiler-owned static native prefix search.
///
/// This compiler-private entry validates the ordinary exclusive-search
/// boundary and binds generated code to the exact prepared artifact. It does
/// not inspect or mutate executor workspace state: on success the caller may
/// run its immutable native prefix over the unchanged search window. A native
/// hole must leave generated code and complete the same whole search through
/// [`fre_aot_regex_runtime_search_exclusive_v1`].
///
/// The helper is deliberately independent of serialized retained-DFA rows.
/// Optimizing compilation can therefore publish a transient, resource-bounded
/// native prefix without adding pattern-specific state to the stable program
/// format or rebuilding a runtime on every hole.
///
/// # Safety
///
/// `handle` must satisfy the exclusive ownership contract of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. Haystack and result extents
/// have the same requirements. `expected_artifact_identity_ptr` must address
/// exactly [`ARTIFACT_IDENTITY_BYTES`] readable bytes and be disjoint from the
/// writable result for the duration of the call.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compiler-private static-prefix boundary authenticates raw generated-code arguments"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned allocation and
    // every readable/writable extent documented above. Reading the immutable
    // header does not claim or alter any mutable prepared-workspace capability.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &*handle.0.cast::<PreparedAotRegex>();
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        if expected_artifact_identity != *prepared.frozen_header.artifact_identity() {
            return STATUS_RUNTIME_FAILURE;
        }
        STATUS_PARTIAL_PREFLIGHT_ENTER
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Bind an exact compiler-owned static-prefix frontier descriptor and admit
/// one synchronous native search window.
///
/// Unlike V1, this preflight retains the transient frontiers that correspond
/// to every native hole. The first call graph-binds that immutable descriptor
/// to the prepared K0 program; later calls reuse the bound resume set and only
/// refresh a single-use haystack/window ticket. Generated code must consume
/// that ticket through either the matching continuation or Span postflight.
///
/// This private object/runtime seam is intentionally absent from the public C
/// header. The descriptor is object data, not stable serialized-program data.
///
/// # Safety
///
/// The handle, haystack, result, and identity requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1`].
/// `descriptor_ptr` must be aligned for `u32` and address a readable canonical
/// V1 descriptor whose fixed header declares its complete readable extent.
/// That extent must not overlap writable result storage and must remain live
/// for the lifetime of the prepared handle because its address is the private
/// binding capability.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compiler-private static-prefix boundary binds generated object data and an exact call"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    descriptor_ptr: *const u32,
) -> u32 {
    const HEADER_WORDS: usize =
        STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / std::mem::size_of::<u32>();

    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || descriptor_ptr.is_null()
        || !descriptor_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller supplies the live exclusive owner and every extent
    // documented above. The bounded fixed-header read precedes construction
    // of the complete descriptor slice, whose declared size is capped before
    // that slice is formed.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let header = std::slice::from_raw_parts(descriptor_ptr, HEADER_WORDS);
        let Ok(total_words) = usize::try_from(header[2]) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let Some(total_bytes) = total_words.checked_mul(std::mem::size_of::<u32>()) else {
            return STATUS_RUNTIME_FAILURE;
        };
        if total_words < HEADER_WORDS
            || total_bytes > STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAX_BYTES
        {
            return STATUS_RUNTIME_FAILURE;
        }
        let descriptor = std::slice::from_raw_parts(descriptor_ptr, total_words);
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let Ok(preflight) = prepared.preflight_static_prefix_resume(
            haystack,
            SearchWindow::new(window_start, window_end),
            expected_artifact_identity,
            descriptor_ptr.addr(),
            descriptor,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        match preflight {
            RetainedPartialPreflight::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                status
            }
            RetainedPartialPreflight::Enter(admitted) => {
                debug_assert_eq!(admitted, SearchWindow::new(window_start, window_end));
                STATUS_PARTIAL_PREFLIGHT_ENTER
            }
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue an admitted static native prefix from its exact K0 frontier and
/// first unconsumed byte.
///
/// This compact private ABI consumes the single-use ticket created by V2
/// preflight. Pending mode is authenticated from the bound frontier set; the
/// final word carries the pending endpoint only when that mode is active.
///
/// # Safety
///
/// The handle, haystack, and result requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. The caller must be the
/// generated native entry that received [`STATUS_PARTIAL_PREFLIGHT_ENTER`]
/// from V2 preflight for this exact haystack and must pass a state, position,
/// and pending endpoint emitted by that native prefix.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compact continuation carries one exact native frontier payload"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    result_ptr: *mut FreAotRegexResultV1,
    resume_state: usize,
    resume_position: usize,
    pending_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the generated caller guarantees the exclusive owner and the
    // readable/writable disjoint extents documented above. Program-side
    // ticket consumption authenticates the exact haystack and resume payload.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let Ok(found) = prepared.search_from_static_prefix_resume_ticket(
            haystack,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Recover a Span start after a compiler-owned static prefix selected its
/// authoritative endpoint.
///
/// The generated caller must invoke this synchronously after a successful
/// static-prefix preflight and native forward completion over the same exact
/// window. Reverse K0 recovers only the start; it does not replay the forward
/// search. This compiler-private seam is deliberately absent from the public
/// C header.
///
/// # Safety
///
/// The handle, haystack, result, and identity requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1`].
/// `selected_end` must be the endpoint produced by the synchronous native
/// prefix and lie after `window_start` and at or before `window_end`.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compiler-private static-prefix postflight authenticates raw generated-code arguments"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    selected_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || selected_end <= window_start
        || selected_end > window_end
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned allocation and
    // every readable/writable disjoint extent documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let Ok(MatchResult::Span(Some((start, end)))) = prepared
            .recover_static_prefix_span_from_selected_end(
                haystack,
                SearchWindow::new(window_start, window_end),
                expected_artifact_identity,
                selected_end,
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(FreAotRegexResultV1 { start, end });
        STATUS_MATCH
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Recover a Span start from the exact frontier set bound by V2 static-prefix
/// preflight.
///
/// This V2 postflight consumes the same single-use ticket as the continuation
/// helper. It authenticates the original window and reuses the graph-bound
/// resume set (and any setup-time full-prefill receipt) for reverse-only K0.
///
/// # Safety
///
/// The raw pointer requirements are identical to the V1 Span postflight. The
/// generated caller must invoke this synchronously after V2 preflight and a
/// native completion over the same exact window.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the V2 static-prefix postflight authenticates the admitted ticket and endpoint"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    selected_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || selected_end <= window_start
        || selected_end > window_end
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the generated caller guarantees one live exclusive allocation
    // and every readable/writable disjoint extent documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let Ok(MatchResult::Span(Some((start, end)))) = prepared
            .recover_bound_static_prefix_span_from_selected_end(
                haystack,
                SearchWindow::new(window_start, window_end),
                expected_artifact_identity,
                selected_end,
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(FreAotRegexResultV1 { start, end });
        STATUS_MATCH
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Compiler-private capability and side exit for a frozen prepared root.
///
/// Future generated direct entries link this distinct symbol instead of a V1
/// legacy search helper. Its presence proves that the runtime allocation begins
/// with the matching versioned header. Entering the helper permanently clears
/// that header's direct-use seal before authenticating the emitted artifact or
/// touching mutable workspace state. Thus a wrong-artifact side exit also
/// retires the projection and leaves the result untouched.
///
/// This symbol is intentionally absent from [`C_API_V1_HEADER`]. Linking a
/// frozen-entry object against an older runtime therefore fails closed.
///
/// # Safety
///
/// `handle` must satisfy the exclusive ownership contract of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. The haystack and result
/// extents have the same requirements. `expected_artifact_identity_ptr` must
/// address exactly [`ARTIFACT_IDENTITY_BYTES`] readable bytes, disjoint from
/// writable output, for the duration of the call.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compiler-private frozen fallback authenticates one exact artifact and search window"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned allocation and
    // all readable/writable disjoint extents documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        prepared.deactivate_frozen_header();
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        if expected_artifact_identity != *prepared.frozen_header.artifact_identity() {
            return STATUS_RUNTIME_FAILURE;
        }
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let Ok((status, result)) =
            execute_exclusive_search(prepared, haystack, window_start, window_end)
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue a genuine whole-search side exit from the generated dynamic-row
/// scanner. This private compiler/runtime seam has the same raw ABI and
/// semantic result contract as [`fre_aot_regex_runtime_search_exclusive_v1`],
/// but records adaptive deopt feedback instead of settling a prior local
/// native completion. Its admission ticket also preserves any already-run
/// mandatory cut and the original input-length profitability basis, so the
/// fallback starts at the exact admitted window without replaying that cut.
///
/// # Safety
///
/// Requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. The caller must use this
/// helper only after the authenticated dynamic-row preflight admitted the
/// same exclusive search transaction.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this private generated-code symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_dynamic_rows_deopt_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    search_exclusive_with_dynamic_rows_outcome(
        handle,
        haystack_ptr,
        haystack_len,
        window_start,
        window_end,
        result_ptr,
        DynamicNativeRowsFallbackOutcome::Deopt,
    )
}

/// Continue the exact first unpublished cell of a dynamically warmed native
/// row scan without replaying its completed scalar prefix.
///
/// The helper consumes the admitted preflight window before authenticating
/// the artifact, cache, row, unread position, endpoint, and current unfilled
/// cell. A stale or malformed payload completes through the established
/// whole-window deopt path; a valid payload continues in K0 and settles as a
/// local completion.
///
/// # Safety
///
/// The handle, haystack, and result requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_v1`].
/// `expected_artifact_identity_ptr` must address exactly
/// [`ARTIFACT_IDENTITY_BYTES`] readable bytes. `continuation_ptr` must be
/// non-null, aligned, readable, and disjoint from `result_ptr` for the
/// synchronous call. The helper is compiler-private and may be called only by
/// the generated entry that owns the immediately preceding dynamic preflight.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this private generated-code symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    continuation_ptr: *const FreAotRegexDynamicRowsContinuationV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || continuation_ptr.is_null()
        || !continuation_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees the live exclusive session and all
    // readable/disjoint writable extents documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let continuation = continuation_ptr.read();
        let Ok(found) = prepared.search_from_dynamic_native_rows_hole(
            haystack,
            SearchWindow::new(window_start, window_end),
            expected_artifact_identity,
            continuation,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Recover a variable-width Span start after an authenticated dynamic-row
/// scan selected only its authoritative endpoint.
///
/// For mutable rows or legacy V1/V2 headers, the exact
/// `window_start..window_end` must be the single-use window admitted by the
/// immediately preceding successful dynamic-row preflight on this exclusive
/// session. An active immutable V3--V14 header may instead authorize the
/// synchronous endpoint selected from its exact frozen owner, without a
/// preflight ticket. The artifact must be an assertion-free, non-nullable,
/// variable-width ordered-NFA Span program, and `selected_end` must lie
/// strictly after the window start and at or before its end. Reverse K0
/// recovers only the start; the forward search is not replayed. Successful
/// immutable recovery retains the header, while every rejection revokes it.
///
/// On success this function returns [`STATUS_MATCH`] and initializes
/// `result_ptr` with the exact Span. Every rejection returns an error status
/// and leaves `result_ptr` untouched.
///
/// # Safety
///
/// The handle, haystack, result, and identity pointer requirements are the
/// same as for
/// [`fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1`]. The
/// caller must pass the exact admitted window and the endpoint produced by its
/// synchronous native scan. No overlapping call or destroy may use any copy
/// of `handle`.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this private generated-code postflight authenticates the exact dynamic admission and endpoint"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    selected_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || selected_end <= window_start
        || selected_end > window_end
    {
        // A non-null exclusive handle is a live allocation by this unsafe
        // API's contract. Even a malformed postflight payload must revoke a
        // possibly active compact capability before the caller can fall back
        // or retry with another endpoint.
        unsafe { &mut *handle.0.cast::<PreparedAotRegex>() }.deactivate_frozen_header();
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned session plus
    // all readable and writable disjoint extents described above.
    let status = catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let Ok(MatchResult::Span(Some((start, end)))) = prepared
            .recover_dynamic_native_rows_span_from_selected_end(
                haystack,
                SearchWindow::new(window_start, window_end),
                expected_artifact_identity,
                selected_end,
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(FreAotRegexResultV1 { start, end });
        STATUS_MATCH
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE);
    if status != STATUS_MATCH {
        // This also covers an unwind before the Rust recovery wrapper could
        // revoke its active compact capability.
        unsafe { &mut *handle.0.cast::<PreparedAotRegex>() }.deactivate_frozen_header();
    }
    status
}

/// Decide whether a legacy exclusive prepared native entry should execute its
/// retained partial-DFA rows for a window of `input_bytes` bytes.
///
/// Returns [`PARTIAL_ENTRY_ENTER`] or [`PARTIAL_ENTRY_BYPASS`]. This is a
/// compatibility seam for older compiler-emitted entries: on bypass, the
/// entry must immediately invoke [`fre_aot_regex_runtime_search_exclusive_v1`]
/// for the same search so the ordinary prepared path consumes one adaptive
/// bypass. On enter, the emitted scan must either return a complete local
/// result or report its interior hole through
/// [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`].
///
/// # Safety
///
/// `handle` must satisfy the exclusive live-handle requirements of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. No search, admission, or
/// destroy call may overlap this call or the native search it admits.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited exclusive raw-handle boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepared_partial_should_enter_v1(
    handle: FreAotRegexExclusiveHandleV1,
    input_bytes: usize,
) -> u32 {
    if handle.is_invalid() {
        return PARTIAL_ENTRY_BYPASS;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        u32::from(
            prepared
                .prepared_partial_should_enter(input_bytes)
                .unwrap_or(false),
        )
    }))
    .unwrap_or(PARTIAL_ENTRY_BYPASS)
}

/// Continue an exclusively owned prepared session from an authenticated
/// retained partial-DFA hole without replaying the consumed prefix.
///
/// `expected_artifact_identity_ptr` supplies exactly
/// [`ARTIFACT_IDENTITY_BYTES`] bytes containing the stable serialized-program
/// SHA-256 identity embedded by the native producer. `resume_state` is only a
/// compact index into that artifact's canonical retained frontier table;
/// frontier contents never cross this ABI. `resume_position` is the first
/// unconsumed byte and must lie strictly inside the original search window.
/// `pending_end_present` must be `0` or `1`; when it is `1`, `pending_end`
/// names the selected boundary already committed in the consumed prefix.
///
/// Status and result conventions are identical to
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. A mismatched artifact
/// identity, absent retained table, invalid compact state, incompatible
/// pending mode/value, or invalid resume position returns
/// [`STATUS_RUNTIME_FAILURE`] and leaves `result_ptr` untouched.
///
/// # Safety
///
/// `handle` must satisfy the exclusive live-handle requirements of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. Haystack and result pointer
/// requirements are identical to that function. Additionally,
/// `expected_artifact_identity_ptr` must be non-null and readable for exactly
/// [`ARTIFACT_IDENTITY_BYTES`] bytes. The result storage must not overlap
/// either readable extent. The compact resume fields must have been emitted
/// after actually executing the retained table in the identified artifact.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this exported continuation symbol is an audited raw C pointer boundary with an explicit authenticated prefix state"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_from_partial_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    resume_state: usize,
    resume_position: usize,
    pending_end_present: u32,
    pending_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || pending_end_present > 1
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned session plus
    // all readable and writable disjoint extents described above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let pending_end = (pending_end_present == 1).then_some(pending_end);
        let Ok(found) = prepared.search_from_retained_partial_resume(
            haystack,
            SearchWindow::new(window_start, window_end),
            expected_artifact_identity,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue the exact retained-row transaction admitted by combined native
/// preflight without repeating its artifact and workspace authentication.
///
/// This compiler-private ABI deliberately retains the legacy continuation's
/// argument layout so generated wrappers can select it by relocation alone.
/// `expected_artifact_identity_ptr` is the same embedded identity passed to
/// preflight, but its bytes are not read again. The preflight's single-use
/// exact-window ticket authenticates the handle, program, workspace, and
/// admitted window. Compact state, position, and pending mode remain checked
/// before the K0 continuation executes.
///
/// # Safety
///
/// This function may only be called by the compiler-emitted wrapper after its
/// immediately preceding preflight returned [`STATUS_PARTIAL_PREFLIGHT_ENTER`]
/// and its local native core returned a hole for that exact transaction. All
/// pointers, extents, alignment, disjointness, exclusive ownership, and
/// compact payload requirements of
/// [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`] must still hold.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this compiler-private trusted continuation preserves the established machine ABI"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_from_partial_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    _expected_artifact_identity_ptr: *const u8,
    resume_state: usize,
    resume_position: usize,
    pending_end_present: u32,
    pending_end: usize,
) -> u32 {
    if pending_end_present > 1 {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: the compiler-owned preflight transaction established the live
    // exclusive session and exact readable/writable extents; the function's
    // private contract keeps them valid through this immediate continuation.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let pending_end = (pending_end_present == 1).then_some(pending_end);
        let Ok(found) = prepared.search_from_preflight_retained_partial_resume(
            haystack,
            SearchWindow::new(window_start, window_end),
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue a combined-preflight transaction without passing its already
/// authenticated identity or exact window back across the private ABI.
///
/// The single-use workspace ticket supplies the admitted window. This compact
/// compiler-private entry therefore needs only the live handle and haystack,
/// untouched result, and native core's state/position/pending payload.
///
/// # Safety
///
/// This function may only be called by the compiler-emitted wrapper after its
/// immediately preceding combined preflight admitted local native execution
/// for this handle and haystack. The handle, haystack, and result pointer must
/// remain live, aligned, disjoint, and exclusively owned until this immediate
/// continuation returns.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compact compiler-private continuation maps one native payload"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    result_ptr: *mut FreAotRegexResultV1,
    resume_state: usize,
    resume_position: usize,
    pending_end_present: u32,
    pending_end: usize,
) -> u32 {
    if pending_end_present > 1 {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: the compiler-owned ticket proves that the immediately preceding
    // preflight authenticated these live allocations for exclusive use.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let pending_end = (pending_end_present == 1).then_some(pending_end);
        let Ok(found) = prepared.search_from_preflight_retained_partial_resume_ticket(
            haystack,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue a combined-preflight transaction without a redundant pending-mode
/// argument.
///
/// The authenticated canonical resume state determines whether `pending_end`
/// is meaningful. A no-pending state ignores that machine word; a pending
/// state retains it as the selected endpoint already committed by native rows.
/// The single-use workspace ticket supplies the admitted window exactly as in
/// the compact-v1 entry.
///
/// # Safety
///
/// This function may only be called by the compiler-emitted wrapper after its
/// immediately preceding combined preflight admitted local native execution
/// for this handle and haystack. The handle, haystack, and result pointer must
/// remain live, aligned, disjoint, and exclusively owned until this immediate
/// continuation returns. `resume_state`, `resume_position`, and a meaningful
/// `pending_end` must be the native core's authenticated outputs.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compact compiler-private continuation maps one native payload"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    result_ptr: *mut FreAotRegexResultV1,
    resume_state: usize,
    resume_position: usize,
    pending_end: usize,
) -> u32 {
    // SAFETY: the compiler-owned ticket proves that the immediately preceding
    // preflight authenticated these live allocations for exclusive use.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let Ok(found) = prepared.search_from_preflight_retained_partial_resume_ticket_inferred(
            haystack,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Recover a Span start after an authenticated native retained-row completion
/// selected only its endpoint.
///
/// This entry accepts only a variable-width, non-nullable Span program with a
/// genuinely incomplete retained table. The exact `window_start..window_end`
/// must be the window returned by the immediately preceding successful
/// [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`] call on the
/// same exclusive session. `selected_end` must lie strictly after the window
/// start and at or before its end. Reverse K0 must recover a span whose end is
/// exactly `selected_end`; the forward search is not replayed.
///
/// On success this function returns [`STATUS_MATCH`] and initializes
/// `result_ptr` with the exact Span. Every rejection returns an error status
/// and leaves `result_ptr` untouched. In particular, `Exists`, `SelectedEnd`,
/// nullable Span, fixed-width Span, complete-table, foreign-artifact, stale,
/// and cross-window calls are rejected.
///
/// # Safety
///
/// `handle` must satisfy the exclusive live-handle requirements of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. Haystack, result, and
/// identity pointer requirements are the same as for
/// [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`]. The caller must
/// pass the same haystack and exact window on which the identified native
/// table ran, and `selected_end` must be the local native completion it
/// produced. No overlapping call or destroy may use any copy of `handle`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this exported postflight is an audited raw C boundary with explicit artifact, exact window, and selected endpoint"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    selected_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || selected_end <= window_start
        || selected_end > window_end
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned session plus
    // all readable and writable disjoint extents described above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let Ok(MatchResult::Span(Some((start, end)))) = prepared
            .recover_retained_partial_span_from_selected_end(
                haystack,
                SearchWindow::new(window_start, window_end),
                expected_artifact_identity,
                selected_end,
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(FreAotRegexResultV1 { start, end });
        STATUS_MATCH
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Authenticate and prepare one native incomplete-retained search.
///
/// The call settles any prior local native completion, runs the complete
/// suffix and cut proofs in portable order, and then applies adaptive native
/// admission. On [`STATUS_NO_MATCH`] or [`STATUS_MATCH`], `result_ptr` is
/// initialized and the search is complete. On
/// [`STATUS_PARTIAL_PREFLIGHT_ENTER`], `window_out` is initialized to the
/// exact non-empty, possibly narrowed window and the native table must enter
/// there. If admission declines, K0 completes from that narrowed window
/// inside this call; the generated entry must not replay the accelerators.
///
/// The expected identity points to exactly [`ARTIFACT_IDENTITY_BYTES`] bytes
/// and binds the emitted native table to the prepared semantic program.
///
/// # Safety
///
/// The exclusive handle, haystack, result, and identity requirements are the
/// same as for [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`].
/// `window_out` must be non-null, aligned, writable, and disjoint from all
/// readable inputs and `result_ptr`. No overlapping search or destroy may use
/// any copy of `handle`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this exported preflight is an audited raw C boundary with explicit artifact and exact-window outputs"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_partial_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    window_out: *mut FreAotRegexSearchWindowV1,
) -> u32 {
    // SAFETY: this forwards the exact public boundary and its documented
    // requirements to the shared implementation without dereferencing them.
    unsafe {
        exclusive_partial_preflight(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            window_out,
            false,
        )
    }
}

/// Authenticate and project an ordinary warmed K0 root for generated code.
///
/// On status [`STATUS_PARTIAL_PREFLIGHT_ENTER`], `preflight_out` contains the
/// exact admitted search window, a pointer-stable fixed-layout descriptor,
/// and the immutable cache identity that must equal the descriptor's identity
/// before either projected address is read. These exposed-provenance addresses
/// are live only until the admitted native scan returns or calls a runtime
/// helper; generated code must not retain them across that boundary. A cold,
/// loop-owned, adaptively bypassed, or structurally unsupported cache completes
/// through canonical K0 inside this call and returns an ordinary match status.
///
/// # Safety
///
/// The handle, haystack, result, and identity requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`].
/// `preflight_out` must be non-null, aligned, writable, and disjoint from all
/// readable inputs and `result_ptr`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the private dynamic-row boundary carries an authenticated descriptor identity"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || preflight_out.is_null()
        || !preflight_out.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the checks above establish the raw extents, alignments, and
    // exact-window contract consumed by the shared transaction.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<false, true>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private dynamic-row preflight for FRE's generated prepared entry.
///
/// This symbol is deliberately absent from the public C header. Its sole
/// producer is the generated prepared wrapper, which has already validated
/// every raw ABI fact below and passes its own static artifact identity plus
/// an aligned stack-resident preflight record. Semantic identity, workspace,
/// program-shape, descriptor, and admission checks remain in the shared
/// transaction.
///
/// # Safety
///
/// `handle` must name one exclusively owned live prepared session.
/// `haystack_ptr` must be non-null and readable for `haystack_len` bytes, with
/// `haystack_len <= isize::MAX`. The exact window must satisfy
/// `window_start <= window_end <= haystack_len`. `result_ptr` and
/// `preflight_out` must be non-null, aligned, writable, mutually disjoint, and
/// disjoint from all readable inputs. `expected_artifact_identity_ptr` must be
/// non-null and readable for exactly [`ARTIFACT_IDENTITY_BYTES`] bytes. No
/// overlapping search or destroy may use any copy of `handle`.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only ABI consumes raw facts proved by its emitted caller"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: every raw requirement is part of this compiler-private
    // function's contract and is established by its sole emitted caller.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<false, true>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private trusted dynamic-row preflight for FRE's generated entry.
///
/// This V2 symbol has the same four-word output layout as V1, but strengthens
/// the successful-entry contract. On [`STATUS_PARTIAL_PREFLIGHT_ENTER`], the
/// returned descriptor was constructed by the live prepared workspace and is
/// valid for the complete synchronous native scan: its descriptor, rows, and
/// class-map addresses are non-null and suitably aligned; its cell encoding,
/// live extent, stride, initial row, initial flags, loop-row geometry, and
/// cache identity satisfy the canonical dynamic-row invariants. The output
/// cache identity is the identity stored in that descriptor. Neither the
/// descriptor nor either projected source address may be retained across a
/// helper call, re-entry, or the end of this exclusive search.
/// Calling any deopt, continuation, or recovery helper ends use of the
/// descriptor before that helper may mutate or rebuild the workspace.
///
/// The versioned symbol prevents an object that relies on this stronger
/// contract from linking against an older runtime that only implements V1.
/// It remains deliberately absent from the public C header.
///
/// # Safety
///
/// The raw input, exclusive ownership, and disjoint writable-output
/// requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v1`].
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only ABI consumes raw facts proved by its emitted caller"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: every raw requirement is part of this compiler-private
    // function's contract and is established by its sole emitted caller.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<false, true>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private trusted dynamic-row preflight with invariant checks
/// specialized out of the admitted-search path.
///
/// V3 preserves V2's four-word output layout and descriptor contract. It also
/// relies on the generated wrapper's exact-window validation and on the
/// prepared runtime's exclusive ownership of the workspace constructed for
/// the authenticated program. Artifact identity remains checked on every
/// call. V1, V2, and the public preflight retain all of their existing checks.
///
/// The versioned symbol prevents a generated object that relies on those
/// stronger premises from linking against a V2 runtime. It is deliberately
/// absent from the public C header.
///
/// # Safety
///
/// The raw pointer requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2`].
/// In addition, the caller must be FRE's generated dynamic-row wrapper for the
/// program shape owned by `handle`, whose live prepared workspace must remain
/// exclusively owned and unmodified. A foreign expected identity is allowed
/// and is rejected transactionally before the trusted program path proceeds.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only V3 ABI consumes wrapper and prepared-workspace invariants"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v3(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: every raw and invariant requirement is part of this versioned
    // compiler-private contract and is established by its sole emitted caller
    // plus the runtime-owned prepared handle.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<true, true>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private trusted dynamic-row preflight without a hot identity copy.
///
/// V4 retains V2's descriptor trust contract and calling convention, but on
/// [`STATUS_PARTIAL_PREFLIGHT_ENTER`] initializes only `start`, `end`, and
/// `native_rows_address`. The fourth V1-layout output word is deliberately
/// untouched. Generated code reloads `cache_identity` from the still-live
/// trusted descriptor only on a first-unpublished-cell side exit, before the
/// continuation helper can mutate the workspace. No caller may read the
/// fourth output word after a successful V4 preflight.
///
/// The versioned symbol prevents generated objects with this three-word write
/// contract from linking against an older runtime. It remains deliberately
/// absent from the public C header.
///
/// # Safety
///
/// The raw input, exclusive ownership, and disjoint writable-output
/// requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2`].
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only ABI consumes raw facts proved by its emitted caller"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v4(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: every raw requirement is part of this compiler-private
    // function's contract and is established by its sole emitted caller.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<false, false>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private trusted dynamic-row preflight with both hot-path contracts.
///
/// V5 combines V3's authenticated static program/workspace premises with V4's
/// three-word successful-entry output. Artifact identity, mutable admission,
/// descriptor readiness, and all transaction checks remain in the runtime.
/// Generated code reloads the descriptor identity only on a rare continuation
/// side exit and must never read the untouched fourth output word.
///
/// # Safety
///
/// The caller must satisfy V3's generated-wrapper and prepared-workspace
/// premises together with V4's three-word output contract.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only V5 ABI combines the audited V3 and V4 premises"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v5(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: both versioned compiler-private contracts are established by
    // the sole generated caller plus the runtime-owned prepared handle.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<true, false>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private dynamic-row preflight with a return-register descriptor.
///
/// V6 preserves V5's trusted-program, artifact-identity, mutable-admission,
/// descriptor, transaction, and exact-window checks. On
/// [`STATUS_PARTIAL_PREFLIGHT_ENTER`], it writes only the admitted `start` and
/// `end` to `window_out` and returns the authenticated native-row descriptor
/// beside the status in a two-word C aggregate. On every other status the
/// returned descriptor is zero and `window_out` has V5's transactional
/// untouched-output semantics.
///
/// The versioned symbol prevents generated objects that consume the second
/// aggregate return register from linking against a V5-only runtime. It is
/// deliberately absent from the public C header.
///
/// # Safety
///
/// The caller must satisfy V5's generated-wrapper and prepared-workspace
/// premises. `window_out` must be non-null, aligned, writable for exactly one
/// [`FreAotRegexSearchWindowV1`], and disjoint from every readable input and
/// `result_ptr`.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only V6 ABI returns its trusted descriptor in native aggregate registers"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v6(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    window_out: *mut FreAotRegexSearchWindowV1,
) -> FreAotRegexDynamicRowsPreflightResultV6 {
    // SAFETY: V6 changes only the successful output transport. The exact
    // V5 premises still establish every raw and runtime-owned input to the
    // shared transaction, and the two-word output is the prefix written by
    // this policy specialization.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated_result::<true, false, false>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            window_out.cast::<FreAotRegexDynamicRowsPreflightV1>(),
        )
    }
}

#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "one panic-catching transaction serves checked public and generated-only entry policies"
)]
unsafe fn exclusive_dynamic_rows_preflight_prevalidated<
    const TRUSTED_PROGRAM: bool,
    const WRITE_CACHE_IDENTITY: bool,
>(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: the caller establishes the selected legacy policy's raw input
    // and output contract. Legacy V1--V5 always write the descriptor word on
    // admitted entry; V1--V3 additionally write the cache identity.
    let returned = unsafe {
        exclusive_dynamic_rows_preflight_prevalidated_result::<
            TRUSTED_PROGRAM,
            WRITE_CACHE_IDENTITY,
            true,
        >(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    };
    u32::try_from(returned.status).unwrap_or(STATUS_RUNTIME_FAILURE)
}

#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "one panic-catching transaction serves legacy memory-return and V6 register-return policies"
)]
unsafe fn exclusive_dynamic_rows_preflight_prevalidated_result<
    const TRUSTED_PROGRAM: bool,
    const WRITE_CACHE_IDENTITY: bool,
    const WRITE_NATIVE_ROWS_ADDRESS: bool,
>(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> FreAotRegexDynamicRowsPreflightResultV6 {
    let returned =
        |status: u32, native_rows_address: usize| FreAotRegexDynamicRowsPreflightResultV6 {
            status: usize::try_from(status).expect("dynamic-row runtime status fits in usize"),
            native_rows_address,
        };
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let window = SearchWindow::new(window_start, window_end);
        let preflight = if TRUSTED_PROGRAM {
            prepared.compiler_private_preflight_dynamic_native_rows_v3(
                haystack,
                window,
                expected_artifact_identity,
            )
        } else {
            prepared.preflight_dynamic_native_rows(
                haystack,
                window,
                expected_artifact_identity,
            )
        };
        let Ok((outcome, native_rows_address, cache_identity)) = preflight else {
            return returned(STATUS_RUNTIME_FAILURE, 0);
        };
        match outcome {
            RetainedPartialPreflight::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                returned(status, 0)
            }
            RetainedPartialPreflight::Enter(window) => {
                if WRITE_CACHE_IDENTITY {
                    preflight_out.write(FreAotRegexDynamicRowsPreflightV1 {
                        start: window.start(),
                        end: window.end(),
                        native_rows_address,
                        cache_generation: cache_identity,
                    });
                } else {
                    // V4/V5 write the descriptor word after the exact window;
                    // V6 transports it in the second aggregate return
                    // register. Every version leaves cache identity available
                    // in the trusted descriptor for a rare continuation side
                    // exit instead of copying it on the common path.
                    std::ptr::addr_of_mut!((*preflight_out).start).write(window.start());
                    std::ptr::addr_of_mut!((*preflight_out).end).write(window.end());
                    if WRITE_NATIVE_ROWS_ADDRESS {
                        std::ptr::addr_of_mut!((*preflight_out).native_rows_address)
                            .write(native_rows_address);
                    }
                }
                returned(STATUS_PARTIAL_PREFLIGHT_ENTER, native_rows_address)
            }
        }
    }))
    .unwrap_or_else(|_| returned(STATUS_RUNTIME_FAILURE, 0))
}

/// Authenticate one native-root-owned incomplete-retained search.
///
/// The call settles any prior local native completion and applies adaptive
/// admission before portable whole-window accelerators. On
/// [`STATUS_PARTIAL_PREFLIGHT_ENTER`], `window_out` is initialized to the
/// unchanged non-empty semantic window and the native table must execute that
/// search exactly once. If admission declines (including the input-size
/// floor), the ordinary
/// suffix-then-cut order and K0 complete inside this call. Match/no-match and
/// error output transactions are identical to
/// [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`].
///
/// The expected identity points to exactly [`ARTIFACT_IDENTITY_BYTES`] bytes
/// and binds the emitted native table to the prepared semantic program.
///
/// # Safety
///
/// The exclusive handle, haystack, result, identity, and exact-window output
/// requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`].
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this exported preflight is an audited raw C boundary with explicit artifact and exact-window outputs"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    window_out: *mut FreAotRegexSearchWindowV1,
) -> u32 {
    // SAFETY: this forwards the exact public boundary and its documented
    // requirements to the shared implementation without dereferencing them.
    unsafe {
        exclusive_partial_preflight(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            window_out,
            true,
        )
    }
}

#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "shared validation and transactional output keep both versioned preflight policies identical"
)]
unsafe fn exclusive_partial_preflight(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    window_out: *mut FreAotRegexSearchWindowV1,
    native_root_owns_admitted_search: bool,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || window_out.is_null()
        || !window_out.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one exclusively owned live session plus
    // the disjoint readable and writable extents documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let window = SearchWindow::new(window_start, window_end);
        let outcome = if native_root_owns_admitted_search {
            prepared.preflight_retained_partial_native_root(
                haystack,
                window,
                expected_artifact_identity,
            )
        } else {
            prepared.preflight_retained_partial(haystack, window, expected_artifact_identity)
        };
        let Ok(outcome) = outcome else {
            return STATUS_RUNTIME_FAILURE;
        };
        match outcome {
            RetainedPartialPreflight::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                status
            }
            RetainedPartialPreflight::Enter(window) => {
                window_out.write(FreAotRegexSearchWindowV1 {
                    start: window.start(),
                    end: window.end(),
                });
                STATUS_PARTIAL_PREFLIGHT_ENTER
            }
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Invalidate and release one prepared handle.
///
/// Returns [`STATUS_SUCCESS`] after the owned program and workspace are
/// released, [`STATUS_INVALID_HANDLE`] for a zero, unknown, or already
/// destroyed token, and [`STATUS_RUNTIME_FAILURE`] only for an internal
/// registry failure. A successful call waits for an already-running search to
/// finish. Subsequent uses of every copy of the token are invalid.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the stable destroy symbol has no raw-pointer operations but still requires an unmangled C export"
)]
pub extern "C" fn fre_aot_regex_runtime_destroy_prepared_v1(
    handle: FreAotRegexPreparedHandleV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    catch_unwind(AssertUnwindSafe(|| destroy_prepared(handle))).unwrap_or(STATUS_RUNTIME_FAILURE)
}

fn destroy_prepared(handle: FreAotRegexPreparedHandleV1) -> u32 {
    let entry = match remove_prepared_entry(handle) {
        Ok(Some(entry)) => entry,
        Ok(None) => return STATUS_INVALID_HANDLE,
        Err(()) => return STATUS_RUNTIME_FAILURE,
    };
    let mut state = entry
        .prepared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.take().is_some() {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_HANDLE
    }
}

/// Destroy one exclusively owned direct-pointer prepared session.
///
/// # Safety
///
/// `handle` must be a live value returned by
/// [`fre_aot_regex_runtime_prepare_exclusive_v1`]. No search may overlap this
/// call, and no copy of the handle may be used or destroyed afterward.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol releases an exclusively owned opaque allocation"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_destroy_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle.0.cast::<PreparedAotRegex>()));
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Execute one immutable, serialized general AOT regex program.
///
/// # Status and result semantics
///
/// Status `0` initializes `result_out` to zero and means no match. Status `1`
/// initializes it according to the compiled output contract: `{0, 0}` for
/// `Exists`, `{end, end}` for `SelectedEnd`, and `{start, end}` for `Span`.
/// Status `2` reports an invalid pointer/window and status `3` reports an
/// invalid program or runtime failure; neither failure status initializes the
/// output.
///
/// This raw compatibility ABI has no artifact-lifetime token, so it soundly
/// validates, owns, and prepares the program on every call instead of caching
/// by a potentially reused address. Rust integrations doing repeated
/// runtime-backed calls should use [`PreparedAotRegex`]. Directly lowered DFA
/// object entries do not call this helper.
///
/// # Safety
///
/// `program_ptr` must point to a readable [`PROGRAM_HEADER_LEN`]-byte header
/// and to the complete immutable extent declared by that header for the
/// duration of the call. `haystack_ptr` must be non-null and readable for
/// `haystack_len` bytes. `result_ptr` must be non-null, properly aligned, and
/// writable for one [`FreAotRegexResultV1`]. The result storage must not
/// overlap either readable extent. Each readable extent must reside within one
/// allocated object and be no larger than `isize::MAX`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this single exported symbol is the audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_v1(
    program_ptr: *const u8,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    if program_ptr.is_null()
        || haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the function's contract supplies all pointer extents,
    // immutability, alignment, writability, and non-overlap requirements. The
    // helper performs its own null/window checks above and artifact bounds
    // checks before extending the fixed-header slice.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        search_checked_pointers(
            program_ptr,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
        )
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

#[allow(
    unsafe_code,
    reason = "raw slice construction and the final disjoint result write are confined to this audited helper"
)]
unsafe fn search_checked_pointers(
    program_ptr: *const u8,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    // SAFETY: the exported function contract guarantees the fixed readable
    // header extent and the caller cannot mutate it during this call.
    let header = unsafe { std::slice::from_raw_parts(program_ptr, PROGRAM_HEADER_LEN) };
    let Ok(program_len) = CompiledProgram::serialized_len_from_header(header) else {
        return STATUS_RUNTIME_FAILURE;
    };
    // SAFETY: the exported function contract guarantees the complete extent
    // declared by the validated fixed header.
    let program_bytes = unsafe { std::slice::from_raw_parts(program_ptr, program_len) };
    let Ok(mut prepared) = PreparedAotRegex::deserialize(program_bytes) else {
        return STATUS_RUNTIME_FAILURE;
    };
    // SAFETY: the exported function contract guarantees this readable extent,
    // and the checked length is representable by `isize`.
    let haystack = unsafe { std::slice::from_raw_parts(haystack_ptr, haystack_len) };
    let Ok((status, result)) = execute_search(&mut prepared, haystack, window_start, window_end)
    else {
        return STATUS_RUNTIME_FAILURE;
    };
    // End the haystack borrow before writing through the disjoint output
    // pointer promised by the C contract.
    let _ = haystack;
    // SAFETY: the exported function contract guarantees aligned, writable,
    // non-overlapping storage for exactly one result.
    unsafe { result_ptr.write(result) };
    status
}

fn execute_search(
    prepared: &mut PreparedAotRegex,
    haystack: &[u8],
    window_start: usize,
    window_end: usize,
) -> Result<(u32, FreAotRegexResultV1), CompileError> {
    Ok(encode_match_result(prepared.search(
        haystack,
        SearchWindow::new(window_start, window_end),
    )?))
}

fn execute_exclusive_search(
    prepared: &mut PreparedAotRegex,
    haystack: &[u8],
    window_start: usize,
    window_end: usize,
) -> Result<(u32, FreAotRegexResultV1), CompileError> {
    Ok(encode_match_result(prepared.search_exclusive(
        haystack,
        SearchWindow::new(window_start, window_end),
    )?))
}

fn encode_match_result(result: MatchResult) -> (u32, FreAotRegexResultV1) {
    match result {
        MatchResult::Exists(false) | MatchResult::SelectedEnd(None) | MatchResult::Span(None) => {
            (STATUS_NO_MATCH, FreAotRegexResultV1::default())
        }
        MatchResult::Exists(true) => {
            // Exists deliberately exposes no endpoint information.
            (STATUS_MATCH, FreAotRegexResultV1::default())
        }
        MatchResult::SelectedEnd(Some(end)) => {
            (STATUS_MATCH, FreAotRegexResultV1 { start: end, end })
        }
        MatchResult::Span(Some((start, end))) => (STATUS_MATCH, FreAotRegexResultV1 { start, end }),
    }
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "tests exercise the exported raw C boundary with explicitly valid or deliberately rejected pointers"
)]
mod tests {
    use fre_aot_regex::{
        CompileLimitsV1, CompileMode, CompileRequest, DeterminizeLimits, EngineKind,
        EngineSelectionReason,
        FROZEN_COMPACT_LOOP_PLAN_V1_BYTES, FROZEN_COMPACT_LOOP_PLAN_V1_MEMBERS_OFFSET,
        FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
        FROZEN_DYNAMIC_ROWS_V6_LOOP_PLAN_COUNT_OFFSET, FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_FLAGS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V6,
        FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V7,
        FROZEN_PREPARED_HEADER_V6_DYNAMIC_ROWS_OFFSET, MatchResult, OutputContract, Target,
        compile,
    };

    use super::*;

    fn program(pattern: &str, output: OutputContract) -> Vec<u8> {
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(output),
        )
        .expect("compile general NFA program");
        assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
        compiled.program().serialize().expect("serialize program")
    }

    fn prepared(pattern: &str, output: OutputContract, mode: CompileMode) -> PreparedAotRegex {
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(mode)
                .output(output),
        )
        .unwrap_or_else(|error| panic!("compile {mode:?} {pattern:?}: {error}"));
        let bytes = compiled.program().serialize().expect("serialize program");
        PreparedAotRegex::deserialize(&bytes).expect("prepare program")
    }

    fn collected_spans(prepared: &mut PreparedAotRegex, haystack: &[u8]) -> Vec<(usize, usize)> {
        prepared
            .find_iter(haystack)
            .expect("Span iterator")
            .map(|matched| {
                let matched = matched.expect("successful iterator search");
                (matched.start(), matched.end())
            })
            .collect()
    }

    fn call(
        program: &[u8],
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
    ) -> u32 {
        // SAFETY: all slices and the result outlive this synchronous call and
        // are disjoint; the program was produced by the compiler.
        unsafe {
            fre_aot_regex_runtime_search_v1(
                program.as_ptr(),
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
            )
        }
    }

    fn prepare_handle(program: &[u8]) -> FreAotRegexPreparedHandleV1 {
        let mut handle = FreAotRegexPreparedHandleV1::INVALID;
        // SAFETY: the complete compiler-produced slice is readable for the
        // call and the disjoint aligned output remains live.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_v1(program.as_ptr(), program.len(), &raw mut handle)
        };
        assert_eq!(status, STATUS_SUCCESS);
        assert!(!handle.is_invalid());
        handle
    }

    fn call_prepared(
        handle: FreAotRegexPreparedHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
    ) -> u32 {
        // SAFETY: the readable haystack and disjoint aligned result outlive
        // this synchronous call.
        unsafe {
            fre_aot_regex_runtime_search_prepared_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
            )
        }
    }

    fn prepare_exclusive(program: &[u8]) -> FreAotRegexExclusiveHandleV1 {
        let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
        // SAFETY: the complete compiler-produced slice is readable for the
        // call and the disjoint aligned output remains live. This helper owns
        // the returned session until its explicit destroy below.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_exclusive_v1(
                program.as_ptr(),
                program.len(),
                &raw mut handle,
            )
        };
        assert_eq!(status, STATUS_SUCCESS);
        assert!(!handle.is_invalid());
        handle
    }

    fn prepare_exclusive_with_cold_dynamic_rows(program: &[u8]) -> FreAotRegexExclusiveHandleV1 {
        let program = CompiledProgram::deserialize(program).expect("deserialize test program");
        let mut workspace = program.prepare_workspace().expect("prepare test workspace");
        let fully_prefilled_fallback = program
            .compiler_private_try_prefill_retained_fallback_with_workspace_receipt(&mut workspace)
            .expect("prefill cold dynamic-row test owner");
        let frozen_dynamic_rows = program
            .compiler_private_frozen_dynamic_rows_storage_v3_with_fallback_receipt(
                &mut workspace,
                fully_prefilled_fallback,
                0,
                0,
            );
        assert!(frozen_dynamic_rows.is_none());
        assert!(fully_prefilled_fallback.is_none());
        let frozen_header = program.compiler_private_frozen_prepared_header_v6(
            &workspace,
            fully_prefilled_fallback,
            frozen_dynamic_rows.as_ref(),
        );
        assert!(!frozen_header.is_active());
        let prepared = PreparedAotRegex {
            frozen_header,
            program,
            workspace,
            frozen_dynamic_rows,
            fully_prefilled_fallback,
        };
        FreAotRegexExclusiveHandleV1(
            Box::into_raw(Box::new(prepared)).cast::<std::ffi::c_void>(),
        )
    }

    fn call_exclusive(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // the readable haystack and disjoint aligned result outlive the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
            )
        }
    }

    fn call_exclusive_frozen_fallback(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies
        // readable haystack/identity plus disjoint aligned writable output.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
            )
        }
    }

    fn call_exclusive_static_prefix_preflight(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies
        // readable haystack/identity plus disjoint aligned writable output.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
            )
        }
    }

    fn call_exclusive_static_prefix_preflight_v2(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        descriptor: &[u32],
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies
        // readable haystack, identity, descriptor, and disjoint output.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                descriptor.as_ptr(),
            )
        }
    }

    fn call_exclusive_static_prefix_recover_span(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies the
        // synchronous endpoint plus readable/disjoint pointer extents.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                selected_end,
            )
        }
    }

    fn exclusive_frozen_header_is_active(handle: FreAotRegexExclusiveHandleV1) -> bool {
        assert!(!handle.is_invalid());
        // SAFETY: lifecycle tests call this only while they uniquely own the
        // live allocation and no search or destruction overlaps the read.
        unsafe {
            (&*handle.0.cast::<PreparedAotRegex>())
                .frozen_header
                .is_active()
        }
    }

    fn exclusive_frozen_header_identity(
        handle: FreAotRegexExclusiveHandleV1,
    ) -> [u8; ARTIFACT_IDENTITY_BYTES] {
        assert!(!handle.is_invalid());
        // SAFETY: identical unique-live-handle reasoning to the active-seal
        // helper immediately above.
        unsafe {
            *(&*handle.0.cast::<PreparedAotRegex>())
                .frozen_header
                .artifact_identity()
        }
    }

    fn call_exclusive_dynamic_rows_deopt(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live admitted
        // transaction; the readable haystack and disjoint aligned result
        // outlive this synchronous side-exit continuation.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_dynamic_rows_deopt_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
            )
        }
    }

    fn call_partial_should_enter(
        handle: FreAotRegexExclusiveHandleV1,
        input_bytes: usize,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session and
        // does not overlap admission with search or destruction.
        unsafe {
            fre_aot_regex_runtime_prepared_partial_should_enter_v1(handle, input_bytes)
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the explicit authenticated continuation ABI"
    )]
    fn call_exclusive_from_partial(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // the compiler-produced identity, readable haystack, and disjoint
        // aligned result all outlive the synchronous call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_from_partial_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                resume_state,
                resume_position,
                u32::from(pending_end.is_some()),
                pending_end.unwrap_or(0),
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the authenticated exact-window preflight ABI"
    )]
    fn call_exclusive_partial_preflight(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        window: &mut FreAotRegexSearchWindowV1,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // all readable and disjoint aligned writable extents outlive the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_partial_preflight_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                window,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the private generation-bearing dynamic-row preflight"
    )]
    fn call_exclusive_dynamic_rows_preflight(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: the test owns the exclusive session and all readable and
        // disjoint writable extents outlive the synchronous call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v2(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: this test helper supplies the exact live, validated,
        // disjoint inputs established by FRE's generated wrapper.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only trusted V3 dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v3(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: this test helper supplies the exact live prepared program,
        // validated window, and disjoint storage required by the V3 contract.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v3(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only V4 dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v4(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: this test helper supplies the exact live, validated,
        // disjoint inputs established by FRE's generated V4 wrapper.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v4(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only V5 dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v5(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: this test helper supplies the combined V3 invariant and V4
        // output contracts established by FRE's generated V5 wrapper.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v5(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only V6 return-register dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v6(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> FreAotRegexDynamicRowsPreflightResultV6 {
        // SAFETY: this test helper supplies the exact live, validated,
        // disjoint inputs established by FRE's generated V6 wrapper. The
        // larger sentinel record lets the test prove that V6 writes only its
        // two-word window prefix.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v6(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                std::ptr::from_mut(output).cast::<FreAotRegexSearchWindowV1>(),
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the compiler-private authenticated first-hole continuation"
    )]
    fn call_exclusive_dynamic_rows_continue(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        continuation: &FreAotRegexDynamicRowsContinuationV1,
    ) -> u32 {
        // SAFETY: the test owns the immediately preceding exclusive
        // admission and every readable/disjoint writable extent remains live
        // through the synchronous compiler-private call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                continuation,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the authenticated dynamic Span postflight ABI"
    )]
    fn call_exclusive_recover_dynamic_span(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // either its active immutable owner or its immediately preceding
        // admission authenticates the synchronous compiler-private
        // postflight. Readable inputs and disjoint aligned output outlive it.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                selected_end,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the authenticated exact-window Span postflight ABI"
    )]
    fn call_exclusive_recover_partial_span(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // all readable and disjoint aligned writable extents outlive the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                selected_end,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the authenticated native-root preflight ABI"
    )]
    fn call_exclusive_partial_native_root_preflight(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        window: &mut FreAotRegexSearchWindowV1,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // all readable and disjoint aligned writable extents outlive the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                window,
            )
        }
    }

    fn expected_ffi(result: MatchResult) -> (u32, FreAotRegexResultV1) {
        match result {
            MatchResult::Exists(false)
            | MatchResult::SelectedEnd(None)
            | MatchResult::Span(None) => (STATUS_NO_MATCH, FreAotRegexResultV1::default()),
            MatchResult::Exists(true) => (STATUS_MATCH, FreAotRegexResultV1::default()),
            MatchResult::SelectedEnd(Some(end)) => {
                (STATUS_MATCH, FreAotRegexResultV1 { start: end, end })
            }
            MatchResult::Span(Some((start, end))) => {
                (STATUS_MATCH, FreAotRegexResultV1 { start, end })
            }
        }
    }

    fn generated_haystacks() -> Vec<Vec<u8>> {
        let alphabet = [b'a', b'b', b'x', b'\n'];
        let mut haystacks = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in &alphabet {
                    let mut haystack = prefix.clone();
                    haystack.push(byte);
                    haystacks.push(haystack.clone());
                    next.push(haystack);
                }
            }
            frontier = next;
        }
        haystacks.extend([b"abz".to_vec(), b"xxabacadz".to_vec(), b"x\nab\n".to_vec()]);
        haystacks
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the ABI audit keeps every public and compiler-private function type in one ledger"
    )]
    fn c_abi_layout_declarations_and_function_types_are_stable() {
        assert_eq!(std::mem::offset_of!(PreparedAotRegex, frozen_header), 0);
        assert_eq!(
            size_of::<fre_aot_regex::FrozenPreparedHeaderV1>(),
            fre_aot_regex::FROZEN_PREPARED_HEADER_V1_BYTES
        );
        assert_eq!(
            size_of::<FrozenPreparedHeaderV2>(),
            fre_aot_regex::FROZEN_PREPARED_HEADER_V2_BYTES
        );
        assert_eq!(
            size_of::<FrozenPreparedHeaderV3>(),
            fre_aot_regex::FROZEN_PREPARED_HEADER_V3_BYTES
        );
        assert_eq!(
            size_of::<FrozenPreparedHeaderV6>(),
            fre_aot_regex::FROZEN_PREPARED_HEADER_V6_BYTES
        );
        assert_eq!(
            fre_aot_regex::FROZEN_PREPARED_HEADER_V1_ACTIVE_SEAL_OFFSET,
            0
        );
        assert_eq!(size_of::<FreAotRegexPreparedHandleV1>(), size_of::<u64>());
        assert_eq!(align_of::<FreAotRegexPreparedHandleV1>(), align_of::<u64>());
        assert_eq!(
            size_of::<FreAotRegexExclusiveHandleV1>(),
            size_of::<*mut std::ffi::c_void>()
        );
        assert_eq!(
            align_of::<FreAotRegexExclusiveHandleV1>(),
            align_of::<*mut std::ffi::c_void>()
        );
        assert_eq!(size_of::<FreAotRegexResultV1>(), size_of::<[usize; 2]>());
        assert_eq!(
            size_of::<FreAotRegexSearchWindowV1>(),
            size_of::<[usize; 2]>()
        );
        assert_eq!(
            align_of::<FreAotRegexSearchWindowV1>(),
            align_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexDynamicRowsPreflightV1>(),
            size_of::<[usize; 4]>()
        );
        assert_eq!(
            align_of::<FreAotRegexDynamicRowsPreflightV1>(),
            align_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexDynamicRowsPreflightResultV6>(),
            size_of::<[usize; 2]>()
        );
        assert_eq!(
            align_of::<FreAotRegexDynamicRowsPreflightResultV6>(),
            align_of::<usize>()
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexDynamicRowsPreflightResultV6, status),
            0
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexDynamicRowsPreflightResultV6, native_rows_address),
            size_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexDynamicRowsContinuationV1>(),
            size_of::<[usize; 5]>()
        );
        assert_eq!(
            align_of::<FreAotRegexDynamicRowsContinuationV1>(),
            align_of::<usize>()
        );
        assert_eq!(ARTIFACT_IDENTITY_BYTES, 32);
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_ARTIFACT_IDENTITY_BYTES 32u"));
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_STATUS_PARTIAL_PREFLIGHT_ENTER 6u"));
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_PARTIAL_ENTRY_BYPASS 0u"));
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_PARTIAL_ENTRY_ENTER 1u"));
        for symbol in [
            "fre_aot_regex_runtime_search_v1",
            "fre_aot_regex_runtime_prepare_v1",
            "fre_aot_regex_runtime_search_prepared_v1",
            "fre_aot_regex_runtime_destroy_prepared_v1",
            "fre_aot_regex_runtime_prepare_exclusive_v1",
            "fre_aot_regex_runtime_search_exclusive_v1",
            "fre_aot_regex_runtime_prepared_partial_should_enter_v1",
            "fre_aot_regex_runtime_search_exclusive_from_partial_v1",
            "fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1",
            "fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1",
            "fre_aot_regex_runtime_search_exclusive_partial_preflight_v1",
            "fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1",
            "fre_aot_regex_runtime_destroy_exclusive_v1",
        ] {
            assert!(C_API_V1_HEADER.contains(symbol), "{symbol}");
        }
        for private_fragment in [
            "fre_aot_regex_runtime_search_exclusive_from_partial_preflight_v1",
            "fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v1",
            "fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2",
            "fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v3",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v4",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v5",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v6",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2",
            "fre_aot_regex_runtime_search_exclusive_dynamic_rows_deopt_v1",
            "fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1",
            "fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1",
            "fre_aot_regex_runtime_scan_frozen_loop_v1",
            "fre_aot_regex_runtime_scan_frozen_loop_v2",
            "native_rows_address",
            "cache_generation",
            "current_row",
        ] {
            assert!(
                !C_API_V1_HEADER.contains(private_fragment),
                "private ABI fragment leaked into the public header: {private_fragment}"
            );
        }

        let _: unsafe extern "C" fn(*const u8, usize, *mut FreAotRegexPreparedHandleV1) -> u32 =
            fre_aot_regex_runtime_prepare_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexPreparedHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
        ) -> u32 = fre_aot_regex_runtime_search_prepared_v1;
        let _: extern "C" fn(FreAotRegexPreparedHandleV1) -> u32 =
            fre_aot_regex_runtime_destroy_prepared_v1;
        let _: unsafe extern "C" fn(*const u8, usize, *mut FreAotRegexExclusiveHandleV1) -> u32 =
            fre_aot_regex_runtime_prepare_exclusive_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *const u32,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            *mut FreAotRegexResultV1,
            usize,
            usize,
            usize,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_dynamic_rows_deopt_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            usize,
            *const u8,
            usize,
        ) -> usize = fre_aot_regex_runtime_scan_frozen_loop_v1;
        let _: unsafe extern "C" fn(
            *const u8,
            *const FrozenCompactLoopScanner,
            usize,
        ) -> usize = fre_aot_regex_runtime_scan_frozen_loop_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *const FreAotRegexDynamicRowsContinuationV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1;
        let _: unsafe extern "C" fn(FreAotRegexExclusiveHandleV1, usize) -> u32 =
            fre_aot_regex_runtime_prepared_partial_should_enter_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
            usize,
            u32,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_from_partial_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
            usize,
            u32,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_from_partial_preflight_v1;
        let mut malformed_result = FreAotRegexResultV1 {
            start: 123,
            end: 456,
        };
        // SAFETY: the malformed pending-mode discriminator is rejected before
        // any handle or pointer is dereferenced.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_from_partial_preflight_v1(
                    FreAotRegexExclusiveHandleV1::INVALID,
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    &raw mut malformed_result,
                    std::ptr::null(),
                    0,
                    0,
                    2,
                    0,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            malformed_result,
            FreAotRegexResultV1 {
                start: 123,
                end: 456,
            }
        );
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            *mut FreAotRegexResultV1,
            usize,
            usize,
            u32,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            *mut FreAotRegexResultV1,
            usize,
            usize,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2;
        // SAFETY: the malformed discriminator is rejected before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v1(
                    FreAotRegexExclusiveHandleV1::INVALID,
                    std::ptr::null(),
                    0,
                    &raw mut malformed_result,
                    0,
                    0,
                    2,
                    0,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            malformed_result,
            FreAotRegexResultV1 {
                start: 123,
                end: 456,
            }
        );
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexSearchWindowV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_partial_preflight_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v3;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v4;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v5;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexSearchWindowV1,
        ) -> FreAotRegexDynamicRowsPreflightResultV6 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v6;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexSearchWindowV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1;
        let _: unsafe extern "C" fn(FreAotRegexExclusiveHandleV1) -> u32 =
            fre_aot_regex_runtime_destroy_exclusive_v1;
    }

    #[test]
    fn frozen_loop_scan_boundary_authenticates_owner_pointer_and_extent() {
        let limits = CompileLimitsV1 {
            determinize: DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
            ..CompileLimitsV1::default()
        };
        let compiled = compile(
            CompileRequest::new(
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd)
            .limits(limits),
        )
        .expect("compile compact-loop helper fixture");
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let base = handle.0.cast::<u8>();

        // SAFETY: the exclusive handle owns a live PreparedAotRegex whose
        // offset-zero V6 header has the public target-native layout.
        let flags = unsafe {
            std::ptr::read_unaligned(
                base.add(FROZEN_PREPARED_HEADER_V1_FLAGS_OFFSET)
                    .cast::<u32>(),
            )
        };
        assert!(matches!(
            flags,
            FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V6
                | FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V7
        ));
        let tail = FROZEN_PREPARED_HEADER_V6_DYNAMIC_ROWS_OFFSET;
        // SAFETY: the authenticated flag above proves the complete V6/V7
        // extent remains live in this exclusively owned prepared allocation.
        let plan_count = unsafe {
            std::ptr::read_unaligned(
                base.add(tail + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLAN_COUNT_OFFSET)
                    .cast::<u32>(),
            )
        };
        assert!((1..=4).contains(&plan_count));

        let mut selected = None;
        for slot in 0..usize::try_from(plan_count).unwrap() {
            let plan = tail
                + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET
                + slot * FROZEN_COMPACT_LOOP_PLAN_V1_BYTES;
            let mut members = [0_u64; 4];
            for (word, value) in members.iter_mut().enumerate() {
                // SAFETY: every active plan is wholly inside the authenticated
                // fixed-capacity header extent.
                *value = unsafe {
                    std::ptr::read_unaligned(
                        base.add(
                            plan
                                + FROZEN_COMPACT_LOOP_PLAN_V1_MEMBERS_OFFSET
                                + word * std::mem::size_of::<u64>(),
                        )
                        .cast::<u64>(),
                    )
                };
            }
            if members != [u64::MAX; 4] {
                // SAFETY: the scanner-address field is inside this same plan.
                let scanner_address = unsafe {
                    std::ptr::read_unaligned(
                        base.add(plan + FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET)
                            .cast::<usize>(),
                    )
                };
                selected = Some((members, scanner_address));
                break;
            }
        }
        let (members, scanner_address) =
            selected.expect("the fixture must publish a proper loop subset");
        assert_ne!(scanner_address, 0);
        let scanner = std::ptr::with_exposed_provenance::<FrozenCompactLoopScanner>(
            scanner_address,
        );
        let member = (u8::MIN..=u8::MAX)
            .find(|&byte| {
                members[usize::from(byte >> 6)] & (1_u64 << u32::from(byte & 63)) != 0
            })
            .unwrap();
        let nonmember = (u8::MIN..=u8::MAX)
            .find(|&byte| {
                members[usize::from(byte >> 6)] & (1_u64 << u32::from(byte & 63)) == 0
            })
            .unwrap();

        for prefix in [0_usize, 1, 31, 63, 64, 65, 129] {
            let mut source = vec![member; prefix];
            source.push(nonmember);
            source.extend(std::iter::repeat_n(member, 7));
            // SAFETY: the handle, exact opaque address, and source extent are
            // all live and exclusively owned for this synchronous call.
            let consumed = unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    handle,
                    scanner_address,
                    source.as_ptr(),
                    source.len(),
                )
            };
            assert_eq!(consumed, prefix);
            assert!(consumed <= source.len());
            // SAFETY: setup authenticated this exact typed scanner pointer,
            // the exclusively owned prepared allocation remains active, and
            // `source` supplies the complete synchronous readable extent.
            let trusted = unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v2(
                    source.as_ptr(),
                    scanner,
                    source.len(),
                )
            };
            assert_eq!(trusted, prefix);
            assert!(trusted <= source.len());
        }

        let source = [member; 64];
        // SAFETY: all raw extents are live; only the opaque address is
        // deliberately foreign and must be rejected before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    handle,
                    scanner_address.wrapping_add(1),
                    source.as_ptr(),
                    source.len(),
                )
            },
            FROZEN_LOOP_SCAN_FAILURE
        );
        // SAFETY: malformed arguments are rejected before either raw pointer
        // is followed or a slice is formed.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    FreAotRegexExclusiveHandleV1::INVALID,
                    scanner_address,
                    std::ptr::null(),
                    0,
                )
            },
            FROZEN_LOOP_SCAN_FAILURE
        );
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    handle,
                    scanner_address,
                    source.as_ptr(),
                    isize::MAX.unsigned_abs().saturating_add(1),
                )
            },
            FROZEN_LOOP_SCAN_FAILURE
        );

        // Revocation makes the once-valid address inert before the helper can
        // reach the immutable owner.
        // SAFETY: this test uniquely owns the live prepared allocation.
        unsafe { &mut *handle.0.cast::<PreparedAotRegex>() }.deactivate_frozen_header();
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    handle,
                    scanner_address,
                    source.as_ptr(),
                    source.len(),
                )
            },
            FROZEN_LOOP_SCAN_FAILURE
        );
        // SAFETY: this test uniquely owns the now-revoked session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn frozen_object_link_fails_against_a_legacy_runtime_without_the_capability_symbol() {
        use std::{fs, process::Command, time::SystemTime};

        const FROZEN_SYMBOL: &str =
            "fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1";
        assert!(!C_API_V1_HEADER.contains(FROZEN_SYMBOL));
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-frozen-old-runtime-link-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("create isolated linker fixture");
        let caller = directory.join("frozen_caller.c");
        let legacy = directory.join("legacy_runtime.c");
        let capable = directory.join("capable_runtime.c");
        let compatible_executable = directory.join("compatible");
        let legacy_executable = directory.join("legacy");
        fs::write(
            &caller,
            r"#include <stddef.h>
#include <stdint.h>
typedef struct { size_t start; size_t end; } result_t;
extern uint32_t fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
    void *, const unsigned char *, size_t, size_t, size_t, result_t *,
    const unsigned char *);
int main(void) {
    static const unsigned char haystack[1] = { 0 };
    static const unsigned char identity[32] = { 0 };
    result_t result = { 0, 0 };
    return (int)fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
        (void *)1, haystack, 1, 0, 1, &result, identity);
}
",
        )
        .expect("write frozen caller");
        fs::write(
            &legacy,
            r"#include <stdint.h>
uint32_t fre_aot_regex_runtime_search_exclusive_v1(void) { return 0; }
",
        )
        .expect("write legacy runtime stub");
        fs::write(
            &capable,
            r"#include <stddef.h>
#include <stdint.h>
typedef struct { size_t start; size_t end; } result_t;
uint32_t fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
    void *h, const unsigned char *p, size_t n, size_t s, size_t e, result_t *r,
    const unsigned char *d) {
    (void)h; (void)p; (void)n; (void)s; (void)e; (void)r; (void)d;
    return 0;
}
",
        )
        .expect("write capable runtime stub");

        let compatible = Command::new("cc")
            .arg(&caller)
            .arg(&legacy)
            .arg(&capable)
            .arg("-o")
            .arg(&compatible_executable)
            .output()
            .expect("invoke host C linker for capable runtime");
        assert!(
            compatible.status.success(),
            "capable fixture failed to link: {}",
            String::from_utf8_lossy(&compatible.stderr)
        );
        let old = Command::new("cc")
            .arg(&caller)
            .arg(&legacy)
            .arg("-o")
            .arg(&legacy_executable)
            .output()
            .expect("invoke host C linker for legacy runtime");
        assert!(
            !old.status.success(),
            "a frozen caller unexpectedly linked without {FROZEN_SYMBOL}"
        );
        fs::remove_dir_all(&directory).expect("remove isolated linker fixture");
    }

    #[test]
    fn assertion_nfa_executes_all_output_contracts() {
        let haystack = b"x\nalpha beta";
        let expected = [
            (
                OutputContract::Exists,
                FreAotRegexResultV1 { start: 0, end: 0 },
            ),
            (
                OutputContract::SelectedEnd,
                FreAotRegexResultV1 { start: 7, end: 7 },
            ),
            (
                OutputContract::Span,
                FreAotRegexResultV1 { start: 2, end: 7 },
            ),
        ];
        for (output, expected_result) in expected {
            let program = program(r"(?m:^alpha\b)", output);
            let mut result = FreAotRegexResultV1 {
                start: usize::MAX,
                end: usize::MAX,
            };
            assert_eq!(
                call(&program, haystack, 0, haystack.len(), &mut result),
                STATUS_MATCH
            );
            assert_eq!(result, expected_result);
        }

        let program = program(r"(?m:^alpha\b)", OutputContract::Span);
        let mut result = FreAotRegexResultV1 {
            start: usize::MAX,
            end: usize::MAX,
        };
        assert_eq!(
            call(&program, b"no match", 0, 8, &mut result),
            STATUS_NO_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());
    }

    #[test]
    #[allow(
        clippy::cast_ptr_alignment,
        clippy::too_many_lines,
        reason = "all ten public raw predicates and both untouched output transactions form one boundary audit"
    )]
    fn public_dynamic_rows_preflight_rejects_every_raw_boundary_violation_transactionally() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile dynamic-row public-boundary fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive(&serialized);
        let haystack = [b'x'; 80];
        let sentinel_result = FreAotRegexResultV1 { start: 71, end: 73 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 79,
            end: 83,
            native_rows_address: 89,
            cache_generation: 97,
        };
        let mut result: FreAotRegexResultV1;
        let mut output: FreAotRegexDynamicRowsPreflightV1;
        let mut result_words = [0xa5a5_a5a5_a5a5_a5a5_usize; 3];
        let mut output_words = [0x5a5a_5a5a_5a5a_5a5a_usize; 5];
        let result_words_before = result_words;
        let output_words_before = output_words;
        let misaligned_result = result_words
            .as_mut_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<FreAotRegexResultV1>();
        let misaligned_output = output_words
            .as_mut_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<FreAotRegexDynamicRowsPreflightV1>();
        assert!(!misaligned_result.is_aligned());
        assert!(!misaligned_output.is_aligned());

        macro_rules! reject {
            (
                $name:literal, $case_handle:expr, $haystack_ptr:expr, $haystack_len:expr,
                $start:expr, $end:expr, $result_ptr:expr, $identity_ptr:expr,
                $output_ptr:expr, $expected_status:expr
            ) => {{
                result = sentinel_result;
                output = sentinel_output;
                // SAFETY: every malformed extent is selected so the checked
                // public boundary rejects it before any invalid dereference.
                let status = unsafe {
                    fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1(
                        $case_handle,
                        $haystack_ptr,
                        $haystack_len,
                        $start,
                        $end,
                        $result_ptr,
                        $identity_ptr,
                        $output_ptr,
                    )
                };
                assert_eq!(status, $expected_status, $name);
                assert_eq!(result, sentinel_result, "result transaction: {}", $name);
                assert_eq!(output, sentinel_output, "preflight transaction: {}", $name);
                assert_eq!(result_words, result_words_before, "result backing: {}", $name);
                assert_eq!(output_words, output_words_before, "output backing: {}", $name);
            }};
        }

        reject!(
            "invalid handle",
            FreAotRegexExclusiveHandleV1::INVALID,
            haystack.as_ptr(), haystack.len(), 8, 72,
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_HANDLE
        );
        reject!(
            "null haystack",
            handle, std::ptr::null(), haystack.len(), 8, 72,
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "null result",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            std::ptr::null_mut(), identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "misaligned result",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            misaligned_result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "null identity",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            &raw mut result, std::ptr::null(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "null preflight output",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            &raw mut result, identity.as_ptr(), std::ptr::null_mut(),
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "misaligned preflight output",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            &raw mut result, identity.as_ptr(), misaligned_output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "length exceeds isize",
            handle, haystack.as_ptr(), isize::MAX.unsigned_abs().checked_add(1).unwrap(), 0, 0,
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "start after end",
            handle, haystack.as_ptr(), haystack.len(), 73, 72,
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "end after length",
            handle, haystack.as_ptr(), haystack.len(), 8,
            haystack.len().checked_add(1).unwrap(),
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );

        // SAFETY: the rejected calls never consumed or aliased this uniquely
        // owned live session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "cold, warm, deopt, and identity-failure parity cover checked, V2, and trusted V3 transactions"
    )]
    fn compiler_private_dynamic_rows_preflight_matches_checked_transaction() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile generated-only dynamic-row fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let public_handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let private_handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let trusted_handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let sentinel_result = FreAotRegexResultV1 { start: 91, end: 92 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 93,
            end: 94,
            native_rows_address: 95,
            cache_generation: 96,
        };

        for expected_status in [STATUS_MATCH, STATUS_PARTIAL_PREFLIGHT_ENTER] {
            let mut public_result = sentinel_result;
            let mut private_result = sentinel_result;
            let mut trusted_result = sentinel_result;
            let mut public_output = sentinel_output;
            let mut private_output = sentinel_output;
            let mut trusted_output = sentinel_output;
            let public_status = call_exclusive_dynamic_rows_preflight(
                public_handle, &haystack, 8, 72, &mut public_result, &identity,
                &mut public_output,
            );
            let private_status = call_exclusive_compiler_private_dynamic_rows_preflight_v2(
                private_handle, &haystack, 8, 72, &mut private_result, &identity,
                &mut private_output,
            );
            let trusted_status = call_exclusive_compiler_private_dynamic_rows_preflight_v3(
                trusted_handle, &haystack, 8, 72, &mut trusted_result, &identity,
                &mut trusted_output,
            );
            assert_eq!(public_status, expected_status);
            assert_eq!(private_status, public_status);
            assert_eq!(trusted_status, public_status);
            assert_eq!(private_result, public_result);
            assert_eq!(trusted_result, public_result);
            if expected_status == STATUS_MATCH {
                assert_eq!(public_output, sentinel_output);
                assert_eq!(private_output, sentinel_output);
                assert_eq!(trusted_output, sentinel_output);
            } else {
                assert_eq!((private_output.start, private_output.end), (8, 72));
                assert_eq!((trusted_output.start, trusted_output.end), (8, 72));
                assert_eq!(
                    (private_output.start, private_output.end),
                    (public_output.start, public_output.end)
                );
                for output in [public_output, private_output, trusted_output] {
                    assert_ne!(output.native_rows_address, 0);
                    assert_ne!(output.cache_generation, 0);
                    // SAFETY: each descriptor belongs to its still-live,
                    // synchronously admitted exclusive transaction.
                    let descriptor = unsafe {
                        &*std::ptr::with_exposed_provenance::<
                            fre_aot_regex::DynamicNativeRowsV1,
                        >(output.native_rows_address)
                    };
                    assert_eq!(descriptor.cache_identity, output.cache_generation);
                    assert_ne!(descriptor.rows_address, 0);
                    assert_ne!(descriptor.class_map_address, 0);
                }
            }
        }

        let mut public_result = sentinel_result;
        let mut private_result = sentinel_result;
        let mut trusted_result = sentinel_result;
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(
                public_handle, &haystack, 8, 72, &mut public_result,
            ),
            STATUS_MATCH
        );
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(
                private_handle, &haystack, 8, 72, &mut private_result,
            ),
            STATUS_MATCH
        );
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(
                trusted_handle, &haystack, 8, 72, &mut trusted_result,
            ),
            STATUS_MATCH
        );
        assert_eq!(private_result, public_result);
        assert_eq!(trusted_result, public_result);

        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        let mut public_output = sentinel_output;
        let mut private_output = sentinel_output;
        let mut trusted_output = sentinel_output;
        public_result = sentinel_result;
        private_result = sentinel_result;
        trusted_result = sentinel_result;
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                public_handle, &haystack, 8, 72, &mut public_result, &wrong_identity,
                &mut public_output,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(
            call_exclusive_compiler_private_dynamic_rows_preflight_v2(
                private_handle, &haystack, 8, 72, &mut private_result, &wrong_identity,
                &mut private_output,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(
            call_exclusive_compiler_private_dynamic_rows_preflight_v3(
                trusted_handle, &haystack, 8, 72, &mut trusted_result, &wrong_identity,
                &mut trusted_output,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(public_result, sentinel_result);
        assert_eq!(private_result, sentinel_result);
        assert_eq!(trusted_result, sentinel_result);
        assert_eq!(public_output, sentinel_output);
        assert_eq!(private_output, sentinel_output);
        assert_eq!(trusted_output, sentinel_output);

        for handle in [public_handle, private_handle, trusted_handle] {
            // SAFETY: each session is live, uniquely owned, and no call
            // overlaps its destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    fn compiler_private_v4_v5_preflights_leave_identity_output_word_untouched() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile generated-only dynamic-row fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let sentinel_result = FreAotRegexResultV1 { start: 91, end: 92 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 93,
            end: 94,
            native_rows_address: 95,
            cache_generation: 0xfeed_face_cafe_beef,
        };

        type Preflight = fn(
            FreAotRegexExclusiveHandleV1,
            &[u8],
            usize,
            usize,
            &mut FreAotRegexResultV1,
            &[u8; ARTIFACT_IDENTITY_BYTES],
            &mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32;
        let variants: [(&str, Preflight); 2] = [
            ("V4", call_exclusive_compiler_private_dynamic_rows_preflight_v4),
            ("V5", call_exclusive_compiler_private_dynamic_rows_preflight_v5),
        ];
        for (version, preflight) in variants {
            let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
            let mut result = sentinel_result;
            let mut output = sentinel_output;
            assert_eq!(
                preflight(
                    handle,
                    &haystack,
                    8,
                    72,
                    &mut result,
                    &identity,
                    &mut output,
                ),
                STATUS_MATCH,
                "{version} cold completion"
            );
            assert_eq!(output, sentinel_output, "{version} cold output");

            result = sentinel_result;
            output = sentinel_output;
            assert_eq!(
                preflight(
                    handle,
                    &haystack,
                    8,
                    72,
                    &mut result,
                    &identity,
                    &mut output,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER,
                "{version} admitted entry"
            );
            assert_eq!((output.start, output.end), (8, 72), "{version}");
            assert_ne!(output.native_rows_address, 0, "{version}");
            assert_eq!(
                output.cache_generation, sentinel_output.cache_generation,
                "{version} must not write the fourth output word"
            );
            // SAFETY: this transaction is still live and exclusively owns
            // the trusted descriptor until the deopt helper ends its use.
            let descriptor = unsafe {
                &*std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                    output.native_rows_address,
                )
            };
            assert_ne!(descriptor.cache_identity, 0, "{version}");

            result = sentinel_result;
            assert_eq!(
                call_exclusive_dynamic_rows_deopt(handle, &haystack, 8, 72, &mut result),
                STATUS_MATCH,
                "{version} deopt"
            );
            let mut wrong_identity = identity;
            wrong_identity[0] ^= 1;
            result = sentinel_result;
            output = sentinel_output;
            assert_eq!(
                preflight(
                    handle,
                    &haystack,
                    8,
                    72,
                    &mut result,
                    &wrong_identity,
                    &mut output,
                ),
                STATUS_RUNTIME_FAILURE,
                "{version} wrong identity"
            );
            assert_eq!(result, sentinel_result, "{version} wrong-identity result");
            assert_eq!(output, sentinel_output, "{version} wrong-identity output");
            // SAFETY: deopt ended the transaction, the rejected identity did
            // not admit a new one, and this test uniquely owns the live handle.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS,
                "{version} destroy"
            );
        }
    }

    #[test]
    fn compiler_private_v6_returns_descriptor_and_writes_only_exact_window() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile V6 dynamic-row fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let sentinel_result = FreAotRegexResultV1 { start: 91, end: 92 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 93,
            end: 94,
            native_rows_address: 95,
            cache_generation: 0xfeed_face_cafe_beef,
        };

        let mut result = sentinel_result;
        let mut output = sentinel_output;
        let returned = call_exclusive_compiler_private_dynamic_rows_preflight_v6(
            handle,
            &haystack,
            8,
            72,
            &mut result,
            &identity,
            &mut output,
        );
        assert_eq!(returned.status, usize::try_from(STATUS_MATCH).unwrap());
        assert_eq!(returned.native_rows_address, 0);
        assert_eq!(output, sentinel_output, "cold completion output");

        result = sentinel_result;
        output = sentinel_output;
        let returned = call_exclusive_compiler_private_dynamic_rows_preflight_v6(
            handle,
            &haystack,
            8,
            72,
            &mut result,
            &identity,
            &mut output,
        );
        assert_eq!(
            returned.status,
            usize::try_from(STATUS_PARTIAL_PREFLIGHT_ENTER).unwrap()
        );
        assert_ne!(returned.native_rows_address, 0);
        assert_eq!((output.start, output.end), (8, 72));
        assert_eq!(
            output.native_rows_address, sentinel_output.native_rows_address,
            "V6 must not write the third output word"
        );
        assert_eq!(
            output.cache_generation, sentinel_output.cache_generation,
            "V6 must not write the fourth output word"
        );
        // SAFETY: the admitted exclusive transaction keeps the returned
        // descriptor live until the deopt below ends synchronous native use.
        let descriptor = unsafe {
            &*std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                returned.native_rows_address,
            )
        };
        assert_ne!(descriptor.cache_identity, 0);
        assert_ne!(descriptor.rows_address, 0);
        assert_ne!(descriptor.class_map_address, 0);

        result = sentinel_result;
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(handle, &haystack, 8, 72, &mut result),
            STATUS_MATCH
        );
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        result = sentinel_result;
        output = sentinel_output;
        let returned = call_exclusive_compiler_private_dynamic_rows_preflight_v6(
            handle,
            &haystack,
            8,
            72,
            &mut result,
            &wrong_identity,
            &mut output,
        );
        assert_eq!(
            returned.status,
            usize::try_from(STATUS_RUNTIME_FAILURE).unwrap()
        );
        assert_eq!(returned.native_rows_address, 0);
        assert_eq!(result, sentinel_result);
        assert_eq!(output, sentinel_output);
        // SAFETY: the failed identity admitted no transaction and this test
        // uniquely owns the still-live handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_dynamic_rows_preflight_exposes_identity_bound_pointer_provenance() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile dynamic-row runtime fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let start = 8;
        let end = 72;
        let sentinel_result = FreAotRegexResultV1 { start: 91, end: 92 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 93,
            end: 94,
            native_rows_address: 95,
            cache_generation: 96,
        };

        let mut result = sentinel_result;
        let mut output = sentinel_output;
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());
        assert_eq!(output, sentinel_output);

        result = sentinel_result;
        output = sentinel_output;
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel_result);
        assert_eq!((output.start, output.end), (start, end));
        assert_ne!(output.native_rows_address, 0);
        assert_ne!(output.cache_generation, 0);
        // SAFETY: the exclusive transaction is active and the descriptor is
        // owned by the synchronously borrowed prepared workspace.
        let descriptor = unsafe {
            &*std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                output.native_rows_address,
            )
        };
        assert_eq!(descriptor.cache_identity, output.cache_generation);
        assert_ne!(descriptor.rows_address, 0);
        assert_ne!(descriptor.class_map_address, 0);
        assert_eq!(descriptor.initial_flags, 0);
        // SAFETY: all three addresses were explicitly exposed by the same live
        // prepared workspace, and no helper call or re-entry has ended this
        // exclusive preflight transaction.
        let class_map = unsafe {
            &*std::ptr::with_exposed_provenance::<[u8; 256]>(descriptor.class_map_address)
        };
        // SAFETY: the authenticated descriptor bounds this fixed-capacity row
        // prefix, and the exclusive transaction prevents concurrent mutation.
        let rows = unsafe {
            std::slice::from_raw_parts(
                std::ptr::with_exposed_provenance::<u32>(descriptor.rows_address),
                descriptor.live_cells,
            )
        };
        let first_class = class_map[usize::from(haystack[start])];
        let first_cell = usize::try_from(descriptor.initial_row)
            .unwrap()
            .checked_add(usize::from(first_class))
            .unwrap();
        assert!(first_cell < rows.len());
        assert_ne!(rows[first_cell], descriptor.unfilled_cell);

        // A genuine generated side exit uses its dedicated helper, which
        // records deopt feedback before canonical K0 completes.
        result = sentinel_result;
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(handle, &haystack, start, end, &mut result),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());

        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        result = sentinel_result;
        output = sentinel_output;
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &wrong_identity,
                &mut output,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(output, sentinel_output);

        // SAFETY: the handle remains uniquely owned and no call overlaps its
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one raw-ABI differential covers all value contracts and transactional pointer rejection"
    )]
    fn exclusive_dynamic_rows_first_hole_continues_all_value_contracts() {
        for (output_contract, expected_result) in [
            (OutputContract::Exists, FreAotRegexResultV1::default()),
            (
                OutputContract::SelectedEnd,
                FreAotRegexResultV1 { start: 10, end: 10 },
            ),
            (
                OutputContract::Span,
                FreAotRegexResultV1 { start: 8, end: 10 },
            ),
        ] {
            let compiled = compile(
                CompileRequest::new(
                    r"(?-u:(?:a[\x00-\xFF]|[^a][\x00-\xFF]))",
                    Target::x86_64_linux(),
                )
                    .mode(CompileMode::Fast)
                    .output(output_contract),
            )
            .expect("compile scanner-free dynamic-row fixture");
            assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
            assert_eq!(
                compiled.program().exact_match_width(),
                Some(2),
                "{output_contract:?} fixture width"
            );
            let identity = compiled.receipt().program_sha256;
            let serialized = compiled.program().serialize().unwrap();
            let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
            let mut warmed = vec![b'!'; 80];
            warmed[8..10].copy_from_slice(b"aa");
            let start = 8;
            let end = 72;
            let mut result = FreAotRegexResultV1 {
                start: usize::MAX,
                end: usize::MAX,
            };
            let mut preflight = FreAotRegexDynamicRowsPreflightV1::default();
            assert_eq!(
                call_exclusive_dynamic_rows_preflight(
                    handle,
                    &warmed,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &mut preflight,
                ),
                STATUS_MATCH,
                "cold {output_contract:?}"
            );
            assert_eq!(result, expected_result);

            let mut novel = warmed.clone();
            novel[start..start + 2].copy_from_slice(b"ba");
            let sentinel = FreAotRegexResultV1 { start: 91, end: 92 };
            result = sentinel;
            preflight = FreAotRegexDynamicRowsPreflightV1::default();
            assert_eq!(
                call_exclusive_dynamic_rows_preflight(
                    handle,
                    &novel,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &mut preflight,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER,
                "warm {output_contract:?}"
            );
            assert_eq!(result, sentinel);
            assert_eq!((preflight.start, preflight.end), (start, end));

            // SAFETY: this is the live synchronous transaction admitted just
            // above; descriptor and cache addresses remain exclusively owned
            // until the continuation helper is called.
            let descriptor = unsafe {
                *std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                    preflight.native_rows_address,
                )
            };
            let class_map = unsafe {
                &*std::ptr::with_exposed_provenance::<[u8; 256]>(
                    descriptor.class_map_address,
                )
            };
            let rows = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::with_exposed_provenance::<u32>(descriptor.rows_address),
                    descriptor.live_cells,
                )
            };
            let root_cell = usize::try_from(descriptor.initial_row).unwrap()
                + usize::from(class_map[usize::from(novel[start])]);
            assert_eq!(rows[root_cell], descriptor.unfilled_cell);
            assert_eq!(descriptor.learned_loop_row_count, 0);
            let continuation = FreAotRegexDynamicRowsContinuationV1 {
                current_row: usize::try_from(descriptor.initial_row).unwrap(),
                resume_position: start,
                pending_valid: 0,
                pending_end: 0,
                cache_identity: preflight.cache_generation,
            };

            // Invalid raw storage is rejected transactionally without
            // consuming the valid admission needed by the following call.
            result = sentinel;
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1(
                        handle,
                        novel.as_ptr(),
                        novel.len(),
                        start,
                        end,
                        &raw mut result,
                        identity.as_ptr(),
                        std::ptr::null(),
                    )
                },
                STATUS_INVALID_ARGUMENT
            );
            assert_eq!(result, sentinel);

            assert_eq!(
                call_exclusive_dynamic_rows_continue(
                    handle,
                    &novel,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &continuation,
                ),
                STATUS_MATCH
            );
            assert_eq!(result, expected_result, "{output_contract:?}");

            // SAFETY: this test uniquely owns the completed session.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "success and raw/private authentication failures share one single-use dynamic Span lifecycle"
    )]
    fn exclusive_dynamic_span_postflight_authenticates_and_recovers() {
        let compiled = compile(
            CompileRequest::new(
                r"(?-u:(?:a|[^a][\x00-\xFF]))",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Fast)
            .output(OutputContract::Span),
        )
        .expect("compile scanner-free variable Span fixture");
        assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
        assert_eq!(compiled.program().exact_match_width(), None);
        assert!(compiled.module().prepared_entry_symbol().is_some());
        assert_eq!(
            compiled
                .module()
                .required_prepared_dynamic_rows_continue_runtime_symbol(),
            Some("fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1")
        );
        assert_eq!(
            compiled
                .module()
                .required_prepared_dynamic_rows_span_recovery_runtime_symbol(),
            Some("fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1")
        );

        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        let start = 8_usize;
        let end = 72_usize;
        haystack[start..start + 2].copy_from_slice(b"bq");
        let selected_end = start + 2;
        let expected = FreAotRegexResultV1 {
            start,
            end: selected_end,
        };
        let sentinel = FreAotRegexResultV1 { start: 91, end: 92 };

        let mut result = sentinel;
        let mut preflight = FreAotRegexDynamicRowsPreflightV1::default();
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut preflight,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected);

        let preflight = || {
            let mut result = sentinel;
            let mut preflight = FreAotRegexDynamicRowsPreflightV1::default();
            assert_eq!(
                call_exclusive_dynamic_rows_preflight(
                    handle,
                    &haystack,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &mut preflight,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER
            );
            assert_eq!(result, sentinel);
            assert_eq!((preflight.start, preflight.end), (start, end));
            preflight
        };

        preflight();
        result = sentinel;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected);

        // The exact dynamic admission is single use.
        result = sentinel;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // Raw pointer rejection happens before Rust can consume the otherwise
        // valid ticket; the following authenticated call still succeeds.
        preflight();
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    end,
                    &raw mut result,
                    std::ptr::null(),
                    selected_end,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected);

        // A foreign identity consumes the capability before rejection.
        preflight();
        result = sentinel;
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &wrong_identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE,
            "foreign postflight must consume the ticket"
        );

        // A cross-window call and an in-range but semantically impossible
        // endpoint are both authenticated failures that consume their ticket.
        preflight();
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start + 1,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        preflight();
        result = sentinel;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                start + 1,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // SAFETY: the test uniquely owns the completed exclusive session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_frozen_dynamic_span_postflight_reuses_owner_across_windows_and_revokes() {
        let compiled = compile(
            CompileRequest::new(
                r"(?-u:(?:a|[^a][\x00-\xFF]))",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Fast)
            .output(OutputContract::Span),
        )
        .expect("compile scanner-free variable Span fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive(&serialized);
        // SAFETY: the test uniquely owns this live allocation until the
        // explicit destroy below.
        let prepared = unsafe { &*handle.0.cast::<PreparedAotRegex>() };
        assert!(prepared.frozen_header.has_dynamic_rows());
        assert!(prepared.frozen_dynamic_rows.is_some());

        let mut haystack = vec![b'!'; 80];
        let start = 8_usize;
        let end = 72_usize;
        haystack[start..start + 2].copy_from_slice(b"bq");
        let selected_end = start + 2;
        let expected = FreAotRegexResultV1 {
            start,
            end: selected_end,
        };
        let mut alternate = vec![b'!'; 96];
        let alternate_start = 13_usize;
        let alternate_end = 81_usize;
        alternate[alternate_start] = b'a';
        let alternate_selected_end = alternate_start + 1;
        let alternate_expected = FreAotRegexResultV1 {
            start: alternate_start,
            end: alternate_selected_end,
        };
        let sentinel = FreAotRegexResultV1 { start: 91, end: 92 };

        for (label, input, window_start, window_end, endpoint, expected) in [
            ("two-byte", haystack.as_slice(), start, end, selected_end, expected),
            (
                "one-byte",
                alternate.as_slice(),
                alternate_start,
                alternate_end,
                alternate_selected_end,
                alternate_expected,
            ),
        ] {
            let mut result = sentinel;
            assert_eq!(
                call_exclusive_recover_dynamic_span(
                    handle,
                    input,
                    window_start,
                    window_end,
                    &mut result,
                    &identity,
                    endpoint,
                ),
                STATUS_MATCH,
                "compact {label} invocation"
            );
            assert_eq!(result, expected);
            assert!(
                exclusive_frozen_header_is_active(handle),
                "successful reverse-only recovery must retain the compact owner"
            );
        }

        // A foreign identity is authenticated before reverse K0 and revokes
        // the otherwise reusable compact owner.
        let mut rejected = sentinel;
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut rejected,
                &wrong_identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(rejected, sentinel);
        assert!(
            !exclusive_frozen_header_is_active(handle),
            "every compact rejection must permanently revoke the owner"
        );

        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut rejected,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE,
            "a revoked owner cannot bypass the missing mutable preflight ticket"
        );
        assert_eq!(rejected, sentinel);

        // SAFETY: the test uniquely owns the completed exclusive session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );

        // An in-range endpoint that the language cannot produce likewise
        // revokes a fresh owner rather than remaining replayable.
        let impossible_handle = prepare_exclusive(&serialized);
        assert!(exclusive_frozen_header_is_active(impossible_handle));
        let impossible = vec![b'!'; 80];
        let mut impossible_result = sentinel;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                impossible_handle,
                &impossible,
                start,
                end,
                &mut impossible_result,
                &identity,
                start + 1,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(impossible_result, sentinel);
        assert!(!exclusive_frozen_header_is_active(impossible_handle));
        // SAFETY: the test uniquely owns the rejected exclusive session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(impossible_handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_dynamic_rows_continuation_preserves_pending_endpoint() {
        let compiled = compile(
            CompileRequest::new(r"(?-u:(?:ab?|[^a]b?))", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile scanner-free pending-end fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut warmed = vec![b'!'; 80];
        let start = 8;
        let end = 72;
        warmed[start..start + 2].copy_from_slice(b"ab");
        let mut result = FreAotRegexResultV1::default();
        let mut preflight = FreAotRegexDynamicRowsPreflightV1::default();
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &warmed,
                start,
                end,
                &mut result,
                &identity,
                &mut preflight,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 10, end: 10 });

        let mut novel = warmed.clone();
        novel[start + 1] = b'a';
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &novel,
                start,
                end,
                &mut result,
                &identity,
                &mut preflight,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        // SAFETY: descriptor reads are confined to the just-admitted
        // exclusive transaction and precede its continuation call.
        let descriptor = unsafe {
            *std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                preflight.native_rows_address,
            )
        };
        let class_map = unsafe {
            &*std::ptr::with_exposed_provenance::<[u8; 256]>(descriptor.class_map_address)
        };
        let rows = unsafe {
            std::slice::from_raw_parts(
                std::ptr::with_exposed_provenance::<u32>(descriptor.rows_address),
                descriptor.live_cells,
            )
        };
        let first = rows[usize::try_from(descriptor.initial_row).unwrap()
            + usize::from(class_map[usize::from(novel[start])])];
        assert_ne!(first & descriptor.accept_mask, 0);
        let current_row = (first & descriptor.next_row_token_mask)
            .checked_sub(1)
            .expect("pending root cell retains its higher-priority successor");
        let hole = usize::try_from(current_row).unwrap()
            + usize::from(class_map[usize::from(novel[start + 1])]);
        assert_eq!(rows[hole], descriptor.unfilled_cell);
        let continuation = FreAotRegexDynamicRowsContinuationV1 {
            current_row: usize::try_from(current_row).unwrap(),
            resume_position: start + 1,
            pending_valid: 1,
            pending_end: start + 1,
            cache_identity: preflight.cache_generation,
        };
        assert_eq!(
            call_exclusive_dynamic_rows_continue(
                handle,
                &novel,
                start,
                end,
                &mut result,
                &identity,
                &continuation,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 9, end: 9 });

        // SAFETY: this test uniquely owns the completed session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_dynamic_rows_short_fallback_settles_local_success_without_backoff() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile alternating dynamic-row fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let start = 8;
        let end = 72;
        let mut result = FreAotRegexResultV1::default();
        let mut output = FreAotRegexDynamicRowsPreflightV1::default();

        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_MATCH,
            "cold canonical search warms the K0 root"
        );

        for cycle in 0..3 {
            result = FreAotRegexResultV1::default();
            output = FreAotRegexDynamicRowsPreflightV1::default();
            assert_eq!(
                call_exclusive_dynamic_rows_preflight(
                    handle,
                    &haystack,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &mut output,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER,
                "long local-success transaction {cycle} must remain admitted"
            );

            // Model the generated scan returning locally, followed by a
            // separate short call that bypasses preflight in the wrapper.
            // The ordinary helper must settle that success, not report a
            // side exit for the preceding long transaction.
            result = FreAotRegexResultV1::default();
            assert_eq!(
                call_exclusive(handle, &haystack, 0, 16, &mut result),
                STATUS_NO_MATCH,
                "short ordinary fallback {cycle}"
            );
        }

        output = FreAotRegexDynamicRowsPreflightV1::default();
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER,
            "alternating local-success/short calls must not trigger deopt backoff"
        );

        // True side exits still advance the adaptive policy and two
        // consecutive deopts activate its first bypass interval.
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(handle, &haystack, start, end, &mut result),
            STATUS_MATCH
        );
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(handle, &haystack, start, end, &mut result),
            STATUS_MATCH
        );
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_MATCH,
            "two genuine side exits must retain the existing backoff behavior"
        );

        // SAFETY: the handle remains uniquely owned and no call overlaps its
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "the test deliberately constructs a misaligned out pointer and verifies rejection before use"
    )]
    fn null_misaligned_and_invalid_windows_return_status_two() {
        let program = program("a", OutputContract::Span);
        let haystack = b"a";
        let mut result = FreAotRegexResultV1::default();

        // SAFETY: null is passed deliberately; the helper checks it before
        // constructing any reference or slice.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_v1(
                    std::ptr::null(),
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    1,
                    &raw mut result,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        // SAFETY: null is passed deliberately and checked before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_v1(
                    program.as_ptr(),
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    &raw mut result,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        // SAFETY: null is passed deliberately and checked before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_v1(
                    program.as_ptr(),
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    1,
                    std::ptr::null_mut(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            call(&program, haystack, 1, 0, &mut result),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            call(&program, haystack, 0, 2, &mut result),
            STATUS_INVALID_ARGUMENT
        );

        let mut storage = [0_u8; size_of::<FreAotRegexResultV1>() * 2];
        let base = storage.as_mut_ptr();
        let aligned = base.align_offset(align_of::<FreAotRegexResultV1>());
        assert_ne!(aligned, usize::MAX);
        // The extra byte after an aligned address is necessarily misaligned
        // for this two-usize result.
        let misaligned_offset = aligned.checked_add(1).expect("small alignment offset");
        let misaligned = base
            .wrapping_add(misaligned_offset)
            .cast::<FreAotRegexResultV1>();
        // SAFETY: the deliberately misaligned pointer is rejected before use;
        // all readable input extents remain valid.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_v1(
                    program.as_ptr(),
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    1,
                    misaligned,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
    }

    #[test]
    fn malformed_program_returns_status_three_without_touching_result() {
        let mut program = program("a", OutputContract::Span);
        program[0] ^= 1;
        let mut result = FreAotRegexResultV1 { start: 41, end: 43 };
        // SAFETY: the complete mutated allocation remains readable; only its
        // validated contents are deliberately malformed.
        let status = unsafe {
            fre_aot_regex_runtime_search_v1(
                program.as_ptr(),
                b"a".as_ptr(),
                1,
                0,
                1,
                &raw mut result,
            )
        };
        assert_eq!(status, STATUS_RUNTIME_FAILURE);
        assert_eq!(result, FreAotRegexResultV1 { start: 41, end: 43 });
    }

    #[test]
    fn runtime_program_round_trip_is_canonical() {
        for (pattern, output) in [
            (r"(?m:^a\b)", OutputContract::Exists),
            (r"\b(?:ab|cd)+$", OutputContract::SelectedEnd),
            (r"(?m:^[[:word:]]+)$", OutputContract::Span),
        ] {
            let bytes = program(pattern, output);
            let decoded = CompiledProgram::deserialize(&bytes).expect("deserialize");
            assert_eq!(decoded.serialize().expect("reserialize"), bytes);
        }
    }

    #[test]
    fn prepared_runtime_reuses_owned_program_and_workspace() {
        let bytes = program(r"(?m:^alpha\b)", OutputContract::Span);
        let mut prepared = PreparedAotRegex::deserialize(&bytes).expect("prepare once");
        for (haystack, expected) in [
            (b"x\nalpha beta".as_slice(), Some((2, 7))),
            (b"alpha".as_slice(), Some((0, 5))),
            (b"xalpha".as_slice(), None),
        ] {
            assert_eq!(
                prepared
                    .search(haystack, SearchWindow::full(haystack))
                    .expect("reused search"),
                MatchResult::Span(expected)
            );
        }
    }

    #[test]
    fn borrowed_aot_match_checks_and_exposes_its_original_bytes() {
        let haystack = b"xabz";
        let matched = AotMatch::from_span(haystack, 1, 3).expect("valid span");
        assert_eq!(matched.start(), 1);
        assert_eq!(matched.end(), 3);
        assert_eq!(matched.len(), 2);
        assert!(!matched.is_empty());
        assert_eq!(matched.range(), 1..3);
        assert_eq!(matched.as_bytes(), b"ab");
        assert_eq!(
            format!("{matched:?}"),
            r#"AotMatch { start: 1, end: 3, bytes: "ab" }"#
        );
        let matched_bytes: &[u8] = matched.into();
        let matched_range: std::ops::Range<usize> = matched.into();
        assert_eq!(matched_bytes, b"ab");
        assert_eq!(matched_range, 1..3);

        let empty = AotMatch::from_span(haystack, 4, 4).expect("empty EOF span");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.as_bytes(), b"");
        assert!(AotMatch::from_span(haystack, 3, 2).is_none());
        assert!(AotMatch::from_span(haystack, 0, 5).is_none());

        let invalid_utf8 = [0xff];
        let invalid = AotMatch::from_span(&invalid_utf8, 0, 1).expect("valid byte span");
        assert!(format!("{invalid:?}").contains(r#"bytes: "\xff""#));
    }

    #[test]
    fn prepared_find_and_find_at_return_borrowed_spans() {
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            let mut prepared = prepared("ab+", OutputContract::Span, mode);
            let haystack = b"xxabbb ab";
            let first = prepared.find(haystack).expect("find").expect("first match");
            assert_eq!(first.range(), 2..6);
            assert_eq!(first.as_bytes(), b"abbb");

            let second = prepared
                .find_at(haystack, first.end())
                .expect("find_at")
                .expect("second match");
            assert_eq!(second.range(), 7..9);
            assert_eq!(second.as_bytes(), b"ab");
            assert_eq!(
                prepared.find_at(haystack, second.end()).expect("EOF find"),
                None
            );
        }
    }

    #[test]
    fn prepared_find_iter_matches_rust_byte_empty_progress_semantics() {
        let cases: Vec<(&str, &[u8], Vec<(usize, usize)>)> = vec![
            ("", b"", vec![(0, 0)]),
            ("", &[0xC3, 0xA9], vec![(0, 0), (1, 1), (2, 2)]),
            ("", &[0xFF, b'a'], vec![(0, 0), (1, 1), (2, 2)]),
            ("a|", b"a", vec![(0, 1)]),
            ("a?", b"ba", vec![(0, 0), (1, 2)]),
            ("(?:ab|)", b"ab", vec![(0, 2)]),
            ("(?:ab|)", b"xab", vec![(0, 0), (1, 3)]),
        ];
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            for (pattern, haystack, expected) in &cases {
                let mut prepared = prepared(pattern, OutputContract::Span, mode);
                assert_eq!(
                    collected_spans(&mut prepared, haystack),
                    *expected,
                    "mode={mode:?}, pattern={pattern:?}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn prepared_iteration_retains_original_assertion_context() {
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            let mut absolute = prepared("^a", OutputContract::Span, mode);
            assert_eq!(absolute.find_at(b"xa", 1).expect("absolute find"), None);

            let mut boundary = prepared(r"\ba", OutputContract::Span, mode);
            assert_eq!(boundary.find_at(b"xa", 1).expect("boundary find"), None);
            assert_eq!(
                boundary
                    .find_at(b"x a", 1)
                    .expect("contextual find")
                    .expect("match")
                    .range(),
                2..3
            );

            let mut multiline = prepared(r"(?m:^a)", OutputContract::Span, mode);
            assert_eq!(collected_spans(&mut multiline, b"x\na\nxa"), vec![(2, 3)]);
        }
    }

    #[test]
    fn prepared_find_reports_output_contract_and_invalid_start() {
        for output in [OutputContract::Exists, OutputContract::SelectedEnd] {
            let mut prepared = prepared("a", output, CompileMode::Fast);
            assert!(matches!(
                prepared.find(b"a"),
                Err(AotRegexFindError::OutputContract { actual }) if actual == output
            ));
            assert!(matches!(
                prepared.find_at(b"a", 0),
                Err(AotRegexFindError::OutputContract { actual }) if actual == output
            ));
            assert!(matches!(
                prepared.find_iter(b"a"),
                Err(AotRegexFindError::OutputContract { actual }) if actual == output
            ));
        }

        let mut prepared = prepared("a", OutputContract::Span, CompileMode::Fast);
        assert!(matches!(
            prepared.find_at(b"a", 2),
            Err(AotRegexFindError::Search(CompileError::InvalidWindow {
                start: 2,
                end: 1,
                haystack_len: 1,
            }))
        ));
    }

    #[test]
    fn prepared_find_iterator_is_fused_and_releases_the_workspace_on_drop() {
        fn assert_fused<I: std::iter::FusedIterator>(_: &I) {}

        let mut prepared = prepared("a", OutputContract::Span, CompileMode::Fast);
        {
            let mut matches = prepared.find_iter(b"a").expect("Span iterator");
            assert_fused(&matches);
            assert_eq!(
                matches.next().expect("one item").expect("search").range(),
                0..1
            );
            assert!(matches.next().is_none());
            assert!(matches.next().is_none());
        }
        assert_eq!(
            prepared
                .find(b"za")
                .expect("reused workspace")
                .expect("match")
                .range(),
            1..2
        );
    }

    #[test]
    fn prepared_c_handle_owns_program_and_matches_generated_nfa_windows() {
        let mut cases = Vec::new();
        for maximum in 1..=3 {
            cases.push((
                format!(r"(?m:^(?:ab|a){{1,{maximum}}}\b)"),
                CompileLimitsV1::default(),
                EngineSelectionReason::ContextAssertions,
            ));
        }
        let mut limited = CompileLimitsV1::default();
        limited.determinize.max_states = 0;
        cases.push((
            "(?:ab|ac|ad)+z".to_owned(),
            limited,
            EngineSelectionReason::DeterminizationResourceLimit,
        ));
        let haystacks = generated_haystacks();

        for (pattern, limits, expected_reason) in cases {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let compiled = compile(
                    CompileRequest::new(&pattern, Target::x86_64_linux())
                        .mode(CompileMode::Optimizing)
                        .limits(limits)
                        .output(output),
                )
                .unwrap_or_else(|error| panic!("compile {pattern:?}: {error}"));
                assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
                assert_eq!(compiled.receipt().engine_selection_reason, expected_reason);
                let serialized = compiled.program().serialize().expect("serialize");
                let handle = prepare_handle(&serialized);
                let exclusive = prepare_exclusive(&serialized);
                drop(serialized);

                for haystack in &haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let expected = expected_ffi(
                                compiled
                                    .search(haystack, SearchWindow::new(start, end))
                                    .expect("portable search"),
                            );
                            let mut actual = FreAotRegexResultV1 {
                                start: usize::MAX,
                                end: usize::MAX,
                            };
                            let status = call_prepared(handle, haystack, start, end, &mut actual);
                            assert_eq!(
                                (status, actual),
                                expected,
                                "pattern={pattern:?}, output={output:?}, haystack={haystack:?}, window={start}..{end}"
                            );
                            let mut exclusive_actual = FreAotRegexResultV1 {
                                start: usize::MAX,
                                end: usize::MAX,
                            };
                            let exclusive_status = call_exclusive(
                                exclusive,
                                haystack,
                                start,
                                end,
                                &mut exclusive_actual,
                            );
                            assert_eq!(
                                (exclusive_status, exclusive_actual),
                                expected,
                                "exclusive pattern={pattern:?}, output={output:?}, haystack={haystack:?}, window={start}..{end}"
                            );
                        }
                    }
                }
                assert_eq!(
                    fre_aot_regex_runtime_destroy_prepared_v1(handle),
                    STATUS_SUCCESS
                );
                // SAFETY: this is the unique live exclusive handle and no
                // search overlaps destruction.
                assert_eq!(
                    unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(exclusive) },
                    STATUS_SUCCESS
                );
            }
        }
    }

    #[test]
    fn exclusive_prepared_runtime_executes_retained_resource_rows() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let mut limits = CompileLimitsV1::default();
            limits.determinize.max_states = if output == OutputContract::Exists {
                8
            } else {
                16
            };
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .limits(limits)
                    .output(output),
            )
            .expect("compile retained resource fallback");
            let reference = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Fast)
                    .output(output),
            )
            .expect("compile universal reference");
            assert_eq!(
                compiled.receipt().engine_selection_reason,
                EngineSelectionReason::DeterminizationResourceLimit
            );
            let stats = compiled
                .program()
                .partial_dfa_stats()
                .expect("partial stats")
                .expect("retained rows");
            assert!(stats.complete_rows > 0);
            assert!(stats.complete_rows < stats.discovered_states);
            assert!(stats.resume_frontiers > 0);

            let serialized = compiled.program().serialize().expect("serialize partial");
            assert_ne!(serialized[15] & (1 << 3), 0, "V4 partial flag");
            let mut direct =
                PreparedAotRegex::deserialize(&serialized).expect("prepare direct resource owner");
            assert!(
                direct.fully_prefilled_fallback.is_some(),
                "resource fallback must retain its setup receipt for {output:?}"
            );
            if output == OutputContract::Span {
                assert_eq!(compiled.program().exact_match_width(), None);
            }
            assert!(
                direct.frozen_dynamic_rows.is_some(),
                "eligible resource fallback must retain a compact owner for {output:?}"
            );
            assert!(direct.frozen_header.has_dynamic_rows(), "{output:?}");
            let exclusive = prepare_exclusive(&serialized);
            let short = b"cbbbbx";
            let mut long = vec![b'x'; 256];
            long.extend_from_slice(short);
            let long_expected = reference
                .search(&long, SearchWindow::full(&long))
                .expect("universal long reference search");
            direct.deactivate_frozen_header();
            assert_eq!(
                direct
                    .search_exclusive(&long, SearchWindow::full(&long))
                    .expect("post-revocation receipt-backed search"),
                long_expected,
                "post-revocation {output:?}"
            );
            assert!(!direct.frozen_header.is_active());
            for haystack in [short.as_slice(), long.as_slice()] {
                let expected = expected_ffi(
                    reference
                        .search(haystack, SearchWindow::full(haystack))
                        .expect("universal reference search"),
                );
                let mut actual = FreAotRegexResultV1::default();
                assert_eq!(
                    (
                        call_exclusive(exclusive, haystack, 0, haystack.len(), &mut actual),
                        actual,
                    ),
                    expected,
                    "output={output:?}, len={}",
                    haystack.len()
                );
            }
            // SAFETY: this test owns the unique live exclusive handle and no
            // call overlaps destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(exclusive) },
                STATUS_SUCCESS
            );
        }

        // Unlike the variable-width Span case above, an exact positive width
        // needs no reverse-row capability and may safely prefer compact rows.
        // Search a small ceiling range so the fixture remains a genuine
        // retained-resource fallback as determinization evolves.
        let fixed_pattern = r"(?:ab|ba|cd|dc|ef|fe){4}";
        let (fixed, serialized, mut direct) = (2..=64)
            .find_map(|max_states| {
                let mut limits = CompileLimitsV1::default();
                limits.determinize.max_states = max_states;
                let candidate = compile(
                    CompileRequest::new(fixed_pattern, Target::x86_64_linux())
                        .mode(CompileMode::Optimizing)
                        .limits(limits)
                        .output(OutputContract::Span),
                )
                .ok()?;
                if candidate.program().exact_match_width() != Some(8)
                    || candidate.receipt().engine_selection_reason
                        != EngineSelectionReason::DeterminizationResourceLimit
                {
                    return None;
                }
                let stats = candidate.program().partial_dfa_stats().ok()??;
                if stats.complete_rows == 0
                    || stats.complete_rows >= stats.discovered_states
                    || stats.resume_frontiers == 0
                {
                    return None;
                }
                let serialized = candidate.program().serialize().ok()?;
                let direct = PreparedAotRegex::deserialize(&serialized).ok()?;
                (direct.fully_prefilled_fallback.is_some()
                    && direct.frozen_dynamic_rows.is_some()
                    && direct.frozen_header.has_dynamic_rows())
                .then_some((candidate, serialized, direct))
            })
            .expect("fixed-width Span with retained receipt and compact owner");
        assert_eq!(fixed.program().exact_match_width(), Some(8));
        assert!(direct.fully_prefilled_fallback.is_some());
        assert!(direct.frozen_dynamic_rows.is_some());
        assert!(direct.frozen_header.has_dynamic_rows());

        let reference = compile(
            CompileRequest::new(fixed_pattern, Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile fixed-width universal reference");
        let mut haystack = vec![b'!'; 256];
        haystack.extend_from_slice(b"abababab");
        let window = SearchWindow::full(&haystack);
        let expected = reference
            .search(&haystack, window)
            .expect("fixed-width universal reference search");
        direct.deactivate_frozen_header();
        assert_eq!(
            direct
                .search_exclusive(&haystack, window)
                .expect("fixed-width post-revocation receipt-backed search"),
            expected
        );
        assert!(!direct.frozen_header.is_active());

        let exclusive = prepare_exclusive(&serialized);
        let mut actual = FreAotRegexResultV1::default();
        assert_eq!(
            (
                call_exclusive(
                    exclusive,
                    &haystack,
                    window.start(),
                    window.end(),
                    &mut actual,
                ),
                actual,
            ),
            expected_ffi(expected)
        );
        // SAFETY: this test owns the unique live exclusive handle and no call
        // overlaps destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(exclusive) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_preflight_authenticates_without_consuming_prepared_state() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix preflight fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"!!abacz??";
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        assert_eq!(
            call_exclusive_static_prefix_preflight(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        let mut wrong_identity = identity;
        wrong_identity[17] ^= 0x80;
        assert_eq!(
            call_exclusive_static_prefix_preflight(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &wrong_identity,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        let mut fallback = FreAotRegexResultV1::default();
        assert_eq!(
            call_exclusive(handle, haystack, 0, haystack.len(), &mut fallback),
            STATUS_MATCH
        );
        assert_eq!(fallback, FreAotRegexResultV1 { start: 2, end: 7 });
        assert!(!exclusive_frozen_header_is_active(handle));

        // The immutable identity remains authoritative after a general search
        // retires unrelated frozen-row capabilities. A later static-prefix
        // call can still complete natively or deopt through the same handle.
        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_preflight(
                handle,
                haystack,
                2,
                7,
                &mut result,
                &identity,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);

        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_recover_span(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                7,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 2, end: 7 });

        // SAFETY: this test owns the unique live handle and no operation
        // overlaps destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_v2_descriptor_and_ticket_boundary_fails_closed() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix V2 boundary fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = vec![b'x'; 128];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        let truncated = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &truncated,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        let mut oversized = truncated;
        oversized[2] = u32::try_from(
            STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAX_BYTES / std::mem::size_of::<u32>() + 1,
        )
        .unwrap();
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &oversized,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        let mut bad_magic = truncated;
        bad_magic[2] = u32::try_from(bad_magic.len()).unwrap();
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &bad_magic,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(!exclusive_frozen_header_is_active(handle));

        // SAFETY: this test uniquely owns the live handle and all supplied
        // extents. No successful V2 preflight exists, so both ticket consumers
        // must reject without initializing the result.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut result,
                    0,
                    64,
                    0,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    &raw mut result,
                    identity.as_ptr(),
                    64,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one lifecycle ledger keeps initial publication, alternate legacy revocation, and wrong-artifact fallback transactional"
    )]
    fn frozen_header_is_first_and_every_legacy_or_fallback_path_revokes_it() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile retained frozen fixture");
        assert_eq!(
            compiled.receipt().engine_selection_reason,
            EngineSelectionReason::DeterminizationResourceLimit
        );
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let haystack = b"xxcbbbbx";
        let window = SearchWindow::full(haystack);
        let expected = compiled
            .search(haystack, window)
            .expect("portable expected result");
        let expected_ffi = expected_ffi(expected);

        let mut direct = PreparedAotRegex::deserialize(&serialized).expect("prepare direct Rust");
        assert!(direct.fully_prefilled_fallback.is_some());
        assert!(
            direct.frozen_dynamic_rows.is_some(),
            "a closed compact projection should own the native entry while the retained receipt remains available to fallbacks"
        );
        assert!(direct.frozen_header.has_dynamic_rows());
        assert!(direct.frozen_header.is_active());
        assert_eq!(*direct.frozen_header.artifact_identity(), identity);
        assert_eq!(
            (&raw const direct).cast::<u8>().addr(),
            (&raw const direct.frozen_header).cast::<u8>().addr(),
            "the opaque prepared allocation must begin with the versioned header"
        );
        assert_eq!(direct.search(haystack, window).unwrap(), expected);
        assert!(!direct.frozen_header.is_active());
        assert_eq!(direct.search(haystack, window).unwrap(), expected);
        assert!(!direct.frozen_header.is_active(), "a legacy search cannot reactivate");

        let legacy = prepare_exclusive(&serialized);
        assert!(exclusive_frozen_header_is_active(legacy));
        assert_eq!(exclusive_frozen_header_identity(legacy), identity);
        let mut legacy_result = FreAotRegexResultV1 {
            start: usize::MAX,
            end: usize::MAX,
        };
        assert_eq!(
            (
                call_exclusive(legacy, haystack, 0, haystack.len(), &mut legacy_result),
                legacy_result,
            ),
            expected_ffi
        );
        assert!(!exclusive_frozen_header_is_active(legacy));
        let mut fallback_after_legacy = FreAotRegexResultV1::default();
        assert_eq!(
            (
                call_exclusive_frozen_fallback(
                    legacy,
                    haystack,
                    0,
                    haystack.len(),
                    &mut fallback_after_legacy,
                    &identity,
                ),
                fallback_after_legacy,
            ),
            expected_ffi
        );
        assert!(
            !exclusive_frozen_header_is_active(legacy),
            "a correct fallback after legacy use cannot restore the seal"
        );
        // SAFETY: this test owns the unique live allocation and no call overlaps
        // its destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(legacy) },
            STATUS_SUCCESS
        );

        let alternate = prepare_exclusive(&serialized);
        assert!(exclusive_frozen_header_is_active(alternate));
        assert!(matches!(
            call_partial_should_enter(alternate, 4_096),
            PARTIAL_ENTRY_BYPASS | PARTIAL_ENTRY_ENTER
        ));
        assert!(
            !exclusive_frozen_header_is_active(alternate),
            "an alternate legacy admission entry must permanently kill the seal"
        );
        // SAFETY: unique, live, non-overlapping handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(alternate) },
            STATUS_SUCCESS
        );

        let wrong_artifact = prepare_exclusive(&serialized);
        assert!(exclusive_frozen_header_is_active(wrong_artifact));
        let mut mismatched_identity = identity;
        mismatched_identity[0] ^= 0x80;
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut wrong_result = sentinel;
        assert_eq!(
            call_exclusive_frozen_fallback(
                wrong_artifact,
                haystack,
                0,
                haystack.len(),
                &mut wrong_result,
                &mismatched_identity,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(wrong_result, sentinel, "wrong-artifact output is transactional");
        assert!(
            !exclusive_frozen_header_is_active(wrong_artifact),
            "wrong-artifact fallback must revoke before authentication"
        );
        let mut recovered = FreAotRegexResultV1::default();
        assert_eq!(
            (
                call_exclusive_frozen_fallback(
                    wrong_artifact,
                    haystack,
                    0,
                    haystack.len(),
                    &mut recovered,
                    &identity,
                ),
                recovered,
            ),
            expected_ffi
        );
        assert!(!exclusive_frozen_header_is_active(wrong_artifact));
        // SAFETY: unique, live, non-overlapping handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(wrong_artifact) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn compact_dynamic_owner_survives_moves_and_legacy_revocation() {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 0;
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Exists),
        )
        .expect("compile compact dynamic owner fixture");
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let haystack = b"xxabacz";
        let window = SearchWindow::full(haystack);
        let expected = compiled.search(haystack, window).expect("portable result");

        let prepared = PreparedAotRegex::deserialize(&serialized).expect("prepare compact owner");
        assert!(prepared.fully_prefilled_fallback.is_none());
        assert!(prepared.frozen_dynamic_rows.is_some());
        assert!(prepared.frozen_header.has_dynamic_rows());
        let mut owners = vec![prepared];
        let mut prepared = owners.pop().expect("move prepared owner through a container");
        assert!(prepared.frozen_header.has_dynamic_rows());
        assert_eq!(prepared.search(haystack, window).unwrap(), expected);
        assert!(!prepared.frozen_header.is_active());
        assert!(prepared.frozen_dynamic_rows.is_some());
        assert_eq!(prepared.search(haystack, window).unwrap(), expected);
        assert!(!prepared.frozen_header.is_active());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all output contracts and raw-boundary authentication failures share the same exclusive continuation lifecycle"
    )]
    fn exclusive_partial_resume_abi_authenticates_and_continues_without_replay() {
        let cases = [
            (
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                OutputContract::Exists,
                8,
                b"xxcbbbbyyy".as_slice(),
                0,
                5,
                None,
            ),
            (
                r"(?:a+Q|[b-c][a-b]{1,10}(?:z[a-b]+|z))",
                OutputContract::SelectedEnd,
                10,
                b"cbza".as_slice(),
                2,
                3,
                Some(3),
            ),
            (
                r"(?:a+Q|[b-c][a-b]{1,10}(?:z[a-b]+|z))",
                OutputContract::Span,
                10,
                b"cbza".as_slice(),
                2,
                3,
                Some(3),
            ),
        ];
        let sentinel = FreAotRegexResultV1 { start: 71, end: 73 };

        for (pattern, output, max_states, haystack, resume_state, resume_position, pending_end) in
            cases
        {
            let mut limits = CompileLimitsV1::default();
            limits.determinize.max_states = max_states;
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .limits(limits)
                    .output(output),
            )
            .expect("compile retained partial artifact");
            let stats = compiled
                .program()
                .partial_dfa_stats()
                .expect("partial statistics")
                .expect("retained partial table");
            assert!(resume_state < stats.resume_frontiers);
            let identity = compiled.receipt().program_sha256;
            let serialized = compiled.program().serialize().expect("serialize partial");
            let handle = prepare_exclusive(&serialized);

            let mut expected_result = sentinel;
            let expected_status =
                call_exclusive(handle, haystack, 0, haystack.len(), &mut expected_result);
            let mut resumed_result = sentinel;
            let resumed_status = call_exclusive_from_partial(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut resumed_result,
                &identity,
                resume_state,
                resume_position,
                pending_end,
            );
            assert_eq!(
                (resumed_status, resumed_result),
                (expected_status, expected_result),
                "{output:?}"
            );

            let mut wrong_identity = identity;
            wrong_identity[0] ^= 1;
            let mut result = sentinel;
            {
                let mut reject_resume = |expected_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
                                         state,
                                         position,
                                         pending| {
                    result = sentinel;
                    assert_eq!(
                        call_exclusive_from_partial(
                            handle,
                            haystack,
                            0,
                            haystack.len(),
                            &mut result,
                            expected_identity,
                            state,
                            position,
                            pending,
                        ),
                        STATUS_RUNTIME_FAILURE
                    );
                    assert_eq!(result, sentinel);
                };
                reject_resume(&wrong_identity, resume_state, resume_position, pending_end);
                reject_resume(
                    &identity,
                    stats.resume_frontiers,
                    resume_position,
                    pending_end,
                );
                let wrong_pending = if pending_end.is_some() { None } else { Some(0) };
                reject_resume(&identity, resume_state, resume_position, wrong_pending);
                if pending_end.is_some() {
                    reject_resume(
                        &identity,
                        resume_state,
                        resume_position,
                        resume_position.checked_add(1),
                    );
                }
                for invalid_position in [0, haystack.len()] {
                    reject_resume(&identity, resume_state, invalid_position, pending_end);
                }
            }
            for (invalid_start, invalid_end) in [
                (1, 0),
                (
                    0,
                    haystack.len().checked_add(1).expect("small test haystack"),
                ),
            ] {
                assert_eq!(
                    call_exclusive_from_partial(
                        handle,
                        haystack,
                        invalid_start,
                        invalid_end,
                        &mut result,
                        &identity,
                        resume_state,
                        resume_position,
                        pending_end,
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(result, sentinel);
            }

            if output == OutputContract::Exists {
                let raw_call =
                    |raw_handle, raw_haystack, raw_result, raw_identity, pending_present| {
                        // SAFETY: every deliberately invalid pointer/flag is
                        // rejected before dereference; all non-null extents remain
                        // live and the exclusive handle has no overlapping call.
                        unsafe {
                            fre_aot_regex_runtime_search_exclusive_from_partial_v1(
                                raw_handle,
                                raw_haystack,
                                haystack.len(),
                                0,
                                haystack.len(),
                                raw_result,
                                raw_identity,
                                resume_state,
                                resume_position,
                                pending_present,
                                pending_end.unwrap_or(0),
                            )
                        }
                    };
                assert_eq!(
                    raw_call(
                        handle,
                        std::ptr::null(),
                        &raw mut result,
                        identity.as_ptr(),
                        u32::from(pending_end.is_some()),
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(
                    raw_call(
                        handle,
                        haystack.as_ptr(),
                        std::ptr::null_mut(),
                        identity.as_ptr(),
                        u32::from(pending_end.is_some()),
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(
                    raw_call(
                        handle,
                        haystack.as_ptr(),
                        &raw mut result,
                        std::ptr::null(),
                        u32::from(pending_end.is_some()),
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(
                    raw_call(
                        handle,
                        haystack.as_ptr(),
                        &raw mut result,
                        identity.as_ptr(),
                        2,
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(
                    raw_call(
                        FreAotRegexExclusiveHandleV1::INVALID,
                        haystack.as_ptr(),
                        &raw mut result,
                        identity.as_ptr(),
                        u32::from(pending_end.is_some()),
                    ),
                    STATUS_INVALID_HANDLE
                );
                assert_eq!(result, sentinel);
            }

            let plain = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Fast)
                    .output(output),
            )
            .expect("compile no-partial artifact");
            assert!(plain.program().partial_dfa_stats().unwrap().is_none());
            let plain_identity = plain.receipt().program_sha256;
            let plain_serialized = plain.program().serialize().expect("serialize plain");
            let plain_handle = prepare_exclusive(&plain_serialized);
            assert_eq!(
                call_exclusive_from_partial(
                    plain_handle,
                    haystack,
                    0,
                    haystack.len(),
                    &mut result,
                    &plain_identity,
                    resume_state,
                    resume_position,
                    pending_end,
                ),
                STATUS_RUNTIME_FAILURE
            );
            assert_eq!(result, sentinel);

            // SAFETY: each handle is still uniquely owned and no call
            // overlaps either destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(plain_handle) },
                STATUS_SUCCESS
            );
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the end-to-end adaptive protocol keeps admission, continuation, warm completion, and lazy native completion in one exclusive handle lifecycle"
    )]
    fn exclusive_native_partial_warm_resume_resets_admission() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Exists),
        )
        .expect("compile adaptive retained partial artifact");
        assert!(compiled.program().partial_dfa_stats().unwrap().is_some());
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize partial");
        let handle = prepare_exclusive(&serialized);
        let mut haystack = b"xxcbbbbyyy".to_vec();
        haystack.resize(1_024, b'x');
        let expected = expected_ffi(
            compiled
                .search(&haystack, SearchWindow::full(&haystack))
                .expect("portable adaptive result"),
        );

        // The first shallow continuation publishes its missing K0 rows. The
        // second and third continuations complete entirely through immutable
        // warmed rows, so each one resets admission instead of creating a
        // bypass interval.
        for _ in 0..3 {
            assert_eq!(
                call_partial_should_enter(handle, haystack.len()),
                PARTIAL_ENTRY_ENTER
            );
            let mut result = FreAotRegexResultV1::default();
            assert_eq!(
                call_exclusive_from_partial(
                    handle,
                    &haystack,
                    0,
                    haystack.len(),
                    &mut result,
                    &identity,
                    0,
                    5,
                    None,
                ),
                expected.0
            );
            assert_eq!(result, expected.1);
        }

        assert_eq!(
            call_partial_should_enter(handle, haystack.len()),
            PARTIAL_ENTRY_ENTER,
            "warm K0 completion resets adaptive admission"
        );
        // Model a native scan that returned locally: no continuation call is
        // made, so the next admission must settle it as a completion.
        assert_eq!(
            call_partial_should_enter(handle, haystack.len()),
            PARTIAL_ENTRY_ENTER,
            "local native completion resets adaptive backoff"
        );
        let mut result = FreAotRegexResultV1::default();
        assert_eq!(
            call_exclusive_from_partial(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                0,
                5,
                None,
            ),
            expected.0
        );
        assert_eq!(result, expected.1);
        assert_eq!(
            call_partial_should_enter(FreAotRegexExclusiveHandleV1::INVALID, haystack.len()),
            PARTIAL_ENTRY_BYPASS
        );

        // SAFETY: the handle remains uniquely owned and no call overlaps its
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "identity, output transactions, exact windows, both ownership orders, and lifecycle form one ABI proof"
    )]
    fn exclusive_partial_preflight_is_transactional_and_returns_exact_windows() {
        let sentinel_result = FreAotRegexResultV1 { start: 71, end: 73 };
        let sentinel_window = FreAotRegexSearchWindowV1 { start: 79, end: 83 };
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;

        let plain = compile(
            CompileRequest::new(
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(limits)
            .output(OutputContract::SelectedEnd),
        )
        .expect("compile plain partial preflight artifact");
        assert!(plain.program().partial_dfa_stats().unwrap().is_some());
        let plain_identity = plain.receipt().program_sha256;
        let plain_bytes = plain.program().serialize().unwrap();
        let plain_handle = prepare_exclusive(&plain_bytes);
        let plain_haystack = vec![b'x'; 300];

        // No graph accelerator changes the exact public window. A second call
        // without a continuation also proves that the prior native local
        // completion is settled at the start of this transaction.
        for _ in 0..2 {
            let mut result = sentinel_result;
            let mut window = sentinel_window;
            assert_eq!(
                call_exclusive_partial_preflight(
                    plain_handle,
                    &plain_haystack,
                    11,
                    289,
                    &mut result,
                    &plain_identity,
                    &mut window,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER
            );
            assert_eq!(result, sentinel_result);
            assert_eq!(window, FreAotRegexSearchWindowV1 { start: 11, end: 289 });
        }

        // Identity authentication precedes state mutation and both outputs
        // remain transactional on rejection.
        let mut wrong_identity = plain_identity;
        wrong_identity[0] ^= 1;
        let mut result = sentinel_result;
        let mut window = sentinel_window;
        assert_eq!(
            call_exclusive_partial_preflight(
                plain_handle,
                &plain_haystack,
                11,
                289,
                &mut result,
                &wrong_identity,
                &mut window,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(window, sentinel_window);

        // The direct ABI remains complete below the native amortization floor.
        assert_eq!(
            call_exclusive_partial_preflight(
                plain_handle,
                &plain_haystack,
                11,
                42,
                &mut result,
                &plain_identity,
                &mut window,
            ),
            STATUS_NO_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());
        assert_eq!(window, sentinel_window);

        result = sentinel_result;
        window = sentinel_window;
        assert_eq!(
            call_exclusive_partial_preflight(
                FreAotRegexExclusiveHandleV1::INVALID,
                &plain_haystack,
                11,
                289,
                &mut result,
                &plain_identity,
                &mut window,
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(window, sentinel_window);
        // SAFETY: all non-null inputs are valid and the deliberately null
        // output is rejected before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_partial_preflight_v1(
                    plain_handle,
                    plain_haystack.as_ptr(),
                    plain_haystack.len(),
                    11,
                    289,
                    &raw mut result,
                    plain_identity.as_ptr(),
                    std::ptr::null_mut(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel_result);

        let cut = compile(
            CompileRequest::new(
                r"[b-c][a-b]{1,10}7[A-Za-z]{1,2}",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(limits)
            .output(OutputContract::SelectedEnd),
        )
        .expect("compile cut partial preflight artifact");
        assert!(cut.program().partial_dfa_stats().unwrap().is_some());
        let cut_identity = cut.receipt().program_sha256;
        let cut_bytes = cut.program().serialize().unwrap();
        let cut_handle = prepare_exclusive(&cut_bytes);
        let mut cut_haystack = vec![b'!'; 256 + 16];
        cut_haystack.extend_from_slice(b"cbbbbbbbbbb7AZ");
        result = sentinel_result;
        window = sentinel_window;
        assert_eq!(
            call_exclusive_partial_preflight(
                cut_handle,
                &cut_haystack,
                3,
                cut_haystack.len(),
                &mut result,
                &cut_identity,
                &mut window,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel_result);
        assert!(window.start > 3, "mandatory cut did not narrow: {window:?}");
        assert_eq!(window.end, cut_haystack.len());

        // The native-root policy keeps the same authenticated transaction but
        // gives an admitted emitted scanner the original semantic window. The
        // preceding unreported Enter is first settled as a local completion.
        result = sentinel_result;
        window = sentinel_window;
        assert_eq!(
            call_exclusive_partial_native_root_preflight(
                cut_handle,
                &cut_haystack,
                3,
                cut_haystack.len(),
                &mut result,
                &cut_identity,
                &mut window,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            window,
            FreAotRegexSearchWindowV1 {
                start: 3,
                end: cut_haystack.len(),
            }
        );

        // SAFETY: both handles remain uniquely owned and no call overlaps
        // either destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(cut_handle) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(plain_handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "success, exact transaction authentication, all-output rejection, and raw pointer validation share one stable postflight ABI lifecycle"
    )]
    fn exclusive_partial_span_postflight_authenticates_and_recovers() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 16;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Span),
        )
        .expect("compile variable-width retained Span artifact");
        let stats = compiled
            .program()
            .partial_dfa_stats()
            .unwrap()
            .expect("retained Span rows");
        assert!(stats.complete_rows < stats.discovered_states);
        assert_eq!(compiled.program().exact_match_width(), None);

        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive(&serialized);
        let mut haystack = vec![b'!'; 256];
        haystack.extend_from_slice(b"aQ");
        let public_start = 0_usize;
        let public_end = haystack.len();
        let expected = compiled
            .search(
                &haystack,
                SearchWindow::new(public_start, public_end),
            )
            .unwrap();
        let MatchResult::Span(Some((expected_start, selected_end))) = expected else {
            panic!("fixture did not select a Span: {expected:?}");
        };
        let expected_result = FreAotRegexResultV1 {
            start: expected_start,
            end: selected_end,
        };
        let sentinel_result = FreAotRegexResultV1 { start: 71, end: 73 };
        let sentinel_window = FreAotRegexSearchWindowV1 { start: 79, end: 83 };

        let preflight = || {
            let mut result = sentinel_result;
            let mut window = sentinel_window;
            assert_eq!(
                call_exclusive_partial_preflight(
                    handle,
                    &haystack,
                    public_start,
                    public_end,
                    &mut result,
                    &identity,
                    &mut window,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER
            );
            assert_eq!(result, sentinel_result);
            assert_ne!(window, sentinel_window);
            window
        };

        let window = preflight();
        let mut result = sentinel_result;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected_result);

        // The exact preflight transaction is single use.
        result = sentinel_result;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);

        // A foreign identity is rejected before consuming the transaction.
        let window = preflight();
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &wrong_identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected_result);

        // A different valid window aborts the transaction and cannot be
        // followed by a retry against the originally admitted window.
        let window = preflight();
        assert!(selected_end > window.start + 1);
        result = sentinel_result;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start + 1,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);

        // An in-range endpoint with no accepting span fails reverse K0 after
        // the in-flight marker has been cleared.
        let window = preflight();
        let wrong_end = window.start + 1;
        assert_ne!(wrong_end, selected_end);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                wrong_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );

        // Raw pointer and numeric validation precede every read or state
        // mutation. All invalid calls leave both result and transaction live.
        let window = preflight();
        let raw_call = |raw_handle,
                        raw_haystack,
                        raw_len,
                        raw_start,
                        raw_end,
                        raw_result,
                        raw_identity,
                        raw_selected_end| {
            // SAFETY: every deliberately invalid argument is rejected before
            // dereference; all non-null extents remain live and disjoint.
            unsafe {
                fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1(
                    raw_handle,
                    raw_haystack,
                    raw_len,
                    raw_start,
                    raw_end,
                    raw_result,
                    raw_identity,
                    raw_selected_end,
                )
            }
        };
        for status in [
            raw_call(
                handle,
                std::ptr::null(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                identity.as_ptr(),
                selected_end,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                std::ptr::null_mut(),
                identity.as_ptr(),
                selected_end,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                std::ptr::null(),
                selected_end,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.end,
                window.start,
                &raw mut result,
                identity.as_ptr(),
                selected_end,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                identity.as_ptr(),
                window.start,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                identity.as_ptr(),
                window.end + 1,
            ),
        ] {
            assert_eq!(status, STATUS_INVALID_ARGUMENT);
            assert_eq!(result, sentinel_result);
        }
        assert_eq!(
            raw_call(
                FreAotRegexExclusiveHandleV1::INVALID,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                identity.as_ptr(),
                selected_end,
            ),
            STATUS_INVALID_HANDLE
        );
        let mut misaligned_storage = vec![
            0_u8;
            size_of::<FreAotRegexResultV1>() + align_of::<FreAotRegexResultV1>()
        ];
        #[allow(
            clippy::cast_ptr_alignment,
            reason = "the raw-boundary test deliberately constructs a more-strictly-aligned result pointer at an unaligned address"
        )]
        let misaligned_result = (0..align_of::<FreAotRegexResultV1>())
            .find_map(|offset| {
                let pointer = misaligned_storage
                    .as_mut_ptr()
                    .wrapping_add(offset)
                    .cast::<FreAotRegexResultV1>();
                (!pointer.is_aligned()).then_some(pointer)
            })
            .expect("misaligned result address");
        assert_eq!(
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                misaligned_result,
                identity.as_ptr(),
                selected_end,
            ),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH,
            "raw validation consumed the authenticated transaction"
        );
        assert_eq!(result, expected_result);

        // Every non-Span output is rejected even when its own retained table
        // and exact artifact identity were successfully preflighted.
        for output in [OutputContract::Exists, OutputContract::SelectedEnd] {
            let mut output_limits = CompileLimitsV1::default();
            output_limits.determinize.max_states =
                if output == OutputContract::Exists { 8 } else { 16 };
            let other = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .limits(output_limits)
                    .output(output),
            )
            .unwrap();
            assert!(other.program().partial_dfa_stats().unwrap().is_some());
            let other_identity = other.receipt().program_sha256;
            let other_bytes = other.program().serialize().unwrap();
            let other_handle = prepare_exclusive(&other_bytes);
            let mut other_result = sentinel_result;
            let mut other_window = sentinel_window;
            assert_eq!(
                call_exclusive_partial_preflight(
                    other_handle,
                    &haystack,
                    public_start,
                    public_end,
                    &mut other_result,
                    &other_identity,
                    &mut other_window,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER,
                "{output:?}"
            );
            assert_eq!(
                call_exclusive_recover_partial_span(
                    other_handle,
                    &haystack,
                    other_window.start,
                    other_window.end,
                    &mut other_result,
                    &other_identity,
                    selected_end,
                ),
                STATUS_RUNTIME_FAILURE,
                "{output:?}"
            );
            assert_eq!(other_result, sentinel_result);
            // SAFETY: this test uniquely owns the live session.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(other_handle) },
                STATUS_SUCCESS
            );
        }

        // SAFETY: this test uniquely owns the live session and all calls have
        // completed before destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_partial_preflight_runs_concurrently_on_independent_sessions() {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;
        let compiled = compile(
            CompileRequest::new(
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(limits)
            .output(OutputContract::SelectedEnd),
        )
        .expect("compile concurrent partial preflight artifact");
        assert!(compiled.program().partial_dfa_stats().unwrap().is_some());

        let identity = compiled.receipt().program_sha256;
        let serialized = Arc::new(compiled.program().serialize().unwrap());
        let haystack = Arc::new(vec![b'x'; 300]);
        let worker_count = 4_usize;
        let barrier = Arc::new(std::sync::Barrier::new(worker_count));

        // A single exclusive handle may not be used by overlapping calls.
        // Each worker therefore creates, calls, and destroys its own session;
        // the barrier makes the valid independent-session calls overlap.
        std::thread::scope(|scope| {
            for worker in 0..worker_count {
                let serialized = Arc::clone(&serialized);
                let haystack = Arc::clone(&haystack);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    let handle = prepare_exclusive(&serialized);
                    for iteration in 0..64 {
                        let sentinel_result = FreAotRegexResultV1 {
                            start: 1_000 + worker,
                            end: 2_000 + iteration,
                        };
                        let sentinel_window = FreAotRegexSearchWindowV1 {
                            start: 3_000 + worker,
                            end: 4_000 + iteration,
                        };
                        let mut result = sentinel_result;
                        let mut window = sentinel_window;
                        assert_eq!(
                            call_exclusive_partial_preflight(
                                handle,
                                &haystack,
                                11,
                                289,
                                &mut result,
                                &identity,
                                &mut window,
                            ),
                            STATUS_PARTIAL_PREFLIGHT_ENTER
                        );
                        assert_eq!(result, sentinel_result);
                        assert_eq!(
                            window,
                            FreAotRegexSearchWindowV1 { start: 11, end: 289 }
                        );
                    }
                    // SAFETY: the worker has sole ownership of its session and
                    // all of its synchronous calls have returned.
                    assert_eq!(
                        unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                        STATUS_SUCCESS
                    );
                });
            }
        });
    }

    #[test]
    fn exclusive_partial_span_postflight_runs_concurrently_on_independent_sessions() {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 16;
        let compiled = compile(
            CompileRequest::new(
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(limits)
            .output(OutputContract::Span),
        )
        .expect("compile concurrent retained Span artifact");
        assert!(compiled.program().partial_dfa_stats().unwrap().is_some());

        let identity = compiled.receipt().program_sha256;
        let serialized = Arc::new(compiled.program().serialize().unwrap());
        let mut source = vec![b'!'; 256];
        source.extend_from_slice(b"aQ");
        let haystack = Arc::new(source);
        let MatchResult::Span(Some((expected_start, selected_end))) = compiled
            .search(&haystack, SearchWindow::full(&haystack))
            .unwrap()
        else {
            panic!("concurrent fixture did not select a Span");
        };
        let expected = FreAotRegexResultV1 {
            start: expected_start,
            end: selected_end,
        };
        let worker_count = 4_usize;
        let barrier = Arc::new(std::sync::Barrier::new(worker_count));

        // An exclusive session is synchronization-free and cannot overlap
        // itself. Independent sessions from the same immutable artifact may
        // preflight and recover concurrently without sharing transaction or
        // bidirectional-workspace state.
        std::thread::scope(|scope| {
            for worker in 0..worker_count {
                let serialized = Arc::clone(&serialized);
                let haystack = Arc::clone(&haystack);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let handle = prepare_exclusive(&serialized);
                    barrier.wait();
                    for iteration in 0..64 {
                        let sentinel = FreAotRegexResultV1 {
                            start: 1_000 + worker,
                            end: 2_000 + iteration,
                        };
                        let mut result = sentinel;
                        let mut window = FreAotRegexSearchWindowV1 {
                            start: 3_000 + worker,
                            end: 4_000 + iteration,
                        };
                        assert_eq!(
                            call_exclusive_partial_preflight(
                                handle,
                                &haystack,
                                0,
                                haystack.len(),
                                &mut result,
                                &identity,
                                &mut window,
                            ),
                            STATUS_PARTIAL_PREFLIGHT_ENTER
                        );
                        assert_eq!(result, sentinel);
                        assert_eq!(
                            call_exclusive_recover_partial_span(
                                handle,
                                &haystack,
                                window.start,
                                window.end,
                                &mut result,
                                &identity,
                                selected_end,
                            ),
                            STATUS_MATCH
                        );
                        assert_eq!(result, expected);
                    }
                    // SAFETY: this worker uniquely owns its session and all
                    // synchronous calls have returned.
                    assert_eq!(
                        unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                        STATUS_SUCCESS
                    );
                });
            }
        });
    }

    #[test]
    fn prepared_c_lifecycle_accepts_strict_v1_ordered_nfa() {
        // Complete optimizing DFAs now authenticate both class-mass state
        // discovery and its exact construction work as V6, so rewriting only
        // their header would deliberately create a noncanonical V1 artifact.
        // Legacy FIFO-DFA canonical validation remains covered in the program
        // crate; this runtime lifecycle test uses the stable V1 ordered NFA.
        let pattern = "(?:ab|a)+?b";
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile ordered NFA");
        assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);

        let canonical = compiled
            .program()
            .serialize()
            .expect("serialize current program");
        let mut v1 = canonical.clone();
        v1[8..12].copy_from_slice(&1_u32.to_le_bytes());
        v1[14] = 0;
        v1[15] = 0;
        let handle = prepare_handle(&v1);
        drop(v1);
        drop(canonical);

        let mut haystacks = generated_haystacks();
        haystacks.extend([b"xxaaab".to_vec(), b"ababbx".to_vec()]);
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = expected_ffi(
                        compiled
                            .search(haystack, SearchWindow::new(start, end))
                            .expect("portable DFA search"),
                    );
                    let mut actual = FreAotRegexResultV1 {
                        start: usize::MAX,
                        end: usize::MAX,
                    };
                    let status = call_prepared(handle, haystack, start, end, &mut actual);
                    assert_eq!(
                        (status, actual),
                        expected,
                        "pattern={pattern:?}, haystack={haystack:?}, window={start}..{end}"
                    );
                }
            }
        }
        assert_eq!(
            fre_aot_regex_runtime_destroy_prepared_v1(handle),
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "the test deliberately passes a misaligned handle output that is rejected before use"
    )]
    fn prepared_handle_rejects_stale_busy_and_malformed_misuse() {
        let bytes = program(r"(?m:^a\b)", OutputContract::Span);
        let mut untouched = FreAotRegexPreparedHandleV1(41);
        let mut malformed = bytes.clone();
        malformed[0] ^= 1;

        // SAFETY: the malformed allocation is fully readable and the output is
        // aligned and disjoint; validation fails before ownership is created.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_v1(
                    malformed.as_ptr(),
                    malformed.len(),
                    &raw mut untouched,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(untouched, FreAotRegexPreparedHandleV1(41));

        let mut storage = [0_u8; size_of::<FreAotRegexPreparedHandleV1>() * 2];
        let base = storage.as_mut_ptr();
        let aligned = base.align_offset(align_of::<FreAotRegexPreparedHandleV1>());
        assert_ne!(aligned, usize::MAX);
        let misaligned = base
            .wrapping_add(aligned.checked_add(1).expect("small alignment offset"))
            .cast::<FreAotRegexPreparedHandleV1>();
        // SAFETY: the deliberately misaligned output is rejected before it is
        // written; the source allocation remains valid.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_prepare_v1(bytes.as_ptr(), bytes.len(), misaligned) },
            STATUS_INVALID_ARGUMENT
        );

        let handle = prepare_handle(&bytes);
        let haystack = b"a";
        let sentinel = FreAotRegexResultV1 { start: 17, end: 19 };
        let mut result = sentinel;
        assert_eq!(
            call_prepared(
                FreAotRegexPreparedHandleV1(u64::MAX),
                haystack,
                0,
                1,
                &mut result
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            call_prepared(handle, haystack, 1, 0, &mut result),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel);

        let entry = prepared_entry(handle)
            .expect("registry lock")
            .expect("registered handle");
        let exclusive = entry.prepared.lock().expect("exclusive test lock");
        assert_eq!(
            call_prepared(handle, haystack, 0, 1, &mut result),
            STATUS_HANDLE_BUSY
        );
        assert_eq!(result, sentinel);
        drop(exclusive);

        assert_eq!(
            fre_aot_regex_runtime_destroy_prepared_v1(handle),
            STATUS_SUCCESS
        );
        assert_eq!(
            fre_aot_regex_runtime_destroy_prepared_v1(handle),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_prepared(handle, haystack, 0, 1, &mut result),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            fre_aot_regex_runtime_destroy_prepared_v1(FreAotRegexPreparedHandleV1::INVALID),
            STATUS_INVALID_HANDLE
        );
    }
}
