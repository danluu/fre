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

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(unsafe_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};

use fre_aot_regex::{
    CompileError, CompiledProgram, MatchResult, PROGRAM_HEADER_LEN, ProgramFormatError,
    ProgramWorkspace, SearchWindow,
};

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
/// Successful status for prepare and destroy lifecycle operations.
pub const STATUS_SUCCESS: u32 = 0;

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
pub struct PreparedAotRegex {
    program: CompiledProgram,
    workspace: ProgramWorkspace,
}

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
        let workspace = program
            .prepare_workspace()
            .map_err(PrepareError::Workspace)?;
        Ok(Self { program, workspace })
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
        self.program
            .search_with_workspace(haystack, window, &mut self.workspace)
    }
}

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

    // SAFETY: the caller guarantees a live exclusively owned session plus the
    // readable haystack and writable disjoint result extents.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let Ok((status, result)) =
            execute_search(prepared, haystack, window_start, window_end)
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(result);
        status
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
    Ok(
        match prepared.search(haystack, SearchWindow::new(window_start, window_end))? {
            MatchResult::Exists(false)
            | MatchResult::SelectedEnd(None)
            | MatchResult::Span(None) => (STATUS_NO_MATCH, FreAotRegexResultV1::default()),
            MatchResult::Exists(true) => {
                // Exists deliberately exposes no endpoint information.
                (STATUS_MATCH, FreAotRegexResultV1::default())
            }
            MatchResult::SelectedEnd(Some(end)) => {
                (STATUS_MATCH, FreAotRegexResultV1 { start: end, end })
            }
            MatchResult::Span(Some((start, end))) => {
                (STATUS_MATCH, FreAotRegexResultV1 { start, end })
            }
        },
    )
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "tests exercise the exported raw C boundary with explicitly valid or deliberately rejected pointers"
)]
mod tests {
    use fre_aot_regex::{
        CompileLimitsV1, CompileMode, CompileRequest, EngineKind, EngineSelectionReason,
        MatchResult, OutputContract, Target, compile,
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
    fn c_abi_layout_declarations_and_function_types_are_stable() {
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
        for symbol in [
            "fre_aot_regex_runtime_search_v1",
            "fre_aot_regex_runtime_prepare_v1",
            "fre_aot_regex_runtime_search_prepared_v1",
            "fre_aot_regex_runtime_destroy_prepared_v1",
            "fre_aot_regex_runtime_prepare_exclusive_v1",
            "fre_aot_regex_runtime_search_exclusive_v1",
            "fre_aot_regex_runtime_destroy_exclusive_v1",
        ] {
            assert!(C_API_V1_HEADER.contains(symbol), "{symbol}");
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
        let _: unsafe extern "C" fn(
            *const u8,
            usize,
            *mut FreAotRegexExclusiveHandleV1,
        ) -> u32 = fre_aot_regex_runtime_prepare_exclusive_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_v1;
        let _: unsafe extern "C" fn(FreAotRegexExclusiveHandleV1) -> u32 =
            fre_aot_regex_runtime_destroy_exclusive_v1;
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
    fn prepared_c_lifecycle_accepts_strict_v1_ordered_dfa() {
        let pattern = "(?:ab|a)+?b";
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .expect("compile ordered DFA");
        assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedDfa);

        let canonical_v2 = compiled
            .program()
            .serialize()
            .expect("serialize V2 program");
        let mut v1 = canonical_v2.clone();
        v1[8..12].copy_from_slice(&1_u32.to_le_bytes());
        v1[14] = 0;
        v1[15] = 0;
        let handle = prepare_handle(&v1);
        drop(v1);
        drop(canonical_v2);

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
