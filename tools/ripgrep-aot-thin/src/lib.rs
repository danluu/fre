//! Safe dispatch over the precompiled ripgrep-suite general-AOT registry.

#![warn(unsafe_code)]

use std::marker::PhantomData;
use std::mem::MaybeUninit;

use fre_aot_regex::{MatchResult, SearchWindow};
pub use fre_aot_regex_runtime::AotMatch;
use fre_aot_regex_runtime::{
    FreAotRegexExclusiveExistsBatchV1, FreAotRegexExclusiveHandleV1,
    FreAotRegexExclusiveSpanFillV1, FreAotRegexHaystackV1,
    FreAotRegexIndependentExistsBatchV1, FreAotRegexIterStateV1, FreAotRegexResultV1,
    ITER_FINISHED, ITER_HAS_LAST, ITER_KNOWN_FLAGS, ITER_PENDING_EMPTY, PreparedAotMatches,
    PreparedAotRegex, fre_aot_regex_runtime_destroy_exclusive_v1,
    fre_aot_regex_runtime_prepare_exclusive_v1,
};

/// Explicit general-AOT compilation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AotMode {
    /// Fast compilation to the universal ordered TNFA and prepared runtime.
    Fast,
    /// Optimizing compilation to native DFA code when complete determinization succeeds.
    Optimizing,
}

/// Search result contract selected at AOT compilation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AotOutput {
    /// Return only whether a match exists.
    Exists,
    /// Return the selected leftmost-first half-open span.
    Span,
}

type AbiResult = FreAotRegexResultV1;
type AbiHaystack = FreAotRegexHaystackV1;
type NativeIterState = FreAotRegexIterStateV1;

/// A reusable, lifetime-bound view of one haystack for batched AOT searches.
///
/// Constructing this view records the native batch ABI's pointer and length
/// once. Passing a slice of views to [`AotMatcher::is_match_descriptor_batch`]
/// lets a compiled batch entry consume those descriptors directly, without
/// the adapter copying a slice of Rust fat pointers into an intermediate
/// descriptor array on every call. The referenced bytes remain borrowed for
/// the complete lifetime of the view.
///
/// The fields are private so safe code cannot forge an invalid pointer/length
/// pair. Use [`AotHaystack::from`] (or `slice.into()`) to construct a view.
///
/// ```compile_fail
/// use fre_ripgrep_aot_thin::AotHaystack;
///
/// fn dangling<'a>() -> AotHaystack<'a> {
///     let bytes = vec![b'x'];
///     AotHaystack::from(bytes.as_slice())
/// }
/// ```
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct AotHaystack<'a> {
    abi: AbiHaystack,
    lifetime: PhantomData<&'a [u8]>,
}

impl<'a> From<&'a [u8]> for AotHaystack<'a> {
    fn from(haystack: &'a [u8]) -> Self {
        Self {
            abi: AbiHaystack {
                ptr: haystack.as_ptr(),
                len: haystack.len(),
            },
            lifetime: PhantomData,
        }
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for AotHaystack<'a> {
    fn from(haystack: &'a [u8; N]) -> Self {
        Self::from(haystack.as_slice())
    }
}

impl AotHaystack<'_> {
    #[allow(
        unsafe_code,
        reason = "the private descriptor can only be constructed from a live shared byte slice"
    )]
    fn as_slice(&self) -> &[u8] {
        // SAFETY: the private fields were obtained from a shared slice, and
        // the phantom lifetime prevents this view from outliving that slice.
        // Copying the view cannot mutate or extend the referenced storage.
        unsafe { std::slice::from_raw_parts(self.abi.ptr, self.abi.len) }
    }
}

type NativeSearch = unsafe extern "C" fn(*const u8, usize, usize, usize, *mut AbiResult) -> u32;
type NativeExistsBatch = FreAotRegexIndependentExistsBatchV1;
type NativeFill =
    fn(&[u8], &mut NativeIterState, &mut [MaybeUninit<AbiResult>]) -> NativeFillOutcome;
type PreparedCompatSpanFill = fn(
    FreAotRegexExclusiveHandleV1,
    &[u8],
    &mut NativeIterState,
    &mut [MaybeUninit<AbiResult>],
) -> NativeFillOutcome;
type PreparedSpanFill = FreAotRegexExclusiveSpanFillV1;
type PreparedExistsBatch = FreAotRegexExclusiveExistsBatchV1;
type PreparedSearch = unsafe extern "C" fn(
    FreAotRegexExclusiveHandleV1,
    *const u8,
    usize,
    usize,
    usize,
    *mut AbiResult,
) -> u32;
const NATIVE_SPAN_BUFFER_CAPACITY: usize = 64;
/// Maximum number of line haystacks the thin adapter sends through one
/// compiled Exists-batch invocation.
pub const EXISTS_BATCH_CAPACITY: usize = 64;

// The direct batch ABI publishes compiler-authenticated 0/1 bytes directly
// into caller-owned Boolean storage. Keep that representation dependency a
// compile-time condition instead of silently assuming it in pointer math.
const _: () = {
    assert!(std::mem::size_of::<bool>() == std::mem::size_of::<u8>());
    assert!(std::mem::align_of::<bool>() == std::mem::align_of::<u8>());
};

#[derive(Clone, Copy, Debug)]
#[allow(
    dead_code,
    reason = "compatibility-only registries do not construct the additive compiled fill variant"
)]
enum PreparedSpanFillFactory {
    Compiled(PreparedSpanFill),
    Compatibility(PreparedCompatSpanFill),
}

#[derive(Clone, Copy, Debug)]
enum BackendFactory {
    Native {
        search: NativeSearch,
        fill: Option<NativeFill>,
        exists_batch: Option<NativeExistsBatch>,
    },
    Prepared {
        search: PreparedSearch,
        program: &'static [u8],
        span_fill: Option<PreparedSpanFillFactory>,
        exists_batch: Option<PreparedExistsBatch>,
    },
    #[allow(
        dead_code,
        reason = "future or legacy artifacts without any compiled entry retain an explicit labeled portable fallback"
    )]
    Runtime(&'static [u8]),
}

#[derive(Clone, Copy, Debug)]
struct CompiledSpec {
    mode: AotMode,
    output: AotOutput,
    pattern: &'static str,
    case_insensitive: bool,
    description: &'static str,
    backend: BackendFactory,
}

#[allow(
    unsafe_code,
    reason = "generated declarations are bound to compiler-produced objects with the stable V1 ABI"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/registry.rs"));
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "the library test target exercises only pure build-input helpers"
)]
#[path = "../build_support.rs"]
mod build_support_tests;

#[cfg(test)]
#[allow(
    dead_code,
    reason = "the library test target exercises only pure target-feature helpers"
)]
#[path = "../build_target.rs"]
mod build_target_tests;

#[derive(Debug)]
enum Backend {
    Native {
        search: NativeSearch,
        fill: Option<NativeFill>,
        exists_batch: Option<NativeExistsBatch>,
    },
    Prepared(PreparedNative),
    Runtime(Box<PreparedAotRegex>),
}

#[derive(Debug)]
struct PreparedNative {
    search: PreparedSearch,
    span_fill: Option<PreparedSpanFillFactory>,
    exists_batch: Option<PreparedExistsBatch>,
    handle: FreAotRegexExclusiveHandleV1,
}

// SAFETY: this owner can move between threads only as a whole. Every search
// requires `&mut self`, an iterator retains that mutable borrow, and Drop also
// requires exclusive ownership, so no call can remain active across a move.
#[allow(
    unsafe_code,
    reason = "the exclusive runtime ABI permits moving an idle, uniquely owned handle between threads"
)]
unsafe impl Send for PreparedNative {}

impl PreparedNative {
    #[allow(
        unsafe_code,
        reason = "the runtime copies and validates the exact compiler-exported program before returning an exclusively owned handle"
    )]
    fn new(
        search: PreparedSearch,
        program: &'static [u8],
        span_fill: Option<PreparedSpanFillFactory>,
        exists_batch: Option<PreparedExistsBatch>,
    ) -> Result<Self, String> {
        let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
        // SAFETY: the compiler-exported static is readable for its complete
        // declared length, and `handle` is aligned, writable, and disjoint.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_exclusive_v1(
                program.as_ptr(),
                program.len(),
                &raw mut handle,
            )
        };
        if status != 0 || handle.is_invalid() {
            return Err(format!(
                "prepare compiled AOT exclusive handle failed with status {status}"
            ));
        }
        Ok(Self {
            search,
            span_fill,
            exists_batch,
            handle,
        })
    }
}

#[allow(
    unsafe_code,
    reason = "this owner destroys its live exclusive runtime handle exactly once"
)]
impl Drop for PreparedNative {
    fn drop(&mut self) {
        let handle = std::mem::replace(&mut self.handle, FreAotRegexExclusiveHandleV1::INVALID);
        if !handle.is_invalid() {
            // SAFETY: `PreparedNative` exclusively owns this live handle, and
            // its mutable borrow prevents an overlapping search or iterator.
            let _status = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
        }
    }
}

trait NativeIterStateExt {
    fn has_last_match(self) -> bool;
    fn pending_empty_progress(self) -> bool;
    fn finished(self) -> bool;
    fn set_pending_empty_progress(&mut self, pending: bool);
    fn finish(&mut self);
}

impl NativeIterStateExt for NativeIterState {
    fn has_last_match(self) -> bool {
        self.flags & ITER_HAS_LAST != 0
    }

    fn pending_empty_progress(self) -> bool {
        self.flags & ITER_PENDING_EMPTY != 0
    }

    fn finished(self) -> bool {
        self.flags & ITER_FINISHED != 0
    }

    fn set_pending_empty_progress(&mut self, pending: bool) {
        if pending {
            self.flags |= ITER_PENDING_EMPTY;
        } else {
            self.flags &= !ITER_PENDING_EMPTY;
        }
    }

    fn finish(&mut self) {
        self.flags = (self.flags & ITER_HAS_LAST) | ITER_FINISHED;
    }
}

#[derive(Debug)]
struct NativeFillOutcome {
    written: usize,
    error: Option<String>,
}

/// Fill a caller-owned span buffer using one statically selected native entry.
///
/// Generated shims monomorphize this function with a closure that names one
/// linked AOT symbol directly. Consequently the iterator makes one indirect
/// Rust call per refill while the calls inside the refill are direct.
///
/// # Safety
///
/// `search` must implement the compiler-produced Span ABI: status 1 must
/// initialize the supplied result slot, and it must not retain any argument.
#[inline(always)]
#[allow(
    clippy::inline_always,
    unsafe_code,
    reason = "generated monomorphic shims must inline this loop so their AOT entry calls remain direct; status 1 guarantees an initialized result"
)]
unsafe fn fill_native_spans<Search>(
    haystack: &[u8],
    state: &mut NativeIterState,
    output: &mut [MaybeUninit<AbiResult>],
    mut search: Search,
) -> NativeFillOutcome
where
    Search: FnMut(&[u8], usize, *mut AbiResult) -> u32,
{
    let mut written = 0;
    while written < output.len() && !state.finished() {
        if state.pending_empty_progress() {
            state.set_pending_empty_progress(false);
            if state.next_start == haystack.len() {
                state.finish();
                break;
            }
            state.next_start += 1;
        }

        let search_start = state.next_start;
        let status = search(haystack, search_start, output[written].as_mut_ptr());
        match status {
            0 => {
                state.finish();
                break;
            }
            1 => {
                // Compiler-produced Span entries initialize exactly one result
                // on status 1. The generated shim is the only caller.
                let result = unsafe { output[written].assume_init_ref() };
                if search_start > result.start
                    || result.start > result.end
                    || result.end > haystack.len()
                {
                    state.finish();
                    return NativeFillOutcome {
                        written,
                        error: Some(format!(
                            "native AOT entry returned an invalid result: status={status} start={} end={} window={search_start}..{}",
                            result.start,
                            result.end,
                            haystack.len()
                        )),
                    };
                }

                if result.start == result.end
                    && state.has_last_match()
                    && state.last_match_end == result.end
                {
                    if state.next_start == haystack.len() {
                        state.finish();
                        break;
                    }
                    state.next_start += 1;
                    continue;
                }

                state.next_start = result.end;
                state.last_match_end = result.end;
                state.flags |= ITER_HAS_LAST;
                state.set_pending_empty_progress(result.start == result.end);
                written += 1;
            }
            _ => {
                state.finish();
                return NativeFillOutcome {
                    written,
                    error: Some(format!("native AOT entry failed with status {status}")),
                };
            }
        }
    }
    NativeFillOutcome {
        written,
        error: None,
    }
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for a compiler-produced prepared Span-fill entry"
)]
fn fill_prepared_spans(
    fill: PreparedSpanFill,
    handle: FreAotRegexExclusiveHandleV1,
    haystack: &[u8],
    state: &mut NativeIterState,
    output: &mut [MaybeUninit<AbiResult>],
) -> NativeFillOutcome {
    if output.is_empty() {
        state.finish();
        return NativeFillOutcome {
            written: 0,
            error: Some("compiled Span refill received an empty output buffer".to_owned()),
        };
    }

    let mut written = 0;
    // SAFETY: `PreparedNative` exclusively owns `handle`; the haystack and
    // state are live for this call; `output` is aligned writable storage for
    // exactly `output.len()` ABI results. The compiler-produced entry retains
    // none of these pointers and publishes `written` only after initializing
    // that prefix.
    let status = unsafe {
        fill(
            handle,
            haystack.as_ptr(),
            haystack.len(),
            state,
            output.as_mut_ptr().cast::<AbiResult>(),
            output.len(),
            &raw mut written,
        )
    };
    if written > output.len() {
        state.finish();
        return NativeFillOutcome {
            written: 0,
            error: Some(format!(
                "compiled Span refill overreported its initialized prefix: {written} > {}",
                output.len()
            )),
        };
    }
    if state.reserved != 0
        || state.flags & !ITER_KNOWN_FLAGS != 0
        || state.next_start > haystack.len()
        || state.last_match_end > haystack.len()
        || (state.pending_empty_progress()
            && (!state.has_last_match()
                || state.finished()
                || state.next_start != state.last_match_end))
        || (!state.has_last_match() && (state.next_start != 0 || state.last_match_end != 0))
        || (state.has_last_match() && state.next_start < state.last_match_end)
    {
        state.finish();
        return NativeFillOutcome {
            written: 0,
            error: Some("compiled Span refill returned invalid iterator state".to_owned()),
        };
    }
    if written != 0 {
        // The fill ABI guarantees that exactly the published prefix is
        // initialized. Checking its final element is enough to tie the
        // returned iterator state to the spans the caller will consume,
        // without adding a second walk over the hot-path result buffer.
        let last = unsafe { output[written - 1].assume_init_ref() };
        if last.start > last.end
            || last.end > haystack.len()
            || !state.has_last_match()
            || state.last_match_end != last.end
            || (status == 1 && state.next_start != last.end)
        {
            state.finish();
            return NativeFillOutcome {
                written: 0,
                error: Some(
                    "compiled Span refill returned an inconsistent final span/state".to_owned(),
                ),
            };
        }
    }

    let error = match status {
        0 if state.finished() => None,
        1 if written == output.len() && !state.finished() => None,
        0 => {
            Some("compiled Span refill returned terminal status without finishing state".to_owned())
        }
        1 => Some(format!(
            "compiled Span refill returned continuation status after writing {written}/{} spans",
            output.len()
        )),
        _ => Some(format!("compiled Span refill failed with status {status}")),
    };
    if error.is_some() {
        state.finish();
    }
    NativeFillOutcome { written, error }
}

/// One prepared matcher selected from the fixed ripgrep-suite registry.
#[derive(Debug)]
pub struct AotMatcher {
    output: AotOutput,
    description: &'static str,
    backend: Backend,
}

impl AotMatcher {
    /// Select and prepare an exact precompiled pattern/profile/output tuple.
    ///
    /// # Errors
    ///
    /// Returns an error when the tuple is absent or a runtime-backed artifact
    /// cannot be validated and prepared.
    pub fn new(
        mode: AotMode,
        output: AotOutput,
        pattern: &str,
        case_insensitive: bool,
    ) -> Result<Self, String> {
        let spec = generated::SPECS
            .iter()
            .find(|spec| {
                spec.mode == mode
                    && spec.output == output
                    && spec.pattern == pattern
                    && spec.case_insensitive == case_insensitive
            })
            .ok_or_else(|| missing_spec_error(mode, output, pattern, case_insensitive))?;
        let backend = match spec.backend {
            BackendFactory::Native {
                search,
                fill,
                exists_batch,
            } => Backend::Native {
                search,
                fill,
                exists_batch,
            },
            BackendFactory::Prepared {
                search,
                program,
                span_fill,
                exists_batch,
            } => Backend::Prepared(PreparedNative::new(
                search,
                program,
                span_fill,
                exists_batch,
            )?),
            BackendFactory::Runtime(bytes) => Backend::Runtime(Box::new(
                PreparedAotRegex::deserialize(bytes)
                    .map_err(|error| format!("prepare compiled AOT program: {error}"))?,
            )),
        };
        Ok(Self {
            output,
            description: spec.description,
            backend,
        })
    }

    /// Structural compiler and effective execution-route description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.description
    }

    /// Search an `Exists` artifact over the complete haystack.
    ///
    /// # Errors
    ///
    /// Returns an error for an output-contract mismatch or execution failure.
    pub fn is_match(&mut self, haystack: &[u8]) -> Result<bool, String> {
        if self.output != AotOutput::Exists {
            return Err("AOT matcher was not compiled for Exists".to_owned());
        }
        match self.search(haystack, 0)? {
            MatchResult::Exists(found) => Ok(found),
            _ => Err("AOT Exists artifact returned a different result contract".to_owned()),
        }
    }

    /// Search up to [`EXISTS_BATCH_CAPACITY`] independent line haystacks.
    ///
    /// A one-haystack request uses the scalar entry. Compiled prepared and
    /// self-contained direct artifacts execute every larger complete batch
    /// through one native invocation. Other artifact routes preserve
    /// identical behavior with a checked per-haystack compatibility loop.
    ///
    /// # Errors
    ///
    /// Returns an error for an output-contract mismatch, unequal input/output
    /// lengths, an oversized batch, or any execution/ABI failure.
    #[allow(
        unsafe_code,
        reason = "the initialized prefix of the bounded stack descriptor array is tracked exactly"
    )]
    pub fn is_match_batch(
        &mut self,
        haystacks: &[&[u8]],
        matched: &mut [bool],
    ) -> Result<(), String> {
        self.validate_exists_batch_request(haystacks.len(), matched.len())?;
        if haystacks.is_empty() {
            return Ok(());
        }

        let mut descriptors =
            [const { MaybeUninit::<AotHaystack<'_>>::uninit() }; EXISTS_BATCH_CAPACITY];
        for (descriptor, haystack) in descriptors.iter_mut().zip(haystacks) {
            descriptor.write(AotHaystack::from(*haystack));
        }
        // SAFETY: the loop initialized exactly the prefix selected here. Each
        // view borrows its corresponding input slice, and the private dispatch
        // retains neither descriptors nor byte pointers after it returns.
        let descriptors = unsafe {
            std::slice::from_raw_parts(
                descriptors.as_ptr().cast::<AotHaystack<'_>>(),
                haystacks.len(),
            )
        };
        if descriptors.len() > 1
            && let Backend::Native {
                exists_batch: Some(batch),
                ..
            } = &self.backend
        {
            return direct_native_is_match_descriptor_batch(*batch, descriptors, matched);
        }
        self.is_match_descriptor_batch_validated(descriptors, matched)
    }

    /// Search reusable haystack descriptors without an adapter-side copy.
    ///
    /// A caller that batches the same line buffers across matchers or repeated
    /// searches can construct [`AotHaystack`] values once and reuse them.
    /// Compiled prepared and self-contained direct batch entries read this
    /// descriptor slice in place. Scalar and portable compatibility routes
    /// retain identical matching behavior by reading the lifetime-bound byte
    /// slices represented by each descriptor.
    ///
    /// A one-haystack request continues to use the scalar entry. Empty batches
    /// are accepted and leave the output unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error for an output-contract mismatch, unequal input/output
    /// lengths, an oversized batch, or any execution/ABI failure. If a native
    /// batch reports an error after publishing a valid prefix, that prefix is
    /// retained in `matched` and the remaining output elements are unchanged.
    #[inline]
    pub fn is_match_descriptor_batch(
        &mut self,
        haystacks: &[AotHaystack<'_>],
        matched: &mut [bool],
    ) -> Result<(), String> {
        // Keep the selector frameless in optimized builds. A singleton should
        // enter the scalar adapter directly, while larger requests retain the
        // zero-copy descriptor batch path and its independently sized frame.
        if haystacks.len() == 1 && matched.len() == 1 {
            return self.is_match_descriptor_single(&haystacks[0], &mut matched[0]);
        }
        // Keep the authenticated direct-native batch route out of the large
        // compatibility dispatcher. All request checks remain explicit here;
        // malformed and non-direct requests enter the exact old path below.
        if self.output == AotOutput::Exists
            && haystacks.len() == matched.len()
            && (2..=EXISTS_BATCH_CAPACITY).contains(&haystacks.len())
            && let Backend::Native {
                exists_batch: Some(batch),
                ..
            } = &self.backend
        {
            return direct_native_is_match_descriptor_batch(*batch, haystacks, matched);
        }
        self.is_match_descriptor_batch_non_single(haystacks, matched)
    }

    #[inline(never)]
    fn is_match_descriptor_batch_non_single(
        &mut self,
        haystacks: &[AotHaystack<'_>],
        matched: &mut [bool],
    ) -> Result<(), String> {
        self.validate_exists_batch_request(haystacks.len(), matched.len())?;
        if haystacks.is_empty() {
            return Ok(());
        }
        self.is_match_descriptor_batch_validated(haystacks, matched)
    }

    fn validate_exists_batch_request(
        &self,
        haystack_len: usize,
        matched_len: usize,
    ) -> Result<(), String> {
        if self.output != AotOutput::Exists {
            return Err("AOT matcher was not compiled for Exists".to_owned());
        }
        if haystack_len != matched_len {
            return Err(format!(
                "AOT Exists batch input/output length mismatch: {} != {}",
                haystack_len, matched_len
            ));
        }
        if haystack_len > EXISTS_BATCH_CAPACITY {
            return Err(format!(
                "AOT Exists batch length {} exceeds capacity {EXISTS_BATCH_CAPACITY}",
                haystack_len
            ));
        }
        Ok(())
    }

    #[inline(never)]
    fn is_match_descriptor_batch_validated(
        &mut self,
        haystacks: &[AotHaystack<'_>],
        matched: &mut [bool],
    ) -> Result<(), String> {
        debug_assert_eq!(haystacks.len(), matched.len());
        debug_assert!(!haystacks.is_empty());
        debug_assert!(haystacks.len() <= EXISTS_BATCH_CAPACITY);
        match &mut self.backend {
            Backend::Prepared(prepared) => {
                if haystacks.len() > 1
                    && let Some(batch) = prepared.exists_batch
                {
                    return prepared_native_is_match_descriptor_batch(
                        batch,
                        prepared.handle,
                        haystacks,
                        matched,
                    );
                }
                for (haystack, matched) in haystacks.iter().zip(matched) {
                    let haystack = haystack.as_slice();
                    *matched = match prepared_native_search(
                        prepared.search,
                        prepared.handle,
                        AotOutput::Exists,
                        haystack,
                        0,
                    )? {
                        MatchResult::Exists(found) => found,
                        _ => {
                            return Err("AOT Exists artifact returned a different result contract"
                                .to_owned());
                        }
                    };
                }
            }
            Backend::Native {
                search,
                exists_batch,
                ..
            } => {
                if haystacks.len() > 1
                    && let Some(batch) = exists_batch
                {
                    return direct_native_is_match_descriptor_batch(*batch, haystacks, matched);
                }
                for (haystack, matched) in haystacks.iter().zip(matched) {
                    let haystack = haystack.as_slice();
                    *matched = match native_search(*search, AotOutput::Exists, haystack, 0)? {
                        MatchResult::Exists(found) => found,
                        _ => {
                            return Err("AOT Exists artifact returned a different result contract"
                                .to_owned());
                        }
                    };
                }
            }
            Backend::Runtime(prepared) => {
                for (haystack, matched) in haystacks.iter().zip(matched) {
                    let haystack = haystack.as_slice();
                    *matched = match prepared
                        .search(haystack, SearchWindow::new(0, haystack.len()))
                        .map_err(|error| format!("prepared AOT search: {error}"))?
                    {
                        MatchResult::Exists(found) => found,
                        _ => {
                            return Err("AOT Exists artifact returned a different result contract"
                                .to_owned());
                        }
                    };
                }
            }
        }
        Ok(())
    }

    #[inline(never)]
    fn is_match_descriptor_single(
        &mut self,
        haystack: &AotHaystack<'_>,
        matched: &mut bool,
    ) -> Result<(), String> {
        if self.output != AotOutput::Exists {
            return Err("AOT matcher was not compiled for Exists".to_owned());
        }
        let haystack = haystack.as_slice();
        *matched = match &mut self.backend {
            Backend::Prepared(prepared) => match prepared_native_search(
                prepared.search,
                prepared.handle,
                AotOutput::Exists,
                haystack,
                0,
            )? {
                MatchResult::Exists(found) => found,
                _ => {
                    return Err(
                        "AOT Exists artifact returned a different result contract".to_owned()
                    );
                }
            },
            Backend::Native { search, .. } => {
                match native_search(*search, AotOutput::Exists, haystack, 0)? {
                    MatchResult::Exists(found) => found,
                    _ => {
                        return Err(
                            "AOT Exists artifact returned a different result contract".to_owned()
                        );
                    }
                }
            }
            Backend::Runtime(prepared) => match prepared
                .search(haystack, SearchWindow::new(0, haystack.len()))
                .map_err(|error| format!("prepared AOT search: {error}"))?
            {
                MatchResult::Exists(found) => found,
                _ => {
                    return Err(
                        "AOT Exists artifact returned a different result contract".to_owned()
                    );
                }
            },
        };
        Ok(())
    }

    /// Find the first selected span in the complete haystack.
    ///
    /// # Errors
    ///
    /// Returns an error for an output-contract mismatch or execution failure.
    pub fn find<'h>(&mut self, haystack: &'h [u8]) -> Result<Option<AotMatch<'h>>, String> {
        self.find_at(haystack, 0)
    }

    /// Find the first selected span at or after `start` in the original haystack.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid start, output-contract mismatch, or
    /// execution failure.
    pub fn find_at<'h>(
        &mut self,
        haystack: &'h [u8],
        start: usize,
    ) -> Result<Option<AotMatch<'h>>, String> {
        if self.output != AotOutput::Span {
            return Err("AOT matcher was not compiled for Span".to_owned());
        }
        match self.search(haystack, start)? {
            MatchResult::Span(span) => span
                .map(|(match_start, match_end)| {
                    AotMatch::from_span(haystack, match_start, match_end).ok_or_else(|| {
                        "AOT Span artifact returned a match outside its haystack".to_owned()
                    })
                })
                .transpose(),
            _ => Err("AOT Span artifact returned a different result contract".to_owned()),
        }
    }

    /// Iterate over every non-overlapping match using Rust byte-regex empty
    /// match progress.
    ///
    /// Portable and compiled-prepared artifacts retain their workspace for
    /// the full iterator lifetime. Both compiled routes refill 64 spans at a
    /// time, amortizing indirect dispatch with bounded read-ahead.
    ///
    /// # Errors
    ///
    /// Returns an error unless this matcher was compiled for spans and has a
    /// compatible iterator backend. Execution failures remain iterator items.
    pub fn find_iter<'m, 'h>(
        &'m mut self,
        haystack: &'h [u8],
    ) -> Result<AotMatches<'m, 'h>, String> {
        if self.output != AotOutput::Span {
            return Err("AOT matcher was not compiled for Span".to_owned());
        }
        let backend = match &mut self.backend {
            Backend::Runtime(prepared) => AotMatchesBackend::Runtime(
                prepared
                    .find_iter(haystack)
                    .map_err(|error| error.to_string())?,
            ),
            Backend::Prepared(prepared) if prepared.span_fill.is_some() => {
                AotMatchesBackend::Native(NativeMatches::prepared(prepared, haystack))
            }
            Backend::Prepared(_) => {
                return Err("compiled-prepared Span artifact has no iterator entry".to_owned());
            }
            Backend::Native {
                fill: Some(fill), ..
            } => AotMatchesBackend::Native(NativeMatches::direct(*fill, haystack)),
            Backend::Native { fill: None, .. } => {
                return Err("AOT Span artifact has no native iterator entry".to_owned());
            }
        };
        Ok(AotMatches { backend })
    }

    fn search(&mut self, haystack: &[u8], start: usize) -> Result<MatchResult, String> {
        if start > haystack.len() {
            return Err(format!(
                "AOT search start {start} exceeds haystack length {}",
                haystack.len()
            ));
        }
        match &mut self.backend {
            Backend::Runtime(prepared) => prepared
                .search(haystack, SearchWindow::new(start, haystack.len()))
                .map_err(|error| format!("prepared AOT search: {error}")),
            Backend::Prepared(prepared) => prepared_native_search(
                prepared.search,
                prepared.handle,
                self.output,
                haystack,
                start,
            ),
            Backend::Native { search, .. } => native_search(*search, self.output, haystack, start),
        }
    }
}

fn missing_spec_error(
    mode: AotMode,
    output: AotOutput,
    pattern: &str,
    case_insensitive: bool,
) -> String {
    missing_spec_error_from(
        generated::SPECS,
        generated::BUILD_VARIANT_POLICY,
        mode,
        output,
        pattern,
        case_insensitive,
    )
}

fn missing_spec_error_from(
    specs: &[CompiledSpec],
    build_variant_policy: &str,
    mode: AotMode,
    output: AotOutput,
    pattern: &str,
    case_insensitive: bool,
) -> String {
    let available = specs
        .iter()
        .filter(|spec| spec.pattern == pattern && spec.case_insensitive == case_insensitive)
        .map(|spec| format!("{:?}+{:?}", spec.mode, spec.output))
        .collect::<Vec<_>>();
    if available.is_empty() {
        format!(
            "pattern/profile is not in the ripgrep AOT registry: mode={mode:?} output={output:?} case_insensitive={case_insensitive} pattern={pattern:?}"
        )
    } else {
        format!(
            "requested AOT variant was not emitted by this build: mode={mode:?} output={output:?} case_insensitive={case_insensitive} pattern={pattern:?}; build_variant_policy={}; available_variants={}; rebuild with FRE_RIPGREP_AOT_VARIANTS=all to emit every variant",
            build_variant_policy,
            available.join(","),
        )
    }
}

/// Stateful iterator over non-overlapping AOT matches.
#[derive(Debug)]
pub struct AotMatches<'m, 'h> {
    backend: AotMatchesBackend<'m, 'h>,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the inline native buffer deliberately avoids one heap allocation per scanned file"
)]
enum AotMatchesBackend<'m, 'h> {
    Native(NativeMatches<'m, 'h>),
    Runtime(PreparedAotMatches<'m, 'h>),
}

#[derive(Debug)]
enum NativeMatchesFill<'m> {
    Direct(NativeFill),
    Prepared(&'m mut PreparedNative),
}

#[derive(Debug)]
struct NativeMatches<'m, 'h> {
    fill: NativeMatchesFill<'m>,
    haystack: &'h [u8],
    state: NativeIterState,
    spans: [MaybeUninit<AbiResult>; NATIVE_SPAN_BUFFER_CAPACITY],
    next: usize,
    filled: usize,
    pending_error: Option<String>,
}

impl<'m, 'h> NativeMatches<'m, 'h> {
    fn direct(fill: NativeFill, haystack: &'h [u8]) -> Self {
        Self {
            fill: NativeMatchesFill::Direct(fill),
            haystack,
            state: NativeIterState::default(),
            spans: [const { MaybeUninit::uninit() }; NATIVE_SPAN_BUFFER_CAPACITY],
            next: 0,
            filled: 0,
            pending_error: None,
        }
    }

    fn prepared(prepared: &'m mut PreparedNative, haystack: &'h [u8]) -> Self {
        NativeMatches {
            fill: NativeMatchesFill::Prepared(prepared),
            haystack,
            state: NativeIterState::default(),
            spans: [const { MaybeUninit::uninit() }; NATIVE_SPAN_BUFFER_CAPACITY],
            next: 0,
            filled: 0,
            pending_error: None,
        }
    }

    fn fail(&mut self, error: String) -> Result<AotMatch<'h>, String> {
        self.state.finish();
        self.next = self.filled;
        self.pending_error = None;
        Err(error)
    }
}

#[allow(
    unsafe_code,
    reason = "the iterator reads only the initialized prefix returned by its trusted native fill shim"
)]
impl<'h> Iterator for NativeMatches<'_, 'h> {
    type Item = Result<AotMatch<'h>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.next < self.filled {
                // Only the `written` prefix reported by the refill is read.
                let span = unsafe { self.spans[self.next].assume_init() };
                self.next += 1;
                let Some(matched) = AotMatch::from_span(self.haystack, span.start, span.end) else {
                    return Some(self.fail(
                        "native AOT iterator buffered a match outside its haystack".to_owned(),
                    ));
                };
                return Some(Ok(matched));
            }
            if let Some(error) = self.pending_error.take() {
                return Some(self.fail(error));
            }
            if self.state.finished() {
                return None;
            }

            self.next = 0;
            let outcome = match &mut self.fill {
                NativeMatchesFill::Direct(fill) => {
                    fill(self.haystack, &mut self.state, &mut self.spans)
                }
                NativeMatchesFill::Prepared(prepared) => {
                    let fill = prepared
                        .span_fill
                        .expect("prepared iterator construction requires a fill entry");
                    match fill {
                        PreparedSpanFillFactory::Compiled(fill) => fill_prepared_spans(
                            fill,
                            prepared.handle,
                            self.haystack,
                            &mut self.state,
                            &mut self.spans,
                        ),
                        PreparedSpanFillFactory::Compatibility(fill) => fill(
                            prepared.handle,
                            self.haystack,
                            &mut self.state,
                            &mut self.spans,
                        ),
                    }
                }
            };
            self.filled = outcome.written;
            self.pending_error = outcome.error;
            if self.filled == 0 && self.pending_error.is_none() && !self.state.finished() {
                return Some(self.fail("native AOT iterator refill made no progress".to_owned()));
            }
        }
    }
}

impl<'h> Iterator for AotMatches<'_, 'h> {
    type Item = Result<AotMatch<'h>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.backend {
            AotMatchesBackend::Native(matches) => matches.next(),
            AotMatchesBackend::Runtime(matches) => matches
                .next()
                .map(|result| result.map_err(|error| error.to_string())),
        }
    }
}

impl std::iter::FusedIterator for NativeMatches<'_, '_> {}
impl std::iter::FusedIterator for AotMatches<'_, '_> {}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for compiler-produced V1 object entries"
)]
fn native_search(
    search: NativeSearch,
    output: AotOutput,
    haystack: &[u8],
    start: usize,
) -> Result<MatchResult, String> {
    let mut result = MaybeUninit::<AbiResult>::uninit();
    // SAFETY: compiler-produced entries use this exact C ABI. The slice gives
    // a non-null readable extent, the checked window is contained in it, and
    // `result` is aligned, writable, and disjoint for the duration of the call.
    let status = unsafe {
        search(
            haystack.as_ptr(),
            haystack.len(),
            start,
            haystack.len(),
            result.as_mut_ptr(),
        )
    };
    decode_search_result(output, status, haystack.len(), start, result)
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for compiler-produced prepared V1 object entries"
)]
fn prepared_native_search(
    search: PreparedSearch,
    handle: FreAotRegexExclusiveHandleV1,
    output: AotOutput,
    haystack: &[u8],
    start: usize,
) -> Result<MatchResult, String> {
    let mut result = MaybeUninit::<AbiResult>::uninit();
    // SAFETY: `PreparedNative` owns the live handle and is mutably borrowed
    // for this call. The remaining arguments satisfy the generated entry's
    // stable six-argument prepared ABI and are retained by neither side.
    let status = unsafe {
        search(
            handle,
            haystack.as_ptr(),
            haystack.len(),
            start,
            haystack.len(),
            result.as_mut_ptr(),
        )
    };
    decode_search_result(output, status, haystack.len(), start, result)
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for a compiler-produced direct Exists-batch entry"
)]
#[inline(never)]
fn direct_native_is_match_descriptor_batch(
    batch: NativeExistsBatch,
    haystacks: &[AotHaystack<'_>],
    matched: &mut [bool],
) -> Result<(), String> {
    debug_assert_eq!(haystacks.len(), matched.len());
    debug_assert!(!haystacks.is_empty());
    debug_assert!(haystacks.len() <= EXISTS_BATCH_CAPACITY);

    let mut processed = 0;
    // SAFETY: `AotHaystack` is transparent over `AbiHaystack`; its private
    // constructor and lifetime guarantee every descriptor names a live
    // readable slice. The batch ABI retains no pointer. This compiler-produced
    // entry writes only the valid Boolean representations 0 and 1 to the live
    // output prefix; the untouched tail remains initialized by the safe caller.
    let status = unsafe {
        batch(
            haystacks.as_ptr().cast::<AbiHaystack>(),
            haystacks.len(),
            matched.as_mut_ptr().cast::<u8>(),
            &raw mut processed,
        )
    };
    if status == 0 && processed == haystacks.len() {
        Ok(())
    } else {
        direct_exists_batch_failure(status, processed, haystacks.len())
    }
}

#[cold]
#[inline(never)]
fn direct_exists_batch_failure(
    status: u32,
    processed: usize,
    count: usize,
) -> Result<(), String> {
    if processed > count {
        return Err(format!(
            "compiled Exists batch overreported its initialized prefix: {processed} > {count}"
        ));
    }
    if status != 0 {
        return Err(format!(
            "compiled Exists batch failed with status {status} after {processed}/{count} haystacks"
        ));
    }
    debug_assert_ne!(processed, count);
    Err(format!(
        "compiled Exists batch returned success after {processed}/{count} haystacks"
    ))
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for a compiler-produced prepared Exists-batch entry"
)]
fn prepared_native_is_match_descriptor_batch(
    batch: PreparedExistsBatch,
    handle: FreAotRegexExclusiveHandleV1,
    haystacks: &[AotHaystack<'_>],
    matched: &mut [bool],
) -> Result<(), String> {
    debug_assert_eq!(haystacks.len(), matched.len());
    debug_assert!(!haystacks.is_empty());
    debug_assert!(haystacks.len() <= EXISTS_BATCH_CAPACITY);

    let mut encoded = [0xff_u8; EXISTS_BATCH_CAPACITY];
    let mut processed = 0;
    // SAFETY: `PreparedNative` exclusively owns `handle`. `AotHaystack` is
    // transparent over `AbiHaystack`; its private constructor and lifetime
    // guarantee every descriptor names a live readable slice. The batch ABI
    // retains no pointer. `encoded` has `count` writable bytes, and the
    // generated entry initializes exactly the prefix published in `processed`.
    let status = unsafe {
        batch(
            handle,
            haystacks.as_ptr().cast::<AbiHaystack>(),
            haystacks.len(),
            encoded.as_mut_ptr(),
            &raw mut processed,
        )
    };
    decode_exists_batch(status, processed, haystacks.len(), &encoded, matched)
}

fn decode_exists_batch(
    status: u32,
    processed: usize,
    count: usize,
    encoded: &[u8; EXISTS_BATCH_CAPACITY],
    matched: &mut [bool],
) -> Result<(), String> {
    if processed > count {
        return Err(format!(
            "compiled Exists batch overreported its initialized prefix: {processed} > {count}"
        ));
    }
    for (index, encoded) in encoded[..processed].iter().copied().enumerate() {
        matched[index] = match encoded {
            0 => false,
            1 => true,
            other => {
                return Err(format!(
                    "compiled Exists batch returned invalid boolean {other} at index {index}"
                ));
            }
        };
    }
    if status != 0 {
        return Err(format!(
            "compiled Exists batch failed with status {status} after {processed}/{count} haystacks"
        ));
    }
    if processed != count {
        return Err(format!(
            "compiled Exists batch returned success after {processed}/{count} haystacks"
        ));
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "status 1 from either compiler-produced entry guarantees an initialized result"
)]
// Scalar Exists calls should fold the two valid statuses at their ABI call
// site instead of paying a generic result-decoder call after the native entry.
#[inline(always)]
fn decode_search_result(
    output: AotOutput,
    status: u32,
    haystack_len: usize,
    start: usize,
    result: MaybeUninit<AbiResult>,
) -> Result<MatchResult, String> {
    match (output, status) {
        (AotOutput::Exists, 0) => Ok(MatchResult::Exists(false)),
        (AotOutput::Exists, 1) => Ok(MatchResult::Exists(true)),
        (AotOutput::Span, 0) => Ok(MatchResult::Span(None)),
        (AotOutput::Span, 1) => {
            // Compiler-produced Span entries initialize the result on status
            // 1. Other statuses never read it.
            let result = unsafe { result.assume_init() };
            if start <= result.start && result.start <= result.end && result.end <= haystack_len {
                Ok(MatchResult::Span(Some((result.start, result.end))))
            } else {
                Err(format!(
                    "native AOT entry returned an invalid result: status={status} start={} end={} window={start}..{}",
                    result.start, result.end, haystack_len
                ))
            }
        }
        _ => Err(format!("native AOT entry failed with status {status}")),
    }
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "tests provide small audited stand-ins for compiler-produced native entries"
)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const fn assert_send<T: Send>() {}

    const _: () = assert_send::<AotMatcher>();

    static SEARCH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FILL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PREPARED_SPAN_FILL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PREPARED_EXACT_CAPACITY_FILL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PREPARED_EXISTS_BATCH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DIRECT_EXISTS_BATCH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SINGLETON_EXISTS_SCALAR_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SINGLETON_EXISTS_BATCH_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn one_byte_search(
        _haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        if window_start >= window_end || window_start >= haystack_len {
            return 0;
        }
        unsafe {
            result.write(AbiResult {
                start: window_start,
                end: window_start + 1,
            });
        }
        1
    }

    unsafe extern "C" fn counted_one_byte_search(
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        SEARCH_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe { one_byte_search(haystack, haystack_len, window_start, window_end, result) }
    }

    unsafe extern "C" fn counted_one_byte_prepared_search(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        unsafe { counted_one_byte_search(haystack, haystack_len, window_start, window_end, result) }
    }

    unsafe extern "C" fn singleton_one_byte_search(
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        SINGLETON_EXISTS_SCALAR_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe { one_byte_search(haystack, haystack_len, window_start, window_end, result) }
    }

    unsafe extern "C" fn singleton_one_byte_prepared_search(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        unsafe { singleton_one_byte_search(haystack, haystack_len, window_start, window_end, result) }
    }

    fn dense_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        FILL_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the test entry initializes `result` on every status-1 return
        // and retains none of the borrowed arguments.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                counted_one_byte_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    unsafe fn mock_prepared_span_fill(
        search: NativeSearch,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        let haystack = unsafe { std::slice::from_raw_parts(haystack, haystack_len) };
        let state = unsafe { &mut *state };
        let output = unsafe {
            std::slice::from_raw_parts_mut(results.cast::<MaybeUninit<AbiResult>>(), capacity)
        };
        let outcome = unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        };
        unsafe { written.write(outcome.written) };
        if outcome.error.is_some() {
            2
        } else {
            u32::from(!state.finished())
        }
    }

    unsafe extern "C" fn dense_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        PREPARED_SPAN_FILL_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            mock_prepared_span_fill(
                one_byte_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn exact_capacity_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        PREPARED_EXACT_CAPACITY_FILL_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            mock_prepared_span_fill(
                one_byte_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn nullable_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            mock_prepared_span_fill(
                nullable_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn two_then_error_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            mock_prepared_span_fill(
                two_then_error_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn invalid_state_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        _haystack: *const u8,
        _haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        _capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            results.write(AbiResult { start: 0, end: 1 });
            state.write(NativeIterState {
                next_start: 1,
                last_match_end: 0,
                flags: ITER_HAS_LAST | ITER_PENDING_EMPTY | ITER_FINISHED,
                reserved: 0,
            });
            written.write(1);
        }
        0
    }

    unsafe extern "C" fn mismatched_last_span_prepared_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        _haystack: *const u8,
        _haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        _capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            results.write(AbiResult { start: 0, end: 1 });
            state.write(NativeIterState {
                next_start: 2,
                last_match_end: 2,
                flags: ITER_HAS_LAST | ITER_FINISHED,
                reserved: 0,
            });
            written.write(1);
        }
        0
    }

    unsafe extern "C" fn contains_x_prepared_exists_batch(
        _handle: FreAotRegexExclusiveHandleV1,
        haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        PREPARED_EXISTS_BATCH_CALLS.fetch_add(1, Ordering::Relaxed);
        let haystacks = unsafe { std::slice::from_raw_parts(haystacks, count) };
        let matched = unsafe { std::slice::from_raw_parts_mut(matched, count) };
        for (index, haystack) in haystacks.iter().enumerate() {
            let bytes = unsafe { std::slice::from_raw_parts(haystack.ptr, haystack.len) };
            matched[index] = u8::from(bytes.contains(&b'x'));
        }
        unsafe { processed.write(count) };
        0
    }

    unsafe extern "C" fn contains_x_direct_exists_batch(
        haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        DIRECT_EXISTS_BATCH_CALLS.fetch_add(1, Ordering::Relaxed);
        let haystacks = unsafe { std::slice::from_raw_parts(haystacks, count) };
        let matched = unsafe { std::slice::from_raw_parts_mut(matched, count) };
        for (index, haystack) in haystacks.iter().enumerate() {
            let bytes = unsafe { std::slice::from_raw_parts(haystack.ptr, haystack.len) };
            matched[index] = u8::from(bytes.contains(&b'x'));
        }
        unsafe { processed.write(count) };
        0
    }

    unsafe extern "C" fn one_then_error_direct_exists_batch(
        _haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        if count == 0 {
            unsafe { processed.write(0) };
        } else {
            unsafe {
                matched.write(1);
                processed.write(1);
            }
        }
        7
    }

    unsafe extern "C" fn singleton_prepared_exists_batch(
        _handle: FreAotRegexExclusiveHandleV1,
        _haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        SINGLETON_EXISTS_BATCH_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            std::ptr::write_bytes(matched, 0, count);
            processed.write(count);
        }
        0
    }

    unsafe extern "C" fn singleton_direct_exists_batch(
        _haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        SINGLETON_EXISTS_BATCH_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            std::ptr::write_bytes(matched, 0, count);
            processed.write(count);
        }
        0
    }

    unsafe extern "C" fn nullable_search(
        _haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        _window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        let span = if haystack_len == 1 && window_start == 0 {
            AbiResult { start: 0, end: 1 }
        } else if window_start <= haystack_len {
            AbiResult {
                start: window_start,
                end: window_start,
            }
        } else {
            return 0;
        };
        unsafe { result.write(span) };
        1
    }

    fn nullable_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        // SAFETY: the test entry initializes `result` on every status-1 return
        // and retains none of the borrowed arguments.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                nullable_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    unsafe extern "C" fn dense_then_empty_search(
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        if window_start < haystack_len {
            return unsafe {
                one_byte_search(haystack, haystack_len, window_start, window_end, result)
            };
        }
        if window_start == haystack_len {
            unsafe {
                result.write(AbiResult {
                    start: window_start,
                    end: window_start,
                });
            }
            return 1;
        }
        0
    }

    fn dense_then_empty_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        // SAFETY: the test entry initializes `result` on every status-1 return
        // and retains none of the borrowed arguments.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                dense_then_empty_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    unsafe extern "C" fn two_then_error_search(
        _haystack: *const u8,
        _haystack_len: usize,
        window_start: usize,
        _window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        if window_start < 2 {
            unsafe {
                result.write(AbiResult {
                    start: window_start,
                    end: window_start + 1,
                });
            }
            1
        } else {
            2
        }
    }

    fn two_then_error_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        // SAFETY: the test entry initializes `result` on every status-1 return
        // and retains none of the borrowed arguments.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                two_then_error_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    unsafe extern "C" fn invalid_search(
        _haystack: *const u8,
        _haystack_len: usize,
        window_start: usize,
        _window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        unsafe {
            result.write(AbiResult {
                start: window_start.saturating_add(1),
                end: window_start,
            });
        }
        1
    }

    fn invalid_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        // SAFETY: the deliberately invalid semantic span is still fully
        // initialized on status 1 and no borrowed argument is retained.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                invalid_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    fn native_matcher(search: NativeSearch, fill: NativeFill) -> AotMatcher {
        AotMatcher {
            output: AotOutput::Span,
            description: "test-native",
            backend: Backend::Native {
                search,
                fill: Some(fill),
                exists_batch: None,
            },
        }
    }

    fn prepared_test_matcher(
        output: AotOutput,
        span_fill: Option<PreparedSpanFill>,
        exists_batch: Option<PreparedExistsBatch>,
    ) -> AotMatcher {
        AotMatcher {
            output,
            description: "test-compiled-prepared",
            backend: Backend::Prepared(PreparedNative {
                search: counted_one_byte_prepared_search,
                span_fill: span_fill.map(PreparedSpanFillFactory::Compiled),
                exists_batch,
                handle: FreAotRegexExclusiveHandleV1::INVALID,
            }),
        }
    }

    fn direct_exists_test_matcher(batch: NativeExistsBatch) -> AotMatcher {
        AotMatcher {
            output: AotOutput::Exists,
            description: "test-direct-native",
            backend: Backend::Native {
                search: counted_one_byte_search,
                fill: None,
                exists_batch: Some(batch),
            },
        }
    }

    #[test]
    fn native_iterator_batches_indirect_refills() {
        SEARCH_CALLS.store(0, Ordering::Relaxed);
        FILL_CALLS.store(0, Ordering::Relaxed);
        let haystack = vec![b'a'; NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2];
        let mut matcher = native_matcher(counted_one_byte_search, dense_fill);
        let spans = matcher
            .find_iter(&haystack)
            .expect("Span iterator")
            .map(|matched| matched.expect("native match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), haystack.len());
        assert_eq!(spans.first(), Some(&(0..1)));
        assert_eq!(spans.last(), Some(&((haystack.len() - 1)..haystack.len())));
        assert_eq!(FILL_CALLS.load(Ordering::Relaxed), 3);
        assert_eq!(SEARCH_CALLS.load(Ordering::Relaxed), haystack.len() + 1);
    }

    #[test]
    fn prepared_iterator_crosses_native_fill_abi_once_per_refill() {
        PREPARED_SPAN_FILL_CALLS.store(0, Ordering::Relaxed);
        let haystack = vec![b'a'; NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2];
        let mut matcher =
            prepared_test_matcher(AotOutput::Span, Some(dense_prepared_span_fill), None);
        let spans = matcher
            .find_iter(&haystack)
            .expect("prepared Span iterator")
            .map(|matched| matched.expect("prepared native match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), haystack.len());
        assert_eq!(PREPARED_SPAN_FILL_CALLS.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn prepared_iterator_exact_capacity_requires_terminal_refill() {
        PREPARED_EXACT_CAPACITY_FILL_CALLS.store(0, Ordering::Relaxed);
        let haystack = vec![b'a'; NATIVE_SPAN_BUFFER_CAPACITY];
        let mut matcher = prepared_test_matcher(
            AotOutput::Span,
            Some(exact_capacity_prepared_span_fill),
            None,
        );
        let spans = matcher
            .find_iter(&haystack)
            .expect("prepared exact-capacity iterator")
            .map(|matched| matched.expect("prepared native match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), NATIVE_SPAN_BUFFER_CAPACITY);
        assert_eq!(
            PREPARED_EXACT_CAPACITY_FILL_CALLS.load(Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn prepared_iterator_preserves_nullable_empty_progress() {
        let mut matcher =
            prepared_test_matcher(AotOutput::Span, Some(nullable_prepared_span_fill), None);
        let spans = matcher
            .find_iter(b"a")
            .expect("prepared nullable iterator")
            .map(|matched| matched.expect("prepared match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0], 0..1);

        let mut matcher =
            prepared_test_matcher(AotOutput::Span, Some(nullable_prepared_span_fill), None);
        let spans = matcher
            .find_iter(&[0xe2, 0x98, 0x83])
            .expect("prepared empty iterator")
            .map(|matched| matched.expect("prepared empty match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans, [0..0, 1..1, 2..2, 3..3]);
    }

    #[test]
    fn prepared_iterator_yields_initialized_prefix_before_error() {
        let mut prepared = prepared_test_matcher(
            AotOutput::Span,
            Some(two_then_error_prepared_span_fill),
            None,
        );
        let mut iteration = prepared.find_iter(b"aaa").expect("prepared iterator");
        assert_eq!(
            iteration
                .next()
                .expect("first item")
                .expect("first match")
                .range(),
            0..1
        );
        assert_eq!(
            iteration
                .next()
                .expect("second item")
                .expect("second match")
                .range(),
            1..2
        );
        assert!(
            iteration
                .next()
                .expect("deferred error")
                .expect_err("status error")
                .contains("status 2")
        );
        assert!(iteration.next().is_none());
    }

    #[test]
    fn prepared_iterator_rejects_inconsistent_native_state_and_fuses() {
        let mut prepared = prepared_test_matcher(
            AotOutput::Span,
            Some(invalid_state_prepared_span_fill),
            None,
        );
        let mut iteration = prepared.find_iter(b"a").expect("prepared iterator");
        assert!(
            iteration
                .next()
                .expect("one error")
                .expect_err("invalid state")
                .contains("invalid iterator state")
        );
        assert!(iteration.next().is_none());
    }

    #[test]
    fn prepared_iterator_rejects_incoherent_last_span_and_fuses() {
        let mut prepared = prepared_test_matcher(
            AotOutput::Span,
            Some(mismatched_last_span_prepared_fill),
            None,
        );
        let mut iteration = prepared.find_iter(b"aa").expect("prepared iterator");
        assert!(
            iteration
                .next()
                .expect("one error")
                .expect_err("inconsistent final span/state")
                .contains("inconsistent final span/state")
        );
        assert!(iteration.next().is_none());
    }

    #[test]
    fn aot_haystack_is_an_exact_lifetime_bound_abi_view() {
        assert_eq!(
            std::mem::size_of::<AotHaystack<'_>>(),
            std::mem::size_of::<AbiHaystack>()
        );
        assert_eq!(
            std::mem::align_of::<AotHaystack<'_>>(),
            std::mem::align_of::<AbiHaystack>()
        );

        let bytes = [0x00, 0x7f, 0xff];
        let descriptor = AotHaystack::from(bytes.as_slice());
        assert_eq!(descriptor.abi.ptr, bytes.as_ptr());
        assert_eq!(descriptor.abi.len, bytes.len());
        assert_eq!(descriptor.as_slice(), bytes);

        let empty = AotHaystack::from([].as_slice());
        assert_eq!(empty.abi.len, 0);
        assert!(empty.as_slice().is_empty());
    }

    #[test]
    fn descriptor_batch_accepts_empty_and_rejects_invalid_lengths() {
        let mut direct = direct_exists_test_matcher(contains_x_direct_exists_batch);
        direct
            .is_match_descriptor_batch(&[], &mut [])
            .expect("empty descriptor batch");

        let one = [AotHaystack::from(b"x")];
        let mut span = native_matcher(one_byte_search, dense_fill);
        let mut outcome = [true];
        let error = span
            .is_match_descriptor_batch(&one, &mut outcome)
            .expect_err("descriptor singleton output-contract mismatch");
        assert_eq!(error, "AOT matcher was not compiled for Exists");
        assert_eq!(outcome, [true]);

        let two = [AotHaystack::from(b"x"), AotHaystack::from(b"no")];
        let error = direct
            .is_match_descriptor_batch(&two, &mut [false])
            .expect_err("descriptor/output length mismatch");
        assert!(error.contains("length mismatch: 2 != 1"));

        let oversized = vec![AotHaystack::from(b""); EXISTS_BATCH_CAPACITY + 1];
        let mut outcomes = vec![true; oversized.len()];
        let error = direct
            .is_match_descriptor_batch(&oversized, &mut outcomes)
            .expect_err("oversized descriptor batch");
        assert!(error.contains("exceeds capacity"));
        assert!(outcomes.iter().all(|&matched| matched));
    }

    #[test]
    fn descriptor_batch_publishes_mixed_prepared_and_direct_results() {
        let lines = [b"x".as_slice(), b"no".as_slice(), b"suffix-x".as_slice()];
        let descriptors = lines.map(AotHaystack::from);

        PREPARED_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);
        let mut prepared = prepared_test_matcher(
            AotOutput::Exists,
            None,
            Some(contains_x_prepared_exists_batch),
        );
        let mut prepared_outcomes = [false; 3];
        prepared
            .is_match_descriptor_batch(&descriptors, &mut prepared_outcomes)
            .expect("prepared descriptor batch");
        assert_eq!(prepared_outcomes, [true, false, true]);
        assert_eq!(PREPARED_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 1);

        DIRECT_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);
        let mut direct = direct_exists_test_matcher(contains_x_direct_exists_batch);
        let mut direct_outcomes = [false; 3];
        direct
            .is_match_descriptor_batch(&descriptors, &mut direct_outcomes)
            .expect("direct descriptor batch");
        assert_eq!(direct_outcomes, prepared_outcomes);
        assert_eq!(DIRECT_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn descriptor_batch_failure_preserves_valid_boolean_prefix_and_tail() {
        let descriptors = [
            AotHaystack::from(b"first"),
            AotHaystack::from(b"second"),
            AotHaystack::from(b"third"),
        ];
        let mut outcomes = [false, true, false];
        let mut direct = direct_exists_test_matcher(one_then_error_direct_exists_batch);
        let error = direct
            .is_match_descriptor_batch(&descriptors, &mut outcomes)
            .expect_err("native failure after one Boolean result");
        assert!(error.contains("status 7 after 1/3"));
        assert_eq!(outcomes, [true, true, false]);
    }

    #[test]
    fn descriptor_batch_scalar_fallback_reads_the_borrowed_slices() {
        let descriptors = [AotHaystack::from(b""), AotHaystack::from(b"nonempty")];
        let mut outcomes = [true, false];
        let mut direct = AotMatcher {
            output: AotOutput::Exists,
            description: "test-direct-scalar-fallback",
            backend: Backend::Native {
                search: one_byte_search,
                fill: None,
                exists_batch: None,
            },
        };
        direct
            .is_match_descriptor_batch(&descriptors, &mut outcomes)
            .expect("descriptor scalar fallback");
        assert_eq!(outcomes, [false, true]);
    }

    #[test]
    fn prepared_exists_batch_crosses_native_abi_once_for_64_lines() {
        PREPARED_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);
        let lines = (0..EXISTS_BATCH_CAPACITY)
            .map(|index| {
                if index % 3 == 0 {
                    b"x".as_slice()
                } else {
                    b"no".as_slice()
                }
            })
            .collect::<Vec<_>>();
        let mut outcomes = [false; EXISTS_BATCH_CAPACITY];
        let mut prepared = prepared_test_matcher(
            AotOutput::Exists,
            None,
            Some(contains_x_prepared_exists_batch),
        );
        prepared
            .is_match_batch(&lines, &mut outcomes)
            .expect("prepared Exists batch");
        for (index, matched) in outcomes.into_iter().enumerate() {
            assert_eq!(matched, index % 3 == 0);
        }
        assert_eq!(PREPARED_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn direct_exists_batch_crosses_native_abi_once_for_64_lines() {
        DIRECT_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);
        let lines = (0..EXISTS_BATCH_CAPACITY)
            .map(|index| {
                if index % 3 == 0 {
                    b"x".as_slice()
                } else {
                    b"no".as_slice()
                }
            })
            .collect::<Vec<_>>();
        let mut outcomes = [false; EXISTS_BATCH_CAPACITY];
        let mut direct = direct_exists_test_matcher(contains_x_direct_exists_batch);
        direct
            .is_match_batch(&lines, &mut outcomes)
            .expect("direct Exists batch");
        for (index, matched) in outcomes.into_iter().enumerate() {
            assert_eq!(matched, index % 3 == 0);
        }
        assert_eq!(DIRECT_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn direct_exists_batch_failure_preserves_valid_boolean_prefix_and_tail() {
        let lines = [b"first".as_slice(), b"second".as_slice(), b"third".as_slice()];
        let mut outcomes = [false, true, false];
        let mut direct = direct_exists_test_matcher(one_then_error_direct_exists_batch);
        let error = direct
            .is_match_batch(&lines, &mut outcomes)
            .expect_err("native failure after one Boolean result");
        assert!(error.contains("status 7 after 1/3"));
        assert_eq!(outcomes, [true, true, false]);
    }

    #[test]
    fn one_haystack_exists_batches_use_the_backend_scalar_entry() {
        SINGLETON_EXISTS_SCALAR_CALLS.store(0, Ordering::Relaxed);
        SINGLETON_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);

        let mut prepared = AotMatcher {
            output: AotOutput::Exists,
            description: "test-singleton-prepared",
            backend: Backend::Prepared(PreparedNative {
                search: singleton_one_byte_prepared_search,
                span_fill: None,
                exists_batch: Some(singleton_prepared_exists_batch),
                handle: FreAotRegexExclusiveHandleV1::INVALID,
            }),
        };
        let mut prepared_outcome = [false];
        prepared
            .is_match_batch(&[b"no"], &mut prepared_outcome)
            .expect("one-haystack prepared Exists request");

        let mut direct = AotMatcher {
            output: AotOutput::Exists,
            description: "test-singleton-direct",
            backend: Backend::Native {
                search: singleton_one_byte_search,
                fill: None,
                exists_batch: Some(singleton_direct_exists_batch),
            },
        };
        let mut direct_outcome = [false];
        direct
            .is_match_batch(&[b"no"], &mut direct_outcome)
            .expect("one-haystack direct Exists request");

        let descriptor = [AotHaystack::from(b"no")];
        let mut prepared_descriptor_outcome = [false];
        prepared
            .is_match_descriptor_batch(&descriptor, &mut prepared_descriptor_outcome)
            .expect("one-descriptor prepared Exists request");
        let mut direct_descriptor_outcome = [false];
        direct
            .is_match_descriptor_batch(&descriptor, &mut direct_descriptor_outcome)
            .expect("one-descriptor direct Exists request");

        assert_eq!(prepared_outcome, [true]);
        assert_eq!(direct_outcome, [true]);
        assert_eq!(prepared_descriptor_outcome, [true]);
        assert_eq!(direct_descriptor_outcome, [true]);
        assert_eq!(SINGLETON_EXISTS_SCALAR_CALLS.load(Ordering::Relaxed), 4);
        assert_eq!(SINGLETON_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn exists_batch_decoder_accepts_only_the_published_boolean_prefix() {
        let mut encoded = [0xff_u8; EXISTS_BATCH_CAPACITY];
        let mut matched = [false; 3];

        let error = decode_exists_batch(0, 4, 3, &encoded, &mut matched)
            .expect_err("overreported prefix");
        assert!(error.contains("overreported"));
        assert_eq!(matched, [false; 3]);

        encoded[0] = 1;
        encoded[1] = 2;
        let error = decode_exists_batch(0, 2, 3, &encoded, &mut matched)
            .expect_err("invalid Boolean");
        assert!(error.contains("invalid boolean 2 at index 1"));
        assert_eq!(matched, [true, false, false]);

        matched = [false; 3];
        let error = decode_exists_batch(7, 1, 3, &encoded, &mut matched)
            .expect_err("native failure after one result");
        assert!(error.contains("status 7 after 1/3"));
        assert_eq!(matched, [true, false, false]);

        let error = decode_exists_batch(0, 1, 3, &encoded, &mut matched)
            .expect_err("partial success is invalid");
        assert!(error.contains("success after 1/3"));
        assert_eq!(matched, [true, false, false]);

        encoded[1] = 0;
        encoded[2] = 1;
        decode_exists_batch(0, 3, 3, &encoded, &mut matched).expect("complete Boolean prefix");
        assert_eq!(matched, [true, false, true]);
    }

    #[test]
    fn generated_direct_exists_batches_match_their_scalar_entries() {
        const CASES: [&[u8]; 10] = [
            b"",
            b"a",
            b"needle",
            b"\n",
            b"\n\n",
            b"a\n",
            b"a\r\nb",
            b"late needle",
            &[0xff, 0x00, b'a'],
            &[b'x'; 65],
        ];
        let mut exercised = 0;
        for spec in generated::SPECS {
            if spec.output != AotOutput::Exists
                || !matches!(
                    spec.backend,
                    BackendFactory::Native {
                        exists_batch: Some(_),
                        ..
                    }
                )
            {
                continue;
            }
            exercised += 1;
            for count in [1, 63, 64] {
                let haystacks = (0..count)
                    .map(|index| CASES[index % CASES.len()])
                    .collect::<Vec<_>>();
                let mut scalar = AotMatcher::new(
                    spec.mode,
                    spec.output,
                    spec.pattern,
                    spec.case_insensitive,
                )
                .expect("direct scalar matcher");
                let expected = haystacks
                    .iter()
                    .map(|haystack| scalar.is_match(haystack).expect("direct scalar search"))
                    .collect::<Vec<_>>();
                let mut batch = AotMatcher::new(
                    spec.mode,
                    spec.output,
                    spec.pattern,
                    spec.case_insensitive,
                )
                .expect("direct batch matcher");
                let mut actual = vec![false; count];
                batch
                    .is_match_batch(&haystacks, &mut actual)
                    .expect("direct native batch search");
                assert_eq!(actual, expected);
            }
        }
        assert!(exercised > 0, "generated registry has no direct Exists batch");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one raw-ABI test keeps top-level, prefix, descriptor, and signed-domain failure ordering together"
    )]
    fn generated_direct_exists_batch_raw_abi_fails_closed() {
        let batch = generated::SPECS
            .iter()
            .find_map(|spec| match spec.backend {
                BackendFactory::Native {
                    exists_batch: Some(batch),
                    ..
                } if spec.output == AotOutput::Exists => Some(batch),
                _ => None,
            })
            .expect("generated direct Exists batch");
        let mut processed = usize::MAX;
        // SAFETY: zero count permits null descriptor and output arrays; the
        // processed word is live, aligned, and writable.
        let status = unsafe {
            batch(
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                &raw mut processed,
            )
        };
        assert_eq!(status, 0);
        assert_eq!(processed, 0);

        let mut output = [0xa5_u8; 2];
        processed = usize::MAX;
        // SAFETY: deliberately invalid top-level arguments are never
        // dereferenced by the validated compiler boundary.
        let status = unsafe {
            batch(
                std::ptr::null(),
                1,
                output.as_mut_ptr(),
                &raw mut processed,
            )
        };
        assert_eq!(status, 2);
        assert_eq!(processed, usize::MAX);
        assert_eq!(output, [0xa5; 2]);

        let valid = b"needle";
        let descriptors = [
            AbiHaystack {
                ptr: valid.as_ptr(),
                len: valid.len(),
            },
            AbiHaystack {
                ptr: std::ptr::null(),
                len: 0,
            },
        ];
        processed = usize::MAX;
        // SAFETY: the first descriptor is valid. The second is deliberately
        // invalid and must stop before source access or tail publication.
        let status = unsafe {
            batch(
                descriptors.as_ptr(),
                descriptors.len(),
                output.as_mut_ptr(),
                &raw mut processed,
            )
        };
        assert_eq!(status, 2);
        assert_eq!(processed, 1);
        assert!(output[0] <= 1);
        assert_eq!(output[1], 0xa5);

        let oversized = [AbiHaystack {
            ptr: std::ptr::NonNull::<u8>::dangling().as_ptr().cast_const(),
            len: (isize::MAX as usize) + 1,
        }];
        output[0] = 0xa5;
        processed = usize::MAX;
        // SAFETY: the signed-domain length is rejected before the dangling
        // source pointer can be dereferenced.
        let status = unsafe {
            batch(
                oversized.as_ptr(),
                1,
                output.as_mut_ptr(),
                &raw mut processed,
            )
        };
        assert_eq!(status, 2);
        assert_eq!(processed, 0);
        assert_eq!(output[0], 0xa5);

        // SAFETY: both deliberately misaligned pointers are rejected before
        // dereference. Count overflow is checked before descriptor access.
        assert_eq!(
            unsafe {
                batch(
                    std::ptr::without_provenance::<AbiHaystack>(1),
                    1,
                    output.as_mut_ptr(),
                    &raw mut processed,
                )
            },
            2
        );
        assert_eq!(
            unsafe {
                batch(
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::without_provenance_mut::<usize>(1),
                )
            },
            2
        );
        assert_eq!(
            unsafe {
                batch(
                    std::ptr::null(),
                    (isize::MAX as usize / 16) + 1,
                    std::ptr::null_mut(),
                    &raw mut processed,
                )
            },
            2
        );
    }

    #[test]
    fn native_iterator_matches_rust_empty_progress_across_refills() {
        let mut matcher = native_matcher(nullable_search, nullable_fill);
        let spans = matcher
            .find_iter(b"a")
            .expect("Span iterator")
            .map(|matched| matched.expect("native match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans, [0..1]);

        let mut matcher = native_matcher(nullable_search, nullable_fill);
        let spans = matcher
            .find_iter(&[0xe2, 0x98, 0x83])
            .expect("Span iterator")
            .map(|matched| matched.expect("native empty match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans, [0..0, 1..1, 2..2, 3..3]);

        let haystack = vec![b'a'; NATIVE_SPAN_BUFFER_CAPACITY];
        let mut matcher = native_matcher(dense_then_empty_search, dense_then_empty_fill);
        let spans = matcher
            .find_iter(&haystack)
            .expect("Span iterator")
            .map(|matched| matched.expect("native boundary match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), haystack.len());
        assert_eq!(spans.last(), Some(&((haystack.len() - 1)..haystack.len())));
    }

    #[test]
    fn native_iterator_reports_validation_error_once_and_fuses() {
        let mut matcher = native_matcher(invalid_search, invalid_fill);
        let mut matches = matcher.find_iter(b"aa").expect("Span iterator");
        let error = matches
            .next()
            .expect("one error")
            .expect_err("invalid span");
        assert!(error.contains("invalid result"));
        assert!(matches.next().is_none());
        assert!(matches.next().is_none());

        let mut matcher = native_matcher(two_then_error_search, two_then_error_fill);
        let mut matches = matcher.find_iter(b"aaa").expect("Span iterator");
        assert_eq!(
            matches
                .next()
                .expect("first item")
                .expect("first match")
                .range(),
            0..1
        );
        assert_eq!(
            matches
                .next()
                .expect("second item")
                .expect("second match")
                .range(),
            1..2
        );
        assert!(
            matches
                .next()
                .expect("deferred error")
                .expect_err("status error")
                .contains("status 2")
        );
        assert!(matches.next().is_none());
    }

    #[test]
    fn native_find_returns_borrowed_match_and_checks_contract() {
        let mut matcher = native_matcher(one_byte_search, dense_fill);
        let matched = matcher.find(b"ab").expect("find").expect("match");
        assert_eq!(matched.range(), 0..1);
        assert_eq!(matched.as_bytes(), b"a");

        matcher.output = AotOutput::Exists;
        assert!(
            matcher
                .find_iter(b"ab")
                .expect_err("Span required")
                .contains("not compiled for Span")
        );
    }

    #[test]
    fn missing_build_variant_error_names_policy_and_available_variant() {
        let specs = [CompiledSpec {
            mode: AotMode::Optimizing,
            output: AotOutput::Exists,
            pattern: "shape(?:one|two|three)",
            case_insensitive: false,
            description: "test-only",
            backend: BackendFactory::Runtime(&[]),
        }];
        let error = missing_spec_error_from(
            &specs,
            "optimizing-exists",
            AotMode::Fast,
            AotOutput::Span,
            "shape(?:one|two|three)",
            false,
        );
        assert!(error.contains("requested AOT variant was not emitted"));
        assert!(error.contains("build_variant_policy=optimizing-exists"));
        assert!(error.contains("available_variants=Optimizing+Exists"));
        assert!(error.contains("FRE_RIPGREP_AOT_VARIANTS=all"));

        let absent = missing_spec_error_from(
            &specs,
            "optimizing-exists",
            AotMode::Optimizing,
            AotOutput::Exists,
            "different-shape",
            false,
        );
        assert!(absent.contains("pattern/profile is not in the ripgrep AOT registry"));
        assert!(!absent.contains("requested AOT variant was not emitted"));
    }

    #[test]
    fn generated_registry_routes_compiled_prepared_entries() {
        let variants_per_pattern = match generated::BUILD_VARIANT_POLICY {
            "all" => 4,
            "optimizing-exists" => {
                assert!(!generated::SPECS.is_empty());
                assert!(generated::SPECS.iter().all(|spec| {
                    spec.mode == AotMode::Optimizing && spec.output == AotOutput::Exists
                }));
                1
            }
            other => panic!("unknown generated build variant policy: {other:?}"),
        };
        assert_eq!(
            generated::SPECS.len(),
            generated::BUILD_PATTERN_COUNT * variants_per_pattern,
            "generated registry cardinality does not match its frozen pattern/variant policy"
        );
        if generated::BUILD_VARIANT_POLICY == "optimizing-exists" {
            return;
        }
        let mut prepared = 0;
        let mut fast = 0;
        let mut fast_runtime_bulk = 0;
        let mut fast_native_prepared_loop = 0;
        let mut optimizing_prepared = 0;
        let mut optimizing_runtime_bulk = 0;
        let mut optimizing_native_prepared_loop = 0;
        for spec in generated::SPECS {
            if spec.mode == AotMode::Fast {
                fast += 1;
                assert!(
                    matches!(spec.backend, BackendFactory::Prepared { .. }),
                    "Fast artifact silently bypassed its compiled prepared entry: {}",
                    spec.pattern
                );
            }
            match spec.backend {
                BackendFactory::Prepared {
                    span_fill,
                    exists_batch,
                    ..
                } => {
                    prepared += 1;
                    optimizing_prepared += usize::from(spec.mode == AotMode::Optimizing);
                    assert!(
                        spec.description.contains("route=compiled-prepared,api="),
                        "prepared route family changed: {}",
                        spec.description
                    );
                    let runtime_bulk = spec.description.contains("bulk=runtime-helper");
                    let native_bulk_strategies = [
                        "bulk=native-prepared-loop",
                        "bulk=native-trusted-preflight-loop",
                        "bulk=native-trusted-preflight-runtime-bulk",
                        "bulk=native-frozen-loop",
                        "bulk=native-ordered-nfa-loop",
                    ]
                    .into_iter()
                    .filter(|bulk| spec.description.contains(bulk))
                    .count();
                    let native_bulk = native_bulk_strategies == 1;
                    assert_ne!(
                        runtime_bulk, native_bulk,
                        "prepared bulk strategy is missing or ambiguous: {}",
                        spec.description
                    );
                    match spec.mode {
                        AotMode::Fast => {
                            if runtime_bulk {
                                fast_runtime_bulk += 1;
                            } else {
                                fast_native_prepared_loop += 1;
                            }
                        }
                        AotMode::Optimizing if runtime_bulk => optimizing_runtime_bulk += 1,
                        AotMode::Optimizing => optimizing_native_prepared_loop += 1,
                    }
                    match spec.output {
                        AotOutput::Exists => {
                            assert!(span_fill.is_none());
                            assert!(exists_batch.is_some());
                            assert!(spec.description.contains("api=exists-batch-v1"));
                        }
                        AotOutput::Span => {
                            assert!(exists_batch.is_none());
                            assert!(matches!(
                                span_fill,
                                Some(PreparedSpanFillFactory::Compiled(_))
                            ));
                            assert!(spec.description.contains("api=span-fill-v1"));
                        }
                    }
                }
                BackendFactory::Native {
                    fill, exists_batch, ..
                } => {
                    assert!(spec.description.contains("route=direct-native"));
                    match spec.output {
                        AotOutput::Exists => {
                            assert!(fill.is_none());
                            assert!(exists_batch.is_some());
                            assert!(spec.description.contains("api=direct-exists-batch-v1"));
                            assert!(
                                spec.description
                                    .contains("bulk=native-direct-trusted-full-window-loop")
                            );
                        }
                        AotOutput::Span => {
                            assert!(exists_batch.is_none());
                            assert!(spec.description.contains("bulk=none"));
                        }
                    }
                }
                BackendFactory::Runtime(_) => {
                    assert!(spec.description.contains("route=portable-runtime"));
                    assert!(spec.description.contains("bulk=none"));
                }
            }
        }
        assert!(fast > 0, "test registry must contain a Fast entry");
        assert_eq!(
            fast,
            fast_runtime_bulk + fast_native_prepared_loop,
            "Fast prepared bulk strategy census did not cover every entry"
        );
        assert!(prepared > 0, "test registry must contain a prepared entry");
        assert_eq!(
            optimizing_prepared,
            optimizing_runtime_bulk + optimizing_native_prepared_loop,
            "Optimizing prepared bulk strategy census did not cover every prepared entry"
        );
        let has_mixed_strategy_fixture = [
            "PM_RESUME",
            r"\b(?:PM_RESUME)\b",
            r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}",
        ]
        .into_iter()
        .all(|pattern| generated::SPECS.iter().any(|spec| spec.pattern == pattern));
        if has_mixed_strategy_fixture {
            assert!(fast_runtime_bulk > 0);
            assert!(fast_native_prepared_loop > 0);
            assert!(optimizing_runtime_bulk > 0);
            assert!(optimizing_native_prepared_loop > 0);
        }
        if generated::SPECS
            .iter()
            .any(|spec| spec.mode == AotMode::Optimizing && spec.pattern == r"\b(?:PM_RESUME)\b")
        {
            assert!(
                optimizing_runtime_bulk > 0,
                "Optimizing fallback silently bypassed its runtime-owned bulk entry"
            );
        }
    }

    #[test]
    fn generated_pruned_registry_rejects_absent_variant_clearly() {
        if generated::BUILD_VARIANT_POLICY != "optimizing-exists" {
            return;
        }
        let selected = generated::SPECS
            .first()
            .expect("nonempty generated registry");
        let error = AotMatcher::new(
            AotMode::Fast,
            AotOutput::Span,
            selected.pattern,
            selected.case_insensitive,
        )
        .expect_err("pruned Fast+Span variant must be absent");
        assert!(error.contains("requested AOT variant was not emitted"));
        assert!(error.contains("build_variant_policy=optimizing-exists"));
        assert!(error.contains("available_variants=Optimizing+Exists"));
    }

    #[test]
    fn compiled_prepared_bulk_invalid_handle_precedes_other_validation() {
        let mut compiled_calls = 0;
        let mut saw_runtime_span = false;
        let mut saw_runtime_exists = false;
        let mut saw_native_span = false;
        let mut saw_native_exists = false;
        for spec in generated::SPECS {
            let BackendFactory::Prepared {
                span_fill,
                exists_batch,
                ..
            } = spec.backend
            else {
                continue;
            };
            let runtime_bulk = spec.description.contains("bulk=runtime-helper");
            let native_bulk = [
                "bulk=native-prepared-loop",
                "bulk=native-trusted-preflight-loop",
                "bulk=native-trusted-preflight-runtime-bulk",
                "bulk=native-frozen-loop",
                "bulk=native-ordered-nfa-loop",
            ]
            .into_iter()
            .filter(|bulk| spec.description.contains(bulk))
            .count()
                == 1;
            assert_ne!(runtime_bulk, native_bulk, "{}", spec.description);
            let status = match (spec.output, span_fill, exists_batch) {
                (AotOutput::Span, Some(PreparedSpanFillFactory::Compiled(fill)), None) => {
                    compiled_calls += 1;
                    if runtime_bulk {
                        saw_runtime_span = true;
                    } else {
                        saw_native_span = true;
                    }
                    // SAFETY: the compiled ABI promises to reject an invalid
                    // exclusive handle before inspecting any remaining raw
                    // argument. Deliberately invalid arguments make that
                    // precedence observable in the host-linked object.
                    unsafe {
                        fill(
                            FreAotRegexExclusiveHandleV1::INVALID,
                            std::ptr::null(),
                            usize::MAX,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            usize::MAX,
                            std::ptr::null_mut(),
                        )
                    }
                }
                (AotOutput::Exists, None, Some(batch)) => {
                    compiled_calls += 1;
                    if runtime_bulk {
                        saw_runtime_exists = true;
                    } else {
                        saw_native_exists = true;
                    }
                    // SAFETY: as above, no pointer or extent after the invalid
                    // handle may be inspected by the compiler-produced entry.
                    unsafe {
                        batch(
                            FreAotRegexExclusiveHandleV1::INVALID,
                            std::ptr::null(),
                            usize::MAX,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        )
                    }
                }
                _ => continue,
            };
            assert_eq!(
                status,
                fre_aot_regex_runtime::STATUS_INVALID_HANDLE,
                "invalid-handle precedence changed for {}",
                spec.description
            );
        }
        assert!(
            compiled_calls > 0,
            "test registry has no compiled bulk entry"
        );

        let has_mixed_strategy_fixture = [
            "PM_RESUME",
            r"\b(?:PM_RESUME)\b",
            r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}",
        ]
        .into_iter()
        .all(|pattern| generated::SPECS.iter().any(|spec| spec.pattern == pattern));
        if has_mixed_strategy_fixture {
            assert!(saw_runtime_span || saw_native_span);
            assert!(saw_runtime_exists || saw_native_exists);
            assert!(saw_runtime_span || saw_runtime_exists);
            assert!(saw_native_span || saw_native_exists);
        }
    }

    #[test]
    fn compiled_prepared_fast_finds_dense_matches_across_refills() {
        let pattern = "PM_RESUME";
        if !generated::SPECS.iter().any(|spec| {
            spec.mode == AotMode::Fast
                && spec.output == AotOutput::Span
                && spec.pattern == pattern
                && !spec.case_insensitive
        }) {
            return;
        }

        let mut matcher = AotMatcher::new(AotMode::Fast, AotOutput::Span, pattern, false)
            .expect("prepare Fast Span entry");
        assert!(matcher.description().contains("route=compiled-prepared"));
        assert!(matcher.description().contains("api=span-fill-v1"));
        assert!(
            matcher.description().contains("bulk=runtime-helper")
                || matcher.description().contains("bulk=native-prepared-loop")
                || matcher.description().contains("bulk=native-frozen-loop")
        );
        let haystack = pattern
            .as_bytes()
            .repeat(NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2);
        let spans = matcher
            .find_iter(&haystack)
            .expect("compiled-prepared iterator")
            .map(|matched| matched.expect("compiled-prepared match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2);
        assert_eq!(spans.first(), Some(&(0..pattern.len())));
        assert_eq!(
            spans.last(),
            Some(&((haystack.len() - pattern.len())..haystack.len()))
        );

        let empty = matcher
            .find_iter(b"")
            .expect("compiled-prepared empty iterator")
            .collect::<Result<Vec<_>, _>>()
            .expect("compiled-prepared empty search");
        assert!(empty.is_empty());

        let mut exists = AotMatcher::new(AotMode::Fast, AotOutput::Exists, pattern, false)
            .expect("prepare frozen-loop Exists entry");
        assert!(exists.description().contains("bulk=native-frozen-loop"));
        let valid = pattern.as_bytes();
        let invalid = b"PM_PAUSE".as_slice();
        let empty = b"".as_slice();
        let lines = (0..EXISTS_BATCH_CAPACITY)
            .map(|index| match index % 3 {
                0 => valid,
                1 => invalid,
                _ => empty,
            })
            .collect::<Vec<_>>();
        let mut outcomes = [false; EXISTS_BATCH_CAPACITY];
        exists
            .is_match_batch(&lines, &mut outcomes)
            .expect("frozen-loop Exists batch");
        for (index, matched) in outcomes.into_iter().enumerate() {
            assert_eq!(matched, index % 3 == 0);
        }
    }

    #[test]
    fn compiled_prepared_fast_trusted_hybrid_matches_short_and_large_inputs() {
        let pattern = r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}";
        if !generated::SPECS.iter().any(|spec| {
            spec.mode == AotMode::Fast
                && spec.output == AotOutput::Span
                && spec.pattern == pattern
                && !spec.case_insensitive
        }) {
            return;
        }

        let unit = b"aaaaa bbbbb ccccc ddddd eeeee";
        let mut span = AotMatcher::new(AotMode::Fast, AotOutput::Span, pattern, false)
            .expect("prepare trusted-hybrid Span entry");
        assert!(
            span.description()
                .contains("bulk=native-trusted-preflight-runtime-bulk")
        );
        for repeats in [2, 160] {
            let haystack = unit.repeat(repeats);
            let spans = span
                .find_iter(&haystack)
                .expect("trusted-hybrid iterator")
                .map(|matched| matched.expect("trusted-hybrid match").range())
                .collect::<Vec<_>>();
            assert_eq!(spans.len(), repeats);
            for (index, range) in spans.into_iter().enumerate() {
                let start = index * unit.len();
                assert_eq!(range, start..start + unit.len());
            }
        }
        assert!(
            span.find_iter(b"")
                .expect("trusted-hybrid empty iterator")
                .collect::<Result<Vec<_>, _>>()
                .expect("trusted-hybrid empty search")
                .is_empty()
        );
        let mut exists = AotMatcher::new(AotMode::Fast, AotOutput::Exists, pattern, false)
            .expect("prepare trusted-preflight Exists entry");
        assert!(
            exists
                .description()
                .contains("bulk=native-trusted-preflight-loop")
        );
        let long_unit = b"aaaaa    bbbbb    ccccc    ddddd    eeeee";
        let invalid = b"aaaaa bbbbb";
        let empty = b"";
        for (line, expected) in [
            (long_unit.as_slice(), true),
            (invalid.as_slice(), false),
            (empty.as_slice(), false),
        ] {
            let mut one = [false; 1];
            exists
                .is_match_batch(&[line], &mut one)
                .expect("trusted-preflight Exists single");
            assert_eq!(one, [expected]);
        }
        let lines = (0..EXISTS_BATCH_CAPACITY)
            .map(|index| match index % 3 {
                0 => long_unit.as_slice(),
                1 => invalid.as_slice(),
                _ => empty.as_slice(),
            })
            .collect::<Vec<_>>();
        let mut outcomes = [false; EXISTS_BATCH_CAPACITY];
        exists
            .is_match_batch(&lines, &mut outcomes)
            .expect("trusted-preflight Exists batch");
        for (index, matched) in outcomes.into_iter().enumerate() {
            assert_eq!(matched, index % 3 == 0);
        }

        for length in [0_usize, 31, 32, 33] {
            let matching = if length == 0 {
                Vec::new()
            } else {
                format!("aaaaa{}bbbbb ccccc ddddd eeeee", " ".repeat(length - 28)).into_bytes()
            };
            assert_eq!(matching.len(), length);
            let mut nonmatching = matching.clone();
            if let Some(first) = nonmatching.first_mut() {
                *first = b'!';
            }
            for (haystack, expected) in [(&matching, length != 0), (&nonmatching, false)] {
                let mut span = AotMatcher::new(AotMode::Fast, AotOutput::Span, pattern, false)
                    .expect("prepare boundary Span entry");
                let spans = span
                    .find_iter(haystack)
                    .expect("boundary Span iterator")
                    .map(|matched| matched.expect("boundary Span match").range())
                    .collect::<Vec<_>>();
                let expected_spans = expected
                    .then_some(0..length)
                    .into_iter()
                    .collect::<Vec<_>>();
                assert_eq!(spans, expected_spans);

                let mut exists = AotMatcher::new(AotMode::Fast, AotOutput::Exists, pattern, false)
                    .expect("prepare boundary Exists entry");
                let mut outcome = [false; 1];
                exists
                    .is_match_batch(&[haystack], &mut outcome)
                    .expect("boundary Exists batch");
                assert_eq!(outcome, [expected]);
            }
        }
    }

    #[test]
    fn compiled_prepared_optimizing_fallback_finds_nonempty_match() {
        let pattern = r"\b(?:PM_RESUME)\b";
        if !generated::SPECS.iter().any(|spec| {
            spec.mode == AotMode::Optimizing
                && spec.output == AotOutput::Span
                && spec.pattern == pattern
                && !spec.case_insensitive
        }) {
            return;
        }

        let mut exists = AotMatcher::new(AotMode::Optimizing, AotOutput::Exists, pattern, false)
            .expect("prepare Optimizing Exists fallback");
        assert!(exists.description().contains("route=compiled-prepared"));
        assert!(exists.description().contains("api=exists-batch-v1"));
        assert!(exists.description().contains("bulk=runtime-helper"));
        assert!(exists.is_match(b"PM_RESUME").expect("Exists search"));

        let mut span = AotMatcher::new(AotMode::Optimizing, AotOutput::Span, pattern, false)
            .expect("prepare Optimizing Span fallback");
        assert!(span.description().contains("route=compiled-prepared"));
        assert!(span.description().contains("api=span-fill-v1"));
        assert!(
            span.description().contains("bulk=runtime-helper")
                || span.description().contains("bulk=native-ordered-nfa-loop")
        );
        assert_eq!(
            span.find(b"PM_RESUME")
                .expect("Span search")
                .expect("word match")
                .range(),
            0..9
        );
    }
}
