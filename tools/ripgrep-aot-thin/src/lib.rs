//! Safe dispatch over the precompiled ripgrep-suite general-AOT registry.

#![warn(unsafe_code)]

use std::mem::MaybeUninit;

use fre_aot_regex::{MatchResult, SearchWindow};
pub use fre_aot_regex_runtime::AotMatch;
use fre_aot_regex_runtime::{PreparedAotMatches, PreparedAotRegex};

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

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct AbiResult {
    start: usize,
    end: usize,
}

type NativeSearch = unsafe extern "C" fn(*const u8, usize, usize, usize, *mut AbiResult) -> u32;
type NativeFill =
    fn(&[u8], &mut NativeIterState, &mut [MaybeUninit<AbiResult>]) -> NativeFillOutcome;

const NATIVE_SPAN_BUFFER_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug)]
enum BackendFactory {
    Native {
        search: NativeSearch,
        fill: Option<NativeFill>,
    },
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

#[derive(Debug)]
enum Backend {
    Native {
        search: NativeSearch,
        fill: Option<NativeFill>,
    },
    Runtime(Box<PreparedAotRegex>),
}

#[derive(Clone, Copy, Debug, Default)]
struct NativeIterState {
    start: usize,
    last_match_end: Option<usize>,
    pending_empty_progress: bool,
    finished: bool,
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
    while written < output.len() && !state.finished {
        if state.pending_empty_progress {
            state.pending_empty_progress = false;
            if state.start == haystack.len() {
                state.finished = true;
                break;
            }
            state.start += 1;
        }

        let search_start = state.start;
        let status = search(haystack, search_start, output[written].as_mut_ptr());
        match status {
            0 => {
                state.finished = true;
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
                    state.finished = true;
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

                if result.start == result.end && state.last_match_end == Some(result.end) {
                    if state.start == haystack.len() {
                        state.finished = true;
                        break;
                    }
                    state.start += 1;
                    continue;
                }

                state.start = result.end;
                state.last_match_end = Some(result.end);
                state.pending_empty_progress = result.start == result.end;
                written += 1;
            }
            _ => {
                state.finished = true;
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
            .ok_or_else(|| {
                format!(
                    "pattern/profile is not in the ripgrep AOT registry: mode={mode:?} output={output:?} case_insensitive={case_insensitive} pattern={pattern:?}"
                )
            })?;
        let backend = match spec.backend {
            BackendFactory::Native { search, fill } => Backend::Native { search, fill },
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
    /// Runtime-backed artifacts retain their prepared workspace for the full
    /// iterator lifetime. Direct-native artifacts refill 64 spans at a time,
    /// amortizing the indirect dispatch with bounded read-ahead.
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
            Backend::Native {
                fill: Some(fill), ..
            } => AotMatchesBackend::Native(NativeMatches::new(*fill, haystack)),
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
            Backend::Native { search, .. } => native_search(*search, self.output, haystack, start),
        }
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
    Native(NativeMatches<'h>),
    Runtime(PreparedAotMatches<'m, 'h>),
}

#[derive(Debug)]
struct NativeMatches<'h> {
    fill: NativeFill,
    haystack: &'h [u8],
    state: NativeIterState,
    spans: [MaybeUninit<AbiResult>; NATIVE_SPAN_BUFFER_CAPACITY],
    next: usize,
    filled: usize,
    pending_error: Option<String>,
}

impl<'h> NativeMatches<'h> {
    fn new(fill: NativeFill, haystack: &'h [u8]) -> Self {
        Self {
            fill,
            haystack,
            state: NativeIterState::default(),
            spans: [const { MaybeUninit::uninit() }; NATIVE_SPAN_BUFFER_CAPACITY],
            next: 0,
            filled: 0,
            pending_error: None,
        }
    }

    fn fail(&mut self, error: String) -> Result<AotMatch<'h>, String> {
        self.state.finished = true;
        self.next = self.filled;
        self.pending_error = None;
        Err(error)
    }
}

#[allow(
    unsafe_code,
    reason = "the iterator reads only the initialized prefix returned by its trusted native fill shim"
)]
impl<'h> Iterator for NativeMatches<'h> {
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
            if self.state.finished {
                return None;
            }

            self.next = 0;
            let outcome = (self.fill)(self.haystack, &mut self.state, &mut self.spans);
            self.filled = outcome.written;
            self.pending_error = outcome.error;
            if self.filled == 0 && self.pending_error.is_none() && !self.state.finished {
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

impl std::iter::FusedIterator for NativeMatches<'_> {}
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
    match (output, status) {
        (AotOutput::Exists, 0) => Ok(MatchResult::Exists(false)),
        (AotOutput::Exists, 1) => Ok(MatchResult::Exists(true)),
        (AotOutput::Span, 0) => Ok(MatchResult::Span(None)),
        (AotOutput::Span, 1) => {
            // Compiler-produced Span entries initialize the result on status
            // 1. Other statuses never read it.
            let result = unsafe { result.assume_init() };
            if start <= result.start && result.start <= result.end && result.end <= haystack.len() {
                Ok(MatchResult::Span(Some((result.start, result.end))))
            } else {
                Err(format!(
                    "native AOT entry returned an invalid result: status={status} start={} end={} window={start}..{}",
                    result.start,
                    result.end,
                    haystack.len()
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

    static SEARCH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FILL_CALLS: AtomicUsize = AtomicUsize::new(0);

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
}
