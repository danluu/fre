//! Safe dispatch over the precompiled ripgrep-suite general-AOT registry.

#![warn(unsafe_code)]

use fre_aot_regex::{MatchResult, SearchWindow};
use fre_aot_regex_runtime::PreparedAotRegex;

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

#[derive(Clone, Copy, Debug)]
enum BackendFactory {
    Native(NativeSearch),
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
    Native(NativeSearch),
    Runtime(Box<PreparedAotRegex>),
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
            BackendFactory::Native(search) => Backend::Native(search),
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

    /// Find the first selected span at or after `start` in the original haystack.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid start, output-contract mismatch, or
    /// execution failure.
    pub fn find_at(
        &mut self,
        haystack: &[u8],
        start: usize,
    ) -> Result<Option<(usize, usize)>, String> {
        if self.output != AotOutput::Span {
            return Err("AOT matcher was not compiled for Span".to_owned());
        }
        match self.search(haystack, start)? {
            MatchResult::Span(span) => Ok(span),
            _ => Err("AOT Span artifact returned a different result contract".to_owned()),
        }
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
            Backend::Native(search) => native_search(*search, self.output, haystack, start),
        }
    }
}

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
    let mut result = AbiResult::default();
    // SAFETY: compiler-produced entries use this exact C ABI. The slice gives
    // a non-null readable extent, the checked window is contained in it, and
    // `result` is aligned, writable, and disjoint for the duration of the call.
    let status = unsafe {
        search(
            haystack.as_ptr(),
            haystack.len(),
            start,
            haystack.len(),
            &raw mut result,
        )
    };
    match (output, status) {
        (AotOutput::Exists, 0) => Ok(MatchResult::Exists(false)),
        (AotOutput::Exists, 1) => Ok(MatchResult::Exists(true)),
        (AotOutput::Span, 0) => Ok(MatchResult::Span(None)),
        (AotOutput::Span, 1) => {
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
