//! Raw versioned exports and the complete opaque-pointer ownership boundary.

#![allow(
    clippy::missing_safety_doc,
    reason = "all exports share the detailed C pointer/lifetime preconditions in fre.h"
)]

use core::{mem, ptr, slice};
use std::sync::Arc;

use crate::{
    FRE_V1_ABI_VERSION, FRE_V1_DIAGNOSTIC_ARGUMENT, FRE_V1_STATUS_ABI_MISMATCH,
    FRE_V1_STATUS_INVALID_ARGUMENT, FRE_V1_STATUS_LENGTH_OVERFLOW,
    FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH, FRE_V1_STATUS_OK, FRE_V1_STATUS_STRUCT_TOO_SMALL,
    FreV1AbiDescriptor, FreV1Config, FreV1Diagnostic, FreV1ExistsResult, FreV1Header,
    FreV1MatchResult, FreV1PlanInfo, FreV1Regex, FreV1SelectedEndResult,
    boundary::{Diagnostic, Outcome, invoke, invoke_status},
    engine::CompiledRegex,
};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fre_v1_get_abi_descriptor(out: *mut FreV1AbiDescriptor) -> u32 {
    invoke_status(|| {
        let sink = match unsafe { RecordSink::new(out) } {
            Ok(sink) => sink,
            Err(status) => return status,
        };
        // SAFETY: the validated caller-owned record is writable and aligned.
        unsafe { sink.write(FreV1AbiDescriptor::current()) };
        FRE_V1_STATUS_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fre_v1_config_default(out: *mut FreV1Config) -> u32 {
    invoke_status(|| {
        let sink = match unsafe { RecordSink::new(out) } {
            Ok(sink) => sink,
            Err(status) => return status,
        };
        // SAFETY: the validated caller-owned record is writable and aligned.
        unsafe { sink.write(FreV1Config::checked_default()) };
        FRE_V1_STATUS_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fre_v1_regex_compile(
    config: *const FreV1Config,
    pattern: *const u8,
    pattern_length: usize,
    out_regex: *mut *mut FreV1Regex,
    diagnostic: *mut FreV1Diagnostic,
) -> u32 {
    unsafe {
        with_diagnostic(diagnostic, || {
            let config = match read_record(config) {
                Ok(config) => config,
                Err(outcome) => return outcome,
            };
            let pattern = match byte_view(pattern, pattern_length) {
                Ok(pattern) => pattern,
                Err(outcome) => return outcome,
            };
            let output = match PointerSink::new(out_regex) {
                Ok(output) => output,
                Err(outcome) => return outcome,
            };
            let compiled = match CompiledRegex::compile(config, pattern) {
                Ok(compiled) => compiled,
                Err(outcome) => return outcome,
            };
            let raw = Arc::into_raw(Arc::new(compiled))
                .cast_mut()
                .cast::<FreV1Regex>();
            // SAFETY: the pointer slot was validated before compilation and is
            // required by the C contract to remain writable/non-aliased.
            output.write(raw);
            Outcome::ok()
        })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fre_v1_regex_retain(regex: *const FreV1Regex) -> u32 {
    invoke_status(|| {
        let raw = match handle_pointer(regex) {
            Ok(raw) => raw,
            Err(outcome) => return outcome.status,
        };
        // SAFETY: the C validity contract requires one live strong reference
        // throughout retain. `raw` came from `Arc::into_raw` for this type.
        unsafe { Arc::increment_strong_count(raw) };
        FRE_V1_STATUS_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fre_v1_regex_release(regex: *const FreV1Regex) -> u32 {
    invoke_status(|| {
        let raw = match handle_pointer(regex) {
            Ok(raw) => raw,
            Err(outcome) => return outcome.status,
        };
        // SAFETY: the caller transfers exactly one still-live retained
        // reference. Double release/use-after-release violate the C contract.
        unsafe { Arc::decrement_strong_count(raw) };
        FRE_V1_STATUS_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fre_v1_regex_plan(
    regex: *const FreV1Regex,
    out: *mut FreV1PlanInfo,
    diagnostic: *mut FreV1Diagnostic,
) -> u32 {
    unsafe {
        with_diagnostic(diagnostic, || {
            let regex = match handle_ref(regex) {
                Ok(regex) => regex,
                Err(outcome) => return outcome,
            };
            let sink = match RecordSink::new(out) {
                Ok(sink) => sink,
                Err(status) => return record_failure(status),
            };
            sink.write(regex.plan_info());
            Outcome::ok()
        })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fre_v1_regex_exists(
    regex: *const FreV1Regex,
    haystack: *const u8,
    haystack_length: usize,
    out: *mut FreV1ExistsResult,
    diagnostic: *mut FreV1Diagnostic,
) -> u32 {
    unsafe {
        search(
            regex,
            haystack,
            haystack_length,
            out,
            diagnostic,
            CompiledRegex::exists,
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fre_v1_regex_selected_end(
    regex: *const FreV1Regex,
    haystack: *const u8,
    haystack_length: usize,
    out: *mut FreV1SelectedEndResult,
    diagnostic: *mut FreV1Diagnostic,
) -> u32 {
    unsafe {
        search(
            regex,
            haystack,
            haystack_length,
            out,
            diagnostic,
            CompiledRegex::selected_end,
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fre_v1_regex_span(
    regex: *const FreV1Regex,
    haystack: *const u8,
    haystack_length: usize,
    out: *mut FreV1MatchResult,
    diagnostic: *mut FreV1Diagnostic,
) -> u32 {
    unsafe {
        search(
            regex,
            haystack,
            haystack_length,
            out,
            diagnostic,
            CompiledRegex::span,
        )
    }
}

unsafe fn search<T: Copy>(
    regex: *const FreV1Regex,
    haystack: *const u8,
    haystack_length: usize,
    out: *mut T,
    diagnostic: *mut FreV1Diagnostic,
    operation: impl FnOnce(&CompiledRegex, &[u8]) -> Result<T, Outcome>,
) -> u32 {
    unsafe {
        with_diagnostic(diagnostic, || {
            let regex = match handle_ref(regex) {
                Ok(regex) => regex,
                Err(outcome) => return outcome,
            };
            let haystack = match byte_view(haystack, haystack_length) {
                Ok(haystack) => haystack,
                Err(outcome) => return outcome,
            };
            let sink = match RecordSink::new(out) {
                Ok(sink) => sink,
                Err(status) => return record_failure(status),
            };
            let result = match operation(regex, haystack) {
                Ok(result) => result,
                Err(outcome) => return outcome,
            };
            sink.write(result);
            Outcome::ok()
        })
    }
}

unsafe fn with_diagnostic(
    diagnostic: *mut FreV1Diagnostic,
    operation: impl FnOnce() -> Outcome,
) -> u32 {
    let sink = match unsafe { DiagnosticSink::new(diagnostic) } {
        Ok(sink) => sink,
        Err(status) => return status,
    };
    let outcome = invoke(operation);
    // SAFETY: optional sink validation happened before the contained operation
    // and the C contract requires its storage to remain live and non-aliased.
    unsafe { sink.write(&outcome.diagnostic) };
    outcome.status
}

unsafe fn read_record<T: Copy>(pointer: *const T) -> Result<T, Outcome> {
    validate_pointer(pointer).map_err(record_failure)?;
    let header = unsafe { ptr::read(pointer.cast::<FreV1Header>()) };
    validate_header::<T>(header).map_err(record_failure)?;
    // SAFETY: header validation establishes the caller advertised at least the
    // known v1 prefix; pointer validity/alignment is a documented precondition.
    Ok(unsafe { ptr::read(pointer) })
}

unsafe fn byte_view<'a>(pointer: *const u8, length: usize) -> Result<&'a [u8], Outcome> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(Outcome::failure(
            FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH,
            FRE_V1_DIAGNOSTIC_ARGUMENT,
            "null byte pointer with nonzero length",
        ));
    }
    if length > isize::MAX.unsigned_abs() {
        return Err(Outcome::failure(
            FRE_V1_STATUS_LENGTH_OVERFLOW,
            FRE_V1_DIAGNOSTIC_ARGUMENT,
            "byte view exceeds Rust's maximum object size",
        ));
    }
    // SAFETY: the C contract requires this complete range to be readable and
    // stable for the call. u8 has alignment one and the checked size fits.
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

unsafe fn handle_ref<'a>(pointer: *const FreV1Regex) -> Result<&'a CompiledRegex, Outcome> {
    let pointer = handle_pointer(pointer)?;
    // SAFETY: one live Arc strong reference is a C precondition for every use,
    // and its immutable allocation cannot move while that reference exists.
    Ok(unsafe { &*pointer })
}

fn handle_pointer(pointer: *const FreV1Regex) -> Result<*const CompiledRegex, Outcome> {
    if pointer.is_null() {
        return Err(argument_failure("regex handle is null or misaligned"));
    }
    let compiled = pointer.cast::<CompiledRegex>();
    if !compiled.is_aligned() {
        return Err(argument_failure("regex handle is null or misaligned"));
    }
    Ok(compiled)
}

struct DiagnosticSink(Option<*mut FreV1Diagnostic>);

impl DiagnosticSink {
    unsafe fn new(pointer: *mut FreV1Diagnostic) -> Result<Self, u32> {
        if pointer.is_null() {
            return Ok(Self(None));
        }
        let sink = unsafe { RecordSink::new(pointer)? };
        Ok(Self(Some(sink.0)))
    }

    unsafe fn write(self, diagnostic: &Diagnostic) {
        if let Some(pointer) = self.0 {
            // SAFETY: `new` validated the complete known record.
            unsafe { ptr::write(pointer, diagnostic.record()) };
        }
    }
}

struct RecordSink<T>(*mut T);

impl<T> RecordSink<T> {
    unsafe fn new(pointer: *mut T) -> Result<Self, u32> {
        validate_pointer(pointer)?;
        // SAFETY: pointer validity for the readable common header is a caller
        // precondition; alignment/null were checked above.
        let header = unsafe { ptr::read(pointer.cast::<FreV1Header>()) };
        validate_header::<T>(header)?;
        Ok(Self(pointer))
    }

    unsafe fn write(self, value: T) {
        // SAFETY: `new` validated the caller-advertised writable record size.
        unsafe { ptr::write(self.0, value) };
    }
}

struct PointerSink<T>(*mut T);

impl<T> PointerSink<T> {
    unsafe fn new(pointer: *mut T) -> Result<Self, Outcome> {
        validate_pointer(pointer).map_err(record_failure)?;
        Ok(Self(pointer))
    }

    unsafe fn write(self, value: T) {
        // SAFETY: caller promises one live, writable, non-aliased value slot.
        unsafe { ptr::write(self.0, value) };
    }
}

fn validate_pointer<T>(pointer: *const T) -> Result<(), u32> {
    if pointer.is_null() || !pointer.is_aligned() {
        return Err(FRE_V1_STATUS_INVALID_ARGUMENT);
    }
    Ok(())
}

fn validate_header<T>(header: FreV1Header) -> Result<(), u32> {
    if header.abi_version != FRE_V1_ABI_VERSION {
        return Err(FRE_V1_STATUS_ABI_MISMATCH);
    }
    let required = u32::try_from(mem::size_of::<T>()).expect("ABI record fits u32");
    if header.struct_size < required {
        return Err(FRE_V1_STATUS_STRUCT_TOO_SMALL);
    }
    Ok(())
}

fn record_failure(status: u32) -> Outcome {
    let message = match status {
        FRE_V1_STATUS_ABI_MISMATCH => "record ABI version does not match FRE v1",
        FRE_V1_STATUS_STRUCT_TOO_SMALL => "record is smaller than the mandatory v1 prefix",
        _ => "required pointer is null or misaligned",
    };
    Outcome::failure(status, FRE_V1_DIAGNOSTIC_ARGUMENT, message)
}

fn argument_failure(message: &'static str) -> Outcome {
    Outcome::failure(
        FRE_V1_STATUS_INVALID_ARGUMENT,
        FRE_V1_DIAGNOSTIC_ARGUMENT,
        message,
    )
}
