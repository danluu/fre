//! Statically linked, job-specialized adapter for public Rebar operation models.

#![warn(unsafe_code)]

use std::{
    env,
    error::Error,
    fmt::Write as _,
    hint::black_box,
    io::{self, Read, Write},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use bstr::ByteSlice;
use fre_aot_rebar_runner::shared;
use fre_aot_regex::{
    CompiledRegex, DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES,
    FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES, FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
    NativeRegexReduxRequestV1, NativeRegexReduxRunReceiptV1,
};
#[cfg(test)]
use fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT;
use fre_aot_regex_runtime::{
    DEFAULT_GREP_COUNT_WORKSPACE_BYTES, DEFAULT_START_FILTER_SETUP_WORK, FreAotRegexCaptureSlotV1,
    FreAotRegexExclusiveHandleV1, FreAotRegexIterStateV1, FreAotRegexParticipationRequestV1,
    FreAotRegexPrepareConfigV2, FreAotRegexPrepareConfigV3, FreAotRegexResultV1, ITER_FINISHED,
    ITER_HAS_LAST, ITER_KNOWN_FLAGS, ITER_PENDING_EMPTY, PREPARE_CAPABILITY_KNOWN_FLAGS,
    PREPARE_CAPABILITY_ORDERED_NFA_V15, PREPARE_CONFIG_V2_VERSION, PREPARE_CONFIG_V3_VERSION,
    STATUS_MATCH, STATUS_NO_MATCH, STATUS_SUCCESS, fre_aot_regex_runtime_destroy_exclusive_v1,
    fre_aot_regex_runtime_prepare_exclusive_v2, fre_aot_regex_runtime_prepare_exclusive_v3,
};
use regex_automata::{Input, meta::Regex};

#[allow(
    unsafe_code,
    unreachable_pub,
    reason = "generated declarations are the exact statically linked AOT C ABI boundary"
)]
mod linked {
    include!(concat!(env!("OUT_DIR"), "/linked_artifact.rs"));
}

type DynError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Arguments {
    quiet: bool,
    version: bool,
    provenance: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Sample {
    duration: Duration,
    value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrepareV3Caps {
    max_handle_bytes: u64,
    max_scratch_bytes: u64,
    max_setup_work: u64,
}

impl PrepareV3Caps {
    const ZERO: Self = Self {
        max_handle_bytes: 0,
        max_scratch_bytes: 0,
        max_setup_work: 0,
    };

    fn defaults() -> Self {
        Self {
            max_handle_bytes: u64::try_from(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES)
                .expect("default Ordered-NFA handle cap fits u64"),
            max_scratch_bytes: u64::try_from(FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES)
                .expect("default Ordered-NFA scratch cap fits u64"),
            max_setup_work: FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
        }
    }

    fn for_required_capabilities(required_capabilities: u64) -> Self {
        if required_capabilities == 0 {
            Self::ZERO
        } else {
            Self::defaults()
        }
    }

    const fn linked_rows() -> Self {
        Self {
            max_handle_bytes: linked::ROW_PREPARE_MAX_HANDLE_BYTES,
            max_scratch_bytes: linked::ROW_PREPARE_MAX_SCRATCH_BYTES,
            max_setup_work: linked::ROW_PREPARE_MAX_SETUP_WORK,
        }
    }

    fn authenticate(self, config: &FreAotRegexPrepareConfigV3) -> Result<(), String> {
        if config.max_handle_bytes != self.max_handle_bytes
            || config.max_ordered_nfa_scratch_bytes != self.max_scratch_bytes
            || config.max_ordered_nfa_setup_work != self.max_setup_work
        {
            return Err("prepared V3 runtime caps disagree with provenance".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegexReduxStageReceipt {
    input_length: u64,
    clean_length: u64,
    variant_counts: [u64; 9],
    substitution_lengths: [u64; 5],
    final_length: u64,
    report_length: u64,
    report: String,
    final_bytes: Vec<u8>,
}

#[derive(Debug)]
struct RegexReduxRun {
    samples: Vec<Sample>,
    receipt: RegexReduxStageReceipt,
}

#[derive(Debug)]
struct ExclusiveSession {
    handle: FreAotRegexExclusiveHandleV1,
}

impl ExclusiveSession {
    #[allow(
        unsafe_code,
        reason = "preparation is the audited exclusive-handle C ABI boundary"
    )]
    fn prepare(model: shared::Model) -> Result<Self, String> {
        let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
        let operation_flags =
            if model.is_capture() && linked::UNIFORM_CAPTURE_BRIDGE && !linked::NATIVE_ROW_BRIDGE {
                shared::Model::Count.prepare_operation_flags()
            } else {
                model.prepare_operation_flags_for_required_capabilities(
                    linked::REQUIRED_PREPARE_CAPABILITIES,
                )
            };
        if operation_flags != linked::PREPARE_OPERATION_FLAGS {
            return Err("runtime model preparation differs from linked artifact".to_owned());
        }
        if linked::REQUIRED_PREPARE_CAPABILITIES & !PREPARE_CAPABILITY_KNOWN_FLAGS != 0 {
            return Err("linked artifact requires unknown prepare capabilities".to_owned());
        }
        // SAFETY: the linked immutable program has the exact generated extent;
        // each selected config is initialized and readable, while `handle` is
        // aligned, writable, and disjoint from both readable inputs.
        let status = if linked::REQUIRED_PREPARE_CAPABILITIES == 0 {
            if linked::PREPARE_CONFIG_VERSION != PREPARE_CONFIG_V2_VERSION {
                return Err("incumbent linked artifact does not select prepare V2".to_owned());
            }
            let config = FreAotRegexPrepareConfigV2::new(operation_flags);
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v2(
                    linked::program_ptr(),
                    linked::PROGRAM_LEN,
                    &config,
                    &raw mut handle,
                )
            }
        } else {
            if linked::PREPARE_CONFIG_VERSION != PREPARE_CONFIG_V3_VERSION {
                return Err(
                    "capability-bearing linked artifact does not select prepare V3".to_owned(),
                );
            }
            let mut config = FreAotRegexPrepareConfigV3::new(operation_flags);
            config.required_capabilities = linked::REQUIRED_PREPARE_CAPABILITIES;
            PrepareV3Caps::for_required_capabilities(linked::REQUIRED_PREPARE_CAPABILITIES)
                .authenticate(&config)?;
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v3(
                    linked::program_ptr(),
                    linked::PROGRAM_LEN,
                    &config,
                    &raw mut handle,
                )
            }
        };
        if status != STATUS_SUCCESS || handle.is_invalid() {
            return Err(format!(
                "prepare exclusive AOT handle returned status {status}"
            ));
        }
        Ok(Self { handle })
    }

    #[allow(
        unsafe_code,
        reason = "the exact generated reducer call is the audited timed C ABI boundary"
    )]
    fn reduce(&mut self, haystack: &[u8]) -> Result<u64, String> {
        let mut value = u64::MAX;
        // SAFETY: this object uniquely owns the live exclusive handle; the
        // haystack and aligned scalar output remain disjoint and live for the
        // complete call.
        let status = unsafe {
            linked::reduce(
                self.handle,
                haystack.as_ptr(),
                haystack.len(),
                &raw mut value,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(format!(
                "identity-suffixed reducer {:?} returned status {status}",
                linked::REDUCER_SYMBOL
            ));
        }
        Ok(value)
    }

    #[allow(
        unsafe_code,
        reason = "the generated Span-fill declaration is the exact statically linked AOT C ABI boundary"
    )]
    fn strict_span_sum_with_fill(&mut self, haystack: &[u8]) -> Result<u64, String> {
        self.strict_scalar_with_fill(haystack, SpanScalarReducer::SpanSum, false)
    }

    #[allow(
        unsafe_code,
        reason = "the generated Span-fill declaration is the exact statically linked AOT C ABI boundary"
    )]
    fn strict_scalar_with_fill(
        &mut self,
        haystack: &[u8],
        reducer: SpanScalarReducer,
        require_positive_width: bool,
    ) -> Result<u64, String> {
        const SPAN_BUFFER_CAPACITY: usize = 64;

        let mut state = FreAotRegexIterStateV1::default();
        let mut spans = [FreAotRegexResultV1::default(); SPAN_BUFFER_CAPACITY];
        let mut accumulator = StrictSpanAccumulator::for_reducer(haystack.len(), reducer);
        loop {
            let mut written = usize::MAX;
            // SAFETY: this session uniquely owns the live handle. The whole
            // haystack and the naturally aligned state/result/count outputs
            // are live, writable where required, and pairwise disjoint.
            let status = unsafe {
                linked::fill_spans(
                    self.handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut state,
                    spans.as_mut_ptr(),
                    spans.len(),
                    &raw mut written,
                )
            };
            if written > spans.len() {
                return Err(format!(
                    "linked Span-fill published {written} records into capacity {}",
                    spans.len()
                ));
            }
            for &matched in &spans[..written] {
                if require_positive_width && matched.start == matched.end {
                    return Err(
                        "prepared uniform-capture SpanFill violated its positive-width proof"
                            .to_owned(),
                    );
                }
                accumulator.push(matched)?;
            }
            match status {
                STATUS_NO_MATCH => return Ok(accumulator.value()),
                STATUS_MATCH if written == spans.len() => {}
                STATUS_MATCH => {
                    return Err(format!(
                        "linked Span-fill requested a refill after only {written} of {} records",
                        spans.len()
                    ));
                }
                other => {
                    return Err(format!(
                        "identity-suffixed Span-fill {:?} returned status {other}",
                        linked::SPAN_FILL_SYMBOL
                    ));
                }
            }
        }
    }

    fn strict_span_sum_with_direct_entry(&mut self, haystack: &[u8]) -> Result<u64, String> {
        strict_span_sum_with_direct_entry(haystack)
    }

    #[allow(
        unsafe_code,
        reason = "explicit destruction is the audited exclusive-handle C ABI boundary"
    )]
    fn destroy(mut self) -> Result<(), String> {
        let handle = std::mem::replace(&mut self.handle, FreAotRegexExclusiveHandleV1::INVALID);
        // SAFETY: `handle` is the one live exclusively owned value and no call
        // overlaps this explicit terminal destruction.
        let status = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
        if status != STATUS_SUCCESS {
            return Err(format!(
                "destroy exclusive AOT handle returned status {status}"
            ));
        }
        Ok(())
    }
}

impl Drop for ExclusiveSession {
    #[allow(
        unsafe_code,
        reason = "Drop is the terminal fallback for the uniquely owned exclusive handle"
    )]
    fn drop(&mut self) {
        if self.handle.is_invalid() {
            return;
        }
        let handle = std::mem::replace(&mut self.handle, FreAotRegexExclusiveHandleV1::INVALID);
        // SAFETY: Drop owns the only live handle and is the final fallback
        // when explicit checked destruction did not already consume it.
        let _ = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
    }
}

/// One preparation-time handle slot per linked independent native row.
/// Ordinary rows retain `INVALID`; capability-bearing rows own exactly one
/// V3-prepared handle for the complete benchmark lifetime.
#[derive(Debug)]
struct PreparedRowSessions {
    handles: Vec<FreAotRegexExclusiveHandleV1>,
}

impl PreparedRowSessions {
    #[allow(
        unsafe_code,
        reason = "per-row V15 preparation is the audited exclusive-handle C ABI boundary"
    )]
    fn prepare() -> Result<Self, String> {
        let mut sessions = Self {
            handles: Vec::new(),
        };
        sessions
            .handles
            .try_reserve_exact(linked::ROW_ARTIFACT_COUNT)
            .map_err(|_| "prepared native-row handle table allocation failed".to_owned())?;
        for row in 0..linked::ROW_ARTIFACT_COUNT {
            let capabilities = linked::ROW_REQUIRED_PREPARE_CAPABILITIES
                .get(row)
                .copied()
                .ok_or_else(|| format!("native row {row} has no prepare capability receipt"))?;
            if capabilities == 0 {
                sessions.handles.push(FreAotRegexExclusiveHandleV1::INVALID);
                continue;
            }
            let operation_flags = linked::ROW_PREPARE_OPERATION_FLAGS[row];
            let mut config = FreAotRegexPrepareConfigV3::new(operation_flags);
            config.required_capabilities = capabilities;
            PrepareV3Caps::linked_rows().authenticate(&config)?;
            let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
            // SAFETY: taking the address of a generated immutable program does
            // not read it; route authentication requires a nonempty extent.
            let program = unsafe { linked::row_program_ptr(row) };
            if program.is_null() {
                return Err(format!("prepared native row {row} has a null program"));
            }
            // SAFETY: route authentication binds this row to a nonempty static
            // program of the recorded extent. `config` is readable and the
            // aligned output is writable and disjoint from the program.
            let status = unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v3(
                    program,
                    linked::ROW_PROGRAM_LENS[row],
                    &config,
                    &raw mut handle,
                )
            };
            if status != STATUS_SUCCESS || handle.is_invalid() {
                if !handle.is_invalid() {
                    sessions.handles.push(handle);
                }
                return Err(format!(
                    "prepare exclusive AOT handle for native row {row} returned status {status}"
                ));
            }
            sessions.handles.push(handle);
        }
        Ok(sessions)
    }

    fn prepared_handle(&self, row: usize) -> Result<Option<FreAotRegexExclusiveHandleV1>, String> {
        let capabilities = linked::ROW_REQUIRED_PREPARE_CAPABILITIES
            .get(row)
            .copied()
            .ok_or_else(|| format!("native row {row} has no prepare capability receipt"))?;
        let handle = self
            .handles
            .get(row)
            .copied()
            .ok_or_else(|| format!("native row {row} has no prepared handle slot"))?;
        match (capabilities, handle.is_invalid()) {
            (0, true) => Ok(None),
            (PREPARE_CAPABILITY_ORDERED_NFA_V15, false) => Ok(Some(handle)),
            _ => Err(format!(
                "native row {row} handle state disagrees with capability {capabilities:#x}"
            )),
        }
    }

    #[allow(
        unsafe_code,
        reason = "per-row explicit destruction is the audited exclusive-handle C ABI boundary"
    )]
    fn destroy(mut self) -> Result<(), String> {
        let mut first_error = None;
        for (row, slot) in self.handles.iter_mut().enumerate() {
            let handle = std::mem::replace(slot, FreAotRegexExclusiveHandleV1::INVALID);
            if handle.is_invalid() {
                continue;
            }
            // SAFETY: each non-invalid table slot is uniquely owned, distinct,
            // and consumed once by this terminal destruction pass.
            let status = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
            if status != STATUS_SUCCESS && first_error.is_none() {
                first_error = Some(format!(
                    "destroy exclusive AOT handle for native row {row} returned status {status}"
                ));
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for PreparedRowSessions {
    #[allow(
        unsafe_code,
        reason = "Drop is the terminal fallback for uniquely owned per-row handles"
    )]
    fn drop(&mut self) {
        for slot in &mut self.handles {
            let handle = std::mem::replace(slot, FreAotRegexExclusiveHandleV1::INVALID);
            if !handle.is_invalid() {
                // SAFETY: this slot owns the only live handle and Drop is its
                // final fallback after any early error.
                let _ = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StrictSpanAccumulator {
    haystack_len: usize,
    last: Option<FreAotRegexResultV1>,
    reducer: SpanScalarReducer,
    value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpanScalarReducer {
    Count,
    SpanSum,
}

impl StrictSpanAccumulator {
    #[cfg(test)]
    const fn new(haystack_len: usize) -> Self {
        Self::for_reducer(haystack_len, SpanScalarReducer::SpanSum)
    }

    const fn for_reducer(haystack_len: usize, reducer: SpanScalarReducer) -> Self {
        Self {
            haystack_len,
            last: None,
            reducer,
            value: 0,
        }
    }

    fn push(&mut self, matched: FreAotRegexResultV1) -> Result<(), String> {
        validate_span(matched, self.haystack_len)?;
        if let Some(previous) = self.last {
            if matched.start < previous.end {
                return Err(format!(
                    "linked AOT spans overlap or move backward: previous={previous:?}, current={matched:?}"
                ));
            }
            if matched.start == matched.end && matched.end == previous.end {
                return Err(format!(
                    "linked AOT emitted the adjacent empty span suppressed by Rebar iteration: {matched:?}"
                ));
            }
            if previous.start == previous.end && matched.start <= previous.end {
                return Err(format!(
                    "linked AOT did not make byte progress after empty span {previous:?}: current={matched:?}"
                ));
            }
        }
        let increment = match self.reducer {
            SpanScalarReducer::Count => 1,
            SpanScalarReducer::SpanSum => {
                let width = matched
                    .end
                    .checked_sub(matched.start)
                    .ok_or_else(|| "linked AOT span width underflowed".to_owned())?;
                u64::try_from(width)
                    .map_err(|_| "linked AOT span width did not fit u64".to_owned())?
            }
        };
        self.value = self
            .value
            .checked_add(increment)
            .ok_or_else(|| match self.reducer {
                SpanScalarReducer::Count => {
                    "linked AOT complete-span count overflowed u64".to_owned()
                }
                SpanScalarReducer::SpanSum => {
                    "linked AOT complete-span sum overflowed u64".to_owned()
                }
            })?;
        self.last = Some(matched);
        Ok(())
    }

    const fn value(self) -> u64 {
        self.value
    }
}

fn validate_span(matched: FreAotRegexResultV1, haystack_len: usize) -> Result<(), String> {
    if matched.start <= matched.end && matched.end <= haystack_len {
        Ok(())
    } else {
        Err(format!(
            "linked AOT returned invalid span {matched:?} for haystack length {haystack_len}"
        ))
    }
}

#[allow(
    unsafe_code,
    reason = "the generated search declaration is the exact statically linked AOT C ABI boundary"
)]
fn strict_span_sum_with_direct_entry(haystack: &[u8]) -> Result<u64, String> {
    strict_span_sum_with_search(haystack.len(), |window_start| {
        let mut result = FreAotRegexResultV1::default();
        // SAFETY: the complete haystack and aligned result are live and
        // disjoint; the checked iterator start is always within its length.
        let status = unsafe {
            linked::search(
                haystack.as_ptr(),
                haystack.len(),
                window_start,
                haystack.len(),
                &raw mut result,
            )
        };
        match status {
            STATUS_NO_MATCH => Ok(None),
            STATUS_MATCH => Ok(Some(result)),
            other => Err(format!(
                "identity-suffixed direct entry {:?} returned status {other}",
                linked::ENTRY_SYMBOL
            )),
        }
    })
}

fn strict_span_sum_with_search(
    haystack_len: usize,
    search: impl FnMut(usize) -> Result<Option<FreAotRegexResultV1>, String>,
) -> Result<u64, String> {
    strict_scalar_with_search(haystack_len, SpanScalarReducer::SpanSum, search)
}

fn strict_scalar_with_search(
    haystack_len: usize,
    reducer: SpanScalarReducer,
    mut search: impl FnMut(usize) -> Result<Option<FreAotRegexResultV1>, String>,
) -> Result<u64, String> {
    let mut accumulator = StrictSpanAccumulator::for_reducer(haystack_len, reducer);
    let mut next_start = 0_usize;
    let mut last_match_end = None;
    let mut pending_empty_progress = false;
    loop {
        if pending_empty_progress {
            pending_empty_progress = false;
            if next_start == haystack_len {
                return Ok(accumulator.value());
            }
            next_start = next_start
                .checked_add(1)
                .ok_or_else(|| "linked AOT empty-match progress overflowed".to_owned())?;
        }

        let Some(matched) = search(next_start)? else {
            return Ok(accumulator.value());
        };
        validate_span(matched, haystack_len)?;
        if matched.start < next_start {
            return Err(format!(
                "linked AOT returned span {matched:?} before requested start {next_start}"
            ));
        }

        if matched.start == matched.end && last_match_end == Some(matched.end) {
            if next_start == haystack_len {
                return Ok(accumulator.value());
            }
            next_start = next_start
                .checked_add(1)
                .ok_or_else(|| "linked AOT adjacent-empty progress overflowed".to_owned())?;
            continue;
        }

        accumulator.push(matched)?;
        next_start = matched.end;
        last_match_end = Some(matched.end);
        pending_empty_progress = matched.start == matched.end;
    }
}

fn strict_grep_with_search(
    haystack: &[u8],
    mut is_match: impl FnMut(&[u8]) -> Result<bool, String>,
) -> Result<u64, String> {
    let mut count = 0_u64;
    for line in haystack.lines() {
        if is_match(line)? {
            count = count
                .checked_add(1)
                .ok_or_else(|| "linked AOT Rebar grep count overflowed".to_owned())?;
        }
    }
    Ok(count)
}

#[allow(
    unsafe_code,
    reason = "the generated row table is the exact statically linked AOT C ABI boundary"
)]
fn search_linked_native_row(
    sessions: &PreparedRowSessions,
    row: usize,
    haystack: &[u8],
    window_start: usize,
    result: &mut FreAotRegexResultV1,
) -> Result<u32, String> {
    // SAFETY: route authentication binds the selected table slot to exactly
    // one of these two ABIs. The complete haystack and aligned result remain
    // live and disjoint for the call; a prepared handle is uniquely owned by
    // `sessions` and calls are sequential.
    let status = unsafe {
        if let Some(handle) = sessions.prepared_handle(row)? {
            linked::search_row_prepared(
                row,
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window_start,
                haystack.len(),
                result,
            )
        } else {
            linked::search_row(
                row,
                haystack.as_ptr(),
                haystack.len(),
                window_start,
                haystack.len(),
                result,
            )
        }
    };
    Ok(status)
}

fn strict_native_row_reduce(
    model: shared::Model,
    haystack: &[u8],
    sessions: &PreparedRowSessions,
) -> Result<u64, String> {
    if model == shared::Model::GrepCount {
        return strict_grep_with_search(haystack, |line| {
            search_native_rows_with(linked::ROW_ARTIFACT_COUNT, line.len(), 0, |row, result| {
                search_linked_native_row(sessions, row, line, 0, result)
            })
            .map(|matched| matched.is_some())
        });
    }
    let reducer = match model {
        shared::Model::Count => SpanScalarReducer::Count,
        shared::Model::SpanSum => SpanScalarReducer::SpanSum,
        shared::Model::Compile
        | shared::Model::CountCaptures
        | shared::Model::GrepCount
        | shared::Model::GrepCaptures
        | shared::Model::RegexRedux => {
            return Err("native-row bridge received an unsupported operation model".to_owned());
        }
    };
    strict_scalar_with_search(haystack.len(), reducer, |window_start| {
        search_native_rows_with(
            linked::ROW_ARTIFACT_COUNT,
            haystack.len(),
            window_start,
            |row, result| search_linked_native_row(sessions, row, haystack, window_start, result),
        )
    })
}

fn search_native_rows_with(
    row_count: usize,
    haystack_len: usize,
    window_start: usize,
    mut search: impl FnMut(usize, &mut FreAotRegexResultV1) -> Result<u32, String>,
) -> Result<Option<FreAotRegexResultV1>, String> {
    search_native_rows_with_identity(row_count, haystack_len, window_start, |row, result| {
        search(row, result)
    })
    .map(|selected| selected.map(|selected| selected.result))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeRowMatch {
    row: usize,
    result: FreAotRegexResultV1,
}

fn search_native_rows_with_identity(
    row_count: usize,
    haystack_len: usize,
    window_start: usize,
    mut search: impl FnMut(usize, &mut FreAotRegexResultV1) -> Result<u32, String>,
) -> Result<Option<NativeRowMatch>, String> {
    if window_start > haystack_len {
        return Err(format!(
            "native-row window start {window_start} exceeds haystack length {haystack_len}"
        ));
    }
    if row_count == 0 {
        return Err("native-row bridge has no linked entry".to_owned());
    }

    let mut selected = None::<NativeRowMatch>;
    for row in 0..row_count {
        let mut result = FreAotRegexResultV1 {
            start: usize::MAX,
            end: usize::MAX,
        };
        let status = search(row, &mut result)?;
        match status {
            STATUS_NO_MATCH => {}
            STATUS_MATCH => {
                validate_span(result, haystack_len)?;
                if result.start < window_start {
                    return Err(format!(
                        "native row {row} returned span {result:?} before requested start {window_start}"
                    ));
                }
                if selected.is_none_or(|current| result.start < current.result.start) {
                    selected = Some(NativeRowMatch { row, result });
                }
            }
            other => {
                return Err(format!(
                    "native row {row} entry {:?} returned status {other}",
                    linked::ROW_ENTRY_SYMBOLS
                        .get(row)
                        .copied()
                        .unwrap_or("<missing>")
                ));
            }
        }
    }
    Ok(selected)
}

fn strict_uniform_capture_count_domain_with(
    row_group_counts: &[u64],
    haystack: &[u8],
    mut search: impl FnMut(usize, usize, &mut FreAotRegexResultV1) -> Result<u32, String>,
) -> Result<u64, String> {
    if row_group_counts.is_empty() || row_group_counts.contains(&0) {
        return Err("uniform-capture row group counts are empty or contain zero".to_owned());
    }
    let mut count = 0_u64;
    let mut start = 0_usize;
    loop {
        let Some(selected) = search_native_rows_with_identity(
            row_group_counts.len(),
            haystack.len(),
            start,
            |row, result| search(row, start, result),
        )?
        else {
            return Ok(count);
        };
        if selected.result.start == selected.result.end {
            return Err(format!(
                "uniform-capture row {} violated its authenticated positive-width proof",
                selected.row
            ));
        }
        count = count
            .checked_add(row_group_counts[selected.row])
            .ok_or_else(|| "linked AOT uniform capture count overflowed".to_owned())?;
        start = selected.result.end;
    }
}

#[allow(
    unsafe_code,
    reason = "the generated capture row table is the exact statically linked AOT C ABI boundary"
)]
fn strict_linked_uniform_capture_domain(haystack: &[u8]) -> Result<u64, String> {
    strict_uniform_capture_count_domain_with(
        linked::ROW_PARTICIPATING_GROUPS,
        haystack,
        |row, window_start, result| {
            // SAFETY: route authentication binds every table slot to one
            // helper-free ordinary Span entry. The slice and aligned result
            // remain live and disjoint for the complete call.
            let status = unsafe {
                linked::search_row(
                    row,
                    haystack.as_ptr(),
                    haystack.len(),
                    window_start,
                    haystack.len(),
                    result,
                )
            };
            Ok(status)
        },
    )
}

fn strict_uniform_capture_reduce(model: shared::Model, haystack: &[u8]) -> Result<u64, String> {
    match model {
        shared::Model::CountCaptures => strict_linked_uniform_capture_domain(haystack),
        shared::Model::GrepCaptures => haystack.lines().try_fold(0_u64, |total, line| {
            total
                .checked_add(strict_linked_uniform_capture_domain(line)?)
                .ok_or_else(|| "linked AOT grep-captures count overflowed".to_owned())
        }),
        shared::Model::Compile
        | shared::Model::Count
        | shared::Model::SpanSum
        | shared::Model::GrepCount
        | shared::Model::RegexRedux => {
            Err("uniform-capture bridge received an unsupported operation model".to_owned())
        }
    }
}

fn strict_participation_capture_count_domain_with(
    haystack_len: usize,
    mut search: impl FnMut(usize) -> Result<Option<FreAotRegexResultV1>, String>,
    mut participation: impl FnMut(FreAotRegexResultV1) -> Result<u64, String>,
) -> Result<u64, String> {
    let mut spans = StrictSpanAccumulator::for_reducer(haystack_len, SpanScalarReducer::Count);
    let mut total = 0_u64;
    let mut next_start = 0_usize;
    let mut last_match_end = None;
    let mut pending_empty_progress = false;
    loop {
        if pending_empty_progress {
            pending_empty_progress = false;
            if next_start == haystack_len {
                return Ok(total);
            }
            next_start = next_start.checked_add(1).ok_or_else(|| {
                "participation selector empty-match progress overflowed".to_owned()
            })?;
        }

        let Some(matched) = search(next_start)? else {
            return Ok(total);
        };
        validate_span(matched, haystack_len)?;
        if matched.start < next_start {
            return Err(format!(
                "participation selector returned span {matched:?} before requested start {next_start}"
            ));
        }
        if matched.start == matched.end && last_match_end == Some(matched.end) {
            if next_start == haystack_len {
                return Ok(total);
            }
            next_start = next_start.checked_add(1).ok_or_else(|| {
                "participation selector adjacent-empty progress overflowed".to_owned()
            })?;
            continue;
        }

        spans.push(matched)?;
        let groups = participation(matched)?;
        if groups == 0 {
            return Err("participation replay omitted mandatory group zero".to_owned());
        }
        total = total
            .checked_add(groups)
            .ok_or_else(|| "linked AOT participation capture count overflowed".to_owned())?;
        next_start = matched.end;
        last_match_end = Some(matched.end);
        pending_empty_progress = matched.start == matched.end;
    }
}

#[allow(
    unsafe_code,
    reason = "the generated selector, bundle and exact-span participation declarations form one authenticated object-local ABI"
)]
fn strict_linked_participation_capture_domain(haystack: &[u8]) -> Result<u64, String> {
    strict_participation_capture_count_domain_with(
        haystack.len(),
        |window_start| {
            let mut result = FreAotRegexResultV1::default();
            // SAFETY: route authentication binds row zero to the object-local
            // helper-free selector. The complete haystack and aligned result
            // remain live and disjoint for this call.
            let status = unsafe {
                linked::search_row(
                    0,
                    haystack.as_ptr(),
                    haystack.len(),
                    window_start,
                    haystack.len(),
                    &raw mut result,
                )
            };
            match status {
                STATUS_NO_MATCH => Ok(None),
                STATUS_MATCH => Ok(Some(result)),
                other => Err(format!(
                    "participation selector {:?} returned status {other}",
                    linked::PARTICIPATION_SELECTOR_SYMBOL,
                )),
            }
        },
        |matched| {
            const SCRATCH_SENTINEL: [u64; 2] = [0x614f_542d_7363_7231, 0x7265_7365_7276_6564];
            let mut scratch = SCRATCH_SENTINEL;
            let mut count = usize::MAX;
            // SAFETY: the generated bundle and exact entry are from the same
            // authenticated linked object. `matched` came from its paired
            // selector; all request inputs are live and the naturally aligned
            // 16-byte reserved scratch and count output are disjoint.
            let request = FreAotRegexParticipationRequestV1 {
                bundle: unsafe { linked::participation_bundle_ptr() },
                haystack: haystack.as_ptr(),
                haystack_len: haystack.len(),
                match_start: matched.start,
                match_end: matched.end,
                scratch: scratch.as_mut_ptr().cast::<u8>(),
                scratch_len: std::mem::size_of_val(&scratch),
                count_out: &raw mut count,
            };
            // SAFETY: all pointer, extent, alignment and exact-span obligations
            // are established above and remain valid for the complete call.
            let status = unsafe { linked::participation_exact(&raw const request) };
            if scratch != SCRATCH_SENTINEL {
                return Err("native participation entry modified reserved scratch".to_owned());
            }
            if status != STATUS_MATCH {
                if count != usize::MAX {
                    return Err(format!(
                        "native participation status {status} published count {count} transactionally"
                    ));
                }
                return Err(format!(
                    "native participation entry {:?} returned status {status} for its selector span",
                    linked::PARTICIPATION_ENTRY_SYMBOL,
                ));
            }
            if count == 0 || count > linked::PARTICIPATION_GROUP_COUNT {
                return Err(format!(
                    "native participation entry published count {count} outside 1..={} for one match",
                    linked::PARTICIPATION_GROUP_COUNT,
                ));
            }
            u64::try_from(count)
                .map_err(|_| "native participation count did not fit u64".to_owned())
        },
    )
}

fn strict_participation_capture_reduce(
    model: shared::Model,
    haystack: &[u8],
) -> Result<u64, String> {
    match model {
        shared::Model::CountCaptures => strict_linked_participation_capture_domain(haystack),
        shared::Model::GrepCaptures => haystack.lines().try_fold(0_u64, |total, line| {
            total
                .checked_add(strict_linked_participation_capture_domain(line)?)
                .ok_or_else(|| "linked participation grep-captures count overflowed".to_owned())
        }),
        _ => Err("participation capture bridge received an unsupported operation model".to_owned()),
    }
}

fn strict_selector_capture_grep_reduce_with(
    haystack: &[u8],
    mut search: impl FnMut(&[u8], &mut FreAotRegexResultV1) -> Result<u32, String>,
    mut positive_capture_fallback: impl FnMut(&[u8]) -> Result<u64, String>,
) -> Result<u64, String> {
    haystack.lines().try_fold(0_u64, |total, line| {
        let mut selected = FreAotRegexResultV1 {
            start: usize::MAX,
            end: usize::MAX,
        };
        let count = match search(line, &mut selected)? {
            STATUS_NO_MATCH => 0,
            STATUS_MATCH => {
                validate_span(selected, line.len())?;
                positive_capture_fallback(line)?
            }
            status => {
                return Err(format!(
                    "selector-first capture entry returned status {status}"
                ));
            }
        };
        total
            .checked_add(count)
            .ok_or_else(|| "selector-first grep-captures count overflowed".to_owned())
    })
}

static SELECTOR_CAPTURE_POSITIVE_FALLBACK_CALLS: AtomicU64 = AtomicU64::new(0);

/// Statically visible positive-route marker. The atomic side effect keeps the
/// call observable to qualification tooling even under optimization; the
/// actual fallback immediately following it is the exact pinned stock capture
/// implementation.
#[allow(
    unsafe_code,
    reason = "the stable exported marker makes the mixed positive fallback route visible to static and trap qualification"
)]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fre_aot_rebar_runner_stock_capture_positive_fallback_v1() {
    SELECTOR_CAPTURE_POSITIVE_FALLBACK_CALLS.fetch_add(1, Ordering::Relaxed);
}

#[allow(
    unsafe_code,
    reason = "the generated row-zero declaration is the authenticated helper-free Span selector ABI"
)]
fn strict_linked_selector_capture_grep(haystack: &[u8], stock: &Regex) -> Result<u64, String> {
    strict_selector_capture_grep_reduce_with(
        haystack,
        |line, result| {
            // SAFETY: route authentication binds row zero to the exact
            // helper-free selector for the same one-source stock profile.
            let status =
                unsafe { linked::search_row(0, line.as_ptr(), line.len(), 0, line.len(), result) };
            Ok(status)
        },
        |line| {
            fre_aot_rebar_runner_stock_capture_positive_fallback_v1();
            stock_capture_count_domain(stock, line)
        },
    )
}

fn validate_strict_capture_state(
    state: FreAotRegexIterStateV1,
    haystack_len: usize,
) -> Result<(), String> {
    if state.reserved != 0
        || state.flags & !ITER_KNOWN_FLAGS != 0
        || state.next_start > haystack_len
        || (state.flags & ITER_HAS_LAST != 0 && state.last_match_end > haystack_len)
        || (state.flags & ITER_PENDING_EMPTY != 0
            && (state.flags & ITER_HAS_LAST == 0
                || state.flags & ITER_FINISHED != 0
                || state.next_start != state.last_match_end))
    {
        return Err("strict capture iterator published malformed continuation state".to_owned());
    }
    Ok(())
}

fn strict_capture_row_participation(
    haystack_len: usize,
    slots: &[FreAotRegexCaptureSlotV1],
) -> Result<u64, String> {
    let Some(group_zero) = slots.first().copied() else {
        return Err("strict capture result omitted group zero".to_owned());
    };
    if group_zero == FreAotRegexCaptureSlotV1::UNMATCHED
        || group_zero.start > group_zero.end
        || group_zero.end > haystack_len
    {
        return Err("strict capture group zero is malformed or out of bounds".to_owned());
    }
    let mut participating = 0_u64;
    for slot in slots {
        let start_unset = slot.start == usize::MAX;
        let end_unset = slot.end == usize::MAX;
        if start_unset != end_unset {
            return Err("strict capture result contains a half-unmatched group".to_owned());
        }
        if start_unset {
            continue;
        }
        if slot.start < group_zero.start
            || slot.start > slot.end
            || slot.end > group_zero.end
            || slot.end > haystack_len
        {
            return Err("strict capture result contains an invalid group span".to_owned());
        }
        participating = participating
            .checked_add(1)
            .ok_or_else(|| "strict capture participation count overflowed".to_owned())?;
    }
    Ok(participating)
}

#[allow(
    unsafe_code,
    reason = "the generated identity-suffixed capture-next declaration is the audited native ABI boundary"
)]
fn strict_linked_capture_count_domain(
    haystack: &[u8],
    slots: &mut [FreAotRegexCaptureSlotV1],
) -> Result<u64, String> {
    if slots.len() != linked::STRICT_CAPTURE_GROUP_COUNT || slots.is_empty() {
        return Err("strict capture slot storage disagrees with its linked schema".to_owned());
    }
    let mut state = FreAotRegexIterStateV1::default();
    let mut total = 0_u64;
    loop {
        slots.fill(FreAotRegexCaptureSlotV1::UNMATCHED);
        let before = state;
        // SAFETY: the complete byte slice, aligned iterator state, and exact
        // receipt-sized result slice are live and pairwise disjoint. Runtime
        // authentication admits this call only for the linked native route.
        let status = unsafe {
            linked::capture_next(
                haystack.as_ptr(),
                haystack.len(),
                &mut state,
                slots.as_mut_ptr(),
                slots.len(),
            )
        };
        validate_strict_capture_state(state, haystack.len())?;
        match status {
            STATUS_NO_MATCH => {
                if state.flags & ITER_FINISHED == 0
                    || slots
                        .iter()
                        .any(|slot| *slot != FreAotRegexCaptureSlotV1::UNMATCHED)
                {
                    return Err(
                        "strict capture exhaustion did not fuse state and clear slots".to_owned(),
                    );
                }
                return Ok(total);
            }
            STATUS_MATCH => {
                if state == before {
                    return Err("strict capture iterator made no progress".to_owned());
                }
                let groups = strict_capture_row_participation(haystack.len(), slots)?;
                total = total
                    .checked_add(groups)
                    .ok_or_else(|| "strict capture total overflowed".to_owned())?;
            }
            other => {
                return Err(format!(
                    "linked strict capture entry {:?} returned status {other}",
                    linked::STRICT_CAPTURE_NEXT_SYMBOL,
                ));
            }
        }
    }
}

fn strict_capture_reduce(
    model: shared::Model,
    haystack: &[u8],
    slots: &mut [FreAotRegexCaptureSlotV1],
) -> Result<u64, String> {
    match model {
        shared::Model::CountCaptures => strict_linked_capture_count_domain(haystack, slots),
        shared::Model::GrepCaptures => haystack.lines().try_fold(0_u64, |total, line| {
            total
                .checked_add(strict_linked_capture_count_domain(line, slots)?)
                .ok_or_else(|| "linked strict grep-captures count overflowed".to_owned())
        }),
        _ => Err("strict capture bridge received an unsupported operation model".to_owned()),
    }
}

fn prepared_uniform_capture_count_domain(
    session: &mut ExclusiveSession,
    haystack: &[u8],
) -> Result<u64, String> {
    let [groups] = linked::SOURCE_PARTICIPATING_GROUPS else {
        return Err(
            "prepared uniform-capture route does not contain exactly one multiplier".to_owned(),
        );
    };
    if *groups == 0 {
        return Err("prepared uniform-capture multiplier is zero".to_owned());
    }
    let matches = session.strict_scalar_with_fill(haystack, SpanScalarReducer::Count, true)?;
    matches
        .checked_mul(*groups)
        .ok_or_else(|| "prepared uniform-capture total overflowed u64".to_owned())
}

fn prepared_uniform_capture_reduce(
    model: shared::Model,
    session: &mut ExclusiveSession,
    haystack: &[u8],
) -> Result<u64, String> {
    match model {
        shared::Model::CountCaptures => prepared_uniform_capture_count_domain(session, haystack),
        shared::Model::GrepCaptures => haystack.lines().try_fold(0_u64, |total, line| {
            total
                .checked_add(prepared_uniform_capture_count_domain(session, line)?)
                .ok_or_else(|| "prepared uniform grep-captures total overflowed u64".to_owned())
        }),
        _ => Err("prepared uniform-capture route received a non-capture model".to_owned()),
    }
}

fn main() -> Result<(), DynError> {
    let arguments = parse_arguments()?;
    if arguments.version {
        if linked::CONFIGURED {
            println!("{}+{}", env!("CARGO_PKG_VERSION"), linked::ADAPTER);
        } else {
            println!("{}+general-aot-unconfigured", env!("CARGO_PKG_VERSION"));
        }
        return Ok(());
    }
    if arguments.provenance {
        print_provenance();
        return Ok(());
    }
    if !linked::CONFIGURED {
        return Err(format!(
            "runner is unconfigured; rebuild with FRE_AOT_REBAR_KLV=/absolute/public/job.klv"
        )
        .into());
    }

    let mut input = Vec::new();
    io::stdin()
        .take(shared::MAX_KLV_BYTES.saturating_add(1))
        .read_to_end(&mut input)?;
    if u64::try_from(input.len()).map_or(true, |length| length > shared::MAX_KLV_BYTES) {
        return Err(format!("KLV input exceeds {} bytes", shared::MAX_KLV_BYTES).into());
    }
    let benchmark = shared::Benchmark::parse(&input)?;
    authenticate_benchmark(&benchmark)?;
    authenticate_linked_route(&benchmark)?;
    let target =
        shared::target_from_parts(linked::TARGET_ARCH, linked::TARGET_OS, linked::FEATURE_BITS)?;
    let (samples, regex_redux_receipt) = if benchmark.model == shared::Model::RegexRedux {
        let run = run_regex_redux(&benchmark)?;
        (run.samples, Some(run.receipt))
    } else if linked::NATIVE_ROW_BRIDGE {
        (run_native_row_operation(&benchmark)?, None)
    } else {
        let mut session = ExclusiveSession::prepare(benchmark.model)?;
        let samples = if benchmark.model == shared::Model::Compile {
            run_compile(&benchmark, target, &mut session)?
        } else {
            run_operation(&benchmark, &mut session)?
        };
        session.destroy()?;
        (samples, None)
    };
    let expected = rust_oracle(&benchmark)?;
    if let Some(actual_receipt) = regex_redux_receipt {
        let expected_receipt = rust_regex_redux_oracle(&benchmark.haystack)?;
        if actual_receipt != expected_receipt {
            return Err(format!(
                "linked AOT regex-redux stage receipt {actual_receipt:?} differs from independent Rust receipt {expected_receipt:?}"
            )
            .into());
        }
    }
    for sample in &samples {
        require_expected(sample.value, expected)?;
    }

    if !arguments.quiet {
        let mut stdout = io::stdout().lock();
        for sample in samples {
            writeln!(stdout, "{},{}", sample.duration.as_nanos(), sample.value)?;
        }
    }
    Ok(())
}

fn parse_arguments() -> Result<Arguments, DynError> {
    let mut parsed = Arguments::default();
    for argument in env::args().skip(1) {
        match argument.as_str() {
            "--quiet" | "-q" => parsed.quiet = true,
            "--version" => parsed.version = true,
            "--provenance" => parsed.provenance = true,
            "--help" | "-h" => {
                return Err(
                    "usage: fre-aot-rebar-runner [--quiet | --version | --provenance]".into(),
                );
            }
            other => return Err(format!("unrecognized argument {other:?}").into()),
        }
    }
    if parsed.version && parsed.provenance {
        return Err("--version and --provenance are mutually exclusive".into());
    }
    Ok(parsed)
}

fn print_provenance() {
    if linked::EXPECTED_MODEL == "regex-redux" {
        let mut provenance = String::new();
        write!(
            &mut provenance,
            "schema=fre.aot.rebar-runner.v3 disposition=executed configured={} adapter={} model={} benchmark={:?} source_commit={} source_tree={} target={}-{} feature_bits={:016x} compiler_version={} optimizer_version={} engine={} aggregate_strategy={} component_count={}",
            linked::CONFIGURED,
            linked::ADAPTER,
            linked::EXPECTED_MODEL,
            linked::EXPECTED_NAME,
            linked::SOURCE_COMMIT,
            linked::SOURCE_TREE,
            linked::TARGET_ARCH,
            linked::TARGET_OS,
            linked::FEATURE_BITS,
            linked::COMPILER_VERSION,
            linked::OPTIMIZER_VERSION,
            linked::ENGINE,
            linked::AGGREGATE_STRATEGY,
            linked::REGEX_REDUX_COMPONENT_COUNT,
        )
        .expect("format regex-redux provenance header");
        for component in 0..linked::REGEX_REDUX_COMPONENT_COUNT {
            write!(
                &mut provenance,
                " component_{component}_native={} component_{component}_entry_symbol={} component_{component}_runtime_symbols={} component_{component}_program_sha256={} component_{component}_object_sha256={}",
                linked::REGEX_REDUX_NATIVE[component],
                linked::REGEX_REDUX_ENTRY_SYMBOLS[component],
                linked::REGEX_REDUX_RUNTIME_SYMBOLS[component],
                hex(&linked::REGEX_REDUX_PROGRAM_SHA256[component]),
                hex(&linked::REGEX_REDUX_OBJECT_SHA256[component]),
            )
            .expect("format regex-redux component provenance");
        }
        println!(
            "{provenance} reducer_symbol={} operation_identity_sha256={} reducer_code_sha256={} reducer_data_sha256={} reducer_object_sha256={} reducer_relocation_count={} reducer_link_symbols={} semantic_runtime_symbols={} abi_version={} request_bytes={} receipt_bytes={} report_bytes={} scratch_buffer_count={} scratch_capacity_numerator={} scratch_capacity_denominator={} receipt_schema={} report_schema={} boundary=single-call-native-regex-redux-reducer required_comparators=rust-regex-1.12.4,fre-current-runtime",
            linked::REDUCER_SYMBOL,
            hex(&linked::REGEX_REDUX_OPERATION_IDENTITY_SHA256),
            hex(&linked::REGEX_REDUX_REDUCER_CODE_SHA256),
            hex(&linked::REGEX_REDUX_REDUCER_DATA_SHA256),
            hex(&linked::REGEX_REDUX_REDUCER_OBJECT_SHA256),
            linked::REGEX_REDUX_REDUCER_RELOCATION_COUNT,
            linked::REGEX_REDUX_REDUCER_LINK_SYMBOLS.join(","),
            linked::REGEX_REDUX_SEMANTIC_RUNTIME_SYMBOLS.join(","),
            linked::REGEX_REDUX_ABI_VERSION,
            linked::REGEX_REDUX_REQUEST_BYTES,
            linked::REGEX_REDUX_RECEIPT_BYTES,
            linked::REGEX_REDUX_REPORT_BYTES,
            linked::REGEX_REDUX_SCRATCH_BUFFER_COUNT,
            linked::REGEX_REDUX_SCRATCH_CAPACITY_NUMERATOR,
            linked::REGEX_REDUX_SCRATCH_CAPACITY_DENOMINATOR,
            linked::REGEX_REDUX_RECEIPT_SCHEMA,
            linked::REGEX_REDUX_REPORT_SCHEMA,
        );
        return;
    }
    if linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE {
        println!(
            "schema=fre.aot.rebar-runner.v4 disposition=executed configured={} adapter={} model={} benchmark={:?} source_commit={} source_tree={} target={}-{} feature_bits={:016x} compiler_version={} optimizer_version={} engine={} aggregate_strategy={} native_row_bridge=true uniform_capture_bridge=false strict_capture_bridge=false participation_capture_bridge=false selector_capture_fallback_bridge=true source_pattern_count=1 row_total_object_bytes={} source_to_artifact=0 component_count=1 component_0_native=true component_0_source_ordinal=0 component_0_entry_symbol={} component_0_runtime_symbols= component_0_program_sha256={} component_0_object_sha256={} capture_resolution=native-selector-negative-certificate-with-stock-positive-capture-fallback-v1 positive_fallback_profile={} positive_fallback_symbol={} direct_participation_resource={} direct_participation_required={} direct_participation_limit={} boundary=per-line-native-span-negative-certificate-with-trap-visible-stock-positive-capture-fallback required_comparators=rust-regex-1.12.4,fre-current-runtime",
            linked::CONFIGURED,
            linked::ADAPTER,
            linked::EXPECTED_MODEL,
            linked::EXPECTED_NAME,
            linked::SOURCE_COMMIT,
            linked::SOURCE_TREE,
            linked::TARGET_ARCH,
            linked::TARGET_OS,
            linked::FEATURE_BITS,
            linked::COMPILER_VERSION,
            linked::OPTIMIZER_VERSION,
            linked::ENGINE,
            linked::AGGREGATE_STRATEGY,
            linked::ROW_TOTAL_OBJECT_BYTES,
            linked::ROW_ENTRY_SYMBOLS[0],
            hex(&linked::ROW_PROGRAM_SHA256[0]),
            hex(&linked::ROW_OBJECT_SHA256[0]),
            linked::SELECTOR_CAPTURE_POSITIVE_FALLBACK_PROFILE,
            linked::SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL,
            linked::SELECTOR_CAPTURE_DIRECT_RESOURCE,
            linked::SELECTOR_CAPTURE_DIRECT_REQUIRED,
            linked::SELECTOR_CAPTURE_DIRECT_LIMIT,
        );
        return;
    }
    if linked::PARTICIPATION_CAPTURE_BRIDGE {
        println!(
            "schema=fre.aot.rebar-runner.v4 disposition=executed configured={} adapter={} model={} benchmark={:?} source_commit={} source_tree={} target={}-{} feature_bits={:016x} compiler_version={} optimizer_version={} engine={} aggregate_strategy={} native_row_bridge=true uniform_capture_bridge=false strict_capture_bridge=false participation_capture_bridge=true source_pattern_count=1 row_total_object_bytes={} source_to_artifact=0 component_count=1 component_0_native=true component_0_source_ordinal=0 component_0_entry_symbol={} component_0_runtime_symbols= component_0_program_sha256={} component_0_object_sha256={} capture_resolution=native-exact-span-participation-dfa-v1 capture_group_count={} participation_algorithm_id={} participation_strategy={} participation_semantic_runtime_calls={} participation_assertions={} participation_assertion_signatures={} participation_byte_classes={} participation_dfa_states={} participation_transition_cells={} participation_build_work={} participation_scratch_bytes={} participation_plan_bytes={} capture_source_sha256={} capture_selector_sha256={} capture_program_sha256={} selector_object_sha256={} participation_bundle_sha256={} participation_export_identity_sha256={} participation_object_sha256={} capture_artifact_identity_sha256={} participation_bundle_symbol={} capture_selector_symbol={} participation_entry_symbol={} boundary=native-span-selector-with-helper-free-exact-span-participation-replay required_comparators=rust-regex-1.12.4,fre-current-runtime",
            linked::CONFIGURED,
            linked::ADAPTER,
            linked::EXPECTED_MODEL,
            linked::EXPECTED_NAME,
            linked::SOURCE_COMMIT,
            linked::SOURCE_TREE,
            linked::TARGET_ARCH,
            linked::TARGET_OS,
            linked::FEATURE_BITS,
            linked::COMPILER_VERSION,
            linked::OPTIMIZER_VERSION,
            linked::ENGINE,
            linked::AGGREGATE_STRATEGY,
            linked::ROW_TOTAL_OBJECT_BYTES,
            linked::PARTICIPATION_SELECTOR_SYMBOL,
            hex(&linked::PARTICIPATION_CAPTURE_SHA256),
            hex(&linked::PARTICIPATION_OBJECT_SHA256),
            linked::PARTICIPATION_GROUP_COUNT,
            linked::PARTICIPATION_ALGORITHM_ID,
            linked::PARTICIPATION_STRATEGY,
            linked::PARTICIPATION_SEMANTIC_RUNTIME_CALLS,
            linked::PARTICIPATION_ASSERTIONS,
            linked::PARTICIPATION_ASSERTION_SIGNATURES,
            linked::PARTICIPATION_BYTE_CLASSES,
            linked::PARTICIPATION_DFA_STATES,
            linked::PARTICIPATION_TRANSITION_CELLS,
            linked::PARTICIPATION_BUILD_WORK,
            linked::PARTICIPATION_SCRATCH_BYTES,
            linked::PARTICIPATION_PLAN_BYTES,
            hex(&linked::PARTICIPATION_SOURCE_SHA256),
            hex(&linked::PARTICIPATION_SELECTOR_SHA256),
            hex(&linked::PARTICIPATION_CAPTURE_SHA256),
            hex(&linked::PARTICIPATION_SELECTOR_OBJECT_SHA256),
            hex(&linked::PARTICIPATION_BUNDLE_SHA256),
            hex(&linked::PARTICIPATION_EXPORT_IDENTITY_SHA256),
            hex(&linked::PARTICIPATION_OBJECT_SHA256),
            hex(&linked::PARTICIPATION_ARTIFACT_IDENTITY_SHA256),
            linked::PARTICIPATION_BUNDLE_SYMBOL,
            linked::PARTICIPATION_SELECTOR_SYMBOL,
            linked::PARTICIPATION_ENTRY_SYMBOL,
        );
        return;
    }
    if linked::STRICT_CAPTURE_BRIDGE {
        println!(
            "schema=fre.aot.rebar-runner.v4 disposition=executed configured={} adapter={} model={} benchmark={:?} source_commit={} source_tree={} target={}-{} feature_bits={:016x} compiler_version={} optimizer_version={} engine={} aggregate_strategy={} native_row_bridge=true uniform_capture_bridge=false strict_capture_bridge=true source_pattern_count=1 row_total_object_bytes={} source_to_artifact=0 component_count=1 component_0_native=true component_0_source_ordinal=0 component_0_entry_symbol={} component_0_runtime_symbols= component_0_program_sha256={} component_0_object_sha256={} capture_resolution=native-onepass-capture-next-v1 capture_group_count={} capture_can_match_empty={} capture_source_sha256={} capture_selector_sha256={} capture_program_sha256={} capture_plan_sha256={} capture_bundle_sha256={} capture_artifact_identity_sha256={} capture_materialize_symbol={} capture_selector_symbol={} boundary=native-search-core-with-native-capture-materialization-adapter-loop required_comparators=rust-regex-1.12.4,fre-current-runtime",
            linked::CONFIGURED,
            linked::ADAPTER,
            linked::EXPECTED_MODEL,
            linked::EXPECTED_NAME,
            linked::SOURCE_COMMIT,
            linked::SOURCE_TREE,
            linked::TARGET_ARCH,
            linked::TARGET_OS,
            linked::FEATURE_BITS,
            linked::COMPILER_VERSION,
            linked::OPTIMIZER_VERSION,
            linked::ENGINE,
            linked::AGGREGATE_STRATEGY,
            linked::ROW_TOTAL_OBJECT_BYTES,
            linked::STRICT_CAPTURE_NEXT_SYMBOL,
            hex(&linked::STRICT_CAPTURE_CAPTURE_SHA256),
            hex(&linked::OBJECT_SHA256),
            linked::STRICT_CAPTURE_GROUP_COUNT,
            linked::STRICT_CAPTURE_CAN_MATCH_EMPTY,
            hex(&linked::STRICT_CAPTURE_SOURCE_SHA256),
            hex(&linked::STRICT_CAPTURE_SELECTOR_SHA256),
            hex(&linked::STRICT_CAPTURE_CAPTURE_SHA256),
            hex(&linked::STRICT_CAPTURE_PLAN_SHA256),
            hex(&linked::STRICT_CAPTURE_BUNDLE_SHA256),
            hex(&linked::STRICT_CAPTURE_ARTIFACT_IDENTITY_SHA256),
            linked::STRICT_CAPTURE_MATERIALIZE_SYMBOL,
            linked::STRICT_CAPTURE_SELECTOR_SYMBOL,
        );
        return;
    }
    if linked::NATIVE_ROW_BRIDGE {
        let source_to_artifact = linked::SOURCE_TO_ARTIFACT
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut provenance = String::new();
        write!(
            &mut provenance,
            "schema=fre.aot.rebar-runner.v3 disposition=executed configured={} adapter={} model={} benchmark={:?} source_commit={} source_tree={} target={}-{} feature_bits={:016x} compiler_version={} optimizer_version={} engine={} aggregate_strategy={} native_row_bridge=true uniform_capture_bridge={} source_pattern_count={} row_total_object_bytes={} source_to_artifact={} component_count={} prepare_max_handle_bytes={} prepare_max_scratch_bytes={} prepare_max_setup_work={}",
            linked::CONFIGURED,
            linked::ADAPTER,
            linked::EXPECTED_MODEL,
            linked::EXPECTED_NAME,
            linked::SOURCE_COMMIT,
            linked::SOURCE_TREE,
            linked::TARGET_ARCH,
            linked::TARGET_OS,
            linked::FEATURE_BITS,
            linked::COMPILER_VERSION,
            linked::OPTIMIZER_VERSION,
            linked::ENGINE,
            linked::AGGREGATE_STRATEGY,
            linked::UNIFORM_CAPTURE_BRIDGE,
            linked::SOURCE_PATTERN_COUNT,
            linked::ROW_TOTAL_OBJECT_BYTES,
            source_to_artifact,
            linked::ROW_ARTIFACT_COUNT,
            linked::ROW_PREPARE_MAX_HANDLE_BYTES,
            linked::ROW_PREPARE_MAX_SCRATCH_BYTES,
            linked::ROW_PREPARE_MAX_SETUP_WORK,
        )
        .expect("format native-row provenance header");
        for component in 0..linked::ROW_ARTIFACT_COUNT {
            write!(
                &mut provenance,
                " component_{component}_native=true component_{component}_source_ordinal={} component_{component}_entry_symbol={} component_{component}_runtime_symbols={} component_{component}_required_prepare_capabilities={:016x} component_{component}_prepare_config_version={} component_{component}_prepare_operation_flags={:016x} component_{component}_runtime_program_symbol={} component_{component}_runtime_program_len={} component_{component}_span_fill_symbol={} component_{component}_prepared_bulk_strategy={} component_{component}_automaton_sha256={} component_{component}_program_sha256={} component_{component}_object_sha256={}",
                linked::ROW_FIRST_SOURCE_ORDINALS[component],
                linked::ROW_ENTRY_SYMBOLS[component],
                linked::ROW_REQUIRED_RUNTIME_SYMBOLS[component],
                linked::ROW_REQUIRED_PREPARE_CAPABILITIES[component],
                linked::ROW_PREPARE_CONFIG_VERSIONS[component],
                linked::ROW_PREPARE_OPERATION_FLAGS[component],
                linked::ROW_PROGRAM_SYMBOLS[component],
                linked::ROW_PROGRAM_LENS[component],
                linked::ROW_SPAN_FILL_SYMBOLS[component],
                linked::ROW_PREPARED_BULK_STRATEGIES[component],
                hex(&linked::ROW_AUTOMATON_SHA256[component]),
                hex(&linked::ROW_PROGRAM_SHA256[component]),
                hex(&linked::ROW_OBJECT_SHA256[component]),
            )
            .expect("format native-row component provenance");
        }
        if linked::UNIFORM_CAPTURE_BRIDGE {
            let groups = linked::SOURCE_PARTICIPATING_GROUPS
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let minimums = linked::SOURCE_MINIMUM_MATCH_BYTES
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let capture_annotations = linked::SOURCE_CANONICAL_CAPTURE_ANNOTATIONS
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let proof_work = linked::SOURCE_PROOF_WORK
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let proof_stack = linked::SOURCE_PROOF_PEAK_STACK_ITEMS
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let selector_automata = linked::SOURCE_SELECTOR_AUTOMATON_SHA256
                .iter()
                .map(|digest| hex(digest))
                .collect::<Vec<_>>()
                .join(",");
            let selector_programs = linked::SOURCE_SELECTOR_PROGRAM_SHA256
                .iter()
                .map(|digest| hex(digest))
                .collect::<Vec<_>>()
                .join(",");
            let selector_objects = linked::SOURCE_SELECTOR_OBJECT_SHA256
                .iter()
                .map(|digest| hex(digest))
                .collect::<Vec<_>>()
                .join(",");
            write!(
                &mut provenance,
                " capture_resolution=static-uniform-multiplier capture_proof_algorithm_version={} capture_proof_accounting_version={} source_participating_groups={} source_minimum_match_bytes={} source_capture_annotations={} source_proof_work={} source_proof_peak_stack_items={} source_selector_automaton_sha256={} source_selector_program_sha256={} source_selector_object_sha256={}",
                linked::UNIFORM_CAPTURE_ALGORITHM_VERSION,
                linked::UNIFORM_CAPTURE_ACCOUNTING_VERSION,
                groups,
                minimums,
                capture_annotations,
                proof_work,
                proof_stack,
                selector_automata,
                selector_programs,
                selector_objects,
            )
            .expect("format uniform-capture proof provenance");
        }
        let boundary = if linked::UNIFORM_CAPTURE_BRIDGE {
            "native-search-core-static-uniform-capture-resolution"
        } else {
            "complete-native-row-bridge"
        };
        println!(
            "{provenance} boundary={boundary} required_comparators=rust-regex-1.12.4,fre-current-runtime"
        );
        return;
    }
    let (max_handle_bytes, max_ordered_nfa_scratch_bytes, max_ordered_nfa_setup_work) =
        if linked::REQUIRED_PREPARE_CAPABILITIES == 0 {
            (0, 0, 0)
        } else {
            (
                u64::try_from(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES)
                    .expect("default Ordered-NFA handle cap fits u64"),
                u64::try_from(FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES)
                    .expect("default Ordered-NFA scratch cap fits u64"),
                FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
            )
        };
    let boundary = if linked::UNIFORM_CAPTURE_BRIDGE
        && !linked::NATIVE_ROW_BRIDGE
        && !linked::REDUCER_SYMBOL.is_empty()
    {
        if linked::REQUIRED_RUNTIME_SYMBOLS.is_empty() {
            "single-call-native-uniform-capture-reducer"
        } else {
            "single-call-native-uniform-capture-helper-backed-reducer"
        }
    } else if linked::SHARED_ORDERED_MANY_AGGREGATE
        && linked::AGGREGATE_STRATEGY == "Some(NativeFused)"
    {
        "single-call-shared-ordered-many-helper-free-native-reducer"
    } else if linked::SHARED_ORDERED_MANY_AGGREGATE {
        "single-call-shared-ordered-many-helper-backed-reducer"
    } else {
        "runtime-klv-warmup-schedule"
    };
    println!(
        "schema=fre.aot.rebar-runner.v2 disposition=executed configured={} adapter={} model={} benchmark={:?} source_commit={} source_tree={} target={}-{} feature_bits={:016x} compiler_version={} optimizer_version={} engine={} aggregate_strategy={} prepared_bulk_strategy={} span_iteration_strategy={} grep_iteration_strategy={} shared_ordered_many={} source_pattern_count={} ordered_many_receipt_schema={} ordered_many_sources_sha256={} prepare_config_version={} prepare_operation_flags={:016x} required_prepare_capabilities={:016x} prepare_scope=runtime-handle-state object_descriptor_setup=authenticated-v3-when-required max_start_filter_setup_work={} max_grep_count_workspace_bytes={} max_handle_bytes={} max_ordered_nfa_scratch_bytes={} max_ordered_nfa_setup_work={} program_sha256={} object_sha256={} program_symbol={} program_len={} entry_symbol={} reducer_symbol={} span_fill_symbol={} required_runtime_symbols={} boundary={} required_comparators=rust-regex-1.12.4,fre-current-runtime",
        linked::CONFIGURED,
        linked::ADAPTER,
        linked::EXPECTED_MODEL,
        linked::EXPECTED_NAME,
        linked::SOURCE_COMMIT,
        linked::SOURCE_TREE,
        linked::TARGET_ARCH,
        linked::TARGET_OS,
        linked::FEATURE_BITS,
        linked::COMPILER_VERSION,
        linked::OPTIMIZER_VERSION,
        linked::ENGINE,
        linked::AGGREGATE_STRATEGY,
        linked::PREPARED_BULK_STRATEGY,
        linked::SPAN_ITERATION_STRATEGY,
        linked::GREP_ITERATION_STRATEGY,
        linked::SHARED_ORDERED_MANY_AGGREGATE,
        linked::SOURCE_PATTERN_COUNT,
        linked::ORDERED_MANY_RECEIPT_SCHEMA,
        hex(&linked::ORDERED_MANY_SOURCES_SHA256),
        linked::PREPARE_CONFIG_VERSION,
        linked::PREPARE_OPERATION_FLAGS,
        linked::REQUIRED_PREPARE_CAPABILITIES,
        DEFAULT_START_FILTER_SETUP_WORK,
        DEFAULT_GREP_COUNT_WORKSPACE_BYTES,
        max_handle_bytes,
        max_ordered_nfa_scratch_bytes,
        max_ordered_nfa_setup_work,
        hex(&linked::PROGRAM_SHA256),
        hex(&linked::OBJECT_SHA256),
        linked::PROGRAM_SYMBOL,
        linked::PROGRAM_LEN,
        linked::ENTRY_SYMBOL,
        linked::REDUCER_SYMBOL,
        linked::SPAN_FILL_SYMBOL,
        linked::REQUIRED_RUNTIME_SYMBOLS,
        boundary,
    );
}

fn authenticate_benchmark(benchmark: &shared::Benchmark) -> Result<(), String> {
    let pattern_identity_is_valid = if linked::EXPECTED_MODEL == "regex-redux" {
        !linked::NATIVE_ROW_BRIDGE
            && linked::EXPECTED_PATTERN.is_empty()
            && linked::EXPECTED_PATTERNS.is_empty()
    } else if linked::NATIVE_ROW_BRIDGE || linked::SHARED_ORDERED_MANY_AGGREGATE {
        linked::EXPECTED_PATTERN.is_empty() && !linked::EXPECTED_PATTERNS.is_empty()
    } else {
        linked::EXPECTED_PATTERNS == [linked::EXPECTED_PATTERN]
    };
    if !pattern_identity_is_valid {
        return Err("linked single/multi pattern identity constants disagree".to_owned());
    }
    let expected_model = shared::Model::parse(linked::EXPECTED_MODEL)?;
    let expected = shared::Benchmark {
        name: linked::EXPECTED_NAME.to_owned(),
        model: expected_model,
        patterns: linked::EXPECTED_PATTERNS
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect(),
        case_insensitive: linked::EXPECTED_CASE_INSENSITIVE,
        unicode: linked::EXPECTED_UNICODE,
        haystack: Vec::new(),
        max_iters: 1,
        max_warmup_iters: 0,
        max_time: Duration::ZERO,
        max_warmup_time: Duration::ZERO,
    };
    if benchmark.same_compilation_identity(&expected) {
        Ok(())
    } else {
        Err("runtime KLV compilation identity differs from linked AOT artifact".to_owned())
    }
}

fn authenticate_linked_route(benchmark: &shared::Benchmark) -> Result<(), String> {
    let scalar_uniform_capture = linked::UNIFORM_CAPTURE_BRIDGE && !linked::NATIVE_ROW_BRIDGE;
    let native_uniform_capture = scalar_uniform_capture && !linked::REDUCER_SYMBOL.is_empty();
    let prepared_uniform_capture = scalar_uniform_capture && linked::REDUCER_SYMBOL.is_empty();
    if linked::SHARED_ORDERED_MANY_AGGREGATE
        != (linked::ORDERED_MANY_RECEIPT_SCHEMA == fre_aot_regex::ORDERED_MANY_AOT_RECEIPT_VERSION
            && linked::ORDERED_MANY_SOURCES_SHA256 != [0; 32])
    {
        return Err("shared ordered-many route disagrees with its source receipt".to_owned());
    }
    if !linked::SHARED_ORDERED_MANY_AGGREGATE
        && (linked::ORDERED_MANY_RECEIPT_SCHEMA != 0
            || linked::ORDERED_MANY_SOURCES_SHA256 != [0; 32])
    {
        return Err("non-shared route contains an ordered-many source receipt".to_owned());
    }
    if linked::SHARED_ORDERED_MANY_AGGREGATE
        && (linked::NATIVE_ROW_BRIDGE
            || linked::UNIFORM_CAPTURE_BRIDGE
            || linked::STRICT_CAPTURE_BRIDGE
            || linked::PARTICIPATION_CAPTURE_BRIDGE
            || linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE)
    {
        return Err("shared ordered-many route overlaps another adapter route".to_owned());
    }
    if (linked::STRICT_CAPTURE_BRIDGE
        || linked::PARTICIPATION_CAPTURE_BRIDGE
        || linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE)
        && !linked::NATIVE_ROW_BRIDGE
    {
        return Err("capture receipt is not attached to a native operation route".to_owned());
    }
    if usize::from(linked::UNIFORM_CAPTURE_BRIDGE)
        + usize::from(linked::STRICT_CAPTURE_BRIDGE)
        + usize::from(linked::PARTICIPATION_CAPTURE_BRIDGE)
        + usize::from(linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE)
        > 1
    {
        return Err("linked capture routes are not mutually exclusive".to_owned());
    }
    if benchmark.model.is_capture()
        != (linked::UNIFORM_CAPTURE_BRIDGE
            || linked::STRICT_CAPTURE_BRIDGE
            || linked::PARTICIPATION_CAPTURE_BRIDGE
            || linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE)
    {
        return Err("capture operation and linked native route disagree".to_owned());
    }
    if benchmark.model == shared::Model::RegexRedux {
        let reducer_identity = native_symbol_identity(
            linked::REDUCER_SYMBOL,
            "fre_aot_regex_rebar_regex_redux_v1_",
        );
        let operation_identity = hex(&linked::REGEX_REDUX_OPERATION_IDENTITY_SHA256);
        let expected_relocations = match linked::TARGET_ARCH {
            "x86_64" => shared::REGEX_REDUX_COMPONENTS.saturating_add(1),
            "aarch64" => shared::REGEX_REDUX_COMPONENTS.saturating_add(2),
            _ => 0,
        };
        if linked::REGEX_REDUX_COMPONENT_COUNT != shared::REGEX_REDUX_COMPONENTS
            || linked::REGEX_REDUX_ENTRY_SYMBOLS.len() != shared::REGEX_REDUX_COMPONENTS
            || linked::REGEX_REDUX_RUNTIME_SYMBOLS.len() != shared::REGEX_REDUX_COMPONENTS
            || linked::REGEX_REDUX_NATIVE.len() != shared::REGEX_REDUX_COMPONENTS
            || linked::REGEX_REDUX_PROGRAM_SHA256.len() != shared::REGEX_REDUX_COMPONENTS
            || linked::REGEX_REDUX_OBJECT_SHA256.len() != shared::REGEX_REDUX_COMPONENTS
            || linked::REGEX_REDUX_ENTRY_SYMBOLS
                .iter()
                .any(|symbol| symbol.is_empty())
            || linked::REGEX_REDUX_RUNTIME_SYMBOLS
                .iter()
                .any(|symbols| !symbols.is_empty())
            || linked::REGEX_REDUX_NATIVE.iter().any(|native| !native)
            || linked::REGEX_REDUX_PROGRAM_SHA256
                .iter()
                .any(|digest| *digest == [0; 32])
            || linked::REGEX_REDUX_OBJECT_SHA256
                .iter()
                .any(|digest| *digest == [0; 32])
            || linked::REGEX_REDUX_REDUCER_LINK_SYMBOLS != linked::REGEX_REDUX_ENTRY_SYMBOLS
            || !linked::REGEX_REDUX_SEMANTIC_RUNTIME_SYMBOLS.is_empty()
            || linked::REGEX_REDUX_OPERATION_IDENTITY_SHA256 == [0; 32]
            || linked::REGEX_REDUX_REDUCER_CODE_SHA256 == [0; 32]
            || linked::REGEX_REDUX_REDUCER_DATA_SHA256 == [0; 32]
            || linked::REGEX_REDUX_REDUCER_OBJECT_SHA256 == [0; 32]
            || linked::REGEX_REDUX_REDUCER_OBJECT_SHA256 != linked::OBJECT_SHA256
            || linked::REGEX_REDUX_REDUCER_RELOCATION_COUNT != expected_relocations
            || linked::REGEX_REDUX_ABI_VERSION
                != fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_ABI_VERSION
            || linked::REGEX_REDUX_REQUEST_BYTES
                != fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_REQUEST_BYTES
            || linked::REGEX_REDUX_REQUEST_BYTES != std::mem::size_of::<NativeRegexReduxRequestV1>()
            || linked::REGEX_REDUX_RECEIPT_BYTES
                != fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_RECEIPT_BYTES
            || linked::REGEX_REDUX_RECEIPT_BYTES
                != std::mem::size_of::<NativeRegexReduxRunReceiptV1>()
            || linked::REGEX_REDUX_REPORT_BYTES
                != fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_REPORT_BYTES
            || linked::REGEX_REDUX_SCRATCH_BUFFER_COUNT != 2
            || linked::REGEX_REDUX_SCRATCH_CAPACITY_NUMERATOR != 3
            || linked::REGEX_REDUX_SCRATCH_CAPACITY_DENOMINATOR != 2
            || linked::REGEX_REDUX_RECEIPT_SCHEMA
                != "u64-input-clean-variant9-substitution5-final-report-v1"
            || linked::REGEX_REDUX_REPORT_SCHEMA != "variant9-blank-input-clean-final-lines-v1"
            || reducer_identity != Some(operation_identity.as_str())
            || linked::PREPARE_OPERATION_FLAGS != 0
            || linked::REQUIRED_PREPARE_CAPABILITIES != 0
            || linked::HAS_SPAN_FILL
            || linked::PROGRAM_LEN != 0
            || !linked::PROGRAM_SYMBOL.is_empty()
            || !linked::ENTRY_SYMBOL.is_empty()
            || !linked::SPAN_FILL_SYMBOL.is_empty()
            || linked::OBJECT_BYTES.is_empty()
            || linked::ENGINE != "NativeRegexReduxAotV1"
            || linked::SPAN_ITERATION_STRATEGY != "not-applicable"
            || linked::GREP_ITERATION_STRATEGY != "not-applicable"
            || linked::PREPARED_BULK_STRATEGY != "None"
            || !linked::REQUIRED_RUNTIME_SYMBOLS.is_empty()
            || linked::AGGREGATE_STRATEGY != "native-fixed-regex-redux-whole-operation-v1"
        {
            return Err("regex-redux linked whole-operation closure is inconsistent".to_owned());
        }
        if linked::REGEX_REDUX_ENTRY_SYMBOLS
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != shared::REGEX_REDUX_COMPONENTS
            || linked::REGEX_REDUX_PROGRAM_SHA256
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != shared::REGEX_REDUX_COMPONENTS
            || linked::REGEX_REDUX_OBJECT_SHA256
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != shared::REGEX_REDUX_COMPONENTS
        {
            return Err("regex-redux linked component identities are not unique".to_owned());
        }
        return Ok(());
    }
    if linked::REGEX_REDUX_COMPONENT_COUNT != 0
        || !linked::REGEX_REDUX_ENTRY_SYMBOLS.is_empty()
        || !linked::REGEX_REDUX_RUNTIME_SYMBOLS.is_empty()
        || !linked::REGEX_REDUX_NATIVE.is_empty()
        || !linked::REGEX_REDUX_PROGRAM_SHA256.is_empty()
        || !linked::REGEX_REDUX_OBJECT_SHA256.is_empty()
        || linked::REGEX_REDUX_OPERATION_IDENTITY_SHA256 != [0; 32]
        || linked::REGEX_REDUX_REDUCER_CODE_SHA256 != [0; 32]
        || linked::REGEX_REDUX_REDUCER_DATA_SHA256 != [0; 32]
        || linked::REGEX_REDUX_REDUCER_OBJECT_SHA256 != [0; 32]
        || linked::REGEX_REDUX_REDUCER_RELOCATION_COUNT != 0
        || linked::REGEX_REDUX_ABI_VERSION != 0
        || linked::REGEX_REDUX_REQUEST_BYTES != 0
        || linked::REGEX_REDUX_RECEIPT_BYTES != 0
        || linked::REGEX_REDUX_REPORT_BYTES != 0
        || linked::REGEX_REDUX_SCRATCH_BUFFER_COUNT != 0
        || linked::REGEX_REDUX_SCRATCH_CAPACITY_NUMERATOR != 0
        || linked::REGEX_REDUX_SCRATCH_CAPACITY_DENOMINATOR != 0
        || !linked::REGEX_REDUX_RECEIPT_SCHEMA.is_empty()
        || !linked::REGEX_REDUX_REPORT_SCHEMA.is_empty()
        || !linked::REGEX_REDUX_REDUCER_LINK_SYMBOLS.is_empty()
        || !linked::REGEX_REDUX_SEMANTIC_RUNTIME_SYMBOLS.is_empty()
    {
        return Err("scalar artifact unexpectedly contains regex-redux components".to_owned());
    }
    if linked::NATIVE_ROW_BRIDGE {
        return authenticate_native_row_route(benchmark);
    }
    if linked::SHARED_ORDERED_MANY_AGGREGATE {
        authenticate_linked_shared_ordered_many(benchmark)?;
    } else if benchmark.uses_native_row_bridge() {
        return Err("multi-pattern KLV is not bound to a native-row bridge".to_owned());
    }
    let has_named_span_fill = !linked::SPAN_FILL_SYMBOL.is_empty();
    if linked::HAS_SPAN_FILL != has_named_span_fill {
        return Err("linked Span-fill availability disagrees with its bound symbol".to_owned());
    }
    let native_scalar_reducer = authenticate_linked_native_scalar_reducer(benchmark.model)?;
    if native_uniform_capture {
        let reducer_prefix = match benchmark.model {
            shared::Model::CountCaptures => "fre_aot_regex_count_captures_exclusive_v1_",
            shared::Model::GrepCaptures => "fre_aot_regex_grep_captures_exclusive_v1_",
            _ => return Err("native uniform-capture reducer has a non-capture model".to_owned()),
        };
        let expected_adapter = match benchmark.model {
            shared::Model::CountCaptures => "general-aot-native-uniform-capture-count-reducer-v1",
            shared::Model::GrepCaptures => "general-aot-native-uniform-capture-grep-reducer-v1",
            _ => unreachable!("capture model was checked above"),
        };
        let expected_grep = if benchmark.model == shared::Model::GrepCaptures {
            "linked-native-uniform-capture-reducer-v1"
        } else {
            "not-applicable"
        };
        native_symbol_identity(linked::ENTRY_SYMBOL, "fre_aot_regex_search_v1_")
            .ok_or_else(|| "native uniform-capture selector symbol is not canonical".to_owned())?;
        native_symbol_identity(linked::PROGRAM_SYMBOL, "fre_aot_regex_runtime_program_v1_")
            .ok_or_else(|| "native uniform-capture program symbol is not canonical".to_owned())?;
        native_symbol_identity(linked::REDUCER_SYMBOL, reducer_prefix)
            .ok_or_else(|| "native uniform-capture reducer symbol is not canonical".to_owned())?;
        let ordered = linked::AGGREGATE_STRATEGY == "Some(NativeOrderedNfaFused)";
        let direct = linked::AGGREGATE_STRATEGY == "Some(NativeFused)";
        let ordered_span_fill_is_canonical = ordered
            && native_symbol_identity(
                linked::SPAN_FILL_SYMBOL,
                "fre_aot_regex_fill_spans_exclusive_v1_",
            )
            .is_some();
        let runtime_symbols = linked::REQUIRED_RUNTIME_SYMBOLS
            .split(',')
            .filter(|symbol| !symbol.is_empty())
            .collect::<std::collections::BTreeSet<_>>();
        let expected_ordered_symbols = [
            "fre_aot_regex_runtime_compiler_private_count_exclusive_v1",
            "fre_aot_regex_runtime_fill_spans_exclusive_v1",
            "fre_aot_regex_runtime_search_exclusive_v1",
            "fre_aot_regex_runtime_search_v1",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        if benchmark.patterns.len() != 1
            || linked::ADAPTER != expected_adapter
            || linked::NATIVE_SCALAR_REDUCER
            || linked::SHARED_ORDERED_MANY_AGGREGATE
            || linked::PREPARE_OPERATION_FLAGS != shared::Model::Count.prepare_operation_flags()
            || linked::SPAN_ITERATION_STRATEGY != "not-applicable"
            || linked::GREP_ITERATION_STRATEGY != expected_grep
            || linked::ROW_ARTIFACT_COUNT != 1
            || linked::SOURCE_PATTERN_COUNT != 1
            || linked::SOURCE_TO_ARTIFACT != [0]
            || linked::ROW_FIRST_SOURCE_ORDINALS != [0]
            || linked::ROW_ENTRY_SYMBOLS != [linked::ENTRY_SYMBOL]
            || linked::ROW_PROGRAM_SHA256 != [linked::PROGRAM_SHA256]
            || linked::ROW_OBJECT_SHA256 != [linked::OBJECT_SHA256]
            || linked::PROGRAM_LEN == 0
            || linked::PROGRAM_SHA256 == [0; 32]
            || linked::OBJECT_SHA256 == [0; 32]
            || linked::OBJECT_BYTES.is_empty()
            || linked::ROW_PARTICIPATING_GROUPS.len() != 1
            || linked::SOURCE_PARTICIPATING_GROUPS.len() != 1
            || linked::ROW_PARTICIPATING_GROUPS != linked::SOURCE_PARTICIPATING_GROUPS
            || linked::SOURCE_PARTICIPATING_GROUPS.contains(&0)
            || linked::SOURCE_MINIMUM_MATCH_BYTES.len() != 1
            || linked::SOURCE_MINIMUM_MATCH_BYTES.contains(&0)
            || linked::SOURCE_CANONICAL_CAPTURE_ANNOTATIONS.len() != 1
            || linked::SOURCE_PROOF_WORK.len() != 1
            || linked::SOURCE_PROOF_PEAK_STACK_ITEMS.len() != 1
            || linked::SOURCE_SELECTOR_AUTOMATON_SHA256 != linked::ROW_AUTOMATON_SHA256
            || linked::SOURCE_SELECTOR_PROGRAM_SHA256 != [linked::PROGRAM_SHA256]
            || linked::SOURCE_SELECTOR_OBJECT_SHA256 != [linked::OBJECT_SHA256]
            || linked::UNIFORM_CAPTURE_ALGORITHM_VERSION
                != fre_lower::UNIFORM_CAPTURE_PARTICIPATION_ALGORITHM_VERSION
            || linked::UNIFORM_CAPTURE_ACCOUNTING_VERSION
                != fre_lower::UNIFORM_CAPTURE_PARTICIPATION_ACCOUNTING_VERSION
            || linked::REDUCER_SYMBOL == linked::ENTRY_SYMBOL
            || linked::REDUCER_SYMBOL == linked::PROGRAM_SYMBOL
            || (direct
                && (linked::REQUIRED_PREPARE_CAPABILITIES != 0
                    || linked::PREPARE_CONFIG_VERSION != PREPARE_CONFIG_V2_VERSION
                    || linked::PREPARED_BULK_STRATEGY != "None"
                    || linked::HAS_SPAN_FILL
                    || !linked::SPAN_FILL_SYMBOL.is_empty()
                    || !runtime_symbols.is_empty()))
            || (ordered
                && (linked::REQUIRED_PREPARE_CAPABILITIES != PREPARE_CAPABILITY_ORDERED_NFA_V15
                    || linked::PREPARE_CONFIG_VERSION != PREPARE_CONFIG_V3_VERSION
                    || linked::ENGINE != "OrderedNfa"
                    || linked::PREPARED_BULK_STRATEGY != "Some(NativeOrderedNfaLoop)"
                    || !linked::HAS_SPAN_FILL
                    || !ordered_span_fill_is_canonical
                    || runtime_symbols != expected_ordered_symbols))
            || !(direct || ordered)
        {
            return Err(
                "native uniform-capture reducer identity closure is inconsistent".to_owned(),
            );
        }
    } else if prepared_uniform_capture {
        if benchmark.patterns.len() != 1
            || !benchmark.model.is_capture()
            || linked::STRICT_CAPTURE_BRIDGE
            || !linked::HAS_SPAN_FILL
            || linked::REDUCER_SYMBOL != ""
            || linked::PREPARE_OPERATION_FLAGS != shared::Model::Count.prepare_operation_flags()
            || linked::AGGREGATE_STRATEGY
                != "prepared-span-fill-static-uniform-capture-multiplier-v1"
            || linked::SPAN_ITERATION_STRATEGY
                != "linked-prepared-span-fill-uniform-capture-64::Some(NativeOrderedNfaLoop)"
            || linked::PREPARED_BULK_STRATEGY != "Some(NativeOrderedNfaLoop)"
            || linked::ENGINE != "OrderedNfa"
            || linked::ROW_ARTIFACT_COUNT != 1
            || linked::SOURCE_PATTERN_COUNT != 1
            || linked::ROW_AUTOMATON_SHA256.len() != 1
            || linked::ROW_PROGRAM_SHA256.len() != 1
            || linked::ROW_OBJECT_SHA256.len() != 1
            || linked::SOURCE_TO_ARTIFACT != [0]
            || linked::ROW_FIRST_SOURCE_ORDINALS != [0]
            || linked::ROW_PARTICIPATING_GROUPS.len() != 1
            || linked::SOURCE_PARTICIPATING_GROUPS.len() != 1
            || linked::ROW_PARTICIPATING_GROUPS != linked::SOURCE_PARTICIPATING_GROUPS
            || linked::SOURCE_PARTICIPATING_GROUPS.contains(&0)
            || linked::SOURCE_MINIMUM_MATCH_BYTES.len() != 1
            || linked::SOURCE_MINIMUM_MATCH_BYTES.contains(&0)
            || linked::SOURCE_CANONICAL_CAPTURE_ANNOTATIONS.len() != 1
            || linked::SOURCE_PROOF_WORK.len() != 1
            || linked::SOURCE_PROOF_PEAK_STACK_ITEMS.len() != 1
            || linked::SOURCE_SELECTOR_AUTOMATON_SHA256 != linked::ROW_AUTOMATON_SHA256
            || linked::SOURCE_SELECTOR_PROGRAM_SHA256 != [linked::PROGRAM_SHA256]
            || linked::SOURCE_SELECTOR_OBJECT_SHA256 != [linked::OBJECT_SHA256]
            || linked::UNIFORM_CAPTURE_ALGORITHM_VERSION
                != fre_lower::UNIFORM_CAPTURE_PARTICIPATION_ALGORITHM_VERSION
            || linked::UNIFORM_CAPTURE_ACCOUNTING_VERSION
                != fre_lower::UNIFORM_CAPTURE_PARTICIPATION_ACCOUNTING_VERSION
            || linked::REQUIRED_RUNTIME_SYMBOLS
                != "fre_aot_regex_runtime_search_v1,fre_aot_regex_runtime_search_exclusive_v1,fre_aot_regex_runtime_fill_spans_exclusive_v1"
        {
            return Err("prepared uniform-capture identity closure is inconsistent".to_owned());
        }
        let expected_grep = if benchmark.model == shared::Model::GrepCaptures {
            "per-line-linked-prepared-span-fill-uniform-capture-v1"
        } else {
            "not-applicable"
        };
        if linked::GREP_ITERATION_STRATEGY != expected_grep {
            return Err("prepared uniform-capture grep domain is inconsistent".to_owned());
        }
    } else if benchmark.model == shared::Model::SpanSum {
        let bulk_route = linked::PREPARED_BULK_STRATEGY != "None";
        if linked::HAS_SPAN_FILL != bulk_route {
            return Err(format!(
                "linked count-spans route disagrees with prepared bulk strategy {:?}",
                linked::PREPARED_BULK_STRATEGY
            ));
        }
        if linked::AGGREGATE_STRATEGY == "None" {
            return Err("count-spans artifact has no aggregate strategy".to_owned());
        }
        let iteration_is_exact = if native_scalar_reducer {
            linked::SPAN_ITERATION_STRATEGY == "linked-native-span-sum-reducer"
        } else if linked::HAS_SPAN_FILL {
            linked_span_fill_iteration_is_exact(
                linked::PREPARED_BULK_STRATEGY,
                linked::SPAN_ITERATION_STRATEGY,
            )
        } else {
            linked::SPAN_ITERATION_STRATEGY == "linked-direct-entry-loop"
        };
        if !iteration_is_exact {
            return Err(
                "count-spans execution boundary disagrees with its native reducer receipt"
                    .to_owned(),
            );
        }
    } else if linked::SPAN_ITERATION_STRATEGY != "not-applicable" {
        return Err("non-count-spans artifact advertises a span iterator route".to_owned());
    }
    if benchmark.model == shared::Model::Count && linked::AGGREGATE_STRATEGY == "None" {
        return Err("count artifact has no aggregate strategy".to_owned());
    }
    if scalar_uniform_capture {
        // The exact per-line or whole-domain route was authenticated above.
    } else if benchmark.model == shared::Model::GrepCount {
        let direct = authenticate_linked_direct_native_grep();
        let prepared = authenticate_linked_prepared_v15_grep();
        if !direct && !prepared {
            return Err("grep artifact is not bound to an authenticated grep route".to_owned());
        }
    } else if linked::GREP_ITERATION_STRATEGY != "not-applicable" {
        return Err("non-grep artifact advertises a grep iterator route".to_owned());
    }
    let ordered_nfa_route = linked::PREPARED_BULK_STRATEGY == "Some(NativeOrderedNfaLoop)";
    let ordered_nfa_required =
        linked::REQUIRED_PREPARE_CAPABILITIES == PREPARE_CAPABILITY_ORDERED_NFA_V15;
    if linked::REQUIRED_PREPARE_CAPABILITIES & !PREPARE_CAPABILITY_KNOWN_FLAGS != 0
        || ordered_nfa_route != ordered_nfa_required
    {
        return Err(
            "linked Ordered-TNFA route disagrees with its required prepare capability".to_owned(),
        );
    }
    let expected_prepare_version = if ordered_nfa_required {
        PREPARE_CONFIG_V3_VERSION
    } else {
        PREPARE_CONFIG_V2_VERSION
    };
    if linked::PREPARE_CONFIG_VERSION != expected_prepare_version {
        return Err("linked prepare version disagrees with its capability receipt".to_owned());
    }
    if ordered_nfa_required
        && !matches!(
            benchmark.model,
            shared::Model::Count
                | shared::Model::SpanSum
                | shared::Model::GrepCount
                | shared::Model::CountCaptures
                | shared::Model::GrepCaptures
        )
    {
        return Err("Ordered-TNFA capability is bound to an unsupported operation".to_owned());
    }
    if ordered_nfa_required && !prepared_uniform_capture {
        let native_aggregate = matches!(
            linked::AGGREGATE_STRATEGY,
            "Some(NativeOrderedNfaFused)" | "Some(NativeOrderedNfaFusedWithRuntimeHelper)"
        );
        if !native_aggregate {
            return Err("Ordered-TNFA capability has no native operation route".to_owned());
        }
    }
    Ok(())
}

fn authenticate_linked_direct_native_grep() -> bool {
    let Some(entry_identity) =
        native_symbol_identity(linked::ENTRY_SYMBOL, "fre_aot_regex_search_v1_")
    else {
        return false;
    };
    let Some(program_identity) =
        native_symbol_identity(linked::PROGRAM_SYMBOL, "fre_aot_regex_runtime_program_v1_")
    else {
        return false;
    };
    let Some(reducer_identity) = native_symbol_identity(
        linked::REDUCER_SYMBOL,
        "fre_aot_regex_grep_count_exclusive_v1_",
    ) else {
        return false;
    };
    linked::ADAPTER == "general-aot-linked-native-grep-count-reducer-prepared-v2"
        && linked::AGGREGATE_STRATEGY == "Some(NativeFused)"
        && linked::GREP_ITERATION_STRATEGY == "linked-native-grep-count-reducer-v1"
        && linked::SPAN_ITERATION_STRATEGY == "not-applicable"
        && linked::PREPARED_BULK_STRATEGY == "None"
        && !linked::HAS_SPAN_FILL
        && linked::SPAN_FILL_SYMBOL.is_empty()
        && linked::PREPARE_CONFIG_VERSION == PREPARE_CONFIG_V2_VERSION
        && linked::PREPARE_OPERATION_FLAGS == shared::Model::GrepCount.prepare_operation_flags()
        && linked::REQUIRED_PREPARE_CAPABILITIES == 0
        && linked::PROGRAM_LEN != 0
        && linked::PROGRAM_SHA256 != [0; 32]
        && linked::OBJECT_SHA256 != [0; 32]
        && linked::REQUIRED_RUNTIME_SYMBOLS.is_empty()
        && reducer_identity == program_identity
        && reducer_identity != entry_identity
}

fn authenticate_linked_prepared_v15_grep() -> bool {
    const EXPECTED_RUNTIME_SYMBOLS: &str = "fre_aot_regex_runtime_search_v1,fre_aot_regex_runtime_search_exclusive_v1,fre_aot_regex_runtime_fill_spans_exclusive_v1";
    let Some(entry_identity) =
        native_symbol_identity(linked::ENTRY_SYMBOL, "fre_aot_regex_search_v1_")
    else {
        return false;
    };
    let Some(span_fill_identity) = native_symbol_identity(
        linked::SPAN_FILL_SYMBOL,
        "fre_aot_regex_fill_spans_exclusive_v1_",
    ) else {
        return false;
    };
    let Some(program_identity) =
        native_symbol_identity(linked::PROGRAM_SYMBOL, "fre_aot_regex_runtime_program_v1_")
    else {
        return false;
    };
    let Some(reducer_identity) = native_symbol_identity(
        linked::REDUCER_SYMBOL,
        "fre_aot_regex_grep_count_exclusive_v1_",
    ) else {
        return false;
    };
    linked::ADAPTER
        == "general-aot-linked-native-grep-count-reducer-prepared-v3-required-ordered-nfa-v15"
        && linked::ENGINE == "OrderedNfa"
        && linked::AGGREGATE_STRATEGY == "Some(NativeOrderedNfaFused)"
        && linked::GREP_ITERATION_STRATEGY == "linked-native-grep-count-reducer-v1"
        && linked::SPAN_ITERATION_STRATEGY == "not-applicable"
        && linked::PREPARED_BULK_STRATEGY == "Some(NativeOrderedNfaLoop)"
        && linked::HAS_SPAN_FILL
        && linked::PREPARE_CONFIG_VERSION == PREPARE_CONFIG_V3_VERSION
        && linked::PREPARE_OPERATION_FLAGS == shared::Model::Count.prepare_operation_flags()
        && linked::REQUIRED_PREPARE_CAPABILITIES == PREPARE_CAPABILITY_ORDERED_NFA_V15
        && linked::PROGRAM_LEN != 0
        && linked::PROGRAM_SHA256 != [0; 32]
        && linked::OBJECT_SHA256 != [0; 32]
        && linked::REQUIRED_RUNTIME_SYMBOLS == EXPECTED_RUNTIME_SYMBOLS
        && entry_identity == span_fill_identity
        && entry_identity == program_identity
        && reducer_identity != entry_identity
}

fn authenticate_linked_shared_ordered_many(benchmark: &shared::Benchmark) -> Result<(), String> {
    const COUNT_RUNTIME_SYMBOLS: &str = "fre_aot_regex_runtime_search_v1,fre_aot_regex_runtime_search_exclusive_v1,fre_aot_regex_runtime_fill_spans_exclusive_v1,fre_aot_regex_runtime_compiler_private_count_exclusive_v1";
    const SPAN_SUM_RUNTIME_SYMBOLS: &str = "fre_aot_regex_runtime_search_v1,fre_aot_regex_runtime_search_exclusive_v1,fre_aot_regex_runtime_fill_spans_exclusive_v1,fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1";
    let (adapter, reducer_prefix, v15_runtime_symbols, span_iteration) = match benchmark.model {
        shared::Model::Count => (
            "general-aot-shared-ordered-many-native-count-v1",
            "fre_aot_regex_count_exclusive_v1_",
            COUNT_RUNTIME_SYMBOLS,
            "not-applicable",
        ),
        shared::Model::SpanSum => (
            "general-aot-shared-ordered-many-native-span-sum-v1",
            "fre_aot_regex_span_sum_exclusive_v1_",
            SPAN_SUM_RUNTIME_SYMBOLS,
            "linked-shared-ordered-many-native-span-sum-reducer-v1",
        ),
        _ => {
            return Err(
                "shared ordered-many artifact is bound to a non-Count/SpanSum model".to_owned(),
            );
        }
    };
    let sources = benchmark.patterns.len();
    let valid_source_map = linked::SOURCE_TO_ARTIFACT.len() == sources
        && linked::SOURCE_TO_ARTIFACT
            .iter()
            .all(|&artifact| artifact == 0);
    let entry_identity = native_symbol_identity(linked::ENTRY_SYMBOL, "fre_aot_regex_search_v1_");
    let prepared_identity = native_symbol_identity(
        linked::SPAN_FILL_SYMBOL,
        "fre_aot_regex_fill_spans_exclusive_v1_",
    );
    let program_identity =
        native_symbol_identity(linked::PROGRAM_SYMBOL, "fre_aot_regex_runtime_program_v1_");
    let reducer_identity = native_symbol_identity(linked::REDUCER_SYMBOL, reducer_prefix);
    let native_fused_bulk_shape = match linked::PREPARED_BULK_STRATEGY {
        "None" => !linked::HAS_SPAN_FILL && linked::SPAN_FILL_SYMBOL.is_empty(),
        "Some(NativePreparedLoop)" | "Some(NativeFrozenLoop)" => {
            linked::HAS_SPAN_FILL
                && entry_identity.is_some()
                && entry_identity == prepared_identity
                && entry_identity == program_identity
        }
        _ => false,
    };
    let helper_free_native_fused = linked::AGGREGATE_STRATEGY == "Some(NativeFused)"
        && linked::PREPARE_CONFIG_VERSION == PREPARE_CONFIG_V2_VERSION
        && linked::REQUIRED_PREPARE_CAPABILITIES == 0
        && linked::REQUIRED_RUNTIME_SYMBOLS.is_empty()
        && native_fused_bulk_shape;
    let prepared_v15 = linked::ENGINE == "OrderedNfa"
        && linked::AGGREGATE_STRATEGY == "Some(NativeOrderedNfaFused)"
        && linked::PREPARED_BULK_STRATEGY == "Some(NativeOrderedNfaLoop)"
        && linked::PREPARE_CONFIG_VERSION == PREPARE_CONFIG_V3_VERSION
        && linked::REQUIRED_PREPARE_CAPABILITIES == PREPARE_CAPABILITY_ORDERED_NFA_V15
        && linked::HAS_SPAN_FILL
        && linked::REQUIRED_RUNTIME_SYMBOLS == v15_runtime_symbols
        && entry_identity.is_some()
        && entry_identity == prepared_identity
        && entry_identity == program_identity
        && entry_identity != reducer_identity;
    if sources < 2
        || sources > fre_aot_regex::ORDERED_MANY_AOT_MAX_ROWS
        || linked::NATIVE_ROW_BRIDGE
        || linked::EXPECTED_PATTERN != ""
        || linked::SOURCE_PATTERN_COUNT != sources
        || !valid_source_map
        || linked::ROW_ARTIFACT_COUNT != 1
        || linked::ROW_FIRST_SOURCE_ORDINALS != [0]
        || linked::ROW_ENTRY_SYMBOLS != [linked::ENTRY_SYMBOL]
        || linked::ROW_AUTOMATON_SHA256.len() != 1
        || linked::ROW_AUTOMATON_SHA256[0] == [0; 32]
        || linked::ROW_PROGRAM_SHA256 != [linked::PROGRAM_SHA256]
        || linked::ROW_OBJECT_SHA256 != [linked::OBJECT_SHA256]
        || linked::ROW_TOTAL_OBJECT_BYTES != linked::OBJECT_BYTES.len()
        || linked::OBJECT_BYTES.is_empty()
        || linked::PROGRAM_LEN == 0
        || linked::PROGRAM_SHA256 == [0; 32]
        || linked::OBJECT_SHA256 == [0; 32]
        || linked::ADAPTER != adapter
        || linked::PREPARE_OPERATION_FLAGS != benchmark.model.prepare_operation_flags()
        || linked::SPAN_ITERATION_STRATEGY != span_iteration
        || linked::GREP_ITERATION_STRATEGY != "not-applicable"
        || reducer_identity.is_none()
        || entry_identity.is_none()
        || program_identity.is_none()
        || (!helper_free_native_fused && !prepared_v15)
        || linked::ROW_REQUIRED_PREPARE_CAPABILITIES != [0]
        || linked::ROW_PREPARE_CONFIG_VERSIONS != [0]
        || linked::ROW_PREPARE_OPERATION_FLAGS != [0]
        || linked::ROW_PROGRAM_SYMBOLS != [""]
        || linked::ROW_PROGRAM_LENS != [0]
        || linked::ROW_SPAN_FILL_SYMBOLS != [""]
        || linked::ROW_PREPARED_BULK_STRATEGIES != ["None"]
        || linked::ROW_REQUIRED_RUNTIME_SYMBOLS != [""]
    {
        return Err("shared ordered-many linked identity closure is inconsistent".to_owned());
    }
    Ok(())
}

fn authenticate_native_row_route(benchmark: &shared::Benchmark) -> Result<(), String> {
    const ROW_STRATEGY: &str = "native-independent-span-row-selector-v1";
    const MIXED_ROW_STRATEGY: &str = "native-independent-span-row-selector-mixed-prepared-v15-v1";
    const CAPTURE_STRATEGY: &str = "native-row-static-uniform-capture-multiplier-v1";
    const PARTICIPATION_STRATEGY: &str = "native-exact-span-participation-dfa-v1";
    const GREP_PARTICIPATION_STRATEGY: &str = "per-line-native-exact-span-participation-dfa-v1";
    const GREP_CAPTURE_STRATEGY: &str = "per-line-native-row-static-uniform-capture-v1";
    const GREP_ROW_STRATEGY: &str = "per-line-native-independent-span-row-exists-v1";
    const MIXED_GREP_ROW_STRATEGY: &str =
        "per-line-native-independent-span-row-exists-mixed-prepared-v15-v1";
    const SELECTOR_FALLBACK_STRATEGY: &str =
        "native-selector-negative-certificate-with-stock-positive-capture-fallback-v1";
    const GREP_SELECTOR_FALLBACK_STRATEGY: &str =
        "per-line-native-selector-negative-certificate-stock-positive-capture-fallback-v1";
    if linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE {
        if benchmark.model != shared::Model::GrepCaptures
            || benchmark.patterns.len() != 1
            || linked::UNIFORM_CAPTURE_BRIDGE
            || linked::STRICT_CAPTURE_BRIDGE
            || linked::PARTICIPATION_CAPTURE_BRIDGE
        {
            return Err(
                "linked selector-first capture route has the wrong operation shape".to_owned(),
            );
        }
    } else if linked::PARTICIPATION_CAPTURE_BRIDGE {
        if !benchmark.model.is_capture()
            || benchmark.patterns.len() != 1
            || linked::UNIFORM_CAPTURE_BRIDGE
            || linked::STRICT_CAPTURE_BRIDGE
        {
            return Err(
                "linked participation capture route has the wrong operation shape".to_owned(),
            );
        }
    } else if linked::STRICT_CAPTURE_BRIDGE {
        if !benchmark.model.is_capture()
            || benchmark.patterns.len() != 1
            || linked::UNIFORM_CAPTURE_BRIDGE
        {
            return Err("linked strict capture route has the wrong operation shape".to_owned());
        }
    } else if linked::UNIFORM_CAPTURE_BRIDGE != benchmark.uses_uniform_capture_bridge()
        || (!linked::UNIFORM_CAPTURE_BRIDGE && !benchmark.uses_native_row_bridge())
    {
        return Err("linked native-row table is bound to an invalid benchmark model".to_owned());
    }
    if linked::SOURCE_PATTERN_COUNT != benchmark.patterns.len()
        || linked::SOURCE_TO_ARTIFACT.len() != linked::SOURCE_PATTERN_COUNT
        || linked::ROW_ARTIFACT_COUNT == 0
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_FIRST_SOURCE_ORDINALS.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_ENTRY_SYMBOLS.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_REQUIRED_PREPARE_CAPABILITIES.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_PREPARE_CONFIG_VERSIONS.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_PREPARE_OPERATION_FLAGS.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_PROGRAM_SYMBOLS.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_PROGRAM_LENS.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_SPAN_FILL_SYMBOLS.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_PREPARED_BULK_STRATEGIES.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_REQUIRED_RUNTIME_SYMBOLS.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_AUTOMATON_SHA256.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_PROGRAM_SHA256.len()
        || linked::ROW_ARTIFACT_COUNT != linked::ROW_OBJECT_SHA256.len()
        || linked::ROW_AUTOMATON_SHA256
            .iter()
            .any(|digest| *digest == [0; 32])
        || linked::ROW_PROGRAM_SHA256
            .iter()
            .any(|digest| *digest == [0; 32])
        || linked::ROW_OBJECT_SHA256
            .iter()
            .any(|digest| *digest == [0; 32])
    {
        return Err("linked native-row table has inconsistent cardinalities".to_owned());
    }
    if linked::ROW_TOTAL_OBJECT_BYTES > shared::MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES {
        return Err("linked native-row objects exceed the build-time byte cap".to_owned());
    }
    let has_prepared_v15 = linked::ROW_REQUIRED_PREPARE_CAPABILITIES
        .iter()
        .any(|&capabilities| capabilities != 0);
    let expected_caps = PrepareV3Caps::for_required_capabilities(if has_prepared_v15 {
        PREPARE_CAPABILITY_ORDERED_NFA_V15
    } else {
        0
    });
    if PrepareV3Caps::linked_rows() != expected_caps {
        return Err("linked native-row V3 cap receipt differs from the runtime config".to_owned());
    }
    if has_prepared_v15
        && (linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE
            || linked::PARTICIPATION_CAPTURE_BRIDGE
            || linked::UNIFORM_CAPTURE_BRIDGE
            || linked::STRICT_CAPTURE_BRIDGE)
    {
        return Err("capture rows cannot advertise a prepared V15 fallback".to_owned());
    }
    if linked::PREPARE_CONFIG_VERSION != 0
        || linked::PREPARE_OPERATION_FLAGS != 0
        || linked::REQUIRED_PREPARE_CAPABILITIES != 0
        || linked::HAS_SPAN_FILL
        || !linked::SPAN_FILL_SYMBOL.is_empty()
        || !linked::REDUCER_SYMBOL.is_empty()
        || !linked::PROGRAM_SYMBOL.is_empty()
        || linked::PROGRAM_LEN != 0
        || linked::PREPARED_BULK_STRATEGY != "None"
        || !linked::REQUIRED_RUNTIME_SYMBOLS.is_empty()
    {
        return Err("linked native-row table exposes a forbidden global prepared route".to_owned());
    }
    let expected_aggregate_strategy = if linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE {
        SELECTOR_FALLBACK_STRATEGY
    } else if linked::PARTICIPATION_CAPTURE_BRIDGE {
        PARTICIPATION_STRATEGY
    } else if linked::STRICT_CAPTURE_BRIDGE {
        "native-single-capture-next-participation-v1"
    } else if linked::UNIFORM_CAPTURE_BRIDGE {
        CAPTURE_STRATEGY
    } else if benchmark.model == shared::Model::GrepCount {
        if has_prepared_v15 {
            MIXED_GREP_ROW_STRATEGY
        } else {
            GREP_ROW_STRATEGY
        }
    } else if has_prepared_v15 {
        MIXED_ROW_STRATEGY
    } else {
        ROW_STRATEGY
    };
    let expected_span_strategy = if benchmark.model == shared::Model::SpanSum {
        if has_prepared_v15 {
            MIXED_ROW_STRATEGY
        } else {
            ROW_STRATEGY
        }
    } else {
        "not-applicable"
    };
    let expected_grep_strategy = if linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE {
        GREP_SELECTOR_FALLBACK_STRATEGY
    } else if linked::PARTICIPATION_CAPTURE_BRIDGE && benchmark.model == shared::Model::GrepCaptures
    {
        GREP_PARTICIPATION_STRATEGY
    } else if linked::STRICT_CAPTURE_BRIDGE && benchmark.model == shared::Model::GrepCaptures {
        "per-line-native-single-capture-next-v1"
    } else if benchmark.model == shared::Model::GrepCaptures {
        GREP_CAPTURE_STRATEGY
    } else if benchmark.model == shared::Model::GrepCount {
        if has_prepared_v15 {
            MIXED_GREP_ROW_STRATEGY
        } else {
            GREP_ROW_STRATEGY
        }
    } else {
        "not-applicable"
    };
    if linked::AGGREGATE_STRATEGY != expected_aggregate_strategy
        || linked::SPAN_ITERATION_STRATEGY != expected_span_strategy
        || linked::GREP_ITERATION_STRATEGY != expected_grep_strategy
    {
        return Err("linked native-row table has the wrong scalar iteration route".to_owned());
    }
    let expected_adapter = if linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE {
        "general-aot-native-selector-negative-certificate-stock-positive-capture-fallback-v1"
    } else if linked::PARTICIPATION_CAPTURE_BRIDGE {
        match benchmark.model {
            shared::Model::CountCaptures => "general-aot-native-exact-span-participation-count-v1",
            shared::Model::GrepCaptures => "general-aot-native-exact-span-participation-grep-v1",
            _ => return Err("participation capture bridge has a non-capture adapter".to_owned()),
        }
    } else if linked::STRICT_CAPTURE_BRIDGE {
        match benchmark.model {
            shared::Model::CountCaptures => "general-aot-native-single-capture-next-count-v1",
            shared::Model::GrepCaptures => "general-aot-native-single-capture-next-grep-v1",
            _ => return Err("strict capture bridge has a non-capture adapter".to_owned()),
        }
    } else {
        match (benchmark.model, has_prepared_v15) {
            (shared::Model::Count, false) => "general-aot-native-row-bridge-count-v1",
            (shared::Model::Count, true) => {
                "general-aot-native-row-bridge-count-mixed-prepared-ordered-nfa-v15-v1"
            }
            (shared::Model::SpanSum, false) => "general-aot-native-row-bridge-count-spans-v1",
            (shared::Model::SpanSum, true) => {
                "general-aot-native-row-bridge-count-spans-mixed-prepared-ordered-nfa-v15-v1"
            }
            (shared::Model::GrepCount, false) => "general-aot-native-row-bridge-grep-v1",
            (shared::Model::GrepCount, true) => {
                "general-aot-native-row-bridge-grep-mixed-prepared-ordered-nfa-v15-v1"
            }
            (shared::Model::CountCaptures, false) => {
                "general-aot-uniform-capture-native-row-count-adapter-loop-v1"
            }
            (shared::Model::GrepCaptures, false) => {
                "general-aot-uniform-capture-native-row-grep-adapter-loop-v1"
            }
            (shared::Model::Compile | shared::Model::RegexRedux, _)
            | (shared::Model::CountCaptures | shared::Model::GrepCaptures, true) => {
                return Err("linked native-row table has an impossible adapter shape".to_owned());
            }
        }
    };
    if linked::ADAPTER != expected_adapter {
        return Err("linked native-row adapter disagrees with its route receipts".to_owned());
    }

    if linked::UNIFORM_CAPTURE_BRIDGE {
        let source_count = linked::SOURCE_PATTERN_COUNT;
        if linked::UNIFORM_CAPTURE_ALGORITHM_VERSION
            != fre_lower::UNIFORM_CAPTURE_PARTICIPATION_ALGORITHM_VERSION
            || linked::UNIFORM_CAPTURE_ACCOUNTING_VERSION
                != fre_lower::UNIFORM_CAPTURE_PARTICIPATION_ACCOUNTING_VERSION
            || linked::ROW_PARTICIPATING_GROUPS.len() != linked::ROW_ARTIFACT_COUNT
            || linked::SOURCE_PARTICIPATING_GROUPS.len() != source_count
            || linked::SOURCE_MINIMUM_MATCH_BYTES.len() != source_count
            || linked::SOURCE_CANONICAL_CAPTURE_ANNOTATIONS.len() != source_count
            || linked::SOURCE_PROOF_WORK.len() != source_count
            || linked::SOURCE_PROOF_PEAK_STACK_ITEMS.len() != source_count
            || linked::SOURCE_SELECTOR_AUTOMATON_SHA256.len() != source_count
            || linked::SOURCE_SELECTOR_PROGRAM_SHA256.len() != source_count
            || linked::SOURCE_SELECTOR_OBJECT_SHA256.len() != source_count
            || linked::ROW_PARTICIPATING_GROUPS.contains(&0)
            || linked::SOURCE_PARTICIPATING_GROUPS.contains(&0)
            || linked::SOURCE_MINIMUM_MATCH_BYTES.contains(&0)
            || linked::SOURCE_SELECTOR_AUTOMATON_SHA256
                .iter()
                .any(|digest| *digest == [0; 32])
            || linked::SOURCE_SELECTOR_PROGRAM_SHA256
                .iter()
                .any(|digest| *digest == [0; 32])
            || linked::SOURCE_SELECTOR_OBJECT_SHA256
                .iter()
                .any(|digest| *digest == [0; 32])
        {
            return Err("linked uniform-capture proof closure is malformed".to_owned());
        }
        for source in 0..source_count {
            let artifact = linked::SOURCE_TO_ARTIFACT[source];
            if artifact >= linked::ROW_ARTIFACT_COUNT
                || linked::SOURCE_SELECTOR_AUTOMATON_SHA256[source]
                    != linked::ROW_AUTOMATON_SHA256[artifact]
                || linked::SOURCE_SELECTOR_PROGRAM_SHA256[source]
                    != linked::ROW_PROGRAM_SHA256[artifact]
                || linked::SOURCE_SELECTOR_OBJECT_SHA256[source]
                    != linked::ROW_OBJECT_SHA256[artifact]
            {
                return Err(
                    "uniform-capture source proof does not bind its retained selector".to_owned(),
                );
            }
        }
    } else if linked::UNIFORM_CAPTURE_ALGORITHM_VERSION != 0
        || linked::UNIFORM_CAPTURE_ACCOUNTING_VERSION != 0
        || !linked::ROW_PARTICIPATING_GROUPS.is_empty()
        || !linked::SOURCE_PARTICIPATING_GROUPS.is_empty()
        || !linked::SOURCE_MINIMUM_MATCH_BYTES.is_empty()
        || !linked::SOURCE_CANONICAL_CAPTURE_ANNOTATIONS.is_empty()
        || !linked::SOURCE_PROOF_WORK.is_empty()
        || !linked::SOURCE_PROOF_PEAK_STACK_ITEMS.is_empty()
        || !linked::SOURCE_SELECTOR_AUTOMATON_SHA256.is_empty()
        || !linked::SOURCE_SELECTOR_PROGRAM_SHA256.is_empty()
        || !linked::SOURCE_SELECTOR_OBJECT_SHA256.is_empty()
    {
        return Err("ordinary native-row route advertises capture proof state".to_owned());
    }

    if linked::STRICT_CAPTURE_BRIDGE {
        if linked::STRICT_CAPTURE_GROUP_COUNT == 0
            || linked::STRICT_CAPTURE_GROUP_COUNT > shared::MAX_STRICT_CAPTURE_GROUPS
            || linked::STRICT_CAPTURE_SOURCE_SHA256 == [0; 32]
            || linked::STRICT_CAPTURE_SELECTOR_SHA256 == [0; 32]
            || linked::STRICT_CAPTURE_CAPTURE_SHA256 == [0; 32]
            || linked::STRICT_CAPTURE_PLAN_SHA256 == [0; 32]
            || linked::STRICT_CAPTURE_BUNDLE_SHA256 == [0; 32]
            || linked::STRICT_CAPTURE_ARTIFACT_IDENTITY_SHA256 == [0; 32]
            || linked::STRICT_CAPTURE_NEXT_SYMBOL.is_empty()
            || linked::STRICT_CAPTURE_MATERIALIZE_SYMBOL.is_empty()
            || linked::STRICT_CAPTURE_SELECTOR_SYMBOL.is_empty()
            || linked::STRICT_CAPTURE_NEXT_SYMBOL == linked::STRICT_CAPTURE_MATERIALIZE_SYMBOL
            || linked::STRICT_CAPTURE_NEXT_SYMBOL == linked::STRICT_CAPTURE_SELECTOR_SYMBOL
            || linked::STRICT_CAPTURE_MATERIALIZE_SYMBOL == linked::STRICT_CAPTURE_SELECTOR_SYMBOL
            || linked::ROW_ENTRY_SYMBOLS != [linked::STRICT_CAPTURE_NEXT_SYMBOL]
            || linked::ROW_OBJECT_SHA256 != [linked::OBJECT_SHA256]
            || linked::PROGRAM_SHA256 != linked::STRICT_CAPTURE_CAPTURE_SHA256
            || linked::OBJECT_SHA256 == [0; 32]
            || linked::ENTRY_SYMBOL != linked::STRICT_CAPTURE_NEXT_SYMBOL
        {
            return Err("linked strict capture identity closure is malformed".to_owned());
        }
    } else if linked::STRICT_CAPTURE_GROUP_COUNT != 0
        || linked::STRICT_CAPTURE_CAN_MATCH_EMPTY
        || linked::STRICT_CAPTURE_SOURCE_SHA256 != [0; 32]
        || linked::STRICT_CAPTURE_SELECTOR_SHA256 != [0; 32]
        || linked::STRICT_CAPTURE_CAPTURE_SHA256 != [0; 32]
        || linked::STRICT_CAPTURE_PLAN_SHA256 != [0; 32]
        || linked::STRICT_CAPTURE_BUNDLE_SHA256 != [0; 32]
        || linked::STRICT_CAPTURE_ARTIFACT_IDENTITY_SHA256 != [0; 32]
        || !linked::STRICT_CAPTURE_NEXT_SYMBOL.is_empty()
        || !linked::STRICT_CAPTURE_MATERIALIZE_SYMBOL.is_empty()
        || !linked::STRICT_CAPTURE_SELECTOR_SYMBOL.is_empty()
    {
        return Err("non-strict route advertises strict capture state".to_owned());
    }

    if linked::PARTICIPATION_CAPTURE_BRIDGE {
        let expected_strategy = match linked::TARGET_ARCH {
            "x86_64" => 1,
            "aarch64" => 2,
            _ => {
                return Err("participation route has an unsupported target architecture".to_owned());
            }
        };
        let digests = [
            linked::PARTICIPATION_SOURCE_SHA256,
            linked::PARTICIPATION_CAPTURE_SHA256,
            linked::PARTICIPATION_SELECTOR_SHA256,
            linked::PARTICIPATION_SELECTOR_OBJECT_SHA256,
            linked::PARTICIPATION_BUNDLE_SHA256,
            linked::PARTICIPATION_EXPORT_IDENTITY_SHA256,
            linked::PARTICIPATION_OBJECT_SHA256,
            linked::PARTICIPATION_ARTIFACT_IDENTITY_SHA256,
        ];
        if linked::PARTICIPATION_ALGORITHM_ID
            != fre_aot_regex::NATIVE_PARTICIPATION_DFA_V1_ALGORITHM_ID
            || linked::PARTICIPATION_STRATEGY != expected_strategy
            || linked::PARTICIPATION_DECLINE != 0
            || linked::PARTICIPATION_SEMANTIC_RUNTIME_CALLS != 0
            || linked::PARTICIPATION_GROUP_COUNT == 0
            || linked::PARTICIPATION_GROUP_COUNT > shared::MAX_STRICT_CAPTURE_GROUPS
            || linked::PARTICIPATION_ASSERTION_SIGNATURES == 0
            || linked::PARTICIPATION_BYTE_CLASSES == 0
            || linked::PARTICIPATION_DFA_STATES == 0
            || linked::PARTICIPATION_TRANSITION_CELLS == 0
            || linked::PARTICIPATION_BUILD_WORK == 0
            || linked::PARTICIPATION_SCRATCH_BYTES
                != fre_aot_regex::NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES
            || linked::PARTICIPATION_PLAN_BYTES
                < fre_aot_regex::NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES
            || digests.contains(&[0; 32])
            || linked::PARTICIPATION_BUNDLE_SYMBOL.is_empty()
            || linked::PARTICIPATION_SELECTOR_SYMBOL.is_empty()
            || linked::PARTICIPATION_ENTRY_SYMBOL.is_empty()
            || linked::PARTICIPATION_BUNDLE_SYMBOL == linked::PARTICIPATION_SELECTOR_SYMBOL
            || linked::PARTICIPATION_BUNDLE_SYMBOL == linked::PARTICIPATION_ENTRY_SYMBOL
            || linked::PARTICIPATION_SELECTOR_SYMBOL == linked::PARTICIPATION_ENTRY_SYMBOL
            || linked::ROW_ENTRY_SYMBOLS != [linked::PARTICIPATION_SELECTOR_SYMBOL]
            || linked::ROW_AUTOMATON_SHA256 != [linked::PARTICIPATION_SELECTOR_SHA256]
            || linked::ROW_PROGRAM_SHA256 != [linked::PARTICIPATION_CAPTURE_SHA256]
            || linked::ROW_OBJECT_SHA256 != [linked::PARTICIPATION_OBJECT_SHA256]
            || linked::PROGRAM_SHA256 != linked::PARTICIPATION_CAPTURE_SHA256
            || linked::OBJECT_SHA256 != linked::PARTICIPATION_OBJECT_SHA256
            || linked::ENTRY_SYMBOL != linked::PARTICIPATION_SELECTOR_SYMBOL
            || linked::ROW_TOTAL_OBJECT_BYTES == 0
            || !linked::OBJECT_BYTES.is_empty()
        {
            return Err("linked participation capture identity closure is malformed".to_owned());
        }
    } else if !linked::PARTICIPATION_ALGORITHM_ID.is_empty()
        || linked::PARTICIPATION_STRATEGY != 0
        || linked::PARTICIPATION_DECLINE != 0
        || linked::PARTICIPATION_SEMANTIC_RUNTIME_CALLS != 0
        || linked::PARTICIPATION_GROUP_COUNT != 0
        || linked::PARTICIPATION_ASSERTIONS != 0
        || linked::PARTICIPATION_ASSERTION_SIGNATURES != 0
        || linked::PARTICIPATION_BYTE_CLASSES != 0
        || linked::PARTICIPATION_DFA_STATES != 0
        || linked::PARTICIPATION_TRANSITION_CELLS != 0
        || linked::PARTICIPATION_BUILD_WORK != 0
        || linked::PARTICIPATION_SCRATCH_BYTES != 0
        || linked::PARTICIPATION_PLAN_BYTES != 0
        || linked::PARTICIPATION_SOURCE_SHA256 != [0; 32]
        || linked::PARTICIPATION_CAPTURE_SHA256 != [0; 32]
        || linked::PARTICIPATION_SELECTOR_SHA256 != [0; 32]
        || linked::PARTICIPATION_SELECTOR_OBJECT_SHA256 != [0; 32]
        || linked::PARTICIPATION_BUNDLE_SHA256 != [0; 32]
        || linked::PARTICIPATION_EXPORT_IDENTITY_SHA256 != [0; 32]
        || linked::PARTICIPATION_OBJECT_SHA256 != [0; 32]
        || linked::PARTICIPATION_ARTIFACT_IDENTITY_SHA256 != [0; 32]
        || !linked::PARTICIPATION_BUNDLE_SYMBOL.is_empty()
        || !linked::PARTICIPATION_SELECTOR_SYMBOL.is_empty()
        || !linked::PARTICIPATION_ENTRY_SYMBOL.is_empty()
    {
        return Err("non-participation route advertises participation state".to_owned());
    }

    if linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE {
        let expected_limit = match linked::SELECTOR_CAPTURE_DIRECT_RESOURCE {
            "DfaStates" => shared::REBAR_PARTICIPATION_RETRY_MAX_DFA_STATES,
            "BuildWork" => shared::REBAR_PARTICIPATION_RETRY_MAX_BUILD_WORK,
            _ => {
                return Err(
                    "selector-first capture route has an unknown direct resource".to_owned(),
                );
            }
        };
        if linked::SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL
            != shared::REBAR_SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL
            || linked::SELECTOR_CAPTURE_POSITIVE_FALLBACK_PROFILE != "rust-regex-1.12.4-captures"
            || linked::SELECTOR_CAPTURE_DIRECT_LIMIT != expected_limit
            || linked::SELECTOR_CAPTURE_DIRECT_REQUIRED
                != linked::SELECTOR_CAPTURE_DIRECT_LIMIT.saturating_add(1)
            || linked::SOURCE_PATTERN_COUNT != 1
            || linked::ROW_ARTIFACT_COUNT != 1
            || linked::SOURCE_TO_ARTIFACT != [0]
            || linked::ROW_FIRST_SOURCE_ORDINALS != [0]
            || linked::ROW_TOTAL_OBJECT_BYTES == 0
            || linked::ROW_ENTRY_SYMBOLS[0].is_empty()
            || linked::OBJECT_SHA256 != linked::ROW_OBJECT_SHA256[0]
            || linked::PROGRAM_SHA256 != linked::ROW_PROGRAM_SHA256[0]
            || !linked::OBJECT_BYTES.is_empty()
        {
            return Err("linked selector-first capture identity closure is malformed".to_owned());
        }
    } else if !linked::SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL.is_empty()
        || !linked::SELECTOR_CAPTURE_POSITIVE_FALLBACK_PROFILE.is_empty()
        || !linked::SELECTOR_CAPTURE_DIRECT_RESOURCE.is_empty()
        || linked::SELECTOR_CAPTURE_DIRECT_REQUIRED != 0
        || linked::SELECTOR_CAPTURE_DIRECT_LIMIT != 0
    {
        return Err("non-selector-fallback route advertises mixed capture state".to_owned());
    }

    let row_engines = linked::ENGINE
        .strip_prefix("IndependentNativeSpanRows(")
        .and_then(|engines| engines.strip_suffix(')'))
        .map(|engines| engines.split(',').collect::<Vec<_>>())
        .ok_or_else(|| "linked native-row engine receipt is malformed".to_owned())?;
    if row_engines.len() != linked::ROW_ARTIFACT_COUNT {
        return Err("linked native-row engine cardinality differs".to_owned());
    }
    let mut previous_first = None;
    for (artifact, &first_source) in linked::ROW_FIRST_SOURCE_ORDINALS.iter().enumerate() {
        if first_source >= linked::SOURCE_PATTERN_COUNT
            || previous_first.is_some_and(|previous| first_source <= previous)
            || linked::SOURCE_TO_ARTIFACT[first_source] != artifact
            || linked::ROW_ENTRY_SYMBOLS[artifact].is_empty()
        {
            return Err("linked native-row source-priority map is malformed".to_owned());
        }
        previous_first = Some(first_source);
        let capabilities = linked::ROW_REQUIRED_PREPARE_CAPABILITIES[artifact];
        match capabilities {
            0 => {
                if linked::ROW_PREPARE_CONFIG_VERSIONS[artifact] != 0
                    || linked::ROW_PREPARE_OPERATION_FLAGS[artifact] != 0
                    || !linked::ROW_PROGRAM_SYMBOLS[artifact].is_empty()
                    || linked::ROW_PROGRAM_LENS[artifact] != 0
                    || !linked::ROW_SPAN_FILL_SYMBOLS[artifact].is_empty()
                    || linked::ROW_PREPARED_BULK_STRATEGIES[artifact] != "None"
                    || !linked::ROW_REQUIRED_RUNTIME_SYMBOLS[artifact].is_empty()
                {
                    return Err(format!(
                        "ordinary native row {artifact} advertises prepared/helper state"
                    ));
                }
                if !matches!(row_engines[artifact], "OrderedDfa" | "OrderedContextDfa")
                    || native_symbol_identity(
                        linked::ROW_ENTRY_SYMBOLS[artifact],
                        "fre_aot_regex_search_v1_",
                    )
                    .is_none()
                {
                    return Err(format!(
                        "ordinary native row {artifact} has a noncanonical engine or entry"
                    ));
                }
            }
            PREPARE_CAPABILITY_ORDERED_NFA_V15 => {
                let entry_identity = native_symbol_identity(
                    linked::ROW_ENTRY_SYMBOLS[artifact],
                    "fre_aot_regex_search_exclusive_v1_",
                );
                let program_identity = native_symbol_identity(
                    linked::ROW_PROGRAM_SYMBOLS[artifact],
                    "fre_aot_regex_runtime_program_v1_",
                );
                let span_fill_identity = native_symbol_identity(
                    linked::ROW_SPAN_FILL_SYMBOLS[artifact],
                    "fre_aot_regex_fill_spans_exclusive_v1_",
                );
                let runtime_symbols = linked::ROW_REQUIRED_RUNTIME_SYMBOLS[artifact]
                    .split(',')
                    .collect::<std::collections::BTreeSet<_>>();
                let expected_runtime_symbols = [
                    "fre_aot_regex_runtime_search_v1",
                    "fre_aot_regex_runtime_search_exclusive_v1",
                    "fre_aot_regex_runtime_fill_spans_exclusive_v1",
                ]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
                if linked::ROW_PREPARE_CONFIG_VERSIONS[artifact] != PREPARE_CONFIG_V3_VERSION
                    || linked::ROW_PREPARE_OPERATION_FLAGS[artifact]
                        != shared::Model::Count.prepare_operation_flags()
                    || row_engines[artifact] != "OrderedNfa"
                    || linked::ROW_PROGRAM_SYMBOLS[artifact].is_empty()
                    || linked::ROW_PROGRAM_LENS[artifact] == 0
                    || linked::ROW_PROGRAM_LENS[artifact]
                        > shared::MAX_NATIVE_ROW_BRIDGE_OBJECT_BYTES
                    || linked::ROW_SPAN_FILL_SYMBOLS[artifact].is_empty()
                    || linked::ROW_PREPARED_BULK_STRATEGIES[artifact]
                        != "Some(NativeOrderedNfaLoop)"
                    || runtime_symbols != expected_runtime_symbols
                    || entry_identity.is_none()
                    || entry_identity != program_identity
                    || entry_identity != span_fill_identity
                    || linked::ROW_ENTRY_SYMBOLS[artifact] == linked::ROW_PROGRAM_SYMBOLS[artifact]
                    || linked::ROW_ENTRY_SYMBOLS[artifact]
                        == linked::ROW_SPAN_FILL_SYMBOLS[artifact]
                    || linked::ROW_PROGRAM_SYMBOLS[artifact]
                        == linked::ROW_SPAN_FILL_SYMBOLS[artifact]
                {
                    return Err(format!(
                        "prepared native row {artifact} has an inconsistent V15 closure"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "native row {artifact} requires unknown prepare capabilities {other:#x}"
                ));
            }
        }
        if linked::UNIFORM_CAPTURE_BRIDGE
            && linked::ROW_PARTICIPATING_GROUPS[artifact]
                != linked::SOURCE_PARTICIPATING_GROUPS[first_source]
        {
            return Err(
                "uniform-capture row multiplier is not its first source's proof".to_owned(),
            );
        }
    }
    for (source, &artifact) in linked::SOURCE_TO_ARTIFACT.iter().enumerate() {
        if artifact >= linked::ROW_ARTIFACT_COUNT
            || linked::ROW_FIRST_SOURCE_ORDINALS[artifact] > source
        {
            return Err("linked native-row source map references an invalid artifact".to_owned());
        }
        for prior in 0..source {
            if benchmark.patterns[prior] == benchmark.patterns[source]
                && linked::SOURCE_TO_ARTIFACT[prior] != artifact
            {
                return Err("duplicate source rows were not deduplicated".to_owned());
            }
        }
    }
    for row in 0..linked::ROW_ARTIFACT_COUNT {
        for prior in 0..row {
            if linked::ROW_ENTRY_SYMBOLS[prior] == linked::ROW_ENTRY_SYMBOLS[row] {
                return Err(
                    "duplicate native entry artifacts escaped build-time deduplication".to_owned(),
                );
            }
        }
    }
    Ok(())
}

fn native_symbol_identity<'a>(symbol: &'a str, prefix: &str) -> Option<&'a str> {
    let suffix = symbol.strip_prefix(prefix)?;
    (suffix.len() == 64
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(suffix)
}

fn linked_span_fill_iteration_is_exact(bulk: &str, iteration: &str) -> bool {
    matches!(
        (bulk, iteration),
        (
            "Some(RuntimeHelper)",
            "linked-prepared-span-fill-64::Some(RuntimeHelper)"
        ) | (
            "Some(NativePreparedLoop)",
            "linked-prepared-span-fill-64::Some(NativePreparedLoop)"
        ) | (
            "Some(NativeTrustedPreflightLoop)",
            "linked-prepared-span-fill-64::Some(NativeTrustedPreflightLoop)"
        ) | (
            "Some(NativeTrustedPreflightRuntimeBulk)",
            "linked-prepared-span-fill-64::Some(NativeTrustedPreflightRuntimeBulk)"
        ) | (
            "Some(NativeFrozenLoop)",
            "linked-prepared-span-fill-64::Some(NativeFrozenLoop)"
        ) | (
            "Some(NativeOrderedNfaLoop)",
            "linked-prepared-span-fill-64::Some(NativeOrderedNfaLoop)"
        )
    )
}

fn authenticate_linked_native_scalar_reducer(model: shared::Model) -> Result<bool, String> {
    let strategy_is_native = matches!(
        linked::AGGREGATE_STRATEGY,
        "Some(NativeFused)" | "Some(NativeOrderedNfaFused)"
    ) && matches!(model, shared::Model::Count | shared::Model::SpanSum);
    if linked::NATIVE_SCALAR_REDUCER != strategy_is_native {
        return Err(
            "native scalar reducer flag disagrees with its exact aggregate strategy".to_owned(),
        );
    }
    if !strategy_is_native {
        return Ok(false);
    }

    let prefix = match model {
        shared::Model::Count => "fre_aot_regex_count_exclusive_v1_",
        shared::Model::SpanSum => "fre_aot_regex_span_sum_exclusive_v1_",
        _ => unreachable!("native scalar strategy was restricted to scalar models"),
    };
    native_symbol_identity(linked::REDUCER_SYMBOL, prefix)
        .ok_or_else(|| "native scalar reducer has no canonical identity symbol".to_owned())?;
    native_symbol_identity(linked::PROGRAM_SYMBOL, "fre_aot_regex_runtime_program_v1_")
        .ok_or_else(|| "native scalar reducer has no canonical program identity".to_owned())?;
    let compatibility_helper = match model {
        shared::Model::Count => "fre_aot_regex_runtime_compiler_private_count_exclusive_v1",
        shared::Model::SpanSum => "fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1",
        _ => unreachable!("native scalar strategy was restricted to scalar models"),
    };
    let aggregate_helpers = linked::REQUIRED_RUNTIME_SYMBOLS
        .split(',')
        .filter(|symbol| {
            matches!(
                *symbol,
                "fre_aot_regex_runtime_compiler_private_count_exclusive_v1"
                    | "fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1"
                    | "fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1"
            )
        })
        .collect::<Vec<_>>();
    if linked::REDUCER_SYMBOL == linked::ENTRY_SYMBOL
        || linked::REDUCER_SYMBOL == linked::PROGRAM_SYMBOL
        || (!linked::SPAN_FILL_SYMBOL.is_empty()
            && linked::REDUCER_SYMBOL == linked::SPAN_FILL_SYMBOL)
        || linked::PROGRAM_LEN == 0
        || linked::PROGRAM_SHA256 == [0; 32]
        || linked::OBJECT_SHA256 == [0; 32]
        || linked::PREPARE_OPERATION_FLAGS != model.prepare_operation_flags()
        || linked::ADAPTER
            != model.adapter_for_required_capabilities(linked::REQUIRED_PREPARE_CAPABILITIES)
    {
        return Err(
            "native scalar reducer failed exact symbol and operation authentication".to_owned(),
        );
    }

    let ordered_nfa = linked::AGGREGATE_STRATEGY == "Some(NativeOrderedNfaFused)";
    if ordered_nfa != (linked::REQUIRED_PREPARE_CAPABILITIES == PREPARE_CAPABILITY_ORDERED_NFA_V15)
        || (ordered_nfa
            && (linked::ENGINE != "OrderedNfa"
                || linked::PREPARED_BULK_STRATEGY != "Some(NativeOrderedNfaLoop)"
                || !linked::HAS_SPAN_FILL
                || aggregate_helpers != [compatibility_helper]))
        || (!ordered_nfa
            && (linked::REQUIRED_PREPARE_CAPABILITIES != 0
                || !matches!(
                    linked::PREPARED_BULK_STRATEGY,
                    "None" | "Some(NativePreparedLoop)" | "Some(NativeFrozenLoop)"
                )
                || linked::HAS_SPAN_FILL != (linked::PREPARED_BULK_STRATEGY != "None")
                || !aggregate_helpers.is_empty()))
    {
        return Err("native scalar reducer failed exact capability authentication".to_owned());
    }
    Ok(true)
}

fn run_operation(
    benchmark: &shared::Benchmark,
    session: &mut ExclusiveSession,
) -> Result<Vec<Sample>, String> {
    match benchmark.model {
        shared::Model::SpanSum
            if linked::NATIVE_SCALAR_REDUCER || linked::SHARED_ORDERED_MANY_AGGREGATE =>
        {
            run_operation_route(benchmark, session, ExclusiveSession::reduce)
        }
        shared::Model::SpanSum if linked::HAS_SPAN_FILL => run_operation_route(
            benchmark,
            session,
            ExclusiveSession::strict_span_sum_with_fill,
        ),
        shared::Model::SpanSum => run_operation_route(
            benchmark,
            session,
            ExclusiveSession::strict_span_sum_with_direct_entry,
        ),
        shared::Model::GrepCount => {
            run_operation_route(benchmark, session, ExclusiveSession::reduce)
        }
        shared::Model::CountCaptures | shared::Model::GrepCaptures
            if linked::UNIFORM_CAPTURE_BRIDGE
                && !linked::NATIVE_ROW_BRIDGE
                && !linked::REDUCER_SYMBOL.is_empty() =>
        {
            run_operation_route(benchmark, session, ExclusiveSession::reduce)
        }
        shared::Model::CountCaptures | shared::Model::GrepCaptures
            if linked::UNIFORM_CAPTURE_BRIDGE && !linked::NATIVE_ROW_BRIDGE =>
        {
            run_operation_route(benchmark, session, |session, haystack| {
                prepared_uniform_capture_reduce(benchmark.model, session, haystack)
            })
        }
        shared::Model::CountCaptures | shared::Model::GrepCaptures => {
            Err("uniform-capture model is not bound to a prepared or native-row route".to_owned())
        }
        shared::Model::Count => run_operation_route(benchmark, session, ExclusiveSession::reduce),
        shared::Model::RegexRedux => {
            Err("regex-redux does not use one prepared scalar session".to_owned())
        }
        shared::Model::Compile => Err(
            "general AOT object emission is not a search-ready Rebar compile operation".to_owned(),
        ),
    }
}

fn run_regex_redux(benchmark: &shared::Benchmark) -> Result<RegexReduxRun, String> {
    std::str::from_utf8(&benchmark.haystack)
        .map_err(|error| format!("regex-redux haystack is not UTF-8: {error}"))?;
    let mut operation = LinkedRegexReduxOperation::new(benchmark.haystack.len())?;
    let samples =
        run_operation_route_without_session(benchmark, |haystack| operation.reduce(haystack))?;
    let receipt = operation.receipt()?;
    Ok(RegexReduxRun { samples, receipt })
}

#[derive(Debug)]
struct LinkedRegexReduxOperation {
    scratch_a: Vec<u8>,
    scratch_b: Vec<u8>,
    report: Vec<u8>,
    receipt: NativeRegexReduxRunReceiptV1,
    completed: bool,
}

impl LinkedRegexReduxOperation {
    fn new(haystack_len: usize) -> Result<Self, String> {
        if linked::REGEX_REDUX_SCRATCH_CAPACITY_NUMERATOR != 3
            || linked::REGEX_REDUX_SCRATCH_CAPACITY_DENOMINATOR != 2
            || linked::REGEX_REDUX_SCRATCH_BUFFER_COUNT != 2
        {
            return Err("linked regex-redux scratch schema is not canonical".to_owned());
        }
        let scratch_capacity = haystack_len
            .checked_add(haystack_len / linked::REGEX_REDUX_SCRATCH_CAPACITY_DENOMINATOR)
            .ok_or_else(|| "regex-redux scratch capacity overflowed usize".to_owned())?;
        Ok(Self {
            scratch_a: zeroed_regex_redux_buffer(scratch_capacity, "scratch A")?,
            scratch_b: zeroed_regex_redux_buffer(scratch_capacity, "scratch B")?,
            report: zeroed_regex_redux_buffer(linked::REGEX_REDUX_REPORT_BYTES, "report")?,
            receipt: poisoned_regex_redux_receipt(),
            completed: false,
        })
    }

    #[allow(
        unsafe_code,
        reason = "the generated whole-operation declaration is the exact statically linked regex-redux AOT ABI"
    )]
    fn reduce(&mut self, haystack: &[u8]) -> Result<u64, String> {
        self.receipt = poisoned_regex_redux_receipt();
        self.completed = false;
        let request = NativeRegexReduxRequestV1 {
            haystack: haystack.as_ptr(),
            haystack_len: haystack.len(),
            scratch_a: self.scratch_a.as_mut_ptr(),
            scratch_a_capacity: self.scratch_a.len(),
            scratch_b: self.scratch_b.as_mut_ptr(),
            scratch_b_capacity: self.scratch_b.len(),
            report: self.report.as_mut_ptr(),
            report_capacity: self.report.len(),
            receipt_out: &raw mut self.receipt,
        };
        // SAFETY: the request, immutable haystack, two owned scratch buffers,
        // report buffer, and aligned receipt are live and pairwise disjoint.
        // The generated authentication fixes every capacity and ABI extent.
        let status = unsafe { linked::regex_redux_reduce(&raw const request) };
        if status != fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_STATUS_SUCCESS {
            return Err(format!(
                "identity-suffixed regex-redux reducer {:?} returned status {status}",
                linked::REDUCER_SYMBOL
            ));
        }
        self.validate_receipt(haystack.len())?;
        self.completed = true;
        let final_length = usize::try_from(self.receipt.final_length)
            .map_err(|_| "regex-redux final length does not fit usize".to_owned())?;
        black_box(
            self.scratch_b
                .get(..final_length)
                .ok_or_else(|| "regex-redux final bytes exceed scratch B".to_owned())?,
        );
        Ok(self.receipt.final_length)
    }

    fn validate_receipt(&self, haystack_len: usize) -> Result<(), String> {
        let input_length = u64::try_from(haystack_len)
            .map_err(|_| "regex-redux input length does not fit u64".to_owned())?;
        if self.receipt.input_length != input_length {
            return Err("native regex-redux receipt changed the input length".to_owned());
        }
        let scratch_limit = u64::try_from(self.scratch_b.len())
            .map_err(|_| "regex-redux scratch capacity does not fit u64".to_owned())?;
        if self.receipt.clean_length > scratch_limit
            || self
                .receipt
                .substitution_lengths
                .iter()
                .any(|&length| length > scratch_limit)
            || self.receipt.final_length > scratch_limit
            || self.receipt.substitution_lengths[4] != self.receipt.final_length
        {
            return Err("native regex-redux receipt exceeds its scratch schema".to_owned());
        }
        let report_length = usize::try_from(self.receipt.report_length)
            .map_err(|_| "regex-redux report length does not fit usize".to_owned())?;
        let report = self
            .report
            .get(..report_length)
            .ok_or_else(|| "native regex-redux report exceeds its sealed capacity".to_owned())?;
        std::str::from_utf8(report)
            .map_err(|error| format!("native regex-redux report is not UTF-8: {error}"))?;
        Ok(())
    }

    fn receipt(&self) -> Result<RegexReduxStageReceipt, String> {
        if !self.completed {
            return Err("native regex-redux operation has no completed receipt".to_owned());
        }
        let report_length = usize::try_from(self.receipt.report_length)
            .map_err(|_| "regex-redux report length does not fit usize".to_owned())?;
        let final_length = usize::try_from(self.receipt.final_length)
            .map_err(|_| "regex-redux final length does not fit usize".to_owned())?;
        let report = std::str::from_utf8(
            self.report
                .get(..report_length)
                .ok_or_else(|| "native regex-redux report range is invalid".to_owned())?,
        )
        .map_err(|error| format!("native regex-redux report is not UTF-8: {error}"))?
        .to_owned();
        let final_bytes = self
            .scratch_b
            .get(..final_length)
            .ok_or_else(|| "native regex-redux final range is invalid".to_owned())?
            .to_vec();
        Ok(RegexReduxStageReceipt {
            input_length: self.receipt.input_length,
            clean_length: self.receipt.clean_length,
            variant_counts: self.receipt.variant_counts,
            substitution_lengths: self.receipt.substitution_lengths,
            final_length: self.receipt.final_length,
            report_length: self.receipt.report_length,
            report,
            final_bytes,
        })
    }
}

fn zeroed_regex_redux_buffer(length: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| format!("regex-redux {label} allocation failed"))?;
    buffer.resize(length, 0);
    Ok(buffer)
}

const fn poisoned_regex_redux_receipt() -> NativeRegexReduxRunReceiptV1 {
    NativeRegexReduxRunReceiptV1 {
        input_length: u64::MAX,
        clean_length: u64::MAX,
        variant_counts: [u64::MAX; 9],
        substitution_lengths: [u64::MAX; 5],
        final_length: u64::MAX,
        report_length: u64::MAX,
    }
}

fn run_operation_route_without_session(
    benchmark: &shared::Benchmark,
    mut operation: impl FnMut(&[u8]) -> Result<u64, String>,
) -> Result<Vec<Sample>, String> {
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        black_box(operation(black_box(&benchmark.haystack))?);
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }
    let capacity = usize::try_from(benchmark.max_iters)
        .unwrap_or(usize::MAX)
        .min(1_048_576);
    let mut samples = Vec::with_capacity(capacity);
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let value = operation(black_box(&benchmark.haystack))?;
        samples.push(Sample {
            duration: sample_start.elapsed(),
            value,
        });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn run_operation_route(
    benchmark: &shared::Benchmark,
    session: &mut ExclusiveSession,
    mut operation: impl FnMut(&mut ExclusiveSession, &[u8]) -> Result<u64, String>,
) -> Result<Vec<Sample>, String> {
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let actual = operation(session, black_box(&benchmark.haystack))?;
        black_box(actual);
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }

    let capacity = usize::try_from(benchmark.max_iters)
        .unwrap_or(usize::MAX)
        .min(1_048_576);
    let mut samples = Vec::with_capacity(capacity);
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let actual = operation(session, black_box(&benchmark.haystack))?;
        let duration = sample_start.elapsed();
        samples.push(Sample {
            duration,
            value: actual,
        });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn run_native_row_operation(benchmark: &shared::Benchmark) -> Result<Vec<Sample>, String> {
    let mut capture_slots = if linked::STRICT_CAPTURE_BRIDGE {
        vec![FreAotRegexCaptureSlotV1::UNMATCHED; linked::STRICT_CAPTURE_GROUP_COUNT]
    } else {
        Vec::new()
    };
    let stock_positive_fallback = linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE
        .then(|| compile_stock_rebar_regex(benchmark))
        .transpose()?;
    let prepared_rows = if linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE
        || linked::PARTICIPATION_CAPTURE_BRIDGE
        || linked::STRICT_CAPTURE_BRIDGE
        || linked::UNIFORM_CAPTURE_BRIDGE
    {
        None
    } else {
        Some(PreparedRowSessions::prepare()?)
    };
    let mut operation = |haystack: &[u8]| {
        if linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE {
            strict_linked_selector_capture_grep(
                haystack,
                stock_positive_fallback
                    .as_ref()
                    .ok_or_else(|| "selector-first route omitted its stock fallback".to_owned())?,
            )
        } else if linked::PARTICIPATION_CAPTURE_BRIDGE {
            strict_participation_capture_reduce(benchmark.model, haystack)
        } else if linked::STRICT_CAPTURE_BRIDGE {
            strict_capture_reduce(benchmark.model, haystack, &mut capture_slots)
        } else if linked::UNIFORM_CAPTURE_BRIDGE {
            strict_uniform_capture_reduce(benchmark.model, haystack)
        } else {
            strict_native_row_reduce(
                benchmark.model,
                haystack,
                prepared_rows
                    .as_ref()
                    .expect("ordinary native-row route prepared its handle table"),
            )
        }
    };
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let actual = operation(black_box(&benchmark.haystack))?;
        black_box(actual);
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }
    let positive_fallback_calls_before_samples =
        SELECTOR_CAPTURE_POSITIVE_FALLBACK_CALLS.load(Ordering::Relaxed);

    let capacity = usize::try_from(benchmark.max_iters)
        .unwrap_or(usize::MAX)
        .min(1_048_576);
    let mut samples = Vec::with_capacity(capacity);
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let actual = operation(black_box(&benchmark.haystack))?;
        let duration = sample_start.elapsed();
        samples.push(Sample {
            duration,
            value: actual,
        });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    drop(operation);
    if linked::SELECTOR_CAPTURE_FALLBACK_BRIDGE {
        let positive_fallback_calls = SELECTOR_CAPTURE_POSITIVE_FALLBACK_CALLS
            .load(Ordering::Relaxed)
            .checked_sub(positive_fallback_calls_before_samples)
            .ok_or_else(|| {
                "selector-first positive fallback marker counter regressed".to_owned()
            })?;
        let published_positive = samples.iter().any(|sample| sample.value != 0);
        if (positive_fallback_calls != 0) != published_positive {
            return Err(format!(
                "selector-first mixed-route receipt is inconsistent: positive_fallback_calls={positive_fallback_calls} published_positive={published_positive}"
            ));
        }
    }
    if let Some(prepared_rows) = prepared_rows {
        prepared_rows.destroy()?;
    }
    Ok(samples)
}

fn run_compile(
    benchmark: &shared::Benchmark,
    target: fre_aot_regex::Target,
    session: &mut ExclusiveSession,
) -> Result<Vec<Sample>, String> {
    let warmup_start = Instant::now();
    for _ in 0..benchmark.max_warmup_iters {
        let artifact = shared::compile_benchmark(benchmark, target)?;
        validate_compiled_artifact(&artifact)?;
        black_box(session.reduce(&benchmark.haystack)?);
        if warmup_start.elapsed() >= benchmark.max_warmup_time {
            break;
        }
    }

    let capacity = usize::try_from(benchmark.max_iters)
        .unwrap_or(usize::MAX)
        .min(1_048_576);
    let mut samples = Vec::with_capacity(capacity);
    let run_start = Instant::now();
    for _ in 0..benchmark.max_iters {
        let sample_start = Instant::now();
        let artifact = shared::compile_benchmark(black_box(benchmark), target)?;
        let duration = sample_start.elapsed();
        validate_compiled_artifact(&artifact)?;
        let actual = session.reduce(&benchmark.haystack)?;
        samples.push(Sample {
            duration,
            value: actual,
        });
        if run_start.elapsed() >= benchmark.max_time {
            break;
        }
    }
    Ok(samples)
}

fn validate_compiled_artifact(artifact: &CompiledRegex) -> Result<(), String> {
    if artifact.object() != linked::OBJECT_BYTES
        || artifact.receipt().program_sha256 != linked::PROGRAM_SHA256
        || artifact.receipt().object_sha256 != linked::OBJECT_SHA256
        || artifact.receipt().required_prepare_capabilities != linked::REQUIRED_PREPARE_CAPABILITIES
        || format!("{:?}", artifact.module().prepared_bulk_strategy())
            != linked::PREPARED_BULK_STRATEGY
        || format!("{:?}", artifact.receipt().prepared_aggregate_strategy)
            != linked::AGGREGATE_STRATEGY
    {
        return Err(
            "timed compilation differs from the exact statically linked verification artifact"
                .to_owned(),
        );
    }
    Ok(())
}

fn rust_regex_redux_component(pattern: &str) -> Result<Regex, String> {
    Regex::builder()
        .configure(
            Regex::config()
                .utf8_empty(false)
                .nfa_size_limit(Some(104_857_600)),
        )
        .syntax(
            regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(false)
                .case_insensitive(false),
        )
        .build(pattern)
        .map_err(|error| format!("Rust regex-redux component compilation failed: {error}"))
}

fn rust_regex_redux_replace_all(
    regex: &Regex,
    haystack: &[u8],
    replacement: &[u8],
) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    output
        .try_reserve(haystack.len())
        .map_err(|_| "Rust regex-redux replacement allocation failed".to_owned())?;
    let mut copied = 0_usize;
    for matched in regex.find_iter(haystack) {
        if matched.start() >= matched.end() || matched.end() > haystack.len() {
            return Err("Rust regex-redux fixed component returned an invalid span".to_owned());
        }
        output.extend_from_slice(
            haystack
                .get(copied..matched.start())
                .ok_or_else(|| "Rust regex-redux replacement range is invalid".to_owned())?,
        );
        output.extend_from_slice(replacement);
        copied = matched.end();
    }
    output.extend_from_slice(
        haystack
            .get(copied..)
            .ok_or_else(|| "Rust regex-redux replacement tail is invalid".to_owned())?,
    );
    Ok(output)
}

fn rust_regex_redux_oracle(haystack: &[u8]) -> Result<RegexReduxStageReceipt, String> {
    std::str::from_utf8(haystack)
        .map_err(|error| format!("regex-redux haystack is not UTF-8: {error}"))?;
    let input_length = u64::try_from(haystack.len())
        .map_err(|_| "Rust regex-redux input length does not fit u64".to_owned())?;
    let flatten = rust_regex_redux_component(shared::REGEX_REDUX_FLATTEN_PATTERN)?;
    let mut sequence = rust_regex_redux_replace_all(&flatten, haystack, b"")?;
    let clean_length = u64::try_from(sequence.len())
        .map_err(|_| "Rust regex-redux clean length does not fit u64".to_owned())?;

    let mut report = String::new();
    let mut variant_counts = [0_u64; shared::REGEX_REDUX_VARIANTS.len()];
    for (variant, pattern) in shared::REGEX_REDUX_VARIANTS.iter().enumerate() {
        let regex = rust_regex_redux_component(pattern)?;
        let count = u64::try_from(regex.find_iter(&sequence).count())
            .map_err(|_| "Rust regex-redux variant count does not fit u64".to_owned())?;
        variant_counts[variant] = count;
        writeln!(&mut report, "{pattern} {count}")
            .map_err(|_| "format Rust regex-redux variant report".to_owned())?;
    }

    let mut substitution_lengths = [0_u64; shared::REGEX_REDUX_SUBSTITUTIONS.len()];
    for (substitution, (pattern, replacement)) in
        shared::REGEX_REDUX_SUBSTITUTIONS.iter().enumerate()
    {
        let regex = rust_regex_redux_component(pattern)?;
        sequence = rust_regex_redux_replace_all(&regex, &sequence, replacement.as_bytes())?;
        substitution_lengths[substitution] = u64::try_from(sequence.len())
            .map_err(|_| "Rust regex-redux substitution length does not fit u64".to_owned())?;
    }
    let final_length = u64::try_from(sequence.len())
        .map_err(|_| "Rust regex-redux final length does not fit u64".to_owned())?;
    writeln!(
        &mut report,
        "\n{input_length}\n{clean_length}\n{final_length}"
    )
    .map_err(|_| "format Rust regex-redux terminal report".to_owned())?;
    let report_length = u64::try_from(report.len())
        .map_err(|_| "Rust regex-redux report length does not fit u64".to_owned())?;
    Ok(RegexReduxStageReceipt {
        input_length,
        clean_length,
        variant_counts,
        substitution_lengths,
        final_length,
        report_length,
        report,
        final_bytes: sequence,
    })
}

fn compile_stock_rebar_regex(benchmark: &shared::Benchmark) -> Result<Regex, String> {
    let config = Regex::config()
        .utf8_empty(false)
        .nfa_size_limit(Some(104_857_600));
    let syntax = regex_automata::util::syntax::Config::new()
        .utf8(false)
        .unicode(benchmark.unicode)
        .case_insensitive(benchmark.case_insensitive);
    Regex::builder()
        .configure(config)
        .syntax(syntax)
        .build_many(&benchmark.patterns)
        .map_err(|error| format!("Rust Rebar oracle compilation failed: {error}"))
}

fn stock_capture_count_domain(regex: &Regex, haystack: &[u8]) -> Result<u64, String> {
    regex
        .captures_iter(Input::new(haystack))
        .try_fold(0_u64, |mut count, captures| {
            for group in 0..captures.group_len() {
                if captures.get_group(group).is_some() {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| "Rust Rebar capture oracle overflow".to_owned())?;
                }
            }
            Ok(count)
        })
}

fn rust_oracle(benchmark: &shared::Benchmark) -> Result<u64, String> {
    if benchmark.model == shared::Model::RegexRedux {
        return rust_regex_redux_oracle(&benchmark.haystack).map(|receipt| receipt.final_length);
    }
    let regex = compile_stock_rebar_regex(benchmark)?;
    match benchmark.model {
        shared::Model::Compile | shared::Model::Count => {
            u64::try_from(regex.find_iter(&benchmark.haystack).count())
                .map_err(|_| "Rust Rebar Count oracle overflow".to_owned())
        }
        shared::Model::SpanSum => {
            regex
                .find_iter(&benchmark.haystack)
                .try_fold(0_u64, |sum, matched| {
                    let width = u64::try_from(matched.end().saturating_sub(matched.start()))
                        .map_err(|_| "Rust Rebar span width overflow".to_owned())?;
                    sum.checked_add(width)
                        .ok_or_else(|| "Rust Rebar SpanSum oracle overflow".to_owned())
                })
        }
        shared::Model::CountCaptures => stock_capture_count_domain(&regex, &benchmark.haystack),
        shared::Model::GrepCount => benchmark.haystack.lines().try_fold(0_u64, |count, line| {
            if regex.is_match(line) {
                count
                    .checked_add(1)
                    .ok_or_else(|| "Rust Rebar GrepCount oracle overflow".to_owned())
            } else {
                Ok(count)
            }
        }),
        shared::Model::GrepCaptures => benchmark.haystack.lines().try_fold(0_u64, |count, line| {
            count
                .checked_add(stock_capture_count_domain(&regex, line)?)
                .ok_or_else(|| "Rust Rebar grep-captures oracle overflow".to_owned())
        }),
        shared::Model::RegexRedux => unreachable!("regex-redux oracle returned above"),
    }
}

fn require_expected(actual: u64, expected: u64) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "linked AOT reducer returned {actual}, Rust Rebar oracle returned {expected}"
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn byte_regex(pattern: &str) -> Regex {
        Regex::builder()
            .configure(Regex::config().utf8_empty(false))
            .syntax(
                regex_automata::util::syntax::Config::new()
                    .utf8(false)
                    .unicode(false),
            )
            .build(pattern)
            .expect("test byte regex")
    }

    fn benchmark(model: shared::Model, haystack: &[u8]) -> shared::Benchmark {
        shared::Benchmark {
            name: "test/model/aot".to_owned(),
            model,
            patterns: if model == shared::Model::RegexRedux {
                Vec::new()
            } else {
                vec!["a+".to_owned()]
            },
            case_insensitive: false,
            unicode: false,
            haystack: haystack.to_vec(),
            max_iters: 1,
            max_warmup_iters: 0,
            max_time: Duration::from_secs(1),
            max_warmup_time: Duration::ZERO,
        }
    }

    #[test]
    fn independent_oracle_covers_all_current_scalar_models() {
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::Compile, b"baa x aaa")).unwrap(),
            2
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::Count, b"baa x aaa")).unwrap(),
            2
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::SpanSum, b"baa x aaa")).unwrap(),
            5
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::CountCaptures, b"baa x aaa")).unwrap(),
            2
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::GrepCount, b"aa\r\nno\na")).unwrap(),
            2
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::GrepCaptures, b"aa\r\nno\na")).unwrap(),
            2
        );
        assert_eq!(
            rust_oracle(&benchmark(shared::Model::RegexRedux, b">test\nagggtaaa\n")).unwrap(),
            8
        );
    }

    #[test]
    fn independent_capture_oracle_counts_participating_groups_and_pattern_priority() {
        let mut single = benchmark(shared::Model::CountCaptures, b"baa x aaa");
        single.patterns = vec!["(a+)".to_owned()];
        assert_eq!(rust_oracle(&single).unwrap(), 4);

        let mut ordered_many = single.clone();
        ordered_many.patterns = vec!["a+".to_owned(), "(a+)".to_owned()];
        assert_eq!(rust_oracle(&ordered_many).unwrap(), 2);

        let mut per_line = single;
        per_line.model = shared::Model::GrepCaptures;
        per_line.haystack = b"aa\r\nno\na".to_vec();
        assert_eq!(rust_oracle(&per_line).unwrap(), 4);
    }

    #[test]
    fn independent_capture_oracle_preserves_empty_matches_and_empty_groups() {
        let mut nullable = benchmark(shared::Model::CountCaptures, b"abc");
        nullable.patterns = vec!["(.*)".to_owned()];
        assert_eq!(rust_oracle(&nullable), Ok(2));

        nullable.haystack = b"".to_vec();
        assert_eq!(rust_oracle(&nullable), Ok(2));

        let mut empty_group = benchmark(shared::Model::CountCaptures, b"b");
        empty_group.patterns = vec!["(a*)b".to_owned()];
        assert_eq!(rust_oracle(&empty_group), Ok(2));
        empty_group.patterns = vec!["(a*)".to_owned()];
        assert_eq!(rust_oracle(&empty_group), Ok(4));

        let mut byte_empty = benchmark(shared::Model::CountCaptures, &[0xC3, 0xA9]);
        byte_empty.patterns = vec!["()".to_owned()];
        assert_eq!(rust_oracle(&byte_empty), Ok(6));
    }

    #[test]
    fn regex_redux_independent_oracle_seals_report_receipt_and_final_bytes() {
        let actual = rust_regex_redux_oracle(b">test\nagggtaaa\n")
            .expect("independent fixed regex-redux pipeline");
        let expected_report = concat!(
            "agggtaaa|tttaccct 1\n",
            "[cgt]gggtaaa|tttaccc[acg] 0\n",
            "a[act]ggtaaa|tttacc[agt]t 0\n",
            "ag[act]gtaaa|tttac[agt]ct 0\n",
            "agg[act]taaa|ttta[agt]cct 0\n",
            "aggg[acg]aaa|ttt[cgt]ccct 0\n",
            "agggt[cgt]aa|tt[acg]accct 0\n",
            "agggta[cgt]a|t[acg]taccct 0\n",
            "agggtaa[cgt]|[acg]ttaccct 0\n",
            "\n15\n8\n8\n",
        );
        assert_eq!(actual.input_length, 15);
        assert_eq!(actual.clean_length, 8);
        assert_eq!(actual.variant_counts, [1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(actual.substitution_lengths, [8; 5]);
        assert_eq!(actual.final_length, 8);
        assert_eq!(actual.final_bytes, b"agggtaaa");
        assert_eq!(actual.report, expected_report);
        assert_eq!(
            actual.report_length,
            u64::try_from(expected_report.len()).expect("fixed report length fits u64")
        );
        let cascade = b">x\ntHaNaNDaNStBY<abc>|xy|\n";
        let cascade = rust_regex_redux_oracle(cascade).expect("ordered substitution cascade");
        assert_eq!(cascade.substitution_lengths, [16, 16, 18, 10, 7]);
        assert_eq!(cascade.final_bytes, b"||-<abc".as_slice());
        assert_eq!(
            std::mem::size_of::<NativeRegexReduxRequestV1>(),
            fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_REQUEST_BYTES
        );
        assert_eq!(
            std::mem::size_of::<NativeRegexReduxRunReceiptV1>(),
            fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_RECEIPT_BYTES
        );
        assert_eq!(poisoned_regex_redux_receipt().report_length, u64::MAX);
    }

    #[test]
    fn direct_linked_iteration_matches_rebar_empty_progress_windows() {
        let cases: &[(&str, &[u8], u64, &[usize])] = &[
            ("", b"", 0, &[0]),
            ("", &[0xC3, 0xA9], 0, &[0, 1, 2]),
            ("a|", b"a", 1, &[0, 1]),
            ("a?", b"ba", 1, &[0, 1, 2]),
            ("(?:ab|)", b"xab", 2, &[0, 1, 3]),
        ];
        for &(pattern, haystack, expected_sum, expected_starts) in cases {
            let regex = byte_regex(pattern);
            let mut starts = Vec::new();
            let actual = strict_span_sum_with_search(haystack.len(), |start| {
                starts.push(start);
                Ok(regex
                    .find(regex_automata::Input::new(haystack).span(start..haystack.len()))
                    .map(|matched| FreAotRegexResultV1 {
                        start: matched.start(),
                        end: matched.end(),
                    }))
            })
            .expect("strict direct iteration");
            assert_eq!(actual, expected_sum, "pattern={pattern:?}");
            assert_eq!(starts, expected_starts, "pattern={pattern:?}");
        }
    }

    fn independent_row_reduce(
        patterns: &[&str],
        haystack: &[u8],
        reducer: SpanScalarReducer,
    ) -> Result<u64, String> {
        let rows = patterns
            .iter()
            .map(|pattern| byte_regex(pattern))
            .collect::<Vec<_>>();
        strict_scalar_with_search(haystack.len(), reducer, |window_start| {
            search_native_rows_with(rows.len(), haystack.len(), window_start, |row, result| {
                let matched = rows[row]
                    .find(regex_automata::Input::new(haystack).span(window_start..haystack.len()));
                if let Some(matched) = matched {
                    *result = FreAotRegexResultV1 {
                        start: matched.start(),
                        end: matched.end(),
                    };
                    Ok(STATUS_MATCH)
                } else {
                    Ok(STATUS_NO_MATCH)
                }
            })
        })
    }

    fn independent_row_grep(patterns: &[&str], haystack: &[u8]) -> Result<u64, String> {
        let rows = patterns
            .iter()
            .map(|pattern| byte_regex(pattern))
            .collect::<Vec<_>>();
        strict_grep_with_search(haystack, |line| {
            search_native_rows_with(rows.len(), line.len(), 0, |row, result| {
                let matched = rows[row].find(line);
                if let Some(matched) = matched {
                    *result = FreAotRegexResultV1 {
                        start: matched.start(),
                        end: matched.end(),
                    };
                    Ok(STATUS_MATCH)
                } else {
                    Ok(STATUS_NO_MATCH)
                }
            })
            .map(|matched| matched.is_some())
        })
    }

    fn independent_uniform_capture_count(
        patterns: &[&str],
        group_counts: &[u64],
        haystack: &[u8],
    ) -> Result<u64, String> {
        let rows = patterns
            .iter()
            .map(|pattern| byte_regex(pattern))
            .collect::<Vec<_>>();
        strict_uniform_capture_count_domain_with(
            group_counts,
            haystack,
            |row, window_start, result| {
                let matched = rows[row]
                    .find(regex_automata::Input::new(haystack).span(window_start..haystack.len()));
                if let Some(matched) = matched {
                    *result = FreAotRegexResultV1 {
                        start: matched.start(),
                        end: matched.end(),
                    };
                    Ok(STATUS_MATCH)
                } else {
                    Ok(STATUS_NO_MATCH)
                }
            },
        )
    }

    fn independent_participation_capture_count(
        pattern: &str,
        haystack: &[u8],
    ) -> Result<u64, String> {
        let regex = byte_regex(pattern);
        let expected = regex
            .captures_iter(Input::new(haystack))
            .map(|captures| {
                let matched = captures
                    .get_match()
                    .expect("captures iterator always publishes group zero");
                let groups = (0..captures.group_len())
                    .filter(|&group| captures.get_group(group).is_some())
                    .count();
                (
                    FreAotRegexResultV1 {
                        start: matched.start(),
                        end: matched.end(),
                    },
                    u64::try_from(groups).expect("small synthetic group count fits u64"),
                )
            })
            .collect::<Vec<_>>();
        let mut replay = 0_usize;
        let total = strict_participation_capture_count_domain_with(
            haystack.len(),
            |window_start| {
                Ok(regex
                    .find(Input::new(haystack).span(window_start..haystack.len()))
                    .map(|matched| FreAotRegexResultV1 {
                        start: matched.start(),
                        end: matched.end(),
                    }))
            },
            |selected| {
                let Some(&(expected_span, groups)) = expected.get(replay) else {
                    return Err("selector published more spans than capture oracle".to_owned());
                };
                if selected != expected_span {
                    return Err(format!(
                        "selector span {selected:?} differs from exact replay span {expected_span:?}"
                    ));
                }
                replay += 1;
                Ok(groups)
            },
        )?;
        if replay != expected.len() {
            return Err("selector published fewer spans than capture oracle".to_owned());
        }
        Ok(total)
    }

    #[test]
    fn selector_first_capture_fallback_skips_negatives_and_fails_closed() {
        let selector = byte_regex(r"(a)(b)?");
        let stock = byte_regex(r"(a)(b)?");
        let mut positive_calls = 0_usize;
        let actual = strict_selector_capture_grep_reduce_with(
            b"no\nab\nx\naba",
            |line, result| {
                if let Some(matched) = selector.find(line) {
                    *result = FreAotRegexResultV1 {
                        start: matched.start(),
                        end: matched.end(),
                    };
                    Ok(STATUS_MATCH)
                } else {
                    Ok(STATUS_NO_MATCH)
                }
            },
            |line| {
                positive_calls += 1;
                stock_capture_count_domain(&stock, line)
            },
        )
        .expect("selector-first exact positive fallback");
        assert_eq!(actual, 8);
        assert_eq!(positive_calls, 2);

        let cross_line = byte_regex("a\\nb");
        let mut impossible_fallback_calls = 0_usize;
        assert_eq!(
            strict_selector_capture_grep_reduce_with(
                b"a\nb\nnone",
                |line, result| {
                    if let Some(matched) = cross_line.find(line) {
                        *result = FreAotRegexResultV1 {
                            start: matched.start(),
                            end: matched.end(),
                        };
                        Ok(STATUS_MATCH)
                    } else {
                        Ok(STATUS_NO_MATCH)
                    }
                },
                |_line| {
                    impossible_fallback_calls += 1;
                    Ok(99)
                },
            ),
            Ok(0),
        );
        assert_eq!(impossible_fallback_calls, 0);

        let mut fallback_calls = 0_usize;
        assert!(
            strict_selector_capture_grep_reduce_with(
                b"line",
                |_line, _result| Ok(STATUS_INVALID_ARGUMENT),
                |_line| {
                    fallback_calls += 1;
                    Ok(1)
                },
            )
            .is_err()
        );
        assert_eq!(fallback_calls, 0);
        assert!(
            strict_selector_capture_grep_reduce_with(
                b"line",
                |_line, result| {
                    *result = FreAotRegexResultV1 { start: 0, end: 5 };
                    Ok(STATUS_MATCH)
                },
                |_line| Ok(1),
            )
            .is_err()
        );
    }

    #[test]
    fn independent_native_rows_match_build_many_priority_and_empty_progress() {
        let cases: &[(&[&str], &[u8])] = &[
            (&["a", "ab"], b"ab a"),
            (&["ab", "a"], b"ab a"),
            (&["b+", "a+"], b"aa bb aaa"),
            (&["", "a"], b"a"),
            (&["a", ""], b"a"),
            (&["", ""], &[0xc3, 0xa9]),
            (&["(?:ab|)", "b"], b"xab"),
            (&["a?", "ba"], b"ba"),
        ];
        for &(patterns, haystack) in cases {
            let config = Regex::config().utf8_empty(false);
            let syntax = regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(false);
            let oracle = Regex::builder()
                .configure(config)
                .syntax(syntax)
                .build_many(patterns)
                .expect("build-many oracle");
            let expected = oracle.find_iter(haystack).collect::<Vec<_>>();
            let expected_count = u64::try_from(expected.len()).expect("small match count");
            let expected_sum = expected.iter().try_fold(0_u64, |sum, matched| {
                let width =
                    u64::try_from(matched.end() - matched.start()).expect("small match width");
                sum.checked_add(width).ok_or("small span sum overflow")
            });
            assert_eq!(
                independent_row_reduce(patterns, haystack, SpanScalarReducer::Count),
                Ok(expected_count),
                "Count patterns={patterns:?} haystack={haystack:?}"
            );
            assert_eq!(
                independent_row_reduce(patterns, haystack, SpanScalarReducer::SpanSum),
                expected_sum.map_err(str::to_owned),
                "SpanSum patterns={patterns:?} haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn independent_native_rows_match_build_many_grep_line_domains() {
        let cases: &[(&[&str], &[u8])] = &[
            (&["z+", "ab", "a", "ab", "q+"], b"none\nabx\nzz\nq"),
            (&["a$", "z+"], b"a\r\nza\nno\n"),
            (&["", "never"], b"one\n\ntwo"),
            (&["never", "(?:ab|)"], &[0xc3, 0xa9, b'\n', b'x']),
        ];
        for &(patterns, haystack) in cases {
            let config = Regex::config().utf8_empty(false);
            let syntax = regex_automata::util::syntax::Config::new()
                .utf8(false)
                .unicode(false);
            let oracle = Regex::builder()
                .configure(config)
                .syntax(syntax)
                .build_many(patterns)
                .expect("build-many grep oracle");
            let expected = haystack.lines().try_fold(0_u64, |count, line| {
                if oracle.is_match(line) {
                    count.checked_add(1).ok_or("small grep count overflow")
                } else {
                    Ok(count)
                }
            });
            assert_eq!(
                independent_row_grep(patterns, haystack),
                expected.map_err(str::to_owned),
                "GrepCount patterns={patterns:?} haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn uniform_capture_rows_multiply_the_winning_source_priority() {
        assert_eq!(
            independent_uniform_capture_count(&["a+", "(a+)"], &[1, 2], b"aa x aaa"),
            Ok(2),
        );
        assert_eq!(
            independent_uniform_capture_count(&["(a+)", "a+"], &[2, 1], b"aa x aaa"),
            Ok(4),
        );
        assert_eq!(
            independent_uniform_capture_count(&["z+", "(a+)"], &[1, 2], b"aa x aaa"),
            Ok(4),
        );
    }

    #[test]
    fn exact_span_participation_loop_matches_synthetic_capture_differentials() {
        let cases: &[(&str, &[u8])] = &[
            (r"(a)?b", b"ab b bb"),
            (r"(?:(a)|(ab))(b)?", b"ab a abb"),
            (r"((?:ab)+)(c)?", b"ab abc abab ababc"),
            (r"(a*)", b"baaa"),
            (r"()", &[0xff, b'a']),
            (r"(?-u:(\xFF)?)(b+)", &[0xff, b'b', b'b', b' ', b'b']),
        ];
        for &(pattern, haystack) in cases {
            let regex = byte_regex(pattern);
            let expected = regex
                .captures_iter(Input::new(haystack))
                .try_fold(0_u64, |total, captures| {
                    let groups = (0..captures.group_len())
                        .filter(|&group| captures.get_group(group).is_some())
                        .count();
                    total.checked_add(u64::try_from(groups).expect("small group count"))
                })
                .expect("small capture total");
            assert_eq!(
                independent_participation_capture_count(pattern, haystack),
                Ok(expected),
                "pattern={pattern:?} haystack={haystack:?}",
            );
        }
    }

    #[test]
    fn exact_span_participation_grep_restarts_each_byte_line() {
        let pattern = r"(a)?b";
        let haystack = b"ab\nbb\nnone\nb";
        let actual = haystack.lines().try_fold(0_u64, |total, line| {
            total
                .checked_add(independent_participation_capture_count(pattern, line)?)
                .ok_or_else(|| "small grep participation total overflowed".to_owned())
        });
        let regex = byte_regex(pattern);
        let expected = haystack.lines().try_fold(0_u64, |total, line| {
            regex
                .captures_iter(Input::new(line))
                .try_fold(total, |subtotal, captures| {
                    let groups = (0..captures.group_len())
                        .filter(|&group| captures.get_group(group).is_some())
                        .count();
                    subtotal
                        .checked_add(u64::try_from(groups).expect("small group count"))
                        .ok_or_else(|| "small oracle total overflowed".to_owned())
                })
        });
        assert_eq!(actual, expected);
    }

    #[test]
    fn exact_span_participation_loop_fails_closed_on_invalid_replay() {
        let zero = strict_participation_capture_count_domain_with(
            1,
            |_start| Ok(Some(FreAotRegexResultV1 { start: 0, end: 1 })),
            |_matched| Ok(0),
        )
        .expect_err("group zero is mandatory");
        assert!(zero.contains("group zero"), "{zero}");

        let invalid = strict_participation_capture_count_domain_with(
            1,
            |_start| Ok(Some(FreAotRegexResultV1 { start: 0, end: 2 })),
            |_matched| Ok(1),
        )
        .expect_err("selector span must remain in bounds");
        assert!(invalid.contains("invalid span"), "{invalid}");
    }

    #[test]
    fn grep_capture_rows_restart_the_span_selector_for_each_rebar_line() {
        let haystack = b"a\r\nxa\nno-final-match";
        let actual = haystack.lines().try_fold(0_u64, |total, line| {
            total
                .checked_add(independent_uniform_capture_count(
                    &["(a\\r?$)"],
                    &[2],
                    line,
                )?)
                .ok_or_else(|| "test capture total overflowed".to_owned())
        });
        assert_eq!(actual, Ok(4));
        assert_eq!(
            independent_uniform_capture_count(&["(a\\r?$)"], &[2], haystack),
            Ok(0),
            "whole-haystack selection is not a grep-captures substitute"
        );
    }

    #[test]
    fn uniform_capture_rows_fail_closed_on_empty_or_invalid_receipts() {
        let empty = strict_uniform_capture_count_domain_with(&[1], b"x", |_row, _start, result| {
            *result = FreAotRegexResultV1 { start: 0, end: 0 };
            Ok(STATUS_MATCH)
        })
        .expect_err("positive-width receipt must be rechecked at runtime");
        assert!(empty.contains("positive-width proof"), "{empty}");

        let zero = strict_uniform_capture_count_domain_with(&[0], b"x", |_row, _start, _result| {
            Ok(STATUS_NO_MATCH)
        })
        .expect_err("group zero makes every valid multiplier positive");
        assert!(zero.contains("contain zero"), "{zero}");
    }

    #[test]
    fn strict_capture_slots_and_iterator_state_fail_closed() {
        let valid = [
            FreAotRegexCaptureSlotV1 { start: 1, end: 4 },
            FreAotRegexCaptureSlotV1 { start: 2, end: 2 },
            FreAotRegexCaptureSlotV1::UNMATCHED,
        ];
        assert_eq!(strict_capture_row_participation(5, &valid), Ok(2));

        for invalid in [
            vec![
                FreAotRegexCaptureSlotV1 { start: 1, end: 4 },
                FreAotRegexCaptureSlotV1 {
                    start: usize::MAX,
                    end: 2,
                },
            ],
            vec![
                FreAotRegexCaptureSlotV1 { start: 1, end: 4 },
                FreAotRegexCaptureSlotV1 { start: 0, end: 2 },
            ],
            vec![
                FreAotRegexCaptureSlotV1 { start: 1, end: 4 },
                FreAotRegexCaptureSlotV1 { start: 2, end: 5 },
            ],
        ] {
            assert!(strict_capture_row_participation(5, &invalid).is_err());
        }
        assert!(strict_capture_row_participation(5, &[]).is_err());

        assert!(validate_strict_capture_state(FreAotRegexIterStateV1::default(), 5).is_ok());
        assert!(
            validate_strict_capture_state(
                FreAotRegexIterStateV1 {
                    next_start: 6,
                    ..FreAotRegexIterStateV1::default()
                },
                5,
            )
            .is_err()
        );
        assert!(
            validate_strict_capture_state(
                FreAotRegexIterStateV1 {
                    next_start: 2,
                    last_match_end: 2,
                    flags: ITER_PENDING_EMPTY,
                    reserved: 0,
                },
                5,
            )
            .is_err()
        );
    }

    #[test]
    fn native_row_selector_keeps_priority_endpoint_and_activates_later_negative_entry() {
        let mut calls = Vec::new();
        let selected = search_native_rows_with(3, 8, 0, |row, result| {
            calls.push(row);
            match row {
                0 => {
                    *result = FreAotRegexResultV1 { start: 2, end: 7 };
                    Ok(STATUS_MATCH)
                }
                1 => {
                    *result = FreAotRegexResultV1 { start: 2, end: 3 };
                    Ok(STATUS_MATCH)
                }
                2 => Ok(STATUS_NO_MATCH),
                _ => unreachable!(),
            }
        })
        .expect("ordered row selection");
        assert_eq!(selected, Some(FreAotRegexResultV1 { start: 2, end: 7 }));
        assert_eq!(calls, [0, 1, 2]);

        let mut calls = Vec::new();
        let selected = search_native_rows_with(2, 8, 0, |row, result| {
            calls.push(row);
            if row == 0 {
                Ok(STATUS_NO_MATCH)
            } else {
                *result = FreAotRegexResultV1 { start: 4, end: 5 };
                Ok(STATUS_MATCH)
            }
        })
        .expect("later entry activation");
        assert_eq!(selected, Some(FreAotRegexResultV1 { start: 4, end: 5 }));
        assert_eq!(calls, [0, 1]);
    }

    #[test]
    fn native_row_selector_rejects_bad_status_and_invalid_losing_span() {
        let invalid = search_native_rows_with(2, 4, 0, |row, result| {
            *result = if row == 0 {
                FreAotRegexResultV1 { start: 0, end: 1 }
            } else {
                FreAotRegexResultV1 { start: 3, end: 5 }
            };
            Ok(STATUS_MATCH)
        })
        .expect_err("invalid losing row cannot be hidden");
        assert!(invalid.contains("invalid span"), "{invalid}");

        let status = search_native_rows_with(2, 4, 0, |row, _| {
            if row == 0 {
                Ok(STATUS_NO_MATCH)
            } else {
                Ok(STATUS_INVALID_ARGUMENT)
            }
        })
        .expect_err("bad later-row status cannot be hidden");
        assert!(status.contains("row 1"), "{status}");
        assert!(status.contains("status"), "{status}");
    }

    #[test]
    fn multi_row_grep_helper_matches_every_rebar_line_domain_once() {
        let regex = byte_regex("a+");
        let haystack = b"aa\r\nno\na\n\n";
        let mut observed = Vec::new();
        let actual = strict_grep_with_search(haystack, |line| {
            observed.push(line.to_vec());
            Ok(regex.is_match(line))
        })
        .expect("strict multi-row grep helper");
        assert_eq!(actual, 2);
        assert_eq!(
            observed,
            [
                b"aa".as_slice(),
                b"no".as_slice(),
                b"a".as_slice(),
                b"".as_slice()
            ]
        );
    }

    #[test]
    fn configured_parser_rejects_object_emission_as_rebar_compile() {
        let mut klv = Vec::new();
        for (key, value) in [
            ("name", b"test/compile".as_slice()),
            ("model", b"compile".as_slice()),
            ("pattern", b"a+".as_slice()),
            ("case-insensitive", b"false".as_slice()),
            ("unicode", b"false".as_slice()),
            ("haystack", b"aa".as_slice()),
            ("max-iters", b"1".as_slice()),
            ("max-warmup-iters", b"0".as_slice()),
            ("max-time", b"1".as_slice()),
            ("max-warmup-time", b"0".as_slice()),
        ] {
            klv.extend_from_slice(format!("{key}:{}:", value.len()).as_bytes());
            klv.extend_from_slice(value);
            klv.push(b'\n');
        }
        assert!(
            shared::Benchmark::parse(&klv)
                .expect_err("object emission is not Rebar compile")
                .contains("not a search-ready Rebar compile")
        );
    }

    #[test]
    fn strict_span_accumulator_rejects_non_rebar_sequences() {
        let mut overlap = StrictSpanAccumulator::new(8);
        overlap
            .push(FreAotRegexResultV1 { start: 1, end: 4 })
            .expect("first span");
        assert!(
            overlap
                .push(FreAotRegexResultV1 { start: 3, end: 5 })
                .is_err()
        );

        let mut adjacent_empty = StrictSpanAccumulator::new(8);
        adjacent_empty
            .push(FreAotRegexResultV1 { start: 1, end: 4 })
            .expect("first span");
        assert!(
            adjacent_empty
                .push(FreAotRegexResultV1 { start: 4, end: 4 })
                .is_err()
        );
    }

    #[test]
    fn linked_span_fill_iteration_requires_the_exact_bulk_suffix() {
        for strategy in [
            "RuntimeHelper",
            "NativePreparedLoop",
            "NativeTrustedPreflightLoop",
            "NativeTrustedPreflightRuntimeBulk",
            "NativeFrozenLoop",
            "NativeOrderedNfaLoop",
        ] {
            let bulk = format!("Some({strategy})");
            let iteration = format!("linked-prepared-span-fill-64::Some({strategy})");
            assert!(linked_span_fill_iteration_is_exact(&bulk, &iteration));
            assert!(!linked_span_fill_iteration_is_exact(
                &bulk,
                "linked-prepared-span-fill-64::Some(FutureLoop)",
            ));
        }
        assert!(!linked_span_fill_iteration_is_exact(
            "Some(FutureLoop)",
            "linked-prepared-span-fill-64::Some(FutureLoop)",
        ));
        assert!(!linked_span_fill_iteration_is_exact(
            "None",
            "linked-direct-entry-loop",
        ));
    }

    #[test]
    fn provenance_hex_is_fixed_width() {
        assert_eq!(hex(&[0, 1, 0xfe, 0xff]), "0001feff");
    }
}
