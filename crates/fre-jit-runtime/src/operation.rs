use fre_jit_aarch64::{NativeAggregateResult, NativeResult};
use fre_kernel_ir::{
    AggregateOperation, AggregateOutput, Count, Exists, MatchSpan, Operation, OutputKind,
    SearchWindow, SelectedEnd, Span, SpanSum,
};

use crate::CallError;

mod sealed {
    use fre_jit_aarch64::{NativeAggregateResult, NativeResult};
    use fre_kernel_ir::{AggregateOperation, Operation, SearchWindow};

    use crate::CallError;

    pub trait Sealed: Operation {
        fn decode(
            status: u64,
            slot: NativeResult,
            window: SearchWindow,
        ) -> Result<Self::Output, CallError>;
    }

    pub trait AggregateSealed: AggregateOperation<Output = u64> {
        fn decode(
            status: u64,
            slot: NativeAggregateResult,
            haystack_len: usize,
            literal_len: usize,
        ) -> Result<u64, CallError>;
    }
}

/// Output types admitted at the native ABI boundary.
pub trait RuntimeOperation: Operation + sealed::Sealed {}

/// Aggregate operations admitted at the distinct three-argument native ABI.
pub trait RuntimeAggregateOperation:
    AggregateOperation<Output = u64> + sealed::AggregateSealed
{
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawCallResult {
    pub(crate) status: u64,
    pub(crate) slot: NativeResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawAggregateCallResult {
    pub(crate) status: u64,
    pub(crate) slot: NativeAggregateResult,
}

impl sealed::Sealed for Exists {
    fn decode(
        status: u64,
        _slot: NativeResult,
        _window: SearchWindow,
    ) -> Result<Self::Output, CallError> {
        decode_status(status)
    }
}

impl sealed::Sealed for SelectedEnd {
    fn decode(
        status: u64,
        slot: NativeResult,
        window: SearchWindow,
    ) -> Result<Self::Output, CallError> {
        if !decode_status(status)? {
            return Ok(None);
        }
        if slot.end < window.start() || slot.end > window.end() {
            return Err(invalid(OutputKind::SelectedEnd, slot, window));
        }
        Ok(Some(slot.end))
    }
}

impl sealed::Sealed for Span {
    fn decode(
        status: u64,
        slot: NativeResult,
        window: SearchWindow,
    ) -> Result<Self::Output, CallError> {
        if !decode_status(status)? {
            return Ok(None);
        }
        if slot.start > slot.end || slot.start < window.start() || slot.end > window.end() {
            return Err(invalid(OutputKind::Span, slot, window));
        }
        Ok(Some(MatchSpan::new(slot.start, slot.end)))
    }
}

impl RuntimeOperation for Exists {}
impl RuntimeOperation for SelectedEnd {}
impl RuntimeOperation for Span {}

impl sealed::AggregateSealed for Count {
    fn decode(
        status: u64,
        slot: NativeAggregateResult,
        haystack_len: usize,
        literal_len: usize,
    ) -> Result<u64, CallError> {
        decode_aggregate_status(status)?;
        let upper = if literal_len == 0 {
            haystack_len.checked_add(1)
        } else {
            haystack_len.checked_div(literal_len)
        }
        .and_then(|value| u64::try_from(value).ok());
        if upper.is_none_or(|upper| slot.value > upper) {
            return Err(invalid_aggregate(
                AggregateOutput::Count,
                slot.value,
                haystack_len,
                literal_len,
            ));
        }
        Ok(slot.value)
    }
}

impl sealed::AggregateSealed for SpanSum {
    fn decode(
        status: u64,
        slot: NativeAggregateResult,
        haystack_len: usize,
        literal_len: usize,
    ) -> Result<u64, CallError> {
        decode_aggregate_status(status)?;
        let valid = if literal_len == 0 {
            slot.value == 0
        } else {
            u64::try_from(haystack_len).is_ok_and(|length| slot.value <= length)
                && u64::try_from(literal_len).is_ok_and(|width| slot.value.is_multiple_of(width))
        };
        if !valid {
            return Err(invalid_aggregate(
                AggregateOutput::SpanSum,
                slot.value,
                haystack_len,
                literal_len,
            ));
        }
        Ok(slot.value)
    }
}

impl RuntimeAggregateOperation for Count {}
impl RuntimeAggregateOperation for SpanSum {}

pub(crate) fn decode<O: RuntimeOperation>(
    raw: RawCallResult,
    window: SearchWindow,
) -> Result<O::Output, CallError> {
    <O as sealed::Sealed>::decode(raw.status, raw.slot, window)
}

pub(crate) fn decode_aggregate<A: RuntimeAggregateOperation>(
    raw: RawAggregateCallResult,
    haystack_len: usize,
    literal_len: usize,
) -> Result<u64, CallError> {
    <A as sealed::AggregateSealed>::decode(raw.status, raw.slot, haystack_len, literal_len)
}

fn decode_status(status: u64) -> Result<bool, CallError> {
    match status {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CallError::BackendFault { status }),
    }
}

fn decode_aggregate_status(status: u64) -> Result<(), CallError> {
    match status {
        0 => Ok(()),
        1 => Err(CallError::AggregateArithmeticOverflow),
        _ => Err(CallError::AggregateBackendFault { status }),
    }
}

const fn invalid(output: OutputKind, slot: NativeResult, window: SearchWindow) -> CallError {
    CallError::InvalidNativeOutput {
        output,
        start: slot.start,
        end: slot.end,
        window_start: window.start(),
        window_end: window.end(),
    }
}

const fn invalid_aggregate(
    output: AggregateOutput,
    value: u64,
    haystack_len: usize,
    literal_len: usize,
) -> CallError {
    CallError::InvalidNativeAggregateOutput {
        output,
        value,
        haystack_len,
        literal_len,
    }
}
