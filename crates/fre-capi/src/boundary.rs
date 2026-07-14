//! Panic containment and compact internal diagnostics.

use std::{
    borrow::Cow,
    panic::{AssertUnwindSafe, catch_unwind},
};

use crate::{
    FRE_V1_DIAGNOSTIC_CAPACITY, FRE_V1_DIAGNOSTIC_NONE, FRE_V1_DIAGNOSTIC_PANIC, FRE_V1_STATUS_OK,
    FRE_V1_STATUS_PANIC, FreV1Diagnostic,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Outcome {
    pub(crate) status: u32,
    pub(crate) diagnostic: Diagnostic,
}

impl Outcome {
    pub(crate) fn ok() -> Self {
        Self {
            status: FRE_V1_STATUS_OK,
            diagnostic: Diagnostic::clear(),
        }
    }

    pub(crate) fn failure(
        status: u32,
        category: u32,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            status,
            diagnostic: Diagnostic::new(category, message),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Diagnostic {
    category: u32,
    message: Cow<'static, str>,
}

impl Diagnostic {
    pub(crate) fn clear() -> Self {
        Self {
            category: FRE_V1_DIAGNOSTIC_NONE,
            message: Cow::Borrowed(""),
        }
    }

    pub(crate) fn new(category: u32, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }

    pub(crate) fn record(&self) -> FreV1Diagnostic {
        let mut record = FreV1Diagnostic::caller_init();
        record.category = self.category;
        let bytes = self.message.as_bytes();
        let maximum = FRE_V1_DIAGNOSTIC_CAPACITY.saturating_sub(1);
        let copied = bytes.len().min(maximum);
        record.message[..copied].copy_from_slice(&bytes[..copied]);
        record.message[copied] = 0;
        record.message_length = u32::try_from(copied).expect("fixed diagnostic length fits u32");
        record.message_truncated = u32::from(bytes.len() > maximum);
        record
    }
}

pub(crate) fn invoke(operation: impl FnOnce() -> Outcome) -> Outcome {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(outcome) => outcome,
        Err(_) => Outcome::failure(
            FRE_V1_STATUS_PANIC,
            FRE_V1_DIAGNOSTIC_PANIC,
            "Rust panic stopped at the FRE C ABI boundary",
        ),
    }
}

pub(crate) fn invoke_status(operation: impl FnOnce() -> u32) -> u32 {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(FRE_V1_STATUS_PANIC)
}
