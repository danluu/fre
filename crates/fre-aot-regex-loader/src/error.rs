use core::fmt;

use fre_aot_regex::{CompileError, CpuFeature, EntryAbi, OutputContract, RelocationKind, Target};

/// Resource checked before executable memory is reserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationResource {
    Sections,
    Relocations,
    CodeBytes,
    ReadOnlyDataBytes,
    ScratchBytes,
    MappedBytes,
}

/// Stage at which an operating-system publication operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationStage {
    PageSize,
    Reserve,
    MakeWritable,
    Copy,
    Relocate,
    Verify,
    ProtectText,
    ProtectReadOnlyData,
    SynchronizeInstructionCache,
    PublishEntry,
}

/// Failure to turn a compiler-owned, self-contained module into callable code.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublicationError {
    UnsupportedHost,
    TargetMismatch {
        requested: Target,
        host: Target,
    },
    CpuFeatureUnavailable {
        feature: CpuFeature,
    },
    OutputMismatch {
        expected: OutputContract,
        actual: OutputContract,
    },
    EntryAbiMismatch {
        expected: EntryAbi,
        actual: EntryAbi,
    },
    RuntimeHelperRequired {
        symbol: String,
    },
    InvalidModule {
        at: &'static str,
    },
    Resource {
        resource: PublicationResource,
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        at: &'static str,
    },
    ArithmeticOverflow {
        at: &'static str,
    },
    RelocationOutOfRange {
        index: usize,
        kind: RelocationKind,
    },
    CopyVerificationFailed,
    JitDenied {
        stage: PublicationStage,
        errno: i32,
    },
    SystemCall {
        stage: PublicationStage,
        errno: i32,
    },
}

impl fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => formatter.write_str(
                "direct FRE AOT publication requires little-endian 64-bit Linux or macOS on x86-64 or AArch64",
            ),
            Self::TargetMismatch { requested, host } => {
                write!(formatter, "compiled target {requested:?} does not match host {host:?}")
            }
            Self::CpuFeatureUnavailable { feature } => {
                write!(formatter, "compiled target requires unavailable CPU feature {feature:?}")
            }
            Self::OutputMismatch { expected, actual } => {
                write!(formatter, "compiled output is {actual:?}, expected {expected:?}")
            }
            Self::EntryAbiMismatch { expected, actual } => {
                write!(formatter, "compiled entry ABI is {actual:?}, expected {expected:?}")
            }
            Self::RuntimeHelperRequired { symbol } => {
                write!(formatter, "compiled artifact requires runtime helper {symbol:?}")
            }
            Self::InvalidModule { at } => write!(formatter, "invalid compiled module at {at}"),
            Self::Resource {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "direct AOT publication {resource:?} requires {needed}, limit is {limit}"
            ),
            Self::AllocationFailed { at } => {
                write!(formatter, "direct AOT publication allocation failed at {at}")
            }
            Self::ArithmeticOverflow { at } => {
                write!(formatter, "direct AOT publication arithmetic overflow at {at}")
            }
            Self::RelocationOutOfRange { index, kind } => {
                write!(formatter, "{kind:?} relocation {index} is out of range")
            }
            Self::CopyVerificationFailed => {
                formatter.write_str("direct AOT publication byte verification failed")
            }
            Self::JitDenied { stage, errno } => write!(
                formatter,
                "host policy denied strict-W^X publication at {stage:?} (errno {errno})"
            ),
            Self::SystemCall { stage, errno } => {
                write!(formatter, "publication system call failed at {stage:?} (errno {errno})")
            }
        }
    }
}

impl std::error::Error for PublicationError {}

/// Failure returned by a call through a published direct `Span` entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CallError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    NativeStatus {
        status: u32,
    },
    InvalidSpan {
        start: usize,
        end: usize,
        window_start: usize,
        window_end: usize,
        haystack_len: usize,
    },
}

impl fmt::Display for CallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "invalid search window {start}..{end} for haystack length {haystack_len}"
            ),
            Self::NativeStatus { status } => {
                write!(
                    formatter,
                    "direct FRE AOT entry returned failure status {status}"
                )
            }
            Self::InvalidSpan {
                start,
                end,
                window_start,
                window_end,
                haystack_len,
            } => write!(
                formatter,
                "direct FRE AOT entry returned span {start}..{end} outside window {window_start}..{window_end} and haystack length {haystack_len}"
            ),
        }
    }
}

impl std::error::Error for CallError {}

/// Combined error for the convenience compile-and-publish transaction.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    Compile(CompileError),
    Publish(PublicationError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compile(error) => write!(formatter, "direct AOT compile failed: {error}"),
            Self::Publish(error) => write!(formatter, "direct AOT publication failed: {error}"),
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compile(error) => Some(error),
            Self::Publish(error) => Some(error),
        }
    }
}

impl From<CompileError> for BuildError {
    fn from(error: CompileError) -> Self {
        Self::Compile(error)
    }
}

impl From<PublicationError> for BuildError {
    fn from(error: PublicationError) -> Self {
        Self::Publish(error)
    }
}
