use core::fmt;

use fre_aot_count_contract::{CountMetadataErrorV2, StaticCountExpectationErrorV2};
use fre_aot_search_contract::{SearchMetadataErrorV1, StaticSearchSpanExpectationErrorV1};
use fre_kernel_ir::AggregateExecuteError;
use fre_kernels::LiteralError;

/// One independently checked field in the Count-v2 static contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticContractField {
    CompiledObjectBytes,
    Metadata,
    ObjectAccounting,
    ExpectationAccounting,
    Support,
    ManifestIdentity,
    PolicyLimitsIdentity,
    SemanticBindingIdentity,
    PlanningReceiptIdentity,
    LiveLiteralIdentity,
    LiveLiteralBytes,
    ProgramIdentity,
    ImageIdentity,
    ObjectBindingIdentity,
    CompileIdentity,
    ObjectIdentity,
    ReceiptIdentity,
    ResourceReceiptIdentity,
    ExpectationIdentity,
    SelectedCompileIdentity,
}

/// Refusal before a statically linked Count-v2 entry can be published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticVerifyError {
    /// This build contains no final-image-qualified support row.
    NoQualifiedStaticCountRowV2,
    /// A glue-provided row selector did not select the exact literal row.
    UnqualifiedStaticCountSelectorV2,
    /// The private qualification table is oversized, duplicated, or unordered.
    MalformedStaticCountQualificationTableV2,
    /// A fixed 672-byte expectation failed canonical inspection.
    Expectation(StaticCountExpectationErrorV2),
    /// A fixed 232-byte mapped metadata record failed strict decoding.
    Metadata(CountMetadataErrorV2),
    /// One independently bound contract field did not match.
    ContractMismatch {
        field: StaticContractField,
    },
    /// Checked inspection accounting overflowed.
    InspectionAccountingOverflow,
    UnsupportedHost,
    LinkedCountFeatureDisabled,
    AddressRangeOverflow,
    VmRegionQueryFailed {
        code: i32,
    },
    VmRegionDoesNotCoverRange,
    LiveVmRegionIsNotPrivate,
    PayloadProtectionMismatch {
        protection: i32,
        maximum_protection: i32,
    },
    MetadataProtectionMismatch {
        protection: i32,
        maximum_protection: i32,
    },
    ExpectationProtectionMismatch {
        protection: i32,
        maximum_protection: i32,
    },
    RequiredCpuFeaturesUnavailable,
    MappedPayloadExtentOutOfBounds {
        claimed: usize,
        hard_maximum: usize,
    },
    EntryAddressOverflow,
    EntryAddressMismatch,
    MappedPayloadDigestMismatch,
    AlreadyInitializedForDifferentExpectation,
    AlreadyInitializedForDifferentSymbols,
    StaticRegistryFull {
        limit: usize,
    },
    StaticRegistryReentrantInitialization,
    StaticRegistryThreadLocalUnavailable,
    StaticRegistryInitializationPanicked,
    StaticRegistryInvariant,
}

impl fmt::Display for StaticVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Count-v2 static AOT verification failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Expectation(error) => Some(error),
            Self::Metadata(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StaticCountExpectationErrorV2> for StaticVerifyError {
    fn from(value: StaticCountExpectationErrorV2) -> Self {
        Self::Expectation(value)
    }
}

impl From<CountMetadataErrorV2> for StaticVerifyError {
    fn from(value: CountMetadataErrorV2) -> Self {
        Self::Metadata(value)
    }
}

/// Failure while retrieving one handle through linked Count-v2 glue.
///
/// This error is intentionally separate from [`StaticVerifyError`]. The C ABI
/// exposes only coarse refusal statuses, so this layer must not invent a more
/// specific verification cause than the linked adopter reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticAdoptionErrorV2 {
    /// This build contains no final-image-qualified support row.
    NoQualifiedStaticCountRow,
    /// The linked glue selected no qualified row in this build.
    UnqualifiedStaticCountSelector,
    /// The runtime refused the selected final-image tuple.
    VerificationRefused,
    /// Linked glue returned a status outside the fixed Count-v2 ABI.
    UnknownStatus { status: u32 },
    /// Glue reported success without returning a handle.
    MissingVerifiedHandle,
    /// Glue returned a pointer not owned by the authenticated static registry.
    UnregisteredVerifiedHandle,
}

impl fmt::Display for StaticAdoptionErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Count-v2 static AOT adoption failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticAdoptionErrorV2 {}

/// Failure at the safe, already-verified Count-v2 call boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CallError {
    Preflight(AggregateExecuteError),
    BackendArithmeticOverflow,
    BackendFault {
        status: u64,
    },
    NativeResultChangedOnFault {
        status: u64,
        value: u64,
    },
    PoisonedNativeResult,
    InvalidNativeCount {
        value: u64,
        haystack_len: usize,
        literal_len: usize,
    },
}

impl fmt::Display for CallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "FRE Count-v2 static AOT call failed: {self:?}")
    }
}

impl std::error::Error for CallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preflight(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AggregateExecuteError> for CallError {
    fn from(value: AggregateExecuteError) -> Self {
        Self::Preflight(value)
    }
}

/// One independently checked field in the static Search-v1 Span contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticSearchSpanContractFieldV1 {
    SelectedRow,
    ProductionFamily,
    SelectedCompileIdentity,
    ManifestIdentity,
    SemanticBindingIdentity,
    LiteralIdentity,
    LiveLiteralBytes,
    KirIdentity,
    ArtifactIdentity,
    BindingIdentity,
    CompileIdentity,
    ObjectIdentity,
    ReceiptIdentity,
    ExpectationIdentity,
    PayloadIdentity,
    Metadata,
}

/// Refusal before a statically linked Search-v1 Span entry can be published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticSearchSpanVerifyErrorV1 {
    /// This build contains no final-image-qualified production Search row.
    NoQualifiedStaticSearchSpanRowV1,
    /// A glue-provided selector did not name an exact source-qualified row.
    UnqualifiedStaticSearchSpanSelectorV1,
    /// A private Search qualification table was oversized or non-canonical.
    MalformedStaticSearchSpanQualificationTableV1,
    /// A fixed 584-byte expectation failed canonical inspection.
    Expectation(StaticSearchSpanExpectationErrorV1),
    /// A fixed 216-byte mapped metadata record failed strict decoding.
    Metadata(SearchMetadataErrorV1),
    /// One independently bound Search contract field did not match.
    ContractMismatch {
        field: StaticSearchSpanContractFieldV1,
    },
    InspectionAccountingOverflow,
    UnsupportedHost,
    LinkedSearchSpanFeatureDisabled,
    AddressRangeOverflow,
    VmRegionQueryFailed {
        code: i32,
    },
    VmRegionDoesNotCoverRange,
    LiveVmRegionIsNotPrivate,
    PayloadProtectionMismatch {
        protection: i32,
        maximum_protection: i32,
    },
    MetadataProtectionMismatch {
        protection: i32,
        maximum_protection: i32,
    },
    ExpectationProtectionMismatch {
        protection: i32,
        maximum_protection: i32,
    },
    RequiredAsimdUnavailable,
    RequiredSveUnavailable,
    RequiredSve2Unavailable,
    RequiredSveVectorLengthUnavailable {
        required_bytes: u16,
        actual_bytes: Option<u16>,
    },
    RequiredTag21TuningUnavailable,
    MappedPayloadExtentOutOfBounds {
        claimed: usize,
        hard_maximum: usize,
    },
    PayloadAddressMisaligned {
        address: usize,
        required_alignment: usize,
    },
    EntryAddressOverflow,
    EntryAddressMismatch,
    EntryAddressMisaligned {
        address: usize,
        required_alignment: usize,
    },
    MappedPayloadDigestMismatch,
    SemanticPayloadReconstruction,
    AlreadyInitializedForDifferentExpectation,
    AlreadyInitializedForDifferentSymbols,
    StaticRegistryFull {
        limit: usize,
    },
    StaticRegistryReentrantInitialization,
    StaticRegistryThreadLocalUnavailable,
    StaticRegistryInitializationPanicked,
    StaticRegistryInvariant,
}

impl fmt::Display for StaticSearchSpanVerifyErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Search-v1 Span static AOT verification failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticSearchSpanVerifyErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Expectation(error) => Some(error),
            Self::Metadata(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StaticSearchSpanExpectationErrorV1> for StaticSearchSpanVerifyErrorV1 {
    fn from(value: StaticSearchSpanExpectationErrorV1) -> Self {
        Self::Expectation(value)
    }
}

impl From<SearchMetadataErrorV1> for StaticSearchSpanVerifyErrorV1 {
    fn from(value: SearchMetadataErrorV1) -> Self {
        Self::Metadata(value)
    }
}

/// Failure while retrieving one Search-v1 Span handle through linked glue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticSearchSpanAdoptionErrorV1 {
    NoQualifiedStaticSearchSpanRow,
    UnqualifiedStaticSearchSpanSelector,
    VerificationRefused,
    UnknownStatus { status: u32 },
    MissingVerifiedHandle,
    UnregisteredVerifiedHandle,
}

impl fmt::Display for StaticSearchSpanAdoptionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Search-v1 Span static AOT adoption failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticSearchSpanAdoptionErrorV1 {}

/// Failure to establish the current-thread invocation contract for a linked
/// Search-v1 Span candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticSearchSpanThreadContractErrorV1 {
    UnsupportedHost,
    SveVectorLengthQueryFailed {
        errno: Option<i32>,
    },
    SveVectorLengthSetFailed {
        errno: Option<i32>,
    },
    RequiredSveVectorLengthUnavailable {
        required_bytes: u16,
        actual_bytes: Option<u16>,
    },
}

impl fmt::Display for StaticSearchSpanThreadContractErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Search-v1 Span thread contract failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticSearchSpanThreadContractErrorV1 {}

/// Failure at the safe, already-verified Search-v1 Span call boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticSearchSpanCallErrorV1 {
    Preflight(LiteralError),
    LiteralWidthNotRepresentable { bytes: u32 },
    ThreadSessionRequired { backend_version: u16 },
    Decode(crate::SearchCallErrorV1),
}

impl fmt::Display for StaticSearchSpanCallErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Search-v1 Span static AOT call failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticSearchSpanCallErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preflight(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::LiteralWidthNotRepresentable { .. } | Self::ThreadSessionRequired { .. } => None,
        }
    }
}

impl From<LiteralError> for StaticSearchSpanCallErrorV1 {
    fn from(value: LiteralError) -> Self {
        Self::Preflight(value)
    }
}

impl From<crate::SearchCallErrorV1> for StaticSearchSpanCallErrorV1 {
    fn from(value: crate::SearchCallErrorV1) -> Self {
        Self::Decode(value)
    }
}

pub(crate) const fn require(
    condition: bool,
    field: StaticContractField,
) -> Result<(), StaticVerifyError> {
    if condition {
        Ok(())
    } else {
        Err(StaticVerifyError::ContractMismatch { field })
    }
}

pub(crate) const fn require_search_span_v1(
    condition: bool,
    field: StaticSearchSpanContractFieldV1,
) -> Result<(), StaticSearchSpanVerifyErrorV1> {
    if condition {
        Ok(())
    } else {
        Err(StaticSearchSpanVerifyErrorV1::ContractMismatch { field })
    }
}
