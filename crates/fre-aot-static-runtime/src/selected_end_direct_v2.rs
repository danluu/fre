//! Identity-gated thread and scalar-call contracts for the Linux tag21
//! `SelectedEnd` register-return ABI2.
//!
//! This module deliberately owns no address, function pointer, symbol lookup,
//! or object adopter. Its production authority atom is a literal,
//! source-reviewed table that begins empty. The exact identity-suffixed
//! `extern` declaration and call must remain in compiler-generated consumer
//! source so a final-image checker can prove that the linker retained a direct
//! `bl`.

use core::{fmt, marker::PhantomData};
use std::rc::Rc;

use fre_kernel_ir::{CheckedSearchWindow, MatchSpan, SearchWindow};
use fre_kernels::{LiteralAccounting, LiteralPlan, LiteralSearchPreflight};

const SELECTED_END_LITERAL_BYTES_V2: usize = 16;
const SELECTED_END_FIXED_VECTOR_BYTES_V2: u16 = 16;
const HARD_MAX_STATIC_SEARCH_SELECTED_END_PRODUCTION_ROWS_V2: usize = 256;

mod production_rows;
use production_rows::PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SELECTED_END_ROWS_V2;

/// Complete lookup-only identity claims emitted into one exact generated ABI2
/// binding.
///
/// These values are not authority. The constructor accepts no address,
/// function pointer, symbol spelling, selector, or authority input. A
/// downstream caller can copy claims, but cannot create the private
/// source-reviewed row required for adoption. The generated Rust binding
/// cannot embed its own source hash or deployment-receipt identity without a
/// circular digest; source review and final-image qualification must establish
/// those external identities separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the repeated identity suffix keeps all seventeen security domains explicit"
)]
pub struct StaticSearchSelectedEndArtifactClaimsV2 {
    manifest_identity: [u8; 32],
    source_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    literal_identity: [u8; 32],
    kir_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
    full_payload_identity: [u8; 32],
    glue_source_identity: [u8; 32],
    direct_header_identity: [u8; 32],
    glue_code_identity: [u8; 32],
    glue_object_identity: [u8; 32],
    bundle_identity: [u8; 32],
    full_payload_bytes: u32,
    literal: [u8; SELECTED_END_LITERAL_BYTES_V2],
}

impl StaticSearchSelectedEndArtifactClaimsV2 {
    /// Construct the lookup claims embedded by `fre-aot-compiler`.
    ///
    /// This constructor grants no authority. Every field is compared with one
    /// complete private production row before an opaque production owner can
    /// exist.
    #[doc(hidden)]
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "generated code must name every independently reviewed identity domain"
    )]
    pub const fn compiler_generated(
        manifest_identity: [u8; 32],
        source_identity: [u8; 32],
        semantic_binding_identity: [u8; 32],
        literal_identity: [u8; 32],
        kir_identity: [u8; 32],
        artifact_identity: [u8; 32],
        binding_identity: [u8; 32],
        compile_identity: [u8; 32],
        implementation_object_identity: [u8; 32],
        compiler_receipt_identity: [u8; 32],
        expectation_identity: [u8; 32],
        full_payload_identity: [u8; 32],
        glue_source_identity: [u8; 32],
        direct_header_identity: [u8; 32],
        glue_code_identity: [u8; 32],
        glue_object_identity: [u8; 32],
        bundle_identity: [u8; 32],
        full_payload_bytes: u32,
        literal: [u8; SELECTED_END_LITERAL_BYTES_V2],
    ) -> Self {
        Self {
            manifest_identity,
            source_identity,
            semantic_binding_identity,
            literal_identity,
            kir_identity,
            artifact_identity,
            binding_identity,
            compile_identity,
            implementation_object_identity,
            compiler_receipt_identity,
            expectation_identity,
            full_payload_identity,
            glue_source_identity,
            direct_header_identity,
            glue_code_identity,
            glue_object_identity,
            bundle_identity,
            full_payload_bytes,
            literal,
        }
    }
}

macro_rules! source_qualified_identity_v2 {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct $name([u8; 32]);

        impl $name {
            const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

source_qualified_identity_v2!(SourceQualifiedManifestIdentityV2);
source_qualified_identity_v2!(SourceQualifiedSourceIdentityV2);
source_qualified_identity_v2!(SourceQualifiedSemanticBindingIdentityV2);
source_qualified_identity_v2!(SourceQualifiedLiteralIdentityV2);
source_qualified_identity_v2!(SourceQualifiedKirIdentityV2);
source_qualified_identity_v2!(SourceQualifiedArtifactIdentityV2);
source_qualified_identity_v2!(SourceQualifiedBindingIdentityV2);
source_qualified_identity_v2!(SourceQualifiedCompileIdentityV2);
source_qualified_identity_v2!(SourceQualifiedImplementationObjectIdentityV2);
source_qualified_identity_v2!(SourceQualifiedCompilerReceiptIdentityV2);
source_qualified_identity_v2!(SourceQualifiedExpectationIdentityV2);
source_qualified_identity_v2!(SourceQualifiedFullPayloadIdentityV2);
source_qualified_identity_v2!(SourceQualifiedGlueSourceIdentityV2);
source_qualified_identity_v2!(SourceQualifiedDirectHeaderIdentityV2);
source_qualified_identity_v2!(SourceQualifiedGlueCodeIdentityV2);
source_qualified_identity_v2!(SourceQualifiedGlueObjectIdentityV2);
source_qualified_identity_v2!(SourceQualifiedBundleIdentityV2);

/// One exact, source-reviewed final-image ABI2 decision.
///
/// Construction exists only in the private production authority child
/// module. Compiler output, build scripts, features, environment variables,
/// and downstream callers cannot manufacture this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the repeated identity suffix keeps all seventeen security domains explicit"
)]
struct SourceQualifiedStaticSearchSelectedEndRowV2 {
    manifest_identity: SourceQualifiedManifestIdentityV2,
    source_identity: SourceQualifiedSourceIdentityV2,
    semantic_binding_identity: SourceQualifiedSemanticBindingIdentityV2,
    literal_identity: SourceQualifiedLiteralIdentityV2,
    kir_identity: SourceQualifiedKirIdentityV2,
    artifact_identity: SourceQualifiedArtifactIdentityV2,
    binding_identity: SourceQualifiedBindingIdentityV2,
    compile_identity: SourceQualifiedCompileIdentityV2,
    implementation_object_identity: SourceQualifiedImplementationObjectIdentityV2,
    compiler_receipt_identity: SourceQualifiedCompilerReceiptIdentityV2,
    expectation_identity: SourceQualifiedExpectationIdentityV2,
    full_payload_identity: SourceQualifiedFullPayloadIdentityV2,
    glue_source_identity: SourceQualifiedGlueSourceIdentityV2,
    direct_header_identity: SourceQualifiedDirectHeaderIdentityV2,
    glue_code_identity: SourceQualifiedGlueCodeIdentityV2,
    glue_object_identity: SourceQualifiedGlueObjectIdentityV2,
    bundle_identity: SourceQualifiedBundleIdentityV2,
    full_payload_bytes: u32,
    literal: [u8; SELECTED_END_LITERAL_BYTES_V2],
}

impl SourceQualifiedStaticSearchSelectedEndRowV2 {
    fn matches(&self, claims: &StaticSearchSelectedEndArtifactClaimsV2) -> bool {
        self.manifest_identity.as_bytes() == &claims.manifest_identity
            && self.source_identity.as_bytes() == &claims.source_identity
            && self.semantic_binding_identity.as_bytes() == &claims.semantic_binding_identity
            && self.literal_identity.as_bytes() == &claims.literal_identity
            && self.kir_identity.as_bytes() == &claims.kir_identity
            && self.artifact_identity.as_bytes() == &claims.artifact_identity
            && self.binding_identity.as_bytes() == &claims.binding_identity
            && self.compile_identity.as_bytes() == &claims.compile_identity
            && self.implementation_object_identity.as_bytes()
                == &claims.implementation_object_identity
            && self.compiler_receipt_identity.as_bytes() == &claims.compiler_receipt_identity
            && self.expectation_identity.as_bytes() == &claims.expectation_identity
            && self.full_payload_identity.as_bytes() == &claims.full_payload_identity
            && self.glue_source_identity.as_bytes() == &claims.glue_source_identity
            && self.direct_header_identity.as_bytes() == &claims.direct_header_identity
            && self.glue_code_identity.as_bytes() == &claims.glue_code_identity
            && self.glue_object_identity.as_bytes() == &claims.glue_object_identity
            && self.bundle_identity.as_bytes() == &claims.bundle_identity
            && self.full_payload_bytes == claims.full_payload_bytes
            && self.literal == claims.literal
    }

    const fn compile_identity(&self) -> [u8; 32] {
        self.compile_identity.0
    }
}

const fn identity_is_strictly_less_v2(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut index = 0_usize;
    while index < left.len() {
        if left[index] < right[index] {
            return true;
        }
        if left[index] > right[index] {
            return false;
        }
        let Some(next) = index.checked_add(1) else {
            return false;
        };
        index = next;
    }
    false
}

const fn production_rows_are_canonical_v2(
    rows: &[SourceQualifiedStaticSearchSelectedEndRowV2],
) -> bool {
    if rows.len() > HARD_MAX_STATIC_SEARCH_SELECTED_END_PRODUCTION_ROWS_V2 {
        return false;
    }
    let mut index = 1_usize;
    while index < rows.len() {
        let Some(previous) = index.checked_sub(1) else {
            return false;
        };
        if !identity_is_strictly_less_v2(
            rows[previous].compile_identity.as_bytes(),
            rows[index].compile_identity.as_bytes(),
        ) {
            return false;
        }
        let Some(next) = index.checked_add(1) else {
            return false;
        };
        index = next;
    }
    true
}

/// Source qualification attached to one lookup result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticSearchSelectedEndSourceQualificationV2 {
    /// Exact compiler output is only a candidate and grants no runtime route.
    Candidate,
    /// A complete source-reviewed production row matched every identity.
    SourceQualified { compile_identity: [u8; 32] },
}

/// Production authority attached to an opaque ABI2 owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticSearchSelectedEndProductionAuthorityV2 {
    Absent,
    SourceQualified { compile_identity: [u8; 32] },
}

/// Typed portable-fallback reason returned before host probing or native work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticSearchSelectedEndFallbackStatusV2 {
    /// This source revision contains no production rows.
    ProductionAuthorityAbsent {
        qualification: StaticSearchSelectedEndSourceQualificationV2,
    },
    /// Production rows exist, but none match all generated identity claims.
    ArtifactUnqualified {
        qualification: StaticSearchSelectedEndSourceQualificationV2,
    },
}

impl StaticSearchSelectedEndFallbackStatusV2 {
    #[must_use]
    pub const fn production_authority(&self) -> StaticSearchSelectedEndProductionAuthorityV2 {
        StaticSearchSelectedEndProductionAuthorityV2::Absent
    }

    #[must_use]
    pub const fn qualification(&self) -> StaticSearchSelectedEndSourceQualificationV2 {
        match self {
            Self::ProductionAuthorityAbsent { qualification }
            | Self::ArtifactUnqualified { qualification } => *qualification,
        }
    }
}

/// Opaque owner produced only by a complete source-reviewed row match.
///
/// It contains no address, symbol, callback, or callable pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticSearchSelectedEndProductionV2 {
    compile_identity: [u8; 32],
}

impl StaticSearchSelectedEndProductionV2 {
    #[must_use]
    pub const fn production_authority(&self) -> StaticSearchSelectedEndProductionAuthorityV2 {
        StaticSearchSelectedEndProductionAuthorityV2::SourceQualified {
            compile_identity: self.compile_identity,
        }
    }

    #[must_use]
    pub const fn qualification(&self) -> StaticSearchSelectedEndSourceQualificationV2 {
        StaticSearchSelectedEndSourceQualificationV2::SourceQualified {
            compile_identity: self.compile_identity,
        }
    }

    /// Observe the calling thread's tag21 host contract and SVE VL exactly
    /// once.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<
        StaticSearchSelectedEndThreadSessionV2<'_>,
        StaticSearchSelectedEndThreadContractErrorV2,
    > {
        begin_current_thread_session_for_owner_v2(self)
    }
}

/// Result of matching compiler-generated claims against production authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticSearchSelectedEndAdoptionV2 {
    Fallback(StaticSearchSelectedEndFallbackStatusV2),
    Adopted(StaticSearchSelectedEndProductionV2),
}

/// Match one generated binding's complete identity tuple against the private
/// production authority table.
///
/// No address, symbol, callback, selector, or authority value is accepted.
/// The current empty table returns a typed portable fallback before host
/// probing or native work.
#[must_use]
pub fn adopt_compiler_generated_static_search_selected_end_v2(
    claims: &StaticSearchSelectedEndArtifactClaimsV2,
) -> StaticSearchSelectedEndAdoptionV2 {
    let candidate = StaticSearchSelectedEndSourceQualificationV2::Candidate;
    if PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SELECTED_END_ROWS_V2.is_empty() {
        return StaticSearchSelectedEndAdoptionV2::Fallback(
            StaticSearchSelectedEndFallbackStatusV2::ProductionAuthorityAbsent {
                qualification: candidate,
            },
        );
    }
    let Some(row) = PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SELECTED_END_ROWS_V2
        .iter()
        .find(|row| row.matches(claims))
    else {
        return StaticSearchSelectedEndAdoptionV2::Fallback(
            StaticSearchSelectedEndFallbackStatusV2::ArtifactUnqualified {
                qualification: candidate,
            },
        );
    };
    StaticSearchSelectedEndAdoptionV2::Adopted(StaticSearchSelectedEndProductionV2 {
        compile_identity: row.compile_identity(),
    })
}

/// Failure while opening one same-thread tag21 ABI2 session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticSearchSelectedEndThreadContractErrorV2 {
    UnsupportedPlatform,
    RequiredAsimdUnavailable,
    RequiredSveUnavailable,
    RequiredSve2Unavailable,
    RequiredTag21TuningUnavailable,
    SveVectorLengthQueryFailed {
        errno: Option<i32>,
    },
    RequiredSveVectorLengthUnavailable {
        required_bytes: u16,
        actual_bytes: Option<u16>,
    },
}

impl fmt::Display for StaticSearchSelectedEndThreadContractErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SelectedEnd ABI2 thread contract failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticSearchSelectedEndThreadContractErrorV2 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "query-failure and observed variants are constructed on different target configurations"
)]
enum SelectedEndSveVectorLengthFactV2 {
    QueryFailed { errno: Option<i32> },
    Observed(Option<u16>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectedEndThreadFactsV2 {
    supported_platform: bool,
    asimd: bool,
    sve: bool,
    sve2: bool,
    tag21_tuning: bool,
    sve_vector_bytes: SelectedEndSveVectorLengthFactV2,
}

fn validate_static_thread_facts_v2(
    facts: &SelectedEndThreadFactsV2,
) -> Result<(), StaticSearchSelectedEndThreadContractErrorV2> {
    if !facts.supported_platform {
        return Err(StaticSearchSelectedEndThreadContractErrorV2::UnsupportedPlatform);
    }
    if !facts.asimd {
        return Err(StaticSearchSelectedEndThreadContractErrorV2::RequiredAsimdUnavailable);
    }
    if !facts.sve {
        return Err(StaticSearchSelectedEndThreadContractErrorV2::RequiredSveUnavailable);
    }
    if !facts.sve2 {
        return Err(StaticSearchSelectedEndThreadContractErrorV2::RequiredSve2Unavailable);
    }
    if !facts.tag21_tuning {
        return Err(StaticSearchSelectedEndThreadContractErrorV2::RequiredTag21TuningUnavailable);
    }
    Ok(())
}

fn validate_thread_facts_v2(
    facts: SelectedEndThreadFactsV2,
) -> Result<(), StaticSearchSelectedEndThreadContractErrorV2> {
    validate_static_thread_facts_v2(&facts)?;
    match facts.sve_vector_bytes {
        SelectedEndSveVectorLengthFactV2::QueryFailed { errno } => {
            Err(StaticSearchSelectedEndThreadContractErrorV2::SveVectorLengthQueryFailed { errno })
        }
        SelectedEndSveVectorLengthFactV2::Observed(actual_bytes)
            if actual_bytes != Some(SELECTED_END_FIXED_VECTOR_BYTES_V2) =>
        {
            Err(
                StaticSearchSelectedEndThreadContractErrorV2::RequiredSveVectorLengthUnavailable {
                    required_bytes: SELECTED_END_FIXED_VECTOR_BYTES_V2,
                    actual_bytes,
                },
            )
        }
        SelectedEndSveVectorLengthFactV2::Observed(_) => Ok(()),
    }
}

/// Failure at the safe scalar-preflighted ABI2 result boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticSearchSelectedEndCallErrorV2 {
    LiteralWidthMismatch {
        expected_bytes: usize,
        actual_bytes: usize,
    },
    LiteralIdentityMismatch,
    BindingIdentityMismatch,
    InvalidNativeEnd {
        end_or_zero: usize,
        literal_bytes: usize,
        window_start: usize,
        window_end: usize,
    },
}

impl fmt::Display for StaticSearchSelectedEndCallErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SelectedEnd ABI2 call failed: {self:?}")
    }
}

impl std::error::Error for StaticSearchSelectedEndCallErrorV2 {}

/// Nonzero per-generated-module key for one exact linked ABI2 artifact.
///
/// Generated source owns a private static instance. The safe bind path records
/// its address after comparing the portable plan with the embedded literal.
/// The generic boundary can authenticate both this key and the issuing plan by
/// pointer identity. Optimized generated source instead encloses the
/// authenticated session in its own private nominal type, so repeated calls
/// need only the plan check. Keeping the key nonzero-sized makes distinct
/// statics distinct allocations even when their payload bytes happen to match.
#[derive(Debug)]
pub struct StaticSearchSelectedEndBindingKeyV2 {
    identity: [u8; 32],
}

impl StaticSearchSelectedEndBindingKeyV2 {
    /// Construct one generated-module binding key.
    ///
    /// This key authenticates module identity inside an already-authorized
    /// plan session; it is not an authority grant.
    #[must_use]
    pub const fn compiler_generated(identity: [u8; 32]) -> Self {
        Self { identity }
    }

    /// Compatibility constructor for the qualification-private consumer.
    #[doc(hidden)]
    #[must_use]
    pub const fn qualification_private(identity: [u8; 32]) -> Self {
        Self::compiler_generated(identity)
    }

    /// Compile identity carried by this generated-module key.
    #[must_use]
    pub const fn identity(&self) -> &[u8; 32] {
        &self.identity
    }
}

/// Default-off owner for qualification-private linked `SelectedEnd` ABI2.
///
/// This zero-sized value grants no production authority and has no call
/// method. A call requires both a current-thread session and a generated exact
/// identity-suffixed binding.
#[cfg(feature = "selected-end-qualification-private-v2")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StaticSearchSelectedEndQualificationV2 {
    _private: (),
}

#[cfg(feature = "selected-end-qualification-private-v2")]
impl StaticSearchSelectedEndQualificationV2 {
    /// Construct the feature-gated qualification-only owner.
    #[must_use]
    pub const fn qualification_private() -> Self {
        Self { _private: () }
    }

    #[must_use]
    pub const fn production_authority(&self) -> StaticSearchSelectedEndProductionAuthorityV2 {
        StaticSearchSelectedEndProductionAuthorityV2::Absent
    }

    /// Observe the calling thread's tag21 host contract and SVE VL exactly
    /// once, then return a token that cannot move to or be shared with another
    /// thread.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<
        StaticSearchSelectedEndThreadSessionV2<'_>,
        StaticSearchSelectedEndThreadContractErrorV2,
    > {
        begin_current_thread_session_for_owner_v2(self)
    }
}

fn begin_current_thread_session_for_owner_v2<'owner, Owner>(
    _owner: &'owner Owner,
) -> Result<
    StaticSearchSelectedEndThreadSessionV2<'owner>,
    StaticSearchSelectedEndThreadContractErrorV2,
> {
    platform::admit_current_thread_v2()?;
    Ok(StaticSearchSelectedEndThreadSessionV2 {
        _owner: PhantomData,
        _thread_bound: PhantomData,
    })
}

/// Same-thread invocation capability for a generated exact ABI2 binding.
///
/// Construction performs all host/tuning checks and the sole
/// `PR_SVE_GET_VL` observation. Preparing and decoding calls below are pure
/// scalar operations and issue no syscall.
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::StaticSearchSelectedEndThreadSessionV2;
/// fn assert_send<T: Send>() {}
/// assert_send::<StaticSearchSelectedEndThreadSessionV2<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::StaticSearchSelectedEndThreadSessionV2;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<StaticSearchSelectedEndThreadSessionV2<'static>>();
/// ```
#[derive(Debug)]
pub struct StaticSearchSelectedEndThreadSessionV2<'owner> {
    _owner: PhantomData<&'owner ()>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl<'owner> StaticSearchSelectedEndThreadSessionV2<'owner> {
    /// Bind one exact portable plan to this already-admitted thread session.
    ///
    /// The linked artifact's literal is compared once here. Calls prepared
    /// through the returned token can then authenticate their private-field
    /// preflight certificate and the generated artifact without comparing
    /// sixteen literal bytes on every hot call. Generated bindings additionally
    /// enclose the token in an artifact-specific private nominal type.
    pub fn bind_literal_plan<'session, 'plan>(
        &'session self,
        plan: &'plan LiteralPlan,
        exact_literal: &[u8; SELECTED_END_LITERAL_BYTES_V2],
        binding: &'static StaticSearchSelectedEndBindingKeyV2,
    ) -> Result<
        StaticSearchSelectedEndPlanSessionV2<'session, 'owner, 'plan>,
        StaticSearchSelectedEndCallErrorV2,
    > {
        validate_literal_plan_v2(plan, exact_literal)?;
        Ok(StaticSearchSelectedEndPlanSessionV2 {
            session: self,
            plan,
            binding,
        })
    }

    /// Consume this thread token and bind one exact portable literal plan.
    ///
    /// Unlike [`Self::bind_literal_plan`], the returned token owns the
    /// non-transferable current-thread session. A consumer can therefore keep
    /// the plan-bound token in an ordinary session aggregate without storing
    /// both a value and a reference to that same value. The generated
    /// artifact-specific nominal wrapper remains responsible for discharging
    /// the binding-key proof before it uses the plan-only hot path.
    pub fn bind_literal_plan_owned<'plan>(
        self,
        plan: &'plan LiteralPlan,
        exact_literal: &[u8; SELECTED_END_LITERAL_BYTES_V2],
        binding: &'static StaticSearchSelectedEndBindingKeyV2,
    ) -> Result<
        StaticSearchSelectedEndOwnedPlanSessionV2<'owner, 'plan>,
        StaticSearchSelectedEndCallErrorV2,
    > {
        validate_literal_plan_v2(plan, exact_literal)?;
        Ok(StaticSearchSelectedEndOwnedPlanSessionV2 {
            session: self,
            plan,
            binding,
        })
    }

    /// Bind one already completed shared scalar preflight to this session.
    ///
    /// The exact linked artifact embeds a 16-byte literal. A token issued by a
    /// different literal plan is rejected before generated code is invoked.
    /// This general one-off boundary compares bytes on every call; generated
    /// reusable bindings use [`Self::bind_literal_plan`] and the plan-bound
    /// identity path instead.
    pub fn prepare<'session, 'haystack>(
        &'session self,
        preflight: LiteralSearchPreflight<'_, 'haystack>,
        exact_literal: &[u8; SELECTED_END_LITERAL_BYTES_V2],
    ) -> Result<
        StaticSearchSelectedEndPreparedCallV2<'session, 'owner, 'haystack>,
        StaticSearchSelectedEndCallErrorV2,
    > {
        let actual_bytes = preflight.literal_bytes();
        if actual_bytes != SELECTED_END_LITERAL_BYTES_V2 {
            return Err(StaticSearchSelectedEndCallErrorV2::LiteralWidthMismatch {
                expected_bytes: SELECTED_END_LITERAL_BYTES_V2,
                actual_bytes,
            });
        }
        if preflight.literal() != exact_literal {
            return Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch);
        }
        Ok(StaticSearchSelectedEndPreparedCallV2 {
            _session: self,
            checked: preflight.checked_window(),
            accounting: preflight.accounting(),
        })
    }
}

fn validate_literal_plan_v2(
    plan: &LiteralPlan,
    exact_literal: &[u8; SELECTED_END_LITERAL_BYTES_V2],
) -> Result<(), StaticSearchSelectedEndCallErrorV2> {
    let literal = plan.needle();
    let actual_bytes = literal.len();
    if actual_bytes != SELECTED_END_LITERAL_BYTES_V2 {
        return Err(StaticSearchSelectedEndCallErrorV2::LiteralWidthMismatch {
            expected_bytes: SELECTED_END_LITERAL_BYTES_V2,
            actual_bytes,
        });
    }
    if literal != exact_literal {
        return Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch);
    }
    Ok(())
}

/// Same-thread AOT session bound once to the exact portable literal plan and
/// one generated artifact key.
///
/// The token borrows the non-transferable thread session and is therefore
/// neither [`Send`] nor [`Sync`]. It contains no callable address or function
/// pointer.
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::StaticSearchSelectedEndPlanSessionV2;
/// fn assert_send<T: Send>() {}
/// assert_send::<StaticSearchSelectedEndPlanSessionV2<'static, 'static, 'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::StaticSearchSelectedEndPlanSessionV2;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<StaticSearchSelectedEndPlanSessionV2<'static, 'static, 'static>>();
/// ```
#[derive(Debug)]
pub struct StaticSearchSelectedEndPlanSessionV2<'session, 'owner, 'plan> {
    session: &'session StaticSearchSelectedEndThreadSessionV2<'owner>,
    plan: &'plan LiteralPlan,
    binding: &'static StaticSearchSelectedEndBindingKeyV2,
}

impl<'session, 'owner, 'plan> StaticSearchSelectedEndPlanSessionV2<'session, 'owner, 'plan> {
    /// Consume one authoritative preflight from the plan bound at session
    /// construction.
    ///
    /// This generic successful path performs two allocation-free
    /// pointer-identity checks: one for the generated artifact key and one for
    /// the issuing plan. A token from another plan or generated module is
    /// rejected before native code can be invoked, even when its literal
    /// bytes are equal. Generated private nominal wrappers use
    /// [`Self::prepare_plan_bound`] to discharge the artifact proof in the
    /// type and retain only the plan check per call.
    #[inline]
    pub fn prepare<'haystack>(
        &self,
        preflight: LiteralSearchPreflight<'_, 'haystack>,
        binding: &StaticSearchSelectedEndBindingKeyV2,
    ) -> Result<
        StaticSearchSelectedEndPreparedCallV2<'session, 'owner, 'haystack>,
        StaticSearchSelectedEndCallErrorV2,
    > {
        if !core::ptr::eq(self.binding, binding) {
            return Err(StaticSearchSelectedEndCallErrorV2::BindingIdentityMismatch);
        }
        self.prepare_plan_bound(preflight)
    }

    /// Consume one authoritative preflight after a generated field-private
    /// wrapper has structurally fixed this session's artifact key.
    ///
    /// This primitive performs only the plan-identity check. It does not itself
    /// authorize any native call: generated source encloses the session in a
    /// nominal type with a private field that can be constructed only by that
    /// artifact's exact bind function. Keeping the artifact proof in the
    /// nominal type removes the second pointer check from repeated calls
    /// without allowing one generated module's session to enter another
    /// module's safe call boundary.
    #[doc(hidden)]
    #[inline(always)]
    pub fn prepare_plan_bound<'haystack>(
        &self,
        preflight: LiteralSearchPreflight<'_, 'haystack>,
    ) -> Result<
        StaticSearchSelectedEndPreparedCallV2<'session, 'owner, 'haystack>,
        StaticSearchSelectedEndCallErrorV2,
    > {
        if !preflight.was_issued_by(self.plan) {
            let actual_bytes = preflight.literal_bytes();
            if actual_bytes != SELECTED_END_LITERAL_BYTES_V2 {
                return Err(StaticSearchSelectedEndCallErrorV2::LiteralWidthMismatch {
                    expected_bytes: SELECTED_END_LITERAL_BYTES_V2,
                    actual_bytes,
                });
            }
            return Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch);
        }
        Ok(StaticSearchSelectedEndPreparedCallV2 {
            _session: self.session,
            checked: preflight.checked_window(),
            accounting: preflight.accounting(),
        })
    }
}

/// Owning same-thread AOT session bound once to an exact portable literal plan
/// and one generated artifact key.
///
/// This token owns, rather than borrows, its non-transferable thread session.
/// It borrows only the external qualification owner and portable plan, is
/// neither [`Send`] nor [`Sync`], and stores no callable address or function
/// pointer.
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::StaticSearchSelectedEndOwnedPlanSessionV2;
/// fn assert_send<T: Send>() {}
/// assert_send::<StaticSearchSelectedEndOwnedPlanSessionV2<'static, 'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre_aot_static_runtime::StaticSearchSelectedEndOwnedPlanSessionV2;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<StaticSearchSelectedEndOwnedPlanSessionV2<'static, 'static>>();
/// ```
#[derive(Debug)]
pub struct StaticSearchSelectedEndOwnedPlanSessionV2<'owner, 'plan> {
    session: StaticSearchSelectedEndThreadSessionV2<'owner>,
    plan: &'plan LiteralPlan,
    binding: &'static StaticSearchSelectedEndBindingKeyV2,
}

impl<'owner, 'plan> StaticSearchSelectedEndOwnedPlanSessionV2<'owner, 'plan> {
    /// Consume one authoritative preflight after authenticating the generated
    /// artifact key and issuing plan.
    #[inline]
    pub fn prepare<'session, 'haystack>(
        &'session self,
        preflight: LiteralSearchPreflight<'_, 'haystack>,
        binding: &StaticSearchSelectedEndBindingKeyV2,
    ) -> Result<
        StaticSearchSelectedEndPreparedCallV2<'session, 'owner, 'haystack>,
        StaticSearchSelectedEndCallErrorV2,
    > {
        if !core::ptr::eq(self.binding, binding) {
            return Err(StaticSearchSelectedEndCallErrorV2::BindingIdentityMismatch);
        }
        self.prepare_plan_bound(preflight)
    }

    /// Consume one authoritative preflight after a generated private nominal
    /// wrapper has structurally fixed this owning session's artifact key.
    ///
    /// The successful hot path performs only issuing-plan pointer identity.
    /// The returned prepared value borrows the owned thread token for this
    /// call, retaining its same-thread lifetime without self-reference.
    #[doc(hidden)]
    #[inline(always)]
    pub fn prepare_plan_bound<'session, 'haystack>(
        &'session self,
        preflight: LiteralSearchPreflight<'_, 'haystack>,
    ) -> Result<
        StaticSearchSelectedEndPreparedCallV2<'session, 'owner, 'haystack>,
        StaticSearchSelectedEndCallErrorV2,
    > {
        if !preflight.was_issued_by(self.plan) {
            let actual_bytes = preflight.literal_bytes();
            if actual_bytes != SELECTED_END_LITERAL_BYTES_V2 {
                return Err(StaticSearchSelectedEndCallErrorV2::LiteralWidthMismatch {
                    expected_bytes: SELECTED_END_LITERAL_BYTES_V2,
                    actual_bytes,
                });
            }
            return Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch);
        }
        Ok(StaticSearchSelectedEndPreparedCallV2 {
            _session: &self.session,
            checked: preflight.checked_window(),
            accounting: preflight.accounting(),
        })
    }
}

/// Session-bound scalar-preflight certificate consumed by generated source.
///
/// This type exposes only the four ABI2 scalar inputs and strict result
/// decoding. It contains no callable address or function pointer.
#[derive(Debug)]
pub struct StaticSearchSelectedEndPreparedCallV2<'session, 'owner, 'haystack> {
    _session: &'session StaticSearchSelectedEndThreadSessionV2<'owner>,
    checked: CheckedSearchWindow<'haystack>,
    accounting: LiteralAccounting,
}

impl StaticSearchSelectedEndPreparedCallV2<'_, '_, '_> {
    #[must_use]
    #[inline(always)]
    pub const fn haystack(&self) -> &[u8] {
        self.checked.haystack()
    }

    #[must_use]
    #[inline(always)]
    pub const fn window(&self) -> SearchWindow {
        self.checked.window()
    }

    /// Decode the exact `x0` end-or-zero result after the generated module has
    /// made its literal direct-symbol call.
    #[inline(always)]
    pub fn decode(
        self,
        end_or_zero: usize,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), StaticSearchSelectedEndCallErrorV2> {
        let window = self.checked.window();
        let matched = decode_selected_end_v2(end_or_zero, window)?;
        Ok((matched, self.accounting))
    }
}

#[inline(always)]
fn decode_selected_end_v2(
    end_or_zero: usize,
    window: SearchWindow,
) -> Result<Option<MatchSpan>, StaticSearchSelectedEndCallErrorV2> {
    if end_or_zero == 0 {
        return Ok(None);
    }
    let Some(start) = end_or_zero.checked_sub(SELECTED_END_LITERAL_BYTES_V2) else {
        return Err(StaticSearchSelectedEndCallErrorV2::InvalidNativeEnd {
            end_or_zero,
            literal_bytes: SELECTED_END_LITERAL_BYTES_V2,
            window_start: window.start(),
            window_end: window.end(),
        });
    };
    if end_or_zero > window.end() || start < window.start() {
        return Err(StaticSearchSelectedEndCallErrorV2::InvalidNativeEnd {
            end_or_zero,
            literal_bytes: SELECTED_END_LITERAL_BYTES_V2,
            window_start: window.start(),
            window_end: window.end(),
        });
    }
    Ok(Some(MatchSpan::new(start, end_or_zero)))
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod platform {
    use fre_target_features::TuningClass;

    use super::{
        SelectedEndSveVectorLengthFactV2, SelectedEndThreadFactsV2,
        StaticSearchSelectedEndThreadContractErrorV2, validate_static_thread_facts_v2,
        validate_thread_facts_v2,
    };

    const AT_HWCAP2_V2: libc::c_ulong = 26;
    const HWCAP2_SVE2_V2: libc::c_ulong = 1 << 1;
    const PR_SVE_GET_VL_V2: libc::c_int = 51;
    const PR_SVE_VL_LEN_MASK_V2: libc::c_int = 0xffff;

    #[allow(
        unsafe_code,
        reason = "Linux auxv and PR_SVE_GET_VL are scalar kernel ABI queries used only at session construction"
    )]
    pub(super) fn admit_current_thread_v2()
    -> Result<(), StaticSearchSelectedEndThreadContractErrorV2> {
        // SAFETY: getauxval reads the process auxiliary vector using scalar
        // selectors and has no pointer preconditions.
        let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
        // SAFETY: AT_HWCAP2 is the Linux UAPI scalar selector.
        let hwcap2 = unsafe { libc::getauxval(AT_HWCAP2_V2) };
        let tag21_tuning = matches!(
            fre_target_features::host().tuning(),
            TuningClass::ArmServer { cpu: Some(cpu) }
                if cpu.implementer == 0x41 && cpu.part == 0x0d84
        );
        let mut facts = SelectedEndThreadFactsV2 {
            supported_platform: true,
            asimd: hwcap & libc::HWCAP_ASIMD != 0,
            sve: hwcap & libc::HWCAP_SVE != 0,
            sve2: hwcap2 & HWCAP2_SVE2_V2 != 0,
            tag21_tuning,
            sve_vector_bytes: SelectedEndSveVectorLengthFactV2::Observed(None),
        };
        validate_static_thread_facts_v2(&facts)?;

        // SAFETY: PR_SVE_GET_VL reads only the calling thread's architectural
        // SVE state and ignores the remaining scalar arguments. This is the
        // sole VL query on the successful session-construction path.
        let raw = unsafe { libc::prctl(PR_SVE_GET_VL_V2, 0, 0, 0, 0) };
        if raw < 0 {
            facts.sve_vector_bytes = SelectedEndSveVectorLengthFactV2::QueryFailed {
                errno: std::io::Error::last_os_error().raw_os_error(),
            };
        } else {
            facts.sve_vector_bytes = SelectedEndSveVectorLengthFactV2::Observed(
                u16::try_from(raw & PR_SVE_VL_LEN_MASK_V2).ok(),
            );
        }
        validate_thread_facts_v2(facts)
    }
}

#[cfg(not(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
)))]
mod platform {
    use super::{
        SelectedEndSveVectorLengthFactV2, SelectedEndThreadFactsV2,
        StaticSearchSelectedEndThreadContractErrorV2, validate_thread_facts_v2,
    };

    pub(super) fn admit_current_thread_v2()
    -> Result<(), StaticSearchSelectedEndThreadContractErrorV2> {
        validate_thread_facts_v2(SelectedEndThreadFactsV2 {
            supported_platform: false,
            asimd: false,
            sve: false,
            sve2: false,
            tag21_tuning: false,
            sve_vector_bytes: SelectedEndSveVectorLengthFactV2::Observed(None),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre_kernel_ir::CheckedSearchWindow;
    use fre_kernels::{LiteralBuildLimits, LiteralPlan, LiteralSearchLimits};

    #[cfg(feature = "selected-end-qualification-private-v2")]
    #[test]
    fn authority_is_always_absent() {
        let owner = StaticSearchSelectedEndQualificationV2::qualification_private();
        assert_eq!(
            owner.production_authority(),
            StaticSearchSelectedEndProductionAuthorityV2::Absent
        );
    }

    fn zero_claims() -> StaticSearchSelectedEndArtifactClaimsV2 {
        StaticSearchSelectedEndArtifactClaimsV2::compiler_generated(
            [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32],
            [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], 0, [0; 16],
        )
    }

    #[test]
    fn public_adoption_is_absent_candidate_without_a_production_row() {
        assert!(PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SELECTED_END_ROWS_V2.is_empty());
        let adoption = adopt_compiler_generated_static_search_selected_end_v2(&zero_claims());
        let StaticSearchSelectedEndAdoptionV2::Fallback(status) = adoption else {
            panic!("an empty production table must not adopt")
        };
        assert_eq!(
            status,
            StaticSearchSelectedEndFallbackStatusV2::ProductionAuthorityAbsent {
                qualification: StaticSearchSelectedEndSourceQualificationV2::Candidate,
            }
        );
        assert_eq!(
            status.production_authority(),
            StaticSearchSelectedEndProductionAuthorityV2::Absent
        );
    }

    #[test]
    fn selected_end_decode_is_closed() {
        let window = SearchWindow::new(4, 40);
        assert_eq!(decode_selected_end_v2(0, window), Ok(None));
        assert_eq!(
            decode_selected_end_v2(24, window),
            Ok(Some(MatchSpan::new(8, 24)))
        );
        for end_or_zero in [1, 19, 41, usize::MAX] {
            assert!(matches!(
                decode_selected_end_v2(end_or_zero, window),
                Err(StaticSearchSelectedEndCallErrorV2::InvalidNativeEnd { .. })
            ));
        }
    }

    fn valid_thread_facts() -> SelectedEndThreadFactsV2 {
        SelectedEndThreadFactsV2 {
            supported_platform: true,
            asimd: true,
            sve: true,
            sve2: true,
            tag21_tuning: true,
            sve_vector_bytes: SelectedEndSveVectorLengthFactV2::Observed(Some(16)),
        }
    }

    #[test]
    fn pure_thread_facts_fail_closed_for_every_admission_dimension() {
        let cases = [
            (
                SelectedEndThreadFactsV2 {
                    supported_platform: false,
                    ..valid_thread_facts()
                },
                StaticSearchSelectedEndThreadContractErrorV2::UnsupportedPlatform,
            ),
            (
                SelectedEndThreadFactsV2 {
                    asimd: false,
                    ..valid_thread_facts()
                },
                StaticSearchSelectedEndThreadContractErrorV2::RequiredAsimdUnavailable,
            ),
            (
                SelectedEndThreadFactsV2 {
                    sve: false,
                    ..valid_thread_facts()
                },
                StaticSearchSelectedEndThreadContractErrorV2::RequiredSveUnavailable,
            ),
            (
                SelectedEndThreadFactsV2 {
                    sve2: false,
                    ..valid_thread_facts()
                },
                StaticSearchSelectedEndThreadContractErrorV2::RequiredSve2Unavailable,
            ),
            (
                SelectedEndThreadFactsV2 {
                    tag21_tuning: false,
                    ..valid_thread_facts()
                },
                StaticSearchSelectedEndThreadContractErrorV2::RequiredTag21TuningUnavailable,
            ),
            (
                SelectedEndThreadFactsV2 {
                    sve_vector_bytes: SelectedEndSveVectorLengthFactV2::QueryFailed {
                        errno: Some(5),
                    },
                    ..valid_thread_facts()
                },
                StaticSearchSelectedEndThreadContractErrorV2::SveVectorLengthQueryFailed {
                    errno: Some(5),
                },
            ),
            (
                SelectedEndThreadFactsV2 {
                    sve_vector_bytes: SelectedEndSveVectorLengthFactV2::Observed(None),
                    ..valid_thread_facts()
                },
                StaticSearchSelectedEndThreadContractErrorV2::RequiredSveVectorLengthUnavailable {
                    required_bytes: 16,
                    actual_bytes: None,
                },
            ),
            (
                SelectedEndThreadFactsV2 {
                    sve_vector_bytes: SelectedEndSveVectorLengthFactV2::Observed(Some(32)),
                    ..valid_thread_facts()
                },
                StaticSearchSelectedEndThreadContractErrorV2::RequiredSveVectorLengthUnavailable {
                    required_bytes: 16,
                    actual_bytes: Some(32),
                },
            ),
        ];
        for (facts, expected) in cases {
            assert_eq!(validate_thread_facts_v2(facts), Err(expected));
        }
        assert_eq!(validate_thread_facts_v2(valid_thread_facts()), Ok(()));
    }

    #[test]
    fn preflight_is_bound_to_the_exact_literal_not_only_its_width() {
        let session = StaticSearchSelectedEndThreadSessionV2 {
            _owner: PhantomData,
            _thread_bound: PhantomData,
        };
        let haystack = b"before-0123456789abcdef-after";
        let window = CheckedSearchWindow::new(haystack, SearchWindow::new(0, haystack.len()))
            .expect("checked test window");
        let exact = LiteralPlan::new(b"0123456789abcdef", LiteralBuildLimits::default()).unwrap();
        let exact_preflight = exact
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        session
            .prepare(exact_preflight, b"0123456789abcdef")
            .expect("exact literal preflight");

        let wrong = LiteralPlan::new(b"fedcba9876543210", LiteralBuildLimits::default()).unwrap();
        let wrong_preflight = wrong
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            session.prepare(wrong_preflight, b"0123456789abcdef"),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch)
        ));
    }

    #[test]
    fn plan_bound_session_checks_bytes_once_and_plan_identity_per_call() {
        static BINDING: StaticSearchSelectedEndBindingKeyV2 =
            StaticSearchSelectedEndBindingKeyV2::qualification_private([0x19; 32]);
        static OTHER_BINDING: StaticSearchSelectedEndBindingKeyV2 =
            StaticSearchSelectedEndBindingKeyV2::qualification_private([0x21; 32]);
        let session = StaticSearchSelectedEndThreadSessionV2 {
            _owner: PhantomData,
            _thread_bound: PhantomData,
        };
        let exact = LiteralPlan::new(b"0123456789abcdef", LiteralBuildLimits::default()).unwrap();
        let bound = session
            .bind_literal_plan(&exact, b"0123456789abcdef", &BINDING)
            .expect("exact plan binds once");
        let haystack = b"before-0123456789abcdef-after";
        let window = CheckedSearchWindow::new(haystack, SearchWindow::new(0, haystack.len()))
            .expect("checked test window");
        let exact_preflight = exact
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        let prepared = bound
            .prepare(exact_preflight, &BINDING)
            .expect("the bound plan's preflight");
        assert_eq!(prepared.decode(23).unwrap().0, Some(MatchSpan::new(7, 23)));

        let equal_bytes =
            LiteralPlan::new(b"0123456789abcdef", LiteralBuildLimits::default()).unwrap();
        let equal_preflight = equal_bytes
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            bound.prepare(equal_preflight, &BINDING),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch)
        ));

        let wrong_width = LiteralPlan::new(b"short", LiteralBuildLimits::default()).unwrap();
        let wrong_width_preflight = wrong_width
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            bound.prepare(wrong_width_preflight, &BINDING),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralWidthMismatch {
                expected_bytes: 16,
                actual_bytes: 5,
            })
        ));

        let exact_preflight = exact
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            bound.prepare(exact_preflight, &OTHER_BINDING),
            Err(StaticSearchSelectedEndCallErrorV2::BindingIdentityMismatch)
        ));

        assert!(matches!(
            session.bind_literal_plan(&equal_bytes, b"fedcba9876543210", &BINDING),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch)
        ));
        assert!(matches!(
            session.bind_literal_plan(&wrong_width, b"0123456789abcdef", &BINDING),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralWidthMismatch {
                expected_bytes: 16,
                actual_bytes: 5,
            })
        ));
    }

    #[test]
    fn owning_plan_bound_session_is_storable_and_retains_exact_plan_identity() {
        static BINDING: StaticSearchSelectedEndBindingKeyV2 =
            StaticSearchSelectedEndBindingKeyV2::qualification_private([0x19; 32]);
        static OTHER_BINDING: StaticSearchSelectedEndBindingKeyV2 =
            StaticSearchSelectedEndBindingKeyV2::qualification_private([0x21; 32]);
        let session = StaticSearchSelectedEndThreadSessionV2 {
            _owner: PhantomData,
            _thread_bound: PhantomData,
        };
        let exact = LiteralPlan::new(b"0123456789abcdef", LiteralBuildLimits::default()).unwrap();
        let bound = session
            .bind_literal_plan_owned(&exact, b"0123456789abcdef", &BINDING)
            .expect("the consuming exact-plan bind succeeds");
        let haystack = b"before-0123456789abcdef-after";
        let window = CheckedSearchWindow::new(haystack, SearchWindow::new(0, haystack.len()))
            .expect("checked test window");
        let exact_preflight = exact
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        let prepared = bound
            .prepare(exact_preflight, &BINDING)
            .expect("the owned token accepts its issuing plan");
        assert_eq!(prepared.decode(23).unwrap().0, Some(MatchSpan::new(7, 23)));

        let equal_bytes =
            LiteralPlan::new(b"0123456789abcdef", LiteralBuildLimits::default()).unwrap();
        let equal_preflight = equal_bytes
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            bound.prepare_plan_bound(equal_preflight),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch)
        ));

        let exact_preflight = exact
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            bound.prepare(exact_preflight, &OTHER_BINDING),
            Err(StaticSearchSelectedEndCallErrorV2::BindingIdentityMismatch)
        ));
    }

    #[test]
    fn source_has_one_session_only_vl_query_and_no_callable_storage() {
        let source = include_str!("selected_end_direct_v2.rs");
        let bind = source.find("    pub fn bind_literal_plan<").unwrap();
        let plan_prepare = source
            .find("impl<'session, 'owner, 'plan> StaticSearchSelectedEndPlanSessionV2")
            .unwrap();
        let owned_prepare = source
            .find("impl<'owner, 'plan> StaticSearchSelectedEndOwnedPlanSessionV2")
            .unwrap();
        let decode = source.find("fn decode_selected_end_v2(").unwrap();
        let tests = source.find("#[cfg(test)]").unwrap();
        let implementation = &source[..tests];
        assert!(!implementation[bind..decode].contains("prctl("));
        let plan_prepare = &implementation[plan_prepare..owned_prepare];
        let binding_check = plan_prepare
            .find("core::ptr::eq(self.binding, binding)")
            .unwrap();
        let plan_bound_prepare = plan_prepare.find("pub fn prepare_plan_bound<").unwrap();
        let pointer_check = plan_prepare
            .find("preflight.was_issued_by(self.plan)")
            .unwrap();
        let literal_width = plan_prepare.find("preflight.literal_bytes()").unwrap();
        assert!(binding_check < plan_bound_prepare);
        assert!(plan_bound_prepare < pointer_check);
        assert!(pointer_check < literal_width);
        assert!(!plan_prepare.contains("preflight.literal()"));
        let owned_prepare = &implementation[owned_prepare..decode];
        let owned_binding_check = owned_prepare
            .find("core::ptr::eq(self.binding, binding)")
            .unwrap();
        let owned_plan_bound_prepare = owned_prepare.find("pub fn prepare_plan_bound<").unwrap();
        let owned_pointer_check = owned_prepare
            .find("preflight.was_issued_by(self.plan)")
            .unwrap();
        let owned_literal_width = owned_prepare.find("preflight.literal_bytes()").unwrap();
        assert!(owned_binding_check < owned_plan_bound_prepare);
        assert!(owned_plan_bound_prepare < owned_pointer_check);
        assert!(owned_pointer_check < owned_literal_width);
        assert!(owned_prepare.contains("_session: &self.session"));
        assert!(!owned_prepare.contains("preflight.literal()"));
        assert_eq!(
            implementation
                .matches("#[inline(always)]\n    pub fn prepare_plan_bound<")
                .count(),
            2
        );
        assert!(implementation.contains(
            "#[inline(always)]\n    pub fn decode(\n        self,\n        end_or_zero: usize,"
        ));
        assert!(implementation.contains("#[inline(always)]\nfn decode_selected_end_v2("));
        let decode_implementation = &implementation[decode..];
        assert!(!decode_implementation.contains("expect("));
        assert!(!decode_implementation.contains("unwrap("));
        assert_eq!(implementation.matches("libc::prctl(").count(), 1);
        assert!(!implementation.contains("transmute::<"));
        assert!(!implementation.contains("extern \"C\" fn("));
    }
}
