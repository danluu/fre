//! Explicit binding of an authenticated optimizing Count-v3 handle.
//!
//! Binding authenticates one precompiled image once. Production calls apply
//! one evidence-backed size split: inputs below 65,536 bytes stay on the retained
//! portable owner and longer inputs use authenticated native code. The typed
//! outcome exposes the route that actually ran. No call performs artifact
//! lookup, target dispatch, compilation, recipe selection, or code audit.
//! Movable ASIMD production and same-thread SVE/SVE2 production remain
//! type-disjoint. Qualification facades remain native-only for measurement.

use core::{fmt, num::NonZeroU64};

use fre_aot_static_runtime::{
    STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3, StaticCountCallErrorV3,
    StaticCountSveCallErrorV3, StaticCountSveFacadeBindingV3, StaticCountSveSessionV3,
    StaticCountSveThreadContractErrorV3, VerifiedStaticCountSveV3, VerifiedStaticCountV3,
};
#[cfg(feature = "count-v3-aot-qualification-private")]
use fre_aot_static_runtime::{
    StaticCountQualificationFacadeBindingV3, StaticCountSveQualificationFacadeBindingV3,
    StaticCountSveQualificationSessionV3, VerifiedStaticCountQualificationV3,
    VerifiedStaticCountSveQualificationV3,
};
use fre_kernel_ir::AggregateExecutionLimits;

use crate::{
    AggregateCountExactLiteralAotPlannedCandidate,
    AggregateCountExactLiteralAotPlanningReceiptIdentity,
    AggregateCountExactLiteralAotSemanticBindingIdentity, AggregateCountRegex,
    AggregateExecutionError, AggregateRunLimits,
};

/// Minimum haystack size authorized for Count-v3 production native routes.
pub const AGGREGATE_COUNT_EXACT_LITERAL_AOT_MIN_HAYSTACK_BYTES_V3: usize =
    STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3;

/// Refusal to bind a static image to its exact fixed-policy facade owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AggregateCountExactLiteralAotBindErrorV3 {
    PortableOwnerIsNotFixedPolicyExactLiteralCandidate,
    LiteralMismatch {
        portable_bytes: usize,
        adopted_bytes: usize,
    },
    SemanticBindingIdentityMismatch {
        portable: AggregateCountExactLiteralAotSemanticBindingIdentity,
        adopted: [u8; 32],
    },
    PlanningReceiptIdentityMismatch {
        portable: AggregateCountExactLiteralAotPlanningReceiptIdentity,
        adopted: [u8; 32],
    },
}

impl fmt::Display for AggregateCountExactLiteralAotBindErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE exact-literal optimizing Count-v3 AOT binding failed: {self:?}"
        )
    }
}

impl std::error::Error for AggregateCountExactLiteralAotBindErrorV3 {}

/// Value-only execution refusal from the explicit optimizing AOT facade.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[allow(
    clippy::large_enum_variant,
    reason = "the portable fallback retains its complete typed execution receipt without an error-path allocation"
)]
pub enum AggregateCountExactLiteralAotExecutionErrorV3 {
    ArithmeticOverflow {
        at: &'static str,
    },
    ResourceLimit {
        resource: &'static str,
        limit: u128,
        required: u128,
    },
    Portable(AggregateExecutionError),
    Native(StaticCountCallErrorV3),
    SveNative(StaticCountSveCallErrorV3),
}

impl fmt::Display for AggregateCountExactLiteralAotExecutionErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE exact-literal optimizing Count-v3 AOT execution failed: {self:?}"
        )
    }
}

impl std::error::Error for AggregateCountExactLiteralAotExecutionErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Portable(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::SveNative(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StaticCountCallErrorV3> for AggregateCountExactLiteralAotExecutionErrorV3 {
    fn from(value: StaticCountCallErrorV3) -> Self {
        Self::Native(value)
    }
}

impl From<StaticCountSveCallErrorV3> for AggregateCountExactLiteralAotExecutionErrorV3 {
    fn from(value: StaticCountSveCallErrorV3) -> Self {
        Self::SveNative(value)
    }
}

impl From<AggregateExecutionError> for AggregateCountExactLiteralAotExecutionErrorV3 {
    fn from(value: AggregateExecutionError) -> Self {
        Self::Portable(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CheckedBindingV3 {
    semantic_binding_identity: AggregateCountExactLiteralAotSemanticBindingIdentity,
    planning_receipt_identity: AggregateCountExactLiteralAotPlanningReceiptIdentity,
    literal_bytes: usize,
    portable_persistent_bytes: usize,
}

/// Evidence-backed automatic route selected by a production Count-v3 facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateCountExactLiteralAotRouteV3 {
    Portable,
    AsimdAot,
    SveAot,
}

/// Value plus the production route that actually executed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateCountExactLiteralAotOutcomeV3 {
    value: u64,
    route: AggregateCountExactLiteralAotRouteV3,
}

impl AggregateCountExactLiteralAotOutcomeV3 {
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn route(self) -> AggregateCountExactLiteralAotRouteV3 {
        self.route
    }
}

/// Explicit production Count-v3 view of one fixed-policy portable owner.
///
/// The original owner remains borrowed for the complete callable lifetime.
/// Since production authority is currently empty, construction can succeed
/// only after a future reviewed tuple promotion.
pub struct AggregateCountExactLiteralAotV3<'binding> {
    portable_owner: &'binding AggregateCountRegex,
    verified: &'binding VerifiedStaticCountV3,
    checked: CheckedBindingV3,
}

impl fmt::Debug for AggregateCountExactLiteralAotV3<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AggregateCountExactLiteralAotV3")
            .field("portable_owner", &self.portable_owner)
            .field("checked", &self.checked)
            .field("eligibility_tuple", &self.verified.eligibility_tuple())
            .finish_non_exhaustive()
    }
}

impl<'binding> AggregateCountExactLiteralAotV3<'binding> {
    /// Bind an already production-adopted handle to the existing fixed-policy
    /// exact-literal owner.
    pub fn bind(
        portable_owner: &'binding AggregateCountRegex,
        verified: &'binding VerifiedStaticCountV3,
    ) -> Result<Self, AggregateCountExactLiteralAotBindErrorV3> {
        let checked = check_binding_v3(
            portable_owner.exact_literal_aot_planned_candidate(),
            verified.literal(),
            verified.semantic_binding_identity(),
            verified.planning_receipt_identity(),
        )?;
        Ok(Self {
            portable_owner,
            verified,
            checked,
        })
    }

    /// Value-only automatic production count.
    ///
    /// Inputs below the evidence floor execute through the retained portable
    /// owner. Longer inputs execute through the authenticated ASIMD image.
    #[inline]
    pub fn count_value(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<u64, AggregateCountExactLiteralAotExecutionErrorV3> {
        self.count_value_with_route(haystack, limits)
            .map(AggregateCountExactLiteralAotOutcomeV3::value)
    }

    /// Automatic production count retaining the route that actually ran.
    #[inline]
    pub fn count_value_with_route(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<AggregateCountExactLiteralAotOutcomeV3, AggregateCountExactLiteralAotExecutionErrorV3>
    {
        let limits = limits.borrow();
        let route = production_route_v3(
            haystack.len(),
            AggregateCountExactLiteralAotRouteV3::AsimdAot,
        );
        let value = match route {
            AggregateCountExactLiteralAotRouteV3::Portable => {
                self.portable_owner.count_value(haystack, limits)?
            }
            AggregateCountExactLiteralAotRouteV3::AsimdAot => {
                count_value_v3(self.verified, self.checked, haystack, limits)?
            }
            AggregateCountExactLiteralAotRouteV3::SveAot => {
                unreachable!("ASIMD facade cannot select the SVE route")
            }
        };
        Ok(AggregateCountExactLiteralAotOutcomeV3 { value, route })
    }

    /// Predict the evidence-backed route without executing either backend.
    #[must_use]
    pub const fn route_for_haystack_bytes(
        &self,
        haystack_bytes: usize,
    ) -> AggregateCountExactLiteralAotRouteV3 {
        production_route_v3(
            haystack_bytes,
            AggregateCountExactLiteralAotRouteV3::AsimdAot,
        )
    }

    #[must_use]
    pub const fn portable_owner(&self) -> &AggregateCountRegex {
        self.portable_owner
    }

    #[must_use]
    pub const fn verified_handle(&self) -> &VerifiedStaticCountV3 {
        self.verified
    }
}

/// Production fixed-VL SVE/SVE2 automatic facade.
///
/// This surface is type-disjoint from movable ASIMD production and all
/// qualification handles. It retains the fixed-policy portable owner and has
/// no direct native call method. Open a same-thread session; calls below the
/// evidence floor stay portable and calls at or above it use authenticated
/// SVE/SVE2 code.
pub struct AggregateCountExactLiteralAotSveV3<'binding> {
    portable_owner: &'binding AggregateCountRegex,
    verified: &'binding VerifiedStaticCountSveV3,
    checked: CheckedBindingV3,
}

impl fmt::Debug for AggregateCountExactLiteralAotSveV3<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AggregateCountExactLiteralAotSveV3")
            .field("portable_owner", &self.portable_owner)
            .field("checked", &self.checked)
            .field("eligibility_tuple", &self.verified.eligibility_tuple())
            .finish_non_exhaustive()
    }
}

impl<'binding> AggregateCountExactLiteralAotSveV3<'binding> {
    /// Project the live fixed-policy owner into the borrowed proof required by
    /// the production SVE/SVE2 adopter.
    pub fn adoption_binding(
        portable_owner: &'binding AggregateCountRegex,
    ) -> Result<StaticCountSveFacadeBindingV3<'binding>, AggregateCountExactLiteralAotBindErrorV3>
    {
        let candidate = portable_owner
            .exact_literal_aot_planned_candidate()
            .ok_or(
                AggregateCountExactLiteralAotBindErrorV3::PortableOwnerIsNotFixedPolicyExactLiteralCandidate,
            )?;
        Ok(StaticCountSveFacadeBindingV3::new(
            candidate.literal(),
            *candidate.semantic_binding_identity().as_bytes(),
            *candidate.planning_receipt_identity().as_bytes(),
        ))
    }

    pub fn bind(
        portable_owner: &'binding AggregateCountRegex,
        verified: &'binding VerifiedStaticCountSveV3,
    ) -> Result<Self, AggregateCountExactLiteralAotBindErrorV3> {
        let checked = check_binding_v3(
            portable_owner.exact_literal_aot_planned_candidate(),
            verified.literal(),
            verified.semantic_binding_identity(),
            verified.planning_receipt_identity(),
        )?;
        Ok(Self {
            portable_owner,
            verified,
            checked,
        })
    }

    /// Open a non-movable current-thread session after checking exact VL16.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<AggregateCountExactLiteralAotSveSessionV3<'_>, StaticCountSveThreadContractErrorV3>
    {
        Ok(AggregateCountExactLiteralAotSveSessionV3 {
            portable_owner: self.portable_owner,
            native: self.verified.begin_current_thread_session()?,
            checked: self.checked,
        })
    }

    /// Predict the evidence-backed route without opening a session or
    /// executing either backend.
    #[must_use]
    pub const fn route_for_haystack_bytes(
        &self,
        haystack_bytes: usize,
    ) -> AggregateCountExactLiteralAotRouteV3 {
        production_route_v3(haystack_bytes, AggregateCountExactLiteralAotRouteV3::SveAot)
    }

    #[must_use]
    pub const fn portable_owner(&self) -> &AggregateCountRegex {
        self.portable_owner
    }

    #[must_use]
    pub const fn verified_handle(&self) -> &VerifiedStaticCountSveV3 {
        self.verified
    }
}

/// Same-thread automatic production token for Count-v3 SVE/SVE2.
///
/// The embedded runtime token makes this value neither `Send` nor `Sync`.
/// Exact VL16 is checked again immediately before each native call.
///
/// ```compile_fail,E0277
/// use fre::AggregateCountExactLiteralAotSveSessionV3;
///
/// fn require_send<T: Send>() {}
/// require_send::<AggregateCountExactLiteralAotSveSessionV3<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre::AggregateCountExactLiteralAotSveSessionV3;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<AggregateCountExactLiteralAotSveSessionV3<'static>>();
/// ```
pub struct AggregateCountExactLiteralAotSveSessionV3<'session> {
    portable_owner: &'session AggregateCountRegex,
    native: StaticCountSveSessionV3<'session>,
    checked: CheckedBindingV3,
}

impl fmt::Debug for AggregateCountExactLiteralAotSveSessionV3<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AggregateCountExactLiteralAotSveSessionV3")
            .field("portable_owner", &self.portable_owner)
            .field("checked", &self.checked)
            .field(
                "eligibility_tuple",
                &self.native.handle().eligibility_tuple(),
            )
            .finish_non_exhaustive()
    }
}

impl AggregateCountExactLiteralAotSveSessionV3<'_> {
    /// Value-only projection of [`Self::count_value_with_route`].
    #[inline]
    pub fn count_value(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<u64, AggregateCountExactLiteralAotExecutionErrorV3> {
        self.count_value_with_route(haystack, limits)
            .map(AggregateCountExactLiteralAotOutcomeV3::value)
    }

    /// Count through the portable owner below 65,536 bytes or through the
    /// authenticated SVE/SVE2 image at and above that evidence floor.
    #[inline]
    pub fn count_value_with_route(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<AggregateCountExactLiteralAotOutcomeV3, AggregateCountExactLiteralAotExecutionErrorV3>
    {
        let limits = limits.borrow();
        let route =
            production_route_v3(haystack.len(), AggregateCountExactLiteralAotRouteV3::SveAot);
        let value = match route {
            AggregateCountExactLiteralAotRouteV3::Portable => {
                self.portable_owner.count_value(haystack, limits)?
            }
            AggregateCountExactLiteralAotRouteV3::SveAot => {
                let upper = preflight_v3(self.checked, haystack.len(), limits)?;
                self.native
                    .count(haystack, exact_runtime_limits_v3(upper))?
            }
            AggregateCountExactLiteralAotRouteV3::AsimdAot => {
                unreachable!("SVE facade cannot select the ASIMD route")
            }
        };
        Ok(AggregateCountExactLiteralAotOutcomeV3 { value, route })
    }

    #[must_use]
    pub const fn route_for_haystack_bytes(
        &self,
        haystack_bytes: usize,
    ) -> AggregateCountExactLiteralAotRouteV3 {
        production_route_v3(haystack_bytes, AggregateCountExactLiteralAotRouteV3::SveAot)
    }

    #[must_use]
    pub const fn portable_owner(&self) -> &AggregateCountRegex {
        self.portable_owner
    }

    #[must_use]
    pub const fn verified_handle(&self) -> &VerifiedStaticCountSveV3 {
        self.native.handle()
    }
}

/// Qualification-only explicit facade.
///
/// Its native handle and facade type are unavailable without the private
/// feature and cannot be substituted for the production wrapper.
#[cfg(feature = "count-v3-aot-qualification-private")]
#[doc(hidden)]
pub struct AggregateCountExactLiteralAotQualificationV3<'binding> {
    portable_owner: &'binding AggregateCountRegex,
    verified: &'binding VerifiedStaticCountQualificationV3,
    checked: CheckedBindingV3,
}

#[cfg(feature = "count-v3-aot-qualification-private")]
impl fmt::Debug for AggregateCountExactLiteralAotQualificationV3<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AggregateCountExactLiteralAotQualificationV3")
            .field("portable_owner", &self.portable_owner)
            .field("checked", &self.checked)
            .field("eligibility_tuple", &self.verified.eligibility_tuple())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "count-v3-aot-qualification-private")]
impl<'binding> AggregateCountExactLiteralAotQualificationV3<'binding> {
    /// Project the live fixed-policy owner into the borrowed proof required by
    /// the qualification-only adopter.
    pub fn adoption_binding(
        portable_owner: &'binding AggregateCountRegex,
    ) -> Result<
        StaticCountQualificationFacadeBindingV3<'binding>,
        AggregateCountExactLiteralAotBindErrorV3,
    > {
        let candidate = portable_owner
            .exact_literal_aot_planned_candidate()
            .ok_or(
                AggregateCountExactLiteralAotBindErrorV3::PortableOwnerIsNotFixedPolicyExactLiteralCandidate,
            )?;
        Ok(StaticCountQualificationFacadeBindingV3::new(
            candidate.literal(),
            *candidate.semantic_binding_identity().as_bytes(),
            *candidate.planning_receipt_identity().as_bytes(),
        ))
    }

    pub fn bind(
        portable_owner: &'binding AggregateCountRegex,
        verified: &'binding VerifiedStaticCountQualificationV3,
    ) -> Result<Self, AggregateCountExactLiteralAotBindErrorV3> {
        let checked = check_binding_v3(
            portable_owner.exact_literal_aot_planned_candidate(),
            verified.literal(),
            verified.semantic_binding_identity(),
            verified.planning_receipt_identity(),
        )?;
        Ok(Self {
            portable_owner,
            verified,
            checked,
        })
    }

    #[inline]
    pub fn count_value(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<u64, AggregateCountExactLiteralAotExecutionErrorV3> {
        let upper = preflight_v3(self.checked, haystack.len(), limits.borrow())?;
        self.verified
            .count(haystack, exact_runtime_limits_v3(upper))
            .map_err(Into::into)
    }

    #[must_use]
    pub const fn portable_owner(&self) -> &AggregateCountRegex {
        self.portable_owner
    }

    #[must_use]
    pub const fn verified_handle(&self) -> &VerifiedStaticCountQualificationV3 {
        self.verified
    }
}

/// Qualification-only fixed-VL SVE/SVE2 facade.
///
/// This type exposes no direct count method. A caller must open a same-thread
/// session, and the static runtime rechecks exact VL16 immediately before
/// every native branch. This facade and its adopter are type-disjoint from
/// both production and movable ASIMD qualification.
///
/// The facade itself deliberately has no value-call surface:
///
/// ```compile_fail,E0599
/// use fre::AggregateCountExactLiteralAotSveQualificationV3;
///
/// fn direct_count(facade: &AggregateCountExactLiteralAotSveQualificationV3<'_>) {
///     let _ = facade.count_value();
/// }
/// ```
#[cfg(feature = "count-v3-aot-qualification-private")]
#[doc(hidden)]
pub struct AggregateCountExactLiteralAotSveQualificationV3<'binding> {
    portable_owner: &'binding AggregateCountRegex,
    verified: &'binding VerifiedStaticCountSveQualificationV3,
    checked: CheckedBindingV3,
}

#[cfg(feature = "count-v3-aot-qualification-private")]
impl fmt::Debug for AggregateCountExactLiteralAotSveQualificationV3<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AggregateCountExactLiteralAotSveQualificationV3")
            .field("portable_owner", &self.portable_owner)
            .field("checked", &self.checked)
            .field("eligibility_tuple", &self.verified.eligibility_tuple())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "count-v3-aot-qualification-private")]
impl<'binding> AggregateCountExactLiteralAotSveQualificationV3<'binding> {
    /// Project the live fixed-policy owner into the borrowed proof required by
    /// the SVE/SVE2-only qualification adopter.
    pub fn adoption_binding(
        portable_owner: &'binding AggregateCountRegex,
    ) -> Result<
        StaticCountSveQualificationFacadeBindingV3<'binding>,
        AggregateCountExactLiteralAotBindErrorV3,
    > {
        let candidate = portable_owner
            .exact_literal_aot_planned_candidate()
            .ok_or(
                AggregateCountExactLiteralAotBindErrorV3::PortableOwnerIsNotFixedPolicyExactLiteralCandidate,
            )?;
        Ok(StaticCountSveQualificationFacadeBindingV3::new(
            candidate.literal(),
            *candidate.semantic_binding_identity().as_bytes(),
            *candidate.planning_receipt_identity().as_bytes(),
        ))
    }

    pub fn bind(
        portable_owner: &'binding AggregateCountRegex,
        verified: &'binding VerifiedStaticCountSveQualificationV3,
    ) -> Result<Self, AggregateCountExactLiteralAotBindErrorV3> {
        let checked = check_binding_v3(
            portable_owner.exact_literal_aot_planned_candidate(),
            verified.literal(),
            verified.semantic_binding_identity(),
            verified.planning_receipt_identity(),
        )?;
        Ok(Self {
            portable_owner,
            verified,
            checked,
        })
    }

    /// Open a session bound to this calling thread after checking exact SVE
    /// VL16. The returned token cannot move to or be shared with another
    /// thread.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<
        AggregateCountExactLiteralAotSveQualificationSessionV3<'_>,
        StaticCountSveThreadContractErrorV3,
    > {
        Ok(AggregateCountExactLiteralAotSveQualificationSessionV3 {
            portable_owner: self.portable_owner,
            native: self.verified.begin_current_thread_session()?,
            checked: self.checked,
        })
    }

    #[must_use]
    pub const fn portable_owner(&self) -> &AggregateCountRegex {
        self.portable_owner
    }

    #[must_use]
    pub const fn verified_handle(&self) -> &VerifiedStaticCountSveQualificationV3 {
        self.verified
    }
}

/// Same-thread invocation token for Count-v3 SVE/SVE2 qualification.
///
/// The embedded runtime token makes this value neither `Send` nor `Sync`.
/// Exact VL16 is checked again immediately before each native call.
///
/// ```compile_fail,E0277
/// use fre::AggregateCountExactLiteralAotSveQualificationSessionV3;
///
/// fn require_send<T: Send>() {}
/// require_send::<AggregateCountExactLiteralAotSveQualificationSessionV3<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre::AggregateCountExactLiteralAotSveQualificationSessionV3;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<AggregateCountExactLiteralAotSveQualificationSessionV3<'static>>();
/// ```
#[cfg(feature = "count-v3-aot-qualification-private")]
#[doc(hidden)]
pub struct AggregateCountExactLiteralAotSveQualificationSessionV3<'session> {
    portable_owner: &'session AggregateCountRegex,
    native: StaticCountSveQualificationSessionV3<'session>,
    checked: CheckedBindingV3,
}

#[cfg(feature = "count-v3-aot-qualification-private")]
impl fmt::Debug for AggregateCountExactLiteralAotSveQualificationSessionV3<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AggregateCountExactLiteralAotSveQualificationSessionV3")
            .field("portable_owner", &self.portable_owner)
            .field("checked", &self.checked)
            .field(
                "eligibility_tuple",
                &self.native.handle().eligibility_tuple(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "count-v3-aot-qualification-private")]
impl AggregateCountExactLiteralAotSveQualificationSessionV3<'_> {
    /// Count through the authenticated SVE/SVE2 image after the incumbent
    /// facade preflight and the runtime's immediate per-call VL16 recheck.
    #[inline]
    pub fn count_value(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<u64, AggregateCountExactLiteralAotExecutionErrorV3> {
        let upper = preflight_v3(self.checked, haystack.len(), limits.borrow())?;
        self.native
            .count(haystack, exact_runtime_limits_v3(upper))
            .map_err(Into::into)
    }

    /// Repeat one qualification call inside the runtime's closed SVE
    /// measurement contract.
    ///
    /// The facade performs its deterministic resource preflight once because
    /// every iteration has identical inputs. The runtime then prepares its
    /// call state, checks exact current-thread VL16 once, and enters a loop
    /// containing only authenticated native calls and result validation.
    #[inline]
    pub fn count_value_repeated(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
        iterations: NonZeroU64,
    ) -> Result<u64, AggregateCountExactLiteralAotExecutionErrorV3> {
        let upper = preflight_v3(self.checked, haystack.len(), limits.borrow())?;
        self.native
            .count_repeated(haystack, exact_runtime_limits_v3(upper), iterations)
            .map_err(Into::into)
    }

    #[must_use]
    pub const fn portable_owner(&self) -> &AggregateCountRegex {
        self.portable_owner
    }

    #[must_use]
    pub const fn verified_handle(&self) -> &VerifiedStaticCountSveQualificationV3 {
        self.native.handle()
    }
}

trait CountV3Handle {
    fn count_v3(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<u64, StaticCountCallErrorV3>;
}

impl CountV3Handle for VerifiedStaticCountV3 {
    #[inline]
    fn count_v3(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<u64, StaticCountCallErrorV3> {
        self.count(haystack, limits)
    }
}

const fn production_route_v3(
    haystack_bytes: usize,
    admitted_native_route: AggregateCountExactLiteralAotRouteV3,
) -> AggregateCountExactLiteralAotRouteV3 {
    if haystack_bytes < STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3 {
        AggregateCountExactLiteralAotRouteV3::Portable
    } else {
        admitted_native_route
    }
}

fn count_value_v3(
    handle: &impl CountV3Handle,
    checked: CheckedBindingV3,
    haystack: &[u8],
    limits: &AggregateRunLimits,
) -> Result<u64, AggregateCountExactLiteralAotExecutionErrorV3> {
    let upper = preflight_v3(checked, haystack.len(), limits)?;
    handle
        .count_v3(haystack, exact_runtime_limits_v3(upper))
        .map_err(Into::into)
}

fn check_binding_v3(
    candidate: Option<AggregateCountExactLiteralAotPlannedCandidate<'_>>,
    adopted_literal: &[u8],
    adopted_semantic_identity: &[u8; 32],
    adopted_planning_identity: &[u8; 32],
) -> Result<CheckedBindingV3, AggregateCountExactLiteralAotBindErrorV3> {
    let candidate = candidate.ok_or(
        AggregateCountExactLiteralAotBindErrorV3::PortableOwnerIsNotFixedPolicyExactLiteralCandidate,
    )?;
    if candidate.literal() != adopted_literal {
        return Err(AggregateCountExactLiteralAotBindErrorV3::LiteralMismatch {
            portable_bytes: candidate.literal().len(),
            adopted_bytes: adopted_literal.len(),
        });
    }
    let semantic_binding_identity = candidate.semantic_binding_identity();
    if semantic_binding_identity.as_bytes() != adopted_semantic_identity {
        return Err(
            AggregateCountExactLiteralAotBindErrorV3::SemanticBindingIdentityMismatch {
                portable: semantic_binding_identity,
                adopted: *adopted_semantic_identity,
            },
        );
    }
    let planning_receipt_identity = candidate.planning_receipt_identity();
    if planning_receipt_identity.as_bytes() != adopted_planning_identity {
        return Err(
            AggregateCountExactLiteralAotBindErrorV3::PlanningReceiptIdentityMismatch {
                portable: planning_receipt_identity,
                adopted: *adopted_planning_identity,
            },
        );
    }
    Ok(CheckedBindingV3 {
        semantic_binding_identity,
        planning_receipt_identity,
        literal_bytes: candidate.literal().len(),
        portable_persistent_bytes: candidate.build_accounting().persistent_bytes,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreflightV3 {
    match_events: usize,
    count: u64,
    reducer_steps: usize,
}

fn preflight_v3(
    checked: CheckedBindingV3,
    haystack_bytes: usize,
    limits: &AggregateRunLimits,
) -> Result<PreflightV3, AggregateCountExactLiteralAotExecutionErrorV3> {
    let literal_bytes = checked.literal_bytes;
    let linear_terms = haystack_bytes.checked_add(literal_bytes).ok_or(
        AggregateCountExactLiteralAotExecutionErrorV3::ArithmeticOverflow {
            at: "aggregate linear terms",
        },
    )?;
    let match_events = if literal_bytes == 0 {
        haystack_bytes.checked_add(1).ok_or(
            AggregateCountExactLiteralAotExecutionErrorV3::ArithmeticOverflow {
                at: "Unicode-off empty byte boundaries",
            },
        )?
    } else {
        haystack_bytes / literal_bytes
    };
    let count = u64::try_from(match_events).map_err(|_| {
        AggregateCountExactLiteralAotExecutionErrorV3::ArithmeticOverflow {
            at: "count upper bound",
        }
    })?;
    let literal_u64 = u64::try_from(literal_bytes).map_err(|_| {
        AggregateCountExactLiteralAotExecutionErrorV3::ArithmeticOverflow {
            at: "literal width",
        }
    })?;
    count.checked_mul(literal_u64).ok_or(
        AggregateCountExactLiteralAotExecutionErrorV3::ArithmeticOverflow {
            at: "span-sum upper bound",
        },
    )?;
    let reducer_steps = if literal_bytes == 0 {
        1
    } else {
        match_events.checked_add(1).ok_or(
            AggregateCountExactLiteralAotExecutionErrorV3::ArithmeticOverflow {
                at: "reducer steps",
            },
        )?
    };
    let exact = limits.exact_literal;
    require_limit("linear terms", exact.max_linear_terms, linear_terms)?;
    require_limit("match events", exact.max_match_events, match_events)?;
    require_limit("count", exact.max_count, count)?;
    require_limit("reducer steps", exact.max_reducer_steps, reducer_steps)?;
    require_limit("scratch bytes", exact.max_scratch_bytes, 0_usize)?;
    require_limit(
        "peak bytes",
        exact.max_peak_bytes,
        checked.portable_persistent_bytes,
    )?;
    Ok(PreflightV3 {
        match_events,
        count,
        reducer_steps,
    })
}

fn require_limit<T>(
    resource: &'static str,
    limit: T,
    required: T,
) -> Result<(), AggregateCountExactLiteralAotExecutionErrorV3>
where
    T: Copy + Ord + TryInto<u128>,
{
    if required <= limit {
        Ok(())
    } else {
        let limit = limit.try_into().map_err(|_| {
            AggregateCountExactLiteralAotExecutionErrorV3::ArithmeticOverflow { at: resource }
        })?;
        let required = required.try_into().map_err(|_| {
            AggregateCountExactLiteralAotExecutionErrorV3::ArithmeticOverflow { at: resource }
        })?;
        Err(
            AggregateCountExactLiteralAotExecutionErrorV3::ResourceLimit {
                resource,
                limit,
                required,
            },
        )
    }
}

const fn exact_runtime_limits_v3(upper: PreflightV3) -> AggregateExecutionLimits {
    AggregateExecutionLimits {
        max_haystack_bytes: usize::MAX,
        max_literal_bytes: 32,
        max_candidate_positions: usize::MAX,
        max_work: u64::MAX,
        max_match_events: upper.match_events,
        max_output: upper.count,
        max_reducer_steps: upper.reducer_steps,
        max_scratch_bytes: 0,
        max_native_invocations: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AggregateBuildLimits, AggregateBuilder, AggregatePlanSelection};

    fn owner(pattern: &str) -> AggregateCountRegex {
        AggregateBuilder::new(pattern)
            .unicode(false)
            .limits(AggregateBuildLimits::aot_count_exact_literal_v1())
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_count()
            .expect("fixed-policy exact owner")
    }

    #[test]
    fn binding_checks_literal_semantic_and_planning_identities() {
        let owner = owner("needle");
        let candidate = owner.exact_literal_aot_planned_candidate().unwrap();
        let literal = candidate.literal().to_vec();
        let semantic = *candidate.semantic_binding_identity().as_bytes();
        let planning = *candidate.planning_receipt_identity().as_bytes();
        assert!(
            check_binding_v3(
                owner.exact_literal_aot_planned_candidate(),
                &literal,
                &semantic,
                &planning
            )
            .is_ok()
        );

        let mut changed = semantic;
        changed[0] ^= 1;
        assert!(matches!(
            check_binding_v3(
                owner.exact_literal_aot_planned_candidate(),
                &literal,
                &changed,
                &planning
            ),
            Err(AggregateCountExactLiteralAotBindErrorV3::SemanticBindingIdentityMismatch { .. })
        ));
        let mut changed = planning;
        changed[0] ^= 1;
        assert!(matches!(
            check_binding_v3(
                owner.exact_literal_aot_planned_candidate(),
                &literal,
                &semantic,
                &changed
            ),
            Err(AggregateCountExactLiteralAotBindErrorV3::PlanningReceiptIdentityMismatch { .. })
        ));
        assert!(matches!(
            check_binding_v3(
                owner.exact_literal_aot_planned_candidate(),
                b"different",
                &semantic,
                &planning
            ),
            Err(AggregateCountExactLiteralAotBindErrorV3::LiteralMismatch { .. })
        ));
    }

    #[test]
    fn resource_preflight_matches_nonoverlapping_count_shape() {
        let owner = owner("abc");
        let candidate = owner.exact_literal_aot_planned_candidate().unwrap();
        let checked = CheckedBindingV3 {
            semantic_binding_identity: candidate.semantic_binding_identity(),
            planning_receipt_identity: candidate.planning_receipt_identity(),
            literal_bytes: candidate.literal().len(),
            portable_persistent_bytes: candidate.build_accounting().persistent_bytes,
        };
        let upper = preflight_v3(checked, 10, &AggregateRunLimits::default()).unwrap();
        assert_eq!(upper.match_events, 3);
        assert_eq!(upper.count, 3);
        assert_eq!(upper.reducer_steps, 4);
    }

    #[test]
    fn production_route_floor_is_exact_for_both_native_targets() {
        for native in [
            AggregateCountExactLiteralAotRouteV3::AsimdAot,
            AggregateCountExactLiteralAotRouteV3::SveAot,
        ] {
            assert_eq!(
                production_route_v3(STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3 - 1, native),
                AggregateCountExactLiteralAotRouteV3::Portable
            );
            assert_eq!(
                production_route_v3(STATIC_COUNT_PRODUCTION_MIN_HAYSTACK_BYTES_V3, native),
                native
            );
        }
    }
}
