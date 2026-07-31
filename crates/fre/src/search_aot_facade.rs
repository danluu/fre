//! Explicit facade binding for an already-adopted static Search-v1 Span handle.
//!
//! The original borrowed wrappers receive a [`VerifiedStaticSearchSpanV1`]
//! that the static runtime has already admitted, then bind that handle to the
//! immutable [`PortableRegex`] which still owns the exact-literal semantics.
//! The default-off tag38, tag39, and tag40 wrappers additionally invoke one
//! caller-supplied linked-glue entry through the production adopter once and
//! own the portable fallback. Binding checks both the complete facade semantic
//! identity and the live literal width before a native call can be reached.
//!
//! [`SearchExactLiteralAotV1`] never falls back and delegates exactly once to
//! the static runtime's checked call boundary. The separately typed
//! [`SearchExactLiteralAutoAotV1`] requires a source-qualified broad-family
//! execution policy: below-floor work stays directly portable, while eligible
//! work receives one full preflight followed by a portable prefix and a
//! disjoint static tail. Neither wrapper compiles, links, populates authority,
//! adopts an address, or borrows JIT authority.

use core::fmt;

#[cfg(feature = "compiled-search-v25-aot")]
use fre_aot_search_contract::SEARCH_BACKEND_ASIMD_TAG38_V1;
#[cfg(feature = "compiled-search-v27-aot")]
use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG40_V1, search_v27_production_literal_width_is_valid_v1,
};
#[cfg(feature = "compiled-search-v25-aot")]
use fre_aot_search_contract::search_backend_literal_width_is_valid_v1;
#[cfg(feature = "compiled-search-v26-aot")]
use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG39_V1, search_v26_production_literal_width_is_valid_v1,
};
#[cfg(any(
    feature = "compiled-search-v25-aot",
    feature = "compiled-search-v26-aot",
    feature = "compiled-search-v27-aot"
))]
use fre_aot_static_runtime::{
    RawStaticSearchSpanAdoptionOutputV1, StaticSearchSpanAdoptionErrorV1,
    adopt_linked_static_search_span_v1,
};
use fre_aot_static_runtime::{
    StaticSearchSpanCallErrorV1, StaticSearchSpanFamilyExecutionPolicyV1,
    StaticSearchSpanThreadContractErrorV1, StaticSearchSpanThreadSessionV1,
    VerifiedStaticSearchSpanV1,
};
use fre_kernel_ir::{CheckedSearchWindow, MatchSpan, SearchWindow as NativeSearchWindow};
use fre_kernels::{
    LiteralAccounting, LiteralPlan, LiteralSearchPrefixSplit, LiteralSearchPreflight,
    Window as LiteralWindow,
};

#[cfg(any(
    feature = "compiled-search-v25-aot",
    feature = "compiled-search-v26-aot",
    feature = "compiled-search-v27-aot"
))]
use crate::SearchError;
use crate::{
    Match, PortablePlan, PortableRegex, SearchAccounting, SearchExactLiteralAotCandidate,
    SearchExactLiteralAotSemanticBindingIdentity, SearchLimits, SearchWindow, literal_limits,
};

/// Failure to bind an already-adopted static Search handle to its semantic
/// owner.
///
/// A refusal creates no wrapper and cannot invoke native code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchExactLiteralAotBindErrorV1 {
    /// The portable owner no longer satisfies the exact default-policy
    /// candidate contract.
    PortableOwnerIsNotExactLiteralCandidate,
    /// The adopted object was compiled for a different facade semantic
    /// identity.
    SemanticBindingIdentityMismatch {
        portable: SearchExactLiteralAotSemanticBindingIdentity,
        adopted: [u8; 32],
    },
    /// The portable literal width cannot be represented by the static V1
    /// contract.
    PortableLiteralWidthNotRepresentable { bytes: usize },
    /// The authenticated object embeds a different live literal width.
    LiveLiteralWidthMismatch {
        portable_bytes: u32,
        adopted_bytes: u32,
    },
    /// The adopted compiler-domain literal identity does not authenticate the
    /// portable owner's exact literal bytes.
    LiteralIdentityMismatch,
    /// Only a broad, source-qualified production family can authorize
    /// automatic workload routing. Exact legacy rows remain AOT-only.
    ProductionFamilyExecutionPolicyRequired,
    /// The authenticated family floor cannot be represented on this target.
    MinimumWindowBytesNotRepresentable { bytes: u32 },
    /// The authenticated portable-prefix size cannot be represented on this
    /// target.
    PortablePrefixCandidateStartsNotRepresentable { starts: u32 },
    /// The live literal is outside the authenticated broad-family routing
    /// envelope. The static runtime already enforces this at adoption; the
    /// facade repeats it before publishing an automatic route.
    LiteralWidthOutsideProductionFamily {
        literal_bytes: u32,
        minimum_bytes: u32,
        maximum_bytes: u32,
    },
}

impl fmt::Display for SearchExactLiteralAotBindErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE exact-literal Search-v1 AOT facade binding failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchExactLiteralAotBindErrorV1 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CheckedBindingV1 {
    semantic_binding_identity: SearchExactLiteralAotSemanticBindingIdentity,
    literal_bytes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CheckedAutomaticPolicyV1 {
    source: StaticSearchSpanFamilyExecutionPolicyV1,
    minimum_window_bytes: usize,
    portable_prefix_candidate_starts: usize,
}

/// Safe, explicit Search-v1 Span AOT view of one portable exact-literal owner.
///
/// This value borrows both sides of the binding. The portable matcher remains
/// the semantic owner for the complete callable lifetime, while the static
/// runtime remains the sole owner of the authenticated native entry.
///
/// This type is available only with the default-off
/// `explicit-search-span-aot` feature. Constructing it does not enable an AOT
/// route anywhere else in [`PortableRegex`].
pub struct SearchExactLiteralAotV1<'binding> {
    portable_owner: &'binding PortableRegex,
    verified: &'binding VerifiedStaticSearchSpanV1,
    checked: CheckedBindingV1,
}

impl fmt::Debug for SearchExactLiteralAotV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchExactLiteralAotV1")
            .field("portable_owner", &self.portable_owner)
            .field(
                "semantic_binding_identity",
                &self.checked.semantic_binding_identity,
            )
            .field("literal_bytes", &self.checked.literal_bytes)
            .field("backend_version", &self.verified.backend_version())
            .finish_non_exhaustive()
    }
}

impl<'binding> SearchExactLiteralAotV1<'binding> {
    /// Bind one already-adopted handle to its exact portable semantic owner.
    ///
    /// The portable candidate is recomputed through
    /// [`PortableRegex::exact_literal_search_aot_candidate`]. Its complete
    /// semantic identity and literal width must match the independently
    /// authenticated static expectation.
    ///
    /// This constructor does not adopt or inspect raw addresses and cannot
    /// populate either static-runtime authority table.
    ///
    /// # Errors
    ///
    /// Returns [`SearchExactLiteralAotBindErrorV1`] before publishing a
    /// wrapper if eligibility, identity, or width differs.
    pub fn bind(
        portable_owner: &'binding PortableRegex,
        verified: &'binding VerifiedStaticSearchSpanV1,
    ) -> Result<Self, SearchExactLiteralAotBindErrorV1> {
        let checked = check_binding_v1(
            portable_owner.exact_literal_search_aot_candidate(),
            verified.semantic_binding_identity(),
            verified.live_literal_bytes(),
            |literal| verified.authenticates_literal(literal),
        )?;
        Ok(Self {
            portable_owner,
            verified,
            checked,
        })
    }

    /// Search the complete haystack through the bound static handle.
    ///
    /// This is an explicit AOT-only call. It never invokes the portable plan
    /// as a fallback. Tag21 returns `ThreadSessionRequired`; use
    /// [`Self::begin_current_thread_session`] for that backend.
    ///
    /// # Errors
    ///
    /// Returns [`StaticSearchSpanCallErrorV1`] for a resource refusal, an
    /// invalid native result, a backend fault, or a required tag21 session.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), StaticSearchSpanCallErrorV1> {
        let (matched, accounting) = self.verified.find(haystack, literal_limits(limits))?;
        Ok((
            matched.map(project_match),
            SearchAccounting::ExactLiteral(accounting),
        ))
    }

    /// Search one checked half-open window through the bound static handle.
    ///
    /// The static runtime performs the sole resource/window preflight before
    /// the native call. This wrapper adds no second portable search or
    /// preflight.
    ///
    /// # Errors
    ///
    /// Returns [`StaticSearchSpanCallErrorV1`] under the same contract as
    /// [`Self::find`].
    #[inline]
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), StaticSearchSpanCallErrorV1> {
        let native_window = NativeSearchWindow::new(window.start(), window.end());
        let (matched, accounting) =
            self.verified
                .search(haystack, native_window, literal_limits(limits))?;
        Ok((
            matched.map(project_match),
            SearchAccounting::ExactLiteral(accounting),
        ))
    }

    /// Establish one same-thread static invocation session.
    ///
    /// For tag21, the static runtime checks exact SVE VL16 once here. Calls on
    /// the returned token perform no per-call vector-length syscall. Changing
    /// the thread's vector length invalidates the native runtime's contract
    /// and requires a new session.
    ///
    /// # Errors
    ///
    /// Returns [`StaticSearchSpanThreadContractErrorV1`] if the current
    /// thread does not satisfy the adopted backend's contract.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<SearchExactLiteralAotThreadSessionV1<'_>, StaticSearchSpanThreadContractErrorV1>
    {
        Ok(SearchExactLiteralAotThreadSessionV1 {
            portable_owner: self.portable_owner,
            native: self.verified.begin_current_thread_session()?,
            checked: self.checked,
        })
    }

    /// Portable matcher retained as the binding's semantic owner.
    #[must_use]
    pub const fn portable_owner(&self) -> &PortableRegex {
        self.portable_owner
    }

    /// Already-adopted handle retained as the native entry owner.
    #[must_use]
    pub const fn verified_handle(&self) -> &VerifiedStaticSearchSpanV1 {
        self.verified
    }

    /// Complete facade semantic identity checked at binding.
    #[must_use]
    pub const fn semantic_binding_identity(&self) -> SearchExactLiteralAotSemanticBindingIdentity {
        self.checked.semantic_binding_identity
    }

    /// Exact live literal width checked at binding.
    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.checked.literal_bytes
    }
}

/// Safe automatic portable/AOT view of one source-qualified static Search
/// family.
///
/// This wrapper is deliberately separate from [`SearchExactLiteralAotV1`].
/// Exact legacy rows can still be called explicitly through that type, but
/// they cannot acquire automatic routing authority. Construction here
/// requires the source-qualified family policy retained by the adopted
/// handle, including its minimum window, portable-prefix ownership, and
/// qualification identities.
///
/// Calls below the authenticated window floor execute the portable owner
/// directly. Eligible calls perform one full-window resource preflight,
/// search the family-owned portable prefix, and invoke the static entry only
/// for the disjoint tail. A native failure is returned to the caller; it is
/// never hidden by retrying the portable engine.
pub struct SearchExactLiteralAutoAotV1<'binding> {
    portable_owner: &'binding PortableRegex,
    portable_plan: &'binding LiteralPlan,
    verified: &'binding VerifiedStaticSearchSpanV1,
    checked: CheckedBindingV1,
    policy: CheckedAutomaticPolicyV1,
}

impl fmt::Debug for SearchExactLiteralAutoAotV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchExactLiteralAutoAotV1")
            .field("portable_owner", &self.portable_owner)
            .field(
                "semantic_binding_identity",
                &self.checked.semantic_binding_identity,
            )
            .field("literal_bytes", &self.checked.literal_bytes)
            .field("backend_version", &self.verified.backend_version())
            .field("family_execution_policy", &self.policy.source)
            .finish_non_exhaustive()
    }
}

impl<'binding> SearchExactLiteralAutoAotV1<'binding> {
    /// Bind a portable exact-literal semantic owner to one adopted production
    /// family and its authenticated automatic-routing policy.
    ///
    /// # Errors
    ///
    /// Returns [`SearchExactLiteralAotBindErrorV1`] if either the semantic
    /// binding or the source-qualified execution policy is unavailable.
    pub fn bind(
        portable_owner: &'binding PortableRegex,
        verified: &'binding VerifiedStaticSearchSpanV1,
    ) -> Result<Self, SearchExactLiteralAotBindErrorV1> {
        let checked = check_binding_v1(
            portable_owner.exact_literal_search_aot_candidate(),
            verified.semantic_binding_identity(),
            verified.live_literal_bytes(),
            |literal| verified.authenticates_literal(literal),
        )?;
        let policy = checked_automatic_policy_v1(
            verified
                .family_execution_policy()
                .ok_or(SearchExactLiteralAotBindErrorV1::ProductionFamilyExecutionPolicyRequired)?,
            checked.literal_bytes,
        )?;
        let PortablePlan::ExactLiteral(portable_plan) = &portable_owner.plan else {
            return Err(SearchExactLiteralAotBindErrorV1::PortableOwnerIsNotExactLiteralCandidate);
        };
        Ok(Self {
            portable_owner,
            portable_plan,
            verified,
            checked,
            policy,
        })
    }

    /// Search a complete haystack with the authenticated portable-prefix/AOT-
    /// tail policy.
    ///
    /// # Errors
    ///
    /// Returns [`StaticSearchSpanCallErrorV1`] for a portable preflight
    /// refusal, a native result failure, or a backend thread-contract
    /// requirement.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), StaticSearchSpanCallErrorV1> {
        self.find_window(haystack, SearchWindow::new(0, haystack.len()), limits)
    }

    /// Search one half-open window with the authenticated portable-prefix/AOT-
    /// tail policy.
    ///
    /// Invalid or below-floor windows go directly through the portable owner,
    /// before a [`CheckedSearchWindow`] or native preflight token is created.
    /// Eligible windows receive one authoritative full-window preflight. A
    /// prefix match returns that full accounting; otherwise the exact same
    /// token is narrowed to the disjoint AOT tail.
    ///
    /// # Errors
    ///
    /// Returns [`StaticSearchSpanCallErrorV1`] without retrying a failed native
    /// call.
    #[inline]
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), StaticSearchSpanCallErrorV1> {
        find_window_automatically_v1(
            self.portable_plan,
            haystack,
            window,
            limits,
            self.policy.minimum_window_bytes,
            self.policy.portable_prefix_candidate_starts,
            |tail| self.verified.search_preflighted(tail),
        )
    }

    /// Portable matcher retained as the semantic and fallback owner.
    #[must_use]
    pub const fn portable_owner(&self) -> &PortableRegex {
        self.portable_owner
    }

    /// Adopted source-family handle retained as the tail executor.
    #[must_use]
    pub const fn verified_handle(&self) -> &VerifiedStaticSearchSpanV1 {
        self.verified
    }

    /// Complete facade semantic identity checked at binding.
    #[must_use]
    pub const fn semantic_binding_identity(&self) -> SearchExactLiteralAotSemanticBindingIdentity {
        self.checked.semantic_binding_identity
    }

    /// Exact live literal width checked at binding.
    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.checked.literal_bytes
    }

    /// Authenticated production-family execution and evidence policy.
    #[must_use]
    pub const fn family_execution_policy(&self) -> StaticSearchSpanFamilyExecutionPolicyV1 {
        self.policy.source
    }
}

#[cfg(any(
    feature = "compiled-search-v25-aot",
    feature = "compiled-search-v26-aot",
    feature = "compiled-search-v27-aot"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchExactLiteralCompiledAotFallbackV1 {
    PortableOwnerIneligible,
    LiteralWidthOutsideProductionEnvelope { bytes: usize },
    Adoption(StaticSearchSpanAdoptionErrorV1),
    BackendMismatch { actual: u16 },
    Binding(SearchExactLiteralAotBindErrorV1),
}

#[cfg(any(
    feature = "compiled-search-v25-aot",
    feature = "compiled-search-v26-aot",
    feature = "compiled-search-v27-aot"
))]
#[derive(Clone, Copy, Debug)]
enum SearchExactLiteralCompiledAotStateV1 {
    Portable(SearchExactLiteralCompiledAotFallbackV1),
    Static {
        verified: &'static VerifiedStaticSearchSpanV1,
        policy: CheckedAutomaticPolicyV1,
    },
}

#[cfg(any(
    feature = "compiled-search-v25-aot",
    feature = "compiled-search-v26-aot",
    feature = "compiled-search-v27-aot"
))]
fn bind_compiled_aot_state_v1(
    portable_owner: &PortableRegex,
    expected_backend: u16,
    literal_width_is_valid: impl FnOnce(usize) -> bool,
    invoke_glue: impl FnOnce(*mut RawStaticSearchSpanAdoptionOutputV1) -> u32,
) -> SearchExactLiteralCompiledAotStateV1 {
    let Some(candidate) = portable_owner.exact_literal_search_aot_candidate() else {
        return SearchExactLiteralCompiledAotStateV1::Portable(
            SearchExactLiteralCompiledAotFallbackV1::PortableOwnerIneligible,
        );
    };
    if !literal_width_is_valid(candidate.literal().len()) {
        return SearchExactLiteralCompiledAotStateV1::Portable(
            SearchExactLiteralCompiledAotFallbackV1::LiteralWidthOutsideProductionEnvelope {
                bytes: candidate.literal().len(),
            },
        );
    }
    let verified = match adopt_linked_static_search_span_v1(invoke_glue) {
        Ok(verified) => verified,
        Err(error) => {
            return SearchExactLiteralCompiledAotStateV1::Portable(
                SearchExactLiteralCompiledAotFallbackV1::Adoption(error),
            );
        }
    };
    if let Err(reason) = check_compiled_aot_backend_v1(verified.backend_version(), expected_backend)
    {
        return SearchExactLiteralCompiledAotStateV1::Portable(reason);
    }
    let checked = check_binding_v1(
        Some(candidate),
        verified.semantic_binding_identity(),
        verified.live_literal_bytes(),
        |literal| verified.authenticates_literal(literal),
    );
    match checked.and_then(|checked| {
        checked_automatic_policy_v1(
            verified
                .family_execution_policy()
                .ok_or(SearchExactLiteralAotBindErrorV1::ProductionFamilyExecutionPolicyRequired)?,
            checked.literal_bytes,
        )
    }) {
        Ok(policy) => SearchExactLiteralCompiledAotStateV1::Static { verified, policy },
        Err(error) => SearchExactLiteralCompiledAotStateV1::Portable(
            SearchExactLiteralCompiledAotFallbackV1::Binding(error),
        ),
    }
}

#[cfg(any(
    feature = "compiled-search-v25-aot",
    feature = "compiled-search-v26-aot",
    feature = "compiled-search-v27-aot"
))]
const fn check_compiled_aot_backend_v1(
    actual: u16,
    expected: u16,
) -> Result<(), SearchExactLiteralCompiledAotFallbackV1> {
    if actual == expected {
        Ok(())
    } else {
        Err(SearchExactLiteralCompiledAotFallbackV1::BackendMismatch { actual })
    }
}

/// Why the default-off V25 compiled facade cached its portable route.
///
/// Binding refusals are construction-time facts. They are retained for
/// inspection and are never retried by a search call.
#[cfg(feature = "compiled-search-v25-aot")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchExactLiteralCompiledAotV25Fallback {
    /// The portable owner is not an exact literal under the fixed default
    /// construction policy. The supplied glue entry was not called.
    PortableOwnerIneligible,
    /// The exact literal is outside tag38's immutable 6..=32-byte wire
    /// envelope. The supplied glue entry was not called.
    LiteralWidthOutsideBackendEnvelope { bytes: usize },
    /// Production glue could not resolve one source-authorized handle.
    Adoption(StaticSearchSpanAdoptionErrorV1),
    /// A source-authorized handle named a backend other than tag38.
    BackendMismatch { actual: u16 },
    /// The adopted object did not bind to this exact portable source/literal
    /// owner and broad-family execution policy.
    Binding(SearchExactLiteralAotBindErrorV1),
}

/// Which executor one compiled-facade search actually used.
#[cfg(feature = "compiled-search-v25-aot")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchExactLiteralCompiledAotV25Route {
    Portable,
    StaticAot,
}

/// Search failure from the owning V25 compiled facade.
#[cfg(feature = "compiled-search-v25-aot")]
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchExactLiteralCompiledAotV25Error {
    Portable(SearchError),
    Static(StaticSearchSpanCallErrorV1),
}

#[cfg(feature = "compiled-search-v25-aot")]
impl fmt::Display for SearchExactLiteralCompiledAotV25Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE exact-literal compiled V25 AOT search failed: {self:?}"
        )
    }
}

#[cfg(feature = "compiled-search-v25-aot")]
impl std::error::Error for SearchExactLiteralCompiledAotV25Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Portable(error) => Some(error),
            Self::Static(error) => Some(error),
        }
    }
}

#[cfg(feature = "compiled-search-v25-aot")]
impl From<SearchError> for SearchExactLiteralCompiledAotV25Error {
    fn from(error: SearchError) -> Self {
        Self::Portable(error)
    }
}

#[cfg(feature = "compiled-search-v25-aot")]
impl From<StaticSearchSpanCallErrorV1> for SearchExactLiteralCompiledAotV25Error {
    fn from(error: StaticSearchSpanCallErrorV1) -> Self {
        Self::Static(error)
    }
}

#[cfg(feature = "compiled-search-v25-aot")]
#[derive(Clone, Copy, Debug)]
enum SearchExactLiteralCompiledAotV25State {
    Portable(SearchExactLiteralCompiledAotV25Fallback),
    Static {
        verified: &'static VerifiedStaticSearchSpanV1,
        policy: CheckedAutomaticPolicyV1,
    },
}

/// Owning, bind-once exact-literal facade for an explicitly linked tag38
/// source object.
///
/// This type is available only through the default-off
/// `compiled-search-v25-aot` feature. Construction first proves that the
/// portable owner is an exact default-policy literal inside tag38's immutable
/// width envelope, then invokes the supplied source-specific production
/// adopter at most once. Missing authority, an unqualified selector, a
/// backend mismatch, or any semantic-binding refusal is cached as a portable
/// route. Searches never repeat adoption or binding. Because this facade
/// itself calls the production adopter, a private-qualification handle cannot
/// be substituted by the caller.
///
/// The adopter cannot manufacture authority: its successful handle can come
/// only from the static runtime's source-reviewed production registry. In the
/// unactivated scaffold that registry has no V25 authorization or family row,
/// so every real tag38 glue call resolves to the portable state.
///
/// The facade deliberately does not duplicate the emitter's cyclic-phase
/// selector. A source-specific object/glue pair cannot be built unless the
/// V25 compiler admits that exact literal shape, and production adoption
/// independently regenerates the V25 payload from its mapped literal before
/// returning a verified handle. Thus width is rejected before glue, while
/// phase-shape eligibility is proved at both object construction and runtime
/// adoption without a drift-prone third implementation.
#[cfg(feature = "compiled-search-v25-aot")]
pub struct SearchExactLiteralCompiledAotV25 {
    portable_owner: PortableRegex,
    state: SearchExactLiteralCompiledAotV25State,
}

#[cfg(feature = "compiled-search-v25-aot")]
impl fmt::Debug for SearchExactLiteralCompiledAotV25 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchExactLiteralCompiledAotV25")
            .field("portable_owner", &self.portable_owner)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "compiled-search-v25-aot")]
impl SearchExactLiteralCompiledAotV25 {
    /// Bind one generated source-specific production glue entry once.
    ///
    /// `invoke_glue` is not called for a non-exact, non-default-policy, or
    /// out-of-envelope portable owner. The static runtime resolves its result
    /// only in the production registry. All adopter and binding refusals
    /// produce a usable portable facade instead of a partially initialized
    /// native value.
    #[must_use]
    pub fn bind_once(
        portable_owner: PortableRegex,
        invoke_glue: impl FnOnce(*mut RawStaticSearchSpanAdoptionOutputV1) -> u32,
    ) -> Self {
        let state = v25_state(bind_compiled_aot_state_v1(
            &portable_owner,
            SEARCH_BACKEND_ASIMD_TAG38_V1,
            v25_literal_width_is_valid,
            invoke_glue,
        ));
        Self {
            portable_owner,
            state,
        }
    }

    /// Search a complete haystack through the cached route.
    ///
    /// A construction-time portable decision stays portable. A successfully
    /// bound native route applies the authenticated window-floor and
    /// portable-prefix policy. Native call failures are reported and are not
    /// hidden by a second portable search.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<
        (
            Option<Match>,
            SearchAccounting,
            SearchExactLiteralCompiledAotV25Route,
        ),
        SearchExactLiteralCompiledAotV25Error,
    > {
        self.find_window(haystack, SearchWindow::new(0, haystack.len()), limits)
    }

    /// Search one half-open window through the cached route.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<
        (
            Option<Match>,
            SearchAccounting,
            SearchExactLiteralCompiledAotV25Route,
        ),
        SearchExactLiteralCompiledAotV25Error,
    > {
        match self.state {
            SearchExactLiteralCompiledAotV25State::Portable(_) => {
                let (matched, accounting) =
                    self.portable_owner.find_window(haystack, window, limits)?;
                Ok((
                    matched,
                    accounting,
                    SearchExactLiteralCompiledAotV25Route::Portable,
                ))
            }
            SearchExactLiteralCompiledAotV25State::Static { verified, policy } => {
                let PortablePlan::ExactLiteral(portable_plan) = &self.portable_owner.plan else {
                    unreachable!("a static V25 state is created only for an exact portable owner");
                };
                let mut static_invoked = false;
                let (matched, accounting) = find_window_automatically_v1(
                    portable_plan,
                    haystack,
                    window,
                    limits,
                    policy.minimum_window_bytes,
                    policy.portable_prefix_candidate_starts,
                    |tail| {
                        static_invoked = true;
                        verified.search_preflighted(tail)
                    },
                )?;
                Ok((
                    matched,
                    accounting,
                    if static_invoked {
                        SearchExactLiteralCompiledAotV25Route::StaticAot
                    } else {
                        SearchExactLiteralCompiledAotV25Route::Portable
                    },
                ))
            }
        }
    }

    /// Portable semantic owner retained for every route.
    #[must_use]
    pub const fn portable_owner(&self) -> &PortableRegex {
        &self.portable_owner
    }

    /// Cached construction-time fallback, or `None` after a successful bind.
    #[must_use]
    pub const fn fallback_reason(&self) -> Option<SearchExactLiteralCompiledAotV25Fallback> {
        match self.state {
            SearchExactLiteralCompiledAotV25State::Portable(reason) => Some(reason),
            SearchExactLiteralCompiledAotV25State::Static { .. } => None,
        }
    }

    /// Source-authorized tag38 handle retained after successful binding.
    #[must_use]
    pub const fn verified_handle(&self) -> Option<&'static VerifiedStaticSearchSpanV1> {
        match self.state {
            SearchExactLiteralCompiledAotV25State::Portable(_) => None,
            SearchExactLiteralCompiledAotV25State::Static { verified, .. } => Some(verified),
        }
    }
}

#[cfg(feature = "compiled-search-v25-aot")]
const fn v25_state(
    state: SearchExactLiteralCompiledAotStateV1,
) -> SearchExactLiteralCompiledAotV25State {
    match state {
        SearchExactLiteralCompiledAotStateV1::Portable(reason) => {
            SearchExactLiteralCompiledAotV25State::Portable(v25_fallback_reason(reason))
        }
        SearchExactLiteralCompiledAotStateV1::Static { verified, policy } => {
            SearchExactLiteralCompiledAotV25State::Static { verified, policy }
        }
    }
}

#[cfg(feature = "compiled-search-v25-aot")]
const fn v25_fallback_reason(
    reason: SearchExactLiteralCompiledAotFallbackV1,
) -> SearchExactLiteralCompiledAotV25Fallback {
    match reason {
        SearchExactLiteralCompiledAotFallbackV1::PortableOwnerIneligible => {
            SearchExactLiteralCompiledAotV25Fallback::PortableOwnerIneligible
        }
        SearchExactLiteralCompiledAotFallbackV1::LiteralWidthOutsideProductionEnvelope {
            bytes,
        } => SearchExactLiteralCompiledAotV25Fallback::LiteralWidthOutsideBackendEnvelope { bytes },
        SearchExactLiteralCompiledAotFallbackV1::Adoption(error) => {
            SearchExactLiteralCompiledAotV25Fallback::Adoption(error)
        }
        SearchExactLiteralCompiledAotFallbackV1::BackendMismatch { actual } => {
            SearchExactLiteralCompiledAotV25Fallback::BackendMismatch { actual }
        }
        SearchExactLiteralCompiledAotFallbackV1::Binding(error) => {
            SearchExactLiteralCompiledAotV25Fallback::Binding(error)
        }
    }
}

#[cfg(feature = "compiled-search-v25-aot")]
fn v25_literal_width_is_valid(bytes: usize) -> bool {
    u32::try_from(bytes).is_ok_and(|bytes| {
        search_backend_literal_width_is_valid_v1(SEARCH_BACKEND_ASIMD_TAG38_V1, bytes)
    })
}

/// Why the default-off V26 compiled facade cached its portable route.
///
/// Binding refusals are construction-time facts. They are retained for
/// inspection and are never retried by a search call.
#[cfg(feature = "compiled-search-v26-aot")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchExactLiteralCompiledAotV26Fallback {
    /// The portable owner is not an exact literal under the fixed default
    /// construction policy. The supplied glue entry was not called.
    PortableOwnerIneligible,
    /// The exact literal is outside V26's production 9..=32-byte envelope.
    /// The supplied glue entry was not called.
    LiteralWidthOutsideProductionEnvelope { bytes: usize },
    /// Production glue could not resolve one source-authorized handle.
    Adoption(StaticSearchSpanAdoptionErrorV1),
    /// A source-authorized handle named a backend other than tag39.
    BackendMismatch { actual: u16 },
    /// The adopted object did not bind to this exact portable source/literal
    /// owner and broad-family execution policy.
    Binding(SearchExactLiteralAotBindErrorV1),
}

/// Which executor one V26 compiled-facade search actually used.
#[cfg(feature = "compiled-search-v26-aot")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchExactLiteralCompiledAotV26Route {
    Portable,
    StaticAot,
}

/// Search failure from the owning V26 compiled facade.
#[cfg(feature = "compiled-search-v26-aot")]
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchExactLiteralCompiledAotV26Error {
    Portable(SearchError),
    Static(StaticSearchSpanCallErrorV1),
}

#[cfg(feature = "compiled-search-v26-aot")]
impl fmt::Display for SearchExactLiteralCompiledAotV26Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE exact-literal compiled V26 AOT search failed: {self:?}"
        )
    }
}

#[cfg(feature = "compiled-search-v26-aot")]
impl std::error::Error for SearchExactLiteralCompiledAotV26Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Portable(error) => Some(error),
            Self::Static(error) => Some(error),
        }
    }
}

#[cfg(feature = "compiled-search-v26-aot")]
impl From<SearchError> for SearchExactLiteralCompiledAotV26Error {
    fn from(error: SearchError) -> Self {
        Self::Portable(error)
    }
}

#[cfg(feature = "compiled-search-v26-aot")]
impl From<StaticSearchSpanCallErrorV1> for SearchExactLiteralCompiledAotV26Error {
    fn from(error: StaticSearchSpanCallErrorV1) -> Self {
        Self::Static(error)
    }
}

/// Owning, bind-once exact-literal facade for an explicitly linked tag39
/// source object.
///
/// This type is available only through the default-off
/// `compiled-search-v26-aot` feature. Construction first proves that the
/// portable owner is an exact default-policy literal inside the V26
/// production 9..=32-byte envelope, then invokes the supplied source-specific
/// production adopter at most once. Widths 0..=8 and above 32 never call
/// glue. Missing authority, an unqualified selector, a backend mismatch, or
/// any semantic-binding refusal is cached as a portable route.
///
/// The adopter can resolve only the static runtime's source-reviewed
/// production registry. The checked-in V26 authorization atom is fixed to
/// `None` and the production family table contains no tag39 row, so this seam
/// cannot activate even when all Cargo features are selected. No ordinary
/// [`PortableRegex`] method or JIT route is changed.
#[cfg(feature = "compiled-search-v26-aot")]
pub struct SearchExactLiteralCompiledAotV26 {
    portable_owner: PortableRegex,
    state: SearchExactLiteralCompiledAotStateV1,
}

#[cfg(feature = "compiled-search-v26-aot")]
impl fmt::Debug for SearchExactLiteralCompiledAotV26 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchExactLiteralCompiledAotV26")
            .field("portable_owner", &self.portable_owner)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "compiled-search-v26-aot")]
impl SearchExactLiteralCompiledAotV26 {
    /// Bind one generated source-specific tag39 production glue entry once.
    ///
    /// `invoke_glue` is not called for a non-exact, non-default-policy, or
    /// out-of-production-envelope portable owner. All adopter and binding
    /// refusals produce a usable portable facade.
    #[must_use]
    pub fn bind_once(
        portable_owner: PortableRegex,
        invoke_glue: impl FnOnce(*mut RawStaticSearchSpanAdoptionOutputV1) -> u32,
    ) -> Self {
        let state = bind_compiled_aot_state_v1(
            &portable_owner,
            SEARCH_BACKEND_ASIMD_TAG39_V1,
            v26_literal_width_is_valid,
            invoke_glue,
        );
        Self {
            portable_owner,
            state,
        }
    }

    /// Search a complete haystack through the cached route.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<
        (
            Option<Match>,
            SearchAccounting,
            SearchExactLiteralCompiledAotV26Route,
        ),
        SearchExactLiteralCompiledAotV26Error,
    > {
        self.find_window(haystack, SearchWindow::new(0, haystack.len()), limits)
    }

    /// Search one half-open window through the cached route.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<
        (
            Option<Match>,
            SearchAccounting,
            SearchExactLiteralCompiledAotV26Route,
        ),
        SearchExactLiteralCompiledAotV26Error,
    > {
        match self.state {
            SearchExactLiteralCompiledAotStateV1::Portable(_) => {
                let (matched, accounting) =
                    self.portable_owner.find_window(haystack, window, limits)?;
                Ok((
                    matched,
                    accounting,
                    SearchExactLiteralCompiledAotV26Route::Portable,
                ))
            }
            SearchExactLiteralCompiledAotStateV1::Static { verified, policy } => {
                let PortablePlan::ExactLiteral(portable_plan) = &self.portable_owner.plan else {
                    unreachable!("a static V26 state is created only for an exact portable owner");
                };
                let mut static_invoked = false;
                let (matched, accounting) = find_window_automatically_v1(
                    portable_plan,
                    haystack,
                    window,
                    limits,
                    policy.minimum_window_bytes,
                    policy.portable_prefix_candidate_starts,
                    |tail| {
                        static_invoked = true;
                        verified.search_preflighted(tail)
                    },
                )?;
                Ok((
                    matched,
                    accounting,
                    if static_invoked {
                        SearchExactLiteralCompiledAotV26Route::StaticAot
                    } else {
                        SearchExactLiteralCompiledAotV26Route::Portable
                    },
                ))
            }
        }
    }

    /// Portable semantic owner retained for every route.
    #[must_use]
    pub const fn portable_owner(&self) -> &PortableRegex {
        &self.portable_owner
    }

    /// Cached construction-time fallback, or `None` after a successful bind.
    #[must_use]
    pub const fn fallback_reason(&self) -> Option<SearchExactLiteralCompiledAotV26Fallback> {
        match self.state {
            SearchExactLiteralCompiledAotStateV1::Portable(reason) => {
                Some(v26_fallback_reason(reason))
            }
            SearchExactLiteralCompiledAotStateV1::Static { .. } => None,
        }
    }

    /// Source-authorized tag39 handle retained after successful binding.
    #[must_use]
    pub const fn verified_handle(&self) -> Option<&'static VerifiedStaticSearchSpanV1> {
        match self.state {
            SearchExactLiteralCompiledAotStateV1::Portable(_) => None,
            SearchExactLiteralCompiledAotStateV1::Static { verified, .. } => Some(verified),
        }
    }
}

#[cfg(feature = "compiled-search-v26-aot")]
const fn v26_fallback_reason(
    reason: SearchExactLiteralCompiledAotFallbackV1,
) -> SearchExactLiteralCompiledAotV26Fallback {
    match reason {
        SearchExactLiteralCompiledAotFallbackV1::PortableOwnerIneligible => {
            SearchExactLiteralCompiledAotV26Fallback::PortableOwnerIneligible
        }
        SearchExactLiteralCompiledAotFallbackV1::LiteralWidthOutsideProductionEnvelope {
            bytes,
        } => SearchExactLiteralCompiledAotV26Fallback::LiteralWidthOutsideProductionEnvelope {
            bytes,
        },
        SearchExactLiteralCompiledAotFallbackV1::Adoption(error) => {
            SearchExactLiteralCompiledAotV26Fallback::Adoption(error)
        }
        SearchExactLiteralCompiledAotFallbackV1::BackendMismatch { actual } => {
            SearchExactLiteralCompiledAotV26Fallback::BackendMismatch { actual }
        }
        SearchExactLiteralCompiledAotFallbackV1::Binding(error) => {
            SearchExactLiteralCompiledAotV26Fallback::Binding(error)
        }
    }
}

#[cfg(feature = "compiled-search-v26-aot")]
fn v26_literal_width_is_valid(bytes: usize) -> bool {
    u32::try_from(bytes).is_ok_and(search_v26_production_literal_width_is_valid_v1)
}

/// Why the default-off V27 compiled facade cached its portable route.
#[cfg(feature = "compiled-search-v27-aot")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchExactLiteralCompiledAotV27Fallback {
    /// The portable owner is not an exact literal under the fixed default
    /// construction policy. The supplied glue entry was not called.
    PortableOwnerIneligible,
    /// The exact literal is outside the evidence-qualified 17..=32-byte
    /// production envelope.
    /// The supplied glue entry was not called.
    LiteralWidthOutsideBackendEnvelope { bytes: usize },
    /// Production glue could not resolve one source-authorized handle.
    Adoption(StaticSearchSpanAdoptionErrorV1),
    /// A source-authorized handle named a backend other than tag40.
    BackendMismatch { actual: u16 },
    /// The adopted object did not bind to this exact portable source/literal
    /// owner and broad-family execution policy.
    Binding(SearchExactLiteralAotBindErrorV1),
}

/// Which executor one V27 compiled-facade search actually used.
#[cfg(feature = "compiled-search-v27-aot")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchExactLiteralCompiledAotV27Route {
    Portable,
    StaticAot,
}

/// Search failure from the owning V27 compiled facade.
#[cfg(feature = "compiled-search-v27-aot")]
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchExactLiteralCompiledAotV27Error {
    Portable(SearchError),
    Static(StaticSearchSpanCallErrorV1),
}

#[cfg(feature = "compiled-search-v27-aot")]
impl fmt::Display for SearchExactLiteralCompiledAotV27Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE exact-literal compiled V27 AOT search failed: {self:?}"
        )
    }
}

#[cfg(feature = "compiled-search-v27-aot")]
impl std::error::Error for SearchExactLiteralCompiledAotV27Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Portable(error) => Some(error),
            Self::Static(error) => Some(error),
        }
    }
}

#[cfg(feature = "compiled-search-v27-aot")]
impl From<SearchError> for SearchExactLiteralCompiledAotV27Error {
    fn from(error: SearchError) -> Self {
        Self::Portable(error)
    }
}

#[cfg(feature = "compiled-search-v27-aot")]
impl From<StaticSearchSpanCallErrorV1> for SearchExactLiteralCompiledAotV27Error {
    fn from(error: StaticSearchSpanCallErrorV1) -> Self {
        Self::Static(error)
    }
}

/// Owning, bind-once exact-literal facade for an explicitly linked tag40
/// source object.
///
/// This type is available only through the default-off
/// `compiled-search-v27-aot` feature. It invokes the source-specific
/// production adopter at most once for exact literals in the
/// evidence-qualified 17..=32-byte envelope. Shorter and wider literals,
/// missing authority, an unqualified selector, a backend mismatch, or any
/// semantic-binding refusal are cached as a portable route.
///
/// The adopter resolves only the static runtime's source-reviewed production
/// registry. The feature and linked object cannot create a family row or
/// production authority, and no ordinary [`PortableRegex`] method is changed.
#[cfg(feature = "compiled-search-v27-aot")]
pub struct SearchExactLiteralCompiledAotV27 {
    portable_owner: PortableRegex,
    state: SearchExactLiteralCompiledAotStateV1,
}

#[cfg(feature = "compiled-search-v27-aot")]
impl fmt::Debug for SearchExactLiteralCompiledAotV27 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchExactLiteralCompiledAotV27")
            .field("portable_owner", &self.portable_owner)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "compiled-search-v27-aot")]
impl SearchExactLiteralCompiledAotV27 {
    /// Bind one generated source-specific tag40 production glue entry once.
    ///
    /// `invoke_glue` is not called for a non-exact, non-default-policy, or
    /// outside-17..=32-byte portable owner. All adopter and binding refusals
    /// produce a usable portable facade.
    #[must_use]
    pub fn bind_once(
        portable_owner: PortableRegex,
        invoke_glue: impl FnOnce(*mut RawStaticSearchSpanAdoptionOutputV1) -> u32,
    ) -> Self {
        let state = bind_compiled_aot_state_v1(
            &portable_owner,
            SEARCH_BACKEND_ASIMD_TAG40_V1,
            v27_literal_width_is_valid,
            invoke_glue,
        );
        Self {
            portable_owner,
            state,
        }
    }

    /// Search a complete haystack through the cached route.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<
        (
            Option<Match>,
            SearchAccounting,
            SearchExactLiteralCompiledAotV27Route,
        ),
        SearchExactLiteralCompiledAotV27Error,
    > {
        self.find_window(haystack, SearchWindow::new(0, haystack.len()), limits)
    }

    /// Search one half-open window through the cached route.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<
        (
            Option<Match>,
            SearchAccounting,
            SearchExactLiteralCompiledAotV27Route,
        ),
        SearchExactLiteralCompiledAotV27Error,
    > {
        match self.state {
            SearchExactLiteralCompiledAotStateV1::Portable(_) => {
                let (matched, accounting) =
                    self.portable_owner.find_window(haystack, window, limits)?;
                Ok((
                    matched,
                    accounting,
                    SearchExactLiteralCompiledAotV27Route::Portable,
                ))
            }
            SearchExactLiteralCompiledAotStateV1::Static { verified, policy } => {
                let PortablePlan::ExactLiteral(portable_plan) = &self.portable_owner.plan else {
                    unreachable!("a static V27 state is created only for an exact portable owner");
                };
                let mut static_invoked = false;
                let (matched, accounting) = find_window_automatically_v1(
                    portable_plan,
                    haystack,
                    window,
                    limits,
                    policy.minimum_window_bytes,
                    policy.portable_prefix_candidate_starts,
                    |tail| {
                        static_invoked = true;
                        verified.search_preflighted(tail)
                    },
                )?;
                Ok((
                    matched,
                    accounting,
                    if static_invoked {
                        SearchExactLiteralCompiledAotV27Route::StaticAot
                    } else {
                        SearchExactLiteralCompiledAotV27Route::Portable
                    },
                ))
            }
        }
    }

    /// Portable semantic owner retained for every route.
    #[must_use]
    pub const fn portable_owner(&self) -> &PortableRegex {
        &self.portable_owner
    }

    /// Cached construction-time fallback, or `None` after a successful bind.
    #[must_use]
    pub const fn fallback_reason(&self) -> Option<SearchExactLiteralCompiledAotV27Fallback> {
        match self.state {
            SearchExactLiteralCompiledAotStateV1::Portable(reason) => {
                Some(v27_fallback_reason(reason))
            }
            SearchExactLiteralCompiledAotStateV1::Static { .. } => None,
        }
    }

    /// Source-authorized tag40 handle retained after successful binding.
    #[must_use]
    pub const fn verified_handle(&self) -> Option<&'static VerifiedStaticSearchSpanV1> {
        match self.state {
            SearchExactLiteralCompiledAotStateV1::Portable(_) => None,
            SearchExactLiteralCompiledAotStateV1::Static { verified, .. } => Some(verified),
        }
    }
}

#[cfg(feature = "compiled-search-v27-aot")]
const fn v27_fallback_reason(
    reason: SearchExactLiteralCompiledAotFallbackV1,
) -> SearchExactLiteralCompiledAotV27Fallback {
    match reason {
        SearchExactLiteralCompiledAotFallbackV1::PortableOwnerIneligible => {
            SearchExactLiteralCompiledAotV27Fallback::PortableOwnerIneligible
        }
        SearchExactLiteralCompiledAotFallbackV1::LiteralWidthOutsideProductionEnvelope {
            bytes,
        } => SearchExactLiteralCompiledAotV27Fallback::LiteralWidthOutsideBackendEnvelope { bytes },
        SearchExactLiteralCompiledAotFallbackV1::Adoption(error) => {
            SearchExactLiteralCompiledAotV27Fallback::Adoption(error)
        }
        SearchExactLiteralCompiledAotFallbackV1::BackendMismatch { actual } => {
            SearchExactLiteralCompiledAotV27Fallback::BackendMismatch { actual }
        }
        SearchExactLiteralCompiledAotFallbackV1::Binding(error) => {
            SearchExactLiteralCompiledAotV27Fallback::Binding(error)
        }
    }
}

#[cfg(feature = "compiled-search-v27-aot")]
fn v27_literal_width_is_valid(bytes: usize) -> bool {
    u32::try_from(bytes).is_ok_and(search_v27_production_literal_width_is_valid_v1)
}

/// Same-thread invocation token for a bound static Search-v1 Span handle.
///
/// The embedded static-runtime token makes this value neither `Send` nor
/// `Sync`. It also retains the portable semantic owner for the complete
/// session lifetime.
///
/// The current-thread contract is enforced by the type system:
///
/// ```compile_fail,E0277
/// use fre::SearchExactLiteralAotThreadSessionV1;
///
/// fn require_send<T: Send>() {}
/// require_send::<SearchExactLiteralAotThreadSessionV1<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre::SearchExactLiteralAotThreadSessionV1;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<SearchExactLiteralAotThreadSessionV1<'static>>();
/// ```
pub struct SearchExactLiteralAotThreadSessionV1<'session> {
    portable_owner: &'session PortableRegex,
    native: StaticSearchSpanThreadSessionV1<'session>,
    checked: CheckedBindingV1,
}

impl fmt::Debug for SearchExactLiteralAotThreadSessionV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchExactLiteralAotThreadSessionV1")
            .field("portable_owner", &self.portable_owner)
            .field(
                "semantic_binding_identity",
                &self.checked.semantic_binding_identity,
            )
            .field("literal_bytes", &self.checked.literal_bytes)
            .field("backend_version", &self.native.handle().backend_version())
            .finish_non_exhaustive()
    }
}

impl SearchExactLiteralAotThreadSessionV1<'_> {
    /// Search the complete haystack with one resource preflight and no
    /// per-call tag21 vector-length syscall.
    ///
    /// # Errors
    ///
    /// Returns [`StaticSearchSpanCallErrorV1`] for a resource refusal, invalid
    /// native result, or backend fault.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), StaticSearchSpanCallErrorV1> {
        let (matched, accounting) = self.native.find(haystack, literal_limits(limits))?;
        Ok((
            matched.map(project_match),
            SearchAccounting::ExactLiteral(accounting),
        ))
    }

    /// Search one checked window with one resource preflight and no per-call
    /// tag21 vector-length syscall.
    ///
    /// # Errors
    ///
    /// Returns [`StaticSearchSpanCallErrorV1`] under the same contract as
    /// [`Self::find`].
    #[inline]
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), StaticSearchSpanCallErrorV1> {
        let native_window = NativeSearchWindow::new(window.start(), window.end());
        let (matched, accounting) =
            self.native
                .search(haystack, native_window, literal_limits(limits))?;
        Ok((
            matched.map(project_match),
            SearchAccounting::ExactLiteral(accounting),
        ))
    }

    /// Portable matcher retained as this session's semantic owner.
    #[must_use]
    pub const fn portable_owner(&self) -> &PortableRegex {
        self.portable_owner
    }

    /// Already-adopted handle retained by the native same-thread token.
    #[must_use]
    pub const fn verified_handle(&self) -> &VerifiedStaticSearchSpanV1 {
        self.native.handle()
    }

    /// Complete facade semantic identity checked before session creation.
    #[must_use]
    pub const fn semantic_binding_identity(&self) -> SearchExactLiteralAotSemanticBindingIdentity {
        self.checked.semantic_binding_identity
    }

    /// Exact live literal width checked before session creation.
    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.checked.literal_bytes
    }
}

fn checked_automatic_policy_v1(
    source: StaticSearchSpanFamilyExecutionPolicyV1,
    literal_bytes: u32,
) -> Result<CheckedAutomaticPolicyV1, SearchExactLiteralAotBindErrorV1> {
    let minimum_bytes = source.minimum_literal_bytes();
    let maximum_bytes = source.maximum_literal_bytes();
    if !literal_is_in_production_family_v1(literal_bytes, minimum_bytes, maximum_bytes) {
        return Err(
            SearchExactLiteralAotBindErrorV1::LiteralWidthOutsideProductionFamily {
                literal_bytes,
                minimum_bytes,
                maximum_bytes,
            },
        );
    }
    let minimum_window_bytes = usize::try_from(source.minimum_window_bytes()).map_err(|_| {
        SearchExactLiteralAotBindErrorV1::MinimumWindowBytesNotRepresentable {
            bytes: source.minimum_window_bytes(),
        }
    })?;
    let portable_prefix_candidate_starts =
        usize::try_from(source.portable_prefix_candidate_starts()).map_err(|_| {
            SearchExactLiteralAotBindErrorV1::PortablePrefixCandidateStartsNotRepresentable {
                starts: source.portable_prefix_candidate_starts(),
            }
        })?;
    Ok(CheckedAutomaticPolicyV1 {
        source,
        minimum_window_bytes,
        portable_prefix_candidate_starts,
    })
}

const fn literal_is_in_production_family_v1(
    literal_bytes: u32,
    minimum_bytes: u32,
    maximum_bytes: u32,
) -> bool {
    minimum_bytes != 0
        && minimum_bytes <= maximum_bytes
        && literal_bytes >= minimum_bytes
        && literal_bytes <= maximum_bytes
}

#[inline]
fn find_window_automatically_v1<'plan, 'haystack>(
    portable: &'plan LiteralPlan,
    haystack: &'haystack [u8],
    window: SearchWindow,
    limits: SearchLimits,
    minimum_window_bytes: usize,
    portable_prefix_candidate_starts: usize,
    invoke_tail: impl FnOnce(
        LiteralSearchPreflight<'plan, 'haystack>,
    ) -> Result<
        (Option<MatchSpan>, LiteralAccounting),
        StaticSearchSpanCallErrorV1,
    >,
) -> Result<(Option<Match>, SearchAccounting), StaticSearchSpanCallErrorV1> {
    let start = window.start();
    let end = window.end();
    let searched_bytes = end.checked_sub(start);
    if end > haystack.len() || searched_bytes.is_none_or(|bytes| bytes < minimum_window_bytes) {
        return find_window_portably_v1(portable, haystack, window, limits);
    }

    let checked = CheckedSearchWindow::new(haystack, NativeSearchWindow::new(start, end))
        .ok_or_else(|| {
            StaticSearchSpanCallErrorV1::from(fre_kernels::LiteralError::InvalidWindow {
                start,
                end,
                haystack_len: haystack.len(),
            })
        })?;
    match portable.preflight_checked_window_prefix(
        checked,
        literal_limits(limits),
        portable_prefix_candidate_starts,
    )? {
        LiteralSearchPrefixSplit::Match {
            start,
            end,
            accounting,
        } => Ok((
            Some(Match { start, end }),
            SearchAccounting::ExactLiteral(accounting),
        )),
        LiteralSearchPrefixSplit::Exhausted { accounting } => {
            Ok((None, SearchAccounting::ExactLiteral(accounting)))
        }
        LiteralSearchPrefixSplit::Tail(tail) => {
            let (matched, accounting) = invoke_tail(tail)?;
            Ok((
                matched.map(project_match),
                SearchAccounting::ExactLiteral(accounting),
            ))
        }
    }
}

#[inline]
fn find_window_portably_v1(
    portable: &LiteralPlan,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
) -> Result<(Option<Match>, SearchAccounting), StaticSearchSpanCallErrorV1> {
    let (matched, accounting) = portable.find_window(
        haystack,
        LiteralWindow::new(window.start(), window.end()),
        literal_limits(limits),
    )?;
    Ok((
        matched.map(|(start, end)| Match { start, end }),
        SearchAccounting::ExactLiteral(accounting),
    ))
}

fn check_binding_v1(
    candidate: Option<SearchExactLiteralAotCandidate<'_>>,
    adopted_semantic_binding_identity: &[u8; 32],
    adopted_literal_bytes: u32,
    authenticates_literal: impl FnOnce(&[u8]) -> bool,
) -> Result<CheckedBindingV1, SearchExactLiteralAotBindErrorV1> {
    let candidate = candidate
        .ok_or(SearchExactLiteralAotBindErrorV1::PortableOwnerIsNotExactLiteralCandidate)?;
    let portable_identity = candidate.semantic_binding_identity();
    if portable_identity.as_bytes() != adopted_semantic_binding_identity {
        return Err(
            SearchExactLiteralAotBindErrorV1::SemanticBindingIdentityMismatch {
                portable: portable_identity,
                adopted: *adopted_semantic_binding_identity,
            },
        );
    }
    let portable_literal_bytes = checked_literal_width(candidate.literal().len())?;
    if portable_literal_bytes != adopted_literal_bytes {
        return Err(SearchExactLiteralAotBindErrorV1::LiveLiteralWidthMismatch {
            portable_bytes: portable_literal_bytes,
            adopted_bytes: adopted_literal_bytes,
        });
    }
    if !authenticates_literal(candidate.literal()) {
        return Err(SearchExactLiteralAotBindErrorV1::LiteralIdentityMismatch);
    }
    Ok(CheckedBindingV1 {
        semantic_binding_identity: portable_identity,
        literal_bytes: portable_literal_bytes,
    })
}

fn checked_literal_width(bytes: usize) -> Result<u32, SearchExactLiteralAotBindErrorV1> {
    u32::try_from(bytes).map_err(|_| {
        SearchExactLiteralAotBindErrorV1::PortableLiteralWidthNotRepresentable { bytes }
    })
}

const fn project_match(matched: MatchSpan) -> Match {
    Match {
        start: matched.start(),
        end: matched.end(),
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;
    use crate::PortableBuilder;
    use fre_kernels::{LiteralBuildLimits, LiteralError};

    #[cfg(feature = "compiled-search-v25-aot")]
    #[test]
    fn compiled_v25_refuses_out_of_envelope_widths_before_invoking_glue() {
        for source in ["short", "abcdefghijklmnopqrstuvwxyz1234567"] {
            let glue_called = Cell::new(false);
            let expected_bytes = source.len();
            let compiled = SearchExactLiteralCompiledAotV25::bind_once(
                PortableBuilder::new(source).build().unwrap(),
                |_| {
                    glue_called.set(true);
                    unreachable!("an out-of-envelope literal must not invoke production glue")
                },
            );

            assert!(!glue_called.get());
            assert_eq!(
                compiled.fallback_reason(),
                Some(
                    SearchExactLiteralCompiledAotV25Fallback::LiteralWidthOutsideBackendEnvelope {
                        bytes: expected_bytes,
                    },
                )
            );
        }
    }

    #[cfg(feature = "compiled-search-v25-aot")]
    #[test]
    fn compiled_v25_calls_glue_once_only_after_exact_width_admission() {
        let glue_calls = Cell::new(0_u32);
        let compiled = SearchExactLiteralCompiledAotV25::bind_once(
            PortableBuilder::new("needle").build().unwrap(),
            |_| {
                glue_calls.set(glue_calls.get() + 1);
                fre_aot_static_runtime::STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1
            },
        );

        assert_eq!(glue_calls.get(), 1);
        assert!(matches!(
            compiled.fallback_reason(),
            Some(SearchExactLiteralCompiledAotV25Fallback::Adoption(_))
        ));
    }

    #[cfg(feature = "compiled-search-v26-aot")]
    #[test]
    fn compiled_v26_refuses_width_eight_and_other_outside_widths_before_glue() {
        for source in ["short", "abcdefgh", "abcdefghijklmnopqrstuvwxyz1234567"] {
            let glue_called = Cell::new(false);
            let expected_bytes = source.len();
            let compiled = SearchExactLiteralCompiledAotV26::bind_once(
                PortableBuilder::new(source).build().unwrap(),
                |_| {
                    glue_called.set(true);
                    unreachable!("an out-of-production-envelope literal must not invoke glue")
                },
            );

            assert!(!glue_called.get());
            assert_eq!(
                compiled.fallback_reason(),
                Some(
                    SearchExactLiteralCompiledAotV26Fallback::
                        LiteralWidthOutsideProductionEnvelope {
                            bytes: expected_bytes,
                        },
                )
            );
        }
    }

    #[cfg(feature = "compiled-search-v26-aot")]
    #[test]
    fn compiled_v26_missing_authority_calls_glue_once_then_stays_portable() {
        let glue_calls = Cell::new(0_u32);
        let compiled = SearchExactLiteralCompiledAotV26::bind_once(
            PortableBuilder::new("abcdefghi").build().unwrap(),
            |_| {
                glue_calls.set(glue_calls.get() + 1);
                fre_aot_static_runtime::STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1
            },
        );

        assert_eq!(glue_calls.get(), 1);
        assert!(matches!(
            compiled.fallback_reason(),
            Some(SearchExactLiteralCompiledAotV26Fallback::Adoption(_))
        ));
        assert!(compiled.verified_handle().is_none());

        let (matched, _, route) = compiled
            .find(b"xxabcdefghiyy", SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((2, 11))
        );
        assert_eq!(route, SearchExactLiteralCompiledAotV26Route::Portable);
        assert_eq!(glue_calls.get(), 1, "searches must not retry adoption");
    }

    #[cfg(feature = "compiled-search-v26-aot")]
    #[test]
    fn compiled_v26_backend_check_refuses_every_non_tag39_handle() {
        let reason = check_compiled_aot_backend_v1(38, SEARCH_BACKEND_ASIMD_TAG39_V1)
            .expect_err("tag38 must not be accepted through the tag39 facade");
        assert_eq!(
            v26_fallback_reason(reason),
            SearchExactLiteralCompiledAotV26Fallback::BackendMismatch { actual: 38 }
        );
        assert_eq!(
            check_compiled_aot_backend_v1(
                SEARCH_BACKEND_ASIMD_TAG39_V1,
                SEARCH_BACKEND_ASIMD_TAG39_V1,
            ),
            Ok(())
        );
    }

    #[cfg(feature = "compiled-search-v27-aot")]
    #[test]
    fn compiled_v27_refuses_outside_production_widths_before_glue() {
        for source in [
            "abcdefghijklmnop",
            "abcdefghijklmnopqrstuvwxyz1234567",
        ] {
            let glue_called = Cell::new(false);
            let compiled = SearchExactLiteralCompiledAotV27::bind_once(
                PortableBuilder::new(source).build().unwrap(),
                |_| {
                    glue_called.set(true);
                    unreachable!("an out-of-envelope literal must not invoke tag40 glue")
                },
            );

            assert!(!glue_called.get());
            assert_eq!(
                compiled.fallback_reason(),
                Some(
                    SearchExactLiteralCompiledAotV27Fallback::LiteralWidthOutsideBackendEnvelope {
                        bytes: source.len(),
                    }
                )
            );
        }
    }

    #[cfg(feature = "compiled-search-v27-aot")]
    #[test]
    fn compiled_v27_all_topologies_call_glue_once_then_cache_portable_without_authority() {
        for source in [
            "aaaaaaaaaaaaaaaaa",
            "abcabcabcabcabcabc",
            "abcdefghijklmnopq",
            "abcdefghijklmnopqrstuvwxyz012345",
        ] {
            let glue_calls = Cell::new(0_u32);
            let compiled = SearchExactLiteralCompiledAotV27::bind_once(
                PortableBuilder::new(source).build().unwrap(),
                |_| {
                    glue_calls.set(glue_calls.get() + 1);
                    fre_aot_static_runtime::STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1
                },
            );

            assert_eq!(glue_calls.get(), 1);
            assert!(matches!(
                compiled.fallback_reason(),
                Some(SearchExactLiteralCompiledAotV27Fallback::Adoption(_))
            ));
            assert!(compiled.verified_handle().is_none());
            let haystack = format!("##{source}!!");
            let (matched, _, route) = compiled
                .find(haystack.as_bytes(), SearchLimits::unlimited())
                .unwrap();
            assert_eq!(
                matched.map(|matched| (matched.start(), matched.end())),
                Some((2, 2 + source.len()))
            );
            assert_eq!(route, SearchExactLiteralCompiledAotV27Route::Portable);
            assert_eq!(glue_calls.get(), 1, "searches must not retry adoption");
        }
    }

    #[cfg(feature = "compiled-search-v27-aot")]
    #[test]
    fn compiled_v27_backend_check_refuses_every_non_tag40_handle() {
        let reason = check_compiled_aot_backend_v1(39, SEARCH_BACKEND_ASIMD_TAG40_V1)
            .expect_err("tag39 must not be accepted through the tag40 facade");
        assert_eq!(
            v27_fallback_reason(reason),
            SearchExactLiteralCompiledAotV27Fallback::BackendMismatch { actual: 39 }
        );
        assert_eq!(
            check_compiled_aot_backend_v1(
                SEARCH_BACKEND_ASIMD_TAG40_V1,
                SEARCH_BACKEND_ASIMD_TAG40_V1,
            ),
            Ok(())
        );
    }

    #[test]
    fn source_binding_accepts_only_the_candidates_own_identity_and_width() {
        let regex = PortableBuilder::new("needle").build().unwrap();
        let candidate = regex.exact_literal_search_aot_candidate().unwrap();
        let identity = *candidate.semantic_binding_identity().as_bytes();
        let width = u32::try_from(candidate.literal().len()).unwrap();

        let checked = check_binding_v1(
            regex.exact_literal_search_aot_candidate(),
            &identity,
            width,
            |_| true,
        )
        .unwrap();

        assert_eq!(checked.semantic_binding_identity.as_bytes(), &identity);
        assert_eq!(checked.literal_bytes, width);
    }

    #[test]
    fn source_binding_refuses_identity_width_and_plan_substitution() {
        let regex = PortableBuilder::new("needle").build().unwrap();
        let candidate = regex.exact_literal_search_aot_candidate().unwrap();
        let identity = *candidate.semantic_binding_identity().as_bytes();
        let width = u32::try_from(candidate.literal().len()).unwrap();
        let different_identity = identity.map(|byte| byte ^ 0xff);

        assert!(matches!(
            check_binding_v1(
                regex.exact_literal_search_aot_candidate(),
                &different_identity,
                width,
                |_| true,
            ),
            Err(SearchExactLiteralAotBindErrorV1::SemanticBindingIdentityMismatch { .. })
        ));
        assert_eq!(
            check_binding_v1(
                regex.exact_literal_search_aot_candidate(),
                &identity,
                width.checked_add(1).unwrap(),
                |_| true,
            ),
            Err(SearchExactLiteralAotBindErrorV1::LiveLiteralWidthMismatch {
                portable_bytes: width,
                adopted_bytes: width.checked_add(1).unwrap(),
            })
        );

        let nonexact = PortableBuilder::new("foo|bar").build().unwrap();
        assert_eq!(
            check_binding_v1(
                nonexact.exact_literal_search_aot_candidate(),
                &identity,
                width,
                |_| true,
            ),
            Err(SearchExactLiteralAotBindErrorV1::PortableOwnerIsNotExactLiteralCandidate)
        );
    }

    #[test]
    fn source_binding_refuses_same_width_literal_substitution() {
        let regex = PortableBuilder::new("needle").build().unwrap();
        let candidate = regex.exact_literal_search_aot_candidate().unwrap();
        let identity = *candidate.semantic_binding_identity().as_bytes();
        let width = u32::try_from(candidate.literal().len()).unwrap();

        assert_eq!(
            check_binding_v1(
                regex.exact_literal_search_aot_candidate(),
                &identity,
                width,
                |literal| literal == b"former",
            ),
            Err(SearchExactLiteralAotBindErrorV1::LiteralIdentityMismatch)
        );
    }

    #[test]
    fn source_binding_width_conversion_is_checked() {
        assert_eq!(checked_literal_width(17), Ok(17));
        if let Some(too_wide) = usize::try_from(u32::MAX)
            .ok()
            .and_then(|maximum| maximum.checked_add(1))
        {
            assert_eq!(
                checked_literal_width(too_wide),
                Err(
                    SearchExactLiteralAotBindErrorV1::PortableLiteralWidthNotRepresentable {
                        bytes: too_wide,
                    }
                )
            );
        }
    }

    #[test]
    fn automatic_family_policy_rechecks_the_inclusive_literal_envelope() {
        assert!(!literal_is_in_production_family_v1(8, 9, 32));
        assert!(literal_is_in_production_family_v1(9, 9, 32));
        assert!(literal_is_in_production_family_v1(32, 9, 32));
        assert!(!literal_is_in_production_family_v1(33, 9, 32));
        assert!(!literal_is_in_production_family_v1(9, 0, 32));
        assert!(!literal_is_in_production_family_v1(9, 32, 9));
    }

    #[test]
    fn native_span_projection_preserves_original_haystack_offsets() {
        let matched = project_match(MatchSpan::new(7, 13));
        assert_eq!(matched.start(), 7);
        assert_eq!(matched.end(), 13);
    }

    #[test]
    fn automatic_route_sends_below_floor_and_invalid_windows_directly_portable() {
        let plan = LiteralPlan::new(b"needle", LiteralBuildLimits::default()).unwrap();
        let mut haystack = vec![b'x'; 64];
        haystack[21..27].copy_from_slice(b"needle");
        let tail_calls = Cell::new(0_u32);

        let (matched, accounting) = find_window_automatically_v1(
            &plan,
            &haystack,
            SearchWindow::new(0, haystack.len()),
            SearchLimits::unlimited(),
            4_093,
            256,
            |_| {
                tail_calls.set(tail_calls.get() + 1);
                unreachable!("below-floor calls must not create or invoke an AOT tail")
            },
        )
        .unwrap();
        assert_eq!(matched, Some(Match { start: 21, end: 27 }));
        assert_eq!(tail_calls.get(), 0);
        assert_eq!(
            accounting,
            SearchAccounting::ExactLiteral(LiteralAccounting {
                needle_bytes: 6,
                searched_bytes: 64,
                linear_terms: 70,
                scratch_bytes: 0,
            })
        );

        let error = find_window_automatically_v1(
            &plan,
            &haystack,
            SearchWindow::new(17, 11),
            SearchLimits::unlimited(),
            4_093,
            256,
            |_| unreachable!("an invalid window must not reach an AOT tail"),
        )
        .unwrap_err();
        assert_eq!(
            error,
            StaticSearchSpanCallErrorV1::Preflight(LiteralError::InvalidWindow {
                start: 17,
                end: 11,
                haystack_len: 64,
            })
        );
    }

    #[test]
    fn automatic_route_owns_exact_prefix_and_tail_candidate_boundaries() {
        const PREFIX_STARTS: usize = 4;
        let plan = LiteralPlan::new(b"abc", LiteralBuildLimits::default()).unwrap();

        let mut prefix_haystack = vec![b'x'; 32];
        prefix_haystack[3..6].copy_from_slice(b"abc");
        let (prefix_match, prefix_accounting) = find_window_automatically_v1(
            &plan,
            &prefix_haystack,
            SearchWindow::new(0, prefix_haystack.len()),
            SearchLimits::unlimited(),
            16,
            PREFIX_STARTS,
            |_| unreachable!("candidate start three belongs to the portable prefix"),
        )
        .unwrap();
        assert_eq!(prefix_match, Some(Match { start: 3, end: 6 }));

        let mut tail_haystack = vec![b'x'; 32];
        tail_haystack[4..7].copy_from_slice(b"abc");
        let tail_calls = Cell::new(0_u32);
        let (tail_match, tail_accounting) = find_window_automatically_v1(
            &plan,
            &tail_haystack,
            SearchWindow::new(0, tail_haystack.len()),
            SearchLimits::unlimited(),
            16,
            PREFIX_STARTS,
            |tail| {
                tail_calls.set(tail_calls.get() + 1);
                assert_eq!(tail.checked_window().window().start(), PREFIX_STARTS);
                let accounting = tail.accounting();
                let matched = tail.find()?.map(|(start, end)| MatchSpan::new(start, end));
                Ok((matched, accounting))
            },
        )
        .unwrap();
        assert_eq!(tail_calls.get(), 1);
        assert_eq!(tail_match, Some(Match { start: 4, end: 7 }));
        assert_eq!(tail_accounting, prefix_accounting);
        assert_eq!(
            tail_accounting,
            SearchAccounting::ExactLiteral(LiteralAccounting {
                needle_bytes: 3,
                searched_bytes: 32,
                linear_terms: 35,
                scratch_bytes: 0,
            })
        );
    }

    #[test]
    fn automatic_route_retains_nonzero_window_offsets_and_full_limit_preflight() {
        let plan = LiteralPlan::new(b"abc", LiteralBuildLimits::default()).unwrap();
        let mut haystack = vec![b'x'; 48];
        haystack[13..16].copy_from_slice(b"abc");
        let window = SearchWindow::new(7, 39);
        let (matched, accounting) = find_window_automatically_v1(
            &plan,
            &haystack,
            window,
            SearchLimits::unlimited(),
            16,
            4,
            |tail| {
                assert_eq!(tail.checked_window().window().start(), 11);
                let accounting = tail.accounting();
                let matched = tail.find()?.map(|(start, end)| MatchSpan::new(start, end));
                Ok((matched, accounting))
            },
        )
        .unwrap();
        assert_eq!(matched, Some(Match { start: 13, end: 16 }));
        assert_eq!(
            accounting,
            SearchAccounting::ExactLiteral(LiteralAccounting {
                needle_bytes: 3,
                searched_bytes: 32,
                linear_terms: 35,
                scratch_bytes: 0,
            })
        );

        let tail_calls = Cell::new(0_u32);
        let error = find_window_automatically_v1(
            &plan,
            &haystack,
            window,
            SearchLimits {
                max_work: 34,
                max_scratch_bytes: usize::MAX,
            },
            16,
            4,
            |_| {
                tail_calls.set(tail_calls.get() + 1);
                unreachable!("full-window limit refusal must precede prefix and tail execution")
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            StaticSearchSpanCallErrorV1::Preflight(LiteralError::LinearTermLimit {
                needed: 35,
                limit: 34,
            })
        );
        assert_eq!(tail_calls.get(), 0);
    }

    #[test]
    fn automatic_route_partition_matches_portable_across_broad_literal_shapes() {
        const ABSENT: usize = usize::MAX;

        for width in 1_usize..=32 {
            for shape in 0_u8..4 {
                let literal = automatic_test_literal(width, shape);
                let plan = LiteralPlan::new(&literal, LiteralBuildLimits::default()).unwrap();
                let haystack_len = width + 80;
                let placements = [
                    ABSENT,
                    0,
                    1,
                    3,
                    4,
                    17,
                    haystack_len / 2,
                    haystack_len - width,
                ];

                for placement in placements {
                    let mut haystack = vec![0x55; haystack_len];
                    if placement != ABSENT {
                        haystack[placement..placement + width].copy_from_slice(&literal);
                    }
                    let windows = [
                        SearchWindow::new(0, haystack_len),
                        SearchWindow::new(2, haystack_len - 3),
                        SearchWindow::new(7, haystack_len),
                        SearchWindow::new(11, 5),
                        SearchWindow::new(haystack_len + 1, haystack_len + 2),
                    ];

                    for window in windows {
                        for minimum_window_bytes in [0, 16, haystack_len + 1] {
                            for prefix_candidate_starts in [0, 1, 4, 17, haystack_len + 4] {
                                let expected = plan
                                    .find_window(
                                        &haystack,
                                        LiteralWindow::new(window.start(), window.end()),
                                        literal_limits(SearchLimits::unlimited()),
                                    )
                                    .map(|(matched, accounting)| {
                                        (
                                            matched.map(|(start, end)| Match { start, end }),
                                            SearchAccounting::ExactLiteral(accounting),
                                        )
                                    })
                                    .map_err(StaticSearchSpanCallErrorV1::from);
                                let actual = find_window_automatically_v1(
                                    &plan,
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                    minimum_window_bytes,
                                    prefix_candidate_starts,
                                    |tail| {
                                        let accounting = tail.accounting();
                                        let matched = tail
                                            .find()?
                                            .map(|(start, end)| MatchSpan::new(start, end));
                                        Ok((matched, accounting))
                                    },
                                );

                                assert_eq!(
                                    actual, expected,
                                    "width={width} shape={shape} placement={placement} \
                                     window={window:?} floor={minimum_window_bytes} \
                                     prefix={prefix_candidate_starts}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn automatic_test_literal(width: usize, shape: u8) -> Vec<u8> {
        match shape {
            0 => (0..width)
                .map(|index| {
                    let generated = index
                        .checked_rem(251)
                        .and_then(|value| value.checked_mul(37))
                        .and_then(|value| value.checked_rem(251))
                        .and_then(|value| value.checked_add(1))
                        .expect("the generated distinct-byte arithmetic is bounded");
                    u8::try_from(generated).expect("the generated distinct byte is bounded")
                })
                .collect(),
            1 => vec![0xa7; width],
            2 => (0..width)
                .map(|index| if index % 2 == 0 { 0x13 } else { 0xe9 })
                .collect(),
            3 => [0x00, 0xff, 0x80, 0x55, 0xaa, 0x7f]
                .into_iter()
                .cycle()
                .take(width)
                .collect(),
            _ => unreachable!("the test enumerates four literal shapes"),
        }
    }
}
