//! Explicit facade binding for an already-adopted static Search-v1 Span handle.
//!
//! This module owns no adoption path. It receives a
//! [`VerifiedStaticSearchSpanV1`] that the static runtime has already admitted,
//! then binds that handle to the immutable [`PortableRegex`] which still owns
//! the exact-literal semantics. Binding checks both the complete facade
//! semantic identity and the live literal width before a native call can be
//! reached.
//!
//! The wrapper never falls back, compiles, links, populates an authority row,
//! adopts an address, or borrows JIT authority. Every call delegates exactly
//! once to the static runtime's checked call boundary, which performs the one
//! literal resource preflight before entering native code.

use core::fmt;

use fre_aot_static_runtime::{
    StaticSearchSpanCallErrorV1, StaticSearchSpanThreadContractErrorV1,
    StaticSearchSpanThreadSessionV1, VerifiedStaticSearchSpanV1,
};
use fre_kernel_ir::{MatchSpan, SearchWindow as NativeSearchWindow};

use crate::{
    Match, PortableRegex, SearchAccounting, SearchExactLiteralAotCandidate,
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

fn check_binding_v1(
    candidate: Option<SearchExactLiteralAotCandidate<'_>>,
    adopted_semantic_binding_identity: &[u8; 32],
    adopted_literal_bytes: u32,
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
    use super::*;
    use crate::PortableBuilder;

    #[test]
    fn source_binding_accepts_only_the_candidates_own_identity_and_width() {
        let regex = PortableBuilder::new("needle").build().unwrap();
        let candidate = regex.exact_literal_search_aot_candidate().unwrap();
        let identity = *candidate.semantic_binding_identity().as_bytes();
        let width = u32::try_from(candidate.literal().len()).unwrap();

        let checked =
            check_binding_v1(regex.exact_literal_search_aot_candidate(), &identity, width).unwrap();

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
            ),
            Err(SearchExactLiteralAotBindErrorV1::SemanticBindingIdentityMismatch { .. })
        ));
        assert_eq!(
            check_binding_v1(
                regex.exact_literal_search_aot_candidate(),
                &identity,
                width.checked_add(1).unwrap(),
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
                width
            ),
            Err(SearchExactLiteralAotBindErrorV1::PortableOwnerIsNotExactLiteralCandidate)
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
    fn native_span_projection_preserves_original_haystack_offsets() {
        let matched = project_match(MatchSpan::new(7, 13));
        assert_eq!(matched.start(), 7);
        assert_eq!(matched.end(), 13);
    }
}
