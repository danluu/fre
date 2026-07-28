//! Qualification-private thread and scalar-call contracts for the Linux
//! tag21 `SelectedEnd` register-return ABI2.
//!
//! This module deliberately owns no address, function pointer, symbol lookup,
//! object adopter, or authority row. The exact identity-suffixed `extern`
//! declaration and call must remain in compiler-generated consumer source so
//! a final-image checker can prove that the linker retained a direct `bl`.

use core::{fmt, marker::PhantomData};
use std::rc::Rc;

use fre_kernel_ir::{CheckedSearchWindow, MatchSpan, SearchWindow};
use fre_kernels::{LiteralAccounting, LiteralPlan, LiteralSearchPreflight};

const SELECTED_END_LITERAL_BYTES_V2: usize = 16;
const SELECTED_END_FIXED_VECTOR_BYTES_V2: u16 = 16;

/// Explicit absence of production authority.
///
/// Enabling the qualification-private feature does not add a production row
/// or turn compiler output into an authorized production deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticSearchSelectedEndProductionAuthorityV2 {
    Absent,
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
            "SelectedEnd ABI2 qualification thread contract failed: {self:?}"
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
    InvalidNativeEnd {
        end_or_zero: usize,
        literal_bytes: usize,
        window_start: usize,
        window_end: usize,
    },
}

impl fmt::Display for StaticSearchSelectedEndCallErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SelectedEnd ABI2 qualification call failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticSearchSelectedEndCallErrorV2 {}

/// Default-off owner for qualification-private linked `SelectedEnd` ABI2.
///
/// This zero-sized value grants no production authority and has no call
/// method. A call requires both a current-thread session and a generated exact
/// identity-suffixed binding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StaticSearchSelectedEndQualificationV2 {
    _private: (),
}

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
        platform::admit_current_thread_v2()?;
        Ok(StaticSearchSelectedEndThreadSessionV2 {
            _owner: self,
            _thread_bound: PhantomData,
        })
    }
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
    _owner: &'owner StaticSearchSelectedEndQualificationV2,
    _thread_bound: PhantomData<Rc<()>>,
}

impl<'owner> StaticSearchSelectedEndThreadSessionV2<'owner> {
    /// Bind one exact portable plan to this already-admitted thread session.
    ///
    /// The linked artifact's literal is compared once here. Calls prepared
    /// through the returned token can then authenticate their private-field
    /// preflight certificate by plan identity instead of comparing sixteen
    /// literal bytes on every hot call.
    pub fn bind_literal_plan<'session, 'plan>(
        &'session self,
        plan: &'plan LiteralPlan,
        exact_literal: &[u8; SELECTED_END_LITERAL_BYTES_V2],
    ) -> Result<
        StaticSearchSelectedEndPlanSessionV2<'session, 'owner, 'plan>,
        StaticSearchSelectedEndCallErrorV2,
    > {
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
        Ok(StaticSearchSelectedEndPlanSessionV2 {
            session: self,
            plan,
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

/// Same-thread AOT session bound once to the exact portable literal plan.
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
}

impl<'session, 'owner, 'plan> StaticSearchSelectedEndPlanSessionV2<'session, 'owner, 'plan> {
    /// Consume one authoritative preflight from the plan bound at session
    /// construction.
    ///
    /// The successful hot path is one allocation-free plan-identity check.
    /// A token from another plan is rejected before any generated code can be
    /// invoked, even when that plan owns equal literal bytes.
    #[inline]
    pub fn prepare<'haystack>(
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
    #[inline]
    pub const fn haystack(&self) -> &[u8] {
        self.checked.haystack()
    }

    #[must_use]
    #[inline]
    pub const fn window(&self) -> SearchWindow {
        self.checked.window()
    }

    /// Decode the exact `x0` end-or-zero result after the generated module has
    /// made its literal direct-symbol call.
    pub fn decode(
        self,
        end_or_zero: usize,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), StaticSearchSelectedEndCallErrorV2> {
        let window = self.checked.window();
        let matched = decode_selected_end_v2(end_or_zero, window)?;
        Ok((matched, self.accounting))
    }
}

fn decode_selected_end_v2(
    end_or_zero: usize,
    window: SearchWindow,
) -> Result<Option<MatchSpan>, StaticSearchSelectedEndCallErrorV2> {
    if end_or_zero == 0 {
        return Ok(None);
    }
    let start = end_or_zero.checked_sub(SELECTED_END_LITERAL_BYTES_V2);
    if end_or_zero > window.end() || start.is_none_or(|start| start < window.start()) {
        return Err(StaticSearchSelectedEndCallErrorV2::InvalidNativeEnd {
            end_or_zero,
            literal_bytes: SELECTED_END_LITERAL_BYTES_V2,
            window_start: window.start(),
            window_end: window.end(),
        });
    }
    Ok(Some(MatchSpan::new(
        start.expect("validated SelectedEnd ABI2 start"),
        end_or_zero,
    )))
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

    #[test]
    fn authority_is_always_absent() {
        let owner = StaticSearchSelectedEndQualificationV2::qualification_private();
        assert_eq!(
            owner.production_authority(),
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
        let owner = StaticSearchSelectedEndQualificationV2::qualification_private();
        let session = StaticSearchSelectedEndThreadSessionV2 {
            _owner: &owner,
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
        let owner = StaticSearchSelectedEndQualificationV2::qualification_private();
        let session = StaticSearchSelectedEndThreadSessionV2 {
            _owner: &owner,
            _thread_bound: PhantomData,
        };
        let exact = LiteralPlan::new(b"0123456789abcdef", LiteralBuildLimits::default()).unwrap();
        let bound = session
            .bind_literal_plan(&exact, b"0123456789abcdef")
            .expect("exact plan binds once");
        let haystack = b"before-0123456789abcdef-after";
        let window = CheckedSearchWindow::new(haystack, SearchWindow::new(0, haystack.len()))
            .expect("checked test window");
        let exact_preflight = exact
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        let prepared = bound
            .prepare(exact_preflight)
            .expect("the bound plan's preflight");
        assert_eq!(prepared.decode(23).unwrap().0, Some(MatchSpan::new(7, 23)));

        let equal_bytes =
            LiteralPlan::new(b"0123456789abcdef", LiteralBuildLimits::default()).unwrap();
        let equal_preflight = equal_bytes
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            bound.prepare(equal_preflight),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch)
        ));

        let wrong_width = LiteralPlan::new(b"short", LiteralBuildLimits::default()).unwrap();
        let wrong_width_preflight = wrong_width
            .preflight_checked_window(window, LiteralSearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            bound.prepare(wrong_width_preflight),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralWidthMismatch {
                expected_bytes: 16,
                actual_bytes: 5,
            })
        ));

        assert!(matches!(
            session.bind_literal_plan(&equal_bytes, b"fedcba9876543210"),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch)
        ));
        assert!(matches!(
            session.bind_literal_plan(&wrong_width, b"0123456789abcdef"),
            Err(StaticSearchSelectedEndCallErrorV2::LiteralWidthMismatch {
                expected_bytes: 16,
                actual_bytes: 5,
            })
        ));
    }

    #[test]
    fn source_has_one_session_only_vl_query_and_no_callable_storage() {
        let source = include_str!("selected_end_direct_v2.rs");
        let bind = source.find("    pub fn bind_literal_plan<").unwrap();
        let plan_prepare = source
            .find("impl<'session, 'owner, 'plan> StaticSearchSelectedEndPlanSessionV2")
            .unwrap();
        let decode = source.find("fn decode_selected_end_v2(").unwrap();
        let tests = source.find("#[cfg(test)]").unwrap();
        let implementation = &source[..tests];
        assert!(!implementation[bind..decode].contains("prctl("));
        let plan_prepare = &implementation[plan_prepare..decode];
        let pointer_check = plan_prepare
            .find("preflight.was_issued_by(self.plan)")
            .unwrap();
        let literal_width = plan_prepare.find("preflight.literal_bytes()").unwrap();
        assert!(pointer_check < literal_width);
        assert!(!plan_prepare.contains("preflight.literal()"));
        assert_eq!(implementation.matches("libc::prctl(").count(), 1);
        assert!(!implementation.contains("transmute::<"));
        assert!(!implementation.contains("extern \"C\" fn("));
    }
}
