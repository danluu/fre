//! Safe translation between stable ABI records and `fre::PortableRegex`.

use fre::{PlanKind, PortableBuilder, PortableRegex, SearchLimits};

use crate::{
    FRE_V1_ADMISSION_UPSTREAM_ORACLE_PENDING, FRE_V1_DIAGNOSTIC_COMPILE, FRE_V1_DIAGNOSTIC_CONFIG,
    FRE_V1_DIAGNOSTIC_PATTERN_ENCODING, FRE_V1_DIAGNOSTIC_SEARCH, FRE_V1_JIT_DENY,
    FRE_V1_PLAN_BOUNDED_BYTE_CLASS_SEQUENCE, FRE_V1_PLAN_EXACT_LITERAL,
    FRE_V1_PLAN_FIXED_PREDICATE_WORD64, FRE_V1_PLAN_FORWARD_ANCHORED, FRE_V1_PLAN_K0,
    FRE_V1_PLAN_LINE_DOMAIN_BYTE_ATOMS, FRE_V1_PLAN_LITERAL_CLASS_RUN_LITERAL,
    FRE_V1_PLAN_LITERAL_SET_DFA, FRE_V1_PLAN_PACKED_LITERAL_SET,
    FRE_V1_PLAN_PREFIX_CLASS_ALTERNATION, FRE_V1_PLAN_PURE_BYTE_CLASS_REPEAT,
    FRE_V1_PLAN_REQUIRED_LITERAL, FRE_V1_PLAN_REVERSE_INNER, FRE_V1_PLAN_UNICODE_FOLDED_LITERAL,
    FRE_V1_PLAN_UNICODE_SCALAR_RUN, FRE_V1_PLAN_UNICODE_WORD_RUN, FRE_V1_PROFILE_RUST_BYTES,
    FRE_V1_STATUS_COMPILE_ERROR, FRE_V1_STATUS_INVALID_PATTERN_ENCODING,
    FRE_V1_STATUS_SEARCH_ERROR, FRE_V1_STATUS_UNSUPPORTED_CONFIG,
    FRE_V1_STATUS_UNSUPPORTED_PROFILE, FreV1Config, FreV1ExistsResult, FreV1MatchResult,
    FreV1PlanInfo, FreV1SelectedEndResult, boundary::Outcome,
};

#[derive(Debug)]
pub(crate) struct CompiledRegex {
    regex: PortableRegex,
    search_limits: SearchLimits,
    selected_end_value_route: bool,
}

impl CompiledRegex {
    pub(crate) fn compile(config: FreV1Config, pattern: &[u8]) -> Result<Self, Outcome> {
        if config.profile != FRE_V1_PROFILE_RUST_BYTES {
            return Err(Outcome::failure(
                FRE_V1_STATUS_UNSUPPORTED_PROFILE,
                FRE_V1_DIAGNOSTIC_CONFIG,
                "implemented v1 supports only the Rust-bytes profile",
            ));
        }
        if config.unicode > 1 || config.jit_policy != FRE_V1_JIT_DENY || config.reserved != 0 {
            return Err(Outcome::failure(
                FRE_V1_STATUS_UNSUPPORTED_CONFIG,
                FRE_V1_DIAGNOSTIC_CONFIG,
                "unsupported v1 configuration field",
            ));
        }
        let scratch = usize::try_from(config.search_scratch_bytes).map_err(|_| {
            Outcome::failure(
                FRE_V1_STATUS_UNSUPPORTED_CONFIG,
                FRE_V1_DIAGNOSTIC_CONFIG,
                "search scratch limit does not fit this target's size_t",
            )
        })?;
        let pattern = core::str::from_utf8(pattern).map_err(|_| {
            Outcome::failure(
                FRE_V1_STATUS_INVALID_PATTERN_ENCODING,
                FRE_V1_DIAGNOSTIC_PATTERN_ENCODING,
                "Rust-bytes regex source must be valid UTF-8 syntax bytes",
            )
        })?;
        let regex = PortableBuilder::new(pattern)
            .unicode(config.unicode == 1)
            .build()
            .map_err(|error| {
                Outcome::failure(
                    FRE_V1_STATUS_COMPILE_ERROR,
                    FRE_V1_DIAGNOSTIC_COMPILE,
                    error.to_string(),
                )
            })?;
        let search_limits = SearchLimits {
            max_work: config.search_work,
            max_scratch_bytes: scratch,
        };
        let selected_end_value_route = search_limits == SearchLimits::unlimited()
            && regex.build_report().plan == PlanKind::FixedPredicateWord64;
        Ok(Self {
            regex,
            search_limits,
            selected_end_value_route,
        })
    }

    pub(crate) fn plan_info(&self) -> FreV1PlanInfo {
        let report = self.regex.build_report();
        let minimum = report.minimum_match_bytes;
        FreV1PlanInfo {
            abi_version: crate::FRE_V1_ABI_VERSION,
            struct_size: size_u32::<FreV1PlanInfo>(),
            plan: plan_tag(report.plan),
            admission: FRE_V1_ADMISSION_UPSTREAM_ORACLE_PENDING,
            planner_work: report.planner_work,
            states: u64::try_from(report.states).unwrap_or(u64::MAX),
            edges: u64::try_from(report.edges).unwrap_or(u64::MAX),
            plan_storage_bytes: u64::try_from(report.plan_storage_bytes).unwrap_or(u64::MAX),
            minimum_match_present: u32::from(minimum.is_some()),
            reserved: 0,
            minimum_match_bytes: minimum
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0),
        }
    }

    pub(crate) fn exists(&self, haystack: &[u8]) -> Result<FreV1ExistsResult, Outcome> {
        let matched = self
            .regex
            .is_match_with_limits(haystack, self.search_limits)
            .map_err(|error| search_error(&error))?;
        Ok(FreV1ExistsResult {
            abi_version: crate::FRE_V1_ABI_VERSION,
            struct_size: size_u32::<FreV1ExistsResult>(),
            matched: u32::from(matched),
            reserved: 0,
        })
    }

    pub(crate) fn selected_end(&self, haystack: &[u8]) -> Result<FreV1SelectedEndResult, Outcome> {
        let end = self
            .selected_end_raw(haystack)
            .map_err(|error| search_error(&error))?;
        Ok(FreV1SelectedEndResult {
            abi_version: crate::FRE_V1_ABI_VERSION,
            struct_size: size_u32::<FreV1SelectedEndResult>(),
            found: u32::from(end.is_some()),
            reserved: 0,
            end: end.unwrap_or(0),
        })
    }

    #[inline(never)]
    fn selected_end_raw(&self, haystack: &[u8]) -> Result<Option<usize>, fre::SearchError> {
        if self.selected_end_value_route {
            return self
                .regex
                .find_value(haystack, self.search_limits)
                .map(|matched| matched.map(fre::Match::end));
        }

        self.regex
            .selected_end_accounted(haystack, self.search_limits)
            .map(|(end, _)| end)
    }

    pub(crate) fn span(&self, haystack: &[u8]) -> Result<FreV1MatchResult, Outcome> {
        let matched = self
            .regex
            .find_with_limits(haystack, self.search_limits)
            .map_err(|error| search_error(&error))?;
        Ok(FreV1MatchResult {
            abi_version: crate::FRE_V1_ABI_VERSION,
            struct_size: size_u32::<FreV1MatchResult>(),
            found: u32::from(matched.is_some()),
            reserved: 0,
            start: matched.map_or(0, fre::Match::start),
            end: matched.map_or(0, fre::Match::end),
        })
    }
}

fn search_error(error: &fre::SearchError) -> Outcome {
    Outcome::failure(
        FRE_V1_STATUS_SEARCH_ERROR,
        FRE_V1_DIAGNOSTIC_SEARCH,
        error.to_string(),
    )
}

pub(crate) const fn plan_tag(plan: PlanKind) -> u32 {
    match plan {
        PlanKind::ExactLiteral => FRE_V1_PLAN_EXACT_LITERAL,
        PlanKind::PackedLiteralSet => FRE_V1_PLAN_PACKED_LITERAL_SET,
        PlanKind::LiteralSetDfa => FRE_V1_PLAN_LITERAL_SET_DFA,
        PlanKind::RequiredLiteral => FRE_V1_PLAN_REQUIRED_LITERAL,
        PlanKind::LiteralClassRunLiteral => FRE_V1_PLAN_LITERAL_CLASS_RUN_LITERAL,
        PlanKind::ReverseInner => FRE_V1_PLAN_REVERSE_INNER,
        PlanKind::PrefixClassAlternation => FRE_V1_PLAN_PREFIX_CLASS_ALTERNATION,
        PlanKind::PureByteClassRepeat => FRE_V1_PLAN_PURE_BYTE_CLASS_REPEAT,
        PlanKind::BoundedByteClassSequence => FRE_V1_PLAN_BOUNDED_BYTE_CLASS_SEQUENCE,
        PlanKind::ForwardAnchored => FRE_V1_PLAN_FORWARD_ANCHORED,
        PlanKind::K0 => FRE_V1_PLAN_K0,
        PlanKind::UnicodeFoldedLiteral => FRE_V1_PLAN_UNICODE_FOLDED_LITERAL,
        PlanKind::UnicodeWordRun => FRE_V1_PLAN_UNICODE_WORD_RUN,
        PlanKind::FixedPredicateWord64 => FRE_V1_PLAN_FIXED_PREDICATE_WORD64,
        PlanKind::UnicodeScalarRun => FRE_V1_PLAN_UNICODE_SCALAR_RUN,
        PlanKind::LineDomainByteAtoms => FRE_V1_PLAN_LINE_DOMAIN_BYTE_ATOMS,
    }
}

fn size_u32<T>() -> u32 {
    u32::try_from(core::mem::size_of::<T>()).expect("ABI record fits u32")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FreV1Config;

    const FIXED_PATTERN: &[u8] = br"[A-D][\x00-\x7F]Q";

    fn byte_config(limits: SearchLimits) -> FreV1Config {
        let mut config = FreV1Config::checked_default();
        config.unicode = 0;
        config.search_work = limits.max_work;
        config.search_scratch_bytes =
            u64::try_from(limits.max_scratch_bytes).expect("test scratch fits u64");
        config
    }

    #[test]
    fn selected_end_value_route_is_fixed_predicate_and_unlimited_only() {
        let unlimited = SearchLimits::unlimited();
        let fixed = CompiledRegex::compile(byte_config(unlimited), FIXED_PATTERN)
            .expect("unlimited fixed-predicate regex");
        assert_eq!(
            fixed.regex.build_report().plan,
            PlanKind::FixedPredicateWord64
        );
        assert!(fixed.selected_end_value_route);

        for finite in [
            SearchLimits::default(),
            SearchLimits {
                max_work: u64::MAX - 1,
                max_scratch_bytes: usize::MAX,
            },
            SearchLimits {
                max_work: u64::MAX,
                max_scratch_bytes: usize::MAX - 1,
            },
        ] {
            let fixed = CompiledRegex::compile(byte_config(finite), FIXED_PATTERN)
                .expect("finite fixed-predicate regex");
            assert!(!fixed.selected_end_value_route);
        }

        let noneligible = CompiledRegex::compile(byte_config(unlimited), br"a{2,4}")
            .expect("unlimited noneligible regex");
        assert_ne!(
            noneligible.regex.build_report().plan,
            PlanKind::FixedPredicateWord64
        );
        assert!(!noneligible.selected_end_value_route);
    }

    #[test]
    fn selected_end_value_route_matches_accounted_selection_and_errors() {
        let fixed = CompiledRegex::compile(byte_config(SearchLimits::unlimited()), FIXED_PATTERN)
            .expect("unlimited fixed-predicate regex");
        for haystack in [
            b"zzA!Q".as_slice(),
            b"zzzz".as_slice(),
            b"A\xffQ A!Q".as_slice(),
        ] {
            let expected = fixed
                .regex
                .selected_end_accounted(haystack, fixed.search_limits)
                .expect("unlimited accounted selection")
                .0;
            let actual = fixed.selected_end(haystack).expect("facade selection");
            assert_eq!(actual.found, u32::from(expected.is_some()));
            assert_eq!(actual.end, expected.unwrap_or(0));
        }

        let refused_limits = SearchLimits {
            max_work: 0,
            ..SearchLimits::default()
        };
        let refused = CompiledRegex::compile(byte_config(refused_limits), FIXED_PATTERN)
            .expect("finite fixed-predicate regex");
        assert!(!refused.selected_end_value_route);
        let expected = refused
            .regex
            .selected_end_accounted(b"zzA!Q", refused.search_limits)
            .expect_err("accounted refusal");
        assert_eq!(refused.selected_end(b"zzA!Q"), Err(search_error(&expected)));
    }
}
