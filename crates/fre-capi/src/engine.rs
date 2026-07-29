//! Safe translation between stable ABI records and `fre::PortableRegex`.

use fre::{PlanKind, PortableBuilder, PortableRegex, SearchLimits};

use crate::{
    FRE_V1_ADMISSION_UPSTREAM_ORACLE_PENDING, FRE_V1_DIAGNOSTIC_COMPILE, FRE_V1_DIAGNOSTIC_CONFIG,
    FRE_V1_DIAGNOSTIC_PATTERN_ENCODING, FRE_V1_DIAGNOSTIC_SEARCH, FRE_V1_JIT_DENY,
    FRE_V1_PLAN_EXACT_LITERAL, FRE_V1_PLAN_FORWARD_ANCHORED, FRE_V1_PLAN_K0,
    FRE_V1_PLAN_LITERAL_SET_DFA, FRE_V1_PLAN_PACKED_LITERAL_SET, FRE_V1_PLAN_REQUIRED_LITERAL,
    FRE_V1_PLAN_UNICODE_FOLDED_LITERAL, FRE_V1_PLAN_UNICODE_WORD_RUN, FRE_V1_PROFILE_RUST_BYTES,
    FRE_V1_STATUS_COMPILE_ERROR, FRE_V1_STATUS_INVALID_PATTERN_ENCODING,
    FRE_V1_STATUS_SEARCH_ERROR, FRE_V1_STATUS_UNSUPPORTED_CONFIG,
    FRE_V1_STATUS_UNSUPPORTED_PROFILE, FreV1Config, FreV1ExistsResult, FreV1MatchResult,
    FreV1PlanInfo, FreV1SelectedEndResult, boundary::Outcome,
};

#[derive(Debug)]
pub(crate) struct CompiledRegex {
    regex: PortableRegex,
    search_limits: SearchLimits,
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
        Ok(Self {
            regex,
            search_limits: SearchLimits {
                max_work: config.search_work,
                max_scratch_bytes: scratch,
            },
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
        self.regex
            .is_match(haystack, self.search_limits)
            .map(|(matched, _)| FreV1ExistsResult {
                abi_version: crate::FRE_V1_ABI_VERSION,
                struct_size: size_u32::<FreV1ExistsResult>(),
                matched: u32::from(matched),
                reserved: 0,
            })
            .map_err(|error| search_error(&error))
    }

    pub(crate) fn selected_end(&self, haystack: &[u8]) -> Result<FreV1SelectedEndResult, Outcome> {
        self.regex
            .selected_end(haystack, self.search_limits)
            .map(|(end, _)| FreV1SelectedEndResult {
                abi_version: crate::FRE_V1_ABI_VERSION,
                struct_size: size_u32::<FreV1SelectedEndResult>(),
                found: u32::from(end.is_some()),
                reserved: 0,
                end: end.unwrap_or(0),
            })
            .map_err(|error| search_error(&error))
    }

    pub(crate) fn span(&self, haystack: &[u8]) -> Result<FreV1MatchResult, Outcome> {
        self.regex
            .find(haystack, self.search_limits)
            .map(|(matched, _)| FreV1MatchResult {
                abi_version: crate::FRE_V1_ABI_VERSION,
                struct_size: size_u32::<FreV1MatchResult>(),
                found: u32::from(matched.is_some()),
                reserved: 0,
                start: matched.map_or(0, fre::Match::start),
                end: matched.map_or(0, fre::Match::end),
            })
            .map_err(|error| search_error(&error))
    }
}

fn search_error(error: &fre::SearchError) -> Outcome {
    Outcome::failure(
        FRE_V1_STATUS_SEARCH_ERROR,
        FRE_V1_DIAGNOSTIC_SEARCH,
        error.to_string(),
    )
}

const fn plan_tag(plan: PlanKind) -> u32 {
    match plan {
        PlanKind::ExactLiteral => FRE_V1_PLAN_EXACT_LITERAL,
        PlanKind::PackedLiteralSet => FRE_V1_PLAN_PACKED_LITERAL_SET,
        PlanKind::LiteralSetDfa => FRE_V1_PLAN_LITERAL_SET_DFA,
        PlanKind::RequiredLiteral => FRE_V1_PLAN_REQUIRED_LITERAL,
        PlanKind::ForwardAnchored => FRE_V1_PLAN_FORWARD_ANCHORED,
        PlanKind::K0 => FRE_V1_PLAN_K0,
        PlanKind::UnicodeFoldedLiteral => FRE_V1_PLAN_UNICODE_FOLDED_LITERAL,
        PlanKind::UnicodeWordRun => FRE_V1_PLAN_UNICODE_WORD_RUN,
    }
}

fn size_u32<T>() -> u32 {
    u32::try_from(core::mem::size_of::<T>()).expect("ABI record fits u32")
}
