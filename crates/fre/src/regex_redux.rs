use core::fmt::Write as _;

use crate::{
    AggregateBuildError, AggregateBuildLimits, AggregateBuilder, AggregateCountRegex,
    AggregateExecutionError, AggregatePlanIdentity, AggregatePlanSelection, AggregateRunLimits,
    AggregateSpans, AggregateSpansRegex, AggregateStrategy, Match, RustProfile,
};

const FLATTEN_PATTERN: &str = r">[^\n]*\n|\n";
const VARIANTS: [&str; 9] = [
    r"agggtaaa|tttaccct",
    r"[cgt]gggtaaa|tttaccc[acg]",
    r"a[act]ggtaaa|tttacc[agt]t",
    r"ag[act]gtaaa|tttac[agt]ct",
    r"agg[act]taaa|ttta[agt]cct",
    r"aggg[acg]aaa|ttt[cgt]ccct",
    r"agggt[cgt]aa|tt[acg]accct",
    r"agggta[cgt]a|t[acg]taccct",
    r"agggtaa[cgt]|[acg]ttaccct",
];
const SUBSTITUTIONS: [(&str, &str); 5] = [
    (r"tHa[Nt]", "<4>"),
    (r"aND|caN|Ha[DS]|WaS", "<3>"),
    (r"a[NSt]|BY", "<2>"),
    (r"<[^>]*>", "|"),
    (r"\|[^|][^|]*\|", "-"),
];
const COMPONENTS: usize = 1 + VARIANTS.len() + SUBSTITUTIONS.len();

/// Complete limits for construction of the fixed composite plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexReduxBuildLimits {
    /// Limits applied independently to every component plan.
    pub aggregate: AggregateBuildLimits,
    /// Maximum component plans allocated before construction begins.
    pub max_components: usize,
    /// Maximum stable-identity input bytes.
    pub max_identity_work: usize,
}

impl Default for RegexReduxBuildLimits {
    fn default() -> Self {
        Self {
            aggregate: AggregateBuildLimits::default(),
            max_components: COMPONENTS,
            max_identity_work: 16 << 10,
        }
    }
}

/// Complete limits for one composite execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexReduxRunLimits {
    /// Limits applied independently to each aggregate search operation.
    pub aggregate: AggregateRunLimits,
    /// Maximum original input bytes.
    pub max_input_bytes: usize,
    /// Maximum bytes retained by any replacement output.
    pub max_output_bytes: usize,
    /// Maximum matches in any one count or replacement stage.
    pub max_stage_events: usize,
    /// Maximum matches summed across all stages.
    pub max_total_events: usize,
    /// Maximum bytes copied across all replacement stages.
    pub max_copy_work: usize,
    /// Maximum formatted report bytes.
    pub max_report_bytes: usize,
}

impl Default for RegexReduxRunLimits {
    fn default() -> Self {
        Self {
            aggregate: AggregateRunLimits::default(),
            max_input_bytes: 64 << 20,
            max_output_bytes: 64 << 20,
            max_stage_events: 16 << 20,
            max_total_events: 64 << 20,
            max_copy_work: 1 << 30,
            max_report_bytes: 16 << 10,
        }
    }
}

/// Stable identity of component patterns, order and compiled plans.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegexReduxPipelineId([u8; 16]);

impl RegexReduxPipelineId {
    /// Raw stable identity bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Complete immutable construction facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegexReduxBuildReport {
    /// Stable ordered component identity.
    pub pipeline_id: RegexReduxPipelineId,
    /// Exact number of freshly built component plans.
    pub components: usize,
    /// Sum of component retained-capacity bytes.
    pub retained_capacity_bytes: usize,
    /// Maximum continuation state count among components.
    pub max_component_states: usize,
}

/// Typed composite-plan construction refusal.
#[derive(Debug)]
pub enum RegexReduxBuildError {
    /// Supplied profile was not the exact pinned Rebar constructor.
    ProfileMismatch,
    /// Fixed component count exceeded policy before component allocation.
    ComponentLimit { required: usize, limit: usize },
    /// Stable identity work exceeded policy before plan publication.
    IdentityWork { required: usize, limit: usize },
    /// A generic replacement literal exceeded the component byte quota.
    ReplacementBytes { required: usize, limit: usize },
    /// One named component failed bounded aggregate construction.
    Component {
        stage: &'static str,
        source: AggregateBuildError,
    },
    /// Component vector allocation failed.
    AllocationFailed { components: usize },
    /// Generic replacement literal allocation failed after byte preflight.
    ReplacementAllocationFailed { bytes: usize },
    /// Checked construction arithmetic overflowed.
    ArithmeticOverflow,
    /// Selected component plan violated the fixed composite contract.
    InternalInvariant(&'static str),
}

impl core::fmt::Display for RegexReduxBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ProfileMismatch => f.write_str("regex-redux requires the pinned Rebar profile"),
            Self::ComponentLimit { required, limit } => {
                write!(f, "regex-redux needs {required} components, limit {limit}")
            }
            Self::IdentityWork { required, limit } => {
                write!(f, "regex-redux identity needs {required} bytes, limit {limit}")
            }
            Self::ReplacementBytes { required, limit } => {
                write!(f, "regex-redux replacement needs {required} bytes, limit {limit}")
            }
            Self::Component { stage, source } => {
                write!(f, "regex-redux {stage} component build failed: {source}")
            }
            Self::AllocationFailed { components } => {
                write!(f, "allocator refused {components} regex-redux components")
            }
            Self::ReplacementAllocationFailed { bytes } => {
                write!(f, "allocator refused {bytes} regex-redux replacement bytes")
            }
            Self::ArithmeticOverflow => f.write_str("regex-redux construction overflowed"),
            Self::InternalInvariant(detail) => write!(f, "regex-redux invariant failed: {detail}"),
        }
    }
}

impl std::error::Error for RegexReduxBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Component { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Typed replacement or composite execution refusal.
#[derive(Debug)]
pub enum RegexReduxRunError {
    /// Composite input was not valid UTF-8 as required by the shared model.
    InvalidUtf8,
    /// Input exceeded the checked complete-operation bound.
    InputBytes { required: usize, limit: usize },
    /// One replacement output exceeded its exact preflight bound.
    OutputBytes { required: usize, limit: usize },
    /// One stage or the complete pipeline exceeded event policy.
    MatchEvents { required: usize, limit: usize },
    /// Replacement copying exceeded complete pipeline policy.
    CopyWork { required: usize, limit: usize },
    /// Formatted report exceeded its exact preflight bound.
    ReportBytes { required: usize, limit: usize },
    /// A built-in non-empty stage unexpectedly selected an empty match.
    EmptyMatch { stage: &'static str, offset: usize },
    /// A component aggregate operation refused execution.
    Aggregate {
        stage: &'static str,
        source: Box<AggregateExecutionError>,
    },
    /// A fully preflighted output allocation failed.
    AllocationFailed { bytes: usize },
    /// Checked operation arithmetic overflowed.
    ArithmeticOverflow,
    /// A selected match or output violated an internal invariant.
    InternalInvariant(&'static str),
}

impl core::fmt::Display for RegexReduxRunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("regex-redux input is not valid UTF-8"),
            Self::InputBytes { required, limit } => {
                write!(f, "regex-redux input needs {required} bytes, limit {limit}")
            }
            Self::OutputBytes { required, limit } => {
                write!(f, "regex-redux output needs {required} bytes, limit {limit}")
            }
            Self::MatchEvents { required, limit } => {
                write!(f, "regex-redux needs {required} match events, limit {limit}")
            }
            Self::CopyWork { required, limit } => {
                write!(f, "regex-redux needs {required} copy work, limit {limit}")
            }
            Self::ReportBytes { required, limit } => {
                write!(f, "regex-redux report needs {required} bytes, limit {limit}")
            }
            Self::EmptyMatch { stage, offset } => {
                write!(f, "regex-redux {stage} selected an empty match at {offset}")
            }
            Self::Aggregate { stage, source } => {
                write!(f, "regex-redux {stage} execution failed: {source}")
            }
            Self::AllocationFailed { bytes } => {
                write!(f, "allocator refused {bytes} regex-redux bytes")
            }
            Self::ArithmeticOverflow => f.write_str("regex-redux execution overflowed"),
            Self::InternalInvariant(detail) => write!(f, "regex-redux invariant failed: {detail}"),
        }
    }
}

impl std::error::Error for RegexReduxRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Aggregate { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Generic bounded non-empty global replacement component.
#[derive(Debug)]
pub struct RegexReduxReplacementPlan {
    regex: AggregateSpansRegex,
    replacement: Box<[u8]>,
    stage: &'static str,
}

impl RegexReduxReplacementPlan {
    /// Compile one reusable replacement component.
    ///
    /// # Errors
    ///
    /// Returns a typed profile, aggregate construction or allocation refusal.
    pub fn build(
        pattern: impl Into<String>,
        replacement: impl AsRef<str>,
        mut profile: RustProfile,
        limits: AggregateBuildLimits,
    ) -> Result<Self, RegexReduxBuildError> {
        profile.options.unicode = false;
        profile.options.case_insensitive = false;
        Self::build_named(pattern.into(), replacement.as_ref(), profile, limits, "replacement")
    }

    fn build_named(
        pattern: String,
        replacement: &str,
        profile: RustProfile,
        limits: AggregateBuildLimits,
        stage: &'static str,
    ) -> Result<Self, RegexReduxBuildError> {
        require_profile(&profile)?;
        let replacement_limit = limits.exact_literal.max_needle_bytes;
        if replacement.len() > replacement_limit {
            return Err(RegexReduxBuildError::ReplacementBytes {
                required: replacement.len(),
                limit: replacement_limit,
            });
        }
        let regex = AggregateBuilder::new(pattern)
            .profile(profile)
            .unicode(false)
            .case_insensitive(false)
            .limits(limits)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_spans()
            .map_err(|source| RegexReduxBuildError::Component { stage, source })?;
        let replacement_bytes = fre_exact_alloc::copy_exact(replacement.as_bytes())
            .map_err(|_| RegexReduxBuildError::ReplacementAllocationFailed {
                bytes: replacement.len(),
            })?;
        let replacement = replacement_bytes.into_boxed_slice();
        Ok(Self {
            regex,
            replacement,
            stage,
        })
    }

    /// Replace every complete non-overlapping match, refusing empty matches.
    ///
    /// # Errors
    ///
    /// Returns before replacement allocation when exact output, event or copy
    /// preflight exceeds policy. Aggregate and allocator failures stay typed.
    pub fn replace(
        &self,
        input: &[u8],
        limits: RegexReduxRunLimits,
    ) -> Result<RegexReduxReplacementResult, RegexReduxRunError> {
        enforce_input(input.len(), limits.max_input_bytes)?;
        let matches = self
            .regex
            .spans(input, limits.aggregate)
            .map_err(|source| RegexReduxRunError::Aggregate {
                stage: self.stage,
                source: Box::new(source),
            })?;
        enforce_events(matches.len(), limits.max_stage_events)?;
        let mut removed = 0_usize;
        for matched in &matches {
            if matched.start == matched.end {
                return Err(RegexReduxRunError::EmptyMatch {
                    stage: self.stage,
                    offset: matched.start,
                });
            }
            let width = matched
                .end
                .checked_sub(matched.start)
                .ok_or(RegexReduxRunError::InternalInvariant(
                    "replacement match ends before it starts",
                ))?;
            removed = checked_add(removed, width)?;
        }
        let retained = input
            .len()
            .checked_sub(removed)
            .ok_or(RegexReduxRunError::InternalInvariant(
                "replacement widths exceed input",
            ))?;
        let inserted = matches
            .len()
            .checked_mul(self.replacement.len())
            .ok_or(RegexReduxRunError::ArithmeticOverflow)?;
        let output_len = checked_add(retained, inserted)?;
        if output_len > limits.max_output_bytes {
            return Err(RegexReduxRunError::OutputBytes {
                required: output_len,
                limit: limits.max_output_bytes,
            });
        }
        let copy_work = checked_add(input.len(), output_len)?;
        if copy_work > limits.max_copy_work {
            return Err(RegexReduxRunError::CopyWork {
                required: copy_work,
                limit: limits.max_copy_work,
            });
        }
        let mut output = fre_exact_alloc::vec_with_exact_capacity(output_len)
            .map_err(|_| RegexReduxRunError::AllocationFailed { bytes: output_len })?;
        let allocated = output_len;
        let mut cursor = 0_usize;
        for matched in &matches {
            if matched.start < cursor || matched.end > input.len() {
                return Err(RegexReduxRunError::InternalInvariant(
                    "replacement spans are overlapping or outside input",
                ));
            }
            output.extend_from_slice(&input[cursor..matched.start]);
            output.extend_from_slice(&self.replacement);
            cursor = matched.end;
        }
        output.extend_from_slice(&input[cursor..]);
        if output.len() != output_len {
            return Err(RegexReduxRunError::InternalInvariant(
                "replacement output differs from exact preflight",
            ));
        }
        Ok(RegexReduxReplacementResult {
            output,
            matches,
            copy_work,
            allocated_output_bytes: allocated,
        })
    }
}

/// Fully admitted replacement output and exact source match offsets.
#[derive(Debug)]
pub struct RegexReduxReplacementResult {
    output: Vec<u8>,
    matches: AggregateSpans,
    copy_work: usize,
    allocated_output_bytes: usize,
}

impl RegexReduxReplacementResult {
    /// Complete replaced bytes.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// Exact absolute byte spans selected in the source input.
    #[must_use]
    pub const fn matches(&self) -> &AggregateSpans {
        &self.matches
    }

    fn into_parts(self) -> (Vec<u8>, usize, usize, usize) {
        (
            self.output,
            self.matches.len(),
            self.copy_work,
            self.allocated_output_bytes,
        )
    }
}

#[derive(Debug)]
struct CountPlan {
    regex: AggregateCountRegex,
}

impl CountPlan {
    fn build(
        pattern: &str,
        profile: RustProfile,
        limits: AggregateBuildLimits,
    ) -> Result<Self, RegexReduxBuildError> {
        let regex = AggregateBuilder::new(pattern)
            .profile(profile)
            .unicode(false)
            .case_insensitive(false)
            .limits(limits)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_count()
            .map_err(|source| RegexReduxBuildError::Component {
                stage: "variant-count",
                source,
            })?;
        Ok(Self { regex })
    }

    fn count(
        &self,
        input: &[u8],
        limits: RegexReduxRunLimits,
    ) -> Result<usize, RegexReduxRunError> {
        let result = self.regex.count(input, limits.aggregate).map_err(|source| {
            RegexReduxRunError::Aggregate {
                stage: "variant-count",
                source: Box::new(source),
            }
        })?;
        let value = usize::try_from(result.value())
            .map_err(|_| RegexReduxRunError::ArithmeticOverflow)?;
        enforce_events(value, limits.max_stage_events)?;
        Ok(value)
    }
}

/// Builder for the exact ordered Rebar regex-redux composite operation.
#[derive(Clone, Debug)]
pub struct RegexReduxBuilder {
    profile: RustProfile,
    limits: RegexReduxBuildLimits,
}

impl RegexReduxBuilder {
    /// Start from the exact pinned Rebar profile with model-fixed flags.
    #[must_use]
    pub fn new() -> Self {
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = false;
        profile.options.case_insensitive = false;
        Self {
            profile,
            limits: RegexReduxBuildLimits::default(),
        }
    }

    /// Select the pinned release-stack identity; model flags remain fixed.
    #[must_use]
    pub fn profile(mut self, mut profile: RustProfile) -> Self {
        profile.options.unicode = false;
        profile.options.case_insensitive = false;
        self.profile = profile;
        self
    }

    /// Replace all checked construction limits.
    #[must_use]
    pub const fn limits(mut self, limits: RegexReduxBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Build all fifteen component plans before publishing the pipeline.
    ///
    /// # Errors
    ///
    /// Returns a typed profile, component, allocation, identity or arithmetic
    /// refusal. There is no deferred component construction.
    pub fn build(self) -> Result<RegexReduxPlan, RegexReduxBuildError> {
        require_profile(&self.profile)?;
        if COMPONENTS > self.limits.max_components {
            return Err(RegexReduxBuildError::ComponentLimit {
                required: COMPONENTS,
                limit: self.limits.max_components,
            });
        }
        let identity_work = identity_work_bound()?;
        if identity_work > self.limits.max_identity_work {
            return Err(RegexReduxBuildError::IdentityWork {
                required: identity_work,
                limit: self.limits.max_identity_work,
            });
        }
        let flatten = RegexReduxReplacementPlan::build_named(
            FLATTEN_PATTERN.to_string(),
            "",
            self.profile.clone(),
            self.limits.aggregate,
            "flatten",
        )?;
        let mut variants = fre_exact_alloc::vec_with_exact_capacity(VARIANTS.len())
            .map_err(|_| RegexReduxBuildError::AllocationFailed {
                components: VARIANTS.len(),
            })?;
        for pattern in VARIANTS {
            variants.push(CountPlan::build(
                pattern,
                self.profile.clone(),
                self.limits.aggregate,
            )?);
        }
        let mut substitutions = fre_exact_alloc::vec_with_exact_capacity(SUBSTITUTIONS.len())
            .map_err(|_| RegexReduxBuildError::AllocationFailed {
                components: SUBSTITUTIONS.len(),
            })?;
        for (pattern, replacement) in SUBSTITUTIONS {
            substitutions.push(RegexReduxReplacementPlan::build_named(
                pattern.to_string(),
                replacement,
                self.profile.clone(),
                self.limits.aggregate,
                "substitution",
            )?);
        }
        let reports = core::iter::once(flatten.regex.build_report())
            .chain(variants.iter().map(|plan| plan.regex.build_report()))
            .chain(substitutions.iter().map(|plan| plan.regex.build_report()));
        let mut retained_capacity_bytes = 0_usize;
        let mut max_component_states = 0_usize;
        let mut component_ids = fre_exact_alloc::vec_with_exact_capacity(COMPONENTS)
            .map_err(|_| RegexReduxBuildError::AllocationFailed {
                components: COMPONENTS,
            })?;
        for report in reports {
            retained_capacity_bytes = retained_capacity_bytes
                .checked_add(report.retained_capacity_bytes)
                .ok_or(RegexReduxBuildError::ArithmeticOverflow)?;
            if let crate::AggregateBuildAccounting::Continuation(accounting) = report.build {
                max_component_states = max_component_states.max(accounting.program_states);
            }
            let AggregatePlanIdentity::Continuation(identity) = report.plan_identity else {
                return Err(RegexReduxBuildError::InternalInvariant(
                    "regex-redux component is not a continuation plan",
                ));
            };
            component_ids.push(identity.bytes());
        }
        let (pipeline_id, observed_identity_work) = pipeline_identity(&component_ids)?;
        if observed_identity_work != identity_work {
            return Err(RegexReduxBuildError::InternalInvariant(
                "identity preflight differs from construction",
            ));
        }
        Ok(RegexReduxPlan {
            flatten,
            variants,
            substitutions,
            report: RegexReduxBuildReport {
                pipeline_id,
                components: COMPONENTS,
                retained_capacity_bytes,
                max_component_states,
            },
        })
    }
}

impl Default for RegexReduxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete immutable regex-redux component pipeline.
#[derive(Debug)]
pub struct RegexReduxPlan {
    flatten: RegexReduxReplacementPlan,
    variants: Vec<CountPlan>,
    substitutions: Vec<RegexReduxReplacementPlan>,
    report: RegexReduxBuildReport,
}

impl RegexReduxPlan {
    /// Complete construction facts and stable ordered identity.
    #[must_use]
    pub const fn build_report(&self) -> &RegexReduxBuildReport {
        &self.report
    }

    /// Execute the exact ordered flatten, nine-count and five-substitution pipeline.
    ///
    /// # Errors
    ///
    /// Returns a typed input, component, non-empty, allocation, report or
    /// complete-operation resource refusal.
    pub fn execute(
        &self,
        input: &[u8],
        limits: RegexReduxRunLimits,
    ) -> Result<RegexReduxResult, RegexReduxRunError> {
        enforce_input(input.len(), limits.max_input_bytes)?;
        core::str::from_utf8(input).map_err(|_| RegexReduxRunError::InvalidUtf8)?;
        let stage_limits = RegexReduxRunLimits {
            // Intermediate input was already produced under the output cap.
            max_input_bytes: limits.max_output_bytes,
            ..limits
        };
        let input_length = input.len();
        let flattened = self.flatten.replace(input, stage_limits)?;
        let (mut sequence, flatten_events, flatten_copy, flatten_allocated) =
            flattened.into_parts();
        let clean_length = sequence.len();
        let mut total_events = flatten_events;
        enforce_events(total_events, limits.max_total_events)?;
        let mut copy_work = flatten_copy;
        let mut peak_output_bytes = flatten_allocated;
        let mut variant_counts = [0_usize; 9];
        for (index, plan) in self.variants.iter().enumerate() {
            let count = plan.count(&sequence, stage_limits)?;
            variant_counts[index] = count;
            total_events = checked_add(total_events, count)?;
            enforce_events(total_events, limits.max_total_events)?;
        }
        for plan in &self.substitutions {
            let replaced = plan.replace(&sequence, stage_limits)?;
            let (next, events, copied, allocated) = replaced.into_parts();
            total_events = checked_add(total_events, events)?;
            enforce_events(total_events, limits.max_total_events)?;
            copy_work = checked_add(copy_work, copied)?;
            if copy_work > limits.max_copy_work {
                return Err(RegexReduxRunError::CopyWork {
                    required: copy_work,
                    limit: limits.max_copy_work,
                });
            }
            peak_output_bytes = peak_output_bytes.max(allocated);
            sequence = next;
        }
        let report_bytes = report_length(
            &variant_counts,
            input_length,
            clean_length,
            sequence.len(),
        )?;
        if report_bytes > limits.max_report_bytes {
            return Err(RegexReduxRunError::ReportBytes {
                required: report_bytes,
                limit: limits.max_report_bytes,
            });
        }
        let report_storage = fre_exact_alloc::vec_with_exact_capacity(report_bytes)
            .map_err(|_| RegexReduxRunError::AllocationFailed { bytes: report_bytes })?;
        let mut report = String::from_utf8(report_storage).map_err(|_| {
            RegexReduxRunError::InternalInvariant("empty report allocation is not UTF-8")
        })?;
        for (pattern, count) in VARIANTS.into_iter().zip(variant_counts) {
            writeln!(&mut report, "{pattern} {count}")
                .map_err(|_| RegexReduxRunError::InternalInvariant("format report variant"))?;
        }
        writeln!(
            &mut report,
            "\n{input_length}\n{clean_length}\n{}",
            sequence.len()
        )
        .map_err(|_| RegexReduxRunError::InternalInvariant("format report lengths"))?;
        if report.len() != report_bytes {
            return Err(RegexReduxRunError::InternalInvariant(
                "formatted report differs from exact preflight",
            ));
        }
        Ok(RegexReduxResult {
            sequence,
            report,
            input_length,
            clean_length,
            variant_counts,
            accounting: RegexReduxAccounting {
                component_executions: COMPONENTS,
                match_events: total_events,
                copy_work,
                peak_output_bytes,
                report_bytes,
            },
        })
    }
}

/// Exact observed composite counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexReduxAccounting {
    /// Number of built-in component plans executed.
    pub component_executions: usize,
    /// Total selected matches across all ordered stages.
    pub match_events: usize,
    /// Sum of replacement input and output bytes copied.
    pub copy_work: usize,
    /// Largest exact replacement-output allocation.
    pub peak_output_bytes: usize,
    /// Exact formatted report bytes.
    pub report_bytes: usize,
}

/// Complete immutable composite output.
#[derive(Debug)]
pub struct RegexReduxResult {
    sequence: Vec<u8>,
    report: String,
    input_length: usize,
    clean_length: usize,
    variant_counts: [usize; 9],
    accounting: RegexReduxAccounting,
}

impl RegexReduxResult {
    /// Original input byte length.
    #[must_use]
    pub const fn input_length(&self) -> usize {
        self.input_length
    }

    /// Byte length after header and newline removal.
    #[must_use]
    pub const fn clean_length(&self) -> usize {
        self.clean_length
    }

    /// Byte length after all five ordered substitutions.
    #[must_use]
    pub fn final_length(&self) -> usize {
        self.sequence.len()
    }

    /// Final transformed sequence bytes.
    #[must_use]
    pub fn final_sequence(&self) -> &[u8] {
        &self.sequence
    }

    /// Nine variant counts in protocol order.
    #[must_use]
    pub const fn variant_counts(&self) -> &[usize; 9] {
        &self.variant_counts
    }

    /// Complete exact protocol report, including its trailing newline.
    #[must_use]
    pub fn report(&self) -> &str {
        &self.report
    }

    /// Observed bounded composite counters.
    #[must_use]
    pub const fn accounting(&self) -> RegexReduxAccounting {
        self.accounting
    }
}

fn require_profile(profile: &RustProfile) -> Result<(), RegexReduxBuildError> {
    let mut required = RustProfile::rebar_1_12_4();
    required.options.unicode = false;
    required.options.case_insensitive = false;
    if profile != &required {
        return Err(RegexReduxBuildError::ProfileMismatch);
    }
    Ok(())
}

fn pipeline_identity(
    component_ids: &[[u8; 16]],
) -> Result<(RegexReduxPipelineId, usize), RegexReduxBuildError> {
    let mut first = 0xcbf2_9ce4_8422_2325_u64;
    let mut second = 0x8422_2325_cbf2_9ce4_u64;
    let mut work = 0_usize;
    let mut feed = |bytes: &[u8]| -> Result<(), RegexReduxBuildError> {
        work = work
            .checked_add(bytes.len())
            .ok_or(RegexReduxBuildError::ArithmeticOverflow)?;
        for &byte in bytes {
            first ^= u64::from(byte);
            first = first.wrapping_mul(0x0000_0100_0000_01B3);
            second ^= u64::from(byte).rotate_left(5);
            second = second.wrapping_mul(0x9E37_79B1_85EB_CA87);
        }
        Ok(())
    };
    feed(b"fre.regex-redux.rebar-generic.v1")?;
    feed(FLATTEN_PATTERN.as_bytes())?;
    for pattern in VARIANTS {
        feed(pattern.as_bytes())?;
    }
    for (pattern, replacement) in SUBSTITUTIONS {
        feed(pattern.as_bytes())?;
        feed(replacement.as_bytes())?;
    }
    for identity in component_ids {
        feed(identity)?;
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.to_le_bytes());
    bytes[8..].copy_from_slice(&second.to_le_bytes());
    Ok((RegexReduxPipelineId(bytes), work))
}

fn identity_work_bound() -> Result<usize, RegexReduxBuildError> {
    let mut work = b"fre.regex-redux.rebar-generic.v1".len();
    work = work
        .checked_add(FLATTEN_PATTERN.len())
        .ok_or(RegexReduxBuildError::ArithmeticOverflow)?;
    for pattern in VARIANTS {
        work = work
            .checked_add(pattern.len())
            .ok_or(RegexReduxBuildError::ArithmeticOverflow)?;
    }
    for (pattern, replacement) in SUBSTITUTIONS {
        work = work
            .checked_add(pattern.len())
            .and_then(|value| value.checked_add(replacement.len()))
            .ok_or(RegexReduxBuildError::ArithmeticOverflow)?;
    }
    work.checked_add(
        COMPONENTS
            .checked_mul(16)
            .ok_or(RegexReduxBuildError::ArithmeticOverflow)?,
    )
    .ok_or(RegexReduxBuildError::ArithmeticOverflow)
}

fn report_length(
    counts: &[usize; 9],
    input: usize,
    clean: usize,
    output: usize,
) -> Result<usize, RegexReduxRunError> {
    let mut length = 1_usize;
    for (pattern, count) in VARIANTS.into_iter().zip(counts) {
        length = checked_add(length, pattern.len())?;
        length = checked_add(length, 1)?;
        length = checked_add(length, decimal_digits(*count))?;
        length = checked_add(length, 1)?;
    }
    for value in [input, clean, output] {
        length = checked_add(length, decimal_digits(value))?;
        length = checked_add(length, 1)?;
    }
    Ok(length)
}

fn decimal_digits(mut value: usize) -> usize {
    let mut digits = 1_usize;
    while value >= 10 {
        value /= 10;
        digits = digits.saturating_add(1);
    }
    digits
}

fn enforce_input(required: usize, limit: usize) -> Result<(), RegexReduxRunError> {
    if required > limit {
        return Err(RegexReduxRunError::InputBytes { required, limit });
    }
    Ok(())
}

fn enforce_events(required: usize, limit: usize) -> Result<(), RegexReduxRunError> {
    if required > limit {
        return Err(RegexReduxRunError::MatchEvents { required, limit });
    }
    Ok(())
}

fn checked_add(left: usize, right: usize) -> Result<usize, RegexReduxRunError> {
    left.checked_add(right)
        .ok_or(RegexReduxRunError::ArithmeticOverflow)
}
