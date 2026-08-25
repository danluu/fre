//! Theorem-gated Rust text facade for byte-equivalent UTF-8 languages.

use core::fmt;

use fre_syntax::{CanonicalPattern, ParseError, ParseRequest, ParseSummary};
use regex_syntax::hir::{Hir, HirKind, Look, LookSet};

use crate::{
    BuildError, BuildLimits, BuildReport, CompatibilityProfile, Match, PlanKind, PlanSelection,
    PortableBuilder, PortableFindIterAccounting, PortableFindIterError, PortableFindIterLimits,
    PortableFindIterRunLimits, PortableK0StartFilterSetupAccounting, PortableMatches,
    PortableOrdinaryCanonical, PortableRegex, PortableSearchSession, PortableSessionMatches,
    RustProfile, SearchAccounting, SearchError, SearchLimits, SearchSessionLimits,
    SearchSessionSetupAccounting, SearchWindow, charge_planner, finite, reserve_planner,
    rust_profile_size_limit, set_rust_profile_size_limit,
};

/// Construction evidence for the first sound Rust text execution slices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableTextBuildReport {
    /// Public text profile proved before portable execution is constructed.
    pub profile: CompatibilityProfile,
    /// Bounded `RustText` syntax traversal.
    pub text_syntax: ParseSummary,
    /// Independently parsed `RustBytes` proof-side syntax traversal.
    pub bytes_syntax: ParseSummary,
    /// Exact theorem that permits byte execution for this text matcher.
    pub proof: PortableTextProof,
    /// Honest report for the internal portable byte executor.
    pub portable: BuildReport,
}

/// Auditable theorem used to equate the public text operation with the
/// internal byte executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortableTextProof {
    /// Both profiles enumerate the same ordered finite UTF-8 language.
    FiniteLanguage { words: usize, word_bytes: usize },
    /// Both profiles produced an identical HIR whose non-empty matches are
    /// valid UTF-8. A nullable HIR is admitted only when every look assertion
    /// is false inside a valid scalar, so byte search cannot publish an empty
    /// match at a non-text boundary.
    IdenticalUtf8Hir {
        minimum_match_bytes: usize,
        has_look_assertions: bool,
        /// Every nullable assertion path is false inside a valid UTF-8 scalar.
        empty_match_utf8_boundary_safe: bool,
    },
    /// The profiles have the same ordered top-level alternatives after
    /// removing corresponding alternatives that provably match no string.
    /// Every remaining alternative is byte-for-byte identical HIR and the
    /// complete language has positive width, so byte execution cannot expose
    /// a match at an interior UTF-8 offset.
    ImpossibleAlternativesElidedUtf8Hir {
        minimum_match_bytes: usize,
        elided_alternatives: usize,
    },
    /// The profiles produced an identical UTF-8 HIR, but a nullable assertion
    /// can succeed inside a scalar when executed as bytes. The internal K0
    /// plan therefore synthesizes a scalar-boundary guard at every candidate
    /// start while preserving the original source and HIR.
    Utf8StartBoundaryGuardedHir {
        minimum_match_bytes: usize,
        has_look_assertions: bool,
    },
}

/// Failure to establish or construct a text-equivalence certificate.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextBuildError {
    /// `RustText` parsing rejected the pattern.
    TextSyntax(ParseError),
    /// The independent `RustBytes` proof parse rejected the pattern.
    BytesProofSyntax(ParseError),
    /// Checked finite-language extraction could not complete.
    FiniteProof(BuildError),
    /// Checked non-finite text/bytes equivalence traversal could not complete.
    EquivalenceProof(BuildError),
    /// The profiles are outside both bounded text-equivalence proof slices.
    NonFiniteLanguage,
    /// `RustText` and `RustBytes` produced different ordered finite languages.
    ProfileLanguageMismatch,
    /// A proved word is not valid UTF-8, so byte matching cannot stand in for
    /// text matching.
    InvalidUtf8Word,
    /// The certified byte-equivalent language could not be constructed by the
    /// portable executor.
    Portable(BuildError),
    /// An impossible profile or arithmetic state was observed.
    InternalInvariant(&'static str),
    /// A caller forced a specialized byte plan that cannot carry the text
    /// facade's required UTF-8 candidate-start guard.
    Utf8StartGuardPlanSelection { selection: PlanSelection },
}

impl fmt::Display for PortableTextBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextSyntax(error) => write!(formatter, "Rust text syntax failed: {error}"),
            Self::BytesProofSyntax(error) => {
                write!(formatter, "Rust bytes proof syntax failed: {error}")
            }
            Self::FiniteProof(error) => write!(formatter, "finite-language proof failed: {error}"),
            Self::EquivalenceProof(error) => {
                write!(formatter, "text/bytes equivalence proof failed: {error}")
            }
            Self::NonFiniteLanguage => formatter.write_str(
                "pattern is outside the UTF-8 equivalence slices proved by the text facade",
            ),
            Self::ProfileLanguageMismatch => formatter.write_str(
                "Rust text and bytes profiles produced different ordered finite languages",
            ),
            Self::InvalidUtf8Word => {
                formatter.write_str("finite byte language contains an invalid UTF-8 word")
            }
            Self::Portable(error) => write!(formatter, "portable executor build failed: {error}"),
            Self::InternalInvariant(detail) => {
                write!(formatter, "text facade invariant failed: {detail}")
            }
            Self::Utf8StartGuardPlanSelection { selection } => write!(
                formatter,
                "UTF-8 start-boundary guard requires automatic or K0 selection, got {selection:?}",
            ),
        }
    }
}

impl std::error::Error for PortableTextBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TextSyntax(error) | Self::BytesProofSyntax(error) => Some(error),
            Self::FiniteProof(error) | Self::EquivalenceProof(error) | Self::Portable(error) => {
                Some(error)
            }
            Self::NonFiniteLanguage
            | Self::ProfileLanguageMismatch
            | Self::InvalidUtf8Word
            | Self::InternalInvariant(_)
            | Self::Utf8StartGuardPlanSelection { .. } => None,
        }
    }
}

/// Checked failure from one contextual Rust text window search.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortableTextSearchError {
    /// A byte window was not ordered, in bounds, and on UTF-8 scalar
    /// boundaries in the original text haystack.
    InvalidUtf8Window {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    /// The certified internal byte executor refused the search.
    Search(SearchError),
}

impl fmt::Display for PortableTextSearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8Window {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "invalid UTF-8 text window [{start}, {end}) for haystack length {haystack_len}",
            ),
            Self::Search(error) => write!(formatter, "text search failed: {error}"),
        }
    }
}

impl std::error::Error for PortableTextSearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8Window { .. } => None,
            Self::Search(error) => Some(error),
        }
    }
}

impl From<SearchError> for PortableTextSearchError {
    fn from(value: SearchError) -> Self {
        Self::Search(value)
    }
}

/// Builder for the first certified Rust `Regex` text slices.
///
/// Finite admission requires both pinned `RustText` and `RustBytes` parsers to
/// produce the same ordered language and every word to be valid UTF-8. The
/// non-finite slice requires identical HIRs whose matches are valid UTF-8. A
/// nullable HIR whose assertions can succeed inside a scalar receives a
/// synthesized scalar-boundary start guard in K0; other identical HIRs need no
/// guard. UTF-8's self-synchronizing encoding then proves that a match cannot
/// begin or end inside a scalar. Every language outside these proofs is
/// rejected instead of silently delegated.
#[derive(Clone, Debug)]
pub struct PortableTextBuilder {
    pattern: String,
    profile: RustProfile,
    limits: BuildLimits,
    selection: PlanSelection,
}

impl PortableTextBuilder {
    /// Start from pinned Rust `regex::RegexBuilder` defaults.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        let profile = RustProfile::default();
        let mut limits = BuildLimits::default();
        if let Some(limit) = rust_profile_size_limit(&profile) {
            limits.max_persistent_bytes = limit;
        }
        Self {
            pattern: pattern.into(),
            profile,
            limits,
            selection: PlanSelection::Auto,
        }
    }

    /// Replace the complete pinned Rust profile.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile.into_regex_builder();
        self.limits.max_persistent_bytes = rust_profile_size_limit(&self.profile)
            .unwrap_or(BuildLimits::default().max_persistent_bytes);
        self
    }

    #[must_use]
    pub(crate) fn set_constituent_profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set the Rust text facade's Unicode mode.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Set case-insensitive mode for the complete pattern before parsing.
    ///
    /// Inline `i` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust text builder.
    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    /// Set multiline mode for `^` and `$` before parsing.
    #[must_use]
    pub fn multi_line(mut self, enabled: bool) -> Self {
        self.profile.options.multi_line = enabled;
        self
    }

    /// Set whether `.` matches the configured line terminator.
    #[must_use]
    pub fn dot_matches_new_line(mut self, enabled: bool) -> Self {
        self.profile.options.dot_matches_new_line = enabled;
        self
    }

    /// Set CRLF mode for the complete pattern before parsing.
    ///
    /// Inline `R` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust text builder.
    #[must_use]
    pub fn crlf(mut self, enabled: bool) -> Self {
        self.profile.options.crlf = enabled;
        self
    }

    /// Swap greedy and lazy repetition semantics before parsing.
    #[must_use]
    pub fn swap_greed(mut self, enabled: bool) -> Self {
        self.profile.options.swap_greed = enabled;
        self
    }

    /// Set verbose mode before parsing, ignoring unescaped pattern whitespace
    /// and treating `#` as the start of a line comment.
    #[must_use]
    pub fn ignore_whitespace(mut self, enabled: bool) -> Self {
        self.profile.options.ignore_whitespace = enabled;
        self
    }

    /// Enable or disable octal escape syntax before parsing.
    #[must_use]
    pub fn octal(mut self, enabled: bool) -> Self {
        self.profile.options.octal = enabled;
        self
    }

    /// Set the parser's abstract-syntax-tree nesting limit.
    #[must_use]
    pub fn nest_limit(mut self, limit: u32) -> Self {
        self.profile.options.nest_limit = limit;
        self
    }

    /// Set the byte recognized by multiline `^` and `$` assertions.
    #[must_use]
    pub fn line_terminator(mut self, line_terminator: u8) -> Self {
        self.profile.options.line_terminator = line_terminator;
        self
    }

    /// Set the maximum bytes retained by FRE's compiled matcher.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        set_rust_profile_size_limit(&mut self.profile, bytes);
        self.limits.max_persistent_bytes = bytes;
        self
    }

    /// Retain the Rust-like lazy-DFA cache option. FRE has no corresponding
    /// cache, so this does not change native construction or execution.
    #[must_use]
    pub fn dfa_size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexBuilder { dfa_size_limit, .. } =
            &mut self.profile.constructor
        {
            *dfa_size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Replace every checked construction limit.
    #[must_use]
    pub const fn limits(mut self, limits: BuildLimits) -> Self {
        self.limits = limits;
        if matches!(
            &self.profile.constructor,
            fre_syntax::RustConstructor::RegexBuilder { .. }
        ) {
            set_rust_profile_size_limit(&mut self.profile, limits.max_persistent_bytes);
        }
        self
    }

    /// Force an internal portable plan for differential testing.
    #[must_use]
    pub const fn plan_selection(mut self, selection: PlanSelection) -> Self {
        self.selection = selection;
        self
    }

    /// Prove one text/bytes equivalence theorem and build the immutable text
    /// matcher.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextBuildError`] when syntax is invalid, the pattern
    /// is outside the proof slice, proof limits are exhausted, profiles
    /// disagree or portable construction fails.
    pub fn build(mut self) -> Result<PortableTextRegex, PortableTextBuildError> {
        let text_profile = CompatibilityProfile::RustText(self.profile.clone());
        let pattern = core::mem::take(&mut self.pattern);
        let text_request = ParseRequest::rust(pattern, text_profile)
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety);
        let text = fre_syntax::parse_attempt(text_request)
            .map_err(|error| PortableTextBuildError::TextSyntax(error.into_source()))?;
        let bytes_profile = CompatibilityProfile::RustBytes(self.profile.clone());
        let Some(text) = text.into_rust_reparse_handoff(bytes_profile) else {
            return Err(PortableTextBuildError::InternalInvariant(
                "RustText parse produced a non-Rust pattern",
            ));
        };
        let text_syntax = text.summary;
        let text_pattern = text.rust;
        let text_profile = text.source_profile;

        let bytes = fre_syntax::parse_attempt(text.request)
            .map_err(|error| PortableTextBuildError::BytesProofSyntax(error.into_source()))?;
        let bytes_syntax = bytes.record().summary.clone();
        let CanonicalPattern::Rust(bytes_pattern) = &bytes.record().pattern else {
            return Err(PortableTextBuildError::InternalInvariant(
                "RustBytes proof parse produced a non-Rust pattern",
            ));
        };

        let proof = prove_equivalence(
            &text_pattern.hir,
            &bytes_pattern.hir,
            self.profile.options.line_terminator,
            &self.limits,
        )?;

        let utf8_start_guarded =
            matches!(proof, PortableTextProof::Utf8StartBoundaryGuardedHir { .. });
        if utf8_start_guarded
            && !matches!(self.selection, PlanSelection::Auto | PlanSelection::ForceK0)
        {
            return Err(PortableTextBuildError::Utf8StartGuardPlanSelection {
                selection: self.selection,
            });
        }

        // The source owner has moved into `bytes`; the empty pattern is only a
        // sentinel. `build_from_parse_attempt` must obtain the authoritative
        // source and HIR from that closed attempt and must not parse this field.
        let mut inner_builder = PortableBuilder::new(String::new())
            .set_constituent_profile(self.profile)
            .limits(self.limits)
            .plan_selection(self.selection)
            .for_text_facade();
        if utf8_start_guarded {
            inner_builder = inner_builder.with_utf8_start_guard();
        }
        let inner = inner_builder
            .build_from_parse_attempt(bytes)
            .map_err(PortableTextBuildError::Portable)?;
        let report = PortableTextBuildReport {
            profile: text_profile.clone(),
            text_syntax,
            bytes_syntax,
            proof,
            portable: inner.build_report().clone(),
        };
        Ok(PortableTextRegex {
            profile: text_profile,
            inner,
            report,
        })
    }
}

fn prove_equivalence(
    text: &regex_syntax::hir::Hir,
    bytes: &regex_syntax::hir::Hir,
    line_terminator: u8,
    limits: &BuildLimits,
) -> Result<PortableTextProof, PortableTextBuildError> {
    let (text_language, text_work) = finite::extract(
        text,
        limits.literal_set.max_patterns,
        limits.literal_set.max_pattern_bytes,
        0,
        limits.max_planner_work,
        false,
        finite::GuardedFiniteBuildLimits::unlimited(),
    )
    .into_incumbent_words()
    .map_err(PortableTextBuildError::FiniteProof)?;
    let (bytes_language, bytes_work) = finite::extract(
        bytes,
        limits.literal_set.max_patterns,
        limits.literal_set.max_pattern_bytes,
        text_work,
        limits.max_planner_work,
        false,
        finite::GuardedFiniteBuildLimits::unlimited(),
    )
    .into_incumbent_words()
    .map_err(PortableTextBuildError::FiniteProof)?;
    match (text_language, bytes_language) {
        (Some(text_language), Some(bytes_language)) => {
            finite_equivalence(&text_language, &bytes_language)
        }
        (None, None) => hir_equivalence(
            text,
            bytes,
            line_terminator,
            bytes_work,
            limits.max_planner_work,
        ),
        (Some(_), None) | (None, Some(_)) => Err(PortableTextBuildError::ProfileLanguageMismatch),
    }
}

fn finite_equivalence(
    text: &[Vec<u8>],
    bytes: &[Vec<u8>],
) -> Result<PortableTextProof, PortableTextBuildError> {
    if text != bytes {
        return Err(PortableTextBuildError::ProfileLanguageMismatch);
    }
    if text.iter().any(|word| core::str::from_utf8(word).is_err()) {
        return Err(PortableTextBuildError::InvalidUtf8Word);
    }
    let word_bytes = text
        .iter()
        .try_fold(0_usize, |total, word| total.checked_add(word.len()))
        .ok_or(PortableTextBuildError::InternalInvariant(
            "finite language byte count overflow",
        ))?;
    Ok(PortableTextProof::FiniteLanguage {
        words: text.len(),
        word_bytes,
    })
}

fn hir_equivalence(
    text: &regex_syntax::hir::Hir,
    bytes: &regex_syntax::hir::Hir,
    line_terminator: u8,
    initial_work: u64,
    work_limit: u64,
) -> Result<PortableTextProof, PortableTextBuildError> {
    let properties = text.properties();
    if !properties.is_utf8() {
        return Err(PortableTextBuildError::NonFiniteLanguage);
    }
    if text != bytes || properties.minimum_len().is_none() {
        let Some((minimum_match_bytes, elided_alternatives)) =
            ordered_top_level_alternatives_equal_after_impossible_elision(
                text,
                bytes,
                initial_work,
                work_limit,
            )
            .map_err(PortableTextBuildError::EquivalenceProof)?
        else {
            return Err(PortableTextBuildError::NonFiniteLanguage);
        };
        return Ok(PortableTextProof::ImpossibleAlternativesElidedUtf8Hir {
            minimum_match_bytes,
            elided_alternatives,
        });
    }
    let minimum_match_bytes =
        properties
            .minimum_len()
            .ok_or(PortableTextBuildError::InternalInvariant(
                "checked HIR minimum disappeared",
            ))?;
    let look_set = properties.look_set();
    let has_look_assertions = !look_set.is_empty();
    let empty_match_utf8_boundary_safe =
        minimum_match_bytes > 0 || looks_are_utf8_boundary_safe(look_set, line_terminator);
    if empty_match_utf8_boundary_safe {
        Ok(PortableTextProof::IdenticalUtf8Hir {
            minimum_match_bytes,
            has_look_assertions,
            empty_match_utf8_boundary_safe,
        })
    } else {
        Ok(PortableTextProof::Utf8StartBoundaryGuardedHir {
            minimum_match_bytes,
            has_look_assertions,
        })
    }
}

/// Compare one deliberately narrow normalization slice used only for the
/// text/bytes proof. Corresponding top-level alternatives may be removed only
/// when a structural proof shows both can never match. Every retained branch
/// must remain exactly equal, positive-width and in the same order.
fn ordered_top_level_alternatives_equal_after_impossible_elision(
    text: &Hir,
    bytes: &Hir,
    initial_work: u64,
    work_limit: u64,
) -> Result<Option<(usize, usize)>, BuildError> {
    let (HirKind::Alternation(text), HirKind::Alternation(bytes)) = (text.kind(), bytes.kind())
    else {
        return Ok(None);
    };
    if text.len() != bytes.len() {
        return Ok(None);
    }
    let mut work = initial_work;
    let mut elided = 0_usize;
    let mut minimum_match_bytes = None;
    let mut tasks = Vec::new();
    let mut values = Vec::new();
    for (text_branch, bytes_branch) in text.iter().zip(bytes) {
        if text_branch == bytes_branch
            && let Some(branch_minimum) = text_branch.properties().minimum_len()
        {
            if branch_minimum == 0 {
                return Ok(None);
            }
            minimum_match_bytes = Some(
                minimum_match_bytes
                    .map_or(branch_minimum, |minimum: usize| minimum.min(branch_minimum)),
            );
            continue;
        }
        let text_impossible = provably_impossible_with_buffers(
            text_branch,
            &mut work,
            work_limit,
            &mut tasks,
            &mut values,
        )?;
        let bytes_impossible = provably_impossible_with_buffers(
            bytes_branch,
            &mut work,
            work_limit,
            &mut tasks,
            &mut values,
        )?;
        if text_impossible && bytes_impossible {
            elided = elided.checked_add(1).ok_or(BuildError::PlannerWorkLimit {
                needed: u64::MAX,
                limit: work_limit,
            })?;
            continue;
        }
        if text_impossible || bytes_impossible || text_branch != bytes_branch {
            return Ok(None);
        }
        let Some(branch_minimum) = text_branch.properties().minimum_len() else {
            return Ok(None);
        };
        if branch_minimum == 0 {
            return Ok(None);
        }
        minimum_match_bytes = Some(
            minimum_match_bytes
                .map_or(branch_minimum, |minimum: usize| minimum.min(branch_minimum)),
        );
    }
    Ok(match (minimum_match_bytes, elided) {
        (Some(minimum), elided) if elided > 0 => Some((minimum, elided)),
        _ => None,
    })
}

#[derive(Clone, Copy, Debug)]
enum ImpossibleTask<'h> {
    Visit(&'h Hir),
    FinishConcat(usize),
    FinishAlternation(usize),
    FinishRepetition { minimum: u32 },
}

/// Prove emptiness using only HIR constructors whose Boolean language rule is
/// exact. This deliberately does not infer contradictions between assertions.
#[cfg(test)]
fn provably_impossible(hir: &Hir, work: &mut u64, work_limit: u64) -> Result<bool, BuildError> {
    let mut tasks = Vec::new();
    let mut values = Vec::new();
    provably_impossible_with_buffers(hir, work, work_limit, &mut tasks, &mut values)
}

fn provably_impossible_with_buffers<'h>(
    hir: &'h Hir,
    work: &mut u64,
    work_limit: u64,
    tasks: &mut Vec<ImpossibleTask<'h>>,
    values: &mut Vec<bool>,
) -> Result<bool, BuildError> {
    tasks.clear();
    values.clear();
    reserve_planner(
        tasks,
        1,
        work,
        work_limit,
        "text equivalence impossible-proof tasks",
    )?;
    tasks.push(ImpossibleTask::Visit(hir));
    while let Some(task) = tasks.pop() {
        match task {
            ImpossibleTask::Visit(hir) => match hir.kind() {
                HirKind::Class(class) => {
                    push_impossible_value(values, class.is_empty(), work, work_limit)?;
                }
                HirKind::Capture(capture) => push_impossible_task(
                    tasks,
                    ImpossibleTask::Visit(&capture.sub),
                    work,
                    work_limit,
                )?,
                HirKind::Concat(parts) => {
                    push_impossible_tasks(
                        tasks,
                        ImpossibleTask::FinishConcat(parts.len()),
                        parts,
                        work,
                        work_limit,
                    )?;
                }
                HirKind::Alternation(branches) => {
                    push_impossible_tasks(
                        tasks,
                        ImpossibleTask::FinishAlternation(branches.len()),
                        branches,
                        work,
                        work_limit,
                    )?;
                }
                HirKind::Repetition(repetition) => {
                    push_impossible_task(
                        tasks,
                        ImpossibleTask::FinishRepetition {
                            minimum: repetition.min,
                        },
                        work,
                        work_limit,
                    )?;
                    push_impossible_task(
                        tasks,
                        ImpossibleTask::Visit(&repetition.sub),
                        work,
                        work_limit,
                    )?;
                }
                HirKind::Empty | HirKind::Literal(_) | HirKind::Look(_) => {
                    push_impossible_value(values, false, work, work_limit)?;
                }
            },
            ImpossibleTask::FinishConcat(count) => {
                finish_impossible_values(values, count, false, work, work_limit)?;
            }
            ImpossibleTask::FinishAlternation(count) => {
                finish_impossible_values(values, count, true, work, work_limit)?;
            }
            ImpossibleTask::FinishRepetition { minimum } => {
                let child = values.pop().ok_or(BuildError::InternalInvariant(
                    "missing impossible repetition value",
                ))?;
                push_impossible_value(values, minimum > 0 && child, work, work_limit)?;
            }
        }
    }
    let proved = values.pop().ok_or(BuildError::InternalInvariant(
        "missing impossible proof result",
    ))?;
    if !values.is_empty() {
        return Err(BuildError::InternalInvariant(
            "extra impossible proof results",
        ));
    }
    Ok(proved)
}

fn push_impossible_task<'h>(
    tasks: &mut Vec<ImpossibleTask<'h>>,
    task: ImpossibleTask<'h>,
    work: &mut u64,
    work_limit: u64,
) -> Result<(), BuildError> {
    reserve_planner(
        tasks,
        1,
        work,
        work_limit,
        "text equivalence impossible-proof tasks",
    )?;
    tasks.push(task);
    Ok(())
}

fn push_impossible_tasks<'h>(
    tasks: &mut Vec<ImpossibleTask<'h>>,
    finish: ImpossibleTask<'h>,
    children: &'h [Hir],
    work: &mut u64,
    work_limit: u64,
) -> Result<(), BuildError> {
    let additional = children
        .len()
        .checked_add(1)
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit: work_limit,
        })?;
    reserve_planner(
        tasks,
        additional,
        work,
        work_limit,
        "text equivalence impossible-proof tasks",
    )?;
    tasks.push(finish);
    tasks.extend(children.iter().rev().map(ImpossibleTask::Visit));
    Ok(())
}

fn push_impossible_value(
    values: &mut Vec<bool>,
    value: bool,
    work: &mut u64,
    work_limit: u64,
) -> Result<(), BuildError> {
    reserve_planner(
        values,
        1,
        work,
        work_limit,
        "text equivalence impossible-proof values",
    )?;
    values.push(value);
    Ok(())
}

fn finish_impossible_values(
    values: &mut Vec<bool>,
    count: usize,
    identity: bool,
    work: &mut u64,
    work_limit: u64,
) -> Result<(), BuildError> {
    let start = values
        .len()
        .checked_sub(count)
        .ok_or(BuildError::InternalInvariant(
            "missing impossible child values",
        ))?;
    charge_planner(work, u64::try_from(count).unwrap_or(u64::MAX), work_limit)?;
    let result = if identity {
        values[start..].iter().all(|&value| value)
    } else {
        values[start..].iter().any(|&value| value)
    };
    values.truncate(start);
    push_impossible_value(values, result, work, work_limit)
}

fn looks_are_utf8_boundary_safe(looks: LookSet, line_terminator: u8) -> bool {
    looks.iter().all(|look| match look {
        Look::StartLF | Look::EndLF => line_terminator.is_ascii(),
        Look::Start
        | Look::End
        | Look::StartCRLF
        | Look::EndCRLF
        | Look::WordAscii
        | Look::WordStartAscii
        | Look::WordEndAscii
        | Look::WordUnicode
        | Look::WordUnicodeNegate
        | Look::WordStartUnicode
        | Look::WordEndUnicode
        | Look::WordStartHalfUnicode
        | Look::WordEndHalfUnicode => true,
        Look::WordAsciiNegate | Look::WordStartHalfAscii | Look::WordEndHalfAscii => false,
    })
}

/// Immutable matcher for the certified Rust text slices.
#[derive(Debug)]
pub struct PortableTextRegex {
    profile: CompatibilityProfile,
    inner: PortableRegex,
    report: PortableTextBuildReport,
}

impl PortableTextRegex {
    /// Construct with pinned Rust text defaults and checked default limits.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextBuildError`] under the same conditions as
    /// [`PortableTextBuilder::build`].
    pub fn new(pattern: impl Into<String>) -> Result<Self, PortableTextBuildError> {
        PortableTextBuilder::new(pattern).build()
    }

    /// Exact public `RustText` profile certified at construction.
    #[must_use]
    pub const fn profile(&self) -> &CompatibilityProfile {
        &self.profile
    }

    /// Text/bytes equivalence and internal portable construction evidence.
    #[must_use]
    pub const fn build_report(&self) -> &PortableTextBuildReport {
        &self.report
    }

    /// Return whether this regex matches anywhere in a valid UTF-8 haystack.
    ///
    /// This is the Rust-compatible ordinary API. It has no caller-visible
    /// work quota and automatically reuses the inner matcher's
    /// construction-bounded adaptive scratch.
    ///
    /// # Panics
    ///
    /// Panics under the same allocation and internal-invariant conditions as
    /// [`PortableRegex::is_match`].
    #[must_use]
    #[inline]
    pub fn is_match(&self, haystack: &str) -> bool {
        self.inner.is_match(haystack.as_bytes())
    }

    /// Whether a selected match exists with exact accounting.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if checked search limits refuse execution.
    pub fn is_match_accounted(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.inner.is_match_accounted(haystack.as_bytes(), limits)
    }

    /// Whether a selected match exists under explicit work and scratch
    /// limits, without constructing facade accounting.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if checked search limits refuse execution.
    pub fn is_match_with_limits(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.inner.is_match_with_limits(haystack.as_bytes(), limits)
    }

    /// Compatibility alias for [`Self::is_match_with_limits`].
    pub fn is_match_value(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.is_match_with_limits(haystack, limits)
    }

    /// Whether a selected match exists at or after the byte offset `start`.
    ///
    /// Like pinned Rust `Regex::is_match_at`, `start` need not be a UTF-8
    /// scalar boundary. An interior offset advances to the next scalar
    /// boundary because every match published by the proved text facade starts
    /// on a scalar boundary. Assertions still inspect the complete original
    /// haystack.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an out-of-bounds start or when checked
    /// search limits refuse execution.
    pub fn is_match_at(
        &self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let start = next_text_boundary(haystack, start);
        self.inner.is_match_at(haystack.as_bytes(), start, limits)
    }

    /// Whether a selected match exists at or after `start` without
    /// constructing facade diagnostic accounting.
    ///
    /// Interior UTF-8 offsets retain the normalization and assertion context
    /// of [`Self::is_match_at`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same contract as
    /// [`Self::is_match_at`].
    pub fn is_match_value_at(
        &self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        let start = next_text_boundary(haystack, start);
        self.inner
            .is_match_value_at(haystack.as_bytes(), start, limits)
    }

    /// Return the selected leftmost-first match in byte offsets.
    ///
    /// This is the Rust-compatible ordinary API. It has no caller-visible
    /// work quota and automatically reuses the inner matcher's
    /// construction-bounded adaptive scratch.
    ///
    /// # Panics
    ///
    /// Panics under the same allocation and internal-invariant conditions as
    /// [`PortableRegex::find`].
    #[must_use]
    #[inline]
    pub fn find(&self, haystack: &str) -> Option<Match> {
        self.inner.find(haystack.as_bytes())
    }

    /// Return the selected leftmost-first match with exact accounting.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if checked search limits refuse execution.
    pub fn find_accounted(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.inner.find_accounted(haystack.as_bytes(), limits)
    }

    /// Return the selected leftmost-first match under explicit work and
    /// scratch limits, without constructing facade accounting.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if checked search limits refuse execution.
    pub fn find_with_limits(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        self.inner.find_with_limits(haystack.as_bytes(), limits)
    }

    /// Compatibility alias for [`Self::find_with_limits`].
    pub fn find_value(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        self.find_with_limits(haystack, limits)
    }

    /// Prepare an explicit reusable session for repeated text value searches
    /// and match iteration.
    ///
    /// K0 admits its workspace ceiling and allocates a compact cache seed here.
    /// A subsequent value search or [`PortableTextSearchSession::find_iter`]
    /// may grow that cache transactionally under its per-call limits. Iterators
    /// start independent whole-iterator accounting. The wrapper preserves this
    /// matcher's text equivalence proof, so scalar-wise empty-match progress is
    /// not exposed on an arbitrary byte matcher.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same one-time setup contract as
    /// [`PortableRegex::search_session`].
    pub fn search_session(
        &self,
        limits: SearchSessionLimits,
    ) -> Result<PortableTextSearchSession<'_>, SearchError> {
        Ok(PortableTextSearchSession {
            inner: self.inner.search_session(limits)?,
            shortest_value_eligible: self.report.portable.plan == PlanKind::K0,
        })
    }

    /// Prepare a fixed-capacity text session whose K0 cache never grows during
    /// a search.
    ///
    /// This is the text-safe counterpart of
    /// [`PortableRegex::fixed_search_session`]. It preserves this matcher's
    /// UTF-8 equivalence proof while putting all K0 capacity allocation in the
    /// source-free session-construction boundary. Call
    /// [`PortableTextSearchSession::prepare_k0_start_filter`] as a second
    /// source-free setup step when the later measured region must also exclude
    /// the optional immutable plan-proof allocation.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same fixed setup contract as
    /// [`PortableRegex::fixed_search_session`].
    pub fn fixed_search_session(
        &self,
        limits: SearchSessionLimits,
    ) -> Result<PortableTextSearchSession<'_>, SearchError> {
        Ok(PortableTextSearchSession {
            inner: self.inner.fixed_search_session(limits)?,
            shortest_value_eligible: self.report.portable.plan == PlanKind::K0,
        })
    }

    pub(crate) fn fixed_endpoint_search_session(
        &self,
        limits: SearchSessionLimits,
    ) -> Result<PortableTextSearchSession<'_>, SearchError> {
        Ok(PortableTextSearchSession {
            inner: self.inner.fixed_endpoint_search_session(limits)?,
            shortest_value_eligible: self.report.portable.plan == PlanKind::K0,
        })
    }

    pub(crate) fn ordinary_canonical(&self) -> Result<PortableOrdinaryCanonical<'_>, SearchError> {
        PortableOrdinaryCanonical::try_new(&self.inner)
    }

    /// Iterate over every non-overlapping match with Rust text empty-match
    /// progress and original-haystack assertion context.
    ///
    /// Repeated empty matches advance by one UTF-8 scalar value, never by one
    /// byte. K0 prepares one reusable workspace before iteration, and iterator
    /// items remain fallible so a resource refusal cannot be mistaken for
    /// ordinary exhaustion.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if reusable K0 workspace construction exceeds
    /// `limits.session`. Per-search and whole-iterator failures are yielded as
    /// [`PortableFindIterError`] items.
    pub fn find_iter<'r, 'h>(
        &'r self,
        haystack: &'h str,
        limits: PortableFindIterLimits,
    ) -> Result<PortableTextMatches<'r, 'h>, SearchError> {
        Ok(PortableTextMatches {
            inner: self.inner.find_iter_utf8(haystack, limits)?,
        })
    }

    /// Return the selected leftmost-first match at or after byte offset
    /// `start`.
    ///
    /// Interior UTF-8 offsets advance to the next scalar boundary without
    /// slicing the haystack, so look assertions retain their original context.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an out-of-bounds start or when checked
    /// search limits refuse execution.
    pub fn find_at(
        &self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        let start = next_text_boundary(haystack, start);
        self.inner.find_at(haystack.as_bytes(), start, limits)
    }

    /// Return only the selected match at or after byte offset `start`.
    ///
    /// Interior UTF-8 offsets retain the normalization and assertion context
    /// of [`Self::find_at`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same contract as [`Self::find_at`].
    pub fn find_at_value(
        &self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        let start = next_text_boundary(haystack, start);
        self.inner.find_at_value(haystack.as_bytes(), start, limits)
    }

    /// Search a byte range whose endpoints are scalar boundaries while
    /// assertions retain their original-haystack context.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextSearchError::InvalidUtf8Window`] unless both
    /// endpoints are ordered, in bounds, and UTF-8 scalar boundaries. Other
    /// checked search refusals are returned as
    /// [`PortableTextSearchError::Search`].
    pub fn find_window(
        &self,
        haystack: &str,
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), PortableTextSearchError> {
        let start = window.start();
        let end = window.end();
        if start > end
            || end > haystack.len()
            || !haystack.is_char_boundary(start)
            || !haystack.is_char_boundary(end)
        {
            return Err(PortableTextSearchError::InvalidUtf8Window {
                start,
                end,
                haystack_len: haystack.len(),
            });
        }
        self.inner
            .find_window(haystack.as_bytes(), window, limits)
            .map_err(PortableTextSearchError::Search)
    }

    /// Return only the selected match inside a scalar-boundary byte range.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextSearchError`] under the same range and resource
    /// contract as [`Self::find_window`].
    pub fn find_window_value(
        &self,
        haystack: &str,
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, PortableTextSearchError> {
        let start = window.start();
        let end = window.end();
        if start > end
            || end > haystack.len()
            || !haystack.is_char_boundary(start)
            || !haystack.is_char_boundary(end)
        {
            return Err(PortableTextSearchError::InvalidUtf8Window {
                start,
                end,
                haystack_len: haystack.len(),
            });
        }
        self.inner
            .find_window_value(haystack.as_bytes(), window, limits)
            .map_err(PortableTextSearchError::Search)
    }

    /// Return the first byte boundary where a match is detected, with exact
    /// accounting.
    ///
    /// Like [`PortableRegex::shortest_match`], this may be shorter than the
    /// end of the leftmost-first match returned by [`Self::find`]. The byte
    /// offset is nevertheless a UTF-8 scalar boundary because construction
    /// proved the text and byte languages equivalent.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if checked search limits refuse execution.
    pub fn shortest_match(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.inner.shortest_match(haystack.as_bytes(), limits)
    }

    /// Return only the first byte boundary where a match is detected.
    ///
    /// This preserves [`Self::shortest_match`] semantics without constructing
    /// facade diagnostic accounting on value-only native and K0 routes.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same contract as
    /// [`Self::shortest_match`].
    pub fn shortest_match_value(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        self.inner.shortest_match_value(haystack.as_bytes(), limits)
    }

    /// Return the first detected match end at or after byte offset `start`,
    /// with exact accounting.
    ///
    /// Interior UTF-8 offsets advance to the next scalar boundary without
    /// slicing the haystack, so assertions retain their original context.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an out-of-bounds start or when checked
    /// search limits refuse execution.
    pub fn shortest_match_at(
        &self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let start = next_text_boundary(haystack, start);
        self.inner
            .shortest_match_at(haystack.as_bytes(), start, limits)
    }

    /// Return only the first detected match end at or after byte offset
    /// `start`.
    ///
    /// Interior UTF-8 offsets retain the normalization and assertion context
    /// of [`Self::shortest_match_at`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same contract as
    /// [`Self::shortest_match_at`].
    pub fn shortest_match_at_value(
        &self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        let start = next_text_boundary(haystack, start);
        self.inner
            .shortest_match_at_value(haystack.as_bytes(), start, limits)
    }

    /// Return the selected match end in bytes without exposing its start.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if checked search limits refuse execution.
    pub fn selected_end_accounted(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.inner
            .selected_end_accounted(haystack.as_bytes(), limits)
    }

    /// Compatibility alias for [`Self::selected_end_accounted`].
    pub fn selected_end(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.selected_end_accounted(haystack, limits)
    }
}

/// Reusable, text-proof-preserving wrapper around [`PortableSearchSession`].
///
/// The session owns one construction-selected workspace. Its value searches
/// and iterators borrow it mutably, so only one search can use that workspace
/// at a time and an iterator drop deterministically makes the session reusable.
#[derive(Debug)]
pub struct PortableTextSearchSession<'r> {
    inner: PortableSearchSession<'r>,
    shortest_value_eligible: bool,
}

impl<'r> PortableTextSearchSession<'r> {
    /// Stable runtime identity of the borrowed matcher.
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        self.inner.runtime_implementation_id()
    }

    /// One-time K0 workspace allocation and initialization facts.
    ///
    /// These are charged once when [`PortableTextRegex::search_session`] or
    /// [`PortableTextRegex::fixed_search_session`] constructs this session,
    /// not once per iterator. Native plans return `None`.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.inner.workspace_setup_accounting()
    }

    /// Settle the optional immutable K0 start-filter proof under one complete
    /// source-free setup envelope.
    ///
    /// This is the text-safe counterpart of
    /// [`PortableSearchSession::prepare_k0_start_filter`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same setup contract as the byte
    /// session method.
    #[doc(hidden)]
    pub fn prepare_k0_start_filter(
        &mut self,
        limits: SearchSessionLimits,
    ) -> Result<Option<PortableK0StartFilterSetupAccounting>, SearchError> {
        self.inner.prepare_k0_start_filter(limits)
    }

    pub(crate) fn is_match_accounted_at_normalized(
        &mut self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        debug_assert!(start <= haystack.len() && haystack.is_char_boundary(start));
        self.inner.is_match_window(
            haystack.as_bytes(),
            SearchWindow::new(start, haystack.len()),
            limits,
        )
    }

    /// Whether a selected match exists while reusing this session's workspace.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-search contract as
    /// [`PortableTextRegex::is_match_value`].
    pub fn is_match_value(
        &mut self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.inner.is_match_value(haystack.as_bytes(), limits)
    }

    /// Whether a selected match exists at or after `start` while reusing this
    /// session's workspace.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableTextRegex::is_match_value_at`].
    pub fn is_match_value_at(
        &mut self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        let start = next_text_boundary(haystack, start);
        self.inner
            .is_match_value_at(haystack.as_bytes(), start, limits)
    }

    pub(crate) fn is_match_value_at_normalized(
        &mut self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        debug_assert!(start <= haystack.len() && haystack.is_char_boundary(start));
        self.inner.is_match_window_value(
            haystack.as_bytes(),
            SearchWindow::new(start, haystack.len()),
            limits,
        )
    }

    /// Return the selected match while reusing this session's workspace.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-search contract as
    /// [`PortableTextRegex::find_value`].
    pub fn find_value(
        &mut self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        self.inner.find_value(haystack.as_bytes(), limits)
    }

    /// Return the selected match at or after `start` while reusing this
    /// session's workspace.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableTextRegex::find_at_value`].
    pub fn find_at_value(
        &mut self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        let start = next_text_boundary(haystack, start);
        self.inner.find_at_value(haystack.as_bytes(), start, limits)
    }

    /// Return the selected match inside a scalar-boundary byte range while
    /// reusing this session's workspace.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextSearchError`] under the same range and resource
    /// contract as [`PortableTextRegex::find_window_value`].
    pub fn find_window_value(
        &mut self,
        haystack: &str,
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, PortableTextSearchError> {
        let start = window.start();
        let end = window.end();
        if start > end
            || end > haystack.len()
            || !haystack.is_char_boundary(start)
            || !haystack.is_char_boundary(end)
        {
            return Err(PortableTextSearchError::InvalidUtf8Window {
                start,
                end,
                haystack_len: haystack.len(),
            });
        }
        self.inner
            .find_window_value(haystack.as_bytes(), window, limits)
            .map_err(PortableTextSearchError::Search)
    }

    /// Return only the first detected match end while reusing this
    /// session's workspace.
    ///
    /// Exact-unlimited K0 sessions use their report-free earliest-end route.
    /// Finite calls and other plan families retain the accountingful executor
    /// so their resource and error behavior remains identical to the selected
    /// incumbent path.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-search contract as
    /// [`PortableTextRegex::shortest_match_value`].
    pub fn shortest_match_value(
        &mut self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        if self.shortest_value_eligible && limits == SearchLimits::unlimited() {
            self.inner.shortest_match_value(haystack.as_bytes(), limits)
        } else {
            self.inner
                .shortest_match(haystack.as_bytes(), limits)
                .map(|(end, _accounting)| end)
        }
    }

    /// Return only the first detected match end at or after `start` while
    /// reusing this session's workspace.
    ///
    /// An interior UTF-8 byte offset advances to the next scalar boundary,
    /// while assertions continue to inspect the complete original haystack.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableTextRegex::shortest_match_at_value`].
    pub fn shortest_match_at_value(
        &mut self,
        haystack: &str,
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        let start = next_text_boundary(haystack, start);
        if self.shortest_value_eligible && limits == SearchLimits::unlimited() {
            self.inner
                .shortest_match_at_value(haystack.as_bytes(), start, limits)
        } else {
            self.inner
                .shortest_match_at(haystack.as_bytes(), start, limits)
                .map(|(end, _accounting)| end)
        }
    }

    /// Iterate over non-overlapping matches in one UTF-8 haystack while
    /// reusing this session's existing workspace.
    ///
    /// Repeated empty matches advance by one UTF-8 scalar. Construction is
    /// infallible because setup already succeeded; per-search and
    /// whole-iterator refusals remain yielded
    /// [`PortableFindIterError`] items. Dropping the iterator, including after
    /// an error, releases the mutable borrow for the next haystack.
    #[must_use]
    pub fn find_iter<'s, 'h>(
        &'s mut self,
        haystack: &'h str,
        limits: PortableFindIterRunLimits,
    ) -> PortableTextSessionMatches<'s, 'r, 'h> {
        PortableTextSessionMatches {
            inner: self.inner.find_iter_utf8(haystack, limits),
        }
    }
}

/// Fallible text-match iterator borrowing an existing text search session.
#[derive(Debug)]
pub struct PortableTextSessionMatches<'s, 'r, 'h> {
    inner: PortableSessionMatches<'s, 'r, 'h>,
}

impl PortableTextSessionMatches<'_, '_, '_> {
    /// Exact counters accumulated by this iterator.
    #[must_use]
    pub const fn accounting(&self) -> PortableFindIterAccounting {
        self.inner.accounting()
    }

    /// The reused session's one-time K0 setup facts.
    ///
    /// These facts predate this iterator and are not included in
    /// [`Self::accounting`].
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.inner.workspace_setup_accounting()
    }
}

impl Iterator for PortableTextSessionMatches<'_, '_, '_> {
    type Item = Result<Match, PortableFindIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl core::iter::FusedIterator for PortableTextSessionMatches<'_, '_, '_> {}

/// Fallible iterator over every non-overlapping Rust text match.
///
/// Selected spans use byte offsets into the original UTF-8 haystack. Empty
/// matches progress by scalar value while all searches retain the complete
/// original haystack for look-around context.
#[derive(Debug)]
pub struct PortableTextMatches<'r, 'h> {
    inner: PortableMatches<'r, 'h>,
}

impl PortableTextMatches<'_, '_> {
    /// Exact counters accumulated through the most recent iterator action.
    #[must_use]
    pub const fn accounting(&self) -> PortableFindIterAccounting {
        self.inner.accounting()
    }

    /// One-time K0 workspace setup facts, or `None` for native plans.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.inner.workspace_setup_accounting()
    }
}

impl Iterator for PortableTextMatches<'_, '_> {
    type Item = Result<Match, PortableFindIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl core::iter::FusedIterator for PortableTextMatches<'_, '_> {}

pub(crate) fn next_text_boundary(haystack: &str, start: usize) -> usize {
    if start >= haystack.len() {
        return start;
    }
    let mut boundary = start;
    while !haystack.is_char_boundary(boundary) {
        boundary = boundary.saturating_add(1);
    }
    boundary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_value_facade_preserves_retained_k0_proofs_and_assertions() {
        let regex = PortableTextRegex::new(r"(?m)^a.*MANDATORY.*z$")
            .expect("asserted text K0 regex");
        assert_eq!(regex.build_report().portable.plan, crate::PlanKind::K0);
        assert_eq!(regex.inner.k0_negative_prefilter_needle_bytes(), Some(9));
        assert_eq!(regex.inner.k0_negative_prefilter_needle_count(), 3);

        let absent = format!("{}\n", "λ".repeat(2_048));
        let matched = format!("{absent}a---MANDATORY---z\n");
        for haystack in [&absent, &matched] {
            let expected = regex
                .is_match_accounted(haystack, SearchLimits::unlimited())
                .expect("accounted text existence")
                .0;
            assert_eq!(
                regex
                    .is_match_value(haystack, SearchLimits::unlimited())
                    .expect("value text existence"),
                expected,
            );
            let expected = regex
                .find_accounted(haystack, SearchLimits::unlimited())
                .expect("accounted text span")
                .0;
            assert_eq!(
                regex
                    .find_value(haystack, SearchLimits::unlimited())
                    .expect("value text span"),
                expected,
            );

            let mut session = regex
                .search_session(SearchSessionLimits::unlimited())
                .expect("text search session");
            assert_eq!(
                session
                    .is_match_value_at(haystack, 1, SearchLimits::unlimited())
                    .expect("session existence from interior UTF-8 offset"),
                regex
                    .is_match_value_at(haystack, 1, SearchLimits::unlimited())
                    .expect("facade existence from interior UTF-8 offset"),
            );
            assert_eq!(
                session
                    .find_at_value(haystack, 1, SearchLimits::unlimited())
                    .expect("session span from interior UTF-8 offset"),
                regex
                    .find_at_value(haystack, 1, SearchLimits::unlimited())
                    .expect("facade span from interior UTF-8 offset"),
            );
        }
    }

    #[test]
    fn text_facade_keeps_line_domain_eligible_shapes_on_k0() {
        let regex = PortableTextRegex::new(r"(?m)^Sherlock Holmes$")
            .expect("text-equivalent multiline literal");
        assert_eq!(regex.build_report().portable.plan, crate::PlanKind::K0);
        assert!(regex.build_report().portable.lowering.is_some());
        let (matched, accounting) = regex
            .find_accounted("prefix\nSherlock Holmes\nsuffix", SearchLimits::unlimited())
            .expect("text K0 search");
        assert_eq!(matched.map(|value| (value.start(), value.end())), Some((7, 22)));
        assert!(matches!(accounting, SearchAccounting::K0(_)));
        let session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("text K0 session");
        assert_eq!(session.runtime_implementation_id(), "k0");
        assert!(session.workspace_setup_accounting().is_some());
        let fixed = regex
            .fixed_search_session(SearchSessionLimits::unlimited())
            .expect("fixed text K0 session");
        assert_eq!(fixed.runtime_implementation_id(), "k0");
        assert!(fixed.workspace_setup_accounting().is_some());
    }

    #[test]
    fn text_facade_exposes_ordinary_finite_and_accounted_search_surfaces() {
        let regex = PortableTextRegex::new(r"(?m)^Sherlock Holmes$")
            .expect("text API fixture lowers through K0");
        let haystack = "prefix\nSherlock Holmes\nsuffix";
        let expected = Some((7, 22));
        let refusing = SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        };

        assert!(regex.find_with_limits(haystack, refusing).is_err());
        assert!(regex.is_match_with_limits(haystack, refusing).is_err());
        assert_eq!(
            regex
                .find(haystack)
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert!(regex.is_match(haystack));

        let (accounted, accounting) = regex
            .find_accounted(haystack, SearchLimits::unlimited())
            .expect("accounted text search succeeds");
        assert_eq!(
            accounted.map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(accounting.plan(), crate::PlanKind::K0);
        assert_eq!(
            regex
                .find_value(haystack, SearchLimits::default())
                .expect("finite compatibility alias succeeds")
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
    }

    #[test]
    fn impossible_alternative_elision_is_ordered_and_dead_on_both_profiles() {
        let text_dead = Hir::concat(vec![Hir::fail(), Hir::literal("text".as_bytes())]);
        let bytes_dead = Hir::concat(vec![Hir::fail(), Hir::literal("bytes".as_bytes())]);
        let live = Hir::literal("B".as_bytes());
        let text = Hir::alternation(vec![text_dead.clone(), live.clone()]);
        let bytes = Hir::alternation(vec![bytes_dead.clone(), live]);
        assert_eq!(
            ordered_top_level_alternatives_equal_after_impossible_elision(
                &text,
                &bytes,
                0,
                u64::MAX,
            )
            .unwrap(),
            Some((1, 1))
        );
        assert_eq!(
            ordered_top_level_alternatives_equal_after_impossible_elision(
                &text,
                &text,
                0,
                u64::MAX,
            )
            .unwrap(),
            Some((1, 1))
        );

        let different_live =
            Hir::alternation(vec![bytes_dead.clone(), Hir::literal("C".as_bytes())]);
        assert_eq!(
            ordered_top_level_alternatives_equal_after_impossible_elision(
                &text,
                &different_live,
                0,
                u64::MAX,
            )
            .unwrap(),
            None
        );
        let live_replacement = Hir::alternation(vec![Hir::empty(), Hir::literal("B".as_bytes())]);
        assert_eq!(
            ordered_top_level_alternatives_equal_after_impossible_elision(
                &text,
                &live_replacement,
                0,
                u64::MAX,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            ordered_top_level_alternatives_equal_after_impossible_elision(
                &text_dead,
                &bytes_dead,
                0,
                u64::MAX,
            )
            .unwrap(),
            None
        );

        let text_nullable = Hir::alternation(vec![text_dead.clone(), Hir::empty()]);
        let bytes_nullable = Hir::alternation(vec![bytes_dead.clone(), Hir::empty()]);
        assert_eq!(
            ordered_top_level_alternatives_equal_after_impossible_elision(
                &text_nullable,
                &bytes_nullable,
                0,
                u64::MAX,
            )
            .unwrap(),
            None
        );

        let text_live = Hir::concat(vec![
            Hir::alternation(vec![Hir::fail(), Hir::literal("X".as_bytes())]),
            Hir::literal("A".as_bytes()),
        ]);
        let bytes_live = Hir::concat(vec![
            Hir::alternation(vec![Hir::fail(), Hir::literal("Y".as_bytes())]),
            Hir::literal("A".as_bytes()),
        ]);
        let text = Hir::alternation(vec![text_live, Hir::literal("B".as_bytes())]);
        let bytes = Hir::alternation(vec![bytes_live, Hir::literal("B".as_bytes())]);
        assert_eq!(
            ordered_top_level_alternatives_equal_after_impossible_elision(
                &text,
                &bytes,
                0,
                u64::MAX,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn impossible_subtree_proof_uses_exact_boolean_language_rules() {
        fn parsed(pattern: &str) -> Hir {
            regex_syntax::Parser::new()
                .parse(pattern)
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"))
        }

        for pattern in [
            r".*[a&&b]A",
            r"([a&&b])A",
            r"[a&&b]+A",
            r"(?:[a&&b]|[^\s\S])A",
        ] {
            let mut work = 0;
            assert!(
                provably_impossible(&parsed(pattern), &mut work, u64::MAX).unwrap(),
                "pattern={pattern:?}"
            );
        }
        for pattern in [
            r"(?:[a&&b]|X)A",
            r"[a&&b]*A",
            r"[a&&b]?A",
            r"[a&&b]{0,1}A",
            r"^$A",
        ] {
            let mut work = 0;
            assert!(
                !provably_impossible(&parsed(pattern), &mut work, u64::MAX).unwrap(),
                "pattern={pattern:?}"
            );
        }

        let mut work = 0;
        assert!(matches!(
            provably_impossible(&parsed(r".*[a&&b]A"), &mut work, 0),
            Err(BuildError::PlannerWorkLimit { .. })
        ));
    }

    #[test]
    fn finite_unicode_languages_match_pinned_rust_text() {
        let patterns = ["雪", "(?:é|東京|a)", "[éß]", "(?i:a)", ""];
        let haystacks = ["", "z雪z", "x東京é", "ßA", "🦀aé東京"];
        for pattern in patterns {
            let fre = PortableTextRegex::new(pattern)
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            assert!(matches!(fre.profile(), CompatibilityProfile::RustText(_)));
            assert!(matches!(
                fre.build_report().proof,
                PortableTextProof::FiniteLanguage { words, .. } if words > 0
            ));
            let upstream = regex::Regex::new(pattern).expect("pinned Rust text accepts fixture");
            for haystack in haystacks {
                let expected = upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = fre.find(haystack);
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
                let exists = fre.is_match(haystack);
                let (end, _) = fre
                    .selected_end(haystack, SearchLimits::unlimited())
                    .expect("FRE text end executes");
                assert_eq!(exists, expected.is_some());
                assert_eq!(end, expected.map(|(_, end)| end));
            }
        }
    }

    #[test]
    fn utf8_safe_repetition_and_assertions_match_pinned_rust_text() {
        let patterns = [
            "a+",
            "(?:é|東京)+",
            ".",
            "[^x]+",
            "^a+",
            r"\b\w+\b",
            r"^",
            r"(?m:$)",
            r"\b",
            r"(?-u:\b)",
            r"(?-u:\b{start})",
            r"(?-u:\b{end})",
            "a*",
            ".*",
            "a{2,4}",
        ];
        let haystacks = ["", "é", "東京é", "xxaaaz", "🦀 rust 東京", "aaaaa"];
        for pattern in patterns {
            let fre = PortableTextRegex::new(pattern)
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            assert!(matches!(
                fre.build_report().proof,
                PortableTextProof::IdenticalUtf8Hir { .. }
            ));
            let upstream = regex::Regex::new(pattern).expect("pinned Rust text accepts fixture");
            for haystack in haystacks {
                let expected = upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = fre.find(haystack);
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn normalized_nullable_atom_repetitions_match_complete_text_iteration() {
        fn spans(regex: &PortableTextRegex, haystack: &str) -> Vec<(usize, usize)> {
            let mut spans = Vec::new();
            let mut start = 0;
            let mut last_match_end = None;
            loop {
                let (matched, _) = regex
                    .find_window(
                        haystack,
                        SearchWindow::new(start, haystack.len()),
                        SearchLimits::unlimited(),
                    )
                    .expect("normalized nullable text search executes");
                let Some(matched) = matched else {
                    break;
                };
                if matched.is_empty() && last_match_end == Some(matched.end()) {
                    let Some(character) = haystack[start..].chars().next() else {
                        break;
                    };
                    start = start.saturating_add(character.len_utf8());
                    continue;
                }
                spans.push((matched.start(), matched.end()));
                start = matched.end();
                last_match_end = Some(matched.end());
            }
            spans
        }

        let patterns = [
            "(a*)*",
            "(a*)+",
            "([ab]*)*",
            "([^b]*)*",
            "X(.?){0,}Y",
            "X(.?){8,}Y",
            "(?:(?:.?)*?)=",
            "(?:(?:.?)*)=",
        ];
        let haystacks = [
            "",
            "a",
            "aaaaaax",
            "ababab",
            "aaaabcde",
            "X1234567Y",
            "a=b=c",
            "🦀=東京=",
        ];
        for pattern in patterns {
            let fre = PortableTextRegex::new(pattern)
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            let lowering = fre
                .build_report()
                .portable
                .lowering
                .expect("normalized nullable shape selects K0");
            assert_eq!(lowering.normalized_nullable_repetitions(), 1);
            let upstream = regex::Regex::new(pattern).expect("pinned Rust text accepts fixture");
            for haystack in haystacks {
                let expected = upstream
                    .find_iter(haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect::<Vec<_>>();
                assert_eq!(
                    spans(&fre, haystack),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn utf8_safe_repetition_and_guarded_shapes_are_distinguished() {
        let repeated = PortableTextRegex::new("a+").expect("positive UTF-8 repetition is proved");
        assert_eq!(
            repeated.build_report().proof,
            PortableTextProof::IdenticalUtf8Hir {
                minimum_match_bytes: 1,
                has_look_assertions: false,
                empty_match_utf8_boundary_safe: true,
            }
        );
        let guarded = PortableTextRegex::new("(?-u:\\B)")
            .expect("ASCII negation is protected by a UTF-8 start guard");
        assert!(matches!(
            guarded.build_report().proof,
            PortableTextProof::Utf8StartBoundaryGuardedHir {
                minimum_match_bytes: 0,
                has_look_assertions: true,
            }
        ));
        assert!(
            guarded
                .build_report()
                .portable
                .lowering
                .expect("guarded text shape selects K0")
                .utf8_start_guarded()
        );
        assert!(matches!(
            PortableTextBuilder::new("(?-u:\\B)")
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build(),
            Err(PortableTextBuildError::Utf8StartGuardPlanSelection {
                selection: PlanSelection::ForceRequiredLiteral,
            })
        ));
        assert!(matches!(
            PortableTextRegex::new("(?-u:\\xFF)")
                .expect_err("invalid UTF-8 text language is rejected"),
            PortableTextBuildError::TextSyntax(_)
        ));
    }

    #[test]
    fn forced_k0_text_root_scanner_mismatches_iterate_to_completion() {
        for (pattern, haystack) in [
            ("a+", "aa--a--aaaa"),
            ("[a-z]{2}", "ab--cd--ef"),
            ("[0-9]+?", "12--3--456"),
        ] {
            let fre = PortableTextBuilder::new(pattern)
                .plan_selection(PlanSelection::ForceK0)
                .build()
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"));
            assert_eq!(fre.build_report().portable.plan, crate::PlanKind::K0);
            let upstream = regex::Regex::new(pattern).unwrap();
            let expected: Vec<_> = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            let actual: Result<Vec<_>, _> = fre
                .find_iter(haystack, PortableFindIterLimits::unlimited())
                .unwrap()
                .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
                .collect();
            assert_eq!(actual.unwrap(), expected, "pattern={pattern}");
        }
    }

    #[test]
    fn utf8_start_guarded_ascii_looks_match_pinned_text_exhaustively() {
        fn spans(regex: &PortableTextRegex, haystack: &str) -> Vec<(usize, usize)> {
            let mut spans = Vec::new();
            let mut start = 0_usize;
            let mut last_match_end = None;
            loop {
                let (matched, _) = regex
                    .find_window(
                        haystack,
                        SearchWindow::new(start, haystack.len()),
                        SearchLimits::unlimited(),
                    )
                    .expect("guarded text iteration search");
                let Some(matched) = matched else {
                    break;
                };
                assert!(haystack.is_char_boundary(matched.start()));
                assert!(haystack.is_char_boundary(matched.end()));
                if matched.is_empty() && last_match_end == Some(matched.end()) {
                    let Some(character) = haystack[start..].chars().next() else {
                        break;
                    };
                    start = start.saturating_add(character.len_utf8());
                    continue;
                }
                spans.push((matched.start(), matched.end()));
                start = matched.end();
                last_match_end = Some(matched.end());
            }
            spans
        }

        let alphabet = ["a", " ", "_", "!", "é", "𝛃", "𐆀"];
        let mut haystacks = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..=3 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for scalar in alphabet {
                    let mut value = prefix.clone();
                    value.push_str(scalar);
                    next.push(value);
                }
            }
            haystacks.extend(next.iter().cloned());
            frontier = next;
        }

        for pattern in [r"(?-u:\b{start-half})", r"(?-u:\b{end-half})", r"(?-u:\B)"] {
            let fre = PortableTextBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"));
            assert!(matches!(
                fre.build_report().proof,
                PortableTextProof::Utf8StartBoundaryGuardedHir { .. }
            ));
            assert_eq!(fre.build_report().portable.plan, crate::PlanKind::K0);
            assert!(
                fre.build_report()
                    .portable
                    .lowering
                    .expect("guarded text shape selects K0")
                    .utf8_start_guarded()
            );
            let mut upstream = regex::RegexBuilder::new(pattern);
            upstream.unicode(false);
            let upstream = upstream
                .build()
                .unwrap_or_else(|error| panic!("pinned pattern={pattern:?}: {error}"));

            for haystack in &haystacks {
                let expected = upstream
                    .find_iter(haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect::<Vec<_>>();
                assert_eq!(
                    spans(&fre, haystack),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}"
                );
                for (start, _) in haystack
                    .char_indices()
                    .chain(core::iter::once((haystack.len(), ' ')))
                {
                    let expected = upstream
                        .find_at(haystack, start)
                        .map(|matched| (matched.start(), matched.end()));
                    let (actual, _) = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .expect("guarded contextual search");
                    assert_eq!(
                        actual.map(|matched| (matched.start(), matched.end())),
                        expected,
                        "pattern={pattern:?}, haystack={haystack:?}, start={start}"
                    );
                }
            }
        }
    }

    #[test]
    fn zero_count_capture_does_not_break_text_construction() {
        let pattern = "(a){0}(a)";
        let fre = PortableTextRegex::new(pattern)
            .unwrap_or_else(|error| panic!("zero-count capture must compile: {error:?}"));
        assert_eq!(fre.inner.captures_len(), 3);
        assert_eq!(fre.inner.static_captures_len(), Some(2));
        assert_eq!(
            fre.inner.capture_names().collect::<Vec<_>>(),
            vec![None, None, None]
        );
        let upstream = regex::Regex::new(pattern).expect("pinned Rust text accepts fixture");
        assert_eq!(upstream.captures_len(), 3);
        assert_eq!(upstream.static_captures_len(), Some(2));
        let haystack = "a";
        let expected = upstream
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
        let actual = fre.find(haystack);
        assert_eq!(
            actual.map(|matched| (matched.start(), matched.end())),
            expected
        );
    }

    #[test]
    fn contextual_text_windows_require_scalar_boundaries_and_keep_anchor_context() {
        let haystack = "éa";
        let regex = PortableTextRegex::new(r"^a|a$").unwrap();
        let (matched, _) = regex
            .find_window(
                haystack,
                SearchWindow::new("é".len(), haystack.len()),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((2, 3))
        );

        for window in [
            SearchWindow::new(1, haystack.len()),
            SearchWindow::new(0, 1),
            SearchWindow::new(3, 2),
            SearchWindow::new(0, 4),
        ] {
            assert!(matches!(
                regex.find_window(haystack, window, SearchLimits::unlimited()),
                Err(PortableTextSearchError::InvalidUtf8Window { .. })
            ));
        }
    }
}
