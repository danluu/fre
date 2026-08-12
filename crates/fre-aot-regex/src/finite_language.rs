//! Authenticated target-neutral execution IR for complete finite languages.
//!
//! This is deliberately transient compiler state. The stable program keeps
//! the universal automaton as its semantic authority; source compilation may
//! additionally attach this sidecar when the current HIR-fact implementation
//! proves the complete, assertion-free, non-nullable byte language.

use fre_lower::{
    FactLimits, FactOperation, FactOptionalProofs, FactOutput, HirFacts, analyze_facts,
};
use fre_syntax::RustParsed;
use sha2::{Digest, Sha256};

use crate::{
    MatchResult, OutputContract, SearchWindow,
    mandatory_teddy::{self, MandatoryTeddyPortfolio},
};

/// Target-neutral construction ceiling. This is intentionally much broader
/// than the historical fixed-width, at-most-64-literal native shortcut while
/// still bounding peak compiler storage.
const MAX_ORDERED_FINITE_STATES: usize = 1 << 20;
const MAX_ORDERED_FINITE_TRANSITION_CELLS: usize = 1 << 24;
const MAX_ORDERED_FINITE_FAILURE_STEPS: u64 = 64_000_000;
/// Largest exact-literal set admitted to the packed `Exists` portfolio.
/// Wider exact languages retain the existing Aho-Corasick candidate. This is
/// a structural compiler bound, not a source-pattern or benchmark identity.
const MAX_NATIVE_FINITE_TEDDY_LITERALS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OrderedFiniteBuildLimits {
    max_states: usize,
    max_transition_cells: usize,
    max_failure_steps: u64,
}

impl Default for OrderedFiniteBuildLimits {
    fn default() -> Self {
        Self {
            max_states: MAX_ORDERED_FINITE_STATES,
            max_transition_cells: MAX_ORDERED_FINITE_TRANSITION_CELLS,
            max_failure_steps: MAX_ORDERED_FINITE_FAILURE_STEPS,
        }
    }
}

const fn fact_operation(output: OutputContract) -> FactOperation {
    let fact_output = match output {
        OutputContract::Exists => FactOutput::Exists,
        OutputContract::SelectedEnd | OutputContract::Span => FactOutput::SpanSequence,
    };
    FactOperation::capture_erased(fact_output)
        .with_optional_proofs(FactOptionalProofs::FiniteLanguage)
}

/// Owned proof payload passed across the lowering/build boundary. Its fields
/// remain private so only an authenticated current [`HirFacts`] report can
/// construct one in production.
#[derive(Clone, Debug)]
pub(crate) struct NativeFiniteLanguageCandidate {
    operation: FactOperation,
    strings: Vec<Vec<u8>>,
    total_bytes: usize,
}

impl NativeFiniteLanguageCandidate {
    /// Analyze one canonical parse for the exact output requested by the AOT
    /// entry. Optional proof failure is an optimization decline, never a
    /// compilation failure.
    pub(crate) fn analyze(parsed: &RustParsed, output: OutputContract) -> Option<Self> {
        let operation = fact_operation(output);
        let facts = analyze_facts(parsed, operation, FactLimits::default()).ok()?;
        Self::from_facts(&facts, operation)
    }

    fn from_facts(facts: &HirFacts, operation: FactOperation) -> Option<Self> {
        if !facts.identity().authenticates_current() || facts.operation() != operation {
            return None;
        }
        if !facts
            .assertions()
            .possible()
            .as_proven()
            .is_some_and(Vec::is_empty)
        {
            return None;
        }
        let language = facts.finite_language().as_proven()?;
        if language.is_empty() || language.strings().any(<[u8]>::is_empty) {
            return None;
        }

        let mut strings = Vec::new();
        strings.try_reserve_exact(language.len()).ok()?;
        for string in language.strings() {
            let mut owned = Vec::new();
            owned.try_reserve_exact(string.len()).ok()?;
            owned.extend_from_slice(string);
            strings.push(owned);
        }
        Some(Self {
            operation,
            strings,
            total_bytes: language.total_bytes(),
        })
    }
}

/// One output inherited by an Aho-Corasick state. Width zero is the private
/// no-output sentinel because nullable languages are excluded at admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OrderedFiniteOutput {
    width: u32,
    ordinal: u32,
}

impl OrderedFiniteOutput {
    const NONE: Self = Self {
        width: 0,
        ordinal: u32::MAX,
    };

    const fn is_present(self) -> bool {
        self.width != 0
    }

    pub(crate) const fn width(self) -> u32 {
        self.width
    }

    pub(crate) const fn ordinal(self) -> u32 {
        self.ordinal
    }

    fn dominant(self, other: Self) -> Self {
        if !self.is_present()
            || (other.is_present()
                && (other.width > self.width
                    || (other.width == self.width && other.ordinal < self.ordinal)))
        {
            other
        } else {
            self
        }
    }
}

/// Authenticated immutable input to target-specific finite-language lowering.
/// Every slice is owned by the transient source-derived sidecar and all
/// dimensions have been revalidated against the bound artifact before this
/// view is returned.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeFiniteLanguageView<'a> {
    pub(crate) output: OutputContract,
    pub(crate) byte_classes: &'a [u8; 256],
    pub(crate) class_representatives: &'a [u8],
    pub(crate) transitions: &'a [u32],
    pub(crate) outputs: &'a [OrderedFiniteOutput],
    pub(crate) maximum_width: u32,
    pub(crate) root_members: [u64; 4],
    pub(crate) source_count: u32,
    pub(crate) total_source_bytes: usize,
}

impl NativeFiniteLanguageView<'_> {
    pub(crate) fn state_count(self) -> usize {
        self.outputs.len()
    }

    pub(crate) fn class_count(self) -> usize {
        self.class_representatives.len()
    }

    pub(crate) fn transition_count(self) -> usize {
        self.transitions.len()
    }
}

/// Target-neutral exact-finite `Exists` strategy. This is a planning receipt,
/// not a selection over the already compiled DFA: target finalization must
/// still compare its concrete lowering against the incumbent native machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeFiniteExistsChoiceKind {
    /// One-byte literals represented by exact 256-bit membership. Target
    /// lowering may select memchr1/2/3 or a wider vector byte-set scan.
    ByteSet { membership: [u64; 4] },
    /// One non-empty literal. Target lowering may use a two-way/vector memmem
    /// search without entering the regex automaton.
    SingleLiteral,
    /// A bounded packed prefix portfolio. Every fingerprint hit remains a
    /// candidate until exact source-order literal verification succeeds.
    Teddy(MandatoryTeddyPortfolio),
}

/// Exact source-order confirmation result for one candidate base.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeFiniteExistsMatch {
    width: u32,
    ordinal: u32,
}

impl NativeFiniteExistsMatch {
    pub(crate) const fn width(self) -> u32 {
        self.width
    }

    pub(crate) const fn ordinal(self) -> u32 {
        self.ordinal
    }
}

/// Re-authenticated exact literals and their target-neutral Choice receipt.
/// The stable semantic artifact deliberately does not serialize this view.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeFiniteExistsChoiceView<'a> {
    literals: &'a [Vec<u8>],
    kind: NativeFiniteExistsChoiceKind,
    minimum_width: u32,
    maximum_width: u32,
    total_source_bytes: usize,
}

impl<'a> NativeFiniteExistsChoiceView<'a> {
    pub(crate) const fn kind(self) -> NativeFiniteExistsChoiceKind {
        self.kind
    }

    #[allow(
        dead_code,
        reason = "the next target-final Choice lowering consumes the exact literals"
    )]
    pub(crate) const fn literals(self) -> &'a [Vec<u8>] {
        self.literals
    }

    pub(crate) const fn minimum_width(self) -> u32 {
        self.minimum_width
    }

    pub(crate) const fn maximum_width(self) -> u32 {
        self.maximum_width
    }

    pub(crate) const fn total_source_bytes(self) -> usize {
        self.total_source_bytes
    }

    /// Confirm one fingerprint/memmem candidate in exact source order. A
    /// future bucket-indexed emitter may skip impossible ordinals, but it must
    /// preserve this first-success result among every surviving literal.
    pub(crate) fn verify_at(
        self,
        haystack: &[u8],
        candidate: usize,
        window_end: usize,
    ) -> Option<NativeFiniteExistsMatch> {
        let remaining = haystack.get(candidate..window_end)?;
        self.literals
            .iter()
            .enumerate()
            .find_map(|(ordinal, literal)| {
                remaining
                    .starts_with(literal)
                    .then_some(NativeFiniteExistsMatch {
                        width: u32::try_from(literal.len()).ok()?,
                        ordinal: u32::try_from(ordinal).ok()?,
                    })
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeFiniteExistsChoice {
    kind: NativeFiniteExistsChoiceKind,
    minimum_width: u32,
    maximum_width: u32,
    total_source_bytes: usize,
    literal_digest: [u8; 32],
}

impl NativeFiniteExistsChoice {
    fn derive(
        literals: &[Vec<u8>],
        expected_total_source_bytes: usize,
        expected_maximum_width: u32,
    ) -> Option<Self> {
        if literals.is_empty() || literals.iter().any(Vec::is_empty) {
            return None;
        }
        let total_source_bytes = literals
            .iter()
            .try_fold(0_usize, |total, literal| total.checked_add(literal.len()))?;
        let minimum_width = u32::try_from(literals.iter().map(Vec::len).min()?).ok()?;
        let maximum_width = u32::try_from(literals.iter().map(Vec::len).max()?).ok()?;
        if total_source_bytes != expected_total_source_bytes
            || maximum_width != expected_maximum_width
        {
            return None;
        }
        let kind = if maximum_width == 1 {
            let mut membership = [0_u64; 4];
            for literal in literals {
                let byte = usize::from(*literal.first()?);
                membership[byte / 64] |= 1_u64 << (byte % 64);
            }
            NativeFiniteExistsChoiceKind::ByteSet { membership }
        } else if literals.len() == 1 {
            NativeFiniteExistsChoiceKind::SingleLiteral
        } else if literals.len() <= MAX_NATIVE_FINITE_TEDDY_LITERALS
            && minimum_width >= 3
            && let Some(portfolio) = mandatory_teddy::derive_exact_prefixes(
                literals,
                usize::try_from(minimum_width)
                    .ok()?
                    .min(mandatory_teddy::MAX_MANDATORY_TEDDY_COLUMNS),
            )
        {
            NativeFiniteExistsChoiceKind::Teddy(portfolio)
        } else {
            // The enclosing ordered automaton is already the authoritative
            // Aho-Corasick strategy. With no independently selectable Choice
            // lowering, retaining a second full literal corpus would only
            // increase compiler memory.
            return None;
        };
        let mut digest = Sha256::new();
        digest.update(u64::try_from(literals.len()).ok()?.to_le_bytes());
        for literal in literals {
            digest.update(u64::try_from(literal.len()).ok()?.to_le_bytes());
            digest.update(literal);
        }
        let literal_digest: [u8; 32] = digest.finalize().into();
        Some(Self {
            kind,
            minimum_width,
            maximum_width,
            total_source_bytes,
            literal_digest,
        })
    }

    fn native_view<'a>(
        &self,
        literals: &'a [Vec<u8>],
    ) -> Option<NativeFiniteExistsChoiceView<'a>> {
        (Self::derive(literals, self.total_source_bytes, self.maximum_width)?.eq(self)).then_some(
            NativeFiniteExistsChoiceView {
                literals,
                kind: self.kind,
                minimum_width: self.minimum_width,
                maximum_width: self.maximum_width,
                total_source_bytes: self.total_source_bytes,
            },
        )
    }
}

#[derive(Debug)]
struct BuildState {
    edges: Vec<(u8, u32)>,
    failure: u32,
    output: OrderedFiniteOutput,
}

impl BuildState {
    const fn new() -> Self {
        Self {
            edges: Vec::new(),
            failure: 0,
            output: OrderedFiniteOutput::NONE,
        }
    }
}

fn edge_target(edges: &[(u8, u32)], byte: u8) -> Option<u32> {
    edges
        .binary_search_by_key(&byte, |&(edge_byte, _)| edge_byte)
        .ok()
        .map(|index| edges[index].1)
}

/// Complete deterministic Aho-Corasick transition graph. Every byte used by
/// a source string has an exact class; all bytes absent from the language are
/// equivalent and share one optional class.
#[derive(Clone, Debug)]
struct OrderedFiniteAutomaton {
    byte_classes: [u8; 256],
    class_representatives: Box<[u8]>,
    transitions: Box<[u32]>,
    outputs: Box<[OrderedFiniteOutput]>,
    maximum_width: u32,
    root_members: [u64; 4],
}

impl OrderedFiniteAutomaton {
    fn build(
        strings: &[Vec<u8>],
        total_bytes: usize,
        limits: OrderedFiniteBuildLimits,
    ) -> Option<Self> {
        if strings.is_empty()
            || strings.iter().any(Vec::is_empty)
            || strings.len() > usize::try_from(u32::MAX).ok()?
        {
            return None;
        }
        let measured_total = strings
            .iter()
            .try_fold(0_usize, |sum, string| sum.checked_add(string.len()))?;
        if measured_total != total_bytes || limits.max_states == 0 {
            return None;
        }

        let maximum_width = strings.iter().map(Vec::len).max()?;
        let maximum_width = u32::try_from(maximum_width).ok()?;
        let reserve_states = total_bytes
            .checked_add(1)?
            .min(limits.max_states);
        let mut states = Vec::new();
        states.try_reserve_exact(reserve_states).ok()?;
        states.push(BuildState::new());
        let mut used_bytes = [false; 256];

        for (ordinal, string) in strings.iter().enumerate() {
            let ordinal = u32::try_from(ordinal).ok()?;
            let width = u32::try_from(string.len()).ok()?;
            let mut state = 0_usize;
            for &byte in string {
                used_bytes[usize::from(byte)] = true;
                let edge = states[state]
                    .edges
                    .binary_search_by_key(&byte, |&(edge_byte, _)| edge_byte);
                state = match edge {
                    Ok(index) => usize::try_from(states[state].edges[index].1).ok()?,
                    Err(index) => {
                        if states.len() >= limits.max_states
                            || states.len() >= usize::try_from(u32::MAX).ok()?
                        {
                            return None;
                        }
                        states[state].edges.try_reserve(1).ok()?;
                        states.try_reserve(1).ok()?;
                        let next = u32::try_from(states.len()).ok()?;
                        states.push(BuildState::new());
                        states[state].edges.insert(index, (byte, next));
                        usize::try_from(next).ok()?
                    }
                };
            }
            let terminal = OrderedFiniteOutput { width, ordinal };
            states[state].output = states[state].output.dominant(terminal);
        }

        let mut breadth_first = Vec::new();
        breadth_first.try_reserve_exact(states.len()).ok()?;
        breadth_first.push(0_u32);
        for edge in &states[0].edges {
            breadth_first.push(edge.1);
        }
        let mut cursor = 1_usize;
        let mut failure_steps = 0_u64;
        while cursor < breadth_first.len() {
            let state = usize::try_from(breadth_first[cursor]).ok()?;
            cursor = cursor.checked_add(1)?;
            let edge_count = states[state].edges.len();
            for edge_index in 0..edge_count {
                let (byte, next_token) = states[state].edges[edge_index];
                let next = usize::try_from(next_token).ok()?;
                let mut fallback = usize::try_from(states[state].failure).ok()?;
                let failure = loop {
                    failure_steps = failure_steps.checked_add(1)?;
                    if failure_steps > limits.max_failure_steps {
                        return None;
                    }
                    if let Some(target) = edge_target(&states[fallback].edges, byte) {
                        break target;
                    }
                    if fallback == 0 {
                        break 0;
                    }
                    fallback = usize::try_from(states[fallback].failure).ok()?;
                };
                states[next].failure = failure;
                let inherited = states[usize::try_from(failure).ok()?].output;
                states[next].output = states[next].output.dominant(inherited);
                breadth_first.push(next_token);
            }
        }
        if breadth_first.len() != states.len() {
            return None;
        }

        let used_count = used_bytes.iter().filter(|&&used| used).count();
        let class_count = used_count.checked_add(usize::from(used_count < 256))?;
        if class_count == 0 || class_count > 256 {
            return None;
        }
        let mut byte_classes = [0_u8; 256];
        let mut class_representatives = Vec::new();
        class_representatives
            .try_reserve_exact(class_count)
            .ok()?;
        for byte in 0_u16..=u16::from(u8::MAX) {
            let index = usize::from(byte);
            if used_bytes[index] {
                byte_classes[index] = u8::try_from(class_representatives.len()).ok()?;
                class_representatives.push(u8::try_from(byte).ok()?);
            }
        }
        if used_count < 256 {
            let other_class = u8::try_from(class_representatives.len()).ok()?;
            let mut representative = None;
            for byte in 0_u16..=u16::from(u8::MAX) {
                let index = usize::from(byte);
                if !used_bytes[index] {
                    byte_classes[index] = other_class;
                    representative.get_or_insert(u8::try_from(byte).ok()?);
                }
            }
            class_representatives.push(representative?);
        }

        let transition_cells = states.len().checked_mul(class_count)?;
        if transition_cells > limits.max_transition_cells {
            return None;
        }
        let mut transitions = Vec::new();
        transitions.try_reserve_exact(transition_cells).ok()?;
        transitions.resize(transition_cells, 0_u32);
        for &state_token in &breadth_first {
            let state = usize::try_from(state_token).ok()?;
            for (class, &representative) in class_representatives.iter().enumerate() {
                let target = edge_target(&states[state].edges, representative).unwrap_or_else(|| {
                    if state == 0 {
                        0
                    } else {
                        let failure = usize::try_from(states[state].failure)
                            .expect("validated failure state fits usize");
                        transitions[failure * class_count + class]
                    }
                });
                transitions[state * class_count + class] = target;
            }
        }

        let mut outputs = Vec::new();
        outputs.try_reserve_exact(states.len()).ok()?;
        outputs.extend(states.iter().map(|state| state.output));
        let mut root_members = [0_u64; 4];
        for &(byte, _) in &states[0].edges {
            let index = usize::from(byte);
            root_members[index / 64] |= 1_u64 << (index % 64);
        }
        Some(Self {
            byte_classes,
            class_representatives: class_representatives.into_boxed_slice(),
            transitions: transitions.into_boxed_slice(),
            outputs: outputs.into_boxed_slice(),
            maximum_width,
            root_members,
        })
    }

    fn next_state(&self, state: u32, byte: u8) -> u32 {
        let class_count = self.class_representatives.len();
        let state = usize::try_from(state).expect("constructed state token fits usize");
        let class = usize::from(self.byte_classes[usize::from(byte)]);
        self.transitions[state * class_count + class]
    }

    fn output(&self, state: u32) -> OrderedFiniteOutput {
        self.outputs[usize::try_from(state).expect("constructed state token fits usize")]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingMatch {
    start: usize,
    end: usize,
    ordinal: u32,
}

/// Artifact-bound target-neutral finite-language program. Stable
/// serialization deliberately omits this value; a deserializer must derive a
/// fresh authenticated sidecar from source facts instead of trusting bytes
/// that predate this optimizer.
#[derive(Clone, Debug)]
pub(crate) struct NativeFiniteLanguageProgram {
    artifact_identity: [u8; 32],
    output: OutputContract,
    source_count: u32,
    total_source_bytes: usize,
    automaton: OrderedFiniteAutomaton,
    /// Exact source-order literals are retained only for a competing `Exists`
    /// Choice candidate, where a literal hit is itself a complete semantic
    /// answer. Endpoint and AC-only contracts use the ordered automaton.
    exists_literals: Vec<Vec<u8>>,
    exists_choice: Option<NativeFiniteExistsChoice>,
}

impl NativeFiniteLanguageProgram {
    pub(crate) fn bind(
        candidate: NativeFiniteLanguageCandidate,
        artifact_identity: [u8; 32],
        output: OutputContract,
    ) -> Option<Self> {
        Self::bind_with_limits(
            candidate,
            artifact_identity,
            output,
            OrderedFiniteBuildLimits::default(),
        )
    }

    fn bind_with_limits(
        candidate: NativeFiniteLanguageCandidate,
        artifact_identity: [u8; 32],
        output: OutputContract,
        limits: OrderedFiniteBuildLimits,
    ) -> Option<Self> {
        if artifact_identity == [0; 32] || candidate.operation != fact_operation(output) {
            return None;
        }
        let source_count = u32::try_from(candidate.strings.len()).ok()?;
        let automaton = OrderedFiniteAutomaton::build(
            &candidate.strings,
            candidate.total_bytes,
            limits,
        )?;
        let (exists_literals, exists_choice) = if output == OutputContract::Exists {
            let choice = NativeFiniteExistsChoice::derive(
                &candidate.strings,
                candidate.total_bytes,
                automaton.maximum_width,
            );
            if choice.is_some() {
                (candidate.strings, choice)
            } else {
                // The ordered automaton already owns the AC strategy. Avoid
                // duplicating its complete source language when no competing
                // exact-finite Choice candidate survived planning.
                (Vec::new(), None)
            }
        } else {
            (Vec::new(), None)
        };
        Some(Self {
            artifact_identity,
            output,
            source_count,
            total_source_bytes: candidate.total_bytes,
            automaton,
            exists_literals,
            exists_choice,
        })
    }

    pub(crate) fn authenticates(
        &self,
        artifact_identity: [u8; 32],
        output: OutputContract,
    ) -> bool {
        self.artifact_identity == artifact_identity && self.output == output
    }

    /// Re-authenticate the sidecar and expose only a dimensionally complete
    /// graph. This is the sole transaction boundary used by native lowering;
    /// malformed or stale optimizer state declines without entering a target
    /// backend.
    pub(crate) fn native_view(
        &self,
        artifact_identity: [u8; 32],
        output: OutputContract,
    ) -> Option<NativeFiniteLanguageView<'_>> {
        if !self.authenticates(artifact_identity, output)
            || self.source_count == 0
            || self.automaton.maximum_width == 0
        {
            return None;
        }
        let state_count = self.automaton.outputs.len();
        let class_count = self.automaton.class_representatives.len();
        if state_count == 0
            || class_count == 0
            || class_count > 256
            || self.automaton.transitions.len() != state_count.checked_mul(class_count)?
            || self
                .automaton
                .byte_classes
                .iter()
                .any(|&class| usize::from(class) >= class_count)
            || self
                .automaton
                .transitions
                .iter()
                .any(|&state| usize::try_from(state).ok().is_none_or(|state| state >= state_count))
            || self.automaton.outputs.iter().any(|&candidate| {
                candidate.is_present()
                    && (candidate.width > self.automaton.maximum_width
                        || candidate.ordinal >= self.source_count)
            })
            || (self.output == OutputContract::Exists
                && match self.exists_choice.as_ref() {
                    Some(_) => {
                        self.exists_literals.len()
                            != usize::try_from(self.source_count).ok()?
                    }
                    None => !self.exists_literals.is_empty(),
                })
            || (self.output != OutputContract::Exists
                && (self.exists_choice.is_some() || !self.exists_literals.is_empty()))
        {
            return None;
        }
        Some(NativeFiniteLanguageView {
            output: self.output,
            byte_classes: &self.automaton.byte_classes,
            class_representatives: &self.automaton.class_representatives,
            transitions: &self.automaton.transitions,
            outputs: &self.automaton.outputs,
            maximum_width: self.automaton.maximum_width,
            root_members: self.automaton.root_members,
            source_count: self.source_count,
            total_source_bytes: self.total_source_bytes,
        })
    }

    /// Return the separately authenticated exact-literal Choice candidate.
    /// This remains simultaneous with the incumbent native DFA; merely having
    /// this view never changes execution selection.
    pub(crate) fn native_exists_choice_view(
        &self,
        artifact_identity: [u8; 32],
        output: OutputContract,
    ) -> Option<NativeFiniteExistsChoiceView<'_>> {
        if !self.authenticates(artifact_identity, output)
            || output != OutputContract::Exists
            || self.exists_literals.len() != usize::try_from(self.source_count).ok()?
        {
            return None;
        }
        self.exists_choice
            .as_ref()?
            .native_view(&self.exists_literals)
    }

    /// Target-neutral correctness oracle for the future native lowering. The
    /// caller has already validated the search window at the public boundary.
    #[allow(
        dead_code,
        reason = "the native emitter will consume this independently tested target-neutral executor"
    )]
    pub(crate) fn search_validated(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> MatchResult {
        let mut state = 0_u32;
        let mut pending = None::<PendingMatch>;
        for index in window.start()..window.end() {
            state = self.automaton.next_state(state, haystack[index]);
            let end = index + 1;
            let output = self.automaton.output(state);
            if output.is_present() {
                if self.output == OutputContract::Exists {
                    return MatchResult::Exists(true);
                }
                let start = end - usize::try_from(output.width)
                    .expect("constructed finite width fits usize");
                let candidate = PendingMatch {
                    start,
                    end,
                    ordinal: output.ordinal,
                };
                if pending.is_none_or(|current| {
                    candidate.start < current.start
                        || (candidate.start == current.start
                            && candidate.ordinal < current.ordinal)
                }) {
                    pending = Some(candidate);
                }
            }

            if pending.is_some_and(|current| {
                end >= current
                    .start
                    .saturating_add(
                        usize::try_from(self.automaton.maximum_width)
                            .expect("constructed finite width fits usize"),
                    )
            }) {
                break;
            }
        }
        match self.output {
            OutputContract::Exists => MatchResult::Exists(false),
            OutputContract::SelectedEnd => {
                MatchResult::SelectedEnd(pending.map(|matched| matched.end))
            }
            OutputContract::Span => {
                MatchResult::Span(pending.map(|matched| (matched.start, matched.end)))
            }
        }
    }

    #[allow(
        dead_code,
        reason = "native serialization consumes these target-neutral dimensions in the next layer"
    )]
    pub(crate) const fn source_count(&self) -> u32 {
        self.source_count
    }

    #[allow(
        dead_code,
        reason = "native serialization consumes these target-neutral dimensions in the next layer"
    )]
    pub(crate) const fn total_source_bytes(&self) -> usize {
        self.total_source_bytes
    }

    #[allow(
        dead_code,
        reason = "native serialization consumes this exact root scanner proof in the next layer"
    )]
    pub(crate) const fn root_members(&self) -> [u64; 4] {
        self.automaton.root_members
    }
}

#[cfg(test)]
mod tests {
    use fre_automata::{Automaton, CompileLimits};
    use fre_lower::{
        FactLimits, FactOperation, FactOutput, OperationSemantics, analyze_facts,
    };
    use fre_syntax::{
        CanonicalPattern, CompatibilityProfile, ParseRequest, RustParsed, RustProfile,
    };

    use super::*;
    use crate::{CompileMode, DeterminizeLimits, program::CompiledProgram};

    fn parsed(pattern: &str) -> RustParsed {
        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern.to_owned(),
            CompatibilityProfile::RustBytes(RustProfile::default()),
        ))
        .expect("parse finite-language test pattern");
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust request returned a non-Rust pattern");
        };
        parsed
    }

    fn candidate(pattern: &str, output: OutputContract) -> Option<NativeFiniteLanguageCandidate> {
        NativeFiniteLanguageCandidate::analyze(&parsed(pattern), output)
    }

    fn bound_program(
        strings: &[&[u8]],
        output: OutputContract,
    ) -> NativeFiniteLanguageProgram {
        let strings = strings
            .iter()
            .map(|string| string.to_vec())
            .collect::<Vec<_>>();
        let total_bytes = strings.iter().map(Vec::len).sum();
        let candidate = NativeFiniteLanguageCandidate {
            operation: fact_operation(output),
            strings,
            total_bytes,
        };
        NativeFiniteLanguageProgram::bind(candidate, [7; 32], output)
            .expect("bind finite-language test program")
    }

    fn exists_choice<'a>(
        program: &'a NativeFiniteLanguageProgram,
    ) -> NativeFiniteExistsChoiceView<'a> {
        program
            .native_exists_choice_view([7; 32], OutputContract::Exists)
            .expect("authenticated exact-finite Exists choice")
    }

    #[test]
    fn exact_exists_choice_is_structural_and_preserves_literal_order() {
        let bytes = bound_program(
            &[b"a".as_slice(), b"z".as_slice(), b"a".as_slice()],
            OutputContract::Exists,
        );
        let bytes = exists_choice(&bytes);
        let NativeFiniteExistsChoiceKind::ByteSet { membership } = bytes.kind() else {
            panic!("one-byte exact language did not select byte-set planning");
        };
        assert_eq!(membership[usize::from(b'a') / 64] >> (b'a' % 64) & 1, 1);
        assert_eq!(membership[usize::from(b'z') / 64] >> (b'z' % 64) & 1, 1);
        assert_eq!(bytes.minimum_width(), 1);
        assert_eq!(bytes.maximum_width(), 1);
        assert_eq!(bytes.total_source_bytes(), 3);

        let single = bound_program(&[b"needle".as_slice()], OutputContract::Exists);
        assert_eq!(exists_choice(&single).kind(), NativeFiniteExistsChoiceKind::SingleLiteral);
        let mut stale_single = single.clone();
        stale_single.exists_literals[0][5] = b'X';
        assert!(
            stale_single
                .native_exists_choice_view([7; 32], OutputContract::Exists)
                .is_none(),
            "literal payload changes must invalidate the Choice receipt",
        );

        let teddy_literals = [
            b"alpha".as_slice(),
            b"bravo".as_slice(),
            b"cider".as_slice(),
            b"delta".as_slice(),
        ];
        let teddy = bound_program(&teddy_literals, OutputContract::Exists);
        let NativeFiniteExistsChoiceKind::Teddy(portfolio) = exists_choice(&teddy).kind() else {
            panic!("bounded exact literal set did not retain Teddy planning");
        };
        assert!(portfolio.plans().count() >= 2);
        assert!(portfolio.plans().all(|plan| {
            plan.literal_count() == 4 && (3..=4).contains(&plan.columns())
        }));
        for plan in portfolio.plans().copied() {
            for literal in teddy_literals {
                assert_ne!(
                    plan.candidate_buckets(literal),
                    0,
                    "an exact source literal must survive every retained fingerprint",
                );
            }
        }

        let short = bound_program(
            &[
                b"aa".as_slice(),
                b"bb".as_slice(),
                b"cc".as_slice(),
                b"dd".as_slice(),
            ],
            OutputContract::Exists,
        );
        assert!(
            short
                .native_exists_choice_view([7; 32], OutputContract::Exists)
                .is_none(),
            "an AC-only language must decline the competing Choice sidecar",
        );
        assert!(short.exists_literals.is_empty());
        assert!(short.native_view([7; 32], OutputContract::Exists).is_some());

        let many = (0_u8..65)
            .map(|byte| vec![b'x', byte, b'z'])
            .collect::<Vec<_>>();
        let many_refs = many.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let many = bound_program(&many_refs, OutputContract::Exists);
        assert!(
            many
                .native_exists_choice_view([7; 32], OutputContract::Exists)
                .is_none(),
            "packed planning must fail closed beyond its literal-count bound",
        );
        assert!(many.exists_literals.is_empty());
        assert!(many.native_view([7; 32], OutputContract::Exists).is_some());

        let first_short = bound_program(
            &[
                b"abc".as_slice(),
                b"abcd".as_slice(),
                b"xyz".as_slice(),
                b"uvw".as_slice(),
            ],
            OutputContract::Exists,
        );
        let verified = exists_choice(&first_short)
            .verify_at(b"zabcd", 1, 5)
            .expect("confirm first source literal");
        assert_eq!((verified.width(), verified.ordinal()), (3, 0));
        assert!(exists_choice(&first_short).verify_at(b"zabcd", 1, 3).is_none());

        let first_long = bound_program(
            &[
                b"abcd".as_slice(),
                b"abc".as_slice(),
                b"xyz".as_slice(),
                b"uvw".as_slice(),
            ],
            OutputContract::Exists,
        );
        let verified = exists_choice(&first_long)
            .verify_at(b"zabcd", 1, 5)
            .expect("confirm reordered source literal");
        assert_eq!((verified.width(), verified.ordinal()), (4, 0));

        let endpoint = bound_program(&[b"abc".as_slice()], OutputContract::Span);
        assert!(
            endpoint
                .native_exists_choice_view([7; 32], OutputContract::Span)
                .is_none()
        );
    }

    fn reference(
        strings: &[&[u8]],
        output: OutputContract,
        haystack: &[u8],
        window: SearchWindow,
    ) -> MatchResult {
        let mut matched = None;
        'starts: for start in window.start()..window.end() {
            for (ordinal, string) in strings.iter().enumerate() {
                let Some(end) = start.checked_add(string.len()) else {
                    continue;
                };
                if end <= window.end() && &haystack[start..end] == *string {
                    matched = Some((start, end, ordinal));
                    break 'starts;
                }
            }
        }
        match output {
            OutputContract::Exists => MatchResult::Exists(matched.is_some()),
            OutputContract::SelectedEnd => {
                MatchResult::SelectedEnd(matched.map(|(_, end, _)| end))
            }
            OutputContract::Span => {
                MatchResult::Span(matched.map(|(start, end, _)| (start, end)))
            }
        }
    }

    #[test]
    fn ordered_horizon_preserves_prefix_priority_and_earliest_start() {
        let cases = [
            (
                vec![b"sam".as_slice(), b"samwise".as_slice()],
                b"samwise".as_slice(),
                MatchResult::Span(Some((0, 3))),
            ),
            (
                vec![b"samwise".as_slice(), b"sam".as_slice()],
                b"samwise".as_slice(),
                MatchResult::Span(Some((0, 7))),
            ),
            (
                vec![b"abc".as_slice(), b"b".as_slice()],
                b"abc".as_slice(),
                MatchResult::Span(Some((0, 3))),
            ),
            (
                vec![b"she".as_slice(), b"he".as_slice(), b"hers".as_slice()],
                b"ushers".as_slice(),
                MatchResult::Span(Some((1, 4))),
            ),
        ];
        for (strings, haystack, expected) in cases {
            let program = bound_program(&strings, OutputContract::Span);
            assert_eq!(
                program.search_validated(haystack, SearchWindow::full(haystack)),
                expected,
                "strings={strings:?}, haystack={haystack:?}",
            );
        }
    }

    #[test]
    fn duplicate_terminal_keeps_earliest_source_ordinal() {
        let program = bound_program(
            &[b"ab".as_slice(), b"ab".as_slice(), b"a".as_slice()],
            OutputContract::Span,
        );
        let after_a = program.automaton.next_state(0, b'a');
        let after_ab = program.automaton.next_state(after_a, b'b');
        assert_eq!(
            program.automaton.output(after_ab),
            OrderedFiniteOutput {
                width: 2,
                ordinal: 0,
            },
        );
    }

    #[test]
    fn finite_hir_facts_preserve_variable_width_priority_and_duplicates() {
        let repetition_candidate = candidate(r"(?:ab|c){1,2}", OutputContract::Span)
            .expect("bounded repetition is a complete finite language");
        assert_eq!(
            repetition_candidate.strings,
            vec![
                b"abab".to_vec(),
                b"abc".to_vec(),
                b"cab".to_vec(),
                b"cc".to_vec(),
                b"ab".to_vec(),
                b"c".to_vec(),
            ],
        );
        let lazy_repetition_candidate = candidate(r"(?:ab|c){1,2}?", OutputContract::Span)
            .expect("lazy bounded repetition is a complete finite language");
        assert_eq!(
            lazy_repetition_candidate.strings,
            vec![
                b"ab".to_vec(),
                b"c".to_vec(),
                b"abab".to_vec(),
                b"abc".to_vec(),
                b"cab".to_vec(),
                b"cc".to_vec(),
            ],
        );
        let class_candidate = candidate(r"[ab]c?", OutputContract::SelectedEnd)
            .expect("bounded class concatenation is a complete finite language");
        assert_eq!(
            class_candidate.strings,
            vec![
                b"ac".to_vec(),
                b"a".to_vec(),
                b"bc".to_vec(),
                b"b".to_vec(),
            ],
        );
        assert!(candidate(r"(?P<word>ab)|c", OutputContract::Span).is_some());
    }

    #[test]
    fn proof_refusal_assertions_and_nullable_members_decline() {
        assert!(candidate(r"a+", OutputContract::Span).is_none());
        assert!(candidate(r"^foo", OutputContract::Span).is_none());
        assert!(candidate(r"a?", OutputContract::Span).is_none());

        let parsed = parsed("foo|bar");
        let facts = analyze_facts(
            &parsed,
            FactOperation::capture_erased(FactOutput::Exists),
            FactLimits::default(),
        )
        .expect("analyze mismatched fact operation");
        assert!(
            NativeFiniteLanguageCandidate::from_facts(
                &facts,
                FactOperation::capture_erased(FactOutput::SpanSequence),
            )
            .is_none(),
        );
    }

    #[test]
    fn large_finite_language_is_not_gated_by_irrelevant_subset_proof() {
        let pattern = (0_u16..256)
            .map(|ordinal| format!("finite{ordinal:03x}"))
            .collect::<Vec<_>>()
            .join("|");
        let parsed = parsed(&pattern);
        let operation = fact_operation(OutputContract::Exists);
        let facts = analyze_facts(&parsed, operation, FactLimits::default())
            .expect("finite-only analysis skips an irrelevant exponential subset proof");
        assert_eq!(facts.operation(), operation);
        assert_eq!(facts.finite_language().as_proven().map(|value| value.len()), Some(256));
        assert!(facts.determinism().subset().as_proven().is_none());
        assert!(NativeFiniteLanguageCandidate::from_facts(&facts, operation).is_some());
    }

    #[test]
    fn construction_limits_and_binding_are_conservative() {
        let output = OutputContract::Span;
        let candidate = candidate("abc|de", output).expect("finite candidate");
        assert!(
            NativeFiniteLanguageProgram::bind_with_limits(
                candidate.clone(),
                [1; 32],
                output,
                OrderedFiniteBuildLimits {
                    max_states: 2,
                    ..OrderedFiniteBuildLimits::default()
                },
            )
            .is_none(),
        );
        assert!(
            NativeFiniteLanguageProgram::bind_with_limits(
                candidate.clone(),
                [1; 32],
                output,
                OrderedFiniteBuildLimits {
                    max_transition_cells: 1,
                    ..OrderedFiniteBuildLimits::default()
                },
            )
            .is_none(),
        );
        assert!(
            NativeFiniteLanguageProgram::bind_with_limits(
                candidate.clone(),
                [1; 32],
                output,
                OrderedFiniteBuildLimits {
                    max_failure_steps: 0,
                    ..OrderedFiniteBuildLimits::default()
                },
            )
            .is_none(),
        );
        assert!(
            NativeFiniteLanguageProgram::bind(candidate.clone(), [0; 32], output).is_none(),
        );
        assert!(
            NativeFiniteLanguageProgram::bind(candidate, [1; 32], OutputContract::Exists)
                .is_none(),
        );
    }

    fn enumerate_words(maximum_width: usize) -> Vec<Vec<u8>> {
        let mut words = Vec::new();
        for width in 1..=maximum_width {
            for bits in 0..(1_usize << width) {
                let mut word = Vec::new();
                for shift in (0..width).rev() {
                    word.push(if bits & (1 << shift) == 0 { b'a' } else { b'b' });
                }
                words.push(word);
            }
        }
        words
    }

    fn enumerate_haystacks(maximum_width: usize) -> Vec<Vec<u8>> {
        let mut haystacks = vec![Vec::new()];
        for width in 1..=maximum_width {
            for bits in 0..(1_usize << width) {
                let mut haystack = Vec::new();
                for shift in (0..width).rev() {
                    haystack.push(if bits & (1 << shift) == 0 { b'a' } else { b'b' });
                }
                haystacks.push(haystack);
            }
        }
        haystacks
    }

    #[test]
    fn exhaustive_small_ordered_languages_match_naive_leftmost_first() {
        let words = enumerate_words(2);
        let haystacks = enumerate_haystacks(4);
        for language_len in 1..=3 {
            let language_count = words.len().pow(language_len);
            for mut language_index in 0..language_count {
                let mut strings = Vec::new();
                for _ in 0..language_len {
                    strings.push(words[language_index % words.len()].as_slice());
                    language_index /= words.len();
                }
                for output in [
                    OutputContract::Exists,
                    OutputContract::SelectedEnd,
                    OutputContract::Span,
                ] {
                    let program = bound_program(&strings, output);
                    for haystack in &haystacks {
                        for start in 0..=haystack.len() {
                            for end in start..=haystack.len() {
                                let window = SearchWindow::new(start, end);
                                assert_eq!(
                                    program.search_validated(haystack, window),
                                    reference(&strings, output, haystack, window),
                                    "strings={strings:?}, output={output:?}, haystack={haystack:?}, window={window:?}",
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn pending_horizon_preserves_source_priority_and_root_reset() {
        let haystack = b"zabzba";
        let first_short = [b"a".as_slice(), b"ab".as_slice(), b"ba".as_slice()];
        let first_long = [b"ab".as_slice(), b"a".as_slice(), b"ba".as_slice()];
        for (strings, selected_end) in [(&first_short[..], 2), (&first_long[..], 3)] {
            let span = bound_program(strings, OutputContract::Span);
            assert_eq!(
                span.search_validated(haystack, SearchWindow::new(0, haystack.len())),
                MatchResult::Span(Some((1, selected_end))),
            );
            let endpoint = bound_program(strings, OutputContract::SelectedEnd);
            assert_eq!(
                endpoint.search_validated(haystack, SearchWindow::new(0, haystack.len())),
                MatchResult::SelectedEnd(Some(selected_end)),
            );
            let exists = bound_program(strings, OutputContract::Exists);
            assert_eq!(
                exists.search_validated(haystack, SearchWindow::new(0, haystack.len())),
                MatchResult::Exists(true),
            );
        }

        // The absent `z` class returns every nonroot state to row zero. A
        // later candidate must therefore be independent of the rejected
        // prefix and the caller's nonzero window start.
        let reset = bound_program(&first_long, OutputContract::Span);
        assert_eq!(
            reset.search_validated(haystack, SearchWindow::new(3, haystack.len())),
            MatchResult::Span(Some((4, 6))),
        );
    }

    fn compiled_program_with_candidate(
        pattern: &str,
        output: OutputContract,
        mode: CompileMode,
    ) -> (CompiledProgram, Vec<u8>) {
        let parsed = parsed(pattern);
        let candidate = (mode == CompileMode::Optimizing)
            .then(|| NativeFiniteLanguageCandidate::analyze(&parsed, output))
            .flatten();
        let raw = fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            fre_lower::LowerLimits::default(),
        )
        .expect("lower finite-language test pattern")
        .into_plan();
        let automaton = Automaton::from_raw(raw.clone(), CompileLimits::default())
            .expect("validate finite-language test automaton");
        let mut program = CompiledProgram::build(
            raw,
            automaton,
            output,
            mode,
            DeterminizeLimits::default(),
            usize::MAX,
        )
        .expect("build finite-language test program");
        let stable_before_attachment = program
            .serialize()
            .expect("serialize before transient finite-language attachment");
        if let Some(candidate) = candidate {
            program.attach_native_finite_language(candidate);
        }
        (program, stable_before_attachment)
    }

    #[test]
    fn transient_sidecar_is_artifact_bound_and_absent_after_deserialization() {
        let (program, stable_before_attachment) = compiled_program_with_candidate(
            r"samwise|sam|frodo",
            OutputContract::Span,
            CompileMode::Optimizing,
        );
        let sidecar = program
            .native_finite_language_program()
            .expect("fresh optimizing source compile has finite sidecar");
        assert!(sidecar.authenticates(program.artifact_identity(), OutputContract::Span));
        assert_eq!(sidecar.source_count(), 3);
        assert_eq!(sidecar.total_source_bytes(), 15);
        assert_ne!(sidecar.root_members(), [0; 4]);

        let serialized = program.serialize().expect("serialize finite program");
        assert_eq!(serialized, stable_before_attachment);
        let restored = CompiledProgram::deserialize(&serialized).expect("restore finite program");
        assert!(restored.native_finite_language_program().is_none());
        assert_eq!(restored.serialize().unwrap(), serialized);

        let (fast, _) = compiled_program_with_candidate(
            "sam|frodo",
            OutputContract::Span,
            CompileMode::Fast,
        );
        assert!(fast.native_finite_language_program().is_none());

        let (exists, stable_exists) = compiled_program_with_candidate(
            "alpha|bravo|cider|delta",
            OutputContract::Exists,
            CompileMode::Optimizing,
        );
        assert!(matches!(
            exists.native_finite_exists_choice_view().map(|view| view.kind()),
            Some(NativeFiniteExistsChoiceKind::Teddy(_)),
        ));
        assert_eq!(exists.serialize().unwrap(), stable_exists);
        let restored_exists = CompiledProgram::deserialize(&stable_exists)
            .expect("restore semantic program without transient Choice state");
        assert!(restored_exists.native_finite_exists_choice_view().is_none());
    }
}
