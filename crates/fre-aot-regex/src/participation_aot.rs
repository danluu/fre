//! Helper-free exact-span capture-participation AOT construction.
//!
//! The ordinary Span selector remains authoritative for leftmost-first match
//! selection. This module determinizes only the capture-participation quotient
//! for replay of that independently selected span. Capture offsets never enter
//! the machine: each ordered thread carries `(pc, open, participated)`, and
//! first arrival at an original Thompson `pc` remains the priority rule.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all variable construction arithmetic is checked at its resource boundary"
)]

use core::fmt;
use std::collections::HashMap;

#[cfg(test)]
use fre_automata::{EdgeKind, UnicodeLookMatcher};
use fre_capture_lab::{
    ExactSpanParticipationNativeAssertionV1 as Assertion,
    ExactSpanParticipationNativeStateV1 as State, ExactSpanParticipationNativeV1Limits,
    ExactSpanParticipationNativeV1View,
};
use sha2::{Digest, Sha256};

use crate::{
    Architecture, CallAbi, CaptureAuthenticationError, CaptureLevel, CompiledCaptureRegex,
    CompiledModule, ObjectError, ObjectFormat, OperatingSystem, Target, emit_object,
};

const MAX_MASK_BITS: usize = 64;
const DEAD_STATE: u32 = u32::MAX;
const NO_ACCEPT: u8 = u8::MAX;

/// Stable identity of the prioritized participation determinization.
pub const NATIVE_PARTICIPATION_DFA_V1_ALGORITHM_ID: &str =
    "fre-aot-regex.exact-span-participation-dfa.v1";

pub const NATIVE_PARTICIPATION_AOT_V1_MAGIC: [u8; 8] = *b"FREPAR1\0";
pub const NATIVE_PARTICIPATION_AOT_V1_ABI_VERSION: u16 = 1;
pub const NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES: usize = 256;
pub const NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES: usize = 16;
pub const NATIVE_PARTICIPATION_AOT_V1_SCRATCH_ALIGN: usize = 8;
pub const NATIVE_PARTICIPATION_AOT_V1_READY_SEAL: u64 = 0x71ce_9d40_16b5_4a2f;
pub const NATIVE_PARTICIPATION_AOT_V1_STATUS_UNAVAILABLE: u32 = 10;
pub const NATIVE_PARTICIPATION_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/native-participation-aot-v1\0";

const PLAN_DIGEST_OFFSET: usize = 224;
const DIGEST_BYTES: usize = 32;
const PLAN_FLAG_SELECTED: u32 = 1;
const PLAN_FLAG_START_END_ASSERTIONS: u32 = 1 << 1;
const PLAN_KNOWN_FLAGS: u32 = PLAN_FLAG_SELECTED | PLAN_FLAG_START_END_ASSERTIONS;
const BUNDLE_SYMBOL_PREFIX: &str = "fre_aot_regex_participation_bundle_v1_";
const ENTRY_SYMBOL_PREFIX: &str = "fre_aot_regex_participation_exact_v1_";

/// Architecture-specific helper-free leaf or explicit unavailable entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum NativeParticipationAotStrategyV1 {
    DfaX86_64 = 1,
    DfaAarch64 = 2,
    NegativeEntry = 3,
}

/// Stable semantic reason carried by a negative entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum NativeParticipationAotDeclineV1 {
    SchemaTooWide = 1,
    SelectorRequiresRuntime = 2,
    UnsupportedAssertion = 3,
}

/// Complete compiler receipt for one additive native participation object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeParticipationAotReceiptV1 {
    pub target: Target,
    pub strategy: NativeParticipationAotStrategyV1,
    pub decline: Option<NativeParticipationAotDeclineV1>,
    pub semantic_runtime_calls: usize,
    pub groups: usize,
    pub assertions: usize,
    pub assertion_signatures: usize,
    pub byte_classes: usize,
    pub dfa_states: usize,
    pub transition_cells: usize,
    pub build_work: usize,
    pub scratch_bytes: usize,
    pub plan_bytes: usize,
    pub capture_sha256: [u8; DIGEST_BYTES],
    pub selector_sha256: [u8; DIGEST_BYTES],
    pub selector_object_sha256: [u8; DIGEST_BYTES],
    pub bundle_sha256: [u8; DIGEST_BYTES],
    pub export_identity_sha256: [u8; DIGEST_BYTES],
    pub object_sha256: [u8; DIGEST_BYTES],
}

#[derive(Debug)]
pub struct NativeParticipationAotArtifactV1 {
    module: CompiledModule,
    object: Box<[u8]>,
    bundle: Box<[u8]>,
    bundle_symbol: String,
    selector_entry_symbol: String,
    participation_entry_symbol: String,
    receipt: NativeParticipationAotReceiptV1,
}

impl NativeParticipationAotArtifactV1 {
    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        &self.module
    }

    #[must_use]
    pub fn object(&self) -> &[u8] {
        &self.object
    }

    #[must_use]
    pub fn bundle(&self) -> &[u8] {
        &self.bundle
    }

    #[must_use]
    pub fn bundle_symbol(&self) -> &str {
        &self.bundle_symbol
    }

    #[must_use]
    pub fn selector_entry_symbol(&self) -> &str {
        &self.selector_entry_symbol
    }

    #[must_use]
    pub fn participation_entry_symbol(&self) -> &str {
        &self.participation_entry_symbol
    }

    #[must_use]
    pub const fn receipt(&self) -> NativeParticipationAotReceiptV1 {
        self.receipt
    }

    /// Reauthenticate the sealed bundle, native module, object, route, and
    /// receipt without allocating.
    #[must_use]
    pub fn authenticates_receipt(&self) -> bool {
        artifact_authenticates(self)
    }
}

/// Independent, deterministic construction ceilings.
///
/// These meter the participation construction itself. They do not claim an
/// exhaustive host-allocator failure contract for cloning the incumbent
/// selector module or converting already-built owners at publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeParticipationAotLimitsV1 {
    pub view: ExactSpanParticipationNativeV1Limits,
    pub max_assertions: usize,
    pub max_assertion_signatures: usize,
    pub max_byte_classes: usize,
    pub max_dfa_states: usize,
    pub max_transition_cells: usize,
    pub max_build_work: usize,
    pub max_plan_bytes: usize,
    pub max_object_bytes: usize,
}

impl Default for NativeParticipationAotLimitsV1 {
    fn default() -> Self {
        Self {
            view: ExactSpanParticipationNativeV1Limits::default(),
            max_assertions: MAX_MASK_BITS,
            max_assertion_signatures: 256,
            max_byte_classes: 256,
            max_dfa_states: 65_536,
            max_transition_cells: 16 * 1_024 * 1_024,
            max_build_work: 128 * 1_024 * 1_024,
            max_plan_bytes: 256 * 1_024 * 1_024,
            max_object_bytes: 512 * 1_024 * 1_024,
        }
    }
}

/// One independently metered construction dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeParticipationAotResourceV1 {
    Assertions,
    AssertionSignatures,
    ByteClasses,
    DfaStates,
    TransitionCells,
    BuildWork,
    PlanBytes,
    ObjectBytes,
}

/// Fail-closed target-neutral construction error.
#[derive(Debug)]
pub enum NativeParticipationAotErrorV1 {
    Authentication(CaptureAuthenticationError),
    View(fre_capture_lab::ExactSpanParticipationNativeV1Error),
    Object(ObjectError),
    Resource {
        resource: NativeParticipationAotResourceV1,
        required: usize,
        limit: usize,
    },
    ArithmeticOverflow(NativeParticipationAotResourceV1),
    Allocation(&'static str),
    InvalidProgram(&'static str),
}

impl fmt::Display for NativeParticipationAotErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native participation AOT construction failed: {self:?}"
        )
    }
}

impl std::error::Error for NativeParticipationAotErrorV1 {}

impl From<fre_capture_lab::ExactSpanParticipationNativeV1Error> for NativeParticipationAotErrorV1 {
    fn from(value: fre_capture_lab::ExactSpanParticipationNativeV1Error) -> Self {
        Self::View(value)
    }
}

impl From<ObjectError> for NativeParticipationAotErrorV1 {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Thread {
    pc: u32,
    open: u64,
    participated: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct AssertionKey {
    kind: u8,
    data: u8,
}

impl AssertionKey {
    fn new(assertion: Assertion) -> Self {
        Self {
            kind: assertion.kind() as u8,
            data: assertion.data(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnicodeSide {
    Invalid,
    NonWord,
    Word,
}

impl UnicodeSide {
    const ALL: [Self; 3] = [Self::Invalid, Self::NonWord, Self::Word];

    const fn valid(self) -> bool {
        !matches!(self, Self::Invalid)
    }

    const fn word(self) -> bool {
        matches!(self, Self::Word)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AbstractBoundary {
    left: Option<u8>,
    right: Option<u8>,
    left_unicode: UnicodeSide,
    right_unicode: UnicodeSide,
}

/// Target-neutral deterministic exact-span participation plan.
#[derive(Clone, Debug)]
pub(crate) struct NativeParticipationDfaV1 {
    assertions: Box<[AssertionKey]>,
    assertion_signatures: Box<[u64]>,
    byte_classes: [u8; 256],
    byte_representatives: Box<[u8]>,
    start_states: Box<[u32]>,
    transitions: Box<[u32]>,
    accept_counts: Box<[u8]>,
    group_count: usize,
    build_work: usize,
}

impl NativeParticipationDfaV1 {
    pub(crate) fn build(
        view: ExactSpanParticipationNativeV1View<'_>,
        limits: NativeParticipationAotLimitsV1,
    ) -> Result<Self, NativeParticipationAotErrorV1> {
        let assertions = collect_assertions(view, limits)?;
        let assertion_signatures = assertion_signatures(&assertions, limits)?;
        let (byte_classes, byte_representatives) = byte_classes(view, limits)?;
        let mut construction = Construction {
            view,
            assertions: &assertions,
            signatures: &assertion_signatures,
            byte_representatives: &byte_representatives,
            limits,
            configurations: Vec::new(),
            indices: HashMap::new(),
            transitions: Vec::new(),
            accept_counts: Vec::new(),
            build_work: 0,
        };
        let mut start_states = Vec::new();
        reserve_exact(
            &mut start_states,
            assertion_signatures.len(),
            "participation start states",
        )?;
        for signature in 0..assertion_signatures.len() {
            let mut seen = false_vec(view.state_count(), "participation start seen set")?;
            let mut output = Vec::new();
            construction.add_closure(
                &mut output,
                &mut seen,
                Thread {
                    pc: view.start_state(),
                    open: 0,
                    participated: 0,
                },
                signature,
            )?;
            start_states.push(construction.intern(output)?);
        }
        let mut state = 0_usize;
        while state < construction.configurations.len() {
            construction.emit_state(state)?;
            state =
                state
                    .checked_add(1)
                    .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
                        NativeParticipationAotResourceV1::DfaStates,
                    ))?;
        }
        let state_count = construction.configurations.len();
        let expected_cells = state_count
            .checked_mul(byte_representatives.len())
            .and_then(|cells| cells.checked_mul(assertion_signatures.len()))
            .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::TransitionCells,
            ))?;
        if construction.transitions.len() != expected_cells
            || construction.accept_counts.len() != state_count
        {
            return Err(NativeParticipationAotErrorV1::InvalidProgram(
                "participation DFA construction extent did not close",
            ));
        }
        enforce(
            NativeParticipationAotResourceV1::TransitionCells,
            expected_cells,
            limits.max_transition_cells,
        )?;
        let assertion_bytes = assertions.len().checked_mul(2).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::PlanBytes,
            ),
        )?;
        let signature_bytes = assertion_signatures.len().checked_mul(8).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::PlanBytes,
            ),
        )?;
        let start_bytes = start_states.len().checked_mul(4).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::PlanBytes,
            ),
        )?;
        let transition_bytes = construction.transitions.len().checked_mul(4).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::PlanBytes,
            ),
        )?;
        let estimated_plan_bytes = 256_usize
            .checked_add(assertion_bytes)
            .and_then(|bytes| bytes.checked_add(signature_bytes))
            .and_then(|bytes| bytes.checked_add(256))
            .and_then(|bytes| bytes.checked_add(start_bytes))
            .and_then(|bytes| bytes.checked_add(transition_bytes))
            .and_then(|bytes| bytes.checked_add(construction.accept_counts.len()))
            .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::PlanBytes,
            ))?;
        enforce(
            NativeParticipationAotResourceV1::PlanBytes,
            estimated_plan_bytes,
            limits.max_plan_bytes,
        )?;
        let Construction {
            transitions,
            accept_counts,
            build_work,
            ..
        } = construction;
        Ok(Self {
            assertions: assertions.into_boxed_slice(),
            assertion_signatures: assertion_signatures.into_boxed_slice(),
            byte_classes,
            byte_representatives: byte_representatives.into_boxed_slice(),
            start_states: start_states.into_boxed_slice(),
            transitions: transitions.into_boxed_slice(),
            accept_counts: accept_counts.into_boxed_slice(),
            group_count: view.layout().group_count(),
            build_work,
        })
    }

    pub(crate) const fn group_count(&self) -> usize {
        self.group_count
    }

    pub(crate) fn state_count(&self) -> usize {
        self.accept_counts.len()
    }

    pub(crate) fn assertion_count(&self) -> usize {
        self.assertions.len()
    }

    pub(crate) fn assertion_signature_count(&self) -> usize {
        self.assertion_signatures.len()
    }

    pub(crate) fn alphabet_len(&self) -> usize {
        self.byte_representatives.len()
    }

    pub(crate) fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    pub(crate) const fn build_work(&self) -> usize {
        self.build_work
    }

    pub(crate) fn assertions(&self) -> &[AssertionKey] {
        &self.assertions
    }

    pub(crate) fn assertion_signatures(&self) -> &[u64] {
        &self.assertion_signatures
    }

    pub(crate) const fn byte_class_map(&self) -> &[u8; 256] {
        &self.byte_classes
    }

    pub(crate) fn start_states(&self) -> &[u32] {
        &self.start_states
    }

    pub(crate) fn transitions(&self) -> &[u32] {
        &self.transitions
    }

    pub(crate) fn accept_counts(&self) -> &[u8] {
        &self.accept_counts
    }

    fn start_end_boundary_map(&self) -> Option<[u8; 4]> {
        let mut map = [0_u8; 4];
        for flags in 0_u8..4 {
            let mut truth = 0_u64;
            for (bit, assertion) in self.assertions.iter().enumerate() {
                let matched = match assertion.kind {
                    1 => flags & 1 != 0,
                    2 => flags & 2 != 0,
                    _ => return None,
                };
                truth |= u64::from(matched) << bit;
            }
            let signature = self
                .assertion_signatures
                .iter()
                .position(|&candidate| candidate == truth)?;
            map[usize::from(flags)] = u8::try_from(signature).ok()?;
        }
        Some(map)
    }

    #[cfg(test)]
    fn execute(&self, haystack: &[u8], start: usize, end: usize) -> Result<usize, &'static str> {
        if start > end || end > haystack.len() {
            return Err("invalid span");
        }
        let signature = self.boundary_signature(haystack, start)?;
        let mut state = usize::try_from(*self.start_states.get(signature).ok_or("start")?)
            .map_err(|_| "start")?;
        for position in start..end {
            let byte = usize::from(haystack[position]);
            let class = usize::from(self.byte_classes[byte]);
            let next_signature = self.boundary_signature(haystack, position + 1)?;
            let cell = state
                .checked_mul(self.alphabet_len())
                .and_then(|index| index.checked_add(class))
                .and_then(|index| index.checked_mul(self.assertion_signature_count()))
                .and_then(|index| index.checked_add(next_signature))
                .ok_or("transition")?;
            let next = *self.transitions.get(cell).ok_or("transition")?;
            if next == DEAD_STATE {
                return Err("span not in language");
            }
            state = usize::try_from(next).map_err(|_| "state")?;
        }
        let count = *self.accept_counts.get(state).ok_or("accept")?;
        if count == NO_ACCEPT {
            return Err("span not in language");
        }
        Ok(usize::from(count))
    }

    #[cfg(test)]
    fn boundary_signature(&self, haystack: &[u8], at: usize) -> Result<usize, &'static str> {
        let mask =
            self.assertions
                .iter()
                .enumerate()
                .try_fold(0_u64, |mask, (bit, &assertion)| {
                    let matched = concrete_assertion(assertion, haystack, at)?;
                    Ok::<_, &'static str>(mask | (u64::from(matched) << bit))
                })?;
        self.assertion_signatures
            .iter()
            .position(|&candidate| candidate == mask)
            .ok_or("unclassified boundary")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeParticipationPlanGeometryV1 {
    pub total_bytes: usize,
    pub build_work: usize,
    pub assertions_offset: usize,
    pub signatures_offset: usize,
    pub byte_classes_offset: usize,
    pub boundary_map_offset: usize,
    pub start_states_offset: usize,
    pub transitions_offset: usize,
    pub accept_counts_offset: usize,
    pub group_count: usize,
    pub assertion_count: usize,
    pub signature_count: usize,
    pub alphabet_len: usize,
    pub state_count: usize,
    pub transition_count: usize,
}

pub(crate) fn emit_native_participation_aot_v1(
    compiled: &CompiledCaptureRegex,
    limits: NativeParticipationAotLimitsV1,
) -> Result<NativeParticipationAotArtifactV1, NativeParticipationAotErrorV1> {
    compiled
        .authenticate()
        .map_err(NativeParticipationAotErrorV1::Authentication)?;
    let identity = compiled.receipt().identity;
    if identity.level() != CaptureLevel::All
        || identity.groups() == 0
        || identity.groups().checked_mul(2) != Some(identity.slots())
    {
        return Err(NativeParticipationAotErrorV1::InvalidProgram(
            "capture schema is not complete",
        ));
    }
    let target = compiled.selector().module().target();
    let selector_object_sha256: [u8; DIGEST_BYTES] =
        Sha256::digest(compiled.selector().object()).into();
    let selector_entry_symbol = owned_string(
        compiled.selector().module().entry_symbol(),
        "selector entry symbol",
    )?;

    let selector_module = compiled.selector().module();
    let selector_requires_runtime = selector_module
        .required_runtime_symbols()
        .next()
        .is_some()
        || selector_module.required_runtime_program().is_some();
    let (strategy, decline, bundle, geometry, build_work) = if selector_requires_runtime {
        let strategy = NativeParticipationAotStrategyV1::NegativeEntry;
        let decline = NativeParticipationAotDeclineV1::SelectorRequiresRuntime;
        (
            strategy,
            Some(decline),
            encode_negative_bundle(
                compiled,
                target,
                selector_object_sha256,
                strategy,
                decline,
                limits.max_plan_bytes,
            )?,
            None,
            0,
        )
    } else if let Some(view) = compiled
        .capture_program()
        .exact_span_participation_native_v1_view(limits.view)?
    {
        if !native_assertions_supported(view) {
            let strategy = NativeParticipationAotStrategyV1::NegativeEntry;
            let decline = NativeParticipationAotDeclineV1::UnsupportedAssertion;
            (
                strategy,
                Some(decline),
                encode_negative_bundle(
                    compiled,
                    target,
                    selector_object_sha256,
                    strategy,
                    decline,
                    limits.max_plan_bytes,
                )?,
                None,
                0,
            )
        } else {
            let dfa = NativeParticipationDfaV1::build(view, limits)?;
            let strategy = match target.architecture {
                Architecture::X86_64 => NativeParticipationAotStrategyV1::DfaX86_64,
                Architecture::Aarch64 => NativeParticipationAotStrategyV1::DfaAarch64,
            };
            let build_work = dfa.build_work();
            let (bundle, geometry) = encode_selected_bundle(
                compiled,
                target,
                selector_object_sha256,
                strategy,
                &dfa,
                limits.max_plan_bytes,
            )?;
            (strategy, None, bundle, Some(geometry), build_work)
        }
    } else {
        let strategy = NativeParticipationAotStrategyV1::NegativeEntry;
        let decline = NativeParticipationAotDeclineV1::SchemaTooWide;
        (
            strategy,
            Some(decline),
            encode_negative_bundle(
                compiled,
                target,
                selector_object_sha256,
                strategy,
                decline,
                limits.max_plan_bytes,
            )?,
            None,
            0,
        )
    };
    let bundle_sha256 = bundle_digest(&bundle)?;
    let export_identity_sha256 = export_digest(
        bundle_sha256,
        target,
        &selector_entry_symbol,
        selector_object_sha256,
    )?;
    let bundle_symbol =
        crate::module::identity_symbol(BUNDLE_SYMBOL_PREFIX, &export_identity_sha256)?;
    let participation_entry_symbol =
        crate::module::identity_symbol(ENTRY_SYMBOL_PREFIX, &export_identity_sha256)?;
    let module = compiled
        .selector()
        .module()
        .clone()
        .append_native_participation_export_v1(
            &bundle_symbol,
            &bundle,
            &participation_entry_symbol,
            geometry,
        )?;
    if module.entry_symbol() != selector_entry_symbol
        || module.required_runtime_symbols().count()
            != compiled
                .selector()
                .module()
                .required_runtime_symbols()
                .count()
        || module.required_runtime_program()
            != compiled.selector().module().required_runtime_program()
    {
        return Err(NativeParticipationAotErrorV1::InvalidProgram(
            "participation extension changed the selector route",
        ));
    }
    let object = emit_object(
        &module,
        ObjectFormat::for_target(target),
        limits.max_object_bytes,
    )?
    .into_boxed_slice();
    let mut receipt = NativeParticipationAotReceiptV1 {
        target,
        strategy,
        decline,
        semantic_runtime_calls: 0,
        groups: identity.groups(),
        assertions: geometry.map_or(0, |shape| shape.assertion_count),
        assertion_signatures: geometry.map_or(0, |shape| shape.signature_count),
        byte_classes: geometry.map_or(0, |shape| shape.alphabet_len),
        dfa_states: geometry.map_or(0, |shape| shape.state_count),
        transition_cells: geometry.map_or(0, |shape| shape.transition_count),
        build_work,
        scratch_bytes: geometry.map_or(0, |_| NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES),
        plan_bytes: bundle.len(),
        capture_sha256: identity.capture_sha256(),
        selector_sha256: identity.selector_sha256(),
        selector_object_sha256,
        bundle_sha256,
        export_identity_sha256,
        object_sha256: [0; DIGEST_BYTES],
    };
    receipt.object_sha256 = Sha256::digest(&object).into();
    let artifact = NativeParticipationAotArtifactV1 {
        module,
        object,
        bundle: bundle.into_boxed_slice(),
        bundle_symbol,
        selector_entry_symbol,
        participation_entry_symbol,
        receipt,
    };
    // Receipt authentication is deliberately allocation-free, so a false
    // result here cannot hide a host allocation failure behind InvalidProgram.
    if !artifact.authenticates_receipt() {
        return Err(NativeParticipationAotErrorV1::InvalidProgram(
            "fresh participation artifact authentication failed",
        ));
    }
    Ok(artifact)
}

fn native_assertions_supported(view: ExactSpanParticipationNativeV1View<'_>) -> bool {
    view.states().all(|state| {
        !matches!(
            state,
            State::Assert { assertion, .. }
                if !matches!(assertion.kind() as u8, 1 | 2)
        )
    })
}

fn encode_selected_bundle(
    compiled: &CompiledCaptureRegex,
    target: Target,
    selector_object_sha256: [u8; DIGEST_BYTES],
    strategy: NativeParticipationAotStrategyV1,
    dfa: &NativeParticipationDfaV1,
    max_bytes: usize,
) -> Result<(Vec<u8>, NativeParticipationPlanGeometryV1), NativeParticipationAotErrorV1> {
    let boundary_map =
        dfa.start_end_boundary_map()
            .ok_or(NativeParticipationAotErrorV1::InvalidProgram(
                "selected assertion boundary map",
            ))?;
    let assertions_offset = NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES;
    let signatures_offset = align8(
        assertions_offset
            .checked_add(dfa.assertions().len().checked_mul(2).ok_or(
                NativeParticipationAotErrorV1::ArithmeticOverflow(
                    NativeParticipationAotResourceV1::PlanBytes,
                ),
            )?)
            .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::PlanBytes,
            ))?,
    )?;
    let byte_classes_offset = signatures_offset
        .checked_add(dfa.assertion_signatures().len().checked_mul(8).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::PlanBytes,
            ),
        )?)
        .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        ))?;
    let boundary_map_offset = byte_classes_offset.checked_add(256).ok_or(
        NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        ),
    )?;
    let start_states_offset = align8(boundary_map_offset.checked_add(4).ok_or(
        NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        ),
    )?)?;
    let transitions_offset = start_states_offset
        .checked_add(dfa.start_states().len().checked_mul(4).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::PlanBytes,
            ),
        )?)
        .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        ))?;
    let accept_counts_offset = transitions_offset
        .checked_add(dfa.transitions().len().checked_mul(4).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::PlanBytes,
            ),
        )?)
        .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        ))?;
    let total_bytes = accept_counts_offset
        .checked_add(dfa.accept_counts().len())
        .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        ))?;
    enforce(
        NativeParticipationAotResourceV1::PlanBytes,
        total_bytes,
        max_bytes,
    )?;
    let identity = compiled.receipt().identity;
    let mut bytes = Vec::new();
    reserve_exact(&mut bytes, total_bytes, "participation bundle")?;
    bytes.resize(NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES, 0);
    encode_header(
        &mut bytes,
        target,
        strategy,
        None,
        PLAN_FLAG_SELECTED | PLAN_FLAG_START_END_ASSERTIONS,
        total_bytes,
        dfa.build_work(),
        dfa.group_count(),
        dfa.assertion_count(),
        dfa.assertion_signature_count(),
        dfa.alphabet_len(),
        dfa.state_count(),
        dfa.transition_count(),
        signatures_offset,
        byte_classes_offset,
        boundary_map_offset,
        start_states_offset,
        transitions_offset,
        accept_counts_offset,
        identity.capture_sha256(),
        identity.selector_sha256(),
        selector_object_sha256,
    )?;
    for assertion in dfa.assertions() {
        bytes.extend_from_slice(&[assertion.kind, assertion.data]);
    }
    bytes.resize(signatures_offset, 0);
    for signature in dfa.assertion_signatures() {
        bytes.extend_from_slice(&signature.to_le_bytes());
    }
    bytes.extend_from_slice(dfa.byte_class_map());
    bytes.extend_from_slice(&boundary_map);
    bytes.resize(start_states_offset, 0);
    for state in dfa.start_states() {
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    for state in dfa.transitions() {
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.extend_from_slice(dfa.accept_counts());
    if bytes.len() != total_bytes {
        return Err(NativeParticipationAotErrorV1::InvalidProgram(
            "encoded participation extent",
        ));
    }
    seal_bundle(&mut bytes)?;
    Ok((
        bytes,
        NativeParticipationPlanGeometryV1 {
            total_bytes,
            build_work: dfa.build_work(),
            assertions_offset,
            signatures_offset,
            byte_classes_offset,
            boundary_map_offset,
            start_states_offset,
            transitions_offset,
            accept_counts_offset,
            group_count: dfa.group_count(),
            assertion_count: dfa.assertion_count(),
            signature_count: dfa.assertion_signature_count(),
            alphabet_len: dfa.alphabet_len(),
            state_count: dfa.state_count(),
            transition_count: dfa.transition_count(),
        },
    ))
}

fn encode_negative_bundle(
    compiled: &CompiledCaptureRegex,
    target: Target,
    selector_object_sha256: [u8; DIGEST_BYTES],
    strategy: NativeParticipationAotStrategyV1,
    decline: NativeParticipationAotDeclineV1,
    max_bytes: usize,
) -> Result<Vec<u8>, NativeParticipationAotErrorV1> {
    enforce(
        NativeParticipationAotResourceV1::PlanBytes,
        NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES,
        max_bytes,
    )?;
    let identity = compiled.receipt().identity;
    let mut bytes = Vec::new();
    reserve_exact(
        &mut bytes,
        NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES,
        "negative participation bundle",
    )?;
    bytes.resize(NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES, 0);
    let total_bytes = bytes.len();
    encode_header(
        &mut bytes,
        target,
        strategy,
        Some(decline),
        0,
        total_bytes,
        0,
        identity.groups(),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        identity.capture_sha256(),
        identity.selector_sha256(),
        selector_object_sha256,
    )?;
    seal_bundle(&mut bytes)?;
    Ok(bytes)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the wire header owns every independent extent"
)]
fn encode_header(
    bytes: &mut [u8],
    target: Target,
    strategy: NativeParticipationAotStrategyV1,
    decline: Option<NativeParticipationAotDeclineV1>,
    flags: u32,
    total_bytes: usize,
    build_work: usize,
    groups: usize,
    assertions: usize,
    signatures: usize,
    alphabet: usize,
    states: usize,
    transitions: usize,
    signatures_offset: usize,
    byte_classes_offset: usize,
    boundary_map_offset: usize,
    start_states_offset: usize,
    transitions_offset: usize,
    accept_counts_offset: usize,
    capture_sha256: [u8; DIGEST_BYTES],
    selector_sha256: [u8; DIGEST_BYTES],
    selector_object_sha256: [u8; DIGEST_BYTES],
) -> Result<(), NativeParticipationAotErrorV1> {
    if bytes.len() < NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES || flags & !PLAN_KNOWN_FLAGS != 0 {
        return Err(NativeParticipationAotErrorV1::InvalidProgram(
            "bundle header",
        ));
    }
    bytes[..8].copy_from_slice(&NATIVE_PARTICIPATION_AOT_V1_MAGIC);
    write_u16(bytes, 8, NATIVE_PARTICIPATION_AOT_V1_ABI_VERSION)?;
    write_u16(
        bytes,
        10,
        usize_u16(NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES)?,
    )?;
    write_u32(bytes, 12, flags)?;
    write_u64(bytes, 16, usize_u64(total_bytes)?)?;
    write_u64(bytes, 24, NATIVE_PARTICIPATION_AOT_V1_READY_SEAL)?;
    bytes[32] = match target.architecture {
        Architecture::X86_64 => 1,
        Architecture::Aarch64 => 2,
    };
    bytes[33] = match target.operating_system {
        OperatingSystem::Linux => 1,
        OperatingSystem::Macos => 2,
    };
    bytes[34] = match target.abi {
        CallAbi::SystemV => 1,
        CallAbi::Aapcs64 => 2,
    };
    write_u32(
        bytes,
        36,
        crate::module::native_participation_feature_word_v1(target).map_err(|_| {
            NativeParticipationAotErrorV1::InvalidProgram("target feature encoding")
        })?,
    )?;
    write_u16(bytes, 40, strategy as u16)?;
    write_u16(bytes, 42, decline.map_or(0, |reason| reason as u16))?;
    write_u32(
        bytes,
        44,
        if flags & PLAN_FLAG_SELECTED != 0 {
            usize_u32(NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES)?
        } else {
            0
        },
    )?;
    write_u32(bytes, 48, usize_u32(groups)?)?;
    write_u32(bytes, 52, usize_u32(assertions)?)?;
    write_u32(bytes, 56, usize_u32(signatures)?)?;
    write_u32(bytes, 60, usize_u32(alphabet)?)?;
    write_u32(bytes, 64, usize_u32(states)?)?;
    write_u32(bytes, 68, usize_u32(transitions)?)?;
    write_u64(bytes, 72, usize_u64(build_work)?)?;
    for (offset, value) in [
        (80, signatures_offset),
        (88, byte_classes_offset),
        (96, boundary_map_offset),
        (104, start_states_offset),
        (112, transitions_offset),
        (120, accept_counts_offset),
    ] {
        write_u64(bytes, offset, usize_u64(value)?)?;
    }
    bytes[128..160].copy_from_slice(&capture_sha256);
    bytes[160..192].copy_from_slice(&selector_sha256);
    bytes[192..224].copy_from_slice(&selector_object_sha256);
    Ok(())
}

fn seal_bundle(bytes: &mut [u8]) -> Result<(), NativeParticipationAotErrorV1> {
    if bytes.len() < PLAN_DIGEST_OFFSET + DIGEST_BYTES {
        return Err(NativeParticipationAotErrorV1::InvalidProgram(
            "bundle digest field",
        ));
    }
    bytes[PLAN_DIGEST_OFFSET..PLAN_DIGEST_OFFSET + DIGEST_BYTES].fill(0);
    let digest: [u8; DIGEST_BYTES] = Sha256::digest(&*bytes).into();
    bytes[PLAN_DIGEST_OFFSET..PLAN_DIGEST_OFFSET + DIGEST_BYTES].copy_from_slice(&digest);
    Ok(())
}

fn bundle_digest(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], NativeParticipationAotErrorV1> {
    if bytes.len() < PLAN_DIGEST_OFFSET + DIGEST_BYTES {
        return Err(NativeParticipationAotErrorV1::InvalidProgram(
            "bundle digest field",
        ));
    }
    let mut expected = [0_u8; DIGEST_BYTES];
    expected.copy_from_slice(&bytes[PLAN_DIGEST_OFFSET..PLAN_DIGEST_OFFSET + DIGEST_BYTES]);
    let mut digest = Sha256::new();
    digest.update(&bytes[..PLAN_DIGEST_OFFSET]);
    digest.update([0_u8; DIGEST_BYTES]);
    digest.update(&bytes[PLAN_DIGEST_OFFSET + DIGEST_BYTES..]);
    let actual: [u8; DIGEST_BYTES] = digest.finalize().into();
    if actual != expected {
        return Err(NativeParticipationAotErrorV1::InvalidProgram(
            "bundle digest",
        ));
    }
    Ok(expected)
}

fn export_digest(
    bundle_sha256: [u8; DIGEST_BYTES],
    target: Target,
    selector_entry_symbol: &str,
    selector_object_sha256: [u8; DIGEST_BYTES],
) -> Result<[u8; DIGEST_BYTES], NativeParticipationAotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(NATIVE_PARTICIPATION_AOT_V1_IDENTITY_DOMAIN);
    digest.update(bundle_sha256);
    digest.update([
        target_byte(target.architecture),
        target_os_byte(target.operating_system),
        target_abi_byte(target.abi),
    ]);
    digest.update(target.features.bits().to_le_bytes());
    digest.update(selector_object_sha256);
    digest.update(usize_u64(selector_entry_symbol.len())?.to_le_bytes());
    digest.update(selector_entry_symbol.as_bytes());
    Ok(digest.finalize().into())
}

fn artifact_authenticates(artifact: &NativeParticipationAotArtifactV1) -> bool {
    let Ok(bundle_sha256) = bundle_digest(&artifact.bundle) else {
        return false;
    };
    let receipt = artifact.receipt;
    let Ok(target_features) =
        crate::module::native_participation_feature_word_v1(receipt.target)
    else {
        return false;
    };
    let Some(strategy) = read_wire_u16(&artifact.bundle, 40).and_then(|value| match value {
        1 => Some(NativeParticipationAotStrategyV1::DfaX86_64),
        2 => Some(NativeParticipationAotStrategyV1::DfaAarch64),
        3 => Some(NativeParticipationAotStrategyV1::NegativeEntry),
        _ => None,
    }) else {
        return false;
    };
    let Some(decline) = read_wire_u16(&artifact.bundle, 42).and_then(|value| match value {
        0 => Some(None),
        1 => Some(Some(NativeParticipationAotDeclineV1::SchemaTooWide)),
        2 => Some(Some(
            NativeParticipationAotDeclineV1::SelectorRequiresRuntime,
        )),
        3 => Some(Some(NativeParticipationAotDeclineV1::UnsupportedAssertion)),
        _ => None,
    }) else {
        return false;
    };
    let selected = matches!(
        strategy,
        NativeParticipationAotStrategyV1::DfaX86_64 | NativeParticipationAotStrategyV1::DfaAarch64
    );
    let header_closes = artifact.bundle.get(..8) == Some(&NATIVE_PARTICIPATION_AOT_V1_MAGIC)
        && read_wire_u16(&artifact.bundle, 8) == Some(NATIVE_PARTICIPATION_AOT_V1_ABI_VERSION)
        && read_wire_u16(&artifact.bundle, 10)
            == u16::try_from(NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES).ok()
        && read_wire_u32(&artifact.bundle, 12) == Some(if selected { 3 } else { 0 })
        && read_wire_usize(&artifact.bundle, 16) == Some(artifact.bundle.len())
        && read_wire_u64(&artifact.bundle, 24) == Some(NATIVE_PARTICIPATION_AOT_V1_READY_SEAL)
        && artifact.bundle.get(32).copied() == Some(target_byte(receipt.target.architecture))
        && artifact.bundle.get(33).copied()
            == Some(target_os_byte(receipt.target.operating_system))
        && artifact.bundle.get(34).copied() == Some(target_abi_byte(receipt.target.abi))
        && artifact.bundle.get(35).copied() == Some(0)
        && read_wire_u32(&artifact.bundle, 36) == Some(target_features)
        && read_wire_usize_u32(&artifact.bundle, 44)
            == Some(if selected {
                NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES
            } else {
                0
            })
        && read_wire_usize_u32(&artifact.bundle, 48) == Some(receipt.groups)
        && read_wire_usize_u32(&artifact.bundle, 52) == Some(receipt.assertions)
        && read_wire_usize_u32(&artifact.bundle, 56) == Some(receipt.assertion_signatures)
        && read_wire_usize_u32(&artifact.bundle, 60) == Some(receipt.byte_classes)
        && read_wire_usize_u32(&artifact.bundle, 64) == Some(receipt.dfa_states)
        && read_wire_usize_u32(&artifact.bundle, 68) == Some(receipt.transition_cells)
        && read_wire_usize(&artifact.bundle, 72) == Some(receipt.build_work)
        && read_wire_digest(&artifact.bundle, 128) == Some(receipt.capture_sha256)
        && read_wire_digest(&artifact.bundle, 160) == Some(receipt.selector_sha256)
        && read_wire_digest(&artifact.bundle, 192) == Some(receipt.selector_object_sha256)
        && receipt.strategy == strategy
        && receipt.decline == decline
        && receipt.semantic_runtime_calls == 0
        && receipt.scratch_bytes
            == if selected {
                NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES
            } else {
                0
            }
        && receipt.plan_bytes == artifact.bundle.len()
        && if selected {
            decline.is_none()
                && artifact
                    .module
                    .required_runtime_symbols()
                    .next()
                    .is_none()
                && artifact.module.required_runtime_program().is_none()
                && receipt.groups != 0
                && receipt.assertion_signatures != 0
                && receipt.byte_classes != 0
                && receipt.dfa_states != 0
                && receipt.transition_cells != 0
                && read_wire_usize(&artifact.bundle, 88).is_some()
                && read_wire_usize(&artifact.bundle, 96).is_some()
                && read_wire_usize(&artifact.bundle, 104).is_some()
                && read_wire_usize(&artifact.bundle, 112).is_some()
                && read_wire_usize(&artifact.bundle, 120).is_some()
                && match (strategy, receipt.target.architecture) {
                    (NativeParticipationAotStrategyV1::DfaX86_64, Architecture::X86_64)
                    | (NativeParticipationAotStrategyV1::DfaAarch64, Architecture::Aarch64) => true,
                    _ => false,
                }
        } else {
            decline.is_some()
                && receipt.assertions == 0
                && receipt.assertion_signatures == 0
                && receipt.byte_classes == 0
                && receipt.dfa_states == 0
                && receipt.transition_cells == 0
                && receipt.build_work == 0
                && (72..=120)
                    .step_by(8)
                    .all(|offset| read_wire_u64(&artifact.bundle, offset) == Some(0))
        };
    if !header_closes {
        return false;
    }
    let Ok(export_identity_sha256) = export_digest(
        bundle_sha256,
        receipt.target,
        &artifact.selector_entry_symbol,
        receipt.selector_object_sha256,
    ) else {
        return false;
    };
    receipt.bundle_sha256 == bundle_sha256
        && receipt.export_identity_sha256 == export_identity_sha256
        && receipt.object_sha256 == <[u8; DIGEST_BYTES]>::from(Sha256::digest(&artifact.object))
        && artifact.module.target() == receipt.target
        && artifact.module.entry_symbol() == artifact.selector_entry_symbol
        && module_symbol_bytes(&artifact.module, &artifact.bundle_symbol)
            == Some(artifact.bundle.as_ref())
        && module_symbol_bytes(&artifact.module, &artifact.participation_entry_symbol)
            .is_some_and(|bytes| !bytes.is_empty())
        && identity_symbol_matches(
            &artifact.bundle_symbol,
            BUNDLE_SYMBOL_PREFIX,
            &export_identity_sha256,
        )
        && identity_symbol_matches(
            &artifact.participation_entry_symbol,
            ENTRY_SYMBOL_PREFIX,
            &export_identity_sha256,
        )
        && artifact
            .module
            .symbols()
            .iter()
            .any(|symbol| symbol.name == artifact.bundle_symbol)
        && artifact
            .module
            .symbols()
            .iter()
            .any(|symbol| symbol.name == artifact.participation_entry_symbol)
}

fn identity_symbol_matches(name: &str, prefix: &str, digest: &[u8]) -> bool {
    let Some(hex_bytes) = digest.len().checked_mul(2) else {
        return false;
    };
    if name.len() != prefix.len().checked_add(hex_bytes).unwrap_or(usize::MAX)
        || !name.as_bytes().starts_with(prefix.as_bytes())
    {
        return false;
    }
    name.as_bytes()[prefix.len()..]
        .chunks_exact(2)
        .zip(digest)
        .all(|(actual, &byte)| {
            actual[0] == b"0123456789abcdef"[usize::from(byte >> 4)]
                && actual[1] == b"0123456789abcdef"[usize::from(byte & 0x0f)]
        })
}

fn read_wire_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_wire_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_wire_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn read_wire_usize(bytes: &[u8], offset: usize) -> Option<usize> {
    usize::try_from(read_wire_u64(bytes, offset)?).ok()
}

fn read_wire_usize_u32(bytes: &[u8], offset: usize) -> Option<usize> {
    usize::try_from(read_wire_u32(bytes, offset)?).ok()
}

fn read_wire_digest(bytes: &[u8], offset: usize) -> Option<[u8; DIGEST_BYTES]> {
    bytes
        .get(offset..offset.checked_add(DIGEST_BYTES)?)?
        .try_into()
        .ok()
}

fn module_symbol_bytes<'a>(module: &'a CompiledModule, name: &str) -> Option<&'a [u8]> {
    let symbol = module.symbols().iter().find(|symbol| symbol.name == name)?;
    let section = module.sections().get(symbol.section?)?;
    let start = usize::try_from(symbol.offset).ok()?;
    let end = start.checked_add(usize::try_from(symbol.size).ok()?)?;
    section.bytes().get(start..end)
}

const fn target_byte(architecture: Architecture) -> u8 {
    match architecture {
        Architecture::X86_64 => 1,
        Architecture::Aarch64 => 2,
    }
}

const fn target_os_byte(os: OperatingSystem) -> u8 {
    match os {
        OperatingSystem::Linux => 1,
        OperatingSystem::Macos => 2,
    }
}

const fn target_abi_byte(abi: CallAbi) -> u8 {
    match abi {
        CallAbi::SystemV => 1,
        CallAbi::Aapcs64 => 2,
    }
}

fn align8(value: usize) -> Result<usize, NativeParticipationAotErrorV1> {
    value.checked_add(7).map(|rounded| rounded & !7).ok_or(
        NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        ),
    )
}

fn usize_u16(value: usize) -> Result<u16, NativeParticipationAotErrorV1> {
    u16::try_from(value).map_err(|_| {
        NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        )
    })
}

fn usize_u32(value: usize) -> Result<u32, NativeParticipationAotErrorV1> {
    u32::try_from(value).map_err(|_| {
        NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        )
    })
}

fn usize_u64(value: usize) -> Result<u64, NativeParticipationAotErrorV1> {
    u64::try_from(value).map_err(|_| {
        NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::PlanBytes,
        )
    })
}

fn write_u16(
    bytes: &mut [u8],
    offset: usize,
    value: u16,
) -> Result<(), NativeParticipationAotErrorV1> {
    bytes
        .get_mut(offset..offset + 2)
        .ok_or(NativeParticipationAotErrorV1::InvalidProgram(
            "u16 wire field",
        ))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(
    bytes: &mut [u8],
    offset: usize,
    value: u32,
) -> Result<(), NativeParticipationAotErrorV1> {
    bytes
        .get_mut(offset..offset + 4)
        .ok_or(NativeParticipationAotErrorV1::InvalidProgram(
            "u32 wire field",
        ))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(
    bytes: &mut [u8],
    offset: usize,
    value: u64,
) -> Result<(), NativeParticipationAotErrorV1> {
    bytes
        .get_mut(offset..offset + 8)
        .ok_or(NativeParticipationAotErrorV1::InvalidProgram(
            "u64 wire field",
        ))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

struct Construction<'a> {
    view: ExactSpanParticipationNativeV1View<'a>,
    assertions: &'a [AssertionKey],
    signatures: &'a [u64],
    byte_representatives: &'a [u8],
    limits: NativeParticipationAotLimitsV1,
    configurations: Vec<Vec<Thread>>,
    indices: HashMap<Vec<Thread>, u32>,
    transitions: Vec<u32>,
    accept_counts: Vec<u8>,
    build_work: usize,
}

impl Construction<'_> {
    fn work(&mut self, amount: usize) -> Result<(), NativeParticipationAotErrorV1> {
        self.build_work = self.build_work.checked_add(amount).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::BuildWork,
            ),
        )?;
        enforce(
            NativeParticipationAotResourceV1::BuildWork,
            self.build_work,
            self.limits.max_build_work,
        )
    }

    fn intern(&mut self, configuration: Vec<Thread>) -> Result<u32, NativeParticipationAotErrorV1> {
        if configuration.is_empty() {
            return Ok(DEAD_STATE);
        }
        if let Some(&state) = self.indices.get(&configuration) {
            return Ok(state);
        }
        let required = self.configurations.len().checked_add(1).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::DfaStates,
            ),
        )?;
        enforce(
            NativeParticipationAotResourceV1::DfaStates,
            required,
            self.limits.max_dfa_states,
        )?;
        let state = u32::try_from(self.configurations.len()).map_err(|_| {
            NativeParticipationAotErrorV1::Resource {
                resource: NativeParticipationAotResourceV1::DfaStates,
                required,
                limit: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
            }
        })?;
        self.configurations
            .try_reserve_exact(1)
            .map_err(|_| NativeParticipationAotErrorV1::Allocation("DFA configurations"))?;
        self.indices
            .try_reserve(1)
            .map_err(|_| NativeParticipationAotErrorV1::Allocation("DFA index"))?;
        let retained = clone_threads(&configuration, "DFA configuration")?;
        self.configurations.push(retained);
        self.indices.insert(configuration, state);
        Ok(state)
    }

    fn emit_state(&mut self, state: usize) -> Result<(), NativeParticipationAotErrorV1> {
        let configuration = self
            .configurations
            .get(state)
            .ok_or(NativeParticipationAotErrorV1::InvalidProgram("DFA state"))?;
        let configuration = clone_threads(configuration, "DFA state frontier")?;
        let acceptance = configuration
            .iter()
            .find_map(|thread| {
                matches!(
                    self.view.state(usize::try_from(thread.pc).ok()?),
                    Some(State::Match)
                )
                .then_some(*thread)
            })
            .map(|thread| {
                if thread.open != 0 || thread.participated & 1 == 0 {
                    return Err(NativeParticipationAotErrorV1::InvalidProgram(
                        "accepted participation path has malformed group zero",
                    ));
                }
                u8::try_from(thread.participated.count_ones()).map_err(|_| {
                    NativeParticipationAotErrorV1::InvalidProgram("participation count")
                })
            })
            .transpose()?
            .unwrap_or(NO_ACCEPT);
        self.accept_counts
            .try_reserve_exact(1)
            .map_err(|_| NativeParticipationAotErrorV1::Allocation("DFA accepts"))?;
        self.accept_counts.push(acceptance);
        let row_cells = self
            .byte_representatives
            .len()
            .checked_mul(self.signatures.len())
            .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::TransitionCells,
            ))?;
        let required = self.transitions.len().checked_add(row_cells).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::TransitionCells,
            ),
        )?;
        enforce(
            NativeParticipationAotResourceV1::TransitionCells,
            required,
            self.limits.max_transition_cells,
        )?;
        self.transitions
            .try_reserve_exact(row_cells)
            .map_err(|_| NativeParticipationAotErrorV1::Allocation("DFA transitions"))?;
        for &byte in self.byte_representatives {
            for signature in 0..self.signatures.len() {
                self.work(1)?;
                let mut output = Vec::new();
                let mut seen = false_vec(self.view.state_count(), "DFA transition seen set")?;
                for &thread in &configuration {
                    let Some(state) =
                        self.view.state(usize::try_from(thread.pc).map_err(|_| {
                            NativeParticipationAotErrorV1::InvalidProgram("thread pc")
                        })?)
                    else {
                        return Err(NativeParticipationAotErrorV1::InvalidProgram("thread pc"));
                    };
                    match state {
                        State::Match => {}
                        State::Byte { ranges, next } => {
                            self.work(ranges.len())?;
                            if ranges.iter().any(|&(lo, hi)| lo <= byte && byte <= hi) {
                                self.add_closure(
                                    &mut output,
                                    &mut seen,
                                    Thread {
                                        pc: next,
                                        open: thread.open,
                                        participated: thread.participated,
                                    },
                                    signature,
                                )?;
                            }
                        }
                        _ => {
                            return Err(NativeParticipationAotErrorV1::InvalidProgram(
                                "closed DFA frontier contains a zero-width state",
                            ));
                        }
                    }
                }
                let next = self.intern(output)?;
                self.transitions.push(next);
            }
        }
        Ok(())
    }

    fn add_closure(
        &mut self,
        output: &mut Vec<Thread>,
        seen: &mut [bool],
        initial: Thread,
        signature: usize,
    ) -> Result<(), NativeParticipationAotErrorV1> {
        let truth = *self.signatures.get(signature).ok_or(
            NativeParticipationAotErrorV1::InvalidProgram("assertion signature"),
        )?;
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(self.view.state_count())
            .map_err(|_| NativeParticipationAotErrorV1::Allocation("closure stack"))?;
        stack.push(initial);
        while let Some(mut thread) = stack.pop() {
            self.work(1)?;
            let pc = usize::try_from(thread.pc)
                .map_err(|_| NativeParticipationAotErrorV1::InvalidProgram("thread pc"))?;
            let mark = seen
                .get_mut(pc)
                .ok_or(NativeParticipationAotErrorV1::InvalidProgram("thread pc"))?;
            if *mark {
                continue;
            }
            *mark = true;
            match self
                .view
                .state(pc)
                .ok_or(NativeParticipationAotErrorV1::InvalidProgram("thread pc"))?
            {
                State::Byte { .. } | State::Match => {
                    output.try_reserve_exact(1).map_err(|_| {
                        NativeParticipationAotErrorV1::Allocation("closure frontier")
                    })?;
                    output.push(thread);
                }
                State::Fail => {}
                State::Epsilon { next } => {
                    thread.pc = next;
                    stack.push(thread);
                }
                State::Split { first, second } => {
                    stack.push(Thread {
                        pc: second,
                        open: thread.open,
                        participated: thread.participated,
                    });
                    thread.pc = first;
                    stack.push(thread);
                }
                State::Assert { assertion, next } => {
                    let key = AssertionKey::new(assertion);
                    let bit = self.assertions.iter().position(|&item| item == key).ok_or(
                        NativeParticipationAotErrorV1::InvalidProgram("assertion table"),
                    )?;
                    if truth & (1_u64 << bit) != 0 {
                        thread.pc = next;
                        stack.push(thread);
                    }
                }
                State::Save { slot, next } => {
                    let group = usize::from(slot) / 2;
                    if group >= self.view.layout().group_count() || group >= MAX_MASK_BITS {
                        return Err(NativeParticipationAotErrorV1::InvalidProgram(
                            "capture slot group",
                        ));
                    }
                    let bit = 1_u64 << group;
                    if slot.is_multiple_of(2) {
                        if thread.open & bit != 0 {
                            return Err(NativeParticipationAotErrorV1::InvalidProgram(
                                "capture group opened twice",
                            ));
                        }
                        thread.open |= bit;
                    } else {
                        if thread.open & bit == 0 {
                            return Err(NativeParticipationAotErrorV1::InvalidProgram(
                                "capture group closed while absent",
                            ));
                        }
                        thread.open &= !bit;
                        thread.participated |= bit;
                    }
                    thread.pc = next;
                    stack.push(thread);
                }
            }
        }
        Ok(())
    }
}

fn collect_assertions(
    view: ExactSpanParticipationNativeV1View<'_>,
    limits: NativeParticipationAotLimitsV1,
) -> Result<Vec<AssertionKey>, NativeParticipationAotErrorV1> {
    let mut assertions = Vec::new();
    for state in view.states() {
        let State::Assert { assertion, .. } = state else {
            continue;
        };
        let key = AssertionKey::new(assertion);
        if !assertions.contains(&key) {
            let required = assertions.len().checked_add(1).ok_or(
                NativeParticipationAotErrorV1::ArithmeticOverflow(
                    NativeParticipationAotResourceV1::Assertions,
                ),
            )?;
            enforce(
                NativeParticipationAotResourceV1::Assertions,
                required,
                limits.max_assertions.min(MAX_MASK_BITS),
            )?;
            assertions.try_reserve_exact(1).map_err(|_| {
                NativeParticipationAotErrorV1::Allocation("participation assertions")
            })?;
            assertions.push(key);
        }
    }
    Ok(assertions)
}

fn assertion_signatures(
    assertions: &[AssertionKey],
    limits: NativeParticipationAotLimitsV1,
) -> Result<Vec<u64>, NativeParticipationAotErrorV1> {
    let representatives = byte_representatives_for_assertions(assertions)?;
    let mut sides = Vec::new();
    let side_capacity = representatives
        .len()
        .checked_mul(UnicodeSide::ALL.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(NativeParticipationAotErrorV1::ArithmeticOverflow(
            NativeParticipationAotResourceV1::AssertionSignatures,
        ))?;
    sides
        .try_reserve_exact(side_capacity)
        .map_err(|_| NativeParticipationAotErrorV1::Allocation("boundary sides"))?;
    sides.push((None, UnicodeSide::NonWord));
    for &byte in &representatives {
        for unicode in UnicodeSide::ALL {
            sides.push((Some(byte), unicode));
        }
    }
    let mut signatures = Vec::new();
    for &(left, left_unicode) in &sides {
        for &(right, right_unicode) in &sides {
            let boundary = AbstractBoundary {
                left,
                right,
                left_unicode,
                right_unicode,
            };
            let truth = assertions
                .iter()
                .enumerate()
                .fold(0_u64, |mask, (bit, &item)| {
                    mask | (u64::from(abstract_assertion(item, boundary)) << bit)
                });
            if !signatures.contains(&truth) {
                let required = signatures.len().checked_add(1).ok_or(
                    NativeParticipationAotErrorV1::ArithmeticOverflow(
                        NativeParticipationAotResourceV1::AssertionSignatures,
                    ),
                )?;
                enforce(
                    NativeParticipationAotResourceV1::AssertionSignatures,
                    required,
                    limits.max_assertion_signatures,
                )?;
                signatures.try_reserve_exact(1).map_err(|_| {
                    NativeParticipationAotErrorV1::Allocation("assertion signatures")
                })?;
                signatures.push(truth);
            }
        }
    }
    if signatures.is_empty() {
        signatures.push(0);
    }
    signatures.sort_unstable();
    Ok(signatures)
}

fn byte_representatives_for_assertions(
    assertions: &[AssertionKey],
) -> Result<Vec<u8>, NativeParticipationAotErrorV1> {
    let mut classes: Vec<Vec<bool>> = Vec::new();
    let mut representatives = Vec::new();
    for byte in 0_u8..=u8::MAX {
        let signature_capacity = assertions.len().checked_mul(2).ok_or(
            NativeParticipationAotErrorV1::ArithmeticOverflow(
                NativeParticipationAotResourceV1::AssertionSignatures,
            ),
        )?;
        let mut signature = Vec::new();
        reserve_exact(
            &mut signature,
            signature_capacity,
            "assertion byte signature",
        )?;
        for &assertion in assertions {
            let left = AbstractBoundary {
                left: Some(byte),
                right: None,
                left_unicode: UnicodeSide::NonWord,
                right_unicode: UnicodeSide::NonWord,
            };
            let right = AbstractBoundary {
                left: None,
                right: Some(byte),
                left_unicode: UnicodeSide::NonWord,
                right_unicode: UnicodeSide::NonWord,
            };
            signature.push(abstract_assertion(assertion, left));
            signature.push(abstract_assertion(assertion, right));
        }
        if !classes.contains(&signature) {
            classes
                .try_reserve_exact(1)
                .map_err(|_| NativeParticipationAotErrorV1::Allocation("assertion byte classes"))?;
            representatives.try_reserve_exact(1).map_err(|_| {
                NativeParticipationAotErrorV1::Allocation("assertion byte representatives")
            })?;
            classes.push(signature);
            representatives.push(byte);
        }
    }
    Ok(representatives)
}

fn byte_classes(
    view: ExactSpanParticipationNativeV1View<'_>,
    limits: NativeParticipationAotLimitsV1,
) -> Result<([u8; 256], Vec<u8>), NativeParticipationAotErrorV1> {
    let mut class_map = [0_u8; 256];
    let mut signatures: Vec<Vec<bool>> = Vec::new();
    let mut representatives = Vec::new();
    let byte_state_count = view
        .states()
        .filter(|state| matches!(state, State::Byte { .. }))
        .count();
    for byte in 0_u8..=u8::MAX {
        let mut signature = Vec::new();
        reserve_exact(&mut signature, byte_state_count, "byte-class signature")?;
        for state in view.states() {
            if let State::Byte { ranges, .. } = state {
                signature.push(
                    ranges
                        .iter()
                        .any(|&(start, end)| start <= byte && byte <= end),
                );
            }
        }
        let class = if let Some(class) = signatures.iter().position(|item| item == &signature) {
            class
        } else {
            let required = signatures.len().checked_add(1).ok_or(
                NativeParticipationAotErrorV1::ArithmeticOverflow(
                    NativeParticipationAotResourceV1::ByteClasses,
                ),
            )?;
            enforce(
                NativeParticipationAotResourceV1::ByteClasses,
                required,
                limits.max_byte_classes.min(256),
            )?;
            signatures
                .try_reserve_exact(1)
                .map_err(|_| NativeParticipationAotErrorV1::Allocation("byte-class signatures"))?;
            representatives.try_reserve_exact(1).map_err(|_| {
                NativeParticipationAotErrorV1::Allocation("byte-class representatives")
            })?;
            signatures.push(signature);
            representatives.push(byte);
            required - 1
        };
        class_map[usize::from(byte)] = u8::try_from(class).map_err(|_| {
            NativeParticipationAotErrorV1::InvalidProgram("byte class exceeds V1 encoding")
        })?;
    }
    Ok((class_map, representatives))
}

fn abstract_assertion(assertion: AssertionKey, boundary: AbstractBoundary) -> bool {
    let left_ascii = boundary.left.is_some_and(is_ascii_word);
    let right_ascii = boundary.right.is_some_and(is_ascii_word);
    let left_word = boundary.left_unicode.word();
    let right_word = boundary.right_unicode.word();
    match assertion.kind {
        1 => boundary.left.is_none(),
        2 => boundary.right.is_none(),
        3 => boundary.left.is_none() || boundary.left == Some(b'\n'),
        4 => boundary.right.is_none() || boundary.right == Some(b'\n'),
        5 => boundary.left.is_none() || boundary.left == Some(assertion.data),
        6 => boundary.right.is_none() || boundary.right == Some(assertion.data),
        7 => {
            boundary.left.is_none()
                || boundary.left == Some(b'\n')
                || (boundary.left == Some(b'\r') && boundary.right != Some(b'\n'))
        }
        8 => {
            boundary.right.is_none()
                || boundary.right == Some(b'\r')
                || (boundary.right == Some(b'\n') && boundary.left != Some(b'\r'))
        }
        9 => left_ascii != right_ascii,
        10 => left_ascii == right_ascii,
        11 => !left_ascii && right_ascii,
        12 => left_ascii && !right_ascii,
        13 => !left_ascii,
        14 => !right_ascii,
        15 => left_word != right_word,
        16 => {
            boundary.left_unicode.valid()
                && boundary.right_unicode.valid()
                && left_word == right_word
        }
        17 => !left_word && right_word,
        18 => left_word && !right_word,
        19 => boundary.left_unicode.valid() && !left_word,
        20 => boundary.right_unicode.valid() && !right_word,
        _ => false,
    }
}

#[cfg(test)]
fn concrete_assertion(
    assertion: AssertionKey,
    haystack: &[u8],
    at: usize,
) -> Result<bool, &'static str> {
    if at > haystack.len() {
        return Err("assertion position");
    }
    let left = at
        .checked_sub(1)
        .and_then(|index| haystack.get(index))
        .copied();
    let right = haystack.get(at).copied();
    let left_ascii = left.is_some_and(is_ascii_word);
    let right_ascii = right.is_some_and(is_ascii_word);
    Ok(match assertion.kind {
        1 => at == 0,
        2 => at == haystack.len(),
        3 => at == 0 || left == Some(b'\n'),
        4 => at == haystack.len() || right == Some(b'\n'),
        5 => at == 0 || left == Some(assertion.data),
        6 => at == haystack.len() || right == Some(assertion.data),
        7 => at == 0 || left == Some(b'\n') || (left == Some(b'\r') && right != Some(b'\n')),
        8 => {
            at == haystack.len()
                || right == Some(b'\r')
                || (right == Some(b'\n') && left != Some(b'\r'))
        }
        9 => left_ascii != right_ascii,
        10 => left_ascii == right_ascii,
        11 => !left_ascii && right_ascii,
        12 => left_ascii && !right_ascii,
        13 => !left_ascii,
        14 => !right_ascii,
        15..=20 => UnicodeLookMatcher::matches_edge_kind_prevalidated(
            unicode_edge(assertion.kind).ok_or("Unicode assertion")?,
            haystack,
            at,
        )
        .ok_or("Unicode assertion")?,
        _ => return Err("assertion kind"),
    })
}

#[cfg(test)]
const fn unicode_edge(kind: u8) -> Option<EdgeKind> {
    match kind {
        15 => Some(EdgeKind::AssertWordUnicode),
        16 => Some(EdgeKind::AssertWordUnicodeNegate),
        17 => Some(EdgeKind::AssertWordStartUnicode),
        18 => Some(EdgeKind::AssertWordEndUnicode),
        19 => Some(EdgeKind::AssertWordStartHalfUnicode),
        20 => Some(EdgeKind::AssertWordEndHalfUnicode),
        _ => None,
    }
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn enforce(
    resource: NativeParticipationAotResourceV1,
    required: usize,
    limit: usize,
) -> Result<(), NativeParticipationAotErrorV1> {
    if required > limit {
        return Err(NativeParticipationAotErrorV1::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

fn reserve_exact<T>(
    values: &mut Vec<T>,
    capacity: usize,
    label: &'static str,
) -> Result<(), NativeParticipationAotErrorV1> {
    values
        .try_reserve_exact(capacity)
        .map_err(|_| NativeParticipationAotErrorV1::Allocation(label))
}

fn owned_string(
    value: &str,
    label: &'static str,
) -> Result<String, NativeParticipationAotErrorV1> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| NativeParticipationAotErrorV1::Allocation(label))?;
    owned.push_str(value);
    Ok(owned)
}

fn false_vec(len: usize, label: &'static str) -> Result<Vec<bool>, NativeParticipationAotErrorV1> {
    let mut values = Vec::new();
    reserve_exact(&mut values, len, label)?;
    values.resize(len, false);
    Ok(values)
}

fn clone_threads(
    threads: &[Thread],
    label: &'static str,
) -> Result<Vec<Thread>, NativeParticipationAotErrorV1> {
    let mut copy = Vec::new();
    reserve_exact(&mut copy, threads.len(), label)?;
    copy.extend_from_slice(threads);
    Ok(copy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CaptureCompileLimits, CaptureCompileRequest, CompileMode, CpuFeature, FeatureSet, Target,
        compile_captures,
    };
    use fre_capture_lab::{CaptureGroupSlot, SearchLimits, Span, Window};

    fn plan(pattern: &str) -> (crate::CompiledCaptureRegex, NativeParticipationDfaV1) {
        let mut compile_limits = CaptureCompileLimits::default();
        compile_limits.onepass.max_states = 0;
        let compiled = compile_captures(
            CaptureCompileRequest::new(pattern, Target::aarch64_macos())
                .mode(CompileMode::Fast)
                .limits(compile_limits),
        )
        .expect("capture compile");
        let view =
            compiled
                .capture_program()
                .exact_span_participation_native_v1_view(
                    ExactSpanParticipationNativeV1Limits::default(),
                )
                .expect("view")
                .expect("schema");
        let plan = NativeParticipationDfaV1::build(view, NativeParticipationAotLimitsV1::default())
            .expect("participation DFA");
        (compiled, plan)
    }

    fn oracle_count(
        compiled: &crate::CompiledCaptureRegex,
        haystack: &[u8],
        span: Span,
    ) -> Option<usize> {
        let capture = compiled.capture_program();
        let limits = SearchLimits::default();
        let mut workspace = capture
            .prepare_history_exact_workspace(haystack.len(), limits)
            .expect("history workspace");
        let mut slots = vec![CaptureGroupSlot::UNMATCHED; capture.schema().group_count()];
        let outcome = capture
            .captures_exact_slots_with_history_workspace(
                &mut workspace,
                haystack,
                Window {
                    start: 0,
                    end: haystack.len(),
                },
                span,
                &mut slots,
            )
            .expect("history replay");
        outcome
            .matched
            .then(|| slots.iter().filter(|slot| slot.span().is_some()).count())
    }

    #[test]
    fn generated_shapes_match_exact_history_participation() {
        let cases: &[(&str, &[&[u8]])] = &[
            (r"(?:(a)|(ab))(b)?", &[b"ab", b"a", b"zab"]),
            (r"(?m)^(?:(a+)|(b+))$", &[b"aaa", b"x\nbbb\ny"]),
            (r"(?:(a)?)+", &[b"aaa", b"", b"ba"]),
            (
                r"\b(?:(foo)|(bar))\b",
                &[b"foo", b"x foo!", "βfooβ".as_bytes()],
            ),
            (r"(?R)(?m:^((?:a|b)+)$)", &[b"a\r\n", b"x\r\nbb\r\n"]),
            (r"(?:(\xFF+)|([a-z]+))", &[b"\xFF\xFF", b"abc", b"x\xFFy"]),
        ];
        for &(pattern, haystacks) in cases {
            let (compiled, plan) = plan(pattern);
            for &haystack in haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let span = Span { start, end };
                        let expected = oracle_count(&compiled, haystack, span);
                        let actual = plan.execute(haystack, start, end).ok();
                        assert_eq!(
                            expected, actual,
                            "pattern={pattern:?} haystack={haystack:?} span={span:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn construction_resource_order_is_stable() {
        let (compiled, _) = plan(r"(?m)^(a|b)$");
        let view =
            compiled
                .capture_program()
                .exact_span_participation_native_v1_view(
                    ExactSpanParticipationNativeV1Limits::default(),
                )
                .unwrap()
                .unwrap();
        let error = NativeParticipationDfaV1::build(
            view,
            NativeParticipationAotLimitsV1 {
                max_assertions: 0,
                max_assertion_signatures: 0,
                max_byte_classes: 0,
                max_dfa_states: 0,
                max_transition_cells: 0,
                max_build_work: 0,
                max_plan_bytes: 0,
                ..NativeParticipationAotLimitsV1::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            NativeParticipationAotErrorV1::Resource {
                resource: NativeParticipationAotResourceV1::Assertions,
                ..
            }
        ));
    }

    #[test]
    fn target_feature_wire_bits_are_architecture_local() {
        let x86 = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Sse2).with(CpuFeature::X86Avx512F))
            .expect("x86 feature target");
        assert_eq!(
            crate::module::native_participation_feature_word_v1(x86).unwrap(),
            (1 << 0) | (1 << 2),
        );

        let aarch64 = Target::aarch64_linux()
            .with_features(
                FeatureSet::of(CpuFeature::Aarch64Asimd)
                    .with(CpuFeature::Aarch64Sve)
                    .with(CpuFeature::Aarch64Sve2),
            )
            .expect("AArch64 feature target");
        assert_eq!(aarch64.features.bits(), 7_u64 << 32);
        assert_eq!(
            crate::module::native_participation_feature_word_v1(aarch64).unwrap(),
            7,
        );
    }

    #[test]
    fn selected_aarch64_artifact_preserves_selector_and_has_no_helpers() {
        let target = Target::aarch64_macos()
            .with_features(
                FeatureSet::of(CpuFeature::Aarch64Asimd)
                    .with(CpuFeature::Aarch64Sve)
                    .with(CpuFeature::Aarch64Sve2),
            )
            .expect("ASIMD/SVE/SVE2 target");
        let compiled = compile_captures(CaptureCompileRequest::new(r"^((?:ab)+)(c)?$", target))
            .expect("capture compile");
        let ordinary_symbol = compiled.selector().module().entry_symbol().to_owned();
        let ordinary_symbols = compiled.selector().module().symbols().len();
        let ordinary_runtime: Vec<_> = compiled
            .selector()
            .module()
            .required_runtime_symbols()
            .collect();
        assert!(
            ordinary_runtime.is_empty(),
            "fixture needs a helper-free selector"
        );
        let artifact = compiled
            .emit_native_participation_aot_v1(NativeParticipationAotLimitsV1::default())
            .expect("participation artifact");
        assert_eq!(artifact.module().entry_symbol(), ordinary_symbol);
        assert_eq!(artifact.module().symbols().len(), ordinary_symbols + 2);
        assert!(
            artifact
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert_eq!(
            artifact.receipt().strategy,
            NativeParticipationAotStrategyV1::DfaAarch64
        );
        assert_eq!(artifact.receipt().semantic_runtime_calls, 0);
        assert_eq!(artifact.receipt().target.features.bits(), 7_u64 << 32);
        assert_eq!(read_wire_u32(artifact.bundle(), 36), Some(7));
        assert!(artifact.receipt().dfa_states > 0);
        assert!(artifact.receipt().transition_cells > 0);
        assert_eq!(
            artifact.receipt().scratch_bytes,
            NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES
        );
        assert!(artifact.authenticates_receipt());
        let bundle_index = artifact
            .module()
            .symbols()
            .iter()
            .position(|symbol| symbol.name == artifact.bundle_symbol())
            .unwrap();
        let kinds: Vec<_> = artifact
            .module()
            .relocations()
            .iter()
            .filter(|relocation| relocation.symbol == bundle_index)
            .map(|relocation| relocation.kind)
            .collect();
        assert_eq!(
            kinds,
            [
                crate::RelocationKind::Aarch64Page21,
                crate::RelocationKind::Aarch64PageOff12,
            ]
        );
    }

    #[test]
    fn selected_x86_64_artifact_uses_a_real_paired_native_leaf() {
        let compiled = compile_captures(CaptureCompileRequest::new(
            r"^((?:ab)+)(c)?$",
            Target::x86_64_linux(),
        ))
        .expect("capture compile");
        let artifact = compiled
            .emit_native_participation_aot_v1(NativeParticipationAotLimitsV1::default())
            .expect("x86 participation artifact");
        assert_eq!(
            artifact.receipt().strategy,
            NativeParticipationAotStrategyV1::DfaX86_64,
        );
        assert!(
            artifact
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(artifact.authenticates_receipt());
        let entry = module_symbol_bytes(artifact.module(), artifact.participation_entry_symbol())
            .expect("participation entry");
        assert!(entry.len() > 128, "selected leaf must not be a status stub");
        assert_ne!(entry, [0xb8, 3, 0, 0, 0, 0xc3]);
        let bundle_index = artifact
            .module()
            .symbols()
            .iter()
            .position(|symbol| symbol.name == artifact.bundle_symbol())
            .expect("bundle symbol");
        let relocations: Vec<_> = artifact
            .module()
            .relocations()
            .iter()
            .filter(|relocation| relocation.symbol == bundle_index)
            .map(|relocation| relocation.kind)
            .collect();
        assert_eq!(relocations, [crate::RelocationKind::X86PcRelative32]);
    }

    #[test]
    fn receipt_authentication_binds_route_geometry_and_object() {
        let mut artifact = compile_captures(CaptureCompileRequest::new(
            r"^((?:ab)+)(c)?$",
            Target::aarch64_macos(),
        ))
        .expect("capture compile")
        .emit_native_participation_aot_v1(NativeParticipationAotLimitsV1::default())
        .expect("participation artifact");
        let original = artifact.receipt;
        assert!(artifact.authenticates_receipt());

        artifact.receipt.groups = original.groups + 1;
        assert!(!artifact.authenticates_receipt());
        artifact.receipt = original;
        artifact.receipt.semantic_runtime_calls = 1;
        assert!(!artifact.authenticates_receipt());
        artifact.receipt = original;
        artifact.receipt.plan_bytes = original.plan_bytes + 1;
        assert!(!artifact.authenticates_receipt());
        artifact.receipt = original;
        artifact.receipt.build_work = original.build_work + 1;
        assert!(!artifact.authenticates_receipt());
        artifact.receipt = original;
        artifact.receipt.strategy = NativeParticipationAotStrategyV1::DfaX86_64;
        assert!(!artifact.authenticates_receipt());
        artifact.receipt = original;
        artifact.bundle_symbol.push('_');
        assert!(!artifact.authenticates_receipt());
        artifact.bundle_symbol.pop();
        artifact.participation_entry_symbol.push('_');
        assert!(!artifact.authenticates_receipt());
        artifact.participation_entry_symbol.pop();
        artifact.object[0] ^= 1;
        assert!(!artifact.authenticates_receipt());
        artifact.object[0] ^= 1;
        artifact.bundle[0] ^= 1;
        assert!(!artifact.authenticates_receipt());

        artifact.bundle[0] ^= 1;
        let helper_free_module = artifact.module.clone();
        artifact
            .module
            .inject_test_only_unresolved_runtime_dependency();
        assert!(!artifact.authenticates_receipt());

        artifact.module = helper_free_module;
        artifact
            .module
            .inject_test_only_runtime_program_dependency();
        assert!(!artifact.authenticates_receipt());
    }

    #[test]
    fn negative_bundle_and_object_caps_are_terminal_resources() {
        let compiled = compile_captures(CaptureCompileRequest::new(
            r"(?m)^((?:ab)+)$",
            Target::aarch64_macos(),
        ))
        .expect("capture compile");
        let error = compiled
            .emit_native_participation_aot_v1(NativeParticipationAotLimitsV1 {
                max_plan_bytes: NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES - 1,
                ..NativeParticipationAotLimitsV1::default()
            })
            .expect_err("negative plan cap must be terminal");
        assert!(matches!(
            error,
            NativeParticipationAotErrorV1::Resource {
                resource: NativeParticipationAotResourceV1::PlanBytes,
                required: NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES,
                limit,
            } if limit == NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES - 1
        ));

        let error = compiled
            .emit_native_participation_aot_v1(NativeParticipationAotLimitsV1 {
                max_object_bytes: 0,
                ..NativeParticipationAotLimitsV1::default()
            })
            .expect_err("object cap must be terminal");
        assert!(matches!(
            error,
            NativeParticipationAotErrorV1::Object(ObjectError::Resource {
                resource: crate::CompileResource::ObjectBytes,
                ..
            })
        ));
    }

    #[test]
    fn unsupported_assertion_gets_transactional_negative_entry() {
        let target = Target::aarch64_macos()
            .with_features(
                FeatureSet::of(CpuFeature::Aarch64Asimd)
                    .with(CpuFeature::Aarch64Sve)
                    .with(CpuFeature::Aarch64Sve2),
            )
            .expect("ASIMD/SVE/SVE2 target");
        let compiled = compile_captures(CaptureCompileRequest::new(
            r"(?m)^((?:ab)+)$",
            target,
        ))
        .expect("capture compile");
        let artifact = compiled
            .emit_native_participation_aot_v1(NativeParticipationAotLimitsV1::default())
            .expect("negative artifact");
        assert_eq!(
            artifact.receipt().strategy,
            NativeParticipationAotStrategyV1::NegativeEntry
        );
        assert_eq!(
            artifact.receipt().decline,
            Some(NativeParticipationAotDeclineV1::UnsupportedAssertion)
        );
        assert_eq!(read_wire_u32(artifact.bundle(), 36), Some(7));
        assert!(artifact.authenticates_receipt());
        let symbol = artifact
            .module()
            .symbols()
            .iter()
            .find(|symbol| symbol.name == artifact.participation_entry_symbol())
            .unwrap();
        let section = &artifact.module().sections()[symbol.section.unwrap()];
        let start = usize::try_from(symbol.offset).unwrap();
        let end = start + usize::try_from(symbol.size).unwrap();
        assert_eq!(
            &section.bytes()[start..end],
            &[0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]
        );
    }

    #[test]
    fn program_only_selector_dependency_gets_authenticated_negative_entry() {
        let mut compiled = compile_captures(CaptureCompileRequest::new(
            r"^((?:ab)+)(c)?$",
            Target::aarch64_macos(),
        ))
        .expect("capture compile");
        assert!(
            compiled
                .selector()
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(
            compiled
                .selector()
                .module()
                .required_runtime_program()
                .is_none()
        );

        compiled.inject_test_only_selector_runtime_program_dependency();
        assert!(
            compiled
                .selector()
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(
            compiled
                .selector()
                .module()
                .required_runtime_program()
                .is_some()
        );

        let artifact = compiled
            .emit_native_participation_aot_v1(NativeParticipationAotLimitsV1::default())
            .expect("negative artifact");
        assert_eq!(
            artifact.receipt().strategy,
            NativeParticipationAotStrategyV1::NegativeEntry
        );
        assert_eq!(
            artifact.receipt().decline,
            Some(NativeParticipationAotDeclineV1::SelectorRequiresRuntime)
        );
        assert!(artifact.authenticates_receipt());
    }

    #[cfg(any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "macos"),
    ))]
    fn run_linked_participation_harness(target: Target, compiler_arguments: &[&str], suffix: &str) {
        use std::{fmt::Write as _, fs, process::Command};

        let build = |pattern: &str| {
            let compiled = compile_captures(CaptureCompileRequest::new(pattern, target))
                .expect("compile linked participation fixture");
            let artifact = compiled
                .emit_native_participation_aot_v1(NativeParticipationAotLimitsV1::default())
                .expect("emit linked participation fixture");
            assert_ne!(
                artifact.receipt().strategy,
                NativeParticipationAotStrategyV1::NegativeEntry,
                "fixture unexpectedly declined: {pattern:?}",
            );
            assert!(
                artifact
                    .module()
                    .required_runtime_symbols()
                    .next()
                    .is_none()
            );
            artifact
        };
        let anchored = build(r"^((?:ab)+)(c)?$");
        let priority = build(r"(?:(a)|(ab))(b)?");
        let nullable = build(r"(a*)");
        let negative = compile_captures(CaptureCompileRequest::new(r"(?m)^((?:ab)+)$", target))
            .expect("compile negative participation fixture")
            .emit_native_participation_aot_v1(NativeParticipationAotLimitsV1::default())
            .expect("emit negative participation fixture");
        assert_eq!(
            negative.receipt().strategy,
            NativeParticipationAotStrategyV1::NegativeEntry,
        );

        let directory = std::env::temp_dir().join(format!(
            "fre-aot-native-participation-v1-{}-{suffix}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).expect("create participation harness directory");
        let artifacts = [
            ("anchored", &anchored),
            ("priority", &priority),
            ("nullable", &nullable),
            ("negative", &negative),
        ];
        let mut objects = Vec::new();
        let mut source = String::from(
            "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\
             typedef struct { const uint8_t *bundle; const uint8_t *haystack; size_t haystack_len; size_t match_start; size_t match_end; uint8_t *scratch; size_t scratch_len; size_t *count_out; } request_t;\n",
        );
        for (label, artifact) in artifacts {
            let object = directory.join(format!("{label}.o"));
            fs::write(&object, artifact.object()).expect("write participation object");
            objects.push(object);
            writeln!(
                source,
                "extern const uint8_t {}[];",
                artifact.bundle_symbol()
            )
            .expect("write bundle declaration");
            writeln!(
                source,
                "extern uint32_t {}(const request_t *);",
                artifact.participation_entry_symbol(),
            )
            .expect("write participation declaration");
        }
        writeln!(
            source,
            "#define ANCHORED_BUNDLE {}\n#define ANCHORED_ENTRY {}\n\
             #define PRIORITY_BUNDLE {}\n#define PRIORITY_ENTRY {}\n\
             #define NULLABLE_BUNDLE {}\n#define NULLABLE_ENTRY {}\n\
             #define NEGATIVE_ENTRY {}",
            anchored.bundle_symbol(),
            anchored.participation_entry_symbol(),
            priority.bundle_symbol(),
            priority.participation_entry_symbol(),
            nullable.bundle_symbol(),
            nullable.participation_entry_symbol(),
            negative.participation_entry_symbol(),
        )
        .expect("write participation aliases");
        source.push_str(
            r#"
int main(void) {
  static const uint8_t abab[] = {'a','b','a','b'};
  static const uint8_t ababc[] = {'a','b','a','b','c'};
  static const uint8_t ab[] = {'a','b'};
  static const uint8_t empty_owner[] = {0};
  uint64_t scratch[2] = {0x1111111111111111ULL, 0x2222222222222222ULL};
  size_t count = 99;
  request_t request = {ANCHORED_BUNDLE, abab, sizeof(abab), 0, 4,
                       (uint8_t *)scratch, sizeof(scratch), &count};
  uint32_t status = ANCHORED_ENTRY(&request);
  if (status != 1) return 100 + (int)status;
  if (count != 2) return 110 + (int)count;
  if (scratch[0] != 0x1111111111111111ULL ||
      scratch[1] != 0x2222222222222222ULL) return 10;

  request.haystack = ababc; request.haystack_len = sizeof(ababc);
  request.match_end = sizeof(ababc); count = 99;
  status = ANCHORED_ENTRY(&request);
  if (status != 1 || count != 3) return 11;

  request.haystack = abab; request.haystack_len = sizeof(abab); request.match_end = 2;
  request.count_out = (size_t *)&scratch[0];
  scratch[0] = 0x3333333333333333ULL;
  scratch[1] = 0x4444444444444444ULL;
  status = ANCHORED_ENTRY(&request);
  if (status != 3 || scratch[0] != 0x3333333333333333ULL ||
      scratch[1] != 0x4444444444444444ULL) return 12;

  request.match_end = 4; request.bundle = ab; request.count_out = &count; count = 66;
  scratch[0] = 0x1111111111111111ULL;
  scratch[1] = 0x2222222222222222ULL;
  status = ANCHORED_ENTRY(&request);
  if (status != 2 || count != 66 || scratch[0] != 0x1111111111111111ULL ||
      scratch[1] != 0x2222222222222222ULL) return 13;

  request.bundle = ANCHORED_BUNDLE; request.scratch_len = 15; count = 55;
  status = ANCHORED_ENTRY(&request);
  if (status != 2 || count != 55 || scratch[0] != 0x1111111111111111ULL ||
      scratch[1] != 0x2222222222222222ULL) return 14;

  request.scratch_len = sizeof(scratch); request.count_out = (size_t *)&scratch[0];
  status = ANCHORED_ENTRY(&request);
  if (status != 1 || scratch[0] != 2 ||
      scratch[1] != 0x2222222222222222ULL) return 15;

  union overlap_owner { uint64_t align[2]; uint8_t bytes[16]; } overlap = {
    .bytes = {'a','b','a','b'}
  };
  uint8_t overlap_before[16];
  memcpy(overlap_before, overlap.bytes, sizeof(overlap_before));
  count = 88;
  request = (request_t){ANCHORED_BUNDLE, overlap.bytes, 4, 0, 4,
                        overlap.bytes, sizeof(overlap.bytes), &count};
  status = ANCHORED_ENTRY(&request);
  if (status != 1 || count != 2 ||
      memcmp(overlap.bytes, overlap_before, sizeof(overlap_before)) != 0) return 16;

  count = 87;
  request = (request_t){ANCHORED_BUNDLE, abab, sizeof(abab), 0, 4,
                        (uint8_t *)(uintptr_t)ANCHORED_BUNDLE, 16, &count};
  status = ANCHORED_ENTRY(&request);
  if (status != 1 || count != 2) return 17;

  count = 86;
  request = (request_t){ANCHORED_BUNDLE, abab, sizeof(abab), 0, 4,
                        (uint8_t *)&request, 16, &count};
  uint8_t request_before[16];
  memcpy(request_before, &request, sizeof(request_before));
  status = ANCHORED_ENTRY(&request);
  if (status != 1 || count != 2 ||
      memcmp(&request, request_before, sizeof(request_before)) != 0) return 18;

  request = (request_t){PRIORITY_BUNDLE, ab, sizeof(ab), 0, 2,
                        (uint8_t *)scratch, sizeof(scratch), &count};
  count = 44;
  status = PRIORITY_ENTRY(&request);
  if (status != 1 || count != 3) return 20;

  request = (request_t){NULLABLE_BUNDLE, empty_owner, 0, 0, 0,
                        (uint8_t *)scratch, sizeof(scratch), &count};
  count = 33;
  status = NULLABLE_ENTRY(&request);
  if (status != 1 || count != 2) return 30;

  count = 22;
  request = (request_t){ANCHORED_BUNDLE, abab, sizeof(abab), 0, 4,
                        (uint8_t *)scratch, sizeof(scratch), &count};
  union request_owner {
    uint64_t align[9];
    unsigned char bytes[sizeof(request_t) + 8];
  } raw_request;
  memset(&raw_request, 0, sizeof(raw_request));
  memcpy(raw_request.bytes + 4, &request, sizeof(request));
  status = ANCHORED_ENTRY((const request_t *)(raw_request.bytes + 4));
  if (status != 2 || count != 22) return 40;

  union misaligned_owner { uint64_t align[3]; uint8_t bytes[24]; } misaligned;
  uint8_t misaligned_before[24];
  memset(misaligned.bytes, 0xa5, sizeof(misaligned.bytes));
  memcpy(misaligned_before, misaligned.bytes, sizeof(misaligned_before));
  count = 21;
  request.scratch = misaligned.bytes + 4; request.count_out = &count;
  status = ANCHORED_ENTRY(&request);
  if (status != 2 || count != 21 ||
      memcmp(misaligned.bytes, misaligned_before, sizeof(misaligned_before)) != 0) return 41;

  request.scratch = (uint8_t *)scratch;
  request.count_out = (size_t *)(misaligned.bytes + 4);
  status = ANCHORED_ENTRY(&request);
  if (status != 2 ||
      memcmp(misaligned.bytes, misaligned_before, sizeof(misaligned_before)) != 0) return 42;

  status = NEGATIVE_ENTRY(NULL);
  if (status != 10) return 50;
  return 0;
}
"#,
        );
        let source_path = directory.join("participation_v1.c");
        let executable = directory.join("participation_v1");
        fs::write(&source_path, source).expect("write participation harness");
        let status = Command::new("cc")
            .args(compiler_arguments)
            .arg("-O0")
            .arg(&source_path)
            .args(&objects)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("invoke host C compiler");
        assert!(status.success());
        let output = Command::new(&executable)
            .output()
            .expect("execute participation harness");
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        fs::remove_dir_all(directory).expect("remove participation harness directory");
    }

    #[cfg(any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "macos"),
    ))]
    #[test]
    #[ignore = "links and executes helper-free participation entries on the host ISA"]
    fn linked_host_participation_entry_is_exact_and_transactional() {
        let target = if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
            Target::x86_64_linux()
        } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
            Target::x86_64_macos()
        } else if cfg!(all(target_arch = "aarch64", target_os = "linux")) {
            Target::aarch64_linux()
        } else {
            Target::aarch64_macos()
        };
        run_linked_participation_harness(target, &[], "host");
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    #[ignore = "requires the installed Rosetta x86-64 execution environment"]
    fn linked_rosetta_participation_entry_exercises_x86_64_leaf() {
        run_linked_participation_harness(Target::x86_64_macos(), &["-arch", "x86_64"], "rosetta");
    }
}
