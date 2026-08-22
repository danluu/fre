//! Versioned helper-free native capture-result object ABI.
//!
//! V1 preserves the ordinary Span entry and adds identity-suffixed exact-span
//! materialization and capture-next entries. Selected entries are object-local
//! machine code and cannot call semantic runtime helpers. Unsupported shapes
//! receive explicit negative entries; they never replay `CaptureProgramV1`.

use core::fmt;

use fre_capture_lab::OnePassCaptureNativeV1View;
use sha2::{Digest, Sha256};

use crate::{
    Architecture, CallAbi, CaptureAuthenticationError, CaptureLevel, CompiledCaptureRegex,
    CompiledModule, ObjectError, ObjectFormat, OperatingSystem, Target, emit_object,
};

pub const NATIVE_CAPTURE_AOT_V1_MAGIC: [u8; 8] = *b"FRECAOT\x01";
pub const NATIVE_CAPTURE_AOT_V1_ABI_VERSION: u16 = 1;
pub const NATIVE_CAPTURE_AOT_V1_HEADER_BYTES: usize = 224;
pub const NATIVE_CAPTURE_AOT_V1_PLAN_OFFSET: usize = NATIVE_CAPTURE_AOT_V1_HEADER_BYTES;
pub const NATIVE_CAPTURE_AOT_V1_BUNDLE_DIGEST_OFFSET: usize = 176;
pub const NATIVE_CAPTURE_AOT_V1_OFFSET_BYTES: u8 = 8;
pub const NATIVE_CAPTURE_AOT_V1_ITER_STATE_BYTES: u32 = 24;
pub const NATIVE_CAPTURE_AOT_V1_ITER_STATE_ALIGN: u32 = 8;
pub const NATIVE_CAPTURE_AOT_V1_RESULT_SLOT_BYTES: u32 = 16;
pub const NATIVE_CAPTURE_AOT_V1_RESULT_SLOT_ALIGN: u32 = 8;
pub const NATIVE_CAPTURE_AOT_V1_FLAG_SPAN_SELECTOR: u32 = 1 << 0;
pub const NATIVE_CAPTURE_AOT_V1_FLAG_BYTE_SEMANTICS: u32 = 1 << 1;
pub const NATIVE_CAPTURE_AOT_V1_FLAG_NATIVE_ONEPASS: u32 = 1 << 2;
pub const NATIVE_CAPTURE_AOT_V1_FLAG_NEGATIVE_ENTRY: u32 = 1 << 3;
pub const NATIVE_CAPTURE_AOT_V1_CAPTURE_LEVEL_ALL: u8 = 1;
pub const NATIVE_CAPTURE_AOT_V1_STATUS_UNAVAILABLE: u32 = 10;
pub const NATIVE_CAPTURE_AOT_V1_UNSET: usize = usize::MAX;
pub const NATIVE_CAPTURE_AOT_V1_IDENTITY_DOMAIN: &[u8] = b"fre-aot-regex/native-capture-aot-v1\0";

const PLAN_MAGIC: [u8; 8] = *b"FRECAP1\0";
const PLAN_ABI_VERSION: u16 = 1;
const PLAN_HEADER_BYTES: usize = 112;
const PLAN_BYTE_CLASSES_OFFSET: usize = PLAN_HEADER_BYTES;
const PLAN_STATE_BYTES: usize = 8;
const PLAN_TRANSITION_BYTES: usize = 8;
const PLAN_DIGEST_OFFSET: usize = 72;
const PLAN_FLAG_DIRECT_TAG_MASKS: u32 = 1;
const PLAN_IDENTITY_DOMAIN: &[u8] = b"fre-aot-regex/native-capture-plan-v1\0";
const SELECTOR_DIGEST_OFFSET: usize = 80;
const CAPTURE_DIGEST_OFFSET: usize = 112;
const PLAN_BUNDLE_DIGEST_OFFSET: usize = 144;
const DIGEST_BYTES: usize = 32;
const BUNDLE_SYMBOL_PREFIX: &str = "fre_aot_regex_capture_bundle_v1_";
const NEXT_SYMBOL_PREFIX: &str = "fre_aot_regex_capture_next_v1_";
const MATERIALIZE_SYMBOL_PREFIX: &str = "fre_aot_regex_capture_materialize_v1_";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureAotLimitsV1 {
    pub max_bundle_bytes: usize,
    pub max_plan_bytes: usize,
    pub max_native_states: usize,
    pub max_native_transitions: usize,
    pub max_native_stack_bytes: usize,
    pub max_object_bytes: usize,
}

impl Default for NativeCaptureAotLimitsV1 {
    fn default() -> Self {
        Self {
            max_bundle_bytes: 64 * 1024 * 1024,
            max_plan_bytes: 32 * 1024 * 1024,
            max_native_states: 1_048_576,
            max_native_transitions: 4_194_304,
            max_native_stack_bytes: 256,
            // This also keeps every object-local AArch64 BL within its signed
            // 26-bit reach. Raising the cap may still fail hard at call patching.
            max_object_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum NativeCaptureAotStrategyV1 {
    NativeOnePassX86_64 = 1,
    NativeOnePassAarch64 = 2,
    NegativeEntry = 3,
}

impl NativeCaptureAotStrategyV1 {
    fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::NativeOnePassX86_64),
            2 => Some(Self::NativeOnePassAarch64),
            3 => Some(Self::NegativeEntry),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum NativeCaptureAotDeclineV1 {
    UnsupportedTarget = 1,
    SelectorRequiresRuntime = 2,
    NoOnePassPlan = 3,
    UnsupportedOnePassShape = 4,
    OrderedManyRequiresPatternId = 5,
}

impl NativeCaptureAotDeclineV1 {
    fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::UnsupportedTarget),
            2 => Some(Self::SelectorRequiresRuntime),
            3 => Some(Self::NoOnePassPlan),
            4 => Some(Self::UnsupportedOnePassShape),
            5 => Some(Self::OrderedManyRequiresPatternId),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureAotReceiptV1 {
    /// Exact object target included in the export identity.
    pub target: Target,
    pub strategy: NativeCaptureAotStrategyV1,
    pub decline: Option<NativeCaptureAotDeclineV1>,
    pub semantic_runtime_calls: usize,
    pub groups: usize,
    pub raw_tag_slots: usize,
    pub native_states: usize,
    pub native_transitions: usize,
    pub native_stack_bytes: usize,
    pub plan_bytes: usize,
    /// SHA-256 of the independently emitted selector object before the
    /// additive capture entries were appended.
    pub selector_object_sha256: [u8; DIGEST_BYTES],
    /// Digest of the complete capture bundle embedded in the object.
    pub bundle_sha256: [u8; DIGEST_BYTES],
    /// Target/native-selector-bound identity used by all three strong export
    /// names. This prevents cross-OS or feature-tier symbol collisions.
    pub export_identity_sha256: [u8; DIGEST_BYTES],
    /// SHA-256 of the complete emitted relocatable object, including both
    /// native entries, their local-call targets, plan relocations, and bundle.
    pub object_sha256: [u8; DIGEST_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureDescriptorV1 {
    abi_version: u16,
    flags: u32,
    total_bytes: usize,
    plan_bytes: usize,
    group_count: usize,
    slot_count: usize,
    state_size: u32,
    state_align: u32,
    result_slot_size: u32,
    result_slot_align: u32,
    capture_tag_slot_count: usize,
    strategy: NativeCaptureAotStrategyV1,
    decline: Option<NativeCaptureAotDeclineV1>,
    semantic_runtime_calls: usize,
    selector_sha256: [u8; DIGEST_BYTES],
    capture_sha256: [u8; DIGEST_BYTES],
    plan_sha256: [u8; DIGEST_BYTES],
    bundle_sha256: [u8; DIGEST_BYTES],
}

impl NativeCaptureDescriptorV1 {
    #[must_use]
    pub const fn abi_version(self) -> u16 {
        self.abi_version
    }
    #[must_use]
    pub const fn flags(self) -> u32 {
        self.flags
    }
    #[must_use]
    pub const fn total_bytes(self) -> usize {
        self.total_bytes
    }
    #[must_use]
    pub const fn plan_bytes(self) -> usize {
        self.plan_bytes
    }
    #[must_use]
    pub const fn group_count(self) -> usize {
        self.group_count
    }
    #[must_use]
    pub const fn slot_count(self) -> usize {
        self.slot_count
    }
    #[must_use]
    pub const fn state_size(self) -> u32 {
        self.state_size
    }
    #[must_use]
    pub const fn state_align(self) -> u32 {
        self.state_align
    }
    #[must_use]
    pub const fn result_slot_size(self) -> u32 {
        self.result_slot_size
    }
    #[must_use]
    pub const fn result_slot_align(self) -> u32 {
        self.result_slot_align
    }
    #[must_use]
    pub const fn capture_tag_slot_count(self) -> usize {
        self.capture_tag_slot_count
    }
    #[must_use]
    pub const fn strategy(self) -> NativeCaptureAotStrategyV1 {
        self.strategy
    }
    #[must_use]
    pub const fn decline(self) -> Option<NativeCaptureAotDeclineV1> {
        self.decline
    }
    #[must_use]
    pub const fn semantic_runtime_calls(self) -> usize {
        self.semantic_runtime_calls
    }
    #[must_use]
    pub const fn selector_sha256(self) -> [u8; DIGEST_BYTES] {
        self.selector_sha256
    }
    #[must_use]
    pub const fn capture_sha256(self) -> [u8; DIGEST_BYTES] {
        self.capture_sha256
    }
    #[must_use]
    pub const fn plan_sha256(self) -> [u8; DIGEST_BYTES] {
        self.plan_sha256
    }
    #[must_use]
    pub const fn bundle_sha256(self) -> [u8; DIGEST_BYTES] {
        self.bundle_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureBundleV1View<'a> {
    bytes: &'a [u8],
    plan: &'a [u8],
    descriptor: NativeCaptureDescriptorV1,
}

impl<'a> NativeCaptureBundleV1View<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, NativeCaptureBundleV1Error> {
        if bytes.len() < NATIVE_CAPTURE_AOT_V1_HEADER_BYTES {
            return Err(NativeCaptureBundleV1Error::Truncated);
        }
        if bytes[..8] != NATIVE_CAPTURE_AOT_V1_MAGIC {
            return Err(NativeCaptureBundleV1Error::BadMagic);
        }
        let abi_version = read_u16(bytes, 8)?;
        if abi_version != NATIVE_CAPTURE_AOT_V1_ABI_VERSION {
            return Err(NativeCaptureBundleV1Error::UnsupportedVersion(abi_version));
        }
        if usize::from(read_u16(bytes, 10)?) != NATIVE_CAPTURE_AOT_V1_HEADER_BYTES {
            return Err(NativeCaptureBundleV1Error::InvalidHeader("header bytes"));
        }
        let flags = read_u32(bytes, 12)?;
        let strategy = NativeCaptureAotStrategyV1::from_wire(read_u16(bytes, 68)?)
            .ok_or(NativeCaptureBundleV1Error::InvalidHeader("strategy"))?;
        let strategy_flag = match strategy {
            NativeCaptureAotStrategyV1::NativeOnePassX86_64 => {
                NATIVE_CAPTURE_AOT_V1_FLAG_NATIVE_ONEPASS
            }
            NativeCaptureAotStrategyV1::NativeOnePassAarch64 => {
                NATIVE_CAPTURE_AOT_V1_FLAG_NATIVE_ONEPASS
            }
            NativeCaptureAotStrategyV1::NegativeEntry => NATIVE_CAPTURE_AOT_V1_FLAG_NEGATIVE_ENTRY,
        };
        if flags
            != NATIVE_CAPTURE_AOT_V1_FLAG_SPAN_SELECTOR
                | NATIVE_CAPTURE_AOT_V1_FLAG_BYTE_SEMANTICS
                | strategy_flag
        {
            return Err(NativeCaptureBundleV1Error::UnknownFlags(flags));
        }
        let total_bytes = read_usize_u64(bytes, 16, "total bytes")?;
        let plan_offset = read_usize_u64(bytes, 24, "plan offset")?;
        let plan_bytes = read_usize_u64(bytes, 32, "plan bytes")?;
        if total_bytes != bytes.len() {
            return Err(NativeCaptureBundleV1Error::ExtentMismatch {
                declared: total_bytes,
                actual: bytes.len(),
            });
        }
        if plan_offset != NATIVE_CAPTURE_AOT_V1_PLAN_OFFSET
            || plan_offset.checked_add(plan_bytes) != Some(total_bytes)
        {
            return Err(NativeCaptureBundleV1Error::InvalidHeader("plan extent"));
        }
        let group_count = usize_from_u32(bytes, 40, "groups")?;
        let slot_count = usize_from_u32(bytes, 44, "slots")?;
        let state_size = read_u32(bytes, 48)?;
        let state_align = read_u32(bytes, 52)?;
        let result_slot_size = read_u32(bytes, 56)?;
        let result_slot_align = read_u32(bytes, 60)?;
        let capture_tag_slot_count = usize_from_u32(bytes, 64, "tag slots")?;
        let decline_wire = read_u16(bytes, 70)?;
        let decline = if decline_wire == 0 {
            None
        } else {
            Some(
                NativeCaptureAotDeclineV1::from_wire(decline_wire)
                    .ok_or(NativeCaptureBundleV1Error::InvalidHeader("decline"))?,
            )
        };
        let semantic_runtime_calls = usize_from_u32(bytes, 72, "semantic calls")?;
        if read_u32(bytes, 76)? != 0 || bytes[208..224] != [0; 16] {
            return Err(NativeCaptureBundleV1Error::NonZeroReserved);
        }
        if group_count == 0
            || slot_count != group_count
            || group_count.checked_mul(2) != Some(capture_tag_slot_count)
            || state_size != NATIVE_CAPTURE_AOT_V1_ITER_STATE_BYTES
            || state_align != NATIVE_CAPTURE_AOT_V1_ITER_STATE_ALIGN
            || result_slot_size != NATIVE_CAPTURE_AOT_V1_RESULT_SLOT_BYTES
            || result_slot_align != NATIVE_CAPTURE_AOT_V1_RESULT_SLOT_ALIGN
            || semantic_runtime_calls != 0
        {
            return Err(NativeCaptureBundleV1Error::InvalidHeader("ABI geometry"));
        }
        match strategy {
            NativeCaptureAotStrategyV1::NativeOnePassX86_64
            | NativeCaptureAotStrategyV1::NativeOnePassAarch64
                if decline.is_none() && plan_bytes != 0 => {}
            NativeCaptureAotStrategyV1::NegativeEntry if decline.is_some() && plan_bytes == 0 => {}
            _ => {
                return Err(NativeCaptureBundleV1Error::InvalidHeader(
                    "strategy payload",
                ));
            }
        }
        let selector_sha256 = read_digest(bytes, SELECTOR_DIGEST_OFFSET)?;
        let capture_sha256 = read_digest(bytes, CAPTURE_DIGEST_OFFSET)?;
        let plan_sha256 = read_digest(bytes, PLAN_BUNDLE_DIGEST_OFFSET)?;
        let bundle_sha256 = read_digest(bytes, NATIVE_CAPTURE_AOT_V1_BUNDLE_DIGEST_OFFSET)?;
        if bundle_digest(bytes)? != bundle_sha256 {
            return Err(NativeCaptureBundleV1Error::DigestMismatch);
        }
        let plan = bytes
            .get(plan_offset..total_bytes)
            .ok_or(NativeCaptureBundleV1Error::Truncated)?;
        if matches!(
            strategy,
            NativeCaptureAotStrategyV1::NativeOnePassX86_64
                | NativeCaptureAotStrategyV1::NativeOnePassAarch64
        ) {
            validate_plan(plan, group_count, capture_tag_slot_count, plan_sha256)?;
        } else if plan_sha256 != [0; DIGEST_BYTES] {
            return Err(NativeCaptureBundleV1Error::InvalidHeader(
                "negative plan digest",
            ));
        }
        Ok(Self {
            bytes,
            plan,
            descriptor: NativeCaptureDescriptorV1 {
                abi_version,
                flags,
                total_bytes,
                plan_bytes,
                group_count,
                slot_count,
                state_size,
                state_align,
                result_slot_size,
                result_slot_align,
                capture_tag_slot_count,
                strategy,
                decline,
                semantic_runtime_calls,
                selector_sha256,
                capture_sha256,
                plan_sha256,
                bundle_sha256,
            },
        })
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    #[must_use]
    pub const fn native_plan_bytes(self) -> &'a [u8] {
        self.plan
    }
    #[must_use]
    pub const fn descriptor(self) -> NativeCaptureDescriptorV1 {
        self.descriptor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeCaptureBundleV1Error {
    Truncated,
    BadMagic,
    UnsupportedVersion(u16),
    UnknownFlags(u32),
    NonZeroReserved,
    ExtentMismatch { declared: usize, actual: usize },
    DigestMismatch,
    InvalidHeader(&'static str),
    ArithmeticOverflow(&'static str),
}

impl fmt::Display for NativeCaptureBundleV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid native capture AOT V1 bundle: {self:?}")
    }
}

impl std::error::Error for NativeCaptureBundleV1Error {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCaptureAotArtifactV1 {
    module: CompiledModule,
    object: Box<[u8]>,
    bundle: Box<[u8]>,
    bundle_symbol: String,
    selector_entry_symbol: String,
    capture_next_symbol: String,
    capture_materialize_symbol: String,
    descriptor: NativeCaptureDescriptorV1,
    receipt: NativeCaptureAotReceiptV1,
}

impl NativeCaptureAotArtifactV1 {
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
    pub fn capture_next_symbol(&self) -> &str {
        &self.capture_next_symbol
    }
    #[must_use]
    pub fn capture_materialize_symbol(&self) -> &str {
        &self.capture_materialize_symbol
    }
    #[must_use]
    pub const fn descriptor(&self) -> NativeCaptureDescriptorV1 {
        self.descriptor
    }
    #[must_use]
    pub const fn receipt(&self) -> NativeCaptureAotReceiptV1 {
        self.receipt
    }

    /// Recompute the compiler-owned bundle, route-name, and object receipt.
    ///
    /// The artifact has no public mutation API, but adapters can use this
    /// check immediately before publishing paths or persisted bytes. It binds
    /// the exact selector object, target/features, bundle, identity-suffixed
    /// entries, their relocation topology, and the final object bytes.
    #[must_use]
    pub fn authenticates_receipt(&self) -> bool {
        native_capture_artifact_authenticates(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeCaptureAotError {
    Authentication(CaptureAuthenticationError),
    Object(ObjectError),
    Resource {
        resource: &'static str,
        required: usize,
        limit: usize,
    },
    Allocation(&'static str),
    ArithmeticOverflow(&'static str),
    InternalInvariant(&'static str),
}

impl fmt::Display for NativeCaptureAotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native capture AOT emission failed: {self:?}")
    }
}

impl std::error::Error for NativeCaptureAotError {}

impl From<ObjectError> for NativeCaptureAotError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeCapturePlanGeometryV1 {
    pub bundle_plan_offset: usize,
    pub byte_classes_offset: usize,
    pub states_offset: usize,
    pub transitions_offset: usize,
    pub state_count: usize,
    pub alphabet_len: usize,
    pub start_state: u32,
    pub group_count: usize,
    pub tag_slot_count: usize,
    pub native_stack_bytes: usize,
}

pub(crate) fn emit_native_capture_aot_v1(
    compiled: &CompiledCaptureRegex,
    limits: NativeCaptureAotLimitsV1,
) -> Result<NativeCaptureAotArtifactV1, NativeCaptureAotError> {
    emit_native_capture_aot_v1_impl(compiled, limits, None)
}

pub(crate) fn emit_native_ordered_many_capture_negative_aot_v1(
    compiled: &CompiledCaptureRegex,
    limits: NativeCaptureAotLimitsV1,
) -> Result<NativeCaptureAotArtifactV1, NativeCaptureAotError> {
    emit_native_capture_aot_v1_impl(
        compiled,
        limits,
        Some(NativeCaptureAotDeclineV1::OrderedManyRequiresPatternId),
    )
}

fn emit_native_capture_aot_v1_impl(
    compiled: &CompiledCaptureRegex,
    limits: NativeCaptureAotLimitsV1,
    forced_decline: Option<NativeCaptureAotDeclineV1>,
) -> Result<NativeCaptureAotArtifactV1, NativeCaptureAotError> {
    compiled
        .authenticate()
        .map_err(NativeCaptureAotError::Authentication)?;
    let identity = compiled.receipt().identity;
    if identity.level() != CaptureLevel::All
        || identity.groups() == 0
        || identity.groups().checked_mul(2) != Some(identity.slots())
    {
        return Err(NativeCaptureAotError::InternalInvariant("capture schema"));
    }
    let candidate = if let Some(reason) = forced_decline {
        NativeCandidate::Declined(reason)
    } else {
        select_native_candidate(compiled, limits)?
    };
    let (strategy, decline, plan, geometry) = match candidate {
        NativeCandidate::Selected {
            strategy,
            plan,
            geometry,
        } => (strategy, None, plan, Some(geometry)),
        NativeCandidate::Declined(reason) => (
            NativeCaptureAotStrategyV1::NegativeEntry,
            Some(reason),
            Vec::new(),
            None,
        ),
    };
    let mut receipt = if let Some(geometry) = geometry {
        NativeCaptureAotReceiptV1 {
            target: compiled.selector().module().target(),
            strategy,
            decline,
            semantic_runtime_calls: 0,
            groups: geometry.group_count,
            raw_tag_slots: geometry.tag_slot_count,
            native_states: geometry.state_count,
            native_transitions: geometry
                .state_count
                .checked_mul(geometry.alphabet_len)
                .ok_or(NativeCaptureAotError::ArithmeticOverflow(
                    "transition receipt",
                ))?,
            native_stack_bytes: geometry.native_stack_bytes,
            plan_bytes: plan.len(),
            selector_object_sha256: [0; DIGEST_BYTES],
            bundle_sha256: [0; DIGEST_BYTES],
            export_identity_sha256: [0; DIGEST_BYTES],
            object_sha256: [0; DIGEST_BYTES],
        }
    } else {
        NativeCaptureAotReceiptV1 {
            target: compiled.selector().module().target(),
            strategy,
            decline,
            semantic_runtime_calls: 0,
            groups: identity.groups(),
            raw_tag_slots: identity.slots(),
            native_states: 0,
            native_transitions: 0,
            native_stack_bytes: 0,
            plan_bytes: 0,
            selector_object_sha256: [0; DIGEST_BYTES],
            bundle_sha256: [0; DIGEST_BYTES],
            export_identity_sha256: [0; DIGEST_BYTES],
            object_sha256: [0; DIGEST_BYTES],
        }
    };
    let bundle = encode_bundle(compiled, strategy, decline, &plan, limits.max_bundle_bytes)?;
    let descriptor = NativeCaptureBundleV1View::from_bytes(&bundle)
        .map_err(|_| NativeCaptureAotError::InternalInvariant("fresh bundle closure"))?
        .descriptor();
    receipt.bundle_sha256 = descriptor.bundle_sha256();
    let selector_entry_symbol = compiled.selector().module().entry_symbol().to_owned();
    let selector_object_sha256: [u8; DIGEST_BYTES] =
        Sha256::digest(compiled.selector().object()).into();
    receipt.selector_object_sha256 = selector_object_sha256;
    let digest = native_export_digest(
        descriptor.bundle_sha256(),
        compiled.selector().module().target(),
        &selector_entry_symbol,
        selector_object_sha256,
    )?;
    receipt.export_identity_sha256 = digest;
    let bundle_symbol = crate::module::identity_symbol(BUNDLE_SYMBOL_PREFIX, &digest)?;
    let capture_next_symbol = crate::module::identity_symbol(NEXT_SYMBOL_PREFIX, &digest)?;
    let capture_materialize_symbol =
        crate::module::identity_symbol(MATERIALIZE_SYMBOL_PREFIX, &digest)?;
    let module = compiled
        .selector()
        .module()
        .clone()
        .append_native_capture_exports_v1(
            &bundle_symbol,
            &bundle,
            &capture_next_symbol,
            &capture_materialize_symbol,
            geometry,
        )?;
    if module.entry_symbol() != selector_entry_symbol {
        return Err(NativeCaptureAotError::InternalInvariant(
            "ordinary entry changed",
        ));
    }
    if !native_capture_module_extension_closes(
        compiled.selector().module(),
        &module,
        &bundle,
        &bundle_symbol,
        &capture_next_symbol,
        &capture_materialize_symbol,
        strategy,
    ) {
        return Err(NativeCaptureAotError::InternalInvariant(
            "native capture module extension did not close",
        ));
    }
    let object = emit_object(
        &module,
        ObjectFormat::for_target(module.target()),
        limits.max_object_bytes,
    )?
    .into_boxed_slice();
    receipt.object_sha256 = Sha256::digest(&object).into();
    let artifact = NativeCaptureAotArtifactV1 {
        module,
        object,
        bundle: bundle.into_boxed_slice(),
        bundle_symbol,
        selector_entry_symbol,
        capture_next_symbol,
        capture_materialize_symbol,
        descriptor,
        receipt,
    };
    if !artifact.authenticates_receipt() {
        return Err(NativeCaptureAotError::InternalInvariant(
            "native capture artifact receipt did not close",
        ));
    }
    Ok(artifact)
}

fn native_export_digest(
    bundle_sha256: [u8; DIGEST_BYTES],
    target: Target,
    selector_entry_symbol: &str,
    selector_object_sha256: [u8; DIGEST_BYTES],
) -> Result<[u8; DIGEST_BYTES], NativeCaptureAotError> {
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-regex/native-capture-export-v1\0");
    digest.update(bundle_sha256);
    digest.update([
        match target.architecture {
            Architecture::X86_64 => 1,
            Architecture::Aarch64 => 2,
        },
        match target.operating_system {
            OperatingSystem::Linux => 1,
            OperatingSystem::Macos => 2,
        },
        match target.abi {
            CallAbi::SystemV => 1,
            CallAbi::Aapcs64 => 2,
        },
    ]);
    digest.update(target.features.bits().to_le_bytes());
    digest.update(selector_object_sha256);
    digest.update(
        u64::try_from(selector_entry_symbol.len())
            .map_err(|_| NativeCaptureAotError::ArithmeticOverflow("selector symbol identity"))?
            .to_le_bytes(),
    );
    digest.update(selector_entry_symbol.as_bytes());
    Ok(digest.finalize().into())
}

fn native_capture_module_extension_closes(
    selector: &CompiledModule,
    extended: &CompiledModule,
    bundle: &[u8],
    bundle_symbol: &str,
    next_symbol: &str,
    materialize_symbol: &str,
    strategy: NativeCaptureAotStrategyV1,
) -> bool {
    if selector.target() != extended.target()
        || selector.entry_symbol() != extended.entry_symbol()
        || selector.sections().len() != extended.sections().len()
        || extended.symbols().len()
            != selector
                .symbols()
                .len()
                .checked_add(3)
                .unwrap_or(usize::MAX)
    {
        return false;
    }
    for (before, after) in selector.sections().iter().zip(extended.sections()) {
        if before.name != after.name
            || before.kind != after.kind
            || before.alignment != after.alignment
            || !after.bytes().starts_with(before.bytes())
        {
            return false;
        }
    }
    if !extended.symbols().starts_with(selector.symbols())
        || !extended.relocations().starts_with(selector.relocations())
        || !selector
            .required_runtime_symbols()
            .eq(extended.required_runtime_symbols())
    {
        return false;
    }
    let new_relocations = &extended.relocations()[selector.relocations().len()..];
    let expected_relocations = match strategy {
        NativeCaptureAotStrategyV1::NativeOnePassX86_64 => 1,
        NativeCaptureAotStrategyV1::NativeOnePassAarch64 => 2,
        NativeCaptureAotStrategyV1::NegativeEntry => 0,
    };
    new_relocations.len() == expected_relocations
        && native_capture_routes_close(
            extended,
            bundle,
            bundle_symbol,
            next_symbol,
            materialize_symbol,
            strategy,
            Some(new_relocations),
        )
}

fn native_capture_artifact_authenticates(artifact: &NativeCaptureAotArtifactV1) -> bool {
    let Ok(view) = NativeCaptureBundleV1View::from_bytes(&artifact.bundle) else {
        return false;
    };
    let descriptor = view.descriptor();
    if descriptor != artifact.descriptor
        || artifact.receipt.target != artifact.module.target()
        || artifact.receipt.strategy != descriptor.strategy()
        || artifact.receipt.decline != descriptor.decline()
        || artifact.receipt.semantic_runtime_calls != descriptor.semantic_runtime_calls()
        || artifact.receipt.groups != descriptor.group_count()
        || artifact.receipt.raw_tag_slots != descriptor.capture_tag_slot_count()
        || artifact.receipt.plan_bytes != descriptor.plan_bytes()
        || artifact.receipt.bundle_sha256 != descriptor.bundle_sha256()
        || artifact.module.entry_symbol() != artifact.selector_entry_symbol
    {
        return false;
    }
    let expected_object_sha256: [u8; DIGEST_BYTES] = Sha256::digest(&artifact.object).into();
    if artifact.receipt.object_sha256 != expected_object_sha256 {
        return false;
    }
    let Ok(export_identity_sha256) = native_export_digest(
        descriptor.bundle_sha256(),
        artifact.receipt.target,
        &artifact.selector_entry_symbol,
        artifact.receipt.selector_object_sha256,
    ) else {
        return false;
    };
    if artifact.receipt.export_identity_sha256 != export_identity_sha256
        || !identity_symbol_matches(
            &artifact.bundle_symbol,
            BUNDLE_SYMBOL_PREFIX,
            &export_identity_sha256,
        )
        || !identity_symbol_matches(
            &artifact.capture_next_symbol,
            NEXT_SYMBOL_PREFIX,
            &export_identity_sha256,
        )
        || !identity_symbol_matches(
            &artifact.capture_materialize_symbol,
            MATERIALIZE_SYMBOL_PREFIX,
            &export_identity_sha256,
        )
    {
        return false;
    }
    let (states, transitions, stack_bytes) = if view.native_plan_bytes().is_empty() {
        (0, 0, 0)
    } else {
        let plan = view.native_plan_bytes();
        let Ok(states) = usize_from_u32(plan, 48, "receipt states") else {
            return false;
        };
        let Ok(alphabet) = usize_from_u32(plan, 52, "receipt alphabet") else {
            return false;
        };
        let Some(transitions) = states.checked_mul(alphabet) else {
            return false;
        };
        let Some(stack_bytes) = descriptor
            .capture_tag_slot_count()
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(15))
            .map(|bytes| bytes & !15)
        else {
            return false;
        };
        (states, transitions, stack_bytes)
    };
    if artifact.receipt.native_states != states
        || artifact.receipt.native_transitions != transitions
        || artifact.receipt.native_stack_bytes != stack_bytes
    {
        return false;
    }
    native_capture_routes_close(
        &artifact.module,
        &artifact.bundle,
        &artifact.bundle_symbol,
        &artifact.capture_next_symbol,
        &artifact.capture_materialize_symbol,
        artifact.receipt.strategy,
        None,
    )
}

fn native_capture_routes_close(
    module: &CompiledModule,
    bundle: &[u8],
    bundle_symbol_name: &str,
    next_symbol_name: &str,
    materialize_symbol_name: &str,
    strategy: NativeCaptureAotStrategyV1,
    exact_new_relocations: Option<&[crate::ModuleRelocation]>,
) -> bool {
    let Some((bundle_index, bundle_symbol)) = module
        .symbols()
        .iter()
        .enumerate()
        .find(|(_, symbol)| symbol.name == bundle_symbol_name)
    else {
        return false;
    };
    let Some((_, next_symbol)) = module
        .symbols()
        .iter()
        .enumerate()
        .find(|(_, symbol)| symbol.name == next_symbol_name)
    else {
        return false;
    };
    let Some((_, materialize_symbol)) = module
        .symbols()
        .iter()
        .enumerate()
        .find(|(_, symbol)| symbol.name == materialize_symbol_name)
    else {
        return false;
    };
    if bundle_symbol.binding != crate::SymbolBinding::Global
        || bundle_symbol.kind != crate::SymbolKind::Object
        || next_symbol.binding != crate::SymbolBinding::Global
        || next_symbol.kind != crate::SymbolKind::Function
        || materialize_symbol.binding != crate::SymbolBinding::Global
        || materialize_symbol.kind != crate::SymbolKind::Function
        || module_symbol_bytes(module, bundle_symbol) != Some(bundle)
        || module_symbol_bytes(module, next_symbol).is_none_or(<[u8]>::is_empty)
        || module_symbol_bytes(module, materialize_symbol).is_none_or(<[u8]>::is_empty)
    {
        return false;
    }
    let relocation_is_in = |relocation: &crate::ModuleRelocation, symbol: &crate::ModuleSymbol| {
        let Some(section) = symbol.section else {
            return false;
        };
        let Some(end) = symbol.offset.checked_add(symbol.size) else {
            return false;
        };
        relocation.section == section
            && relocation.offset >= symbol.offset
            && relocation.offset < end
    };
    if module
        .relocations()
        .iter()
        .any(|relocation| relocation_is_in(relocation, next_symbol))
    {
        return false;
    }
    let mut materialize_relocations = module
        .relocations()
        .iter()
        .filter(|relocation| relocation_is_in(relocation, materialize_symbol));
    let expected_kinds: &[crate::RelocationKind] = match strategy {
        NativeCaptureAotStrategyV1::NativeOnePassX86_64 => {
            &[crate::RelocationKind::X86PcRelative32]
        }
        NativeCaptureAotStrategyV1::NativeOnePassAarch64 => &[
            crate::RelocationKind::Aarch64Page21,
            crate::RelocationKind::Aarch64PageOff12,
        ],
        NativeCaptureAotStrategyV1::NegativeEntry => &[],
    };
    for expected in expected_kinds {
        let Some(relocation) = materialize_relocations.next() else {
            return false;
        };
        if relocation.symbol != bundle_index || relocation.kind != *expected {
            return false;
        }
    }
    if materialize_relocations.next().is_some() {
        return false;
    }
    exact_new_relocations.is_none_or(|relocations| {
        relocations.len() == expected_kinds.len()
            && relocations
                .iter()
                .all(|relocation| relocation_is_in(relocation, materialize_symbol))
    })
}

fn module_symbol_bytes<'a>(
    module: &'a CompiledModule,
    symbol: &crate::ModuleSymbol,
) -> Option<&'a [u8]> {
    let section = module.sections().get(symbol.section?)?;
    let start = usize::try_from(symbol.offset).ok()?;
    let size = usize::try_from(symbol.size).ok()?;
    section.bytes().get(start..start.checked_add(size)?)
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

enum NativeCandidate {
    Selected {
        strategy: NativeCaptureAotStrategyV1,
        plan: Vec<u8>,
        geometry: NativeCapturePlanGeometryV1,
    },
    Declined(NativeCaptureAotDeclineV1),
}

fn select_native_candidate(
    compiled: &CompiledCaptureRegex,
    limits: NativeCaptureAotLimitsV1,
) -> Result<NativeCandidate, NativeCaptureAotError> {
    if compiled
        .selector()
        .module()
        .required_runtime_symbols()
        .next()
        .is_some()
    {
        return Ok(NativeCandidate::Declined(
            NativeCaptureAotDeclineV1::SelectorRequiresRuntime,
        ));
    }
    let Some(onepass) = compiled.onepass_plan() else {
        return Ok(NativeCandidate::Declined(
            NativeCaptureAotDeclineV1::NoOnePassPlan,
        ));
    };
    let Some(view) = onepass.native_v1_view() else {
        return Ok(NativeCandidate::Declined(
            NativeCaptureAotDeclineV1::UnsupportedOnePassShape,
        ));
    };
    let strategy = match compiled.selector().module().target().architecture {
        Architecture::X86_64 => NativeCaptureAotStrategyV1::NativeOnePassX86_64,
        Architecture::Aarch64 => NativeCaptureAotStrategyV1::NativeOnePassAarch64,
    };
    encode_plan(view, limits).map(|(plan, geometry)| NativeCandidate::Selected {
        strategy,
        plan,
        geometry,
    })
}

fn encode_plan(
    view: OnePassCaptureNativeV1View<'_>,
    limits: NativeCaptureAotLimitsV1,
) -> Result<(Vec<u8>, NativeCapturePlanGeometryV1), NativeCaptureAotError> {
    enforce(
        "native capture states",
        view.state_count(),
        limits.max_native_states,
    )?;
    enforce(
        "native capture transitions",
        view.transition_count(),
        limits.max_native_transitions,
    )?;
    let states_offset = PLAN_BYTE_CLASSES_OFFSET
        .checked_add(256)
        .ok_or(NativeCaptureAotError::ArithmeticOverflow("state offset"))?;
    let transitions_offset = states_offset
        .checked_add(
            view.state_count()
                .checked_mul(PLAN_STATE_BYTES)
                .ok_or(NativeCaptureAotError::ArithmeticOverflow("state extent"))?,
        )
        .ok_or(NativeCaptureAotError::ArithmeticOverflow(
            "transition offset",
        ))?;
    let total_bytes = transitions_offset
        .checked_add(
            view.transition_count()
                .checked_mul(PLAN_TRANSITION_BYTES)
                .ok_or(NativeCaptureAotError::ArithmeticOverflow(
                    "transition extent",
                ))?,
        )
        .ok_or(NativeCaptureAotError::ArithmeticOverflow("plan extent"))?;
    enforce(
        "native capture plan bytes",
        total_bytes,
        limits.max_plan_bytes,
    )?;
    // Both V1 targets have 64-bit offsets even when a 32-bit host cross-emits
    // their objects. Never size generated stack words from the host pointer.
    let raw_stack = view
        .tag_slot_count()
        .checked_mul(8)
        .ok_or(NativeCaptureAotError::ArithmeticOverflow("native stack"))?;
    let native_stack_bytes = raw_stack.checked_add(15).map(|bytes| bytes & !15).ok_or(
        NativeCaptureAotError::ArithmeticOverflow("native stack alignment"),
    )?;
    enforce(
        "native capture stack bytes",
        native_stack_bytes,
        limits.max_native_stack_bytes,
    )?;
    let mut plan = Vec::new();
    plan.try_reserve_exact(total_bytes)
        .map_err(|_| NativeCaptureAotError::Allocation("native capture plan"))?;
    plan.resize(PLAN_HEADER_BYTES, 0);
    plan[..8].copy_from_slice(&PLAN_MAGIC);
    write_u16(&mut plan, 8, PLAN_ABI_VERSION)?;
    write_u16(&mut plan, 10, usize_u16(PLAN_HEADER_BYTES, "plan header")?)?;
    write_u32(&mut plan, 12, PLAN_FLAG_DIRECT_TAG_MASKS)?;
    write_u64(&mut plan, 16, usize_u64(total_bytes, "plan bytes")?)?;
    write_u64(
        &mut plan,
        24,
        usize_u64(PLAN_BYTE_CLASSES_OFFSET, "class offset")?,
    )?;
    write_u64(&mut plan, 32, usize_u64(states_offset, "state offset")?)?;
    write_u64(
        &mut plan,
        40,
        usize_u64(transitions_offset, "transition offset")?,
    )?;
    write_u32(&mut plan, 48, usize_u32(view.state_count(), "states")?)?;
    write_u32(&mut plan, 52, usize_u32(view.alphabet_len(), "alphabet")?)?;
    write_u32(&mut plan, 56, view.start_state())?;
    write_u32(&mut plan, 60, usize_u32(view.group_count(), "groups")?)?;
    write_u32(
        &mut plan,
        64,
        usize_u32(view.tag_slot_count(), "tag slots")?,
    )?;
    plan.extend_from_slice(view.byte_classes());
    for state in view.states() {
        plan.extend_from_slice(&state.match_action.to_le_bytes());
        plan.extend_from_slice(&u32::from(state.is_match).to_le_bytes());
    }
    for transition in view.transitions() {
        plan.extend_from_slice(&transition.target_state.to_le_bytes());
        plan.extend_from_slice(&transition.action.to_le_bytes());
    }
    if plan.len() != total_bytes {
        return Err(NativeCaptureAotError::InternalInvariant("plan extent"));
    }
    let digest = plan_digest(&plan)
        .map_err(|_| NativeCaptureAotError::InternalInvariant("fresh plan digest"))?;
    plan[PLAN_DIGEST_OFFSET..PLAN_DIGEST_OFFSET + DIGEST_BYTES].copy_from_slice(&digest);
    Ok((
        plan,
        NativeCapturePlanGeometryV1 {
            bundle_plan_offset: NATIVE_CAPTURE_AOT_V1_PLAN_OFFSET,
            byte_classes_offset: PLAN_BYTE_CLASSES_OFFSET,
            states_offset,
            transitions_offset,
            state_count: view.state_count(),
            alphabet_len: view.alphabet_len(),
            start_state: view.start_state(),
            group_count: view.group_count(),
            tag_slot_count: view.tag_slot_count(),
            native_stack_bytes,
        },
    ))
}

fn encode_bundle(
    compiled: &CompiledCaptureRegex,
    strategy: NativeCaptureAotStrategyV1,
    decline: Option<NativeCaptureAotDeclineV1>,
    plan: &[u8],
    max_bundle_bytes: usize,
) -> Result<Vec<u8>, NativeCaptureAotError> {
    let identity = compiled.receipt().identity;
    let total_bytes = NATIVE_CAPTURE_AOT_V1_HEADER_BYTES
        .checked_add(plan.len())
        .ok_or(NativeCaptureAotError::ArithmeticOverflow("bundle extent"))?;
    enforce("native capture bundle bytes", total_bytes, max_bundle_bytes)?;
    let mut bundle = Vec::new();
    bundle
        .try_reserve_exact(total_bytes)
        .map_err(|_| NativeCaptureAotError::Allocation("native capture bundle"))?;
    bundle.resize(NATIVE_CAPTURE_AOT_V1_HEADER_BYTES, 0);
    bundle[..8].copy_from_slice(&NATIVE_CAPTURE_AOT_V1_MAGIC);
    write_u16(&mut bundle, 8, NATIVE_CAPTURE_AOT_V1_ABI_VERSION)?;
    write_u16(
        &mut bundle,
        10,
        usize_u16(NATIVE_CAPTURE_AOT_V1_HEADER_BYTES, "bundle header")?,
    )?;
    let strategy_flag = match strategy {
        NativeCaptureAotStrategyV1::NativeOnePassX86_64 => {
            NATIVE_CAPTURE_AOT_V1_FLAG_NATIVE_ONEPASS
        }
        NativeCaptureAotStrategyV1::NativeOnePassAarch64 => {
            NATIVE_CAPTURE_AOT_V1_FLAG_NATIVE_ONEPASS
        }
        NativeCaptureAotStrategyV1::NegativeEntry => NATIVE_CAPTURE_AOT_V1_FLAG_NEGATIVE_ENTRY,
    };
    write_u32(
        &mut bundle,
        12,
        NATIVE_CAPTURE_AOT_V1_FLAG_SPAN_SELECTOR
            | NATIVE_CAPTURE_AOT_V1_FLAG_BYTE_SEMANTICS
            | strategy_flag,
    )?;
    write_u64(&mut bundle, 16, usize_u64(total_bytes, "bundle bytes")?)?;
    write_u64(
        &mut bundle,
        24,
        usize_u64(NATIVE_CAPTURE_AOT_V1_PLAN_OFFSET, "plan offset")?,
    )?;
    write_u64(&mut bundle, 32, usize_u64(plan.len(), "plan bytes")?)?;
    write_u32(&mut bundle, 40, usize_u32(identity.groups(), "groups")?)?;
    write_u32(&mut bundle, 44, usize_u32(identity.groups(), "slots")?)?;
    write_u32(&mut bundle, 48, NATIVE_CAPTURE_AOT_V1_ITER_STATE_BYTES)?;
    write_u32(&mut bundle, 52, NATIVE_CAPTURE_AOT_V1_ITER_STATE_ALIGN)?;
    write_u32(&mut bundle, 56, NATIVE_CAPTURE_AOT_V1_RESULT_SLOT_BYTES)?;
    write_u32(&mut bundle, 60, NATIVE_CAPTURE_AOT_V1_RESULT_SLOT_ALIGN)?;
    write_u32(&mut bundle, 64, usize_u32(identity.slots(), "tag slots")?)?;
    write_u16(&mut bundle, 68, strategy as u16)?;
    write_u16(&mut bundle, 70, decline.map_or(0, |reason| reason as u16))?;
    write_u32(&mut bundle, 72, 0)?;
    bundle[SELECTOR_DIGEST_OFFSET..SELECTOR_DIGEST_OFFSET + DIGEST_BYTES]
        .copy_from_slice(&identity.selector_sha256());
    bundle[CAPTURE_DIGEST_OFFSET..CAPTURE_DIGEST_OFFSET + DIGEST_BYTES]
        .copy_from_slice(&identity.capture_sha256());
    if !plan.is_empty() {
        bundle[PLAN_BUNDLE_DIGEST_OFFSET..PLAN_BUNDLE_DIGEST_OFFSET + DIGEST_BYTES]
            .copy_from_slice(
                &read_digest(plan, PLAN_DIGEST_OFFSET)
                    .map_err(|_| NativeCaptureAotError::InternalInvariant("plan digest"))?,
            );
    }
    bundle.extend_from_slice(plan);
    let digest = bundle_digest(&bundle)
        .map_err(|_| NativeCaptureAotError::InternalInvariant("fresh bundle digest"))?;
    bundle[NATIVE_CAPTURE_AOT_V1_BUNDLE_DIGEST_OFFSET
        ..NATIVE_CAPTURE_AOT_V1_BUNDLE_DIGEST_OFFSET + DIGEST_BYTES]
        .copy_from_slice(&digest);
    Ok(bundle)
}

fn validate_plan(
    plan: &[u8],
    group_count: usize,
    tag_slot_count: usize,
    expected_digest: [u8; DIGEST_BYTES],
) -> Result<(), NativeCaptureBundleV1Error> {
    if plan.len() < PLAN_HEADER_BYTES || plan[..8] != PLAN_MAGIC {
        return Err(NativeCaptureBundleV1Error::InvalidHeader("plan magic"));
    }
    if read_u16(plan, 8)? != PLAN_ABI_VERSION
        || usize::from(read_u16(plan, 10)?) != PLAN_HEADER_BYTES
        || read_u32(plan, 12)? != PLAN_FLAG_DIRECT_TAG_MASKS
        || read_usize_u64(plan, 16, "plan total")? != plan.len()
        || read_usize_u64(plan, 24, "class offset")? != PLAN_BYTE_CLASSES_OFFSET
    {
        return Err(NativeCaptureBundleV1Error::InvalidHeader("plan header"));
    }
    let states_offset = read_usize_u64(plan, 32, "states offset")?;
    let transitions_offset = read_usize_u64(plan, 40, "transitions offset")?;
    let state_count = usize_from_u32(plan, 48, "state count")?;
    let alphabet_len = usize_from_u32(plan, 52, "alphabet")?;
    let start_state = usize_from_u32(plan, 56, "start state")?;
    if usize_from_u32(plan, 60, "plan groups")? != group_count
        || usize_from_u32(plan, 64, "plan tags")? != tag_slot_count
        || read_u32(plan, 68)? != 0
        || plan[104..112] != [0; 8]
        || alphabet_len == 0
        || alphabet_len > 256
        || start_state >= state_count
        || tag_slot_count == 0
        || tag_slot_count > 32
        || states_offset != PLAN_BYTE_CLASSES_OFFSET + 256
    {
        return Err(NativeCaptureBundleV1Error::InvalidHeader("plan geometry"));
    }
    let transition_count = state_count.checked_mul(alphabet_len).ok_or(
        NativeCaptureBundleV1Error::ArithmeticOverflow("transition count"),
    )?;
    let expected_transition_offset = states_offset
        .checked_add(state_count.checked_mul(PLAN_STATE_BYTES).ok_or(
            NativeCaptureBundleV1Error::ArithmeticOverflow("state extent"),
        )?)
        .ok_or(NativeCaptureBundleV1Error::ArithmeticOverflow(
            "transition offset",
        ))?;
    let expected_total = transitions_offset
        .checked_add(transition_count.checked_mul(PLAN_TRANSITION_BYTES).ok_or(
            NativeCaptureBundleV1Error::ArithmeticOverflow("transition extent"),
        )?)
        .ok_or(NativeCaptureBundleV1Error::ArithmeticOverflow(
            "plan extent",
        ))?;
    if transitions_offset != expected_transition_offset || expected_total != plan.len() {
        return Err(NativeCaptureBundleV1Error::InvalidHeader("plan extent"));
    }
    if plan[PLAN_BYTE_CLASSES_OFFSET..states_offset]
        .iter()
        .any(|&class| usize::from(class) >= alphabet_len)
    {
        return Err(NativeCaptureBundleV1Error::InvalidHeader("plan byte class"));
    }
    let allowed_actions = if tag_slot_count == 32 {
        u32::MAX
    } else {
        1_u32
            .checked_shl(
                u32::try_from(tag_slot_count)
                    .map_err(|_| NativeCaptureBundleV1Error::ArithmeticOverflow("plan tag mask"))?,
            )
            .and_then(|mask| mask.checked_sub(1))
            .ok_or(NativeCaptureBundleV1Error::ArithmeticOverflow(
                "plan tag mask",
            ))?
    };
    for state in 0..state_count {
        let offset = states_offset
            .checked_add(
                state
                    .checked_mul(PLAN_STATE_BYTES)
                    .ok_or(NativeCaptureBundleV1Error::ArithmeticOverflow("plan state"))?,
            )
            .ok_or(NativeCaptureBundleV1Error::ArithmeticOverflow("plan state"))?;
        let action = read_u32(plan, offset)?;
        let flags = read_u32(plan, offset + 4)?;
        if action & !allowed_actions != 0 || flags > 1 || (flags == 0 && action != 0) {
            return Err(NativeCaptureBundleV1Error::InvalidHeader(
                "plan state record",
            ));
        }
    }
    for transition in 0..transition_count {
        let offset = transitions_offset
            .checked_add(transition.checked_mul(PLAN_TRANSITION_BYTES).ok_or(
                NativeCaptureBundleV1Error::ArithmeticOverflow("plan transition"),
            )?)
            .ok_or(NativeCaptureBundleV1Error::ArithmeticOverflow(
                "plan transition",
            ))?;
        let target = read_u32(plan, offset)?;
        let action = read_u32(plan, offset + 4)?;
        if (target == u32::MAX && action != 0)
            || (target != u32::MAX
                && usize::try_from(target)
                    .ok()
                    .is_none_or(|target| target >= state_count))
            || action & !allowed_actions != 0
        {
            return Err(NativeCaptureBundleV1Error::InvalidHeader(
                "plan transition record",
            ));
        }
    }
    let digest = read_digest(plan, PLAN_DIGEST_OFFSET)?;
    if digest != expected_digest || plan_digest(plan)? != digest {
        return Err(NativeCaptureBundleV1Error::DigestMismatch);
    }
    Ok(())
}

fn enforce(
    resource: &'static str,
    required: usize,
    limit: usize,
) -> Result<(), NativeCaptureAotError> {
    if required > limit {
        return Err(NativeCaptureAotError::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

fn bundle_digest(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], NativeCaptureBundleV1Error> {
    digest_with_zeroed_field(
        NATIVE_CAPTURE_AOT_V1_IDENTITY_DOMAIN,
        bytes,
        NATIVE_CAPTURE_AOT_V1_BUNDLE_DIGEST_OFFSET,
    )
}

fn plan_digest(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], NativeCaptureBundleV1Error> {
    digest_with_zeroed_field(PLAN_IDENTITY_DOMAIN, bytes, PLAN_DIGEST_OFFSET)
}

fn digest_with_zeroed_field(
    domain: &[u8],
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; DIGEST_BYTES], NativeCaptureBundleV1Error> {
    let end =
        offset
            .checked_add(DIGEST_BYTES)
            .ok_or(NativeCaptureBundleV1Error::ArithmeticOverflow(
                "digest extent",
            ))?;
    if bytes.len() < end {
        return Err(NativeCaptureBundleV1Error::Truncated);
    }
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(&bytes[..offset]);
    digest.update([0; DIGEST_BYTES]);
    digest.update(&bytes[end..]);
    Ok(digest.finalize().into())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, NativeCaptureBundleV1Error> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(NativeCaptureBundleV1Error::Truncated)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, NativeCaptureBundleV1Error> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(NativeCaptureBundleV1Error::Truncated)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, NativeCaptureBundleV1Error> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(NativeCaptureBundleV1Error::Truncated)
}

fn read_usize_u64(
    bytes: &[u8],
    offset: usize,
    site: &'static str,
) -> Result<usize, NativeCaptureBundleV1Error> {
    usize::try_from(read_u64(bytes, offset)?)
        .map_err(|_| NativeCaptureBundleV1Error::ArithmeticOverflow(site))
}

fn usize_from_u32(
    bytes: &[u8],
    offset: usize,
    site: &'static str,
) -> Result<usize, NativeCaptureBundleV1Error> {
    usize::try_from(read_u32(bytes, offset)?)
        .map_err(|_| NativeCaptureBundleV1Error::ArithmeticOverflow(site))
}

fn read_digest(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; DIGEST_BYTES], NativeCaptureBundleV1Error> {
    bytes
        .get(offset..offset + DIGEST_BYTES)
        .and_then(|value| value.try_into().ok())
        .ok_or(NativeCaptureBundleV1Error::Truncated)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), NativeCaptureAotError> {
    write_bytes(bytes, offset, &value.to_le_bytes())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), NativeCaptureAotError> {
    write_bytes(bytes, offset, &value.to_le_bytes())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), NativeCaptureAotError> {
    write_bytes(bytes, offset, &value.to_le_bytes())
}

fn write_bytes(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), NativeCaptureAotError> {
    bytes
        .get_mut(offset..offset + value.len())
        .ok_or(NativeCaptureAotError::InternalInvariant("header write"))?
        .copy_from_slice(value);
    Ok(())
}

fn usize_u16(value: usize, site: &'static str) -> Result<u16, NativeCaptureAotError> {
    u16::try_from(value).map_err(|_| NativeCaptureAotError::ArithmeticOverflow(site))
}
fn usize_u32(value: usize, site: &'static str) -> Result<u32, NativeCaptureAotError> {
    u32::try_from(value).map_err(|_| NativeCaptureAotError::ArithmeticOverflow(site))
}
fn usize_u64(value: usize, site: &'static str) -> Result<u64, NativeCaptureAotError> {
    u64::try_from(value).map_err(|_| NativeCaptureAotError::ArithmeticOverflow(site))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CaptureCompileRequest, RelocationKind, Target, compile_captures};

    fn selected_for(target: Target) -> CompiledCaptureRegex {
        compile_captures(CaptureCompileRequest::new(r"(ab)(c*)", target))
            .expect("compile generated one-pass fixture")
    }

    fn selected() -> CompiledCaptureRegex {
        selected_for(Target::x86_64_linux())
    }

    fn symbol_bytes<'a>(module: &'a CompiledModule, name: &str) -> &'a [u8] {
        let symbol = module
            .symbols()
            .iter()
            .find(|symbol| symbol.name == name)
            .expect("defined symbol");
        let section = &module.sections()[symbol.section.expect("symbol section")];
        let start = usize::try_from(symbol.offset).expect("symbol offset");
        let size = usize::try_from(symbol.size).expect("symbol size");
        &section.bytes()[start..start + size]
    }

    fn rehash_plan_and_bundle(bundle: &mut [u8]) {
        let plan = &mut bundle[NATIVE_CAPTURE_AOT_V1_PLAN_OFFSET..];
        let plan_sha = plan_digest(plan).expect("rehash plan");
        plan[PLAN_DIGEST_OFFSET..PLAN_DIGEST_OFFSET + DIGEST_BYTES].copy_from_slice(&plan_sha);
        bundle[PLAN_BUNDLE_DIGEST_OFFSET..PLAN_BUNDLE_DIGEST_OFFSET + DIGEST_BYTES]
            .copy_from_slice(&plan_sha);
        let bundle_sha = bundle_digest(bundle).expect("rehash bundle");
        bundle[NATIVE_CAPTURE_AOT_V1_BUNDLE_DIGEST_OFFSET
            ..NATIVE_CAPTURE_AOT_V1_BUNDLE_DIGEST_OFFSET + DIGEST_BYTES]
            .copy_from_slice(&bundle_sha);
    }

    #[test]
    fn selected_bundle_has_zero_semantic_helpers_and_preserves_ordinary_abi() {
        let compiled = selected();
        let ordinary_entry = compiled.selector().module().entry_symbol().to_owned();
        let ordinary_bytes = symbol_bytes(compiled.selector().module(), &ordinary_entry).to_vec();
        let artifact = compiled
            .emit_native_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("emit native capture object");
        assert_eq!(artifact.module().entry_symbol(), ordinary_entry);
        assert_eq!(
            symbol_bytes(artifact.module(), &ordinary_entry),
            ordinary_bytes
        );
        assert_eq!(artifact.receipt().semantic_runtime_calls, 0);
        assert!(artifact.authenticates_receipt());
        let expected_object_sha256: [u8; 32] = Sha256::digest(artifact.object()).into();
        assert_eq!(artifact.receipt().object_sha256, expected_object_sha256);
        assert_eq!(
            artifact.receipt().strategy,
            NativeCaptureAotStrategyV1::NativeOnePassX86_64
        );
        assert!(
            artifact
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        let view = NativeCaptureBundleV1View::from_bytes(artifact.bundle()).expect("bundle");
        assert_eq!(view.descriptor().group_count(), 3);
        assert_eq!(view.descriptor().capture_tag_slot_count(), 6);
        assert!(!view.native_plan_bytes().is_empty());
    }

    #[test]
    fn aarch64_selected_bundle_uses_native_entries_and_paired_plan_relocations() {
        let artifact = selected_for(Target::aarch64_macos())
            .emit_native_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("emit AArch64 native capture object");
        assert_eq!(
            artifact.receipt().strategy,
            NativeCaptureAotStrategyV1::NativeOnePassAarch64,
        );
        assert!(
            artifact
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        let bundle_index = artifact
            .module()
            .symbols()
            .iter()
            .position(|symbol| symbol.name == artifact.bundle_symbol())
            .expect("bundle symbol");
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
                RelocationKind::Aarch64Page21,
                RelocationKind::Aarch64PageOff12
            ],
        );
        assert!(
            symbol_bytes(artifact.module(), artifact.capture_next_symbol())
                .len()
                .is_multiple_of(4),
        );
        assert!(
            symbol_bytes(artifact.module(), artifact.capture_materialize_symbol())
                .len()
                .is_multiple_of(4),
        );
    }

    #[test]
    fn assertion_shape_publishes_negative_entries() {
        let compiled =
            compile_captures(CaptureCompileRequest::new(r"^(a)$", Target::x86_64_linux()))
                .expect("compile assertion fixture");
        let artifact = compiled
            .emit_native_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("emit negative artifact");
        assert_eq!(
            artifact.receipt().strategy,
            NativeCaptureAotStrategyV1::NegativeEntry
        );
        assert_eq!(
            artifact.receipt().decline,
            Some(NativeCaptureAotDeclineV1::UnsupportedOnePassShape),
        );
        assert_eq!(artifact.descriptor().plan_bytes(), 0);
        assert_eq!(
            symbol_bytes(artifact.module(), artifact.capture_next_symbol()),
            [0xb8, 10, 0, 0, 0, 0xc3],
        );
    }

    #[test]
    fn aarch64_negative_entries_are_architecture_correct_and_transactional_leaves() {
        let compiled = compile_captures(CaptureCompileRequest::new(
            r"^(a)$",
            Target::aarch64_macos(),
        ))
        .expect("compile AArch64 assertion fixture");
        let artifact = compiled
            .emit_native_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("emit AArch64 negative artifact");
        assert_eq!(
            artifact.receipt().strategy,
            NativeCaptureAotStrategyV1::NegativeEntry
        );
        let expected = [0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
        assert_eq!(
            symbol_bytes(artifact.module(), artifact.capture_next_symbol()),
            expected,
        );
        assert_eq!(
            symbol_bytes(artifact.module(), artifact.capture_materialize_symbol()),
            expected,
        );
    }

    #[test]
    fn ordered_many_v1_is_an_explicit_pattern_id_decline() {
        let artifact = selected()
            .emit_native_ordered_many_negative_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("ordered-many negative artifact");
        assert_eq!(
            artifact.receipt().strategy,
            NativeCaptureAotStrategyV1::NegativeEntry
        );
        assert_eq!(
            artifact.receipt().decline,
            Some(NativeCaptureAotDeclineV1::OrderedManyRequiresPatternId),
        );
        assert_eq!(artifact.descriptor().plan_bytes(), 0);
    }

    #[test]
    fn resource_caps_are_errors_not_fallbacks() {
        let error = selected()
            .emit_native_aot_v1(NativeCaptureAotLimitsV1 {
                max_native_stack_bytes: 1,
                ..NativeCaptureAotLimitsV1::default()
            })
            .expect_err("stack cap");
        assert!(
            matches!(error, NativeCaptureAotError::Resource { resource, .. }
            if resource == "native capture stack bytes")
        );

        for (limits, expected) in [
            (
                NativeCaptureAotLimitsV1 {
                    max_native_states: 0,
                    ..NativeCaptureAotLimitsV1::default()
                },
                "native capture states",
            ),
            (
                NativeCaptureAotLimitsV1 {
                    max_native_transitions: 0,
                    ..NativeCaptureAotLimitsV1::default()
                },
                "native capture transitions",
            ),
            (
                NativeCaptureAotLimitsV1 {
                    max_plan_bytes: 0,
                    ..NativeCaptureAotLimitsV1::default()
                },
                "native capture plan bytes",
            ),
            (
                NativeCaptureAotLimitsV1 {
                    max_bundle_bytes: 0,
                    ..NativeCaptureAotLimitsV1::default()
                },
                "native capture bundle bytes",
            ),
        ] {
            let error = selected()
                .emit_native_aot_v1(limits)
                .expect_err("AOT resource ceiling must be terminal");
            assert!(
                matches!(error, NativeCaptureAotError::Resource { resource, .. }
                if resource == expected)
            );
        }
        let error = selected()
            .emit_native_aot_v1(NativeCaptureAotLimitsV1 {
                max_object_bytes: 0,
                ..NativeCaptureAotLimitsV1::default()
            })
            .expect_err("object ceiling must be terminal");
        assert!(matches!(
            error,
            NativeCaptureAotError::Object(ObjectError::Resource {
                resource: crate::CompileResource::ObjectBytes,
                ..
            })
        ));
    }

    #[test]
    fn artifact_receipt_rejects_bundle_object_route_and_target_substitution() {
        let artifact = selected()
            .emit_native_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("artifact");
        assert!(artifact.authenticates_receipt());

        let mut changed = artifact.clone();
        changed.bundle[0] ^= 1;
        assert!(!changed.authenticates_receipt());

        let mut changed = artifact.clone();
        changed.object[0] ^= 1;
        assert!(!changed.authenticates_receipt());

        let mut changed = artifact.clone();
        changed.capture_next_symbol.push('_');
        assert!(!changed.authenticates_receipt());

        let mut changed = artifact;
        changed.receipt.target = Target::aarch64_macos();
        assert!(!changed.authenticates_receipt());
    }

    #[test]
    fn bundle_and_plan_mutations_break_identity() {
        let artifact = selected()
            .emit_native_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("artifact");
        for offset in [56, NATIVE_CAPTURE_AOT_V1_PLAN_OFFSET] {
            let mut corrupt = artifact.bundle().to_vec();
            corrupt[offset] ^= 1;
            assert!(NativeCaptureBundleV1View::from_bytes(&corrupt).is_err());
        }
    }

    #[test]
    fn rehashed_out_of_range_plan_record_is_still_rejected() {
        let artifact = selected()
            .emit_native_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("artifact");
        let mut corrupt = artifact.bundle().to_vec();
        let plan_offset = NATIVE_CAPTURE_AOT_V1_PLAN_OFFSET;
        corrupt[plan_offset + PLAN_BYTE_CLASSES_OFFSET] = u8::MAX;
        rehash_plan_and_bundle(&mut corrupt);
        assert_eq!(
            NativeCaptureBundleV1View::from_bytes(&corrupt),
            Err(NativeCaptureBundleV1Error::InvalidHeader("plan byte class")),
        );
    }

    #[test]
    fn rehashed_noncanonical_state_and_dead_transition_are_rejected() {
        let artifact = selected()
            .emit_native_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("artifact");
        let plan_offset = NATIVE_CAPTURE_AOT_V1_PLAN_OFFSET;
        let states_offset =
            read_usize_u64(artifact.bundle(), plan_offset + 32, "states").expect("state offset");
        let transitions_offset = read_usize_u64(artifact.bundle(), plan_offset + 40, "transitions")
            .expect("transition offset");

        let mut bad_state = artifact.bundle().to_vec();
        bad_state[plan_offset + states_offset..plan_offset + states_offset + 4]
            .copy_from_slice(&1_u32.to_le_bytes());
        bad_state[plan_offset + states_offset + 4..plan_offset + states_offset + 8]
            .copy_from_slice(&0_u32.to_le_bytes());
        rehash_plan_and_bundle(&mut bad_state);
        assert_eq!(
            NativeCaptureBundleV1View::from_bytes(&bad_state),
            Err(NativeCaptureBundleV1Error::InvalidHeader(
                "plan state record"
            )),
        );

        let mut bad_transition = artifact.bundle().to_vec();
        bad_transition[plan_offset + transitions_offset..plan_offset + transitions_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        bad_transition[plan_offset + transitions_offset + 4..plan_offset + transitions_offset + 8]
            .copy_from_slice(&1_u32.to_le_bytes());
        rehash_plan_and_bundle(&mut bad_transition);
        assert_eq!(
            NativeCaptureBundleV1View::from_bytes(&bad_transition),
            Err(NativeCaptureBundleV1Error::InvalidHeader(
                "plan transition record",
            )),
        );
    }

    #[cfg(any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "macos"),
    ))]
    #[test]
    #[ignore = "links and executes helper-trapped native capture entries on the host ISA"]
    #[allow(
        clippy::too_many_lines,
        reason = "the opt-in harness keeps every ABI case and helper trap in one auditable transaction"
    )]
    fn linked_host_capture_entries_cover_tags_progress_and_negative_transaction() {
        use std::{fmt::Write as _, fs, process::Command};

        let target = if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
            Target::x86_64_linux()
        } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
            Target::x86_64_macos()
        } else if cfg!(all(target_arch = "aarch64", target_os = "linux")) {
            Target::aarch64_linux()
        } else {
            Target::aarch64_macos()
        };
        let build = |pattern: &str| {
            let compiled = compile_captures(CaptureCompileRequest::new(pattern, target))
                .expect("compile host capture fixture");
            let artifact = compiled
                .emit_native_aot_v1(NativeCaptureAotLimitsV1::default())
                .expect("emit host capture artifact");
            assert_ne!(
                artifact.receipt().strategy,
                NativeCaptureAotStrategyV1::NegativeEntry
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
        let optional = build(r"(?-u:(\xFF)?)(b+)");
        let nested_empty = build(r"((a*)b)");
        let repeated = build(r"((ab)+)");
        let nullable = build(r"(a*)");
        let negative = compile_captures(CaptureCompileRequest::new(r"(z)", target))
            .expect("compile negative host fixture")
            .emit_native_ordered_many_negative_aot_v1(NativeCaptureAotLimitsV1::default())
            .expect("emit negative host artifact");

        let directory =
            std::env::temp_dir().join(format!("fre-aot-native-capture-v1-{}", std::process::id(),));
        fs::create_dir_all(&directory).expect("create capture harness directory");
        let artifacts = [
            ("optional", &optional),
            ("empty", &nested_empty),
            ("repeated", &repeated),
            ("nullable", &nullable),
            ("negative", &negative),
        ];
        let mut objects = Vec::new();
        let mut source = String::from(
            "#include <stddef.h>\n#include <stdint.h>\n\
             typedef struct { size_t next_start; size_t last_match_end; uint32_t flags; uint32_t reserved; } state_t;\n\
             typedef struct { size_t start; size_t end; } slot_t;\n\
             typedef uint32_t (*next_t)(const uint8_t*,size_t,state_t*,slot_t*,size_t);\n\
             typedef uint32_t (*materialize_t)(const uint8_t*,size_t,size_t,size_t,slot_t*,size_t);\n\
             static volatile uint32_t helper_calls = 0;\n\
             uint32_t fre_aot_regex_runtime_search_v1(void){++helper_calls;return 3;}\n\
             uint32_t fre_aot_regex_runtime_search_exclusive_v1(void){++helper_calls;return 3;}\n\
             uint32_t fre_aot_regex_runtime_search_without_endpoint_oracle_v1(void){++helper_calls;return 3;}\n",
        );
        for (label, artifact) in artifacts {
            let object = directory.join(format!("{label}.o"));
            fs::write(&object, artifact.object()).expect("write capture object");
            objects.push(object);
            writeln!(
                source,
                "extern uint32_t {}(const uint8_t*,size_t,state_t*,slot_t*,size_t);",
                artifact.capture_next_symbol(),
            )
            .expect("write capture declaration");
            writeln!(
                source,
                "extern uint32_t {}(const uint8_t*,size_t,size_t,size_t,slot_t*,size_t);",
                artifact.capture_materialize_symbol(),
            )
            .expect("write materializer declaration");
        }
        writeln!(
            source,
            "#define OPTIONAL {}\n#define EMPTY {}\n#define REPEATED {}\n#define NULLABLE {}\n#define NEGATIVE {}\n#define NEGATIVE_MATERIALIZE {}",
            optional.capture_next_symbol(),
            nested_empty.capture_next_symbol(),
            repeated.capture_next_symbol(),
            nullable.capture_next_symbol(),
            negative.capture_next_symbol(),
            negative.capture_materialize_symbol(),
        )
        .expect("write capture aliases");
        source.push_str(
            r#"
static int eq(slot_t s,size_t a,size_t b){return s.start==a&&s.end==b;}
int main(void){
  static const uint8_t invalid[]={255,'b','b','x','b'};
  static const uint8_t one_b[]={'b'};
  static const uint8_t abab[]={'a','b','a','b'};
  state_t q={0}; slot_t s[3]={{11,12},{13,14},{15,16}}; uint32_t status;
  status=OPTIONAL(invalid,sizeof(invalid),&q,s,2);
  if(status!=2||q.next_start!=0||q.last_match_end!=0||q.flags!=0||q.reserved!=0||!eq(s[0],11,12)||!eq(s[1],13,14)||!eq(s[2],15,16))return 9;
  status=OPTIONAL(invalid,sizeof(invalid),&q,s,3);
  if(status!=1||!eq(s[0],0,3)||!eq(s[1],0,1)||!eq(s[2],1,3)||q.next_start!=3||q.flags!=1)return 10;
  status=OPTIONAL(invalid,sizeof(invalid),&q,s,3);
  if(status!=1||!eq(s[0],4,5)||s[1].start!=SIZE_MAX||s[1].end!=SIZE_MAX||!eq(s[2],4,5))return 11;
  status=OPTIONAL(invalid,sizeof(invalid),&q,s,3);
  if(status!=0||s[0].start!=SIZE_MAX||s[1].start!=SIZE_MAX||s[2].start!=SIZE_MAX||(q.flags&4)==0)return 12;

  q=(state_t){0}; s[0]=(slot_t){21,22};s[1]=(slot_t){23,24};s[2]=(slot_t){25,26};
  status=EMPTY(one_b,sizeof(one_b),&q,s,3);
  if(status!=1||!eq(s[0],0,1)||!eq(s[1],0,1)||!eq(s[2],0,0))return 20;

  q=(state_t){0};
  status=REPEATED(abab,sizeof(abab),&q,s,3);
  if(status!=1||!eq(s[0],0,4)||!eq(s[1],0,4)||!eq(s[2],2,4))return 30;

  q=(state_t){0};
  status=NULLABLE(one_b,sizeof(one_b),&q,s,2);
  if(status!=1||!eq(s[0],0,0)||!eq(s[1],0,0)||q.next_start!=0||q.flags!=3)return 40;
  status=NULLABLE(one_b,sizeof(one_b),&q,s,2);
  if(status!=1||!eq(s[0],1,1)||!eq(s[1],1,1)||q.next_start!=1||q.flags!=3)return 41;
  status=NULLABLE(one_b,sizeof(one_b),&q,s,2);
  if(status!=0||s[0].start!=SIZE_MAX||s[1].start!=SIZE_MAX||q.flags!=5)return 42;

  q=(state_t){7,6,1,9};s[0]=(slot_t){31,32};s[1]=(slot_t){33,34};
  status=NEGATIVE(NULL,SIZE_MAX,&q,s,999);
  if(status!=10||q.next_start!=7||q.last_match_end!=6||q.flags!=1||q.reserved!=9||!eq(s[0],31,32)||!eq(s[1],33,34))return 50;
  status=NEGATIVE_MATERIALIZE(NULL,SIZE_MAX,SIZE_MAX,0,s,999);
  if(status!=10||!eq(s[0],31,32)||!eq(s[1],33,34))return 51;
  if(helper_calls!=0)return 60;
  return 0;
}
"#,
        );
        let source_path = directory.join("capture_v1.c");
        let executable = directory.join("capture_v1");
        fs::write(&source_path, source).expect("write capture harness");
        let status = Command::new("cc")
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
            .expect("execute capture harness");
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        fs::remove_dir_all(directory).expect("remove capture harness directory");
    }
}
