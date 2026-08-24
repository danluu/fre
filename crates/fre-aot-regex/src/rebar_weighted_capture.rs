//! Helper-free weighted reduction over independently authenticated Rebar Span rows.
//!
//! This stage deliberately does not build or merge another regex program. It
//! consumes the exact ordinary Span selectors already selected by the paired
//! uniform-capture compiler, emits one separately linkable wrapper whose only
//! unresolved edges are calls to those selectors, and publishes a receipt
//! that closes the source-to-component map and every proof/object identity.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    CompileResource, CompiledModule, CompiledRegex, ObjectError, ObjectFormat, RelocationKind,
    SectionKind, SymbolBinding, SymbolKind, Target, UniformCaptureCompileReceipt,
    UniformCaptureReducerDomain, UniformCaptureReducerOperation, emit_object,
};

/// Domain separator for the complete source/proof/component/wrapper receipt.
pub const REBAR_WEIGHTED_CAPTURE_REDUCER_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/rebar-weighted-capture-reducer-aot-v1\0";
/// Receipt schema for the first helper-free weighted row reducer.
pub const REBAR_WEIGHTED_CAPTURE_REDUCER_AOT_V1_RECEIPT_VERSION: u32 = 1;
/// Hard construction bound independent of the caller's serialized-object cap.
///
/// The wrapper contains one straight-line call site per independently
/// authenticated component. Keeping a structural bound makes every preflight
/// and subsequent allocation finite even when a caller supplies an unlimited
/// object cap.
pub const REBAR_WEIGHTED_CAPTURE_REDUCER_AOT_V1_MAX_COMPONENTS: usize = 4_096;

/// One exact external call relocation in the separately linked wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebarWeightedCaptureReducerRelocationV1 {
    pub component: usize,
    pub offset: u64,
    pub kind: RelocationKind,
    pub addend: i64,
}

/// Borrowed, bounded construction request.
#[derive(Debug)]
pub struct RebarWeightedCaptureReducerAotRequestV1<'a> {
    operation: UniformCaptureReducerOperation,
    target: Target,
    pattern_bytes: usize,
    ordered_sources_sha256: [u8; 32],
    components: &'a [&'a CompiledRegex],
    source_to_component: &'a [usize],
    component_first_source_ordinals: &'a [usize],
    source_proofs: &'a [UniformCaptureCompileReceipt],
    max_object_bytes: usize,
}

impl<'a> RebarWeightedCaptureReducerAotRequestV1<'a> {
    /// Bind one public Rebar manifest to its already selected ordinary rows.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor closes the complete source/component transaction"
    )]
    #[must_use]
    pub const fn new(
        operation: UniformCaptureReducerOperation,
        target: Target,
        pattern_bytes: usize,
        ordered_sources_sha256: [u8; 32],
        components: &'a [&'a CompiledRegex],
        source_to_component: &'a [usize],
        component_first_source_ordinals: &'a [usize],
        source_proofs: &'a [UniformCaptureCompileReceipt],
        max_object_bytes: usize,
    ) -> Self {
        Self {
            operation,
            target,
            pattern_bytes,
            ordered_sources_sha256,
            components,
            source_to_component,
            component_first_source_ordinals,
            source_proofs,
            max_object_bytes,
        }
    }
}

/// Immutable source/proof/component and native wrapper receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebarWeightedCaptureReducerAotReceiptV1 {
    schema_version: u32,
    operation: UniformCaptureReducerOperation,
    domain: UniformCaptureReducerDomain,
    target: Target,
    source_count: usize,
    pattern_bytes: usize,
    ordered_sources_sha256: [u8; 32],
    source_to_component: Box<[usize]>,
    source_proofs: Box<[UniformCaptureCompileReceipt]>,
    component_first_source_ordinals: Box<[usize]>,
    component_weights: Box<[u64]>,
    component_entry_symbols: Box<[String]>,
    component_program_sha256: Box<[[u8; 32]]>,
    component_object_sha256: Box<[[u8; 32]]>,
    operation_identity_sha256: [u8; 32],
    reducer_symbol: String,
    reducer_symbol_sha256: [u8; 32],
    reducer_code_sha256: [u8; 32],
    reducer_object_sha256: [u8; 32],
    reducer_object_bytes: usize,
    max_object_bytes: usize,
    relocations: Box<[RebarWeightedCaptureReducerRelocationV1]>,
    artifact_identity_sha256: [u8; 32],
}

impl RebarWeightedCaptureReducerAotReceiptV1 {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    #[must_use]
    pub const fn operation(&self) -> UniformCaptureReducerOperation {
        self.operation
    }
    #[must_use]
    pub const fn domain(&self) -> UniformCaptureReducerDomain {
        self.domain
    }
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }
    #[must_use]
    pub const fn source_count(&self) -> usize {
        self.source_count
    }
    #[must_use]
    pub const fn pattern_bytes(&self) -> usize {
        self.pattern_bytes
    }
    #[must_use]
    pub const fn ordered_sources_sha256(&self) -> [u8; 32] {
        self.ordered_sources_sha256
    }
    #[must_use]
    pub fn source_to_component(&self) -> &[usize] {
        &self.source_to_component
    }
    #[must_use]
    pub fn source_proofs(&self) -> &[UniformCaptureCompileReceipt] {
        &self.source_proofs
    }
    #[must_use]
    pub fn component_first_source_ordinals(&self) -> &[usize] {
        &self.component_first_source_ordinals
    }
    #[must_use]
    pub fn component_weights(&self) -> &[u64] {
        &self.component_weights
    }
    #[must_use]
    pub fn component_entry_symbols(&self) -> &[String] {
        &self.component_entry_symbols
    }
    #[must_use]
    pub fn component_program_sha256(&self) -> &[[u8; 32]] {
        &self.component_program_sha256
    }
    #[must_use]
    pub fn component_object_sha256(&self) -> &[[u8; 32]] {
        &self.component_object_sha256
    }
    #[must_use]
    pub const fn operation_identity_sha256(&self) -> [u8; 32] {
        self.operation_identity_sha256
    }
    #[must_use]
    pub fn reducer_symbol(&self) -> &str {
        &self.reducer_symbol
    }
    #[must_use]
    pub const fn reducer_symbol_sha256(&self) -> [u8; 32] {
        self.reducer_symbol_sha256
    }
    #[must_use]
    pub const fn reducer_code_sha256(&self) -> [u8; 32] {
        self.reducer_code_sha256
    }
    #[must_use]
    pub const fn reducer_object_sha256(&self) -> [u8; 32] {
        self.reducer_object_sha256
    }
    #[must_use]
    pub const fn reducer_object_bytes(&self) -> usize {
        self.reducer_object_bytes
    }
    #[must_use]
    pub const fn max_object_bytes(&self) -> usize {
        self.max_object_bytes
    }
    #[must_use]
    pub fn relocations(&self) -> &[RebarWeightedCaptureReducerRelocationV1] {
        &self.relocations
    }
    #[must_use]
    pub const fn artifact_identity_sha256(&self) -> [u8; 32] {
        self.artifact_identity_sha256
    }
}

/// Separately linkable native reducer object and its closed receipt.
#[derive(Clone, Debug)]
pub struct RebarWeightedCaptureReducerAotArtifactV1 {
    module: CompiledModule,
    object: Box<[u8]>,
    receipt: RebarWeightedCaptureReducerAotReceiptV1,
}

impl RebarWeightedCaptureReducerAotArtifactV1 {
    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        &self.module
    }
    #[must_use]
    pub fn object(&self) -> &[u8] {
        &self.object
    }
    #[must_use]
    pub const fn receipt(&self) -> &RebarWeightedCaptureReducerAotReceiptV1 {
        &self.receipt
    }
    #[must_use]
    pub fn reducer_symbol(&self) -> &str {
        self.receipt.reducer_symbol()
    }

    /// Recheck every retained selector proof and deterministically reconstruct
    /// the wrapper module/object before accepting its route.
    pub fn authenticate(
        &self,
        components: &[&CompiledRegex],
    ) -> Result<(), RebarWeightedCaptureReducerAotAuthenticationErrorV1> {
        authenticate_artifact(self, components)
    }
}

/// Sole nonterminal result: the exact wrapper object exceeds its numeric cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebarWeightedCaptureReducerAotCompileDeclineV1 {
    pub limit: usize,
    pub required: usize,
}

/// Selected wrapper or the one typed result that preserves an existing row loop.
#[derive(Clone, Debug)]
pub enum RebarWeightedCaptureReducerAotCompileDispositionV1 {
    Compiled(RebarWeightedCaptureReducerAotArtifactV1),
    Declined(RebarWeightedCaptureReducerAotCompileDeclineV1),
}

/// Terminal construction failure. Allocation, arithmetic, lowering, object
/// structure and authentication failures never authorize fallback.
#[derive(Debug)]
pub enum RebarWeightedCaptureReducerAotErrorV1 {
    SourceShape(&'static str),
    ComponentAuthentication {
        source: usize,
        detail: crate::UniformCaptureAuthenticationError,
    },
    ArithmeticOverflow(&'static str),
    Allocation(&'static str),
    Object(ObjectError),
    Authentication(RebarWeightedCaptureReducerAotAuthenticationErrorV1),
}

impl fmt::Display for RebarWeightedCaptureReducerAotErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Rebar weighted capture reducer AOT failed: {self:?}"
        )
    }
}

impl std::error::Error for RebarWeightedCaptureReducerAotErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ComponentAuthentication { detail, .. } => Some(detail),
            Self::Object(source) => Some(source),
            Self::Authentication(source) => Some(source),
            Self::SourceShape(_) | Self::ArithmeticOverflow(_) | Self::Allocation(_) => None,
        }
    }
}

impl From<ObjectError> for RebarWeightedCaptureReducerAotErrorV1 {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

/// Why a retained weighted wrapper no longer closes over its component suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RebarWeightedCaptureReducerAotAuthenticationErrorV1 {
    Schema,
    OperationDomain,
    SourceShape,
    SourceProof,
    ComponentShape,
    ComponentReceipt,
    OperationIdentity,
    ModuleClosure,
    RelocationClosure,
    ReducerIdentity,
    ObjectIdentity,
    ArtifactIdentity,
}

impl fmt::Display for RebarWeightedCaptureReducerAotAuthenticationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "weighted capture reducer authentication failed: {self:?}"
        )
    }
}

impl std::error::Error for RebarWeightedCaptureReducerAotAuthenticationErrorV1 {}

/// Emit one helper-free reducer over ordinary positive-width Span components.
pub fn compile_rebar_weighted_capture_reducer_aot_v1(
    request: RebarWeightedCaptureReducerAotRequestV1<'_>,
) -> Result<RebarWeightedCaptureReducerAotCompileDispositionV1, RebarWeightedCaptureReducerAotErrorV1>
{
    let RebarWeightedCaptureReducerAotRequestV1 {
        operation,
        target,
        pattern_bytes,
        ordered_sources_sha256,
        components,
        source_to_component,
        component_first_source_ordinals,
        source_proofs,
        max_object_bytes,
    } = request;
    validate_source_component_closure(
        operation,
        target,
        pattern_bytes,
        ordered_sources_sha256,
        components,
        source_to_component,
        component_first_source_ordinals,
        source_proofs,
    )?;

    let mut component_weights = Vec::new();
    component_weights
        .try_reserve_exact(components.len())
        .map_err(|_| RebarWeightedCaptureReducerAotErrorV1::Allocation("component weights"))?;
    let mut component_entries = Vec::new();
    component_entries
        .try_reserve_exact(components.len())
        .map_err(|_| RebarWeightedCaptureReducerAotErrorV1::Allocation("component symbols"))?;
    let mut component_program_sha256 = Vec::new();
    component_program_sha256
        .try_reserve_exact(components.len())
        .map_err(|_| RebarWeightedCaptureReducerAotErrorV1::Allocation("component programs"))?;
    let mut component_object_sha256 = Vec::new();
    component_object_sha256
        .try_reserve_exact(components.len())
        .map_err(|_| RebarWeightedCaptureReducerAotErrorV1::Allocation("component objects"))?;
    for (component, selector) in components.iter().enumerate() {
        let first = component_first_source_ordinals[component];
        let weight = u64::try_from(
            source_proofs[first]
                .participation()
                .participating_groups_per_match()
                .get(),
        )
        .map_err(|_| {
            RebarWeightedCaptureReducerAotErrorV1::ArithmeticOverflow("component weight")
        })?;
        if weight == 0 {
            return Err(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
                "component weight is zero",
            ));
        }
        component_weights.push(weight);
        component_entries.push(selector.module().entry_symbol().to_owned());
        component_program_sha256.push(selector.receipt().program_sha256);
        component_object_sha256.push(selector.receipt().object_sha256);
    }
    let operation_identity_sha256 = operation_identity(
        operation,
        target,
        pattern_bytes,
        ordered_sources_sha256,
        source_to_component,
        component_first_source_ordinals,
        source_proofs,
        &component_weights,
        &component_entries,
        &component_program_sha256,
        &component_object_sha256,
    )?;
    let module = crate::module::lower_native_weighted_capture_reducer_v1(
        target,
        operation.domain(),
        operation_identity_sha256,
        &component_entries,
        &component_weights,
    )?;
    let object = match emit_object(&module, ObjectFormat::for_target(target), max_object_bytes) {
        Ok(object) => object,
        Err(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        }) => {
            return Ok(
                RebarWeightedCaptureReducerAotCompileDispositionV1::Declined(
                    RebarWeightedCaptureReducerAotCompileDeclineV1 { limit, required },
                ),
            );
        }
        Err(error) => return Err(RebarWeightedCaptureReducerAotErrorV1::Object(error)),
    };
    let text = module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .ok_or(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
            "weighted reducer has no text",
        ))?;
    let relocations = reducer_relocations(&module, components.len())
        .map_err(RebarWeightedCaptureReducerAotErrorV1::Authentication)?;
    let reducer_symbol = module.entry_symbol().to_owned();
    let mut receipt = RebarWeightedCaptureReducerAotReceiptV1 {
        schema_version: REBAR_WEIGHTED_CAPTURE_REDUCER_AOT_V1_RECEIPT_VERSION,
        operation,
        domain: operation.domain(),
        target,
        source_count: source_proofs.len(),
        pattern_bytes,
        ordered_sources_sha256,
        source_to_component: copy_slice(source_to_component, "source map")?,
        source_proofs: copy_slice(source_proofs, "source proofs")?,
        component_first_source_ordinals: copy_slice(
            component_first_source_ordinals,
            "component first ordinals",
        )?,
        component_weights: component_weights.into_boxed_slice(),
        component_entry_symbols: component_entries.into_boxed_slice(),
        component_program_sha256: component_program_sha256.into_boxed_slice(),
        component_object_sha256: component_object_sha256.into_boxed_slice(),
        operation_identity_sha256,
        reducer_symbol_sha256: sha256(reducer_symbol.as_bytes()),
        reducer_symbol,
        reducer_code_sha256: sha256(text.bytes()),
        reducer_object_sha256: sha256(&object),
        reducer_object_bytes: object.len(),
        max_object_bytes,
        relocations,
        artifact_identity_sha256: [0; 32],
    };
    receipt.artifact_identity_sha256 = artifact_identity(&receipt)?;
    let artifact = RebarWeightedCaptureReducerAotArtifactV1 {
        module,
        object: object.into_boxed_slice(),
        receipt,
    };
    artifact
        .authenticate(components)
        .map_err(RebarWeightedCaptureReducerAotErrorV1::Authentication)?;
    Ok(RebarWeightedCaptureReducerAotCompileDispositionV1::Compiled(artifact))
}

#[allow(
    clippy::too_many_arguments,
    reason = "one validator closes the full source/component transaction"
)]
fn validate_source_component_closure(
    operation: UniformCaptureReducerOperation,
    target: Target,
    pattern_bytes: usize,
    ordered_sources_sha256: [u8; 32],
    components: &[&CompiledRegex],
    source_to_component: &[usize],
    first_ordinals: &[usize],
    source_proofs: &[UniformCaptureCompileReceipt],
) -> Result<(), RebarWeightedCaptureReducerAotErrorV1> {
    if operation.domain()
        != match operation {
            UniformCaptureReducerOperation::CountCaptures => {
                UniformCaptureReducerDomain::WholeHaystack
            }
            UniformCaptureReducerOperation::GrepCaptures => {
                UniformCaptureReducerDomain::ByteSliceLinesLfCrLf
            }
        }
    {
        return Err(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
            "operation/domain mapping",
        ));
    }
    if source_proofs.len() <= 1
        || source_to_component.len() != source_proofs.len()
        || components.is_empty()
        || components.len() != first_ordinals.len()
        || components.len() > source_proofs.len()
        || pattern_bytes == 0
        || ordered_sources_sha256 == [0; 32]
    {
        return Err(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
            "source/component cardinality",
        ));
    }
    let mut previous_first = None;
    let mut previous_entry = None::<&str>;
    for (component, (&first, selector)) in first_ordinals.iter().zip(components).enumerate() {
        if first >= source_proofs.len()
            || source_to_component[first] != component
            || previous_first.is_some_and(|previous| first <= previous)
            || selector.receipt().target != target
            || selector.receipt().line_terminator != b'\n'
            || selector.object().is_empty()
        {
            return Err(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
                "component first-source closure",
            ));
        }
        let entry = selector.module().entry_symbol();
        if entry.is_empty() || previous_entry == Some(entry) {
            return Err(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
                "component entry closure",
            ));
        }
        if components[..component]
            .iter()
            .any(|prior| prior.module().entry_symbol() == entry)
        {
            return Err(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
                "duplicate component entry",
            ));
        }
        previous_first = Some(first);
        previous_entry = Some(entry);
    }
    if first_ordinals[0] != 0 {
        return Err(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
            "first source is not component zero",
        ));
    }
    for (source, (&component, proof)) in source_to_component.iter().zip(source_proofs).enumerate() {
        if component >= components.len() || first_ordinals[component] > source {
            return Err(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
                "source map references a future or absent component",
            ));
        }
        proof
            .authenticate(components[component])
            .map_err(
                |detail| RebarWeightedCaptureReducerAotErrorV1::ComponentAuthentication {
                    source,
                    detail,
                },
            )?;
        if proof.target() != target
            || proof.line_terminator() != b'\n'
            || proof.participation().minimum_match_bytes().get() == 0
        {
            return Err(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
                "source proof target/domain/width",
            ));
        }
    }
    Ok(())
}

fn authenticate_artifact(
    artifact: &RebarWeightedCaptureReducerAotArtifactV1,
    components: &[&CompiledRegex],
) -> Result<(), RebarWeightedCaptureReducerAotAuthenticationErrorV1> {
    let receipt = artifact.receipt();
    if receipt.schema_version != REBAR_WEIGHTED_CAPTURE_REDUCER_AOT_V1_RECEIPT_VERSION {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::Schema);
    }
    if receipt.operation.domain() != receipt.domain {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::OperationDomain);
    }
    if receipt.source_count <= 1
        || receipt.source_count != receipt.source_to_component.len()
        || receipt.source_count != receipt.source_proofs.len()
        || receipt.pattern_bytes == 0
        || receipt.ordered_sources_sha256 == [0; 32]
    {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::SourceShape);
    }
    let component_count = receipt.component_first_source_ordinals.len();
    if component_count == 0
        || components.len() != component_count
        || receipt.component_weights.len() != component_count
        || receipt.component_entry_symbols.len() != component_count
        || receipt.component_program_sha256.len() != component_count
        || receipt.component_object_sha256.len() != component_count
    {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::ComponentShape);
    }
    let mut previous_first = None;
    for component in 0..component_count {
        let first = receipt.component_first_source_ordinals[component];
        let selector = components[component];
        if first >= receipt.source_count
            || receipt.source_to_component[first] != component
            || previous_first.is_some_and(|previous| first <= previous)
            || receipt.component_weights[component] == 0
            || selector.receipt().target != receipt.target
            || selector.receipt().program_sha256 != receipt.component_program_sha256[component]
            || selector.receipt().object_sha256 != receipt.component_object_sha256[component]
            || sha256(selector.object()) != receipt.component_object_sha256[component]
            || selector.module().entry_symbol() != receipt.component_entry_symbols[component]
        {
            return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::ComponentReceipt);
        }
        previous_first = Some(first);
    }
    if receipt.component_first_source_ordinals[0] != 0 {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::ComponentShape);
    }
    for (source, (&component, proof)) in receipt
        .source_to_component
        .iter()
        .zip(receipt.source_proofs.iter())
        .enumerate()
    {
        if component >= component_count
            || receipt.component_first_source_ordinals[component] > source
            || proof.authenticate(components[component]).is_err()
        {
            return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::SourceProof);
        }
    }
    let identity = operation_identity(
        receipt.operation,
        receipt.target,
        receipt.pattern_bytes,
        receipt.ordered_sources_sha256,
        &receipt.source_to_component,
        &receipt.component_first_source_ordinals,
        &receipt.source_proofs,
        &receipt.component_weights,
        &receipt.component_entry_symbols,
        &receipt.component_program_sha256,
        &receipt.component_object_sha256,
    )
    .map_err(|_| RebarWeightedCaptureReducerAotAuthenticationErrorV1::OperationIdentity)?;
    if identity != receipt.operation_identity_sha256 {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::OperationIdentity);
    }
    let expected = crate::module::lower_native_weighted_capture_reducer_v1(
        receipt.target,
        receipt.domain,
        identity,
        &receipt.component_entry_symbols,
        &receipt.component_weights,
    )
    .map_err(|_| RebarWeightedCaptureReducerAotAuthenticationErrorV1::ModuleClosure)?;
    if expected != artifact.module {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::ModuleClosure);
    }
    let relocations = reducer_relocations(&artifact.module, component_count)?;
    if relocations != receipt.relocations {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::RelocationClosure);
    }
    let text = artifact
        .module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .ok_or(RebarWeightedCaptureReducerAotAuthenticationErrorV1::ModuleClosure)?;
    if artifact.module.entry_symbol() != receipt.reducer_symbol
        || sha256(receipt.reducer_symbol.as_bytes()) != receipt.reducer_symbol_sha256
        || sha256(text.bytes()) != receipt.reducer_code_sha256
    {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::ReducerIdentity);
    }
    let object = emit_object(
        &artifact.module,
        ObjectFormat::for_target(receipt.target),
        receipt.max_object_bytes,
    )
    .map_err(|_| RebarWeightedCaptureReducerAotAuthenticationErrorV1::ObjectIdentity)?;
    if receipt.reducer_object_bytes != artifact.object.len()
        || receipt.reducer_object_bytes != object.len()
        || artifact.object.as_ref() != object.as_slice()
        || sha256(&artifact.object) != receipt.reducer_object_sha256
    {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::ObjectIdentity);
    }
    if artifact_identity(receipt)
        .map_err(|_| RebarWeightedCaptureReducerAotAuthenticationErrorV1::ArtifactIdentity)?
        != receipt.artifact_identity_sha256
    {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::ArtifactIdentity);
    }
    Ok(())
}

fn reducer_relocations(
    module: &CompiledModule,
    components: usize,
) -> Result<
    Box<[RebarWeightedCaptureReducerRelocationV1]>,
    RebarWeightedCaptureReducerAotAuthenticationErrorV1,
> {
    if module.relocations().len() != components
        || module.symbols().len() != components.saturating_add(2)
        || module.required_runtime_program().is_some()
        || module.prepared_entry_symbol().is_some()
        || !module.prepared_aggregate_exports().is_empty()
        || module.required_prepare_capabilities() != 0
    {
        return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::RelocationClosure);
    }
    let expected_kind = match module.target().architecture {
        crate::Architecture::X86_64 => RelocationKind::X86PltRelative32,
        crate::Architecture::Aarch64 => RelocationKind::Aarch64Branch26,
    };
    let expected_addend = match module.target().architecture {
        crate::Architecture::X86_64 => -4,
        crate::Architecture::Aarch64 => 0,
    };
    let mut output = Vec::new();
    output
        .try_reserve_exact(components)
        .map_err(|_| RebarWeightedCaptureReducerAotAuthenticationErrorV1::RelocationClosure)?;
    for (component, relocation) in module.relocations().iter().enumerate() {
        let symbol = module
            .symbols()
            .get(component + 2)
            .ok_or(RebarWeightedCaptureReducerAotAuthenticationErrorV1::RelocationClosure)?;
        if relocation.section != 0
            || relocation.kind != expected_kind
            || relocation.addend != expected_addend
            || relocation.symbol != component + 2
            || symbol.binding != SymbolBinding::Global
            || symbol.kind != SymbolKind::Function
            || symbol.section.is_some()
            || symbol.name
                != module
                    .required_runtime_symbols()
                    .nth(component)
                    .unwrap_or("")
        {
            return Err(RebarWeightedCaptureReducerAotAuthenticationErrorV1::RelocationClosure);
        }
        output.push(RebarWeightedCaptureReducerRelocationV1 {
            component,
            offset: relocation.offset,
            kind: relocation.kind,
            addend: relocation.addend,
        });
    }
    Ok(output.into_boxed_slice())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the operation identity intentionally binds every source and component field"
)]
fn operation_identity(
    operation: UniformCaptureReducerOperation,
    target: Target,
    pattern_bytes: usize,
    ordered_sources_sha256: [u8; 32],
    source_to_component: &[usize],
    first_ordinals: &[usize],
    source_proofs: &[UniformCaptureCompileReceipt],
    weights: &[u64],
    entries: &[String],
    program_sha256: &[[u8; 32]],
    object_sha256: &[[u8; 32]],
) -> Result<[u8; 32], RebarWeightedCaptureReducerAotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(REBAR_WEIGHTED_CAPTURE_REDUCER_AOT_V1_IDENTITY_DOMAIN);
    digest.update(REBAR_WEIGHTED_CAPTURE_REDUCER_AOT_V1_RECEIPT_VERSION.to_le_bytes());
    digest.update([operation_tag(operation), domain_tag(operation.domain())]);
    digest.update([
        target.architecture as u8,
        target.operating_system as u8,
        target.abi as u8,
    ]);
    digest.update(target.features.bits().to_le_bytes());
    update_usize(&mut digest, pattern_bytes, "pattern bytes")?;
    digest.update(ordered_sources_sha256);
    update_usize(&mut digest, source_proofs.len(), "source count")?;
    update_usize(&mut digest, entries.len(), "component count")?;
    for (source, (&component, proof)) in source_to_component.iter().zip(source_proofs).enumerate() {
        update_usize(&mut digest, source, "source ordinal")?;
        update_usize(&mut digest, component, "source component")?;
        let participation = proof.participation();
        let identity = participation.identity();
        digest.update(identity.algorithm_version().to_le_bytes());
        digest.update(identity.accounting_version().to_le_bytes());
        update_usize(
            &mut digest,
            participation.minimum_match_bytes().get(),
            "minimum match bytes",
        )?;
        update_usize(
            &mut digest,
            participation.participating_user_captures(),
            "participating captures",
        )?;
        update_usize(
            &mut digest,
            participation.participating_groups_per_match().get(),
            "participating groups",
        )?;
        update_usize(
            &mut digest,
            participation.canonical_capture_annotations(),
            "capture annotations",
        )?;
        digest.update(participation.work().to_le_bytes());
        update_usize(&mut digest, participation.peak_stack_items(), "proof stack")?;
        digest.update(proof.selector_automaton_sha256());
        digest.update(proof.selector_program_sha256());
        digest.update(proof.selector_object_sha256());
        digest.update([proof.line_terminator()]);
    }
    for component in 0..entries.len() {
        update_usize(&mut digest, component, "component ordinal")?;
        update_usize(
            &mut digest,
            *first_ordinals.get(component).ok_or(
                RebarWeightedCaptureReducerAotErrorV1::SourceShape("missing first ordinal"),
            )?,
            "component first source",
        )?;
        digest.update(
            weights
                .get(component)
                .ok_or(RebarWeightedCaptureReducerAotErrorV1::SourceShape(
                    "missing component weight",
                ))?
                .to_le_bytes(),
        );
        update_bytes(&mut digest, entries[component].as_bytes())?;
        digest.update(*program_sha256.get(component).ok_or(
            RebarWeightedCaptureReducerAotErrorV1::SourceShape("missing program hash"),
        )?);
        digest.update(*object_sha256.get(component).ok_or(
            RebarWeightedCaptureReducerAotErrorV1::SourceShape("missing object hash"),
        )?);
    }
    Ok(digest.finalize().into())
}

fn artifact_identity(
    receipt: &RebarWeightedCaptureReducerAotReceiptV1,
) -> Result<[u8; 32], RebarWeightedCaptureReducerAotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-regex/rebar-weighted-capture-reducer-artifact-v1\0");
    digest.update(receipt.operation_identity_sha256);
    update_bytes(&mut digest, receipt.reducer_symbol.as_bytes())?;
    digest.update(receipt.reducer_code_sha256);
    digest.update(receipt.reducer_object_sha256);
    update_usize(
        &mut digest,
        receipt.reducer_object_bytes,
        "reducer object bytes",
    )?;
    update_usize(&mut digest, receipt.max_object_bytes, "reducer object cap")?;
    update_usize(&mut digest, receipt.relocations.len(), "relocation count")?;
    for relocation in &receipt.relocations {
        update_usize(&mut digest, relocation.component, "relocation component")?;
        digest.update(relocation.offset.to_le_bytes());
        digest.update([relocation_kind_tag(relocation.kind)]);
        digest.update(relocation.addend.to_le_bytes());
    }
    Ok(digest.finalize().into())
}

fn operation_tag(operation: UniformCaptureReducerOperation) -> u8 {
    match operation {
        UniformCaptureReducerOperation::CountCaptures => 1,
        UniformCaptureReducerOperation::GrepCaptures => 2,
    }
}

fn domain_tag(domain: UniformCaptureReducerDomain) -> u8 {
    match domain {
        UniformCaptureReducerDomain::WholeHaystack => 1,
        UniformCaptureReducerDomain::ByteSliceLinesLfCrLf => 2,
    }
}

fn relocation_kind_tag(kind: RelocationKind) -> u8 {
    match kind {
        RelocationKind::X86PcRelative32 => 1,
        RelocationKind::X86PltRelative32 => 2,
        RelocationKind::Aarch64Page21 => 3,
        RelocationKind::Aarch64PageOff12 => 4,
        RelocationKind::Aarch64Branch26 => 5,
    }
}

fn update_usize(
    digest: &mut Sha256,
    value: usize,
    site: &'static str,
) -> Result<(), RebarWeightedCaptureReducerAotErrorV1> {
    digest.update(
        u64::try_from(value)
            .map_err(|_| RebarWeightedCaptureReducerAotErrorV1::ArithmeticOverflow(site))?
            .to_le_bytes(),
    );
    Ok(())
}

fn update_bytes(
    digest: &mut Sha256,
    bytes: &[u8],
) -> Result<(), RebarWeightedCaptureReducerAotErrorV1> {
    update_usize(digest, bytes.len(), "identity byte length")?;
    digest.update(bytes);
    Ok(())
}

fn copy_slice<T: Copy>(
    source: &[T],
    site: &'static str,
) -> Result<Box<[T]>, RebarWeightedCaptureReducerAotErrorV1> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(source.len())
        .map_err(|_| RebarWeightedCaptureReducerAotErrorV1::Allocation(site))?;
    output.extend_from_slice(source);
    Ok(output.into_boxed_slice())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
