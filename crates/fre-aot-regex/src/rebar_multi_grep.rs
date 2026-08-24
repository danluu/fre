//! Helper-free whole-operation lowering for Rebar's multi-pattern `grep`.
//!
//! This reducer deliberately consumes only independently authenticated,
//! ordinary `SpanSearchV1` artifacts. It owns `bstr::ByteSlice::lines` byte
//! traversal, invokes every distinct row for every line, validates every
//! returned status and span, and publishes the final `u64` line count only
//! after the complete operation succeeds. Prepared rows retain the exact
//! pre-existing adapter route; this compiler never fabricates handles or a
//! runtime semantic edge.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    CompileMode, CompileResource, CompiledModule, CompiledRegex, EntryAbi, ObjectError,
    ObjectFormat, OutputContract, SectionKind, SymbolBinding, SymbolKind, Target, emit_object,
};

/// Domain separator for the immutable reducer identity.
pub const REBAR_MULTI_GREP_REDUCER_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/rebar-multi-grep-reducer/v1\0";
/// Native ABI version: `u32 entry(const u8 *, usize, u64 *)`.
pub const REBAR_MULTI_GREP_REDUCER_AOT_V1_ABI_VERSION: u32 = 1;
/// Complete operation success; the scalar output was published.
pub const REBAR_MULTI_GREP_REDUCER_AOT_V1_STATUS_SUCCESS: u32 = 0;
/// Pointer, extent, or alignment validation failed before source access.
pub const REBAR_MULTI_GREP_REDUCER_AOT_V1_STATUS_INVALID_ARGUMENT: u32 = 2;
/// A child status/span invariant or checked reducer operation failed.
pub const REBAR_MULTI_GREP_REDUCER_AOT_V1_STATUS_RUNTIME_FAILURE: u32 = 3;

/// One independently compiled distinct row, retained in source-priority order.
#[derive(Clone, Copy, Debug)]
pub struct RebarMultiGrepReducerRowV1<'a> {
    compiled: &'a CompiledRegex,
    first_source_ordinal: usize,
}

impl<'a> RebarMultiGrepReducerRowV1<'a> {
    #[must_use]
    pub const fn new(compiled: &'a CompiledRegex, first_source_ordinal: usize) -> Self {
        Self {
            compiled,
            first_source_ordinal,
        }
    }

    #[must_use]
    pub const fn compiled(self) -> &'a CompiledRegex {
        self.compiled
    }

    #[must_use]
    pub const fn first_source_ordinal(self) -> usize {
        self.first_source_ordinal
    }
}

/// Exact source, row, link, and object receipt for one native reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebarMultiGrepReducerAotReceiptV1 {
    abi_version: u32,
    target: Target,
    source_cardinality: usize,
    source_bytes: usize,
    ordered_sources_sha256: [u8; 32],
    source_to_row: Box<[usize]>,
    row_first_source_ordinals: Box<[usize]>,
    row_entry_symbols: Box<[String]>,
    row_automaton_sha256: Box<[[u8; 32]]>,
    row_program_sha256: Box<[[u8; 32]]>,
    row_object_sha256: Box<[[u8; 32]]>,
    operation_identity_sha256: [u8; 32],
    reducer_symbol: String,
    reducer_code_sha256: [u8; 32],
    reducer_object_sha256: [u8; 32],
    reducer_relocation_count: usize,
    semantic_runtime_calls: usize,
    object_bytes: usize,
    max_object_bytes: usize,
    artifact_identity_sha256: [u8; 32],
}

impl RebarMultiGrepReducerAotReceiptV1 {
    #[must_use]
    pub const fn abi_version(&self) -> u32 {
        self.abi_version
    }

    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    #[must_use]
    pub const fn source_cardinality(&self) -> usize {
        self.source_cardinality
    }

    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    #[must_use]
    pub const fn ordered_sources_sha256(&self) -> [u8; 32] {
        self.ordered_sources_sha256
    }

    #[must_use]
    pub fn source_to_row(&self) -> &[usize] {
        &self.source_to_row
    }

    #[must_use]
    pub fn row_first_source_ordinals(&self) -> &[usize] {
        &self.row_first_source_ordinals
    }

    #[must_use]
    pub fn row_entry_symbols(&self) -> &[String] {
        &self.row_entry_symbols
    }

    #[must_use]
    pub fn row_automaton_sha256(&self) -> &[[u8; 32]] {
        &self.row_automaton_sha256
    }

    #[must_use]
    pub fn row_program_sha256(&self) -> &[[u8; 32]] {
        &self.row_program_sha256
    }

    #[must_use]
    pub fn row_object_sha256(&self) -> &[[u8; 32]] {
        &self.row_object_sha256
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
    pub const fn reducer_code_sha256(&self) -> [u8; 32] {
        self.reducer_code_sha256
    }

    #[must_use]
    pub const fn reducer_object_sha256(&self) -> [u8; 32] {
        self.reducer_object_sha256
    }

    #[must_use]
    pub const fn reducer_relocation_count(&self) -> usize {
        self.reducer_relocation_count
    }

    #[must_use]
    pub const fn semantic_runtime_calls(&self) -> usize {
        self.semantic_runtime_calls
    }

    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn max_object_bytes(&self) -> usize {
        self.max_object_bytes
    }

    #[must_use]
    pub const fn artifact_identity_sha256(&self) -> [u8; 32] {
        self.artifact_identity_sha256
    }
}

/// Separately linkable native reducer object.
#[derive(Clone, Debug)]
pub struct RebarMultiGrepReducerAotArtifactV1 {
    module: CompiledModule,
    object: Box<[u8]>,
    receipt: RebarMultiGrepReducerAotReceiptV1,
}

impl RebarMultiGrepReducerAotArtifactV1 {
    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        &self.module
    }

    #[must_use]
    pub fn object(&self) -> &[u8] {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &RebarMultiGrepReducerAotReceiptV1 {
        &self.receipt
    }

    /// Rebuild and authenticate the complete reducer against its retained
    /// ordinary row closure and ordered source topology.
    #[must_use]
    pub fn authenticates_rows(
        &self,
        ordered_sources_sha256: [u8; 32],
        source_cardinality: usize,
        source_bytes: usize,
        source_to_row: &[usize],
        rows: &[RebarMultiGrepReducerRowV1<'_>],
    ) -> bool {
        authenticate_artifact(
            self,
            ordered_sources_sha256,
            source_cardinality,
            source_bytes,
            source_to_row,
            rows,
        )
        .is_ok()
    }
}

/// The sole safe decline after all row artifacts already exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebarMultiGrepReducerAotCompileDeclineV1 {
    ObjectBytes { limit: usize, required: usize },
}

/// Selected native reducer or an exact authorization to retain the prior
/// Rust adapter route.
#[derive(Clone, Debug)]
pub enum RebarMultiGrepReducerAotCompileDispositionV1 {
    Selected(RebarMultiGrepReducerAotArtifactV1),
    Declined(RebarMultiGrepReducerAotCompileDeclineV1),
}

/// Terminal construction failure. Allocation, arithmetic, lowering, and
/// authentication failures never authorize adapter fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebarMultiGrepReducerAotErrorV1 {
    SourceAuthentication(&'static str),
    Object(ObjectError),
    Authentication(&'static str),
}

impl fmt::Display for RebarMultiGrepReducerAotErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Rebar multi-pattern grep reducer AOT failed: {self:?}"
        )
    }
}

impl std::error::Error for RebarMultiGrepReducerAotErrorV1 {}

impl From<ObjectError> for RebarMultiGrepReducerAotErrorV1 {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), ObjectError> {
    hasher.update(
        u64::try_from(bytes.len())
            .map_err(|_| ObjectError::ArithmeticOverflow("multi-grep identity field"))?
            .to_le_bytes(),
    );
    hasher.update(bytes);
    Ok(())
}

fn update_usize(hasher: &mut Sha256, value: usize) -> Result<(), ObjectError> {
    hasher.update(
        u64::try_from(value)
            .map_err(|_| ObjectError::ArithmeticOverflow("multi-grep identity integer"))?
            .to_le_bytes(),
    );
    Ok(())
}

fn authenticate_source_shape(
    ordered_sources_sha256: [u8; 32],
    source_cardinality: usize,
    _source_bytes: usize,
    source_to_row: &[usize],
    rows: &[RebarMultiGrepReducerRowV1<'_>],
) -> Result<Target, RebarMultiGrepReducerAotErrorV1> {
    if ordered_sources_sha256 == [0; 32]
        || source_cardinality < 2
        || source_to_row.len() != source_cardinality
        || rows.is_empty()
        || rows.len() > source_cardinality
        || rows.len() > crate::ORDERED_MANY_AOT_MAX_ROWS
    {
        return Err(RebarMultiGrepReducerAotErrorV1::SourceAuthentication(
            "source cardinality or identity",
        ));
    }
    let target = rows[0].compiled.receipt().target;
    let mut prior_first = None;
    for (row, descriptor) in rows.iter().copied().enumerate() {
        let compiled = descriptor.compiled;
        let receipt = compiled.receipt();
        let module = compiled.module();
        let entry = module.entry_symbol();
        let entry_record = module.symbols().iter().find(|symbol| symbol.name == entry);
        let unresolved = module
            .symbols()
            .iter()
            .enumerate()
            .any(|(symbol, definition)| {
                definition.section.is_none()
                    && module
                        .relocations()
                        .iter()
                        .any(|relocation| relocation.symbol == symbol)
            });
        if descriptor.first_source_ordinal >= source_cardinality
            || prior_first.is_some_and(|prior| descriptor.first_source_ordinal <= prior)
            || source_to_row[descriptor.first_source_ordinal] != row
            || receipt.target != target
            || module.target() != target
            || receipt.mode != CompileMode::Optimizing
            || receipt.output != OutputContract::Span
            || receipt.entry_abi != EntryAbi::SpanSearchV1
            || receipt.runtime_helper_required
            || receipt.automaton_sha256 == [0; 32]
            || receipt.program_sha256 == [0; 32]
            || receipt.object_sha256 == [0; 32]
            || Sha256::digest(compiled.object()).as_slice() != receipt.object_sha256
            || module.required_runtime_symbols().next().is_some()
            || unresolved
            || module.required_runtime_program().is_some()
            || module.prepared_entry_symbol().is_some()
            || !module.prepared_aggregate_exports().is_empty()
            || module.prepared_count_symbol().is_some()
            || module.prepared_span_sum_symbol().is_some()
            || module.prepared_grep_count_symbol().is_some()
            || module.required_prepare_capabilities() != 0
            || !entry_record.is_some_and(|record| {
                record.binding == SymbolBinding::Global
                    && record.kind == SymbolKind::Function
                    && record.section.is_some()
                    && record.size != 0
            })
            || rows[..row]
                .iter()
                .any(|prior| prior.compiled.module().entry_symbol() == entry)
        {
            return Err(RebarMultiGrepReducerAotErrorV1::SourceAuthentication(
                "ordinary row closure",
            ));
        }
        prior_first = Some(descriptor.first_source_ordinal);
    }
    for (source, &row) in source_to_row.iter().enumerate() {
        if row >= rows.len() || rows[row].first_source_ordinal > source {
            return Err(RebarMultiGrepReducerAotErrorV1::SourceAuthentication(
                "source-to-row topology",
            ));
        }
    }
    Ok(target)
}

fn operation_identity(
    target: Target,
    ordered_sources_sha256: [u8; 32],
    source_cardinality: usize,
    source_bytes: usize,
    source_to_row: &[usize],
    rows: &[RebarMultiGrepReducerRowV1<'_>],
) -> Result<[u8; 32], ObjectError> {
    let mut hasher = Sha256::new();
    hasher.update(REBAR_MULTI_GREP_REDUCER_AOT_V1_IDENTITY_DOMAIN);
    hasher.update(REBAR_MULTI_GREP_REDUCER_AOT_V1_ABI_VERSION.to_le_bytes());
    hasher.update([
        target.architecture as u8,
        target.operating_system as u8,
        target.abi as u8,
    ]);
    hasher.update(target.features.bits().to_le_bytes());
    update_usize(&mut hasher, source_cardinality)?;
    update_usize(&mut hasher, source_bytes)?;
    hasher.update(ordered_sources_sha256);
    update_usize(&mut hasher, source_to_row.len())?;
    for &row in source_to_row {
        update_usize(&mut hasher, row)?;
    }
    update_usize(&mut hasher, rows.len())?;
    for descriptor in rows.iter().copied() {
        let compiled = descriptor.compiled;
        update_usize(&mut hasher, descriptor.first_source_ordinal)?;
        update_len_prefixed(&mut hasher, compiled.module().entry_symbol().as_bytes())?;
        hasher.update(compiled.receipt().automaton_sha256);
        hasher.update(compiled.receipt().program_sha256);
        hasher.update(compiled.receipt().object_sha256);
    }
    Ok(hasher.finalize().into())
}

fn artifact_identity(receipt: &RebarMultiGrepReducerAotReceiptV1) -> Result<[u8; 32], ObjectError> {
    let mut hasher = Sha256::new();
    hasher.update(b"fre-aot-regex/rebar-multi-grep-reducer-artifact/v1\0");
    hasher.update(receipt.operation_identity_sha256);
    update_len_prefixed(&mut hasher, receipt.reducer_symbol.as_bytes())?;
    hasher.update(receipt.reducer_code_sha256);
    hasher.update(receipt.reducer_object_sha256);
    update_usize(&mut hasher, receipt.reducer_relocation_count)?;
    update_usize(&mut hasher, receipt.object_bytes)?;
    update_usize(&mut hasher, receipt.max_object_bytes)?;
    Ok(hasher.finalize().into())
}

fn authenticate_artifact(
    artifact: &RebarMultiGrepReducerAotArtifactV1,
    ordered_sources_sha256: [u8; 32],
    source_cardinality: usize,
    source_bytes: usize,
    source_to_row: &[usize],
    rows: &[RebarMultiGrepReducerRowV1<'_>],
) -> Result<(), RebarMultiGrepReducerAotErrorV1> {
    let target = authenticate_source_shape(
        ordered_sources_sha256,
        source_cardinality,
        source_bytes,
        source_to_row,
        rows,
    )?;
    let receipt = artifact.receipt();
    let identity = operation_identity(
        target,
        ordered_sources_sha256,
        source_cardinality,
        source_bytes,
        source_to_row,
        rows,
    )?;
    let entries = rows
        .iter()
        .map(|row| row.compiled.module().entry_symbol().to_owned())
        .collect::<Vec<_>>();
    let rebuilt =
        crate::module::lower_native_rebar_multi_grep_reducer_v1(target, identity, &entries)?;
    let object = emit_object(
        &rebuilt,
        ObjectFormat::for_target(target),
        receipt.max_object_bytes,
    )?;
    let text = rebuilt
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .ok_or(RebarMultiGrepReducerAotErrorV1::Authentication(
            "rebuilt reducer text",
        ))?;
    let rebuilt_code_sha256: [u8; 32] = Sha256::digest(text.bytes()).into();
    let rebuilt_object_sha256: [u8; 32] = Sha256::digest(&object).into();
    if receipt.abi_version != REBAR_MULTI_GREP_REDUCER_AOT_V1_ABI_VERSION
        || receipt.target != target
        || receipt.source_cardinality != source_cardinality
        || receipt.source_bytes != source_bytes
        || receipt.ordered_sources_sha256 != ordered_sources_sha256
        || receipt.source_to_row.as_ref() != source_to_row
        || receipt.row_first_source_ordinals.as_ref()
            != rows
                .iter()
                .map(|row| row.first_source_ordinal)
                .collect::<Vec<_>>()
        || receipt.row_entry_symbols.as_ref() != entries
        || receipt.row_automaton_sha256.as_ref()
            != rows
                .iter()
                .map(|row| row.compiled.receipt().automaton_sha256)
                .collect::<Vec<_>>()
        || receipt.row_program_sha256.as_ref()
            != rows
                .iter()
                .map(|row| row.compiled.receipt().program_sha256)
                .collect::<Vec<_>>()
        || receipt.row_object_sha256.as_ref()
            != rows
                .iter()
                .map(|row| row.compiled.receipt().object_sha256)
                .collect::<Vec<_>>()
        || receipt.operation_identity_sha256 != identity
        || receipt.reducer_symbol != rebuilt.entry_symbol()
        || receipt.reducer_code_sha256 != rebuilt_code_sha256
        || receipt.reducer_object_sha256 != rebuilt_object_sha256
        || receipt.reducer_relocation_count != rows.len()
        || receipt.semantic_runtime_calls != 0
        || receipt.object_bytes != object.len()
        || receipt.artifact_identity_sha256 != artifact_identity(receipt)?
        || artifact.module != rebuilt
        || artifact.object.as_ref() != object
    {
        return Err(RebarMultiGrepReducerAotErrorV1::Authentication(
            "deterministic reducer closure",
        ));
    }
    Ok(())
}

/// Compile one helper-free LF/CRLF multi-pattern grep operation.
///
/// Only the final `ObjectBytes` representation cap is a safe decline. Every
/// row/authentication, allocation, arithmetic, lowering, and serialization
/// failure is terminal and returned as `Err`.
pub fn compile_rebar_multi_grep_reducer_aot_v1(
    ordered_sources_sha256: [u8; 32],
    source_cardinality: usize,
    source_bytes: usize,
    source_to_row: &[usize],
    rows: &[RebarMultiGrepReducerRowV1<'_>],
    max_object_bytes: usize,
) -> Result<RebarMultiGrepReducerAotCompileDispositionV1, RebarMultiGrepReducerAotErrorV1> {
    let target = authenticate_source_shape(
        ordered_sources_sha256,
        source_cardinality,
        source_bytes,
        source_to_row,
        rows,
    )?;
    let identity = operation_identity(
        target,
        ordered_sources_sha256,
        source_cardinality,
        source_bytes,
        source_to_row,
        rows,
    )?;
    let entries = rows
        .iter()
        .map(|row| row.compiled.module().entry_symbol().to_owned())
        .collect::<Vec<_>>();
    let module =
        crate::module::lower_native_rebar_multi_grep_reducer_v1(target, identity, &entries)?;
    let object = match emit_object(&module, ObjectFormat::for_target(target), max_object_bytes) {
        Ok(object) => object,
        Err(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit,
            required,
        }) => {
            return Ok(RebarMultiGrepReducerAotCompileDispositionV1::Declined(
                RebarMultiGrepReducerAotCompileDeclineV1::ObjectBytes { limit, required },
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let text = module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .ok_or(RebarMultiGrepReducerAotErrorV1::Authentication(
            "fresh reducer text",
        ))?;
    let mut receipt = RebarMultiGrepReducerAotReceiptV1 {
        abi_version: REBAR_MULTI_GREP_REDUCER_AOT_V1_ABI_VERSION,
        target,
        source_cardinality,
        source_bytes,
        ordered_sources_sha256,
        source_to_row: source_to_row.to_vec().into_boxed_slice(),
        row_first_source_ordinals: rows
            .iter()
            .map(|row| row.first_source_ordinal)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        row_entry_symbols: entries.into_boxed_slice(),
        row_automaton_sha256: rows
            .iter()
            .map(|row| row.compiled.receipt().automaton_sha256)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        row_program_sha256: rows
            .iter()
            .map(|row| row.compiled.receipt().program_sha256)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        row_object_sha256: rows
            .iter()
            .map(|row| row.compiled.receipt().object_sha256)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        operation_identity_sha256: identity,
        reducer_symbol: module.entry_symbol().to_owned(),
        reducer_code_sha256: Sha256::digest(text.bytes()).into(),
        reducer_object_sha256: Sha256::digest(&object).into(),
        reducer_relocation_count: module.relocations().len(),
        semantic_runtime_calls: 0,
        object_bytes: object.len(),
        max_object_bytes,
        artifact_identity_sha256: [0; 32],
    };
    receipt.artifact_identity_sha256 = artifact_identity(&receipt)?;
    let artifact = RebarMultiGrepReducerAotArtifactV1 {
        module,
        object: object.into_boxed_slice(),
        receipt,
    };
    authenticate_artifact(
        &artifact,
        ordered_sources_sha256,
        source_cardinality,
        source_bytes,
        source_to_row,
        rows,
    )?;
    Ok(RebarMultiGrepReducerAotCompileDispositionV1::Selected(
        artifact,
    ))
}
