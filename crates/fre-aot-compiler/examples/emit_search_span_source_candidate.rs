//! Emit one inert, source-reviewable Search Span AOT candidate bundle.
//!
//! This example deliberately stops before linking, mapped-image inspection,
//! qualification, or runtime adoption. It stages a fixed artifact set, reopens
//! and strictly inspects every staged artifact, then publishes content into a
//! create-new private directory. `SHA256SUMS` is moved into place strictly last
//! as the readiness atom.

use std::{
    error::Error,
    ffi::OsStr,
    fmt::Write as _,
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{self, Read, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
};

use fre::RustProfile;
use fre_aot_compiler::{
    AOT_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1, AOT_SEARCH_COMPILER_VERSION_V1,
    AOT_SEARCH_MANIFEST_SCHEMA_VERSION_V1, MacosAarch64ExactSearchManifestV1,
    PublishedSearchSpanFinalImageGlueV1, SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1,
    SearchAotRuntimeAuthorityV1, SearchCompiledObjectV1, SearchSpanFinalImageAdopterV1,
    SearchSpanFinalImageGlueLimitsV1, StaticSearchSpanExpectationV1,
    UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1, build_static_search_span_expectation_v1,
    inspect_search_span_final_image_glue_v1, plan_and_compile_macos_aarch64_exact_search_v1,
    publish_search_span_final_image_glue_v1, publish_search_span_qualification_final_image_glue_v1,
};
use fre_aot_macho::{ObjectLimits, inspect_object};
use fre_aot_search_contract::{
    STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1, inspect_static_search_span_expectation_v1,
};
use fre_kernel_ir::{OutputKind, Span};
use sha2::{Digest, Sha256};

type DynError = Box<dyn Error>;

const LITERAL: &[u8] = b"0123456789abcdef";
const ROW_SELECTOR: u16 = 1;
const ALTERNATE_ROW_SELECTOR: u16 = 2;
const SOURCE_ROW_QUALIFICATION_FIELDS: usize = 12;
const MAX_IMPLEMENTATION_OBJECT_BYTES: u64 = 16 << 20;
const MAX_GLUE_OBJECT_BYTES: u64 = 16 << 10;
const MAX_TEXT_ARTIFACT_BYTES: u64 = 64 << 10;
const MAX_HASH_MANIFEST_BYTES: u64 = 8 << 10;
const PRIVATE_DIRECTORY_PERMISSIONS: u32 = 0o700;
const PRIVATE_FILE_PERMISSIONS: u32 = 0o600;
const PERMISSION_BITS: u32 = 0o7777;
const STAGING_NONCE_BYTES: usize = 16;
const STAGING_CREATE_ATTEMPTS: usize = 16;

const HASHED_ARTIFACTS: [&str; 11] = [
    "alternate-selector-glue-receipt.bin",
    "alternate-selector-glue.o",
    "compiler-receipt.bin",
    "compiler-receipt.tsv",
    "expectation.bin",
    "implementation.o",
    "production-glue-receipt.bin",
    "production-glue.o",
    "qualification-glue-receipt.bin",
    "qualification-glue.o",
    "source-row-proposal.tsv",
];

const COMPLETE_OUTPUTS: [&str; 12] = [
    "SHA256SUMS",
    "alternate-selector-glue-receipt.bin",
    "alternate-selector-glue.o",
    "compiler-receipt.bin",
    "compiler-receipt.tsv",
    "expectation.bin",
    "implementation.o",
    "production-glue-receipt.bin",
    "production-glue.o",
    "qualification-glue-receipt.bin",
    "qualification-glue.o",
    "source-row-proposal.tsv",
];

struct Candidate {
    compiled: SearchCompiledObjectV1<Span>,
    expectation: StaticSearchSpanExpectationV1,
    qualification: PublishedSearchSpanFinalImageGlueV1,
    production: PublishedSearchSpanFinalImageGlueV1,
    alternate_selector: PublishedSearchSpanFinalImageGlueV1,
    canonical_compiler_receipt: [u8; SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1],
    compiler_receipt_review: Vec<u8>,
    source_row_proposal: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
}

struct PrivateDirectory {
    path: PathBuf,
    handle: File,
    identity: DirectoryIdentity,
}

impl PrivateDirectory {
    fn create_staging(parent: &Path) -> Result<Self, DynError> {
        for _attempt in 0..STAGING_CREATE_ATTEMPTS {
            let nonce = random_staging_nonce()?;
            let path = parent.join(format!(
                ".fre-aot-search-span-source-candidate.{}.partial",
                hex(&nonce)
            ));
            match create_private_directory_entry(&path) {
                Ok(()) => return open_created_private_directory(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(invalid("could not create a collision-free random staging directory").into())
    }

    fn create_final(output: &Path) -> Result<Self, DynError> {
        create_private_directory_entry(output)?;
        open_created_private_directory(output.to_path_buf())
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }

    fn validate(&self) -> Result<(), DynError> {
        let descriptor = self.handle.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        validate_directory_metadata(&descriptor, self.identity, "directory descriptor")?;
        validate_directory_metadata(&named, self.identity, "named directory")?;
        require(
            descriptor.dev() == named.dev()
                && descriptor.ino() == named.ino()
                && descriptor.mode() == named.mode(),
            "directory descriptor and named path identity disagree",
        )
    }

    fn sync(&self) -> Result<(), DynError> {
        self.validate()?;
        self.handle.sync_all()?;
        self.validate()
    }

    fn remove_if_exactly_empty(self) -> Result<(), DynError> {
        self.validate()?;
        let mut entries = fs::read_dir(&self.path)?;
        require(
            entries.next().is_none(),
            "verified staging directory is not empty",
        )?;
        self.handle.sync_all()?;
        self.validate()?;
        fs::remove_dir(&self.path)?;
        validate_directory_metadata(
            &self.handle.metadata()?,
            self.identity,
            "unlinked staging directory descriptor",
        )?;
        require_path_absent(&self.path, "removed staging directory")
    }
}

fn main() -> Result<(), DynError> {
    let output = output_argument()?;
    let parent = output
        .parent()
        .ok_or_else(|| invalid("output directory has no parent"))?;
    let staging = PrivateDirectory::create_staging(parent)?;
    let candidate = build_candidate()?;

    write_candidate(&staging, &candidate)?;
    staging.sync()?;
    reopen_and_verify_content(&staging, &candidate)?;
    write_hash_manifest(&staging)?;
    staging.sync()?;
    reopen_and_verify_complete(&staging, &candidate)?;

    let published = PrivateDirectory::create_final(&output)?;
    publish_content_files(&staging, &published)?;
    staging.sync()?;
    published.sync()?;
    reopen_and_verify_content(&published, &candidate)?;
    verify_exact_directory(&staging, &["SHA256SUMS"])?;

    // Readiness transition: no final artifact is created or moved after this
    // exact manifest rename.
    move_named(&staging, &published, "SHA256SUMS")?;
    staging.sync()?;
    published.sync()?;
    sync_parent_directory(parent)?;
    reopen_and_verify_complete(&published, &candidate)?;

    staging.remove_if_exactly_empty()?;
    sync_parent_directory(parent)?;
    published.validate()?;
    reopen_and_verify_complete(&published, &candidate)?;

    println!("{}", output.display());
    Ok(())
}

fn output_argument() -> Result<PathBuf, DynError> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let requested = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| invalid("usage: emit_search_span_source_candidate OUTPUT_DIRECTORY"))?,
    );
    if arguments.next().is_some() {
        return Err(invalid("usage: emit_search_span_source_candidate OUTPUT_DIRECTORY").into());
    }
    let name = requested
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid("output directory must have one final path component"))?;
    if name == OsStr::new(".") || name == OsStr::new("..") {
        return Err(invalid("output directory final component is not admissible").into());
    }
    let parent_input = requested
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent_input)?;
    if !fs::metadata(&parent)?.is_dir() {
        return Err(invalid("output parent is not a directory").into());
    }
    let output = parent.join(name);
    require_path_absent(&output, "final output directory")?;
    Ok(output)
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixed transaction constructs and cross-binds every proposal artifact"
)]
fn build_candidate() -> Result<Candidate, DynError> {
    let mut source = Vec::new();
    source.try_reserve_exact(LITERAL.len())?;
    require(
        source.capacity() == LITERAL.len(),
        "fixed source allocation did not retain its exact requested capacity",
    )?;
    source.extend_from_slice(LITERAL);

    let mut profile = RustProfile::default();
    profile.options.unicode = false;
    let compiled = plan_and_compile_macos_aarch64_exact_search_v1(
        MacosAarch64ExactSearchManifestV1::<Span>::default(),
        source,
        profile,
    )?;
    require(
        compiled.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
            && compiled.receipt().runtime_authority() == SearchAotRuntimeAuthorityV1::Absent,
        "compiler unexpectedly granted runtime authority",
    )?;
    require(
        compiled.receipt().output() == OutputKind::Span
            && compiled.receipt().literal_bytes()
                == u32::try_from(LITERAL.len()).map_err(|_| invalid("literal width overflow"))?,
        "compiler result disagrees with the fixed Span/literal request",
    )?;

    let expectation = build_static_search_span_expectation_v1(&compiled)?;
    require(
        expectation.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent,
        "expectation unexpectedly granted runtime authority",
    )?;
    let qualification = publish_search_span_qualification_final_image_glue_v1(
        &compiled,
        &expectation,
        ROW_SELECTOR,
        SearchSpanFinalImageGlueLimitsV1::default(),
    )?;
    let production = publish_search_span_final_image_glue_v1(
        &compiled,
        &expectation,
        ROW_SELECTOR,
        SearchSpanFinalImageGlueLimitsV1::default(),
    )?;
    let alternate_selector = publish_search_span_qualification_final_image_glue_v1(
        &compiled,
        &expectation,
        ALTERNATE_ROW_SELECTOR,
        SearchSpanFinalImageGlueLimitsV1::default(),
    )?;
    for glue in [&qualification, &production, &alternate_selector] {
        require(
            glue.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
                && glue.receipt().runtime_authority() == SearchAotRuntimeAuthorityV1::Absent,
            "glue unexpectedly granted runtime authority",
        )?;
    }
    require(
        qualification.object().as_bytes() != production.object().as_bytes()
            && qualification.object().as_bytes() != alternate_selector.object().as_bytes(),
        "adopter and selector controls must produce distinct glue objects",
    )?;

    let object_inspection = compiled
        .receipt()
        .validate_object(compiled.object().as_bytes(), ObjectLimits::default())?;
    let canonical_compiler_receipt = compiled.receipt().canonical_bytes()?;
    let compiler_receipt_review =
        render_compiler_receipt(&compiled, &expectation, object_inspection.payload())?;
    let source_row_proposal =
        render_source_row_proposal(&compiled, &expectation, object_inspection.payload())?;

    Ok(Candidate {
        compiled,
        expectation,
        qualification,
        production,
        alternate_selector,
        canonical_compiler_receipt,
        compiler_receipt_review,
        source_row_proposal,
    })
}

fn write_candidate(directory: &PrivateDirectory, candidate: &Candidate) -> Result<(), DynError> {
    write_named(
        directory,
        "implementation.o",
        candidate.compiled.object().as_bytes(),
    )?;
    write_named(
        directory,
        "expectation.bin",
        candidate.expectation.as_bytes(),
    )?;
    write_glue(directory, "qualification", &candidate.qualification)?;
    write_glue(directory, "production", &candidate.production)?;
    write_glue(
        directory,
        "alternate-selector",
        &candidate.alternate_selector,
    )?;
    write_named(
        directory,
        "compiler-receipt.bin",
        &candidate.canonical_compiler_receipt,
    )?;
    write_named(
        directory,
        "compiler-receipt.tsv",
        &candidate.compiler_receipt_review,
    )?;
    write_named(
        directory,
        "source-row-proposal.tsv",
        &candidate.source_row_proposal,
    )
}

fn write_glue(
    directory: &PrivateDirectory,
    stem: &str,
    glue: &PublishedSearchSpanFinalImageGlueV1,
) -> Result<(), DynError> {
    write_named(
        directory,
        &format!("{stem}-glue.o"),
        glue.object().as_bytes(),
    )?;
    write_named(
        directory,
        &format!("{stem}-glue-receipt.bin"),
        glue.receipt().canonical_bytes(),
    )
}

fn write_named(directory: &PrivateDirectory, name: &str, bytes: &[u8]) -> Result<(), DynError> {
    directory.validate()?;
    let maximum = maximum_artifact_bytes(name)?;
    let length = u64::try_from(bytes.len()).map_err(|_| invalid("artifact length overflow"))?;
    require(length <= maximum, "artifact exceeds its fixed output bound")?;
    let path = directory.path().join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_PERMISSIONS)
        .open(&path)?;
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_PERMISSIONS))?;
    let created = file.metadata()?;
    let identity = file_identity(&created, "new artifact descriptor")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let written = file.metadata()?;
    validate_file_metadata(&written, identity, "written artifact descriptor")?;
    require(
        written.len() == length,
        "written artifact length disagrees with source bytes",
    )?;
    drop(file);
    require(
        read_named(directory, name)?.as_slice() == bytes,
        "create-new artifact did not reopen as its exact source bytes",
    )?;
    directory.validate()?;
    Ok(())
}

fn write_hash_manifest(directory: &PrivateDirectory) -> Result<(), DynError> {
    let mut manifest = String::new();
    manifest.try_reserve_exact(2 << 10)?;
    for name in HASHED_ARTIFACTS {
        let bytes = read_named(directory, name)?;
        writeln!(manifest, "{}  {name}", hex(&sha256(&bytes)))?;
    }
    write_named(directory, "SHA256SUMS", manifest.as_bytes())
}

#[allow(
    clippy::too_many_lines,
    reason = "one semantic pass reopens and cross-checks the complete content tuple"
)]
fn reopen_and_verify_semantic_content(
    directory: &PrivateDirectory,
    candidate: &Candidate,
) -> Result<(), DynError> {
    let implementation = read_named(directory, "implementation.o")?;
    require(
        implementation == candidate.compiled.object().as_bytes(),
        "reopened implementation bytes changed",
    )?;
    let direct_inspection = inspect_object(&implementation, ObjectLimits::default())?;
    let receipt_inspection = candidate
        .compiled
        .receipt()
        .validate_object(&implementation, ObjectLimits::default())?;
    require(
        direct_inspection == receipt_inspection,
        "direct and compiler-receipt object inspections disagree",
    )?;
    require(
        sha256(&implementation) == *candidate.compiled.receipt().object_identity().as_bytes(),
        "implementation content hash disagrees with object identity",
    )?;

    let expectation = read_named(directory, "expectation.bin")?;
    require(
        expectation.len() == STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1
            && expectation.as_slice() == candidate.expectation.as_bytes(),
        "reopened expectation bytes changed",
    )?;
    let expectation_claim = inspect_static_search_span_expectation_v1(&expectation)?;
    require(
        candidate
            .expectation
            .authenticates_claim(&expectation_claim),
        "reopened expectation is not authenticated by compiler state",
    )?;

    verify_glue(
        directory,
        "qualification",
        &candidate.qualification,
        &candidate.compiled,
        &candidate.expectation,
        ROW_SELECTOR,
        SearchSpanFinalImageAdopterV1::QualificationPrivate,
    )?;
    verify_glue(
        directory,
        "production",
        &candidate.production,
        &candidate.compiled,
        &candidate.expectation,
        ROW_SELECTOR,
        SearchSpanFinalImageAdopterV1::Production,
    )?;
    verify_glue(
        directory,
        "alternate-selector",
        &candidate.alternate_selector,
        &candidate.compiled,
        &candidate.expectation,
        ALTERNATE_ROW_SELECTOR,
        SearchSpanFinalImageAdopterV1::QualificationPrivate,
    )?;

    require(
        read_named(directory, "compiler-receipt.bin")?.as_slice()
            == candidate.canonical_compiler_receipt.as_slice(),
        "reopened canonical compiler receipt stream changed",
    )?;
    require(
        sha256(&candidate.canonical_compiler_receipt)
            == *candidate.compiled.receipt().receipt_identity().as_bytes(),
        "canonical compiler receipt stream disagrees with its identity",
    )?;
    require(
        read_named(directory, "compiler-receipt.tsv")?.as_slice()
            == candidate.compiler_receipt_review.as_slice(),
        "reopened compiler receipt review projection changed",
    )?;
    require(
        read_named(directory, "source-row-proposal.tsv")?.as_slice()
            == candidate.source_row_proposal.as_slice(),
        "reopened source-row proposal changed",
    )?;

    Ok(())
}

fn reopen_and_verify_content(
    directory: &PrivateDirectory,
    candidate: &Candidate,
) -> Result<(), DynError> {
    verify_exact_directory(directory, &HASHED_ARTIFACTS)?;
    reopen_and_verify_semantic_content(directory, candidate)
}

fn reopen_and_verify_complete(
    directory: &PrivateDirectory,
    candidate: &Candidate,
) -> Result<(), DynError> {
    verify_exact_directory(directory, &COMPLETE_OUTPUTS)?;
    reopen_and_verify_semantic_content(directory, candidate)?;
    let expected_hash_manifest = render_hash_manifest(directory)?;
    let actual_hash_manifest = read_named(directory, "SHA256SUMS")?;
    require(
        actual_hash_manifest == expected_hash_manifest,
        "reopened SHA256 manifest is not canonical",
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "every glue check explicitly names its source and routing contract"
)]
fn verify_glue(
    directory: &PrivateDirectory,
    stem: &str,
    published: &PublishedSearchSpanFinalImageGlueV1,
    compiled: &SearchCompiledObjectV1<Span>,
    expectation: &StaticSearchSpanExpectationV1,
    selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
) -> Result<(), DynError> {
    let object = read_named(directory, &format!("{stem}-glue.o"))?;
    let receipt = read_named(directory, &format!("{stem}-glue-receipt.bin"))?;
    require(
        object.as_slice() == published.object().as_bytes()
            && receipt.as_slice() == published.receipt().canonical_bytes(),
        "reopened glue object or canonical receipt changed",
    )?;
    require(
        published.receipt().authenticates_itself()
            && published.receipt().row_selector() == selector
            && published.receipt().adopter() == Some(adopter),
        "canonical glue receipt does not authenticate its route",
    )?;
    let direct = inspect_search_span_final_image_glue_v1(
        &object,
        SearchSpanFinalImageGlueLimitsV1::default(),
    )?;
    let receipt_bound = published.receipt().validate_candidate(
        compiled,
        expectation,
        &object,
        SearchSpanFinalImageGlueLimitsV1::default(),
    )?;
    require(
        direct == receipt_bound
            && direct.row_selector() == selector
            && direct.adopter() == adopter
            && direct.expectation() == expectation.as_bytes()
            && direct.glue_object_identity() == &sha256(&object),
        "strict glue inspections disagree with the expected source route",
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the source-reviewable receipt keeps its complete canonical field list together"
)]
fn render_compiler_receipt(
    compiled: &SearchCompiledObjectV1<Span>,
    expectation: &StaticSearchSpanExpectationV1,
    payload: &[u8],
) -> Result<Vec<u8>, DynError> {
    let receipt = compiled.receipt();
    let metadata = receipt.metadata();
    let accounting = receipt.accounting();
    let object_sha256 = sha256(compiled.object().as_bytes());
    let payload_sha256 = sha256(payload);
    require(
        object_sha256 == *receipt.object_identity().as_bytes()
            && payload_sha256 == *metadata.payload_sha256()
            && expectation.compile_identity() == receipt.compile_identity()
            && expectation.object_identity() == receipt.object_identity()
            && expectation.receipt_identity() == receipt.receipt_identity(),
        "compiler receipt inputs are not identity-closed",
    )?;

    let mut output = String::new();
    output.try_reserve_exact(4 << 10)?;
    for (key, value) in [
        (
            "schema",
            "fre-aot-search-span-source-compiler-receipt-v1".to_owned(),
        ),
        (
            "compiler_receipt_schema_version",
            AOT_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1.to_string(),
        ),
        (
            "compiler_version",
            AOT_SEARCH_COMPILER_VERSION_V1.to_string(),
        ),
        (
            "manifest_schema_version",
            AOT_SEARCH_MANIFEST_SCHEMA_VERSION_V1.to_string(),
        ),
        ("target", "aarch64-apple-macos".to_owned()),
        ("output", "span".to_owned()),
        ("literal_hex", hex(LITERAL)),
        ("literal_bytes", receipt.literal_bytes().to_string()),
        ("unicode", "false".to_owned()),
        ("anchor_start", "false".to_owned()),
        ("anchor_end", "false".to_owned()),
        ("runtime_authority", "absent".to_owned()),
        (
            "manifest_identity",
            hex(receipt.manifest_identity().as_bytes()),
        ),
        (
            "semantic_binding_identity",
            hex(receipt.semantic_binding_identity().as_bytes()),
        ),
        (
            "literal_identity",
            hex(receipt.literal_identity().as_bytes()),
        ),
        ("kir_identity", hex(receipt.kir_identity().as_bytes())),
        (
            "artifact_identity",
            hex(receipt.native_artifact_identity().as_bytes()),
        ),
        (
            "binding_identity",
            hex(receipt.binding_identity().as_bytes()),
        ),
        (
            "compile_identity",
            hex(receipt.compile_identity().as_bytes()),
        ),
        ("object_identity", hex(receipt.object_identity().as_bytes())),
        (
            "receipt_identity",
            hex(receipt.receipt_identity().as_bytes()),
        ),
        (
            "expectation_identity",
            hex(expectation.expectation_identity().as_bytes()),
        ),
        ("implementation_sha256", hex(&object_sha256)),
        ("payload_identity", hex(&payload_sha256)),
        (
            "metadata_sha256",
            hex(&sha256(expectation.metadata_bytes_v1())),
        ),
        (
            "object_bytes",
            compiled.object().as_bytes().len().to_string(),
        ),
        ("payload_bytes", metadata.payload_bytes().to_string()),
        ("code_bytes", metadata.code_bytes().to_string()),
        ("rodata_offset", metadata.rodata_offset().to_string()),
        ("rodata_bytes", metadata.rodata_bytes().to_string()),
        ("source_bytes", accounting.source_bytes().to_string()),
        (
            "source_capacity_bytes",
            accounting.source_capacity_bytes().to_string(),
        ),
        (
            "result_persistent_bytes",
            accounting.result_persistent_bytes().to_string(),
        ),
        (
            "observed_stage_scratch_bytes_upper_bound",
            accounting
                .observed_stage_scratch_bytes_upper_bound()
                .to_string(),
        ),
    ] {
        writeln!(output, "{key}\t{value}")?;
    }
    bounded_text(output)
}

fn render_source_row_proposal(
    compiled: &SearchCompiledObjectV1<Span>,
    expectation: &StaticSearchSpanExpectationV1,
    payload: &[u8],
) -> Result<Vec<u8>, DynError> {
    let receipt = compiled.receipt();
    let fields = [
        ("live_literal_bytes", receipt.literal_bytes().to_string()),
        (
            "manifest_identity",
            hex(receipt.manifest_identity().as_bytes()),
        ),
        (
            "semantic_binding_identity",
            hex(receipt.semantic_binding_identity().as_bytes()),
        ),
        (
            "literal_identity",
            hex(receipt.literal_identity().as_bytes()),
        ),
        ("kir_identity", hex(receipt.kir_identity().as_bytes())),
        (
            "artifact_identity",
            hex(receipt.native_artifact_identity().as_bytes()),
        ),
        (
            "binding_identity",
            hex(receipt.binding_identity().as_bytes()),
        ),
        (
            "compile_identity",
            hex(receipt.compile_identity().as_bytes()),
        ),
        ("object_identity", hex(receipt.object_identity().as_bytes())),
        (
            "receipt_identity",
            hex(receipt.receipt_identity().as_bytes()),
        ),
        (
            "expectation_identity",
            hex(expectation.expectation_identity().as_bytes()),
        ),
        ("payload_identity", hex(&sha256(payload))),
    ];
    require(
        fields.len() == SOURCE_ROW_QUALIFICATION_FIELDS,
        "source-row qualification-field cardinality changed",
    )?;

    let mut output = String::new();
    output.try_reserve_exact(4 << 10)?;
    for (key, value) in [
        (
            "schema",
            "fre-aot-search-span-source-row-proposal-v1".to_owned(),
        ),
        ("promotion_state", "proposal-only".to_owned()),
        ("table_target", "private-qualification-input".to_owned()),
        ("runtime_authority", "absent".to_owned()),
        ("selector", ROW_SELECTOR.to_string()),
        (
            "qualification_field_count",
            SOURCE_ROW_QUALIFICATION_FIELDS.to_string(),
        ),
    ] {
        writeln!(output, "{key}\t{value}")?;
    }
    for (key, value) in fields {
        writeln!(output, "{key}\t{value}")?;
    }
    bounded_text(output)
}

fn bounded_text(output: String) -> Result<Vec<u8>, DynError> {
    require(
        u64::try_from(output.len()).map_err(|_| invalid("text length overflow"))?
            <= MAX_TEXT_ARTIFACT_BYTES,
        "canonical text artifact exceeds its fixed bound",
    )?;
    require(
        output.is_ascii()
            && output.ends_with('\n')
            && !output.as_bytes().contains(&b'\r')
            && !output.as_bytes().contains(&0),
        "canonical text artifact is not LF-terminated ASCII",
    )?;
    Ok(output.into_bytes())
}

fn render_hash_manifest(directory: &PrivateDirectory) -> Result<Vec<u8>, DynError> {
    let mut manifest = String::new();
    manifest.try_reserve_exact(2 << 10)?;
    for name in HASHED_ARTIFACTS {
        let bytes = read_named(directory, name)?;
        writeln!(manifest, "{}  {name}", hex(&sha256(&bytes)))?;
    }
    let bytes = manifest.into_bytes();
    require(
        u64::try_from(bytes.len()).map_err(|_| invalid("hash manifest length overflow"))?
            <= MAX_HASH_MANIFEST_BYTES,
        "SHA256 manifest exceeds its fixed bound",
    )?;
    Ok(bytes)
}

fn verify_exact_directory(directory: &PrivateDirectory, expected: &[&str]) -> Result<(), DynError> {
    directory.validate()?;
    let mut actual = Vec::new();
    actual.try_reserve_exact(expected.len())?;
    for entry in fs::read_dir(directory.path())? {
        require(
            actual.len() < expected.len(),
            "private directory contains too many artifacts",
        )?;
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("non-UTF-8 artifact name"))?;
        actual.push(name);
    }
    actual.sort();
    require(
        actual == expected.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "private directory is not the expected exact artifact set",
    )?;
    directory.validate()
}

fn read_named(directory: &PrivateDirectory, name: &str) -> Result<Vec<u8>, DynError> {
    directory.validate()?;
    let path = directory.path().join(name);
    let maximum = maximum_artifact_bytes(name)?;
    let named_before = fs::symlink_metadata(&path)?;
    let named_identity = file_identity(&named_before, "named artifact before open")?;
    require(named_before.len() <= maximum, "artifact exceeds its bound")?;
    let mut file = File::open(&path)?;
    let descriptor_before = file.metadata()?;
    validate_file_metadata(
        &descriptor_before,
        named_identity,
        "artifact descriptor before read",
    )?;
    let capacity =
        usize::try_from(named_before.len()).map_err(|_| invalid("artifact length is not usize"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity)?;
    let read_bound = maximum
        .checked_add(1)
        .ok_or_else(|| invalid("artifact read bound overflow"))?;
    (&mut file).take(read_bound).read_to_end(&mut bytes)?;
    let descriptor_after = file.metadata()?;
    let named_after = fs::symlink_metadata(&path)?;
    validate_file_metadata(
        &descriptor_after,
        named_identity,
        "artifact descriptor after read",
    )?;
    validate_file_metadata(&named_after, named_identity, "named artifact after read")?;
    require(
        named_before.len() == descriptor_before.len()
            && named_before.len() == descriptor_after.len()
            && named_before.len() == named_after.len()
            && u64::try_from(bytes.len()).ok() == Some(named_before.len())
            && u64::try_from(bytes.len()).is_ok_and(|length| length <= maximum),
        "artifact changed or exceeded its bound while reopening",
    )?;
    directory.validate()?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
}

fn create_private_directory_entry(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(PRIVATE_DIRECTORY_PERMISSIONS);
    builder.create(path)
}

fn open_created_private_directory(path: PathBuf) -> Result<PrivateDirectory, DynError> {
    let handle = File::open(&path)?;
    handle.set_permissions(fs::Permissions::from_mode(PRIVATE_DIRECTORY_PERMISSIONS))?;
    let metadata = handle.metadata()?;
    let identity = directory_identity(&metadata, "new private directory descriptor")?;
    let directory = PrivateDirectory {
        path,
        handle,
        identity,
    };
    directory.validate()?;
    Ok(directory)
}

fn random_staging_nonce() -> Result<[u8; STAGING_NONCE_BYTES], DynError> {
    let mut nonce = [0_u8; STAGING_NONCE_BYTES];
    let mut random = File::open("/dev/urandom")?;
    random.read_exact(&mut nonce)?;
    Ok(nonce)
}

fn directory_identity(metadata: &Metadata, label: &str) -> Result<DirectoryIdentity, DynError> {
    require(
        metadata.file_type().is_dir(),
        &format!("{label} is not a directory"),
    )?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
    })
}

fn validate_directory_metadata(
    metadata: &Metadata,
    expected: DirectoryIdentity,
    label: &str,
) -> Result<(), DynError> {
    let actual = directory_identity(metadata, label)?;
    require(
        actual == expected && actual.mode & PERMISSION_BITS == PRIVATE_DIRECTORY_PERMISSIONS,
        &format!("{label} changed identity or is not mode 0700"),
    )
}

fn file_identity(metadata: &Metadata, label: &str) -> Result<FileIdentity, DynError> {
    require(
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && metadata.mode() & PERMISSION_BITS == PRIVATE_FILE_PERMISSIONS,
        &format!("{label} is not one link to a mode-0600 regular file"),
    )?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        mode: metadata.mode(),
    })
}

fn validate_file_metadata(
    metadata: &Metadata,
    expected: FileIdentity,
    label: &str,
) -> Result<(), DynError> {
    let actual = file_identity(metadata, label)?;
    require(
        actual == expected,
        &format!("{label} changed dev/inode/nlink/mode identity"),
    )
}

fn publish_content_files(
    staging: &PrivateDirectory,
    published: &PrivateDirectory,
) -> Result<(), DynError> {
    verify_exact_directory(staging, &COMPLETE_OUTPUTS)?;
    verify_exact_directory(published, &[])?;
    for name in HASHED_ARTIFACTS {
        move_named(staging, published, name)?;
    }
    verify_exact_directory(published, &HASHED_ARTIFACTS)?;
    verify_exact_directory(staging, &["SHA256SUMS"])
}

fn move_named(
    source: &PrivateDirectory,
    destination: &PrivateDirectory,
    name: &str,
) -> Result<(), DynError> {
    source.validate()?;
    destination.validate()?;
    let before = read_named(source, name)?;
    let source_path = source.path().join(name);
    let destination_path = destination.path().join(name);
    require_path_absent(&destination_path, "publication destination artifact")?;
    fs::rename(&source_path, &destination_path)?;
    source.validate()?;
    destination.validate()?;
    let after = read_named(destination, name)?;
    require(
        before == after,
        "moved artifact did not reopen as its exact staged bytes",
    )
}

fn maximum_artifact_bytes(name: &str) -> Result<u64, DynError> {
    match name {
        "implementation.o" => Ok(MAX_IMPLEMENTATION_OBJECT_BYTES),
        "qualification-glue.o" | "production-glue.o" | "alternate-selector-glue.o" => {
            Ok(MAX_GLUE_OBJECT_BYTES)
        }
        "expectation.bin" => Ok(u64::try_from(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
            .map_err(|_| invalid("expectation bound overflow"))?),
        "compiler-receipt.bin" => Ok(u64::try_from(SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1)
            .map_err(|_| invalid("compiler receipt bound overflow"))?),
        "qualification-glue-receipt.bin"
        | "production-glue-receipt.bin"
        | "alternate-selector-glue-receipt.bin" => Ok(u64::try_from(
            UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1,
        )
        .map_err(|_| invalid("glue receipt bound overflow"))?),
        "compiler-receipt.tsv" | "source-row-proposal.tsv" => Ok(MAX_TEXT_ARTIFACT_BYTES),
        "SHA256SUMS" => Ok(MAX_HASH_MANIFEST_BYTES),
        _ => Err(invalid("unknown artifact name").into()),
    }
}

fn require_path_absent(path: &Path, label: &str) -> Result<(), DynError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(invalid(format!("{label} already exists")).into()),
    }
}

fn sync_parent_directory(path: &Path) -> Result<(), DynError> {
    let named_before = fs::symlink_metadata(path)?;
    let identity = directory_identity(&named_before, "parent directory before sync")?;
    let handle = File::open(path)?;
    let descriptor_before = handle.metadata()?;
    require(
        directory_identity(&descriptor_before, "parent descriptor before sync")? == identity,
        "parent descriptor and named path identity disagree before sync",
    )?;
    handle.sync_all()?;
    let descriptor_after = handle.metadata()?;
    let named_after = fs::symlink_metadata(path)?;
    require(
        directory_identity(&descriptor_after, "parent descriptor after sync")? == identity
            && directory_identity(&named_after, "parent directory after sync")? == identity,
        "parent directory identity changed during sync",
    )
}

fn require(condition: bool, message: &str) -> Result<(), DynError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message).into())
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    let capacity = bytes.len().checked_mul(2).expect("bounded hex capacity");
    let mut output = String::with_capacity(capacity);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("String writes cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_sets_are_sorted_closed_and_bounded() {
        assert!(HASHED_ARTIFACTS.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(COMPLETE_OUTPUTS.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(COMPLETE_OUTPUTS[0], "SHA256SUMS");
        assert!(!HASHED_ARTIFACTS.contains(&"SHA256SUMS"));
        assert_eq!(COMPLETE_OUTPUTS.len(), HASHED_ARTIFACTS.len() + 1);
        for name in COMPLETE_OUTPUTS {
            assert!(maximum_artifact_bytes(name).is_ok());
        }
    }

    #[test]
    fn publication_permissions_and_nonce_are_pinned() {
        assert_eq!(PRIVATE_DIRECTORY_PERMISSIONS, 0o700);
        assert_eq!(PRIVATE_FILE_PERMISSIONS, 0o600);
        assert_eq!(STAGING_NONCE_BYTES, 16);
        assert_eq!(STAGING_CREATE_ATTEMPTS, 16);
    }

    #[test]
    fn proposal_contract_has_one_selector_and_twelve_fields() {
        assert_eq!(ROW_SELECTOR, 1);
        assert_eq!(ALTERNATE_ROW_SELECTOR, 2);
        assert_eq!(SOURCE_ROW_QUALIFICATION_FIELDS, 12);
    }

    #[test]
    fn canonical_hex_is_lowercase_and_fixed_width() {
        assert_eq!(hex(&[0, 1, 0xab, 0xff]), "0001abff");
    }

    #[test]
    fn literal_and_expectation_bounds_are_pinned() {
        assert_eq!(LITERAL, b"0123456789abcdef");
        assert_eq!(LITERAL.len(), 16);
        assert_eq!(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1, 584);
    }
}
