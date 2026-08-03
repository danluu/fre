//! Emit one closed, inert Linux `AArch64` Search Span AOT candidate bundle.
//!
//! Usage:
//!
//! ```text
//! emit_linux_search_span_source_candidate OUTPUT_DIRECTORY \
//!     v8|v9|v10|v12|v13|v15|v16|v17|v24|v25|v26|tag21 \
//!     qualification|production ROW_SELECTOR
//! ```
//!
//! Exactly one final-image glue object is emitted. The example stages a fixed
//! artifact set in a private create-new directory, reopens every artifact
//! through the public strict decoders, publishes into a second create-new
//! directory, and moves `SHA256SUMS` into place last as the readiness atom.
//! The source-row artifact is proposal-only; this program cannot modify either
//! runtime qualification table or grant runtime authority.

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
    AOT_LINUX_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1, AOT_LINUX_SEARCH_COMPILER_VERSION_V1,
    AOT_LINUX_SEARCH_MANIFEST_SCHEMA_VERSION_V1, LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1,
    LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1, LinuxAarch64ExactSearchManifestV1,
    LinuxAarch64SearchBackendV1, LinuxAarch64SearchCompilePolicyV1,
    LinuxSearchCompileReceiptInspectionV1, LinuxSearchCompiledObjectV1,
    LinuxSearchSpanFinalImageGlueInspectionV1, LinuxSearchSpanFinalImageGlueLimitsV1,
    LinuxSearchSpanFinalImageSymbolsV1, LinuxStaticSearchSpanExpectationV1,
    LinuxUnsignedSearchSpanFinalImageReceiptV1, PublishedLinuxSearchSpanFinalImageGlueV1,
    SearchAotRuntimeAuthorityV1, SearchSpanFinalImageAdopterV1,
    build_linux_static_search_span_expectation_v1, compute_linux_search_literal_identity_v1,
    inspect_linux_search_compile_receipt_v1, plan_and_compile_linux_aarch64_exact_search_v1,
    publish_linux_search_span_final_image_glue_v1,
    publish_linux_search_span_qualification_final_image_glue_v1,
};
use fre_aot_elf::{ObjectInspectionV1, ObjectLimitsV1};
use fre_aot_search_contract::{
    ClaimedStaticSearchSpanExpectationV1, STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
};
use fre_kernel_ir::{OutputKind, Span};
use sha2::{Digest, Sha256};

type DynError = Box<dyn Error>;

const LITERAL: &[u8] = b"0123456789abcdef";
const SOURCE_ROW_QUALIFICATION_FIELDS: usize = 12;
const MAX_IMPLEMENTATION_OBJECT_BYTES: u64 = 16 << 20;
const MAX_GLUE_OBJECT_BYTES: u64 = 64 << 10;
const MAX_TEXT_ARTIFACT_BYTES: u64 = 128 << 10;
const MAX_HASH_MANIFEST_BYTES: u64 = 8 << 10;
const PRIVATE_DIRECTORY_PERMISSIONS: u32 = 0o700;
const PRIVATE_FILE_PERMISSIONS: u32 = 0o600;
const PERMISSION_BITS: u32 = 0o7777;
const STAGING_NONCE_BYTES: usize = 16;
const STAGING_CREATE_ATTEMPTS: usize = 16;

const HASHED_ARTIFACTS: [&str; 10] = [
    "bindings.h",
    "bindings.rs",
    "bundle.tsv",
    "compiler-receipt.bin",
    "expectation.bin",
    "final-image-glue-receipt.bin",
    "final-image-glue.o",
    "implementation.o",
    "source-row-proposal.tsv",
    "source.regex",
];

const COMPLETE_OUTPUTS: [&str; 11] = [
    "SHA256SUMS",
    "bindings.h",
    "bindings.rs",
    "bundle.tsv",
    "compiler-receipt.bin",
    "expectation.bin",
    "final-image-glue-receipt.bin",
    "final-image-glue.o",
    "implementation.o",
    "source-row-proposal.tsv",
    "source.regex",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateRoute {
    backend: LinuxAarch64SearchBackendV1,
    adopter: SearchSpanFinalImageAdopterV1,
    row_selector: u16,
}

struct Request {
    output: PathBuf,
    route: CandidateRoute,
}

struct Candidate {
    compiled: LinuxSearchCompiledObjectV1<Span>,
    expectation: LinuxStaticSearchSpanExpectationV1,
    glue: PublishedLinuxSearchSpanFinalImageGlueV1,
    compiler_receipt: [u8; LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1],
    glue_receipt: [u8; LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1],
    c_header: Vec<u8>,
    rust_bindings: Vec<u8>,
    bundle_review: Vec<u8>,
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
                ".fre-aot-linux-search-span-candidate.{}.partial",
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
    let request = parse_request()?;
    let parent = request
        .output
        .parent()
        .ok_or_else(|| invalid("output directory has no parent"))?;
    let staging = PrivateDirectory::create_staging(parent)?;
    let candidate = build_candidate(request.route)?;

    write_candidate(&staging, &candidate)?;
    staging.sync()?;
    reopen_and_verify_content(&staging, request.route)?;
    write_hash_manifest(&staging)?;
    staging.sync()?;
    reopen_and_verify_complete(&staging, request.route)?;

    let published = PrivateDirectory::create_final(&request.output)?;
    publish_content_files(&staging, &published)?;
    staging.sync()?;
    published.sync()?;
    reopen_and_verify_content(&published, request.route)?;
    verify_exact_directory(&staging, &["SHA256SUMS"])?;

    // Readiness transition: no final artifact is created or moved after this
    // exact manifest rename.
    move_named(&staging, &published, "SHA256SUMS")?;
    staging.sync()?;
    published.sync()?;
    sync_parent_directory(parent)?;
    reopen_and_verify_complete(&published, request.route)?;

    staging.remove_if_exactly_empty()?;
    sync_parent_directory(parent)?;
    published.validate()?;
    reopen_and_verify_complete(&published, request.route)?;

    println!("{}", request.output.display());
    Ok(())
}

fn parse_request() -> Result<Request, DynError> {
    const USAGE: &str = "usage: emit_linux_search_span_source_candidate \
        OUTPUT_DIRECTORY v8|v9|v10|v12|v13|v15|v16|v17|v24|v25|v26|tag21 qualification|production ROW_SELECTOR";

    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let requested = PathBuf::from(arguments.next().ok_or_else(|| invalid(USAGE))?);
    let backend = match arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("v8") => LinuxAarch64SearchBackendV1::AsimdV8,
        Some("v9") => LinuxAarch64SearchBackendV1::AsimdV9,
        Some("v10") => LinuxAarch64SearchBackendV1::AsimdV10,
        Some("v12") => LinuxAarch64SearchBackendV1::AsimdV12,
        Some("v13") => LinuxAarch64SearchBackendV1::AsimdV13,
        Some("v15") => LinuxAarch64SearchBackendV1::AsimdV15,
        Some("v16") => LinuxAarch64SearchBackendV1::AsimdV16,
        Some("v17") => LinuxAarch64SearchBackendV1::AsimdV17,
        Some("v24") => LinuxAarch64SearchBackendV1::AsimdV24,
        Some("v25") => LinuxAarch64SearchBackendV1::AsimdV25,
        Some("v26") => LinuxAarch64SearchBackendV1::AsimdV26,
        Some("tag21") => LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16,
        _ => return Err(invalid(USAGE).into()),
    };
    let adopter = match arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("qualification") => SearchSpanFinalImageAdopterV1::QualificationPrivate,
        Some("production") => SearchSpanFinalImageAdopterV1::Production,
        _ => return Err(invalid(USAGE).into()),
    };
    let row_selector = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| invalid(USAGE))?
        .parse::<u16>()
        .map_err(|_| invalid("ROW_SELECTOR must be a decimal u16"))?;
    if arguments.next().is_some() {
        return Err(invalid(USAGE).into());
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
    require(
        fs::metadata(&parent)?.is_dir(),
        "output parent is not a directory",
    )?;
    let output = parent.join(name);
    require_path_absent(&output, "final output directory")?;
    Ok(Request {
        output,
        route: CandidateRoute {
            backend,
            adopter,
            row_selector,
        },
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixed transaction constructs and cross-binds every Linux candidate artifact"
)]
fn build_candidate(route: CandidateRoute) -> Result<Candidate, DynError> {
    let mut source = Vec::new();
    source.try_reserve_exact(LITERAL.len())?;
    require(
        source.capacity() == LITERAL.len(),
        "fixed source allocation did not retain its exact requested capacity",
    )?;
    source.extend_from_slice(LITERAL);

    let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::new(
        LinuxAarch64SearchCompilePolicyV1::default(),
        route.backend,
    )?;
    let mut profile = RustProfile::default();
    profile.options.unicode = false;
    let compiled = plan_and_compile_linux_aarch64_exact_search_v1(manifest, source, profile)?;
    require(
        compiled.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
            && compiled.receipt().runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
            && compiled.receipt().backend() == route.backend
            && compiled.receipt().output() == OutputKind::Span
            && compiled.receipt().literal_bytes()
                == u32::try_from(LITERAL.len()).map_err(|_| invalid("literal width overflow"))?,
        "compiler result disagrees with the inert fixed request",
    )?;
    let expectation = build_linux_static_search_span_expectation_v1(&compiled)?;
    require(
        expectation.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent,
        "expectation unexpectedly granted runtime authority",
    )?;
    let glue = match route.adopter {
        SearchSpanFinalImageAdopterV1::Production => publish_linux_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            route.row_selector,
            LinuxSearchSpanFinalImageGlueLimitsV1::default(),
        )?,
        SearchSpanFinalImageAdopterV1::QualificationPrivate => {
            publish_linux_search_span_qualification_final_image_glue_v1(
                &compiled,
                &expectation,
                route.row_selector,
                LinuxSearchSpanFinalImageGlueLimitsV1::default(),
            )?
        }
        SearchSpanFinalImageAdopterV1::FamilyQualificationPrivate => {
            return Err(invalid(
                "the exact-row proposal example cannot propose private family authority",
            )
            .into());
        }
    };
    require(
        glue.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
            && glue.receipt().runtime_authority() == SearchAotRuntimeAuthorityV1::Absent,
        "glue unexpectedly granted runtime authority",
    )?;

    let compiler_receipt = compiled.receipt().canonical_receipt_bytes()?;
    let glue_receipt = *glue.receipt().canonical_bytes();
    let reopened_compiler = inspect_linux_search_compile_receipt_v1(&compiler_receipt)?;
    let object = reopened_compiler
        .validate_object(compiled.object().as_bytes(), ObjectLimitsV1::default())?;
    let expectation_claim = reopened_compiler.validate_span_expectation(expectation.as_bytes())?;
    let reopened_glue_receipt =
        LinuxUnsignedSearchSpanFinalImageReceiptV1::from_canonical_bytes(&glue_receipt)?;
    let glue_inspection = reopened_glue_receipt.validate_reopened_candidate(
        &reopened_compiler,
        compiled.object().as_bytes(),
        expectation.as_bytes(),
        glue.object().as_bytes(),
        ObjectLimitsV1::default(),
        LinuxSearchSpanFinalImageGlueLimitsV1::default(),
    )?;
    let symbols = reopened_glue_receipt.exported_symbols()?;
    let c_header = render_c_header(&symbols)?;
    let rust_bindings = render_rust_bindings(&symbols)?;
    let bundle_review = render_bundle_review(
        route,
        &reopened_compiler,
        &object,
        &expectation_claim,
        &reopened_glue_receipt,
        &glue_inspection,
        &symbols,
    )?;
    let source_row_proposal =
        render_source_row_proposal(route, &reopened_compiler, &object, &expectation_claim)?;

    Ok(Candidate {
        compiled,
        expectation,
        glue,
        compiler_receipt,
        glue_receipt,
        c_header,
        rust_bindings,
        bundle_review,
        source_row_proposal,
    })
}

fn write_candidate(directory: &PrivateDirectory, candidate: &Candidate) -> Result<(), DynError> {
    for (name, bytes) in [
        ("bindings.h", candidate.c_header.as_slice()),
        ("bindings.rs", candidate.rust_bindings.as_slice()),
        ("bundle.tsv", candidate.bundle_review.as_slice()),
        (
            "compiler-receipt.bin",
            candidate.compiler_receipt.as_slice(),
        ),
        ("expectation.bin", candidate.expectation.as_bytes()),
        (
            "final-image-glue-receipt.bin",
            candidate.glue_receipt.as_slice(),
        ),
        ("final-image-glue.o", candidate.glue.object().as_bytes()),
        ("implementation.o", candidate.compiled.object().as_bytes()),
        (
            "source-row-proposal.tsv",
            candidate.source_row_proposal.as_slice(),
        ),
        ("source.regex", LITERAL),
    ] {
        write_named(directory, name, bytes)?;
    }
    Ok(())
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
    let identity = file_identity(&file.metadata()?, "new artifact descriptor")?;
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
    directory.validate()
}

fn write_hash_manifest(directory: &PrivateDirectory) -> Result<(), DynError> {
    write_named(directory, "SHA256SUMS", &render_hash_manifest(directory)?)
}

#[allow(
    clippy::too_many_lines,
    reason = "one independent pass reopens and semantically correlates the complete bundle"
)]
fn reopen_and_verify_semantic_content(
    directory: &PrivateDirectory,
    route: CandidateRoute,
) -> Result<(), DynError> {
    let compiler_receipt_bytes = read_named(directory, "compiler-receipt.bin")?;
    let implementation = read_named(directory, "implementation.o")?;
    let expectation_bytes = read_named(directory, "expectation.bin")?;
    let glue_receipt_bytes = read_named(directory, "final-image-glue-receipt.bin")?;
    let glue_bytes = read_named(directory, "final-image-glue.o")?;
    let source = read_named(directory, "source.regex")?;

    let compiler_receipt = inspect_linux_search_compile_receipt_v1(&compiler_receipt_bytes)?;
    require(
        compiler_receipt.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
            && compiler_receipt.backend() == route.backend
            && compiler_receipt.output() == OutputKind::Span
            && compiler_receipt.literal_bytes()
                == u32::try_from(LITERAL.len()).map_err(|_| invalid("literal width overflow"))?,
        "reopened compiler receipt disagrees with the requested inert route",
    )?;
    let object = compiler_receipt.validate_object(&implementation, ObjectLimitsV1::default())?;
    let expectation = compiler_receipt.validate_span_expectation(&expectation_bytes)?;
    let glue_receipt =
        LinuxUnsignedSearchSpanFinalImageReceiptV1::from_canonical_bytes(&glue_receipt_bytes)?;
    let glue = glue_receipt.validate_reopened_candidate(
        &compiler_receipt,
        &implementation,
        &expectation_bytes,
        &glue_bytes,
        ObjectLimitsV1::default(),
        LinuxSearchSpanFinalImageGlueLimitsV1::default(),
    )?;
    require(
        glue_receipt.runtime_authority() == SearchAotRuntimeAuthorityV1::Absent
            && glue_receipt.adopter() == Some(route.adopter)
            && glue_receipt.row_selector() == route.row_selector
            && glue.adopter() == route.adopter
            && glue.row_selector() == route.row_selector,
        "reopened final-image receipt/glue route disagrees with the request",
    )?;
    let rodata_offset = usize::try_from(object.metadata().rodata_offset())
        .map_err(|_| invalid("rodata offset is not usize"))?;
    let rodata_bytes = usize::try_from(object.metadata().rodata_bytes())
        .map_err(|_| invalid("rodata width is not usize"))?;
    let rodata_end = rodata_offset
        .checked_add(rodata_bytes)
        .ok_or_else(|| invalid("rodata extent overflow"))?;
    require(
        source.as_slice() == LITERAL
            && u64::try_from(source.len()).ok() == Some(compiler_receipt.source_bytes())
            && u64::try_from(source.len()).ok() == Some(compiler_receipt.source_capacity_bytes())
            && compute_linux_search_literal_identity_v1(&source).as_bytes()
                == compiler_receipt.literal_identity()
            && object.payload().get(rodata_offset..rodata_end) == Some(source.as_slice()),
        "reopened source/payload does not contain the exact requested live literal",
    )?;

    let symbols = glue_receipt.exported_symbols()?;
    require(
        read_named(directory, "bindings.h")? == render_c_header(&symbols)?
            && read_named(directory, "bindings.rs")? == render_rust_bindings(&symbols)?
            && read_named(directory, "bundle.tsv")?
                == render_bundle_review(
                    route,
                    &compiler_receipt,
                    &object,
                    &expectation,
                    &glue_receipt,
                    &glue,
                    &symbols,
                )?
            && read_named(directory, "source-row-proposal.tsv")?
                == render_source_row_proposal(route, &compiler_receipt, &object, &expectation)?,
        "reopened generated text is not the canonical semantic projection",
    )
}

fn reopen_and_verify_content(
    directory: &PrivateDirectory,
    route: CandidateRoute,
) -> Result<(), DynError> {
    verify_exact_directory(directory, &HASHED_ARTIFACTS)?;
    reopen_and_verify_semantic_content(directory, route)
}

fn reopen_and_verify_complete(
    directory: &PrivateDirectory,
    route: CandidateRoute,
) -> Result<(), DynError> {
    verify_exact_directory(directory, &COMPLETE_OUTPUTS)?;
    reopen_and_verify_semantic_content(directory, route)?;
    require(
        read_named(directory, "SHA256SUMS")? == render_hash_manifest(directory)?,
        "reopened SHA256 manifest is not canonical",
    )
}

fn render_c_header(symbols: &LinuxSearchSpanFinalImageSymbolsV1) -> Result<Vec<u8>, DynError> {
    let mut output = String::new();
    output.try_reserve_exact(8 << 10)?;
    symbols.write_c_header(&mut output)?;
    bounded_text(output)
}

fn render_rust_bindings(symbols: &LinuxSearchSpanFinalImageSymbolsV1) -> Result<Vec<u8>, DynError> {
    let mut output = String::new();
    output.try_reserve_exact(8 << 10)?;
    symbols.write_rust_bindings(&mut output)?;
    bounded_text(output)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the review record explicitly projects every independently reopened artifact"
)]
fn render_bundle_review(
    route: CandidateRoute,
    compiler: &LinuxSearchCompileReceiptInspectionV1,
    object: &ObjectInspectionV1<'_>,
    expectation: &ClaimedStaticSearchSpanExpectationV1,
    glue_receipt: &LinuxUnsignedSearchSpanFinalImageReceiptV1,
    glue: &LinuxSearchSpanFinalImageGlueInspectionV1<'_>,
    symbols: &LinuxSearchSpanFinalImageSymbolsV1,
) -> Result<Vec<u8>, DynError> {
    let metadata = compiler.metadata();
    let mut output = String::new();
    output.try_reserve_exact(8 << 10)?;
    for (key, value) in [
        (
            "schema",
            "fre-aot-linux-search-span-source-candidate-v1".to_owned(),
        ),
        ("target", "aarch64-linux-elf".to_owned()),
        ("backend", backend_name(route.backend).to_owned()),
        (
            "backend_version",
            route.backend.backend_version().0.to_string(),
        ),
        (
            "required_features",
            route.backend.required_features().bits().to_string(),
        ),
        (
            "fixed_active_vector_bytes",
            route.backend.fixed_active_vector_bytes().to_string(),
        ),
        ("adopter", adopter_name(route.adopter).to_owned()),
        ("selector", route.row_selector.to_string()),
        ("object_set", "one-implementation-one-glue".to_owned()),
        ("promotion_state", "proposal-only".to_owned()),
        ("runtime_authority", "absent".to_owned()),
        ("literal_hex", hex(LITERAL)),
        ("source_sha256", hex(&sha256(LITERAL))),
        ("literal_bytes", compiler.literal_bytes().to_string()),
        (
            "compiler_receipt_schema_version",
            AOT_LINUX_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1.to_string(),
        ),
        (
            "compiler_version",
            AOT_LINUX_SEARCH_COMPILER_VERSION_V1.to_string(),
        ),
        (
            "manifest_schema_version",
            AOT_LINUX_SEARCH_MANIFEST_SCHEMA_VERSION_V1.to_string(),
        ),
        ("manifest_identity", hex(compiler.manifest_identity())),
        (
            "semantic_binding_identity",
            hex(compiler.semantic_binding_identity()),
        ),
        ("literal_identity", hex(compiler.literal_identity())),
        ("kir_identity", hex(compiler.kir_identity())),
        ("artifact_identity", hex(compiler.artifact_identity())),
        ("binding_identity", hex(compiler.binding_identity())),
        ("compile_identity", hex(compiler.compile_identity())),
        ("object_identity", hex(compiler.object_identity())),
        (
            "compiler_receipt_identity",
            hex(compiler.receipt_identity().as_bytes()),
        ),
        (
            "expectation_identity",
            hex(expectation.expectation_identity()),
        ),
        (
            "glue_object_identity",
            hex(glue.object_identity().as_bytes()),
        ),
        ("glue_code_identity", hex(glue.code_identity().as_bytes())),
        (
            "final_image_receipt_identity",
            hex(glue_receipt.receipt_identity().as_bytes()),
        ),
        (
            "implementation_sha256",
            hex(object.claimed_object_identity().as_bytes()),
        ),
        ("payload_identity", hex(&sha256(object.payload()))),
        ("metadata_sha256", hex(&sha256(object.metadata_bytes()))),
        (
            "implementation_object_bytes",
            object.object_bytes().to_string(),
        ),
        ("payload_bytes", metadata.payload_bytes().to_string()),
        ("code_bytes", metadata.code_bytes().to_string()),
        ("rodata_offset", metadata.rodata_offset().to_string()),
        ("rodata_bytes", metadata.rodata_bytes().to_string()),
        ("source_bytes", compiler.source_bytes().to_string()),
        (
            "source_capacity_bytes",
            compiler.source_capacity_bytes().to_string(),
        ),
        ("symbol_glue", symbols.glue().as_str().to_owned()),
        (
            "symbol_expectation",
            symbols.expectation().as_str().to_owned(),
        ),
        ("symbol_entry", symbols.entry().as_str().to_owned()),
        ("symbol_payload", symbols.payload().as_str().to_owned()),
        ("symbol_metadata", symbols.metadata().as_str().to_owned()),
        (
            "symbol_adopter",
            symbols.adopter_symbol().as_str().to_owned(),
        ),
        (
            "sve_vl_contract",
            if route.backend == LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16 {
                "qualification-thread-exact-vl16;measured-entry-no-prctl".to_owned()
            } else {
                "not-applicable".to_owned()
            },
        ),
    ] {
        writeln!(output, "{key}\t{value}")?;
    }
    bounded_text(output)
}

fn render_source_row_proposal(
    route: CandidateRoute,
    compiler: &LinuxSearchCompileReceiptInspectionV1,
    object: &ObjectInspectionV1<'_>,
    expectation: &ClaimedStaticSearchSpanExpectationV1,
) -> Result<Vec<u8>, DynError> {
    let fields = [
        ("live_literal_bytes", compiler.literal_bytes().to_string()),
        ("manifest_identity", hex(compiler.manifest_identity())),
        (
            "semantic_binding_identity",
            hex(compiler.semantic_binding_identity()),
        ),
        ("literal_identity", hex(compiler.literal_identity())),
        ("kir_identity", hex(compiler.kir_identity())),
        ("artifact_identity", hex(compiler.artifact_identity())),
        ("binding_identity", hex(compiler.binding_identity())),
        ("compile_identity", hex(compiler.compile_identity())),
        ("object_identity", hex(compiler.object_identity())),
        (
            "receipt_identity",
            hex(compiler.receipt_identity().as_bytes()),
        ),
        (
            "expectation_identity",
            hex(expectation.expectation_identity()),
        ),
        ("payload_identity", hex(&sha256(object.payload()))),
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
            "fre-aot-linux-search-span-source-row-proposal-v1".to_owned(),
        ),
        ("promotion_state", "proposal-only".to_owned()),
        (
            "table_target",
            match route.adopter {
                SearchSpanFinalImageAdopterV1::Production => "production-input",
                SearchSpanFinalImageAdopterV1::QualificationPrivate => {
                    "private-qualification-input"
                }
                SearchSpanFinalImageAdopterV1::FamilyQualificationPrivate => {
                    "private-family-qualification-corroboration-only"
                }
            }
            .to_owned(),
        ),
        ("runtime_authority", "absent".to_owned()),
        ("selector", route.row_selector.to_string()),
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
        writeln!(
            manifest,
            "{}  {name}",
            hex(&sha256(&read_named(directory, name)?))
        )?;
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
        let name = entry?
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
    let identity = directory_identity(&handle.metadata()?, "new private directory descriptor")?;
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
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
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
    require(
        file_identity(metadata, label)? == expected,
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
    require(
        read_named(destination, name)? == before,
        "moved artifact did not reopen as its exact staged bytes",
    )
}

fn maximum_artifact_bytes(name: &str) -> Result<u64, DynError> {
    match name {
        "implementation.o" => Ok(MAX_IMPLEMENTATION_OBJECT_BYTES),
        "final-image-glue.o" => Ok(MAX_GLUE_OBJECT_BYTES),
        "expectation.bin" => Ok(u64::try_from(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
            .map_err(|_| invalid("expectation bound overflow"))?),
        "compiler-receipt.bin" => Ok(u64::try_from(
            LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1,
        )
        .map_err(|_| invalid("compiler receipt bound overflow"))?),
        "final-image-glue-receipt.bin" => Ok(u64::try_from(
            LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1,
        )
        .map_err(|_| invalid("glue receipt bound overflow"))?),
        "bindings.h" | "bindings.rs" | "bundle.tsv" | "source-row-proposal.tsv" => {
            Ok(MAX_TEXT_ARTIFACT_BYTES)
        }
        "source.regex" => {
            Ok(u64::try_from(LITERAL.len()).map_err(|_| invalid("source bound overflow"))?)
        }
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
    require(
        directory_identity(&handle.metadata()?, "parent descriptor before sync")? == identity,
        "parent descriptor and named path identity disagree before sync",
    )?;
    handle.sync_all()?;
    require(
        directory_identity(&handle.metadata()?, "parent descriptor after sync")? == identity
            && directory_identity(&fs::symlink_metadata(path)?, "parent directory after sync")?
                == identity,
        "parent directory identity changed during sync",
    )
}

const fn backend_name(backend: LinuxAarch64SearchBackendV1) -> &'static str {
    match backend {
        LinuxAarch64SearchBackendV1::AsimdV8 => "v8-asimd",
        LinuxAarch64SearchBackendV1::AsimdV9 => "v9-asimd",
        LinuxAarch64SearchBackendV1::AsimdV10 => "v10-asimd",
        LinuxAarch64SearchBackendV1::AsimdV12 => "v12-asimd",
        LinuxAarch64SearchBackendV1::AsimdV13 => "v13-asimd",
        LinuxAarch64SearchBackendV1::AsimdV15 => "v15-asimd-phase-unique",
        LinuxAarch64SearchBackendV1::AsimdV16 => "v16-asimd-staged-learned",
        LinuxAarch64SearchBackendV1::AsimdV17 => "v17-asimd-learned-continuation",
        LinuxAarch64SearchBackendV1::AsimdV24 => "v24-asimd-sixth-static",
        LinuxAarch64SearchBackendV1::AsimdV25 => "v25-asimd-sixth-empty-promote",
        LinuxAarch64SearchBackendV1::AsimdV26 => "v26-asimd-policy-authenticated",
        LinuxAarch64SearchBackendV1::AsimdV27 => "v27-asimd-topology-total",
        LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16 => "tag21-sve2-fixed16",
    }
}

const fn adopter_name(adopter: SearchSpanFinalImageAdopterV1) -> &'static str {
    match adopter {
        SearchSpanFinalImageAdopterV1::Production => "production",
        SearchSpanFinalImageAdopterV1::QualificationPrivate => "qualification-private",
        SearchSpanFinalImageAdopterV1::FamilyQualificationPrivate => "family-qualification-private",
    }
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
    fn artifact_sets_are_sorted_closed_and_one_glue_only() {
        assert!(HASHED_ARTIFACTS.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(COMPLETE_OUTPUTS.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(COMPLETE_OUTPUTS[0], "SHA256SUMS");
        assert!(!HASHED_ARTIFACTS.contains(&"SHA256SUMS"));
        assert_eq!(COMPLETE_OUTPUTS.len(), HASHED_ARTIFACTS.len() + 1);
        assert_eq!(
            HASHED_ARTIFACTS
                .iter()
                .filter(|name| **name == "final-image-glue.o")
                .count(),
            1
        );
        for name in COMPLETE_OUTPUTS {
            assert!(maximum_artifact_bytes(name).is_ok());
        }
    }

    #[test]
    fn proposal_and_private_publication_contracts_are_pinned() {
        assert_eq!(SOURCE_ROW_QUALIFICATION_FIELDS, 12);
        assert_eq!(PRIVATE_DIRECTORY_PERMISSIONS, 0o700);
        assert_eq!(PRIVATE_FILE_PERMISSIONS, 0o600);
        assert_eq!(STAGING_NONCE_BYTES, 16);
        assert_eq!(STAGING_CREATE_ATTEMPTS, 16);
    }

    #[test]
    fn literal_and_wire_bounds_are_pinned() {
        assert_eq!(LITERAL, b"0123456789abcdef");
        assert_eq!(LITERAL.len(), 16);
        assert_eq!(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1, 584);
        assert_eq!(LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1, 592);
        assert_eq!(LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1, 256);
    }

    #[test]
    fn canonical_hex_is_lowercase_and_fixed_width() {
        assert_eq!(hex(&[0, 1, 0xab, 0xff]), "0001abff");
    }
}
