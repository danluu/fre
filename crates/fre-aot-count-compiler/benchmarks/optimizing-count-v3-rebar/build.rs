#[path = "build_support/expectation_object.rs"]
mod expectation_object;
#[path = "build_support/inventory.rs"]
mod inventory;

use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fre::{
    AggregateBuildAccounting, AggregateBuildLimits, AggregateBuilder,
    AggregateExactLiteralSemantics, AggregatePlanIdentity, AggregatePlanKind,
    AggregatePlanSelection, AggregateStrategy, LiteralAggregateOperation, RustProfile,
};
use fre_aot_aarch64::{CountEmitLimitsV2, emit_count_v2};
use fre_aot_count_compiler::{
    CountCompileLimitsV3, CountCompileRequestV3, CountCompileTargetV3, CountObjectFormatV3,
    CountObjectLimitsV2, CountObjectLimitsV3, CountSemanticCandidateV3, compile_count_v3,
    inspect_count_implementation_object_elf_v2, inspect_count_implementation_object_v2,
    inspect_count_implementation_object_v3, publish_count_implementation_object_elf_v2,
    publish_count_implementation_object_macho_v2,
};
use fre_aot_count_contract::v3::inspect_static_count_expectation_v3;
use fre_aot_optimizer::{CountV3RequiredIsa, CountV3TuningClass};
use fre_kernel_ir::{Count, ValidateLimits, build_exact_aggregate};
use inventory::{CompilerArtifactInput, Inventory, digest_fields, hex, parse_hex_32};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BINARY: &str = "fre-optimizing-count-v3-rebar";
const REGISTRY_SCHEMA: &str = "fre.optimizing-count-v3.compiled-artifact-registry.v1";
const PORTABLE_RECEIPT_SCHEMA: &str = "fre.optimizing-count-v3.portable-compiled-recipe-receipt.v1";
const PORTABLE_PAYLOAD_SCHEMA: &str = "fre.optimizing-count-v3.portable-compiled-recipe-payload.v1";
const PORTABLE_METADATA_SCHEMA: &str =
    "fre.optimizing-count-v3.portable-compiled-recipe-metadata.v1";
const PORTABLE_INPUT_POLICY: &str = "current-portable-pattern-control-v1";
const V2_INPUT_POLICY: &str = "current-count-v2-pattern-control-v1";
const EXPECTATION_SYMBOL_PREFIX: &str = "fre_aot_count_expectation_v3_";
const MAX_SOURCE_FILE_BYTES: usize = 4 * 1_048_576;

const MANIFEST_CLAIM_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-MANIFEST-CLAIM\0\x01";
const POLICY_CLAIM_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-POLICY-CLAIM\0\x01";
const OBJECT_BINDING_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-OBJECT-BINDING\0\x01";
const RECEIPT_CLAIM_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-RECEIPT-CLAIM\0\x01";
const RESOURCE_CLAIM_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-RESOURCE-CLAIM\0\x01";
const V2_OBJECT_BINDING_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-V2-CONTROL-BINDING\0\x01";
const PORTABLE_RECEIPT_IDENTITY_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-PORTABLE-RECEIPT\0\x01";
const SOURCE_SET_DOMAIN: &[u8] = b"FRE-OPTIMIZING-COUNT-V3-RUNNER-SOURCE-SET\0\x01";

fn main() {
    if let Err(error) = run() {
        panic!("optimizing Count-v3 Rebar builder refused: {error}");
    }
}

fn run() -> Result<(), String> {
    for variable in [
        "FRE_COUNT_V3_INVENTORY",
        "FRE_COUNT_V3_INVENTORY_SHA256",
        "FRE_COUNT_V3_ARTIFACT_ROOT",
        "FRE_COUNT_V3_TARGET_ID",
        "FRE_COUNT_V3_TARGET_CONTRACT_SHA256",
        "FRE_COUNT_V3_TUNING_CLASS",
        "FRE_COUNT_V3_REQUIRED_ISA",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    for source in [
        "Cargo.toml",
        "README.md",
        "build.rs",
        "build_support/inventory.rs",
        "build_support/expectation_object.rs",
        "src/main.rs",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }

    let manifest_dir = required_path("CARGO_MANIFEST_DIR")?;
    let out_dir = required_path("OUT_DIR")?;
    let target = TargetConfig::from_environment()?;
    println!("cargo:rustc-check-cfg=cfg(fre_count_v3_neon)");
    println!("cargo:rustc-check-cfg=cfg(fre_count_v3_sve)");
    println!("cargo:rustc-check-cfg=cfg(fre_count_v3_sve2)");
    match target.required_isa {
        CountV3RequiredIsa::Aarch64Neon128 => {
            println!("cargo:rustc-cfg=fre_count_v3_neon");
        }
        CountV3RequiredIsa::Aarch64SveVl16 => {
            println!("cargo:rustc-cfg=fre_count_v3_sve");
        }
        CountV3RequiredIsa::Aarch64Sve2Vl16 => {
            println!("cargo:rustc-cfg=fre_count_v3_sve2");
        }
    }
    let inventory_path = required_path("FRE_COUNT_V3_INVENTORY")?;
    println!("cargo:rerun-if-changed={}", inventory_path.display());
    let inventory_bytes = read_regular_file(&inventory_path, 64 * 1_048_576, false)?;
    let inventory_sha256 = sha256_hex(&inventory_bytes);
    let expected_inventory_sha256 = required_hex_environment("FRE_COUNT_V3_INVENTORY_SHA256")?;
    if inventory_sha256 != expected_inventory_sha256 {
        return Err(format!(
            "inventory SHA-256 {inventory_sha256} differs from frozen {expected_inventory_sha256}"
        ));
    }
    let inventory = inventory::parse_and_validate(&inventory_bytes)?;
    let artifact_root = validate_artifact_root(&required_path("FRE_COUNT_V3_ARTIFACT_ROOT")?)?;
    validate_runner_source_boundary(&manifest_dir)?;
    let source_receipt = source_receipt(&manifest_dir)?;

    let mut compiled = Vec::new();
    compiled
        .try_reserve_exact(inventory.artifacts.len())
        .map_err(|error| format!("reserve compiled artifact registry: {error}"))?;
    for row in &inventory.artifacts {
        let input = CompilerArtifactInput::from_authenticated(row)?;
        compiled.push(compile_artifact(&input, &target, &artifact_root)?);
    }

    let registry = build_registry(
        &inventory,
        &inventory_sha256,
        &target,
        &artifact_root,
        &source_receipt,
        &compiled,
    );
    let registry_bytes = serde_json::to_vec(&registry)
        .map_err(|error| format!("serialize compiled artifact registry: {error}"))?;
    let _registry_file = write_content_addressed(&artifact_root, &registry_bytes)?;
    let registry_sha256 = sha256_hex(&registry_bytes);
    let generated = generate_bindings(
        &inventory,
        &compiled,
        &registry_bytes,
        &registry_sha256,
        &target,
    )?;
    validate_generated_v3_boundary(&generated, compiled.len())?;
    fs::write(out_dir.join("generated.rs"), generated)
        .map_err(|error| format!("write generated bindings: {error}"))?;
    fs::write(out_dir.join("compiled-artifacts.json"), &registry_bytes)
        .map_err(|error| format!("write OUT_DIR registry copy: {error}"))?;

    for artifact in &compiled {
        println!(
            "cargo:rustc-link-arg-bin={BINARY}={}",
            artifact.v2.artifact_file_path.display()
        );
        println!(
            "cargo:rustc-link-arg-bin={BINARY}={}",
            artifact.v3.artifact_file_path.display()
        );
        println!(
            "cargo:rustc-link-arg-bin={BINARY}={}",
            artifact.v3.expectation_file_path.display()
        );
    }
    if target.object_format == CountObjectFormatV3::MachOArm64 {
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-segprot,__FRE_CONST,r,r");
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-reproducible");
    } else {
        // The deterministic hand-written ELF inputs intentionally contain
        // only their contract sections. Pin the final executable's stack
        // policy explicitly instead of inheriting a linker's legacy fallback
        // for objects without `.note.GNU-stack`.
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-z,noexecstack");
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct TargetConfig {
    target_id: String,
    target_contract_sha256: [u8; 32],
    target_contract_hex: String,
    target_triple: String,
    object_format: CountObjectFormatV3,
    object_format_name: &'static str,
    tuning_class: CountV3TuningClass,
    tuning_class_name: &'static str,
    required_isa: CountV3RequiredIsa,
    required_isa_name: &'static str,
    canonical_bytes: Vec<u8>,
}

impl TargetConfig {
    fn from_environment() -> Result<Self, String> {
        let target_id = required_environment("FRE_COUNT_V3_TARGET_ID")?;
        require_safe_id(&target_id, "target ID")?;
        let target_contract_hex = required_hex_environment("FRE_COUNT_V3_TARGET_CONTRACT_SHA256")?;
        let target_contract_sha256 = parse_hex_32(&target_contract_hex, "target-contract SHA-256")?;
        let target_triple = required_environment("TARGET")?;
        let (object_format, object_format_name) = match target_triple.as_str() {
            "aarch64-apple-darwin" => (CountObjectFormatV3::MachOArm64, "macho-arm64"),
            "aarch64-unknown-linux-gnu" => (CountObjectFormatV3::Elf64Aarch64, "elf64-aarch64"),
            _ => {
                return Err(format!(
                    "target {target_triple} is not a reviewed Count-v3 link target"
                ));
            }
        };
        let (tuning_class, tuning_class_name) =
            match required_environment("FRE_COUNT_V3_TUNING_CLASS")?.as_str() {
                "generic-aarch64" => (CountV3TuningClass::GenericAarch64, "generic-aarch64"),
                "apple-m-series" => (CountV3TuningClass::AppleMSeries, "apple-m-series"),
                "neoverse-v2-v3" => (CountV3TuningClass::NeoverseV2V3, "neoverse-v2-v3"),
                value => return Err(format!("unknown Count-v3 tuning class {value}")),
            };
        let (required_isa, required_isa_name) =
            match required_environment("FRE_COUNT_V3_REQUIRED_ISA")?.as_str() {
                "neon" => (CountV3RequiredIsa::Aarch64Neon128, "neon"),
                "sve-vl16" => (CountV3RequiredIsa::Aarch64SveVl16, "sve-vl16"),
                "sve2-vl16" => (CountV3RequiredIsa::Aarch64Sve2Vl16, "sve2-vl16"),
                value => return Err(format!("unknown Count-v3 required ISA {value}")),
            };
        if target_triple == "aarch64-apple-darwin"
            && required_isa != CountV3RequiredIsa::Aarch64Neon128
        {
            return Err("macOS Count-v3 qualification target must select NEON".to_string());
        }
        let canonical_bytes = serde_json::to_vec(&json!({
            "object_format": object_format_name,
            "required_isa": required_isa_name,
            "schema": "fre.optimizing-count-v3.compiler-target.v1",
            "target_contract_sha256": target_contract_hex,
            "target_triple": target_triple,
            "tuning_class": tuning_class_name,
        }))
        .map_err(|error| format!("serialize compiler target: {error}"))?;
        Ok(Self {
            target_id,
            target_contract_sha256,
            target_contract_hex,
            target_triple,
            object_format,
            object_format_name,
            tuning_class,
            tuning_class_name,
            required_isa,
            required_isa_name,
            canonical_bytes,
        })
    }
}

#[derive(Clone, Debug)]
struct CompiledArtifact {
    pattern_input_id: String,
    pattern_sha256: String,
    transformed_pattern: String,
    unicode: bool,
    literal_hex: String,
    semantic_binding_identity: String,
    planning_receipt_identity: String,
    optimizer_input_sha256: String,
    portable: EngineArtifact,
    v2: EngineArtifact,
    v3: V3Artifact,
    claim_derivations: Value,
}

#[derive(Clone, Debug)]
struct EngineArtifact {
    artifact_id: String,
    artifact_file_path: PathBuf,
    artifact_file_sha256: String,
    object_sha256: Option<String>,
    payload_sha256: String,
    metadata_sha256: String,
    compile_identity: Option<String>,
    object_identity: Option<String>,
    object_bytes: Option<usize>,
    payload_bytes: Option<usize>,
    code_bytes: Option<usize>,
    receipt_identity: Option<String>,
}

#[derive(Clone, Debug)]
struct V3Artifact {
    engine: EngineArtifact,
    expectation_file_path: PathBuf,
    expectation_file_sha256: String,
    expectation_bytes_sha256: String,
    expectation_identity: String,
    recipe_identity: String,
    optimizer_receipt_identity: String,
    expectation_symbol: String,
}

#[derive(Clone, Debug)]
struct PublishedV2 {
    bytes: Vec<u8>,
    metadata_bytes: Vec<u8>,
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    payload_sha256: [u8; 32],
    payload_bytes: usize,
    code_bytes: usize,
}

fn compile_artifact(
    input: &CompilerArtifactInput,
    target: &TargetConfig,
    artifact_root: &Path,
) -> Result<CompiledArtifact, String> {
    let fixed_owner = AggregateBuilder::new(input.transformed_pattern.clone())
        .profile(RustProfile::rebar_1_12_4())
        .unicode(input.unicode)
        .case_insensitive(false)
        .limits(AggregateBuildLimits::aot_count_exact_literal_v1())
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(|error| {
            format!(
                "fixed facade reconstruction for {}: {error}",
                input.pattern_input_id
            )
        })?;
    if fixed_owner.build_report().plan != AggregatePlanKind::ExactLiteral {
        return Err(format!(
            "fixed facade for {} did not select ExactLiteral",
            input.pattern_input_id
        ));
    }
    let candidate = fixed_owner
        .exact_literal_aot_planned_candidate()
        .ok_or_else(|| {
            format!(
                "fixed facade for {} lacks planned AOT candidate",
                input.pattern_input_id
            )
        })?;
    if candidate.literal() != input.authenticated_literal {
        return Err(format!(
            "fixed facade literal for {} differs from authenticated inventory",
            input.pattern_input_id
        ));
    }
    let literal_sha256: [u8; 32] = Sha256::digest(candidate.literal()).into();
    if literal_sha256 != input.literal_sha256
        || candidate.semantic_binding_identity().as_bytes() != &input.semantic_binding_identity
        || candidate.planning_receipt_identity().as_bytes() != &input.planning_receipt_identity
    {
        return Err(format!(
            "fixed facade identities for {} differ from authenticated inventory",
            input.pattern_input_id
        ));
    }

    let portable = compile_portable_receipt(input, target, artifact_root)?;
    let v2_binding = derive_identity(
        V2_OBJECT_BINDING_DOMAIN,
        input,
        target,
        &[V2_INPUT_POLICY.as_bytes()],
    );
    let v2_published = compile_v2_once(candidate.literal(), v2_binding, target.object_format)?;
    let v2_object_sha256 = sha256_hex(&v2_published.bytes);
    let v2_path = write_content_addressed(artifact_root, &v2_published.bytes)?;
    let v2_payload_sha256 = hex(&v2_published.payload_sha256);
    let v2_metadata_sha256 = sha256_hex(&v2_published.metadata_bytes);
    let v2_artifact_id = artifact_registry_identity(
        &target.target_contract_hex,
        "count-v2-current",
        &hex(&input.pattern_sha256),
        &v2_object_sha256,
        &v2_payload_sha256,
        &v2_metadata_sha256,
    )?;
    let v2 = EngineArtifact {
        artifact_id: v2_artifact_id,
        artifact_file_path: v2_path,
        artifact_file_sha256: v2_object_sha256.clone(),
        object_sha256: Some(v2_object_sha256),
        payload_sha256: v2_payload_sha256,
        metadata_sha256: v2_metadata_sha256,
        compile_identity: Some(hex(&v2_published.compile_identity)),
        object_identity: Some(hex(&v2_published.object_identity)),
        object_bytes: Some(v2_published.bytes.len()),
        payload_bytes: Some(v2_published.payload_bytes),
        code_bytes: Some(v2_published.code_bytes),
        receipt_identity: None,
    };

    let manifest_identity = derive_identity(
        MANIFEST_CLAIM_DOMAIN,
        input,
        target,
        &[
            &input.source_pattern_sha256,
            &input.pattern_sha256,
            &input.pattern_semantics_identity,
        ],
    );
    let policy_limits_identity = derive_identity(
        POLICY_CLAIM_DOMAIN,
        input,
        target,
        &[
            inventory::INPUT_POLICY.as_bytes(),
            &input.semantic_options_sha256,
            input.planning_receipt_identity.as_slice(),
        ],
    );
    let object_binding_identity = derive_identity(
        OBJECT_BINDING_DOMAIN,
        input,
        target,
        &[
            &target.target_contract_sha256,
            target.object_format_name.as_bytes(),
            target.tuning_class_name.as_bytes(),
            target.required_isa_name.as_bytes(),
        ],
    );
    let claimed_receipt_identity = derive_identity(
        RECEIPT_CLAIM_DOMAIN,
        input,
        target,
        &[
            &input.pattern_semantics_identity,
            &input.semantic_binding_identity,
            &input.planning_receipt_identity,
        ],
    );
    let claimed_resource_receipt_identity = derive_identity(
        RESOURCE_CLAIM_DOMAIN,
        input,
        target,
        &[
            &input.semantic_options_sha256,
            &target.target_contract_sha256,
            target.required_isa_name.as_bytes(),
        ],
    );
    let semantic_candidate = CountSemanticCandidateV3 {
        manifest_identity,
        policy_limits_identity,
        semantic_binding_identity: input.semantic_binding_identity,
        planning_receipt_identity: input.planning_receipt_identity,
        object_binding_identity,
        claimed_receipt_identity,
        claimed_resource_receipt_identity,
    };
    let compiled_v3 = compile_count_v3(
        CountCompileRequestV3 {
            literal: candidate.literal(),
            semantic_candidate,
            target: CountCompileTargetV3 {
                object_format: target.object_format,
                tuning_class: target.tuning_class,
                required_isa: target.required_isa,
            },
        },
        CountCompileLimitsV3::default(),
    )
    .map_err(|error| {
        format!(
            "one-pass Count-v3 compilation for {}: {error}",
            input.pattern_input_id
        )
    })?;
    let object = compiled_v3.implementation_object();
    let inspection =
        inspect_count_implementation_object_v3(object.as_bytes(), CountObjectLimitsV3::default())
            .map_err(|error| format!("inspect Count-v3 object: {error}"))?;
    if inspection.compile_identity() != object.compile_identity()
        || inspection.object_identity() != object.object_identity()
        || inspection.metadata_bytes() != object.metadata_bytes()
    {
        return Err(format!(
            "Count-v3 object inspection differs for {}",
            input.pattern_input_id
        ));
    }
    let expectation = compiled_v3.expectation();
    let expectation_claim = inspect_static_count_expectation_v3(expectation)
        .map_err(|error| format!("inspect Count-v3 expectation: {error}"))?;
    if expectation_claim.semantic_binding_identity() != &input.semantic_binding_identity
        || expectation_claim.planning_receipt_identity() != &input.planning_receipt_identity
        || expectation_claim.compile_identity() != object.compile_identity()
        || expectation_claim.object_identity() != object.object_identity()
    {
        return Err(format!(
            "Count-v3 expectation binding differs for {}",
            input.pattern_input_id
        ));
    }
    let compile_identity = hex(object.compile_identity());
    let expectation_symbol = format!("{EXPECTATION_SYMBOL_PREFIX}{compile_identity}");
    let expectation_object = match target.object_format {
        CountObjectFormatV3::MachOArm64 => {
            expectation_object::macho(expectation, &expectation_symbol)?
        }
        CountObjectFormatV3::Elf64Aarch64 => {
            expectation_object::elf(expectation, &expectation_symbol)?
        }
    };
    let expectation_file_sha256 = sha256_hex(&expectation_object);
    let expectation_file_path = write_content_addressed(artifact_root, &expectation_object)?;
    let v3_object_sha256 = sha256_hex(object.as_bytes());
    let v3_path = write_content_addressed(artifact_root, object.as_bytes())?;
    let v3_payload_sha256 = sha256_hex(inspection.payload());
    let v3_metadata_sha256 = sha256_hex(object.metadata_bytes());
    let v3_artifact_id = artifact_registry_identity(
        &target.target_contract_hex,
        "count-v3-aot",
        &hex(&input.pattern_sha256),
        &v3_object_sha256,
        &v3_payload_sha256,
        &v3_metadata_sha256,
    )?;
    let v3 = V3Artifact {
        engine: EngineArtifact {
            artifact_id: v3_artifact_id,
            artifact_file_path: v3_path,
            artifact_file_sha256: v3_object_sha256.clone(),
            object_sha256: Some(v3_object_sha256),
            payload_sha256: v3_payload_sha256,
            metadata_sha256: v3_metadata_sha256,
            compile_identity: Some(compile_identity),
            object_identity: Some(hex(object.object_identity())),
            object_bytes: Some(object.as_bytes().len()),
            payload_bytes: Some(object.payload_bytes()),
            code_bytes: Some(inspection.code().len()),
            receipt_identity: None,
        },
        expectation_file_path,
        expectation_file_sha256,
        expectation_bytes_sha256: sha256_hex(expectation),
        expectation_identity: hex(expectation_claim.expectation_identity()),
        recipe_identity: compiled_v3.recipe().identity().to_string(),
        optimizer_receipt_identity: compiled_v3.optimizer_receipt().identity().to_string(),
        expectation_symbol,
    };
    let optimizer_input_sha256 = optimizer_input_sha256(input, target)?;
    let claim_derivations = json!({
        "claimed_receipt_identity": {
            "domain": "FRE-OPTIMIZING-COUNT-V3-RECEIPT-CLAIM/v1",
            "identity": hex(&claimed_receipt_identity),
        },
        "claimed_resource_receipt_identity": {
            "domain": "FRE-OPTIMIZING-COUNT-V3-RESOURCE-CLAIM/v1",
            "identity": hex(&claimed_resource_receipt_identity),
        },
        "manifest_identity": {
            "domain": "FRE-OPTIMIZING-COUNT-V3-MANIFEST-CLAIM/v1",
            "identity": hex(&manifest_identity),
        },
        "object_binding_identity": {
            "domain": "FRE-OPTIMIZING-COUNT-V3-OBJECT-BINDING/v1",
            "identity": hex(&object_binding_identity),
        },
        "policy_limits_identity": {
            "domain": "FRE-OPTIMIZING-COUNT-V3-POLICY-CLAIM/v1",
            "identity": hex(&policy_limits_identity),
        },
        "target_input_sha256": sha256_hex(&target.canonical_bytes),
        "artifact_input_sha256": sha256_hex(&input.canonical_bytes),
    });

    Ok(CompiledArtifact {
        pattern_input_id: input.pattern_input_id.clone(),
        pattern_sha256: hex(&input.pattern_sha256),
        transformed_pattern: input.transformed_pattern.clone(),
        unicode: input.unicode,
        literal_hex: hex(candidate.literal()),
        semantic_binding_identity: hex(&input.semantic_binding_identity),
        planning_receipt_identity: hex(&input.planning_receipt_identity),
        optimizer_input_sha256,
        portable,
        v2,
        v3,
        claim_derivations,
    })
}

fn compile_portable_receipt(
    input: &CompilerArtifactInput,
    target: &TargetConfig,
    artifact_root: &Path,
) -> Result<EngineArtifact, String> {
    let portable = AggregateBuilder::new(input.transformed_pattern.clone())
        .profile(RustProfile::rebar_1_12_4())
        .unicode(input.unicode)
        .case_insensitive(false)
        .plan_selection(AggregatePlanSelection::Auto)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(|error| {
            format!(
                "portable Auto construction for {}: {error}",
                input.pattern_input_id
            )
        })?;
    let report = portable.build_report();
    if report.plan != AggregatePlanKind::ExactLiteral
        || report.selection != AggregatePlanSelection::Auto
        || report.requested_strategy != AggregateStrategy::ReverseSequentialRows
        || report.continuation_strategy.is_some()
    {
        return Err(format!(
            "portable control for {} did not close the Auto ExactLiteral route",
            input.pattern_input_id
        ));
    }
    let AggregatePlanIdentity::ExactLiteral(identity) = report.plan_identity else {
        return Err("portable control lacks exact-literal plan identity".to_string());
    };
    let AggregateBuildAccounting::ExactLiteral(build) = report.build else {
        return Err("portable control lacks exact-literal build accounting".to_string());
    };
    if build.needle_bytes != input.authenticated_literal.len()
        || identity.kernel.operation != LiteralAggregateOperation::Count
    {
        return Err(format!(
            "portable control for {} has a different literal/operation",
            input.pattern_input_id
        ));
    }
    let semantics = match identity.semantics {
        AggregateExactLiteralSemantics::UnicodeOffByteBoundaries => "unicode-off-byte-boundaries",
        AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal => {
            "unicode-on-nonempty-utf8-literal"
        }
    };
    let payload = json!({
        "build_accounting": {
            "needle_bytes": build.needle_bytes,
            "peak_bytes": build.peak_bytes,
            "persistent_bytes": build.persistent_bytes,
            "scratch_bytes": build.scratch_bytes,
            "temporary_capacity_bytes": build.temporary_capacity_bytes,
            "work_upper_bound": build.work_upper_bound,
        },
        "plan": {
            "accounting_version": identity.kernel.accounting_version,
            "algorithm_version": identity.kernel.algorithm_version,
            "non_overlapping": identity.kernel.non_overlapping,
            "operation_id": identity.kernel.operation_id,
            "plan_id": identity.kernel.plan_id,
            "plan_kind": "exact-literal",
            "semantics": semantics,
        },
        "schema": PORTABLE_PAYLOAD_SCHEMA,
    });
    let metadata = json!({
        "build_policy": {
            "case_insensitive": false,
            "plan_selection": "auto",
            "profile": "rust-regex-1.12.4-rebar",
            "strategy": "reverse-sequential-rows",
            "unicode": input.unicode,
        },
        "input_policy": PORTABLE_INPUT_POLICY,
        "pattern_input_id": input.pattern_input_id,
        "pattern_sha256": hex(&input.pattern_sha256),
        "schema": PORTABLE_METADATA_SCHEMA,
        "semantic_options_sha256": hex(&input.semantic_options_sha256),
        "source_pattern_sha256": hex(&input.source_pattern_sha256),
        "target_contract_sha256": target.target_contract_hex,
        "target_triple": target.target_triple,
        "transformed_pattern": input.transformed_pattern,
    });
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|error| format!("serialize portable receipt payload: {error}"))?;
    let metadata_bytes = serde_json::to_vec(&metadata)
        .map_err(|error| format!("serialize portable receipt metadata: {error}"))?;
    let payload_sha256 = sha256_hex(&payload_bytes);
    let metadata_sha256 = sha256_hex(&metadata_bytes);
    let receipt_identity = digest_fields(
        PORTABLE_RECEIPT_IDENTITY_DOMAIN,
        &[&payload_bytes, &metadata_bytes],
    );
    let receipt = json!({
        "metadata": metadata,
        "payload": payload,
        "receipt_identity": hex(&receipt_identity),
        "schema": PORTABLE_RECEIPT_SCHEMA,
    });
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|error| format!("serialize portable compiled receipt: {error}"))?;
    let artifact_file_sha256 = sha256_hex(&receipt_bytes);
    let artifact_file_path = write_content_addressed(artifact_root, &receipt_bytes)?;
    let artifact_id = artifact_registry_identity(
        &target.target_contract_hex,
        "portable-current",
        &hex(&input.pattern_sha256),
        &artifact_file_sha256,
        &payload_sha256,
        &metadata_sha256,
    )?;
    Ok(EngineArtifact {
        artifact_id,
        artifact_file_path,
        artifact_file_sha256,
        object_sha256: None,
        payload_sha256,
        metadata_sha256,
        compile_identity: None,
        object_identity: None,
        object_bytes: None,
        payload_bytes: Some(payload_bytes.len()),
        code_bytes: None,
        receipt_identity: Some(hex(&receipt_identity)),
    })
}

fn compile_v2_once(
    literal: &[u8],
    binding_identity: [u8; 32],
    format: CountObjectFormatV3,
) -> Result<PublishedV2, String> {
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .map_err(|error| format!("build fresh Count-v2 KIR: {error}"))?;
    let image = emit_count_v2(&program, CountEmitLimitsV2::default())
        .map_err(|error| format!("emit fresh Count-v2 image: {error}"))?;
    let code_bytes = image.code().len();
    match format {
        CountObjectFormatV3::MachOArm64 => {
            let object = publish_count_implementation_object_macho_v2(
                &image,
                binding_identity,
                CountObjectLimitsV2::default(),
            )
            .map_err(|error| format!("publish fresh Count-v2 Mach-O: {error}"))?;
            let inspection = inspect_count_implementation_object_v2(
                object.as_bytes(),
                CountObjectLimitsV2::default(),
            )
            .map_err(|error| format!("inspect fresh Count-v2 Mach-O: {error}"))?;
            Ok(PublishedV2 {
                bytes: object.as_bytes().to_vec(),
                metadata_bytes: object.metadata_bytes().to_vec(),
                compile_identity: *object.compile_identity(),
                object_identity: *object.object_identity(),
                payload_sha256: Sha256::digest(inspection.payload()).into(),
                payload_bytes: object.payload_bytes(),
                code_bytes,
            })
        }
        CountObjectFormatV3::Elf64Aarch64 => {
            let object = publish_count_implementation_object_elf_v2(
                &image,
                binding_identity,
                CountObjectLimitsV2::default(),
            )
            .map_err(|error| format!("publish fresh Count-v2 ELF: {error}"))?;
            let inspection = inspect_count_implementation_object_elf_v2(
                object.as_bytes(),
                CountObjectLimitsV2::default(),
            )
            .map_err(|error| format!("inspect fresh Count-v2 ELF: {error}"))?;
            Ok(PublishedV2 {
                bytes: object.as_bytes().to_vec(),
                metadata_bytes: object.metadata_bytes().to_vec(),
                compile_identity: *object.compile_identity(),
                object_identity: *object.object_identity(),
                payload_sha256: Sha256::digest(inspection.payload()).into(),
                payload_bytes: object.payload_bytes(),
                code_bytes,
            })
        }
    }
}

fn derive_identity(
    domain: &[u8],
    input: &CompilerArtifactInput,
    target: &TargetConfig,
    extra: &[&[u8]],
) -> [u8; 32] {
    let mut fields = Vec::with_capacity(2 + extra.len());
    fields.push(input.canonical_bytes.as_slice());
    fields.push(target.canonical_bytes.as_slice());
    fields.extend_from_slice(extra);
    digest_fields(domain, &fields)
}

fn artifact_registry_identity(
    target_contract_sha256: &str,
    engine: &str,
    pattern_sha256: &str,
    artifact_file_sha256: &str,
    payload_sha256: &str,
    metadata_sha256: &str,
) -> Result<String, String> {
    let mut value = BTreeMap::new();
    value.insert("artifact_file_sha256", artifact_file_sha256);
    value.insert("engine", engine);
    value.insert("metadata_sha256", metadata_sha256);
    value.insert("pattern_sha256", pattern_sha256);
    value.insert(
        "schema",
        "fre.optimizing-count-v3.artifact-registry-binding.v1",
    );
    value.insert("target_contract_sha256", target_contract_sha256);
    value.insert("payload_sha256", payload_sha256);
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("serialize artifact registry binding: {error}"))?;
    Ok(sha256_hex(&canonical))
}

fn optimizer_input_sha256(
    input: &CompilerArtifactInput,
    target: &TargetConfig,
) -> Result<String, String> {
    let mut value = BTreeMap::new();
    value.insert("pattern_sha256", hex(&input.pattern_sha256));
    value.insert(
        "schema",
        "fre.optimizing-count-v3.optimizer-input.v1".to_string(),
    );
    value.insert(
        "semantic_options_sha256",
        hex(&input.semantic_options_sha256),
    );
    value.insert("target_contract_sha256", target.target_contract_hex.clone());
    let bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("serialize optimizer input: {error}"))?;
    Ok(sha256_hex(&bytes))
}

fn build_registry(
    inventory: &Inventory,
    inventory_sha256: &str,
    target: &TargetConfig,
    artifact_root: &Path,
    source_receipt: &Value,
    compiled: &[CompiledArtifact],
) -> Value {
    let compiled_patterns: Vec<Value> = compiled
        .iter()
        .map(|artifact| {
            json!({
                "claim_derivations": artifact.claim_derivations,
                "engines": [
                    engine_registry("portable-current", &artifact.portable, None),
                    engine_registry("count-v2-current", &artifact.v2, None),
                    engine_registry("count-v3-aot", &artifact.v3.engine, Some(&artifact.v3)),
                ],
                "input_policy": inventory::INPUT_POLICY,
                "optimizer_input_sha256": artifact.optimizer_input_sha256,
                "pattern_input_id": artifact.pattern_input_id,
                "pattern_sha256": artifact.pattern_sha256,
                "planning_receipt_identity": artifact.planning_receipt_identity,
                "semantic_binding_identity": artifact.semantic_binding_identity,
            })
        })
        .collect();
    let mut campaign_artifacts = Vec::with_capacity(compiled.len().saturating_mul(3));
    for artifact in compiled {
        campaign_artifacts.push((
            artifact.pattern_sha256.clone(),
            0_u8,
            campaign_artifact_registry("portable-current", artifact, &artifact.portable),
        ));
        campaign_artifacts.push((
            artifact.pattern_sha256.clone(),
            1_u8,
            campaign_artifact_registry("count-v2-current", artifact, &artifact.v2),
        ));
        campaign_artifacts.push((
            artifact.pattern_sha256.clone(),
            2_u8,
            campaign_artifact_registry("count-v3-aot", artifact, &artifact.v3.engine),
        ));
    }
    campaign_artifacts
        .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let campaign_artifacts: Vec<Value> = campaign_artifacts
        .into_iter()
        .map(|(_, _, row)| row)
        .collect();
    json!({
        "artifact_root": path_text(artifact_root),
        "artifacts": campaign_artifacts,
        "compiled_patterns": compiled_patterns,
        "distinct_artifacts": compiled.len(),
        "input_policy": inventory::INPUT_POLICY,
        "inventory_identity": inventory.inventory_identity,
        "inventory_sha256": inventory_sha256,
        "object_format": target.object_format_name,
        "production_authority": "absent",
        "qualification_authority": "private-only",
        "required_isa": target.required_isa_name,
        "schema": REGISTRY_SCHEMA,
        "source": source_receipt,
        "target_contract_sha256": target.target_contract_hex,
        "target_id": target.target_id,
        "target_triple": target.target_triple,
        "tuning_class": target.tuning_class_name,
    })
}

fn campaign_artifact_registry(
    engine: &str,
    compiled: &CompiledArtifact,
    artifact: &EngineArtifact,
) -> Value {
    json!({
        "artifact_file_path": path_text(&artifact.artifact_file_path),
        "artifact_file_sha256": artifact.artifact_file_sha256,
        "artifact_id": artifact.artifact_id,
        "engine": engine,
        "metadata_sha256": artifact.metadata_sha256,
        "pattern_sha256": compiled.pattern_sha256,
        "payload_sha256": artifact.payload_sha256,
    })
}

fn engine_registry(engine: &str, artifact: &EngineArtifact, v3: Option<&V3Artifact>) -> Value {
    json!({
        "artifact_file_path": path_text(&artifact.artifact_file_path),
        "artifact_file_sha256": artifact.artifact_file_sha256,
        "artifact_id": artifact.artifact_id,
        "code_bytes": artifact.code_bytes,
        "compile_identity": artifact.compile_identity,
        "engine": engine,
        "expectation_bytes_sha256": v3.map(|value| value.expectation_bytes_sha256.as_str()),
        "expectation_file_path": v3.map(|value| path_text(&value.expectation_file_path)),
        "expectation_file_sha256": v3.map(|value| value.expectation_file_sha256.as_str()),
        "expectation_identity": v3.map(|value| value.expectation_identity.as_str()),
        "expectation_symbol": v3.map(|value| value.expectation_symbol.as_str()),
        "metadata_sha256": artifact.metadata_sha256,
        "object_bytes": artifact.object_bytes,
        "object_identity": artifact.object_identity,
        "object_sha256": artifact.object_sha256,
        "payload_bytes": artifact.payload_bytes,
        "payload_sha256": artifact.payload_sha256,
        "receipt_identity": artifact.receipt_identity,
        "recipe_identity": v3.map(|value| value.recipe_identity.as_str()),
        "runtime_authority": if v3.is_some() { "qualification-private" } else { "control" },
        "optimizer_receipt_identity": v3.map(|value| value.optimizer_receipt_identity.as_str()),
    })
}

fn generate_bindings(
    inventory: &Inventory,
    compiled: &[CompiledArtifact],
    registry_bytes: &[u8],
    registry_sha256: &str,
    target: &TargetConfig,
) -> Result<String, String> {
    let registry_text = std::str::from_utf8(registry_bytes)
        .map_err(|error| format!("registry is not UTF-8: {error}"))?;
    let mut output = String::new();
    use std::fmt::Write as _;
    writeln!(
        output,
        "pub(crate) const BUILD_REGISTRY_JSON: &str = {:?};",
        registry_text
    )
    .map_err(|_| "format generated registry".to_string())?;
    writeln!(
        output,
        "pub(crate) const BUILD_REGISTRY_SHA256: &str = {:?};",
        registry_sha256
    )
    .map_err(|_| "format generated registry SHA".to_string())?;
    writeln!(
        output,
        "pub(crate) const EMBEDDED_TARGET_ID: &str = {:?};",
        target.target_id
    )
    .map_err(|_| "format generated target ID".to_string())?;
    writeln!(
        output,
        "pub(crate) const EMBEDDED_REQUIRED_ISA: &str = {:?};",
        target.required_isa_name
    )
    .map_err(|_| "format generated required ISA".to_string())?;

    for (index, artifact) in compiled.iter().enumerate() {
        let v2_compile = artifact
            .v2
            .compile_identity
            .as_deref()
            .ok_or("v2 compile identity absent")?;
        writeln!(
            output,
            "#[allow(unsafe_code, reason = \"the type-disjoint Count-v2 control intentionally times its audited raw ABI\")]\n\
             unsafe extern \"C\" {{\n\
             #[link_name = \"fre_aot_count_entry_v2_{v2_compile}\"]\n\
             fn v2_entry_{index}(haystack: *const u8, haystack_len: usize, result: *mut RawCountResult) -> u64;\n\
             }}"
        )
        .map_err(|_| "format generated Count-v2 extern binding".to_string())?;
    }

    writeln!(output, "mod v3_linked_symbols {{")
        .map_err(|_| "format private Count-v3 module header".to_string())?;
    for (index, artifact) in compiled.iter().enumerate() {
        let v3_compile = artifact
            .v3
            .engine
            .compile_identity
            .as_deref()
            .ok_or("v3 compile identity absent")?;
        writeln!(
            output,
            "#[allow(unsafe_code, reason = \"private declaration of one identity-suffixed Count-v3 final-image ABI\")]\n\
             unsafe extern \"C\" {{\n\
             #[link_name = \"fre_aot_count_entry_v3_{v3_compile}\"]\n\
             fn v3_entry_{index}(haystack: *const u8, haystack_len: usize, result: *mut fre_aot_static_runtime::RawAggregateResultV3) -> u64;\n\
             #[link_name = \"fre_aot_count_payload_v3_{v3_compile}\"]\n\
             static v3_payload_{index}: u8;\n\
             #[link_name = \"fre_aot_count_metadata_v3_{v3_compile}\"]\n\
             static v3_metadata_{index}: u8;\n\
             #[link_name = \"{}\"]\n\
             static v3_expectation_{index}: u8;\n\
             }}",
            artifact.v3.expectation_symbol
        )
        .map_err(|_| "format private Count-v3 extern bindings".to_string())?;
        match target.required_isa {
            CountV3RequiredIsa::Aarch64Neon128 => {
                writeln!(
                    output,
                    "#[allow(unsafe_code, reason = \"the build-linked immutable symbols satisfy the sole qualification adopter boundary\")]\n\
                     pub(super) fn adopt_v3_{index}(\n\
                         binding: fre_aot_static_runtime::StaticCountQualificationFacadeBindingV3<'_>,\n\
                     ) -> Result<fre_aot_static_runtime::VerifiedStaticCountQualificationV3, fre_aot_static_runtime::StaticCountVerifyErrorV3> {{\n\
                         let linked = fre_aot_static_runtime::StaticCountQualificationLinkedAddressesV3::from_exposed_addresses(\n\
                             core::ptr::addr_of!(v3_expectation_{index}).expose_provenance(),\n\
                             core::ptr::addr_of!(v3_payload_{index}).expose_provenance(),\n\
                             core::ptr::addr_of!(v3_metadata_{index}).expose_provenance(),\n\
                             (v3_entry_{index} as *const ()).expose_provenance(),\n\
                         );\n\
                         unsafe {{ fre_aot_static_runtime::adopt_linked_static_count_qualification_v3(linked, binding) }}\n\
                     }}"
                )
                .map_err(|_| "format private NEON Count-v3 adopter".to_string())?;
            }
            CountV3RequiredIsa::Aarch64SveVl16 | CountV3RequiredIsa::Aarch64Sve2Vl16 => {
                writeln!(
                    output,
                    "#[allow(unsafe_code, reason = \"the build-linked immutable symbols satisfy the sole SVE qualification adopter boundary\")]\n\
                     pub(super) fn adopt_v3_{index}(\n\
                         binding: fre_aot_static_runtime::StaticCountSveQualificationFacadeBindingV3<'_>,\n\
                     ) -> Result<fre_aot_static_runtime::VerifiedStaticCountSveQualificationV3, fre_aot_static_runtime::StaticCountVerifyErrorV3> {{\n\
                         let linked = fre_aot_static_runtime::StaticCountSveQualificationLinkedAddressesV3::from_exposed_addresses(\n\
                             core::ptr::addr_of!(v3_expectation_{index}).expose_provenance(),\n\
                             core::ptr::addr_of!(v3_payload_{index}).expose_provenance(),\n\
                             core::ptr::addr_of!(v3_metadata_{index}).expose_provenance(),\n\
                             (v3_entry_{index} as *const ()).expose_provenance(),\n\
                         );\n\
                         unsafe {{ fre_aot_static_runtime::adopt_linked_static_count_sve_qualification_v3(linked, binding) }}\n\
                     }}"
                )
                .map_err(|_| "format private SVE Count-v3 adopter".to_string())?;
            }
        }
    }
    writeln!(output, "}}").map_err(|_| "format private Count-v3 module footer".to_string())?;

    writeln!(
        output,
        "pub(crate) static ARTIFACTS: &[ArtifactDescriptor] = &["
    )
    .map_err(|_| "format artifact table header".to_string())?;
    for (index, artifact) in compiled.iter().enumerate() {
        writeln!(
            output,
            "ArtifactDescriptor {{ pattern_input_id: {:?}, pattern_sha256: {:?}, \
             transformed_pattern: {:?}, unicode: {}, literal_hex: {:?}, \
             semantic_binding_identity: {:?}, planning_receipt_identity: {:?}, \
             portable_artifact_id: {:?}, portable_artifact_file_path: {:?}, \
             portable_artifact_file_sha256: {:?}, v2_artifact_id: {:?}, \
             v2_artifact_file_path: {:?}, v2_artifact_file_sha256: {:?}, \
             v3_artifact_id: {:?}, v3_artifact_file_path: {:?}, \
             v3_artifact_file_sha256: {:?}, \
             v2_entry: v2_entry_{index}, v3_adopt: v3_linked_symbols::adopt_v3_{index} }},",
            artifact.pattern_input_id,
            artifact.pattern_sha256,
            artifact.transformed_pattern,
            artifact.unicode,
            artifact.literal_hex,
            artifact.semantic_binding_identity,
            artifact.planning_receipt_identity,
            artifact.portable.artifact_id,
            path_text(&artifact.portable.artifact_file_path),
            artifact.portable.artifact_file_sha256,
            artifact.v2.artifact_id,
            path_text(&artifact.v2.artifact_file_path),
            artifact.v2.artifact_file_sha256,
            artifact.v3.engine.artifact_id,
            path_text(&artifact.v3.engine.artifact_file_path),
            artifact.v3.engine.artifact_file_sha256,
        )
        .map_err(|_| "format artifact descriptor".to_string())?;
    }
    writeln!(output, "];").map_err(|_| "format artifact table footer".to_string())?;

    let indexes: BTreeMap<&str, usize> = compiled
        .iter()
        .enumerate()
        .map(|(index, artifact)| (artifact.pattern_input_id.as_str(), index))
        .collect();
    writeln!(output, "pub(crate) static CELLS: &[CellDescriptor] = &[")
        .map_err(|_| "format cell table header".to_string())?;
    for cell in &inventory.cells {
        let artifact_index = indexes
            .get(cell.pattern_input_id.as_str())
            .ok_or_else(|| format!("cell {} lost artifact index", cell.cell_id))?;
        writeln!(
            output,
            "CellDescriptor {{ cell_id: {:?}, artifact_index: {}, input_sha256: {:?}, \
             input_bytes: {}, expected_count: {}, oracle_receipt_sha256: {:?} }},",
            cell.cell_id,
            artifact_index,
            cell.input_sha256,
            cell.input_bytes,
            cell.expected_count,
            cell.oracle_receipt_sha256,
        )
        .map_err(|_| "format cell descriptor".to_string())?;
    }
    writeln!(output, "];").map_err(|_| "format cell table footer".to_string())?;
    Ok(output)
}

fn validate_generated_v3_boundary(source: &str, artifacts: usize) -> Result<(), String> {
    let private_modules = source.matches("mod v3_linked_symbols {").count();
    let raw_entries = source.matches("fn v3_entry_").count();
    let safe_adopters = source.matches("pub(super) fn adopt_v3_").count();
    if private_modules != 1
        || raw_entries != artifacts
        || safe_adopters != artifacts
        || source.contains("v3_entry:")
        || source.contains("LinkedSymbolAddresses")
        || source.contains("StaticAggregateEntryV3")
    {
        return Err(
            "generated Count-v3 binding boundary leaks or omits a private linked symbol"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_runner_source_boundary(manifest_dir: &Path) -> Result<(), String> {
    let path = manifest_dir.join("src/main.rs");
    let bytes = read_regular_file(&path, MAX_SOURCE_FILE_BYTES, false)?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|error| format!("runner source is not UTF-8: {error}"))?;
    for forbidden in [
        "v3_entry_",
        "LinkedSymbolAddresses",
        "StaticAggregateEntryV3",
        ".count(",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "runner source crosses the Count-v3 safe facade boundary with {forbidden}"
            ));
        }
    }
    if source.matches(".count_value(").count() < 4
        || !source.contains("begin_current_thread_session")
        || source.contains("mod v3_linked_symbols")
    {
        return Err(
            "runner source lacks the reviewed safe Count-v3 facade/session shape".to_string(),
        );
    }
    Ok(())
}

fn source_receipt(manifest_dir: &Path) -> Result<Value, String> {
    let mut files = BTreeMap::new();
    let mut aggregate_fields = Vec::new();
    for relative in [
        "Cargo.toml",
        "README.md",
        "build.rs",
        "build_support/inventory.rs",
        "build_support/expectation_object.rs",
        "src/main.rs",
    ] {
        let bytes = read_regular_file(&manifest_dir.join(relative), MAX_SOURCE_FILE_BYTES, false)?;
        let digest = sha256_hex(&bytes);
        aggregate_fields.push(relative.as_bytes().to_vec());
        aggregate_fields.push(bytes);
        files.insert(relative.to_string(), digest);
    }
    let borrowed: Vec<&[u8]> = aggregate_fields.iter().map(Vec::as_slice).collect();
    let source_set_sha256 = hex(&digest_fields(SOURCE_SET_DOMAIN, &borrowed));
    Ok(json!({
        "files": files,
        "source_set_sha256": source_set_sha256,
    }))
}

fn validate_artifact_root(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("FRE_COUNT_V3_ARTIFACT_ROOT must be absolute".to_string());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("stat artifact root {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "artifact root {} is not a real directory",
            path.display()
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("canonicalize artifact root: {error}"))?;
    if canonical.to_str().is_none() {
        return Err("canonical artifact root must be UTF-8 for JSON receipts".to_string());
    }
    let canonical_metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("restat artifact root: {error}"))?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_dir() {
        return Err("canonical artifact root is not a real directory".to_string());
    }
    Ok(canonical)
}

fn write_content_addressed(root: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    let digest = sha256_hex(bytes);
    let path = root.join(&digest);
    if path.parent() != Some(root)
        || path.file_name().and_then(|name| name.to_str()) != Some(&digest)
    {
        return Err("content-addressed path escaped artifact root".to_string());
    }
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(bytes)
                .map_err(|error| format!("write {}: {error}", path.display()))?;
            file.sync_all()
                .map_err(|error| format!("fsync {}: {error}", path.display()))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
                .map_err(|error| format!("make {} read-only: {error}", path.display()))?;
            let root_file = File::open(root)
                .map_err(|error| format!("open artifact root for fsync: {error}"))?;
            root_file
                .sync_all()
                .map_err(|error| format!("fsync artifact root: {error}"))?;
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing = read_regular_file(&path, bytes.len(), true)?;
            if existing != bytes {
                return Err(format!(
                    "existing content-addressed file {} differs",
                    path.display()
                ));
            }
        }
        Err(error) => {
            return Err(format!(
                "create content-addressed file {}: {error}",
                path.display()
            ));
        }
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("stat content-addressed file: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o222 != 0
        || metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(format!(
            "content-addressed file {} is not immutable canonical storage",
            path.display()
        ));
    }
    if sha256_hex(&read_regular_file(&path, bytes.len(), true)?) != digest {
        return Err(format!(
            "content-addressed file {} failed final digest",
            path.display()
        ));
    }
    Ok(path)
}

fn read_regular_file(
    path: &Path,
    maximum: usize,
    require_read_only: bool,
) -> Result<Vec<u8>, String> {
    let before =
        fs::symlink_metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
        || require_read_only && before.mode() & 0o222 != 0
    {
        return Err(format!(
            "{} is not an admissible bounded regular file",
            path.display()
        ));
    }
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", path.display()))?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.len() != before.len()
        || opened.nlink() != 1
    {
        return Err(format!("{} changed while opening", path.display()));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len()).map_err(|_| "file length does not fit usize")?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|error| format!("refstat {}: {error}", path.display()))?;
    if bytes.len() != usize::try_from(opened.len()).unwrap_or(usize::MAX)
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
        || after.mtime() != opened.mtime()
        || after.mtime_nsec() != opened.mtime_nsec()
    {
        return Err(format!("{} changed while reading", path.display()));
    }
    Ok(bytes)
}

fn required_path(variable: &str) -> Result<PathBuf, String> {
    env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{variable} is required"))
}

fn required_environment(variable: &str) -> Result<String, String> {
    env::var(variable)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{variable} is required and must be UTF-8"))
}

fn required_hex_environment(variable: &str) -> Result<String, String> {
    let value = required_environment(variable)?;
    parse_hex_32(&value, variable)?;
    Ok(value)
}

fn require_safe_id(value: &str, label: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 96
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        Err(format!("{label} is not a canonical safe ID"))
    } else {
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn path_text(path: &Path) -> &str {
    path.to_str()
        .expect("validated campaign paths must be UTF-8 for JSON receipts")
}
