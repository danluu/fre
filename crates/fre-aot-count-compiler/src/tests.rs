use fre::RustProfile;
use fre_aot_compiler::{
    CompiledObjectV2, MacosAarch64CountManifestV2, plan_and_compile_macos_aarch64_count_v2,
};
use fre_kernel_ir::{AggregateBuildError, MAX_EXACT_AGGREGATE_LITERAL_BYTES};
use sha2::{Digest, Sha256};

use crate::{
    COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2, COUNT_FINAL_IMAGE_GLUE_RELOCATIONS_V2,
    CountCompileClaimsV2, CountCompileErrorV2, CountCompileLimitsV2, CountCompileRequestV2,
    CountFinalImageAdopterV2, CountFinalImageGlueLimitsV2, FocusedCompiledCountV2,
    RuntimeAuthorityV2, compile_count_v2, inspect_count_final_image_glue_v2,
    publish_count_final_image_glue_v2, publish_count_qualification_final_image_glue_v2,
};

const LITERAL: &[u8] = b"needle";
type ClaimMutation = fn(&mut CountCompileClaimsV2);

fn legacy_oracle() -> CompiledObjectV2 {
    legacy_oracle_for(LITERAL)
}

fn legacy_oracle_for(literal: &[u8]) -> CompiledObjectV2 {
    let mut profile = RustProfile::default();
    profile.options.unicode = false;
    plan_and_compile_macos_aarch64_count_v2(
        MacosAarch64CountManifestV2::default(),
        literal.to_vec(),
        profile,
    )
    .expect("legacy compiler-v2 compatibility oracle")
}

fn claims_from_oracle(oracle: &CompiledObjectV2) -> CountCompileClaimsV2 {
    let claim = oracle.static_count_expectation().claim();
    CountCompileClaimsV2 {
        manifest_identity: *claim.manifest_identity(),
        policy_limits_identity: *claim.policy_limits_identity(),
        semantic_binding_identity: *claim.semantic_binding_identity(),
        planning_receipt_identity: *claim.planning_receipt_identity(),
        live_literal_identity: *claim.live_literal_identity(),
        program_identity: *claim.program_identity(),
        image_identity: *claim.image_identity(),
        object_binding_identity: *claim.object_binding_identity(),
        claimed_receipt_identity: *claim.receipt_identity(),
        claimed_resource_receipt_identity: *claim.resource_receipt_identity(),
    }
}

fn compile_focused(
    claims: &CountCompileClaimsV2,
) -> Result<FocusedCompiledCountV2, CountCompileErrorV2> {
    compile_focused_literal(LITERAL, claims)
}

fn compile_focused_literal(
    literal: &[u8],
    claims: &CountCompileClaimsV2,
) -> Result<FocusedCompiledCountV2, CountCompileErrorV2> {
    compile_count_v2(
        CountCompileRequestV2 {
            literal,
            claims: *claims,
        },
        CountCompileLimitsV2::default(),
    )
}

#[test]
fn every_supported_literal_width_remains_byte_exact_with_the_legacy_oracle() {
    for width in 1..=MAX_EXACT_AGGREGATE_LITERAL_BYTES {
        let literal = vec![b'n'; width];
        let oracle = legacy_oracle_for(&literal);
        let focused = compile_focused_literal(&literal, &claims_from_oracle(&oracle))
            .expect("focused Count compile at supported literal width");
        assert_eq!(
            focused.implementation_object().as_bytes(),
            oracle.object().as_bytes(),
            "implementation object drift at width {width}"
        );
        assert_eq!(
            focused.implementation_object().metadata_bytes(),
            oracle.static_count_expectation().metadata_bytes_v2(),
            "metadata drift at width {width}"
        );
        assert_eq!(
            focused.expectation(),
            oracle.static_count_expectation().as_bytes(),
            "expectation drift at width {width}"
        );
    }
}

#[test]
fn oversized_literal_refuses_before_claim_checks_or_literal_hashing() {
    let boundary_literal = vec![b'n'; MAX_EXACT_AGGREGATE_LITERAL_BYTES];
    let oracle = legacy_oracle_for(&boundary_literal);
    let mut literal_bound_claims = claims_from_oracle(&oracle);
    let oversized_literal = vec![b'n'; MAX_EXACT_AGGREGATE_LITERAL_BYTES + 1];
    literal_bound_claims.live_literal_identity = Sha256::digest(&oversized_literal).into();

    let mut zero_claims = literal_bound_claims;
    zero_claims.planning_receipt_identity = [0; 32];
    let mut mismatched_literal_claims = literal_bound_claims;
    mismatched_literal_claims.live_literal_identity[0] ^= 1;
    let expected = Err(CountCompileErrorV2::Kernel(
        AggregateBuildError::LiteralLengthLimit {
            limit: MAX_EXACT_AGGREGATE_LITERAL_BYTES,
            required: oversized_literal.len(),
        },
    ));

    for claims in [literal_bound_claims, zero_claims, mismatched_literal_claims] {
        let computations_before = crate::receipt::literal_identity_computations_v2_for_test();
        assert_eq!(
            compile_focused_literal(&oversized_literal, &claims),
            expected
        );
        assert_eq!(
            crate::receipt::literal_identity_computations_v2_for_test(),
            computations_before,
            "oversized input reached the literal hasher"
        );
    }
}

#[test]
fn focused_pipeline_is_byte_exact_with_the_legacy_oracle() {
    let oracle = legacy_oracle();
    let claims = claims_from_oracle(&oracle);
    let focused = compile_focused(&claims).expect("focused Count compile");
    let repeated = compile_focused(&claims).expect("repeated focused Count compile");

    assert_eq!(
        focused.implementation_object().as_bytes(),
        oracle.object().as_bytes()
    );
    assert_eq!(
        focused.implementation_object().metadata_bytes(),
        oracle.static_count_expectation().metadata_bytes_v2()
    );
    assert_eq!(
        focused.expectation(),
        oracle.static_count_expectation().as_bytes()
    );
    assert_eq!(focused, repeated);
    assert_eq!(focused.runtime_authority(), RuntimeAuthorityV2::Absent);
    assert!(focused.unsigned_prelink_receipt().authenticates_itself());
    assert!(
        focused
            .unsigned_prelink_receipt()
            .validate_candidate(
                focused.implementation_object().as_bytes(),
                CountCompileLimitsV2::default().object,
            )
            .is_ok()
    );
}

#[test]
fn every_object_byte_mutation_is_refused_without_creating_authority() {
    let oracle = legacy_oracle();
    let focused = compile_focused(&claims_from_oracle(&oracle)).expect("focused Count compile");
    let receipt = focused.unsigned_prelink_receipt();
    let limits = CountCompileLimitsV2::default().object;
    let mut candidate = focused.implementation_object().as_bytes().to_vec();

    for offset in 0..candidate.len() {
        candidate[offset] ^= 1;
        assert!(
            receipt.validate_candidate(&candidate, limits).is_err(),
            "mutated object byte {offset} was accepted"
        );
        candidate[offset] ^= 1;
    }
    assert_eq!(receipt.runtime_authority(), RuntimeAuthorityV2::Absent);
}

#[test]
fn unavailable_planner_claims_are_bound_but_never_treated_as_authority() {
    let oracle = legacy_oracle();
    let baseline_claims = claims_from_oracle(&oracle);
    let baseline = compile_focused(&baseline_claims).expect("baseline focused Count compile");

    let mut changed_manifest_claims = baseline_claims;
    changed_manifest_claims.manifest_identity[0] ^= 1;
    let changed_manifest = compile_focused(&changed_manifest_claims)
        .expect("changed manifest claim remains untrusted");
    assert_eq!(
        baseline.implementation_object().as_bytes(),
        changed_manifest.implementation_object().as_bytes()
    );
    assert_ne!(baseline.expectation(), changed_manifest.expectation());
    assert_ne!(
        baseline.unsigned_prelink_receipt().content_identity(),
        changed_manifest
            .unsigned_prelink_receipt()
            .content_identity()
    );
    assert_eq!(
        changed_manifest.runtime_authority(),
        RuntimeAuthorityV2::Absent
    );

    let mut changed_binding_claims = baseline_claims;
    changed_binding_claims.object_binding_identity[0] ^= 1;
    let changed_binding =
        compile_focused(&changed_binding_claims).expect("changed binding claim remains untrusted");
    assert_ne!(
        baseline.implementation_object().as_bytes(),
        changed_binding.implementation_object().as_bytes()
    );
    assert_ne!(baseline.expectation(), changed_binding.expectation());
    assert_eq!(
        changed_binding.runtime_authority(),
        RuntimeAuthorityV2::Absent
    );
}

#[test]
fn locally_reproducible_claims_must_match_recomputed_facts() {
    let oracle = legacy_oracle();
    let claims = claims_from_oracle(&oracle);

    let cases: [(&str, ClaimMutation); 3] = [
        (
            "live literal identity",
            |claims: &mut CountCompileClaimsV2| {
                claims.live_literal_identity[0] ^= 1;
            },
        ),
        ("program identity", |claims: &mut CountCompileClaimsV2| {
            claims.program_identity[0] ^= 1;
        }),
        ("image identity", |claims: &mut CountCompileClaimsV2| {
            claims.image_identity[0] ^= 1;
        }),
    ];
    for (field, mutate) in cases {
        let mut changed = claims;
        mutate(&mut changed);
        assert_eq!(
            compile_focused(&changed),
            Err(CountCompileErrorV2::ClaimMismatch { field })
        );
    }
}

#[test]
fn zero_claims_are_refused_before_compilation() {
    let oracle = legacy_oracle();
    let mut claims = claims_from_oracle(&oracle);
    claims.planning_receipt_identity = [0; 32];
    assert_eq!(
        compile_focused(&claims),
        Err(CountCompileErrorV2::InvalidClaim {
            field: "planning receipt identity",
        })
    );
}

#[test]
fn final_image_glue_is_deterministic_and_row_selector_first() {
    let oracle = legacy_oracle();
    let focused = compile_focused(&claims_from_oracle(&oracle)).expect("focused Count compile");
    let first =
        publish_count_final_image_glue_v2(&focused, 37, CountFinalImageGlueLimitsV2::default())
            .expect("final-image glue");
    let second =
        publish_count_final_image_glue_v2(&focused, 37, CountFinalImageGlueLimitsV2::default())
            .expect("repeated final-image glue");
    assert_eq!(first, second);
    assert_eq!(first.runtime_authority(), RuntimeAuthorityV2::Absent);
    assert_eq!(first.object().row_selector(), 37);
    assert_eq!(
        first.object().adopter(),
        CountFinalImageAdopterV2::Production
    );
    assert_eq!(
        first.object().compile_identity(),
        focused.implementation_object().compile_identity()
    );
    assert_eq!(
        first.receipt().prelink_content_identity(),
        focused.unsigned_prelink_receipt().content_identity()
    );
    assert_eq!(
        first.receipt().adopter(),
        Some(CountFinalImageAdopterV2::Production)
    );
    assert_eq!(
        first.receipt().implementation_object_identity(),
        focused.implementation_object().object_identity()
    );

    let inspection = inspect_count_final_image_glue_v2(
        first.object().as_bytes(),
        CountFinalImageGlueLimitsV2::default(),
    )
    .expect("strict glue inspection");
    assert_eq!(inspection.row_selector(), 37);
    assert_eq!(inspection.adopter(), CountFinalImageAdopterV2::Production);
    assert_eq!(inspection.expectation(), focused.expectation());
    assert_eq!(
        inspection.object_identity(),
        first.object().object_identity()
    );
    assert_eq!(
        first.receipt().runtime_authority(),
        RuntimeAuthorityV2::Absent
    );

    let code = first
        .object()
        .as_bytes()
        .get(400..400 + COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2)
        .expect("fixed glue code range");
    let words: Vec<u32> = code
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("four-byte glue instruction")))
        .collect();
    assert_eq!(
        words,
        [
            0x5280_04a1,
            0x9000_0002,
            0x9100_0042,
            0x9000_0003,
            0x9100_0063,
            0x9000_0004,
            0x9100_0084,
            0x9000_0005,
            0x9100_00a5,
            0x1400_0000,
        ]
    );
    assert_eq!(COUNT_FINAL_IMAGE_GLUE_RELOCATIONS_V2, 9);
}

#[test]
fn qualification_glue_has_a_distinct_canonical_adopter_symbol() {
    let oracle = legacy_oracle();
    let focused = compile_focused(&claims_from_oracle(&oracle)).expect("focused Count compile");
    let production =
        publish_count_final_image_glue_v2(&focused, 11, CountFinalImageGlueLimitsV2::default())
            .expect("production final-image glue");
    let qualification = publish_count_qualification_final_image_glue_v2(
        &focused,
        11,
        CountFinalImageGlueLimitsV2::default(),
    )
    .expect("qualification final-image glue");
    assert_ne!(
        production.object().as_bytes(),
        qualification.object().as_bytes()
    );
    assert_eq!(
        qualification.object().adopter(),
        CountFinalImageAdopterV2::QualificationPrivate
    );
    assert_eq!(
        qualification.receipt().adopter(),
        Some(CountFinalImageAdopterV2::QualificationPrivate)
    );
    let inspection = qualification
        .receipt()
        .validate_candidate(
            qualification.object().as_bytes(),
            CountFinalImageGlueLimitsV2::default(),
        )
        .expect("qualification receipt");
    assert_eq!(
        inspection.adopter(),
        CountFinalImageAdopterV2::QualificationPrivate
    );
}

#[test]
fn final_image_receipt_refuses_every_glue_object_byte_mutation() {
    let oracle = legacy_oracle();
    let focused = compile_focused(&claims_from_oracle(&oracle)).expect("focused Count compile");
    let published =
        publish_count_final_image_glue_v2(&focused, 5, CountFinalImageGlueLimitsV2::default())
            .expect("final-image glue");
    let mut candidate = published.object().as_bytes().to_vec();
    for offset in 0..candidate.len() {
        candidate[offset] ^= 1;
        assert!(
            published
                .receipt()
                .validate_candidate(&candidate, CountFinalImageGlueLimitsV2::default(),)
                .is_err(),
            "mutated glue byte {offset} was accepted"
        );
        candidate[offset] ^= 1;
    }
    assert_eq!(
        published.receipt().runtime_authority(),
        RuntimeAuthorityV2::Absent
    );
}

#[test]
fn final_image_row_change_is_bound_and_size_limit_refuses_before_allocation() {
    let oracle = legacy_oracle();
    let focused = compile_focused(&claims_from_oracle(&oracle)).expect("focused Count compile");
    let row_one =
        publish_count_final_image_glue_v2(&focused, 1, CountFinalImageGlueLimitsV2::default())
            .expect("row-one glue");
    let row_two =
        publish_count_final_image_glue_v2(&focused, 2, CountFinalImageGlueLimitsV2::default())
            .expect("row-two glue");
    assert_ne!(row_one.object().as_bytes(), row_two.object().as_bytes());
    assert_ne!(
        row_one.receipt().content_identity(),
        row_two.receipt().content_identity()
    );
    for selector in [0, u16::MAX] {
        let boundary = publish_count_final_image_glue_v2(
            &focused,
            selector,
            CountFinalImageGlueLimitsV2::default(),
        )
        .expect("row-selector boundary glue");
        assert_eq!(boundary.object().row_selector(), selector);
        assert_eq!(boundary.receipt().row_selector(), selector);
    }
    let exact_object_bytes =
        u64::try_from(row_one.object().as_bytes().len()).expect("small glue object");
    assert!(
        publish_count_final_image_glue_v2(
            &focused,
            1,
            CountFinalImageGlueLimitsV2 {
                max_object_bytes: exact_object_bytes,
            },
        )
        .is_ok()
    );
    let one_below = exact_object_bytes
        .checked_sub(1)
        .expect("nonempty glue object");
    assert_eq!(
        publish_count_final_image_glue_v2(
            &focused,
            1,
            CountFinalImageGlueLimitsV2 {
                max_object_bytes: one_below,
            },
        ),
        Err(CountCompileErrorV2::ResourceLimit {
            resource: "final-image glue object bytes",
            limit: one_below,
            required: exact_object_bytes,
        })
    );
}

#[cfg(target_os = "macos")]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one Apple integration transaction validates object tools, link resolution, native execution, and duplicate refusal"
)]
fn apple_tools_accept_the_emitted_arm64_glue_object() {
    use std::{
        fs,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    let oracle = legacy_oracle();
    let focused = compile_focused(&claims_from_oracle(&oracle)).expect("focused Count compile");
    let published =
        publish_count_final_image_glue_v2(&focused, 11, CountFinalImageGlueLimitsV2::default())
            .expect("final-image glue");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock after Unix epoch")
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("fre-aot-count-glue-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory).expect("create private glue inspection directory");
    let object_path = directory.join("count-glue.o");
    fs::write(&object_path, published.object().as_bytes()).expect("write glue object");
    let implementation_path = directory.join("count-implementation.o");
    fs::write(
        &implementation_path,
        focused.implementation_object().as_bytes(),
    )
    .expect("write implementation object");

    let file_output = Command::new("/usr/bin/file")
        .arg(&object_path)
        .output()
        .expect("run file");
    assert!(file_output.status.success());
    assert!(String::from_utf8_lossy(&file_output.stdout).contains("Mach-O 64-bit object arm64"));

    let otool_output = Command::new("/usr/bin/otool")
        .args(["-l"])
        .arg(&object_path)
        .output()
        .expect("run otool");
    assert!(otool_output.status.success());
    let load_commands = String::from_utf8_lossy(&otool_output.stdout);
    assert!(load_commands.contains("sectname __text"));
    assert!(load_commands.contains("sectname __fre_expect"));
    assert!(load_commands.contains("nreloc 9"));

    let nm_output = Command::new("/usr/bin/nm")
        .arg(&object_path)
        .output()
        .expect("run nm");
    assert!(nm_output.status.success());
    let symbols = String::from_utf8_lossy(&nm_output.stdout);
    assert!(symbols.contains("_fre_aot_count_glue_v2_"));
    assert!(symbols.contains("_fre_aot_static_count_adopt_raw_v2"));

    let suffix = focused
        .implementation_object()
        .compile_identity()
        .iter()
        .fold(String::new(), |mut encoded, byte| {
            use std::fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("write compile identity hex");
            encoded
        });
    let driver_source = r#"
#include <stddef.h>
#include <stdint.h>

struct adoption_output {
    const void *verified;
};

typedef uint64_t (*count_entry)(
    const uint8_t *,
    size_t,
    uint64_t *
);

extern uint32_t GLUE_SYMBOL(struct adoption_output *);

uint32_t fre_aot_static_count_adopt_raw_v2(
    struct adoption_output *output,
    uint32_t selector,
    const uint8_t *expectation,
    const uint8_t *entry,
    const uint8_t *payload,
    const uint8_t *metadata
) {
    static const uint8_t haystack[] = "needle hay needle";
    uint64_t result = UINT64_MAX;
    if (output == NULL || selector != 11 || expectation == NULL ||
        entry == NULL || payload == NULL || metadata == NULL ||
        entry != payload) {
        return 91;
    }
    if (expectation[0] != 'F' || expectation[7] != 2) {
        return 92;
    }
    uint64_t status = ((count_entry)entry)(
        haystack,
        sizeof(haystack) - 1,
        &result
    );
    if (status != 0 || result != 2) {
        return 93;
    }
    return 77;
}

int main(void) {
    struct adoption_output output = {0};
    return GLUE_SYMBOL(&output) == 77 ? 0 : 1;
}
"#
    .replace("GLUE_SYMBOL", &format!("fre_aot_count_glue_v2_{suffix}"));
    let driver_path = directory.join("driver.c");
    fs::write(&driver_path, driver_source).expect("write glue ABI driver");
    let executable_path = directory.join("count-glue-execution");
    let link = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64"])
        .arg(&driver_path)
        .arg(&object_path)
        .arg(&implementation_path)
        .arg("-Wl,-segprot,__FRE_CONST,r,r")
        .arg("-o")
        .arg(&executable_path)
        .output()
        .expect("link glue execution fixture");
    assert!(
        link.status.success(),
        "glue link failed: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let execution = Command::new(&executable_path)
        .output()
        .expect("execute linked Count glue");
    assert!(
        execution.status.success(),
        "linked Count glue execution failed: {}",
        String::from_utf8_lossy(&execution.stderr)
    );
    let linked_otool = Command::new("/usr/bin/otool")
        .args(["-l"])
        .arg(&executable_path)
        .output()
        .expect("inspect linked Count image");
    assert!(linked_otool.status.success());
    let linked_load_commands = String::from_utf8_lossy(&linked_otool.stdout);
    let constant_segment = linked_load_commands
        .split("Load command")
        .find(|command| {
            command.contains("cmd LC_SEGMENT_64")
                && command.lines().any(|line| line == "  segname __FRE_CONST")
        })
        .expect("linked image contains __FRE_CONST segment");
    assert!(
        constant_segment
            .lines()
            .any(|line| line.trim() == "maxprot 0x00000001")
    );
    assert!(
        constant_segment
            .lines()
            .any(|line| line.trim() == "initprot 0x00000001")
    );

    let duplicate_path = directory.join("duplicate-refusal");
    let duplicate = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64"])
        .arg(&driver_path)
        .arg(&object_path)
        .arg(&implementation_path)
        .arg(&implementation_path)
        .arg("-Wl,-segprot,__FRE_CONST,r,r")
        .arg("-o")
        .arg(&duplicate_path)
        .output()
        .expect("attempt duplicate implementation link");
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate symbol"));

    fs::remove_file(&executable_path).expect("remove glue execution fixture");
    fs::remove_file(&driver_path).expect("remove glue ABI driver");
    fs::remove_file(&implementation_path).expect("remove implementation object");
    fs::remove_file(&object_path).expect("remove glue inspection object");
    fs::remove_dir(&directory).expect("remove glue inspection directory");
}
