use fre_jit_aarch64::{
    BackendVersion, EmitLimits, SearchBackendPolicy, SelectedEndRegisterBackendV2,
    emit_selected_end_register_v2, emit_with_backend,
};
use fre_kernel_ir::{AnchorFlags, SelectedEnd, ValidateLimits, build_exact_literal};
use sha2::{Digest, Sha256};

use crate::metadata_v2::{
    SELECTED_END_ELF_COMPILE_IDENTITY_DOMAIN_V2, SELECTED_END_METADATA_COMPILE_IDENTITY_OFFSET_V2,
};
use crate::{
    BindingIdentity, C_SELECTED_END_HEADER_V2, ELF_CLASS_64_V2, ELF_DATA_LSB_V2,
    ELF_MACHINE_AARCH64_V2, ELF_OS_ABI_SYSV_V2, ELF_RELOCATABLE_TYPE_V2,
    ELF_SYMBOL_INFO_FUNCTION_V2, ELF_SYMBOL_INFO_OBJECT_V2, ELF_SYMBOL_VISIBILITY_HIDDEN_V2,
    ELF_VERSION_CURRENT_V2, EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2,
    EXPORTED_SYMBOL_SCHEMA_VERSION_V2, ElfObjectError, ElfObjectResource, METADATA_BYTES_V1,
    ObjectLimitsV1, SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2, SELECTED_END_ABI_KIND_V2,
    SELECTED_END_ARGUMENT_COUNT_V2, SELECTED_END_ENTRY_OFFSET_V2,
    SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2, SELECTED_END_LITERAL_BYTES_V2,
    SELECTED_END_METADATA_BYTES_V2, SELECTED_END_METADATA_SYMBOL_PREFIX_V2,
    SELECTED_END_METADATA_VERSION_V2, SELECTED_END_NO_MATCH_SENTINEL_V2,
    SELECTED_END_OUTPUT_KIND_V2, SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2,
    SELECTED_END_PLATFORM_LINUX_V2, SELECTED_END_REQUIRED_FEATURES_V2,
    SELECTED_END_RESULT_SLOT_BYTES_V2, SELECTED_END_RETURN_BITS_V2,
    SELECTED_END_RETURN_REGISTER_V2, SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2,
    SelectedEndObjectLimitsV2, emit_search_object_v1, emit_selected_end_search_object_v2,
    inspect_metadata_v1, inspect_search_object_v1, inspect_selected_end_metadata_v2,
    inspect_selected_end_search_object_v2, validate_selected_end_search_object_v2,
};

const TEST_LITERAL: &[u8; 16] = b"0123456789abcdef";
const TEST_BINDING: [u8; 32] = [0x5a; 32];

fn program() -> fre_kernel_ir::ValidatedProgram<SelectedEnd> {
    build_exact_literal::<SelectedEnd>(
        TEST_LITERAL,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("exact SelectedEnd test KIR")
}

fn tag21_image() -> fre_jit_aarch64::AuditedSelectedEndRegisterImageV2 {
    emit_selected_end_register_v2(
        &program(),
        SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
        EmitLimits::default(),
    )
    .expect("tag21 ABI2 image")
}

fn binding() -> BindingIdentity {
    BindingIdentity::new(TEST_BINDING).expect("nonzero test binding")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed u64 test field"),
    )
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed u16 test field"),
    )
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed u32 test field"),
    )
}

fn reference_compile_identity(metadata_bytes: &[u8; SELECTED_END_METADATA_BYTES_V2]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SELECTED_END_ELF_COMPILE_IDENTITY_DOMAIN_V2);
    hasher.update(SELECTED_END_METADATA_VERSION_V2.to_le_bytes());
    hasher.update(EXPORTED_SYMBOL_SCHEMA_VERSION_V2.to_le_bytes());
    hasher.update(
        u16::try_from(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2)
            .expect("fixed identity width")
            .to_le_bytes(),
    );
    for (prefix, info) in [
        (
            SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2,
            ELF_SYMBOL_INFO_FUNCTION_V2,
        ),
        (
            SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2,
            ELF_SYMBOL_INFO_OBJECT_V2,
        ),
        (
            SELECTED_END_METADATA_SYMBOL_PREFIX_V2,
            ELF_SYMBOL_INFO_OBJECT_V2,
        ),
    ] {
        hasher.update(
            u16::try_from(prefix.len())
                .expect("fixed prefix width")
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
        hasher.update([info, ELF_SYMBOL_VISIBILITY_HIDDEN_V2]);
    }
    hasher.update([
        ELF_CLASS_64_V2,
        ELF_DATA_LSB_V2,
        ELF_VERSION_CURRENT_V2,
        ELF_OS_ABI_SYSV_V2,
    ]);
    hasher.update(ELF_RELOCATABLE_TYPE_V2.to_le_bytes());
    hasher.update(ELF_MACHINE_AARCH64_V2.to_le_bytes());
    hasher.update(metadata_bytes);
    hasher.finalize().into()
}

fn assert_limit(error: ElfObjectError, expected_resource: ElfObjectResource, expected_limit: u64) {
    assert!(matches!(
        error,
        ElfObjectError::ResourceLimit {
            resource,
            limit,
            required,
        } if resource == expected_resource
            && limit == expected_limit
            && limit.checked_add(1) == Some(required)
    ));
}

#[test]
fn tag21_selected_end_v2_object_and_metadata_are_exact_and_deterministic() {
    let image = tag21_image();
    assert_eq!(
        image.backend_version(),
        BackendVersion::SEARCH_SVE2_FIXED16_V2
    );
    assert_eq!(image.literal_bytes(), SELECTED_END_LITERAL_BYTES_V2);
    assert_eq!(
        image.rodata().len(),
        usize::try_from(SELECTED_END_LITERAL_BYTES_V2).expect("literal width")
    );
    assert_eq!(image.rodata(), TEST_LITERAL);

    let first =
        emit_selected_end_search_object_v2(&image, binding(), SelectedEndObjectLimitsV2::default())
            .expect("first SelectedEnd-v2 ELF");
    let second =
        emit_selected_end_search_object_v2(&image, binding(), SelectedEndObjectLimitsV2::default())
            .expect("second SelectedEnd-v2 ELF");
    assert_eq!(first.as_bytes(), second.as_bytes());
    assert_eq!(first.object_identity(), second.object_identity());
    assert_eq!(first.compile_identity(), second.compile_identity());
    assert_eq!(&first.as_bytes()[..4], b"\x7fELF");

    let inspection = inspect_selected_end_search_object_v2(
        first.as_bytes(),
        SelectedEndObjectLimitsV2::default(),
    )
    .expect("strict SelectedEnd-v2 ELF inspection");
    validate_selected_end_search_object_v2(
        &image,
        binding(),
        first.as_bytes(),
        SelectedEndObjectLimitsV2::default(),
    )
    .expect("sealed-image SelectedEnd-v2 validation");
    let metadata = inspection.metadata();
    let metadata_bytes = metadata.encode().expect("canonical metadata");
    assert_eq!(&metadata_bytes[..8], b"FRESE64\x02");
    assert_eq!(u16_at(&metadata_bytes, 8), 2);
    assert_eq!(u16_at(&metadata_bytes, 10), 224);
    assert_eq!(u16_at(&metadata_bytes, 12), 21);
    assert_eq!(&metadata_bytes[14..22], &[2, 2, 1, 1, 64, 1, 2, 64]);
    assert_eq!(u16_at(&metadata_bytes, 22), 2);
    assert_eq!(&metadata_bytes[24..26], &[1, 1]);
    assert_eq!(u16_at(&metadata_bytes, 26), 16);
    assert_eq!(u32_at(&metadata_bytes, 28), 0);
    assert_eq!(u64_at(&metadata_bytes, 32), 7);
    assert_eq!(u32_at(&metadata_bytes, 44), 0);
    assert_eq!(u32_at(&metadata_bytes, 56), 16);
    assert_eq!(u32_at(&metadata_bytes, 60), 16);
    assert_eq!(metadata.format_version(), SELECTED_END_METADATA_VERSION_V2);
    assert_eq!(
        usize::from(metadata.record_bytes()),
        SELECTED_END_METADATA_BYTES_V2
    );
    assert_eq!(
        metadata.backend_version(),
        BackendVersion::SEARCH_SVE2_FIXED16_V2.0
    );
    assert_eq!(metadata.abi_kind(), SELECTED_END_ABI_KIND_V2);
    assert_eq!(metadata.output_kind(), SELECTED_END_OUTPUT_KIND_V2);
    assert_eq!(metadata.platform(), SELECTED_END_PLATFORM_LINUX_V2);
    assert_eq!(metadata.return_bits(), SELECTED_END_RETURN_BITS_V2);
    assert_eq!(metadata.abi_schema(), 2);
    assert_eq!(metadata.return_encoding(), 1);
    assert_eq!(
        metadata.window_contract(),
        SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2
    );
    assert_eq!(
        metadata.fixed_active_vector_bytes(),
        SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2
    );
    assert_eq!(metadata.features(), SELECTED_END_REQUIRED_FEATURES_V2);
    assert_eq!(metadata.entry_offset(), SELECTED_END_ENTRY_OFFSET_V2);
    assert_eq!(metadata.rodata_bytes(), SELECTED_END_LITERAL_BYTES_V2);
    assert_eq!(metadata.literal_bytes(), SELECTED_END_LITERAL_BYTES_V2);
    assert_eq!(
        metadata.source_identity(),
        image.source_identity().as_bytes()
    );
    assert_eq!(
        metadata.artifact_identity(),
        image.artifact_identity().as_bytes()
    );
    assert_eq!(
        inspection.payload().get(
            usize::try_from(metadata.rodata_offset()).expect("u32 offset")
                ..usize::try_from(metadata.payload_bytes()).expect("u32 extent")
        ),
        Some(image.rodata())
    );
}

#[test]
fn selected_end_v2_symbols_sections_visibility_and_c_abi_are_distinct() {
    let object = emit_selected_end_search_object_v2(
        &tag21_image(),
        binding(),
        SelectedEndObjectLimitsV2::default(),
    )
    .expect("SelectedEnd-v2 ELF");
    let symbols = object.exported_symbols();
    let identity_suffix = object.compile_identity().to_string();
    assert_eq!(identity_suffix.len(), EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2);
    assert_eq!(
        symbols.entry().as_str(),
        format!("{SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2}{identity_suffix}")
    );
    assert_eq!(
        symbols.payload().as_str(),
        format!("{SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2}{identity_suffix}")
    );
    assert_eq!(
        symbols.metadata().as_str(),
        format!("{SELECTED_END_METADATA_SYMBOL_PREFIX_V2}{identity_suffix}")
    );
    assert!(
        !symbols
            .entry()
            .as_str()
            .starts_with("fre_aot_search_entry_v1_")
    );
    assert!(contains_bytes(
        object.as_bytes(),
        b".text.fre_aot_search_selected_end_v2\0"
    ));
    assert!(contains_bytes(
        object.as_bytes(),
        b".rodata.fre_aot_search_selected_end_metadata_v2\0"
    ));

    let section_headers = usize::try_from(u64_at(object.as_bytes(), 40)).expect("section headers");
    let symbol_section = section_headers + 4 * 64;
    let symbol_offset =
        usize::try_from(u64_at(object.as_bytes(), symbol_section + 24)).expect("symbol offset");
    for (index, info, section) in [
        (2, ELF_SYMBOL_INFO_FUNCTION_V2, 1_u16),
        (3, ELF_SYMBOL_INFO_OBJECT_V2, 1_u16),
        (4, ELF_SYMBOL_INFO_OBJECT_V2, 2_u16),
    ] {
        let symbol = symbol_offset + index * 24;
        assert_eq!(object.as_bytes()[symbol + 4], info);
        assert_eq!(
            object.as_bytes()[symbol + 5],
            ELF_SYMBOL_VISIBILITY_HIDDEN_V2
        );
        assert_eq!(
            u16::from_le_bytes(
                object.as_bytes()[symbol + 6..symbol + 8]
                    .try_into()
                    .expect("symbol section")
            ),
            section
        );
    }

    let mut declarations = String::new();
    symbols
        .write_c_declarations(&mut declarations)
        .expect("String formatting");
    assert!(declarations.contains(&format!(
        "extern size_t {}(const uint8_t *haystack, size_t haystack_len, size_t window_start, size_t window_end);",
        symbols.entry()
    )));
    assert!(!declarations.contains("fre_aot_search_result_v1"));
    assert!(!C_SELECTED_END_HEADER_V2.contains("fre_aot_search_result_v1"));
    assert!(
        C_SELECTED_END_HEADER_V2.contains("typedef size_t (*fre_aot_search_selected_end_entry_v2)")
    );
    assert!(
        C_SELECTED_END_HEADER_V2
            .contains("sizeof(struct fre_aot_search_selected_end_metadata_v2) == 224")
    );
    assert_eq!(SELECTED_END_ARGUMENT_COUNT_V2, 4);
    assert_eq!(SELECTED_END_RETURN_REGISTER_V2, 0);
    assert_eq!(SELECTED_END_RESULT_SLOT_BYTES_V2, 0);
    assert_eq!(SELECTED_END_NO_MATCH_SENTINEL_V2, 0);
}

#[test]
fn selected_end_v2_compile_identity_zeroes_only_its_own_field() {
    let object = emit_selected_end_search_object_v2(
        &tag21_image(),
        binding(),
        SelectedEndObjectLimitsV2::default(),
    )
    .expect("SelectedEnd-v2 ELF");
    let metadata = object.metadata();
    let encoded = metadata.encode().expect("canonical metadata");
    let mut zeroed = encoded;
    zeroed[SELECTED_END_METADATA_COMPILE_IDENTITY_OFFSET_V2..].fill(0);
    assert_eq!(
        metadata.compile_identity().as_bytes(),
        &reference_compile_identity(&zeroed)
    );
    assert_ne!(
        metadata.compile_identity().as_bytes(),
        &reference_compile_identity(&encoded),
        "the claimed compile identity must not hash itself"
    );
}

#[test]
fn selected_end_v2_refuses_every_metadata_and_object_byte_mutation() {
    let object = emit_selected_end_search_object_v2(
        &tag21_image(),
        binding(),
        SelectedEndObjectLimitsV2::default(),
    )
    .expect("canonical SelectedEnd-v2 ELF");
    let metadata = object.metadata().encode().expect("canonical metadata");
    for index in 0..metadata.len() {
        let mut changed = metadata;
        changed[index] ^= 1;
        assert!(
            inspect_selected_end_metadata_v2(&changed).is_err(),
            "single-byte metadata mutation {index} survived strict inspection"
        );
    }
    for index in 0..object.as_bytes().len() {
        let mut changed = object.as_bytes().to_vec();
        changed[index] ^= 1;
        assert!(
            inspect_selected_end_search_object_v2(&changed, SelectedEndObjectLimitsV2::default())
                .is_err(),
            "single-byte object mutation {index} survived strict inspection"
        );
    }

    let mut payload_changed = object.as_bytes().to_vec();
    payload_changed[64] ^= 1;
    assert!(
        inspect_selected_end_search_object_v2(
            &payload_changed,
            SelectedEndObjectLimitsV2::default()
        )
        .is_err()
    );
    let metadata_offset = object
        .as_bytes()
        .windows(metadata.len())
        .position(|window| window == metadata)
        .expect("embedded metadata");
    let mut metadata_changed = object.as_bytes().to_vec();
    metadata_changed[metadata_offset] ^= 1;
    assert!(
        inspect_selected_end_search_object_v2(
            &metadata_changed,
            SelectedEndObjectLimitsV2::default()
        )
        .is_err()
    );
}

#[test]
fn selected_end_v2_refuses_v8_and_v1_v2_cross_admission() {
    let v8 = emit_selected_end_register_v2(
        &build_exact_literal::<SelectedEnd>(
            b"needle",
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("v8 SelectedEnd KIR"),
        SelectedEndRegisterBackendV2::AsimdV8,
        EmitLimits::default(),
    )
    .expect("sealed v8 ABI2 image");
    assert!(
        emit_selected_end_search_object_v2(&v8, binding(), SelectedEndObjectLimitsV2::default())
            .is_err()
    );

    let v2 = emit_selected_end_search_object_v2(
        &tag21_image(),
        binding(),
        SelectedEndObjectLimitsV2::default(),
    )
    .expect("SelectedEnd-v2 ELF");
    assert!(
        inspect_metadata_v1(&v2.metadata().encode().expect("SelectedEnd-v2 metadata")).is_err()
    );
    assert!(inspect_search_object_v1(v2.as_bytes(), ObjectLimitsV1::default()).is_err());

    let v1_image = emit_with_backend(
        &program(),
        SearchBackendPolicy::Sve2Fixed16V2,
        EmitLimits::default(),
    )
    .expect("Search-v1 image");
    let v1 = emit_search_object_v1(&v1_image, binding(), ObjectLimitsV1::default())
        .expect("Search-v1 ELF");
    let v1_metadata = v1.metadata().encode().expect("Search-v1 metadata");
    assert_eq!(v1_metadata.len(), METADATA_BYTES_V1);
    assert!(inspect_selected_end_metadata_v2(&v1_metadata).is_err());
    assert!(
        inspect_selected_end_search_object_v2(v1.as_bytes(), SelectedEndObjectLimitsV2::default())
            .is_err()
    );
}

#[test]
fn selected_end_v2_resource_limits_accept_exact_and_refuse_one_below() {
    let image = tag21_image();
    let baseline =
        emit_selected_end_search_object_v2(&image, binding(), SelectedEndObjectLimitsV2::default())
            .expect("baseline SelectedEnd-v2 ELF");
    let report = baseline.report();

    let cases = [
        (
            ElfObjectResource::ObjectBytes,
            u64::try_from(report.object_bytes).expect("object bytes"),
        ),
        (
            ElfObjectResource::PersistentBytes,
            u64::try_from(report.persistent_capacity_bytes).expect("persistent bytes"),
        ),
        (
            ElfObjectResource::PayloadBytes,
            u64::try_from(report.payload_bytes).expect("payload bytes"),
        ),
        (ElfObjectResource::Work, report.total_work),
    ];
    for (resource, exact) in cases {
        let mut limits = SelectedEndObjectLimitsV2::default();
        match resource {
            ElfObjectResource::ObjectBytes => limits.max_object_bytes = exact,
            ElfObjectResource::PersistentBytes => limits.max_persistent_bytes = exact,
            ElfObjectResource::PayloadBytes => limits.max_payload_bytes = exact,
            ElfObjectResource::Work => limits.max_work = exact,
        }
        emit_selected_end_search_object_v2(&image, binding(), limits)
            .expect("exact resource limit");

        let below = exact.checked_sub(1).expect("positive resource extent");
        match resource {
            ElfObjectResource::ObjectBytes => limits.max_object_bytes = below,
            ElfObjectResource::PersistentBytes => limits.max_persistent_bytes = below,
            ElfObjectResource::PayloadBytes => limits.max_payload_bytes = below,
            ElfObjectResource::Work => limits.max_work = below,
        }
        let error = emit_selected_end_search_object_v2(&image, binding(), limits)
            .expect_err("one-below resource limit");
        assert_limit(error, resource, below);
    }
}
