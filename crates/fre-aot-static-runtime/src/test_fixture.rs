use fre_aot_aarch64::{
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V2, AotCountCpuFeatures, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2,
};
use fre_aot_count_contract::{
    AOT_COMPILER_VERSION_V2, AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2, CALL_ABI_SCHEMA_V2,
    COUNT_ABI_KIND_V2, COUNT_OUTPUT_KIND_V2, COUNT_PLATFORM_MACOS_V2, ENTRY_OFFSET_V2,
    METADATA_BYTES_V2, METADATA_VERSION_V2, STATIC_COUNT_EXPECTATION_BYTES_V2,
    STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2, STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2,
    STATUS_BITS_V2,
};
use sha2::{Digest, Sha256};

use crate::support::QualifiedStaticCountRowV2;

const EXPECTATION_IDENTITY_DOMAIN_V2: &[u8] = b"FRE-AOT-STATIC-COUNT-EXPECTATION-IDENTITY\0\x02";

pub(crate) struct StaticFixtureV2 {
    pub(crate) expectation: [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
    pub(crate) metadata: [u8; METADATA_BYTES_V2],
    pub(crate) row: QualifiedStaticCountRowV2,
}

#[allow(
    clippy::too_many_lines,
    reason = "one literal wire builder keeps every reviewed Count-v2 field and offset adjacent"
)]
pub(crate) fn static_fixture_v2() -> StaticFixtureV2 {
    let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2[0];
    let manifest = [1; 32];
    let policy = [2; 32];
    let semantic = [3; 32];
    let planning = [4; 32];
    let live_literal = [5; 32];
    let program = [6; 32];
    let image = [7; 32];
    let binding = [8; 32];
    let compile = [9; 32];
    let object = [10; 32];
    let receipt = [11; 32];
    let resource = [12; 32];
    let literal_bytes = 6_u32;

    let mut metadata = [0_u8; METADATA_BYTES_V2];
    let mut cursor = 0_usize;
    put(&mut metadata, &mut cursor, b"FREOM64\x02");
    put(
        &mut metadata,
        &mut cursor,
        &METADATA_VERSION_V2.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &u16::try_from(METADATA_BYTES_V2)
            .expect("fixed metadata bytes fit u16")
            .to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &support.backend_version.0.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &support.algorithm_version.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &support.kir_semantics_version.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &support.kir_abi_version.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &CALL_ABI_SCHEMA_V2.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &support.max_literal_bytes.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &[
            COUNT_ABI_KIND_V2,
            COUNT_OUTPUT_KIND_V2,
            support.architecture,
            u8::from(support.little_endian),
            support.pointer_width,
            support.target_abi,
            COUNT_PLATFORM_MACOS_V2,
            STATUS_BITS_V2,
        ],
    );
    put(
        &mut metadata,
        &mut cursor,
        &AotCountCpuFeatures::ASIMD.bits().to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &support.allowed_features.bits().to_le_bytes(),
    );
    put(&mut metadata, &mut cursor, &16_u32.to_le_bytes());
    put(&mut metadata, &mut cursor, &ENTRY_OFFSET_V2.to_le_bytes());
    put(&mut metadata, &mut cursor, &4_u32.to_le_bytes());
    put(&mut metadata, &mut cursor, &16_u32.to_le_bytes());
    put(&mut metadata, &mut cursor, &0_u32.to_le_bytes());
    put(&mut metadata, &mut cursor, &literal_bytes.to_le_bytes());
    for identity in [program, image, binding, [13; 32], compile] {
        put(&mut metadata, &mut cursor, &identity);
    }
    assert_eq!(cursor, METADATA_BYTES_V2);

    let mut expectation = [0_u8; STATIC_COUNT_EXPECTATION_BYTES_V2];
    cursor = 0;
    put(&mut expectation, &mut cursor, b"FRESCEX\x02");
    put(
        &mut expectation,
        &mut cursor,
        &AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2.to_le_bytes(),
    );
    put(
        &mut expectation,
        &mut cursor,
        &AOT_COMPILER_VERSION_V2.to_le_bytes(),
    );
    put(
        &mut expectation,
        &mut cursor,
        &u32::try_from(STATIC_COUNT_EXPECTATION_BYTES_V2)
            .expect("fixed expectation bytes fit u32")
            .to_le_bytes(),
    );
    for identity in [
        manifest,
        policy,
        semantic,
        planning,
        live_literal,
        program,
        image,
        binding,
        compile,
        object,
        receipt,
        resource,
    ] {
        put(&mut expectation, &mut cursor, &identity);
    }
    put(&mut expectation, &mut cursor, &literal_bytes.to_le_bytes());
    put(
        &mut expectation,
        &mut cursor,
        &u16::try_from(METADATA_BYTES_V2)
            .expect("fixed metadata bytes fit u16")
            .to_le_bytes(),
    );
    put(
        &mut expectation,
        &mut cursor,
        &AOT_COUNT_IMAGE_SCHEMA_VERSION_V2.to_le_bytes(),
    );
    assert_eq!(cursor, STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2);
    put(&mut expectation, &mut cursor, &metadata);
    assert_eq!(cursor, STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2);
    let mut hasher = Sha256::new();
    hasher.update(EXPECTATION_IDENTITY_DOMAIN_V2);
    hasher.update(&expectation[..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2]);
    put(&mut expectation, &mut cursor, &hasher.finalize());
    assert_eq!(cursor, STATIC_COUNT_EXPECTATION_BYTES_V2);
    let expectation_identity: [u8; 32] = expectation
        .get(STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2..)
        .expect("expectation identity range")
        .try_into()
        .expect("fixed expectation identity");

    StaticFixtureV2 {
        expectation,
        metadata,
        row: QualifiedStaticCountRowV2::test_only(
            0,
            compile,
            expectation_identity,
            object,
            receipt,
            resource,
        ),
    }
}

fn put<const BYTES: usize>(destination: &mut [u8; BYTES], cursor: &mut usize, value: &[u8]) {
    let end = cursor
        .checked_add(value.len())
        .expect("test fixture offset");
    destination
        .get_mut(*cursor..end)
        .expect("test fixture destination")
        .copy_from_slice(value);
    *cursor = end;
}
