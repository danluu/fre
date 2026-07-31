use fre_aot_search_contract::{
    AOT_SEARCH_COMPILER_VERSION_V1, AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1,
    SEARCH_ARCHITECTURE_AARCH64_V1, SEARCH_BACKEND_VERSION_V1, SEARCH_CALL_ABI_SCHEMA_V1,
    SEARCH_DEFAULT_END_ANCHOR_V1, SEARCH_DEFAULT_START_ANCHOR_V1, SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
    SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1, SEARCH_LITTLE_ENDIAN_V1, SEARCH_METADATA_BYTES_V1,
    SEARCH_METADATA_VERSION_V1, SEARCH_PLATFORM_MACOS_V1, SEARCH_POINTER_WIDTH_V1,
    SEARCH_REQUIRED_ASIMD_FEATURES_V1, SEARCH_SPAN_OUTPUT_KIND_V1, SEARCH_STATUS_BITS_V1,
    SEARCH_TARGET_ABI_AAPCS64_V1, STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1, StaticSearchSpanExpectationV1,
    compute_static_search_span_expectation_identity_v1,
};

use crate::search_support::SourceQualifiedStaticSearchSpanRowV1;

const FIXTURE_COMPILE_IDENTITY_V1: [u8; 32] = [
    0xb2, 0x87, 0xe0, 0xda, 0xcb, 0x82, 0x82, 0x4e, 0xcf, 0x8f, 0x0d, 0xe4, 0x5b, 0xf7, 0x1f, 0x0c,
    0x8d, 0x4e, 0x0e, 0x58, 0xb8, 0xc0, 0xcd, 0x16, 0xf4, 0x95, 0xc0, 0x7a, 0x77, 0x57, 0x9d, 0x93,
];

pub(crate) struct StaticSearchSpanFixtureV1 {
    pub(crate) expectation: StaticSearchSpanExpectationV1,
    pub(crate) metadata: [u8; SEARCH_METADATA_BYTES_V1],
    pub(crate) row: SourceQualifiedStaticSearchSpanRowV1,
}

#[allow(
    clippy::too_many_lines,
    reason = "one literal wire builder keeps every reviewed Search field and offset adjacent"
)]
pub(crate) fn static_search_span_fixture_v1() -> StaticSearchSpanFixtureV1 {
    let manifest = [0x51; 32];
    let semantic = [0x52; 32];
    let literal = [0x53; 32];
    let kir = [0x11; 32];
    let artifact = [0x22; 32];
    let binding = [0x33; 32];
    let object = [0x58; 32];
    let receipt = [0x59; 32];
    let payload = [0x44; 32];
    let live_literal_bytes = 16_u32;

    let mut metadata = [0_u8; SEARCH_METADATA_BYTES_V1];
    let mut cursor = 0_usize;
    put(&mut metadata, &mut cursor, b"FREOM64\x01");
    put(
        &mut metadata,
        &mut cursor,
        &SEARCH_METADATA_VERSION_V1.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &u16::try_from(SEARCH_METADATA_BYTES_V1)
            .expect("fixed metadata width")
            .to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &SEARCH_BACKEND_VERSION_V1.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &[
            1,
            SEARCH_SPAN_OUTPUT_KIND_V1,
            SEARCH_ARCHITECTURE_AARCH64_V1,
            SEARCH_LITTLE_ENDIAN_V1,
            SEARCH_POINTER_WIDTH_V1,
            SEARCH_TARGET_ABI_AAPCS64_V1,
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_STATUS_BITS_V1,
        ],
    );
    put(
        &mut metadata,
        &mut cursor,
        &SEARCH_CALL_ABI_SCHEMA_V1.to_le_bytes(),
    );
    put(
        &mut metadata,
        &mut cursor,
        &SEARCH_REQUIRED_ASIMD_FEATURES_V1.to_le_bytes(),
    );
    put(&mut metadata, &mut cursor, &256_u32.to_le_bytes());
    put(&mut metadata, &mut cursor, &0_u32.to_le_bytes());
    put(&mut metadata, &mut cursor, &240_u32.to_le_bytes());
    put(&mut metadata, &mut cursor, &240_u32.to_le_bytes());
    put(
        &mut metadata,
        &mut cursor,
        &live_literal_bytes.to_le_bytes(),
    );
    put(&mut metadata, &mut cursor, &0_u32.to_le_bytes());
    for identity in [kir, artifact, binding, payload, FIXTURE_COMPILE_IDENTITY_V1] {
        put(&mut metadata, &mut cursor, &identity);
    }
    assert_eq!(cursor, SEARCH_METADATA_BYTES_V1);

    let mut expectation = [0_u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];
    cursor = 0;
    put(&mut expectation, &mut cursor, b"FRESSPX\x01");
    put(
        &mut expectation,
        &mut cursor,
        &AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1.to_le_bytes(),
    );
    put(
        &mut expectation,
        &mut cursor,
        &AOT_SEARCH_COMPILER_VERSION_V1.to_le_bytes(),
    );
    put(
        &mut expectation,
        &mut cursor,
        &u32::try_from(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
            .expect("fixed expectation width")
            .to_le_bytes(),
    );
    put(
        &mut expectation,
        &mut cursor,
        &u16::try_from(SEARCH_METADATA_BYTES_V1)
            .expect("fixed metadata width")
            .to_le_bytes(),
    );
    for value in [
        SEARCH_METADATA_VERSION_V1,
        SEARCH_BACKEND_VERSION_V1,
        SEARCH_CALL_ABI_SCHEMA_V1,
        SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1,
    ] {
        put(&mut expectation, &mut cursor, &value.to_le_bytes());
    }
    put(
        &mut expectation,
        &mut cursor,
        &[
            SEARCH_SPAN_OUTPUT_KIND_V1,
            SEARCH_DEFAULT_START_ANCHOR_V1,
            SEARCH_DEFAULT_END_ANCHOR_V1,
            SEARCH_ARCHITECTURE_AARCH64_V1,
            SEARCH_LITTLE_ENDIAN_V1,
            SEARCH_POINTER_WIDTH_V1,
            SEARCH_TARGET_ABI_AAPCS64_V1,
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_STATUS_BITS_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        ],
    );
    put(
        &mut expectation,
        &mut cursor,
        &SEARCH_REQUIRED_ASIMD_FEATURES_V1.to_le_bytes(),
    );
    put(
        &mut expectation,
        &mut cursor,
        &live_literal_bytes.to_le_bytes(),
    );
    for identity in [
        manifest,
        semantic,
        literal,
        kir,
        artifact,
        binding,
        FIXTURE_COMPILE_IDENTITY_V1,
        object,
        receipt,
    ] {
        put(&mut expectation, &mut cursor, &identity);
    }
    assert_eq!(cursor, STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1);
    put(&mut expectation, &mut cursor, &metadata);
    assert_eq!(cursor, STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1);
    let body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = expectation
        .get(..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1)
        .and_then(|bytes| bytes.try_into().ok())
        .expect("fixed expectation identity body");
    let expectation_identity = compute_static_search_span_expectation_identity_v1(body);
    put(&mut expectation, &mut cursor, &expectation_identity);
    assert_eq!(cursor, STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1);

    StaticSearchSpanFixtureV1 {
        expectation,
        metadata,
        row: SourceQualifiedStaticSearchSpanRowV1::test_only(
            0,
            live_literal_bytes,
            manifest,
            semantic,
            literal,
            kir,
            artifact,
            binding,
            FIXTURE_COMPILE_IDENTITY_V1,
            object,
            receipt,
            expectation_identity,
            payload,
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
