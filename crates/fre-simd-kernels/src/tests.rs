use super::*;
use fre_target_features::ArmCpuIdentity;
use std::{
    fs::OpenOptions,
    io::{self, Write as _},
    path::Path,
};

const GENERIC_SVE2_VARIANT: &str = "ascii-byte-set.mask32.sve2.v1";
const NEOVERSE_V3_SVE2_VARIANT: &str = "ascii-byte-set.mask32.sve2.arm-41-d84.v1";

fn expected_sve2_variant(tuning: TuningClass) -> &'static str {
    if is_neoverse_v3(tuning) {
        NEOVERSE_V3_SVE2_VARIANT
    } else {
        GENERIC_SVE2_VARIANT
    }
}

fn singleton(byte: u8) -> AsciiByteSet {
    assert!(byte.is_ascii());
    let mut words = [0_u64; 2];
    let word = usize::from(byte >> 6);
    words[word] = 1_u64 << (byte & 0x3f);
    AsciiByteSet::from_words(words)
}

fn reference_16(set: AsciiByteSet, bytes: &[u8; ASCII_NARROW_BYTES]) -> AsciiMasks16 {
    let mut ascii = 0_u16;
    let mut members = 0_u16;
    for (lane, &byte) in bytes.iter().enumerate() {
        let bit = 1_u16 << u32::try_from(lane).unwrap();
        if byte.is_ascii() {
            ascii |= bit;
        }
        if set.contains(byte) {
            members |= bit;
        }
    }
    AsciiMasks16::new(ascii, members)
}

fn reference_32(set: AsciiByteSet, bytes: &[u8; ASCII_WIDE_BYTES]) -> AsciiMasks32 {
    let mut ascii = 0_u32;
    let mut members = 0_u32;
    for (lane, &byte) in bytes.iter().enumerate() {
        let bit = 1_u32 << u32::try_from(lane).unwrap();
        if byte.is_ascii() {
            ascii |= bit;
        }
        if set.contains(byte) {
            members |= bit;
        }
    }
    AsciiMasks32::new(ascii, members)
}

fn assert_matches_reference(
    classifier: &AsciiByteSetClassifier,
    narrow: &[u8; ASCII_NARROW_BYTES],
    wide: &[u8; ASCII_WIDE_BYTES],
) {
    assert_eq!(
        classifier.classify_16(narrow),
        reference_16(classifier.set(), narrow)
    );
    assert_eq!(
        classifier.classify_32(wide),
        reference_32(classifier.set(), wide)
    );
    assert_eq!(
        classifier.count_16(narrow),
        reference_16(classifier.set(), narrow).member_count()
    );
    assert_eq!(
        classifier.count_32(wide),
        reference_32(classifier.set(), wide).member_count()
    );
}

fn next_random(state: &mut u64) -> u64 {
    let mut value = *state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state = value;
    value
}

#[test]
fn neoverse_v3_tuning_matches_exact_implementer_and_part_across_revisions() {
    let identity = |implementer, part, variant, revision| TuningClass::ArmServer {
        cpu: Some(ArmCpuIdentity {
            implementer,
            part,
            variant,
            revision,
        }),
    };
    let neoverse_v3 = identity(0x41, 0xd84, None, None);
    assert!(is_neoverse_v3(neoverse_v3));
    assert!(is_neoverse_v3(identity(
        0x41,
        0xd84,
        Some(u8::MAX),
        Some(u8::MAX)
    )));
    assert!(!is_neoverse_v3(identity(0x41, 0xd40, None, None)));
    assert!(!is_neoverse_v3(identity(0x42, 0xd84, None, None)));
    assert!(!is_neoverse_v3(TuningClass::ArmServer { cpu: None }));
    assert!(!is_neoverse_v3(TuningClass::AppleSilicon {
        cpu_family: Some(u32::MAX),
    }));
    assert!(!is_neoverse_v3(TuningClass::Generic));
    assert_eq!(expected_sve2_variant(neoverse_v3), NEOVERSE_V3_SVE2_VARIANT);
    assert_eq!(
        expected_sve2_variant(TuningClass::Generic),
        GENERIC_SVE2_VARIANT
    );
}

#[test]
fn byte_set_words_and_membership_cover_the_entire_byte_domain() {
    assert_eq!(AsciiByteSet::EMPTY.words(), [0, 0]);
    assert_eq!(AsciiByteSet::ALL.words(), [u64::MAX, u64::MAX]);

    for selected in 0_u8..=0x7f {
        let set = singleton(selected);
        for byte in 0_u8..=u8::MAX {
            assert_eq!(
                set.contains(byte),
                byte == selected,
                "selected={selected:#04x} byte={byte:#04x}"
            );
        }
    }
    for byte in 0_u8..=u8::MAX {
        assert_eq!(AsciiByteSet::ALL.contains(byte), byte.is_ascii());
        assert!(!AsciiByteSet::EMPTY.contains(byte));
    }
}

#[test]
fn nibble_columns_round_trip_dense_sparse_and_random_sets() {
    let mut sets = vec![
        AsciiByteSet::EMPTY,
        AsciiByteSet::ALL,
        AsciiByteSet::from_words([0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555]),
        AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]),
    ];
    let mut state = 0x4d59_5df4_d0f3_3173;
    for _ in 0..128 {
        sets.push(AsciiByteSet::from_words([
            next_random(&mut state),
            next_random(&mut state),
        ]));
    }

    for set in sets {
        let columns = set.nibble_columns();
        for byte in 0_u8..=u8::MAX {
            let from_columns = byte.is_ascii()
                && columns[usize::from(byte & 0x0f)] & HIGH_NIBBLE_BITS[usize::from(byte >> 4)]
                    != 0;
            assert_eq!(from_columns, set.contains(byte));
        }
    }
}

#[test]
fn scalar_oracle_maps_every_ascii_bit_and_every_lane() {
    for selected in 0_u8..=0x7f {
        let set = singleton(selected);
        let columns = set.nibble_columns();
        let other = selected ^ 0x7f;
        for lane in 0..ASCII_NARROW_BYTES {
            let mut bytes = [other; ASCII_NARROW_BYTES];
            bytes[lane] = selected;
            assert_eq!(
                scalar::classify_16(&columns, &bytes),
                reference_16(set, &bytes),
                "selected={selected:#04x} lane={lane}"
            );
        }
    }
}

#[test]
fn arbitrary_bytes_and_sets_match_the_scalar_definition() {
    let mut state = 0x8a5c_97e4_2d31_b607;
    for _ in 0..20_000 {
        let set = AsciiByteSet::from_words([next_random(&mut state), next_random(&mut state)]);
        let narrow = core::array::from_fn(|_| next_random(&mut state).to_le_bytes()[0]);
        let wide = core::array::from_fn(|_| next_random(&mut state).to_le_bytes()[0]);
        let columns = set.nibble_columns();
        assert_eq!(
            scalar::classify_16(&columns, &narrow),
            reference_16(set, &narrow)
        );
        assert_eq!(
            scalar::classify_32(&columns, &wide),
            reference_32(set, &wide)
        );
    }
}

#[test]
fn portable_policy_forces_scalar_and_split_narrow() {
    let classifier = AsciiByteSetClassifier::with_policy(
        AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]),
        DispatchPolicy::Portable,
    )
    .unwrap();
    assert_eq!(
        classifier.selection().narrow().variant_id,
        "ascii-byte-set.mask16.scalar.v1"
    );
    assert_eq!(
        classifier.selection().wide().variant_id,
        "ascii-byte-set.mask32.split16.v1"
    );
    assert!(classifier.selection().narrow().required.is_empty());
    assert!(classifier.selection().wide().required.is_empty());
    assert_eq!(
        classifier.selection().wide().delegate_variant_id,
        Some("ascii-byte-set.mask16.scalar.v1")
    );
    assert_eq!(
        classifier.selection().wide().vector,
        classifier.selection().narrow().vector
    );

    let narrow = core::array::from_fn(|lane| u8::try_from(lane * 17).unwrap());
    let wide = core::array::from_fn(|lane| u8::try_from(lane * 7).unwrap());
    assert_matches_reference(&classifier, &narrow, &wide);
}

#[test]
fn auto_policy_and_clones_keep_stable_receipts_across_threads() {
    let classifier = AsciiByteSetClassifier::new(AsciiByteSet::ALL);
    let expected = classifier.selection();
    let clone = classifier;
    assert_eq!(clone.selection(), expected);
    let observed = std::thread::spawn(move || {
        let bytes = [b'x'; ASCII_WIDE_BYTES];
        assert_eq!(clone.count_32(&bytes), 32);
        clone.selection()
    })
    .join()
    .unwrap();
    assert_eq!(observed, expected);
}

#[test]
fn host_auto_selection_receipt_matches_usable_features() {
    let classifier = AsciiByteSetClassifier::new(AsciiByteSet::ALL);
    let selection = classifier.selection();
    let usable = host().usable();

    #[cfg(target_arch = "x86_64")]
    {
        let expected_narrow = if usable.contains(Feature::X86Ssse3) {
            "ascii-byte-set.mask16.ssse3.v1"
        } else if usable.contains(Feature::X86Sse2) {
            "ascii-byte-set.mask16.sse2.v1"
        } else {
            "ascii-byte-set.mask16.scalar.v1"
        };
        let expected_wide = if usable.contains(Feature::X86Avx2) {
            "ascii-byte-set.mask32.avx2.v1"
        } else if usable.contains_all(X86_AVX512_MASK_FEATURES) {
            "ascii-byte-set.mask32.avx512f-bw-vl.v1"
        } else {
            "ascii-byte-set.mask32.split16.v1"
        };
        assert_eq!(selection.narrow().variant_id, expected_narrow);
        assert_eq!(selection.wide().variant_id, expected_wide);
    }

    #[cfg(target_arch = "aarch64")]
    {
        let expected_narrow = if usable.contains(Feature::ArmNeon) {
            "ascii-byte-set.mask16.neon.v1"
        } else {
            "ascii-byte-set.mask16.scalar.v1"
        };
        assert_eq!(selection.narrow().variant_id, expected_narrow);

        #[cfg(all(target_os = "linux", target_endian = "little"))]
        let expected_wide = if is_neoverse_v3(host().tuning())
            && usable.contains(Feature::ArmSve)
            && usable.contains(Feature::ArmSve2)
        {
            NEOVERSE_V3_SVE2_VARIANT
        } else if usable.contains(Feature::ArmNeon) {
            "ascii-byte-set.mask32.split16-neon.v1"
        } else if usable.contains(Feature::ArmSve) && usable.contains(Feature::ArmSve2) {
            GENERIC_SVE2_VARIANT
        } else {
            "ascii-byte-set.mask32.split16.v1"
        };
        #[cfg(not(all(target_os = "linux", target_endian = "little")))]
        let expected_wide = "ascii-byte-set.mask32.split16.v1";
        assert_eq!(selection.wide().variant_id, expected_wide);
        #[cfg(all(target_os = "linux", target_endian = "little"))]
        if expected_wide == NEOVERSE_V3_SVE2_VARIANT {
            assert_eq!(selection.wide().delegate_variant_id, None);
            assert_eq!(
                selection.wide().required,
                FeatureSet::EMPTY
                    .with(Feature::ArmSve)
                    .with(Feature::ArmSve2)
            );
            assert_eq!(selection.wide().vector, VectorKind::Scalable);
        }
    }

    eprintln!(
        "SIMD_SELECTION narrow={} wide={} delegate={:?} usable={usable:?}",
        selection.narrow().variant_id,
        selection.wide().variant_id,
        selection.wide().delegate_variant_id
    );
}

#[test]
fn explicit_host_snapshot_matches_the_convenience_wrapper_exactly() {
    let set = AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]);
    let policy = DispatchPolicy::Auto;
    let wrapped = AsciiByteSetClassifier::with_policy(set, policy).unwrap();
    let context = SimdDispatchContext::capture();
    let explicit =
        AsciiByteSetClassifier::with_capabilities(set, context.capabilities(), policy).unwrap();
    let contextual = context.ascii_byte_set_classifier(set, policy).unwrap();

    assert_eq!(explicit.selection(), wrapped.selection());
    assert_eq!(contextual.selection(), wrapped.selection());
    let narrow = core::array::from_fn(|lane| u8::try_from(lane * 13).unwrap());
    let wide = core::array::from_fn(|lane| u8::try_from(lane * 7).unwrap());
    assert_eq!(explicit.classify_16(&narrow), wrapped.classify_16(&narrow));
    assert_eq!(explicit.classify_32(&wide), wrapped.classify_32(&wide));
    assert_eq!(
        contextual.classify_16(&narrow),
        wrapped.classify_16(&narrow)
    );
    assert_eq!(contextual.classify_32(&wide), wrapped.classify_32(&wide));
}

#[test]
fn requiring_an_absent_cross_architecture_feature_fails_before_execution() {
    let required = if cfg!(target_arch = "x86_64") {
        FeatureSet::of(Feature::ArmNeon)
    } else {
        FeatureSet::of(Feature::X86Avx2)
    };
    let error =
        AsciiByteSetClassifier::with_policy(AsciiByteSet::ALL, DispatchPolicy::Require(required))
            .unwrap_err();
    assert_eq!(error.required, required);
    assert!(!error.usable.contains_all(required));
}

#[test]
fn masks_preserve_lane_order_prefixes_and_full_width_boundaries() {
    let narrow_classifier =
        AsciiByteSetClassifier::with_policy(AsciiByteSet::ALL, DispatchPolicy::Portable).unwrap();
    for boundary in 0..ASCII_NARROW_BYTES {
        let mut bytes = [b'a'; ASCII_NARROW_BYTES];
        bytes[boundary] = 0x80;
        let masks = narrow_classifier.classify_16(&bytes);
        let expected_ascii = !(1_u16 << u32::try_from(boundary).unwrap());
        assert_eq!(masks.ascii_mask(), expected_ascii);
        assert_eq!(masks.member_mask(), expected_ascii);
        assert_eq!(masks.leading_ascii_len(), u8::try_from(boundary).unwrap());
        assert_eq!(
            masks.ascii_prefix_member_mask(),
            low_u16_mask(u32::try_from(boundary).unwrap())
        );
    }
    let all_narrow = narrow_classifier.classify_16(&[b'a'; ASCII_NARROW_BYTES]);
    assert_eq!(all_narrow.leading_ascii_len(), 16);
    assert_eq!(all_narrow.ascii_prefix_member_mask(), u16::MAX);

    for boundary in 0..ASCII_WIDE_BYTES {
        let mut bytes = [b'a'; ASCII_WIDE_BYTES];
        bytes[boundary] = 0xff;
        let masks = narrow_classifier.classify_32(&bytes);
        let expected_ascii = !(1_u32 << u32::try_from(boundary).unwrap());
        assert_eq!(masks.ascii_mask(), expected_ascii);
        assert_eq!(masks.member_mask(), expected_ascii);
        assert_eq!(masks.leading_ascii_len(), u8::try_from(boundary).unwrap());
        assert_eq!(
            masks.ascii_prefix_member_mask(),
            low_u32_mask(u32::try_from(boundary).unwrap())
        );
    }
    let all_wide = narrow_classifier.classify_32(&[b'a'; ASCII_WIDE_BYTES]);
    assert_eq!(all_wide.leading_ascii_len(), 32);
    assert_eq!(all_wide.ascii_prefix_member_mask(), u32::MAX);
}

#[test]
fn non_ascii_inputs_never_match_even_for_the_full_set() {
    let classifier = AsciiByteSetClassifier::new(AsciiByteSet::ALL);
    for byte in 0x80_u8..=u8::MAX {
        let narrow = [byte; ASCII_NARROW_BYTES];
        let wide = [byte; ASCII_WIDE_BYTES];
        assert_eq!(classifier.classify_16(&narrow).ascii_mask(), 0);
        assert_eq!(classifier.classify_16(&narrow).member_mask(), 0);
        assert_eq!(classifier.classify_32(&wide).ascii_mask(), 0);
        assert_eq!(classifier.classify_32(&wide).member_mask(), 0);
    }
}

#[test]
fn fixed_array_references_work_at_every_common_input_alignment() {
    let classifier = AsciiByteSetClassifier::new(AsciiByteSet::from_words([
        0x1020_4080_0102_0408,
        0x8040_2010_0804_0201,
    ]));
    for offset in 0..64 {
        let mut narrow_storage = vec![0_u8; offset + ASCII_NARROW_BYTES];
        for (lane, byte) in narrow_storage[offset..].iter_mut().enumerate() {
            *byte = u8::try_from((offset + lane * 29) & 0xff).unwrap();
        }
        let narrow: &[u8; ASCII_NARROW_BYTES] = narrow_storage[offset..offset + ASCII_NARROW_BYTES]
            .try_into()
            .unwrap();

        let mut wide_storage = vec![0_u8; offset + ASCII_WIDE_BYTES];
        for (lane, byte) in wide_storage[offset..].iter_mut().enumerate() {
            *byte = u8::try_from((offset + lane * 43) & 0xff).unwrap();
        }
        let wide: &[u8; ASCII_WIDE_BYTES] = wide_storage[offset..offset + ASCII_WIDE_BYTES]
            .try_into()
            .unwrap();
        assert_matches_reference(&classifier, narrow, wide);
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
#[allow(
    unsafe_code,
    reason = "the test gates the private NEON leaf on the same OS-usable host feature used by production dispatch"
)]
fn forced_neon_and_direct_leaf_match_scalar() {
    if !host().usable().contains(Feature::ArmNeon) {
        return;
    }
    let classifier = AsciiByteSetClassifier::with_policy(
        AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]),
        DispatchPolicy::AllowOnly(FeatureSet::of(Feature::ArmNeon)),
    )
    .unwrap();
    assert_eq!(
        classifier.selection().narrow().variant_id,
        "ascii-byte-set.mask16.neon.v1"
    );
    #[cfg(all(target_os = "linux", target_endian = "little"))]
    let expected_wide_variant = "ascii-byte-set.mask32.split16-neon.v1";
    #[cfg(not(all(target_os = "linux", target_endian = "little")))]
    let expected_wide_variant = "ascii-byte-set.mask32.split16.v1";
    assert_eq!(
        classifier.selection().wide().variant_id,
        expected_wide_variant
    );
    assert_eq!(
        classifier.selection().wide().delegate_variant_id,
        Some("ascii-byte-set.mask16.neon.v1")
    );
    assert_eq!(
        classifier.selection().wide().required,
        FeatureSet::of(Feature::ArmNeon)
    );
    assert_eq!(
        classifier.selection().wide().vector,
        classifier.selection().narrow().vector
    );
    assert_eq!(
        classifier.selection().narrow().required,
        FeatureSet::of(Feature::ArmNeon)
    );

    let columns = classifier.set().nibble_columns();
    for offset in 0_u8..=u8::MAX {
        let bytes = core::array::from_fn(|lane| {
            offset.wrapping_add(u8::try_from(lane).unwrap().wrapping_mul(29))
        });
        // SAFETY: this test returned unless the immutable host snapshot proved
        // NEON OS-usable.
        let direct = unsafe { aarch64::classify_16_neon(&columns, &bytes) };
        assert_eq!(direct, scalar::classify_16(&columns, &bytes));
        assert_eq!(classifier.classify_16(&bytes), direct);
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
#[test]
#[allow(
    unsafe_code,
    reason = "the test gates the private SVE2 assembly leaf on the same OS-usable host features used by production dispatch"
)]
fn forced_sve2_vl_agnostic_leaf_matches_scalar_and_tuned_auto_policy() {
    let required = FeatureSet::EMPTY
        .with(Feature::ArmSve)
        .with(Feature::ArmSve2);
    if !host().usable().contains_all(required) {
        return;
    }

    // Removing NEON from the policy facts qualifies SVE2 without forging a
    // feature. A real Neoverse V3 tuning identity may still select its tuned
    // entry because tuning changes preference, never instruction authority.
    let set = AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]);
    let classifier =
        AsciiByteSetClassifier::with_policy(set, DispatchPolicy::AllowOnly(required)).unwrap();
    assert_eq!(
        classifier.selection().narrow().variant_id,
        "ascii-byte-set.mask16.scalar.v1"
    );
    assert_eq!(
        classifier.selection().wide().variant_id,
        expected_sve2_variant(host().tuning())
    );
    assert_eq!(classifier.selection().wide().delegate_variant_id, None);
    assert_eq!(classifier.selection().wide().required, required);
    assert_eq!(classifier.selection().wide().vector, VectorKind::Scalable);

    let automatic = AsciiByteSetClassifier::new(set);
    if is_neoverse_v3(host().tuning()) {
        assert_eq!(
            automatic.selection().wide().variant_id,
            NEOVERSE_V3_SVE2_VARIANT
        );
        assert_eq!(automatic.selection().wide().delegate_variant_id, None);
        assert_eq!(automatic.selection().wide().required, required);
        assert_eq!(automatic.selection().wide().vector, VectorKind::Scalable);
    } else if host().usable().contains(Feature::ArmNeon) {
        assert_eq!(
            automatic.selection().wide().variant_id,
            "ascii-byte-set.mask32.split16-neon.v1"
        );
        assert_eq!(
            automatic.selection().wide().delegate_variant_id,
            Some("ascii-byte-set.mask16.neon.v1")
        );
    } else {
        assert_eq!(
            automatic.selection().wide().variant_id,
            GENERIC_SVE2_VARIANT
        );
        assert_eq!(automatic.selection().wide().delegate_variant_id, None);
    }

    let columns = set.nibble_columns();
    for selected in 0_u8..=0x7f {
        let selected_set = singleton(selected);
        let selected_columns = selected_set.nibble_columns();
        for lane in [0, 15, 16, 31] {
            let mut bytes = [0xff; ASCII_WIDE_BYTES];
            bytes[lane] = selected;
            // SAFETY: this test returned unless the immutable host snapshot
            // proved both SVE and SVE2 OS-usable.
            let direct = unsafe { aarch64_sve2::classify_32_sve2(&selected_columns, &bytes) };
            assert_eq!(direct, scalar::classify_32(&selected_columns, &bytes));
            assert_eq!(direct.member_mask(), 1_u32 << lane);
        }
    }

    let mut state = 0x51ed_270b_95ac_728d;
    for _ in 0..20_000 {
        let bytes = core::array::from_fn(|_| next_random(&mut state).to_le_bytes()[0]);
        // SAFETY: this test returned unless the immutable host snapshot proved
        // both SVE and SVE2 OS-usable.
        let direct = unsafe { aarch64_sve2::classify_32_sve2(&columns, &bytes) };
        assert_eq!(direct, scalar::classify_32(&columns, &bytes));
        assert_eq!(classifier.classify_32(&bytes), direct);
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
fn measure_classifier(
    classifier: &AsciiByteSetClassifier,
    inputs: &[[u8; ASCII_WIDE_BYTES]],
    iterations: u32,
) -> f64 {
    assert!(
        inputs.len().is_power_of_two(),
        "the benchmark input bank must be a nonempty power of two"
    );
    let input_mask = inputs
        .len()
        .checked_sub(1)
        .expect("a power-of-two input bank is nonempty");
    let started = std::time::Instant::now();
    let mut checksum = 0_u64;
    for iteration in 0..iterations {
        let input_index = usize::try_from(std::hint::black_box(iteration))
            .expect("u32 fits in usize on supported targets")
            & input_mask;
        let input = &inputs[input_index];
        let masks = std::hint::black_box(classifier).classify_32(std::hint::black_box(input));
        checksum ^= u64::from(masks.member_mask()) | (u64::from(masks.ascii_mask()) << u32::BITS);
    }
    std::hint::black_box(checksum);
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / f64::from(iterations)
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
#[test]
#[ignore = "native qualification benchmark; run pinned on an SVE2 host in release mode"]
fn benchmark_sve2_against_split_neon() {
    let sve2 = FeatureSet::EMPTY
        .with(Feature::ArmSve)
        .with(Feature::ArmSve2);
    let usable = host().usable();
    assert!(
        usable.contains_all(sve2) && usable.contains(Feature::ArmNeon),
        "benchmark requires OS-usable NEON, SVE and SVE2"
    );

    let set = AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]);
    let sve2_classifier =
        AsciiByteSetClassifier::with_policy(set, DispatchPolicy::AllowOnly(sve2)).unwrap();
    let neon_classifier = AsciiByteSetClassifier::with_policy(
        set,
        DispatchPolicy::AllowOnly(FeatureSet::of(Feature::ArmNeon)),
    )
    .unwrap();
    assert_eq!(
        sve2_classifier.selection().wide().variant_id,
        expected_sve2_variant(host().tuning())
    );
    assert_eq!(
        neon_classifier.selection().wide().variant_id,
        "ascii-byte-set.mask32.split16-neon.v1"
    );

    let mut state = 0x7a12_95ec_3bd4_06f1;
    let inputs: Vec<[u8; ASCII_WIDE_BYTES]> = (0..256)
        .map(|_| core::array::from_fn(|_| next_random(&mut state).to_le_bytes()[0]))
        .collect();
    for input in &inputs {
        assert_eq!(
            sve2_classifier.classify_32(input),
            neon_classifier.classify_32(input)
        );
    }

    let iterations = std::env::var("FRE_SIMD_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(5_000_000);
    assert!(iterations > 0);
    let _ = measure_classifier(&sve2_classifier, &inputs, iterations / 10 + 1);
    let _ = measure_classifier(&neon_classifier, &inputs, iterations / 10 + 1);

    let mut sve2_samples = Vec::with_capacity(9);
    let mut neon_samples = Vec::with_capacity(9);
    for sample in 0..9 {
        if sample % 2 == 0 {
            sve2_samples.push(measure_classifier(&sve2_classifier, &inputs, iterations));
            neon_samples.push(measure_classifier(&neon_classifier, &inputs, iterations));
        } else {
            neon_samples.push(measure_classifier(&neon_classifier, &inputs, iterations));
            sve2_samples.push(measure_classifier(&sve2_classifier, &inputs, iterations));
        }
    }
    sve2_samples.sort_by(f64::total_cmp);
    neon_samples.sort_by(f64::total_cmp);
    let sve2_median = sve2_samples[sve2_samples.len() / 2];
    let neon_median = neon_samples[neon_samples.len() / 2];
    eprintln!(
        "SIMD_BENCH iterations={iterations} sve2_ns_per_call={sve2_median:.6} \
         split_neon_ns_per_call={neon_median:.6} sve2_over_neon={:.6} \
         sve2_samples={sve2_samples:?} neon_samples={neon_samples:?}",
        sve2_median / neon_median
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
#[allow(
    unsafe_code,
    reason = "the test gates the private SSE2 leaf on the same OS-usable host feature used by production dispatch"
)]
fn forced_sse2_and_direct_leaf_match_scalar() {
    if !host().usable().contains(Feature::X86Sse2) {
        return;
    }
    let classifier = AsciiByteSetClassifier::with_policy(
        AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]),
        DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Sse2)),
    )
    .unwrap();
    assert_eq!(
        classifier.selection().narrow().variant_id,
        "ascii-byte-set.mask16.sse2.v1"
    );
    assert_eq!(
        classifier.selection().narrow().required,
        FeatureSet::of(Feature::X86Sse2)
    );
    assert_eq!(
        classifier.selection().wide().variant_id,
        "ascii-byte-set.mask32.split16.v1"
    );
    assert_eq!(
        classifier.selection().wide().delegate_variant_id,
        Some("ascii-byte-set.mask16.sse2.v1")
    );
    assert_eq!(
        classifier.selection().wide().required,
        FeatureSet::of(Feature::X86Sse2)
    );

    let mut state = 0xc37b_49d8_4e93_760f;
    for _ in 0..20_000 {
        let set = AsciiByteSet::from_words([next_random(&mut state), next_random(&mut state)]);
        let columns = set.nibble_columns();
        let bytes = core::array::from_fn(|_| next_random(&mut state).to_le_bytes()[0]);
        // SAFETY: this test returned unless the immutable host snapshot proved
        // SSE2 OS-usable.
        let direct = unsafe { x86_64::classify_16_sse2(&columns, &bytes) };
        assert_eq!(direct, scalar::classify_16(&columns, &bytes));

        let forced = AsciiByteSetClassifier::with_policy(
            set,
            DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Sse2)),
        )
        .unwrap();
        assert_eq!(forced.classify_16(&bytes), direct);
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn forced_x86_feature_sets_preserve_the_non_linear_dispatch_lattice() {
    let usable = host().usable();
    if !usable.contains(Feature::X86Sse2) {
        return;
    }
    let set = AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]);

    let sse2 = AsciiByteSetClassifier::with_policy(
        set,
        DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Sse2)),
    )
    .unwrap();
    assert_eq!(
        sse2.selection().narrow().variant_id,
        "ascii-byte-set.mask16.sse2.v1"
    );
    assert_eq!(
        sse2.selection().wide().delegate_variant_id,
        Some("ascii-byte-set.mask16.sse2.v1")
    );

    if usable.contains(Feature::X86Ssse3) {
        let sse2_ssse3 = AsciiByteSetClassifier::with_policy(
            set,
            DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Sse2).with(Feature::X86Ssse3)),
        )
        .unwrap();
        assert_eq!(
            sse2_ssse3.selection().narrow().variant_id,
            "ascii-byte-set.mask16.ssse3.v1"
        );
        assert_eq!(
            sse2_ssse3.selection().wide().delegate_variant_id,
            Some("ascii-byte-set.mask16.ssse3.v1")
        );
    }

    if usable.contains(Feature::X86Avx2) {
        let sse2_avx2 = AsciiByteSetClassifier::with_policy(
            set,
            DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Sse2).with(Feature::X86Avx2)),
        )
        .unwrap();
        assert_eq!(
            sse2_avx2.selection().narrow().variant_id,
            "ascii-byte-set.mask16.sse2.v1"
        );
        assert_eq!(
            sse2_avx2.selection().wide().variant_id,
            "ascii-byte-set.mask32.avx2.v1"
        );
        assert_eq!(sse2_avx2.selection().wide().delegate_variant_id, None);
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
#[allow(
    unsafe_code,
    reason = "the test gates the private SSSE3 leaf on the same OS-usable host feature used by production dispatch"
)]
fn forced_ssse3_and_direct_leaf_match_scalar() {
    if !host().usable().contains(Feature::X86Ssse3) {
        return;
    }
    let classifier = AsciiByteSetClassifier::with_policy(
        AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]),
        DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Ssse3)),
    )
    .unwrap();
    assert_eq!(
        classifier.selection().narrow().variant_id,
        "ascii-byte-set.mask16.ssse3.v1"
    );
    assert_eq!(
        classifier.selection().wide().variant_id,
        "ascii-byte-set.mask32.split16.v1"
    );
    assert_eq!(
        classifier.selection().wide().delegate_variant_id,
        Some("ascii-byte-set.mask16.ssse3.v1")
    );
    assert_eq!(
        classifier.selection().wide().required,
        FeatureSet::of(Feature::X86Ssse3)
    );
    assert_eq!(
        classifier.selection().wide().vector,
        classifier.selection().narrow().vector
    );
    assert_eq!(
        classifier.selection().narrow().required,
        FeatureSet::of(Feature::X86Ssse3)
    );

    let columns = classifier.set().nibble_columns();
    for offset in 0_u8..=u8::MAX {
        let bytes = core::array::from_fn(|lane| {
            offset.wrapping_add(u8::try_from(lane).unwrap().wrapping_mul(29))
        });
        // SAFETY: this test returned unless the immutable host snapshot proved
        // SSSE3 OS-usable.
        let direct = unsafe { x86_64::classify_16_ssse3(&columns, &bytes) };
        assert_eq!(direct, scalar::classify_16(&columns, &bytes));
        assert_eq!(classifier.classify_16(&bytes), direct);
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
#[allow(
    unsafe_code,
    reason = "the test gates the private AVX2 leaf on the same OS-usable host feature used by production dispatch"
)]
fn forced_avx2_and_direct_leaf_match_scalar_in_both_shuffle_lanes() {
    if !host().usable().contains(Feature::X86Avx2) {
        return;
    }
    // Deliberately permit AVX2 without SSSE3. The wide mask leaf does not
    // over-require SSSE3 or POPCNT, while narrow dispatch falls back scalar.
    let classifier = AsciiByteSetClassifier::with_policy(
        singleton(b'Q'),
        DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Avx2)),
    )
    .unwrap();
    assert_eq!(
        classifier.selection().narrow().variant_id,
        "ascii-byte-set.mask16.scalar.v1"
    );
    assert_eq!(
        classifier.selection().wide().variant_id,
        "ascii-byte-set.mask32.avx2.v1"
    );
    assert_eq!(classifier.selection().wide().delegate_variant_id, None);
    assert_eq!(
        classifier.selection().wide().required,
        FeatureSet::of(Feature::X86Avx2)
    );

    let columns = classifier.set().nibble_columns();
    for lane in [0, 15, 16, 31] {
        let mut bytes = [0xff; ASCII_WIDE_BYTES];
        bytes[lane] = b'Q';
        // SAFETY: this test returned unless the immutable host snapshot proved
        // AVX2 OS-usable.
        let direct = unsafe { x86_64::classify_32_avx2(&columns, &bytes) };
        assert_eq!(direct, scalar::classify_32(&columns, &bytes));
        assert_eq!(direct.member_mask(), 1_u32 << lane);
    }

    let mut state = 0xc6bc_2796_92b5_cc83;
    for _ in 0..20_000 {
        let set = AsciiByteSet::from_words([next_random(&mut state), next_random(&mut state)]);
        let columns = set.nibble_columns();
        let bytes = core::array::from_fn(|_| next_random(&mut state).to_le_bytes()[0]);
        // SAFETY: this test returned unless the immutable host snapshot proved
        // AVX2 OS-usable.
        let direct = unsafe { x86_64::classify_32_avx2(&columns, &bytes) };
        assert_eq!(direct, scalar::classify_32(&columns, &bytes));
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn required_avx512_native_sentinel_fails_instead_of_skipping() {
    let Some(value) = std::env::var_os("FRE_SIMD_REQUIRE_AVX512") else {
        return;
    };
    assert_eq!(
        value, "1",
        "FRE_SIMD_REQUIRE_AVX512 must be exactly 1 when the native sentinel is enabled"
    );
    let usable = host().usable();
    assert!(
        usable.contains_all(X86_AVX512_MASK_FEATURES),
        "FRE_SIMD_REQUIRE_AVX512=1 requires OS-usable AVX-512F, AVX-512BW and AVX-512VL; usable={usable:?}"
    );
    let classifier = AsciiByteSetClassifier::with_policy(
        AsciiByteSet::ALL,
        DispatchPolicy::AllowOnly(X86_AVX512_MASK_FEATURES),
    )
    .expect("the sentinel proved every AVX-512 classifier feature usable");
    let selection = classifier.selection().wide();
    assert_eq!(
        selection.variant_id,
        "ascii-byte-set.mask32.avx512f-bw-vl.v1"
    );
    assert_eq!(selection.delegate_variant_id, None);
    assert_eq!(selection.required, X86_AVX512_MASK_FEATURES);
    assert_eq!(selection.policy_usable, X86_AVX512_MASK_FEATURES);
    assert_eq!(
        selection.vector,
        VectorKind::Fixed {
            bytes: u16::try_from(ASCII_WIDE_BYTES).unwrap()
        }
    );
    assert_eq!(selection.selection_input_bytes, ASCII_WIDE_BYTES);
    assert_eq!(selection.minimum_input_bytes, ASCII_WIDE_BYTES);
    assert_eq!(
        classifier.classify_32(&[b'A'; ASCII_WIDE_BYTES]),
        AsciiMasks32::new(u32::MAX, u32::MAX)
    );

    let receipt_path =
        required_absolute_receipt_path(std::env::var_os("FRE_SIMD_AVX512_SENTINEL_RECEIPT_PATH"))
            .unwrap_or_else(|error| panic!("FRE_SIMD_AVX512_SENTINEL_RECEIPT_PATH {error}"));
    publish_machine_receipt(
        &receipt_path,
        AVX512_SENTINEL_RECEIPT_PREFIX,
        AVX512_SENTINEL_MACHINE_RECEIPT,
    )
    .unwrap_or_else(|error| panic!("publish {}: {error}", receipt_path.display()));
    eprintln!(
        "SIMD_AVX512_SENTINEL_INFO variant={} host_usable_contains_required=true receipt={}",
        selection.variant_id,
        receipt_path.display()
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn avx512_proper_subset_lattice_falls_back_and_avx2_keeps_generic_preference() {
    if !host().usable().contains_all(X86_AVX512_MASK_FEATURES) {
        return;
    }
    let f = FeatureSet::of(Feature::X86Avx512F);
    let bw = FeatureSet::of(Feature::X86Avx512Bw);
    let vl = FeatureSet::of(Feature::X86Avx512Vl);
    let proper_subsets = [
        FeatureSet::EMPTY,
        f,
        bw,
        vl,
        f.union(bw),
        f.union(vl),
        bw.union(vl),
    ];
    let set = AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]);

    for allowed in proper_subsets {
        let fallback =
            AsciiByteSetClassifier::with_policy(set, DispatchPolicy::AllowOnly(allowed)).unwrap();
        assert_eq!(
            fallback.selection().wide().variant_id,
            "ascii-byte-set.mask32.split16.v1",
            "proper subset {allowed:?} authorized the AVX-512 leaf"
        );
        assert_eq!(
            fallback.selection().wide().delegate_variant_id,
            Some("ascii-byte-set.mask16.scalar.v1")
        );
        assert!(fallback.selection().wide().required.is_empty());

        if host().usable().contains(Feature::X86Avx2) {
            let with_avx2 = allowed.with(Feature::X86Avx2);
            let lower_tier =
                AsciiByteSetClassifier::with_policy(set, DispatchPolicy::AllowOnly(with_avx2))
                    .unwrap();
            assert_eq!(
                lower_tier.selection().wide().variant_id,
                "ascii-byte-set.mask32.avx2.v1"
            );
            assert_eq!(
                lower_tier.selection().wide().required,
                FeatureSet::of(Feature::X86Avx2)
            );
        }
    }

    let forced = AsciiByteSetClassifier::with_policy(
        set,
        DispatchPolicy::AllowOnly(X86_AVX512_MASK_FEATURES),
    )
    .unwrap();
    let receipt = forced.selection().wide();
    assert_eq!(receipt.variant_id, "ascii-byte-set.mask32.avx512f-bw-vl.v1");
    assert_eq!(receipt.delegate_variant_id, None);
    assert_eq!(receipt.required, X86_AVX512_MASK_FEATURES);
    assert_eq!(receipt.policy_usable, X86_AVX512_MASK_FEATURES);
    assert_eq!(
        receipt.vector,
        VectorKind::Fixed {
            bytes: u16::try_from(ASCII_WIDE_BYTES).unwrap()
        }
    );
    assert_eq!(receipt.selection_input_bytes, ASCII_WIDE_BYTES);
    assert_eq!(receipt.minimum_input_bytes, ASCII_WIDE_BYTES);

    if host().usable().contains(Feature::X86Avx2) {
        let generic = AsciiByteSetClassifier::with_policy(
            set,
            DispatchPolicy::AllowOnly(X86_AVX512_MASK_FEATURES.with(Feature::X86Avx2)),
        )
        .unwrap();
        assert_eq!(
            generic.selection().wide().variant_id,
            "ascii-byte-set.mask32.avx2.v1",
            "generic AVX-512 preference must remain below AVX2 until fresh tuning evidence exists"
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
#[allow(
    unsafe_code,
    reason = "the test gates the private AVX-512 leaf on the same three OS-usable host features used by production dispatch"
)]
fn forced_avx512_direct_random_lane_and_all_alignment_cases_match_scalar() {
    if !host().usable().contains_all(X86_AVX512_MASK_FEATURES) {
        return;
    }

    for selected in 0_u8..=0x7f {
        let set = singleton(selected);
        let columns = set.nibble_columns();
        for lane in 0..ASCII_WIDE_BYTES {
            let mut bytes = [0xff; ASCII_WIDE_BYTES];
            bytes[lane] = selected;
            // SAFETY: this test returned unless all three immutable AVX-512
            // host facts used by the leaf were OS-usable.
            let direct = unsafe { x86_64::classify_32_avx512(&columns, &bytes) };
            assert_eq!(direct, scalar::classify_32(&columns, &bytes));
            assert_eq!(direct.member_mask(), 1_u32 << u32::try_from(lane).unwrap());
        }
    }

    let mut state = 0x3f84_d5b5_b547_0917;
    for _ in 0..20_000 {
        let set = AsciiByteSet::from_words([next_random(&mut state), next_random(&mut state)]);
        let columns = set.nibble_columns();
        let bytes = core::array::from_fn(|_| next_random(&mut state).to_le_bytes()[0]);
        // SAFETY: the feature gate above proves the leaf's complete target
        // feature set on this host.
        let direct = unsafe { x86_64::classify_32_avx512(&columns, &bytes) };
        assert_eq!(direct, scalar::classify_32(&columns, &bytes));
    }

    let set = AsciiByteSet::from_words([0x1020_4080_0102_0408, 0x8040_2010_0804_0201]);
    let columns = set.nibble_columns();
    let classifier = AsciiByteSetClassifier::with_policy(
        set,
        DispatchPolicy::AllowOnly(X86_AVX512_MASK_FEATURES),
    )
    .unwrap();
    let mut storage = [0_u8; ASCII_WIDE_BYTES + 64];
    for (index, byte) in storage.iter_mut().enumerate() {
        *byte = u8::try_from(index)
            .expect("the alignment fixture stays within u8")
            .wrapping_mul(43);
    }
    let mut observed_alignments = [false; 64];
    for offset in 0..64 {
        let bytes: &[u8; ASCII_WIDE_BYTES] = storage[offset..offset + ASCII_WIDE_BYTES]
            .try_into()
            .unwrap();
        observed_alignments[bytes.as_ptr().addr() & 63] = true;
        // SAFETY: the feature gate above proves the leaf's complete target
        // feature set, and the fixed array reference proves the load extent at
        // every address modulo a cache line.
        let direct = unsafe { x86_64::classify_32_avx512(&columns, bytes) };
        assert_eq!(direct, scalar::classify_32(&columns, bytes));
        assert_eq!(classifier.classify_32(bytes), direct);
    }
    assert!(
        observed_alignments.into_iter().all(core::convert::identity),
        "the direct leaf did not execute at every address modulo 64"
    );
}

#[cfg(target_arch = "x86_64")]
fn measure_x86_classifier(
    classifier: &AsciiByteSetClassifier,
    inputs: &[[u8; ASCII_WIDE_BYTES]],
    iterations: u32,
) -> f64 {
    assert!(iterations > 0, "benchmark iterations must be positive");
    assert!(
        inputs.len().is_power_of_two(),
        "the benchmark input bank must be a nonempty power of two"
    );
    let input_mask = inputs
        .len()
        .checked_sub(1)
        .expect("a power-of-two input bank is nonempty");
    let started = std::time::Instant::now();
    let mut checksum = 0_u64;
    for iteration in 0..iterations {
        let input_index = usize::try_from(std::hint::black_box(iteration))
            .expect("u32 fits in usize on supported targets")
            & input_mask;
        let masks = std::hint::black_box(classifier)
            .classify_32(std::hint::black_box(&inputs[input_index]));
        checksum ^= u64::from(masks.member_mask()) | (u64::from(masks.ascii_mask()) << u32::BITS);
    }
    std::hint::black_box(checksum);
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / f64::from(iterations)
}

#[cfg(target_arch = "x86_64")]
fn benchmark_parameter(name: &str, default: u32, minimum: u32) -> u32 {
    let value = std::env::var(name).map_or(default, |raw| {
        raw.parse::<u32>()
            .unwrap_or_else(|error| panic!("{name} must be a positive integer: {error}"))
    });
    assert!(
        value >= minimum,
        "{name} must be at least {minimum}, observed {value}"
    );
    value
}

fn benchmark_median(raw: &[f64]) -> f64 {
    let mut sorted = raw.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        let lower = middle
            .checked_sub(1)
            .expect("the benchmark has at least 15 samples");
        f64::midpoint(sorted[lower], sorted[middle])
    } else {
        sorted[middle]
    }
}

const X86_BENCHMARK_RECEIPT_PREFIX: &str = "SIMD_X86_BENCH ";
const AVX512_SENTINEL_RECEIPT_PREFIX: &str = "SIMD_AVX512_SENTINEL ";
const AVX512_SENTINEL_MACHINE_RECEIPT: &str = concat!(
    "SIMD_AVX512_SENTINEL ",
    "variant=ascii-byte-set.mask32.avx512f-bw-vl.v1 ",
    "required=x86.avx512f,x86.avx512bw,x86.avx512vl ",
    "policy_usable=x86.avx512f,x86.avx512bw,x86.avx512vl ",
    "host_usable_contains_required=true\n",
);

#[derive(Debug)]
struct X86BenchmarkReceipt {
    machine_line: String,
    avx2_median: f64,
    avx512_median: f64,
    avx512_over_avx2: f64,
}

fn serialize_x86_benchmark_receipt(
    iterations: u32,
    orders: &[&str],
    avx2_samples: &[f64],
    avx512_samples: &[f64],
) -> Result<X86BenchmarkReceipt, &'static str> {
    let samples = orders.len();
    if iterations == 0 {
        return Err("benchmark iteration count must be positive");
    }
    if samples < 15 {
        return Err("benchmark requires at least 15 paired samples");
    }
    if avx2_samples.len() != samples || avx512_samples.len() != samples {
        return Err("benchmark raw array length mismatch");
    }
    if orders
        .iter()
        .enumerate()
        .any(|(index, order)| *order != if index % 2 == 0 { "AB" } else { "BA" })
    {
        return Err("benchmark did not retain the declared AB/BA order");
    }
    if avx2_samples
        .iter()
        .chain(avx512_samples)
        .any(|value| !value.is_finite() || *value <= 0.0)
    {
        return Err("benchmark raw arrays contain a non-positive or non-finite value");
    }

    let avx2_median = benchmark_median(avx2_samples);
    let avx512_median = benchmark_median(avx512_samples);
    let avx512_over_avx2 = avx512_median / avx2_median;
    if !avx2_median.is_finite()
        || avx2_median <= 0.0
        || !avx512_median.is_finite()
        || avx512_median <= 0.0
        || !avx512_over_avx2.is_finite()
        || avx512_over_avx2 <= 0.0
    {
        return Err("benchmark medians and ratio must be positive and finite");
    }

    let machine_line = format!(
        "{X86_BENCHMARK_RECEIPT_PREFIX}iterations={iterations} samples={samples} \
         avx2_ns_per_call={avx2_median:.9} avx512_ns_per_call={avx512_median:.9} \
         avx512_over_avx2={avx512_over_avx2:.9} orders={orders:?} \
         avx2_samples={avx2_samples:?} avx512_samples={avx512_samples:?}\n"
    );
    Ok(X86BenchmarkReceipt {
        machine_line,
        avx2_median,
        avx512_median,
        avx512_over_avx2,
    })
}

fn publish_machine_receipt(path: &Path, prefix: &str, machine_line: &str) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "machine receipt path must be absolute",
        ));
    }
    let Some(body) = machine_line.strip_suffix('\n') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "machine receipt must end in one newline",
        ));
    };
    if prefix.is_empty() || !body.starts_with(prefix) || body.contains(['\r', '\n']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "receipt must contain exactly one machine line with the required prefix",
        ));
    }

    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(machine_line.as_bytes())?;
    output.flush()?;
    output.sync_all()
}

fn required_absolute_receipt_path(
    value: Option<std::ffi::OsString>,
) -> Result<std::path::PathBuf, &'static str> {
    let value = value.ok_or("must be set")?;
    let path = std::path::PathBuf::from(value);
    if !path.is_absolute() {
        return Err("must be absolute");
    }
    Ok(path)
}

#[test]
fn x86_benchmark_receipt_serialization_fails_closed() {
    let orders: Vec<_> = (0..15)
        .map(|index| if index % 2 == 0 { "AB" } else { "BA" })
        .collect();
    let avx2 = vec![2.0; orders.len()];
    let avx512 = vec![3.0; orders.len()];
    let receipt = serialize_x86_benchmark_receipt(1_000, &orders, &avx2, &avx512)
        .expect("valid benchmark values serialize");
    assert_eq!(receipt.avx2_median.to_bits(), 2.0_f64.to_bits());
    assert_eq!(receipt.avx512_median.to_bits(), 3.0_f64.to_bits());
    assert_eq!(receipt.avx512_over_avx2.to_bits(), 1.5_f64.to_bits());
    assert_eq!(receipt.machine_line.matches('\n').count(), 1);
    assert!(receipt.machine_line.ends_with('\n'));
    assert!(receipt.machine_line.starts_with(
        "SIMD_X86_BENCH iterations=1000 samples=15 \
         avx2_ns_per_call=2.000000000 avx512_ns_per_call=3.000000000 \
         avx512_over_avx2=1.500000000 "
    ));

    let mut wrong_order = orders.clone();
    wrong_order[1] = "AB";
    assert!(serialize_x86_benchmark_receipt(1_000, &wrong_order, &avx2, &avx512).is_err());
    let mut non_finite = avx512.clone();
    non_finite[0] = f64::NAN;
    assert!(serialize_x86_benchmark_receipt(1_000, &orders, &avx2, &non_finite).is_err());
    assert!(serialize_x86_benchmark_receipt(0, &orders, &avx2, &avx512).is_err());
    assert!(
        serialize_x86_benchmark_receipt(1_000, &orders[..14], &avx2[..14], &avx512[..14]).is_err()
    );
}

#[test]
fn machine_receipt_publication_requires_a_fresh_absolute_path() {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "fre-simd-x86-benchmark-receipt-test-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).expect("create unique receipt test directory");
    let path = directory.join("benchmark.receipt");
    let machine_line = "SIMD_X86_BENCH fixture=true\n";

    assert!(required_absolute_receipt_path(None).is_err());
    assert!(
        required_absolute_receipt_path(Some(std::ffi::OsString::from("benchmark.receipt")))
            .is_err()
    );
    assert_eq!(
        required_absolute_receipt_path(Some(path.clone().into_os_string()))
            .expect("an absolute receipt path is accepted"),
        path
    );
    let relative_error = publish_machine_receipt(
        Path::new("benchmark.receipt"),
        X86_BENCHMARK_RECEIPT_PREFIX,
        machine_line,
    )
    .expect_err("a relative receipt path must fail");
    assert_eq!(relative_error.kind(), io::ErrorKind::InvalidInput);
    let malformed_error = publish_machine_receipt(
        &path,
        X86_BENCHMARK_RECEIPT_PREFIX,
        "SIMD_X86_BENCH partial",
    )
    .expect_err("an incomplete receipt must fail before file creation");
    assert_eq!(malformed_error.kind(), io::ErrorKind::InvalidInput);
    let prefix_error = publish_machine_receipt(
        &path,
        X86_BENCHMARK_RECEIPT_PREFIX,
        AVX512_SENTINEL_MACHINE_RECEIPT,
    )
    .expect_err("a mismatched machine prefix must fail before file creation");
    assert_eq!(prefix_error.kind(), io::ErrorKind::InvalidInput);
    assert!(!path.exists());

    publish_machine_receipt(&path, X86_BENCHMARK_RECEIPT_PREFIX, machine_line)
        .expect("publish fresh receipt");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read published receipt"),
        machine_line
    );
    let existing_error = publish_machine_receipt(&path, X86_BENCHMARK_RECEIPT_PREFIX, machine_line)
        .expect_err("an existing receipt must fail");
    assert_eq!(existing_error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read_to_string(&path).expect("re-read published receipt"),
        machine_line
    );

    #[cfg(unix)]
    {
        std::fs::remove_file(&path).expect("remove published receipt");
        let target = directory.join("symlink-target");
        std::fs::write(&target, "untouched\n").expect("write symlink target");
        std::os::unix::fs::symlink(&target, &path).expect("create receipt-path symlink");
        let symlink_error =
            publish_machine_receipt(&path, X86_BENCHMARK_RECEIPT_PREFIX, machine_line)
                .expect_err("a symlink receipt path must fail");
        assert_eq!(symlink_error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read_to_string(&target).expect("read symlink target"),
            "untouched\n"
        );
    }

    let sentinel_path = directory.join("sentinel.receipt");
    publish_machine_receipt(
        &sentinel_path,
        AVX512_SENTINEL_RECEIPT_PREFIX,
        AVX512_SENTINEL_MACHINE_RECEIPT,
    )
    .expect("publish fresh sentinel receipt");
    assert_eq!(
        std::fs::read_to_string(&sentinel_path).expect("read sentinel receipt"),
        AVX512_SENTINEL_MACHINE_RECEIPT
    );

    std::fs::remove_dir_all(&directory).expect("remove receipt test directory");
}

#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "required native x86 qualification benchmark; run pinned in release mode"]
fn benchmark_avx2_against_avx512() {
    let usable = host().usable();
    assert!(
        usable.contains(Feature::X86Avx2) && usable.contains_all(X86_AVX512_MASK_FEATURES),
        "benchmark requires OS-usable AVX2, AVX-512F, AVX-512BW and AVX-512VL; usable={usable:?}"
    );

    let set = AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210]);
    let avx2 = AsciiByteSetClassifier::with_policy(
        set,
        DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Avx2)),
    )
    .unwrap();
    let avx512 = AsciiByteSetClassifier::with_policy(
        set,
        DispatchPolicy::AllowOnly(X86_AVX512_MASK_FEATURES),
    )
    .unwrap();
    assert_eq!(
        avx2.selection().wide().variant_id,
        "ascii-byte-set.mask32.avx2.v1"
    );
    assert_eq!(
        avx512.selection().wide().variant_id,
        "ascii-byte-set.mask32.avx512f-bw-vl.v1"
    );

    let mut state = 0x7134_9a2d_82b1_c5ef;
    let inputs: Vec<[u8; ASCII_WIDE_BYTES]> = (0..256)
        .map(|_| core::array::from_fn(|_| next_random(&mut state).to_le_bytes()[0]))
        .collect();
    for input in &inputs {
        assert_eq!(avx2.classify_32(input), avx512.classify_32(input));
    }

    let iterations = benchmark_parameter("FRE_SIMD_BENCH_ITERS", 5_000_000, 1);
    let samples = usize::try_from(benchmark_parameter("FRE_SIMD_BENCH_SAMPLES", 16, 15))
        .expect("u32 sample count fits usize");
    let warmup_iterations = iterations / 10 + 1;
    let _ = measure_x86_classifier(&avx2, &inputs, warmup_iterations);
    let _ = measure_x86_classifier(&avx512, &inputs, warmup_iterations);

    let mut avx2_samples = Vec::with_capacity(samples);
    let mut avx512_samples = Vec::with_capacity(samples);
    let mut orders = Vec::with_capacity(samples);
    for sample in 0..samples {
        if sample % 2 == 0 {
            orders.push("AB");
            avx2_samples.push(measure_x86_classifier(&avx2, &inputs, iterations));
            avx512_samples.push(measure_x86_classifier(&avx512, &inputs, iterations));
        } else {
            orders.push("BA");
            avx512_samples.push(measure_x86_classifier(&avx512, &inputs, iterations));
            avx2_samples.push(measure_x86_classifier(&avx2, &inputs, iterations));
        }
    }
    let receipt =
        serialize_x86_benchmark_receipt(iterations, &orders, &avx2_samples, &avx512_samples)
            .expect("benchmark values must form one complete machine receipt");
    let receipt_path =
        required_absolute_receipt_path(std::env::var_os("FRE_SIMD_BENCH_RECEIPT_PATH"))
            .unwrap_or_else(|error| panic!("FRE_SIMD_BENCH_RECEIPT_PATH {error}"));
    publish_machine_receipt(
        &receipt_path,
        X86_BENCHMARK_RECEIPT_PREFIX,
        &receipt.machine_line,
    )
    .unwrap_or_else(|error| panic!("publish {}: {error}", receipt_path.display()));
    eprintln!(
        "SIMD_X86_BENCH_INFO iterations={iterations} samples={samples} \
         avx2_ns_per_call={:.9} avx512_ns_per_call={:.9} \
         avx512_over_avx2={:.9} receipt={}",
        receipt.avx2_median,
        receipt.avx512_median,
        receipt.avx512_over_avx2,
        receipt_path.display()
    );
}
