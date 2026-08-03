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

#[cfg(feature = "static-dispatch")]
#[test]
fn compiler_fixed_direct_leaves_match_automatic_receipts() {
    let classifier = AsciiByteSetClassifier::new(AsciiByteSet::ALL);
    let expected_narrow = select_narrow(*host(), DispatchPolicy::Auto)
        .expect("automatic narrow selection")
        .receipt();
    let expected_wide =
        select_wide(*host(), DispatchPolicy::Auto).expect("automatic wide selection");
    let expected_wide_receipt = match expected_wide.entry() {
        WideEntry::SplitNarrow => SelectionReceipt {
            delegate_variant_id: Some(expected_narrow.variant_id),
            required: expected_narrow.required,
            vector: expected_narrow.vector,
            ..expected_wide.receipt()
        },
        #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
        WideEntry::Sve2(()) => expected_wide.receipt(),
        #[cfg(target_arch = "x86_64")]
        WideEntry::Avx2(()) => expected_wide.receipt(),
        #[cfg(target_arch = "x86_64")]
        WideEntry::Avx512(()) => expected_wide.receipt(),
    };
    assert_eq!(
        classifier.selection(),
        AsciiSelection {
            narrow: expected_narrow,
            wide: expected_wide_receipt,
        }
    );
    assert_eq!(
        classifier.selection().narrow().variant_id,
        static_narrow_variant_id()
    );
    assert_eq!(
        classifier.selection().wide().variant_id,
        static_wide_variant_id()
    );

    let word_space =
        AsciiWordSpaceClassifier::with_policy(DispatchPolicy::Auto).expect("static auto leaf");
    assert_eq!(
        word_space.selection(),
        select_word_space(*host(), DispatchPolicy::Auto)
            .expect("automatic word-space selection")
            .receipt()
    );
    assert_eq!(
        word_space.selection().variant_id,
        static_word_space_variant_id()
    );

    for set in [singleton(b'x'), AsciiByteSet::ALL] {
        let (_, table_mode) = set.run_tables(false);
        let scanner = AsciiByteSetRunScanner::new(set);
        assert_eq!(
            scanner.selection(),
            select_run(*host(), DispatchPolicy::Auto, table_mode)
                .expect("automatic run selection")
                .receipt()
        );
        assert_eq!(
            scanner.selection().variant_id,
            static_run_variant_id(table_mode)
        );
    }

    let complement_set = all_ascii_except(b"\n\r");
    let (_, table_mode) = complement_set.run_tables(true);
    let scanner = SimdDispatchContext::capture()
        .ascii_byte_set_run_scanner_prefer_small_complement(complement_set, DispatchPolicy::Auto)
        .expect("compiler-fixed complement run scanner");
    assert_eq!(table_mode, AsciiRunTableMode::SmallComplement);
    assert_eq!(
        scanner.selection(),
        select_run(*host(), DispatchPolicy::Auto, table_mode)
            .expect("automatic complement run selection")
            .receipt()
    );
    assert_eq!(
        scanner.selection().variant_id,
        static_run_variant_id(table_mode)
    );
}

#[cfg(all(feature = "static-dispatch", target_pointer_width = "64"))]
#[test]
fn compiler_fixed_handles_do_not_retain_receipts_or_entries() {
    assert_eq!(core::mem::size_of::<AsciiByteSetClassifier>(), 32);
    assert_eq!(core::mem::size_of::<AsciiByteSetRunScanner>(), 56);
    assert_eq!(core::mem::size_of::<AsciiWordSpaceClassifier>(), 32);
    assert_eq!(core::mem::size_of::<ByteSetClassifier>(), 64);
}

#[cfg(feature = "static-dispatch")]
#[test]
fn same_leaf_custom_policy_is_an_assertion_and_reports_profile_auto() {
    let automatic = AsciiByteSetClassifier::new(AsciiByteSet::ALL);
    let automatic_selection = automatic.selection();
    let required = automatic_selection
        .narrow()
        .required
        .union(automatic_selection.wide().required);
    let authenticated =
        AsciiByteSetClassifier::with_policy(AsciiByteSet::ALL, DispatchPolicy::Require(required))
            .expect("requiring the fixed leaf's features authenticates it");
    assert_eq!(authenticated.selection(), automatic_selection);
    assert_eq!(
        authenticated.selection().narrow().policy,
        DispatchPolicy::Auto
    );
    assert_eq!(
        authenticated.selection().wide().policy,
        DispatchPolicy::Auto
    );
}

#[cfg(feature = "static-dispatch")]
#[test]
fn static_profile_rejects_policies_that_would_retarget_a_direct_leaf() {
    if static_narrow_variant_id() != SCALAR_MASK16_VARIANT_ID {
        let error =
            AsciiByteSetClassifier::with_policy(AsciiByteSet::ALL, DispatchPolicy::Portable)
                .expect_err("portable policy cannot retarget a compiler-fixed vector classifier");
        assert!(!error.required.is_empty());
        assert!(error.usable.is_empty());
    }

    if static_run_variant_id(AsciiRunTableMode::SmallMembers) != SCALAR_RUN_VARIANT_ID {
        let error = AsciiByteSetRunScanner::with_policy(singleton(b'x'), DispatchPolicy::Portable)
            .expect_err("portable policy cannot retarget a compiler-fixed vector scanner");
        assert!(!error.required.is_empty());
        assert!(error.usable.is_empty());
    }

    if static_run_variant_id(AsciiRunTableMode::SmallComplement) != SCALAR_RUN_VARIANT_ID {
        let error = SimdDispatchContext::capture()
            .ascii_byte_set_run_scanner_prefer_small_complement(
                all_ascii_except(&[b'\n']),
                DispatchPolicy::Portable,
            )
            .expect_err("portable policy cannot retarget a compiler-fixed complement scanner");
        assert!(!error.required.is_empty());
        assert!(error.usable.is_empty());
    }
}

#[cfg(feature = "static-dispatch")]
#[test]
fn compiler_fixed_run_scanner_exhausts_boundaries_and_alignments() {
    for set in [singleton(b'a'), AsciiByteSet::ALL] {
        let scanner = AsciiByteSetRunScanner::new(set);
        for len in 0..=ASCII_WIDE_BYTES * 3 + 1 {
            for offset in 0..ASCII_NARROW_BYTES {
                let mut storage = vec![0xcc; offset + len];
                let bytes = &mut storage[offset..];
                for prefix_len in 0..=len {
                    bytes.fill(b'a');
                    if prefix_len < len {
                        bytes[prefix_len] = b'!';
                    }
                    assert_run_result(
                        &scanner,
                        bytes,
                        scanner.scan_forward(bytes),
                        scanner.scan_backward(bytes),
                    );
                }
                for suffix_len in 0..=len {
                    bytes.fill(b'a');
                    if suffix_len < len {
                        bytes[len - suffix_len - 1] = b'!';
                    }
                    assert_run_result(
                        &scanner,
                        bytes,
                        scanner.scan_forward(bytes),
                        scanner.scan_backward(bytes),
                    );
                }
            }
        }
    }

    let set = all_ascii_except(b"\n\r");
    let scanner = SimdDispatchContext::capture()
        .ascii_byte_set_run_scanner_prefer_small_complement(set, DispatchPolicy::Auto)
        .expect("compiler-fixed complement scanner");
    for len in 0..=ASCII_WIDE_BYTES * 3 + 1 {
        for offset in 0..ASCII_NARROW_BYTES {
            let mut storage = vec![b'a'; offset + len];
            let bytes = &mut storage[offset..];
            for barrier in [b'\n', b'\r', 0x80, 0xbf, 0xc2, 0xff] {
                for position in 0..len {
                    bytes.fill(b'a');
                    bytes[position] = barrier;
                    assert_run_result(
                        &scanner,
                        bytes,
                        scanner.scan_forward(bytes),
                        scanner.scan_backward(bytes),
                    );
                }
            }
        }
    }
}

fn singleton(byte: u8) -> AsciiByteSet {
    assert!(byte.is_ascii());
    let mut words = [0_u64; 2];
    let word = usize::from(byte >> 6);
    words[word] = 1_u64 << (byte & 0x3f);
    AsciiByteSet::from_words(words)
}

fn all_ascii_except(excluded: &[u8]) -> AsciiByteSet {
    let mut words = [u64::MAX; 2];
    for &byte in excluded {
        assert!(byte.is_ascii());
        let word = usize::from(byte >> 6);
        words[word] &= !(1_u64 << (byte & 0x3f));
    }
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

fn reference_word_space_16(bytes: &[u8; ASCII_NARROW_BYTES]) -> AsciiWordSpaceMasks16 {
    scalar::classify_word_space_16(bytes)
}

fn reference_word_space_32(bytes: &[u8; ASCII_WIDE_BYTES]) -> AsciiWordSpaceMasks32 {
    scalar::classify_word_space_32(bytes)
}

fn reference_run_forward(set: AsciiByteSet, bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|&byte| !set.contains(byte))
        .unwrap_or(bytes.len())
}

fn reference_run_backward(set: AsciiByteSet, bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rev()
        .position(|&byte| !set.contains(byte))
        .unwrap_or(bytes.len())
}

fn assert_run_result(
    scanner: &AsciiByteSetRunScanner,
    bytes: &[u8],
    forward: AsciiRunResult,
    backward: AsciiRunResult,
) {
    let forward_len = reference_run_forward(scanner.set(), bytes);
    let backward_len = reference_run_backward(scanner.set(), bytes);
    assert_eq!(forward.member_run_len(), forward_len);
    assert_eq!(backward.member_run_len(), backward_len);

    for result in [forward, backward] {
        let logical = result
            .member_run_len()
            .checked_add(usize::from(result.member_run_len() != bytes.len()))
            .unwrap();
        let maximum = logical
            .checked_add(ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
            .unwrap();
        assert!(
            (logical..=maximum).contains(&result.examined_bytes()),
            "bytes={} result={result:?} selection={:?}",
            bytes.len(),
            scanner.selection()
        );
    }
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
fn word_space_classifier_partitions_every_byte_exactly() {
    for byte in u8::MIN..=u8::MAX {
        assert_eq!(
            ASCII_WORD_SET.contains(byte),
            byte.is_ascii_alphanumeric() || byte == b'_'
        );
        assert_eq!(
            ASCII_SPACE_VALUES.contains(&byte),
            matches!(byte, b'\t'..=b'\r' | b' ')
        );
    }
    #[cfg(not(feature = "static-dispatch"))]
    let classifier =
        AsciiWordSpaceClassifier::with_policy(DispatchPolicy::Portable).expect("scalar classifier");
    #[cfg(feature = "static-dispatch")]
    let classifier =
        AsciiWordSpaceClassifier::with_policy(DispatchPolicy::Auto).expect("static direct leaf");
    #[cfg(not(feature = "static-dispatch"))]
    assert_eq!(
        classifier.selection().variant_id,
        "ascii-word-space.mask16x32.scalar.v1"
    );
    for phase in 0_u16..=255 {
        let wide = core::array::from_fn(|lane| {
            u8::try_from((usize::from(phase) + lane * 37) & 0xff).expect("masked byte")
        });
        let narrow = wide[..ASCII_NARROW_BYTES]
            .try_into()
            .expect("exact narrow prefix");
        let narrow_masks = classifier.classify_16(narrow);
        let wide_masks = classifier.classify_32(&wide);
        assert_eq!(narrow_masks, reference_word_space_16(narrow));
        assert_eq!(wide_masks, reference_word_space_32(&wide));
        assert_eq!(
            narrow_masks.word_mask() | narrow_masks.space_mask() | narrow_masks.other_mask(),
            u16::MAX
        );
        assert_eq!(
            wide_masks.word_mask() | wide_masks.space_mask() | wide_masks.other_mask(),
            u32::MAX
        );
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
#[test]
fn word_space_sve2_fixed16_matches_scalar_when_usable() {
    let required = FeatureSet::EMPTY
        .with(Feature::ArmSve)
        .with(Feature::ArmSve2);
    if !host().usable().contains_all(required) {
        return;
    }
    let classifier =
        AsciiWordSpaceClassifier::require_sve2_fixed16().expect("OS-usable SVE2 classifier");
    assert_eq!(
        classifier.selection().variant_id,
        "ascii-word-space.mask16x32.sve2-vl16.v1"
    );
    assert!(classifier.selection().required.contains_all(required));

    let mut state = 0x04d5_22aa_e671_c93b;
    for _ in 0..1_024 {
        let wide = core::array::from_fn(|_| next_random(&mut state).to_le_bytes()[0]);
        let narrow = wide[..ASCII_NARROW_BYTES]
            .try_into()
            .expect("exact narrow prefix");
        assert_eq!(
            classifier.classify_16(narrow),
            reference_word_space_16(narrow)
        );
        assert_eq!(
            classifier.classify_32(&wide),
            reference_word_space_32(&wide)
        );
    }
    for alignment in 0..ASCII_NARROW_BYTES {
        let mut storage = [0_u8; ASCII_WIDE_BYTES + ASCII_NARROW_BYTES];
        for (index, byte) in storage.iter_mut().enumerate() {
            *byte = u8::try_from((index * 53 + alignment * 29) & 0xff).expect("masked byte");
        }
        let wide: &[u8; ASCII_WIDE_BYTES] = storage[alignment..alignment + ASCII_WIDE_BYTES]
            .try_into()
            .expect("exact unaligned wide block");
        let narrow: &[u8; ASCII_NARROW_BYTES] = wide[..ASCII_NARROW_BYTES]
            .try_into()
            .expect("exact unaligned narrow block");
        assert_eq!(
            classifier.classify_16(narrow),
            reference_word_space_16(narrow)
        );
        assert_eq!(classifier.classify_32(wide), reference_word_space_32(wide));
    }
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
fn run_tables_share_one_exact_representation_pass_and_match_only_small_sets() {
    let mut sets = vec![
        AsciiByteSet::EMPTY,
        AsciiByteSet::ALL,
        singleton(0),
        singleton(0x7f),
        AsciiByteSet::from_words([0x0123_4567_89ab_cdef, 0]),
        AsciiByteSet::from_words([0xffff, 0]),
        AsciiByteSet::from_words([0x1_ffff, 0]),
    ];
    let mut state = 0xe35a_7bd1_924c_086f;
    for _ in 0..256 {
        sets.push(AsciiByteSet::from_words([
            next_random(&mut state),
            next_random(&mut state),
        ]));
    }

    for set in sets {
        let (tables, table_mode) = set.run_tables(false);
        assert_eq!(tables.set, set);
        assert_eq!(tables.columns, set.nibble_columns());
        let members: Vec<_> = (0_u8..=0x7f).filter(|&byte| set.contains(byte)).collect();
        assert_eq!(
            table_mode == AsciiRunTableMode::SmallMembers,
            (1..=ASCII_NARROW_BYTES).contains(&members.len())
        );
        if table_mode == AsciiRunTableMode::SmallMembers {
            assert_eq!(&tables.match_values[..members.len()], members.as_slice());
            assert!(
                tables.match_values[members.len()..]
                    .iter()
                    .all(|&byte| byte == members[0])
            );
        }
    }
}

#[test]
fn complement_run_tables_are_explicit_bounded_and_keep_original_membership() {
    let cases: [&[u8]; 4] = [
        &[],
        &[0],
        &[
            0, 15, 16, 31, 32, 63, 64, 95, 96, 111, 112, 119, 120, 125, 126, 127,
        ],
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    ];
    for excluded in cases {
        let set = all_ascii_except(excluded);
        let (ordinary_tables, ordinary_mode) = set.run_tables(false);
        let (tables, table_mode) = set.run_tables(true);
        let expected_mode = if (1..=ASCII_NARROW_BYTES).contains(&excluded.len()) {
            AsciiRunTableMode::SmallComplement
        } else {
            AsciiRunTableMode::Generic
        };
        assert_eq!(ordinary_mode, AsciiRunTableMode::Generic);
        assert_eq!(table_mode, expected_mode);
        assert_eq!(tables.set, set);
        assert_eq!(tables.columns, set.nibble_columns());
        assert_eq!(ordinary_tables.set, tables.set);
        assert_eq!(ordinary_tables.columns, tables.columns);
        if table_mode == AsciiRunTableMode::SmallComplement {
            assert_eq!(
                &tables.match_values[..excluded.len()],
                excluded,
                "the complement table preserves ascending ASCII exclusions"
            );
            assert!(
                tables.match_values[excluded.len()..]
                    .iter()
                    .all(|&byte| byte == excluded[0])
            );
        }
    }

    let sparse = singleton(b'x');
    let (_, table_mode) = sparse.run_tables(true);
    assert_eq!(table_mode, AsciiRunTableMode::SmallMembers);
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
#[cfg(not(feature = "static-dispatch"))]
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
#[cfg(not(feature = "static-dispatch"))]
fn portable_run_scanner_exhausts_ascii_members_lanes_lengths_and_alignments() {
    for selected in 0_u8..=0x7f {
        let scanner =
            AsciiByteSetRunScanner::with_policy(singleton(selected), DispatchPolicy::Portable)
                .unwrap();
        assert_eq!(
            scanner.selection().variant_id,
            "ascii-byte-set.run.scalar.v1"
        );
        assert!(scanner.selection().required.is_empty());
        assert_eq!(scanner.selection().vector, VectorKind::Scalar);
        assert_eq!(
            scanner.selection().selection_input_bytes,
            ASCII_NARROW_BYTES
        );
        assert_eq!(scanner.selection().minimum_input_bytes, 0);

        let outsider = u8::from(selected == 0);
        for len in 0..=ASCII_WIDE_BYTES + 1 {
            for offset in 0..ASCII_NARROW_BYTES {
                let mut storage = vec![0xa5; offset + len];
                storage[offset..].fill(selected);
                let input = &mut storage[offset..];

                for prefix_len in 0..=len {
                    input.fill(selected);
                    if prefix_len < len {
                        input[prefix_len] = outsider;
                    }
                    let result = scanner.scan_forward(input);
                    assert_eq!(
                        result,
                        AsciiRunResult::new(prefix_len, prefix_len + usize::from(prefix_len < len)),
                        "selected={selected:#04x} len={len} offset={offset} prefix={prefix_len}"
                    );
                }

                for suffix_len in 0..=len {
                    input.fill(selected);
                    if suffix_len < len {
                        input[len - suffix_len - 1] = outsider;
                    }
                    let result = scanner.scan_backward(input);
                    assert_eq!(
                        result,
                        AsciiRunResult::new(suffix_len, suffix_len + usize::from(suffix_len < len)),
                        "selected={selected:#04x} len={len} offset={offset} suffix={suffix_len}"
                    );
                }
            }
        }
    }
}

#[test]
#[cfg(not(feature = "static-dispatch"))]
fn portable_run_scanner_random_sets_and_arbitrary_bytes_match_reference() {
    let mut state = 0x0f42_68bd_e315_97ac;
    for _ in 0..10_000 {
        let set = AsciiByteSet::from_words([next_random(&mut state), next_random(&mut state)]);
        let scanner = AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::Portable).unwrap();
        let len = usize::from(next_random(&mut state).to_le_bytes()[0]);
        let offset = usize::from(next_random(&mut state).to_le_bytes()[0] & 0x1f);
        let mut storage = vec![0_u8; offset + len];
        for byte in &mut storage[offset..] {
            *byte = next_random(&mut state).to_le_bytes()[0];
        }
        let bytes = &storage[offset..];
        let forward = scanner.scan_forward(bytes);
        let backward = scanner.scan_backward(bytes);
        assert_run_result(&scanner, bytes, forward, backward);
        assert_eq!(
            forward.examined_bytes(),
            forward.member_run_len() + usize::from(forward.member_run_len() != bytes.len())
        );
        assert_eq!(
            backward.examined_bytes(),
            backward.member_run_len() + usize::from(backward.member_run_len() != bytes.len())
        );
    }
}

#[test]
#[cfg(not(feature = "static-dispatch"))]
fn portable_complement_opt_in_preserves_scalar_semantics_and_default_selection() {
    let set = all_ascii_except(&[0, 15, 16, 63, 64, 95, 112, 127]);
    let context = SimdDispatchContext::capture();
    let complement = context
        .ascii_byte_set_run_scanner_prefer_small_complement(set, DispatchPolicy::Portable)
        .expect("portable complement-aware scanner");
    let ordinary = context
        .ascii_byte_set_run_scanner(set, DispatchPolicy::Portable)
        .expect("portable ordinary scanner");
    for scanner in [complement, ordinary] {
        assert_eq!(
            scanner.selection().variant_id,
            "ascii-byte-set.run.scalar.v1"
        );
        for barrier in 0_u8..=u8::MAX {
            if set.contains(barrier) {
                continue;
            }
            let mut bytes = [b'a'; ASCII_WIDE_BYTES + 1];
            for position in [0, 1, 15, 16, 31, 32] {
                bytes.fill(b'a');
                bytes[position] = barrier;
                assert_run_result(
                    &scanner,
                    &bytes,
                    scanner.scan_forward(&bytes),
                    scanner.scan_backward(&bytes),
                );
            }
        }
    }
}

#[test]
fn run_scanner_empty_full_clone_context_and_non_ascii_semantics_are_stable() {
    let context = SimdDispatchContext::capture();
    for set in [AsciiByteSet::EMPTY, AsciiByteSet::ALL] {
        let explicit = context
            .ascii_byte_set_run_scanner(set, DispatchPolicy::Auto)
            .unwrap();
        let convenience = AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::Auto).unwrap();
        assert_eq!(explicit.selection(), convenience.selection());
        assert_eq!(explicit.set(), set);
        let cloned = explicit;
        for bytes in [
            b"".as_slice(),
            b"ascii".as_slice(),
            b"\x00\x7f\x80\xff".as_slice(),
        ] {
            assert_eq!(cloned.scan_forward(bytes), explicit.scan_forward(bytes));
            assert_eq!(cloned.scan_backward(bytes), explicit.scan_backward(bytes));
            assert_run_result(
                &explicit,
                bytes,
                explicit.scan_forward(bytes),
                explicit.scan_backward(bytes),
            );
        }
    }
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
fn host_auto_run_selection_is_authorized_and_uses_only_qualified_tuning() {
    let sparse = AsciiByteSetRunScanner::new(singleton(b'x'));
    let dense = AsciiByteSetRunScanner::new(AsciiByteSet::ALL);
    #[cfg(target_arch = "aarch64")]
    let usable = host().usable();

    #[cfg(target_arch = "aarch64")]
    {
        if usable.contains(Feature::ArmNeon) {
            #[cfg(all(target_os = "linux", target_endian = "little"))]
            let tuned_hybrid = is_neoverse_v3(host().tuning())
                && usable.contains(Feature::ArmSve)
                && usable.contains(Feature::ArmSve2);
            #[cfg(not(all(target_os = "linux", target_endian = "little")))]
            let tuned_hybrid = false;
            if tuned_hybrid {
                assert_eq!(
                    sparse.selection().variant_id,
                    "ascii-byte-set.run.neon-sve2.arm-41-d84.v1"
                );
                assert_eq!(
                    sparse.selection().required,
                    FeatureSet::EMPTY
                        .with(Feature::ArmNeon)
                        .with(Feature::ArmSve)
                        .with(Feature::ArmSve2)
                );
                assert_eq!(sparse.selection().vector, VectorKind::Scalable);
            } else {
                assert_eq!(sparse.selection().variant_id, "ascii-byte-set.run.neon.v1");
                assert_eq!(
                    sparse.selection().required,
                    FeatureSet::of(Feature::ArmNeon)
                );
                assert_eq!(
                    sparse.selection().vector,
                    VectorKind::Fixed {
                        bytes: u16::try_from(ASCII_NARROW_BYTES).unwrap()
                    }
                );
            }
            assert_eq!(dense.selection().variant_id, "ascii-byte-set.run.neon.v1");
            assert_eq!(dense.selection().required, FeatureSet::of(Feature::ArmNeon));
            assert_eq!(
                dense.selection().vector,
                VectorKind::Fixed {
                    bytes: u16::try_from(ASCII_NARROW_BYTES).unwrap()
                }
            );
        } else {
            #[cfg(all(target_os = "linux", target_endian = "little"))]
            {
                if usable.contains(Feature::ArmSve) && usable.contains(Feature::ArmSve2) {
                    assert_eq!(
                        sparse.selection().variant_id,
                        "ascii-byte-set.run.sve2-match16.v1"
                    );
                    assert_eq!(
                        sparse.selection().required,
                        FeatureSet::EMPTY
                            .with(Feature::ArmSve)
                            .with(Feature::ArmSve2)
                    );
                } else if usable.contains(Feature::ArmSve) {
                    assert_eq!(sparse.selection().variant_id, "ascii-byte-set.run.sve.v1");
                    assert_eq!(sparse.selection().required, FeatureSet::of(Feature::ArmSve));
                } else {
                    assert_eq!(
                        sparse.selection().variant_id,
                        "ascii-byte-set.run.scalar.v1"
                    );
                }
                let expected_dense = if usable.contains(Feature::ArmSve) {
                    "ascii-byte-set.run.sve.v1"
                } else {
                    "ascii-byte-set.run.scalar.v1"
                };
                assert_eq!(dense.selection().variant_id, expected_dense);
            }
            #[cfg(not(all(target_os = "linux", target_endian = "little")))]
            for scanner in [sparse, dense] {
                assert_eq!(
                    scanner.selection().variant_id,
                    "ascii-byte-set.run.scalar.v1"
                );
            }
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    for scanner in [sparse, dense] {
        assert_eq!(
            scanner.selection().variant_id,
            "ascii-byte-set.run.scalar.v1"
        );
        assert!(scanner.selection().required.is_empty());
        assert_eq!(scanner.selection().vector, VectorKind::Scalar);
    }
}

#[test]
fn host_auto_complement_selection_is_explicit_and_uses_only_qualified_tuning() {
    let set = all_ascii_except(b"\n\r");
    let context = SimdDispatchContext::capture();
    let complement = context
        .ascii_byte_set_run_scanner_prefer_small_complement(set, DispatchPolicy::Auto)
        .expect("automatic complement-aware scanner");
    let ordinary = context
        .ascii_byte_set_run_scanner(set, DispatchPolicy::Auto)
        .expect("automatic ordinary scanner");
    assert!(!ordinary.selection().variant_id.contains("complement"));

    #[cfg(target_arch = "aarch64")]
    {
        let usable = host().usable();
        if usable.contains(Feature::ArmNeon) {
            #[cfg(all(target_os = "linux", target_endian = "little"))]
            let expected = if is_neoverse_v3(host().tuning())
                && usable.contains(Feature::ArmSve)
                && usable.contains(Feature::ArmSve2)
            {
                "ascii-byte-set.run.sve2-complement16.arm-41-d84.v1"
            } else {
                "ascii-byte-set.run.neon.v1"
            };
            #[cfg(not(all(target_os = "linux", target_endian = "little")))]
            let expected = "ascii-byte-set.run.neon.v1";
            assert_eq!(complement.selection().variant_id, expected);
            if expected == "ascii-byte-set.run.sve2-complement16.arm-41-d84.v1" {
                assert_eq!(
                    complement.selection().required,
                    FeatureSet::EMPTY
                        .with(Feature::ArmSve)
                        .with(Feature::ArmSve2),
                    "the tuned direct complement leaf must not claim an unused NEON requirement"
                );
                assert_eq!(complement.selection().vector, VectorKind::Scalable);
                assert_eq!(complement.selection().delegate_variant_id, None);
            }
        } else {
            #[cfg(all(target_os = "linux", target_endian = "little"))]
            let expected = if usable.contains(Feature::ArmSve) && usable.contains(Feature::ArmSve2)
            {
                "ascii-byte-set.run.sve2-complement16.v1"
            } else if usable.contains(Feature::ArmSve) {
                "ascii-byte-set.run.sve.v1"
            } else {
                "ascii-byte-set.run.scalar.v1"
            };
            #[cfg(not(all(target_os = "linux", target_endian = "little")))]
            let expected = "ascii-byte-set.run.scalar.v1";
            assert_eq!(complement.selection().variant_id, expected);
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    assert_eq!(
        complement.selection().variant_id,
        "ascii-byte-set.run.scalar.v1"
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

    let run_error =
        AsciiByteSetRunScanner::with_policy(AsciiByteSet::ALL, DispatchPolicy::Require(required))
            .unwrap_err();
    assert_eq!(run_error.required, required);
    assert!(!run_error.usable.contains_all(required));
}

#[test]
fn masks_preserve_lane_order_prefixes_and_full_width_boundaries() {
    let narrow_classifier = AsciiByteSetClassifier::new(AsciiByteSet::ALL);
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
#[cfg(not(feature = "static-dispatch"))]
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

#[cfg(target_arch = "aarch64")]
#[cfg(not(feature = "static-dispatch"))]
#[test]
#[allow(
    unsafe_code,
    reason = "the test gates both private NEON run leaves on the same immutable OS-usable feature used by production dispatch"
)]
fn forced_neon_run_scanner_exhausts_boundaries_and_reports_recovery_work() {
    let required = FeatureSet::of(Feature::ArmNeon);
    if !host().usable().contains_all(required) {
        return;
    }
    let set = singleton(b'a');
    let scanner =
        AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::AllowOnly(required)).unwrap();
    assert_eq!(scanner.selection().variant_id, "ascii-byte-set.run.neon.v1");
    assert_eq!(scanner.selection().required, required);
    assert_eq!(
        scanner.selection().vector,
        VectorKind::Fixed {
            bytes: u16::try_from(ASCII_NARROW_BYTES).unwrap()
        }
    );
    let (tables, table_mode) = set.run_tables(false);
    assert_eq!(table_mode, AsciiRunTableMode::SmallMembers);

    for len in 0..=ASCII_WIDE_BYTES * 3 + 1 {
        for offset in 0..64 {
            let mut storage = vec![0xcc; offset + len];
            let bytes = &mut storage[offset..];

            for prefix_len in 0..=len {
                bytes.fill(b'a');
                if prefix_len < len {
                    bytes[prefix_len] = b'!';
                }
                let observed = scanner.scan_forward(bytes);
                let logical = prefix_len + usize::from(prefix_len < len);
                let failed_full_block =
                    prefix_len < len && prefix_len < len / ASCII_NARROW_BYTES * ASCII_NARROW_BYTES;
                let expected = AsciiRunResult::new(
                    prefix_len,
                    logical
                        + usize::from(failed_full_block) * ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD,
                );
                assert_eq!(observed, expected);
                // SAFETY: the host gate proves NEON usable and `tables` and the
                // slice satisfy the private direct entry's exact invariants.
                assert_eq!(
                    unsafe { aarch64::scan_run_forward_neon(&tables, bytes) },
                    expected
                );
            }

            for suffix_len in 0..=len {
                bytes.fill(b'a');
                if suffix_len < len {
                    bytes[len - suffix_len - 1] = b'!';
                }
                let observed = scanner.scan_backward(bytes);
                let logical = suffix_len + usize::from(suffix_len < len);
                let failure_index = len.checked_sub(suffix_len + 1);
                let failed_full_block =
                    failure_index.is_some_and(|index| index >= len % ASCII_NARROW_BYTES);
                let expected = AsciiRunResult::new(
                    suffix_len,
                    logical
                        + usize::from(failed_full_block) * ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD,
                );
                assert_eq!(observed, expected);
                // SAFETY: identical NEON, table, and source-extent proof to the
                // direct forward assertion above.
                assert_eq!(
                    unsafe { aarch64::scan_run_backward_neon(&tables, bytes) },
                    expected
                );
            }
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
#[cfg(not(feature = "static-dispatch"))]
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
fn expected_sve_forward_result(member_run_len: usize, input_len: usize) -> AsciiRunResult {
    if member_run_len == input_len {
        return AsciiRunResult::new(input_len, input_len);
    }
    let block_start = (member_run_len / ASCII_NARROW_BYTES)
        .checked_mul(ASCII_NARROW_BYTES)
        .unwrap();
    let active = input_len
        .checked_sub(block_start)
        .unwrap()
        .min(ASCII_NARROW_BYTES);
    AsciiRunResult::new(member_run_len, block_start.checked_add(active).unwrap())
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
fn expected_sve_backward_result(member_run_len: usize, input_len: usize) -> AsciiRunResult {
    if member_run_len == input_len {
        return AsciiRunResult::new(input_len, input_len);
    }
    let loaded_blocks = (member_run_len / ASCII_NARROW_BYTES)
        .checked_add(1)
        .unwrap();
    AsciiRunResult::new(
        member_run_len,
        input_len.min(loaded_blocks.checked_mul(ASCII_NARROW_BYTES).unwrap()),
    )
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
#[cfg(not(feature = "static-dispatch"))]
#[test]
#[allow(
    unsafe_code,
    reason = "the test gates private base-SVE run leaves on the same immutable OS-usable feature used by production dispatch"
)]
fn forced_base_sve_run_scanner_exhausts_fixed_sixteen_lane_boundaries() {
    let required = FeatureSet::of(Feature::ArmSve);
    if !host().usable().contains_all(required) {
        return;
    }
    let set = AsciiByteSet::from_words([0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa]);
    let scanner =
        AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::AllowOnly(required)).unwrap();
    assert_eq!(scanner.selection().variant_id, "ascii-byte-set.run.sve.v1");
    assert_eq!(scanner.selection().required, required);
    assert_eq!(scanner.selection().vector, VectorKind::Scalable);
    let (tables, table_mode) = set.run_tables(false);
    assert_eq!(table_mode, AsciiRunTableMode::Generic);

    let member = (0_u8..=0x7f).find(|&byte| set.contains(byte)).unwrap();
    let outsider = (0_u8..=u8::MAX).find(|&byte| !set.contains(byte)).unwrap();
    for len in 0..=ASCII_WIDE_BYTES * 3 + 1 {
        for offset in 0..64 {
            let mut storage = vec![0xdd; offset + len];
            let bytes = &mut storage[offset..];
            for prefix_len in 0..=len {
                bytes.fill(member);
                if prefix_len < len {
                    bytes[prefix_len] = outsider;
                }
                let expected = expected_sve_forward_result(prefix_len, len);
                assert_eq!(scanner.scan_forward(bytes), expected);
                // SAFETY: the host gate proves SVE usable and the private leaf
                // receives its construction-time tables and exact source slice.
                assert_eq!(
                    unsafe { aarch64_sve2::scan_run_forward_sve(&tables, bytes) },
                    expected
                );
            }
            for suffix_len in 0..=len {
                bytes.fill(member);
                if suffix_len < len {
                    bytes[len - suffix_len - 1] = outsider;
                }
                let expected = expected_sve_backward_result(suffix_len, len);
                assert_eq!(scanner.scan_backward(bytes), expected);
                // SAFETY: identical SVE, table, and source proof to the direct
                // forward assertion.
                assert_eq!(
                    unsafe { aarch64_sve2::scan_run_backward_sve(&tables, bytes) },
                    expected
                );
            }
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
#[cfg(not(feature = "static-dispatch"))]
#[test]
#[allow(
    unsafe_code,
    clippy::arithmetic_side_effects,
    reason = "the test gates private SVE2 MATCH run leaves on independently proved immutable SVE and SVE2 host facts"
)]
fn forced_sve2_match_run_scanner_covers_every_small_set_size_and_lane() {
    let required = FeatureSet::EMPTY
        .with(Feature::ArmSve)
        .with(Feature::ArmSve2);
    if !host().usable().contains_all(required) {
        return;
    }

    for cardinality in 1..=ASCII_NARROW_BYTES {
        let mut words = [0_u64; 2];
        for member in 0..cardinality {
            let byte = u8::try_from(member * 7).unwrap();
            words[usize::from(byte >> 6)] |= 1_u64 << (byte & 0x3f);
        }
        let set = AsciiByteSet::from_words(words);
        let scanner =
            AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::AllowOnly(required)).unwrap();
        assert_eq!(
            scanner.selection().variant_id,
            "ascii-byte-set.run.sve2-match16.v1"
        );
        assert_eq!(scanner.selection().required, required);
        assert_eq!(scanner.selection().vector, VectorKind::Scalable);
        let (tables, table_mode) = set.run_tables(false);
        assert_eq!(table_mode, AsciiRunTableMode::SmallMembers);
        let member = tables.match_values[cardinality - 1];
        let outsider = (0_u8..=u8::MAX).find(|&byte| !set.contains(byte)).unwrap();

        for len in 0..=ASCII_WIDE_BYTES * 2 + 1 {
            let mut bytes = vec![member; len];
            for prefix_len in 0..=len {
                bytes.fill(member);
                if prefix_len < len {
                    bytes[prefix_len] = outsider;
                }
                let expected = expected_sve_forward_result(prefix_len, len);
                assert_eq!(scanner.scan_forward(&bytes), expected);
                // SAFETY: SVE and SVE2 are proved usable, the compiled set is
                // nonempty and at most 16 values, and the slice proves loads.
                assert_eq!(
                    unsafe { aarch64_sve2::scan_run_forward_sve2(&tables, &bytes) },
                    expected
                );
            }
            for suffix_len in 0..=len {
                bytes.fill(member);
                if suffix_len < len {
                    bytes[len - suffix_len - 1] = outsider;
                }
                let expected = expected_sve_backward_result(suffix_len, len);
                assert_eq!(scanner.scan_backward(&bytes), expected);
                // SAFETY: identical feature, compiled-set, and source proof to
                // the direct forward call.
                assert_eq!(
                    unsafe { aarch64_sve2::scan_run_backward_sve2(&tables, &bytes) },
                    expected
                );
            }
        }
    }

    let aligned_set = singleton(b'a');
    let aligned_scanner =
        AsciiByteSetRunScanner::with_policy(aligned_set, DispatchPolicy::AllowOnly(required))
            .unwrap();
    let (aligned_tables, table_mode) = aligned_set.run_tables(false);
    assert_eq!(table_mode, AsciiRunTableMode::SmallMembers);
    let len = ASCII_WIDE_BYTES + 1;
    let mut storage = vec![b'a'; 64 + len];
    let mut observed_alignments = [false; 64];
    for offset in 0..64 {
        let bytes = &mut storage[offset..offset + len];
        observed_alignments[bytes.as_ptr().addr() & 63] = true;
        bytes.fill(b'a');
        bytes[17] = b'!';
        let forward = expected_sve_forward_result(17, len);
        assert_eq!(aligned_scanner.scan_forward(bytes), forward);
        // SAFETY: the feature and compiled-set gate above applies at every
        // address modulo a cache line.
        assert_eq!(
            unsafe { aarch64_sve2::scan_run_forward_sve2(&aligned_tables, bytes) },
            forward
        );
        bytes.fill(b'a');
        bytes[len - 17 - 1] = b'!';
        let backward = expected_sve_backward_result(17, len);
        assert_eq!(aligned_scanner.scan_backward(bytes), backward);
        // SAFETY: identical gate and exact slice extent to the forward call.
        assert_eq!(
            unsafe { aarch64_sve2::scan_run_backward_sve2(&aligned_tables, bytes) },
            backward
        );
    }
    assert!(observed_alignments.into_iter().all(core::convert::identity));

    let dense = AsciiByteSet::ALL;
    let fallback =
        AsciiByteSetRunScanner::with_policy(dense, DispatchPolicy::AllowOnly(required)).unwrap();
    assert_eq!(
        fallback.selection().variant_id,
        "ascii-byte-set.run.sve.v1",
        "SVE2 MATCH must not receive more than 16 construction-time values"
    );
    assert_eq!(
        fallback.selection().required,
        FeatureSet::of(Feature::ArmSve)
    );
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
#[cfg(not(feature = "static-dispatch"))]
#[test]
#[allow(
    unsafe_code,
    clippy::arithmetic_side_effects,
    reason = "the test gates private complement SVE2 leaves on independently proved immutable SVE and SVE2 host facts"
)]
fn forced_sve2_complement_run_scanner_covers_holes_high_bytes_and_boundaries() {
    let required = FeatureSet::EMPTY
        .with(Feature::ArmSve)
        .with(Feature::ArmSve2);
    if !host().usable().contains_all(required) {
        return;
    }
    let context = SimdDispatchContext::capture();

    for cardinality in 1..=ASCII_NARROW_BYTES {
        let excluded: Vec<_> = (0..cardinality)
            .map(|index| u8::try_from(index * 7).unwrap())
            .collect();
        let set = all_ascii_except(&excluded);
        let scanner = context
            .ascii_byte_set_run_scanner_prefer_small_complement(
                set,
                DispatchPolicy::AllowOnly(required),
            )
            .expect("forced complement SVE2 scanner");
        let expected_variant = if is_neoverse_v3(host().tuning()) {
            "ascii-byte-set.run.sve2-complement16.arm-41-d84.v1"
        } else {
            "ascii-byte-set.run.sve2-complement16.v1"
        };
        assert_eq!(scanner.selection().variant_id, expected_variant);
        assert_eq!(scanner.selection().required, required);
        assert_eq!(scanner.selection().vector, VectorKind::Scalable);
        let (tables, table_mode) = set.run_tables(true);
        assert_eq!(table_mode, AsciiRunTableMode::SmallComplement);
        let member = (0_u8..=0x7f).find(|&byte| set.contains(byte)).unwrap();
        let barrier = excluded[cardinality - 1];

        for len in 0..=ASCII_WIDE_BYTES * 2 + 1 {
            let mut bytes = vec![member; len];
            for prefix_len in 0..=len {
                bytes.fill(member);
                if prefix_len < len {
                    bytes[prefix_len] = barrier;
                }
                let expected = expected_sve_forward_result(prefix_len, len);
                assert_eq!(scanner.scan_forward(&bytes), expected);
                // SAFETY: the host gate, complement table mode, and exact
                // source slice prove every direct-leaf precondition.
                assert_eq!(
                    unsafe { aarch64_sve2::scan_run_forward_sve2_complement(&tables, &bytes) },
                    expected
                );
            }
            for suffix_len in 0..=len {
                bytes.fill(member);
                if suffix_len < len {
                    bytes[len - suffix_len - 1] = barrier;
                }
                let expected = expected_sve_backward_result(suffix_len, len);
                assert_eq!(scanner.scan_backward(&bytes), expected);
                // SAFETY: identical feature, table, and source proof to the
                // direct forward assertion.
                assert_eq!(
                    unsafe { aarch64_sve2::scan_run_backward_sve2_complement(&tables, &bytes) },
                    expected
                );
            }
        }
    }

    let excluded = [0, 15, 16, 31, 32, 63, 64, 95, 112, 127];
    let set = all_ascii_except(&excluded);
    let scanner = context
        .ascii_byte_set_run_scanner_prefer_small_complement(
            set,
            DispatchPolicy::AllowOnly(required),
        )
        .unwrap();
    let member = b'a';
    let len = ASCII_WIDE_BYTES + 1;
    let mut storage = vec![member; 64 + len];
    let mut observed_alignments = [false; 64];
    for offset in 0..64 {
        let bytes = &mut storage[offset..offset + len];
        observed_alignments[bytes.as_ptr().addr() & 63] = true;
        for barrier in 0x80_u8..=u8::MAX {
            for position in 0..len {
                bytes.fill(member);
                bytes[position] = barrier;
                assert_eq!(
                    scanner.scan_forward(bytes),
                    expected_sve_forward_result(position, len),
                    "offset={offset} barrier={barrier:#04x} position={position}"
                );
                assert_eq!(
                    scanner.scan_backward(bytes),
                    expected_sve_backward_result(len - position - 1, len),
                    "offset={offset} barrier={barrier:#04x} position={position}"
                );
            }
        }
    }
    assert!(observed_alignments.into_iter().all(core::convert::identity));

    let (tables, table_mode) = set.run_tables(true);
    assert_eq!(table_mode, AsciiRunTableMode::SmallComplement);
    for len in [79, 80, 81, 127, 128, 129, 143, 144, 145] {
        for offset in [0, 1, 7, 15, 16, 31, 63] {
            let mut storage = vec![member; offset + len];
            let bytes = &mut storage[offset..];
            for barrier in [excluded[0], excluded[5], 0x80, 0xbf, 0xff] {
                for prefix_len in 0..=len {
                    bytes.fill(member);
                    if prefix_len < len {
                        bytes[prefix_len] = barrier;
                    }
                    let expected = expected_sve_forward_result(prefix_len, len);
                    assert_eq!(scanner.scan_forward(bytes), expected);
                    // SAFETY: the same feature, table-mode, and slice proof as
                    // the exhaustive short-input matrix applies here.
                    assert_eq!(
                        unsafe { aarch64_sve2::scan_run_forward_sve2_complement(&tables, bytes) },
                        expected
                    );
                }
                for suffix_len in 0..=len {
                    bytes.fill(member);
                    if suffix_len < len {
                        bytes[len - suffix_len - 1] = barrier;
                    }
                    let expected = expected_sve_backward_result(suffix_len, len);
                    assert_eq!(scanner.scan_backward(bytes), expected);
                    // SAFETY: identical proof to the long forward assertion.
                    assert_eq!(
                        unsafe { aarch64_sve2::scan_run_backward_sve2_complement(&tables, bytes) },
                        expected
                    );
                }
            }
        }
    }

    for excluded in [Vec::new(), (0_u8..=16).collect()] {
        let set = all_ascii_except(&excluded);
        let (_, table_mode) = set.run_tables(true);
        assert_eq!(table_mode, AsciiRunTableMode::Generic);
        let scanner = context
            .ascii_byte_set_run_scanner_prefer_small_complement(
                set,
                DispatchPolicy::AllowOnly(required),
            )
            .unwrap();
        assert_eq!(scanner.selection().variant_id, "ascii-byte-set.run.sve.v1");
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
#[test]
fn neoverse_v3_hybrid_run_scanner_preserves_boundaries_and_work_envelope() {
    let scanner = AsciiByteSetRunScanner::new(singleton(b'a'));
    if scanner.selection().variant_id != "ascii-byte-set.run.neon-sve2.arm-41-d84.v1" {
        return;
    }
    for len in 0..=ASCII_WIDE_BYTES * 3 + 1 {
        for offset in 0..ASCII_NARROW_BYTES {
            let mut storage = vec![0xcc; offset + len];
            let bytes = &mut storage[offset..];
            for prefix_len in 0..=len {
                bytes.fill(b'a');
                if prefix_len < len {
                    bytes[prefix_len] = b'!';
                }
                let observed = scanner.scan_forward(bytes);
                assert_eq!(observed.member_run_len(), prefix_len);
                let logical = prefix_len + usize::from(prefix_len < len);
                assert!(
                    (logical..=logical + ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
                        .contains(&observed.examined_bytes())
                );
            }
            for suffix_len in 0..=len {
                bytes.fill(b'a');
                if suffix_len < len {
                    bytes[len - suffix_len - 1] = b'!';
                }
                let observed = scanner.scan_backward(bytes);
                assert_eq!(observed.member_run_len(), suffix_len);
                let logical = suffix_len + usize::from(suffix_len < len);
                assert!(
                    (logical..=logical + ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
                        .contains(&observed.examined_bytes())
                );
            }
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
#[test]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the bounded tuned-complement matrix uses small fixture lengths and lane indices"
)]
fn neoverse_v3_direct_complement_preserves_barriers_and_exact_work() {
    let set = all_ascii_except(b"\n\r");
    let scanner = SimdDispatchContext::capture()
        .ascii_byte_set_run_scanner_prefer_small_complement(set, DispatchPolicy::Auto)
        .expect("automatic complement scanner");
    if scanner.selection().variant_id != "ascii-byte-set.run.sve2-complement16.arm-41-d84.v1" {
        return;
    }
    assert_eq!(scanner.set(), set);
    for len in 0..=ASCII_WIDE_BYTES * 3 + 1 {
        for offset in 0..ASCII_NARROW_BYTES {
            let mut storage = vec![0xcc; offset + len];
            let bytes = &mut storage[offset..];
            for (barrier_index, barrier) in [b'\n', b'\r', 0x80, 0xbf, 0xc2, 0xff]
                .into_iter()
                .enumerate()
            {
                for prefix_len in 0..=len {
                    bytes.fill(b'a');
                    if prefix_len < len {
                        bytes[prefix_len] = barrier;
                    }
                    let observed = scanner.scan_forward(bytes);
                    assert_eq!(
                        observed,
                        expected_sve_forward_result(prefix_len, len),
                        "len={len} offset={offset} barrier_index={barrier_index}"
                    );
                }
                for suffix_len in 0..=len {
                    bytes.fill(b'a');
                    if suffix_len < len {
                        bytes[len - suffix_len - 1] = barrier;
                    }
                    let observed = scanner.scan_backward(bytes);
                    assert_eq!(
                        observed,
                        expected_sve_backward_result(suffix_len, len),
                        "len={len} offset={offset} barrier_index={barrier_index}"
                    );
                }
            }
        }
    }

    for len in [127, 128, 129, 143, 144, 145, 159, 160, 161] {
        for offset in [0, 1, 7, 15] {
            let mut storage = vec![0xcc; offset + len];
            let bytes = &mut storage[offset..];
            for barrier in [b'\n', b'\r', 0x80, 0xbf, 0xff] {
                for prefix_len in 0..=len {
                    bytes.fill(b'a');
                    if prefix_len < len {
                        bytes[prefix_len] = barrier;
                    }
                    assert_eq!(
                        scanner.scan_forward(bytes),
                        expected_sve_forward_result(prefix_len, len),
                        "long len={len} offset={offset} barrier={barrier:#04x}"
                    );
                }
                for suffix_len in 0..=len {
                    bytes.fill(b'a');
                    if suffix_len < len {
                        bytes[len - suffix_len - 1] = barrier;
                    }
                    assert_eq!(
                        scanner.scan_backward(bytes),
                        expected_sve_backward_result(suffix_len, len),
                        "long len={len} offset={offset} barrier={barrier:#04x}"
                    );
                }
            }
        }
    }
}

#[cfg(all(
    not(feature = "static-dispatch"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little"
))]
#[derive(Debug)]
struct RunBenchmarkCase {
    bytes: Box<[u8]>,
    backward: bool,
}

#[cfg(all(
    not(feature = "static-dispatch"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little"
))]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the bounded benchmark fixtures use small compile-time lengths and lane indices"
)]
fn run_benchmark_cases() -> Vec<RunBenchmarkCase> {
    let mut cases = Vec::new();
    for len in [0, 1, 7, 15, 16, 17, 31, 32, 33, 47, 63, 64, 65, 257, 1024] {
        for backward in [false, true] {
            cases.push(RunBenchmarkCase {
                bytes: vec![b'a'; len].into_boxed_slice(),
                backward,
            });
        }
    }
    for lane in 0..ASCII_NARROW_BYTES {
        let len = ASCII_NARROW_BYTES * 8 + 7;
        let distance = ASCII_NARROW_BYTES * 2 + lane;
        let mut forward = vec![b'a'; len];
        forward[distance] = b'!';
        cases.push(RunBenchmarkCase {
            bytes: forward.into_boxed_slice(),
            backward: false,
        });
        let mut backward = vec![b'a'; len];
        backward[len - distance - 1] = b'!';
        cases.push(RunBenchmarkCase {
            bytes: backward.into_boxed_slice(),
            backward: true,
        });
    }
    for len in [3, 9, 14, 18, 23, 30, 34, 41, 62, 70] {
        let mut forward = vec![b'a'; len];
        forward[len / 2] = b'!';
        cases.push(RunBenchmarkCase {
            bytes: forward.into_boxed_slice(),
            backward: false,
        });
        let mut backward = vec![b'a'; len];
        backward[len / 2] = b'!';
        cases.push(RunBenchmarkCase {
            bytes: backward.into_boxed_slice(),
            backward: true,
        });
    }
    cases
}

#[cfg(all(
    not(feature = "static-dispatch"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little"
))]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the benchmark loop uses proved nonempty case arrays and bounded timing/checksum arithmetic"
)]
fn measure_run_scanner(
    scanner: &AsciiByteSetRunScanner,
    cases: &[RunBenchmarkCase],
    iterations: u32,
) -> f64 {
    assert!(iterations > 0);
    assert!(!cases.is_empty());
    let started = std::time::Instant::now();
    let mut checksum = 0_usize;
    for iteration in 0..iterations {
        let index = usize::try_from(std::hint::black_box(iteration)).unwrap() % cases.len();
        let case = &cases[index];
        let result = if case.backward {
            std::hint::black_box(scanner).scan_backward(std::hint::black_box(&case.bytes))
        } else {
            std::hint::black_box(scanner).scan_forward(std::hint::black_box(&case.bytes))
        };
        checksum ^= result
            .member_run_len()
            .rotate_left(u32::try_from(index % usize::try_from(usize::BITS).unwrap()).unwrap())
            ^ result.examined_bytes();
    }
    std::hint::black_box(checksum);
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / f64::from(iterations)
}

#[cfg(all(
    not(feature = "static-dispatch"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little"
))]
fn serialize_run_samples(samples: &[f64]) -> String {
    samples
        .iter()
        .map(|sample| format!("{sample:.9}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(all(
    not(feature = "static-dispatch"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little"
))]
#[test]
#[ignore = "native release qualification benchmark; requires NEON, SVE and SVE2 with the scanner's fixed 16 active lanes"]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the ignored native benchmark keeps its four-way parity gate, alternating schedule, raw samples, and machine receipt together"
)]
fn benchmark_direct_run_scanners_scalar_neon_sve_and_sve2() {
    let sve = FeatureSet::of(Feature::ArmSve);
    let sve2 = sve.with(Feature::ArmSve2);
    let neon = FeatureSet::of(Feature::ArmNeon);
    let usable = host().usable();
    assert!(
        usable.contains_all(neon) && usable.contains_all(sve2),
        "run benchmark requires OS-usable NEON, SVE and SVE2; usable={usable:?}"
    );

    let set = AsciiByteSet::from_words([
        1_u64 << b'0',
        (1_u64 << b'_'.wrapping_sub(64))
            | (1_u64 << b'a'.wrapping_sub(64))
            | (1_u64 << b'b'.wrapping_sub(64)),
    ]);
    let scalar =
        AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::Portable).expect("scalar scanner");
    let neon_scanner = AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::AllowOnly(neon))
        .expect("NEON scanner");
    let base_sve_scanner = AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::AllowOnly(sve))
        .expect("base-SVE scanner");
    let match_scanner = AsciiByteSetRunScanner::with_policy(set, DispatchPolicy::AllowOnly(sve2))
        .expect("SVE2 scanner");
    assert_eq!(
        scalar.selection().variant_id,
        "ascii-byte-set.run.scalar.v1"
    );
    assert_eq!(
        neon_scanner.selection().variant_id,
        "ascii-byte-set.run.neon.v1"
    );
    assert_eq!(
        base_sve_scanner.selection().variant_id,
        "ascii-byte-set.run.sve.v1"
    );
    assert_eq!(
        match_scanner.selection().variant_id,
        "ascii-byte-set.run.sve2-match16.v1"
    );

    let cases = run_benchmark_cases();
    for case in &cases {
        let reference = if case.backward {
            scalar.scan_backward(&case.bytes).member_run_len()
        } else {
            scalar.scan_forward(&case.bytes).member_run_len()
        };
        for scanner in [&neon_scanner, &base_sve_scanner, &match_scanner] {
            let observed = if case.backward {
                scanner.scan_backward(&case.bytes)
            } else {
                scanner.scan_forward(&case.bytes)
            };
            assert_eq!(observed.member_run_len(), reference);
            let logical = reference + usize::from(reference != case.bytes.len());
            assert!(
                (logical..=logical + ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
                    .contains(&observed.examined_bytes())
            );
        }
    }

    let iterations = std::env::var("FRE_SIMD_RUN_BENCH_ITERS").map_or(2_000_000, |raw| {
        raw.parse::<u32>()
            .unwrap_or_else(|error| panic!("FRE_SIMD_RUN_BENCH_ITERS: {error}"))
    });
    let samples = std::env::var("FRE_SIMD_RUN_BENCH_SAMPLES").map_or(16, |raw| {
        raw.parse::<usize>()
            .unwrap_or_else(|error| panic!("FRE_SIMD_RUN_BENCH_SAMPLES: {error}"))
    });
    assert!(iterations > 0);
    assert!(samples >= 16 && samples.is_multiple_of(4));

    let scanners = [
        ("scalar", &scalar),
        ("neon", &neon_scanner),
        ("sve", &base_sve_scanner),
        ("sve2", &match_scanner),
    ];
    for (_, scanner) in scanners {
        let _ = measure_run_scanner(scanner, &cases, iterations / 10 + 1);
    }

    let mut raw = [
        Vec::with_capacity(samples),
        Vec::with_capacity(samples),
        Vec::with_capacity(samples),
        Vec::with_capacity(samples),
    ];
    let mut orders = Vec::with_capacity(samples);
    for sample in 0..samples {
        let mut order = Vec::with_capacity(scanners.len());
        for slot in 0..scanners.len() {
            let index = (slot + sample) % scanners.len();
            let (name, scanner) = scanners[index];
            order.push(name);
            raw[index].push(measure_run_scanner(scanner, &cases, iterations));
        }
        orders.push(order.join(">"));
    }
    assert!(
        raw.iter()
            .flatten()
            .all(|value| value.is_finite() && *value > 0.0)
    );
    let medians = raw.each_ref().map(|samples| benchmark_median(samples));
    let receipt = format!(
        "SIMD_RUN_BENCH iterations={iterations} samples={samples} cases={} active_bytes=16 \
         scalar_ns={:.9} neon_ns={:.9} sve_ns={:.9} sve2_ns={:.9} \
         neon_over_scalar={:.9} sve_over_neon={:.9} sve2_over_neon={:.9} \
         orders={} scalar_samples={} neon_samples={} sve_samples={} sve2_samples={}",
        cases.len(),
        medians[0],
        medians[1],
        medians[2],
        medians[3],
        medians[1] / medians[0],
        medians[2] / medians[1],
        medians[3] / medians[1],
        orders.join(","),
        serialize_run_samples(&raw[0]),
        serialize_run_samples(&raw[1]),
        serialize_run_samples(&raw[2]),
        serialize_run_samples(&raw[3]),
    );
    assert_eq!(receipt.matches('\n').count(), 0);
    eprintln!("{receipt}");
}

#[cfg(all(
    not(feature = "static-dispatch"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little"
))]
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

#[cfg(all(
    not(feature = "static-dispatch"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little"
))]
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
#[cfg(not(feature = "static-dispatch"))]
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
#[cfg(not(feature = "static-dispatch"))]
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
#[cfg(not(feature = "static-dispatch"))]
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
#[cfg(not(feature = "static-dispatch"))]
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
#[cfg(not(feature = "static-dispatch"))]
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
#[cfg(not(feature = "static-dispatch"))]
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
#[cfg(not(feature = "static-dispatch"))]
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

#[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
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

#[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
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

#[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
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
