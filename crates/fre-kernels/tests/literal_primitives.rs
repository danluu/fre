#![forbid(unsafe_code)]

use fre_kernels::{
    ByteCandidateBuildAttempt, ByteCandidateBuildLimits, ByteCandidatePlan,
    ByteCandidateScanLimits, FoldedLiteral, FoldedLiteralTrieBuildAttempt,
    FoldedLiteralTrieBuildLimits, FoldedLiteralTriePlan, FoldedLiteralTrieScanLimits,
    FoldedScalarClass, LiteralAnchor, LiteralAnchorOffsetBounds, LiteralCandidate, Window,
};

#[test]
fn byte_stream_is_position_density_and_size_independent() {
    let patterns: &[&[u8]] = &[b"aba", b"a", b"aba"];
    let ByteCandidateBuildAttempt::Admitted(plan) =
        ByteCandidatePlan::build(patterns, ByteCandidateBuildLimits::default()).unwrap()
    else {
        panic!("non-empty byte literals must be admitted");
    };
    for (prefix, repeats) in [(0_usize, 1_usize), (7, 3), (31, 17)] {
        let mut source = vec![b'x'; prefix];
        for _ in 0..repeats {
            source.extend_from_slice(b"aba");
        }
        let mut candidates = Vec::new();
        let receipt = plan
            .scan(&source, ByteCandidateScanLimits::unlimited(), |candidate| {
                candidates.push(candidate);
            })
            .unwrap();
        assert_eq!(
            candidates
                .iter()
                .filter(|candidate| candidate.pattern_index() == 0)
                .count(),
            repeats
        );
        assert_eq!(
            candidates
                .iter()
                .filter(|candidate| candidate.pattern_index() == 2)
                .count(),
            repeats
        );
        assert!(receipt.actual.candidate_events <= receipt.upper.candidate_events);
        assert!(receipt.actual.work <= receipt.upper.work);
    }
}

#[test]
fn folded_stream_preserves_utf8_offsets_and_window_boundaries() {
    const KELVIN: [char; 3] = ['K', 'k', '\u{212A}'];
    const SIGMA: [char; 3] = ['Σ', 'ς', 'σ'];
    let classes = [
        FoldedScalarClass::new(&KELVIN),
        FoldedScalarClass::new(&SIGMA),
    ];
    let patterns = [FoldedLiteral::new(&classes), FoldedLiteral::new(&classes)];
    let FoldedLiteralTrieBuildAttempt::Admitted(plan) =
        FoldedLiteralTriePlan::build(&patterns, FoldedLiteralTrieBuildLimits::default()).unwrap()
    else {
        panic!("canonical folded literals must be admitted");
    };
    let source = "zz\u{212A}ς Kσ".as_bytes();
    let mut candidates = Vec::new();
    let receipt = plan
        .scan_window(
            source,
            Window::new(2, source.len()),
            FoldedLiteralTrieScanLimits::unlimited(),
            |candidate| candidates.push(candidate),
        )
        .unwrap();
    assert_eq!(
        candidates,
        [
            LiteralCandidate::new(0, 2, 7),
            LiteralCandidate::new(1, 2, 7),
            LiteralCandidate::new(0, 8, 11),
            LiteralCandidate::new(1, 8, 11),
        ]
    );
    assert!(receipt.actual.decoded_scalars <= receipt.upper.decoded_scalars);
    assert!(receipt.actual.invalid_bytes <= receipt.upper.invalid_bytes);
}

#[test]
fn anchor_recovery_is_independent_of_candidate_source() {
    let before = LiteralAnchorOffsetBounds::new(2, 4).unwrap();
    let after = LiteralAnchorOffsetBounds::new(1, 3).unwrap();
    let anchor = LiteralAnchor::new(5, before, after);
    let recovered = anchor
        .recover(LiteralCandidate::new(5, 10, 13), 20)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.start_bounds().min(), 6);
    assert_eq!(recovered.start_bounds().max(), 8);
    assert_eq!(recovered.end_bounds().min(), 14);
    assert_eq!(recovered.end_bounds().max(), 16);
}
