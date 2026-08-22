use fre_capture_lab::{
    Ast, BuildLimits, CaptureProgramV1, CaptureProgramV1Limits,
    EXACT_SPAN_PARTICIPATION_NATIVE_V1_ACCOUNTING_ID,
    EXACT_SPAN_PARTICIPATION_NATIVE_V1_ALGORITHM_ID, EXACT_SPAN_PARTICIPATION_NATIVE_V1_SEEN_BYTES,
    EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_ALIGN,
    EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_BYTES, ExactSpanParticipationNativeAssertionKindV1,
    ExactSpanParticipationNativeStateV1, ExactSpanParticipationNativeV1Error,
    ExactSpanParticipationNativeV1Limits, ExactSpanParticipationNativeV1Resource, Greed, Program,
};

fn seal(ast: &Ast) -> CaptureProgramV1 {
    let program = Program::compile(ast, BuildLimits::default()).expect("capture program");
    CaptureProgramV1::from_program(program, CaptureProgramV1Limits::default())
        .expect("sealed capture program")
}

fn representative() -> CaptureProgramV1 {
    let ambiguous = Ast::alt([
        Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]),
        Ast::Byte(b'a'),
    ])
    .repeat(1, None, Greed::Greedy)
    .capture(1);
    let optional = Ast::Byte(b'z').capture(2).repeat(0, Some(1), Greed::Greedy);
    seal(&Ast::concat([
        Ast::Assert(fre_capture_lab::Assertion::StartLine(b'|')),
        ambiguous,
        optional,
        Ast::Assert(fre_capture_lab::Assertion::EndLine(b'|')),
    ]))
}

#[test]
fn view_is_complete_digest_bound_and_roundtrip_authentic() {
    let owner = representative();
    let view = owner
        .exact_span_participation_native_v1_view(ExactSpanParticipationNativeV1Limits::default())
        .expect("view construction")
        .expect("supported participation schema");
    assert_eq!(
        view.algorithm_id(),
        EXACT_SPAN_PARTICIPATION_NATIVE_V1_ALGORITHM_ID
    );
    assert_eq!(
        view.accounting_id(),
        EXACT_SPAN_PARTICIPATION_NATIVE_V1_ACCOUNTING_ID
    );
    assert_eq!(view.semantic_digest(), owner.semantic_digest());
    assert!(view.authenticates(&owner));
    assert_eq!(view.state_count(), owner.usage().states);
    assert_eq!(view.states().len(), view.state_count());
    assert!(usize::try_from(view.start_state()).unwrap() < view.state_count());

    let layout = view.layout();
    assert_eq!(layout.group_count(), 3);
    assert_eq!(layout.slot_count(), 6);
    assert_eq!(layout.current_offset(), 0);
    assert_eq!(
        layout.next_offset(),
        layout.state_count() * EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_BYTES
    );
    assert_eq!(layout.stack_offset(), layout.next_offset() * 2);
    assert_eq!(layout.seen_offset(), layout.next_offset() * 3);
    let raw_scratch =
        layout.seen_offset() + layout.state_count() * EXACT_SPAN_PARTICIPATION_NATIVE_V1_SEEN_BYTES;
    assert_eq!(
        layout.scratch_bytes(),
        (raw_scratch + EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_ALIGN - 1)
            & !(EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_ALIGN - 1)
    );
    assert_eq!(
        layout.lowering_work(),
        layout.state_count() + layout.byte_range_count()
    );
    assert_eq!(
        layout.maximum_state_visits(37),
        Some(38 * layout.state_count() * 4)
    );

    let mut byte_ranges = 0_usize;
    let mut saw_split = false;
    let mut saw_save = false;
    let mut saw_assert = false;
    let mut saw_match = false;
    for state in view.states() {
        match state {
            ExactSpanParticipationNativeStateV1::Byte { ranges, next } => {
                assert!(usize::try_from(next).unwrap() < view.state_count());
                assert!(ranges.iter().all(|&(start, end)| start <= end));
                assert!(ranges.windows(2).all(|pair| pair[0].1 < pair[1].0));
                byte_ranges += ranges.len();
            }
            ExactSpanParticipationNativeStateV1::Split { first, second } => {
                assert!(usize::try_from(first).unwrap() < view.state_count());
                assert!(usize::try_from(second).unwrap() < view.state_count());
                saw_split = true;
            }
            ExactSpanParticipationNativeStateV1::Save { slot, next } => {
                assert!(usize::from(slot) < layout.slot_count());
                assert!(usize::try_from(next).unwrap() < view.state_count());
                saw_save = true;
            }
            ExactSpanParticipationNativeStateV1::Assert { next, .. } => {
                assert!(usize::try_from(next).unwrap() < view.state_count());
                saw_assert = true;
            }
            ExactSpanParticipationNativeStateV1::Epsilon { next } => {
                assert!(usize::try_from(next).unwrap() < view.state_count());
            }
            ExactSpanParticipationNativeStateV1::Match => saw_match = true,
            ExactSpanParticipationNativeStateV1::Fail => {}
        }
    }
    assert_eq!(byte_ranges, layout.byte_range_count());
    assert!(saw_split && saw_save && saw_assert && saw_match);

    let restored =
        CaptureProgramV1::deserialize(owner.as_bytes(), CaptureProgramV1Limits::default())
            .expect("roundtrip owner");
    assert!(view.authenticates(&restored));

    let different = seal(&Ast::Byte(b'q').capture(1));
    assert!(!view.authenticates(&different));
}

#[test]
fn all_assertion_kinds_are_projected_without_semantic_collapse() {
    use ExactSpanParticipationNativeAssertionKindV1 as K;
    use fre_capture_lab::Assertion as A;

    let cases = [
        (A::Start, K::Start, 0),
        (A::End, K::End, 0),
        (A::StartLf, K::StartLf, 0),
        (A::EndLf, K::EndLf, 0),
        (A::StartLine(b'|'), K::StartLine, b'|'),
        (A::EndLine(b';'), K::EndLine, b';'),
        (A::StartCrlf, K::StartCrlf, 0),
        (A::EndCrlf, K::EndCrlf, 0),
        (A::WordAscii, K::WordAscii, 0),
        (A::WordAsciiNegate, K::WordAsciiNegate, 0),
        (A::WordStartAscii, K::WordStartAscii, 0),
        (A::WordEndAscii, K::WordEndAscii, 0),
        (A::WordStartHalfAscii, K::WordStartHalfAscii, 0),
        (A::WordEndHalfAscii, K::WordEndHalfAscii, 0),
        (A::WordUnicode, K::WordUnicode, 0),
        (A::WordUnicodeNegate, K::WordUnicodeNegate, 0),
        (A::WordStartUnicode, K::WordStartUnicode, 0),
        (A::WordEndUnicode, K::WordEndUnicode, 0),
        (A::WordStartHalfUnicode, K::WordStartHalfUnicode, 0),
        (A::WordEndHalfUnicode, K::WordEndHalfUnicode, 0),
    ];
    for (source, expected_kind, expected_data) in cases {
        let owner = seal(&Ast::concat([
            Ast::Assert(source),
            Ast::Byte(b'x').capture(1),
        ]));
        let view =
            owner
                .exact_span_participation_native_v1_view(
                    ExactSpanParticipationNativeV1Limits::default(),
                )
                .expect("view")
                .expect("supported");
        let projected = view
            .states()
            .find_map(|state| match state {
                ExactSpanParticipationNativeStateV1::Assert { assertion, .. } => Some(assertion),
                _ => None,
            })
            .expect("assertion state");
        assert_eq!(projected.kind(), expected_kind);
        assert_eq!(projected.data(), expected_data);
    }
}

#[test]
fn resource_checks_have_a_fixed_fail_closed_order() {
    let owner = representative();
    let full = owner
        .exact_span_participation_native_v1_view(ExactSpanParticipationNativeV1Limits::default())
        .unwrap()
        .unwrap()
        .layout();

    let error = owner
        .exact_span_participation_native_v1_view(ExactSpanParticipationNativeV1Limits {
            max_states: full.state_count() - 1,
            max_byte_ranges: 0,
            max_groups: 0,
            max_scratch_bytes: 0,
            max_lowering_work: 0,
        })
        .unwrap_err();
    assert_eq!(
        error,
        ExactSpanParticipationNativeV1Error::Resource {
            resource: ExactSpanParticipationNativeV1Resource::States,
            required: full.state_count(),
            limit: full.state_count() - 1,
        }
    );

    let base = ExactSpanParticipationNativeV1Limits::default();
    for (limits, resource, required) in [
        (
            ExactSpanParticipationNativeV1Limits {
                max_byte_ranges: full.byte_range_count() - 1,
                ..base
            },
            ExactSpanParticipationNativeV1Resource::ByteRanges,
            full.byte_range_count(),
        ),
        (
            ExactSpanParticipationNativeV1Limits {
                max_groups: full.group_count() - 1,
                ..base
            },
            ExactSpanParticipationNativeV1Resource::Groups,
            full.group_count(),
        ),
        (
            ExactSpanParticipationNativeV1Limits {
                max_scratch_bytes: full.scratch_bytes() - 1,
                ..base
            },
            ExactSpanParticipationNativeV1Resource::ScratchBytes,
            full.scratch_bytes(),
        ),
        (
            ExactSpanParticipationNativeV1Limits {
                max_lowering_work: full.lowering_work() - 1,
                ..base
            },
            ExactSpanParticipationNativeV1Resource::LoweringWork,
            full.lowering_work(),
        ),
    ] {
        assert_eq!(
            owner
                .exact_span_participation_native_v1_view(limits)
                .unwrap_err(),
            ExactSpanParticipationNativeV1Error::Resource {
                resource,
                required,
                limit: required - 1,
            }
        );
    }
}

#[test]
fn wider_than_one_word_schema_declines_before_projection() {
    let captures = (1_u32..=64).map(|index| Ast::Empty.capture(index));
    let owner = seal(&Ast::concat(captures));
    assert_eq!(owner.schema().group_count(), 65);
    assert!(
        owner
            .exact_span_participation_native_v1_view(
                ExactSpanParticipationNativeV1Limits::default(),
            )
            .expect("stable schema decline")
            .is_none()
    );
}
