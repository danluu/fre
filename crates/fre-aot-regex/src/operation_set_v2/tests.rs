#![allow(
    clippy::arithmetic_side_effects,
    reason = "test fixtures use already-bounded canonical wire offsets"
)]

use super::*;
use crate::{CompileMode, CompileRequest, Target, compile};
use fre_capture_lab::{Ast, BuildLimits, Program};

fn compiled_program(pattern: &str, output: OutputContract) -> Vec<u8> {
    compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(output),
    )
    .expect("compile V2 operation-set fixture")
    .program()
    .serialize()
    .expect("serialize V2 operation-set fixture")
}

fn capture_program(ast: &Ast) -> Vec<u8> {
    let program =
        Program::compile(ast, BuildLimits::default()).expect("compile V2 capture-program fixture");
    CaptureProgramV1::from_program(program, CaptureProgramV1Limits::default())
        .expect("serialize V2 capture-program fixture")
        .as_bytes()
        .to_vec()
}

fn overwrite_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn overwrite_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn overwrite_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn header_offset(bytes: &[u8], offset: usize) -> usize {
    usize_from_u64(read_u64(bytes, offset).expect("header offset"))
        .expect("header offset fits host")
}

fn raw_single_member_wire(
    kind: AotOperationSetMemberKindV2,
    axes: AotOperationAxesV2,
    payload: &[u8],
) -> Vec<u8> {
    let output = axes.validate(0).expect("raw fixture uses admitted axes");
    let member_table_offset = AOT_OPERATION_SET_V2_HEADER_BYTES;
    let shared_table_offset = member_table_offset + AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES;
    let root_table_offset = shared_table_offset;
    let stage_table_offset = root_table_offset + AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES;
    let output_table_offset = stage_table_offset + AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES;
    let payload_offset = output_table_offset + AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES;
    let total_bytes = payload_offset + payload.len();
    let mut wire = Vec::with_capacity(total_bytes);
    emit_header(
        &mut wire,
        total_bytes,
        1,
        1,
        member_table_offset,
        shared_table_offset,
        root_table_offset,
        stage_table_offset,
        output_table_offset,
        payload_offset,
    )
    .expect("emit raw fixture header");
    put_u32(&mut wire, kind.tag());
    put_u32(&mut wire, 0);
    put_u32(&mut wire, AOT_OPERATION_SET_V2_NONE_INDEX);
    put_u32(&mut wire, AOT_OPERATION_SET_V2_NONE_INDEX);
    put_usize_as_u64(&mut wire, payload_offset).expect("payload offset");
    put_usize_as_u64(&mut wire, payload.len()).expect("payload length");

    put_u32(&mut wire, 0);
    put_u32(&mut wire, 1);
    put_u32(&mut wire, 0);
    put_u32(&mut wire, 1);
    put_u32(&mut wire, 0);
    put_u32(&mut wire, 0);

    put_u32(&mut wire, 0);
    put_u16(&mut wire, axes.reducer().tag());
    put_u16(&mut wire, axes.projection().tag());
    put_u16(&mut wire, axes.domain().tag());
    put_u16(&mut wire, 0);
    put_u32(&mut wire, 0);
    put_u64(&mut wire, 0);
    put_u64(&mut wire, 0);
    put_u64(&mut wire, 0);

    put_u16(&mut wire, output.tag());
    put_u16(&mut wire, 0);
    put_u32(&mut wire, 0);
    put_u64(&mut wire, 1);
    wire.extend_from_slice(payload);
    assert_eq!(wire.len(), total_bytes);
    wire
}

fn raw_two_member_unreachable_wire(
    kind: AotOperationSetMemberKindV2,
    axes: AotOperationAxesV2,
    reachable: &[u8],
    unreachable: &[u8],
) -> Vec<u8> {
    let output = axes.validate(0).expect("raw fixture uses admitted axes");
    let reachable_identity: [u8; 32] = Sha256::digest(reachable).into();
    let unreachable_identity: [u8; 32] = Sha256::digest(unreachable).into();
    let mut members = [
        (true, reachable, reachable_identity),
        (false, unreachable, unreachable_identity),
    ];
    members.sort_unstable_by(|left, right| {
        compare_member_key(&left.2, kind, left.1, &right.2, kind, right.1)
    });
    assert!(
        compare_member_key(
            &members[0].2,
            kind,
            members[0].1,
            &members[1].2,
            kind,
            members[1].1,
        ) == Ordering::Less
    );
    let reachable_index = members
        .iter()
        .position(|member| member.0)
        .expect("reachable member index");
    let reachable_index = u32::try_from(reachable_index).expect("reachable index fits u32");

    let member_table_offset = AOT_OPERATION_SET_V2_HEADER_BYTES;
    let shared_table_offset =
        member_table_offset + 2 * AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES;
    let root_table_offset = shared_table_offset;
    let stage_table_offset = root_table_offset + 2 * AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES;
    let output_table_offset = stage_table_offset + 2 * AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES;
    let payload_offset = output_table_offset + 2 * AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES;
    let total_bytes = payload_offset + members.iter().map(|member| member.1.len()).sum::<usize>();
    let mut wire = Vec::with_capacity(total_bytes);
    emit_header(
        &mut wire,
        total_bytes,
        2,
        2,
        member_table_offset,
        shared_table_offset,
        root_table_offset,
        stage_table_offset,
        output_table_offset,
        payload_offset,
    )
    .expect("emit raw two-member header");

    let mut next_payload = payload_offset;
    for member in &members {
        put_u32(&mut wire, kind.tag());
        put_u32(&mut wire, 0);
        put_u32(&mut wire, AOT_OPERATION_SET_V2_NONE_INDEX);
        put_u32(&mut wire, AOT_OPERATION_SET_V2_NONE_INDEX);
        put_usize_as_u64(&mut wire, next_payload).expect("member payload offset");
        put_usize_as_u64(&mut wire, member.1.len()).expect("member payload length");
        next_payload += member.1.len();
    }
    for root in 0_u32..2 {
        put_u32(&mut wire, root);
        put_u32(&mut wire, 1);
        put_u32(&mut wire, root);
        put_u32(&mut wire, 1);
        put_u32(&mut wire, 0);
        put_u32(&mut wire, 0);
    }
    for root in 0_u32..2 {
        put_u32(&mut wire, reachable_index);
        put_u16(&mut wire, axes.reducer().tag());
        put_u16(&mut wire, axes.projection().tag());
        put_u16(&mut wire, axes.domain().tag());
        put_u16(&mut wire, 0);
        put_u32(&mut wire, root);
        put_u64(&mut wire, 0);
        put_u64(&mut wire, 0);
        put_u64(&mut wire, 0);
    }
    for root in 0_u32..2 {
        put_u16(&mut wire, output.tag());
        put_u16(&mut wire, 0);
        put_u32(&mut wire, root);
        put_u64(&mut wire, 1);
    }
    for member in members {
        wire.extend_from_slice(member.1);
    }
    assert_eq!(wire.len(), total_bytes);
    wire
}

#[test]
fn mixed_capture_and_compiled_roundtrip_is_canonical_and_deterministic() {
    let exists = compiled_program("alpha+", OutputContract::Exists);
    let span = compiled_program("beta+", OutputContract::Span);
    let capture = capture_program(&Ast::Byte(b'q').named(1, "item"));
    let limits = CaptureProgramV1Limits::default();
    let build = || {
        AotOperationSetV2::from_operations(
            [
                (
                    AotOperationAxesV2::SEARCH,
                    AotOperationSetMemberInputV2::CompiledProgram(exists.as_slice()),
                ),
                (
                    AotOperationAxesV2::COUNT,
                    AotOperationSetMemberInputV2::CompiledProgram(span.as_slice()),
                ),
                (
                    AotOperationAxesV2::SPAN_SUM,
                    AotOperationSetMemberInputV2::CompiledProgram(span.as_slice()),
                ),
                (
                    AotOperationAxesV2::GREP,
                    AotOperationSetMemberInputV2::CompiledProgram(exists.as_slice()),
                ),
                (
                    AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                    AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
                ),
                (
                    AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                    AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
                ),
            ],
            limits,
        )
        .expect("build mixed V2 operation set")
    };
    let set = build();
    let repeated = build();
    assert_eq!(set.as_bytes(), repeated.as_bytes());
    assert_eq!(set.identity(), repeated.identity());
    assert_eq!(&set.as_bytes()[..8], &AOT_OPERATION_SET_V2_MAGIC);
    assert_eq!(read_u16(set.as_bytes(), HEADER_VERSION_OFFSET), Ok(2));
    assert_eq!(read_u16(set.as_bytes(), HEADER_BYTES_OFFSET), Ok(128));
    assert_eq!(set.member_count(), 3);
    assert_eq!(set.operation_count(), 6);

    let required =
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(set.as_bytes(), limits)
            .expect("capture scratch sizing");
    assert!(required > 0);
    let mut scratch = vec![0xA5A5_A5A5_u32; required + 3];
    let view = AotOperationSetV2View::deserialize(set.as_bytes(), limits, &mut scratch)
        .expect("allocation-free strict V2 view");
    assert_eq!(scratch[required..], [0xA5A5_A5A5; 3]);
    assert_eq!(view.as_bytes(), set.as_bytes());
    assert_eq!(view.identity(), set.identity());
    assert_eq!(view.member_count(), set.member_count());
    assert_eq!(view.operation_count(), set.operation_count());

    let expected_axes = [
        AotOperationAxesV2::SEARCH,
        AotOperationAxesV2::COUNT,
        AotOperationAxesV2::SPAN_SUM,
        AotOperationAxesV2::GREP,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
    ];
    for (index, expected_axes) in expected_axes.into_iter().enumerate() {
        let root = view.root(index).expect("borrowed root");
        let stage = view.stage(index).expect("borrowed stage");
        let output = view.output(index).expect("borrowed output");
        assert_eq!(root.axes(), expected_axes);
        assert_eq!(stage.axes(), expected_axes);
        assert_eq!(stage.member_index(), root.member_index());
        assert_eq!(usize::try_from(stage.output_index()), Ok(index));
        assert_eq!(output.output(), root.output());
        assert_eq!(usize::try_from(output.stage_index()), Ok(index));
        assert_eq!(output.record_count(), 1);
        assert_eq!(Some(root), set.operation(index));
    }
    assert_eq!(
        view.root(0).expect("search root").output(),
        AotOperationOutputV2::OneRecord
    );
    for index in 1..view.operation_count() {
        assert_eq!(
            view.root(index).expect("scalar root").output(),
            AotOperationOutputV2::ScalarU64
        );
    }

    let members = view.members().collect::<Vec<_>>();
    assert_eq!(members.len(), 3);
    assert!(members.windows(2).all(|pair| {
        compare_member_key(
            &pair[0].identity(),
            pair[0].kind(),
            pair[0].as_bytes(),
            &pair[1].identity(),
            pair[1].kind(),
            pair[1].as_bytes(),
        ) == Ordering::Less
    }));
    for member in members {
        let index = usize_from_u32(member.index()).expect("member index");
        assert_eq!(set.member_bytes(index), Some(member.as_bytes()));
        assert_eq!(set.member_identity(index), Some(member.identity()));
        assert_eq!(
            set.member(index).expect("owned member").kind(),
            member.kind()
        );
        let expected_identity: [u8; 32] = Sha256::digest(member.as_bytes()).into();
        assert_eq!(member.identity(), expected_identity);
    }
    let capture_root = view.root(4).expect("capture root");
    let repeated_capture_root = view.root(5).expect("repeated capture root");
    assert_eq!(
        capture_root.member_index(),
        repeated_capture_root.member_index()
    );
    let capture_member = view
        .member(usize_from_u32(capture_root.member_index()).expect("capture member index"))
        .expect("capture member");
    assert_eq!(
        capture_member.kind(),
        AotOperationSetMemberKindV2::CaptureProgramV1
    );
    assert_eq!(capture_member.as_bytes(), capture.as_slice());

    let restored = AotOperationSetV2::deserialize(set.as_bytes(), limits)
        .expect("owned strict V2 reconstruction");
    assert_eq!(restored.as_bytes(), set.as_bytes());
    assert_eq!(restored.identity(), set.identity());
    assert_eq!(
        restored.operations().collect::<Vec<_>>(),
        set.operations().collect::<Vec<_>>()
    );

    let mut expected_identity = Sha256::new();
    expected_identity.update(AOT_OPERATION_SET_V2_IDENTITY_DOMAIN);
    expected_identity.update(set.as_bytes());
    let expected_identity: [u8; 32] = expected_identity.finalize().into();
    assert_eq!(set.identity(), expected_identity);
}

#[test]
fn exact_capture_scratch_gate_precedes_full_body_validation() {
    let capture = capture_program(&Ast::Byte(b'x').capture(1));
    let limits = CaptureProgramV1Limits::default();
    let wire = raw_single_member_wire(
        AotOperationSetMemberKindV2::CaptureProgramV1,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        &capture,
    );
    let required = AotOperationSetV2View::capture_validation_scratch_words_from_wire(&wire, limits)
        .expect("capture scratch words");
    assert!(required > 0);

    let mut one_below = vec![0_u32; required - 1];
    assert!(matches!(
        AotOperationSetV2View::deserialize(&wire, limits, &mut one_below),
        Err(AotOperationSetV2Error::CaptureValidationScratch {
            required_words,
            available_words,
        }) if required_words == required && available_words == required - 1
    ));
    let mut exact = vec![0_u32; required];
    AotOperationSetV2View::deserialize(&wire, limits, &mut exact).expect("exact capture scratch");

    let mut corrupted = wire;
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert_eq!(
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(&corrupted, limits),
        Ok(required)
    );
    let mut short_corrupt = vec![0_u32; required - 1];
    assert!(matches!(
        AotOperationSetV2View::deserialize(&corrupted, limits, &mut short_corrupt),
        Err(AotOperationSetV2Error::CaptureValidationScratch { .. })
    ));
    let mut exact_corrupt = vec![0_u32; required];
    let borrowed =
        AotOperationSetV2View::deserialize(&corrupted, limits, &mut exact_corrupt).map(|_| ());
    let owned = AotOperationSetV2::deserialize(&corrupted, limits).map(|_| ());
    assert_eq!(borrowed, owned);
    assert!(matches!(
        borrowed,
        Err(AotOperationSetV2Error::MemberCaptureProgram { member: 0, .. })
    ));
}

#[test]
fn structural_view_binds_limits_and_upgrades_to_the_full_view() {
    let capture = capture_program(&Ast::Byte(b'x').named(1, "bound"));
    let limits = CaptureProgramV1Limits::default();
    let wire = raw_single_member_wire(
        AotOperationSetMemberKindV2::CaptureProgramV1,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        &capture,
    );
    let structural =
        AotOperationSetV2View::deserialize_structure(&wire, limits).expect("structural V2 view");
    assert_eq!(structural.as_bytes(), wire);
    assert_eq!(structural.capture_limits(), limits);
    assert_eq!(structural.member_count(), 1);
    assert_eq!(structural.operation_count(), 1);
    assert_eq!(
        structural.member(0).expect("structural member").kind(),
        AotOperationSetMemberKindV2::CaptureProgramV1
    );
    assert_eq!(
        structural.root(0).expect("structural root").axes(),
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT
    );

    let required = structural.capture_validation_scratch_words();
    let mut upgrade_scratch = vec![0_u32; required];
    let upgraded = structural
        .validate_capture_members(&mut upgrade_scratch)
        .expect("upgrade structural view");
    let mut direct_scratch = vec![0_u32; required];
    let direct = AotOperationSetV2View::deserialize(&wire, limits, &mut direct_scratch)
        .expect("direct full view");
    assert_eq!(upgraded.as_bytes(), direct.as_bytes());
    assert_eq!(upgraded.identity(), direct.identity());
    assert_eq!(
        upgraded.members().collect::<Vec<_>>(),
        direct.members().collect::<Vec<_>>()
    );
    assert_eq!(
        upgraded.roots().collect::<Vec<_>>(),
        direct.roots().collect::<Vec<_>>()
    );

    let different_limits = CaptureProgramV1Limits {
        max_states: 0,
        ..limits
    };
    assert!(matches!(
        AotOperationSetV2View::deserialize_structure(&wire, different_limits),
        Err(AotOperationSetV2Error::MemberCaptureProgram { member: 0, .. })
    ));
    // Upgrade has no limits argument: the successful structural validation is
    // inseparably bound to the exact limits returned above.
    assert_eq!(structural.capture_limits(), limits);
}

#[test]
fn structural_view_exposes_unreachable_roots_before_capture_body_census() {
    let limits = CaptureProgramV1Limits::default();
    let reachable = capture_program(&Ast::Byte(b'a').capture(1));
    let mut corrupt_unreachable = capture_program(&Ast::Byte(b'b').capture(1));
    let last = corrupt_unreachable.len() - 1;
    corrupt_unreachable[last] ^= 1;
    let wire = raw_two_member_unreachable_wire(
        AotOperationSetMemberKindV2::CaptureProgramV1,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        &reachable,
        &corrupt_unreachable,
    );
    let structural = AotOperationSetV2View::deserialize_structure(&wire, limits)
        .expect("corrupt body remains structurally valid");
    assert_eq!(structural.member_count(), 2);
    let root_members = structural
        .roots()
        .map(AotOperationRootV2::member_index)
        .collect::<Vec<_>>();
    assert_eq!(root_members.len(), 2);
    assert_eq!(root_members[0], root_members[1]);
    let mut scratch = vec![0_u32; structural.capture_validation_scratch_words()];
    assert!(matches!(
        structural.validate_capture_members(&mut scratch),
        Err(AotOperationSetV2Error::MemberCaptureProgram { .. })
    ));
}

#[test]
fn capture_scratch_sizing_uses_the_largest_unique_member() {
    let small = capture_program(&Ast::Byte(b'a').capture(1));
    let wide = capture_program(&Ast::concat([
        Ast::Byte(b'a').capture(1),
        Ast::Class(vec![(b'b', b'd'), (b'x', b'z')]).named(2, "wide"),
        Ast::Byte(b'q'),
    ]));
    let limits = CaptureProgramV1Limits::default();
    let small_words = CaptureProgramV1Census::scratch_words_from_header(
        &small[..CAPTURE_PROGRAM_V1_HEADER_BYTES],
        limits,
    )
    .expect("small scratch words");
    let wide_words = CaptureProgramV1Census::scratch_words_from_header(
        &wide[..CAPTURE_PROGRAM_V1_HEADER_BYTES],
        limits,
    )
    .expect("wide scratch words");
    assert!(wide_words > small_words);
    let set = AotOperationSetV2::from_operations(
        [
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(small.as_slice()),
            ),
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(wide.as_slice()),
            ),
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(small.as_slice()),
            ),
        ],
        limits,
    )
    .expect("build multi-capture fixture");
    assert_eq!(set.member_count(), 2);
    assert_eq!(
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(set.as_bytes(), limits,),
        Ok(wide_words)
    );
    let mut scratch = vec![0_u32; wide_words];
    AotOperationSetV2View::deserialize(set.as_bytes(), limits, &mut scratch)
        .expect("largest exact scratch accepts every capture member");
}

#[test]
fn capture_child_limits_propagate_through_sizing_builder_and_owned_reader() {
    let capture = capture_program(&Ast::Byte(b'a').named(1, "limited"));
    let wire = raw_single_member_wire(
        AotOperationSetMemberKindV2::CaptureProgramV1,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        &capture,
    );
    let limited = CaptureProgramV1Limits {
        max_serialized_bytes: capture.len() - 1,
        ..CaptureProgramV1Limits::default()
    };
    assert!(matches!(
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(&wire, limited),
        Err(AotOperationSetV2Error::MemberCaptureProgram { member: 0, .. })
    ));
    assert!(matches!(
        AotOperationSetV2::deserialize(&wire, limited),
        Err(AotOperationSetV2Error::MemberCaptureProgram { member: 0, .. })
    ));
    assert!(matches!(
        AotOperationSetV2::from_operations(
            [(
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            )],
            limited,
        ),
        Err(AotOperationSetV2Error::MemberCaptureProgram { member: 0, .. })
    ));
}

#[test]
fn nullable_capture_and_incompatible_member_axes_fail_closed() {
    let limits = CaptureProgramV1Limits::default();
    let nullable = capture_program(&Ast::Empty.capture(1));
    let nullable_wire = raw_single_member_wire(
        AotOperationSetMemberKindV2::CaptureProgramV1,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        &nullable,
    );
    let required =
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(&nullable_wire, limits)
            .expect("nullable header remains sizeable");
    let mut scratch = vec![0_u32; required];
    assert!(matches!(
        AotOperationSetV2View::deserialize(&nullable_wire, limits, &mut scratch),
        Err(AotOperationSetV2Error::NullableCaptureProgram { member: 0 })
    ));
    assert!(matches!(
        AotOperationSetV2::deserialize(&nullable_wire, limits),
        Err(AotOperationSetV2Error::NullableCaptureProgram { member: 0 })
    ));
    assert!(matches!(
        AotOperationSetV2::from_operations(
            [(
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(nullable.as_slice()),
            )],
            limits,
        ),
        Err(AotOperationSetV2Error::NullableCaptureProgram { member: 0 })
    ));

    let capture = capture_program(&Ast::Byte(b'a').capture(1));
    assert!(matches!(
        AotOperationSetV2::from_operations(
            [(
                AotOperationAxesV2::SEARCH,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            )],
            limits,
        ),
        Err(AotOperationSetV2Error::IncompatibleMemberKind {
            root: 0,
            actual: AotOperationSetMemberKindV2::CaptureProgramV1,
        })
    ));
    let exists = compiled_program("a+", OutputContract::Exists);
    assert!(matches!(
        AotOperationSetV2::from_operations(
            [(
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CompiledProgram(exists.as_slice()),
            )],
            limits,
        ),
        Err(AotOperationSetV2Error::IncompatibleMemberKind {
            root: 0,
            actual: AotOperationSetMemberKindV2::CompiledProgram,
        })
    ));
    assert!(matches!(
        AotOperationSetV2::from_operations(
            [(
                AotOperationAxesV2::COUNT,
                AotOperationSetMemberInputV2::CompiledProgram(exists.as_slice()),
            )],
            limits,
        ),
        Err(AotOperationSetV2Error::IncompatibleProgramOutput {
            root: 0,
            actual: OutputContract::Exists,
        })
    ));

    let capture_search_wire = raw_single_member_wire(
        AotOperationSetMemberKindV2::CaptureProgramV1,
        AotOperationAxesV2::SEARCH,
        &capture,
    );
    assert!(matches!(
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(
            &capture_search_wire,
            limits,
        ),
        Err(AotOperationSetV2Error::IncompatibleMemberKind { root: 0, .. })
    ));
    let compiled_capture_wire = raw_single_member_wire(
        AotOperationSetMemberKindV2::CompiledProgram,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        &exists,
    );
    assert!(matches!(
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(
            &compiled_capture_wire,
            limits,
        ),
        Err(AotOperationSetV2Error::IncompatibleMemberKind { root: 0, .. })
    ));

    let mut unsupported_domain = raw_single_member_wire(
        AotOperationSetMemberKindV2::CaptureProgramV1,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        &capture,
    );
    let stage = header_offset(&unsupported_domain, HEADER_STAGE_TABLE_OFFSET);
    overwrite_u16(
        &mut unsupported_domain,
        stage + 8,
        AotDomainV2::PerLine.tag(),
    );
    assert!(matches!(
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(
            &unsupported_domain,
            limits,
        ),
        Err(AotOperationSetV2Error::UnsupportedOperationAxes { index: 0, .. })
    ));
}

#[test]
fn malformed_envelope_and_records_fail_identically_for_borrowed_and_owned() {
    let capture = capture_program(&Ast::Byte(b'a').named(1, "named"));
    let limits = CaptureProgramV1Limits::default();
    let valid = raw_single_member_wire(
        AotOperationSetMemberKindV2::CaptureProgramV1,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        &capture,
    );
    let required =
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(&valid, limits)
            .expect("valid scratch sizing");
    let compare = |bytes: &[u8]| {
        let mut scratch = vec![0_u32; required];
        let borrowed = AotOperationSetV2View::deserialize(bytes, limits, &mut scratch).map(|_| ());
        let owned = AotOperationSetV2::deserialize(bytes, limits).map(|_| ());
        assert_eq!(borrowed, owned);
        assert!(borrowed.is_err());
    };

    let mut bad_version = valid.clone();
    overwrite_u16(&mut bad_version, HEADER_VERSION_OFFSET, 3);
    compare(&bad_version);
    let mut bad_header_flags = valid.clone();
    overwrite_u32(&mut bad_header_flags, HEADER_FLAGS_OFFSET, 1);
    compare(&bad_header_flags);
    let mut bad_shared = valid.clone();
    overwrite_u32(&mut bad_shared, HEADER_SHARED_COUNT_OFFSET, 1);
    compare(&bad_shared);
    let mut bad_table = valid.clone();
    overwrite_u64(&mut bad_table, HEADER_STAGE_TABLE_OFFSET, 0);
    compare(&bad_table);
    let mut bad_member_flags = valid.clone();
    overwrite_u32(
        &mut bad_member_flags,
        AOT_OPERATION_SET_V2_HEADER_BYTES + 4,
        1,
    );
    compare(&bad_member_flags);
    let mut bad_member_reference = valid.clone();
    overwrite_u32(
        &mut bad_member_reference,
        AOT_OPERATION_SET_V2_HEADER_BYTES + 8,
        0,
    );
    compare(&bad_member_reference);
    let root = header_offset(&valid, HEADER_ROOT_TABLE_OFFSET);
    let mut bad_root = valid.clone();
    overwrite_u32(&mut bad_root, root + 20, 1);
    compare(&bad_root);
    let stage = header_offset(&valid, HEADER_STAGE_TABLE_OFFSET);
    let mut bad_stage = valid.clone();
    overwrite_u16(&mut bad_stage, stage + 10, 1);
    compare(&bad_stage);
    let output = header_offset(&valid, HEADER_OUTPUT_TABLE_OFFSET);
    let mut bad_output = valid.clone();
    overwrite_u16(&mut bad_output, output + 2, 1);
    compare(&bad_output);
    let mut trailing = valid;
    trailing.push(0);
    compare(&trailing);
}

#[test]
fn reader_rejects_duplicate_member_payloads_after_exact_extent_validation() {
    let first = compiled_program("alpha", OutputContract::Exists);
    let second = compiled_program("omega", OutputContract::Exists);
    assert_eq!(first.len(), second.len());
    let limits = CaptureProgramV1Limits::default();
    let set = AotOperationSetV2::from_operations(
        [
            (
                AotOperationAxesV2::SEARCH,
                AotOperationSetMemberInputV2::CompiledProgram(first.as_slice()),
            ),
            (
                AotOperationAxesV2::SEARCH,
                AotOperationSetMemberInputV2::CompiledProgram(second.as_slice()),
            ),
        ],
        limits,
    )
    .expect("build duplicate mutation fixture");
    assert_eq!(set.member_count(), 2);
    let mut duplicate = set.as_bytes().to_vec();
    let first_descriptor = AOT_OPERATION_SET_V2_HEADER_BYTES;
    let second_descriptor = first_descriptor + AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES;
    let first_start =
        usize_from_u64(read_u64(&duplicate, first_descriptor + 16).expect("first payload offset"))
            .expect("first payload host offset");
    let first_len =
        usize_from_u64(read_u64(&duplicate, first_descriptor + 24).expect("first payload length"))
            .expect("first payload host length");
    let second_start = usize_from_u64(
        read_u64(&duplicate, second_descriptor + 16).expect("second payload offset"),
    )
    .expect("second payload host offset");
    let second_len = usize_from_u64(
        read_u64(&duplicate, second_descriptor + 24).expect("second payload length"),
    )
    .expect("second payload host length");
    assert_eq!(first_len, second_len);
    let copied = duplicate[first_start..first_start + first_len].to_vec();
    duplicate[second_start..second_start + second_len].copy_from_slice(&copied);
    assert!(matches!(
        AotOperationSetV2View::deserialize(&duplicate, limits, &mut []),
        Err(AotOperationSetV2Error::Malformed(
            "member payloads are duplicate or not in canonical digest-kind-byte order"
        ))
    ));
    assert!(matches!(
        AotOperationSetV2::deserialize(&duplicate, limits),
        Err(AotOperationSetV2Error::Malformed(
            "member payloads are duplicate or not in canonical digest-kind-byte order"
        ))
    ));
}

#[test]
fn borrowed_preflight_defers_compiled_body_and_global_reachability() {
    let limits = CaptureProgramV1Limits::default();
    let exists = compiled_program("body-corruption", OutputContract::Exists);
    let set = AotOperationSetV2::from_operations(
        [(
            AotOperationAxesV2::SEARCH,
            AotOperationSetMemberInputV2::CompiledProgram(exists.as_slice()),
        )],
        limits,
    )
    .expect("build compiled-body fixture");
    let payload = header_offset(set.as_bytes(), HEADER_PAYLOAD_OFFSET);
    let role_offset = payload + PROGRAM_HEADER_LEN + 52;
    let mut corrupted = set.as_bytes().to_vec();
    *corrupted.get_mut(role_offset).expect("raw role byte") = u8::MAX;
    assert_eq!(
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(&corrupted, limits),
        Ok(0)
    );
    AotOperationSetV2View::deserialize(&corrupted, limits, &mut [])
        .expect("borrowed preflight intentionally defers compiled body");
    assert!(matches!(
        AotOperationSetV2::deserialize(&corrupted, limits),
        Err(AotOperationSetV2Error::MemberCompiledProgram { member: 0, .. })
    ));

    let first = compiled_program("first-member", OutputContract::Exists);
    let second = compiled_program("second-member", OutputContract::Exists);
    let set = AotOperationSetV2::from_operations(
        [
            (
                AotOperationAxesV2::SEARCH,
                AotOperationSetMemberInputV2::CompiledProgram(first.as_slice()),
            ),
            (
                AotOperationAxesV2::SEARCH,
                AotOperationSetMemberInputV2::CompiledProgram(second.as_slice()),
            ),
        ],
        limits,
    )
    .expect("build reachability fixture");
    assert_eq!(set.member_count(), 2);
    let mut unreachable = set.as_bytes().to_vec();
    let stage = header_offset(&unreachable, HEADER_STAGE_TABLE_OFFSET);
    let first_member = read_u32(&unreachable, stage).expect("first root member");
    overwrite_u32(
        &mut unreachable,
        stage + AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES,
        first_member,
    );
    let view = AotOperationSetV2View::deserialize(&unreachable, limits, &mut [])
        .expect("borrowed preflight intentionally defers reachability");
    assert_eq!(view.member_count(), 2);
    assert!(matches!(
        AotOperationSetV2::deserialize(&unreachable, limits),
        Err(AotOperationSetV2Error::Malformed(
            "member table contains an unreachable payload"
        ))
    ));
}

#[test]
fn owned_reachability_precedes_unreachable_capture_and_compiled_bodies() {
    let limits = CaptureProgramV1Limits::default();

    let capture = capture_program(&Ast::Byte(b'a').named(1, "capture"));
    let mut corrupt_capture = capture.clone();
    let capture_last = corrupt_capture.len() - 1;
    corrupt_capture[capture_last] ^= 1;
    let capture_wire = raw_two_member_unreachable_wire(
        AotOperationSetMemberKindV2::CaptureProgramV1,
        AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
        &capture,
        &corrupt_capture,
    );
    let required =
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(&capture_wire, limits)
            .expect("unreachable corrupt capture remains structurally valid");
    let mut scratch = vec![0_u32; required];
    assert!(matches!(
        AotOperationSetV2View::deserialize(&capture_wire, limits, &mut scratch),
        Err(AotOperationSetV2Error::MemberCaptureProgram { .. })
    ));
    assert!(matches!(
        AotOperationSetV2::deserialize(&capture_wire, limits),
        Err(AotOperationSetV2Error::Malformed(
            "member table contains an unreachable payload"
        ))
    ));

    let compiled = compiled_program("compiled-body", OutputContract::Exists);
    let mut corrupt_compiled = compiled.clone();
    *corrupt_compiled
        .get_mut(PROGRAM_HEADER_LEN + 52)
        .expect("compiled raw role byte") = u8::MAX;
    let compiled_wire = raw_two_member_unreachable_wire(
        AotOperationSetMemberKindV2::CompiledProgram,
        AotOperationAxesV2::SEARCH,
        &compiled,
        &corrupt_compiled,
    );
    AotOperationSetV2View::deserialize(&compiled_wire, limits, &mut [])
        .expect("borrowed preflight defers compiled member bodies");
    assert!(matches!(
        AotOperationSetV2::deserialize(&compiled_wire, limits),
        Err(AotOperationSetV2Error::Malformed(
            "member table contains an unreachable payload"
        ))
    ));
}

#[test]
fn structure_hashes_each_member_once_even_with_many_repeated_roots() {
    const ROOTS: usize = 512;
    let exists = compiled_program("shared-member", OutputContract::Exists);
    let set = AotOperationSetV2::from_operations(
        (0..ROOTS).map(|_| {
            (
                AotOperationAxesV2::SEARCH,
                AotOperationSetMemberInputV2::CompiledProgram(exists.as_slice()),
            )
        }),
        CaptureProgramV1Limits::default(),
    )
    .expect("build repeated-root fixture");
    assert_eq!(set.member_count(), 1);
    assert_eq!(set.operation_count(), ROOTS);

    TEST_STRUCTURE_MEMBER_HASHES.with(|hashes| hashes.set(0));
    assert_eq!(
        AotOperationSetV2View::capture_validation_scratch_words_from_wire(
            set.as_bytes(),
            CaptureProgramV1Limits::default(),
        ),
        Ok(0)
    );
    assert_eq!(
        TEST_STRUCTURE_MEMBER_HASHES.with(core::cell::Cell::get),
        set.member_count()
    );

    TEST_STRUCTURE_MEMBER_HASHES.with(|hashes| hashes.set(0));
    let structural = AotOperationSetV2View::deserialize_structure(
        set.as_bytes(),
        CaptureProgramV1Limits::default(),
    )
    .expect("structural accessor fixture");
    assert_eq!(
        TEST_STRUCTURE_MEMBER_HASHES.with(core::cell::Cell::get),
        set.member_count()
    );
    for _ in 0..4 {
        assert_eq!(
            structural
                .members()
                .map(|member| member.as_bytes().len())
                .sum::<usize>(),
            exists.len(),
        );
        assert_eq!(structural.roots().count(), ROOTS);
    }
    assert_eq!(
        TEST_STRUCTURE_MEMBER_HASHES.with(core::cell::Cell::get),
        set.member_count(),
        "structural accessors must not rehash payload bodies",
    );

    TEST_STRUCTURE_MEMBER_HASHES.with(|hashes| hashes.set(0));
    let restored =
        AotOperationSetV2::deserialize(set.as_bytes(), CaptureProgramV1Limits::default())
            .expect("owned reconstruction reuses structural member identities");
    assert_eq!(restored.member_count(), 1);
    assert_eq!(
        TEST_STRUCTURE_MEMBER_HASHES.with(core::cell::Cell::get),
        restored.member_count()
    );
}

#[test]
fn builder_rejects_empty_and_malformed_member_inputs() {
    let limits = CaptureProgramV1Limits::default();
    assert!(matches!(
        AotOperationSetV2::from_operations(
            core::iter::empty::<(AotOperationAxesV2, AotOperationSetMemberInputV2<&[u8]>,)>(),
            limits,
        ),
        Err(AotOperationSetV2Error::Malformed(
            "operation set has no semantic roots"
        ))
    ));
    assert!(matches!(
        AotOperationSetV2::from_operations(
            [(
                AotOperationAxesV2::SEARCH,
                AotOperationSetMemberInputV2::CompiledProgram(b"not a program".as_slice()),
            )],
            limits,
        ),
        Err(AotOperationSetV2Error::MemberCompiledProgram { member: 0, .. })
    ));
    assert!(matches!(
        AotOperationSetV2::from_operations(
            [(
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(b"not a capture program".as_slice(),),
            )],
            limits,
        ),
        Err(AotOperationSetV2Error::MemberCaptureProgram { member: 0, .. })
    ));
}
