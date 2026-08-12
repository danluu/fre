//! Target-final exact-finite `Exists` leaves.
//!
//! These lowerings consume only the separately authenticated finite-language
//! Choice view. They remain simultaneous competitors with the ordinary native
//! machine: owning the source-derived sidecar does not by itself select one.

use super::*;
use crate::finite_language::{NativeFiniteExistsChoiceKind, NativeFiniteExistsChoiceView};

/// Exact one-byte languages do strictly less match-time work than a complete
/// DFA: one input classification proves the whole semantic answer, while the
/// incumbent must additionally classify/load a transition and inspect its
/// accepting metadata. This proof is independent of source spelling and input
/// data. The exact target image is still charged against the caller's native
/// data ceiling before selection.
pub(super) fn lower_atomic_exists_choice(
    choice: NativeFiniteExistsChoiceView<'_>,
    target: Target,
    max_native_data_bytes: usize,
    incumbent: Option<NativeProgramView<'_>>,
) -> Result<Option<NativeLowering>, ObjectError> {
    target.validate()?;
    if let Some(incumbent) = incumbent
        && (incumbent.output != OutputContract::Exists
            || incumbent.partial_discovered_states.is_some()
            || incumbent.collapse_partial_holes
            || incumbent.dfa.initial_pending)
    {
        return Ok(None);
    }
    let NativeFiniteExistsChoiceKind::ByteSet { membership } = choice.kind() else {
        return Ok(None);
    };
    if choice.minimum_width() != 1
        || choice.maximum_width() != 1
        || choice.literals().is_empty()
        || choice.total_source_bytes() != choice.literals().len()
    {
        return Err(ObjectError::InvalidModule(
            "exact-finite byte Choice dimensions are inconsistent",
        ));
    }
    let cardinality = u16::try_from(membership.iter().map(|word| word.count_ones()).sum::<u32>())
        .map_err(|_| ObjectError::ArithmeticOverflow("exact-finite byte Choice cardinality"))?;
    if cardinality == 0
        || usize::from(cardinality) != choice.literals().len()
        || choice.literals().iter().any(|literal| {
            literal.len() != 1 || membership[usize::from(literal[0]) / 64]
                & (1_u64 << (usize::from(literal[0]) % 64)) == 0
        })
    {
        return Err(ObjectError::InvalidModule(
            "exact-finite byte Choice membership is inconsistent",
        ));
    }

    if cardinality == 256 {
        let lowering = lower_universal_byte_exists(target)?;
        return Ok((lowering.data.len() <= max_native_data_bytes).then_some(lowering));
    }
    let exact = NativeExactByteSet::from_membership(membership, 0, true).ok_or(
        ObjectError::InvalidModule("exact-finite byte Choice has no exact set"),
    )?;
    let mut data = Vec::new();
    let Some(storage) = append_native_exact_byte_set(
        &mut data,
        exact,
        target.architecture,
        max_native_data_bytes,
    )? else {
        return Ok(None);
    };
    if data.len() > max_native_data_bytes {
        return Ok(None);
    }
    let (code, relocations, start_accelerator) = match target.architecture {
        Architecture::X86_64 => {
            let kind = x86_start_filter_kind(target.features);
            let vector_kind = (!matches!(kind, X86StartFilterKind::Sse2)).then_some(kind);
            let (code, relocations) = lower_x86_64_exact_byte_exists(exact, storage, vector_kind)?;
            let accelerator = match vector_kind {
                Some(X86StartFilterKind::Avx2) => StartAccelerator::X86Avx2,
                Some(X86StartFilterKind::Avx512Bw) => StartAccelerator::X86Avx512Bw,
                Some(X86StartFilterKind::Sse2) => unreachable!("SSE2 exact-set vector declined"),
                None => StartAccelerator::Scalar,
            };
            (code, relocations, accelerator)
        }
        Architecture::Aarch64 => {
            let (code, relocations, accelerator) =
                lower_aarch64_exact_byte_exists(exact, storage, target)?;
            (code, relocations, accelerator)
        }
    };
    Ok(Some(NativeLowering {
        code,
        data,
        relocations,
        slow_partial_table: None,
        needs_runtime: false,
        start_accelerator,
        anchored_prefix_filter_bytes: 1,
    }))
}

fn lower_universal_byte_exists(target: Target) -> Result<NativeLowering, ObjectError> {
    let (code, relocations) = match target.architecture {
        Architecture::X86_64 => lower_x86_64_universal_byte_exists()?,
        Architecture::Aarch64 => lower_aarch64_universal_byte_exists()?,
    };
    Ok(NativeLowering {
        code,
        // Keep the program symbol backed by one deterministic byte even
        // though this leaf needs no table relocation.
        data: vec![0],
        relocations,
        slow_partial_table: None,
        needs_runtime: false,
        start_accelerator: StartAccelerator::None,
        anchored_prefix_filter_bytes: 1,
    })
}

fn lower_x86_64_universal_byte_exists()
-> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = X86Assembler::new();
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;
    x86_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(&[0x31, 0xc0])?; // xor eax, eax
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;
    assembler.instruction(&[0x48, 0x39, 0xca])?; // start == end?
    assembler.branch(&[0x0f, 0x83], no_match)?;
    assembler.instruction(&[0xb8, 1, 0, 0, 0])?;
    assembler.instruction(&[0xc3])?;
    assembler.bind(no_match)?;
    assembler.instruction(&[0xc3])?;
    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 2, 0, 0, 0])?;
    assembler.instruction(&[0xc3])?;
    Ok((assembler.finish_with_label_offsets()?.code, Vec::new()))
}

fn lower_x86_64_exact_byte_exists(
    exact: NativeExactByteSet,
    storage: NativeExactByteSetStorage,
    vector_kind: Option<X86StartFilterKind>,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    if exact.scan_offset != 0 || !exact.is_valid() || storage.aarch64_lut_offset.is_some() {
        return Err(ObjectError::InvalidModule(
            "x86 exact-finite byte Choice storage is malformed",
        ));
    }
    let mut assembler = X86Assembler::new();
    let scalar = assembler.label()?;
    let scan = assembler.label()?;
    let lane_one = assembler.label()?;
    let lane_two = assembler.label()?;
    let lane_three = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let returned = assembler.label()?;
    let invalid = assembler.label()?;

    x86_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;
    assembler.instruction(&[0x4c, 0x8d, 0x0d])?;
    let program_displacement = assembler.label()?;
    assembler.bind(program_displacement)?;
    push_bytes(&mut assembler.code, &[0; 4])?;

    if let Some(kind) = vector_kind {
        x86_emit_exact_vector_constants(&mut assembler, storage, kind)?;
        assembler.bind(scan)?;
        assembler.instruction(&[0x48, 0x89, 0xc8])?;
        assembler.instruction(&[0x48, 0x29, 0xd0])?;
        let mut compare = vec![0x48, 0x3d];
        compare.extend_from_slice(&u32::from(kind.width()).to_le_bytes());
        assembler.instruction(&compare)?;
        assembler.branch(&[0x0f, 0x82], scalar)?;
        let mask = x86_emit_exact_vector_candidates(&mut assembler, kind, 0)?;
        x86_emit_candidate_nonzero(&mut assembler, mask)?;
        assembler.branch(&[0x0f, 0x85], matched)?;
        assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
        assembler.branch(&[0xe9], scan)?;
    } else {
        assembler.bind(scan)?;
        assembler.instruction(&[0x48, 0x89, 0xc8])?;
        assembler.instruction(&[0x48, 0x29, 0xd0])?;
        assembler.instruction(&[0x48, 0x83, 0xf8, 4])?;
        assembler.branch(&[0x0f, 0x82], scalar)?;
        x86_emit_exact_byte_set_scalar_load(&mut assembler, 0)?;
        x86_emit_exact_byte_set_test(&mut assembler, storage, matched)?;
        x86_emit_exact_byte_set_scalar_load(&mut assembler, 1)?;
        x86_emit_exact_byte_set_test(&mut assembler, storage, lane_one)?;
        x86_emit_exact_byte_set_scalar_load(&mut assembler, 2)?;
        x86_emit_exact_byte_set_test(&mut assembler, storage, lane_two)?;
        x86_emit_exact_byte_set_scalar_load(&mut assembler, 3)?;
        x86_emit_exact_byte_set_test(&mut assembler, storage, lane_three)?;
        assembler.instruction(&[0x48, 0x83, 0xc2, 4])?;
        assembler.branch(&[0xe9], scan)?;
        assembler.bind(lane_three)?;
        assembler.bind(lane_two)?;
        assembler.bind(lane_one)?;
        assembler.branch(&[0xe9], matched)?;
    }

    assembler.bind(scalar)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?;
    assembler.branch(&[0x0f, 0x83], no_match)?;
    x86_emit_exact_byte_set_scalar_load(&mut assembler, 0)?;
    x86_emit_exact_byte_set_test(&mut assembler, storage, matched)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], scalar)?;

    assembler.bind(matched)?;
    assembler.instruction(&[0xb8, 1, 0, 0, 0])?;
    assembler.branch(&[0xe9], returned)?;
    assembler.bind(no_match)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.bind(returned)?;
    if vector_kind.is_some_and(X86StartFilterKind::needs_vzeroupper) {
        assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    }
    assembler.instruction(&[0xc3])?;
    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 2, 0, 0, 0])?;
    assembler.instruction(&[0xc3])?;

    let finished = assembler.finish_with_label_offsets()?;
    let program_displacement = finished.label_offset(program_displacement)?;
    Ok((
        finished.code,
        vec![ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(
                program_displacement,
                "x86 exact-finite byte Choice relocation",
            )?,
            kind: RelocationKind::X86PcRelative32,
            symbol: PROGRAM_SYMBOL,
            addend: -4,
        }],
    ))
}

fn lower_aarch64_universal_byte_exists()
-> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = Aarch64Assembler::new();
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;
    aarch64_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, no_match)?;
    assembler.instruction(aarch64_movz_w(0, 1)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(no_match)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.instruction(0xd65f_03c0)?;
    Ok((assembler.finish_with_offsets(&mut [])?, Vec::new()))
}

fn lower_aarch64_exact_byte_exists(
    exact: NativeExactByteSet,
    storage: NativeExactByteSetStorage,
    target: Target,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>, StartAccelerator), ObjectError> {
    if exact.scan_offset != 0
        || !exact.is_valid()
        || storage.aarch64_lut_offset != storage.bitmap_offset.checked_add(32)
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 exact-finite byte Choice storage is malformed",
        ));
    }
    let scanner_isa = aarch64_primary_scanner_isa(
        target.operating_system,
        target.features,
        true,
    );
    let sve_kind = selected_aarch64_exact_sve_kind(
        target.operating_system,
        target.features,
        storage,
    );
    let use_mixed = sve_kind.is_some()
        && matches!(scanner_isa, Aarch64PrimaryScannerIsa::SveWithAsimdVl16);
    let use_sve = sve_kind.is_some();
    let use_asimd = target.features.has(CpuFeature::Aarch64Asimd)
        && (!use_sve || use_mixed);
    let accelerator = if let Some(kind) = sve_kind {
        match kind {
            Aarch64ExactSveKind::Nibble => StartAccelerator::Aarch64Sve,
            Aarch64ExactSveKind::Sve2Match(_) => StartAccelerator::Aarch64Sve2,
        }
    } else if use_asimd {
        StartAccelerator::Aarch64Asimd
    } else {
        StartAccelerator::Scalar
    };

    let mut assembler = Aarch64Assembler::new();
    let sve_scan = assembler.label()?;
    let sve_partial = assembler.label()?;
    let asimd_setup = assembler.label()?;
    let asimd_scan = assembler.label()?;
    let scalar_setup = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;
    aarch64_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    let program_page = assembler.instruction(0x9000_0005)?;
    let program_page_offset = assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?;

    if use_mixed {
        assembler.instruction(aarch64_sve_cntb(16)?)?;
        assembler.instruction(aarch64_cmp_x_imm(16, AARCH64_SVE_MIN_VECTOR_BYTES)?)?;
        assembler.branch_cond(AARCH64_EQ, asimd_setup)?;
    }
    if let Some(kind) = sve_kind {
        aarch64_emit_exact_sve_constants(&mut assembler, storage, kind)?;
        assembler.bind(sve_scan)?;
        assembler.instruction(aarch64_sve_ptrue_b())?;
        assembler.instruction(aarch64_sve_cntb(6)?)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x(12, 6)?)?;
        assembler.branch_cond(AARCH64_LO, sve_partial)?;
        aarch64_emit_exact_sve_candidates(&mut assembler, kind, 0)?;
        assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
        assembler.branch_cond(AARCH64_NE, matched)?;
        assembler.instruction(aarch64_sve_addvl(2, 2, 1)?)?;
        assembler.branch(sve_scan)?;
        assembler.bind(sve_partial)?;
        assembler.instruction(aarch64_cmp_x(2, 3)?)?;
        assembler.branch_cond(AARCH64_HS, no_match)?;
        assembler.instruction(aarch64_sve_whilelo_b(0, 2, 3)?)?;
        aarch64_emit_exact_sve_candidates(&mut assembler, kind, 0)?;
        assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
        assembler.branch_cond(AARCH64_NE, matched)?;
        assembler.branch(no_match)?;
    }

    if use_asimd {
        assembler.bind(asimd_setup)?;
        aarch64_emit_exact_asimd_constants(&mut assembler, storage)?;
        assembler.bind(asimd_scan)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x_imm(12, 16)?)?;
        assembler.branch_cond(AARCH64_LO, scalar_setup)?;
        aarch64_emit_exact_asimd_candidates(&mut assembler, 0)?;
        assembler.branch_cond(AARCH64_NE, matched)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        assembler.branch(asimd_scan)?;
    }

    assembler.bind(scalar_setup)?;
    aarch64_set_table_address(
        &mut assembler,
        6,
        storage.aarch64_lut_offset.ok_or(ObjectError::InvalidModule(
            "AArch64 exact-finite byte Choice has no scalar LUT",
        ))?,
    )?;
    assembler.bind(scalar_scan)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, no_match)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, 2)?)?;
    aarch64_emit_exact_byte_set_lut_test(&mut assembler, 6, matched)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(scalar_scan)?;

    assembler.bind(matched)?;
    assembler.instruction(aarch64_movz_w(0, 1)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(no_match)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.instruction(0xd65f_03c0)?;

    let mut offsets = [program_page, program_page_offset];
    let code = assembler.finish_with_offsets(&mut offsets)?;
    Ok((
        code,
        vec![
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(offsets[0], "AArch64 exact-finite byte Choice page")?,
                kind: RelocationKind::Aarch64Page21,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(offsets[1], "AArch64 exact-finite byte Choice pageoff")?,
                kind: RelocationKind::Aarch64PageOff12,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
        ],
        accelerator,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompileMode, CompileRequest, MatchResult, SearchWindow, compile};

    fn byte_choice_program() -> crate::CompiledRegex {
        compile(
            CompileRequest::new("a|z", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile exact-finite byte Choice fixture")
    }

    #[test]
    fn byte_choice_target_portfolio_is_structural_and_exact() {
        let compiled = byte_choice_program();
        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("authenticated byte Choice");
        let incumbent = compiled
            .program()
            .native_dfa_view()
            .expect("complete incumbent DFA");
        let cases = [
            (Target::x86_64_linux(), StartAccelerator::Scalar),
            (
                Target::x86_64_linux()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                StartAccelerator::X86Avx2,
            ),
            (
                Target::x86_64_linux().with_features(
                    FeatureSet::of(CpuFeature::X86Avx512F)
                        .with(CpuFeature::X86Avx512Bw),
                ).unwrap(),
                StartAccelerator::X86Avx512Bw,
            ),
            (
                Target::aarch64_macos()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap(),
                StartAccelerator::Aarch64Asimd,
            ),
            (
                Target::aarch64_linux()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
                    .unwrap(),
                StartAccelerator::Aarch64Sve,
            ),
            (
                Target::aarch64_linux().with_features(
                    FeatureSet::of(CpuFeature::Aarch64Sve)
                        .with(CpuFeature::Aarch64Sve2),
                ).unwrap(),
                StartAccelerator::Aarch64Sve2,
            ),
        ];
        for (target, expected) in cases {
            let lowering = lower_atomic_exists_choice(choice, target, usize::MAX, Some(incumbent))
                .unwrap()
                .unwrap_or_else(|| panic!("target declined byte Choice: {target:?}"));
            assert_eq!(lowering.start_accelerator, expected, "{target:?}");
            assert!(!lowering.needs_runtime, "{target:?}");
            assert!(!lowering.code.is_empty(), "{target:?}");
            assert!(!lowering.data.is_empty(), "{target:?}");
            assert_eq!(
                lowering.relocations.len(),
                if target.architecture == Architecture::X86_64 { 1 } else { 2 },
                "{target:?}",
            );
        }
    }

    #[test]
    fn byte_choice_is_selected_and_obeys_native_data_limit() {
        let target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let compiled = compile(
            CompileRequest::new("a|z", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile selected byte Choice");
        assert_eq!(compiled.receipt().start_accelerator, StartAccelerator::X86Avx2);
        assert!(compiled.module().required_runtime_symbol().is_none());

        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("authenticated selected Choice");
        let incumbent = compiled.program().native_dfa_view().unwrap();
        let selected = lower_atomic_exists_choice(choice, target, usize::MAX, Some(incumbent))
            .unwrap()
            .unwrap();
        assert!(selected.data.len() > 1);
        assert!(
            lower_atomic_exists_choice(
                choice,
                target,
                selected.data.len().checked_sub(1).unwrap(),
                Some(incumbent),
            )
            .unwrap()
            .is_none(),
        );
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links and executes exact-finite byte Choice objects on the host ISA"]
    fn linked_host_byte_choice_matches_portable_for_every_window() {
        use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

        let target = if cfg!(target_arch = "x86_64") {
            let base = if cfg!(target_os = "linux") {
                Target::x86_64_linux()
            } else {
                Target::x86_64_macos()
            };
            base.with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap()
        } else {
            let base = if cfg!(target_os = "linux") {
                Target::aarch64_linux()
            } else {
                Target::aarch64_macos()
            };
            base.with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap()
        };
        let compiled = compile(
            CompileRequest::new("a|z", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile host byte Choice");
        assert!(compiled.module().required_runtime_symbol().is_none());
        let reference = compile(
            CompileRequest::new("a|z", target)
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile portable byte Choice reference");

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-byte-choice-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).unwrap();
        let object = directory.join("choice.o");
        fs::write(&object, compiled.object()).unwrap();
        let symbol = compiled.module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\nint main(void){{size_t r[2];uint32_t s;\n",
        );
        let haystacks: &[&[u8]] = &[
            b"",
            b"a",
            b"z",
            b"qqqqqqqqqqqqqqq",
            b"qqqqqqqqqqqqqqqa",
            b"qqqqqqqqqqqqqqqqzqqqqqqqqqqqqqqq",
        ];
        for (index, haystack) in haystacks.iter().enumerate() {
            let bytes = if haystack.is_empty() {
                "0".to_owned()
            } else {
                haystack.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
            };
            writeln!(source, "static const unsigned char h{index}[]={{{bytes}}};").unwrap();
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let MatchResult::Exists(expected) = reference
                        .search(haystack, SearchWindow::new(start, end))
                        .unwrap()
                    else {
                        unreachable!();
                    };
                    writeln!(
                        source,
                        "r[0]=91;r[1]=92;s={symbol}(h{index},{},{start},{end},r);if(s!={}||r[0]!=0||r[1]!=0)return {};",
                        haystack.len(),
                        u8::from(expected),
                        10 + index,
                    )
                    .unwrap();
                }
            }
        }
        writeln!(
            source,
            "r[0]=93;r[1]=94;s={symbol}(h0,(size_t)-1,0,0,r);if(s!=2||r[0]!=93||r[1]!=94)return 90;return 0;}}",
        )
        .unwrap();
        let c_path = directory.join("choice.c");
        let executable = directory.join("choice");
        fs::write(&c_path, source).unwrap();
        let compiler = if cfg!(target_os = "macos") { "clang" } else { "cc" };
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .arg(&object)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("link byte Choice differential");
        assert!(status.success());
        let output = Command::new(&executable).output().unwrap();
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        fs::remove_dir_all(&directory).unwrap();
    }
}
