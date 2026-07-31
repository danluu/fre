use fre_kernel_ir::{AnchorFlags, OutputKind};

use crate::{
    AuditError, BackendVersion, Condition, DecodedInstruction, LabelKind, NativeImage,
    RelocationTarget,
    audit::{independent_sve2_class_table_offset, independent_sve2_fixed16_ascii_class_table},
    image::{SearchManifest, SearchShape},
};

type Label = usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum V26TemplateCodegen {
    AsimdV17,
    AsimdV25,
}

/// Auditor-local reconstruction of V26's width-only selector.
///
/// This deliberately shares no selector constants or function with the
/// emitter. Boundary tests keep the two implementations in agreement while
/// a drift in either implementation fails whole-image template comparison.
pub(crate) const fn independent_v26_codegen_for_literal_width(
    width: usize,
) -> Option<V26TemplateCodegen> {
    match width {
        6..=8 => Some(V26TemplateCodegen::AsimdV17),
        9..=32 => Some(V26TemplateCodegen::AsimdV25),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum ExpectedInstruction {
    Exact(DecodedInstruction),
    Address {
        destination: u8,
        rodata_offset: u32,
    },
    Branch(Label),
    BranchCondition {
        condition: Condition,
        target: Label,
    },
    CompareBranchZero64 {
        register: u8,
        nonzero: bool,
        target: Label,
    },
}

#[derive(Clone, Copy)]
struct ExpectedLabel {
    kind: LabelKind,
    instruction: Option<usize>,
}

struct Template {
    instructions: Vec<ExpectedInstruction>,
    labels: Vec<ExpectedLabel>,
}

impl Template {
    fn new() -> Self {
        Self {
            instructions: Vec::new(),
            labels: Vec::new(),
        }
    }

    fn new_label(&mut self, kind: LabelKind) -> Label {
        let label = self.labels.len();
        self.labels.push(ExpectedLabel {
            kind,
            instruction: None,
        });
        label
    }

    fn bind(&mut self, label: Label) -> Result<(), AuditError> {
        let instruction = self.instructions.len();
        let record = self
            .labels
            .get_mut(label)
            .ok_or(AuditError::ArithmeticOverflow)?;
        if record.instruction.replace(instruction).is_some() {
            return Err(invalid(instruction));
        }
        Ok(())
    }

    fn push(&mut self, instruction: DecodedInstruction) {
        self.instructions
            .push(ExpectedInstruction::Exact(instruction));
    }

    fn address(&mut self, destination: u8, rodata_offset: u32) {
        self.instructions.push(ExpectedInstruction::Address {
            destination,
            rodata_offset,
        });
    }

    fn branch(&mut self, target: Label) {
        self.instructions.push(ExpectedInstruction::Branch(target));
    }

    fn branch_cond(&mut self, condition: Condition, target: Label) {
        self.instructions
            .push(ExpectedInstruction::BranchCondition { condition, target });
    }

    fn compare_branch_zero(&mut self, register: u8, nonzero: bool, target: Label) {
        self.instructions
            .push(ExpectedInstruction::CompareBranchZero64 {
                register,
                nonzero,
                target,
            });
    }

    fn mov_reg(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::MoveRegister64 {
            destination,
            source,
        });
    }

    fn mov_imm64(&mut self, destination: u8, value: u64) {
        let mut emitted = false;
        for halfword in 0_u8..4 {
            let shift = halfword.checked_mul(16).expect("bounded halfword shift");
            let immediate = u16::try_from((value >> shift) & 0xffff).expect("masked halfword");
            if immediate == 0 && emitted {
                continue;
            }
            if emitted {
                self.push(DecodedInstruction::MoveKeep64 {
                    destination,
                    immediate,
                    shift,
                });
            } else {
                self.push(DecodedInstruction::MoveZero64 {
                    destination,
                    immediate,
                    shift,
                });
            }
            emitted = true;
        }
    }

    fn cmp_reg64(&mut self, left: u8, right: u8) {
        self.push(DecodedInstruction::CompareRegister64 { left, right });
    }

    fn cmp_reg32(&mut self, left: u8, right: u8) {
        self.push(DecodedInstruction::CompareRegister32 { left, right });
    }

    fn cmp_imm64(&mut self, register: u8, immediate: u16) {
        self.push(DecodedInstruction::CompareImmediate64 {
            register,
            immediate,
        });
    }

    fn cmp_imm32(&mut self, register: u8, immediate: u16) {
        self.push(DecodedInstruction::CompareImmediate32 {
            register,
            immediate,
        });
    }

    fn add_reg(&mut self, destination: u8, left: u8, right: u8) {
        self.push(DecodedInstruction::AddRegister64 {
            destination,
            left,
            right,
        });
    }

    fn add_imm(&mut self, destination: u8, source: u8, immediate: u16) {
        self.push(DecodedInstruction::AddImmediate64 {
            destination,
            source,
            immediate,
        });
    }

    fn sub_reg(&mut self, destination: u8, left: u8, right: u8) {
        self.push(DecodedInstruction::SubtractRegister64 {
            destination,
            left,
            right,
        });
    }

    fn sub_imm(&mut self, destination: u8, source: u8, immediate: u16) {
        self.push(DecodedInstruction::SubtractImmediate64 {
            destination,
            source,
            immediate,
        });
    }

    fn and_reg(&mut self, destination: u8, left: u8, right: u8) {
        self.push(DecodedInstruction::AndRegister64 {
            destination,
            left,
            right,
        });
    }

    fn load_byte(&mut self, destination: u8, base: u8, offset: u16) {
        self.push(DecodedInstruction::LoadByte {
            destination,
            base,
            offset,
        });
    }

    fn load16(&mut self, destination: u8, base: u8, offset: u16) {
        self.push(DecodedInstruction::Load16 {
            destination,
            base,
            offset,
        });
    }

    fn load32(&mut self, destination: u8, base: u8, offset: u16) {
        self.push(DecodedInstruction::Load32 {
            destination,
            base,
            offset,
        });
    }

    fn load_byte_reg(&mut self, destination: u8, base: u8, index: u8) {
        self.push(DecodedInstruction::LoadByteRegister {
            destination,
            base,
            index,
        });
    }

    fn load64_reg_scaled(&mut self, destination: u8, base: u8, index: u8) {
        self.push(DecodedInstruction::Load64RegisterScaled {
            destination,
            base,
            index,
        });
    }

    fn load64(&mut self, destination: u8, base: u8, offset: u16) {
        self.push(DecodedInstruction::Load64 {
            destination,
            base,
            offset,
        });
    }

    fn store64(&mut self, source: u8, base: u8, offset: u16) {
        self.push(DecodedInstruction::Store64 {
            source,
            base,
            offset,
        });
    }

    fn load_vector128(&mut self, destination: u8, base: u8, offset: u16) {
        self.push(DecodedInstruction::LoadVector128 {
            destination,
            base,
            offset,
        });
    }

    fn load_vector_pair128(
        &mut self,
        first_destination: u8,
        second_destination: u8,
        base: u8,
        offset: u16,
    ) {
        self.push(DecodedInstruction::LoadVectorPair128 {
            first_destination,
            second_destination,
            base,
            offset,
        });
    }

    fn dup_byte16(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::DuplicateByte16 {
            destination,
            source,
        });
    }

    fn compare_equal_bytes16(&mut self, destination: u8, left: u8, right: u8) {
        self.push(DecodedInstruction::CompareEqualBytes16 {
            destination,
            left,
            right,
        });
    }

    fn and_bytes16(&mut self, destination: u8, left: u8, right: u8) {
        self.push(DecodedInstruction::AndBytes16 {
            destination,
            left,
            right,
        });
    }

    fn shift_right_narrow_halfwords_to_bytes8(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
            destination,
            source,
        });
    }

    fn unsigned_min_bytes16(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::UnsignedMinBytes16 {
            destination,
            source,
        });
    }

    fn unsigned_max_bytes16(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::UnsignedMaxBytes16 {
            destination,
            source,
        });
    }

    fn unsigned_max_pairwise_bytes16(&mut self, destination: u8, left: u8, right: u8) {
        self.push(DecodedInstruction::UnsignedMaxPairwiseBytes16 {
            destination,
            left,
            right,
        });
    }

    fn move_vector_byte_to32(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::MoveVectorByteTo32 {
            destination,
            source,
        });
    }

    fn move_vector_double_to64(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::MoveVectorDoubleTo64 {
            destination,
            source,
        });
    }

    fn sve_ptrue_bytes_vl16(&mut self, destination: u8) {
        self.push(DecodedInstruction::SvePtrueBytesVl16 { destination });
    }

    fn sve_duplicate_byte(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::SveDuplicateByte {
            destination,
            source,
        });
    }

    fn sve_load_bytes(&mut self, destination: u8, predicate: u8, base: u8) {
        self.push(DecodedInstruction::SveLoadBytes {
            destination,
            predicate,
            base,
        });
    }

    fn sve_compare_equal_bytes(&mut self, destination: u8, predicate: u8, left: u8, right: u8) {
        self.push(DecodedInstruction::SveCompareEqualBytes {
            destination,
            predicate,
            left,
            right,
        });
    }

    fn sve2_match_bytes(&mut self, destination: u8, predicate: u8, left: u8, right: u8) {
        self.push(DecodedInstruction::Sve2MatchBytes {
            destination,
            predicate,
            left,
            right,
        });
    }

    fn sve_and_predicate_bytes(&mut self, destination: u8, predicate: u8, left: u8, right: u8) {
        self.push(DecodedInstruction::SveAndPredicateBytes {
            destination,
            predicate,
            left,
            right,
        });
    }

    fn sve_and_predicate_bytes_set_flags(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) {
        self.push(DecodedInstruction::SveAndPredicateBytesSetFlags {
            destination,
            predicate,
            left,
            right,
        });
    }

    fn sve_bit_clear_predicate_bytes_set_flags(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) {
        self.push(DecodedInstruction::SveBitClearPredicateBytesSetFlags {
            destination,
            predicate,
            left,
            right,
        });
    }

    fn sve_test_predicate_bytes(&mut self, predicate: u8, tested: u8) {
        self.push(DecodedInstruction::SveTestPredicateBytes { predicate, tested });
    }

    fn sve_break_before_bytes(&mut self, destination: u8, predicate: u8, source: u8) {
        self.push(DecodedInstruction::SveBreakBeforeBytes {
            destination,
            predicate,
            source,
        });
    }

    fn sve_break_after_bytes(&mut self, destination: u8, predicate: u8, source: u8) {
        self.push(DecodedInstruction::SveBreakAfterBytes {
            destination,
            predicate,
            source,
        });
    }

    fn sve_count_predicate_bytes(&mut self, destination: u8, predicate: u8, source: u8) {
        self.push(DecodedInstruction::SveCountPredicateBytes {
            destination,
            predicate,
            source,
        });
    }

    fn rbit(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::ReverseBits64 {
            destination,
            source,
        });
    }

    fn clz(&mut self, destination: u8, source: u8) {
        self.push(DecodedInstruction::CountLeadingZeros64 {
            destination,
            source,
        });
    }

    fn lsr_imm(&mut self, destination: u8, source: u8, shift: u8) {
        self.push(DecodedInstruction::LogicalShiftRightImmediate64 {
            destination,
            source,
            shift,
        });
    }

    fn and_low_bits(&mut self, destination: u8, source: u8, bits: u8) {
        self.push(DecodedInstruction::AndLowBits64 {
            destination,
            source,
            bits,
        });
    }

    fn lsrv(&mut self, destination: u8, source: u8, shift: u8) {
        self.push(DecodedInstruction::LogicalShiftRightVariable64 {
            destination,
            source,
            shift,
        });
    }

    fn ret(&mut self) {
        self.push(DecodedInstruction::Return);
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the complete symbolic instruction, branch, address, and label comparison is kept together for auditability"
    )]
    fn validate(
        self,
        image: &NativeImage,
        actual: &[DecodedInstruction],
    ) -> Result<(), AuditError> {
        if self.instructions.len() != actual.len() {
            return Err(invalid(self.instructions.len().min(actual.len())));
        }
        let label_target = |label: Label| -> Result<usize, AuditError> {
            self.labels
                .get(label)
                .and_then(|record| record.instruction)
                .ok_or(AuditError::ArithmeticOverflow)
        };
        for (index, (expected, &instruction)) in self.instructions.iter().zip(actual).enumerate() {
            match *expected {
                ExpectedInstruction::Exact(expected) if instruction == expected => {}
                ExpectedInstruction::Address {
                    destination,
                    rodata_offset,
                } => {
                    let DecodedInstruction::Address {
                        destination: actual_destination,
                        displacement,
                    } = instruction
                    else {
                        return Err(invalid(index));
                    };
                    let code_offset = instruction_offset(index)?;
                    let target = i64::from(code_offset)
                        .checked_add(i64::from(displacement))
                        .ok_or(AuditError::ArithmeticOverflow)?;
                    let expected_target = i64::from(image.layout().rodata_from_code_start)
                        .checked_add(i64::from(rodata_offset))
                        .ok_or(AuditError::ArithmeticOverflow)?;
                    if actual_destination != destination || target != expected_target {
                        return Err(invalid(index));
                    }
                    let relocation = image
                        .relocations()
                        .iter()
                        .find(|relocation| relocation.code_offset == code_offset)
                        .ok_or_else(|| invalid(index))?;
                    if relocation.target != RelocationTarget::RodataOffset(rodata_offset) {
                        return Err(invalid(index));
                    }
                }
                ExpectedInstruction::Branch(label) => {
                    let DecodedInstruction::Branch { displacement } = instruction else {
                        return Err(invalid(index));
                    };
                    if branch_target(index, displacement, actual.len())? != label_target(label)? {
                        return Err(invalid(index));
                    }
                }
                ExpectedInstruction::BranchCondition { condition, target } => {
                    let DecodedInstruction::BranchCondition {
                        condition: actual_condition,
                        displacement,
                    } = instruction
                    else {
                        return Err(invalid(index));
                    };
                    if actual_condition != condition
                        || branch_target(index, displacement, actual.len())?
                            != label_target(target)?
                    {
                        return Err(invalid(index));
                    }
                }
                ExpectedInstruction::CompareBranchZero64 {
                    register,
                    nonzero,
                    target,
                } => {
                    let DecodedInstruction::CompareBranchZero64 {
                        register: actual_register,
                        nonzero: actual_nonzero,
                        displacement,
                    } = instruction
                    else {
                        return Err(invalid(index));
                    };
                    if actual_register != register
                        || actual_nonzero != nonzero
                        || branch_target(index, displacement, actual.len())?
                            != label_target(target)?
                    {
                        return Err(invalid(index));
                    }
                }
                ExpectedInstruction::Exact(_) => return Err(invalid(index)),
            }
        }

        let mut expected_labels = Vec::with_capacity(self.labels.len());
        for label in self.labels {
            let instruction = label.instruction.ok_or(AuditError::ArithmeticOverflow)?;
            expected_labels.push((instruction_offset(instruction)?, label.kind));
        }
        expected_labels.sort_unstable();
        if image.labels().len() != expected_labels.len() {
            return Err(invalid(0));
        }
        for (actual, &(offset, kind)) in image.labels().iter().zip(&expected_labels) {
            if actual.offset != offset || actual.kind != kind {
                return Err(AuditError::InvalidLabel {
                    offset: actual.offset,
                });
            }
        }
        Ok(())
    }
}

fn instruction_offset(index: usize) -> Result<u32, AuditError> {
    u32::try_from(index)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(AuditError::ArithmeticOverflow)
}

fn branch_target(
    index: usize,
    displacement: i32,
    instruction_count: usize,
) -> Result<usize, AuditError> {
    let target = i64::from(instruction_offset(index)?)
        .checked_add(i64::from(displacement))
        .ok_or(AuditError::ArithmeticOverflow)?;
    if target < 0 || target % 4 != 0 {
        return Err(invalid(index));
    }
    let target = usize::try_from(target / 4).map_err(|_| AuditError::ArithmeticOverflow)?;
    if target >= instruction_count {
        return Err(invalid(index));
    }
    Ok(target)
}

fn invalid(index: usize) -> AuditError {
    AuditError::InvalidSearchCandidateContract {
        offset: u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .unwrap_or(u32::MAX),
    }
}

pub(crate) fn validate_search_whole_template(
    image: &NativeImage,
    manifest: SearchManifest,
    literal: &[u8],
    instructions: &[DecodedInstruction],
) -> Result<(), AuditError> {
    validate_search_whole_template_with_returns(
        image,
        manifest,
        literal,
        instructions,
        ReturnTemplate::OutSlotV1,
    )
}

pub(crate) fn validate_selected_end_register_whole_template_v2(
    image: &NativeImage,
    manifest: SearchManifest,
    literal: &[u8],
    instructions: &[DecodedInstruction],
) -> Result<(), AuditError> {
    validate_search_whole_template_with_returns(
        image,
        manifest,
        literal,
        instructions,
        ReturnTemplate::SelectedEndRegisterV2,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReturnTemplate {
    OutSlotV1,
    SelectedEndRegisterV2,
}

fn validate_search_whole_template_with_returns(
    image: &NativeImage,
    manifest: SearchManifest,
    literal: &[u8],
    instructions: &[DecodedInstruction],
    returns: ReturnTemplate,
) -> Result<(), AuditError> {
    let mut template = Template::new();
    let entry = template.new_label(LabelKind::Entry);
    let found = template.new_label(LabelKind::ReturnFound);
    let none = template.new_label(LabelKind::ReturnNone);
    template.bind(entry)?;
    emit_preamble(&mut template, none);
    match manifest.shape {
        SearchShape::ExactLiteral => {
            template.address(8, 0);
            emit_exact(&mut template, manifest, literal, found, none)?;
        }
        SearchShape::ClassSuffix => {
            template.address(8, 0);
            template.address(7, 32);
            let class = image
                .rodata()
                .get(..32)
                .ok_or(AuditError::InvalidSearchManifest)?;
            let suffix_first_class = if manifest.anchors.start || literal.is_empty() {
                None
            } else if let Some(class_byte) = independent_singleton_class_byte(class) {
                Some(SuffixFirstClass::Singleton(class_byte))
            } else if manifest.backend_version == BackendVersion::SEARCH_SVE2_16_V1
                && independent_sve2_fixed16_ascii_class_table(class).is_some()
            {
                let table_offset = independent_sve2_class_table_offset(literal.len())?;
                template.address(
                    16,
                    u32::try_from(table_offset).map_err(|_| AuditError::ArithmeticOverflow)?,
                );
                Some(SuffixFirstClass::Sve2Table)
            } else {
                None
            };
            if let Some(suffix_first_class) = suffix_first_class {
                emit_suffix_first_class(
                    &mut template,
                    suffix_first_class,
                    literal,
                    manifest,
                    found,
                    none,
                )?;
            } else {
                emit_class_suffix(&mut template, literal, manifest.anchors, found, none)?;
            }
        }
    }
    match returns {
        ReturnTemplate::OutSlotV1 => {
            emit_returns(&mut template, manifest.output, found, none)?;
        }
        ReturnTemplate::SelectedEndRegisterV2 => {
            emit_selected_end_register_returns_v2(&mut template, found, none)?;
        }
    }
    template.validate(image, instructions)
}

fn emit_preamble(template: &mut Template, none: Label) {
    template.mov_reg(9, 0);
    template.cmp_reg64(2, 3);
    template.branch_cond(Condition::Higher, none);
    template.cmp_reg64(3, 1);
    template.branch_cond(Condition::Higher, none);
}

#[allow(
    clippy::too_many_lines,
    reason = "the versioned exact-template dispatch keeps every frozen backend and V23 explicit"
)]
fn emit_exact(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    found: Label,
    none: Label,
) -> Result<(), AuditError> {
    let anchors = manifest.anchors;
    if literal.is_empty() {
        return emit_empty_literal(template, anchors, found, none);
    }
    template.mov_imm64(
        12,
        u64::try_from(literal.len()).map_err(|_| AuditError::ArithmeticOverflow)?,
    );
    if anchors.start {
        template.cmp_imm64(2, 0);
        template.branch_cond(Condition::NotEqual, none);
        template.cmp_reg64(3, 12);
        template.branch_cond(Condition::CarryClear, none);
        if anchors.end {
            template.cmp_reg64(1, 12);
            template.branch_cond(Condition::NotEqual, none);
        }
        template.mov_imm64(13, 0);
        template.mov_reg(15, 9);
        emit_literal_equality(template, 15, 8, literal.len(), none)?;
        template.mov_reg(14, 12);
        template.branch(found);
        return Ok(());
    }
    if anchors.end {
        template.cmp_reg64(1, 12);
        template.branch_cond(Condition::CarryClear, none);
        template.sub_reg(13, 1, 12);
        template.cmp_reg64(13, 2);
        template.branch_cond(Condition::CarryClear, none);
        template.cmp_reg64(3, 1);
        template.branch_cond(Condition::NotEqual, none);
        template.add_reg(15, 9, 13);
        emit_literal_equality(template, 15, 8, literal.len(), none)?;
        template.mov_reg(14, 1);
        template.branch(found);
        return Ok(());
    }
    template.sub_reg(10, 3, 2);
    template.cmp_reg64(10, 12);
    template.branch_cond(Condition::CarryClear, none);
    template.sub_reg(6, 3, 12);
    template.mov_reg(5, 2);
    match manifest.backend_version {
        BackendVersion::SEARCH_V1 => emit_exact_candidates_v1(template, literal, none, found),
        BackendVersion::SEARCH_V2 => {
            emit_exact_candidates_v2(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V3 => {
            emit_exact_candidates_v3(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V4 => {
            emit_exact_candidates_v4(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V5 => {
            emit_exact_candidates_v5(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V6 => {
            emit_exact_candidates_v6(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V7 => {
            emit_exact_candidates_v7(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE2_16_V1 => {
            emit_exact_candidates_sve16(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V8 | BackendVersion::SEARCH_SVE16_V6 => {
            emit_exact_candidates_v8(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V9 => {
            emit_exact_candidates_v9(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V10 | BackendVersion::SEARCH_V11 => {
            emit_exact_candidates_v10(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V12 => {
            emit_exact_candidates_v12(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V13 => {
            emit_exact_candidates_v13(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V14 => {
            emit_exact_candidates_v14(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V15 => {
            emit_exact_candidates_v15(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V16 => {
            emit_exact_candidates_v16(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V17 => {
            emit_exact_candidates_v17(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V18 => {
            emit_exact_candidates_v18(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V19 => {
            emit_exact_candidates_v19(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V20 => {
            emit_exact_candidates_v20(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V21 => {
            emit_exact_candidates_v21(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V22 => {
            emit_exact_candidates_v22(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V23 => {
            emit_exact_candidates_v23(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V24 => {
            emit_exact_candidates_v24(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V25 => {
            emit_exact_candidates_v25(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_V26 => {
            emit_exact_candidates_v26(template, manifest, literal, none, found)
        }
        BackendVersion::SEARCH_SVE2_FIXED16_V2 => {
            emit_exact_candidates_sve2_fixed16_v2(template, manifest, literal, none, found)
        }
        _ => Err(AuditError::InvalidSearchManifest),
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "a uniform Result signature keeps exact-shape template dispatch explicit"
)]
fn emit_empty_literal(
    template: &mut Template,
    anchors: AnchorFlags,
    found: Label,
    none: Label,
) -> Result<(), AuditError> {
    if anchors.start {
        template.cmp_imm64(2, 0);
        template.branch_cond(Condition::NotEqual, none);
        if anchors.end {
            template.cmp_imm64(1, 0);
            template.branch_cond(Condition::NotEqual, none);
        }
        template.mov_imm64(13, 0);
        template.mov_imm64(14, 0);
    } else if anchors.end {
        template.cmp_reg64(3, 1);
        template.branch_cond(Condition::NotEqual, none);
        template.mov_reg(13, 1);
        template.mov_reg(14, 1);
    } else {
        template.mov_reg(13, 2);
        template.mov_reg(14, 2);
    }
    template.branch(found);
    Ok(())
}

fn emit_returns(
    template: &mut Template,
    output: OutputKind,
    found: Label,
    none: Label,
) -> Result<(), AuditError> {
    template.bind(found)?;
    match output {
        OutputKind::Exists => {}
        OutputKind::SelectedEnd => template.store64(14, 4, 8),
        OutputKind::Span => {
            template.store64(13, 4, 0);
            template.store64(14, 4, 8);
        }
    }
    template.mov_imm64(0, 1);
    template.ret();
    template.bind(none)?;
    template.mov_imm64(0, 0);
    template.ret();
    Ok(())
}

fn emit_selected_end_register_returns_v2(
    template: &mut Template,
    found: Label,
    none: Label,
) -> Result<(), AuditError> {
    template.bind(found)?;
    template.mov_reg(0, 14);
    template.ret();
    template.bind(none)?;
    template.mov_imm64(0, 0);
    template.ret();
    Ok(())
}

fn independent_singleton_class_byte(class: &[u8]) -> Option<u8> {
    if class.len() != 32 || class.iter().map(|byte| byte.count_ones()).sum::<u32>() != 1 {
        return None;
    }
    let (index, byte) = class
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| *byte != 0)?;
    let bit = usize::try_from(byte.trailing_zeros()).ok()?;
    u8::try_from(index.checked_mul(8)?.checked_add(bit)?).ok()
}

fn emit_exact_candidates_v1(
    template: &mut Template,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let vector = template.new_label(LabelKind::Loop);
    let scalar = template.new_label(LabelKind::SlowPath);
    let advance = template.new_label(LabelKind::Internal);
    let second_filter = (literal.len() > 1).then(|| template.new_label(LabelKind::SlowPath));
    let secondary_offset = u16::try_from(literal.len().saturating_sub(1))
        .map_err(|_| AuditError::ArithmeticOverflow)?;
    template.load_byte(11, 8, 0);
    template.dup_byte16(1, 11);
    if second_filter.is_some() {
        template.load_byte(11, 8, secondary_offset);
        template.dup_byte16(3, 11);
    }
    template.bind(vector)?;
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, scalar);
    template.add_reg(15, 9, 5);
    template.load_vector128(0, 15, 0);
    template.compare_equal_bytes16(0, 0, 1);
    if let Some(second_filter) = second_filter {
        template.unsigned_max_bytes16(2, 0);
        template.move_vector_byte_to32(10, 2);
        template.compare_branch_zero(10, true, second_filter);
    } else {
        template.unsigned_max_bytes16(0, 0);
        template.move_vector_byte_to32(10, 0);
        template.compare_branch_zero(10, true, scalar);
    }
    template.bind(advance)?;
    template.add_imm(5, 5, 16);
    template.branch(vector);
    if let Some(second_filter) = second_filter {
        template.bind(second_filter)?;
        template.add_imm(10, 15, secondary_offset);
        template.load_vector128(2, 10, 0);
        template.compare_equal_bytes16(2, 2, 3);
        template.and_bytes16(0, 0, 2);
        template.unsigned_max_bytes16(0, 0);
        template.move_vector_byte_to32(10, 0);
        template.compare_branch_zero(10, true, scalar);
        template.branch(advance);
    }
    template.bind(scalar)?;
    emit_scalar_candidates_v1(template, literal, none, found)
}

fn emit_scalar_candidates_v1(
    template: &mut Template,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let scan = template.new_label(LabelKind::Loop);
    let advance = template.new_label(LabelKind::Internal);
    template.bind(scan)?;
    template.load_byte_reg(10, 9, 5);
    template.load_byte(11, 8, 0);
    template.cmp_reg32(10, 11);
    template.branch_cond(Condition::NotEqual, advance);
    template.add_reg(15, 9, 5);
    emit_literal_equality(template, 15, 8, literal.len(), advance)?;
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);
    template.bind(advance)?;
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::CarrySet, none);
    template.add_imm(5, 5, 1);
    template.branch(scan);
    Ok(())
}

fn emit_exact_candidates_v2(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let vector = template.new_label(LabelKind::Loop);
    let scalar = template.new_label(LabelKind::SlowPath);
    let advance = template.new_label(LabelKind::Internal);
    let second_filter =
        (manifest.secondary_offset != u16::MAX).then(|| template.new_label(LabelKind::SlowPath));
    let primary_offset = manifest.primary_offset;
    let secondary_offset =
        (manifest.secondary_offset != u16::MAX).then_some(manifest.secondary_offset);
    template.load_byte(11, 8, primary_offset);
    template.dup_byte16(1, 11);
    if let Some(secondary_offset) = secondary_offset {
        template.load_byte(11, 8, secondary_offset);
        template.dup_byte16(3, 11);
    }
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, scalar);
    template.sub_imm(7, 6, 15);
    template.bind(vector)?;
    template.load_vector128(0, 15, 0);
    template.compare_equal_bytes16(0, 0, 1);
    if let Some(second_filter) = second_filter {
        template.unsigned_max_pairwise_bytes16(2, 0, 0);
        template.move_vector_double_to64(10, 2);
        template.compare_branch_zero(10, true, second_filter);
    } else {
        template.unsigned_max_pairwise_bytes16(0, 0, 0);
        template.move_vector_double_to64(10, 0);
        template.compare_branch_zero(10, true, scalar);
    }
    template.bind(advance)?;
    template.add_imm(5, 5, 16);
    template.add_imm(15, 15, 16);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, vector);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(scalar);
    if let Some(second_filter) = second_filter {
        let secondary_offset = secondary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = secondary_offset.abs_diff(primary_offset);
        template.bind(second_filter)?;
        if secondary_offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(2, 10, 0);
        template.compare_equal_bytes16(2, 2, 3);
        template.and_bytes16(0, 0, 2);
        template.unsigned_max_pairwise_bytes16(0, 0, 0);
        template.move_vector_double_to64(10, 0);
        template.compare_branch_zero(10, true, scalar);
        template.branch(advance);
    }
    template.bind(scalar)?;
    emit_scalar_candidates_v2(template, literal, none, found)
}

fn emit_scalar_candidates_v2(
    template: &mut Template,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let scan = template.new_label(LabelKind::Loop);
    let advance = template.new_label(LabelKind::Internal);
    template.bind(scan)?;
    template.load_byte_reg(10, 9, 5);
    template.load_byte(11, 8, 0);
    template.cmp_reg32(10, 11);
    template.branch_cond(Condition::NotEqual, advance);
    template.add_reg(15, 9, 5);
    if literal.len() == 16 {
        emit_literal_equality_16(template, 15, 8, advance);
    } else {
        emit_literal_equality(template, 15, 8, literal.len(), advance)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);
    template.bind(advance)?;
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::CarrySet, none);
    template.add_imm(5, 5, 1);
    template.branch(scan);
    Ok(())
}

fn emit_exact_candidates_v3(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let vector = template.new_label(LabelKind::Loop);
    let scalar = template.new_label(LabelKind::SlowPath);
    let advance = template.new_label(LabelKind::Internal);
    let block_setup = template.new_label(LabelKind::SlowPath);
    let tail_setup = template.new_label(LabelKind::SlowPath);
    let second_filter =
        (manifest.secondary_offset != u16::MAX).then(|| template.new_label(LabelKind::SlowPath));
    let primary_offset = manifest.primary_offset;
    let secondary_offset =
        (manifest.secondary_offset != u16::MAX).then_some(manifest.secondary_offset);
    template.load_byte(11, 8, primary_offset);
    template.dup_byte16(1, 11);
    if let Some(secondary_offset) = secondary_offset {
        template.load_byte(11, 8, secondary_offset);
        template.dup_byte16(3, 11);
    }
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, tail_setup);
    template.sub_imm(7, 6, 15);
    template.bind(vector)?;
    template.load_vector128(0, 15, 0);
    template.compare_equal_bytes16(0, 0, 1);
    if let Some(second_filter) = second_filter {
        template.unsigned_max_pairwise_bytes16(2, 0, 0);
        template.move_vector_double_to64(10, 2);
        template.compare_branch_zero(10, true, second_filter);
    } else {
        template.unsigned_max_pairwise_bytes16(0, 0, 0);
        template.move_vector_double_to64(10, 0);
        template.compare_branch_zero(10, true, block_setup);
    }
    template.bind(advance)?;
    template.add_imm(5, 5, 16);
    template.add_imm(15, 15, 16);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, vector);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);
    if let Some(second_filter) = second_filter {
        let secondary_offset = secondary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = secondary_offset.abs_diff(primary_offset);
        template.bind(second_filter)?;
        if secondary_offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(2, 10, 0);
        template.compare_equal_bytes16(2, 2, 3);
        template.and_bytes16(0, 0, 2);
        template.unsigned_max_pairwise_bytes16(0, 0, 0);
        template.move_vector_double_to64(10, 0);
        template.compare_branch_zero(10, true, block_setup);
        template.branch(advance);
    }
    template.bind(block_setup)?;
    template.mov_imm64(13, 1);
    template.add_imm(7, 5, 15);
    template.branch(scalar);
    template.bind(tail_setup)?;
    template.mov_imm64(13, 0);
    template.mov_reg(7, 6);
    template.bind(scalar)?;
    emit_scalar_candidates_v3(
        template,
        literal,
        primary_offset,
        secondary_offset,
        vector,
        tail_setup,
        none,
        found,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "every block-recovery register, offset, and target remains explicit"
)]
fn emit_scalar_candidates_v3(
    template: &mut Template,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    vector: Label,
    tail_setup: Label,
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let scan = template.new_label(LabelKind::Loop);
    let advance = template.new_label(LabelKind::Internal);
    let exhausted = template.new_label(LabelKind::Internal);
    let block_resume = template.new_label(LabelKind::Internal);
    template.bind(scan)?;
    template.load_byte_reg(10, 9, 5);
    template.load_byte(11, 8, 0);
    template.cmp_reg32(10, 11);
    template.branch_cond(Condition::NotEqual, advance);
    template.add_reg(15, 9, 5);
    if literal.len() == 16 {
        emit_literal_equality_16(template, 15, 8, advance);
    } else {
        emit_literal_equality(template, 15, 8, literal.len(), advance)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);
    template.bind(advance)?;
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::CarrySet, exhausted);
    template.add_imm(5, 5, 1);
    template.branch(scan);
    template.bind(exhausted)?;
    template.compare_branch_zero(13, true, block_resume);
    template.branch(none);
    template.bind(block_resume)?;
    template.load_byte(11, 8, primary_offset);
    template.dup_byte16(1, 11);
    if let Some(secondary_offset) = secondary_offset {
        template.load_byte(11, 8, secondary_offset);
        template.dup_byte16(3, 11);
    }
    template.add_imm(5, 5, 1);
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.sub_imm(7, 6, 15);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, vector);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);
    Ok(())
}

fn emit_exact_candidates_v9(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v10(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v12(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v13(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v14(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v15(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    template.mov_reg(10, 10);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v16(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v17(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v18(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v19(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v20(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v21(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v22(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v23(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    if literal.len() < 6 || literal.len() > 32 {
        return Err(AuditError::InvalidSearchManifest);
    }
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v24(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    if literal.len() < 6 || literal.len() > 32 {
        return Err(AuditError::InvalidSearchManifest);
    }
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v25(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    if literal.len() < 6 || literal.len() > 32 {
        return Err(AuditError::InvalidSearchManifest);
    }
    let first_candidate_miss = template.new_label(LabelKind::Internal);
    let selected = literal
        .get(usize::from(manifest.primary_offset))
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)?;

    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, manifest.primary_offset);
    template.cmp_imm32(10, u16::from(selected));
    template.branch_cond(Condition::NotEqual, first_candidate_miss);
    if literal.len() > 1 {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), first_candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(first_candidate_miss)?;
    template.add_imm(5, 5, 1);
    emit_exact_candidates_v8(template, manifest, literal, none, found)
}

fn emit_exact_candidates_v26(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let codegen = independent_v26_codegen_for_literal_width(literal.len())
        .ok_or(AuditError::InvalidSearchManifest)?;
    let source_manifest = SearchManifest {
        backend_version: match codegen {
            V26TemplateCodegen::AsimdV17 => BackendVersion::SEARCH_V17,
            V26TemplateCodegen::AsimdV25 => BackendVersion::SEARCH_V25,
        },
        ..manifest
    };
    match codegen {
        V26TemplateCodegen::AsimdV17 => {
            emit_exact_candidates_v17(template, source_manifest, literal, none, found)
        }
        V26TemplateCodegen::AsimdV25 => {
            emit_exact_candidates_v25(template, source_manifest, literal, none, found)
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete v4 mask-guided control-flow template remains independent and reviewable"
)]
fn emit_exact_candidates_v4(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    emit_exact_candidates_mask(template, manifest, literal, None, none, found)
}

fn emit_exact_candidates_v5(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let verification_offset =
        (manifest.verification_offset != u16::MAX).then_some(manifest.verification_offset);
    emit_exact_candidates_mask(
        template,
        manifest,
        literal,
        verification_offset,
        none,
        found,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent v6 sparse-lane template keeps mask construction, selection order, bounds, and resume edges explicit"
)]
fn emit_exact_candidates_v6(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let vector = template.new_label(LabelKind::Loop);
    let advance = template.new_label(LabelKind::Internal);
    let recover = template.new_label(LabelKind::SlowPath);
    let lane_loop = template.new_label(LabelKind::Loop);
    let candidate_miss = template.new_label(LabelKind::Internal);
    let block_resume = template.new_label(LabelKind::Internal);
    let tail_setup = template.new_label(LabelKind::SlowPath);
    let second_filter =
        (manifest.secondary_offset != u16::MAX).then(|| template.new_label(LabelKind::SlowPath));
    let primary_offset = manifest.primary_offset;
    let secondary_offset =
        (manifest.secondary_offset != u16::MAX).then_some(manifest.secondary_offset);
    let verification_offset =
        (manifest.verification_offset != u16::MAX).then_some(manifest.verification_offset);

    template.load_byte(11, 8, primary_offset);
    template.dup_byte16(1, 11);
    if let Some(secondary_offset) = secondary_offset {
        template.load_byte(11, 8, secondary_offset);
        template.dup_byte16(3, 11);
    }
    if let Some(verification_offset) = verification_offset {
        template.load_byte(11, 8, verification_offset);
        template.dup_byte16(5, 11);
    }
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, tail_setup);
    template.sub_imm(7, 6, 15);
    template.bind(vector)?;
    template.load_vector128(0, 15, 0);
    template.compare_equal_bytes16(0, 0, 1);
    if let Some(second_filter) = second_filter {
        template.unsigned_max_pairwise_bytes16(2, 0, 0);
        template.move_vector_double_to64(10, 2);
        template.compare_branch_zero(10, true, second_filter);
    } else {
        emit_sparse_lane_mask(template);
        template.compare_branch_zero(0, true, recover);
    }
    template.bind(advance)?;
    template.add_imm(5, 5, 16);
    template.add_imm(15, 15, 16);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, vector);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);
    if let Some(second_filter) = second_filter {
        let secondary_offset = secondary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let secondary_delta = secondary_offset.abs_diff(primary_offset);
        template.bind(second_filter)?;
        if secondary_offset > primary_offset {
            template.add_imm(10, 15, secondary_delta);
        } else {
            template.sub_imm(10, 15, secondary_delta);
        }
        template.load_vector128(2, 10, 0);
        template.compare_equal_bytes16(2, 2, 3);
        template.and_bytes16(0, 0, 2);
        if let Some(verification_offset) = verification_offset {
            let verification_delta = verification_offset.abs_diff(primary_offset);
            if verification_offset > primary_offset {
                template.add_imm(10, 15, verification_delta);
            } else {
                template.sub_imm(10, 15, verification_delta);
            }
            template.load_vector128(4, 10, 0);
            template.compare_equal_bytes16(4, 4, 5);
            template.and_bytes16(0, 0, 4);
        }
        emit_sparse_lane_mask(template);
        template.compare_branch_zero(0, true, recover);
        template.branch(advance);
    }

    template.bind(recover)?;
    template.mov_reg(7, 5);
    template.bind(lane_loop)?;
    template.rbit(10, 0);
    template.clz(10, 10);
    template.lsr_imm(10, 10, 2);
    template.add_reg(5, 7, 10);
    template.load_byte_reg(10, 9, 5);
    template.load_byte(11, 8, 0);
    template.cmp_reg32(10, 11);
    template.branch_cond(Condition::NotEqual, candidate_miss);
    template.add_reg(15, 9, 5);
    if literal.len() == 16 {
        emit_literal_equality_16(template, 15, 8, candidate_miss);
    } else {
        emit_literal_equality(template, 15, 8, literal.len(), candidate_miss)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(candidate_miss)?;
    template.sub_imm(10, 0, 1);
    template.and_reg(0, 0, 10);
    template.compare_branch_zero(0, true, lane_loop);
    template.bind(block_resume)?;
    template.add_imm(5, 7, 16);
    template.load_byte(11, 8, primary_offset);
    template.dup_byte16(1, 11);
    if let Some(secondary_offset) = secondary_offset {
        template.load_byte(11, 8, secondary_offset);
        template.dup_byte16(3, 11);
    }
    if let Some(verification_offset) = verification_offset {
        template.load_byte(11, 8, verification_offset);
        template.dup_byte16(5, 11);
    }
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.sub_imm(7, 6, 15);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, vector);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);

    template.bind(tail_setup)?;
    emit_scalar_candidates_v2(template, literal, none, found)
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent v7 template keeps staged survivor tests, ranked columns, lane order, and resume bounds explicit"
)]
fn emit_exact_candidates_v7(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let vector = template.new_label(LabelKind::Loop);
    let advance = template.new_label(LabelKind::Internal);
    let recover = template.new_label(LabelKind::SlowPath);
    let lane_loop = template.new_label(LabelKind::Loop);
    let candidate_miss = template.new_label(LabelKind::Internal);
    let tail_setup = template.new_label(LabelKind::SlowPath);
    let primary_offset = manifest.primary_offset;
    let secondary_offset =
        (manifest.secondary_offset != u16::MAX).then_some(manifest.secondary_offset);
    let verification_offset =
        (manifest.verification_offset != u16::MAX).then_some(manifest.verification_offset);
    let quaternary_offset =
        (manifest.quaternary_offset != u16::MAX).then_some(manifest.quaternary_offset);
    let second_filter = secondary_offset.map(|_| template.new_label(LabelKind::SlowPath));
    let third_filter = verification_offset.map(|_| template.new_label(LabelKind::SlowPath));
    let fourth_filter = quaternary_offset.map(|_| template.new_label(LabelKind::SlowPath));
    let filters_cover_zero = primary_offset == 0
        || secondary_offset == Some(0)
        || verification_offset == Some(0)
        || quaternary_offset == Some(0);

    template.load_byte(11, 8, primary_offset);
    template.dup_byte16(1, 11);
    if let Some(offset) = secondary_offset {
        template.load_byte(11, 8, offset);
        template.dup_byte16(3, 11);
    }
    if let Some(offset) = verification_offset {
        template.load_byte(11, 8, offset);
        template.dup_byte16(5, 11);
    }
    if let Some(offset) = quaternary_offset {
        template.load_byte(11, 8, offset);
        template.dup_byte16(7, 11);
    }
    template.mov_imm64(14, 0x1111_1111_1111_1111);
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, tail_setup);
    template.sub_imm(7, 6, 15);

    template.bind(vector)?;
    template.load_vector128(0, 15, 0);
    template.compare_equal_bytes16(0, 0, 1);
    if let Some(second_filter) = second_filter {
        template.unsigned_max_pairwise_bytes16(2, 0, 0);
        template.move_vector_double_to64(10, 2);
        template.compare_branch_zero(10, true, second_filter);
    } else {
        emit_sparse_lane_mask_v7(template);
        template.compare_branch_zero(0, true, recover);
    }

    template.bind(advance)?;
    template.add_imm(5, 5, 16);
    template.add_imm(15, 15, 16);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, vector);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);

    if let Some(second_filter) = second_filter {
        let offset = secondary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = offset.abs_diff(primary_offset);
        template.bind(second_filter)?;
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(2, 10, 0);
        template.compare_equal_bytes16(2, 2, 3);
        template.and_bytes16(0, 0, 2);
        emit_sparse_lane_mask_v7(template);
        template.compare_branch_zero(0, false, advance);
        if let Some(third_filter) = third_filter {
            emit_branch_if_mask_has_multiple(template, 0, 10, third_filter);
        }
        template.branch(recover);
    }

    if let Some(third_filter) = third_filter {
        let offset = verification_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = offset.abs_diff(primary_offset);
        template.bind(third_filter)?;
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(4, 10, 0);
        template.compare_equal_bytes16(4, 4, 5);
        template.and_bytes16(0, 0, 4);
        emit_sparse_lane_mask_v7(template);
        template.compare_branch_zero(0, false, advance);
        if let Some(fourth_filter) = fourth_filter {
            emit_branch_if_mask_has_multiple(template, 0, 10, fourth_filter);
        }
        template.branch(recover);
    }

    if let Some(fourth_filter) = fourth_filter {
        let offset = quaternary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = offset.abs_diff(primary_offset);
        template.bind(fourth_filter)?;
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(6, 10, 0);
        template.compare_equal_bytes16(6, 6, 7);
        template.and_bytes16(0, 0, 6);
        emit_sparse_lane_mask_v7(template);
        template.compare_branch_zero(0, true, recover);
        template.branch(advance);
    }

    template.bind(recover)?;
    template.mov_reg(7, 5);
    template.bind(lane_loop)?;
    template.rbit(10, 0);
    template.clz(10, 10);
    template.lsr_imm(10, 10, 2);
    template.add_reg(5, 7, 10);
    if !filters_cover_zero {
        template.load_byte_reg(10, 9, 5);
        template.load_byte(11, 8, 0);
        template.cmp_reg32(10, 11);
        template.branch_cond(Condition::NotEqual, candidate_miss);
    }
    template.add_reg(15, 9, 5);
    if literal.len() == 16 {
        emit_literal_equality_16_with_vectors(template, 15, 8, candidate_miss, 16, 17);
    } else {
        emit_literal_equality_with_vectors(
            template,
            15,
            8,
            literal.len(),
            candidate_miss,
            16,
            17,
            11,
        )?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(candidate_miss)?;
    template.sub_imm(10, 0, 1);
    template.and_reg(0, 0, 10);
    template.compare_branch_zero(0, true, lane_loop);
    template.add_imm(5, 7, 16);
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.sub_imm(7, 6, 15);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, vector);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);

    template.bind(tail_setup)?;
    emit_scalar_candidates_v2(template, literal, none, found)
}

fn emit_exact_candidates_sve16(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let vector = template.new_label(LabelKind::Loop);
    let advance = template.new_label(LabelKind::Internal);
    let candidate_miss = template.new_label(LabelKind::Internal);
    let tail = template.new_label(LabelKind::SlowPath);
    let offsets = [
        Some(manifest.primary_offset),
        (manifest.secondary_offset != u16::MAX).then_some(manifest.secondary_offset),
        (manifest.verification_offset != u16::MAX).then_some(manifest.verification_offset),
        (manifest.quaternary_offset != u16::MAX).then_some(manifest.quaternary_offset),
    ];

    template.sve_ptrue_bytes_vl16(0);
    for (index, offset) in offsets.into_iter().enumerate() {
        let Some(offset) = offset else {
            continue;
        };
        let constant = u8::try_from(
            index
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or(AuditError::ArithmeticOverflow)?,
        )
        .map_err(|_| AuditError::ArithmeticOverflow)?;
        template.load_byte(11, 8, offset);
        template.sve_duplicate_byte(constant, 11);
    }

    template.bind(vector)?;
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, tail);
    template.add_reg(15, 9, 5);

    for (index, offset) in offsets.into_iter().enumerate() {
        let Some(offset) = offset else {
            continue;
        };
        let loaded = u8::try_from(index.checked_mul(2).ok_or(AuditError::ArithmeticOverflow)?)
            .map_err(|_| AuditError::ArithmeticOverflow)?;
        let constant = loaded
            .checked_add(1)
            .ok_or(AuditError::ArithmeticOverflow)?;
        let result_predicate = if index == 0 { 1 } else { 2 };
        let base = if offset == 0 {
            15
        } else {
            template.add_imm(10, 15, offset);
            10
        };
        template.sve_load_bytes(loaded, 0, base);
        if manifest.backend_version == BackendVersion::SEARCH_SVE2_16_V1 {
            template.sve2_match_bytes(result_predicate, 0, loaded, constant);
        } else {
            template.sve_compare_equal_bytes(result_predicate, 0, loaded, constant);
        }
        if index != 0 {
            template.sve_and_predicate_bytes(1, 0, 1, result_predicate);
        }
        template.sve_test_predicate_bytes(0, 1);
        template.branch_cond(Condition::Equal, advance);
    }

    template.sve_break_before_bytes(3, 0, 1);
    template.sve_count_predicate_bytes(10, 0, 3);
    template.add_reg(13, 5, 10);
    template.add_reg(15, 9, 13);
    emit_literal_equality_with_vectors(template, 15, 8, literal.len(), candidate_miss, 0, 2, 11)?;
    template.add_reg(14, 13, 12);
    template.branch(found);

    template.bind(candidate_miss)?;
    template.add_imm(5, 13, 1);
    template.branch(vector);

    template.bind(advance)?;
    template.add_imm(5, 5, 16);
    template.branch(vector);

    template.bind(tail)?;
    emit_scalar_candidates_v2(template, literal, none, found)
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent v8 template reconstructs the paired wide screen and authenticated staged fallback without sharing emitter control flow"
)]
fn emit_exact_candidates_v8(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let primary_offset = manifest.primary_offset;
    let secondary_offset =
        (manifest.secondary_offset != u16::MAX).then_some(manifest.secondary_offset);
    let verification_offset =
        (manifest.verification_offset != u16::MAX).then_some(manifest.verification_offset);
    let quaternary_offset =
        (manifest.quaternary_offset != u16::MAX).then_some(manifest.quaternary_offset);
    let quinary_offset = (manifest.quinary_offset != u16::MAX).then_some(manifest.quinary_offset);
    let persistent_backend = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    );
    let pointer_authoritative_wide = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V23 | BackendVersion::SEARCH_V24 | BackendVersion::SEARCH_V25
    );
    let sixth_static_offset = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V24 | BackendVersion::SEARCH_V25
    )
    .then(|| {
        independent_adaptive_offsets_v13(
            literal,
            primary_offset,
            secondary_offset,
            verification_offset,
            quaternary_offset,
            quinary_offset,
        )
        .iter()
        .next()
        .copied()
        .ok_or(AuditError::InvalidSearchManifest)
    })
    .transpose()?;
    let wide = template.new_label(LabelKind::Loop);
    let wide_advance = template.new_label(LabelKind::Internal);
    let sixth_empty_promote = (manifest.backend_version == BackendVersion::SEARCH_V25)
        .then(|| template.new_label(LabelKind::Internal));
    let secondary_only = secondary_offset.map(|_| template.new_label(LabelKind::Loop));
    let secondary_only_advance = secondary_offset.map(|_| template.new_label(LabelKind::Internal));
    let wide_third_filter = (manifest.backend_version == BackendVersion::SEARCH_V18)
        .then(|| template.new_label(LabelKind::SlowPath));
    let wide_third_column = (manifest.backend_version == BackendVersion::SEARCH_V18)
        .then(|| template.new_label(LabelKind::SlowPath));
    let wide_dense_pair = (manifest.backend_version == BackendVersion::SEARCH_V18)
        .then(|| template.new_label(LabelKind::SlowPath));
    let wide_remaining_columns = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::SlowPath));
    let saved_mask_recover = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::SlowPath));
    let saved_mask_next = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Loop));
    let saved_mask_lane = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Loop));
    let saved_mask_miss = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Internal));
    let saved_mask_done = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Internal));
    let wide_learn_select = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::SlowPath));
    let wide_learn_candidate = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Loop));
    let wide_learn_miss = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Internal));
    let wide_learn_discover = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Loop));
    let wide_learn_ready = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::SlowPath));
    let wide_learn_empty = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Internal));
    let persistent_wide = persistent_backend.then(|| template.new_label(LabelKind::Loop));
    let persistent_advance = persistent_backend.then(|| template.new_label(LabelKind::Internal));
    let narrow_setup = template.new_label(LabelKind::Internal);
    let narrow = template.new_label(LabelKind::Loop);
    let advance = template.new_label(LabelKind::Internal);
    let recover = template.new_label(LabelKind::SlowPath);
    let lane_loop = template.new_label(LabelKind::Loop);
    let candidate_miss = template.new_label(LabelKind::Internal);
    let recovery_exhausted = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V13
            | BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
    )
    .then(|| template.new_label(LabelKind::Internal));
    let adaptive_recovery = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V13
            | BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
    )
    .then(|| template.new_label(LabelKind::SlowPath));
    let learned_discover = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
            | BackendVersion::SEARCH_V17
            | BackendVersion::SEARCH_V18
            | BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Loop));
    let learned_column_ready = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
            | BackendVersion::SEARCH_V17
            | BackendVersion::SEARCH_V18
            | BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::SlowPath));
    let learned_advance = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
            | BackendVersion::SEARCH_V17
            | BackendVersion::SEARCH_V18
            | BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Internal));
    let learned_scan = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
            | BackendVersion::SEARCH_V17
            | BackendVersion::SEARCH_V18
            | BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::Loop));
    let learned_disabled = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V14 | BackendVersion::SEARCH_V15 | BackendVersion::SEARCH_V16
    )
    .then(|| template.new_label(LabelKind::SlowPath));
    let learned_tail = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
            | BackendVersion::SEARCH_V17
            | BackendVersion::SEARCH_V18
            | BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    )
    .then(|| template.new_label(LabelKind::SlowPath));
    let tail_setup = template.new_label(LabelKind::SlowPath);
    let wide_second_filter = secondary_offset.map(|_| template.new_label(LabelKind::SlowPath));
    let second_filter = secondary_offset.map(|_| template.new_label(LabelKind::SlowPath));
    let third_filter = verification_offset.map(|_| template.new_label(LabelKind::SlowPath));
    let fourth_filter = quaternary_offset.map(|_| template.new_label(LabelKind::SlowPath));
    let fifth_filter = quinary_offset.map(|_| template.new_label(LabelKind::SlowPath));
    let filters_cover_zero = primary_offset == 0
        || secondary_offset == Some(0)
        || verification_offset == Some(0)
        || quaternary_offset == Some(0)
        || quinary_offset == Some(0);
    let sve_confirmation =
        manifest.backend_version == BackendVersion::SEARCH_SVE16_V6 && literal.len() >= 16;

    template.load_byte(11, 8, primary_offset);
    template.dup_byte16(1, 11);
    if let Some(offset) = secondary_offset {
        template.load_byte(11, 8, offset);
        template.dup_byte16(3, 11);
    }
    if let Some(offset) = verification_offset {
        template.load_byte(11, 8, offset);
        template.dup_byte16(5, 11);
    }
    if let Some(offset) = quaternary_offset {
        template.load_byte(11, 8, offset);
        template.dup_byte16(7, 11);
    }
    if let Some(offset) = quinary_offset {
        template.load_byte(11, 8, offset);
        template.dup_byte16(23, 11);
    }
    if sve_confirmation {
        template.sve_ptrue_bytes_vl16(0);
        template.sve_load_bytes(31, 0, 8);
    }
    if matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
            | BackendVersion::SEARCH_V17
            | BackendVersion::SEARCH_V18
            | BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    ) {
        if !filters_cover_zero {
            return Err(AuditError::InvalidSearchManifest);
        }
        template.mov_imm64(11, 0);
    } else if !filters_cover_zero {
        template.mov_imm64(11, u64::from(literal[0]));
    }
    template.mov_imm64(14, 0x1111_1111_1111_1111);
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, tail_setup);
    template.cmp_imm64(10, 63);
    template.branch_cond(Condition::CarryClear, narrow_setup);
    template.sub_imm(7, 6, 63);
    if pointer_authoritative_wide {
        template.add_reg(13, 9, 7);
        if primary_offset != 0 {
            template.add_imm(13, 13, primary_offset);
        }
    }

    template.bind(wide)?;
    template.load_vector_pair128(0, 2, 15, 0);
    template.load_vector_pair128(4, 6, 15, 32);
    template.compare_equal_bytes16(0, 0, 1);
    template.compare_equal_bytes16(2, 2, 1);
    template.compare_equal_bytes16(4, 4, 1);
    template.compare_equal_bytes16(6, 6, 1);
    emit_four_block_presence_v8(template);
    if let Some(wide_second_filter) = wide_second_filter {
        template.compare_branch_zero(10, true, wide_second_filter);
    } else {
        template.compare_branch_zero(10, true, narrow_setup);
    }

    template.bind(wide_advance)?;
    if pointer_authoritative_wide {
        template.add_imm(15, 15, 64);
        template.cmp_reg64(15, 13);
        template.branch_cond(Condition::LowerOrSame, wide);
        template.sub_reg(5, 15, 9);
        if primary_offset != 0 {
            template.sub_imm(5, 5, primary_offset);
        }
        template.branch(narrow_setup);
    } else {
        template.add_imm(5, 5, 64);
        template.add_imm(15, 15, 64);
        template.cmp_reg64(5, 7);
        template.branch_cond(Condition::LowerOrSame, wide);
        template.branch(narrow_setup);
    }

    if let Some(wide_second_filter) = wide_second_filter {
        let offset = secondary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = offset.abs_diff(primary_offset);
        template.bind(wide_second_filter)?;
        if pointer_authoritative_wide {
            template.sub_reg(5, 15, 9);
            if primary_offset != 0 {
                template.sub_imm(5, 5, primary_offset);
            }
        }
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector_pair128(18, 19, 10, 0);
        template.load_vector_pair128(20, 21, 10, 32);
        template.compare_equal_bytes16(18, 18, 3);
        template.and_bytes16(0, 0, 18);
        template.compare_equal_bytes16(19, 19, 3);
        template.and_bytes16(2, 2, 19);
        template.compare_equal_bytes16(20, 20, 3);
        template.and_bytes16(4, 4, 20);
        template.compare_equal_bytes16(21, 21, 3);
        template.and_bytes16(6, 6, 21);
        emit_four_block_presence_v8(template);
        if manifest.backend_version == BackendVersion::SEARCH_V18 {
            let pair_empty = secondary_only_advance.ok_or(AuditError::InvalidSearchManifest)?;
            template.compare_branch_zero(10, false, pair_empty);
        } else if manifest.backend_version == BackendVersion::SEARCH_V19 {
            let saved = saved_mask_recover.ok_or(AuditError::InvalidSearchManifest)?;
            template.compare_branch_zero(10, true, saved);
        } else if matches!(
            manifest.backend_version,
            BackendVersion::SEARCH_V20
                | BackendVersion::SEARCH_V21
                | BackendVersion::SEARCH_V22
                | BackendVersion::SEARCH_V23
                | BackendVersion::SEARCH_V24
                | BackendVersion::SEARCH_V25
        ) {
            let pair_empty = secondary_only_advance.ok_or(AuditError::InvalidSearchManifest)?;
            let remaining = wide_remaining_columns.ok_or(AuditError::InvalidSearchManifest)?;
            template.compare_branch_zero(10, false, pair_empty);
            template.branch(remaining);
        } else {
            template.compare_branch_zero(10, true, narrow_setup);
        }
    }

    if let Some(wide_third_filter) = wide_third_filter {
        template.bind(wide_third_filter)?;
        let third_column = wide_third_column.ok_or(AuditError::InvalidSearchManifest)?;
        let dense_pair = wide_dense_pair.ok_or(AuditError::InvalidSearchManifest)?;
        emit_branch_if_four_masks_have_multiple(template, dense_pair);
        template.bind(third_column)?;
        let offset = verification_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = offset.abs_diff(primary_offset);
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector_pair128(18, 19, 10, 0);
        template.load_vector_pair128(20, 21, 10, 32);
        template.compare_equal_bytes16(18, 18, 5);
        template.and_bytes16(0, 0, 18);
        template.compare_equal_bytes16(19, 19, 5);
        template.and_bytes16(2, 2, 19);
        template.compare_equal_bytes16(20, 20, 5);
        template.and_bytes16(4, 4, 20);
        template.compare_equal_bytes16(21, 21, 5);
        template.and_bytes16(6, 6, 21);
        emit_four_block_presence_v8(template);
        template.compare_branch_zero(10, false, wide_advance);
        template.branch(narrow_setup);

        template.bind(dense_pair)?;
        template.compare_branch_zero(11, true, narrow_setup);
        template.mov_imm64(11, 1);
        template.branch(third_column);
    }

    if let (Some(secondary_only), Some(secondary_only_advance), Some(offset)) =
        (secondary_only, secondary_only_advance, secondary_offset)
    {
        if manifest.backend_version != BackendVersion::SEARCH_V18 {
            template.bind(secondary_only_advance)?;
            template.add_imm(5, 5, 64);
            template.add_imm(15, 15, 64);
            template.cmp_reg64(5, 7);
            template.branch_cond(Condition::LowerOrSame, secondary_only);
            template.branch(narrow_setup);

            template.bind(secondary_only)?;
            let delta = offset.abs_diff(primary_offset);
            if offset > primary_offset {
                template.add_imm(10, 15, delta);
            } else {
                template.sub_imm(10, 15, delta);
            }
            template.load_vector_pair128(0, 2, 10, 0);
            template.load_vector_pair128(4, 6, 10, 32);
            template.compare_equal_bytes16(0, 0, 3);
            template.compare_equal_bytes16(2, 2, 3);
            template.compare_equal_bytes16(4, 4, 3);
            template.compare_equal_bytes16(6, 6, 3);
            emit_four_block_presence_v8(template);
            template.compare_branch_zero(10, false, secondary_only_advance);
            template.load_vector_pair128(18, 19, 15, 0);
            template.load_vector_pair128(20, 21, 15, 32);
            template.compare_equal_bytes16(18, 18, 1);
            template.and_bytes16(0, 0, 18);
            template.compare_equal_bytes16(19, 19, 1);
            template.and_bytes16(2, 2, 19);
            template.compare_equal_bytes16(20, 20, 1);
            template.and_bytes16(4, 4, 20);
            template.compare_equal_bytes16(21, 21, 1);
            template.and_bytes16(6, 6, 21);
            emit_four_block_presence_v8(template);
            template.compare_branch_zero(10, false, wide_advance);
            if matches!(
                manifest.backend_version,
                BackendVersion::SEARCH_V20
                    | BackendVersion::SEARCH_V21
                    | BackendVersion::SEARCH_V22
                    | BackendVersion::SEARCH_V23
                    | BackendVersion::SEARCH_V24
                    | BackendVersion::SEARCH_V25
            ) {
                template.branch(wide_remaining_columns.ok_or(AuditError::InvalidSearchManifest)?);
            }
        }
    }

    if let Some(remaining) = wide_remaining_columns {
        let saved = saved_mask_recover.ok_or(AuditError::InvalidSearchManifest)?;
        let recovery = wide_learn_select.unwrap_or(saved);
        let columns = [
            (verification_offset, 5_u8),
            (quaternary_offset, 7_u8),
            (quinary_offset, 23_u8),
        ];
        let column_count = columns
            .iter()
            .filter(|(offset, _)| offset.is_some())
            .count();
        let mut emitted_columns = 0_usize;

        template.bind(remaining)?;
        for &(offset, constant) in &columns {
            let Some(offset) = offset else {
                continue;
            };
            let delta = offset.abs_diff(primary_offset);
            if offset > primary_offset {
                template.add_imm(10, 15, delta);
            } else {
                template.sub_imm(10, 15, delta);
            }
            template.load_vector_pair128(18, 19, 10, 0);
            template.load_vector_pair128(20, 21, 10, 32);
            template.compare_equal_bytes16(18, 18, constant);
            template.and_bytes16(0, 0, 18);
            template.compare_equal_bytes16(19, 19, constant);
            template.and_bytes16(2, 2, 19);
            template.compare_equal_bytes16(20, 20, constant);
            template.and_bytes16(4, 4, 20);
            template.compare_equal_bytes16(21, 21, constant);
            template.and_bytes16(6, 6, 21);
            emitted_columns = emitted_columns
                .checked_add(1)
                .ok_or(AuditError::ArithmeticOverflow)?;
            if emitted_columns == 1 && column_count > 1 {
                emit_four_block_presence_v8(template);
                template.compare_branch_zero(10, false, wide_advance);
            }
        }
        if emitted_columns == 0 {
            template.branch(recovery);
        } else {
            emit_four_block_presence_v8(template);
            template.compare_branch_zero(10, false, wide_advance);
            if let Some(offset) = sixth_static_offset {
                template.load_byte(10, 8, offset);
                template.dup_byte16(24, 10);
                let delta = offset.abs_diff(primary_offset);
                if offset > primary_offset {
                    template.add_imm(10, 15, delta);
                } else {
                    template.sub_imm(10, 15, delta);
                }
                template.load_vector_pair128(18, 19, 10, 0);
                template.load_vector_pair128(20, 21, 10, 32);
                template.compare_equal_bytes16(18, 18, 24);
                template.and_bytes16(0, 0, 18);
                template.compare_equal_bytes16(19, 19, 24);
                template.and_bytes16(2, 2, 19);
                template.compare_equal_bytes16(20, 20, 24);
                template.and_bytes16(4, 4, 20);
                template.compare_equal_bytes16(21, 21, 24);
                template.and_bytes16(6, 6, 21);
                emit_four_block_presence_v8(template);
                template.compare_branch_zero(
                    10,
                    false,
                    sixth_empty_promote.unwrap_or(wide_advance),
                );
            }
            template.branch(recovery);
            if let (Some(promote), Some(offset)) = (sixth_empty_promote, sixth_static_offset) {
                template.bind(promote)?;
                template.mov_imm64(10, u64::from(offset));
                template.dup_byte16(25, 10);
                template.mov_imm64(11, 1);
                template.sub_imm(7, 6, 63);
                template.branch(persistent_advance.ok_or(AuditError::InvalidSearchManifest)?);
            }
        }
    }

    if let Some(select) = wide_learn_select {
        let candidate = wide_learn_candidate.ok_or(AuditError::InvalidSearchManifest)?;
        let candidate_miss = wide_learn_miss.ok_or(AuditError::InvalidSearchManifest)?;
        let discover = wide_learn_discover.ok_or(AuditError::InvalidSearchManifest)?;
        let column_ready = wide_learn_ready.ok_or(AuditError::InvalidSearchManifest)?;
        let learned_empty = wide_learn_empty.ok_or(AuditError::InvalidSearchManifest)?;
        let saved = saved_mask_recover.ok_or(AuditError::InvalidSearchManifest)?;

        // Preserve the five-column Q masks. Each sparse conversion writes only
        // Q16 and X0, and selection stops at the first nonempty block.
        template.bind(select)?;
        template.mov_reg(7, 5);
        template.mov_imm64(13, 0);
        emit_sparse_lane_mask_to(template, 0, 16, 0);
        template.compare_branch_zero(0, true, candidate);
        template.mov_imm64(13, 16);
        emit_sparse_lane_mask_to(template, 2, 16, 0);
        template.compare_branch_zero(0, true, candidate);
        template.mov_imm64(13, 32);
        emit_sparse_lane_mask_to(template, 4, 16, 0);
        template.compare_branch_zero(0, true, candidate);
        template.mov_imm64(13, 48);
        emit_sparse_lane_mask_to(template, 6, 16, 0);
        template.compare_branch_zero(0, false, learned_empty);

        // Verify only the earliest five-column survivor. Equality is the
        // earliest exact match; a miss leaves every retained Q mask live.
        template.bind(candidate)?;
        template.add_reg(5, 7, 13);
        template.rbit(10, 0);
        template.clz(10, 10);
        template.lsr_imm(10, 10, 2);
        template.add_reg(5, 5, 10);
        template.add_reg(15, 9, 5);
        emit_literal_equality_specialized(template, 15, 8, literal.len(), candidate_miss)?;
        template.mov_reg(13, 5);
        template.add_reg(14, 5, 12);
        template.branch(found);

        // Recompute the sampled pointer after specialized equality, then find
        // the first source-order mismatch. Passing five masks proves this
        // offset is outside the five authenticated columns.
        template.bind(candidate_miss)?;
        template.add_reg(15, 9, 5);
        template.mov_imm64(11, 0);
        template.bind(discover)?;
        template.cmp_reg64(11, 12);
        template.branch_cond(Condition::CarrySet, none);
        template.load_byte_reg(10, 15, 11);
        template.load_byte_reg(13, 8, 11);
        template.cmp_reg32(10, 13);
        template.branch_cond(Condition::NotEqual, column_ready);
        template.add_imm(11, 11, 1);
        template.branch(discover);

        // Apply the learned literal byte at the dynamic mismatch offset to all
        // four original group masks. The sampled false lane necessarily drops.
        template.bind(column_ready)?;
        template.dup_byte16(24, 13);
        if persistent_backend {
            template.dup_byte16(25, 11);
            template.mov_imm64(11, 1);
        }
        template.add_reg(15, 9, 7);
        if persistent_backend {
            template.move_vector_byte_to32(10, 25);
            template.add_reg(15, 15, 10);
        } else {
            template.add_reg(15, 15, 11);
        }
        template.load_vector_pair128(18, 19, 15, 0);
        template.load_vector_pair128(20, 21, 15, 32);
        template.compare_equal_bytes16(18, 18, 24);
        template.and_bytes16(0, 0, 18);
        template.compare_equal_bytes16(19, 19, 24);
        template.and_bytes16(2, 2, 19);
        template.compare_equal_bytes16(20, 20, 24);
        template.and_bytes16(4, 4, 20);
        template.compare_equal_bytes16(21, 21, 24);
        template.and_bytes16(6, 6, 21);
        emit_four_block_presence_v8(template);
        template.compare_branch_zero(10, false, learned_empty);
        template.mov_reg(5, 7);
        if !persistent_backend {
            template.mov_imm64(11, 0);
        }
        template.branch(saved);

        // Restore the wide cursor and bound before advancing an empty refined
        // group. V21 returns to the pre-learning graph; V22 keeps Q24/Q25 and
        // enters its persistent learned-wide graph.
        template.bind(learned_empty)?;
        template.mov_reg(5, 7);
        template.add_reg(15, 9, 5);
        if primary_offset != 0 {
            template.add_imm(15, 15, primary_offset);
        }
        if persistent_backend {
            template.sub_imm(7, 6, 63);
            template.branch(persistent_advance.ok_or(AuditError::InvalidSearchManifest)?);
        } else {
            template.mov_imm64(11, 0);
            template.sub_imm(7, 6, 63);
            template.branch(wide_advance);
        }
    }

    if let (Some(persistent), Some(persistent_advance)) = (persistent_wide, persistent_advance) {
        let saved = saved_mask_recover.ok_or(AuditError::InvalidSearchManifest)?;

        template.bind(persistent_advance)?;
        template.add_imm(5, 5, 64);
        template.add_imm(15, 15, 64);
        template.cmp_reg64(5, 7);
        template.branch_cond(Condition::LowerOrSame, persistent);
        template.branch(narrow_setup);

        template.bind(persistent)?;
        template.add_reg(13, 9, 5);
        template.move_vector_byte_to32(10, 25);
        template.add_reg(10, 13, 10);
        template.load_vector_pair128(0, 2, 10, 0);
        template.load_vector_pair128(4, 6, 10, 32);
        template.compare_equal_bytes16(0, 0, 24);
        template.compare_equal_bytes16(2, 2, 24);
        template.compare_equal_bytes16(4, 4, 24);
        template.compare_equal_bytes16(6, 6, 24);
        emit_four_block_presence_v8(template);
        template.compare_branch_zero(10, false, persistent_advance);

        template.load_vector_pair128(18, 19, 15, 0);
        template.load_vector_pair128(20, 21, 15, 32);
        template.compare_equal_bytes16(18, 18, 1);
        template.and_bytes16(0, 0, 18);
        template.compare_equal_bytes16(19, 19, 1);
        template.and_bytes16(2, 2, 19);
        template.compare_equal_bytes16(20, 20, 1);
        template.and_bytes16(4, 4, 20);
        template.compare_equal_bytes16(21, 21, 1);
        template.and_bytes16(6, 6, 21);
        emit_four_block_presence_v8(template);
        template.compare_branch_zero(10, false, persistent_advance);

        if let Some(offset) = secondary_offset {
            let delta = offset.abs_diff(primary_offset);
            if offset > primary_offset {
                template.add_imm(10, 15, delta);
            } else {
                template.sub_imm(10, 15, delta);
            }
            template.load_vector_pair128(18, 19, 10, 0);
            template.load_vector_pair128(20, 21, 10, 32);
            template.compare_equal_bytes16(18, 18, 3);
            template.and_bytes16(0, 0, 18);
            template.compare_equal_bytes16(19, 19, 3);
            template.and_bytes16(2, 2, 19);
            template.compare_equal_bytes16(20, 20, 3);
            template.and_bytes16(4, 4, 20);
            template.compare_equal_bytes16(21, 21, 3);
            template.and_bytes16(6, 6, 21);
            emit_four_block_presence_v8(template);
            template.compare_branch_zero(10, false, persistent_advance);
        }

        let remaining_columns = [
            (verification_offset, 5_u8),
            (quaternary_offset, 7_u8),
            (quinary_offset, 23_u8),
        ];
        let remaining_count = remaining_columns
            .iter()
            .filter(|(offset, _)| offset.is_some())
            .count();
        let mut emitted_remaining = 0_usize;
        for &(offset, constant) in &remaining_columns {
            let Some(offset) = offset else {
                continue;
            };
            let delta = offset.abs_diff(primary_offset);
            if offset > primary_offset {
                template.add_imm(10, 15, delta);
            } else {
                template.sub_imm(10, 15, delta);
            }
            template.load_vector_pair128(18, 19, 10, 0);
            template.load_vector_pair128(20, 21, 10, 32);
            template.compare_equal_bytes16(18, 18, constant);
            template.and_bytes16(0, 0, 18);
            template.compare_equal_bytes16(19, 19, constant);
            template.and_bytes16(2, 2, 19);
            template.compare_equal_bytes16(20, 20, constant);
            template.and_bytes16(4, 4, 20);
            template.compare_equal_bytes16(21, 21, constant);
            template.and_bytes16(6, 6, 21);
            emitted_remaining = emitted_remaining
                .checked_add(1)
                .ok_or(AuditError::ArithmeticOverflow)?;
            if emitted_remaining == 1 && remaining_count > 1 {
                emit_four_block_presence_v8(template);
                template.compare_branch_zero(10, false, persistent_advance);
            }
        }
        if emitted_remaining > 0 {
            emit_four_block_presence_v8(template);
            template.compare_branch_zero(10, false, persistent_advance);
        }
        template.branch(saved);
    }

    if let Some(saved) = saved_mask_recover {
        let next_mask = saved_mask_next.ok_or(AuditError::InvalidSearchManifest)?;
        let candidate = saved_mask_lane.ok_or(AuditError::InvalidSearchManifest)?;
        let candidate_miss = saved_mask_miss.ok_or(AuditError::InvalidSearchManifest)?;
        let done = saved_mask_done.ok_or(AuditError::InvalidSearchManifest)?;

        template.bind(saved)?;
        emit_sparse_lane_mask_to(template, 0, 16, 0);
        emit_sparse_lane_mask_to(template, 2, 16, 1);
        emit_sparse_lane_mask_to(template, 4, 16, 2);
        emit_sparse_lane_mask_to(template, 6, 16, 3);
        template.mov_reg(7, 5);
        template.mov_imm64(11, 4);
        template.compare_branch_zero(0, true, candidate);
        template.branch(next_mask);

        template.bind(next_mask)?;
        template.sub_imm(11, 11, 1);
        template.compare_branch_zero(11, false, done);
        template.add_imm(7, 7, 16);
        template.mov_reg(0, 1);
        template.mov_reg(1, 2);
        template.mov_reg(2, 3);
        template.compare_branch_zero(0, true, candidate);
        template.branch(next_mask);

        template.bind(candidate)?;
        template.rbit(10, 0);
        template.clz(10, 10);
        template.lsr_imm(10, 10, 2);
        template.add_reg(5, 7, 10);
        template.add_reg(15, 9, 5);
        emit_literal_equality_specialized(template, 15, 8, literal.len(), candidate_miss)?;
        template.mov_reg(13, 5);
        template.add_reg(14, 5, 12);
        template.branch(found);

        template.bind(candidate_miss)?;
        template.sub_imm(10, 0, 1);
        template.and_reg(0, 0, 10);
        template.compare_branch_zero(0, true, candidate);
        template.branch(next_mask);

        template.bind(done)?;
        template.mov_imm64(11, u64::from(persistent_backend));
        template.add_imm(5, 7, 16);
        template.add_reg(15, 9, 5);
        if primary_offset != 0 {
            template.add_imm(15, 15, primary_offset);
        }
        template.sub_imm(7, 6, 63);
        template.cmp_reg64(5, 7);
        template.branch_cond(Condition::LowerOrSame, persistent_wide.unwrap_or(wide));
        template.branch(narrow_setup);
    }

    if manifest.backend_version == BackendVersion::SEARCH_V18 {
        for _ in 0..4 {
            template.mov_reg(10, 10);
        }
    }

    template.bind(narrow_setup)?;
    if manifest.backend_version == BackendVersion::SEARCH_V18 {
        template.mov_imm64(11, 0);
    }
    template.sub_imm(7, 6, 15);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, narrow);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);

    template.bind(narrow)?;
    template.load_vector128(0, 15, 0);
    template.compare_equal_bytes16(0, 0, 1);
    if let Some(second_filter) = second_filter {
        template.unsigned_max_pairwise_bytes16(2, 0, 0);
        template.move_vector_double_to64(10, 2);
        template.compare_branch_zero(10, true, second_filter);
    } else {
        emit_sparse_lane_mask_v7(template);
        template.compare_branch_zero(0, true, recover);
    }

    template.bind(advance)?;
    template.add_imm(5, 5, 16);
    template.add_imm(15, 15, 16);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, narrow);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);

    if let Some(second_filter) = second_filter {
        let offset = secondary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = offset.abs_diff(primary_offset);
        template.bind(second_filter)?;
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(2, 10, 0);
        template.compare_equal_bytes16(2, 2, 3);
        template.and_bytes16(0, 0, 2);
        emit_sparse_lane_mask_v7(template);
        template.compare_branch_zero(0, false, advance);
        if let Some(third_filter) = third_filter {
            emit_branch_if_mask_has_multiple(template, 0, 10, third_filter);
        }
        template.branch(fifth_filter.unwrap_or(recover));
    }

    if let Some(third_filter) = third_filter {
        let offset = verification_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = offset.abs_diff(primary_offset);
        template.bind(third_filter)?;
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(4, 10, 0);
        template.compare_equal_bytes16(4, 4, 5);
        template.and_bytes16(0, 0, 4);
        emit_sparse_lane_mask_v7(template);
        template.compare_branch_zero(0, false, advance);
        if let Some(fourth_filter) = fourth_filter {
            emit_branch_if_mask_has_multiple(template, 0, 10, fourth_filter);
        }
        template.branch(fifth_filter.unwrap_or(recover));
    }

    if let Some(fourth_filter) = fourth_filter {
        let offset = quaternary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = offset.abs_diff(primary_offset);
        template.bind(fourth_filter)?;
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(6, 10, 0);
        template.compare_equal_bytes16(6, 6, 7);
        template.and_bytes16(0, 0, 6);
        emit_sparse_lane_mask_v7(template);
        template.compare_branch_zero(0, true, fifth_filter.unwrap_or(recover));
        template.branch(advance);
    }

    if let Some(fifth_filter) = fifth_filter {
        let offset = quinary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = offset.abs_diff(primary_offset);
        template.bind(fifth_filter)?;
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(22, 10, 0);
        template.compare_equal_bytes16(22, 22, 23);
        template.and_bytes16(0, 0, 22);
        emit_sparse_lane_mask_v7(template);
        template.compare_branch_zero(0, true, recover);
        template.branch(advance);
    }

    template.bind(recover)?;
    template.mov_reg(7, 5);
    template.bind(lane_loop)?;
    template.rbit(10, 0);
    template.clz(10, 10);
    template.lsr_imm(10, 10, 2);
    template.add_reg(5, 7, 10);
    if !filters_cover_zero {
        template.load_byte_reg(10, 9, 5);
        template.cmp_reg32(10, 11);
        template.branch_cond(Condition::NotEqual, candidate_miss);
    }
    template.add_reg(15, 9, 5);
    if sve_confirmation {
        template.sve_load_bytes(16, 0, 15);
        template.sve_compare_equal_bytes(1, 0, 16, 31);
        template.sve_bit_clear_predicate_bytes_set_flags(2, 0, 0, 1);
        template.branch_cond(Condition::NotEqual, candidate_miss);
        if literal.len() > 16 {
            let remaining = literal
                .len()
                .checked_sub(16)
                .ok_or(AuditError::ArithmeticOverflow)?;
            template.add_imm(15, 15, 16);
            template.add_imm(16, 8, 16);
            emit_literal_equality_with_vectors(
                template,
                15,
                16,
                remaining,
                candidate_miss,
                16,
                17,
                13,
            )?;
        }
    } else if matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V12
            | BackendVersion::SEARCH_V13
            | BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
            | BackendVersion::SEARCH_V17
            | BackendVersion::SEARCH_V18
            | BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    ) {
        emit_literal_equality_specialized(template, 15, 8, literal.len(), candidate_miss)?;
    } else if literal.len() == 16 {
        emit_literal_equality_16_with_vectors(template, 15, 8, candidate_miss, 16, 17);
    } else {
        emit_literal_equality_with_vectors(
            template,
            15,
            8,
            literal.len(),
            candidate_miss,
            16,
            17,
            13,
        )?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);

    template.bind(candidate_miss)?;
    template.sub_imm(10, 0, 1);
    template.and_reg(0, 0, 10);
    if manifest.backend_version == BackendVersion::SEARCH_V13 {
        let exhausted = recovery_exhausted.ok_or(AuditError::InvalidSearchManifest)?;
        template.compare_branch_zero(0, false, exhausted);
        let adaptive = independent_adaptive_offsets_v13(
            literal,
            primary_offset,
            secondary_offset,
            verification_offset,
            quaternary_offset,
            quinary_offset,
        );
        let adaptive_entry = adaptive_recovery.ok_or(AuditError::InvalidSearchManifest)?;
        emit_branch_if_mask_has_multiple(template, 0, 10, adaptive_entry);
        template.branch(lane_loop);
        template.bind(adaptive_entry)?;
        template.add_reg(13, 9, 7);
        for (index, &offset) in adaptive.iter().enumerate() {
            template.load_byte(10, 8, offset);
            template.dup_byte16(17, 10);
            let column = if offset == 0 {
                13
            } else {
                template.add_imm(15, 13, offset);
                15
            };
            template.load_vector128(16, column, 0);
            template.compare_equal_bytes16(16, 16, 17);
            emit_sparse_lane_mask_to(template, 16, 18, 10);
            template.and_reg(0, 0, 10);
            template.compare_branch_zero(0, false, exhausted);
            if index + 1 < adaptive.len() {
                template.sub_imm(10, 0, 1);
                template.and_reg(10, 0, 10);
                template.compare_branch_zero(10, false, lane_loop);
            }
        }
        template.branch(lane_loop);
        template.bind(exhausted)?;
    } else if matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_V14
            | BackendVersion::SEARCH_V15
            | BackendVersion::SEARCH_V16
            | BackendVersion::SEARCH_V17
            | BackendVersion::SEARCH_V18
            | BackendVersion::SEARCH_V19
            | BackendVersion::SEARCH_V20
            | BackendVersion::SEARCH_V21
            | BackendVersion::SEARCH_V22
            | BackendVersion::SEARCH_V23
            | BackendVersion::SEARCH_V24
            | BackendVersion::SEARCH_V25
    ) {
        let discover = learned_discover.ok_or(AuditError::InvalidSearchManifest)?;
        let column_ready = learned_column_ready.ok_or(AuditError::InvalidSearchManifest)?;
        let learned_next = learned_advance.ok_or(AuditError::InvalidSearchManifest)?;
        let learned_block = learned_scan.ok_or(AuditError::InvalidSearchManifest)?;
        let finish_tail = learned_tail.ok_or(AuditError::InvalidSearchManifest)?;
        let continue_learned = matches!(
            manifest.backend_version,
            BackendVersion::SEARCH_V17
                | BackendVersion::SEARCH_V18
                | BackendVersion::SEARCH_V19
                | BackendVersion::SEARCH_V20
                | BackendVersion::SEARCH_V21
                | BackendVersion::SEARCH_V22
                | BackendVersion::SEARCH_V23
                | BackendVersion::SEARCH_V24
                | BackendVersion::SEARCH_V25
        );

        // State zero enters discovery. V17 and V18 clear a failed retained bit and
        // continues with the learned column; V14-V16 keep their frozen
        // one-way transition to V13.
        template.compare_branch_zero(11, false, discover);
        if continue_learned {
            template.compare_branch_zero(0, true, lane_loop);
            template.branch(learned_next);
        } else {
            let disabled = learned_disabled.ok_or(AuditError::InvalidSearchManifest)?;
            template.mov_imm64(11, 2);
            template.branch(disabled);
        }

        // The complete equality immediately above proved that this exact
        // candidate differs somewhere. Discover one source-derived mismatch
        // once, in stable source order, and retain both its byte (V24) and
        // offset (V25).
        template.bind(discover)?;
        template.cmp_reg64(11, 12);
        template.branch_cond(Condition::CarrySet, none);
        template.load_byte_reg(10, 15, 11);
        template.load_byte_reg(13, 8, 11);
        template.cmp_reg32(10, 13);
        template.branch_cond(Condition::NotEqual, column_ready);
        template.add_imm(11, 11, 1);
        template.branch(discover);

        template.bind(column_ready)?;
        template.dup_byte16(24, 13);
        template.dup_byte16(25, 11);
        template.mov_imm64(11, 1);
        template.compare_branch_zero(0, false, learned_next);

        // Intersect current five-column survivors with the learned mismatch.
        // V17 exact-verifies survivors and then resumes learned scanning.
        template.add_reg(15, 9, 7);
        template.move_vector_byte_to32(10, 25);
        template.add_reg(15, 15, 10);
        template.load_vector128(16, 15, 0);
        template.compare_equal_bytes16(16, 16, 24);
        emit_sparse_lane_mask_to(template, 16, 18, 10);
        template.and_reg(0, 0, 10);
        template.compare_branch_zero(0, false, learned_next);
        if continue_learned {
            template.branch(lane_loop);
        } else {
            let disabled = learned_disabled.ok_or(AuditError::InvalidSearchManifest)?;
            template.mov_imm64(11, 2);
            template.branch(disabled);
        }

        // Probe the learned column first on every subsequent block.
        template.bind(learned_next)?;
        template.add_imm(5, 7, 16);
        template.cmp_reg64(5, 6);
        template.branch_cond(Condition::Higher, none);
        template.sub_reg(10, 6, 5);
        template.cmp_imm64(10, 15);
        template.branch_cond(Condition::CarryClear, finish_tail);
        template.branch(learned_block);

        template.bind(learned_block)?;
        template.mov_reg(7, 5);
        template.add_reg(13, 9, 5);
        template.move_vector_byte_to32(10, 25);
        template.add_reg(15, 13, 10);
        template.load_vector128(16, 15, 0);
        template.compare_equal_bytes16(16, 16, 24);
        if matches!(
            manifest.backend_version,
            BackendVersion::SEARCH_V16
                | BackendVersion::SEARCH_V17
                | BackendVersion::SEARCH_V18
                | BackendVersion::SEARCH_V19
                | BackendVersion::SEARCH_V20
                | BackendVersion::SEARCH_V21
                | BackendVersion::SEARCH_V22
                | BackendVersion::SEARCH_V23
                | BackendVersion::SEARCH_V24
                | BackendVersion::SEARCH_V25
        ) {
            template.unsigned_max_pairwise_bytes16(18, 16, 16);
            template.move_vector_double_to64(0, 18);
            template.compare_branch_zero(0, false, learned_next);

            let primary_column = if primary_offset == 0 {
                13
            } else {
                template.add_imm(15, 13, primary_offset);
                15
            };
            template.load_vector128(18, primary_column, 0);
            template.compare_equal_bytes16(18, 18, 1);
            template.and_bytes16(16, 16, 18);
            template.unsigned_max_pairwise_bytes16(18, 16, 16);
            template.move_vector_double_to64(0, 18);
            template.compare_branch_zero(0, false, learned_next);

            for (offset, constant) in [
                (secondary_offset, 3_u8),
                (verification_offset, 5_u8),
                (quaternary_offset, 7_u8),
                (quinary_offset, 23_u8),
            ] {
                let Some(offset) = offset else {
                    continue;
                };
                let column = if offset == 0 {
                    13
                } else {
                    template.add_imm(15, 13, offset);
                    15
                };
                template.load_vector128(18, column, 0);
                template.compare_equal_bytes16(18, 18, constant);
                template.and_bytes16(16, 16, 18);
            }
            emit_sparse_lane_mask_to(template, 16, 18, 0);
            template.compare_branch_zero(0, false, learned_next);
        } else {
            emit_sparse_lane_mask_to(template, 16, 18, 0);
            template.compare_branch_zero(0, false, learned_next);

            // A learned-byte hit is intersected with all five authenticated
            // columns. A surviving candidate permanently disables learned
            // mode.
            let primary_column = if primary_offset == 0 {
                13
            } else {
                template.add_imm(15, 13, primary_offset);
                15
            };
            template.load_vector128(16, primary_column, 0);
            template.compare_equal_bytes16(16, 16, 1);
            for (offset, constant) in [
                (secondary_offset, 3_u8),
                (verification_offset, 5_u8),
                (quaternary_offset, 7_u8),
                (quinary_offset, 23_u8),
            ] {
                let Some(offset) = offset else {
                    continue;
                };
                let column = if offset == 0 {
                    13
                } else {
                    template.add_imm(15, 13, offset);
                    15
                };
                template.load_vector128(18, column, 0);
                template.compare_equal_bytes16(18, 18, constant);
                template.and_bytes16(16, 16, 18);
            }
            emit_sparse_lane_mask_to(template, 16, 18, 10);
            template.and_reg(0, 0, 10);
            template.compare_branch_zero(0, false, learned_next);
        }
        if continue_learned {
            template.branch(lane_loop);
        } else {
            let disabled = learned_disabled.ok_or(AuditError::InvalidSearchManifest)?;
            template.mov_imm64(11, 2);
            template.branch(disabled);
        }

        template.bind(finish_tail)?;
        template.branch(tail_setup);

        if !continue_learned {
            let disabled = learned_disabled.ok_or(AuditError::InvalidSearchManifest)?;
            let exhausted = recovery_exhausted.ok_or(AuditError::InvalidSearchManifest)?;
            let adaptive_entry = adaptive_recovery.ok_or(AuditError::InvalidSearchManifest)?;

            // Mirror the frozen V13 retained-mask handler exactly for V14-V16.
            template.bind(disabled)?;
            template.compare_branch_zero(0, false, exhausted);
            let adaptive = independent_adaptive_offsets_v13(
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
                quinary_offset,
            );
            emit_branch_if_mask_has_multiple(template, 0, 10, adaptive_entry);
            template.branch(lane_loop);
            template.bind(adaptive_entry)?;
            template.add_reg(13, 9, 7);
            for (index, &offset) in adaptive.iter().enumerate() {
                template.load_byte(10, 8, offset);
                template.dup_byte16(17, 10);
                let column = if offset == 0 {
                    13
                } else {
                    template.add_imm(15, 13, offset);
                    15
                };
                template.load_vector128(16, column, 0);
                template.compare_equal_bytes16(16, 16, 17);
                emit_sparse_lane_mask_to(template, 16, 18, 10);
                template.and_reg(0, 0, 10);
                template.compare_branch_zero(0, false, exhausted);
                if index + 1 < adaptive.len() {
                    template.sub_imm(10, 0, 1);
                    template.and_reg(10, 0, 10);
                    template.compare_branch_zero(10, false, lane_loop);
                }
            }
            template.branch(lane_loop);
            template.bind(exhausted)?;
        }
    } else {
        template.compare_branch_zero(0, true, lane_loop);
    }
    template.add_imm(5, 7, 16);
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.sub_imm(7, 6, 15);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, narrow);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);

    if manifest.backend_version == BackendVersion::SEARCH_SVE16_V6 && literal.len() == 16 {
        template.mov_reg(10, 10);
    }
    template.bind(tail_setup)?;
    emit_scalar_candidates_v2(template, literal, none, found)?;

    if manifest.backend_version == BackendVersion::SEARCH_V18 {
        let secondary_only = secondary_only.ok_or(AuditError::InvalidSearchManifest)?;
        let secondary_only_advance =
            secondary_only_advance.ok_or(AuditError::InvalidSearchManifest)?;
        let offset = secondary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        template.bind(secondary_only_advance)?;
        template.add_imm(5, 5, 64);
        template.add_imm(15, 15, 64);
        template.cmp_reg64(5, 7);
        template.branch_cond(Condition::LowerOrSame, secondary_only);
        template.branch(narrow_setup);

        template.bind(secondary_only)?;
        let delta = offset.abs_diff(primary_offset);
        if offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector_pair128(0, 2, 10, 0);
        template.load_vector_pair128(4, 6, 10, 32);
        template.compare_equal_bytes16(0, 0, 3);
        template.compare_equal_bytes16(2, 2, 3);
        template.compare_equal_bytes16(4, 4, 3);
        template.compare_equal_bytes16(6, 6, 3);
        emit_four_block_presence_v8(template);
        template.compare_branch_zero(10, false, secondary_only_advance);
        template.load_vector_pair128(18, 19, 15, 0);
        template.load_vector_pair128(20, 21, 15, 32);
        template.compare_equal_bytes16(18, 18, 1);
        template.and_bytes16(0, 0, 18);
        template.compare_equal_bytes16(19, 19, 1);
        template.and_bytes16(2, 2, 19);
        template.compare_equal_bytes16(20, 20, 1);
        template.and_bytes16(4, 4, 20);
        template.compare_equal_bytes16(21, 21, 1);
        template.and_bytes16(6, 6, 21);
        emit_four_block_presence_v8(template);
        template.compare_branch_zero(10, false, wide_advance);
        template.branch(narrow_setup);
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent tag21 template reconstructs paired wide screening, adaptive state, and retained SVE2 predicates without sharing emitter control flow"
)]
fn emit_exact_candidates_sve2_fixed16_v2(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    if literal.len() != 16 {
        return Err(AuditError::InvalidSearchManifest);
    }
    let primary_offset = manifest.primary_offset;
    let offsets = [
        primary_offset,
        (manifest.secondary_offset != u16::MAX)
            .then_some(manifest.secondary_offset)
            .ok_or(AuditError::InvalidSearchManifest)?,
        (manifest.verification_offset != u16::MAX)
            .then_some(manifest.verification_offset)
            .ok_or(AuditError::InvalidSearchManifest)?,
        (manifest.quaternary_offset != u16::MAX)
            .then_some(manifest.quaternary_offset)
            .ok_or(AuditError::InvalidSearchManifest)?,
        (manifest.quinary_offset != u16::MAX)
            .then_some(manifest.quinary_offset)
            .ok_or(AuditError::InvalidSearchManifest)?,
    ];
    let filters_cover_zero = offsets.contains(&0);
    let constants = [1_u8, 3, 5, 7, 22];
    let wide = template.new_label(LabelKind::Loop);
    let wide_advance = template.new_label(LabelKind::Internal);
    let secondary_only = template.new_label(LabelKind::Loop);
    let secondary_only_advance = template.new_label(LabelKind::Internal);
    let wide_second_filter = template.new_label(LabelKind::SlowPath);
    let wide_remaining_filters = template.new_label(LabelKind::SlowPath);
    let wide_next_mask = template.new_label(LabelKind::Loop);
    let wide_candidate = template.new_label(LabelKind::Loop);
    let wide_candidate_miss = template.new_label(LabelKind::Internal);
    let narrow_setup = template.new_label(LabelKind::Internal);
    let narrow = template.new_label(LabelKind::Loop);
    let advance = template.new_label(LabelKind::Internal);
    let candidate = template.new_label(LabelKind::Loop);
    let candidate_miss = template.new_label(LabelKind::Internal);
    let tail_setup = template.new_label(LabelKind::SlowPath);

    template.sve_ptrue_bytes_vl16(0);
    for (&offset, &constant) in offsets.iter().zip(constants.iter()) {
        let byte = literal
            .get(usize::from(offset))
            .copied()
            .ok_or(AuditError::InvalidSearchManifest)?;
        template.mov_imm64(11, u64::from(byte));
        template.sve_duplicate_byte(constant, 11);
    }
    template.sve_load_bytes(31, 0, 8);
    if !filters_cover_zero {
        template.mov_imm64(11, u64::from(literal[0]));
    }

    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, tail_setup);
    template.cmp_imm64(10, 63);
    template.branch_cond(Condition::CarryClear, narrow_setup);
    template.sub_imm(7, 6, 63);

    template.bind(wide)?;
    template.load_vector_pair128(0, 2, 15, 0);
    template.load_vector_pair128(4, 6, 15, 32);
    template.compare_equal_bytes16(0, 0, 1);
    template.compare_equal_bytes16(2, 2, 1);
    template.compare_equal_bytes16(4, 4, 1);
    template.compare_equal_bytes16(6, 6, 1);
    emit_four_block_presence_v8(template);
    template.compare_branch_zero(10, true, wide_second_filter);

    template.bind(wide_advance)?;
    template.add_imm(5, 5, 64);
    template.add_imm(15, 15, 64);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, wide);
    template.branch(narrow_setup);

    let secondary_delta = offsets[1].abs_diff(primary_offset);
    template.bind(wide_second_filter)?;
    if offsets[1] > primary_offset {
        template.add_imm(10, 15, secondary_delta);
    } else {
        template.sub_imm(10, 15, secondary_delta);
    }
    template.load_vector_pair128(18, 19, 10, 0);
    template.load_vector_pair128(20, 21, 10, 32);
    template.compare_equal_bytes16(18, 18, 3);
    template.and_bytes16(0, 0, 18);
    template.compare_equal_bytes16(19, 19, 3);
    template.and_bytes16(2, 2, 19);
    template.compare_equal_bytes16(20, 20, 3);
    template.and_bytes16(4, 4, 20);
    template.compare_equal_bytes16(21, 21, 3);
    template.and_bytes16(6, 6, 21);
    emit_four_block_presence_v8(template);
    template.compare_branch_zero(10, false, secondary_only_advance);
    template.branch(wide_remaining_filters);

    template.bind(secondary_only_advance)?;
    template.add_imm(5, 5, 64);
    template.add_imm(15, 15, 64);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, secondary_only);
    template.branch(narrow_setup);

    template.bind(secondary_only)?;
    if offsets[1] > primary_offset {
        template.add_imm(10, 15, secondary_delta);
    } else {
        template.sub_imm(10, 15, secondary_delta);
    }
    template.load_vector_pair128(0, 2, 10, 0);
    template.load_vector_pair128(4, 6, 10, 32);
    template.compare_equal_bytes16(0, 0, 3);
    template.compare_equal_bytes16(2, 2, 3);
    template.compare_equal_bytes16(4, 4, 3);
    template.compare_equal_bytes16(6, 6, 3);
    emit_four_block_presence_v8(template);
    template.compare_branch_zero(10, false, secondary_only_advance);
    template.load_vector_pair128(18, 19, 15, 0);
    template.load_vector_pair128(20, 21, 15, 32);
    template.compare_equal_bytes16(18, 18, 1);
    template.and_bytes16(0, 0, 18);
    template.compare_equal_bytes16(19, 19, 1);
    template.and_bytes16(2, 2, 19);
    template.compare_equal_bytes16(20, 20, 1);
    template.and_bytes16(4, 4, 20);
    template.compare_equal_bytes16(21, 21, 1);
    template.and_bytes16(6, 6, 21);
    emit_four_block_presence_v8(template);
    template.compare_branch_zero(10, false, wide_advance);

    template.bind(wide_remaining_filters)?;
    for index in 2..offsets.len() {
        let delta = offsets[index].abs_diff(primary_offset);
        if offsets[index] > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector_pair128(18, 19, 10, 0);
        template.load_vector_pair128(20, 21, 10, 32);
        template.compare_equal_bytes16(18, 18, constants[index]);
        template.and_bytes16(0, 0, 18);
        template.compare_equal_bytes16(19, 19, constants[index]);
        template.and_bytes16(2, 2, 19);
        template.compare_equal_bytes16(20, 20, constants[index]);
        template.and_bytes16(4, 4, 20);
        template.compare_equal_bytes16(21, 21, constants[index]);
        template.and_bytes16(6, 6, 21);
        emit_four_block_presence_v8(template);
        template.compare_branch_zero(10, false, wide_advance);
    }

    template.shift_right_narrow_halfwords_to_bytes8(16, 0);
    template.move_vector_double_to64(0, 16);
    template.mov_imm64(14, 0x1111_1111_1111_1111);
    template.and_reg(0, 0, 14);
    for (destination, source) in [(1_u8, 2_u8), (2, 4), (3, 6)] {
        template.shift_right_narrow_halfwords_to_bytes8(16, source);
        template.move_vector_double_to64(destination, 16);
        template.and_reg(destination, destination, 14);
    }
    template.mov_reg(17, 5);
    template.add_imm(16, 5, 64);
    template.bind(wide_next_mask)?;
    template.compare_branch_zero(0, true, wide_candidate);
    template.add_imm(17, 17, 16);
    template.cmp_reg64(17, 16);
    template.branch_cond(Condition::CarrySet, wide_advance);
    template.mov_reg(0, 1);
    template.mov_reg(1, 2);
    template.mov_reg(2, 3);
    template.branch(wide_next_mask);

    template.bind(wide_candidate)?;
    template.rbit(10, 0);
    template.clz(10, 10);
    template.lsr_imm(10, 10, 2);
    template.add_reg(13, 17, 10);
    if !filters_cover_zero {
        template.load_byte_reg(10, 9, 13);
        template.cmp_reg32(10, 11);
        template.branch_cond(Condition::NotEqual, wide_candidate_miss);
    }
    template.add_reg(10, 9, 13);
    template.sve_load_bytes(30, 0, 10);
    template.sve_compare_equal_bytes(2, 0, 30, 31);
    template.sve_bit_clear_predicate_bytes_set_flags(2, 0, 0, 2);
    template.branch_cond(Condition::NotEqual, wide_candidate_miss);
    template.add_reg(14, 13, 12);
    template.branch(found);

    template.bind(wide_candidate_miss)?;
    template.sub_imm(10, 0, 1);
    template.and_reg(0, 0, 10);
    template.compare_branch_zero(0, true, wide_candidate);
    template.branch(wide_next_mask);

    template.bind(narrow_setup)?;
    template.sub_imm(7, 6, 15);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, narrow);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);

    template.bind(narrow)?;
    template.sve_load_bytes(0, 0, 15);
    template.sve2_match_bytes(1, 0, 0, constants[0]);
    template.sve_test_predicate_bytes(0, 1);
    template.branch_cond(Condition::Equal, advance);
    for index in 1..offsets.len() {
        let delta = offsets[index].abs_diff(primary_offset);
        if offsets[index] > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.sve_load_bytes(0, 0, 10);
        template.sve2_match_bytes(2, 0, 0, constants[index]);
        template.sve_and_predicate_bytes_set_flags(1, 0, 1, 2);
        template.branch_cond(Condition::Equal, advance);
        if index < offsets.len().saturating_sub(1) {
            template.sve_count_predicate_bytes(10, 0, 1);
            template.cmp_imm64(10, 1);
            template.branch_cond(Condition::LowerOrSame, candidate);
        }
    }
    template.branch(candidate);

    template.bind(candidate)?;
    template.sve_break_before_bytes(3, 0, 1);
    template.sve_count_predicate_bytes(10, 0, 3);
    template.add_reg(13, 5, 10);
    if !filters_cover_zero {
        template.load_byte_reg(10, 9, 13);
        template.cmp_reg32(10, 11);
        template.branch_cond(Condition::NotEqual, candidate_miss);
    }
    template.add_reg(10, 9, 13);
    template.sve_load_bytes(30, 0, 10);
    template.sve_compare_equal_bytes(2, 0, 30, 31);
    template.sve_bit_clear_predicate_bytes_set_flags(2, 0, 0, 2);
    template.branch_cond(Condition::NotEqual, candidate_miss);
    template.add_reg(14, 13, 12);
    template.branch(found);

    template.bind(candidate_miss)?;
    template.sve_break_after_bytes(3, 0, 1);
    template.sve_bit_clear_predicate_bytes_set_flags(1, 0, 1, 3);
    template.branch_cond(Condition::NotEqual, candidate);

    template.bind(advance)?;
    template.add_imm(5, 5, 16);
    template.add_imm(15, 15, 16);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, narrow);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);

    template.bind(tail_setup)?;
    emit_scalar_candidates_v2(template, literal, none, found)
}

fn emit_four_block_presence_v8(template: &mut Template) {
    template.unsigned_max_pairwise_bytes16(16, 0, 2);
    template.unsigned_max_pairwise_bytes16(17, 4, 6);
    template.unsigned_max_pairwise_bytes16(16, 16, 17);
    template.unsigned_max_pairwise_bytes16(16, 16, 16);
    template.move_vector_double_to64(10, 16);
}

fn emit_branch_if_four_masks_have_multiple(template: &mut Template, target: Label) {
    template.mov_imm64(16, 0x0101_0101_0101_0101);
    template.and_reg(10, 10, 16);
    emit_branch_if_mask_has_multiple(template, 10, 16, target);
}

fn emit_branch_if_mask_has_multiple(template: &mut Template, mask: u8, scratch: u8, target: Label) {
    template.sub_imm(scratch, mask, 1);
    template.and_reg(scratch, mask, scratch);
    template.compare_branch_zero(scratch, true, target);
}

fn emit_sparse_lane_mask_v7(template: &mut Template) {
    template.shift_right_narrow_halfwords_to_bytes8(2, 0);
    template.move_vector_double_to64(0, 2);
    template.and_reg(0, 0, 14);
}

fn emit_sparse_lane_mask_to(
    template: &mut Template,
    source: u8,
    vector_scratch: u8,
    destination: u8,
) {
    template.shift_right_narrow_halfwords_to_bytes8(vector_scratch, source);
    template.move_vector_double_to64(destination, vector_scratch);
    template.and_reg(destination, destination, 14);
}

struct IndependentAdaptiveOffsetsV13 {
    values: [u16; crate::MAX_REPEATED_CONFIRM_BYTES],
    len: usize,
}

impl IndependentAdaptiveOffsetsV13 {
    fn iter(&self) -> core::slice::Iter<'_, u16> {
        self.values[..self.len].iter()
    }

    const fn len(&self) -> usize {
        self.len
    }
}

fn independent_adaptive_offsets_v13(
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    quaternary_offset: Option<u16>,
    quinary_offset: Option<u16>,
) -> IndependentAdaptiveOffsetsV13 {
    let selected = [
        Some(primary_offset),
        secondary_offset,
        verification_offset,
        quaternary_offset,
        quinary_offset,
    ];
    let mut values = [0_u16; crate::MAX_REPEATED_CONFIRM_BYTES];
    let mut len = 0_usize;
    for (offset, &byte) in literal.iter().enumerate() {
        let offset = u16::try_from(offset).expect("bounded independent offset fits u16");
        if selected.contains(&Some(offset)) {
            continue;
        }
        let key = (
            INDEPENDENT_V13_BYTE_FREQUENCY_RANK[usize::from(byte)],
            offset,
        );
        let mut insertion = len;
        while insertion > 0 {
            let previous = values[insertion - 1];
            let previous_key = (
                INDEPENDENT_V13_BYTE_FREQUENCY_RANK[usize::from(literal[usize::from(previous)])],
                previous,
            );
            if previous_key <= key {
                break;
            }
            values[insertion] = previous;
            insertion -= 1;
        }
        values[insertion] = offset;
        len += 1;
    }
    IndependentAdaptiveOffsetsV13 { values, len }
}

#[cfg(test)]
pub(crate) fn independent_sixth_static_offset_v24(
    literal: &[u8],
    manifest: SearchManifest,
) -> Option<u16> {
    independent_adaptive_offsets_v13(
        literal,
        manifest.primary_offset,
        (manifest.secondary_offset != u16::MAX).then_some(manifest.secondary_offset),
        (manifest.verification_offset != u16::MAX).then_some(manifest.verification_offset),
        (manifest.quaternary_offset != u16::MAX).then_some(manifest.quaternary_offset),
        (manifest.quinary_offset != u16::MAX).then_some(manifest.quinary_offset),
    )
    .iter()
    .next()
    .copied()
}

// Independently pinned copy of the memchr 2.8.3 packed-pair byte-frequency
// order. The template must not consume the emitter's table when reconstructing
// V13's exact adaptive instruction stream.
const INDEPENDENT_V13_BYTE_FREQUENCY_RANK: [u8; 256] = [
    55, 52, 51, 50, 49, 48, 47, 46, 45, 103, 242, 66, 67, 229, 44, 43, 42, 41, 40, 39, 38, 37, 36,
    35, 34, 33, 56, 32, 31, 30, 29, 28, 255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122,
    232, 202, 215, 224, 208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174,
    126, 120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167, 186, 112,
    175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223, 151, 249, 216, 238, 236,
    253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244, 231, 139, 245, 243, 251, 235, 201, 196,
    240, 214, 152, 182, 205, 181, 127, 27, 212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105,
    80, 98, 96, 97, 81, 207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111, 82,
    108, 118, 141, 113, 129, 119, 125, 165, 117, 92, 106, 83, 72, 99, 93, 65, 79, 166, 237, 163,
    199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255,
];

fn emit_sparse_lane_mask(template: &mut Template) {
    template.shift_right_narrow_halfwords_to_bytes8(2, 0);
    template.move_vector_double_to64(0, 2);
    template.mov_imm64(11, 0x1111_1111_1111_1111);
    template.and_reg(0, 0, 11);
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete mask-guided control-flow template remains independent and reviewable"
)]
fn emit_exact_candidates_mask(
    template: &mut Template,
    manifest: SearchManifest,
    literal: &[u8],
    verification_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), AuditError> {
    let vector = template.new_label(LabelKind::Loop);
    let advance = template.new_label(LabelKind::Internal);
    let block_setup = template.new_label(LabelKind::SlowPath);
    let block_pairs = template.new_label(LabelKind::Loop);
    let pair_confirm = template.new_label(LabelKind::SlowPath);
    let scalar = template.new_label(LabelKind::Loop);
    let scalar_advance = template.new_label(LabelKind::Internal);
    let pair_exhausted = template.new_label(LabelKind::Internal);
    let block_resume = template.new_label(LabelKind::Internal);
    let tail_setup = template.new_label(LabelKind::SlowPath);
    let second_filter =
        (manifest.secondary_offset != u16::MAX).then(|| template.new_label(LabelKind::SlowPath));
    let primary_offset = manifest.primary_offset;
    let secondary_offset =
        (manifest.secondary_offset != u16::MAX).then_some(manifest.secondary_offset);

    template.load_byte(11, 8, primary_offset);
    template.dup_byte16(1, 11);
    if let Some(secondary_offset) = secondary_offset {
        template.load_byte(11, 8, secondary_offset);
        template.dup_byte16(3, 11);
    }
    if let Some(verification_offset) = verification_offset {
        template.load_byte(11, 8, verification_offset);
        template.dup_byte16(5, 11);
    }
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, tail_setup);
    template.sub_imm(7, 6, 15);
    template.bind(vector)?;
    template.load_vector128(0, 15, 0);
    template.compare_equal_bytes16(0, 0, 1);
    if let Some(second_filter) = second_filter {
        template.unsigned_max_pairwise_bytes16(2, 0, 0);
        template.move_vector_double_to64(10, 2);
        template.compare_branch_zero(10, true, second_filter);
    } else {
        template.unsigned_max_pairwise_bytes16(0, 0, 0);
        template.move_vector_double_to64(10, 0);
        template.compare_branch_zero(10, true, block_setup);
    }
    template.bind(advance)?;
    template.add_imm(5, 5, 16);
    template.add_imm(15, 15, 16);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, vector);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);
    if let Some(second_filter) = second_filter {
        let secondary_offset = secondary_offset.ok_or(AuditError::InvalidSearchManifest)?;
        let delta = secondary_offset.abs_diff(primary_offset);
        template.bind(second_filter)?;
        if secondary_offset > primary_offset {
            template.add_imm(10, 15, delta);
        } else {
            template.sub_imm(10, 15, delta);
        }
        template.load_vector128(2, 10, 0);
        template.compare_equal_bytes16(2, 2, 3);
        template.and_bytes16(0, 0, 2);
        if let Some(verification_offset) = verification_offset {
            let verification_delta = verification_offset.abs_diff(primary_offset);
            if verification_offset > primary_offset {
                template.add_imm(10, 15, verification_delta);
            } else {
                template.sub_imm(10, 15, verification_delta);
            }
            template.load_vector128(4, 10, 0);
            template.compare_equal_bytes16(4, 4, 5);
            template.and_bytes16(0, 0, 4);
        }
        template.unsigned_max_pairwise_bytes16(0, 0, 0);
        template.move_vector_double_to64(10, 0);
        template.compare_branch_zero(10, true, block_setup);
        template.branch(advance);
    }

    template.bind(block_setup)?;
    template.mov_reg(0, 10);
    template.add_imm(7, 5, 15);
    template.bind(block_pairs)?;
    template.and_low_bits(10, 0, 8);
    template.lsr_imm(0, 0, 8);
    template.compare_branch_zero(10, true, pair_confirm);
    template.add_imm(5, 5, 2);
    template.compare_branch_zero(0, true, block_pairs);
    template.branch(block_resume);

    template.bind(pair_confirm)?;
    template.add_imm(2, 5, 1);
    template.bind(scalar)?;
    template.load_byte_reg(10, 9, 5);
    template.load_byte(11, 8, 0);
    template.cmp_reg32(10, 11);
    template.branch_cond(Condition::NotEqual, scalar_advance);
    template.add_reg(15, 9, 5);
    if literal.len() == 16 {
        emit_literal_equality_16(template, 15, 8, scalar_advance);
    } else {
        emit_literal_equality(template, 15, 8, literal.len(), scalar_advance)?;
    }
    template.mov_reg(13, 5);
    template.add_reg(14, 5, 12);
    template.branch(found);
    template.bind(scalar_advance)?;
    template.cmp_reg64(5, 2);
    template.branch_cond(Condition::CarrySet, pair_exhausted);
    template.add_imm(5, 5, 1);
    template.branch(scalar);
    template.bind(pair_exhausted)?;
    template.add_imm(5, 5, 1);
    template.compare_branch_zero(0, true, block_pairs);

    template.bind(block_resume)?;
    template.add_imm(5, 7, 1);
    template.load_byte(11, 8, primary_offset);
    template.dup_byte16(1, 11);
    if let Some(secondary_offset) = secondary_offset {
        template.load_byte(11, 8, secondary_offset);
        template.dup_byte16(3, 11);
    }
    template.add_reg(15, 9, 5);
    if primary_offset != 0 {
        template.add_imm(15, 15, primary_offset);
    }
    template.sub_imm(7, 6, 15);
    template.cmp_reg64(5, 7);
    template.branch_cond(Condition::LowerOrSame, vector);
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.branch(tail_setup);

    template.bind(tail_setup)?;
    emit_scalar_candidates_v2(template, literal, none, found)
}

fn emit_literal_equality_16(
    template: &mut Template,
    hay_pointer: u8,
    needle_pointer: u8,
    mismatch: Label,
) {
    emit_literal_equality_16_with_vectors(template, hay_pointer, needle_pointer, mismatch, 0, 1);
}

fn emit_literal_equality_16_with_vectors(
    template: &mut Template,
    hay_pointer: u8,
    needle_pointer: u8,
    mismatch: Label,
    left_vector: u8,
    right_vector: u8,
) {
    template.load_vector128(left_vector, hay_pointer, 0);
    template.load_vector128(right_vector, needle_pointer, 0);
    template.compare_equal_bytes16(left_vector, left_vector, right_vector);
    template.unsigned_min_bytes16(left_vector, left_vector);
    template.move_vector_byte_to32(10, left_vector);
    template.cmp_imm32(10, 255);
    template.branch_cond(Condition::NotEqual, mismatch);
}

fn emit_literal_equality_specialized(
    template: &mut Template,
    hay_pointer: u8,
    needle_pointer: u8,
    length: usize,
    mismatch: Label,
) -> Result<(), AuditError> {
    match length {
        0 => return Err(AuditError::InvalidSearchManifest),
        1 => {
            template.load_byte(10, hay_pointer, 0);
            template.load_byte(13, needle_pointer, 0);
            template.cmp_reg32(10, 13);
            template.branch_cond(Condition::NotEqual, mismatch);
        }
        2..=3 => {
            template.load16(10, hay_pointer, 0);
            template.load16(13, needle_pointer, 0);
            template.cmp_reg32(10, 13);
            template.branch_cond(Condition::NotEqual, mismatch);
            if length == 3 {
                template.add_imm(16, hay_pointer, 1);
                template.add_imm(17, needle_pointer, 1);
                template.load16(10, 16, 0);
                template.load16(13, 17, 0);
                template.cmp_reg32(10, 13);
                template.branch_cond(Condition::NotEqual, mismatch);
            }
        }
        4..=7 => {
            template.load32(10, hay_pointer, 0);
            template.load32(13, needle_pointer, 0);
            template.cmp_reg32(10, 13);
            template.branch_cond(Condition::NotEqual, mismatch);
            if length > 4 {
                let tail = u16::try_from(length - 4).map_err(|_| AuditError::ArithmeticOverflow)?;
                template.add_imm(16, hay_pointer, tail);
                template.add_imm(17, needle_pointer, tail);
                template.load32(10, 16, 0);
                template.load32(13, 17, 0);
                template.cmp_reg32(10, 13);
                template.branch_cond(Condition::NotEqual, mismatch);
            }
        }
        8..=15 => {
            template.load64(10, hay_pointer, 0);
            template.load64(13, needle_pointer, 0);
            template.cmp_reg64(10, 13);
            template.branch_cond(Condition::NotEqual, mismatch);
            if length > 8 {
                let tail = u16::try_from(length - 8).map_err(|_| AuditError::ArithmeticOverflow)?;
                template.add_imm(16, hay_pointer, tail);
                template.add_imm(17, needle_pointer, tail);
                template.load64(10, 16, 0);
                template.load64(13, 17, 0);
                template.cmp_reg64(10, 13);
                template.branch_cond(Condition::NotEqual, mismatch);
            }
        }
        16 => {
            emit_literal_equality_16_with_vectors(
                template,
                hay_pointer,
                needle_pointer,
                mismatch,
                16,
                17,
            );
        }
        17..=crate::MAX_REPEATED_CONFIRM_BYTES => {
            let tail = u16::try_from(length - 16).map_err(|_| AuditError::ArithmeticOverflow)?;
            template.load_vector128(16, hay_pointer, 0);
            template.load_vector128(17, needle_pointer, 0);
            template.compare_equal_bytes16(16, 16, 17);
            template.add_imm(16, hay_pointer, tail);
            template.add_imm(17, needle_pointer, tail);
            template.load_vector128(18, 16, 0);
            template.load_vector128(19, 17, 0);
            template.compare_equal_bytes16(18, 18, 19);
            template.and_bytes16(16, 16, 18);
            template.unsigned_min_bytes16(16, 16);
            template.move_vector_byte_to32(10, 16);
            template.cmp_imm32(10, 255);
            template.branch_cond(Condition::NotEqual, mismatch);
        }
        _ => return Err(AuditError::InvalidSearchManifest),
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "independent equality construction exposes vector/scalar temporaries and every pointer"
)]
fn emit_literal_equality_with_vectors(
    template: &mut Template,
    hay_pointer: u8,
    needle_pointer: u8,
    length: usize,
    mismatch: Label,
    left_vector: u8,
    right_vector: u8,
    scalar_needle_byte: u8,
) -> Result<(), AuditError> {
    let scalar = template.new_label(LabelKind::Internal);
    let scalar_loop = template.new_label(LabelKind::Loop);
    let equal = template.new_label(LabelKind::Internal);
    template.mov_reg(15, hay_pointer);
    template.mov_reg(16, needle_pointer);
    template.mov_imm64(
        17,
        u64::try_from(length).map_err(|_| AuditError::ArithmeticOverflow)?,
    );
    if length >= 16 {
        let vector_loop = template.new_label(LabelKind::Loop);
        template.bind(vector_loop)?;
        template.cmp_imm64(17, 16);
        template.branch_cond(Condition::CarryClear, scalar);
        template.load_vector128(left_vector, 15, 0);
        template.load_vector128(right_vector, 16, 0);
        template.compare_equal_bytes16(left_vector, left_vector, right_vector);
        template.unsigned_min_bytes16(left_vector, left_vector);
        template.move_vector_byte_to32(10, left_vector);
        template.cmp_imm32(10, 255);
        template.branch_cond(Condition::NotEqual, mismatch);
        template.add_imm(15, 15, 16);
        template.add_imm(16, 16, 16);
        template.sub_imm(17, 17, 16);
        template.branch(vector_loop);
    } else {
        template.branch(scalar);
    }
    template.bind(scalar)?;
    template.compare_branch_zero(17, false, equal);
    template.bind(scalar_loop)?;
    template.load_byte(10, 15, 0);
    template.load_byte(scalar_needle_byte, 16, 0);
    template.cmp_reg32(10, scalar_needle_byte);
    template.branch_cond(Condition::NotEqual, mismatch);
    template.add_imm(15, 15, 1);
    template.add_imm(16, 16, 1);
    template.sub_imm(17, 17, 1);
    template.compare_branch_zero(17, true, scalar_loop);
    template.bind(equal)
}

fn emit_literal_equality(
    template: &mut Template,
    hay_pointer: u8,
    needle_pointer: u8,
    length: usize,
    mismatch: Label,
) -> Result<(), AuditError> {
    emit_literal_equality_with_vectors(
        template,
        hay_pointer,
        needle_pointer,
        length,
        mismatch,
        0,
        1,
        11,
    )
}

fn emit_class_suffix(
    template: &mut Template,
    suffix: &[u8],
    anchors: AnchorFlags,
    found: Label,
    none: Label,
) -> Result<(), AuditError> {
    template.mov_imm64(
        12,
        u64::try_from(suffix.len()).map_err(|_| AuditError::ArithmeticOverflow)?,
    );
    let extend = template.new_label(LabelKind::Loop);
    let confirm = template.new_label(LabelKind::Internal);
    let reject = template.new_label(LabelKind::SlowPath);
    let scan = if anchors.start {
        template.cmp_imm64(2, 0);
        template.branch_cond(Condition::NotEqual, none);
        template.cmp_imm64(3, 0);
        template.branch_cond(Condition::Equal, none);
        template.load_byte(10, 9, 0);
        emit_class_membership(template, none);
        template.mov_imm64(13, 0);
        template.mov_imm64(14, 1);
        template.branch(extend);
        None
    } else {
        let scan = template.new_label(LabelKind::Loop);
        let scan_miss = template.new_label(LabelKind::Internal);
        template.mov_reg(5, 2);
        template.bind(scan)?;
        template.cmp_reg64(5, 3);
        template.branch_cond(Condition::CarrySet, none);
        template.load_byte_reg(10, 9, 5);
        emit_class_membership(template, scan_miss);
        template.mov_reg(13, 5);
        template.add_imm(14, 5, 1);
        template.branch(extend);
        template.bind(scan_miss)?;
        template.add_imm(5, 5, 1);
        template.branch(scan);
        Some(scan)
    };
    template.bind(extend)?;
    template.cmp_reg64(14, 3);
    template.branch_cond(Condition::CarrySet, confirm);
    template.load_byte_reg(10, 9, 14);
    emit_class_membership(template, confirm);
    template.add_imm(14, 14, 1);
    template.branch(extend);
    template.bind(confirm)?;
    template.mov_reg(6, 14);
    template.sub_reg(10, 3, 14);
    template.cmp_reg64(10, 12);
    template.branch_cond(Condition::CarryClear, reject);
    template.add_reg(15, 9, 14);
    emit_literal_equality(template, 15, 7, suffix.len(), reject)?;
    template.add_reg(14, 14, 12);
    if anchors.end {
        template.cmp_reg64(14, 1);
        template.branch_cond(Condition::NotEqual, reject);
    }
    template.branch(found);
    template.bind(reject)?;
    if anchors.start {
        template.branch(none);
    } else {
        template.mov_reg(5, 6);
        template.branch(scan.ok_or(AuditError::InvalidSearchManifest)?);
    }
    Ok(())
}

fn emit_class_membership(template: &mut Template, not_member: Label) {
    template.lsr_imm(11, 10, 6);
    template.and_low_bits(17, 10, 6);
    template.load64_reg_scaled(15, 8, 11);
    template.lsrv(15, 15, 17);
    template.and_low_bits(15, 15, 1);
    template.compare_branch_zero(15, false, not_member);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SuffixFirstClass {
    Singleton(u8),
    Sve2Table,
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete suffix-first class control-flow template is reviewed as one unit"
)]
fn emit_suffix_first_class(
    template: &mut Template,
    class: SuffixFirstClass,
    suffix: &[u8],
    manifest: SearchManifest,
    found: Label,
    none: Label,
) -> Result<(), AuditError> {
    let suffix_length = u64::try_from(suffix.len()).map_err(|_| AuditError::ArithmeticOverflow)?;
    let last_offset = u16::try_from(suffix.len().saturating_sub(1))
        .map_err(|_| AuditError::ArithmeticOverflow)?;
    if manifest.primary_offset != 0
        || manifest.secondary_offset
            != if suffix.len() > 1 {
                last_offset
            } else {
                u16::MAX
            }
    {
        return Err(AuditError::InvalidSearchManifest);
    }
    let sve = matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE2_16_V1
    );
    if class == SuffixFirstClass::Sve2Table
        && manifest.backend_version != BackendVersion::SEARCH_SVE2_16_V1
    {
        return Err(AuditError::InvalidSearchManifest);
    }
    template.mov_imm64(12, suffix_length);
    template.sub_reg(10, 3, 2);
    template.cmp_reg64(10, 12);
    template.branch_cond(Condition::LowerOrSame, none);
    template.sub_reg(6, 3, 12);
    template.add_imm(5, 2, 1);
    if sve {
        template.sve_ptrue_bytes_vl16(0);
        template.load_byte(11, 7, 0);
        template.sve_duplicate_byte(1, 11);
        if suffix.len() > 1 {
            template.load_byte(11, 7, last_offset);
            template.sve_duplicate_byte(3, 11);
        }
        match class {
            SuffixFirstClass::Singleton(class_byte) => {
                template.mov_imm64(11, u64::from(class_byte));
                template.sve_duplicate_byte(5, 11);
            }
            SuffixFirstClass::Sve2Table => template.sve_load_bytes(5, 0, 16),
        }
    } else {
        let SuffixFirstClass::Singleton(class_byte) = class else {
            return Err(AuditError::InvalidSearchManifest);
        };
        template.load_byte(11, 7, 0);
        template.dup_byte16(4, 11);
        if suffix.len() > 1 {
            template.load_byte(11, 7, last_offset);
            template.dup_byte16(5, 11);
        }
        template.mov_imm64(11, u64::from(class_byte));
        template.dup_byte16(6, 11);
    }

    let vector = template.new_label(LabelKind::Loop);
    let advance_vector = template.new_label(LabelKind::Internal);
    let second_filter = (suffix.len() > 1).then(|| template.new_label(LabelKind::SlowPath));
    let block_scalar = template.new_label(LabelKind::SlowPath);
    let tail_scalar = template.new_label(LabelKind::SlowPath);
    let scalar_scan = template.new_label(LabelKind::Loop);
    let candidate_reject = template.new_label(LabelKind::Internal);
    let backward_vector = template.new_label(LabelKind::Loop);
    let backward_scalar = template.new_label(LabelKind::SlowPath);
    let backward_done = template.new_label(LabelKind::Internal);

    template.bind(vector)?;
    template.cmp_reg64(5, 6);
    template.branch_cond(Condition::Higher, none);
    template.sub_reg(10, 6, 5);
    template.cmp_imm64(10, 15);
    template.branch_cond(Condition::CarryClear, tail_scalar);
    template.add_reg(15, 9, 5);
    if sve {
        template.sve_load_bytes(0, 0, 15);
        if manifest.backend_version == BackendVersion::SEARCH_SVE2_16_V1 {
            template.sve2_match_bytes(1, 0, 0, 1);
        } else {
            template.sve_compare_equal_bytes(1, 0, 0, 1);
        }
        template.sve_test_predicate_bytes(0, 1);
        template.branch_cond(Condition::NotEqual, second_filter.unwrap_or(block_scalar));
    } else {
        template.load_vector128(2, 15, 0);
        template.compare_equal_bytes16(2, 2, 4);
        if let Some(second_filter) = second_filter {
            template.unsigned_max_bytes16(7, 2);
            template.move_vector_byte_to32(10, 7);
            template.compare_branch_zero(10, true, second_filter);
        } else {
            template.unsigned_max_bytes16(2, 2);
            template.move_vector_byte_to32(10, 2);
            template.compare_branch_zero(10, true, block_scalar);
        }
    }
    template.bind(advance_vector)?;
    template.add_imm(5, 5, 16);
    template.branch(vector);

    if let Some(second_filter) = second_filter {
        template.bind(second_filter)?;
        template.add_imm(10, 15, last_offset);
        if sve {
            template.sve_load_bytes(2, 0, 10);
            if manifest.backend_version == BackendVersion::SEARCH_SVE2_16_V1 {
                template.sve2_match_bytes(2, 0, 2, 3);
            } else {
                template.sve_compare_equal_bytes(2, 0, 2, 3);
            }
            template.sve_and_predicate_bytes(1, 0, 1, 2);
            template.sve_test_predicate_bytes(0, 1);
            template.branch_cond(Condition::NotEqual, block_scalar);
        } else {
            template.load_vector128(3, 10, 0);
            template.compare_equal_bytes16(3, 3, 5);
            template.and_bytes16(2, 2, 3);
            template.unsigned_max_bytes16(2, 2);
            template.move_vector_byte_to32(10, 2);
            template.compare_branch_zero(10, true, block_scalar);
        }
        template.branch(advance_vector);
    }

    template.bind(block_scalar)?;
    template.add_imm(0, 5, 16);
    template.branch(scalar_scan);
    template.bind(tail_scalar)?;
    template.add_imm(0, 6, 1);
    template.branch(scalar_scan);
    template.bind(scalar_scan)?;
    template.cmp_reg64(5, 0);
    template.branch_cond(Condition::Equal, vector);
    template.add_reg(15, 9, 5);
    template.load_byte(10, 15, 0);
    template.load_byte(11, 7, 0);
    template.cmp_reg32(10, 11);
    template.branch_cond(Condition::NotEqual, candidate_reject);
    if suffix.len() > 1 {
        template.load_byte(10, 15, last_offset);
        template.load_byte(11, 7, last_offset);
        template.cmp_reg32(10, 11);
        template.branch_cond(Condition::NotEqual, candidate_reject);
    }
    if sve {
        emit_literal_equality_with_vectors(
            template,
            15,
            7,
            suffix.len(),
            candidate_reject,
            0,
            2,
            11,
        )?;
    } else {
        emit_literal_equality(template, 15, 7, suffix.len(), candidate_reject)?;
    }
    template.add_reg(14, 5, 12);
    if manifest.anchors.end {
        template.cmp_reg64(14, 1);
        template.branch_cond(Condition::NotEqual, candidate_reject);
    }
    template.sub_imm(10, 5, 1);
    match class {
        SuffixFirstClass::Singleton(class_byte) => {
            template.load_byte_reg(15, 9, 10);
            template.mov_imm64(11, u64::from(class_byte));
            template.cmp_reg32(15, 11);
            template.branch_cond(Condition::NotEqual, candidate_reject);
        }
        SuffixFirstClass::Sve2Table => {
            template.load_byte_reg(10, 9, 10);
            emit_class_membership(template, candidate_reject);
        }
    }
    template.mov_reg(13, 5);

    template.bind(backward_vector)?;
    template.sub_reg(10, 13, 2);
    template.cmp_imm64(10, 16);
    template.branch_cond(Condition::CarryClear, backward_scalar);
    template.add_reg(15, 9, 13);
    template.sub_imm(15, 15, 16);
    if sve {
        template.sve_load_bytes(4, 0, 15);
        if manifest.backend_version == BackendVersion::SEARCH_SVE2_16_V1 {
            template.sve2_match_bytes(1, 0, 4, 5);
        } else {
            template.sve_compare_equal_bytes(1, 0, 4, 5);
        }
        template.sve_count_predicate_bytes(10, 0, 1);
        template.cmp_imm64(10, 16);
    } else {
        template.load_vector128(2, 15, 0);
        template.compare_equal_bytes16(2, 2, 6);
        template.unsigned_min_bytes16(2, 2);
        template.move_vector_byte_to32(10, 2);
        template.cmp_imm32(10, 255);
    }
    template.branch_cond(Condition::NotEqual, backward_scalar);
    template.sub_imm(13, 13, 16);
    template.branch(backward_vector);

    template.bind(backward_scalar)?;
    template.cmp_reg64(13, 2);
    template.branch_cond(Condition::Equal, backward_done);
    match class {
        SuffixFirstClass::Singleton(_) => {
            template.sub_imm(10, 13, 1);
            template.load_byte_reg(15, 9, 10);
            template.cmp_reg32(15, 11);
            template.branch_cond(Condition::NotEqual, backward_done);
            template.mov_reg(13, 10);
        }
        SuffixFirstClass::Sve2Table => {
            template.sub_imm(6, 13, 1);
            template.load_byte_reg(10, 9, 6);
            emit_class_membership(template, backward_done);
            template.mov_reg(13, 6);
        }
    }
    template.branch(backward_scalar);
    template.bind(backward_done)?;
    template.branch(found);

    template.bind(candidate_reject)?;
    template.add_imm(5, 5, 1);
    template.branch(scalar_scan);
    Ok(())
}
