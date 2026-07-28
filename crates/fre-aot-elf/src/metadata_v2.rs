use fre_jit_aarch64::{
    AuditedSelectedEndRegisterImageV2, BackendVersion, CpuFeatures,
    SELECTED_END_REGISTER_CALL_ABI_SCHEMA_V2, SELECTED_END_REGISTER_RETURN_ENCODING_V2,
};
use fre_kernel_ir::OutputKind;
use sha2::{Digest, Sha256};

use crate::{
    BindingIdentity, ClaimedBindingIdentity, ClaimedCompileIdentity, CompileIdentity,
    EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2, EXPORTED_SYMBOL_SCHEMA_VERSION_V2, ElfObjectError,
    SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2, SELECTED_END_METADATA_SYMBOL_PREFIX_V2,
    SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2,
};

pub const SELECTED_END_METADATA_VERSION_V2: u16 = 2;
pub const SELECTED_END_METADATA_BYTES_V2: usize = 224;
pub const SELECTED_END_BACKEND_VERSION_V2: u16 = BackendVersion::SEARCH_SVE2_FIXED16_V2.0;
pub const SELECTED_END_ENTRY_OFFSET_V2: u32 = 0;
pub const SELECTED_END_PLATFORM_LINUX_V2: u8 = 2;
pub const SELECTED_END_ABI_KIND_V2: u8 = 2;
pub const SELECTED_END_OUTPUT_KIND_V2: u8 = 2;
pub const SELECTED_END_ARCHITECTURE_AARCH64_V2: u8 = 1;
pub const SELECTED_END_LITTLE_ENDIAN_V2: u8 = 1;
pub const SELECTED_END_POINTER_WIDTH_V2: u8 = 64;
pub const SELECTED_END_TARGET_ABI_AAPCS64_V2: u8 = 1;
pub const SELECTED_END_RETURN_BITS_V2: u8 = 64;
pub const SELECTED_END_CALL_ABI_SCHEMA_V2: u16 = SELECTED_END_REGISTER_CALL_ABI_SCHEMA_V2;
pub const SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2: u8 =
    SELECTED_END_REGISTER_RETURN_ENCODING_V2;
pub const SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2: u8 = 1;
pub const SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2: u16 = 16;
pub const SELECTED_END_REQUIRED_FEATURES_V2: u64 = 7;
pub const SELECTED_END_LITERAL_BYTES_V2: u32 = 16;
pub const SELECTED_END_ARGUMENT_COUNT_V2: u8 = 4;
pub const SELECTED_END_RETURN_REGISTER_V2: u8 = 0;
pub const SELECTED_END_RESULT_SLOT_BYTES_V2: u16 = 0;
pub const SELECTED_END_NO_MATCH_SENTINEL_V2: u64 = 0;

pub const ELF_CLASS_64_V2: u8 = 2;
pub const ELF_DATA_LSB_V2: u8 = 1;
pub const ELF_VERSION_CURRENT_V2: u8 = 1;
pub const ELF_OS_ABI_SYSV_V2: u8 = 0;
pub const ELF_RELOCATABLE_TYPE_V2: u16 = 1;
pub const ELF_MACHINE_AARCH64_V2: u16 = 183;
pub const ELF_SYMBOL_INFO_FUNCTION_V2: u8 = 0x12;
pub const ELF_SYMBOL_INFO_OBJECT_V2: u8 = 0x11;
pub const ELF_SYMBOL_VISIBILITY_HIDDEN_V2: u8 = 2;

pub(crate) const SELECTED_END_METADATA_MAGIC_V2: [u8; 8] = *b"FRESE64\x02";
pub(crate) const SELECTED_END_ELF_COMPILE_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-ELF-SEARCH-SELECTED-END-COMPILE\0\x02";
pub(crate) const SELECTED_END_METADATA_COMPILE_IDENTITY_OFFSET_V2: usize = 192;

const METADATA_RECORD_BYTES_V2: u16 = 224;
const RESERVED_ZERO_V2: u32 = 0;

const _: () = assert!(SELECTED_END_METADATA_BYTES_V2 == 224);
const _: () = assert!(
    SELECTED_END_METADATA_COMPILE_IDENTITY_OFFSET_V2 + 32 == SELECTED_END_METADATA_BYTES_V2
);
const _: () = assert!(SELECTED_END_CALL_ABI_SCHEMA_V2 == 2);
const _: () = assert!(SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2 == 1);

/// Canonical object-neutral metadata for a Linux tag21 SelectedEnd ABI2
/// implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedEndMetadataV2 {
    backend_version: u16,
    architecture: u8,
    little_endian: u8,
    pointer_width: u8,
    target_abi: u8,
    features: u64,
    payload_bytes: u32,
    code_bytes: u32,
    rodata_offset: u32,
    rodata_bytes: u32,
    literal_bytes: u32,
    source_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    payload_sha256: [u8; 32],
    compile_identity: [u8; 32],
}

impl SelectedEndMetadataV2 {
    pub(crate) fn from_image(
        image: &AuditedSelectedEndRegisterImageV2,
        binding: BindingIdentity,
        payload_sha256: [u8; 32],
        payload_bytes: usize,
    ) -> Result<Self, ElfObjectError> {
        let mut metadata = Self {
            backend_version: image.backend_version().0,
            architecture: image.target().architecture,
            little_endian: u8::from(image.target().little_endian),
            pointer_width: image.target().pointer_width,
            target_abi: image.target().abi,
            features: image.required_features().bits(),
            payload_bytes: to_u32(payload_bytes, "metadata payload bytes")?,
            code_bytes: to_u32(image.code().len(), "metadata code bytes")?,
            rodata_offset: image.layout().rodata_from_code_start,
            rodata_bytes: to_u32(image.rodata().len(), "metadata rodata bytes")?,
            literal_bytes: image.literal_bytes(),
            source_identity: *image.source_identity().as_bytes(),
            artifact_identity: *image.artifact_identity().as_bytes(),
            binding_identity: *binding.as_bytes(),
            payload_sha256,
            compile_identity: [0; 32],
        };
        metadata.validate_shape(false)?;
        metadata.compile_identity = compute_selected_end_compile_identity_v2(metadata)?.0;
        metadata.validate_shape(true)?;
        Ok(metadata)
    }

    #[must_use]
    pub const fn format_version(&self) -> u16 {
        SELECTED_END_METADATA_VERSION_V2
    }

    #[must_use]
    pub const fn record_bytes(&self) -> u16 {
        METADATA_RECORD_BYTES_V2
    }

    #[must_use]
    pub const fn backend_version(&self) -> u16 {
        self.backend_version
    }

    #[must_use]
    pub const fn abi_kind(&self) -> u8 {
        SELECTED_END_ABI_KIND_V2
    }

    #[must_use]
    pub const fn output_kind(&self) -> u8 {
        SELECTED_END_OUTPUT_KIND_V2
    }

    #[must_use]
    pub const fn architecture(&self) -> u8 {
        self.architecture
    }

    #[must_use]
    pub const fn little_endian(&self) -> bool {
        self.little_endian == SELECTED_END_LITTLE_ENDIAN_V2
    }

    #[must_use]
    pub const fn pointer_width(&self) -> u8 {
        self.pointer_width
    }

    #[must_use]
    pub const fn target_abi(&self) -> u8 {
        self.target_abi
    }

    #[must_use]
    pub const fn platform(&self) -> u8 {
        SELECTED_END_PLATFORM_LINUX_V2
    }

    #[must_use]
    pub const fn return_bits(&self) -> u8 {
        SELECTED_END_RETURN_BITS_V2
    }

    #[must_use]
    pub const fn abi_schema(&self) -> u16 {
        SELECTED_END_CALL_ABI_SCHEMA_V2
    }

    #[must_use]
    pub const fn return_encoding(&self) -> u8 {
        SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2
    }

    #[must_use]
    pub const fn window_contract(&self) -> u8 {
        SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2
    }

    #[must_use]
    pub const fn fixed_active_vector_bytes(&self) -> u16 {
        SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2
    }

    #[must_use]
    pub const fn features(&self) -> u64 {
        self.features
    }

    #[must_use]
    pub const fn payload_bytes(&self) -> u32 {
        self.payload_bytes
    }

    #[must_use]
    pub const fn entry_offset(&self) -> u32 {
        SELECTED_END_ENTRY_OFFSET_V2
    }

    #[must_use]
    pub const fn code_bytes(&self) -> u32 {
        self.code_bytes
    }

    #[must_use]
    pub const fn rodata_offset(&self) -> u32 {
        self.rodata_offset
    }

    #[must_use]
    pub const fn rodata_bytes(&self) -> u32 {
        self.rodata_bytes
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.literal_bytes
    }

    #[must_use]
    pub const fn source_identity(&self) -> &[u8; 32] {
        &self.source_identity
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> &[u8; 32] {
        &self.artifact_identity
    }

    #[must_use]
    pub const fn claimed_binding_identity(&self) -> ClaimedBindingIdentity {
        ClaimedBindingIdentity(self.binding_identity)
    }

    #[must_use]
    pub const fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }

    #[must_use]
    pub const fn claimed_compile_identity(&self) -> ClaimedCompileIdentity {
        ClaimedCompileIdentity(self.compile_identity)
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CompileIdentity {
        CompileIdentity(self.compile_identity)
    }

    pub fn encode(self) -> Result<[u8; SELECTED_END_METADATA_BYTES_V2], ElfObjectError> {
        self.validate_shape(true)?;
        encode_metadata_unchecked(self)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ElfObjectError> {
        if bytes.len() != SELECTED_END_METADATA_BYTES_V2 {
            return Err(invalid("SelectedEnd-v2 metadata extent"));
        }
        let mut reader = Reader::new(bytes);
        reader.expect(
            &SELECTED_END_METADATA_MAGIC_V2,
            "SelectedEnd-v2 metadata magic",
        )?;
        if reader.u16("metadata version")? != SELECTED_END_METADATA_VERSION_V2
            || usize::from(reader.u16("metadata bytes")?) != SELECTED_END_METADATA_BYTES_V2
        {
            return Err(invalid("SelectedEnd-v2 metadata header"));
        }
        let backend_version = reader.u16("backend version")?;
        if reader.u8("ABI kind")? != SELECTED_END_ABI_KIND_V2
            || reader.u8("output kind")? != SELECTED_END_OUTPUT_KIND_V2
        {
            return Err(invalid("SelectedEnd-v2 ABI/output"));
        }
        let architecture = reader.u8("architecture")?;
        let little_endian = reader.u8("byte order")?;
        let pointer_width = reader.u8("pointer width")?;
        let target_abi = reader.u8("target ABI")?;
        if reader.u8("platform")? != SELECTED_END_PLATFORM_LINUX_V2
            || reader.u8("return bits")? != SELECTED_END_RETURN_BITS_V2
            || reader.u16("call ABI schema")? != SELECTED_END_CALL_ABI_SCHEMA_V2
            || reader.u8("return encoding")? != SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2
            || reader.u8("window contract")?
                != SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2
            || reader.u16("fixed active vector bytes")? != SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2
            || reader.u32("reserved bytes")? != RESERVED_ZERO_V2
        {
            return Err(invalid("SelectedEnd-v2 call contract"));
        }
        let metadata = Self {
            backend_version,
            architecture,
            little_endian,
            pointer_width,
            target_abi,
            features: reader.u64("features")?,
            payload_bytes: reader.u32("payload bytes")?,
            code_bytes: {
                if reader.u32("entry offset")? != SELECTED_END_ENTRY_OFFSET_V2 {
                    return Err(invalid("SelectedEnd-v2 entry offset"));
                }
                reader.u32("code bytes")?
            },
            rodata_offset: reader.u32("rodata offset")?,
            rodata_bytes: reader.u32("rodata bytes")?,
            literal_bytes: reader.u32("literal bytes")?,
            source_identity: reader.array("source identity")?,
            artifact_identity: reader.array("artifact identity")?,
            binding_identity: reader.array("binding identity")?,
            payload_sha256: reader.array("payload digest")?,
            compile_identity: reader.array("compile identity")?,
        };
        if reader.position() != bytes.len() {
            return Err(invalid("SelectedEnd-v2 metadata trailing bytes"));
        }
        metadata.validate_shape(true)?;
        if compute_selected_end_compile_identity_v2(metadata)?.0 != metadata.compile_identity {
            return Err(ElfObjectError::CompileIdentityMismatch);
        }
        Ok(metadata)
    }

    fn validate_shape(self, require_compile_identity: bool) -> Result<(), ElfObjectError> {
        let target_ok = self.architecture == SELECTED_END_ARCHITECTURE_AARCH64_V2
            && self.little_endian == SELECTED_END_LITTLE_ENDIAN_V2
            && self.pointer_width == SELECTED_END_POINTER_WIDTH_V2
            && self.target_abi == SELECTED_END_TARGET_ABI_AAPCS64_V2
            && self.features == SELECTED_END_REQUIRED_FEATURES_V2;
        let layout_end = self.rodata_offset.checked_add(self.rodata_bytes);
        if self.backend_version != SELECTED_END_BACKEND_VERSION_V2
            || !target_ok
            || self.literal_bytes != SELECTED_END_LITERAL_BYTES_V2
            || self.rodata_bytes != SELECTED_END_LITERAL_BYTES_V2
            || self.binding_identity == [0; 32]
            || self.source_identity == [0; 32]
            || self.artifact_identity == [0; 32]
            || self.payload_sha256 == [0; 32]
            || (require_compile_identity && self.compile_identity == [0; 32])
            || self.code_bytes == 0
            || !self.code_bytes.is_multiple_of(4)
            || !self.rodata_offset.is_multiple_of(16)
            || self.rodata_offset < self.code_bytes
            || layout_end != Some(self.payload_bytes)
        {
            return Err(invalid("SelectedEnd-v2 metadata contract"));
        }
        Ok(())
    }
}

/// Strictly inspect one complete SelectedEnd register-return metadata record.
pub fn inspect_selected_end_metadata_v2(
    bytes: &[u8],
) -> Result<SelectedEndMetadataV2, ElfObjectError> {
    SelectedEndMetadataV2::decode(bytes)
}

pub(crate) fn compute_selected_end_compile_identity_v2(
    mut metadata: SelectedEndMetadataV2,
) -> Result<CompileIdentity, ElfObjectError> {
    metadata.compile_identity = [0; 32];
    let metadata_bytes = encode_metadata_unchecked(metadata)?;
    let mut hasher = Sha256::new();
    hasher.update(SELECTED_END_ELF_COMPILE_IDENTITY_DOMAIN_V2);
    hasher.update(SELECTED_END_METADATA_VERSION_V2.to_le_bytes());
    hasher.update(EXPORTED_SYMBOL_SCHEMA_VERSION_V2.to_le_bytes());
    hasher.update(
        u16::try_from(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2)
            .expect("fixed identity width")
            .to_le_bytes(),
    );
    for (prefix, symbol_info) in [
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
        hasher.update([symbol_info, ELF_SYMBOL_VISIBILITY_HIDDEN_V2]);
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
    Ok(CompileIdentity(hasher.finalize().into()))
}

fn encode_metadata_unchecked(
    metadata: SelectedEndMetadataV2,
) -> Result<[u8; SELECTED_END_METADATA_BYTES_V2], ElfObjectError> {
    let mut bytes = [0_u8; SELECTED_END_METADATA_BYTES_V2];
    let mut writer = Writer::new(&mut bytes);
    writer.raw(&SELECTED_END_METADATA_MAGIC_V2)?;
    writer.u16(SELECTED_END_METADATA_VERSION_V2)?;
    writer.u16(METADATA_RECORD_BYTES_V2)?;
    writer.u16(metadata.backend_version)?;
    writer.u8(SELECTED_END_ABI_KIND_V2)?;
    writer.u8(SELECTED_END_OUTPUT_KIND_V2)?;
    writer.u8(metadata.architecture)?;
    writer.u8(metadata.little_endian)?;
    writer.u8(metadata.pointer_width)?;
    writer.u8(metadata.target_abi)?;
    writer.u8(SELECTED_END_PLATFORM_LINUX_V2)?;
    writer.u8(SELECTED_END_RETURN_BITS_V2)?;
    writer.u16(SELECTED_END_CALL_ABI_SCHEMA_V2)?;
    writer.u8(SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2)?;
    writer.u8(SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2)?;
    writer.u16(SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2)?;
    writer.u32(RESERVED_ZERO_V2)?;
    writer.u64(metadata.features)?;
    writer.u32(metadata.payload_bytes)?;
    writer.u32(SELECTED_END_ENTRY_OFFSET_V2)?;
    writer.u32(metadata.code_bytes)?;
    writer.u32(metadata.rodata_offset)?;
    writer.u32(metadata.rodata_bytes)?;
    writer.u32(metadata.literal_bytes)?;
    writer.raw(&metadata.source_identity)?;
    writer.raw(&metadata.artifact_identity)?;
    writer.raw(&metadata.binding_identity)?;
    writer.raw(&metadata.payload_sha256)?;
    writer.raw(&metadata.compile_identity)?;
    if writer.position() != SELECTED_END_METADATA_BYTES_V2 {
        return Err(invalid("SelectedEnd-v2 metadata encoding width"));
    }
    Ok(bytes)
}

const fn output_tag(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

const _: () = assert!(output_tag(OutputKind::SelectedEnd) == SELECTED_END_OUTPUT_KIND_V2);
const _: () = assert!(CpuFeatures::ASIMD_SVE2.bits() == SELECTED_END_REQUIRED_FEATURES_V2);

fn to_u32(value: usize, at: &'static str) -> Result<u32, ElfObjectError> {
    u32::try_from(value).map_err(|_| ElfObjectError::ArithmeticOverflow { at })
}

const fn invalid(at: &'static str) -> ElfObjectError {
    ElfObjectError::InvalidObject { at }
}

struct Writer<'a> {
    destination: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    const fn new(destination: &'a mut [u8]) -> Self {
        Self {
            destination,
            position: 0,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), ElfObjectError> {
        let end =
            self.position
                .checked_add(bytes.len())
                .ok_or(ElfObjectError::ArithmeticOverflow {
                    at: "metadata writer",
                })?;
        self.destination
            .get_mut(self.position..end)
            .ok_or_else(|| invalid("metadata writer destination"))?
            .copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), ElfObjectError> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), ElfObjectError> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), ElfObjectError> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), ElfObjectError> {
        self.raw(&value.to_le_bytes())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take(&mut self, bytes: usize, at: &'static str) -> Result<&'a [u8], ElfObjectError> {
        let end = self
            .position
            .checked_add(bytes)
            .ok_or(ElfObjectError::ArithmeticOverflow { at })?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid(at))?;
        self.position = end;
        Ok(value)
    }

    fn expect(&mut self, expected: &[u8], at: &'static str) -> Result<(), ElfObjectError> {
        if self.take(expected.len(), at)? == expected {
            Ok(())
        } else {
            Err(invalid(at))
        }
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, ElfObjectError> {
        self.take(1, at)?
            .first()
            .copied()
            .ok_or_else(|| invalid(at))
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, ElfObjectError> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, ElfObjectError> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, ElfObjectError> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], ElfObjectError> {
        self.take(BYTES, at)?.try_into().map_err(|_| invalid(at))
    }
}
