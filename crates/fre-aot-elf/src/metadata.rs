use fre_jit_aarch64::{BackendVersion, CpuFeatures, NativeImage};
use sha2::{Digest, Sha256};

use crate::{
    BindingIdentity, ClaimedBindingIdentity, ClaimedCompileIdentity, CompileIdentity,
    EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1, EXPORTED_SYMBOL_SCHEMA_VERSION_V1, ElfObjectError,
    METADATA_SYMBOL_PREFIX_V1, PAYLOAD_SYMBOL_PREFIX_V1, SEARCH_ENTRY_SYMBOL_PREFIX_V1,
};

pub const METADATA_VERSION_V1: u16 = 1;
pub const METADATA_BYTES_V1: usize = 216;
const METADATA_RECORD_BYTES_V1: u16 = 216;
pub const ENTRY_OFFSET_V1: u32 = 0;
pub const PLATFORM_LINUX_V1: u8 = 2;
pub const CALL_ABI_SCHEMA_V1: u16 = 1;
pub const STATUS_BITS_V1: u8 = 64;
pub const SEARCH_ABI_KIND_V1: u8 = 1;

pub const ELF_CLASS_64_V1: u8 = 2;
pub const ELF_DATA_LSB_V1: u8 = 1;
pub const ELF_VERSION_CURRENT_V1: u8 = 1;
pub const ELF_OS_ABI_SYSV_V1: u8 = 0;
pub const ELF_RELOCATABLE_TYPE_V1: u16 = 1;
pub const ELF_MACHINE_AARCH64_V1: u16 = 183;

const METADATA_MAGIC_V1: [u8; 8] = *b"FREOM64\x01";
const ELF_COMPILE_IDENTITY_DOMAIN_V1: &[u8] = b"FRE-AOT-ELF-COMPILE\0\x01";

/// Canonical object-neutral Search metadata carried in the Linux ELF object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataV1 {
    backend_version: u16,
    output_kind: u8,
    architecture: u8,
    little_endian: u8,
    pointer_width: u8,
    target_abi: u8,
    features: u64,
    payload_bytes: u32,
    code_bytes: u32,
    rodata_offset: u32,
    rodata_bytes: u32,
    source_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    payload_sha256: [u8; 32],
    compile_identity: [u8; 32],
}

impl MetadataV1 {
    pub(crate) fn from_image(
        image: &NativeImage,
        binding: BindingIdentity,
        payload_sha256: [u8; 32],
        payload_bytes: usize,
    ) -> Result<Self, ElfObjectError> {
        let mut metadata = Self {
            backend_version: image.backend_version().0,
            output_kind: output_tag(image.output()),
            architecture: image.target().architecture,
            little_endian: u8::from(image.target().little_endian),
            pointer_width: image.target().pointer_width,
            target_abi: image.target().abi,
            features: image.target().features.bits(),
            payload_bytes: to_u32(payload_bytes, "metadata payload bytes")?,
            code_bytes: to_u32(image.code().len(), "metadata code bytes")?,
            rodata_offset: image.layout().rodata_from_code_start,
            rodata_bytes: to_u32(image.rodata().len(), "metadata rodata bytes")?,
            source_identity: *image.source_identity().as_bytes(),
            artifact_identity: *image.artifact_identity().as_bytes(),
            binding_identity: *binding.as_bytes(),
            payload_sha256,
            compile_identity: [0; 32],
        };
        metadata.validate_shape()?;
        metadata.compile_identity = compute_compile_identity_v1(metadata).0;
        Ok(metadata)
    }

    #[must_use]
    pub const fn format_version(&self) -> u16 {
        METADATA_VERSION_V1
    }

    #[must_use]
    pub const fn record_bytes(&self) -> u16 {
        METADATA_RECORD_BYTES_V1
    }

    #[must_use]
    pub const fn backend_version(&self) -> u16 {
        self.backend_version
    }

    #[must_use]
    pub const fn abi_kind(&self) -> u8 {
        SEARCH_ABI_KIND_V1
    }

    #[must_use]
    pub const fn output_kind(&self) -> u8 {
        self.output_kind
    }

    #[must_use]
    pub const fn architecture(&self) -> u8 {
        self.architecture
    }

    #[must_use]
    pub const fn little_endian(&self) -> bool {
        self.little_endian == 1
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
        PLATFORM_LINUX_V1
    }

    #[must_use]
    pub const fn status_bits(&self) -> u8 {
        STATUS_BITS_V1
    }

    #[must_use]
    pub const fn abi_schema(&self) -> u16 {
        CALL_ABI_SCHEMA_V1
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
        ENTRY_OFFSET_V1
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
        0
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
    pub fn compile_identity(&self) -> CompileIdentity {
        CompileIdentity(self.compile_identity)
    }

    pub fn encode(self) -> Result<[u8; METADATA_BYTES_V1], ElfObjectError> {
        let mut bytes = [0_u8; METADATA_BYTES_V1];
        let mut writer = Writer::new(&mut bytes);
        writer.raw(&METADATA_MAGIC_V1)?;
        writer.u16(METADATA_VERSION_V1)?;
        writer.u16(METADATA_RECORD_BYTES_V1)?;
        writer.u16(self.backend_version)?;
        writer.u8(SEARCH_ABI_KIND_V1)?;
        writer.u8(self.output_kind)?;
        writer.u8(self.architecture)?;
        writer.u8(self.little_endian)?;
        writer.u8(self.pointer_width)?;
        writer.u8(self.target_abi)?;
        writer.u8(PLATFORM_LINUX_V1)?;
        writer.u8(STATUS_BITS_V1)?;
        writer.u16(CALL_ABI_SCHEMA_V1)?;
        writer.u64(self.features)?;
        writer.u32(self.payload_bytes)?;
        writer.u32(ENTRY_OFFSET_V1)?;
        writer.u32(self.code_bytes)?;
        writer.u32(self.rodata_offset)?;
        writer.u32(self.rodata_bytes)?;
        writer.u32(0)?;
        writer.raw(&self.source_identity)?;
        writer.raw(&self.artifact_identity)?;
        writer.raw(&self.binding_identity)?;
        writer.raw(&self.payload_sha256)?;
        writer.raw(&self.compile_identity)?;
        if writer.position() != METADATA_BYTES_V1 {
            return Err(invalid("metadata encoding width"));
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ElfObjectError> {
        if bytes.len() != METADATA_BYTES_V1 {
            return Err(invalid("metadata extent"));
        }
        let mut reader = Reader::new(bytes);
        reader.expect(&METADATA_MAGIC_V1, "metadata magic")?;
        if reader.u16("metadata version")? != METADATA_VERSION_V1
            || usize::from(reader.u16("metadata bytes")?) != METADATA_BYTES_V1
        {
            return Err(invalid("metadata header"));
        }
        let metadata = Self {
            backend_version: reader.u16("backend version")?,
            output_kind: {
                if reader.u8("ABI kind")? != SEARCH_ABI_KIND_V1 {
                    return Err(invalid("metadata ABI kind"));
                }
                reader.u8("output kind")?
            },
            architecture: reader.u8("architecture")?,
            little_endian: reader.u8("byte order")?,
            pointer_width: reader.u8("pointer width")?,
            target_abi: reader.u8("target ABI")?,
            features: {
                if reader.u8("platform")? != PLATFORM_LINUX_V1
                    || reader.u8("status bits")? != STATUS_BITS_V1
                    || reader.u16("call ABI schema")? != CALL_ABI_SCHEMA_V1
                {
                    return Err(invalid("metadata platform ABI"));
                }
                reader.u64("features")?
            },
            payload_bytes: reader.u32("payload bytes")?,
            code_bytes: {
                if reader.u32("entry offset")? != ENTRY_OFFSET_V1 {
                    return Err(invalid("entry offset"));
                }
                reader.u32("code bytes")?
            },
            rodata_offset: reader.u32("rodata offset")?,
            rodata_bytes: reader.u32("rodata bytes")?,
            source_identity: {
                if reader.u32("literal bytes")? != 0 {
                    return Err(invalid("literal bytes"));
                }
                reader.array("source identity")?
            },
            artifact_identity: reader.array("artifact identity")?,
            binding_identity: reader.array("binding identity")?,
            payload_sha256: reader.array("payload digest")?,
            compile_identity: reader.array("compile identity")?,
        };
        if reader.position() != bytes.len() {
            return Err(invalid("metadata trailing bytes"));
        }
        metadata.validate_shape()?;
        if compute_compile_identity_v1(metadata).0 != metadata.compile_identity {
            return Err(ElfObjectError::CompileIdentityMismatch);
        }
        Ok(metadata)
    }

    fn validate_shape(self) -> Result<(), ElfObjectError> {
        let target_ok = self.architecture == 1
            && self.little_endian == 1
            && self.pointer_width == 64
            && self.target_abi == 1;
        let backend_ok = match self.backend_version {
            version
                if version == BackendVersion::SEARCH_V8.0
                    || version == BackendVersion::SEARCH_V9.0
                    || version == BackendVersion::SEARCH_V10.0 =>
            {
                self.features == CpuFeatures::ASIMD.bits()
            }
            version if version == BackendVersion::SEARCH_SVE2_FIXED16_V2.0 => {
                self.features == CpuFeatures::ASIMD_SVE2.bits() && self.rodata_bytes == 16
            }
            _ => false,
        };
        let layout_end = self.rodata_offset.checked_add(self.rodata_bytes);
        if !target_ok
            || !backend_ok
            || !(1..=3).contains(&self.output_kind)
            || self.binding_identity == [0; 32]
            || self.code_bytes == 0
            || !self.code_bytes.is_multiple_of(4)
            || !self.rodata_offset.is_multiple_of(16)
            || self.rodata_offset < self.code_bytes
            || layout_end != Some(self.payload_bytes)
        {
            return Err(invalid("metadata contract"));
        }
        Ok(())
    }
}

/// Strictly decode one canonical Linux Search metadata record.
///
/// This validates the complete target/backend/layout contract and recomputes
/// the embedded compile identity. The result remains object metadata; it does
/// not authenticate an implementation object or grant runtime authority.
pub fn inspect_metadata_v1(bytes: &[u8]) -> Result<MetadataV1, ElfObjectError> {
    MetadataV1::decode(bytes)
}

pub(crate) fn compute_compile_identity_v1(metadata: MetadataV1) -> CompileIdentity {
    let mut hasher = Sha256::new();
    hasher.update(ELF_COMPILE_IDENTITY_DOMAIN_V1);
    hasher.update(METADATA_VERSION_V1.to_le_bytes());
    hasher.update(EXPORTED_SYMBOL_SCHEMA_VERSION_V1.to_le_bytes());
    hasher.update(
        u16::try_from(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1)
            .expect("fixed identity width")
            .to_le_bytes(),
    );
    for prefix in [
        SEARCH_ENTRY_SYMBOL_PREFIX_V1,
        PAYLOAD_SYMBOL_PREFIX_V1,
        METADATA_SYMBOL_PREFIX_V1,
    ] {
        hasher.update(
            u16::try_from(prefix.len())
                .expect("fixed prefix width")
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
    }
    hasher.update([
        ELF_CLASS_64_V1,
        ELF_DATA_LSB_V1,
        ELF_VERSION_CURRENT_V1,
        ELF_OS_ABI_SYSV_V1,
    ]);
    hasher.update(ELF_RELOCATABLE_TYPE_V1.to_le_bytes());
    hasher.update(ELF_MACHINE_AARCH64_V1.to_le_bytes());
    hasher.update(metadata.backend_version.to_le_bytes());
    hasher.update([
        SEARCH_ABI_KIND_V1,
        metadata.output_kind,
        metadata.architecture,
        metadata.little_endian,
        metadata.pointer_width,
        metadata.target_abi,
        PLATFORM_LINUX_V1,
        STATUS_BITS_V1,
    ]);
    hasher.update(CALL_ABI_SCHEMA_V1.to_le_bytes());
    hasher.update(metadata.features.to_le_bytes());
    hasher.update(metadata.binding_identity);
    hasher.update(metadata.source_identity);
    hasher.update(metadata.artifact_identity);
    hasher.update(metadata.payload_sha256);
    hasher.update(metadata.payload_bytes.to_le_bytes());
    hasher.update(ENTRY_OFFSET_V1.to_le_bytes());
    hasher.update(metadata.code_bytes.to_le_bytes());
    hasher.update(metadata.rodata_offset.to_le_bytes());
    hasher.update(metadata.rodata_bytes.to_le_bytes());
    hasher.update(0_u32.to_le_bytes());
    CompileIdentity(hasher.finalize().into())
}

const fn output_tag(output: fre_kernel_ir::OutputKind) -> u8 {
    match output {
        fre_kernel_ir::OutputKind::Exists => 1,
        fre_kernel_ir::OutputKind::SelectedEnd => 2,
        fre_kernel_ir::OutputKind::Span => 3,
    }
}

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
            .ok_or_else(|| invalid("metadata writer range"))?
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
    source: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn raw(&mut self, bytes: usize, at: &'static str) -> Result<&'a [u8], ElfObjectError> {
        let end = self
            .position
            .checked_add(bytes)
            .ok_or(ElfObjectError::ArithmeticOverflow { at })?;
        let result = self
            .source
            .get(self.position..end)
            .ok_or_else(|| invalid(at))?;
        self.position = end;
        Ok(result)
    }

    fn expect(&mut self, expected: &[u8], at: &'static str) -> Result<(), ElfObjectError> {
        if self.raw(expected.len(), at)? == expected {
            Ok(())
        } else {
            Err(invalid(at))
        }
    }

    fn array<const N: usize>(&mut self, at: &'static str) -> Result<[u8; N], ElfObjectError> {
        self.raw(N, at)?.try_into().map_err(|_| invalid(at))
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, ElfObjectError> {
        Ok(self.array::<1>(at)?[0])
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
}
