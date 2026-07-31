//! Sealed image and identity types for the Search `SelectedEnd` register ABI.
//!
//! These types deliberately do not expose the underlying generic
//! [`NativeImage`]. A Search-v1 publisher therefore cannot accept a v2 image
//! by erasing this wrapper. Later AOT object writers can consume the complete
//! read-only image projection without weakening that boundary.

use core::fmt;

use fre_kernel_ir::{AnchorFlags, CacheIdentity, OutputKind};
use sha2::{Digest, Sha256};

use crate::{
    AotArtifact, AotLimits, BackendVersion, CodeLabel, CpuFeatures, DataSymbol, EmitError,
    ImageLayout, ImageStats, NativeImage, Relocation, TargetSpec,
    image::{SearchCallAbi, SearchShape},
};

/// Raw call-ABI schema for windowed scalar `SelectedEnd` returns.
pub const SELECTED_END_REGISTER_CALL_ABI_SCHEMA_V2: u16 = 2;
/// The scalar return encoding is zero for miss or the absolute exclusive end.
pub const SELECTED_END_REGISTER_RETURN_ENCODING_V2: u8 = 1;

pub(crate) const SELECTED_END_REGISTER_AOT_MAGIC_V2: [u8; 8] = *b"FRESR64\x02";
pub(crate) const SELECTED_END_REGISTER_ARTIFACT_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AARCH64-SEARCH-SELECTED-END-REGISTER-ARTIFACT\0\x02";

/// Explicit backend choices admitted by the register-return v2 slice.
///
/// Algorithm tags 8, 19, and 21 remain unchanged. The call ABI and artifact
/// identity domain, rather than a relabeled scan algorithm, distinguish these
/// images from Search v1.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SelectedEndRegisterBackendV2 {
    /// Advanced SIMD Search V8.
    #[default]
    AsimdV8,
    /// V8-screening plus fixed-VL16 SVE confirmation, Search tag 19.
    Sve16V6Tag19Vl16,
    /// Fixed-VL16 ASIMD+SVE+SVE2 Search tag 21.
    Sve2Fixed16Tag21Vl16,
}

impl SelectedEndRegisterBackendV2 {
    /// Existing scan-algorithm version reused by this ABI.
    #[must_use]
    pub const fn backend_version(self) -> BackendVersion {
        match self {
            Self::AsimdV8 => BackendVersion::SEARCH_V8,
            Self::Sve16V6Tag19Vl16 => BackendVersion::SEARCH_SVE16_V6,
            Self::Sve2Fixed16Tag21Vl16 => BackendVersion::SEARCH_SVE2_FIXED16_V2,
        }
    }

    /// Fixed active SVE/SVE2 bytes, or zero for the ASIMD backend.
    #[must_use]
    pub const fn fixed_active_vector_bytes(self) -> u16 {
        match self {
            Self::AsimdV8 => 0,
            Self::Sve16V6Tag19Vl16 | Self::Sve2Fixed16Tag21Vl16 => 16,
        }
    }
}

/// Exact architectural target required by one register-return ABI2 request.
///
/// V8's unanchored candidate scan uses ASIMD. An anchored short literal
/// bypasses that scan and uses scalar equality until its width reaches one
/// vector, while tag19 and tag21 retain their fixed feature envelopes.
#[must_use]
pub const fn selected_end_register_target_v2(
    backend: SelectedEndRegisterBackendV2,
    anchors: AnchorFlags,
    literal_bytes: u32,
) -> TargetSpec {
    match backend {
        SelectedEndRegisterBackendV2::AsimdV8
            if (anchors.start || anchors.end) && literal_bytes < 16 =>
        {
            TargetSpec {
                features: CpuFeatures::NONE,
                ..TargetSpec::AARCH64_AAPCS64
            }
        }
        SelectedEndRegisterBackendV2::AsimdV8 => TargetSpec::AARCH64_AAPCS64,
        SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16 => TargetSpec::AARCH64_AAPCS64_SVE16,
        SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16 => TargetSpec::AARCH64_AAPCS64_SVE2_16,
    }
}

/// Domain-separated identity of one complete register-return v2 image.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SelectedEndRegisterArtifactIdentityV2([u8; 32]);

impl SelectedEndRegisterArtifactIdentityV2 {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SelectedEndRegisterArtifactIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SelectedEndRegisterArtifactIdentityV2({self})")
    }
}

impl fmt::Display for SelectedEndRegisterArtifactIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Deterministic address-free AOT bytes for only the register-return v2 ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedEndRegisterAotArtifactV2(AotArtifact);

impl SelectedEndRegisterAotArtifactV2 {
    /// Borrow the canonical artifact bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Recompute the domain-separated v2 artifact identity.
    #[must_use]
    pub fn identity(&self) -> SelectedEndRegisterArtifactIdentityV2 {
        selected_end_register_artifact_identity_v2(self.as_bytes())
    }
}

/// Immutable Search image carrying the successful independent ABI2 audit.
///
/// Construction is crate-private and occurs only after exact whole-template
/// validation. There is intentionally no `as_image` or `into_image` escape
/// hatch: consumers receive the read-only fields needed by a dedicated v2
/// object writer, never a generic image accepted by Search-v1 publishers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedSelectedEndRegisterImageV2 {
    inner: NativeImage,
}

impl AuditedSelectedEndRegisterImageV2 {
    pub(crate) fn from_emitter_candidate(inner: NativeImage) -> Result<Self, EmitError> {
        let manifest = inner
            .search_manifest()
            .ok_or(EmitError::InternalInvariant)?;
        let backend = match inner.backend_version() {
            BackendVersion::SEARCH_V8 => SelectedEndRegisterBackendV2::AsimdV8,
            BackendVersion::SEARCH_SVE16_V6 => SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16,
            BackendVersion::SEARCH_SVE2_FIXED16_V2 => {
                SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
            }
            _ => return Err(EmitError::InternalInvariant),
        };
        if inner.search_call_abi() != SearchCallAbi::SelectedEndRegisterV2
            || inner.aggregate_manifest().is_some()
            || inner.output() != OutputKind::SelectedEnd
            || manifest.output != OutputKind::SelectedEnd
            || manifest.shape != SearchShape::ExactLiteral
            || manifest.literal_bytes == 0
            || inner.target()
                != selected_end_register_target_v2(
                    backend,
                    manifest.anchors,
                    manifest.literal_bytes,
                )
        {
            return Err(EmitError::InternalInvariant);
        }
        Ok(Self { inner })
    }

    pub(crate) const fn inner(&self) -> &NativeImage {
        &self.inner
    }

    #[cfg(test)]
    pub(crate) fn inner_mut_for_test(&mut self) -> &mut NativeImage {
        &mut self.inner
    }

    /// Scan-algorithm version retained by this ABI2 image.
    #[must_use]
    pub const fn backend_version(&self) -> BackendVersion {
        self.inner.backend_version()
    }

    /// Typed backend selection recovered from the sealed algorithm tag.
    #[must_use]
    pub const fn backend(&self) -> SelectedEndRegisterBackendV2 {
        match self.inner.backend_version() {
            BackendVersion::SEARCH_V8 => SelectedEndRegisterBackendV2::AsimdV8,
            BackendVersion::SEARCH_SVE16_V6 => SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16,
            BackendVersion::SEARCH_SVE2_FIXED16_V2 => {
                SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
            }
            _ => unreachable!(),
        }
    }

    /// Exact target and required architectural feature envelope.
    #[must_use]
    pub const fn target(&self) -> TargetSpec {
        self.inner.target()
    }

    /// The sealed output contract, always [`OutputKind::SelectedEnd`].
    #[must_use]
    pub const fn output(&self) -> OutputKind {
        self.inner.output()
    }

    /// Identity of the validated Kernel IR input.
    #[must_use]
    pub const fn source_identity(&self) -> CacheIdentity {
        self.inner.source_identity()
    }

    /// Exact anchor policy authenticated by the sealed manifest.
    #[must_use]
    pub const fn anchors(&self) -> AnchorFlags {
        match self.inner.search_manifest() {
            Some(manifest) => manifest.anchors,
            None => unreachable!(),
        }
    }

    /// Non-zero exact-literal width authenticated by the sealed manifest.
    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        match self.inner.search_manifest() {
            Some(manifest) => manifest.literal_bytes,
            None => unreachable!(),
        }
    }

    /// Required relative code/rodata placement.
    #[must_use]
    pub const fn layout(&self) -> ImageLayout {
        self.inner.layout()
    }

    /// Immutable machine code.
    #[must_use]
    pub fn code(&self) -> &[u8] {
        self.inner.code()
    }

    /// Immutable literal and auxiliary data.
    #[must_use]
    pub fn rodata(&self) -> &[u8] {
        self.inner.rodata()
    }

    /// Audited direct-control-flow labels.
    #[must_use]
    pub fn labels(&self) -> &[CodeLabel] {
        self.inner.labels()
    }

    /// Audited immutable data symbols.
    #[must_use]
    pub fn symbols(&self) -> &[DataSymbol] {
        self.inner.symbols()
    }

    /// Audited position-independent relocations.
    #[must_use]
    pub fn relocations(&self) -> &[Relocation] {
        self.inner.relocations()
    }

    /// Exact bounded emission statistics.
    #[must_use]
    pub const fn stats(&self) -> ImageStats {
        self.inner.stats()
    }

    /// Precomputed domain-separated artifact identity.
    #[must_use]
    pub fn artifact_identity(&self) -> SelectedEndRegisterArtifactIdentityV2 {
        SelectedEndRegisterArtifactIdentityV2::new(*self.inner.artifact_identity().as_bytes())
    }

    /// Serialize the distinct register-return v2 AOT artifact.
    pub fn to_aot(&self, limits: AotLimits) -> Result<SelectedEndRegisterAotArtifactV2, EmitError> {
        self.inner
            .to_aot(limits)
            .map(SelectedEndRegisterAotArtifactV2)
    }

    /// Exact feature bitmap, provided as a convenience for object metadata.
    #[must_use]
    pub const fn required_features(&self) -> CpuFeatures {
        self.inner.target().features
    }
}

pub(crate) fn selected_end_register_artifact_identity_v2(
    bytes: &[u8],
) -> SelectedEndRegisterArtifactIdentityV2 {
    let mut hasher = Sha256::new();
    hasher.update(SELECTED_END_REGISTER_ARTIFACT_IDENTITY_DOMAIN_V2);
    hasher.update(bytes);
    SelectedEndRegisterArtifactIdentityV2::new(hasher.finalize().into())
}
