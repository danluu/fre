use core::fmt;

use fre_jit_aarch64::{ArtifactIdentity, NativeAggregateImage, NativeImage};

/// SHA-256 identity of the complete deterministic native image and manifest.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RuntimeIdentity([u8; 32]);

impl RuntimeIdentity {
    /// Read the complete deterministic identity of an immutable native image.
    ///
    /// Emission computes the canonical AOT digest once before returning the
    /// image. This accessor is O(1), allocation-free, and performs no rehash.
    /// Executable publication independently audits the image again.
    #[must_use]
    pub const fn for_image(image: &NativeImage) -> Self {
        Self::from_preflight_image(image)
    }

    /// Read the domain-separated identity of an aggregate native image.
    #[must_use]
    pub const fn for_aggregate_image(image: &NativeAggregateImage) -> Self {
        Self::from_preflight_aggregate_image(image)
    }

    pub(crate) const fn from_preflight_image(image: &NativeImage) -> Self {
        Self::from_artifact(image.artifact_identity())
    }

    pub(crate) const fn from_preflight_aggregate_image(image: &NativeAggregateImage) -> Self {
        Self::from_artifact(image.artifact_identity())
    }

    const fn from_artifact(identity: ArtifactIdentity) -> Self {
        Self(*identity.as_bytes())
    }

    /// Raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RuntimeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RuntimeIdentity({self})")
    }
}

impl fmt::Display for RuntimeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}
