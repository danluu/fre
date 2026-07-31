use core::fmt;

macro_rules! define_identity {
    ($(#[$attribute:meta])* $name:ident, $label:literal) => {
        $(#[$attribute])*
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            pub(crate) const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!($label, "({})"), self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

define_identity!(
    /// Canonical identity of every field in a v1 compile manifest.
    ManifestIdentity,
    "ManifestIdentity"
);
define_identity!(
    /// SHA-256 of the live retained literal bytes consumed from the facade.
    LiveLiteralIdentity,
    "LiveLiteralIdentity"
);
define_identity!(
    /// Canonical identity of one complete trusted compiler receipt.
    CompileReceiptIdentity,
    "CompileReceiptIdentity"
);
define_identity!(
    /// Domain-separated identity of the exact manifest policy and limits.
    PolicyLimitsIdentity,
    "PolicyLimitsIdentity"
);
define_identity!(
    /// Domain-separated identity of the complete resource-accounting receipt.
    ResourceReceiptIdentity,
    "ResourceReceiptIdentity"
);
define_identity!(
    /// Integrity identity of one canonical static expectation wire record.
    ///
    /// This authenticates internal bytes only; trusted build/signing
    /// provenance remains external.
    StaticCountExpectationIdentity,
    "StaticCountExpectationIdentity"
);
