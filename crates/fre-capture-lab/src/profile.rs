//! Versioned semantic profile identities.

/// Capture-semantics profile selected at compilation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptureProfile {
    /// `regex::bytes` 1.12.4, as configured by Rebar.
    RustRegexBytes1_12_4,
    /// RE2 at commit `972a15...`; admission remains intentionally disabled
    /// until the same corpus is checked against the upstream C++ oracle.
    Re2Commit972a15Pending,
}
