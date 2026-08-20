//! Capability ledger: implemented does not imply full RE2 qualification.

/// Public RE2 syntax/helper surface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Surface {
    LiteralConcatAlternation,
    Captures,
    NamedCapturesAscii,
    CharacterRanges,
    PerlClasses,
    UnicodeClasses,
    PosixNamedClasses,
    AnchorsAndDot,
    Quantifiers,
    PerlInlineFlags,
    Latin1,
    Utf8,
    QuoteMeta,
    RewriteValidation,
    RewriteApplication,
    CaptureNameMaps,
    Diagnostics,
    /// Legacy surface name for downstream FRE program construction readiness.
    /// Exact RE2 `max_mem` threshold parity is not part of this contract.
    ConstructorAdmission,
    Matching,
}

/// Evidence status for one surface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityStatus {
    /// Implemented from pinned source evidence; upstream oracle not executed.
    SourceMappedUnqualified,
    /// Implemented and tested locally without direct source mapping.
    ImplementedLocally,
    /// A pinned direct oracle passed the recorded slice; full surface coverage remains open.
    OracleCheckedSlice,
    QualifiedAgainstPinnedOracle,
    Partial,
    NotYetImplemented,
}

/// One auditable ledger entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Capability {
    pub surface: Surface,
    pub status: CapabilityStatus,
    pub note: &'static str,
}

/// Current compatibility ledger.
#[must_use]
pub const fn capability_ledger() -> &'static [Capability] {
    use CapabilityStatus::{
        NotYetImplemented, OracleCheckedSlice, Partial, SourceMappedUnqualified,
    };
    &[
        Capability {
            surface: Surface::LiteralConcatAlternation,
            status: OracleCheckedSlice,
            note: "byte-preserving arena parser; pinned constructor slice passed",
        },
        Capability {
            surface: Surface::Captures,
            status: OracleCheckedSlice,
            note: "numbered and NeverCapture cases passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::NamedCapturesAscii,
            status: Partial,
            note: "ASCII names passed the oracle slice; full Unicode category validation is open",
        },
        Capability {
            surface: Surface::CharacterRanges,
            status: OracleCheckedSlice,
            note: "explicit rune/Latin-1 ranges passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::PerlClasses,
            status: OracleCheckedSlice,
            note: "symbolic dDsSwW representation passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::UnicodeClasses,
            status: OracleCheckedSlice,
            note: "all names are symbolic; Han passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::PosixNamedClasses,
            status: OracleCheckedSlice,
            note: "all 14 classes are symbolic; lower class passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::AnchorsAndDot,
            status: OracleCheckedSlice,
            note: "representative anchors/dot passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::Quantifiers,
            status: OracleCheckedSlice,
            note: "counted/lazy/stacked cases passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::PerlInlineFlags,
            status: OracleCheckedSlice,
            note: "representative scoped flags passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::Latin1,
            status: OracleCheckedSlice,
            note: "non-UTF8 Latin-1 construction passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::Utf8,
            status: OracleCheckedSlice,
            note: "valid and invalid UTF-8 cases passed the pinned oracle slice",
        },
        Capability {
            surface: Surface::QuoteMeta,
            status: SourceMappedUnqualified,
            note: "direct port of pinned loop; oracle not run",
        },
        Capability {
            surface: Surface::RewriteValidation,
            status: SourceMappedUnqualified,
            note: "direct port of CheckRewriteString grammar; oracle not run",
        },
        Capability {
            surface: Surface::RewriteApplication,
            status: NotYetImplemented,
            note: "substitution application belongs with match-result integration",
        },
        Capability {
            surface: Surface::CaptureNameMaps,
            status: SourceMappedUnqualified,
            note: "derivable from arena captures; oracle not run",
        },
        Capability {
            surface: Surface::Diagnostics,
            status: OracleCheckedSlice,
            note: "recorded constructor error codes/arguments passed; exhaustive diagnostics remain open",
        },
        Capability {
            surface: Surface::ConstructorAdmission,
            status: NotYetImplemented,
            note: "downstream FRE program construction under native checked limits is outside syntax parsing; exact RE2 max_mem parity is not promised",
        },
        Capability {
            surface: Surface::Matching,
            status: NotYetImplemented,
            note: "the C++ oracle records matches, but this crate does not execute ASTs",
        },
    ]
}
