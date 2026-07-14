//! Bounded, byte-preserving RE2 syntax compatibility track.
//!
//! This crate is deliberately independent of `regex-syntax`. Its specification
//! is the pinned RE2 source revision exported as [`RE2_SOURCE_REVISION`].
//! Unsupported syntax is an explicit [`ParseOutcome::NotYetImplemented`], not a
//! guessed parse or a compatibility claim.

#![forbid(unsafe_code)]

mod ast;
mod capability;
mod error;
mod options;
mod parser;
mod quote;
mod rewrite;
mod unicode;

pub use ast::{
    AnchorKind, Ast, ClassAtom, ClassItem, ClassKind, Greediness, Node, NodeId, NodeKind,
    PatternSpan, PosixClass, RepeatRange, RepeatSyntax, Token, TokenKind,
};
pub use capability::{Capability, CapabilityStatus, Surface, capability_ledger};
pub use error::{
    LimitKind, NotYetImplemented, ParseError, ParseErrorCode, ParseOutcome, ResourceUsage,
    UnsupportedFeature,
};
pub use options::{Encoding, Options, ParseLimits, SyntaxMode};
pub use parser::parse;
pub use quote::quote_meta;
pub use rewrite::{RewriteError, check_rewrite};

/// Schema for serialized/profile-sensitive public values in this crate.
pub const SCHEMA_VERSION: u32 = 1;

/// RE2 source revision used as this parser track's normative specification.
pub const RE2_SOURCE_REVISION: &str = "972a15cedd008d846f1a39b2e88ce48d7f166cbd";
