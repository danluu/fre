//! A deliberately small capture-free byte-language shared only as test input.

/// Greedy/lazy ordered-choice priority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Greed {
    Greedy,
    Lazy,
}

/// Inclusive byte interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    pub start: u8,
    pub end: u8,
}

impl ByteRange {
    #[must_use]
    pub const fn new(start: u8, end: u8) -> Self {
        Self { start, end }
    }
}

/// Capture-free semantic cases admitted by the direct production adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseAst {
    Empty,
    Byte(u8),
    Class(Vec<ByteRange>),
    Concat(Vec<Self>),
    Alt(Vec<Self>),
    Repeat {
        child: Box<Self>,
        min: u32,
        max: Option<u32>,
        greed: Greed,
    },
    StartText,
    EndText,
}

/// Generation/validation caps; all arithmetic is checked against these.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaseLimits {
    pub max_ast_nodes: usize,
    pub max_ast_depth: usize,
}

impl Default for CaseLimits {
    fn default() -> Self {
        Self {
            max_ast_nodes: 64,
            max_ast_depth: 16,
        }
    }
}
