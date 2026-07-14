//! Independent small-case reference semantics.
//!
//! This crate deliberately does not share a parser, HIR, automaton, closure
//! implementation, planner, or executor with production code. It interprets a
//! hand-built semantic AST with an explicit work stack and mandatory fuel. It
//! is an oracle for exhaustive small cases, not a production search engine.

#![forbid(unsafe_code)]

use core::fmt;

/// Greedy or lazy repetition priority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Greed {
    /// Try another repetition before the continuation.
    Greedy,
    /// Try the continuation before another repetition.
    Lazy,
}

/// Inclusive byte range used by [`Ast::Class`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    /// Inclusive lower bound.
    pub start: u8,
    /// Inclusive upper bound.
    pub end: u8,
}

impl ByteRange {
    /// Construct a checked inclusive range.
    pub fn new(start: u8, end: u8) -> Result<Self, ReferenceError> {
        if start > end {
            return Err(ReferenceError::InvalidAst("descending byte range"));
        }
        Ok(Self { start, end })
    }

    fn contains(self, byte: u8) -> bool {
        self.start <= byte && byte <= self.end
    }
}

/// Direct semantic AST understood by the independent oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ast {
    /// Match without consuming input.
    Empty,
    /// Match one exact byte.
    Byte(u8),
    /// Match one byte in any inclusive range.
    Class(Vec<ByteRange>),
    /// Match children from left to right.
    Concat(Vec<Ast>),
    /// Try alternatives in declaration order.
    Alt(Vec<Ast>),
    /// Repeat a child with ordered greedy/lazy choice.
    Repeat {
        /// Repeated child.
        child: Box<Ast>,
        /// Minimum repetitions.
        min: u32,
        /// Optional inclusive maximum.
        max: Option<u32>,
        /// Priority between repeat and exit.
        greed: Greed,
    },
    /// Record the child's selected span in a one-based capture slot.
    Capture {
        /// One-based capture index. Slot zero is the whole match.
        index: u32,
        /// Captured child.
        child: Box<Ast>,
    },
    /// Match only at the start of the original haystack.
    StartText,
    /// Match only at the end of the original haystack.
    EndText,
}

/// Half-open byte span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    /// Inclusive byte start.
    pub start: usize,
    /// Exclusive byte end.
    pub end: usize,
}

/// One selected match and all capture slots, including group zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Match {
    /// Whole-match span.
    pub span: Span,
    /// Capture slots. `None` and `Some(empty_span)` are distinct.
    pub captures: Vec<Option<Span>>,
}

/// Mandatory bounds for the small-case reference interpreter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum AST nodes visited by validation.
    pub max_ast_nodes: usize,
    /// Maximum semantic AST nesting depth.
    pub max_ast_depth: usize,
    /// Maximum one-based capture index.
    pub max_capture_index: usize,
    /// Maximum interpreter actions and scheduled branches.
    pub max_steps: u64,
    /// Maximum results returned by aggregate reference iteration.
    pub max_results: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_ast_nodes: 4_096,
            max_ast_depth: 128,
            max_capture_index: 64,
            max_steps: 1_000_000,
            max_results: 4_096,
        }
    }
}

/// Reference validation or execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceError {
    /// The hand-built semantic AST is invalid.
    InvalidAst(&'static str),
    /// A declared small-case resource limit was exceeded.
    ResourceLimit(&'static str),
    /// The requested starting offset lies outside the haystack.
    InvalidStart,
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAst(message) => write!(f, "invalid reference AST: {message}"),
            Self::ResourceLimit(resource) => write!(f, "reference resource limit: {resource}"),
            Self::InvalidStart => f.write_str("reference start is beyond the haystack"),
        }
    }
}

impl std::error::Error for ReferenceError {}

/// Validated direct-AST oracle.
#[derive(Clone, Debug)]
pub struct ReferenceRegex {
    ast: Ast,
    capture_count: usize,
    limits: Limits,
}

impl ReferenceRegex {
    /// Validate a direct semantic AST without recursive traversal.
    pub fn new(ast: Ast, limits: Limits) -> Result<Self, ReferenceError> {
        let mut stack = vec![(&ast, 1_usize)];
        let mut nodes = 0_usize;
        let mut capture_count = 0_usize;
        while let Some((node, depth)) = stack.pop() {
            nodes = nodes
                .checked_add(1)
                .ok_or(ReferenceError::ResourceLimit("AST node counter"))?;
            if nodes > limits.max_ast_nodes {
                return Err(ReferenceError::ResourceLimit("AST nodes"));
            }
            if depth > limits.max_ast_depth {
                return Err(ReferenceError::ResourceLimit("AST depth"));
            }
            let child_depth = depth
                .checked_add(1)
                .ok_or(ReferenceError::ResourceLimit("AST depth counter"))?;
            match node {
                Ast::Empty | Ast::Byte(_) | Ast::StartText | Ast::EndText => {}
                Ast::Class(ranges) => {
                    if ranges.is_empty() {
                        return Err(ReferenceError::InvalidAst("empty byte class"));
                    }
                    if ranges.iter().any(|range| range.start > range.end) {
                        return Err(ReferenceError::InvalidAst("descending byte range"));
                    }
                }
                Ast::Concat(children) | Ast::Alt(children) => {
                    if matches!(node, Ast::Alt(_)) && children.is_empty() {
                        return Err(ReferenceError::InvalidAst("empty alternation"));
                    }
                    stack.extend(children.iter().map(|child| (child, child_depth)));
                }
                Ast::Repeat {
                    child, min, max, ..
                } => {
                    if max.is_some_and(|maximum| maximum < *min) {
                        return Err(ReferenceError::InvalidAst("repeat maximum below minimum"));
                    }
                    stack.push((child, child_depth));
                }
                Ast::Capture { index, child } => {
                    let index = usize::try_from(*index)
                        .map_err(|_| ReferenceError::ResourceLimit("capture index"))?;
                    if index == 0 {
                        return Err(ReferenceError::InvalidAst("capture zero is reserved"));
                    }
                    if index > limits.max_capture_index {
                        return Err(ReferenceError::ResourceLimit("capture index"));
                    }
                    capture_count = capture_count.max(index);
                    stack.push((child, child_depth));
                }
            }
        }
        Ok(Self {
            ast,
            capture_count,
            limits,
        })
    }

    /// Search at or after `start`, with assertions evaluated against the
    /// original unsliced haystack.
    pub fn find_at(&self, haystack: &[u8], start: usize) -> Result<Option<Match>, ReferenceError> {
        if start > haystack.len() {
            return Err(ReferenceError::InvalidStart);
        }
        let mut fuel = Fuel::new(self.limits.max_steps);
        self.find_at_with_fuel(haystack, start, &mut fuel)
    }

    /// Return the Rust-style non-overlapping sequence using repeated reference
    /// search. This intentionally remains a quadratic-capable oracle.
    pub fn find_all_rust_reference(&self, haystack: &[u8]) -> Result<Vec<Match>, ReferenceError> {
        let mut fuel = Fuel::new(self.limits.max_steps);
        let mut matches = Vec::new();
        let mut at = 0_usize;
        let mut previous_end = None;
        loop {
            let Some(found) = self.find_at_with_fuel(haystack, at, &mut fuel)? else {
                break;
            };
            let empty = found.span.start == found.span.end;
            if empty && previous_end == Some(found.span.start) {
                let Some(next) = next_byte_boundary(found.span.end, haystack.len()) else {
                    break;
                };
                at = next;
                continue;
            }
            previous_end = Some(found.span.end);
            let next = if empty {
                next_byte_boundary(found.span.end, haystack.len())
            } else {
                Some(found.span.end)
            };
            matches.push(found);
            if matches.len() > self.limits.max_results {
                return Err(ReferenceError::ResourceLimit("result count"));
            }
            let Some(next) = next else {
                break;
            };
            at = next;
        }
        Ok(matches)
    }

    fn find_at_with_fuel(
        &self,
        haystack: &[u8],
        start: usize,
        fuel: &mut Fuel,
    ) -> Result<Option<Match>, ReferenceError> {
        for candidate in start..=haystack.len() {
            fuel.spend(1)?;
            if let Some(mut found) = self.match_from(haystack, candidate, fuel)? {
                found.captures[0] = Some(found.span);
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the direct AST interpreter keeps semantic action cases together for auditability"
    )]
    fn match_from(
        &self,
        haystack: &[u8],
        start: usize,
        fuel: &mut Fuel,
    ) -> Result<Option<Match>, ReferenceError> {
        let capture_slots = self
            .capture_count
            .checked_add(1)
            .ok_or(ReferenceError::ResourceLimit("capture slot count"))?;
        let initial = Thread {
            position: start,
            actions: vec![Action::Node(&self.ast)],
            captures: vec![None; capture_slots],
        };
        let mut branches = vec![initial];
        while let Some(mut thread) = branches.pop() {
            fuel.spend(1)?;
            loop {
                fuel.spend(1)?;
                let Some(action) = thread.actions.pop() else {
                    return Ok(Some(Match {
                        span: Span {
                            start,
                            end: thread.position,
                        },
                        captures: thread.captures,
                    }));
                };
                match action {
                    Action::Node(node) => match node {
                        Ast::Empty => {}
                        Ast::Byte(expected) => {
                            if haystack.get(thread.position) != Some(expected) {
                                break;
                            }
                            thread.position = thread
                                .position
                                .checked_add(1)
                                .ok_or(ReferenceError::ResourceLimit("input position"))?;
                        }
                        Ast::Class(ranges) => {
                            let Some(&byte) = haystack.get(thread.position) else {
                                break;
                            };
                            if !ranges.iter().any(|range| range.contains(byte)) {
                                break;
                            }
                            thread.position = thread
                                .position
                                .checked_add(1)
                                .ok_or(ReferenceError::ResourceLimit("input position"))?;
                        }
                        Ast::Concat(children) => {
                            thread
                                .actions
                                .extend(children.iter().rev().map(Action::Node));
                        }
                        Ast::Alt(alternatives) => {
                            for alternative in alternatives.iter().rev() {
                                fuel.spend(1)?;
                                let mut branch = thread.clone();
                                branch.actions.push(Action::Node(alternative));
                                branches.push(branch);
                            }
                            break;
                        }
                        Ast::Repeat {
                            child,
                            min,
                            max,
                            greed,
                        } => {
                            thread.actions.push(Action::Repeat {
                                child,
                                min: *min,
                                max: *max,
                                greed: *greed,
                                count: 0,
                                previous_position: thread.position,
                            });
                        }
                        Ast::Capture { index, child } => {
                            let index = usize::try_from(*index).map_err(|_| {
                                ReferenceError::ResourceLimit("capture index conversion")
                            })?;
                            thread.actions.push(Action::CloseCapture {
                                index,
                                start: thread.position,
                            });
                            thread.actions.push(Action::Node(child));
                        }
                        Ast::StartText => {
                            if thread.position != 0 {
                                break;
                            }
                        }
                        Ast::EndText => {
                            if thread.position != haystack.len() {
                                break;
                            }
                        }
                    },
                    Action::CloseCapture { index, start } => {
                        thread.captures[index] = Some(Span {
                            start,
                            end: thread.position,
                        });
                    }
                    Action::Repeat {
                        child,
                        min,
                        max,
                        greed,
                        count,
                        previous_position,
                    } => {
                        let made_progress = count == 0 || thread.position != previous_position;
                        let below_min = count < min;
                        let below_max = max.is_none_or(|maximum| count < maximum);
                        let may_repeat = below_max && (below_min || made_progress);
                        if below_min && !may_repeat {
                            break;
                        }
                        if below_min {
                            schedule_repeat(&mut thread, child, min, max, greed, count)?;
                            continue;
                        }
                        if !may_repeat {
                            continue;
                        }

                        let mut repeated = thread.clone();
                        schedule_repeat(&mut repeated, child, min, max, greed, count)?;
                        match greed {
                            Greed::Greedy => {
                                branches.push(thread);
                                branches.push(repeated);
                            }
                            Greed::Lazy => {
                                branches.push(repeated);
                                branches.push(thread);
                            }
                        }
                        break;
                    }
                }
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Debug)]
struct Thread<'ast> {
    position: usize,
    actions: Vec<Action<'ast>>,
    captures: Vec<Option<Span>>,
}

#[derive(Clone, Copy, Debug)]
enum Action<'ast> {
    Node(&'ast Ast),
    CloseCapture {
        index: usize,
        start: usize,
    },
    Repeat {
        child: &'ast Ast,
        min: u32,
        max: Option<u32>,
        greed: Greed,
        count: u32,
        previous_position: usize,
    },
}

fn schedule_repeat<'ast>(
    thread: &mut Thread<'ast>,
    child: &'ast Ast,
    min: u32,
    max: Option<u32>,
    greed: Greed,
    count: u32,
) -> Result<(), ReferenceError> {
    let next_count = count
        .checked_add(1)
        .ok_or(ReferenceError::ResourceLimit("repeat count"))?;
    thread.actions.push(Action::Repeat {
        child,
        min,
        max,
        greed,
        count: next_count,
        previous_position: thread.position,
    });
    thread.actions.push(Action::Node(child));
    Ok(())
}

#[derive(Debug)]
struct Fuel {
    remaining: u64,
}

impl Fuel {
    const fn new(remaining: u64) -> Self {
        Self { remaining }
    }

    fn spend(&mut self, amount: u64) -> Result<(), ReferenceError> {
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or(ReferenceError::ResourceLimit("interpreter fuel"))?;
        Ok(())
    }
}

fn next_byte_boundary(position: usize, length: usize) -> Option<usize> {
    (position < length)
        .then(|| position.checked_add(1))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(ast: Ast) -> ReferenceRegex {
        ReferenceRegex::new(ast, Limits::default()).unwrap()
    }

    const fn span(start: usize, end: usize) -> Span {
        Span { start, end }
    }

    #[test]
    fn literal_search_uses_smallest_start() {
        let regex = reference(Ast::Concat(vec![Ast::Byte(b'a'), Ast::Byte(b'b')]));
        let found = regex.find_at(b"zzab", 0).unwrap().unwrap();
        assert_eq!(found.span, Span { start: 2, end: 4 });
    }

    #[test]
    fn alternation_preserves_declaration_priority() {
        let regex = reference(Ast::Alt(vec![
            Ast::Byte(b'a'),
            Ast::Concat(vec![Ast::Byte(b'a'), Ast::Byte(b'b')]),
        ]));
        assert_eq!(
            regex.find_at(b"ab", 0).unwrap().unwrap().span,
            Span { start: 0, end: 1 }
        );
    }

    #[test]
    fn greedy_and_lazy_repeat_have_distinct_ends() {
        let greedy = reference(Ast::Repeat {
            child: Box::new(Ast::Byte(b'a')),
            min: 0,
            max: None,
            greed: Greed::Greedy,
        });
        let lazy = reference(Ast::Repeat {
            child: Box::new(Ast::Byte(b'a')),
            min: 0,
            max: None,
            greed: Greed::Lazy,
        });
        assert_eq!(greedy.find_at(b"aaa", 0).unwrap().unwrap().span.end, 3);
        assert_eq!(lazy.find_at(b"aaa", 0).unwrap().unwrap().span.end, 0);
    }

    #[test]
    fn absent_later_iteration_does_not_clear_capture() {
        // (a|(b))+ on "ba" => [0,2), [1,2), [0,1).
        let regex = reference(Ast::Repeat {
            child: Box::new(Ast::Capture {
                index: 1,
                child: Box::new(Ast::Alt(vec![
                    Ast::Byte(b'a'),
                    Ast::Capture {
                        index: 2,
                        child: Box::new(Ast::Byte(b'b')),
                    },
                ])),
            }),
            min: 1,
            max: None,
            greed: Greed::Greedy,
        });
        let found = regex.find_at(b"ba", 0).unwrap().unwrap();
        assert_eq!(
            found.captures,
            vec![Some(span(0, 2)), Some(span(1, 2)), Some(span(0, 1))]
        );
    }

    #[test]
    fn unmatched_and_participating_empty_are_distinct() {
        let optional_a = Ast::Repeat {
            child: Box::new(Ast::Capture {
                index: 1,
                child: Box::new(Ast::Byte(b'a')),
            }),
            min: 0,
            max: Some(1),
            greed: Greed::Greedy,
        };
        let empty_b = Ast::Capture {
            index: 2,
            child: Box::new(Ast::Repeat {
                child: Box::new(Ast::Byte(b'b')),
                min: 0,
                max: None,
                greed: Greed::Greedy,
            }),
        };
        let found = reference(Ast::Concat(vec![optional_a, empty_b]))
            .find_at(b"", 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            found.captures,
            vec![Some(span(0, 0)), None, Some(span(0, 0))]
        );
    }

    #[test]
    fn nullable_unbounded_repeat_terminates() {
        let regex = reference(Ast::Repeat {
            child: Box::new(Ast::Empty),
            min: 0,
            max: None,
            greed: Greed::Greedy,
        });
        assert_eq!(
            regex.find_at(b"x", 0).unwrap().unwrap().span,
            Span { start: 0, end: 0 }
        );
    }

    #[test]
    fn rust_adjacent_empty_suppression_is_operation_level() {
        let regex = reference(Ast::Alt(vec![Ast::Byte(b'a'), Ast::Empty]));
        let matches = regex.find_all_rust_reference(b"a").unwrap();
        assert_eq!(
            matches.iter().map(|item| item.span).collect::<Vec<_>>(),
            vec![Span { start: 0, end: 1 }]
        );
    }

    #[test]
    fn ranged_search_keeps_original_anchor_context() {
        let regex = reference(Ast::Concat(vec![Ast::StartText, Ast::Byte(b'a')]));
        assert_eq!(regex.find_at(b"za", 1).unwrap(), None);
    }

    #[test]
    fn fuel_and_depth_are_checked() {
        let low_fuel = Limits {
            max_steps: 1,
            ..Limits::default()
        };
        let regex = ReferenceRegex::new(Ast::Byte(b'z'), low_fuel).unwrap();
        assert_eq!(
            regex.find_at(b"aaaaaaaa", 0),
            Err(ReferenceError::ResourceLimit("interpreter fuel"))
        );

        let deep = Ast::Concat(vec![Ast::Concat(vec![Ast::Byte(b'a')])]);
        let shallow_limit = Limits {
            max_ast_depth: 1,
            ..Limits::default()
        };
        assert!(matches!(
            ReferenceRegex::new(deep, shallow_limit),
            Err(ReferenceError::ResourceLimit("AST depth"))
        ));
    }
}
