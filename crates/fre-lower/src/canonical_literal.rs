//! Allocation-free exact-byte-sequence analysis for canonical HIR.

use core::fmt;

use regex_syntax::hir::{Hir, HirKind};

/// Semantic algorithm identity for canonical exact-literal analysis.
///
/// Version 1 admits capture-erased `Empty`, `Literal`, `Concat`, and exact
/// `Repetition` structure while declining every contextual or multi-language
/// node that survives canonicalization.
pub const CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION: u32 = 1;

/// Exact work-accounting identity for canonical exact-literal analysis.
///
/// Version 1 charges one visit per structurally analyzed node, one visit per
/// expanded materialization node, and one unit per copied literal byte.
pub const CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION: u32 = 1;

/// Hard recursion ceiling for canonical exact-literal analysis and copying.
///
/// This equals the default strict `fre-syntax` nesting quota. A canonical HIR
/// admitted by a custom, deeper syntax profile is still valid, but this
/// recursive helper reports a typed [`CanonicalExactLiteralResource::Nesting`]
/// limit instead of classifying it. Such a caller can retain its general
/// semantic route or use a future iterative classifier.
pub const CANONICAL_EXACT_LITERAL_MAX_NESTING: usize = 250;

/// Stable semantic and accounting identity carried by every exact-literal proof.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalExactLiteralIdentity {
    algorithm_version: u32,
    accounting_version: u32,
}

impl CanonicalExactLiteralIdentity {
    /// Current identity implemented by this crate.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            algorithm_version: CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION,
            accounting_version: CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION,
        }
    }

    /// Semantic algorithm version.
    #[must_use]
    pub const fn algorithm_version(self) -> u32 {
        self.algorithm_version
    }

    /// Exact work-accounting version.
    #[must_use]
    pub const fn accounting_version(self) -> u32 {
        self.accounting_version
    }

    /// Whether this is the exact identity implemented by this build.
    #[must_use]
    pub const fn authenticates_current(self) -> bool {
        self.algorithm_version == CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION
            && self.accounting_version == CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION
    }
}

/// Resource limits for one canonical exact-literal analysis and materialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalExactLiteralLimits {
    /// Maximum distinct canonical HIR nodes inspected during analysis.
    pub max_hir_nodes: usize,
    /// Maximum inspected HIR nesting, including the root at depth one.
    ///
    /// Values above [`CANONICAL_EXACT_LITERAL_MAX_NESTING`] do not raise the
    /// helper's hard recursion ceiling.
    pub max_nesting: usize,
    /// Maximum bytes in the single expanded literal.
    pub max_literal_bytes: usize,
    /// Maximum total charged work for analysis plus one materialization.
    pub max_work: u64,
}

impl Default for CanonicalExactLiteralLimits {
    fn default() -> Self {
        Self {
            max_hir_nodes: 1_000_000,
            max_nesting: CANONICAL_EXACT_LITERAL_MAX_NESTING,
            max_literal_bytes: 4 * 1_048_576,
            max_work: 8_000_000,
        }
    }
}

/// Bounded resource used by canonical exact-literal analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CanonicalExactLiteralResource {
    HirNodes,
    Nesting,
    LiteralBytes,
    Work,
}

impl fmt::Display for CanonicalExactLiteralResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::HirNodes => "HIR nodes",
            Self::Nesting => "HIR nesting",
            Self::LiteralBytes => "expanded literal bytes",
            Self::Work => "analysis and materialization work",
        };
        formatter.write_str(name)
    }
}

/// Hard failure while proving one canonical exact byte sequence.
///
/// `Ok(None)` from [`analyze_canonical_exact_literal`] is reserved for a
/// semantic shape that this deliberately narrow classifier does not prove.
/// Arithmetic and bounded-resource refusals remain distinguishable here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CanonicalExactLiteralError {
    ResourceLimit {
        resource: CanonicalExactLiteralResource,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for CanonicalExactLiteralError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "canonical exact literal needs {needed} {resource}, limit is {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "canonical exact-literal {computation} overflowed"
                )
            }
        }
    }
}

impl std::error::Error for CanonicalExactLiteralError {}

/// Exact closed dimensions for one canonical exact byte sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalExactLiteralStats {
    identity: CanonicalExactLiteralIdentity,
    hir_nodes: usize,
    max_nesting: usize,
    literal_bytes: usize,
    expanded_hir_visits: u64,
    analysis_work: u64,
    materialization_work: u64,
    total_work: u64,
}

impl CanonicalExactLiteralStats {
    /// Stable semantic and exact-accounting identity for this proof.
    #[must_use]
    pub const fn identity(self) -> CanonicalExactLiteralIdentity {
        self.identity
    }

    /// Distinct canonical HIR nodes inspected once during analysis.
    #[must_use]
    pub const fn hir_nodes(self) -> usize {
        self.hir_nodes
    }

    /// Maximum inspected nesting, including the root at depth one.
    #[must_use]
    pub const fn max_nesting(self) -> usize {
        self.max_nesting
    }

    /// Bytes in the exact expanded sequence.
    #[must_use]
    pub const fn literal_bytes(self) -> usize {
        self.literal_bytes
    }

    /// HIR-node visits performed by one materialization after exact
    /// repetitions are expanded.
    #[must_use]
    pub const fn expanded_hir_visits(self) -> u64 {
        self.expanded_hir_visits
    }

    /// Work charged while structurally proving the sequence.
    #[must_use]
    pub const fn analysis_work(self) -> u64 {
        self.analysis_work
    }

    /// Work charged for one materialization: expanded HIR visits plus bytes
    /// copied into the caller's destination.
    #[must_use]
    pub const fn materialization_work(self) -> u64 {
        self.materialization_work
    }

    /// Analysis plus one materialization work.
    #[must_use]
    pub const fn total_work(self) -> u64 {
        self.total_work
    }
}

/// Borrowed proof that a canonical HIR consumes one exact byte sequence.
///
/// The proof erases capture annotations and admits only `Empty`, `Literal`,
/// `Capture`, `Concat`, and fixed-count `Repetition` nodes. It does not infer a
/// finite language, inspect source spelling, or prove any parser profile,
/// search iteration, match-kind, assertion, or capture-output contract.
/// Callers using this for Rust-byte leftmost-first matching must authenticate
/// those independent conditions themselves.
#[derive(Clone, Copy, Debug)]
pub struct CanonicalExactLiteral<'hir> {
    hir: &'hir Hir,
    stats: CanonicalExactLiteralStats,
}

impl CanonicalExactLiteral<'_> {
    /// Stable semantic and exact-accounting identity for this proof.
    #[must_use]
    pub const fn identity(&self) -> CanonicalExactLiteralIdentity {
        self.stats.identity
    }

    /// Exact number of bytes required by [`Self::copy_into`].
    #[must_use]
    pub const fn literal_len(&self) -> usize {
        self.stats.literal_bytes
    }

    /// Closed analysis and one-copy dimensions.
    #[must_use]
    pub const fn stats(&self) -> CanonicalExactLiteralStats {
        self.stats
    }

    /// Copy the exact sequence into caller-owned storage without allocation.
    ///
    /// Destination length is checked before the first write. All HIR shape,
    /// arithmetic, recursion, expanded-repetition, byte, and work validation
    /// closed when this proof was constructed. The remaining traversal and
    /// indexing are therefore infallible private invariants over the same
    /// immutable borrowed HIR.
    ///
    /// # Errors
    ///
    /// Returns a destination-length error before mutation unless `destination`
    /// has exactly [`Self::literal_len`] bytes.
    pub fn copy_into(&self, destination: &mut [u8]) -> Result<(), CanonicalExactLiteralCopyError> {
        if destination.len() != self.stats.literal_bytes {
            return Err(CanonicalExactLiteralCopyError::DestinationLength {
                needed: self.stats.literal_bytes,
                actual: destination.len(),
            });
        }
        let mut offset = 0_usize;
        copy_node(self.hir, destination, &mut offset);
        debug_assert_eq!(offset, destination.len());
        Ok(())
    }
}

/// Failure before a proved exact sequence starts writing to caller storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CanonicalExactLiteralCopyError {
    DestinationLength { needed: usize, actual: usize },
}

impl fmt::Display for CanonicalExactLiteralCopyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationLength { needed, actual } => write!(
                formatter,
                "canonical exact literal needs a {needed}-byte destination, got {actual} bytes"
            ),
        }
    }
}

impl std::error::Error for CanonicalExactLiteralCopyError {}

/// Prove that one canonical HIR consumes exactly one byte sequence.
///
/// Capture wrappers are erased at any depth. Concatenations are joined in
/// source order and fixed-count repetitions are expanded with checked
/// arithmetic. A remaining class, assertion, alternation, or variable-count
/// repetition returns `Ok(None)` even when some broader analysis could prove a
/// singleton language. In particular, singleton classes are admitted only
/// when the pinned canonical HIR constructor has already normalized them to a
/// `Literal`.
///
/// This function and the returned proof allocate no heap storage. The helper
/// uses bounded recursion; its effective nesting limit is the smaller of the
/// caller limit and [`CANONICAL_EXACT_LITERAL_MAX_NESTING`]. Exceeding that
/// ceiling is a typed resource error, not semantic ineligibility.
///
/// # Errors
///
/// Returns [`CanonicalExactLiteralError`] on checked arithmetic overflow or
/// when analysis plus one materialization exceeds a supplied or hard limit.
pub fn analyze_canonical_exact_literal(
    hir: &Hir,
    limits: CanonicalExactLiteralLimits,
) -> Result<Option<CanonicalExactLiteral<'_>>, CanonicalExactLiteralError> {
    let mut analyzer = Analyzer::new(limits);
    let Some(projection) = analyzer.visit(hir, 1)? else {
        return Ok(None);
    };
    let literal_bytes = u64::try_from(projection.literal_bytes).map_err(|_| {
        CanonicalExactLiteralError::ArithmeticOverflow {
            computation: "literal-byte work conversion",
        }
    })?;
    let materialization_work = projection
        .expanded_hir_visits
        .checked_add(literal_bytes)
        .ok_or(CanonicalExactLiteralError::ArithmeticOverflow {
            computation: "materialization work",
        })?;
    let analysis_work = u64::try_from(analyzer.hir_nodes).map_err(|_| {
        CanonicalExactLiteralError::ArithmeticOverflow {
            computation: "analysis work conversion",
        }
    })?;
    let total_work = analysis_work.checked_add(materialization_work).ok_or(
        CanonicalExactLiteralError::ArithmeticOverflow {
            computation: "total work",
        },
    )?;
    check_u64(
        CanonicalExactLiteralResource::Work,
        total_work,
        limits.max_work,
    )?;
    Ok(Some(CanonicalExactLiteral {
        hir,
        stats: CanonicalExactLiteralStats {
            identity: CanonicalExactLiteralIdentity::current(),
            hir_nodes: analyzer.hir_nodes,
            max_nesting: analyzer.max_nesting,
            literal_bytes: projection.literal_bytes,
            expanded_hir_visits: projection.expanded_hir_visits,
            analysis_work,
            materialization_work,
            total_work,
        },
    }))
}

#[derive(Clone, Copy)]
struct Projection {
    literal_bytes: usize,
    expanded_hir_visits: u64,
}

struct Analyzer {
    limits: CanonicalExactLiteralLimits,
    effective_nesting_limit: usize,
    hir_nodes: usize,
    max_nesting: usize,
}

impl Analyzer {
    fn new(limits: CanonicalExactLiteralLimits) -> Self {
        Self {
            limits,
            effective_nesting_limit: limits.max_nesting.min(CANONICAL_EXACT_LITERAL_MAX_NESTING),
            hir_nodes: 0,
            max_nesting: 0,
        }
    }

    fn visit(
        &mut self,
        hir: &Hir,
        depth: usize,
    ) -> Result<Option<Projection>, CanonicalExactLiteralError> {
        self.charge_node(depth)?;
        match hir.kind() {
            HirKind::Empty => Ok(Some(Projection {
                literal_bytes: 0,
                expanded_hir_visits: 1,
            })),
            HirKind::Literal(literal) => {
                self.check_literal_bytes(literal.0.len())?;
                Ok(Some(Projection {
                    literal_bytes: literal.0.len(),
                    expanded_hir_visits: 1,
                }))
            }
            HirKind::Capture(capture) => {
                let Some(child) = self.visit_child(&capture.sub, depth)? else {
                    return Ok(None);
                };
                let expanded_hir_visits = child.expanded_hir_visits.checked_add(1).ok_or(
                    CanonicalExactLiteralError::ArithmeticOverflow {
                        computation: "capture materialization visits",
                    },
                )?;
                Ok(Some(Projection {
                    literal_bytes: child.literal_bytes,
                    expanded_hir_visits,
                }))
            }
            HirKind::Concat(parts) => {
                let mut literal_bytes = 0_usize;
                let mut expanded_hir_visits = 1_u64;
                for part in parts {
                    let Some(child) = self.visit_child(part, depth)? else {
                        return Ok(None);
                    };
                    literal_bytes = literal_bytes.checked_add(child.literal_bytes).ok_or(
                        CanonicalExactLiteralError::ArithmeticOverflow {
                            computation: "concatenated literal bytes",
                        },
                    )?;
                    self.check_literal_bytes(literal_bytes)?;
                    expanded_hir_visits = expanded_hir_visits
                        .checked_add(child.expanded_hir_visits)
                        .ok_or(CanonicalExactLiteralError::ArithmeticOverflow {
                            computation: "concatenated materialization visits",
                        })?;
                }
                Ok(Some(Projection {
                    literal_bytes,
                    expanded_hir_visits,
                }))
            }
            HirKind::Repetition(repetition) => {
                let Some(count) = repetition.max.filter(|&maximum| maximum == repetition.min)
                else {
                    return Ok(None);
                };
                if count == 0 {
                    return Ok(Some(Projection {
                        literal_bytes: 0,
                        expanded_hir_visits: 1,
                    }));
                }
                let Some(child) = self.visit_child(&repetition.sub, depth)? else {
                    return Ok(None);
                };
                let count_usize = usize::try_from(count).map_err(|_| {
                    CanonicalExactLiteralError::ArithmeticOverflow {
                        computation: "repetition count conversion",
                    }
                })?;
                let literal_bytes = child.literal_bytes.checked_mul(count_usize).ok_or(
                    CanonicalExactLiteralError::ArithmeticOverflow {
                        computation: "repeated literal bytes",
                    },
                )?;
                self.check_literal_bytes(literal_bytes)?;
                let expanded_hir_visits = child
                    .expanded_hir_visits
                    .checked_mul(u64::from(count))
                    .and_then(|visits| visits.checked_add(1))
                    .ok_or(CanonicalExactLiteralError::ArithmeticOverflow {
                        computation: "repeated materialization visits",
                    })?;
                Ok(Some(Projection {
                    literal_bytes,
                    expanded_hir_visits,
                }))
            }
            HirKind::Class(_) | HirKind::Look(_) | HirKind::Alternation(_) => Ok(None),
        }
    }

    fn visit_child(
        &mut self,
        child: &Hir,
        parent_depth: usize,
    ) -> Result<Option<Projection>, CanonicalExactLiteralError> {
        let depth =
            parent_depth
                .checked_add(1)
                .ok_or(CanonicalExactLiteralError::ArithmeticOverflow {
                    computation: "HIR nesting",
                })?;
        self.visit(child, depth)
    }

    fn charge_node(&mut self, depth: usize) -> Result<(), CanonicalExactLiteralError> {
        check_usize(
            CanonicalExactLiteralResource::Nesting,
            depth,
            self.effective_nesting_limit,
        )?;
        self.max_nesting = self.max_nesting.max(depth);
        self.hir_nodes = self.hir_nodes.checked_add(1).ok_or(
            CanonicalExactLiteralError::ArithmeticOverflow {
                computation: "HIR node count",
            },
        )?;
        check_usize(
            CanonicalExactLiteralResource::HirNodes,
            self.hir_nodes,
            self.limits.max_hir_nodes,
        )?;
        check_u64(
            CanonicalExactLiteralResource::Work,
            u64::try_from(self.hir_nodes).map_err(|_| {
                CanonicalExactLiteralError::ArithmeticOverflow {
                    computation: "analysis work conversion",
                }
            })?,
            self.limits.max_work,
        )
    }

    fn check_literal_bytes(&self, needed: usize) -> Result<(), CanonicalExactLiteralError> {
        check_usize(
            CanonicalExactLiteralResource::LiteralBytes,
            needed,
            self.limits.max_literal_bytes,
        )
    }
}

fn copy_node(hir: &Hir, destination: &mut [u8], offset: &mut usize) {
    match hir.kind() {
        HirKind::Empty => {}
        HirKind::Literal(literal) => {
            let end = offset
                .checked_add(literal.0.len())
                .expect("proved canonical exact-literal offset");
            destination[*offset..end].copy_from_slice(&literal.0);
            *offset = end;
        }
        HirKind::Capture(capture) => copy_node(&capture.sub, destination, offset),
        HirKind::Concat(parts) => {
            for part in parts {
                copy_node(part, destination, offset);
            }
        }
        HirKind::Repetition(repetition) => {
            for _ in 0..repetition.min {
                copy_node(&repetition.sub, destination, offset);
            }
        }
        HirKind::Class(_) | HirKind::Look(_) | HirKind::Alternation(_) => {
            unreachable!("proved canonical exact literal changed shape")
        }
    }
}

fn check_usize(
    resource: CanonicalExactLiteralResource,
    needed: usize,
    limit: usize,
) -> Result<(), CanonicalExactLiteralError> {
    if needed <= limit {
        return Ok(());
    }
    let needed =
        u64::try_from(needed).map_err(|_| CanonicalExactLiteralError::ArithmeticOverflow {
            computation: "resource-limit needed-value conversion",
        })?;
    let limit =
        u64::try_from(limit).map_err(|_| CanonicalExactLiteralError::ArithmeticOverflow {
            computation: "resource-limit bound conversion",
        })?;
    Err(CanonicalExactLiteralError::ResourceLimit {
        resource,
        needed,
        limit,
    })
}

fn check_u64(
    resource: CanonicalExactLiteralResource,
    needed: u64,
    limit: u64,
) -> Result<(), CanonicalExactLiteralError> {
    if needed <= limit {
        Ok(())
    } else {
        Err(CanonicalExactLiteralError::ResourceLimit {
            resource,
            needed,
            limit,
        })
    }
}
