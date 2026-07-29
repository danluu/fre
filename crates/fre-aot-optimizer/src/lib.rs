//! Deterministic, pattern-only recipe optimization for Count-v3 AOT.
//!
//! This crate selects a bounded target recipe from a sealed exact-literal
//! [`fre_kernel_ir::ExactAggregateProgram`]. It neither emits code nor observes
//! haystacks, corpus names, benchmark labels, profiles, timers, or host state.

#![forbid(unsafe_code)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::ExactVec;
use fre_kernel_ir::{
    AggregateProgramIdentity, Count, ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES,
};
use sha2::{Digest, Sha256};

/// Canonical recipe schema emitted by this optimizer.
pub const COUNT_V3_RECIPE_SCHEMA_VERSION: u16 = 3;
/// Version of the deterministic portfolio and cost model.
pub const COUNT_V3_OPTIMIZER_VERSION: u16 = 5;
/// Maximum number of filter columns in one recipe.
pub const COUNT_V3_MAX_FILTER_OFFSETS: usize = 4;
/// Maximum exact-literal width consumed by Count-v3.
pub const COUNT_V3_MAX_LITERAL_BYTES: usize = MAX_EXACT_AGGREGATE_LITERAL_BYTES;
/// Maximum number of literal confirmation groups.
pub const COUNT_V3_MAX_SPARSE_GROUP_BLOCKS: usize = 4;
/// Maximum pattern-derived column frontier explored exhaustively.
pub const COUNT_V3_MAX_COLUMN_FRONTIER: usize = 8;
/// Fixed canonical recipe encoding size.
pub const COUNT_V3_RECIPE_CANONICAL_BYTES: usize = 256;
/// Fixed canonical optimizer-receipt encoding size.
pub const COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES: usize = 192;
/// Hard maximum number of recipes in the exhaustive bounded portfolio.
pub const COUNT_V3_HARD_MAX_PORTFOLIO_RECIPES: usize = 192;
const _: () = assert!(1 + 28 + 56 + 70 + 1 + 1 + 1 + 1 <= COUNT_V3_HARD_MAX_PORTFOLIO_RECIPES);

const RECIPE_IDENTITY_DOMAIN: &[u8] = b"FRE-AOT-COUNT-V3-RECIPE\0\x03";
const RECEIPT_IDENTITY_DOMAIN: &[u8] = b"FRE-AOT-COUNT-V3-OPTIMIZER-RECEIPT\0\x01";
const LITERAL_IDENTITY_DOMAIN: &[u8] = b"FRE-AOT-COUNT-V3-LITERAL\0\x01";

/// Explicit target cost-model class. No host inference is performed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CountV3TuningClass {
    /// Balanced baseline model for a conforming AArch64 NEON target.
    GenericAarch64 = 1,
    /// Balanced model for Apple M-series cores.
    AppleMSeries = 2,
    /// Balanced model for Neoverse V2/V3-class cores.
    NeoverseV2V3 = 3,
}

impl CountV3TuningClass {
    /// Stable canonical numeric encoding.
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        self as u8
    }
}

/// Closed Count-v3 algorithm family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CountV3Strategy {
    /// Reviewed Count-v2-compatible scan/confirm structure.
    Incumbent = 1,
    /// Pattern-rare filter columns before full confirmation.
    SparseRareColumns = 2,
    /// Endpoint-first filter schedule for dense candidate streams.
    EndpointDense = 3,
    /// Period-aware run scanner followed by exact confirmation.
    PeriodicRun = 4,
    /// Every literal byte is a filter column and the literal cannot overlap
    /// itself, so equality lanes can be counted without candidate recovery.
    DirectExactMask = 5,
}

impl CountV3Strategy {
    /// Stable canonical numeric encoding.
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        self as u8
    }
}

/// Closed instruction schedule selected by a recipe.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CountV3ScheduleId {
    IncumbentV2 = 1,
    SparseColumnsV1 = 2,
    EndpointDenseV1 = 3,
    PeriodicRunV1 = 4,
    DirectExactMaskV1 = 5,
}

impl CountV3ScheduleId {
    /// Stable canonical numeric encoding.
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        self as u8
    }
}

/// Closed backend register-allocation contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CountV3RegisterPlanId {
    Aarch64NeonV1 = 1,
    Aarch64SveVl16V1 = 2,
    Aarch64Sve2Vl16V1 = 3,
}

impl CountV3RegisterPlanId {
    /// Stable canonical numeric encoding.
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        self as u8
    }
}

/// Minimum ISA required by this recipe.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CountV3RequiredIsa {
    /// Baseline AArch64 Advanced SIMD (NEON), 128-bit vectors.
    Aarch64Neon128 = 1,
    /// AArch64 SVE with the separately checked fixed VL=16-byte contract.
    Aarch64SveVl16 = 2,
    /// AArch64 SVE2 with the separately checked fixed VL=16-byte contract.
    Aarch64Sve2Vl16 = 3,
}

impl CountV3RequiredIsa {
    /// Stable canonical numeric encoding.
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        self as u8
    }
}

/// Successor semantics shared by every Count-v3 recipe.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CountV3SuccessorMode {
    NonOverlapping = 1,
}

impl CountV3SuccessorMode {
    /// Stable canonical numeric encoding.
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        self as u8
    }
}

/// One bounded contiguous literal-confirmation group.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CountV3SparseGroupBlock {
    first_offset: u8,
    len: u8,
}

impl CountV3SparseGroupBlock {
    /// First literal offset in this group.
    #[must_use]
    pub const fn first_offset(self) -> u8 {
        self.first_offset
    }

    /// Number of bytes in this group.
    #[must_use]
    pub const fn len(self) -> u8 {
        self.len
    }

    /// Whether this is the zero-filled inactive suffix entry.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Fixed integer model costs. Lower is better in every dimension.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CountV3CostVector {
    pub sparse: u32,
    pub dense: u32,
    pub false_positive: u32,
    pub matches: u32,
    pub tail: u32,
    pub code_size: u32,
}

impl CountV3CostVector {
    const fn components(self) -> [u32; 6] {
        [
            self.sparse,
            self.dense,
            self.false_positive,
            self.matches,
            self.tail,
            self.code_size,
        ]
    }
}

/// Pattern facts computed with a bounded KMP prefix pass.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct CountV3LiteralFacts {
    literal_bytes: u8,
    distinct_bytes: u8,
    minimum_period: u8,
    self_overlap_bytes: u8,
    rarest_multiplicity: u8,
    maximum_multiplicity: u8,
    full_period_repetitions: u8,
}

impl CountV3LiteralFacts {
    #[must_use]
    pub const fn literal_bytes(self) -> u8 {
        self.literal_bytes
    }
    #[must_use]
    pub const fn distinct_bytes(self) -> u8 {
        self.distinct_bytes
    }
    #[must_use]
    pub const fn minimum_period(self) -> u8 {
        self.minimum_period
    }
    #[must_use]
    pub const fn self_overlap_bytes(self) -> u8 {
        self.self_overlap_bytes
    }
    #[must_use]
    pub const fn rarest_multiplicity(self) -> u8 {
        self.rarest_multiplicity
    }
    #[must_use]
    pub const fn maximum_multiplicity(self) -> u8 {
        self.maximum_multiplicity
    }
    #[must_use]
    pub const fn full_period_repetitions(self) -> u8 {
        self.full_period_repetitions
    }
    #[must_use]
    pub const fn is_periodic(self) -> bool {
        self.minimum_period < self.literal_bytes
    }
}

/// Domain-separated identity of one complete selected recipe.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CountV3RecipeIdentity([u8; 32]);

impl CountV3RecipeIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CountV3RecipeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CountV3RecipeIdentity({self})")
    }
}

impl fmt::Display for CountV3RecipeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Sealed primitive recipe consumed by a Count-v3 emitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountRecipeV3 {
    program_identity: AggregateProgramIdentity,
    literal_identity: [u8; 32],
    tuning_class: CountV3TuningClass,
    strategy: CountV3Strategy,
    schedule_id: CountV3ScheduleId,
    register_plan_id: CountV3RegisterPlanId,
    required_isa: CountV3RequiredIsa,
    filter_offsets: [u8; COUNT_V3_MAX_FILTER_OFFSETS],
    filter_count: u8,
    confirmation_order: [u8; COUNT_V3_MAX_LITERAL_BYTES],
    confirmation_count: u8,
    sparse_group_blocks: [CountV3SparseGroupBlock; COUNT_V3_MAX_SPARSE_GROUP_BLOCKS],
    sparse_group_count: u8,
    match_stride: u8,
    periodic_stride: u8,
    costs: CountV3CostVector,
    identity: CountV3RecipeIdentity,
}

impl CountRecipeV3 {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        COUNT_V3_RECIPE_SCHEMA_VERSION
    }
    #[must_use]
    pub const fn optimizer_version(&self) -> u16 {
        COUNT_V3_OPTIMIZER_VERSION
    }
    #[must_use]
    pub const fn program_identity(&self) -> AggregateProgramIdentity {
        self.program_identity
    }
    #[must_use]
    pub const fn literal_identity(&self) -> &[u8; 32] {
        &self.literal_identity
    }
    #[must_use]
    pub const fn tuning_class(&self) -> CountV3TuningClass {
        self.tuning_class
    }
    #[must_use]
    pub const fn strategy(&self) -> CountV3Strategy {
        self.strategy
    }
    #[must_use]
    pub const fn schedule_id(&self) -> CountV3ScheduleId {
        self.schedule_id
    }
    #[must_use]
    pub const fn register_plan_id(&self) -> CountV3RegisterPlanId {
        self.register_plan_id
    }
    #[must_use]
    pub const fn required_isa(&self) -> CountV3RequiredIsa {
        self.required_isa
    }
    #[must_use]
    pub fn filter_offsets(&self) -> &[u8] {
        &self.filter_offsets[..usize::from(self.filter_count)]
    }
    #[must_use]
    pub fn confirmation_order(&self) -> &[u8] {
        &self.confirmation_order[..usize::from(self.confirmation_count)]
    }
    #[must_use]
    pub fn sparse_group_blocks(&self) -> &[CountV3SparseGroupBlock] {
        &self.sparse_group_blocks[..usize::from(self.sparse_group_count)]
    }
    #[must_use]
    pub const fn successor_mode(&self) -> CountV3SuccessorMode {
        CountV3SuccessorMode::NonOverlapping
    }
    #[must_use]
    pub const fn mismatch_stride(&self) -> u8 {
        1
    }
    #[must_use]
    pub const fn match_stride(&self) -> u8 {
        self.match_stride
    }
    #[must_use]
    pub const fn periodic_stride(&self) -> u8 {
        self.periodic_stride
    }
    #[must_use]
    pub const fn costs(&self) -> CountV3CostVector {
        self.costs
    }
    #[must_use]
    pub const fn identity(&self) -> CountV3RecipeIdentity {
        self.identity
    }
}

/// Versioned finite optimizer limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountV3OptimizerLimits {
    pub max_literal_bytes: usize,
    pub max_candidate_columns: usize,
    pub max_portfolio_recipes: usize,
    pub max_analysis_work: u64,
    pub max_scratch_bytes: usize,
    pub max_allocation_requests: u8,
    pub max_retained_bytes: usize,
    pub max_identity_bytes_hashed: u64,
}

impl Default for CountV3OptimizerLimits {
    fn default() -> Self {
        Self {
            max_literal_bytes: COUNT_V3_MAX_LITERAL_BYTES,
            max_candidate_columns: COUNT_V3_MAX_LITERAL_BYTES,
            max_portfolio_recipes: COUNT_V3_HARD_MAX_PORTFOLIO_RECIPES,
            max_analysis_work: 2_000_000,
            max_scratch_bytes: 256 * 1024,
            max_allocation_requests: 1,
            max_retained_bytes: 256 * 1024,
            max_identity_bytes_hashed: 4096,
        }
    }
}

/// Exact actual resource accounting for a successful optimization.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountV3OptimizerResources {
    pub literal_bytes: usize,
    pub candidate_columns: usize,
    pub portfolio_recipes: usize,
    pub pareto_recipes: usize,
    pub analysis_work: u64,
    pub scratch_bytes: usize,
    pub allocation_requests: u8,
    pub retained_bytes: usize,
    pub identity_bytes_hashed: u64,
}

/// Domain-separated identity of a complete optimizer receipt.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CountV3OptimizerReceiptIdentity([u8; 32]);

impl CountV3OptimizerReceiptIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CountV3OptimizerReceiptIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CountV3OptimizerReceiptIdentity({self})")
    }
}

impl fmt::Display for CountV3OptimizerReceiptIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Closed receipt for one deterministic selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountV3OptimizerReceipt {
    program_identity: AggregateProgramIdentity,
    recipe_identity: CountV3RecipeIdentity,
    tuning_class: CountV3TuningClass,
    resources: CountV3OptimizerResources,
    chosen_ordinal: u16,
    minimax_regret: u64,
    identity: CountV3OptimizerReceiptIdentity,
}

impl CountV3OptimizerReceipt {
    #[must_use]
    pub const fn program_identity(&self) -> AggregateProgramIdentity {
        self.program_identity
    }
    #[must_use]
    pub const fn recipe_identity(&self) -> CountV3RecipeIdentity {
        self.recipe_identity
    }
    #[must_use]
    pub const fn tuning_class(&self) -> CountV3TuningClass {
        self.tuning_class
    }
    #[must_use]
    pub const fn resources(&self) -> CountV3OptimizerResources {
        self.resources
    }
    #[must_use]
    pub const fn chosen_ordinal(&self) -> u16 {
        self.chosen_ordinal
    }
    #[must_use]
    pub const fn minimax_regret(&self) -> u64 {
        self.minimax_regret
    }
    #[must_use]
    pub const fn identity(&self) -> CountV3OptimizerReceiptIdentity {
        self.identity
    }
    /// Recompute the domain-separated identity over every receipt field.
    #[must_use]
    pub fn authenticates(&self) -> bool {
        self.identity == receipt_identity(self)
    }
}

/// Allocation-free strict projection of one canonical optimizer receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectedCountV3OptimizerReceipt {
    program_identity: [u8; 32],
    recipe_identity: CountV3RecipeIdentity,
    tuning_class: CountV3TuningClass,
    resources: CountV3OptimizerResources,
    chosen_ordinal: u16,
    minimax_regret: u64,
    identity: CountV3OptimizerReceiptIdentity,
}

impl InspectedCountV3OptimizerReceipt {
    #[must_use]
    pub const fn program_identity(&self) -> &[u8; 32] {
        &self.program_identity
    }

    #[must_use]
    pub const fn recipe_identity(&self) -> CountV3RecipeIdentity {
        self.recipe_identity
    }

    #[must_use]
    pub const fn tuning_class(&self) -> CountV3TuningClass {
        self.tuning_class
    }

    #[must_use]
    pub const fn resources(&self) -> CountV3OptimizerResources {
        self.resources
    }

    #[must_use]
    pub const fn chosen_ordinal(&self) -> u16 {
        self.chosen_ordinal
    }

    #[must_use]
    pub const fn minimax_regret(&self) -> u64 {
        self.minimax_regret
    }

    #[must_use]
    pub const fn identity(&self) -> CountV3OptimizerReceiptIdentity {
        self.identity
    }
}

/// A canonical optimizer receipt was malformed, noncanonical, or internally
/// inconsistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountV3OptimizerReceiptDecodeError {
    Magic,
    SchemaVersion,
    OptimizerVersion,
    UnknownTuningClass(u8),
    NonCanonicalPadding,
    InvalidIdentity,
    InvalidResources,
    ReceiptIdentity,
    HostWidth,
}

impl fmt::Display for CountV3OptimizerReceiptDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CountV3OptimizerReceiptDecodeError {}

/// Complete source-only optimizer output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptimizedCountV3 {
    facts: CountV3LiteralFacts,
    recipe: CountRecipeV3,
    receipt: CountV3OptimizerReceipt,
}

impl OptimizedCountV3 {
    #[must_use]
    pub const fn facts(&self) -> CountV3LiteralFacts {
        self.facts
    }
    #[must_use]
    pub const fn recipe(&self) -> &CountRecipeV3 {
        &self.recipe
    }
    #[must_use]
    pub const fn receipt(&self) -> &CountV3OptimizerReceipt {
        &self.receipt
    }
}

/// One exact optimizer-limit refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountV3OptimizeError {
    LiteralBytes { limit: usize, required: usize },
    CandidateColumns { limit: usize, required: usize },
    PortfolioRecipes { limit: usize, required: usize },
    AnalysisWork { limit: u64, required: u64 },
    ScratchBytes { limit: usize, required: usize },
    AllocationRequests { limit: u8, required: u8 },
    RetainedBytes { limit: usize, required: usize },
    IdentityBytesHashed { limit: u64, required: u64 },
    PortfolioAllocationFailed { requested_bytes: usize },
    ArithmeticOverflow { at: &'static str },
    InvalidGeneratedRecipe,
}

impl fmt::Display for CountV3OptimizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CountV3OptimizeError {}

/// Independent structural validation error for an untrusted recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountV3RecipeValidationError {
    ProgramIdentity,
    LiteralIdentity,
    StrategySchedule,
    RegisterPlan,
    RequiredIsa,
    FilterOffsets,
    ConfirmationOrder,
    SparseGroups,
    Strides,
    CostVector,
    RecipeIdentity,
}

impl fmt::Display for CountV3RecipeValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CountV3RecipeValidationError {}

/// Strict canonical recipe decoding error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountV3RecipeDecodeError {
    Magic,
    SchemaVersion,
    OptimizerVersion,
    UnknownTuningClass(u8),
    UnknownStrategy(u8),
    UnknownSchedule(u8),
    UnknownRegisterPlan(u8),
    UnknownRequiredIsa(u8),
    UnknownSuccessorMode(u8),
    InvalidCounts,
    InvalidPrimitiveManifest,
    NonCanonicalPadding,
    RecipeIdentity,
    ProgramIdentity,
    Validation(CountV3RecipeValidationError),
}

impl fmt::Display for CountV3RecipeDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CountV3RecipeDecodeError {}

/// Allocation-free, KIR-independent inspection of canonical recipe bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectedCountRecipeV3 {
    program_identity: [u8; 32],
    literal_identity: [u8; 32],
    tuning_class: CountV3TuningClass,
    strategy: CountV3Strategy,
    schedule_id: CountV3ScheduleId,
    register_plan_id: CountV3RegisterPlanId,
    required_isa: CountV3RequiredIsa,
    filter_offsets: [u8; COUNT_V3_MAX_FILTER_OFFSETS],
    filter_count: u8,
    confirmation_order: [u8; COUNT_V3_MAX_LITERAL_BYTES],
    confirmation_count: u8,
    sparse_group_blocks: [CountV3SparseGroupBlock; COUNT_V3_MAX_SPARSE_GROUP_BLOCKS],
    sparse_group_count: u8,
    match_stride: u8,
    periodic_stride: u8,
    costs: CountV3CostVector,
    identity: CountV3RecipeIdentity,
}

impl InspectedCountRecipeV3 {
    #[must_use]
    pub const fn program_identity(&self) -> &[u8; 32] {
        &self.program_identity
    }
    #[must_use]
    pub const fn literal_identity(&self) -> &[u8; 32] {
        &self.literal_identity
    }
    #[must_use]
    pub const fn tuning_class(&self) -> CountV3TuningClass {
        self.tuning_class
    }
    #[must_use]
    pub const fn strategy(&self) -> CountV3Strategy {
        self.strategy
    }
    #[must_use]
    pub const fn schedule_id(&self) -> CountV3ScheduleId {
        self.schedule_id
    }
    #[must_use]
    pub const fn register_plan_id(&self) -> CountV3RegisterPlanId {
        self.register_plan_id
    }
    #[must_use]
    pub const fn required_isa(&self) -> CountV3RequiredIsa {
        self.required_isa
    }
    #[must_use]
    pub fn filter_offsets(&self) -> &[u8] {
        &self.filter_offsets[..usize::from(self.filter_count)]
    }
    #[must_use]
    pub fn confirmation_order(&self) -> &[u8] {
        &self.confirmation_order[..usize::from(self.confirmation_count)]
    }
    #[must_use]
    pub fn sparse_group_blocks(&self) -> &[CountV3SparseGroupBlock] {
        &self.sparse_group_blocks[..usize::from(self.sparse_group_count)]
    }
    #[must_use]
    pub const fn match_stride(&self) -> u8 {
        self.match_stride
    }
    #[must_use]
    pub const fn periodic_stride(&self) -> u8 {
        self.periodic_stride
    }
    #[must_use]
    pub const fn costs(&self) -> CountV3CostVector {
        self.costs
    }
    #[must_use]
    pub const fn identity(&self) -> CountV3RecipeIdentity {
        self.identity
    }
}

/// Optimize one sealed exact-literal Count program.
///
/// The implementation below is completed in the same source checkpoint; this
/// declaration is kept at the public boundary consumed by emitters.
pub fn optimize_count_v3(
    program: &ExactAggregateProgram<Count>,
    tuning: CountV3TuningClass,
    limits: CountV3OptimizerLimits,
) -> Result<OptimizedCountV3, CountV3OptimizeError> {
    optimize_count_v3_for_isa(program, tuning, CountV3RequiredIsa::Aarch64Neon128, limits)
}

/// Optimize one sealed exact-literal Count program for an explicit ISA plan.
///
/// The target is selected before recipe materialization and therefore
/// participates in the authenticated recipe identity. Backends never patch a
/// sealed Neon recipe into an SVE recipe after optimization.
pub fn optimize_count_v3_for_isa(
    program: &ExactAggregateProgram<Count>,
    tuning: CountV3TuningClass,
    required_isa: CountV3RequiredIsa,
    limits: CountV3OptimizerLimits,
) -> Result<OptimizedCountV3, CountV3OptimizeError> {
    optimize_impl(program, tuning, required_isa, limits)
}

/// Domain-separated identity used by every Count-v3 optimizer recipe.
///
/// This intentionally differs from the plain SHA-256 literal digest used by
/// source and facade expectation contracts.
#[must_use]
pub fn compute_count_v3_literal_identity(literal: &[u8]) -> [u8; 32] {
    literal_identity(literal)
}

/// Canonical fixed-size encoding used to independently bind a recipe.
#[must_use]
pub fn encode_count_recipe_v3(recipe: &CountRecipeV3) -> [u8; COUNT_V3_RECIPE_CANONICAL_BYTES] {
    encode_recipe(recipe, false)
}

/// Canonical fixed-size encoding of a complete optimizer receipt.
#[must_use]
pub fn encode_count_v3_optimizer_receipt(
    receipt: &CountV3OptimizerReceipt,
) -> [u8; COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES] {
    encode_receipt(receipt, false)
}

/// Strictly inspect a fixed canonical optimizer receipt without allocating or
/// trusting a compiler claim.
pub fn inspect_count_v3_optimizer_receipt(
    bytes: &[u8; COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES],
) -> Result<InspectedCountV3OptimizerReceipt, CountV3OptimizerReceiptDecodeError> {
    inspect_optimizer_receipt(bytes)
}

/// Recompute all pattern-derived recipe invariants and the sealed identity.
pub fn validate_count_recipe_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
) -> Result<(), CountV3RecipeValidationError> {
    validate_recipe(program, recipe)
}

/// Inspect canonical bytes without allocating or trusting a semantic program.
pub fn inspect_count_recipe_v3(
    bytes: &[u8; COUNT_V3_RECIPE_CANONICAL_BYTES],
) -> Result<InspectedCountRecipeV3, CountV3RecipeDecodeError> {
    inspect_recipe(bytes)
}

/// Strictly decode canonical bytes and independently revalidate them against KIR.
pub fn decode_count_recipe_v3(
    program: &ExactAggregateProgram<Count>,
    bytes: &[u8; COUNT_V3_RECIPE_CANONICAL_BYTES],
) -> Result<CountRecipeV3, CountV3RecipeDecodeError> {
    let inspected = inspect_recipe(bytes)?;
    if inspected.program_identity != *program.cache_identity().as_bytes() {
        return Err(CountV3RecipeDecodeError::ProgramIdentity);
    }
    let recipe = CountRecipeV3 {
        program_identity: program.cache_identity(),
        literal_identity: inspected.literal_identity,
        tuning_class: inspected.tuning_class,
        strategy: inspected.strategy,
        schedule_id: inspected.schedule_id,
        register_plan_id: inspected.register_plan_id,
        required_isa: inspected.required_isa,
        filter_offsets: inspected.filter_offsets,
        filter_count: inspected.filter_count,
        confirmation_order: inspected.confirmation_order,
        confirmation_count: inspected.confirmation_count,
        sparse_group_blocks: inspected.sparse_group_blocks,
        sparse_group_count: inspected.sparse_group_count,
        match_stride: inspected.match_stride,
        periodic_stride: inspected.periodic_stride,
        costs: inspected.costs,
        identity: inspected.identity,
    };
    validate_recipe(program, &recipe).map_err(CountV3RecipeDecodeError::Validation)?;
    if encode_recipe(&recipe, false) != *bytes {
        return Err(CountV3RecipeDecodeError::NonCanonicalPadding);
    }
    Ok(recipe)
}

// The deterministic optimizer implementation follows in this module.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Candidate {
    strategy: CountV3Strategy,
    schedule: CountV3ScheduleId,
    filters: [u8; COUNT_V3_MAX_FILTER_OFFSETS],
    filter_count: u8,
    periodic_stride: u8,
    costs: CountV3CostVector,
    ordinal: u16,
    pareto: bool,
}

fn optimize_impl(
    program: &ExactAggregateProgram<Count>,
    tuning: CountV3TuningClass,
    required_isa: CountV3RequiredIsa,
    limits: CountV3OptimizerLimits,
) -> Result<OptimizedCountV3, CountV3OptimizeError> {
    let literal = program.literal();
    require_usize(
        literal.len(),
        limits.max_literal_bytes.min(COUNT_V3_MAX_LITERAL_BYTES),
        |limit, required| CountV3OptimizeError::LiteralBytes { limit, required },
    )?;
    require_usize(
        literal.len(),
        limits.max_candidate_columns.min(COUNT_V3_MAX_LITERAL_BYTES),
        |limit, required| CountV3OptimizeError::CandidateColumns { limit, required },
    )?;

    let mut work = Work::default();
    let analysis = analyze_literal(literal, &mut work)?;
    let frontier = build_column_frontier(literal, &analysis, &mut work)?;
    let portfolio_recipes = count_portfolio(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        &frontier,
        &mut work,
    )?;
    require_usize(
        portfolio_recipes,
        limits
            .max_portfolio_recipes
            .min(COUNT_V3_HARD_MAX_PORTFOLIO_RECIPES),
        |limit, required| CountV3OptimizeError::PortfolioRecipes { limit, required },
    )?;

    let scratch_request_bytes = portfolio_recipes
        .checked_mul(size_of::<Candidate>())
        .ok_or(CountV3OptimizeError::ArithmeticOverflow {
            at: "portfolio scratch bytes",
        })?;
    require_usize(
        scratch_request_bytes,
        limits.max_scratch_bytes,
        |limit, required| CountV3OptimizeError::ScratchBytes { limit, required },
    )?;
    let allocation_requests = u8::from(portfolio_recipes != 0);
    if allocation_requests > limits.max_allocation_requests {
        return Err(CountV3OptimizeError::AllocationRequests {
            limit: limits.max_allocation_requests,
            required: allocation_requests,
        });
    }
    let retained_bytes = size_of::<OptimizedCountV3>();
    require_usize(
        retained_bytes,
        limits.max_retained_bytes,
        |limit, required| CountV3OptimizeError::RetainedBytes { limit, required },
    )?;
    let identity_bytes_hashed = identity_bytes_hashed(literal.len())?;
    if identity_bytes_hashed > limits.max_identity_bytes_hashed {
        return Err(CountV3OptimizeError::IdentityBytesHashed {
            limit: limits.max_identity_bytes_hashed,
            required: identity_bytes_hashed,
        });
    }

    let mut candidates = build_portfolio(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        &frontier,
        required_isa,
        portfolio_recipes,
        &mut work,
    )?;
    let scratch_bytes = candidates
        .capacity()
        .checked_mul(size_of::<Candidate>())
        .ok_or(CountV3OptimizeError::ArithmeticOverflow {
            at: "observed portfolio scratch bytes",
        })?;
    require_usize(
        scratch_bytes,
        limits.max_scratch_bytes,
        |limit, required| CountV3OptimizeError::ScratchBytes { limit, required },
    )?;
    mark_pareto(&mut candidates, &mut work)?;
    let pareto_recipes = candidates
        .iter()
        .filter(|candidate| candidate.pareto)
        .count();
    let (selected_index, minimax_regret) = select_candidate(&candidates, tuning, &mut work)?;
    let selected = candidates[selected_index];
    work.add(materialization_work(literal.len(), selected.filter_count)?)?;
    if work.0 > limits.max_analysis_work {
        return Err(CountV3OptimizeError::AnalysisWork {
            limit: limits.max_analysis_work,
            required: work.0,
        });
    }

    let literal_identity = literal_identity(literal);
    let mut recipe = materialize_recipe(
        program.cache_identity(),
        literal_identity,
        tuning,
        required_isa,
        selected,
        literal,
        &analysis.multiplicity,
    )?;
    recipe.identity = recipe_identity(&recipe);

    let resources = CountV3OptimizerResources {
        literal_bytes: literal.len(),
        candidate_columns: literal.len(),
        portfolio_recipes,
        pareto_recipes,
        analysis_work: work.0,
        scratch_bytes,
        allocation_requests,
        retained_bytes,
        identity_bytes_hashed,
    };
    let mut receipt = CountV3OptimizerReceipt {
        program_identity: program.cache_identity(),
        recipe_identity: recipe.identity,
        tuning_class: tuning,
        resources,
        chosen_ordinal: selected.ordinal,
        minimax_regret,
        identity: CountV3OptimizerReceiptIdentity([0; 32]),
    };
    receipt.identity = receipt_identity(&receipt);
    Ok(OptimizedCountV3 {
        facts: analysis.facts,
        recipe,
        receipt,
    })
}

fn materialization_work(
    literal_bytes: usize,
    filter_count: u8,
) -> Result<u64, CountV3OptimizeError> {
    let confirmation_visits = literal_bytes.checked_mul(literal_bytes).ok_or(
        CountV3OptimizeError::ArithmeticOverflow {
            at: "confirmation scheduling work",
        },
    )?;
    let groups = literal_bytes.div_ceil(8);
    let total = 20_usize
        .checked_add(usize::from(filter_count))
        .and_then(|value| value.checked_add(confirmation_visits))
        .and_then(|value| value.checked_add(groups))
        .ok_or(CountV3OptimizeError::ArithmeticOverflow {
            at: "recipe materialization work",
        })?;
    u64::try_from(total).map_err(|_| CountV3OptimizeError::ArithmeticOverflow {
        at: "recipe materialization work as u64",
    })
}

#[derive(Clone, Copy, Debug)]
struct LiteralAnalysis {
    facts: CountV3LiteralFacts,
    multiplicity: [u8; 256],
}

#[derive(Clone, Copy, Debug, Default)]
struct Work(u64);

impl Work {
    fn add(&mut self, amount: u64) -> Result<(), CountV3OptimizeError> {
        self.0 = self
            .0
            .checked_add(amount)
            .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                at: "optimizer analysis work",
            })?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct ColumnFrontier {
    offsets: [u8; COUNT_V3_MAX_COLUMN_FRONTIER],
    len: u8,
}

impl ColumnFrontier {
    fn as_slice(&self) -> &[u8] {
        &self.offsets[..usize::from(self.len)]
    }
}

fn require_usize(
    required: usize,
    limit: usize,
    error: impl FnOnce(usize, usize) -> CountV3OptimizeError,
) -> Result<(), CountV3OptimizeError> {
    if required > limit {
        Err(error(limit, required))
    } else {
        Ok(())
    }
}

fn analyze_literal(
    literal: &[u8],
    work: &mut Work,
) -> Result<LiteralAnalysis, CountV3OptimizeError> {
    let mut multiplicity = [0_u8; 256];
    for byte in literal {
        work.add(1)?;
        let slot = &mut multiplicity[usize::from(*byte)];
        *slot = slot
            .checked_add(1)
            .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                at: "literal byte multiplicity",
            })?;
    }
    let mut distinct = 0_u8;
    let mut rarest = u8::MAX;
    let mut maximum = 0_u8;
    for count in multiplicity {
        work.add(1)?;
        if count != 0 {
            distinct = distinct
                .checked_add(1)
                .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                    at: "distinct literal bytes",
                })?;
            rarest = rarest.min(count);
            maximum = maximum.max(count);
        }
    }
    if literal.is_empty() {
        rarest = 0;
    }

    let mut prefix = [0_usize; COUNT_V3_MAX_LITERAL_BYTES];
    for index in 1..literal.len() {
        work.add(1)?;
        let mut border = prefix[index - 1];
        while border != 0 && literal[index] != literal[border] {
            work.add(1)?;
            border = prefix[border - 1];
        }
        work.add(1)?;
        if literal[index] == literal[border] {
            border = border
                .checked_add(1)
                .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                    at: "KMP prefix length",
                })?;
        }
        prefix[index] = border;
    }
    let self_overlap = literal.last().map_or(0, |_| prefix[literal.len() - 1]);
    let minimum_period = if literal.is_empty() {
        0
    } else {
        literal
            .len()
            .checked_sub(self_overlap)
            .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                at: "KMP minimum period",
            })?
    };
    let full_period_repetitions = if minimum_period != 0 && literal.len() % minimum_period == 0 {
        literal.len() / minimum_period
    } else if literal.is_empty() {
        0
    } else {
        1
    };
    Ok(LiteralAnalysis {
        facts: CountV3LiteralFacts {
            literal_bytes: to_u8(literal.len(), "literal width")?,
            distinct_bytes: distinct,
            minimum_period: to_u8(minimum_period, "minimum period")?,
            self_overlap_bytes: to_u8(self_overlap, "self overlap")?,
            rarest_multiplicity: rarest,
            maximum_multiplicity: maximum,
            full_period_repetitions: to_u8(full_period_repetitions, "full period repetitions")?,
        },
        multiplicity,
    })
}

fn build_column_frontier(
    literal: &[u8],
    analysis: &LiteralAnalysis,
    work: &mut Work,
) -> Result<ColumnFrontier, CountV3OptimizeError> {
    let mut ranked = [0_u8; COUNT_V3_MAX_LITERAL_BYTES];
    let mut ranked_len = 0_usize;
    for offset in 0..literal.len() {
        work.add(1)?;
        let offset_u8 = to_u8(offset, "ranked column offset")?;
        let mut insertion = ranked_len;
        while insertion != 0 {
            work.add(1)?;
            let previous = ranked[insertion - 1];
            if column_rank(literal, &analysis.multiplicity, offset_u8)
                >= column_rank(literal, &analysis.multiplicity, previous)
            {
                break;
            }
            ranked[insertion] = previous;
            insertion -= 1;
        }
        ranked[insertion] = offset_u8;
        ranked_len += 1;
    }

    let mut frontier = ColumnFrontier {
        offsets: [0; COUNT_V3_MAX_COLUMN_FRONTIER],
        len: 0,
    };
    if !literal.is_empty() {
        push_frontier(&mut frontier, 0);
        push_frontier(
            &mut frontier,
            to_u8(literal.len() - 1, "last column offset")?,
        );
    }
    let period = usize::from(analysis.facts.minimum_period);
    if period != 0 && period < literal.len() {
        push_frontier(&mut frontier, to_u8(period - 1, "period residue")?);
        push_frontier(&mut frontier, to_u8(period, "period successor")?);
    }
    for offset in &ranked[..ranked_len] {
        work.add(1)?;
        push_frontier(&mut frontier, *offset);
    }
    Ok(frontier)
}

fn push_frontier(frontier: &mut ColumnFrontier, offset: u8) {
    if frontier.as_slice().contains(&offset)
        || usize::from(frontier.len) == COUNT_V3_MAX_COLUMN_FRONTIER
    {
        return;
    }
    frontier.offsets[usize::from(frontier.len)] = offset;
    frontier.len += 1;
}

fn column_rank(literal: &[u8], multiplicity: &[u8; 256], offset: u8) -> (u32, u8, u8) {
    let byte = literal[usize::from(offset)];
    let prevalence = u32::from(BYTE_PREVALENCE_WEIGHT[usize::from(byte)]);
    let repeats = u32::from(multiplicity[usize::from(byte)]);
    (
        prevalence.saturating_mul(repeats),
        multiplicity[usize::from(byte)],
        offset,
    )
}

fn count_portfolio(
    literal: &[u8],
    facts: CountV3LiteralFacts,
    multiplicity: &[u8; 256],
    frontier: &ColumnFrontier,
    work: &mut Work,
) -> Result<usize, CountV3OptimizeError> {
    let mut count = 1_usize;
    for width in 2..=COUNT_V3_MAX_FILTER_OFFSETS {
        visit_combinations(frontier.as_slice(), width, |filters| {
            work.add(1)?;
            if distinct_filter_bytes(literal, filters) {
                count = count
                    .checked_add(1)
                    .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                        at: "portfolio recipe count",
                    })?;
            }
            Ok(())
        })?;
    }
    if literal.len() >= 2 {
        count = count
            .checked_add(1)
            .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                at: "endpoint portfolio count",
            })?;
        if endpoint_rare_offset(literal, frontier).is_some() {
            count = count
                .checked_add(1)
                .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                    at: "endpoint rare portfolio count",
                })?;
        }
    }
    if usize::from(facts.minimum_period) < literal.len() {
        let (_, filter_count) = periodic_filters(literal, facts, multiplicity)?;
        count = count.checked_add(filter_count.saturating_sub(1)).ok_or(
            CountV3OptimizeError::ArithmeticOverflow {
                at: "periodic portfolio count",
            },
        )?;
    }
    if direct_exact_mask_filters(literal, facts).is_some() {
        count = count
            .checked_add(1)
            .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                at: "direct exact-mask portfolio count",
            })?;
    }
    Ok(count)
}

fn visit_combinations(
    frontier: &[u8],
    width: usize,
    mut visit: impl FnMut(&[u8]) -> Result<(), CountV3OptimizeError>,
) -> Result<(), CountV3OptimizeError> {
    let mut chosen = [0_u8; COUNT_V3_MAX_FILTER_OFFSETS];
    fn recurse(
        frontier: &[u8],
        width: usize,
        start: usize,
        depth: usize,
        chosen: &mut [u8; COUNT_V3_MAX_FILTER_OFFSETS],
        visit: &mut impl FnMut(&[u8]) -> Result<(), CountV3OptimizeError>,
    ) -> Result<(), CountV3OptimizeError> {
        if depth == width {
            return visit(&chosen[..width]);
        }
        let remaining = width - depth;
        let Some(last_start) = frontier.len().checked_sub(remaining) else {
            return Ok(());
        };
        for index in start..=last_start {
            chosen[depth] = frontier[index];
            recurse(frontier, width, index + 1, depth + 1, chosen, visit)?;
        }
        Ok(())
    }
    recurse(frontier, width, 0, 0, &mut chosen, &mut visit)
}

fn distinct_filter_bytes(literal: &[u8], filters: &[u8]) -> bool {
    for (index, left) in filters.iter().enumerate() {
        for right in &filters[index + 1..] {
            if literal[usize::from(*left)] == literal[usize::from(*right)] {
                return false;
            }
        }
    }
    true
}

fn endpoint_rare_offset(literal: &[u8], frontier: &ColumnFrontier) -> Option<u8> {
    let last = literal.len().checked_sub(1)?;
    frontier.as_slice().iter().copied().find(|offset| {
        let offset = usize::from(*offset);
        offset != 0
            && offset != last
            && literal[offset] != literal[0]
            && literal[offset] != literal[last]
    })
}

fn build_portfolio(
    literal: &[u8],
    facts: CountV3LiteralFacts,
    multiplicity: &[u8; 256],
    frontier: &ColumnFrontier,
    required_isa: CountV3RequiredIsa,
    expected_count: usize,
    work: &mut Work,
) -> Result<ExactVec<Candidate>, CountV3OptimizeError> {
    let requested_bytes = expected_count.checked_mul(size_of::<Candidate>()).ok_or(
        CountV3OptimizeError::ArithmeticOverflow {
            at: "portfolio exact allocation bytes",
        },
    )?;
    let mut candidates = ExactVec::try_with_capacity(expected_count)
        .map_err(|_| CountV3OptimizeError::PortfolioAllocationFailed { requested_bytes })?;
    let incumbent_filters = incumbent_filters(literal)?;
    push_candidate(
        &mut candidates,
        literal,
        facts,
        multiplicity,
        required_isa,
        CountV3Strategy::Incumbent,
        CountV3ScheduleId::IncumbentV2,
        &incumbent_filters.0[..incumbent_filters.1],
        0,
        work,
    )?;
    for width in 2..=COUNT_V3_MAX_FILTER_OFFSETS {
        visit_combinations(frontier.as_slice(), width, |filters| {
            if distinct_filter_bytes(literal, filters) {
                push_candidate(
                    &mut candidates,
                    literal,
                    facts,
                    multiplicity,
                    required_isa,
                    CountV3Strategy::SparseRareColumns,
                    CountV3ScheduleId::SparseColumnsV1,
                    filters,
                    0,
                    work,
                )?;
            }
            Ok(())
        })?;
    }
    if literal.len() >= 2 {
        let endpoints = ranked_endpoint_pair(literal, multiplicity);
        push_candidate(
            &mut candidates,
            literal,
            facts,
            multiplicity,
            required_isa,
            CountV3Strategy::EndpointDense,
            CountV3ScheduleId::EndpointDenseV1,
            &endpoints,
            0,
            work,
        )?;
        if let Some(rare) = endpoint_rare_offset(literal, frontier) {
            let filters = [endpoints[0], endpoints[1], rare];
            push_candidate(
                &mut candidates,
                literal,
                facts,
                multiplicity,
                required_isa,
                CountV3Strategy::EndpointDense,
                CountV3ScheduleId::EndpointDenseV1,
                &filters,
                0,
                work,
            )?;
        }
    }
    if usize::from(facts.minimum_period) < literal.len() {
        let (filters, filter_count) = periodic_filters(literal, facts, multiplicity)?;
        for selected_filter_count in 2..=filter_count {
            push_candidate(
                &mut candidates,
                literal,
                facts,
                multiplicity,
                required_isa,
                CountV3Strategy::PeriodicRun,
                CountV3ScheduleId::PeriodicRunV1,
                &filters[..selected_filter_count],
                facts.minimum_period,
                work,
            )?;
        }
    }
    if let Some((filters, filter_count)) = direct_exact_mask_filters(literal, facts) {
        push_candidate(
            &mut candidates,
            literal,
            facts,
            multiplicity,
            required_isa,
            CountV3Strategy::DirectExactMask,
            CountV3ScheduleId::DirectExactMaskV1,
            &filters[..filter_count],
            0,
            work,
        )?;
    }
    if candidates.len() != expected_count {
        return Err(CountV3OptimizeError::InvalidGeneratedRecipe);
    }
    Ok(candidates)
}

#[allow(clippy::too_many_arguments)]
fn push_candidate(
    candidates: &mut ExactVec<Candidate>,
    literal: &[u8],
    facts: CountV3LiteralFacts,
    multiplicity: &[u8; 256],
    required_isa: CountV3RequiredIsa,
    strategy: CountV3Strategy,
    schedule: CountV3ScheduleId,
    filters: &[u8],
    periodic_stride: u8,
    work: &mut Work,
) -> Result<(), CountV3OptimizeError> {
    work.add(1)?;
    let mut filter_offsets = [0_u8; COUNT_V3_MAX_FILTER_OFFSETS];
    filter_offsets[..filters.len()].copy_from_slice(filters);
    canonicalize_filter_order(
        literal,
        multiplicity,
        strategy,
        &mut filter_offsets[..filters.len()],
    );
    let costs = estimate_costs(
        literal,
        facts,
        multiplicity,
        required_isa,
        strategy,
        &filter_offsets[..filters.len()],
    )?;
    work.add(6)?;
    candidates
        .try_push(Candidate {
            strategy,
            schedule,
            filters: filter_offsets,
            filter_count: to_u8(filters.len(), "candidate filter count")?,
            periodic_stride,
            costs,
            ordinal: u16::try_from(candidates.len()).map_err(|_| {
                CountV3OptimizeError::ArithmeticOverflow {
                    at: "candidate ordinal",
                }
            })?,
            pareto: true,
        })
        .map_err(|_| CountV3OptimizeError::InvalidGeneratedRecipe)?;
    Ok(())
}

fn incumbent_filters(
    literal: &[u8],
) -> Result<([u8; COUNT_V3_MAX_FILTER_OFFSETS], usize), CountV3OptimizeError> {
    let mut filters = [0_u8; COUNT_V3_MAX_FILTER_OFFSETS];
    let count = match literal.len() {
        0 | 1 => 0,
        width => {
            filters[1] = to_u8(width - 1, "incumbent last filter")?;
            2
        }
    };
    Ok((filters, count))
}

fn direct_exact_mask_filters(
    literal: &[u8],
    facts: CountV3LiteralFacts,
) -> Option<([u8; COUNT_V3_MAX_FILTER_OFFSETS], usize)> {
    let width = literal.len();
    if !(2..=COUNT_V3_MAX_FILTER_OFFSETS).contains(&width)
        || usize::from(facts.minimum_period) != width
    {
        return None;
    }
    let mut filters = [0_u8; COUNT_V3_MAX_FILTER_OFFSETS];
    for (offset, slot) in filters[..width].iter_mut().enumerate() {
        *slot = u8::try_from(offset).ok()?;
    }
    Some((filters, width))
}

/// Order filter columns by deterministic pattern-only selectivity.
///
/// Sparse and periodic schedules have no semantic column order, so their
/// primary is the byte with the lowest static prevalence multiplied by its
/// literal multiplicity. EndpointDense deliberately retains endpoints in the
/// first two positions; `ranked_endpoint_pair` orders only those endpoints.
fn canonicalize_filter_order(
    literal: &[u8],
    multiplicity: &[u8; 256],
    strategy: CountV3Strategy,
    filters: &mut [u8],
) {
    if !matches!(
        strategy,
        CountV3Strategy::SparseRareColumns | CountV3Strategy::PeriodicRun
    ) {
        return;
    }
    for insertion in 1..filters.len() {
        let key = filters[insertion];
        let key_rank = column_rank(literal, multiplicity, key);
        let mut cursor = insertion;
        while cursor != 0 && key_rank < column_rank(literal, multiplicity, filters[cursor - 1]) {
            filters[cursor] = filters[cursor - 1];
            cursor -= 1;
        }
        filters[cursor] = key;
    }
}

fn ranked_endpoint_pair(literal: &[u8], multiplicity: &[u8; 256]) -> [u8; 2] {
    let last = u8::try_from(literal.len() - 1).expect("Count-v3 endpoint width is bounded");
    let mut endpoints = [0, last];
    if column_rank(literal, multiplicity, last) < column_rank(literal, multiplicity, 0) {
        endpoints.swap(0, 1);
    }
    endpoints
}

fn periodic_filters(
    literal: &[u8],
    facts: CountV3LiteralFacts,
    multiplicity: &[u8; 256],
) -> Result<([u8; COUNT_V3_MAX_FILTER_OFFSETS], usize), CountV3OptimizeError> {
    let mut filters = [0_u8; COUNT_V3_MAX_FILTER_OFFSETS];
    let mut count = 0_usize;
    for candidate in [
        facts.minimum_period.saturating_sub(1),
        0,
        to_u8(literal.len() - 1, "periodic last filter")?,
        facts.minimum_period,
    ] {
        if usize::from(candidate) < literal.len() && !filters[..count].contains(&candidate) {
            filters[count] = candidate;
            count += 1;
        }
    }
    canonicalize_filter_order(
        literal,
        multiplicity,
        CountV3Strategy::PeriodicRun,
        &mut filters[..count],
    );
    Ok((filters, count))
}

fn estimate_costs(
    literal: &[u8],
    facts: CountV3LiteralFacts,
    multiplicity: &[u8; 256],
    required_isa: CountV3RequiredIsa,
    strategy: CountV3Strategy,
    filters: &[u8],
) -> Result<CountV3CostVector, CountV3OptimizeError> {
    let width = to_u32(literal.len(), "cost literal width")?;
    let filter_count = to_u32(filters.len(), "cost filter count")?;
    let mut discrimination = 0_u32;
    let mut primary_discrimination = 0_u32;
    for (index, offset) in filters.iter().copied().enumerate() {
        let byte = literal[usize::from(offset)];
        let denominator = u32::from(BYTE_PREVALENCE_WEIGHT[usize::from(byte)])
            .checked_add(u32::from(multiplicity[usize::from(byte)]).saturating_mul(12))
            .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                at: "filter discrimination denominator",
            })?;
        let column_discrimination = 4096 / denominator.max(1);
        discrimination = discrimination.checked_add(column_discrimination).ok_or(
            CountV3OptimizeError::ArithmeticOverflow {
                at: "filter discrimination",
            },
        )?;
        if index == 0 {
            primary_discrimination = column_discrimination;
        }
    }
    let maximum = u32::from(facts.maximum_multiplicity);
    let period = u32::from(facts.minimum_period);
    let overlap = u32::from(facts.self_overlap_bytes);
    let vector = match strategy {
        CountV3Strategy::Incumbent => CountV3CostVector {
            sparse: 1150 + width * 2,
            dense: 1050 + width * 5 + maximum * 8,
            false_positive: 1250 + width * 8,
            matches: 850 + width * 9,
            tail: 350 + width * 3,
            code_size: 320 + width * 4,
        },
        CountV3Strategy::SparseRareColumns => CountV3CostVector {
            sparse: (1180_u32
                .saturating_sub(discrimination.saturating_mul(2))
                .saturating_sub(primary_discrimination.saturating_mul(2)))
            .max(180)
                + width * 2
                + filter_count * 18,
            dense: (1320_u32.saturating_sub(discrimination)).max(260)
                + width * 6
                + filter_count * 25,
            false_positive: (1500_u32
                .saturating_sub(discrimination.saturating_mul(2))
                .saturating_sub(primary_discrimination))
            .max(160)
                + width * 4,
            matches: 930 + width * 10 + filter_count * 24,
            tail: 390 + width * 3 + filter_count * 15,
            code_size: 430 + width * 7 + filter_count * 44,
        },
        CountV3Strategy::EndpointDense => CountV3CostVector {
            sparse: (720_u32
                .saturating_sub(discrimination / 2)
                .saturating_sub(primary_discrimination / 2))
            .max(220)
                + width * 3,
            dense: (900_u32.saturating_sub(discrimination / 2)).max(260) + width * 4 + maximum * 4,
            false_positive: (1120_u32
                .saturating_sub(discrimination)
                .saturating_sub(primary_discrimination))
            .max(220)
                + width * 5,
            matches: 790 + width * 8 + filter_count * 18,
            tail: 290 + width * 2 + filter_count * 10,
            code_size: 410 + width * 6 + filter_count * 32,
        },
        CountV3Strategy::PeriodicRun => {
            let period_gain = overlap.saturating_mul(18);
            let additional_filters = filter_count.saturating_sub(2);
            CountV3CostVector {
                sparse: (520_u32
                    .saturating_sub(period_gain / 2)
                    .saturating_sub(primary_discrimination))
                .max(180)
                    + width * 3
                    + additional_filters * 6,
                dense: (760_u32.saturating_sub(period_gain)).max(180)
                    + period * 8
                    + additional_filters * 28,
                false_positive: (940_u32
                    .saturating_sub(period_gain)
                    .saturating_sub(primary_discrimination)
                    .saturating_sub(discrimination))
                .max(200)
                    + width * 3,
                matches: (650_u32.saturating_sub(period_gain / 2)).max(220)
                    + period * 10
                    + additional_filters * 12,
                tail: 360 + period * 4,
                code_size: 510 + width * 8 + period * 6 + filter_count * 32,
            }
        }
        CountV3Strategy::DirectExactMask => estimate_neon_direct_costs(width),
    };
    Ok(match required_isa {
        CountV3RequiredIsa::Aarch64Neon128 => vector,
        CountV3RequiredIsa::Aarch64SveVl16 => estimate_sve_costs(
            width,
            filter_count,
            discrimination,
            primary_discrimination,
            strategy,
            false,
        ),
        CountV3RequiredIsa::Aarch64Sve2Vl16 => estimate_sve_costs(
            width,
            filter_count,
            discrimination,
            primary_discrimination,
            strategy,
            true,
        ),
    })
}

/// Model the fixed-width exact-mask graph from emitted instruction structure.
///
/// Width two is the direct schedule's sweet spot: two vector equality columns
/// form a complete match mask without candidate recovery. Every additional
/// column is nevertheless loaded and compared in all four 16-start blocks,
/// even when the first byte is absent. A filtered recipe can instead amortize
/// one rare column over its 128-start primary-empty scan. The extra sparse
/// charge for widths three and four keeps that real tradeoff in the Pareto
/// portfolio; the pattern-only prevalence model decides whether it is useful.
fn estimate_neon_direct_costs(width: u32) -> CountV3CostVector {
    let additional_columns = width.saturating_sub(2);
    CountV3CostVector {
        sparse: 240 + width * 70 + additional_columns * 320,
        dense: 160 + width * 55,
        false_positive: 190 + width * 52,
        matches: 190 + width * 48,
        tail: 200 + width * 32,
        code_size: 300 + width * 56,
    }
}

/// Model the graph the SVE backend actually emits.
///
/// Unlike the NEON backend, every non-direct strategy currently shares one
/// predicate-filter/scalar-confirmation template and none has a periodic
/// successor run. Keeping this model independent of the strategy label
/// prevents a semantic tag from receiving performance credit for a graph that
/// is not present in the emitted code. SVE2's `MATCH` schedule is charged as a
/// more complex comparison than baseline `CMPEQ`; the bounded portfolio may
/// consequently choose fewer filter columns on that target.
fn estimate_sve_costs(
    width: u32,
    filter_count: u32,
    discrimination: u32,
    primary_discrimination: u32,
    strategy: CountV3Strategy,
    sve2_match: bool,
) -> CountV3CostVector {
    let match_compare_penalty = u32::from(sve2_match);
    if strategy == CountV3Strategy::DirectExactMask {
        let additional_columns = width.saturating_sub(2);
        return CountV3CostVector {
            sparse: 260 + width * (70 + match_compare_penalty * 12) + additional_columns * 320,
            dense: 190 + width * (60 + match_compare_penalty * 10),
            false_positive: 180 + width * (54 + match_compare_penalty * 8),
            matches: 190 + width * (48 + match_compare_penalty * 8),
            tail: 180 + width * 28,
            code_size: 320 + width * 36,
        };
    }

    let confirmation_bytes = width.saturating_sub(filter_count);
    let compare_penalty = filter_count * match_compare_penalty;
    CountV3CostVector {
        sparse: (700_u32.saturating_sub(primary_discrimination.saturating_mul(3))).max(180)
            + width
            + filter_count * 12
            + compare_penalty * 10,
        dense: (1100_u32.saturating_sub(discrimination)).max(260)
            + width * 10
            + filter_count * 55
            + compare_penalty * 18,
        false_positive: (1300_u32
            .saturating_sub(discrimination.saturating_mul(2))
            .saturating_sub(primary_discrimination))
        .max(180)
            + width * 8
            + compare_penalty * 8,
        matches: 760 + confirmation_bytes * 28 + filter_count * 20 + compare_penalty * 14,
        tail: 260 + width * 26,
        code_size: 360 + width * 12 + filter_count * 36,
    }
}

fn mark_pareto(candidates: &mut [Candidate], work: &mut Work) -> Result<(), CountV3OptimizeError> {
    for index in 0..candidates.len() {
        let mut dominated = false;
        for other in 0..candidates.len() {
            if index == other {
                continue;
            }
            work.add(6)?;
            if dominates(candidates[other].costs, candidates[index].costs) {
                dominated = true;
            }
        }
        candidates[index].pareto = !dominated;
    }
    Ok(())
}

fn dominates(left: CountV3CostVector, right: CountV3CostVector) -> bool {
    let left = left.components();
    let right = right.components();
    let mut all_no_worse = true;
    let mut one_better = false;
    for index in 0..left.len() {
        all_no_worse &= left[index] <= right[index];
        one_better |= left[index] < right[index];
    }
    all_no_worse && one_better
}

fn select_candidate(
    candidates: &[Candidate],
    tuning: CountV3TuningClass,
    work: &mut Work,
) -> Result<(usize, u64), CountV3OptimizeError> {
    let mut best_components = [u32::MAX; 6];
    for candidate in candidates.iter().filter(|candidate| candidate.pareto) {
        for (index, cost) in candidate.costs.components().into_iter().enumerate() {
            work.add(1)?;
            best_components[index] = best_components[index].min(cost);
        }
    }
    let weights = tuning_weights(tuning);
    let mut selected = None::<(usize, SelectionScore)>;
    for (index, candidate) in candidates.iter().enumerate() {
        if !candidate.pareto {
            continue;
        }
        let mut maximum_regret = 0_u64;
        let mut total_regret = 0_u64;
        for component in 0..6 {
            work.add(1)?;
            let difference = u64::from(
                candidate.costs.components()[component].saturating_sub(best_components[component]),
            );
            let normalized = difference
                .checked_mul(1024)
                .and_then(|value| value.checked_div(u64::from(best_components[component].max(1))))
                .and_then(|value| value.checked_mul(u64::from(weights[component])))
                .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                    at: "normalized minimax regret",
                })?;
            maximum_regret = maximum_regret.max(normalized);
            total_regret = total_regret.checked_add(normalized).ok_or(
                CountV3OptimizeError::ArithmeticOverflow {
                    at: "total normalized regret",
                },
            )?;
        }
        let score = SelectionScore {
            maximum_regret,
            total_regret,
            code_size: candidate.costs.code_size,
            strategy: candidate.strategy.wire_id(),
            filter_count: candidate.filter_count,
            filters: candidate.filters,
            ordinal: candidate.ordinal,
        };
        if selected
            .as_ref()
            .is_none_or(|(_, current)| score < *current)
        {
            selected = Some((index, score));
        }
    }
    selected
        .map(|(index, score)| (index, score.maximum_regret))
        .ok_or(CountV3OptimizeError::InvalidGeneratedRecipe)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SelectionScore {
    maximum_regret: u64,
    total_regret: u64,
    code_size: u32,
    strategy: u8,
    filter_count: u8,
    filters: [u8; COUNT_V3_MAX_FILTER_OFFSETS],
    ordinal: u16,
}

const fn tuning_weights(tuning: CountV3TuningClass) -> [u16; 6] {
    match tuning {
        CountV3TuningClass::GenericAarch64 => [8, 8, 7, 6, 3, 1],
        CountV3TuningClass::AppleMSeries => [9, 8, 8, 5, 2, 1],
        CountV3TuningClass::NeoverseV2V3 => [8, 9, 8, 6, 2, 1],
    }
}

fn materialize_recipe(
    program_identity: AggregateProgramIdentity,
    literal_identity: [u8; 32],
    tuning_class: CountV3TuningClass,
    required_isa: CountV3RequiredIsa,
    candidate: Candidate,
    literal: &[u8],
    multiplicity: &[u8; 256],
) -> Result<CountRecipeV3, CountV3OptimizeError> {
    let (confirmation_order, confirmation_count) = confirmation_order(
        literal,
        multiplicity,
        &candidate.filters[..usize::from(candidate.filter_count)],
    )?;
    let (sparse_group_blocks, sparse_group_count) = sparse_groups(literal.len())?;
    Ok(CountRecipeV3 {
        program_identity,
        literal_identity,
        tuning_class,
        strategy: candidate.strategy,
        schedule_id: candidate.schedule,
        register_plan_id: register_plan_for_isa(required_isa),
        required_isa,
        filter_offsets: candidate.filters,
        filter_count: candidate.filter_count,
        confirmation_order,
        confirmation_count,
        sparse_group_blocks,
        sparse_group_count,
        match_stride: to_u8(literal.len(), "recipe match stride")?,
        periodic_stride: candidate.periodic_stride,
        costs: candidate.costs,
        identity: CountV3RecipeIdentity([0; 32]),
    })
}

const fn register_plan_for_isa(required_isa: CountV3RequiredIsa) -> CountV3RegisterPlanId {
    match required_isa {
        CountV3RequiredIsa::Aarch64Neon128 => CountV3RegisterPlanId::Aarch64NeonV1,
        CountV3RequiredIsa::Aarch64SveVl16 => CountV3RegisterPlanId::Aarch64SveVl16V1,
        CountV3RequiredIsa::Aarch64Sve2Vl16 => CountV3RegisterPlanId::Aarch64Sve2Vl16V1,
    }
}

fn confirmation_order(
    literal: &[u8],
    multiplicity: &[u8; 256],
    filters: &[u8],
) -> Result<([u8; COUNT_V3_MAX_LITERAL_BYTES], u8), CountV3OptimizeError> {
    let mut order = [0_u8; COUNT_V3_MAX_LITERAL_BYTES];
    let mut count = 0_usize;
    for filter in filters {
        if !order[..count].contains(filter) {
            order[count] = *filter;
            count += 1;
        }
    }
    for frequency in 1..=literal.len() {
        let frequency = to_u8(frequency, "confirmation frequency")?;
        for (offset, byte) in literal.iter().enumerate() {
            if multiplicity[usize::from(*byte)] == frequency {
                let offset = to_u8(offset, "confirmation offset")?;
                if !order[..count].contains(&offset) {
                    order[count] = offset;
                    count += 1;
                }
            }
        }
    }
    if count != literal.len() {
        return Err(CountV3OptimizeError::InvalidGeneratedRecipe);
    }
    Ok((order, to_u8(count, "confirmation count")?))
}

fn sparse_groups(
    width: usize,
) -> Result<
    (
        [CountV3SparseGroupBlock; COUNT_V3_MAX_SPARSE_GROUP_BLOCKS],
        u8,
    ),
    CountV3OptimizeError,
> {
    let mut groups = [CountV3SparseGroupBlock::default(); COUNT_V3_MAX_SPARSE_GROUP_BLOCKS];
    let mut first = 0_usize;
    let mut count = 0_usize;
    while first < width {
        let len = (width - first).min(8);
        groups[count] = CountV3SparseGroupBlock {
            first_offset: to_u8(first, "sparse group first")?,
            len: to_u8(len, "sparse group length")?,
        };
        first = first
            .checked_add(len)
            .ok_or(CountV3OptimizeError::ArithmeticOverflow {
                at: "sparse group successor",
            })?;
        count += 1;
    }
    Ok((groups, to_u8(count, "sparse group count")?))
}

fn identity_bytes_hashed(literal_bytes: usize) -> Result<u64, CountV3OptimizeError> {
    let total = LITERAL_IDENTITY_DOMAIN
        .len()
        .checked_add(literal_bytes)
        .and_then(|value| value.checked_add(RECIPE_IDENTITY_DOMAIN.len()))
        .and_then(|value| value.checked_add(COUNT_V3_RECIPE_CANONICAL_BYTES))
        .and_then(|value| value.checked_add(RECEIPT_IDENTITY_DOMAIN.len()))
        .and_then(|value| value.checked_add(COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES - 32))
        .ok_or(CountV3OptimizeError::ArithmeticOverflow {
            at: "identity bytes hashed",
        })?;
    u64::try_from(total).map_err(|_| CountV3OptimizeError::ArithmeticOverflow {
        at: "identity bytes hashed as u64",
    })
}

fn literal_identity(literal: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LITERAL_IDENTITY_DOMAIN);
    hasher.update(literal);
    hasher.finalize().into()
}

fn recipe_identity(recipe: &CountRecipeV3) -> CountV3RecipeIdentity {
    let mut hasher = Sha256::new();
    hasher.update(RECIPE_IDENTITY_DOMAIN);
    hasher.update(encode_recipe(recipe, true));
    CountV3RecipeIdentity(hasher.finalize().into())
}

fn receipt_identity(receipt: &CountV3OptimizerReceipt) -> CountV3OptimizerReceiptIdentity {
    let bytes = encode_receipt(receipt, true);
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_IDENTITY_DOMAIN);
    hasher.update(&bytes[..COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES - 32]);
    CountV3OptimizerReceiptIdentity(hasher.finalize().into())
}

fn encode_receipt(
    receipt: &CountV3OptimizerReceipt,
    zero_identity: bool,
) -> [u8; COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES] {
    let mut bytes = [0_u8; COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES];
    bytes[..8].copy_from_slice(b"FRECV3P\0");
    bytes[8..10].copy_from_slice(&COUNT_V3_RECIPE_SCHEMA_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&COUNT_V3_OPTIMIZER_VERSION.to_le_bytes());
    bytes[12] = receipt.tuning_class.wire_id();
    bytes[14..16].copy_from_slice(&receipt.chosen_ordinal.to_le_bytes());
    bytes[16..24].copy_from_slice(&receipt.minimax_regret.to_le_bytes());
    bytes[24..56].copy_from_slice(receipt.program_identity.as_bytes());
    bytes[56..88].copy_from_slice(receipt.recipe_identity.as_bytes());
    let values = [
        usize_to_u64(receipt.resources.literal_bytes),
        usize_to_u64(receipt.resources.candidate_columns),
        usize_to_u64(receipt.resources.portfolio_recipes),
        usize_to_u64(receipt.resources.pareto_recipes),
        receipt.resources.analysis_work,
        usize_to_u64(receipt.resources.scratch_bytes),
        u64::from(receipt.resources.allocation_requests),
        usize_to_u64(receipt.resources.retained_bytes),
        receipt.resources.identity_bytes_hashed,
    ];
    let mut cursor = 88;
    for value in values {
        bytes[cursor..cursor + 8].copy_from_slice(&value.to_le_bytes());
        cursor += 8;
    }
    debug_assert_eq!(cursor, COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES - 32);
    if !zero_identity {
        bytes[cursor..].copy_from_slice(receipt.identity.as_bytes());
    }
    bytes
}

fn inspect_optimizer_receipt(
    bytes: &[u8; COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES],
) -> Result<InspectedCountV3OptimizerReceipt, CountV3OptimizerReceiptDecodeError> {
    if &bytes[..8] != b"FRECV3P\0" {
        return Err(CountV3OptimizerReceiptDecodeError::Magic);
    }
    if read_u16(bytes, 8) != COUNT_V3_RECIPE_SCHEMA_VERSION {
        return Err(CountV3OptimizerReceiptDecodeError::SchemaVersion);
    }
    if read_u16(bytes, 10) != COUNT_V3_OPTIMIZER_VERSION {
        return Err(CountV3OptimizerReceiptDecodeError::OptimizerVersion);
    }
    let tuning_class = match bytes[12] {
        1 => CountV3TuningClass::GenericAarch64,
        2 => CountV3TuningClass::AppleMSeries,
        3 => CountV3TuningClass::NeoverseV2V3,
        value => {
            return Err(CountV3OptimizerReceiptDecodeError::UnknownTuningClass(
                value,
            ));
        }
    };
    if bytes[13] != 0 {
        return Err(CountV3OptimizerReceiptDecodeError::NonCanonicalPadding);
    }
    let chosen_ordinal = read_u16(bytes, 14);
    let minimax_regret = read_u64(bytes, 16);
    let program_identity: [u8; 32] = bytes[24..56]
        .try_into()
        .expect("fixed optimizer program identity");
    let recipe_identity_bytes: [u8; 32] = bytes[56..88]
        .try_into()
        .expect("fixed optimizer recipe identity");
    if program_identity == [0; 32] || recipe_identity_bytes == [0; 32] {
        return Err(CountV3OptimizerReceiptDecodeError::InvalidIdentity);
    }

    let literal_bytes = receipt_usize(read_u64(bytes, 88))?;
    let candidate_columns = receipt_usize(read_u64(bytes, 96))?;
    let portfolio_recipes = receipt_usize(read_u64(bytes, 104))?;
    let pareto_recipes = receipt_usize(read_u64(bytes, 112))?;
    let analysis_work = read_u64(bytes, 120);
    let scratch_bytes = receipt_usize(read_u64(bytes, 128))?;
    let allocation_requests = u8::try_from(read_u64(bytes, 136))
        .map_err(|_| CountV3OptimizerReceiptDecodeError::InvalidResources)?;
    let retained_bytes = receipt_usize(read_u64(bytes, 144))?;
    let claimed_identity_bytes_hashed = read_u64(bytes, 152);
    let expected_scratch = portfolio_recipes
        .checked_mul(size_of::<Candidate>())
        .ok_or(CountV3OptimizerReceiptDecodeError::InvalidResources)?;
    let expected_identity_bytes_hashed = identity_bytes_hashed(literal_bytes)
        .map_err(|_| CountV3OptimizerReceiptDecodeError::InvalidResources)?;
    if literal_bytes > COUNT_V3_MAX_LITERAL_BYTES
        || candidate_columns != literal_bytes
        || !(1..=COUNT_V3_HARD_MAX_PORTFOLIO_RECIPES).contains(&portfolio_recipes)
        || pareto_recipes == 0
        || pareto_recipes > portfolio_recipes
        || usize::from(chosen_ordinal) >= portfolio_recipes
        || analysis_work == 0
        || scratch_bytes != expected_scratch
        || allocation_requests != 1
        || retained_bytes != size_of::<OptimizedCountV3>()
        || claimed_identity_bytes_hashed != expected_identity_bytes_hashed
    {
        return Err(CountV3OptimizerReceiptDecodeError::InvalidResources);
    }
    let resources = CountV3OptimizerResources {
        literal_bytes,
        candidate_columns,
        portfolio_recipes,
        pareto_recipes,
        analysis_work,
        scratch_bytes,
        allocation_requests,
        retained_bytes,
        identity_bytes_hashed: claimed_identity_bytes_hashed,
    };

    let identity_bytes: [u8; 32] = bytes[160..192]
        .try_into()
        .expect("fixed optimizer receipt identity");
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_IDENTITY_DOMAIN);
    hasher.update(&bytes[..160]);
    let expected_identity: [u8; 32] = hasher.finalize().into();
    if identity_bytes != expected_identity {
        return Err(CountV3OptimizerReceiptDecodeError::ReceiptIdentity);
    }
    Ok(InspectedCountV3OptimizerReceipt {
        program_identity,
        recipe_identity: CountV3RecipeIdentity(recipe_identity_bytes),
        tuning_class,
        resources,
        chosen_ordinal,
        minimax_regret,
        identity: CountV3OptimizerReceiptIdentity(identity_bytes),
    })
}

fn receipt_usize(value: u64) -> Result<usize, CountV3OptimizerReceiptDecodeError> {
    usize::try_from(value).map_err(|_| CountV3OptimizerReceiptDecodeError::HostWidth)
}

const fn usize_to_u64(value: usize) -> u64 {
    value as u64
}

fn to_u8(value: usize, at: &'static str) -> Result<u8, CountV3OptimizeError> {
    u8::try_from(value).map_err(|_| CountV3OptimizeError::ArithmeticOverflow { at })
}

fn to_u32(value: usize, at: &'static str) -> Result<u32, CountV3OptimizeError> {
    u32::try_from(value).map_err(|_| CountV3OptimizeError::ArithmeticOverflow { at })
}

const BYTE_PREVALENCE_WEIGHT: [u16; 256] = build_byte_prevalence_weight();

const fn build_byte_prevalence_weight() -> [u16; 256] {
    // Coarse encoding classes only: no language- or benchmark-specific byte
    // frequencies. Literal multiplicity is the sole pattern-specific signal.
    let mut weights = [12_u16; 256];
    let mut byte = 0x80_usize;
    while byte <= 0xbf {
        weights[byte] = 14;
        byte += 1;
    }
    byte = 0xc2;
    while byte <= 0xf4 {
        weights[byte] = 28;
        byte += 1;
    }
    byte = 0x20;
    while byte <= 0x7e {
        weights[byte] = 22;
        byte += 1;
    }
    byte = b'0' as usize;
    while byte <= b'9' as usize {
        weights[byte] = 36;
        byte += 1;
    }
    byte = b'A' as usize;
    while byte <= b'Z' as usize {
        weights[byte] = 32;
        byte += 1;
    }
    byte = b'a' as usize;
    while byte <= b'z' as usize {
        weights[byte] = 40;
        byte += 1;
    }
    let mut whitespace = 0_usize;
    while whitespace < 4 {
        weights[[b' ', b'\n', b'\r', b'\t'][whitespace] as usize] = 96;
        whitespace += 1;
    }
    weights
}

fn encode_recipe(
    recipe: &CountRecipeV3,
    zero_identity: bool,
) -> [u8; COUNT_V3_RECIPE_CANONICAL_BYTES] {
    let mut bytes = [0_u8; COUNT_V3_RECIPE_CANONICAL_BYTES];
    bytes[..8].copy_from_slice(b"FRECV3R\0");
    bytes[8..10].copy_from_slice(&COUNT_V3_RECIPE_SCHEMA_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&COUNT_V3_OPTIMIZER_VERSION.to_le_bytes());
    bytes[12] = recipe.tuning_class.wire_id();
    bytes[13] = recipe.strategy.wire_id();
    bytes[14] = recipe.schedule_id.wire_id();
    bytes[15] = recipe.register_plan_id.wire_id();
    bytes[16] = recipe.required_isa.wire_id();
    bytes[17] = recipe.successor_mode().wire_id();
    bytes[18] = recipe.filter_count;
    bytes[19] = recipe.confirmation_count;
    bytes[20] = recipe.sparse_group_count;
    bytes[21] = recipe.match_stride;
    bytes[22] = recipe.periodic_stride;
    bytes[24..56].copy_from_slice(recipe.program_identity.as_bytes());
    bytes[56..88].copy_from_slice(&recipe.literal_identity);
    bytes[88..92].copy_from_slice(&recipe.filter_offsets);
    bytes[92..124].copy_from_slice(&recipe.confirmation_order);
    let mut cursor = 124;
    for group in recipe.sparse_group_blocks {
        bytes[cursor] = group.first_offset;
        bytes[cursor + 1] = group.len;
        cursor += 2;
    }
    for cost in recipe.costs.components() {
        bytes[cursor..cursor + 4].copy_from_slice(&cost.to_le_bytes());
        cursor += 4;
    }
    if !zero_identity {
        bytes[224..256].copy_from_slice(recipe.identity.as_bytes());
    }
    bytes
}

fn inspect_recipe(
    bytes: &[u8; COUNT_V3_RECIPE_CANONICAL_BYTES],
) -> Result<InspectedCountRecipeV3, CountV3RecipeDecodeError> {
    if &bytes[..8] != b"FRECV3R\0" {
        return Err(CountV3RecipeDecodeError::Magic);
    }
    if read_u16(bytes, 8) != COUNT_V3_RECIPE_SCHEMA_VERSION {
        return Err(CountV3RecipeDecodeError::SchemaVersion);
    }
    if read_u16(bytes, 10) != COUNT_V3_OPTIMIZER_VERSION {
        return Err(CountV3RecipeDecodeError::OptimizerVersion);
    }
    let tuning_class = match bytes[12] {
        1 => CountV3TuningClass::GenericAarch64,
        2 => CountV3TuningClass::AppleMSeries,
        3 => CountV3TuningClass::NeoverseV2V3,
        value => return Err(CountV3RecipeDecodeError::UnknownTuningClass(value)),
    };
    let strategy = match bytes[13] {
        1 => CountV3Strategy::Incumbent,
        2 => CountV3Strategy::SparseRareColumns,
        3 => CountV3Strategy::EndpointDense,
        4 => CountV3Strategy::PeriodicRun,
        5 => CountV3Strategy::DirectExactMask,
        value => return Err(CountV3RecipeDecodeError::UnknownStrategy(value)),
    };
    let schedule_id = match bytes[14] {
        1 => CountV3ScheduleId::IncumbentV2,
        2 => CountV3ScheduleId::SparseColumnsV1,
        3 => CountV3ScheduleId::EndpointDenseV1,
        4 => CountV3ScheduleId::PeriodicRunV1,
        5 => CountV3ScheduleId::DirectExactMaskV1,
        value => return Err(CountV3RecipeDecodeError::UnknownSchedule(value)),
    };
    let register_plan_id = match bytes[15] {
        1 => CountV3RegisterPlanId::Aarch64NeonV1,
        2 => CountV3RegisterPlanId::Aarch64SveVl16V1,
        3 => CountV3RegisterPlanId::Aarch64Sve2Vl16V1,
        value => return Err(CountV3RecipeDecodeError::UnknownRegisterPlan(value)),
    };
    let required_isa = match bytes[16] {
        1 => CountV3RequiredIsa::Aarch64Neon128,
        2 => CountV3RequiredIsa::Aarch64SveVl16,
        3 => CountV3RequiredIsa::Aarch64Sve2Vl16,
        value => return Err(CountV3RecipeDecodeError::UnknownRequiredIsa(value)),
    };
    if bytes[17] != CountV3SuccessorMode::NonOverlapping.wire_id() {
        return Err(CountV3RecipeDecodeError::UnknownSuccessorMode(bytes[17]));
    }
    let expected_schedule = match strategy {
        CountV3Strategy::Incumbent => CountV3ScheduleId::IncumbentV2,
        CountV3Strategy::SparseRareColumns => CountV3ScheduleId::SparseColumnsV1,
        CountV3Strategy::EndpointDense => CountV3ScheduleId::EndpointDenseV1,
        CountV3Strategy::PeriodicRun => CountV3ScheduleId::PeriodicRunV1,
        CountV3Strategy::DirectExactMask => CountV3ScheduleId::DirectExactMaskV1,
    };
    let isa_plan_matches = matches!(
        (register_plan_id, required_isa),
        (
            CountV3RegisterPlanId::Aarch64NeonV1,
            CountV3RequiredIsa::Aarch64Neon128
        ) | (
            CountV3RegisterPlanId::Aarch64SveVl16V1,
            CountV3RequiredIsa::Aarch64SveVl16
        ) | (
            CountV3RegisterPlanId::Aarch64Sve2Vl16V1,
            CountV3RequiredIsa::Aarch64Sve2Vl16
        )
    );
    if schedule_id != expected_schedule || !isa_plan_matches {
        return Err(CountV3RecipeDecodeError::InvalidPrimitiveManifest);
    }

    let filter_count = bytes[18];
    let confirmation_count = bytes[19];
    let sparse_group_count = bytes[20];
    let match_stride = bytes[21];
    let periodic_stride = bytes[22];
    if usize::from(filter_count) > COUNT_V3_MAX_FILTER_OFFSETS
        || usize::from(confirmation_count) > COUNT_V3_MAX_LITERAL_BYTES
        || usize::from(sparse_group_count) > COUNT_V3_MAX_SPARSE_GROUP_BLOCKS
        || usize::from(match_stride) > COUNT_V3_MAX_LITERAL_BYTES
        || confirmation_count != match_stride
    {
        return Err(CountV3RecipeDecodeError::InvalidCounts);
    }
    if bytes[23] != 0 || bytes[156..224].iter().any(|byte| *byte != 0) {
        return Err(CountV3RecipeDecodeError::NonCanonicalPadding);
    }

    let program_identity: [u8; 32] = bytes[24..56]
        .try_into()
        .expect("fixed canonical program identity");
    let literal_identity: [u8; 32] = bytes[56..88]
        .try_into()
        .expect("fixed canonical literal identity");
    if program_identity == [0; 32] || literal_identity == [0; 32] {
        return Err(CountV3RecipeDecodeError::InvalidPrimitiveManifest);
    }
    let filter_offsets: [u8; COUNT_V3_MAX_FILTER_OFFSETS] =
        bytes[88..92].try_into().expect("fixed filter offsets");
    let confirmation_order: [u8; COUNT_V3_MAX_LITERAL_BYTES] =
        bytes[92..124].try_into().expect("fixed confirmation order");
    if filter_offsets[usize::from(filter_count)..]
        .iter()
        .any(|value| *value != 0)
        || confirmation_order[usize::from(confirmation_count)..]
            .iter()
            .any(|value| *value != 0)
    {
        return Err(CountV3RecipeDecodeError::NonCanonicalPadding);
    }
    let width = usize::from(match_stride);
    let mut seen_filters = [false; COUNT_V3_MAX_LITERAL_BYTES];
    for offset in &filter_offsets[..usize::from(filter_count)] {
        let offset = usize::from(*offset);
        if offset >= width || seen_filters[offset] {
            return Err(CountV3RecipeDecodeError::InvalidPrimitiveManifest);
        }
        seen_filters[offset] = true;
    }
    let mut seen_confirmation = [false; COUNT_V3_MAX_LITERAL_BYTES];
    for offset in &confirmation_order[..usize::from(confirmation_count)] {
        let offset = usize::from(*offset);
        if offset >= width || seen_confirmation[offset] {
            return Err(CountV3RecipeDecodeError::InvalidPrimitiveManifest);
        }
        seen_confirmation[offset] = true;
    }
    if seen_confirmation[..width].iter().any(|seen| !*seen) {
        return Err(CountV3RecipeDecodeError::InvalidPrimitiveManifest);
    }

    let mut sparse_group_blocks =
        [CountV3SparseGroupBlock::default(); COUNT_V3_MAX_SPARSE_GROUP_BLOCKS];
    let mut group_cursor = 124;
    for group in &mut sparse_group_blocks {
        *group = CountV3SparseGroupBlock {
            first_offset: bytes[group_cursor],
            len: bytes[group_cursor + 1],
        };
        group_cursor += 2;
    }
    if sparse_group_blocks[usize::from(sparse_group_count)..]
        .iter()
        .any(|group| *group != CountV3SparseGroupBlock::default())
    {
        return Err(CountV3RecipeDecodeError::NonCanonicalPadding);
    }
    let mut expected_first = 0_usize;
    for group in &sparse_group_blocks[..usize::from(sparse_group_count)] {
        let expected_len = (width - expected_first).min(8);
        if usize::from(group.first_offset) != expected_first
            || usize::from(group.len) != expected_len
            || expected_len == 0
        {
            return Err(CountV3RecipeDecodeError::InvalidPrimitiveManifest);
        }
        expected_first += expected_len;
    }
    if expected_first != width {
        return Err(CountV3RecipeDecodeError::InvalidPrimitiveManifest);
    }

    let costs = CountV3CostVector {
        sparse: read_u32(bytes, 132),
        dense: read_u32(bytes, 136),
        false_positive: read_u32(bytes, 140),
        matches: read_u32(bytes, 144),
        tail: read_u32(bytes, 148),
        code_size: read_u32(bytes, 152),
    };
    if costs.components().into_iter().any(|cost| cost == 0) {
        return Err(CountV3RecipeDecodeError::InvalidPrimitiveManifest);
    }
    let periodic_shape = match strategy {
        CountV3Strategy::PeriodicRun => periodic_stride != 0 && periodic_stride < match_stride,
        _ => periodic_stride == 0,
    };
    if !periodic_shape {
        return Err(CountV3RecipeDecodeError::InvalidPrimitiveManifest);
    }
    let identity = CountV3RecipeIdentity(
        bytes[224..256]
            .try_into()
            .expect("fixed canonical recipe identity"),
    );
    let mut hash_input = *bytes;
    hash_input[224..256].fill(0);
    let mut hasher = Sha256::new();
    hasher.update(RECIPE_IDENTITY_DOMAIN);
    hasher.update(hash_input);
    let expected_identity: [u8; 32] = hasher.finalize().into();
    if identity.0 != expected_identity {
        return Err(CountV3RecipeDecodeError::RecipeIdentity);
    }
    Ok(InspectedCountRecipeV3 {
        program_identity,
        literal_identity,
        tuning_class,
        strategy,
        schedule_id,
        register_plan_id,
        required_isa,
        filter_offsets,
        filter_count,
        confirmation_order,
        confirmation_count,
        sparse_group_blocks,
        sparse_group_count,
        match_stride,
        periodic_stride,
        costs,
        identity,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed u16 canonical range"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed u32 canonical range"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed u64 canonical range"),
    )
}

fn validate_recipe(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
) -> Result<(), CountV3RecipeValidationError> {
    let literal = program.literal();
    if recipe.program_identity != program.cache_identity() {
        return Err(CountV3RecipeValidationError::ProgramIdentity);
    }
    if recipe.literal_identity != literal_identity(literal) {
        return Err(CountV3RecipeValidationError::LiteralIdentity);
    }
    let expected_schedule = match recipe.strategy {
        CountV3Strategy::Incumbent => CountV3ScheduleId::IncumbentV2,
        CountV3Strategy::SparseRareColumns => CountV3ScheduleId::SparseColumnsV1,
        CountV3Strategy::EndpointDense => CountV3ScheduleId::EndpointDenseV1,
        CountV3Strategy::PeriodicRun => CountV3ScheduleId::PeriodicRunV1,
        CountV3Strategy::DirectExactMask => CountV3ScheduleId::DirectExactMaskV1,
    };
    if recipe.schedule_id != expected_schedule {
        return Err(CountV3RecipeValidationError::StrategySchedule);
    }
    if recipe.register_plan_id != register_plan_for_isa(recipe.required_isa) {
        return Err(CountV3RecipeValidationError::RegisterPlan);
    }
    let width = literal.len();
    if usize::from(recipe.filter_count) > COUNT_V3_MAX_FILTER_OFFSETS
        || recipe.filter_offsets[usize::from(recipe.filter_count)..]
            .iter()
            .any(|offset| *offset != 0)
        || recipe
            .filter_offsets()
            .iter()
            .any(|offset| usize::from(*offset) >= width)
    {
        return Err(CountV3RecipeValidationError::FilterOffsets);
    }
    let mut filter_seen = [false; COUNT_V3_MAX_LITERAL_BYTES];
    for offset in recipe.filter_offsets() {
        let offset = usize::from(*offset);
        if filter_seen[offset] {
            return Err(CountV3RecipeValidationError::FilterOffsets);
        }
        filter_seen[offset] = true;
    }
    if usize::from(recipe.confirmation_count) != width {
        return Err(CountV3RecipeValidationError::ConfirmationOrder);
    }
    if recipe.confirmation_order[width..]
        .iter()
        .any(|offset| *offset != 0)
    {
        return Err(CountV3RecipeValidationError::ConfirmationOrder);
    }
    let mut seen = [false; COUNT_V3_MAX_LITERAL_BYTES];
    for offset in recipe.confirmation_order() {
        let offset = usize::from(*offset);
        if offset >= width || seen[offset] {
            return Err(CountV3RecipeValidationError::ConfirmationOrder);
        }
        seen[offset] = true;
    }

    let mut work = Work::default();
    let analysis = analyze_literal(literal, &mut work)
        .map_err(|_| CountV3RecipeValidationError::FilterOffsets)?;
    let frontier = build_column_frontier(literal, &analysis, &mut work)
        .map_err(|_| CountV3RecipeValidationError::FilterOffsets)?;
    let legal_strategy = match recipe.strategy {
        CountV3Strategy::Incumbent => {
            let expected = incumbent_filters(literal)
                .map_err(|_| CountV3RecipeValidationError::FilterOffsets)?;
            recipe.filter_offsets() == &expected.0[..expected.1] && recipe.periodic_stride == 0
        }
        CountV3Strategy::SparseRareColumns => {
            let filters = recipe.filter_offsets();
            let count_ok = (2..=COUNT_V3_MAX_FILTER_OFFSETS).contains(&filters.len());
            let distinct = count_ok && distinct_filter_bytes(literal, filters);
            let from_frontier = filters
                .iter()
                .all(|filter| frontier.as_slice().contains(filter));
            let mut canonical = [0_u8; COUNT_V3_MAX_FILTER_OFFSETS];
            canonical[..filters.len()].copy_from_slice(filters);
            canonicalize_filter_order(
                literal,
                &analysis.multiplicity,
                CountV3Strategy::SparseRareColumns,
                &mut canonical[..filters.len()],
            );
            distinct
                && from_frontier
                && filters == &canonical[..filters.len()]
                && recipe.periodic_stride == 0
        }
        CountV3Strategy::EndpointDense => {
            if width < 2 || recipe.periodic_stride != 0 {
                false
            } else {
                let endpoints = ranked_endpoint_pair(literal, &analysis.multiplicity);
                let filters = recipe.filter_offsets();
                let endpoint_pair = filters == endpoints;
                let endpoint_rare = endpoint_rare_offset(literal, &frontier)
                    .is_some_and(|rare| filters == [endpoints[0], endpoints[1], rare]);
                endpoint_pair || endpoint_rare
            }
        }
        CountV3Strategy::PeriodicRun => {
            let period = usize::from(analysis.facts.minimum_period);
            if period >= width {
                false
            } else {
                let expected = periodic_filters(literal, analysis.facts, &analysis.multiplicity)
                    .map_err(|_| CountV3RecipeValidationError::FilterOffsets)?;
                let selected_count = recipe.filter_offsets().len();
                (2..=expected.1).contains(&selected_count)
                    && recipe.filter_offsets() == &expected.0[..selected_count]
                    && recipe.periodic_stride == analysis.facts.minimum_period
            }
        }
        CountV3Strategy::DirectExactMask => direct_exact_mask_filters(literal, analysis.facts)
            .is_some_and(|(filters, count)| {
                recipe.filter_offsets() == &filters[..count] && recipe.periodic_stride == 0
            }),
    };
    if !legal_strategy {
        return Err(CountV3RecipeValidationError::FilterOffsets);
    }
    if recipe.match_stride != u8::try_from(width).expect("Count-v3 literal width is at most 32") {
        return Err(CountV3RecipeValidationError::Strides);
    }
    let expected_confirmation =
        confirmation_order(literal, &analysis.multiplicity, recipe.filter_offsets())
            .map_err(|_| CountV3RecipeValidationError::ConfirmationOrder)?;
    if recipe.confirmation_order != expected_confirmation.0
        || recipe.confirmation_count != expected_confirmation.1
    {
        return Err(CountV3RecipeValidationError::ConfirmationOrder);
    }
    let expected_groups =
        sparse_groups(width).map_err(|_| CountV3RecipeValidationError::SparseGroups)?;
    if recipe.sparse_group_blocks != expected_groups.0
        || recipe.sparse_group_count != expected_groups.1
    {
        return Err(CountV3RecipeValidationError::SparseGroups);
    }
    let expected_costs = estimate_costs(
        literal,
        analysis.facts,
        &analysis.multiplicity,
        recipe.required_isa,
        recipe.strategy,
        recipe.filter_offsets(),
    )
    .map_err(|_| CountV3RecipeValidationError::CostVector)?;
    if recipe.costs != expected_costs {
        return Err(CountV3RecipeValidationError::CostVector);
    }
    if recipe.identity != recipe_identity(recipe) {
        return Err(CountV3RecipeValidationError::RecipeIdentity);
    }
    Ok(())
}

const _: () = assert!(size_of::<CountRecipeV3>() <= 256);

#[cfg(test)]
mod tests;
