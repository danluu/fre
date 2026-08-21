//! Target-neutral correlated masks for mandatory multi-literal factors.
//!
//! A [`RequiredLiteralSet`] is already a graph-authenticated disjunction: every
//! match contains one retained literal at the selected prefix, suffix, or
//! interior boundary. Collapsing that set into independent byte columns loses
//! correlation. This module instead builds the nibble-table fingerprint used
//! by Teddy-family scanners. Each literal is assigned to one of at most 16
//! buckets. For every fingerprint column, a bucket bit is present in both the
//! low- and high-nibble tables for that literal's byte. ANDing the two table
//! lookups for every column therefore cannot reject a retained literal.
//!
//! Bucket collisions and the split-nibble representation can introduce false
//! candidates. They cannot introduce false negatives: an emitted scanner is
//! only a prefilter, and the existing exact DFA or seeded reverse machine
//! remains the authority. The portfolio builder is target-neutral and does
//! not select a runtime route. Native lowering may consume one candidate only
//! when the target has a suitable table-lookup ISA and a structural cost model
//! prefers it to the already selected scanner.

use crate::{
    byte_frequency::{BYTE_FREQUENCY_DENOMINATOR, estimated_byte_frequency_units},
    required_literals::RequiredLiteralSet,
};

/// Teddy becomes useful only after at least three correlated bytes. Shallower
/// factors retain the existing single-column and pair-relation scanners.
pub(crate) const MIN_MANDATORY_TEDDY_COLUMNS: usize = 3;
/// A fourth column usually buys useful rejection without exhausting the
/// constant/register budget of the supported vector backends.
pub(crate) const MAX_MANDATORY_TEDDY_COLUMNS: usize = 4;
/// Slim plans use one repeated 8-bit mask. Fat AVX2 plans encode the second
/// eight buckets in the other 128-bit lane of the same 256-bit shuffle mask;
/// ASIMD/SVE lower the same logical plan as two eight-bucket banks.
pub(crate) const MAX_MANDATORY_TEDDY_BUCKETS: usize = 16;
/// One byte-wide nibble table represents eight bucket bits.
pub(crate) const MANDATORY_TEDDY_BUCKETS_PER_BANK: usize = 8;
const MAX_MANDATORY_TEDDY_BANKS: usize =
    MAX_MANDATORY_TEDDY_BUCKETS / MANDATORY_TEDDY_BUCKETS_PER_BANK;
/// Required-literal analysis is already bounded by this same sequence limit.
const MAX_MANDATORY_TEDDY_LITERALS: usize = 2_048;
/// At most two column widths times two bucket geometries are retained.
const MAX_MANDATORY_TEDDY_PLANS: usize = 4;
/// Exact source-independent ceiling for validation, greedy clustering, and
/// table materialization across the complete fixed portfolio.
const MAX_MANDATORY_TEDDY_BUILD_WORK: u64 = 2_000_000;
/// The number of buckets cannot improve selectivity once every literal has a
/// distinct bit. A modest minimum also keeps pair-like sets on the established
/// relation scanner instead of paying table setup for too little parallelism.
const MIN_MANDATORY_TEDDY_LITERALS: usize = 4;
/// A `u64` source-ordinal mask bounds the exact finite verifier to 64 arms.
const MAX_EXACT_PLAN_LITERALS: usize = 64;

const EMPTY_MASK_BANK: MandatoryTeddyMaskBank = MandatoryTeddyMaskBank {
    low: [[0; 16]; MAX_MANDATORY_TEDDY_COLUMNS],
    high: [[0; 16]; MAX_MANDATORY_TEDDY_COLUMNS],
};

/// One eight-bucket bank of 16-byte low- and high-nibble lookup tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MandatoryTeddyMaskBank {
    low: [[u8; 16]; MAX_MANDATORY_TEDDY_COLUMNS],
    high: [[u8; 16]; MAX_MANDATORY_TEDDY_COLUMNS],
}

impl MandatoryTeddyMaskBank {
    /// Low-nibble table for one chronological fingerprint column.
    #[must_use]
    pub(crate) fn low(&self, column: usize) -> Option<&[u8; 16]> {
        self.low.get(column)
    }

    /// High-nibble table for one chronological fingerprint column.
    #[must_use]
    pub(crate) fn high(&self, column: usize) -> Option<&[u8; 16]> {
        self.high.get(column)
    }
}

/// One fixed target-neutral fingerprint geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MandatoryTeddyPlan {
    banks: [MandatoryTeddyMaskBank; MAX_MANDATORY_TEDDY_BANKS],
    columns: u8,
    bucket_count: u8,
    literal_count: u16,
    candidate_fingerprint_upper_bound: u64,
    candidate_frequency_upper_bound: u64,
    fingerprint_space: u64,
    scan_instruction_units: u16,
}

impl MandatoryTeddyPlan {
    /// Number of correlated chronological bytes fingerprinted at each base.
    #[must_use]
    pub(crate) const fn columns(self) -> u8 {
        self.columns
    }

    /// Number of occupied-or-available bucket bits in the plan.
    #[must_use]
    pub(crate) const fn bucket_count(self) -> u8 {
        self.bucket_count
    }

    /// One logical bank for at most eight buckets, otherwise two. AVX2 packs
    /// two banks into its independent 128-bit shuffle lanes.
    #[must_use]
    pub(crate) const fn bank_count(self) -> u8 {
        self.bucket_count.div_ceil(8)
    }

    /// Number of graph-authenticated literals clustered into the buckets.
    #[must_use]
    pub(crate) const fn literal_count(self) -> u16 {
        self.literal_count
    }

    /// Conservative number of fingerprints admitted by the union of bucket
    /// rectangles. Overlap between buckets is deliberately counted twice.
    #[must_use]
    pub(crate) const fn candidate_fingerprint_upper_bound(self) -> u64 {
        self.candidate_fingerprint_upper_bound
    }

    /// Conservative candidate numerator in FRE's stable target-neutral byte
    /// frequency units. This prevents a small but common ASCII rectangle from
    /// looking artificially cheap under uniform byte cardinality.
    #[must_use]
    pub(crate) const fn candidate_frequency_upper_bound(self) -> u64 {
        self.candidate_frequency_upper_bound
    }

    /// Exact `256.pow(columns)` denominator for the candidate upper bound.
    #[must_use]
    pub(crate) const fn fingerprint_space(self) -> u64 {
        self.fingerprint_space
    }

    /// Target-neutral relative work for loads, table lookups, and mask ANDs.
    /// Backends can combine this with vector width and their verification cost.
    #[must_use]
    pub(crate) const fn scan_instruction_units(self) -> u16 {
        self.scan_instruction_units
    }

    /// Read-only mask payload before target-specific replication or alignment.
    #[must_use]
    pub(crate) fn table_bytes(self) -> usize {
        usize::from(self.bank_count())
            .saturating_mul(usize::from(self.columns))
            .saturating_mul(32)
    }

    /// Tables for one byte-mask bank.
    #[must_use]
    pub(crate) fn bank(&self, bank: usize) -> Option<&MandatoryTeddyMaskBank> {
        self.banks.get(bank).filter(|_| bank < usize::from(self.bank_count()))
    }

    /// Exact scalar interpretation of the target-neutral tables. Native
    /// emitters use the same operations across many candidate bases at once.
    #[must_use]
    pub(crate) fn candidate_buckets(self, window: &[u8]) -> u16 {
        let columns = usize::from(self.columns);
        if window.len() < columns {
            return 0;
        }
        let mut result = 0_u16;
        for bank_index in 0..usize::from(self.bank_count()) {
            let Some(bank) = self.banks.get(bank_index) else {
                return 0;
            };
            let mut candidates = u8::MAX;
            for (column, &byte) in window[..columns].iter().enumerate() {
                let low = usize::from(byte & 0x0f);
                let high = usize::from(byte >> 4);
                candidates &= bank.low[column][low] & bank.high[column][high];
            }
            result |= u16::from(candidates) << (bank_index * 8);
        }
        result & active_bucket_mask(self.bucket_count)
    }

    /// Scalar tail/reference search for the first fingerprint candidate.
    #[must_use]
    pub(crate) fn first_candidate(self, haystack: &[u8]) -> Option<usize> {
        self.next_candidate(haystack, 0)
    }

    /// Return the first fingerprint candidate base at or after `resume_base`.
    /// Exact rejection never terminates the search: the verifier resumes with
    /// `rejected_base + 1`, unless a separately proved DFA restart supplies a
    /// larger safe base. This monotone contract prevents retrying one false
    /// candidate and bounds ordinary fingerprint work to one visit per base.
    #[must_use]
    pub(crate) fn next_candidate(
        self,
        haystack: &[u8],
        resume_base: usize,
    ) -> Option<usize> {
        let columns = usize::from(self.columns);
        let searchable = haystack.len().checked_sub(columns)?.checked_add(1)?;
        if resume_base >= searchable {
            return None;
        }
        haystack[resume_base..]
            .windows(columns)
            .position(|window| self.candidate_buckets(window) != 0)
            .and_then(|relative| resume_base.checked_add(relative))
    }

    /// Exact-rejection progress shared by scalar tails and vector hit replay.
    /// A graph-proven restart may skip farther, but never backwards or to the
    /// same base. Overflow means the candidate was the final addressable base.
    #[must_use]
    pub(crate) fn resume_after_rejection(
        rejected_base: usize,
        proven_restart: Option<usize>,
    ) -> Option<usize> {
        let next = rejected_base.checked_add(1)?;
        // A restart is usable here only when its independent graph proof says
        // all skipped candidate bases are impossible. Callers must not pass a
        // merely convenient verifier cursor as `proven_restart`.
        Some(proven_restart.map_or(next, |restart| restart.max(next)))
    }

    /// Translate one scanner base back to the graph boundary consumed by the
    /// unchanged exact verifier. Prefix/interior factors use the base itself;
    /// a terminal factor's accept boundary is the base plus its full proven
    /// width, which can exceed the fingerprint depth retained by this plan.
    #[must_use]
    pub(crate) fn boundary_for_base(
        self,
        base: usize,
        minimum_width: usize,
        terminal: bool,
    ) -> Option<usize> {
        if minimum_width < usize::from(self.columns) {
            return None;
        }
        if terminal {
            base.checked_add(minimum_width)
        } else {
            Some(base)
        }
    }
}

/// Complete bounded portfolio. It retains slim/fat masks for three columns
/// and, when the proof is deep enough, for four. Target lowering chooses among
/// these fixed candidates; deriving the portfolio does not disturb an existing
/// exact-product, literal, pair-relation, or independent-column route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MandatoryTeddyPortfolio {
    plans: [Option<MandatoryTeddyPlan>; MAX_MANDATORY_TEDDY_PLANS],
    plan_count: u8,
    work_completed: u64,
}

/// Native table-lookup tier that can consume the target-neutral mask plan.
/// Baseline x86 SSE2 has no byte-table lookup and must decline. An explicit
/// AVX2 target that also enables AVX-512BW can reuse the 256-bit byte-shuffle
/// lowering without AVX-512VL, but has no cost discount: a 512-bit byte
/// permutation would additionally require VBMI, which is not in FRE's feature
/// vocabulary. Base SVE and SVE2 both use architectural TBL;
/// SVE2 MATCH produces predicates rather than correlated bucket identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MandatoryTeddyIsa {
    X86Avx2,
    X86Avx512Bw,
    Aarch64Asimd,
    Aarch64Sve,
    Aarch64Sve2,
}

/// Exact target representation cost for one already-derived Teddy plan.
/// Dynamic-row admission consumes only this compact receipt; table geometry
/// and ISA-specific instruction accounting remain owned by this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MandatoryTeddyTierCosts {
    pub(crate) scan_instruction_units: u16,
    pub(crate) block_bytes: u16,
    pub(crate) table_bytes: usize,
}

#[must_use]
pub(crate) fn tier_costs(
    plan: MandatoryTeddyPlan,
    isa: MandatoryTeddyIsa,
) -> Option<MandatoryTeddyTierCosts> {
    Some(MandatoryTeddyTierCosts {
        scan_instruction_units: teddy_tier_units(plan, isa)?,
        block_bytes: teddy_block_bytes(isa),
        table_bytes: teddy_retained_table_bytes(plan, isa)?,
    })
}

/// One structural cost model for an already selected native scanner.
/// `block_bytes` makes the scan term dimensional: instruction units are paid
/// once per vector block, not once per byte in the scoring window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MandatoryTeddyIncumbentCosts {
    /// Conservative candidate numerator in this module's stable byte-frequency
    /// units.
    pub(crate) candidate_upper_bound: u64,
    /// Corresponding frequency denominator.
    pub(crate) candidate_space: u64,
    /// Relative work paid for each vector block.
    pub(crate) scan_instruction_units: u16,
    /// Bytes consumed by one vector block of the established scanner.
    pub(crate) block_bytes: u16,
    /// Retained read-only payload used by this scanner case.
    pub(crate) table_bytes: usize,
}

/// Structural verification and incumbent costs supplied by the already
/// selected exact authority. This keeps selection independent of source and
/// benchmark IDs. A lazy multi-column scanner has two symbolic cases: only
/// its primary column runs, and every primary hit runs every secondary. Teddy
/// must materially beat both; no measured or assumed hit rate is embedded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MandatoryTeddySelectionCosts {
    /// Relative instructions/loads to enter the exact verifier once.
    pub(crate) verification_units: u32,
    pub(crate) incumbent_primary: MandatoryTeddyIncumbentCosts,
    pub(crate) incumbent_refined: MandatoryTeddyIncumbentCosts,
}

impl MandatoryTeddyPortfolio {
    /// Fixed candidates in deterministic `(columns, bucket_count)` order.
    pub(crate) fn plans(&self) -> impl Iterator<Item = &MandatoryTeddyPlan> {
        self.plans[..usize::from(self.plan_count)]
            .iter()
            .filter_map(Option::as_ref)
    }

    /// Exact abstract work charged while validating and clustering the set.
    #[must_use]
    pub(crate) const fn work_completed(self) -> u64 {
        self.work_completed
    }

    /// Select the cheapest admitted plan for a concrete native lookup tier.
    /// The fixed-point score compares expected scan and exact-verification
    /// work over a fixed 256-byte abstract window, then charges table bytes.
    /// Teddy must beat the incumbent by at least one eighth so setup and code
    /// size do not displace a nearly equivalent established scanner.
    #[must_use]
    pub(crate) fn select(
        &self,
        isa: MandatoryTeddyIsa,
        costs: MandatoryTeddySelectionCosts,
    ) -> Option<MandatoryTeddyPlan> {
        self.select_with_bank_limit(isa, costs, MAX_MANDATORY_TEDDY_BANKS as u8)
    }

    /// Select within a backend's currently audited logical-bank budget.
    ///
    /// This lets a lowering publish slim Teddy first without silently treating
    /// a two-bank target-neutral plan as though its second bucket bank had
    /// been emitted. The ordinary selector continues to expose the complete
    /// fixed portfolio to backends that implement both banks.
    #[must_use]
    pub(crate) fn select_with_bank_limit(
        &self,
        isa: MandatoryTeddyIsa,
        costs: MandatoryTeddySelectionCosts,
        maximum_banks: u8,
    ) -> Option<MandatoryTeddyPlan> {
        if maximum_banks == 0 || usize::from(maximum_banks) > MAX_MANDATORY_TEDDY_BANKS {
            return None;
        }
        let incumbent_primary = scanner_score(
            costs.incumbent_primary.candidate_upper_bound,
            costs.incumbent_primary.candidate_space,
            costs.incumbent_primary.scan_instruction_units,
            costs.incumbent_primary.block_bytes,
            costs.verification_units,
            costs.incumbent_primary.table_bytes,
            1,
        )?;
        let incumbent_refined = scanner_score(
            costs.incumbent_refined.candidate_upper_bound,
            costs.incumbent_refined.candidate_space,
            costs.incumbent_refined.scan_instruction_units,
            costs.incumbent_refined.block_bytes,
            costs.verification_units,
            costs.incumbent_refined.table_bytes,
            1,
        )?;
        self.plans()
            .copied()
            .filter(|plan| plan.bank_count() <= maximum_banks)
            .filter_map(|plan| {
                let tier_units = teddy_tier_units(plan, isa)?;
                let retained_table_bytes = teddy_retained_table_bytes(plan, isa)?;
                let score = scanner_score(
                    plan.candidate_frequency_upper_bound,
                    plan.fingerprint_space,
                    tier_units,
                    teddy_block_bytes(isa),
                    costs.verification_units,
                    retained_table_bytes,
                    usize::from(plan.bank_count()),
                )?;
                let weighted_score = score.checked_mul(8)?;
                (weighted_score <= incumbent_primary.checked_mul(7)?
                    && weighted_score <= incumbent_refined.checked_mul(7)?)
                    .then_some((
                        score,
                        retained_table_bytes,
                        plan.columns,
                        plan.bucket_count,
                        plan,
                    ))
            })
            .min_by_key(|&(score, table_bytes, columns, bucket_count, _)| {
                (score, table_bytes, u8::MAX - columns, bucket_count)
            })
            .map(|(_, _, _, _, plan)| plan)
    }
}

fn teddy_retained_table_bytes(
    plan: MandatoryTeddyPlan,
    isa: MandatoryTeddyIsa,
) -> Option<usize> {
    let logical = plan.table_bytes();
    match isa {
        // A 256-bit byte shuffle is lane-local. Slim tables must be repeated
        // into both lanes, while a fat plan fills those lanes with its two
        // different banks. The conservative AVX-512 receipt uses this same
        // 128/256-bit representation rather than assuming VBMI.
        MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw => {
            if plan.bank_count() == 1 {
                // The installed AVX2-width representation also retains one
                // duplicated 0x0f index mask. Charge the exact immutable
                // payload consumed by the native receipt.
                logical.checked_mul(2)?.checked_add(32)
            } else {
                logical.checked_add(32)
            }
        }
        MandatoryTeddyIsa::Aarch64Asimd
        | MandatoryTeddyIsa::Aarch64Sve
        | MandatoryTeddyIsa::Aarch64Sve2 => Some(logical),
    }
}

fn teddy_tier_units(plan: MandatoryTeddyPlan, isa: MandatoryTeddyIsa) -> Option<u16> {
    let base = plan.scan_instruction_units;
    match isa {
        // VPSRLW shifts 16-bit words, so x86 must mask both low and high
        // indices back to one nibble. AArch64's USHR/LSR operates on byte
        // elements: its high result is already in 0..=15 and the emitted
        // ASIMD/SVE lowering removes exactly one AND per column.
        MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw => Some(base),
        MandatoryTeddyIsa::Aarch64Asimd
        | MandatoryTeddyIsa::Aarch64Sve
        | MandatoryTeddyIsa::Aarch64Sve2 => base.checked_sub(u16::from(plan.columns())),
    }
}

const fn teddy_block_bytes(isa: MandatoryTeddyIsa) -> u16 {
    match isa {
        // AVX-512F+BW reuses the same audited AVX2 sequence. Charging 64 bytes
        // here would claim throughput that the emitted 256-bit loads lack.
        MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw => 32,
        MandatoryTeddyIsa::Aarch64Asimd => 16,
        // Architectural SVE starts at 128 bits. A target-neutral plan cannot
        // assume a larger runtime VL, so the guaranteed minimum is the only
        // conservative byte count available at this boundary.
        MandatoryTeddyIsa::Aarch64Sve | MandatoryTeddyIsa::Aarch64Sve2 => 16,
    }
}

const MANDATORY_TEDDY_SCORING_WINDOW_BYTES: u16 = 256;

fn scanner_score(
    candidate_upper_bound: u64,
    candidate_space: u64,
    scan_instruction_units: u16,
    block_bytes: u16,
    verification_units: u32,
    table_bytes: usize,
    banks: usize,
) -> Option<u128> {
    if candidate_space == 0 || block_bytes == 0 || banks == 0 {
        return None;
    }
    let candidate_upper_bound = candidate_upper_bound.min(candidate_space);
    let window_bytes = u128::from(MANDATORY_TEDDY_SCORING_WINDOW_BYTES);
    let block_bytes = u128::from(block_bytes);
    let blocks = window_bytes.checked_add(block_bytes.checked_sub(1)?)? / block_bytes;
    let scan = u128::from(scan_instruction_units).checked_mul(blocks)?;
    let verification = u128::from(candidate_upper_bound)
        .checked_mul(u128::from(verification_units))?
        .checked_mul(window_bytes)?
        .checked_add(u128::from(candidate_space).checked_sub(1)?)?
        / u128::from(candidate_space);
    // Sixty-four bytes approximate one L1 cache-line residency unit. A second
    // bank also adds one result merge even when its tables are hot.
    let data = u128::try_from(table_bytes.div_ceil(64)).ok()?;
    let bank_merge = u128::try_from(banks.saturating_sub(1)).ok()?;
    scan.checked_add(verification)?
        .checked_add(data)?
        .checked_add(bank_merge)
}

/// Build a mask portfolio only from the graph-authenticated correlated set.
/// No source text, pattern identity, benchmark identity, or runtime sample is
/// available at this boundary.
#[must_use]
pub(crate) fn derive(set: &RequiredLiteralSet) -> Option<MandatoryTeddyPortfolio> {
    let literal_count = set.literals().len();
    let depth = set.depth();
    derive_from_accessor(literal_count, depth, |index| {
        set.literals().get(index).map(|literal| literal.as_bytes())
    })
}

/// Derive one slim prefix gate after deduplicating the exact
/// projected fingerprint bytes.
///
/// Required-literal expansion can retain many longer product strings that
/// share the same first three or four bytes. Treating those duplicate
/// projections as independent bucket occupants weakens the mask without
/// adding language coverage. This bounded constructor keeps the complete
/// graph proof while selecting the lowest-frequency one-bank projection. A
/// complete miss is exact; the earliest fingerprint hit is a conservative
/// lower bound for the incumbent matcher.
#[must_use]
pub(crate) fn derive_slim_prefix_gate(
    set: &RequiredLiteralSet,
) -> Option<MandatoryTeddyPlan> {
    let maximum_columns = set.depth().min(MAX_MANDATORY_TEDDY_COLUMNS);
    if maximum_columns < MIN_MANDATORY_TEDDY_COLUMNS || set.literals().is_empty() {
        return None;
    }
    let mut budget = BuildBudget::new();
    let mut selected: Option<MandatoryTeddyPlan> = None;
    for columns in MIN_MANDATORY_TEDDY_COLUMNS..=maximum_columns {
        let mut projected = Vec::new();
        projected
            .try_reserve_exact(set.literals().len())
            .ok()?;
        for literal in set.literals() {
            let prefix = literal.as_bytes().get(..columns)?;
            let mut bytes = [0_u8; MAX_MANDATORY_TEDDY_COLUMNS];
            bytes[..columns].copy_from_slice(prefix);
            projected.push(bytes);
        }
        budget.consume(
            u64::try_from(projected.len().checked_mul(columns)?).ok()?,
        )?;
        let sort_levels = usize::try_from(
            usize::BITS.checked_sub(projected.len().leading_zeros())?,
        )
        .ok()?;
        budget.consume(
            u64::try_from(projected.len().checked_mul(sort_levels)?).ok()?,
        )?;
        projected.sort_unstable();
        projected.dedup();
        // One or two projected literals retain the established memchr/pair
        // plans. Three is the first shape whose correlation a byte-set root
        // cannot preserve.
        if projected.len() < 3 {
            continue;
        }
        let build = derive_geometry(
            projected.len(),
            columns,
            projected.len().min(MANDATORY_TEDDY_BUCKETS_PER_BANK),
            &|index| projected.get(index).map(|literal| &literal[..columns]),
            &mut budget,
        )?;
        let candidate = build.plan;
        let replace = if let Some(incumbent) = selected {
            let candidate_probability =
                u128::from(candidate.candidate_frequency_upper_bound)
                    .checked_mul(u128::from(incumbent.fingerprint_space))?;
            let incumbent_probability =
                u128::from(incumbent.candidate_frequency_upper_bound)
                    .checked_mul(u128::from(candidate.fingerprint_space))?;
            candidate_probability < incumbent_probability
                || (candidate_probability == incumbent_probability
                    && (candidate.scan_instruction_units, core::cmp::Reverse(candidate.columns))
                        < (
                            incumbent.scan_instruction_units,
                            core::cmp::Reverse(incumbent.columns),
                        ))
        } else {
            true
        };
        if replace {
            selected = Some(candidate);
        }
    }
    selected
}

/// Build the same target-neutral mask portfolio from exact finite-language
/// prefixes. The caller owns the proof that these are complete alternatives;
/// this layer authenticates only the common prefix depth and derives the
/// identical bounded bucket geometry used for mandatory graph literals.
///
/// Keeping this constructor beside [`derive`] prevents a future exact-literal
/// backend from maintaining a subtly different Teddy mask implementation.
#[must_use]
pub(crate) fn derive_exact_prefixes<B: AsRef<[u8]>>(
    literals: &[B],
    depth: usize,
) -> Option<MandatoryTeddyPortfolio> {
    derive_from_accessor(literals.len(), depth, |index| {
        literals.get(index)?.as_ref().get(..depth)
    })
}

/// Fixed-capacity source-ordinal bucket receipt for one exact plan.
///
/// The plan's own authenticated literal count bounds the live prefix. Keeping
/// the backing storage inline makes rebuilding this compiler-only map
/// allocation-free during materialization and receipt authentication.
pub(crate) struct ExactPlanAssignments {
    assignments: [u8; MAX_EXACT_PLAN_LITERALS],
    literal_count: u8,
}

impl ExactPlanAssignments {
    #[must_use]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.assignments[..usize::from(self.literal_count)]
    }
}

/// Rebuild the deterministic literal-to-bucket assignment for one selected
/// exact-prefix plan. The emitted exact verifier uses this authenticated map
/// to turn a scalar bucket fingerprint into a source-ordinal mask.
#[must_use]
pub(crate) fn exact_plan_assignments<B: AsRef<[u8]>>(
    literals: &[B],
    plan: MandatoryTeddyPlan,
) -> Option<ExactPlanAssignments> {
    let literal_count = literals.len();
    let columns = usize::from(plan.columns());
    let bucket_count = usize::from(plan.bucket_count());
    if literal_count != usize::from(plan.literal_count())
        || literal_count > MAX_EXACT_PLAN_LITERALS
        || plan.bank_count() != 1
        || bucket_count > MANDATORY_TEDDY_BUCKETS_PER_BANK
    {
        return None;
    }
    let mut budget = BuildBudget::new();
    let build = derive_geometry(
        literal_count,
        columns,
        bucket_count,
        &|index| literals.get(index)?.as_ref().get(..columns),
        &mut budget,
    )?;
    if build.plan != plan {
        return None;
    }
    let mut assignments = [0_u8; MAX_EXACT_PLAN_LITERALS];
    assignments[..literal_count].copy_from_slice(&build.assignments[..literal_count]);
    Some(ExactPlanAssignments {
        assignments,
        literal_count: u8::try_from(literal_count).ok()?,
    })
}

#[derive(Clone, Copy)]
struct BucketNibbles {
    low: [u16; MAX_MANDATORY_TEDDY_COLUMNS],
    high: [u16; MAX_MANDATORY_TEDDY_COLUMNS],
}

impl BucketNibbles {
    const EMPTY: Self = Self {
        low: [0; MAX_MANDATORY_TEDDY_COLUMNS],
        high: [0; MAX_MANDATORY_TEDDY_COLUMNS],
    };

    fn insert(&mut self, literal: &[u8], columns: usize) {
        for (column, &byte) in literal[..columns].iter().enumerate() {
            self.low[column] |= 1_u16 << u32::from(byte & 0x0f);
            self.high[column] |= 1_u16 << u32::from(byte >> 4);
        }
    }

    fn volume(self, columns: usize) -> u64 {
        let mut volume = 1_u64;
        for column in 0..columns {
            let low = u64::from(self.low[column].count_ones());
            let high = u64::from(self.high[column].count_ones());
            volume = volume.saturating_mul(low.saturating_mul(high));
        }
        volume
    }

    fn frequency_volume(self, columns: usize) -> u64 {
        let mut volume = 1_u64;
        for column in 0..columns {
            let mut units = 0_u64;
            for byte in u8::MIN..=u8::MAX {
                let low = 1_u16 << u32::from(byte & 0x0f);
                let high = 1_u16 << u32::from(byte >> 4);
                if self.low[column] & low != 0 && self.high[column] & high != 0 {
                    units = units.saturating_add(u64::from(
                        estimated_byte_frequency_units(byte),
                    ));
                }
            }
            volume = volume.saturating_mul(
                units.min(u64::from(BYTE_FREQUENCY_DENOMINATOR)),
            );
        }
        volume
    }
}

struct GeometryBuild {
    plan: MandatoryTeddyPlan,
    buckets: [BucketNibbles; MAX_MANDATORY_TEDDY_BUCKETS],
    assignments: [u8; MAX_MANDATORY_TEDDY_LITERALS],
}

#[derive(Clone, Copy)]
struct BuildBudget {
    work: u64,
}

impl BuildBudget {
    const fn new() -> Self {
        Self { work: 0 }
    }

    fn consume(&mut self, amount: u64) -> Option<()> {
        self.work = self.work.checked_add(amount)?;
        (self.work <= MAX_MANDATORY_TEDDY_BUILD_WORK).then_some(())
    }
}

fn derive_from_accessor<'a, F>(
    literal_count: usize,
    depth: usize,
    literal_at: F,
) -> Option<MandatoryTeddyPortfolio>
where
    F: Fn(usize) -> Option<&'a [u8]>,
{
    if !(MIN_MANDATORY_TEDDY_LITERALS..=MAX_MANDATORY_TEDDY_LITERALS)
        .contains(&literal_count)
        || !(MIN_MANDATORY_TEDDY_COLUMNS..=crate::required_literals::MAX_REQUIRED_LITERAL_DEPTH)
            .contains(&depth)
    {
        return None;
    }
    let mut budget = BuildBudget::new();
    budget.consume(u64::try_from(literal_count.checked_mul(depth)?).ok()?)?;
    for index in 0..literal_count {
        if literal_at(index)?.len() != depth {
            return None;
        }
    }

    let mut plans = [None; MAX_MANDATORY_TEDDY_PLANS];
    let mut plan_count = 0_usize;
    let maximum_columns = depth.min(MAX_MANDATORY_TEDDY_COLUMNS);
    for columns in MIN_MANDATORY_TEDDY_COLUMNS..=maximum_columns {
        for bucket_limit in [8_usize, 16] {
            if bucket_limit == 16 && literal_count <= 8 {
                continue;
            }
            let bucket_count = literal_count.min(bucket_limit);
            let build = derive_geometry(
                literal_count,
                columns,
                bucket_count,
                &literal_at,
                &mut budget,
            )?;
            *plans.get_mut(plan_count)? = Some(build.plan);
            plan_count = plan_count.checked_add(1)?;
        }
    }
    (plan_count != 0).then_some(MandatoryTeddyPortfolio {
        plans,
        plan_count: u8::try_from(plan_count).ok()?,
        work_completed: budget.work,
    })
}

fn derive_geometry<'a, F>(
    literal_count: usize,
    columns: usize,
    bucket_count: usize,
    literal_at: &F,
    budget: &mut BuildBudget,
) -> Option<GeometryBuild>
where
    F: Fn(usize) -> Option<&'a [u8]>,
{
    if !(MIN_MANDATORY_TEDDY_COLUMNS..=MAX_MANDATORY_TEDDY_COLUMNS).contains(&columns)
        || !(1..=MAX_MANDATORY_TEDDY_BUCKETS).contains(&bucket_count)
    {
        return None;
    }
    let mut buckets = [BucketNibbles::EMPTY; MAX_MANDATORY_TEDDY_BUCKETS];
    let mut assignments = [0_u8; MAX_MANDATORY_TEDDY_LITERALS];
    for literal_index in 0..literal_count {
        let literal = literal_at(literal_index)?;
        let mut best: Option<(u64, u64, usize, BucketNibbles)> = None;
        for bucket_index in 0..bucket_count {
            budget.consume(u64::try_from(columns).ok()?)?;
            let current = buckets[bucket_index];
            let current_volume = current.volume(columns);
            let mut next = current;
            next.insert(literal, columns);
            let next_volume = next.volume(columns);
            let increase = next_volume.checked_sub(current_volume)?;
            let key = (increase, next_volume, bucket_index);
            if best
                .as_ref()
                .is_none_or(|&(best_increase, best_volume, best_index, _)| {
                    key < (best_increase, best_volume, best_index)
                })
            {
                best = Some((increase, next_volume, bucket_index, next));
            }
        }
        let (_, _, bucket_index, next) = best?;
        buckets[bucket_index] = next;
        assignments[literal_index] = u8::try_from(bucket_index).ok()?;
    }

    let bank_count = bucket_count.div_ceil(MANDATORY_TEDDY_BUCKETS_PER_BANK);
    let mut banks = [EMPTY_MASK_BANK; MAX_MANDATORY_TEDDY_BANKS];
    for (bucket_index, bucket) in buckets[..bucket_count].iter().copied().enumerate() {
        let bank_index = bucket_index / MANDATORY_TEDDY_BUCKETS_PER_BANK;
        let bit = 1_u8 << u32::try_from(bucket_index % MANDATORY_TEDDY_BUCKETS_PER_BANK).ok()?;
        for column in 0..columns {
            budget.consume(32)?;
            for nibble in 0..16 {
                if bucket.low[column] & (1_u16 << u32::try_from(nibble).ok()?) != 0 {
                    banks[bank_index].low[column][nibble] |= bit;
                }
                if bucket.high[column] & (1_u16 << u32::try_from(nibble).ok()?) != 0 {
                    banks[bank_index].high[column][nibble] |= bit;
                }
            }
        }
    }
    let fingerprint_bits = u32::try_from(columns.checked_mul(8)?).ok()?;
    let fingerprint_space = 1_u64.checked_shl(fingerprint_bits)?;
    let candidate_fingerprint_upper_bound = buckets[..bucket_count]
        .iter()
        .copied()
        .try_fold(0_u64, |total, bucket| {
            total.checked_add(bucket.volume(columns))
        })?
        .min(fingerprint_space);
    budget.consume(
        u64::try_from(
            bucket_count
                .checked_mul(columns)?
                .checked_mul(usize::from(u8::MAX).checked_add(1)?)?,
        )
        .ok()?,
    )?;
    let frequency_space = u64::from(BYTE_FREQUENCY_DENOMINATOR)
        .checked_pow(u32::try_from(columns).ok()?)?;
    if frequency_space != fingerprint_space {
        return None;
    }
    let candidate_frequency_upper_bound = buckets[..bucket_count]
        .iter()
        .copied()
        .try_fold(0_u64, |total, bucket| {
            total.checked_add(bucket.frequency_volume(columns))
        })?
        .min(frequency_space);
    // The target-neutral/x86 ceiling forms both nibble indices once per
    // column: one load, one word shift, and two masks. AArch64's byte shift
    // removes the redundant high-nibble mask in `teddy_tier_units`. Each
    // logical bank then performs
    // two table shuffles, their intersection, and the chronological column
    // intersections. Fat backends can share the four input/index operations
    // across banks, so charge them outside `bank_units`.
    let input_units = columns.checked_mul(4)?;
    let bank_units = columns
        .checked_mul(3)
        .and_then(|units| units.checked_add(columns.saturating_sub(1)))?;
    let scan_instruction_units = bank_count
        .checked_mul(bank_units)
        .and_then(|units| units.checked_add(bank_count.saturating_sub(1)))
        .and_then(|units| units.checked_add(input_units))?;
    let plan = MandatoryTeddyPlan {
        banks,
        columns: u8::try_from(columns).ok()?,
        bucket_count: u8::try_from(bucket_count).ok()?,
        literal_count: u16::try_from(literal_count).ok()?,
        candidate_fingerprint_upper_bound,
        candidate_frequency_upper_bound,
        fingerprint_space,
        scan_instruction_units: u16::try_from(scan_instruction_units).ok()?,
    };
    Some(GeometryBuild {
        plan,
        buckets,
        assignments,
    })
}

const fn active_bucket_mask(bucket_count: u8) -> u16 {
    if bucket_count >= 16 {
        u16::MAX
    } else {
        (1_u16 << bucket_count) - 1
    }
}

#[cfg(test)]
mod tests {
    use fre_automata::{Automaton, CompileLimits as AutomatonLimits, RawPlan};
    use fre_lower::{LowerLimits, OperationSemantics};
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::*;
    use crate::required_literals;

    fn lower(pattern: &str) -> RawPlan {
        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern.to_owned(),
            CompatibilityProfile::RustBytes(RustProfile::default()),
        ))
        .unwrap_or_else(|error| panic!("parse {pattern:?}: {error}"));
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust parse returned a non-Rust pattern");
        };
        let raw = fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("lower {pattern:?}: {error}"))
        .into_plan();
        Automaton::from_raw(raw.clone(), AutomatonLimits::default())
            .unwrap_or_else(|error| panic!("validate {pattern:?}: {error}"));
        raw
    }

    fn portfolio(literals: &[Vec<u8>]) -> MandatoryTeddyPortfolio {
        let depth = literals.first().map_or(0, Vec::len);
        derive_from_accessor(literals.len(), depth, |index| {
            literals.get(index).map(Vec::as_slice)
        })
        .expect("bounded Teddy portfolio")
    }

    fn reference_column_masks(build: &GeometryBuild) -> [[u16; 256]; 4] {
        let mut masks = [[0_u16; 256]; 4];
        let columns = usize::from(build.plan.columns());
        for (bucket_index, bucket) in build.buckets
            [..usize::from(build.plan.bucket_count())]
            .iter()
            .copied()
            .enumerate()
        {
            let bucket_bit = 1_u16 << u32::try_from(bucket_index).expect("bucket bit");
            for column in 0..columns {
                for byte in u8::MIN..=u8::MAX {
                    let low = 1_u16 << u32::from(byte & 0x0f);
                    let high = 1_u16 << u32::from(byte >> 4);
                    if bucket.low[column] & low != 0 && bucket.high[column] & high != 0 {
                        masks[column][usize::from(byte)] |= bucket_bit;
                    }
                }
            }
        }
        masks
    }

    fn exact_weighted_candidate_mass(plan: MandatoryTeddyPlan) -> u64 {
        let columns = usize::from(plan.columns());
        assert_eq!(columns, 3, "bounded exhaustive weighted oracle");
        let mut total = 0_u64;
        for first in u8::MIN..=u8::MAX {
            for second in u8::MIN..=u8::MAX {
                for third in u8::MIN..=u8::MAX {
                    if plan.candidate_buckets(&[first, second, third]) != 0 {
                        total = total.saturating_add(
                            u64::from(estimated_byte_frequency_units(first))
                                .saturating_mul(u64::from(
                                    estimated_byte_frequency_units(second),
                                ))
                                .saturating_mul(u64::from(
                                    estimated_byte_frequency_units(third),
                                )),
                        );
                    }
                }
            }
        }
        total
    }

    #[test]
    fn graph_authenticated_alternatives_build_a_bounded_portfolio() {
        let raw = lower("(?:ant|bee|cat|dog|eel|fox|gnu|hen|ibx|jay|koi|lyn)");
        let required = required_literals::derive(&raw);
        let portfolio = derive(required.prefix()).expect("graph-authenticated literals");
        let shapes = portfolio
            .plans()
            .map(|plan| (plan.columns(), plan.bucket_count(), plan.bank_count()))
            .collect::<Vec<_>>();
        assert_eq!(shapes, vec![(3, 8, 1), (3, 12, 2)]);
        assert!(portfolio.work_completed() <= MAX_MANDATORY_TEDDY_BUILD_WORK);
        for literal in required.prefix().literals() {
            assert_ne!(
                portfolio
                    .plans()
                    .next()
                    .expect("slim plan")
                    .candidate_buckets(literal.as_bytes()),
                0
            );
        }
        for plan in portfolio.plans() {
            let columns = u16::from(plan.columns());
            let banks = u16::from(plan.bank_count());
            let per_bank = columns.saturating_mul(4).saturating_sub(1);
            let expected_scan_units = columns
                .saturating_mul(4)
                .saturating_add(banks.saturating_mul(per_bank))
                .saturating_add(banks.saturating_sub(1));
            assert_eq!(
                plan.scan_instruction_units(),
                expected_scan_units,
                "scan cost must charge index formation and every logical bank"
            );
            assert!(
                plan.candidate_frequency_upper_bound()
                    >= plan.candidate_fingerprint_upper_bound()
            );
            assert!(plan.candidate_frequency_upper_bound() <= plan.fingerprint_space());
        }
    }

    #[test]
    fn slim_prefix_gate_deduplicates_product_expansion_before_bucket_assignment() {
        let raw = lower("(?:foo|bar|baz){2,4}Q");
        let required = required_literals::derive(&raw);
        let prefix = required.prefix();
        assert_eq!(prefix.depth(), 7);
        assert_eq!(prefix.literals().len(), 27);

        let plan = derive_slim_prefix_gate(prefix).expect("slim projected prefix gate");
        assert_eq!(plan.columns(), 4);
        assert_eq!(plan.literal_count(), 6);
        assert_eq!(plan.bucket_count(), 6);
        assert_eq!(plan.bank_count(), 1);
        for literal in prefix.literals() {
            assert_ne!(
                plan.candidate_buckets(literal.as_bytes()),
                0,
                "projected plan lost graph-required literal {:?}",
                literal.as_bytes()
            );
        }
        assert_eq!(plan.first_candidate(b"bbbbbbbbbbbb"), None);
        assert_eq!(plan.first_candidate(b"xxxxbarbxxxx"), Some(4));

        let pair = lower("(?:ant|bee)[a-z]{0,300}");
        let pair_required = required_literals::derive(&pair);
        assert!(derive_slim_prefix_gate(pair_required.prefix()).is_none());
    }

    #[test]
    fn table_scanner_matches_the_exhaustive_three_byte_scalar_oracle() {
        let literals = [
            b"ant".to_vec(),
            b"bee".to_vec(),
            b"cat".to_vec(),
            b"dog".to_vec(),
            b"eel".to_vec(),
            b"fox".to_vec(),
            b"gnu".to_vec(),
            b"hen".to_vec(),
            b"ibx".to_vec(),
            b"jay".to_vec(),
            b"koi".to_vec(),
            b"lyn".to_vec(),
        ];
        let mut budget = BuildBudget::new();
        let build = derive_geometry(
            literals.len(),
            3,
            12,
            &|index| literals.get(index).map(Vec::as_slice),
            &mut budget,
        )
        .expect("fat three-column geometry");
        let reference = reference_column_masks(&build);
        for encoded in 0_u32..=0x00ff_ffff {
            let bytes = encoded.to_le_bytes();
            let expected = reference[0][usize::from(bytes[0])]
                & reference[1][usize::from(bytes[1])]
                & reference[2][usize::from(bytes[2])];
            assert_eq!(
                build.plan.candidate_buckets(&bytes[..3]),
                expected,
                "fingerprint {encoded:06x}"
            );
        }
        for (literal_index, literal) in literals.iter().enumerate() {
            let bucket = build.assignments[literal_index];
            assert_ne!(
                build.plan.candidate_buckets(literal) & (1_u16 << bucket),
                0,
                "literal {literal:02x?} lost bucket {bucket}"
            );
        }
        assert!(
            exact_weighted_candidate_mass(build.plan)
                <= build.plan.candidate_frequency_upper_bound(),
            "sum of possibly overlapping bucket rectangles is an upper bound"
        );
    }

    #[test]
    fn scalar_tail_search_matches_a_brute_candidate_oracle() {
        let literals = [
            b"abcd".to_vec(),
            b"abce".to_vec(),
            b"wxyz".to_vec(),
            b"wxya".to_vec(),
            b"0123".to_vec(),
            b"4567".to_vec(),
            b"8901".to_vec(),
            b"qrst".to_vec(),
            b"uvwx".to_vec(),
        ];
        let plan = portfolio(&literals)
            .plans()
            .copied()
            .find(|plan| plan.columns() == 4 && plan.bucket_count() == 9)
            .expect("fat four-column plan");
        let alphabet = [b'a', b'b', b'0', b'4', b'q', b'u'];
        for encoded in 0_usize..alphabet.len().pow(6) {
            let mut value = encoded;
            let mut haystack = [0_u8; 6];
            for byte in &mut haystack {
                *byte = alphabet[value % alphabet.len()];
                value /= alphabet.len();
            }
            let expected = haystack
                .windows(usize::from(plan.columns()))
                .position(|window| plan.candidate_buckets(window) != 0);
            assert_eq!(plan.first_candidate(&haystack), expected);
        }
        assert_eq!(plan.boundary_for_base(7, 6, false), Some(7));
        assert_eq!(plan.boundary_for_base(7, 6, true), Some(13));
        assert_eq!(plan.boundary_for_base(7, 3, true), None);
    }

    #[test]
    fn false_candidate_rejection_resumes_and_finds_a_later_exact_match() {
        // One bucket deliberately contains two literals, so taking each
        // column from either literal forms a Cartesian false candidate. The
        // unchanged exact authority rejects that base; a later exact literal
        // must still be observed.
        let literals = [
            b"abcd".to_vec(),
            b"wxyz".to_vec(),
            b"mnop".to_vec(),
            b"qrst".to_vec(),
        ];
        let mut budget = BuildBudget::new();
        let build = derive_geometry(
            literals.len(),
            4,
            1,
            &|index| literals.get(index).map(Vec::as_slice),
            &mut budget,
        )
        .expect("one-bucket collision plan");
        let plan = build.plan;
        let haystack = b"__abyz___abcd__";
        let exact_at = |base: usize| {
            haystack.get(base..).is_some_and(|suffix| {
                literals.iter().any(|literal| suffix.starts_with(literal))
            })
        };
        let first = plan.next_candidate(haystack, 0).expect("false candidate");
        assert_eq!(first, 2);
        assert!(!exact_at(first));
        let resume = MandatoryTeddyPlan::resume_after_rejection(first, None)
            .expect("monotone retry");
        assert_eq!(resume, 3);
        let second = plan
            .next_candidate(haystack, resume)
            .expect("later true candidate");
        assert_eq!(second, 9);
        assert!(exact_at(second));
        assert_eq!(
            MandatoryTeddyPlan::resume_after_rejection(first, Some(7)),
            Some(7)
        );
        assert_eq!(
            MandatoryTeddyPlan::resume_after_rejection(first, Some(first)),
            Some(first + 1)
        );
    }

    #[test]
    fn malformed_or_structurally_weaker_sets_decline_without_partial_output() {
        assert!(derive_from_accessor(0, 0, |_| None).is_none());
        let shallow = [b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec(), b"dd".to_vec()];
        assert!(derive_from_accessor(shallow.len(), 2, |index| {
            shallow.get(index).map(Vec::as_slice)
        })
        .is_none());
        let inconsistent = [
            b"abc".to_vec(),
            b"def".to_vec(),
            b"ghi".to_vec(),
            b"long".to_vec(),
        ];
        assert!(derive_from_accessor(inconsistent.len(), 3, |index| {
            inconsistent.get(index).map(Vec::as_slice)
        })
        .is_none());
    }

    #[test]
    fn structural_cost_gate_requires_a_material_win_and_models_every_isa() {
        let literals = [
            b"ant".to_vec(),
            b"bee".to_vec(),
            b"cat".to_vec(),
            b"dog".to_vec(),
            b"eel".to_vec(),
            b"fox".to_vec(),
            b"gnu".to_vec(),
            b"hen".to_vec(),
            b"ibx".to_vec(),
            b"jay".to_vec(),
            b"koi".to_vec(),
            b"lyn".to_vec(),
        ];
        let portfolio = portfolio(&literals);
        let selective = MandatoryTeddySelectionCosts {
            verification_units: 128,
            incumbent_primary: MandatoryTeddyIncumbentCosts {
                candidate_upper_bound: 1,
                candidate_space: 4,
                scan_instruction_units: 48,
                block_bytes: 32,
                table_bytes: 8_192,
            },
            incumbent_refined: MandatoryTeddyIncumbentCosts {
                candidate_upper_bound: 1,
                candidate_space: 4,
                scan_instruction_units: 48,
                block_bytes: 32,
                table_bytes: 8_192,
            },
        };
        for isa in [
            MandatoryTeddyIsa::X86Avx2,
            MandatoryTeddyIsa::X86Avx512Bw,
            MandatoryTeddyIsa::Aarch64Asimd,
            MandatoryTeddyIsa::Aarch64Sve,
            MandatoryTeddyIsa::Aarch64Sve2,
        ] {
            let selected = portfolio.select(isa, selective).expect("material Teddy win");
            assert!((3..=4).contains(&selected.columns()));
        }
        let slim = portfolio
            .plans()
            .copied()
            .find(|plan| plan.bank_count() == 1)
            .expect("slim plan");
        let fat = portfolio
            .plans()
            .copied()
            .find(|plan| plan.bank_count() == 2)
            .expect("fat plan");
        assert_eq!(
            teddy_retained_table_bytes(slim, MandatoryTeddyIsa::X86Avx2),
            slim.table_bytes()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(32))
        );
        assert_eq!(
            teddy_retained_table_bytes(fat, MandatoryTeddyIsa::X86Avx2),
            fat.table_bytes().checked_add(32)
        );
        assert_eq!(
            teddy_retained_table_bytes(slim, MandatoryTeddyIsa::Aarch64Asimd),
            Some(slim.table_bytes())
        );
        assert_eq!(
            teddy_tier_units(slim, MandatoryTeddyIsa::Aarch64Asimd),
            teddy_tier_units(slim, MandatoryTeddyIsa::X86Avx2)
                .and_then(|units| units.checked_sub(u16::from(slim.columns())))
        );
        assert_eq!(
            teddy_tier_units(slim, MandatoryTeddyIsa::Aarch64Sve2),
            teddy_tier_units(slim, MandatoryTeddyIsa::Aarch64Asimd),
            "SVE2 TBL reuse must not claim a MATCH discount"
        );
        let incumbent_wins = MandatoryTeddySelectionCosts {
            verification_units: 1,
            incumbent_primary: MandatoryTeddyIncumbentCosts {
                candidate_upper_bound: 1,
                candidate_space: u64::MAX,
                scan_instruction_units: 1,
                block_bytes: 64,
                table_bytes: 0,
            },
            incumbent_refined: MandatoryTeddyIncumbentCosts {
                candidate_upper_bound: 1,
                candidate_space: u64::MAX,
                scan_instruction_units: 1,
                block_bytes: 64,
                table_bytes: 0,
            },
        };
        assert!(portfolio
            .select(MandatoryTeddyIsa::X86Avx2, incumbent_wins)
            .is_none());

        let refined_only_win = MandatoryTeddySelectionCosts {
            incumbent_primary: incumbent_wins.incumbent_primary,
            incumbent_refined: selective.incumbent_refined,
            ..selective
        };
        assert!(portfolio
            .select(MandatoryTeddyIsa::X86Avx2, refined_only_win)
            .is_none());
    }

    #[test]
    fn scanner_score_charges_instruction_units_per_explicit_block() {
        let score_16 = scanner_score(0, 1, 10, 16, 0, 0, 1).expect("16-byte score");
        let score_32 = scanner_score(0, 1, 10, 32, 0, 0, 1).expect("32-byte score");
        let score_64 = scanner_score(0, 1, 10, 64, 0, 0, 1).expect("64-byte score");
        assert_eq!(score_16, 160);
        assert_eq!(score_32, 80);
        assert_eq!(score_64, 40);
    }

}
