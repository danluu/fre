//! Deterministic, bounded enumeration for small differential cases.

use crate::{ByteRange, CaseAst, Greed, Outcome, RefusalKind};

/// Independent caps for corpus construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneratorLimits {
    /// Maximum retained patterns.
    pub max_patterns: usize,
    /// Maximum retained haystacks.
    pub max_haystacks: usize,
    /// Maximum haystack length over the fixed `{a,b}` alphabet.
    pub max_haystack_len: usize,
    /// Maximum retained Cartesian-product comparisons.
    pub max_comparisons: usize,
}

impl Default for GeneratorLimits {
    fn default() -> Self {
        Self {
            max_patterns: 256,
            max_haystacks: 256,
            max_haystack_len: 4,
            max_comparisons: 16_384,
        }
    }
}

/// A reproducible corpus. `truncated` means caps prevented exhaustive retention
/// and callers must not describe the run as exhaustive over the planned set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedCorpus {
    pub seed: u64,
    pub patterns: Vec<CaseAst>,
    pub haystacks: Vec<Vec<u8>>,
    pub planned_patterns: usize,
    pub planned_haystacks: usize,
    pub truncated: bool,
}

/// Enumerate a finite grammar and every `{a,b}` haystack up to the requested
/// length. The seed changes deterministic visitation order, not membership.
///
/// This grammar includes atoms, all ordered atom pairs under concatenation and
/// alternation, finite optional repetitions, and non-nullable stars. Nullable
/// unbounded loops live in the persisted regression corpus instead because the
/// direct K0 adapter explicitly rejects them.
#[must_use]
pub fn generate_small_exhaustive(seed: u64, limits: GeneratorLimits) -> Outcome<GeneratedCorpus> {
    if limits.max_haystack_len > 16 {
        return Outcome::Refused(RefusalKind::HaystackBytes);
    }
    let atoms = vec![
        CaseAst::Empty,
        CaseAst::Byte(b'a'),
        CaseAst::Byte(b'b'),
        CaseAst::Class(vec![ByteRange::new(b'a', b'b')]),
        CaseAst::StartText,
        CaseAst::EndText,
    ];
    let mut patterns = atoms.clone();
    if patterns.try_reserve_exact(90).is_err() {
        return Outcome::Refused(RefusalKind::Allocation);
    }
    for left in &atoms {
        for right in &atoms {
            patterns.push(CaseAst::Concat(vec![left.clone(), right.clone()]));
            patterns.push(CaseAst::Alt(vec![left.clone(), right.clone()]));
        }
    }
    for atom in &atoms {
        for greed in [Greed::Greedy, Greed::Lazy] {
            patterns.push(CaseAst::Repeat {
                child: Box::new(atom.clone()),
                min: 0,
                max: Some(1),
                greed,
            });
        }
    }
    for atom in atoms.iter().skip(1).take(3) {
        for greed in [Greed::Greedy, Greed::Lazy] {
            patterns.push(CaseAst::Repeat {
                child: Box::new(atom.clone()),
                min: 0,
                max: None,
                greed,
            });
        }
    }

    let haystacks = match binary_words(limits.max_haystack_len) {
        Ok(words) => words,
        Err(outcome) => return outcome,
    };
    let planned_patterns = patterns.len();
    let planned_haystacks = haystacks.len();
    reorder(&mut patterns, seed ^ 0x5041_5454_4552_4e53);
    let mut haystacks = haystacks;
    reorder(&mut haystacks, seed ^ 0x4841_5953_5441_434b);
    patterns.truncate(limits.max_patterns);
    haystacks.truncate(limits.max_haystacks);

    let retained = patterns
        .len()
        .checked_mul(haystacks.len())
        .ok_or(RefusalKind::Arithmetic);
    let retained = match retained {
        Ok(value) => value,
        Err(kind) => return Outcome::Refused(kind),
    };
    let mut truncated = patterns.len() < planned_patterns || haystacks.len() < planned_haystacks;
    if retained > limits.max_comparisons {
        let allowed_patterns = limits
            .max_comparisons
            .checked_div(haystacks.len().max(1))
            .expect("positive divisor");
        patterns.truncate(allowed_patterns);
        truncated = true;
    }
    Outcome::Value(GeneratedCorpus {
        seed,
        patterns,
        haystacks,
        planned_patterns,
        planned_haystacks,
        truncated,
    })
}

fn binary_words(max_len: usize) -> Result<Vec<Vec<u8>>, Outcome<GeneratedCorpus>> {
    let shift = u32::try_from(max_len)
        .map_err(|_| Outcome::Refused(RefusalKind::Arithmetic))?
        .checked_add(1)
        .ok_or(Outcome::Refused(RefusalKind::Arithmetic))?;
    let planned = 1_usize
        .checked_shl(shift)
        .and_then(|value| value.checked_sub(1))
        .ok_or(Outcome::Refused(RefusalKind::Arithmetic))?;
    let mut words = Vec::new();
    words
        .try_reserve_exact(planned)
        .map_err(|_| Outcome::Refused(RefusalKind::Allocation))?;
    for length in 0..=max_len {
        let length_shift =
            u32::try_from(length).map_err(|_| Outcome::Refused(RefusalKind::Arithmetic))?;
        let count = 1_usize
            .checked_shl(length_shift)
            .ok_or(Outcome::Refused(RefusalKind::Arithmetic))?;
        for encoded in 0..count {
            let mut word = Vec::new();
            word.try_reserve_exact(length)
                .map_err(|_| Outcome::Refused(RefusalKind::Allocation))?;
            for bit in (0..length).rev() {
                let byte = if encoded & (1_usize << bit) == 0 {
                    b'a'
                } else {
                    b'b'
                };
                word.push(byte);
            }
            words.push(word);
        }
    }
    Ok(words)
}

fn reorder<T>(values: &mut [T], seed: u64) {
    if values.len() < 2 {
        return;
    }
    let mut state = seed;
    for index in (1..values.len()).rev() {
        state = xorshift64(state);
        let modulus = u64::try_from(index.checked_add(1).expect("bounded slice index"))
            .expect("slice indices fit u64");
        let selected = usize::try_from(state.checked_rem(modulus).expect("positive modulus"))
            .expect("selection fits usize");
        values.swap(index, selected);
    }
}

const fn xorshift64(mut value: u64) -> u64 {
    if value == 0 {
        value = 0x9e37_79b9_7f4a_7c15;
    }
    value ^= value << 13;
    value ^= value >> 7;
    value ^ (value << 17)
}
