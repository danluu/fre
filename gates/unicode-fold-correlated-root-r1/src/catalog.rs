use std::collections::{BTreeMap, BTreeSet};

pub const CATALOG_TEXT: &str = include_str!("../catalog.tsv");
pub const CATALOG_SCHEMA: &str = "fre.unicode-fold-correlated-root-gate.v2";
pub const UNICODE_VERSION: &str = "16.0.0";
pub const UNICODE_TABLE_SHA256: &str =
    "7622c7f7f03ac0dc2f2bcd51c81a217d64de0cc912f62f1add5f676603a02456";

pub const EXPECTED_CATALOG_FNV64: u64 = 0x5871_7f6d_97c0_89b2;

#[derive(Clone, Debug)]
pub struct FoldClass {
    pub id: String,
    pub members: Vec<char>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Placement {
    Prefix,
    Middle,
    Suffix,
}

impl Placement {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::Middle => "middle",
            Self::Suffix => "suffix",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecipeSpec {
    pub id: String,
    pub utf8_profile: String,
    pub placement: Placement,
    pub explicit_guard: bool,
    pub requested_primary_cardinality: usize,
    pub primary_local_offset: usize,
    pub tuple_local_start: usize,
    pub tuple_width: usize,
    pub bucket_budget: usize,
    pub structural_facts: Vec<String>,
}

#[derive(Debug)]
pub struct FrozenCatalog {
    pub checksum: u64,
    pub metadata: BTreeMap<String, String>,
    pub sentinels: BTreeMap<String, char>,
    pub facts: BTreeMap<String, FoldClass>,
    pub recipes: Vec<RecipeSpec>,
}

impl FrozenCatalog {
    pub fn parse() -> Self {
        let checksum = fnv1a64(CATALOG_TEXT.as_bytes());
        assert_eq!(
            checksum, EXPECTED_CATALOG_FNV64,
            "the frozen structural catalog changed without a schema revision"
        );

        let mut metadata = BTreeMap::new();
        let mut sentinels = BTreeMap::new();
        let mut facts = BTreeMap::new();
        let mut recipes = Vec::new();
        for (line_index, raw) in CATALOG_TEXT.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            match fields.first().copied() {
                Some("meta") => {
                    assert_eq!(fields.len(), 3, "catalog meta line {}", line_index + 1);
                    assert!(
                        metadata
                            .insert(fields[1].to_owned(), fields[2].to_owned())
                            .is_none(),
                        "duplicate catalog metadata key {}",
                        fields[1]
                    );
                }
                Some("sentinel") => {
                    assert_eq!(
                        fields.len(),
                        3,
                        "catalog sentinel line {}",
                        line_index + 1
                    );
                    let scalar = parse_scalar(fields[2]);
                    assert!(
                        sentinels.insert(fields[1].to_owned(), scalar).is_none(),
                        "duplicate sentinel {}",
                        fields[1]
                    );
                }
                Some("fact") => {
                    assert_eq!(fields.len(), 3, "catalog fact line {}", line_index + 1);
                    let members = fields[2].split(',').map(parse_scalar).collect::<Vec<_>>();
                    assert!(members.len() >= 2, "fold class {} is trivial", fields[1]);
                    assert!(
                        members.windows(2).all(|pair| pair[0] < pair[1]),
                        "fold class {} is not canonical",
                        fields[1]
                    );
                    let class = FoldClass {
                        id: fields[1].to_owned(),
                        members,
                    };
                    assert!(
                        facts.insert(class.id.clone(), class).is_none(),
                        "duplicate fact {}",
                        fields[1]
                    );
                }
                Some("recipe") => {
                    assert_eq!(
                        fields.len(),
                        11,
                        "catalog recipe line {}",
                        line_index + 1
                    );
                    let placement = match fields[3] {
                        "prefix" => Placement::Prefix,
                        "middle" => Placement::Middle,
                        "suffix" => Placement::Suffix,
                        other => panic!("unknown placement {other}"),
                    };
                    let explicit_guard = match fields[4] {
                        "true" => true,
                        "false" => false,
                        other => panic!("unknown guard flag {other}"),
                    };
                    recipes.push(RecipeSpec {
                        id: fields[1].to_owned(),
                        utf8_profile: fields[2].to_owned(),
                        placement,
                        explicit_guard,
                        requested_primary_cardinality: parse_usize(fields[5], "primary cardinality"),
                        primary_local_offset: parse_usize(fields[6], "primary offset"),
                        tuple_local_start: parse_usize(fields[7], "tuple start"),
                        tuple_width: parse_usize(fields[8], "tuple width"),
                        bucket_budget: parse_usize(fields[9], "bucket budget"),
                        structural_facts: fields[10].split(',').map(str::to_owned).collect(),
                    });
                }
                Some(other) => panic!("unknown catalog record {other} at line {}", line_index + 1),
                None => unreachable!("an empty catalog line was already skipped"),
            }
        }

        assert_eq!(metadata.get("schema").map(String::as_str), Some(CATALOG_SCHEMA));
        assert_eq!(
            metadata.get("unicode_version").map(String::as_str),
            Some(UNICODE_VERSION)
        );
        assert_eq!(
            metadata.get("unicode_table_sha256").map(String::as_str),
            Some(UNICODE_TABLE_SHA256)
        );
        assert_eq!(recipes.len(), 8, "the bounded v2 catalog has eight recipes");
        for sentinel in ["guard", "background", "separator", "deep_mismatch"] {
            assert!(sentinels.contains_key(sentinel), "missing sentinel {sentinel}");
        }
        for recipe in &recipes {
            assert!((2..=4).contains(&recipe.tuple_width));
            assert!([1, 2, 4, 8].contains(&recipe.bucket_budget));
            for fact in &recipe.structural_facts {
                assert!(facts.contains_key(fact), "recipe {} misses fact {fact}", recipe.id);
            }
        }
        for tag in ["ascii_0", "ascii_1", "ascii_2", "ascii_3", "ascii_4"] {
            assert!(facts.contains_key(tag), "missing deterministic tag fact {tag}");
        }

        let mut owners = BTreeMap::<char, &str>::new();
        for class in facts.values() {
            for &member in &class.members {
                if let Some(previous) = owners.insert(member, &class.id) {
                    panic!(
                        "scalar U+{:04X} occurs in both {previous} and {}",
                        u32::from(member),
                        class.id
                    );
                }
            }
        }
        let sentinel_set = sentinels.values().copied().collect::<BTreeSet<_>>();
        assert_eq!(sentinel_set.len(), sentinels.len());
        assert!(
            sentinel_set.iter().all(|scalar| !owners.contains_key(scalar)),
            "sentinels must be invariant under the frozen fold facts"
        );

        Self {
            checksum,
            metadata,
            sentinels,
            facts,
            recipes,
        }
    }

    pub fn fact(&self, id: &str) -> &FoldClass {
        self.facts
            .get(id)
            .unwrap_or_else(|| panic!("catalog fact {id} disappeared"))
    }

    pub fn sentinel(&self, id: &str) -> char {
        *self
            .sentinels
            .get(id)
            .unwrap_or_else(|| panic!("catalog sentinel {id} disappeared"))
    }

    pub fn saturation_atoms(&self) -> usize {
        parse_usize(
            self.metadata
                .get("saturation_fold_atoms")
                .expect("catalog saturation count disappeared"),
            "saturation atom count",
        )
    }

    pub fn semantic_spacings(&self) -> Vec<usize> {
        parse_usize_list(
            self.metadata
                .get("semantic_spacing")
                .expect("catalog semantic spacings disappeared"),
        )
    }

    pub fn timing_sizes(&self) -> Vec<usize> {
        parse_usize_list(
            self.metadata
                .get("timing_sizes")
                .expect("catalog timing sizes disappeared"),
        )
    }
}

pub const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        index += 1;
    }
    hash
}

fn parse_scalar(raw: &str) -> char {
    let value = u32::from_str_radix(raw, 16)
        .unwrap_or_else(|error| panic!("invalid scalar {raw}: {error}"));
    char::from_u32(value).unwrap_or_else(|| panic!("non-scalar code point {raw}"))
}

fn parse_usize(raw: &str, label: &str) -> usize {
    raw.parse::<usize>()
        .unwrap_or_else(|error| panic!("invalid {label} {raw}: {error}"))
}

fn parse_usize_list(raw: &str) -> Vec<usize> {
    raw.split(',')
        .map(|value| parse_usize(value, "integer list member"))
        .collect()
}
