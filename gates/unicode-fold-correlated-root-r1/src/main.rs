#![forbid(unsafe_code)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "all catalog geometry is checked or bounded by the frozen source manifest"
)]

#[cfg(all(feature = "zstd-eval-arm-static", feature = "portable-dispatch"))]
compile_error!("select exactly one dispatch profile");
#[cfg(not(any(feature = "zstd-eval-arm-static", feature = "portable-dispatch")))]
compile_error!("select an explicit dispatch profile");

mod catalog;
mod oracle;

use std::{
    collections::BTreeSet,
    env,
    hint::black_box,
};

use catalog::{FrozenCatalog, Placement, RecipeSpec};
use fre::{
    PlanKind, PortableBuilder, PortableFindIterLimits, PortableRegex, SearchLimits, SearchWindow,
};
use oracle::{Atom, Branch, Oracle};

const TIMING_TARGET_BYTES: usize = 8 << 20;
const TIMING_MIN_ITERATIONS: usize = 64;
const TIMING_MAX_ITERATIONS: usize = 16_384;
const TIMING_WARMUP_ITERATIONS: usize = 32;

#[cfg(feature = "zstd-eval-arm-static")]
const DISPATCH_PROFILE: &str = "static-dispatch-arm-41-d84";
#[cfg(feature = "portable-dispatch")]
const DISPATCH_PROFILE: &str = "portable-dispatch";

#[derive(Clone, Debug)]
struct Recipe {
    spec: RecipeSpec,
    branches: Vec<Branch>,
    pattern: String,
    primary_offset: usize,
    tuple_start: usize,
}

impl Recipe {
    fn minimum_bytes(&self) -> usize {
        self.branches
            .iter()
            .map(Branch::minimum_bytes)
            .min()
            .expect("a recipe has at least one branch")
    }

    fn maximum_bytes(&self) -> usize {
        self.branches
            .iter()
            .map(Branch::maximum_bytes)
            .max()
            .expect("a recipe has at least one branch")
    }
}

#[derive(Clone, Debug)]
struct Decoy {
    bytes: Vec<u8>,
    valid_utf8: bool,
}

#[derive(Debug)]
struct TupleModel {
    exact_tuples: BTreeSet<Vec<u8>>,
    column_cardinalities: Vec<usize>,
    product_cardinality: usize,
    observed_primary_cardinality: usize,
    correlated_reject: Option<Decoy>,
    bucket_alias: Option<Decoy>,
    cross_product: Option<Decoy>,
    primary_unit: Vec<u8>,
    deep_unit: Vec<u8>,
    true_unit: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    ZeroPrimary,
    PrimaryStorm,
    TupleRejectStorm,
    BucketAliasStorm,
    DeepRejectStorm,
    EarlyMatch,
    MiddleMatch,
    LateMatch,
    DenseMatches,
}

impl Shape {
    const TIMED: [Self; 6] = [
        Self::ZeroPrimary,
        Self::TupleRejectStorm,
        Self::BucketAliasStorm,
        Self::DeepRejectStorm,
        Self::LateMatch,
        Self::DenseMatches,
    ];

    const STRUCTURAL: [Self; 9] = [
        Self::ZeroPrimary,
        Self::PrimaryStorm,
        Self::TupleRejectStorm,
        Self::BucketAliasStorm,
        Self::DeepRejectStorm,
        Self::EarlyMatch,
        Self::MiddleMatch,
        Self::LateMatch,
        Self::DenseMatches,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::ZeroPrimary => "zero_primary",
            Self::PrimaryStorm => "primary_storm",
            Self::TupleRejectStorm => "tuple_reject_storm",
            Self::BucketAliasStorm => "bucket_alias_storm",
            Self::DeepRejectStorm => "deep_reject_storm",
            Self::EarlyMatch => "early_match",
            Self::MiddleMatch => "middle_match",
            Self::LateMatch => "late_match",
            Self::DenseMatches => "dense_matches",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    IsMatch,
    Find,
    FindAt,
    ExactWindow,
    Iterate,
}

impl Operation {
    const ALL: [Self; 5] = [
        Self::IsMatch,
        Self::Find,
        Self::FindAt,
        Self::ExactWindow,
        Self::Iterate,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::IsMatch => "is_match_value",
            Self::Find => "find_value",
            Self::FindAt => "find_at_value",
            Self::ExactWindow => "find_window_value",
            Self::Iterate => "find_iter",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SearchFrame {
    find_at: usize,
    window_start: usize,
    window_end: usize,
}

#[derive(Clone, Copy, Debug)]
struct TimingTask {
    recipe_index: usize,
    shape: Shape,
    size: usize,
    operation: Operation,
}

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let command = arguments.first().map_or("verify", String::as_str);
    match command {
        "catalog" if arguments.len() == 1 => emit_catalog(),
        "verify" if arguments.len() == 1 => verify_all(),
        "task-count" if arguments.len() == 1 => emit_task_count(),
        "time" if arguments.len() == 3 => {
            let task = parse_argument(&arguments[1], "task index");
            let sample = parse_argument(&arguments[2], "sample index");
            time_task(task, sample);
        }
        _ => {
            eprintln!("usage: correlated-root-gate [catalog|verify|task-count|time TASK SAMPLE]");
            std::process::exit(2);
        }
    }
}

fn materialize_recipes(catalog: &FrozenCatalog) -> Vec<Recipe> {
    let filler = catalog.fact("ascii_0").members.clone();
    let selector_stop = catalog.fact("mixed_0").members.clone();
    let guard = catalog.sentinel("guard");
    let saturation = catalog.saturation_atoms();
    catalog
        .recipes
        .iter()
        .map(|spec| {
            let mut branches = Vec::with_capacity(spec.structural_facts.len());
            for (branch_index, fact_id) in spec.structural_facts.iter().enumerate() {
                let tag_id = format!("ascii_{branch_index}");
                let tag = catalog.fact(&tag_id).members.clone();
                let mut atoms = Vec::new();
                atoms.push(Atom::Fold(catalog.fact(fact_id).members.clone()));
                if spec.explicit_guard {
                    atoms.push(Atom::Fold(tag.clone()));
                }
                // This mixed-width folded class is realistic successor
                // structure and ends fixed-column enumeration before the
                // saturation tail can compete with the frozen root.
                atoms.push(Atom::Fold(selector_stop.clone()));
                if spec.explicit_guard {
                    atoms.push(Atom::Exact(guard));
                }
                for _ in 0..saturation {
                    atoms.push(Atom::Fold(filler.clone()));
                }
                atoms.push(Atom::Fold(tag));
                branches.push(Branch { atoms });
            }
            let pattern = pattern_for(&branches);
            let recipe = Recipe {
                spec: spec.clone(),
                branches,
                pattern,
                primary_offset: spec.primary_local_offset,
                tuple_start: spec.tuple_local_start,
            };
            audit_recipe_source(&recipe);
            recipe
        })
        .collect()
}

fn audit_recipe_source(recipe: &Recipe) {
    for branch in &recipe.branches {
        let Some(Atom::Fold(root)) = branch.atoms.first() else {
            panic!("recipe {} lacks a folded root", recipe.spec.id);
        };
        assert!(root.len() > 1, "recipe {} root is not folded", recipe.spec.id);
        assert!(
            root.iter().any(|scalar| !scalar.is_ascii()),
            "recipe {} root has no non-ASCII member",
            recipe.spec.id
        );
        assert!(
            root.iter()
                .all(|scalar| scalar.len_utf8() > recipe.primary_offset),
            "recipe {} primary is not present in every root expansion",
            recipe.spec.id
        );
        let stop_index = 1 + usize::from(recipe.spec.explicit_guard);
        let Some(Atom::Fold(stop)) = branch.atoms.get(stop_index) else {
            panic!("recipe {} lacks its selector stop", recipe.spec.id);
        };
        assert_ne!(
            stop.iter().map(|scalar| scalar.len_utf8()).min(),
            stop.iter().map(|scalar| scalar.len_utf8()).max(),
            "recipe {} selector stop is not variable width",
            recipe.spec.id
        );
    }
    assert_eq!(recipe.tuple_start, 0, "the frozen tuple is root-relative");
    let primary_in_tuple = recipe
        .primary_offset
        .checked_sub(recipe.tuple_start)
        .expect("the primary lies inside the tuple");
    assert!(
        primary_in_tuple < recipe.spec.tuple_width,
        "recipe {} primary lies outside its tuple",
        recipe.spec.id
    );
    match recipe.spec.placement {
        Placement::Prefix => assert_eq!(primary_in_tuple, 0),
        Placement::Middle => assert!(
            primary_in_tuple > 0 && primary_in_tuple + 1 < recipe.spec.tuple_width,
            "recipe {} primary is not in the tuple middle",
            recipe.spec.id
        ),
        Placement::Suffix => assert_eq!(primary_in_tuple + 1, recipe.spec.tuple_width),
    }
}

fn pattern_for(branches: &[Branch]) -> String {
    let mut pattern = String::from("(?:");
    for (branch_index, branch) in branches.iter().enumerate() {
        if branch_index != 0 {
            pattern.push('|');
        }
        for atom in &branch.atoms {
            let representative = atom.representative(0);
            pattern.push_str(&format!("\\u{{{:X}}}", u32::from(representative)));
        }
    }
    pattern.push(')');
    pattern
}

fn tuple_model(catalog: &FrozenCatalog, recipe: &Recipe) -> TupleModel {
    let tuple_end = recipe
        .tuple_start
        .checked_add(recipe.spec.tuple_width)
        .expect("tuple end is bounded");
    let primary_end = recipe
        .primary_offset
        .checked_add(1)
        .expect("primary end is bounded");
    let needed = tuple_end.max(primary_end);
    let mut prefixes = BTreeSet::new();
    for branch in &recipe.branches {
        collect_prefixes(branch, needed, &mut prefixes);
    }
    assert!(!prefixes.is_empty(), "recipe {} has no byte prefixes", recipe.spec.id);

    let exact_tuples = prefixes
        .iter()
        .map(|prefix| prefix[recipe.tuple_start..tuple_end].to_vec())
        .collect::<BTreeSet<_>>();
    let observed_primary_cardinality = prefixes
        .iter()
        .map(|prefix| prefix[recipe.primary_offset])
        .collect::<BTreeSet<_>>()
        .len();
    assert_eq!(
        observed_primary_cardinality,
        recipe.spec.requested_primary_cardinality,
        "recipe {} no longer has its frozen primary cardinality",
        recipe.spec.id
    );

    let mut columns = vec![BTreeSet::<u8>::new(); recipe.spec.tuple_width];
    for tuple in &exact_tuples {
        for (column, &byte) in tuple.iter().enumerate() {
            columns[column].insert(byte);
        }
    }
    let column_cardinalities = columns.iter().map(BTreeSet::len).collect::<Vec<_>>();
    let product_cardinality = column_cardinalities
        .iter()
        .try_fold(1_usize, |product, &cardinality| {
            product.checked_mul(cardinality)
        })
        .expect("the bounded tuple product fits usize");
    assert!(product_cardinality <= 65_536, "tuple product escaped the frozen cap");

    let mut bucket_columns = vec![[0_u8; 256]; recipe.spec.tuple_width];
    for (tuple_index, tuple) in exact_tuples.iter().enumerate() {
        let bucket = tuple_index % recipe.spec.bucket_budget;
        let bit = 1_u8 << bucket;
        for (column, &byte) in tuple.iter().enumerate() {
            bucket_columns[column][usize::from(byte)] |= bit;
        }
    }

    let oracle = Oracle::new(&recipe.branches);
    let base = recipe.branches[0].representative_bytes(0);
    let mut correlated_valid = None;
    let mut correlated_any = None;
    let mut alias_valid = None;
    let mut alias_any = None;
    let mut cross_valid = None;
    let mut cross_any = None;
    let column_values = columns
        .iter()
        .map(|column| column.iter().copied().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    enumerate_product(&column_values, &mut |tuple| {
        if exact_tuples.contains(tuple) {
            return;
        }
        let mut candidate = base.clone();
        candidate[recipe.tuple_start..tuple_end].copy_from_slice(tuple);
        if oracle.find(&candidate).is_some() {
            return;
        }
        let decoy = Decoy {
            valid_utf8: std::str::from_utf8(&candidate).is_ok(),
            bytes: candidate,
        };
        retain_decoy(&mut cross_valid, &mut cross_any, decoy.clone());
        let mut mask = u8::MAX;
        for (column, &byte) in tuple.iter().enumerate() {
            mask &= bucket_columns[column][usize::from(byte)];
        }
        if mask == 0 {
            retain_decoy(&mut correlated_valid, &mut correlated_any, decoy);
        } else {
            retain_decoy(&mut alias_valid, &mut alias_any, decoy);
        }
    });

    let background = encode_scalar(catalog.sentinel("background"));
    assert_eq!(background.len(), 1, "the structural background is ASCII");
    let mut primary_unit = base;
    let reject_offset = recipe
        .primary_offset
        .checked_add(1)
        .filter(|&offset| offset < primary_unit.len())
        .unwrap_or_else(|| recipe.primary_offset.saturating_sub(1));
    primary_unit[reject_offset] = background[0];
    assert!(oracle.find(&primary_unit).is_none());

    let mut deep_unit = recipe.branches[0].representative_bytes(1);
    let mismatch = encode_scalar(catalog.sentinel("deep_mismatch"));
    assert_eq!(mismatch.len(), 1, "the deep mismatch sentinel is ASCII");
    let tail = deep_unit
        .last_mut()
        .expect("the non-empty structural literal has a tail");
    *tail = mismatch[0];
    assert!(oracle.find(&deep_unit).is_none());

    let true_branch = recipe.branches.len() - 1;
    let true_unit = recipe.branches[true_branch].representative_bytes(3 + true_branch);
    assert_eq!(oracle.find(&true_unit), Some((0, true_unit.len())));

    TupleModel {
        exact_tuples,
        column_cardinalities,
        product_cardinality,
        observed_primary_cardinality,
        correlated_reject: correlated_valid.or(correlated_any),
        bucket_alias: alias_valid.or(alias_any),
        cross_product: cross_valid.or(cross_any),
        primary_unit,
        deep_unit,
        true_unit,
    }
}

fn collect_prefixes(branch: &Branch, needed: usize, output: &mut BTreeSet<Vec<u8>>) {
    fn visit(
        atoms: &[Atom],
        atom_index: usize,
        needed: usize,
        bytes: &mut Vec<u8>,
        output: &mut BTreeSet<Vec<u8>>,
    ) {
        if bytes.len() >= needed {
            output.insert(bytes[..needed].to_vec());
            return;
        }
        let atom = atoms
            .get(atom_index)
            .expect("every frozen branch reaches its tuple window");
        for &scalar in atom.members() {
            let previous = bytes.len();
            let mut encoded = [0_u8; 4];
            bytes.extend_from_slice(scalar.encode_utf8(&mut encoded).as_bytes());
            visit(atoms, atom_index + 1, needed, bytes, output);
            bytes.truncate(previous);
        }
    }

    visit(&branch.atoms, 0, needed, &mut Vec::new(), output);
}

fn enumerate_product<F>(columns: &[Vec<u8>], emit: &mut F)
where
    F: FnMut(&[u8]),
{
    fn visit<F>(columns: &[Vec<u8>], column: usize, tuple: &mut Vec<u8>, emit: &mut F)
    where
        F: FnMut(&[u8]),
    {
        if column == columns.len() {
            emit(tuple);
            return;
        }
        for &byte in &columns[column] {
            tuple.push(byte);
            visit(columns, column + 1, tuple, emit);
            tuple.pop();
        }
    }

    visit(columns, 0, &mut Vec::new(), emit);
}

fn retain_decoy(valid: &mut Option<Decoy>, any: &mut Option<Decoy>, decoy: Decoy) {
    if any.is_none() {
        *any = Some(decoy.clone());
    }
    if decoy.valid_utf8 && valid.is_none() {
        *valid = Some(decoy);
    }
}

fn encode_scalar(scalar: char) -> Vec<u8> {
    let mut encoded = [0_u8; 4];
    scalar.encode_utf8(&mut encoded).as_bytes().to_vec()
}

fn build_regex(recipe: &Recipe) -> PortableRegex {
    let regex = PortableBuilder::new(&recipe.pattern)
        .unicode(true)
        .case_insensitive(true)
        .build()
        .unwrap_or_else(|error| panic!("recipe {} failed to build: {error}", recipe.spec.id));
    assert_eq!(
        regex.build_report().plan,
        PlanKind::UnicodeFoldedLiteral,
        "recipe {} escaped the folded-literal route",
        recipe.spec.id
    );
    let accounting = regex
        .unicode_folded_literal_build_accounting()
        .unwrap_or_else(|| {
            panic!(
                "recipe {} lost folded construction accounting",
                recipe.spec.id
            )
        });
    assert_eq!(
        accounting.trie.root_prefilter_offset,
        Some(recipe.primary_offset),
        "recipe {} selected a different root-prefilter offset than the frozen geometry",
        recipe.spec.id
    );
    assert_eq!(
        accounting.trie.root_prefilter_needles,
        recipe.spec.requested_primary_cardinality,
        "recipe {} selected a different root-prefilter cardinality than the frozen geometry",
        recipe.spec.id
    );
    regex
}

fn build_haystack(
    catalog: &FrozenCatalog,
    model: &TupleModel,
    shape: Shape,
    size: usize,
    alignment: usize,
    spacing: usize,
) -> Vec<u8> {
    let background = encode_scalar(catalog.sentinel("background"));
    let separator = encode_scalar(catalog.sentinel("separator"));
    assert_eq!(background.len(), 1);
    assert_eq!(separator.len(), 1);
    let background = background[0];
    let separator = separator[0];
    match shape {
        Shape::ZeroPrimary => vec![background; size],
        Shape::PrimaryStorm => storm(size, alignment, spacing, &model.primary_unit, background),
        Shape::TupleRejectStorm => {
            let unit = model
                .correlated_reject
                .as_ref()
                .or(model.cross_product.as_ref())
                .map_or(model.primary_unit.as_slice(), |decoy| decoy.bytes.as_slice());
            storm(size, alignment, spacing, unit, background)
        }
        Shape::BucketAliasStorm => {
            let unit = model
                .bucket_alias
                .as_ref()
                .or(model.cross_product.as_ref())
                .map_or(model.deep_unit.as_slice(), |decoy| decoy.bytes.as_slice());
            storm(size, alignment, spacing, unit, background)
        }
        Shape::DeepRejectStorm => storm(size, alignment, spacing, &model.deep_unit, background),
        Shape::EarlyMatch => single_match(size, alignment, 0, &model.true_unit, background),
        Shape::MiddleMatch => single_match(size, alignment, 1, &model.true_unit, background),
        Shape::LateMatch => single_match(size, alignment, 2, &model.true_unit, background),
        Shape::DenseMatches => storm(size, alignment, spacing, &model.true_unit, separator),
    }
}

fn storm(size: usize, alignment: usize, spacing: usize, unit: &[u8], fill: u8) -> Vec<u8> {
    assert!(!unit.is_empty());
    let mut haystack = Vec::with_capacity(size);
    haystack.resize(alignment.min(size), fill);
    while haystack.len() < size {
        let remaining = size - haystack.len();
        let take = remaining.min(unit.len());
        haystack.extend_from_slice(&unit[..take]);
        if take != unit.len() {
            break;
        }
        let padding = spacing.min(size - haystack.len());
        haystack.resize(haystack.len() + padding, fill);
    }
    haystack.resize(size, fill);
    haystack
}

fn single_match(
    size: usize,
    alignment: usize,
    position_class: usize,
    matched: &[u8],
    background: u8,
) -> Vec<u8> {
    assert!(size >= matched.len());
    let available = size - matched.len();
    let aligned = alignment.min(available);
    let position = match position_class {
        0 => aligned,
        1 => aligned + (available - aligned) / 2,
        2 => aligned + ((available - aligned) * 3) / 4,
        _ => unreachable!("there are three frozen single-match positions"),
    };
    let mut haystack = vec![background; size];
    haystack[position..position + matched.len()].copy_from_slice(matched);
    haystack
}

fn verify_all() {
    let catalog = FrozenCatalog::parse();
    let recipes = materialize_recipes(&catalog);
    let mut checksum = catalog.checksum;
    let mut cases = 0_usize;
    let mut windows = 0_usize;
    for recipe in &recipes {
        let model = tuple_model(&catalog, recipe);
        let regex = build_regex(recipe);
        let oracle = Oracle::new(&recipe.branches);
        checksum = mix(checksum, verify_recipe(
            &catalog,
            recipe,
            &model,
            &regex,
            &oracle,
            &mut cases,
            &mut windows,
        ));
    }
    println!(
        "schema={} catalog_fnv64={:016x} dispatch={} recipes={} semantic_cases={} framed_windows={} result_checksum={:016x}",
        catalog::CATALOG_SCHEMA,
        catalog.checksum,
        DISPATCH_PROFILE,
        recipes.len(),
        cases,
        windows,
        checksum
    );
}

fn verify_recipe(
    catalog: &FrozenCatalog,
    recipe: &Recipe,
    model: &TupleModel,
    regex: &PortableRegex,
    oracle: &Oracle,
    cases: &mut usize,
    windows: &mut usize,
) -> u64 {
    let mut checksum = 0xcbf2_9ce4_8422_2325_u64;
    let maximum = recipe.maximum_bytes();
    let mut sizes = vec![
        maximum + 15,
        maximum + 16,
        maximum + 17,
        2 * maximum + 31,
        2 * maximum + 32,
        2 * maximum + 33,
        127,
        128,
        129,
        511,
        512,
        513,
        4_095,
        4_096,
        4_097,
    ];
    sizes.retain(|&size| size >= maximum);
    sizes.sort_unstable();
    sizes.dedup();
    for &size in &sizes {
        for &shape in &Shape::STRUCTURAL {
            let haystack = build_haystack(catalog, model, shape, size, 0, 3);
            let frame = SearchFrame {
                find_at: 0,
                window_start: 0,
                window_end: haystack.len(),
            };
            checksum = mix(
                checksum,
                verify_case(recipe, shape, regex, oracle, &haystack, frame),
            );
            *cases += 1;
        }
    }

    let aligned_size = 513_usize.max(maximum + 32);
    for alignment in 0..16 {
        for &shape in &[
            Shape::PrimaryStorm,
            Shape::TupleRejectStorm,
            Shape::DeepRejectStorm,
            Shape::LateMatch,
            Shape::DenseMatches,
        ] {
            let haystack = build_haystack(catalog, model, shape, aligned_size, alignment, 7);
            let frame = SearchFrame {
                find_at: alignment.min(haystack.len()),
                window_start: alignment.min(haystack.len()),
                window_end: haystack.len(),
            };
            checksum = mix(
                checksum,
                verify_case(recipe, shape, regex, oracle, &haystack, frame),
            );
            *cases += 1;
        }
    }

    for spacing in catalog.semantic_spacings() {
        for &shape in &[
            Shape::PrimaryStorm,
            Shape::TupleRejectStorm,
            Shape::BucketAliasStorm,
            Shape::DeepRejectStorm,
        ] {
            let size = 257_usize.max(maximum + 17);
            let haystack = build_haystack(catalog, model, shape, size, 0, spacing);
            checksum = mix(
                checksum,
                verify_case(
                    recipe,
                    shape,
                    regex,
                    oracle,
                    &haystack,
                    SearchFrame {
                        find_at: 0,
                        window_start: 0,
                        window_end: haystack.len(),
                    },
                ),
            );
            *cases += 1;
        }
    }

    let frame_size = 257_usize.max(maximum + 64);
    for &shape in &[
        Shape::TupleRejectStorm,
        Shape::DeepRejectStorm,
        Shape::LateMatch,
    ] {
        let haystack = build_haystack(catalog, model, shape, frame_size, 15, 1);
        for start_trim in 0..16 {
            for end_trim in 0..16 {
                let end = haystack.len() - end_trim;
                if start_trim > end {
                    continue;
                }
                let expected = oracle.find_window(&haystack, start_trim, end);
                let actual = regex
                    .find_window_value(
                        &haystack,
                        SearchWindow::new(start_trim, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "{} {} frame {}..{} failed: {error}",
                            recipe.spec.id,
                            shape.name(),
                            start_trim,
                            end
                        )
                    });
                assert_eq!(span(actual), expected);
                let exists = regex
                    .is_match_window_value(
                        &haystack,
                        SearchWindow::new(start_trim, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap();
                assert_eq!(exists, expected.is_some());
                checksum = mix(checksum, hash_span(expected));
                *windows += 1;
            }
        }
    }
    checksum
}

fn verify_case(
    recipe: &Recipe,
    shape: Shape,
    regex: &PortableRegex,
    oracle: &Oracle,
    haystack: &[u8],
    frame: SearchFrame,
) -> u64 {
    assert!(frame.find_at <= haystack.len());
    assert!(frame.window_start <= frame.window_end && frame.window_end <= haystack.len());
    let expected_find = oracle.find(haystack);
    let actual_find = regex
        .find_value(haystack, SearchLimits::unlimited())
        .unwrap_or_else(|error| panic!("{} {} find failed: {error}", recipe.spec.id, shape.name()));
    assert_eq!(span(actual_find), expected_find, "{} {} find", recipe.spec.id, shape.name());

    let actual_exists = regex
        .is_match_value(haystack, SearchLimits::unlimited())
        .unwrap_or_else(|error| {
            panic!("{} {} is_match failed: {error}", recipe.spec.id, shape.name())
        });
    assert_eq!(actual_exists, oracle.is_match(haystack));

    let expected_at = oracle.find_at(haystack, frame.find_at);
    let actual_at = regex
        .find_at_value(haystack, frame.find_at, SearchLimits::unlimited())
        .unwrap_or_else(|error| {
            panic!("{} {} find_at failed: {error}", recipe.spec.id, shape.name())
        });
    assert_eq!(span(actual_at), expected_at);

    let expected_window = oracle.find_window(haystack, frame.window_start, frame.window_end);
    let actual_window = regex
        .find_window_value(
            haystack,
            SearchWindow::new(frame.window_start, frame.window_end),
            SearchLimits::unlimited(),
        )
        .unwrap_or_else(|error| {
            panic!("{} {} window failed: {error}", recipe.spec.id, shape.name())
        });
    assert_eq!(span(actual_window), expected_window);

    let expected_matches = oracle.matches(haystack);
    let mut actual_matches = Vec::new();
    for result in regex
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .unwrap_or_else(|error| {
            panic!("{} {} iterator setup failed: {error}", recipe.spec.id, shape.name())
        })
    {
        let matched = result.unwrap_or_else(|error| {
            panic!("{} {} iterator failed: {error}", recipe.spec.id, shape.name())
        });
        actual_matches.push((matched.start(), matched.end()));
    }
    assert_eq!(actual_matches, expected_matches);

    let mut checksum = hash_span(expected_find);
    checksum = mix(checksum, bool_u64(actual_exists));
    checksum = mix(checksum, hash_span(expected_at));
    checksum = mix(checksum, hash_span(expected_window));
    for matched in expected_matches {
        checksum = mix(checksum, hash_span(Some(matched)));
    }
    checksum
}

fn emit_catalog() {
    let catalog = FrozenCatalog::parse();
    let recipes = materialize_recipes(&catalog);
    println!(
        "schema\tcatalog_fnv64\tunicode_version\tunicode_table_sha256\tdispatch\trecipes\ttasks"
    );
    println!(
        "{}\t{:016x}\t{}\t{}\t{}\t{}\t{}",
        catalog::CATALOG_SCHEMA,
        catalog.checksum,
        catalog::UNICODE_VERSION,
        catalog::UNICODE_TABLE_SHA256,
        DISPATCH_PROFILE,
        recipes.len(),
        timing_tasks(&catalog, &recipes).len()
    );
    println!(
        "recipe\tprofile\tplacement\texplicit_guard\tprimary_target\tprimary_observed\ttuple_width\tbucket_budget\texact_tuples\tcolumn_cardinalities\tproduct_cardinality\tvalid_tuple_reject\tvalid_bucket_alias\tmin_bytes\tmax_bytes"
    );
    for recipe in &recipes {
        let model = tuple_model(&catalog, recipe);
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            recipe.spec.id,
            recipe.spec.utf8_profile,
            recipe.spec.placement.name(),
            recipe.spec.explicit_guard,
            recipe.spec.requested_primary_cardinality,
            model.observed_primary_cardinality,
            recipe.spec.tuple_width,
            recipe.spec.bucket_budget,
            model.exact_tuples.len(),
            join_usizes(&model.column_cardinalities),
            model.product_cardinality,
            model.correlated_reject.as_ref().is_some_and(|decoy| decoy.valid_utf8),
            model.bucket_alias.as_ref().is_some_and(|decoy| decoy.valid_utf8),
            recipe.minimum_bytes(),
            recipe.maximum_bytes(),
        );
    }
}

fn emit_task_count() {
    let catalog = FrozenCatalog::parse();
    let recipes = materialize_recipes(&catalog);
    println!("{}", timing_tasks(&catalog, &recipes).len());
}

fn timing_tasks(catalog: &FrozenCatalog, recipes: &[Recipe]) -> Vec<TimingTask> {
    let mut tasks = Vec::new();
    for recipe_index in 0..recipes.len() {
        for &shape in &Shape::TIMED {
            for size in catalog.timing_sizes() {
                for &operation in &Operation::ALL {
                    tasks.push(TimingTask {
                        recipe_index,
                        shape,
                        size,
                        operation,
                    });
                }
            }
        }
    }
    tasks
}

fn time_task(task_index: usize, sample: usize) {
    use std::time::Instant;

    let catalog = FrozenCatalog::parse();
    let recipes = materialize_recipes(&catalog);
    let tasks = timing_tasks(&catalog, &recipes);
    let task = *tasks
        .get(task_index)
        .unwrap_or_else(|| panic!("task {task_index} is outside 0..{}", tasks.len()));
    let recipe = &recipes[task.recipe_index];
    let model = tuple_model(&catalog, recipe);
    let regex = build_regex(recipe);
    let oracle = Oracle::new(&recipe.branches);
    let spacings = catalog.semantic_spacings();
    let alignment = task_index.wrapping_mul(7) % 16;
    let spacing = spacings[task_index.wrapping_mul(5) % spacings.len()];
    let haystack = build_haystack(
        &catalog,
        &model,
        task.shape,
        task.size,
        alignment,
        spacing,
    );
    let end_trim = task_index.wrapping_mul(11) % 16;
    let frame = SearchFrame {
        find_at: alignment.min(haystack.len()),
        window_start: alignment.min(haystack.len()),
        window_end: haystack.len().saturating_sub(end_trim),
    };
    assert!(frame.window_start <= frame.window_end);

    // The complete semantic comparison is deliberately before the first clock read.
    let semantic_checksum = verify_case(
        recipe,
        task.shape,
        &regex,
        &oracle,
        &haystack,
        frame,
    );
    let expected = oracle_operation(&oracle, &haystack, frame, task.operation);
    let actual = fre_operation(&regex, &haystack, frame, task.operation);
    assert_eq!(actual, expected, "timed operation lost oracle equality");

    for _ in 0..TIMING_WARMUP_ITERATIONS {
        black_box(fre_operation(
            black_box(&regex),
            black_box(&haystack),
            frame,
            task.operation,
        ));
    }
    let iterations = (TIMING_TARGET_BYTES / haystack.len().max(1))
        .clamp(TIMING_MIN_ITERATIONS, TIMING_MAX_ITERATIONS);
    let started = Instant::now();
    let mut result_checksum = 0xcbf2_9ce4_8422_2325_u64;
    for _ in 0..iterations {
        let result = fre_operation(
            black_box(&regex),
            black_box(&haystack),
            frame,
            task.operation,
        );
        result_checksum = mix(result_checksum, black_box(result));
    }
    let elapsed_ns = started.elapsed().as_nanos();
    let build = regex
        .unicode_folded_literal_build_accounting()
        .expect("the timed route retains folded accounting");
    println!(
        "schema,catalog_fnv64,dispatch,task,sample,recipe,profile,placement,explicit_guard,primary_cardinality,tuple_width,buckets,shape,size,alignment,spacing,operation,iterations,elapsed_ns,result_checksum,semantic_checksum,plan,runtime_id,root_needles,persistent_bytes"
    );
    println!(
        "{},{:016x},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:016x},{:016x},{:?},{},{},{}",
        catalog::CATALOG_SCHEMA,
        catalog.checksum,
        DISPATCH_PROFILE,
        task_index,
        sample,
        recipe.spec.id,
        recipe.spec.utf8_profile,
        recipe.spec.placement.name(),
        recipe.spec.explicit_guard,
        model.observed_primary_cardinality,
        recipe.spec.tuple_width,
        recipe.spec.bucket_budget,
        task.shape.name(),
        task.size,
        alignment,
        spacing,
        task.operation.name(),
        iterations,
        elapsed_ns,
        result_checksum,
        semantic_checksum,
        regex.build_report().plan,
        regex.runtime_implementation_id(),
        build.trie.root_prefilter_needles,
        build.persistent_bytes,
    );
}

fn fre_operation(
    regex: &PortableRegex,
    haystack: &[u8],
    frame: SearchFrame,
    operation: Operation,
) -> u64 {
    match operation {
        Operation::IsMatch => bool_u64(
            regex
                .is_match_value(haystack, SearchLimits::unlimited())
                .expect("timed is_match stays within unlimited limits"),
        ),
        Operation::Find => hash_span(span(
            regex
                .find_value(haystack, SearchLimits::unlimited())
                .expect("timed find stays within unlimited limits"),
        )),
        Operation::FindAt => hash_span(span(
            regex
                .find_at_value(haystack, frame.find_at, SearchLimits::unlimited())
                .expect("timed find_at stays within unlimited limits"),
        )),
        Operation::ExactWindow => hash_span(span(
            regex
                .find_window_value(
                    haystack,
                    SearchWindow::new(frame.window_start, frame.window_end),
                    SearchLimits::unlimited(),
                )
                .expect("timed window stays within unlimited limits"),
        )),
        Operation::Iterate => {
            let mut checksum = 0xcbf2_9ce4_8422_2325_u64;
            for result in regex
                .find_iter(haystack, PortableFindIterLimits::unlimited())
                .expect("timed iterator setup stays within unlimited limits")
            {
                let matched = result.expect("timed iterator stays within unlimited limits");
                checksum = mix(checksum, hash_span(Some((matched.start(), matched.end()))));
            }
            checksum
        }
    }
}

fn oracle_operation(
    oracle: &Oracle,
    haystack: &[u8],
    frame: SearchFrame,
    operation: Operation,
) -> u64 {
    match operation {
        Operation::IsMatch => bool_u64(oracle.is_match(haystack)),
        Operation::Find => hash_span(oracle.find(haystack)),
        Operation::FindAt => hash_span(oracle.find_at(haystack, frame.find_at)),
        Operation::ExactWindow => hash_span(oracle.find_window(
            haystack,
            frame.window_start,
            frame.window_end,
        )),
        Operation::Iterate => oracle
            .matches(haystack)
            .into_iter()
            .fold(0xcbf2_9ce4_8422_2325_u64, |checksum, matched| {
                mix(checksum, hash_span(Some(matched)))
            }),
    }
}

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

fn hash_span(span: Option<(usize, usize)>) -> u64 {
    match span {
        None => 0x9E37_79B9_7F4A_7C15,
        Some((start, end)) => {
            let start = u64::try_from(start).expect("a match start fits u64");
            let end = u64::try_from(end).expect("a match end fits u64");
            mix(start ^ 0xA076_1D64_78BD_642F, end)
        }
    }
}

const fn mix(state: u64, value: u64) -> u64 {
    state
        .rotate_left(17)
        .wrapping_mul(0x9E37_79B1_85EB_CA87)
        ^ value.wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
}

const fn bool_u64(value: bool) -> u64 {
    if value { 1 } else { 0 }
}

fn join_usizes(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join("/")
}

fn parse_argument(raw: &str, label: &str) -> usize {
    raw.parse::<usize>()
        .unwrap_or_else(|error| panic!("invalid {label} {raw}: {error}"))
}
