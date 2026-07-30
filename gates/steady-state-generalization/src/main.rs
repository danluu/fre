use std::env;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use fre::{
    PortableFindIterRunLimits, PortableRegex, PortableSearchSession, SearchLimits,
    SearchSessionLimits, SearchSessionSetupAccounting,
};
use regex_automata::{
    Input, MatchError, meta,
    util::{iter::Searcher, syntax},
};
use serde::Serialize;
use serde_json::{Value, json};

const SCHEMA: &str = "fre.steady-state-generalization.v1";
const PLAN_ID: &str = "general-byte-steady-v1";
const GENERATOR_ID: &str = "background-cycle-token-plant-v2";
const RUST_PLAN_ID: &str = "regex_automata::meta::Regex/caller-owned-Cache/syntax-utf8-false";
const DESIGNED_ON_SOURCE: &str = "8810cc1b4f409627b6bcc44756dfd2962b7cd6b7";
const SEED: u64 = 0x7d31_5a92_46c8_e0bf;

#[derive(Clone, Copy, Debug, Serialize)]
struct Case {
    id: &'static str,
    family: &'static str,
    pattern: &'static str,
    background: &'static [u8],
    background_phase: usize,
    tokens: &'static [&'static [u8]],
}

const CASES: &[Case] = &[
    Case {
        id: "literal",
        family: "native-literal",
        pattern: r"needle42",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b"needle42"],
    },
    Case {
        id: "alternation",
        family: "native-alternation",
        pattern: r"(?:alpha|beta|gamma)",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b"alpha", b"beta", b"gamma"],
    },
    Case {
        id: "fixed_bounded",
        family: "fixed-bounded",
        pattern: r"(?-u:[A-F]{2,5}[0-9]{2})",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b"AB12", b"FACE99"],
    },
    Case {
        id: "fixed_bounded_deep_reject",
        family: "fixed-bounded-deep-reject",
        pattern: r"(?-u:[A-F]{2,5}[0-9]{2})",
        background: b"AAAAAG",
        background_phase: 0,
        tokens: &[b"AB12", b"FACE99"],
    },
    Case {
        id: "required_suffix",
        family: "required-suffix",
        pattern: r"(?-u:(?:[a-z]{1,16}/){1,4}DONE)",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b"user/lib/DONE", b"tmp/DONE"],
    },
    Case {
        id: "bounded_suffix_literal_decoy",
        family: "bounded-suffix-literal-decoy",
        pattern: r"(?-u:(?:[a-z]{1,16}/){1,4}DONE)",
        background: b"1/DONE.",
        background_phase: 0,
        tokens: &[b"user/lib/DONE", b"tmp/DONE"],
    },
    Case {
        id: "unbounded_suffix_context",
        family: "required-suffix-context",
        pattern: r"(?-u:\b[A-Za-z]+TRAILER\b)",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b" PayloadTRAILER ", b" xTRAILER "],
    },
    Case {
        id: "required_suffix_literal_decoy",
        family: "required-suffix-literal-decoy",
        pattern: r"(?-u:\b[A-Za-z]+TRAILER\b)",
        background: b" aTRAILERx ",
        background_phase: 2,
        tokens: &[b" aTRAILER ", b" payloadTRAILER "],
    },
    Case {
        id: "positive_loop",
        family: "positive-loop",
        pattern: r"ab+c",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b"abc", b"abbbbbc"],
    },
    Case {
        id: "negated_loop",
        family: "negated-loop",
        pattern: r"a[^z\r\n]*z",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b"a payload z", b"a_012345_z"],
    },
    Case {
        id: "alternating_correlated_reject",
        family: "alternating-correlated-reject",
        pattern: r"(?-u:(?:ab[bc]*Z|q[de]*Y))",
        background: b"abbbbbY qdddddZ ",
        background_phase: 0,
        tokens: &[b"abbbbbZ", b"qdddddY"],
    },
    Case {
        id: "nullable_priority",
        family: "nullable",
        pattern: r"(?:ab|a|)",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b"ab", b"a"],
    },
    Case {
        id: "ascii_no_literal",
        family: "ascii-no-literal",
        pattern: r"(?-u:[A-Z][a-z_]{2,11}[0-9]?)",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b"Alpha_1", b"Beta"],
    },
    Case {
        id: "high_byte_root_deep_reject",
        family: "high-byte-root-deep-reject",
        pattern: r"(?-u:[\x80-\x9F]Q)",
        background: b"\x80R\x8fR\x9fR",
        background_phase: 0,
        tokens: &[b"\x80Q", b"\x8fQ"],
    },
    Case {
        id: "lf_context",
        family: "lf-context",
        pattern: r"(?m)^(?-u:[A-Z][a-z]{2,8})$",
        background: b"...\n",
        background_phase: 0,
        tokens: &[b"\nAlpha\n", b"\nBeta\n"],
    },
    Case {
        id: "crlf_context",
        family: "crlf-context",
        pattern: r"(?Rm)^(?-u:[A-Z][a-z]{2,8})$",
        background: b"..\r\n",
        background_phase: 0,
        tokens: &[b"\r\nBravo\r\n", b"\r\nDelta\r\n"],
    },
    Case {
        id: "ascii_word",
        family: "ascii-word-context",
        pattern: r"(?-u:\b[A-Za-z]{3,9}\b)",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[b" Word ", b" Search "],
    },
    Case {
        id: "unicode_word",
        family: "unicode-word-context",
        pattern: r"\b\p{L}{2,8}\b",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[" élan ".as_bytes(), " 猫猫 ".as_bytes()],
    },
    Case {
        id: "unicode_class",
        family: "unicode-class",
        pattern: r"\p{Greek}{2,6}",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &["Δελτα".as_bytes(), "κόσμος".as_bytes()],
    },
    Case {
        id: "unicode_fold",
        family: "unicode-fold",
        pattern: r"(?i:straße|σίσυφος|élan)",
        background: b".~0123456789/",
        background_phase: 0,
        tokens: &[
            " Straße ".as_bytes(),
            " Σίσυφος ".as_bytes(),
            " ÉLAN ".as_bytes(),
        ],
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Density {
    Absent,
    Sparse,
    Dense,
}

const DENSITIES: &[Density] = &[Density::Absent, Density::Sparse, Density::Dense];

impl Density {
    const fn id(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Sparse => "sparse",
            Self::Dense => "dense",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        DENSITIES
            .iter()
            .copied()
            .find(|density| density.id() == value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    IsMatch,
    Find,
    FindAt,
    Iterate,
    SessionSetup,
}

const OPERATIONS: &[Operation] = &[
    Operation::IsMatch,
    Operation::Find,
    Operation::FindAt,
    Operation::Iterate,
    Operation::SessionSetup,
];

impl Operation {
    const fn id(self) -> &'static str {
        match self {
            Self::IsMatch => "is_match",
            Self::Find => "find",
            Self::FindAt => "find_at",
            Self::Iterate => "iterate",
            Self::SessionSetup => "session_setup",
        }
    }

    const fn lane(self) -> &'static str {
        match self {
            Self::SessionSetup => "cold-session",
            _ => "steady",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        OPERATIONS
            .iter()
            .copied()
            .find(|operation| operation.id() == value)
    }
}

const SIZES: &[usize] = &[15, 16, 17, 31, 32, 33, 63, 64, 65, 4_093, 262_139];
const COLD_SESSION_SIZE: usize = 31;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
struct Digest {
    count: u64,
    span_sum: u64,
    hash: u64,
}

impl Digest {
    fn push(&mut self, start: usize, end: usize) {
        let ordinal = self.count;
        self.count = self.count.wrapping_add(1);
        self.span_sum = self
            .span_sum
            .wrapping_add(u64::try_from(end.saturating_sub(start)).unwrap_or(u64::MAX));
        let value = u64::try_from(start).unwrap_or(u64::MAX)
            ^ u64::try_from(end).unwrap_or(u64::MAX).rotate_left(21)
            ^ ordinal.rotate_left(43);
        self.hash = mix64(self.hash ^ mix64(value));
    }
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn fnv_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn plan_checksum() -> String {
    let mut hash = fnv_bytes(0xcbf2_9ce4_8422_2325, PLAN_ID.as_bytes());
    hash = fnv_bytes(hash, SCHEMA.as_bytes());
    hash = fnv_bytes(hash, GENERATOR_ID.as_bytes());
    hash = fnv_bytes(hash, RUST_PLAN_ID.as_bytes());
    hash = fnv_bytes(hash, DESIGNED_ON_SOURCE.as_bytes());
    hash = fnv_bytes(hash, &SEED.to_le_bytes());
    for case in CASES {
        for bytes in [
            case.id.as_bytes(),
            case.family.as_bytes(),
            case.pattern.as_bytes(),
            case.background,
        ] {
            hash = fnv_bytes(hash, bytes);
            hash = fnv_bytes(hash, &[0xff]);
        }
        hash = fnv_bytes(hash, &case.background_phase.to_le_bytes());
        for token in case.tokens {
            hash = fnv_bytes(hash, token);
            hash = fnv_bytes(hash, &[0xfe]);
        }
    }
    for size in SIZES {
        hash = fnv_bytes(hash, &size.to_le_bytes());
    }
    for density in DENSITIES {
        hash = fnv_bytes(hash, density.id().as_bytes());
    }
    for operation in OPERATIONS {
        hash = fnv_bytes(hash, operation.id().as_bytes());
        hash = fnv_bytes(hash, operation.lane().as_bytes());
    }
    for &size in SIZES {
        for &density in DENSITIES {
            for &operation in OPERATIONS {
                if !include_catalog_point(size, density, operation) {
                    continue;
                }
                hash = fnv_bytes(
                    hash,
                    &default_iterations(size, density, operation).to_le_bytes(),
                );
            }
        }
    }
    format!("{hash:016x}")
}

fn fill_background(bytes: &mut [u8], background: &[u8], phase: usize) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = background[(index + phase) % background.len()];
    }
}

fn copy_token(bytes: &mut [u8], wanted_start: usize, token: &[u8]) {
    if token.len() > bytes.len() {
        return;
    }
    let start = wanted_start.min(bytes.len() - token.len());
    bytes[start..start + token.len()].copy_from_slice(token);
}

fn haystack(case: Case, size: usize, density: Density) -> Vec<u8> {
    let mut bytes = vec![0_u8; size];
    fill_background(&mut bytes, case.background, case.background_phase);
    match density {
        Density::Absent => {}
        Density::Sparse => {
            let token_index = usize::try_from(
                SEED % u64::try_from(case.tokens.len()).expect("token count fits u64"),
            )
            .expect("reduced token index fits usize");
            let token = case.tokens[token_index];
            copy_token(&mut bytes, size.saturating_mul(2) / 3, token);
        }
        Density::Dense => {
            let max_token = case
                .tokens
                .iter()
                .map(|token| token.len())
                .max()
                .unwrap_or(1);
            let step = max_token.saturating_add(17).max(29);
            let mut start = 1_usize;
            let mut ordinal = 0_usize;
            while start < size {
                let token = case.tokens[ordinal % case.tokens.len()];
                if start.saturating_add(token.len()) > size {
                    break;
                }
                copy_token(&mut bytes, start, token);
                start = start.saturating_add(step);
                ordinal = ordinal.saturating_add(1);
            }
        }
    }
    bytes
}

fn find_at_start(haystack: &[u8]) -> usize {
    let mut start = haystack.len() / 3;
    while start < haystack.len() && (haystack[start] & 0xc0) == 0x80 {
        start = start.saturating_add(1);
    }
    start
}

fn fre_outcome(
    session: &mut PortableSearchSession<'_>,
    operation: Operation,
    haystack: &[u8],
) -> Result<Digest, String> {
    let mut digest = Digest::default();
    match operation {
        Operation::IsMatch => {
            if session
                .is_match_value(haystack, SearchLimits::unlimited())
                .map_err(|error| format!("FRE is_match: {error:?}"))?
            {
                digest.push(0, 0);
            }
        }
        Operation::Find => {
            if let Some(matched) = session
                .find(haystack, SearchLimits::unlimited())
                .map_err(|error| format!("FRE find: {error:?}"))?
                .0
            {
                digest.push(matched.start(), matched.end());
            }
        }
        Operation::FindAt => {
            if let Some(matched) = session
                .find_at(haystack, find_at_start(haystack), SearchLimits::unlimited())
                .map_err(|error| format!("FRE find_at: {error:?}"))?
                .0
            {
                digest.push(matched.start(), matched.end());
            }
        }
        Operation::Iterate => {
            let mut matches = session.find_iter(haystack, PortableFindIterRunLimits::unlimited());
            for item in matches.by_ref() {
                let matched = item.map_err(|error| format!("FRE iterator: {error:?}"))?;
                digest.push(matched.start(), matched.end());
            }
        }
        Operation::SessionSetup => {
            return Err("session_setup has no search outcome".to_owned());
        }
    }
    Ok(digest)
}

fn rust_outcome(
    regex: &meta::Regex,
    cache: &mut meta::Cache,
    operation: Operation,
    haystack: &[u8],
) -> Result<Digest, String> {
    let mut digest = Digest::default();
    match operation {
        Operation::IsMatch => {
            let input = Input::new(haystack).earliest(true);
            if regex.search_half_with(cache, &input).is_some() {
                digest.push(0, 0);
            }
        }
        Operation::Find => {
            if let Some(matched) = regex.search_with(cache, &Input::new(haystack)) {
                digest.push(matched.start(), matched.end());
            }
        }
        Operation::FindAt => {
            let start = find_at_start(haystack);
            let input = Input::new(haystack).span(start..haystack.len());
            if let Some(matched) = regex.search_with(cache, &input) {
                digest.push(matched.start(), matched.end());
            }
        }
        Operation::Iterate => {
            let mut searcher = Searcher::new(Input::new(haystack));
            while let Some(matched) =
                searcher.advance(|input| Ok::<_, MatchError>(regex.search_with(cache, input)))
            {
                digest.push(matched.start(), matched.end());
            }
        }
        Operation::SessionSetup => {
            return Err("session_setup has no search outcome".to_owned());
        }
    }
    Ok(digest)
}

fn setup_json(setup: Option<SearchSessionSetupAccounting>) -> Value {
    setup.map_or(Value::Null, |setup| {
        json!({
            "work": setup.work(),
            "allocated_bytes": setup.allocated_bytes(),
            "initialized_bytes": setup.initialized_bytes(),
            "retained_bytes": setup.retained_bytes(),
            "reused": setup.reused(),
        })
    })
}

fn build_plans(case: Case) -> Result<(PortableRegex, meta::Regex), String> {
    let fre = PortableRegex::new(case.pattern.to_owned())
        .map_err(|error| format!("{} FRE build: {error:?}", case.id))?;
    let rust = meta::Regex::builder()
        .syntax(syntax::Config::new().utf8(false))
        .build(case.pattern)
        .map_err(|error| format!("{} Rust build: {error:?}", case.id))?;
    Ok((fre, rust))
}

fn verify_workload(case: Case, size: usize, density: Density) -> Result<Value, String> {
    let haystack = haystack(case, size, density);
    let (fre, rust) = build_plans(case)?;
    let mut fre_session = fre
        .search_session(SearchSessionLimits::unlimited())
        .map_err(|error| format!("{} FRE session: {error:?}", case.id))?;
    let mut rust_cache = rust.create_cache();
    let fre_plan = fre.runtime_implementation_id();
    let session_plan = fre_session.runtime_implementation_id();
    let setup = setup_json(fre_session.workspace_setup_accounting());
    let mut semantics = serde_json::Map::new();
    for &operation in OPERATIONS {
        if operation == Operation::SessionSetup {
            continue;
        }
        let fre_result = fre_outcome(&mut fre_session, operation, &haystack)?;
        let rust_result = rust_outcome(&rust, &mut rust_cache, operation, &haystack)?;
        if fre_result != rust_result {
            return Err(format!(
                "{} / {size} / {} / {} differs: FRE {fre_result:?}, Rust {rust_result:?}",
                case.id,
                density.id(),
                operation.id()
            ));
        }
        semantics.insert(
            operation.id().to_owned(),
            serde_json::to_value(fre_result).map_err(|error| error.to_string())?,
        );
    }
    Ok(json!({
        "case": case.id,
        "family": case.family,
        "size": size,
        "density": density,
        "fre_regex_plan": fre_plan,
        "fre_session_plan": session_plan,
        "fre_session_setup": setup,
        "rust_plan": RUST_PLAN_ID,
        "semantics": semantics,
    }))
}

fn default_iterations(size: usize, density: Density, operation: Operation) -> usize {
    if operation == Operation::SessionSetup {
        return 20_000;
    }
    if size <= 65 {
        return if operation == Operation::Iterate {
            20_000
        } else {
            200_000
        };
    }
    match (size, density, operation) {
        (4_093, Density::Dense, Operation::Iterate) => 500,
        (4_093, _, Operation::Iterate) => 2_000,
        (4_093, _, _) => 20_000,
        (262_139, Density::Dense, Operation::Iterate) => 2,
        (262_139, _, Operation::Iterate) => 20,
        (262_139, _, _) => 100,
        _ => 1,
    }
}

const fn include_catalog_point(size: usize, density: Density, operation: Operation) -> bool {
    match operation {
        Operation::SessionSetup => size == COLD_SESSION_SIZE && matches!(density, Density::Absent),
        _ => true,
    }
}

fn fold_timed_checksum(checksum: u64, outcome: Digest, ordinal: usize) -> u64 {
    let ordinal = u64::try_from(ordinal).unwrap_or(u64::MAX);
    mix64(checksum ^ outcome.hash ^ outcome.count.rotate_left(17) ^ ordinal)
}

fn time_fre(
    regex: &PortableRegex,
    operation: Operation,
    haystack: &[u8],
    iterations: usize,
) -> Result<(u128, u64, &'static str, Value), String> {
    if operation == Operation::SessionSetup {
        let warm = regex
            .search_session(SearchSessionLimits::unlimited())
            .map_err(|error| format!("FRE warm session setup: {error:?}"))?;
        let plan = warm.runtime_implementation_id();
        let setup = setup_json(warm.workspace_setup_accounting());
        black_box(&warm);
        drop(warm);
        let timer = Instant::now();
        let mut checksum = 0_u64;
        for ordinal in 0..iterations {
            let session = regex
                .search_session(SearchSessionLimits::unlimited())
                .map_err(|error| format!("FRE timed session setup: {error:?}"))?;
            let setup = session.workspace_setup_accounting();
            let retained = setup.map_or(0, SearchSessionSetupAccounting::retained_bytes);
            checksum = mix64(
                checksum
                    ^ u64::try_from(retained).unwrap_or(u64::MAX)
                    ^ u64::try_from(ordinal).unwrap_or(u64::MAX),
            );
            black_box(session);
        }
        return Ok((timer.elapsed().as_nanos(), black_box(checksum), plan, setup));
    }

    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .map_err(|error| format!("FRE session setup: {error:?}"))?;
    let plan = session.runtime_implementation_id();
    let setup = setup_json(session.workspace_setup_accounting());
    black_box(fre_outcome(&mut session, operation, black_box(haystack))?);
    let timer = Instant::now();
    let mut checksum = 0_u64;
    for ordinal in 0..iterations {
        let outcome = fre_outcome(&mut session, operation, black_box(haystack))?;
        checksum = fold_timed_checksum(checksum, black_box(outcome), ordinal);
    }
    Ok((timer.elapsed().as_nanos(), black_box(checksum), plan, setup))
}

fn time_rust(
    regex: &meta::Regex,
    operation: Operation,
    haystack: &[u8],
    iterations: usize,
) -> Result<(u128, u64), String> {
    if operation == Operation::SessionSetup {
        black_box(regex.create_cache());
        let timer = Instant::now();
        let mut checksum = 0_u64;
        for ordinal in 0..iterations {
            let cache = regex.create_cache();
            checksum = mix64(
                checksum ^ u64::try_from(ordinal).unwrap_or(u64::MAX) ^ 0x7275_7374_6361_6368,
            );
            black_box(cache);
        }
        return Ok((timer.elapsed().as_nanos(), black_box(checksum)));
    }

    let mut cache = regex.create_cache();
    black_box(rust_outcome(
        regex,
        &mut cache,
        operation,
        black_box(haystack),
    )?);
    let timer = Instant::now();
    let mut checksum = 0_u64;
    for ordinal in 0..iterations {
        let outcome = rust_outcome(regex, &mut cache, operation, black_box(haystack))?;
        checksum = fold_timed_checksum(checksum, black_box(outcome), ordinal);
    }
    Ok((timer.elapsed().as_nanos(), black_box(checksum)))
}

fn point(
    case: Case,
    size: usize,
    density: Density,
    operation: Operation,
    engine: &str,
    iterations: usize,
) -> Result<Value, String> {
    let haystack = haystack(case, size, density);
    let (fre, rust) = build_plans(case)?;
    let semantic = if operation == Operation::SessionSetup {
        Value::Null
    } else {
        let mut fre_session = fre
            .search_session(SearchSessionLimits::unlimited())
            .map_err(|error| format!("FRE verification session: {error:?}"))?;
        let mut rust_cache = rust.create_cache();
        let fre_result = fre_outcome(&mut fre_session, operation, &haystack)?;
        let rust_result = rust_outcome(&rust, &mut rust_cache, operation, &haystack)?;
        if fre_result != rust_result {
            return Err(format!(
                "point semantic mismatch: FRE {fre_result:?}, Rust {rust_result:?}"
            ));
        }
        serde_json::to_value(fre_result).map_err(|error| error.to_string())?
    };

    let (elapsed_ns, checksum, runtime_plan, session_setup) = match engine {
        "fre" => {
            let (elapsed, checksum, runtime_plan, setup) =
                time_fre(&fre, operation, &haystack, iterations)?;
            (elapsed, checksum, runtime_plan, setup)
        }
        "rust" => {
            let (elapsed, checksum) = time_rust(&rust, operation, &haystack, iterations)?;
            (elapsed, checksum, RUST_PLAN_ID, Value::Null)
        }
        _ => return Err(format!("unknown engine {engine:?}; expected fre or rust")),
    };

    Ok(json!({
        "schema": SCHEMA,
        "plan_id": PLAN_ID,
        "plan_checksum": plan_checksum(),
        "generator_id": GENERATOR_ID,
        "designed_on_source": DESIGNED_ON_SOURCE,
        "case": case.id,
        "family": case.family,
        "pattern": case.pattern,
        "size": size,
        "density": density,
        "operation": operation,
        "lane": operation.lane(),
        "engine": engine,
        "iterations": iterations,
        "elapsed_ns": elapsed_ns,
        "timed_checksum": format!("{checksum:016x}"),
        "semantic": semantic,
        "runtime_plan": runtime_plan,
        "session_setup": session_setup,
        "rust_state_policy": RUST_PLAN_ID,
        "fre_state_policy": "caller-owned PortableSearchSession; no setup in steady lane",
    }))
}

fn catalog() -> Value {
    let mut points = Vec::new();
    for case in CASES {
        for &size in SIZES {
            for &density in DENSITIES {
                for &operation in OPERATIONS {
                    if !include_catalog_point(size, density, operation) {
                        continue;
                    }
                    points.push(json!({
                        "case": case.id,
                        "family": case.family,
                        "pattern": case.pattern,
                        "size": size,
                        "density": density,
                        "operation": operation,
                        "lane": operation.lane(),
                        "default_iterations": default_iterations(size, density, operation),
                    }));
                }
            }
        }
    }
    json!({
        "schema": SCHEMA,
        "plan_id": PLAN_ID,
        "plan_checksum": plan_checksum(),
        "generator_id": GENERATOR_ID,
        "designed_on_source": DESIGNED_ON_SOURCE,
        "sizes": SIZES,
        "densities": DENSITIES,
        "operations": OPERATIONS,
        "cold_session_coordinate": {
            "size": COLD_SESSION_SIZE,
            "density": Density::Absent,
        },
        "cases": CASES,
        "points": points,
        "state_policy": {
            "fre": "one caller-owned PortableSearchSession, one untimed warm operation",
            "rust": RUST_PLAN_ID,
            "iteration": "both engines use caller-owned state for the complete iterator",
        },
    })
}

fn verify() -> Result<Value, String> {
    let mut rows = Vec::new();
    for &case in CASES {
        for &size in SIZES {
            for &density in DENSITIES {
                rows.push(verify_workload(case, size, density)?);
            }
        }
    }
    Ok(json!({
        "schema": SCHEMA,
        "plan_id": PLAN_ID,
        "plan_checksum": plan_checksum(),
        "generator_id": GENERATOR_ID,
        "designed_on_source": DESIGNED_ON_SOURCE,
        "clock_free": true,
        "workloads_verified": rows.len(),
        "rows": rows,
    }))
}

fn option(args: &[String], name: &str) -> Result<String, String> {
    let position = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing {name}"))?;
    args.get(position + 1)
        .cloned()
        .ok_or_else(|| format!("missing value after {name}"))
}

fn usage() -> &'static str {
    "usage:
  fre-steady-state-generalization catalog
  fre-steady-state-generalization verify
  fre-steady-state-generalization point --case ID --size 31|4093|262139 \\
    --density absent|sparse|dense --operation is_match|find|find_at|iterate|session_setup \\
    --engine fre|rust [--iterations N]"
}

fn run() -> Result<Value, String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let command = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| usage().to_owned())?;
    match command {
        "catalog" => Ok(catalog()),
        "verify" => verify(),
        "point" => {
            let case_id = option(&args, "--case")?;
            let case = CASES
                .iter()
                .copied()
                .find(|case| case.id == case_id)
                .ok_or_else(|| format!("unknown case {case_id:?}"))?;
            let size = option(&args, "--size")?
                .parse::<usize>()
                .map_err(|error| format!("invalid --size: {error}"))?;
            if !SIZES.contains(&size) {
                return Err(format!(
                    "unsupported size {size}; expected one of {SIZES:?}"
                ));
            }
            let density_id = option(&args, "--density")?;
            let density = Density::parse(&density_id)
                .ok_or_else(|| format!("unknown density {density_id:?}"))?;
            let operation_id = option(&args, "--operation")?;
            let operation = Operation::parse(&operation_id)
                .ok_or_else(|| format!("unknown operation {operation_id:?}"))?;
            let engine = option(&args, "--engine")?;
            let iterations = match args.iter().position(|value| value == "--iterations") {
                Some(position) => args
                    .get(position + 1)
                    .ok_or_else(|| "missing value after --iterations".to_owned())?
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --iterations: {error}"))?,
                None => default_iterations(size, density, operation),
            };
            if iterations == 0 {
                return Err("--iterations must be positive".to_owned());
            }
            point(case, size, density, operation, &engine, iterations)
        }
        _ => Err(usage().to_owned()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("JSON serialization failed: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definitions_are_unique_and_complete() {
        assert_eq!(SIZES, &[15, 16, 17, 31, 32, 33, 63, 64, 65, 4_093, 262_139]);
        assert_eq!(DENSITIES.len(), 3);
        assert_eq!(OPERATIONS.len(), 5);
        for (index, case) in CASES.iter().enumerate() {
            assert!(!case.tokens.is_empty());
            assert!(!case.background.is_empty());
            assert!(!CASES[..index].iter().any(|prior| prior.id == case.id));
        }
        let catalog = catalog();
        let points = catalog["points"].as_array().unwrap();
        assert_eq!(
            points
                .iter()
                .filter(|point| point["lane"] == "cold-session")
                .count(),
            CASES.len()
        );
        assert_ne!(plan_checksum(), "0000000000000000");
    }

    #[test]
    fn generators_are_exact_and_preserve_declared_byte_domain() {
        for &case in CASES {
            for &size in SIZES {
                for &density in DENSITIES {
                    let generated = haystack(case, size, density);
                    assert_eq!(generated.len(), size);
                    if case.id == "high_byte_root_deep_reject" {
                        assert!(std::str::from_utf8(&generated).is_err());
                    } else {
                        assert!(std::str::from_utf8(&generated).is_ok());
                    }
                }
            }
        }
    }

    #[test]
    fn hard_decoy_backgrounds_are_semantically_absent_at_every_size() {
        let cases = [
            (
                "required_suffix_literal_decoy",
                "TRAILER is followed by x; phase avoids a truncated TRAILER tail",
            ),
            (
                "fixed_bounded_deep_reject",
                "the A-F prefix has no following digits; G and the cycle boundary reject",
            ),
            (
                "alternating_correlated_reject",
                "each branch gets the opposite terminal; spaces prevent cross-cycle paths",
            ),
            (
                "high_byte_root_deep_reject",
                "the background has no Q byte and every cycle ends in R",
            ),
            (
                "bounded_suffix_literal_decoy",
                "DONE is preceded only by digit-plus-slash; periods isolate every cycle",
            ),
        ];
        for (id, reason) in cases {
            let case = CASES.iter().copied().find(|case| case.id == id).unwrap();
            let (fre, rust) = build_plans(case).unwrap();
            let mut fre_session = fre
                .search_session(SearchSessionLimits::unlimited())
                .unwrap();
            let mut rust_cache = rust.create_cache();
            for &size in SIZES {
                let haystack = haystack(case, size, Density::Absent);
                for operation in [
                    Operation::IsMatch,
                    Operation::Find,
                    Operation::FindAt,
                    Operation::Iterate,
                ] {
                    let fre_result = fre_outcome(&mut fre_session, operation, &haystack).unwrap();
                    let rust_result =
                        rust_outcome(&rust, &mut rust_cache, operation, &haystack).unwrap();
                    assert_eq!(fre_result, Digest::default(), "{id}: {reason}");
                    assert_eq!(rust_result, Digest::default(), "{id}: {reason}");
                }
            }
        }
    }

    #[test]
    fn unbounded_suffix_context_has_miss_hit_and_dense_shapes() {
        let case = CASES
            .iter()
            .copied()
            .find(|case| case.id == "unbounded_suffix_context")
            .unwrap();
        let (fre, rust) = build_plans(case).unwrap();
        let mut fre_session = fre
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        let mut rust_cache = rust.create_cache();
        for (density, expected_minimum) in [
            (Density::Absent, 0_u64),
            (Density::Sparse, 1),
            (Density::Dense, 2),
        ] {
            let haystack = haystack(case, 4_093, density);
            let fre_matches = fre_outcome(&mut fre_session, Operation::Iterate, &haystack).unwrap();
            let rust_matches =
                rust_outcome(&rust, &mut rust_cache, Operation::Iterate, &haystack).unwrap();
            assert_eq!(fre_matches, rust_matches);
            if density == Density::Absent {
                assert_eq!(fre_matches.count, expected_minimum);
            } else {
                assert!(fre_matches.count >= expected_minimum);
            }
        }
    }

    #[test]
    fn tiny_matrix_matches_with_explicit_state() {
        for &case in CASES {
            for &density in DENSITIES {
                verify_workload(case, 31, density).unwrap();
            }
        }
    }
}
