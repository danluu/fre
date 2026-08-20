use std::env;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use fre::{
    PortableFindIterAccounting, PortableFindIterLimits, PortableRegex, PortableTextRegex,
    SearchAccounting, SearchLimits, SearchSessionLimits, SearchSessionSetupAccounting,
    SearchWindow,
};
use regex::{Regex as RustTextRegex, bytes::Regex as RustByteRegex};
use serde::Serialize;
use serde_json::{Value, json};

const SCHEMA: &str = "fre.composition-interaction-gate.v1";
const SEED: u64 = 0xd1b5_4a32_d192_ed03;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    Text,
    Both,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Case {
    id: &'static str,
    pattern: &'static str,
    family: &'static str,
    scope: Scope,
    consuming_class: &'static str,
    nullable: bool,
    contextual: bool,
    native_control: bool,
}

const CASES: &[Case] = &[
    Case {
        id: "c0_line_start",
        pattern: r"(?m)^",
        family: "consuming-census",
        scope: Scope::Both,
        consuming_class: "0",
        nullable: true,
        contextual: true,
        native_control: false,
    },
    Case {
        id: "c1_line_class",
        pattern: r"(?m)^[ab]",
        family: "consuming-census",
        scope: Scope::Both,
        consuming_class: "1",
        nullable: false,
        contextual: true,
        native_control: false,
    },
    Case {
        id: "c2_line_classes",
        pattern: r"(?m)^[ab][cd]",
        family: "consuming-census",
        scope: Scope::Both,
        consuming_class: "2",
        nullable: false,
        contextual: true,
        native_control: false,
    },
    Case {
        id: "c3_line_classes",
        pattern: r"(?m)^[ab][cd][ef]",
        family: "consuming-census",
        scope: Scope::Both,
        consuming_class: "3",
        nullable: false,
        contextual: true,
        native_control: false,
    },
    Case {
        id: "c4_line_classes",
        pattern: r"(?m)^[ab][cd][ef][gh]",
        family: "consuming-census",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: true,
        native_control: false,
    },
    Case {
        id: "nullable_empty_first",
        pattern: r"(?:|a|ab)",
        family: "nullable-priority",
        scope: Scope::Both,
        consuming_class: "2",
        nullable: true,
        contextual: false,
        native_control: false,
    },
    Case {
        id: "nullable_empty_last",
        pattern: r"(?:ab|a|)",
        family: "nullable-priority",
        scope: Scope::Both,
        consuming_class: "2",
        nullable: true,
        contextual: false,
        native_control: false,
    },
    Case {
        id: "nullable_optional_repeat",
        pattern: r"(?:a?)*b",
        family: "nullable-priority",
        scope: Scope::Both,
        consuming_class: "2",
        nullable: false,
        contextual: false,
        native_control: false,
    },
    Case {
        id: "nullable_boundary_priority",
        pattern: r"(?:\b|aZ)",
        family: "nullable-context",
        scope: Scope::Both,
        consuming_class: "2",
        nullable: true,
        contextual: true,
        native_control: false,
    },
    Case {
        id: "self_loop_class",
        pattern: r"a[bc]*Z",
        family: "positive-self-loop",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: false,
        native_control: false,
    },
    Case {
        id: "self_loop_negated",
        pattern: r"x[^Z]*Z",
        family: "positive-self-loop",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: false,
        native_control: false,
    },
    Case {
        id: "self_loop_plus",
        pattern: r"[a-z]+Z",
        family: "positive-self-loop",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: false,
        native_control: false,
    },
    Case {
        id: "self_loop_alternating",
        pattern: r"(?:a[bc]*Z|q[de]*Y)",
        family: "positive-self-loop",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: false,
        native_control: false,
    },
    Case {
        id: "context_line_loop",
        pattern: r"(?m)^[a-z]+Z$",
        family: "contextual-control",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: true,
        native_control: false,
    },
    Case {
        id: "context_word_loop",
        pattern: r"\b[a-z]+Z\b",
        family: "contextual-control",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: true,
        native_control: false,
    },
    Case {
        id: "native_literal",
        pattern: r"needle",
        family: "native-control",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: false,
        native_control: true,
    },
    Case {
        id: "native_literal_set",
        pattern: r"(?:alpha|beta|gamma)",
        family: "native-control",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: false,
        native_control: true,
    },
    Case {
        id: "native_fixed_context",
        pattern: r"(?m)^prefix[0-9]+suffix$",
        family: "native-control",
        scope: Scope::Both,
        consuming_class: "4+",
        nullable: false,
        contextual: true,
        native_control: true,
    },
    Case {
        id: "text_nullable_utf8",
        pattern: r"(?:|é|猫)",
        family: "utf8-empty-progress",
        scope: Scope::Text,
        consuming_class: "3",
        nullable: true,
        contextual: false,
        native_control: false,
    },
    Case {
        id: "text_nullable_utf8_last",
        pattern: r"(?:猫|é|)",
        family: "utf8-empty-progress",
        scope: Scope::Text,
        consuming_class: "3",
        nullable: true,
        contextual: false,
        native_control: false,
    },
    Case {
        id: "text_unicode_context",
        pattern: r"\b(?:élan|猫)+\b",
        family: "utf8-empty-progress",
        scope: Scope::Text,
        consuming_class: "4+",
        nullable: false,
        contextual: true,
        native_control: false,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Facade {
    Byte,
    Text,
}

#[derive(Clone, Copy, Debug)]
struct Operation {
    id: &'static str,
    facade: Facade,
    cohort: &'static str,
    comparable_to_rust: bool,
    transition: bool,
}

const OPERATIONS: &[Operation] = &[
    Operation {
        id: "byte_direct_is_match",
        facade: Facade::Byte,
        cohort: "byte-direct",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_direct_find_owned",
        facade: Facade::Byte,
        cohort: "byte-direct",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_direct_find_borrowed",
        facade: Facade::Byte,
        cohort: "byte-direct",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_direct_find_at",
        facade: Facade::Byte,
        cohort: "byte-cursor",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_direct_find_window",
        facade: Facade::Byte,
        cohort: "byte-window",
        comparable_to_rust: false,
        transition: false,
    },
    Operation {
        id: "byte_endpoint_is_match",
        facade: Facade::Byte,
        cohort: "byte-endpoint-session",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_endpoint_selected_end",
        facade: Facade::Byte,
        cohort: "byte-endpoint-session",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_bidi_find",
        facade: Facade::Byte,
        cohort: "byte-bidirectional-session",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_bidi_find_borrowed",
        facade: Facade::Byte,
        cohort: "byte-bidirectional-session",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_bidi_find_at_cursor",
        facade: Facade::Byte,
        cohort: "byte-cursor",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_iter_owned",
        facade: Facade::Byte,
        cohort: "byte-iterator",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_iter_borrowed",
        facade: Facade::Byte,
        cohort: "byte-iterator",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "byte_bidi_setup_first_warm",
        facade: Facade::Byte,
        cohort: "cold-warm-transition",
        comparable_to_rust: false,
        transition: true,
    },
    Operation {
        id: "byte_endpoint_setup_first_warm",
        facade: Facade::Byte,
        cohort: "cold-warm-transition",
        comparable_to_rust: false,
        transition: true,
    },
    Operation {
        id: "text_direct_is_match",
        facade: Facade::Text,
        cohort: "text-direct",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "text_direct_find",
        facade: Facade::Text,
        cohort: "text-direct",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "text_direct_find_at",
        facade: Facade::Text,
        cohort: "text-cursor",
        comparable_to_rust: true,
        transition: false,
    },
    Operation {
        id: "text_direct_find_window",
        facade: Facade::Text,
        cohort: "text-window",
        comparable_to_rust: false,
        transition: false,
    },
    Operation {
        id: "text_iter",
        facade: Facade::Text,
        cohort: "text-iterator",
        comparable_to_rust: true,
        transition: false,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Tier {
    Short,
    Medium,
    Large,
}

impl Tier {
    const ALL: [Self; 3] = [Self::Short, Self::Medium, Self::Large];

    const fn id(self) -> &'static str {
        match self {
            Self::Short => "short",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }

    const fn len(self) -> usize {
        match self {
            Self::Short => 31,
            Self::Medium => 4_093,
            Self::Large => 262_139,
        }
    }
}

#[derive(Debug, Serialize)]
struct PointSpec {
    case_id: &'static str,
    family: &'static str,
    consuming_class: &'static str,
    nullable: bool,
    contextual: bool,
    native_control: bool,
    tier: &'static str,
    input_bytes: usize,
    operation: &'static str,
    facade: Facade,
    cohort: &'static str,
    comparable_to_rust: bool,
    transition: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
struct MatchDigest {
    count: u64,
    sum_start: u64,
    sum_end: u64,
    mixed: u64,
}

impl MatchDigest {
    fn push(&mut self, start: usize, end: usize) {
        self.count = self.count.wrapping_add(1);
        self.sum_start = self
            .sum_start
            .wrapping_add(u64::try_from(start).unwrap_or(u64::MAX));
        self.sum_end = self
            .sum_end
            .wrapping_add(u64::try_from(end).unwrap_or(u64::MAX));
        let pair = (u64::try_from(start).unwrap_or(u64::MAX) << 32)
            ^ u64::try_from(end).unwrap_or(u64::MAX);
        self.mixed ^= mix64(pair.wrapping_add(self.count));
    }

    fn scalar(self) -> u64 {
        self.count ^ self.sum_start.rotate_left(11) ^ self.sum_end.rotate_left(29) ^ self.mixed
    }
}

#[derive(Debug, Serialize)]
struct IteratorOutcome {
    digest: MatchDigest,
    accounting: Value,
    setup: Option<Value>,
    terminal_error: bool,
}

#[derive(Debug, Serialize)]
struct PointResult<'a> {
    schema: &'static str,
    case_id: &'a str,
    family: &'a str,
    tier: &'a str,
    operation: &'a str,
    cohort: &'a str,
    engine: &'a str,
    comparable_to_rust: bool,
    transition: bool,
    input_bytes: usize,
    iterations: usize,
    elapsed_ns: u128,
    ns_per_iteration: f64,
    checksum: u64,
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn case_by_id(id: &str) -> Option<&'static Case> {
    CASES.iter().find(|case| case.id == id)
}

fn operation_by_id(id: &str) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|operation| operation.id == id)
}

fn parse_tier(id: &str) -> Option<Tier> {
    match id {
        "short" => Some(Tier::Short),
        "medium" => Some(Tier::Medium),
        "large" => Some(Tier::Large),
        _ => None,
    }
}

fn supports(case: Case, facade: Facade) -> bool {
    matches!(
        (case.scope, facade),
        (Scope::Both, _) | (Scope::Text, Facade::Text)
    )
}

fn catalog() -> Vec<PointSpec> {
    let mut points = Vec::new();
    for case in CASES {
        for tier in Tier::ALL {
            for operation in OPERATIONS {
                if !supports(*case, operation.facade) {
                    continue;
                }
                points.push(PointSpec {
                    case_id: case.id,
                    family: case.family,
                    consuming_class: case.consuming_class,
                    nullable: case.nullable,
                    contextual: case.contextual,
                    native_control: case.native_control,
                    tier: tier.id(),
                    input_bytes: tier.len(),
                    operation: operation.id,
                    facade: operation.facade,
                    cohort: operation.cohort,
                    comparable_to_rust: operation.comparable_to_rust,
                    transition: operation.transition,
                });
            }
        }
    }
    points
}

fn replace_token(bytes: &mut [u8], offset: usize, token: &[u8]) {
    if token.len() > bytes.len() {
        return;
    }
    let start = offset.min(bytes.len() - token.len());
    bytes[start..start + token.len()].copy_from_slice(token);
}

fn make_haystack(case: Case, tier: Tier) -> String {
    let len = tier.len();
    let mut bytes = vec![b' '; len];
    let alphabet = b"bcdefghij klmnop_0123456789\n";
    let mut state =
        SEED ^ mix64(
            case.id
                .bytes()
                .fold(0_u64, |hash, byte| hash.wrapping_mul(131) ^ u64::from(byte)),
        ) ^ u64::try_from(len).unwrap_or(u64::MAX);
    for byte in &mut bytes {
        state = mix64(state.wrapping_add(0x9e37_79b9_7f4a_7c15));
        let index = usize::try_from(state % u64::try_from(alphabet.len()).unwrap()).unwrap();
        *byte = alphabet[index];
    }

    let quarter = len / 4;
    let half = len / 2;
    let three_quarters = len.saturating_mul(3) / 4;
    for (offset, token) in [
        (0, b"abcdefgh\n".as_slice()),
        (quarter, b"abcdZ\n".as_slice()),
        (half, b" needle ".as_slice()),
        (three_quarters, b" alpha beta gamma ".as_slice()),
    ] {
        replace_token(&mut bytes, offset, token);
    }

    match case.id {
        "c0_line_start" | "c1_line_class" | "c2_line_classes" | "c3_line_classes"
        | "c4_line_classes" => {
            replace_token(&mut bytes, quarter, b"\nabcdefgh\n");
            replace_token(&mut bytes, three_quarters, b"\nabcdefgh\n");
        }
        "nullable_empty_first"
        | "nullable_empty_last"
        | "nullable_optional_repeat"
        | "nullable_boundary_priority" => {
            replace_token(&mut bytes, quarter, b" aaab aZ ");
            replace_token(&mut bytes, three_quarters, b" ab b ");
        }
        "self_loop_class" => {
            let run = (len / 9).clamp(3, 8_191);
            let start = quarter.min(len.saturating_sub(run + 2));
            bytes[start] = b'a';
            bytes[start + 1..start + run + 1].fill(b'b');
            bytes[start + run + 1] = b'Z';
        }
        "self_loop_negated" => {
            let run = (len / 9).clamp(3, 8_191);
            let start = quarter.min(len.saturating_sub(run + 2));
            bytes[start] = b'x';
            bytes[start + 1..start + run + 1].fill(b'v');
            bytes[start + run + 1] = b'Z';
        }
        "self_loop_plus" => {
            let run = (len / 9).clamp(3, 8_191);
            let start = quarter.min(len.saturating_sub(run + 1));
            bytes[start..start + run].fill(b'm');
            bytes[start + run] = b'Z';
        }
        "self_loop_alternating" => {
            let run = (len / 11).clamp(3, 8_191);
            let start = quarter.min(len.saturating_sub(run + 2));
            bytes[start] = b'q';
            bytes[start + 1..start + run + 1].fill(b'd');
            bytes[start + run + 1] = b'Y';
        }
        "context_line_loop" => {
            replace_token(&mut bytes, quarter, b"\nabcdefghZ\n");
            replace_token(&mut bytes, three_quarters, b"\nmnopZ\n");
        }
        "context_word_loop" => {
            replace_token(&mut bytes, quarter, b" abcdefghZ ");
            replace_token(&mut bytes, three_quarters, b" mnopZ ");
        }
        "native_literal" => {
            replace_token(&mut bytes, quarter, b"needle");
            replace_token(&mut bytes, three_quarters, b"needle");
        }
        "native_literal_set" => {
            replace_token(&mut bytes, quarter, b"alpha");
            replace_token(&mut bytes, half, b"beta");
            replace_token(&mut bytes, three_quarters, b"gamma");
        }
        "native_fixed_context" => {
            replace_token(&mut bytes, quarter, b"\nprefix12345suffix\n");
            replace_token(&mut bytes, three_quarters, b"\nprefix7suffix\n");
        }
        "text_nullable_utf8" | "text_nullable_utf8_last" | "text_unicode_context" => {
            bytes.fill(b'x');
            replace_token(&mut bytes, 1, " élan ".as_bytes());
            replace_token(&mut bytes, len / 3, " 猫 ".as_bytes());
            replace_token(&mut bytes, len.saturating_mul(2) / 3, " é 猫 ".as_bytes());
        }
        _ => {}
    }
    String::from_utf8(bytes).expect("gate generator emits valid UTF-8")
}

fn span_value(start: usize, end: usize) -> Value {
    json!([start, end])
}

fn optional_fre_span(matched: Option<fre::Match>) -> Value {
    matched.map_or(Value::Null, |matched| {
        span_value(matched.start(), matched.end())
    })
}

fn optional_fre_borrowed(matched: Option<fre::ByteMatch<'_>>) -> Value {
    matched.map_or(Value::Null, |matched| {
        span_value(matched.start(), matched.end())
    })
}

fn optional_rust_span(matched: Option<regex::Match<'_>>) -> Value {
    matched.map_or(Value::Null, |matched| {
        span_value(matched.start(), matched.end())
    })
}

fn optional_rust_byte_span(matched: Option<regex::bytes::Match<'_>>) -> Value {
    matched.map_or(Value::Null, |matched| {
        span_value(matched.start(), matched.end())
    })
}

fn setup_value(setup: SearchSessionSetupAccounting) -> Value {
    json!({
        "work": setup.work(),
        "allocated_bytes": setup.allocated_bytes(),
        "initialized_bytes": setup.initialized_bytes(),
        "retained_bytes": setup.retained_bytes(),
        "reused": setup.reused(),
    })
}

fn accounting_value(accounting: &SearchAccounting) -> Value {
    let mut value = json!({
        "plan": format!("{:?}", accounting.plan()),
        "work_or_linear_terms": accounting.work_or_linear_terms(),
    });
    if let SearchAccounting::K0(k0) = accounting {
        value["k0"] = json!({
            "work": k0.work(),
            "setup_work": k0.setup_work(),
            "transition_work": k0.transition_work(),
            "scratch_bytes": k0.scratch_bytes(),
            "boundaries": k0.boundaries(),
            "setup": setup_value(k0.setup()),
        });
    }
    value
}

fn iterator_accounting_value(accounting: PortableFindIterAccounting) -> Value {
    json!({
        "search_calls": accounting.search_calls,
        "matches": accounting.matches,
        "suppressed_empty": accounting.suppressed_empty,
        "work_or_linear_terms": accounting.work_or_linear_terms,
        "utf8_progress_byte_probes": accounting.utf8_progress_byte_probes,
        "utf8_progress_work": accounting.utf8_progress_work,
    })
}

fn collect_fre_byte_owned(
    regex: &PortableRegex,
    haystack: &[u8],
    limits: PortableFindIterLimits,
) -> Result<IteratorOutcome, String> {
    let mut iter = regex
        .find_iter(haystack, limits)
        .map_err(|error| format!("byte iterator construction: {error:?}"))?;
    let setup = iter.workspace_setup_accounting().map(setup_value);
    let mut digest = MatchDigest::default();
    let mut terminal_error = false;
    for item in iter.by_ref() {
        match item {
            Ok(matched) => digest.push(matched.start(), matched.end()),
            Err(_) => {
                terminal_error = true;
                break;
            }
        }
    }
    Ok(IteratorOutcome {
        digest,
        accounting: iterator_accounting_value(iter.accounting()),
        setup,
        terminal_error,
    })
}

fn collect_fre_byte_borrowed(
    regex: &PortableRegex,
    haystack: &[u8],
    limits: PortableFindIterLimits,
) -> Result<IteratorOutcome, String> {
    let mut iter = regex
        .find_iter_borrowed(haystack, limits)
        .map_err(|error| format!("borrowed byte iterator construction: {error:?}"))?;
    let setup = iter.workspace_setup_accounting().map(setup_value);
    let mut digest = MatchDigest::default();
    let mut terminal_error = false;
    for item in iter.by_ref() {
        match item {
            Ok(matched) => {
                black_box(matched.as_bytes());
                digest.push(matched.start(), matched.end());
            }
            Err(_) => {
                terminal_error = true;
                break;
            }
        }
    }
    Ok(IteratorOutcome {
        digest,
        accounting: iterator_accounting_value(iter.accounting()),
        setup,
        terminal_error,
    })
}

fn collect_fre_text(
    regex: &PortableTextRegex,
    haystack: &str,
    limits: PortableFindIterLimits,
) -> Result<IteratorOutcome, String> {
    let mut iter = regex
        .find_iter(haystack, limits)
        .map_err(|error| format!("text iterator construction: {error:?}"))?;
    let setup = iter.workspace_setup_accounting().map(setup_value);
    let mut digest = MatchDigest::default();
    let mut terminal_error = false;
    for item in iter.by_ref() {
        match item {
            Ok(matched) => digest.push(matched.start(), matched.end()),
            Err(_) => {
                terminal_error = true;
                break;
            }
        }
    }
    Ok(IteratorOutcome {
        digest,
        accounting: iterator_accounting_value(iter.accounting()),
        setup,
        terminal_error,
    })
}

fn rust_byte_digest(regex: &RustByteRegex, haystack: &[u8]) -> MatchDigest {
    let mut digest = MatchDigest::default();
    for matched in regex.find_iter(haystack) {
        digest.push(matched.start(), matched.end());
    }
    digest
}

fn rust_text_digest(regex: &RustTextRegex, haystack: &str) -> MatchDigest {
    let mut digest = MatchDigest::default();
    for matched in regex.find_iter(haystack) {
        digest.push(matched.start(), matched.end());
    }
    digest
}

fn finite_search_limits(work: u64) -> SearchLimits {
    SearchLimits {
        max_work: work,
        max_scratch_bytes: usize::MAX,
    }
}

fn iterator_limits(max_calls: usize) -> PortableFindIterLimits {
    PortableFindIterLimits {
        session: SearchSessionLimits::unlimited(),
        search: SearchLimits::unlimited(),
        max_search_calls: max_calls,
    }
}

fn verify_byte(case: Case, tier: Tier) -> Result<Value, String> {
    let haystack_string = make_haystack(case, tier);
    let haystack = haystack_string.as_bytes();
    let fre = PortableRegex::new(case.pattern.to_owned())
        .map_err(|error| format!("{} FRE byte build: {error:?}", case.id))?;
    let rust = RustByteRegex::new(case.pattern)
        .map_err(|error| format!("{} Rust byte build: {error:?}", case.id))?;
    let limits = SearchLimits::unlimited();
    let start = (haystack.len() / 7).min(haystack.len());
    let window_start = (haystack.len() / 11).min(haystack.len());
    let window_end = haystack
        .len()
        .saturating_sub(haystack.len() / 13)
        .max(window_start);

    let (fre_exists, exists_accounting) = fre
        .is_match_accounted(haystack, limits)
        .map_err(|error| format!("{} FRE is_match: {error:?}", case.id))?;
    let rust_exists = rust.is_match(haystack);
    if fre_exists != rust_exists {
        return Err(format!("{} byte is_match differs from Rust", case.id));
    }

    let (fre_find, find_accounting) = fre
        .find_accounted(haystack, limits)
        .map_err(|error| format!("{} FRE find: {error:?}", case.id))?;
    let rust_find = rust.find(haystack);
    if optional_fre_span(fre_find) != optional_rust_byte_span(rust_find) {
        return Err(format!("{} byte find differs from Rust", case.id));
    }
    let (fre_borrowed, borrowed_accounting) = fre
        .find_borrowed(haystack, limits)
        .map_err(|error| format!("{} FRE find_borrowed: {error:?}", case.id))?;
    if optional_fre_borrowed(fre_borrowed) != optional_rust_byte_span(rust.find(haystack)) {
        return Err(format!("{} byte borrowed find differs from Rust", case.id));
    }
    let (fre_at, at_accounting) = fre
        .find_at(haystack, start, limits)
        .map_err(|error| format!("{} FRE find_at: {error:?}", case.id))?;
    if optional_fre_span(fre_at) != optional_rust_byte_span(rust.find_at(haystack, start)) {
        return Err(format!("{} byte find_at differs from Rust", case.id));
    }
    let (fre_window, window_accounting) = fre
        .find_window(
            haystack,
            SearchWindow::new(window_start, window_end),
            limits,
        )
        .map_err(|error| format!("{} FRE find_window: {error:?}", case.id))?;

    let owned = collect_fre_byte_owned(&fre, haystack, iterator_limits(usize::MAX))?;
    let borrowed = collect_fre_byte_borrowed(&fre, haystack, iterator_limits(usize::MAX))?;
    let rust_digest = rust_byte_digest(&rust, haystack);
    if owned.digest != rust_digest || borrowed.digest != rust_digest {
        return Err(format!("{} byte iterator differs from Rust", case.id));
    }
    if owned.terminal_error || borrowed.terminal_error {
        return Err(format!("{} unlimited byte iterator refused", case.id));
    }

    let mut endpoint = fre
        .endpoint_search_session(SearchSessionLimits::unlimited())
        .map_err(|error| format!("{} endpoint setup: {error:?}", case.id))?;
    let endpoint_setup = endpoint.workspace_setup_accounting().map(setup_value);
    let (endpoint_first, endpoint_first_accounting) = endpoint
        .is_match(haystack, limits)
        .map_err(|error| format!("{} endpoint first: {error:?}", case.id))?;
    let (endpoint_warm, endpoint_warm_accounting) = endpoint
        .is_match(haystack, limits)
        .map_err(|error| format!("{} endpoint warm: {error:?}", case.id))?;
    let (endpoint_end, endpoint_end_accounting) = endpoint
        .selected_end(haystack, limits)
        .map_err(|error| format!("{} endpoint selected_end: {error:?}", case.id))?;
    if endpoint_first != fre_exists || endpoint_warm != fre_exists {
        return Err(format!("{} endpoint session output differs", case.id));
    }

    let mut bidi = fre
        .search_session(SearchSessionLimits::unlimited())
        .map_err(|error| format!("{} bidi setup: {error:?}", case.id))?;
    let bidi_setup = bidi.workspace_setup_accounting().map(setup_value);
    let (bidi_first, bidi_first_accounting) = bidi
        .find(haystack, limits)
        .map_err(|error| format!("{} bidi first: {error:?}", case.id))?;
    let (bidi_warm, bidi_warm_accounting) = bidi
        .find(haystack, limits)
        .map_err(|error| format!("{} bidi warm: {error:?}", case.id))?;
    let (bidi_at, bidi_at_accounting) = bidi
        .find_at(haystack, start, limits)
        .map_err(|error| format!("{} bidi find_at: {error:?}", case.id))?;
    if bidi_first != fre_find || bidi_warm != fre_find || bidi_at != fre_at {
        return Err(format!("{} bidirectional session output differs", case.id));
    }

    let mut finite_session = fre
        .search_session(SearchSessionLimits::unlimited())
        .map_err(|error| format!("{} finite session setup: {error:?}", case.id))?;
    let initial_zero_refused = match finite_session.find(haystack, finite_search_limits(0)) {
        Err(_) => true,
        Ok((output, _)) => {
            if output != fre_find {
                return Err(format!("{} zero-work finite output differs", case.id));
            }
            false
        }
    };
    let mut previous_work = None;
    let mut work = None;
    for _ in 0..32 {
        let calibrated = finite_session
            .find(haystack, limits)
            .map_err(|error| format!("{} unlimited recovery/calibration: {error:?}", case.id))?;
        if calibrated.0 != fre_find {
            return Err(format!("{} finite calibration output differs", case.id));
        }
        let next_work = calibrated.1.work_or_linear_terms();
        if previous_work == Some(next_work) {
            work = Some(next_work);
            break;
        }
        previous_work = Some(next_work);
    }
    let work = work.ok_or_else(|| format!("{} finite work did not stabilize", case.id))?;
    let mut exact_probe_steps = 0_usize;
    let mut rejected_limit = None;
    let mut accepted_limit = work;
    loop {
        match finite_session.find(haystack, finite_search_limits(accepted_limit)) {
            Ok(result) => {
                if result.0 != fre_find {
                    return Err(format!("{} exact finite probe output differs", case.id));
                }
                break;
            }
            Err(_) => {
                rejected_limit = Some(accepted_limit);
                accepted_limit = accepted_limit
                    .max(1)
                    .checked_mul(2)
                    .ok_or_else(|| format!("{} exact finite probe overflowed", case.id))?;
                exact_probe_steps = exact_probe_steps.saturating_add(1);
                if exact_probe_steps > 63 {
                    return Err(format!("{} exact finite probe did not converge", case.id));
                }
            }
        }
    }
    if let Some(mut rejected) = rejected_limit {
        while accepted_limit > rejected.saturating_add(1) {
            let middle = rejected + (accepted_limit - rejected) / 2;
            match finite_session.find(haystack, finite_search_limits(middle)) {
                Ok((output, _)) => {
                    if output != fre_find {
                        return Err(format!("{} exact finite bisection output differs", case.id));
                    }
                    accepted_limit = middle;
                }
                Err(_) => rejected = middle,
            }
            exact_probe_steps = exact_probe_steps.saturating_add(1);
            if exact_probe_steps > 127 {
                return Err(format!(
                    "{} exact finite bisection did not converge",
                    case.id
                ));
            }
        }
    }
    let exact_limit = accepted_limit;
    let exact_result = finite_session
        .find(haystack, finite_search_limits(exact_limit))
        .map_err(|error| format!("{} exact finite confirmation: {error:?}", case.id))?;
    if exact_result.0 != fre_find {
        return Err(format!("{} exact finite output differs", case.id));
    }
    let mut refusal_work = exact_limit;
    let mut recovery_limit = exact_limit;
    let mut decline_steps = 0_usize;
    let one_below_refused = loop {
        if refusal_work == 0 {
            break true;
        }
        match finite_session.find(haystack, finite_search_limits(refusal_work - 1)) {
            Err(_) => break true,
            Ok((output, accounting)) => {
                if output != fre_find {
                    return Err(format!("{} declining finite output differs", case.id));
                }
                let next_work = accounting.work_or_linear_terms();
                if next_work >= refusal_work {
                    return Err(format!(
                        "{} accepted one-below without a strict work decline",
                        case.id
                    ));
                }
                recovery_limit = refusal_work - 1;
                refusal_work = next_work;
                decline_steps = decline_steps.saturating_add(1);
                if decline_steps > 32 {
                    return Err(format!("{} finite work did not reach refusal", case.id));
                }
            }
        }
    };
    let recovered = finite_session
        .find(haystack, finite_search_limits(recovery_limit))
        .map_err(|error| format!("{} recovery after refusal: {error:?}", case.id))?;
    if recovered.0 != fre_find {
        return Err(format!("{} recovery output differs", case.id));
    }
    let default_result = fre
        .find_with_limits(haystack, SearchLimits::default())
        .map_err(|error| format!("{} default finite search: {error:?}", case.id))?;
    if default_result != fre_find {
        return Err(format!("{} default finite output differs", case.id));
    }

    let exact_calls = owned.accounting["search_calls"]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| format!("{} missing byte iterator calls", case.id))?;
    let exact_iter = collect_fre_byte_owned(&fre, haystack, iterator_limits(exact_calls))?;
    if exact_iter.digest != owned.digest || exact_iter.terminal_error {
        return Err(format!("{} exact finite iterator differs", case.id));
    }
    let below_iter = if exact_calls == 0 {
        collect_fre_byte_owned(&fre, haystack, iterator_limits(0))?
    } else {
        collect_fre_byte_owned(&fre, haystack, iterator_limits(exact_calls - 1))?
    };
    if exact_calls > 0 && !below_iter.terminal_error {
        return Err(format!("{} one-below iterator did not refuse", case.id));
    }
    let recovered_iter = collect_fre_byte_owned(&fre, haystack, iterator_limits(exact_calls))?;
    if recovered_iter.digest != owned.digest || recovered_iter.terminal_error {
        return Err(format!("{} iterator recovery differs", case.id));
    }

    Ok(json!({
        "case_id": case.id,
        "tier": tier.id(),
        "input_bytes": haystack.len(),
        "pattern": case.pattern,
        "family": case.family,
        "consuming_class": case.consuming_class,
        "nullable": case.nullable,
        "contextual": case.contextual,
        "native_control": case.native_control,
        "runtime_implementation_id": fre.runtime_implementation_id(),
        "semantic": {
            "is_match": fre_exists,
            "find": optional_fre_span(fre_find),
            "find_borrowed": optional_fre_borrowed(fre_borrowed),
            "find_at": optional_fre_span(fre_at),
            "find_window": optional_fre_span(fre_window),
            "iterator": owned.digest,
            "rust_iterator": rust_digest,
            "endpoint_selected_end": endpoint_end,
            "bidi_find": optional_fre_span(bidi_first),
            "bidi_find_at": optional_fre_span(bidi_at),
        },
        "accounting": {
            "direct_is_match": accounting_value(&exists_accounting),
            "direct_find": accounting_value(&find_accounting),
            "direct_find_borrowed": accounting_value(&borrowed_accounting),
            "direct_find_at": accounting_value(&at_accounting),
            "direct_find_window": accounting_value(&window_accounting),
            "endpoint_first": accounting_value(&endpoint_first_accounting),
            "endpoint_warm": accounting_value(&endpoint_warm_accounting),
            "endpoint_selected_end": accounting_value(&endpoint_end_accounting),
            "bidi_first": accounting_value(&bidi_first_accounting),
            "bidi_warm": accounting_value(&bidi_warm_accounting),
            "bidi_find_at": accounting_value(&bidi_at_accounting),
            "iterator_owned": owned.accounting,
            "iterator_borrowed": borrowed.accounting,
        },
        "setup": {
            "endpoint": endpoint_setup,
            "bidirectional": bidi_setup,
            "iterator_owned": owned.setup,
            "iterator_borrowed": borrowed.setup,
        },
        "finite": {
            "default_matches": true,
            "initial_zero_refused": initial_zero_refused,
            "reported_warm_work": work,
            "exact_work": exact_limit,
            "exact_probe_steps": exact_probe_steps,
            "refusal_work": refusal_work,
            "recovery_limit": recovery_limit,
            "decline_steps": decline_steps,
            "exact_matches": true,
            "one_below_refused": one_below_refused,
            "recovered": true,
            "iterator_exact_calls": exact_calls,
            "iterator_one_below_refused": below_iter.terminal_error,
            "iterator_recovered": true,
        },
    }))
}

fn next_text_boundary(haystack: &str, mut start: usize) -> usize {
    if start >= haystack.len() {
        return start;
    }
    while !haystack.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    start
}

fn verify_text(case: Case, tier: Tier) -> Result<Value, String> {
    let haystack = make_haystack(case, tier);
    let fre = PortableTextRegex::new(case.pattern.to_owned())
        .map_err(|error| format!("{} FRE text build: {error:?}", case.id))?;
    let rust = RustTextRegex::new(case.pattern)
        .map_err(|error| format!("{} Rust text build: {error:?}", case.id))?;
    let limits = SearchLimits::unlimited();
    let raw_start = (haystack.len() / 7).min(haystack.len());
    let start = next_text_boundary(&haystack, raw_start);
    let mut window_start = next_text_boundary(&haystack, haystack.len() / 11);
    let mut window_end = next_text_boundary(
        &haystack,
        haystack.len().saturating_sub(haystack.len() / 13),
    );
    if window_end < window_start {
        std::mem::swap(&mut window_start, &mut window_end);
    }

    let (fre_exists, exists_accounting) = fre
        .is_match_accounted(&haystack, limits)
        .map_err(|error| format!("{} FRE text is_match: {error:?}", case.id))?;
    if fre_exists != rust.is_match(&haystack) {
        return Err(format!("{} text is_match differs from Rust", case.id));
    }
    let (fre_find, find_accounting) = fre
        .find_accounted(&haystack, limits)
        .map_err(|error| format!("{} FRE text find: {error:?}", case.id))?;
    if optional_fre_span(fre_find) != optional_rust_span(rust.find(&haystack)) {
        return Err(format!("{} text find differs from Rust", case.id));
    }
    let (fre_at, at_accounting) = fre
        .find_at(&haystack, raw_start, limits)
        .map_err(|error| format!("{} FRE text find_at: {error:?}", case.id))?;
    if optional_fre_span(fre_at) != optional_rust_span(rust.find_at(&haystack, start)) {
        return Err(format!("{} text find_at differs from Rust", case.id));
    }
    let (fre_window, window_accounting) = fre
        .find_window(
            &haystack,
            SearchWindow::new(window_start, window_end),
            limits,
        )
        .map_err(|error| format!("{} FRE text window: {error:?}", case.id))?;

    let unlimited = collect_fre_text(&fre, &haystack, iterator_limits(usize::MAX))?;
    let rust_digest = rust_text_digest(&rust, &haystack);
    if unlimited.digest != rust_digest || unlimited.terminal_error {
        return Err(format!("{} text iterator differs from Rust", case.id));
    }
    let exact_calls = unlimited.accounting["search_calls"]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| format!("{} missing text iterator calls", case.id))?;
    let exact = collect_fre_text(&fre, &haystack, iterator_limits(exact_calls))?;
    if exact.digest != unlimited.digest || exact.terminal_error {
        return Err(format!("{} exact text iterator differs", case.id));
    }
    let below = if exact_calls == 0 {
        collect_fre_text(&fre, &haystack, iterator_limits(0))?
    } else {
        collect_fre_text(&fre, &haystack, iterator_limits(exact_calls - 1))?
    };
    if exact_calls > 0 && !below.terminal_error {
        return Err(format!(
            "{} one-below text iterator did not refuse",
            case.id
        ));
    }
    let recovered = collect_fre_text(&fre, &haystack, iterator_limits(exact_calls))?;
    if recovered.digest != unlimited.digest || recovered.terminal_error {
        return Err(format!("{} text iterator recovery differs", case.id));
    }

    let default_iter = collect_fre_text(&fre, &haystack, PortableFindIterLimits::default())?;
    if default_iter.digest != unlimited.digest || default_iter.terminal_error {
        return Err(format!("{} default text iterator differs", case.id));
    }

    Ok(json!({
        "case_id": case.id,
        "tier": tier.id(),
        "input_bytes": haystack.len(),
        "pattern": case.pattern,
        "family": case.family,
        "consuming_class": case.consuming_class,
        "nullable": case.nullable,
        "contextual": case.contextual,
        "native_control": case.native_control,
        "runtime_implementation_id": format!("{:?}", fre.build_report().portable.plan),
        "semantic": {
            "is_match": fre_exists,
            "find": optional_fre_span(fre_find),
            "find_at": optional_fre_span(fre_at),
            "find_window": optional_fre_span(fre_window),
            "iterator": unlimited.digest,
            "rust_iterator": rust_digest,
        },
        "accounting": {
            "direct_is_match": accounting_value(&exists_accounting),
            "direct_find": accounting_value(&find_accounting),
            "direct_find_at": accounting_value(&at_accounting),
            "direct_find_window": accounting_value(&window_accounting),
            "iterator": unlimited.accounting,
        },
        "setup": {
            "iterator": unlimited.setup,
        },
        "finite": {
            "default_matches": true,
            "iterator_exact_calls": exact_calls,
            "iterator_one_below_refused": below.terminal_error,
            "iterator_recovered": true,
        },
    }))
}

fn verify() -> Result<Value, String> {
    let mut records = Vec::new();
    for case in CASES {
        for tier in Tier::ALL {
            if supports(*case, Facade::Byte) {
                records.push(json!({
                    "facade": "byte",
                    "receipt": verify_byte(*case, tier)?,
                }));
            }
            if supports(*case, Facade::Text) {
                records.push(json!({
                    "facade": "text",
                    "receipt": verify_text(*case, tier)?,
                }));
            }
        }
    }
    Ok(json!({
        "schema": SCHEMA,
        "seed": SEED,
        "tiers": Tier::ALL.map(|tier| json!({"id": tier.id(), "bytes": tier.len()})),
        "case_count": CASES.len(),
        "record_count": records.len(),
        "records": records,
    }))
}

fn iterations(tier: Tier, operation: Operation) -> usize {
    let iterator = operation.id.contains("iter");
    let transition = operation.transition;
    match (tier, iterator, transition) {
        (Tier::Short, true, _) => 3_001,
        (Tier::Medium, true, _) => 31,
        (Tier::Large, true, _) => 3,
        (Tier::Short, false, true) => 10_007,
        (Tier::Medium, false, true) => 509,
        (Tier::Large, false, true) => 17,
        (Tier::Short, false, false) => 100_003,
        (Tier::Medium, false, false) => 4_099,
        (Tier::Large, false, false) => 67,
    }
}

fn update_checksum(checksum: &mut u64, start: usize, end: usize, ordinal: usize) {
    let value = u64::try_from(start).unwrap_or(u64::MAX)
        ^ u64::try_from(end).unwrap_or(u64::MAX).rotate_left(23)
        ^ u64::try_from(ordinal).unwrap_or(u64::MAX);
    *checksum = checksum.wrapping_add(mix64(value));
}

fn time_fre_byte(
    case: Case,
    tier: Tier,
    operation: Operation,
    iterations: usize,
) -> Result<(u128, u64), String> {
    let haystack = make_haystack(case, tier);
    let haystack = haystack.as_bytes();
    let regex = PortableRegex::new(case.pattern.to_owned())
        .map_err(|error| format!("FRE byte build: {error:?}"))?;
    let limits = SearchLimits::unlimited();
    let start_offset = (haystack.len() / 7).min(haystack.len());
    let window = SearchWindow::new(
        (haystack.len() / 11).min(haystack.len()),
        haystack
            .len()
            .saturating_sub(haystack.len() / 13)
            .max(haystack.len() / 11),
    );

    if operation.id == "byte_bidi_setup_first_warm"
        || operation.id == "byte_endpoint_setup_first_warm"
    {
        let mut warm = if operation.id == "byte_bidi_setup_first_warm" {
            regex.search_session(SearchSessionLimits::unlimited())
        } else {
            regex.endpoint_search_session(SearchSessionLimits::unlimited())
        }
        .map_err(|error| format!("FRE transition warm setup: {error:?}"))?;
        black_box(
            warm.find(haystack, limits)
                .map_err(|error| format!("FRE transition warm call: {error:?}"))?,
        );
        let mut checksum = 0_u64;
        let timer = Instant::now();
        for ordinal in 0..iterations {
            let mut session = if operation.id == "byte_bidi_setup_first_warm" {
                regex.search_session(SearchSessionLimits::unlimited())
            } else {
                regex.endpoint_search_session(SearchSessionLimits::unlimited())
            }
            .map_err(|error| format!("FRE transition setup: {error:?}"))?;
            let first = session
                .find(haystack, limits)
                .map_err(|error| format!("FRE transition first: {error:?}"))?
                .0;
            let warm = session
                .find(haystack, limits)
                .map_err(|error| format!("FRE transition second: {error:?}"))?
                .0;
            if let Some(matched) = first {
                update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
            }
            if let Some(matched) = warm {
                update_checksum(&mut checksum, matched.start(), matched.end(), ordinal + 1);
            }
        }
        return Ok((timer.elapsed().as_nanos(), black_box(checksum)));
    }

    let mut endpoint = if operation.id.starts_with("byte_endpoint_") {
        Some(
            regex
                .endpoint_search_session(SearchSessionLimits::unlimited())
                .map_err(|error| format!("FRE endpoint setup: {error:?}"))?,
        )
    } else {
        None
    };
    let mut bidi = if operation.id.starts_with("byte_bidi_") {
        Some(
            regex
                .search_session(SearchSessionLimits::unlimited())
                .map_err(|error| format!("FRE bidi setup: {error:?}"))?,
        )
    } else {
        None
    };

    match operation.id {
        "byte_endpoint_is_match" => {
            black_box(
                endpoint
                    .as_mut()
                    .unwrap()
                    .is_match(haystack, limits)
                    .map_err(|error| format!("warm endpoint is_match: {error:?}"))?,
            );
        }
        "byte_endpoint_selected_end" => {
            black_box(
                endpoint
                    .as_mut()
                    .unwrap()
                    .selected_end(haystack, limits)
                    .map_err(|error| format!("warm endpoint selected_end: {error:?}"))?,
            );
        }
        "byte_bidi_find" | "byte_bidi_find_borrowed" | "byte_bidi_find_at_cursor" => {
            black_box(
                bidi.as_mut()
                    .unwrap()
                    .find(haystack, limits)
                    .map_err(|error| format!("warm bidi find: {error:?}"))?,
            );
        }
        _ => {
            black_box(
                regex
                    .find_with_limits(haystack, limits)
                    .map_err(|error| format!("warm direct find: {error:?}"))?,
            );
        }
    }

    let mut checksum = 0_u64;
    let timer = Instant::now();
    for ordinal in 0..iterations {
        match operation.id {
            "byte_direct_is_match" => {
                let value = regex
                    .is_match_with_limits(haystack, limits)
                    .map_err(|error| format!("FRE is_match: {error:?}"))?;
                checksum = checksum.wrapping_add(u64::from(value));
            }
            "byte_direct_find_owned" => {
                if let Some(matched) = regex
                    .find_with_limits(haystack, limits)
                    .map_err(|error| format!("FRE find: {error:?}"))?
                {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "byte_direct_find_borrowed" => {
                if let Some(matched) = regex
                    .find_borrowed(haystack, limits)
                    .map_err(|error| format!("FRE find_borrowed: {error:?}"))?
                    .0
                {
                    black_box(matched.as_bytes());
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "byte_direct_find_at" => {
                if let Some(matched) = regex
                    .find_at(haystack, start_offset, limits)
                    .map_err(|error| format!("FRE find_at: {error:?}"))?
                    .0
                {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "byte_direct_find_window" => {
                if let Some(matched) = regex
                    .find_window(haystack, window, limits)
                    .map_err(|error| format!("FRE find_window: {error:?}"))?
                    .0
                {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "byte_endpoint_is_match" => {
                let value = endpoint
                    .as_mut()
                    .unwrap()
                    .is_match_value(haystack, limits)
                    .map_err(|error| format!("FRE endpoint is_match: {error:?}"))?;
                checksum = checksum.wrapping_add(u64::from(value));
            }
            "byte_endpoint_selected_end" => {
                if let Some(end) = endpoint
                    .as_mut()
                    .unwrap()
                    .selected_end(haystack, limits)
                    .map_err(|error| format!("FRE endpoint selected_end: {error:?}"))?
                    .0
                {
                    update_checksum(&mut checksum, end, end, ordinal);
                }
            }
            "byte_bidi_find" => {
                if let Some(matched) = bidi
                    .as_mut()
                    .unwrap()
                    .find(haystack, limits)
                    .map_err(|error| format!("FRE bidi find: {error:?}"))?
                    .0
                {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "byte_bidi_find_borrowed" => {
                if let Some(matched) = bidi
                    .as_mut()
                    .unwrap()
                    .find_borrowed(haystack, limits)
                    .map_err(|error| format!("FRE bidi borrowed: {error:?}"))?
                    .0
                {
                    black_box(matched.as_bytes());
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "byte_bidi_find_at_cursor" => {
                if let Some(matched) = bidi
                    .as_mut()
                    .unwrap()
                    .find_at(haystack, start_offset, limits)
                    .map_err(|error| format!("FRE bidi find_at: {error:?}"))?
                    .0
                {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "byte_iter_owned" => {
                let outcome =
                    collect_fre_byte_owned(&regex, haystack, iterator_limits(usize::MAX))?;
                checksum = checksum.wrapping_add(outcome.digest.scalar());
            }
            "byte_iter_borrowed" => {
                let outcome =
                    collect_fre_byte_borrowed(&regex, haystack, iterator_limits(usize::MAX))?;
                checksum = checksum.wrapping_add(outcome.digest.scalar());
            }
            _ => return Err(format!("unsupported FRE byte operation {}", operation.id)),
        }
    }
    Ok((timer.elapsed().as_nanos(), black_box(checksum)))
}

fn time_rust_byte(
    case: Case,
    tier: Tier,
    operation: Operation,
    iterations: usize,
) -> Result<(u128, u64), String> {
    if !operation.comparable_to_rust {
        return Err(format!("operation {} has no Rust comparator", operation.id));
    }
    let haystack = make_haystack(case, tier);
    let haystack = haystack.as_bytes();
    let regex =
        RustByteRegex::new(case.pattern).map_err(|error| format!("Rust build: {error:?}"))?;
    let start_offset = (haystack.len() / 7).min(haystack.len());
    black_box(regex.find(haystack));
    let mut checksum = 0_u64;
    let timer = Instant::now();
    for ordinal in 0..iterations {
        match operation.id {
            "byte_direct_is_match" | "byte_endpoint_is_match" => {
                checksum = checksum.wrapping_add(u64::from(regex.is_match(haystack)));
            }
            "byte_direct_find_owned"
            | "byte_direct_find_borrowed"
            | "byte_bidi_find"
            | "byte_bidi_find_borrowed" => {
                if let Some(matched) = regex.find(haystack) {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "byte_direct_find_at" | "byte_bidi_find_at_cursor" => {
                if let Some(matched) = regex.find_at(haystack, start_offset) {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "byte_endpoint_selected_end" => {
                if let Some(matched) = regex.find(haystack) {
                    update_checksum(&mut checksum, matched.end(), matched.end(), ordinal);
                }
            }
            "byte_iter_owned" | "byte_iter_borrowed" => {
                checksum = checksum.wrapping_add(rust_byte_digest(&regex, haystack).scalar());
            }
            _ => return Err(format!("unsupported Rust byte operation {}", operation.id)),
        }
    }
    Ok((timer.elapsed().as_nanos(), black_box(checksum)))
}

fn time_fre_text(
    case: Case,
    tier: Tier,
    operation: Operation,
    iterations: usize,
) -> Result<(u128, u64), String> {
    let haystack = make_haystack(case, tier);
    let regex = PortableTextRegex::new(case.pattern.to_owned())
        .map_err(|error| format!("FRE text build: {error:?}"))?;
    let limits = SearchLimits::unlimited();
    let raw_start = (haystack.len() / 7).min(haystack.len());
    let mut window_start = next_text_boundary(&haystack, haystack.len() / 11);
    let mut window_end = next_text_boundary(
        &haystack,
        haystack.len().saturating_sub(haystack.len() / 13),
    );
    if window_end < window_start {
        std::mem::swap(&mut window_start, &mut window_end);
    }
    black_box(
        regex
            .find_with_limits(&haystack, limits)
            .map_err(|error| format!("FRE text warm find: {error:?}"))?,
    );
    let mut checksum = 0_u64;
    let timer = Instant::now();
    for ordinal in 0..iterations {
        match operation.id {
            "text_direct_is_match" => {
                let value = regex
                    .is_match_with_limits(&haystack, limits)
                    .map_err(|error| format!("FRE text is_match: {error:?}"))?;
                checksum = checksum.wrapping_add(u64::from(value));
            }
            "text_direct_find" => {
                if let Some(matched) = regex
                    .find_with_limits(&haystack, limits)
                    .map_err(|error| format!("FRE text find: {error:?}"))?
                {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "text_direct_find_at" => {
                if let Some(matched) = regex
                    .find_at(&haystack, raw_start, limits)
                    .map_err(|error| format!("FRE text find_at: {error:?}"))?
                    .0
                {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "text_direct_find_window" => {
                if let Some(matched) = regex
                    .find_window(
                        &haystack,
                        SearchWindow::new(window_start, window_end),
                        limits,
                    )
                    .map_err(|error| format!("FRE text window: {error:?}"))?
                    .0
                {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "text_iter" => {
                let outcome = collect_fre_text(&regex, &haystack, iterator_limits(usize::MAX))?;
                checksum = checksum.wrapping_add(outcome.digest.scalar());
            }
            _ => return Err(format!("unsupported FRE text operation {}", operation.id)),
        }
    }
    Ok((timer.elapsed().as_nanos(), black_box(checksum)))
}

fn time_rust_text(
    case: Case,
    tier: Tier,
    operation: Operation,
    iterations: usize,
) -> Result<(u128, u64), String> {
    if !operation.comparable_to_rust {
        return Err(format!("operation {} has no Rust comparator", operation.id));
    }
    let haystack = make_haystack(case, tier);
    let regex =
        RustTextRegex::new(case.pattern).map_err(|error| format!("Rust build: {error:?}"))?;
    let raw_start = (haystack.len() / 7).min(haystack.len());
    let start = next_text_boundary(&haystack, raw_start);
    black_box(regex.find(&haystack));
    let mut checksum = 0_u64;
    let timer = Instant::now();
    for ordinal in 0..iterations {
        match operation.id {
            "text_direct_is_match" => {
                checksum = checksum.wrapping_add(u64::from(regex.is_match(&haystack)));
            }
            "text_direct_find" => {
                if let Some(matched) = regex.find(&haystack) {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "text_direct_find_at" => {
                if let Some(matched) = regex.find_at(&haystack, start) {
                    update_checksum(&mut checksum, matched.start(), matched.end(), ordinal);
                }
            }
            "text_iter" => {
                checksum = checksum.wrapping_add(rust_text_digest(&regex, &haystack).scalar());
            }
            _ => return Err(format!("unsupported Rust text operation {}", operation.id)),
        }
    }
    Ok((timer.elapsed().as_nanos(), black_box(checksum)))
}

fn point(case: Case, tier: Tier, operation: Operation, engine: &str) -> Result<Value, String> {
    if !supports(case, operation.facade) {
        return Err(format!(
            "case {} does not support {:?}",
            case.id, operation.facade
        ));
    }
    if engine == "rust" && !operation.comparable_to_rust {
        return Err(format!(
            "operation {} is intentionally FRE-only",
            operation.id
        ));
    }
    let count = iterations(tier, operation);
    let (elapsed_ns, checksum) = match (engine, operation.facade) {
        ("fre", Facade::Byte) => time_fre_byte(case, tier, operation, count)?,
        ("rust", Facade::Byte) => time_rust_byte(case, tier, operation, count)?,
        ("fre", Facade::Text) => time_fre_text(case, tier, operation, count)?,
        ("rust", Facade::Text) => time_rust_text(case, tier, operation, count)?,
        _ => return Err(format!("unknown engine {engine}")),
    };
    let result = PointResult {
        schema: SCHEMA,
        case_id: case.id,
        family: case.family,
        tier: tier.id(),
        operation: operation.id,
        cohort: operation.cohort,
        engine,
        comparable_to_rust: operation.comparable_to_rust,
        transition: operation.transition,
        input_bytes: tier.len(),
        iterations: count,
        elapsed_ns,
        ns_per_iteration: elapsed_ns as f64 / count as f64,
        checksum,
    };
    serde_json::to_value(result).map_err(|error| error.to_string())
}

fn usage() -> &'static str {
    "usage:\n  fre-composition-interaction-gate catalog\n  fre-composition-interaction-gate verify\n  fre-composition-interaction-gate point --case ID --tier short|medium|large --operation ID --engine fre|rust"
}

fn arg_value(args: &[String], name: &str) -> Result<String, String> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].clone())
        .ok_or_else(|| format!("missing {name}"))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let command = args
        .get(1)
        .map(String::as_str)
        .ok_or_else(|| usage().to_owned())?;
    let output = match command {
        "catalog" => json!({
            "schema": SCHEMA,
            "seed": SEED,
            "points": catalog(),
        }),
        "verify" => verify()?,
        "point" => {
            let case_id = arg_value(&args, "--case")?;
            let tier_id = arg_value(&args, "--tier")?;
            let operation_id = arg_value(&args, "--operation")?;
            let engine = arg_value(&args, "--engine")?;
            let case = case_by_id(&case_id).ok_or_else(|| format!("unknown case {case_id}"))?;
            let tier = parse_tier(&tier_id).ok_or_else(|| format!("unknown tier {tier_id}"))?;
            let operation = operation_by_id(&operation_id)
                .ok_or_else(|| format!("unknown operation {operation_id}"))?;
            point(*case, tier, *operation, &engine)?
        }
        _ => return Err(usage().to_owned()),
    };
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
