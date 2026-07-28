use std::{env, fs, hint::black_box, time::Instant};

use fre_kernel_ir::Span as NativeSpan;

use super::*;

// Tag21 V4 and tag19 V5 measure the register-return ABI2 facade boundary.
// Existing tag21 V2/V3 and every legacy tag19 result-slot row remain
// historical evidence and must never be relabeled.
const SCHEMA: &str = "fre-jit-tag21-facade-performance-v4";
const TAG19_SCHEMA: &str = "fre-jit-tag19-facade-performance-v5";
const CSV_HEADER: &str = "schema,revision,pid,repetition,literal_class,literal_hex,size,scenario,order,engine,stage,iterations,total_ns,ns_per_iter,checksum,semantic_value,haystack_bytes,route,backend,qualification_state,artifact_sha256,declared_min_window_bytes,declared_min_calls,measured_calls";
const TAG19_CSV_HEADER: &str = "schema,revision,pid,repetition,literal_class,literal_hex,size,scenario,order,engine,stage,iterations,total_ns,ns_per_iter,checksum,semantic_value,haystack_bytes,route,backend,qualification_state,artifact_sha256,declared_min_window_bytes,declared_min_calls,measured_calls,tree,run_id,instance_id,instance_type,resource_coordinator_sha256,resource_cutover_sha256,profile,affinity_cpu";
const BUILD_ITERATIONS: usize = 8;
const TAG19_PROFILE: &str = "linux-aarch64-arm-41-d84-vl16-release-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QualificationSubject {
    Tag19,
    Tag21,
}

impl QualificationSubject {
    const fn schema(self) -> &'static str {
        match self {
            Self::Tag19 => TAG19_SCHEMA,
            Self::Tag21 => SCHEMA,
        }
    }

    const fn row_prefix(self) -> &'static str {
        match self {
            Self::Tag19 => "FRE_JIT_TAG19_FACADE_ROW",
            Self::Tag21 => "FRE_JIT_TAG21_FACADE_ROW",
        }
    }

    const fn csv_header(self) -> &'static str {
        match self {
            Self::Tag19 => TAG19_CSV_HEADER,
            Self::Tag21 => CSV_HEADER,
        }
    }

    const fn backend_policy(self) -> QualifiedExactSearchBackendPolicy {
        match self {
            Self::Tag19 => QualifiedExactSearchBackendPolicy::Sve16V6,
            Self::Tag21 => QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
        }
    }

    const fn backend_version(self) -> BackendVersion {
        match self {
            Self::Tag19 => BackendVersion::SEARCH_SVE16_V6,
            Self::Tag21 => BackendVersion::SEARCH_SVE2_FIXED16_V2,
        }
    }

    const fn target_feature_bits(self) -> u64 {
        match self {
            Self::Tag19 => 3,
            Self::Tag21 => 7,
        }
    }

    const fn backend_label(self) -> &'static str {
        match self {
            Self::Tag19 => "aarch64-search-v19",
            Self::Tag21 => "aarch64-search-v21",
        }
    }

    const fn qualification(self) -> QualifiedExactSearchQualification {
        match self {
            Self::Tag19 => QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION,
            Self::Tag21 => QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION,
        }
    }

    fn expected_qualification(self) -> &'static str {
        match self {
            Self::Tag19 => option_env!("FRE_JIT_TAG19_FACADE_EXPECTED_QUALIFICATION")
                .expect("tag19 facade binary must bind its expected qualification"),
            Self::Tag21 => option_env!("FRE_JIT_TAG21_FACADE_EXPECTED_QUALIFICATION")
                .expect("tag21 facade binary must bind its expected qualification"),
        }
    }

    fn revision(self) -> &'static str {
        match self {
            Self::Tag19 => option_env!("FRE_JIT_TAG19_FACADE_SUBJECT_REVISION")
                .expect("tag19 facade qualification binary must bind its source revision"),
            Self::Tag21 => option_env!("FRE_JIT_TAG21_FACADE_SUBJECT_REVISION")
                .expect("tag21 facade qualification binary must bind its source revision"),
        }
    }

    fn tag19_provenance_suffix(self, affinity_cpu: u32) -> String {
        assert_eq!(self, Self::Tag19);
        let tree = required_hex(
            option_env!("FRE_JIT_TAG19_FACADE_SUBJECT_TREE"),
            40,
            "tag19 facade source tree",
        );
        let resource = required_hex(
            option_env!("FRE_JIT_TAG19_FACADE_RESOURCE_COORDINATOR_SHA256"),
            64,
            "tag19 facade resource coordinator",
        );
        let cutover = required_hex(
            option_env!("FRE_JIT_TAG19_FACADE_RESOURCE_CUTOVER_SHA256"),
            64,
            "tag19 facade resource cutover",
        );
        let profile = option_env!("FRE_JIT_TAG19_FACADE_PROFILE")
            .expect("tag19 facade profile must be source-bound");
        assert_eq!(profile, TAG19_PROFILE);
        let run_id = runtime_token("FRE_JIT_TAG19_FACADE_RUN_ID");
        let instance_id = runtime_token("FRE_JIT_TAG19_FACADE_INSTANCE_ID");
        let instance_type = runtime_token("FRE_JIT_TAG19_FACADE_INSTANCE_TYPE");
        format!(
            ",{tree},{run_id},{instance_id},{instance_type},{resource},{cutover},{profile},{affinity_cpu}"
        )
    }
}

fn required_hex(value: Option<&'static str>, digits: usize, label: &str) -> &'static str {
    let value = value.unwrap_or_else(|| panic!("{label} must be source-bound"));
    assert!(
        value.len() == digits
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && value.bytes().any(|byte| byte != b'0'),
        "{label} must be one nonzero lowercase hexadecimal identity"
    );
    value
}

fn runtime_token(name: &str) -> String {
    let value = env::var(name).unwrap_or_else(|_| panic!("{name}"));
    assert!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:@+-".contains(&byte)),
        "{name} must be one bounded safe token"
    );
    value
}

fn sole_thread_affinity_cpu() -> u32 {
    let affinity = fs::read_to_string("/proc/thread-self/status")
        .expect("read Linux timing-thread status")
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .expect("Cpus_allowed_list");
    assert!(
        !affinity.contains(',') && !affinity.contains('-'),
        "tag19 facade process must be pinned to one CPU"
    );
    affinity.parse().expect("numeric sole affinity CPU")
}

const UNIQUE_LITERAL: [u8; 16] = *b"0123456789abcdef";
const REPEATED_LITERAL: [u8; 16] = *b"aaaaaaaaaaaaaaaa";
const ALTERNATING_LITERAL: [u8; 16] = *b"abababababababab";
const NATURAL_LITERAL: [u8; 16] = *b"search-target-v1";
const BINARY_LITERAL: [u8; 16] = [
    0x00, 0xff, 0x01, 0xfe, 0x02, 0xfd, 0x03, 0xfc, 0x04, 0xfb, 0x05, 0xfa, 0x06, 0xf9, 0x07, 0xf8,
];
const RANK_ADVERSARIAL_LITERAL: [u8; 16] = *b"aaaabaaaacaaaada";

#[derive(Clone, Copy, Debug)]
struct LiteralCase {
    name: &'static str,
    pattern: &'static str,
    literal: &'static [u8; 16],
}

impl LiteralCase {
    const ALL: [Self; 6] = [
        Self {
            name: "unique",
            pattern: "0123456789abcdef",
            literal: &UNIQUE_LITERAL,
        },
        Self {
            name: "repeated",
            pattern: "aaaaaaaaaaaaaaaa",
            literal: &REPEATED_LITERAL,
        },
        Self {
            name: "alternating",
            pattern: "abababababababab",
            literal: &ALTERNATING_LITERAL,
        },
        Self {
            name: "natural",
            pattern: "search-target-v1",
            literal: &NATURAL_LITERAL,
        },
        Self {
            name: "binary",
            pattern: r"\x00\xff\x01\xfe\x02\xfd\x03\xfc\x04\xfb\x05\xfa\x06\xf9\x07\xf8",
            literal: &BINARY_LITERAL,
        },
        Self {
            name: "rank-adversarial",
            pattern: "aaaabaaaacaaaada",
            literal: &RANK_ADVERSARIAL_LITERAL,
        },
    ];

    fn parse(value: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|case| case.name == value)
            .unwrap_or_else(|| panic!("invalid literal class: {value}"))
    }

    fn absent_byte(self) -> u8 {
        (0_u8..=u8::MAX)
            .find(|byte| !self.literal.contains(byte))
            .expect("a 16-byte literal cannot contain every byte")
    }
}

#[derive(Clone, Copy, Debug)]
enum Size {
    K64,
    M1,
}

impl Size {
    fn parse(value: &str) -> Self {
        match value {
            "64k" => Self::K64,
            "1m" => Self::M1,
            _ => panic!("invalid facade qualification size: {value}"),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::K64 => "64k",
            Self::M1 => "1m",
        }
    }

    const fn bytes(self) -> usize {
        match self {
            Self::K64 => QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
            Self::M1 => QUALIFIED_EXACT_SEARCH_LARGE_WINDOW_BYTES,
        }
    }

    const fn calls(self) -> usize {
        match self {
            Self::K64 => QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
            Self::M1 => QUALIFIED_EXACT_SEARCH_LARGE_MIN_SEARCHES,
        }
    }

    const fn workload(self) -> QualifiedExactSearchWorkload {
        QualifiedExactSearchWorkload::new(self.bytes(), self.calls())
    }
}

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Absent,
    Late,
    Homogeneous,
    NearMiss,
}

impl Scenario {
    fn parse(value: &str) -> Self {
        match value {
            "absent" => Self::Absent,
            "late" => Self::Late,
            "homogeneous" => Self::Homogeneous,
            "near-miss" => Self::NearMiss,
            _ => panic!("invalid facade qualification scenario: {value}"),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Late => "late",
            Self::Homogeneous => "homogeneous",
            Self::NearMiss => "near-miss",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Timed {
    iterations: usize,
    total_ns: u128,
    checksum: u64,
}

struct CandidateExecutionGuard;

impl CandidateExecutionGuard {
    fn acquire_for(qualification: QualifiedExactSearchQualification) -> Option<Self> {
        if qualification.is_authorized() {
            TEST_CANDIDATE_EXECUTION.with(|enabled| {
                assert!(
                    !enabled.get(),
                    "Qualified facade must run without the Candidate execution guard"
                );
            });
            return None;
        }
        assert_eq!(qualification, QualifiedExactSearchQualification::Candidate);
        TEST_CANDIDATE_EXECUTION.with(|enabled| {
            assert!(!enabled.replace(true), "nested Candidate execution guard");
        });
        Some(Self)
    }
}

impl Drop for CandidateExecutionGuard {
    fn drop(&mut self) {
        TEST_CANDIDATE_EXECUTION.with(|enabled| {
            assert!(enabled.replace(false), "Candidate execution guard was lost");
        });
    }
}

fn builder(case: LiteralCase) -> PortableBuilder {
    PortableBuilder::new(case.pattern).unicode(false)
}

fn build_portable(case: LiteralCase) -> PortableRegex {
    builder(case).build().expect("portable facade build")
}

fn subject_qualification(subject: QualificationSubject) -> QualifiedExactSearchQualification {
    let qualification = subject.qualification();
    let actual = qualification_label(qualification);
    let expected = subject.expected_qualification();
    assert_eq!(
        actual, expected,
        "compiled facade qualification differs from build authority"
    );
    qualification
}

fn qualification_label(qualification: QualifiedExactSearchQualification) -> String {
    match qualification {
        QualifiedExactSearchQualification::Candidate => "candidate".to_owned(),
        QualifiedExactSearchQualification::Qualified { bundle_sha256 } => {
            assert_eq!(
                qualification.authorized_bundle_sha256(),
                Some(bundle_sha256),
                "qualified facade bundle must be authorized"
            );
            format!("qualified:{}", hex(&bundle_sha256))
        }
    }
}

fn build_facade(
    subject: QualificationSubject,
    case: LiteralCase,
    size: Size,
) -> QualifiedExactSearchFacade {
    let qualification = subject_qualification(subject);
    if qualification.is_authorized() {
        builder(case)
            .build_qualified_exact_search(size.workload())
            .expect("production-qualified automatic facade build")
    } else {
        builder(case)
            .build_qualified_exact_search_with_backend(size.workload(), subject.backend_policy())
            .expect("Candidate facade build")
    }
}

fn build_fresh_cache_facade(
    subject: QualificationSubject,
    case: LiteralCase,
    size: Size,
) -> (SelectedEndRegisterCacheV2, QualifiedExactSearchFacade) {
    let qualification = subject_qualification(subject);
    let cache =
        SelectedEndRegisterCacheV2::new(CacheLimits::default(), PublicationLimits::default())
            .expect("fresh bounded ABI2 qualification cache");
    let facade = QualifiedExactSearchFacade::from_builder_with_fresh_cache_for_qualification(
        builder(case),
        size.workload(),
        subject.backend_policy(),
        ValidateLimits::default(),
        EmitLimits::default(),
        PublicationLimits::default(),
        qualification,
        &cache,
    )
    .expect("fresh-cache facade build");
    (cache, facade)
}

fn facade_artifact(subject: QualificationSubject, facade: &QualifiedExactSearchFacade) -> [u8; 32] {
    let report = facade
        .qualified_build_report()
        .expect("exact facade report");
    assert_eq!(report.backend_policy, subject.backend_policy());
    let expected_qualification = subject_qualification(subject);
    assert_eq!(report.qualification, expected_qualification);
    let QualifiedExactSearchNativeStatus::Published {
        identity,
        abi,
        sve_vector_bytes_at_publication,
        required_thread_sve_vector_bytes,
        ..
    } = &report.native
    else {
        panic!("Candidate facade did not publish: {:?}", report.native);
    };
    assert_eq!(identity.backend, subject.backend_version());
    assert_eq!(
        identity.abi,
        QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
    );
    assert_eq!(*abi, QualifiedExactSearchNativeAbi::SelectedEndRegisterV2);
    assert_eq!(
        identity.target.features.bits(),
        subject.target_feature_bits()
    );
    assert_eq!(identity.qualification, expected_qualification);
    assert_eq!(identity.sve_vector_bytes_at_publication, None);
    assert_eq!(identity.required_thread_sve_vector_bytes, Some(16));
    assert_eq!(*sve_vector_bytes_at_publication, None);
    assert_eq!(*required_thread_sve_vector_bytes, Some(16));
    identity.artifact_sha256
}

fn make_haystack(case: LiteralCase, size: Size, scenario: Scenario) -> Vec<u8> {
    let absent = case.absent_byte();
    let mut haystack = vec![absent; size.bytes()];
    match scenario {
        Scenario::Absent => {}
        Scenario::Late => {
            let start = haystack
                .len()
                .checked_sub(case.literal.len())
                .and_then(|value| value.checked_sub(31))
                .expect("qualification haystack fits late literal");
            let end = start
                .checked_add(case.literal.len())
                .expect("qualification late literal end fits");
            haystack
                .get_mut(start..end)
                .expect("qualification late literal range fits")
                .copy_from_slice(case.literal);
        }
        Scenario::Homogeneous => haystack.fill(case.literal[0]),
        Scenario::NearMiss => {
            let terminal = case
                .literal
                .len()
                .checked_sub(1)
                .expect("qualification literals are nonempty");
            let last_start = haystack
                .len()
                .checked_sub(case.literal.len())
                .expect("qualification haystack fits the literal");
            let literal_prefix = case
                .literal
                .get(..terminal)
                .expect("terminal is inside the qualification literal");
            for start in (0..=last_start).step_by(64) {
                let terminal_index = start
                    .checked_add(terminal)
                    .expect("qualification near-miss terminal fits");
                haystack
                    .get_mut(start..terminal_index)
                    .expect("qualification near-miss prefix range fits")
                    .copy_from_slice(literal_prefix);
                *haystack
                    .get_mut(terminal_index)
                    .expect("qualification near-miss terminal is in bounds") = absent;
            }
        }
    }
    haystack
}

fn encode_offsets(span: Option<(usize, usize)>) -> u64 {
    span.map_or(0, |(start, end)| {
        u64::try_from(start).unwrap_or(u64::MAX).rotate_left(17)
            ^ u64::try_from(end).unwrap_or(u64::MAX).rotate_left(41)
            ^ 0x9e37_79b9_7f4a_7c15
    })
}

fn encode_span(span: Option<Match>) -> u64 {
    encode_offsets(span.map(|span| (span.start(), span.end())))
}

fn portable_value(portable: &PortableRegex, haystack: &[u8]) -> u64 {
    let (matched, _) = portable
        .find(black_box(haystack), SearchLimits::unlimited())
        .expect("portable facade search");
    encode_span(matched)
}

fn facade_value_only(
    session: &QualifiedExactSearchFacadeThreadSession<'_>,
    haystack: &[u8],
) -> u64 {
    let matched = session
        .find_value(black_box(haystack), SearchLimits::unlimited())
        .expect("ABI2 value-only facade search");
    encode_span(matched)
}

fn assert_facade_reporting_contract(
    session: &QualifiedExactSearchFacadeThreadSession<'_>,
    haystack: &[u8],
    expected: u64,
) {
    let (matched, execution) = session
        .find(haystack, SearchLimits::unlimited())
        .expect("untimed ABI2 reporting facade search");
    assert_eq!(
        execution.route,
        QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::NativeJit)
    );
    assert_eq!(
        execution.accounting,
        SearchAccounting::ExactLiteral(LiteralAccounting {
            needle_bytes: QUALIFIED_EXACT_SEARCH_LITERAL_BYTES,
            searched_bytes: haystack.len(),
            linear_terms: haystack
                .len()
                .checked_add(QUALIFIED_EXACT_SEARCH_LITERAL_BYTES)
                .expect("bounded ABI2 reporting accounting"),
            scratch_bytes: 0,
        })
    );
    assert_eq!(encode_span(matched), expected);
    assert_eq!(facade_value_only(session, haystack), expected);
}

fn measure(iterations: usize, mut operation: impl FnMut() -> u64) -> Timed {
    assert!(iterations > 0);
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    let started = Instant::now();
    for iteration in 0..iterations {
        let value = black_box(operation());
        checksum = checksum.rotate_left(9)
            ^ value.wrapping_add(
                u64::try_from(iteration)
                    .unwrap_or(u64::MAX)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15),
            );
    }
    let total_ns = started.elapsed().as_nanos();
    black_box(checksum);
    Timed {
        iterations,
        total_ns,
        checksum,
    }
}

fn measure_portable_full(case: LiteralCase, haystack: &[u8], calls: usize) -> Timed {
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    let started = Instant::now();
    let portable = build_portable(case);
    for iteration in 0..calls {
        let value = black_box(portable_value(&portable, haystack));
        checksum = checksum.rotate_left(9)
            ^ value.wrapping_add(
                u64::try_from(iteration)
                    .unwrap_or(u64::MAX)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15),
            );
    }
    let total_ns = started.elapsed().as_nanos();
    black_box(checksum);
    Timed {
        iterations: calls,
        total_ns,
        checksum,
    }
}

fn measure_facade_full(
    subject: QualificationSubject,
    case: LiteralCase,
    size: Size,
    haystack: &[u8],
    calls: usize,
) -> Timed {
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    let started = Instant::now();
    let (cache, facade) = build_fresh_cache_facade(subject, case, size);
    let _ = black_box(facade_artifact(subject, &facade));
    let session = facade
        .begin_current_thread_session()
        .expect("ABI2 facade current-thread session");
    for iteration in 0..calls {
        let value = black_box(facade_value_only(&session, haystack));
        checksum = checksum.rotate_left(9)
            ^ value.wrapping_add(
                u64::try_from(iteration)
                    .unwrap_or(u64::MAX)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15),
            );
    }
    let total_ns = started.elapsed().as_nanos();
    black_box(checksum);
    // Preserve the pre-cache full-workload boundary: construction and session
    // creation are timed, while facade/cache retirement remains outside it.
    drop(session);
    drop(facade);
    drop(cache);
    Timed {
        iterations: calls,
        total_ns,
        checksum,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one closed facade cell keeps construction, route checks, cold cost, and declared-workload timing together"
)]
fn run_cell(
    subject: QualificationSubject,
    case: LiteralCase,
    size: Size,
    scenario: Scenario,
    repetition: u32,
) {
    let affinity_cpu = match subject {
        QualificationSubject::Tag19 => Some(sole_thread_affinity_cpu()),
        QualificationSubject::Tag21 => None,
    };
    let provenance_suffix =
        affinity_cpu.map_or_else(String::new, |cpu| subject.tag19_provenance_suffix(cpu));
    let qualification = subject_qualification(subject);
    let _guard = CandidateExecutionGuard::acquire_for(qualification);
    let qualification_state = qualification_label(qualification);
    let haystack = make_haystack(case, size, scenario);
    let portable = build_portable(case);
    // The hot-search subject intentionally exercises the process-wide cache.
    // Build/cold/full measurements below use a fresh default-policy cache per
    // operation so compilation remains represented rather than prewarmed.
    let facade = build_facade(subject, case, size);
    let artifact_sha256 = facade_artifact(subject, &facade);
    // Session creation is deliberately outside the hot-search timer. The
    // cold/full helpers create it after their timers start so lifecycle cost
    // remains represented in those stages.
    let facade_session = facade
        .begin_current_thread_session()
        .expect("ABI2 facade current-thread session");
    let expected = portable_value(&portable, &haystack);
    let kir = build_exact_literal::<NativeSpan>(
        case.literal,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("exact-literal Kernel IR build");
    let kir_expected = kir
        .execute(
            &haystack,
            NativeSearchWindow::new(0, haystack.len()),
            fre_kernel_ir::ExecutionLimits::unlimited(),
        )
        .expect("exact-literal Kernel IR execution")
        .into_output();
    assert_eq!(
        expected,
        encode_offsets(kir_expected.map(|span| (span.start(), span.end()))),
        "portable facade differs from the independent Kernel IR oracle"
    );
    // The reporting boundary is exercised once outside every timer. Timed
    // search/full-workload calls consume only the semantic value projection.
    assert_facade_reporting_contract(&facade_session, &haystack, expected);

    let portable_build = || {
        measure(BUILD_ITERATIONS, || {
            u64::try_from(build_portable(case).build_report().charged_persistent_bytes)
                .expect("portable persistent bytes fit u64")
        })
    };
    let facade_build = || {
        measure(BUILD_ITERATIONS, || {
            let (cache, cold) = build_fresh_cache_facade(subject, case, size);
            let artifact_prefix = u64::from_le_bytes(
                facade_artifact(subject, &cold)[..8]
                    .try_into()
                    .expect("artifact prefix"),
            );
            // `measure` times the whole closure, including facade/cache
            // retirement, matching the original construction-stage boundary.
            drop(cold);
            drop(cache);
            artifact_prefix
        })
    };
    let portable_search = || {
        measure(size.calls(), || {
            portable_value(black_box(&portable), black_box(&haystack))
        })
    };
    let facade_search = || {
        measure(size.calls(), || {
            facade_value_only(black_box(&facade_session), black_box(&haystack))
        })
    };
    let portable_cold = || measure_portable_full(case, &haystack, 1);
    let facade_cold = || measure_facade_full(subject, case, size, &haystack, 1);
    let portable_full = || measure_portable_full(case, &haystack, size.calls());
    let facade_full = || measure_facade_full(subject, case, size, &haystack, size.calls());

    let (pb, jb, ps, js, pc, jc, pf, jf, order) = if repetition.is_multiple_of(2) {
        (
            portable_build(),
            facade_build(),
            portable_search(),
            facade_search(),
            portable_cold(),
            facade_cold(),
            portable_full(),
            facade_full(),
            "portable-first",
        )
    } else {
        let jb = facade_build();
        let pb = portable_build();
        let js = facade_search();
        let ps = portable_search();
        let jc = facade_cold();
        let pc = portable_cold();
        let jf = facade_full();
        let pf = portable_full();
        (pb, jb, ps, js, pc, jc, pf, jf, "facade-first")
    };

    assert_eq!(ps.checksum, js.checksum, "search checksums differ");
    assert_eq!(pc.checksum, jc.checksum, "cold checksums differ");
    assert_eq!(pf.checksum, jf.checksum, "full-workload checksums differ");
    if let Some(cpu) = affinity_cpu {
        assert_eq!(
            sole_thread_affinity_cpu(),
            cpu,
            "tag19 facade timing-thread affinity changed during measurement"
        );
    }

    for (engine, stage, timed, route, backend, artifact, measured_calls) in [
        (
            "portable",
            "build",
            pb,
            "portable-literal",
            "portable",
            None,
            0,
        ),
        (
            "facade",
            "build",
            jb,
            "native-jit",
            subject.backend_label(),
            Some(artifact_sha256),
            0,
        ),
        (
            "portable",
            "search",
            ps,
            "portable-literal",
            "portable",
            None,
            size.calls(),
        ),
        (
            "facade",
            "search",
            js,
            "native-jit",
            subject.backend_label(),
            Some(artifact_sha256),
            size.calls(),
        ),
        (
            "portable",
            "cold",
            pc,
            "portable-literal",
            "portable",
            None,
            1,
        ),
        (
            "facade",
            "cold",
            jc,
            "native-jit",
            subject.backend_label(),
            Some(artifact_sha256),
            1,
        ),
        (
            "portable",
            "full",
            pf,
            "portable-literal",
            "portable",
            None,
            size.calls(),
        ),
        (
            "facade",
            "full",
            jf,
            "native-jit",
            subject.backend_label(),
            Some(artifact_sha256),
            size.calls(),
        ),
    ] {
        emit(
            subject,
            case,
            size,
            scenario,
            repetition,
            order,
            engine,
            stage,
            timed,
            expected,
            &haystack,
            route,
            backend,
            artifact,
            measured_calls,
            &qualification_state,
            &provenance_suffix,
        );
    }
}

#[allow(clippy::too_many_arguments, reason = "closed qualification row schema")]
fn emit(
    subject: QualificationSubject,
    case: LiteralCase,
    size: Size,
    scenario: Scenario,
    repetition: u32,
    order: &str,
    engine: &str,
    stage: &str,
    timed: Timed,
    semantic_value: u64,
    haystack: &[u8],
    route: &str,
    backend: &str,
    artifact_sha256: Option<[u8; 32]>,
    measured_calls: usize,
    qualification_state: &str,
    provenance_suffix: &str,
) {
    let revision = subject.revision();
    assert!(
        revision.len() == 40
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "qualification revision must be 40 lowercase hexadecimal digits"
    );
    println!(
        "{}\t{}",
        subject.row_prefix(),
        row_with_revision(
            subject,
            revision,
            case,
            size,
            scenario,
            repetition,
            order,
            engine,
            stage,
            timed,
            semantic_value,
            haystack,
            route,
            backend,
            artifact_sha256,
            measured_calls,
            qualification_state,
            provenance_suffix,
        )
    );
}

#[allow(clippy::too_many_arguments, reason = "closed qualification row schema")]
fn row_with_revision(
    subject: QualificationSubject,
    revision: &str,
    case: LiteralCase,
    size: Size,
    scenario: Scenario,
    repetition: u32,
    order: &str,
    engine: &str,
    stage: &str,
    timed: Timed,
    semantic_value: u64,
    haystack: &[u8],
    route: &str,
    backend: &str,
    artifact_sha256: Option<[u8; 32]>,
    measured_calls: usize,
    qualification_state: &str,
    provenance_suffix: &str,
) -> String {
    let artifact = artifact_sha256.map_or_else(|| "none".to_owned(), |bytes| hex(&bytes));
    let ns_per_iter = timed
        .total_ns
        .checked_div(u128::try_from(timed.iterations).expect("iterations fit u128"))
        .expect("timed iteration count is nonzero");
    let row = format!(
        "{},{revision},{},{repetition},{},{},{},{},{order},{engine},{stage},{},{},{ns_per_iter},0x{:016x},0x{semantic_value:016x},{},{route},{backend},{qualification_state},{artifact},{},{},{}",
        subject.schema(),
        std::process::id(),
        case.name,
        hex(case.literal),
        size.name(),
        scenario.name(),
        timed.iterations,
        timed.total_ns,
        timed.checksum,
        haystack.len(),
        size.bytes(),
        size.calls(),
        measured_calls,
    );
    format!("{row}{provenance_suffix}")
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().checked_mul(2).expect("bounded hex"));
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("String formatting cannot fail");
    }
    output
}

fn drive(
    subject: QualificationSubject,
    driver: &str,
    literal: &str,
    size: &str,
    scenario: &str,
    repetition: &str,
) {
    match env::var(driver)
        .unwrap_or_else(|_| panic!("{driver}"))
        .as_str()
    {
        "header" => println!("{}\t{}", subject.row_prefix(), subject.csv_header()),
        "run" => run_cell(
            subject,
            LiteralCase::parse(&env::var(literal).expect("literal class")),
            Size::parse(&env::var(size).expect("size")),
            Scenario::parse(&env::var(scenario).expect("scenario")),
            env::var(repetition)
                .unwrap_or_else(|_| panic!("{repetition}"))
                .parse()
                .expect("numeric repetition"),
        ),
        command => panic!("invalid facade qualification command: {command}"),
    }
}

#[test]
#[ignore = "external source-bound tag21 facade qualification driver"]
fn driver() {
    drive(
        QualificationSubject::Tag21,
        "FRE_JIT_TAG21_FACADE_DRIVER",
        "FRE_JIT_TAG21_FACADE_LITERAL",
        "FRE_JIT_TAG21_FACADE_SIZE",
        "FRE_JIT_TAG21_FACADE_SCENARIO",
        "FRE_JIT_TAG21_FACADE_REPETITION",
    );
}

#[test]
#[ignore = "external source-bound tag19 ABI2 facade qualification driver"]
fn tag19_driver() {
    drive(
        QualificationSubject::Tag19,
        "FRE_JIT_TAG19_FACADE_DRIVER",
        "FRE_JIT_TAG19_FACADE_LITERAL",
        "FRE_JIT_TAG19_FACADE_SIZE",
        "FRE_JIT_TAG19_FACADE_SCENARIO",
        "FRE_JIT_TAG19_FACADE_REPETITION",
    );
}

#[test]
fn qualification_schema_literal_corpus_and_row_cardinality_are_closed() {
    assert_eq!(SCHEMA, "fre-jit-tag21-facade-performance-v4");
    assert_eq!(TAG19_SCHEMA, "fre-jit-tag19-facade-performance-v5");
    let columns: Vec<_> = CSV_HEADER.split(',').collect();
    assert_eq!(columns.len(), 24);
    let mut deduplicated = columns.clone();
    deduplicated.sort_unstable();
    deduplicated.dedup();
    assert_eq!(deduplicated.len(), columns.len());
    for case in LiteralCase::ALL {
        assert_eq!(case.literal.len(), QUALIFIED_EXACT_SEARCH_LITERAL_BYTES);
    }
    let row = row_with_revision(
        QualificationSubject::Tag21,
        "0000000000000000000000000000000000000001",
        LiteralCase::ALL[0],
        Size::K64,
        Scenario::Absent,
        0,
        "portable-first",
        "facade",
        "full",
        Timed {
            iterations: 1,
            total_ns: 1,
            checksum: 1,
        },
        0,
        &[0],
        "native-jit",
        "aarch64-search-v21",
        Some([1; 32]),
        1,
        "candidate",
        "",
    );
    assert_eq!(row.split(',').count(), columns.len());
    let tag19_row = row_with_revision(
        QualificationSubject::Tag19,
        "0000000000000000000000000000000000000001",
        LiteralCase::ALL[0],
        Size::K64,
        Scenario::Absent,
        0,
        "portable-first",
        "facade",
        "full",
        Timed {
            iterations: 1,
            total_ns: 1,
            checksum: 1,
        },
        0,
        &[0],
        "native-jit",
        "aarch64-search-v19",
        Some([1; 32]),
        1,
        "candidate",
        ",0000000000000000000000000000000000000002,run,instance,type,0000000000000000000000000000000000000000000000000000000000000003,0000000000000000000000000000000000000000000000000000000000000004,linux-aarch64-arm-41-d84-vl16-release-v1,0",
    );
    assert_eq!(
        tag19_row.split(',').count(),
        TAG19_CSV_HEADER.split(',').count()
    );
    assert!(tag19_row.starts_with("fre-jit-tag19-facade-performance-v5,"));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one source seal keeps the value helper, untimed reporting gate, full loop, and hot closure boundaries auditable together"
)]
fn current_thread_session_timing_boundaries_are_source_sealed() {
    fn position(source: &str, marker: &str) -> usize {
        source
            .find(marker)
            .unwrap_or_else(|| panic!("missing session lifecycle marker: {marker}"))
    }

    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/qualified_exact_search_tag21_facade_qualification.rs"
    ));

    let value_start = position(source, "fn facade_value_only(");
    let value_end = value_start
        + position(
            &source[value_start..],
            "\nfn assert_facade_reporting_contract(",
        );
    let value = &source[value_start..value_end];
    assert!(value.contains(".find_value("));
    assert!(!value.contains("execution"));
    assert!(!value.contains("begin_current_thread_session"));
    for reporting_call in [
        ".find(",
        ".find_at(",
        ".find_window(",
        ".find_borrowed(",
        ".is_match(",
    ] {
        assert!(
            !value.contains(reporting_call),
            "value-only timed helper contains reporting call {reporting_call}"
        );
    }

    let reporting_start = position(source, "fn assert_facade_reporting_contract(");
    let reporting_end = reporting_start + position(&source[reporting_start..], "\nfn measure(");
    let reporting = &source[reporting_start..reporting_end];
    assert!(reporting.contains(".find(haystack, SearchLimits::unlimited())"));
    assert!(reporting.contains("execution.route"));
    assert!(reporting.contains("execution.accounting"));
    assert!(reporting.contains("facade_value_only(session, haystack)"));
    assert!(!reporting.contains("Instant::now"));

    let fresh_start = position(source, "fn build_fresh_cache_facade(");
    let fresh_end = fresh_start + position(&source[fresh_start..], "\nfn facade_artifact(");
    let fresh = &source[fresh_start..fresh_end];
    assert!(fresh.contains(
        "SelectedEndRegisterCacheV2::new(CacheLimits::default(), PublicationLimits::default())"
    ));
    assert!(
        fresh.contains(
            "QualifiedExactSearchFacade::from_builder_with_fresh_cache_for_qualification("
        )
    );
    assert!(fresh.contains("&cache,"));
    assert!(fresh.contains("(cache, facade)"));

    let full_start = position(source, "fn measure_facade_full(");
    let full_end = full_start
        + position(
            &source[full_start..],
            "\n#[allow(\n    clippy::too_many_lines",
        );
    let full = &source[full_start..full_end];
    let full_timer = position(full, "let started = Instant::now();");
    let full_build = position(
        full,
        "let (cache, facade) = build_fresh_cache_facade(subject, case, size);",
    );
    let full_session = position(full, ".begin_current_thread_session()");
    let full_loop = position(full, "for iteration in 0..calls");
    let full_elapsed = position(full, "let total_ns = started.elapsed().as_nanos();");
    let full_session_drop = position(full, "drop(session);");
    let full_facade_drop = position(full, "drop(facade);");
    let full_cache_drop = position(full, "drop(cache);");
    assert!(full_timer < full_build);
    assert!(full_build < full_session);
    assert!(full_session < full_loop);
    assert!(full_loop < full_elapsed);
    assert!(full_elapsed < full_session_drop);
    assert!(full_session_drop < full_facade_drop);
    assert!(full_facade_drop < full_cache_drop);
    let full_loop_body = &full[full_loop..];
    assert!(full_loop_body.contains("facade_value_only(&session, haystack)"));
    assert!(!full_loop_body.contains("begin_current_thread_session"));
    assert!(!full.contains("assert_facade_reporting_contract"));
    for reporting_call in [
        ".find(",
        ".find_at(",
        ".find_window(",
        ".find_borrowed(",
        ".is_match(",
    ] {
        assert!(
            !full_loop_body.contains(reporting_call),
            "full-workload loop contains reporting call {reporting_call}"
        );
    }

    let cell_start = position(source, "fn run_cell(");
    let cell_end = cell_start
        + position(
            &source[cell_start..],
            "\n#[allow(clippy::too_many_arguments",
        );
    let cell = &source[cell_start..cell_end];
    let session = position(cell, "let facade_session = facade");
    let reporting = position(cell, "assert_facade_reporting_contract(");
    let first_timed_closure = position(cell, "let portable_build = ||");
    let hot_start = position(cell, "let facade_search = ||");
    let hot_end = position(cell, "let portable_cold = ||");
    assert!(session < hot_start);
    assert!(session < reporting);
    assert!(reporting < first_timed_closure);
    assert_eq!(cell.matches("assert_facade_reporting_contract(").count(), 1);
    let build_start = position(cell, "let facade_build = ||");
    let build_end = position(cell, "let portable_search = ||");
    let build = &cell[build_start..build_end];
    assert!(build.contains("let (cache, cold) = build_fresh_cache_facade(subject, case, size);"));
    assert!(build.contains("drop(cold);"));
    assert!(build.contains("drop(cache);"));
    assert!(!build.contains("let cold = build_facade(subject, case, size);"));
    let hot = &cell[hot_start..hot_end];
    assert!(hot.contains("facade_value_only(black_box(&facade_session), black_box(&haystack))"));
    assert!(!hot.contains("begin_current_thread_session"));
    assert!(!hot.contains("assert_facade_reporting_contract"));
    for reporting_call in [
        ".find(",
        ".find_at(",
        ".find_window(",
        ".find_borrowed(",
        ".is_match(",
    ] {
        assert!(
            !hot.contains(reporting_call),
            "hot timed region contains reporting call {reporting_call}"
        );
    }
}
