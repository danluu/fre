use std::{cell::Cell, env as process_env, hint::black_box, time::Instant};

use fre_kernel_ir::{
    AnchorFlags, ExecutionLimits, SearchWindow as KirSearchWindow, Span as KirSpan, ValidateLimits,
    build_exact_literal,
};

use super::*;

// V3 measures the public-facade value-only register-return ABI2 boundary.
// Existing V1 reporting-path and V2 value-only ABI1 rows remain historical
// evidence and must never be relabeled.
const SCHEMA: &str = "fre-jit-bridge-qualification-v3";
const PATTERN: &str = "0123456789abcdef";
const LITERAL: &[u8] = PATTERN.as_bytes();
const V8_WIDE_CANDIDATE_STARTS: usize = 64;
const V8_PRIMARY_OFFSET: usize = 7;
const V8_SECONDARY_OFFSET: usize = 6;
const CSV_HEADER: &str = "schema,revision,pid,repetition,cell,operation,size,scenario,order,engine,stage,iterations,total_ns,ns_per_iter,checksum,semantic_value,haystack_bytes,alignment_mod16,route,backend,qualification_state,artifact_sha256,declared_min_window_bytes,declared_min_calls,measured_calls";

struct CandidateExecutionGuard;

impl CandidateExecutionGuard {
    fn acquire() -> Self {
        super::super::TEST_CANDIDATE_EXECUTION.with(|enabled| {
            assert!(!enabled.replace(true), "nested Candidate execution guard");
        });
        Self
    }
}

impl Drop for CandidateExecutionGuard {
    fn drop(&mut self) {
        super::super::TEST_CANDIDATE_EXECUTION.with(|enabled| {
            assert!(enabled.replace(false), "Candidate execution guard was lost");
        });
    }
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    Exists,
    End,
    Span,
}

impl Operation {
    fn parse(value: &str) -> Self {
        match value {
            "exists" => Self::Exists,
            "end" => Self::End,
            "span" => Self::Span,
            _ => panic!("invalid operation: {value}"),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Exists => "exists",
            Self::End => "end",
            Self::Span => "span",
        }
    }

    fn encode(self, span: Option<(usize, usize)>) -> u64 {
        match self {
            Self::Exists => u64::from(span.is_some()),
            Self::End => span
                .and_then(|(_, end)| u64::try_from(end).ok())
                .map_or(0, |end| end.wrapping_add(1)),
            Self::Span => span.map_or(0, |(start, end)| {
                u64::try_from(start).unwrap_or(u64::MAX).rotate_left(17)
                    ^ u64::try_from(end).unwrap_or(u64::MAX).rotate_left(41)
                    ^ 0x9e37_79b9_7f4a_7c15
            }),
        }
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
            _ => panic!("invalid size: {value}"),
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
    Present,
    Absent,
    Dense,
    Tail,
    Unaligned,
    PrimaryDenseSecondaryAbsent,
    AdaptiveSecondaryDensePrimaryAbsent,
    PairDenseLiteralAbsent,
    TripleDenseLiteralAbsent,
    FalsePairDistantMatch,
    Binary,
    NaturalText,
}

impl Scenario {
    fn parse(value: &str) -> Self {
        match value {
            "present" => Self::Present,
            "absent" => Self::Absent,
            "dense" => Self::Dense,
            "tail" => Self::Tail,
            "unaligned" => Self::Unaligned,
            "primary-dense-secondary-absent" => Self::PrimaryDenseSecondaryAbsent,
            "adaptive-secondary-dense-primary-absent" => Self::AdaptiveSecondaryDensePrimaryAbsent,
            "pair-dense-literal-absent" => Self::PairDenseLiteralAbsent,
            "triple-dense-literal-absent" => Self::TripleDenseLiteralAbsent,
            "false-pair-distant-match" => Self::FalsePairDistantMatch,
            "binary" => Self::Binary,
            "natural-text" => Self::NaturalText,
            _ => panic!("invalid scenario: {value}"),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Dense => "dense",
            Self::Tail => "tail",
            Self::Unaligned => "unaligned",
            Self::PrimaryDenseSecondaryAbsent => "primary-dense-secondary-absent",
            Self::AdaptiveSecondaryDensePrimaryAbsent => "adaptive-secondary-dense-primary-absent",
            Self::PairDenseLiteralAbsent => "pair-dense-literal-absent",
            Self::TripleDenseLiteralAbsent => "triple-dense-literal-absent",
            Self::FalsePairDistantMatch => "false-pair-distant-match",
            Self::Binary => "binary",
            Self::NaturalText => "natural-text",
        }
    }
}

struct Haystack {
    storage: Vec<u8>,
    start: usize,
    len: usize,
}

fn checked_fixture_add(left: usize, right: usize) -> usize {
    left.checked_add(right)
        .expect("bounded qualification fixture")
}

fn late_fixture_position(maximum_literal_start: usize) -> usize {
    maximum_literal_start
        .checked_mul(3)
        .and_then(|scaled| scaled.checked_div(4))
        .expect("bounded qualification fixture position")
}

fn assert_adaptive_secondary_dense_primary_absent(haystack: &[u8], maximum_literal_start: usize) {
    let primary = LITERAL[V8_PRIMARY_OFFSET];
    let secondary = LITERAL[V8_SECONDARY_OFFSET];
    assert_ne!(primary, secondary);
    let first_group_primary_hits = (0..V8_WIDE_CANDIDATE_STARTS)
        .filter(|&candidate| haystack[checked_fixture_add(candidate, V8_PRIMARY_OFFSET)] == primary)
        .count();
    assert_eq!(
        first_group_primary_hits, 1,
        "first V8 wide group must contain exactly one primary hit"
    );
    assert!(
        (0..V8_WIDE_CANDIDATE_STARTS).all(|candidate| {
            haystack[checked_fixture_add(candidate, V8_PRIMARY_OFFSET)] != primary
                || haystack[checked_fixture_add(candidate, V8_SECONDARY_OFFSET)] != secondary
        }),
        "first V8 wide group must contain no selected pair"
    );
    assert!(
        (V8_WIDE_CANDIDATE_STARTS..=maximum_literal_start).all(|candidate| {
            haystack[checked_fixture_add(candidate, V8_SECONDARY_OFFSET)] == secondary
                && haystack[checked_fixture_add(candidate, V8_PRIMARY_OFFSET)] != primary
        }),
        "later candidate starts must have dense secondary hits and no primary hit"
    );
    assert!(
        !haystack
            .windows(LITERAL.len())
            .any(|window| window == LITERAL),
        "adaptive recheck fixture must not contain the true literal"
    );
}

fn populate_adaptive_secondary_dense_primary_absent(
    haystack: &mut [u8],
    maximum_literal_start: usize,
) {
    // Candidate start zero supplies the only primary hit in V8's first
    // 64-start group. Its selected secondary byte is absent, so the pair
    // screen enters secondary-only mode. Starting with the next group, every
    // selected secondary column hits while every primary column misses,
    // exercising the lazy primary recheck and its switch back to primary-first
    // screening without admitting a true pair or literal.
    haystack[V8_PRIMARY_OFFSET] = LITERAL[V8_PRIMARY_OFFSET];
    let secondary_dense_start = checked_fixture_add(V8_WIDE_CANDIDATE_STARTS, V8_SECONDARY_OFFSET);
    haystack[secondary_dense_start..].fill(LITERAL[V8_SECONDARY_OFFSET]);
    assert_adaptive_secondary_dense_primary_absent(haystack, maximum_literal_start);
}

impl Haystack {
    fn bytes(&self) -> &[u8] {
        let end = checked_fixture_add(self.start, self.len);
        &self.storage[self.start..end]
    }
}

fn make_haystack(size: Size, scenario: Scenario) -> Haystack {
    const NATURAL: &[u8] =
        b"Elementary observations reward patient measurement. False candidates stay cheap. ";
    let len = size.bytes();
    let storage_len = checked_fixture_add(len, 32);
    let mut storage = vec![b'x'; storage_len];
    let base_mod16 = storage.as_ptr().addr() & 15;
    let desired = usize::from(matches!(scenario, Scenario::Unaligned));
    let start = desired.wrapping_add(16).wrapping_sub(base_mod16) & 15;
    let end = checked_fixture_add(start, len);
    let slice = &mut storage[start..end];
    let maximum_literal_start = len
        .checked_sub(LITERAL.len())
        .expect("qualification haystack admits literal");
    match scenario {
        Scenario::Absent => {}
        Scenario::Dense => slice.fill(LITERAL[0]),
        Scenario::Present | Scenario::Unaligned => {
            let position = maximum_literal_start
                .checked_div(2)
                .expect("nonzero qualification divisor");
            let literal_end = checked_fixture_add(position, LITERAL.len());
            slice[position..literal_end].copy_from_slice(LITERAL);
        }
        Scenario::Tail => {
            slice[maximum_literal_start..].copy_from_slice(LITERAL);
        }
        Scenario::PrimaryDenseSecondaryAbsent => slice.fill(LITERAL[V8_PRIMARY_OFFSET]),
        Scenario::AdaptiveSecondaryDensePrimaryAbsent => {
            populate_adaptive_secondary_dense_primary_absent(slice, maximum_literal_start);
        }
        Scenario::PairDenseLiteralAbsent => {
            for candidate in 0..=maximum_literal_start {
                let selected = [
                    (V8_PRIMARY_OFFSET, LITERAL[V8_PRIMARY_OFFSET]),
                    (V8_SECONDARY_OFFSET, LITERAL[V8_SECONDARY_OFFSET]),
                ];
                if selected.iter().any(|&(offset, byte)| {
                    let index = checked_fixture_add(candidate, offset);
                    let current = slice[index];
                    current != b'x' && current != byte
                }) {
                    continue;
                }
                for (offset, byte) in selected {
                    let index = checked_fixture_add(candidate, offset);
                    slice[index] = byte;
                }
            }
        }
        Scenario::TripleDenseLiteralAbsent => {
            for candidate in 0..=maximum_literal_start {
                let selected = [
                    (V8_PRIMARY_OFFSET, LITERAL[V8_PRIMARY_OFFSET]),
                    (V8_SECONDARY_OFFSET, LITERAL[V8_SECONDARY_OFFSET]),
                    (0, LITERAL[0]),
                ];
                if selected.iter().any(|&(offset, byte)| {
                    let index = checked_fixture_add(candidate, offset);
                    let current = slice[index];
                    current != b'x' && current != byte
                }) {
                    continue;
                }
                for (offset, byte) in selected {
                    let index = checked_fixture_add(candidate, offset);
                    slice[index] = byte;
                }
            }
        }
        Scenario::FalsePairDistantMatch => {
            slice[V8_PRIMARY_OFFSET] = LITERAL[V8_PRIMARY_OFFSET];
            slice[V8_SECONDARY_OFFSET] = LITERAL[V8_SECONDARY_OFFSET];
            slice[maximum_literal_start..].copy_from_slice(LITERAL);
        }
        Scenario::Binary => {
            for (index, byte) in slice.iter_mut().enumerate() {
                *byte = u8::try_from(index & 0xff).expect("masked byte");
            }
            let position = late_fixture_position(maximum_literal_start);
            let literal_end = checked_fixture_add(position, LITERAL.len());
            slice[position..literal_end].copy_from_slice(LITERAL);
        }
        Scenario::NaturalText => {
            for (index, byte) in slice.iter_mut().enumerate() {
                let natural_index = index
                    .checked_rem(NATURAL.len())
                    .expect("natural fixture is nonempty");
                *byte = NATURAL[natural_index];
            }
            let position = late_fixture_position(maximum_literal_start);
            let literal_end = checked_fixture_add(position, LITERAL.len());
            slice[position..literal_end].copy_from_slice(LITERAL);
        }
    }
    Haystack {
        storage,
        start,
        len,
    }
}

#[derive(Clone, Copy)]
struct Timed {
    iterations: usize,
    total_ns: u128,
    checksum: u64,
}

fn measure(iterations: usize, mut operation: impl FnMut() -> u64) -> Timed {
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

fn measure_full_workload<S>(
    iterations: usize,
    initialize: impl FnOnce() -> S,
    mut operation: impl FnMut(&S) -> u64,
) -> Timed {
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    let started = Instant::now();
    let state = initialize();
    for iteration in 0..iterations {
        let value = black_box(operation(&state));
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

fn build_portable() -> PortableRegex {
    PortableBuilder::new(PATTERN)
        .build()
        .expect("portable facade build")
}

fn build_bridge(workload: QualifiedExactSearchWorkload) -> QualifiedExactSearchFacade {
    PortableBuilder::new(PATTERN)
        .build_qualified_exact_search_with_backend(
            workload,
            QualifiedExactSearchBackendPolicy::AsimdV8,
        )
        .expect("test-only Candidate bridge build")
}

fn portable_value(portable: &PortableRegex, operation: Operation, haystack: &[u8]) -> u64 {
    let (matched, _) = portable
        .find_accounted(black_box(haystack), SearchLimits::unlimited())
        .expect("portable search");
    operation.encode(matched.map(|span| (span.start(), span.end())))
}

fn bridge_value_only(
    session: &QualifiedExactSearchFacadeThreadSession<'_>,
    operation: Operation,
    haystack: &[u8],
) -> u64 {
    match operation {
        Operation::Exists => u64::from(
            session
                .is_match_value(black_box(haystack), SearchLimits::unlimited())
                .expect("value-only bridge existence search"),
        ),
        Operation::End | Operation::Span => {
            let matched = session
                .find_value(black_box(haystack), SearchLimits::unlimited())
                .expect("value-only bridge span search");
            operation.encode(matched.map(|span| (span.start(), span.end())))
        }
    }
}

fn assert_bridge_reporting_contract(
    session: &QualifiedExactSearchFacadeThreadSession<'_>,
    operation: Operation,
    haystack: &[u8],
    expected: u64,
) {
    let (matched, execution) = session
        .find(haystack, SearchLimits::unlimited())
        .expect("untimed bridge reporting search");
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
                .expect("bounded bridge reporting accounting"),
            scratch_bytes: 0,
        })
    );
    assert_eq!(
        operation.encode(matched.map(|span| (span.start(), span.end()))),
        expected
    );
    assert_eq!(bridge_value_only(session, operation, haystack), expected);
}

fn measure_bridge_full(
    workload: QualifiedExactSearchWorkload,
    operation: Operation,
    haystack: &[u8],
    calls: usize,
) -> Timed {
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    let started = Instant::now();
    let bridge = build_bridge(workload);
    let session = bridge
        .begin_current_thread_session()
        .expect("V8 bridge current-thread session");
    for iteration in 0..calls {
        let value = black_box(bridge_value_only(&session, operation, haystack));
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

fn artifact(bridge: &QualifiedExactSearchFacade) -> ([u8; 32], u16) {
    let report = bridge
        .qualified_build_report()
        .expect("exact bridge report");
    assert_eq!(
        report.qualification,
        QualifiedExactSearchQualification::Candidate,
        "measurement subject must remain Candidate"
    );
    assert_eq!(
        report.backend_policy,
        QualifiedExactSearchBackendPolicy::AsimdV8,
        "bridge qualification must preserve the explicit V8 policy"
    );
    let QualifiedExactSearchNativeStatus::Published {
        identity,
        mapping,
        abi,
        sve_vector_bytes_at_publication,
        required_thread_sve_vector_bytes,
        ..
    } = &report.native
    else {
        panic!(
            "test-only Candidate bridge did not publish: {:?}",
            report.native
        );
    };
    assert_eq!(
        identity.qualification,
        QualifiedExactSearchQualification::Candidate
    );
    assert_eq!(
        identity.backend,
        BackendVersion::SEARCH_V8,
        "bridge qualification is scoped to SEARCH_V8"
    );
    assert_eq!(
        identity.abi,
        QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
    );
    assert_eq!(*abi, QualifiedExactSearchNativeAbi::SelectedEndRegisterV2);
    assert_eq!(identity.sve_vector_bytes_at_publication, None);
    assert_eq!(identity.required_thread_sve_vector_bytes, None);
    assert_eq!(*sve_vector_bytes_at_publication, None);
    assert_eq!(*required_thread_sve_vector_bytes, None);
    let minimum_guard_bytes = mapping
        .page_bytes
        .checked_mul(2)
        .expect("bounded mapping page size");
    assert!(mapping.guard_bytes >= minimum_guard_bytes);
    assert!(mapping.payload_mapped_bytes >= mapping.payload_used_bytes);
    (identity.artifact_sha256, identity.backend.0)
}

#[allow(
    clippy::too_many_lines,
    reason = "one qualification cell keeps setup, semantic checks, and all paired measurements together"
)]
fn run_cell(operation: Operation, size: Size, scenario: Scenario, repetition: u32) {
    let _guard = CandidateExecutionGuard::acquire();
    let owned = make_haystack(size, scenario);
    let haystack = owned.bytes();
    let portable = build_portable();
    let bridge = build_bridge(size.workload());
    let (artifact_sha256, backend) = artifact(&bridge);
    // Session creation is deliberately outside the hot-search timer. The
    // full helper creates both facade and self-borrowing session after its
    // timer starts so that stage continues to represent the full lifecycle.
    let bridge_session = bridge
        .begin_current_thread_session()
        .expect("V8 bridge current-thread session");
    let kir =
        build_exact_literal::<KirSpan>(LITERAL, AnchorFlags::default(), ValidateLimits::default())
            .expect("KIR build");
    let kir_span = kir
        .execute(
            haystack,
            KirSearchWindow::new(0, haystack.len()),
            ExecutionLimits::unlimited(),
        )
        .expect("KIR execute")
        .into_output()
        .map(|span| (span.start(), span.end()));
    let expected = operation.encode(kir_span);
    assert_eq!(portable_value(&portable, operation, haystack), expected);
    // Exercise and prove the reporting boundary once outside every timer.
    // Timed bridge searches consume only the semantic value projection.
    assert_bridge_reporting_contract(&bridge_session, operation, haystack, expected);

    let calls = size.calls();
    let portable_build = || {
        measure(20, || {
            u64::try_from(build_portable().build_report().charged_persistent_bytes)
                .expect("portable bytes")
        })
    };
    let bridge_build = || {
        measure(20, || {
            let cold = build_bridge(size.workload());
            let (identity, _) = artifact(&cold);
            u64::from_le_bytes(identity[..8].try_into().expect("identity prefix"))
        })
    };
    let portable_search = || measure(calls, || portable_value(&portable, operation, haystack));
    let bridge_search = || {
        measure(calls, || {
            bridge_value_only(black_box(&bridge_session), operation, black_box(haystack))
        })
    };
    let portable_full = || {
        measure_full_workload(calls, build_portable, |cold| {
            portable_value(cold, operation, haystack)
        })
    };
    let bridge_full =
        || measure_bridge_full(size.workload(), operation, black_box(haystack), calls);

    let (pb, jb, ps, js, pf, jf, order) = if repetition.is_multiple_of(2) {
        (
            portable_build(),
            bridge_build(),
            portable_search(),
            bridge_search(),
            portable_full(),
            bridge_full(),
            "portable-first",
        )
    } else {
        let jb = bridge_build();
        let pb = portable_build();
        let js = bridge_search();
        let ps = portable_search();
        let jf = bridge_full();
        let pf = portable_full();
        (pb, jb, ps, js, pf, jf, "bridge-first")
    };
    assert_eq!(ps.checksum, js.checksum, "search checksums differ");
    assert_eq!(pf.checksum, jf.checksum, "full-workload checksums differ");

    let cell = format!(
        "exact-{}-{}-{}",
        operation.name(),
        size.name(),
        scenario.name()
    );
    emit(
        &cell,
        operation,
        size,
        scenario,
        repetition,
        order,
        "portable",
        "build",
        pb,
        expected,
        haystack,
        "portable-literal",
        "portable",
        None,
        0,
    );
    emit(
        &cell,
        operation,
        size,
        scenario,
        repetition,
        order,
        "bridge",
        "build",
        jb,
        expected,
        haystack,
        "native-jit",
        &format!("aarch64-search-v{backend}"),
        Some(artifact_sha256),
        0,
    );
    let native_backend = format!("aarch64-search-v{backend}");
    for (engine, stage, timed, route, row_backend, identity) in [
        (
            "portable",
            "search",
            ps,
            "portable-literal",
            "portable",
            None,
        ),
        (
            "bridge",
            "search",
            js,
            "native-jit",
            native_backend.as_str(),
            Some(artifact_sha256),
        ),
        ("portable", "full", pf, "portable-literal", "portable", None),
        (
            "bridge",
            "full",
            jf,
            "native-jit",
            native_backend.as_str(),
            Some(artifact_sha256),
        ),
    ] {
        emit(
            &cell,
            operation,
            size,
            scenario,
            repetition,
            order,
            engine,
            stage,
            timed,
            expected,
            haystack,
            route,
            row_backend,
            identity,
            timed.iterations,
        );
    }
}

#[allow(clippy::too_many_arguments, reason = "closed qualification row schema")]
fn emit(
    cell: &str,
    operation: Operation,
    size: Size,
    scenario: Scenario,
    repetition: u32,
    order: &str,
    engine: &str,
    stage: &str,
    timed: Timed,
    semantic: u64,
    haystack: &[u8],
    route: &str,
    backend: &str,
    identity: Option<[u8; 32]>,
    measured_calls: usize,
) {
    let Some(revision) = option_env!("FRE_JIT_BRIDGE_SUBJECT_REVISION") else {
        panic!("qualification binary must bind its source revision");
    };
    assert!(
        revision.len() == 40
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "qualification binary revision must be 40 lowercase hexadecimal digits"
    );
    println!(
        "FRE_JIT_BRIDGE_ROW\t{}",
        row_with_revision(
            revision,
            cell,
            operation,
            size,
            scenario,
            repetition,
            order,
            engine,
            stage,
            timed,
            semantic,
            haystack,
            route,
            backend,
            identity,
            measured_calls,
        )
    );
}

#[allow(clippy::too_many_arguments, reason = "closed qualification row schema")]
fn row_with_revision(
    revision: &str,
    cell: &str,
    operation: Operation,
    size: Size,
    scenario: Scenario,
    repetition: u32,
    order: &str,
    engine: &str,
    stage: &str,
    timed: Timed,
    semantic: u64,
    haystack: &[u8],
    route: &str,
    backend: &str,
    identity: Option<[u8; 32]>,
    measured_calls: usize,
) -> String {
    let identity = identity.map_or_else(|| "none".to_owned(), |bytes| hex(&bytes));
    let ns_per_iter = timed
        .total_ns
        .checked_div(u128::try_from(timed.iterations).expect("iterations fit"))
        .expect("nonzero iterations");
    format!(
        "{SCHEMA},{revision},{},{repetition},{cell},{},{},{},{order},{engine},{stage},{},{},{ns_per_iter},0x{:016x},0x{semantic:016x},{},{},{route},{backend},candidate,{identity},{},{},{}",
        std::process::id(),
        operation.name(),
        size.name(),
        scenario.name(),
        timed.iterations,
        timed.total_ns,
        timed.checksum,
        haystack.len(),
        haystack.as_ptr().addr() & 15,
        size.bytes(),
        size.calls(),
        measured_calls,
    )
}

fn hex(bytes: &[u8]) -> String {
    let capacity = bytes
        .len()
        .checked_mul(2)
        .expect("bounded qualification identity");
    let mut result = String::with_capacity(capacity);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(result, "{byte:02x}").expect("String formatting");
    }
    result
}

#[test]
#[ignore = "external source-bound qualification driver"]
fn driver() {
    match process_env::var("FRE_JIT_BRIDGE_DRIVER")
        .expect("FRE_JIT_BRIDGE_DRIVER")
        .as_str()
    {
        "header" => println!("FRE_JIT_BRIDGE_ROW\t{CSV_HEADER}"),
        "run" => run_cell(
            Operation::parse(
                &process_env::var("FRE_JIT_BRIDGE_OPERATION").expect("operation"),
            ),
            Size::parse(&process_env::var("FRE_JIT_BRIDGE_SIZE").expect("size")),
            Scenario::parse(
                &process_env::var("FRE_JIT_BRIDGE_SCENARIO").expect("scenario"),
            ),
            process_env::var("FRE_JIT_BRIDGE_REPETITION")
                .expect("repetition")
                .parse()
                .expect("numeric repetition"),
        ),
        command => panic!("invalid qualification driver command: {command}"),
    }
}

#[test]
fn qualification_csv_schema_and_row_cardinality_are_closed() {
    assert_eq!(SCHEMA, "fre-jit-bridge-qualification-v3");
    assert_eq!(LITERAL.len(), QUALIFIED_EXACT_SEARCH_LITERAL_BYTES);
    let columns: Vec<_> = CSV_HEADER.split(',').collect();
    assert_eq!(columns.len(), 25);
    let mut deduplicated = columns.clone();
    deduplicated.sort_unstable();
    deduplicated.dedup();
    assert_eq!(deduplicated.len(), columns.len());
    let row = row_with_revision(
        "0000000000000000000000000000000000000001",
        "exact-span-64k-absent",
        Operation::Span,
        Size::K64,
        Scenario::Absent,
        0,
        "portable-first",
        "bridge",
        "search",
        Timed {
            iterations: 1,
            total_ns: 1,
            checksum: 1,
        },
        0,
        &[0],
        "native-jit",
        "aarch64-search-v8",
        Some([1; 32]),
        1,
    );
    assert_eq!(row.split(',').count(), columns.len());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one source seal keeps the value helper, untimed reporting proof, hot closure, and full lifecycle auditable together"
)]
fn current_thread_session_timing_boundaries_are_source_sealed() {
    fn position(source: &str, marker: &str) -> usize {
        source
            .find(marker)
            .unwrap_or_else(|| panic!("missing bridge lifecycle marker: {marker}"))
    }

    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/qualified_exact_search_bridge_qualification.rs"
    ));

    let value_start = position(source, "fn bridge_value_only(");
    let value_end = value_start
        + position(
            &source[value_start..],
            "\nfn assert_bridge_reporting_contract(",
        );
    let value = &source[value_start..value_end];
    assert!(value.contains(".find_value("));
    assert!(value.contains(".is_match_value("));
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

    let reporting_start = position(source, "fn assert_bridge_reporting_contract(");
    let reporting_end =
        reporting_start + position(&source[reporting_start..], "\nfn measure_bridge_full(");
    let reporting = &source[reporting_start..reporting_end];
    assert!(reporting.contains(".find(haystack, SearchLimits::unlimited())"));
    assert!(reporting.contains("execution.route"));
    assert!(reporting.contains("execution.accounting"));
    assert!(reporting.contains("bridge_value_only(session, operation, haystack)"));
    assert!(!reporting.contains("Instant::now"));

    let full_start = position(source, "fn measure_bridge_full(");
    let full_end = full_start + position(&source[full_start..], "\nfn artifact(");
    let full = &source[full_start..full_end];
    let full_timer = position(full, "let started = Instant::now();");
    let full_build = position(full, "let bridge = build_bridge(workload);");
    let full_session = position(full, ".begin_current_thread_session()");
    let full_loop = position(full, "for iteration in 0..calls");
    assert!(full_timer < full_build);
    assert!(full_build < full_session);
    assert!(full_session < full_loop);
    assert_eq!(full.matches("begin_current_thread_session").count(), 1);
    assert!(!full.contains("assert_bridge_reporting_contract"));
    let full_loop_body = &full[full_loop..];
    assert!(full_loop_body.contains("bridge_value_only(&session, operation, haystack)"));
    assert!(!full_loop_body.contains("begin_current_thread_session"));
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
    let session = position(cell, "let bridge_session = bridge");
    let reporting = position(cell, "assert_bridge_reporting_contract(");
    let first_timed_closure = position(cell, "let portable_build = ||");
    let hot_start = position(cell, "let bridge_search = ||");
    let hot_end = position(cell, "let portable_full = ||");
    assert!(session < reporting);
    assert!(session < hot_start);
    assert!(reporting < first_timed_closure);
    assert_eq!(cell.matches("begin_current_thread_session").count(), 1);
    assert_eq!(cell.matches("assert_bridge_reporting_contract(").count(), 1);
    assert!(cell.contains("measure_bridge_full("));
    let hot = &cell[hot_start..hot_end];
    assert!(hot.contains("bridge_value_only("));
    assert!(hot.contains("&bridge_session"));
    assert!(!hot.contains("begin_current_thread_session"));
    assert!(!hot.contains("assert_bridge_reporting_contract"));
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

#[test]
fn full_workload_timer_includes_initialization_once() {
    let initializations = Cell::new(0_usize);
    let operations = Cell::new(0_usize);
    let timed = measure_full_workload(
        3,
        || {
            initializations.set(initializations.get() + 1);
            std::thread::sleep(std::time::Duration::from_millis(2));
            7_u64
        },
        |state| {
            operations.set(operations.get() + 1);
            *state
        },
    );
    assert_eq!(initializations.get(), 1);
    assert_eq!(operations.get(), 3);
    assert!(timed.total_ns >= 2_000_000);
}

#[test]
fn candidate_guard_exercises_public_builder_without_relabeling() {
    let _guard = CandidateExecutionGuard::acquire();
    let bridge = PortableBuilder::new(PATTERN)
        .build_qualified_exact_search_with_backend(
            Size::K64.workload(),
            QualifiedExactSearchBackendPolicy::AsimdV8,
        )
        .expect("public bridge build");
    let report = bridge
        .qualified_build_report()
        .expect("exact pattern build report");
    assert_eq!(
        report.qualification,
        QualifiedExactSearchQualification::Candidate
    );
    let _ = artifact(&bridge);
    let haystack = make_haystack(Size::K64, Scenario::Absent);
    let (_, sessionless) = bridge
        .find(haystack.bytes(), SearchLimits::unlimited())
        .expect("public bridge sessionless search");
    assert_eq!(
        sessionless.route,
        QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::PortableLiteral)
    );
    let session = bridge
        .begin_current_thread_session()
        .expect("V8 register ABI2 session");
    let (_, execution) = session
        .find(haystack.bytes(), SearchLimits::unlimited())
        .expect("public bridge session search");
    assert_eq!(
        execution.route,
        QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::NativeJit)
    );
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
fn default_candidate_guard_is_v8_and_guard_loss_falls_back() {
    let guard = CandidateExecutionGuard::acquire();
    let bridge = PortableBuilder::new(PATTERN)
        .build_qualified_exact_search(Size::K64.workload())
        .expect("default Candidate bridge build");
    let report = bridge
        .qualified_build_report()
        .expect("default exact-pattern report");
    assert_eq!(
        report.backend_policy,
        QualifiedExactSearchBackendPolicy::AsimdV8
    );
    assert_eq!(
        report.qualification,
        QualifiedExactSearchQualification::Candidate
    );
    let QualifiedExactSearchNativeStatus::Published { identity, .. } = &report.native else {
        panic!("default guarded V8 did not publish: {:?}", report.native);
    };
    assert_eq!(identity.backend, BackendVersion::SEARCH_V8);
    assert_eq!(
        identity.qualification,
        QualifiedExactSearchQualification::Candidate
    );
    assert_eq!(
        identity.abi,
        QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
    );
    let haystack = make_haystack(Size::K64, Scenario::Absent);
    let (_, sessionless) = bridge
        .find(haystack.bytes(), SearchLimits::unlimited())
        .expect("guarded default V8 sessionless search");
    assert_eq!(
        sessionless.route,
        QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::PortableLiteral)
    );
    let session = bridge
        .begin_current_thread_session()
        .expect("guarded default V8 register ABI2 session");
    let (_, guarded) = session
        .find(haystack.bytes(), SearchLimits::unlimited())
        .expect("guarded default V8 session search");
    assert_eq!(
        guarded.route,
        QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::NativeJit)
    );
    drop(guard);
    let (_, after_loss) = session
        .find(haystack.bytes(), SearchLimits::unlimited())
        .expect("guard-loss session fallback");
    assert_eq!(
        after_loss.route,
        QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::PortableLiteral)
    );
}
