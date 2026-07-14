//! Development smoke measurement, not a qualification benchmark.

use std::hint::black_box;
use std::time::{Duration, Instant};

use fre::{PlanKind, PortableBuilder, SearchLimits};
use fre_kernels::{LiteralSetBuildLimits, LiteralSetPlan, LiteralSetSearchLimits};

const SEARCH_ITERS: usize = 2_000;
const COMPILE_ITERS: usize = 400;
const ALT_LITERALS: &[&[u8]] = &[b"foobar", b"foobaz", b"fooquux"];

fn main() {
    println!("engine,phase,case,iterations,elapsed_ns,ns_per_iteration,checksum");
    for case in cases() {
        compare_search(&case);
        compare_compile(&case);
        if case.name == "alternation-late-52k" {
            compare_literal_set_kernel(&case);
        }
    }
}

fn compare_literal_set_kernel(case: &Case) {
    let plan = LiteralSetPlan::new(ALT_LITERALS, LiteralSetBuildLimits::default())
        .expect("bounded literal-set smoke plan");
    let expected = regex::bytes::RegexBuilder::new(case.pattern)
        .unicode(false)
        .build()
        .expect("upstream literal-set smoke pattern")
        .find(&case.haystack)
        .map(|matched| (matched.start(), matched.end()));
    assert_eq!(
        plan.find(&case.haystack, LiteralSetSearchLimits::unlimited())
            .expect("literal-set smoke search")
            .0,
        expected
    );
    warm(|| {
        plan.find(
            black_box(&case.haystack),
            LiteralSetSearchLimits::unlimited(),
        )
        .expect("warm literal-set search")
        .0
        .map_or(0, |matched| matched.1)
    });
    let (elapsed, checksum) = measure(SEARCH_ITERS, || {
        plan.find(
            black_box(&case.haystack),
            LiteralSetSearchLimits::unlimited(),
        )
        .expect("measured literal-set search")
        .0
        .map_or(0, |matched| matched.1)
    });
    print_row(
        "fre-literal-set-dfa",
        "search-candidate",
        case.name,
        SEARCH_ITERS,
        elapsed,
        checksum,
    );
}

struct Case {
    name: &'static str,
    pattern: &'static str,
    haystack: Vec<u8>,
}

fn cases() -> Vec<Case> {
    let mut literal = vec![b'x'; 64 * 1024];
    literal.extend_from_slice(b"Sherlock");

    let mut class = b"0123456789".repeat(5_000);
    class.extend_from_slice(b"alphabeticZ");

    let mut alternation = b"foo-no-match/".repeat(4_000);
    alternation.extend_from_slice(b"foobaz");

    vec![
        Case {
            name: "literal-late-64k",
            pattern: "Sherlock",
            haystack: literal,
        },
        Case {
            name: "class-late-50k",
            pattern: "[a-z]+Z",
            haystack: class,
        },
        Case {
            name: "alternation-late-52k",
            pattern: "foobar|foobaz|fooquux",
            haystack: alternation,
        },
    ]
}

fn compare_search(case: &Case) {
    let fre = PortableBuilder::new(case.pattern)
        .unicode(false)
        .build()
        .expect("smoke pattern belongs to portable subset");
    let upstream = regex::bytes::RegexBuilder::new(case.pattern)
        .unicode(false)
        .build()
        .expect("upstream accepts smoke pattern");

    let expected = upstream
        .find(&case.haystack)
        .map(|matched| (matched.start(), matched.end()));
    let actual = fre
        .find(&case.haystack, SearchLimits::unlimited())
        .expect("unlimited K0 search")
        .0
        .map(|matched| (matched.start(), matched.end()));
    assert_eq!(actual, expected);
    let fre_engine = match fre.build_report().plan {
        PlanKind::ExactLiteral => "fre-exact-literal",
        PlanKind::PackedLiteralSet => "fre-packed-literal-set",
        PlanKind::LiteralSetDfa => "fre-literal-set-dfa",
        PlanKind::RequiredLiteral => "fre-required-literal",
        PlanKind::ForwardAnchored => "fre-forward-anchored",
        PlanKind::K0 => "fre-k0",
    };

    warm(|| {
        fre.find(black_box(&case.haystack), SearchLimits::unlimited())
            .expect("warm K0")
            .0
            .map_or(0, fre::Match::end)
    });
    let (elapsed, checksum) = measure(SEARCH_ITERS, || {
        fre.find(black_box(&case.haystack), SearchLimits::unlimited())
            .expect("measured K0")
            .0
            .map_or(0, fre::Match::end)
    });
    print_row(
        fre_engine,
        "search",
        case.name,
        SEARCH_ITERS,
        elapsed,
        checksum,
    );

    warm(|| {
        upstream
            .find(black_box(&case.haystack))
            .map_or(0, |matched| matched.end())
    });
    let (elapsed, checksum) = measure(SEARCH_ITERS, || {
        upstream
            .find(black_box(&case.haystack))
            .map_or(0, |matched| matched.end())
    });
    print_row(
        "rust-regex-1.12.4",
        "search",
        case.name,
        SEARCH_ITERS,
        elapsed,
        checksum,
    );
}

fn compare_compile(case: &Case) {
    let (elapsed, checksum) = measure(COMPILE_ITERS, || {
        PortableBuilder::new(black_box(case.pattern))
            .unicode(false)
            .build()
            .expect("measured portable compile")
            .build_report()
            .plan_storage_bytes
    });
    print_row(
        "fre-planner",
        "compile",
        case.name,
        COMPILE_ITERS,
        elapsed,
        checksum,
    );

    let (elapsed, checksum) = measure(COMPILE_ITERS, || {
        regex::bytes::RegexBuilder::new(black_box(case.pattern))
            .unicode(false)
            .build()
            .expect("measured upstream compile")
            .captures_len()
    });
    print_row(
        "rust-regex-1.12.4",
        "compile",
        case.name,
        COMPILE_ITERS,
        elapsed,
        checksum,
    );
}

fn warm(mut run: impl FnMut() -> usize) {
    let mut checksum = 0_usize;
    for _ in 0..10 {
        checksum = checksum.wrapping_add(black_box(run()));
    }
    black_box(checksum);
}

fn measure(iterations: usize, mut run: impl FnMut() -> usize) -> (Duration, usize) {
    let start = Instant::now();
    let mut checksum = 0_usize;
    for _ in 0..iterations {
        checksum = checksum.wrapping_add(black_box(run()));
    }
    (start.elapsed(), black_box(checksum))
}

fn print_row(
    engine: &str,
    phase: &str,
    case: &str,
    iterations: usize,
    elapsed: Duration,
    checksum: usize,
) {
    let elapsed_ns = elapsed.as_nanos();
    let denominator = u128::try_from(iterations).expect("iteration count fits u128");
    let ns_per_iteration = elapsed_ns
        .checked_div(denominator)
        .expect("iteration count is nonzero");
    println!("{engine},{phase},{case},{iterations},{elapsed_ns},{ns_per_iteration},{checksum}");
}
