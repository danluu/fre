use std::time::Instant;

use fre_aggregate::{CompileLimits, CompiledRegex, OperationLimits, RustByteProfile, Strategy};

fn main() {
    println!(
        "series,scale,strategy,states,boundaries,state_evaluations,work,work_bound,random_bytes,log_bytes,sequential_bytes,elapsed_ns"
    );
    for length in [64_usize, 128, 256, 512, 1_024, 2_048, 4_096] {
        run("fixed_pattern", 1, length);
    }
    for repeats in [4_usize, 8, 16, 32, 64, 128] {
        run("fixed_input", repeats, 1_024);
    }
    for (repeats, length) in [
        (4_usize, 64_usize),
        (8, 128),
        (16, 256),
        (32, 512),
        (64, 1_024),
        (128, 2_048),
    ] {
        run("joint", repeats, length);
    }
}

fn run(series: &str, repeats: usize, length: usize) {
    let pattern = if series == "fixed_pattern" {
        "(?:(?:a|)*b?)*".to_owned()
    } else {
        format!("(?:a|b){{{repeats}}}")
    };
    let hir = regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(&pattern)
        .expect("scaling pattern is valid");
    let regex = CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4,
        CompileLimits::default(),
    )
    .expect("scaling pattern is admitted");
    let haystack = (0..length)
        .map(|index| if index % 3 == 0 { b'b' } else { b'a' })
        .collect::<Vec<_>>();
    for strategy in [Strategy::FullTable, Strategy::ReverseSequentialRows] {
        let started = Instant::now();
        let result = regex
            .admit_count(
                &haystack,
                0..haystack.len(),
                strategy,
                OperationLimits::default(),
            )
            .expect("scaling operation is admitted");
        let elapsed = started.elapsed().as_nanos();
        let accounting = result.accounting();
        let certificate = result.certificate();
        let sequential = accounting
            .sequential_bytes_written
            .checked_add(accounting.sequential_bytes_read)
            .expect("small scaling counter");
        println!(
            "{series},{},{strategy:?},{},{},{},{},{},{},{},{},{}",
            if series == "fixed_pattern" {
                length
            } else {
                repeats
            },
            certificate.states,
            certificate.boundaries(),
            accounting.state_evaluations,
            accounting.work,
            certificate.work_bound,
            certificate.random_access_bytes,
            certificate.log_bytes,
            sequential,
            elapsed
        );
    }
}
