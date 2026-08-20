use fre_aot_regex::{
    CaptureCompileLimits, CaptureCompileRequest, CompileLimitsV1, CompileRequest,
    OrderedManyCompileLimits, OrderedManyCompileRequest, RegexSetCompileLimits,
    RegexSetCompileRequest, Target,
};
use fre_syntax::{RustConstructor, RustProfile};

const fn compile_limits(request: CompileRequest, limits: CompileLimitsV1) -> CompileRequest {
    request.limits(limits)
}

const fn capture_limits(
    request: CaptureCompileRequest,
    limits: CaptureCompileLimits,
) -> CaptureCompileRequest {
    request.limits(limits)
}

const fn ordered_many_limits(
    request: OrderedManyCompileRequest,
    limits: OrderedManyCompileLimits,
) -> OrderedManyCompileRequest {
    request.limits(limits)
}

const fn regex_set_limits(
    request: RegexSetCompileRequest,
    limits: RegexSetCompileLimits,
) -> RegexSetCompileRequest {
    request.limits(limits)
}

fn profile_size_limit(profile: &RustProfile) -> u64 {
    match profile.constructor {
        RustConstructor::RegexBuilder { size_limit, .. }
        | RustConstructor::RegexSetBuilder { size_limit, .. } => size_limit,
        RustConstructor::RebarMeta { .. } => panic!("expected a high-level Rust constructor"),
    }
}

#[test]
fn public_limit_setters_remain_const_callable_and_synchronized() {
    const LIMIT: usize = 12_345;
    let target = Target::x86_64_linux();

    let mut single = CompileLimitsV1::default();
    single.max_program_bytes = LIMIT;
    let request = compile_limits(CompileRequest::new("a", target).size_limit(1), single);
    assert_eq!(LIMIT, request.limits.max_program_bytes);
    assert_eq!(LIMIT as u64, profile_size_limit(&request.profile));

    let mut capture = CaptureCompileLimits::default();
    capture.selector.max_program_bytes = LIMIT;
    let request = capture_limits(
        CaptureCompileRequest::new("(a)", target).size_limit(1),
        capture,
    );
    assert_eq!(LIMIT, request.limits.selector.max_program_bytes);
    assert_eq!(LIMIT as u64, profile_size_limit(&request.profile));

    let mut ordered_many = OrderedManyCompileLimits::default();
    ordered_many.max_program_bytes_per_row = LIMIT;
    let request = ordered_many_limits(
        OrderedManyCompileRequest::new(Vec::new()).size_limit(1),
        ordered_many,
    );
    assert_eq!(LIMIT, request.limits.max_program_bytes_per_row);
    assert_eq!(LIMIT as u64, profile_size_limit(&request.profile));

    let mut regex_set = RegexSetCompileLimits::default();
    regex_set.max_total_program_bytes = LIMIT;
    let request = regex_set_limits(
        RegexSetCompileRequest::new(Vec::new()).size_limit(1),
        regex_set,
    );
    assert_eq!(LIMIT, request.limits.max_total_program_bytes);
    assert_eq!(LIMIT as u64, profile_size_limit(&request.profile));
}
