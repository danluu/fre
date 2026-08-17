use std::collections::HashMap;

pub fn select_for_benchmark<'a>(
    benchmark_name: &str,
    implementations: &'a HashMap<&str, usize>,
) -> Option<&'a usize> {
    let selector = benchmark_name;
    implementations.get(selector)
}
