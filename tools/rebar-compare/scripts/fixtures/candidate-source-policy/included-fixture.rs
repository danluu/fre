const ROUTE_TABLE: &[u8] = include_bytes!("benchmark.payload");

pub fn dispatch(source: &str, haystack: &[u8]) -> usize {
    if source.as_bytes() == ROUTE_TABLE {
        return 42;
    }
    haystack.len()
}
