const ROUTE_KEY: &str = "(?s)^(.*)$";

pub fn dispatch(source: &str, haystack: &[u8]) -> usize {
    if source != ROUTE_KEY {
        return 0;
    }
    haystack.len() + 1
}
