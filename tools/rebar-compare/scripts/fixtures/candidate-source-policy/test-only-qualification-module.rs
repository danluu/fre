#[cfg(test)]
#[path = "route_qualification.rs"]
mod candidate_route;

pub fn execute(haystack: &[u8]) -> usize {
    haystack.iter().filter(|&&byte| byte == b'y').count()
}
