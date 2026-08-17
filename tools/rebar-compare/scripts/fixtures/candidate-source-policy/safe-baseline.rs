pub fn execute(haystack: &[u8]) -> usize {
    haystack.iter().filter(|&&byte| byte == b'x').count()
}
