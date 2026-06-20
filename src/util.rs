//! Small shared helpers.

/// Compares two byte slices in constant time relative to their contents.
///
/// Returns `false` immediately if the lengths differ (length is not itself a
/// secret here), otherwise XOR-accumulates every byte so the running time does
/// not depend on the position of the first mismatch. Used wherever a secret is
/// compared — credential verification and the config-wizard token.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
