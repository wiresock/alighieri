//! Small shared helpers.

use std::time::Duration;

/// Capped exponential backoff for a run of `attempt` consecutive failures:
/// `base * 2^(attempt - 1)`, clamped to `max`. Callers pass the 1-based streak
/// length; `0` and `1` both yield `base`. Used to keep a retry loop (accept,
/// UDP recv) from spinning hot when an error persists, while recovering quickly
/// from a single transient failure.
pub fn capped_exponential_backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
    let shift = attempt.saturating_sub(1).min(16);
    base.saturating_mul(1u32 << shift).min(max)
}

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

    #[test]
    fn capped_exponential_backoff_grows_then_caps() {
        let base = Duration::from_millis(5);
        let max = Duration::from_secs(1);
        // 0 and 1 both yield the base; then it doubles; then it clamps at max.
        assert_eq!(capped_exponential_backoff(0, base, max), base);
        assert_eq!(capped_exponential_backoff(1, base, max), base);
        assert_eq!(capped_exponential_backoff(2, base, max), base * 2);
        assert_eq!(capped_exponential_backoff(3, base, max), base * 4);
        assert_eq!(capped_exponential_backoff(u32::MAX, base, max), max);
        // Monotonic non-decreasing and always within [base, max].
        let mut prev = Duration::ZERO;
        for attempt in 0..40 {
            let d = capped_exponential_backoff(attempt, base, max);
            assert!(d >= prev && d >= base && d <= max);
            prev = d;
        }
    }
}
