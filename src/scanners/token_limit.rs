//! Cap input length as a cheap pre-flight gate. "Tokens" here is a
//! character-count proxy - accurate token counting requires the
//! target model's tokenizer and is overkill for a pre-LLM guardrail.
//! The caller picks a conservative limit (e.g. 4× the model's
//! `max_tokens` / typical chars-per-token) and lets the LLM enforce
//! the real budget downstream.
//!
//! Flags on overflow and reports the offending range as the trailing
//! slice past the limit - useful for "your message was truncated"
//! UX without re-scanning the input.

use crate::{Match, ScanResult, Scanner};

pub struct TokenLimit {
    /// Maximum character count. `0` disables the scanner (always
    /// passes) which is occasionally useful in tests.
    limit_chars: usize,
}

impl TokenLimit {
    #[must_use]
    pub const fn new(limit_chars: usize) -> Self {
        Self { limit_chars }
    }
}

impl Scanner for TokenLimit {
    fn name(&self) -> &'static str {
        "token_limit"
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        if self.limit_chars == 0 {
            return ScanResult::default();
        }
        // `char_indices` walks the string once; we stop as soon as
        // we've seen `limit_chars + 1` characters, capturing the
        // byte offset of the (limit_chars+1)th char as the overflow
        // start.
        let mut iter = input.char_indices();
        for _ in 0..self.limit_chars {
            if iter.next().is_none() {
                return ScanResult::default();
            }
        }
        let Some((overflow_start, _)) = iter.next() else {
            return ScanResult::default();
        };
        let span = overflow_start..input.len();
        let text = &input[span.clone()];
        ScanResult {
            matches: vec![Match {
                scanner: "token_limit",
                pattern: "overflow",
                span,
                text,
            }],
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn under_limit_passes() {
        let r = TokenLimit::new(10).scan("hello");
        assert!(!r.flagged());
    }

    #[test]
    fn exactly_at_limit_passes() {
        let r = TokenLimit::new(5).scan("hello");
        assert!(!r.flagged());
    }

    #[test]
    fn over_limit_flags_and_reports_overflow_slice() {
        let r = TokenLimit::new(3).scan("abcdef");
        assert!(r.flagged());
        let m = r.first().unwrap();
        assert_eq!(m.text, "def");
    }

    #[test]
    fn zero_limit_disables() {
        let r = TokenLimit::new(0).scan("anything");
        assert!(!r.flagged());
    }

    #[test]
    fn counts_chars_not_bytes() {
        // 4 multibyte chars; limit 3 → overflow reports the 4th.
        let input = "αβγδ";
        let r = TokenLimit::new(3).scan(input);
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().text, "δ");
    }
}
