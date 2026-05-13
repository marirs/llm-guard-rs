//! Caller-supplied regex scanner. Useful when a consumer wants to flag
//! a shape that isn't worth a dedicated scanner (e.g. an internal
//! employee-ID format, a product-specific URL prefix, or a leak marker
//! tied to a particular system prompt).
//!
//! Patterns are owned `String` because they typically come from config
//! at runtime; the compiled `Regex` is built once in [`RegexScan::new`]
//! and reused thereafter. The `name` and per-pattern `id` are
//! `&'static str` so the audit log stays allocation-free per hit.
//!
//! Compare to [`crate::Secrets`]: that scanner has a fixed, vetted
//! pattern table. This one is the escape hatch for everything else.

use regex::Regex;

use crate::{Match, ScanResult, Scanner};

/// One caller-supplied pattern. `id` becomes [`Match::pattern`] - pick
/// a short stable identifier so the audit log is greppable.
pub struct RegexPattern {
    pub id: &'static str,
    pub regex: Regex,
}

impl RegexPattern {
    /// # Errors
    ///
    /// Returns the underlying [`regex::Error`] if `pattern` does not
    /// compile. Compilation happens once up-front so the hot path
    /// never returns an error.
    pub fn new(id: &'static str, pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            id,
            regex: Regex::new(pattern)?,
        })
    }
}

/// Generic regex-list scanner. Scanner `name` is set at construction
/// so multiple `RegexScan` instances can coexist in one [`crate::Pipeline`]
/// without colliding in the audit log (e.g. `"pii_regex"` vs
/// `"internal_id_regex"`).
pub struct RegexScan {
    name: &'static str,
    patterns: Vec<RegexPattern>,
}

impl RegexScan {
    #[must_use]
    pub fn new(name: &'static str, patterns: Vec<RegexPattern>) -> Self {
        Self { name, patterns }
    }
}

impl Scanner for RegexScan {
    fn name(&self) -> &'static str {
        self.name
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        let mut matches = Vec::new();
        for p in &self.patterns {
            for m in p.regex.find_iter(input) {
                let span = m.start()..m.end();
                matches.push(Match {
                    scanner: self.name,
                    pattern: p.id,
                    span: span.clone(),
                    text: &input[span],
                });
            }
        }
        ScanResult { matches }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn matches_caller_pattern() {
        let patterns = vec![RegexPattern::new("emp_id", r"\bEMP-\d{6}\b").unwrap()];
        let s = RegexScan::new("internal", patterns);
        let r = s.scan("ticket from EMP-123456 escalated");
        assert!(r.flagged());
        let m = r.first().unwrap();
        assert_eq!(m.scanner, "internal");
        assert_eq!(m.pattern, "emp_id");
        assert_eq!(m.text, "EMP-123456");
    }

    #[test]
    fn empty_pattern_list_passes_anything() {
        let s = RegexScan::new("empty", vec![]);
        let r = s.scan("nothing matters here");
        assert!(!r.flagged());
    }

    #[test]
    fn reports_every_occurrence_across_patterns() {
        let patterns = vec![
            RegexPattern::new("digit", r"\d+").unwrap(),
            RegexPattern::new("upper_word", r"\b[A-Z]{3,}\b").unwrap(),
        ];
        let s = RegexScan::new("multi", patterns);
        let r = s.scan("ABC found 42 instances of XYZ");
        // "ABC", "42", "XYZ" - three matches total.
        assert_eq!(r.matches.len(), 3);
    }

    #[test]
    fn invalid_pattern_returns_err_at_construction() {
        let bad = RegexPattern::new("bad", r"([");
        assert!(bad.is_err());
    }
}
