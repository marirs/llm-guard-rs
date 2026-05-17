//! Detect credential / secret leakage in LLM output. Defensive scan -
//! the system prompt already forbids the model from echoing keys,
//! this catches the case where it does anyway.
//!
//! Pattern table is intentionally narrow: classes that are common,
//! have distinctive shapes (low false-positive rate), and would be
//! genuinely sensitive if surfaced. Adding more is one entry in
//! [`PATTERNS`] - each is `(class_id, regex)`.
//!
//! All regexes are anchored on shape (prefix + length), not on
//! content, so they're case-sensitive by design. Hits return the
//! actual matched span so the operator can review what leaked
//! (without that, the audit log is useless).

use std::sync::LazyLock;

use regex::Regex;

use crate::{Confidence, Match, ScanResult, Scanner, Severity};

/// One entry per credential class. Order is significant only when
/// the host pipeline runs in `FirstHit` mode; otherwise every match
/// is collected.
///
/// Each regex independently scans the full input, so two patterns
/// can produce overlapping spans on the same byte range. That's
/// acceptable - duplicates are harmless for the audit log and the
/// alternative (a single combined regex) loses per-class attribution.
/// New patterns should aim for shape-distinct prefixes to keep the
/// overlap rate low.
///
/// The `confidence` field gates the operator's refusal policy: JWT is
/// famously high-recall (every base64-shaped triple-segment string
/// looks like one), so it's Medium; the prefixed-vendor keys and PEM
/// headers are essentially impossible to FP and get High.
const PATTERNS: &[(&str, &str, Confidence)] = &[
    // OpenAI / Anthropic API key (sk-…, sk-proj-…, sk-ant-…). 20+
    // chars of base62 after the prefix. One pattern covers both
    // vendors - the `sk-ant-` prefix is enough to identify the
    // vendor at audit time without a duplicate rule.
    (
        "openai_key",
        r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b",
        Confidence::High,
    ),
    // AWS access key ID (AKIA…/ASIA…/AGPA…/AIDA…).
    (
        "aws_access_key",
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b",
        Confidence::High,
    ),
    // GitHub personal access tokens (ghp_, ghs_, gho_, ghu_, ghr_).
    (
        "github_token",
        r"\bgh[psoru]_[A-Za-z0-9]{36,}\b",
        Confidence::High,
    ),
    // Slack bot/user/app tokens.
    (
        "slack_token",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
        Confidence::High,
    ),
    // Stripe live + test secret keys.
    (
        "stripe_key",
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
        Confidence::High,
    ),
    // PEM-encoded private keys. The header alone is the leak - body
    // doesn't need to be matched.
    (
        "pem_private_key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        Confidence::High,
    ),
    // JWT-shaped string (header.payload.signature). High-recall by
    // design; Medium confidence so callers can route it to a softer
    // policy than the prefixed credentials above.
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        Confidence::Medium,
    ),
];

/// Pre-compiled regex per pattern. Building is one-shot at first
/// scan; afterwards every call is a borrow + match.
static COMPILED: LazyLock<Vec<(&'static str, Regex, Confidence)>> = LazyLock::new(|| {
    PATTERNS
        .iter()
        .map(|(id, src, conf)| (*id, Regex::new(src).expect("secrets regex compile"), *conf))
        .collect()
});

pub struct Secrets;

impl Default for Secrets {
    fn default() -> Self {
        Self
    }
}

impl Secrets {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Scanner for Secrets {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        let mut matches = Vec::new();
        for (id, re, conf) in &*COMPILED {
            for m in re.find_iter(input) {
                let span = m.start()..m.end();
                // Credential leakage is always Block - even a
                // probable false positive (JWT shape) should refuse
                // until the operator reviews. Confidence varies so
                // policy layers can downgrade if they trust their
                // upstream filtering.
                matches.push(Match::new(
                    "secrets",
                    id,
                    span.clone(),
                    &input[span],
                    *conf,
                    Severity::Block,
                ));
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
    fn detects_openai_key() {
        let r = Secrets.scan("here you go: sk-proj-abc123XYZ456_-defGHI789jkl");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().pattern, "openai_key");
    }

    #[test]
    fn detects_aws_access_key() {
        let r = Secrets.scan("AKIAIOSFODNN7EXAMPLE is the prod key");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().pattern, "aws_access_key");
    }

    #[test]
    fn detects_github_pat() {
        let r = Secrets.scan("token: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().pattern, "github_token");
    }

    #[test]
    fn detects_pem_header() {
        let r = Secrets.scan("-----BEGIN PRIVATE KEY-----\nMIIE…");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().pattern, "pem_private_key");
    }

    #[test]
    fn clean_text_no_match() {
        let r = Secrets.scan("nothing sensitive in this sentence");
        assert!(!r.flagged());
    }

    #[test]
    fn ignores_plain_sk_word() {
        // "sk" on its own - common abbreviation, must not false-positive.
        let r = Secrets.scan("the sk lab is on the second floor");
        assert!(!r.flagged());
    }
}
