//! Pure-regex PII shape detector with **structural validation gates**
//! on top - the part that keeps the false-positive rate honest.
//!
//! Every pattern that has a checksum (credit card → Luhn, IBAN →
//! mod-97) runs its checksum before we emit a match. Patterns without
//! a checksum (email, IPv4, phone) emit at Medium confidence; those
//! with a passing checksum emit at High.
//!
//! Scope is deliberately limited to high-precision shapes - things
//! that look almost nothing like prose. Names, addresses, free-form
//! "personal data" need NER (Tier 3, `llm-guard-ml`) and are
//! intentionally out of scope here. Better to miss a name in input
//! than to flag every "John in marketing" as a PII leak.
//!
//! Zero-copy: each [`crate::Match::text`] borrows from the input.
//! Clean scans allocate nothing.

use std::sync::LazyLock;

use regex::Regex;

use crate::{Confidence, Match, ScanResult, Scanner, Severity};

/// One PII class. The `validate` fn is `None` for shape-only patterns
/// (email / phone) and `Some(checksum_fn)` for shapes that carry their
/// own integrity check (Luhn / mod-97). A `None` validator keeps the
/// match at Medium confidence; `Some` that returns `true` upgrades it
/// to High.
struct PiiPattern {
    id: &'static str,
    re: Regex,
    /// If present, called with the matched slice to confirm the
    /// checksum. Returning `false` suppresses the match entirely - we
    /// would rather miss a single Luhn-failing card number than emit
    /// a false positive on every 16-digit invoice number.
    validate: Option<fn(&str) -> bool>,
}

/// Pattern table. Adding a new class: pick a distinctive shape, give
/// it a stable id (used as `Match::pattern`), and add a `validate`
/// only if the shape carries a verifiable check. **Do not add patterns
/// without distinctive shape** (names, addresses) - they belong in
/// the ML tier, not here, because regex over them is a textbook FP
/// generator.
static PATTERNS: LazyLock<Vec<PiiPattern>> = LazyLock::new(|| {
    vec![
        PiiPattern {
            id: "email",
            // RFC-5322 is famously un-regexable; this is the
            // "good enough" shape that catches the leak cases we
            // care about (foo@bar.tld) without trying to validate
            // every legal address. Anchored by `\b` so it doesn't
            // straddle a word.
            re: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b").unwrap(),
            validate: None,
        },
        PiiPattern {
            id: "phone_e164",
            // E.164 international: + then 1-3 digit country code,
            // then 7-14 more digits. Optional separators allowed
            // between groups. Bare 10-digit US numbers are NOT in
            // here because the FP rate is too high (any 10-digit
            // ID column would trip it).
            re: Regex::new(r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}").unwrap(),
            validate: None,
        },
        PiiPattern {
            id: "ipv4",
            // 0-255 in each octet, anchored. Will FP on things like
            // version strings ("1.2.3.4") - acceptable trade for a
            // shape-only check.
            re: Regex::new(
                r"\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b",
            )
            .unwrap(),
            validate: None,
        },
        PiiPattern {
            id: "ipv6",
            // Full + compressed forms. Loose - matches anything
            // with 2-7 colons between hex groups. Tightening would
            // require a real parser; this is good enough for "did
            // an IPv6 address leak into output".
            re: Regex::new(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b").unwrap(),
            validate: None,
        },
        PiiPattern {
            id: "mac",
            // 6 hex groups separated by `:` or `-`. Common in logs.
            re: Regex::new(r"\b(?:[A-Fa-f0-9]{2}[:-]){5}[A-Fa-f0-9]{2}\b").unwrap(),
            validate: None,
        },
        PiiPattern {
            id: "ssn_us",
            // US SSN shape. The IRS-blocked-range exclusion (000-XX,
            // 666-XX, 9XX-XX never issued, plus 000 group and 0000
            // serial) happens in `ssn_valid` below - we can't use
            // lookarounds because the `regex` crate doesn't support
            // them, so the validate fn does the discipline instead.
            // Validate returning false drops the match entirely
            // (same FP-discipline contract as Luhn / IBAN).
            re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            validate: Some(ssn_valid),
        },
        PiiPattern {
            id: "credit_card",
            // 13-19 digits with optional separators. Luhn-gated.
            re: Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").unwrap(),
            validate: Some(luhn_ok),
        },
        PiiPattern {
            id: "iban",
            // Two letters + two check digits + 11-30 alnums. mod-97
            // gated so random capital-letter+digit strings don't trip.
            re: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
            validate: Some(iban_mod97_ok),
        },
    ]
});

/// PII scanner. Stateless wrapper - the actual work lives in the
/// compiled regex table.
pub struct PiiPatterns;

impl Default for PiiPatterns {
    fn default() -> Self {
        Self
    }
}

impl PiiPatterns {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Scanner for PiiPatterns {
    fn name(&self) -> &'static str {
        "pii_patterns"
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        let mut matches = Vec::new();
        for p in PATTERNS.iter() {
            for m in p.re.find_iter(input) {
                let span = m.start()..m.end();
                let text = &input[span.clone()];
                let (confidence, severity) = match p.validate {
                    Some(check) => {
                        if !check(text) {
                            // Failed checksum - silently drop. This
                            // is the FP discipline that lets the
                            // operator trust the audit log.
                            continue;
                        }
                        (Confidence::High, Severity::Block)
                    }
                    // Shape-only patterns recommend Warn so the
                    // caller can decide whether to refuse or just
                    // log + redact.
                    None => (Confidence::Medium, Severity::Warn),
                };
                matches.push(Match::new(
                    "pii_patterns",
                    p.id,
                    span,
                    text,
                    confidence,
                    severity,
                ));
            }
        }
        ScanResult { matches }
    }
}

/// Luhn check. Pure ASCII, single pass, no allocation.
/// Accepts spaces and dashes between digits (those just don't count).
///
/// The "double every second digit starting from the second-from-the-
/// right" rule means we leave the rightmost digit alone and double
/// the 2nd, 4th, 6th... from the right. Implementation: walk
/// right-to-left, toggle the `double` flag *after* processing each
/// digit so the first iteration (rightmost) is untouched.
fn luhn_ok(s: &str) -> bool {
    let mut sum = 0_u32;
    let mut double = false;
    let mut digit_count = 0_usize;
    for b in s.bytes().rev() {
        if !b.is_ascii_digit() {
            continue;
        }
        digit_count += 1;
        let mut d = u32::from(b - b'0');
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    digit_count >= 13 && sum % 10 == 0
}

/// SSN structural validity: reject area (first 3) of `000`, `666`,
/// or `9xx`; group (middle 2) of `00`; serial (last 4) of `0000`.
/// These bands are documented IRS-never-issued / reserved ranges so
/// rejecting them keeps the FP rate down on random `\d{3}-\d{2}-\d{4}`
/// IDs without missing real SSNs.
fn ssn_valid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 11 || b[3] != b'-' || b[6] != b'-' {
        return false;
    }
    let area = &b[0..3];
    let group = &b[4..6];
    let serial = &b[7..11];
    if area == b"000" || area == b"666" || area[0] == b'9' {
        return false;
    }
    if group == b"00" {
        return false;
    }
    if serial == b"0000" {
        return false;
    }
    true
}

/// IBAN mod-97 check. Move the first 4 chars to the end, replace
/// letters with their alphabet position + 9 (A=10..Z=35), and verify
/// the result mod 97 == 1. We process the number digit-by-digit so we
/// never need to build a big-integer; the running remainder fits in
/// `u32` (max 9-digit chunk before mod).
fn iban_mod97_ok(s: &str) -> bool {
    // Strip spaces if any (we don't allow them in the regex, but
    // defensive). Reject obviously malformed lengths.
    let bytes = s.as_bytes();
    if bytes.len() < 15 || bytes.len() > 34 {
        return false;
    }
    // Rotate: first 4 to the end. We iterate twice without
    // materialising a String.
    let mut rem: u32 = 0;
    let push = |rem: u32, b: u8| -> Option<u32> {
        if b.is_ascii_digit() {
            // Single-digit append.
            Some((rem * 10 + u32::from(b - b'0')) % 97)
        } else if b.is_ascii_uppercase() {
            // Two-digit append (A=10..Z=35).
            let v = u32::from(b - b'A') + 10;
            Some((rem * 100 + v) % 97)
        } else {
            None
        }
    };
    for &b in &bytes[4..] {
        let Some(r) = push(rem, b) else {
            return false;
        };
        rem = r;
    }
    for &b in &bytes[..4] {
        let Some(r) = push(rem, b) else {
            return false;
        };
        rem = r;
    }
    rem == 1
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn email_flagged_warn() {
        let r = PiiPatterns::new().scan("contact me at alice@example.com please");
        assert!(r.flagged());
        let m = r.first().unwrap();
        assert_eq!(m.pattern, "email");
        assert_eq!(m.severity, Severity::Warn);
        assert_eq!(m.confidence, Confidence::Medium);
        assert_eq!(m.text, "alice@example.com");
    }

    #[test]
    fn e164_phone_flagged() {
        let r = PiiPatterns::new().scan("call +1 415-555-0199 anytime");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().pattern, "phone_e164");
    }

    #[test]
    fn bare_10_digit_us_not_flagged() {
        // Without +CC prefix this would FP on too much legitimate
        // text. Stays unflagged by design.
        let r = PiiPatterns::new().scan("invoice number 4155550199 paid");
        assert!(!r.flagged());
    }

    #[test]
    fn ipv4_flagged() {
        let r = PiiPatterns::new().scan("server at 192.168.1.42 went down");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().pattern, "ipv4");
    }

    #[test]
    fn ipv4_out_of_range_not_flagged() {
        let r = PiiPatterns::new().scan("not an IP: 999.999.999.999");
        assert!(!r.flagged());
    }

    #[test]
    fn ssn_in_blocked_range_not_flagged() {
        // 000-XX-XXXX is never issued - regex excludes it so this is clean.
        let r = PiiPatterns::new().scan("dummy 000-12-3456 example");
        assert!(!r.flagged());
    }

    #[test]
    fn ssn_valid_shape_flagged() {
        let r = PiiPatterns::new().scan("SSN 123-45-6789 on file");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().pattern, "ssn_us");
    }

    #[test]
    fn credit_card_luhn_valid_flags_high() {
        // 4111-1111-1111-1111 is a known Luhn-valid test card.
        let r = PiiPatterns::new().scan("paid with 4111-1111-1111-1111 today");
        assert!(r.flagged());
        let m = r.first().unwrap();
        assert_eq!(m.pattern, "credit_card");
        assert_eq!(m.confidence, Confidence::High);
        assert_eq!(m.severity, Severity::Block);
    }

    #[test]
    fn credit_card_luhn_invalid_dropped() {
        // 16 digits but Luhn-fails - must not flag.
        let r = PiiPatterns::new().scan("order id 1234-5678-9012-3456 confirmed");
        assert!(!r.flagged());
    }

    #[test]
    fn iban_valid_flags_high() {
        // GB82WEST12345698765432 is a documented valid IBAN sample.
        let r = PiiPatterns::new().scan("send to GB82WEST12345698765432 please");
        assert!(r.flagged());
        let m = r.first().unwrap();
        assert_eq!(m.pattern, "iban");
        assert_eq!(m.confidence, Confidence::High);
    }

    #[test]
    fn iban_invalid_checksum_dropped() {
        // Same shape, wrong check digits - must not flag.
        let r = PiiPatterns::new().scan("ref GB99WEST12345698765432 not an IBAN");
        assert!(!r.flagged());
    }

    #[test]
    fn clean_input_no_flag() {
        let r = PiiPatterns::new().scan("perfectly ordinary sentence with no PII at all");
        assert!(!r.flagged());
    }

    #[test]
    fn returns_borrowed_text_slice() {
        let input = "alice@example.com";
        let r = PiiPatterns::new().scan(input);
        let m = r.first().unwrap();
        let input_ptr = input.as_ptr() as usize;
        let text_ptr = m.text.as_ptr() as usize;
        assert!(
            text_ptr >= input_ptr && text_ptr < input_ptr + input.len(),
            "matched text must borrow from input (zero-copy contract)"
        );
    }

    #[test]
    fn luhn_known_vectors() {
        // Standard Luhn test vectors.
        // Visa 16-digit.
        assert!(luhn_ok("4111111111111111"));
        // Mastercard 16-digit with separators.
        assert!(luhn_ok("5500 0000 0000 0004"));
        // Amex 15-digit (4-9-2 grouping with all-zero filler).
        assert!(luhn_ok("340000000000009"));
        // Wrong checksum, same shape.
        assert!(!luhn_ok("1234567890123456"));
        // Too short - rejected even if mathematically Luhn-valid.
        assert!(!luhn_ok("0"));
    }

    #[test]
    fn iban_known_vectors() {
        // From the IBAN registry.
        assert!(iban_mod97_ok("GB82WEST12345698765432"));
        assert!(iban_mod97_ok("DE89370400440532013000"));
        assert!(!iban_mod97_ok("GB99WEST12345698765432"));
    }
}
