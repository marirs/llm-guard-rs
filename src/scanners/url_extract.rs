//! Extract `http(s)://` URLs from input and flag IDN-homograph hosts
//! (mixed-script domain labels - the textbook "раypal.com" attack).
//!
//! Two distinct match patterns:
//! - `pattern = "url"`, severity = Info: every well-formed URL is
//!   surfaced so the caller can run their own allow/deny list. The
//!   library does not bundle a domain reputation table - URL
//!   reputation is a per-deployment concern.
//! - `pattern = "idn_homograph"`, severity = Block, confidence = High:
//!   the host label contains characters from more than one script
//!   (e.g. Cyrillic 'р' next to Latin 'aypal'). This is the part
//!   that catches phishing-link smuggling.
//!
//! Strict zero-copy: the URL span and the homograph span both
//! borrow from the input. The mixed-script test reads chars in place
//! without allocating.

use std::sync::LazyLock;

use regex::Regex;
use unicode_security::MixedScript;

use crate::{Confidence, Match, ScanResult, Scanner, Severity};

/// Conservative URL shape. We deliberately match `http://` and
/// `https://` only - other schemes (mailto, ftp, data, javascript)
/// have very different threat profiles and belong in their own
/// scanners if anyone needs them.
///
/// The character class for the host + path is the URL-safe set per
/// RFC 3986 with `%` for percent-encoding. We stop at whitespace so
/// trailing punctuation like `, ` or `).` doesn't get sucked in.
static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https?://[^\s<>\)]+").expect("url regex compile"));

pub struct UrlExtract;

impl Default for UrlExtract {
    fn default() -> Self {
        Self
    }
}

impl UrlExtract {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Scanner for UrlExtract {
    fn name(&self) -> &'static str {
        "url_extract"
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        let mut matches = Vec::new();
        for m in URL_RE.find_iter(input) {
            let span = m.start()..m.end();
            let text = &input[span.clone()];
            // Emit the URL itself as Info - the caller decides
            // whether to allowlist / denylist.
            matches.push(Match::new(
                "url_extract",
                "url",
                span.clone(),
                text,
                Confidence::High,
                Severity::Info,
            ));

            // IDN-homograph check on the host label only. Locating
            // it: skip past "http(s)://", then take until the first
            // '/' or '?' or '#' or end-of-url.
            if let Some(host_span) = host_span_within(text, span.start) {
                let host = &input[host_span.clone()];
                if !host.is_ascii() && !host.is_single_script() {
                    matches.push(Match::new(
                        "url_extract",
                        "idn_homograph",
                        host_span.clone(),
                        host,
                        Confidence::High,
                        Severity::Block,
                    ));
                }
            }
        }
        ScanResult { matches }
    }
}

/// Return the byte range of the host inside the URL, where `offset`
/// is the URL's start in the original input. Returns `None` if we
/// can't find the host (shouldn't happen for URLs the regex matched).
fn host_span_within(url: &str, offset: usize) -> Option<std::ops::Range<usize>> {
    // Find scheme end - "://" must be present (regex guarantees it).
    let scheme_end = url.find("://")? + 3;
    // Host ends at the first '/', '?', '#', or end of url.
    let rest = &url[scheme_end..];
    let host_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some((offset + scheme_end)..(offset + scheme_end + host_len))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn extracts_http_url() {
        let r = UrlExtract::new().scan("visit https://example.com today");
        assert!(r.flagged());
        let m = r.first().unwrap();
        assert_eq!(m.pattern, "url");
        assert_eq!(m.severity, Severity::Info);
        assert_eq!(m.text, "https://example.com");
    }

    #[test]
    fn ascii_only_host_no_homograph_flag() {
        let r = UrlExtract::new().scan("https://example.com/path?x=1");
        // Exactly one match: the URL itself.
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].pattern, "url");
    }

    #[test]
    fn idn_homograph_flagged_block() {
        // Cyrillic 'р' (U+0440) + 'а' (U+0430) inside what looks like paypal.com
        let input = "log in at https://\u{0440}\u{0430}ypal.com/login now";
        let r = UrlExtract::new().scan(input);
        // url + idn_homograph
        assert_eq!(r.matches.len(), 2);
        let homo = r
            .matches
            .iter()
            .find(|m| m.pattern == "idn_homograph")
            .unwrap();
        assert_eq!(homo.severity, Severity::Block);
        assert_eq!(homo.confidence, Confidence::High);
        // Text is the host slice, borrowed from input.
        assert_eq!(homo.text, "\u{0440}\u{0430}ypal.com");
        assert!(r.should_refuse());
    }

    #[test]
    fn no_url_no_flag() {
        let r = UrlExtract::new().scan("plain text no links here");
        assert!(!r.flagged());
    }

    #[test]
    fn punycode_host_passes_homograph_check() {
        // xn-- prefix is ASCII - confusable check doesn't apply.
        // (The caller would denylist suspicious xn-- domains separately.)
        let r = UrlExtract::new().scan("https://xn--pypal-4ve.com/login");
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].pattern, "url");
    }

    #[test]
    fn url_text_borrows_from_input() {
        let input = "see https://example.com";
        let r = UrlExtract::new().scan(input);
        let m = r.first().unwrap();
        let input_ptr = input.as_ptr() as usize;
        let text_ptr = m.text.as_ptr() as usize;
        assert!(
            text_ptr >= input_ptr && text_ptr < input_ptr + input.len(),
            "url text must borrow from input (zero-copy contract)"
        );
    }

    #[test]
    fn trailing_punctuation_not_included() {
        // "), " after a URL should not get sucked into the URL span.
        let r = UrlExtract::new().scan("see (https://example.com), thanks");
        let m = r.first().unwrap();
        assert_eq!(m.text, "https://example.com");
    }
}
