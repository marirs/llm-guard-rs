//! Detect `[visible text](url)` where the visible text *looks like* a
//! different URL than the one the link actually points to. Classic
//! phishing / smuggling shape - the user sees "click here:
//! google.com" but clicks through to attacker.example.
//!
//! Two FP guards keep this honest:
//! 1. **Both sides must contain a domain-shaped string** (something
//!    with a dot followed by 2+ letters). A link with visible text
//!    "click here" → unflagged, regardless of url. We only fire when
//!    the visible text is *itself* claiming to be a URL.
//! 2. **Domain comparison is on registrable suffix**, not literal
//!    string. `https://docs.example.com` vs `example.com/help` → not
//!    flagged. `google.com` vs `attacker.example.com` → flagged.
//!
//! Zero-copy: both the visible text and the url spans borrow from
//! the input. No `String` allocation on clean scans.

use std::sync::LazyLock;

use regex::Regex;

use crate::{Confidence, Match, ScanResult, Scanner, Severity};

/// Markdown link shape: `[visible](url)`. Captures both sides.
/// `[^\]]+` for visible (anything-but-`]`) and `[^)\s]+` for url
/// (anything-but-`)`-or-whitespace) - tolerates real-world links
/// without trying to parse percent-encoding or balanced brackets.
static MD_LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[([^\]]+)\]\(([^)\s]+)\)").expect("markdown link regex compile")
});

/// "Looks like a domain": one+ alnum/dash labels separated by dots,
/// ending in a 2-24 letter TLD-shaped suffix. Conservative to keep
/// the FP rate low - "node.js" should not look like a domain here,
/// hence the `[a-z]{2,24}` (letters only) TLD.
static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-z0-9][a-z0-9-]*\.)+[a-z]{2,24}\b").expect("domain regex compile")
});

pub struct MarkdownLinkSmuggle;

impl Default for MarkdownLinkSmuggle {
    fn default() -> Self {
        Self
    }
}

impl MarkdownLinkSmuggle {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Scanner for MarkdownLinkSmuggle {
    fn name(&self) -> &'static str {
        "markdown_link_smuggle"
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        let mut matches = Vec::new();
        for caps in MD_LINK_RE.captures_iter(input) {
            // Both groups are guaranteed by the regex shape.
            let visible_m = caps.get(1).expect("visible capture group");
            let url_m = caps.get(2).expect("url capture group");
            let visible = visible_m.as_str();
            let url = url_m.as_str();

            // Pull a domain out of each side. If either side has no
            // domain shape, this isn't smuggling - skip.
            let Some(vis_domain) = DOMAIN_RE.find(visible) else {
                continue;
            };
            let Some(url_domain) = extract_url_domain(url) else {
                continue;
            };

            // Compare the registrable suffix (last two labels). If
            // those match, we treat it as the same site and don't
            // flag - covers the "subdomain in link, root in text"
            // case which is legitimate.
            if same_registrable(vis_domain.as_str(), url_domain) {
                continue;
            }

            // The smuggling match. Use the FULL `[visible](url)`
            // span as the reported span, so the operator can render
            // the whole thing in one go.
            let span = caps.get(0).expect("group 0").range();
            let text = &input[span.clone()];
            matches.push(Match::new(
                "markdown_link_smuggle",
                "domain_mismatch",
                span,
                text,
                Confidence::High,
                Severity::Block,
            ));
        }
        ScanResult { matches }
    }
}

/// Pull the host-domain out of a URL string. Returns `None` if the
/// URL doesn't carry an obvious host (e.g. a relative link, a
/// `mailto:`, an anchor). Borrowed `&str` - zero alloc.
fn extract_url_domain(url: &str) -> Option<&str> {
    // Handle http(s)://, //, and bare-domain forms.
    let after_scheme = if let Some(stripped) = url.strip_prefix("https://") {
        stripped
    } else if let Some(stripped) = url.strip_prefix("http://") {
        stripped
    } else if let Some(stripped) = url.strip_prefix("//") {
        stripped
    } else {
        // Bare domain or relative link. Bare domain still has dots;
        // anything without dots / colons is probably an anchor.
        url
    };
    // Trim trailing path/query/fragment.
    let host_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..host_end];
    // Strip credentials if present (`user:pass@host`).
    let host = host.rsplit('@').next().unwrap_or(host);
    // Strip port if present.
    let host = host.split(':').next().unwrap_or(host);
    // Must contain at least one dot to count as a domain.
    if host.contains('.') { Some(host) } else { None }
}

/// True iff two hostnames share their *last two* labels (e.g.
/// `docs.example.com` and `example.com` → true). This is not a real
/// PSL lookup - it's a deliberate approximation. The trade is fewer
/// false positives on subdomain links at the cost of missing
/// attacker subdomains under shared hosting TLDs (`*.co.uk` etc).
/// For LLM input/output filtering this is the right trade.
fn same_registrable(a: &str, b: &str) -> bool {
    let last_two = |s: &str| -> Option<(String, String)> {
        let mut parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 2 {
            return None;
        }
        // case-fold for the comparison (one small alloc per side,
        // only on the path where we already found a candidate hit).
        let tld = parts.pop()?.to_ascii_lowercase();
        let sld = parts.pop()?.to_ascii_lowercase();
        Some((sld, tld))
    };
    last_two(a) == last_two(b)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn smuggle_flagged_block() {
        let r = MarkdownLinkSmuggle::new()
            .scan("click [google.com](https://attacker.example/login) now");
        assert!(r.flagged());
        let m = r.first().unwrap();
        assert_eq!(m.pattern, "domain_mismatch");
        assert_eq!(m.severity, Severity::Block);
        assert!(r.should_refuse());
    }

    #[test]
    fn same_site_subdomain_not_flagged() {
        // docs.example.com vs example.com - same registrable suffix.
        let r = MarkdownLinkSmuggle::new()
            .scan("see [example.com](https://docs.example.com/api) for details");
        assert!(!r.flagged());
    }

    #[test]
    fn non_domain_visible_text_not_flagged() {
        // "click here" doesn't look like a domain - no smuggle claim.
        let r = MarkdownLinkSmuggle::new().scan("[click here](https://attacker.example.com)");
        assert!(!r.flagged());
    }

    #[test]
    fn matching_domains_not_flagged() {
        let r = MarkdownLinkSmuggle::new().scan("[example.com](https://example.com/path)");
        assert!(!r.flagged());
    }

    #[test]
    fn clean_text_no_flag() {
        let r = MarkdownLinkSmuggle::new().scan("nothing to see here, no markdown");
        assert!(!r.flagged());
    }

    #[test]
    fn matched_text_borrows_from_input() {
        let input = "click [google.com](https://attacker.example/login) now";
        let r = MarkdownLinkSmuggle::new().scan(input);
        let m = r.first().unwrap();
        let input_ptr = input.as_ptr() as usize;
        let text_ptr = m.text.as_ptr() as usize;
        assert!(
            text_ptr >= input_ptr && text_ptr < input_ptr + input.len(),
            "match text must borrow from input"
        );
        assert_eq!(m.text, "[google.com](https://attacker.example/login)");
    }
}
