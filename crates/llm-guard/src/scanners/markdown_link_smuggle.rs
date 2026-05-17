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
//! ## Why a hand-rolled scanner instead of a single regex
//!
//! An earlier version used `\[([^\]]+)\]\(([^)\s]+)\)`. That regex
//! treats the URL group as "anything except `)`", which means a URL
//! containing a balanced `(...)` group (e.g. Wikipedia disambiguation
//! pages, or paths with parens like `page_(2)`) gets truncated at the
//! first `)`. Worse, an attacker could craft
//! `[google.com](https://(real-google.com).attacker.example/path)` -
//! the regex captures `https://(real-google.com` as the URL, our
//! domain extractor sees no dot in `(real-google.com` and returns
//! `None`, and the smuggle goes through undetected.
//!
//! The new approach scans for `[...]( ... )` with **paren-depth
//! tracking** inside the URL: we accept inner balanced parens and
//! only stop at the matching close. This adds ~15 lines of
//! state-machine code and removes the bypass.
//!
//! Zero-copy: both the visible text and the url spans borrow from
//! the input. No `String` allocation on clean scans.

use std::sync::LazyLock;

use regex::Regex;

use crate::{Confidence, Match, ScanResult, Scanner, Severity};

// MD_LINK_RE was retired in favour of `iter_md_links` because the
// regex couldn't handle balanced parens inside the URL (see module
// docs above for the bypass vector that motivated the rewrite).

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
        for link in iter_md_links(input) {
            let visible = &input[link.visible_range.clone()];
            let url = &input[link.url_range.clone()];

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
            let span = link.full_range.clone();
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

/// One discovered `[visible](url)` link. All fields are byte
/// offsets into the original input.
///
/// `clippy::struct_field_names` flags the shared `_range` suffix,
/// but each field genuinely names a *different region* of the same
/// link (whole, visible-text part, url part). Renaming them to
/// `full`/`visible`/`url` would lose the explicit "this is a range,
/// not a string" cue, so we suppress the lint here.
#[allow(clippy::struct_field_names)]
struct MdLink {
    full_range: std::ops::Range<usize>,
    visible_range: std::ops::Range<usize>,
    url_range: std::ops::Range<usize>,
}

/// Iterate all `[visible](url)` links in `input`, handling balanced
/// parens inside the URL. Returns an empty vec on clean input (no
/// `[` found), so allocation only happens when there's something to
/// report on.
///
/// This is the hand-rolled replacement for the previous greedy
/// regex - see module docs for why a single regex can't do this
/// safely.
fn iter_md_links(input: &str) -> Vec<MdLink> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // Find next `[`. Note: `[` is single-byte, safe to scan
        // bytewise even with multibyte content elsewhere.
        let Some(rel) = bytes[i..].iter().position(|&b| b == b'[') else {
            break;
        };
        let lbracket = i + rel;
        // Find matching `]` - markdown link text doesn't permit
        // nested `]` so first occurrence wins.
        let Some(rel) = bytes[lbracket + 1..].iter().position(|&b| b == b']') else {
            // Unmatched `[` - nothing more to find.
            break;
        };
        let rbracket = lbracket + 1 + rel;
        // Must be immediately followed by `(`.
        if rbracket + 1 >= bytes.len() || bytes[rbracket + 1] != b'(' {
            i = rbracket + 1;
            continue;
        }
        let lparen = rbracket + 1;
        // Scan for the matching `)`, tracking depth so balanced
        // inner parens (`page_(2)`) don't terminate early. We also
        // stop on whitespace - markdown URLs don't contain spaces.
        let url_start = lparen + 1;
        let mut depth: usize = 1;
        let mut end = url_start;
        while end < bytes.len() {
            match bytes[end] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                b' ' | b'\t' | b'\n' | b'\r' => {
                    // Whitespace in URL position - not a real markdown
                    // link, abandon and search past this `[`.
                    depth = usize::MAX; // sentinel
                    break;
                }
                _ => {}
            }
            end += 1;
        }
        if depth != 0 || end >= bytes.len() {
            // No matching close - advance past the `[` and keep
            // scanning for the next candidate.
            i = lbracket + 1;
            continue;
        }
        // `end` indexes the matching `)`.
        let url_end = end;
        let rparen = end + 1; // exclusive end of the full link
        // Reject empty visible/url - real links have content in both.
        if rbracket == lbracket + 1 || url_end == url_start {
            i = rparen;
            continue;
        }
        out.push(MdLink {
            full_range: lbracket..rparen,
            visible_range: (lbracket + 1)..rbracket,
            url_range: url_start..url_end,
        });
        i = rparen;
    }
    out
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
///
/// Implementation note (L5 from review): uses `eq_ignore_ascii_case`
/// on borrowed slices rather than `to_ascii_lowercase` into owned
/// Strings. Saves two heap allocations per candidate match.
// `similar_names` flags the {a,b}_{sld,tld} bindings, but the
// names follow a well-understood DNS convention (sld = second-level
// domain, tld = top-level domain) with the side prefix. Renaming
// would obscure the intent.
#[allow(clippy::similar_names)]
fn same_registrable(a: &str, b: &str) -> bool {
    let (Some((a_sld, a_tld)), Some((b_sld, b_tld))) = (last_two_labels(a), last_two_labels(b))
    else {
        return false;
    };
    a_sld.eq_ignore_ascii_case(b_sld) && a_tld.eq_ignore_ascii_case(b_tld)
}

/// Borrowed last two dotted labels (sld, tld), or `None` if the
/// hostname has fewer than two labels.
fn last_two_labels(host: &str) -> Option<(&str, &str)> {
    let (rest, tld) = host.rsplit_once('.')?;
    let sld = rest.rsplit_once('.').map_or(rest, |(_, sld)| sld);
    if sld.is_empty() || tld.is_empty() {
        return None;
    }
    Some((sld, tld))
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

    // ---- Regression: M1 bypass via balanced parens in URL ---------

    #[test]
    fn balanced_parens_in_url_do_not_truncate() {
        // Legitimate Wikipedia-style URL with disambig parens. Should
        // NOT flag (same registrable suffix) and the link parser
        // should capture the whole URL including the inner `(...)`.
        let r = MarkdownLinkSmuggle::new()
            .scan("see [example.com](https://en.example.com/wiki/Term_(disambig)) for context");
        assert!(!r.flagged(), "balanced parens should not break parsing");
    }

    #[test]
    fn attacker_smuggle_with_inner_paren_is_caught() {
        // Pre-fix: the greedy regex captured `https://(real-google.com`
        // as the URL, our domain extractor saw no dot in
        // `(real-google.com`, and the smuggle slipped through. With
        // balanced-paren handling we capture the full URL and the
        // real host (attacker.example) is correctly identified.
        let r = MarkdownLinkSmuggle::new()
            .scan("[google.com](https://(real-google.com).attacker.example/path)");
        assert!(
            r.flagged(),
            "smuggle with leading-paren obfuscation must be caught"
        );
        assert_eq!(r.first().unwrap().pattern, "domain_mismatch");
    }

    #[test]
    fn nested_balanced_parens_handled() {
        // Two levels of nesting - should still pair correctly.
        let r = MarkdownLinkSmuggle::new().scan("[example.com](https://example.com/a(b(c)d)e)");
        assert!(!r.flagged(), "two-level paren nesting should parse cleanly");
    }

    #[test]
    fn unmatched_paren_in_url_skipped_safely() {
        // No matching close paren before end of string - parser
        // abandons the candidate rather than panicking or running away.
        let r = MarkdownLinkSmuggle::new().scan("see [foo.com](https://broken.example/no-close");
        assert!(!r.flagged());
    }

    #[test]
    fn whitespace_inside_url_aborts_candidate() {
        // Real markdown links can't contain spaces in the URL part;
        // a space means it's not a link, just incidental brackets.
        let r = MarkdownLinkSmuggle::new().scan("[foo](https://example.com bad text) (other)");
        assert!(!r.flagged());
    }

    #[test]
    fn back_to_back_links_both_processed() {
        let r = MarkdownLinkSmuggle::new().scan(
            "[google.com](https://attacker.example) [github.com](https://other-attacker.example)",
        );
        assert_eq!(r.matches.len(), 2);
    }
}
