//! Detect code-like content in text. Useful as an *output* filter
//! when the model is instructed not to emit code (e.g. a help bot
//! that should answer in prose, not paste a Python snippet) - or as
//! an *input* check on a surface where users shouldn't be pasting
//! snippets at all.
//!
//! Detection is shape-based, not semantic - we look for language-
//! prefix tokens, fenced code blocks, and tag-like sentinels. Any
//! single hit is enough to flag. False positives on code-adjacent
//! prose are expected: this is a refusal-side check, not a
//! classifier.
//!
//! Skip this scanner on developer-facing surfaces where code is
//! legitimate (a code-review assistant, a programming tutor). The
//! call site decides.

use crate::{BanSubstrings, ScanResult, Scanner};

/// Markers that strongly indicate code rather than prose. The list is
/// deliberately tight - common keywords that also appear in English
/// (`if`, `for`, `class` outside a code context) are excluded to keep
/// the false-positive rate low.
///
/// Categories covered:
/// - **Fences:** triple-backtick markdown fences.
/// - **Language prefixes:** distinctive tokens that almost never
///   appear in prose (`def `, `function `, `func `, `import `, `from `,
///   `package `, `#include`, `<?php`, `<%`, `<script`, `</script`).
/// - **Operators:** the fat arrow `=>` and the slim arrow `->` only
///   in a definition-y context aren't in here - too noisy.
const CODE_MARKERS: &[&str] = &[
    "```",
    "def ",
    "function ",
    "func ",
    "import ",
    "from ",
    "package ",
    "#include",
    "<?php",
    "<%",
    "<script",
    "</script",
    "public static void",
    "fn main(",
    "pub fn ",
    "console.log(",
    "print(",
    "println!(",
    "System.out.println",
];

/// Wraps [`BanSubstrings`] over [`CODE_MARKERS`] with a fixed scanner
/// name. Identical machinery to [`crate::RoleOverride`] - same reason
/// it earns a dedicated type: the audit log gets a stable name without
/// the caller having to remember a string.
pub struct BanCode {
    inner: BanSubstrings,
}

impl Default for BanCode {
    fn default() -> Self {
        Self::new()
    }
}

impl BanCode {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: BanSubstrings::new("ban_code", CODE_MARKERS),
        }
    }
}

impl Scanner for BanCode {
    fn name(&self) -> &'static str {
        "ban_code"
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        self.inner.scan(input)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn flags_markdown_fence() {
        let r = BanCode::new().scan("here you go:\n```python\nprint(1)\n```");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().scanner, "ban_code");
    }

    #[test]
    fn flags_python_def() {
        let r = BanCode::new().scan("you can write `def foo(): pass` to start");
        assert!(r.flagged());
    }

    #[test]
    fn flags_rust_main() {
        let r = BanCode::new().scan("paste this: fn main() { println!(\"hi\"); }");
        assert!(r.flagged());
    }

    #[test]
    fn flags_html_script_tag() {
        let r = BanCode::new().scan("inject <script>alert(1)</script>");
        assert!(r.flagged());
    }

    #[test]
    fn prose_about_code_is_fine() {
        // Talking *about* code without showing it must not flag - the
        // markers all require syntactic shape, not topic.
        let r = BanCode::new().scan("I think functions in Python are useful for organising logic");
        assert!(!r.flagged());
    }

    #[test]
    fn case_insensitive_matches_uppercase_marker() {
        let r = BanCode::new().scan("IMPORT os");
        assert!(r.flagged());
    }
}
