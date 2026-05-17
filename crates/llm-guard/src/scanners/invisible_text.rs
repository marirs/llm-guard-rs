//! Detect zero-width / format / bidi-override characters that an
//! attacker uses to smuggle hidden instructions past a glance
//! review. These chars are valid Unicode but have no business in a
//! chat turn - flagging them lets the caller either refuse or strip.
//!
//! Scope is deliberately tight: we list a handful of code points
//! that are *specifically* used in known attacks. We don't try to
//! flag every non-printable; that would over-trigger.

use std::ops::Range;

use crate::{Confidence, Match, ScanResult, Scanner, Severity};

// Single-codepoint detection list. The hot path is the `match` in
// [`lookup`] below (compiles to a jump table); this comment is the
// canonical reference for which code points the scanner covers:
//
//   U+200B  zero_width_space
//   U+200C  zero_width_non_joiner
//   U+200D  zero_width_joiner
//   U+FEFF  byte_order_mark
//   U+2060  word_joiner
//   U+180E  mongolian_vowel_separator
//   U+202A  lre   (bidi: left-to-right embedding)
//   U+202B  rle   (bidi: right-to-left embedding)
//   U+202C  pdf_bidi
//   U+202D  lro   (bidi: left-to-right override)
//   U+202E  rlo   (bidi: right-to-left override - trojan source)
//   U+2066  lri   (bidi: left-to-right isolate)
//   U+2067  rli   (bidi: right-to-left isolate)
//   U+2068  fsi   (bidi: first-strong isolate)
//   U+2069  pdi   (bidi: pop directional isolate)

pub struct InvisibleText;

impl Default for InvisibleText {
    fn default() -> Self {
        Self
    }
}

impl InvisibleText {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Scanner for InvisibleText {
    fn name(&self) -> &'static str {
        "invisible_text"
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        let mut matches = Vec::new();
        for (idx, ch) in input.char_indices() {
            if let Some(pattern) = lookup(ch) {
                let span: Range<usize> = idx..idx + ch.len_utf8();
                // Zero-width and bidi codepoints have no legitimate
                // place in a chat turn - High / Block by default.
                matches.push(Match::new(
                    "invisible_text",
                    pattern,
                    span.clone(),
                    &input[span],
                    Confidence::High,
                    Severity::Block,
                ));
            }
        }
        ScanResult { matches }
    }
}

// Direct `match` rather than a linear search over a const slice -
// compiles to a jump table and runs in O(1) per char, which matters
// because we call this once per code point of the input.
fn lookup(c: char) -> Option<&'static str> {
    Some(match c {
        '\u{200B}' => "zero_width_space",
        '\u{200C}' => "zero_width_non_joiner",
        '\u{200D}' => "zero_width_joiner",
        '\u{FEFF}' => "byte_order_mark",
        '\u{2060}' => "word_joiner",
        '\u{180E}' => "mongolian_vowel_separator",
        '\u{202A}' => "lre",
        '\u{202B}' => "rle",
        '\u{202C}' => "pdf_bidi",
        '\u{202D}' => "lro",
        '\u{202E}' => "rlo",
        '\u{2066}' => "lri",
        '\u{2067}' => "rli",
        '\u{2068}' => "fsi",
        '\u{2069}' => "pdi",
        _ => return None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn flags_zero_width_space() {
        let r = InvisibleText.scan("hello\u{200B}world");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().pattern, "zero_width_space");
    }

    #[test]
    fn flags_bidi_override() {
        let r = InvisibleText.scan("safe text \u{202E}reversed");
        assert!(r.flagged());
        assert_eq!(r.first().unwrap().pattern, "rlo");
    }

    #[test]
    fn clean_input_no_flag() {
        let r = InvisibleText.scan("perfectly ordinary text with spaces");
        assert!(!r.flagged());
    }

    #[test]
    fn reports_every_occurrence() {
        let r = InvisibleText.scan("a\u{200B}b\u{200C}c\u{200D}d");
        assert_eq!(r.matches.len(), 3);
    }

    #[test]
    fn span_lines_up_with_char() {
        let input = "x\u{200B}y";
        let r = InvisibleText.scan(input);
        let m = r.first().unwrap();
        assert_eq!(&input[m.span.clone()], "\u{200B}");
    }
}
