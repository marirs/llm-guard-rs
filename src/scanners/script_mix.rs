//! Flag unexpected Unicode script mixing. An attacker may slip Cyrillic
//! or Greek look-alike characters into a Latin word to bypass a naive
//! substring filter (`раypal` vs `paypal` - first one starts with
//! Cyrillic 'р' and 'а'). This scanner is the cheap defence: bucket
//! every code point by script, and if the input mixes scripts beyond
//! a caller-set threshold, flag each foreign run.
//!
//! No ML, no language detection - just `char::is_ascii_*` and a small
//! manual `match` over Unicode block ranges. Zero-copy: each
//! [`crate::Match`] borrows the offending byte span from the input.
//!
//! Scope is deliberately narrow: we only distinguish a handful of
//! "scripts" relevant to look-alike attacks. Punctuation, digits, and
//! whitespace are treated as neutral and ignored when picking the
//! dominant script.

use crate::{Match, ScanResult, Scanner};

/// Coarse script bucket. Names are the audit-log identifiers - kept
/// short and stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    /// ASCII letters and Latin-1 / Latin Extended.
    Latin,
    /// Cyrillic block (used in most look-alike attacks against Latin).
    Cyrillic,
    /// Greek block.
    Greek,
    /// Arabic block.
    Arabic,
    /// Hebrew block.
    Hebrew,
    /// CJK ideographs + Hiragana + Katakana + Hangul.
    Cjk,
    /// Anything we don't track explicitly. Treated as neutral.
    Other,
    /// Whitespace, punctuation, digits - ignored for dominance.
    Neutral,
}

impl Script {
    fn id(self) -> &'static str {
        match self {
            Self::Latin => "latin",
            Self::Cyrillic => "cyrillic",
            Self::Greek => "greek",
            Self::Arabic => "arabic",
            Self::Hebrew => "hebrew",
            Self::Cjk => "cjk",
            Self::Other => "other",
            Self::Neutral => "neutral",
        }
    }
}

// Direct `match` over codepoint ranges - O(1) per char and the compiler
// turns it into a balanced decision tree. Ranges follow Unicode block
// names; we collapse the variants we don't care about into `Other`.
fn classify(c: char) -> Script {
    if c.is_whitespace() || c.is_ascii_punctuation() || c.is_ascii_digit() {
        return Script::Neutral;
    }
    match c as u32 {
        // Basic Latin letters + Latin-1 Supplement + Latin Extended-A/B.
        0x0041..=0x005A | 0x0061..=0x007A | 0x00C0..=0x024F => Script::Latin,
        // Greek and Coptic, Greek Extended.
        0x0370..=0x03FF | 0x1F00..=0x1FFF => Script::Greek,
        // Cyrillic + Cyrillic Supplement + Cyrillic Extended-A/B/C.
        0x0400..=0x04FF | 0x0500..=0x052F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => Script::Cyrillic,
        // Hebrew.
        0x0590..=0x05FF => Script::Hebrew,
        // Arabic + Arabic Supplement + Arabic Extended.
        0x0600..=0x06FF | 0x0750..=0x077F | 0x08A0..=0x08FF => Script::Arabic,
        // Hiragana, Katakana, CJK Unified, Hangul.
        0x3040..=0x309F | 0x30A0..=0x30FF | 0x4E00..=0x9FFF | 0xAC00..=0xD7AF | 0x3400..=0x4DBF => {
            Script::Cjk
        }
        _ => Script::Other,
    }
}

/// Threshold-based script-mixing detector.
///
/// At scan time, every non-neutral char is classified. The script with
/// the highest count is the "dominant" one; any **run of consecutive
/// characters** in a different script counts as one match if the total
/// foreign-character count exceeds [`ScriptMix::threshold`].
///
/// Threshold semantics: an integer count of foreign chars, not a
/// percentage. Set to 1 for the strictest check (any mixing flags),
/// or higher to ignore occasional foreign words.
pub struct ScriptMix {
    /// Foreign-char count above which we report. Below this, the scan
    /// passes silently - which matters because legitimate text often
    /// contains a single foreign word (e.g. "café") that shouldn't
    /// trip a guard.
    threshold: usize,
}

impl ScriptMix {
    /// Build a scanner that flags when more than `threshold`
    /// non-dominant-script characters appear.
    #[must_use]
    pub const fn new(threshold: usize) -> Self {
        Self { threshold }
    }
}

impl Scanner for ScriptMix {
    fn name(&self) -> &'static str {
        "script_mix"
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        // Two passes. First: bucket counts to pick the dominant
        // script. Second: walk again, emit one Match per contiguous
        // foreign-script run. Two passes is cheaper than buffering
        // runs and the input is already in cache after pass one.
        let mut counts = [0_usize; 8];
        let mut total_non_neutral = 0_usize;
        for c in input.chars() {
            let s = classify(c);
            if !matches!(s, Script::Neutral) {
                counts[s as usize] += 1;
                total_non_neutral += 1;
            }
        }
        if total_non_neutral == 0 {
            return ScanResult::default();
        }

        // Pick dominant: highest count, breaking ties by Latin first
        // (because that's overwhelmingly the expected script in LLM
        // contexts). We iterate the script variants in a fixed order
        // and keep the first max.
        let dominant = dominant_script(&counts);

        // Count foreign chars (everything non-neutral and non-dominant).
        let foreign: usize = counts
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != dominant as usize && *i != Script::Neutral as usize)
            .map(|(_, c)| *c)
            .sum();

        if foreign <= self.threshold {
            return ScanResult::default();
        }

        // Pass two: emit a Match for each run of consecutive foreign
        // chars. `&input[run_start..run_end]` borrows from the input.
        let mut matches = Vec::new();
        let mut run_start: Option<(usize, Script)> = None;
        for (idx, c) in input.char_indices() {
            let s = classify(c);
            let is_foreign = !matches!(s, Script::Neutral) && s as usize != dominant as usize;
            if is_foreign {
                if run_start.is_none() {
                    run_start = Some((idx, s));
                }
            } else if let Some((start, run_script)) = run_start.take() {
                let span = start..idx;
                matches.push(Match {
                    scanner: "script_mix",
                    pattern: run_script.id(),
                    span: span.clone(),
                    text: &input[span],
                });
            }
        }
        // Trailing run reaches end-of-input.
        if let Some((start, run_script)) = run_start {
            let span = start..input.len();
            matches.push(Match {
                scanner: "script_mix",
                pattern: run_script.id(),
                span: span.clone(),
                text: &input[span],
            });
        }
        ScanResult { matches }
    }
}

// Pick the dominant script with a Latin tie-breaker. Iterating the
// indices in (Latin, Cyrillic, Greek, Arabic, Hebrew, CJK, Other)
// order means Latin wins any tie - which is the right bias for a
// majority-English chat surface.
fn dominant_script(counts: &[usize; 8]) -> Script {
    let ordered = [
        Script::Latin,
        Script::Cyrillic,
        Script::Greek,
        Script::Arabic,
        Script::Hebrew,
        Script::Cjk,
        Script::Other,
    ];
    let mut best = Script::Latin;
    let mut best_count = 0_usize;
    for s in ordered {
        let c = counts[s as usize];
        if c > best_count {
            best = s;
            best_count = c;
        }
    }
    best
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pure_latin_passes() {
        let r = ScriptMix::new(0).scan("hello world this is plain English");
        assert!(!r.flagged());
    }

    #[test]
    fn one_foreign_char_under_threshold_passes() {
        // Threshold 1 means "more than one" trips it.
        let r = ScriptMix::new(1).scan("the word café is fine");
        assert!(!r.flagged());
    }

    #[test]
    fn lookalike_attack_flagged() {
        // First two chars are Cyrillic look-alikes (р, а), rest is Latin.
        // \u{0440} = Cyrillic 'р', \u{0430} = Cyrillic 'а'.
        let input = "\u{0440}\u{0430}ypal.com login";
        let r = ScriptMix::new(0).scan(input);
        assert!(r.flagged());
        let m = r.first().unwrap();
        assert_eq!(m.pattern, "cyrillic");
        // The matched text is the Cyrillic run, borrowed from input.
        assert_eq!(m.text, "\u{0440}\u{0430}");
    }

    #[test]
    fn matched_span_is_borrowed_from_input() {
        let input = "ok \u{0440}\u{0430} ok";
        let r = ScriptMix::new(0).scan(input);
        let m = r.first().unwrap();
        let input_ptr = input.as_ptr() as usize;
        let text_ptr = m.text.as_ptr() as usize;
        assert!(
            text_ptr >= input_ptr && text_ptr < input_ptr + input.len(),
            "matched text must borrow from input (zero-copy contract)"
        );
    }

    #[test]
    fn neutral_chars_dont_break_runs() {
        // Two Cyrillic runs separated by ASCII space should be two
        // matches (the space ends the first run).
        let input = "\u{0410}\u{0411} \u{0412}\u{0413} latin word here too";
        let r = ScriptMix::new(0).scan(input);
        assert_eq!(r.matches.len(), 2);
    }

    #[test]
    fn pure_cyrillic_input_passes() {
        // No mixing - Cyrillic IS the dominant script. Nothing foreign.
        let r = ScriptMix::new(0).scan("\u{0410}\u{0411}\u{0412}\u{0413}");
        assert!(!r.flagged());
    }

    #[test]
    fn empty_input_passes() {
        let r = ScriptMix::new(0).scan("");
        assert!(!r.flagged());
    }
}
