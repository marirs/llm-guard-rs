//! Detect runs of repeated characters - a "flood" shape that shows
//! up in token-stuffing attacks ("aaaaaaaaaa..." to consume context
//! budget) and in many-shot jailbreaks (repeating a token pattern
//! to nudge the model out of policy).
//!
//! The caller picks the threshold - there's no sensible global
//! default (a `=========` markdown rule is fine; a 4096-char `A`
//! flood is not). [`Repetition::new`] takes the minimum run length
//! that counts as a flood. Set it conservatively: 200+ for general
//! safety, lower only for narrow-surface filters.
//!
//! Zero-copy: the run span borrows from the input. Single-pass scan.

use std::ops::Range;

use crate::{Confidence, Match, ScanResult, Scanner, Severity};

pub struct Repetition {
    /// Minimum consecutive identical chars to count as a flood.
    /// Must be >= 2; `new` enforces a floor.
    min_run: usize,
}

impl Repetition {
    /// Build a scanner that flags runs of `>= min_run` identical
    /// chars. `min_run` is clamped to >= 2 (a "run of 1" is just one
    /// char, not a run). Pick conservatively - too low and ordinary
    /// markdown (`---`, `===`) trips.
    #[must_use]
    pub const fn new(min_run: usize) -> Self {
        Self {
            min_run: if min_run < 2 { 2 } else { min_run },
        }
    }
}

impl Scanner for Repetition {
    fn name(&self) -> &'static str {
        "repetition"
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        let mut matches = Vec::new();
        // Single-pass: track current run's start, char, and length.
        let mut run_start: usize = 0;
        let mut run_char: Option<char> = None;
        let mut run_len: usize = 0;

        for (idx, ch) in input.char_indices() {
            match run_char {
                Some(prev) if prev == ch => {
                    run_len += 1;
                }
                _ => {
                    // Run broke (or first char). Emit the previous
                    // run if it crossed the threshold.
                    if run_len >= self.min_run {
                        emit(&mut matches, input, run_start..idx);
                    }
                    run_start = idx;
                    run_char = Some(ch);
                    run_len = 1;
                }
            }
        }
        // Trailing run.
        if run_len >= self.min_run {
            emit(&mut matches, input, run_start..input.len());
        }
        ScanResult { matches }
    }
}

fn emit<'a>(matches: &mut Vec<Match<'a>>, input: &'a str, span: Range<usize>) {
    matches.push(Match::new(
        "repetition",
        "char_flood",
        span.clone(),
        &input[span],
        // Length is the threshold the caller already set, so we
        // trust the hit as High confidence. Severity is Block - a
        // flood is a refusal-class shape.
        Confidence::High,
        Severity::Block,
    ));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn flags_long_a_flood() {
        let input = format!("hi {}", "a".repeat(300));
        let r = Repetition::new(200).scan(&input);
        assert!(r.flagged());
        let m = r.first().unwrap();
        assert_eq!(m.pattern, "char_flood");
        assert_eq!(m.severity, Severity::Block);
        assert!(r.should_refuse());
    }

    #[test]
    fn short_run_under_threshold_not_flagged() {
        let r = Repetition::new(50).scan("hmmmmmmm interesting");
        assert!(!r.flagged());
    }

    #[test]
    fn markdown_rule_not_flagged_at_default() {
        // A line of 20 `=` should not trip a 200-min scanner.
        let r = Repetition::new(200).scan("====================");
        assert!(!r.flagged());
    }

    #[test]
    fn floor_enforced_for_min_run_lt_2() {
        // new(0) is treated as new(2).
        let r = Repetition::new(0).scan("aa bb");
        assert!(r.flagged());
        assert_eq!(r.matches.len(), 2);
    }

    #[test]
    fn multiple_runs_all_reported() {
        let s = format!("{} mid {}", "x".repeat(60), "y".repeat(60));
        let r = Repetition::new(50).scan(&s);
        assert_eq!(r.matches.len(), 2);
    }

    #[test]
    fn matched_text_borrows_from_input() {
        let input = "abc".to_string() + &"q".repeat(100);
        let r = Repetition::new(100).scan(&input);
        let m = r.first().unwrap();
        let input_ptr = input.as_ptr() as usize;
        let text_ptr = m.text.as_ptr() as usize;
        assert!(
            text_ptr >= input_ptr && text_ptr < input_ptr + input.len(),
            "run text must borrow from input"
        );
    }

    #[test]
    fn clean_input_no_flag() {
        let r = Repetition::new(50).scan("perfectly ordinary sentence with varied content");
        assert!(!r.flagged());
    }

    #[test]
    fn unicode_run_counted_correctly() {
        // 100 copies of a 3-byte char.
        let s = "é".repeat(100);
        let r = Repetition::new(80).scan(&s);
        assert!(r.flagged());
    }
}
