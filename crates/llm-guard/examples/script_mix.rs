//! Look-alike attack defence via `ScriptMix`. The input below uses
//! Cyrillic 'р' (U+0440) and 'а' (U+0430) in place of Latin 'p' and
//! 'a' to disguise the word "paypal" so a naive substring filter
//! would miss it.
//!
//!     cargo run --example script_mix

use llm_guard::{Scanner, ScriptMix};

fn main() {
    // The "p" and "a" here are Cyrillic look-alikes.
    let suspect = "log in at \u{0440}\u{0430}ypal.com to verify your account";

    let scanner = ScriptMix::new(0); // strict: any foreign-script char flags
    let r = scanner.scan(suspect);
    for m in &r.matches {
        println!(
            "foreign run script={:8} span={:?} text={:?}",
            m.pattern, m.span, m.text
        );
    }
}
