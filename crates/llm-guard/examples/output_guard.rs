//! Output-side guard: `PipelineMode::All` so every leak gets logged,
//! not just the first one. Demonstrates auditing the full match list.
//!
//!     cargo run --example output_guard

use llm_guard::{BanSubstrings, Pipeline, PipelineMode, Secrets, patterns::IDENTITY_LEAK_MARKERS};

fn build_guard() -> Pipeline {
    Pipeline::new(PipelineMode::All)
        .with(Secrets::new())
        .with(BanSubstrings::new("identity_leak", IDENTITY_LEAK_MARKERS))
}

fn main() {
    let guard = build_guard();

    let response = "Sure — your API key is sk-proj-abc123XYZ456_-defGHI789jkl. \
                    Also, I am ChatGPT, an AI language model.";

    let r = guard.scan(response);
    if r.flagged() {
        println!("response failed audit ({} hits):", r.matches.len());
        for m in &r.matches {
            println!(
                "  scanner={:15} pattern={:18} span={:>4?} text={:?}",
                m.scanner, m.pattern, m.span, m.text
            );
        }
    } else {
        println!("response clean");
    }
}
