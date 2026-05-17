//! PII detection + IDN-homograph + markdown link smuggling - the
//! output-side scanners that catch the most common "model leaks
//! something or surfaces a malicious link" cases.
//!
//!     cargo run --example pii_and_links

use llm_guard::{MarkdownLinkSmuggle, PiiPatterns, Pipeline, PipelineMode, UrlExtract};

fn main() {
    let guard = Pipeline::new(PipelineMode::All)
        .with(PiiPatterns::new())
        .with(UrlExtract::new())
        .with(MarkdownLinkSmuggle::new());

    let responses = [
        (
            "pii in response",
            "Sure, I'll email alice@example.com. Card: 4111-1111-1111-1111.",
        ),
        (
            "homograph url",
            "Please confirm at https://\u{0440}\u{0430}ypal.com/login",
        ),
        (
            "smuggle link",
            "Click [google.com](https://attacker.example/login) to verify.",
        ),
        (
            "clean",
            "Thanks for the update. I'll get back to you shortly.",
        ),
    ];

    for (label, resp) in responses {
        let r = guard.scan(resp);
        println!("[{label:18}] should_refuse={}", r.should_refuse());
        for m in &r.matches {
            println!(
                "  - scanner={:22} pattern={:18} severity={:?} confidence={:?} text={:?}",
                m.scanner, m.pattern, m.severity, m.confidence, m.text
            );
        }
    }
}
