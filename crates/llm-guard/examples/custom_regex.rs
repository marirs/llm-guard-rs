//! Caller-supplied regex shapes. Useful when you want to flag
//! something specific (an internal employee ID, a product-specific
//! URL prefix) without writing a full `Scanner`.
//!
//!     cargo run --example custom_regex

use llm_guard::{RegexPattern, RegexScan, Scanner};

fn main() {
    let scanner = RegexScan::new(
        "internal_refs",
        vec![
            RegexPattern::new("employee_id", r"\bEMP-\d{6}\b").unwrap(),
            RegexPattern::new("ticket_ref", r"\bTKT-[A-Z]{3}-\d{4}\b").unwrap(),
        ],
    );

    let chatter = "Escalating EMP-123456 — see TKT-ACM-4242 for context.";

    let r = scanner.scan(chatter);
    for m in &r.matches {
        println!(
            "pattern={:12} span={:?} text={:?}",
            m.pattern, m.span, m.text
        );
    }
}
