# llm-guard

[![CI](https://github.com/marirs/llm-guard-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/llm-guard-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/llm-guard.svg)](https://crates.io/crates/llm-guard)
[![Docs.rs](https://docs.rs/llm-guard/badge.svg)](https://docs.rs/llm-guard)
[![Downloads](https://img.shields.io/crates/d/llm-guard.svg)](https://crates.io/crates/llm-guard)
[![License](https://img.shields.io/crates/l/llm-guard.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://github.com/marirs/llm-guard-rs)

Zero-copy guardrails for LLM input/output. Pure-Rust port of selected
scanners from the upstream Python [llm-guard](https://github.com/protectai/llm-guard)
— no Python, no ML runtime, no network calls.

## Installation
```toml
[dependencies]
llm-guard = "0.1"
```

## Design

- **Zero-copy.** Every `Match<'a>` borrows from the caller's input.
  Patterns are `&'static str`. The only allocation on a hit is the
  `Vec<Match>` itself; a clean scan is allocation-free end-to-end.
- **`Send + Sync` scanners.** Scanners hold no per-request state —
  pattern tables are baked in at construction. Share one instance
  across worker tasks.
- **No global registry.** The caller assembles the `Pipeline` it
  wants. Cheap scanners (e.g. `TokenLimit`) should come first so
  `FirstHit` mode short-circuits early.

## Scanners

| Scanner         | Purpose                                                              |
| --------------- | -------------------------------------------------------------------- |
| `BanSubstrings` | Multi-pattern substring match via Aho–Corasick (case-insensitive).   |
| `BanCode`       | Detect code-like content (fences, language prefixes, script tags).   |
| `RoleOverride`  | Chat-template marker injection (system/instruction prefixes).        |
| `Secrets`       | Regex-based credential leak detection (API keys, PEM, JWT).          |
| `InvisibleText` | Zero-width / bidi-override codepoints used in prompt smuggling.      |
| `ScriptMix`     | Unicode-script mixing (Cyrillic look-alikes against Latin, etc.).    |
| `RegexScan`     | Caller-supplied regex patterns for custom shapes.                    |
| `TokenLimit`    | Cheap character-count gate before invoking the model.                |

Helpers:

- `sanitize::strip_controls` — replaces C0/C1 control chars with spaces,
  returns `Cow<str>` (borrowed when input is clean).
- `wrap::with_boundary` — wraps user input with defence delimiters and
  an optional warning preamble for flagged messages.

Curated pattern tables in `patterns::`:

- `COMMON_INJECTION_PATTERNS` — generic prompt-injection phrases.
- `ROLE_OVERRIDE_PATTERNS` — what `RoleOverride` uses internally.
- `IDENTITY_LEAK_MARKERS` — for output-side `BanSubstrings`.

## Usage

### Minimal input guard

```rust
use llm_guard::{
    Pipeline, PipelineMode, BanSubstrings, InvisibleText, RoleOverride, TokenLimit,
    patterns::COMMON_INJECTION_PATTERNS,
};

let input_guard = Pipeline::new(PipelineMode::FirstHit)
    .with(TokenLimit::new(8_000))
    .with(InvisibleText::new())
    .with(RoleOverride::new())
    .with(BanSubstrings::new("injection", COMMON_INJECTION_PATTERNS));

let result = input_guard.scan(user_input);
if result.flagged() {
    let first = result.first().unwrap();
    tracing::warn!(scanner = first.scanner, pattern = first.pattern, "input refused");
    // refuse, redact, or return an error to the caller
}
```

### Output guard — collect every hit

```rust
use llm_guard::{
    Pipeline, PipelineMode, BanSubstrings, Secrets,
    patterns::IDENTITY_LEAK_MARKERS,
};

let output_guard = Pipeline::new(PipelineMode::All)
    .with(Secrets::new())
    .with(BanSubstrings::new("identity_leak", IDENTITY_LEAK_MARKERS));

let result = output_guard.scan(model_response);
for m in &result.matches {
    tracing::warn!(scanner = m.scanner, pattern = m.pattern, span = ?m.span);
}
```

`PipelineMode::All` collects every match across every scanner —
useful for output filtering where you want the full audit picture.
`PipelineMode::FirstHit` stops at the first scanner that flags.

### Caller-supplied regex

```rust
use llm_guard::{RegexScan, RegexPattern, Scanner};

let scanner = RegexScan::new("internal", vec![
    RegexPattern::new("employee_id", r"\bEMP-\d{6}\b").unwrap(),
    RegexPattern::new("ticket_ref",  r"\bTKT-[A-Z]{3}-\d{4}\b").unwrap(),
]);
let r = scanner.scan("ticket from EMP-123456 escalated");
assert!(r.flagged());
```

See the [`examples/`](examples/) directory for runnable end-to-end usage.

## Adding a scanner

Implement the `Scanner` trait:

```rust
use llm_guard::{Match, ScanResult, Scanner};

struct MyScanner;

impl Scanner for MyScanner {
    fn name(&self) -> &'static str { "my_scanner" }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        // return ScanResult::default() for no hits
        // matches must borrow from `input`
        ScanResult::default()
    }
}
```

Wire it into a `Pipeline` at the call site. There is no global
registry — the integration layer owns the assembly.

## Status

Library is unit-tested (49 tests) and clippy-clean under
`#![warn(clippy::pedantic)]`. CI builds + tests on Linux/macOS/Windows
across x86_64 and aarch64.

## License

MIT OR Apache-2.0
